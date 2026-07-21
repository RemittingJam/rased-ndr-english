from __future__ import annotations

from collections import Counter, defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from app.detections.port_scan import PortScanRule

from scapy.all import DNS, DNSQR, IP, IPv6, TCP, UDP, PcapReader


PORT_SCAN_WINDOW_SECONDS = 10
PORT_SCAN_UNIQUE_PORTS = 15
DNS_SPIKE_WINDOW_SECONDS = 10
DNS_SPIKE_QUERIES = 25
MAX_PACKETS = 500_000


def _ip_pair(packet: Any) -> tuple[str | None, str | None]:
    if IP in packet:
        return str(packet[IP].src), str(packet[IP].dst)
    if IPv6 in packet:
        return str(packet[IPv6].src), str(packet[IPv6].dst)
    return None, None


def _protocol_name(packet: Any) -> str:
    if DNS in packet:
        return "DNS"
    if TCP in packet:
        return "TCP"
    if UDP in packet:
        return "UDP"
    if IP in packet:
        return "IPv4"
    if IPv6 in packet:
        return "IPv6"
    return packet.lastlayer().name if packet.lastlayer() else "Other"


def _iso_time(timestamp: float | None) -> str | None:
    if timestamp is None:
        return None
    return datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat()


def _detect_port_scans(events: list[tuple[float, str, str, int]]) -> list[dict]:
    grouped: dict[tuple[str, str], list[tuple[float, int]]] = defaultdict(list)
    for ts, src, dst, port in events:
        grouped[(src, dst)].append((ts, port))

    alerts: list[dict] = []
    for (src, dst), items in grouped.items():
        items.sort(key=lambda item: item[0])
        window: deque[tuple[float, int]] = deque()

        for ts, port in items:
            window.append((ts, port))
            while window and ts - window[0][0] > PORT_SCAN_WINDOW_SECONDS:
                window.popleft()

            unique_ports = sorted({item[1] for item in window})
            if len(unique_ports) >= PORT_SCAN_UNIQUE_PORTS:
                alerts.append(
                    {
                        "id": f"RASED-NET-001-{len(alerts) + 1}",
                        "type": "Possible Port Scan",
                        "severity": "medium",
                        "source": src,
                        "destination": dst,
                        "confidence": min(99, 65 + len(unique_ports)),
                        "reason": (
                            f"{src} contacted {len(unique_ports)} unique ports on "
                            f"{dst} within {PORT_SCAN_WINDOW_SECONDS} seconds."
                        ),
                        "evidence": {
                            "unique_ports": len(unique_ports),
                            "sample_ports": unique_ports[:20],
                            "window_seconds": PORT_SCAN_WINDOW_SECONDS,
                            "first_seen": _iso_time(window[0][0]),
                            "last_seen": _iso_time(ts),
                        },
                    }
                )
                break

    return alerts


def _detect_dns_spikes(events: list[tuple[float, str, str]]) -> list[dict]:
    grouped: dict[str, list[tuple[float, str]]] = defaultdict(list)
    for ts, src, query in events:
        grouped[src].append((ts, query))

    alerts: list[dict] = []
    for src, items in grouped.items():
        items.sort(key=lambda item: item[0])
        window: deque[tuple[float, str]] = deque()

        for ts, query in items:
            window.append((ts, query))
            while window and ts - window[0][0] > DNS_SPIKE_WINDOW_SECONDS:
                window.popleft()

            if len(window) >= DNS_SPIKE_QUERIES:
                queries = [item[1] for item in window]
                alerts.append(
                    {
                        "id": f"RASED-NET-002-{len(alerts) + 1}",
                        "type": "Unusual DNS Activity",
                        "severity": "low",
                        "source": src,
                        "destination": "DNS",
                        "confidence": min(98, 60 + len(window)),
                        "reason": (
                            f"{src} generated {len(window)} DNS queries within "
                            f"{DNS_SPIKE_WINDOW_SECONDS} seconds."
                        ),
                        "evidence": {
                            "query_count": len(window),
                            "sample_queries": queries[:10],
                            "window_seconds": DNS_SPIKE_WINDOW_SECONDS,
                            "first_seen": _iso_time(window[0][0]),
                            "last_seen": _iso_time(ts),
                        },
                    }
                )
                break

    return alerts


def analyze_pcap(path: Path, original_name: str | None = None) -> dict:
    protocol_counts: Counter[str] = Counter()
    host_counts: Counter[str] = Counter()
    conversation_counts: Counter[tuple[str, str]] = Counter()
    tcp_port_events: list[tuple[float, str, str, int]] = []
    dns_events: list[tuple[float, str, str]] = []
    timeline: Counter[int] = Counter()

    packet_count = 0
    first_timestamp: float | None = None
    last_timestamp: float | None = None

    with PcapReader(str(path)) as reader:
        for packet in reader:
            packet_count += 1
            if packet_count > MAX_PACKETS:
                break

            timestamp = float(packet.time)
            first_timestamp = timestamp if first_timestamp is None else min(first_timestamp, timestamp)
            last_timestamp = timestamp if last_timestamp is None else max(last_timestamp, timestamp)
            timeline[int(timestamp)] += 1

            protocol_counts[_protocol_name(packet)] += 1
            src, dst = _ip_pair(packet)

            if src:
                host_counts[src] += 1
            if dst:
                host_counts[dst] += 1
            if src and dst:
                conversation_counts[(src, dst)] += 1

            if src and dst and TCP in packet:
                flags = int(packet[TCP].flags)
                is_syn = bool(flags & 0x02)
                is_ack = bool(flags & 0x10)
                if is_syn and not is_ack:
                    tcp_port_events.append(
                        (timestamp, src, dst, int(packet[TCP].dport))
                    )

            if src and DNS in packet and DNSQR in packet:
                raw_query = packet[DNSQR].qname
                if isinstance(raw_query, bytes):
                    query = raw_query.decode(errors="replace").rstrip(".")
                else:
                    query = str(raw_query).rstrip(".")
                dns_events.append((timestamp, src, query))

    alerts = PortScanRule().detect({"tcp_port_events": tcp_port_events})
    alerts.extend(_detect_dns_spikes(dns_events))
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    alerts.sort(key=lambda item: severity_order.get(item["severity"], 99))

    duration = 0.0
    if first_timestamp is not None and last_timestamp is not None:
        duration = max(0.0, last_timestamp - first_timestamp)

    top_hosts = [
        {"host": host, "packets": count}
        for host, count in host_counts.most_common(10)
    ]
    top_conversations = [
        {"source": src, "destination": dst, "packets": count}
        for (src, dst), count in conversation_counts.most_common(10)
    ]
    timeline_points = [
        {"timestamp": _iso_time(float(second)), "packets": count}
        for second, count in sorted(timeline.items())[:300]
    ]

    return {
        "meta": {
            "project": "Rased NDR",
            "version": "0.1.1",
            "filename": original_name or path.name,
            "analyzed_packets": min(packet_count, MAX_PACKETS),
            "packet_limit_reached": packet_count > MAX_PACKETS,
            "first_seen": _iso_time(first_timestamp),
            "last_seen": _iso_time(last_timestamp),
            "duration_seconds": round(duration, 3),
        },
        "summary": {
            "packets": min(packet_count, MAX_PACKETS),
            "devices": len(host_counts),
            "protocols": len(protocol_counts),
            "alerts": len(alerts),
        },
        "protocols": [
            {"name": name, "count": count}
            for name, count in protocol_counts.most_common()
        ],
        "top_hosts": top_hosts,
        "top_conversations": top_conversations,
        "timeline": timeline_points,
        "alerts": alerts,
    }
