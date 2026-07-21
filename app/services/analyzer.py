from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from scapy.all import DNS, DNSQR, IP, IPv6, TCP, UDP, PcapReader

from app.detections.engine import DetectionEngine


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

    if packet.lastlayer():
        return packet.lastlayer().name

    return "Other"


def _iso_time(timestamp: float | None) -> str | None:
    if timestamp is None:
        return None

    return datetime.fromtimestamp(
        timestamp,
        tz=timezone.utc,
    ).isoformat()


def analyze_pcap(
    path: Path,
    original_name: str | None = None,
) -> dict[str, Any]:
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

            if first_timestamp is None:
                first_timestamp = timestamp
            else:
                first_timestamp = min(
                    first_timestamp,
                    timestamp,
                )

            if last_timestamp is None:
                last_timestamp = timestamp
            else:
                last_timestamp = max(
                    last_timestamp,
                    timestamp,
                )

            timeline[int(timestamp)] += 1
            protocol_counts[_protocol_name(packet)] += 1

            source, destination = _ip_pair(packet)

            if source:
                host_counts[source] += 1

            if destination:
                host_counts[destination] += 1

            if source and destination:
                conversation_counts[
                    (source, destination)
                ] += 1

            if source and destination and TCP in packet:
                flags = int(packet[TCP].flags)

                is_syn = bool(flags & 0x02)
                is_ack = bool(flags & 0x10)

                if is_syn and not is_ack:
                    tcp_port_events.append(
                        (
                            timestamp,
                            source,
                            destination,
                            int(packet[TCP].dport),
                        )
                    )

            if source and DNS in packet and DNSQR in packet:
                raw_query = packet[DNSQR].qname

                if isinstance(raw_query, bytes):
                    query = raw_query.decode(
                        errors="replace",
                    ).rstrip(".")
                else:
                    query = str(raw_query).rstrip(".")

                dns_events.append(
                    (
                        timestamp,
                        source,
                        query,
                    )
                )

    detection_context = {
        "tcp_port_events": tcp_port_events,
        "dns_events": dns_events,
    }

    alerts = DetectionEngine().run(
        detection_context
    )

    severity_order = {
        "critical": 0,
        "high": 1,
        "medium": 2,
        "low": 3,
        "info": 4,
    }

    alerts.sort(
        key=lambda item: severity_order.get(
            item["severity"],
            99,
        )
    )

    duration = 0.0

    if (
        first_timestamp is not None
        and last_timestamp is not None
    ):
        duration = max(
            0.0,
            last_timestamp - first_timestamp,
        )

    top_hosts = [
        {
            "host": host,
            "packets": count,
        }
        for host, count in host_counts.most_common(10)
    ]

    top_conversations = [
        {
            "source": source,
            "destination": destination,
            "packets": count,
        }
        for (
            source,
            destination,
        ), count in conversation_counts.most_common(10)
    ]

    timeline_points = [
        {
            "timestamp": _iso_time(float(second)),
            "packets": count,
        }
        for second, count in sorted(
            timeline.items()
        )[:300]
    ]

    analyzed_packets = min(
        packet_count,
        MAX_PACKETS,
    )

    return {
        "meta": {
            "project": "Rased NDR",
            "version": "0.1.1",
            "filename": original_name or path.name,
            "analyzed_packets": analyzed_packets,
            "packet_limit_reached": (
                packet_count > MAX_PACKETS
            ),
            "first_seen": _iso_time(
                first_timestamp
            ),
            "last_seen": _iso_time(
                last_timestamp
            ),
            "duration_seconds": round(
                duration,
                3,
            ),
        },
        "summary": {
            "packets": analyzed_packets,
            "devices": len(host_counts),
            "protocols": len(protocol_counts),
            "alerts": len(alerts),
        },
        "protocols": [
            {
                "name": name,
                "count": count,
            }
            for name, count in protocol_counts.most_common()
        ],
        "top_hosts": top_hosts,
        "top_conversations": top_conversations,
        "timeline": timeline_points,
        "alerts": alerts,
    }