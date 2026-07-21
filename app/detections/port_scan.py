from collections import defaultdict, deque
from datetime import datetime, timezone
from typing import Any

from app.detections.base import DetectionRule


PORT_SCAN_WINDOW_SECONDS = 10
PORT_SCAN_UNIQUE_PORTS = 15


def _iso_time(timestamp: float) -> str:
    return datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat()


class PortScanRule(DetectionRule):
    rule_id = "RASED-NET-001"
    name = "Possible Port Scan"
    severity = "medium"

    def detect(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        events = context.get("tcp_port_events", [])

        grouped: dict[
            tuple[str, str],
            list[tuple[float, int]],
        ] = defaultdict(list)

        for timestamp, source, destination, port in events:
            grouped[(source, destination)].append((timestamp, port))

        alerts: list[dict[str, Any]] = []

        for (source, destination), items in grouped.items():
            items.sort(key=lambda item: item[0])
            window: deque[tuple[float, int]] = deque()

            for timestamp, port in items:
                window.append((timestamp, port))

                while (
                    window
                    and timestamp - window[0][0] > PORT_SCAN_WINDOW_SECONDS
                ):
                    window.popleft()

                unique_ports = sorted({item[1] for item in window})

                if len(unique_ports) >= PORT_SCAN_UNIQUE_PORTS:
                    alerts.append(
                        {
                            "id": f"{self.rule_id}-{len(alerts) + 1}",
                            "type": self.name,
                            "severity": self.severity,
                            "source": source,
                            "destination": destination,
                            "confidence": min(
                                99,
                                65 + len(unique_ports),
                            ),
                            "reason": (
                                f"{source} contacted {len(unique_ports)} "
                                f"unique ports on {destination} within "
                                f"{PORT_SCAN_WINDOW_SECONDS} seconds."
                            ),
                            "evidence": {
                                "unique_ports": len(unique_ports),
                                "sample_ports": unique_ports[:20],
                                "window_seconds": PORT_SCAN_WINDOW_SECONDS,
                                "first_seen": _iso_time(window[0][0]),
                                "last_seen": _iso_time(timestamp),
                            },
                        }
                    )
                    break

        return alerts