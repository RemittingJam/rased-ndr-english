from collections import defaultdict, deque
from datetime import datetime, timezone
from typing import Any

from app.detections.base import DetectionRule


DNS_SPIKE_WINDOW_SECONDS = 10
DNS_SPIKE_QUERIES = 25


def _iso_time(timestamp: float) -> str:
    return datetime.fromtimestamp(
        timestamp,
        tz=timezone.utc,
    ).isoformat()


class DnsSpikeRule(DetectionRule):
    rule_id = "RASED-NET-002"
    name = "Unusual DNS Activity"
    severity = "low"

    def detect(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        events = context.get("dns_events", [])
        grouped = defaultdict(list)

        for timestamp, source, query in events:
            grouped[source].append((timestamp, query))

        alerts = []

        for source, items in grouped.items():
            items.sort(key=lambda item: item[0])
            window = deque()

            for timestamp, query in items:
                window.append((timestamp, query))

                while (
                    window
                    and timestamp - window[0][0]
                    > DNS_SPIKE_WINDOW_SECONDS
                ):
                    window.popleft()

                if len(window) >= DNS_SPIKE_QUERIES:
                    queries = [item[1] for item in window]

                    alerts.append({
                        "id": f"{self.rule_id}-{len(alerts) + 1}",
                        "type": self.name,
                        "severity": self.severity,
                        "source": source,
                        "destination": "DNS",
                        "confidence": min(98, 60 + len(window)),
                        "reason": (
                            f"{source} generated {len(window)} DNS queries "
                            f"within {DNS_SPIKE_WINDOW_SECONDS} seconds."
                        ),
                        "evidence": {
                            "query_count": len(window),
                            "sample_queries": queries[:10],
                            "window_seconds": DNS_SPIKE_WINDOW_SECONDS,
                            "first_seen": _iso_time(window[0][0]),
                            "last_seen": _iso_time(timestamp),
                        },
                    })
                    break

        return alerts