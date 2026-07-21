from typing import Any

from app.detections.base import DetectionRule
from app.detections.dns_spike import DnsSpikeRule
from app.detections.port_scan import PortScanRule


class DetectionEngine:
    def __init__(
        self,
        rules: list[DetectionRule] | None = None,
    ) -> None:
        self.rules = rules or [
            PortScanRule(),
            DnsSpikeRule(),
        ]

    def run(
        self,
        context: dict[str, Any],
    ) -> list[dict[str, Any]]:
        alerts: list[dict[str, Any]] = []

        for rule in self.rules:
            alerts.extend(rule.detect(context))

        return alerts