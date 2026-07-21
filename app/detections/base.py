from abc import ABC, abstractmethod
from typing import Any


class DetectionRule(ABC):
    rule_id: str
    name: str
    severity: str

    @abstractmethod
    def detect(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        """Analyze network data and return generated alerts."""
        raise NotImplementedError