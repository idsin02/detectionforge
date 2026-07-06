from abc import ABC, abstractmethod

from detectionforge.models.result import TelemetryResult
from detectionforge.models.scenario import Scenario


class TelemetryCollector(ABC):
    """Base class for telemetry collection plugins."""

    @abstractmethod
    def collect(self, scenario: Scenario) -> TelemetryResult:
        """Collect telemetry for the scenario."""
        raise NotImplementedError
