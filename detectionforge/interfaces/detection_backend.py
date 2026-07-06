from abc import ABC, abstractmethod

from detectionforge.models.result import (
    TelemetryResult,
    ValidationResult,
)
from detectionforge.models.scenario import Scenario


class DetectionBackend(ABC):
    """Base class for detection validation plugins."""

    @abstractmethod
    def validate(
        self,
        scenario: Scenario,
        telemetry: TelemetryResult,
    ) -> ValidationResult:
        """Validate detections."""
        raise NotImplementedError
