from detectionforge.interfaces.detection_backend import DetectionBackend
from detectionforge.models.result import DetectionMatch, TelemetryResult, ValidationResult
from detectionforge.models.scenario import Scenario


class DummyDetectionBackend(DetectionBackend):
    def validate(
        self,
        scenario: Scenario,
        telemetry: TelemetryResult,
    ) -> ValidationResult:
        return ValidationResult(
            backend=scenario.validation.backend,
            status="pass",
            matches=[
                DetectionMatch(
                    name="Dummy detection matched",
                    rule_id="dummy-001",
                    severity="medium",
                    matched=True,
                )
            ],
        )
