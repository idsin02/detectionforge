from detectionforge.interfaces.telemetry_collector import TelemetryCollector
from detectionforge.models.result import TelemetryResult
from detectionforge.models.scenario import Scenario


class DummyTelemetryCollector(TelemetryCollector):
    def collect(self, scenario: Scenario) -> TelemetryResult:
        return TelemetryResult(
            collector=scenario.telemetry.collector,
            status="success",
            event_count=42,
        )
