
from detectionforge.interfaces.attack_provider import AttackProvider
from detectionforge.interfaces.detection_backend import DetectionBackend
from detectionforge.interfaces.telemetry_collector import TelemetryCollector
from detectionforge.models.result import ForgeResult
from detectionforge.models.scenario import Scenario


class ValidationEngine:
    def __init__(
        self,
        attack_provider: AttackProvider,
        telemetry_collector: TelemetryCollector,
        detection_backend: DetectionBackend,
    ) -> None:
        self.attack_provider = attack_provider
        self.telemetry_collector = telemetry_collector
        self.detection_backend = detection_backend

    def run(self, scenario: Scenario) -> ForgeResult:
        attack_result = self.attack_provider.run(scenario)
        telemetry_result = self.telemetry_collector.collect(scenario)
        validation_result = self.detection_backend.validate(
            scenario=scenario,
            telemetry=telemetry_result,
        )

        overall_status = "pass" if validation_result.status == "pass" else "fail"

        return ForgeResult(
            scenario_id=scenario.metadata.id,
            scenario_name=scenario.metadata.name,
            status=overall_status,
            attack=attack_result,
            telemetry=telemetry_result,
            validation=validation_result,
        )
