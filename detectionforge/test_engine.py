from detectionforge.engine import ValidationEngine
from detectionforge.loader import load_scenario
from detectionforge.plugins.dummy.attack import DummyAttackProvider
from detectionforge.plugins.dummy.backend import DummyDetectionBackend
from detectionforge.plugins.dummy.collector import DummyTelemetryCollector


scenario = load_scenario("scenarios/suspicious_powershell.yaml")

engine = ValidationEngine(
    attack_provider=DummyAttackProvider(),
    telemetry_collector=DummyTelemetryCollector(),
    detection_backend=DummyDetectionBackend(),
)

result = engine.run(scenario)

print(result.model_dump())
