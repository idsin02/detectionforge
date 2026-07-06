from detectionforge.models.result import (
    AttackResult,
    DetectionMatch,
    ForgeResult,
    TelemetryResult,
    ValidationResult,
)


result = ForgeResult(
    scenario_id="DF-0001",
    scenario_name="Suspicious PowerShell",
    status="pass",
    attack=AttackResult(
        provider="atomic",
        status="success",
    ),
    telemetry=TelemetryResult(
        collector="evtx",
        status="success",
        event_count=42,
    ),
    validation=ValidationResult(
        backend="hayabusa",
        status="pass",
        matches=[
            DetectionMatch(
                name="Suspicious PowerShell Execution",
                rule_id="sigma-001",
                severity="high",
                matched=True,
            )
        ],
    ),
)

print(result.model_dump())
