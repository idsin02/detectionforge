
from typing import Any, Literal

from pydantic import BaseModel, Field


class AttackResult(BaseModel):
    provider: str
    status: Literal["success", "failed", "skipped"]
    details: dict[str, Any] = Field(default_factory=dict)


class TelemetryResult(BaseModel):
    collector: str
    status: Literal["success", "failed", "skipped"]
    event_count: int = 0
    details: dict[str, Any] = Field(default_factory=dict)


class DetectionMatch(BaseModel):
    name: str
    rule_id: str | None = None
    severity: str | None = None
    matched: bool = False
    details: dict[str, Any] = Field(default_factory=dict)


class ValidationResult(BaseModel):
    backend: str
    status: Literal["pass", "fail", "skipped"]
    matches: list[DetectionMatch] = Field(default_factory=list)
    gaps: list[str] = Field(default_factory=list)
    details: dict[str, Any] = Field(default_factory=dict)


class ForgeResult(BaseModel):
    scenario_id: str
    scenario_name: str
    status: Literal["pass", "fail", "skipped"]
    attack: AttackResult
    telemetry: TelemetryResult
    validation: ValidationResult
