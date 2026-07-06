
from typing import Any, Literal

from pydantic import BaseModel, Field


class Metadata(BaseModel):
    id: str
    name: str
    description: str
    version: str = "1.0"
    author: str
    tags: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)


class Environment(BaseModel):
    platform: Literal["windows", "linux", "macos"]
    hostname: str | None = None
    os: str | None = None
    architecture: str | None = None


class Attack(BaseModel):
    provider: str
    technique: str
    test: int | str | None = None
    timeout: int = 120
    parameters: dict[str, Any] = Field(default_factory=dict)


class Telemetry(BaseModel):
    collector: str
    sources: list[str]


class Validation(BaseModel):
    backend: str
    detections: dict[str, list[str]] = Field(default_factory=dict)


class Reporting(BaseModel):
    formats: list[Literal["json", "markdown", "html"]] = ["json"]
    output: str = "reports/"


class Scenario(BaseModel):
    metadata: Metadata
    environment: Environment
    attack: Attack
    telemetry: Telemetry
    validation: Validation
    reporting: Reporting = Field(default_factory=Reporting)
