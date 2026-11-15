"""Rule manifest model (``rule.yml``) for DetectionForge.

The manifest is the single source of truth for a detection's metadata, ATT&CK
mapping, telemetry requirements and test inventory.

File-system checks (test fixtures exist, fixture ``expected_matches`` agrees with
the manifest) run only when a ``rule_dir`` is supplied through the Pydantic
validation context::

    RuleManifest.model_validate(data, context={"rule_dir": Path("rules/T1003.006/dcsync")})

Without that context the model validates structure only. ``dforge validate``
always supplies it.
"""

from __future__ import annotations

import json
import re
from datetime import date
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Any, Final, Self, TypeVar
from uuid import UUID

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    HttpUrl,
    ValidationInfo,
    field_validator,
    model_validator,
)

__all__ = [
    "ATTACK_ID_PATTERN",
    "SEMVER_PATTERN",
    "Confidence",
    "RuleManifest",
    "RuleStatus",
    "Severity",
    "TelemetryContract",
    "TestSpec",
    "TestType",
]

# Semantic Versioning 2.0.0 (official regex from semver.org, without the v prefix).
SEMVER_PATTERN: Final = (
    r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
    r"(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)"
    r"(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?"
    r"(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$"
)
ATTACK_ID_PATTERN: Final = r"^T\d{4}(\.\d{3})?$"
TEST_FILE_PATTERN: Final = r"^tests/(positive|negative)_[A-Za-z0-9][A-Za-z0-9_\-]*\.json$"

MIN_POSITIVE_PRODUCTION: Final = 1
MIN_NEGATIVE_PRODUCTION: Final = 2
MIN_RATIONALE_CHARS: Final = 10

_T = TypeVar("_T")

_SEMVER_RE: Final = re.compile(SEMVER_PATTERN)
_ATTACK_RE: Final = re.compile(ATTACK_ID_PATTERN)
_TEST_FILE_RE: Final = re.compile(TEST_FILE_PATTERN)


class RuleStatus(StrEnum):
    EXPERIMENTAL = "experimental"
    PRODUCTION = "production"
    DEPRECATED = "deprecated"


class Severity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Confidence(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class TestType(StrEnum):
    POSITIVE = "positive"
    NEGATIVE = "negative"


def _unique(values: list[_T]) -> list[_T]:
    seen: set[str] = set()
    dupes: set[str] = set()
    for value in values:
        key = str(value)
        if key in seen:
            dupes.add(key)
        seen.add(key)
    if dupes:
        raise ValueError(f"duplicate entries: {sorted(dupes)}")
    return values


def _attack_id(value: str) -> str:
    if not _ATTACK_RE.fullmatch(value):
        raise ValueError(
            f"'{value}' is not a valid ATT&CK technique ID (expected T#### or T####.###)"
        )
    return value


def _semver(value: str) -> str:
    if not _SEMVER_RE.fullmatch(value):
        raise ValueError(
            f"'{value}' is not a semantic version (expected MAJOR.MINOR.PATCH, e.g. 1.0.0; "
            "quote it in YAML so 1.0 is not read as a number)"
        )
    return value


NonEmptyStr = Annotated[str, Field(min_length=1)]
AttackId = Annotated[str, AfterValidator(_attack_id)]
Rationale = Annotated[str, Field(min_length=MIN_RATIONALE_CHARS)]

_STRICT_CONFIG: Final = ConfigDict(
    extra="forbid",
    frozen=True,
    str_strip_whitespace=True,
    use_enum_values=False,
)


class TelemetryContract(BaseModel):
    """What telemetry the rule needs in order to fire at all."""

    model_config = _STRICT_CONFIG

    source: NonEmptyStr = Field(
        description="Telemetry source, e.g. 'sysmon', 'windows-security', 'mde'."
    )
    event_ids: Annotated[list[Annotated[int, Field(ge=0)]], AfterValidator(_unique)] = Field(
        min_length=1, description="Event IDs the rule consumes."
    )
    required_fields: Annotated[list[NonEmptyStr], AfterValidator(_unique)] = Field(
        min_length=1, description="Flat field names that must be present in events."
    )


class TestSpec(BaseModel):
    """One fixture file and the number of matches the rule must produce on it."""

    __test__ = False  # stop pytest from collecting this class

    model_config = _STRICT_CONFIG

    file: str = Field(description="Path relative to the rule dir, e.g. tests/positive_1.json")
    type: TestType
    expected_matches: int = Field(ge=0)

    @field_validator("file")
    @classmethod
    def _file_shape(cls, value: str) -> str:
        if not _TEST_FILE_RE.fullmatch(value):
            raise ValueError(
                f"'{value}' must match tests/positive_<name>.json or tests/negative_<name>.json"
            )
        return value

    @model_validator(mode="after")
    def _type_consistency(self) -> Self:
        prefix = Path(self.file).name.split("_", 1)[0]
        if prefix != self.type.value:
            raise ValueError(f"file '{self.file}' is named '{prefix}_*' but type is '{self.type}'")
        if self.type is TestType.POSITIVE and self.expected_matches < 1:
            raise ValueError(f"positive test '{self.file}' must expect at least 1 match")
        if self.type is TestType.NEGATIVE and self.expected_matches != 0:
            raise ValueError(f"negative test '{self.file}' must expect exactly 0 matches")
        return self


class RuleManifest(BaseModel):
    """Schema for ``rules/<technique>/<slug>/rule.yml``."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        str_strip_whitespace=True,
        title="DetectionForge Rule Manifest",
        json_schema_extra={"$id": "https://github.com/DHRUxMAN/DetectionForge/rule_manifest"},
    )

    id: UUID
    title: str = Field(min_length=5, max_length=120)
    version: Annotated[str, AfterValidator(_semver)] = Field(
        description="Semantic version, e.g. 1.2.0",
        json_schema_extra={"pattern": SEMVER_PATTERN},
    )
    status: RuleStatus
    author: NonEmptyStr
    created: date
    modified: date

    attack: Annotated[list[AttackId], AfterValidator(_unique)] = Field(min_length=1)
    telemetry_contract: TelemetryContract

    severity: Severity
    severity_rationale: Rationale
    confidence: Confidence
    confidence_rationale: Rationale

    known_false_positives: list[NonEmptyStr]
    blind_spots: list[NonEmptyStr]
    tuning_notes: list[NonEmptyStr]
    references: Annotated[list[HttpUrl], AfterValidator(_unique)]

    tests: list[TestSpec]
    deprecated_by: UUID | None = None

    # ---------------------------------------------------------------- validators

    @field_validator("tests")
    @classmethod
    def _unique_test_files(cls, value: list[TestSpec]) -> list[TestSpec]:
        _unique([t.file for t in value])
        return value

    @model_validator(mode="after")
    def _cross_field(self, info: ValidationInfo) -> Self:
        """Run every cross-field rule and report all failures together.

        Each failure is one line formatted as ``<field>: <message>`` so callers
        can map it back to a field.
        """
        problems = [
            *self._check_dates(),
            *self._check_deprecation(),
            *self._check_production_tests(),
            *self._check_files_on_disk(info.context),
        ]
        if problems:
            raise ValueError("\n".join(problems))
        return self

    def _check_dates(self) -> list[str]:
        if self.modified < self.created:
            return [f"modified: ({self.modified}) must be on or after created ({self.created})"]
        return []

    def _check_deprecation(self) -> list[str]:
        if self.status is RuleStatus.DEPRECATED:
            if self.deprecated_by is None:
                return ["deprecated_by: required when status is 'deprecated'"]
            if self.deprecated_by == self.id:
                return ["deprecated_by: cannot reference the rule's own id"]
        elif self.deprecated_by is not None:
            return ["deprecated_by: only allowed when status is 'deprecated'"]
        return []

    def _check_production_tests(self) -> list[str]:
        if self.status is not RuleStatus.PRODUCTION:
            return []
        positives = sum(t.type is TestType.POSITIVE for t in self.tests)
        negatives = sum(t.type is TestType.NEGATIVE for t in self.tests)
        if positives < MIN_POSITIVE_PRODUCTION or negatives < MIN_NEGATIVE_PRODUCTION:
            return [
                f"tests: production rules need >= {MIN_POSITIVE_PRODUCTION} positive and "
                f">= {MIN_NEGATIVE_PRODUCTION} negative tests "
                f"(found {positives} positive, {negatives} negative)"
            ]
        return []

    def _check_files_on_disk(self, context: Any) -> list[str]:
        if not isinstance(context, dict) or context.get("rule_dir") is None:
            return []
        rule_dir = Path(context["rule_dir"]).resolve()
        problems: list[str] = []
        for spec in self.tests:
            path = (rule_dir / spec.file).resolve()
            if not path.is_relative_to(rule_dir):
                problems.append(f"tests: {spec.file} resolves outside the rule directory")
            elif not path.is_file():
                problems.append(f"tests: {spec.file} file not found")
            else:
                problems.extend(f"tests: {p}" for p in _fixture_agreement(spec, path))
        return problems


def _fixture_agreement(spec: TestSpec, path: Path) -> list[str]:
    """Cheap consistency check between manifest and fixture. Full parsing is in fixtures.py."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError) as exc:
        return [f"{spec.file}: cannot read ({exc})"]
    except json.JSONDecodeError as exc:
        return [f"{spec.file}: invalid JSON (line {exc.lineno}, col {exc.colno}: {exc.msg})"]
    if not isinstance(data, dict):
        return [f"{spec.file}: fixture must be a JSON object"]
    fixture_expected = data.get("expected_matches")
    if fixture_expected is not None and fixture_expected != spec.expected_matches:
        return [
            f"{spec.file}: fixture says expected_matches={fixture_expected} "
            f"but rule.yml says {spec.expected_matches}"
        ]
    return []