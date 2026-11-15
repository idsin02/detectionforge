"""Discover and validate every ``rule.yml`` under the rules directory."""

from __future__ import annotations

import re
from collections.abc import Hashable, Iterable
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any, Final

import yaml
from pydantic import ValidationError

from detectionforge.attack import AttackCatalog, AttackStatus
from detectionforge.schema.manifest import ATTACK_ID_PATTERN, RuleManifest

__all__ = [
    "Issue",
    "Level",
    "RuleReport",
    "ValidationSummary",
    "discover_rules",
    "load_yaml",
    "validate_rule",
    "validate_tree",
]

MANIFEST_NAME: Final = "rule.yml"
SLUG_RE: Final = re.compile(r"^[a-z0-9][a-z0-9_-]*$")
_ATTACK_RE: Final = re.compile(ATTACK_ID_PATTERN)
_MAX_INPUT_REPR: Final = 60


class Level(StrEnum):
    ERROR = "error"
    WARNING = "warning"


@dataclass(frozen=True, slots=True)
class Issue:
    level: Level
    location: str
    message: str

    def render(self) -> str:
        return f"[{self.level.value}] {self.location}: {self.message}"


@dataclass(slots=True)
class RuleReport:
    path: Path
    manifest: RuleManifest | None = None
    issues: list[Issue] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return not any(i.level is Level.ERROR for i in self.issues)

    def error(self, location: str, message: str) -> None:
        self.issues.append(Issue(Level.ERROR, location, message))

    def warn(self, location: str, message: str) -> None:
        self.issues.append(Issue(Level.WARNING, location, message))


@dataclass(slots=True)
class ValidationSummary:
    reports: list[RuleReport]

    @property
    def failed(self) -> list[RuleReport]:
        return [r for r in self.reports if not r.passed]

    @property
    def ok(self) -> bool:
        return not self.failed


# ------------------------------------------------------------------ YAML loading


class _StrictLoader(yaml.SafeLoader):
    """SafeLoader that rejects duplicate mapping keys instead of silently overwriting."""


def _construct_mapping(loader: _StrictLoader, node: yaml.MappingNode) -> dict[Hashable, Any]:
    loader.flatten_mapping(node)
    mapping: dict[Hashable, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=True)
        if key in mapping:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                f"duplicate key '{key}'",
                key_node.start_mark,
            )
        mapping[key] = loader.construct_object(value_node, deep=True)
    return mapping


_StrictLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_mapping,
)


def load_yaml(path: Path) -> Any:
    """Load YAML safely, rejecting duplicate keys. Raises yaml.YAMLError / OSError."""
    with path.open(encoding="utf-8") as handle:
        return yaml.load(handle, Loader=_StrictLoader)  # noqa: S506 (_StrictLoader is SafeLoader)


# ------------------------------------------------------------------ helpers


def _format_loc(loc: Iterable[int | str]) -> str:
    parts: list[str] = []
    for item in loc:
        if isinstance(item, int):
            parts.append(f"[{item}]")
        else:
            parts.append(f".{item}" if parts else str(item))
    return "".join(parts) or "<root>"


_FIELD_PREFIX_RE: Final = re.compile(r"^([a-z_]+): (.+)$", re.DOTALL)
_UUID_HINT: Final = "generate one with: python -c 'import uuid; print(uuid.uuid4())'"
_NO_GOT_SUFFIX: Final = frozenset({"missing", "extra_forbidden", "string_type"})


def format_pydantic_error(err: Any) -> list[tuple[str, str]]:
    """Turn one Pydantic error into (location, message) pairs.

    Cross-field errors arrive at the model root as several ``field: message`` lines;
    they are split back out so each one points at its field.
    """
    location = _format_loc(err["loc"])
    message_text = str(err["msg"]).removeprefix("Value error, ")
    if location == "<root>" and err["type"] == "value_error":
        pairs: list[tuple[str, str]] = []
        for line in message_text.splitlines():
            match = _FIELD_PREFIX_RE.match(line)
            pairs.append((match.group(1), match.group(2)) if match else (location, line))
        return pairs
    return [_format_field_error(err)]


def _format_field_error(err: Any) -> tuple[str, str]:
    kind = str(err["type"])
    raw = err.get("input")
    message = str(err["msg"]).removeprefix("Value error, ")

    if kind == "missing":
        message = "field is required"
    elif kind == "extra_forbidden":
        message = "unknown field (typo?)"
    elif kind in {"uuid_parsing", "uuid_type"}:
        message = f"not a valid UUID ({_UUID_HINT})"
    elif kind == "string_type" and isinstance(raw, int | float) and not isinstance(raw, bool):
        message = f"expected a string but YAML read a number ({raw!r}); wrap it in quotes"

    show_input = (
        kind not in _NO_GOT_SUFFIX
        and isinstance(raw, str | int | float | bool)
        and repr(raw) not in message
    )
    if show_input:
        shown = repr(raw)
        if len(shown) > _MAX_INPUT_REPR:
            shown = shown[: _MAX_INPUT_REPR - 3] + "..."
        message = f"{message} (got {shown})"
    return _format_loc(err["loc"]), message


def discover_rules(rules_dir: Path) -> list[Path]:
    return sorted(p for p in rules_dir.rglob(MANIFEST_NAME) if p.is_file())


# ------------------------------------------------------------------ validation


def _check_layout(report: RuleReport, rules_dir: Path) -> str | None:
    """Enforce rules/<technique>/<slug>/rule.yml. Returns the technique dir name."""
    try:
        rel = report.path.relative_to(rules_dir)
    except ValueError:
        report.error("path", f"not inside {rules_dir}")
        return None
    expected_parts = 3  # <technique>/<slug>/rule.yml
    if len(rel.parts) != expected_parts:
        report.error("path", "must be rules/<attack_technique_id>/<rule_slug>/rule.yml")
        return None
    technique, slug, _ = rel.parts
    if not _ATTACK_RE.fullmatch(technique):
        report.error("path", f"directory '{technique}' is not an ATT&CK technique ID")
    if not SLUG_RE.fullmatch(slug):
        report.error("path", f"slug '{slug}' must be lowercase letters, digits, '-' or '_'")
    return technique


def _check_attack(report: RuleReport, manifest: RuleManifest, catalog: AttackCatalog) -> None:
    for idx, technique in enumerate(manifest.attack):
        status = catalog.status(technique)
        if status is AttackStatus.UNKNOWN:
            report.error(f"attack[{idx}]", f"{technique} does not exist in ATT&CK")
        elif status is AttackStatus.DEPRECATED:
            report.warn(f"attack[{idx}]", f"{technique} is deprecated or revoked in ATT&CK")


def validate_rule(
    path: Path,
    rules_dir: Path,
    catalog: AttackCatalog | None = None,
) -> RuleReport:
    report = RuleReport(path=path)
    technique_dir = _check_layout(report, rules_dir)

    try:
        data = load_yaml(path)
    except yaml.YAMLError as exc:
        mark = getattr(exc, "problem_mark", None)
        where = f"line {mark.line + 1}, col {mark.column + 1}" if mark else "yaml"
        problem = getattr(exc, "problem", None) or str(exc)
        report.error(where, f"YAML error: {problem}")
        return report
    except (OSError, UnicodeDecodeError) as exc:
        report.error("file", f"cannot read: {exc}")
        return report

    if not isinstance(data, dict):
        report.error("<root>", "rule.yml must be a YAML mapping")
        return report

    try:
        manifest = RuleManifest.model_validate(data, context={"rule_dir": path.parent})
    except ValidationError as exc:
        for err in exc.errors():
            for location, message in format_pydantic_error(err):
                report.error(location, message)
        return report

    report.manifest = manifest
    in_technique_dir = technique_dir is not None and _ATTACK_RE.fullmatch(technique_dir)
    if in_technique_dir and technique_dir not in manifest.attack:
        report.error("attack", f"rule lives under '{technique_dir}/' but that ID is not listed")
    if catalog is not None:
        _check_attack(report, manifest, catalog)
    return report


def validate_tree(rules_dir: Path, catalog: AttackCatalog | None = None) -> ValidationSummary:
    reports = [validate_rule(p, rules_dir, catalog) for p in discover_rules(rules_dir)]

    seen: dict[str, Path] = {}
    for report in reports:
        if report.manifest is None:
            continue
        rule_id = str(report.manifest.id)
        if rule_id in seen:
            report.error("id", f"duplicate id {rule_id} (also used by {seen[rule_id]})")
        else:
            seen[rule_id] = report.path

    for report in reports:
        manifest = report.manifest
        if manifest is not None and manifest.deprecated_by is not None:
            target = str(manifest.deprecated_by)
            if target not in seen:
                report.error("deprecated_by", f"no rule with id {target} in {rules_dir}")
    return ValidationSummary(reports)