"""Unit tests for RuleManifest."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest
from pydantic import ValidationError

from detectionforge.schema.manifest import RuleManifest, RuleStatus

Data = dict[str, Any]


def base_manifest(**overrides: Any) -> Data:
    data: Data = {
        "id": "6f1c2a9e-3b7d-4c8e-9a51-2d4f8b0c7e13",
        "title": "Sample detection title",
        "version": "1.0.0",
        "status": "production",
        "author": "Dhruv Singh",
        "created": "2026-11-01",
        "modified": "2026-11-14",
        "attack": ["T1003.006"],
        "telemetry_contract": {
            "source": "windows-security",
            "event_ids": [4662],
            "required_fields": ["SubjectUserName"],
        },
        "severity": "high",
        "severity_rationale": "Exposes every credential hash in the domain.",
        "confidence": "medium",
        "confidence_rationale": "Sync tooling produces identical events.",
        "known_false_positives": ["Entra Connect"],
        "blind_spots": ["Needs DS-Access auditing"],
        "tuning_notes": ["Exclude sync accounts by SID"],
        "references": ["https://attack.mitre.org/techniques/T1003/006/"],
        "tests": [
            {"file": "tests/positive_a.json", "type": "positive", "expected_matches": 1},
            {"file": "tests/negative_a.json", "type": "negative", "expected_matches": 0},
            {"file": "tests/negative_b.json", "type": "negative", "expected_matches": 0},
        ],
    }
    data.update(overrides)
    return data


def errors_for(data: Data, **ctx: Any) -> str:
    with pytest.raises(ValidationError) as exc:
        RuleManifest.model_validate(data, context=ctx or None)
    return str(exc.value)


@pytest.fixture
def write_fixtures(tmp_path: Path) -> Callable[[Data], Path]:
    def _write(data: Data) -> Path:
        tests_dir = tmp_path / "tests"
        tests_dir.mkdir(exist_ok=True)
        for spec in data["tests"]:
            fixture = {
                "description": "t",
                "source": "synthetic",
                "expected_matches": spec["expected_matches"],
                "events": [],
            }
            (tmp_path / spec["file"]).write_text(json.dumps(fixture), encoding="utf-8")
        return tmp_path

    return _write


# ------------------------------------------------------------------ valid


def test_valid_manifest() -> None:
    manifest = RuleManifest.model_validate(base_manifest())
    assert manifest.status is RuleStatus.PRODUCTION
    assert manifest.attack == ["T1003.006"]


def test_valid_manifest_with_files_on_disk(write_fixtures: Callable[[Data], Path]) -> None:
    data = base_manifest()
    rule_dir = write_fixtures(data)
    RuleManifest.model_validate(data, context={"rule_dir": rule_dir})


def test_experimental_rule_may_have_no_tests() -> None:
    RuleManifest.model_validate(base_manifest(status="experimental", tests=[]))


def test_same_day_created_and_modified_is_allowed() -> None:
    RuleManifest.model_validate(base_manifest(created="2026-11-14", modified="2026-11-14"))


def test_manifest_is_immutable() -> None:
    manifest = RuleManifest.model_validate(base_manifest())
    with pytest.raises(ValidationError):
        manifest.title = "changed"  # type: ignore[misc]


# ------------------------------------------------------------------ invalid fields


@pytest.mark.parametrize(
    ("overrides", "expected"),
    [
        ({"id": "not-a-uuid"}, "id"),
        ({"title": "abc"}, "title"),
        ({"version": "1.0"}, "not a semantic version"),
        ({"version": "v1.0.0"}, "not a semantic version"),
        ({"version": 1.0}, "version"),
        ({"status": "stable"}, "status"),
        ({"author": ""}, "author"),
        ({"created": "14/11/2026"}, "created"),
        ({"modified": "2026-10-01"}, "modified: (2026-10-01) must be on or after created"),
        ({"attack": []}, "attack"),
        ({"attack": ["T1003.6"]}, "not a valid ATT&CK technique ID"),
        ({"attack": ["t1003"]}, "not a valid ATT&CK technique ID"),
        ({"attack": ["T1003", "T1003"]}, "duplicate entries"),
        ({"severity": "urgent"}, "severity"),
        ({"severity_rationale": "short"}, "severity_rationale"),
        ({"confidence": "certain"}, "confidence"),
        ({"confidence_rationale": ""}, "confidence_rationale"),
        ({"references": ["not-a-url"]}, "references"),
        ({"owner": "x"}, "Extra inputs are not permitted"),
    ],
)
def test_invalid_field(overrides: Data, expected: str) -> None:
    assert expected in errors_for(base_manifest(**overrides))


@pytest.mark.parametrize(
    "missing",
    ["id", "known_false_positives", "blind_spots", "telemetry_contract", "tests"],
)
def test_required_fields(missing: str) -> None:
    data = base_manifest()
    del data[missing]
    assert missing in errors_for(data)


@pytest.mark.parametrize(
    ("contract", "expected"),
    [
        ({"source": "x", "event_ids": [], "required_fields": ["a"]}, "event_ids"),
        ({"source": "x", "event_ids": [1, 1], "required_fields": ["a"]}, "duplicate"),
        ({"source": "x", "event_ids": [-1], "required_fields": ["a"]}, "event_ids"),
        ({"source": "x", "event_ids": [1], "required_fields": []}, "required_fields"),
        ({"source": "", "event_ids": [1], "required_fields": ["a"]}, "source"),
    ],
)
def test_invalid_telemetry_contract(contract: Data, expected: str) -> None:
    assert expected in errors_for(base_manifest(telemetry_contract=contract))


# ------------------------------------------------------------------ tests list


@pytest.mark.parametrize(
    ("spec", "expected"),
    [
        (
            {"file": "positive_a.json", "type": "positive", "expected_matches": 1},
            "must match tests/positive_",
        ),
        (
            {"file": "tests/../../evil.json", "type": "positive", "expected_matches": 1},
            "must match tests/positive_",
        ),
        (
            {"file": "tests/negative_x.json", "type": "positive", "expected_matches": 1},
            "is named 'negative_*' but type is 'positive'",
        ),
        (
            {"file": "tests/positive_x.json", "type": "positive", "expected_matches": 0},
            "must expect at least 1 match",
        ),
        (
            {"file": "tests/negative_x.json", "type": "negative", "expected_matches": 2},
            "must expect exactly 0 matches",
        ),
    ],
)
def test_invalid_test_spec(spec: Data, expected: str) -> None:
    assert expected in errors_for(base_manifest(status="experimental", tests=[spec]))


def test_duplicate_test_files() -> None:
    spec = {"file": "tests/positive_a.json", "type": "positive", "expected_matches": 1}
    assert "duplicate entries" in errors_for(base_manifest(tests=[spec, spec]))


@pytest.mark.parametrize(
    ("positives", "negatives"),
    [(0, 2), (1, 1), (1, 0), (0, 0)],
)
def test_production_requires_enough_tests(positives: int, negatives: int) -> None:
    tests = [
        {"file": f"tests/positive_{i}.json", "type": "positive", "expected_matches": 1}
        for i in range(positives)
    ] + [
        {"file": f"tests/negative_{i}.json", "type": "negative", "expected_matches": 0}
        for i in range(negatives)
    ]
    message = errors_for(base_manifest(tests=tests))
    assert f"found {positives} positive, {negatives} negative" in message


def test_missing_test_file_on_disk(write_fixtures: Callable[[Data], Path]) -> None:
    data = base_manifest()
    rule_dir = write_fixtures(data)
    (rule_dir / "tests" / "negative_b.json").unlink()
    assert "tests/negative_b.json file not found" in errors_for(data, rule_dir=rule_dir)


def test_fixture_expected_matches_mismatch(write_fixtures: Callable[[Data], Path]) -> None:
    data = base_manifest()
    rule_dir = write_fixtures(data)
    fixture = rule_dir / "tests" / "positive_a.json"
    fixture.write_text(json.dumps({"expected_matches": 3, "events": []}), encoding="utf-8")
    assert "fixture says expected_matches=3" in errors_for(data, rule_dir=rule_dir)


def test_fixture_invalid_json(write_fixtures: Callable[[Data], Path]) -> None:
    data = base_manifest()
    rule_dir = write_fixtures(data)
    (rule_dir / "tests" / "positive_a.json").write_text("{bad", encoding="utf-8")
    assert "invalid JSON" in errors_for(data, rule_dir=rule_dir)


# ------------------------------------------------------------------ deprecation


def test_deprecated_requires_deprecated_by() -> None:
    message = errors_for(base_manifest(status="deprecated"))
    assert "deprecated_by: required when status" in message


def test_deprecated_with_replacement_is_valid() -> None:
    replacement = uuid4()
    manifest = RuleManifest.model_validate(
        base_manifest(status="deprecated", deprecated_by=str(replacement), tests=[])
    )
    assert manifest.deprecated_by == replacement


def test_deprecated_by_cannot_be_self() -> None:
    data = base_manifest(status="deprecated")
    data["deprecated_by"] = data["id"]
    assert "cannot reference the rule's own id" in errors_for(data)


@pytest.mark.parametrize("status", ["experimental", "production"])
def test_deprecated_by_forbidden_unless_deprecated(status: str) -> None:
    message = errors_for(base_manifest(status=status, deprecated_by=str(uuid4())))
    assert "only allowed when status is 'deprecated'" in message


def test_all_cross_field_errors_reported_together() -> None:
    data = base_manifest(modified="2026-10-01", deprecated_by=str(uuid4()), tests=[])
    message = errors_for(data)
    assert "modified:" in message
    assert "deprecated_by:" in message
    assert "found 0 positive, 0 negative" in message