"""Semantics of the SQLite engine: what matches, what does not, and what is rejected."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from detectionforge.engines import EngineError, create_engine
from detectionforge.engines.sqlite import SQLiteEngine
from detectionforge.fixtures import Fixture
from detectionforge.schema.manifest import RuleManifest

RULE_ID = "6f1c2a9e-3b7d-4c8e-9a51-2d4f8b0c7e13"


def manifest() -> RuleManifest:
    return RuleManifest.model_validate(
        {
            "id": RULE_ID,
            "title": "Engine semantics test",
            "version": "0.1.0",
            "status": "experimental",
            "author": "t",
            "created": "2026-11-15",
            "modified": "2026-11-15",
            "attack": ["T1059"],
            "telemetry_contract": {"source": "s", "event_ids": [1], "required_fields": ["a"]},
            "severity": "low",
            "severity_rationale": "test rationale",
            "confidence": "low",
            "confidence_rationale": "test rationale",
            "known_false_positives": [],
            "blind_spots": [],
            "tuning_notes": [],
            "references": [],
            "tests": [],
        }
    )


def sigma(detection: str, rule_id: str = RULE_ID) -> str:
    return (
        "title: semantics\n"
        f"id: {rule_id}\n"
        "logsource: {product: windows, category: process_creation}\n"
        "detection:\n"
        f"{detection}\n"
    )


def count(
    tmp_path: Path,
    detection: str,
    events: list[dict[str, Any]],
    mapping: dict[str, str] | None = None,
) -> int:
    (tmp_path / "sigma.yml").write_text(sigma(detection), encoding="utf-8")
    engine = SQLiteEngine(mapping)
    prepared = engine.prepare(tmp_path, manifest())
    fixture = Fixture(description="d", source="s", expected_matches=0, events=events)
    return engine.run(prepared, fixture)


# ------------------------------------------------------------------ matching semantics


def test_string_match_is_case_insensitive(tmp_path: Path) -> None:
    det = "  s: {Image|endswith: '\\\\certutil.exe', User: 'admin'}\n  condition: s"
    events = [
        {"Image": "C:\\WINDOWS\\CERTUTIL.EXE", "User": "ADMIN"},
        {"Image": "c:\\windows\\certutil.exe", "User": "Admin"},
        {"Image": "c:\\windows\\certutil.exe.bak", "User": "admin"},
    ]
    assert count(tmp_path, det, events) == 2


def test_missing_field_is_null_and_never_matches(tmp_path: Path) -> None:
    det = "  s: {CommandLine|contains: 'x'}\n  condition: s"
    assert count(tmp_path, det, [{"Image": "a"}, {"Image": "b"}]) == 0


def test_field_referenced_by_rule_but_absent_from_all_events(tmp_path: Path) -> None:
    det = "  s: {Image: 'a'}\n  f: {ParentImage|endswith: 'x'}\n  condition: s and not f"
    assert count(tmp_path, det, [{"Image": "a"}]) == 1


def test_null_and_exists_modifiers(tmp_path: Path) -> None:
    events = [{"Image": "a", "Extra": "v"}, {"Image": "b"}]
    assert count(tmp_path, "  s: {Extra: null}\n  condition: s", events) == 1
    assert count(tmp_path, "  s: {Extra|exists: true}\n  condition: s", events) == 1


def test_numbers_compare_numerically(tmp_path: Path) -> None:
    det = "  s: {Count|gt: 5}\n  condition: s"
    assert count(tmp_path, det, [{"Count": 10}, {"Count": 3}, {"Count": 5}]) == 1


def test_number_in_rule_does_not_match_string_in_fixture(tmp_path: Path) -> None:
    det = "  s: {EventID: 4662}\n  condition: s"
    assert count(tmp_path, det, [{"EventID": 4662}, {"EventID": "4662"}]) == 1


def test_cased_modifier_is_case_sensitive(tmp_path: Path) -> None:
    det = "  s: {Image|cased: 'Evil.exe'}\n  condition: s"
    assert count(tmp_path, det, [{"Image": "Evil.exe"}, {"Image": "evil.exe"}]) == 1


def test_regex_is_unanchored_and_case_sensitive_by_default(tmp_path: Path) -> None:
    events = [{"CommandLine": "run -EncodedCommand AAAA"}, {"CommandLine": "run -encodedcommand"}]
    assert count(tmp_path, "  s: {CommandLine|re: '-Enc\\w+'}\n  condition: s", events) == 1
    assert count(tmp_path, "  s: {CommandLine|re|i: '-enc\\w+'}\n  condition: s", events) == 2


def test_windash_matches_slash_and_dash(tmp_path: Path) -> None:
    det = "  s: {CommandLine|windash|contains: '-urlcache'}\n  condition: s"
    events = [{"CommandLine": "x /urlcache"}, {"CommandLine": "x -urlcache"}, {"CommandLine": "x"}]
    assert count(tmp_path, det, events) == 2


def test_contains_all(tmp_path: Path) -> None:
    det = "  s: {CommandLine|contains|all: ['-a', '-b']}\n  condition: s"
    events = [{"CommandLine": "-a -b"}, {"CommandLine": "-a"}]
    assert count(tmp_path, det, events) == 1


def test_wildcards_and_like_metacharacters(tmp_path: Path) -> None:
    det = "  s: {Path: 'C:\\\\Users\\\\*\\\\100%_done.txt'}\n  condition: s"
    events = [
        {"Path": "C:\\Users\\bob\\100%_done.txt"},
        {"Path": "C:\\Users\\bob\\100X_done.txt"},
        {"Path": "C:\\Users\\bob\\1000_done.txt"},
    ]
    assert count(tmp_path, det, events) == 1


def test_one_of_and_boolean_logic(tmp_path: Path) -> None:
    det = "  s1: {A: 'x'}\n  s2: {B: 'y'}\n  f: {C: 'z'}\n  condition: 1 of s* and not f"
    events = [{"A": "x"}, {"B": "y", "C": "z"}, {"B": "y"}, {"C": "z"}]
    assert count(tmp_path, det, events) == 2


def test_field_mapping(tmp_path: Path) -> None:
    det = "  s: {Image|endswith: 'cmd.exe'}\n  condition: s"
    events = [{"NewProcessName": "C:\\cmd.exe"}, {"Image": "C:\\cmd.exe"}]
    assert count(tmp_path, det, events, mapping={"Image": "NewProcessName"}) == 1


def test_boolean_values(tmp_path: Path) -> None:
    det = "  s: {Elevated: true}\n  condition: s"
    assert count(tmp_path, det, [{"Elevated": True}, {"Elevated": False}]) == 1


# ------------------------------------------------------------------ rejected input


@pytest.mark.parametrize(
    ("detection", "message"),
    [
        ("  k: ['mimikatz']\n  condition: k", "Keyword search"),
        ("  s: {Image|expand: '%p%'}\n  condition: s", "placeholder"),
    ],
)
def test_unsupported_constructs_raise_engine_error(
    tmp_path: Path, detection: str, message: str
) -> None:
    with pytest.raises(EngineError, match=message):
        count(tmp_path, detection, [{"Image": "a"}])


def test_sigma_id_must_match_manifest(tmp_path: Path) -> None:
    other = "11111111-1111-4111-8111-111111111111"
    (tmp_path / "sigma.yml").write_text(
        sigma("  s: {A: 'x'}\n  condition: s", rule_id=other), encoding="utf-8"
    )
    with pytest.raises(EngineError, match=r"does not match rule\.yml id"):
        SQLiteEngine().prepare(tmp_path, manifest())


def test_missing_sigma_file(tmp_path: Path) -> None:
    with pytest.raises(EngineError, match=r"sigma\.yml not found"):
        SQLiteEngine().prepare(tmp_path, manifest())


def test_invalid_sigma(tmp_path: Path) -> None:
    (tmp_path / "sigma.yml").write_text("title: x\nlogsource: {}\n", encoding="utf-8")
    with pytest.raises(EngineError, match="invalid Sigma"):
        SQLiteEngine().prepare(tmp_path, manifest())


def test_multi_document_sigma_rejected(tmp_path: Path) -> None:
    one = sigma("  s: {A: 'x'}\n  condition: s")
    two = sigma("  s: {A: 'y'}\n  condition: s", rule_id="22222222-2222-4222-8222-222222222222")
    (tmp_path / "sigma.yml").write_text(one + "---\n" + two, encoding="utf-8")
    with pytest.raises(EngineError, match="exactly one detection rule"):
        SQLiteEngine().prepare(tmp_path, manifest())


def test_unknown_engine() -> None:
    with pytest.raises(EngineError, match="unknown engine 'kusto'"):
        create_engine("kusto")


def test_version_reports_components() -> None:
    version = SQLiteEngine().version()
    assert "pySigma" in version
    assert "SQLite" in version