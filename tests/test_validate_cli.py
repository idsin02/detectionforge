"""Tests for rule discovery, `dforge validate`, ATT&CK check and schema export."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest
import yaml

from detectionforge.attack import INDEX_FILENAME, INDEX_FORMAT_VERSION, load_catalog
from detectionforge.cli import main
from detectionforge.schema.export import build_schema, render_schema
from detectionforge.validate import validate_tree

DATA = Path(__file__).parent / "data"
VALID = DATA / "rules_valid"
BROKEN = DATA / "rules_broken"
VALID_RULE = VALID / "T1003.006" / "dcsync-replication-request"


@pytest.fixture
def rules(tmp_path: Path) -> Path:
    target = tmp_path / "rules"
    shutil.copytree(VALID, target)
    return target


def run(capsys: pytest.CaptureFixture[str], *argv: str) -> tuple[int, str]:
    code = main(["validate", "--attack-check", "off", *argv])
    out = capsys.readouterr()
    return code, out.out + out.err


# ------------------------------------------------------------------ CLI


def test_valid_tree_passes(capsys: pytest.CaptureFixture[str]) -> None:
    code, output = run(capsys, "--rules-dir", str(VALID))
    assert code == 0
    assert "1 passed, 0 failed" in output


def test_broken_sample_fails_with_clear_messages(capsys: pytest.CaptureFixture[str]) -> None:
    code, output = run(capsys, "--rules-dir", str(BROKEN))
    assert code == 1
    assert "FAIL" in output
    for expected in (
        "id: not a valid UUID",
        "version: expected a string but YAML read a number (1.0)",
        "attack[0]: 'T1003.6' is not a valid ATT&CK technique ID",
        "severity: Input should be 'low', 'medium', 'high' or 'critical'",
        "owner: unknown field",
        "0 passed, 1 failed",
    ):
        assert expected in output, expected


def test_empty_rules_dir_is_ok(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    code, output = run(capsys, "--rules-dir", str(tmp_path))
    assert code == 0
    assert "No rule.yml files found" in output


def test_missing_rules_dir_is_usage_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code, _ = run(capsys, "--rules-dir", str(tmp_path / "nope"))
    assert code == 2


def test_no_command_prints_help(capsys: pytest.CaptureFixture[str]) -> None:
    assert main([]) == 0
    assert "usage: dforge" in capsys.readouterr().out


# ------------------------------------------------------------------ tree-level checks


def test_missing_fixture_file(rules: Path) -> None:
    rule = rules / "T1003.006" / "dcsync-replication-request"
    (rule / "tests" / "negative_entra_sync.json").unlink()
    summary = validate_tree(rules)
    assert not summary.ok
    assert any("file not found" in i.message for i in summary.reports[0].issues)


def test_directory_must_be_listed_in_attack(rules: Path) -> None:
    (rules / "T1003.006").rename(rules / "T1003.001")
    summary = validate_tree(rules)
    assert any("'T1003.001/'" in i.message for i in summary.reports[0].issues)


def test_bad_layout(rules: Path) -> None:
    (rules / "T1003.006" / "dcsync-replication-request").rename(rules / "T1003.006" / "Bad Slug")
    summary = validate_tree(rules)
    assert any("slug 'Bad Slug'" in i.message for i in summary.reports[0].issues)


def test_duplicate_ids(rules: Path) -> None:
    shutil.copytree(VALID_RULE, rules / "T1003.006" / "copy")
    summary = validate_tree(rules)
    assert sum("duplicate id" in i.message for r in summary.reports for i in r.issues) == 1


def test_deprecated_by_must_point_to_existing_rule(rules: Path) -> None:
    rule_yml = rules / "T1003.006" / "dcsync-replication-request" / "rule.yml"
    text = rule_yml.read_text(encoding="utf-8").replace("status: production", "status: deprecated")
    text += "deprecated_by: 11111111-1111-4111-8111-111111111111\n"
    rule_yml.write_text(text, encoding="utf-8")
    summary = validate_tree(rules)
    assert any("no rule with id" in i.message for i in summary.reports[0].issues)


def test_duplicate_yaml_keys_rejected(rules: Path) -> None:
    rule_yml = rules / "T1003.006" / "dcsync-replication-request" / "rule.yml"
    rule_yml.write_text(rule_yml.read_text(encoding="utf-8") + "severity: low\n", encoding="utf-8")
    summary = validate_tree(rules)
    assert any("duplicate key 'severity'" in i.message for i in summary.reports[0].issues)


def test_non_mapping_yaml(rules: Path) -> None:
    rule_yml = rules / "T1003.006" / "dcsync-replication-request" / "rule.yml"
    rule_yml.write_text("- just\n- a list\n", encoding="utf-8")
    summary = validate_tree(rules)
    assert any("must be a YAML mapping" in i.message for i in summary.reports[0].issues)


# ------------------------------------------------------------------ ATT&CK check (offline)


def _write_index(cache: Path, active: list[str], deprecated: list[str]) -> None:
    cache.mkdir(parents=True, exist_ok=True)
    (cache / INDEX_FILENAME).write_text(
        json.dumps(
            {
                "format": INDEX_FORMAT_VERSION,
                "source_sha256": "n/a",
                "attack_version": "test",
                "active": active,
                "deprecated": deprecated,
            }
        ),
        encoding="utf-8",
    )


def test_attack_auto_without_cache_skips(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code = main(
        ["validate", "--rules-dir", str(VALID), "--attack-cache-dir", str(tmp_path / "empty")]
    )
    assert code == 0
    assert "check skipped" in capsys.readouterr().out


def test_attack_require_without_cache_fails(tmp_path: Path) -> None:
    code = main(
        [
            "validate",
            "--rules-dir",
            str(VALID),
            "--attack-check",
            "require",
            "--attack-cache-dir",
            str(tmp_path / "empty"),
        ]
    )
    assert code == 2


def test_attack_unknown_id_fails(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    cache = tmp_path / "cache"
    _write_index(cache, active=["T1059"], deprecated=[])
    code = main(["validate", "--rules-dir", str(VALID), "--attack-cache-dir", str(cache)])
    out = capsys.readouterr()
    assert code == 1
    assert "T1003.006 does not exist in ATT&CK" in out.out


def test_attack_known_id_passes_and_deprecated_warns(tmp_path: Path) -> None:
    cache = tmp_path / "cache"
    _write_index(cache, active=["T1059"], deprecated=["T1003.006"])
    catalog = load_catalog(cache)
    assert catalog is not None
    summary = validate_tree(VALID, catalog)
    assert summary.ok
    assert any("deprecated or revoked" in i.message for i in summary.reports[0].issues)


# ------------------------------------------------------------------ JSON Schema export


def test_schema_export_is_current() -> None:
    committed = Path(__file__).parents[1] / "schema" / "rule_manifest.schema.json"
    assert committed.read_text(encoding="utf-8") == render_schema(), (
        "Run: python -m detectionforge.schema.export"
    )


def test_schema_accepts_valid_sample() -> None:
    jsonschema = pytest.importorskip("jsonschema")
    data = yaml.safe_load((VALID_RULE / "rule.yml").read_text(encoding="utf-8"))
    data = json.loads(json.dumps(data, default=str))
    jsonschema.validate(data, build_schema())