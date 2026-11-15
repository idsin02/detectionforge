"""Runner and `dforge test` behaviour, including the "altered expectation fails CI" proof."""

from __future__ import annotations

import json
import re
import shutil
from pathlib import Path

import pytest

from detectionforge.cli import main
from detectionforge.runner import run_tests

ROOT = Path(__file__).parents[1]
EXAMPLES = ROOT / "examples" / "rules"
RULE_KEY = "T1105/certutil-urlcache-download"
POSITIVE = "tests/positive_urlcache_download.json"


@pytest.fixture
def rules(tmp_path: Path) -> Path:
    target = tmp_path / "rules"
    shutil.copytree(EXAMPLES, target)
    return target


def rule_dir(rules: Path) -> Path:
    return rules / RULE_KEY


def set_expected(rules: Path, new: int, *, manifest: bool, fixture: bool) -> None:
    rd = rule_dir(rules)
    if manifest:
        path = rd / "rule.yml"
        text = path.read_text(encoding="utf-8")
        marker = f"file: {POSITIVE}\n    type: positive\n    expected_matches: 3"
        assert marker in text
        path.write_text(text.replace(marker, marker[:-1] + str(new)), encoding="utf-8")
    if fixture:
        path = rd / POSITIVE
        data = json.loads(path.read_text(encoding="utf-8"))
        data["expected_matches"] = new
        path.write_text(json.dumps(data), encoding="utf-8")


def dforge_test(capsys: pytest.CaptureFixture[str], *argv: str) -> tuple[int, str]:
    code = main(["test", *argv])
    out = capsys.readouterr()
    return code, out.out + out.err


# ------------------------------------------------------------------ happy path


def test_example_rule_passes(capsys: pytest.CaptureFixture[str]) -> None:
    code, output = dforge_test(capsys, "--rules-dir", str(EXAMPLES))
    assert code == 0, output
    assert "3 fixture(s): 3 passed, 0 failed, 0 error(s)" in output
    assert re.search(r"positive_urlcache_download\.json\s+3\s+3\s+PASS", output)


def test_report_has_contract_fields() -> None:
    report = run_tests(EXAMPLES)
    assert report.ok
    result = report.results[0]
    assert result.rule_id == "0b3d7a52-6f41-4c2e-9d8a-3e5f1c7b9a20"
    assert result.fixture == f"{RULE_KEY}/{POSITIVE}"
    assert (result.expected, result.actual, result.passed, result.engine) == (3, 3, True, "sqlite")
    assert result.duration_ms >= 0


def test_json_output(capsys: pytest.CaptureFixture[str]) -> None:
    code, output = dforge_test(capsys, "--rules-dir", str(EXAMPLES), "--json")
    assert code == 0
    data = json.loads(output)
    assert data["summary"] == {
        "total": 3,
        "passed": 3,
        "failed": 0,
        "errors": 0,
        "skipped": 0,
        "ok": True,
    }
    assert set(data["results"][0]) == {
        "rule_id",
        "fixture",
        "expected",
        "actual",
        "passed",
        "engine",
        "duration_ms",
    }


# ------------------------------------------------------------------ CI must fail


def test_altered_expected_matches_fails(rules: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Changing expected_matches consistently (rule.yml + fixture) gives a FAIL row."""
    set_expected(rules, 2, manifest=True, fixture=True)
    code, output = dforge_test(capsys, "--rules-dir", str(rules))
    assert code == 1
    assert re.search(r"positive_urlcache_download\.json\s+2\s+3\s+FAIL", output)
    assert "1 failed" in output


def test_fixture_only_change_is_caught(rules: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Editing only the fixture makes rule.yml and fixture disagree -> error, exit 1."""
    set_expected(rules, 5, manifest=False, fixture=True)
    code, output = dforge_test(capsys, "--rules-dir", str(rules))
    assert code == 1
    assert "rule.yml is invalid" in output
    assert "fixture says expected_matches=5" in output


def test_negative_fixture_that_matches_fails(rules: Path) -> None:
    path = rule_dir(rules) / "tests" / "negative_other_downloaders.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    data["events"].append(
        {"Image": "C:\\Windows\\System32\\certutil.exe", "CommandLine": "-urlcache http://x"}
    )
    path.write_text(json.dumps(data), encoding="utf-8")
    report = run_tests(rules)
    failed = report.failed
    assert len(failed) == 1
    assert (failed[0].expected, failed[0].actual) == (0, 1)


def test_broken_sigma_is_error_for_every_fixture(rules: Path) -> None:
    (rule_dir(rules) / "sigma.yml").write_text("title: x\n", encoding="utf-8")
    report = run_tests(rules)
    assert not report.ok
    assert all(r.actual is None and not r.passed for r in report.results)
    assert len(report.errors) == 3


def test_unlisted_fixture_is_error(rules: Path) -> None:
    extra = rule_dir(rules) / "tests" / "positive_sneaky.json"
    extra.write_text("{}", encoding="utf-8")
    report = run_tests(rules)
    assert any("not listed in rule.yml" in e.message for e in report.errors)


def test_invalid_fixture_content_is_error(rules: Path) -> None:
    path = rule_dir(rules) / "tests" / "negative_other_downloaders.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    data["events"] = [{"nested": {"a": 1}}]
    path.write_text(json.dumps(data), encoding="utf-8")
    report = run_tests(rules)
    assert any("negative_other_downloaders.json" in e.location for e in report.errors)


# ------------------------------------------------------------------ filters and options


@pytest.mark.parametrize(
    "rule_filter",
    [
        "certutil-urlcache-download",
        "T1105",
        RULE_KEY,
        "0b3d7a52-6f41-4c2e-9d8a-3e5f1c7b9a20",
        "certutil-*",
        "T1105/*",
    ],
)
def test_rule_filter_matches(rule_filter: str) -> None:
    report = run_tests(EXAMPLES, rule_filters=[rule_filter])
    assert len(report.results) == 3


def test_rule_filter_without_match_is_usage_error(capsys: pytest.CaptureFixture[str]) -> None:
    code, output = dforge_test(capsys, "--rules-dir", str(EXAMPLES), "--rule", "nope")
    assert code == 2
    assert "No rule matched" in output


def test_unknown_engine_is_rejected_by_cli() -> None:
    with pytest.raises(SystemExit) as exc:
        main(["test", "--engine", "kusto"])
    assert exc.value.code == 2


def test_missing_rules_dir(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    code, _ = dforge_test(capsys, "--rules-dir", str(tmp_path / "nope"))
    assert code == 2


def test_empty_rules_dir_passes(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    code, output = dforge_test(capsys, "--rules-dir", str(tmp_path))
    assert code == 0
    assert "No fixtures to run" in output


def test_deprecated_rule_is_skipped(rules: Path) -> None:
    replacement = rules / "T1105" / "replacement"
    shutil.copytree(rule_dir(rules), replacement)
    new_id = "33333333-3333-4333-8333-333333333333"
    for name in ("rule.yml", "sigma.yml"):
        path = replacement / name
        text = path.read_text(encoding="utf-8")
        path.write_text(text.replace("0b3d7a52-6f41-4c2e-9d8a-3e5f1c7b9a20", new_id), "utf-8")
    old = rule_dir(rules) / "rule.yml"
    text = old.read_text(encoding="utf-8").replace("status: experimental", "status: deprecated")
    old.write_text(text + f"deprecated_by: {new_id}\n", encoding="utf-8")

    report = run_tests(rules)
    assert report.ok, report.errors
    assert any("certutil-urlcache-download (deprecated)" in s for s in report.skipped)
    assert len(report.results) == 3


def test_field_mapping_file(rules: Path, tmp_path: Path) -> None:
    rd = rule_dir(rules)
    for path in (rd / "tests").glob("*.json"):
        data = json.loads(path.read_text(encoding="utf-8"))
        for event in data["events"]:
            if "Image" in event:
                event["NewProcessName"] = event.pop("Image")
        path.write_text(json.dumps(data), encoding="utf-8")

    unmapped = run_tests(rules, mappings_dir=tmp_path / "no-mappings")
    assert not unmapped.ok

    mappings = tmp_path / "mappings"
    mappings.mkdir()
    (mappings / "sysmon.yml").write_text("Image: NewProcessName\n", encoding="utf-8")
    mapped = run_tests(rules, mappings_dir=mappings)
    assert mapped.ok, [(r.fixture, r.actual) for r in mapped.results]


def test_invalid_mapping_file(rules: Path, tmp_path: Path) -> None:
    (tmp_path / "sysmon.yml").write_text("- not a mapping\n", encoding="utf-8")
    report = run_tests(rules, mappings_dir=tmp_path)
    assert not report.ok
    assert any("must map Sigma field names" in e.message for e in report.errors)