"""Run every rule's fixtures through an engine and collect TestResults."""

from __future__ import annotations

import fnmatch
import time
from collections.abc import Sequence
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Final

import yaml

from detectionforge.engines import Engine, EngineError, PreparedRule, create_engine
from detectionforge.fixtures import FixtureError, load_fixture
from detectionforge.schema.manifest import RuleManifest, RuleStatus, TestSpec
from detectionforge.validate import load_yaml, validate_tree

__all__ = [
    "Collection",
    "RunError",
    "RunReport",
    "Runner",
    "TestCase",
    "TestResult",
    "collect_cases",
    "run_tests",
]

DEFAULT_MAPPINGS_DIR: Final = Path("mappings")


@dataclass(frozen=True, slots=True)
class TestResult:
    """Outcome of one rule against one fixture. ``actual`` is None if it could not run."""

    __test__ = False

    rule_id: str
    fixture: str
    expected: int
    actual: int | None
    passed: bool
    engine: str
    duration_ms: float


@dataclass(frozen=True, slots=True)
class RunError:
    location: str
    message: str


@dataclass(frozen=True, slots=True)
class TestCase:
    """One (rule, fixture) pair to execute."""

    __test__ = False

    rule_dir: Path
    rule_key: str  # "<technique>/<slug>"
    manifest: RuleManifest
    spec: TestSpec

    @property
    def fixture_label(self) -> str:
        return f"{self.rule_key}/{self.spec.file}"


@dataclass(slots=True)
class Collection:
    cases: list[TestCase] = field(default_factory=list)
    errors: list[RunError] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)


@dataclass(slots=True)
class RunReport:
    engine: str
    engine_version: str
    results: list[TestResult] = field(default_factory=list)
    errors: list[RunError] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)

    @property
    def failed(self) -> list[TestResult]:
        return [r for r in self.results if not r.passed]

    @property
    def ok(self) -> bool:
        return not self.failed and not self.errors

    def to_dict(self) -> dict[str, Any]:
        return {
            "engine": self.engine,
            "engine_version": self.engine_version,
            "summary": {
                "total": len(self.results),
                "passed": len(self.results) - len(self.failed),
                "failed": len(self.failed),
                "errors": len(self.errors),
                "skipped": len(self.skipped),
                "ok": self.ok,
            },
            "results": [asdict(r) for r in self.results],
            "errors": [asdict(e) for e in self.errors],
            "skipped": list(self.skipped),
        }


# ------------------------------------------------------------------ collection


def _matches(filters: Sequence[str], rule_key: str, manifest: RuleManifest) -> bool:
    if not filters:
        return True
    technique, slug = rule_key.split("/", 1)
    candidates = {rule_key, technique, slug, str(manifest.id)}
    return any(
        f in candidates or fnmatch.fnmatchcase(rule_key, f) or fnmatch.fnmatchcase(slug, f)
        for f in filters
    )


def collect_cases(rules_dir: Path, rule_filters: Sequence[str] = ()) -> Collection:
    """Validate the tree and turn every (rule, listed fixture) into a TestCase."""
    collection = Collection()
    summary = validate_tree(rules_dir)
    for report in summary.reports:
        rule_dir = report.path.parent
        rule_key = rule_dir.relative_to(rules_dir).as_posix()
        if not report.passed or report.manifest is None:
            if not rule_filters or any(f in rule_key for f in rule_filters):
                first = next((i.render() for i in report.issues), "invalid")
                collection.errors.append(
                    RunError(rule_key, f"rule.yml is invalid, run `dforge validate` ({first})")
                )
            continue

        manifest = report.manifest
        if not _matches(rule_filters, rule_key, manifest):
            continue
        if manifest.status is RuleStatus.DEPRECATED:
            collection.skipped.append(f"{rule_key} (deprecated)")
            continue

        listed = {spec.file for spec in manifest.tests}
        tests_dir = rule_dir / "tests"
        on_disk = sorted(tests_dir.glob("*.json")) if tests_dir.is_dir() else []
        for path in on_disk:
            rel = path.relative_to(rule_dir).as_posix()
            if rel not in listed:
                collection.errors.append(
                    RunError(f"{rule_key}/{rel}", "fixture exists but is not listed in rule.yml")
                )
        if not manifest.tests:
            collection.skipped.append(f"{rule_key} (no tests listed)")
        collection.cases.extend(
            TestCase(rule_dir, rule_key, manifest, spec) for spec in manifest.tests
        )
    return collection


# ------------------------------------------------------------------ execution


def _load_mapping(mappings_dir: Path, source: str) -> dict[str, str]:
    path = mappings_dir / f"{source}.yml"
    if not path.is_file():
        return {}
    try:
        data = load_yaml(path)
    except (yaml.YAMLError, OSError, UnicodeDecodeError) as exc:
        raise EngineError(f"cannot read field mapping {path.as_posix()}: {exc}") from exc
    if data is None:
        return {}
    if not isinstance(data, dict) or not all(
        isinstance(k, str) and isinstance(v, str) and k and v for k, v in data.items()
    ):
        raise EngineError(f"{path.as_posix()} must map Sigma field names to fixture field names")
    return dict(data)


class Runner:
    """Executes TestCases, converting each rule once per engine/mapping."""

    def __init__(self, engine_name: str, mappings_dir: Path = DEFAULT_MAPPINGS_DIR) -> None:
        self.engine_name = engine_name
        self.mappings_dir = mappings_dir
        self._engines: dict[str, Engine] = {}
        self._prepared: dict[Path, PreparedRule | EngineError] = {}
        self.engine_version = create_engine(engine_name).version()

    def _engine_for(self, source: str) -> Engine:
        if source not in self._engines:
            mapping = _load_mapping(self.mappings_dir, source)
            self._engines[source] = create_engine(self.engine_name, mapping)
        return self._engines[source]

    def _prepare(self, case: TestCase) -> tuple[Engine, PreparedRule]:
        engine = self._engine_for(case.manifest.telemetry_contract.source)
        cached = self._prepared.get(case.rule_dir)
        if cached is None:
            try:
                cached = engine.prepare(case.rule_dir, case.manifest)
            except EngineError as exc:
                cached = exc
            self._prepared[case.rule_dir] = cached
        if isinstance(cached, EngineError):
            raise cached
        return engine, cached

    def run_case(self, case: TestCase) -> tuple[TestResult, RunError | None]:
        start = time.perf_counter()
        expected = case.spec.expected_matches
        actual: int | None = None
        error: RunError | None = None
        try:
            engine, prepared = self._prepare(case)
            fixture = load_fixture(case.rule_dir / case.spec.file)
            if fixture.expected_matches != expected:
                raise EngineError(
                    f"fixture expected_matches={fixture.expected_matches} "
                    f"but rule.yml says {expected}"
                )
            actual = engine.run(prepared, fixture)
        except FixtureError as exc:
            error = RunError(case.fixture_label, "; ".join(exc.problems))
        except EngineError as exc:
            error = RunError(case.fixture_label, str(exc))
        duration = round((time.perf_counter() - start) * 1000, 3)
        result = TestResult(
            rule_id=str(case.manifest.id),
            fixture=case.fixture_label,
            expected=expected,
            actual=actual,
            passed=error is None and actual == expected,
            engine=self.engine_name,
            duration_ms=duration,
        )
        return result, error


def run_tests(
    rules_dir: Path,
    engine_name: str = "sqlite",
    rule_filters: Sequence[str] = (),
    mappings_dir: Path = DEFAULT_MAPPINGS_DIR,
) -> RunReport:
    """Run every listed fixture of every (filtered) rule. Never raises for rule problems."""
    runner = Runner(engine_name, mappings_dir)
    collection = collect_cases(rules_dir, rule_filters)
    report = RunReport(
        engine=engine_name,
        engine_version=runner.engine_version,
        errors=list(collection.errors),
        skipped=list(collection.skipped),
    )
    for case in collection.cases:
        result, error = runner.run_case(case)
        report.results.append(result)
        if error is not None:
            report.errors.append(error)
    return report