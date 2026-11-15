"""One pytest test per (rule, fixture) pair in rules/ and examples/rules/.

`pytest` therefore fails CI on any rule regression, and failures name the exact
rule and fixture, e.g. ``test_rule_fixture[T1105/certutil-urlcache-download/tests/...]``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Final

import pytest

from detectionforge.runner import Runner, TestCase, collect_cases

ROOT: Final = Path(__file__).parents[1]
RULE_TREES: Final = [ROOT / "rules", ROOT / "examples" / "rules"]
MAPPINGS: Final = ROOT / "mappings"

COLLECTIONS: Final = {tree: collect_cases(tree) for tree in RULE_TREES if tree.is_dir()}
CASES: Final = [case for collection in COLLECTIONS.values() for case in collection.cases]


@pytest.fixture(scope="module")
def runner() -> Runner:
    return Runner("sqlite", MAPPINGS)


@pytest.mark.parametrize("tree", list(COLLECTIONS), ids=lambda p: p.relative_to(ROOT).as_posix())
def test_rule_tree_has_no_errors(tree: Path) -> None:
    errors = COLLECTIONS[tree].errors
    assert not errors, "\n".join(f"{e.location}: {e.message}" for e in errors)


@pytest.mark.parametrize("case", CASES, ids=lambda c: c.fixture_label)
def test_rule_fixture(case: TestCase, runner: Runner) -> None:
    result, error = runner.run_case(case)
    assert error is None, f"{error.location}: {error.message}"
    assert result.passed, (
        f"{case.fixture_label}: expected {result.expected} match(es), got {result.actual}"
    )
