"""Command-line interface for DetectionForge (`dforge`).

Implemented: --version, validate, test.
Planned (later parts): evidence, coverage. They are not registered yet,
so the CLI never advertises functionality that does not exist.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Final

from detectionforge import __version__
from detectionforge.attack import (
    ATTACK_STIX_URL,
    AttackCatalog,
    AttackCatalogError,
    default_cache_dir,
    load_catalog,
    update_cache,
)
from detectionforge.engines import ENGINES, EngineError
from detectionforge.runner import DEFAULT_MAPPINGS_DIR, RunReport, run_tests
from detectionforge.validate import validate_tree

EXIT_OK: Final = 0
EXIT_FAILED: Final = 1
EXIT_USAGE: Final = 2


def _err(message: str) -> None:
    print(message, file=sys.stderr)


# ------------------------------------------------------------------ validate


def _resolve_catalog(args: argparse.Namespace) -> tuple[AttackCatalog | None, int | None]:
    """Returns (catalog, early_exit_code)."""
    mode: str = args.attack_check
    if mode == "off":
        return None, None
    cache_dir: Path = args.attack_cache_dir or default_cache_dir()
    catalog: AttackCatalog | None
    try:
        if args.update_attack_cache:
            print(f"Downloading ATT&CK bundle to {cache_dir} ...")
            catalog = update_cache(cache_dir, args.attack_url)
        else:
            catalog = load_catalog(cache_dir)
    except AttackCatalogError as exc:
        _err(f"ATT&CK check: {exc}")
        return None, (EXIT_USAGE if mode == "require" else None)

    if catalog is None:
        hint = "run `dforge validate --update-attack-cache` once (needs network)"
        if mode == "require":
            _err(f"ATT&CK check required but no cache in {cache_dir}; {hint}.")
            return None, EXIT_USAGE
        print(f"Note: ATT&CK ID existence check skipped (no cache); {hint}.")
        return None, None

    version = catalog.attack_version or "unknown version"
    print(f"ATT&CK check: ON (Enterprise ATT&CK {version}, {len(catalog.active)} techniques)")
    return catalog, None


def cmd_validate(args: argparse.Namespace) -> int:
    rules_dir: Path = args.rules_dir
    if not rules_dir.is_dir():
        _err(f"Rules directory not found: {rules_dir}")
        return EXIT_USAGE

    catalog, early_exit = _resolve_catalog(args)
    if early_exit is not None:
        return early_exit

    summary = validate_tree(rules_dir, catalog)
    if not summary.reports:
        print(f"No rule.yml files found under {rules_dir}.")
        return EXIT_OK

    for report in summary.reports:
        label = "PASS" if report.passed else "FAIL"
        print(f"{label}  {report.path.as_posix()}")
        for issue in report.issues:
            print(f"      {issue.render()}")

    total = len(summary.reports)
    failed = len(summary.failed)
    print(f"\nValidated {total} rule(s): {total - failed} passed, {failed} failed.")
    return EXIT_OK if summary.ok else EXIT_FAILED


# ------------------------------------------------------------------ test


def _render_table(report: RunReport) -> str:
    headers = ("RULE / FIXTURE", "EXPECTED", "ACTUAL", "RESULT", "MS")
    rows = [
        (
            r.fixture,
            str(r.expected),
            "ERR" if r.actual is None else str(r.actual),
            "PASS" if r.passed else "FAIL",
            f"{r.duration_ms:.1f}",
        )
        for r in report.results
    ]
    widths = [max(len(h), *(len(row[i]) for row in rows)) for i, h in enumerate(headers)]

    def line(cells: Sequence[str]) -> str:
        fixture, expected, actual, result, ms = cells
        return "  ".join(
            [
                fixture.ljust(widths[0]),
                expected.rjust(widths[1]),
                actual.rjust(widths[2]),
                result.ljust(widths[3]),
                ms.rjust(widths[4]),
            ]
        )

    out = [line(headers), "  ".join("-" * w for w in widths)]
    out.extend(line(row) for row in rows)
    return "\n".join(out)


def cmd_test(args: argparse.Namespace) -> int:
    rules_dir: Path = args.rules_dir
    if not rules_dir.is_dir():
        _err(f"Rules directory not found: {rules_dir}")
        return EXIT_USAGE
    filters: list[str] = args.rule or []

    try:
        report = run_tests(rules_dir, args.engine, filters, args.mappings_dir)
    except EngineError as exc:
        _err(f"Engine '{args.engine}' unavailable: {exc}")
        return EXIT_USAGE

    if filters and not report.results and not report.errors and not report.skipped:
        _err(f"No rule matched --rule {' '.join(filters)}")
        return EXIT_USAGE

    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
        return EXIT_OK if report.ok else EXIT_FAILED

    print(f"Engine: {report.engine} ({report.engine_version})\n")
    if report.results:
        print(_render_table(report))
    else:
        print(f"No fixtures to run under {rules_dir}.")
    for item in report.skipped:
        print(f"SKIP  {item}")
    if report.errors:
        print("\nErrors:")
        for error in report.errors:
            print(f"  [error] {error.location}: {error.message}")

    passed = len(report.results) - len(report.failed)
    print(
        f"\n{len(report.results)} fixture(s): {passed} passed, {len(report.failed)} failed, "
        f"{len(report.errors)} error(s), {len(report.skipped)} skipped."
    )
    return EXIT_OK if report.ok else EXIT_FAILED


# ------------------------------------------------------------------ parser


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dforge",
        description="DetectionForge: validate, test, and release detections as code.",
    )
    parser.add_argument("--version", action="version", version=f"dforge {__version__}")
    sub = parser.add_subparsers(dest="command", metavar="<command>")

    validate = sub.add_parser("validate", help="validate every rules/**/rule.yml manifest")
    validate.add_argument("--rules-dir", type=Path, default=Path("rules"))
    validate.add_argument(
        "--attack-check",
        choices=["auto", "require", "off"],
        default="auto",
        help="ATT&CK ID existence check: auto = use cache if present (default), "
        "require = fail without cache, off = skip",
    )
    validate.add_argument(
        "--attack-cache-dir",
        type=Path,
        default=None,
        help="cache dir (default: $DFORGE_CACHE_DIR or ~/.cache/detectionforge)",
    )
    validate.add_argument(
        "--update-attack-cache",
        action="store_true",
        help="download the Enterprise ATT&CK bundle before validating (network)",
    )
    validate.add_argument("--attack-url", default=ATTACK_STIX_URL, help=argparse.SUPPRESS)
    validate.set_defaults(func=cmd_validate)

    test = sub.add_parser("test", help="run every rule against its positive/negative fixtures")
    test.add_argument("--rules-dir", type=Path, default=Path("rules"))
    test.add_argument(
        "--engine",
        choices=sorted(ENGINES),
        default="sqlite",
        help="query engine (kusto is added in Part 6)",
    )
    test.add_argument(
        "--rule",
        action="append",
        metavar="FILTER",
        help="only run matching rules: id, slug, technique, <technique>/<slug> or a glob "
        "(repeatable)",
    )
    test.add_argument("--mappings-dir", type=Path, default=DEFAULT_MAPPINGS_DIR)
    test.add_argument("--json", action="store_true", help="print results as JSON")
    test.set_defaults(func=cmd_test)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command is None:
        parser.print_help()
        return EXIT_OK
    result: int = args.func(args)
    return result