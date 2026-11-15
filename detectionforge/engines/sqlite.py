"""SQLite engine: Sigma -> SQL via pySigma-backend-sqlite, executed on an in-memory table.

Semantics (pinned so results are deterministic):
- Table ``logs`` is created per fixture in a fresh ``:memory:`` database.
- One column per field seen in the fixture plus every field the rule references.
  Fields absent from an event are NULL.
- Columns have no type affinity, so JSON types are kept: numbers compare as numbers
  (``Count|gt: 5`` works), strings as strings. A JSON string "4662" does NOT equal
  the Sigma number 4662; write numbers as JSON numbers in fixtures.
- Columns use ``COLLATE NOCASE`` and SQLite ``LIKE`` is case-insensitive, so string
  matching is case-insensitive like Sigma. Both fold ASCII letters only.
- ``|cased`` becomes ``GLOB`` (case-sensitive).
- ``|re`` uses a REGEXP function backed by Python ``re.search`` (unanchored,
  case-sensitive unless the rule uses ``|re|i``).
"""

from __future__ import annotations

import json
import re
import sqlite3
from collections.abc import Mapping
from functools import lru_cache
from importlib import metadata
from pathlib import Path
from typing import Any, ClassVar, Final

from detectionforge.engines.base import Engine, EngineError, PreparedRule
from detectionforge.fixtures import Fixture
from detectionforge.schema.manifest import RuleManifest

__all__ = ["SIGMA_FILENAME", "SQLiteEngine"]

SIGMA_FILENAME: Final = "sigma.yml"
TABLE: Final = "logs"
_REGEX_CACHE_SIZE: Final = 512


@lru_cache(maxsize=_REGEX_CACHE_SIZE)
def _compile(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern)


def _regexp(pattern: str | None, value: Any) -> int:
    """SQLite calls ``regexp(pattern, value)`` for ``value REGEXP pattern``."""
    if pattern is None or value is None:
        return 0
    return 1 if _compile(pattern).search(str(value)) else 0


def _quote_ident(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


def _dist_version(name: str) -> str:
    try:
        return metadata.version(name)
    except metadata.PackageNotFoundError:
        return "not-installed"


class SQLiteEngine(Engine):
    name: ClassVar[str] = "sqlite"

    def __init__(self, field_mapping: Mapping[str, str] | None = None) -> None:
        super().__init__(field_mapping)
        try:
            # Imported here so `dforge validate` works even if pySigma is broken.
            from sigma.backends.sqlite.sqlite import sqliteBackend  # noqa: PLC0415
            from sigma.collection import SigmaCollection  # noqa: PLC0415
            from sigma.exceptions import SigmaError  # noqa: PLC0415
            from sigma.processing.pipeline import (  # noqa: PLC0415
                ProcessingItem,
                ProcessingPipeline,
            )
            from sigma.processing.transformations import (  # noqa: PLC0415
                FieldMappingTransformation,
            )
        except ImportError as exc:
            raise EngineError(
                'pySigma / pySigma-backend-sqlite are not installed: pip install -e ".[dev]"'
            ) from exc

        self._collection_cls: Any = SigmaCollection
        self._sigma_error: type[Exception] = SigmaError
        pipeline = None
        if self.field_mapping:
            mapping: dict[str | None, str | list[str]] = dict(self.field_mapping.items())
            pipeline = ProcessingPipeline(
                name="dforge field mapping",
                priority=50,
                items=[
                    ProcessingItem(
                        identifier="dforge_field_mapping",
                        transformation=FieldMappingTransformation(mapping),
                    )
                ],
            )
        backend_cls: Any = sqliteBackend  # backend ships without type hints
        self._backend: Any = backend_cls(processing_pipeline=pipeline)

    # ------------------------------------------------------------------ interface

    def version(self) -> str:
        return (
            f"pySigma {_dist_version('pysigma')}, "
            f"pySigma-backend-sqlite {_dist_version('pysigma-backend-sqlite')}, "
            f"SQLite {sqlite3.sqlite_version}"
        )

    def prepare(self, rule_dir: Path, manifest: RuleManifest) -> PreparedRule:
        sigma_path = rule_dir / SIGMA_FILENAME
        try:
            text = sigma_path.read_text(encoding="utf-8")
        except FileNotFoundError as exc:
            raise EngineError(f"{SIGMA_FILENAME} not found in {rule_dir.as_posix()}") from exc
        except (OSError, UnicodeDecodeError) as exc:
            raise EngineError(f"cannot read {sigma_path.as_posix()}: {exc}") from exc

        try:
            collection = self._collection_cls.from_yaml(text, collect_errors=True)
        except self._sigma_error as exc:
            raise EngineError(f"{SIGMA_FILENAME}: invalid Sigma: {exc}") from exc
        except Exception as exc:  # YAML parser errors surface as assorted types
            raise EngineError(f"{SIGMA_FILENAME}: cannot parse: {exc}") from exc
        if collection.errors:
            raise EngineError(
                f"{SIGMA_FILENAME}: invalid Sigma: " + "; ".join(map(str, collection.errors))
            )

        rules = list(collection.rules)
        if len(rules) != 1 or type(rules[0]).__name__ != "SigmaRule":
            raise EngineError(
                f"{SIGMA_FILENAME} must contain exactly one detection rule "
                "(correlation rules and multi-document files are not supported yet)"
            )
        sigma_rule = rules[0]
        if sigma_rule.id is not None and str(sigma_rule.id) != str(manifest.id):
            raise EngineError(
                f"{SIGMA_FILENAME} id {sigma_rule.id} does not match rule.yml id {manifest.id}"
            )

        try:
            converted = self._backend.convert(collection, "zircolite")
        except self._sigma_error as exc:
            raise EngineError(f"Sigma -> SQLite conversion failed: {exc}") from exc

        query, fields = self._parse_conversion(converted)
        return PreparedRule(
            rule_id=str(manifest.id),
            engine=self.name,
            query=query,
            required_fields=tuple(fields),
        )

    def run(self, prepared: PreparedRule, fixture: Fixture) -> int:
        columns = self._columns(fixture, prepared.required_fields)
        connection = sqlite3.connect(":memory:")
        try:
            connection.create_function("REGEXP", 2, _regexp, deterministic=True)
            column_sql = ", ".join(f"{_quote_ident(c)} COLLATE NOCASE" for c in columns)
            connection.execute(f"CREATE TABLE {TABLE} ({column_sql})")
            self._insert(connection, columns, fixture)
            row = connection.execute(f"SELECT COUNT(*) FROM ({prepared.query})").fetchone()  # noqa: S608
        except sqlite3.Error as exc:
            raise EngineError(f"SQLite execution failed: {exc} | query: {prepared.query}") from exc
        finally:
            connection.close()
        return int(row[0])

    # ------------------------------------------------------------------ helpers

    @staticmethod
    def _parse_conversion(converted: Any) -> tuple[str, list[str]]:
        try:
            payload = json.loads(converted) if isinstance(converted, str) else converted
            entry = payload[0]
            queries = entry["rule"]
            fields = [str(f) for f in entry.get("required_fields", [])]
        except (json.JSONDecodeError, KeyError, IndexError, TypeError) as exc:
            raise EngineError(f"unexpected backend output: {str(converted)[:200]}") from exc
        if entry.get("result_type", "event") != "event":
            raise EngineError("only event rules are supported (got a correlation plan)")
        if len(queries) != 1:
            raise EngineError(f"expected 1 SQL query, backend produced {len(queries)}")
        return str(queries[0]), fields

    @staticmethod
    def _columns(fixture: Fixture, required: tuple[str, ...]) -> list[str]:
        by_lower: dict[str, str] = {}
        for name in [*fixture.field_names(), *required]:
            by_lower.setdefault(name.lower(), name)
        return list(by_lower.values())

    @staticmethod
    def _insert(connection: sqlite3.Connection, columns: list[str], fixture: Fixture) -> None:
        lookup = [c.lower() for c in columns]
        placeholders = ", ".join("?" for _ in columns)
        names = ", ".join(_quote_ident(c) for c in columns)
        rows = []
        for event in fixture.events:
            lowered = {k.lower(): v for k, v in event.items()}
            rows.append(tuple(lowered.get(c) for c in lookup))
        connection.executemany(
            f"INSERT INTO {TABLE} ({names}) VALUES ({placeholders})",  # noqa: S608
            rows,
        )