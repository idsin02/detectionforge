"""Query engines. Add new engines to ENGINES (Kusto arrives in Part 6)."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Final

from detectionforge.engines.base import Engine, EngineError, PreparedRule
from detectionforge.engines.sqlite import SQLiteEngine

__all__ = ["ENGINES", "Engine", "EngineError", "PreparedRule", "create_engine"]

ENGINES: Final[dict[str, type[Engine]]] = {
    SQLiteEngine.name: SQLiteEngine,
}


def create_engine(name: str, field_mapping: Mapping[str, str] | None = None) -> Engine:
    try:
        engine_cls = ENGINES[name]
    except KeyError as exc:
        available = ", ".join(sorted(ENGINES))
        raise EngineError(f"unknown engine '{name}' (available: {available})") from exc
    return engine_cls(field_mapping)