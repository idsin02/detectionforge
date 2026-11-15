"""Engine interface: every query engine (SQLite now, Kusto in Part 6) implements this."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import ClassVar

from detectionforge.fixtures import Fixture
from detectionforge.schema.manifest import RuleManifest

__all__ = ["Engine", "EngineError", "PreparedRule"]


class EngineError(RuntimeError):
    """The engine could not convert or execute a rule. Message is user-facing."""


@dataclass(frozen=True, slots=True)
class PreparedRule:
    """A rule converted into an engine-specific query, ready to run against fixtures."""

    rule_id: str
    engine: str
    query: str
    required_fields: tuple[str, ...] = ()
    notes: tuple[str, ...] = field(default=())


class Engine(ABC):
    """Converts a rule once (``prepare``) and evaluates it per fixture (``run``)."""

    name: ClassVar[str]

    def __init__(self, field_mapping: Mapping[str, str] | None = None) -> None:
        # Sigma field name -> fixture field name. Applied during conversion.
        self.field_mapping: dict[str, str] = dict(field_mapping or {})

    @abstractmethod
    def version(self) -> str:
        """Human-readable versions of every component that affects results."""

    @abstractmethod
    def prepare(self, rule_dir: Path, manifest: RuleManifest) -> PreparedRule:
        """Convert the rule in ``rule_dir``. Raises EngineError on failure."""

    @abstractmethod
    def run(self, prepared: PreparedRule, fixture: Fixture) -> int:
        """Return how many fixture events the rule matches. Raises EngineError on failure."""
