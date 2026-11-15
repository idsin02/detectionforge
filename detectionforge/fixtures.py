"""Load and validate test fixtures (``tests/positive_*.json`` / ``tests/negative_*.json``).

Fixture contract::

    {
      "description": str,          # what the events represent
      "source": str,               # where they came from (dataset + attribution)
      "expected_matches": int,     # how many events the rule must match
      "events": [ {flat field: scalar value}, ... ]
    }

Event values must be flat scalars (string, number, boolean or null). Nested
objects and arrays are rejected: flatten them first (e.g. ``Event.System.EventID``).
Value types matter: a number in the rule (``EventID: 4662``) only matches a JSON
number in the fixture, not the string ``"4662"``.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated, Any, Final

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from detectionforge.validate import format_pydantic_error

__all__ = ["Fixture", "FixtureError", "Scalar", "load_fixture"]

Scalar = str | int | float | bool | None
MAX_FIXTURE_BYTES: Final = 20 * 1024 * 1024  # 20 MiB; larger data belongs in datasets/
_RESERVED_FIELDS: Final = frozenset({"rowid", "oid", "_rowid_"})


class FixtureError(ValueError):
    """A fixture file is missing, unreadable or violates the contract."""

    def __init__(self, path: Path, problems: list[str]) -> None:
        self.path = path
        self.problems = problems
        super().__init__(f"{path.as_posix()}: " + "; ".join(problems))


class Fixture(BaseModel):
    """A validated fixture file."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    description: Annotated[str, Field(min_length=1)]
    source: Annotated[str, Field(min_length=1)]
    expected_matches: Annotated[int, Field(ge=0)]
    events: Annotated[list[dict[str, Scalar]], Field(min_length=1)]

    @field_validator("events")
    @classmethod
    def _check_events(cls, events: list[dict[str, Scalar]]) -> list[dict[str, Scalar]]:
        problems: list[str] = []
        for index, event in enumerate(events):
            if not event:
                problems.append(f"events[{index}] is empty")
            seen: dict[str, str] = {}
            for name in event:
                lowered = name.lower()
                if not name.strip():
                    problems.append(f"events[{index}] has an empty field name")
                elif lowered in _RESERVED_FIELDS:
                    problems.append(f"events[{index}].{name} is a reserved SQLite column name")
                elif lowered in seen:
                    problems.append(
                        f"events[{index}] has fields '{seen[lowered]}' and '{name}', which "
                        "differ only by case (field names are case-insensitive)"
                    )
                seen.setdefault(lowered, name)
        if problems:
            raise ValueError("; ".join(problems))
        return events

    def field_names(self) -> list[str]:
        """All field names across events, first spelling wins, in first-seen order."""
        names: dict[str, str] = {}
        for event in self.events:
            for name in event:
                names.setdefault(name.lower(), name)
        return list(names.values())


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key '{key}'")
        result[key] = value
    return result


def load_fixture(path: Path) -> Fixture:
    """Read and validate one fixture. Raises FixtureError with readable messages."""
    try:
        if path.stat().st_size > MAX_FIXTURE_BYTES:
            raise FixtureError(path, [f"larger than {MAX_FIXTURE_BYTES // (1024 * 1024)} MiB"])
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise FixtureError(path, ["file not found"]) from exc
    except (OSError, UnicodeDecodeError) as exc:
        raise FixtureError(path, [f"cannot read ({exc})"]) from exc

    try:
        data = json.loads(text, object_pairs_hook=_reject_duplicate_keys)
    except json.JSONDecodeError as exc:
        raise FixtureError(
            path, [f"invalid JSON (line {exc.lineno}, col {exc.colno}: {exc.msg})"]
        ) from exc
    except ValueError as exc:
        raise FixtureError(path, [str(exc)]) from exc

    try:
        return Fixture.model_validate(data)
    except ValidationError as exc:
        problems = [
            f"{loc}: {msg}" for err in exc.errors() for loc, msg in format_pydantic_error(err)
        ]
        raise FixtureError(path, problems) from exc