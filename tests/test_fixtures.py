"""Fixture contract validation."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from detectionforge.fixtures import FixtureError, load_fixture


def write(tmp_path: Path, data: Any) -> Path:
    path = tmp_path / "positive_x.json"
    path.write_text(data if isinstance(data, str) else json.dumps(data), encoding="utf-8")
    return path


def base(**overrides: Any) -> dict[str, Any]:
    data: dict[str, Any] = {
        "description": "d",
        "source": "synthetic",
        "expected_matches": 1,
        "events": [{"Image": "a.exe", "EventID": 1, "Elevated": True, "Extra": None}],
    }
    data.update(overrides)
    return data


def test_valid_fixture(tmp_path: Path) -> None:
    fixture = load_fixture(write(tmp_path, base()))
    assert fixture.expected_matches == 1
    assert fixture.field_names() == ["Image", "EventID", "Elevated", "Extra"]


@pytest.mark.parametrize(
    ("data", "expected"),
    [
        (base(description=""), "description"),
        (base(source=""), "source"),
        (base(expected_matches=-1), "expected_matches"),
        (base(expected_matches="1"), "expected_matches"),
        (base(events=[]), "events"),
        (base(events=[{}]), "events[0] is empty"),
        (base(events=[{"A": {"nested": 1}}]), "events"),
        (base(events=[{"A": [1, 2]}]), "events"),
        (base(events=[{"Image": "a", "image": "b"}]), "differ only by case"),
        (base(events=[{"rowid": 1}]), "reserved SQLite column name"),
        (base(extra="x"), "unknown field"),
        ({"description": "d", "source": "s", "events": [{"a": 1}]}, "expected_matches"),
    ],
)
def test_invalid_fixture(tmp_path: Path, data: Any, expected: str) -> None:
    with pytest.raises(FixtureError) as exc:
        load_fixture(write(tmp_path, data))
    assert expected in str(exc.value)


def test_invalid_json(tmp_path: Path) -> None:
    with pytest.raises(FixtureError, match="invalid JSON"):
        load_fixture(write(tmp_path, "{bad"))


def test_duplicate_json_keys(tmp_path: Path) -> None:
    text = '{"description": "d", "description": "e", "source": "s", "expected_matches": 0}'
    with pytest.raises(FixtureError, match="duplicate JSON key 'description'"):
        load_fixture(write(tmp_path, text))


def test_missing_file(tmp_path: Path) -> None:
    with pytest.raises(FixtureError, match="file not found"):
        load_fixture(tmp_path / "nope.json")