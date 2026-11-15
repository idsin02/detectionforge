"""Smoke tests for the dforge CLI."""

from __future__ import annotations

import pytest

from detectionforge import __version__
from detectionforge.cli import main


def test_version_flag_prints_version(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert capsys.readouterr().out.strip() == f"dforge {__version__}"