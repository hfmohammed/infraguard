from pathlib import Path

import pytest

from infraguard.errors import ToolError, ToolNotFoundError
from infraguard.utils import tools


def test_which_finds_path_binary() -> None:
    assert tools.which("git").name == "git"


def test_which_raises_with_install_hint(monkeypatch) -> None:
    monkeypatch.setattr("shutil.which", lambda name: None)
    with pytest.raises(ToolNotFoundError, match="make setup"):
        tools.which("definitely-missing-infraguard-tool")


def test_run_captures_stdout() -> None:
    result = tools.run(["git", "--version"])
    assert result.stdout.startswith("git version")


def test_run_maps_unexpected_exit() -> None:
    with pytest.raises(ToolError, match="failed"):
        tools.run(["git", "show", "not-a-real-ref"])


def test_local_bin_takes_precedence(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    local = tmp_path / "bin" / "demo"
    local.parent.mkdir()
    local.write_text("#!/bin/sh\n")
    local.chmod(0o755)
    assert tools.which("demo") == local
