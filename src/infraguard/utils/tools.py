"""Safe external-tool discovery and execution."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

from infraguard.errors import ToolError, ToolNotFoundError


def which(name: str) -> Path:
    """Resolve a binary from the repository bin directory, then PATH."""
    local = Path.cwd() / "bin" / name
    if local.is_file() and local.stat().st_mode & 0o111:
        return local
    found = shutil.which(name)
    if found:
        return Path(found)
    raise ToolNotFoundError(f"{name} not found; run `make setup` to install required tools")


def run(
    cmd: list[str], timeout: float = 120, ok_codes: tuple[int, ...] = (0,), cwd: Path | None = None
) -> subprocess.CompletedProcess[str]:
    """Execute a command without a shell and enforce timeout and exit codes."""
    binary = which(cmd[0])
    result = subprocess.run(  # noqa: S603 - argv-only execution is intentional
        [str(binary), *cmd[1:]], cwd=cwd, capture_output=True, text=True, timeout=timeout, check=False
    )
    if result.returncode not in ok_codes:
        raise ToolError(f"{' '.join(cmd)} failed ({result.returncode}): {result.stderr.strip()}")
    return result

