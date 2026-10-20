"""Safe external-tool discovery and execution."""

from __future__ import annotations

import shutil
import subprocess
from collections.abc import Mapping
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
    cmd: list[str],
    timeout: float = 120,
    ok_codes: tuple[int, ...] = (0,),
    cwd: Path | None = None,
    env: Mapping[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    """Execute a command without a shell and enforce timeout and exit codes."""
    binary = which(cmd[0])
    try:
        result = subprocess.run(
            [str(binary), *cmd[1:]],
            cwd=cwd,
            env=env,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (subprocess.TimeoutExpired, OSError) as error:
        raise ToolError(f"{cmd[0]} could not complete: {error}") from error
    if result.returncode not in ok_codes:
        raise ToolError(f"{' '.join(cmd)} failed ({result.returncode}): {result.stderr.strip()}")
    return result
