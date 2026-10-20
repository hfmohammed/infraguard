"""The CI cluster is required; local runs can explicitly skip without Docker."""

import os
import subprocess

import pytest

from infraguard.utils.tools import which


@pytest.fixture(scope="session")
def cluster_context():
    try:
        kubectl = which("kubectl")
        ready = (
            subprocess.run(
                [str(kubectl), "--context", "kind-infraguard", "cluster-info"],
                capture_output=True,
                timeout=20,
                check=False,
            ).returncode
            == 0
        )
    except Exception:
        ready = False
    if not ready:
        if os.getenv("CI") == "true":
            pytest.fail("kind-infraguard must be available in CI")
        pytest.skip("kind-infraguard is not available")
    return "kind-infraguard"
