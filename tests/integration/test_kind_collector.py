import os
import shutil
import subprocess

import pytest

from infraguard.collectors.kubernetes_live import KubernetesLiveCollector


def cluster_available() -> bool:
    if not shutil.which("kubectl"):
        return False
    return (
        subprocess.run(
            ["kubectl", "--context", "kind-infraguard", "cluster-info"],
            capture_output=True,
            check=False,
        ).returncode
        == 0
    )


@pytest.mark.integration
def test_kind_inventory_contains_sample_namespaces() -> None:
    if not cluster_available():
        if os.getenv("CI") == "true":
            pytest.fail("kind-infraguard is required in CI")
        pytest.skip("kind-infraguard is not available")
    resources = list(KubernetesLiveCollector("kind-infraguard").collect())
    keys = {resource.ref.key() for resource in resources}
    assert "ig-compliant/Deployment/compliant-app" in keys
    assert "ig-noncompliant/Deployment/vulnerable-app" in keys
