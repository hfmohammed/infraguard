"""Explicit validation modes; external-tool failures never trigger a fallback."""

from pathlib import Path

from infraguard.policies.catalog import PolicyCatalog
from infraguard.validators.base import Validator
from infraguard.validators.conftest import ConftestValidator
from infraguard.validators.cross_resource import CrossResourceValidator
from infraguard.validators.kubeconform import KubeconformValidator
from infraguard.validators.native import NativePolicyValidator
from infraguard.validators.terraform_analyzer import TerraformPlanAnalyzer


def build_validators(
    catalog: PolicyCatalog,
    *,
    offline: bool = False,
    policy_root: Path | None = None,
    skip_schema: bool = False,
) -> list[Validator]:
    """Use schema/Rego validation by default or the explicit native offline mode."""
    if offline:
        return [NativePolicyValidator(catalog)]
    return [
        *([] if skip_schema else [KubeconformValidator()]),
        ConftestValidator(catalog, policy_root),
        CrossResourceValidator(catalog),
        TerraformPlanAnalyzer(catalog),
    ]
