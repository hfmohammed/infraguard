"""Terraform destructive-change analysis compatibility wrapper."""

from infraguard.models import Finding, Resource, ValidatorRun
from infraguard.policies.catalog import PolicyCatalog
from infraguard.validators.native import NativePolicyValidator


class TerraformPlanAnalyzer:
    """Run native Terraform plan risk checks."""

    name = "terraform_analyzer"

    def __init__(self, catalog: PolicyCatalog) -> None:
        self.native = NativePolicyValidator(catalog)

    def validate(self, resources: list[Resource]) -> tuple[list[Finding], ValidatorRun]:
        """Filter built-in findings to destructive plan checks."""
        findings, run = self.native.validate(resources)
        filtered = [finding for finding in findings if finding.policy_id.startswith("TF-PLAN-")]
        return filtered, run.model_copy(update={"name": self.name, "findings": len(filtered)})

