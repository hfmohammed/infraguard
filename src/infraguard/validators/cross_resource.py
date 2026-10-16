"""Cross-resource Kubernetes validation compatibility wrapper."""

from infraguard.models import Finding, Resource, ValidatorRun
from infraguard.policies.catalog import PolicyCatalog
from infraguard.validators.native import NativePolicyValidator


class CrossResourceValidator:
    """Check namespace-level network policy coverage."""

    name = "cross_resource"

    def __init__(self, catalog: PolicyCatalog) -> None:
        self.native = NativePolicyValidator(catalog)

    def validate(self, resources: list[Resource]) -> tuple[list[Finding], ValidatorRun]:
        """Return only cross-resource findings."""
        findings, run = self.native.validate(resources)
        filtered = [finding for finding in findings if finding.policy_id == "K8S-NET-002"]
        return filtered, run.model_copy(update={"name": self.name, "findings": len(filtered)})

