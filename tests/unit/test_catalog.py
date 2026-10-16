from infraguard.policies.catalog import PolicyCatalog


def test_catalog_loads_all_policies() -> None:
    catalog = PolicyCatalog.load()
    assert len(catalog) == 21
    assert catalog.get("K8S-SEC-001").severity.value == "CRITICAL"


def test_catalog_is_sorted() -> None:
    identifiers = [policy.id for policy in PolicyCatalog.load().all()]
    assert identifiers == sorted(identifiers)

