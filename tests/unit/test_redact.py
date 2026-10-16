from infraguard.utils.redact import redact_manifest, redact_sensitive


def test_redacts_sensitive_environment_variables() -> None:
    source = {"kind": "Pod", "spec": {"containers": [{"env": [{"name": "API_TOKEN", "value": "secret"}, {"name": "MODE", "value": "prod"}]}]}}
    result = redact_manifest(source)
    assert result["spec"]["containers"][0]["env"][0]["value"] == "***REDACTED***"
    assert result["spec"]["containers"][0]["env"][1]["value"] == "prod"
    assert source["spec"]["containers"][0]["env"][0]["value"] == "secret"


def test_redacts_parallel_terraform_tree() -> None:
    assert redact_sensitive({"safe": "x", "password": "y"}, {"password": True}) == {"safe": "x", "password": "***REDACTED***"}

