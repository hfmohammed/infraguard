import json
from pathlib import Path


def test_terraform_artifacts_are_ignored() -> None:
    content = Path(".gitignore").read_text()
    for pattern in ("*.tfplan", "*.tfstate", ".terraform/", "plan.json"):
        assert pattern in content


def test_iam_allow_statements_contain_no_write_actions() -> None:
    policy = json.loads(Path("iam/infraguard-readonly-policy.json").read_text())
    denied_prefixes = (
        "Put",
        "Create",
        "Delete",
        "Update",
        "Attach",
        "Detach",
        "Modify",
        "Authorize",
        "Revoke",
        "PassRole",
    )
    for statement in policy["Statement"]:
        if statement["Effect"] != "Allow":
            continue
        for action in statement["Action"]:
            verb = action.split(":", 1)[1]
            assert verb != "*" and not verb.endswith(":*")
            assert not verb.startswith(denied_prefixes)
