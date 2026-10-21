import json
from pathlib import Path

from infraguard.collectors.terraform_plan import TerraformPlanCollector


def test_collects_and_redacts_plan(tmp_path: Path) -> None:
    path = tmp_path / "fixture.json"
    path.write_text(
        json.dumps(
            {
                "resource_changes": [
                    {
                        "address": "aws_s3_bucket.logs",
                        "type": "aws_s3_bucket",
                        "name": "logs",
                        "change": {
                            "actions": ["create"],
                            "before": None,
                            "after": {"bucket": "logs", "password": "hidden"},
                            "after_sensitive": {"password": True},
                        },
                    }
                ]
            }
        )
    )
    collector = TerraformPlanCollector(plan_json=path)
    resource = next(iter(collector.collect()))
    assert resource.raw["change"]["after"]["password"] == "***REDACTED***"
    assert collector.changes()[0].address == "aws_s3_bucket.logs"
    assert "hidden" not in json.dumps(collector.plan())


def test_requires_exactly_one_source(tmp_path: Path) -> None:
    try:
        TerraformPlanCollector()
    except ValueError as error:
        assert "exactly one" in str(error)
    else:
        raise AssertionError("collector accepted no source")


def test_computed_bucket_ids_retain_configuration_references(tmp_path: Path) -> None:
    path = tmp_path / "fixture.json"
    path.write_text(
        json.dumps(
            {
                "configuration": {
                    "root_module": {
                        "resources": [
                            {
                                "address": "aws_s3_bucket_public_access_block.logs",
                                "expressions": {
                                    "bucket": {"references": ["aws_s3_bucket.logs.id"]},
                                    "nested_block": [{"value": True}],
                                },
                            }
                        ]
                    }
                },
                "resource_changes": [
                    {
                        "address": "aws_s3_bucket_public_access_block.logs",
                        "type": "aws_s3_bucket_public_access_block",
                        "name": "logs",
                        "change": {"actions": ["create"], "after": {}},
                    }
                ],
            }
        )
    )
    resource = next(iter(TerraformPlanCollector(plan_json=path).collect()))
    assert resource.raw["_references"]["bucket"] == ["aws_s3_bucket.logs.id"]


def test_temporary_plan_does_not_change_parent_environment(tmp_path, monkeypatch):
    import os
    from types import SimpleNamespace

    module = tmp_path / "module"
    module.mkdir()
    (module / "main.tf").write_text("# test module\n")
    before = dict(os.environ)
    commands = []

    def run(command, **kwargs):
        commands.append(command)
        assert kwargs["env"]["AWS_ACCESS_KEY_ID"] == "mock"
        assert dict(os.environ) == before
        return SimpleNamespace(stdout='{"resource_changes": []}')

    monkeypatch.setattr("infraguard.collectors.terraform_plan.run", run)
    assert TerraformPlanCollector(tf_dir=module).plan()["resource_changes"] == []
    assert [command[1] for command in commands] == ["init", "plan", "show"]
    assert list(module.iterdir()) == [module / "main.tf"]


def test_full_plan_redacts_planned_values_outputs_and_provider_constants(tmp_path):
    path = tmp_path / "fixture.json"
    path.write_text(
        json.dumps(
            {
                "configuration": {
                    "provider_config": {
                        "aws": {"expressions": {"secret_key": {"constant_value": "literal-secret"}}}
                    }
                },
                "planned_values": {
                    "outputs": {"token": {"value": "output-secret", "sensitive": True}},
                    "root_module": {
                        "resources": [
                            {
                                "values": {"password": "planned-secret"},
                                "sensitive_values": {"password": True},
                            }
                        ]
                    },
                },
                "resource_changes": [],
            }
        )
    )
    cleaned = json.dumps(TerraformPlanCollector(plan_json=path).plan())
    assert "literal-secret" not in cleaned
    assert "output-secret" not in cleaned
    assert "planned-secret" not in cleaned
