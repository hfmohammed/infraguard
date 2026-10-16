import json
from pathlib import Path

from infraguard.collectors.terraform_plan import TerraformPlanCollector


def test_collects_and_redacts_plan(tmp_path: Path) -> None:
    path = tmp_path / "fixture.json"
    path.write_text(json.dumps({"resource_changes": [{"address": "aws_s3_bucket.logs", "type": "aws_s3_bucket", "name": "logs", "change": {"actions": ["create"], "before": None, "after": {"bucket": "logs", "password": "hidden"}, "after_sensitive": {"password": True}}}]}))
    collector = TerraformPlanCollector(plan_json=path)
    resource = list(collector.collect())[0]
    assert resource.raw["change"]["after"]["password"] == "***REDACTED***"
    assert collector.changes()[0].address == "aws_s3_bucket.logs"


def test_requires_exactly_one_source(tmp_path: Path) -> None:
    try:
        TerraformPlanCollector()
    except ValueError as error:
        assert "exactly one" in str(error)
    else:
        raise AssertionError("collector accepted no source")

