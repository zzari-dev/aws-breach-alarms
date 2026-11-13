"""Plans the Terraform module offline and checks it renders exactly what the catalog renders."""
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

import catalog

ROOT = Path(__file__).resolve().parent.parent
pytestmark = [pytest.mark.terraform, pytest.mark.skipif(not shutil.which("terraform"), reason="terraform not installed")]

PROVIDER = """
provider "aws" {
  region                      = "%(region)s"
  access_key                  = "test"
  secret_key                  = "test"
  skip_credentials_validation = true
  skip_requesting_account_id  = true
  skip_metadata_api_check     = true
}
"""


def _plan(tmp_path, module_args):
    (tmp_path / "main.tf").write_text(
        PROVIDER % {"region": module_args.get("region", "ap-northeast-2")}
        + 'module "alarms" {\n  source = "%s"\n%s}\n' % (
            os.path.relpath(ROOT, tmp_path),  # "../" sources are used in place, not copied
            "".join(f"  {k} = {json.dumps(v)}\n" for k, v in module_args.items() if k != "region")))
    env = {**os.environ, "TF_PLUGIN_CACHE_DIR": str(ROOT / ".cache" / "tf-plugins"), "TF_IN_AUTOMATION": "1"}
    (ROOT / ".cache" / "tf-plugins").mkdir(parents=True, exist_ok=True)
    run = lambda *a: subprocess.run(["terraform", *a], cwd=tmp_path, env=env, check=True, capture_output=True, text=True).stdout
    run("init", "-input=false", "-backend=false")
    run("plan", "-input=false", "-refresh=false", "-out=plan.tfplan")
    return json.loads(run("show", "-json", "plan.tfplan"))


def _resources(plan, type_):
    return {r["index"]: r for r in plan["resource_changes"] if r["type"] == type_}


def _module_args(config, **extra):
    return {
        "monitored_role_names": config["monitored_role_names"],
        "allowed_source_patterns": config["allowed_source_patterns"],
        "deployer_principal_patterns": config["deployer_principal_patterns"],
        **extra,
    }


@pytest.fixture(scope="module")
def home_plan(tmp_path_factory, test_config):
    return _plan(tmp_path_factory.mktemp("home"), _module_args(test_config, alert_emails=["security@example.com"]))


@pytest.fixture(scope="module")
def forwarder_plan(tmp_path_factory, test_config):
    return _plan(tmp_path_factory.mktemp("fwd"), _module_args(test_config, mode="forwarder", home_region="ap-northeast-2", region="us-east-1"))


def test_forwarder_renders_every_pattern_like_the_catalog(forwarder_plan, test_config):
    config = catalog.with_defaults({**test_config, "alert_topic_arn": ""})
    rules = _resources(forwarder_plan, "aws_cloudwatch_event_rule")
    for rule in catalog.load_rules():
        if rule["kind"] == "event":
            after = rules[rule["slug"]]["change"]["after"]
            assert json.loads(after["event_pattern"]) == catalog.render_pattern(rule, config), rule["slug"]
            assert after["state"] == rule["state"]
            assert after["name"] == f"breach-alarms-{rule['id'].lower()}-{rule['slug']}"


def test_forwarder_targets_the_home_region_bus_and_creates_no_topic(forwarder_plan):
    assert not _resources(forwarder_plan, "aws_sns_topic")
    forwarders = _resources(forwarder_plan, "aws_cloudwatch_event_target")
    assert set(forwarders) == {r["slug"] for r in catalog.load_rules() if r["kind"] == "event"}
    assert len(_resources(forwarder_plan, "aws_iam_role_policy")) == 1
    # The bus ARN embeds the account ID, which is only known after apply.
    for target in forwarders.values():
        assert target["change"]["after_unknown"]["arn"] and target["change"]["after_unknown"]["role_arn"]


def test_home_sends_the_catalog_message_to_sns(home_plan):
    targets = _resources(home_plan, "aws_cloudwatch_event_target")
    runbook = catalog.with_defaults({})["runbook_url"]
    for rule in catalog.load_rules():
        if rule["kind"] == "event":
            transformer = targets[rule["slug"]]["change"]["after"]["input_transformer"][0]
            assert transformer["input_template"] == catalog.message_template(rule, runbook), rule["slug"]
            assert transformer["input_paths"] == catalog.INPUT_PATHS


def test_home_creates_topic_email_subscription_dlq_and_delivery_alarm(home_plan):
    assert len(_resources(home_plan, "aws_sns_topic")) == 1
    subs = _resources(home_plan, "aws_sns_topic_subscription")
    assert [s["change"]["after"]["endpoint"] for s in subs.values()] == ["security@example.com"]
    assert len(_resources(home_plan, "aws_sqs_queue")) == 1
    alarms = [a["change"]["after"]["alarm_name"] for a in _resources(home_plan, "aws_cloudwatch_metric_alarm").values()]
    assert "breach-alarms-h1-delivery-failure" in alarms


def test_role_rules_are_skipped_without_monitored_roles(tmp_path, test_config):
    plan = _plan(tmp_path, _module_args({**test_config, "monitored_role_names": []}))
    rules = _resources(plan, "aws_cloudwatch_event_rule")
    assert "role-denied" not in rules and "role-offsite" not in rules and "remote-exec" in rules


EXISTING = "arn:aws:sns:ap-northeast-2:123456789012:existing-alarm-topic"


@pytest.fixture(scope="module")
def existing_topic_plan(tmp_path_factory, test_config):
    return _plan(tmp_path_factory.mktemp("existing"), _module_args(test_config, alert_topic_arn=EXISTING, alert_emails=["a@example.com"]))


def test_home_can_reuse_an_existing_topic_without_touching_it(existing_topic_plan, test_config):
    assert not _resources(existing_topic_plan, "aws_sns_topic")
    assert not _resources(existing_topic_plan, "aws_sns_topic_policy")
    assert not _resources(existing_topic_plan, "aws_sns_topic_subscription")
    targets = _resources(existing_topic_plan, "aws_cloudwatch_event_target")
    assert {t["change"]["after"]["arn"] for t in targets.values()} == {EXISTING}
    tamper = next(r for r in catalog.load_rules() if r["slug"] == "alarm-tamper")
    after = _resources(existing_topic_plan, "aws_cloudwatch_event_rule")["alarm-tamper"]["change"]["after"]
    assert json.loads(after["event_pattern"]) == catalog.render_pattern(tamper, catalog.with_defaults({**test_config, "alert_topic_arn": EXISTING}))


def test_home_omits_the_runbook_line_when_runbook_url_is_empty(tmp_path, test_config):
    plan = _plan(tmp_path, _module_args(test_config, runbook_url=""))
    rule = next(r for r in catalog.load_rules() if r["slug"] == "remote-exec")
    transformer = _resources(plan, "aws_cloudwatch_event_target")["remote-exec"]["change"]["after"]["input_transformer"][0]
    assert transformer["input_template"] == catalog.message_template(rule, "")
