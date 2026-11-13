import json
import shutil
import subprocess
from pathlib import Path

import pytest

import build_cfn
import catalog
from cfn_eval import Stack

TEMPLATE = Path(__file__).resolve().parent.parent / "cloudformation" / "template.json"
TOPIC = "arn:aws:sns:ap-northeast-2:123456789012:breach-alarms-alerts"
REFS = {
    "AWS::AccountId": "123456789012", "AWS::Region": "ap-northeast-2", "AWS::Partition": "aws",
    "AlertTopic": TOPIC, "DeadLetterQueue.Arn": "arn:aws:sqs:ap-northeast-2:123456789012:breach-alarms-dlq",
    "ForwarderRole.Arn": "arn:aws:iam::123456789012:role/breach-alarms-forwarder",
}


def _params(config, **extra):
    return {
        "NamePrefix": config["name_prefix"],
        "MonitoredRoleNames": ",".join(config["monitored_role_names"]),
        "AllowedSourcePatterns": ",".join(config["allowed_source_patterns"]),
        "DeployerPrincipalPatterns": ",".join(config["deployer_principal_patterns"]),
        **extra,
    }


def _rule_resources(stack):
    return {stack.eval(r["Properties"]["Name"]): r for lid, r in stack.t["Resources"].items()
            if r["Type"] == "AWS::Events::Rule" and stack.exists(lid)}


def test_committed_template_matches_the_generator():
    assert json.loads(TEMPLATE.read_text()) == build_cfn.build(), "run: make build"


def test_home_stack_renders_the_same_patterns_as_the_catalog(test_config):
    stack = Stack(build_cfn.build(), _params(test_config), REFS)
    rules = _rule_resources(stack)
    config = catalog.with_defaults(test_config)
    for rule in catalog.load_rules():
        if rule["kind"] != "event":
            continue
        resource = rules[f"breach-alarms-{rule['id'].lower()}-{rule['slug']}"]
        assert stack.eval(resource["Properties"]["EventPattern"]) == catalog.render_pattern(rule, config), rule["slug"]
        assert resource["Properties"]["State"] == rule["state"]


def test_home_stack_sends_readable_alerts_to_sns_with_a_dead_letter_queue(test_config):
    stack = Stack(build_cfn.build(), _params(test_config), REFS)
    rule = next(r for r in catalog.load_rules() if r["slug"] == "remote-exec")
    target = stack.eval(_rule_resources(stack)["breach-alarms-r3-remote-exec"]["Properties"]["Targets"])[0]
    assert target["Arn"] == TOPIC
    assert target["DeadLetterConfig"]["Arn"] == REFS["DeadLetterQueue.Arn"]
    assert target["InputTransformer"]["InputPathsMap"] == catalog.INPUT_PATHS
    assert target["InputTransformer"]["InputTemplate"] == catalog.message_template(rule, catalog.with_defaults({})["runbook_url"])


def test_forwarder_stack_forwards_to_the_home_bus_and_creates_no_topic(test_config):
    stack = Stack(build_cfn.build(), _params(test_config, Mode="forwarder", HomeRegion="ap-northeast-2"), REFS)
    assert not stack.exists("AlertTopic")
    target = stack.eval(_rule_resources(stack)["breach-alarms-r4-iam-persistence"]["Properties"]["Targets"])[0]
    assert target["Arn"] == "arn:aws:events:ap-northeast-2:123456789012:event-bus/default"
    assert target["RoleArn"] == REFS["ForwarderRole.Arn"]


def test_role_rules_are_not_created_without_monitored_roles(test_config):
    stack = Stack(build_cfn.build(), _params({**test_config, "monitored_role_names": []}), REFS)
    names = _rule_resources(stack)
    assert "breach-alarms-r1-role-denied" not in names and "breach-alarms-r2-role-offsite" not in names


def test_a_rule_can_be_switched_off(test_config):
    stack = Stack(build_cfn.build(), _params(test_config, EnableConsoleSignin="false"), REFS)
    assert "breach-alarms-r7-console-signin" not in _rule_resources(stack)


def test_waf_alarm_exists_only_when_a_web_acl_is_given(test_config):
    assert not Stack(build_cfn.build(), _params(test_config), REFS).exists("WafSpikeAlarm")
    assert not Stack(build_cfn.build(), _params(test_config, WafWebAclName="acl"), REFS).exists("WafSpikeAlarm")
    assert Stack(build_cfn.build(), _params(test_config, WafWebAclName="acl", WafRuleName="block-vuln-paths"), REFS).exists("WafSpikeAlarm")


@pytest.mark.skipif(not shutil.which("cfn-lint"), reason="cfn-lint not installed")
def test_template_passes_cfn_lint():
    result = subprocess.run(["cfn-lint", str(TEMPLATE)], capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr


EXISTING = "arn:aws:sns:ap-northeast-2:123456789012:existing-alarm-topic"


def test_home_stack_can_reuse_an_existing_topic(test_config):
    stack = Stack(build_cfn.build(), _params(test_config, ExistingTopicArn=EXISTING, AlertEmail="a@example.com"), REFS)
    assert not stack.exists("AlertTopic") and not stack.exists("AlertTopicPolicy") and not stack.exists("AlertSubscription")
    rules = _rule_resources(stack)
    assert stack.eval(rules["breach-alarms-r3-remote-exec"]["Properties"]["Targets"])[0]["Arn"] == EXISTING
    tamper = next(r for r in catalog.load_rules() if r["slug"] == "alarm-tamper")
    expected = catalog.render_pattern(tamper, catalog.with_defaults({**test_config, "alert_topic_arn": EXISTING}))
    assert stack.eval(rules["breach-alarms-r5b-alarm-tamper"]["Properties"]["EventPattern"]) == expected
    assert stack.eval(stack.t["Resources"]["DeliveryFailureAlarm"]["Properties"]["AlarmActions"]) == [EXISTING]


def test_home_stack_omits_the_runbook_line_when_runbook_url_is_empty(test_config):
    stack = Stack(build_cfn.build(), _params(test_config, RunbookUrl=""), REFS)
    rule = next(r for r in catalog.load_rules() if r["slug"] == "remote-exec")
    target = stack.eval(_rule_resources(stack)["breach-alarms-r3-remote-exec"]["Properties"]["Targets"])[0]
    assert target["InputTransformer"]["InputTemplate"] == catalog.message_template(rule, "")


def test_committed_template_fits_the_direct_upload_limit():
    # `aws cloudformation deploy` without --s3-bucket accepts at most 51,200 bytes.
    assert TEMPLATE.stat().st_size <= 51200
