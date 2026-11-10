"""Generates cloudformation/template.json from the rule catalog. Run: make build"""
import json
from pathlib import Path

import catalog

OUT = Path(__file__).resolve().parent.parent / "cloudformation" / "template.json"


def camel(snake):
    return "".join(part.capitalize() for part in snake.replace("-", "_").split("_"))


def enable_param(rule):
    return "Enable" + camel(rule["slug"])


def rule_logical_id(rule):
    return "Rule" + camel(rule["slug"])


LIST_PARAMS = {
    "monitored_role_names": "Names of IAM roles to watch for R1/R2 (e.g. EC2 instance or ECS task roles). Empty disables R1/R2.",
    "allowed_source_patterns": "R2: source IP wildcards where monitored roles may be used, e.g. 203.0.113.10,10.*,*.amazonaws.com,AWS Internal. Empty disables R2.",
    "operator_principal_patterns": "R3: principal ARN wildcards allowed to run SSM commands, sessions and ECS Exec.",
    "deployer_principal_patterns": "R4/R6: principal ARN wildcards (CI, Terraform) whose IAM, sharing and bucket-policy changes are expected.",
}


def _token_value(name, need):
    if name == "name_prefix":
        return {"Ref": "NamePrefix"}
    if name == "alert_topic_arn":
        return {"Fn::If": ["IsHome", {"Ref": "AlertTopic"}, catalog.SENTINEL]}
    ref = {"Ref": camel(name)}
    return ref if need == "required" else {"Fn::If": ["Has" + camel(name), ref, [catalog.SENTINEL]]}


def _substitute(node, values):
    if isinstance(node, dict):
        return {k: _substitute(v, values) for k, v in node.items()}
    if isinstance(node, list):
        return [_substitute(v, values) for v in node]
    if isinstance(node, str) and catalog.TOKEN.match(node):
        return values[catalog.TOKEN.match(node).group(1)]
    return node


def _parameters(defaults, rules):
    params = {
        "Mode": {"Type": "String", "AllowedValues": ["home", "forwarder"], "Default": "home",
                 "Description": "home: sends alerts (deploy once). forwarder: forwards matched events to the home region."},
        "HomeRegion": {"Type": "String", "Default": "", "Description": "Forwarder only: the region of the home stack."},
        "NamePrefix": {"Type": "String", "Default": defaults["name_prefix"], "MinLength": 1, "AllowedPattern": "[A-Za-z0-9_.-]+",
                       "Description": "Prefix for resource names. R5b watches rules with this prefix."},
        "AlertEmail": {"Type": "String", "Default": "", "Description": "Home only: email address that receives alerts (confirm the subscription once)."},
        "RunbookUrl": {"Type": "String", "Default": defaults["runbook_url"], "Description": "Base URL of the runbook linked from alerts."},
    }
    for name, description in LIST_PARAMS.items():
        params[camel(name)] = {"Type": "CommaDelimitedList", "Default": ",".join(defaults[name]), "Description": description}
    for rule in rules:
        params[enable_param(rule)] = {"Type": "String", "AllowedValues": ["true", "false"], "Default": "true",
                                      "Description": f"Create {rule['id']} {rule['slug']}."}
    params.update({
        "WafWebAclName": {"Type": "String", "Default": "", "Description": "R8: WebACL name. Empty disables R8."},
        "WafRuleName": {"Type": "String", "Default": "", "Description": "R8: rule (metric) name inside the WebACL."},
        "WafThreshold": {"Type": "Number", "Default": 10, "Description": "R8: blocked requests per 5 minutes that trigger the alarm."},
        "KmsKeyArn": {"Type": "String", "Default": "", "Description": "Optional KMS key for the SNS topic and DLQ."},
    })
    return params


def _conditions(rules):
    conditions = {
        "IsHome": {"Fn::Equals": [{"Ref": "Mode"}, "home"]},
        "IsForwarder": {"Fn::Not": [{"Condition": "IsHome"}]},
        "HasAlertEmail": {"Fn::And": [{"Condition": "IsHome"}, {"Fn::Not": [{"Fn::Equals": [{"Ref": "AlertEmail"}, ""]}]}]},
        "HasKms": {"Fn::Not": [{"Fn::Equals": [{"Ref": "KmsKeyArn"}, ""]}]},
        "HasWafAlarm": {"Fn::And": [
            {"Condition": "IsHome"},
            {"Fn::Not": [{"Fn::Equals": [{"Ref": "WafWebAclName"}, ""]}]},
            {"Fn::Not": [{"Fn::Equals": [{"Ref": "WafRuleName"}, ""]}]},
        ]},
    }
    for name in LIST_PARAMS:
        conditions["Has" + camel(name)] = {"Fn::Not": [{"Fn::Equals": [{"Fn::Join": ["", {"Ref": camel(name)}]}, ""]}]}
    for rule in rules:
        required = [{"Condition": "Has" + camel(p)} for p, need in rule["params"].items() if need == "required" and p in LIST_PARAMS]
        enabled = {"Fn::Equals": [{"Ref": enable_param(rule)}, "true"]}
        conditions["Create" + camel(rule["slug"])] = {"Fn::And": [enabled, *required]} if required else enabled
    return conditions


def _rule_resource(rule):
    values = {name: _token_value(name, need) for name, need in rule["params"].items()}
    home_target = {
        "Id": "alert",
        "Arn": {"Ref": "AlertTopic"},
        "DeadLetterConfig": {"Arn": {"Fn::GetAtt": ["DeadLetterQueue", "Arn"]}},
        "InputTransformer": {
            "InputPathsMap": catalog.INPUT_PATHS,
            # Fn::Sub fills ${RunbookUrl} only; EventBridge fills the <placeholders>.
            "InputTemplate": {"Fn::Sub": catalog.message_template(rule, "${RunbookUrl}")},
        },
    }
    forward_target = {
        "Id": "forward",
        "Arn": {"Fn::Sub": "arn:${AWS::Partition}:events:${HomeRegion}:${AWS::AccountId}:event-bus/default"},
        "RoleArn": {"Fn::GetAtt": ["ForwarderRole", "Arn"]},
    }
    return {
        "Type": "AWS::Events::Rule",
        "Condition": "Create" + camel(rule["slug"]),
        "Properties": {
            "Name": {"Fn::Sub": f"${{NamePrefix}}-{rule['id'].lower()}-{rule['slug']}"},
            "Description": f"[aws-breach-alarms] {rule['id']}: {rule['title']}",
            "State": rule["state"],
            "EventPattern": _substitute(rule["pattern"], values),
            "Targets": [{"Fn::If": ["IsHome", home_target, forward_target]}],
        },
    }


def _shared_resources():
    kms = {"Fn::If": ["HasKms", {"Ref": "KmsKeyArn"}, {"Ref": "AWS::NoValue"}]}
    account = {"aws:SourceAccount": {"Ref": "AWS::AccountId"}}
    return {
        "AlertTopic": {
            "Type": "AWS::SNS::Topic", "Condition": "IsHome",
            "Properties": {"TopicName": {"Fn::Sub": "${NamePrefix}-alerts"}, "KmsMasterKeyId": kms},
        },
        "AlertTopicPolicy": {
            "Type": "AWS::SNS::TopicPolicy", "Condition": "IsHome",
            "Properties": {
                "Topics": [{"Ref": "AlertTopic"}],
                "PolicyDocument": {"Version": "2012-10-17", "Statement": [{
                    "Sid": "AllowEventBridgeAndCloudWatch", "Effect": "Allow",
                    "Principal": {"Service": ["events.amazonaws.com", "cloudwatch.amazonaws.com"]},
                    "Action": "sns:Publish", "Resource": {"Ref": "AlertTopic"},
                    "Condition": {"StringEquals": account},
                }]},
            },
        },
        "AlertSubscription": {
            "Type": "AWS::SNS::Subscription", "Condition": "HasAlertEmail",
            "Properties": {"TopicArn": {"Ref": "AlertTopic"}, "Protocol": "email", "Endpoint": {"Ref": "AlertEmail"}},
        },
        "DeadLetterQueue": {
            "Type": "AWS::SQS::Queue", "Condition": "IsHome",
            "Properties": {
                "QueueName": {"Fn::Sub": "${NamePrefix}-dlq"},
                "MessageRetentionPeriod": 1209600,
                "KmsMasterKeyId": kms,
                "SqsManagedSseEnabled": {"Fn::If": ["HasKms", {"Ref": "AWS::NoValue"}, True]},
            },
        },
        "DeadLetterQueuePolicy": {
            "Type": "AWS::SQS::QueuePolicy", "Condition": "IsHome",
            "Properties": {
                "Queues": [{"Ref": "DeadLetterQueue"}],
                "PolicyDocument": {"Version": "2012-10-17", "Statement": [{
                    "Sid": "AllowEventBridge", "Effect": "Allow", "Principal": {"Service": "events.amazonaws.com"},
                    "Action": "sqs:SendMessage", "Resource": {"Fn::GetAtt": ["DeadLetterQueue", "Arn"]},
                    "Condition": {"StringEquals": account},
                }]},
            },
        },
        "DeliveryFailureAlarm": {
            "Type": "AWS::CloudWatch::Alarm", "Condition": "IsHome",
            "Properties": {
                "AlarmName": {"Fn::Sub": "${NamePrefix}-h1-delivery-failure"},
                "AlarmDescription": "[aws-breach-alarms] H1: an alert could not be delivered and is waiting in the dead-letter queue.",
                "Namespace": "AWS/SQS", "MetricName": "ApproximateNumberOfMessagesVisible",
                "Dimensions": [{"Name": "QueueName", "Value": {"Fn::GetAtt": ["DeadLetterQueue", "QueueName"]}}],
                "Statistic": "Maximum", "Period": 300, "EvaluationPeriods": 1, "Threshold": 0,
                "ComparisonOperator": "GreaterThanThreshold", "TreatMissingData": "notBreaching",
                "AlarmActions": [{"Ref": "AlertTopic"}],
            },
        },
        "WafSpikeAlarm": {
            "Type": "AWS::CloudWatch::Alarm", "Condition": "HasWafAlarm",
            "Properties": {
                "AlarmName": {"Fn::Sub": "${NamePrefix}-r8-waf-spike"},
                "AlarmDescription": "[aws-breach-alarms] R8: requests blocked by the watched WAF rule spiked.",
                "Namespace": "AWS/WAFV2", "MetricName": "BlockedRequests",
                "Dimensions": [
                    {"Name": "WebACL", "Value": {"Ref": "WafWebAclName"}},
                    {"Name": "Rule", "Value": {"Ref": "WafRuleName"}},
                    {"Name": "Region", "Value": {"Ref": "AWS::Region"}},
                ],
                "Statistic": "Sum", "Period": 300, "EvaluationPeriods": 1, "Threshold": {"Ref": "WafThreshold"},
                "ComparisonOperator": "GreaterThanOrEqualToThreshold", "TreatMissingData": "notBreaching",
                "AlarmActions": [{"Ref": "AlertTopic"}],
            },
        },
        "ForwarderRole": {
            "Type": "AWS::IAM::Role", "Condition": "IsForwarder",
            "Properties": {
                "RoleName": {"Fn::Sub": "${NamePrefix}-forwarder-${AWS::Region}"},
                "AssumeRolePolicyDocument": {"Version": "2012-10-17", "Statement": [{
                    "Effect": "Allow", "Principal": {"Service": "events.amazonaws.com"}, "Action": "sts:AssumeRole",
                    "Condition": {"StringEquals": account},
                }]},
                "Policies": [{"PolicyName": "put-events-to-home-bus", "PolicyDocument": {"Version": "2012-10-17", "Statement": [{
                    "Effect": "Allow", "Action": "events:PutEvents",
                    "Resource": {"Fn::Sub": "arn:${AWS::Partition}:events:${HomeRegion}:${AWS::AccountId}:event-bus/default"},
                }]}}],
            },
        },
    }


def build():
    defaults = catalog.with_defaults({})
    rules = [r for r in catalog.load_rules() if r["kind"] == "event"]
    resources = _shared_resources()
    for rule in rules:
        resources[rule_logical_id(rule)] = _rule_resource(rule)
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Description": "aws-breach-alarms: near-zero-cost CloudTrail breach alarms (generated from rules/*.json - do not edit)",
        "Parameters": _parameters(defaults, rules),
        "Conditions": _conditions(rules),
        "Resources": resources,
        "Outputs": {
            "AlertTopicArn": {"Condition": "IsHome", "Value": {"Ref": "AlertTopic"}},
            "DeadLetterQueueArn": {"Condition": "IsHome", "Value": {"Fn::GetAtt": ["DeadLetterQueue", "Arn"]}},
            "ForwarderRoleArn": {"Condition": "IsForwarder", "Value": {"Fn::GetAtt": ["ForwarderRole", "Arn"]}},
        },
    }


if __name__ == "__main__":
    OUT.parent.mkdir(exist_ok=True)
    OUT.write_text(json.dumps(build(), indent=2) + "\n")
    print(f"wrote {OUT}")
