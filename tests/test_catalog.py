import json

import catalog


def _rule(slug):
    return next(r for r in catalog.load_rules() if r["slug"] == slug)


def test_rule_is_skipped_when_a_required_parameter_is_empty(test_config):
    config = catalog.with_defaults({**test_config, "monitored_role_names": []})
    assert catalog.render_pattern(_rule("role-denied"), config) is None


def test_empty_optional_principal_list_becomes_a_sentinel_that_excludes_nothing(test_config):
    config = catalog.with_defaults({**test_config, "deployer_principal_patterns": []})
    pattern = catalog.render_pattern(_rule("iam-persistence"), config)
    assert pattern["detail"]["userIdentity"]["arn"] == [{"anything-but": {"wildcard": [catalog.SENTINEL]}}]


def test_defaults_trust_sso_and_ssm_state_manager_for_remote_exec():
    defaults = catalog.with_defaults({})
    assert any("AWSReservedSSO_" in p for p in defaults["operator_principal_patterns"])
    assert any("AWSServiceRoleForAmazonSSM" in p for p in defaults["operator_principal_patterns"])


def test_rule_ids_and_slugs_are_unique():
    rules = catalog.load_rules()
    assert len({r["id"] for r in rules}) == len(rules)
    assert len({r["slug"] for r in rules}) == len(rules)


def test_every_parameter_token_in_a_pattern_is_declared():
    for rule in catalog.load_rules():
        assert catalog.tokens_in(rule.get("pattern", {})) <= set(rule.get("params", {})), rule["slug"]


def test_alert_message_names_the_rule_and_links_its_runbook():
    rule = _rule("remote-exec")
    message = catalog.message_template(rule, "https://example.com/runbook.md")
    assert message.splitlines()[0] == "HIGH R3 remote-exec: " + rule["title"]
    assert "aws-breach-alarms" in message.splitlines()[1]
    assert "https://example.com/runbook.md#r3-remote-exec" in message
    assert "<eventName>" in message and "<sourceIPAddress>" in message


def test_rendered_patterns_fit_the_default_eventbridge_size_limit(test_config):
    config = catalog.with_defaults(test_config)
    for rule in catalog.load_rules():
        if rule["kind"] == "event":
            size = len(json.dumps(catalog.render_pattern(rule, config), separators=(",", ":")))
            assert size <= 2048, f"{rule['slug']} pattern is {size} chars"


def test_every_alert_links_to_an_existing_runbook_section_in_both_languages():
    docs = catalog.RULES_DIR.parent / "docs"
    for name in ("runbook.md", "runbook.ko.md"):
        headings = {line[3:].strip().lower().replace(" ", "-") for line in (docs / name).read_text().splitlines() if line.startswith("## ")}
        for rule in catalog.load_rules():
            assert catalog.anchor(rule) in headings, f"{name} lacks a section for {rule['id']} {rule['slug']}"


def test_alert_message_is_plain_text_for_eventbridge():
    # EventBridge parses an InputTemplate starting with "[" or "{" as JSON and rejects the target.
    for rule in catalog.load_rules():
        assert catalog.message_template(rule, "https://example.com")[0] not in "[{\"", rule["slug"]
