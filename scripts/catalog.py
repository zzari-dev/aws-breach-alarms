"""Loads the rule catalog (rules/*.json) and renders event patterns from configuration.

Patterns contain parameter tokens: a JSON string value "@@name@@" is replaced by the
configured value (a string or a list). Terraform and the CloudFormation generator
perform the same substitution, so all three stay in lockstep.
"""
import json
import re
from pathlib import Path

RULES_DIR = Path(__file__).resolve().parent.parent / "rules"
SENTINEL = "__none__"
TOKEN = re.compile(r"^@@([a-z_]+)@@$")

MESSAGE = json.loads((RULES_DIR / "message.json").read_text())
INPUT_PATHS = MESSAGE["input_paths"]


def load_rules():
    return [json.loads(p.read_text()) for p in sorted(RULES_DIR.glob("r*.json"))]


def with_defaults(config):
    defaults = json.loads((RULES_DIR / "defaults.json").read_text())
    return {**defaults, **{k: v for k, v in config.items() if v is not None}}


def tokens_in(node):
    if isinstance(node, dict):
        return set().union(*(tokens_in(v) for v in node.values())) if node else set()
    if isinstance(node, list):
        return set().union(*(tokens_in(v) for v in node)) if node else set()
    if isinstance(node, str) and TOKEN.match(node):
        return {TOKEN.match(node).group(1)}
    return set()


def render_pattern(rule, config):
    """Returns the event pattern for this config, or None when a required parameter is empty."""
    values = {}
    for name, need in rule.get("params", {}).items():
        value = config.get(name)
        if not value:
            if need == "required":
                return None
            value = [SENTINEL] if isinstance(value, list) else SENTINEL
        values[name] = value
    return _substitute(rule["pattern"], values)


def _substitute(node, values):
    if isinstance(node, dict):
        return {k: _substitute(v, values) for k, v in node.items()}
    if isinstance(node, list):
        return [_substitute(v, values) for v in node]
    if isinstance(node, str) and TOKEN.match(node):
        return values[TOKEN.match(node).group(1)]
    return node


def anchor(rule):
    return f"{rule['id'].lower()}-{rule['slug']}"


def message_template(rule, runbook_url):
    """Plain-text alert. EventBridge reads InputTemplate as JSON, so each line is its own quoted string."""
    fields = {**rule, "runbook_url": runbook_url, "anchor": anchor(rule)}
    lines = []
    for line in MESSAGE["template"]:
        if not runbook_url and "{runbook_url}" in line:
            continue
        for key in ("severity", "id", "slug", "title", "why", "runbook_url", "anchor"):
            line = line.replace("{" + key + "}", fields[key])
        lines.append('"' + line.replace('"', '\\"') + '"')
    return "\n".join(lines)
