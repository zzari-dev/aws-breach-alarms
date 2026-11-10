"""Every rule must match its match/ fixtures and none of its nomatch/ fixtures."""
import json
from pathlib import Path

import pytest

import catalog
from ruler import match_all

EVENTS = Path(__file__).resolve().parent / "events"


def _fixtures():
    return sorted(EVENTS.glob("*/*/*.json"))


@pytest.fixture(scope="module")
def verdicts(test_config):
    rules = {r["slug"]: r for r in catalog.load_rules()}
    cases = {}
    for path in _fixtures():
        slug, kind = path.parent.parent.name, path.parent.name
        pattern = catalog.render_pattern(rules[slug], catalog.with_defaults(test_config))
        cases[str(path.relative_to(EVENTS))] = (pattern, json.loads(path.read_text()))
    return match_all(cases)


@pytest.mark.parametrize("path", _fixtures(), ids=lambda p: str(p.relative_to(EVENTS)))
def test_rule_verdict_matches_fixture_folder(path, verdicts):
    expected = path.parent.name == "match"
    assert verdicts[str(path.relative_to(EVENTS))] == expected


def test_every_pattern_rule_has_match_and_nomatch_fixtures():
    for rule in catalog.load_rules():
        if rule["kind"] != "event":
            continue
        for kind in ("match", "nomatch"):
            assert list((EVENTS / rule["slug"] / kind).glob("*.json")), f"{rule['slug']} has no {kind} fixtures"


def test_every_fixture_folder_belongs_to_a_rule():
    slugs = {r["slug"] for r in catalog.load_rules()}
    assert {p.name for p in EVENTS.iterdir() if p.is_dir()} <= slugs
