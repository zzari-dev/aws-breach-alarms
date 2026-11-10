"""Runs every fixture through the real EventBridge TestEventPattern API and compares
the verdict with the fixture folder (match/nomatch). Needs AWS credentials; creates nothing."""
import json
import subprocess
import sys
from pathlib import Path

import catalog

ROOT = Path(__file__).resolve().parent.parent
config = catalog.with_defaults(json.loads((ROOT / "tests" / "config.json").read_text()))
rules = {r["slug"]: r for r in catalog.load_rules()}
failures = 0
for path in sorted((ROOT / "tests" / "events").glob("*/*/*.json")):
    slug, expected = path.parent.parent.name, path.parent.name == "match"
    pattern = catalog.render_pattern(rules[slug], config)
    out = subprocess.run(["aws", "events", "test-event-pattern", "--output", "json",
                          "--event-pattern", json.dumps(pattern), "--event", path.read_text()],
                         capture_output=True, text=True)
    if out.returncode != 0:
        print(f"ERROR {path.relative_to(ROOT)}: {out.stderr.strip()}")
        failures += 1
        continue
    actual = json.loads(out.stdout)["Result"]
    status = "ok  " if actual == expected else "FAIL"
    failures += actual != expected
    print(f"{status} {path.relative_to(ROOT / 'tests' / 'events')} -> {actual}")
print(f"{failures} mismatches")
sys.exit(1 if failures else 0)
