"""Runs event patterns through aws/event-ruler, the engine behind Amazon EventBridge."""
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
JARS = ROOT / ".cache" / "ruler"
CLASSES = ROOT / ".cache" / "classes"
SOURCE = ROOT / "tests" / "ruler" / "Matcher.java"


def _compile():
    subprocess.run([str(ROOT / "scripts" / "fetch_ruler.sh")], check=True)
    target = CLASSES / "Matcher.class"
    if not target.exists() or target.stat().st_mtime < SOURCE.stat().st_mtime:
        CLASSES.mkdir(parents=True, exist_ok=True)
        subprocess.run(["javac", "-Xlint:all", "-Werror", "-cp", f"{JARS}/*", "-d", str(CLASSES), str(SOURCE)], check=True)


def match_all(cases):
    """cases: {id: (pattern, event)} -> {id: True | False | 'error: ...'}"""
    _compile()
    lines = "\n".join(json.dumps({"id": i, "pattern": p, "event": e}) for i, (p, e) in cases.items())
    out = subprocess.run(["java", "-cp", f"{CLASSES}:{JARS}/*", "Matcher"], input=lines,
                         capture_output=True, text=True, check=True).stdout
    verdicts = {}
    for row in out.splitlines():
        parts = row.split("\t")
        verdicts[parts[0]] = parts[1] == "true" if parts[1] != "error" else "error: " + parts[2]
    return verdicts
