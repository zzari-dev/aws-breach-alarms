import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))


@pytest.fixture(scope="session")
def test_config():
    return json.loads((ROOT / "tests" / "config.json").read_text())
