"""
tests/test_versions.py — every place that carries the release version must agree.

2.0.0 shipped with stale versions in several places (Archeion's /health said 1.0.0, the skill and
the manifest said 1.0.0, the plugin and the compose tag lagged). This fails if any of them drifts.
VERIFIER_VERSION is deliberately separate: it changes only when verdicts can change.
"""

from __future__ import annotations

import json
import re
import sys
import unittest
from pathlib import Path

_ROOT = Path(__file__).parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import sasana  # noqa: E402
from sasana.skill import SasanaSkill  # noqa: E402


def _toml_version(path: Path) -> str:
    m = re.search(r'^version\s*=\s*"([^"]+)"', path.read_text(), re.M)
    assert m, path
    return m.group(1)


class TestVersionsAgree(unittest.TestCase):
    def test_all_release_versions_match_the_package(self):
        want = sasana.__version__
        found = {
            "pyproject.toml": _toml_version(_ROOT / "pyproject.toml"),
            "sasana-rs/Cargo.toml": _toml_version(_ROOT / "sasana-rs" / "Cargo.toml"),
            "sasanamanifest.json": json.loads((_ROOT / "sasanamanifest.json").read_text())[
                "version"
            ],
            "SasanaSkill.version": SasanaSkill.version,
            "openclaw-plugin package.json": json.loads(
                (_ROOT / "openclaw-plugin" / "sasana-openclaw" / "package.json").read_text()
            )["version"],
            "docker-compose image tag": re.search(
                r"image:\s*sasana-archeion:(\S+)", (_ROOT / "docker-compose.yml").read_text()
            ).group(1),
        }
        for where, got in found.items():
            self.assertEqual(got, want, f"{where} is {got}, package is {want}")

    def test_archeion_reports_the_package_version(self):
        try:
            from fastapi.testclient import TestClient

            from archeion.server import app
        except ImportError:
            self.skipTest("fastapi / httpx not installed")
        self.assertEqual(app.version, sasana.__version__)
        self.assertEqual(TestClient(app).get("/health").json()["version"], sasana.__version__)

    def test_changelog_has_an_entry_for_this_version(self):
        self.assertIn(f"## [{sasana.__version__}]", (_ROOT / "CHANGELOG.md").read_text())


if __name__ == "__main__":
    unittest.main()
