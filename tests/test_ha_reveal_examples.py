"""
tests/test_ha_reveal_examples.py — the synthetic bundles in examples/ha-reveal/ verify as documented.

Two things are checked: (1) the COMMITTED bundles give exactly the verdicts in expected.json when run
through the real CLI (examples/ha-reveal/run.py); (2) the generator still produces bundles that do the same
(so the example cannot rot silently). Synthetic data only; no network; the generator runs in a subprocess
with a throwaway Archeion key so it can never touch ~/.archeion.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

_ROOT = Path(__file__).parent.parent
EX = _ROOT / "examples" / "ha-reveal"

try:
    import fastapi  # noqa: F401
    import httpx  # noqa: F401

    _GEN = True
except ImportError:
    _GEN = False


def _cli(ex: Path, name: str, *extra: str, pin: bool = True, dirname: str = "") -> tuple:
    trust = json.loads((ex / "trust" / "trust.json").read_text())
    d = ex / "bundles" / (dirname or name)
    cmd = [
        sys.executable,
        "-m",
        "sasana_cli",
        "verify-commitment",
        str(d / "bundle.json"),
        "--deadline",
        trust["deadline"],
        "--tsa-anchor",
        str(ex / "trust" / "tsa-anchor.pem"),
        "--receipts",
        str(d / "receipts.json"),
        "--receipt-key",
        trust["receipt_pubkey"],
        "--mapping",
        trust["mapping_id"],
        "--json",
    ]
    if pin:
        cmd += ["--trust-key", trust["seal_pubkey"]]
    if (d / "closing.json").exists():
        cmd += ["--closing-receipt", str(d / "closing.json")]
    r = subprocess.run(
        cmd + list(extra),
        capture_output=True,
        text=True,
        cwd=_ROOT,
        env={**os.environ, "NO_COLOR": "1"},
    )
    return r.returncode, json.loads(r.stdout)


class TestCommittedBundles(unittest.TestCase):
    def test_every_bundle_matches_expected_through_the_real_cli(self) -> None:
        expected = json.loads((EX / "expected.json").read_text())
        on_disk = sorted(p.name for p in (EX / "bundles").iterdir() if p.is_dir())
        self.assertEqual(on_disk, sorted({e.get("dir", n) for n, e in expected.items()}))
        scenarios = {n.split("-")[0] for n in expected}
        self.assertEqual(scenarios, set("a b c d d2 e e2 f f2 g h h2 i j k l".split()))
        self.assertEqual(len(expected), 16, "scenarios a-l plus e2, f2, h2 and the lenient run d2")
        for name, exp in expected.items():
            with self.subTest(bundle=name):
                code, data = _cli(EX, name, *exp.get("extra_args", []), dirname=exp.get("dir", ""))
                self.assertEqual(
                    data["verdict"], exp["verdict"], (data["errors"], data["warnings"])
                )
                self.assertEqual(data["effective_revision"], exp["effective_revision"])
                self.assertEqual(code, exp["exit"])
                self.assertEqual(data.get("lenient", []), exp.get("lenient", []))
                text = " | ".join(map(str, data["errors"] + data["warnings"]))
                self.assertIn(exp.get("contains", ""), text)

    def test_run_py_prints_the_table_and_exits_zero(self) -> None:
        r = subprocess.run(
            [sys.executable, str(EX / "run.py")], capture_output=True, text=True, cwd=_ROOT
        )
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("bundle", r.stdout.splitlines()[0])
        self.assertIn("16/16 bundles match expected", r.stdout)

    def test_pinned_seal_key_makes_the_trace_authoritative_and_unpinned_does_not(self) -> None:
        _, pinned = _cli(EX, "b-revision-accepted")
        self.assertEqual(pinned["evidence_class"], "AUTHORITATIVE_EVIDENCE")
        code, unpinned = _cli(EX, "b-revision-accepted", pin=False)
        self.assertEqual(unpinned["evidence_class"], "SELF_SEALED_EVIDENCE")
        self.assertEqual(
            (code, unpinned["verdict"]), (0, "VALID_ON_TIME")
        )  # the verdict does not depend on it

    def test_a8_bundle_has_an_authoritative_seal_and_is_still_invalid(self) -> None:
        code, data = _cli(EX, "i-operator-reseal-after-commit")
        self.assertEqual(code, 1)
        self.assertEqual(data["checks"]["trace"]["evidence_class"], "AUTHORITATIVE_EVIDENCE")
        self.assertEqual(data["verdict"], "INVALID")

    def test_the_wrong_receipt_key_or_tsa_anchor_fails_every_bundle(self) -> None:
        for name in ("a-initial-only", "b-revision-accepted"):
            code, data = _cli(
                EX, name, "--receipt-key", "A" * 43 + "="
            )  # later flag wins in argparse
            self.assertEqual((code, data["verdict"]), (1, "INVALID"), name)

    def test_bundles_are_synthetic(self) -> None:
        trust = json.loads((EX / "trust" / "trust.json").read_text())
        self.assertIn("synthetic", trust["subject_id"])
        self.assertIn("synthetic", trust["context_id"])
        for p in (EX / "bundles").rglob("*.json"):
            text = p.read_text()
            self.assertNotIn("headlinearena", text.lower(), p.name)
            self.assertNotIn("PRIVATE KEY", text, p.name)

    def test_no_private_key_material_is_committed(self) -> None:
        for p in EX.rglob("*"):
            if p.is_file() and p.suffix in {".json", ".pem", ".md", ".py"}:
                self.assertNotIn("PRIVATE KEY", p.read_text(), str(p))


@unittest.skipUnless(_GEN, "fastapi / httpx not installed")
class TestGeneratorStillWorks(unittest.TestCase):
    def test_regenerated_bundles_match_expected(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "ha-reveal"
            env = {k: v for k, v in os.environ.items() if not k.startswith("ARCHEION_")}
            r = subprocess.run(
                [sys.executable, str(EX / "generate.py"), "--out", str(out)],
                capture_output=True,
                text=True,
                cwd=_ROOT,
                env=env,
            )
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            expected = json.loads((EX / "expected.json").read_text())
            self.assertEqual(json.loads((out / "expected.json").read_text()), expected)
            for name, exp in expected.items():
                with self.subTest(bundle=name):
                    code, data = _cli(
                        out, name, *exp.get("extra_args", []), dirname=exp.get("dir", "")
                    )
                    self.assertEqual(
                        (data["verdict"], data["effective_revision"], code),
                        (exp["verdict"], exp["effective_revision"], exp["exit"]),
                    )


if __name__ == "__main__":
    unittest.main()
