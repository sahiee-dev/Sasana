"""
tests/test_ha_reveal_examples.py — the synthetic bundles in examples/ha-reveal/ verify as documented.

Every bundle, receipt, closing receipt and the trust file is SYNTHETIC and says so ("SYNTHETIC — not HA-issued"):
receipts are a PROPOSED EXTENSION that no counterparty issues.

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


def _expected() -> dict:
    """expected.json without its `_notice` label."""
    raw = json.loads((EX / "expected.json").read_text("utf-8"))
    return {n: e for n, e in raw.items() if not n.startswith("_")}


def _cli(ex: Path, name: str, *extra: str, pin: bool = True, dirname: str = "") -> tuple:
    trust = json.loads((ex / "trust" / "trust.json").read_text())
    d = ex / "bundles" / (dirname or name)
    cmd = [
        sys.executable,
        "-m",
        "sasana_cli",
        "verify-commitment",
        str(d / "bundle.json"),
        "--agent-id",
        trust["subject_id"],
        "--challenge-id",
        trust["context_id"],
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
        expected = _expected()
        on_disk = sorted(p.name for p in (EX / "bundles").iterdir() if p.is_dir())
        self.assertEqual(on_disk, sorted({e.get("dir", n) for n, e in expected.items()}))
        scenarios = {n.split("-")[0] for n in expected}
        self.assertEqual(
            scenarios, set("a b c d d2 e e2 f f2 g h h2 i j k l m n o p q r s t".split())
        )
        self.assertEqual(
            len(expected),
            24,
            "scenarios a-l plus e2, f2, h2, the lenient run d2, and m-t (identity, bundle-level, v3)",
        )
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
                for absent in exp.get("not_contains", []):
                    self.assertNotIn(absent, text)

    def test_run_py_prints_the_table_and_exits_zero(self) -> None:
        r = subprocess.run(
            [sys.executable, str(EX / "run.py")], capture_output=True, text=True, cwd=_ROOT
        )
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("bundle", r.stdout.splitlines()[0])
        self.assertIn("24/24 bundles match expected", r.stdout)

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

    def test_every_synthetic_file_says_so(self) -> None:
        notice = "SYNTHETIC \u2014 not HA-issued"
        self.assertEqual(
            json.loads((EX / "trust" / "trust.json").read_text("utf-8"))["synthetic_notice"], notice
        )
        self.assertEqual(json.loads((EX / "expected.json").read_text("utf-8"))["_notice"], notice)
        self.assertTrue((EX / "trust" / "tsa-anchor.pem").read_text().startswith("# SYNTHETIC"))
        self.assertIn(notice, (EX / "README.md").read_text("utf-8"))
        for d in sorted((EX / "bundles").iterdir()):
            with self.subTest(bundle=d.name):
                self.assertEqual(
                    json.loads((d / "bundle.json").read_text("utf-8"))["synthetic_notice"], notice
                )
                for r in json.loads((d / "receipts.json").read_text("utf-8")):
                    self.assertEqual(r["body"]["notice"], notice)
                if (d / "closing.json").exists():
                    self.assertEqual(
                        json.loads((d / "closing.json").read_text("utf-8"))["body"]["notice"],
                        notice,
                    )

    def test_no_receipt_carries_a_payload_hash_threat_t6(self) -> None:
        for p in (EX / "bundles").rglob("*.json"):
            if p.name != "bundle.json":
                self.assertNotIn("payload_hash", p.read_text("utf-8"), str(p))

    def test_the_verdicts_say_the_receipts_are_synthetic(self) -> None:
        _, data = _cli(EX, "b-revision-accepted")
        self.assertTrue(any(w.startswith("SYNTHETIC_RECEIPTS_USED") for w in data["warnings"]))

    def test_the_identity_bundles_are_honest_for_the_identity_they_were_committed_under(
        self,
    ) -> None:
        """m and n are refused ONLY because the verifier's record names someone else: told the identity they
        were committed under, they verify. (Each has its own receipts and closing receipt for that identity.)"""
        trust = json.loads((EX / "trust" / "trust.json").read_text("utf-8"))
        for name, flag, value in (
            ("m-wrong-agent", "--agent-id", "agent-synthetic-002"),
            ("n-wrong-challenge", "--challenge-id", "challenge-synthetic-daily-2026-10-15"),
        ):
            with self.subTest(bundle=name):
                bundle = json.loads((EX / "bundles" / name / "bundle.json").read_text("utf-8"))
                self.assertIn(value, (bundle["subject_id"], bundle["context_id"]))
                code, refused = _cli(EX, name)
                self.assertEqual((code, refused["verdict"]), (1, "INVALID"))
                self.assertEqual(
                    len(refused["errors"]), 1, refused["errors"]
                )  # one reason, not two
                code, ok = _cli(EX, name, flag, value)  # (a later flag wins)
                self.assertEqual(
                    (code, ok["verdict"]), (0, "VALID_ON_TIME"), (ok["errors"], ok["warnings"])
                )
        self.assertNotEqual(trust["subject_id"], "agent-synthetic-002")

    def test_the_two_identity_cases_have_different_reasons(self) -> None:
        _, m = _cli(EX, "m-wrong-agent")
        _, n = _cli(EX, "n-wrong-challenge")
        self.assertTrue(m["errors"][0].startswith("AGENT_ID_MISMATCH"))
        self.assertTrue(n["errors"][0].startswith("CHALLENGE_ID_MISMATCH"))

    def test_the_reordered_bundle_gives_exactly_the_verdict_of_the_ordered_one(self) -> None:
        a = json.loads((EX / "bundles" / "b-revision-accepted" / "bundle.json").read_text("utf-8"))
        r = json.loads(
            (EX / "bundles" / "r-reordered-revisions" / "bundle.json").read_text("utf-8")
        )
        self.assertEqual([x["revision_index"] for x in a["revisions"]], [0, 1])
        self.assertEqual([x["revision_index"] for x in r["revisions"]], [1, 0])  # reversed
        (_, got_a), (_, got_r) = _cli(EX, "b-revision-accepted"), _cli(EX, "r-reordered-revisions")
        self.assertEqual(got_a, got_r)  # the whole output: verdict, warnings, checks

    def test_the_corrupted_seal_is_the_only_thing_wrong_with_p(self) -> None:
        code, bad = _cli(EX, "p-corrupted-seal")
        self.assertEqual((code, bad["verdict"]), (1, "INVALID"))
        self.assertTrue(
            any("CHAIN_SEAL signature invalid" in e for e in bad["errors"]), bad["errors"]
        )
        self.assertEqual(bad["checks"]["trace"]["status"], "COMPROMISED")
        events = json.loads(
            (EX / "bundles" / "p-corrupted-seal" / "bundle.json").read_text("utf-8")
        )["session_events"]
        self.assertEqual(events[-1]["event_type"], "CHAIN_SEAL")

    def test_the_wrong_revision_index_and_the_duplicate_are_refused_for_their_own_reasons(
        self,
    ) -> None:
        _, o = _cli(EX, "o-wrong-revision-index")
        self.assertTrue(
            any("commitment does not match" in str(e) for e in o["errors"] + o["warnings"])
        )
        _, q = _cli(EX, "q-duplicate-revisions")
        self.assertEqual(q["errors"], ["duplicate revision_index in bundle"])

    def test_the_unstaked_full_vector_example(self) -> None:
        """HA-4: probabilities 0.60 / 0.30 / 0.10, amount omitted, an uppercase 64-hex prompt_hash."""
        code, data = _cli(EX, "s-unstaked-full-vector")
        self.assertEqual(
            (code, data["verdict"], data["effective_revision"]), (0, "VALID_ON_TIME", 0)
        )
        payload = data["effective_payload"]
        self.assertNotIn("amount", payload)
        self.assertEqual(payload["probabilities"], {"bearish": 0.6, "neutral": 0.3, "bullish": 0.1})
        self.assertRegex(payload["prompt_hash"], r"^[0-9A-F]{64}$")
        self.assertFalse(
            [
                w
                for w in data["warnings"]
                if w.startswith(("PROBABILITY", "DIRECTION", "CONFIDENCE"))
            ]
        )

    def test_the_off_by_one_revision_number_is_caught_in_t(self) -> None:
        _, data = _cli(EX, "t-receipt-revision-number-off-by-one")
        self.assertTrue(
            any("RECEIPT_REVISION_NUMBER_MISMATCH:1" in e for e in data["errors"]), data["errors"]
        )

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
            expected = json.loads((EX / "expected.json").read_text("utf-8"))
            self.assertEqual(json.loads((out / "expected.json").read_text("utf-8")), expected)
            for name, exp in _expected().items():
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
