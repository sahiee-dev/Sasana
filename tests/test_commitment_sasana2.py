"""
tests/test_commitment_sasana2.py — the commitment verifier under the Sasana 2.x trust model.

Pins down, with tests, the statements docs/pre-outcome-commitment.md makes about:
  * which timestamp path a commitment bundle uses (strict) versus `sasana verify` (imprint only);
  * what a pinned Archeion key does and does not do for a commitment verdict;
  * threat A8 (operator rewrites and reseals the session after committing) against a commitment.

Synthetic data only; the TSA is the local test authority (tests/tsa_fixture.py); no network.
"""

from __future__ import annotations

import copy
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

_ROOT = Path(__file__).parent.parent
for _p in (str(_ROOT), str(_ROOT / "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import tsa_fixture as fx  # noqa: E402
from test_commitment import T0, Base, FakeTsa, make_session  # noqa: E402

from sasana import commitment as cm  # noqa: E402
from sasana import rfc3161  # noqa: E402
from sasana.verifier import verify  # noqa: E402

try:
    from fastapi.testclient import TestClient  # noqa: E402

    from archeion.server import app  # noqa: E402

    _FASTAPI = True
except ImportError:
    _FASTAPI = False


def _jsonl(events: list) -> bytes:
    return ("\n".join(json.dumps(e) for e in events) + "\n").encode()


class TestTimestampPaths(Base):
    """A commitment's time comes ONLY from verify_timestamp_strict over the commitment token. The
    SESSION_START RFC 3161 token inside the trace is checked by `sasana verify` for imprint only and is
    never used for any commitment decision."""

    def test_session_start_token_is_imprint_only_even_when_its_signature_is_corrupt(self):
        import tempfile
        from sasana.sqlite_ledger import SqliteLedger

        auth = fx.make_authority()
        with tempfile.TemporaryDirectory() as d:
            ledger = SqliteLedger(Path(d) / "s.db")
            ledger.connect()
            with patch(
                "sasana.rfc3161.request_timestamp",
                lambda h, **kw: fx.respond(auth, h, tamper_signature=True),
            ):
                ledger.open_session("sess-ts", agent_id="a")
            ledger.close_session()
            ledger.export_jsonl(Path(d) / "s.jsonl")
            ledger.close()
            events = [
                json.loads(ln)
                for ln in (Path(d) / "s.jsonl").read_text().splitlines()
                if ln.strip()
            ]

        # `sasana verify`: imprint match only; the corrupt CMS signature is not noticed.
        r = verify(events)
        self.assertEqual(r.checks["rfc3161_timestamp"]["status"], "IMPRINT_MATCH")
        self.assertFalse(r.timestamp_verified)
        # The strict verifier rejects the very same token.
        token = __import__("base64").b64decode(events[0]["payload"]["rfc3161_token"])
        import hashlib
        from sasana.jcs import canonicalize

        pre = {k: v for k, v in events[0].items() if k not in ("event_hash", "signature")}
        pre["payload"] = {k: v for k, v in pre["payload"].items() if k != "rfc3161_token"}
        res = rfc3161.verify_timestamp_strict(
            token, hashlib.sha256(canonicalize(pre)).digest(), trust_anchors=[auth.anchor_der]
        )
        self.assertFalse(res.ok)

    def test_a_commitment_token_with_a_corrupt_signature_makes_the_bundle_invalid(self):
        s = make_session()
        bad = FakeTsa(self.auth, now=T0, tamper_signature=True)
        with patch("sasana.rfc3161.request_timestamp", bad):
            with self.assertRaises(cm.CommitmentError):  # commit() is fail-closed on a bad token
                cm.commit(
                    subject_id="a",
                    context_id="c",
                    payload={"d": "up"},
                    session_events=s,
                    trusted_tsa_anchors=self.anchors,
                )

    def test_a_bundle_whose_token_is_signed_by_an_unpinned_tsa_is_invalid(self):
        s = make_session()
        rogue = fx.make_authority()
        tsa = FakeTsa(rogue, now=T0)
        with patch("sasana.rfc3161.request_timestamp", tsa):
            pub, sec = cm.commit(
                subject_id="a",
                context_id="c",
                payload={"d": "up"},
                session_events=s,
                trusted_tsa_anchors=[rogue.anchor_der],
            )
        v = self.verify(self.bundle(s, [(pub, sec)]))  # verifier pins the *real* anchors
        self.assertEqual(v.verdict, "INVALID")


@unittest.skipUnless(_FASTAPI, "fastapi / httpx not installed")
class TestSealPolicyForCommitments(Base):
    """A pinned Archeion key is honoured, requires a seal, and never changes a commitment's time."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.client = TestClient(app)
        cls.pub = cls.client.get("/pubkey").json()["pubkey"]

    def _sealed(self, session):
        resp = self.client.post("/seal", content=_jsonl(session))
        self.assertEqual(resp.status_code, 200, resp.text)
        return [json.loads(ln) for ln in resp.text.splitlines() if ln.strip()]

    def test_pinned_key_with_a_genuinely_sealed_trace(self):
        s = make_session()
        pub, sec = self.do_commit(s)
        sealed = self._sealed(s)
        v = self.verify(self.bundle(sealed, [(pub, sec)]), trusted_seal_pubkey=self.pub)
        self.assertEqual(v.verdict, "VALID_ON_TIME", (v.errors, v.warnings))
        self.assertEqual(v.evidence_class, "AUTHORITATIVE_EVIDENCE")

    def test_unpinned_sealed_trace_is_only_self_sealed_and_the_verdict_is_unchanged(self):
        s = make_session()
        pub, sec = self.do_commit(s)
        v = self.verify(self.bundle(self._sealed(s), [(pub, sec)]))
        self.assertEqual(v.verdict, "VALID_ON_TIME")
        self.assertEqual(v.evidence_class, "SELF_SEALED_EVIDENCE")

    def test_pinned_key_requires_a_seal(self):
        s = make_session()
        pub, sec = self.do_commit(s)
        v = self.verify(self.bundle(s, [(pub, sec)]), trusted_seal_pubkey=self.pub)
        self.assertEqual(v.verdict, "INVALID")
        self.assertTrue(any("no CHAIN_SEAL" in e for e in v.errors), v.errors)

    def test_pinned_key_rejects_a_seal_from_another_key(self):
        from sasana.signing import generate_keypair

        s = make_session()
        pub, sec = self.do_commit(s)
        _, other = generate_keypair()
        v = self.verify(self.bundle(self._sealed(s), [(pub, sec)]), trusted_seal_pubkey=other)
        self.assertEqual(v.verdict, "INVALID")


@unittest.skipUnless(_FASTAPI, "fastapi / httpx not installed")
class TestA8AgainstACommitment(Base):
    """A8: the operator rewrites the session after committing and has the genuine Archeion reseal it.
    The seal verifies (AUTHORITATIVE under the pin). The COMMITMENT is what catches it: C binds the
    session root, which a rewrite of anything up to the root changes."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.client = TestClient(app)
        cls.pub = cls.client.get("/pubkey").json()["pubkey"]

    def _rechain_and_seal(self, events):
        from test_tamper_matrix import _rechain

        return self._seal(_rechain(events))

    def _seal(self, events):
        resp = self.client.post("/seal", content=_jsonl(events))
        self.assertEqual(
            resp.status_code, 200, resp.text
        )  # the genuine Archeion seals the rewrite (A8)
        return [json.loads(ln) for ln in resp.text.splitlines() if ln.strip()]

    def test_rewrite_before_the_committed_root_is_detected_by_the_commitment_not_the_seal(self):
        full = make_session()
        prefix = full[:3]  # commit to the chain tip as of event 3
        pub, sec = self.do_commit(prefix)
        original_root = sec.session_root

        forged = copy.deepcopy(full)
        forged[1]["payload"]["prompt_hash"] = "f" * 64  # rewrite an event BEFORE the root
        sealed_forgery = self._rechain_and_seal(forged)

        # the seal alone is fooled: genuine key, pinned, AUTHORITATIVE
        trace = verify(sealed_forgery, trusted_seal_pubkey=self.pub)
        self.assertEqual((trace.status, trace.evidence_class), ("INTACT", "AUTHORITATIVE_EVIDENCE"))
        # the commitment is not: the root it bound no longer exists in the rewritten chain
        self.assertNotIn(original_root, [e["event_hash"] for e in sealed_forgery])
        # reveal_bundle() refuses to build such a bundle for an honest committer...
        with self.assertRaises(cm.CommitmentError):
            self.bundle(sealed_forgery, [(pub, sec)])
        # ...so an attacker hand-crafts it: honest bundle, session_events swapped for the sealed rewrite.
        crafted = self.bundle(self._seal(full), [(pub, sec)])
        crafted["session_events"] = sealed_forgery
        v = self.verify(crafted, trusted_seal_pubkey=self.pub)
        self.assertEqual(v.verdict, "INVALID")
        rev_errors = [e for r in v.checks["revisions"] for e in r["errors"]]
        self.assertTrue(any("session_root is not an event" in e for e in rev_errors), rev_errors)

    def test_rewrite_after_the_committed_root_is_not_caught_but_is_reported(self):
        """Honest limit: C binds the trace only up to the root. Later events can change, and the
        verifier says how many post-commitment events there are."""
        full = make_session()
        prefix = full[:3]
        pub, sec = self.do_commit(prefix)
        forged = copy.deepcopy(full)
        forged[-1]["payload"]["status"] = "error"  # SESSION_END, after the root
        sealed = self._rechain_and_seal(forged)
        v = self.verify(self.bundle(sealed, [(pub, sec)]), trusted_seal_pubkey=self.pub)
        self.assertEqual(v.verdict, "VALID_ON_TIME")
        self.assertTrue(any(w.startswith("POST_COMMITMENT_EVENTS") for w in v.warnings), v.warnings)


if __name__ == "__main__":
    unittest.main()
