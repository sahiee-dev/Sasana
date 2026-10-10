"""
tests/test_commitment.py — pre-outcome commitment: encoding, commit, reveal, verify.

All timestamping goes through a local test TSA (tests/tsa_fixture.py); no network.
"""

from __future__ import annotations

import copy
import datetime as dt
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

_ROOT = Path(__file__).parent.parent
for _p in (str(_ROOT), str(_ROOT / "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import tsa_fixture as fx  # noqa: E402
from sasana import commitment as cm  # noqa: E402
from sasana._utils import content_hash  # noqa: E402
from sasana.sqlite_ledger import SqliteLedger  # noqa: E402

UTC = dt.timezone.utc
T0 = dt.datetime(2026, 6, 1, 10, 0, 0, tzinfo=UTC)
DEADLINE = dt.datetime(2026, 6, 1, 12, 0, 0, tzinfo=UTC)
SUBJ, CTX = "agent-7", "market-2026-06-01"
PAYLOAD = {"direction": "up", "confidence": "0.72", "reasoning": "x"}


class FakeTsa:
    """Patches rfc3161.request_timestamp with a signing TSA whose clock the test controls."""

    def __init__(self, auth, now=T0, **respond_kw):
        self.auth, self.now, self.kw = auth, now, respond_kw
        self.calls = []

    def __call__(self, hash_bytes, *, url=None, nonce=None):
        self.calls.append((hash_bytes, url, nonce))
        kw = dict(self.kw)
        kw.setdefault("nonce", nonce)
        return fx.respond(self.auth, hash_bytes, gen_time=self.now, **kw)


def make_session(*, close: bool = True, extra=None) -> list:
    """Real SqliteLedger session, exported as event dicts (no anchoring, no network)."""
    with tempfile.TemporaryDirectory() as d:
        ledger = SqliteLedger(Path(d) / "s.db")
        ledger.connect()
        with patch("sasana.rfc3161.request_timestamp", return_value=None):
            ledger.open_session("sess-1", agent_id="a")
        ledger.record("LLM_CALL", {"prompt_hash": "a" * 64})
        ledger.record("TOOL_CALL", {"tool_name": "search", "args_hash": content_hash({"q": 1})})
        for et, pl in extra or []:
            ledger.record(et, pl)
        if close:
            ledger.close_session()
        out = Path(d) / "s.jsonl"
        ledger.export_jsonl(out)
        ledger.close()
        return [json.loads(ln) for ln in out.read_text().splitlines() if ln.strip()]


class Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.auth = fx.make_authority()
        cls.anchors = [cls.auth.anchor_der]

    def do_commit(self, session, *, now=T0, payload=None, prev=None, **kw):
        tsa = FakeTsa(self.auth, now=now)
        with patch("sasana.rfc3161.request_timestamp", tsa):
            return cm.commit(
                subject_id=SUBJ,
                context_id=CTX,
                payload=payload or PAYLOAD,
                session_events=session,
                trusted_tsa_anchors=self.anchors,
                prev=prev,
                **kw,
            )

    def bundle(self, session, pairs, mode="sidecar", **kw):
        return cm.reveal_bundle(pairs, session, capture_mode=mode, **kw)

    def verify(self, bundle, **kw):
        kw.setdefault("deadline", DEADLINE)
        kw.setdefault("trusted_tsa_anchors", self.anchors)
        return cm.verify_commitment(bundle, **kw)


class TestEncoding(Base):
    def test_known_answer_matches_independent_construction(self) -> None:
        salt = bytes(range(32))
        root = "ab" * 32
        ph = hashlib.sha256(b'{"a":1}').digest()

        def lp(b: bytes) -> bytes:
            return len(b).to_bytes(4, "big") + b

        expected = hashlib.sha256(
            lp(b"sasana/commit/v1")
            + lp(b"s")
            + lp(b"c")
            + lp((3).to_bytes(4, "big"))
            + lp(ph)
            + lp(bytes.fromhex(root))
            + lp(salt)
        ).hexdigest()
        got = cm.compute_commitment(
            subject_id="s",
            context_id="c",
            revision_index=3,
            payload={"a": 1},
            session_root=root,
            salt=salt,
        )
        self.assertEqual(got, expected)

    def test_no_ambiguity_between_adjacent_fields(self) -> None:
        kw = dict(revision_index=0, payload={"a": 1}, session_root="00" * 32, salt=b"\x01" * 32)
        a = cm.compute_commitment(subject_id="ab", context_id="c", **kw)
        b = cm.compute_commitment(subject_id="a", context_id="bc", **kw)
        self.assertNotEqual(a, b)

    def test_every_input_changes_the_commitment(self) -> None:
        base = dict(
            subject_id="s",
            context_id="c",
            revision_index=0,
            payload={"a": 1},
            session_root="00" * 32,
            salt=b"\x01" * 32,
        )
        c0 = cm.compute_commitment(**base)
        for k, v in [
            ("subject_id", "s2"),
            ("context_id", "c2"),
            ("revision_index", 1),
            ("payload", {"a": 2}),
            ("session_root", "01" * 32),
            ("salt", b"\x02" * 32),
        ]:
            self.assertNotEqual(cm.compute_commitment(**{**base, k: v}), c0, k)

    def test_payload_key_order_irrelevant(self) -> None:
        self.assertEqual(cm.payload_hash({"a": 1, "b": 2}), cm.payload_hash({"b": 2, "a": 1}))

    def test_input_validation(self) -> None:
        ok = dict(
            subject_id="s",
            context_id="c",
            revision_index=0,
            payload_hash_raw=b"\x00" * 32,
            session_root="00" * 32,
            salt=b"\x00" * 32,
        )
        cm.encode_commitment_input(**ok)
        for bad in (
            {"salt": b"\x00" * 31},
            {"payload_hash_raw": b"\x00" * 31},
            {"session_root": "AB" * 32},
            {"session_root": "ab" * 31},
            {"revision_index": -1},
            {"revision_index": 2**32},
            {"subject_id": "\ud800"},
        ):
            with self.assertRaises((ValueError, TypeError), msg=str(bad)):
                cm.encode_commitment_input(**{**ok, **bad})

    def test_payload_profile(self) -> None:
        cm.validate_payload_profile({"a": [1, "x", None, True, {"b": -5}]})
        for bad in (
            {"a": 0.5},
            {"a": float("nan")},
            {"a": 2**53 + 1},
            {"a": {"b": [1.0]}},
            {"a": b"bytes"},
            {1: "x"},
        ):
            with self.assertRaises(ValueError, msg=str(bad)):
                cm.validate_payload_profile(bad)
        with self.assertRaises(ValueError):
            cm.validate_payload_profile([1, 2])  # type: ignore[arg-type]


class TestCommit(Base):
    def test_basic_commit(self) -> None:
        s = make_session()
        pub, sec = self.do_commit(s)
        self.assertEqual(pub.revision_index, 0)
        self.assertIsNone(pub.prev_commitment)
        self.assertEqual(sec.session_root, s[-1]["event_hash"])
        self.assertEqual(len(sec.salt), 32)
        self.assertEqual(pub.tsa_gen_time, "2026-06-01T10:00:00.000000Z")
        self.assertEqual(
            pub.commitment,
            cm.compute_commitment(
                subject_id=SUBJ,
                context_id=CTX,
                revision_index=0,
                payload=PAYLOAD,
                session_root=sec.session_root,
                salt=sec.salt,
            ),
        )

    def test_fresh_salt_each_commit(self) -> None:
        s = make_session()
        a, sa = self.do_commit(s)
        b, sb = self.do_commit(s)
        self.assertNotEqual(sa.salt, sb.salt)
        self.assertNotEqual(a.commitment, b.commitment)

    def test_nonce_is_sent_and_unique(self) -> None:
        s = make_session()
        tsa = FakeTsa(self.auth)
        with patch("sasana.rfc3161.request_timestamp", tsa):
            for _ in range(2):
                cm.commit(
                    subject_id=SUBJ,
                    context_id=CTX,
                    payload=PAYLOAD,
                    session_events=s,
                    trusted_tsa_anchors=self.anchors,
                )
        n1, n2 = tsa.calls[0][2], tsa.calls[1][2]
        self.assertTrue(n1 and n2 and n1 != n2)

    def test_revision_links_to_previous(self) -> None:
        s = make_session()
        p0, _ = self.do_commit(s)
        p1, _ = self.do_commit(s, prev=p0, payload={**PAYLOAD, "direction": "down"})
        self.assertEqual(p1.revision_index, 1)
        self.assertEqual(p1.prev_commitment, p0.commitment)

    def test_prev_from_other_context_rejected(self) -> None:
        s = make_session()
        p0, _ = self.do_commit(s)
        other = cm.PublicCommitment(**{**p0.to_dict(), "context_id": "other"})
        with self.assertRaises(cm.CommitmentError):
            self.do_commit(s, prev=other)

    def test_fail_closed_no_tsa_response(self) -> None:
        s = make_session()
        with patch("sasana.rfc3161.request_timestamp", return_value=None):
            with self.assertRaises(cm.CommitmentError):
                cm.commit(
                    subject_id=SUBJ,
                    context_id=CTX,
                    payload=PAYLOAD,
                    session_events=s,
                    trusted_tsa_anchors=self.anchors,
                )

    def test_fail_closed_untrusted_tsa(self) -> None:
        s = make_session()
        rogue = FakeTsa(fx.make_authority())
        with patch("sasana.rfc3161.request_timestamp", rogue):
            with self.assertRaises(cm.CommitmentError):
                cm.commit(
                    subject_id=SUBJ,
                    context_id=CTX,
                    payload=PAYLOAD,
                    session_events=s,
                    trusted_tsa_anchors=self.anchors,
                )

    def test_fail_closed_nonce_not_echoed(self) -> None:
        s = make_session()
        tsa = FakeTsa(self.auth)
        tsa.kw["nonce"] = 12345  # echoes a fixed wrong nonce
        # FakeTsa uses setdefault, so the explicit kw wins
        with patch("sasana.rfc3161.request_timestamp", tsa):
            with self.assertRaises(cm.CommitmentError):
                cm.commit(
                    subject_id=SUBJ,
                    context_id=CTX,
                    payload=PAYLOAD,
                    session_events=s,
                    trusted_tsa_anchors=self.anchors,
                )

    def test_falls_through_to_second_tsa(self) -> None:
        s = make_session()
        calls = []

        def flaky(h, *, url=None, nonce=None):
            calls.append(url)
            return None if url == "bad" else fx.respond(self.auth, h, gen_time=T0, nonce=nonce)

        with patch("sasana.rfc3161.request_timestamp", flaky):
            pub, _ = cm.commit(
                subject_id=SUBJ,
                context_id=CTX,
                payload=PAYLOAD,
                session_events=s,
                trusted_tsa_anchors=self.anchors,
                tsa_urls=["bad", "good"],
            )
        self.assertEqual(calls, ["bad", "good"])
        self.assertEqual(pub.tsa_url, "good")

    def test_requires_anchors(self) -> None:
        with self.assertRaises(cm.CommitmentError):
            cm.commit(
                subject_id=SUBJ,
                context_id=CTX,
                payload=PAYLOAD,
                session_events=make_session(),
                trusted_tsa_anchors=[],
            )

    def test_refuses_broken_chain(self) -> None:
        s = make_session()
        s[1]["payload"]["prompt_hash"] = "f" * 64
        with self.assertRaises(cm.CommitmentError):
            self.do_commit(s)

    def test_refuses_float_payload(self) -> None:
        with self.assertRaises(ValueError):
            self.do_commit(make_session(), payload={"confidence": 0.72})

    def test_commit_on_open_session(self) -> None:
        s = make_session(close=False)
        pub, sec = self.do_commit(s)
        self.assertEqual(sec.session_root, s[-1]["event_hash"])

    def test_secrets_roundtrip(self) -> None:
        s = make_session()
        pub, sec = self.do_commit(s)
        self.assertEqual(cm.CommitmentSecrets.from_dict(sec.to_dict()), sec)
        self.assertEqual(cm.PublicCommitment.from_dict(pub.to_dict()), pub)


class TestReveal(Base):
    def test_reveal_rejects_mismatched_secrets(self) -> None:
        s = make_session()
        pub, sec = self.do_commit(s)
        bad = cm.CommitmentSecrets(
            payload={**PAYLOAD, "direction": "down"}, session_root=sec.session_root, salt=sec.salt
        )
        with self.assertRaises(cm.CommitmentError):
            self.bundle(s, [(pub, bad)])

    def test_reveal_rejects_root_not_in_session(self) -> None:
        s = make_session()
        pub, sec = self.do_commit(s)
        with self.assertRaises(cm.CommitmentError):
            self.bundle(s[:1], [(pub, sec)])

    def test_reveal_rejects_bad_capture_mode(self) -> None:
        s = make_session()
        pair = self.do_commit(s)
        with self.assertRaises(ValueError):
            self.bundle(s, [pair], mode="trust-me")

    def test_reveal_rejects_bad_disclosure(self) -> None:
        s = make_session()
        pair = self.do_commit(s)
        seq = next(e["seq"] for e in s if e["event_type"] == "TOOL_CALL")
        bad = {"seq": seq, "field": "args_hash", "form": "jcs", "preimage": {"q": 2}}
        with self.assertRaises(cm.CommitmentError):
            self.bundle(s, [pair], disclosures=[bad])

    def test_bundle_is_json_serializable_and_has_no_outcome_or_deadline(self) -> None:
        s = make_session()
        b = self.bundle(s, [self.do_commit(s)])
        text = json.dumps(b)
        self.assertNotIn("deadline", b)
        self.assertEqual(json.loads(text)["subject_id"], SUBJ)


class TestVerify(Base):
    def setUp(self) -> None:
        self.s = make_session()
        self.p0, self.s0 = self.do_commit(self.s, now=T0)
        self.b = self.bundle(self.s, [(self.p0, self.s0)])

    def test_valid_on_time(self) -> None:
        v = self.verify(self.b)
        self.assertEqual(v.verdict, "VALID_ON_TIME", (v.errors, v.warnings))
        self.assertEqual(v.effective_revision, 0)
        self.assertEqual(v.effective_payload, PAYLOAD)

    def test_survives_json_roundtrip(self) -> None:
        v = self.verify(json.loads(json.dumps(self.b)))
        self.assertEqual(v.verdict, "VALID_ON_TIME")

    def test_late(self) -> None:
        v = self.verify(self.b, deadline=T0 - dt.timedelta(minutes=1))
        self.assertEqual(v.verdict, "LATE")
        self.assertIsNone(v.effective_revision)

    def test_accuracy_pushes_upper_bound_past_deadline(self) -> None:
        # genTime 10:00:00, accuracy 1s -> upper bound 10:00:01; deadline 10:00:00.5 is missed.
        v = self.verify(self.b, deadline=T0 + dt.timedelta(milliseconds=500))
        self.assertEqual(v.verdict, "LATE")
        v = self.verify(self.b, deadline=T0 + dt.timedelta(seconds=2))
        self.assertEqual(v.verdict, "VALID_ON_TIME")

    def test_missing_accuracy_assumed_and_flagged(self) -> None:
        tsa = FakeTsa(self.auth, now=T0, accuracy=None)
        with patch("sasana.rfc3161.request_timestamp", tsa):
            pub, sec = cm.commit(
                subject_id=SUBJ,
                context_id=CTX,
                payload=PAYLOAD,
                session_events=self.s,
                trusted_tsa_anchors=self.anchors,
            )
        b = self.bundle(self.s, [(pub, sec)])
        v = self.verify(b, deadline=T0 + dt.timedelta(seconds=2))
        self.assertEqual(v.verdict, "VALID_ON_TIME")
        self.assertTrue(any("TSA_ACCURACY_ASSUMED" in w for w in v.warnings))
        # Within the assumed 1s default, it is not provably on time.
        v = self.verify(b, deadline=T0 + dt.timedelta(milliseconds=500))
        self.assertEqual(v.verdict, "LATE")

    def test_tampered_payload(self) -> None:
        b = copy.deepcopy(self.b)
        b["revisions"][0]["payload"]["direction"] = "down"
        v = self.verify(b)
        self.assertEqual(v.verdict, "INVALID")
        self.assertIn("does not match revealed", v.checks["revisions"][0]["errors"][0])

    def test_tampered_salt(self) -> None:
        b = copy.deepcopy(self.b)
        b["revisions"][0]["salt"] = "00" * 32
        v = self.verify(b)
        self.assertEqual(v.verdict, "INVALID")
        self.assertIn("does not match revealed", v.checks["revisions"][0]["errors"][0])

    def test_tampered_trace_event(self) -> None:
        b = copy.deepcopy(self.b)
        b["session_events"][1]["payload"]["prompt_hash"] = "f" * 64
        v = self.verify(b)
        self.assertEqual(v.verdict, "INVALID")
        self.assertIn("trace", " ".join(v.errors))

    def test_trace_rewritten_consistently_after_commit_is_detected(self) -> None:
        # Attacker rebuilds a *valid* chain with different content: root no longer matches.
        other = make_session(extra=[("LLM_RESPONSE", {"content_hash": "c" * 64})])
        b = copy.deepcopy(self.b)
        b["session_events"] = other
        v = self.verify(b)
        self.assertEqual(v.verdict, "INVALID")
        self.assertIn("session_root", v.checks["revisions"][0]["errors"][0])

    def test_untrusted_tsa_anchor(self) -> None:
        v = self.verify(self.b, trusted_tsa_anchors=[fx.make_authority().anchor_der])
        self.assertEqual(v.verdict, "INVALID")
        self.assertIn("timestamp invalid", v.checks["revisions"][0]["errors"][0])

    def test_forged_timestamp_from_unpinned_tsa(self) -> None:
        rogue = FakeTsa(fx.make_authority(), now=T0 - dt.timedelta(days=1))
        with patch("sasana.rfc3161.request_timestamp", rogue):
            # committer cannot even obtain it via commit() (fail-closed) ...
            with self.assertRaises(cm.CommitmentError):
                cm.commit(
                    subject_id=SUBJ,
                    context_id=CTX,
                    payload=PAYLOAD,
                    session_events=self.s,
                    trusted_tsa_anchors=self.anchors,
                )
        # ... and splicing a rogue token into a bundle fails verification.
        b = copy.deepcopy(self.b)
        c = bytes.fromhex(b["revisions"][0]["commitment"])
        import base64

        b["revisions"][0]["tsa_token"] = base64.b64encode(
            fx.respond(fx.make_authority(), c, gen_time=T0 - dt.timedelta(days=1))
        ).decode()
        self.assertEqual(self.verify(b).verdict, "INVALID")

    def test_truncated_session_fails_trace_check(self) -> None:
        b = copy.deepcopy(self.b)
        b["session_events"] = b["session_events"][:1]
        v = self.verify(b)
        self.assertEqual(v.verdict, "INVALID")
        self.assertIn("trace", " ".join(v.errors))

    def test_commit_on_open_session_then_post_commitment_events_reported(self) -> None:
        s_open = make_session(close=False)
        pub, sec = self.do_commit(s_open)
        # The session continues after the commitment: extend the exact committed chain.
        full = list(s_open)
        from sasana.envelope import build_event

        full.append(
            build_event(
                full[-1]["seq"] + 1,
                "SESSION_END",
                "sess-1",
                {"status": "success"},
                full[-1]["event_hash"],
            )
        )
        full.append(
            build_event(
                full[-1]["seq"] + 1,
                "LLM_CALL",
                "sess-1",
                {"prompt_hash": "d" * 64},
                full[-1]["event_hash"],
            )
        )
        b = self.bundle(full, [(pub, sec)])
        v = self.verify(b)
        self.assertEqual(v.verdict, "VALID_ON_TIME", (v.errors, v.warnings))
        self.assertTrue(any(w.startswith("POST_COMMITMENT_EVENTS:2") for w in v.warnings))

    def test_incomplete_session_rejected_at_reveal(self) -> None:
        s_open = make_session(close=False)
        pub, sec = self.do_commit(s_open)
        v = self.verify(self.bundle(s_open, [(pub, sec)]))
        self.assertEqual(v.verdict, "INVALID")

    def test_partial_trace_rejected_unless_allowed(self) -> None:
        s = make_session(extra=[("LOG_DROP", {"reason": "privacy"})])
        pair = self.do_commit(s)
        b = self.bundle(s, [pair])
        self.assertEqual(self.verify(b).verdict, "INVALID")
        v = self.verify(b, allow_partial=True)
        self.assertEqual(v.verdict, "VALID_ON_TIME")
        self.assertIn("TRACE_PARTIAL", v.warnings)

    def test_in_process_capture_mode_warns(self) -> None:
        b = self.bundle(self.s, [(self.p0, self.s0)], mode="in_process")
        v = self.verify(b)
        self.assertTrue(any(w.startswith("CAPTURE_MODE_IN_PROCESS") for w in v.warnings))

    def test_disclosures(self) -> None:
        seq = next(e["seq"] for e in self.s if e["event_type"] == "TOOL_CALL")
        good = {"seq": seq, "field": "args_hash", "form": "jcs", "preimage": {"q": 1}}
        b = self.bundle(self.s, [(self.p0, self.s0)], disclosures=[good])
        v = self.verify(b)
        self.assertEqual(v.verdict, "VALID_ON_TIME")
        self.assertTrue(v.checks["disclosures"][0]["ok"])
        b["disclosures"][0]["preimage"] = {"q": 2}
        v = self.verify(b)
        self.assertEqual(v.verdict, "VALID_ON_TIME")  # informational only
        self.assertTrue(any(w.startswith("DISCLOSURE_FAILED") for w in v.warnings))

    def test_bad_deadline_and_malformed_input_never_raise(self) -> None:
        self.assertEqual(
            cm.verify_commitment({}, deadline=DEADLINE, trusted_tsa_anchors=self.anchors).verdict,
            "INVALID",
        )
        naive = DEADLINE.replace(tzinfo=None)
        self.assertEqual(self.verify(self.b, deadline=naive).verdict, "INVALID")
        for mutate in (
            lambda b: b.update(revisions=[{"revision_index": "zero"}]),
            lambda b: b.update(session_events="nope"),
            lambda b: b.update(revisions=[]),
            lambda b: b["revisions"][0].pop("tsa_token"),
            lambda b: b.update(domain_tag="other"),
        ):
            b = copy.deepcopy(self.b)
            mutate(b)
            self.assertEqual(self.verify(b).verdict, "INVALID")


class TestRevisions(Base):
    def setUp(self) -> None:
        self.s = make_session()

    def two_revisions(self, t0=T0, t1=T0 + dt.timedelta(minutes=30)):
        p0, s0 = self.do_commit(self.s, now=t0)
        p1, s1 = self.do_commit(
            self.s,
            now=t1,
            prev=p0,
            payload={**PAYLOAD, "direction": "down", "revision_reason": "news"},
        )
        return (p0, s0), (p1, s1)

    def test_last_revision_before_deadline_is_effective_and_superseded_verifies(self) -> None:
        a, b = self.two_revisions()
        v = self.verify(self.bundle(self.s, [a, b]))
        self.assertEqual(v.verdict, "VALID_ON_TIME", (v.errors, v.warnings))
        self.assertEqual(v.effective_revision, 1)
        self.assertEqual(v.effective_payload["direction"], "down")
        self.assertTrue(all(r["valid"] for r in v.checks["revisions"]))

    def test_late_revision_is_not_effective(self) -> None:
        a, b = self.two_revisions(t1=DEADLINE + dt.timedelta(hours=1))
        v = self.verify(self.bundle(self.s, [a, b]))
        self.assertEqual(v.verdict, "VALID_ON_TIME")
        self.assertEqual(v.effective_revision, 0)
        self.assertEqual(v.effective_payload["direction"], "up")

    def test_invalid_higher_revision_makes_verdict_invalid(self) -> None:
        a, b = self.two_revisions()
        bundle = self.bundle(self.s, [a, b])
        bundle["revisions"][1]["payload"]["direction"] = "sideways"
        v = self.verify(bundle)
        self.assertEqual(v.verdict, "INVALID")

    def test_invalid_lower_revision_is_only_a_warning(self) -> None:
        a, b = self.two_revisions()
        bundle = self.bundle(self.s, [a, b])
        bundle["revisions"][0]["payload"]["direction"] = "sideways"
        v = self.verify(bundle)
        self.assertEqual(v.verdict, "VALID_ON_TIME")
        self.assertEqual(v.effective_revision, 1)
        self.assertTrue(any(w.startswith("REVISION_INVALID:0") for w in v.warnings))

    def test_prev_commitment_mismatch(self) -> None:
        a, b = self.two_revisions()
        bundle = self.bundle(self.s, [a, b])
        bundle["revisions"][1]["prev_commitment"] = "00" * 32
        self.assertEqual(self.verify(bundle).verdict, "INVALID")

    def test_revision_zero_with_prev_is_invalid(self) -> None:
        a, _ = self.two_revisions()
        bundle = self.bundle(self.s, [a])
        bundle["revisions"][0]["prev_commitment"] = "00" * 32
        self.assertEqual(self.verify(bundle).verdict, "INVALID")

    def test_unrevealed_predecessor_is_flagged(self) -> None:
        _, b = self.two_revisions()
        v = self.verify(self.bundle(self.s, [b]))
        self.assertEqual(v.verdict, "VALID_ON_TIME")
        self.assertTrue(any(w.startswith("UNREVEALED_REVISION") for w in v.warnings))

    def test_non_monotonic_timestamps_invalid(self) -> None:
        a, b = self.two_revisions(t0=T0 + dt.timedelta(hours=1), t1=T0)
        self.assertEqual(self.verify(self.bundle(self.s, [a, b])).verdict, "INVALID")

    def test_duplicate_revision_index_invalid(self) -> None:
        a, _ = self.two_revisions()
        bundle = self.bundle(self.s, [a])
        bundle["revisions"].append(copy.deepcopy(bundle["revisions"][0]))
        self.assertEqual(self.verify(bundle).verdict, "INVALID")


class TestRegistry(Base):
    def setUp(self) -> None:
        self.s = make_session()
        self.p0, self.s0 = self.do_commit(self.s, now=T0)
        self.b = self.bundle(self.s, [(self.p0, self.s0)])

    def entry(self, pub, received=T0 + dt.timedelta(seconds=5)):
        return {
            "commitment": pub.commitment,
            "subject_id": pub.subject_id,
            "context_id": pub.context_id,
            "revision_index": pub.revision_index,
            "received_at": received.isoformat(),
        }

    def test_received_in_time(self) -> None:
        v = self.verify(self.b, registry=[self.entry(self.p0)])
        self.assertEqual(v.verdict, "VALID_ON_TIME")

    def test_not_in_registry_is_not_on_time(self) -> None:
        v = self.verify(self.b, registry=[])
        self.assertEqual(v.verdict, "LATE")

    def test_received_after_deadline_is_not_on_time(self) -> None:
        v = self.verify(self.b, registry=[self.entry(self.p0, DEADLINE + dt.timedelta(minutes=1))])
        self.assertEqual(v.verdict, "LATE")

    def test_unrevealed_registry_entry_is_flagged(self) -> None:
        hidden = cm.PublicCommitment(
            **{**self.p0.to_dict(), "commitment": "ee" * 32, "revision_index": 1}
        )
        v = self.verify(self.b, registry=[self.entry(self.p0), self.entry(hidden)])
        self.assertEqual(v.verdict, "VALID_ON_TIME")
        self.assertTrue(any(w.startswith("UNREVEALED_COMMITMENT") for w in v.warnings))

    def test_equivocation_is_invalid(self) -> None:
        twin = cm.PublicCommitment(**{**self.p0.to_dict(), "commitment": "ee" * 32})
        v = self.verify(self.b, registry=[self.entry(self.p0), self.entry(twin)])
        self.assertEqual(v.verdict, "INVALID")
        self.assertTrue(any("EQUIVOCATION" in e for e in v.errors))

    def test_other_contexts_ignored(self) -> None:
        other = {**self.entry(self.p0), "context_id": "someone-else", "commitment": "dd" * 32}
        v = self.verify(self.b, registry=[self.entry(self.p0), other])
        self.assertEqual(v.verdict, "VALID_ON_TIME")
        self.assertFalse(any(w.startswith("UNREVEALED_COMMITMENT") for w in v.warnings))


if __name__ == "__main__":
    unittest.main()


class TestCli(Base):
    def run_cli(self, bundle, deadline, anchor_der, *extra):
        import contextlib
        import io

        import sasana_cli
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization

        with tempfile.TemporaryDirectory() as d:
            bp, ap = Path(d) / "b.json", Path(d) / "anchor.pem"
            bp.write_text(json.dumps(bundle))
            cert = x509.load_der_x509_certificate(anchor_der)
            ap.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                code = sasana_cli._cmd_verify_commitment(
                    [str(bp), "--deadline", deadline, "--tsa-anchor", str(ap), *extra]
                )
            return code, out.getvalue()

    def test_exit_codes_and_json(self) -> None:
        s = make_session()
        b = self.bundle(s, [self.do_commit(s, now=T0)])
        code, out = self.run_cli(b, "2026-06-01T12:00:00Z", self.anchors[0], "--json")
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["verdict"], "VALID_ON_TIME")
        code, _ = self.run_cli(b, "2026-06-01T09:00:00Z", self.anchors[0])
        self.assertEqual(code, 2)  # LATE
        code, _ = self.run_cli(b, "2026-06-01T12:00:00Z", fx.make_authority().anchor_der)
        self.assertEqual(code, 1)  # INVALID (wrong anchor)

    def test_bad_input_exit_3(self) -> None:
        import sasana_cli

        self.assertEqual(
            sasana_cli._cmd_verify_commitment(
                [
                    "/nonexistent.json",
                    "--deadline",
                    "2026-06-01T12:00:00Z",
                    "--tsa-anchor",
                    "/x.pem",
                ]
            ),
            3,
        )
