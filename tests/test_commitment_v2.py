"""
tests/test_commitment_v2.py — C_v2 (prev_commitment and mapping id inside C), counterparty acceptance
receipts (a PROPOSED EXTENSION), the scored-revision rule, and the trust and time policy.

Scenario names a..i follow examples/ha-reveal/. Every policy claim in docs/pre-outcome-commitment.md
Part 3 maps to a test here (or is marked NOT ENFORCED and tested as a limitation).
Synthetic data only; the TSA and the receipt signer are local throwaway keys; no network.
"""

from __future__ import annotations

import copy
import datetime as dt
import inspect
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
from test_commitment import CTX, DEADLINE, SUBJ, T0, Base, FakeTsa, make_session  # noqa: E402

from sasana import commitment as cm  # noqa: E402
from sasana import commitment_mapping as cmap  # noqa: E402
from sasana.signing import generate_keypair  # noqa: E402

MAP = cmap.HA_DAILY_V2
T1 = T0 + dt.timedelta(minutes=30)
T2 = T0 + dt.timedelta(minutes=60)
LATE = DEADLINE + dt.timedelta(hours=1)
SEC = dt.timedelta(seconds=2)

SUB0 = {
    "direction": "up",
    "confidence": 0.72,
    "probabilities": {"up": 0.72, "down": 0.28},
    "reasoning": "Synthetic reasoning that is comfortably longer than twenty characters.",
    "summary": "up",
    "is_revision": False,
}
SUB1 = {
    **SUB0,
    "direction": "down",
    "confidence": "0.64",
    "probabilities": {"up": 0.36, "down": 0.64},
    "summary": "down",
    "is_revision": True,
    "revision_reason": "synthetic news",
}
SUB2 = {
    **SUB1,
    "direction": "flat",
    "confidence": "0.51",
    "probabilities": {"up": 0.2, "down": 0.29, "flat": 0.51},
}


def iso(t: dt.datetime) -> str:
    return t.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class V2Base(Base):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls.rkey, cls.rpub = generate_keypair()
        cls.full = make_session(
            extra=[("LLM_CALL", {"prompt_hash": "b" * 64}), ("LLM_CALL", {"prompt_hash": "c" * 64})]
        )  # START, LLM, TOOL, LLM, LLM, END

    def commit2(self, prefix, submission, when, *, prev=None, auth=None, mapping=MAP, **tsa_kw):
        tsa = FakeTsa(auth or self.auth, now=when, **tsa_kw)
        anchors = [(auth or self.auth).anchor_der]
        with patch("sasana.rfc3161.request_timestamp", tsa):
            return cm.commit(
                subject_id=SUBJ,
                context_id=CTX,
                payload=cmap.get_mapping(mapping).map(submission).payload,
                session_events=self.full[:prefix],
                trusted_tsa_anchors=anchors,
                prev=prev,
                mapping_id=mapping,
            )

    def chain(self, t1=T1):
        p0 = self.commit2(3, SUB0, T0)
        p1 = self.commit2(4, SUB1, t1, prev=p0[0])
        return p0, p1

    def receipt(self, pair, *, accepted=True, at=None, reason=None, key=None, **over):
        pub, sec = pair
        body = {
            "challenge_id": CTX,
            "agent_id": SUBJ,
            "revision_index": pub.revision_index,
            "commitment": pub.commitment,
            "accepted_at": iso(at or T0 + SEC),
            "accepted": accepted,
            "reason": reason,
        }
        body.update(over)
        return cm.sign_receipt(body, key or self.rkey)

    def bundle2(self, pairs, session=None):
        return cm.reveal_bundle(pairs, session or self.full, capture_mode="sidecar")

    def closing(self, receipts, *, key=None, at=None, mapping_id=MAP, **over):
        """A closing receipt that AGREES with `receipts`: what an honest counterparty would sign."""
        eligible = sorted(
            (
                r["body"]
                for r in receipts
                if r["body"]["accepted"]
                and (r["body"]["agent_id"], r["body"]["challenge_id"]) == (SUBJ, CTX)
                and cm._parse_when(r["body"]["accepted_at"]) < DEADLINE
            ),
            key=lambda b: b["revision_index"],
        )
        last = eligible[-1] if eligible else None
        body = {
            "challenge_id": CTX,
            "agent_id": SUBJ,
            "accepted_count": len(eligible),
            "last_accepted_revision_index": None if last is None else last["revision_index"],
            "last_accepted_C": None if last is None else last["commitment"],
            "closed_at": iso(at or DEADLINE + dt.timedelta(minutes=1)),
            "mapping_id": mapping_id,
        }
        body.update(over)
        return cm.sign_closing_receipt(body, key or self.rkey)

    def vr(self, bundle, receipts, closing="auto", **kw):
        if closing == "auto":
            closing = None if receipts is None else self.closing(receipts)
        kw.setdefault("trusted_receipt_pubkey", self.rpub)
        kw.setdefault("expected_mapping_id", MAP)
        return self.verify(bundle, receipts=receipts, closing_receipt=closing, **kw)


class TestV2CommitAndBundle(V2Base):
    def test_commit_v2_chain_binds_prev_and_mapping_inside_c(self) -> None:
        (pub0, sec0), (pub1, sec1) = self.chain()
        self.assertEqual((pub0.version, pub0.mapping_id, pub0.prev_commitment), ("2", MAP, None))
        self.assertEqual(pub1.prev_commitment, pub0.commitment)
        self.assertEqual(
            pub1.commitment,
            cm.compute_commitment_v2(
                mapping_id=MAP,
                subject_id=SUBJ,
                context_id=CTX,
                revision_index=1,
                prev_commitment=pub0.commitment,
                payload=sec1.payload,
                session_root=sec1.session_root,
                salt=sec1.salt,
            ),
        )

    def test_commit_refuses_what_it_cannot_bind(self) -> None:
        s = self.full[:3]
        kw = dict(
            subject_id=SUBJ, context_id=CTX, session_events=s, trusted_tsa_anchors=self.anchors
        )
        with patch("sasana.rfc3161.request_timestamp", FakeTsa(self.auth)):
            with self.assertRaises(cm.CommitmentError):  # unknown mapping
                cm.commit(payload={"direction": "up"}, mapping_id="nope-v1", **kw)
            with self.assertRaises(
                cm.CommitmentError
            ):  # not canonical: "0.720" would hash differently elsewhere
                cm.commit(payload={"confidence": "0.720"}, mapping_id=MAP, **kw)
            with self.assertRaises(cm.CommitmentError):  # a float
                cm.commit(payload={"confidence": 0.72}, mapping_id=MAP, **kw)
            p0, _ = cm.commit(payload={"direction": "up"}, mapping_id=MAP, **kw)
            v1_pub, _ = cm.commit(payload={"direction": "up"}, **kw)
            with self.assertRaises(
                cm.CommitmentError
            ):  # extending a v1 chain with v2, and vice versa
                cm.commit(payload={"direction": "up"}, mapping_id=MAP, prev=v1_pub, **kw)
            with self.assertRaises(cm.CommitmentError):
                cm.commit(payload={"direction": "up"}, prev=p0, **kw)

    def test_bundle_v2_shape_and_json_roundtrip(self) -> None:
        b = self.bundle2(list(self.chain()))
        self.assertEqual(
            (b["bundle_version"], b["domain_tag"], b["mapping_id"]), ("2", "sasana/commit/v2", MAP)
        )
        b = json.loads(json.dumps(b))
        v = self.vr(b, None, expected_mapping_id=MAP)
        self.assertEqual(v.verdict, "VALID_ON_TIME", (v.errors, v.warnings))
        self.assertEqual(v.checks["policy"]["commitment_version"], "2")

    def test_reveal_refuses_mixed_versions_and_bad_secrets(self) -> None:
        p0, p1 = self.chain()
        with patch("sasana.rfc3161.request_timestamp", FakeTsa(self.auth, now=T0)):
            v1 = cm.commit(
                subject_id=SUBJ,
                context_id=CTX,
                payload={"d": "x"},
                session_events=self.full[:3],
                trusted_tsa_anchors=self.anchors,
            )
        with self.assertRaises(cm.CommitmentError):
            self.bundle2([p0, v1])
        with self.assertRaises(cm.CommitmentError):
            self.bundle2([(p1[0], p0[1])])  # secrets of revision 0 under revision 1's commitment

    def test_prev_commitment_is_authenticated_by_the_timestamped_commitment(self) -> None:
        """C_v1 only checked prev_commitment for self-consistency. In C_v2 editing it breaks C itself."""
        b = self.bundle2(list(self.chain()))
        b["revisions"][1]["prev_commitment"] = "00" * 32
        v = self.verify(b, expected_mapping_id=MAP)
        self.assertEqual(v.verdict, "INVALID")
        self.assertIn("commitment does not match", " ".join(v.checks["revisions"][1]["errors"]))

    def test_splicing_a_different_predecessor_is_detected(self) -> None:
        p0, p1 = self.chain()
        other0 = self.commit2(
            3, {**SUB0, "direction": "down"}, T0
        )  # a different, equally valid revision 0
        v = self.verify(self.bundle2([other0, p1]), expected_mapping_id=MAP)
        self.assertEqual(v.verdict, "INVALID")
        self.assertTrue(
            any("prev_commitment does not match revision 0" in e for e in v.errors), v.errors
        )

    def test_revision_zero_cannot_carry_a_prev(self) -> None:
        b = self.bundle2([self.chain()[0]])
        b["revisions"][0]["prev_commitment"] = "11" * 32
        self.assertEqual(self.verify(b).verdict, "INVALID")

    def test_a_c_v1_bundle_still_verifies_but_cannot_satisfy_a_required_mapping(self) -> None:
        s = self.full[:3]
        with patch("sasana.rfc3161.request_timestamp", FakeTsa(self.auth, now=T0)):
            pair = cm.commit(
                subject_id=SUBJ,
                context_id=CTX,
                payload={"direction": "up"},
                session_events=s,
                trusted_tsa_anchors=self.anchors,
            )
        b = self.bundle2([pair])
        self.assertEqual(b["bundle_version"], "1")
        self.assertEqual(self.verify(b).verdict, "VALID_ON_TIME")
        v = self.verify(b, expected_mapping_id=MAP)
        self.assertEqual(v.verdict, "INVALID")
        self.assertIn("C_v1", v.errors[0])

    def test_noncanonical_payload_is_rejected_even_when_the_hash_matches(self) -> None:
        """A hash match must not hide a change in meaning: 0.720 vs 0.72 are the same number under two
        spellings, so a committer who hashed the spelling HA would not produce is refused."""
        sec_payload = cmap.map_ha_daily_v2(SUB0).payload
        pub, sec = self.commit2(3, SUB0, T0)
        odd = {**sec_payload, "confidence": "0.720"}
        salt = sec.salt
        c = cm.compute_commitment_v2(
            mapping_id=MAP, subject_id=SUBJ, context_id=CTX, revision_index=0,
            prev_commitment=None, payload=odd, session_root=sec.session_root, salt=salt,
        )  # fmt: skip
        b = self.bundle2([(pub, sec)])
        b["revisions"][0].update(payload=odd, commitment=c)
        v = self.verify(b)
        self.assertEqual(
            v.verdict, "INVALID"
        )  # (the token is for the other C, but the canonical check fires first)
        self.assertIn("not canonical", " ".join(v.checks["revisions"][0]["errors"]))


class TestReceiptSignatures(V2Base):
    def test_roundtrip_and_tamper(self) -> None:
        pair = self.chain()[0]
        r = self.receipt(pair)
        body, err = cm.verify_receipt(r, self.rpub)
        self.assertIsNone(err)
        self.assertEqual(body["commitment"], pair[0].commitment)
        for field, value in (("accepted", False), ("accepted_at", iso(T0)), ("revision_index", 5)):
            bad = copy.deepcopy(r)
            bad["body"][field] = value
            self.assertIsNotNone(cm.verify_receipt(bad, self.rpub)[1], field)

    def test_only_the_pinned_key_counts(self) -> None:
        pair = self.chain()[0]
        other_key, other_pub = generate_keypair()
        self.assertIsNotNone(cm.verify_receipt(self.receipt(pair, key=other_key), self.rpub)[1])
        self.assertIsNone(cm.verify_receipt(self.receipt(pair, key=other_key), other_pub)[1])
        r = self.receipt(pair)
        r["public_key"] = other_pub  # an embedded key is ignored, never trusted
        r_forged = self.receipt(pair, key=other_key)
        r_forged["public_key"] = other_pub
        self.assertIsNotNone(cm.verify_receipt(r_forged, self.rpub)[1])

    def test_domain_separation(self) -> None:
        pair = self.chain()[0]
        r = self.receipt(pair)
        # the same signature does not verify as a bare-JCS signature, i.e. the domain tag is in the message
        from sasana.jcs import canonicalize

        sig = bytes.fromhex(r["signature"])
        import base64

        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        with self.assertRaises(InvalidSignature):
            Ed25519PublicKey.from_public_bytes(base64.b64decode(self.rpub)).verify(
                sig, canonicalize(r["body"])
            )

    def test_malformed_receipts_never_raise(self) -> None:
        pair = self.chain()[0]
        good = self.receipt(pair)
        cases = [
            None,
            {},
            {"body": {}, "signature": "00"},
            {**good, "signature": "zz"},
            {**good, "signature": good["signature"][:-2]},
            {"body": {**good["body"], "extra": 1}, "signature": good["signature"]},
            {"body": {**good["body"], "accepted": "yes"}, "signature": good["signature"]},
            {
                "body": {**good["body"], "accepted_at": "2026-06-01T10:00:00"},
                "signature": good["signature"],
            },
            {"body": {**good["body"], "commitment": "ab"}, "signature": good["signature"]},
        ]
        for c in cases:
            self.assertIsNotNone(cm.verify_receipt(c, self.rpub)[1], str(c)[:60])
        self.assertIsNotNone(cm.verify_receipt(good, "not-base64!!")[1])
        self.assertIsNotNone(cm.verify_receipt(good, "AAAA")[1])


class TestScenarios(V2Base):
    """Scenarios a..i (examples/ha-reveal/ builds the same cases as files)."""

    def test_a_initial_only_accepted(self) -> None:
        p0 = self.chain()[0]
        v = self.vr(self.bundle2([p0]), [self.receipt(p0)])
        self.assertEqual(
            (v.verdict, v.effective_revision), ("VALID_ON_TIME", 0), (v.errors, v.warnings)
        )
        self.assertEqual(v.checks["receipts"]["scored_revision"], 0)

    def test_b_initial_and_revision_accepted_revision_is_scored(self) -> None:
        p0, p1 = self.chain()
        v = self.vr(self.bundle2([p0, p1]), [self.receipt(p0), self.receipt(p1, at=T1 + SEC)])
        self.assertEqual(
            (v.verdict, v.effective_revision), ("VALID_ON_TIME", 1), (v.errors, v.warnings)
        )
        self.assertEqual(v.effective_payload["direction"], "down")
        self.assertTrue(
            all(r["valid"] for r in v.checks["revisions"])
        )  # the superseded one still verifies
        self.assertFalse(
            [w for w in v.warnings if w.startswith("TSA_TIME_AFTER")]
        )  # honest ordering

    def test_c_revision_rejected_by_the_counterparty_initial_is_scored(self) -> None:
        """The highest on-time revision in the bundle (1) is NOT the one the counterparty accepted (0)."""
        p0, p1 = self.chain()
        b = self.bundle2([p0, p1])
        rs = [self.receipt(p0), self.receipt(p1, accepted=False, at=T1 + SEC, reason="synthetic")]
        v = self.vr(b, rs)
        self.assertEqual((v.verdict, v.effective_revision), ("VALID_ON_TIME", 0))
        self.assertEqual(v.effective_payload["direction"], "up")
        self.assertIn("NOT_ACCEPTED_BY_COUNTERPARTY:1", v.warnings)
        # the same bundle WITHOUT receipts scores revision 1: exactly the ambiguity receipts remove
        w = self.verify(b)
        self.assertEqual(w.effective_revision, 1)
        self.assertTrue(any(x.startswith("NO_RECEIPTS") for x in w.warnings))

    def test_c2_retry_after_rejection_continues_the_chain(self) -> None:
        p0, p1 = self.chain()
        p2 = self.commit2(5, SUB2, T2, prev=p1[0])
        rs = [
            self.receipt(p0),
            self.receipt(p1, accepted=False, at=T1 + SEC),
            self.receipt(p2, at=T2 + SEC),
        ]
        v = self.vr(self.bundle2([p0, p1, p2]), rs)
        self.assertEqual(
            (v.verdict, v.effective_revision), ("VALID_ON_TIME", 2), (v.errors, v.warnings)
        )

    def test_d_bundle_omits_the_initial_commitment(self) -> None:
        p0, p1 = self.chain()
        rs = [self.receipt(p0), self.receipt(p1, at=T1 + SEC)]
        v = self.vr(self.bundle2([p1]), rs)
        self.assertEqual(v.verdict, "INVALID")
        self.assertTrue(any(e.startswith("HISTORY_GAP") for e in v.errors), v.errors)
        # the gap is provable because prev_commitment is inside C: this is the selective-reveal check
        self.assertEqual(self.bundle2([p1])["revisions"][0]["prev_commitment"], p0[0].commitment)
        # policy knob: a committer who lost revision 0's salt may accept a verdict with a warning
        w = self.vr(self.bundle2([p1]), rs, allow_unrevealed_history=True)
        self.assertEqual((w.verdict, w.effective_revision), ("VALID_ON_TIME", 1))
        self.assertTrue(any(x.startswith("HISTORY_GAP") for x in w.warnings))
        self.assertIn("UNREVEALED_COMMITMENT:0", w.warnings)

    def test_e_revision_after_deadline_is_not_eligible(self) -> None:
        p0, p1 = self.chain(t1=LATE)
        rs = [
            self.receipt(p0),
            self.receipt(p1, accepted=False, at=LATE + SEC, reason="after deadline"),
        ]
        v = self.vr(self.bundle2([p0, p1]), rs)
        self.assertEqual((v.verdict, v.effective_revision), ("VALID_ON_TIME", 0))
        self.assertFalse(v.checks["revisions"][1]["timestamp_on_time"])

    def test_e2_receipt_says_accepted_but_the_timestamp_is_after_the_deadline(self) -> None:
        """Inconsistent evidence: a commitment cannot be submitted before it exists. The scored revision is
        the counterparty's (1), it is not provably on time, so the verdict is LATE. There is NO silent
        fall-back to revision 0, which the counterparty did not score."""
        p0, p1 = self.chain(t1=LATE)
        rs = [self.receipt(p0), self.receipt(p1, at=DEADLINE - dt.timedelta(minutes=1))]
        v = self.vr(self.bundle2([p0, p1]), rs)
        self.assertEqual((v.verdict, v.effective_revision), ("LATE", None))
        self.assertIn("SCORED_REVISION_NOT_ON_TIME:1", v.warnings)
        # impossible ordering is reported on its own: acceptance at 11:59, the TSA says 13:00
        self.assertIn("TSA_TIME_AFTER_ACCEPTANCE:1", v.warnings)
        # ...unless the verifier assumes the two clocks may disagree by that much
        skewed = self.vr(self.bundle2([p0, p1]), rs, clock_skew_s=7200.0)
        self.assertNotIn("TSA_TIME_AFTER_ACCEPTANCE:1", skewed.warnings)

    def test_f_payload_tampered_after_commit(self) -> None:
        p0, p1 = self.chain()
        b = self.bundle2([p0, p1])
        b["revisions"][1]["payload"]["confidence"] = "0.94"
        v = self.vr(b, [self.receipt(p0), self.receipt(p1, at=T1 + SEC)])
        self.assertEqual(v.verdict, "INVALID")
        self.assertTrue(
            any("commitment does not match revealed payload" in e for e in v.errors), v.errors
        )

    def test_f2_a_tampered_superseded_revision_is_unverified_history_not_a_warning(self) -> None:
        """Presenting a broken reveal of an earlier revision hides it as surely as omitting it, so it is
        treated like the d case (HISTORY_GAP) and not downgraded to a REVISION_INVALID warning."""
        p0, p1 = self.chain()
        b = self.bundle2([p0, p1])
        b["revisions"][0]["payload"]["direction"] = "flat"
        rs = [self.receipt(p0), self.receipt(p1, at=T1 + SEC)]
        v = self.vr(b, rs)
        self.assertEqual((v.verdict, v.effective_revision), ("INVALID", None))
        self.assertTrue(
            any(e.startswith("HISTORY_GAP") and "failed verification" in e for e in v.errors),
            v.errors,
        )
        w = self.vr(b, rs, allow_unrevealed_history=True)
        self.assertEqual((w.verdict, w.effective_revision), ("VALID_ON_TIME", 1))
        self.assertTrue(any(x.startswith("REVISION_INVALID:0") for x in w.warnings))

    def test_g_wrong_mapping_version(self) -> None:
        p0 = self.chain()[0]
        b = self.bundle2([p0])
        b["mapping_id"] = "ha-daily-v3"
        v = self.vr(b, [self.receipt(p0)])
        self.assertEqual(v.verdict, "INVALID")
        self.assertIn("unknown payload mapping", v.errors[0])

    def test_g2_relabelling_to_another_known_mapping_breaks_c(self) -> None:
        """The mapping id is inside C: the same payload relabelled under a different (known) mapping is a
        different commitment, so a hash match cannot be reinterpreted."""
        alt = cmap.PayloadMapping(
            "ha-daily-alt",
            cmap.map_ha_daily_v2,
            cmap.check_canonical_ha_daily_v2,
            cmap.probability_warnings,
        )
        p0 = self.chain()[0]
        b = self.bundle2([p0])
        b["mapping_id"] = "ha-daily-alt"
        with (
            patch.dict(cmap.MAPPINGS, {"ha-daily-alt": alt})
            if isinstance(cmap.MAPPINGS, dict)
            else self.fail("MAPPINGS must be a dict")
        ):
            v = self.verify(b)  # no expected_mapping_id: only C can catch it
        self.assertEqual(v.verdict, "INVALID")
        self.assertIn("commitment does not match", " ".join(v.checks["revisions"][0]["errors"]))

    def test_g3_a_required_mapping_is_enforced(self) -> None:
        p0 = self.chain()[0]
        v = self.vr(self.bundle2([p0]), [self.receipt(p0)], expected_mapping_id="ha-daily-v1")
        self.assertEqual(v.verdict, "INVALID")
        self.assertIn("is not the required", v.errors[0])

    def test_h_never_revealed_is_unrevealed_not_failed_or_passed(self) -> None:
        p0, p1 = self.chain()
        b = self.bundle2([p0, p1])
        b["revisions"], b["session_events"] = [], []
        v = self.vr(b, [self.receipt(p0), self.receipt(p1, at=T1 + SEC)])
        self.assertEqual(v.verdict, "UNREVEALED")
        self.assertIsNone(v.effective_revision)
        self.assertEqual(v.errors, [])
        self.assertEqual(v.checks["receipts"]["scored_revision"], 1)
        self.assertIsNone(v.checks["trace"])
        # the same empty bundle with NO receipts says nothing, so it stays INVALID
        self.assertEqual(self.verify(b).verdict, "INVALID")

    def test_h2_the_scored_revision_is_the_one_not_revealed(self) -> None:
        p0, p1 = self.chain()
        v = self.vr(self.bundle2([p0]), [self.receipt(p0), self.receipt(p1, at=T1 + SEC)])
        self.assertEqual(
            v.verdict, "UNREVEALED"
        )  # revision 0 verifies, but the counterparty scored 1
        self.assertIn("UNREVEALED_COMMITMENT:1", v.warnings)

    def test_i_a8_operator_reseal_after_commit_session_root_no_longer_matches(self) -> None:
        from test_tamper_matrix import _rechain

        p0 = self.chain()[0]
        forged = copy.deepcopy(self.full)
        forged[1]["payload"]["prompt_hash"] = "f" * 64  # rewrite BEFORE the committed root
        crafted = self.bundle2([p0])
        crafted["session_events"] = _rechain(forged)  # internally consistent, hash chain verifies
        v = self.vr(crafted, [self.receipt(p0)])
        self.assertEqual(v.verdict, "INVALID")
        self.assertTrue(any("session_root is not an event" in e for e in v.errors), v.errors)


class TestReceiptPolicy(V2Base):
    def two(self):
        p0, p1 = self.chain()
        return p0, p1, self.bundle2([p0, p1])

    def test_receipts_need_a_pinned_key(self) -> None:
        p0, p1, b = self.two()
        v = self.verify(b, receipts=[self.receipt(p0)])  # no trusted_receipt_pubkey
        self.assertEqual(v.verdict, "INVALID")
        self.assertIn("no receipt key pinned", v.errors[0])

    def test_receipts_signed_by_another_key_are_invalid(self) -> None:
        p0, p1, b = self.two()
        other_key, _ = generate_keypair()
        v = self.vr(b, [self.receipt(p0), self.receipt(p1, key=other_key, at=T1 + SEC)])
        self.assertEqual(v.verdict, "INVALID")
        self.assertTrue(any(e.startswith("RECEIPT_INVALID:1") for e in v.errors), v.errors)

    def test_receipts_for_other_agents_or_challenges_are_ignored(self) -> None:
        p0, p1, b = self.two()
        noise = [
            self.receipt(p1, agent_id="someone-else", at=T1 + SEC),
            self.receipt(p1, challenge_id="other-challenge", at=T1 + SEC),
        ]
        v = self.vr(b, [self.receipt(p0), *noise])
        self.assertEqual((v.verdict, v.effective_revision), ("VALID_ON_TIME", 0))
        self.assertEqual(v.checks["receipts"]["out_of_scope"], 2)

    def test_two_accepted_commitments_for_one_revision_is_equivocation(self) -> None:
        p0, p1, b = self.two()
        twin = self.commit2(4, {**SUB1, "direction": "flat"}, T1, prev=p0[0])
        v = self.vr(
            b, [self.receipt(p0), self.receipt(p1, at=T1 + SEC), self.receipt(twin, at=T1 + SEC)]
        )
        self.assertEqual(v.verdict, "INVALID")
        self.assertTrue(any("EQUIVOCATION" in e for e in v.errors), v.errors)

    def test_contradictory_receipts_for_one_commitment(self) -> None:
        p0, p1, b = self.two()
        v = self.vr(
            b,
            [
                self.receipt(p0),
                self.receipt(p1, at=T1 + SEC),
                self.receipt(p1, accepted=False, at=T1 + SEC),
            ],
        )
        self.assertEqual(v.verdict, "INVALID")
        self.assertTrue(any("RECEIPT_CONFLICT" in e for e in v.errors), v.errors)

    def test_acceptance_after_the_deadline_is_not_eligible(self) -> None:
        p0, p1, b = self.two()
        v = self.vr(b, [self.receipt(p0), self.receipt(p1, at=DEADLINE + SEC)])
        self.assertEqual((v.verdict, v.effective_revision), ("VALID_ON_TIME", 0))
        self.assertIn("RECEIPT_AFTER_DEADLINE:1", v.warnings)

    def test_acceptance_exactly_at_the_deadline_is_not_eligible(self) -> None:
        p0, p1, b = self.two()
        v = self.vr(b, [self.receipt(p0), self.receipt(p1, at=DEADLINE)])
        self.assertEqual(v.effective_revision, 0)

    def test_no_accepted_receipt_before_the_deadline_is_late(self) -> None:
        p0, p1, b = self.two()
        v = self.vr(
            b, [self.receipt(p0, accepted=False), self.receipt(p1, accepted=False, at=T1 + SEC)]
        )
        self.assertEqual(v.verdict, "LATE")
        self.assertIn("NO_ACCEPTED_RECEIPT_BEFORE_DEADLINE", v.warnings)
        self.assertEqual(
            self.vr(b, []).verdict, "LATE"
        )  # an empty receipt log: nothing was accepted

    def test_acceptance_order_must_follow_revision_order(self) -> None:
        p0, p1, b = self.two()
        v = self.vr(b, [self.receipt(p0, at=T1 + SEC), self.receipt(p1, at=T0 + SEC)])
        self.assertEqual(v.verdict, "INVALID")
        self.assertTrue(any("RECEIPTS_NON_MONOTONIC" in e for e in v.errors), v.errors)

    def test_receipt_payload_hash_must_match_what_was_revealed(self) -> None:
        p0, p1, b = self.two()
        good = cm.payload_hash(p1[1].payload).hex()
        ok = self.vr(
            b, [self.receipt(p0), self.receipt(p1, at=T1 + SEC, mapping_id=MAP, payload_hash=good)]
        )
        self.assertEqual(ok.verdict, "VALID_ON_TIME", (ok.errors, ok.warnings))
        bad = self.vr(b, [self.receipt(p0), self.receipt(p1, at=T1 + SEC, payload_hash="00" * 32)])
        self.assertEqual(bad.verdict, "INVALID")
        self.assertTrue(any("RECEIPT_PAYLOAD_MISMATCH" in e for e in bad.errors), bad.errors)

    def test_receipt_mapping_and_index_must_match(self) -> None:
        p0, p1, b = self.two()
        v = self.vr(b, [self.receipt(p0), self.receipt(p1, at=T1 + SEC, mapping_id="ha-daily-v1")])
        self.assertTrue(any("RECEIPT_MAPPING_MISMATCH" in e for e in v.errors), v.errors)
        v = self.vr(b, [self.receipt(p0), self.receipt(p1, at=T1 + SEC, revision_index=7)])
        self.assertTrue(any("RECEIPT_INDEX_MISMATCH" in e for e in v.errors), v.errors)

    def test_a_failed_scored_revision_is_not_replaced_by_a_lower_valid_one(self) -> None:
        p0, p1, b = self.two()
        b["revisions"][1]["salt"] = "00" * 32
        v = self.vr(b, [self.receipt(p0), self.receipt(p1, at=T1 + SEC)])
        self.assertEqual(v.verdict, "INVALID")

    def test_require_receipts(self) -> None:
        p0, p1, b = self.two()
        v = self.verify(b, require_receipts=True)
        self.assertEqual(v.verdict, "INVALID")
        self.assertIn("receipts are required", v.errors[0])

    def test_without_receipts_a_v2_bundle_warns_that_acceptance_is_unknown(self) -> None:
        p0, p1, b = self.two()
        v = self.verify(b)
        self.assertEqual(v.verdict, "VALID_ON_TIME")
        self.assertTrue(any(w.startswith("NO_RECEIPTS") for w in v.warnings))


class TestTimeAndTrustPolicy(V2Base):
    """Each statement in the note's Part 3 maps to a test here."""

    def one(self, when, *, accuracy=(1, None, None), auth=None):
        a = auth or self.auth
        pair = self.commit2(3, SUB0, when, auth=a, accuracy=accuracy)
        return pair, self.bundle2([pair])

    def test_empty_trust_anchors_fail_closed(self) -> None:
        _, b = self.one(T0)
        v = self.verify(b, trusted_tsa_anchors=[])
        self.assertEqual(v.verdict, "INVALID")
        self.assertIn("no TSA trust anchors", v.errors[0])

    def test_unknown_tsa_is_rejected_even_if_its_cert_travels_in_the_token(self) -> None:
        rogue = fx.make_authority()
        _, b = self.one(T0, auth=rogue)
        v = self.verify(b)  # verifier pins the real anchor
        self.assertEqual(v.verdict, "INVALID")
        self.assertIn("timestamp invalid", " ".join(v.checks["revisions"][0]["errors"]))
        self.assertEqual(
            self.verify(b, trusted_tsa_anchors=[rogue.anchor_der]).verdict, "VALID_ON_TIME"
        )

    def test_a_token_whose_signing_cert_was_not_valid_at_gentime_is_refused_at_commit(self) -> None:
        expired = fx.make_authority(
            valid_from=dt.datetime(2020, 1, 1, tzinfo=dt.timezone.utc),
            valid_to=dt.datetime(2026, 5, 1, tzinfo=dt.timezone.utc),
        )
        with self.assertRaises(cm.CommitmentError):
            self.commit2(3, SUB0, T0, auth=expired)

    def test_time_rule_is_strict_gentime_plus_accuracy_before_deadline(self) -> None:
        # accuracy is 1 s in the fixture: upper bound = genTime + 1 s
        _, on_time = self.one(DEADLINE - dt.timedelta(seconds=2))
        self.assertEqual(self.verify(on_time).verdict, "VALID_ON_TIME")
        _, boundary = self.one(DEADLINE - dt.timedelta(seconds=1))  # upper bound == deadline
        self.assertEqual(self.verify(boundary).verdict, "LATE")
        _, after = self.one(DEADLINE)
        self.assertEqual(self.verify(after).verdict, "LATE")

    def test_declared_accuracy_widens_the_window(self) -> None:
        _, b = self.one(DEADLINE - dt.timedelta(minutes=5), accuracy=(600, None, None))
        v = self.verify(b)
        self.assertEqual(v.verdict, "LATE")
        self.assertEqual(v.checks["revisions"][0]["accuracy_s"], 600)

    def test_absent_accuracy_is_assumed_and_reported(self) -> None:
        _, b = self.one(DEADLINE - dt.timedelta(seconds=30), accuracy=None)
        v = self.verify(b)
        self.assertEqual(v.verdict, "VALID_ON_TIME")
        self.assertTrue(any(w.startswith("TSA_ACCURACY_ASSUMED") for w in v.warnings))
        self.assertTrue(v.checks["revisions"][0]["accuracy_assumed"])
        # the assumption is the verifier's to set: a stricter one turns the same token LATE
        self.assertEqual(self.verify(b, default_accuracy_s=60.0).verdict, "LATE")
        self.assertEqual(v.checks["policy"]["accuracy_default_s"], 1.0)

    def test_clock_skew_allowance_is_part_of_the_time_rule(self) -> None:
        _, b = self.one(DEADLINE - dt.timedelta(seconds=5))  # upper bound = deadline - 4 s
        self.assertEqual(self.verify(b).verdict, "VALID_ON_TIME")
        self.assertEqual(self.verify(b, clock_skew_s=3.0).verdict, "VALID_ON_TIME")
        self.assertEqual(self.verify(b, clock_skew_s=4.0).verdict, "LATE")  # == deadline
        v = self.verify(b, clock_skew_s=30.0)
        self.assertEqual(v.verdict, "LATE")
        self.assertEqual(v.checks["policy"]["clock_skew_s"], 30.0)

    def test_bad_skew_values_fail_closed(self) -> None:
        _, b = self.one(T0)
        for bad in (-1.0, float("nan"), float("inf"), "soon"):
            self.assertEqual(self.verify(b, clock_skew_s=bad).verdict, "INVALID", repr(bad))

    def test_the_deadline_comes_from_the_verifier_never_from_the_bundle(self) -> None:
        _, b = self.one(T0)
        b["deadline"] = "2099-01-01T00:00:00Z"  # ignored
        self.assertEqual(self.verify(b, deadline=T0 - dt.timedelta(hours=1)).verdict, "LATE")
        naive = cm.verify_commitment(
            b, deadline=dt.datetime(2026, 6, 1), trusted_tsa_anchors=self.anchors
        )  # a naive deadline is refused, not guessed
        self.assertEqual(naive.verdict, "INVALID")
        self.assertIn("bad deadline", naive.errors[0])

    # --- NOT ENFORCED ---------------------------------------------------------------------------

    def test_revocation_is_not_checked_NOT_ENFORCED(self) -> None:
        params = inspect.signature(cm.verify_commitment).parameters
        self.assertFalse([p for p in params if "revo" in p or "crl" in p or "ocsp" in p])
        _, b = self.one(T0)
        v = self.verify(b)
        self.assertIs(v.checks["policy"]["revocation_checked"], False)

    def test_what_missing_revocation_costs_a_stolen_tsa_key_can_backdate_NOT_ENFORCED(self) -> None:
        """An attacker holding a TSA signing key (or the TSA itself) can mint a token with any genTime.
        Revocation checking would only help if the CA had revoked that key AND we compared the revocation
        date with genTime; we do neither, so such a token verifies exactly like an honest one."""
        real_now = LATE  # the commitment is actually made AFTER the deadline...
        stolen_clock = T0  # ...but the key holder stamps it as if it were 10:00
        pair = self.commit2(3, SUB0, stolen_clock)
        self.assertGreater(real_now, DEADLINE)
        self.assertEqual(self.verify(self.bundle2([pair])).verdict, "VALID_ON_TIME")


class TestSealIsOptionalAndNotRelied(V2Base):
    def test_unpinned_seal_key_is_reported_and_does_not_change_the_verdict(self) -> None:
        p0 = self.chain()[0]
        v = self.vr(self.bundle2([p0]), [self.receipt(p0)])
        self.assertEqual(v.verdict, "VALID_ON_TIME")
        self.assertIs(v.checks["policy"]["seal_key_pinned"], False)
        self.assertNotEqual(
            v.evidence_class, "AUTHORITATIVE_EVIDENCE"
        )  # no seal, no pin: not authoritative

    def test_pinning_a_seal_key_demands_a_seal(self) -> None:
        p0 = self.chain()[0]
        _, pub = generate_keypair()
        v = self.vr(self.bundle2([p0]), [self.receipt(p0)], trusted_seal_pubkey=pub)
        self.assertEqual(v.verdict, "INVALID")
        self.assertTrue(any("no CHAIN_SEAL" in e for e in v.errors), v.errors)


class TestCli(V2Base):
    def run_cli(self, bundle, receipts, *extra, anchor=None, closing="auto", text=False):
        import contextlib
        import io

        from cryptography import x509
        from cryptography.hazmat.primitives import serialization

        import sasana_cli

        with tempfile.TemporaryDirectory() as d:
            bp, rp, ap = Path(d) / "b.json", Path(d) / "r.json", Path(d) / "anchor.pem"
            cp = Path(d) / "c.json"
            bp.write_text(json.dumps(bundle))
            rp.write_text(json.dumps(receipts))
            if closing == "auto":
                closing = None if receipts is None else self.closing(receipts)
            if closing is not None:
                cp.write_text(json.dumps(closing))
            ap.write_bytes(
                x509.load_der_x509_certificate(anchor or self.anchors[0]).public_bytes(
                    serialization.Encoding.PEM
                )
            )
            args = [
                str(bp),
                "--deadline",
                "2026-06-01T12:00:00Z",
                "--tsa-anchor",
                str(ap),
            ]
            if not text:
                args.append("--json")
            if receipts is not None or closing is not None:
                args += ["--receipt-key", self.rpub]
            if receipts is not None:
                args += ["--receipts", str(rp)]
            if closing is not None:
                args += ["--closing-receipt", str(cp)]
            out = io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
                code = sasana_cli._cmd_verify_commitment(args + list(extra))
            return code, out.getvalue()

    def test_exit_codes_including_unrevealed(self) -> None:
        p0, p1 = self.chain()
        rs = [self.receipt(p0), self.receipt(p1, at=T1 + SEC)]
        code, out = self.run_cli(self.bundle2([p0, p1]), rs, "--mapping", MAP)
        self.assertEqual((code, json.loads(out)["verdict"]), (0, "VALID_ON_TIME"))
        code, out = self.run_cli(self.bundle2([p0]), rs, "--mapping", MAP)
        self.assertEqual((code, json.loads(out)["verdict"]), (4, "UNREVEALED"))
        code, _ = self.run_cli(self.bundle2([p1]), rs, "--mapping", MAP)
        self.assertEqual(code, 1)  # history gap
        # a lenient pass is NOT a strict pass: exit 5, and the JSON says so
        code, out = self.run_cli(
            self.bundle2([p1]), rs, "--mapping", MAP, "--allow-unrevealed-history"
        )
        self.assertEqual(code, 5, out)
        j = json.loads(out)
        self.assertEqual(
            (j["verdict"], j["lenient"]), ("VALID_ON_TIME", ["unrevealed history allowed"])
        )
        # no closing receipt: not valid, and not the same as invalid either
        code, out = self.run_cli(self.bundle2([p0, p1]), rs, "--mapping", MAP, closing=None)
        self.assertEqual((code, json.loads(out)["verdict"]), (6, "INCOMPLETE_RECEIPTS"))

    def test_the_lenient_banner_is_printed_in_text_mode(self) -> None:
        p0, p1 = self.chain()
        rs = [self.receipt(p0), self.receipt(p1, at=T1 + SEC)]
        code, out = self.run_cli(self.bundle2([p1]), rs, "--allow-unrevealed-history", text=True)
        self.assertEqual(code, 5)
        self.assertIn("LENIENT: unrevealed history allowed", out)
        code, out = self.run_cli(self.bundle2([p0, p1]), rs, text=True)
        self.assertEqual(code, 0)
        self.assertNotIn("LENIENT", out)

    def test_unknown_or_abbreviated_flags_are_refused_not_ignored(self) -> None:
        p0 = self.chain()[0]
        b, rs = self.bundle2([p0]), [self.receipt(p0)]
        for bad in (["--recipt-key", "x"], ["--trust", "x"], ["--no-such-flag"], ["--mapping"]):
            code, _ = self.run_cli(b, rs, *bad)
            self.assertEqual(code, 3, bad)  # exit 3, never a silent drop of a policy flag

    def test_receipts_without_a_key_are_refused(self) -> None:
        import contextlib
        import io

        import sasana_cli

        p0 = self.chain()[0]
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "b.json").write_text(json.dumps(self.bundle2([p0])))
            (Path(d) / "r.json").write_text(json.dumps([self.receipt(p0)]))
            from cryptography import x509
            from cryptography.hazmat.primitives import serialization

            (Path(d) / "a.pem").write_bytes(
                x509.load_der_x509_certificate(self.anchors[0]).public_bytes(
                    serialization.Encoding.PEM
                )
            )
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                code = sasana_cli._cmd_verify_commitment(
                    [str(Path(d) / "b.json"), "--deadline", "2026-06-01T12:00:00Z", "--tsa-anchor",
                     str(Path(d) / "a.pem"), "--receipts", str(Path(d) / "r.json"), "--json"]
                )  # fmt: skip
        self.assertEqual(code, 1)
        self.assertIn("no receipt key pinned", out.getvalue())


class TestClosingReceipt(V2Base):
    """PROPOSED EXTENSION: the counterparty signs, at the deadline, how many submissions it accepted and which
    was last. Without it a verifier cannot tell a complete receipt list from one with a receipt withheld."""

    def two(self):
        p0, p1 = self.chain()
        return p0, p1, self.bundle2([p0, p1]), [self.receipt(p0), self.receipt(p1, at=T1 + SEC)]

    def test_j_a_withheld_later_accepted_receipt_is_caught(self) -> None:
        """The committer hands over only the initial's receipt; the counterparty's closing receipt says two
        submissions were accepted, the last being revision 1."""
        p0, p1, b, rs = self.two()
        honest_closing = self.closing(rs)
        v = self.vr(b, [rs[0]], closing=honest_closing)
        self.assertEqual(v.verdict, "INVALID")
        self.assertTrue(
            any(e.startswith("RECEIPT_LIST_DISAGREES_WITH_CLOSING") for e in v.errors), v.errors
        )
        # the same withholding WITHOUT a closing receipt is not even a valid verdict: it is INCOMPLETE
        self.assertEqual(self.vr(b, [rs[0]], closing=None).verdict, "INCOMPLETE_RECEIPTS")

    def test_j2_an_extra_receipt_is_caught_too(self) -> None:
        p0, p1, b, rs = self.two()
        v = self.vr(b, rs, closing=self.closing([rs[0]]))  # closing says one; two supplied
        self.assertEqual(v.verdict, "INVALID")
        self.assertTrue(any("RECEIPT_LIST_DISAGREES_WITH_CLOSING" in e for e in v.errors), v.errors)

    def test_j3_same_count_but_a_different_last_commitment(self) -> None:
        p0, p1, b, rs = self.two()
        other = self.commit2(4, {**SUB1, "direction": "flat"}, T1, prev=p0[0])
        closing = self.closing(rs, last_accepted_C=other[0].commitment)
        v = self.vr(b, rs, closing=closing)
        self.assertEqual(v.verdict, "INVALID")
        self.assertTrue(any("RECEIPT_LIST_DISAGREES_WITH_CLOSING" in e for e in v.errors), v.errors)

    def test_k_closing_receipt_missing_is_incomplete_not_valid(self) -> None:
        p0, p1, b, rs = self.two()
        v = self.vr(b, rs, closing=None)
        self.assertEqual(v.verdict, "INCOMPLETE_RECEIPTS")
        self.assertIsNone(v.effective_revision)
        self.assertTrue(any(w.startswith("CLOSING_RECEIPT_MISSING") for w in v.warnings))
        self.assertEqual(v.checks["receipts"]["closing_receipt"], "missing")
        self.assertNotIn(v.verdict, ("VALID_ON_TIME", "LATE", "UNREVEALED"))

    def test_k2_incomplete_even_when_the_scored_revision_is_unrevealed_or_late(self) -> None:
        p0, p1, b, rs = self.two()
        self.assertEqual(
            self.vr(self.bundle2([p0]), rs, closing=None).verdict, "INCOMPLETE_RECEIPTS"
        )
        self.assertEqual(self.vr(b, [], closing=None).verdict, "INCOMPLETE_RECEIPTS")

    def test_k3_other_errors_still_win_over_incomplete(self) -> None:
        p0, p1, b, rs = self.two()
        b["revisions"][1]["salt"] = "00" * 32
        self.assertEqual(self.vr(b, rs, closing=None).verdict, "INVALID")

    def test_l_closing_receipt_signed_by_the_wrong_key(self) -> None:
        p0, p1, b, rs = self.two()
        other_key, _ = generate_keypair()
        v = self.vr(b, rs, closing=self.closing(rs, key=other_key))
        self.assertEqual(v.verdict, "INVALID")
        self.assertTrue(any(e.startswith("CLOSING_RECEIPT_INVALID") for e in v.errors), v.errors)

    def test_closing_body_tampering_invalidates_the_signature(self) -> None:
        p0, p1, b, rs = self.two()
        c = self.closing(rs)
        c["body"]["accepted_count"] = 1
        self.assertEqual(self.vr(b, rs, closing=c).verdict, "INVALID")

    def test_a_consistent_closing_receipt_gives_the_normal_verdicts(self) -> None:
        p0, p1, b, rs = self.two()
        v = self.vr(b, rs)
        self.assertEqual((v.verdict, v.effective_revision), ("VALID_ON_TIME", 1))
        self.assertEqual(v.checks["receipts"]["closing_receipt"], "ok")
        self.assertEqual(self.vr(self.bundle2([p0]), rs).verdict, "UNREVEALED")

    def test_closing_must_not_predate_the_deadline(self) -> None:
        p0, p1, b, rs = self.two()
        early = self.closing(rs, at=DEADLINE - dt.timedelta(seconds=1))
        v = self.vr(b, rs, closing=early)
        self.assertEqual(v.verdict, "INVALID")
        self.assertTrue(any(e.startswith("CLOSING_BEFORE_DEADLINE") for e in v.errors), v.errors)
        self.assertEqual(
            self.vr(b, rs, closing=self.closing(rs, at=DEADLINE)).verdict, "VALID_ON_TIME"
        )

    def test_closing_for_another_agent_or_challenge_is_an_error_not_ignored(self) -> None:
        p0, p1, b, rs = self.two()
        for over in ({"agent_id": "someone-else"}, {"challenge_id": "other"}):
            v = self.vr(b, rs, closing=self.closing(rs, **over))
            self.assertEqual(v.verdict, "INVALID", over)
            self.assertTrue(any("CLOSING_RECEIPT_OUT_OF_SCOPE" in e for e in v.errors), v.errors)

    def test_closing_must_name_the_bundles_mapping(self) -> None:
        p0, p1, b, rs = self.two()
        v = self.vr(b, rs, closing=self.closing(rs, mapping_id="ha-daily-v1"))
        self.assertEqual(v.verdict, "INVALID")
        self.assertTrue(any("CLOSING_MAPPING_MISMATCH" in e for e in v.errors), v.errors)

    def test_nothing_accepted_is_a_late_verdict_and_the_list_must_be_empty_of_accepted(
        self,
    ) -> None:
        p0, p1, b, rs = self.two()
        rejected = [self.receipt(p0, accepted=False), self.receipt(p1, accepted=False, at=T1 + SEC)]
        v = self.vr(b, rejected)
        self.assertEqual(v.verdict, "LATE")
        self.assertEqual(v.checks["receipts"]["scored_revision"], None)
        # a closing receipt that says "none accepted" contradicts a list that holds an accepted receipt
        v = self.vr(b, rs, closing=self.closing(rejected))
        self.assertEqual(v.verdict, "INVALID")

    def test_acceptances_after_the_deadline_are_not_counted(self) -> None:
        p0, p1, b, rs = self.two()
        late = [rs[0], self.receipt(p1, at=DEADLINE + SEC)]
        v = self.vr(b, late)  # auto closing: one eligible acceptance
        self.assertEqual((v.verdict, v.effective_revision), ("VALID_ON_TIME", 0))
        self.assertIn("RECEIPT_AFTER_DEADLINE:1", v.warnings)

    def test_closing_alone_names_the_scored_revision(self) -> None:
        p0, p1, b, rs = self.two()
        v = self.verify(
            b, receipts=None, closing_receipt=self.closing(rs), trusted_receipt_pubkey=self.rpub,
            expected_mapping_id=MAP,
        )  # fmt: skip
        self.assertEqual((v.verdict, v.effective_revision), ("VALID_ON_TIME", 1))
        self.assertTrue(any(w.startswith("NO_PER_SUBMISSION_RECEIPTS") for w in v.warnings))
        v = self.verify(
            self.bundle2([p0]), receipts=None, closing_receipt=self.closing(rs),
            trusted_receipt_pubkey=self.rpub, expected_mapping_id=MAP,
        )  # fmt: skip
        self.assertEqual(v.verdict, "UNREVEALED")

    def test_closing_needs_the_pinned_key_too(self) -> None:
        p0, p1, b, rs = self.two()
        v = self.verify(b, receipts=None, closing_receipt=self.closing(rs))
        self.assertEqual(v.verdict, "INVALID")
        self.assertIn("no receipt key pinned", v.errors[0])

    def test_the_two_receipt_kinds_cannot_stand_in_for_each_other(self) -> None:
        p0, p1, b, rs = self.two()
        closing = self.closing(rs)
        self.assertIsNotNone(
            cm.verify_receipt(closing, self.rpub)[1]
        )  # a closing receipt is not a receipt
        self.assertIsNotNone(cm.verify_closing_receipt(rs[0], self.rpub)[1])
        # same bytes, different domain tag: re-signing the closing body under the receipt domain still fails
        forged = {
            "body": closing["body"],
            "signature": self.rkey.sign(
                cm.RECEIPT_DOMAIN + cm.jcs_canonicalize(closing["body"])
            ).hex(),
        }
        self.assertIsNotNone(cm.verify_closing_receipt(forged, self.rpub)[1])

    def test_closing_body_shape_rules(self) -> None:
        p0, p1, b, rs = self.two()
        good = self.closing(rs)["body"]
        for over in (
            {"accepted_count": -1},
            {"accepted_count": True},
            {"accepted_count": 0},  # count 0 with a non-null last
            {"last_accepted_C": "ab"},
            {"last_accepted_revision_index": "1"},
            {"closed_at": "2026-06-01T12:01:00"},  # naive
            {"mapping_id": "Bad Id"},
        ):
            with self.assertRaises(ValueError, msg=str(over)):
                cm.sign_closing_receipt({**good, **over}, self.rkey)
        with self.assertRaises(ValueError):
            cm.sign_closing_receipt({k: v for k, v in good.items() if k != "closed_at"}, self.rkey)
        with self.assertRaises(ValueError):
            cm.sign_closing_receipt({**good, "extra": 1}, self.rkey)


class TestLenientAndSuperseded(V2Base):
    def test_a_lenient_pass_says_so_in_the_verdict_and_json(self) -> None:
        p0, p1 = self.chain()
        rs = [self.receipt(p0), self.receipt(p1, at=T1 + SEC)]
        b = self.bundle2([p1])
        strict = self.vr(b, rs)
        self.assertEqual(strict.verdict, "INVALID")
        lenient = self.vr(b, rs, allow_unrevealed_history=True)
        self.assertEqual(lenient.verdict, "VALID_ON_TIME")
        self.assertEqual(list(lenient.lenient), ["unrevealed history allowed"])
        self.assertEqual(lenient.as_dict()["lenient"], ("unrevealed history allowed",))
        self.assertTrue(lenient.checks["policy"]["history_gaps_allowed"])
        self.assertTrue(any(w.startswith("HISTORY_GAP") for w in lenient.warnings))

    def test_a_strict_pass_is_not_marked_lenient_even_if_the_flag_was_set(self) -> None:
        p0, p1 = self.chain()
        rs = [self.receipt(p0), self.receipt(p1, at=T1 + SEC)]
        full = self.bundle2([p0, p1])
        self.assertEqual(self.vr(full, rs).lenient, ())
        v = self.vr(full, rs, allow_unrevealed_history=True)  # flag set but never needed
        self.assertEqual((v.verdict, tuple(v.lenient)), ("VALID_ON_TIME", ()))
        self.assertTrue(v.checks["policy"]["history_gaps_allowed"])  # the setting is still recorded

    def test_lenient_is_recorded_once_however_many_gaps_were_forgiven(self) -> None:
        p0 = self.commit2(3, SUB0, T0)
        p1 = self.commit2(4, SUB1, T1, prev=p0[0])
        p2 = self.commit2(5, SUB2, T2, prev=p1[0])
        rs = [self.receipt(p0), self.receipt(p1, at=T1 + SEC), self.receipt(p2, at=T2 + SEC)]
        b = self.bundle2(
            [p1, p2]
        )  # revision 0 omitted; revision 1's reveal broken: two forgiven gaps
        b["revisions"][0]["payload"]["direction"] = "flat"
        v = self.vr(b, rs, allow_unrevealed_history=True)
        self.assertEqual(sum(w.startswith("HISTORY_GAP") for w in v.warnings), 2)
        self.assertEqual(
            (v.verdict, list(v.lenient)), ("VALID_ON_TIME", ["unrevealed history allowed"])
        )

    def test_a_broken_reveal_allowed_leniently_is_also_marked(self) -> None:
        p0, p1 = self.chain()
        b = self.bundle2([p0, p1])
        b["revisions"][0]["payload"]["direction"] = "flat"
        v = self.vr(
            b, [self.receipt(p0), self.receipt(p1, at=T1 + SEC)], allow_unrevealed_history=True
        )
        self.assertEqual(
            (v.verdict, list(v.lenient)), ("VALID_ON_TIME", ["unrevealed history allowed"])
        )

    def test_a_superseded_mapping_still_verifies_with_a_warning(self) -> None:
        p0 = self.commit2(3, {"direction": "up", "confidence": 0.7}, T0, mapping=cmap.HA_DAILY_V1)
        b = self.bundle2([p0])
        v = self.verify(b)
        self.assertEqual(v.verdict, "VALID_ON_TIME", (v.errors, v.warnings))
        self.assertIn("MAPPING_SUPERSEDED:ha-daily-v1->ha-daily-v2", v.warnings)
        # a verifier that requires the current mapping refuses it
        self.assertEqual(self.verify(b, expected_mapping_id=cmap.HA_DAILY_V2).verdict, "INVALID")
        # and the current mapping carries no such warning
        p = self.chain()[0]
        self.assertFalse([w for w in self.verify(self.bundle2([p])).warnings if "SUPERSEDED" in w])

    def test_a_v2_mapping_bundle_binds_all_fields_end_to_end(self) -> None:
        """Tampering with `amount` or `trigger_event_id` after commit is caught by C (v1 missed both)."""
        full = {
            **SUB1,
            "prompt_hash": "c" * 64,
            "amount": 25,
            "token_usage": {"input": 10, "output": 5},
            "trigger_event_id": "evt-1",
        }
        p0 = self.commit2(3, SUB0, T0)
        p1 = self.commit2(4, full, T1, prev=p0[0])
        rs = [self.receipt(p0), self.receipt(p1, at=T1 + SEC)]
        self.assertEqual(self.vr(self.bundle2([p0, p1]), rs).verdict, "VALID_ON_TIME")
        for field, value in (("amount", "26"), ("trigger_event_id", "evt-2")):
            b = self.bundle2([p0, p1])
            b["revisions"][1]["payload"][field] = value
            v = self.vr(b, rs)
            self.assertEqual(v.verdict, "INVALID", field)
            self.assertTrue(
                any("commitment does not match" in e for e in v.errors), (field, v.errors)
            )


if __name__ == "__main__":
    unittest.main()
