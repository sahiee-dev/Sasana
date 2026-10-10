"""
tests/test_rfc3161_strict.py — strict RFC 3161 verification (CMS signature, chain, EKU,
nonce, accuracy) against a local test TSA. No network access.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import sys
import unittest
from pathlib import Path

_ROOT = Path(__file__).parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))
if str(_ROOT / "tests") not in sys.path:
    sys.path.insert(0, str(_ROOT / "tests"))

import tsa_fixture as fx  # noqa: E402
from sasana.rfc3161 import build_timestamp_request, verify_timestamp_strict  # noqa: E402

UTC = dt.timezone.utc
H = hashlib.sha256(b"commitment").digest()


class TestStrictVerification(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.auth = fx.make_authority()
        cls.other = fx.make_authority()  # unrelated CA
        cls.no_eku = fx.make_authority(with_eku=False)
        cls.chained = fx.make_authority(intermediate=True)
        cls.expired = fx.make_authority(
            valid_from=dt.datetime(2020, 1, 1, tzinfo=UTC),
            valid_to=dt.datetime(2021, 1, 1, tzinfo=UTC),
        )

    def verify(self, token, anchors=None, **kw):
        return verify_timestamp_strict(
            token, kw.pop("expected", H), trust_anchors=anchors or [self.auth.anchor_der], **kw
        )

    def test_valid_token(self) -> None:
        r = self.verify(fx.respond(self.auth, H))
        self.assertTrue(r.ok, r.error)
        self.assertEqual(r.gen_time, dt.datetime(2026, 6, 15, 10, 32, 11, 250000, tzinfo=UTC))
        self.assertEqual(r.accuracy_s, 1.0)
        self.assertEqual(r.gen_time_upper, r.gen_time + dt.timedelta(seconds=1))
        self.assertIn("Test TSA", r.signer_subject)

    def test_accuracy_millis_micros(self) -> None:
        r = self.verify(fx.respond(self.auth, H, accuracy=(0, 500, 250)))
        self.assertTrue(r.ok, r.error)
        self.assertAlmostEqual(r.accuracy_s, 0.50025)

    def test_missing_accuracy_reported_as_none(self) -> None:
        r = self.verify(fx.respond(self.auth, H, accuracy=None))
        self.assertTrue(r.ok, r.error)
        self.assertIsNone(r.accuracy_s)
        self.assertEqual(r.gen_time_upper, r.gen_time)

    def test_ski_signer_identifier(self) -> None:
        self.assertTrue(self.verify(fx.respond(self.auth, H, sid="ski")).ok)

    def test_intermediate_chain_with_only_root_pinned(self) -> None:
        tok = fx.respond(self.chained, H)
        r = self.verify(tok, anchors=[self.chained.anchor_der])
        self.assertTrue(r.ok, r.error)

    def test_wrong_hash(self) -> None:
        r = self.verify(fx.respond(self.auth, H), expected=hashlib.sha256(b"x").digest())
        self.assertFalse(r.ok)
        self.assertIn("MessageImprint", r.error)

    def test_untrusted_anchor(self) -> None:
        r = self.verify(fx.respond(self.auth, H), anchors=[self.other.anchor_der])
        self.assertFalse(r.ok)
        self.assertIn("trust anchor", r.error)

    def test_no_anchors(self) -> None:
        r = verify_timestamp_strict(fx.respond(self.auth, H), H, trust_anchors=[])
        self.assertFalse(r.ok)

    def test_self_signed_forgery_not_trusted(self) -> None:
        # Attacker embeds their own cert; only the pinned anchor counts.
        tok = fx.respond(self.other, H)
        self.assertFalse(self.verify(tok).ok)

    def test_tampered_gentime_breaks_message_digest(self) -> None:
        tok = fx.respond(self.auth, H)
        needle = b"20260615103211.25Z"
        self.assertIn(needle, tok)
        forged = tok.replace(needle, b"20260615093211.25Z")
        r = self.verify(forged)
        self.assertFalse(r.ok)
        self.assertIn("messageDigest", r.error)

    def test_tampered_signature(self) -> None:
        r = self.verify(fx.respond(self.auth, H, tamper_signature=True))
        self.assertFalse(r.ok)
        self.assertIn("signature", r.error)

    def test_missing_eku(self) -> None:
        r = self.verify(fx.respond(self.no_eku, H), anchors=[self.no_eku.anchor_der])
        self.assertFalse(r.ok)
        self.assertIn("ExtendedKeyUsage", r.error)

    def test_cert_not_valid_at_gentime(self) -> None:
        r = self.verify(fx.respond(self.expired, H), anchors=[self.expired.anchor_der])
        self.assertFalse(r.ok)

    def test_nonce_match_and_mismatch(self) -> None:
        tok = fx.respond(self.auth, H, nonce=987654321)
        self.assertTrue(self.verify(tok, nonce=987654321).ok)
        self.assertFalse(self.verify(tok, nonce=1).ok)
        self.assertFalse(self.verify(fx.respond(self.auth, H), nonce=987654321).ok)

    def test_policy_allowlist(self) -> None:
        tok = fx.respond(self.auth, H, policy="1.2.3.4.5")
        self.assertTrue(self.verify(tok, allowed_policies=["1.2.3.4.5"]).ok)
        self.assertFalse(self.verify(tok, allowed_policies=["9.9.9"]).ok)

    def test_signer_cert_must_be_in_token(self) -> None:
        r = self.verify(fx.respond(self.auth, H, embed_certs=False))
        self.assertFalse(r.ok)

    def test_status_rejected(self) -> None:
        r = self.verify(fx.respond(self.auth, H, status=2))
        self.assertFalse(r.ok)
        self.assertIn("not granted", r.error)

    def test_garbage_does_not_raise(self) -> None:
        for junk in (b"", b"\x00", b"\x30\x03\x02\x01\x00", b"x" * 100):
            self.assertFalse(self.verify(junk).ok)


class TestNonceInRequest(unittest.TestCase):
    def test_request_without_nonce_is_unchanged_shape(self) -> None:
        req = build_timestamp_request(H)
        self.assertEqual(req[0], 0x30)
        self.assertIn(H, req)

    def test_request_with_nonce_carries_it(self) -> None:
        a = build_timestamp_request(H)
        b = build_timestamp_request(H, nonce=0x0102030405060708)
        self.assertIn(bytes.fromhex("0102030405060708"), b)
        self.assertGreater(len(b), len(a))


if __name__ == "__main__":
    unittest.main()
