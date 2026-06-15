"""
tests/test_rfc3161.py — RFC 3161 timestamp anchoring tests.

All tests mock the TSA network call. No live network access.
The mock TSA response is built with the same DER primitives as sasana/rfc3161.py
so the full parse/verify path is exercised end-to-end.
"""

from __future__ import annotations

import base64
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

_ROOT = Path(__file__).parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from sasana.jcs import canonicalize as jcs_canonicalize  # noqa: E402
from sasana.rfc3161 import (  # noqa: E402
    _SHA256_ALG_ID,
    _TSTINFO_OID_VALUE,
    _dlen,
    _int_der,
    _octet,
    _seq,
    build_timestamp_request,
    verify_timestamp,
)
from sasana.verifier import compute_event_hash, verify  # noqa: E402


# ---------------------------------------------------------------------------
# Mock TSA response builder (valid DER, no real TSA signature)
# ---------------------------------------------------------------------------


def _build_mock_tsa_response(hash_bytes: bytes, gen_time: str = "20260615103211Z") -> bytes:
    """
    Build a syntactically valid RFC 3161 TimeStampResp DER for the given hash.

    gen_time must be "YYYYMMDDHHmmssZ". The response contains no real TSA signature
    (signerInfos is empty), which is sufficient for testing the parse/verify path
    that verifies only MessageImprint hash matching.
    """

    def _gen_time_der(s: str) -> bytes:
        enc = s.encode("ascii")
        return b"\x18" + _dlen(len(enc)) + enc

    def _oid(value_bytes: bytes) -> bytes:
        return b"\x06" + _dlen(len(value_bytes)) + value_bytes

    def _ctx0(inner: bytes) -> bytes:
        return b"\xa0" + _dlen(len(inner)) + inner

    # TSTInfo SEQUENCE { version, policy, messageImprint, serialNumber, genTime }
    tstinfo = _seq(
        _int_der(1)  # version = 1
        + _oid(bytes.fromhex("60864801650304020103"))  # arbitrary policy OID
        + _seq(_SHA256_ALG_ID + _octet(hash_bytes))  # messageImprint
        + _int_der(42)  # serialNumber
        + _gen_time_der(gen_time)  # genTime
    )

    # EncapsulatedContentInfo { OID(id-ct-TSTInfo), [0]{ OCTET STRING{ tstinfo } } }
    encap = _seq(_oid(_TSTINFO_OID_VALUE) + _ctx0(_octet(tstinfo)))

    # Minimal SignedData { version, digestAlgorithms, encapContentInfo, signerInfos }
    signed_data = _seq(
        _int_der(3)
        + (b"\x31" + _dlen(len(_seq(_SHA256_ALG_ID))) + _seq(_SHA256_ALG_ID))
        + encap
        + b"\x31\x00"  # empty signerInfos
    )

    # ContentInfo { OID(id-signedData), [0]{ SignedData } }
    _SIGNED_DATA_OID = bytes.fromhex("2a864886f70d010702")
    content_info = _seq(_oid(_SIGNED_DATA_OID) + _ctx0(signed_data))

    # TimeStampResp { PKIStatusInfo{ status=0 }, ContentInfo }
    return _seq(_seq(_int_der(0)) + content_info)


# ---------------------------------------------------------------------------
# Session event builder for verifier tests
# ---------------------------------------------------------------------------


def _make_session_events(with_token: bool = False, tamper_token: bool = False) -> list[dict]:
    """Build a minimal valid session, optionally with an RFC 3161 token in SESSION_START."""
    session_id = "test-session-rfc3161"
    base_payload: dict = {"agent_id": "test-agent"}

    if with_token:
        # Compute the pre-token hash (SESSION_START fields without the token)
        base_event: dict = {
            "seq": 1,
            "event_type": "SESSION_START",
            "session_id": session_id,
            "timestamp": "2026-06-15T10:32:00.000000Z",
            "payload": base_payload.copy(),
            "prev_hash": "0" * 64,
        }
        pre_token_hash = hashlib.sha256(jcs_canonicalize(base_event)).digest()

        token_hash = hashlib.sha256(b"wrong-hash").digest() if tamper_token else pre_token_hash
        token_der = _build_mock_tsa_response(token_hash)

        payload: dict = {**base_payload, "rfc3161_token": base64.b64encode(token_der).decode()}
    else:
        payload = base_payload.copy()

    event1: dict = {
        "seq": 1,
        "event_type": "SESSION_START",
        "session_id": session_id,
        "timestamp": "2026-06-15T10:32:00.000000Z",
        "payload": payload,
        "prev_hash": "0" * 64,
    }
    event1["event_hash"] = compute_event_hash(event1)

    event2: dict = {
        "seq": 2,
        "event_type": "SESSION_END",
        "session_id": session_id,
        "timestamp": "2026-06-15T10:32:01.000000Z",
        "payload": {"status": "success"},
        "prev_hash": event1["event_hash"],
    }
    event2["event_hash"] = compute_event_hash(event2)

    return [event1, event2]


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestRfc3161TokenEmbeddedOnSessionStart(unittest.TestCase):
    """SqliteLedger embeds a TSA token in SESSION_START and hash chain remains valid."""

    def test_token_stored_in_payload_and_chain_intact(self) -> None:
        from sasana.sqlite_ledger import SqliteLedger

        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"
            ledger = SqliteLedger(db_path=db_path)
            ledger.connect()

            # Patch request_timestamp so the mock TSA returns a valid token
            # using the same hash the ledger computed for SESSION_START.
            with patch(
                "sasana.rfc3161.request_timestamp",
                side_effect=lambda h: _build_mock_tsa_response(h),
            ):
                ledger.open_session("sess-embed-test", agent_id="test")
                ledger.record("LLM_CALL", {"prompt_hash": "a" * 64})
                ledger.close_session(status="success")

            jsonl_path = Path(tmpdir) / "out.jsonl"
            ledger.export_jsonl(jsonl_path)
            ledger.close()

            events = [json.loads(ln) for ln in jsonl_path.read_text().splitlines() if ln.strip()]

            ss = next(e for e in events if e["event_type"] == "SESSION_START")
            self.assertIn("rfc3161_token", ss["payload"], "TOKEN not embedded in SESSION_START")

            result = verify(events)
            self.assertNotEqual(result.status, "COMPROMISED", result.errors)
            self.assertTrue(result.timestamp_verified, "timestamp_verified should be True")
            ts_check = result.checks.get("rfc3161_timestamp", {})
            self.assertEqual(ts_check.get("status"), "PASS")
            self.assertEqual(ts_check.get("timestamp_utc"), "2026-06-15T10:32:11Z")


class TestRfc3161TsaFailureDoesNotBlockRecording(unittest.TestCase):
    """Network failure is fail-open — session records normally without a token."""

    def test_session_proceeds_without_token_when_tsa_returns_none(self) -> None:
        from sasana.sqlite_ledger import SqliteLedger

        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"
            ledger = SqliteLedger(db_path=db_path)
            ledger.connect()

            with patch("sasana.rfc3161.request_timestamp", return_value=None):
                ledger.open_session("sess-tsa-fail", agent_id="test")
                ledger.record("LLM_CALL", {"prompt_hash": "b" * 64})
                ledger.close_session(status="success")

            jsonl_path = Path(tmpdir) / "out.jsonl"
            ledger.export_jsonl(jsonl_path)
            ledger.close()

            events = [json.loads(ln) for ln in jsonl_path.read_text().splitlines() if ln.strip()]
            ss = next(e for e in events if e["event_type"] == "SESSION_START")

            self.assertNotIn("rfc3161_token", ss["payload"])

            result = verify(events)
            self.assertNotEqual(result.status, "COMPROMISED", result.errors)
            self.assertFalse(result.timestamp_verified)
            ts_check = result.checks.get("rfc3161_timestamp", {})
            self.assertEqual(ts_check.get("status"), "SKIPPED")


class TestRfc3161TokenVerifiesAgainstSessionStartHash(unittest.TestCase):
    """verify_timestamp PASS when MessageImprint matches the pre-token hash."""

    def test_valid_token_returns_true_and_iso_timestamp(self) -> None:
        hash_bytes = hashlib.sha256(b"test-pre-token-hash").digest()
        token_der = _build_mock_tsa_response(hash_bytes, gen_time="20260615103211Z")

        valid, utc_time = verify_timestamp(token_der, hash_bytes)

        self.assertTrue(valid)
        self.assertEqual(utc_time, "2026-06-15T10:32:11Z")

    def test_verifier_check_passes_for_valid_token(self) -> None:
        events = _make_session_events(with_token=True)
        result = verify(events)

        self.assertTrue(result.timestamp_verified)
        ts_check = result.checks.get("rfc3161_timestamp", {})
        self.assertEqual(ts_check.get("status"), "PASS")
        self.assertIsNotNone(ts_check.get("timestamp_utc"))

    def test_session_without_token_check_is_skipped(self) -> None:
        events = _make_session_events(with_token=False)
        result = verify(events)

        self.assertFalse(result.timestamp_verified)
        self.assertEqual(result.checks.get("rfc3161_timestamp", {}).get("status"), "SKIPPED")


class TestRfc3161TamperedTokenDetected(unittest.TestCase):
    """verify_timestamp FAIL when MessageImprint does not match the session hash."""

    def test_wrong_hash_in_token_returns_false(self) -> None:
        real_hash = hashlib.sha256(b"real-hash").digest()
        attacker_hash = hashlib.sha256(b"attacker-hash").digest()
        token_der = _build_mock_tsa_response(attacker_hash)

        valid, utc_time = verify_timestamp(token_der, real_hash)

        self.assertFalse(valid)
        self.assertIsNone(utc_time)

    def test_verifier_check_fails_for_tampered_token(self) -> None:
        events = _make_session_events(with_token=True, tamper_token=True)
        result = verify(events)

        self.assertFalse(result.timestamp_verified)
        ts_check = result.checks.get("rfc3161_timestamp", {})
        self.assertEqual(ts_check.get("status"), "FAIL")

    def test_tampered_token_does_not_break_hash_chain(self) -> None:
        """Swapped token is informational — the hash chain guard is the primary protection."""
        events = _make_session_events(with_token=True, tamper_token=True)
        result = verify(events)

        # Hash chain still passes (token is embedded in payload; stored hash matches it)
        self.assertEqual(result.checks.get("hash_chain", {}).get("status"), "PASS")
        # RFC 3161 FAIL alone does not push status to COMPROMISED
        self.assertNotEqual(result.status, "COMPROMISED")


class TestBuildTimestampRequest(unittest.TestCase):
    """DER request builder produces a parseable outer SEQUENCE with the hash embedded."""

    def test_outer_tag_is_sequence(self) -> None:
        req = build_timestamp_request(b"\xab" * 32)
        self.assertEqual(req[0], 0x30)

    def test_sha256_alg_id_present(self) -> None:
        req = build_timestamp_request(b"\x00" * 32)
        self.assertIn(_SHA256_ALG_ID, req)

    def test_hash_bytes_embedded(self) -> None:
        hash_bytes = hashlib.sha256(b"arbitrary").digest()
        req = build_timestamp_request(hash_bytes)
        self.assertIn(hash_bytes, req)


if __name__ == "__main__":
    unittest.main()
