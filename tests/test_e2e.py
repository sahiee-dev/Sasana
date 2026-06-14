"""
tests/test_e2e.py — End-to-end: SDK records → Archeion seals → verify → AUTHORITATIVE_EVIDENCE.

Uses FastAPI's TestClient (ASGI, no network) so this runs in CI without a live server.
"""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

_ROOT = Path(__file__).parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

try:
    from fastapi.testclient import TestClient  # noqa: E402

    from archeion.server import app  # noqa: E402

    _FASTAPI_AVAILABLE = True
except ImportError:
    _FASTAPI_AVAILABLE = False

from sasana.sqlite_ledger import SqliteLedger  # noqa: E402
from sasana.verifier import AUTHORITATIVE_EVIDENCE, INTACT, verify  # noqa: E402


def _make_partial_jsonl(tmp: Path, session_id: str = "partial-session") -> Path:
    """Record a session that includes a LOG_DROP event."""
    ledger = SqliteLedger(db_path=tmp / f"{session_id}.db")
    ledger.connect()
    ledger.open_session(session_id=session_id, agent_id="test-agent")
    ledger.record("LOG_DROP", {"dropped_count": 3, "reason": "rate_limit"})
    ledger.record("LLM_CALL", {"prompt_hash": "a" * 64, "prompt_count": 1})
    ledger.close_session(status="success")
    jsonl = tmp / f"{session_id}.jsonl"
    ledger.export_jsonl(jsonl)
    ledger.close()
    return jsonl


def _load_jsonl(path: Path) -> list:
    return [json.loads(ln) for ln in path.read_text().splitlines() if ln.strip()]


def _make_session_jsonl(tmp: Path, session_id: str = "e2e-session") -> Path:
    """Record a real session through SqliteLedger and export to JSONL."""
    ledger = SqliteLedger(db_path=tmp / f"{session_id}.db")
    ledger.connect()
    ledger.open_session(session_id=session_id, agent_id="test-agent")
    ledger.record("LLM_CALL", {"prompt_hash": "a" * 64, "prompt_count": 1})
    ledger.record("LLM_RESPONSE", {"response_hash": "b" * 64, "response_len": 42})
    ledger.record("TOOL_CALL", {"tool_name_hash": "c" * 64, "args_hash": "d" * 64})
    ledger.record("TOOL_RESULT", {"result_hash": "e" * 64})
    ledger.close_session(status="success")
    jsonl = tmp / f"{session_id}.jsonl"
    ledger.export_jsonl(jsonl)
    ledger.close()
    return jsonl


@unittest.skipUnless(_FASTAPI_AVAILABLE, "fastapi / httpx not installed")
class TestSealEndpoint(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)
        self.tmp = Path(tempfile.mkdtemp())

    # ------------------------------------------------------------------
    # Happy path
    # ------------------------------------------------------------------

    def test_seal_appends_chain_seal_event(self):
        jsonl = _make_session_jsonl(self.tmp)
        resp = self.client.post("/seal", content=jsonl.read_bytes())
        self.assertEqual(resp.status_code, 200)
        events = [json.loads(ln) for ln in resp.text.splitlines() if ln.strip()]
        seal_events = [e for e in events if e["event_type"] == "CHAIN_SEAL"]
        self.assertEqual(len(seal_events), 1)

    def test_sealed_session_is_intact_authoritative(self):
        jsonl = _make_session_jsonl(self.tmp)
        resp = self.client.post("/seal", content=jsonl.read_bytes())
        self.assertEqual(resp.status_code, 200)
        sealed_path = self.tmp / "sealed.jsonl"
        sealed_path.write_text(resp.text)
        result = verify(_load_jsonl(sealed_path))
        self.assertEqual(result.status, INTACT)
        self.assertEqual(result.evidence_class, AUTHORITATIVE_EVIDENCE)
        self.assertEqual(result.errors, [])

    def test_chain_seal_has_required_fields(self):
        jsonl = _make_session_jsonl(self.tmp)
        resp = self.client.post("/seal", content=jsonl.read_bytes())
        events = [json.loads(ln) for ln in resp.text.splitlines() if ln.strip()]
        seal = next(e for e in events if e["event_type"] == "CHAIN_SEAL")
        for field in (
            "seq",
            "event_type",
            "session_id",
            "timestamp",
            "payload",
            "prev_hash",
            "event_hash",
            "signature",
        ):
            self.assertIn(field, seal)
        for key in ("session_hash", "sealed_by", "server_pubkey"):
            self.assertIn(key, seal["payload"])

    def test_seal_links_into_hash_chain(self):
        """CHAIN_SEAL prev_hash must equal the last event's event_hash."""
        jsonl = _make_session_jsonl(self.tmp)
        resp = self.client.post("/seal", content=jsonl.read_bytes())
        events = sorted(
            [json.loads(ln) for ln in resp.text.splitlines() if ln.strip()],
            key=lambda e: e["seq"],
        )
        seal = events[-1]
        prev = events[-2]
        self.assertEqual(seal["prev_hash"], prev["event_hash"])

    def test_verify_shows_seal_signature_pass(self):
        jsonl = _make_session_jsonl(self.tmp)
        resp = self.client.post("/seal", content=jsonl.read_bytes())
        result = verify([json.loads(ln) for ln in resp.text.splitlines() if ln.strip()])
        self.assertEqual(result.checks["seal_signature"]["status"], "PASS")

    # ------------------------------------------------------------------
    # Rejection cases
    # ------------------------------------------------------------------

    def test_double_seal_returns_409(self):
        jsonl = _make_session_jsonl(self.tmp)
        resp1 = self.client.post("/seal", content=jsonl.read_bytes())
        self.assertEqual(resp1.status_code, 200)
        resp2 = self.client.post("/seal", content=resp1.content)
        self.assertEqual(resp2.status_code, 409)

    def test_broken_chain_returns_422(self):
        jsonl = _make_session_jsonl(self.tmp)
        events = _load_jsonl(jsonl)
        events[1]["payload"]["injected"] = "evil"
        body = "\n".join(json.dumps(e) for e in events).encode()
        resp = self.client.post("/seal", content=body)
        self.assertEqual(resp.status_code, 422)

    def test_empty_body_returns_400(self):
        resp = self.client.post("/seal", content=b"")
        self.assertEqual(resp.status_code, 400)

    def test_malformed_jsonl_returns_400(self):
        resp = self.client.post("/seal", content=b"not json\n")
        self.assertEqual(resp.status_code, 400)

    def test_partial_session_returns_422(self):
        """Archeion must reject sessions with LOG_DROP events — cannot seal incomplete logs."""
        jsonl = _make_partial_jsonl(self.tmp)
        resp = self.client.post("/seal", content=jsonl.read_bytes())
        self.assertEqual(resp.status_code, 422)
        self.assertIn("LOG_DROP", resp.json()["detail"])

    # ------------------------------------------------------------------
    # Tamper detection
    # ------------------------------------------------------------------

    def test_tampered_seal_signature_detected(self):
        """Replacing the CHAIN_SEAL signature causes verify() to return COMPROMISED."""
        jsonl = _make_session_jsonl(self.tmp)
        resp = self.client.post("/seal", content=jsonl.read_bytes())
        events = [json.loads(ln) for ln in resp.text.splitlines() if ln.strip()]
        for e in events:
            if e["event_type"] == "CHAIN_SEAL":
                e["signature"] = "A" * len(e["signature"])
        result = verify(events)
        self.assertEqual(result.status, "COMPROMISED")
        self.assertTrue(any("signature" in err for err in result.errors))

    def test_tampered_seal_payload_detected(self):
        """Mutating CHAIN_SEAL payload breaks its event_hash → COMPROMISED."""
        jsonl = _make_session_jsonl(self.tmp)
        resp = self.client.post("/seal", content=jsonl.read_bytes())
        events = [json.loads(ln) for ln in resp.text.splitlines() if ln.strip()]
        for e in events:
            if e["event_type"] == "CHAIN_SEAL":
                e["payload"]["sealed_by"] = "attacker"
        result = verify(events)
        self.assertEqual(result.status, "COMPROMISED")

    # ------------------------------------------------------------------
    # Pubkey endpoint
    # ------------------------------------------------------------------

    def test_health_returns_ok(self):
        resp = self.client.get("/health")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["status"], "ok")
        self.assertIn("version", data)
        self.assertIn("pubkey", data)

    def test_health_pubkey_matches_pubkey_endpoint(self):
        """Health endpoint pubkey must equal /pubkey — used for key-change monitoring."""
        health = self.client.get("/health").json()
        pubkey = self.client.get("/pubkey").json()
        self.assertEqual(health["pubkey"], pubkey["pubkey"])

    def test_pubkey_returns_server_key(self):
        resp = self.client.get("/pubkey")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("pubkey", data)
        self.assertEqual(data["algorithm"], "ed25519")
        self.assertEqual(data["encoding"], "base64")

    def test_pubkey_matches_chain_seal_payload(self):
        """The pubkey endpoint must return the same key embedded in CHAIN_SEAL."""
        jsonl = _make_session_jsonl(self.tmp)
        seal_resp = self.client.post("/seal", content=jsonl.read_bytes())
        events = [json.loads(ln) for ln in seal_resp.text.splitlines() if ln.strip()]
        seal = next(e for e in events if e["event_type"] == "CHAIN_SEAL")
        pubkey_resp = self.client.get("/pubkey")
        self.assertEqual(seal["payload"]["server_pubkey"], pubkey_resp.json()["pubkey"])

    def test_trust_key_pinning_accepts_correct_key(self):
        """verify() with the correct trusted_seal_pubkey passes."""
        jsonl = _make_session_jsonl(self.tmp)
        resp = self.client.post("/seal", content=jsonl.read_bytes())
        pubkey = self.client.get("/pubkey").json()["pubkey"]
        events = [json.loads(ln) for ln in resp.text.splitlines() if ln.strip()]
        result = verify(events, trusted_seal_pubkey=pubkey)
        self.assertEqual(result.status, INTACT)
        self.assertEqual(result.checks["seal_signature"]["status"], "PASS")

    def test_trust_key_pinning_rejects_wrong_key(self):
        """verify() with a different trusted_seal_pubkey returns COMPROMISED."""
        from sasana.signing import generate_keypair

        jsonl = _make_session_jsonl(self.tmp)
        resp = self.client.post("/seal", content=jsonl.read_bytes())
        _, wrong_key = generate_keypair()
        events = [json.loads(ln) for ln in resp.text.splitlines() if ln.strip()]
        result = verify(events, trusted_seal_pubkey=wrong_key)
        self.assertEqual(result.status, "COMPROMISED")
        self.assertTrue(any("untrusted key" in e for e in result.errors))


if __name__ == "__main__":
    unittest.main()
