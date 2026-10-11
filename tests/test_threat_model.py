"""
tests/test_threat_model.py — executable statements of what docs/THREAT_MODEL.md says is NOT defended.

These assert a documented LIMITATION. They pass today because the limitation exists. If one starts
failing, behaviour changed: update docs/THREAT_MODEL.md, README, DEPLOYMENT.md and the CHANGELOG at the
same time rather than "fixing" the test.
"""

from __future__ import annotations

import copy
import json
import sys
import unittest
from pathlib import Path

_ROOT = Path(__file__).parent.parent
for _p in (str(_ROOT), str(_ROOT / "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from test_tamper_matrix import _base_session, _rechain  # noqa: E402

from sasana.verifier import AUTHORITATIVE_EVIDENCE, INTACT, verify  # noqa: E402

try:
    from fastapi.testclient import TestClient  # noqa: E402

    from archeion.server import app  # noqa: E402

    _FASTAPI = True
except ImportError:
    _FASTAPI = False


def _jsonl(events: list) -> bytes:
    return ("\n".join(json.dumps(e) for e in events) + "\n").encode()


@unittest.skipUnless(_FASTAPI, "fastapi / httpx not installed")
class TestA8RewriteThenGenuineSeal(unittest.TestCase):
    """A8 (and A2): the genuine Archeion seals any consistent chain it is sent, including a rewrite of
    a session it already sealed. With the Archeion key pinned, the rewrite verifies as AUTHORITATIVE."""

    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)
        cls.pub = cls.client.get("/pubkey").json()["pubkey"]

    def test_a8_genuine_archeion_seals_a_rewrite_and_it_verifies_authoritative_when_pinned(self):
        original = _base_session()
        r1 = self.client.post("/seal", content=_jsonl(original))
        self.assertEqual(r1.status_code, 200)
        sealed_original = [json.loads(ln) for ln in r1.text.splitlines()]

        rewrite = copy.deepcopy(original)
        rewrite[3]["payload"]["classification"] = "IN-BOUNDS"
        rewrite = _rechain(rewrite)
        self.assertNotEqual(
            rewrite[-1]["event_hash"], original[-1]["event_hash"]
        )  # a different head
        self.assertEqual(rewrite[0]["session_id"], original[0]["session_id"])  # same session

        r2 = self.client.post("/seal", content=_jsonl(rewrite))
        self.assertEqual(r2.status_code, 200, "Archeion keeps no record of what it sealed (A8)")
        sealed_rewrite = [json.loads(ln) for ln in r2.text.splitlines()]

        # both seals are signed by the same, genuine, pinned key
        self.assertEqual(
            sealed_original[-1]["payload"]["server_pubkey"],
            sealed_rewrite[-1]["payload"]["server_pubkey"],
        )
        result = verify(sealed_rewrite, trusted_seal_pubkey=self.pub)
        self.assertEqual((result.status, result.evidence_class), (INTACT, AUTHORITATIVE_EVIDENCE))
        self.assertEqual(sealed_rewrite[3]["payload"]["classification"], "IN-BOUNDS")

    def test_a2_archeion_seals_whatever_consistent_chain_it_is_sent(self):
        """Nothing ties the submitted chain to the agent that produced it."""
        forged = _rechain(_base_session())
        forged[1]["payload"]["tool_name"] = "never-ran"
        forged = _rechain(forged)
        resp = self.client.post("/seal", content=_jsonl(forged))
        self.assertEqual(resp.status_code, 200)


if __name__ == "__main__":
    unittest.main()
