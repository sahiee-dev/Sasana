#!/usr/bin/env python3
"""
Generate the SYNTHETIC reveal bundles in examples/ha-reveal/bundles/.

Synthetic data only: no counterparty endpoint is called, no real agent or challenge id is used, and every
key (TSA, receipt signer, Archeion) is generated here, used once and discarded. The private halves never
touch disk except the throwaway Archeion key in a temp directory this script creates.

    python3 examples/ha-reveal/generate.py [--out examples/ha-reveal]

Needs the dev extras (fastapi, httpx) and the repo's tests/tsa_fixture.py (a local RFC 3161 authority).
Regenerating changes every salt, key and signature; the committed files are one such run.

Receipts are a PROPOSED EXTENSION, not an interface of Headline Arena or of anyone else.
"""

from __future__ import annotations

import argparse
import copy
import datetime as dt
import json
import os
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]

# A throwaway Archeion key, set BEFORE archeion is imported. Never the user's real key.
_KEYDIR = tempfile.mkdtemp(prefix="ha-reveal-archeion-")
os.environ.pop("ARCHEION_PRIVATE_KEY", None)
os.environ["ARCHEION_KEY_FILE"] = str(Path(_KEYDIR) / "key")

sys.path[:0] = [str(ROOT), str(ROOT / "tests")]

import tsa_fixture as fx  # noqa: E402
from cryptography.hazmat.primitives import serialization  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from archeion.server import app  # noqa: E402
from sasana import commitment as cm  # noqa: E402
from sasana import commitment_mapping as cmap  # noqa: E402
from sasana.signing import generate_keypair  # noqa: E402
from sasana.sqlite_ledger import SqliteLedger  # noqa: E402
from sasana.verifier import GENESIS_HASH, compute_event_hash  # noqa: E402

UTC = dt.timezone.utc
SUBJECT = "agent-synthetic-001"
CONTEXT = "challenge-synthetic-daily-2026-10-14"
MAPPING = cmap.HA_DAILY_V1
DEADLINE = dt.datetime(2026, 10, 14, 12, 0, 0, tzinfo=UTC)
T_INIT = dt.datetime(2026, 10, 14, 9, 0, 0, tzinfo=UTC)
T_REV = dt.datetime(2026, 10, 14, 9, 30, 0, tzinfo=UTC)
T_LATE = dt.datetime(2026, 10, 14, 13, 0, 0, tzinfo=UTC)

SUBMISSION_0 = {
    "direction": "up",
    "confidence": 0.72,
    "probabilities": {"up": 0.72, "down": 0.2, "flat": 0.08},
    "reasoning": "Synthetic example reasoning: the index opened firm and breadth is positive.",
    "summary": "Synthetic: up.",
    "is_revision": False,
    # declared by the daily schema but deliberately NOT bound by the mapping:
    "prompt_hash": "a" * 64,
    "amount": 10,
    "token_usage": {"input": 123, "output": 45},
}
SUBMISSION_1 = {
    "direction": "down",
    "confidence": "0.64",
    "probabilities": {"up": 0.2, "down": 0.64, "flat": 0.16},
    "reasoning": "Synthetic example reasoning: a revision after a synthetic overnight headline.",
    "summary": "Synthetic: down.",
    "is_revision": True,
    "revision_reason": "synthetic new information",
    "prompt_hash": "b" * 64,
}


def iso(t: dt.datetime) -> str:
    return t.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def make_session() -> list:
    """A real closed SqliteLedger session with 5 events, exported as event dicts."""
    with tempfile.TemporaryDirectory() as d:
        ledger = SqliteLedger(Path(d) / "s.db")
        ledger.connect()
        with patch("sasana.rfc3161.request_timestamp", return_value=None):
            ledger.open_session("sess-ha-synthetic", agent_id=SUBJECT)
        ledger.record("LLM_CALL", {"prompt_hash": "a" * 64})
        ledger.record("TOOL_CALL", {"tool_name": "search", "args_hash": "c" * 64})
        ledger.record("LLM_CALL", {"prompt_hash": "b" * 64})
        ledger.close_session()
        out = Path(d) / "s.jsonl"
        ledger.export_jsonl(out)
        ledger.close()
        return [json.loads(ln) for ln in out.read_text().splitlines() if ln.strip()]


def rechain(events: list) -> list:
    events = copy.deepcopy(events)
    for i, ev in enumerate(events):
        ev["prev_hash"] = events[i - 1]["event_hash"] if i else GENESIS_HASH
        ev["event_hash"] = compute_event_hash(ev, "jcs-rfc8785")
    return events


class World:
    def __init__(self) -> None:
        self.tsa = fx.make_authority()
        self.anchors = [self.tsa.anchor_der]
        self.receipt_key, self.receipt_pub = generate_keypair()
        self.client = TestClient(app)
        self.seal_pub = self.client.get("/pubkey").json()["pubkey"]
        self.full = make_session()  # START, LLM, TOOL, LLM, END
        self.sealed = self.seal(self.full)

    def seal(self, events: list) -> list:
        body = ("\n".join(json.dumps(e) for e in events) + "\n").encode()
        resp = self.client.post("/seal", content=body)
        assert resp.status_code == 200, resp.text
        return [json.loads(ln) for ln in resp.text.splitlines() if ln.strip()]

    def commit(self, prefix_len: int, submission: dict, when: dt.datetime, prev=None):
        def fake_tsa(hash_bytes, *, url=None, nonce=None):
            return fx.respond(self.tsa, hash_bytes, gen_time=when, nonce=nonce)

        mapped = cmap.map_ha_daily_v1(submission)
        with patch("sasana.rfc3161.request_timestamp", fake_tsa):
            return cm.commit(
                subject_id=SUBJECT,
                context_id=CONTEXT,
                payload=mapped.payload,
                session_events=self.full[:prefix_len],
                trusted_tsa_anchors=self.anchors,
                prev=prev,
                mapping_id=MAPPING,
            )

    def receipt(self, pair, *, accepted: bool, at: dt.datetime, reason=None) -> dict:
        pub, sec = pair
        return cm.sign_receipt(
            {
                "challenge_id": CONTEXT,
                "agent_id": SUBJECT,
                "revision_index": pub.revision_index,
                "commitment": pub.commitment,
                "accepted_at": iso(at),
                "accepted": accepted,
                "reason": reason,
                "mapping_id": MAPPING,
                "payload_hash": cm.payload_hash(sec.payload).hex(),
            },
            self.receipt_key,
        )

    def bundle(self, pairs, session=None) -> dict:
        return cm.reveal_bundle(pairs, session or self.sealed, capture_mode="sidecar")


def build(world: World) -> dict:
    """name -> (bundle, receipts). Every bundle is verified against the same pinned trust material."""
    w = world
    s = dt.timedelta(seconds=2)
    out: dict = {}

    p0 = w.commit(3, SUBMISSION_0, T_INIT)
    p1 = w.commit(4, SUBMISSION_1, T_REV, prev=p0[0])
    r0 = w.receipt(p0, accepted=True, at=T_INIT + s)
    r1 = w.receipt(p1, accepted=True, at=T_REV + s)

    out["a-initial-only"] = (w.bundle([p0]), [r0])
    out["b-revision-accepted"] = (w.bundle([p0, p1]), [r0, r1])
    out["c-revision-rejected"] = (
        w.bundle([p0, p1]),
        [r0, w.receipt(p1, accepted=False, at=T_REV + s, reason="synthetic: rejected")],
    )
    out["d-initial-omitted"] = (w.bundle([p1]), [r0, r1])

    late1 = w.commit(4, SUBMISSION_1, T_LATE, prev=p0[0])
    out["e-revision-after-deadline-rejected"] = (
        w.bundle([p0, late1]),
        [r0, w.receipt(late1, accepted=False, at=T_LATE + s, reason="synthetic: after deadline")],
    )
    out["e2-revision-after-deadline-but-receipt-says-accepted"] = (
        w.bundle([p0, late1]),
        [r0, w.receipt(late1, accepted=True, at=DEADLINE - dt.timedelta(minutes=1))],
    )

    tampered = w.bundle([p0, p1])
    tampered["revisions"][1]["payload"]["confidence"] = "0.94"
    out["f-payload-tampered"] = (tampered, [r0, r1])

    wrong_mapping = w.bundle([p0, p1])
    wrong_mapping["mapping_id"] = "ha-daily-v2"
    out["g-wrong-mapping-version"] = (wrong_mapping, [r0, r1])

    nothing = w.bundle([p0, p1])
    nothing["revisions"], nothing["session_events"] = [], []
    out["h-never-revealed"] = (nothing, [r0, r1])
    out["h2-scored-revision-not-revealed"] = (w.bundle([p0]), [r0, r1])

    forged = copy.deepcopy(w.full)
    forged[1]["payload"]["prompt_hash"] = "f" * 64  # rewrite an event BEFORE the committed root
    sealed_forgery = w.seal(rechain(forged))
    a8 = w.bundle([p0])
    a8["session_events"] = sealed_forgery
    out["i-operator-reseal-after-commit"] = (a8, [r0])
    return out


EXPECTED = {
    "a-initial-only": {"verdict": "VALID_ON_TIME", "effective_revision": 0, "exit": 0},
    "b-revision-accepted": {"verdict": "VALID_ON_TIME", "effective_revision": 1, "exit": 0},
    "c-revision-rejected": {
        "verdict": "VALID_ON_TIME",
        "effective_revision": 0,
        "exit": 0,
        "contains": "NOT_ACCEPTED_BY_COUNTERPARTY:1",
    },
    "d-initial-omitted": {
        "verdict": "INVALID",
        "effective_revision": None,
        "exit": 1,
        "contains": "HISTORY_GAP",
    },
    "e-revision-after-deadline-rejected": {
        "verdict": "VALID_ON_TIME",
        "effective_revision": 0,
        "exit": 0,
        "contains": "NOT_ACCEPTED_BY_COUNTERPARTY:1",
    },
    "e2-revision-after-deadline-but-receipt-says-accepted": {
        "verdict": "LATE",
        "effective_revision": None,
        "exit": 2,
        "contains": "SCORED_REVISION_NOT_ON_TIME:1",
    },
    "f-payload-tampered": {
        "verdict": "INVALID",
        "effective_revision": None,
        "exit": 1,
        "contains": "commitment does not match revealed payload/root/salt",
    },
    "g-wrong-mapping-version": {
        "verdict": "INVALID",
        "effective_revision": None,
        "exit": 1,
        "contains": "unknown payload mapping 'ha-daily-v2'",
    },
    "h-never-revealed": {"verdict": "UNREVEALED", "effective_revision": None, "exit": 4},
    "h2-scored-revision-not-revealed": {
        "verdict": "UNREVEALED",
        "effective_revision": None,
        "exit": 4,
    },
    "i-operator-reseal-after-commit": {
        "verdict": "INVALID",
        "effective_revision": None,
        "exit": 1,
        "contains": "session_root is not an event in the revealed session",
    },
}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(Path(__file__).resolve().parent))
    out = Path(ap.parse_args().out)
    world = World()
    bundles = build(world)

    (out / "trust").mkdir(parents=True, exist_ok=True)
    pem = world.tsa.anchor.public_bytes(serialization.Encoding.PEM)
    (out / "trust" / "tsa-anchor.pem").write_bytes(pem)
    (out / "trust" / "trust.json").write_text(
        json.dumps(
            {
                "note": "SYNTHETIC trust material. Pin your own in real use.",
                "deadline": iso(DEADLINE),
                "mapping_id": MAPPING,
                "receipt_pubkey": world.receipt_pub,
                "seal_pubkey": world.seal_pub,
                "subject_id": SUBJECT,
                "context_id": CONTEXT,
            },
            indent=2,
        )
        + "\n"
    )
    for name, (bundle, receipts) in bundles.items():
        d = out / "bundles" / name
        d.mkdir(parents=True, exist_ok=True)
        (d / "bundle.json").write_text(json.dumps(bundle, indent=2) + "\n")
        (d / "receipts.json").write_text(json.dumps(receipts, indent=2) + "\n")
    (out / "expected.json").write_text(json.dumps(EXPECTED, indent=2) + "\n")
    print(f"wrote {len(bundles)} bundles to {out}")


if __name__ == "__main__":
    main()
