#!/usr/bin/env python3
"""
Generate the SYNTHETIC reveal bundles in examples/ha-reveal/bundles/.

Synthetic data only: no counterparty endpoint is called, no real agent or challenge id is used, and every
key (TSA, receipt signer, Archeion) is generated here, used once and discarded. The private halves never
touch disk except the throwaway Archeion key in a temp directory this script creates.

    python3 examples/ha-reveal/generate.py [--out examples/ha-reveal]

Needs the dev extras (fastapi, httpx) and the repo's tests/tsa_fixture.py (a local RFC 3161 authority).
Regenerating changes every salt, key and signature; the committed files are one such run.

Receipts are a PROPOSED EXTENSION, not an interface of Headline Arena or of anyone else. Every bundle,
receipt, closing receipt and the trust file this script writes carries the notice "SYNTHETIC — not HA-issued".
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
OTHER_SUBJECT = "agent-synthetic-002"  # scenario m: an honest bundle committed under another agent
OTHER_CONTEXT = "challenge-synthetic-daily-2026-10-15"  # scenario n: ...under another challenge
MAPPING = cmap.HA_DAILY_V3
NOTICE = cm.SYNTHETIC_NOTICE  # "SYNTHETIC — not HA-issued"
DEADLINE = dt.datetime(2026, 10, 14, 12, 0, 0, tzinfo=UTC)
T_INIT = dt.datetime(2026, 10, 14, 9, 0, 0, tzinfo=UTC)
T_REV = dt.datetime(2026, 10, 14, 9, 30, 0, tzinfo=UTC)
T_LATE = dt.datetime(2026, 10, 14, 13, 0, 0, tzinfo=UTC)

# Legacy-route submissions under ha-daily-v3: the route's own vocabulary (bearish / neutral / bullish), JSON
# numbers, and direction / confidence consistent with the argmax / maximum of the vector.
SUBMISSION_0 = {
    "direction": "bullish",
    "confidence": 0.72,
    "probabilities": {"bullish": 0.72, "bearish": 0.2, "neutral": 0.08},
    "reasoning": "Synthetic example reasoning: the index opened firm and breadth is positive.",
    "summary": "Synthetic: bullish.",
    "is_revision": False,
    # every declared field that is sent is bound by ha-daily-v3, including these:
    "prompt_hash": "a" * 64,
    "amount": 10,
    "token_usage": {"input": 123, "output": 45},
}
SUBMISSION_1 = {
    "direction": "bearish",
    "confidence": 0.64,
    "probabilities": {"bullish": 0.2, "bearish": 0.64, "neutral": 0.16},
    "reasoning": "Synthetic example reasoning: a revision after a synthetic overnight headline.",
    "summary": "Synthetic: bearish.",
    "is_revision": True,
    "revision_reason": "synthetic new information",
    "trigger_event_id": "evt-synthetic-1",
    "prompt_hash": "b" * 64,
    "amount": 10,
    "token_usage": {
        "input": 140,
        "output": 52,
        "cached": 0.5,
    },  # free-form: any JSON object is bound
    "idempotency_key": "synthetic-idem-0001",
    "model_provider": "synthetic-gateway",
    "model_name": "synthetic-model",
    "model_version": "0.0.1",
    "forecast_context": {"schema_version": "1", "decision": "update", "run_ref": "synthetic-run-1"},
}
# Scenario s: a small unstaked directional example with the full vector. `amount` is OMITTED (zero is not an
# unstaked submission), and `prompt_hash` is UPPERCASE hex, kept byte-exact (HA-4).
SUBMISSION_KOPEI = {
    "probabilities": {"bearish": 0.60, "neutral": 0.30, "bullish": 0.10},
    "prompt_hash": "A1B2C3D4E5F60718293A4B5C6D7E8F90A1B2C3D4E5F60718293A4B5C6D7E8F90",
    "reasoning": "Synthetic example reasoning for an unstaked full-vector submission.",
    "summary": "Synthetic: unstaked vector.",
    "is_revision": False,
}


def iso(t: dt.datetime) -> str:
    return t.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def make_session(agent_id: str = SUBJECT) -> list:
    """A real closed SqliteLedger session with 5 events, exported as event dicts."""
    with tempfile.TemporaryDirectory() as d:
        ledger = SqliteLedger(Path(d) / "s.db")
        ledger.connect()
        with patch("sasana.rfc3161.request_timestamp", return_value=None):
            ledger.open_session("sess-ha-synthetic", agent_id=agent_id)
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
        self.wrong_key, _ = generate_keypair()  # signs the closing receipt of scenario l
        self.client = TestClient(app)
        self.seal_pub = self.client.get("/pubkey").json()["pubkey"]
        self.full = make_session()  # START, LLM, TOOL, LLM, END
        self.sealed = self.seal(self.full)
        self.other_full = make_session(
            OTHER_SUBJECT
        )  # a different agent's own session (scenario m)
        self.other_sealed = self.seal(self.other_full)

    def seal(self, events: list) -> list:
        body = ("\n".join(json.dumps(e) for e in events) + "\n").encode()
        resp = self.client.post("/seal", content=body)
        assert resp.status_code == 200, resp.text
        return [json.loads(ln) for ln in resp.text.splitlines() if ln.strip()]

    def commit(
        self, prefix_len: int, submission: dict, when: dt.datetime, prev=None,
        subject=SUBJECT, context=CONTEXT, session=None,
    ):  # fmt: skip
        def fake_tsa(hash_bytes, *, url=None, nonce=None):
            return fx.respond(self.tsa, hash_bytes, gen_time=when, nonce=nonce)

        mapped = cmap.get_mapping(MAPPING).map(submission)
        with patch("sasana.rfc3161.request_timestamp", fake_tsa):
            return cm.commit(
                subject_id=subject,
                context_id=context,
                payload=mapped.payload,
                session_events=(session or self.full)[:prefix_len],
                trusted_tsa_anchors=self.anchors,
                prev=prev,
                mapping_id=MAPPING,
            )

    def receipt(
        self, pair, *, accepted: bool, at: dt.datetime, reason=None,
        subject=SUBJECT, context=CONTEXT, ha_revision_number=None,
    ) -> dict:  # fmt: skip
        """A SYNTHETIC receipt. No payload_hash: an unsalted hash of a low-entropy payload must not be published
        before the reveal (T6). `ha_revision_number` is the counterparty's own number, starting at 1."""
        pub, _sec = pair
        return cm.sign_receipt(
            {
                "challenge_id": context,
                "agent_id": subject,
                "revision_index": pub.revision_index,
                "ha_revision_number": ha_revision_number
                if ha_revision_number is not None
                else cmap.HA_REVISION_NUMBERING.counterparty_number(pub.revision_index),
                "commitment": pub.commitment,
                "accepted_at": iso(at),
                "accepted": accepted,
                "reason": reason,
                "mapping_id": MAPPING,
                "notice": NOTICE,
            },
            self.receipt_key,
        )

    def closing(self, accepted_pairs, *, key=None, subject=SUBJECT, context=CONTEXT) -> dict:
        """The counterparty's closing receipt: how many it accepted before the deadline, and the last."""
        last = accepted_pairs[-1][0] if accepted_pairs else None
        return cm.sign_closing_receipt(
            {
                "challenge_id": context,
                "agent_id": subject,
                "accepted_count": len(accepted_pairs),
                "last_accepted_revision_index": None if last is None else last.revision_index,
                "last_accepted_C": None if last is None else last.commitment,
                "closed_at": iso(DEADLINE + dt.timedelta(minutes=1)),
                "mapping_id": MAPPING,
                "notice": NOTICE,
            },
            key or self.receipt_key,
        )

    def bundle(self, pairs, session=None) -> dict:
        b = cm.reveal_bundle(pairs, session or self.sealed, capture_mode="sidecar")
        b["synthetic_notice"] = NOTICE
        return b


def build(world: World) -> dict:
    """name -> (bundle, receipts, closing receipt or None). All verified against the same pinned trust material."""
    w = world
    s = dt.timedelta(seconds=2)
    out: dict = {}

    p0 = w.commit(3, SUBMISSION_0, T_INIT)
    p1 = w.commit(4, SUBMISSION_1, T_REV, prev=p0[0])
    r0 = w.receipt(p0, accepted=True, at=T_INIT + s)
    r1 = w.receipt(p1, accepted=True, at=T_REV + s)
    both = w.closing([p0, p1])
    only0 = w.closing([p0])

    out["a-initial-only"] = (w.bundle([p0]), [r0], only0)
    out["b-revision-accepted"] = (w.bundle([p0, p1]), [r0, r1], both)
    out["c-revision-rejected"] = (
        w.bundle([p0, p1]),
        [r0, w.receipt(p1, accepted=False, at=T_REV + s, reason="synthetic: rejected")],
        only0,
    )
    out["d-initial-omitted"] = (w.bundle([p1]), [r0, r1], both)

    late1 = w.commit(4, SUBMISSION_1, T_LATE, prev=p0[0])
    out["e-revision-after-deadline-rejected"] = (
        w.bundle([p0, late1]),
        [r0, w.receipt(late1, accepted=False, at=T_LATE + s, reason="synthetic: after deadline")],
        only0,
    )
    out["e2-revision-after-deadline-but-receipt-says-accepted"] = (
        w.bundle([p0, late1]),
        [r0, w.receipt(late1, accepted=True, at=DEADLINE - dt.timedelta(minutes=1))],
        w.closing([p0, late1]),
    )

    tampered = w.bundle([p0, p1])
    tampered["revisions"][1]["payload"]["confidence"] = "0.94"
    out["f-payload-tampered"] = (tampered, [r0, r1], both)

    tampered_amount = w.bundle([p0, p1])
    tampered_amount["revisions"][1]["payload"]["amount"] = "1000"
    out["f2-amount-tampered"] = (tampered_amount, [r0, r1], both)

    wrong_mapping = w.bundle([p0, p1])
    wrong_mapping["mapping_id"] = (
        "ha-daily-v1"  # the superseded mapping: known, but not the required one
    )
    out["g-wrong-mapping-version"] = (wrong_mapping, [r0, r1], both)

    nothing = w.bundle([p0, p1])
    nothing["revisions"], nothing["session_events"] = [], []
    out["h-never-revealed"] = (nothing, [r0, r1], both)
    out["h2-scored-revision-not-revealed"] = (w.bundle([p0]), [r0, r1], both)

    forged = copy.deepcopy(w.full)
    forged[1]["payload"]["prompt_hash"] = "f" * 64  # rewrite an event BEFORE the committed root
    sealed_forgery = w.seal(rechain(forged))
    a8 = w.bundle([p0])
    a8["session_events"] = sealed_forgery
    out["i-operator-reseal-after-commit"] = (a8, [r0], only0)

    # The committer hands over only the initial's receipt and withholds the later accepted one.
    out["j-later-receipt-withheld"] = (w.bundle([p0, p1]), [r0], both)
    # No closing receipt: the verifier cannot tell whether it was given everything.
    out["k-closing-receipt-missing"] = (w.bundle([p0, p1]), [r0, r1], None)
    # A closing receipt signed by a key the verifier did not pin.
    out["l-closing-receipt-wrong-key"] = (
        w.bundle([p0, p1]),
        [r0, r1],
        w.closing([p0, p1], key=w.wrong_key),
    )

    # --- identity: an HONEST, fully valid bundle committed under another agent / another challenge. Its own
    # receipts and closing receipt (signed by the genuine key) are for that other identity, so nothing inside
    # it is inconsistent. Only the verifier's own record of whose bundle it is can refuse it.
    m0 = w.commit(3, SUBMISSION_0, T_INIT, subject=OTHER_SUBJECT, session=w.other_full)
    out["m-wrong-agent"] = (
        w.bundle([m0], session=w.other_sealed),
        [w.receipt(m0, accepted=True, at=T_INIT + s, subject=OTHER_SUBJECT)],
        w.closing([m0], subject=OTHER_SUBJECT),
    )
    n0 = w.commit(3, SUBMISSION_0, T_INIT, context=OTHER_CONTEXT)
    out["n-wrong-challenge"] = (
        w.bundle([n0]),
        [w.receipt(n0, accepted=True, at=T_INIT + s, context=OTHER_CONTEXT)],
        w.closing([n0], context=OTHER_CONTEXT),
    )

    # --- bundle-level cases ---------------------------------------------------------------------------
    # o: a revision's revision_index is edited (1 -> 5); C is computed over the index, so it no longer matches.
    wrong_index = w.bundle([p0, p1])
    wrong_index["revisions"][1]["revision_index"] = 5
    out["o-wrong-revision-index"] = (wrong_index, [r0, r1], both)

    # p: the CHAIN_SEAL signature is corrupted. The signature is not part of the event hash, so the hash chain
    # stays intact and ONLY the pinned-key seal check can catch it.
    bad_seal = copy.deepcopy(w.sealed)
    sig = bad_seal[-1]["signature"]
    bad_seal[-1]["signature"] = ("0" if sig[0] != "0" else "1") + sig[1:]
    corrupted = w.bundle([p0])
    corrupted["session_events"] = bad_seal
    out["p-corrupted-seal"] = (corrupted, [r0], only0)

    # q: the same revision is listed twice.
    duplicated = w.bundle([p0, p1])
    duplicated["revisions"].append(copy.deepcopy(duplicated["revisions"][1]))
    out["q-duplicate-revisions"] = (duplicated, [r0, r1], both)

    # r: the revisions array is in reverse order. The verifier orders by revision_index, so the array order is
    # ignored and the verdict is exactly that of b-revision-accepted.
    reordered = w.bundle([p0, p1])
    reordered["revisions"].reverse()
    out["r-reordered-revisions"] = (reordered, [r0, r1], both)

    # s: a small unstaked directional example (full vector, amount omitted, uppercase prompt_hash).
    k0 = w.commit(3, SUBMISSION_KOPEI, T_INIT)
    out["s-unstaked-full-vector"] = (
        w.bundle([k0]),
        [w.receipt(k0, accepted=True, at=T_INIT + s)],
        w.closing([k0]),
    )

    # t: the counterparty's receipt numbers the revision 1 for revision_index 1 (it starts counting at 1, so
    # revision_index 1 is revision_number 2). The off-by-one is stated, so it is caught, not assumed away.
    out["t-receipt-revision-number-off-by-one"] = (
        w.bundle([p0, p1]),
        [r0, w.receipt(p1, accepted=True, at=T_REV + s, ha_revision_number=1)],
        both,
    )
    return out


EXPECTED = {
    "_notice": NOTICE,
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
    "d2-initial-omitted-lenient": {
        "dir": "d-initial-omitted",
        "extra_args": ["--allow-unrevealed-history"],
        "verdict": "VALID_ON_TIME",
        "effective_revision": 1,
        "exit": 5,
        "contains": "HISTORY_GAP",
        "lenient": ["unrevealed history allowed"],
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
    "f2-amount-tampered": {
        "verdict": "INVALID",
        "effective_revision": None,
        "exit": 1,
        "contains": "commitment does not match revealed payload/root/salt",
    },
    "g-wrong-mapping-version": {
        "verdict": "INVALID",
        "effective_revision": None,
        "exit": 1,
        "contains": "is not the required 'ha-daily-v3'",
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
    "j-later-receipt-withheld": {
        "verdict": "INVALID",
        "effective_revision": None,
        "exit": 1,
        "contains": "RECEIPT_LIST_DISAGREES_WITH_CLOSING",
    },
    "k-closing-receipt-missing": {
        "verdict": "INCOMPLETE_RECEIPTS",
        "effective_revision": None,
        "exit": 6,
        "contains": "CLOSING_RECEIPT_MISSING",
    },
    "l-closing-receipt-wrong-key": {
        "verdict": "INVALID",
        "effective_revision": None,
        "exit": 1,
        "contains": "CLOSING_RECEIPT_INVALID",
    },
    "m-wrong-agent": {
        "verdict": "INVALID",
        "effective_revision": None,
        "exit": 1,
        "contains": "AGENT_ID_MISMATCH",
        "not_contains": ["CHALLENGE_ID_MISMATCH"],
    },
    "n-wrong-challenge": {
        "verdict": "INVALID",
        "effective_revision": None,
        "exit": 1,
        "contains": "CHALLENGE_ID_MISMATCH",
        "not_contains": ["AGENT_ID_MISMATCH"],
    },
    "o-wrong-revision-index": {
        "verdict": "INVALID",
        "effective_revision": None,
        "exit": 1,
        "contains": "commitment does not match revealed payload/root/salt",
    },
    "p-corrupted-seal": {
        "verdict": "INVALID",
        "effective_revision": None,
        "exit": 1,
        "contains": "session trace failed verification",
    },
    "q-duplicate-revisions": {
        "verdict": "INVALID",
        "effective_revision": None,
        "exit": 1,
        "contains": "duplicate revision_index in bundle",
    },
    "r-reordered-revisions": {"verdict": "VALID_ON_TIME", "effective_revision": 1, "exit": 0},
    "s-unstaked-full-vector": {"verdict": "VALID_ON_TIME", "effective_revision": 0, "exit": 0},
    "t-receipt-revision-number-off-by-one": {
        "verdict": "INVALID",
        "effective_revision": None,
        "exit": 1,
        "contains": "RECEIPT_REVISION_NUMBER_MISMATCH",
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
    label = f"# {NOTICE}: a throwaway test TSA root, not a real time authority.\n".encode()
    (out / "trust" / "tsa-anchor.pem").write_bytes(label + pem)
    (out / "trust" / "trust.json").write_text(
        json.dumps(
            {
                "synthetic_notice": NOTICE,
                "note": "SYNTHETIC trust material. Pin your own in real use.",
                "deadline": iso(DEADLINE),
                "mapping_id": MAPPING,
                "receipt_pubkey": world.receipt_pub,
                "seal_pubkey": world.seal_pub,
                "subject_id": SUBJECT,
                "context_id": CONTEXT,
            },
            indent=2,
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )
    for name, (bundle, receipts, closing) in bundles.items():
        d = out / "bundles" / name
        d.mkdir(parents=True, exist_ok=True)
        (d / "bundle.json").write_text(
            json.dumps(bundle, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )
        (d / "receipts.json").write_text(
            json.dumps(receipts, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )
        if closing is not None:
            (d / "closing.json").write_text(
                json.dumps(closing, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
            )
    (out / "expected.json").write_text(
        json.dumps(EXPECTED, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    print(f"wrote {len(bundles)} bundles to {out}")


if __name__ == "__main__":
    main()
