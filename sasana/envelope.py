"""
envelope.py — Event envelope construction with SHA-256 hash chain.

build_event() is the single source of truth for event construction.
Hash: SHA-256(canonical JSON of event without event_hash/signature). New sessions use RFC 8785
("jcs-rfc8785") and declare it in the SESSION_START payload; see sasana.jcs.
"""

import datetime
import hashlib
from typing import Optional

from sasana.jcs import CANON_RFC8785, canonicalizer

GENESIS_HASH = "0" * 64


def build_event(
    seq: int,
    event_type: str,
    session_id: str,
    payload: dict,
    prev_hash: str,
    private_key: Optional[object] = None,
    canonicalization: str = CANON_RFC8785,
) -> dict:
    """Build a complete event envelope with computed hash and optional Ed25519 signature.

    canonicalization must be the algorithm the session declares in SESSION_START (default RFC 8785).
    """
    timestamp = _utc_timestamp()
    event = {
        "seq": seq,
        "event_type": event_type,
        "session_id": session_id,
        "timestamp": timestamp,
        "payload": payload,
        "prev_hash": prev_hash,
    }
    event["event_hash"] = _compute_event_hash(event, canonicalization)
    if private_key is not None:
        try:
            from sasana.signing import sign_event_hash

            event["signature"] = sign_event_hash(private_key, event["event_hash"])
        except Exception:
            pass
    return event


def _compute_event_hash(event: dict, canonicalization: str = CANON_RFC8785) -> str:
    # Strip both event_hash (the field being computed) and signature (added after
    # hashing) so re-verification of a stored signed event produces the same hash.
    event_for_hash = {k: v for k, v in event.items() if k not in ("event_hash", "signature")}
    return hashlib.sha256(canonicalizer(canonicalization)(event_for_hash)).hexdigest()


def _utc_timestamp() -> str:
    now = datetime.datetime.now(datetime.timezone.utc)
    return now.strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"
