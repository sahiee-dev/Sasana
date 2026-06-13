"""
envelope.py — Event envelope construction with SHA-256 hash chain.

build_event() is the single source of truth for event construction.
Hash: SHA-256(RFC 8785 canonical JSON of event without event_hash/signature).
"""

import datetime
import hashlib
from typing import Optional

from sasana.jcs import canonicalize as jcs_canonicalize

GENESIS_HASH = "0" * 64


def build_event(
    seq: int,
    event_type: str,
    session_id: str,
    payload: dict,
    prev_hash: str,
    private_key: Optional[object] = None,
) -> dict:
    """Build a complete event envelope with computed hash and optional Ed25519 signature."""
    timestamp = _utc_timestamp()
    event = {
        "seq": seq,
        "event_type": event_type,
        "session_id": session_id,
        "timestamp": timestamp,
        "payload": payload,
        "prev_hash": prev_hash,
    }
    event["event_hash"] = _compute_event_hash(event)
    if private_key is not None:
        try:
            from sasana.signing import sign_event_hash
            event["signature"] = sign_event_hash(private_key, event["event_hash"])
        except Exception:
            pass
    return event


def _compute_event_hash(event: dict) -> str:
    # Strip both event_hash (the field being computed) and signature (added after
    # hashing) so re-verification of a stored signed event produces the same hash.
    event_for_hash = {k: v for k, v in event.items() if k not in ("event_hash", "signature")}
    return hashlib.sha256(jcs_canonicalize(event_for_hash)).hexdigest()


def _utc_timestamp() -> str:
    now = datetime.datetime.now(datetime.timezone.utc)
    return now.strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"
