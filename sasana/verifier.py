"""
sasana.verifier — Canonical verification engine.

Single source of truth for all Sasana session log verification.
verify.py, sasana_cli.py, and sasana.compliance all delegate here.
"""

from __future__ import annotations

import dataclasses
import hashlib
from typing import Optional

from sasana.jcs import canonicalize as jcs_canonicalize

VERIFIER_VERSION = "1.0.0"
GENESIS_HASH = "0" * 64

ALLOWED_EVENT_TYPES = frozenset(
    {
        "SESSION_START",
        "SESSION_END",
        "LLM_CALL",
        "LLM_RESPONSE",
        "TOOL_CALL",
        "TOOL_RESULT",
        "TOOL_ERROR",
        "LOG_DROP",
        "CHAIN_SEAL",
    }
)
REQUIRED_FIELDS = frozenset(
    {
        "seq",
        "event_type",
        "session_id",
        "timestamp",
        "payload",
        "prev_hash",
        "event_hash",
    }
)

# Status constants
INTACT = "INTACT"
PARTIAL = "PARTIAL"
COMPROMISED = "COMPROMISED"
ERROR = "ERROR"

# Evidence class constants (strongest → weakest)
AUTHORITATIVE_EVIDENCE = "AUTHORITATIVE_EVIDENCE"
SIGNED_NON_AUTHORITATIVE_EVIDENCE = "SIGNED_NON_AUTHORITATIVE_EVIDENCE"
NON_AUTHORITATIVE_EVIDENCE = "NON_AUTHORITATIVE_EVIDENCE"
PARTIAL_EVIDENCE = "PARTIAL_EVIDENCE"
NO_EVIDENCE = "NO_EVIDENCE"


@dataclasses.dataclass
class VerifyResult:
    """Structured output from verify(). All fields are read-only by convention."""

    status: str  # INTACT | PARTIAL | COMPROMISED | ERROR
    evidence_class: str  # AUTHORITATIVE_EVIDENCE | … | NO_EVIDENCE
    session_id: Optional[str]
    event_count: int
    log_drop_count: int
    root_hash: Optional[str]
    errors: list = dataclasses.field(default_factory=list)
    checks: dict = dataclasses.field(default_factory=dict)

    def as_dict(self) -> dict:
        return dataclasses.asdict(self)


def compute_event_hash(event: dict) -> str:
    """
    SHA-256/JCS hash of an event envelope.

    Strips event_hash and signature before hashing — event_hash is the
    output of this function, and signature is added after, so neither
    is part of the hash input.
    """
    payload = {k: v for k, v in event.items() if k not in ("event_hash", "signature")}
    return hashlib.sha256(jcs_canonicalize(payload)).hexdigest()


def _check_structural(events: list) -> dict:
    errors: list = []
    for event in events:
        seq = event.get("seq", "?")
        for field in REQUIRED_FIELDS:
            if field not in event:
                errors.append(f"seq={seq}: missing required field '{field}'")
        et = event.get("event_type")
        if et and et not in ALLOWED_EVENT_TYPES:
            errors.append(f"seq={seq}: unknown event_type '{et}'")
        for hfield in ("prev_hash", "event_hash"):
            h = event.get(hfield)
            if h is not None and not (
                isinstance(h, str) and len(h) == 64 and all(c in "0123456789abcdef" for c in h)
            ):
                errors.append(f"seq={seq}: '{hfield}' must be 64-char lowercase hex")
    return {"status": "PASS" if not errors else "FAIL", "errors": errors}


def _check_sequence(events: list) -> dict:
    errors: list = []
    sorted_events = sorted(events, key=lambda e: e.get("seq", 0))
    seqs = [e.get("seq") for e in sorted_events]

    if len({e.get("session_id") for e in events}) > 1:
        errors.append("Multiple session_ids found in single session file")

    # seq must start at 1 — partial/sub-range exports are not supported by design.
    if not seqs or seqs[0] != 1:
        errors.append(f"First seq must be 1, got {seqs[0] if seqs else None}")

    seen: set = set()
    duplicates: list = []
    for s in seqs:
        if s in seen:
            duplicates.append(s)
        seen.add(s)
    if duplicates:
        errors.append(f"Duplicate seq values: {duplicates}")

    for i in range(1, len(seqs)):
        if seqs[i] != seqs[i - 1] + 1:
            errors.append(f"Expected seq={seqs[i - 1] + 1}, found seq={seqs[i]}")

    return {"status": "PASS" if not errors else "FAIL", "errors": errors}


def _check_hash_chain(events: list) -> dict:
    """
    Verifies event_hash integrity and prev_hash linkage.

    Stops at the first violation — once the chain is broken, all subsequent
    errors are artifacts of the break, not independent failures.
    """
    errors: list = []
    sorted_events = sorted(events, key=lambda e: e.get("seq", 0))

    if sorted_events and sorted_events[0].get("prev_hash") != GENESIS_HASH:
        errors.append("seq=1: prev_hash must be 64 zeros (genesis hash)")

    prev_hash: Optional[str] = None
    for event in sorted_events:
        seq = event.get("seq", "?")
        try:
            expected = compute_event_hash(event)
        except Exception as exc:
            errors.append(f"seq={seq}: hash computation failed: {exc}")
            break
        if event.get("event_hash") != expected:
            errors.append(f"seq={seq} ({event.get('event_type', '?')}): event_hash mismatch")
            break
        if prev_hash is not None and event.get("prev_hash") != prev_hash:
            errors.append(f"seq={seq}: prev_hash chain broken")
            break
        prev_hash = event.get("event_hash")

    return {"status": "PASS" if not errors else "FAIL", "errors": errors}


def _check_completeness(events: list) -> dict:
    """
    Session must open with SESSION_START.
    Session must close with SESSION_END. A CHAIN_SEAL event (appended by an
    authority server after SESSION_END) is also accepted as a closing marker.
    """
    errors: list = []
    sorted_events = sorted(events, key=lambda e: e.get("seq", 0))
    types = [e.get("event_type") for e in sorted_events]

    ss_count = types.count("SESSION_START")
    if ss_count != 1:
        errors.append(f"Expected 1 SESSION_START, found {ss_count}")
    elif sorted_events[0].get("event_type") != "SESSION_START":
        errors.append("SESSION_START must be the first event")

    has_end = "SESSION_END" in types
    has_seal = "CHAIN_SEAL" in types
    if not has_end and not has_seal:
        errors.append("Session has no SESSION_END or CHAIN_SEAL")

    return {
        "status": "PASS" if not errors else "FAIL",
        "has_session_start": "SESSION_START" in types,
        "has_session_end": has_end,
        "has_chain_seal": has_seal,
        "log_drop_count": types.count("LOG_DROP"),
        "errors": errors,
    }


def _check_seal_signature(events: list) -> dict:
    """
    If a CHAIN_SEAL event is present, verify its Ed25519 signature against the
    server_pubkey embedded in the payload.

    A CHAIN_SEAL without a valid signature is a forged or tampered seal — the
    session is treated as COMPROMISED, not merely non-authoritative.
    """
    seal_events = [e for e in events if e.get("event_type") == "CHAIN_SEAL"]
    if not seal_events:
        return {"status": "PASS", "errors": []}

    seal = seal_events[0]
    pubkey = seal.get("payload", {}).get("server_pubkey")
    signature = seal.get("signature")
    event_hash = seal.get("event_hash")

    if not pubkey:
        return {"status": "FAIL", "errors": ["CHAIN_SEAL missing server_pubkey in payload"]}
    if not signature:
        return {"status": "FAIL", "errors": ["CHAIN_SEAL missing signature"]}
    if not event_hash:
        return {"status": "FAIL", "errors": ["CHAIN_SEAL missing event_hash"]}

    from sasana.signing import verify_signature

    if not verify_signature(pubkey, event_hash, signature):
        return {
            "status": "FAIL",
            "errors": ["CHAIN_SEAL signature invalid — seal has been tampered with"],
        }

    return {"status": "PASS", "errors": []}


def _determine_evidence_class(events: list, signatures_valid: bool = False) -> str:
    has_seal = any(e.get("event_type") == "CHAIN_SEAL" for e in events)
    has_drop = any(e.get("event_type") == "LOG_DROP" for e in events)
    # LOG_DROP degrades evidence class even in server-sealed sessions.
    if has_drop:
        return PARTIAL_EVIDENCE
    if has_seal:
        return AUTHORITATIVE_EVIDENCE
    if signatures_valid:
        return SIGNED_NON_AUTHORITATIVE_EVIDENCE
    return NON_AUTHORITATIVE_EVIDENCE


def verify(events: list, signatures_valid: bool = False) -> VerifyResult:
    """
    Run the full 4-check verification pipeline on a list of events.

    Checks 2–4 are skipped when structural check fails — malformed events
    produce misleading errors in hash and sequence checks.
    """
    if not events:
        return VerifyResult(
            status=ERROR,
            evidence_class=NO_EVIDENCE,
            session_id=None,
            event_count=0,
            log_drop_count=0,
            root_hash=None,
            errors=["Session file is empty"],
            checks={},
        )

    session_id = events[0].get("session_id")
    sorted_events = sorted(events, key=lambda e: e.get("seq", 0))
    root_hash = sorted_events[-1].get("event_hash")
    log_drops = sum(1 for e in events if e.get("event_type") == "LOG_DROP")
    _skipped = {"status": "SKIPPED", "errors": []}

    c1 = _check_structural(events)
    if c1["status"] != "PASS":
        return VerifyResult(
            status=COMPROMISED,
            evidence_class=NO_EVIDENCE,
            session_id=session_id,
            event_count=len(events),
            log_drop_count=log_drops,
            root_hash=root_hash,
            errors=c1["errors"],
            checks={
                "structural": c1,
                "sequence": _skipped,
                "hash_chain": _skipped,
                "completeness": _skipped,
            },
        )

    c2 = _check_sequence(events)
    c3 = _check_hash_chain(events)
    c4 = _check_completeness(events)
    c5 = _check_seal_signature(events)
    checks = {
        "structural": c1,
        "sequence": c2,
        "hash_chain": c3,
        "completeness": c4,
        "seal_signature": c5,
    }
    all_errors = c2["errors"] + c3["errors"] + c4["errors"] + c5["errors"]

    if all_errors:
        return VerifyResult(
            status=COMPROMISED,
            evidence_class=NO_EVIDENCE,
            session_id=session_id,
            event_count=len(events),
            log_drop_count=log_drops,
            root_hash=root_hash,
            errors=all_errors,
            checks=checks,
        )

    evidence = _determine_evidence_class(events, signatures_valid=signatures_valid)
    status = PARTIAL if log_drops > 0 else INTACT

    return VerifyResult(
        status=status,
        evidence_class=evidence,
        session_id=session_id,
        event_count=len(events),
        log_drop_count=log_drops,
        root_hash=root_hash,
        errors=[],
        checks=checks,
    )
