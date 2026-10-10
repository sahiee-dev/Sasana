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

VERIFIER_VERSION = "2.0.0"
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
#
# AUTHORITATIVE_EVIDENCE requires the CHAIN_SEAL to verify against a key the CALLER pinned
# (trusted_seal_pubkey / --trust-key). A seal that only verifies against the public key
# embedded in the seal itself proves nothing about who made it — anyone can generate a
# keypair, rewrite a log, and seal it — so it is reported as SELF_SEALED_EVIDENCE.
AUTHORITATIVE_EVIDENCE = "AUTHORITATIVE_EVIDENCE"
SELF_SEALED_EVIDENCE = "SELF_SEALED_EVIDENCE"
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
    # Always False in this release: verify() does not validate the TSA signature, the
    # certificate chain or genTime, so it never claims "verified time". Kept for API
    # compatibility. See timestamp_imprint_match for what is actually checked.
    timestamp_verified: bool = False
    # True when an RFC 3161 token is present and its MessageImprint equals the recomputed
    # SESSION_START hash. This says nothing about who issued the token or what time it claims.
    timestamp_imprint_match: bool = False
    warnings: list = dataclasses.field(default_factory=list)
    pinned: bool = False  # a trusted_seal_pubkey was supplied
    require_seal: bool = False  # the caller demanded a CHAIN_SEAL
    seal_present: bool = False
    seal_trusted: bool = False  # seal present AND verified against the pinned key

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


def _check_seal_signature(
    events: list, trusted_pubkey: Optional[str] = None, require_seal: bool = False
) -> dict:
    """
    Verify the CHAIN_SEAL, if any.

    Result keys: status (PASS|FAIL), errors, seal_present, seal_trusted.

    seal_trusted is True only when a CHAIN_SEAL is present, every check below passes AND
    the caller pinned trusted_pubkey (so the seal's key matched it). An unpinned seal that
    merely verifies against its own embedded server_pubkey is NOT trusted: the key is
    attacker-controllable. See SELF_SEALED_EVIDENCE.

    Rules:
      * no CHAIN_SEAL + trusted_pubkey given  → FAIL. A pin means "this session must have
        been sealed by that key"; deleting the seal must not downgrade the verdict.
      * no CHAIN_SEAL + require_seal          → FAIL (independent of any pin).
      * more than one CHAIN_SEAL              → FAIL.
      * CHAIN_SEAL not the final event        → FAIL.
      * missing pubkey/signature/hash         → FAIL.
      * pin given and seal key differs        → FAIL.
      * Ed25519 signature over event_hash bad → FAIL (forged or tampered seal).
      * payload.session_hash != the hash of the event preceding the seal → FAIL.
    """
    seal_events = [e for e in events if e.get("event_type") == "CHAIN_SEAL"]

    def fail(*msgs: str, present: bool = True) -> dict:
        return {
            "status": "FAIL",
            "errors": list(msgs),
            "seal_present": present,
            "seal_trusted": False,
        }

    if not seal_events:
        errors = []
        if trusted_pubkey is not None:
            errors.append("pinned key provided but session has no CHAIN_SEAL")
        if require_seal:
            errors.append("seal required but session has no CHAIN_SEAL")
        if errors:
            return fail(*errors, present=False)
        return {"status": "PASS", "errors": [], "seal_present": False, "seal_trusted": False}

    if len(seal_events) > 1:
        return fail(f"session has {len(seal_events)} CHAIN_SEAL events; exactly one is allowed")

    sorted_events = sorted(events, key=lambda e: e.get("seq", 0))
    seal = seal_events[0]
    if sorted_events[-1] is not seal:
        return fail("CHAIN_SEAL must be the final event")

    payload = seal.get("payload", {})
    pubkey = payload.get("server_pubkey")
    signature = seal.get("signature")
    event_hash = seal.get("event_hash")

    if not pubkey:
        return fail("CHAIN_SEAL missing server_pubkey in payload")
    if not signature:
        return fail("CHAIN_SEAL missing signature")
    if not event_hash:
        return fail("CHAIN_SEAL missing event_hash")
    if not isinstance(pubkey, str) or not isinstance(signature, str):
        return fail("CHAIN_SEAL server_pubkey and signature must be strings")

    if trusted_pubkey is not None and pubkey != trusted_pubkey:
        return fail(
            f"CHAIN_SEAL signed by untrusted key — expected {trusted_pubkey[:16]}…, "
            f"got {pubkey[:16]}…"
        )

    from sasana.signing import verify_signature

    if not verify_signature(pubkey, event_hash, signature):
        return fail("CHAIN_SEAL signature invalid — seal has been tampered with")

    # The seal must attest to the chain head it actually follows. The prev_hash linkage
    # already forces this for honest seals, but session_hash is part of what Archeion signs
    # and it is meaningless if nobody reads it.
    if len(sorted_events) >= 2:
        head = sorted_events[-2].get("event_hash")
        if payload.get("session_hash") != head:
            return fail(
                "CHAIN_SEAL session_hash does not match the preceding event's event_hash "
                f"(seal says {str(payload.get('session_hash'))[:16]}…, chain head is "
                f"{str(head)[:16]}…)"
            )

    return {
        "status": "PASS",
        "errors": [],
        "seal_present": True,
        "seal_trusted": trusted_pubkey is not None,
    }


def _check_session_signatures(events: list) -> tuple[bool, dict]:
    """
    Verify per-event Ed25519 signatures when the session was recorded with signing enabled.

    Signing is active when SESSION_START.payload contains a session_pubkey field.
    Returns (all_signed: bool, check_result: dict).

    - all_signed=True only when every non-CHAIN_SEAL event carries a valid signature.
    - Invalid signatures cause FAIL (caller should treat as COMPROMISED).
    - Missing signatures when pubkey is present cause all_signed=False (soft degradation
      to NON_AUTHORITATIVE_EVIDENCE), not FAIL — the SDK signing step may have errored
      on individual events without being a tamper indicator.
    """
    start_events = [e for e in events if e.get("event_type") == "SESSION_START"]
    if not start_events:
        return False, {"status": "SKIPPED", "errors": []}

    pubkey = start_events[0].get("payload", {}).get("session_pubkey")
    if not pubkey:
        return False, {"status": "SKIPPED", "errors": []}

    from sasana.signing import verify_signature

    errors: list = []
    verified = 0
    unsigned = 0

    for e in events:
        if e.get("event_type") == "CHAIN_SEAL":
            continue  # CHAIN_SEAL signature handled by _check_seal_signature
        sig = e.get("signature")
        if sig is None:
            unsigned += 1
            continue
        if not verify_signature(pubkey, e.get("event_hash", ""), sig):
            errors.append(f"seq={e.get('seq', '?')}: Ed25519 signature invalid")
        else:
            verified += 1

    if errors:
        return False, {"status": "FAIL", "errors": errors}
    if verified == 0:
        return False, {"status": "SKIPPED", "errors": []}
    all_signed = unsigned == 0
    return all_signed, {"status": "PASS", "errors": []}


_TS_CAVEAT = (
    "imprint match only: the TSA signature, certificate chain and genTime are NOT verified, "
    "so this does not establish when the session happened"
)


def _check_rfc3161_timestamp(events: list) -> tuple[bool, dict]:
    """
    Check the RFC 3161 token in the SESSION_START payload, if present.

    Returns (imprint_match: bool, check_result: dict). INFORMATIONAL: never affects status.

    What this checks, and nothing more: the token parses and its MessageImprint equals the
    SESSION_START hash recomputed without the token. It does NOT verify the TSA's CMS
    signature, the signer certificate chain, or that the claimed genTime is genuine. A token
    forged or backdated by anyone passes. (A strict verifier exists as
    sasana.rfc3161.verify_timestamp_strict but is not wired into verify().)

    check_result["status"]:
      SKIPPED         no rfc3161_token in SESSION_START
      IMPRINT_MATCH   token parses, imprint equals the recomputed hash (see caveat above)
      FAIL            token present but malformed, or its imprint does not match

    "timestamp_utc" is the time the token CLAIMS; treat it as unverified.
    """
    import base64 as _b64

    def result(status, errors=None, utc=None, detail=None):
        return {
            "status": status,
            "errors": errors or [],
            "timestamp_utc": utc,
            "detail": detail,
        }

    start_events = [e for e in events if e.get("event_type") == "SESSION_START"]
    if not start_events:
        return False, result("SKIPPED")

    session_start = start_events[0]
    payload = session_start.get("payload", {})
    token_b64 = payload.get("rfc3161_token")

    if not token_b64:
        return False, result("SKIPPED")

    try:
        token_der = _b64.b64decode(token_b64)
    except Exception:
        return False, result("FAIL", ["rfc3161_token is not valid base64"])

    # Reconstruct the hash that was submitted to the TSA:
    # SESSION_START fields minus event_hash, signature, and rfc3161_token from payload.
    try:
        payload_without_token = {k: v for k, v in payload.items() if k != "rfc3161_token"}
        event_without_token = {
            k: v for k, v in session_start.items() if k not in ("event_hash", "signature")
        }
        event_without_token["payload"] = payload_without_token
        pre_token_hash = hashlib.sha256(jcs_canonicalize(event_without_token)).digest()
    except Exception as exc:
        return False, result("FAIL", [f"Pre-token hash computation failed: {exc}"])

    try:
        from sasana.rfc3161 import verify_timestamp

        valid, utc_time = verify_timestamp(token_der, pre_token_hash)
    except Exception as exc:
        return False, result("FAIL", [f"Token verification error: {exc}"])

    if not valid:
        return False, result("FAIL", ["RFC 3161 MessageImprint does not match SESSION_START hash"])

    return True, result("IMPRINT_MATCH", utc=utc_time, detail=_TS_CAVEAT)


def _determine_evidence_class(
    events: list, signatures_valid: bool = False, seal_trusted: bool = False
) -> str:
    has_seal = any(e.get("event_type") == "CHAIN_SEAL" for e in events)
    has_drop = any(e.get("event_type") == "LOG_DROP" for e in events)
    # Archeion rejects PARTIAL sessions, so has_drop + has_seal should not occur
    # through normal flow. Check order is defensive: LOG_DROP always degrades.
    if has_drop:
        return PARTIAL_EVIDENCE
    if has_seal:
        # A seal vouches for nothing unless its key is one the caller chose to trust.
        return AUTHORITATIVE_EVIDENCE if seal_trusted else SELF_SEALED_EVIDENCE
    if signatures_valid:
        return SIGNED_NON_AUTHORITATIVE_EVIDENCE
    return NON_AUTHORITATIVE_EVIDENCE


def _validate_input(events: object) -> list:
    """
    Reject input that is not a list of well-typed event objects BEFORE any check runs.

    Everything here is "cannot be assessed" (→ status ERROR), not "assessed and found
    tampered" (→ COMPROMISED). Without this, a non-object line or a mixed-type `seq`
    crashed the pipeline with a traceback and exit code 1 — indistinguishable from
    COMPROMISED. Missing fields and malformed hashes are NOT handled here; those are
    ordinary structural findings reported as COMPROMISED.
    """
    if not isinstance(events, list):
        return [f"Session must be a list of events, got {type(events).__name__}"]
    if not events:
        return ["Session file is empty"]
    errors: list = []
    for i, ev in enumerate(events):
        if not isinstance(ev, dict):
            errors.append(f"event[{i}] is not a JSON object (got {type(ev).__name__})")
            continue
        if "seq" in ev and (isinstance(ev["seq"], bool) or not isinstance(ev["seq"], int)):
            errors.append(f"event[{i}]: 'seq' must be an integer, got {type(ev['seq']).__name__}")
        for field in ("event_type", "session_id"):
            if field in ev and not isinstance(ev[field], str):
                errors.append(f"event[{i}]: '{field}' must be a string")
        if "payload" in ev and not isinstance(ev["payload"], dict):
            errors.append(f"event[{i}]: 'payload' must be an object")
        if ev.get("signature") is not None and not isinstance(ev["signature"], str):
            errors.append(f"event[{i}]: 'signature' must be a string")
    return errors


def verify_chain_integrity(events: list) -> list:
    """
    Structural, sequence and hash-chain checks only — no completeness, seal or
    timestamp checks. Returns a list of error strings (empty means the events
    form a valid chain prefix).

    Use this for sessions that may still be open (no SESSION_END yet), e.g. when
    committing to the current chain tip. A full verdict needs verify().
    """
    bad_input = _validate_input(events)
    if bad_input:
        return bad_input
    c1 = _check_structural(events)
    if c1["status"] != "PASS":
        return list(c1["errors"])
    return list(_check_sequence(events)["errors"]) + list(_check_hash_chain(events)["errors"])


def _error_result(errors: list, session_id: Optional[str] = None, **flags) -> VerifyResult:
    return VerifyResult(
        status=ERROR,
        evidence_class=NO_EVIDENCE,
        session_id=session_id,
        event_count=0,
        log_drop_count=0,
        root_hash=None,
        errors=errors,
        checks={},
        **flags,
    )


def verify(
    events: list,
    signatures_valid: bool = False,
    trusted_seal_pubkey: Optional[str] = None,
    require_seal: bool = False,
) -> VerifyResult:
    """
    Run the full verification pipeline on a list of events.

    Checks 2–5 are skipped when structural check fails — malformed events
    produce misleading errors in downstream checks.

    trusted_seal_pubkey: base64 Ed25519 public key of the Archeion instance you trust,
        obtained out-of-band. Supplying it (a) requires the session to carry a CHAIN_SEAL,
        (b) requires that seal to be signed by exactly this key, and (c) is the only way
        to reach AUTHORITATIVE_EVIDENCE. Without it a valid seal yields only
        SELF_SEALED_EVIDENCE: the verifier cannot tell Archeion from an attacker.
    require_seal: demand a CHAIN_SEAL even when no key is pinned. Missing → COMPROMISED.

    Fails closed: input that is not a list of event objects, or any unexpected exception,
    yields status ERROR (never a traceback, never INTACT).
    """
    flags = {"pinned": trusted_seal_pubkey is not None, "require_seal": require_seal}
    bad_input = _validate_input(events)
    if bad_input:
        return _error_result(bad_input, **flags)
    try:
        return _verify(events, signatures_valid, trusted_seal_pubkey, require_seal)
    except Exception as exc:  # pragma: no cover - defensive: a verifier must never crash open
        return _error_result(
            [f"internal verifier error ({type(exc).__name__}): {exc}"],
            session_id=events[0].get("session_id") if isinstance(events[0], dict) else None,
            **flags,
        )


def _verify(
    events: list,
    signatures_valid: bool,
    trusted_seal_pubkey: Optional[str],
    require_seal: bool,
) -> VerifyResult:
    pinned = trusted_seal_pubkey is not None
    session_id = events[0].get("session_id")
    sorted_events = sorted(events, key=lambda e: e.get("seq", 0))
    root_hash = sorted_events[-1].get("event_hash")
    log_drops = sum(1 for e in events if e.get("event_type") == "LOG_DROP")
    _skipped = {"status": "SKIPPED", "errors": []}
    flags = {"pinned": pinned, "require_seal": require_seal}

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
                "seal_signature": _skipped,
                "session_signatures": _skipped,
                "rfc3161_timestamp": _skipped,
            },
            seal_present=any(e.get("event_type") == "CHAIN_SEAL" for e in events),
            **flags,
        )

    c2 = _check_sequence(events)
    c3 = _check_hash_chain(events)
    c4 = _check_completeness(events)
    c5 = _check_seal_signature(
        events, trusted_pubkey=trusted_seal_pubkey, require_seal=require_seal
    )
    _sigs_valid, c6 = _check_session_signatures(events)
    _ts_match, c7 = _check_rfc3161_timestamp(events)
    # Accept caller override (for testing) or auto-detected result
    computed_sigs_valid = signatures_valid or _sigs_valid
    checks = {
        "structural": c1,
        "sequence": c2,
        "hash_chain": c3,
        "completeness": c4,
        "seal_signature": c5,
        "session_signatures": c6,
        "rfc3161_timestamp": c7,
    }

    warnings: list = []
    seal_present = bool(c5.get("seal_present"))
    if seal_present and not pinned:
        warnings.append(
            "seal not verified against a trusted key; anyone can produce this "
            "(pass --trust-key with the Archeion public key to verify who sealed it)"
        )
    if not seal_present and not require_seal and not pinned:
        warnings.append(
            "session has no CHAIN_SEAL: only internal consistency was checked, so a "
            "complete rewrite of this log cannot be detected"
        )
    if c7["status"] == "IMPRINT_MATCH":
        warnings.append(f"RFC 3161 token: {_TS_CAVEAT}")

    # RFC 3161 failure is informational — does not cause COMPROMISED on its own.
    all_errors = c2["errors"] + c3["errors"] + c4["errors"] + c5["errors"] + c6["errors"]
    common = dict(
        session_id=session_id,
        event_count=len(events),
        log_drop_count=log_drops,
        root_hash=root_hash,
        checks=checks,
        timestamp_verified=False,
        timestamp_imprint_match=_ts_match,
        warnings=warnings,
        seal_present=seal_present,
        seal_trusted=bool(c5.get("seal_trusted")) and not all_errors,
        **flags,
    )

    if all_errors:
        return VerifyResult(
            status=COMPROMISED,
            evidence_class=NO_EVIDENCE,
            errors=all_errors,
            **{**common, "seal_trusted": False},
        )

    evidence = _determine_evidence_class(
        events, signatures_valid=computed_sigs_valid, seal_trusted=common["seal_trusted"]
    )
    status = PARTIAL if log_drops > 0 else INTACT

    return VerifyResult(status=status, evidence_class=evidence, errors=[], **common)
