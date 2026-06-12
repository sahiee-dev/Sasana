#!/usr/bin/env python3
"""
verify.py — Standalone verifier for Sasana session logs.

Usage:
  python3 verify.py <session.jsonl> [--format {text,json}] [--verbose]

Exit codes: 0=PASS  1=FAIL  2=ERROR
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys

from sasana.jcs import canonicalize as jcs_canonicalize

VERIFIER_VERSION = "1.0.0"
GENESIS_HASH = "0" * 64

ALLOWED_EVENT_TYPES = {
    "SESSION_START", "SESSION_END", "LLM_CALL", "LLM_RESPONSE",
    "TOOL_CALL", "TOOL_RESULT", "TOOL_ERROR", "LOG_DROP",
    "CHAIN_SEAL", "CHAIN_BROKEN", "REDACTION", "FORENSIC_FREEZE",
}
REQUIRED_FIELDS = {"seq", "event_type", "session_id", "timestamp", "payload", "prev_hash", "event_hash"}


def check_structural_validity(events: list[dict]) -> dict:
    errors = []
    for event in events:
        seq = event.get("seq", "?")
        for field in REQUIRED_FIELDS:
            if field not in event:
                errors.append(f"seq={seq}: Missing required field '{field}'")
        if "event_type" in event and event["event_type"] not in ALLOWED_EVENT_TYPES:
            errors.append(f"seq={seq}: Unknown event_type '{event['event_type']}'")
        for hfield in ("prev_hash", "event_hash"):
            h = event.get(hfield)
            if h is not None and not (isinstance(h, str) and len(h) == 64 and all(c in "0123456789abcdef" for c in h)):
                errors.append(f"seq={seq}: '{hfield}' must be 64-char lowercase hex")
    return {"status": "PASS" if not errors else "FAIL", "events_checked": len(events), "errors": errors}


def check_sequence_integrity(events: list[dict]) -> dict:
    errors, gaps, duplicates = [], [], []
    sorted_events = sorted(events, key=lambda e: e.get("seq", 0))
    seqs = [e.get("seq") for e in sorted_events]
    if len(set(e.get("session_id") for e in events)) > 1:
        errors.append("Multiple session_ids found")
    first_seq = seqs[0] if seqs else None
    if first_seq != 1:
        errors.append(f"First seq must be 1, got {first_seq}")
    seen: dict = {}
    for s in seqs:
        if s in seen:
            duplicates.append(s)
        seen[s] = True
    for i in range(1, len(seqs)):
        if seqs[i] != seqs[i - 1] + 1:
            msg = f"Expected seq={seqs[i-1]+1}, found seq={seqs[i]}"
            gaps.append(msg); errors.append(msg)
    if duplicates:
        errors.append(f"Duplicate seq values: {duplicates}")
    return {"status": "PASS" if not errors else "FAIL", "gaps": gaps, "errors": errors}


def _compute_event_hash(event: dict) -> str:
    stripped = {k: v for k, v in event.items() if k not in ("event_hash", "signature")}
    return hashlib.sha256(jcs_canonicalize(stripped)).hexdigest()


def check_hash_chain_integrity(events: list[dict]) -> dict:
    errors = []
    sorted_events = sorted(events, key=lambda e: e.get("seq", 0))
    first = [e for e in sorted_events if e.get("seq") == 1]
    if first and first[0].get("prev_hash") != GENESIS_HASH:
        errors.append("seq=1: prev_hash must be 64 zeros (genesis hash)")
    prev_hash: str | None = None
    for event in sorted_events:
        seq = event.get("seq", "?")
        try:
            expected = _compute_event_hash(event)
        except Exception as e:
            errors.append(f"seq={seq}: hash computation failed: {e}"); break
        if event.get("event_hash") != expected:
            errors.append(f"seq={seq} ({event.get('event_type','?')}): event_hash mismatch"); break
        if prev_hash is not None and event.get("prev_hash") != prev_hash:
            errors.append(f"seq={seq}: prev_hash chain broken"); break
        prev_hash = event.get("event_hash")
    return {"status": "PASS" if not errors else "FAIL", "errors": errors}


def check_session_completeness(events: list[dict]) -> dict:
    errors = []
    sorted_events = sorted(events, key=lambda e: e.get("seq", 0))
    types = [e.get("event_type") for e in sorted_events]
    if types.count("SESSION_START") != 1:
        errors.append(f"Expected 1 SESSION_START, found {types.count('SESSION_START')}")
    if "SESSION_START" in types:
        ss_seq = next(e["seq"] for e in sorted_events if e.get("event_type") == "SESSION_START")
        if ss_seq != sorted_events[0].get("seq"):
            errors.append("SESSION_START must be at seq=1")
    if "SESSION_END" not in types and "CHAIN_SEAL" not in types:
        errors.append("Session has no SESSION_END or CHAIN_SEAL")
    return {"status": "PASS" if not errors else "FAIL",
            "has_session_start": "SESSION_START" in types,
            "has_session_end": "SESSION_END" in types,
            "log_drop_count": types.count("LOG_DROP"), "errors": errors}


def determine_evidence_class(events: list[dict], signatures_valid: bool = False) -> str:
    has_seal = any(e.get("event_type") == "CHAIN_SEAL" for e in events)
    has_drop = any(e.get("event_type") == "LOG_DROP" for e in events)
    if has_seal and not has_drop:
        return "AUTHORITATIVE_EVIDENCE"
    return "SIGNED_NON_AUTHORITATIVE_EVIDENCE" if signatures_valid else "NON_AUTHORITATIVE_EVIDENCE"


def main() -> None:
    parser = argparse.ArgumentParser(description=f"Sasana Verifier v{VERIFIER_VERSION}")
    parser.add_argument("session_file")
    parser.add_argument("--format", choices=["text", "json"], default="text")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    try:
        with open(args.session_file) as f:
            raw = f.read()
    except (FileNotFoundError, OSError) as e:
        print(f"ERROR: {e}", file=sys.stderr); sys.exit(2)

    events: list[dict] = []
    try:
        for line in raw.splitlines():
            line = line.strip()
            if line:
                events.append(json.loads(line))
    except json.JSONDecodeError as e:
        print(f"ERROR: Malformed JSONL: {e}", file=sys.stderr); sys.exit(2)

    session_id = events[0].get("session_id", "unknown") if events else "unknown"
    cr: dict = {}
    all_errors: list[str] = []

    cr["structural"] = c1 = check_structural_validity(events)
    cr["sequence"] = c2 = check_sequence_integrity(events) if c1["status"] == "PASS" else {"status": "FAIL", "errors": []}
    cr["hash_chain"] = c3 = check_hash_chain_integrity(events) if c1["status"] == "PASS" else {"status": "FAIL", "errors": []}
    if all(cr[k]["status"] == "PASS" for k in ["structural", "sequence", "hash_chain"]):
        cr["completeness"] = c4 = check_session_completeness(events)
    else:
        cr["completeness"] = c4 = None

    for k in ["structural", "sequence", "hash_chain", "completeness"]:
        r = cr.get(k)
        if r:
            all_errors.extend(r.get("errors", []))

    overall = "PASS" if all(cr.get(k, {}).get("status") == "PASS"
        for k in ["structural", "sequence", "hash_chain", "completeness"] if cr.get(k)) else "FAIL"
    evidence = determine_evidence_class(events) if overall == "PASS" else None
    log_drops = sum(1 for e in events if e.get("event_type") == "LOG_DROP")

    if args.format == "json":
        print(json.dumps({"verifier_version": VERIFIER_VERSION, "session_id": session_id,
            "event_count": len(events), "evidence_class": evidence, "result": overall,
            "log_drop_count": log_drops, "errors": all_errors}, indent=2))
    else:
        print(f"Sasana Verifier v{VERIFIER_VERSION}")
        print("=" * 32)
        print(f"File     : {args.session_file}")
        print(f"Session  : {session_id}")
        print(f"Events   : {len(events)}")
        print(f"Evidence : {evidence or '(cannot determine — chain invalid)'}")
        print()
        for label, key in [("[1/4] Structural validity ", "structural"),
                           ("[2/4] Sequence integrity  ", "sequence"),
                           ("[3/4] Hash chain integrity", "hash_chain"),
                           ("[4/4] Session completeness", "completeness")]:
            r = cr.get(key)
            st = r["status"] if r else "(skipped)"
            print(f"{label} ... {st}")
            if r and r["status"] == "FAIL" and args.verbose:
                for e in r.get("errors", []):
                    print(f"      {e}")
        print()
        if overall == "PASS" and log_drops == 0:
            print("Result: INTACT ✅")
        elif overall == "PASS":
            print(f"Result: PARTIAL ⚠️  ({log_drops} LOG_DROP events)")
        else:
            print("Result: FAIL ❌")
            for err in all_errors[:10]:
                print(f"  → {err}")
    sys.exit(0 if overall == "PASS" else 1)


if __name__ == "__main__":
    main()
