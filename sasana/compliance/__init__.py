"""
sasana.compliance — Compliance export engine for Phase 3.

Produces machine-readable and human-readable evidence packages from
Sasana session JSONL files.

Supported standards:
    soc2       SOC 2 Type II CC7.2 evidence report (HTML + JSON)
    eu_ai_act  EU AI Act Article 12 technical logging report (HTML + JSON)
    hipaa      HIPAA §164.312(b) audit control log (CSV + JSON)
    siem       SIEM export — CEF events, JSON webhook, Splunk HEC

Usage:
    from sasana.compliance import load_session, verify_session
    from sasana.compliance.soc2 import generate_soc2_report
    from sasana.compliance.eu_ai_act import generate_eu_ai_act_report
    from sasana.compliance.hipaa import generate_hipaa_audit_log
    from sasana.compliance.siem import SiemExporter
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


def load_session(jsonl_path: str | Path) -> list[dict]:
    """Load and parse a Sasana session JSONL file."""
    path = Path(jsonl_path).expanduser()
    events: list[dict] = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                events.append(json.loads(line))
    return sorted(events, key=lambda e: e.get("seq", 0))


def verify_session(events: list[dict]) -> dict:
    """
    Run hash-chain verification on a loaded session.

    Returns a dict with keys: intact, error_count, errors, evidence_class,
    log_drop_count, root_hash, session_id, event_count.
    """
    from sasana.jcs import canonicalize as jcs_canonicalize

    GENESIS = "0" * 64
    errors: list[str] = []
    log_drops = 0
    prev_hash = GENESIS
    session_id: str | None = None
    root_hash: str | None = None

    for evt in events:
        seq = evt.get("seq", "?")
        if session_id is None:
            session_id = evt.get("session_id")
        if evt.get("event_type") == "LOG_DROP":
            log_drops += 1
        stored_prev = evt.get("prev_hash", "")
        if stored_prev != prev_hash:
            errors.append(f"seq={seq}: prev_hash chain broken")
        stripped = {k: v for k, v in evt.items() if k not in ("event_hash", "signature")}
        try:
            computed = hashlib.sha256(jcs_canonicalize(stripped)).hexdigest()
            if computed != evt.get("event_hash", ""):
                errors.append(f"seq={seq}: event_hash mismatch")
        except Exception as exc:
            errors.append(f"seq={seq}: hash error: {exc}")
        prev_hash = evt.get("event_hash", prev_hash)
        root_hash = prev_hash

    has_seal = any(e.get("event_type") == "CHAIN_SEAL" for e in events)
    if has_seal and not errors and not log_drops:
        evidence_class = "AUTHORITATIVE_EVIDENCE"
    elif not errors and not log_drops:
        evidence_class = "NON_AUTHORITATIVE_EVIDENCE"
    elif not errors and log_drops:
        evidence_class = "PARTIAL_EVIDENCE"
    else:
        evidence_class = "NO_EVIDENCE"

    return {
        "intact": len(errors) == 0,
        "error_count": len(errors),
        "errors": errors,
        "evidence_class": evidence_class,
        "log_drop_count": log_drops,
        "root_hash": root_hash,
        "session_id": session_id,
        "event_count": len(events),
    }
