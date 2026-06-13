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

import json
from pathlib import Path


def load_session(jsonl_path: str | Path) -> list:
    """Load and parse a Sasana session JSONL file."""
    path = Path(jsonl_path).expanduser()
    events: list = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                events.append(json.loads(line))
    return sorted(events, key=lambda e: e.get("seq", 0))


def verify_session(events: list) -> dict:
    """
    Run hash-chain verification on a loaded session.

    Returns a dict with keys: intact, error_count, errors, evidence_class,
    log_drop_count, root_hash, session_id, event_count.

    Delegates to sasana.verifier — single source of truth for all verification.
    """
    from sasana.verifier import verify as _verify
    result = _verify(events)
    return {
        "intact": result.status in ("INTACT", "PARTIAL"),
        "error_count": len(result.errors),
        "errors": result.errors,
        "evidence_class": result.evidence_class,
        "log_drop_count": result.log_drop_count,
        "root_hash": result.root_hash,
        "session_id": result.session_id,
        "event_count": result.event_count,
    }
