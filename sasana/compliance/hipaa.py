"""
sasana.compliance.hipaa — HIPAA §164.312(b) Audit Controls export.

Requirement: "Implement hardware, software, and/or procedural mechanisms
that record and examine activity in information systems that contain or
use electronic protected health information."

Sasana maps AI session events to HIPAA audit categories:
  LLM_CALL/LLM_RESPONSE → READ (querying AI for information)
  TOOL_CALL/TOOL_RESULT  → EXECUTE (invoking a tool/function)
  TOOL_ERROR             → EXECUTE_FAILURE
  SESSION_START/END      → SYSTEM_ACCESS

Usage:
    from sasana.compliance.hipaa import generate_hipaa_audit_log

    report = generate_hipaa_audit_log(
        "~/.openclaw/sasana/<session_id>.jsonl",
        system_id="ClinicalAI-v2",
        covered_entity="General Hospital",
        output_dir="./compliance_reports/",
    )
"""

from __future__ import annotations

import csv
import datetime
import io
import json
from pathlib import Path
from typing import Optional

from sasana.compliance import load_session, verify_session

REGULATION = "HIPAA Security Rule"
STANDARD = "§164.312(b) — Audit Controls"

_ACCESS_TYPE_MAP = {
    "SESSION_START": ("SYSTEM_ACCESS", "SUCCESS"),
    "SESSION_END": ("SYSTEM_ACCESS", "SUCCESS"),
    "LLM_CALL": ("READ", "PENDING"),
    "LLM_RESPONSE": ("READ", "SUCCESS"),
    "TOOL_CALL": ("EXECUTE", "PENDING"),
    "TOOL_RESULT": ("EXECUTE", "SUCCESS"),
    "TOOL_ERROR": ("EXECUTE", "FAILURE"),
    "LOG_DROP": ("AUDIT_FAILURE", "FAILURE"),
    "CHAIN_SEAL": ("INTEGRITY_SEAL", "SUCCESS"),
    "CHAIN_BROKEN": ("INTEGRITY_CHECK", "FAILURE"),
    "REDACTION": ("DELETE", "SUCCESS"),
    "FORENSIC_FREEZE": ("INTEGRITY_SEAL", "SUCCESS"),
}


def generate_hipaa_audit_log(
    session_jsonl: str | Path,
    system_id: str = "AI System",
    covered_entity: Optional[str] = None,
    business_associate: Optional[str] = None,
    output_dir: Optional[str | Path] = None,
) -> dict:
    path = Path(session_jsonl).expanduser()
    events = load_session(path)
    verification = verify_session(events)

    generated_at = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    session_id = verification["session_id"] or path.stem

    audit_records = []
    for evt in events:
        access_type, outcome = _ACCESS_TYPE_MAP.get(
            evt.get("event_type", ""), ("UNKNOWN", "UNKNOWN")
        )
        payload = evt.get("payload", {})
        record = {
            "seq": evt.get("seq"),
            "timestamp": evt.get("timestamp", ""),
            "system_id": system_id,
            "session_id": session_id,
            "event_type": evt.get("event_type", ""),
            "access_type": access_type,
            "outcome": outcome,
            "event_hash": evt.get("event_hash", ""),
            "payload_fields": sorted(payload.keys()),
        }
        audit_records.append(record)

    has_tamper_evidence = verification["intact"]
    has_no_drops = verification["log_drop_count"] == 0
    has_timestamps = all(r["timestamp"] for r in audit_records)

    compliant_core = has_tamper_evidence and has_timestamps
    flags = []
    if not has_tamper_evidence:
        flags.append("HASH_CHAIN_VIOLATED — audit log integrity cannot be guaranteed")
    if not has_no_drops:
        flags.append(f"LOG_DROPS_DETECTED — {verification['log_drop_count']} events not captured")

    report = {
        "schema_version": "1.0",
        "regulation": REGULATION,
        "standard": STANDARD,
        "generated_at": generated_at,
        "session_id": session_id,
        "system_id": system_id,
        "covered_entity": covered_entity,
        "business_associate": business_associate,
        "source_file": str(path),
        "compliant_core": compliant_core,
        "evidence_class": verification["evidence_class"],
        "audit_record_count": len(audit_records),
        "log_drop_count": verification["log_drop_count"],
        "hash_chain_intact": verification["intact"],
        "root_hash": verification["root_hash"],
        "compliance_flags": flags,
        "audit_records": audit_records,
    }

    out_dir = Path(output_dir).expanduser() if output_dir else path.parent
    out_dir.mkdir(parents=True, exist_ok=True)
    stem = f"{session_id}_hipaa_audit"

    json_path = out_dir / f"{stem}.json"
    json_path.write_text(json.dumps(report, indent=2))

    csv_path = out_dir / f"{stem}.csv"
    csv_path.write_text(_render_csv(audit_records))

    html_path = out_dir / f"{stem}.html"
    html_path.write_text(_render_hipaa_html(report))

    report["json_path"] = str(json_path)
    report["csv_path"] = str(csv_path)
    report["html_path"] = str(html_path)
    return report


def _render_csv(records: list[dict]) -> str:
    buf = io.StringIO()
    if not records:
        return ""
    fieldnames = [
        "seq",
        "timestamp",
        "system_id",
        "session_id",
        "event_type",
        "access_type",
        "outcome",
        "event_hash",
    ]
    writer = csv.DictWriter(buf, fieldnames=fieldnames, extrasaction="ignore")
    writer.writeheader()
    writer.writerows(records)
    return buf.getvalue()


def _render_hipaa_html(r: dict) -> str:
    status_color = "#22c55e" if r["compliant_core"] else "#ef4444"
    status_text = "COMPLIANT" if r["compliant_core"] else "REVIEW REQUIRED"

    flag_html = ""
    if r["compliance_flags"]:
        items = "\n".join(f"<li>⚠️ {f}</li>" for f in r["compliance_flags"])
        flag_html = f"<div class='flags'><h3>Compliance Flags</h3><ul>{items}</ul></div>"

    rows = ""
    for rec in r["audit_records"][:100]:
        outcome_color = (
            "#22c55e"
            if rec["outcome"] == "SUCCESS"
            else ("#94a3b8" if rec["outcome"] == "PENDING" else "#ef4444")
        )
        rows += f"""<tr>
  <td>{rec["seq"]}</td>
  <td class='mono'>{rec["timestamp"]}</td>
  <td>{rec["system_id"]}</td>
  <td>{rec["event_type"]}</td>
  <td>{rec["access_type"]}</td>
  <td style="color:{outcome_color};font-weight:600">{rec["outcome"]}</td>
  <td class='mono hash'>{rec["event_hash"][:16]}…</td>
</tr>\n"""
    if len(r["audit_records"]) > 100:
        rows += f"<tr><td colspan='7'>… and {len(r['audit_records']) - 100} more records (see CSV export)</td></tr>"

    ce = r.get("covered_entity") or "Not specified"
    ba = r.get("business_associate") or "Not specified"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>HIPAA Audit Log — {r["session_id"]}</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
         max-width: 1100px; margin: 40px auto; padding: 0 20px; color: #1e293b; }}
  h1   {{ font-size: 1.5rem; border-bottom: 2px solid #e2e8f0; padding-bottom: 8px; }}
  h2   {{ font-size: 1.1rem; color: #475569; margin-top: 28px; }}
  h3   {{ font-size: 1rem; color: #475569; }}
  .badge {{ display: inline-block; background: {status_color}; color: #fff;
            font-weight: 700; padding: 4px 14px; border-radius: 4px;
            font-size: 1.1rem; vertical-align: middle; }}
  table  {{ width: 100%; border-collapse: collapse; margin: 12px 0; font-size: 0.85rem; }}
  th, td {{ text-align: left; padding: 6px 10px; border: 1px solid #e2e8f0; }}
  th     {{ background: #f8fafc; font-weight: 600; }}
  .mono  {{ font-family: 'SF Mono', 'Fira Code', monospace; }}
  .hash  {{ font-size: 0.75rem; color: #64748b; }}
  .flags {{ background: #fffbeb; border: 1px solid #fcd34d; padding: 12px 16px;
            margin: 16px 0; border-radius: 4px; }}
  .flags li {{ margin: 4px 0; }}
  footer {{ margin-top: 40px; color: #94a3b8; font-size: 0.8rem;
            border-top: 1px solid #e2e8f0; padding-top: 12px; }}
</style>
</head>
<body>
<h1>HIPAA §164.312(b) Audit Control Log &nbsp; <span class="badge">{status_text}</span></h1>
<p><strong>Regulation:</strong> {r["regulation"]}<br>
<strong>Standard:</strong> {r["standard"]}<br>
<strong>Generated:</strong> {r["generated_at"]}</p>

<h2>System Information</h2>
<table>
  <tr><th>System ID</th><td>{r["system_id"]}</td></tr>
  <tr><th>Covered Entity</th><td>{ce}</td></tr>
  <tr><th>Business Associate</th><td>{ba}</td></tr>
  <tr><th>Session ID</th><td class="mono">{r["session_id"]}</td></tr>
  <tr><th>Evidence Class</th><td><strong>{r["evidence_class"]}</strong></td></tr>
  <tr><th>Audit Records</th><td>{r["audit_record_count"]}</td></tr>
  <tr><th>Hash Chain Intact</th><td>{"✅ Yes" if r["hash_chain_intact"] else "❌ No"}</td></tr>
  <tr><th>Log Drops</th><td>{r["log_drop_count"]}</td></tr>
  <tr><th>Root Hash</th><td class="mono hash">{r["root_hash"] or "N/A"}</td></tr>
</table>

{flag_html}

<h2>Audit Records (first 100 — full set in CSV export)</h2>
<table>
  <tr>
    <th>Seq</th><th>Timestamp</th><th>System ID</th>
    <th>Event Type</th><th>Access Type</th><th>Outcome</th><th>Event Hash</th>
  </tr>
  {rows}
</table>

<footer>Generated by Sasana v1.0.0 &middot; HIPAA §164.312(b) &middot; Source: {r["source_file"]}</footer>
</body>
</html>"""
