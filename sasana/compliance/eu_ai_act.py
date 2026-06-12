"""
sasana.compliance.eu_ai_act — EU AI Act Article 12 logging evidence report.

Article 12: "High-risk AI systems shall be designed and developed with
capabilities enabling the automatic recording of events throughout the
lifetime of the system ('logs')."

Usage:
    from sasana.compliance.eu_ai_act import generate_eu_ai_act_report

    report = generate_eu_ai_act_report(
        "~/.openclaw/sasana/<session_id>.jsonl",
        system_name="MyHighRiskAISystem",
        output_dir="./compliance_reports/",
    )
"""

from __future__ import annotations

import datetime
import json
from pathlib import Path
from typing import Optional

from sasana.compliance import load_session, verify_session

ARTICLE = "Article 12"
REGULATION = "EU AI Act (Regulation (EU) 2024/1689)"
REQUIREMENT = "Automatic recording of events throughout the AI system lifetime"


def generate_eu_ai_act_report(
    session_jsonl: str | Path,
    system_name: str = "AI System",
    system_version: str = "1.0.0",
    operator_id: Optional[str] = None,
    output_dir: Optional[str | Path] = None,
) -> dict:
    path = Path(session_jsonl).expanduser()
    events = load_session(path)
    verification = verify_session(events)

    generated_at = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    session_id = verification["session_id"] or path.stem

    first_evt = events[0] if events else {}
    last_evt = events[-1] if events else {}

    event_types = {e.get("event_type") for e in events}
    has_timestamps = all("timestamp" in e for e in events)
    has_input_logging = bool(event_types & {"LLM_CALL", "TOOL_CALL"})
    has_output_logging = bool(event_types & {"LLM_RESPONSE", "TOOL_RESULT"})
    has_error_logging = "TOOL_ERROR" in event_types
    has_session_bounds = "SESSION_START" in event_types and "SESSION_END" in event_types
    has_integrity_seal = "CHAIN_SEAL" in event_types

    requirement_checks = {
        "timestamps_on_all_events": has_timestamps,
        "input_events_logged": has_input_logging,
        "output_events_logged": has_output_logging,
        "error_events_logged": has_error_logging,
        "session_lifecycle_logged": has_session_bounds,
        "hash_chain_tamper_evident": verification["intact"],
        "no_log_drops": verification["log_drop_count"] == 0,
        "server_sealed": has_integrity_seal,
    }

    compliant = all(requirement_checks[k] for k in [
        "timestamps_on_all_events",
        "input_events_logged",
        "output_events_logged",
        "hash_chain_tamper_evident",
        "session_lifecycle_logged",
    ])

    interactions = []
    for evt in events:
        if evt.get("event_type") in ("LLM_CALL", "LLM_RESPONSE", "TOOL_CALL", "TOOL_RESULT", "TOOL_ERROR"):
            interactions.append({
                "seq": evt["seq"],
                "event_type": evt["event_type"],
                "timestamp": evt.get("timestamp", ""),
                "payload_keys": list(evt.get("payload", {}).keys()),
            })

    report = {
        "schema_version": "1.0",
        "regulation": REGULATION,
        "article": ARTICLE,
        "requirement": REQUIREMENT,
        "generated_at": generated_at,
        "session_id": session_id,
        "system_name": system_name,
        "system_version": system_version,
        "source_file": str(path),
        "compliant": compliant,
        "evidence_class": verification["evidence_class"],
        "event_count": verification["event_count"],
        "interaction_count": len(interactions),
        "session_start": first_evt.get("timestamp", ""),
        "session_end": last_evt.get("timestamp", ""),
        "log_drop_count": verification["log_drop_count"],
        "root_hash": verification["root_hash"],
        "requirement_checks": requirement_checks,
        "interaction_timeline": interactions,
        "integrity_errors": verification["errors"],
        "privacy_note": (
            "Raw AI inputs and outputs are not stored in this log. "
            "SHA-256 hashes of all content are recorded, satisfying Art. 12 "
            "logging requirements while preserving data minimisation (Art. 10.5)."
        ),
    }

    out_dir = Path(output_dir).expanduser() if output_dir else path.parent
    out_dir.mkdir(parents=True, exist_ok=True)
    stem = f"{session_id}_eu_ai_act_art12"

    json_path = out_dir / f"{stem}.json"
    json_path.write_text(json.dumps(report, indent=2))

    html_path = out_dir / f"{stem}.html"
    html_path.write_text(_render_eu_html(report))

    report["json_path"] = str(json_path)
    report["html_path"] = str(html_path)
    return report


def _render_eu_html(r: dict) -> str:
    status_color = "#22c55e" if r["compliant"] else "#f59e0b"
    status_text = "COMPLIANT" if r["compliant"] else "GAPS DETECTED"
    checks = r["requirement_checks"]

    def check_row(label: str, key: str) -> str:
        ok = checks.get(key, False)
        icon = "✅" if ok else "❌"
        return f"<tr><td>{label}</td><td>{icon}</td></tr>"

    interaction_rows = ""
    for ia in r["interaction_timeline"][:50]:
        interaction_rows += f"<tr><td>{ia['seq']}</td><td>{ia['event_type']}</td><td>{ia['timestamp']}</td></tr>\n"
    if len(r["interaction_timeline"]) > 50:
        interaction_rows += f"<tr><td colspan='3'>... and {len(r['interaction_timeline'])-50} more</td></tr>"

    error_section = ""
    if r["integrity_errors"]:
        items = "\n".join(f"<li>{e}</li>" for e in r["integrity_errors"])
        error_section = f"<h3>Integrity Errors</h3><ul class='errors'>{items}</ul>"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>EU AI Act Art.12 — {r["session_id"]}</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
         max-width: 900px; margin: 40px auto; padding: 0 20px; color: #1e293b; }}
  h1   {{ font-size: 1.5rem; border-bottom: 2px solid #e2e8f0; padding-bottom: 8px; }}
  h2   {{ font-size: 1.1rem; color: #475569; margin-top: 28px; }}
  h3   {{ font-size: 1rem; color: #475569; }}
  .badge {{ display: inline-block; background: {status_color}; color: #fff;
            font-weight: 700; padding: 4px 14px; border-radius: 4px;
            font-size: 1.1rem; vertical-align: middle; }}
  table  {{ width: 100%; border-collapse: collapse; margin: 12px 0; font-size: 0.9rem; }}
  th, td {{ text-align: left; padding: 8px 12px; border: 1px solid #e2e8f0; }}
  th     {{ background: #f8fafc; font-weight: 600; }}
  .mono  {{ font-family: 'SF Mono', 'Fira Code', monospace; font-size: 0.8rem; word-break: break-all; }}
  .errors li {{ color: #ef4444; margin: 4px 0; }}
  .note  {{ background: #f0f9ff; border-left: 4px solid #0ea5e9; padding: 12px 16px;
            font-size: 0.9rem; margin: 16px 0; }}
  footer {{ margin-top: 40px; color: #94a3b8; font-size: 0.8rem;
            border-top: 1px solid #e2e8f0; padding-top: 12px; }}
</style>
</head>
<body>
<h1>EU AI Act — Article 12 Logging Evidence &nbsp; <span class="badge">{status_text}</span></h1>
<p><strong>Regulation:</strong> {r["regulation"]}<br>
<strong>Article:</strong> {r["article"]} — {r["requirement"]}<br>
<strong>Generated:</strong> {r["generated_at"]}</p>

<h2>System Under Audit</h2>
<table>
  <tr><th>System Name</th><td>{r["system_name"]} v{r["system_version"]}</td></tr>
  <tr><th>Session ID</th><td class="mono">{r["session_id"]}</td></tr>
  <tr><th>Evidence Class</th><td><strong>{r["evidence_class"]}</strong></td></tr>
  <tr><th>Session Period</th><td>{r["session_start"]} → {r["session_end"]}</td></tr>
  <tr><th>Total Events</th><td>{r["event_count"]}</td></tr>
  <tr><th>AI Interactions Logged</th><td>{r["interaction_count"]}</td></tr>
  <tr><th>Log Drops</th><td>{r["log_drop_count"]}</td></tr>
  <tr><th>Root Hash</th><td class="mono">{r["root_hash"] or "N/A"}</td></tr>
</table>

<h2>Article 12 Requirement Checks</h2>
<table>
  <tr><th>Requirement</th><th>Status</th></tr>
  {check_row("Timestamps on all events", "timestamps_on_all_events")}
  {check_row("Input events logged (LLM calls, tool invocations)", "input_events_logged")}
  {check_row("Output events logged (LLM responses, tool results)", "output_events_logged")}
  {check_row("Error events logged", "error_events_logged")}
  {check_row("Session lifecycle logged (start/end)", "session_lifecycle_logged")}
  {check_row("Hash chain tamper-evident", "hash_chain_tamper_evident")}
  {check_row("No log drops detected", "no_log_drops")}
  {check_row("Server-sealed (AUTHORITATIVE_EVIDENCE)", "server_sealed")}
</table>

<h2>Interaction Timeline (first 50)</h2>
<table>
  <tr><th>Seq</th><th>Event Type</th><th>Timestamp</th></tr>
  {interaction_rows}
</table>

{error_section}

<div class="note">
  <strong>Privacy Note:</strong> {r["privacy_note"]}
</div>

<footer>Generated by Sasana v1.0.0 &middot; Source: {r["source_file"]}</footer>
</body>
</html>"""
