"""
sasana.compliance.siem — SIEM integration: CEF, JSON webhook, Splunk HEC.

Supports:
  - Common Event Format (CEF) — ArcSight, QRadar, Splunk
  - JSON webhook — generic HTTP POST to any SIEM
  - Splunk HTTP Event Collector (HEC)
  - Syslog (RFC 5424) — Elastic, Graylog, Sumo Logic
  - File export — pipe to syslogd or forward via Filebeat

All CEF/JSON events contain only hashed content.

Usage:
    from sasana.compliance.siem import SiemExporter

    exporter = SiemExporter(
        session_jsonl="~/.openclaw/sasana/<session_id>.jsonl",
        device_vendor="Sasana",
        device_product="AI Audit Trail",
    )
    exporter.to_cef_file("./siem_output/session.cef")
    exporter.to_json_lines("./siem_output/session.jsonl")
    exporter.to_splunk_hec("https://splunk.internal:8088/services/collector",
                            token="YOUR_HEC_TOKEN")
"""

from __future__ import annotations

import datetime
import json
import logging
import urllib.request
import urllib.error
from pathlib import Path
from typing import Dict, Optional

from sasana.compliance import load_session, verify_session

logger = logging.getLogger("sasana.compliance.siem")

_CEF_VERSION = "0"
_CEF_SEVERITY_MAP = {
    "SESSION_START":    "3",
    "SESSION_END":      "3",
    "LLM_CALL":         "4",
    "LLM_RESPONSE":     "4",
    "TOOL_CALL":        "5",
    "TOOL_RESULT":      "5",
    "TOOL_ERROR":       "7",
    "LOG_DROP":         "8",
    "CHAIN_SEAL":       "2",
    "CHAIN_BROKEN":     "9",
    "REDACTION":        "6",
    "FORENSIC_FREEZE":  "6",
}

_CEF_NAME_MAP = {
    "SESSION_START":    "AI Session Started",
    "SESSION_END":      "AI Session Ended",
    "LLM_CALL":         "LLM Invocation",
    "LLM_RESPONSE":     "LLM Response Received",
    "TOOL_CALL":        "Tool Invoked",
    "TOOL_RESULT":      "Tool Result Received",
    "TOOL_ERROR":       "Tool Execution Error",
    "LOG_DROP":         "Audit Event Dropped",
    "CHAIN_SEAL":       "Chain Sealed",
    "CHAIN_BROKEN":     "Chain Integrity Violation",
    "REDACTION":        "Event Redacted",
    "FORENSIC_FREEZE":  "Forensic Freeze Applied",
}

_EVENT_CLASS_ID_MAP = {
    "SESSION_START":    "100",
    "SESSION_END":      "101",
    "LLM_CALL":         "200",
    "LLM_RESPONSE":     "201",
    "TOOL_CALL":        "300",
    "TOOL_RESULT":      "301",
    "TOOL_ERROR":       "302",
    "LOG_DROP":         "400",
    "CHAIN_SEAL":       "500",
    "CHAIN_BROKEN":     "501",
    "REDACTION":        "600",
    "FORENSIC_FREEZE":  "601",
}


def _cef_escape(s: str) -> str:
    return s.replace("\\", "\\\\").replace("|", "\\|")


def _ext_escape(s: str) -> str:
    return s.replace("\\", "\\\\").replace("=", "\\=").replace("\n", "\\n")


class SiemExporter:
    """
    Exports a Sasana session to various SIEM formats.

    Parameters
    ----------
    session_jsonl  : path to a Sasana .jsonl session file
    device_vendor  : CEF DeviceVendor field (default: "Sasana")
    device_product : CEF DeviceProduct field (default: "AI Audit Trail")
    device_version : CEF DeviceVersion field (default: "1.0.0")
    """

    def __init__(
        self,
        session_jsonl: str | Path,
        device_vendor: str = "Sasana",
        device_product: str = "AI Audit Trail",
        device_version: str = "1.0.0",
    ) -> None:
        self._path = Path(session_jsonl).expanduser()
        self._vendor = device_vendor
        self._product = device_product
        self._version = device_version
        self._events: Optional[list[dict]] = None
        self._verification: Optional[dict] = None

    def _load(self) -> tuple[list[dict], dict]:
        if self._events is None:
            self._events = load_session(self._path)
            self._verification = verify_session(self._events)
        return self._events, self._verification

    def to_cef(self) -> list[str]:
        """Return a list of CEF-formatted log lines, one per event."""
        events, verification = self._load()
        return [self._event_to_cef(evt, verification["session_id"]) for evt in events]

    def to_cef_file(self, output_path: str | Path) -> Path:
        """Write CEF events to a file, one line per event."""
        out = Path(output_path).expanduser()
        out.parent.mkdir(parents=True, exist_ok=True)
        cef_lines = self.to_cef()
        out.write_text("\n".join(cef_lines) + "\n")
        logger.info("Sasana SIEM: wrote %d CEF events → %s", len(cef_lines), out)
        return out

    def _event_to_cef(self, evt: dict, session_id: Optional[str]) -> str:
        et = evt.get("event_type", "UNKNOWN")
        class_id = _EVENT_CLASS_ID_MAP.get(et, "999")
        name = _CEF_NAME_MAP.get(et, et)
        severity = _CEF_SEVERITY_MAP.get(et, "5")

        payload = evt.get("payload", {})
        ext_parts = [
            f"rt={_ext_escape(evt.get('timestamp', ''))}",
            f"cs1={_ext_escape(evt.get('event_hash', '')[:32])}",
            "cs1Label=eventHash",
            f"cs2={_ext_escape(evt.get('prev_hash', '')[:32])}",
            "cs2Label=prevHash",
            f"cn1={evt.get('seq', 0)}",
            "cn1Label=seq",
            f"cs3={_ext_escape(session_id or '')}",
            "cs3Label=sessionId",
        ]
        for key in ["framework", "tool_name_hash", "model_hash", "error_type"]:
            if key in payload:
                ext_parts.append(f"flexString1={_ext_escape(str(payload[key]))}")
                ext_parts.append(f"flexString1Label={key}")
                break

        header = (
            f"CEF:{_CEF_VERSION}"
            f"|{_cef_escape(self._vendor)}"
            f"|{_cef_escape(self._product)}"
            f"|{_cef_escape(self._version)}"
            f"|{class_id}"
            f"|{_cef_escape(name)}"
            f"|{severity}"
        )
        return f"{header}|{' '.join(ext_parts)}"

    def to_json_records(self) -> list[dict]:
        """Return a list of SIEM-ready JSON records."""
        events, verification = self._load()
        return [
            {
                "sasana_version": "1.0.0",
                "device_vendor": self._vendor,
                "device_product": self._product,
                "session_id": verification["session_id"],
                "seq": evt.get("seq"),
                "timestamp": evt.get("timestamp"),
                "event_type": evt.get("event_type"),
                "event_hash": evt.get("event_hash"),
                "prev_hash": evt.get("prev_hash"),
                "evidence_class": verification["evidence_class"],
                "payload_keys": sorted(evt.get("payload", {}).keys()),
                "framework": evt.get("payload", {}).get("framework"),
            }
            for evt in events
        ]

    def to_json_lines(self, output_path: str | Path) -> Path:
        """Write one JSON record per line (JSONL) — suitable for Filebeat/Logstash."""
        out = Path(output_path).expanduser()
        out.parent.mkdir(parents=True, exist_ok=True)
        records = self.to_json_records()
        out.write_text("\n".join(json.dumps(r) for r in records) + "\n")
        logger.info("Sasana SIEM: wrote %d JSON events → %s", len(records), out)
        return out

    def to_splunk_hec(
        self,
        hec_url: str,
        token: str,
        index: str = "main",
        source: str = "sasana",
        sourcetype: str = "sasana:audit",
        batch_size: int = 100,
        timeout: int = 10,
    ) -> dict:
        """POST events to Splunk HEC. Returns dict with sent/failed/batches."""
        records = self.to_json_records()
        if not token.startswith("Splunk "):
            token = f"Splunk {token}"
        sent = failed = batches = 0
        for i in range(0, len(records), batch_size):
            batch = records[i:i + batch_size]
            payload = "\n".join(
                json.dumps({"time": _ts_to_epoch(r.get("timestamp", "")),
                            "host": "sasana", "source": source,
                            "sourcetype": sourcetype, "index": index, "event": r})
                for r in batch
            ).encode("utf-8")
            req = urllib.request.Request(
                hec_url, data=payload,
                headers={"Authorization": token, "Content-Type": "application/json"},
                method="POST",
            )
            try:
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    resp.read()
                    sent += len(batch); batches += 1
            except urllib.error.URLError as exc:
                logger.error("Sasana SIEM: Splunk HEC batch %d failed: %s", batches, exc)
                failed += len(batch)
        return {"sent": sent, "failed": failed, "batches": batches}

    def to_webhook(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        batch_size: int = 50,
        timeout: int = 10,
    ) -> dict:
        """POST events as JSON batches to any HTTP endpoint."""
        records = self.to_json_records()
        hdrs = {"Content-Type": "application/json"}
        if headers:
            hdrs.update(headers)
        sent = failed = batches = 0
        for i in range(0, len(records), batch_size):
            batch = records[i:i + batch_size]
            payload = json.dumps({"events": batch, "batch": batches,
                                   "source": self._product}).encode("utf-8")
            req = urllib.request.Request(url, data=payload, headers=hdrs, method="POST")
            try:
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    resp.read()
                    sent += len(batch); batches += 1
            except urllib.error.URLError as exc:
                logger.error("Sasana SIEM: webhook batch %d failed: %s", batches, exc)
                failed += len(batch)
        return {"sent": sent, "failed": failed, "batches": batches}

    def to_syslog_lines(self) -> list[str]:
        """Return RFC 5424 syslog-formatted lines."""
        events, verification = self._load()
        session_id = (verification["session_id"] or "unknown")[:48]
        lines = []
        for evt in events:
            et = evt.get("event_type", "UNKNOWN")
            severity = int(_CEF_SEVERITY_MAP.get(et, "5"))
            syslog_sev = min(7, max(0, 7 - severity // 2))
            pri = 16 * 8 + syslog_sev
            ts = evt.get("timestamp", datetime.datetime.utcnow().isoformat() + "Z")
            msg = json.dumps({
                "event_type": et,
                "seq": evt.get("seq"),
                "event_hash": evt.get("event_hash", "")[:16],
                "session_id": session_id,
            })
            lines.append(f"<{pri}>1 {ts} sasana-ai-audit sasana - {session_id[:32]} - {msg}")
        return lines

    def to_syslog_file(self, output_path: str | Path) -> Path:
        """Write RFC 5424 syslog lines to a file."""
        out = Path(output_path).expanduser()
        out.parent.mkdir(parents=True, exist_ok=True)
        lines = self.to_syslog_lines()
        out.write_text("\n".join(lines) + "\n")
        logger.info("Sasana SIEM: wrote %d syslog events → %s", len(lines), out)
        return out

    def summary(self) -> dict:
        """Return a summary of the session for SIEM dashboards."""
        events, verification = self._load()
        counts: dict[str, int] = {}
        for evt in events:
            et = evt.get("event_type", "UNKNOWN")
            counts[et] = counts.get(et, 0) + 1
        return {
            "session_id": verification["session_id"],
            "evidence_class": verification["evidence_class"],
            "event_count": verification["event_count"],
            "log_drop_count": verification["log_drop_count"],
            "hash_chain_intact": verification["intact"],
            "root_hash": verification["root_hash"],
            "event_type_counts": counts,
            "source_file": str(self._path),
        }


def _ts_to_epoch(ts: str) -> float:
    """Convert ISO timestamp to Unix epoch float for Splunk."""
    try:
        ts = ts.rstrip("Z").replace("T", " ")
        fmt = "%Y-%m-%d %H:%M:%S.%f" if "." in ts else "%Y-%m-%d %H:%M:%S"
        return datetime.datetime.strptime(ts, fmt).replace(
            tzinfo=datetime.timezone.utc
        ).timestamp()
    except (ValueError, AttributeError):
        return datetime.datetime.now(datetime.timezone.utc).timestamp()
