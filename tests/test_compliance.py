"""
test_compliance.py — Unit tests for sasana Phase 3 compliance exports.

Covers:
  - load_session / verify_session (shared utilities)
  - SOC 2 CC7.2 report generation (JSON + HTML)
  - EU AI Act Article 12 report generation
  - HIPAA §164.312(b) audit log (JSON + CSV + HTML)
  - SIEM: CEF format, JSON lines, syslog
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import sys
import unittest
from pathlib import Path

_DIST = Path(__file__).parent.parent
if str(_DIST) not in sys.path:
    sys.path.insert(0, str(_DIST))

from sasana.jcs import canonicalize as jcs_canonicalize  # noqa: E402
from sasana.compliance import load_session, verify_session  # noqa: E402
from sasana.compliance.soc2 import generate_soc2_report  # noqa: E402
from sasana.compliance.eu_ai_act import generate_eu_ai_act_report  # noqa: E402
from sasana.compliance.hipaa import generate_hipaa_audit_log  # noqa: E402
from sasana.compliance.siem import SiemExporter, _ts_to_epoch  # noqa: E402


def _build_event(seq, event_type, session_id, payload, prev_hash):
    import datetime
    ts = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"
    evt = {"seq": seq, "event_type": event_type, "session_id": session_id,
           "timestamp": ts, "payload": payload, "prev_hash": prev_hash}
    stripped = {k: v for k, v in evt.items() if k != "event_hash"}
    evt["event_hash"] = hashlib.sha256(jcs_canonicalize(stripped)).hexdigest()
    return evt


def _write_session(path, events):
    with open(path, "w") as f:
        for evt in events:
            f.write(json.dumps(evt) + "\n")


def _make_session_jsonl(tmp_dir, session_id="test-session-001"):
    GENESIS = "0" * 64
    events = []
    def append(seq, et, payload):
        prev = events[-1]["event_hash"] if events else GENESIS
        events.append(_build_event(seq, et, session_id, payload, prev))
    append(1, "SESSION_START", {"agent_id": "test-agent", "model": "claude-4"})
    append(2, "LLM_CALL",      {"model_hash": "a"*64, "prompt_hash": "b"*64, "prompt_count": 1})
    append(3, "LLM_RESPONSE",  {"response_hash": "c"*64, "response_len": 150})
    append(4, "TOOL_CALL",     {"tool_name_hash": "d"*64, "input_hash": "e"*64})
    append(5, "TOOL_RESULT",   {"output_hash": "f"*64, "output_len": 42})
    append(6, "TOOL_ERROR",    {"error_type": "ValueError", "error_hash": "0"*64})
    append(7, "SESSION_END",   {"status": "success"})
    path = Path(tmp_dir) / f"{session_id}.jsonl"
    _write_session(path, events)
    return path


def _make_tampered_session(tmp_dir, session_id="bad-session"):
    GENESIS = "0" * 64
    events = []
    def append(seq, et, payload):
        prev = events[-1]["event_hash"] if events else GENESIS
        events.append(_build_event(seq, et, session_id, payload, prev))
    append(1, "SESSION_START", {"agent_id": "test"})
    append(2, "LLM_CALL", {"prompt_hash": "a"*64})
    events[-1]["payload"]["injected"] = "evil"
    append(3, "SESSION_END", {"status": "success"})
    path = Path(tmp_dir) / f"{session_id}.jsonl"
    _write_session(path, events)
    return path


class TestLoadAndVerify(unittest.TestCase):
    def setUp(self):
        import tempfile
        self.tmp = Path(tempfile.mkdtemp())

    def test_load_session_returns_sorted_events(self):
        events = load_session(_make_session_jsonl(self.tmp))
        assert len(events) == 7
        assert [e["seq"] for e in events] == list(range(1, 8))

    def test_verify_intact_session(self):
        v = verify_session(load_session(_make_session_jsonl(self.tmp)))
        assert v["intact"] and v["error_count"] == 0
        assert v["evidence_class"] == "NON_AUTHORITATIVE_EVIDENCE"
        assert v["event_count"] == 7 and v["log_drop_count"] == 0

    def test_verify_tampered_session(self):
        v = verify_session(load_session(_make_tampered_session(self.tmp)))
        assert not v["intact"] and v["evidence_class"] == "NO_EVIDENCE"

    def test_verify_session_with_log_drop(self):
        GENESIS = "0" * 64
        sid = "drop-session"
        events = []
        def append(seq, et, payload):
            prev = events[-1]["event_hash"] if events else GENESIS
            events.append(_build_event(seq, et, sid, payload, prev))
        append(1, "SESSION_START", {})
        append(2, "LOG_DROP", {"dropped_count": 5})
        append(3, "SESSION_END", {"status": "success"})
        path = self.tmp / f"{sid}.jsonl"
        _write_session(path, events)
        v = verify_session(load_session(path))
        assert v["intact"] and v["log_drop_count"] == 1
        assert v["evidence_class"] == "PARTIAL_EVIDENCE"

    def test_verify_returns_correct_session_id(self):
        v = verify_session(load_session(_make_session_jsonl(self.tmp, "my-special-session")))
        assert v["session_id"] == "my-special-session"


class TestSoc2Report(unittest.TestCase):
    def setUp(self):
        import tempfile
        self.tmp = Path(tempfile.mkdtemp())
        self.jsonl = _make_session_jsonl(self.tmp)
        self.out = self.tmp / "reports"

    def test_generates_json_and_html(self):
        r = generate_soc2_report(self.jsonl, output_dir=self.out)
        assert Path(r["json_path"]).exists() and Path(r["html_path"]).exists()

    def test_report_passes_for_intact_session(self):
        r = generate_soc2_report(self.jsonl, output_dir=self.out)
        assert r["result"] == "PASS" and r["hash_chain_verified"] and r["event_count"] == 7

    def test_report_fails_for_tampered_session(self):
        r = generate_soc2_report(_make_tampered_session(self.tmp), output_dir=self.out)
        assert r["result"] == "FAIL" and not r["hash_chain_verified"]

    def test_report_contains_required_fields(self):
        r = generate_soc2_report(self.jsonl, output_dir=self.out)
        for f in ["framework","control_id","generated_at","session_id","result",
                  "evidence_class","event_count","root_hash","session_start",
                  "session_end","event_type_summary"]:
            assert f in r

    def test_report_json_is_valid(self):
        r = generate_soc2_report(self.jsonl, output_dir=self.out)
        data = json.loads(Path(r["json_path"]).read_text())
        assert data["control_id"] == "CC7.2" and data["framework"] == "SOC 2 Type II"

    def test_report_html_contains_session_id(self):
        r = generate_soc2_report(self.jsonl, output_dir=self.out)
        html = Path(r["html_path"]).read_text()
        assert r["session_id"] in html and "CC7.2" in html

    def test_event_type_summary_counts_correct(self):
        r = generate_soc2_report(self.jsonl, output_dir=self.out)
        s = r["event_type_summary"]
        assert s.get("SESSION_START") == 1 and s.get("SESSION_END") == 1
        assert s.get("LLM_CALL") == 1 and s.get("TOOL_ERROR") == 1


class TestEuAiActReport(unittest.TestCase):
    def setUp(self):
        import tempfile
        self.tmp = Path(tempfile.mkdtemp())
        self.jsonl = _make_session_jsonl(self.tmp)
        self.out = self.tmp / "reports"

    def test_generates_json_and_html(self):
        r = generate_eu_ai_act_report(self.jsonl, output_dir=self.out)
        assert Path(r["json_path"]).exists() and Path(r["html_path"]).exists()

    def test_compliant_for_intact_session(self):
        assert generate_eu_ai_act_report(self.jsonl, system_name="TestAI",
                                          output_dir=self.out)["compliant"]

    def test_requirement_checks_all_present(self):
        checks = generate_eu_ai_act_report(self.jsonl, output_dir=self.out)["requirement_checks"]
        for k in ["timestamps_on_all_events","input_events_logged","output_events_logged",
                  "hash_chain_tamper_evident","session_lifecycle_logged"]:
            assert k in checks

    def test_interaction_timeline_populated(self):
        r = generate_eu_ai_act_report(self.jsonl, output_dir=self.out)
        types = {x["event_type"] for x in r["interaction_timeline"]}
        assert "LLM_CALL" in types and "TOOL_CALL" in types

    def test_privacy_note_present(self):
        r = generate_eu_ai_act_report(self.jsonl, output_dir=self.out)
        assert "SHA-256" in r.get("privacy_note", "")

    def test_html_contains_article_reference(self):
        r = generate_eu_ai_act_report(self.jsonl, output_dir=self.out)
        assert "Article 12" in Path(r["html_path"]).read_text()

    def test_not_compliant_for_tampered_session(self):
        r = generate_eu_ai_act_report(_make_tampered_session(self.tmp), output_dir=self.out)
        assert not r["compliant"] and not r["requirement_checks"]["hash_chain_tamper_evident"]


class TestHipaaAuditLog(unittest.TestCase):
    def setUp(self):
        import tempfile
        self.tmp = Path(tempfile.mkdtemp())
        self.jsonl = _make_session_jsonl(self.tmp)
        self.out = self.tmp / "reports"

    def test_generates_json_csv_html(self):
        r = generate_hipaa_audit_log(self.jsonl, output_dir=self.out)
        assert all(Path(r[k]).exists() for k in ["json_path","csv_path","html_path"])

    def test_audit_record_count(self):
        assert generate_hipaa_audit_log(self.jsonl, output_dir=self.out)["audit_record_count"] == 7

    def test_access_types_mapped_correctly(self):
        recs = {r["event_type"]: r for r in
                generate_hipaa_audit_log(self.jsonl, output_dir=self.out)["audit_records"]}
        assert recs["SESSION_START"]["access_type"] == "SYSTEM_ACCESS"
        assert recs["LLM_CALL"]["access_type"] == "READ"
        assert recs["TOOL_CALL"]["access_type"] == "EXECUTE"
        assert recs["TOOL_ERROR"]["outcome"] == "FAILURE"

    def test_csv_parseable(self):
        r = generate_hipaa_audit_log(self.jsonl, output_dir=self.out)
        rows = list(csv.DictReader(io.StringIO(Path(r["csv_path"]).read_text())))
        assert len(rows) == 7 and "event_type" in rows[0]

    def test_compliant_core_for_intact_session(self):
        r = generate_hipaa_audit_log(self.jsonl, output_dir=self.out)
        assert r["compliant_core"] and r["compliance_flags"] == []

    def test_flags_for_tampered_session(self):
        r = generate_hipaa_audit_log(_make_tampered_session(self.tmp), output_dir=self.out)
        assert not r["compliant_core"] and len(r["compliance_flags"]) > 0

    def test_html_contains_hipaa_reference(self):
        r = generate_hipaa_audit_log(self.jsonl, output_dir=self.out)
        assert "164.312" in Path(r["html_path"]).read_text()

    def test_all_records_have_required_fields(self):
        recs = generate_hipaa_audit_log(self.jsonl, output_dir=self.out)["audit_records"]
        for rec in recs:
            for f in ["timestamp","system_id","access_type","outcome","event_hash"]:
                assert f in rec


class TestSiemExporter(unittest.TestCase):
    def setUp(self):
        import tempfile
        self.tmp = Path(tempfile.mkdtemp())
        self.jsonl = _make_session_jsonl(self.tmp)
        self.exporter = SiemExporter(self.jsonl, device_vendor="TestVendor",
                                      device_product="TestProduct")

    def test_to_cef_returns_one_line_per_event(self):
        assert len(self.exporter.to_cef()) == 7

    def test_cef_lines_start_with_cef_header(self):
        for line in self.exporter.to_cef():
            assert line.startswith("CEF:0|TestVendor|TestProduct|")

    def test_cef_contains_event_class_id(self):
        assert "|100|" in self.exporter.to_cef()[0]

    def test_cef_file_written(self):
        out = self.exporter.to_cef_file(self.tmp / "output.cef")
        assert out.exists() and out.read_text().count("CEF:0") == 7

    def test_json_records_structure(self):
        for rec in self.exporter.to_json_records():
            for f in ["session_id","event_type","event_hash","timestamp"]:
                assert f in rec

    def test_json_lines_file(self):
        out = self.exporter.to_json_lines(self.tmp / "output.jsonl")
        lines = [ln for ln in out.read_text().splitlines() if ln.strip()]
        assert len(lines) == 7 and all("event_type" in json.loads(ln) for ln in lines)

    def test_syslog_lines(self):
        lines = self.exporter.to_syslog_lines()
        assert len(lines) == 7
        for line in lines:
            assert line.startswith("<") and ">1 " in line

    def test_syslog_file_written(self):
        out = self.exporter.to_syslog_file(self.tmp / "output.syslog")
        assert out.exists() and out.stat().st_size > 0

    def test_summary(self):
        s = self.exporter.summary()
        assert s["event_count"] == 7 and s["hash_chain_intact"]

    def test_cef_session_start_severity_low(self):
        assert self.exporter.to_cef()[0].split("|")[6] == "3"

    def test_cef_tool_error_severity_high(self):
        err = [line for line in self.exporter.to_cef() if "|302|" in line]
        assert len(err) == 1 and int(err[0].split("|")[6]) >= 7


class TestTimestampConversion(unittest.TestCase):
    def test_iso_with_microseconds(self):
        assert _ts_to_epoch("2026-06-12T15:30:00.123456Z") > 1_700_000_000

    def test_iso_without_microseconds(self):
        assert _ts_to_epoch("2026-06-12T15:30:00Z") > 1_700_000_000

    def test_invalid_returns_now(self):
        import time
        assert abs(_ts_to_epoch("not-a-timestamp") - time.time()) < 5


if __name__ == "__main__":
    unittest.main()
