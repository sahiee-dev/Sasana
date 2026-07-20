"""
test_otel_exporter.py — Unit tests for sasana.integrations.otel.

opentelemetry is an optional dependency and is not required to run these
tests: span_to_events is a pure function over duck-typed spans, and the full
export path is exercised by temporarily flipping the availability flag (the
exporter uses no real OpenTelemetry symbols at runtime).
"""

from __future__ import annotations

import sys
import tempfile
import types
import unittest
from pathlib import Path

_DIST = Path(__file__).parent.parent
if str(_DIST) not in sys.path:
    sys.path.insert(0, str(_DIST))

from sasana._utils import content_hash  # noqa: E402
from sasana.integrations import otel  # noqa: E402
from sasana.integrations.otel import SasanaSpanExporter, span_to_events  # noqa: E402
from sasana.verifier import verify  # noqa: E402


class FakeSpan:
    def __init__(self, name="", attributes=None, trace_id=1, status_name="OK"):
        self.name = name
        self.attributes = attributes or {}
        self.context = types.SimpleNamespace(trace_id=trace_id)
        self.status = types.SimpleNamespace(status_code=types.SimpleNamespace(name=status_name))


class TestSpanMapping(unittest.TestCase):
    def test_llm_chat_span_maps_to_call_and_response(self):
        span = FakeSpan(
            name="chat gpt-4o",
            attributes={
                "gen_ai.operation.name": "chat",
                "gen_ai.system": "openai",
                "gen_ai.request.model": "gpt-4o",
                "gen_ai.usage.input_tokens": 1841,
                "gen_ai.usage.output_tokens": 412,
                "gen_ai.response.id": "resp-123",
            },
        )
        events = span_to_events(span)
        types_ = [e[0] for e in events]
        assert types_ == ["LLM_CALL", "LLM_RESPONSE"]
        assert events[0][1]["model_hash"] == content_hash("gpt-4o")
        assert events[0][1]["prompt_tokens"] == 1841
        assert events[1][1]["completion_tokens"] == 412
        assert events[1][1]["response_hash"] == content_hash("resp-123")

    def test_tool_span_maps_to_call_and_result(self):
        span = FakeSpan(
            name="execute_tool search",
            attributes={"gen_ai.operation.name": "execute_tool", "gen_ai.tool.name": "web_search"},
        )
        events = span_to_events(span)
        assert [e[0] for e in events] == ["TOOL_CALL", "TOOL_RESULT"]
        assert events[0][1]["tool_name_hash"] == content_hash("web_search")

    def test_error_llm_span_maps_to_call_and_error(self):
        span = FakeSpan(
            name="chat",
            attributes={
                "gen_ai.operation.name": "chat",
                "gen_ai.request.model": "gpt-4o",
                "error.type": "RateLimitError",
            },
            status_name="ERROR",
        )
        events = span_to_events(span)
        assert [e[0] for e in events] == ["LLM_CALL", "TOOL_ERROR"]
        assert events[1][1]["error_type"] == "RateLimitError"

    def test_error_via_status_code_only(self):
        span = FakeSpan(
            name="execute_tool",
            attributes={"gen_ai.tool.name": "db_query"},
            status_name="ERROR",
        )
        events = span_to_events(span)
        assert [e[0] for e in events] == ["TOOL_CALL", "TOOL_ERROR"]

    def test_legacy_token_attribute_names(self):
        span = FakeSpan(
            attributes={
                "gen_ai.operation.name": "chat",
                "gen_ai.request.model": "claude-sonnet-5",
                "gen_ai.usage.prompt_tokens": 100,
                "gen_ai.usage.completion_tokens": 50,
            },
        )
        events = span_to_events(span)
        assert events[0][1]["prompt_tokens"] == 100
        assert events[1][1]["completion_tokens"] == 50

    def test_non_genai_span_maps_to_nothing(self):
        span = FakeSpan(name="GET /health", attributes={"http.method": "GET"})
        assert span_to_events(span) == []

    def test_model_present_without_operation_is_llm(self):
        span = FakeSpan(attributes={"gen_ai.request.model": "gpt-4o-mini"})
        assert [e[0] for e in span_to_events(span)] == ["LLM_CALL", "LLM_RESPONSE"]


class TestExporterAvailabilityGuard(unittest.TestCase):
    def test_instantiation_requires_otel_when_absent(self):
        if otel._OTEL_AVAILABLE:
            self.skipTest("opentelemetry is installed; guard not exercised")
        with self.assertRaises(ImportError):
            SasanaSpanExporter()


class TestFullExportFlow(unittest.TestCase):
    """Exercise export → ledger → verify with the availability flag forced on."""

    def setUp(self):
        self._saved = otel._OTEL_AVAILABLE
        otel._OTEL_AVAILABLE = True
        self.tmp = Path(tempfile.mkdtemp())

    def tearDown(self):
        otel._OTEL_AVAILABLE = self._saved

    def test_export_produces_verifiable_intact_ledger(self):
        exporter = SasanaSpanExporter(output_dir=self.tmp)
        trace_id = 0xABCDEF
        spans = [
            FakeSpan(
                attributes={
                    "gen_ai.operation.name": "chat",
                    "gen_ai.system": "anthropic",
                    "gen_ai.request.model": "claude-opus-4-8",
                    "gen_ai.usage.input_tokens": 900,
                    "gen_ai.usage.output_tokens": 120,
                },
                trace_id=trace_id,
            ),
            FakeSpan(
                attributes={"gen_ai.operation.name": "execute_tool", "gen_ai.tool.name": "calc"},
                trace_id=trace_id,
            ),
        ]
        exporter.export(spans)
        exporter.shutdown()

        jsonl = self.tmp / f"{trace_id:032x}.jsonl"
        assert jsonl.exists()
        import json

        events = [json.loads(ln) for ln in jsonl.read_text().splitlines() if ln.strip()]
        result = verify(events)
        assert result.status == "INTACT", result.errors
        recorded = {e["event_type"] for e in events}
        # SESSION_START/END bracket the mapped GenAI events
        assert {
            "SESSION_START",
            "SESSION_END",
            "LLM_CALL",
            "LLM_RESPONSE",
            "TOOL_CALL",
            "TOOL_RESULT",
        } <= recorded

    def test_separate_traces_produce_separate_sessions(self):
        exporter = SasanaSpanExporter(output_dir=self.tmp)
        exporter.export([FakeSpan(attributes={"gen_ai.request.model": "m"}, trace_id=1)])
        exporter.export([FakeSpan(attributes={"gen_ai.request.model": "m"}, trace_id=2)])
        exporter.shutdown()
        assert (self.tmp / f"{1:032x}.jsonl").exists()
        assert (self.tmp / f"{2:032x}.jsonl").exists()


if __name__ == "__main__":
    unittest.main()
