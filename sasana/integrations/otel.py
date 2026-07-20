"""
sasana.integrations.otel — OpenTelemetry → Sasana span exporter.

Lets teams keep their existing tracing and get a tamper-evident evidence
ledger underneath. Point your OpenTelemetry tracer at SasanaSpanExporter and
every GenAI span (OTel GenAI semantic conventions) is mapped to hash-chained
Sasana events — LLM calls, tool calls, errors — while your normal exporter
(LangSmith, Langfuse, Datadog, an OTLP collector) keeps receiving the same
spans unchanged.

Only hashes are stored. Model names, tool names, and error messages are
recorded as SHA-256 digests; token counts are kept as numeric metadata.

Install:
    pip install "sasana[otel]"        # opentelemetry-sdk

Usage:
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor
    from sasana.integrations.otel import SasanaSpanExporter

    provider = TracerProvider()
    provider.add_span_processor(BatchSpanProcessor(SasanaSpanExporter()))
    # ... add your existing OTLP/other exporter alongside it ...

    # on shutdown, sessions are closed and exported:
    provider.shutdown()

    # Verify:
    #   sasana verify ~/.openclaw/sasana/<trace_id>.jsonl
    #   sasana evidence-pack ~/.openclaw/sasana/<trace_id>.jsonl --standard eu_ai_act

One Sasana session (ledger) is created per OpenTelemetry trace. Events are
recorded in arrival order; the hash chain proves integrity of the recorded
sequence regardless of span-export batching.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any, Optional

from sasana._utils import content_hash as _sha256
from sasana.sqlite_ledger import SqliteLedger

logger = logging.getLogger("sasana.integrations.otel")

try:
    from opentelemetry.sdk.trace.export import SpanExporter, SpanExportResult

    _OTEL_AVAILABLE = True
except ImportError:
    _OTEL_AVAILABLE = False

    class SpanExporter:  # type: ignore[no-redef]
        """Stub so the module imports without opentelemetry installed."""

    class SpanExportResult:  # type: ignore[no-redef]
        SUCCESS = "SUCCESS"
        FAILURE = "FAILURE"


_DEFAULT_OUTPUT_DIR = Path.home() / ".openclaw" / "sasana"

# OTel GenAI semantic-convention attribute keys (with legacy fallbacks).
_ATTR_OPERATION = "gen_ai.operation.name"
_ATTR_SYSTEM = "gen_ai.system"
_ATTR_REQUEST_MODEL = "gen_ai.request.model"
_ATTR_RESPONSE_MODEL = "gen_ai.response.model"
_ATTR_RESPONSE_ID = "gen_ai.response.id"
_ATTR_TOOL_NAME = "gen_ai.tool.name"
_ATTR_AGENT_NAME = "gen_ai.agent.name"
_ATTR_ERROR_TYPE = "error.type"
_TOOL_OPERATIONS = frozenset({"execute_tool", "invoke_tool", "tool"})
_LLM_OPERATIONS = frozenset(
    {"chat", "text_completion", "generate_content", "embeddings", "completion"}
)


def _get(attrs: dict, *keys: str) -> Any:
    for k in keys:
        if k in attrs and attrs[k] is not None:
            return attrs[k]
    return None


def _is_error(span: Any, attrs: dict) -> bool:
    if _ATTR_ERROR_TYPE in attrs:
        return True
    status = getattr(span, "status", None)
    code = getattr(status, "status_code", None)
    name = getattr(code, "name", None) or (str(code) if code is not None else "")
    return "ERROR" in name.upper()


def span_to_events(span: Any) -> list[tuple[str, dict]]:
    """
    Map one OpenTelemetry span to zero or more Sasana (event_type, payload) pairs.

    Pure function — works on any object exposing ``.attributes`` (a mapping),
    ``.name``, and optionally ``.status``. Non-GenAI spans map to no events.
    """
    attrs = dict(getattr(span, "attributes", None) or {})
    name = getattr(span, "name", "") or ""
    operation = _get(attrs, _ATTR_OPERATION) or ""
    tool_name = _get(attrs, _ATTR_TOOL_NAME)
    model = _get(attrs, _ATTR_REQUEST_MODEL, _ATTR_RESPONSE_MODEL)
    system = _get(attrs, _ATTR_SYSTEM)
    input_tokens = _get(attrs, "gen_ai.usage.input_tokens", "gen_ai.usage.prompt_tokens")
    output_tokens = _get(attrs, "gen_ai.usage.output_tokens", "gen_ai.usage.completion_tokens")
    is_error = _is_error(span, attrs)

    is_tool = (
        operation in _TOOL_OPERATIONS or tool_name is not None or name.startswith("execute_tool")
    )
    is_llm = operation in _LLM_OPERATIONS or (model is not None and not is_tool)

    events: list[tuple[str, dict]] = []

    if is_tool:
        call: dict = {"framework": "otel", "operation": operation or "execute_tool"}
        if tool_name is not None:
            call["tool_name_hash"] = _sha256(tool_name)
        if system is not None:
            call["system_hash"] = _sha256(system)
        events.append(("TOOL_CALL", call))
        if is_error:
            events.append(
                (
                    "TOOL_ERROR",
                    {
                        "framework": "otel",
                        "error_type": str(_get(attrs, _ATTR_ERROR_TYPE) or "ToolError"),
                        "error_hash": _sha256(name or operation or "tool_error"),
                    },
                )
            )
        else:
            events.append(("TOOL_RESULT", {"framework": "otel", "status": "ok"}))
        return events

    if is_llm:
        call = {"framework": "otel", "operation": operation or "chat"}
        if model is not None:
            call["model_hash"] = _sha256(model)
        if system is not None:
            call["system_hash"] = _sha256(system)
        if isinstance(input_tokens, (int, float)):
            call["prompt_tokens"] = int(input_tokens)
        events.append(("LLM_CALL", call))
        if is_error:
            events.append(
                (
                    "TOOL_ERROR",
                    {
                        "framework": "otel",
                        "error_type": str(_get(attrs, _ATTR_ERROR_TYPE) or "LLMError"),
                        "error_hash": _sha256(name or operation or "llm_error"),
                    },
                )
            )
        else:
            resp: dict = {
                "framework": "otel",
                "response_hash": _sha256(
                    str(_get(attrs, _ATTR_RESPONSE_ID) or model or operation or name)
                ),
            }
            if isinstance(output_tokens, (int, float)):
                resp["completion_tokens"] = int(output_tokens)
            events.append(("LLM_RESPONSE", resp))
        return events

    return events


def _trace_id_hex(span: Any) -> str:
    ctx = getattr(span, "context", None) or getattr(span, "get_span_context", lambda: None)()
    trace_id = getattr(ctx, "trace_id", None)
    if isinstance(trace_id, int):
        return format(trace_id, "032x")
    return str(trace_id) if trace_id else "otel-session"


def _agent_id_for(span: Any) -> str:
    attrs = dict(getattr(span, "attributes", None) or {})
    return str(_get(attrs, _ATTR_AGENT_NAME, _ATTR_SYSTEM) or "otel")


class SasanaSpanExporter(SpanExporter):  # type: ignore[misc]
    """
    An OpenTelemetry SpanExporter that writes GenAI spans to tamper-evident
    Sasana ledgers, one session per trace.

    Parameters
    ----------
    output_dir : str | Path | None
        Directory for .db / .jsonl files. Default ~/.openclaw/sasana/
        (override with SASANA_OUTPUT_DIR).
    agent_id : str | None
        Force a fixed agent id for all sessions. Default: inferred per span
        from gen_ai.agent.name / gen_ai.system.
    """

    def __init__(
        self,
        *,
        output_dir: Optional[str | Path] = None,
        agent_id: Optional[str] = None,
    ) -> None:
        if not _OTEL_AVAILABLE:
            raise ImportError(
                "SasanaSpanExporter requires opentelemetry-sdk. "
                'Install with: pip install "sasana[otel]"'
            )
        self._output_dir = Path(
            output_dir or os.environ.get("SASANA_OUTPUT_DIR", str(_DEFAULT_OUTPUT_DIR))
        ).expanduser()
        self._agent_id = agent_id
        self._ledgers: dict[str, SqliteLedger] = {}

    def _ledger_for(self, trace_id: str, span: Any) -> SqliteLedger:
        ledger = self._ledgers.get(trace_id)
        if ledger is None:
            self._output_dir.mkdir(parents=True, exist_ok=True)
            ledger = SqliteLedger(db_path=self._output_dir / f"{trace_id}.db")
            agent_id = self._agent_id or _agent_id_for(span)
            ledger.open_session(trace_id, agent_id=agent_id, metadata={"source": "opentelemetry"})
            self._ledgers[trace_id] = ledger
        return ledger

    def export(self, spans: Any) -> Any:
        try:
            for span in spans:
                events = span_to_events(span)
                if not events:
                    continue
                ledger = self._ledger_for(_trace_id_hex(span), span)
                for event_type, payload in events:
                    ledger.record(event_type, payload)
            return SpanExportResult.SUCCESS
        except Exception as exc:  # fail-open; never break the host tracer
            logger.warning("Sasana OTel export error (ignored): %s", exc)
            return SpanExportResult.FAILURE

    def force_flush(self, timeout_millis: int = 30000) -> bool:
        return True

    def shutdown(self) -> None:
        for trace_id, ledger in list(self._ledgers.items()):
            try:
                ledger.close_session(status="success")
                ledger.export_jsonl(self._output_dir / f"{trace_id}.jsonl")
            except Exception as exc:
                logger.warning("Sasana OTel shutdown error for %s: %s", trace_id, exc)
            finally:
                try:
                    ledger.close()
                except Exception:
                    pass
        self._ledgers.clear()
