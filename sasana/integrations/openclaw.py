"""
sasana.integrations.openclaw — Real OpenClaw plugin bridge.

Receives forwarded lifecycle events from the sasana-openclaw TypeScript
plugin (openclaw-plugin/sasana-openclaw/) over a local Unix domain socket
and records them into the Sasana ledger.

Real OpenClaw plugin hook names (OpenClaw v2026.6.6, Plugin SDK
`api.on(...)`, confirmed against a live gateway instance): session_start,
session_end, before_tool_call, after_tool_call, model_call_started,
model_call_ended, llm_input, llm_output. These are typed, in-process
TypeScript plugin hooks — a different surface from the `command:new` /
`gateway:startup` style internal file-based hooks that sasana.observer's
_GATEWAY_EVENT_MAP was written against, and from the on_llm_call /
on_tool_invoke method names sasana.skill.SasanaSkill assumes. Neither of
those matches how real OpenClaw loads plugins (TypeScript, api.on(...),
definePluginEntry) — there is no Python-class-based skill-loading path.

Privacy guarantee: raw prompt/response/args/result content is NEVER stored.
Only SHA-256 hashes enter the audit chain.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import uuid
from pathlib import Path
from typing import Any

from sasana._utils import content_hash
from sasana.sqlite_ledger import SqliteLedger

logger = logging.getLogger("sasana.integrations.openclaw")

_DEFAULT_OUTPUT_DIR = Path.home() / ".openclaw" / "sasana"
_DEFAULT_SOCKET_PATH = Path.home() / ".openclaw" / "sasana" / "bridge.sock"


def _first(event: dict, *keys: str) -> Any:
    for k in keys:
        v = event.get(k)
        if v is not None:
            return v
    return None


def map_bridge_event(event: dict) -> tuple[str, dict] | None:
    """
    Map one forwarded OpenClaw plugin-hook event to a (event_type, payload)
    tuple in Sasana's taxonomy, or None if the hook is unrecognized.

    `source` is stamped on every payload so it stays traceable which real
    OpenClaw hook produced the entry — llm_input/model_call_started both map
    to LLM_CALL, and model_call_ended/llm_output both map to LLM_RESPONSE,
    since real OpenClaw splits call setup and provider telemetry across two
    hooks where Sasana's event taxonomy has one.
    """
    hook = event.get("hook")

    if hook == "session_start":
        payload = {"reason": event.get("reason", "unknown"), "agent_id": event.get("agentId")}
        return "SESSION_START", {k: v for k, v in payload.items() if v is not None}

    if hook == "session_end":
        return "SESSION_END", {"status": "success", "reason": event.get("reason", "unknown")}

    if hook == "llm_input":
        content = _first(event, "prompt", "systemPrompt", "messages")
        return "LLM_CALL", {
            "prompt_hash": content_hash(content) if content is not None else content_hash(""),
            "source": "llm_input",
        }

    if hook == "model_call_started":
        payload = {
            "model_id": event.get("model", "unknown"),
            "provider": event.get("provider"),
            "run_id": event.get("runId"),
            "source": "model_call_started",
        }
        return "LLM_CALL", {k: v for k, v in payload.items() if v is not None}

    if hook == "model_call_ended":
        payload = {
            "outcome": event.get("outcome", "unknown"),
            "duration_ms": event.get("durationMs"),
            "source": "model_call_ended",
        }
        return "LLM_RESPONSE", {k: v for k, v in payload.items() if v is not None}

    if hook == "llm_output":
        content = _first(event, "output", "content")
        payload: dict = {
            "content_hash": content_hash(content) if content is not None else content_hash(""),
            "source": "llm_output",
        }
        usage = event.get("usage")
        if usage:
            payload["prompt_tokens"] = usage.get("prompt_tokens") or usage.get("input_tokens")
            payload["completion_tokens"] = usage.get("completion_tokens") or usage.get(
                "output_tokens"
            )
        return "LLM_RESPONSE", {k: v for k, v in payload.items() if v is not None}

    if hook == "before_tool_call":
        args = _first(event, "params", "args")
        return "TOOL_CALL", {
            "tool_name": event.get("toolName", "unknown"),
            "args_hash": content_hash(args) if args is not None else content_hash(""),
            "source": "before_tool_call",
        }

    if hook == "after_tool_call":
        if event.get("error"):
            return "TOOL_ERROR", {
                "tool_name": event.get("toolName", "unknown"),
                "error_type": "ToolError",
                "error_message": str(event.get("error"))[:500],
                "source": "after_tool_call",
            }
        result = _first(event, "result", "output")
        return "TOOL_RESULT", {
            "tool_name": event.get("toolName", "unknown"),
            "result_hash": content_hash(result) if result is not None else content_hash(""),
            "source": "after_tool_call",
        }

    return None


class OpenClawBridgeServer:
    """
    Unix-socket server that receives forwarded lifecycle events from the
    sasana-openclaw plugin and records them to per-session SqliteLedgers.

    One ledger per OpenClaw sessionKey, matching SasanaSkill's model.
    """

    def __init__(
        self,
        socket_path: str | Path | None = None,
        output_dir: str | Path | None = None,
    ) -> None:
        self._socket_path = Path(
            socket_path or os.environ.get("SASANA_BRIDGE_SOCKET", str(_DEFAULT_SOCKET_PATH))
        ).expanduser()
        self._output_dir = Path(
            output_dir or os.environ.get("SASANA_OUTPUT_DIR", str(_DEFAULT_OUTPUT_DIR))
        ).expanduser()
        self._output_dir.mkdir(parents=True, exist_ok=True)
        self._ledgers: dict[str, SqliteLedger] = {}

    def _get_or_create_ledger(self, session_key: str) -> SqliteLedger:
        ledger = self._ledgers.get(session_key)
        if ledger is None:
            sid = str(uuid.uuid4())
            ledger = SqliteLedger(db_path=self._output_dir / f"{sid}.db")
            ledger.connect()
            ledger._session_id = sid
            self._ledgers[session_key] = ledger
        return ledger

    def _close_and_export(self, session_key: str) -> Path | None:
        ledger = self._ledgers.pop(session_key, None)
        if ledger is None:
            return None
        try:
            sid = ledger.session_id or session_key.replace("/", "_")
            path = ledger.export_jsonl(self._output_dir / f"{sid}.jsonl")
            return path
        finally:
            ledger.close()

    def handle_event(self, event: dict) -> None:
        mapped = map_bridge_event(event)
        if mapped is None:
            logger.debug("Sasana bridge: unrecognized hook %r, skipped", event.get("hook"))
            return
        event_type, payload = mapped
        session_key = event.get("sessionKey") or "default"

        if event_type == "SESSION_START":
            ledger = self._get_or_create_ledger(session_key)
            ledger.open_session(
                session_id=ledger.session_id,
                agent_id=event.get("agentId"),
                metadata=payload,
            )
            return

        ledger = self._ledgers.get(session_key)
        if ledger is None:
            ledger = self._get_or_create_ledger(session_key)
            ledger.open_session(session_id=ledger.session_id, metadata={"implicit": True})

        if event_type == "SESSION_END":
            ledger.close_session(status=payload.get("status", "success"))
            self._close_and_export(session_key)
            return

        ledger.record(event_type, payload)

    async def _handle_conn(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        buf = b""
        try:
            while True:
                chunk = await reader.read(65536)
                if not chunk:
                    break
                buf += chunk
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    if not line.strip():
                        continue
                    try:
                        event = json.loads(line)
                    except json.JSONDecodeError as exc:
                        logger.debug("Sasana bridge: bad JSON line (%s)", exc)
                        continue
                    try:
                        self.handle_event(event)
                    except Exception as exc:
                        logger.error("Sasana bridge: error handling event: %s", exc)
        finally:
            writer.close()

    async def serve_forever(self) -> None:
        self._socket_path.parent.mkdir(parents=True, exist_ok=True)
        if self._socket_path.exists():
            self._socket_path.unlink()
        server = await asyncio.start_unix_server(self._handle_conn, path=str(self._socket_path))
        logger.info("Sasana OpenClaw bridge listening on %s", self._socket_path)
        async with server:
            await server.serve_forever()

    def close_all(self) -> None:
        for key in list(self._ledgers.keys()):
            self._close_and_export(key)
        if self._socket_path.exists():
            self._socket_path.unlink()


def run(socket_path: str | None = None, output_dir: str | None = None) -> None:
    """Entry point for `sasana bridge` CLI command."""
    server = OpenClawBridgeServer(socket_path=socket_path, output_dir=output_dir)
    try:
        asyncio.run(server.serve_forever())
    except KeyboardInterrupt:
        pass
    finally:
        server.close_all()
