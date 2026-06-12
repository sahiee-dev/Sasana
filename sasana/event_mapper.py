"""
event_mapper.py — Translate OpenClaw hook/WebSocket events into Sasana (event_type, payload) tuples.

Privacy guarantee: raw prompt/response/args/result content is NEVER stored.
Only SHA-256 hashes enter the audit chain.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any


def _sha256(value: Any) -> str:
    if isinstance(value, str):
        data = value.encode("utf-8")
    elif isinstance(value, (dict, list)):
        data = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    elif isinstance(value, bytes):
        data = value
    else:
        data = str(value).encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def map_session_start(oc_event: dict) -> tuple[str, dict]:
    payload = {
        "agent_id": oc_event.get("agentId") or oc_event.get("agent_id", "unknown"),
        "model_id": oc_event.get("model"),
        "tags": oc_event.get("tags", []),
        "agent_role": "autonomous" if oc_event.get("autonomy_mode") else "interactive",
    }
    payload = {k: v for k, v in payload.items() if v is not None}
    return "SESSION_START", payload


def map_session_end(oc_event: dict) -> tuple[str, dict]:
    status = oc_event.get("status", "success")
    if status not in ("success", "error"):
        status = "success"
    return "SESSION_END", {"status": status}


def map_llm_call(oc_event: dict) -> tuple[str, dict]:
    messages = oc_event.get("messages") or oc_event.get("prompt")
    payload: dict = {
        "prompt_hash": _sha256(messages) if messages is not None else _sha256(""),
        "model_id": oc_event.get("model", "unknown"),
    }
    if oc_event.get("tool_list"):
        payload["tool_count"] = len(oc_event["tool_list"])
    return "LLM_CALL", payload


def map_llm_response(oc_event: dict) -> tuple[str, dict]:
    content = oc_event.get("content") or oc_event.get("response")
    payload: dict = {
        "content_hash": _sha256(content) if content is not None else _sha256(""),
        "finish_reason": oc_event.get("finish_reason", "stop"),
    }
    if oc_event.get("usage"):
        usage = oc_event["usage"]
        payload["prompt_tokens"] = usage.get("prompt_tokens") or usage.get("input_tokens")
        payload["completion_tokens"] = usage.get("completion_tokens") or usage.get("output_tokens")
        payload = {k: v for k, v in payload.items() if v is not None}
    return "LLM_RESPONSE", payload


def map_tool_invoke(oc_event: dict) -> tuple[str, dict]:
    args = oc_event.get("args") or oc_event.get("arguments") or oc_event.get("input")
    return "TOOL_CALL", {
        "tool_name": oc_event.get("tool_name") or oc_event.get("name", "unknown"),
        "args_hash": _sha256(args) if args is not None else _sha256(""),
    }


def map_tool_result(oc_event: dict) -> tuple[str, dict]:
    result = oc_event.get("result") or oc_event.get("output")
    return "TOOL_RESULT", {
        "tool_name": oc_event.get("tool_name") or oc_event.get("name", "unknown"),
        "result_hash": _sha256(result) if result is not None else _sha256(""),
    }


def map_tool_error(oc_event: dict) -> tuple[str, dict]:
    msg = oc_event.get("error_message") or oc_event.get("error") or ""
    return "TOOL_ERROR", {
        "error_type": oc_event.get("error_type", "ToolError"),
        "error_message": str(msg)[:500],
    }


_WS_DISPATCH: dict[str, Any] = {
    "session.start":   map_session_start,
    "session.end":     map_session_end,
    "llm.call":        map_llm_call,
    "llm.response":    map_llm_response,
    "tool.invoke":     map_tool_invoke,
    "tool.result":     map_tool_result,
    "tool.error":      map_tool_error,
}

_GATEWAY_EVENT_MAP: dict[str, str] = {
    "gateway:startup":  "session.start",
    "gateway:shutdown": "session.end",
    "command:new":      "llm.call",
    "message:sent":     "llm.response",
}


def map_hook_event(hook_name: str, oc_event: dict) -> tuple[str, dict] | None:
    mapper = _WS_DISPATCH.get(hook_name)
    if mapper is None:
        return None
    return mapper(oc_event)


def map_websocket_event(ws_message: dict) -> tuple[str, dict] | None:
    raw_type: str = ws_message.get("type", "")
    hook_name = _GATEWAY_EVENT_MAP.get(raw_type)
    if hook_name:
        return map_hook_event(hook_name, ws_message)
    if raw_type in _WS_DISPATCH:
        return map_hook_event(raw_type, ws_message)
    return None
