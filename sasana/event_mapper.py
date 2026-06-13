"""
event_mapper.py — Translate OpenClaw hook/WebSocket events into Sasana (event_type, payload) tuples.

Privacy guarantee: raw prompt/response/args/result content is NEVER stored.
Only SHA-256 hashes enter the audit chain.
"""

from __future__ import annotations

from sasana._utils import content_hash


def map_session_start(oc_event: dict) -> tuple:
    payload = {
        "agent_id": oc_event.get("agentId") or oc_event.get("agent_id", "unknown"),
        "model_id": oc_event.get("model"),
        "tags": oc_event.get("tags", []),
        "agent_role": "autonomous" if oc_event.get("autonomy_mode") else "interactive",
    }
    return "SESSION_START", {k: v for k, v in payload.items() if v is not None}


def map_session_end(oc_event: dict) -> tuple:
    status = oc_event.get("status", "success")
    return "SESSION_END", {"status": status if status in ("success", "error") else "success"}


def map_llm_call(oc_event: dict) -> tuple:
    messages = oc_event.get("messages") or oc_event.get("prompt")
    payload: dict = {
        "prompt_hash": content_hash(messages) if messages is not None else content_hash(""),
        "model_id": oc_event.get("model", "unknown"),
    }
    if oc_event.get("tool_list"):
        payload["tool_count"] = len(oc_event["tool_list"])
    return "LLM_CALL", payload


def map_llm_response(oc_event: dict) -> tuple:
    content = oc_event.get("content") or oc_event.get("response")
    payload: dict = {
        "content_hash": content_hash(content) if content is not None else content_hash(""),
        "finish_reason": oc_event.get("finish_reason", "stop"),
    }
    if oc_event.get("usage"):
        u = oc_event["usage"]
        payload["prompt_tokens"] = u.get("prompt_tokens") or u.get("input_tokens")
        payload["completion_tokens"] = u.get("completion_tokens") or u.get("output_tokens")
        payload = {k: v for k, v in payload.items() if v is not None}
    return "LLM_RESPONSE", payload


def map_tool_invoke(oc_event: dict) -> tuple:
    args = oc_event.get("args") or oc_event.get("arguments") or oc_event.get("input")
    return "TOOL_CALL", {
        "tool_name": oc_event.get("tool_name") or oc_event.get("name", "unknown"),
        "args_hash": content_hash(args) if args is not None else content_hash(""),
    }


def map_tool_result(oc_event: dict) -> tuple:
    result = oc_event.get("result") or oc_event.get("output")
    return "TOOL_RESULT", {
        "tool_name": oc_event.get("tool_name") or oc_event.get("name", "unknown"),
        "result_hash": content_hash(result) if result is not None else content_hash(""),
    }


def map_tool_error(oc_event: dict) -> tuple:
    msg = oc_event.get("error_message") or oc_event.get("error") or ""
    return "TOOL_ERROR", {
        "error_type": oc_event.get("error_type", "ToolError"),
        "error_message": str(msg)[:500],
    }


_WS_DISPATCH: dict = {
    "session.start": map_session_start,
    "session.end": map_session_end,
    "llm.call": map_llm_call,
    "llm.response": map_llm_response,
    "tool.invoke": map_tool_invoke,
    "tool.result": map_tool_result,
    "tool.error": map_tool_error,
}

_GATEWAY_EVENT_MAP: dict = {
    "gateway:startup": "session.start",
    "gateway:shutdown": "session.end",
    "command:new": "llm.call",
    "message:sent": "llm.response",
}


def map_hook_event(hook_name: str, oc_event: dict) -> tuple | None:
    mapper = _WS_DISPATCH.get(hook_name)
    return mapper(oc_event) if mapper else None


def map_websocket_event(ws_message: dict) -> tuple | None:
    raw_type: str = ws_message.get("type", "")
    hook_name = _GATEWAY_EVENT_MAP.get(raw_type)
    if hook_name:
        return map_hook_event(hook_name, ws_message)
    return map_hook_event(raw_type, ws_message) if raw_type in _WS_DISPATCH else None
