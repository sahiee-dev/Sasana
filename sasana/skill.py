"""
skill.py — SasanaSkill: OpenClaw AgentSkill implementation.

Installed via:
    openclaw skill install sasana

Every OpenClaw session produces:
    ~/.openclaw/sasana/<session_id>.db    — SHA-256 hash-chained SQLite ledger
    ~/.openclaw/sasana/<session_id>.jsonl — JSONL export for verification

Verify with:
    sasana verify ~/.openclaw/sasana/<session_id>.jsonl
"""

from __future__ import annotations

import logging
import os
import threading
import uuid
from pathlib import Path

from sasana.event_mapper import map_hook_event, map_session_start
from sasana.sqlite_ledger import SqliteLedger

logger = logging.getLogger("sasana.skill")

_DEFAULT_OUTPUT_DIR = Path.home() / ".openclaw" / "sasana"


class SasanaSkill:
    """
    OpenClaw AgentSkill — instruments sessions with a SHA-256 hash-chained SQLite ledger.

    Config (via sasanamanifest.json or environment variables):
        SASANA_OUTPUT_DIR  — directory for .db and .jsonl files (default: ~/.openclaw/sasana/)
        SASANA_SERVER_URL  — optional ingestion server URL (enables AUTHORITATIVE_EVIDENCE)
    """

    name = "sasana"
    version = "1.0.0"

    def __init__(self, config: dict | None = None) -> None:
        cfg = config or {}
        self._output_dir = Path(
            cfg.get("output_dir")
            or os.environ.get("SASANA_OUTPUT_DIR", str(_DEFAULT_OUTPUT_DIR))
        ).expanduser()
        self._output_dir.mkdir(parents=True, exist_ok=True)
        self._ledgers: dict[str, SqliteLedger] = {}
        self._lock = threading.Lock()

    def _get_or_create_ledger(self, session_key: str, session_id: str | None = None) -> SqliteLedger:
        with self._lock:
            if session_key not in self._ledgers:
                sid = session_id or str(uuid.uuid4())
                db_path = self._output_dir / f"{sid}.db"
                ledger = SqliteLedger(db_path=db_path)
                ledger.connect()
                ledger._session_id = sid
                self._ledgers[session_key] = ledger
            return self._ledgers[session_key]

    def _close_and_export(self, session_key: str) -> None:
        with self._lock:
            ledger = self._ledgers.pop(session_key, None)
        if ledger is None:
            return
        try:
            sid = ledger.session_id or session_key.replace("/", "_")
            jsonl_path = self._output_dir / f"{sid}.jsonl"
            ledger.export_jsonl(jsonl_path)
            ledger.close()
            logger.info("Sasana: session %s → %s", session_key, jsonl_path)
        except Exception as exc:
            logger.error("Sasana: export failed for %s: %s", session_key, exc)
            try:
                ledger.close()
            except Exception:
                pass

    def _record(self, oc_event: dict, hook_name: str) -> None:
        try:
            session_key = oc_event.get("sessionKey") or oc_event.get("session_key", "default")
            result = map_hook_event(hook_name, oc_event)
            if result is None:
                return
            event_type, payload = result
            ledger = self._ledgers.get(session_key)
            if ledger is None:
                ledger = self._get_or_create_ledger(session_key)
                ledger.open_session(
                    session_id=ledger.session_id or str(uuid.uuid4()),
                    metadata={"implicit": True},
                )
            ledger.record(event_type, payload)
        except Exception as exc:
            logger.debug("Sasana: _record error (%s): %s", hook_name, exc)

    def on_session_start(self, oc_event: dict) -> None:
        try:
            session_key = oc_event.get("sessionKey") or oc_event.get("session_key", "default")
            agent_id = oc_event.get("agentId") or oc_event.get("agent_id")
            session_id = str(uuid.uuid4())
            ledger = self._get_or_create_ledger(session_key, session_id=session_id)
            _, metadata = map_session_start(oc_event)
            ledger.open_session(session_id=session_id, agent_id=agent_id, metadata=metadata)
        except Exception as exc:
            logger.debug("Sasana: on_session_start error: %s", exc)

    def on_session_end(self, oc_event: dict) -> None:
        session_key = oc_event.get("sessionKey") or oc_event.get("session_key", "default")
        try:
            status = oc_event.get("status", "success")
            ledger = self._ledgers.get(session_key)
            if ledger:
                ledger.close_session(status=status)
        except Exception as exc:
            logger.debug("Sasana: on_session_end error: %s", exc)
        finally:
            self._close_and_export(session_key)

    def on_llm_call(self, oc_event: dict) -> None:
        self._record(oc_event, "llm.call")

    def on_llm_response(self, oc_event: dict) -> None:
        self._record(oc_event, "llm.response")

    def on_tool_invoke(self, oc_event: dict) -> None:
        self._record(oc_event, "tool.invoke")

    def on_tool_result(self, oc_event: dict) -> None:
        self._record(oc_event, "tool.result")

    def on_tool_error(self, oc_event: dict) -> None:
        self._record(oc_event, "tool.error")
