"""
observer.py — OpenClawObserver: passive WebSocket sidecar for Sasana.

Connects to the OpenClaw Gateway WebSocket without modifying OpenClaw.
Use SasanaSkill (skill.py) when possible — it receives semantically richer events.
Use the observer when you cannot install the skill or need non-intrusive deployment.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import signal
import uuid
from pathlib import Path
from typing import Any

from sasana.event_mapper import map_websocket_event
from sasana.sqlite_ledger import SqliteLedger

logger = logging.getLogger("sasana.observer")

_DEFAULT_WS_URL = "ws://localhost:3517/ws"
_DEFAULT_OUTPUT_DIR = Path.home() / ".openclaw" / "sasana"
_RECONNECT_DELAY_SECS = 5
_MAX_RECONNECT_ATTEMPTS = 12


def _load_openclaw_ws_url() -> str:
    config_path = Path.home() / ".openclaw" / "config.yml"
    if config_path.exists():
        try:
            import yaml
            with open(config_path) as f:
                cfg = yaml.safe_load(f) or {}
            port = cfg.get("gateway", {}).get("port") or cfg.get("port", 3517)
            host = cfg.get("gateway", {}).get("host", "localhost")
            return f"ws://{host}:{port}/ws"
        except Exception:
            pass
    return os.environ.get("OPENCLAW_WS_URL", _DEFAULT_WS_URL)


class OpenClawObserver:
    """Passive WebSocket observer. One SqliteLedger per active OpenClaw session."""

    def __init__(
        self,
        ws_url: str | None = None,
        output_dir: Path | str | None = None,
        server_url: str | None = None,
        buffer_size: int = 1000,
    ) -> None:
        self._ws_url = ws_url or _load_openclaw_ws_url()
        self._output_dir = Path(output_dir or _DEFAULT_OUTPUT_DIR).expanduser()
        self._output_dir.mkdir(parents=True, exist_ok=True)
        self._ledgers: dict[str, SqliteLedger] = {}
        self._running = False

    async def run(self, ws_url: str | None = None) -> None:
        url = ws_url or self._ws_url
        self._running = True
        attempts = 0
        while self._running and attempts < _MAX_RECONNECT_ATTEMPTS:
            try:
                await self._connect_and_consume(url)
                attempts = 0
            except Exception as exc:
                attempts += 1
                logger.warning("Sasana observer: disconnected (%s). Retry %d/%d in %ds",
                    exc, attempts, _MAX_RECONNECT_ATTEMPTS, _RECONNECT_DELAY_SECS)
                if self._running:
                    await asyncio.sleep(_RECONNECT_DELAY_SECS)
        if attempts >= _MAX_RECONNECT_ATTEMPTS:
            logger.error("Sasana observer: max reconnect attempts reached.")

    def stop(self) -> None:
        self._running = False

    async def _connect_and_consume(self, url: str) -> None:
        try:
            import websockets
        except ImportError:
            raise ImportError("websockets package required: pip install websockets")
        async with websockets.connect(url) as ws:
            async for raw_message in ws:
                if not self._running:
                    break
                await self._handle_raw(raw_message)

    async def _handle_raw(self, raw: str | bytes) -> None:
        try:
            msg: dict = json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            return
        result = map_websocket_event(msg)
        if result is None:
            return
        event_type, payload = result
        session_key: str = msg.get("sessionKey") or msg.get("session_key") or "default"
        if event_type == "SESSION_START":
            ledger = self._get_or_create_ledger(session_key)
            agent_id = payload.pop("agent_id", None)
            ledger.open_session(session_id=ledger.session_id or str(uuid.uuid4()),
                agent_id=agent_id, metadata=payload or None)
        elif event_type == "SESSION_END":
            ledger = self._ledgers.get(session_key)
            if ledger:
                ledger.close_session(status=payload.get("status", "success"))
                self._flush_and_remove(session_key)
        else:
            ledger = self._ledgers.get(session_key)
            if ledger is None:
                ledger = self._get_or_create_ledger(session_key)
                ledger.open_session(session_id=str(uuid.uuid4()), metadata={"implicit": True})
            ledger.record(event_type, payload)

    def _get_or_create_ledger(self, session_key: str) -> SqliteLedger:
        if session_key not in self._ledgers:
            sid = str(uuid.uuid4())
            ledger = SqliteLedger(db_path=self._output_dir / f"{sid}.db")
            ledger.connect()
            ledger._session_id = sid
            self._ledgers[session_key] = ledger
        return self._ledgers[session_key]

    def _flush_and_remove(self, session_key: str) -> None:
        ledger = self._ledgers.pop(session_key, None)
        if ledger is None:
            return
        try:
            sid = ledger.session_id or session_key.replace("/", "_")
            out_path = self._output_dir / f"{sid}.jsonl"
            ledger.export_jsonl(out_path)
            ledger.close()
        except Exception as exc:
            logger.error("Sasana: flush failed for %s: %s", session_key, exc)
