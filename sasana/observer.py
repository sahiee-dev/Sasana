"""
observer.py — Passive WebSocket sidecar for Sasana.

Zero modifications to OpenClaw required. Auto-reconnects up to 12 times.
Use SasanaSkill when possible — it receives richer hook events.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import uuid
from pathlib import Path

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
    ) -> None:
        self._ws_url = ws_url or _load_openclaw_ws_url()
        self._output_dir = Path(output_dir or _DEFAULT_OUTPUT_DIR).expanduser()
        self._output_dir.mkdir(parents=True, exist_ok=True)
        self._server_url = server_url  # reserved for future server-assisted verification
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
                logger.warning(
                    "Sasana observer: disconnected (%s). Retry %d/%d in %ds",
                    exc,
                    attempts,
                    _MAX_RECONNECT_ATTEMPTS,
                    _RECONNECT_DELAY_SECS,
                )
                if self._running:
                    await asyncio.sleep(_RECONNECT_DELAY_SECS)

    def stop(self) -> None:
        self._running = False

    async def _connect_and_consume(self, url: str) -> None:
        try:
            import websockets
        except ImportError:
            raise ImportError("pip install sasana[observer]")
        async with websockets.connect(url) as ws:
            async for raw in ws:
                if not self._running:
                    break
                await self._handle_raw(raw)

    async def _handle_raw(self, raw: str | bytes) -> None:
        try:
            msg: dict = json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            return
        result = map_websocket_event(msg)
        if result is None:
            return
        event_type, payload = result
        sk: str = msg.get("sessionKey") or msg.get("session_key") or "default"
        if event_type == "SESSION_START":
            ledger = self._get_or_create_ledger(sk)
            ledger.open_session(
                session_id=ledger.session_id or str(uuid.uuid4()),
                agent_id=payload.pop("agent_id", None),
                metadata=payload or None,
            )
        elif event_type == "SESSION_END":
            ledger = self._ledgers.get(sk)
            if ledger:
                ledger.close_session(status=payload.get("status", "success"))
                self._flush_and_remove(sk)
        else:
            ledger = self._ledgers.get(sk)
            if ledger is None:
                ledger = self._get_or_create_ledger(sk)
                ledger.open_session(session_id=str(uuid.uuid4()), metadata={"implicit": True})
            ledger.record(event_type, payload)

    def _get_or_create_ledger(self, sk: str) -> SqliteLedger:
        if sk not in self._ledgers:
            sid = str(uuid.uuid4())
            ledger = SqliteLedger(db_path=self._output_dir / f"{sid}.db")
            ledger.connect()
            ledger._session_id = sid
            self._ledgers[sk] = ledger
        return self._ledgers[sk]

    def _flush_and_remove(self, sk: str) -> None:
        ledger = self._ledgers.pop(sk, None)
        if ledger is None:
            return
        try:
            sid = ledger.session_id or sk.replace("/", "_")
            ledger.export_jsonl(self._output_dir / f"{sid}.jsonl")
            ledger.close()
        except Exception as exc:
            logger.error("Sasana: flush failed for %s: %s", sk, exc)
