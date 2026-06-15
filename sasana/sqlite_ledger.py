"""
sqlite_ledger.py — SHA-256 hash-chained SQLite ledger for Sasana sessions.

WAL mode + synchronous=FULL: crash-safe, no data loss.
One .db file per session; events committed one by one immediately.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
from pathlib import Path
from typing import Any

from sasana.envelope import build_event, GENESIS_HASH
from sasana.events import EventType

logger = logging.getLogger("sasana.sqlite_ledger")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    seq          INTEGER NOT NULL,
    session_id   TEXT    NOT NULL,
    event_type   TEXT    NOT NULL,
    timestamp    TEXT    NOT NULL,
    prev_hash    TEXT    NOT NULL,
    event_hash   TEXT    NOT NULL,
    payload_json TEXT    NOT NULL,
    signature    TEXT,
    raw_json     TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_session_seq ON events (session_id, seq);
"""


class SqliteLedger:
    """SHA-256 hash-chained SQLite ledger. Thread-safe. One instance per session."""

    def __init__(self, db_path: str | Path, private_key: Any = None) -> None:
        self._db_path = Path(db_path).expanduser()
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._private_key = private_key
        self._session_id: str | None = None
        self._next_seq = 1
        self._last_hash = GENESIS_HASH
        self._lock = threading.Lock()
        self._conn: sqlite3.Connection | None = None

    def connect(self) -> None:
        conn = sqlite3.connect(str(self._db_path), check_same_thread=False)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=FULL")
        conn.executescript(_SCHEMA)
        conn.commit()
        self._conn = conn

    def close(self) -> None:
        if self._conn:
            try:
                self._conn.close()
            except Exception:
                pass
            self._conn = None

    def __enter__(self) -> "SqliteLedger":
        self.connect()
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()

    def open_session(
        self, session_id: str, agent_id: str | None = None, metadata: dict | None = None
    ) -> None:
        if self._conn is None:
            self.connect()
        self._session_id = session_id
        self._next_seq = 1
        self._last_hash = GENESIS_HASH
        payload: dict = {"agent_id": agent_id or session_id}
        if metadata:
            payload.update(metadata)
        if self._private_key is not None:
            from sasana.signing import pubkey_from_private

            payload["session_pubkey"] = pubkey_from_private(self._private_key)
        self.__write_event("SESSION_START", payload)

    def close_session(self, status: str = "success") -> None:
        self.__write_event(
            "SESSION_END", {"status": status if status in ("success", "error") else "success"}
        )

    def record(self, event_type: str, payload: dict) -> None:
        """Append one event. Silently drops server-authority events."""
        try:
            if not EventType(event_type).is_sdk_authority:
                return
        except ValueError:
            return
        self.__write_event(event_type, payload)

    def export_jsonl(self, output_path: str | Path) -> Path:
        if self._conn is None or self._session_id is None:
            raise RuntimeError("Ledger not ready")
        out = Path(output_path).expanduser()
        out.parent.mkdir(parents=True, exist_ok=True)
        cursor = self._conn.execute(
            "SELECT raw_json FROM events WHERE session_id = ? ORDER BY seq ASC",
            (self._session_id,),
        )
        with open(out, "w") as f:
            for (raw_json,) in cursor:
                f.write(raw_json + "\n")
        return out

    @property
    def session_id(self) -> str | None:
        return self._session_id

    def __write_event(self, event_type: str, payload: dict) -> None:
        if self._conn is None:
            self.connect()
        with self._lock:
            try:
                event = build_event(
                    seq=self._next_seq,
                    event_type=event_type,
                    session_id=self._session_id or "unknown",
                    payload=payload,
                    prev_hash=self._last_hash,
                    private_key=self._private_key,
                )
                self._conn.execute(
                    """INSERT INTO events (seq, session_id, event_type, timestamp, prev_hash,
                       event_hash, payload_json, signature, raw_json)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        event["seq"],
                        event["session_id"],
                        event["event_type"],
                        event["timestamp"],
                        event["prev_hash"],
                        event["event_hash"],
                        json.dumps(event.get("payload", {})),
                        event.get("signature"),
                        json.dumps(event),
                    ),
                )
                self._conn.commit()
                self._next_seq += 1
                self._last_hash = event["event_hash"]
            except Exception as exc:
                logger.error("Sasana: failed to write %s: %s", event_type, exc)
