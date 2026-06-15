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
        # self._last_hash is now the SESSION_START event_hash (pre-token).
        # Attempt RFC 3161 anchoring — fail-open, never blocks session recording.
        self._try_anchor_rfc3161(bytes.fromhex(self._last_hash))

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

    def _try_anchor_rfc3161(self, pre_token_hash: bytes) -> None:
        """Request a RFC 3161 timestamp and embed it in SESSION_START. Fail-open."""
        try:
            from sasana.rfc3161 import request_timestamp

            token_der = request_timestamp(pre_token_hash)
            if token_der is None:
                return
            self._embed_rfc3161_token(token_der)
        except Exception as exc:
            logger.warning("Sasana: RFC 3161 anchoring skipped: %s", exc)

    def _embed_rfc3161_token(self, token_der: bytes) -> None:
        """
        Embed a TSA token in the SESSION_START row, recompute event_hash, update DB.

        Two-pass design: SESSION_START was already written without the token so its
        hash could be submitted to the TSA. Here we add the token to the stored
        payload, recompute event_hash over the full payload (including the token),
        update the DB row, and advance self._last_hash so the rest of the chain
        chains correctly from the new hash.
        """
        import base64 as _b64
        import hashlib as _hashlib
        import json as _json

        from sasana.jcs import canonicalize as _jcs

        if self._conn is None or self._session_id is None:
            return

        with self._lock:
            try:
                cursor = self._conn.execute(
                    "SELECT raw_json FROM events WHERE session_id = ? AND seq = 1",
                    (self._session_id,),
                )
                row = cursor.fetchone()
                if row is None:
                    return

                event = _json.loads(row[0])
                event["payload"]["rfc3161_token"] = _b64.b64encode(token_der).decode()

                # Recompute event_hash — strips event_hash and signature per envelope convention
                event_for_hash = {
                    k: v for k, v in event.items() if k not in ("event_hash", "signature")
                }
                new_hash = _hashlib.sha256(_jcs(event_for_hash)).hexdigest()
                event["event_hash"] = new_hash

                # Recompute signature if private key is set
                if self._private_key is not None:
                    try:
                        from sasana.signing import sign_event_hash

                        event["signature"] = sign_event_hash(self._private_key, new_hash)
                    except Exception as exc:
                        logger.debug("Sasana: RFC 3161 re-sign failed: %s", exc)

                new_raw_json = _json.dumps(event)
                new_payload_json = _json.dumps(event["payload"])

                self._conn.execute(
                    "UPDATE events SET payload_json = ?, event_hash = ?, raw_json = ? "
                    "WHERE session_id = ? AND seq = 1",
                    (new_payload_json, new_hash, new_raw_json, self._session_id),
                )
                self._conn.commit()
                self._last_hash = new_hash
                logger.info(
                    "Sasana: RFC 3161 token embedded in SESSION_START (session=%s)",
                    self._session_id,
                )
            except Exception as exc:
                logger.warning("Sasana: RFC 3161 token embedding failed: %s", exc)

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
