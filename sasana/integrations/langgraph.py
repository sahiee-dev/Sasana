"""
sasana.integrations.langgraph — TamperEvidentCheckpointSaver for LangGraph.

Every checkpoint write (= one node completion in the graph) is appended to a
SHA-256 hash-chained Sasana ledger.  Raw state values are never stored —
only hashes.

Install:
    pip install langgraph

Usage:
    from sasana.integrations.langgraph import TamperEvidentCheckpointSaver
    from langgraph.checkpoint.memory import MemorySaver

    inner  = MemorySaver()
    saver  = TamperEvidentCheckpointSaver(inner)

    graph  = my_graph.compile(checkpointer=saver)

    async with saver:                             # emits SESSION_START / SESSION_END
        result = await graph.ainvoke(inputs, config={"configurable": {"thread_id": "t1"}})

    # Verify:
    #   sasana verify ~/.openclaw/sasana/<session_id>.jsonl
"""

from __future__ import annotations

import hashlib
import logging
import os
import threading
import uuid
from pathlib import Path
from typing import Any, Iterator, Optional

logger = logging.getLogger("sasana.integrations.langgraph")

try:
    from langgraph.checkpoint.base import BaseCheckpointSaver
    _LANGGRAPH_AVAILABLE = True
except ImportError:
    _LANGGRAPH_AVAILABLE = False
    BaseCheckpointSaver = object  # type: ignore[assignment,misc]

from sasana.sqlite_ledger import SqliteLedger

_DEFAULT_OUTPUT_DIR = Path.home() / ".openclaw" / "sasana"


def _sha256(value: Any) -> str:
    return hashlib.sha256(str(value).encode()).hexdigest()


def _mk_ledger(session_id: str, output_dir: Path) -> SqliteLedger:
    output_dir.mkdir(parents=True, exist_ok=True)
    ledger = SqliteLedger(db_path=output_dir / f"{session_id}.db")
    return ledger


class TamperEvidentCheckpointSaver(BaseCheckpointSaver):  # type: ignore[misc]
    """
    Wraps any LangGraph BaseCheckpointSaver and appends one Sasana audit event
    per checkpoint write.

    Parameters
    ----------
    inner : BaseCheckpointSaver | None
        The real checkpoint storage backend (MemorySaver, SqliteSaver, etc.).
        If None, checkpoints are audited only (not persisted).
    output_dir : str | Path | None
        Directory for .db and .jsonl files.  Default: ~/.openclaw/sasana/
        Override with SASANA_OUTPUT_DIR env var.
    session_id : str | None
        Explicit session ID.  Default: auto-generated UUID.
    """

    def __init__(
        self,
        inner: Optional[Any] = None,
        *,
        output_dir: Optional[str | Path] = None,
        session_id: Optional[str] = None,
    ) -> None:
        if not _LANGGRAPH_AVAILABLE:
            raise ImportError("langgraph is required: pip install langgraph")
        super().__init__()
        self._inner = inner
        self._output_dir = Path(
            output_dir or os.environ.get("SASANA_OUTPUT_DIR", str(_DEFAULT_OUTPUT_DIR))
        ).expanduser()
        self._session_id = session_id or str(uuid.uuid4())
        self._ledger: Optional[SqliteLedger] = None
        self._lock = threading.Lock()
        self._started = False

    # ------------------------------------------------------------------ #
    # Session lifecycle                                                    #
    # ------------------------------------------------------------------ #

    def _ensure_started(self, thread_id: str) -> SqliteLedger:
        with self._lock:
            if self._ledger is None:
                self._ledger = _mk_ledger(self._session_id, self._output_dir)
            if not self._started:
                self._ledger.open_session(
                    self._session_id,
                    agent_id="langgraph",
                    metadata={
                        "framework": "langgraph",
                        "thread_id_hash": _sha256(thread_id),
                    },
                )
                self._started = True
        return self._ledger

    def end_session(self, status: str = "success") -> None:
        with self._lock:
            if not self._started or self._ledger is None:
                return
            try:
                self._ledger.close_session(status=status)
                jsonl = self._output_dir / f"{self._session_id}.jsonl"
                self._ledger.export_jsonl(jsonl)
                logger.info("Sasana LangGraph session → %s", jsonl)
            except Exception as exc:
                logger.error("Sasana: end_session error: %s", exc)
            finally:
                self._ledger.close()
                self._ledger = None
                self._started = False

    def __enter__(self) -> "TamperEvidentCheckpointSaver":
        return self

    def __exit__(self, exc_type: Any, *_: Any) -> None:
        self.end_session(status="error" if exc_type else "success")

    async def __aenter__(self) -> "TamperEvidentCheckpointSaver":
        return self

    async def __aexit__(self, exc_type: Any, *_: Any) -> None:
        self.end_session(status="error" if exc_type else "success")

    # ------------------------------------------------------------------ #
    # BaseCheckpointSaver interface                                        #
    # ------------------------------------------------------------------ #

    def get_tuple(self, config: Any) -> Optional[Any]:
        return self._inner.get_tuple(config) if self._inner else None

    async def aget_tuple(self, config: Any) -> Optional[Any]:
        if self._inner and hasattr(self._inner, "aget_tuple"):
            return await self._inner.aget_tuple(config)
        return self.get_tuple(config)

    def list(
        self,
        config: Any,
        *,
        filter: Any = None,
        before: Any = None,
        limit: Any = None,
    ) -> Iterator[Any]:
        if self._inner:
            yield from self._inner.list(config, filter=filter, before=before, limit=limit)

    async def alist(self, config: Any, *, filter: Any = None, before: Any = None, limit: Any = None):
        if self._inner and hasattr(self._inner, "alist"):
            async for item in self._inner.alist(config, filter=filter, before=before, limit=limit):
                yield item

    def put(self, config: Any, checkpoint: Any, metadata: Any, new_versions: Any) -> Any:
        thread_id = _extract_thread_id(config)
        ledger = self._ensure_started(thread_id)
        _audit_checkpoint(ledger, checkpoint, metadata, thread_id)
        if self._inner:
            return self._inner.put(config, checkpoint, metadata, new_versions)
        return config

    async def aput(self, config: Any, checkpoint: Any, metadata: Any, new_versions: Any) -> Any:
        thread_id = _extract_thread_id(config)
        ledger = self._ensure_started(thread_id)
        _audit_checkpoint(ledger, checkpoint, metadata, thread_id)
        if self._inner and hasattr(self._inner, "aput"):
            return await self._inner.aput(config, checkpoint, metadata, new_versions)
        return self.put(config, checkpoint, metadata, new_versions)

    def put_writes(self, config: Any, writes: Any, task_id: str) -> None:
        thread_id = _extract_thread_id(config)
        ledger = self._ensure_started(thread_id)
        _audit_writes(ledger, writes, task_id, thread_id)
        if self._inner:
            self._inner.put_writes(config, writes, task_id)

    async def aput_writes(self, config: Any, writes: Any, task_id: str) -> None:
        thread_id = _extract_thread_id(config)
        ledger = self._ensure_started(thread_id)
        _audit_writes(ledger, writes, task_id, thread_id)
        if self._inner and hasattr(self._inner, "aput_writes"):
            await self._inner.aput_writes(config, writes, task_id)
        else:
            self.put_writes(config, writes, task_id)

    @property
    def session_id(self) -> str:
        return self._session_id


# ------------------------------------------------------------------ #
# Helpers (module-level for easy testing)                             #
# ------------------------------------------------------------------ #

def _extract_thread_id(config: Any) -> str:
    try:
        return (config or {}).get("configurable", {}).get("thread_id", "unknown")
    except Exception:
        return "unknown"


def _audit_checkpoint(
    ledger: SqliteLedger,
    checkpoint: Any,
    metadata: Any,
    thread_id: str,
) -> None:
    try:
        step = -1
        source = "unknown"
        node_names: list[str] = []

        if metadata is not None:
            if hasattr(metadata, "step"):
                step = metadata.step
            elif isinstance(metadata, dict):
                step = metadata.get("step", -1)
            if hasattr(metadata, "source"):
                source = str(metadata.source)
            elif isinstance(metadata, dict):
                source = str(metadata.get("source", "unknown"))
            writes = getattr(metadata, "writes", None) or (metadata.get("writes") if isinstance(metadata, dict) else None)
            if isinstance(writes, dict):
                node_names = list(writes.keys())

        channel_count = 0
        checkpoint_id = ""
        if checkpoint is not None:
            if hasattr(checkpoint, "channel_values"):
                channel_count = len(checkpoint.channel_values or {})
            elif isinstance(checkpoint, dict):
                channel_count = len(checkpoint.get("channel_values", {}))
            checkpoint_id = str(getattr(checkpoint, "id", "") or (checkpoint.get("id", "") if isinstance(checkpoint, dict) else ""))

        ledger.record(
            "TOOL_RESULT",
            {
                "framework": "langgraph",
                "node_name_hashes": [_sha256(n) for n in node_names],
                "source": _sha256(source),
                "step": step,
                "thread_id_hash": _sha256(thread_id),
                "channel_count": channel_count,
                "checkpoint_id_hash": _sha256(checkpoint_id),
            },
        )
    except Exception as exc:
        logger.debug("Sasana: _audit_checkpoint error (ignored): %s", exc)


def _audit_writes(
    ledger: SqliteLedger,
    writes: Any,
    task_id: str,
    thread_id: str,
) -> None:
    if not writes:
        return
    try:
        write_count = len(writes) if hasattr(writes, "__len__") else -1
        write_key_hashes = []
        if isinstance(writes, (list, tuple)):
            write_key_hashes = [_sha256(w[0]) for w in writes if isinstance(w, (list, tuple)) and len(w) >= 1]

        ledger.record(
            "TOOL_CALL",
            {
                "framework": "langgraph",
                "task_id_hash": _sha256(task_id),
                "write_count": write_count,
                "write_key_hashes": write_key_hashes,
                "thread_id_hash": _sha256(thread_id),
            },
        )
    except Exception as exc:
        logger.debug("Sasana: _audit_writes error (ignored): %s", exc)
