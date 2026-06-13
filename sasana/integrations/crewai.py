"""
sasana.integrations.crewai — SasanaCrewAITracer for CrewAI agents.

Implements both LangChain's BaseCallbackHandler interface (for deep tracing
of LLM calls and tool use) and CrewAI's step_callback convention.

Install:
    pip install crewai langchain-core

Usage (recommended — full tracing):

    from sasana.integrations.crewai import SasanaCrewAITracer

    tracer = SasanaCrewAITracer()
    tracer.start()

    agent = Agent(
        role="...",
        goal="...",
        backstory="...",
        tools=[...],
        callbacks=[tracer],           # LLM + tool call tracing
    )
    crew = Crew(
        agents=[agent],
        tasks=[...],
        step_callback=tracer.step_callback,  # agent step tracing
    )
    result = crew.kickoff()
    tracer.stop()

    # Verify:
    #   sasana verify ~/.openclaw/sasana/<session_id>.jsonl
"""

from __future__ import annotations

import logging
import os
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

logger = logging.getLogger("sasana.integrations.crewai")

try:
    from langchain_core.callbacks import BaseCallbackHandler
    from langchain_core.outputs import LLMResult
    _LANGCHAIN_AVAILABLE = True
except ImportError:
    try:
        from langchain.callbacks.base import BaseCallbackHandler  # type: ignore[no-redef]
        from langchain.schema import LLMResult  # type: ignore[no-redef]
        _LANGCHAIN_AVAILABLE = True
    except ImportError:
        _LANGCHAIN_AVAILABLE = False
        BaseCallbackHandler = object  # type: ignore[assignment,misc]
        LLMResult = object  # type: ignore[assignment,misc]

from sasana._utils import content_hash as _sha256
from sasana.sqlite_ledger import SqliteLedger

_DEFAULT_OUTPUT_DIR = Path.home() / ".openclaw" / "sasana"


def _mk_ledger(session_id: str, output_dir: Path) -> SqliteLedger:
    output_dir.mkdir(parents=True, exist_ok=True)
    ledger = SqliteLedger(db_path=output_dir / f"{session_id}.db")
    return ledger


class SasanaCrewAITracer(BaseCallbackHandler):  # type: ignore[misc]
    """
    Tamper-evident tracer for CrewAI crews.

    Captures LLM calls, tool invocations, and agent steps as hash-chained
    Sasana events.  No raw prompts or results are ever stored — only SHA-256
    hashes.

    Parameters
    ----------
    output_dir : str | Path | None
        Directory for .db and .jsonl files.  Default: ~/.openclaw/sasana/
        Override with SASANA_OUTPUT_DIR env var.
    session_id : str | None
        Explicit session ID.  Default: auto-generated UUID.
    agent_id : str | None
        Human-readable name for this crew.  Default: "crewai".
    """

    def __init__(
        self,
        *,
        output_dir: Optional[str | Path] = None,
        session_id: Optional[str] = None,
        agent_id: str = "crewai",
    ) -> None:
        if _LANGCHAIN_AVAILABLE:
            super().__init__()
        self._output_dir = Path(
            output_dir or os.environ.get("SASANA_OUTPUT_DIR", str(_DEFAULT_OUTPUT_DIR))
        ).expanduser()
        self._session_id = session_id or str(uuid.uuid4())
        self._agent_id = agent_id
        self._ledger: Optional[SqliteLedger] = None
        self._started = False

    def start(self, metadata: Optional[dict] = None) -> "SasanaCrewAITracer":
        if self._started:
            return self
        self._ledger = _mk_ledger(self._session_id, self._output_dir)
        meta: dict = {"framework": "crewai", "agent_id": self._agent_id}
        if metadata:
            meta.update({k: _sha256(v) for k, v in metadata.items()})
        self._ledger.open_session(
            self._session_id,
            agent_id=self._agent_id,
            metadata=meta,
        )
        self._started = True
        logger.info("Sasana CrewAI session started: %s", self._session_id)
        return self

    def stop(self, status: str = "success") -> None:
        if not self._started or self._ledger is None:
            return
        try:
            self._ledger.close_session(status=status)
            jsonl = self._output_dir / f"{self._session_id}.jsonl"
            self._ledger.export_jsonl(jsonl)
            logger.info("Sasana CrewAI session → %s", jsonl)
        except Exception as exc:
            logger.error("Sasana: stop error: %s", exc)
        finally:
            if self._ledger:
                self._ledger.close()
            self._ledger = None
            self._started = False

    def __enter__(self) -> "SasanaCrewAITracer":
        return self.start()

    def __exit__(self, exc_type: Any, *_: Any) -> None:
        self.stop(status="error" if exc_type else "success")

    def _record(self, event_type: str, payload: dict) -> None:
        if not self._started:
            self.start()
        if self._ledger:
            try:
                self._ledger.record(event_type, payload)
            except Exception as exc:
                logger.debug("Sasana: record error (ignored): %s", exc)

    @property
    def session_id(self) -> str:
        return self._session_id

    def step_callback(self, agent_output: Any) -> None:
        """Pass as ``Crew(step_callback=tracer.step_callback)``."""
        try:
            output_str = str(getattr(agent_output, "return_values", agent_output) or "")
            self._record(
                "TOOL_RESULT",
                {
                    "framework": "crewai",
                    "step": "agent_step",
                    "output_hash": _sha256(output_str),
                    "output_len": len(output_str),
                    "agent_id": self._agent_id,
                },
            )
        except Exception as exc:
            logger.debug("Sasana: step_callback error (ignored): %s", exc)

    def on_llm_start(self, serialized: Dict[str, Any], prompts: List[str], **kwargs: Any) -> None:
        model_name = (serialized or {}).get("name") or (serialized or {}).get("id", ["unknown"])[-1]
        self._record(
            "LLM_CALL",
            {
                "framework": "crewai",
                "model_hash": _sha256(model_name),
                "prompt_count": len(prompts),
                "prompt_hash": _sha256("".join(prompts)),
                "agent_id": self._agent_id,
            },
        )

    def on_llm_end(self, response: Any, **kwargs: Any) -> None:
        try:
            text = ""
            if hasattr(response, "generations"):
                text = " ".join(
                    getattr(g, "text", "") or ""
                    for gens in response.generations
                    for g in (gens if isinstance(gens, list) else [gens])
                )
            self._record(
                "LLM_RESPONSE",
                {
                    "framework": "crewai",
                    "response_hash": _sha256(text),
                    "response_len": len(text),
                    "agent_id": self._agent_id,
                },
            )
        except Exception as exc:
            logger.debug("Sasana: on_llm_end error (ignored): %s", exc)

    def on_llm_error(self, error: Union[Exception, KeyboardInterrupt], **kwargs: Any) -> None:
        self._record(
            "TOOL_ERROR",
            {
                "framework": "crewai",
                "error_type": type(error).__name__,
                "error_hash": _sha256(str(error)),
                "agent_id": self._agent_id,
            },
        )

    def on_tool_start(self, serialized: Dict[str, Any], input_str: str, **kwargs: Any) -> None:
        tool_name = (serialized or {}).get("name", "unknown")
        self._record(
            "TOOL_CALL",
            {
                "framework": "crewai",
                "tool_name_hash": _sha256(tool_name),
                "input_hash": _sha256(input_str),
                "input_len": len(str(input_str)),
                "agent_id": self._agent_id,
            },
        )

    def on_tool_end(self, output: str, **kwargs: Any) -> None:
        self._record(
            "TOOL_RESULT",
            {
                "framework": "crewai",
                "output_hash": _sha256(output),
                "output_len": len(str(output)),
                "agent_id": self._agent_id,
            },
        )

    def on_tool_error(self, error: Union[Exception, KeyboardInterrupt], **kwargs: Any) -> None:
        self._record(
            "TOOL_ERROR",
            {
                "framework": "crewai",
                "error_type": type(error).__name__,
                "error_hash": _sha256(str(error)),
                "agent_id": self._agent_id,
            },
        )

    def on_agent_action(self, action: Any, **kwargs: Any) -> Any:
        try:
            tool = getattr(action, "tool", "unknown")
            tool_input = getattr(action, "tool_input", "")
            self._record(
                "TOOL_CALL",
                {
                    "framework": "crewai",
                    "source": "agent_action",
                    "tool_name_hash": _sha256(tool),
                    "input_hash": _sha256(tool_input),
                    "agent_id": self._agent_id,
                },
            )
        except Exception as exc:
            logger.debug("Sasana: on_agent_action error (ignored): %s", exc)

    def on_agent_finish(self, finish: Any, **kwargs: Any) -> Any:
        try:
            return_values = getattr(finish, "return_values", {}) or {}
            output = str(return_values.get("output", ""))
            self._record(
                "LLM_RESPONSE",
                {
                    "framework": "crewai",
                    "source": "agent_finish",
                    "output_hash": _sha256(output),
                    "output_len": len(output),
                    "agent_id": self._agent_id,
                },
            )
        except Exception as exc:
            logger.debug("Sasana: on_agent_finish error (ignored): %s", exc)

    def on_chain_start(self, serialized: Any, inputs: Any, **kwargs: Any) -> None:
        pass

    def on_chain_end(self, outputs: Any, **kwargs: Any) -> None:
        pass

    def on_chain_error(self, error: Any, **kwargs: Any) -> None:
        pass

    def on_text(self, text: str, **kwargs: Any) -> None:
        pass
