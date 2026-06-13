"""
sasana.integrations.autogpt — SasanaAutoGPTPlugin for AutoGPT.

Hooks into AutoGPT's plugin lifecycle to record every command invocation and
result as a hash-chained Sasana audit event.  Raw command arguments and
outputs are never stored — only SHA-256 hashes.

Install:
    pip install auto-gpt-plugin-template

Usage:
    1. Copy this file (or the sasana package) into your AutoGPT plugins/ dir.
    2. Add "SasanaAutoGPTPlugin" to ALLOWLISTED_PLUGINS in your .env.
    3. Plugin auto-discovers on startup.

    # Or use programmatically:
    from sasana.integrations.autogpt import SasanaAutoGPTPlugin
    plugin = SasanaAutoGPTPlugin()
    plugin.start_session(agent_name="myagent")
    # ... run agent ...
    plugin.end_session()

    # Verify:
    #   sasana verify ~/.openclaw/sasana/<session_id>.jsonl
"""

from __future__ import annotations

import logging
import os
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("sasana.integrations.autogpt")

try:
    from auto_gpt_plugin_template import AutoGPTPluginTemplate
    _AUTOGPT_AVAILABLE = True
except ImportError:
    _AUTOGPT_AVAILABLE = False
    AutoGPTPluginTemplate = object  # type: ignore[assignment,misc]

from sasana._utils import content_hash as _sha256
from sasana.sqlite_ledger import SqliteLedger

_DEFAULT_OUTPUT_DIR = Path.home() / ".openclaw" / "sasana"


def _mk_ledger(session_id: str, output_dir: Path) -> SqliteLedger:
    output_dir.mkdir(parents=True, exist_ok=True)
    ledger = SqliteLedger(db_path=output_dir / f"{session_id}.db")
    return ledger


class SasanaAutoGPTPlugin(AutoGPTPluginTemplate):  # type: ignore[misc]
    """
    AutoGPT plugin that records every command and result to a Sasana
    hash-chained audit ledger.

    All command arguments and outputs are SHA-256 hashed before storage.
    """

    _name = "SasanaAutoGPTPlugin"
    _version = "1.0.0"
    _description = "Tamper-evident audit trail for AutoGPT command execution."

    def __init__(self) -> None:
        if _AUTOGPT_AVAILABLE:
            super().__init__()
        self._output_dir = Path(
            os.environ.get("SASANA_OUTPUT_DIR", str(_DEFAULT_OUTPUT_DIR))
        ).expanduser()
        self._session_id: Optional[str] = None
        self._ledger: Optional[SqliteLedger] = None
        self._started = False
        self._pending_command: Optional[str] = None

    def start_session(
        self,
        agent_name: str = "autogpt",
        session_id: Optional[str] = None,
        metadata: Optional[dict] = None,
    ) -> str:
        if self._started:
            return self._session_id or ""
        self._session_id = session_id or str(uuid.uuid4())
        self._ledger = _mk_ledger(self._session_id, self._output_dir)
        meta: dict = {"framework": "autogpt", "agent_name": agent_name}
        if metadata:
            meta.update({k: _sha256(str(v)) for k, v in metadata.items()})
        self._ledger.open_session(
            self._session_id,
            agent_id=agent_name,
            metadata=meta,
        )
        self._started = True
        logger.info("Sasana AutoGPT session started: %s", self._session_id)
        return self._session_id

    def end_session(self, status: str = "success") -> Optional[Path]:
        if not self._started or self._ledger is None:
            return None
        try:
            self._ledger.close_session(status=status)
            jsonl = self._output_dir / f"{self._session_id}.jsonl"
            self._ledger.export_jsonl(jsonl)
            logger.info("Sasana AutoGPT session → %s", jsonl)
            return jsonl
        except Exception as exc:
            logger.error("Sasana: end_session error: %s", exc)
            return None
        finally:
            if self._ledger:
                self._ledger.close()
            self._ledger = None
            self._started = False

    def _record(self, event_type: str, payload: dict) -> None:
        if not self._started:
            self.start_session()
        if self._ledger:
            try:
                self._ledger.record(event_type, payload)
            except Exception as exc:
                logger.debug("Sasana: record error (ignored): %s", exc)

    @property
    def session_id(self) -> Optional[str]:
        return self._session_id

    def can_handle_pre_command(self) -> bool:
        return True

    def pre_command(self, command_name: str, arguments: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
        self._pending_command = command_name
        try:
            arg_hash = _sha256(str(sorted(arguments.items())))
            self._record(
                "TOOL_CALL",
                {
                    "framework": "autogpt",
                    "command_name_hash": _sha256(command_name),
                    "arguments_hash": arg_hash,
                    "argument_keys": sorted(arguments.keys()),
                },
            )
        except Exception as exc:
            logger.debug("Sasana: pre_command error (ignored): %s", exc)
        return command_name, arguments

    def can_handle_post_command(self) -> bool:
        return True

    def post_command(self, command_name: str, response: str) -> str:
        try:
            self._record(
                "TOOL_RESULT",
                {
                    "framework": "autogpt",
                    "command_name_hash": _sha256(command_name),
                    "response_hash": _sha256(response),
                    "response_len": len(str(response)),
                    "pending_command_match": (self._pending_command == command_name),
                },
            )
            self._pending_command = None
        except Exception as exc:
            logger.debug("Sasana: post_command error (ignored): %s", exc)
        return response

    def can_handle_pre_message_history_summary(self) -> bool:
        return True

    def pre_message_history_summary(self, params: Any, messages: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        try:
            self._record(
                "LLM_CALL",
                {
                    "framework": "autogpt",
                    "source": "message_history_summary",
                    "message_count": len(messages),
                    "history_hash": _sha256(str(messages)),
                },
            )
        except Exception as exc:
            logger.debug("Sasana: pre_message_history_summary error (ignored): %s", exc)
        return messages

    def can_handle_post_message_history_summary(self) -> bool:
        return True

    def post_message_history_summary(self, params: Any, summary: str) -> str:
        try:
            self._record(
                "LLM_RESPONSE",
                {
                    "framework": "autogpt",
                    "source": "message_history_summary",
                    "summary_hash": _sha256(summary),
                    "summary_len": len(str(summary)),
                },
            )
        except Exception as exc:
            logger.debug("Sasana: post_message_history_summary error (ignored): %s", exc)
        return summary

    def can_handle_on_planning(self) -> bool:
        return True

    def on_planning(self, prompt: Any, messages: List[Dict[str, Any]]) -> Optional[str]:
        try:
            self._record(
                "LLM_CALL",
                {
                    "framework": "autogpt",
                    "source": "planning",
                    "message_count": len(messages),
                    "prompt_hash": _sha256(str(prompt)),
                },
            )
        except Exception as exc:
            logger.debug("Sasana: on_planning error (ignored): %s", exc)
        return None

    def can_handle_post_planning(self) -> bool:
        return True

    def post_planning(self, response: str) -> str:
        try:
            self._record(
                "LLM_RESPONSE",
                {
                    "framework": "autogpt",
                    "source": "planning",
                    "response_hash": _sha256(response),
                    "response_len": len(str(response)),
                },
            )
        except Exception as exc:
            logger.debug("Sasana: post_planning error (ignored): %s", exc)
        return response

    def can_handle_on_response(self) -> bool:
        return True

    def on_response(self, response: str, *args: Any, **kwargs: Any) -> str:
        try:
            self._record(
                "LLM_RESPONSE",
                {
                    "framework": "autogpt",
                    "source": "on_response",
                    "response_hash": _sha256(response),
                    "response_len": len(str(response)),
                },
            )
        except Exception as exc:
            logger.debug("Sasana: on_response error (ignored): %s", exc)
        return response

    def can_handle_on_instruction(self) -> bool:
        return False

    def on_instruction(self, messages: List[Dict[str, Any]]) -> Optional[str]:
        return None

    def can_handle_post_prompt(self) -> bool:
        return False

    def post_prompt(self, prompt: Any) -> Any:
        return prompt

    def can_handle_on_enter_agency(self) -> bool:
        return False

    def on_enter_agency(self) -> None:
        pass

    def can_handle_generate_image(self) -> bool:
        return False

    def generate_image(self, prompt: str) -> str:
        return ""

    def can_handle_audio_transcription(self) -> bool:
        return False

    def audio_transcription(self, filename: str) -> str:
        return ""

    def can_handle_shutdown(self) -> bool:
        return True

    def shutdown(self) -> None:
        self.end_session(status="success")
