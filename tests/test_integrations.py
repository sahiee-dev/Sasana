"""
test_integrations.py — Unit tests for sasana Phase 2 framework integrations.

Covers:
  - LangGraph: TamperEvidentCheckpointSaver session lifecycle + event types
  - CrewAI: SasanaCrewAITracer callbacks + step_callback
  - AutoGPT: SasanaAutoGPTPlugin pre/post command hooks

All tests run without the third-party frameworks installed.
"""

from __future__ import annotations

import json
import sys
import types
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

_DIST = Path(__file__).parent.parent
if str(_DIST) not in sys.path:
    sys.path.insert(0, str(_DIST))


def _stub_langgraph() -> None:
    if "langgraph" in sys.modules:
        return
    pkg = types.ModuleType("langgraph")
    checkpoint = types.ModuleType("langgraph.checkpoint")
    base = types.ModuleType("langgraph.checkpoint.base")
    base.BaseCheckpointSaver = object
    pkg.checkpoint = checkpoint
    checkpoint.base = base
    sys.modules.update(
        {
            "langgraph": pkg,
            "langgraph.checkpoint": checkpoint,
            "langgraph.checkpoint.base": base,
        }
    )


def _stub_langchain() -> None:
    for mod in (
        "langchain_core",
        "langchain_core.callbacks",
        "langchain_core.outputs",
        "langchain",
        "langchain.callbacks",
        "langchain.callbacks.base",
        "langchain.schema",
    ):
        if mod not in sys.modules:
            sys.modules[mod] = types.ModuleType(mod)
    sys.modules["langchain_core.callbacks"].BaseCallbackHandler = object
    sys.modules["langchain_core.outputs"].LLMResult = object
    sys.modules["langchain.callbacks.base"].BaseCallbackHandler = object
    sys.modules["langchain.schema"].LLMResult = object


def _stub_autogpt() -> None:
    if "auto_gpt_plugin_template" not in sys.modules:
        mod = types.ModuleType("auto_gpt_plugin_template")
        mod.AutoGPTPluginTemplate = object
        sys.modules["auto_gpt_plugin_template"] = mod


_stub_langgraph()
_stub_langchain()
_stub_autogpt()

import importlib  # noqa: E402

_lg_mod = importlib.import_module("sasana.integrations.langgraph")
_ca_mod = importlib.import_module("sasana.integrations.crewai")
_ag_mod = importlib.import_module("sasana.integrations.autogpt")


def _make_saver(tmp_path, **kwargs) -> Any:
    with patch.object(_lg_mod, "_LANGGRAPH_AVAILABLE", True):
        saver = _lg_mod.TamperEvidentCheckpointSaver(output_dir=tmp_path, **kwargs)
    return saver


def _make_tracer(tmp_path, **kwargs) -> Any:
    with patch.object(_ca_mod, "_LANGCHAIN_AVAILABLE", True):
        tracer = _ca_mod.SasanaCrewAITracer(output_dir=tmp_path, **kwargs)
    return tracer


def _make_plugin(tmp_path) -> Any:
    plugin = _ag_mod.SasanaAutoGPTPlugin()
    plugin._output_dir = Path(tmp_path)
    return plugin


def _read_jsonl(path: Path) -> list:
    lines = [ln.strip() for ln in path.read_text().splitlines() if ln.strip()]
    return [json.loads(ln) for ln in lines]


class TestExtractThreadId(unittest.TestCase):
    def test_extracts_thread_id_from_config(self):
        assert (
            _lg_mod._extract_thread_id({"configurable": {"thread_id": "my-thread"}}) == "my-thread"
        )

    def test_returns_unknown_for_empty_config(self):
        assert _lg_mod._extract_thread_id({}) == "unknown"
        assert _lg_mod._extract_thread_id(None) == "unknown"

    def test_returns_unknown_for_missing_thread_id(self):
        assert _lg_mod._extract_thread_id({"configurable": {}}) == "unknown"


class TestTamperEvidentCheckpointSaverLifecycle(unittest.TestCase):
    def setUp(self):
        import tempfile

        self.tmp = Path(tempfile.mkdtemp())

    def _checkpoint(self, channels=None, cid="c"):
        cp = MagicMock()
        cp.id = cid
        cp.channel_values = channels or {}
        meta = MagicMock()
        meta.step = 0
        meta.source = "input"
        meta.writes = {}
        return cp, meta

    def test_session_id_is_uuid(self):
        saver = _make_saver(self.tmp)
        assert len(saver.session_id) == 36

    def test_session_id_explicit(self):
        saver = _make_saver(self.tmp, session_id="explicit-42")
        assert saver.session_id == "explicit-42"

    def test_put_starts_session(self):
        saver = _make_saver(self.tmp)
        cp, meta = self._checkpoint()
        saver.put({"configurable": {"thread_id": "t1"}}, cp, meta, {})
        assert saver._started is True

    def test_end_session_produces_jsonl(self):
        saver = _make_saver(self.tmp)
        cp, meta = self._checkpoint()
        saver.put({"configurable": {"thread_id": "t1"}}, cp, meta, {})
        saver.end_session()
        files = list(self.tmp.glob("*.jsonl"))
        assert len(files) == 1
        evts = _read_jsonl(files[0])
        assert evts[0]["event_type"] == "SESSION_START"
        assert evts[-1]["event_type"] == "SESSION_END"

    def test_hash_chain_valid(self):
        saver = _make_saver(self.tmp)
        cp, meta = self._checkpoint()
        for _ in range(3):
            saver.put({"configurable": {"thread_id": "t-chain"}}, cp, meta, {})
        saver.end_session()
        evts = _read_jsonl(list(self.tmp.glob("*.jsonl"))[0])
        from sasana.jcs import canonicalize as jcs
        import hashlib

        prev = "0" * 64
        for evt in evts:
            stripped = {k: v for k, v in evt.items() if k not in ("event_hash", "signature")}
            computed = hashlib.sha256(jcs(stripped)).hexdigest()
            assert computed == evt["event_hash"]
            assert evt["prev_hash"] == prev
            prev = evt["event_hash"]

    def test_context_manager(self):
        saver = _make_saver(self.tmp)
        cp, meta = self._checkpoint()
        with saver:
            saver.put({"configurable": {"thread_id": "t-ctx"}}, cp, meta, {})
        assert saver._started is False
        assert len(list(self.tmp.glob("*.jsonl"))) == 1

    def test_inner_saver_delegated(self):
        inner = MagicMock()
        inner.put.return_value = {"configurable": {"checkpoint_id": "x"}}
        saver = _make_saver(self.tmp)
        saver._inner = inner
        cp, meta = self._checkpoint()
        result = saver.put({"configurable": {"thread_id": "t"}}, cp, meta, {})
        inner.put.assert_called_once()
        assert result == {"configurable": {"checkpoint_id": "x"}}


class TestSasanaCrewAITracer(unittest.TestCase):
    def setUp(self):
        import tempfile

        self.tmp = Path(tempfile.mkdtemp())

    def test_start_creates_session(self):
        t = _make_tracer(self.tmp)
        t.start()
        assert t._started
        t.stop()

    def test_double_start_idempotent(self):
        t = _make_tracer(self.tmp)
        t.start()
        t.start()
        assert t._started
        t.stop()

    def test_stop_produces_jsonl(self):
        t = _make_tracer(self.tmp)
        t.start()
        t.stop()
        evts = _read_jsonl(list(self.tmp.glob("*.jsonl"))[0])
        assert evts[0]["event_type"] == "SESSION_START"
        assert evts[-1]["event_type"] == "SESSION_END"

    def test_tool_start_end(self):
        t = _make_tracer(self.tmp)
        t.start()
        t.on_tool_start({"name": "search"}, "query")
        t.on_tool_end("results")
        t.stop()
        evts = _read_jsonl(list(self.tmp.glob("*.jsonl"))[0])
        assert any(e["event_type"] == "TOOL_CALL" for e in evts)
        assert any(e["event_type"] == "TOOL_RESULT" for e in evts)

    def test_tool_error(self):
        t = _make_tracer(self.tmp)
        t.start()
        t.on_tool_error(ValueError("fail"))
        t.stop()
        evts = _read_jsonl(list(self.tmp.glob("*.jsonl"))[0])
        errors = [e for e in evts if e["event_type"] == "TOOL_ERROR"]
        assert errors[0]["payload"]["error_type"] == "ValueError"

    def test_llm_call_and_response(self):
        t = _make_tracer(self.tmp)
        t.start()
        t.on_llm_start({"name": "claude"}, ["prompt"])
        resp = MagicMock()
        g = MagicMock()
        g.text = "response"
        resp.generations = [[g]]
        t.on_llm_end(resp)
        t.stop()
        evts = _read_jsonl(list(self.tmp.glob("*.jsonl"))[0])
        assert any(e["event_type"] == "LLM_CALL" for e in evts)
        assert any(e["event_type"] == "LLM_RESPONSE" for e in evts)

    def test_raw_content_not_stored(self):
        t = _make_tracer(self.tmp)
        t.start()
        secret = "my_secret_password_xyz"
        t.on_tool_start({"name": "tool"}, secret)
        t.stop()
        content = list(self.tmp.glob("*.jsonl"))[0].read_text()
        assert secret not in content

    def test_hash_chain_integrity(self):
        t = _make_tracer(self.tmp)
        t.start()
        t.on_tool_start({"name": "t"}, "i")
        t.on_tool_end("o")
        t.stop()
        evts = _read_jsonl(list(self.tmp.glob("*.jsonl"))[0])
        from sasana.jcs import canonicalize as jcs
        import hashlib

        prev = "0" * 64
        for evt in evts:
            stripped = {k: v for k, v in evt.items() if k not in ("event_hash", "signature")}
            assert hashlib.sha256(jcs(stripped)).hexdigest() == evt["event_hash"]
            assert evt["prev_hash"] == prev
            prev = evt["event_hash"]


class TestSasanaAutoGPTPlugin(unittest.TestCase):
    def setUp(self):
        import tempfile

        self.tmp = Path(tempfile.mkdtemp())

    def test_start_session_returns_sid(self):
        p = _make_plugin(self.tmp)
        sid = p.start_session()
        assert len(sid) == 36
        p.end_session()

    def test_explicit_session_id(self):
        p = _make_plugin(self.tmp)
        p.start_session(session_id="custom-99")
        assert p.session_id == "custom-99"
        p.end_session()

    def test_pre_post_command(self):
        p = _make_plugin(self.tmp)
        p.start_session()
        name, args = p.pre_command("web_search", {"q": "python"})
        assert name == "web_search" and args == {"q": "python"}
        result = p.post_command("web_search", "5 results")
        assert result == "5 results"
        p.end_session()
        evts = _read_jsonl(list(self.tmp.glob("*.jsonl"))[0])
        assert any(e["event_type"] == "TOOL_CALL" for e in evts)
        assert any(e["event_type"] == "TOOL_RESULT" for e in evts)

    def test_raw_content_not_in_ledger(self):
        p = _make_plugin(self.tmp)
        p.start_session()
        secret = "password=hunter2&token=abc"
        p.pre_command("req", {"url": secret})
        p.end_session()
        content = list(self.tmp.glob("*.jsonl"))[0].read_text()
        assert secret not in content

    def test_shutdown_ends_session(self):
        p = _make_plugin(self.tmp)
        p.start_session()
        p.shutdown()
        assert not p._started
        assert len(list(self.tmp.glob("*.jsonl"))) == 1

    def test_hash_chain_integrity(self):
        p = _make_plugin(self.tmp)
        p.start_session()
        for i in range(4):
            p.pre_command(f"cmd{i}", {"a": str(i)})
            p.post_command(f"cmd{i}", f"r{i}")
        p.end_session()
        evts = _read_jsonl(list(self.tmp.glob("*.jsonl"))[0])
        from sasana.jcs import canonicalize as jcs
        import hashlib

        prev = "0" * 64
        for evt in evts:
            stripped = {k: v for k, v in evt.items() if k not in ("event_hash", "signature")}
            assert hashlib.sha256(jcs(stripped)).hexdigest() == evt["event_hash"]
            assert evt["prev_hash"] == prev
            prev = evt["event_hash"]


class TestEventTypeConsistency(unittest.TestCase):
    VALID_TYPES = {
        "SESSION_START",
        "SESSION_END",
        "LLM_CALL",
        "LLM_RESPONSE",
        "TOOL_CALL",
        "TOOL_RESULT",
        "TOOL_ERROR",
        "LOG_DROP",
    }

    def test_all_frameworks_emit_only_known_types(self):
        import tempfile

        # LangGraph
        tmp = Path(tempfile.mkdtemp())
        saver = _make_saver(tmp)
        cp = MagicMock()
        cp.id = "c"
        cp.channel_values = {}
        meta = MagicMock()
        meta.step = 0
        meta.source = "input"
        meta.writes = {}
        saver.put({"configurable": {"thread_id": "t"}}, cp, meta, {})
        saver.end_session()
        for evt in _read_jsonl(list(tmp.glob("*.jsonl"))[0]):
            assert evt["event_type"] in self.VALID_TYPES

        # CrewAI
        tmp = Path(tempfile.mkdtemp())
        t = _make_tracer(tmp)
        t.start()
        t.on_tool_start({"name": "t"}, "i")
        t.on_tool_end("o")
        t.stop()
        for evt in _read_jsonl(list(tmp.glob("*.jsonl"))[0]):
            assert evt["event_type"] in self.VALID_TYPES

        # AutoGPT
        tmp = Path(tempfile.mkdtemp())
        p = _make_plugin(tmp)
        p.start_session()
        p.pre_command("c", {})
        p.post_command("c", "r")
        p.end_session()
        for evt in _read_jsonl(list(tmp.glob("*.jsonl"))[0]):
            assert evt["event_type"] in self.VALID_TYPES


if __name__ == "__main__":
    unittest.main()
