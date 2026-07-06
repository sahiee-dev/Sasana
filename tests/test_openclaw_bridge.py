"""
test_openclaw_bridge.py — Unit tests for sasana.integrations.openclaw.

Covers:
  - map_bridge_event: all 8 real OpenClaw plugin-hook -> Sasana event mappings
  - OpenClawBridgeServer: session lifecycle, multi-session isolation, and a
    full record -> export -> verify round trip using real ledger + verifier
    code (no mocks) against synthetic events shaped like what the real
    sasana-openclaw TypeScript plugin forwards.
"""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

_ROOT = Path(__file__).parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from sasana.integrations.openclaw import OpenClawBridgeServer, map_bridge_event  # noqa: E402


class TestMapBridgeEvent(unittest.TestCase):
    def test_session_start(self):
        event_type, payload = map_bridge_event(
            {"hook": "session_start", "reason": "new", "agentId": "main"}
        )
        self.assertEqual(event_type, "SESSION_START")
        self.assertEqual(payload["reason"], "new")
        self.assertEqual(payload["agent_id"], "main")

    def test_session_end(self):
        event_type, payload = map_bridge_event({"hook": "session_end", "reason": "shutdown"})
        self.assertEqual(event_type, "SESSION_END")
        self.assertEqual(payload["status"], "success")
        self.assertEqual(payload["reason"], "shutdown")

    def test_llm_input_hashes_prompt_not_raw(self):
        event_type, payload = map_bridge_event(
            {"hook": "llm_input", "prompt": "the secret prompt text"}
        )
        self.assertEqual(event_type, "LLM_CALL")
        self.assertNotIn("the secret prompt text", json.dumps(payload))
        self.assertEqual(len(payload["prompt_hash"]), 64)
        self.assertEqual(payload["source"], "llm_input")

    def test_model_call_started(self):
        event_type, payload = map_bridge_event(
            {
                "hook": "model_call_started",
                "model": "gpt-5.5",
                "provider": "openai",
                "runId": "run-1",
            }
        )
        self.assertEqual(event_type, "LLM_CALL")
        self.assertEqual(payload["model_id"], "gpt-5.5")
        self.assertEqual(payload["provider"], "openai")
        self.assertEqual(payload["run_id"], "run-1")

    def test_model_call_ended(self):
        event_type, payload = map_bridge_event(
            {"hook": "model_call_ended", "outcome": "error", "durationMs": 42}
        )
        self.assertEqual(event_type, "LLM_RESPONSE")
        self.assertEqual(payload["outcome"], "error")
        self.assertEqual(payload["duration_ms"], 42)

    def test_llm_output_hashes_content_and_keeps_usage(self):
        event_type, payload = map_bridge_event(
            {
                "hook": "llm_output",
                "output": "the secret response text",
                "usage": {"input_tokens": 10, "output_tokens": 20},
            }
        )
        self.assertEqual(event_type, "LLM_RESPONSE")
        self.assertNotIn("the secret response text", json.dumps(payload))
        self.assertEqual(payload["prompt_tokens"], 10)
        self.assertEqual(payload["completion_tokens"], 20)

    def test_before_tool_call(self):
        event_type, payload = map_bridge_event(
            {"hook": "before_tool_call", "toolName": "exec", "params": {"cmd": "ls -la /secret"}}
        )
        self.assertEqual(event_type, "TOOL_CALL")
        self.assertEqual(payload["tool_name"], "exec")
        self.assertNotIn("/secret", json.dumps(payload))

    def test_after_tool_call_result(self):
        event_type, payload = map_bridge_event(
            {"hook": "after_tool_call", "toolName": "exec", "result": "output text"}
        )
        self.assertEqual(event_type, "TOOL_RESULT")
        self.assertEqual(payload["tool_name"], "exec")

    def test_after_tool_call_error(self):
        event_type, payload = map_bridge_event(
            {"hook": "after_tool_call", "toolName": "exec", "error": "boom"}
        )
        self.assertEqual(event_type, "TOOL_ERROR")
        self.assertEqual(payload["error_message"], "boom")

    def test_unknown_hook_returns_none(self):
        self.assertIsNone(map_bridge_event({"hook": "some_future_hook"}))
        self.assertIsNone(map_bridge_event({}))


class TestOpenClawBridgeServer(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.server = OpenClawBridgeServer(
            socket_path=self.tmp / "bridge.sock", output_dir=self.tmp / "out"
        )

    def test_full_session_round_trip_verifies_intact(self):
        sk = "agent:default:test-session"
        self.server.handle_event({"hook": "session_start", "sessionKey": sk, "reason": "new"})
        self.server.handle_event(
            {"hook": "llm_input", "sessionKey": sk, "prompt": "hello"},
        )
        self.server.handle_event(
            {
                "hook": "before_tool_call",
                "sessionKey": sk,
                "toolName": "read_file",
                "params": {"path": "/tmp/x"},
            }
        )
        self.server.handle_event(
            {
                "hook": "after_tool_call",
                "sessionKey": sk,
                "toolName": "read_file",
                "result": "contents",
            }
        )
        self.server.handle_event({"hook": "session_end", "sessionKey": sk, "reason": "reset"})

        out_dir = self.tmp / "out"
        jsonl_files = list(out_dir.glob("*.jsonl"))
        self.assertEqual(len(jsonl_files), 1)

        events = [json.loads(line) for line in jsonl_files[0].read_text().splitlines() if line]
        self.assertEqual(
            [e["event_type"] for e in events],
            [
                "SESSION_START",
                "LLM_CALL",
                "TOOL_CALL",
                "TOOL_RESULT",
                "SESSION_END",
            ],
        )

        from sasana.verifier import verify

        result = verify(events)
        self.assertEqual(result.status, "INTACT")

    def test_multiple_sessions_isolated(self):
        self.server.handle_event(
            {"hook": "session_start", "sessionKey": "agent:default:a", "reason": "new"}
        )
        self.server.handle_event(
            {"hook": "session_start", "sessionKey": "agent:default:b", "reason": "new"}
        )
        self.assertEqual(len(self.server._ledgers), 2)
        self.server.handle_event(
            {"hook": "session_end", "sessionKey": "agent:default:a", "reason": "reset"}
        )
        self.assertEqual(len(self.server._ledgers), 1)
        self.assertIn("agent:default:b", self.server._ledgers)

    def test_implicit_session_when_no_session_start_seen(self):
        sk = "agent:default:implicit"
        self.server.handle_event(
            {"hook": "before_tool_call", "sessionKey": sk, "toolName": "exec", "params": {}}
        )
        self.assertIn(sk, self.server._ledgers)


if __name__ == "__main__":
    unittest.main()
