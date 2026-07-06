# sasana-openclaw

Real OpenClaw Plugin SDK bridge for [Sasana](https://pypi.org/project/sasana/).
Forwards Gateway lifecycle hooks to the local Sasana tamper-evident audit
ledger over a Unix domain socket. No raw prompt, response, tool argument, or
tool result content ever leaves this plugin's process — only SHA-256 hashes
reach the ledger.

Verified against a live OpenClaw v2026.6.6 gateway (not mocked): the plugin
loads, registers all 8 hooks below with zero diagnostics, and `session_start`
was captured end-to-end into a real hash-chained, RFC 3161-anchored ledger
entry. See `docs/openclaw-integration-notes.md` in the Sasana repo for the
full verification record, including which hooks still need a live model
provider credential to fire in a given environment.

## Hooks

`session_start`, `session_end`, `before_tool_call`, `after_tool_call`,
`model_call_started`, `model_call_ended`, `llm_input`, `llm_output`.

## Install

```bash
openclaw plugins install /path/to/sasana-openclaw --link
```

Non-bundled plugins that read prompt/response content (`llm_input`,
`llm_output`) require an explicit opt-in — OpenClaw blocks them otherwise:

```bash
openclaw config set plugins.entries.sasana-openclaw.hooks.allowConversationAccess true
```

Restart the gateway to load the plugin.

## Run the Python bridge

```bash
sasana bridge
```

Listens on `~/.openclaw/sasana/bridge.sock` by default (override with
`SASANA_BRIDGE_SOCKET` env var, or `sasana bridge --socket <path>`). Ledger
output defaults to `~/.openclaw/sasana/` (override with `SASANA_OUTPUT_DIR`
or `--output-dir`).

## Verify

```bash
sasana verify ~/.openclaw/sasana/<session_id>.jsonl
```
