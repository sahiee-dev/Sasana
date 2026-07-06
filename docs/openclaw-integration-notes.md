# OpenClaw integration — verification record

This documents what was actually verified against a live OpenClaw v2026.6.6
gateway (not mocks) when building the real `sasana-openclaw` plugin, and
where the original assumptions in `sasana.skill.SasanaSkill` and
`sasana.observer.OpenClawObserver` were wrong.

## What the original integration assumed (incorrect)

- `SasanaSkill` (Python class with `on_session_start`, `on_llm_call`, etc.)
  assumed OpenClaw loads Python classes and calls hook methods on them.
  There is no such mechanism. OpenClaw plugins are TypeScript, registered via
  `definePluginEntry` + `api.on(...)` from the Plugin SDK.
- `OpenClawObserver` assumed an open, unauthenticated WebSocket at
  `ws://localhost:3517/ws`, configured via a YAML `~/.openclaw/config.yml`,
  broadcasting `{"type": "llm.call", ...}`-shaped messages.
  - Real default gateway port: `18789` (confirmed running).
  - Real config file: `~/.openclaw/openclaw.json` (JSON, not YAML).
  - Connecting to the real gateway socket returns an authenticated challenge
    handshake (`{"type":"event","event":"connect.challenge",...}`) and never
    broadcasts anything until that handshake completes. Confirmed empirically
    with a raw client connection — no data flows without it.
- Neither module's event names (`session.start`, `llm.call`, `tool.invoke`,
  etc.) match OpenClaw's real hook names.

## What's real (from `docs/plugins/hooks.md` in the installed OpenClaw
package, cross-checked against a live gateway)

Real typed plugin hooks used here: `session_start`, `session_end`,
`before_tool_call`, `after_tool_call`, `model_call_started`,
`model_call_ended`, `llm_input`, `llm_output`. Registered via
`api.on(name, handler)` inside `register(api)` in a `definePluginEntry(...)`
plugin, loaded from a manifest (`openclaw.plugin.json`) + `package.json` with
an `openclaw.extensions` entry pointing at the TS source (Node 22.19+ strips
types natively — no build step needed for local/linked installs).

Non-bundled plugins that read `llm_input` or `llm_output` are blocked by
default and must opt in:

```
plugins.entries.<id>.hooks.allowConversationAccess = true
```

This was discovered live: the gateway logged
`typed hook "llm_input" blocked because non-bundled plugins must set
plugins.entries.sasana-openclaw.hooks.allowConversationAccess=true` on first
load, before the config was set.

## What was verified live, end-to-end

Using an isolated `--dev` profile gateway (`~/.openclaw-dev`, port `19001`)
— never the production gateway on `18789` — with `sasana-openclaw` linked
via `openclaw plugins install ./openclaw-plugin/sasana-openclaw --link`:

1. `openclaw plugins inspect sasana-openclaw --runtime --json` shows all 8
   hooks (plus `gateway_start`/`gateway_stop`) in `typedHooks`, `status:
   "loaded"`, `diagnostics: []`, `policy.allowConversationAccess: true`.
2. Firing a real agent turn (`openclaw agent --message ... --session-key
   agent:default:sasana-test`) triggered a real `session_start` hook call,
   forwarded over a real Unix socket to a running `sasana bridge` process,
   which wrote a real SHA-256 hash-chained SESSION_START event — including a
   live RFC 3161 timestamp token fetched from freetsa.org — into a real
   SQLite ledger.
3. `sasana verify` against the exported `.jsonl` passed structural validity,
   sequence integrity, hash chain integrity, seal signature, and RFC 3161
   timestamp checks, and correctly reported `COMPROMISED` for session
   completeness — because no `SESSION_END` had fired yet, which is exactly
   what that check exists to catch.

## What was not empirically fired

`session_end`, `before_tool_call`, `after_tool_call`, `model_call_started`,
`model_call_ended`, `llm_input`, `llm_output` are registered and load without
error, but were not independently observed firing in this environment:

- The one-shot `openclaw agent` CLI invocation errored at model-provider
  resolution (`FailoverError`, then `HTTP 401` with a placeholder key) before
  OpenClaw's hook-instrumented turn pipeline ran far enough to reach
  `llm_input` / `model_call_started`. Reaching those requires a real,
  working model-provider credential.
- `session_end` fires either on explicit session reset/idle/deletion, or from
  the gateway's shutdown finalizer for sessions still marked active at
  shutdown time — the one-shot CLI session here had already finished (with
  an error) before shutdown, so it wasn't in that active set.
- `before_tool_call` / `after_tool_call` additionally require a successful
  model response that requests a tool call.

None of this is a defect in the plugin or bridge — `map_bridge_event` and
`OpenClawBridgeServer` are unit-tested end-to-end (including a full
synthetic session that verifies `INTACT`) in
`tests/test_openclaw_bridge.py`. It reflects a credential-gated limit of what
could be exercised against a real gateway without a live provider key in this
session.

## Incident during testing

A `pkill -f "dist/index.js gateway"` pattern-matched and killed the
production gateway (port `18789`) instead of only the isolated dev instance,
since both run the identical binary and differ only by `--port`. A `launchd`
supervisor (`ai.openclaw.gateway`) auto-restarted it within about a minute;
confirmed responsive afterward. All process management after this incident
used PID-verified kills only (`lsof -i :<port>` first, then `kill <pid>`),
never pattern matching.
