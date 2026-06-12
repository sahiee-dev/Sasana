# Sasana

**Tamper-evident cryptographic audit trail for OpenClaw and multi-agent AI sessions.**

Every session produces a SHA-256 hash-chained ledger. Any post-hoc modification — even a single character — is detectable. Nothing leaves your machine.

```
sasana verify ~/.openclaw/sasana/<session_id>.jsonl

Sasana Verifier v1.0.0
================================
File     : abc123.jsonl
Session  : abc123...
Events   : 12
Evidence : NON_AUTHORITATIVE_EVIDENCE

[1/4] Structural validity  ... PASS
[2/4] Sequence integrity   ... PASS
[3/4] Hash chain integrity ... PASS
[4/4] Session completeness ... PASS

Result: INTACT ✅
```

## Why

OpenClaw, LangGraph, CrewAI, and AutoGPT all produce mutable local logs with zero tamper-evidence. An attacker with file-system access can silently rewrite your agent's session history — and you'd never know.

Sasana makes that detectable.

## Install

```bash
# As an OpenClaw skill (recommended)
openclaw skill install sasana

# Or directly
pip install sasana
```

## Quick start — OpenClaw skill

Install once, then every session is automatically audited:

```bash
openclaw skill install sasana
# Every session now produces:
#   ~/.openclaw/sasana/<session_id>.db
#   ~/.openclaw/sasana/<session_id>.jsonl

# Verify any session:
sasana verify ~/.openclaw/sasana/<session_id>.jsonl
```

## Quick start — passive observer (zero OpenClaw changes)

```bash
pip install sasana[observer]
sasana observe  # auto-detects OpenClaw WebSocket port
```

## Verify with the Rust binary (zero Python dependency)

```bash
cd sasana-rs
cargo build --release
./target/release/sasana verify <session.jsonl>
```

## How it works

Each event is committed to SQLite with:
- **SHA-256 hash** of the event (RFC 8785 canonical JSON)
- **`prev_hash`** linking to the previous event — forming an immutable chain
- **Ed25519 signature** over the hash (optional, per-session keypair)

Raw content (prompts, responses, tool args) is **never stored** — only SHA-256 hashes.

## Evidence classes

| Class | Meaning |
|---|---|
| `NON_AUTHORITATIVE_EVIDENCE` | Local hash chain only — proves internal consistency |
| `SIGNED_NON_AUTHORITATIVE_EVIDENCE` | + Ed25519 signatures — requires private key to forge |
| `AUTHORITATIVE_EVIDENCE` | + server-sealed (Archeion) — independent third-party verification |

## Compliance

- **SOC 2 CC7.2** — active requirement for system monitoring
- **EU AI Act Article 12** — automatic recording of AI system events
- **HIPAA** — audit trail requirements for healthcare AI agents

## Privacy

Sasana stores **hashes only** — never raw prompts, responses, or tool arguments.

```
stores_content:       false
stores_hashes_only:   true
cloud_dependency:     false
network_required:     false
```

## License

MIT
