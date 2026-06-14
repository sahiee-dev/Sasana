# Sasana

**Your AI agent logs are not evidence. Sasana makes them defensible.**

Every major observability tool — LangSmith, Arize, Langfuse — stores logs in mutable,
operator-controlled storage. An administrator with file-system or database access can
modify or delete a record with no detectable trace. Those logs satisfy a reporting
requirement. They do not prove what happened.

Sasana records a SHA-256 hash-chained audit trail where any modification — to any byte,
in any historical event — is detectable. Raw content never leaves your machine: only
hashes are stored.

```
$ sasana verify session.jsonl --trust-key <archeion-pubkey>

Sasana Verifier v1.0.0
File     : session.jsonl
Session  : 3f8a2c1d-…
Events   : 7
Evidence : AUTHORITATIVE_EVIDENCE

[1/5] Structural validity  ... PASS
[2/5] Sequence integrity   ... PASS
[3/5] Hash chain integrity ... PASS
[4/5] Session completeness ... PASS
[5/5] Seal signature       ... PASS

Result: INTACT ✅
```

---

## Who this is for

Teams deploying AI agents in regulated environments — fintech, healthtech, HR tech.
Specifically:

- Compliance engineers implementing **EU AI Act Article 12** (tamper-evident logging for
  high-risk AI systems)
- Security teams who need a cryptographically verifiable audit trail for incident response
- DevSecOps engineers who need to prove a session log has not been touched since it ended

If you are building an AI agent for a use case that falls under GDPR, SOC 2, HIPAA, or
EU AI Act audit requirements, Sasana is the audit layer.

---

## What it produces

A completed session produces a JSONL file. The verifier checks five properties and
returns one of three results:

| Result | Meaning |
|---|---|
| `INTACT` | All checks pass. The log has not been modified. |
| `PARTIAL` | Hash chain intact but events were dropped during the session. |
| `COMPROMISED` | Hash chain broken. Log has been modified after the fact. |

Exit codes: `0` (INTACT), `1` (COMPROMISED), `2` (PARTIAL), `3` (ERROR) — suitable for
CI pipeline integration.

The evidence class tells you how strong the guarantee is:

| Class | Meaning |
|---|---|
| `AUTHORITATIVE_EVIDENCE` | Independent sealing authority verified this log. The agent could not have forged this. |
| `SIGNED_NON_AUTHORITATIVE` | Ed25519 signatures present. Requires private key to forge. |
| `NON_AUTHORITATIVE_EVIDENCE` | Hash chain intact. Proves no post-hoc modification. |

---

## Install

```bash
pip install sasana
```

### Install via OpenClaw

```bash
# Via GitHub URL
openclaw skill install https://github.com/sahiee-dev/Sasana

# Via skills.sh shorthand (when listed in the registry)
openclaw skill install sahiee-dev/Sasana/sasana
```

Every session automatically produces `~/.openclaw/sasana/<session_id>.jsonl`.
No configuration required.

---

## Quick start

```python
from sasana.sqlite_ledger import SqliteLedger
import hashlib

def sha256(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()

ledger = SqliteLedger(db_path="session.db")
ledger.connect()
ledger.open_session(session_id="my-session", agent_id="my-agent")
ledger.record("LLM_CALL",     {"prompt_hash":   sha256(prompt)})
ledger.record("LLM_RESPONSE", {"response_hash": sha256(response)})
ledger.close_session(status="success")
ledger.export_jsonl("session.jsonl")
ledger.close()
```

Verify:

```bash
sasana verify session.jsonl
```

Passive observer (zero code changes required):

```bash
pip install sasana[observer]
sasana observe  # auto-detects OpenClaw WebSocket port
```

---

## Authority sealing

For regulatory submissions and legal proceedings, `NON_AUTHORITATIVE_EVIDENCE` means the
operator is attesting their own logs. That is insufficient when the operator is a party
to a dispute.

[Archeion](archeion/) is a sealing server that runs inside your security perimeter,
controlled by your security team — structurally separate from the agent process. The
agent cannot forge a seal. The sealed log carries `AUTHORITATIVE_EVIDENCE`.

```bash
# Start Archeion (self-hosted, inside your perimeter)
docker compose up -d

# Seal a completed session
sasana seal session.jsonl --server http://localhost:8747

# Verify with key pinning
sasana verify session.jsonl --trust-key <archeion-pubkey>
```

See [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) for the full deployment guide — key
lifecycle, network isolation, and what to tell a security reviewer.

---

## How it works

Each event is stored with:

- **SHA-256 hash** over RFC 8785 canonical JSON — any mutation changes the hash
- **`prev_hash`** — each event commits to all prior events, forming a chain
- **Ed25519 signature** — optional per-session keypair; or Archeion's independent key

Raw content is **never stored** — only hashes. You cannot reconstruct what the agent said
from a Sasana log.

A Rust binary (`sasana-rs/`) verifies sessions without a Python dependency — for forensic
environments where Python is not present or trusted.

---

## Compliance mapping

| Regulation | Requirement addressed |
|---|---|
| EU AI Act Article 12 | Tamper-evident automatic recording for high-risk AI systems |
| SOC 2 CC7.2 | System monitoring with cryptographically verifiable audit trail |
| HIPAA §164.312(b) | Audit control for healthcare AI; raw PHI never recorded |

---

## What Sasana does not do

- **Does not record raw content.** Hashes only — you cannot reconstruct prompts or
  responses.
- **Does not prevent tampering.** Detects it. Detection and prevention are different.
- **Does not replace LangSmith or Arize.** Those tools are for observability. Sasana is
  for evidence production. They are complementary.
- **Does not have a managed cloud offering.** Self-hosted only.

---

## License

MIT
