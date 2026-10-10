# Sasana

**Your AI agent logs are not evidence. Sasana makes them defensible.**

Every major observability tool — LangSmith, Arize, Langfuse — stores logs in mutable,
operator-controlled storage. An administrator with file-system or database access can
modify or delete a record with no detectable trace. Those logs satisfy a reporting
requirement. They do not prove what happened.

Sasana records a SHA-256 hash-chained audit trail: editing, inserting, deleting or
reordering any event breaks the chain and `sasana verify` reports it. Raw content never
leaves your machine: only hashes are stored.

**What the chain alone does not do.** Someone with write access to the file can edit an
event *and* recompute every hash after it; the result is a different, internally
consistent chain. Detecting that needs an independent seal from [Archeion](#authority-sealing)
**verified against a public key you pinned** with `--trust-key`. Without the pin, a seal
only proves the file is self-consistent — anyone can generate a key and seal a rewritten
log. Read the [evidence class](#what-it-produces), not just the word `INTACT`.

```
$ sasana verify session.jsonl --trust-key <archeion-pubkey> --strict

Sasana Verifier v2.0.0
File: session.jsonl
Session: 3f8a2c1d-…
Events: 5  Evidence: AUTHORITATIVE_EVIDENCE
Trusted key: pinned (--trust-key)

[1/5] Structural validity  ... PASS
[2/5] Sequence integrity   ... PASS
[3/5] Hash chain integrity ... PASS
[4/5] Session completeness ... PASS
[5/5] Seal signature       ... PASS  (signed by the pinned key)

Result: INTACT ✅
```

---

## Who this is for

Teams deploying AI agents in regulated environments — fintech, healthtech, HR tech.
Specifically:

- Compliance engineers implementing **EU AI Act Article 12** (automatic event logging for
  high-risk AI systems) who want integrity evidence on top of the log
- Security teams who need a cryptographically verifiable audit trail for incident response
- DevSecOps engineers who need to detect whether a session log was modified after it ended
  (a complete rewrite is detectable only with a pinned Archeion seal)

If you are building an AI agent for a use case that falls under GDPR, SOC 2, HIPAA, or
EU AI Act audit requirements, Sasana is the audit layer.

---

## What it produces

A completed session produces a JSONL file. The verifier checks the structure, sequence,
hash chain, session bookends and (if present) the seal, and returns one of four results:

| Result | Meaning |
|---|---|
| `INTACT` | All checks pass: the file is internally consistent. **How much that proves is given by the evidence class below.** |
| `PARTIAL` | Hash chain intact but events were dropped during the session (`LOG_DROP`). |
| `COMPROMISED` | An integrity check failed (broken chain, bad or untrusted seal, missing required seal, …). |
| `ERROR` | The input could not be assessed (empty file, not JSONL, wrongly-typed fields). Never a pass. |

Exit codes — parse the JSON `status` and `evidence_class` rather than relying on the exit
code alone, because `0` also covers `INTACT` with a weak evidence class:

| Code | Meaning |
|---|---|
| `0` | `INTACT` |
| `1` | `COMPROMISED` |
| `2` | `PARTIAL` |
| `3` | `ERROR`, or bad usage (including an unrecognised flag) |
| `4` | `--strict` only: `INTACT` but not `AUTHORITATIVE_EVIDENCE` |

`--json` prints the full result: status, evidence class, per-check results, errors,
warnings, whether a key was pinned, whether a seal is present and trusted, and the
timestamp check.

The evidence class tells you how strong the guarantee is (strongest first):

| Class | Meaning |
|---|---|
| `AUTHORITATIVE_EVIDENCE` | The log carries a `CHAIN_SEAL` that verified against the Archeion public key **you pinned** with `--trust-key`. Only then does the sealing authority, rather than whoever holds the file, vouch for the chain head. |
| `SELF_SEALED_EVIDENCE` | A well-formed `CHAIN_SEAL` that verifies only against the key embedded in the seal itself. **Anyone can produce this**; it does not show who sealed the log. The CLI prints a warning. |
| `SIGNED_NON_AUTHORITATIVE_EVIDENCE` | Per-event Ed25519 signatures verify against a session key embedded in the log. They show consistency, not identity: a complete rewrite under a fresh key verifies equally well. |
| `NON_AUTHORITATIVE_EVIDENCE` | Hash chain intact, no seal. Detects edits to individual events; **cannot detect a complete rewrite** of the file. |
| `PARTIAL_EVIDENCE` | The session recorded dropped events. |
| `NO_EVIDENCE` | `COMPROMISED` or `ERROR`. |

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

This checks internal consistency only. For a verdict you can rely on against someone who
can write to the file, seal the session with Archeion and verify with
`--trust-key` (see [Authority sealing](#authority-sealing)).

Passive observer (zero code changes required):

```bash
pip install sasana[observer]
sasana observe  # auto-detects OpenClaw WebSocket port
```

Already using OpenTelemetry? Keep your existing tracing (LangSmith, Langfuse, Datadog,
OTLP) and get a hash-chained evidence ledger underneath — one session per trace:

```bash
pip install sasana[otel]
```

```python
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from sasana.integrations.otel import SasanaSpanExporter

provider.add_span_processor(BatchSpanProcessor(SasanaSpanExporter()))
```

---

## Evidence packs

Turn any verified session into the artifact an auditor actually reads — a self-contained
report plus a machine-readable manifest anyone can re-verify:

```bash
sasana evidence-pack session.jsonl --standard eu_ai_act
```

Writes `<session>_eu_ai_act_art12.html` (the report) and `.json` (re-verifiable
independently with `sasana verify`). Standards: `eu_ai_act`, `soc2`, `hipaa`, `siem`.
Exit codes `0` (compliant) / `2` (gaps) / `3` (error) for CI.

Pass `--trust-key <archeion-pubkey>` so the report can show the session as sealed by your
Archeion; without it a seal is reported as self-sealed and the evidence class is not
`AUTHORITATIVE_EVIDENCE`. "Compliant" here means the report's checklist passed. It is not a
legal determination.

Try it with no install at **[sasana.site/verify](https://sasana.site/verify)** — paste a
session and the hash chain + Article 12 checks run live in your browser.

---

## Authority sealing

`NON_AUTHORITATIVE_EVIDENCE` means the operator is attesting their own logs, and anyone
who can write the file can rebuild the chain. That is weak when the operator is a party to
a dispute.

[Archeion](archeion/) is a sealing server you run inside your security perimeter,
structurally separate from the agent process. It appends a signed `CHAIN_SEAL` over the
chain head. The agent never holds Archeion's private key, so it cannot produce a seal that
verifies against Archeion's public key.

**The seal is only as trustworthy as the key you check it against.** The public key is
embedded in the seal, so a verifier that does not already know Archeion's key cannot tell
Archeion from an attacker who generated a fresh key and re-sealed a rewritten log. Record
Archeion's public key out-of-band when you deploy it (`GET /pubkey`, over a channel you
trust) and pin it:

```bash
# Start Archeion (self-hosted, inside your perimeter)
docker compose up -d

# Seal a completed session
sasana seal session.jsonl --server http://localhost:8747

# Verify. --trust-key requires a seal signed by exactly this key, and is the only way to
# get AUTHORITATIVE_EVIDENCE. --strict makes anything weaker exit 4.
sasana verify session.jsonl --trust-key <archeion-pubkey> --strict
```

| How you verify | Rewrite + re-seal with an attacker key | Seal stripped |
|---|---|---|
| `--trust-key K` | `COMPROMISED` (untrusted key) | `COMPROMISED` (pinned key but no seal) |
| `--require-seal` (no key) | `INTACT`, `SELF_SEALED_EVIDENCE` — not detected | `COMPROMISED` (seal required) |
| neither | `INTACT`, `SELF_SEALED_EVIDENCE` — not detected | `INTACT`, `NON_AUTHORITATIVE_EVIDENCE` — not detected |

For regulatory submissions and legal proceedings, verify with `--trust-key` (and
`--strict` in automation). Use `--require-seal` on its own only when you cannot pin a key,
knowing the best result is `SELF_SEALED_EVIDENCE`.

A seal also proves nothing about whether the recorded events are true or complete — only
that this chain head was presented to the sealing key and has not changed since.

Version 1.0.0 and 1.1.0 treated any valid seal as `AUTHORITATIVE_EVIDENCE` and accepted a
log whose seal had been removed even when a key was pinned; see the
[changelog](CHANGELOG.md#120--2026-10-10).

See [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) for the full deployment guide — key
lifecycle, network isolation, and what to tell a security reviewer.

---

## Timestamps

When a session opens, Sasana sends the SHA-256 hash of `SESSION_START` — never content —
to an RFC 3161 time-stamp authority (FreeTSA by default; set `SASANA_TSA_URL` to change it)
and embeds the returned token. This is fail-open: if the TSA is unreachable the session is
recorded without a token.

`sasana verify` checks only that the token's MessageImprint matches the recomputed
`SESSION_START` hash, and reports `IMPRINT_MATCH`. **It does not verify the TSA's
signature, the certificate chain, or that the time in the token is genuine**, so a forged
or backdated token passes. Treat the reported time as a claim, not as proof of when the
session happened. A strict verifier exists as a library function
(`sasana.rfc3161.verify_timestamp_strict`, used by `sasana verify-commitment`) but is not
part of `sasana verify`.

---

## How it works

Each event is stored with:

- **SHA-256 hash** over RFC 8785 canonical JSON — any mutation changes the hash
- **`prev_hash`** — each event commits to all prior events, forming a chain
- **Ed25519 signature** — optional per-session keypair; or Archeion's independent key

Raw content is **never stored** — only hashes. You cannot reconstruct what the agent said
from a Sasana log.

A Rust binary (`sasana-rs/`) verifies sessions without a Python dependency — for forensic
environments where Python is not present or trusted. It follows the same trust model
(pinned key, `--require-seal`, `--strict`, `SELF_SEALED_EVIDENCE`) as the Python verifier
v2.0.0 and is tested against the same tamper cases. It does not check RFC 3161 tokens or
per-event signatures, and its `--json` output has no per-check breakdown.

---

## Compliance mapping

| Regulation | Requirement addressed |
|---|---|
| EU AI Act Article 12 | Automatic event recording for high-risk AI systems, with integrity evidence |
| SOC 2 CC7.2 | System monitoring with a hash-chained, verifiable audit trail |
| HIPAA §164.312(b) | Audit control for healthcare AI; raw PHI never recorded |

These map Sasana's output to the requirement text. They are not a certification or legal
advice; whether a system complies is a determination for you and your auditor.

---

## What Sasana does not do

- **Does not record raw content.** Hashes only — you cannot reconstruct prompts or
  responses.
- **Does not prevent tampering.** Detects it, within limits: a rewrite of the whole file is
  detected only with a seal verified against a pinned Archeion key. Detection and
  prevention are different.
- **Does not prove when a session happened.** Timestamp checking is an imprint match only;
  the TSA signature and claimed time are not verified.
- **Does not prove the recorded events are true.** It proves what was recorded has not
  changed since sealing, not that the agent reported honestly.
- **Does not replace LangSmith or Arize.** Those tools are for observability. Sasana is
  for evidence production. They are complementary.
- **Does not have a managed cloud offering.** Self-hosted only.

---

## License

MIT
