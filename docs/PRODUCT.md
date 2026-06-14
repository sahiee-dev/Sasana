# Sasana — Product Document

## The Problem

Every major AI agent observability tool — LangSmith, Arize, Langfuse, W&B, Helicone, Datadog — records what your agent did. None of them can prove it.

The logs these tools produce are mutable files sitting on a file system or in a database controlled by the same operator who runs the agent. An attacker with file-system access, a database administrator, or even the agent developer themselves can alter those logs after the fact — silently, without any trace. There is no structural guarantee that what you see in the log reflects what actually happened during the session.

This distinction matters in three situations:

1. **Regulatory audit** — A regulator asks for evidence that your high-risk AI system behaved correctly. You hand over logs. The regulator cannot tell whether those logs were edited before submission.

2. **Incident investigation** — Something went wrong. Your agent may have made a harmful decision. You need to prove what actually happened — or prove that you don't know because logs were dropped or modified.

3. **Legal proceedings** — A counterparty disputes what your AI agent agreed to or communicated. Your logs are the only record. Their admissibility depends on whether they constitute reliable evidence.

LangSmith tells you what happened. It cannot prove it.

---

## What Sasana Is

Sasana is a tamper-evident cryptographic audit trail for AI agent sessions.

It does not record what your agent said. It records that your agent said something, and cryptographically commits to that record in a way that makes any subsequent modification detectable. Any post-hoc change — to a single character in a single event — breaks the hash chain and is detected on the next verification.

The core guarantee: if `sasana verify` reports `INTACT`, the session log has not been altered since it was recorded. This is a mathematical guarantee, not a policy guarantee.

---

## How It Works — In Plain Terms

When a session starts, Sasana creates a ledger. Every event in the session is:

1. Assigned a sequence number
2. Given a SHA-256 hash computed from its own content
3. Linked to the previous event's hash (forming a chain)
4. Written immediately to SQLite with crash-safe settings (WAL mode, synchronous=FULL)

Raw content — prompts, responses, tool arguments, tool results — is **never stored**. Only SHA-256 hashes of that content are recorded. This satisfies tamper-evidence requirements while preserving data minimisation obligations.

When the session ends, the ledger is exported to a portable JSONL file. That file can be verified by anyone — offline, without contacting any server — using the `sasana verify` command or the Rust binary.

Optionally, a completed session can be submitted to **Archeion**, a self-hosted authority sealing server. Archeion appends a signed `CHAIN_SEAL` event to the log using its own Ed25519 keypair, upgrading the evidence class to `AUTHORITATIVE_EVIDENCE`. Because Archeion holds the sealing key — and the agent process never does — even a fully compromised agent cannot forge a valid seal.

---

## Evidence Classes

Sasana does not produce binary pass/fail output. It produces an evidence class that describes how much a court, regulator, or auditor can trust the log.

| Class | What it means | When you get it |
|---|---|---|
| `AUTHORITATIVE_EVIDENCE` | Independent third-party sealed. The agent could not have forged this. | Session sealed by Archeion |
| `SIGNED_NON_AUTHORITATIVE_EVIDENCE` | Per-session Ed25519 signatures present. Requires the private key to forge. | SDK signing enabled |
| `NON_AUTHORITATIVE_EVIDENCE` | Local hash chain only. Proves internal consistency. | Default for all sessions |
| `PARTIAL_EVIDENCE` | Valid chain, but LOG_DROP events indicate gaps. | Events were dropped during recording |
| `NO_EVIDENCE` | Chain is broken or structurally invalid. | Verification failed |

`NON_AUTHORITATIVE_EVIDENCE` is still meaningful — it proves that the log has not been modified since it was written, assuming the writing process was not compromised. For most internal audit and compliance purposes this is sufficient. `AUTHORITATIVE_EVIDENCE` is required when you need to prove to an external party that the log was not edited by the operator.

---

## What Sasana Does Not Do

Being precise about scope is important.

**Sasana does not record raw content.** It records SHA-256 hashes of prompts, responses, and tool arguments. You cannot reconstruct what the agent said from the Sasana log. The log proves that a specific piece of content existed at a specific point in the session; it does not preserve that content.

**Sasana does not prevent tampering.** It detects it. An attacker with write access to the ledger can still delete or modify events. What they cannot do is make those modifications invisible to verification. Every modification breaks the chain.

**Sasana does not replace your observability tool.** It is complementary. Your existing tool tells you what happened and helps you debug. Sasana proves what happened for audit, compliance, and legal purposes.

**Sasana does not rate-limit or filter agent actions.** It is a passive recording system. It observes and records; it does not intervene.

**Sasana does not currently have a managed cloud offering.** The entire system — SDK, ledger, verifier, and Archeion — runs on your infrastructure. This is a deliberate design choice explained below.

---

## Target Audience

### Primary: AI teams at regulated companies

Companies deploying AI agents in financial services, healthcare, legal, or any domain where the EU AI Act classifies the system as high-risk. These teams have a specific problem: regulators and auditors are beginning to ask for tamper-evident evidence that their AI systems behaved correctly. No current observability tool provides this.

They are technically sophisticated — they can integrate a Python SDK and deploy a Docker container — but they are not cryptographers. The abstractions need to be clear without requiring deep cryptographic knowledge.

**Why they buy:** EU AI Act Article 12 enforcement begins August 2, 2026. HIPAA PHI attribution requirements are active. SOC 2 CC7.2 is in every audit questionnaire that involves AI. These are not hypothetical future requirements.

### Secondary: Compliance and legal teams at enterprises

The audit and legal functions at companies where AI agents handle consequential decisions. These people are not developers. They care about:
- Can I show a regulator evidence that our AI behaved correctly?
- If something goes wrong, do I have a defensible record?
- Does our audit trail satisfy the specific requirements of the regulation we operate under?

The compliance exports (EU AI Act, SOC 2, HIPAA, SIEM) are built specifically for this audience. They produce structured reports and HTML artifacts that a compliance officer can submit to an auditor without needing to understand the cryptographic details.

### Tertiary: Security and forensics teams

Teams investigating AI incidents — where an agent made a harmful decision, leaked information, or was used in an attack. These users need to reconstruct exactly what happened, verify that the log has not been tampered with, and produce evidence for legal or regulatory proceedings.

The Rust verifier (`sasana-rs`) is built for this use case: it has zero Python dependency and can run in isolated forensic environments.

---

## How We Plan to Achieve It

### Current state (as of June 2026)

The core product is complete:
- Python SDK (v1.0.0) with SQLite ledger, hash chain, Ed25519 signing
- OpenClaw skill integration (`SasanaSkill`)
- Passive WebSocket observer
- Integrations for LangGraph, CrewAI, AutoGPT
- 5-check Python verifier
- Rust verifier (cross-language, zero Python dependency)
- Archeion authority sealing server (FastAPI)
- Compliance exports for EU AI Act Art. 12, SOC 2 CC7.2, HIPAA §164.312(b), SIEM
- CLI (`sasana verify`, `sasana seal`, `sasana observe`)
- 117 tests passing, CI green on Python 3.10 and 3.12

### Near-term (next 3 months)

**Credibility before outreach.** Before approaching anyone, the product needs to be presented clearly. This means:

1. A README that leads with the problem, not the architecture. Currently the README explains how Sasana works before explaining why anyone would need it.

2. One substantive technical article explaining why existing observability tools don't produce legally admissible evidence, what EU AI Act Article 12 actually requires, and how Sasana addresses it. This is written for the technical decision-maker at a company trying to become compliant before August 2, 2026.

3. Explicit alignment documentation with the IETF Agent Audit Trail draft (`draft-sharif-agent-audit-trail-00`, March 2026). Sasana's architecture closely matches the emerging standard. This is a credibility signal for compliance buyers who are researching the space.

**First users.** The GTM strategy is not enterprise sales — that requires relationships and sales cycles that are too slow. It is:
- Developer discovery through the technical article and GitHub
- Compliance consultancy partnerships — firms helping companies achieve EU AI Act compliance need a technical product to recommend. We are that product.
- Inbound from the article, before cold outreach of any kind.

### Deployment model

Sasana is self-hosted. This is the right choice for the target audience:
- BFSI and healthcare companies cannot send session hashes to a third-party cloud service without legal review. Even hashes of patient or financial data have compliance implications.
- The authority separation model requires that the agent operator and the sealing authority are structurally different. A single startup running both the SDK and a cloud sealing service does not provide meaningful separation.
- A solo developer cannot responsibly operate compliance-critical SaaS infrastructure with the uptime and security guarantees enterprise buyers require.

The analogy is HashiCorp Vault — organisations run Vault inside their own perimeter to manage secrets. Similarly, organisations run Archeion inside their own perimeter to provide an independent sealing authority for their AI agents. Revenue comes from deployment support, enterprise consulting, and future managed-deployment assistance, not per-seal fees.

---

## Parameters and Constraints

**What Sasana guarantees:** If `verify` reports `INTACT`, the log has not been modified since it was written. This is a cryptographic guarantee.

**What Sasana does not guarantee:** That the agent was honest when writing the log. A malicious agent can write false records into the hash chain. Sasana makes those false records immutable and attributable, but it cannot detect lies told at write time. The AUTHORITATIVE_EVIDENCE class reduces (but does not eliminate) this concern because the agent and the sealing authority are structurally separated — the agent cannot forge a seal it did not earn.

**Performance:** The SQLite ledger uses WAL mode and `synchronous=FULL`. This means every event write is crash-safe but involves a file sync. On typical hardware this is measured in milliseconds per event. It is not suitable for extremely high-frequency event streams (thousands of events per second per session) without modification.

**Language support:** The SDK is Python 3.10+. The Rust verifier is language-independent and can verify any log produced by the Python SDK. Integrations for LangGraph, CrewAI, and AutoGPT exist. Other frameworks are not yet supported.

**Storage:** One SQLite `.db` file and one JSONL file per session. The JSONL file is the portable artifact. Both live on local disk by default.

**Cryptographic algorithm choices:** SHA-256 for hashing (RFC 8785 canonical form), Ed25519 for signatures. Both are well-established, widely supported, and align with the IETF AAT draft. No post-quantum algorithms are implemented. This is consistent with the current threat model but is a known limitation as post-quantum migration timelines approach.
