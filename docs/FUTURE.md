# Sasana — Future Plan

This document describes where Sasana is today, what is missing, and what the realistic path forward looks like. It is written to be honest about what is not yet built and what is uncertain.

---

## Where We Are Now (June 2026)

The core cryptographic system is complete and correct. A session recorded by the SDK produces a JSONL file that:

- Has a verified SHA-256 hash chain (RFC 8785 canonical JSON)
- Can be verified offline, without network access, in under a second
- Can be sealed by Archeion to upgrade to `AUTHORITATIVE_EVIDENCE`
- Passes 117 automated tests on Python 3.10 and 3.12

What exists:
- Python SDK v1.0.0
- OpenClaw skill and passive observer
- LangGraph, CrewAI, AutoGPT integrations
- 5-check Python verifier
- Rust verifier (4 checks)
- Archeion authority sealing server
- Compliance exports (EU AI Act Art. 12, SOC 2 CC7.2, HIPAA §164.312(b), SIEM)
- CLI (`sasana verify`, `sasana seal`, `sasana observe`)

What does not exist:
- A user-facing website or landing page
- Any documentation aimed at non-developers
- A deployment guide for Archeion (Docker image, configuration reference)
- Any paying customers or users
- Any commercial relationship with a compliance consultancy
- A way for someone to discover Sasana without knowing to search for it

The gap between the technical state and the commercial state is large. The product works. Nobody knows about it.

---

## What Needs to Happen Before Anything Else

### 1. Presentation layer

The current README explains the architecture. It does not explain the problem in terms that a compliance officer or legal team would recognise. Before any outreach, the README needs to lead with the problem: your AI agent logs are not evidence, here is why, here is what changes that.

This is a one-time rewrite, not an ongoing investment. It should be done before the next commit goes to GitHub.

### 2. One substantive technical article

The EU AI Act Article 12 enforcement deadline is August 2, 2026. Companies in active compliance cycles are researching this right now. A technically accurate article explaining:

- What Art. 12 actually requires (automatic recording of events with tamper-evidence)
- Why existing observability tools (LangSmith, Arize, etc.) do not satisfy this requirement
- What a compliant solution looks like
- How Sasana addresses it

This article should not be marketing. It should be a genuine technical explanation that would be useful to a compliance engineer trying to understand the requirement. It should cite the regulation text, the IETF AAT draft, and be accurate about what Sasana does and does not do.

The goal is to be discoverable when someone searches for "EU AI Act Article 12 audit trail" or "tamper-evident AI logs compliance."

---

## Phase 5 — Archeion Deployment Packaging

**What the phase delivers:** A deployable Archeion package that a security or DevOps team can stand up in 30 minutes, with clear documentation about key management, network isolation, and operational requirements.

Currently, Archeion is a FastAPI server that can be started with `archeion` or `uvicorn archeion.server:app`. It is functional but not packaged for production deployment.

What needs to be built:
- Dockerfile for Archeion (`FROM python:3.12-slim`, non-root user, health endpoint)
- `docker-compose.yml` example showing Archeion behind a reverse proxy with TLS
- Deployment guide covering:
  - Key management (env var vs. file, rotation procedure)
  - Network isolation (Archeion should not be on the public internet; it should be accessible only to internal systems)
  - Key pinning (how clients verify the server's public key before trusting a seal)
  - Backup and recovery for the server key (if the key is lost, sealed sessions cannot be re-verified)
- `GET /health` endpoint for load balancer and monitoring probes

**What this is not:** A managed SaaS. The intent is that the customer runs Archeion inside their own network, managed by their security team, isolated from the agent developers. The Dockerfile is a packaging convenience, not a cloud deployment.

**Why this matters:** The deployment guide is the product for enterprise buyers. The code works; the question is whether a security team at a bank or hospital can confidently deploy it. Without a clear deployment story, the gap between "this is interesting" and "we will use this in production" is too wide.

---

## Phase 6 — Seal Signature in Rust Verifier

**What the phase delivers:** Full parity between the Python and Rust verifiers.

Currently the Rust verifier does not verify Ed25519 seal signatures (check 5). It reports `AUTHORITATIVE_EVIDENCE` based on the presence of a `CHAIN_SEAL` event without verifying the signature. This is incorrect for forensic use — a forged seal would pass the Rust verifier.

What needs to be built:
- Ed25519 signature verification in Rust (using `ed25519-dalek` or `ring` crate)
- The same check-5 logic as the Python verifier: if `CHAIN_SEAL` is present, extract `server_pubkey` from payload, verify `signature` against `event_hash`
- A `--trust-key <base64 pubkey>` CLI flag that pins the expected server public key (optional but useful for forensic workflows where the analyst knows what key the Archeion instance used)

This is a bounded, well-defined task. The algorithm is already specified by the Python implementation.

---

## Phase 7 — Additional Framework Integrations

**What the phase delivers:** Integrations for frameworks that have significant adoption among teams likely to need compliance audit trails.

Current integrations: LangGraph, CrewAI, AutoGPT (via `sasana/integrations/`).

Candidates for addition, roughly in priority order based on adoption:
- **LangChain** — largest Python LLM framework; callbacks interface is well-documented. Note: LangSmith is LangChain's observability product, so this integration competes directly in their ecosystem.
- **Semantic Kernel** — Microsoft's framework; relevant for enterprise Windows deployments and Azure AI customers
- **DSPy** — Stanford research framework gaining production adoption
- **Haystack** — common in document-heavy enterprise use cases

Each integration follows the same pattern as the existing ones: translate framework callbacks to the Sasana `SqliteLedger` API. The main complexity is usually around session lifecycle (when does a session start and end in that framework's model) and mapping framework-specific event structures to Sasana payload fields.

None of these should be built speculatively. Build each integration when there is a concrete user who needs it.

---

## Phase 8 — Cross-Session Capabilities

**What the phase delivers:** Capabilities that operate across multiple sessions rather than within a single session.

This is not planned for the near term. It is listed here because it represents a meaningful expansion of scope that would require architectural decisions now to not foreclose later.

Possible future capabilities in this category:
- **Session index:** A SQLite or flat-file index of all sessions for a given agent, with their verification status and evidence class. Currently there is no way to ask "show me all sessions from agent X that are AUTHORITATIVE."
- **Cross-session hash chaining:** Linking the root hash of session N into the genesis of session N+1. This would allow verification that no sessions were dropped from the history of an agent. This is a significant protocol change and should not be added without a clear requirement.
- **Batch verification:** `sasana verify --dir ~/.openclaw/sasana/` to verify all sessions in a directory and produce a summary report.

These are not committed future work. They are possibilities.

---

## What We Are Not Planning to Build

**Managed cloud sealing service.** Not planned. The reasons are explained in the product document: the target audience cannot send data to third-party cloud services, and a solo developer cannot operate compliance-critical infrastructure at enterprise uptime requirements. This decision may be revisited if the situation changes substantially (e.g., a team is in place, enterprise SLAs are negotiated), but it is not a current goal.

**Agent interception or content analysis.** Sasana records what happened. It does not analyse content, detect policy violations, or rate-limit agent actions. That is a different product category (AI safety / guardrails) and is not a direction we are heading.

**A UI dashboard.** Compliance reports are generated as HTML. There is no web dashboard for browsing sessions. This may eventually be useful, but it is not a near-term priority and is not needed to deliver value to the target audience.

**Post-quantum cryptography migration.** Not planned for 2026. SHA-256 and Ed25519 are adequate for the current threat model. Post-quantum migration will need to happen eventually, but the NIST PQC standards are still in their first year of publication and tooling is immature. This is a known future obligation, not an immediate one.

---

## Honest Assessment of What Could Go Wrong

**The compliance market moves slowly.** Enterprise compliance buying cycles are 6–18 months. The EU AI Act enforcement deadline creates urgency, but urgency in compliance does not mean rapid procurement. It is realistic that the first revenue from Sasana comes 9–12 months after first contact with a potential customer.

**The IETF AAT draft may not become a standard.** The IETF draft is from March 2026 and is at an early stage. If it stalls or the working group takes a different direction, the "aligns with the emerging standard" positioning weakens. This is a risk, not a certainty.

**Competing products may close the gap.** Asqav, AgentMint, and Microsoft AGT are all moving in this space. None of them currently have the authority separation model. That could change. The structural moat (Archeion's independent sealing authority) is real but not permanent — competitors can implement the same model.

**The OpenClaw ecosystem may not grow.** The primary integration is with OpenClaw. If OpenClaw does not gain meaningful adoption, the skill integration is not a useful distribution channel. The framework-agnostic SDK (`SqliteLedger` directly) and the other framework integrations are the fallback.

**Solo maintainer risk.** This is a one-person project. Technical debt, burnout, or competing priorities can stall development. The most important mitigation is keeping the scope disciplined: finish what is started before beginning the next thing, and do not add features that are not needed.

---

## Realistic 12-Month View

| Timeframe | Milestone | Confidence |
|---|---|---|
| July 2026 | README rewrite, technical article published | High |
| August 2026 | Archeion deployment guide (Phase 5) | High |
| September 2026 | First inbound inquiry from article | Uncertain |
| October 2026 | Rust seal signature check (Phase 6) | High |
| Q4 2026 | First pilot engagement with a compliance consultancy | Uncertain |
| Q1 2027 | One paying enterprise pilot | Low confidence — sales cycles are long |

The "High confidence" items are things we control. The "Uncertain" items depend on market response and timing. The honest position is: the core product works and is differentiated; whether it finds paying users in 12 months depends on execution of the non-technical parts (writing, outreach, relationships) more than on the technical parts.

---

## What Success Looks Like

In 12 months, success is not a large revenue number. It is:

1. At least one enterprise team using Sasana in a production compliance workflow
2. Archeion deployed inside at least one organisation's security perimeter
3. The technical article cited or linked to by at least one compliance consultancy or regulator resource
4. A clear understanding of what the next significant feature request actually is (as told by users, not assumed)

These are achievable targets that do not require the product to be perfect. They require the product to be known, understandable, and trustworthy enough for one organisation to commit to using it.
