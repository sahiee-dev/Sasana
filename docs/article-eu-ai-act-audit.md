---
title: Your AI agent logs satisfy Article 12. They won't survive a dispute.
published: false
tags: ai, security, python, compliance
cover_image:
canonical_url:
---

# Your AI agent logs satisfy Article 12. They won't survive a dispute.

---

## What Article 12 actually says

The regulation text is precise: "High-risk AI systems shall be designed and developed
with capabilities enabling the automatic recording of events ('logs') throughout the
lifetime of the AI system."

One piece of context compliance consultants should have before reading further: the
Digital Omnibus provisional agreement reached on 7 May 2026 moved the high-risk deadline
for stand-alone systems to 2 December 2027, pending formal adoption by the European
Parliament and Council. The original 2 August 2026 date remains in law until that process
completes. For teams doing compliance work now, treat August 2026 as the planning deadline
and any extension as a bonus — not because of urgency theater, but because the audit
infrastructure work takes months. Starting in Q4 2026 against a December 2027 deadline
is still tight.

Now, to the logs themselves.

---

## What your current tooling produces

LangSmith, Arize, Langfuse, Helicone, and Datadog are good tools. They were built for
what they do: real-time debugging, cost tracking, performance monitoring, and
observability. None of this is in dispute.

What they produce, structurally, is mutable records in operator-controlled storage. An
administrator with database access or filesystem permissions can modify or delete a record
after the fact. There is no detectable trace of that modification. The log still exists.
It satisfies Article 12's "automatic recording" requirement. It does not prove it hasn't
been touched since the event occurred.

This is not a criticism of those tools. It is a structural property of how they were
designed. They were not designed for evidence production.

One objection worth addressing directly, because it appears in analyst commentary:
"Article 12 does not require tamper-evident logging." That is technically correct. The
regulation uses "logs," not "tamper-evident logs." The counterargument is not about the
regulatory minimum — it is about what happens when you need to use the log as evidence.

Article 9 requires a risk management system for high-risk AI systems. When an incident
occurs — a credit scoring model produces a discriminatory output, a medical AI diagnostic
is challenged, an AI recruitment tool is investigated — and a regulator or counterparty
demands your logs, "we have logs but cannot prove they weren't modified" is a gap in your
risk management system. The regulation doesn't mandate cryptographic immutability.
Defensible evidence production requires it regardless.

A log that cannot prove its own integrity is not the same as a log that records
something.

---

## What tamper-evidence actually requires technically

Three properties make a log forensically credible. Each is a distinct technical problem.

**Integrity.** Any modification to a historical record must be detectable. The mechanism:
SHA-256 hash over RFC 8785 canonical JSON, chained via a `prev_hash` field. Each event
commits to all prior events. Changing any byte in any prior event breaks every subsequent
hash. Canonical JSON (RFC 8785) matters because without a deterministic serialization,
two implementations can hash the same logical object to different bytes — producing
different hashes for identical content, or the same hash for different content. The chain
gives you internal consistency: you can verify the log was not modified after the fact.

**Attribution.** A hash chain proves internal consistency. It does not prove who wrote it.
An operator who controls the storage can rewrite the entire chain — generating a fresh,
internally-consistent chain where every hash is correct and every event is fabricated.

Ed25519 signatures provide attribution. A per-session signing key produces a signature
over each event's hash. If the key is controlled by the agent operator, this gives you
a statement of the form "the operator attests this event occurred." That is weaker than
what you need for a dispute, but stronger than an unsigned log. The distinction matters:
operator-attested evidence and independently-attested evidence are not the same thing.

**Independence.** The entity that seals the log must be structurally separate from the
entity that operates the agent. If the same team controls both the agent and the sealing
authority, a sophisticated adversary who owns the team can forge both the log and the
seal.

The correct architecture separates these two roles:

```
┌──────────────────────────────────────────────────┐
│  Agent process  (operator trust boundary)        │
│                                                  │
│  SDK records events → JSONL                      │
│  SDK cannot emit CHAIN_SEAL events               │
└──────────────────────────┬───────────────────────┘
                           │  POST /seal
                           ▼
┌──────────────────────────────────────────────────┐
│  Archeion sealing server  (security team boundary)│
│                                                  │
│  Verifies hash chain integrity                   │
│  Appends CHAIN_SEAL with Ed25519 signature       │
│  Returns sealed JSONL                            │
└──────────────────────────────────────────────────┘
```

The SDK enforces the boundary at the type level: `EventType.is_sdk_authority` blocks any
attempt by the agent process to emit a `CHAIN_SEAL` event. The agent cannot produce its
own seal. This is a structural guarantee, not a policy.

Archeion runs inside your security perimeter, controlled by your security team — not the
agent developers. No session content leaves: only hashes pass through `POST /seal`. The
sealing authority appends one event and returns the sealed log.

---

## Evidence classes

Not every deployment has an independent sealing authority. The verifier produces five
evidence classes reflecting what can be cryptographically proven given what is present:

| Class | What it means | When you have it |
|---|---|---|
| `AUTHORITATIVE_EVIDENCE` | Independent party sealed it. Agent could not have forged this. | Archeion sealed |
| `SIGNED_NON_AUTHORITATIVE` | Ed25519 signatures present. Requires private key to forge. | SDK signing enabled |
| `NON_AUTHORITATIVE_EVIDENCE` | Hash chain intact. Proves no post-hoc modification. | Default |
| `PARTIAL_EVIDENCE` | Chain intact but events were dropped during the session. | `LOG_DROP` events present |
| `NO_EVIDENCE` | Chain broken or structurally invalid. | Verification failed |

For most internal compliance purposes, `NON_AUTHORITATIVE_EVIDENCE` is sufficient. For
regulatory submissions and legal proceedings where the operator is a party to the dispute,
`AUTHORITATIVE_EVIDENCE` is the correct target.

---

## What verification looks like

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

If a single byte in any event is changed after sealing:

```
$ sasana verify tampered.jsonl --trust-key <archeion-pubkey>

[3/5] Hash chain integrity ... FAIL
      seq=3: expected 7f3a4b… got d91c08…

Evidence : NO_EVIDENCE
Result   : COMPROMISED ❌
```

The verification binary has no external dependencies. It reads one file, checks five
properties, and exits 0 (INTACT), 1 (COMPROMISED), 2 (PARTIAL), or 3 (ERROR). No network
calls. No API keys. No running server required. A Rust binary ships alongside the Python
implementation for forensic environments where Python is not available.

Archeion is self-hosted: it runs as a container inside your perimeter. The deployment
guide covers docker-compose, key lifecycle, and network isolation. The signing key is a
CA-root-equivalent — generated once, retained for the lifetime of sealed sessions,
rotated only on compromise.

---

## What Sasana does not do

- **Does not record raw content.** Hashes only. You cannot reconstruct what the agent
  said from a Sasana log.
- **Does not prevent tampering.** Detects it after the fact. Detection and prevention are
  different properties.
- **Does not replace LangSmith or Arize.** Those tools are for debugging and
  observability. Sasana is for evidence production. The two are complementary.
- **Does not rate-limit, filter, or modify agent behaviour.**
- **Does not currently have a managed cloud offering.** Self-hosted only.

---

## Further reading

- [EU AI Act Article 12 — EUR-Lex official text](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32024R1689)
- [IETF draft-sharif-agent-audit-trail-00 (March 2026)](https://datatracker.ietf.org/doc/draft-sharif-agent-audit-trail/) — Internet-Draft, expires September 2026. Consult the IETF datatracker for current status.
- [Sasana — GitHub](https://github.com/sahiee-dev/Sasana)
