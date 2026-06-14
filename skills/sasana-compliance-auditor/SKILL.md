---
name: sasana-compliance-auditor
description: >-
  Verifies AI agent session logs for tamper-evidence and produces compliance
  reports for EU AI Act Article 12, SOC 2 CC7.2, and HIPAA audit requirements.
  Invoke when asked to verify session integrity, produce an audit trail, check
  whether a log has been tampered with, or generate a compliance export.
---

# Sasana Compliance Auditor

Use this skill when the user asks to:

- Verify that an AI agent's session log has not been tampered with
- Produce a compliance report for EU AI Act Article 12, SOC 2, or HIPAA
- Check session integrity before a regulatory audit
- Confirm a log's evidence class (`AUTHORITATIVE_EVIDENCE`, `NON_AUTHORITATIVE_EVIDENCE`, etc.)
- Export audit trail evidence for legal or regulatory submission

## Prerequisites

```bash
pip install sasana
```

## Verify a session log

```bash
sasana verify <session.jsonl>
```

Output explains five checks and returns one of three verdicts:

| Result | Meaning |
|---|---|
| `INTACT` | Log has not been modified since recording. |
| `PARTIAL` | Hash chain intact but events were dropped during the session. |
| `COMPROMISED` | Hash chain broken — log has been modified after the fact. |

Exit codes: `0` (INTACT), `1` (COMPROMISED), `2` (PARTIAL), `3` (ERROR).

## Verify with key pinning

If the session was sealed by an Archeion authority server, pin the expected
public key to reject seals from any other source:

```bash
sasana verify <session.jsonl> --trust-key <base64-pubkey>
```

## Evidence classes

The verifier returns an evidence class alongside the result:

| Class | What it means |
|---|---|
| `AUTHORITATIVE_EVIDENCE` | Independently sealed — agent could not have forged this |
| `SIGNED_NON_AUTHORITATIVE` | Ed25519 signatures present — requires private key to forge |
| `NON_AUTHORITATIVE_EVIDENCE` | Hash chain intact — proves no post-hoc modification |
| `PARTIAL_EVIDENCE` | Chain intact but events were dropped |
| `NO_EVIDENCE` | Chain broken or structurally invalid |

For regulatory submissions and legal proceedings where the operator is a party
to the dispute, `AUTHORITATIVE_EVIDENCE` is the correct target.

## Generate a compliance report

```bash
# EU AI Act Article 12
sasana export <session.jsonl> --format eu-ai-act

# SOC 2 CC7.2
sasana export <session.jsonl> --format soc2

# HIPAA §164.312(b)
sasana export <session.jsonl> --format hipaa

# SIEM-compatible JSON
sasana export <session.jsonl> --format siem
```

## Regulatory mapping

| Regulation | Requirement | How Sasana addresses it |
|---|---|---|
| EU AI Act Article 12 | Tamper-evident automatic recording for high-risk AI systems | SHA-256 hash chain detects any post-hoc modification |
| SOC 2 CC7.2 | System monitoring with verifiable audit trail | Sealed sessions provide cryptographic evidence of monitoring |
| HIPAA §164.312(b) | Audit control for healthcare AI | Hash-only storage — raw PHI never recorded |

## What Sasana does not do

- Does not record raw content — hashes only; you cannot reconstruct what the agent said
- Does not prevent tampering — detects it after the fact
- Does not replace LangSmith or Arize — this is for evidence production, not observability

## Install

```bash
npx skills add sahiee-dev/Sasana/sasana-compliance-auditor
```

Source: [github.com/sahiee-dev/Sasana](https://github.com/sahiee-dev/Sasana)
