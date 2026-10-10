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
public key (recorded out-of-band when Archeion was deployed). The pin rejects seals
from any other key **and** makes a missing seal a failure:

```bash
sasana verify <session.jsonl> --trust-key <base64-pubkey> --strict
```

Without `--trust-key`, a seal only proves the file is self-consistent (anyone can produce
one) and the result is `SELF_SEALED_EVIDENCE`. Use `--require-seal` if you cannot pin a
key but still need to reject unsealed logs.

## Evidence classes

The verifier returns an evidence class alongside the result:

| Class | What it means |
|---|---|
| `AUTHORITATIVE_EVIDENCE` | Seal verified against the Archeion key you pinned with `--trust-key` |
| `SELF_SEALED_EVIDENCE` | Valid seal, but only against its own embedded key — anyone can produce this |
| `SIGNED_NON_AUTHORITATIVE_EVIDENCE` | Per-event signatures against a key inside the log — consistency, not identity |
| `NON_AUTHORITATIVE_EVIDENCE` | Hash chain intact — detects edits to events, not a complete rewrite |
| `PARTIAL_EVIDENCE` | Chain intact but events were dropped |
| `NO_EVIDENCE` | Chain broken or structurally invalid |

For regulatory submissions and legal proceedings where the operator is a party
to the dispute, `AUTHORITATIVE_EVIDENCE` (pinned `--trust-key`) is the correct target.
Reports from `evidence-pack` also need `--trust-key` to show a session as sealed.

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
| EU AI Act Article 12 | Automatic event recording for high-risk AI systems | SHA-256 hash chain detects edits to recorded events; a pinned Archeion seal detects a complete rewrite |
| SOC 2 CC7.2 | System monitoring with verifiable audit trail | Sessions sealed and verified with a pinned key provide cryptographic evidence of monitoring |
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
