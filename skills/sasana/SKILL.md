---
name: sasana
slug: sasana
description: >
  Records every OpenClaw session as a cryptographically verifiable audit trail.
  Produces tamper-evident evidence of what your agent did — verifiable offline,
  without trusting any third party.
version: 1.0.0
license: MIT
authors:
  - name: sahiee-dev
    homepage: https://github.com/sahiee-dev
homepage: https://github.com/sahiee-dev/Sasana
tags:
  - audit
  - security
  - compliance
  - tamper-evident
metadata:
  paperclip:
    entrypoint: ../../sasana_skill_entry.py
    class: SasanaSkillEntry
    permissions:
      - session.read
      - filesystem.write
    hooks:
      - session.start
      - session.end
      - llm.call
      - llm.response
      - tool.invoke
      - tool.result
      - tool.error
    config:
      output_dir:
        type: string
        default: "~/.openclaw/sasana/"
      server_url:
        type: string
        default: null
    privacy:
      stores_content: false
      stores_hashes_only: true
      cloud_dependency: false
      network_required: false
---

# Sasana

Sasana runs passively in the background. Once installed, every session
automatically produces a hash-chained JSONL audit file at
`~/.openclaw/sasana/<session_id>.jsonl`. You do not need to invoke it.

Every LLM call, response, tool invocation, and tool result is recorded as
a SHA-256 hash. Raw content — prompts, responses, tool arguments — is never
stored. Only hashes.

Any modification to any event in the session history, after the session ends,
is detectable by the verifier.

## Verify a session

```bash
sasana verify ~/.openclaw/sasana/<session_id>.jsonl
```

Expected output for an unmodified session:

```
Evidence : NON_AUTHORITATIVE_EVIDENCE
Result   : INTACT ✅
```

If any byte was changed after the session ended:

```
Evidence : NO_EVIDENCE
Result   : COMPROMISED ❌
```

Exit codes: `0` (INTACT), `1` (COMPROMISED), `2` (PARTIAL), `3` (ERROR) — suitable
for scripting and CI pipelines.

## Authority sealing (optional)

For compliance use cases requiring an independent third-party attestation,
submit a completed session to Archeion — a self-hosted sealing server that
produces `AUTHORITATIVE_EVIDENCE`:

```bash
sasana seal <session.jsonl> --server http://localhost:8747
sasana verify <session.jsonl> --trust-key <archeion-pubkey>
```

Archeion runs inside your own security perimeter. No session data is sent to
any external service. See the [deployment guide](../../docs/DEPLOYMENT.md).

## Install

```bash
# Via skills.sh (when listed)
openclaw skill install sahiee-dev/Sasana/sasana

# Via GitHub URL (always works)
openclaw skill install https://github.com/sahiee-dev/Sasana

# Direct Python install (without OpenClaw)
pip install sasana
```
