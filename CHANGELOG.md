# Changelog

All notable changes to Sasana are documented here. This project adheres to
[Semantic Versioning](https://semver.org/).

## [1.2.0] — 2026-10-10

### Security

**Two verification gaps let a tampered log verify as trustworthy. Affected: `sasana`
1.0.0 and 1.1.0 (Python `verify()`, `sasana verify`, `agentops-verify`, `sasana
evidence-pack`), and every released version of the Rust verifier (`sasana-rs`). Fixed in
1.2.0. Archeion's sealing itself is not affected.** Both were found in an internal
tamper audit; we are not aware of exploitation.

1. **Any valid seal was reported as `AUTHORITATIVE_EVIDENCE`.** The verifier checked a
   `CHAIN_SEAL` signature against the public key *embedded in the seal itself*. Anyone who
   could write a session file could edit it, recompute the hash chain, generate their own
   keypair, seal the result, and `sasana verify` returned `INTACT` /
   `AUTHORITATIVE_EVIDENCE` with exit code 0 — unless the verifier had been given the real
   Archeion key with `--trust-key`. The README, docs, skills and compliance reports
   described `AUTHORITATIVE_EVIDENCE` as proof that an independent authority sealed the log
   and that "the agent could not have forged this"; that was only true for pinned verifies.
2. **A pinned key did not require a seal.** With `--trust-key` set, deleting the
   `CHAIN_SEAL` (and recomputing the chain) returned `INTACT` /
   `NON_AUTHORITATIVE_EVIDENCE`, exit 0 — the pin was silently skipped when there was
   nothing to check it against.

Related defects fixed in the same audit: more than one `CHAIN_SEAL`, a `CHAIN_SEAL` that
was not the final event, and a seal whose `session_hash` disagreed with the chain were all
accepted; malformed input (a non-object line, a non-integer `seq`) crashed with a Python
traceback and **exit code 1, the same code as `COMPROMISED`**; unrecognised CLI flags were
silently ignored, so a typo such as `--trust_key` dropped the pin and still printed a
verdict; `--json` omitted the timestamp, seal and pin results; the RFC 3161 check was
labelled `PASS` / `timestamp_verified: true` for any token whose imprint matched, including
forged and backdated ones, because the TSA signature and `genTime` are not verified; the
EU AI Act report set `server_sealed` whenever a `CHAIN_SEAL` event existed; and the Rust
verifier reported `AUTHORITATIVE_EVIDENCE` for any valid seal and accepted a missing one
under `--trust-key`.

**Action required.** Re-verify archived logs and regenerate evidence packs with
`--trust-key <your Archeion public key>` (and `--strict` in automation). A log that
returned `AUTHORITATIVE_EVIDENCE` from 1.0.0/1.1.0 *without* a pinned key was never
independently verified. Existing sealed files remain valid; the seal format is unchanged.

### Changed (breaking)
- **New evidence class `SELF_SEALED_EVIDENCE`.** A valid `CHAIN_SEAL` verified without a
  pinned key is `INTACT` / `SELF_SEALED_EVIDENCE`, and the CLI warns "seal not verified
  against a trusted key; anyone can produce this". `AUTHORITATIVE_EVIDENCE` now requires
  the seal to verify against the key passed as `trusted_seal_pubkey` / `--trust-key`.
  Code that compared `evidence_class == "AUTHORITATIVE_EVIDENCE"` without passing a key
  will now see `SELF_SEALED_EVIDENCE`.
- `trusted_seal_pubkey` / `--trust-key` now **requires** a `CHAIN_SEAL`; a session without
  one is `COMPROMISED`. New `require_seal` / `--require-seal` does the same without a pin.
- Exactly one `CHAIN_SEAL` is allowed, it must be the final event, and its
  `payload.session_hash` must equal the preceding event's `event_hash`. Violations are
  `COMPROMISED`.
- Input that cannot be assessed (non-object events, non-integer `seq`, non-string
  `event_type` / `session_id` / `signature`, non-object `payload`, empty file, bad UTF-8,
  invalid JSON) returns status `ERROR` / `NO_EVIDENCE` and exit code 3 instead of a
  traceback. Unrecognised CLI flags are an error (exit 3), never ignored.
- RFC 3161 check status `PASS` is now `IMPRINT_MATCH`; `timestamp_verified` is always
  `false` (new `timestamp_imprint_match` carries the old meaning). The check remains
  informational and only compares the imprint; the TSA signature, certificate chain and
  `genTime` are still not verified by `verify()`.
- `sasana verify --json` now includes `checks`, `warnings`, `pinned`, `require_seal`,
  `seal_present`, `seal_trusted`, `strict`, `exit_code` and a `timestamp` object.
- Archeion seal payload: `timestamp_verified` → `timestamp_imprint_match`, `timestamp_utc`
  → `timestamp_claimed_utc` (previously a signed claim of "verified" for an imprint-only
  check). Previously sealed files are unaffected.
- `evidence-pack` and the compliance generators take `--trust-key` /
  `trusted_seal_pubkey`; without it a seal is reported as self-sealed, not server-sealed.
- `VERIFIER_VERSION` is `2.0.0`: the same input can now produce a different verdict.
- Exit codes: `0` INTACT, `1` COMPROMISED, `2` PARTIAL, `3` ERROR / bad usage, and new `4`
  (`--strict` only: INTACT but not `AUTHORITATIVE_EVIDENCE`).

### Added
- `sasana verify --require-seal`, `--strict` (requires `--trust-key`), `--verbose`.
- Rust verifier: same trust model (`--trust-key`, `--require-seal`, `--strict`,
  `SELF_SEALED_EVIDENCE`, single/final seal, `session_hash`), strict flag parsing, and
  tests mirroring the Python tamper matrix. It still does not check RFC 3161 tokens or
  per-event signatures.
- `tests/test_tamper_matrix.py` (edit / rechain / re-seal / strip / forge cases through the
  real CLI, cross-checked against the Rust binary) and `tests/test_verifier_hardening.py`.
  `tests/conftest.py` keeps the suite away from any real `~/.archeion` signing key.
- Pre-outcome commitments (`sasana.commitment`, `sasana verify-commitment`) and a strict
  RFC 3161 verifier (`sasana.rfc3161.verify_timestamp_strict`: CMS signature, pinned trust
  anchor chain, timestamping EKU, nonce). Neither is part of `sasana verify`.

### Changed
- JCS (RFC 8785) number serialisation is now conformant (ECMAScript number formatting).
  Whole-number floats such as `100.0` or `0.0` now serialise as `100` / `0`, and integers
  beyond ±2^53 round through a double. **Compatibility:** a log written by 1.1.0 or earlier
  whose payload contains such a number has an `event_hash` computed from the old
  serialisation and will fail verification with this change.

## [1.1.0] — 2026-07-20

### Added
- **`sasana evidence-pack` CLI** — turns a verified session into an auditor-ready
  report (HTML) plus a re-verifiable manifest (JSON) in one command. Standards:
  `eu_ai_act` (EU AI Act Article 12), `soc2` (CC7.2), `hipaa` (§164.312(b)), `siem`
  (CEF + JSON). Exit codes `0` compliant / `2` gaps / `3` error for CI.
- **OpenTelemetry exporter** (`sasana[otel]`) — `sasana.integrations.otel.SasanaSpanExporter`
  maps OTel GenAI-semantic-convention spans to a tamper-evident Sasana ledger, one
  session per trace. Run it alongside your existing tracing exporter; nothing is
  replaced. Only hashes are stored.

### Changed
- The tool version shown in generated evidence reports (EU AI Act / SOC 2 / HIPAA
  footers and the SIEM `sasana_version` field) is now sourced from
  `sasana.__version__`, so it can no longer drift from the package version.

### Notes
- The verification algorithm is unchanged; `VERIFIER_VERSION` remains `1.0.0`, so logs
  verified under 1.0.0 verify identically under 1.1.0.
- Companion site adds a live in-browser verifier at
  [sasana.site/verify](https://sasana.site/verify).

## [1.0.0] — 2026-06-15

### Added
- SHA-256 hash-chained, Ed25519-signed tamper-evident session ledger (SQLite + JSONL).
- Canonical verifier (Python + Rust) with evidence-class model
  (`AUTHORITATIVE_EVIDENCE` → `NO_EVIDENCE`).
- RFC 3161 trusted-timestamp anchoring on `SESSION_START`.
- Archeion independent sealing server.
- Compliance export engine (EU AI Act Article 12, SOC 2, HIPAA, SIEM).
- Framework integrations: OpenClaw, LangGraph, CrewAI, AutoGPT.
