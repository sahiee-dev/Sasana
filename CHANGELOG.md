# Changelog

All notable changes to Sasana are documented here. This project adheres to
[Semantic Versioning](https://semver.org/).

## [2.0.1] — 2026-10-11

Patch release: one display fix, one stale version string, and documentation that corrects an incomplete
statement in the 2.0.0 notes. **No change to verdicts**; `VERIFIER_VERSION` stays 2.0.0.

### Correction to the 2.0.0 notes

The 2.0.0 Security entry said "Archeion's sealing itself is not affected." That was incomplete. The two
flaws fixed in 2.0.0 (any self-consistent seal reported `AUTHORITATIVE_EVIDENCE`; a pinned key did not
require a seal) were in the *verifier*, and are fixed. But a separate, documented property of Archeion
was not described plainly: **Archeion authenticates no callers and keeps no record of what it has
sealed.** Anyone who can reach `POST /seal` can get a rewritten copy of a session sealed with the genuine
key, and with that key pinned it verifies as `INTACT` / `AUTHORITATIVE_EVIDENCE` (threat **A8**; reproduced
against the real server). A seal therefore shows that a chain head was presented to Archeion at the seal's
time, not that it is the original.

**Against the operator, Sasana 2.x provides no rewrite protection unless access to `/seal` is controlled by
a party independent of the operator.** This is a design limitation, not something 2.0.1 fixes. See
[`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) and the (unimplemented) direction in
[`docs/design/witness-anchoring.md`](docs/design/witness-anchoring.md). The 2.0.0 entry is left as
published.

### Fixed
- `sasana verify` (Python and Rust) printed `Seal signature ... SELF-SIGNED` on a **pinned** verify whose
  verdict was `COMPROMISED` for an unrelated reason (for example an edited event), although the seal had
  verified against the pinned key. The label now reflects the seal check alone. Verdicts, exit codes and
  `--json` are unchanged.
- Archeion's FastAPI app (and `/health`) reported version `1.0.0`; it now follows the package version.
  `tests/test_versions.py` fails if any release version string (pyproject, Cargo, manifest, skill, plugin,
  compose tag, Archeion) drifts again.

### Documentation
- New `docs/THREAT_MODEL.md` (A1-A8 in plain words, including what is not defended and why a timing
  warning or an Archeion-side registry would not close A8).
- README, `DEPLOYMENT.md` (the "perimeter isolation" reviewer answer assumed an outside attacker; the
  operator is the adversary Sasana exists for), `TECHNICAL.md` and `PRODUCT.md` state A8 and the sentence above.
- New design document `docs/design/witness-anchoring.md` (design only).

## [2.0.0] — 2026-10-10

A security release with breaking changes, hence the major version. **If you verify evidence with
Sasana, read "Security" and "Breaking" before upgrading.**

### Security

**Two verification gaps let a tampered log verify as trustworthy.** Affected: `sasana` **1.0.0 and
1.1.0** (Python `verify()`, `sasana verify`, `agentops-verify`, `sasana evidence-pack`) and **every
released version of the Rust verifier** (`sasana-rs`). Fixed in 2.0.0. Archeion's sealing itself is
not affected. Both were found in an internal tamper audit; we are not aware of exploitation.

1. **Any valid seal was reported as `AUTHORITATIVE_EVIDENCE`.** The verifier checked a `CHAIN_SEAL`
   signature against the public key *embedded in the seal itself*. Anyone who could write a session
   file could edit it, recompute the hash chain, generate their own keypair, seal the result, and
   `sasana verify` returned `INTACT` / `AUTHORITATIVE_EVIDENCE` with exit code 0, unless the
   verifier had been given the real Archeion key with `--trust-key`. The README, docs, skills and
   compliance reports described `AUTHORITATIVE_EVIDENCE` as proof that an independent authority
   sealed the log and that "the agent could not have forged this"; that was only true for pinned
   verifies.
2. **A pinned key did not require a seal.** With `--trust-key` set, deleting the `CHAIN_SEAL` (and
   recomputing the chain) returned `INTACT` / `NON_AUTHORITATIVE_EVIDENCE`, exit 0: the pin was
   silently skipped when there was nothing to check it against.

Related defects fixed in the same audit: more than one `CHAIN_SEAL`, a `CHAIN_SEAL` that was not the
final event, and a seal whose `session_hash` disagreed with the chain were all accepted; malformed input
(a non-object line, a non-integer `seq`) crashed with a Python traceback and **exit code 1, the same
code as `COMPROMISED`**; unrecognised CLI flags were silently ignored, so a typo such as `--trust_key`
dropped the pin and still printed a verdict; `--json` omitted the timestamp, seal and pin results; the
RFC 3161 check was labelled `PASS` / `timestamp_verified: true` for any token whose imprint matched,
including forged and backdated ones, because the TSA signature and `genTime` are not verified; the EU
AI Act report set `server_sealed` whenever a `CHAIN_SEAL` event existed; and the Rust verifier reported
`AUTHORITATIVE_EVIDENCE` for any valid seal and accepted a missing one under `--trust-key`.

**Workaround on any affected version:** always verify with `--trust-key <your Archeion public key>`,
which makes a missing or foreign seal fail. **Action after upgrading:** re-verify archived logs and
regenerate evidence packs with `--trust-key` (and `--strict` in automation). A log that returned
`AUTHORITATIVE_EVIDENCE` from 1.0.0/1.1.0 *without* a pinned key was never independently verified.
Existing sealed files remain valid; the seal format is unchanged.

### Breaking

- **`AUTHORITATIVE_EVIDENCE` requires a pinned key.** Without `trusted_seal_pubkey` / `--trust-key`, a
  valid `CHAIN_SEAL` yields the new class **`SELF_SEALED_EVIDENCE`** (status still `INTACT`, with the
  warning "seal not verified against a trusted key; anyone can produce this"). Code that compared
  `evidence_class == "AUTHORITATIVE_EVIDENCE"` without passing a key will now see `SELF_SEALED_EVIDENCE`.
- **`--trust-key` now requires a seal**: a session with no `CHAIN_SEAL` is `COMPROMISED`. New
  `require_seal` / `--require-seal` does the same without a pin.
- **Seal structure:** exactly one `CHAIN_SEAL`, it must be the final event, and its `session_hash` must
  equal the preceding event's `event_hash`. Violations are `COMPROMISED`.
- **Unassessable input is `ERROR` (exit 3)**, not a traceback: non-object events, non-integer `seq`,
  non-string `event_type` / `session_id` / `signature`, non-object `payload`, empty file, bad UTF-8,
  invalid JSON, an unknown canonicalization.
- **Unknown CLI flags exit 3** instead of being ignored (also for `verify-commitment`).
- **Exit codes:** `0` INTACT, `1` COMPROMISED, `2` PARTIAL, `3` ERROR / bad usage, and new `4`
  (`--strict` only: INTACT but not `AUTHORITATIVE_EVIDENCE`). `0` still covers weak evidence classes;
  read `evidence_class` or use `--strict`.
- **RFC 3161:** check status `PASS` is now `IMPRINT_MATCH`; `timestamp_verified` is always `false`
  (new `timestamp_imprint_match` carries the old meaning). The check stays informational and still only
  compares the imprint; the TSA signature, certificate chain and `genTime` are not verified by `verify()`.
- **`sasana verify --json`** now includes `checks`, `warnings`, `canonicalization`, `pinned`,
  `require_seal`, `seal_present`, `seal_trusted`, `strict`, `exit_code` and a `timestamp` object.
- **Archeion seal payload:** `timestamp_verified` → `timestamp_imprint_match`, `timestamp_utc` →
  `timestamp_claimed_utc` (previously a signed claim of "verified" for an imprint-only check).
  Previously sealed files are unaffected.
- **`evidence-pack` / compliance generators** take `--trust-key` / `trusted_seal_pubkey`; without it a
  seal is reported as self-sealed, not server-sealed.
- **`VERIFIER_VERSION` is `2.0.0`:** the same input can now produce a different verdict.
- **New logs are not verifiable by 1.x verifiers when they contain whole-number floats** (see
  Canonicalization): upgrade every verifier, including any copy of the verification logic outside this
  repository, before producing 2.0 logs.
- `verify.py` / `agentops-verify` is now a thin alias for `sasana verify` (same flags and exit codes).

### Canonicalization

An event's hash is computed over canonical JSON bytes, and 2.0.0 makes that encoding strict RFC 8785
(needed so JS and Rust producers can write logs Python verifies). The 1.0.0/1.1.0 encoding differed
for numbers: whole-number floats such as `100.0` or `0.0` serialised as `100.0`, exponent floats as
`1e-05`, and integers beyond 2^53 exactly. Switching encodings silently would have made existing,
valid logs fail verification, and accepting either encoding would stop the hash defining the event
uniquely. Instead each session **declares** its canonicalization:

- New sessions write `"canonicalization": "jcs-rfc8785"` in the `SESSION_START` payload (SDK, ledger and
  OpenClaw bridge). It is part of the hashed event, so it is covered by the chain and any seal.
- **A missing field means `legacy`** (the 1.0.0/1.1.0 encoding, frozen as
  `sasana.jcs.canonicalize_legacy`), so existing logs keep verifying.
- The verifier reads the declaration once and uses exactly that algorithm for every event. It never
  tries both. Any other value (including an explicit `"legacy"`) is `ERROR`, exit 3.
- Removing or changing the declaration breaks the chain, so a sealed log cannot be downgraded
  unnoticed. Archeion seals a session with the algorithm that session declares.
- The Rust verifier implements both algorithms and picks by the same rule. Known limit: a legacy log
  with an integer larger than u64 verifies in Python but not in Rust.
- `tests/fixtures/legacy/` holds logs written by the published 1.0.0 and 1.1.0 releases (unsealed,
  signed, sealed, timestamped). They must verify `INTACT` under both verifiers, and sealed + pinned ones
  as `AUTHORITATIVE_EVIDENCE`. Shared vectors (RFC 8785 Appendix B, the RFC examples, Node as an
  independent oracle, the real 1.1.0 code) pin both algorithms byte-for-byte.

### Added
- `sasana verify --require-seal`, `--strict` (requires `--trust-key`), `--verbose`.
- Rust verifier: the same trust model (`--trust-key`, `--require-seal`, `--strict`,
  `SELF_SEALED_EVIDENCE`, single/final seal, `session_hash`), per-event Ed25519 signatures, both
  canonicalizations, strict flag parsing, and tests mirroring the Python tamper matrix. It still does
  not check RFC 3161 tokens.
- `tests/test_tamper_matrix.py` (10 attacks × 2 formats × 2 verifiers, through the real CLI),
  `tests/test_canonicalization.py`, `tests/test_verifier_hardening.py`; `tests/conftest.py` keeps the
  suite away from any real `~/.archeion` signing key. CI builds the Rust binary so the Python/Rust
  agreement tests fail, rather than skip, when it is missing.
- Pre-outcome commitments (`sasana.commitment`, `sasana verify-commitment`) and a strict RFC 3161
  verifier (`sasana.rfc3161.verify_timestamp_strict`: CMS signature, pinned trust-anchor chain,
  timestamping EKU, nonce). Neither is part of `sasana verify`.

### Changed
- CI pins `ruff<0.16`: ruff 0.16+ enables extra default rules and reports 191 errors on the untouched
  1.1.0 tag.

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
