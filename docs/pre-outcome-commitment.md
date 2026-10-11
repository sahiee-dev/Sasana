# Pre-Outcome Commitment — Design Proposal

**Status:** IMPLEMENTED on branch `design/ha-reveal-bundle` (not merged, not pushed). Sections 1–2 describe the code *as it was before* this work; see **Implementation status** and the reconciliation block below for what changed. **Commitment v2 (§3.5) supersedes v1.**
**Scope:** a generic primitive. Platform-specific mappings live only in Appendix A and in `examples/ha-reveal/` (synthetic bundles). A statement about a named platform is either cited to that platform's public interface (as that platform described it to us) or marked **PROPOSED EXTENSION — not an HA interface**. Nothing here is an interface, commitment or endorsement of any platform.

### Implementation status

Decisions taken: commitment formula first **as originally specified** (v1: no `prev_commitment` inside `C`), then **amendment A1 adopted as v2** (§3.5: `prev_commitment` and the payload mapping id inside `C`; v1 stays verifiable but is superseded); sidecar bundle (no new event type); strings/ints-only payload profile; `commit()` fail-closed; session-open commitment **deferred**.

| Area | Change | Where |
|---|---|---|
| JCS floats | Now RFC 8785-conformant (ECMAScript number formatting); ints beyond ±2^53 round through a double. All 24 RFC 8785 Appendix B vectors pass. **Behaviour change, since handled:** this alone would have re-hashed events in logs written by 1.0.0/1.1.0 (whole-number floats such as `100.0`, exponent floats). It was resolved in 2.0.0 by *versioned canonicalization* (see "Reconciled with Sasana 2.x" below), not by accepting both encodings. | `sasana/jcs.py`, `tests/test_jcs.py` |
| RFC 3161 | New `verify_timestamp_strict()`: CMS signature (RSA PKCS#1 v1.5 / ECDSA / Ed25519), chain to caller-pinned anchors, timeStamping EKU, validity at genTime, SHA-256 imprint, nonce, optional policy allow-list, sub-second genTime, accuracy. Request builder accepts a nonce; `request_timestamp` accepts `url`/`nonce`. The old imprint-only `verify_timestamp` is unchanged (existing verifier behaviour and tests intact). **Not done:** revocation (CRL/OCSP), RSA-PSS. | `sasana/rfc3161.py`, `tests/test_rfc3161_strict.py`, `tests/tsa_fixture.py` |
| Verifier | New public `verify_chain_integrity()` (structural + sequence + hash chain only) so `commit()` can work on open sessions. No existing function changed. | `sasana/verifier.py` |
| Commitment | `commit()`, `reveal_bundle()`, `verify_commitment()`, `compute_commitment()`, payload profile, disclosures. | `sasana/commitment.py`, `tests/test_commitment.py` |
| CLI | `sasana verify-commitment` (exit 0 valid, 1 invalid, 2 late, 3 input error or unknown flag, 4 unrevealed). Policy flags: `--receipts`, `--receipt-key`, `--mapping`, `--clock-skew`, `--require-receipts`, `--allow-unrevealed-history`. Unknown or abbreviated flags are refused (they were silently ignored before). | `sasana_cli.py` |
| Payload mapping | `ha-daily-v1`: an explicit, versioned map from a submission to the canonical payload (decimal strings; absent ≠ empty ≠ null); its id is bound inside `C`. | `sasana/commitment_mapping.py`, `tests/test_commitment_mapping.py`, `tests/fixtures/mapping/ha-daily-v1.json` |
| C_v2, receipts, policy | `compute_commitment_v2`; `sign_receipt` / `verify_receipt` (a **PROPOSED EXTENSION**, §5.3); the scored-revision rule; verdict `UNREVEALED`; `HISTORY_GAP`; the time and trust policy of §10. | `sasana/commitment.py`, `tests/test_commitment_v2.py` |
| Examples | 11 synthetic bundles and a runner that prints `bundle \| expected \| actual \| match`. | `examples/ha-reveal/`, `tests/test_ha_reveal_examples.py` |

Validation: 247 tests pass on Python 3.11 (160 pre-existing + 87 new), 229 pass + 18 pre-existing skips on 3.10 (cryptography 41); `ruff check` and `ruff format --check` clean. Nine deliberate mutations of `commitment.py` were each caught by a test. The strict verifier was also checked against a **live FreeTSA token** (nonce echoed, chain to FreeTSA's published root), and a full `commit()` → `reveal_bundle()` → `sasana verify-commitment` run against FreeTSA gave `VALID_ON_TIME`, and `LATE` for an earlier deadline. FreeTSA omits `accuracy` and issues whole-second `genTime`; the verifier assumes 1 s by default (`default_accuracy_s`) and warns.

Branch `design/ha-reveal-bundle` (C_v2, mapping, receipts, policy, examples): **476 Python tests pass on 3.10, 3.11 and 3.12** (368 at the 2.0.1 release, +9 Sasana-2.x reconciliation tests, +99 new), 26 Rust tests, `ruff check` and `ruff format --check` clean (ruff 0.15.x, the CI pin is `<0.16`). Twenty deliberate mutations of the security-relevant lines (mapping id or `prev_commitment` dropped from `C`, scored revision ignoring `accepted`, `<` weakened to `<=`, clock skew or assumed accuracy ignored, empty anchors allowed, receipt key not required, the canonical-form check skipped, strict flag parsing reverted, and others) were each caught by a test. Eleven synthetic bundles in `examples/ha-reveal/` verify as `expected.json` says. Not run: anything against a real counterparty or a real TSA.

**Known gaps in the implementation:** no revocation checking; single-TSA per commitment (`tsa_urls` is tried in order, not n-of-m); *(superseded in 2.0.0: the Rust verifier now implements both canonicalizations and is tested against the same vectors and golden logs as Python; ~88,000 random doubles hash identically)*; `commit()` has no default TSA trust anchor (callers pin it); session-open commitment (§5.2) is not implemented; no real counterparty issues receipts: they are a **PROPOSED EXTENSION** (§5.3) implemented only as a verifier input, and `registry` is an unsigned input list.


### Reconciled with Sasana 2.x (as of 2.0.1)

This note was written before 2.0.0. The statements below replace anything above that disagrees with them. Each
is pinned by a test (`tests/test_commitment_sasana2.py`, `tests/test_canonicalization.py`,
`tests/test_threat_model.py`) unless marked otherwise.

**1. Canonicalization is versioned and declared.** A session written by Sasana ≥ 2.0.0 declares
`"canonicalization": "jcs-rfc8785"` inside its (hashed) `SESSION_START` payload; a missing field means `legacy`
(the 1.0.0/1.1.0 float behaviour); any other value is `ERROR`. The verifier reads the declaration once and uses
exactly that algorithm for every event; it never tries both. Two separate things use JCS, and they are
independent:

| What | Algorithm |
|---|---|
| The **trace** (`session_events`): each `event_hash`, the chain, the `session_root` | the session's own declared algorithm (`jcs-rfc8785` or `legacy`) |
| The **commitment** (`H(JCS(payload))`, the `jcs` disclosure form, the bytes that go into `C`) | always RFC 8785 (`sasana.jcs.canonicalize`), whatever the session declares |

The payload profile (strings, booleans, null, arrays, objects, integers within ±2^53; real numbers as decimal
*strings*) predates the float break and is now backed by it: a whole-number float changed bytes between `100.0`
and `100` and silently invalidated every old log that contained one.

**2. Evidence classes, and what a pinned key does here.** `verify()` (called by `verify_commitment`) now reports
`SELF_SEALED_EVIDENCE` for a seal that verifies only against its own embedded key, and
`AUTHORITATIVE_EVIDENCE` only when the seal verifies against a key the caller pinned
(`trusted_seal_pubkey` / `--trust-key`). Since 2.0.0 a pinned key **requires a seal**: an unsealed trace with a
pinned key is `COMPROMISED`, so `verify_commitment` returns `INVALID`; a seal from a different key is also
`INVALID`. The evidence class is recorded in the verdict but **never changes the commitment verdict or the
time**. (Tested: pinned+sealed, unpinned+sealed, pinned+unsealed, pinned+wrong key.)

**3. Threat A8, and why the commitment, not the seal, is the defence.** An operator who can reach Archeion's
`POST /seal` can have a rewritten session sealed with the genuine key, which verifies as
`AUTHORITATIVE_EVIDENCE` under the pin ([`THREAT_MODEL.md`](THREAT_MODEL.md), A8; reproduced by
`tests/test_threat_model.py`). **Against the operator the seal therefore adds little** (it shows a chain head was
presented to Archeion at the seal's time, not that it is the original). What does bind the session is a
commitment `C` that a **counterparty records before the deadline**: `C` contains `session_root`, so any rewrite of
an event at or before the root removes the root from the chain and the verifier returns `INVALID`
(tested against a genuinely resealed rewrite). That is the *counterparty* witness option in
[`design/witness-anchoring.md`](design/witness-anchoring.md) (Option 2) in practice. Limits, also tested: `C` binds the
trace only **up to `session_root`**; events after it can differ and are reported as `POST_COMMITMENT_EVENTS`; and
it only helps if a counterparty actually holds `C` from before the deadline, which is a property of the
counterparty's process, not of this code.

**4. Which timestamp path a bundle uses.** The time of a commitment comes **only** from
`rfc3161.verify_timestamp_strict()` applied to the revision's `tsa_token` over `C` (CMS signature, chain to the
verifier's pinned anchors, timeStamping EKU, validity at `genTime`, SHA-256 imprint, optional policy OIDs); the nonce
is checked at `commit()`, not at reveal. **`sasana verify` is different and remains imprint-only:** for the
`SESSION_START` RFC 3161 token inside the *trace* it reports `IMPRINT_MATCH` and does not verify the TSA signature or
`genTime`. That token is **not used for any commitment decision.** (Tested: a `SESSION_START` token with a corrupted
CMS signature gets `IMPRINT_MATCH` from `verify()` and is rejected by `verify_timestamp_strict`; a commitment token
from an unpinned TSA makes the bundle `INVALID`; `commit()` is fail-closed on a bad token.) Revocation is still not
checked.

**5. Commitment v2 supersedes v1 (`design/ha-reveal-bundle`).** v1 carried `prev_commitment` *beside* `C`, so a
timestamp did not authenticate the revision chain, and the payload had no declared meaning. v2 puts the payload
mapping id and `prev_commitment` *inside* `C` (§3.5), adds an optional signed counterparty receipt so the scored
revision is the one the counterparty accepted rather than "the highest on-time revision in the bundle" (§5.3), adds
the verdict `UNREVEALED`, and makes the time and trust policy explicit and tested (§10). v1 bundles still verify.

---

## 0. Purpose

An agent (or its operator) commits to **a decision plus the full trace that produced it** *before* the outcome is known, obtains an independent trusted timestamp over that commitment, and later reveals everything so that a third party can verify:

1. the revealed decision and trace are exactly what was committed, and
2. the commitment existed before a stated deadline.

Intended uses: forecasts, trading decisions, evaluation submissions, audits. Nothing here is specific to any one of them.

---

## 1. Current architecture (what this design builds on)

Every claim below cites the file and function it comes from. Claims about *what the code does not do* are marked **(absent)**.

| # | Fact | Source |
|---|---|---|
| 1 | Event envelope fields: `seq, event_type, session_id, timestamp, payload, prev_hash, event_hash` (+ optional `signature`). `timestamp` is the *writer's* local UTC clock. | `sasana/envelope.py::build_event`, `_utc_timestamp`; required set in `sasana/verifier.py::REQUIRED_FIELDS` |
| 2 | `event_hash = SHA-256(JCS(event minus event_hash, signature))`; `prev_hash` of `seq=1` is 64 zeros. | `envelope.py::_compute_event_hash`, `GENESIS_HASH`; `verifier.py::compute_event_hash`, `_check_hash_chain` |
| 3 | Canonicalization is a hand-written JCS (`sasana/jcs.py::canonicalize`). **It was not fully RFC 8785 conformant for floats at the time of writing** (see §1.1); 2.0.0 made `jcs.canonicalize` conformant and froze the old behaviour as `canonicalize_legacy`, selected per session by a declaration (below). | `sasana/jcs.py::_float_to_string`, `canonicalize` |
| 4 | Content is never stored; only SHA-256 digests of prompts/responses/args/results enter events. `content_hash` hashes dict/list via JCS, str via UTF-8, bytes raw, **anything else via `str(value)`**. | `sasana/event_mapper.py` (module docstring, `map_llm_call`, `map_tool_invoke`…); `sasana/_utils.py::content_hash` |
| 5 | **"Session root" is the chain tip.** There is no Merkle tree in this repo **(absent)**. `VerifyResult.root_hash` is the last event's `event_hash`; `CHAIN_SEAL.payload.session_hash` is the same value. | `verifier.py::verify` (`root_hash = sorted_events[-1]["event_hash"]`); `archeion/server.py::seal` (`"session_hash": last["event_hash"]`) |
| 6 | Ledger is a per-session SQLite file (WAL, `synchronous=FULL`), events committed one at a time, exported to JSONL at session close. | `sasana/sqlite_ledger.py::SqliteLedger.connect`, `__write_event`, `export_jsonl` |
| 7 | Authority split: `EventType.is_sdk_authority` gates `SqliteLedger.record()`; `CHAIN_SEAL` etc. are server-authority and silently dropped from the SDK path. This is an **in-process check**, not an isolation boundary. | `sasana/events.py::EventType`; `sqlite_ledger.py::record` |
| 8 | Archeion `POST /seal` runs `verify()`, refuses `PARTIAL`/non-`INTACT`/no-`SESSION_END`, then appends one Ed25519-signed `CHAIN_SEAL` (`sealed_by`, `server_pubkey`, `session_hash`, `timestamp_imprint_match`, optional `timestamp_claimed_utc` — renamed in 2.0.0 from `timestamp_verified` / `timestamp_utc`, which overstated an imprint-only check). Sealing is **post-hoc** and attests chain integrity only. | `archeion/server.py::seal`; keys in `archeion/keys.py::load_or_generate` |
| 9 | Per-event Ed25519 signing exists but is **opt-in**: `SqliteLedger(private_key=…)` embeds `session_pubkey` in `SESSION_START`. `SasanaSkill`, `OpenClawObserver`, and the OTel exporter construct ledgers **without** a key, so they do not sign. | `sqlite_ledger.py::open_session`; `signing.py`; `sasana/skill.py::_get_or_create_ledger`; `observer.py::_get_or_create_ledger`; `integrations/otel.py::_ledger_for` |
| 10 | RFC 3161 flow: `open_session` writes `SESSION_START`, submits its **pre-token** hash to the TSA (default Freetsa, `SASANA_TSA_URL` override), then **rewrites the seq-1 row** with `payload.rfc3161_token` and a recomputed `event_hash`/signature. Anchoring is **fail-open**. | `sqlite_ledger.py::open_session`, `_try_anchor_rfc3161`, `_embed_rfc3161_token`; `sasana/rfc3161.py::request_timestamp` |
| 11 | `verify_timestamp` checks only that the token parses and its `messageImprint` equals the expected hash. **The CMS signature, certificate chain, TSA identity, and policy are not verified** **(absent)**. The request carries **no nonce** **(absent)**. `genTime` is truncated to whole seconds; `accuracy` is ignored. | `rfc3161.py::verify_timestamp`, `build_timestamp_request`, `_parse_tstinfo`; `verifier.py::_check_rfc3161_timestamp` (docstring says so explicitly) |
| 11b | A bad/missing timestamp is **informational**: it never makes a session `COMPROMISED`. | `verifier.py::verify` (comment above `all_errors`) |
| 12 | Verifier runs 7 checks: structural, sequence, hash_chain, completeness, seal_signature, session_signatures, rfc3161_timestamp. Event types outside `ALLOWED_EVENT_TYPES` fail the structural check. | `verifier.py::verify`, `ALLOWED_EVENT_TYPES` |
| 13 | Evidence classes: `PARTIAL_EVIDENCE` (any `LOG_DROP`) > … > `AUTHORITATIVE_EVIDENCE` (has `CHAIN_SEAL` — *as of 1.0.0/1.1.0; from 2.0.0 it requires a seal verified against a pinned key, and an unpinned seal is `SELF_SEALED_EVIDENCE`*) > `SIGNED_NON_AUTHORITATIVE_EVIDENCE` > `NON_AUTHORITATIVE_EVIDENCE`. Nothing in the SDK ever *emits* `LOG_DROP`; it is only defined and counted. | `verifier.py::_determine_evidence_class`; `events.py`; `git grep LOG_DROP` finds no producer |
| 14 | Public surface today: `SasanaSkill`, `OpenClawObserver` (`sasana/__init__.py`), `SqliteLedger`, `build_event`, `verify`, `request_timestamp`/`verify_timestamp`, CLI `verify`/`seal`/`evidence-pack`/`observe`/`bridge` (`sasana_cli.py::main`), Archeion `/seal` `/pubkey` `/health`, integrations (OpenClaw bridge, LangGraph, CrewAI, AutoGPT, OTel). Independent Rust verifier (`sasana-rs/src/main.rs::verify_file`). |
| 15 | Tests: 160 across `tests/` (compliance 45, verifier 38, integrations 25, e2e 18, openclaw-bridge 13, rfc3161 11, otel 10). RFC 3161 tests use a synthetic token and a mocked TSA (`tests/test_rfc3161.py`). |

### 1.1 Discrepancies and gaps that affect this design

These are the places where the brief, project notes, or older docs differ from the code. None is fixed by this step.

1. **No Merkle tree.** Older notes mention one; the code has only a linear hash chain. `session_root` therefore means *chain tip* (row 5). Consequence: no selective-disclosure inclusion proofs; revealing the trace means revealing the whole chain (acceptable because events already hold only hashes — row 4).
2. **No ingestion backend in this repo.** Archeion exposes only `/seal`, `/pubkey`, `/health` (`archeion/server.py`). The "10-step FastAPI ingestion pipeline" is not here. `docs/TECHNICAL.md` and `docs/FUTURE.md` also still say "5-check verifier"; the code has 7.
3. **RFC 3161 verification is weaker than the brief assumes.** "Verification requires genTime < deadline" is only meaningful if the token is cryptographically authentic. Today it is not checked (row 11). **Pre-outcome commitment is blocked on a real CMS/chain verifier.** This is the largest dependency.
4. **RFC 3161 anchoring is fail-open** (row 10). A commitment must be **fail-closed**: no token ⇒ no commitment.
5. **JCS float non-conformance.** I ran `canonicalize` on sample values: `0.00001 → 1e-05` (RFC 8785 requires `0.00001`), `1e-7 → 1e-07` (requires `1e-7`), `1e16 → 1e16` (requires `10000000000000000`), `1e21 → 1e21` (requires `1e+21`), `2**60` is emitted exactly (RFC 8785 would round via IEEE-754). Integers/strings/booleans/typical decimals such as `0.7` are fine. For commitments this is a **cross-implementation hazard** (a verifier in another language computes a different `H(JCS(payload))`). Mitigation without touching `jcs.py` now: the commitment payload profile (§3.2) restricts numbers; fixing `jcs.py` is a separate, versioned change.
6. **`content_hash` fallback `str(value)`** (row 4) is Python-repr-dependent for non-str/dict/list/bytes inputs and not portable. Reveal-time preimage checks (§6) must restrict to the three well-defined forms.
7. **Capture is in-process by default.** The writer of the ledger and the agent are the same process (rows 6, 7, 9). See T3.
8. **Mutable seq-1 row.** `_embed_rfc3161_token` UPDATEs the stored `SESSION_START` after the TSA call (row 10). The TSA token covers the *pre-token* hash, not the final `event_hash`. This works, but it means chain rows are not append-only at the storage layer.

---

## 2. Threat model

Actors: **Committer** (agent/operator), **Counterparty** (platform/auditor/competition host that sets the deadline and, ideally, receives commitments), **Verifier** (anyone with the bundle), **TSA** (RFC 3161 time authority), **Archeion** (optional sealing authority).

Assumed: SHA-256 collision/preimage resistance; Ed25519 unforgeability; the TSA's signing key is not compromised and its clock is honest within its stated accuracy; the verifier has an authentic copy of the TSA trust anchor and of the deadline.

| ID | Threat | Defended? | By what |
|---|---|---|---|
| **T1** | **Post-outcome fabrication or editing of the trace or decision.** Committer sees the outcome, then writes or alters the reasoning to fit. | **Yes** | `C` binds `payload_hash` and `session_root` (chain tip). TSA token proves `C` existed before `genTime`. Changing any byte of payload or any earlier event changes `C`. |
| **T2** | **Post-hoc claims about tools or evidence used** ("I consulted X"). | **Partly** | Trace contains `TOOL_CALL`/`TOOL_RESULT` hashes (row 4). Claims become checkable only if the committer *discloses preimages* that hash to those fields (§6). Without disclosure the claim is unverifiable, not false. The OTel path records only `tool_name_hash`, not `args_hash`/`result_hash` (`integrations/otel.py::span_to_events`), so its trace supports weaker claims. |
| **T3** | **Undisclosed edits inside the instrumented process.** Code running in the agent process writes false events, skips events, or edits the SQLite file before commit. | **No — explicitly out of scope.** | The hash chain is only as honest as its writer. `record()`'s authority check is not a security boundary (row 7); sealing verifies structure, not truth (row 8); signing keys live in the same process (row 9). Mitigation is *graded attestation*: bundle records `capture_mode` (in-process / out-of-process sidecar / counterparty-side gateway) so verifiers can weigh it. Out-of-process capture (`OpenClawObserver`, bridge) raises the bar; it does not remove the trust assumption. |
| **T4** | **"Run many sessions, commit the best."** | **Partly, and only with a counterparty.** | A TSA proves existence, not uniqueness. Defences, strongest last: (a) one *effective* commitment per `(subject_id, context_id)` by rule; (b) **session-open commitments** published to the counterparty at `SESSION_START` so it can count sessions per context (§5); (c) counterparty-side receipt log of every `C`. Residual: sessions never opened through instrumentation are invisible. |
| T5 | Backdating by choosing a favorable TSA or replaying an old token. | Partly | Token must bind `C` (which contains a fresh 32-byte salt, so replay across commitments is impossible). Add a request nonce (row 11 gap) and a pinned TSA set. A single hobbyist TSA remains a single trust point (Open Question 6). |
| T6 | Salt or payload guessing before reveal (low-entropy decisions like `up / 0.7`). | **Yes** | 32-byte random salt inside `C`. `payload_hash` alone must never be published. |
| T7 | Selective reveal of revisions (reveal the lucky one, hide the others). | **Partly** | `prev_commitment` chaining exposes that a predecessor exists (provably, in v2, where it is inside `C`); a counterparty receipt log exposes all `C`s. Non-reveal of any received `C` is reported as a signal (§8). |
| T8 | Equivocation (two different commitments for the same `(subject, context, revision_index)`). | **Partly** | Detectable only if both reach the counterparty. Bundle verification flags it when a registry or signed receipts are supplied (`EQUIVOCATION`). |
| T9 | Colluding committer + TSA, or committer + counterparty. | **No** | Out of scope. |

---

## 3. Commitment

### 3.1 Definition

```
C = SHA-256( domain_tag || subject_id || context_id || revision_index
             || H(JCS(payload)) || session_root || salt )
```

with the byte-level encoding in §3.3 (`sasana/commitment.py::compute_commitment`). `H(JCS(payload)) = SHA-256(RFC 8785 canonical bytes of payload)`.

> **C_v1 (this section) is superseded by C_v2 (§3.5).** In v1, `prev_commitment` is *not* inside `C`: the revision chain is metadata beside `C`, the verifier checks only that it is self-consistent within a bundle, and the timestamp does not authenticate it, so it cannot prove a revision's claimed predecessor is the real one. Amendment A1 (put it inside `C`) was first declined and has now been adopted as a `domain_tag` bump to `sasana/commit/v2`. v1 bundles keep verifying so archived evidence is not stranded; new commitments should use v2.

### 3.2 Field definitions

| Field | Type | Notes |
|---|---|---|
| `domain_tag` | ASCII | `"sasana/commit/v1"` (C_v1, superseded) or `"sasana/commit/v2"` (§3.5). Separates this hash from every other SHA-256 use in the project (event hashes, content hashes). Bumped on any encoding change. |
| `subject_id` | UTF-8 string | Who commits (agent/account). Opaque to core. No Unicode normalization is applied: bytes are exactly as supplied; the bundle carries the same string. |
| `context_id` | UTF-8 string | What it's about (market+date, trade slot, eval task…). Opaque to core. |
| `revision_index` | uint32 | `0` for the first commitment, `+1` per revision. |
| `payload` | JSON object | The decision. **Payload profile:** only strings, booleans, null, arrays, objects, and *integers within ±2^53*. Real numbers must be encoded as decimal **strings** (e.g. `"0.7"`) or scaled integers. The reason was that `sasana/jcs.py` was not float-conformant (§1.1-5); it is now, but the profile is kept because the whole-number break of 2026-10-10 showed that two spellings of one number (`100` and `100.0`) can be two different byte strings. A platform mapping must say exactly how each number is spelled (Appendix A.2). |
| `session_root` | 32 bytes | `event_hash` (hex → raw) of the last event of the Sasana session chain *at commit time* (§3.4). |
| `salt` | 32 bytes | `secrets.token_bytes(32)`, fresh per revision, kept private until reveal. |

### 3.3 Byte-level encoding

Every field is encoded as **length-prefixed bytes**: `len(v)` as an unsigned 32-bit big-endian integer, followed by `v`. No separators, no implicit lengths, no concatenation of unprefixed variable-length data. Fixed-width fields are still length-prefixed so the parser is uniform, and verifiers **must** reject a field whose length differs from its definition.

```
enc(v)  = u32_be(len(v)) || v

input   = enc(domain_tag_utf8)
        || enc(subject_id_utf8)
        || enc(context_id_utf8)
        || enc(u32_be(revision_index))        # len = 4
        || enc(sha256(JCS(payload)))          # len = 32
        || enc(session_root_raw32)            # len = 32
        || enc(salt_raw32)                    # len = 32

C = SHA-256(input)                            # 32 bytes; hex lowercase in transport
```

Rules (enforced in `sasana/commitment.py::encode_commitment_input`): strings must be valid UTF-8 (reject lone surrogates); lengths must fit in u32; hex inputs must be exactly 64 lowercase hex chars (the same rule `verifier.py::_check_structural` applies to `event_hash`); `revision_index` must be < 2^32.

Unambiguity argument: the field order is fixed by `domain_tag`'s version, and each field's extent is determined by its own length prefix, so two different field tuples can never produce the same `input`.

### 3.4 What `session_root` is, and when it is fixed

`session_root` = `event_hash` of the **last event at the moment of commitment** (the chain tip). Because every `event_hash` covers `prev_hash`, the tip commits to every earlier event.

Two ways to carry the commitment:

* **Sidecar (recommended first):** the commitment lives only in the reveal bundle and counterparty record; the session JSONL is unchanged. Zero verifier changes. `session_root` must be located *somewhere* on the chain at verification; events after it are reported as post-commitment.
* **In-chain `COMMITMENT` event (later):** append an event holding `C` and token *after* computing `C` over the pre-event tip (no circularity: `C` binds seq `k-1`, the event is seq `k`). Requires adding the type to `EventType` and `verifier.ALLOWED_EVENT_TYPES`, a verifier change out of scope here. Benefit: Archeion's seal then covers the commitment.

The session need not be closed at commit time. Anything recorded after the committed tip is not covered by `C`, and verification lists it.

### 3.5 C_v2 (current): the mapping id and `prev_commitment` inside `C`

```
input   = enc("sasana/commit/v2")
        || enc(mapping_id_utf8)                 # which payload mapping gives `payload` its meaning
        || enc(subject_id_utf8)
        || enc(context_id_utf8)
        || enc(u32_be(revision_index))          # len = 4
        || enc(prev_commitment_raw32)           # len = 32 for revision > 0; len = 0 (empty) for revision 0
        || enc(sha256(JCS(payload)))            # len = 32
        || enc(session_root_raw32)              # len = 32
        || enc(salt_raw32)                      # len = 32
C = SHA-256(input)
```

(`sasana/commitment.py::encode_commitment_input_v2`, `compute_commitment_v2`.) `prev_commitment` is required exactly when
`revision_index > 0`; `mapping_id` matches `[a-z0-9][a-z0-9._-]{0,63}`. Bundles carry `bundle_version` `"2"` and a top-level
`mapping_id`. What moving them inside `C` buys, each pinned by a test (`tests/test_commitment_v2.py::TestV2CommitAndBundle`):

* **The timestamp authenticates the chain.** Editing a revision's `prev_commitment`, or splicing in a different but valid
  predecessor, changes or breaks `C`.
* **An omitted earlier commitment is provable.** Revision 1 commits, inside `C`, to a predecessor `P`; a bundle that
  does not reveal `P` is reported `HISTORY_GAP` (an error by default, §7.1). In v1 this was only an `UNREVEALED_REVISION` warning.
* **A hash match cannot be reinterpreted.** The same payload under another mapping is a different `C`; a payload that is not in
  its mapping's canonical form is refused even if its hash matches (`0.720` hashes differently from `0.72` in every other
  implementation).

What it does not do: it does not show that anyone *accepted* the predecessor or the revision (that is §5.3), and it does not
make an unrevealed predecessor revealable.

---

## 4. Trusted timestamp

1. Committer computes `C` and sends the 32 bytes to the TSA as an RFC 3161 `TimeStampReq` (SHA-256, `certReq=TRUE`, **with a random nonce**). Only a hash leaves the machine (same privacy property as `rfc3161.py::request_timestamp`).
2. The token is obtained **before** submission to the counterparty. **Fail-closed:** if no valid token is returned, `commit()` raises; it does not degrade silently (unlike `sqlite_ledger.py::_try_anchor_rfc3161`).
3. Verification of a token (all required; implemented by `rfc3161.verify_timestamp_strict`, which does **not** check revocation — §1.1-3 describes the older imprint-only check, which `sasana verify` still uses for the trace):
   * CMS `SignedData` signature valid; signer cert chains to a **verifier-pinned** TSA trust anchor; signer cert has the `id-kp-timeStamping` EKU and was valid at `genTime`.
   * `TSTInfo.messageImprint.hashAlgorithm == SHA-256` and `hashedMessage == C`.
   * Nonce echoed, if sent.
   * Policy OID acceptable to the verifier's policy.
4. **Time rule:** let `t_hi = genTime + accuracy + clock_skew_s`. If the TSA omits `accuracy` the verifier assumes `default_accuracy_s` (1 s by default) and says so in a warning; `clock_skew_s` is the verifier's assumed disagreement between the TSA's clock and the counterparty's deadline clock (default 0). The commitment is **on time** iff `t_hi < deadline`, strictly. `deadline` is an **input supplied by the verifier/counterparty, not read from the bundle**. Sub-second precision from `genTime` is preserved by the strict parser (the older imprint-only parser, `rfc3161.py::_parse_tstinfo`, truncates it). §10 lists every time and trust rule with its test.
5. Local clocks are never used: `event.timestamp` fields are writer-asserted (§1 row 1) and carry no weight here.

---

## 5. Revisions and session-open commitment

### 5.1 Revisions

* Revision `i` is a complete, independent commitment with its own salt, payload, `session_root`, and timestamp. A revision may reference a newer chain tip, which is how new tool calls enter the record.
* `prev_commitment` = `C` of revision `i-1` (`null` for `i = 0`). **Inside `C` in v2** (authenticated by the timestamp); beside it in v1.
* **A retry after a counterparty rejection continues the chain from the rejected commitment** (`prev` = the rejected `C`, index +1). Revision indices along a chain are therefore never reused, and the rejected attempt stays part of the verifiable history.
* **Scored (effective) revision.**
  * *With signed receipts* (§5.3): the receipt with the highest `revision_index` among those with `accepted == true` and `accepted_at < deadline`. It is scored only if its own commitment also passes the time rule; if not, the verdict is `LATE`, with **no fall-back** to an earlier revision the counterparty did not score. If its secrets are not in the bundle the verdict is `UNREVEALED`.
  * *Without receipts*: the highest `revision_index` among those whose `t_hi < deadline` (the v1 rule). In v2 this carries the warning `NO_RECEIPTS`, because that revision **may differ from the one the counterparty accepted** (a rejected revision, or an omitted earlier commitment, is invisible to a bundle alone).
* **Ordering check:** `t_hi` must be non-decreasing in `revision_index`, and receipt `accepted_at` must be non-decreasing in `revision_index`; a violation is an error.
* **Superseded revisions remain verifiable:** the bundle may and, by policy, should include them; each verifies exactly like the effective one.
* **Gaps.** v2: a revealed revision whose predecessor is absent, or present but failing verification, is `HISTORY_GAP`, an error unless `allow_unrevealed_history` (a broken reveal hides a revision as surely as omitting it). v1: `UNREVEALED_REVISION` warning.

### 5.2 Optional session-open commitment — DEFERRED (not implemented)

Goal: let a counterparty **count sessions per context** (T4).

At `SESSION_START` the committer publishes `open_binding = SHA-256(enc("sasana/open/v1") || enc(subject_id) || enc(context_id) || enc(session_id) || enc(salt_open))` to the counterparty and stores `context_binding = open_binding` in the `SESSION_START` payload (a new optional key; the existing hash chain and the existing RFC 3161 token over the pre-token `SESSION_START` hash then also cover it for free). The counterparty's registry then holds one entry per opened session per `(subject, context)`.

At reveal, the committer discloses `salt_open` and `session_id`; the verifier recomputes `open_binding`, checks it matches the `SESSION_START` payload, and compares the registry's session count for the context with the number of revealed sessions. Differences are reported (`SESSIONS_UNACCOUNTED`).

Registering the session root (or a hash of it) with the counterparty at `SESSION_START` would make the counterparty the first checkpoint witness of [`design/witness-anchoring.md`](design/witness-anchoring.md) (heads published *during* the session). **It is still deferred; see §11.**

Caveats stated plainly: this only works with a counterparty-held registry; it cannot detect sessions that were never instrumented; and the existing session-start anchoring is fail-open (`sqlite_ledger.py::_try_anchor_rfc3161`) so session-open mode needs its own fail-closed path.

### 5.3 Counterparty acceptance receipts — PROPOSED EXTENSION (verifier input only)

Which revision a counterparty *accepted before its cutoff* cannot be read off a bundle: the highest on-time revision in a bundle may differ from the last accepted submission, a rejected revision still carries a valid timestamp, and an omitted earlier commitment leaves no trace. What closes this is a record **made by the counterparty at acceptance time**. The verifier accepts one as a signed receipt.

> **PROPOSED EXTENSION — not an HA interface** (and not an interface of any other platform). No counterparty we know of issues this. It is implemented here only as something `verify_commitment` can consume, and exercised with synthetic keys.

```jsonc
{ "body": { "challenge_id": "…",        // = context_id
            "agent_id": "…",            // = subject_id
            "revision_index": 1,
            "commitment": "<hex C>",
            "accepted_at": "2026-10-14T09:30:02Z",   // the COUNTERPARTY's clock, tz-aware
            "accepted": true,           // false = the submission carrying this C was rejected
            "reason": null,             // free text, signed but never interpreted
            // optional, lets the counterparty vouch for WHAT it accepted (Appendix A.3):
            "mapping_id": "ha-daily-v1",
            "payload_hash": "<hex SHA-256 of JCS(canonical payload)>" },
  "signature": "<hex Ed25519 signature over the bytes  'sasana/receipt/v1' + LF  followed by  JCS(body)>" }
```

Rules (all in code, `sasana/commitment.py::verify_receipt` and `_process_receipts`; tested in `tests/test_commitment_v2.py`):

* The signature is checked against **one pinned key** the verifier supplies (`trusted_receipt_pubkey`, base64 raw Ed25519). Receipts supplied without a pinned key make the verdict `INVALID`. A key travelling inside a receipt is never read.
* Receipts for another `agent_id` / `challenge_id` are ignored (counted). A bad signature, two accepted commitments for one `revision_index` (`EQUIVOCATION`), or contradictory receipts for one commitment make the verdict `INVALID`.
* If a receipt carries `payload_hash` or `mapping_id`, they must match the revealed revision (`RECEIPT_PAYLOAD_MISMATCH`, `RECEIPT_MAPPING_MISMATCH`).
* `TSA_TIME_AFTER_ACCEPTANCE` (warning): a commitment cannot be submitted before it exists, so the TSA's time for `C` must not be later than `accepted_at` beyond accuracy and the assumed skew.

What a receipt does **not** establish: that the receipt list is *complete* (a committer who supplies the list can withhold a later accepted receipt, so receipts must come from the counterparty, and a terminal "closed at the deadline, last accepted = k" receipt would let a verifier detect withholding; **not implemented**, see §10 and §11), that the counterparty's clock is honest, or that its signing key is genuine (that is the pin).

---

## 6. Reveal bundle (as implemented)

A single JSON document (JCS-canonical when hashed or signed; pretty-printed for humans is fine otherwise).

```jsonc
{
  "bundle_version": "1",
  "domain_tag": "sasana/commit/v1",
  "subject_id": "…",
  "context_id": "…",
  "capture_mode": "in_process | sidecar | gateway",      // self-declared, see T3
  "revisions": [
    {
      "revision_index": 0,
      "prev_commitment": null,                          // hex C of previous revision
      "commitment": "<hex C>",
      "payload": { /* the committed decision, profile of §3.2 */ },
      "session_root": "<hex>",
      "salt": "<hex 32 bytes>",
      "tsa_token": "<base64 DER TimeStampResp>"
    }
  ],
  "session_events": [ /* full JSONL of the session, as objects, incl. CHAIN_SEAL if sealed */ ],
  "disclosures": [                                      // optional preimages for T2
    { "seq": 7, "field": "args_hash", "form": "jcs|utf8|bytes", "preimage": "<json | string | base64>" }
  ],
}
```

**v2 bundle.** Same shape with `"bundle_version": "2"`, `"domain_tag": "sasana/commit/v2"` and a top-level `"mapping_id"`; `prev_commitment` is then authenticated by `C`. Receipts (§5.3) are **not** part of the bundle: they are a separate verifier input obtained from the counterparty, because a committer must not be the courier of the acceptance evidence. A v2 bundle may have an empty `revisions` list when receipts are supplied (verdict `UNREVEALED`).

Notes: the TSA certificate chain travels inside each `tsa_token` (requested with `certReq=TRUE`); trust anchors are never taken from the bundle. The bundle never contains the outcome, and the **deadline is not in it** (verifier input). Events already contain only digests (§1 row 4), so publishing `session_events` does not publish prompts or tool content; `disclosures` is how a committer chooses to prove specific evidence claims, limited to the three well-defined forms (`jcs`, `utf8`, `bytes`), never the `str(value)` fallback (§1.1-6).

---

## 7. Verification algorithm (as implemented in `verify_commitment`)

Differences from the first draft: step 7 (session-open) is omitted because §5.2 is deferred; a revealed session must be **complete** (`SESSION_END` present), because step 2 uses the unmodified `verify()`; a failure of a *higher-index* revision than the effective one makes the verdict `INVALID` (the effective revision cannot be established), whereas a failed lower-index revision is a warning.

Inputs: `bundle`, `deadline`, `trusted_tsa_anchors`, optional `trusted_seal_pubkey`, optional `registry` (list of `C` and open-bindings the counterparty received), `policy` flags.

1. **Parse and version-check.** Unknown `bundle_version`/`domain_tag` ⇒ `INVALID`.
2. **Trace integrity.** Run the existing `sasana.verifier.verify(session_events, trusted_seal_pubkey=…)` (since 2.0.0: under the session's declared canonicalization; a pinned key requires a seal; an unpinned seal is `SELF_SEALED_EVIDENCE`, not authoritative). `COMPROMISED`/`ERROR` ⇒ `INVALID`. `PARTIAL` ⇒ `INVALID` unless `policy.allow_partial`. Record `evidence_class`.
3. For **each revision** `r`:
   1. Check payload profile (§3.2). Compute `ph = SHA-256(JCS(r.payload))`.
   2. Check each hex/length rule; build `input` per §3.3; compute `C'`. `C' != r.commitment` ⇒ revision `INVALID`.
   3. **Locate `session_root`** among `session_events[*].event_hash`; absent ⇒ `INVALID`. Let `k` be its `seq`. Events with `seq > k` are listed as `post_commitment_events` (informational; this is where outcome-aware activity would appear).
   4. **Verify the TSA token** per §4.3 against `C'`. Extract `genTime`, `accuracy`.
   5. `on_time = (genTime + accuracy) < deadline`.
4. **Revision chain.** Indices contiguous from 0 within the bundle (gaps ⇒ `UNREVEALED_REVISION`); `prev_commitment` equals the previous revision's `C` (in v2 it is inside `C`); `t_hi` non-decreasing.
5. **Select the effective revision:** highest index with `on_time`. None ⇒ verdict `LATE` (all commitments postdate the deadline).
6. **Registry cross-check (if supplied):** every `C` in the registry must appear in the bundle (else `UNREVEALED_COMMITMENT`, with count); every bundle `C` must be in the registry received before `deadline` (else `NOT_RECEIVED_BY_COUNTERPARTY`); two registry entries sharing `(subject, context, revision_index)` with different `C` ⇒ `EQUIVOCATION`.
7. *(Deferred — session-open cross-check.)*
8. **Disclosures (if present):** for each, recompute `content_hash` in the declared form and compare to the event's field at `seq`; mismatch ⇒ that disclosure `FAILED` (does not invalidate the commitment).
9. **Verdict.** One of `VALID_ON_TIME`, `LATE`, `INVALID` or (v2 with receipts) `UNREVEALED` (§7.1), plus a list of warnings (`UNREVEALED_*`, `EQUIVOCATION`, `SESSIONS_UNACCOUNTED`, `post_commitment_events`, `capture_mode`, evidence class, weak-TSA-accuracy). The verifier never collapses warnings into a boolean.

### 7.1 Current verifier behaviour (v2, receipts, policy)

Differences from the steps above, all in `verify_commitment`:

* **Preconditions fail closed (`INVALID`):** no pinned TSA anchors; negative, non-finite or non-numeric `clock_skew_s`; receipts without a pinned receipt key; `require_receipts` without receipts; a naive (timezone-less) deadline.
* **Step 1** accepts `(bundle_version, domain_tag)` of `("1", "sasana/commit/v1")` or `("2", "sasana/commit/v2")`. For v2 the `mapping_id` must be a registered mapping, and equal to `expected_mapping_id` if the verifier requires one. A v1 bundle cannot satisfy a required mapping.
* **Step 3.2** for v2 recomputes `C_v2` and then requires the payload to be in its mapping's canonical form.
* **Step 4** for v2: a missing or unverified predecessor is `HISTORY_GAP` (error, or warning with `allow_unrevealed_history`).
* **Step 5** with receipts: the scored revision comes from the receipts (§5.1), not from the bundle.
* **Verdicts:** `VALID_ON_TIME`, `LATE`, `INVALID`, and **`UNREVEALED`**: the counterparty accepted a revision whose secrets the bundle does not reveal. That is neither a pass nor a failure; it is the absence of evidence, reported as such (CLI exit 4). Without receipts a bundle with no revisions is still `INVALID`, because nothing is known.
* **Warnings added:** `NO_RECEIPTS`, `NOT_ACCEPTED_BY_COUNTERPARTY:i`, `UNREVEALED_COMMITMENT:i`, `RECEIPT_AFTER_DEADLINE:i`, `NO_ACCEPTED_RECEIPT_BEFORE_DEADLINE`, `SCORED_REVISION_NOT_ON_TIME:i`, `TSA_TIME_AFTER_ACCEPTANCE:i`, and the mapping's payload warnings (`PROBABILITY_SUM:x`, `PROBABILITY_NEGATIVE`).
* `checks["policy"]` in the verdict records the policy actually applied (anchors pinned, time rule, assumed accuracy and skew, revocation not checked, seal key pinned, receipt key pinned).

---

## 8. Limits (stated plainly)

* **Completeness is not proven.** The chain proves the recorded events were not altered; it cannot show that every relevant action was recorded (the SDK never even emits `LOG_DROP`, §1 row 13).
* **Truthfulness is not proven.** A committed trace may record false statements. Commitment fixes *what was claimed and when*, not whether it was true.
* **Human influence outside instrumentation is invisible.** A person (or another program) may have chosen the decision and fed it in; the trace shows only the instrumented path. See T3: undisclosed in-process edits are not defended.
* **Time is as good as the TSA.** Without the full CMS verification described in §4, the "timestamp" is just a blob. A single TSA is a single trust point.
* **Uniqueness requires a counterparty.** A timestamp proves "existed by", never "the only one".
* **Non-reveal is itself a signal, not a proof.** A committed `C` that is never revealed tells a counterparty something (the committer chose not to be scored) but proves nothing about the hidden contents. Platforms should define the consequence in their rules; the core only reports it.
* **A seal does not protect against the operator (A8).** An operator with access to `/seal` can obtain an authoritative seal on a rewritten session. Against the operator Sasana 2.x provides no rewrite protection unless `/seal` access is controlled by a party independent of the operator; the commitment `C` held by a counterparty before the deadline is what binds the session up to `session_root`.
* **Which revision was accepted is only as good as the receipts.** Without a counterparty's signed receipts the verifier cannot know it; with them it trusts the counterparty's key, clock and the completeness of the list it is handed (§5.3).
* **A matching trace is not completeness, truthfulness, or absence of human influence.** A trace that hashes to a timestamped `C` shows those bytes existed by `genTime`; it does not show every relevant action was recorded, that the recorded statements are true, or that nobody outside the instrumented process chose the decision.
* **Lost salt = unrevealable commitment.** The salt must be persisted with the same care as a signing key.

---

## 9. API (as implemented, `sasana/commitment.py`)

```python
def commit(*, subject_id: str, context_id: str, payload: Mapping[str, Any],
           session_events: Sequence[Mapping[str, Any]], trusted_tsa_anchors: Sequence[bytes],
           tsa_urls: Optional[Sequence[str]] = None, prev: Optional[PublicCommitment] = None,
           salt: Optional[bytes] = None, allowed_policies: Optional[Sequence[str]] = None,
           mapping_id: Optional[str] = None,   # set => C_v2; payload must already be canonical for it
           ) -> tuple[PublicCommitment, CommitmentSecrets]: ...          # raises CommitmentError (fail-closed)

def reveal_bundle(commitments: Sequence[tuple[PublicCommitment, CommitmentSecrets]],
                  session_events: Sequence[Mapping[str, Any]], *,
                  capture_mode: Literal["in_process", "sidecar", "gateway"],
                  disclosures: Optional[Sequence[Mapping[str, Any]]] = None) -> dict: ...

def verify_commitment(bundle: Mapping[str, Any], *, deadline: datetime,
                      trusted_tsa_anchors: Sequence[bytes], trusted_seal_pubkey: Optional[str] = None,
                      registry: Optional[Sequence[Mapping[str, Any]]] = None,
                      allow_partial: bool = False, default_accuracy_s: float = 1.0,
                      allowed_policies: Optional[Sequence[str]] = None,
                      receipts: Optional[Sequence[Mapping[str, Any]]] = None,   # PROPOSED EXTENSION input
                      trusted_receipt_pubkey: Optional[str] = None,
                      expected_mapping_id: Optional[str] = None,
                      require_receipts: bool = False, allow_unrevealed_history: bool = False,
                      clock_skew_s: float = 0.0) -> CommitmentVerdict: ...  # never raises
```

Also public: `compute_commitment` / `encode_commitment_input` (v1), `compute_commitment_v2` / `encode_commitment_input_v2`, `payload_hash`, `validate_payload_profile`, `disclosure_hash`, `sign_receipt`, `verify_receipt`; dataclasses `PublicCommitment` (now with `mapping_id`), `CommitmentSecrets` (both with `to_dict`/`from_dict`), `CommitmentVerdict` (verdict now also `UNREVEALED`); and, in `sasana/commitment_mapping.py`, `map_ha_daily_v1`, `canonical_decimal`, `check_canonical_ha_daily_v1`, `probability_warnings`, `cross_check_published`, `MAPPINGS`. Differences from the first sketch: `commit()` takes `trusted_tsa_anchors` (it self-verifies the token before returning) and `allowed_policies`; `reveal_bundle` has no `session_open`; the verdict also carries `effective_payload` and `errors`.

**Operational note:** `CommitmentSecrets.salt` must be persisted with the same care as a signing key; without it the commitment can never be revealed.

---

## 10. Time and trust policy (enforced in code)

Every row is either pinned by a test or marked **NOT ENFORCED** (and, where useful, pinned by a test that documents the limitation). Tests are in `tests/test_commitment_v2.py` unless another file is named. The effective policy is echoed in `verdict.checks["policy"]`.

| # | Rule | What the code does | Status / test |
|---|---|---|---|
| 1 | **TSA anchors are pinned by the verifier** | `trusted_tsa_anchors` (CLI `--tsa-anchor`, repeatable) are the only roots trusted; certificates inside a token are never trusted on their own. An empty list is `INVALID`, never "trust anything". | Enforced. `TestTimeAndTrustPolicy::test_empty_trust_anchors_fail_closed` |
| 2 | **An unknown TSA is refused** | A token that does not chain to a pinned anchor makes that revision invalid (`timestamp invalid`). If it is the scored revision, or (v2) the predecessor of a revealed one, the bundle is `INVALID`. `commit()` raises rather than return such a token. | Enforced. `test_unknown_tsa_is_rejected_even_if_its_cert_travels_in_the_token`; `test_commitment.py::TestVerify::test_forged_timestamp_from_unpinned_tsa`; `test_commitment_sasana2.py::TestTimestampPaths` |
| 3 | **TSA certificates were valid at `genTime`** | Every certificate on the path must be valid at `genTime`. | Enforced (`rfc3161.verify_timestamp_strict`). `test_a_token_whose_signing_cert_was_not_valid_at_gentime_is_refused_at_commit`; `tests/test_rfc3161_strict.py` |
| 4 | **Time rule** | On time iff `genTime + accuracy + clock_skew_s < deadline`, **strictly** (equality is late). The deadline is a verifier input, never read from the bundle; a timezone-less deadline is `INVALID`. | Enforced. `test_time_rule_is_strict_gentime_plus_accuracy_before_deadline`, `test_declared_accuracy_widens_the_window`, `test_the_deadline_comes_from_the_verifier_never_from_the_bundle` |
| 5 | **Accuracy absent** | The verifier assumes `default_accuracy_s` (1 s unless set), flags the revision `accuracy_assumed`, and warns `TSA_ACCURACY_ASSUMED`. A stricter assumption can turn the same token late. FreeTSA omits accuracy and issues whole-second `genTime`. | Enforced. `test_absent_accuracy_is_assumed_and_reported` |
| 6 | **Clock-skew assumptions** | Three clocks exist. The **TSA's** is trusted within its stated accuracy. The **counterparty's** defines the deadline and `accepted_at` (compared with each other directly). The **committer's** is never used (event timestamps are writer-asserted). Disagreement between the TSA's and the counterparty's clock is *not measured*: the default assumption is none, `clock_skew_s` lets the verifier assume some, and an impossible ordering (TSA time for `C` later than the counterparty's `accepted_at`) is flagged `TSA_TIME_AFTER_ACCEPTANCE`. | Enforced as described. `test_clock_skew_allowance_is_part_of_the_time_rule`, `test_bad_skew_values_fail_closed`, `TestScenarios::test_e2_…`. **NOT ENFORCED:** any bound on TSA-versus-counterparty drift beyond that warning |
| 7 | **Revocation is not checked** | CRL/OCSP are not consulted and no revocation date is compared with `genTime`. The verdict records `revocation_checked: false`. | **NOT ENFORCED.** Limitation tests: `test_revocation_is_not_checked_NOT_ENFORCED`, `test_what_missing_revocation_costs_a_stolen_tsa_key_can_backdate_NOT_ENFORCED` |
| 8 | **One TSA per commitment** | `tsa_urls` are tried in order; one token is kept. | **NOT ENFORCED:** no n-of-m |
| 9 | **The seal is optional and is verified only against a pinned key** | `trusted_seal_pubkey` (`--trust-key`) pins it. With a pin a seal is required and must verify (`INVALID` otherwise); without one a seal that verifies only against its own key is `SELF_SEALED_EVIDENCE`. The evidence class is reported and **never changes the verdict or the time**. | Enforced. `TestSealIsOptionalAndNotRelied`; `test_commitment_sasana2.py::TestSealPolicyForCommitments`; examples `b` with and without `--trust-key` |
| 10 | **The seal is not relied on against the operator (A8)** | A rewritten session resealed by the genuine key verifies `AUTHORITATIVE_EVIDENCE` under the pin; the commitment is what fails (`session_root` no longer in the session). | Enforced by the commitment, not the seal. `test_commitment_sasana2.py::TestA8AgainstACommitment`; `TestScenarios::test_i_…`; `examples/ha-reveal/bundles/i-…` |
| 11 | **The receipt key is pinned** | `trusted_receipt_pubkey` (`--receipt-key`, base64 raw Ed25519) is the only key trusted. Receipts without a pin are `INVALID`; a key inside a receipt is ignored; a different key makes the receipt invalid; the signature covers a domain tag, so it cannot be replayed as another message type. | Enforced. `TestReceiptSignatures`, `TestReceiptPolicy::test_receipts_need_a_pinned_key`, `…signed_by_another_key_are_invalid` |
| 12 | **How the receipt key is published, rotated or scoped** | There is one key, no key id, no validity period; a rotation is a new out-of-band pin. How a counterparty would publish the key is unspecified. | **NOT ENFORCED / NOT SPECIFIED** |
| 13 | **Receipt-list completeness** | The verifier uses the receipts it is given. It cannot tell whether a later accepted receipt was withheld, so the list must come from the counterparty, not the committer. | **NOT ENFORCED.** A terminal "closed at the deadline, last accepted = k" receipt would let the verifier detect withholding; not implemented (§11) |
| 14 | **The payload mapping is pinned** | `expected_mapping_id` (`--mapping`) is required to equal the bundle's. A verifier that does not pass one accepts the bundle's own registered mapping. | Enforced when supplied. `test_g3_a_required_mapping_is_enforced`, `test_a_c_v1_bundle_still_verifies_but_cannot_satisfy_a_required_mapping` |
| 15 | **A broken or missing earlier revision is not silently accepted** | `HISTORY_GAP` is an error unless `allow_unrevealed_history`. | Enforced. `test_d_bundle_omits_the_initial_commitment`, `test_f2_…` |
| 16 | **A mistyped policy flag is not ignored** | Unknown or abbreviated flags of `verify-commitment` exit 3 (they were silently dropped before, so a mistyped `--trust-key` removed the pin). | Enforced. `TestCli::test_unknown_or_abbreviated_flags_are_refused_not_ignored` |

**What the missing revocation check costs an attacker nothing.** Someone who holds a TSA signing key can mint a token with any `genTime`, and a token signed by a key that was compromised and later revoked verifies exactly like a genuine one, because we neither consult revocation nor compare a revocation time with `genTime`. The attacker's gain is a *backdated* commitment: one made after the deadline that appears to predate it. Two things bound the damage. With receipts (§5.3) the scored revision is whatever the counterparty accepted before its cutoff, so a backdated token does not change *which* revision is scored; it only weakens the independence of the "existed before the deadline" claim from the counterparty's own clock. And the attacker needs the TSA's key, not the committer's, which is why n-of-m TSAs (row 8) would be the real fix.

---

## 11. What is still open (stated plainly)

* **Session-open commitments are still deferred (§5.2).** Registering the session root, or a hash of it, with the counterparty at `SESSION_START` would make the counterparty the first checkpoint witness of [`design/witness-anchoring.md`](design/witness-anchoring.md). Until then nothing external has seen the chain before the first commitment: an operator can rewrite events recorded *before* the first `C` and no one can tell, and sessions that were never committed are invisible (T4).
* **A matching trace does not prove completeness, truthfulness, or the absence of human influence outside the instrumentation (§8, T3).** It shows those bytes existed by `genTime` and were not altered since; nothing more.
* **No counterparty issues receipts.** Receipts (§5.3) are a proposal, and every statement here about which revision was accepted holds only if a counterparty produced such receipts. The completeness of the receipt list and the publication and rotation of its key are not enforced or specified (§10 rows 12–13).
* **The mapping binds seven fields and not the rest.** `prompt_hash`, `amount`, `token_usage` and `trigger_event_id` are declared by the daily schema but are **not** in the payload, so a change to them is not detected. Whether any of them should be bound is undecided (Open question 20).
* **Probability shape and range rules are not known.** The mapping is shape-agnostic and treats the sum as a warning, not a rejection, so that anything a counterparty accepted can be committed.
* **Single TSA, no revocation (§10 rows 7–8).**
* **Verification depends on later availability** of the counterparty's receipts and results; a counterparty's current anonymous access is not a retention guarantee.
* **There is only a Python implementation of `verify_commitment`.** The mapping has shared vectors (`tests/fixtures/mapping/ha-daily-v1.json`) so another implementation can be held to the same table; none exists.

---

## Appendix A — Headline Arena daily-market mapping (worked example, synthetic data only)

### A.0 Provenance and status

* **HA-1** = Headline Arena's (HA) description to us of its **current public interface**, 2026-10-05, with daily-market forecasts as the main example. The field lists are, per HA, from its public OpenAPI schema. **We have not independently read that schema;** where this appendix says "HA declares", it means "HA told us the schema declares". HA may correct any row.
* **HA-2** = HA's follow-up questions, 2026-10-11 (the three mapping questions answered in A.2, A.3 and §10).
* **ours** = Sasana's own proposal. A row marked *ours* is **not** an HA interface.
* **PROPOSED EXTENSION — not an HA interface** marks every HA-side change this note suggests. HA API changes, engineering work, access and any joint publication would need a separate agreement with HA; nothing here is an HA integration, and HA has neither reviewed nor endorsed this note.
* **Family:** daily-market directional forecasts only. HA's other families (price-event, civic, the unified schema) declare different fields and have different revision semantics; they are not covered.
* **Data:** every bundle, identifier and key in `examples/ha-reveal/` is synthetic. No HA endpoint was called and no HA data or real agent id was used.

### A.1 What HA's public interface declares (as described to us)

| Topic | HA's public interface | Source |
|---|---|---|
| Daily-market submission fields | `direction`, `confidence`, `probabilities`, `prompt_hash`, `amount`, `reasoning`, `summary`, `token_usage`, `is_revision`, `trigger_event_id`, `revision_reason` | HA-1 §1 |
| Challenge and agent identity | The challenge is identified in the endpoint, the agent through authentication. Neither is a body field. | HA-1 §1 |
| Attaching a session root | **No documented generic metadata or session-root attachment field.** `prompt_hash` is the 64-character SHA-256 digest of the prompt configuration and must not be reused for a session root; `token_usage` is not a general-purpose commitment field. A dedicated binding would be proposed interface work. | HA-1 §1 |
| Reasoning length | 20–8,000 characters for daily and price-event submissions. | HA-1 §1 |
| Revisions | Daily revisions use `is_revision: true` before the deadline; a duplicate initial submission is rejected. The methodology preserves pre-deadline revision history, which does not mean every endpoint exports a complete revision/proof chain. Revision semantics differ by family. | HA-1 §2 |
| What the deadline fixes | It closes eligibility to create or revise the scored forecast. Later daily submissions may be separate paper-trade signals (`counts_for_score: false`). Settlement rules are defined in advance. The cutoff is application-level and **does not establish cryptographic immutability of every submitted field.** | HA-1 §3 |
| Post-resolution response (daily example) | `challenge_id, status, result, open_price, close_price, resolution_source, resolved_at, submitted_count, predictions`; each prediction has `agent_id, direction, confidence, reasoning, summary, is_correct, score`. | HA-1 §4 |
| Not in that response | prediction IDs, `probabilities`, `prompt_hash`, `prediction_hash`, TSA tokens, revision history, submission timestamps. It is a results API, not a cryptographic proof export. | HA-1 §4 |
| Access | Availability is endpoint-specific; today's anonymous access is not a permanent-access or retention guarantee. | HA-1 §4 |
| Scope HA considers sensible | Hash-only, with no trace or data exchange at this stage. | HA-1 §4 |

### A.2 The versioned payload mapping `ha-daily-v1` (HA-2 question 1)

A successful hash check must not be able to conceal a change in meaning, so the commitment binds an explicit, **versioned** mapping from the submission to the payload hashed inside `C`. The mapping id is itself inside `C` (§3.5). Implementation: `sasana/commitment_mapping.py::map_ha_daily_v1`.

| Sasana field | From HA (as declared) | Canonical form inside `H(JCS(payload))` | Source |
|---|---|---|---|
| `subject_id` | the agent: identified by authentication on submission, `agent_id` in resolved predictions | the exact string, no normalisation | HA-1 §1, §4 |
| `context_id` | the challenge: in the endpoint on submission, `challenge_id` in the resolved response | the exact string, no normalisation | HA-1 §1, §4 |
| `mapping_id` | — | `"ha-daily-v1"`, **inside `C`** | ours |
| `revision_index` | HA documents `is_revision` (a boolean) and no index | assigned by the committer: 0 for the initial forecast, +1 per revision | ours |
| `prev_commitment` | — | the previous revision's `C`, **inside `C`** | ours |
| `payload.direction` | `direction` | string, byte-exact | HA-1 §1 |
| `payload.confidence` | `confidence` | decimal string (rules below) | HA-1 §1 |
| `payload.probabilities` | `probabilities` | the shape HA uses is not stated, so an object or an array is preserved; each entry is a decimal string; 1–1000 entries | HA-1 §1 |
| `payload.reasoning` | `reasoning` | string, byte-exact: not trimmed, no Unicode normalisation (NFC and NFD differ) | HA-1 §1 |
| `payload.summary` | `summary` | string or null; **omitted** if not supplied | HA-1 §1 |
| `payload.is_revision` | `is_revision` | boolean only | HA-1 §1 |
| `payload.revision_reason` | `revision_reason` | string or null; **omitted** if not supplied | HA-1 §1 |
| *not bound* | `prompt_hash`, `amount`, `token_usage`, `trigger_event_id` | not in the payload. A change to them is **not detected** by the commitment. The mapping reports which were present (`unbound_present`). | HA-1 §1 |
| `session_root` | not an HA field (see A.1) | chain tip of the Sasana session, hex | ours |
| `deadline` | HA's cutoff for the challenge (value not in what we were given) | verifier input; never read from the bundle | HA-1 §3 |

**Absence is meaningful.** A field not supplied is omitted, a field supplied as `null` is `null`, and a field supplied as `""` is `""`; these three hash differently. The mapping never invents a default and does not decide which fields HA requires. Unknown fields (including `agent_id` or `challenge_id` in the body) are rejected, not ignored.

**Numbers become decimal strings, never JSON numbers:**

| Rule | Behaviour |
|---|---|
| Notation | plain decimal; no exponent, no `+`, no leading zeros (`.5`, `5.`, `+1`, `00.5` are rejected) |
| Zeros | no trailing zeros and no trailing `.`; `0.6`, `0.60`, `"6e-1"` all become `"0.6"`; `100` and `100.0` both become `"100"` |
| Zero | `0`, `-0`, `-0.0` and `"0.000"` all become `"0"` |
| Precision | at most 18 integer and 12 fractional digits; more is **rejected, never rounded** (`0.1 + 0.2` is refused; round it first) |
| Not a number | `NaN`, `±Infinity`, booleans, `null` and non-decimal text are rejected |
| Floats | enter through their shortest round-trip repr, so `0.6` is `"0.6"` on every IEEE-754 platform |

The `100` / `100.0` case is not hypothetical: it is the whole-number-float break found on 2026-10-10 (CHANGELOG 2.0.0, "Canonicalization"), where one number had two byte strings.

**Probability policy.** `probabilities` is **not** rejected for summing to something other than 1, because the mapping must be total over whatever HA accepted or a forecast it scored could not be committed. It warns instead: `PROBABILITY_SUM:<sum>` when `|sum − 1| > 1e-6`, and `PROBABILITY_NEGATIVE`.

**Test vectors** (`tests/fixtures/mapping/ha-daily-v1.json`, run by `tests/test_commitment_mapping.py`; another implementation should reproduce all of them): 6 equivalence groups hash the same (`0.6` spelled five ways; `100`/`100.0`; `0`/`-0.0`; probability key order; declared-but-unbound fields differing); 15 pairs hash differently (`0.6` vs `0.06`; `up` vs `down`; `summary` missing vs `""` vs `null`; `is_revision` missing vs `false`; `revision_reason` missing vs `""`; probabilities swapped; object vs array; NFC vs NFD; a trailing space); 23 inputs are rejected.

### A.3 Which revision HA accepted: the registry (HA-2 question 2)

HA's public interface exposes no acceptance record: the resolved response carries no revision history, no submission timestamps and no commitment. So the verifier cannot tell from HA's current data which revision was accepted before the cutoff, and "the highest on-time revision in a bundle" is not that. What would let it:

> **PROPOSED EXTENSION — not an HA interface.** (a) An optional `commitment` field on a daily submission, carrying the hex `C` (hash only; no trace or data exchange, matching the scope HA called sensible). The TSA token stays with the committer and arrives in the reveal bundle. (b) A **signed acceptance receipt** for every submission attempt, in HA's vocabulary: `{challenge_id, agent_id, revision_index, commitment, accepted_at, accepted: true|false, reason}`, signed by an HA key the verifier pins (§5.3). Optionally `mapping_id` and `payload_hash`: HA recomputes `H(JCS(ha-daily-v1(accepted fields)))` from what it *actually accepted* and signs it, which is the only way to bind the commitment to the exact payload HA accepted for the three fields its results API does not publish (probabilities, `is_revision`, `revision_reason`).

The scored revision is then the receipt with the highest `revision_index` that has `accepted: true` and `accepted_at` before the deadline (§5.1). Two cases from HA-2 are in `examples/ha-reveal/`: a **rejected revision** (`c`: the initial is scored) and an **omitted earlier commitment** (`d`: provable because `prev_commitment` is inside `C`). What this still does not give is the completeness of the receipt list (§10 row 13).

**What can be checked against HA's current public data alone.** `cross_check_published(payload, prediction)` compares a revealed payload with a prediction as HA's results API returns it, on the four fields it returns: `direction`, `confidence`, `reasoning`, `summary` (confidence compared as a number, not as text). It cannot check `probabilities`, `is_revision` or `revision_reason`, which the results API does not return. It proves nothing about timing and can only be run after resolution.

### A.4 Trust and time policy for this example (HA-2 question 3)

The example requires: a **pinned TSA anchor**; the time rule `genTime + accuracy + clock_skew_s < deadline` with `default_accuracy_s` assumed (and reported) when the TSA omits accuracy, as FreeTSA does; an **optional seal**, verified only when `--trust-key` is given and never changing the verdict; a **pinned receipt key**; a required `ha-daily-v1` mapping; and **no revocation checking**, documented in §10 with what that costs. Each rule has a test or is marked NOT ENFORCED there.

### A.5 Synthetic reveal bundles (HA-2: an example of an initial forecast plus one revision)

`examples/ha-reveal/` holds eleven synthetic bundles for an initial forecast and one revision, and a runner that prints `bundle | expected | actual | match`:

| Bundle | Case | Verdict |
|---|---|---|
| `a-initial-only` | initial, accepted | `VALID_ON_TIME`, scored 0 |
| `b-revision-accepted` | initial + revision, both accepted | `VALID_ON_TIME`, scored 1 |
| `c-revision-rejected` | revision rejected by the counterparty | `VALID_ON_TIME`, scored **0** |
| `d-initial-omitted` | bundle omits the initial commitment | `INVALID` (`HISTORY_GAP`) |
| `e-…-rejected`, `e2-…-receipt-says-accepted` | revision timestamped after the deadline | scored 0; and `LATE` when a receipt claims it was accepted |
| `f-payload-tampered` | payload edited after commit | `INVALID` |
| `g-wrong-mapping-version` | mapping id not the required one | `INVALID` |
| `h-never-revealed`, `h2-scored-revision-not-revealed` | accepted revision never revealed | `UNREVEALED` |
| `i-operator-reseal-after-commit` | session rewritten and resealed after commit | `INVALID` |

Run `python3 examples/ha-reveal/run.py`; see `examples/ha-reveal/README.md`.

### A.6 Open, HA-specific

* The values HA would use for the deadline, and the TSA(s) it would accept, are HA's to state.
* Whether HA would add a `commitment` field, issue receipts, or sign `payload_hash` is HA's decision and needs a separate agreement; the commercial question is not addressed by this note.
* There is no HA adapter. `examples/ha-reveal/` contains synthetic bundles only; any integration would be separate work and would belong outside core.
* Session-open commitments, and the limits in §11, apply unchanged.

---

## Open design questions — status

Resolved by earlier choices and later work:

1. ~~Bind `prev_commitment` inside C?~~ **Yes, as C_v2** (§3.5). It was first declined; a counterparty review asked how an omitted earlier commitment would be detected, which only works if the chain is authenticated. v1 is superseded but still verifies.
2. ~~Sidecar vs in-chain event?~~ **Sidecar.** No new `EventType`; verifier unchanged apart from one added helper.
3. ~~Number policy?~~ **Strings/ints-only payload profile kept; `jcs.py` also fixed** (RFC 8785 vectors). Rust verifier aligned in 2.0.0.
4. ~~Who builds the TSA verifier?~~ **In `sasana/rfc3161.py` with `cryptography`** (no `openssl` dependency); nonce, accuracy, policy allow-list included.
7. ~~Fail-closed?~~ **`commit()` fail-closed; session-start anchoring left fail-open** (unchanged).
8. ~~Session-open in v1?~~ **Deferred.**

Still open — need your decision:

5. **Default TSA trust anchor.** `commit()`/`verify` require the caller to pin one. Should the package ship FreeTSA's root (I verified live that it works), or stay anchor-free?
6. **Multiple TSAs (n-of-m).** Currently first-success failover, one token per commitment.
9. **Counterparty registry protocol.** Now a *proposed* signed acceptance receipt (§5.3, Appendix A.3) that the verifier consumes. No counterparty issues it, and the completeness of the receipt list and the publication and rotation of its key are not enforced (§10 rows 12–13). Should Archeion (or a sibling service) issue them for counterparties that have none?
10. **Archeion's role** relative to commitment (seal before commit vs mid-session). Today a revealed session must be complete, but need not be sealed.
11. **`capture_mode` is self-declared**; only produces a warning for `in_process`.
12. **Per-event signing is off in every shipped integration**; should commitments require `SIGNED_NON_AUTHORITATIVE_EVIDENCE` or better?
13. **Selective disclosure / Merkle tree** — still all-or-nothing trace reveal.
14. **Non-reveal verdict** — still informational (registry gives `UNREVEALED_COMMITMENT`); no reveal-deadline input.
15. ~~**Namespacing/versioning** of `sasana/commit/v1`, `bundle_version`.~~ Done for v2 (`sasana/commit/v2`, `bundle_version` `"2"`); the payload mapping id is a separate version axis, inside `C`.
16. **HA specifics** (appendix only): ~~identifiers, deadline semantics~~ answered by HA's description of its public interface (Appendix A.1). Still HA's to decide: the deadline value, accepted TSAs, and whether to add a `commitment` field or issue receipts, which needs a separate agreement.
17. **New:** revocation checking (CRL/OCSP) for TSA certificates is not implemented (NOT ENFORCED, §10 row 7).
18. ~~**New:** Rust verifier number formatting vs the now-conformant Python `jcs.py`.~~ Resolved in 2.0.0 (shared vectors, ~88,000 doubles identical).
19. ~~**New:** the JCS change alters hashes of any stored event with an exotic float.~~ Resolved in 2.0.0 by versioned canonicalization and golden legacy fixtures.
20. **New:** `ha-daily-v1` does not bind `prompt_hash`, `amount`, `token_usage` or `trigger_event_id`. Should any of them be bound (for example `amount` and `trigger_event_id`)? Default: no; it changes what a hash match proves.
21. **New:** receipt-list completeness. Add a terminal "closed at the deadline, last accepted = k" receipt so a verifier can detect withheld receipts?
22. **New:** how a counterparty publishes, scopes and rotates its receipt key (key id, validity period).
23. **New:** session-open commitments with the counterparty as first checkpoint witness (§5.2, §11), now that the witness design publishes heads during the session.
