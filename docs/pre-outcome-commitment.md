# Pre-Outcome Commitment — Design Proposal

**Status:** IMPLEMENTED on branch `design/ha-reveal-bundle` (not merged, not pushed). Sections 1–2 describe the code *as it was before* this work; see **Implementation status** and the reconciliation block below for what changed. **Commitment v2 (§3.5) supersedes v1, payload mapping `ha-daily-v2` supersedes `ha-daily-v1`, and `ha-daily-v3` (Appendix A.2) supersedes `ha-daily-v2`. `verify_commitment` takes the expected agent id and challenge id as required inputs (§7.1, §10 row 22).**
**Scope:** a generic primitive. Platform-specific mappings live only in Appendix A and in `examples/ha-reveal/` (synthetic bundles). A statement about a named platform is either cited to that platform's public interface (as that platform described it to us) or marked **PROPOSED EXTENSION — not an HA interface**. Nothing here is an interface, commitment or endorsement of any platform.

### Implementation status

Decisions taken: commitment formula first **as originally specified** (v1: no `prev_commitment` inside `C`), then **amendment A1 adopted as v2** (§3.5: `prev_commitment` and the payload mapping id inside `C`; v1 stays verifiable but is superseded); sidecar bundle (no new event type); strings/ints-only payload profile; `commit()` fail-closed; session-open commitment **deferred**.

| Area | Change | Where |
|---|---|---|
| JCS floats | Now RFC 8785-conformant (ECMAScript number formatting); ints beyond ±2^53 round through a double. All 24 RFC 8785 Appendix B vectors pass. **Behaviour change, since handled:** this alone would have re-hashed events in logs written by 1.0.0/1.1.0 (whole-number floats such as `100.0`, exponent floats). It was resolved in 2.0.0 by *versioned canonicalization* (see "Reconciled with Sasana 2.x" below), not by accepting both encodings. | `sasana/jcs.py`, `tests/test_jcs.py` |
| RFC 3161 | New `verify_timestamp_strict()`: CMS signature (RSA PKCS#1 v1.5 / ECDSA / Ed25519), chain to caller-pinned anchors, timeStamping EKU, validity at genTime, SHA-256 imprint, nonce, optional policy allow-list, sub-second genTime, accuracy. Request builder accepts a nonce; `request_timestamp` accepts `url`/`nonce`. The old imprint-only `verify_timestamp` is unchanged (existing verifier behaviour and tests intact). **Not done:** revocation (CRL/OCSP), RSA-PSS. | `sasana/rfc3161.py`, `tests/test_rfc3161_strict.py`, `tests/tsa_fixture.py` |
| Verifier | New public `verify_chain_integrity()` (structural + sequence + hash chain only) so `commit()` can work on open sessions. No existing function changed. | `sasana/verifier.py` |
| Commitment | `commit()`, `reveal_bundle()`, `verify_commitment()`, `compute_commitment()`, payload profile, disclosures. | `sasana/commitment.py`, `tests/test_commitment.py` |
| CLI | `sasana verify-commitment` (exit 0 valid, 1 invalid, 2 late, 3 input error or unknown flag, 4 unrevealed, 5 valid **only under a lenient option**, 6 incomplete receipts). Policy flags: `--receipts`, `--closing-receipt`, `--receipt-key`, `--mapping`, `--clock-skew`, `--require-receipts`, `--allow-unrevealed-history`. Unknown or abbreviated flags are refused, in every subcommand (released as 2.0.2; before that they were silently ignored). | `sasana_cli.py` |
| Payload mapping | `ha-daily-v3` (current, **default-deny**: binds all seventeen properties of the legacy daily route, `null` / omitted / present kept distinct, numbers as JSON numbers under RFC 8785 with no rounding and no fractional cap, `probabilities` an object with exactly `bearish` / `neutral` / `bullish`, an explicit `revision_number` ↔ `revision_index` relation), `ha-daily-v2` (**superseded** by v3: eleven fields, twelve-digit cap) and `ha-daily-v1` (**superseded**: bound seven, accepted two shapes). Both superseded mappings still verify, with a warning. An explicit, versioned map from a submission to the canonical payload; its id is bound inside `C`. | `sasana/commitment_mapping.py`, `tests/test_commitment_mapping.py`, `tests/test_commitment_v3.py`, `tests/fixtures/mapping/ha-daily-v{1,2,3}.json` |
| Trusted identity | `verify_commitment(…, expected_agent_id=, expected_challenge_id=)` are REQUIRED keyword inputs from the verifier's own record, never the bundle's; a mismatch is `INVALID` with a distinct reason each (`AGENT_ID_MISMATCH`, `CHALLENGE_ID_MISMATCH`). CLI: `--agent-id`, `--challenge-id` (required). | `sasana/commitment.py`, `sasana_cli.py`, `tests/test_commitment_v3.py::TestTrustedIdentity` |
| C_v2, receipts, policy | `compute_commitment_v2`; `sign_receipt` / `verify_receipt` (a **PROPOSED EXTENSION**, §5.3; no `payload_hash`, an explicit `ha_revision_number`, a `SYNTHETIC — not HA-issued` notice); the scored-revision rule; verdicts `UNREVEALED` and `INCOMPLETE_RECEIPTS`; the closing receipt; `HISTORY_GAP` and the lenient flag; the time and trust policy of §10. | `sasana/commitment.py`, `tests/test_commitment_v2.py` |
| Examples | 24 synthetic scenarios (23 bundles, all labelled `SYNTHETIC — not HA-issued`) and a runner that prints `bundle \| expected \| actual \| match`. | `examples/ha-reveal/`, `tests/test_ha_reveal_examples.py` |

Validation: 247 tests pass on Python 3.11 (160 pre-existing + 87 new), 229 pass + 18 pre-existing skips on 3.10 (cryptography 41); `ruff check` and `ruff format --check` clean. Nine deliberate mutations of `commitment.py` were each caught by a test. The strict verifier was also checked against a **live FreeTSA token** (nonce echoed, chain to FreeTSA's published root), and a full `commit()` → `reveal_bundle()` → `sasana verify-commitment` run against FreeTSA gave `VALID_ON_TIME`, and `LATE` for an earlier deadline. FreeTSA omits `accuracy` and issues whole-second `genTime`; the verifier assumes 1 s by default (`default_accuracy_s`) and warns.

Branch `design/ha-reveal-bundle` (C_v2, default-deny mapping, receipts and closing receipt, policy, examples): **613 Python tests pass on 3.10 and 3.11** (379 on `main` at 2.0.2, +234 on this branch; 3.12 was not re-run for the HA-4 changes because a 3.12 environment could not be built on the machine that did them), 26 Rust tests, `ruff check` and `ruff format --check` clean (ruff 0.15.x; the CI pin is `<0.16`). Thirty-five deliberate mutations of the security-relevant lines (mapping id or `prev_commitment` dropped from `C`, `amount` or `trigger_event_id` unbound, arrays accepted for `probabilities`, the closing receipt's count/last comparison, scope, deadline, mapping or signature check removed, a missing closing receipt treated as fine, a lenient pass not marked or not given its own exit code, `<` weakened to `<=`, clock skew or assumed accuracy ignored, empty anchors allowed, the canonical-form check skipped, strict flag parsing reverted, and others) were each caught by a test; two of the first run's results were errors in the mutation harness itself and one exposed a weak test (duplicate `lenient` entries), which was strengthened. Twenty-four synthetic scenarios in `examples/ha-reveal/` verify as `expected.json` says. **HA-4 changes (trusted identity, receipts without `payload_hash`, `ha-daily-v3`, bundle-level cases):** fifty-five further deliberate mutations of the new lines (the agent or challenge check removed, the two reasons merged or swapped, an unusable expected value accepted, the CLI flags made optional or crossed, `payload_hash` allowed in a receipt again, the revision-number comparison or offset changed, the synthetic notice not recognised, floats allowed under the decimal-string profile, NaN allowed, the number profile ignored by the commitment, integers beyond 2^53 or booleans accepted as numbers, a fractional cap restored, `amount` of 0 accepted, any label set or an array accepted for `probabilities`, `prompt_hash` case-folded, a declared field dropped, `forecast_context` unbound, `token_usage` restricted to integers again, a schema default applied, null collapsed into omitted, the nesting guard removed, each warning inverted, duplicate revisions accepted, the `revisions` array no longer sorted) were each caught by a test (55 of 55, after the formatter ran, with each source file restored byte for byte). An earlier round found one mutation that survived: a byte comparison in `check_canonical_ha_daily_v3` that could never fail, because the mapping returns its input unchanged. It was **deleted**, not kept (the function now checks the field set and runs the mapping's own rules, and three mutations of those lines are caught). Two results of the first mutation run were errors in the harness (a pattern that did not apply) and one exposed a weak test, which was strengthened. Every `ha-daily-v3` equivalence group's hash was also reproduced by an independent implementation (Node `JSON.stringify`). The Rust verifier (26 tests) is untouched: there is only a Python `verify_commitment`. Not run: anything against a real counterparty or a real TSA, and no HA endpoint other than the public OpenAPI document (once).

**Known gaps in the implementation:** no revocation checking; single-TSA per commitment (`tsa_urls` is tried in order, not n-of-m); *(superseded in 2.0.0: the Rust verifier now implements both canonicalizations and is tested against the same vectors and golden logs as Python; ~88,000 random doubles hash identically)*; `commit()` has no default TSA trust anchor (callers pin it); session-open commitment (§5.2) is not implemented; no real counterparty issues receipts or a closing receipt: both are **PROPOSED EXTENSIONS** (§5.3) implemented only as verifier inputs, and `registry` is an unsigned input list.


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
the verdicts `UNREVEALED` and `INCOMPLETE_RECEIPTS`, adds a signed **closing receipt** so a withheld receipt is detectable,
and makes the time and trust policy explicit and tested (§10). v1 bundles still verify.

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
| T6 | Salt or payload guessing before reveal (low-entropy decisions like `up / 0.7`). | **Yes** | 32-byte random salt inside `C`, never in any public record (`PublicCommitment` has no salt, payload or `session_root` field; the TSA sees only `C`). **`payload_hash` alone must never be published, and no receipt carries one**: a receipt that is public before the reveal would hand anyone an unsalted hash of a low-entropy payload to test guesses against, so `payload_hash` is no longer a receipt field and a receipt that carries it is refused (HA-4 agrees: "dropping the unsalted payload_hash from any pre-reveal public receipt avoids the low-entropy guessing issue"). Residual: a caller may pass its own `salt` to `commit()`, which is length-checked (32 bytes) but not entropy-checked. |
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
  * *With signed receipts and the counterparty's closing receipt* (§5.3): the revision the closing receipt names as last accepted, which must agree with the receipt with the highest `revision_index` among those with `accepted == true` and `accepted_at < deadline`. **Receipts without a closing receipt give `INCOMPLETE_RECEIPTS`, not a verdict.** It is scored only if its own commitment also passes the time rule; if not, the verdict is `LATE`, with **no fall-back** to an earlier revision the counterparty did not score. If its secrets are not in the bundle the verdict is `UNREVEALED`.
  * *Without receipts*: the highest `revision_index` among those whose `t_hi < deadline` (the v1 rule). In v2 this carries the warning `NO_RECEIPTS`, because that revision **may differ from the one the counterparty accepted** (a rejected revision, or an omitted earlier commitment, is invisible to a bundle alone).
* **Ordering check:** `t_hi` must be non-decreasing in `revision_index`, and receipt `accepted_at` must be non-decreasing in `revision_index`; a violation is an error.
* **Superseded revisions remain verifiable:** the bundle may and, by policy, should include them; each verifies exactly like the effective one.
* **Gaps.** v2: a revealed revision whose predecessor is absent, or present but failing verification, is `HISTORY_GAP`, an error unless `allow_unrevealed_history` (a broken reveal hides a revision as surely as omitting it). When that option is what let the bundle pass, the verdict says so: `lenient: ["unrevealed history allowed"]` in the verdict and `--json`, a `(LENIENT: …)` banner in text mode, and **exit code 5** instead of 0, so a lenient pass is never mistaken for a strict one. v1: `UNREVEALED_REVISION` warning.

### 5.2 Optional session-open commitment — DEFERRED (not implemented)

Goal: let a counterparty **count sessions per context** (T4).

At `SESSION_START` the committer publishes `open_binding = SHA-256(enc("sasana/open/v1") || enc(subject_id) || enc(context_id) || enc(session_id) || enc(salt_open))` to the counterparty and stores `context_binding = open_binding` in the `SESSION_START` payload (a new optional key; the existing hash chain and the existing RFC 3161 token over the pre-token `SESSION_START` hash then also cover it for free). The counterparty's registry then holds one entry per opened session per `(subject, context)`.

At reveal, the committer discloses `salt_open` and `session_id`; the verifier recomputes `open_binding`, checks it matches the `SESSION_START` payload, and compares the registry's session count for the context with the number of revealed sessions. Differences are reported (`SESSIONS_UNACCOUNTED`).

Registering the session root (or a hash of it) with the counterparty at `SESSION_START` would make the counterparty the first checkpoint witness of [`design/witness-anchoring.md`](design/witness-anchoring.md) (heads published *during* the session). **It is still deferred; see §11.**

Caveats stated plainly: this only works with a counterparty-held registry; it cannot detect sessions that were never instrumented; and the existing session-start anchoring is fail-open (`sqlite_ledger.py::_try_anchor_rfc3161`) so session-open mode needs its own fail-closed path.

### 5.3 Counterparty acceptance receipts and the closing receipt — PROPOSED EXTENSIONS (verifier inputs only)

Which revision a counterparty *accepted before its cutoff* cannot be read off a bundle: the highest on-time revision in a bundle may differ from the last accepted submission, a rejected revision still carries a valid timestamp, and an omitted earlier commitment leaves no trace. What closes this is a record **made by the counterparty at acceptance time**, and a second record **made at the deadline** that says the first set is complete. The verifier accepts both as signed messages.

> **PROPOSED EXTENSION — not an HA interface** (and not an interface of any other platform). No counterparty we know of issues either. Both are implemented here only as something `verify_commitment` can consume, and are exercised with synthetic keys.

**(a) Per-submission acceptance receipt**, one for every submission attempt:

```jsonc
{ "body": { "challenge_id": "…",        // = context_id
            "agent_id": "…",            // = subject_id
            "revision_index": 1,
            "commitment": "<hex C>",
            "accepted_at": "2026-10-14T09:30:02Z",   // the COUNTERPARTY's clock, tz-aware
            "accepted": true,           // false = the submission carrying this C was rejected
            "reason": null,             // free text, signed but never interpreted
            // optional:
            "mapping_id": "ha-daily-v3",
            "ha_revision_number": 2,    // the COUNTERPARTY's own number, starting at 1 (= revision_index + 1)
            "notice": "SYNTHETIC — not HA-issued" },   // set on every receipt this repository generates
  "signature": "<hex Ed25519 signature over the bytes  'sasana/receipt/v1' + LF  followed by  JCS(body)>" }
```

**(b) Closing receipt**, one per `(agent_id, challenge_id)`, signed at the deadline:

```jsonc
{ "body": { "challenge_id": "…", "agent_id": "…",
            "accepted_count": 2,                       // submissions accepted before the deadline
            "last_accepted_revision_index": 1,         // null when accepted_count is 0
            "last_accepted_C": "<hex C>",              // null when accepted_count is 0
            "closed_at": "2026-10-14T12:00:30Z",       // counterparty clock; must not precede the deadline
            "mapping_id": "ha-daily-v3",
            "notice": "SYNTHETIC — not HA-issued" },   // optional
  "signature": "<hex Ed25519 signature over  'sasana/closing-receipt/v1' + LF  followed by  JCS(body)>" }
```

Without (b) a verifier cannot tell a complete list of (a) from one with a receipt withheld: a committer who supplies the list could simply leave out a later accepted receipt. With (b), any list that disagrees with the counterparty's own count and last commitment is rejected. The two use different domain tags, so neither can be replayed as the other.

Rules (all in code, `sasana/commitment.py::verify_receipt`, `verify_closing_receipt`, `_process_receipts`, `_apply_closing`; tested in `tests/test_commitment_v2.py`):

* Both are checked against **one pinned key** the verifier supplies (`trusted_receipt_pubkey`, base64 raw Ed25519). Either kind supplied without a pinned key makes the verdict `INVALID`. A key travelling inside a receipt is never read.
* **A receipt list with no closing receipt is `INCOMPLETE_RECEIPTS`** (CLI exit 6): not valid, and deliberately not `INVALID` either (nothing is wrong, something is missing). Other errors still take precedence.
* **The list must agree with the closing receipt:** the number of `accepted` receipts before the deadline must equal `accepted_count`, and the one with the highest `revision_index` must be `(last_accepted_revision_index, last_accepted_C)`, or the verdict is `INVALID` (`RECEIPT_LIST_DISAGREES_WITH_CLOSING`; this is how a withheld or an added receipt is caught). A closing receipt for another agent or challenge, signed before the deadline, or naming a different mapping is `INVALID`.
* The closing receipt alone is enough to name the scored revision (warning `NO_PER_SUBMISSION_RECEIPTS`: `accepted_count` could not then be cross-checked).
* Receipts for another `agent_id` / `challenge_id` are ignored (counted). A bad signature, two accepted commitments for one `revision_index` (`EQUIVOCATION`), or contradictory receipts for one commitment make the verdict `INVALID`.
* **There is no `payload_hash` in a receipt** (threat T6, row 23 of §10): an unsalted hash of a low-entropy payload published before the reveal lets anyone test guesses. A receipt that carries one is refused (`RECEIPT_INVALID`), and the reference signer will not build one. If a hash of the payload is ever attested, it must be salted, and it would be a different message.
* If a receipt carries `mapping_id` it must match the bundle (`RECEIPT_MAPPING_MISMATCH`).
* **A counterparty's revision number is related to `revision_index` only through the mapping's declared numbering, never by assumption.** Under `ha-daily-v3` the counterparty's `revision_number` starts at 1 and `revision_index` at 0 (HA-4), so `revision_number = revision_index + 1`. A receipt's `ha_revision_number`, if present, must equal that (`RECEIPT_REVISION_NUMBER_MISMATCH`); if absent the verifier warns (`RECEIPT_REVISION_NUMBER_ABSENT:i`); under a mapping that states no relation a present number is an error (`RECEIPT_REVISION_NUMBER_UNDEFINED`).
* **Synthetic receipts say so.** A receipt or closing receipt whose `notice` begins with `SYNTHETIC` makes the verdict carry `SYNTHETIC_RECEIPTS_USED`. No counterparty issues either kind (HA-4: no approval or delivery commitment, no signing keys, no key rotation, no deployment), and a successful HTTP response is not a signature or an independent timestamp.
* `TSA_TIME_AFTER_ACCEPTANCE` (warning): a commitment cannot be submitted before it exists, so the TSA's time for `C` must not be later than `accepted_at` beyond accuracy and the assumed skew.

What they do **not** establish: that the counterparty's signing key is genuine (that is the pin), that its clock is honest, or that it counted honestly: a counterparty that signs a false `accepted_count` is believed. They move the question from "was I handed everything?" to "do I trust this counterparty's key?", which is a smaller and more explicit assumption.

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

Inputs: `bundle`, **`expected_agent_id`, `expected_challenge_id`** (required; the verifier's own record), `deadline`, `trusted_tsa_anchors`, optional `trusted_seal_pubkey`, optional `registry` (list of `C` and open-bindings the counterparty received), `policy` flags.

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

* **Preconditions fail closed (`INVALID`):** an `expected_agent_id` or `expected_challenge_id` that is not a non-empty string; no pinned TSA anchors; negative, non-finite or non-numeric `clock_skew_s`; receipts or a closing receipt without a pinned receipt key; `require_receipts` with neither; a naive (timezone-less) deadline.
* **Identity (right after parsing, before anything else):** the bundle's `subject_id` must equal `expected_agent_id` and its `context_id` must equal `expected_challenge_id`, as exact strings (no case folding, trimming or Unicode normalisation). Each mismatch is its own error, `AGENT_ID_MISMATCH` and `CHALLENGE_ID_MISMATCH`, and both are reported when both differ. An honest, fully valid bundle committed under another agent or challenge is therefore `INVALID` for this verifier (examples `m`, `n`). Rewriting the bundle's ids to match breaks `C`, because both ids are inside it.
* **Step 1** accepts `(bundle_version, domain_tag)` of `("1", "sasana/commit/v1")` or `("2", "sasana/commit/v2")`. For v2 the `mapping_id` must be a registered mapping, and equal to `expected_mapping_id` if the verifier requires one. A v1 bundle cannot satisfy a required mapping.
* **Step 3.1** applies the payload profile of the bundle's mapping: integers within ±2^53 and strings, booleans, null, arrays, objects for every mapping, plus finite floats under `ha-daily-v3` (`ieee754-rfc8785`; v1 and v2 refuse floats).
* **Step 3.2** for v2 recomputes `C_v2` and then requires the payload to be in its mapping's canonical form.
* **Revision order and duplicates:** revisions are ordered by `revision_index`, so the order of the `revisions` array in a bundle is ignored (examples `r`; a test checks every permutation); two entries with one `revision_index` make the bundle `INVALID` (`q`). A revision whose `revision_index` was edited no longer matches its `C` (`o`).
* **Step 4** for v2: a missing or unverified predecessor is `HISTORY_GAP` (error, or warning with `allow_unrevealed_history`).
* **Step 5** with receipts: the scored revision comes from the closing receipt, cross-checked against the receipt list (§5.1, §5.3), not from the bundle.
* **Verdicts:** `VALID_ON_TIME`, `LATE`, `INVALID`, **`UNREVEALED`** (the counterparty accepted a revision whose secrets the bundle does not reveal: neither a pass nor a failure, but the absence of evidence; exit 4) and **`INCOMPLETE_RECEIPTS`** (a receipt list was supplied without the counterparty's closing receipt, so completeness cannot be judged; exit 6). Without receipts a bundle with no revisions is still `INVALID`, because nothing is known.
* **Lenient passes are marked.** `CommitmentVerdict.lenient` is non-empty only when a lenient option (`allow_unrevealed_history`) changed the outcome; the CLI then prints `(LENIENT: …)` and exits **5**, not 0. Setting the option when it was not needed does not mark a pass lenient (the setting is still echoed in `checks["policy"]`).
* **Warnings added:** `MAPPING_SUPERSEDED:old->new`, `CLOSING_RECEIPT_MISSING`, `NO_PER_SUBMISSION_RECEIPTS`, `NO_RECEIPTS`, `NOT_ACCEPTED_BY_COUNTERPARTY:i`, `UNREVEALED_COMMITMENT:i`, `RECEIPT_AFTER_DEADLINE:i`, `NO_ACCEPTED_RECEIPT_BEFORE_DEADLINE`, `SCORED_REVISION_NOT_ON_TIME:i`, `TSA_TIME_AFTER_ACCEPTANCE:i`, `SYNTHETIC_RECEIPTS_USED`, `RECEIPT_REVISION_NUMBER_ABSENT:i`, and the mapping's payload warnings (v1/v2: `PROBABILITY_SUM:x`, `PROBABILITY_NEGATIVE`; v3 adds `DIRECTION_ARGMAX_MISMATCH:d`, `CONFIDENCE_MAX_MISMATCH:c`, `MODEL_PROVIDER_NAME_NOT_PAIRED`). Errors added: `AGENT_ID_MISMATCH`, `CHALLENGE_ID_MISMATCH`, `RECEIPT_REVISION_NUMBER_MISMATCH`, `RECEIPT_REVISION_NUMBER_UNDEFINED`.
* `checks["policy"]` in the verdict records the policy actually applied (the expected agent and challenge, anchors pinned, time rule, assumed accuracy and skew, revocation not checked, seal key pinned, receipt key pinned).

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

def verify_commitment(bundle: Mapping[str, Any], *,
                      expected_agent_id: str, expected_challenge_id: str,   # REQUIRED; from YOUR record, not the bundle
                      deadline: datetime, trusted_tsa_anchors: Sequence[bytes], trusted_seal_pubkey: Optional[str] = None,
                      registry: Optional[Sequence[Mapping[str, Any]]] = None,
                      allow_partial: bool = False, default_accuracy_s: float = 1.0,
                      allowed_policies: Optional[Sequence[str]] = None,
                      receipts: Optional[Sequence[Mapping[str, Any]]] = None,   # PROPOSED EXTENSION input
                      closing_receipt: Optional[Mapping[str, Any]] = None,      # PROPOSED EXTENSION input
                      trusted_receipt_pubkey: Optional[str] = None,
                      expected_mapping_id: Optional[str] = None,
                      require_receipts: bool = False, allow_unrevealed_history: bool = False,
                      clock_skew_s: float = 0.0) -> CommitmentVerdict: ...  # never raises
```

Also public: `compute_commitment` / `encode_commitment_input` (v1), `compute_commitment_v2` / `encode_commitment_input_v2`, `payload_hash`, `validate_payload_profile`, `disclosure_hash`, `sign_receipt`, `verify_receipt`, `sign_closing_receipt`, `verify_closing_receipt`; dataclasses `PublicCommitment` (now with `mapping_id`), `CommitmentSecrets` (both with `to_dict`/`from_dict`), `CommitmentVerdict` (verdict now also `UNREVEALED` and `INCOMPLETE_RECEIPTS`, and a `lenient` field); and, in `sasana/commitment_mapping.py`, `map_ha_daily_v3` (and the superseded `map_ha_daily_v2`, `map_ha_daily_v1`), `canonical_decimal`, `check_canonical_ha_daily_v3` / `_v2`, `payload_warnings_v3`, `probability_warnings`, `cross_check_published`, `RevisionNumbering`, `HA_REVISION_NUMBERING`, `number_profile_for`, `MAPPINGS`, `DECLARED_FIELDS_V3` / `_V2`, `EXCLUDED_FIELDS_V3` / `_V2`; in `sasana/commitment.py` also `SYNTHETIC_NOTICE` and `PAYLOAD_HASH_REFUSED`. Differences from the first sketch: `commit()` takes `trusted_tsa_anchors` (it self-verifies the token before returning) and `allowed_policies`; `reveal_bundle` has no `session_open`; the verdict also carries `effective_payload` and `errors`.

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
| 6 | **Clock-skew assumptions** | Three clocks exist. The **TSA's** is trusted within its stated accuracy. The **counterparty's** defines the deadline, `accepted_at` and `closed_at` (compared with each other directly). The **committer's** is never used (event timestamps are writer-asserted). Disagreement between the TSA's and the counterparty's clock is *not measured*: the default assumption is none, `clock_skew_s` lets the verifier assume some, and an impossible ordering (TSA time for `C` later than the counterparty's `accepted_at`) is flagged `TSA_TIME_AFTER_ACCEPTANCE`. | Enforced as described. `test_clock_skew_allowance_is_part_of_the_time_rule`, `test_bad_skew_values_fail_closed`, `TestScenarios::test_e2_…`. **NOT ENFORCED:** any bound on TSA-versus-counterparty drift beyond that warning |
| 7 | **Revocation is not checked** | CRL/OCSP are not consulted and no revocation date is compared with `genTime`. The verdict records `revocation_checked: false`. | **NOT ENFORCED.** Limitation tests: `test_revocation_is_not_checked_NOT_ENFORCED`, `test_what_missing_revocation_costs_a_stolen_tsa_key_can_backdate_NOT_ENFORCED` |
| 8 | **One TSA per commitment** | `tsa_urls` are tried in order; one token is kept. | **NOT ENFORCED:** no n-of-m |
| 9 | **The seal is optional and is verified only against a pinned key** | `trusted_seal_pubkey` (`--trust-key`) pins it. With a pin a seal is required and must verify (`INVALID` otherwise); without one a seal that verifies only against its own key is `SELF_SEALED_EVIDENCE`. The evidence class is reported and **never changes the verdict or the time**. | Enforced. `TestSealIsOptionalAndNotRelied`; `test_commitment_sasana2.py::TestSealPolicyForCommitments`; examples `b` with and without `--trust-key` |
| 10 | **The seal is not relied on against the operator (A8)** | A rewritten session resealed by the genuine key verifies `AUTHORITATIVE_EVIDENCE` under the pin; the commitment is what fails (`session_root` no longer in the session). | Enforced by the commitment, not the seal. `test_commitment_sasana2.py::TestA8AgainstACommitment`; `TestScenarios::test_i_…`; `examples/ha-reveal/bundles/i-…` |
| 11 | **The receipt key is pinned (both receipt kinds)** | `trusted_receipt_pubkey` (`--receipt-key`, base64 raw Ed25519) is the only key trusted. Receipts or a closing receipt without a pin are `INVALID`; a key inside a receipt is ignored; a different key makes the message invalid; each kind signs under its own domain tag, so neither replays as the other. | Enforced. `TestReceiptSignatures`, `TestReceiptPolicy::test_receipts_need_a_pinned_key`, `TestClosingReceipt::test_closing_needs_the_pinned_key_too`, `…test_the_two_receipt_kinds_cannot_stand_in_for_each_other` |
| 12 | **How the receipt key is published, rotated or scoped** | There is one key, no key id, no validity period; a rotation is a new out-of-band pin. How a counterparty would publish the key is unspecified. | **NOT ENFORCED / NOT SPECIFIED** |
| 13 | **A receipt list needs the closing receipt** | Receipts supplied without the counterparty's closing receipt give `INCOMPLETE_RECEIPTS` (exit 6): not valid, because completeness cannot be judged. Other errors still win over it. | Enforced. Scenario `k`; `TestClosingReceipt::test_k_closing_receipt_missing_is_incomplete_not_valid`, `…test_k2_…`, `…test_k3_…` |
| 14 | **The receipt list must agree with the closing receipt** | The count of `accepted` receipts before the deadline must equal `accepted_count`, and the highest-index one must be `(last_accepted_revision_index, last_accepted_C)`; otherwise `INVALID` (`RECEIPT_LIST_DISAGREES_WITH_CLOSING`). This is what catches a committer who withholds a later accepted receipt, or adds one. | Enforced. Scenario `j`; `TestClosingReceipt::test_j_…`, `…test_j2_…`, `…test_j3_…` |
| 15 | **The closing receipt is authentic and in scope** | A wrong key (scenario `l`), a tampered body, another agent or challenge, a `closed_at` before the deadline, or a different mapping id is `INVALID`; `closed_at` equal to the deadline is accepted. | Enforced. `TestClosingReceipt::test_l_…`, `…test_closing_body_tampering_invalidates_the_signature`, `…test_closing_must_not_predate_the_deadline`, `…test_closing_for_another_agent_or_challenge_is_an_error_not_ignored`, `…test_closing_must_name_the_bundles_mapping` |
| 16 | **The counterparty's count is believed** | A counterparty that signs a false `accepted_count` or `last_accepted_C` is believed; the pin only says who signed. Without any receipts the verifier warns `NO_RECEIPTS` and falls back to the highest on-time revision in the bundle. | **NOT ENFORCED** (a trust assumption). `TestScenarios::test_c_…` shows the fallback differs from the accepted revision |
| 17 | **The payload mapping is pinned** | `expected_mapping_id` (`--mapping`) is required to equal the bundle's. A verifier that does not pass one accepts the bundle's own registered mapping. | Enforced when supplied. `test_g3_a_required_mapping_is_enforced`, `test_a_c_v1_bundle_still_verifies_but_cannot_satisfy_a_required_mapping` |
| 18 | **The mapping is default-deny** | `ha-daily-v3` binds every property the legacy daily route declares (seventeen) and rejects an undeclared one; a field can be excluded only by an entry with a written reason (there are none); omitted, `null` and present are three states; `probabilities` has exactly three labels; numbers are lossless (RFC 8785, no cap); the commitment does not validate the forecast (sum, sign and direction/confidence only warn). | Enforced. `test_commitment_v3.py::TestHaDailyV3PinnedToTheSchema`, `TestHaDailyV3Mapping`, `TestHaDailyV3Numbers`, `TestHaDailyV3SharedVectors`; v2: `test_commitment_mapping.py::TestHaDailyV2DefaultDeny` |
| 19 | **A superseded mapping is flagged** | A bundle under `ha-daily-v1` or `ha-daily-v2` still verifies, with `MAPPING_SUPERSEDED:ha-daily-v1->ha-daily-v2` or `MAPPING_SUPERSEDED:ha-daily-v2->ha-daily-v3`; a verifier that requires `ha-daily-v3` refuses both. | Enforced. `TestLenientAndSuperseded::test_a_superseded_mapping_still_verifies_with_a_warning`; `test_commitment_v3.py::TestV3EndToEnd::test_a_v2_bundle_is_not_the_required_v3_mapping` |
| 20 | **A broken or missing earlier revision is not silently accepted, and leniency is visible** | `HISTORY_GAP` is an error unless `allow_unrevealed_history`; when that option let the bundle pass, the verdict carries `lenient`, the text output a `LENIENT` banner, and the exit code is **5**, not 0. | Enforced. `test_d_bundle_omits_the_initial_commitment`, `test_f2_…`, `TestLenientAndSuperseded`, `TestCli::test_exit_codes_including_unrevealed`, `…test_the_lenient_banner_is_printed_in_text_mode` |
| 21 | **A mistyped policy flag is not ignored** | Unknown or abbreviated flags exit 3 in **every** subcommand (before 2.0.2, `evidence-pack`, `verify-commitment` and `seal` silently dropped them, so a mistyped `--trust-key` removed the pin). | Enforced (on `main`, 2.0.2). `tests/test_cli_strict_flags.py`; `TestCli::test_unknown_or_abbreviated_flags_are_refused_not_ignored` |
| 22 | **The bundle's agent and challenge come from the verifier, not the bundle** | `expected_agent_id` and `expected_challenge_id` (CLI `--agent-id`, `--challenge-id`) are required, with no default, and are compared as exact strings before any other check. A mismatch is `INVALID` with `AGENT_ID_MISMATCH` and `CHALLENGE_ID_MISMATCH`, each its own reason (HA-4: keep the wrong-agent and wrong-challenge cases separate). A bundle committed honestly under another identity is refused; relabelling it breaks `C`. Where the verifier's record comes from is the verifier's job. | Enforced. `test_commitment_v3.py::TestTrustedIdentity`; examples `m`, `n`; `test_ha_reveal_examples.py::…test_the_identity_bundles_are_honest_for_the_identity_they_were_committed_under`; `test_cli_strict_flags.py` |
| 23 | **No receipt carries a payload hash** | `payload_hash` is not a receipt field; a receipt that carries it is refused, and the reference signer will not build one (threat T6: it is unsalted and the payload is low-entropy). | Enforced. `TestReceiptPolicy::test_a_receipt_may_not_carry_payload_hash_threat_t6`; `test_commitment_v3.py::TestReceiptRules::test_payload_hash_is_no_longer_a_receipt_field`; `test_ha_reveal_examples.py::…test_no_receipt_carries_a_payload_hash_threat_t6`. **Cost:** a receipt can no longer vouch for the exact payload the counterparty accepted; see A.3 |
| 24 | **A counterparty's revision number is related to `revision_index` explicitly** | `PayloadMapping.revision_numbering` states `revision_number = revision_index + 1` for `ha-daily-v3` (HA-4: `revision_number` starts at 1, the commitment's index at 0); a receipt's `ha_revision_number` must agree, is flagged when absent, and is an error under a mapping that states no relation. | Enforced. `TestReceiptRules::test_a_wrong_revision_number_is_an_error_the_off_by_one_is_not_assumed_away` and the three tests after it; example `t`. **NOT ENFORCED:** `expected_revision` in a submission is bound as sent and is not related to anything (its meaning is not stated, A.6) |
| 25 | **Synthetic receipts and fixtures are labelled** | Every receipt, closing receipt, bundle, trust file and vector file this repository generates carries `SYNTHETIC — not HA-issued`; a verdict that used a receipt or closing receipt whose `notice` starts with `SYNTHETIC` carries `SYNTHETIC_RECEIPTS_USED`. This is honesty labelling, not a security control: a receipt without the notice is not recognised as synthetic. | Enforced as described. `TestReceiptRules::test_a_synthetic_receipt_makes_every_verdict_say_so`, `…test_the_label_on_the_closing_receipt_alone_is_enough`; `test_ha_reveal_examples.py::…test_every_synthetic_file_says_so` |
| 26 | **The revision list is bound by index and order-insensitive** | A revision whose `revision_index` was edited fails its `C` (the index is inside it); two entries with one index are `INVALID`; the order of the `revisions` array is ignored (ordered by `revision_index`); a corrupted `CHAIN_SEAL` signature is `COMPROMISED` (the signature is outside the event hash, so only the seal check sees it). | Enforced. `TestBundleLevelCases`, `TestCorruptedSeal`; examples `o`, `p`, `q`, `r` |

**What the missing revocation check costs an attacker nothing.** Someone who holds a TSA signing key can mint a token with any `genTime`, and a token signed by a key that was compromised and later revoked verifies exactly like a genuine one, because we neither consult revocation nor compare a revocation time with `genTime`. The attacker's gain is a *backdated* commitment: one made after the deadline that appears to predate it. Two things bound the damage. With receipts (§5.3) the scored revision is whatever the counterparty accepted before its cutoff, so a backdated token does not change *which* revision is scored; it only weakens the independence of the "existed before the deadline" claim from the counterparty's own clock. And the attacker needs the TSA's key, not the committer's, which is why n-of-m TSAs (row 8) would be the real fix.

---

## 11. What is still open (stated plainly)

* **Session-open commitments are still deferred (§5.2).** Registering the session root, or a hash of it, with the counterparty at `SESSION_START` would make the counterparty the first checkpoint witness of [`design/witness-anchoring.md`](design/witness-anchoring.md). Until then nothing external has seen the chain before the first commitment: an operator can rewrite events recorded *before* the first `C` and no one can tell, and sessions that were never committed are invisible (T4).
* **A matching trace does not prove completeness, truthfulness, or the absence of human influence outside the instrumentation (§8, T3).** It shows those bytes existed by `genTime` and were not altered since; nothing more.
* **No counterparty issues receipts or a closing receipt.** Both (§5.3) are proposals, and every statement here about which revision was accepted holds only if a counterparty produced them. With them, a withheld receipt is detected; what remains is trust in the counterparty's key, clock and count (§10 rows 12 and 16). Without them the verifier can only fall back to the highest on-time revision in the bundle, and says so.
* **The mapping binds everything the legacy route declares, but only for that route.** `ha-daily-v3` binds all seventeen properties of `POST /api/v1/eval/challenges/{challenge_id}/predict` as published in OpenAPI 2.2.9 (A.2), and the types now come from that schema and from HA-4, not from our reading. It is a legacy directional mapping: not a mapping for the canonical `/api/v1/agent/ha/predict` contract, not for numeric price-event predictions, and not a statement that any route is enabled (HA-4: the capabilities response declared the legacy financial REST transport enabled and canonical REST supported but disabled on 2026-10-25). What stays open is HA's (A.6): the meaning of `expected_revision`, the inner schema of `forecast_context`, and the tolerance HA applies to the `direction` / `confidence` cross-check.
* **The commitment does not validate forecasts.** It does not check ranges, that probabilities are non-negative and sum to 1, or that `direction` and `confidence` match their argmax and maximum; each of those only warns. (The label set of `probabilities` IS checked under v3: exactly `bearish`, `neutral`, `bullish`.)
* **Single TSA, no revocation (§10 rows 7–8).**
* **Verification depends on later availability** of the counterparty's receipts and results; a counterparty's current anonymous access is not a retention guarantee.
* **There is only a Python implementation of `verify_commitment`.** The mappings have shared vectors (`tests/fixtures/mapping/`) so another implementation can be held to the same table; none exists.

---

## Appendix A — Headline Arena daily-market mapping (worked example, synthetic data only)

### A.0 Provenance and status

* **HA-1** = Headline Arena's (HA) description to us of its **current public interface**, 2026-10-05, with daily-market forecasts as the main example. The field lists are, per HA, from its public OpenAPI schema. **For the legacy daily route we have since read that schema once (OpenAPI, above);** a row that says "HA declares" is HA-1 (HA told us), and a row marked OpenAPI or HA-4 was checked against the schema or restated by HA after 2026-10-25. Where HA-1 and the later sources differ, the later source wins and the difference is stated. HA may correct any row.
* **HA-2** = HA's follow-up questions, 2026-10-11 (the three mapping questions answered in A.2, A.3 and §10).
* **HA-4** = Kopei's email to us, 2026-10-25 (Source 4 in the working source list), written after reading HA's published schema at `https://headlinearena.com/api/openapi.json` and its transport declarations at `https://headlinearena.com/api/v1/agent/capabilities` on 2026-10-25. HA-4 says the OpenAPI document labels itself 2.2.9, that the plugin-version endpoint advertises 2.5.0, and that **neither label establishes a backend release or an endpoint acceptance test**; it also says that no live acceptance test was run.
* **OpenAPI** = that OpenAPI document, which **we retrieved once, read-only, on 2026-10-27T04:16:44Z** (HTTP 200, 416,227 bytes, `info.version` 2.2.9, SHA-256 `b45661082500e025f93f90db92c6f3e203452dd4707d88f607033283ebe8fb36`). It is cited as "OpenAPI". It is a schema, not evidence of a deployed endpoint or an enabled feature gate (HA-4). The SHA-256, the retrieval record and a verbatim excerpt of the parts cited here (the legacy route's request body, the revision-number and `counts_for_score` response fields, the canonical route's property names) are in [`docs/sources/ha-openapi-2.2.9-2026-10-27.json`](sources/ha-openapi-2.2.9-2026-10-27.json); the full document is not in the repository, and a later retrieval may differ. No other HA endpoint was called, and `capabilities` was not fetched by us (that is HA-4's own statement, cited as such).
* **ours** = Sasana's own proposal. A row marked *ours* is **not** an HA interface.
* **PROPOSED EXTENSION — not an HA interface** marks every HA-side change this note suggests. HA API changes, engineering work, access and any joint publication would need a separate agreement with HA; nothing here is an HA integration, and HA has neither reviewed nor endorsed this note.
* **Family:** the **legacy daily directional route** only. HA's other families (price-event, civic, the unified schema) declare different fields and have different revision semantics (HA-1 §1–2); the canonical `POST /api/v1/agent/ha/predict` request is `challenge_id` plus a nested `prediction` matching the discovered `prediction_schema`, and `prompt_hash` and `token_usage` are not declared canonical request fields (HA-4; OpenAPI lists no such properties). They are not covered, and **none of this mapping's daily fields should be transplanted into the canonical contract or into numeric price-event predictions** (HA-4).
* **Data:** every bundle, identifier and key in `examples/ha-reveal/` is synthetic. **The only HA endpoint ever called is the public OpenAPI document, once, read-only, on 2026-10-27 (above).** No other HA endpoint was called, no HA account or credential was used, and no HA data or real agent id appears anywhere.

### A.1 What HA's public interface declares (as described to us)

| Topic | HA's public interface | Source |
|---|---|---|
| Daily-market submission fields | HA-1 listed eleven: `direction`, `confidence`, `probabilities`, `prompt_hash`, `amount`, `reasoning`, `summary`, `token_usage`, `is_revision`, `trigger_event_id`, `revision_reason`. **The request now declares seventeen**: also `forecast_context`, `expected_revision`, `idempotency_key`, `model_provider`, `model_name`, `model_version`. | HA-1 §1; HA-4 ("the request now also declares …"); OpenAPI (`PredictRequest`, 17 properties) |
| Transport status (2026-10-25) | The legacy financial REST transport is enabled, canonical REST is supported but disabled, MCP is enabled. An endpoint appearing in OpenAPI is not evidence that its feature gate is enabled. | HA-4 |
| Types of the daily fields | `probabilities`: an object with exactly `bearish`, `neutral`, `bullish` (non-negative, sum 1, tolerance 1e-6); if `direction` / `confidence` are supplied beside it they must match the argmax / maximum; the full vector is preferred. `amount`: optional, a number strictly greater than zero, or null; zero is not an unstaked submission. `token_usage`: optional object or null, values **not** restricted to non-negative integers. `trigger_event_id`: optional string or null, described as a market-event UUID, **no UUID format constraint** in the schema. `prompt_hash`: exactly 64 hexadecimal characters, upper case allowed, the prompt-configuration hash and not a carrier for a session root. `expected_revision`: integer ≥ 1 or null, no description. | HA-4; OpenAPI (types, patterns and `exclusiveMinimum` agree) |
| Revision numbering | The response `revision_number` starts at 1; our synthetic commitment index starts at 0, and the relation must be explicit. Own-prediction readback is `GET /api/v1/eval/challenges/{challenge_id}/own-prediction`. | HA-4. OpenAPI types `revision_number` as an integer with default 1 in the submission response (201); the own-prediction response (200) has an **empty schema** there, so that endpoint's fields rest on HA-4 alone |
| Locking | No separate public lock endpoint in the schema. The challenge exposes status and a deadline; the daily response includes `counts_for_score`, and late submissions are paper-trade only when it is false. **That is not a cryptographic locking receipt.** | HA-4; OpenAPI (no path contains "lock"; `counts_for_score` description as stated) |
| Challenge and agent identity | The challenge is identified in the endpoint, the agent through authentication. Neither is a body field. | HA-1 §1; OpenAPI agrees for the legacy route (`challenge_id` is a `uuid` path parameter, the agent is the bearer-authenticated caller, and the request body has neither) |
| Attaching a session root | **No documented generic metadata or session-root attachment field.** `prompt_hash` is the 64-character SHA-256 digest of the prompt configuration and must not be reused for a session root; `token_usage` is not a general-purpose commitment field. A dedicated binding would be proposed interface work. **Since HA-1 the request also declares `forecast_context`** (HA-4 names it; OpenAPI describes it): `schema_version`, `decision`, `observed_at`, `run_ref` ("client-owned run reference; not an authenticated ModelRun") and up to 32 `evidence_refs` (each with an optional `content_sha256`), described as "declarations, never attestation". So the statement above is **HA-1's and may be out of date**: HA has not said that `forecast_context` may carry a commitment or a session root, and we do not put one there. Whether it could is HA's question (A.6). | HA-1 §1 (the "no metadata field" claim); HA-4 and OpenAPI for `prompt_hash` and `token_usage` and for `forecast_context` |
| Reasoning length | 20–8,000 characters for daily and price-event submissions. | HA-1 §1; OpenAPI agrees for the legacy route (`minLength` 20, `maxLength` 8000); price-event submissions: HA-1 only |
| Revisions | Daily revisions use `is_revision: true` before the deadline; a duplicate initial submission is rejected. The methodology preserves pre-deadline revision history, which does not mean every endpoint exports a complete revision/proof chain. Revision semantics differ by family. | HA-1 §2 **only** (not in HA-4; OpenAPI shows `is_revision` and `revision_reason` but not the duplicate-initial rule) |
| What the deadline fixes | It closes eligibility to create or revise the scored forecast. Later daily submissions may be separate paper-trade signals (`counts_for_score: false`). Settlement rules are defined in advance. The cutoff is application-level and **does not establish cryptographic immutability of every submitted field.** | HA-1 §3; HA-4 and OpenAPI for `counts_for_score` and paper-trade-only (and HA-4: "not a cryptographic locking receipt"); "settlement rules are defined in advance" and "application-level cutoff": HA-1 only |
| Post-resolution response (daily example) | `challenge_id, status, result, open_price, close_price, resolution_source, resolved_at, submitted_count, predictions`; each prediction has `agent_id, direction, confidence, reasoning, summary, is_correct, score`. | HA-1 §4 (HA-1 only: not in HA-4, and the resolved-response endpoint was not checked in the OpenAPI excerpt) |
| Not in that response | prediction IDs, `probabilities`, `prompt_hash`, `prediction_hash`, TSA tokens, revision history, submission timestamps. It is a results API, not a cryptographic proof export. | HA-1 §4 (HA-1 only: not in HA-4, and the resolved-response endpoint was not checked in the OpenAPI excerpt) |
| Access | Availability is endpoint-specific; today's anonymous access is not a permanent-access or retention guarantee. | HA-1 §4 (HA-1 only: not in HA-4, and the resolved-response endpoint was not checked in the OpenAPI excerpt) |
| Scope HA considers sensible | Hash-only, with no trace or data exchange at this stage. | HA-1 §4 (HA-1 only: not in HA-4, and the resolved-response endpoint was not checked in the OpenAPI excerpt) |

### A.2 The versioned payload mapping `ha-daily-v3` (HA-2 question 1; revised after HA-4)

A successful hash check must not be able to conceal a change in meaning, so the commitment binds an explicit, **versioned** mapping from the submission to the payload hashed inside `C`. The mapping id is itself inside `C` (§3.5). Implementation: `sasana/commitment_mapping.py::map_ha_daily_v3`.

**Scope: a legacy directional mapping, not a canonical mapping.** `ha-daily-v3` is for `POST /api/v1/eval/challenges/{challenge_id}/predict` only (HA-4 calls it the "published legacy daily directional route"). It is **not** a mapping for the canonical `POST /api/v1/agent/ha/predict` contract, **not** for numeric price-event predictions, and it does not assert that the legacy route is live: HA-4 reports that on 2026-10-25 the legacy financial REST transport was enabled and canonical REST was supported but disabled, and that an endpoint appearing in OpenAPI is not evidence that its feature gate is on. `ha-daily-v2` stays registered as a superseded legacy directional mapping, not a generic current mapping and not a route around any retired interface (HA-4).

**The mapping is default-deny over all seventeen properties of the route's request body** (OpenAPI; `DECLARED_FIELDS_V3`, pinned by a test to the excerpt in `docs/sources/`). A field outside the list is rejected; a field may be left out only by an entry in `EXCLUDED_FIELDS_V3` with a written reason, and **there are none**. HA-4 asked us to "either pin the eleven-field subset explicitly or version the expanded mapping, with omissions and nulls kept distinct"; we versioned it.

| Sasana field | HA field (legacy route) | Type the mapping accepts | Canonical form inside `H(JCS(payload))` | Source |
|---|---|---|---|---|
| `subject_id` | the agent: identified by authentication on submission, `agent_id` in resolved predictions | — | the exact string; **the verifier supplies the expected value** (§7.1) | HA-1 §1, §4; HA-4 |
| `context_id` | the challenge: in the endpoint on submission, `challenge_id` in the resolved response | — | the exact string; **the verifier supplies the expected value** (§7.1) | HA-1 §1, §4; HA-4 |
| `mapping_id` | — | — | `"ha-daily-v3"`, **inside `C`** | ours |
| `revision_index` | HA's own revision is `revision_number` (starts at 1) | — | assigned by the committer, starting at **0**; **`revision_number = revision_index + 1`**, stated in `PayloadMapping.revision_numbering` and checked on receipts (§5.3), never assumed | HA-4; OpenAPI |
| `prev_commitment` | — | — | the previous revision's `C`, **inside `C`** | ours |
| `payload.direction` | `direction` | string or null (the schema pattern is `bullish\|bearish\|neutral`; **not enforced** here) | byte-exact | OpenAPI |
| `payload.confidence` | `confidence` | JSON number or null (the schema range is 0–1; not enforced) | the number (below) | OpenAPI |
| `payload.probabilities` | `probabilities` | **null, or an object with exactly the keys `bearish`, `neutral`, `bullish`**, each a JSON number; any other label set, an array, or a non-number value is **rejected** | the three numbers | HA-4; OpenAPI |
| `payload.prompt_hash` | `prompt_hash` | exactly 64 hexadecimal characters (either case), or null | byte-exact, **case preserved, never folded** | HA-4; OpenAPI |
| `payload.amount` | `amount` | omitted, null, or a number **strictly greater than zero**; `0` (and any negative) is **rejected** | the number | HA-4; OpenAPI |
| `payload.reasoning` | `reasoning` | string or null (HA's 20–8,000 character rule is HA's and is not checked) | byte-exact: not trimmed, no Unicode normalisation (NFC and NFD differ) | OpenAPI; HA-1 §1 |
| `payload.summary` | `summary` | string or null | byte-exact | OpenAPI |
| `payload.forecast_context` | `forecast_context` | an object or null, **bound whole**. Its inner schema (`additionalProperties: false`, a `schema_version`, a `decision`, `evidence_refs` …) is HA's and is not checked | the object, numbers as below | HA-4 (names it); OpenAPI |
| `payload.expected_revision` | `expected_revision` | an integer ≥ 1 or null (`2.0` is the integer 2). **Its meaning is not stated** (no description in the schema): it is bound as sent and is *not* related to `revision_index` | the integer | HA-4 (names it); OpenAPI |
| `payload.idempotency_key` | `idempotency_key` | string or null | byte-exact | HA-4 (names it); OpenAPI |
| `payload.model_provider`, `model_name`, `model_version` | the same names | string or null each. `model_provider` and `model_name` "must be sent together": a lone one **warns** (`MODEL_PROVIDER_NAME_NOT_PAIRED`) | byte-exact | HA-4 (names them); OpenAPI |
| `payload.token_usage` | `token_usage` | **any JSON object, or null** (the schema has `additionalProperties: true`); the former count-only restriction is gone | the object, numbers as below | HA-4; OpenAPI |
| `payload.is_revision` | `is_revision` | boolean only (not nullable); its schema default `false` is **not applied** | boolean | OpenAPI |
| `payload.trigger_event_id` | `trigger_event_id` | string or null (described as a market-event UUID; the schema sets **no UUID format**, so none is enforced) | byte-exact | HA-4; OpenAPI |
| `payload.revision_reason` | `revision_reason` | string or null | byte-exact | OpenAPI |
| `session_root` | not an HA field (see A.1) | — | chain tip of the Sasana session, hex | ours |
| `deadline` | HA's cutoff for the challenge (value not in what we were given) | — | verifier input; never read from the bundle | HA-1 §3; HA-4 ("the challenge exposes status and deadline"; the value is not given) |

**Omitted, null and present are three different states and stay three different states.** A field not supplied is not in the payload, a field supplied as `null` is `null`, and a present value is bound as sent. The mapping never invents a default (not even `is_revision`'s `false`), and every declared field except `is_revision` may be `null` because the schema declares each of them nullable.

**Numbers are lossless: JSON numbers under RFC 8785, no cap, no rounding.** (HA-4: "the public number schema has no [fractional] cap"; "do not round an already accepted payload to make it fit".) A number is an `int` or a finite `float`, bound as given and serialized by RFC 8785 (ECMAScript `Number::toString`) when the payload is hashed.

| Rule | Behaviour |
|---|---|
| Precision | **No fractional cap** (v2 refused more than 12 fractional digits). `0.1234567890123456` and its neighbour `0.1234567890123457` are different numbers with different `C` |
| Equality | **At the IEEE-754 double level.** `0.6`, `0.60`, `6e-1`, `60e-2` and `0.6000000000000000055511151231257827` are one number; so are `10`, `10.0` and `1e1`; and two decimals that round to the same double are the same number. This is documented here rather than hidden: the mapping preserves the double, not the digits of the text |
| Zero | `0`, `-0`, `0.0`, `-0.0` and `0e0` are all the number `0` (RFC 8785 serializes negative zero as `0`) |
| Exponents | `1e21` serializes as `1e+21`, `1e-7` as `1e-7`, `1e-6` as `0.000001` |
| Integers | exact within ±2^53. An integer **beyond ±2^53 is rejected**: a double cannot hold it, so accepting it would round it. A float such as `2^60` is a double and is accepted |
| Not a number | `NaN`, `±Infinity` (including `1e999`, which parses to infinity), booleans, numeric strings (`"0.6"`) and non-numbers are rejected |
| Where it applies | every number in the payload, including numbers nested inside `token_usage` and `forecast_context` |

The payload profile of §3.2 follows the mapping: `ha-daily-v1` and `-v2` payloads still refuse floats (reals are decimal strings there); `ha-daily-v3` payloads may contain finite floats (`number_profile` `ieee754-rfc8785`), and the profile is chosen by the mapping id inside `C`, so one payload cannot be re-read under the other profile. A committer who needs a cross-implementation guarantee should know the one cost: an implementation that parses JSON numbers into something other than doubles (for example an arbitrary-precision decimal) can disagree with this one about which numbers are equal.

**`probabilities` is an object with exactly `bearish`, `neutral` and `bullish`** (HA-4); that is a *semantic* rule beyond the schema type (HA-4: schema validation alone is insufficient: the numeric sum and exact label set are additional semantic rules). The label set is **rejected** if wrong, because a vector over other labels is not the vector HA scores.

**The commitment does not validate forecasts, so most of HA's other rules only warn.** The mapping must be total over whatever HA accepted. It warns, never rejects, when: the entries sum to something other than 1 beyond **1e-6** (`PROBABILITY_SUM:<sum>`; HA-4: tolerance 1e-6), an entry is negative (`PROBABILITY_NEGATIVE`), `direction` is supplied beside `probabilities` and is not the argmax (`DIRECTION_ARGMAX_MISMATCH:<d>`; either member of a tie counts), or `confidence` is supplied and is not the maximum (`CONFIDENCE_MAX_MISMATCH:<c>`; compared with a 1e-6 tolerance of ours, because HA states none), or only one of `model_provider` / `model_name` is present. A verifier that trusts a clean commitment verdict to mean "a sensible forecast" is wrong.

**`amount`**: omitted, null, or strictly greater than zero. **`0` is rejected**, not mapped to "unstaked": HA-4 says "zero is not an unstaked submission", and an unstaked submission omits `amount` entirely.

**Test vectors** (`tests/fixtures/mapping/ha-daily-v3.json`, run by `tests/test_commitment_v3.py`; another implementation should reproduce all of them): 5 equivalence groups hash the same (24 inputs: `confidence` 0.6 spelled five ways, `amount` 10 spelled four ways, zero spelled five ways, `1e21` spelled three ways, and key order); 36 pairs hash differently **and give different `C`**, including one change per declared field (all seventeen), omitted vs `null` vs a present or empty value for `amount`, `token_usage`, `forecast_context`, `direction`, `probabilities`, `is_revision` and `expected_revision`, a lower- vs upper-case `prompt_hash`, adjacent doubles, and a 16-digit fraction vs its neighbour; 30 inputs are rejected, including `amount` of `0`, an array or a wrong label set for `probabilities`, a numeric string for a number, an integer beyond 2^53, a lone surrogate and a canonical-route field. Every equivalence group's `payload_hash` was also reproduced by an **independent implementation** (Node's `JSON.stringify`, which is ECMAScript `Number::toString`), and a test re-runs that check when `node` is installed. The vectors are labelled `SYNTHETIC — not HA-issued`: they are not HA acceptance fixtures (HA-4: deterministic acceptance fixtures still need a separately agreed test environment and pinned expected IDs, revision mapping, deadline boundary and rejection behaviour).

**`ha-daily-v2` is superseded by v3.** It bound eleven fields, so a change to `forecast_context`, `expected_revision`, `idempotency_key`, `model_provider`, `model_name` or `model_version` was **not detected** by `C` (it could not even be committed: the fields were rejected as undeclared), it capped fractional precision at twelve places, it restricted `token_usage` to non-negative integer counts, and it allowed any label set for `probabilities`. It stays registered so archived v2 bundles verify (with `MAPPING_SUPERSEDED:ha-daily-v2->ha-daily-v3`), its vectors are kept, and a verifier that requires `ha-daily-v3` refuses a v2 bundle. **`ha-daily-v1` is superseded** by v2 and, transitively, v3: it bound seven of the eleven fields, accepted both an object and an array for `probabilities`, and is kept only so archived v1 bundles verify. New commitments should use v3; the example bundles are generated under v3.

### A.3 Which revision HA accepted: the registry (HA-2 question 2)

HA's public interface exposes no acceptance record (HA-1 §1, §4; HA-1 only): the resolved response carries no revision history, no submission timestamps and no commitment. Since then HA-4 reports an authenticated own-prediction readback (`GET /api/v1/eval/challenges/{challenge_id}/own-prediction`, "own-only state" per OpenAPI, whose response schema is empty in the document) and no public lock endpoint; neither is a signed acceptance record. So the verifier cannot tell from HA's current data which revision was accepted before the cutoff, and "the highest on-time revision in a bundle" is not that. What would let it:

> **PROPOSED EXTENSION — not an HA interface.** (a) An optional `commitment` field on a daily submission, carrying the hex `C` (hash only; no trace or data exchange, matching the scope HA called sensible). The TSA token stays with the committer and arrives in the reveal bundle. (b) A **signed acceptance receipt** for every submission attempt, in HA's vocabulary: `{challenge_id, agent_id, revision_index, commitment, accepted_at, accepted: true|false, reason}`, signed by an HA key the verifier pins (§5.3). Optionally `mapping_id` and `ha_revision_number` (HA's own number, starting at 1; §5.3). **There is no `payload_hash`**: an earlier draft had HA sign an unsalted hash of the payload it accepted, which would have been public before the reveal and let anyone test guesses against a low-entropy forecast (threat T6; HA-4 agrees). The cost is real: a receipt can no longer vouch for *exactly which payload* HA accepted for the fields its results API does not publish. What still binds the payload is `C`, which the receipt names and which HA recorded before the deadline; after resolution `cross_check_published` compares four fields with HA's results. If a hash of the accepted payload is ever attested, it must be **salted** (a per-submission salt HA and the committer share, or one disclosed at reveal) and would be a separate message, not a field of the pre-reveal receipt. (c) A **closing receipt**, one per agent and challenge, signed at the deadline: `{challenge_id, agent_id, accepted_count, last_accepted_revision_index, last_accepted_C, closed_at, mapping_id}`. HA-4: there is **no approval or delivery commitment** for any of these HA-side extensions, no signing keys, no key rotation and no deployment; they remain proposed verifier inputs, and every receipt in this repository is **SYNTHETIC — not HA-issued**. `accepted_count` counts scored-eligible acceptances only (not `counts_for_score: false` paper-trade signals).

The scored revision is then the one the closing receipt names, which must agree with the receipt list (§5.1, §5.3). Cases from HA-2 are in `examples/ha-reveal/`: a **rejected revision** (`c`: the initial is scored), an **omitted earlier commitment** (`d`: provable because `prev_commitment` is inside `C`), a **withheld later receipt** (`j`: caught by the closing receipt), and a **missing closing receipt** (`k`: `INCOMPLETE_RECEIPTS`).

**What can be checked against HA's current public data alone.** `cross_check_published(payload, prediction)` compares a revealed payload with a prediction as HA's results API returns it, on the four fields it returns (HA-1 §4): `direction`, `confidence`, `reasoning`, `summary` (confidence compared as a number, not as text). It cannot check the other seven bound fields, which the results API does not return (HA-1 §4). It proves nothing about timing and can only be run after resolution.

### A.4 Trust and time policy for this example (HA-2 question 3)

The example requires: a **pinned TSA anchor**; the time rule `genTime + accuracy + clock_skew_s < deadline` with `default_accuracy_s` assumed (and reported) when the TSA omits accuracy, as FreeTSA does; an **optional seal**, verified only when `--trust-key` is given and never changing the verdict; a **pinned receipt key** covering both receipt kinds; a required `ha-daily-v3` mapping; the verifier's own **expected agent and challenge ids**; and **no revocation checking**, documented in §10 with what that costs. Each rule has a test or is marked NOT ENFORCED there.

### A.5 Synthetic reveal bundles (HA-2: an example of an initial forecast plus one revision)

`examples/ha-reveal/` holds twenty-three synthetic bundles (twenty-four scenarios), all labelled `SYNTHETIC — not HA-issued` in their data, each with its receipts and closing receipt (except `k`, which has none by design), and a runner that prints `bundle | expected | actual | match`. They are not HA acceptance fixtures, signed HA receipts or live forecasts (HA-4). All verify against `trust/trust.json`, which holds the verifier's expected agent and challenge ids.

| Bundle | Case | Verdict |
|---|---|---|
| `a-initial-only` | initial, accepted | `VALID_ON_TIME`, scored 0 |
| `b-revision-accepted` | initial + revision, both accepted | `VALID_ON_TIME`, scored 1 |
| `c-revision-rejected` | revision rejected by the counterparty | `VALID_ON_TIME`, scored **0** |
| `d-initial-omitted` | bundle omits the initial commitment | `INVALID` (`HISTORY_GAP`) |
| `d2-initial-omitted-lenient` | the same bundle with `--allow-unrevealed-history` | `VALID_ON_TIME` **LENIENT**, exit **5** |
| `e-…-rejected`, `e2-…-receipt-says-accepted` | revision timestamped after the deadline | scored 0; and `LATE` when a receipt claims it was accepted |
| `f-payload-tampered`, `f2-amount-tampered` | `confidence` / `amount` edited after commit | `INVALID` |
| `g-wrong-mapping-version` | bundle claims the superseded `ha-daily-v1` | `INVALID` (not the required mapping) |
| `h-never-revealed`, `h2-scored-revision-not-revealed` | accepted revision never revealed | `UNREVEALED` |
| `i-operator-reseal-after-commit` | session rewritten and resealed after commit | `INVALID` |
| `j-later-receipt-withheld` | committer supplies only the initial's receipt | `INVALID` (disagrees with the closing receipt) |
| `k-closing-receipt-missing` | receipts but no closing receipt | `INCOMPLETE_RECEIPTS`, exit **6** |
| `l-closing-receipt-wrong-key` | closing receipt signed by an unpinned key | `INVALID` |
| `m-wrong-agent` | an honest bundle committed under another agent | `INVALID` (`AGENT_ID_MISMATCH` only) |
| `n-wrong-challenge` | an honest bundle committed under another challenge | `INVALID` (`CHALLENGE_ID_MISMATCH` only) |
| `o-wrong-revision-index` | a revision's `revision_index` edited | `INVALID` (the index is inside `C`) |
| `p-corrupted-seal` | one digit of the `CHAIN_SEAL` signature flipped | `INVALID` (`CHAIN_SEAL signature invalid`) |
| `q-duplicate-revisions` | one revision listed twice | `INVALID` (`duplicate revision_index`) |
| `r-reordered-revisions` | the `revisions` array reversed | `VALID_ON_TIME`, scored 1: **identical to `b`** (array order is ignored) |
| `s-unstaked-full-vector` | HA-4's example: 0.60 / 0.30 / 0.10, `amount` omitted, uppercase `prompt_hash` | `VALID_ON_TIME`, scored 0 |
| `t-receipt-revision-number-off-by-one` | receipt numbers revision_index 1 as revision number 1 | `INVALID` (`RECEIPT_REVISION_NUMBER_MISMATCH`) |

Run `python3 examples/ha-reveal/run.py`; see `examples/ha-reveal/README.md`.

### A.6 Open, HA-specific

These are questions for HA, not decisions this note can make. The first block of v2's questions is answered by HA-4 and OpenAPI; what is left:

1. **`expected_revision`.** The schema types it (integer ≥ 1 or null) and does not describe it. The mapping binds it as sent and does not relate it to `revision_index` or to `revision_number`. What does it mean, and is it in HA's numbering (starting at 1)?
2. **The inner schema of `forecast_context`** is HA's (`additionalProperties: false`, `evidence_refs` …); the mapping binds the object whole and does not check it. HA's rule may change without a mapping change, and a stricter HA that rejects a field does not affect a commitment that already bound it.
3. **The tolerance for the `direction` / `confidence` cross-check.** HA-4 and the schema say an explicit value "must match" the argmax / maximum and give no tolerance; the mapping warns beyond 1e-6 of its own choosing.
4. **Per-submission receipts and a closing receipt** (§5.3). HA-4: no approval or delivery commitment, no signing keys, no key rotation, no deployment. Whether HA records per-submission acceptance times (its results API does not expose them, HA-1 §4), and whether it would ever attest the accepted payload (which would have to be salted, A.3).
5. **The deadline value** for a challenge, and which TSA(s) HA would accept. HA-4: there is no public lock endpoint and `counts_for_score` is not a cryptographic locking receipt.
6. **Deterministic acceptance fixtures** need a separately agreed test environment and pinned expected IDs, revision mapping, deadline boundary and rejection behaviour (HA-4). None exists; nothing here is one.
7. **Whether the legacy route stays enabled.** HA-4 reports it enabled and canonical REST supported but disabled on 2026-10-25; a canonical-route mapping would be a different mapping with a different field set.
8. Whether HA would add a `commitment` field. This, any receipts and any integration need a separate agreement; the commercial question is not addressed by this note.
9. There is no HA adapter. `examples/ha-reveal/` contains synthetic bundles only.

Session-open commitments, and the limits in §11, apply unchanged.

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
20. ~~**New:** `ha-daily-v1` does not bind `prompt_hash`, `amount`, `token_usage` or `trigger_event_id`.~~ Resolved: `ha-daily-v2` was default-deny over eleven fields, and `ha-daily-v3` (Appendix A.2) binds all seventeen the legacy route now declares; `ha-daily-v1` is superseded.
21. ~~**New:** receipt-list completeness.~~ Resolved as a proposal: the signed closing receipt (§5.3); a list without one is `INCOMPLETE_RECEIPTS`, a list that disagrees with it is `INVALID`.
22. **New:** how a counterparty publishes, scopes and rotates its receipt key (key id, validity period).
23. **New:** session-open commitments with the counterparty as first checkpoint witness (§5.2, §11), now that the witness design publishes heads during the session.
24. ~~**New (HA-specific):** the exact shape of `probabilities` and the types of `amount`, `token_usage` and `trigger_event_id` are assumptions the mapping commits to.~~ Resolved by HA-4 and the OpenAPI schema (Appendix A.1, A.2): `probabilities` is an object with exactly `bearish` / `neutral` / `bullish`, `amount` is omitted, null or > 0, `token_usage` is any object or null, `trigger_event_id` is a string or null. What remains HA's is Appendix A.6 (`expected_revision`, the inner schema of `forecast_context`, the cross-check tolerance).
