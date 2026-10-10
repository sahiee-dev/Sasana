# Pre-Outcome Commitment — Design Proposal

**Status:** IMPLEMENTED (uncommitted, awaiting review). Sections 1–2 describe the code *as it was before* this work; see **Implementation status** below for what changed.
**Scope:** a generic primitive. Platform-specific mappings live only in the appendix (and, later, in `examples/`).

### Implementation status

Decisions taken: commitment formula **exactly as originally specified** (no `prev_commitment` inside `C`; amendment A1 not adopted); sidecar bundle (no new event type); strings/ints-only payload profile; `commit()` fail-closed; session-open commitment **deferred**.

| Area | Change | Where |
|---|---|---|
| JCS floats | Now RFC 8785-conformant (ECMAScript number formatting); ints beyond ±2^53 round through a double. All 24 RFC 8785 Appendix B vectors pass. **Behaviour change:** a stored event containing an exotic float (e.g. `1e-05`) will now hash differently. | `sasana/jcs.py`, `tests/test_jcs.py` |
| RFC 3161 | New `verify_timestamp_strict()`: CMS signature (RSA PKCS#1 v1.5 / ECDSA / Ed25519), chain to caller-pinned anchors, timeStamping EKU, validity at genTime, SHA-256 imprint, nonce, optional policy allow-list, sub-second genTime, accuracy. Request builder accepts a nonce; `request_timestamp` accepts `url`/`nonce`. The old imprint-only `verify_timestamp` is unchanged (existing verifier behaviour and tests intact). **Not done:** revocation (CRL/OCSP), RSA-PSS. | `sasana/rfc3161.py`, `tests/test_rfc3161_strict.py`, `tests/tsa_fixture.py` |
| Verifier | New public `verify_chain_integrity()` (structural + sequence + hash chain only) so `commit()` can work on open sessions. No existing function changed. | `sasana/verifier.py` |
| Commitment | `commit()`, `reveal_bundle()`, `verify_commitment()`, `compute_commitment()`, payload profile, disclosures. | `sasana/commitment.py`, `tests/test_commitment.py` |
| CLI | `sasana verify-commitment` (exit 0 valid, 2 late, 1 invalid, 3 input error). | `sasana_cli.py` |

Validation: 247 tests pass on Python 3.11 (160 pre-existing + 87 new), 229 pass + 18 pre-existing skips on 3.10 (cryptography 41); `ruff check` and `ruff format --check` clean. Nine deliberate mutations of `commitment.py` were each caught by a test. The strict verifier was also checked against a **live FreeTSA token** (nonce echoed, chain to FreeTSA's published root), and a full `commit()` → `reveal_bundle()` → `sasana verify-commitment` run against FreeTSA gave `VALID_ON_TIME`, and `LATE` for an earlier deadline. FreeTSA omits `accuracy` and issues whole-second `genTime`; the verifier assumes 1 s by default (`default_accuracy_s`) and warns.

**Known gaps in the implementation:** no revocation checking; single-TSA per commitment (`tsa_urls` is tried in order, not n-of-m); the Rust verifier and its number formatting were not touched, so Rust `canonical_json` may still differ from Python/JS for exotic floats (it did before this change too); `commit()` has no default TSA trust anchor (callers pin it); session-open commitment (§5.2) is not implemented; no counterparty-receipt protocol exists, `registry` is just an input.

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
| 3 | Canonicalization is a hand-written JCS (`sasana/jcs.py::canonicalize`). **It is not fully RFC 8785 conformant for floats** (see §1.1). | `sasana/jcs.py::_float_to_string`, `canonicalize` |
| 4 | Content is never stored; only SHA-256 digests of prompts/responses/args/results enter events. `content_hash` hashes dict/list via JCS, str via UTF-8, bytes raw, **anything else via `str(value)`**. | `sasana/event_mapper.py` (module docstring, `map_llm_call`, `map_tool_invoke`…); `sasana/_utils.py::content_hash` |
| 5 | **"Session root" is the chain tip.** There is no Merkle tree in this repo **(absent)**. `VerifyResult.root_hash` is the last event's `event_hash`; `CHAIN_SEAL.payload.session_hash` is the same value. | `verifier.py::verify` (`root_hash = sorted_events[-1]["event_hash"]`); `archeion/server.py::seal` (`"session_hash": last["event_hash"]`) |
| 6 | Ledger is a per-session SQLite file (WAL, `synchronous=FULL`), events committed one at a time, exported to JSONL at session close. | `sasana/sqlite_ledger.py::SqliteLedger.connect`, `__write_event`, `export_jsonl` |
| 7 | Authority split: `EventType.is_sdk_authority` gates `SqliteLedger.record()`; `CHAIN_SEAL` etc. are server-authority and silently dropped from the SDK path. This is an **in-process check**, not an isolation boundary. | `sasana/events.py::EventType`; `sqlite_ledger.py::record` |
| 8 | Archeion `POST /seal` runs `verify()`, refuses `PARTIAL`/non-`INTACT`/no-`SESSION_END`, then appends one Ed25519-signed `CHAIN_SEAL` (`sealed_by`, `server_pubkey`, `session_hash`, `timestamp_imprint_match`, optional `timestamp_claimed_utc` — renamed in 1.2.0 from `timestamp_verified` / `timestamp_utc`, which overstated an imprint-only check). Sealing is **post-hoc** and attests chain integrity only. | `archeion/server.py::seal`; keys in `archeion/keys.py::load_or_generate` |
| 9 | Per-event Ed25519 signing exists but is **opt-in**: `SqliteLedger(private_key=…)` embeds `session_pubkey` in `SESSION_START`. `SasanaSkill`, `OpenClawObserver`, and the OTel exporter construct ledgers **without** a key, so they do not sign. | `sqlite_ledger.py::open_session`; `signing.py`; `sasana/skill.py::_get_or_create_ledger`; `observer.py::_get_or_create_ledger`; `integrations/otel.py::_ledger_for` |
| 10 | RFC 3161 flow: `open_session` writes `SESSION_START`, submits its **pre-token** hash to the TSA (default Freetsa, `SASANA_TSA_URL` override), then **rewrites the seq-1 row** with `payload.rfc3161_token` and a recomputed `event_hash`/signature. Anchoring is **fail-open**. | `sqlite_ledger.py::open_session`, `_try_anchor_rfc3161`, `_embed_rfc3161_token`; `sasana/rfc3161.py::request_timestamp` |
| 11 | `verify_timestamp` checks only that the token parses and its `messageImprint` equals the expected hash. **The CMS signature, certificate chain, TSA identity, and policy are not verified** **(absent)**. The request carries **no nonce** **(absent)**. `genTime` is truncated to whole seconds; `accuracy` is ignored. | `rfc3161.py::verify_timestamp`, `build_timestamp_request`, `_parse_tstinfo`; `verifier.py::_check_rfc3161_timestamp` (docstring says so explicitly) |
| 11b | A bad/missing timestamp is **informational**: it never makes a session `COMPROMISED`. | `verifier.py::verify` (comment above `all_errors`) |
| 12 | Verifier runs 7 checks: structural, sequence, hash_chain, completeness, seal_signature, session_signatures, rfc3161_timestamp. Event types outside `ALLOWED_EVENT_TYPES` fail the structural check. | `verifier.py::verify`, `ALLOWED_EVENT_TYPES` |
| 13 | Evidence classes: `PARTIAL_EVIDENCE` (any `LOG_DROP`) > … > `AUTHORITATIVE_EVIDENCE` (has `CHAIN_SEAL` — *as of 1.0.0/1.1.0; from 1.2.0 it requires a seal verified against a pinned key, and an unpinned seal is `SELF_SEALED_EVIDENCE`*) > `SIGNED_NON_AUTHORITATIVE_EVIDENCE` > `NON_AUTHORITATIVE_EVIDENCE`. Nothing in the SDK ever *emits* `LOG_DROP`; it is only defined and counted. | `verifier.py::_determine_evidence_class`; `events.py`; `git grep LOG_DROP` finds no producer |
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
| T7 | Selective reveal of revisions (reveal the lucky one, hide the others). | **Partly** | `prev_commitment` chaining exposes that a predecessor exists; a counterparty receipt log exposes all `C`s. Non-reveal of any received `C` is reported as a signal (§8). |
| T8 | Equivocation (two different commitments for the same `(subject, context, revision_index)`). | **Partly** | Detectable only if both reach the counterparty. Bundle verification flags it when a registry is supplied. |
| T9 | Colluding committer + TSA, or committer + counterparty. | **No** | Out of scope. |

---

## 3. Commitment

### 3.1 Definition

```
C = SHA-256( domain_tag || subject_id || context_id || revision_index
             || H(JCS(payload)) || session_root || salt )
```

with the byte-level encoding in §3.3 (`sasana/commitment.py::compute_commitment`). `H(JCS(payload)) = SHA-256(RFC 8785 canonical bytes of payload)`.

> **Decision: amendment A1 not adopted.** `prev_commitment` is *not* inside `C`. The revision chain is therefore metadata beside `C`: the verifier checks it is self-consistent within a bundle, but the timestamp does not authenticate it, so it cannot prove a revision's claimed predecessor is the real one. Tamper-evidence for "which revisions exist" comes from the counterparty registry (§7 step 6), not from the chain. Adopting A1 later would be a `domain_tag` bump (`sasana/commit/v2`).

### 3.2 Field definitions

| Field | Type | Notes |
|---|---|---|
| `domain_tag` | ASCII | `"sasana/commit/v1"`. Separates this hash from every other SHA-256 use in the project (event hashes, content hashes). Bumped on any encoding change. |
| `subject_id` | UTF-8 string | Who commits (agent/account). Opaque to core. No Unicode normalization is applied: bytes are exactly as supplied; the bundle carries the same string. |
| `context_id` | UTF-8 string | What it's about (market+date, trade slot, eval task…). Opaque to core. |
| `revision_index` | uint32 | `0` for the first commitment, `+1` per revision. |
| `payload` | JSON object | The decision. **Payload profile:** only strings, booleans, null, arrays, objects, and *integers within ±2^53*. Real numbers must be encoded as decimal **strings** (e.g. `"0.7"`) or scaled integers, because `sasana/jcs.py` is not float-conformant (§1.1-5). |
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

---

## 4. Trusted timestamp

1. Committer computes `C` and sends the 32 bytes to the TSA as an RFC 3161 `TimeStampReq` (SHA-256, `certReq=TRUE`, **with a random nonce**). Only a hash leaves the machine (same privacy property as `rfc3161.py::request_timestamp`).
2. The token is obtained **before** submission to the counterparty. **Fail-closed:** if no valid token is returned, `commit()` raises; it does not degrade silently (unlike `sqlite_ledger.py::_try_anchor_rfc3161`).
3. Verification of a token (all required, none present today — §1.1-3):
   * CMS `SignedData` signature valid; signer cert chains to a **verifier-pinned** TSA trust anchor; signer cert has the `id-kp-timeStamping` EKU and was valid at `genTime`.
   * `TSTInfo.messageImprint.hashAlgorithm == SHA-256` and `hashedMessage == C`.
   * Nonce echoed, if sent.
   * Policy OID acceptable to the verifier's policy.
4. **Time rule:** let `t_hi = genTime + accuracy` (accuracy defaults to 0 only if the TSA omits it, and the verdict says so). The commitment is **on time** iff `t_hi < deadline`. `deadline` is an **input supplied by the verifier/counterparty, not read from the bundle**. Sub-second precision from `genTime` must be preserved (the current parser truncates it, `rfc3161.py::_parse_tstinfo`).
5. Local clocks are never used: `event.timestamp` fields are writer-asserted (§1 row 1) and carry no weight here.

---

## 5. Revisions and session-open commitment

### 5.1 Revisions

* Revision `i` is a complete, independent commitment with its own salt, payload, `session_root`, and timestamp. A revision may reference a newer chain tip, which is how new tool calls enter the record.
* `prev_commitment` = `C` of revision `i-1` (`null` for `i = 0`). Carried in the public record; **not** bound into `C` (decision above).
* **Effective commitment** = the revision with the highest `revision_index` among those whose `t_hi < deadline`. Revisions that are late are *recorded but not effective*.
* **Ordering check:** `t_hi` must be non-decreasing in `revision_index`; a violation invalidates the later revision.
* **Superseded revisions remain verifiable:** the bundle may and, by policy, should include them; each verifies exactly like the effective one.
* Gaps in indices, or an unrevealed predecessor referenced by `prev_commitment`, are reported as `UNREVEALED_REVISION`.

### 5.2 Optional session-open commitment — DEFERRED (not implemented)

Goal: let a counterparty **count sessions per context** (T4).

At `SESSION_START` the committer publishes `open_binding = SHA-256(enc("sasana/open/v1") || enc(subject_id) || enc(context_id) || enc(session_id) || enc(salt_open))` to the counterparty and stores `context_binding = open_binding` in the `SESSION_START` payload (a new optional key; the existing hash chain and the existing RFC 3161 token over the pre-token `SESSION_START` hash then also cover it for free). The counterparty's registry then holds one entry per opened session per `(subject, context)`.

At reveal, the committer discloses `salt_open` and `session_id`; the verifier recomputes `open_binding`, checks it matches the `SESSION_START` payload, and compares the registry's session count for the context with the number of revealed sessions. Differences are reported (`SESSIONS_UNACCOUNTED`).

Caveats stated plainly: this only works with a counterparty-held registry; it cannot detect sessions that were never instrumented; and the existing session-start anchoring is fail-open (`sqlite_ledger.py::_try_anchor_rfc3161`) so session-open mode needs its own fail-closed path.

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

Notes: the TSA certificate chain travels inside each `tsa_token` (requested with `certReq=TRUE`); trust anchors are never taken from the bundle. The bundle never contains the outcome, and the **deadline is not in it** (verifier input). Events already contain only digests (§1 row 4), so publishing `session_events` does not publish prompts or tool content; `disclosures` is how a committer chooses to prove specific evidence claims, limited to the three well-defined forms (`jcs`, `utf8`, `bytes`), never the `str(value)` fallback (§1.1-6).

---

## 7. Verification algorithm (as implemented in `verify_commitment`)

Differences from the first draft: step 7 (session-open) is omitted because §5.2 is deferred; a revealed session must be **complete** (`SESSION_END` present), because step 2 uses the unmodified `verify()`; a failure of a *higher-index* revision than the effective one makes the verdict `INVALID` (the effective revision cannot be established), whereas a failed lower-index revision is a warning.

Inputs: `bundle`, `deadline`, `trusted_tsa_anchors`, optional `trusted_seal_pubkey`, optional `registry` (list of `C` and open-bindings the counterparty received), `policy` flags.

1. **Parse and version-check.** Unknown `bundle_version`/`domain_tag` ⇒ `INVALID`.
2. **Trace integrity.** Run the existing `sasana.verifier.verify(session_events, trusted_seal_pubkey=…)`. `COMPROMISED`/`ERROR` ⇒ `INVALID`. `PARTIAL` ⇒ `INVALID` unless `policy.allow_partial`. Record `evidence_class`.
3. For **each revision** `r`:
   1. Check payload profile (§3.2). Compute `ph = SHA-256(JCS(r.payload))`.
   2. Check each hex/length rule; build `input` per §3.3; compute `C'`. `C' != r.commitment` ⇒ revision `INVALID`.
   3. **Locate `session_root`** among `session_events[*].event_hash`; absent ⇒ `INVALID`. Let `k` be its `seq`. Events with `seq > k` are listed as `post_commitment_events` (informational; this is where outcome-aware activity would appear).
   4. **Verify the TSA token** per §4.3 against `C'`. Extract `genTime`, `accuracy`.
   5. `on_time = (genTime + accuracy) < deadline`.
4. **Revision chain.** Indices contiguous from 0 within the bundle (gaps ⇒ `UNREVEALED_REVISION`); `prev_commitment` equals the previous revision's `C` (and, with A1, was inside `C`); `t_hi` non-decreasing.
5. **Select the effective revision:** highest index with `on_time`. None ⇒ verdict `LATE` (all commitments postdate the deadline).
6. **Registry cross-check (if supplied):** every `C` in the registry must appear in the bundle (else `UNREVEALED_COMMITMENT`, with count); every bundle `C` must be in the registry received before `deadline` (else `NOT_RECEIVED_BY_COUNTERPARTY`); two registry entries sharing `(subject, context, revision_index)` with different `C` ⇒ `EQUIVOCATION`.
7. *(Deferred — session-open cross-check.)*
8. **Disclosures (if present):** for each, recompute `content_hash` in the declared form and compare to the event's field at `seq`; mismatch ⇒ that disclosure `FAILED` (does not invalidate the commitment).
9. **Verdict.** One of `VALID_ON_TIME`, `LATE`, `INVALID`, plus a list of warnings (`UNREVEALED_*`, `EQUIVOCATION`, `SESSIONS_UNACCOUNTED`, `post_commitment_events`, `capture_mode`, evidence class, weak-TSA-accuracy). The verifier never collapses warnings into a boolean.

---

## 8. Limits (stated plainly)

* **Completeness is not proven.** The chain proves the recorded events were not altered; it cannot show that every relevant action was recorded (the SDK never even emits `LOG_DROP`, §1 row 13).
* **Truthfulness is not proven.** A committed trace may record false statements. Commitment fixes *what was claimed and when*, not whether it was true.
* **Human influence outside instrumentation is invisible.** A person (or another program) may have chosen the decision and fed it in; the trace shows only the instrumented path. See T3: undisclosed in-process edits are not defended.
* **Time is as good as the TSA.** Without the full CMS verification described in §4, the "timestamp" is just a blob. A single TSA is a single trust point.
* **Uniqueness requires a counterparty.** A timestamp proves "existed by", never "the only one".
* **Non-reveal is itself a signal, not a proof.** A committed `C` that is never revealed tells a counterparty something (the committer chose not to be scored) but proves nothing about the hidden contents. Platforms should define the consequence in their rules; the core only reports it.
* **Lost salt = unrevealable commitment.** The salt must be persisted with the same care as a signing key.

---

## 9. API (as implemented, `sasana/commitment.py`)

```python
def commit(*, subject_id: str, context_id: str, payload: Mapping[str, Any],
           session_events: Sequence[Mapping[str, Any]], trusted_tsa_anchors: Sequence[bytes],
           tsa_urls: Optional[Sequence[str]] = None, prev: Optional[PublicCommitment] = None,
           salt: Optional[bytes] = None, allowed_policies: Optional[Sequence[str]] = None,
           ) -> tuple[PublicCommitment, CommitmentSecrets]: ...          # raises CommitmentError (fail-closed)

def reveal_bundle(commitments: Sequence[tuple[PublicCommitment, CommitmentSecrets]],
                  session_events: Sequence[Mapping[str, Any]], *,
                  capture_mode: Literal["in_process", "sidecar", "gateway"],
                  disclosures: Optional[Sequence[Mapping[str, Any]]] = None) -> dict: ...

def verify_commitment(bundle: Mapping[str, Any], *, deadline: datetime,
                      trusted_tsa_anchors: Sequence[bytes], trusted_seal_pubkey: Optional[str] = None,
                      registry: Optional[Sequence[Mapping[str, Any]]] = None,
                      allow_partial: bool = False, default_accuracy_s: float = 1.0,
                      allowed_policies: Optional[Sequence[str]] = None) -> CommitmentVerdict: ...  # never raises
```

Also public: `compute_commitment`, `encode_commitment_input`, `payload_hash`, `validate_payload_profile`, `disclosure_hash`; dataclasses `PublicCommitment`, `CommitmentSecrets` (both with `to_dict`/`from_dict`), `CommitmentVerdict`. Differences from the sketch: `commit()` takes `trusted_tsa_anchors` (it self-verifies the token before returning) and `allowed_policies`; `verify_commitment` adds `default_accuracy_s`; `reveal_bundle` has no `session_open`; the verdict also carries `effective_payload` and `errors`.

**Operational note:** `CommitmentSecrets.salt` must be persisted with the same care as a signing key; without it the commitment can never be revealed.

---

## Appendix A — Headline Arena mapping (worked example only)

> **Provenance caveat.** I have not read Headline Arena's documentation or API. The field names below are exactly the ones given in the task brief for their daily-market submissions: `direction`, `confidence`, `probabilities`, `reasoning`, `summary`, `is_revision`, `revision_reason`. Anything else about their platform is unknown and left as an open question. **I do not use, hash, or depend on their `prompt_hash` or `token_usage` fields.**

| Generic field | HA mapping |
|---|---|
| `subject_id` | HA's identifier for the forecasting agent/account *(exact field unknown)* |
| `context_id` | HA's identifier for the daily market *(exact field unknown)*, e.g. market id + date |
| `payload` | the seven public fields above, under the §3.2 profile: `confidence` and each entry of `probabilities` as decimal **strings** (not floats) |
| `revision_index` / `prev_commitment` | derived from `is_revision`; `revision_reason` stays inside the payload |
| `session_root` | chain tip of the Sasana session that produced the forecast (not an HA field) |
| `deadline` | HA's submission cutoff for that market *(unknown; supplied by HA/verifier)* |

**PROPOSED EXTENSION — not part of the existing HA API.** Two new optional fields on a submission:

* `commitment` — hex `C`
* `tsa_token` — base64 DER RFC 3161 token over `C`

HA would store them with the submission; `salt`, `session_root`, and the session JSONL arrive later in the reveal bundle. If HA exposed nothing new, the committer could still publish `(C, token)` themselves and HA's existing `is_revision`/`revision_reason` would be mirrored by `revision_index` — but then there is no counterparty registry and T4/T7/T8 defences degrade (§2).

An HA adapter, if built, belongs in `examples/headline_arena/`, not in core.

---

## Open design questions — status

Resolved by your choices (Whole feature; original formula; recommended defaults otherwise):

1. ~~Bind `prev_commitment` inside C?~~ **No** — original formula kept (see §3.1).
2. ~~Sidecar vs in-chain event?~~ **Sidecar.** No new `EventType`; verifier unchanged apart from one added helper.
3. ~~Number policy?~~ **Strings/ints-only payload profile kept; `jcs.py` also fixed** (RFC 8785 vectors). Rust verifier not updated (see Known gaps).
4. ~~Who builds the TSA verifier?~~ **In `sasana/rfc3161.py` with `cryptography`** (no `openssl` dependency); nonce, accuracy, policy allow-list included.
7. ~~Fail-closed?~~ **`commit()` fail-closed; session-start anchoring left fail-open** (unchanged).
8. ~~Session-open in v1?~~ **Deferred.**

Still open — need your decision:

5. **Default TSA trust anchor.** `commit()`/`verify` require the caller to pin one. Should the package ship FreeTSA's root (I verified live that it works), or stay anchor-free?
6. **Multiple TSAs (n-of-m).** Currently first-success failover, one token per commitment.
9. **Counterparty registry protocol.** `registry` is only an input list; nobody issues signed receipts yet. Should Archeion (or a sibling service) do it?
10. **Archeion's role** relative to commitment (seal before commit vs mid-session). Today a revealed session must be complete, but need not be sealed.
11. **`capture_mode` is self-declared**; only produces a warning for `in_process`.
12. **Per-event signing is off in every shipped integration**; should commitments require `SIGNED_NON_AUTHORITATIVE_EVIDENCE` or better?
13. **Selective disclosure / Merkle tree** — still all-or-nothing trace reveal.
14. **Non-reveal verdict** — still informational (registry gives `UNREVEALED_COMMITMENT`); no reveal-deadline input.
15. **Namespacing/versioning** of `sasana/commit/v1`, `bundle_version`.
16. **HA specifics** (appendix only): identifiers, deadline semantics, whether they would accept the two extra fields.
17. **New:** revocation checking (CRL/OCSP) for TSA certificates is not implemented.
18. **New:** Rust verifier number formatting vs the now-conformant Python `jcs.py` — align and add shared test vectors?
19. **New:** the JCS change alters hashes of any stored event with an exotic float. Is there any real log in the wild with such values (I found none in tests/fixtures), or do you want a migration/compat note in the CHANGELOG?
