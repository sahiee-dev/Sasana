# Sasana — Technical Architecture Document

Version: 1.0.0  
Date: June 2026

---

## System Overview

Sasana is composed of five independent subsystems:

```
┌─────────────────────────────────────────────────────┐
│                   Agent Process                      │
│  ┌──────────────────────────────────────────────┐   │
│  │  SasanaSkill / Observer / Integration        │   │
│  │  (event capture layer)                       │   │
│  └────────────────────┬─────────────────────────┘   │
│                       │ events                       │
│  ┌────────────────────▼─────────────────────────┐   │
│  │  SqliteLedger                                │   │
│  │  (hash chain, WAL SQLite)                    │   │
│  └────────────────────┬─────────────────────────┘   │
│                       │ export JSONL                 │
└───────────────────────┼─────────────────────────────┘
                        │
           ┌────────────▼────────────┐
           │   session.jsonl         │
           │   (portable artifact)   │
           └──────┬──────────┬───────┘
                  │          │
      ┌───────────▼──┐  ┌────▼────────────────┐
      │   Verifier   │  │   Archeion           │
      │   (Python    │  │   (sealing server)   │
      │    or Rust)  │  └────┬────────────────┘
      └──────────────┘       │ sealed JSONL
                             │
                   ┌─────────▼──────────┐
                   │  Verifier (again)  │
                   │  AUTHORITATIVE     │
                   └────────────────────┘
```

The JSONL file is the only artifact that matters for verification and compliance. It is self-contained and can be verified without network access, without the original agent process, and without Sasana being installed (via the Rust binary).

---

## 1. Event Envelope

Every event recorded by Sasana has exactly 7 required fields plus one optional field:

```json
{
  "seq":        1,
  "event_type": "SESSION_START",
  "session_id": "abc-123",
  "timestamp":  "2026-06-14T03:22:01.543210Z",
  "payload":    { "agent_id": "my-agent" },
  "prev_hash":  "0000000000000000000000000000000000000000000000000000000000000000",
  "event_hash": "a3f9...",
  "signature":  "base64..."
}
```

| Field | Type | Description |
|---|---|---|
| `seq` | integer | Monotonically increasing, starting at 1. Must be contiguous — no gaps. |
| `event_type` | string | One of the defined event types (see section 3). |
| `session_id` | string | UUID identifying the session. Identical across all events in a session. |
| `timestamp` | string | UTC ISO 8601 with microseconds: `%Y-%m-%dT%H:%M:%S.%fZ`. |
| `payload` | object | Event-specific data. Content is never raw text — only hashes and metadata. |
| `prev_hash` | string | SHA-256 hex (64 chars, lowercase) of the previous event's `event_hash`. For `seq=1`, this is GENESIS_HASH. |
| `event_hash` | string | SHA-256 hex of this event (computed over the event minus `event_hash` and `signature`). |
| `signature` | string (optional) | Base64 Ed25519 signature over `event_hash`. Present when SDK signing is enabled or when the event is a `CHAIN_SEAL`. |

**GENESIS_HASH:** `"0000000000000000000000000000000000000000000000000000000000000000"` (64 zeros). This is the `prev_hash` of the first event in every session.

---

## 2. Hash Algorithm

### Canonicalization (RFC 8785 / JCS)

Before hashing, the event object is serialised to canonical JSON per RFC 8785. This is critical: without a canonical form, different implementations can produce different byte representations of the same logical object, causing hash mismatches.

RFC 8785 rules (as implemented in `sasana/jcs.py` and `sasana-rs/src/main.rs`):

1. **Object keys** are sorted by UTF-16 code unit sequence (not UTF-8, not Unicode codepoint)
2. **No whitespace** outside string values
3. **Strings**: control characters U+0000–U+001F escaped as `\uXXXX`
4. **Numbers**: IEEE-754 doubles, shortest round-trip representation; `-0.0` serialises as `"0"`
5. **Arrays**: order preserved
6. **Booleans/null**: `true`, `false`, `null`

### Fields excluded from hashing

When computing `event_hash`, both `event_hash` (the output field) and `signature` (added after hashing) are stripped from the object before canonicalization. This means:

- Adding or removing a `signature` field does not change `event_hash`
- The hash can be recomputed and verified without knowing the private key
- The verifier can check hash integrity independently of signature validity

### Hash computation

```python
def compute_event_hash(event: dict) -> str:
    payload = {k: v for k, v in event.items() if k not in ("event_hash", "signature")}
    return hashlib.sha256(jcs_canonicalize(payload)).hexdigest()
```

Output: 64 lowercase hexadecimal characters.

---

## 3. Event Types and Authority Model

Events are divided into two authority classes. This is a structural security property, not just a naming convention.

### SDK-authority events (the agent may produce these)

| Event type | Meaning |
|---|---|
| `SESSION_START` | Session opened. Payload: `{agent_id, ...metadata}` |
| `SESSION_END` | Session closed cleanly. Payload: `{status: "success"\|"error"}` |
| `LLM_CALL` | LLM invocation. Payload: `{prompt_hash, prompt_count}` |
| `LLM_RESPONSE` | LLM response received. Payload: `{response_hash, response_len}` |
| `TOOL_CALL` | Tool invoked. Payload: `{tool_name_hash, args_hash}` |
| `TOOL_RESULT` | Tool returned a result. Payload: `{result_hash}` |
| `TOOL_ERROR` | Tool raised an error. Payload: `{error_hash}` |
| `LOG_DROP` | Event was intentionally not recorded (e.g. privacy filter). Presence degrades evidence class to `PARTIAL_EVIDENCE`. |

### Server-authority events (only Archeion may produce these)

| Event type | Meaning |
|---|---|
| `CHAIN_SEAL` | Session sealed by the authority server. Contains server public key and signature. |
| `CHAIN_BROKEN` | Reserved. Not yet implemented. |
| `REDACTION` | Reserved. Not yet implemented. |
| `FORENSIC_FREEZE` | Reserved. Not yet implemented. |

**Enforcement:** `SqliteLedger.record()` checks `EventType.is_sdk_authority` before writing any event. Server-authority events submitted through the SDK's recording path are silently dropped. The SDK cannot produce a `CHAIN_SEAL` — only Archeion can.

---

## 4. SQLite Ledger (`sasana/sqlite_ledger.py`)

### Schema

```sql
CREATE TABLE events (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    seq          INTEGER NOT NULL,
    session_id   TEXT    NOT NULL,
    event_type   TEXT    NOT NULL,
    timestamp    TEXT    NOT NULL,
    prev_hash    TEXT    NOT NULL,
    event_hash   TEXT    NOT NULL,
    payload_json TEXT    NOT NULL,
    signature    TEXT,
    raw_json     TEXT    NOT NULL
);
CREATE INDEX idx_session_seq ON events (session_id, seq);
```

`raw_json` stores the complete event JSON exactly as it will appear in the JSONL export. This is the authoritative representation — not reconstructed from the individual columns.

### Durability settings

```sql
PRAGMA journal_mode=WAL;
PRAGMA synchronous=FULL;
```

- **WAL mode**: Writers do not block readers; concurrent reads are possible without locking.
- **synchronous=FULL**: Every commit is flushed to the OS and then to storage. On systems without battery-backed write caches, this means every event write survives a power failure. On systems with write caches, it is as durable as the hardware allows.

### Thread safety

`SqliteLedger` uses a `threading.Lock` around `_write_event()`. The connection is opened with `check_same_thread=False` to allow the lock-protected writes from any thread. One ledger instance per session; one session per ledger.

### Export

`export_jsonl()` queries events in `seq ASC` order and writes one JSON line per event to the output file. The `raw_json` column is used directly — no re-serialisation occurs.

---

## 5. Ed25519 Signing (`sasana/signing.py`)

### Per-session keypair

When signing is enabled, the SDK generates a fresh Ed25519 keypair at the start of each session. The public key is embedded in the `SESSION_START` payload. The private key is held in memory for the duration of the session and discarded afterward.

This means:
- No external key registry is needed to verify signatures
- The verifier is fully self-contained: the public key is in the log itself
- Losing the private key does not prevent verification (only the public key is needed)
- A different session's private key cannot forge signatures for this session

### Signing

```python
def sign_event_hash(private_key: Ed25519PrivateKey, event_hash_hex: str) -> str:
    return base64.b64encode(private_key.sign(event_hash_hex.encode("utf-8"))).decode()
```

The input to Ed25519 signing is the `event_hash` as a UTF-8 encoded hex string (64 bytes). Output is base64-encoded.

### Verification

```python
def verify_signature(public_key_b64: str, event_hash_hex: str, signature_b64: str) -> bool:
    pub = Ed25519PublicKey.from_public_bytes(base64.b64decode(public_key_b64))
    pub.verify(base64.b64decode(signature_b64), event_hash_hex.encode("utf-8"))
    return True  # InvalidSignature raises an exception if it fails
```

### Library

Uses `cryptography` (PyCA, version ≥ 41.0). Ed25519 key generation, signing, and verification are all delegated to this library. The library uses OpenSSL under the hood on most platforms.

---

## 6. Verification Pipeline (`sasana/verifier.py`)

The Python verifier runs 5 sequential checks. Checks 2–5 are skipped if check 1 fails (malformed events produce misleading downstream errors).

### Check 1 — Structural validity

Every event must have all 7 required fields: `seq`, `event_type`, `session_id`, `timestamp`, `payload`, `prev_hash`, `event_hash`.

`event_type` must be one of the 9 allowed values: `SESSION_START`, `SESSION_END`, `LLM_CALL`, `LLM_RESPONSE`, `TOOL_CALL`, `TOOL_RESULT`, `TOOL_ERROR`, `LOG_DROP`, `CHAIN_SEAL`.

`prev_hash` and `event_hash` must each be exactly 64-character lowercase hex strings.

Failure: `COMPROMISED`, evidence `NO_EVIDENCE`.

### Check 2 — Sequence integrity

- All events must share the same `session_id`
- First event must have `seq=1` (partial/sub-range exports are not supported)
- No duplicate `seq` values
- `seq` values must be contiguous with no gaps

Failure: `COMPROMISED`, evidence `NO_EVIDENCE`.

### Check 3 — Hash chain integrity

For each event (sorted by seq):
- Recompute `event_hash` from the event's fields and compare to stored `event_hash`
- Verify that `prev_hash` equals the previous event's `event_hash`
- First event's `prev_hash` must equal GENESIS_HASH

Stops at the first violation — once the chain is broken, all subsequent errors are artifacts of that break, not independent failures.

Failure: `COMPROMISED`, evidence `NO_EVIDENCE`.

### Check 4 — Session completeness

- Exactly one `SESSION_START` event must exist
- `SESSION_START` must be the first event (`seq=1`)
- Session must end with either `SESSION_END` or `CHAIN_SEAL` (or both, in that order)

Also records:
- `has_session_start`, `has_session_end`, `has_chain_seal`
- `log_drop_count`

Failure: `COMPROMISED`, evidence `NO_EVIDENCE`.

### Check 5 — Seal signature

If no `CHAIN_SEAL` event is present, this check passes as a no-op (non-sealed sessions are valid).

If a `CHAIN_SEAL` is present:
- Must have `payload.server_pubkey`
- Must have a `signature` field
- Must have `event_hash`
- `signature` must be a valid Ed25519 signature over `event_hash` using `server_pubkey`

A `CHAIN_SEAL` with an invalid signature is treated as `COMPROMISED` — not merely non-authoritative. An invalid seal is stronger evidence of tampering than no seal at all.

Failure: `COMPROMISED`, evidence `NO_EVIDENCE`.

### Evidence class determination

After all checks pass (status is `INTACT` or `PARTIAL`):

```python
def _determine_evidence_class(events, signatures_valid=False):
    has_seal = any(e["event_type"] == "CHAIN_SEAL" for e in events)
    has_drop = any(e["event_type"] == "LOG_DROP" for e in events)
    if has_drop:
        return PARTIAL_EVIDENCE      # LOG_DROP degrades class even with a seal
    if has_seal:
        return AUTHORITATIVE_EVIDENCE
    if signatures_valid:
        return SIGNED_NON_AUTHORITATIVE_EVIDENCE
    return NON_AUTHORITATIVE_EVIDENCE
```

### Exit codes

| Code | Status |
|---|---|
| 0 | INTACT |
| 1 | COMPROMISED |
| 2 | PARTIAL |
| 3 | ERROR |

### `VerifyResult` fields

| Field | Type | Description |
|---|---|---|
| `status` | string | `INTACT`, `PARTIAL`, `COMPROMISED`, or `ERROR` |
| `evidence_class` | string | Evidence class constant |
| `session_id` | string or None | From first event |
| `event_count` | int | Total events |
| `log_drop_count` | int | Count of `LOG_DROP` events |
| `root_hash` | string or None | `event_hash` of the last event |
| `errors` | list of strings | All error messages |
| `checks` | dict | Per-check result dicts with `status` and `errors` |

---

## 7. Archeion Authority Sealing Server (`archeion/`)

### Purpose

Archeion is the structural mechanism that separates the log-writing authority from the log-sealing authority. The agent process writes the log; a separate server, with its own keypair that the agent never has access to, seals it.

### Key management (`archeion/keys.py`)

The server private key is loaded in this priority order:

1. `ARCHEION_PRIVATE_KEY` environment variable (base64 raw bytes) — for containers and CI
2. `ARCHEION_KEY_FILE` environment variable — path to a key file
3. `~/.archeion/server_key.b64` — default persistent location

If none of the above exist, a new Ed25519 keypair is generated, persisted to `~/.archeion/server_key.b64` with permissions `0600`, and used.

The keypair is loaded once at module import. All requests within the server process use the same keypair.

### Endpoints

**`GET /pubkey`**

Returns the server's Ed25519 public key. Clients can pin this key to independently verify sealed sessions without contacting the server again.

Response:
```json
{
  "pubkey": "<base64 encoded 32-byte Ed25519 public key>",
  "algorithm": "ed25519",
  "encoding": "base64"
}
```

**`POST /seal`**

Request body: session JSONL (content-type `application/x-ndjson`).

Process:
1. Parse JSONL body. Return `400` on malformed JSON or empty body.
2. Check for existing `CHAIN_SEAL`. Return `409` if already sealed.
3. Run the full Python verification pipeline. Return `422` if status is not `INTACT` or `PARTIAL`, or if `SESSION_END` is absent.
4. Build a `CHAIN_SEAL` event:
   ```json
   {
     "seq": <last_seq + 1>,
     "event_type": "CHAIN_SEAL",
     "session_id": "<session_id>",
     "timestamp": "<utc_now>",
     "payload": {
       "session_hash": "<last event_hash>",
       "sealed_by": "archeion",
       "server_pubkey": "<base64 server public key>"
     },
     "prev_hash": "<last event_hash>"
   }
   ```
5. Compute `event_hash` for the seal event.
6. Sign `event_hash` with the server private key; add as `signature` field.
7. Return original events + seal event as JSONL.

**Chain linkage:** The seal event's `prev_hash` equals the last session event's `event_hash`. The `payload.session_hash` also records this value for redundancy. This means the seal is structurally part of the hash chain — it cannot be detached and reattached to a different session without breaking the chain.

### Default port

`8747` — no particular significance; chosen to avoid conflicts with common development ports.

### CLI entry point

`archeion` command (from `pyproject.toml` scripts) calls `archeion.server:run()`, which starts uvicorn on `0.0.0.0:8747`.

---

## 8. Rust Verifier (`sasana-rs/`)

### Purpose

A zero-Python-dependency binary for forensic verification. Runs anywhere Rust can compile to. Produces the same results as the Python verifier for all cases it checks.

### Build

```bash
cd sasana-rs
cargo build --release
./target/release/sasana verify <session.jsonl>
./target/release/sasana verify <session.jsonl> --json
```

### Checks implemented in Rust

The Rust verifier implements 4 checks (structural, sequence, hash chain, session bookends). It does not currently implement the Ed25519 seal signature check (check 5). This is a known gap.

| Check | Python | Rust |
|---|---|---|
| Structural validity | Yes | Yes |
| Sequence integrity | Yes | Yes |
| Hash chain integrity | Yes | Yes |
| Session completeness | Yes | Yes |
| Seal signature | Yes | No |

### JCS implementation in Rust

The Rust JCS implementation is independent of the Python implementation. Both produce identical output for all valid inputs. Key point: object key sorting uses UTF-16 code unit comparison (`encode_utf16().collect::<Vec<u16>>()`), matching the RFC 8785 specification exactly.

### Hash cross-compatibility

`compute_event_hash` in Rust strips `event_hash` and `signature` before hashing, identical to the Python implementation. A session recorded by the Python SDK can be verified by the Rust binary without any conversion.

### Dependencies (Rust)

- `serde` and `serde_json` — JSON parsing
- `sha2` — SHA-256
- `hex` — hex encoding

---

## 9. Compliance Exports (`sasana/compliance/`)

All compliance modules share a common pattern: load a JSONL session file, run the verifier, map results to regulation-specific fields, and write both a JSON and an HTML artifact.

### EU AI Act Article 12 (`eu_ai_act.py`)

Regulation: EU AI Act (Regulation (EU) 2024/1689), Article 12 — "Automatic recording of events throughout the AI system lifetime."

Requirement checks performed:
- `timestamps_on_all_events` — every event has a `timestamp` field
- `input_events_logged` — at least one `LLM_CALL` or `TOOL_CALL` present
- `output_events_logged` — at least one `LLM_RESPONSE` or `TOOL_RESULT` present
- `error_events_logged` — at least one `TOOL_ERROR` present
- `session_lifecycle_logged` — both `SESSION_START` and `SESSION_END` present
- `hash_chain_tamper_evident` — verifier reports `intact`
- `no_log_drops` — no `LOG_DROP` events
- `server_sealed` — `CHAIN_SEAL` present

Compliance (`compliant: true`) requires: timestamps, input logging, output logging, hash chain intact, and session lifecycle. Server sealing is reported separately but not required for the `compliant` flag.

Output: JSON report + HTML report (human-readable, submittable to auditors).

Privacy note included in every report: raw AI inputs/outputs are not stored; only SHA-256 hashes are recorded, satisfying Art. 10.5 data minimisation.

### SOC 2 CC7.2 (`soc2.py`)

Control: CC7.2 — System Monitoring (AICPA 2017 Trust Services Criteria).

Reports: session summary, event type counts, hash chain verification result, attestation statement. Result is `PASS` or `FAIL` based on `verification["intact"]`.

### HIPAA §164.312(b) (`hipaa.py`)

Standard: HIPAA Security Rule §164.312(b) Audit Controls.

Maps each Sasana event type to HIPAA access categories:
- `LLM_CALL`, `LLM_RESPONSE` → `READ`
- `TOOL_CALL`, `TOOL_RESULT` → `EXECUTE`
- `TOOL_ERROR` → `EXECUTE_FAILURE`
- `SESSION_START`, `SESSION_END` → `SYSTEM_ACCESS`
- `LOG_DROP` → `AUDIT_FAILURE`
- `CHAIN_SEAL` → `INTEGRITY_SEAL`

Output: JSON report + HTML report + CSV (for SIEM ingestion).

### SIEM (`siem.py`)

Outputs structured JSON events suitable for ingestion into SIEM systems (Splunk, Elastic, etc.). Batch export with configurable batch size.

---

## 10. Integration Layer (`sasana/integrations/`)

### OpenClaw Skill (`sasana/skill.py` — `SasanaSkill`)

The primary integration path. Implements the OpenClaw `AgentSkill` interface.

Hooks consumed:
- `on_session_start` — opens ledger, writes `SESSION_START`
- `on_session_end` — writes `SESSION_END`, exports JSONL, closes ledger
- `on_llm_call` — writes `LLM_CALL`
- `on_llm_response` — writes `LLM_RESPONSE`
- `on_tool_invoke` — writes `TOOL_CALL`
- `on_tool_result` — writes `TOOL_RESULT`
- `on_tool_error` — writes `TOOL_ERROR`

Each hook receives the OpenClaw event dict. `event_mapper.py` translates OpenClaw-specific field names to Sasana payload structure. One `SqliteLedger` per active session, keyed by `sessionKey`.

Output directory: `~/.openclaw/sasana/` (configurable via `SASANA_OUTPUT_DIR`).

### Passive Observer (`sasana/observer.py` — `OpenClawObserver`)

Zero-modification alternative when OpenClaw cannot be modified to install skills. Connects to OpenClaw's WebSocket broadcast interface and reconstructs session events from the stream.

Limitations vs. SasanaSkill:
- Receives the WebSocket broadcast, which may have less detail than the hook event
- Cannot guarantee capture of all events (network glitches, reconnects)
- Up to 12 reconnect attempts with 5-second delays

`LOG_DROP` events should be inserted when the observer detects it missed events. This is not yet automatically implemented — it requires detecting sequence gaps in the WebSocket stream, which is framework-dependent.

### LangGraph, CrewAI, AutoGPT (`sasana/integrations/`)

Thin wrappers that translate framework-specific callbacks to Sasana's `SqliteLedger` API. Each tries to import the framework at runtime; if the framework is not installed, the integration module loads but does nothing. This means `pip install sasana` works without requiring any specific framework to be installed.

---

## 11. CLI (`sasana_cli.py`)

```
sasana verify <session.jsonl> [--json]     Run 5-check verification
sasana seal   <session.jsonl> [--server URL] [--out FILE]   Submit to Archeion
sasana observe [--ws URL] [--output-dir DIR]   Passive WebSocket observer
sasana version                              Print version
```

`sasana seal` uses `urllib.request` (Python standard library, no extra dependencies) to POST the session JSONL to the Archeion `/seal` endpoint. Default server: `http://localhost:8747`.

Also available as `agentops-verify` (legacy alias for `sasana verify`, registered in `pyproject.toml`).

---

## 12. Package Structure

```
sasana/                     Core SDK
├── __init__.py
├── envelope.py             Event construction and hashing
├── events.py               EventType enum, authority classification
├── jcs.py                  RFC 8785 canonical JSON
├── signing.py              Ed25519 keypair, sign, verify
├── sqlite_ledger.py        Hash-chained SQLite ledger
├── skill.py                OpenClaw AgentSkill
├── observer.py             Passive WebSocket sidecar
├── event_mapper.py         OpenClaw hook/WS → Sasana payload translation
├── _utils.py               content_hash() helper (SHA-256 of arbitrary content)
├── verifier.py             5-check verification engine (single source of truth)
├── integrations/
│   ├── langgraph.py
│   ├── crewai.py
│   └── autogpt.py
└── compliance/
    ├── __init__.py         load_session(), verify_session() helpers
    ├── eu_ai_act.py
    ├── hipaa.py
    ├── soc2.py
    └── siem.py

archeion/                   Authority sealing server
├── __init__.py
├── keys.py                 Persistent Ed25519 server keypair
└── server.py               FastAPI app (POST /seal, GET /pubkey)

sasana-rs/                  Rust verifier
├── Cargo.toml
└── src/main.rs             Zero-dependency verification binary

tests/
├── test_verifier.py        Unit tests for all 5 verification checks
├── test_e2e.py             End-to-end: SDK → Archeion → verify
├── test_compliance.py      Compliance export tests
└── test_integrations.py    Integration wrapper tests

sasana_cli.py               CLI entry point
verify.py                   Standalone verifier script (agentops-verify)
pyproject.toml              Package definition, scripts, dependencies
```

---

## 13. Dependencies

### Runtime (always required)

```
cryptography>=41.0          Ed25519 key generation, signing, verification
```

### Optional

```
# sasana[observer]
websockets>=12.0            WebSocket client for passive observer
pyyaml>=6.0                 Reading ~/.openclaw/config.yml

# sasana[archeion]
fastapi>=0.110              HTTP framework for Archeion server
uvicorn[standard]>=0.27     ASGI server for Archeion
```

### Development

```
pytest>=7.0
ruff>=0.4
httpx>=0.27                 Required by FastAPI TestClient
fastapi>=0.110
```

---

## 14. Test Coverage

117 tests as of v1.0.0.

| Module | Tests | Coverage notes |
|---|---|---|
| `test_verifier.py` | Core verification cases | 5-check pipeline, evidence classes, CHAIN_SEAL signature verification, tamper detection |
| `test_e2e.py` | 13 tests | SDK → Archeion → verify full flow; tamper detection; double-seal rejection; broken chain rejection |
| `test_compliance.py` | Compliance export generation | EU AI Act, SOC 2, HIPAA, SIEM |
| `test_integrations.py` | Integration wrappers | LangGraph, CrewAI, AutoGPT |

CI: GitHub Actions, Python 3.10 and 3.12, ruff lint + format check.

---

## 15. Known Gaps and Honest Limitations

**Rust verifier does not check seal signature.** The Rust binary performs 4 checks. Check 5 (Ed25519 seal signature verification) is not implemented in Rust. A sealed session will be reported as `INTACT` / `AUTHORITATIVE_EVIDENCE` by the Rust verifier based on the presence of a `CHAIN_SEAL` event, without verifying that the signature is valid. For full forensic verification of sealed sessions, use the Python verifier.

**Observer does not auto-detect dropped events.** The passive WebSocket observer reconnects on disconnect, but it does not currently insert `LOG_DROP` events when it detects a gap in the event stream. This would require framework-specific sequence tracking and is not implemented.

**No post-quantum signatures.** SHA-256 and Ed25519 are both pre-quantum algorithms. Ed25519's security assumption (discrete logarithm on Curve25519) is broken by Grover's and Shor's algorithms on a sufficiently capable quantum computer. Post-quantum migration is a known future concern, not an immediate operational risk.

**Per-session signing is SDK-controlled.** When SDK signing is enabled, the agent process generates and holds the per-session keypair. A fully compromised agent process could forge signed events for that session. `SIGNED_NON_AUTHORITATIVE_EVIDENCE` is meaningfully harder to forge than an unsigned log, but it is not equivalent to `AUTHORITATIVE_EVIDENCE`.

**Single-session JSONL only.** The verifier operates on one session file at a time. Cross-session consistency checks (e.g. detecting that a session was split across multiple files or that sessions overlap in time) are not implemented.

**SQLite is local disk.** The ledger does not replicate to a remote store. If the local disk is destroyed before export, the session is lost. For high-stakes use cases, the JSONL export should be persisted to a separate storage system after session close.
