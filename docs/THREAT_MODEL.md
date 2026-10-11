# Sasana threat model

What an adversary can do to a recorded session, what `sasana verify` reports, and what Sasana does
**not** protect against. Written in plain words on purpose: where something is not defended, it says so.

> **Against the operator, Sasana 2.x provides no rewrite protection unless access to Archeion's
> `POST /seal` is controlled by a party independent of the operator.** The operator is the party most
> likely to want a log changed. If they can reach `/seal`, they can have a rewritten session sealed by the
> genuine Archeion key, and with that key pinned the rewrite verifies as `AUTHORITATIVE_EVIDENCE`.
> Detecting that needs an external witness the operator does not control; see
> [`design/witness-anchoring.md`](design/witness-anchoring.md) (design only, not implemented).

## What a seal shows

A `CHAIN_SEAL` shows that **a chain head was presented to Archeion, at the time recorded in the seal**,
and was signed by Archeion's key. It does **not** show that the head is the original, that it is the
first head Archeion was shown for that `session_id`, or that the recorded events are true. Archeion
authenticates no callers and keeps no record of what it has sealed (see `DEPLOYMENT.md`, "Authentication
model"), so it will seal any consistent chain it is sent.

## Adversaries

"Detected" means `sasana verify` returns `COMPROMISED` (or, where stated, a weaker evidence class).
Tests: A1, A3, A4, A5 in `tests/test_verifier.py`; A5-A7 in the tamper matrix
(`tests/test_tamper_matrix.py`, both canonicalization formats, Python and Rust); **A2 and A8 in
`tests/test_threat_model.py`**, which assert the documented limitation against the real Archeion app.

| ID | Attack | Result | Condition |
|---|---|---|---|
| A1 | Insert an event | **Detected** | Chain is not rebuilt (rebuilding is A5) |
| A2 | Tamper with a session on its way to the sealer | **Not defended** | Archeion re-verifies the chain it receives but seals any consistent chain; protect the path from agent to Archeion |
| A3 | Delete an event | **Detected** | `seq` gap and broken `prev_hash`. Chain not rebuilt (A5). There is no Merkle tree; the chain tip is the root |
| A4 | Reorder events | **Detected** | `seq` and `prev_hash` links. Chain not rebuilt (A5) |
| A5 | Rewrite the whole file and rebuild the hash chain | **Not defended** without a seal | An unsealed log verifies as `INTACT` / `NON_AUTHORITATIVE_EVIDENCE`. RFC 3161 does not help: a rewrite just gets a new token with a new time |
| A6 | Rewrite, then re-seal under the attacker's own key | **Detected only with `--trust-key`** | Unpinned it verifies as `INTACT` / `SELF_SEALED_EVIDENCE` with a warning, never `AUTHORITATIVE_EVIDENCE` |
| A7 | Rewrite, then strip the seal | **Detected with `--trust-key` or `--require-seal`** | With neither flag: `INTACT` / `NON_AUTHORITATIVE_EVIDENCE` and a warning |
| **A8** | **Rewrite a session, then have the genuine Archeion seal the rewrite** | **Not defended** | Needs only network access to `POST /seal`. With the Archeion key pinned the rewrite verifies as `INTACT` / `AUTHORITATIVE_EVIDENCE`. Reproduced against the real server (same `session_id`, different chain head, both sealed with the same key) |

### A8 in detail

1. The operator's agent records a session; it is sealed by Archeion. (Or it is never sealed at all.)
2. Later the operator edits the stored log, re-chains it, and submits it to `POST /seal`.
3. Archeion verifies the new chain is internally consistent and seals it. Nothing in Archeion records that
   it already sealed a different head for that `session_id`.
4. `sasana verify <file> --trust-key <archeion-pubkey>` reports `INTACT` / `AUTHORITATIVE_EVIDENCE`.

What helps, and what does not:

- **Helps (operational):** keep Archeion network-isolated from the people being audited; seal at session
  end, not later; retain a copy of the sealed log somewhere the operator cannot edit.
- **Does not help:** an Archeion-side registry of sealed heads (Archeion is run by the operator, so the
  registry is theirs to reset); comparing the seal timestamp with `SESSION_END` (an operator who rewrites
  right after the session passes, and no threshold is sound across session lengths).
- **Would help:** publishing each seal's chain head to an append-only log the operator does not control, so
  a rewrite produces a conflicting second entry. See `design/witness-anchoring.md`.

## Out of scope (not defended, by design)

- **A lying agent.** If the agent records a false event, the chain and any seal faithfully preserve it.
- **Compromise of the agent process before the event is recorded**, or of the machine recording it.
- **Compromise of Archeion's signing key.** Anyone holding it can mint seals.
- **Deleting the log.** Sasana detects alteration, not loss. Keep copies elsewhere.
- **Time.** `sasana verify` checks only that an RFC 3161 token's imprint matches (`IMPRINT_MATCH`); the
  TSA's signature and the claimed time are not verified (`sasana.rfc3161.verify_timestamp_strict` does, but
  `sasana verify` does not call it). An Archeion seal carries the sealing server's own clock reading.

## Assumptions the guarantees rest on

- SHA-256 collision/preimage resistance and Ed25519 unforgeability.
- The verifier is given Archeion's public key out-of-band (recorded at deployment; not taken from the file
  being verified) wherever the table says `--trust-key`.
- For anything stronger than "edits to events are detectable" **against the operator**: Archeion is
  operated, or at least network-gated, by a party independent of the operator.
