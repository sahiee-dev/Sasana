# Design: witness anchoring (detecting rewrite-and-reseal, A8)

**Status: design only. Nothing here is implemented, and no release should claim it.**
Target: a possible 2.1. Read [`../THREAT_MODEL.md`](../THREAT_MODEL.md) first.

**Verification convention.** A statement about an external system (Rekor, Sigstore, etc.) is marked
**VERIFY** unless it was checked against current documentation. Checked on 2026-10-10:
[docs.sigstore.dev/logging/overview](https://docs.sigstore.dev/logging/overview/) and
[github.com/sigstore/rekor-tiles](https://github.com/sigstore/rekor-tiles). Those pages state that Rekor is a
transparency log, the public instance is `rekor.sigstore.dev` with a 99.5% availability SLO, Rekor v2 is a
tile-backed redesign, and the public v2 URL changes roughly every six months as the log is sharded
(clients are told not to hard-code it). Everything else about Rekor below is **VERIFY**.

## 1. Goal and non-goals

**Goal.** Detect an **operator rewrite-and-reseal** (threat **A8**): the operator edits a stored session,
re-chains it, and has the genuine Archeion seal the rewrite, so that with Archeion's key pinned it verifies
as `AUTHORITATIVE_EVIDENCE`. The only thing a seal shows today is "this chain head was presented to
Archeion at time T"; it cannot show "this is the first head for this session."

**Why Archeion cannot fix this itself.** Archeion is run by the operator. Anything it stores (a registry of
sealed heads, a timestamp comparison) can be reset or fabricated by the party we are trying to constrain. A
verifier-side "seal is much later than `SESSION_END`" warning is evadable by rewriting immediately and has
no sound threshold across session lengths. Any fix must put the first-seen record **outside the operator's
control**.

**Non-goals.** Detecting a premeditated operator who never lets the honest head out (they can fabricate from
the start; that is the "lying agent / compromised recorder" class, out of scope). Proving events are true.
Replacing Archeion. Hiding that a session exists from the witness.

## 2. What a witness has to provide

For a session `S` with sealed chain head `H` (the `session_hash` of its `CHAIN_SEAL`):

1. **First-seen ordering the operator cannot rewrite:** a record that `H` was presented for `S` at witness
   time `T_w`, in a store the operator cannot edit or delete from.
2. **Conflict visibility:** a rewrite `H' != H` for the same `S` either has no record before `T_w'` or
   produces a **second, later** record that anyone can see next to the first.
3. **Hashes only:** publish `session_id_hash = SHA-256("sasana-witness-v1" || session_id)` and `H`, never
   content. (Session ids are random UUIDs today; a guessable id would be linkable. **Decision needed**.)
4. **Offline-checkable evidence for the honest case:** a proof bundle stored next to the log (a sidecar,
   because `CHAIN_SEAL` must stay the final event) so a verifier can check "`H` was witnessed at `T_w`"
   without the operator's cooperation.

New verifier outcomes (proposal, not final): `WITNESSED` (inclusion proof valid, no conflicting earlier
entry found), `WITNESS_CONFLICT` (another head for the same `session_id_hash`; verdict `COMPROMISED`, with
both entries shown), `WITNESS_ABSENT` (no claim made; **must not** be reported as safe). An optional
`--require-witness` flag would make absence a failure. A conflict means *someone presented two heads*; it
does not say which is genuine, only that an earlier independent record exists.

## 3. Option 1: publish `(session_id_hash, H)` to a public transparency log (e.g. Sigstore Rekor)

**Flow.** At seal time (agent side or Archeion) submit an entry binding `session_id_hash` and `H`; store the
returned inclusion proof / signed checkpoint beside the log. Verifier: validate the proof against a pinned
log key; (online or via a monitor snapshot) query for other entries with the same `session_id_hash`.

**Detects.** A rewrite after the honest head was logged: the rewrite either has no earlier entry or
creates a conflicting later one, with log-assigned ordering the operator does not control.

**Does not detect.** An operator who never logs the honest head (premeditated); an operator who logs only
the rewrite; a rewrite of any session that was never witnessed. Also: a conflict identifies an anomaly, not
the liar.

**Privacy.** Hashes only, but the log reveals that *some* session with that hash existed at that time, and
how many sessions an operator seals. Operators may object; a private log run by the operator defeats the
purpose; a regulator- or consortium-run log is a possible middle path.

**Offline verification.** Inclusion proof and checkpoint signature: yes, given the log's public key and
that the proof embeds enough to verify without a live query (**VERIFY** for Rekor v1 vs v2 proof/checkpoint
formats). Conflict detection: needs an online query or a recent monitor snapshot; an offline verifier can
say "witnessed at `T_w`" but not "no conflicting entry exists."

**Cost.** One network call per seal. The public instance has a stated 99.5% SLO (checked); rate limits,
acceptable use for non-Sigstore entries, and entry size limits: **VERIFY**. Policy needed for seal-time
failure (fail closed vs seal without a witness and mark `WITNESS_ABSENT`).

**Dependency risk.** Log availability and long-term proof validity. The public Rekor v2 URL changes about
every six months as the log shards and the old instance is turned down (checked), so a stored proof must
carry the log identity and checkpoint and must remain verifiable after the instance is retired (**VERIFY**
how clients verify old shards). Fitting Sasana's data into Rekor: entry types, whether an arbitrary
`(hash, signature, key)` is accepted, whether Archeion's raw Ed25519 key and its signature over the seal
`event_hash` (a hex string, not an artifact digest) can be used as-is or a separate identity/key is needed
(keyless signing would attach an OIDC identity), and whether entries can be looked up by attribute: all
**VERIFY**. If Rekor's model does not fit, the same design works with any append-only log offering inclusion
proofs and consistency checks.

## 4. Option 2: counterparty or regulator co-signature (witness cosigning)

**Flow.** At session close Archeion (or the agent side) sends `(session_id_hash, H, seal)` to a counterparty
who keeps a copy and returns a signature over it. The counterparty's signature is stored in a sidecar.
This is the shape of the existing commitment `registry` (the counterparty's receipt log) in
`verify-commitment`; the machinery to reuse is partly there.

**Detects.** A rewrite presented later against a counterparty who holds the original head: the counterparty
can show what it received and when.

**Does not detect.** Anything when there is no counterparty, when the counterparty colludes or loses its
records, or when the operator simply never sends the honest head.

**Privacy.** The counterparty sees only hashes unless the deployment chooses otherwise. Strongest fit for
the dispute setting where the adverse party is known in advance.

**Offline verification.** Yes: a cosignature verifies offline against a pinned counterparty key. Conflict
detection is the counterparty producing its record, i.e. interactive but cheap.

**Cost / dependency.** Operational and contractual rather than technical; scales to a few counterparties,
not to every deployment. Depends on the counterparty's availability and key custody.

## 5. Option 3: periodic publication of a Merkle root of seal heads

**Flow.** Archeion batches the heads it sealed in an epoch (say hourly or daily), builds a Merkle tree,
and publishes the root, plus a link to the previous root, to a third-party append-only place (a git
repository, a transparency log, a timestamping service). Each log gets an inclusion proof for `H` in
epoch `E`.

**Detects.** That `H` existed by the end of epoch `E`. Conflict detection **only if the leaves (hashed
`session_id_hash` and `H`) are published too**; a bare root cannot show that a different head for the same
session exists. Note the repository has no Merkle tree today (`root_hash` is the last event's hash).

**Does not detect.** Everything Option 1 misses; and a root published to a place the operator controls (their
own repository) adds nothing against A8.

**Privacy.** Better than per-session publication: only batch roots (and optionally hashed leaves) appear;
reveals counts per epoch.

**Offline verification.** Inclusion proof against a published root: yes. **Cost.** Cheapest per seal;
coarse time granularity (the epoch). **Dependency.** Wherever roots are published, plus a Merkle
implementation and proof format Sasana must build and maintain.

Option 3 is best understood as a **cost and privacy optimisation of Option 1** (batching what is submitted
to an external log), not an independent defence.

## 6. Comparison

| | Opt 1: per-session to transparency log | Opt 2: counterparty cosign | Opt 3: Merkle roots |
|---|---|---|---|
| Needs operator-independent store | yes (the log) | yes (the counterparty) | yes (where roots go) |
| Detects post-hoc rewrite | yes, if honest head was logged | yes, if counterparty kept it | only if leaves are published |
| Misses premeditated non-publication | yes | yes | yes |
| Hashes only | yes | yes | yes |
| Offline verify of "was witnessed" | proof bundle (**VERIFY**) | yes | proof bundle |
| Offline verify of "no conflict" | no | no | no |
| Per-seal cost | one call | one exchange | amortised |
| Main dependency risk | log availability and shard turn-over | counterparty | publication target + new Merkle code |

## 7. Recommendation

1. **Design to Option 1, log-agnostic.** Define a small `Witness` interface and a proof-bundle sidecar;
   treat Rekor as the first candidate implementation, not a hard dependency, because its fit for
   non-Sigstore entries and key types is unverified (§3). It is the only option that gives an
   operator-independent, publicly ordered first-seen record for every witnessed session with no per-deployment
   relationship, which is exactly what A8 needs.
2. **Offer Option 2 as an overlay** where an identifiable counterparty exists (the operator-versus-regulator
   or operator-versus-customer dispute is the motivating case). It reuses the receipt-registry idea and needs
   no public log.
3. **Use Option 3 only as batching** if per-session publication proves too revealing or too costly.
4. **Be exact in the product claims.** A witness turns A8 from "undetectable" into "detectable if the honest
   head was witnessed before the rewrite". It does not make a log "unforgeable", and `WITNESS_ABSENT` must be
   shown as no claim, never as a pass.

## 8. Open questions

- Can Rekor (v1 or v2) accept Sasana's entries and key type, and can entries be found by an attribute such as
  `session_id_hash`? (**VERIFY**, determines Option 1's feasibility on Rekor specifically.)
- Proof format and long-term verifiability across log shards. (**VERIFY**)
- Who submits: the agent side at `SESSION_END`, or Archeion at seal time? Submitting from the agent side
  before sealing avoids trusting Archeion for the first-seen record.
- Session-id privacy and uniqueness requirements for `session_id_hash`.
- Failure policy when the witness is unreachable at seal time.
- Interaction with legacy (1.x) logs: they can be witnessed retroactively but with a later `T_w`, which says
  nothing about their original state.
