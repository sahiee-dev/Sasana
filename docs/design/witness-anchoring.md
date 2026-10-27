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

**Non-goals.** Detecting an operator who disables or bypasses the publication hook *before* the session and
fabricates from the start (the "lying agent / compromised recorder" class, out of scope). Note the contrast with
a **post-hoc** rewriter, who decides only after a dispute exists: that attacker is the target, and §2.5 explains why
publishing only at seal time does **not** stop them. Proving events are true.
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

## 2.5 Publication schedule: publish during the session, not only at the seal

**The flaw in "publish at seal".** If the head is published only when the session is sealed, then "the operator
never publishes the honest head" is not an edge case, it is the default attack. The operator simply never seals
(or never publishes) the honest session, waits, rewrites the log after the dispute starts, then seals and
publishes **only the rewrite**. The witness then faithfully records the forgery as the first and only entry, with
nothing to conflict with. A seal-time-only witness protects sessions the operator chose to witness honestly,
which is exactly the set the operator does not need to attack.

**Fix: automatic, early, repeated publication.** Because every event's `event_hash` commits to the whole prefix
(`prev_hash` chain), publishing the head at sequence `k` pins events `1..k`. So publish:

1. **At session open, automatically:** the `SESSION_START` head (`seq=1`). The hook exists: `open_session()`
   already hashes `SESSION_START` and calls the TSA at exactly this point
   (`sqlite_ledger.py::_try_anchor_rfc3161`); the same hook would also submit to the witness. (Which hash: the
   final `SESSION_START` `event_hash`, i.e. the one that includes the TSA token, because that is the one the
   chain commits to. **Decision needed**.)
2. **Checkpoints every `N` events or `T` seconds, whichever comes first:** `(session_id_hash, seq, head)`.
3. **At close:** the final head (the seal's `session_hash`) and `seq`.

**Conflict rule (proposal).** Two witnessed entries with the same `session_id_hash` and the same `seq` but
different heads are a conflict. A rewrite of any event `j <= k` changes the head at every `seq >= j`, so it
conflicts with an already-witnessed checkpoint at `seq >= j`.

**What this buys: the undetected-rewrite window shrinks** from "any time before the dispute" to "the events after
the last witnessed checkpoint", at most one checkpoint interval (`N` events / `T` seconds), and zero once the
final head is witnessed. A rewrite that touches only the unwitnessed tail is still undetected; that tail is the
price of the interval.

**What it does not buy.** An operator who disables the hook ahead of time, or who chooses to run the agent
outside the instrumented path, produces no entries to conflict with. That is a premeditated, pre-session
decision (the T3 class) rather than a post-hoc rewrite. Publishing schedules must therefore be reported by the
verifier as *coverage*: which `seq` values were witnessed, and when. A session with only a final head, or none,
is **not** "witnessed" in this sense and must say so.

**Cost consequence.** This turns one log entry per session into roughly `1 + events/N + duration/T + 1` entries
per session. At an agent producing thousands of events that is hundreds of entries, which is where per-entry
costs, rate limits and the public log's acceptable-use rules (**VERIFY**, §3) start to bite, and why §5's
batching earns its place rather than being a mere optimisation. Batching widens the window by the batch
interval (a head is only as early as the batch that carries it), so `N`, `T` and the batch interval are one
trade-off: window length against entries per session.

## 3. Option 1: publish `(session_id_hash, H)` to a public transparency log (e.g. Sigstore Rekor)

**Flow.** At session open, at each checkpoint (§2.5) and at close, submit an entry binding `session_id_hash`, `seq` and the head; store the
returned inclusion proofs / signed checkpoints beside the log. (Publishing only at seal time is **not** sufficient, §2.5.) Verifier: validate the proof against a pinned
log key; (online or via a monitor snapshot) query for other entries with the same `session_id_hash`.

**Detects.** A rewrite after the honest head was logged: the rewrite either has no earlier entry or
creates a conflicting later one, with log-assigned ordering the operator does not control.

**Does not detect.** A rewrite confined to the events after the last witnessed checkpoint; an operator who disabled the hook before the session (premeditated); a rewrite of any session that was never witnessed. (With seal-time-only publication, "operator who never logs the honest head" would be the default attack, which is why §2.5 publishes early.) Also: a conflict identifies an anomaly, not
the liar.

**Privacy.** Hashes only, but the log reveals that *some* session with that hash existed at that time, and
how many sessions an operator seals. Operators may object; a private log run by the operator defeats the
purpose; a regulator- or consortium-run log is a possible middle path.

**Offline verification.** Inclusion proof and checkpoint signature: yes, given the log's public key and
that the proof embeds enough to verify without a live query (**VERIFY** for Rekor v1 vs v2 proof/checkpoint
formats). Conflict detection: needs an online query or a recent monitor snapshot; an offline verifier can
say "witnessed at `T_w`" but not "no conflicting entry exists."

**Cost.** One network call per witnessed head: at least two per session (open, close) plus one per checkpoint interval (§2.5), i.e. many per long session. The public instance has a stated 99.5% SLO (checked); rate limits,
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
to an external log), not an independent defence. With the in-session checkpoints of §2.5 it stops being optional in
practice: many heads per session is exactly the volume batching exists for. A batch that publishes its leaves
(hashed) keeps conflict detection; a bare root does not (above). The batch interval adds to the undetected window.

## 6. Comparison

| | Opt 1: per-session to transparency log | Opt 2: counterparty cosign | Opt 3: Merkle roots |
|---|---|---|---|
| Needs operator-independent store | yes (the log) | yes (the counterparty) | yes (where roots go) |
| Detects post-hoc rewrite | yes, if honest head was logged | yes, if counterparty kept it | only if leaves are published |
| Misses non-publication decided before the session | yes | yes | yes |
| Undetected-rewrite window | last checkpoint interval (§2.5) | since last cosign | batch interval + checkpoint interval |
| Entries per session | many (§2.5) | one per cosign | amortised across sessions |
| Hashes only | yes | yes | yes |
| Offline verify of "was witnessed" | proof bundle (**VERIFY**) | yes | proof bundle |
| Offline verify of "no conflict" | no | no | no |
| Per-seal cost | one call | one exchange | amortised |
| Main dependency risk | log availability and shard turn-over | counterparty | publication target + new Merkle code |

## 7. Recommendation

0. **Publish during the session, not only at the seal (§2.5).** Without it, Options 1 and 3 witness only what the operator chooses to
   witness, and a post-hoc rewriter simply never witnesses the honest version. This is a precondition for everything below.
1. **Design to Option 1, log-agnostic.** Define a small `Witness` interface and a proof-bundle sidecar;
   treat Rekor as the first candidate implementation, not a hard dependency, because its fit for
   non-Sigstore entries and key types is unverified (§3). It is the only option that gives an
   operator-independent, publicly ordered first-seen record for every witnessed session with no per-deployment
   relationship, which is exactly what A8 needs.
2. **Offer Option 2 as an overlay** where an identifiable counterparty exists (the operator-versus-regulator
   or operator-versus-customer dispute is the motivating case). It reuses the receipt-registry idea and needs
   no public log.
3. **Use Option 3 as the batching layer for Option 1.** In-session checkpoints produce many entries per session, so batching (publishing hashed leaves, not bare roots) is part of the design, with the batch interval counted in the window.
4. **Be exact in the product claims.** A witness turns A8 from "undetectable" into "detectable for the part of a session that was witnessed before the rewrite" (all of it except the tail after the last checkpoint). It does not make a log "unforgeable", and `WITNESS_ABSENT` must be
   shown as no claim, never as a pass.

## 8. Open questions

- Can Rekor (v1 or v2) accept Sasana's entries and key type, and can entries be found by an attribute such as
  `session_id_hash`? (**VERIFY**, determines Option 1's feasibility on Rekor specifically.)
- Proof format and long-term verifiability across log shards. (**VERIFY**)
- Who submits: the SDK in the agent process (open, checkpoints, close), not Archeion at seal time. Submitting from
  the agent side, early and automatically, is what removes the operator's choice of *whether* to witness.
- Choice of `N` and `T`, and what the SDK does when the witness is unreachable (buffer and flush; a late-flushed head has a
  later witness time, so the verifier must report the time each head was actually witnessed, not when it was produced).
- Which `SESSION_START` hash is published (§2.5) and how coverage is reported (`seq` values and witness times).
- Session-id privacy and uniqueness requirements for `session_id_hash`.
- Failure policy when the witness is unreachable at seal time.
- Interaction with legacy (1.x) logs: they can be witnessed retroactively but with a later `T_w`, which says
  nothing about their original state.

## 9. Empirical support

A demonstration of A8 and of A8+E (A8 plus an edit of the external effect) against Sasana 2.0.2 is in [sasana-kalpang-witness](https://github.com/sahiee-dev/sasana-kalpang-witness). It is one run per cell, with one person playing every role, and is not a proof.

In the A8+E cell, an operator who edited the GitHub comment back to the authorized body and had the real Archeion seal a rewritten record obtained `INTACT` / `AUTHORITATIVE_EVIDENCE` under a pinned key, and neither a fresh REST read nor a sealed-versus-fresh comparator flagged it. Only GitHub's edit history showed the edit; the comment's author could delete the divergent revision's content, but the edit and a deletion marker remained (observed 2026-10-21, GitHub behaviour may change, **VERIFY**).
