# Legacy golden fixtures

Session logs written by **published** Sasana releases, using those releases' own code. They are the
regression suite for "existing evidence keeps verifying": every file here must verify `INTACT`
under the current Python verifier and the Rust verifier, and the two must agree
(`tests/test_canonicalization.py`, and `cargo test` in `sasana-rs/`).

**Never regenerate these to make a test pass.** `manifest.json` records each file's SHA-256 and a test
fails if one changes. A fixture that stops verifying means a release would invalidate real users'
logs: fix the verifier, not the fixture.

## Where they came from

| Release | Source used | PyPI wheel (SHA-256) | Uploaded |
|---|---|---|---|
| 1.0.0 | git commit `86645bd` (there is no `v1.0.0` tag; this is the last commit before the upload) | `3e2c55c3a101ec81e4ab8d68c846a537eab0a014d382389843ea9fb1c581d0fb` | 2026-07-06T10:14:40Z |
| 1.1.0 | git tag `v1.1.0` (`0c94b6f`) | `51d0aa6a5dfea0515600f3ed22ceb97aa1bf351187c3a92a79a60b00519377a2` | 2026-07-20T14:27:38Z |

The generating trees were checked against the real PyPI wheels before use: `sasana/jcs.py`,
`envelope.py`, `verifier.py`, `sqlite_ledger.py`, `signing.py`, `archeion/server.py` and
`archeion/keys.py` have identical SHA-256 in the wheel and in the git tree, for both releases. (They
are also identical between 1.0.0 and 1.1.0, so the two sets of fixtures differ only in their ids,
timestamps and keys.)

## How they were generated

`git archive` is used instead of a git worktree so the repository's own `.git` is not modified.

```bash
mkdir -p /tmp/rel/v1.0.0 /tmp/rel/v1.1.0
git archive 86645bd | tar -x -C /tmp/rel/v1.0.0
git archive v1.1.0  | tar -x -C /tmp/rel/v1.1.0

cd /tmp   # NOT the repo root: the release's sasana/ must be the one imported
python3.11 <repo>/tests/fixtures/legacy/generate_legacy_fixtures.py /tmp/rel/v1.0.0 v1.0.0 <out-dir>
python3.11 <repo>/tests/fixtures/legacy/generate_legacy_fixtures.py /tmp/rel/v1.1.0 v1.1.0 <out-dir>
```

The script imports that release's `sasana` and `archeion` (it asserts the import path), so the bytes on
disk are exactly what the release wrote. Throwaway keys only: Archeion's `ARCHEION_KEY_FILE` points to a
temp directory and its public key is recorded in `manifest.json`; no TSA is contacted (the timestamped
fixture uses the offline test TSA in `tests/tsa_fixture.py`).

## Files (per release `vX`)

| File | What it is |
|---|---|
| `vX_unsealed.jsonl` | plain hash chain |
| `vX_signed.jsonl` | per-event Ed25519 signatures (session key in `SESSION_START`) |
| `vX_sealed.jsonl` | sealed by that release's Archeion; verifies `AUTHORITATIVE_EVIDENCE` only with `archeion_pubkey` from the manifest |
| `vX_timestamped.jsonl` | `SESSION_START` carries an RFC 3161 token (verifies as `IMPRINT_MATCH`) |

## What is in the payloads, and why

Values that distinguish canonicalizations or that real logs contain: whole-number floats (`0.0`,
`100.0`, `1200.0`), negative zero, exponent-form floats (`1e-05`, `1.5e-07`, `1e16`, `1e21`),
`0.1`/`1234.5678`, integers beyond 2^53, 2^63 and up to u64 max, unicode (Latin, CJK, Hebrew, emoji),
escapes, and nested objects with unsorted keys. The float-formatting change that motivated this suite
broke exactly such values; a test log without them would not have caught it.
