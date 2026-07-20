---
title: Your tamper-evident log can still be backdated. Here's what closes that.
published: false
description: A demonstration of how operator-controlled timestamps fail Article 12 compliance, and what RFC 3161 anchoring actually proves.
tags: ai, security, compliance, euaiact
cover_image:
---

Most audit trail implementations record timestamps as fields in the log. The agent sets them, or the framework does. Either way, the party controlling the log also controls the clock.

This matters under EU AI Act Article 12. Article 12 requires high-risk AI systems to maintain logs enabling verification of system operation. A log where the operator controls the timestamps does not enable independent verification of anything. It enables the operator to construct a plausible-looking history after the fact.

Here is the demonstration.

---

## A 2020 session passes a 2026 audit

We ran Sasana's own verifier against a session with every timestamp set to January 1, 2020:

```
Status: INTACT
Evidence class: NON_AUTHORITATIVE_EVIDENCE
Hash chain: PASS
Structural integrity: PASS
Completeness: PASS
Errors: []

Timestamps:
  SESSION_START  2020-01-01T00:00:00.000000Z
  LLM_CALL       2020-01-01T00:00:00.000000Z
  SESSION_END    2020-01-01T00:00:00.000000Z
```

INTACT. No errors. The session is internally consistent. The hash chain links every event to the next. The problem is that the entire chain, including those timestamps, was written today, not in 2020.

The verifier correctly returns `NON_AUTHORITATIVE_EVIDENCE`. That classification is load-bearing. A regulator asking "when did this session run" cannot answer that question from this record. They can verify the log was not modified after it was written. They cannot verify when "after it was written" actually was.

---

## Operator-attested vs independently-attested

Every log where the recording system and the system being recorded share the same authority boundary is operator-attested. The operator controls what timestamps go in. They can also discard and re-create the log before anyone looks at it, and the hash chain of the replacement will be just as valid as the original.

The hash chain proves internal consistency. It does not prove when that consistent record was created.

Independently-attested requires an external party, one the operator cannot impersonate, to sign: "this specific hash existed at this specific UTC time." That statement is verifiable without trusting the operator at all.

---

## RFC 3161

RFC 3161 is the IETF standard for trusted timestamps. A Timestamp Authority (TSA) receives a hash, not the data itself, only its SHA-256 digest, and returns a signed token containing that hash and the current time. The token is verifiable against the TSA's public certificate.

The operator cannot forge this after the fact. Producing a valid token for a different time requires either finding a SHA-256 collision or obtaining the TSA's private key.

Freetsa (`freetsa.org`) is a public TSA based in Wuerzburg, Germany. No account required. The endpoint is `https://freetsa.org/tsr`. You POST a DER-encoded timestamp request and receive a DER-encoded response. The response from the live run for this article:

```
Status: Granted.
Hash Algorithm: sha256
TSA: /O=Free TSA/OU=TSA/CN=www.freetsa.org
Time stamp: Jun 18 15:21:55 2026 GMT
```

The TSA is independent of the operator. It has no relationship to the session being timestamped. It received a 32-byte hash and returned a signed statement about when that hash arrived. The operator cannot produce an equivalent statement for a different time, because they do not control Freetsa's signing key.

---

## How the implementation works

There is a design constraint: the TSA must receive a hash, but the token must also be committed into the hash chain, otherwise substituting a different token later is trivial.

The solution is a two-pass write. On `open_session()`, SESSION_START is written without a token. That event's hash is submitted to the TSA. When the token returns, it is embedded in SESSION_START's payload, and `event_hash` is recomputed over the full payload, now including the token.

From the fresh run:

```
SESSION_START event_hash WITHOUT rfc3161_token:
  ff4be53f333aa85e7491961e0d944093e7a3ef896a399d11f98967d05bb5c34e

SESSION_START event_hash WITH rfc3161_token:
  db37c1d4ab178e14018565bbfb5f65d0eadfe3ca17260d3774833e9793e572ea

Hashes differ: True
SESSION_END.prev_hash chains to WITH-token hash: True
Token size: 4633 bytes
```

The hash `ff4be53f...` is exactly what the TSA received. Confirmed by parsing the MessageImprint field out of the returned token with `openssl ts -reply -text`:

```
Message data:
    0000 - ff 4b e5 3f 33 3a a8 5e-74 91 96 1e 0d 94 40 93
    0010 - e7 a3 ef 89 6a 39 9d 11-f9 89 67 d0 5b b5 c3 4e
```

That reconstructs to `ff4be53f333aa85e7491961e0d944093e7a3ef896a399d11f98967d05bb5c34e`. Byte-for-byte identical.

The rest of the session chains from `db37c1d4...`. Swapping the token changes that hash, which breaks every subsequent `prev_hash` link. You cannot substitute the token without breaking the chain. The TSA's statement was produced by an external party and is bound into the record. The operator did not produce it and cannot retroactively produce a different one with a different time.

Network failures are handled fail-open. If the TSA is unreachable, the session records without a token, and the verifier marks the timestamp check SKIPPED rather than failing the session.

---

## What in-process verification does and does not check

The `sasana_cli verify` command checks that the token's MessageImprint matches the pre-token hash. It does not verify the TSA's signature chain. A token with a valid hash but a forged TSA signature would pass that check.

The full verification path requires `openssl ts -verify`:

```bash
$ DIGEST=$(xxd -p sasana_pre_token_hash.bin | tr -d '\n')
$ openssl ts -verify \
    -in sasana_fresh_token.tsr \
    -digest "$DIGEST" \
    -CAfile freetsa_ca.pem \
    -untrusted freetsa_tsa.crt

Verification: OK
```

`Verification: OK` means the TSA's certificate chain is valid, the MessageImprint matches the expected hash, and the token is genuine. The `.tsr` file embedded in SESSION_START is sufficient input. No Sasana tooling is involved at this stage, only standard OpenSSL against Freetsa's published root certificate.

---

## Article 12

Article 12 requires that logs enable verification of system functioning. The question regulators will ask is not whether the log was modified after it was created. Hash chains handle that. The question is whether the log reflects what actually happened when it happened.

A session anchored to RFC 3161 provides a verifiable answer to the second question that does not depend on trusting the operator. Any attempt to reconstruct the log for a different time requires forging the TSA's signature. The distinction between `NON_AUTHORITATIVE_EVIDENCE` and `AUTHORITATIVE_EVIDENCE` is architectural. Compliant evidence requires an external anchor.

---

*Sasana is an open-source AI session auditing library. Source: [github.com/sahiee-dev/Sasana](https://github.com/sahiee-dev/Sasana)*
