"""
sasana.commitment — pre-outcome commitment.

Commit to a decision plus the trace that produced it BEFORE the outcome is known,
obtain an independent RFC 3161 timestamp over the commitment, and reveal later so a
third party can verify (a) the revealed decision and trace are what was committed and
(b) the commitment existed before a deadline.

    C = SHA-256( enc(domain_tag) || enc(subject_id) || enc(context_id)
                 || enc(revision_index) || enc(SHA-256(JCS(payload)))
                 || enc(session_root) || enc(salt) )          enc(v) = u32_be(len v) || v

Design: docs/pre-outcome-commitment.md. This module is platform-agnostic.

Commitment versions. C_v1 (above; domain tag "sasana/commit/v1", bundle_version "1") carried
prev_commitment BESIDE C, so the revision chain was self-consistent inside a bundle but not authenticated
by the timestamp. C_v1 is SUPERSEDED and kept verifiable only for archived bundles. C_v2 (domain tag
"sasana/commit/v2", bundle_version "2") puts the payload mapping id and prev_commitment INSIDE C:

    C = SHA-256( enc("sasana/commit/v2") || enc(mapping_id) || enc(subject_id) || enc(context_id)
                 || enc(revision_index) || enc(prev_commitment, or empty for revision 0)
                 || enc(SHA-256(JCS(payload))) || enc(session_root) || enc(salt) )

so the timestamp authenticates the revision chain, and the same payload hashed under another mapping is a
different commitment. The payload mapping is sasana.commitment_mapping.

What this does NOT prove: completeness of the trace, truthfulness of its contents, absence of human
influence outside the instrumented process, or uniqueness (a timestamp proves "existed by", not "the only
one"). Which revision a counterparty ACCEPTED is established only by counterparty receipts (a PROPOSED
EXTENSION, see verify_commitment), never by the bundle alone.
"""

from __future__ import annotations

import base64
import dataclasses
import hashlib
import math
import secrets
from datetime import datetime, timezone
from typing import Any, Literal, Mapping, Optional, Sequence

from sasana import commitment_mapping as cmap
from sasana import rfc3161
from sasana.jcs import canonicalize as jcs_canonicalize
from sasana.verifier import verify, verify_chain_integrity

DOMAIN_TAG = "sasana/commit/v1"  # C_v1: superseded, verifiable for archived bundles only
BUNDLE_VERSION = "1"
DOMAIN_TAG_V2 = "sasana/commit/v2"
BUNDLE_VERSION_V2 = "2"
RECEIPT_DOMAIN = b"sasana/receipt/v1\n"
_MAX_SAFE_INT = 2**53
_U32_MAX = 2**32 - 1
_CAPTURE_MODES = ("in_process", "sidecar", "gateway")
_DISCLOSURE_FORMS = ("jcs", "utf8", "bytes")


class CommitmentError(Exception):
    """Raised by commit()/reveal_bundle() when a commitment cannot be made soundly."""


# --------------------------------------------------------------------------- #
# Encoding                                                                     #
# --------------------------------------------------------------------------- #


def _enc(value: bytes) -> bytes:
    if len(value) > _U32_MAX:
        raise ValueError("field too long for u32 length prefix")
    return len(value).to_bytes(4, "big") + value


def _utf8(name: str, value: str) -> bytes:
    if not isinstance(value, str):
        raise TypeError(f"{name} must be str")
    try:
        return value.encode("utf-8")  # raises on lone surrogates
    except UnicodeEncodeError as exc:
        raise ValueError(f"{name} is not valid UTF-8: {exc}") from exc


def _hex32(name: str, value: str) -> bytes:
    if not (
        isinstance(value, str) and len(value) == 64 and all(c in "0123456789abcdef" for c in value)
    ):
        raise ValueError(f"{name} must be 64 lowercase hex characters")
    return bytes.fromhex(value)


def validate_payload_profile(payload: Any) -> None:
    """
    Commitment payload profile: a JSON object containing only strings, booleans, null,
    arrays, objects, and integers within +/-2**53. Floats are rejected: encode real
    numbers as decimal strings or scaled integers so every implementation canonicalizes
    identically.
    """
    if not isinstance(payload, dict):
        raise ValueError("payload must be a JSON object (dict)")

    def walk(v: Any, path: str) -> None:
        if v is None or isinstance(v, (bool, str)):
            if isinstance(v, str):
                _utf8(path, v)
            return
        if isinstance(v, int):
            if abs(v) > _MAX_SAFE_INT:
                raise ValueError(f"{path}: integer exceeds +/-2**53")
            return
        if isinstance(v, float):
            raise ValueError(
                f"{path}: floats are not allowed in a commitment payload "
                "(use a decimal string or scaled integer)"
            )
        if isinstance(v, list):
            for i, item in enumerate(v):
                walk(item, f"{path}[{i}]")
            return
        if isinstance(v, dict):
            for k, item in v.items():
                if not isinstance(k, str):
                    raise ValueError(f"{path}: object keys must be strings")
                _utf8(path, k)
                walk(item, f"{path}.{k}")
            return
        raise ValueError(f"{path}: unsupported type {type(v).__name__}")

    walk(payload, "payload")


def payload_hash(payload: Mapping[str, Any]) -> bytes:
    """SHA-256 of the RFC 8785 canonical form of payload (profile-checked)."""
    validate_payload_profile(payload)
    return hashlib.sha256(jcs_canonicalize(dict(payload))).digest()


def encode_commitment_input(
    *,
    subject_id: str,
    context_id: str,
    revision_index: int,
    payload_hash_raw: bytes,
    session_root: str,
    salt: bytes,
    domain_tag: str = DOMAIN_TAG,
) -> bytes:
    """Byte-exact preimage of C. Every field is u32-length-prefixed; fixed fields are length-checked."""
    if not isinstance(revision_index, int) or isinstance(revision_index, bool):
        raise TypeError("revision_index must be int")
    if not 0 <= revision_index <= _U32_MAX:
        raise ValueError("revision_index out of range for u32")
    if len(payload_hash_raw) != 32:
        raise ValueError("payload hash must be 32 bytes")
    if len(salt) != 32:
        raise ValueError("salt must be 32 bytes")
    return (
        _enc(_utf8("domain_tag", domain_tag))
        + _enc(_utf8("subject_id", subject_id))
        + _enc(_utf8("context_id", context_id))
        + _enc(revision_index.to_bytes(4, "big"))
        + _enc(payload_hash_raw)
        + _enc(_hex32("session_root", session_root))
        + _enc(salt)
    )


def compute_commitment(
    *,
    subject_id: str,
    context_id: str,
    revision_index: int,
    payload: Mapping[str, Any],
    session_root: str,
    salt: bytes,
    domain_tag: str = DOMAIN_TAG,
) -> str:
    """Return C as 64 lowercase hex characters."""
    data = encode_commitment_input(
        subject_id=subject_id,
        context_id=context_id,
        revision_index=revision_index,
        payload_hash_raw=payload_hash(payload),
        session_root=session_root,
        salt=salt,
        domain_tag=domain_tag,
    )
    return hashlib.sha256(data).hexdigest()


def encode_commitment_input_v2(
    *,
    mapping_id: str,
    subject_id: str,
    context_id: str,
    revision_index: int,
    prev_commitment: Optional[str],
    payload_hash_raw: bytes,
    session_root: str,
    salt: bytes,
) -> bytes:
    """
    Byte-exact preimage of C_v2. prev_commitment is 64 lowercase hex for revision > 0 and None for
    revision 0; it is encoded as 32 bytes or as an empty field, which the length prefix keeps unambiguous.
    """
    cmap.validate_mapping_id(mapping_id)
    if not isinstance(revision_index, int) or isinstance(revision_index, bool):
        raise TypeError("revision_index must be int")
    if not 0 <= revision_index <= _U32_MAX:
        raise ValueError("revision_index out of range for u32")
    if (revision_index == 0) != (prev_commitment is None):
        raise ValueError(
            "prev_commitment is required for revision > 0 and forbidden for revision 0"
        )
    if len(payload_hash_raw) != 32:
        raise ValueError("payload hash must be 32 bytes")
    if len(salt) != 32:
        raise ValueError("salt must be 32 bytes")
    prev_raw = b"" if prev_commitment is None else _hex32("prev_commitment", prev_commitment)
    return (
        _enc(_utf8("domain_tag", DOMAIN_TAG_V2))
        + _enc(_utf8("mapping_id", mapping_id))
        + _enc(_utf8("subject_id", subject_id))
        + _enc(_utf8("context_id", context_id))
        + _enc(revision_index.to_bytes(4, "big"))
        + _enc(prev_raw)
        + _enc(payload_hash_raw)
        + _enc(_hex32("session_root", session_root))
        + _enc(salt)
    )


def compute_commitment_v2(
    *,
    mapping_id: str,
    subject_id: str,
    context_id: str,
    revision_index: int,
    prev_commitment: Optional[str],
    payload: Mapping[str, Any],
    session_root: str,
    salt: bytes,
) -> str:
    """Return C_v2 as 64 lowercase hex characters."""
    data = encode_commitment_input_v2(
        mapping_id=mapping_id,
        subject_id=subject_id,
        context_id=context_id,
        revision_index=revision_index,
        prev_commitment=prev_commitment,
        payload_hash_raw=payload_hash(payload),
        session_root=session_root,
        salt=salt,
    )
    return hashlib.sha256(data).hexdigest()


# --------------------------------------------------------------------------- #
# Data types                                                                   #
# --------------------------------------------------------------------------- #


@dataclasses.dataclass(frozen=True)
class PublicCommitment:
    """What is sent to the counterparty at commit time. Contains no secrets."""

    version: str
    subject_id: str
    context_id: str
    revision_index: int
    prev_commitment: Optional[str]
    commitment: str
    tsa_token_b64: str
    tsa_gen_time: str  # ISO-8601 UTC, sub-second precision as issued
    tsa_accuracy_s: Optional[float]
    tsa_url: Optional[str]
    mapping_id: Optional[str] = None  # set for C_v2 (version "2"); None for C_v1

    def to_dict(self) -> dict:
        return dataclasses.asdict(self)

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> "PublicCommitment":
        return cls(
            **{
                f.name: d[f.name] if f.name in d or f.default is dataclasses.MISSING else f.default
                for f in dataclasses.fields(cls)
            }
        )


@dataclasses.dataclass(frozen=True)
class CommitmentSecrets:
    """Kept private until reveal. Losing `salt` makes the commitment unrevealable."""

    payload: Mapping[str, Any]
    session_root: str
    salt: bytes

    def to_dict(self) -> dict:
        return {
            "payload": dict(self.payload),
            "session_root": self.session_root,
            "salt": self.salt.hex(),
        }

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> "CommitmentSecrets":
        return cls(
            payload=d["payload"], session_root=d["session_root"], salt=bytes.fromhex(d["salt"])
        )


@dataclasses.dataclass(frozen=True)
class CommitmentVerdict:
    verdict: Literal["VALID_ON_TIME", "LATE", "INVALID", "UNREVEALED"]
    effective_revision: Optional[int]
    effective_payload: Optional[Mapping[str, Any]]
    checks: Mapping[str, Any]
    warnings: Sequence[str]
    errors: Sequence[str]
    evidence_class: Optional[str]

    def as_dict(self) -> dict:
        return dataclasses.asdict(self)


# --------------------------------------------------------------------------- #
# commit                                                                       #
# --------------------------------------------------------------------------- #


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"


def _chain_tip(session_events: Sequence[Mapping[str, Any]]) -> str:
    errors = verify_chain_integrity(list(session_events))
    if errors:
        raise CommitmentError(f"session chain is not valid, refusing to commit: {errors[:3]}")
    return max(session_events, key=lambda e: e["seq"])["event_hash"]


def commit(
    *,
    subject_id: str,
    context_id: str,
    payload: Mapping[str, Any],
    session_events: Sequence[Mapping[str, Any]],
    trusted_tsa_anchors: Sequence[bytes],
    tsa_urls: Optional[Sequence[str]] = None,
    prev: Optional[PublicCommitment] = None,
    salt: Optional[bytes] = None,
    allowed_policies: Optional[Sequence[str]] = None,
    mapping_id: Optional[str] = None,
) -> tuple[PublicCommitment, CommitmentSecrets]:
    """
    Commit to `payload` and the current chain tip of `session_events`.

    FAIL-CLOSED: raises CommitmentError unless a TSA returns a token that passes
    strict verification (CMS signature, chain to `trusted_tsa_anchors`, EKU, nonce, SHA-256
    imprint equal to C). There is no unsigned fallback.

    The session may still be open; anything recorded after the tip is not covered.
    `prev` makes this a revision of an earlier commitment (same subject and context).
    The returned secrets (notably the salt) must be persisted by the caller.

    `mapping_id` selects C_v2 (prev_commitment and the mapping id inside C). `payload` must then already be
    in that mapping's canonical form (build it with e.g. commitment_mapping.map_ha_daily_v1(...).payload).
    Without `mapping_id` this makes a C_v1 commitment, which is superseded; use it only to extend a v1 chain.
    A revision after a counterparty rejection continues the chain from the rejected commitment (prev=it).
    """
    if not trusted_tsa_anchors:
        raise CommitmentError("trusted_tsa_anchors is required (the caller pins the TSA root)")
    if prev is not None and (prev.subject_id != subject_id or prev.context_id != context_id):
        raise CommitmentError("prev commitment belongs to a different subject/context")
    if salt is not None and len(salt) != 32:
        raise ValueError("salt must be 32 bytes")
    if mapping_id is not None:
        mapping = cmap.get_mapping(mapping_id)
        if mapping is None:
            raise CommitmentError(f"unknown payload mapping {mapping_id!r}")
        try:
            mapping.check_canonical(payload)
        except cmap.MappingError as exc:
            raise CommitmentError(f"payload is not canonical for {mapping_id}: {exc}") from exc
        if prev is not None and (
            prev.version != BUNDLE_VERSION_V2 or prev.mapping_id != mapping_id
        ):
            raise CommitmentError("prev commitment was made under a different version or mapping")
    elif prev is not None and prev.version != BUNDLE_VERSION:
        raise CommitmentError("prev is a C_v2 commitment; pass its mapping_id")
    revision_index = 0 if prev is None else prev.revision_index + 1
    session_root = _chain_tip(session_events)
    salt = salt if salt is not None else secrets.token_bytes(32)
    if mapping_id is not None:
        c_hex = compute_commitment_v2(
            mapping_id=mapping_id,
            subject_id=subject_id,
            context_id=context_id,
            revision_index=revision_index,
            prev_commitment=None if prev is None else prev.commitment,
            payload=payload,
            session_root=session_root,
            salt=salt,
        )
    else:
        c_hex = compute_commitment(
            subject_id=subject_id,
            context_id=context_id,
            revision_index=revision_index,
            payload=payload,
            session_root=session_root,
            salt=salt,
        )

    urls = list(tsa_urls) if tsa_urls else [None]
    failures: list[str] = []
    for url in urls:
        nonce = int.from_bytes(secrets.token_bytes(8), "big") | 1
        token = rfc3161.request_timestamp(bytes.fromhex(c_hex), url=url, nonce=nonce)
        if token is None:
            failures.append(f"{url or 'default TSA'}: no response")
            continue
        res = rfc3161.verify_timestamp_strict(
            token,
            bytes.fromhex(c_hex),
            trust_anchors=trusted_tsa_anchors,
            nonce=nonce,
            allowed_policies=allowed_policies,
        )
        if not res.ok:
            failures.append(f"{url or 'default TSA'}: {res.error}")
            continue
        public = PublicCommitment(
            version=BUNDLE_VERSION if mapping_id is None else BUNDLE_VERSION_V2,
            subject_id=subject_id,
            context_id=context_id,
            revision_index=revision_index,
            prev_commitment=None if prev is None else prev.commitment,
            commitment=c_hex,
            tsa_token_b64=base64.b64encode(token).decode(),
            tsa_gen_time=_iso(res.gen_time),
            tsa_accuracy_s=res.accuracy_s,
            tsa_url=url,
            mapping_id=mapping_id,
        )
        return public, CommitmentSecrets(
            payload=dict(payload), session_root=session_root, salt=salt
        )
    raise CommitmentError("no valid RFC 3161 timestamp obtained: " + "; ".join(failures))


# --------------------------------------------------------------------------- #
# reveal_bundle                                                                #
# --------------------------------------------------------------------------- #


def disclosure_hash(form: str, preimage: Any) -> str:
    """
    SHA-256 hex of a disclosed preimage, in one of the three portable forms that match
    sasana._utils.content_hash: "jcs" (JSON value), "utf8" (string), "bytes" (base64 text).
    The lossy str(value) fallback of content_hash is deliberately not supported.
    """
    if form == "jcs":
        return hashlib.sha256(jcs_canonicalize(preimage)).hexdigest()
    if form == "utf8":
        if not isinstance(preimage, str):
            raise ValueError("utf8 preimage must be a string")
        return hashlib.sha256(preimage.encode("utf-8")).hexdigest()
    if form == "bytes":
        if not isinstance(preimage, str):
            raise ValueError("bytes preimage must be base64 text")
        return hashlib.sha256(base64.b64decode(preimage, validate=True)).hexdigest()
    raise ValueError(f"unknown disclosure form {form!r}")


def reveal_bundle(
    commitments: Sequence[tuple[PublicCommitment, CommitmentSecrets]],
    session_events: Sequence[Mapping[str, Any]],
    *,
    capture_mode: Literal["in_process", "sidecar", "gateway"],
    disclosures: Optional[Sequence[Mapping[str, Any]]] = None,
) -> dict:
    """
    Assemble a self-contained, JSON-serializable reveal bundle. Does no network I/O.

    Sanity-checks what it can locally (so the committer finds mistakes before the
    verifier does) but is not a substitute for verify_commitment().
    """
    if capture_mode not in _CAPTURE_MODES:
        raise ValueError(f"capture_mode must be one of {_CAPTURE_MODES}")
    if not commitments:
        raise ValueError("at least one commitment is required")
    subject_id = commitments[0][0].subject_id
    context_id = commitments[0][0].context_id
    version = commitments[0][0].version
    mapping_id = commitments[0][0].mapping_id
    if any(p.version != version or p.mapping_id != mapping_id for p, _ in commitments):
        raise CommitmentError("all revisions must share one commitment version and mapping")
    v2 = version == BUNDLE_VERSION_V2
    events = [dict(e) for e in session_events]
    hash_to_seq = {e["event_hash"]: e["seq"] for e in events}
    revisions = []
    for pub, sec in sorted(commitments, key=lambda pair: pair[0].revision_index):
        if (pub.subject_id, pub.context_id) != (subject_id, context_id):
            raise CommitmentError("all revisions must share subject_id and context_id")
        if v2:
            recomputed = compute_commitment_v2(
                mapping_id=mapping_id,  # type: ignore[arg-type]
                subject_id=pub.subject_id,
                context_id=pub.context_id,
                revision_index=pub.revision_index,
                prev_commitment=pub.prev_commitment,
                payload=sec.payload,
                session_root=sec.session_root,
                salt=sec.salt,
            )
        else:
            recomputed = compute_commitment(
                subject_id=pub.subject_id,
                context_id=pub.context_id,
                revision_index=pub.revision_index,
                payload=sec.payload,
                session_root=sec.session_root,
                salt=sec.salt,
            )
        if recomputed != pub.commitment:
            raise CommitmentError(f"revision {pub.revision_index}: secrets do not match commitment")
        if sec.session_root not in hash_to_seq:
            raise CommitmentError(
                f"revision {pub.revision_index}: session_root is not in the supplied session"
            )
        revisions.append(
            {
                "revision_index": pub.revision_index,
                "prev_commitment": pub.prev_commitment,
                "commitment": pub.commitment,
                "payload": dict(sec.payload),
                "session_root": sec.session_root,
                "salt": sec.salt.hex(),
                "tsa_token": pub.tsa_token_b64,
            }
        )
    by_seq = {e["seq"]: e for e in events}
    for d in disclosures or []:
        ev = by_seq.get(d.get("seq"))
        if ev is None or d.get("field") not in ev.get("payload", {}):
            raise CommitmentError(f"disclosure refers to a missing event field: {dict(d)!r}")
        if d.get("form") not in _DISCLOSURE_FORMS:
            raise CommitmentError(f"disclosure form must be one of {_DISCLOSURE_FORMS}")
        if disclosure_hash(d["form"], d["preimage"]) != ev["payload"][d["field"]]:
            raise CommitmentError(f"disclosure does not hash to the recorded value: {dict(d)!r}")
    bundle = {
        "bundle_version": version,
        "domain_tag": DOMAIN_TAG_V2 if v2 else DOMAIN_TAG,
        "subject_id": subject_id,
        "context_id": context_id,
        "capture_mode": capture_mode,
        "revisions": revisions,
        "session_events": events,
        "disclosures": [dict(d) for d in disclosures or []],
    }
    if v2:
        bundle["mapping_id"] = mapping_id
    return bundle


# --------------------------------------------------------------------------- #
# Counterparty acceptance receipts                                             #
# --------------------------------------------------------------------------- #
#
# PROPOSED EXTENSION: this receipt is NOT an interface of Headline Arena or of any counterparty. The public
# interface we were given has no commitment field, no acceptance receipt, no revision history export and no
# submission timestamps (docs/pre-outcome-commitment.md, Appendix A). Everything below describes what a
# counterparty WOULD have to sign for a verifier to establish which revision it accepted, and is
# exercised only with synthetic keys. challenge_id plays context_id; agent_id plays subject_id.

_RECEIPT_REQUIRED = (
    "challenge_id",
    "agent_id",
    "revision_index",
    "commitment",
    "accepted_at",
    "accepted",
    "reason",
)
_RECEIPT_OPTIONAL = (
    "mapping_id",
    "payload_hash",
)  # payload_hash: SHA-256 hex of JCS(canonical payload)


def _check_receipt_body(body: Any) -> None:
    if not isinstance(body, Mapping):
        raise ValueError("receipt body must be an object")
    missing = [k for k in _RECEIPT_REQUIRED if k not in body]
    extra = [k for k in body if k not in _RECEIPT_REQUIRED + _RECEIPT_OPTIONAL]
    if missing or extra:
        raise ValueError(f"receipt body fields: missing={missing} unexpected={extra}")
    for k in ("challenge_id", "agent_id"):
        _utf8(k, body[k])
    ri = body["revision_index"]
    if not isinstance(ri, int) or isinstance(ri, bool) or not 0 <= ri <= _U32_MAX:
        raise ValueError("revision_index must be a u32 integer")
    _hex32("commitment", body["commitment"])
    _parse_when(body["accepted_at"])
    if not isinstance(body["accepted"], bool):
        raise ValueError("accepted must be a boolean")
    if body["reason"] is not None:
        _utf8("reason", body["reason"])
    if "mapping_id" in body:
        cmap.validate_mapping_id(body["mapping_id"])
    if "payload_hash" in body:
        _hex32("payload_hash", body["payload_hash"])


def _receipt_message(body: Mapping[str, Any]) -> bytes:
    return RECEIPT_DOMAIN + jcs_canonicalize(dict(body))


def sign_receipt(body: Mapping[str, Any], private_key: Any) -> dict:
    """Reference signer for the PROPOSED receipt (tests and examples). `private_key`: Ed25519PrivateKey."""
    _check_receipt_body(body)
    return {"body": dict(body), "signature": private_key.sign(_receipt_message(body)).hex()}


def verify_receipt(receipt: Any, trusted_pubkey_b64: str) -> tuple:
    """
    Verify a receipt against the PINNED counterparty key (base64 raw Ed25519). Returns (body, None) or
    (None, error). No key is ever read from the receipt itself.
    """
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        body = receipt["body"]
        _check_receipt_body(body)
        sig = bytes.fromhex(receipt["signature"])
        raw = base64.b64decode(trusted_pubkey_b64, validate=True)
        if len(raw) != 32 or len(sig) != 64:
            raise ValueError("bad key or signature length")
        try:
            Ed25519PublicKey.from_public_bytes(raw).verify(sig, _receipt_message(body))
        except InvalidSignature:
            return None, "signature does not verify under the pinned receipt key"
        return dict(body), None
    except Exception as exc:  # malformed receipts must not crash a verifier
        return None, f"malformed receipt: {type(exc).__name__}: {exc}"


# --------------------------------------------------------------------------- #
# verify_commitment                                                            #
# --------------------------------------------------------------------------- #


def _parse_when(value: Any) -> datetime:
    if isinstance(value, datetime):
        dt = value
    else:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if dt.tzinfo is None:
        raise ValueError("timestamps must be timezone-aware")
    return dt.astimezone(timezone.utc)


def _invalid(errors: list, checks: dict, warnings: list, evidence: Optional[str] = None):
    return CommitmentVerdict("INVALID", None, None, checks, warnings, errors, evidence)


def verify_commitment(
    bundle: Mapping[str, Any],
    *,
    deadline: datetime,
    trusted_tsa_anchors: Sequence[bytes],
    trusted_seal_pubkey: Optional[str] = None,
    registry: Optional[Sequence[Mapping[str, Any]]] = None,
    allow_partial: bool = False,
    default_accuracy_s: float = 1.0,
    allowed_policies: Optional[Sequence[str]] = None,
    receipts: Optional[Sequence[Mapping[str, Any]]] = None,
    trusted_receipt_pubkey: Optional[str] = None,
    expected_mapping_id: Optional[str] = None,
    require_receipts: bool = False,
    allow_unrevealed_history: bool = False,
    clock_skew_s: float = 0.0,
) -> CommitmentVerdict:
    """
    Verify a reveal bundle (see _verify_commitment for parameter semantics).

    Never raises on bad input: any unexpected failure yields verdict INVALID.
    """
    try:
        return _verify_commitment(
            bundle,
            deadline=deadline,
            trusted_tsa_anchors=trusted_tsa_anchors,
            trusted_seal_pubkey=trusted_seal_pubkey,
            registry=registry,
            allow_partial=allow_partial,
            default_accuracy_s=default_accuracy_s,
            allowed_policies=allowed_policies,
            receipts=receipts,
            trusted_receipt_pubkey=trusted_receipt_pubkey,
            expected_mapping_id=expected_mapping_id,
            require_receipts=require_receipts,
            allow_unrevealed_history=allow_unrevealed_history,
            clock_skew_s=clock_skew_s,
        )
    except Exception as exc:  # malformed input must not crash a verifier
        return CommitmentVerdict(
            "INVALID", None, None, {}, [], [f"malformed bundle: {type(exc).__name__}: {exc}"], None
        )


def _process_receipts(
    receipts: Sequence[Mapping[str, Any]],
    pubkey: str,
    *,
    subject_id: str,
    context_id: str,
    deadline: datetime,
    mapping_id: Optional[str],
    skew: float,
    rev_results: list,
    raw_by_commit: Mapping[str, Mapping[str, Any]],
    errors: list,
    warnings: list,
) -> dict:
    """
    Establish which revision the counterparty accepted before the deadline. The scored revision is the
    accepted receipt with the highest revision_index among those with accepted == true and
    accepted_at < deadline; accepted_at must not decrease as revision_index increases.
    """
    verified: list = []
    out_of_scope = 0
    for i, r in enumerate(receipts):
        body, err = verify_receipt(r, pubkey)
        if err is not None:
            errors.append(f"RECEIPT_INVALID:{i}: {err}")
            continue
        if body["agent_id"] != subject_id or body["challenge_id"] != context_id:
            out_of_scope += 1
            continue
        body["_when"] = _parse_when(body["accepted_at"])
        verified.append(body)

    # one outcome per commitment, one accepted commitment per revision_index
    by_commit: dict = {}
    for b in verified:
        by_commit.setdefault(b["commitment"], []).append(b)
    for c, group in by_commit.items():
        if len({(b["accepted"], b["revision_index"]) for b in group}) > 1:
            errors.append(f"RECEIPT_CONFLICT: contradictory receipts for commitment {c[:16]}...")
    accepted_by_index: dict = {}
    for b in verified:
        if b["accepted"]:
            accepted_by_index.setdefault(b["revision_index"], set()).add(b["commitment"])
    for idx, cs in sorted(accepted_by_index.items()):
        if len(cs) > 1:
            errors.append(
                f"EQUIVOCATION: the counterparty accepted two commitments for revision {idx}"
            )

    eligible = [b for b in verified if b["accepted"] and b["_when"] < deadline]
    for b in verified:
        if b["accepted"] and b["_when"] >= deadline:
            warnings.append(f"RECEIPT_AFTER_DEADLINE:{b['revision_index']}")
    ordered = sorted(eligible, key=lambda b: b["revision_index"])
    for a, b in zip(ordered, ordered[1:]):
        if b["_when"] < a["_when"]:
            errors.append(
                f"RECEIPTS_NON_MONOTONIC: revision {b['revision_index']} was accepted before "
                f"revision {a['revision_index']}"
            )
    scored = ordered[-1] if ordered else None

    revealed = set(raw_by_commit)
    for c, group in by_commit.items():
        accepted = [b for b in group if b["accepted"]]
        if accepted and c not in revealed:
            warnings.append(f"UNREVEALED_COMMITMENT:{accepted[0]['revision_index']}")
    for res in rev_results:
        c = res.get("declared_commitment")
        group = by_commit.get(c, [])
        if not any(b["accepted"] for b in group):
            warnings.append(f"NOT_ACCEPTED_BY_COUNTERPARTY:{res['revision_index']}")
        raw = raw_by_commit.get(c)
        for b in group:
            if not b["accepted"] or raw is None or "commitment" not in res:
                continue  # only a reveal whose C verified can be compared with the receipt
            if res.get("valid"):
                # A commitment cannot be submitted before it exists: the TSA's time for C must not be
                # later than the counterparty's acceptance time (beyond accuracy and assumed skew).
                gen = _parse_when(res["gen_time"]).timestamp()
                if gen - res["accuracy_s"] - skew > b["_when"].timestamp():
                    warnings.append(f"TSA_TIME_AFTER_ACCEPTANCE:{res['revision_index']}")
            if b["revision_index"] != res["revision_index"]:
                errors.append(
                    f"RECEIPT_INDEX_MISMATCH: receipt says revision {b['revision_index']}"
                )
            if "mapping_id" in b and b["mapping_id"] != mapping_id:
                errors.append(f"RECEIPT_MAPPING_MISMATCH: receipt says {b['mapping_id']!r}")
            if "payload_hash" in b and b["payload_hash"] != payload_hash(raw["payload"]).hex():
                errors.append(
                    f"RECEIPT_PAYLOAD_MISMATCH: revision {res['revision_index']} is not what the "
                    "counterparty recorded"
                )
    return {
        "in_scope": len(verified),
        "out_of_scope": out_of_scope,
        "eligible": len(eligible),
        "scored": scored,
    }


def _verify_commitment(
    bundle: Mapping[str, Any],
    *,
    deadline: datetime,
    trusted_tsa_anchors: Sequence[bytes],
    trusted_seal_pubkey: Optional[str] = None,
    registry: Optional[Sequence[Mapping[str, Any]]] = None,
    allow_partial: bool = False,
    default_accuracy_s: float = 1.0,
    allowed_policies: Optional[Sequence[str]] = None,
    receipts: Optional[Sequence[Mapping[str, Any]]] = None,
    trusted_receipt_pubkey: Optional[str] = None,
    expected_mapping_id: Optional[str] = None,
    require_receipts: bool = False,
    allow_unrevealed_history: bool = False,
    clock_skew_s: float = 0.0,
) -> CommitmentVerdict:
    """
    Verify a reveal bundle. Never raises on bad input; returns verdict INVALID with errors.

    deadline            tz-aware instant supplied by the verifier/counterparty (never read
                        from the bundle).
    trusted_tsa_anchors DER certificates the verifier pins; certificates inside tokens are
                        never trusted on their own. Empty means INVALID, never "trust anything".
    registry            optional unsigned counterparty log: dicts with commitment, subject_id,
                        context_id, revision_index, received_at (tz-aware ISO-8601). When
                        given, a revision counts as on time only if the counterparty
                        received it before the deadline too, and unrevealed or
                        equivocating entries are reported.
    receipts            optional SIGNED counterparty acceptance receipts (a PROPOSED EXTENSION, see
                        verify_receipt) and the pinned `trusted_receipt_pubkey` (base64 Ed25519) that
                        must accompany them. With receipts the scored revision is the one the
                        counterparty accepted, not the highest on-time revision in the bundle, and a
                        scored revision that was never revealed gives the verdict UNREVEALED.
    expected_mapping_id for a C_v2 bundle, the payload mapping the verifier requires.
    require_receipts    refuse (INVALID) to give a verdict without receipts.
    allow_unrevealed_history  a C_v2 revision commits, inside C, to the revision before it. By default a
                        bundle that does not reveal that earlier revision is INVALID (selective reveal);
                        True downgrades it to the warning HISTORY_GAP.
    default_accuracy_s  assumed accuracy when the TSA omits it (FreeTSA does, and issues
                        whole-second genTime). Reported as a warning.
    clock_skew_s        assumed disagreement between the TSA clock and the counterparty's deadline
                        clock, added to the time rule: genTime + accuracy + clock_skew_s < deadline.

    Verdicts: VALID_ON_TIME (scored revision found, on time, trace intact), LATE (valid commitments
    exist but the scored one was not provably committed before the deadline), UNREVEALED (the
    counterparty accepted a revision whose secrets the bundle does not reveal: neither passed nor
    failed), INVALID. Warnings are never collapsed into the verdict; read them.
    """
    checks: dict = {}
    warnings: list = []
    errors: list = []
    try:
        if deadline.tzinfo is None:
            raise ValueError("deadline must be timezone-aware")
        deadline = deadline.astimezone(timezone.utc)
    except Exception as exc:
        return _invalid([f"bad deadline: {exc}"], checks, warnings)

    # Policy preconditions: fail closed rather than silently weaken the check.
    if not trusted_tsa_anchors:
        return _invalid(["no TSA trust anchors pinned"], checks, warnings)
    try:
        skew = float(clock_skew_s)
        if not math.isfinite(skew) or skew < 0:
            raise ValueError
    except (TypeError, ValueError):
        return _invalid(["clock_skew_s must be a finite number >= 0"], checks, warnings)
    if receipts is not None and not trusted_receipt_pubkey:
        return _invalid(
            [
                "receipts supplied but no receipt key pinned (keys inside receipts are never trusted)"
            ],
            checks,
            warnings,
        )
    if require_receipts and receipts is None:
        return _invalid(
            ["receipts are required by policy but none were supplied"], checks, warnings
        )

    try:
        version, tag = bundle.get("bundle_version"), bundle.get("domain_tag")
        if (version, tag) == (BUNDLE_VERSION, DOMAIN_TAG):
            v2 = False
        elif (version, tag) == (BUNDLE_VERSION_V2, DOMAIN_TAG_V2):
            v2 = True
        else:
            return _invalid(["unknown bundle_version or domain_tag"], checks, warnings)
        subject_id = bundle["subject_id"]
        context_id = bundle["context_id"]
        events = list(bundle["session_events"])
        raw_revisions = list(bundle["revisions"])
        capture_mode = bundle.get("capture_mode")
        mapping_id = None
        mapping = None
        if v2:
            mapping_id = bundle.get("mapping_id")
            mapping = cmap.get_mapping(mapping_id) if isinstance(mapping_id, str) else None
            if mapping is None:
                return _invalid(
                    [
                        f"unknown payload mapping {mapping_id!r} (known: {list(cmap.known_mapping_ids())})"
                    ],
                    checks,
                    warnings,
                )
            if expected_mapping_id is not None and mapping_id != expected_mapping_id:
                return _invalid(
                    [f"bundle mapping {mapping_id!r} is not the required {expected_mapping_id!r}"],
                    checks,
                    warnings,
                )
        elif expected_mapping_id is not None:
            return _invalid(
                [f"a payload mapping ({expected_mapping_id!r}) is required but the bundle is C_v1"],
                checks,
                warnings,
            )
        if not raw_revisions and not (v2 and receipts is not None):
            return _invalid(["bundle contains no revisions"], checks, warnings)
    except Exception as exc:
        return _invalid([f"malformed bundle: {exc}"], checks, warnings)

    checks["policy"] = {
        "commitment_version": version,
        "mapping_id": mapping_id,
        "expected_mapping_id": expected_mapping_id,
        "tsa_anchors_pinned": len(trusted_tsa_anchors),
        "time_rule": "genTime + accuracy + clock_skew_s < deadline (strict)",
        "accuracy_default_s": default_accuracy_s,
        "clock_skew_s": skew,
        "revocation_checked": False,
        "seal_key_pinned": bool(trusted_seal_pubkey),
        "receipts_supplied": receipts is not None,
        "receipt_key_pinned": bool(trusted_receipt_pubkey),
        "history_gaps_allowed": allow_unrevealed_history,
    }

    # 1. Trace integrity (existing verifier; unchanged semantics).
    trace = None
    if raw_revisions:
        trace = verify(events, trusted_seal_pubkey=trusted_seal_pubkey)
        checks["trace"] = {
            "status": trace.status,
            "evidence_class": trace.evidence_class,
            "event_count": trace.event_count,
            "errors": trace.errors[:5],
        }
        if trace.status == "COMPROMISED" or trace.status == "ERROR":
            return _invalid(
                ["session trace failed verification"] + trace.errors[:5], checks, warnings
            )
        if trace.status == "PARTIAL" and not allow_partial:
            return _invalid(
                ["session trace is PARTIAL (LOG_DROP events present)"], checks, warnings
            )
        if trace.status == "PARTIAL":
            warnings.append("TRACE_PARTIAL")
        if capture_mode not in _CAPTURE_MODES:
            warnings.append("CAPTURE_MODE_UNDECLARED")
        elif capture_mode == "in_process":
            warnings.append(
                "CAPTURE_MODE_IN_PROCESS: undisclosed in-process edits are not detectable"
            )
    else:
        checks["trace"] = None
    checks["capture_mode"] = capture_mode

    hash_to_seq = {e["event_hash"]: e["seq"] for e in events}
    last_seq = max((e["seq"] for e in events), default=0)

    # Registry index.
    reg_by_commit: dict = {}
    reg_scope: list = []
    if registry is not None:
        for entry in registry:
            if entry.get("subject_id") == subject_id and entry.get("context_id") == context_id:
                reg_scope.append(entry)
                reg_by_commit.setdefault(entry["commitment"], []).append(entry)

    # 2. Per-revision checks.
    rev_results: list = []
    raw_sorted = sorted(raw_revisions, key=lambda r: r.get("revision_index", -1))
    for raw in raw_sorted:
        idx = raw.get("revision_index")
        res: dict = {
            "revision_index": idx,
            "valid": False,
            "errors": [],
            "declared_commitment": raw.get("commitment"),
        }
        rev_results.append(res)
        try:
            salt = bytes.fromhex(raw["salt"])
            if v2:
                c_hex = compute_commitment_v2(
                    mapping_id=mapping_id,  # type: ignore[arg-type]
                    subject_id=subject_id,
                    context_id=context_id,
                    revision_index=idx,
                    prev_commitment=raw.get("prev_commitment"),
                    payload=raw["payload"],
                    session_root=raw["session_root"],
                    salt=salt,
                )
            else:
                c_hex = compute_commitment(
                    subject_id=subject_id,
                    context_id=context_id,
                    revision_index=idx,
                    payload=raw["payload"],
                    session_root=raw["session_root"],
                    salt=salt,
                )
        except Exception as exc:
            res["errors"].append(f"cannot recompute commitment: {exc}")
            continue
        if c_hex != raw.get("commitment"):
            res["errors"].append("commitment does not match revealed payload/root/salt")
            continue
        res["commitment"] = c_hex
        if mapping is not None:
            try:
                mapping.check_canonical(raw["payload"])
            except cmap.MappingError as exc:
                res["errors"].append(f"payload is not canonical for {mapping_id}: {exc}")
                continue
        root_seq = hash_to_seq.get(raw["session_root"])
        if root_seq is None:
            res["errors"].append("session_root is not an event in the revealed session")
            continue
        res["post_commitment_events"] = last_seq - root_seq
        try:
            token = base64.b64decode(raw["tsa_token"], validate=True)
        except Exception:
            res["errors"].append("tsa_token is not valid base64")
            continue
        ts = rfc3161.verify_timestamp_strict(
            token,
            bytes.fromhex(c_hex),
            trust_anchors=trusted_tsa_anchors,
            allowed_policies=allowed_policies,
        )
        if not ts.ok:
            res["errors"].append(f"timestamp invalid: {ts.error}")
            continue
        accuracy = ts.accuracy_s
        if accuracy is None:
            accuracy = default_accuracy_s
            res["accuracy_assumed"] = True
        upper = ts.gen_time.timestamp() + accuracy + skew
        res.update(
            gen_time=_iso(ts.gen_time),
            accuracy_s=accuracy,
            tsa_signer=ts.signer_subject,
            timestamp_on_time=upper < deadline.timestamp(),
            upper_bound=_iso(datetime.fromtimestamp(upper, tz=timezone.utc)),
        )
        res["_upper"] = upper
        res["valid"] = True
        res["on_time"] = res["timestamp_on_time"]
        if registry is not None:
            receipts_seen = reg_by_commit.get(c_hex, [])
            if not receipts_seen:
                res["on_time"] = False
                res["registry"] = "NOT_RECEIVED_BY_COUNTERPARTY"
            else:
                received = min(_parse_when(r["received_at"]) for r in receipts_seen)
                res["registry_received_at"] = _iso(received)
                if received >= deadline:
                    res["on_time"] = False
                    res["registry"] = "RECEIVED_AFTER_DEADLINE"
                else:
                    res["registry"] = "OK"

    # 3. Revision chain consistency.
    indices = [r["revision_index"] for r in rev_results if isinstance(r["revision_index"], int)]
    if len(indices) != len(set(indices)):
        return _invalid(["duplicate revision_index in bundle"], checks, warnings)
    if v2:
        # prev_commitment is INSIDE C here, so a revision's link to its predecessor is authenticated:
        # a missing predecessor is proof that an earlier commitment exists and was not revealed.
        by_index = {r.get("revision_index"): r for r in raw_sorted}
        res_by_index = {r["revision_index"]: r for r in rev_results}
        for raw in raw_sorted:
            idx, prev = raw.get("revision_index"), raw.get("prev_commitment")
            if idx == 0:
                if prev is not None:
                    errors.append("revision 0 must not have a prev_commitment")
                continue
            before = by_index.get(idx - 1) if isinstance(idx, int) else None
            if before is None:
                why = "that the bundle does not reveal"
            elif before.get("commitment") != prev:
                errors.append(f"revision {idx}: prev_commitment does not match revision {idx - 1}")
                continue
            elif not res_by_index[idx - 1]["valid"]:
                # presenting a broken reveal of an earlier revision hides it as surely as omitting it
                why = f"whose reveal in the bundle failed verification (revision {idx - 1})"
            else:
                continue
            (warnings if allow_unrevealed_history else errors).append(
                f"HISTORY_GAP: revision {idx} commits (inside C) to an earlier commitment "
                f"{str(prev)[:16]}... {why}"
            )
    else:
        # C_v1: prev_commitment is NOT covered by C; self-consistency only.
        for i, raw in enumerate(raw_sorted):
            idx = raw.get("revision_index")
            if i == 0:
                if idx == 0 and raw.get("prev_commitment") is not None:
                    errors.append("revision 0 must not have a prev_commitment")
                elif idx != 0:
                    warnings.append(f"UNREVEALED_REVISION: bundle starts at revision {idx}")
                continue
            prev_raw = raw_sorted[i - 1]
            if idx == prev_raw.get("revision_index") + 1:
                if raw.get("prev_commitment") != prev_raw.get("commitment"):
                    errors.append(
                        f"revision {idx}: prev_commitment does not match revision {idx - 1}"
                    )
            else:
                warnings.append(
                    f"UNREVEALED_REVISION: gap between {prev_raw['revision_index']} and {idx}"
                )
    valid_revs = [r for r in rev_results if r["valid"]]
    for a, b in zip(valid_revs, valid_revs[1:]):
        if b["_upper"] < a["_upper"] - 1e-6:
            errors.append(
                f"revision {b['revision_index']} was timestamped before revision "
                f"{a['revision_index']} (non-monotonic)"
            )
    if any(r.get("accuracy_assumed") for r in valid_revs):
        warnings.append(
            f"TSA_ACCURACY_ASSUMED: TSA omitted accuracy; assumed {default_accuracy_s}s"
        )

    # 4. Registry cross-checks.
    if registry is not None:
        bundle_commits = {r.get("commitment") for r in raw_revisions}
        missing = sorted(c for c in reg_by_commit if c not in bundle_commits)
        if missing:
            warnings.append(f"UNREVEALED_COMMITMENT: {len(missing)} registry entries not in bundle")
        seen: dict = {}
        for entry in reg_scope:
            key = entry.get("revision_index")
            if key in seen and seen[key] != entry["commitment"]:
                errors.append(f"EQUIVOCATION: two different commitments for revision {key}")
            seen.setdefault(key, entry["commitment"])
        checks["registry"] = {"entries_in_scope": len(reg_scope), "unrevealed": len(missing)}

    # 4b. Signed receipts: which revision did the counterparty accept?
    scored = None
    if receipts is not None:
        raw_by_commit = {r.get("commitment"): r for r in raw_sorted}
        rc = _process_receipts(
            receipts,
            trusted_receipt_pubkey,  # type: ignore[arg-type]
            subject_id=subject_id,
            context_id=context_id,
            deadline=deadline,
            mapping_id=mapping_id,
            skew=skew,
            rev_results=rev_results,
            raw_by_commit=raw_by_commit,
            errors=errors,
            warnings=warnings,
        )
        scored = rc["scored"]
        checks["receipts"] = {
            "in_scope": rc["in_scope"],
            "out_of_scope": rc["out_of_scope"],
            "eligible": rc["eligible"],
            "scored_revision": None if scored is None else scored["revision_index"],
            "scored_commitment": None if scored is None else scored["commitment"],
        }
    elif v2:
        warnings.append(
            "NO_RECEIPTS: the effective revision is the highest on-time revision in the bundle; "
            "the counterparty may have accepted a different one"
        )

    # 5. Effective revision.
    invalid_revs = [r for r in rev_results if not r["valid"]]
    for r in invalid_revs:
        warnings.append(f"REVISION_INVALID:{r['revision_index']}: " + "; ".join(r["errors"]))
    effective = None
    unrevealed = False
    if receipts is not None:
        if scored is None:
            warnings.append("NO_ACCEPTED_RECEIPT_BEFORE_DEADLINE")
        else:
            rr = next(
                (r for r in rev_results if r.get("declared_commitment") == scored["commitment"]),
                None,
            )
            if rr is None:
                unrevealed = True
            elif not rr["valid"]:
                errors.append(
                    f"the revision the counterparty scored ({scored['revision_index']}) failed "
                    "verification: " + "; ".join(rr["errors"])
                )
            elif not rr["on_time"]:
                warnings.append(f"SCORED_REVISION_NOT_ON_TIME:{scored['revision_index']}")
            else:
                effective = rr
    else:
        eligible = [r for r in rev_results if r["valid"] and r.get("on_time")]
        effective = max(eligible, key=lambda r: r["revision_index"]) if eligible else None
        if effective is not None:
            later_invalid = [
                r for r in invalid_revs if r["revision_index"] > effective["revision_index"]
            ]
            if later_invalid:
                errors.append(
                    "a higher-index revision failed verification, so the effective revision "
                    "cannot be established"
                )
    for r in rev_results:
        r.pop("_upper", None)
    checks["revisions"] = rev_results

    # 6. Disclosures (informational; a failure does not invalidate the commitment).
    disc_results = []
    by_seq = {e["seq"]: e for e in events}
    for d in bundle.get("disclosures") or []:
        ok = False
        try:
            ev = by_seq[d["seq"]]
            ok = disclosure_hash(d["form"], d["preimage"]) == ev["payload"][d["field"]]
        except Exception:
            ok = False
        disc_results.append({"seq": d.get("seq"), "field": d.get("field"), "ok": ok})
        if not ok:
            warnings.append(f"DISCLOSURE_FAILED:{d.get('seq')}/{d.get('field')}")
    checks["disclosures"] = disc_results

    evidence = trace.evidence_class if trace is not None else None
    if errors:
        return _invalid(errors, checks, warnings, evidence)
    if unrevealed:
        return CommitmentVerdict("UNREVEALED", None, None, checks, warnings, [], evidence)
    if effective is None:
        if receipts is not None or valid_revs:
            return CommitmentVerdict("LATE", None, None, checks, warnings, [], evidence)
        return _invalid(["no revision passed verification"], checks, warnings, evidence)

    if effective["post_commitment_events"]:
        warnings.append(f"POST_COMMITMENT_EVENTS:{effective['post_commitment_events']}")
    eff_raw = next(r for r in raw_revisions if r["revision_index"] == effective["revision_index"])
    if mapping is not None:
        warnings.extend(mapping.payload_warnings(eff_raw["payload"]))
    return CommitmentVerdict(
        "VALID_ON_TIME",
        effective["revision_index"],
        eff_raw["payload"],
        checks,
        warnings,
        [],
        evidence,
    )
