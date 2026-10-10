"""
sasana/rfc3161.py — RFC 3161 trusted timestamp anchoring.

Sends the SHA-256 hash of SESSION_START to a public TSA (Freetsa by default)
and verifies returned tokens. The TSA receives only a hash — never session content.

TSA endpoint is configurable via SASANA_TSA_URL env var. Default: Freetsa.
Network failure is fail-open: the session proceeds without a timestamp token.
"""

from __future__ import annotations

import dataclasses
import hashlib
import logging
import os
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from typing import Optional, Sequence

logger = logging.getLogger("sasana.rfc3161")

_DEFAULT_TSA_URL = "https://freetsa.org/tsr"

# SHA-256 AlgorithmIdentifier DER: SEQUENCE { OID(2.16.840.1.101.3.4.2.1) NULL }
_SHA256_ALG_ID = bytes.fromhex("300d06096086480165030402010500")

# id-ct-TSTInfo OID value bytes: 1.2.840.113549.1.9.16.1.4
_TSTINFO_OID_VALUE = bytes.fromhex("2a864886f70d0109100104")


# ------------------------------------------------------------------ #
# Minimal DER builder                                                  #
# ------------------------------------------------------------------ #


def _dlen(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    if n < 0x100:
        return bytes([0x81, n])
    if n < 0x10000:
        return bytes([0x82, (n >> 8) & 0xFF, n & 0xFF])
    raise ValueError(f"DER length {n} too large")


def _seq(data: bytes) -> bytes:
    return b"\x30" + _dlen(len(data)) + data


def _int_der(n: int) -> bytes:
    if n == 0:
        return b"\x02\x01\x00"
    raw = n.to_bytes((n.bit_length() + 8) // 8, "big")
    while len(raw) > 1 and raw[0] == 0 and not (raw[1] & 0x80):
        raw = raw[1:]
    return b"\x02" + _dlen(len(raw)) + raw


def _octet(data: bytes) -> bytes:
    return b"\x04" + _dlen(len(data)) + data


def _bool_der(v: bool) -> bytes:
    return b"\x01\x01\xff" if v else b"\x01\x01\x00"


def build_timestamp_request(hash_bytes: bytes, nonce: Optional[int] = None) -> bytes:
    """
    Build a DER-encoded RFC 3161 TimeStampReq for a SHA-256 hash.

    nonce, when given, is a positive integer the TSA must echo in TSTInfo; it
    binds the response to this request (anti-replay).
    """
    msg_imprint = _seq(_SHA256_ALG_ID + _octet(hash_bytes))
    # version=1, messageImprint, [nonce], certReq=TRUE (include cert for offline verification)
    nonce_der = _int_der(nonce) if nonce is not None else b""
    return _seq(_int_der(1) + msg_imprint + nonce_der + _bool_der(True))


# ------------------------------------------------------------------ #
# Minimal DER parser                                                   #
# ------------------------------------------------------------------ #


def _read_tlv(data: bytes, offset: int) -> tuple[int, int, bytes]:
    """Parse one TLV at offset. Returns (tag, next_offset, value_bytes)."""
    if offset + 2 > len(data):
        raise ValueError(f"DER underrun at offset {offset}")
    tag = data[offset]
    offset += 1
    b = data[offset]
    offset += 1
    if b & 0x80:
        n_bytes = b & 0x7F
        if n_bytes == 0 or offset + n_bytes > len(data):
            raise ValueError("DER indefinite or malformed length")
        length = int.from_bytes(data[offset : offset + n_bytes], "big")
        offset += n_bytes
    else:
        length = b
    end = offset + length
    if end > len(data):
        raise ValueError(f"DER value overrun: need {length} at {offset}, have {len(data) - offset}")
    return tag, end, data[offset:end]


def _children(data: bytes) -> list[tuple[int, bytes]]:
    """Parse all immediate TLV children from raw SEQUENCE/SET value bytes."""
    result = []
    offset = 0
    while offset < len(data):
        tag, offset, val = _read_tlv(data, offset)
        result.append((tag, val))
    return result


def _extract_tstinfo(resp_der: bytes) -> bytes:
    """
    Extract DER-encoded TSTInfo from a RFC 3161 TimeStampResp.

    Structure navigated:
      TimeStampResp SEQUENCE
        PKIStatusInfo SEQUENCE  (status must be 0=granted or 1=grantedWithMods)
        ContentInfo SEQUENCE
          OID(id-signedData)
          [0] EXPLICIT → SignedData SEQUENCE
            ...
            EncapsulatedContentInfo SEQUENCE
              OID(id-ct-TSTInfo)
              [0] EXPLICIT → OCTET STRING  ← TSTInfo DER lives here
    """
    tag, _, resp_val = _read_tlv(resp_der, 0)
    if tag != 0x30:
        raise ValueError(f"Expected outer SEQUENCE(0x30), got {tag:#x}")

    items = _children(resp_val)
    if len(items) < 2:
        raise ValueError("TimeStampResp must contain PKIStatusInfo + ContentInfo")

    # PKIStatusInfo: first child — check status is granted (0 or 1)
    status_items = _children(items[0][1])
    status_val = status_items[0][1] if status_items else b"\x00"
    status = int.from_bytes(status_val, "big") if status_val else 0
    if status not in (0, 1):
        raise ValueError(f"TSA status not granted: {status}")

    # ContentInfo: second child
    ci_items = _children(items[1][1])
    if len(ci_items) < 2:
        raise ValueError("ContentInfo is missing content")

    # [0] EXPLICIT wrapping SignedData
    ctx_tag, ctx_val = ci_items[1]
    if ctx_tag != 0xA0:
        raise ValueError(f"Expected [0] EXPLICIT (0xa0), got {ctx_tag:#x}")

    # SignedData SEQUENCE inside [0]
    sd_tag, _, sd_val = _read_tlv(ctx_val, 0)
    if sd_tag != 0x30:
        raise ValueError("Expected SignedData SEQUENCE inside [0] EXPLICIT")

    # Find EncapsulatedContentInfo: a SEQUENCE whose first child is id-ct-TSTInfo OID
    for child_tag, child_val in _children(sd_val):
        if child_tag != 0x30:
            continue
        ec_items = _children(child_val)
        if not ec_items or ec_items[0][0] != 0x06:
            continue
        if ec_items[0][1] != _TSTINFO_OID_VALUE:
            continue
        # Found — extract the nested OCTET STRING
        if len(ec_items) < 2:
            raise ValueError("EncapsulatedContentInfo is missing eContent")
        ec0_tag, ec0_val = ec_items[1]
        if ec0_tag != 0xA0:
            raise ValueError(f"Expected [0] EXPLICIT for eContent, got {ec0_tag:#x}")
        os_tag, _, os_val = _read_tlv(ec0_val, 0)
        if os_tag != 0x04:
            raise ValueError(f"Expected OCTET STRING for TSTInfo DER, got {os_tag:#x}")
        return os_val

    raise ValueError("id-ct-TSTInfo EncapsulatedContentInfo not found in SignedData")


def _parse_tstinfo(tstinfo_der: bytes) -> tuple[bytes, str]:
    """
    Parse TSTInfo. Returns (message_imprint_hash: bytes, gen_time_iso_utc: str).

    TSTInfo SEQUENCE:
      version INTEGER
      policy OID
      messageImprint SEQUENCE {
        hashAlgorithm AlgorithmIdentifier
        hashedMessage OCTET STRING      ← what was originally hashed
      }
      serialNumber INTEGER
      genTime GeneralizedTime (tag 0x18)
    """
    tag, _, tst_val = _read_tlv(tstinfo_der, 0)
    if tag != 0x30:
        raise ValueError("Expected SEQUENCE for TSTInfo")

    items = _children(tst_val)
    if len(items) < 5:
        raise ValueError(f"TSTInfo has too few fields: {len(items)}")

    # messageImprint is index 2
    mi_tag, mi_val = items[2]
    if mi_tag != 0x30:
        raise ValueError("Expected SEQUENCE for messageImprint")
    mi_items = _children(mi_val)
    if len(mi_items) < 2:
        raise ValueError("messageImprint missing hashedMessage")
    hash_tag, hash_val = mi_items[1]
    if hash_tag != 0x04:
        raise ValueError("Expected OCTET STRING for hashedMessage")

    # genTime is index 4 (GeneralizedTime, ASN.1 tag 0x18)
    gt_tag, gt_val = items[4]
    if gt_tag != 0x18:
        raise ValueError(f"Expected GeneralizedTime(0x18), got {gt_tag:#x}")

    gen_time_raw = gt_val.decode("ascii")
    try:
        base = gen_time_raw.rstrip("Z").split(".")[0]  # strip fractional seconds
        dt = datetime.strptime(base, "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc)
        gen_time = dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        gen_time = gen_time_raw

    return hash_val, gen_time


# ------------------------------------------------------------------ #
# Public API                                                           #
# ------------------------------------------------------------------ #


def request_timestamp(
    hash_bytes: bytes, *, url: Optional[str] = None, nonce: Optional[int] = None
) -> Optional[bytes]:
    """
    Submit hash_bytes to the configured TSA. Returns raw DER response, or None on failure.

    Configurable via the url argument or SASANA_TSA_URL env var (default:
    https://freetsa.org/tsr).
    Only a 32-byte hash is transmitted — no session content ever leaves the machine.
    """
    url = url or os.environ.get("SASANA_TSA_URL", _DEFAULT_TSA_URL)
    req_der = build_timestamp_request(hash_bytes, nonce=nonce)
    try:
        http_req = urllib.request.Request(
            url,
            data=req_der,
            headers={"Content-Type": "application/timestamp-query"},
            method="POST",
        )
        with urllib.request.urlopen(http_req, timeout=10) as resp:
            if resp.status != 200:
                logger.warning(
                    "Sasana RFC 3161: TSA returned HTTP %d — session proceeds without timestamp",
                    resp.status,
                )
                return None
            return resp.read()
    except Exception as exc:
        logger.warning(
            "Sasana RFC 3161: TSA request failed (session proceeds without timestamp): %s", exc
        )
        return None


def verify_timestamp(token_der: bytes, hash_bytes: bytes) -> tuple[bool, Optional[str]]:
    """
    Verify a RFC 3161 timestamp token against the expected pre-token hash.

    Returns (valid: bool, utc_timestamp: str | None).

    valid=True means the token parsed correctly and its MessageImprint matches
    hash_bytes. The TSA's Ed25519 signature chain is not verified here; the raw
    DER token embedded in the session is verifiable offline with standard RFC 3161
    tools (e.g. openssl ts -verify).
    """
    try:
        tstinfo_der = _extract_tstinfo(token_der)
        imprint_hash, gen_time = _parse_tstinfo(tstinfo_der)
        if imprint_hash != hash_bytes:
            logger.debug(
                "Sasana RFC 3161: MessageImprint mismatch — expected %s, got %s",
                hash_bytes.hex(),
                imprint_hash.hex(),
            )
            return False, None
        return True, gen_time
    except Exception as exc:
        logger.debug("Sasana RFC 3161: token verification failed: %s", exc)
        return False, None


# ------------------------------------------------------------------ #
# Strict verification: CMS signature, certificate chain, TSTInfo       #
# ------------------------------------------------------------------ #
#
# verify_timestamp() above only matches the MessageImprint. The functions below
# are what an adversarial verifier needs: the token must be signed by a TSA
# whose certificate chains to a caller-pinned trust anchor, and the time and
# accuracy are taken from the signed TSTInfo.
#
# Not done: revocation checking (CRL/OCSP), RSA-PSS signatures, SHA-1 digests.

_OID_SIGNED_DATA = bytes.fromhex("2a864886f70d010702")
_OID_CONTENT_TYPE = bytes.fromhex("2a864886f70d010903")
_OID_MESSAGE_DIGEST = bytes.fromhex("2a864886f70d010904")
_OID_SHA256 = bytes.fromhex("608648016503040201")
_OID_SHA384 = bytes.fromhex("608648016503040202")
_OID_SHA512 = bytes.fromhex("608648016503040203")
_OID_ED25519 = bytes.fromhex("2b6570")
_EKU_TIME_STAMPING = "1.3.6.1.5.5.7.3.8"

_DIGESTS = {
    _OID_SHA256: hashlib.sha256,
    _OID_SHA384: hashlib.sha384,
    _OID_SHA512: hashlib.sha512,
}


@dataclasses.dataclass(frozen=True)
class TimestampVerification:
    """Result of verify_timestamp_strict(). Never raised; check `ok`."""

    ok: bool
    error: Optional[str] = None
    gen_time: Optional[datetime] = None  # UTC, microsecond precision
    accuracy_s: Optional[float] = None  # None if the TSA omitted accuracy
    policy_oid: Optional[str] = None
    serial_number: Optional[int] = None
    signer_subject: Optional[str] = None

    @property
    def gen_time_upper(self) -> Optional[datetime]:
        """Latest instant the TSA vouches for: genTime + accuracy (0 if omitted)."""
        if self.gen_time is None:
            return None
        return self.gen_time + timedelta(seconds=self.accuracy_s or 0.0)


def _oid_to_str(value: bytes) -> str:
    if not value:
        raise ValueError("empty OID")
    first = value[0]
    arcs = [first // 40, first % 40]
    acc = 0
    for b in value[1:]:
        acc = (acc << 7) | (b & 0x7F)
        if not b & 0x80:
            arcs.append(acc)
            acc = 0
    return ".".join(str(a) for a in arcs)


def _children_raw(data: bytes) -> list[tuple[int, bytes, bytes]]:
    """Like _children, but also returns each element's full raw TLV bytes."""
    out = []
    offset = 0
    while offset < len(data):
        start = offset
        tag, offset, val = _read_tlv(data, offset)
        out.append((tag, val, data[start:offset]))
    return out


def _uint(value: bytes) -> int:
    return int.from_bytes(value, "big")


def _parse_generalized_time(raw: bytes) -> datetime:
    text = raw.decode("ascii")
    if not text.endswith("Z"):
        raise ValueError("GeneralizedTime must be UTC (end in Z)")
    text = text[:-1]
    base, _, frac = text.partition(".")
    if len(base) != 14 or not base.isdigit() or (frac and not frac.isdigit()):
        raise ValueError(f"malformed GeneralizedTime: {text!r}")
    dt = datetime.strptime(base, "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc)
    if frac:
        micros = int((frac + "000000")[:6])
        dt = dt.replace(microsecond=micros)
    return dt


def _parse_tstinfo_full(tstinfo_der: bytes) -> dict:
    tag, _, tst_val = _read_tlv(tstinfo_der, 0)
    if tag != 0x30:
        raise ValueError("TSTInfo is not a SEQUENCE")
    items = _children(tst_val)
    if len(items) < 5:
        raise ValueError("TSTInfo has too few fields")
    if items[0][0] != 0x02 or _uint(items[0][1]) != 1:
        raise ValueError("unsupported TSTInfo version")
    if items[1][0] != 0x06:
        raise ValueError("TSTInfo policy is not an OID")
    mi = _children(items[2][1])
    if len(mi) < 2 or mi[0][0] != 0x30 or mi[1][0] != 0x04:
        raise ValueError("malformed messageImprint")
    alg_children = _children(mi[0][1])
    if not alg_children or alg_children[0][0] != 0x06:
        raise ValueError("malformed messageImprint algorithm")
    if items[3][0] != 0x02:
        raise ValueError("TSTInfo serialNumber is not an INTEGER")
    if items[4][0] != 0x18:
        raise ValueError("TSTInfo genTime is not GeneralizedTime")
    info: dict = {
        "policy": _oid_to_str(items[1][1]),
        "imprint_alg": alg_children[0][1],
        "imprint": mi[1][1],
        "serial": _uint(items[3][1]),
        "gen_time": _parse_generalized_time(items[4][1]),
        "accuracy_s": None,
        "nonce": None,
    }
    for t, v in items[5:]:
        if t == 0x30 and info["accuracy_s"] is None:
            secs = 0.0
            for at, av in _children(v):
                if at == 0x02:
                    secs += _uint(av)
                elif at == 0x80:
                    secs += _uint(av) / 1e3
                elif at == 0x81:
                    secs += _uint(av) / 1e6
            info["accuracy_s"] = secs
        elif t == 0x02 and info["nonce"] is None:
            info["nonce"] = _uint(v)
    return info


def _parse_cms(resp_der: bytes) -> dict:
    """Parse a TimeStampResp down to TSTInfo bytes, certificates, and the one SignerInfo."""
    tag, _, resp_val = _read_tlv(resp_der, 0)
    if tag != 0x30:
        raise ValueError("TimeStampResp is not a SEQUENCE")
    items = _children(resp_val)
    if len(items) < 2:
        raise ValueError("TimeStampResp has no token")
    status_items = _children(items[0][1])
    status = _uint(status_items[0][1]) if status_items else -1
    if status not in (0, 1):
        raise ValueError(f"TSA status not granted: {status}")

    ci = _children(items[1][1])
    if len(ci) < 2 or ci[0][0] != 0x06 or ci[0][1] != _OID_SIGNED_DATA or ci[1][0] != 0xA0:
        raise ValueError("token is not CMS SignedData")
    sd_tag, _, sd_val = _read_tlv(ci[1][1], 0)
    if sd_tag != 0x30:
        raise ValueError("SignedData is not a SEQUENCE")

    econtent: Optional[bytes] = None
    certs: list[bytes] = []
    sets: list[bytes] = []
    for t, v, raw in _children_raw(sd_val):
        if t == 0x30 and econtent is None:
            ec = _children(v)
            if ec and ec[0][0] == 0x06 and ec[0][1] == _TSTINFO_OID_VALUE:
                if len(ec) < 2 or ec[1][0] != 0xA0:
                    raise ValueError("eContent missing")
                os_tag, _, os_val = _read_tlv(ec[1][1], 0)
                if os_tag != 0x04:
                    raise ValueError("eContent is not an OCTET STRING")
                econtent = os_val
        elif t == 0xA0:  # certificates [0] IMPLICIT SET OF
            certs = [raw_c for _, _, raw_c in _children_raw(v)]
        elif t == 0x31:  # digestAlgorithms SET, then signerInfos SET (always last)
            sets.append(v)
    signer_infos = [raw_s for tt, _, raw_s in _children_raw(sets[-1]) if tt == 0x30] if sets else []
    if econtent is None:
        raise ValueError("TSTInfo eContent not found")
    if len(signer_infos) != 1:
        raise ValueError(f"expected exactly 1 SignerInfo, found {len(signer_infos)}")
    return {"tstinfo": econtent, "certs": certs, "signer_info": signer_infos[0]}


def _parse_signer_info(si_der: bytes) -> dict:
    _, _, si_val = _read_tlv(si_der, 0)
    parts = _children_raw(si_val)
    if len(parts) < 5:
        raise ValueError("SignerInfo too short")
    idx = 1  # parts[0] = version
    sid_tag, sid_val, _ = parts[idx]
    idx += 1
    dig_tag, dig_val, _ = parts[idx]
    idx += 1
    if dig_tag != 0x30:
        raise ValueError("bad SignerInfo digestAlgorithm")
    dig_oid = _children(dig_val)[0][1]
    if parts[idx][0] != 0xA0:
        raise ValueError("SignerInfo has no signedAttrs (required by RFC 3161)")
    signed_attrs_raw = parts[idx][2]
    signed_attrs_val = parts[idx][1]
    idx += 1
    sig_alg_tag, sig_alg_val, _ = parts[idx]
    idx += 1
    sig_tag, sig_val, _ = parts[idx]
    if sig_alg_tag != 0x30 or sig_tag != 0x04:
        raise ValueError("bad SignerInfo signature fields")
    sig_alg_oid = _children(sig_alg_val)[0][1]
    attrs: dict[bytes, bytes] = {}
    for at, av in _children(signed_attrs_val):
        if at != 0x30:
            continue
        ac = _children(av)
        if len(ac) == 2 and ac[0][0] == 0x06 and ac[1][0] == 0x31:
            vals = _children(ac[1][1])
            if vals:
                attrs[ac[0][1]] = vals[0][1]
    return {
        "sid_tag": sid_tag,
        "sid_val": sid_val,
        "digest_oid": dig_oid,
        "signed_attrs_raw": signed_attrs_raw,
        "sig_alg_oid": sig_alg_oid,
        "signature": sig_val,
        "attrs": attrs,
    }


def _cert_time(cert, which: str) -> datetime:
    attr = f"{which}_utc"
    if hasattr(cert, attr):
        return getattr(cert, attr)
    return getattr(cert, which).replace(tzinfo=timezone.utc)  # cryptography < 42


def _check_cert_valid_at(cert, when: datetime) -> bool:
    return _cert_time(cert, "not_valid_before") <= when <= _cert_time(cert, "not_valid_after")


def _build_chain(leaf, intermediates: list, anchors: list, when: datetime):
    """Return a verified path [leaf, ..., anchor] or raise ValueError."""

    def is_ca(cert) -> bool:
        from cryptography import x509

        try:
            bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
            return bool(bc.ca)
        except x509.ExtensionNotFound:
            return False

    def walk(cert, path: list, depth: int):
        if depth > 8:
            return None
        for a in anchors:
            if cert == a:
                return path
            try:
                cert.verify_directly_issued_by(a)
            except Exception:
                continue
            if _check_cert_valid_at(a, when) and is_ca(a):
                return path + [a]
        for inter in intermediates:
            if inter in path:
                continue
            try:
                cert.verify_directly_issued_by(inter)
            except Exception:
                continue
            if _check_cert_valid_at(inter, when) and is_ca(inter):
                found = walk(inter, path + [inter], depth + 1)
                if found:
                    return found
        return None

    result = walk(leaf, [leaf], 0)
    if result is None:
        raise ValueError("signer certificate does not chain to a pinned trust anchor")
    return result


def _verify_cms_signature(cert, signer: dict) -> None:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa

    hash_cls = {_OID_SHA256: hashes.SHA256, _OID_SHA384: hashes.SHA384, _OID_SHA512: hashes.SHA512}
    if signer["digest_oid"] not in hash_cls:
        raise ValueError("unsupported or weak SignerInfo digest algorithm")
    hash_alg = hash_cls[signer["digest_oid"]]()
    # Signature covers the DER of signedAttrs with the [0] IMPLICIT tag replaced by SET (0x31).
    signed = b"\x31" + signer["signed_attrs_raw"][1:]
    pub = cert.public_key()
    sig = signer["signature"]
    if isinstance(pub, rsa.RSAPublicKey):
        pub.verify(sig, signed, padding.PKCS1v15(), hash_alg)
    elif isinstance(pub, ec.EllipticCurvePublicKey):
        pub.verify(sig, signed, ec.ECDSA(hash_alg))
    elif isinstance(pub, ed25519.Ed25519PublicKey):
        pub.verify(sig, signed)
    else:
        raise ValueError("unsupported signer public-key type")


def verify_timestamp_strict(
    token_der: bytes,
    expected_hash: bytes,
    *,
    trust_anchors: Sequence[bytes],
    nonce: Optional[int] = None,
    allowed_policies: Optional[Sequence[str]] = None,
) -> TimestampVerification:
    """
    Fully verify an RFC 3161 TimeStampResp. Never raises; inspect `.ok` / `.error`.

    Checks, all required:
      * TSA status granted; CMS SignedData with exactly one SignerInfo
      * signedAttrs: contentType == id-ct-TSTInfo, messageDigest == H(TSTInfo)
      * CMS signature valid under the signer certificate (RSA PKCS#1 v1.5, ECDSA, Ed25519)
      * signer certificate carries the timeStamping EKU and chains, through
        embedded intermediates, to one of `trust_anchors` (DER certificates the
        CALLER pins; certificates inside the token are never trusted on their own)
      * every certificate on the path was valid at genTime
      * TSTInfo: SHA-256 imprint equals expected_hash; nonce echoed if one was sent;
        policy OID in allowed_policies if given

    Not checked: revocation (CRL/OCSP).
    """
    try:
        from cryptography import x509

        if not trust_anchors:
            return TimestampVerification(False, "no trust anchors supplied")
        anchors = [x509.load_der_x509_certificate(a) for a in trust_anchors]

        cms = _parse_cms(token_der)
        info = _parse_tstinfo_full(cms["tstinfo"])
        signer = _parse_signer_info(cms["signer_info"])

        if signer["attrs"].get(_OID_CONTENT_TYPE) != _TSTINFO_OID_VALUE:
            return TimestampVerification(False, "signedAttrs contentType is not id-ct-TSTInfo")
        digest_fn = _DIGESTS.get(signer["digest_oid"])
        if digest_fn is None:
            return TimestampVerification(False, "unsupported or weak SignerInfo digest algorithm")
        if signer["attrs"].get(_OID_MESSAGE_DIGEST) != digest_fn(cms["tstinfo"]).digest():
            return TimestampVerification(False, "signedAttrs messageDigest does not match TSTInfo")

        embedded = [x509.load_der_x509_certificate(c) for c in cms["certs"]]
        leaf = _find_signer_cert(embedded, signer)
        if leaf is None:
            return TimestampVerification(False, "signer certificate not present in token")

        try:
            _verify_cms_signature(leaf, signer)
        except Exception:
            return TimestampVerification(False, "CMS signature invalid")

        gen_time: datetime = info["gen_time"]
        try:
            _build_chain(leaf, [c for c in embedded if c != leaf], anchors, gen_time)
        except ValueError as exc:
            return TimestampVerification(False, str(exc))
        if not _check_cert_valid_at(leaf, gen_time):
            return TimestampVerification(False, "signer certificate not valid at genTime")
        try:
            eku = leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        except x509.ExtensionNotFound:
            return TimestampVerification(False, "signer certificate has no ExtendedKeyUsage")
        if _EKU_TIME_STAMPING not in {o.dotted_string for o in eku}:
            return TimestampVerification(False, "signer certificate lacks timeStamping EKU")

        if info["imprint_alg"] != _OID_SHA256:
            return TimestampVerification(False, "TSTInfo imprint algorithm is not SHA-256")
        if info["imprint"] != expected_hash:
            return TimestampVerification(False, "MessageImprint does not match expected hash")
        if nonce is not None and info["nonce"] != nonce:
            return TimestampVerification(False, "nonce missing or does not match request")
        if allowed_policies is not None and info["policy"] not in allowed_policies:
            return TimestampVerification(False, f"TSA policy {info['policy']} not allowed")

        return TimestampVerification(
            True,
            None,
            gen_time=gen_time,
            accuracy_s=info["accuracy_s"],
            policy_oid=info["policy"],
            serial_number=info["serial"],
            signer_subject=leaf.subject.rfc4514_string(),
        )
    except Exception as exc:
        return TimestampVerification(False, f"malformed token: {exc}")


def _find_signer_cert(certs: list, signer: dict):
    from cryptography import x509

    if signer["sid_tag"] == 0x30:  # IssuerAndSerialNumber
        parts = _children_raw(signer["sid_val"])
        if len(parts) != 2:
            return None
        issuer_der = parts[0][2]
        serial = _uint(parts[1][1])
        for c in certs:
            if c.serial_number == serial and c.issuer.public_bytes() == issuer_der:
                return c
        return None
    if signer["sid_tag"] == 0x80:  # [0] subjectKeyIdentifier
        for c in certs:
            try:
                ski = c.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
            except x509.ExtensionNotFound:
                continue
            if ski.digest == signer["sid_val"]:
                return c
    return None
