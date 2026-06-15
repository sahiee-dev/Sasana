"""
sasana/rfc3161.py — RFC 3161 trusted timestamp anchoring.

Sends the SHA-256 hash of SESSION_START to a public TSA (Freetsa by default)
and verifies returned tokens. The TSA receives only a hash — never session content.

TSA endpoint is configurable via SASANA_TSA_URL env var. Default: Freetsa.
Network failure is fail-open: the session proceeds without a timestamp token.
"""

from __future__ import annotations

import logging
import os
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Optional

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


def build_timestamp_request(hash_bytes: bytes) -> bytes:
    """Build a DER-encoded RFC 3161 TimeStampReq for a SHA-256 hash."""
    msg_imprint = _seq(_SHA256_ALG_ID + _octet(hash_bytes))
    # version=1, messageImprint, certReq=TRUE (include cert in response for offline verification)
    return _seq(_int_der(1) + msg_imprint + _bool_der(True))


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


def request_timestamp(hash_bytes: bytes) -> Optional[bytes]:
    """
    Submit hash_bytes to the configured TSA. Returns raw DER response, or None on failure.

    Configurable via SASANA_TSA_URL env var (default: https://freetsa.org/tsr).
    Only a 32-byte hash is transmitted — no session content ever leaves the machine.
    """
    url = os.environ.get("SASANA_TSA_URL", _DEFAULT_TSA_URL)
    req_der = build_timestamp_request(hash_bytes)
    try:
        http_req = urllib.request.Request(
            url,
            data=req_der,
            headers={"Content-Type": "application/timestamp-query"},
            method="POST",
        )
        with urllib.request.urlopen(http_req, timeout=10) as resp:
            if resp.status != 200:
                logger.warning("Sasana RFC 3161: TSA returned HTTP %d — session proceeds without timestamp", resp.status)
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
