"""
tests/tsa_fixture.py — a local RFC 3161 Time-Stamp Authority for tests.

Produces genuine CMS-signed TimeStampResp DER (RSA PKCS#1 v1.5 / SHA-256) from a
throwaway CA, so the strict verifier's signature, chain, EKU, nonce and
accuracy logic is exercised against real cryptography with no network access.
Not a test module itself (no `test_` prefix).
"""

from __future__ import annotations

import datetime as _dt
from dataclasses import dataclass, field
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from sasana.rfc3161 import _SHA256_ALG_ID, _TSTINFO_OID_VALUE, _dlen, _int_der, _octet, _seq

_UTC = _dt.timezone.utc
_OID_SIGNED_DATA = bytes.fromhex("2a864886f70d010702")
_OID_CONTENT_TYPE = bytes.fromhex("2a864886f70d010903")
_OID_MESSAGE_DIGEST = bytes.fromhex("2a864886f70d010904")
_RSA_ENC_ALG_ID = bytes.fromhex("300d06092a864886f70d0101010500")


def _tlv(tag: int, body: bytes) -> bytes:
    return bytes([tag]) + _dlen(len(body)) + body


def _set(body: bytes) -> bytes:
    return _tlv(0x31, body)


def _oid_value(dotted: str) -> bytes:
    arcs = [int(a) for a in dotted.split(".")]
    out = bytearray([arcs[0] * 40 + arcs[1]])
    for a in arcs[2:]:
        chunk = [a & 0x7F]
        a >>= 7
        while a:
            chunk.append(0x80 | (a & 0x7F))
            a >>= 7
        out.extend(reversed(chunk))
    return bytes(out)


def _oid(dotted: str) -> bytes:
    return _tlv(0x06, _oid_value(dotted))


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


@dataclass
class Authority:
    """A CA (optionally with an intermediate) plus one TSA signing certificate."""

    key: rsa.RSAPrivateKey
    cert: x509.Certificate
    anchor: x509.Certificate  # what a verifier would pin (the root)
    chain: list = field(default_factory=list)  # intermediates to embed, leaf-ward last

    @property
    def anchor_der(self) -> bytes:
        return self.anchor.public_bytes(serialization.Encoding.DER)


def _make_cert(
    subject: x509.Name,
    issuer: x509.Name,
    pub,
    signing_key,
    *,
    ca: bool,
    eku: bool,
    not_before: _dt.datetime,
    not_after: _dt.datetime,
) -> x509.Certificate:
    b = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(pub)
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(pub), critical=False)
    )
    if eku:
        b = b.add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.TIME_STAMPING]), critical=True
        )
    return b.sign(signing_key, hashes.SHA256())


def make_authority(
    *,
    with_eku: bool = True,
    intermediate: bool = False,
    valid_from: Optional[_dt.datetime] = None,
    valid_to: Optional[_dt.datetime] = None,
) -> Authority:
    nb = valid_from or _dt.datetime(2020, 1, 1, tzinfo=_UTC)
    na = valid_to or _dt.datetime(2040, 1, 1, tzinfo=_UTC)
    root_key = rsa.generate_private_key(65537, 2048)
    root = _make_cert(
        _name("Test Root CA"),
        _name("Test Root CA"),
        root_key.public_key(),
        root_key,
        ca=True,
        eku=False,
        not_before=nb,
        not_after=na,
    )
    issuer_key, issuer_name = root_key, _name("Test Root CA")
    chain: list = []
    if intermediate:
        ikey = rsa.generate_private_key(65537, 2048)
        icert = _make_cert(
            _name("Test Intermediate CA"),
            issuer_name,
            ikey.public_key(),
            issuer_key,
            ca=True,
            eku=False,
            not_before=nb,
            not_after=na,
        )
        issuer_key, issuer_name = ikey, _name("Test Intermediate CA")
        chain.append(icert)
    tsa_key = rsa.generate_private_key(65537, 2048)
    tsa_cert = _make_cert(
        _name("Test TSA"),
        issuer_name,
        tsa_key.public_key(),
        issuer_key,
        ca=False,
        eku=with_eku,
        not_before=nb,
        not_after=na,
    )
    return Authority(key=tsa_key, cert=tsa_cert, anchor=root, chain=chain)


def _generalized_time(t: _dt.datetime) -> bytes:
    text = t.astimezone(_UTC).strftime("%Y%m%d%H%M%S")
    if t.microsecond:
        text += "." + f"{t.microsecond:06d}".rstrip("0")
    return _tlv(0x18, (text + "Z").encode("ascii"))


def respond(
    auth: Authority,
    hash_bytes: bytes,
    *,
    gen_time: Optional[_dt.datetime] = None,
    nonce: Optional[int] = None,
    accuracy: Optional[tuple] = (1, None, None),  # (seconds, millis, micros)
    policy: str = "1.2.3.4.5",
    sid: str = "issuer",  # "issuer" | "ski"
    embed_certs: bool = True,
    status: int = 0,
    tamper_signature: bool = False,
) -> bytes:
    """Build a TimeStampResp for hash_bytes, signed by auth's TSA key."""
    gen_time = gen_time or _dt.datetime(2026, 6, 15, 10, 32, 11, 250000, tzinfo=_UTC)

    tst = _int_der(1) + _oid(policy) + _seq(_SHA256_ALG_ID + _octet(hash_bytes))
    tst += _int_der(0x1234) + _generalized_time(gen_time)
    if accuracy is not None:
        secs, ms, us = accuracy
        acc = b""
        if secs is not None:
            acc += _int_der(secs)
        if ms is not None:
            acc += _tlv(0x80, bytes([ms >> 8, ms & 0xFF]) if ms > 255 else bytes([ms]))
        if us is not None:
            acc += _tlv(0x81, bytes([us >> 8, us & 0xFF]) if us > 255 else bytes([us]))
        tst += _seq(acc)
    if nonce is not None:
        tst += _int_der(nonce)
    tstinfo = _seq(tst)

    digest = hashes.Hash(hashes.SHA256())
    digest.update(tstinfo)
    md = digest.finalize()

    attrs = _seq(_oid("1.2.840.113549.1.9.3") + _set(_tlv(0x06, _TSTINFO_OID_VALUE)))
    attrs += _seq(_oid("1.2.840.113549.1.9.4") + _set(_octet(md)))
    signature = auth.key.sign(_set(attrs), padding.PKCS1v15(), hashes.SHA256())
    if tamper_signature:
        signature = signature[:-1] + bytes([signature[-1] ^ 0x01])

    if sid == "ski":
        ski = auth.cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value.digest
        sid_der = _tlv(0x80, ski)
    else:
        sid_der = _seq(auth.cert.issuer.public_bytes() + _int_der(auth.cert.serial_number))

    signer_info = _seq(
        _int_der(1 if sid == "issuer" else 3)
        + sid_der
        + _SHA256_ALG_ID
        + _tlv(0xA0, attrs)
        + _RSA_ENC_ALG_ID
        + _octet(signature)
    )

    certs_der = b""
    if embed_certs:
        for c in [auth.cert, *auth.chain]:
            certs_der += c.public_bytes(serialization.Encoding.DER)
    signed_data = _seq(
        _int_der(3)
        + _set(_SHA256_ALG_ID)
        + _seq(_tlv(0x06, _TSTINFO_OID_VALUE) + _tlv(0xA0, _octet(tstinfo)))
        + (_tlv(0xA0, certs_der) if certs_der else b"")
        + _set(signer_info)
    )
    content_info = _seq(_tlv(0x06, _OID_SIGNED_DATA) + _tlv(0xA0, signed_data))
    return _seq(_seq(_int_der(status)) + content_info)
