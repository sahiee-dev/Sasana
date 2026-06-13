"""
signing.py — Ed25519 signing primitives for Sasana sessions.

Per-session keypair: public key embedded in SESSION_START,
verifier is self-contained — no external key registry needed.
"""

from __future__ import annotations

import base64

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.exceptions import InvalidSignature


def generate_keypair() -> tuple[Ed25519PrivateKey, str]:
    """Generate a fresh Ed25519 keypair. Returns (private_key, public_key_b64)."""
    private_key = Ed25519PrivateKey.generate()
    public_key_b64 = base64.b64encode(private_key.public_key().public_bytes_raw()).decode()
    return private_key, public_key_b64


def sign_event_hash(private_key: Ed25519PrivateKey, event_hash_hex: str) -> str:
    """Sign event_hash with session private key. Returns base64-encoded signature."""
    return base64.b64encode(private_key.sign(event_hash_hex.encode("utf-8"))).decode()


def verify_signature(public_key_b64: str, event_hash_hex: str, signature_b64: str) -> bool:
    """Verify an Ed25519 signature against an event_hash."""
    try:
        pub = Ed25519PublicKey.from_public_bytes(base64.b64decode(public_key_b64))
        pub.verify(base64.b64decode(signature_b64), event_hash_hex.encode("utf-8"))
        return True
    except (InvalidSignature, Exception):
        return False
