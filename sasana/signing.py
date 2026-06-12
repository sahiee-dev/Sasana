"""
signing.py — Ed25519 signing primitives for Sasana sessions.

Every event envelope carries an Ed25519 signature over its event_hash.
The session's public key is embedded in SESSION_START so the verifier
is self-contained — no external key registry needed.
"""
from __future__ import annotations

import base64

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.exceptions import InvalidSignature


def generate_keypair() -> tuple[Ed25519PrivateKey, str]:
    """Generate a fresh Ed25519 keypair. Returns (private_key, public_key_b64)."""
    private_key = Ed25519PrivateKey.generate()
    public_key_b64 = base64.b64encode(
        private_key.public_key().public_bytes_raw()
    ).decode()
    return private_key, public_key_b64


def sign_event_hash(private_key: Ed25519PrivateKey, event_hash_hex: str) -> str:
    """Sign event_hash with session private key. Returns base64-encoded signature."""
    signature_bytes = private_key.sign(event_hash_hex.encode("utf-8"))
    return base64.b64encode(signature_bytes).decode()


def verify_signature(
    public_key_b64: str,
    event_hash_hex: str,
    signature_b64: str,
) -> bool:
    """Verify an Ed25519 signature against an event_hash. Returns True if valid."""
    try:
        public_bytes = base64.b64decode(public_key_b64)
        public_key = Ed25519PublicKey.from_public_bytes(public_bytes)
        signature = base64.b64decode(signature_b64)
        public_key.verify(signature, event_hash_hex.encode("utf-8"))
        return True
    except (InvalidSignature, Exception):
        return False
