"""
archeion/keys.py — Persistent Ed25519 server keypair.

Storage priority:
  1. ARCHEION_PRIVATE_KEY env var (base64 raw bytes) — for containers / CI.
  2. ARCHEION_KEY_FILE env var path.
  3. ~/.archeion/server_key.b64 — default persistent location.

A new keypair is generated and persisted when none of the above exist.
"""

from __future__ import annotations

import base64
import os
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

_DEFAULT_KEY_FILE = Path.home() / ".archeion" / "server_key.b64"


def _key_path() -> Path:
    return Path(os.environ.get("ARCHEION_KEY_FILE", str(_DEFAULT_KEY_FILE)))


def load_or_generate() -> Ed25519PrivateKey:
    """Return the server private key, generating and persisting one if absent."""
    raw_b64 = os.environ.get("ARCHEION_PRIVATE_KEY")
    if raw_b64:
        return Ed25519PrivateKey.from_private_bytes(base64.b64decode(raw_b64))

    key_path = _key_path()
    if key_path.exists():
        return Ed25519PrivateKey.from_private_bytes(base64.b64decode(key_path.read_text().strip()))

    private_key = Ed25519PrivateKey.generate()
    key_path.parent.mkdir(parents=True, exist_ok=True)
    key_path.write_text(base64.b64encode(private_key.private_bytes_raw()).decode())
    key_path.chmod(0o600)
    return private_key


def pubkey_b64(private_key: Ed25519PrivateKey) -> str:
    """Return the base64-encoded raw public key bytes."""
    return base64.b64encode(private_key.public_key().public_bytes_raw()).decode()
