"""
tests/conftest.py — keep the test suite away from real signing keys.

archeion.server loads its signing key at import time. Without this guard, importing it
from a test reads (or, if absent, creates) ~/.archeion/server_key.b64 — the developer's
real Archeion key. Point it at a throwaway temp file before any test module is imported.
"""

import os
import tempfile

_KEY_DIR = tempfile.mkdtemp(prefix="sasana-test-archeion-")
os.environ["ARCHEION_KEY_FILE"] = os.path.join(_KEY_DIR, "server_key.b64")
os.environ.pop("ARCHEION_PRIVATE_KEY", None)
