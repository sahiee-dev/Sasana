"""
tests/rust_bin.py — locate the compiled sasana-rs verifier for cross-implementation tests.

Locally the binary is optional: tests that need it skip with a clear message. In CI (the ``CI``
environment variable is set by GitHub Actions) a missing binary is a FAILURE, not a skip — the
Python and Rust verifiers agreeing on every fixture is a release gate, and a skipped gate looks
exactly like a passing one.
"""

from __future__ import annotations

import json
import os
import subprocess
import unittest
from pathlib import Path
from typing import Optional

_ROOT = Path(__file__).parent.parent


def rust_binary() -> Optional[Path]:
    override = os.environ.get("SASANA_RS_BIN")
    candidates = [Path(override)] if override else []
    candidates += [_ROOT / "sasana-rs" / "target" / d / "sasana" for d in ("debug", "release")]
    return next((c for c in candidates if c.is_file()), None)


def require_rust_binary() -> Path:
    """Return the binary, or skip locally / fail in CI."""
    binary = rust_binary()
    if binary is not None:
        return binary
    msg = "sasana-rs binary not built (cargo build --manifest-path sasana-rs/Cargo.toml)"
    if os.environ.get("CI"):
        raise AssertionError(f"{msg}; CI must build it so the cross-implementation gate runs")
    raise unittest.SkipTest(msg)


def rust_verify(path, trust_key=None, require_seal=False, strict=False):
    """Run the Rust verifier. Returns (exit_code, parsed --json or {}, stdout, stderr)."""
    cmd = [str(require_rust_binary()), "verify", str(path), "--json"]
    if trust_key:
        cmd += ["--trust-key", trust_key]
    if require_seal:
        cmd += ["--require-seal"]
    if strict:
        cmd += ["--strict"]
    r = subprocess.run(cmd, capture_output=True, text=True)
    try:
        data = json.loads(r.stdout)
    except json.JSONDecodeError:
        data = {}
    return r.returncode, data, r.stdout, r.stderr
