#!/usr/bin/env python3
"""
Generate golden session logs using the code of a PUBLISHED Sasana release.

    python generate_legacy_fixtures.py <path-to-release-source-tree> <release-label> <out-dir>

<path-to-release-source-tree> is an unpacked copy of the release (``git archive <commit> |
tar -x -C <dir>`` or an unzipped PyPI wheel). Its ``sasana`` and ``archeion`` packages are
imported — NOT the ones in this repository — so the bytes on disk are exactly what that
release wrote. See README.md in this directory for how each committed fixture was produced.

Writes, for the release label (e.g. ``v1.1.0``):
    <label>_unsealed.jsonl      plain hash-chained session
    <label>_signed.jsonl        per-event Ed25519 signatures (session key in SESSION_START)
    <label>_sealed.jsonl        sealed by that release's Archeion (throwaway key)
    <label>_timestamped.jsonl   SESSION_START carries an RFC 3161 token (offline test TSA)
and a ``<label>_meta.json`` with the throwaway Archeion public key.

The payloads deliberately contain the values that distinguish canonicalizations: ordinary
whole-number floats (0.0, 100.0, 1200.0), negative zero, exponent-form floats, integers beyond
2**53 and beyond 2**63, unicode, and nested objects with unsorted keys.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

tree, label, out_dir = Path(sys.argv[1]).resolve(), sys.argv[2], Path(sys.argv[3]).resolve()
out_dir.mkdir(parents=True, exist_ok=True)

# Never touch a real key; never reach a real TSA (the ledger is fail-open and would try).
os.environ["ARCHEION_KEY_FILE"] = str(Path(tempfile.mkdtemp(prefix="sasana-fixture-")) / "k.b64")
os.environ.pop("ARCHEION_PRIVATE_KEY", None)
os.environ["SASANA_TSA_URL"] = "http://127.0.0.1:9/"

sys.path.insert(0, str(tree))
sys.path.append(str(Path(__file__).resolve().parents[2]))  # tests/ for tsa_fixture

import sasana  # noqa: E402

assert Path(sasana.__file__).resolve().is_relative_to(tree), (
    f"imported sasana from {sasana.__file__}, expected it under {tree}"
)

from sasana.signing import generate_keypair  # noqa: E402
from sasana.sqlite_ledger import SqliteLedger  # noqa: E402

H = {c: c * 64 for c in "abcdef"}


def record_session(ledger: SqliteLedger, session_id: str) -> None:
    ledger.open_session(
        session_id=session_id,
        agent_id="golden-agent",
        metadata={
            "model": "ünïcode-model ☃ 😀",
            "labels": {"z": 1, "a": [1, 2.0, {"y": -0.0, "b": "שלום"}], "m": None},
        },
    )
    ledger.record(
        "LLM_CALL",
        {
            "prompt_hash": H["a"],
            "temperature": 0.0,
            "top_p": 1.0,
            "max_tokens": 1200,
            "params": {"stop": ["\n", "é"], "nested": {"deep": {"x": [0.5, 100.0, 1e-05]}}},
        },
    )
    ledger.record(
        "LLM_RESPONSE",
        {
            "content_hash": H["b"],
            "duration_ms": 1200.0,
            "latency_s": 100.0,
            "cost_usd": 0.0,
            "neg_zero": -0.0,
            "ratio": 0.1,
            "precise": 1234.5678,
            "tiny": 1.5e-07,
            "huge": 1e21,
            "wide": 1e16,
            "int_beyond_2_53": 9007199254740993,
            "int_u64": 12345678901234567890,
            "int_2_63": 9223372036854775808,
            "text": "Grüße, 世界 — “quotes” \\ \t tab / slash",
        },
    )
    ledger.record("TOOL_CALL", {"tool_name": "bash", "args_hash": H["c"], "timeout_s": 30.0})
    ledger.record("TOOL_RESULT", {"tool_name": "bash", "result_hash": H["d"], "exit_code": 0})
    ledger.record("TOOL_ERROR", {"tool_name": "curl", "error_type": "Timeout", "after_s": 2.5})
    ledger.close_session(status="success")


def build(name: str, session_id: str, **ledger_kwargs) -> list:
    db = Path(tempfile.mkdtemp(prefix="sasana-fixture-db-")) / f"{name}.db"
    ledger = SqliteLedger(db_path=db, **ledger_kwargs)
    ledger.connect()
    return ledger, db


def export(ledger: SqliteLedger, name: str) -> Path:
    path = out_dir / f"{label}_{name}.jsonl"
    ledger.export_jsonl(path)
    ledger.close()
    return path


def main() -> None:
    # unsealed
    ledger, _ = build("unsealed", f"golden-{label}-unsealed")
    record_session(ledger, f"golden-{label}-unsealed")
    unsealed = export(ledger, "unsealed")

    # per-event signed
    private_key, session_pubkey = generate_keypair()
    ledger, _ = build("signed", f"golden-{label}-signed", private_key=private_key)
    record_session(ledger, f"golden-{label}-signed")
    export(ledger, "signed")

    # sealed by this release's Archeion with a throwaway key
    from fastapi.testclient import TestClient

    from archeion.server import app

    client = TestClient(app)
    archeion_pubkey = client.get("/pubkey").json()["pubkey"]
    ledger, _ = build("sealed", f"golden-{label}-sealed")
    record_session(ledger, f"golden-{label}-sealed")
    raw = export(ledger, "sealed").read_bytes()
    resp = client.post("/seal", content=raw)
    assert resp.status_code == 200, resp.text
    (out_dir / f"{label}_sealed.jsonl").write_text(resp.text)

    # timestamped: patch the release's TSA request with an offline throwaway TSA
    import tsa_fixture as fx
    import sasana.rfc3161 as rfc

    authority = fx.make_authority()
    rfc.request_timestamp = lambda h, **kw: fx.respond(authority, h)
    ledger, _ = build("timestamped", f"golden-{label}-timestamped")
    record_session(ledger, f"golden-{label}-timestamped")
    export(ledger, "timestamped")

    meta = {
        "label": label,
        "sasana_version_imported": getattr(sasana, "__version__", "?"),
        "release_tree": tree.name,
        "archeion_pubkey": archeion_pubkey,
        "session_pubkey_signed_fixture": session_pubkey,
    }
    (out_dir / f"{label}_meta.json").write_text(json.dumps(meta, indent=2) + "\n")
    for p in sorted(out_dir.glob(f"{label}_*")):
        print(p.name, p.stat().st_size, "bytes")
    assert unsealed.exists()


main()
