"""
archeion/server.py — Sasana authority sealing server.

Endpoints:
  POST /seal   — Verify a session JSONL, append a signed CHAIN_SEAL, return sealed JSONL.
  GET  /pubkey — Return the server Ed25519 public key.

Run:
  uvicorn archeion.server:app --host 0.0.0.0 --port 8747

The server key is loaded from ~/.archeion/server_key.b64 on startup (generated if absent).
Override with ARCHEION_PRIVATE_KEY (base64) or ARCHEION_KEY_FILE env vars.
"""

from __future__ import annotations

import datetime
import json
import logging

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import PlainTextResponse

from archeion.keys import load_or_generate, pubkey_b64
from sasana.signing import sign_event_hash
from sasana.verifier import compute_event_hash, verify

logger = logging.getLogger("archeion")

app = FastAPI(
    title="Archeion",
    description="Sasana authority sealing server — upgrades sessions to AUTHORITATIVE_EVIDENCE.",
    version="1.0.0",
)

# Keypair is loaded once at module import so TestClient and uvicorn share the same key.
_private_key = load_or_generate()
_pubkey = pubkey_b64(_private_key)


@app.get("/health")
async def health() -> dict:
    """Liveness + readiness probe. Returns current server pubkey for key-change detection."""
    return {"status": "ok", "version": app.version, "pubkey": _pubkey}


@app.get("/pubkey")
async def get_pubkey() -> dict:
    """Return the server Ed25519 public key. Clients pin this to trust sealed sessions."""
    return {"pubkey": _pubkey, "algorithm": "ed25519", "encoding": "base64"}


@app.post("/seal", response_class=PlainTextResponse)
async def seal(request: Request) -> str:
    """
    Accept a session JSONL body, verify its hash chain, append a signed CHAIN_SEAL event,
    and return the sealed JSONL.

    Errors:
      400 — malformed or empty body.
      409 — session already carries a CHAIN_SEAL.
      422 — hash chain broken or session incomplete.
    """
    body = await request.body()
    try:
        events = [json.loads(ln) for ln in body.decode().splitlines() if ln.strip()]
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise HTTPException(status_code=400, detail=f"Invalid JSONL: {exc}")

    if not events:
        raise HTTPException(status_code=400, detail="Empty session body")

    if any(e.get("event_type") == "CHAIN_SEAL" for e in events):
        raise HTTPException(status_code=409, detail="Session is already sealed")

    result = verify(events)
    if result.status == "PARTIAL":
        raise HTTPException(
            status_code=422,
            detail=(
                f"Cannot seal: session has {result.log_drop_count} LOG_DROP event(s). "
                "Sealing a partial log would falsely imply a complete record."
            ),
        )
    if result.status != "INTACT":
        raise HTTPException(
            status_code=422,
            detail=f"Cannot seal: session is {result.status}. Errors: {result.errors[:5]}",
        )
    if not result.checks.get("completeness", {}).get("has_session_end"):
        raise HTTPException(status_code=422, detail="Cannot seal: SESSION_END not present")

    sorted_events = sorted(events, key=lambda e: e.get("seq", 0))
    last = sorted_events[-1]

    ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"
    seal_event: dict = {
        "seq": last["seq"] + 1,
        "event_type": "CHAIN_SEAL",
        "session_id": last["session_id"],
        "timestamp": ts,
        "payload": {
            "session_hash": last["event_hash"],
            "sealed_by": "archeion",
            "server_pubkey": _pubkey,
        },
        "prev_hash": last["event_hash"],
    }
    seal_event["event_hash"] = compute_event_hash(seal_event)
    seal_event["signature"] = sign_event_hash(_private_key, seal_event["event_hash"])

    logger.info("Sealed session=%s events=%d", last["session_id"], len(sorted_events) + 1)
    return "\n".join(json.dumps(e) for e in sorted_events + [seal_event]) + "\n"


def run() -> None:
    """Entry point for `archeion` CLI command."""
    import uvicorn

    uvicorn.run("archeion.server:app", host="0.0.0.0", port=8747, reload=False)
