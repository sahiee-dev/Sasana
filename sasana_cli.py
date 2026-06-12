#!/usr/bin/env python3
"""
sasana_cli.py — CLI entry point.

Usage:
  sasana verify <session.jsonl> [--json]
  sasana observe [--ws URL] [--output-dir DIR]
  sasana version
"""

from __future__ import annotations

import os
import sys

_ROOT = os.path.dirname(os.path.abspath(__file__))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

VERSION = "1.0.0"


def _cmd_verify(args: list[str]) -> int:
    if not args:
        print("Usage: sasana verify <session.jsonl> [--json]", file=sys.stderr)
        return 3
    import json
    path, json_out = args[0], "--json" in args
    try:
        with open(path) as f:
            lines = [l.strip() for l in f if l.strip()]
        events = [json.loads(l) for l in lines]
    except (OSError, json.JSONDecodeError) as e:
        print(f"ERROR: {e}", file=sys.stderr); return 3
    if not events:
        print("ERROR: file is empty", file=sys.stderr); return 3

    import verify as v
    c1 = v.check_structural_validity(events)
    c2 = v.check_sequence_integrity(events)
    c3 = v.check_hash_chain_integrity(events)
    c4 = v.check_session_completeness(events)
    errs = c1["errors"] + c2["errors"] + c3["errors"] + c4["errors"]
    drops = sum(1 for e in events if e.get("event_type") == "LOG_DROP")
    sid = next((e.get("session_id") for e in events), None)
    status = "COMPROMISED" if errs else ("PARTIAL" if drops else "INTACT")
    ev_cls = "NO_EVIDENCE" if errs else ("PARTIAL_EVIDENCE" if drops else "NON_AUTHORITATIVE_EVIDENCE")
    code = 1 if errs else (2 if drops else 0)

    if json_out:
        print(json.dumps({"status": status, "evidence_class": ev_cls, "session_id": sid,
            "event_count": len(events), "log_drop_count": drops, "errors": errs,
            "verifier_version": VERSION}, indent=2))
    else:
        print(f"Sasana Verifier v{VERSION}")
        print(f"File: {path}")
        if sid: print(f"Session: {sid}")
        print(f"Events: {len(events)}  Evidence: {ev_cls}")
        print()
        for lbl, chk in [("[1/4] Structural validity ", c1), ("[2/4] Sequence integrity  ", c2),
                         ("[3/4] Hash chain integrity", c3), ("[4/4] Session completeness", c4)]:
            print(f"{lbl} ... {'PASS' if not chk['errors'] else 'FAIL'}")
        print()
        if status == "INTACT": print("Result: INTACT ✅")
        elif status == "PARTIAL": print(f"Result: PARTIAL ⚠️  ({drops} LOG_DROP events)")
        else:
            print("Result: COMPROMISED ❌")
            for e in errs[:10]: print(f"  → {e}")
    return code


def _cmd_observe(args: list[str]) -> int:
    import asyncio
    from sasana.observer import OpenClawObserver
    ws_url = output_dir = None
    i = 0
    while i < len(args):
        if args[i] == "--ws" and i + 1 < len(args):
            ws_url = args[i + 1]; i += 2
        elif args[i] == "--output-dir" and i + 1 < len(args):
            output_dir = args[i + 1]; i += 2
        else:
            i += 1
    print("Sasana observer → ~/.openclaw/sasana/  (Ctrl-C to stop)")
    try:
        asyncio.run(OpenClawObserver(ws_url=ws_url, output_dir=output_dir).run())
    except KeyboardInterrupt:
        print("\nStopped.")
    return 0


def main() -> None:
    args = sys.argv[1:]
    if not args or args[0] in ("--help", "-h", "help"):
        print(f"Sasana v{VERSION} — tamper-evident audit trail for OpenClaw sessions")
        print("\nUSAGE:")
        print("  sasana verify <session.jsonl> [--json]   Verify hash chain")
        print("  sasana observe [--ws URL]                Passive WebSocket observer")
        print("  sasana version                           Print version")
        sys.exit(0)
    if args[0] in ("--version", "-V", "version"):
        print(f"sasana {VERSION}"); sys.exit(0)
    if args[0] == "verify":
        sys.exit(_cmd_verify(args[1:]))
    if args[0] == "observe":
        sys.exit(_cmd_observe(args[1:]))
    print(f"Unknown command: {args[0]}", file=sys.stderr); sys.exit(3)


if __name__ == "__main__":
    main()
