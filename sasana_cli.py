#!/usr/bin/env python3
"""
sasana — CLI entry point.

Usage:
  sasana verify <session.jsonl>         Verify hash chain integrity
  sasana verify <session.jsonl> --json  JSON output
  sasana observe [--ws URL]             Run passive WebSocket observer
  sasana version                        Print version
"""

from __future__ import annotations

import os
import sys

_REPO_ROOT = os.path.dirname(os.path.abspath(__file__))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

VERSION = "1.0.0"


def _cmd_verify(args: list[str]) -> int:
    if not args:
        print("Usage: sasana verify <session.jsonl> [--json]", file=sys.stderr)
        return 3
    path = args[0]
    json_output = "--json" in args

    import json
    try:
        with open(path) as f:
            lines = [line.strip() for line in f if line.strip()]
    except OSError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 3

    try:
        events = [json.loads(line) for line in lines]
    except json.JSONDecodeError as e:
        print(f"ERROR: malformed JSONL: {e}", file=sys.stderr)
        return 3

    if not events:
        print("ERROR: file is empty", file=sys.stderr)
        return 3

    import verify as v
    c1 = v.check_structural_validity(events)
    c2 = v.check_sequence_integrity(events)
    c3 = v.check_hash_chain_integrity(events)
    c4 = v.check_session_completeness(events)

    all_errors = c1["errors"] + c2["errors"] + c3["errors"] + c4["errors"]
    log_drops = sum(1 for e in events if e.get("event_type") == "LOG_DROP")
    session_id = next((e.get("session_id") for e in events), None)

    if all_errors:
        status, evidence_class, exit_code = "COMPROMISED", "NO_EVIDENCE", 1
    elif log_drops > 0:
        status, evidence_class, exit_code = "PARTIAL", "PARTIAL_EVIDENCE", 2
    else:
        status, evidence_class, exit_code = "INTACT", "NON_AUTHORITATIVE_EVIDENCE", 0

    if json_output:
        print(json.dumps({"status": status, "evidence_class": evidence_class,
            "session_id": session_id, "event_count": len(events),
            "log_drop_count": log_drops, "errors": all_errors, "verifier_version": VERSION}, indent=2))
    else:
        print(f"Sasana Verifier v{VERSION}")
        print(f"File: {path}")
        if session_id:
            print(f"Session: {session_id}")
        print(f"Events: {len(events)}")
        print(f"Evidence: {evidence_class}")
        print()
        print(f"[1/4] Structural validity  ... {'PASS' if not c1['errors'] else 'FAIL'}")
        print(f"[2/4] Sequence integrity   ... {'PASS' if not c2['errors'] else 'FAIL'}")
        print(f"[3/4] Hash chain integrity ... {'PASS' if not c3['errors'] else 'FAIL'}")
        print(f"[4/4] Session completeness ... {'PASS' if not c4['errors'] else 'FAIL'}")
        print()
        if status == "INTACT":
            print("Result: INTACT ✅")
        elif status == "PARTIAL":
            print(f"Result: PARTIAL ⚠️  ({log_drops} LOG_DROP events)")
        else:
            print("Result: COMPROMISED ❌")
            for err in all_errors[:10]:
                print(f"  → {err}")
    return exit_code


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
    observer = OpenClawObserver(ws_url=ws_url, output_dir=output_dir)
    print("Sasana observer starting. Session JSONL → ~/.openclaw/sasana/")
    print("Press Ctrl-C to stop.")
    try:
        asyncio.run(observer.run())
    except KeyboardInterrupt:
        print("\nSasana observer stopped.")
    return 0


def main() -> None:
    args = sys.argv[1:]
    if not args or args[0] in ("--help", "-h", "help"):
        print(f"Sasana v{VERSION} — tamper-evident audit trail for OpenClaw sessions")
        print()
        print("USAGE:")
        print("  sasana verify <session.jsonl>           Verify hash chain")
        print("  sasana verify <session.jsonl> --json    JSON output")
        print("  sasana observe [--ws URL]               Passive WebSocket observer")
        print("  sasana version                          Print version")
        sys.exit(0)
    if args[0] in ("--version", "-V", "version"):
        print(f"sasana {VERSION}")
        sys.exit(0)
    if args[0] == "verify":
        sys.exit(_cmd_verify(args[1:]))
    if args[0] == "observe":
        sys.exit(_cmd_observe(args[1:]))
    print(f"Unknown command: {args[0]}", file=sys.stderr)
    sys.exit(3)


if __name__ == "__main__":
    main()
