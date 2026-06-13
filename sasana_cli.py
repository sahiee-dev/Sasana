#!/usr/bin/env python3
"""
sasana_cli.py — CLI entry point.

Usage:
  sasana verify <session.jsonl> [--json]
  sasana observe [--ws URL] [--output-dir DIR]
  sasana version
"""

from __future__ import annotations

import argparse
import json
import os
import sys

_ROOT = os.path.dirname(os.path.abspath(__file__))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

VERSION = "1.0.0"


def _cmd_verify(args: list) -> int:
    if not args:
        print("Usage: sasana verify <session.jsonl> [--json]", file=sys.stderr)
        return 3

    ap = argparse.ArgumentParser(prog="sasana verify", add_help=False)
    ap.add_argument("session_file")
    ap.add_argument("--json", dest="json_out", action="store_true")
    parsed, _ = ap.parse_known_args(args)

    try:
        with open(parsed.session_file) as f:
            events = [json.loads(line) for line in f if line.strip()]
    except FileNotFoundError:
        print(f"ERROR: file not found: {parsed.session_file}", file=sys.stderr)
        return 3
    except (OSError, json.JSONDecodeError) as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 3

    from sasana.verifier import verify, VERIFIER_VERSION

    result = verify(events)

    if parsed.json_out:
        print(
            json.dumps(
                {
                    "status": result.status,
                    "evidence_class": result.evidence_class,
                    "session_id": result.session_id,
                    "event_count": result.event_count,
                    "log_drop_count": result.log_drop_count,
                    "root_hash": result.root_hash,
                    "errors": result.errors,
                    "verifier_version": VERIFIER_VERSION,
                },
                indent=2,
            )
        )
    else:
        print(f"Sasana Verifier v{VERIFIER_VERSION}")
        print(f"File: {parsed.session_file}")
        if result.session_id:
            print(f"Session: {result.session_id}")
        print(f"Events: {result.event_count}  Evidence: {result.evidence_class}")
        print()
        for label, key in [
            ("[1/5] Structural validity ", "structural"),
            ("[2/5] Sequence integrity  ", "sequence"),
            ("[3/5] Hash chain integrity", "hash_chain"),
            ("[4/5] Session completeness", "completeness"),
            ("[5/5] Seal signature      ", "seal_signature"),
        ]:
            r = result.checks.get(key)
            st = r["status"] if r else "SKIPPED"
            print(f"{label} ... {st}")
        print()
        if result.status == "INTACT":
            print("Result: INTACT ✅")
        elif result.status == "PARTIAL":
            print(f"Result: PARTIAL ⚠️  ({result.log_drop_count} LOG_DROP events)")
        elif result.status == "COMPROMISED":
            print("Result: COMPROMISED ❌")
            for err in result.errors[:10]:
                print(f"  → {err}")
        else:
            print("Result: ERROR ❌")
            for err in result.errors[:10]:
                print(f"  → {err}")

    return {"INTACT": 0, "PARTIAL": 2, "COMPROMISED": 1, "ERROR": 3}.get(result.status, 3)


def _cmd_seal(args: list) -> int:
    ap = argparse.ArgumentParser(prog="sasana seal", add_help=False)
    ap.add_argument("session_file")
    ap.add_argument("--server", default="http://localhost:8747", metavar="URL")
    ap.add_argument("--out", default=None, metavar="FILE")
    parsed, _ = ap.parse_known_args(args)

    try:
        body = open(parsed.session_file, "rb").read()
    except FileNotFoundError:
        print(f"ERROR: file not found: {parsed.session_file}", file=sys.stderr)
        return 3

    import urllib.error
    import urllib.request

    url = parsed.server.rstrip("/") + "/seal"
    req = urllib.request.Request(
        url, data=body, method="POST", headers={"Content-Type": "application/x-ndjson"}
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            sealed = resp.read()
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode(errors="replace")
        print(f"ERROR: Archeion returned {exc.code}: {detail}", file=sys.stderr)
        return 1
    except urllib.error.URLError as exc:
        print(f"ERROR: cannot reach Archeion at {url}: {exc.reason}", file=sys.stderr)
        return 3

    out_path = parsed.out or parsed.session_file
    with open(out_path, "wb") as f:
        f.write(sealed)

    print(f"Sealed → {out_path}")
    return 0


def _cmd_observe(args: list) -> int:
    import asyncio

    ap = argparse.ArgumentParser(prog="sasana observe")
    ap.add_argument("--ws", dest="ws_url", default=None, metavar="URL")
    ap.add_argument("--output-dir", dest="output_dir", default=None, metavar="DIR")
    parsed = ap.parse_args(args)

    from sasana.observer import OpenClawObserver

    print("Sasana observer → ~/.openclaw/sasana/  (Ctrl-C to stop)")
    try:
        asyncio.run(OpenClawObserver(ws_url=parsed.ws_url, output_dir=parsed.output_dir).run())
    except KeyboardInterrupt:
        print("\nStopped.")
    return 0


def main() -> None:
    args = sys.argv[1:]
    if not args or args[0] in ("--help", "-h", "help"):
        print(f"Sasana v{VERSION} — tamper-evident audit trail for OpenClaw sessions")
        print("\nUSAGE:")
        print("  sasana verify <session.jsonl> [--json]          Verify hash chain")
        print("  sasana seal   <session.jsonl> [--server URL]    Submit to Archeion for sealing")
        print("  sasana observe [--ws URL]                       Passive WebSocket observer")
        print("  sasana version                                  Print version")
        sys.exit(0)
    if args[0] in ("--version", "-V", "version"):
        print(f"sasana {VERSION}")
        sys.exit(0)
    if args[0] == "verify":
        sys.exit(_cmd_verify(args[1:]))
    if args[0] == "seal":
        sys.exit(_cmd_seal(args[1:]))
    if args[0] == "observe":
        sys.exit(_cmd_observe(args[1:]))
    print(f"Unknown command: {args[0]}", file=sys.stderr)
    sys.exit(3)


if __name__ == "__main__":
    main()
