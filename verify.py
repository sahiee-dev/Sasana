#!/usr/bin/env python3
"""
verify.py — Standalone verifier for Sasana session logs.

Usage:
  python3 verify.py <session.jsonl> [--format {text,json}] [--verbose]

Exit codes: 0=INTACT  1=COMPROMISED  2=PARTIAL  3=ERROR
"""

from __future__ import annotations

import argparse
import json
import sys

from sasana.verifier import (
    INTACT,
    PARTIAL,
    verify,
    VERIFIER_VERSION,
)


def main() -> None:
    parser = argparse.ArgumentParser(description=f"Sasana Verifier v{VERIFIER_VERSION}")
    parser.add_argument("session_file")
    parser.add_argument("--format", choices=["text", "json"], default="text")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    try:
        with open(args.session_file) as f:
            raw = f.read()
    except (FileNotFoundError, OSError) as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(3)

    events: list = []
    try:
        for line in raw.splitlines():
            line = line.strip()
            if line:
                events.append(json.loads(line))
    except json.JSONDecodeError as e:
        print(f"ERROR: malformed JSONL: {e}", file=sys.stderr)
        sys.exit(3)

    result = verify(events)

    if args.format == "json":
        print(
            json.dumps(
                {
                    "verifier_version": VERIFIER_VERSION,
                    "session_id": result.session_id,
                    "event_count": result.event_count,
                    "evidence_class": result.evidence_class,
                    "status": result.status,
                    "log_drop_count": result.log_drop_count,
                    "root_hash": result.root_hash,
                    "errors": result.errors,
                },
                indent=2,
            )
        )
    else:
        print(f"Sasana Verifier v{VERIFIER_VERSION}")
        print("=" * 32)
        print(f"File     : {args.session_file}")
        print(f"Session  : {result.session_id or 'unknown'}")
        print(f"Events   : {result.event_count}")
        print(f"Evidence : {result.evidence_class}")
        print()
        for label, key in [
            ("[1/4] Structural validity ", "structural"),
            ("[2/4] Sequence integrity  ", "sequence"),
            ("[3/4] Hash chain integrity", "hash_chain"),
            ("[4/4] Session completeness", "completeness"),
        ]:
            r = result.checks.get(key)
            st = r["status"] if r else "SKIPPED"
            print(f"{label} ... {st}")
            if args.verbose and r and r.get("errors"):
                for err in r["errors"]:
                    print(f"      {err}")
        print()
        if result.status == INTACT:
            print("Result: INTACT ✅")
        elif result.status == PARTIAL:
            print(f"Result: PARTIAL ⚠️  ({result.log_drop_count} LOG_DROP events)")
        else:
            label = "COMPROMISED" if result.status == "COMPROMISED" else "ERROR"
            print(f"Result: {label} ❌")
            for err in result.errors[:10]:
                print(f"  → {err}")

    sys.exit({"INTACT": 0, "PARTIAL": 2, "COMPROMISED": 1, "ERROR": 3}.get(result.status, 3))


if __name__ == "__main__":
    main()
