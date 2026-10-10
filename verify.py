#!/usr/bin/env python3
"""
verify.py — `agentops-verify`, the legacy standalone entry point.

A thin alias for `sasana verify`: one implementation, so the two can never disagree about
what a verdict means. See `sasana verify --help` or the README for flags and exit codes.

Usage:
  python3 verify.py <session.jsonl> [--json] [--trust-key KEY] [--require-seal] [--strict]
                    [--verbose]

Exit codes: 0=INTACT  1=COMPROMISED  2=PARTIAL  3=ERROR/usage  4=--strict and not AUTHORITATIVE
"""

from __future__ import annotations

import sys


def main() -> None:
    from sasana_cli import _cmd_verify

    sys.exit(_cmd_verify(sys.argv[1:]))


if __name__ == "__main__":
    main()
