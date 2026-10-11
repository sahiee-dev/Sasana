#!/usr/bin/env python3
"""
Run the real `sasana verify-commitment` CLI over every synthetic bundle in bundles/ and print

    bundle | expected | actual | match

Exit code 0 only if every bundle matches expected.json. Nothing here touches the network.

    python3 examples/ha-reveal/run.py            # from a checkout, or with `pip install sasana`
    python3 examples/ha-reveal/run.py --only d-initial-omitted --verbose
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]


def run_one(name: str, trust: dict, extra: list) -> dict:
    d = HERE / "bundles" / name
    cmd = [
        sys.executable,
        "-m",
        "sasana_cli",
        "verify-commitment",
        str(d / "bundle.json"),
        "--deadline",
        trust["deadline"],
        "--tsa-anchor",
        str(HERE / "trust" / "tsa-anchor.pem"),
        "--receipts",
        str(d / "receipts.json"),
        "--receipt-key",
        trust["receipt_pubkey"],
        "--mapping",
        trust["mapping_id"],
        "--trust-key",
        trust["seal_pubkey"],
        "--json",
        *extra,
    ]
    cwd = REPO if (REPO / "sasana_cli.py").exists() else None
    env = {**os.environ, "NO_COLOR": "1"}
    r = subprocess.run(cmd, capture_output=True, text=True, cwd=cwd, env=env)
    try:
        data = json.loads(r.stdout)
    except json.JSONDecodeError:
        data = {"verdict": "CLI-ERROR", "errors": [r.stderr.strip()], "warnings": []}
    return {"exit": r.returncode, "data": data}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", action="append", default=[])
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()
    trust = json.loads((HERE / "trust" / "trust.json").read_text())
    expected = json.loads((HERE / "expected.json").read_text())
    names = [n for n in sorted(expected) if not args.only or n in args.only]

    rows, all_ok = [], True
    for name in names:
        exp = expected[name]
        got = run_one(name, trust, [])
        data = got["data"]
        text = " | ".join(map(str, data.get("errors", []) + data.get("warnings", [])))
        ok = (
            data.get("verdict") == exp["verdict"]
            and data.get("effective_revision") == exp["effective_revision"]
            and got["exit"] == exp["exit"]
            and exp.get("contains", "") in text
        )
        all_ok &= ok
        fmt = lambda v, r, e: f"{v} rev={r} exit={e}"  # noqa: E731
        rows.append(
            (
                name,
                fmt(exp["verdict"], exp["effective_revision"], exp["exit"]),
                fmt(data.get("verdict"), data.get("effective_revision"), got["exit"]),
                "yes" if ok else "NO",
                text,
            )
        )
    w = [
        max(len(r[i]) for r in rows + [("bundle", "expected", "actual", "match", "")])
        for i in range(4)
    ]
    head = ("bundle", "expected", "actual", "match")
    print(" | ".join(h.ljust(w[i]) for i, h in enumerate(head)))
    print("-+-".join("-" * x for x in w))
    for r in rows:
        print(" | ".join(r[i].ljust(w[i]) for i in range(4)))
        if args.verbose or r[3] == "NO":
            for part in r[4].split(" | "):
                if part:
                    print(f"    {part[:160]}")
    print(f"\n{sum(r[3] == 'yes' for r in rows)}/{len(rows)} bundles match expected")
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
