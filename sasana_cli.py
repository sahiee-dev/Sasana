#!/usr/bin/env python3
"""
sasana_cli.py — CLI entry point.

Usage:
  sasana verify <session.jsonl> [--json]
  sasana evidence-pack <session.jsonl> [--standard eu_ai_act|soc2|hipaa|siem]
  sasana verify-commitment <bundle.json> --deadline ISO8601 --tsa-anchor CERT [--json]
  sasana observe [--ws URL] [--output-dir DIR]
  sasana bridge  [--socket PATH] [--output-dir DIR]
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

from sasana import __version__ as VERSION  # noqa: E402  (must follow sys.path setup above)

_NO_COLOR = os.environ.get("NO_COLOR") is not None or not sys.stdout.isatty()


def _c(code: str, text: str) -> str:
    return text if _NO_COLOR else f"\033[{code}m{text}\033[0m"


def _bold(text: str) -> str:
    return _c("1", text)


def _dim(text: str) -> str:
    return _c("2", text)


def _cyan(text: str) -> str:
    return _c("36", text)


def _green(text: str) -> str:
    return _c("32", text)


def _yellow(text: str) -> str:
    return _c("33", text)


def _red(text: str) -> str:
    return _c("31", text)


def _magenta(text: str) -> str:
    return _c("35", text)


def _cmd_verify(args: list) -> int:
    if not args:
        print("Usage: sasana verify <session.jsonl> [--json]", file=sys.stderr)
        return 3

    ap = argparse.ArgumentParser(prog="sasana verify", add_help=False)
    ap.add_argument("session_file")
    ap.add_argument("--json", dest="json_out", action="store_true")
    ap.add_argument(
        "--trust-key",
        dest="trust_key",
        default=None,
        metavar="BASE64_PUBKEY",
        help="Pin the expected Archeion server public key (base64). Rejects seals from any other key.",
    )
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

    result = verify(events, trusted_seal_pubkey=parsed.trust_key)

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
        print(_bold(_cyan(f"Sasana Verifier v{VERIFIER_VERSION}")))
        print(_dim(f"File: {parsed.session_file}"))
        if result.session_id:
            print(_dim(f"Session: {result.session_id}"))
        print(f"Events: {result.event_count}  Evidence: {result.evidence_class}")
        print()
        _ts_check = result.checks.get("rfc3161_timestamp", {})
        _has_ts = _ts_check.get("status") not in (None, "SKIPPED")
        _total = 6 if _has_ts else 5

        def _st(label: str, status: str, suffix: str = "") -> str:
            color = _green if status == "PASS" else (_yellow if status == "SKIPPED" else _red)
            return f"{label} ... {color(status)}{suffix}"

        for label, key in [
            (f"[1/{_total}] Structural validity ", "structural"),
            (f"[2/{_total}] Sequence integrity  ", "sequence"),
            (f"[3/{_total}] Hash chain integrity", "hash_chain"),
            (f"[4/{_total}] Session completeness", "completeness"),
            (f"[5/{_total}] Seal signature      ", "seal_signature"),
        ]:
            r = result.checks.get(key)
            st = r["status"] if r else "SKIPPED"
            print(_st(label, st))
        if _has_ts:
            st = _ts_check.get("status", "SKIPPED")
            ts_utc = _ts_check.get("timestamp_utc")
            suffix = f"  ({ts_utc})" if ts_utc else ""
            print(_st("[6/6] RFC 3161 timestamp   ", st, suffix))
        print()
        if result.status == "INTACT":
            print(_bold(_green("Result: INTACT ✅")))
        elif result.status == "PARTIAL":
            print(_bold(_yellow(f"Result: PARTIAL ⚠️  ({result.log_drop_count} LOG_DROP events)")))
        elif result.status == "COMPROMISED":
            print(_bold(_red("Result: COMPROMISED ❌")))
            for err in result.errors[:10]:
                print(_red(f"  → {err}"))
        else:
            print(_bold(_red("Result: ERROR ❌")))
            for err in result.errors[:10]:
                print(_red(f"  → {err}"))

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


def _load_cert_der(path: str) -> bytes:
    """Read a certificate file (PEM or DER) and return DER bytes."""
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization

    raw = open(os.path.expanduser(path), "rb").read()
    cert = (
        x509.load_pem_x509_certificate(raw)
        if b"-----BEGIN" in raw
        else x509.load_der_x509_certificate(raw)
    )
    return cert.public_bytes(serialization.Encoding.DER)


def _cmd_verify_commitment(args: list) -> int:
    ap = argparse.ArgumentParser(prog="sasana verify-commitment", add_help=False)
    ap.add_argument("bundle_file")
    ap.add_argument(
        "--deadline",
        required=True,
        metavar="ISO8601",
        help="UTC deadline, e.g. 2026-06-01T12:00:00Z",
    )
    ap.add_argument(
        "--tsa-anchor",
        dest="tsa_anchors",
        action="append",
        required=True,
        metavar="CERT",
        help="Pinned TSA root/leaf certificate (PEM or DER). Repeatable.",
    )
    ap.add_argument(
        "--registry", default=None, metavar="FILE", help="Counterparty receipt log (JSON list)."
    )
    ap.add_argument("--trust-key", dest="trust_key", default=None, metavar="BASE64_PUBKEY")
    ap.add_argument("--allow-partial", dest="allow_partial", action="store_true")
    ap.add_argument("--json", dest="json_out", action="store_true")
    parsed, _ = ap.parse_known_args(args)

    from datetime import datetime, timezone

    try:
        with open(parsed.bundle_file) as f:
            bundle = json.load(f)
        registry = None
        if parsed.registry:
            with open(parsed.registry) as f:
                registry = json.load(f)
        anchors = [_load_cert_der(p) for p in parsed.tsa_anchors]
        deadline = datetime.fromisoformat(parsed.deadline.replace("Z", "+00:00"))
        if deadline.tzinfo is None:
            deadline = deadline.replace(tzinfo=timezone.utc)
    except (OSError, ValueError, json.JSONDecodeError) as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 3

    from sasana.commitment import verify_commitment

    v = verify_commitment(
        bundle,
        deadline=deadline,
        trusted_tsa_anchors=anchors,
        trusted_seal_pubkey=parsed.trust_key,
        registry=registry,
        allow_partial=parsed.allow_partial,
    )
    if parsed.json_out:
        print(json.dumps(v.as_dict(), indent=2, default=str))
    else:
        print(_bold(_cyan("Sasana Commitment Verifier")))
        print(_dim(f"Bundle   : {parsed.bundle_file}"))
        print(_dim(f"Deadline : {deadline.isoformat()}"))
        print(f"Evidence : {v.evidence_class or '—'}")
        if v.effective_revision is not None:
            print(f"Effective revision: {v.effective_revision}")
        color = (
            _green if v.verdict == "VALID_ON_TIME" else (_yellow if v.verdict == "LATE" else _red)
        )
        print(f"Verdict  : {_bold(color(v.verdict))}")
        for err in v.errors:
            print(_red(f"  ✗ {err}"))
        for w in v.warnings:
            print(_yellow(f"  ! {w}"))
    return {"VALID_ON_TIME": 0, "LATE": 2, "INVALID": 1}.get(v.verdict, 3)


_STANDARDS = {
    "eu_ai_act": "EU AI Act — Article 12 logging evidence",
    "soc2": "SOC 2 Type II — CC7.2 monitoring evidence",
    "hipaa": "HIPAA §164.312(b) — audit controls log",
    "siem": "SIEM export — CEF + JSON events",
}


def _cmd_evidence_pack(args: list) -> int:
    ap = argparse.ArgumentParser(prog="sasana evidence-pack", add_help=False)
    ap.add_argument("session_file")
    ap.add_argument(
        "--standard",
        default="eu_ai_act",
        choices=sorted(_STANDARDS),
        help="Compliance standard to generate evidence for (default: eu_ai_act).",
    )
    ap.add_argument("--system-name", dest="system_name", default="AI System")
    ap.add_argument("--system-version", dest="system_version", default="1.0.0")
    ap.add_argument("--operator-id", dest="operator_id", default=None)
    ap.add_argument("--out", dest="out_dir", default=None, metavar="DIR")
    parsed, _ = ap.parse_known_args(args)

    if not os.path.exists(os.path.expanduser(parsed.session_file)):
        print(f"ERROR: file not found: {parsed.session_file}", file=sys.stderr)
        return 3

    status_ok: bool
    status_label: str
    evidence_class = "—"
    outputs: list[str] = []

    try:
        if parsed.standard == "eu_ai_act":
            from sasana.compliance.eu_ai_act import generate_eu_ai_act_report

            r = generate_eu_ai_act_report(
                parsed.session_file,
                system_name=parsed.system_name,
                system_version=parsed.system_version,
                operator_id=parsed.operator_id,
                output_dir=parsed.out_dir,
            )
            status_ok = r["compliant"]
            status_label = "COMPLIANT" if status_ok else "GAPS DETECTED"
            evidence_class = r["evidence_class"]
        elif parsed.standard == "soc2":
            from sasana.compliance.soc2 import generate_soc2_report

            r = generate_soc2_report(parsed.session_file, output_dir=parsed.out_dir)
            status_ok = r["result"] == "PASS"
            status_label = r["result"]
            evidence_class = r["evidence_class"]
        elif parsed.standard == "hipaa":
            from sasana.compliance.hipaa import generate_hipaa_audit_log

            r = generate_hipaa_audit_log(
                parsed.session_file,
                system_id=parsed.system_name,
                output_dir=parsed.out_dir,
            )
            status_ok = r["compliant_core"]
            status_label = "COMPLIANT" if status_ok else "GAPS DETECTED"
            evidence_class = r["evidence_class"]
        else:  # siem
            import os.path as _osp

            from sasana.compliance.siem import SiemExporter

            exporter = SiemExporter(parsed.session_file)
            summary = exporter.summary()
            evidence_class = summary.get("evidence_class", "—")
            session_id = (
                summary.get("session_id") or _osp.splitext(_osp.basename(parsed.session_file))[0]
            )
            out_dir = parsed.out_dir or _osp.dirname(_osp.abspath(parsed.session_file))
            cef_path = exporter.to_cef_file(_osp.join(out_dir, f"{session_id}_siem.cef"))
            json_path = exporter.to_json_lines(_osp.join(out_dir, f"{session_id}_siem.jsonl"))
            r = {"cef_path": str(cef_path), "json_path": str(json_path)}
            status_ok = evidence_class not in ("NO_EVIDENCE",)
            status_label = "EXPORTED"
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 3

    outputs = [str(v) for k, v in r.items() if k.endswith("_path")]

    print(_bold(_cyan("Sasana Evidence Pack")))
    print(_dim(f"Standard : {_STANDARDS[parsed.standard]}"))
    print(_dim(f"Source   : {parsed.session_file}"))
    print(f"Evidence : {evidence_class}")
    color = _green if status_ok else _yellow
    print(f"Status   : {_bold(color(status_label))}")
    print()
    print(_bold("Generated:"))
    for path in outputs:
        print(f"  {_green('→')} {path}")
    print()
    print(
        _dim(
            "Open the .html for the auditor-ready report; the .json manifest is "
            "independently verifiable with `sasana verify`."
        )
    )
    return 0 if status_ok else 2


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


def _cmd_bridge(args: list) -> int:
    ap = argparse.ArgumentParser(prog="sasana bridge")
    ap.add_argument("--socket", dest="socket_path", default=None, metavar="PATH")
    ap.add_argument("--output-dir", dest="output_dir", default=None, metavar="DIR")
    parsed = ap.parse_args(args)

    from sasana.integrations.openclaw import _DEFAULT_OUTPUT_DIR, _DEFAULT_SOCKET_PATH, run

    socket_path = parsed.socket_path or str(_DEFAULT_SOCKET_PATH)
    output_dir = parsed.output_dir or str(_DEFAULT_OUTPUT_DIR)

    print(_bold(_magenta("╭─ Sasana ⇄ OpenClaw bridge ─────────────────────────╮")))
    print(f"{_dim('│')} socket : {_cyan(socket_path)}")
    print(f"{_dim('│')} ledger : {_cyan(output_dir)}")
    print(f"{_dim('│')} hooks  : {_dim('session_start/end, before/after_tool_call,')}")
    print(f"{_dim('│')}          {_dim('model_call_started/ended, llm_input/output')}")
    print(_bold(_magenta("╰─────────────────────────────────────────────────────╯")))
    print(_green("listening… ") + _dim("(Ctrl-C to stop)"))
    try:
        run(socket_path=parsed.socket_path, output_dir=parsed.output_dir)
    except KeyboardInterrupt:
        print("\nStopped.")
    return 0


def main() -> None:
    args = sys.argv[1:]
    if not args or args[0] in ("--help", "-h", "help"):
        print(
            _bold(_cyan(f"Sasana v{VERSION}")) + _dim(" — tamper-evident audit trail for AI agents")
        )
        print(_dim("  hash-chained · Ed25519-signed · RFC 3161-anchored"))
        print(_bold("\nUSAGE:"))
        print(f"  {_green('sasana verify')}  <session.jsonl> [--json]        Verify hash chain")
        print(
            f"  {_green('sasana seal')}    <session.jsonl> [--server URL]  Submit to Archeion for sealing"
        )
        print(
            f"  {_green('sasana evidence-pack')} <session.jsonl> [--standard S]  Auditor-ready compliance report"
        )
        print(
            f"  {_green('sasana verify-commitment')} <bundle.json> --deadline T --tsa-anchor CERT"
            "  Verify a pre-outcome commitment"
        )
        print(
            f"  {_green('sasana observe')} [--ws URL]                      Passive WebSocket observer"
        )
        print(
            f"  {_green('sasana bridge')}  [--socket PATH]                 Real OpenClaw plugin bridge"
        )
        print(f"  {_green('sasana version')}                                 Print version")
        sys.exit(0)
    if args[0] in ("--version", "-V", "version"):
        print(_bold(_cyan(f"sasana {VERSION}")))
        sys.exit(0)
    if args[0] == "verify":
        sys.exit(_cmd_verify(args[1:]))
    if args[0] == "seal":
        sys.exit(_cmd_seal(args[1:]))
    if args[0] in ("verify-commitment", "verify_commitment"):
        sys.exit(_cmd_verify_commitment(args[1:]))
    if args[0] in ("evidence-pack", "evidence_pack"):
        sys.exit(_cmd_evidence_pack(args[1:]))
    if args[0] == "observe":
        sys.exit(_cmd_observe(args[1:]))
    if args[0] == "bridge":
        sys.exit(_cmd_bridge(args[1:]))
    print(_red(f"Unknown command: {args[0]}"), file=sys.stderr)
    sys.exit(3)


if __name__ == "__main__":
    main()
