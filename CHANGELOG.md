# Changelog

All notable changes to Sasana are documented here. This project adheres to
[Semantic Versioning](https://semver.org/).

## [1.1.0] — 2026-07-20

### Added
- **`sasana evidence-pack` CLI** — turns a verified session into an auditor-ready
  report (HTML) plus a re-verifiable manifest (JSON) in one command. Standards:
  `eu_ai_act` (EU AI Act Article 12), `soc2` (CC7.2), `hipaa` (§164.312(b)), `siem`
  (CEF + JSON). Exit codes `0` compliant / `2` gaps / `3` error for CI.
- **OpenTelemetry exporter** (`sasana[otel]`) — `sasana.integrations.otel.SasanaSpanExporter`
  maps OTel GenAI-semantic-convention spans to a tamper-evident Sasana ledger, one
  session per trace. Run it alongside your existing tracing exporter; nothing is
  replaced. Only hashes are stored.

### Changed
- The tool version shown in generated evidence reports (EU AI Act / SOC 2 / HIPAA
  footers and the SIEM `sasana_version` field) is now sourced from
  `sasana.__version__`, so it can no longer drift from the package version.

### Notes
- The verification algorithm is unchanged; `VERIFIER_VERSION` remains `1.0.0`, so logs
  verified under 1.0.0 verify identically under 1.1.0.
- Companion site adds a live in-browser verifier at
  [sasana.site/verify](https://sasana.site/verify).

## [1.0.0] — 2026-06-15

### Added
- SHA-256 hash-chained, Ed25519-signed tamper-evident session ledger (SQLite + JSONL).
- Canonical verifier (Python + Rust) with evidence-class model
  (`AUTHORITATIVE_EVIDENCE` → `NO_EVIDENCE`).
- RFC 3161 trusted-timestamp anchoring on `SESSION_START`.
- Archeion independent sealing server.
- Compliance export engine (EU AI Act Article 12, SOC 2, HIPAA, SIEM).
- Framework integrations: OpenClaw, LangGraph, CrewAI, AutoGPT.
