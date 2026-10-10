"""
tests/test_canonicalization.py — versioned canonicalization and the golden-fixture regression suite.

A session declares its canonicalization in the (hashed) SESSION_START payload:
``"canonicalization": "jcs-rfc8785"``; no field means ``legacy`` (Sasana 1.0.0 / 1.1.0). The
verifier reads the declaration once and uses exactly that algorithm. These tests pin down:

* both algorithms byte-for-byte against shared vectors (RFC 8785 Appendix B, the RFC's own
  examples, Node's ECMAScript Number::toString as an independent oracle, and the real 1.1.0 code);
* that logs written by the PUBLISHED 1.0.0 and 1.1.0 releases still verify — sealed + pinned ones
  as AUTHORITATIVE — and that Python and Rust agree on every one of them;
* that the declaration cannot be changed, removed or ignored without breaking the chain, and that
  the verifier never "tries the other algorithm".
"""

from __future__ import annotations

import copy
import datetime as dt
import hashlib
import json
import os
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

_ROOT = Path(__file__).parent.parent
for _p in (str(_ROOT), str(_ROOT / "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import tsa_fixture as fx  # noqa: E402
from rust_bin import require_rust_binary, rust_verify  # noqa: E402

from sasana.envelope import build_event  # noqa: E402
from sasana.jcs import (  # noqa: E402
    CANON_FIELD,
    CANON_LEGACY,
    CANON_RFC8785,
    canonicalize,
    canonicalize_legacy,
    canonicalizer,
)
from sasana.signing import generate_keypair  # noqa: E402
from sasana.sqlite_ledger import SqliteLedger  # noqa: E402
from sasana.verifier import (  # noqa: E402
    AUTHORITATIVE_EVIDENCE,
    COMPROMISED,
    ERROR,
    GENESIS_HASH,
    INTACT,
    NO_EVIDENCE,
    SELF_SEALED_EVIDENCE,
    SIGNED_NON_AUTHORITATIVE_EVIDENCE,
    compute_event_hash,
    select_canonicalization,
    verify,
)

try:
    from fastapi.testclient import TestClient  # noqa: E402

    from archeion.server import app  # noqa: E402

    _FASTAPI = True
except ImportError:
    _FASTAPI = False

_FIXTURES = _ROOT / "tests" / "fixtures"
_LEGACY = _FIXTURES / "legacy"
_VECTORS = json.loads((_FIXTURES / "jcs_vectors.json").read_text())
_MANIFEST = json.loads((_LEGACY / "manifest.json").read_text())
_CLI = str(_ROOT / "sasana_cli.py")


def _load(path: Path) -> list:
    return [json.loads(ln) for ln in path.read_text().splitlines() if ln.strip()]


def _cli(path: Path, *flags):
    r = subprocess.run(
        [sys.executable, _CLI, "verify", str(path), "--json", *flags],
        capture_output=True,
        text=True,
        env={**os.environ, "NO_COLOR": "1"},
    )
    try:
        data = json.loads(r.stdout)
    except json.JSONDecodeError:
        data = {}
    return r.returncode, data


def _write(events: list, path: Path) -> Path:
    path.write_text("\n".join(json.dumps(e) for e in events) + "\n")
    return path


# ---------------------------------------------------------------------------------------
# Vectors
# ---------------------------------------------------------------------------------------
class TestVectors(unittest.TestCase):
    def test_number_vectors_both_algorithms(self):
        self.assertGreaterEqual(len(_VECTORS["numbers"]), 40)
        for v in _VECTORS["numbers"]:
            value = json.loads(v["json"])
            with self.subTest(token=v["json"]):
                self.assertEqual(canonicalize(value).decode(), v["rfc8785"])
                self.assertEqual(canonicalize_legacy(value).decode(), v["legacy"])

    def test_rfc8785_appendix_b(self):
        self.assertEqual(len(_VECTORS["appendix_b"]), 24)
        for bits, expected in _VECTORS["appendix_b"].items():
            f = struct.unpack(">d", struct.pack(">Q", int(bits, 16)))[0]
            with self.subTest(bits=bits):
                self.assertEqual(canonicalize(f).decode(), expected)

    def test_documents_both_algorithms(self):
        for d in _VECTORS["documents"]:
            value = json.loads(d["json"])
            with self.subTest(name=d["name"]):
                self.assertEqual(canonicalize(value).decode(), d["rfc8785"])
                self.assertEqual(canonicalize_legacy(value).decode(), d["legacy"])

    def test_the_two_algorithms_really_differ_where_expected(self):
        diff = [v for v in _VECTORS["numbers"] if v["legacy"] != v["rfc8785"]]
        self.assertGreater(len(diff), 10)
        self.assertEqual(canonicalize_legacy(1200.0), b"1200.0")
        self.assertEqual(canonicalize(1200.0), b"1200")

    def test_event_hash_is_byte_exact_against_the_vector_strings(self):
        """event_hash = sha256 of the event's canonical bytes, assembled here by hand from the
        vector expectations — not produced by the code under test."""
        for d in _VECTORS["documents"]:
            event = {
                "seq": 1,
                "event_type": "LLM_RESPONSE",
                "session_id": "s",
                "timestamp": "t",
                "payload": json.loads(d["json"]),
                "prev_hash": GENESIS_HASH,
            }
            for canon, key in ((CANON_RFC8785, "rfc8785"), (CANON_LEGACY, "legacy")):
                expected_bytes = (
                    '{"event_type":"LLM_RESPONSE","payload":'
                    + d[key]
                    + ',"prev_hash":"'
                    + GENESIS_HASH
                    + '","seq":1,"session_id":"s","timestamp":"t"}'
                ).encode("utf-8")
                with self.subTest(name=d["name"], canon=canon):
                    self.assertEqual(
                        compute_event_hash(event, canon), hashlib.sha256(expected_bytes).hexdigest()
                    )

    def test_unknown_algorithm_name_is_rejected(self):
        with self.assertRaises(ValueError):
            canonicalizer("jcs-rfc9999")


# ---------------------------------------------------------------------------------------
# Declaration
# ---------------------------------------------------------------------------------------
def _start(payload: dict) -> list:
    return [
        build_event(1, "SESSION_START", "s", payload, GENESIS_HASH, canonicalization=CANON_LEGACY)
    ]


class TestDeclaration(unittest.TestCase):
    def test_absent_means_legacy_and_rfc_is_rfc(self):
        self.assertEqual(select_canonicalization(_start({"agent_id": "a"})), (CANON_LEGACY, None))
        self.assertEqual(
            select_canonicalization(_start({CANON_FIELD: CANON_RFC8785})), (CANON_RFC8785, None)
        )

    def test_anything_else_is_an_error_never_a_guess(self):
        for bad in (
            "legacy",
            "jcs-rfc8785 ",
            "JCS-RFC8785",
            "rfc8785",
            "jcs-rfc9999",
            "",
            None,
            1,
            True,
            ["jcs-rfc8785"],
            {},
        ):
            with self.subTest(value=bad):
                algo, err = select_canonicalization(_start({CANON_FIELD: bad}))
                self.assertIsNone(algo)
                self.assertIn("unsupported canonicalization", err)

    def test_verify_returns_error_not_compromised_for_an_unknown_value(self):
        r = verify(_start({CANON_FIELD: "jcs-rfc9999"}))
        self.assertEqual((r.status, r.evidence_class), (ERROR, NO_EVIDENCE))
        self.assertTrue(any("Refusing to guess" in e for e in r.errors))

    def test_cli_exit_3_and_json_for_an_unknown_value(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = _write(_start({CANON_FIELD: "jcs-rfc9999"}), Path(tmp) / "s.jsonl")
            rc, data = _cli(p)
            self.assertEqual(rc, 3)
            self.assertEqual((data["status"], data["evidence_class"]), (ERROR, NO_EVIDENCE))
            self.assertEqual(data["exit_code"], 3)

    def test_only_session_start_is_consulted(self):
        events = _start({"agent_id": "a"})
        events.append(
            build_event(
                2,
                "LLM_CALL",
                "s",
                {CANON_FIELD: "jcs-rfc9999"},
                events[-1]["event_hash"],
                canonicalization=CANON_LEGACY,
            )
        )
        self.assertEqual(select_canonicalization(events), (CANON_LEGACY, None))

    def test_ledger_declares_rfc8785_and_metadata_cannot_override(self):
        with tempfile.TemporaryDirectory() as tmp:
            ledger = SqliteLedger(db_path=Path(tmp) / "l.db")
            ledger.connect()
            ledger.open_session(session_id="s", metadata={CANON_FIELD: "legacy", "x": 1})
            ledger.record("LLM_RESPONSE", {"duration_ms": 1200.0})
            ledger.close_session()
            ledger.export_jsonl(Path(tmp) / "l.jsonl")
            ledger.close()
            events = _load(Path(tmp) / "l.jsonl")
        self.assertEqual(events[0]["payload"][CANON_FIELD], CANON_RFC8785)
        r = verify(events)
        self.assertEqual((r.status, r.canonicalization), (INTACT, CANON_RFC8785))
        # the float is hashed the RFC 8785 way: recompute it by hand
        ev = events[1]
        stripped = {k: v for k, v in ev.items() if k not in ("event_hash", "signature")}
        text = canonicalize(stripped).decode()
        self.assertIn('"duration_ms":1200}', text)
        self.assertEqual(ev["event_hash"], hashlib.sha256(text.encode()).hexdigest())


# ---------------------------------------------------------------------------------------
# Downgrade / no-fallback
# ---------------------------------------------------------------------------------------
def _new_ledger_session(tmp: Path, name: str = "n") -> list:
    ledger = SqliteLedger(db_path=tmp / f"{name}.db")
    ledger.connect()
    ledger.open_session(session_id=f"sess-{name}", agent_id="a")
    ledger.record("LLM_RESPONSE", {"content_hash": "b" * 64, "duration_ms": 1200.0, "cost": 0.0})
    ledger.record("TOOL_RESULT", {"result_hash": "d" * 64, "elapsed": 100.0})
    ledger.close_session()
    path = tmp / f"{name}.jsonl"
    ledger.export_jsonl(path)
    ledger.close()
    return _load(path)


def _rechain(events: list, canon: str) -> list:
    events = copy.deepcopy(events)
    for i, ev in enumerate(events):
        ev["prev_hash"] = events[i - 1]["event_hash"] if i else GENESIS_HASH
        ev["event_hash"] = compute_event_hash(ev, canon)
    return events


@unittest.skipUnless(_FASTAPI, "fastapi / httpx not installed")
class TestDowngradeDetection(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        cls.tmp = Path(cls._tmp.name)
        cls.client = TestClient(app)
        cls.pub = cls.client.get("/pubkey").json()["pubkey"]
        raw = _write(_new_ledger_session(cls.tmp), cls.tmp / "n_unsealed.jsonl").read_bytes()
        resp = cls.client.post("/seal", content=raw)
        assert resp.status_code == 200, resp.text
        cls.sealed = [json.loads(ln) for ln in resp.text.splitlines() if ln.strip()]

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def _pinned(self, events):
        return verify(events, trusted_seal_pubkey=self.pub)

    def test_baseline_new_sealed_log_is_authoritative_rfc8785(self):
        r = self._pinned(self.sealed)
        self.assertEqual(
            (r.status, r.evidence_class, r.canonicalization),
            (INTACT, AUTHORITATIVE_EVIDENCE, CANON_RFC8785),
        )

    def test_removing_the_declaration_breaks_verification(self):
        ev = copy.deepcopy(self.sealed)
        del ev[0]["payload"][CANON_FIELD]
        r = self._pinned(ev)
        self.assertEqual(r.status, COMPROMISED)
        self.assertEqual(r.canonicalization, CANON_LEGACY)  # read from the (edited) log, used alone
        self.assertTrue(any("event_hash mismatch" in e for e in r.errors))

    def test_changing_the_declaration_to_another_value_is_error_never_a_pass(self):
        ev = copy.deepcopy(self.sealed)
        ev[0]["payload"][CANON_FIELD] = "legacy"
        self.assertEqual(self._pinned(ev).status, ERROR)

    def test_downgrade_with_chain_recomputed_but_old_seal_kept(self):
        ev = copy.deepcopy(self.sealed)
        del ev[0]["payload"][CANON_FIELD]
        ev[:-1] = _rechain(ev[:-1], CANON_LEGACY)  # seal event untouched
        r = self._pinned(ev)
        self.assertEqual(r.status, COMPROMISED)

    def test_downgrade_fully_rechained_with_attacker_seal_fails_when_pinned(self):
        ev = copy.deepcopy(self.sealed)
        del ev[0]["payload"][CANON_FIELD]
        ev = _rechain(ev, CANON_LEGACY)
        r = self._pinned(ev)  # seal signature no longer matches: stale signature
        self.assertEqual(r.status, COMPROMISED)

    def test_log_hashed_with_rfc8785_but_not_declared_is_not_accepted(self):
        """No fallback: the verifier must not notice the hashes fit the OTHER algorithm."""
        events = _new_ledger_session(self.tmp, "nodecl")
        del events[0]["payload"][CANON_FIELD]
        events = _rechain(events, CANON_RFC8785)  # self-consistent under RFC 8785, undeclared
        self.assertEqual(verify(events).status, COMPROMISED)
        # ... while the same events hashed with legacy and undeclared are fine
        self.assertEqual(verify(_rechain(events, CANON_LEGACY)).status, INTACT)

    def test_log_hashed_legacy_but_declared_rfc8785_is_not_accepted(self):
        events = _new_ledger_session(self.tmp, "decl")
        events = _rechain(events, CANON_LEGACY)  # declared rfc8785, hashed legacy
        self.assertEqual(verify(events).status, COMPROMISED)

    def test_python_and_rust_agree_on_every_variant(self):
        require_rust_binary()
        variants = {"baseline": self.sealed}
        ev = copy.deepcopy(self.sealed)
        del ev[0]["payload"][CANON_FIELD]
        variants["undeclared"] = ev
        ev = copy.deepcopy(self.sealed)
        ev[0]["payload"][CANON_FIELD] = "legacy"
        variants["explicit_legacy"] = ev
        for name, events in variants.items():
            p = _write(events, self.tmp / f"v_{name}.jsonl")
            rc_py, py = _cli(p, "--trust-key", self.pub)
            rc_rs, rs, out, _ = rust_verify(p, trust_key=self.pub)
            with self.subTest(variant=name):
                self.assertEqual(
                    (py["status"], py["evidence_class"], rc_py),
                    (rs["status"], rs["evidence_class"], rc_rs),
                    out,
                )


# ---------------------------------------------------------------------------------------
# Golden fixtures: logs written by the published 1.0.0 / 1.1.0 releases
# ---------------------------------------------------------------------------------------
class TestLegacyFixtures(unittest.TestCase):
    def test_manifest_covers_both_releases_and_all_kinds(self):
        files = _MANIFEST["files"]
        self.assertEqual({m["release"] for m in files.values()}, {"v1.0.0", "v1.1.0"})
        for rel in ("v1.0.0", "v1.1.0"):
            self.assertEqual(
                {m["kind"] for m in files.values() if m["release"] == rel},
                {"unsealed", "signed", "sealed", "timestamped"},
            )
        for rel, info in _MANIFEST["releases"].items():
            self.assertEqual(len(info["pypi_wheel_sha256"]), 64, rel)

    def test_fixtures_are_unmodified(self):
        for name, meta in _MANIFEST["files"].items():
            digest = hashlib.sha256((_LEGACY / name).read_bytes()).hexdigest()
            self.assertEqual(
                digest, meta["sha256"], f"{name} changed — never regenerate to make a test pass"
            )

    def test_fixtures_contain_the_values_that_broke_the_float_change(self):
        text = (_LEGACY / "v1.1.0_unsealed.jsonl").read_text()
        for needle in (
            '"duration_ms": 1200.0',
            '"cost_usd": 0.0',
            '"latency_s": 100.0',
            '"neg_zero": -0.0',
            '"tiny": 1.5e-07',
            '"int_u64": 12345678901234567890',
            "\\u2603",
            "\\u05e9",
        ):
            self.assertIn(needle, text)

    def test_every_legacy_fixture_is_intact_under_python(self):
        for name, meta in _MANIFEST["files"].items():
            events = _load(_LEGACY / name)
            r = verify(events)
            with self.subTest(fixture=name):
                self.assertEqual(r.status, INTACT, r.errors)
                self.assertEqual(r.canonicalization, CANON_LEGACY)
                self.assertEqual(r.evidence_class, meta["unpinned"]["evidence_class"])
                self.assertNotIn(CANON_FIELD, events[0]["payload"])
                if "pinned" in meta:
                    p = verify(events, trusted_seal_pubkey=meta["archeion_pubkey"])
                    self.assertEqual((p.status, p.evidence_class), (INTACT, AUTHORITATIVE_EVIDENCE))
                    self.assertTrue(p.seal_trusted)
                if meta["kind"] == "timestamped":
                    self.assertEqual(
                        r.checks["rfc3161_timestamp"]["status"], meta["timestamp_status"]
                    )
                    self.assertFalse(r.timestamp_verified)
                if meta["kind"] == "signed":
                    self.assertEqual(r.evidence_class, SIGNED_NON_AUTHORITATIVE_EVIDENCE)

    def test_cli_exit_codes_on_every_legacy_fixture(self):
        for name, meta in _MANIFEST["files"].items():
            flags = ["--trust-key", meta["archeion_pubkey"], "--strict"] if "pinned" in meta else []
            rc, data = _cli(_LEGACY / name, *flags)
            with self.subTest(fixture=name):
                self.assertEqual(
                    (rc, data["status"], data["canonicalization"]), (0, INTACT, CANON_LEGACY)
                )

    def test_sealed_unpinned_is_never_authoritative(self):
        for name, meta in _MANIFEST["files"].items():
            if meta["kind"] == "sealed":
                self.assertEqual(verify(_load(_LEGACY / name)).evidence_class, SELF_SEALED_EVIDENCE)

    def test_tampering_with_a_legacy_fixture_is_still_detected(self):
        for name, meta in _MANIFEST["files"].items():
            events = _load(_LEGACY / name)
            events[2]["payload"]["duration_ms"] = 1201.0
            with self.subTest(fixture=name):
                self.assertEqual(verify(events).status, COMPROMISED)

    def test_python_and_rust_agree_on_every_legacy_fixture(self):
        require_rust_binary()
        for name, meta in _MANIFEST["files"].items():
            pin = meta.get("archeion_pubkey")
            for key in (None, pin) if pin else (None,):
                flags = ["--trust-key", key] if key else []
                rc_py, py = _cli(_LEGACY / name, *flags)
                rc_rs, rs, out, _ = rust_verify(_LEGACY / name, trust_key=key)
                with self.subTest(fixture=name, pinned=bool(key)):
                    self.assertEqual(
                        (py["status"], py["evidence_class"], rc_py),
                        (rs["status"], rs["evidence_class"], rc_rs),
                        out,
                    )
                    self.assertEqual(py["canonicalization"], rs["canonicalization"])
                    self.assertEqual(rs["status"], INTACT)
                    if key:
                        self.assertEqual(rs["evidence_class"], AUTHORITATIVE_EVIDENCE)

    def test_archeion_can_still_seal_a_legacy_session_with_legacy_hashing(self):
        if not _FASTAPI:
            self.skipTest("fastapi / httpx not installed")
        client = TestClient(app)
        pub = client.get("/pubkey").json()["pubkey"]
        raw = (_LEGACY / "v1.1.0_unsealed.jsonl").read_bytes()
        resp = client.post("/seal", content=raw)
        self.assertEqual(resp.status_code, 200, resp.text)
        sealed = [json.loads(ln) for ln in resp.text.splitlines() if ln.strip()]
        self.assertEqual(sealed[:-1], _load(_LEGACY / "v1.1.0_unsealed.jsonl"))  # untouched
        self.assertNotIn(CANON_FIELD, sealed[-1]["payload"])
        self.assertEqual(sealed[-1]["event_hash"], compute_event_hash(sealed[-1], CANON_LEGACY))
        r = verify(sealed, trusted_seal_pubkey=pub)
        self.assertEqual(
            (r.status, r.evidence_class, r.canonicalization),
            (INTACT, AUTHORITATIVE_EVIDENCE, CANON_LEGACY),
        )

    def test_archeion_refuses_to_seal_an_unknown_declaration(self):
        if not _FASTAPI:
            self.skipTest("fastapi / httpx not installed")
        events = _start({CANON_FIELD: "jcs-rfc9999"})
        events.append(
            build_event(
                2,
                "SESSION_END",
                "s",
                {"status": "success"},
                events[-1]["event_hash"],
                canonicalization=CANON_LEGACY,
            )
        )
        body = ("\n".join(json.dumps(e) for e in events) + "\n").encode()
        resp = TestClient(app).post("/seal", content=body)
        self.assertEqual(resp.status_code, 422)
        self.assertIn("canonicalization", resp.json()["detail"])


# ---------------------------------------------------------------------------------------
# New-format logs
# ---------------------------------------------------------------------------------------
class TestNewFormatLogs(unittest.TestCase):
    def test_new_sessions_with_floats_verify_and_python_matches_rust(self):
        require_rust_binary()
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            private_key, _ = generate_keypair()
            for name, kw in (("plain", {}), ("signed", {"private_key": private_key})):
                ledger = SqliteLedger(db_path=tmp / f"{name}.db", **kw)
                ledger.connect()
                ledger.open_session(
                    session_id=name, metadata={"labels": {"z": 1, "a": [1, 2.0, -0.0]}}
                )
                ledger.record(
                    "LLM_RESPONSE",
                    {"d": 1200.0, "tiny": 1e-5, "huge": 1e21, "big": 2**60, "u": "é☃😀"},
                )
                ledger.close_session()
                p = tmp / f"{name}.jsonl"
                ledger.export_jsonl(p)
                ledger.close()
                rc_py, py = _cli(p)
                rc_rs, rs, out, _ = rust_verify(p)
                with self.subTest(session=name):
                    self.assertEqual(
                        (py["status"], py["canonicalization"], rc_py), (INTACT, CANON_RFC8785, 0)
                    )
                    self.assertEqual(
                        (rs["status"], rs["canonicalization"], rc_rs),
                        (INTACT, CANON_RFC8785, 0),
                        out,
                    )
                    self.assertEqual(py["evidence_class"], rs["evidence_class"])

    def test_rfc3161_pre_token_hash_follows_the_declared_algorithm(self):
        authority = fx.make_authority()
        with tempfile.TemporaryDirectory() as tmp:
            ledger = SqliteLedger(db_path=Path(tmp) / "t.db")
            ledger.connect()
            with mock.patch(
                "sasana.rfc3161.request_timestamp",
                lambda h, **kw: fx.respond(
                    authority, h, gen_time=dt.datetime(2026, 6, 15, tzinfo=dt.timezone.utc)
                ),
            ):
                ledger.open_session(session_id="t", metadata={"score": 100.0})
            ledger.close_session()
            ledger.export_jsonl(Path(tmp) / "t.jsonl")
            ledger.close()
            events = _load(Path(tmp) / "t.jsonl")
        r = verify(events)
        self.assertEqual((r.status, r.canonicalization), (INTACT, CANON_RFC8785))
        self.assertEqual(r.checks["rfc3161_timestamp"]["status"], "IMPRINT_MATCH")


if __name__ == "__main__":
    unittest.main()
