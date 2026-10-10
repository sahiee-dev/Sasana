"""
tests/test_tamper_matrix.py — end-to-end tamper matrix for sealed sessions.

A 4-event session (SESSION_START, TOOL_CALL, TOOL_RESULT, SESSION_END carrying
classification "DIVERGENT") is sealed through the real Archeion app (TestClient, throwaway
key), then each attack an adversary with write access to the stored file could mount is
run through the real CLI (`sasana_cli.py verify --json`). Status, evidence class and exit
code all come from the CLI, so this tests what a user or CI script actually sees.

    python tests/test_tamper_matrix.py     # print the matrix table
"""

from __future__ import annotations

import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

_ROOT = Path(__file__).parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))
if str(_ROOT / "tests") not in sys.path:
    sys.path.insert(0, str(_ROOT / "tests"))

# Never touch a real signing key (conftest.py does this too; repeated for direct runs).
if "ARCHEION_KEY_FILE" not in os.environ:
    os.environ["ARCHEION_KEY_FILE"] = os.path.join(
        tempfile.mkdtemp(prefix="sasana-test-archeion-"), "server_key.b64"
    )
os.environ.pop("ARCHEION_PRIVATE_KEY", None)

try:
    from fastapi.testclient import TestClient  # noqa: E402

    from archeion.server import app  # noqa: E402

    _FASTAPI_AVAILABLE = True
except ImportError:
    _FASTAPI_AVAILABLE = False

from rust_bin import require_rust_binary, rust_binary, rust_verify  # noqa: E402
from sasana.envelope import build_event  # noqa: E402
from sasana.jcs import CANON_FIELD, CANON_LEGACY, CANON_RFC8785  # noqa: E402
from sasana.signing import generate_keypair, sign_event_hash  # noqa: E402
from sasana.verifier import GENESIS_HASH, compute_event_hash  # noqa: E402

_CLI = str(_ROOT / "sasana_cli.py")
_SID = "tamper-matrix"


def _base_session(canon: str = CANON_RFC8785) -> list:
    """Four-event session. `canon` is the algorithm the hashes use; RFC 8785 sessions declare it
    in SESSION_START (as Sasana >= 2.0.0 does), legacy sessions carry no declaration (as 1.x).
    The payloads hold whole-number floats, so the two algorithms hash them differently."""
    start = {"agent_id": "a1", "phase": "authorization"}
    if canon == CANON_RFC8785:
        start[CANON_FIELD] = CANON_RFC8785
    spec = [
        ("SESSION_START", start),
        ("TOOL_CALL", {"tool_name": "bash", "args_hash": "c" * 64, "phase": "execution"}),
        (
            "TOOL_RESULT",
            {"result_hash": "d" * 64, "phase": "observation", "duration_ms": 1200.0, "cost": 0.0},
        ),
        (
            "SESSION_END",
            {"status": "success", "phase": "reconciliation", "classification": "DIVERGENT"},
        ),
    ]
    events: list = []
    prev = GENESIS_HASH
    for i, (et, payload) in enumerate(spec, start=1):
        ev = build_event(i, et, _SID, payload, prev, canonicalization=canon)
        events.append(ev)
        prev = ev["event_hash"]
    return events


def _rechain(events: list, canon: str = CANON_RFC8785) -> list:
    """Recompute prev_hash / event_hash for every event; leave `signature` as it is."""
    events = copy.deepcopy(events)
    for i, ev in enumerate(events):
        ev["prev_hash"] = events[i - 1]["event_hash"] if i else GENESIS_HASH
        ev["event_hash"] = compute_event_hash(ev, canon)
    return events


def _write(events: list, path: Path) -> Path:
    path.write_text("\n".join(json.dumps(e) for e in events) + "\n")
    return path


def cli_verify(path: Path, trust_key=None, require_seal: bool = False, strict: bool = False):
    """Run the real CLI. Returns (exit_code, parsed --json output, stdout, stderr)."""
    cmd = [sys.executable, _CLI, "verify", str(path), "--json"]
    if trust_key:
        cmd += ["--trust-key", trust_key]
    if require_seal:
        cmd += ["--require-seal"]
    if strict:
        cmd += ["--strict"]
    r = subprocess.run(cmd, capture_output=True, text=True, env={**os.environ, "NO_COLOR": "1"})
    try:
        data = json.loads(r.stdout)
    except json.JSONDecodeError:
        data = {}
    return r.returncode, data, r.stdout, r.stderr


# case id -> (description, expected status, expected class or None, expected exit,
#             pin?, require_seal?)
# `None` class = not part of the specified expectation for that case.
MATRIX = {
    "a": ("original, no pin", "INTACT", None, 0, False, False),
    "a'": ("original, pinned real key", "INTACT", "AUTHORITATIVE_EVIDENCE", 0, True, False),
    "b": ("edit classification only", "COMPROMISED", "NO_EVIDENCE", 1, True, False),
    "c1": ("edit + rechain 1-4, seal untouched", "COMPROMISED", "NO_EVIDENCE", 1, True, False),
    "c2": (
        "edit + rechain incl. seal, old signature",
        "COMPROMISED",
        "NO_EVIDENCE",
        1,
        True,
        False,
    ),
    "d": (
        "edit + rechain + attacker re-seal, pinned",
        "COMPROMISED",
        "NO_EVIDENCE",
        1,
        True,
        False,
    ),
    "e": ("same as d, no pin", "INTACT", "SELF_SEALED_EVIDENCE", 0, False, False),
    "f": ("edit + rechain + seal stripped, pinned", "COMPROMISED", "NO_EVIDENCE", 1, True, False),
    "f'": ("same as f, --require-seal, no pin", "COMPROMISED", "NO_EVIDENCE", 1, False, True),
    "g": ("seal claims real pubkey, attacker sig", "COMPROMISED", "NO_EVIDENCE", 1, False, False),
}


def build_cases(workdir: Path, canon: str = CANON_RFC8785) -> dict:
    """Seal through the real Archeion app and derive every tampered variant. Returns
    {"real_pubkey": str, "files": {case_id: Path}}."""
    client = TestClient(app)
    real_pub = client.get("/pubkey").json()["pubkey"]

    base = _base_session(canon)
    resp = client.post("/seal", content=("\n".join(json.dumps(e) for e in base) + "\n").encode())
    assert resp.status_code == 200, resp.text
    sealed = [json.loads(ln) for ln in resp.text.splitlines() if ln.strip()]
    assert [e["event_type"] for e in sealed][-1] == "CHAIN_SEAL" and len(sealed) == 5
    assert (sealed[0]["payload"].get(CANON_FIELD) == CANON_RFC8785) == (canon == CANON_RFC8785)

    files: dict = {}
    files["a"] = _write(sealed, workdir / "a.jsonl")

    b = copy.deepcopy(sealed)
    b[3]["payload"]["classification"] = "IN-BOUNDS"
    files["b"] = _write(b, workdir / "b.jsonl")

    # c1: rechain events 1-4 only; the CHAIN_SEAL event is left byte-identical
    c1 = copy.deepcopy(b)
    c1[:4] = _rechain(c1[:4], canon)
    files["c1"] = _write(c1, workdir / "c1.jsonl")

    # c2: rechain everything, including the seal event's hash/prev_hash/session_hash,
    # but keep the original (now stale) signature string
    c2 = copy.deepcopy(c1)
    c2[4]["payload"]["session_hash"] = c2[3]["event_hash"]
    c2[4]["prev_hash"] = c2[3]["event_hash"]
    c2[4]["event_hash"] = compute_event_hash(c2[4], canon)
    files["c2"] = _write(c2, workdir / "c2.jsonl")

    # d/e: attacker rebuilds the whole seal under their own key
    atk_priv, atk_pub = generate_keypair()
    d = copy.deepcopy(c2)
    d[4]["payload"]["server_pubkey"] = atk_pub
    d[4]["event_hash"] = compute_event_hash(d[4], canon)
    d[4]["signature"] = sign_event_hash(atk_priv, d[4]["event_hash"])
    files["d"] = files["e"] = _write(d, workdir / "d.jsonl")

    # f/f': attacker deletes the seal and rechains the four events
    f = _rechain(copy.deepcopy(b[:4]), canon)
    files["f"] = files["f'"] = _write(f, workdir / "f.jsonl")

    # g: seal advertises the real pubkey but is signed with the attacker's key
    g = copy.deepcopy(d)
    g[4]["payload"]["server_pubkey"] = real_pub
    g[4]["event_hash"] = compute_event_hash(g[4], canon)
    g[4]["signature"] = sign_event_hash(atk_priv, g[4]["event_hash"])
    files["g"] = _write(g, workdir / "g.jsonl")

    files["a'"] = files["a"]
    return {"real_pubkey": real_pub, "files": files}


def run_case(cases: dict, case_id: str):
    desc, _, _, _, pinned, require_seal = MATRIX[case_id]
    return cli_verify(
        cases["files"][case_id],
        trust_key=cases["real_pubkey"] if pinned else None,
        require_seal=require_seal,
    )


class _MatrixTests:
    """The ten cases. Run once per canonicalization (see the two concrete classes below)."""

    CANON = CANON_RFC8785

    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        cls.cases = build_cases(Path(cls._tmp.name), cls.CANON)

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def _check(self, case_id: str) -> None:
        desc, status, evidence, exit_code, _, _ = MATRIX[case_id]
        rc, data, out, err = run_case(self.cases, case_id)
        self.assertEqual(data.get("status"), status, f"{case_id} ({desc}): {out}{err}")
        if evidence is not None:
            self.assertEqual(data.get("evidence_class"), evidence, f"{case_id} ({desc}): {out}")
        self.assertEqual(rc, exit_code, f"{case_id} ({desc}): exit code. {out}{err}")

    def test_a_original_no_pin(self):
        self._check("a")

    def test_a_prime_original_pinned(self):
        self._check("a'")

    def test_b_edit_only(self):
        self._check("b")

    def test_c1_rechain_events_seal_untouched(self):
        self._check("c1")

    def test_c2_rechain_incl_seal_old_signature(self):
        self._check("c2")

    def test_d_attacker_reseal_pinned(self):
        self._check("d")

    def test_e_attacker_reseal_no_pin_is_not_authoritative(self):
        _, data, out, _ = run_case(self.cases, "e")
        self.assertNotEqual(data.get("evidence_class"), "AUTHORITATIVE_EVIDENCE", out)
        self._check("e")

    def test_f_seal_stripped_pinned(self):
        self._check("f")

    def test_f_prime_seal_stripped_require_seal(self):
        self._check("f'")

    def test_g_claims_real_key_attacker_signature(self):
        self._check("g")

    def test_unpinned_genuine_seal_is_self_sealed_not_authoritative(self):
        """Even the genuine Archeion seal is not AUTHORITATIVE unless the key is pinned."""
        _, data, out, _ = run_case(self.cases, "a")
        self.assertEqual(data.get("evidence_class"), "SELF_SEALED_EVIDENCE", out)

    def test_reports_the_algorithm_the_session_declares(self):
        _, data, out, _ = run_case(self.cases, "a")
        self.assertEqual(data.get("canonicalization"), self.CANON, out)


@unittest.skipUnless(_FASTAPI_AVAILABLE, "fastapi / httpx not installed")
class TestTamperMatrix(_MatrixTests, unittest.TestCase):
    """Sessions written by Sasana >= 2.0.0: SESSION_START declares jcs-rfc8785."""

    CANON = CANON_RFC8785


@unittest.skipUnless(_FASTAPI_AVAILABLE, "fastapi / httpx not installed")
class TestTamperMatrixLegacy(_MatrixTests, unittest.TestCase):
    """The same ten attacks against Sasana 1.x-format sessions (no declaration)."""

    CANON = CANON_LEGACY


@unittest.skipUnless(_FASTAPI_AVAILABLE, "fastapi / httpx not installed")
class TestRustVerifierParity(unittest.TestCase):
    """The Rust verifier must reach the same verdict as Python on every case, in both formats.
    Fails in CI if the binary is missing (see rust_bin.py)."""

    @classmethod
    def setUpClass(cls):
        require_rust_binary()
        cls._tmp = tempfile.TemporaryDirectory()
        cls.cases = {}
        for canon in (CANON_RFC8785, CANON_LEGACY):
            d = Path(cls._tmp.name) / canon
            d.mkdir()
            cls.cases[canon] = build_cases(d, canon)

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def test_matrix_parity(self):
        for canon, cases in self.cases.items():
            for cid, (desc, status, evidence, exit_code, pinned, require_seal) in MATRIX.items():
                rc, data, out, _ = rust_verify(
                    cases["files"][cid],
                    trust_key=cases["real_pubkey"] if pinned else None,
                    require_seal=require_seal,
                )
                with self.subTest(canon=canon, case=cid, desc=desc):
                    self.assertEqual(data.get("status"), status, out)
                    if evidence:
                        self.assertEqual(data.get("evidence_class"), evidence, out)
                    self.assertEqual(rc, exit_code)

    def test_unknown_flag_is_rejected(self):
        cases = self.cases[CANON_RFC8785]
        r = subprocess.run(
            [str(require_rust_binary()), "verify", str(cases["files"]["a"]), "--trust_key", "x"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(r.returncode, 3, r.stdout + r.stderr)


def _print_table() -> int:
    """Print the matrix for BOTH verifiers (Python CLI and, when built, the Rust binary) and
    BOTH canonicalization formats."""
    if not _FASTAPI_AVAILABLE:
        print("fastapi/httpx not installed")
        return 3
    have_rust = rust_binary() is not None
    all_ok = True
    for canon in (CANON_RFC8785, CANON_LEGACY):
        with tempfile.TemporaryDirectory() as tmp:
            cases = build_cases(Path(tmp), canon)
            hdr = ["case", "expected"]
            hdr += ["py status/class/exit"] + (["rust status/class/exit"] if have_rust else [])
            hdr += ["match"]
            rows = [tuple(hdr)]
            for cid, (desc, status, evidence, exit_code, pinned, req) in MATRIX.items():
                exp = status + (f"/{evidence}" if evidence else "") + f"/{exit_code}"
                row = [f"{cid} {desc}", exp]
                ok = True
                impls = [("py", run_case(cases, cid))]
                if have_rust:
                    impls.append(
                        (
                            "rust",
                            rust_verify(
                                cases["files"][cid],
                                trust_key=cases["real_pubkey"] if pinned else None,
                                require_seal=req,
                            ),
                        )
                    )
                for _, (rc, data, _o, _e) in impls:
                    got_s, got_c = data.get("status", "?"), data.get("evidence_class", "?")
                    ok &= got_s == status and rc == exit_code
                    ok &= evidence is None or got_c == evidence
                    row.append(f"{got_s}/{got_c}/{rc}")
                all_ok &= ok
                row.append("yes" if ok else "NO")
                rows.append(tuple(row))
            widths = [max(len(r[i]) for r in rows) for i in range(len(rows[0]))]
            print(f"\n=== canonicalization: {canon}")
            for i, r in enumerate(rows):
                print(" | ".join(c.ljust(widths[j]) for j, c in enumerate(r)))
                if i == 0:
                    print("-+-".join("-" * w for w in widths))
    return 0 if all_ok else 1


if __name__ == "__main__":
    if len(sys.argv) == 1:
        sys.exit(_print_table())
    unittest.main()
