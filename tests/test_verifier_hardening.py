"""
tests/test_verifier_hardening.py — trust-boundary behaviour of verify() and `sasana verify`.

Covers: seal required / pinned-implies-seal, single final seal, seal payload consistency,
fail-closed handling of malformed input, the completeness of --json and the exit-code
contract, and the refusal to call an RFC 3161 imprint match "verified time".
"""

from __future__ import annotations

import base64
import copy
import datetime as dt
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

_ROOT = Path(__file__).parent.parent
for _p in (str(_ROOT), str(_ROOT / "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import tsa_fixture as fx  # noqa: E402
from test_verifier import (  # noqa: E402
    _TEST_PRIVATE_KEY,
    _TEST_PUBKEY,
    _build_event,
    _make_session,
    _signed_chain_seal,
)

from sasana.envelope import build_event  # noqa: E402
from sasana.jcs import canonicalize  # noqa: E402
from sasana.signing import generate_keypair, sign_event_hash  # noqa: E402
from sasana.verifier import (  # noqa: E402
    AUTHORITATIVE_EVIDENCE,
    COMPROMISED,
    ERROR,
    GENESIS_HASH,
    INTACT,
    NO_EVIDENCE,
    NON_AUTHORITATIVE_EVIDENCE,
    PARTIAL,
    SELF_SEALED_EVIDENCE,
    compute_event_hash,
    verify,
)

_CLI = str(_ROOT / "sasana_cli.py")


def _sealed(key=None, pub=None) -> list:
    events = _make_session()
    events.append(
        _signed_chain_seal(7, events[0]["session_id"], events[-1]["event_hash"], key, pub)
    )
    return events


def _write(events, path: Path) -> Path:
    path.write_text("\n".join(json.dumps(e) for e in events) + "\n")
    return path


def _cli(*argv):
    r = subprocess.run(
        [sys.executable, _CLI, "verify", *map(str, argv)],
        capture_output=True,
        text=True,
        env={**os.environ, "NO_COLOR": "1"},
    )
    return r.returncode, r.stdout, r.stderr


# --------------------------------------------------------------------------------------
# 1. pin / require_seal imply a seal; exactly one seal; seal is final
# --------------------------------------------------------------------------------------
class TestSealRequirements(unittest.TestCase):
    def test_pinned_key_with_no_seal_is_compromised(self):
        r = verify(_make_session(), trusted_seal_pubkey=_TEST_PUBKEY)
        assert r.status == COMPROMISED
        assert r.evidence_class == NO_EVIDENCE
        assert any("pinned key provided but session has no CHAIN_SEAL" in e for e in r.errors)

    def test_require_seal_with_no_seal_is_compromised(self):
        r = verify(_make_session(), require_seal=True)
        assert r.status == COMPROMISED
        assert any("seal required but session has no CHAIN_SEAL" in e for e in r.errors)

    def test_no_seal_and_no_requirement_is_still_intact_but_warns(self):
        r = verify(_make_session())
        assert r.status == INTACT
        assert r.evidence_class == NON_AUTHORITATIVE_EVIDENCE
        assert any("no CHAIN_SEAL" in w for w in r.warnings)

    def test_require_seal_accepts_a_valid_unpinned_seal_as_self_sealed(self):
        r = verify(_sealed(), require_seal=True)
        assert r.status == INTACT
        assert r.evidence_class == SELF_SEALED_EVIDENCE

    def test_two_chain_seals_rejected(self):
        events = _sealed()
        second = _signed_chain_seal(8, events[0]["session_id"], events[-1]["event_hash"])
        events.append(second)
        r = verify(events, trusted_seal_pubkey=_TEST_PUBKEY)
        assert r.status == COMPROMISED
        assert any("2 CHAIN_SEAL events" in e for e in r.errors)

    def test_two_chain_seals_rejected_even_when_unpinned(self):
        events = _sealed()
        events.append(_signed_chain_seal(8, events[0]["session_id"], events[-1]["event_hash"]))
        assert verify(events).status == COMPROMISED

    def test_chain_seal_not_final_event_rejected(self):
        # START, TOOL_CALL, CHAIN_SEAL, TOOL_RESULT, SESSION_END — chain is internally valid
        base = _make_session()
        events = base[:2]
        events.append(_signed_chain_seal(3, base[0]["session_id"], events[-1]["event_hash"]))
        for seq, src in ((4, base[3]), (5, base[5])):
            events.append(
                _build_event(
                    seq,
                    src["event_type"],
                    src["session_id"],
                    src["payload"],
                    events[-1]["event_hash"],
                )
            )
        r = verify(events)
        assert r.status == COMPROMISED
        assert any("CHAIN_SEAL must be the final event" in e for e in r.errors)


# --------------------------------------------------------------------------------------
# 3. seal payload consistency
# --------------------------------------------------------------------------------------
def _reseal(events, mutate):
    """Replace the seal on a sealed session with one whose payload is mutated, re-signed validly."""
    events = copy.deepcopy(events)
    seal = events[-1]
    mutate(seal["payload"])
    seal["event_hash"] = compute_event_hash(seal)
    seal["signature"] = sign_event_hash(_TEST_PRIVATE_KEY, seal["event_hash"])
    return events


class TestSealPayloadConsistency(unittest.TestCase):
    def test_session_hash_mismatch_is_compromised(self):
        events = _reseal(_sealed(), lambda p: p.update(session_hash="a" * 64))
        r = verify(events, trusted_seal_pubkey=_TEST_PUBKEY)
        assert r.status == COMPROMISED
        assert any("session_hash does not match" in e for e in r.errors)

    def test_session_hash_pointing_at_an_earlier_event_is_compromised(self):
        events = _sealed()
        events = _reseal(events, lambda p: p.update(session_hash=events[1]["event_hash"]))
        assert verify(events, trusted_seal_pubkey=_TEST_PUBKEY).status == COMPROMISED

    def test_missing_session_hash_is_compromised(self):
        events = _reseal(_sealed(), lambda p: p.pop("session_hash"))
        r = verify(events, trusted_seal_pubkey=_TEST_PUBKEY)
        assert r.status == COMPROMISED
        assert any("session_hash" in e for e in r.errors)

    def test_matching_session_hash_passes(self):
        events = _sealed()
        assert events[-1]["payload"]["session_hash"] == events[-2]["event_hash"]
        assert verify(events, trusted_seal_pubkey=_TEST_PUBKEY).status == INTACT

    def test_real_archeion_seal_session_hash_matches_chain_head(self):
        try:
            from fastapi.testclient import TestClient

            from archeion.server import app
        except ImportError:
            self.skipTest("fastapi / httpx not installed")
        client = TestClient(app)
        body = "\n".join(json.dumps(e) for e in _make_session()) + "\n"
        resp = client.post("/seal", content=body.encode())
        assert resp.status_code == 200
        sealed = [json.loads(ln) for ln in resp.text.splitlines() if ln.strip()]
        assert sealed[-1]["payload"]["session_hash"] == sealed[-2]["event_hash"]
        r = verify(sealed, trusted_seal_pubkey=client.get("/pubkey").json()["pubkey"])
        assert (r.status, r.evidence_class) == (INTACT, AUTHORITATIVE_EVIDENCE)


# --------------------------------------------------------------------------------------
# 4. fail closed on malformed input
# --------------------------------------------------------------------------------------
class TestMalformedInputFailsClosed(unittest.TestCase):
    def _assert_error(self, events):
        r = verify(events)  # must not raise
        assert r.status == ERROR, (r.status, r.errors)
        assert r.evidence_class == NO_EVIDENCE
        assert r.errors

    def test_empty_list(self):
        self._assert_error([])

    def test_not_a_list(self):
        self._assert_error({"seq": 1})

    def test_non_dict_event(self):
        events = _make_session()
        events[2] = [1, 2]
        self._assert_error(events)

    def test_scalar_events(self):
        for bad in (1, "x", None, 3.5, True):
            events = _make_session()
            events[1] = bad
            self._assert_error(events)

    def test_mixed_type_seq(self):
        events = _make_session()
        events[2]["seq"] = "3"
        self._assert_error(events)

    def test_bool_seq(self):
        events = _make_session()
        events[2]["seq"] = True
        self._assert_error(events)

    def test_float_seq(self):
        events = _make_session()
        events[2]["seq"] = 3.0
        self._assert_error(events)

    def test_payload_not_an_object(self):
        events = _make_session()
        events[1]["payload"] = "oops"
        self._assert_error(events)

    def test_unhashable_event_type_and_session_id(self):
        for field in ("event_type", "session_id"):
            events = _make_session()
            events[1][field] = ["x"]
            self._assert_error(events)

    def test_non_string_signature(self):
        events = _make_session()
        events[1]["signature"] = 12345
        self._assert_error(events)

    # --- well-typed but invalid: assessed and found bad → COMPROMISED, never a crash ---
    def _assert_compromised(self, events):
        r = verify(events)
        assert r.status == COMPROMISED, (r.status, r.errors)
        assert r.evidence_class == NO_EVIDENCE

    def test_missing_required_field(self):
        for field in (
            "seq",
            "event_type",
            "session_id",
            "timestamp",
            "payload",
            "prev_hash",
            "event_hash",
        ):
            events = _make_session()
            del events[2][field]
            self._assert_compromised(events)

    def test_non_string_hashes(self):
        for bad in (123, ["a" * 64], {"h": 1}, True, None):
            for field in ("event_hash", "prev_hash"):
                events = _make_session()
                events[2][field] = bad
                self._assert_compromised(events)

    def test_duplicate_seq(self):
        events = _make_session()
        events[3]["seq"] = events[2]["seq"]
        self._assert_compromised(events)

    def test_uppercase_or_short_hash(self):
        events = _make_session()
        events[2]["event_hash"] = events[2]["event_hash"].upper()
        self._assert_compromised(events)
        events = _make_session()
        events[2]["prev_hash"] = "abc"
        self._assert_compromised(events)


class TestCliFailsClosed(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def _run(self, content, *flags, binary=False):
        p = self.tmp / "s.jsonl"
        if binary:
            p.write_bytes(content)
        else:
            p.write_text(content)
        return _cli(p, *flags)

    def _assert_exit3_no_traceback(self, rc, out, err):
        assert rc == 3, (rc, out, err)
        assert "Traceback" not in err and "Traceback" not in out

    def test_empty_file(self):
        self._assert_exit3_no_traceback(*self._run(""))

    def test_non_dict_line(self):
        self._assert_exit3_no_traceback(*self._run("[1,2]\n"))

    def test_mixed_type_seq(self):
        ev = _make_session()
        ev[2]["seq"] = "3"
        self._assert_exit3_no_traceback(*self._run("\n".join(json.dumps(e) for e in ev) + "\n"))

    def test_invalid_json(self):
        self._assert_exit3_no_traceback(*self._run("not json\n"))

    def test_invalid_utf8(self):
        self._assert_exit3_no_traceback(*self._run(b"\xff\xfe\x00bad\n", binary=True))

    def test_missing_file(self):
        rc, out, err = _cli(self.tmp / "nope.jsonl")
        self._assert_exit3_no_traceback(rc, out, err)

    def test_json_mode_emits_error_object_on_stdout(self):
        rc, out, err = self._run("not json\n", "--json")
        assert rc == 3
        data = json.loads(out)
        assert data["status"] == ERROR and data["evidence_class"] == NO_EVIDENCE
        assert data["exit_code"] == 3

    def test_unknown_flag_is_an_error_not_silently_ignored(self):
        p = _write(_make_session(), self.tmp / "ok.jsonl")
        for bad in ("--trust_key", "--require-seals", "--stict", "--bogus"):
            rc, out, err = _cli(p, bad)
            assert rc == 3, (bad, rc, out, err)
            assert "Result: INTACT" not in out

    def test_typo_in_pin_flag_does_not_downgrade_to_unpinned_verdict(self):
        p = _write(_sealed(), self.tmp / "sealed.jsonl")
        rc, out, err = _cli(p, "--trust_key", _TEST_PUBKEY, "--json")
        assert rc == 3, (rc, out, err)
        assert out.strip() == "" and "unrecognized arguments" in err


# --------------------------------------------------------------------------------------
# 5. --json is a complete signal; exit-code contract; --strict
# --------------------------------------------------------------------------------------
class TestCliJsonAndExitCodes(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def _json(self, events, *flags):
        p = _write(events, self.tmp / "s.jsonl")
        rc, out, err = _cli(p, "--json", *flags)
        return rc, json.loads(out), err

    def test_json_contains_every_trust_relevant_field(self):
        rc, d, _ = self._json(_sealed(), "--trust-key", _TEST_PUBKEY)
        for key in (
            "status",
            "evidence_class",
            "exit_code",
            "errors",
            "warnings",
            "checks",
            "pinned",
            "require_seal",
            "strict",
            "seal_present",
            "seal_trusted",
            "timestamp",
            "timestamp_verified",
            "verifier_version",
        ):
            assert key in d, key
        assert d["pinned"] is True and d["seal_present"] is True and d["seal_trusted"] is True
        assert d["exit_code"] == rc == 0
        assert set(d["checks"]) >= {"hash_chain", "seal_signature", "rfc3161_timestamp"}
        assert set(d["timestamp"]) >= {
            "status",
            "imprint_match",
            "verified",
            "claimed_time_utc",
            "detail",
        }

    def test_unpinned_seal_is_visible_in_json(self):
        rc, d, _ = self._json(_sealed())
        assert rc == 0
        assert d["status"] == INTACT and d["evidence_class"] == SELF_SEALED_EVIDENCE
        assert d["pinned"] is False and d["seal_present"] is True and d["seal_trusted"] is False
        assert any(
            "seal not verified against a trusted key; anyone can produce this" in w
            for w in d["warnings"]
        )

    def test_exit_codes(self):
        assert self._json(_make_session())[0] == 0  # INTACT
        bad = _make_session()
        bad[2]["payload"]["x"] = 1
        assert self._json(bad)[0] == 1  # COMPROMISED
        partial = []
        for i, (et, pl) in enumerate(
            [
                ("SESSION_START", {"agent_id": "a"}),
                ("LOG_DROP", {"dropped_count": 1}),
                ("SESSION_END", {"status": "success"}),
            ],
            start=1,
        ):
            partial.append(
                _build_event(i, et, "p", pl, partial[-1]["event_hash"] if partial else GENESIS_HASH)
            )
        rc, d, _ = self._json(partial)
        assert rc == 2 and d["status"] == PARTIAL  # PARTIAL
        p = self.tmp / "empty.jsonl"
        p.write_text("")
        assert _cli(p)[0] == 3  # ERROR

    def test_strict_requires_trust_key(self):
        p = _write(_sealed(), self.tmp / "s.jsonl")
        rc, out, err = _cli(p, "--strict")
        assert rc == 3 and "--strict requires --trust-key" in err

    def test_strict_authoritative_exits_0(self):
        rc, d, _ = self._json(_sealed(), "--trust-key", _TEST_PUBKEY, "--strict")
        assert rc == 0 and d["evidence_class"] == AUTHORITATIVE_EVIDENCE and d["strict"] is True

    def test_strict_never_masks_failures_as_exit_4(self):
        # a genuine seal verified with a *different* pin is COMPROMISED, not exit 4 …
        other_priv, other_pub = generate_keypair()
        rc, d, _ = self._json(_sealed(), "--trust-key", other_pub, "--strict")
        assert rc == 1 and d["status"] == COMPROMISED
        # … while INTACT-but-unsealed under a pin is also COMPROMISED (seal required) …
        rc, d, _ = self._json(_make_session(), "--trust-key", _TEST_PUBKEY, "--strict")
        assert rc == 1 and d["status"] == COMPROMISED

    def test_strict_exit_4_guard(self):
        # Under --strict a pin is mandatory, and a pin that passes yields AUTHORITATIVE by
        # construction, so exit 4 is a defence-in-depth guard against any future class that
        # reaches INTACT without a trusted seal. Exercise the guard directly.
        import sasana_cli

        class R:
            status = "INTACT"
            evidence_class = SELF_SEALED_EVIDENCE

        assert sasana_cli._verify_exit_code(R, strict=True) == 4
        assert sasana_cli._verify_exit_code(R, strict=False) == 0

    def test_human_output_warns_on_unpinned_seal(self):
        p = _write(_sealed(), self.tmp / "s.jsonl")
        rc, out, _ = _cli(p)
        assert rc == 0
        assert "seal not verified against a trusted key; anyone can produce this" in out
        assert "SELF_SEALED_EVIDENCE" in out

    def test_human_output_has_no_warning_when_pinned(self):
        p = _write(_sealed(), self.tmp / "s.jsonl")
        rc, out, _ = _cli(p, "--trust-key", _TEST_PUBKEY)
        assert rc == 0 and "anyone can produce this" not in out
        assert "AUTHORITATIVE_EVIDENCE" in out


# --------------------------------------------------------------------------------------
# 6. timestamp honesty
# --------------------------------------------------------------------------------------
_AUTH = fx.make_authority()  # throwaway TSA, pinned nowhere


def _session_with_token(token_fn) -> list:
    sid = "ts-honesty"
    start = build_event(1, "SESSION_START", sid, {"agent_id": "a"}, GENESIS_HASH)
    pre = {k: v for k, v in start.items() if k not in ("event_hash", "signature")}
    pre_hash = hashlib.sha256(canonicalize(pre)).digest()
    start["payload"]["rfc3161_token"] = base64.b64encode(token_fn(pre_hash)).decode()
    start["event_hash"] = compute_event_hash(start)
    events = [start]
    for seq, (et, pl) in enumerate(
        [
            ("TOOL_CALL", {"tool_name": "t", "args_hash": "c" * 64}),
            ("SESSION_END", {"status": "success"}),
        ],
        start=2,
    ):
        events.append(build_event(seq, et, sid, pl, events[-1]["event_hash"]))
    return events


class TestTimestampHonesty(unittest.TestCase):
    def _assert_not_verified_time(self, events):
        r = verify(events)
        ts = r.checks["rfc3161_timestamp"]
        assert r.status == INTACT  # informational: does not change the verdict …
        assert r.timestamp_verified is False  # … and is never reported as verified time
        assert ts["status"] == "IMPRINT_MATCH"  # never a bare PASS
        assert ts["status"] != "PASS"
        assert "NOT verified" in ts["detail"]
        assert any("NOT verified" in w for w in r.warnings)
        return r, ts

    def test_backdated_token_is_not_verified_time(self):
        old = dt.datetime(2020, 1, 1, tzinfo=dt.timezone.utc)
        r, ts = self._assert_not_verified_time(
            _session_with_token(lambda h: fx.respond(_AUTH, h, gen_time=old))
        )
        assert ts["timestamp_utc"] == "2020-01-01T00:00:00Z"  # a claim, reported as such
        assert r.timestamp_imprint_match is True

    def test_corrupted_cms_signature_is_not_verified_time(self):
        self._assert_not_verified_time(
            _session_with_token(lambda h: fx.respond(_AUTH, h, tamper_signature=True))
        )

    def test_token_from_unpinned_tsa_is_not_verified_time(self):
        self._assert_not_verified_time(_session_with_token(lambda h: fx.respond(_AUTH, h)))

    def test_wrong_imprint_fails_and_is_not_verified(self):
        events = _session_with_token(lambda h: fx.respond(_AUTH, hashlib.sha256(b"x").digest()))
        r = verify(events)
        assert r.checks["rfc3161_timestamp"]["status"] == "FAIL"
        assert r.timestamp_verified is False and r.timestamp_imprint_match is False

    def test_cli_states_signature_and_gentime_are_not_verified(self):
        with tempfile.TemporaryDirectory() as tmp:
            old = dt.datetime(2020, 1, 1, tzinfo=dt.timezone.utc)
            p = _write(
                _session_with_token(
                    lambda h: fx.respond(_AUTH, h, gen_time=old, tamper_signature=True)
                ),
                Path(tmp) / "s.jsonl",
            )
            rc, out, _ = _cli(p)
            assert rc == 0
            assert "IMPRINT_MATCH" in out and "NOT verified" in out
            assert "PASS  (2020" not in out
            rc, out, _ = _cli(p, "--json")
            d = json.loads(out)
            assert d["timestamp"]["verified"] is False and d["timestamp_verified"] is False
            assert d["timestamp"]["imprint_match"] is True
            assert d["timestamp"]["claimed_time_utc"] == "2020-01-01T00:00:00Z"


# --------------------------------------------------------------------------------------
# Compliance reports must not call an untrusted seal "server-sealed"
# --------------------------------------------------------------------------------------
class TestComplianceDoesNotTrustPresenceOfSeal(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def _report(self, events, **kw):
        from sasana.compliance.eu_ai_act import generate_eu_ai_act_report

        p = _write(events, self.tmp / "s.jsonl")
        return generate_eu_ai_act_report(p, output_dir=self.tmp / "out", **kw)

    def test_unpinned_seal_is_not_reported_as_server_sealed(self):
        r = self._report(_sealed())
        assert r["evidence_class"] == SELF_SEALED_EVIDENCE
        assert r["requirement_checks"]["server_sealed"] is False

    def test_pinned_seal_is_reported_as_server_sealed(self):
        r = self._report(_sealed(), trusted_seal_pubkey=_TEST_PUBKEY)
        assert r["evidence_class"] == AUTHORITATIVE_EVIDENCE
        assert r["requirement_checks"]["server_sealed"] is True

    def test_attacker_seal_pinned_to_real_key_is_not_server_sealed(self):
        atk_priv, atk_pub = generate_keypair()
        r = self._report(_sealed(atk_priv, atk_pub), trusted_seal_pubkey=_TEST_PUBKEY)
        assert r["requirement_checks"]["server_sealed"] is False
        assert r["compliant"] is False  # chain check fails: the pinned verify is COMPROMISED

    def test_evidence_pack_cli_trust_key(self):
        p = _write(_sealed(), self.tmp / "s.jsonl")
        base = [sys.executable, _CLI, "evidence-pack", str(p), "--out", str(self.tmp / "o")]
        env = {**os.environ, "NO_COLOR": "1"}
        out = subprocess.run(base, capture_output=True, text=True, env=env).stdout
        assert "Evidence : SELF_SEALED_EVIDENCE" in out
        out = subprocess.run(
            base + ["--trust-key", _TEST_PUBKEY], capture_output=True, text=True, env=env
        ).stdout
        assert "Evidence : AUTHORITATIVE_EVIDENCE" in out


if __name__ == "__main__":
    unittest.main()
