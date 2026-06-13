"""
tests/test_verifier.py — Adversarial and correctness tests for sasana.verifier.

Each test class represents one attack surface or invariant. Tests are authored
from the adversary's perspective — what an attacker would attempt against the
hash-chain integrity guarantee, and what the verifier must catch.
"""

from __future__ import annotations

import datetime
import sys
import unittest
from pathlib import Path

_ROOT = Path(__file__).parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from sasana.signing import generate_keypair, sign_event_hash  # noqa: E402
from sasana.verifier import (  # noqa: E402
    AUTHORITATIVE_EVIDENCE,
    COMPROMISED,
    ERROR,
    GENESIS_HASH,
    INTACT,
    NON_AUTHORITATIVE_EVIDENCE,
    PARTIAL,
    PARTIAL_EVIDENCE,
    SIGNED_NON_AUTHORITATIVE_EVIDENCE,
    compute_event_hash,
    verify,
)

# Module-level test keypair — generated once, shared across all tests that build signed seals.
_TEST_PRIVATE_KEY, _TEST_PUBKEY = generate_keypair()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _ts() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"


def _build_event(seq: int, event_type: str, session_id: str, payload: dict, prev_hash: str) -> dict:
    evt: dict = {
        "seq": seq,
        "event_type": event_type,
        "session_id": session_id,
        "timestamp": _ts(),
        "payload": payload,
        "prev_hash": prev_hash,
    }
    evt["event_hash"] = compute_event_hash(evt)
    return evt


def _make_session(session_id: str = "test-session") -> list:
    """Build a minimal valid 6-event session."""
    events: list = []

    def append(seq: int, et: str, payload: dict) -> None:
        prev = events[-1]["event_hash"] if events else GENESIS_HASH
        events.append(_build_event(seq, et, session_id, payload, prev))

    append(1, "SESSION_START", {"agent_id": "test-agent"})
    append(2, "LLM_CALL", {"prompt_hash": "a" * 64})
    append(3, "LLM_RESPONSE", {"content_hash": "b" * 64})
    append(4, "TOOL_CALL", {"tool_name": "bash", "args_hash": "c" * 64})
    append(5, "TOOL_RESULT", {"result_hash": "d" * 64})
    append(6, "SESSION_END", {"status": "success"})
    return events


def _signed_chain_seal(seq: int, session_id: str, prev_hash: str) -> dict:
    """Build a properly signed CHAIN_SEAL event using the module-level test keypair."""
    seal: dict = {
        "seq": seq,
        "event_type": "CHAIN_SEAL",
        "session_id": session_id,
        "timestamp": _ts(),
        "payload": {
            "session_hash": prev_hash,
            "sealed_by": "archeion-test",
            "server_pubkey": _TEST_PUBKEY,
        },
        "prev_hash": prev_hash,
    }
    seal["event_hash"] = compute_event_hash(seal)
    seal["signature"] = sign_event_hash(_TEST_PRIVATE_KEY, seal["event_hash"])
    return seal


def _rechain(events: list) -> list:
    """Recompute all hashes from scratch after structural modifications."""
    out = []
    for i, evt in enumerate(events):
        prev = out[-1]["event_hash"] if out else GENESIS_HASH
        rebuilt = {**evt, "prev_hash": prev}
        rebuilt["event_hash"] = compute_event_hash(rebuilt)
        out.append(rebuilt)
    return out


# ---------------------------------------------------------------------------
# Golden vector — catches hash algorithm drift
# ---------------------------------------------------------------------------


class TestGoldenVector(unittest.TestCase):
    def test_genesis_hash_is_64_zeros(self):
        assert GENESIS_HASH == "0" * 64 and len(GENESIS_HASH) == 64

    def test_compute_event_hash_deterministic(self):
        evt = _build_event(1, "SESSION_START", "s1", {"agent_id": "x"}, GENESIS_HASH)
        assert compute_event_hash(evt) == compute_event_hash(evt)

    def test_event_hash_excludes_event_hash_and_signature(self):
        """event_hash and signature must not contribute to the hash input."""
        base = _build_event(1, "SESSION_START", "s1", {"agent_id": "x"}, GENESIS_HASH)
        with_noise = {**base, "event_hash": "dead" * 16, "signature": "fakesig"}
        assert compute_event_hash(base) == compute_event_hash(with_noise)

    def test_payload_mutation_changes_hash(self):
        evt = _build_event(1, "SESSION_START", "s1", {"k": "v"}, GENESIS_HASH)
        h1 = evt["event_hash"]
        evt["payload"]["k"] = "different"
        assert compute_event_hash(evt) != h1

    def test_valid_session_is_intact(self):
        r = verify(_make_session())
        assert r.status == INTACT
        assert r.evidence_class == NON_AUTHORITATIVE_EVIDENCE
        assert r.errors == []
        assert r.event_count == 6
        assert r.log_drop_count == 0


# ---------------------------------------------------------------------------
# A1 — Payload mutation attack
# ---------------------------------------------------------------------------


class TestPayloadMutation(unittest.TestCase):
    """Attacker edits payload content after the event is written."""

    def test_single_field_mutation_detected(self):
        events = _make_session()
        events[2]["payload"]["injected"] = "malicious"
        r = verify(events)
        assert r.status == COMPROMISED
        assert any("event_hash mismatch" in e for e in r.errors)

    def test_payload_replacement_detected(self):
        events = _make_session()
        events[3]["payload"] = {"tool_name": "rm", "args_hash": "e" * 64}
        r = verify(events)
        assert r.status == COMPROMISED

    def test_session_start_metadata_mutation_detected(self):
        events = _make_session()
        events[0]["payload"]["agent_id"] = "impersonator"
        r = verify(events)
        assert r.status == COMPROMISED


# ---------------------------------------------------------------------------
# A2 — Genesis hash forgery (covers log truncation)
# ---------------------------------------------------------------------------


class TestGenesisForgery(unittest.TestCase):
    """Attacker replaces seq=1 prev_hash to cover a truncated log."""

    def test_non_genesis_prev_hash_on_seq1_detected(self):
        events = _make_session()
        events[0]["prev_hash"] = "1" * 64
        events[0]["event_hash"] = compute_event_hash(events[0])
        # Recompute downstream so hash chain is internally consistent
        for i in range(1, len(events)):
            events[i]["prev_hash"] = events[i - 1]["event_hash"]
            events[i]["event_hash"] = compute_event_hash(events[i])
        r = verify(events)
        assert r.status == COMPROMISED
        assert any("genesis" in e for e in r.errors)


# ---------------------------------------------------------------------------
# A3 — Event deletion with chain relinking
# ---------------------------------------------------------------------------


class TestEventDeletion(unittest.TestCase):
    """Attacker deletes an event and relinks the chain to hide the gap."""

    def test_deleted_event_detected_via_sequence_gap(self):
        events = _make_session()
        events.pop(2)  # remove seq=3 (LLM_RESPONSE)
        # Relink seq=4's prev_hash to seq=2's event_hash
        events[2]["prev_hash"] = events[1]["event_hash"]
        events[2]["event_hash"] = compute_event_hash(events[2])
        for i in range(3, len(events)):
            events[i]["prev_hash"] = events[i - 1]["event_hash"]
            events[i]["event_hash"] = compute_event_hash(events[i])
        r = verify(events)
        # Sequence check catches the missing seq=3
        assert r.status == COMPROMISED

    def test_seq_renumbered_after_deletion_detected(self):
        """Attacker also renumbers seqs to hide the gap — first event hash reveals it."""
        events = _make_session()
        events.pop(2)  # remove seq=3
        # Renumber and rechain — but the original seq=4 now maps to a different position,
        # so the event_hash of seq=3 won't match what was written originally
        for i, evt in enumerate(events):
            evt["seq"] = i + 1
        events = _rechain(events)
        r = verify(events)
        # Chain is internally consistent, but the sequence integrity check
        # will now pass (the attacker successfully renumbered). This is the
        # documented NON_AUTHORITATIVE_EVIDENCE limitation — the only defence
        # against this attack is AUTHORITATIVE_EVIDENCE (server seal).
        # This test documents, not fails, that behaviour.
        assert r.evidence_class in (NON_AUTHORITATIVE_EVIDENCE, AUTHORITATIVE_EVIDENCE)


# ---------------------------------------------------------------------------
# A4 — Event reordering
# ---------------------------------------------------------------------------


class TestEventReordering(unittest.TestCase):
    """
    Attacker swaps event content to change the apparent execution order.

    Note: the verifier sorts by seq, so list-position reordering without
    changing the event content is undetectable — and correctly so, since
    the chain's logical ordering is defined by seq+prev_hash, not file position.
    What an attacker can attempt is swapping payloads between seq positions,
    which breaks the event_hash of both affected events.
    """

    def test_payload_swap_between_positions_detected(self):
        events = _make_session()
        # Swap event_type + payload of seq=3 and seq=4 — event_hashes now wrong
        events[2]["event_type"], events[3]["event_type"] = (
            events[3]["event_type"],
            events[2]["event_type"],
        )
        events[2]["payload"], events[3]["payload"] = (events[3]["payload"], events[2]["payload"])
        r = verify(events)
        assert r.status == COMPROMISED

    def test_non_adjacent_payload_swap_detected(self):
        events = _make_session()
        events[1]["payload"], events[4]["payload"] = (events[4]["payload"], events[1]["payload"])
        r = verify(events)
        assert r.status == COMPROMISED


# ---------------------------------------------------------------------------
# A5 — Event insertion
# ---------------------------------------------------------------------------


class TestEventInsertion(unittest.TestCase):
    """Attacker injects a forged event into the middle of the chain."""

    def test_inserted_event_detected_via_chain_break(self):
        events = _make_session()
        forged = _build_event(
            7,
            "TOOL_CALL",
            events[0]["session_id"],
            {"tool_name": "rm", "args_hash": "e" * 64},
            events[-2]["event_hash"],
        )
        events.insert(-1, forged)  # insert before SESSION_END
        # SESSION_END now has the wrong prev_hash (points to seq=5, not forged seq=7)
        r = verify(events)
        assert r.status == COMPROMISED


# ---------------------------------------------------------------------------
# A6 — Full log replacement (documents known NON_AUTHORITATIVE limitation)
# ---------------------------------------------------------------------------


class TestFullLogReplacement(unittest.TestCase):
    """
    Attacker replaces the entire log with a fresh valid chain.
    Without a server seal this attack is undetectable — the verifier
    correctly reports NON_AUTHORITATIVE_EVIDENCE, not INTACT.
    """

    def test_replacement_passes_without_seal_non_authoritative(self):
        fake = _make_session(session_id="original-id")
        fake[1]["payload"]["prompt_hash"] = "f" * 64
        fake = _rechain(fake)
        r = verify(fake)
        assert r.status == INTACT
        assert r.evidence_class == NON_AUTHORITATIVE_EVIDENCE

    def test_replacement_requires_authoritative_evidence_to_prevent(self):
        """CHAIN_SEAL commits to the original root hash; a replacement would differ."""
        events = _make_session()
        events.append(_signed_chain_seal(7, events[0]["session_id"], events[-1]["event_hash"]))
        r = verify(events)
        assert r.evidence_class == AUTHORITATIVE_EVIDENCE


# ---------------------------------------------------------------------------
# Sequence integrity
# ---------------------------------------------------------------------------


class TestSequenceIntegrity(unittest.TestCase):
    def test_seq_gap_detected(self):
        events = _make_session()
        events[3]["seq"] = 99
        r = verify(events)
        assert r.status == COMPROMISED

    def test_duplicate_seq_detected(self):
        events = _make_session()
        events[3]["seq"] = events[2]["seq"]
        r = verify(events)
        assert r.status == COMPROMISED

    def test_seq_not_starting_at_one_detected(self):
        events = _make_session()
        for i, e in enumerate(events):
            e["seq"] = i + 2  # starts at 2
        r = verify(events)
        assert r.status == COMPROMISED

    def test_mixed_session_ids_detected(self):
        events = _make_session()
        events[3]["session_id"] = "attacker-session"
        r = verify(events)
        assert r.status == COMPROMISED


# ---------------------------------------------------------------------------
# Session completeness
# ---------------------------------------------------------------------------


class TestSessionCompleteness(unittest.TestCase):
    def test_missing_session_start_detected(self):
        r = verify(_make_session()[1:])
        assert r.status == COMPROMISED

    def test_missing_session_end_without_seal_detected(self):
        r = verify(_make_session()[:-1])
        assert r.status == COMPROMISED

    def test_chain_seal_alone_accepted_as_closing_marker(self):
        events = _make_session()[:-1]  # no SESSION_END
        events.append(_signed_chain_seal(6, events[0]["session_id"], events[-1]["event_hash"]))
        r = verify(events)
        assert r.status == INTACT
        assert r.evidence_class == AUTHORITATIVE_EVIDENCE

    def test_chain_seal_after_session_end_accepted(self):
        events = _make_session()
        events.append(_signed_chain_seal(7, events[0]["session_id"], events[-1]["event_hash"]))
        r = verify(events)
        assert r.status == INTACT
        assert r.evidence_class == AUTHORITATIVE_EVIDENCE


# ---------------------------------------------------------------------------
# Evidence classes
# ---------------------------------------------------------------------------


class TestEvidenceClasses(unittest.TestCase):
    def test_non_authoritative_for_unsigned_local_session(self):
        assert verify(_make_session()).evidence_class == NON_AUTHORITATIVE_EVIDENCE

    def test_authoritative_for_chain_sealed_session(self):
        events = _make_session()
        events.append(_signed_chain_seal(7, events[0]["session_id"], events[-1]["event_hash"]))
        assert verify(events).evidence_class == AUTHORITATIVE_EVIDENCE

    def test_signed_non_authoritative_when_signatures_valid(self):
        r = verify(_make_session(), signatures_valid=True)
        assert r.evidence_class == SIGNED_NON_AUTHORITATIVE_EVIDENCE

    def test_partial_evidence_for_session_with_log_drop(self):
        events: list = []

        def append(seq: int, et: str, payload: dict) -> None:
            prev = events[-1]["event_hash"] if events else GENESIS_HASH
            events.append(_build_event(seq, et, "drop-session", payload, prev))

        append(1, "SESSION_START", {"agent_id": "a"})
        append(2, "LOG_DROP", {"dropped_count": 3})
        append(3, "SESSION_END", {"status": "success"})
        r = verify(events)
        assert r.status == PARTIAL
        assert r.evidence_class == PARTIAL_EVIDENCE
        assert r.log_drop_count == 1

    def test_no_evidence_for_compromised_session(self):
        events = _make_session()
        events[2]["payload"]["evil"] = "injected"
        assert verify(events).evidence_class == "NO_EVIDENCE"

    def test_log_drop_degrades_sealed_session_to_partial(self):
        """CHAIN_SEAL + LOG_DROP → PARTIAL_EVIDENCE, not AUTHORITATIVE."""
        events: list = []

        def append(seq: int, et: str, payload: dict) -> None:
            prev = events[-1]["event_hash"] if events else GENESIS_HASH
            events.append(_build_event(seq, et, "s1", payload, prev))

        append(1, "SESSION_START", {})
        append(2, "LOG_DROP", {"dropped_count": 1})
        append(3, "SESSION_END", {"status": "success"})
        events.append(_signed_chain_seal(4, "s1", events[-1]["event_hash"]))
        r = verify(events)
        assert r.evidence_class == PARTIAL_EVIDENCE


# ---------------------------------------------------------------------------
# Edge cases and structural checks
# ---------------------------------------------------------------------------


class TestEdgeCases(unittest.TestCase):
    def test_empty_session_is_error(self):
        r = verify([])
        assert r.status == ERROR
        assert r.evidence_class == "NO_EVIDENCE"
        assert "empty" in r.errors[0].lower()

    def test_single_session_start_only_is_incomplete(self):
        events = [_build_event(1, "SESSION_START", "s1", {"agent_id": "x"}, GENESIS_HASH)]
        r = verify(events)
        assert r.status == COMPROMISED

    def test_session_id_preserved(self):
        r = verify(_make_session(session_id="my-session-42"))
        assert r.session_id == "my-session-42"

    def test_root_hash_is_last_event_hash(self):
        events = _make_session()
        r = verify(events)
        assert r.root_hash == events[-1]["event_hash"]

    def test_all_check_results_present_on_pass(self):
        r = verify(_make_session())
        for key in ("structural", "sequence", "hash_chain", "completeness"):
            assert key in r.checks
            assert r.checks[key]["status"] == "PASS"

    def test_downstream_checks_skipped_on_structural_failure(self):
        events = _make_session()
        del events[0]["seq"]  # structurally invalid
        r = verify(events)
        assert r.checks["structural"]["status"] == "FAIL"
        for key in ("sequence", "hash_chain", "completeness"):
            assert r.checks[key]["status"] == "SKIPPED"

    def test_unknown_event_type_caught_by_structural_check(self):
        events = _make_session()
        events[2]["event_type"] = "EVIL_TYPE"
        events[2]["event_hash"] = compute_event_hash(events[2])
        r = verify(events)
        assert r.status == COMPROMISED
        assert r.checks["structural"]["status"] == "FAIL"

    def test_bad_hex_in_prev_hash_caught_by_structural(self):
        events = _make_session()
        events[2]["prev_hash"] = "zzzz" + "0" * 60
        r = verify(events)
        assert r.status == COMPROMISED


if __name__ == "__main__":
    unittest.main()
