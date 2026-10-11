"""
tests/test_commitment_mapping.py — the ha-daily-v1 payload mapping and the C_v2 preimage.

The mapping exists so that a successful hash check cannot hide a change in meaning: equivalent inputs
must hash the same and different inputs must not. Shared vectors live in
tests/fixtures/mapping/ha-daily-v1.json so another implementation can be held to the same table.
Synthetic data only.
"""

from __future__ import annotations

import hashlib
import json
import math
import sys
import unittest
from decimal import Decimal
from pathlib import Path

_ROOT = Path(__file__).parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from sasana import commitment as cm  # noqa: E402
from sasana import commitment_mapping as cmap  # noqa: E402

VECTORS = json.loads((_ROOT / "tests/fixtures/mapping/ha-daily-v1.json").read_text())


def h(submission: dict) -> str:
    return cm.payload_hash(cmap.map_ha_daily_v1(submission).payload).hex()


class TestCanonicalDecimal(unittest.TestCase):
    def test_spellings_of_the_same_number(self) -> None:
        for v in (0.6, "0.6", "0.60", "6e-1", "0.600000000000", Decimal("0.60")):
            self.assertEqual(cmap.canonical_decimal(v), "0.6", repr(v))

    def test_whole_numbers_have_no_fraction(self) -> None:
        # the 2026-10-10 break: 100 and 100.0 canonicalised differently across implementations
        for v in (100, 100.0, "100", "100.0", "1e2", "1E+2"):
            self.assertEqual(cmap.canonical_decimal(v), "100", repr(v))

    def test_zero_and_negative_zero(self) -> None:
        for v in (0, 0.0, -0.0, "0", "-0", "0.0", "-0.000", Decimal("-0")):
            self.assertEqual(cmap.canonical_decimal(v), "0", repr(v))

    def test_negative_numbers_keep_their_sign(self) -> None:
        self.assertEqual(cmap.canonical_decimal("-0.50"), "-0.5")
        self.assertEqual(cmap.canonical_decimal(-3), "-3")

    def test_never_an_exponent(self) -> None:
        for v in (1e-7, "1e-7", 1.5e10, "123456789012345678", "0.000000000001"):
            self.assertNotIn("e", cmap.canonical_decimal(v).lower(), repr(v))
        self.assertEqual(cmap.canonical_decimal(1e-7), "0.0000001")

    def test_precision_limits_reject_rather_than_round(self) -> None:
        self.assertEqual(cmap.canonical_decimal("0.123456789012"), "0.123456789012")  # 12 digits
        for v in ("0.1234567890123", 0.1 + 0.2, 5e-324, "1000000000000000000", 1e22):
            with self.assertRaises(cmap.MappingError, msg=repr(v)):
                cmap.canonical_decimal(v)

    def test_non_finite_and_non_numbers_rejected(self) -> None:
        for v in (float("nan"), float("inf"), float("-inf"), Decimal("NaN"), Decimal("Infinity")):
            with self.assertRaises(cmap.MappingError, msg=repr(v)):
                cmap.canonical_decimal(v)
        for v in (True, False, None, [1], {"a": 1}, b"1", "NaN", "inf", "", " 1", "1 ", "+1", ".5"):
            with self.assertRaises(cmap.MappingError, msg=repr(v)):
                cmap.canonical_decimal(v)

    def test_is_idempotent(self) -> None:
        for v in (0.6, "0.60", 100.0, "-0", 1e-7, 12345.678):
            once = cmap.canonical_decimal(v)
            self.assertEqual(cmap.canonical_decimal(once), once)

    def test_floats_enter_through_their_shortest_repr(self) -> None:
        # a float is the number its shortest round-trip repr denotes, not its exact binary expansion
        self.assertEqual(cmap.canonical_decimal(0.1), "0.1")
        self.assertEqual(cmap.canonical_decimal(0.72), "0.72")
        self.assertTrue(math.isfinite(float(cmap.canonical_decimal(0.1))))


class TestSharedVectors(unittest.TestCase):
    def test_vector_file_is_for_this_mapping(self) -> None:
        self.assertEqual(VECTORS["mapping"], cmap.HA_DAILY_V1)
        self.assertTrue(VECTORS["equivalent"] and VECTORS["distinct"] and VECTORS["rejected"])

    def test_equivalent_inputs_hash_the_same(self) -> None:
        for g in VECTORS["equivalent"]:
            hashes = {h(i) for i in g["inputs"]}
            self.assertEqual(len(hashes), 1, g["name"])
            self.assertEqual(hashes.pop(), g["payload_hash"], g["name"])
            self.assertEqual(
                cmap.map_ha_daily_v1(g["inputs"][0]).payload, g["canonical"], g["name"]
            )

    def test_different_inputs_hash_differently(self) -> None:
        for g in VECTORS["distinct"]:
            self.assertNotEqual(h(g["a"]), h(g["b"]), g["name"])

    def test_rejected_inputs(self) -> None:
        for g in VECTORS["rejected"]:
            with self.assertRaises(cmap.MappingError, msg=g["name"]) as ctx:
                cmap.map_ha_daily_v1(g["input"])
            self.assertIn(g["error_contains"], str(ctx.exception), g["name"])

    def test_the_named_cases_from_the_review(self) -> None:
        base = {"direction": "up", "confidence": 0.6, "reasoning": "r" * 25}
        self.assertEqual(h({**base, "confidence": 0.6}), h({**base, "confidence": "0.60"}))
        self.assertNotEqual(h({**base, "confidence": 0.6}), h({**base, "confidence": 0.06}))
        self.assertNotEqual(h({**base, "direction": "up"}), h({**base, "direction": "down"}))
        self.assertNotEqual(
            h({**base}), h({**base, "summary": ""})
        )  # field missing vs empty string
        self.assertNotEqual(h({**base, "summary": None}), h({**base, "summary": ""}))


class TestMappingBehaviour(unittest.TestCase):
    SUB = {
        "direction": "up",
        "confidence": 0.72,
        "probabilities": {"up": 0.72, "down": 0.28},
        "reasoning": "x" * 30,
        "summary": "s",
        "is_revision": False,
        "prompt_hash": "a" * 64,
        "amount": 5,
        "token_usage": {"input": 1},
        "trigger_event_id": "ev-1",
    }

    def test_only_the_seven_fields_are_bound(self) -> None:
        m = cmap.map_ha_daily_v1(self.SUB)
        self.assertEqual(set(m.payload), set(cmap.BOUND_FIELDS) - {"revision_reason"})
        self.assertEqual(
            set(m.unbound_present), {"prompt_hash", "amount", "token_usage", "trigger_event_id"}
        )
        self.assertEqual(
            set(cmap.BOUND_FIELDS) | set(cmap.UNBOUND_FIELDS),
            {
                "direction",
                "confidence",
                "probabilities",
                "reasoning",
                "summary",
                "is_revision",
                "revision_reason",
                "prompt_hash",
                "amount",
                "token_usage",
                "trigger_event_id",
            },
        )

    def test_payload_satisfies_the_commitment_profile(self) -> None:
        cm.validate_payload_profile(cmap.map_ha_daily_v1(self.SUB).payload)  # no floats survive

    def test_text_is_byte_exact(self) -> None:
        a = cmap.map_ha_daily_v1({"reasoning": "café"}).payload
        b = cmap.map_ha_daily_v1({"reasoning": "café"}).payload
        self.assertNotEqual(a, b)  # no Unicode normalisation: NFC and NFD are different bytes
        with self.assertRaises(cmap.MappingError):
            cmap.map_ha_daily_v1({"reasoning": "\ud800"})

    def test_mapping_is_pure(self) -> None:
        sub = dict(self.SUB)
        cmap.map_ha_daily_v1(sub)
        self.assertEqual(sub, self.SUB)

    def test_check_canonical(self) -> None:
        good = cmap.map_ha_daily_v1(self.SUB).payload
        cmap.check_canonical_ha_daily_v1(good)
        for bad in (
            {**good, "confidence": "0.720"},  # hashes differently from every other implementation
            {**good, "confidence": 0.72},  # a float
            {**good, "probabilities": {"up": "0.72", "down": "0.280"}},
            {**good, "prompt_hash": "a" * 64},  # not a bound field
            {**good, "is_revision": 0},
        ):
            with self.assertRaises(cmap.MappingError, msg=str(bad)):
                cmap.check_canonical_ha_daily_v1(bad)

    def test_registry(self) -> None:
        self.assertEqual(cmap.known_mapping_ids(), (cmap.HA_DAILY_V1,))
        self.assertIsNone(cmap.get_mapping("ha-daily-v2"))
        for bad in ("", "HA", "a b", "x" * 65, None, 3):
            with self.assertRaises(ValueError):
                cmap.validate_mapping_id(bad)


class TestProbabilityPolicy(unittest.TestCase):
    """The sum policy is a WARNING, not a rejection: the mapping must be total over whatever the
    counterparty accepted, or a forecast it scored could not be committed."""

    def w(self, probs):
        return cmap.probability_warnings(cmap.map_ha_daily_v1({"probabilities": probs}).payload)

    def test_sums_within_tolerance_are_silent(self) -> None:
        self.assertEqual(self.w({"up": 0.6, "down": 0.4}), [])
        self.assertEqual(self.w([0.333333, 0.333333, 0.333334]), [])
        self.assertEqual(self.w({"up": "0.5000004", "down": "0.5"}), [])  # off by 4e-7 < 1e-6

    def test_off_sum_is_flagged_but_still_mappable(self) -> None:
        self.assertEqual(self.w({"up": 0.6, "down": 0.5}), ["PROBABILITY_SUM:1.1"])
        self.assertEqual(self.w({"up": "0.5000011", "down": "0.5"}), ["PROBABILITY_SUM:1.0000011"])

    def test_negative_entries_are_flagged(self) -> None:
        self.assertIn("PROBABILITY_NEGATIVE", self.w({"up": 1.2, "down": -0.2}))

    def test_absent_probabilities_are_not_flagged(self) -> None:
        self.assertEqual(cmap.probability_warnings({"direction": "up"}), [])


class TestCrossCheckAgainstPublishedPrediction(unittest.TestCase):
    """After resolution the counterparty publishes direction, confidence, reasoning and summary per
    prediction (and not probabilities, is_revision, revision_reason). Those four can be cross-checked."""

    PAYLOAD = cmap.map_ha_daily_v1(
        {
            "direction": "up",
            "confidence": 0.72,
            "probabilities": {"up": 0.72, "down": 0.28},
            "reasoning": "r" * 30,
            "summary": "s",
            "is_revision": False,
        }
    ).payload

    def test_match_ignores_number_spelling(self) -> None:
        pub = {"direction": "up", "confidence": 0.72, "reasoning": "r" * 30, "summary": "s"}
        out = cmap.cross_check_published(self.PAYLOAD, pub)
        self.assertEqual(out["mismatches"], [])
        self.assertEqual(set(out["compared"]), set(cmap.PUBLISHED_COMPARABLE))
        self.assertEqual(
            set(out["not_published"]), {"probabilities", "is_revision", "revision_reason"}
        )

    def test_mismatch_is_reported_per_field(self) -> None:
        pub = {"direction": "down", "confidence": "0.27", "reasoning": "r" * 30, "summary": "s"}
        self.assertEqual(
            cmap.cross_check_published(self.PAYLOAD, pub)["mismatches"], ["direction", "confidence"]
        )

    def test_unparseable_published_confidence_is_a_mismatch(self) -> None:
        pub = {"confidence": "high"}
        self.assertEqual(
            cmap.cross_check_published(self.PAYLOAD, pub)["mismatches"], ["confidence"]
        )


class TestCommitmentV2Preimage(unittest.TestCase):
    ROOT = "ab" * 32
    SALT = bytes(range(32))
    PREV = "cd" * 32
    PAYLOAD = {"direction": "up"}

    def kw(self, **over):
        base = dict(
            mapping_id="ha-daily-v1",
            subject_id="agent-1",
            context_id="challenge-1",
            revision_index=1,
            prev_commitment=self.PREV,
            payload=self.PAYLOAD,
            session_root=self.ROOT,
            salt=self.SALT,
        )
        return {**base, **over}

    def test_known_answer_matches_independent_construction(self) -> None:
        def lp(b: bytes) -> bytes:
            return len(b).to_bytes(4, "big") + b

        ph = hashlib.sha256(b'{"direction":"up"}').digest()
        expected = hashlib.sha256(
            lp(b"sasana/commit/v2")
            + lp(b"ha-daily-v1")
            + lp(b"agent-1")
            + lp(b"challenge-1")
            + lp((1).to_bytes(4, "big"))
            + lp(bytes.fromhex(self.PREV))
            + lp(ph)
            + lp(bytes.fromhex(self.ROOT))
            + lp(self.SALT)
        ).hexdigest()
        self.assertEqual(cm.compute_commitment_v2(**self.kw()), expected)

    def test_revision_zero_has_an_empty_prev_field(self) -> None:
        def lp(b: bytes) -> bytes:
            return len(b).to_bytes(4, "big") + b

        data = cm.encode_commitment_input_v2(
            mapping_id="m",
            subject_id="s",
            context_id="c",
            revision_index=0,
            prev_commitment=None,
            payload_hash_raw=b"\x00" * 32,
            session_root=self.ROOT,
            salt=self.SALT,
        )
        self.assertIn(lp(b""), data)
        self.assertTrue(data.startswith(lp(b"sasana/commit/v2") + lp(b"m")))

    def test_every_input_changes_the_commitment_including_mapping_and_prev(self) -> None:
        c0 = cm.compute_commitment_v2(**self.kw())
        for k, v in [
            ("mapping_id", "ha-daily-v2"),
            ("subject_id", "agent-2"),
            ("context_id", "challenge-2"),
            ("revision_index", 2),
            ("prev_commitment", "ee" * 32),
            ("payload", {"direction": "down"}),
            ("session_root", "01" * 32),
            ("salt", b"\x09" * 32),
        ]:
            self.assertNotEqual(cm.compute_commitment_v2(**self.kw(**{k: v})), c0, k)

    def test_v1_and_v2_never_collide(self) -> None:
        v1 = cm.compute_commitment(
            subject_id="agent-1",
            context_id="challenge-1",
            revision_index=1,
            payload=self.PAYLOAD,
            session_root=self.ROOT,
            salt=self.SALT,
        )
        self.assertNotEqual(v1, cm.compute_commitment_v2(**self.kw()))

    def test_prev_is_required_exactly_when_revision_is_not_zero(self) -> None:
        for over in ({"revision_index": 0}, {"prev_commitment": None}):
            with self.assertRaises(ValueError, msg=str(over)):
                cm.compute_commitment_v2(**self.kw(**over))
        cm.compute_commitment_v2(**self.kw(revision_index=0, prev_commitment=None))

    def test_input_validation(self) -> None:
        for over in (
            {"prev_commitment": "AB" * 32},
            {"prev_commitment": "ab" * 31},
            {"mapping_id": "Bad Id"},
            {"salt": b"\x00" * 31},
            {"session_root": "00" * 31},
            {"revision_index": -1},
            {"revision_index": True},
        ):
            with self.assertRaises((ValueError, TypeError), msg=str(over)):
                cm.compute_commitment_v2(**self.kw(**over))


if __name__ == "__main__":
    unittest.main()
