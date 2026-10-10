"""
tests/test_jcs.py — RFC 8785 number-serialization conformance.

Vectors are RFC 8785 Appendix B (IEEE-754 bit pattern -> canonical text).
"""

from __future__ import annotations

import struct
import sys
import unittest
from pathlib import Path

_ROOT = Path(__file__).parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from sasana.jcs import canonicalize  # noqa: E402

_APPENDIX_B = {
    0x0000000000000000: "0",
    0x8000000000000000: "0",
    0x0000000000000001: "5e-324",
    0x8000000000000001: "-5e-324",
    0x7FEFFFFFFFFFFFFF: "1.7976931348623157e+308",
    0xFFEFFFFFFFFFFFFF: "-1.7976931348623157e+308",
    0x4340000000000000: "9007199254740992",
    0xC340000000000000: "-9007199254740992",
    0x4430000000000000: "295147905179352830000",
    0x44B52D02C7E14AF5: "9.999999999999997e+22",
    0x44B52D02C7E14AF6: "1e+23",
    0x44B52D02C7E14AF7: "1.0000000000000001e+23",
    0x444B1AE4D6E2EF4E: "999999999999999700000",
    0x444B1AE4D6E2EF4F: "999999999999999900000",
    0x444B1AE4D6E2EF50: "1e+21",
    0x3EB0C6F7A0B5ED8C: "9.999999999999997e-7",
    0x3EB0C6F7A0B5ED8D: "0.000001",
    0x41B3DE4355555553: "333333333.3333332",
    0x41B3DE4355555554: "333333333.33333325",
    0x41B3DE4355555555: "333333333.3333333",
    0x41B3DE4355555556: "333333333.3333334",
    0x41B3DE4355555557: "333333333.33333343",
    0xBECBF647612F3696: "-0.0000033333333333333333",
    0x43143FF3C1CB0959: "1424953923781206.2",
}


class TestJcsNumbers(unittest.TestCase):
    def test_rfc8785_appendix_b(self) -> None:
        for bits, expected in _APPENDIX_B.items():
            f = struct.unpack(">d", struct.pack(">Q", bits))[0]
            self.assertEqual(canonicalize(f).decode(), expected, hex(bits))

    def test_small_and_large_exponents(self) -> None:
        self.assertEqual(canonicalize(0.00001), b"0.00001")
        self.assertEqual(canonicalize(1e-7), b"1e-7")
        self.assertEqual(canonicalize(1e16), b"10000000000000000")
        self.assertEqual(canonicalize(1e21), b"1e+21")

    def test_ordinary_values_unchanged(self) -> None:
        self.assertEqual(canonicalize(0.7), b"0.7")
        self.assertEqual(canonicalize(-12.5), b"-12.5")
        self.assertEqual(canonicalize(42), b"42")
        self.assertEqual(canonicalize({"b": [1, 2.5], "a": None}), b'{"a":null,"b":[1,2.5]}')

    def test_integers_within_safe_range_are_exact(self) -> None:
        self.assertEqual(canonicalize(2**53), b"9007199254740992")
        self.assertEqual(canonicalize(-(2**53)), b"-9007199254740992")

    def test_integers_beyond_safe_range_round_through_double(self) -> None:
        self.assertEqual(canonicalize(2**60), b"1152921504606847000")

    def test_non_finite_rejected(self) -> None:
        for bad in (float("nan"), float("inf"), float("-inf")):
            with self.assertRaises(ValueError):
                canonicalize(bad)

    def test_bool_is_not_a_number(self) -> None:
        self.assertEqual(canonicalize(True), b"true")
        self.assertEqual(canonicalize(False), b"false")


if __name__ == "__main__":
    unittest.main()
