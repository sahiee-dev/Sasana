"""
tests/test_cli_strict_flags.py — a mistyped or abbreviated flag must never be guessed at or dropped.

In <= 2.0.1, `seal`, `verify-commitment` and `evidence-pack` parsed with `parse_known_args`, so an unknown
flag was silently ignored (a mistyped `--trust-key` removed the key pin and the command still ran), and
every subcommand allowed argparse's prefix abbreviation (`--trust-ke`). Every subcommand now exits 3 on
either, before doing any work. These tests run the real CLI with otherwise-valid inputs, so the only thing
that can make them exit 3 is the flag.
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

_ROOT = Path(__file__).parent.parent
_CLI = str(_ROOT / "sasana_cli.py")
_VERIFY_PY = str(_ROOT / "verify.py")
_SESSION = _ROOT / "tests" / "fixtures" / "legacy" / "v1.1.0_sealed.jsonl"
_KEY = (
    "A" * 43 + "="
)  # well-formed base64 of 32 zero bytes: a pin that cannot match the fixture's seal


def run(*args: str, script: str = _CLI, timeout: int = 20):
    r = subprocess.run(
        [sys.executable, script, *args],
        capture_output=True,
        text=True,
        timeout=timeout,
        env={**os.environ, "NO_COLOR": "1"},
    )
    return r.returncode, r.stdout, r.stderr


class TestEverySubcommandRefusesGuesses(unittest.TestCase):
    def assert_refused(self, *args: str, script: str = _CLI) -> None:
        code, out, err = run(*args, script=script)
        self.assertEqual(code, 3, (args, out[-300:], err[-300:]))
        self.assertIn("error:", err, args)  # refused by the parser, not by some later failure
        self.assertEqual(out.strip(), "", f"produced output before refusing: {args}")

    def test_verify(self) -> None:
        for flag in ("--trust-ke", "--trust", "--truts-key", "--require-sea", "--stric", "--js"):
            with self.subTest(flag=flag):
                self.assert_refused(
                    "verify", str(_SESSION), flag, *([_KEY] if "trust" in flag else [])
                )

    def test_verify_py_alias_agentops_verify(self) -> None:
        self.assert_refused(str(_SESSION), "--trust-ke", _KEY, script=_VERIFY_PY)

    def test_evidence_pack_does_not_drop_the_pin(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            for flag in ("--trust-ke", "--truts-key", "--out-dir"):
                with self.subTest(flag=flag):
                    self.assert_refused("evidence-pack", str(_SESSION), flag, _KEY, "--out", d)
            self.assertEqual(
                list(Path(d).iterdir()), [], "an evidence pack was written despite a bad flag"
            )

    def test_verify_commitment(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            b = Path(d) / "b.json"
            b.write_text("{}")
            base = [
                "verify-commitment",
                str(b),
                "--agent-id",
                "a",
                "--challenge-id",
                "c",
                "--deadline",
                "2026-01-01T00:00:00Z",
                "--tsa-anchor",
                str(b),
            ]
            for extra in (["--trust-ke", _KEY], ["--bogus"], ["--dead", "x"], ["--receipt", "r"]):
                with self.subTest(extra=extra):
                    code, out, err = run(*base, *extra)
                    self.assertEqual(code, 3, (extra, err[-300:]))
                    self.assertIn("error:", err)

    def test_seal_refuses_before_any_network_call(self) -> None:
        for extra in (["--serv", "http://127.0.0.1:9"], ["--bogus"]):
            with self.subTest(extra=extra):
                self.assert_refused("seal", str(_SESSION), *extra)

    def test_observe_and_bridge(self) -> None:
        # a parser that accepted these would start a long-running process (the timeout would fire)
        self.assert_refused("observe", "--w", "ws://127.0.0.1:9")
        self.assert_refused("observe", "--bogus")
        self.assert_refused("bridge", "--sock", "/tmp/sasana-test.sock")
        self.assert_refused("bridge", "--bogus")


class TestFullFlagsStillWork(unittest.TestCase):
    """The strictness must not break correct usage."""

    def test_verify_with_the_full_flag_names(self) -> None:
        code, out, err = run(
            "verify", str(_SESSION), "--trust-key", _KEY, "--require-seal", "--json"
        )
        self.assertNotEqual(code, 3, err)  # parsed; the verdict itself is COMPROMISED (wrong pin)
        self.assertEqual(code, 1)
        self.assertIn('"pinned": true', out)

    def test_verify_unpinned_runs(self) -> None:
        code, _, err = run("verify", str(_SESSION), "--json")
        self.assertEqual(code, 0, err)

    def test_evidence_pack_with_the_full_flag_names(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            code, _, err = run("evidence-pack", str(_SESSION), "--trust-key", _KEY, "--out", d)
            self.assertNotEqual(code, 3, err)
            self.assertTrue(any(Path(d).iterdir()))

    def test_help_and_version_unchanged(self) -> None:
        self.assertEqual(run("--help")[0], 0)
        code, out, _ = run("version")
        self.assertEqual(code, 0)
        self.assertIn("2.0", out)

    def test_every_subcommand_parser_is_strict(self) -> None:
        """Structural guard: no lenient parse call or bare ArgumentParser may creep back in."""
        src = Path(_CLI).read_text()
        self.assertFalse(".parse_known_args(" in src, "parse_known_args() call reintroduced")
        after_class = src.split("class _StrictParser")[1]
        self.assertFalse(
            "argparse.ArgumentParser(" in after_class, "bare ArgumentParser reintroduced"
        )


if __name__ == "__main__":
    unittest.main()
