"""
tests/test_commitment_v3.py — the trusted-identity inputs of verify_commitment, the receipt rules added after
HA-4 (no payload_hash; an explicit revision-number relation; the SYNTHETIC label), the payload mapping
`ha-daily-v3`, and the bundle-level cases (wrong revision index, duplicate and reordered revisions, a corrupted seal).

Every statement about Headline Arena (HA) here is sourced: "HA-4" is Kopei's email of 2026-10-25 and "OpenAPI" is
the document retrieved once on 2026-10-27 (docs/sources/ha-openapi-2.2.9-2026-10-27.json holds its SHA-256 and the
excerpt the tests pin the mapping to). Nothing here calls an HA endpoint. Receipts are a PROPOSED EXTENSION that HA
does not issue; every receipt in these tests is SYNTHETIC. Synthetic data only; the TSA and the receipt signer are
local throwaway keys; no network.
"""

from __future__ import annotations

import contextlib
import copy
import datetime as dt
import inspect
import io
import itertools
import json
import math
import shutil
import subprocess
import sys
import tempfile
import unicodedata
import unittest
from pathlib import Path
from unittest.mock import patch

_ROOT = Path(__file__).parent.parent
for _p in (str(_ROOT), str(_ROOT / "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from test_commitment import CTX, DEADLINE, SUBJ, T0, FakeTsa  # noqa: E402
from test_commitment_v2 import SEC, T1, V2Base  # noqa: E402

from sasana import commitment as cm  # noqa: E402
from sasana import commitment_mapping as cmap  # noqa: E402

try:
    from fastapi.testclient import TestClient  # noqa: E402

    from archeion.server import app  # noqa: E402

    _FASTAPI = True
except ImportError:
    _FASTAPI = False

V3 = cmap.HA_DAILY_V3
EXCERPT = json.loads(
    (_ROOT / "docs/sources/ha-openapi-2.2.9-2026-10-27.json").read_text(encoding="utf-8")
)
VECTORS = json.loads(
    (_ROOT / "tests/fixtures/mapping/ha-daily-v3.json").read_text(encoding="utf-8")
)

S0 = {
    "direction": "bullish",
    "confidence": 0.72,
    "probabilities": {"bullish": 0.72, "bearish": 0.2, "neutral": 0.08},
    "reasoning": "Synthetic reasoning that is comfortably longer than twenty characters.",
    "summary": "bullish",
    "is_revision": False,
}
S1 = {
    **S0,
    "direction": "bearish",
    "confidence": 0.64,
    "probabilities": {"bullish": 0.2, "bearish": 0.64, "neutral": 0.16},
    "summary": "bearish",
    "is_revision": True,
    "revision_reason": "synthetic news",
}
S2 = {
    **S1,
    "direction": "neutral",
    "confidence": 0.5,
    "probabilities": {"bullish": 0.25, "bearish": 0.25, "neutral": 0.5},
}
# HA-4: "a small synthetic unstaked directional example ... probabilities bearish=0.60, neutral=0.30, bullish=0.10,
# omit amount, and use a 64-character uppercase hexadecimal prompt_hash".
KOPEI = {
    "probabilities": {"bearish": 0.60, "neutral": 0.30, "bullish": 0.10},
    "prompt_hash": "A1B2C3D4E5F60718293A4B5C6D7E8F90A1B2C3D4E5F60718293A4B5C6D7E8F90",
    "reasoning": "Synthetic example reasoning for an unstaked full-vector submission.",
    "is_revision": False,
}
FULL = VECTORS["equivalent"][0]["canonical"]  # all seventeen declared fields


class V3Base(V2Base):
    def commit3(self, prefix, submission, when, *, prev=None, subject=SUBJ, context=CTX):
        with patch("sasana.rfc3161.request_timestamp", FakeTsa(self.auth, now=when)):
            return cm.commit(
                subject_id=subject,
                context_id=context,
                payload=cmap.map_ha_daily_v3(submission).payload,
                session_events=self.full[:prefix],
                trusted_tsa_anchors=[self.auth.anchor_der],
                prev=prev,
                mapping_id=V3,
            )

    def chain3(self):
        p0 = self.commit3(3, S0, T0)
        return p0, self.commit3(4, S1, T1, prev=p0[0])

    def receipt3(self, pair, **over):
        over.setdefault("ha_revision_number", pair[0].revision_index + 1)
        over.setdefault("notice", cm.SYNTHETIC_NOTICE)
        return self.receipt(pair, **over)

    def vr3(self, bundle, receipts, closing="auto", **kw):
        if closing == "auto":
            closing = None if receipts is None else self.closing(receipts, mapping_id=V3)
        kw.setdefault("expected_mapping_id", V3)
        return self.vr(bundle, receipts, closing=closing, **kw)

    def cli(self, bundle, *extra):
        import sasana_cli
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization

        with tempfile.TemporaryDirectory() as d:
            bp, ap = Path(d) / "b.json", Path(d) / "anchor.pem"
            bp.write_text(json.dumps(bundle))
            cert = x509.load_der_x509_certificate(self.anchors[0])
            ap.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
            args = [
                str(bp),
                "--deadline",
                "2026-06-01T12:00:00Z",
                "--tsa-anchor",
                str(ap),
                "--json",
            ]
            out = io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
                code = sasana_cli._cmd_verify_commitment(args + list(extra))
            return code, out.getvalue()


# --------------------------------------------------------------------------- #
# 1. Trusted identity                                                          #
# --------------------------------------------------------------------------- #


class TestTrustedIdentity(V3Base):
    """HA-4: "The expected agent and challenge must come from the verifier's trusted HA-side record, not from the
    bundle being checked. Please keep the wrong-agent and wrong-challenge cases separate."
    """

    def test_an_honest_bundle_for_another_agent_is_refused_with_its_own_reason(self) -> None:
        other = self.commit3(3, S0, T0, subject="agent-other")
        b = self.bundle2([other])
        # control: the very same bundle is fine for a verifier that expects THAT agent
        ok = self.verify(b, expected_agent_id="agent-other", expected_mapping_id=V3)
        self.assertEqual(ok.verdict, "VALID_ON_TIME", (ok.errors, ok.warnings))
        v = self.verify(b, expected_mapping_id=V3)
        self.assertEqual(v.verdict, "INVALID")
        self.assertEqual(len(v.errors), 1, v.errors)
        self.assertTrue(v.errors[0].startswith("AGENT_ID_MISMATCH:"), v.errors)
        self.assertNotIn("CHALLENGE_ID_MISMATCH", " ".join(v.errors))

    def test_an_honest_bundle_for_another_challenge_is_refused_with_its_own_reason(self) -> None:
        other = self.commit3(3, S0, T0, context="challenge-other")
        b = self.bundle2([other])
        ok = self.verify(b, expected_challenge_id="challenge-other", expected_mapping_id=V3)
        self.assertEqual(ok.verdict, "VALID_ON_TIME", (ok.errors, ok.warnings))
        v = self.verify(b, expected_mapping_id=V3)
        self.assertEqual(v.verdict, "INVALID")
        self.assertEqual(len(v.errors), 1, v.errors)
        self.assertTrue(v.errors[0].startswith("CHALLENGE_ID_MISMATCH:"), v.errors)
        self.assertNotIn("AGENT_ID_MISMATCH", " ".join(v.errors))

    def test_both_wrong_gives_both_reasons_each_once(self) -> None:
        other = self.commit3(3, S0, T0, subject="agent-other", context="challenge-other")
        v = self.verify(self.bundle2([other]), expected_mapping_id=V3)
        self.assertEqual(v.verdict, "INVALID")
        codes = sorted(e.split(":")[0] for e in v.errors)
        self.assertEqual(codes, ["AGENT_ID_MISMATCH", "CHALLENGE_ID_MISMATCH"])

    def test_the_expected_identity_is_required_there_is_no_default(self) -> None:
        params = inspect.signature(cm.verify_commitment).parameters
        for name in ("expected_agent_id", "expected_challenge_id"):
            self.assertIn(name, params)
            self.assertIs(params[name].kind, inspect.Parameter.KEYWORD_ONLY)
            self.assertIs(params[name].default, inspect.Parameter.empty, name)
        with self.assertRaises(TypeError):
            cm.verify_commitment({}, deadline=DEADLINE, trusted_tsa_anchors=self.anchors)  # type: ignore[call-arg]

    def test_an_unusable_expected_value_is_refused_not_skipped(self) -> None:
        p = self.commit3(3, S0, T0)
        b = self.bundle2([p])
        for bad in ("", None, 7, b"agent-7", "\ud800"):
            for kw in ("expected_agent_id", "expected_challenge_id"):
                with self.subTest(value=repr(bad), arg=kw):
                    v = self.verify(b, **{kw: bad})
                    self.assertEqual(v.verdict, "INVALID")
                    self.assertIn(f"{kw} must be a non-empty string", v.errors[0])

    def test_ids_are_compared_as_exact_strings(self) -> None:
        composed, decomposed = "agent-é", unicodedata.normalize("NFD", "agent-é")
        self.assertNotEqual(composed, decomposed)
        other = self.commit3(3, S0, T0, subject=composed)
        b = self.bundle2([other])
        for expected in (decomposed, composed + " ", composed.upper(), composed[:-1]):
            with self.subTest(expected=repr(expected)):
                v = self.verify(b, expected_agent_id=expected, expected_mapping_id=V3)
                self.assertEqual(v.verdict, "INVALID")
                self.assertTrue(v.errors[0].startswith("AGENT_ID_MISMATCH"), v.errors)

    def test_rewriting_the_bundles_ids_to_match_breaks_C_because_the_ids_are_inside_it(
        self,
    ) -> None:
        other = self.commit3(3, S0, T0, subject="agent-other", context="challenge-other")
        b = self.bundle2([other])
        b["subject_id"], b["context_id"] = SUBJ, CTX  # an attacker relabels an honest bundle
        v = self.verify(b, expected_mapping_id=V3)
        self.assertEqual(v.verdict, "INVALID")
        self.assertNotIn("MISMATCH", " ".join(v.errors))  # the identity check passed...
        self.assertIn("commitment does not match", " ".join(v.checks["revisions"][0]["errors"]))

    def test_receipts_for_the_expected_identity_do_not_rescue_a_wrong_bundle(self) -> None:
        p0, _ = self.chain3()
        other = self.commit3(3, S0, T0, subject="agent-other")
        v = self.vr3(self.bundle2([other]), [self.receipt3(p0)])  # in-scope, validly signed
        self.assertEqual(v.verdict, "INVALID")
        self.assertTrue(v.errors[0].startswith("AGENT_ID_MISMATCH"), v.errors)

    def test_the_policy_record_names_the_expected_ids(self) -> None:
        p0 = self.commit3(3, S0, T0)
        v = self.verify(self.bundle2([p0]), expected_mapping_id=V3)
        self.assertEqual(v.checks["policy"]["expected_agent_id"], SUBJ)
        self.assertEqual(v.checks["policy"]["expected_challenge_id"], CTX)

    def test_the_cli_requires_both_and_reports_each_mismatch(self) -> None:
        p0 = self.commit3(3, S0, T0)
        b = self.bundle2([p0])
        self.assertEqual(self.cli(b)[0], 3)  # neither flag
        self.assertEqual(self.cli(b, "--agent-id", SUBJ)[0], 3)
        self.assertEqual(self.cli(b, "--challenge-id", CTX)[0], 3)
        code, out = self.cli(b, "--agent-id", SUBJ, "--challenge-id", CTX)
        self.assertEqual((code, json.loads(out)["verdict"]), (0, "VALID_ON_TIME"))
        code, out = self.cli(b, "--agent-id", "agent-x", "--challenge-id", CTX)
        self.assertEqual(code, 1)
        self.assertTrue(json.loads(out)["errors"][0].startswith("AGENT_ID_MISMATCH"))
        code, out = self.cli(b, "--agent-id", SUBJ, "--challenge-id", "challenge-x")
        self.assertEqual(code, 1)
        self.assertTrue(json.loads(out)["errors"][0].startswith("CHALLENGE_ID_MISMATCH"))


# --------------------------------------------------------------------------- #
# 2. Receipts                                                                  #
# --------------------------------------------------------------------------- #


class TestReceiptRules(V3Base):
    def test_payload_hash_is_no_longer_a_receipt_field(self) -> None:
        self.assertNotIn("payload_hash", cm._RECEIPT_REQUIRED + cm._RECEIPT_OPTIONAL)
        self.assertNotIn("payload_hash", cm._CLOSING_REQUIRED + cm._CLOSING_OPTIONAL)
        self.assertIn("T6", cm.PAYLOAD_HASH_REFUSED)

    def test_a_synthetic_receipt_makes_every_verdict_say_so(self) -> None:
        p0, p1 = self.chain3()
        b = self.bundle2([p0, p1])
        rs = [self.receipt3(p0), self.receipt3(p1, at=T1 + SEC)]
        v = self.vr3(b, rs)
        self.assertEqual(v.verdict, "VALID_ON_TIME", (v.errors, v.warnings))
        warn = [w for w in v.warnings if w.startswith("SYNTHETIC_RECEIPTS_USED")]
        self.assertEqual(len(warn), 1, v.warnings)
        self.assertIn("SYNTHETIC — not HA-issued", warn[0])
        self.assertEqual(v.checks["receipts"]["synthetic"], [cm.SYNTHETIC_NOTICE])

    def test_the_label_on_the_closing_receipt_alone_is_enough(self) -> None:
        p0, p1 = self.chain3()
        b = self.bundle2([p0, p1])
        rs = [self.receipt3(p0, notice="free text"), self.receipt3(p1, at=T1 + SEC, notice="x")]
        closing = self.closing(rs, mapping_id=V3, notice=cm.SYNTHETIC_NOTICE)
        v = self.vr3(b, rs, closing=closing)
        self.assertTrue(any(w.startswith("SYNTHETIC_RECEIPTS_USED") for w in v.warnings))

    def test_a_receipt_without_the_label_does_not_trigger_the_warning(self) -> None:
        p0, p1 = self.chain3()
        rs = [
            self.receipt(p0, ha_revision_number=1),
            self.receipt(p1, at=T1 + SEC, ha_revision_number=2),
        ]
        v = self.vr3(self.bundle2([p0, p1]), rs)
        self.assertFalse([w for w in v.warnings if "SYNTHETIC" in w], v.warnings)

    def test_revision_number_and_revision_index_are_related_explicitly(self) -> None:
        n = cmap.HA_REVISION_NUMBERING
        self.assertEqual(
            (n.counterparty_field, n.counterparty_first, n.commitment_first),
            ("revision_number", 1, 0),
        )
        for i in range(0, 50):
            self.assertEqual(n.counterparty_number(i), i + 1)
            self.assertEqual(n.commitment_index(n.counterparty_number(i)), i)
        self.assertEqual(cmap.get_mapping(V3).revision_numbering, n)
        # v1 and v2 never stated it
        self.assertIsNone(cmap.get_mapping(cmap.HA_DAILY_V2).revision_numbering)

    def test_a_wrong_revision_number_is_an_error_the_off_by_one_is_not_assumed_away(self) -> None:
        p0, p1 = self.chain3()
        b = self.bundle2([p0, p1])
        for wrong in (1, 3, 7):  # 1 is revision_index itself, the exact confusion HA-4 warns about
            with self.subTest(ha_revision_number=wrong):
                rs = [self.receipt3(p0), self.receipt3(p1, at=T1 + SEC, ha_revision_number=wrong)]
                v = self.vr3(b, rs)
                self.assertEqual(v.verdict, "INVALID")
                self.assertTrue(
                    any("RECEIPT_REVISION_NUMBER_MISMATCH:1" in e for e in v.errors), v.errors
                )

    def test_a_missing_revision_number_is_flagged_under_a_mapping_that_states_the_relation(
        self,
    ) -> None:
        p0, p1 = self.chain3()
        rs = [self.receipt(p0), self.receipt(p1, at=T1 + SEC)]
        v = self.vr3(self.bundle2([p0, p1]), rs)
        self.assertEqual(v.verdict, "VALID_ON_TIME")
        self.assertIn("RECEIPT_REVISION_NUMBER_ABSENT:0", v.warnings)
        self.assertIn("RECEIPT_REVISION_NUMBER_ABSENT:1", v.warnings)

    def test_a_revision_number_under_a_mapping_that_states_no_relation_is_an_error(self) -> None:
        p0 = self.commit2(3, {"direction": "up", "confidence": 0.7}, T0)  # ha-daily-v2
        v = self.vr(self.bundle2([p0]), [self.receipt(p0, ha_revision_number=1)])
        self.assertEqual(v.verdict, "INVALID")
        self.assertTrue(any("RECEIPT_REVISION_NUMBER_UNDEFINED" in e for e in v.errors), v.errors)
        ok = self.vr(self.bundle2([p0]), [self.receipt(p0)])  # no number: nothing to flag
        self.assertFalse([w for w in ok.warnings if "REVISION_NUMBER" in w])

    def test_a_receipt_revision_number_must_be_an_integer_of_at_least_one(self) -> None:
        p0 = self.commit3(3, S0, T0)
        for bad in (0, -1, True, "1", 1.0, None, 2**32):
            with self.subTest(value=repr(bad)), self.assertRaises(ValueError):
                self.receipt(p0, ha_revision_number=bad)


# --------------------------------------------------------------------------- #
# 3. ha-daily-v3                                                               #
# --------------------------------------------------------------------------- #


class TestHaDailyV3PinnedToTheSchema(unittest.TestCase):
    """The mapping is pinned to the schema excerpt: OpenAPI 2.2.9, retrieved 2026-10-27, SHA-256 in the record."""

    def test_the_citation_record_is_complete(self) -> None:
        self.assertEqual(EXCERPT["info_version"], "2.2.9")
        self.assertEqual(EXCERPT["retrieved_at_utc"][:10], "2026-10-27")
        self.assertRegex(EXCERPT["sha256"], r"^[0-9a-f]{64}$")
        self.assertEqual(EXCERPT["http_status"], 200)
        self.assertEqual(
            EXCERPT["legacy_predict_route"]["path"],
            "/api/v1/eval/challenges/{challenge_id}/predict",
        )

    def test_the_declared_fields_are_the_routes_seventeen_properties_in_schema_order(self) -> None:
        route = EXCERPT["legacy_predict_route"]
        self.assertEqual(list(cmap.DECLARED_FIELDS_V3), route["request_body_property_order"])
        self.assertEqual(len(cmap.DECLARED_FIELDS_V3), 17)
        self.assertEqual(cmap.EXCLUDED_FIELDS_V3, {})
        self.assertEqual(cmap.BOUND_FIELDS_V3, cmap.DECLARED_FIELDS_V3)
        # the eleven v2 bound are a prefix-free subset; the six HA-4 names are all new in v3
        new = set(cmap.DECLARED_FIELDS_V3) - set(cmap.DECLARED_FIELDS_V2)
        self.assertEqual(
            new,
            {
                "forecast_context",
                "expected_revision",
                "idempotency_key",
                "model_provider",
                "model_name",
                "model_version",
            },
        )  # HA-4: "the request now also declares ..."

    def test_the_rules_follow_the_published_types(self) -> None:
        props = EXCERPT["legacy_predict_route"]["request_body_schema"]["properties"]
        self.assertEqual(
            props["amount"]["anyOf"][0]["exclusiveMinimum"], 0.0
        )  # strictly greater than zero
        self.assertIn({"type": "null"}, props["amount"]["anyOf"])
        self.assertEqual(
            props["prompt_hash"]["anyOf"][0]["pattern"], "^[0-9a-fA-F]{64}$"
        )  # either case
        self.assertIs(
            props["token_usage"]["anyOf"][0]["additionalProperties"], True
        )  # arbitrary object
        self.assertEqual(props["expected_revision"]["anyOf"][0]["minimum"], 1.0)
        self.assertIn("exactly bearish/neutral/bullish", props["probabilities"]["description"])
        self.assertEqual(props["is_revision"]["type"], "boolean")
        for name in cmap.DECLARED_FIELDS_V3:
            if name != "is_revision":  # every other property is declared nullable
                self.assertIn({"type": "null"}, props[name]["anyOf"], name)
        self.assertEqual(
            EXCERPT["legacy_predict_route"]["response_201_revision_number"]["default"], 1
        )  # revision_number starts at 1
        self.assertEqual(
            EXCERPT["own_prediction_get_200_schema"], {}
        )  # (untyped: HA-4 is the source)
        self.assertEqual(
            EXCERPT["paths_containing_the_word_lock"], []
        )  # HA-4: no public lock endpoint

    def test_it_is_not_a_mapping_for_the_canonical_route(self) -> None:
        canonical = set(EXCERPT["canonical_predict_request_properties"])
        self.assertNotIn("prompt_hash", canonical)  # HA-4: not declared canonical request fields
        self.assertNotIn("token_usage", canonical)
        self.assertIn(
            "prediction", canonical
        )  # a nested prediction object: not a field of this mapping
        with self.assertRaises(cmap.MappingError):
            cmap.map_ha_daily_v3({"prediction": {"direction": "bullish"}})
        with self.assertRaises(cmap.MappingError):
            cmap.map_ha_daily_v3({"challenge_id": "c", "prediction": {}})


class TestHaDailyV3Mapping(unittest.TestCase):
    def test_every_declared_field_is_bound_and_nothing_is_added(self) -> None:
        p = cmap.map_ha_daily_v3(FULL).payload
        self.assertEqual(tuple(p), cmap.DECLARED_FIELDS_V3)
        self.assertEqual(p, FULL)

    def test_omitted_null_and_present_stay_three_things(self) -> None:
        cases = {
            "amount": 10, "token_usage": {"a": 1}, "forecast_context": {"b": 2}, "direction": "bearish",
            "probabilities": FULL["probabilities"], "expected_revision": 2, "confidence": 0.5,
            "prompt_hash": "a" * 64, "idempotency_key": "synthetic-key-1", "summary": "s",
        }  # fmt: skip
        for f, val in cases.items():
            with self.subTest(field=f):
                omitted, null, present = {}, {f: None}, {f: val}
                self.assertEqual(cmap.map_ha_daily_v3(omitted).payload, {})
                self.assertEqual(cmap.map_ha_daily_v3(null).payload, {f: None})
                self.assertEqual(cmap.map_ha_daily_v3(present).payload, {f: val})
                hashes = {
                    cm.payload_hash(
                        cmap.map_ha_daily_v3(s).payload, number_profile=cmap.NUMBERS_IEEE754_RFC8785
                    )
                    for s in (omitted, null, present)
                }
                self.assertEqual(len(hashes), 3)

    def test_a_schema_default_is_never_applied(self) -> None:
        self.assertNotIn("is_revision", cmap.map_ha_daily_v3({"direction": "bullish"}).payload)
        with self.assertRaises(cmap.MappingError):
            cmap.map_ha_daily_v3({"is_revision": None})  # the one non-nullable field

    def test_unknown_fields_are_refused(self) -> None:
        for extra in ({"x": 1}, {"session_root": "ab" * 32}, {"challenge_id": "c"}, {1: 2}):
            with self.subTest(extra=extra), self.assertRaises(cmap.MappingError):
                cmap.map_ha_daily_v3(extra)
        with self.assertRaises(cmap.MappingError):
            cmap.map_ha_daily_v3([])  # type: ignore[arg-type]

    # --- probabilities ------------------------------------------------------------------------------------

    def test_probabilities_is_an_object_with_exactly_the_three_labels(self) -> None:
        ok = {"bearish": 0.6, "neutral": 0.3, "bullish": 0.1}
        self.assertEqual(cmap.map_ha_daily_v3({"probabilities": ok}).payload["probabilities"], ok)
        bad_label_sets = [
            {"bearish": 0.6, "bullish": 0.4},
            {"bearish": 0.5, "neutral": 0.3, "bullish": 0.1, "flat": 0.1},
            {"up": 0.6, "down": 0.4},
            {"Bearish": 0.6, "Neutral": 0.3, "Bullish": 0.1},
            {"bearish ": 0.6, "neutral": 0.3, "bullish": 0.1},
            {},
            {1: 0.6, "neutral": 0.3, "bullish": 0.1},
        ]
        for bad in bad_label_sets:
            with self.subTest(labels=sorted(map(repr, bad))), self.assertRaises(cmap.MappingError):
                cmap.map_ha_daily_v3({"probabilities": bad})
        for bad in ([0.6, 0.3, 0.1], 0.6, "x", True):
            with self.subTest(shape=repr(bad)), self.assertRaises(cmap.MappingError):
                cmap.map_ha_daily_v3({"probabilities": bad})
        for bad_value in ("0.6", True, None, [0.6], {"a": 1}, float("nan"), float("inf")):
            with self.subTest(value=repr(bad_value)), self.assertRaises(cmap.MappingError):
                cmap.map_ha_daily_v3({"probabilities": {**ok, "bearish": bad_value}})

    def test_the_sum_and_the_sign_only_warn_the_commitment_does_not_validate_forecasts(
        self,
    ) -> None:
        def w(probs):
            return cmap.payload_warnings_v3(cmap.map_ha_daily_v3({"probabilities": probs}).payload)

        self.assertEqual(
            w({"bearish": 0.6, "neutral": 0.3, "bullish": 0.1}), []
        )  # exactly 1 in decimal
        self.assertEqual(
            w({"bearish": 0.5, "neutral": 0.3, "bullish": 0.1}), ["PROBABILITY_SUM:0.9"]
        )
        self.assertEqual(
            w({"bearish": 0.4, "neutral": 0.4, "bullish": 0.4}), ["PROBABILITY_SUM:1.2"]
        )
        within = {"bearish": 0.6, "neutral": 0.3, "bullish": 0.1 + 5e-7}  # |sum - 1| = 5e-7 <= 1e-6
        self.assertEqual(w(within), [])
        beyond = {"bearish": 0.6, "neutral": 0.3, "bullish": 0.1 + 2e-6}
        self.assertTrue(w(beyond)[0].startswith("PROBABILITY_SUM"))
        self.assertEqual(
            w({"bearish": -0.1, "neutral": 0.6, "bullish": 0.5}), ["PROBABILITY_NEGATIVE"]
        )
        self.assertEqual(w({"bearish": 2, "neutral": -1, "bullish": 0}), ["PROBABILITY_NEGATIVE"])
        # ...and the mapping itself accepted every one of them
        cmap.map_ha_daily_v3({"probabilities": {"bearish": 9, "neutral": -3, "bullish": 7}})

    def test_direction_and_confidence_beside_probabilities_must_match_the_argmax_and_maximum(
        self,
    ) -> None:
        probs = {"bearish": 0.6, "neutral": 0.3, "bullish": 0.1}

        def w(**kw):
            return cmap.payload_warnings_v3(
                cmap.map_ha_daily_v3({"probabilities": probs, **kw}).payload
            )

        self.assertEqual(w(direction="bearish", confidence=0.6), [])
        self.assertEqual(w(direction="bullish"), ["DIRECTION_ARGMAX_MISMATCH:bullish"])
        self.assertEqual(w(direction="up"), ["DIRECTION_ARGMAX_MISMATCH:up"])
        self.assertEqual(w(confidence=0.7), ["CONFIDENCE_MAX_MISMATCH:0.7"])
        self.assertEqual(
            w(confidence=0.6 + 5e-7), []
        )  # inside the 1e-6 tolerance (HA's own is not stated)
        self.assertEqual(
            w(direction="neutral", confidence=0.3),
            ["DIRECTION_ARGMAX_MISMATCH:neutral", "CONFIDENCE_MAX_MISMATCH:0.3"],
        )
        self.assertEqual(w(direction=None, confidence=None), [])  # null is "not supplied alongside"
        tie = {"probabilities": {"bearish": 0.5, "neutral": 0.0, "bullish": 0.5}}
        for d in ("bearish", "bullish"):  # either member of a tie is an argmax
            self.assertEqual(
                cmap.payload_warnings_v3(cmap.map_ha_daily_v3({**tie, "direction": d}).payload), []
            )
        self.assertEqual(
            cmap.payload_warnings_v3(cmap.map_ha_daily_v3({**tie, "direction": "neutral"}).payload),
            ["DIRECTION_ARGMAX_MISMATCH:neutral"],
        )
        # with no vector there is nothing to compare
        self.assertEqual(cmap.payload_warnings_v3({"direction": "bullish", "confidence": 0.1}), [])

    def test_model_provider_and_name_must_be_sent_together_is_a_warning(self) -> None:
        both = {"model_provider": "p", "model_name": "n"}
        self.assertEqual(cmap.payload_warnings_v3(both), [])
        self.assertEqual(cmap.payload_warnings_v3({}), [])
        self.assertEqual(
            cmap.payload_warnings_v3({"model_provider": "p"}), ["MODEL_PROVIDER_NAME_NOT_PAIRED"]
        )
        self.assertEqual(
            cmap.payload_warnings_v3({"model_name": "n", "model_provider": None}),
            ["MODEL_PROVIDER_NAME_NOT_PAIRED"],
        )

    # --- amount ---------------------------------------------------------------------------------------------

    def test_amount_is_omitted_null_or_strictly_positive_and_zero_is_rejected(self) -> None:
        self.assertEqual(cmap.map_ha_daily_v3({}).payload, {})
        self.assertEqual(cmap.map_ha_daily_v3({"amount": None}).payload, {"amount": None})
        for ok in (1, 10, 0.5, 5e-324, 1e300, 0.30000000000000004):
            self.assertEqual(cmap.map_ha_daily_v3({"amount": ok}).payload, {"amount": ok})
        for bad in (
            0,
            0.0,
            -0.0,
            -1,
            -1e-300,
            "10",
            True,
            False,
            [10],
            float("nan"),
            float("inf"),
            float("-inf"),
        ):
            with self.subTest(amount=repr(bad)), self.assertRaises(cmap.MappingError):
                cmap.map_ha_daily_v3({"amount": bad})

    # --- prompt_hash ----------------------------------------------------------------------------------------

    def test_prompt_hash_is_64_hex_characters_byte_exact_and_case_preserved(self) -> None:
        for ok in ("a" * 64, "A" * 64, "aA0" * 21 + "f", "0123456789abcdefABCDEF" + "0" * 42):
            self.assertEqual(cmap.map_ha_daily_v3({"prompt_hash": ok}).payload["prompt_hash"], ok)
        upper, lower = "AB" * 32, "ab" * 32
        self.assertNotEqual(
            cm.payload_hash(
                cmap.map_ha_daily_v3({"prompt_hash": upper}).payload,
                number_profile=cmap.NUMBERS_IEEE754_RFC8785,
            ),
            cm.payload_hash(
                cmap.map_ha_daily_v3({"prompt_hash": lower}).payload,
                number_profile=cmap.NUMBERS_IEEE754_RFC8785,
            ),
        )  # no case folding
        for bad in (
            "a" * 63,
            "a" * 65,
            "g" * 64,
            " " + "a" * 63,
            "a" * 64 + "\n",
            5,
            b"a" * 64,
            ["a" * 64],
        ):
            with self.subTest(value=repr(bad)), self.assertRaises(cmap.MappingError):
                cmap.map_ha_daily_v3({"prompt_hash": bad})

    # --- token_usage and forecast_context ---------------------------------------------------------------------

    def test_token_usage_is_an_arbitrary_object_or_null_with_no_count_only_restriction(
        self,
    ) -> None:
        free = {
            "input": 120, "output": 45.5, "cached": -3, "model": "synthetic", "ok": True, "none": None,
            "nested": {"a": [1, 2.5, {"b": "c"}], "empty": {}, "list": []}, "unicode": "café",
        }  # fmt: skip
        self.assertEqual(cmap.map_ha_daily_v3({"token_usage": free}).payload["token_usage"], free)
        self.assertEqual(cmap.map_ha_daily_v3({"token_usage": {}}).payload["token_usage"], {})
        for bad in ([1], 5, "x", True):
            with self.subTest(value=repr(bad)), self.assertRaises(cmap.MappingError):
                cmap.map_ha_daily_v3({"token_usage": bad})
        for bad in (
            {"a": float("nan")},
            {"a": 2**53 + 1},
            {"a": {1: 2}},
            {"a": "\ud800"},
            {"a": object()},
        ):
            with self.subTest(value=repr(bad)), self.assertRaises(cmap.MappingError):
                cmap.map_ha_daily_v3({"token_usage": bad})
        deep: dict = {}
        node = deep
        for _ in range(100):
            node["x"] = {}
            node = node["x"]
        with self.assertRaises(cmap.MappingError):  # a recursion guard, documented; not an HA rule
            cmap.map_ha_daily_v3({"token_usage": deep})

    def test_forecast_context_is_bound_whole_as_an_object_or_null(self) -> None:
        ctx = {
            "schema_version": "1",
            "decision": "update",
            "evidence_refs": [{"kind": "external", "id": "x"}],
        }
        self.assertEqual(
            cmap.map_ha_daily_v3({"forecast_context": ctx}).payload["forecast_context"], ctx
        )
        # HA's inner schema (additionalProperties false) is HA's to enforce; the commitment binds what was sent
        odd = {"unknown_key": [1, 2.5, None]}
        self.assertEqual(
            cmap.map_ha_daily_v3({"forecast_context": odd}).payload["forecast_context"], odd
        )
        with self.assertRaises(cmap.MappingError):
            cmap.map_ha_daily_v3({"forecast_context": "text"})

    def test_text_fields_are_byte_exact(self) -> None:
        for f in ("direction", "reasoning", "summary", "trigger_event_id", "revision_reason",
                  "idempotency_key", "model_provider", "model_name", "model_version"):  # fmt: skip
            nfc, nfd = "café ", unicodedata.normalize("NFD", "café ")
            self.assertEqual(cmap.map_ha_daily_v3({f: nfc}).payload[f], nfc)
            self.assertNotEqual(cmap.map_ha_daily_v3({f: nfd}).payload[f], nfc)
            self.assertEqual(cmap.map_ha_daily_v3({f: ""}).payload[f], "")
            for bad in (5, True, ["x"], b"x", "\ud800"):
                with self.subTest(field=f, value=repr(bad)), self.assertRaises(cmap.MappingError):
                    cmap.map_ha_daily_v3({f: bad})

    def test_expected_revision_is_an_integer_of_at_least_one_in_the_counterpartys_numbering(
        self,
    ) -> None:
        for ok, canon in ((1, 1), (2, 2), (2.0, 2), (10**6, 10**6)):
            self.assertEqual(
                cmap.map_ha_daily_v3({"expected_revision": ok}).payload["expected_revision"], canon
            )
        for bad in (0, -1, 1.5, "2", True, [1], float("nan"), 2**53 + 1):
            with self.subTest(value=repr(bad)), self.assertRaises(cmap.MappingError):
                cmap.map_ha_daily_v3({"expected_revision": bad})


class TestHaDailyV3Numbers(unittest.TestCase):
    """RFC 8785 number serialization: lossless at the IEEE-754 double level, no fractional cap, no rounding."""

    def h(self, sub):
        return cm.payload_hash(
            cmap.map_ha_daily_v3(sub).payload, number_profile=cmap.NUMBERS_IEEE754_RFC8785
        ).hex()

    def test_v2s_twelve_digit_fractional_cap_is_gone(self) -> None:
        precise = 0.1234567890123456  # 16 fractional digits: v2 REJECTS this, v3 binds it as is
        with self.assertRaises(cmap.MappingError):
            cmap.map_ha_daily_v2({"confidence": precise})
        self.assertEqual(
            cmap.map_ha_daily_v3({"confidence": precise}).payload["confidence"], precise
        )
        self.assertEqual(
            cmap.map_ha_daily_v3({"confidence": 0.1 + 0.2}).payload["confidence"],
            0.30000000000000004,
        )

    def test_nothing_is_rounded_adjacent_doubles_are_different_numbers(self) -> None:
        a, b = 0.1, math.nextafter(0.1, 1)
        self.assertNotEqual(self.h({"confidence": a}), self.h({"confidence": b}))
        self.assertNotEqual(self.h({"amount": 1}), self.h({"amount": math.nextafter(1.0, 2)}))
        self.assertNotEqual(self.h({"confidence": 1e-7}), self.h({"confidence": 1e-8}))

    def test_equality_is_at_the_double_level_spelling_does_not_matter(self) -> None:
        spellings = ["0.6", "0.60", "6e-1", "6E-1", "60e-2", "0.6000000000000000055511151231257827"]
        hashes = {self.h({"confidence": json.loads(s)}) for s in spellings}
        self.assertEqual(len(hashes), 1)
        self.assertEqual(self.h({"amount": 10}), self.h({"amount": 10.0}))
        self.assertEqual(self.h({"token_usage": {"n": 0}}), self.h({"token_usage": {"n": -0.0}}))
        # two decimals that round to ONE double ARE the same number here (documented, not hidden)
        self.assertEqual(self.h({"confidence": json.loads("0.1000000000000000055511151231257827")}),
                         self.h({"confidence": 0.1}))  # fmt: skip

    def test_the_committed_bytes_are_the_rfc_8785_serialization(self) -> None:
        from sasana.jcs import canonicalize

        cases = {1e21: b"1e+21", 1e-7: b"1e-7", 123456789012345680000.0: b"123456789012345680000", 0.000001: b"0.000001",
                 5e-324: b"5e-324", 1.7976931348623157e308: b"1.7976931348623157e+308", -0.0: b"0", 100.0: b"100",
                 0.30000000000000004: b"0.30000000000000004", 4.35: b"4.35", 9.5e-7: b"9.5e-7"}  # fmt: skip
        for value, text in cases.items():
            self.assertEqual(canonicalize({"v": value}), b'{"v":' + text + b"}", repr(value))
            payload = cmap.map_ha_daily_v3({"token_usage": {"v": value}}).payload
            self.assertIn(b'"v":' + text, canonicalize(payload), repr(value))

    def test_non_finite_numbers_and_unrepresentable_integers_are_refused(self) -> None:
        for bad in (
            float("nan"),
            float("inf"),
            float("-inf"),
            json.loads("1e999"),
            2**53 + 1,
            -(2**53) - 1,
            10**30,
        ):
            with self.subTest(value=repr(bad)), self.assertRaises(cmap.MappingError):
                cmap.map_ha_daily_v3({"confidence": bad})
        self.assertEqual(cmap.map_ha_daily_v3({"confidence": 2**53}).payload["confidence"], 2**53)

    def test_booleans_and_numeric_strings_are_not_numbers(self) -> None:
        for bad in (True, False, "0.6", "6e-1", b"1", [1], {"a": 1}):
            with self.subTest(value=repr(bad)), self.assertRaises(cmap.MappingError):
                cmap.map_ha_daily_v3({"confidence": bad})

    def test_the_payload_profile_follows_the_mapping(self) -> None:
        payload = {"confidence": 0.6}
        cm.validate_payload_profile(payload, cmap.NUMBERS_IEEE754_RFC8785)
        with self.assertRaises(ValueError):
            cm.validate_payload_profile(payload)  # the default profile still refuses floats
        with self.assertRaises(ValueError):
            cm.validate_payload_profile({"c": float("nan")}, cmap.NUMBERS_IEEE754_RFC8785)
        with self.assertRaises(ValueError):
            cm.validate_payload_profile({"c": 2**53 + 1}, cmap.NUMBERS_IEEE754_RFC8785)
        with self.assertRaises(ValueError):
            cm.validate_payload_profile(payload, "nope")
        self.assertEqual(cmap.number_profile_for(V3), cmap.NUMBERS_IEEE754_RFC8785)
        self.assertEqual(cmap.number_profile_for(cmap.HA_DAILY_V2), cmap.NUMBERS_DECIMAL_STRING)
        self.assertEqual(cmap.number_profile_for("unknown"), cmap.NUMBERS_DECIMAL_STRING)
        self.assertEqual(cmap.number_profile_for(None), cmap.NUMBERS_DECIMAL_STRING)

    def test_a_float_payload_cannot_be_committed_under_v2_or_v1(self) -> None:
        for mapping_id in (cmap.HA_DAILY_V2, None):
            with self.subTest(mapping=mapping_id), self.assertRaises(ValueError):
                cm.compute_commitment_v2(
                    mapping_id=mapping_id or cmap.HA_DAILY_V2, subject_id="s", context_id="c", revision_index=0,
                    prev_commitment=None, payload={"confidence": 0.6}, session_root="ab" * 32, salt=bytes(32),
                )  # fmt: skip

    def test_the_mapping_id_is_inside_C_so_the_same_payload_under_v2_and_v3_differs(self) -> None:
        kw = dict(subject_id="s", context_id="c", revision_index=0, prev_commitment=None,
                  payload={"direction": "bearish"}, session_root="ab" * 32, salt=bytes(32))  # fmt: skip
        self.assertNotEqual(
            cm.compute_commitment_v2(mapping_id=cmap.HA_DAILY_V2, **kw),
            cm.compute_commitment_v2(mapping_id=V3, **kw),
        )


class TestHaDailyV3SharedVectors(unittest.TestCase):
    def h(self, payload):
        return cm.payload_hash(payload, number_profile=cmap.NUMBERS_IEEE754_RFC8785).hex()

    def c(self, payload):
        return cm.compute_commitment_v2(
            mapping_id=V3, subject_id="agent-1", context_id="challenge-1", revision_index=0,
            prev_commitment=None, payload=payload, session_root="ab" * 32, salt=bytes(range(32)),
        )  # fmt: skip

    def test_the_file_is_for_this_mapping_and_labelled_synthetic(self) -> None:
        self.assertEqual(VECTORS["mapping"], V3)
        self.assertEqual(tuple(VECTORS["declared_fields"]), cmap.DECLARED_FIELDS_V3)
        self.assertEqual(VECTORS["synthetic_notice"][:9], "SYNTHETIC")
        self.assertIn("HA-issued", VECTORS["synthetic_notice"])

    def test_equivalent_inputs_hash_the_same(self) -> None:
        for g in VECTORS["equivalent"]:
            inputs = [json.loads(t) for t in g["json_texts"]] if "json_texts" in g else g["inputs"]
            hashes = {self.h(cmap.map_ha_daily_v3(i).payload) for i in inputs}
            self.assertEqual(hashes, {g["payload_hash"]}, g["name"])
            self.assertEqual(cmap.map_ha_daily_v3(inputs[0]).payload, g["canonical"], g["name"])
            cmap.check_canonical_ha_daily_v3(g["canonical"])

    def test_different_inputs_hash_differently_and_give_different_C(self) -> None:
        for g in VECTORS["distinct"]:
            pa, pb = cmap.map_ha_daily_v3(g["a"]).payload, cmap.map_ha_daily_v3(g["b"]).payload
            self.assertNotEqual(self.h(pa), self.h(pb), g["name"])
            self.assertNotEqual(self.c(pa), self.c(pb), g["name"])

    def test_every_field_has_a_change_that_breaks_the_commitment(self) -> None:
        names = " ".join(g["name"] for g in VECTORS["distinct"])
        for f in cmap.DECLARED_FIELDS_V3:
            self.assertIn(f"{f.upper()} change breaks the commitment", names)
        self.assertIn("amount omitted vs null", names)
        self.assertIn("lower case vs upper case", names)

    def test_rejected_inputs(self) -> None:
        for g in VECTORS["rejected"]:
            with self.assertRaises(cmap.MappingError, msg=g["name"]) as ctx:
                cmap.map_ha_daily_v3(g["input"])
            self.assertIn(g["error_contains"], str(ctx.exception), g["name"])

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_an_independent_implementation_reproduces_every_payload_hash(self) -> None:
        """Node's JSON.stringify is ES Number::toString, the number rule RFC 8785 mandates, so it is an
        implementation of the serializer that does not share a line of code with sasana/jcs.py."""
        script = r"""
        const fs = require('fs'), crypto = require('crypto');
        function jcs(v) {
          if (v === null) return 'null';
          if (typeof v === 'number') { if (!Number.isFinite(v)) throw new Error('non-finite'); return JSON.stringify(v); }
          if (typeof v === 'string' || typeof v === 'boolean') return JSON.stringify(v);
          if (Array.isArray(v)) return '[' + v.map(jcs).join(',') + ']';
          return '{' + Object.keys(v).sort().map(k => JSON.stringify(k) + ':' + jcs(v[k])).join(',') + '}';
        }
        const sha = o => crypto.createHash('sha256').update(Buffer.from(jcs(o), 'utf8')).digest('hex');
        const vec = JSON.parse(fs.readFileSync(process.argv[1], 'utf8'));
        const bad = [];
        for (const g of vec.equivalent) {
          const inputs = g.json_texts ? g.json_texts.map(t => JSON.parse(t)) : g.inputs;
          for (const i of inputs) if (sha(i) !== g.payload_hash) bad.push(g.name);
          if (sha(g.canonical) !== g.payload_hash) bad.push(g.name + ' (canonical)');
        }
        console.log(JSON.stringify(bad));
        """
        r = subprocess.run(
            ["node", "-e", script, str(_ROOT / "tests/fixtures/mapping/ha-daily-v3.json")],
            capture_output=True, text=True, timeout=60,
        )  # fmt: skip
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(json.loads(r.stdout), [])


class TestHaDailyV3Registry(unittest.TestCase):
    def test_v3_is_current_v2_is_superseded_by_it_and_still_registered(self) -> None:
        self.assertIsNone(cmap.get_mapping(V3).superseded_by)
        self.assertEqual(cmap.get_mapping(cmap.HA_DAILY_V2).superseded_by, V3)
        self.assertIsNotNone(cmap.get_mapping(cmap.HA_DAILY_V2))
        self.assertEqual(cmap.get_mapping(V3).number_profile, cmap.NUMBERS_IEEE754_RFC8785)

    def test_check_canonical_accepts_what_the_mapping_accepts_and_names_an_unbound_field(
        self,
    ) -> None:
        cmap.check_canonical_ha_daily_v3({"amount": 1})
        cmap.check_canonical_ha_daily_v3({"amount": 1.0})
        cmap.check_canonical_ha_daily_v3({"expected_revision": 2.0})
        for bad in (
            {"amount": 0},
            {"unknown": 1},
            {"probabilities": [1]},
            {"expected_revision": 2.5},
            [],
            None,
            5,
        ):
            with self.subTest(payload=bad), self.assertRaises(cmap.MappingError):
                cmap.check_canonical_ha_daily_v3(bad)  # type: ignore[arg-type]
        with self.assertRaises(cmap.MappingError) as ctx:  # the field-set check names the problem
            cmap.check_canonical_ha_daily_v3({"unknown": 1})
        self.assertIn("does not bind", str(ctx.exception))


# --------------------------------------------------------------------------- #
# 4. ha-daily-v3 end to end                                                    #
# --------------------------------------------------------------------------- #


class TestV3EndToEnd(V3Base):
    def test_a_two_revision_chain_verifies_with_no_superseded_warning(self) -> None:
        p0, p1 = self.chain3()
        rs = [self.receipt3(p0), self.receipt3(p1, at=T1 + SEC)]
        v = self.vr3(self.bundle2([p0, p1]), rs)
        self.assertEqual(
            (v.verdict, v.effective_revision), ("VALID_ON_TIME", 1), (v.errors, v.warnings)
        )
        self.assertFalse([w for w in v.warnings if "SUPERSEDED" in w], v.warnings)
        self.assertFalse([w for w in v.warnings if "REVISION_NUMBER" in w], v.warnings)

    def test_numbers_survive_a_json_round_trip_with_no_rounding(self) -> None:
        sub = {
            **S0, "confidence": 0.1234567890123456, "amount": 0.30000000000000004, "expected_revision": 1,
            "token_usage": {"p": 1e-7, "q": 123456789.123456789, "r": [0.1, 2.5e300]},
            "probabilities": {"bullish": 0.1234567890123456, "bearish": 0.5, "neutral": 0.3765432109876544},
            "direction": "bearish",
        }  # fmt: skip
        p0 = self.commit3(3, sub, T0)
        b = json.loads(json.dumps(self.bundle2([p0])))
        self.assertEqual(b["revisions"][0]["payload"]["confidence"], 0.1234567890123456)
        v = self.verify(b, expected_mapping_id=V3)
        self.assertEqual(v.verdict, "VALID_ON_TIME", (v.errors, v.warnings))

    def test_a_number_respelled_in_the_bundle_text_still_verifies_double_level_equality(
        self,
    ) -> None:
        p0 = self.commit3(3, S0, T0)
        text = json.dumps(self.bundle2([p0]))
        self.assertIn("0.72", text)
        respelled = text.replace("0.72,", "7.2e-1,").replace("0.72}", "720e-3}")
        self.assertNotEqual(respelled, text)
        v = self.verify(json.loads(respelled), expected_mapping_id=V3)
        self.assertEqual(v.verdict, "VALID_ON_TIME", (v.errors, v.warnings))

    def test_one_ulp_changes_C(self) -> None:
        p0 = self.commit3(3, S0, T0)
        b = self.bundle2([p0])
        b["revisions"][0]["payload"]["confidence"] = math.nextafter(0.72, 1)
        v = self.verify(b, expected_mapping_id=V3)
        self.assertEqual(v.verdict, "INVALID")
        self.assertIn("commitment does not match", " ".join(v.checks["revisions"][0]["errors"]))

    def test_every_field_tampered_after_commit_is_caught(self) -> None:
        full = copy.deepcopy(FULL)
        p0 = self.commit3(3, full, T0)
        for g in VECTORS["distinct"][: len(cmap.DECLARED_FIELDS_V3)]:
            b = self.bundle2([p0])
            b["revisions"][0]["payload"] = cmap.map_ha_daily_v3(g["b"]).payload
            v = self.verify(b, expected_mapping_id=V3)
            self.assertEqual(v.verdict, "INVALID", g["name"])

    def test_the_unstaked_full_vector_example(self) -> None:
        """HA-4's example: probabilities 0.60 / 0.30 / 0.10, amount omitted, an uppercase 64-hex prompt_hash."""
        p0 = self.commit3(3, KOPEI, T0)
        sec = p0[1].payload
        self.assertNotIn("amount", sec)  # omitted, not null and not 0
        self.assertEqual(sec["probabilities"], {"bearish": 0.6, "neutral": 0.3, "bullish": 0.1})
        self.assertEqual(sec["prompt_hash"], KOPEI["prompt_hash"])
        self.assertNotEqual(sec["prompt_hash"], sec["prompt_hash"].lower())
        b = json.loads(json.dumps(self.bundle2([p0])))
        self.assertEqual(
            b["revisions"][0]["payload"]["prompt_hash"], KOPEI["prompt_hash"]
        )  # byte-exact
        v = self.vr3(b, [self.receipt3(p0)])
        self.assertEqual(
            (v.verdict, v.effective_revision), ("VALID_ON_TIME", 0), (v.errors, v.warnings)
        )
        self.assertEqual(v.effective_payload["prompt_hash"], KOPEI["prompt_hash"])
        self.assertFalse(
            [w for w in v.warnings if w.startswith(("PROBABILITY", "DIRECTION", "CONFIDENCE"))]
        )
        # a lower-cased prompt_hash is a different commitment
        low = copy.deepcopy(b)
        low["revisions"][0]["payload"]["prompt_hash"] = KOPEI["prompt_hash"].lower()
        self.assertEqual(self.vr3(low, [self.receipt3(p0)]).verdict, "INVALID")
        # and "amount": 0 cannot be committed at all
        with self.assertRaises(cmap.MappingError):
            cmap.map_ha_daily_v3({**KOPEI, "amount": 0})

    def test_a_forecast_with_a_bad_sum_is_committed_and_verified_with_a_warning_not_refused(
        self,
    ) -> None:
        sub = {
            **S0,
            "probabilities": {"bullish": 0.5, "bearish": 0.2, "neutral": 0.2},
            "direction": "bullish",
            "confidence": 0.5,
        }
        p0 = self.commit3(3, sub, T0)
        v = self.vr3(self.bundle2([p0]), [self.receipt3(p0)])
        self.assertEqual(v.verdict, "VALID_ON_TIME")
        self.assertIn("PROBABILITY_SUM:0.9", v.warnings)

    def test_a_v2_bundle_is_not_the_required_v3_mapping(self) -> None:
        p0 = self.commit2(3, {"direction": "up", "confidence": 0.7}, T0)
        v = self.verify(self.bundle2([p0]), expected_mapping_id=V3)
        self.assertEqual(v.verdict, "INVALID")
        self.assertIn("is not the required 'ha-daily-v3'", v.errors[0])

    def test_relabelling_a_v2_bundle_as_v3_breaks_C(self) -> None:
        p0 = self.commit2(3, {"direction": "up", "confidence": 0.7}, T0)
        b = self.bundle2([p0])
        b["mapping_id"] = V3
        self.assertEqual(self.verify(b, expected_mapping_id=V3).verdict, "INVALID")


# --------------------------------------------------------------------------- #
# 5. Bundle-level cases                                                        #
# --------------------------------------------------------------------------- #


class TestBundleLevelCases(V3Base):
    def three(self):
        p0, p1 = self.chain3()
        p2 = self.commit3(5, S2, T1 + dt.timedelta(minutes=10), prev=p1[0])
        rs = [
            self.receipt3(p0),
            self.receipt3(p1, at=T1 + SEC),
            self.receipt3(p2, at=T1 + dt.timedelta(minutes=10, seconds=2)),
        ]
        return (p0, p1, p2), rs

    def test_a_wrong_revision_index_is_refused_because_the_index_is_inside_C(self) -> None:
        (p0, p1, _), rs = self.three()
        for wrong in (0, 2, 5, 2**31):
            with self.subTest(revision_index=wrong):
                b = self.bundle2([p0, p1])
                b["revisions"][1]["revision_index"] = wrong
                v = self.vr3(b, rs[:2])
                self.assertEqual(v.verdict, "INVALID", (wrong, v.errors, v.warnings))
        # the SAME edit on the only revision: nothing valid is left
        b = self.bundle2([p0])
        b["revisions"][0]["revision_index"] = 3
        v = self.vr3(b, rs[:1])
        self.assertEqual(v.verdict, "INVALID")
        rev = v.checks["revisions"][
            0
        ]  # (index 3 with no predecessor fails the prev_commitment rule first)
        self.assertIs(rev["valid"], False)
        self.assertTrue(rev["errors"], rev)

    def test_a_non_integer_or_negative_revision_index_never_crashes_the_verifier(self) -> None:
        p0, p1 = self.chain3()
        for bad in (-1, 1.5, "1", None, True, [1]):
            with self.subTest(revision_index=repr(bad)):
                b = self.bundle2([p0, p1])
                b["revisions"][1]["revision_index"] = bad
                self.assertEqual(
                    self.vr3(b, [self.receipt3(p0), self.receipt3(p1, at=T1 + SEC)]).verdict,
                    "INVALID",
                )

    def test_the_same_revision_listed_twice_is_invalid(self) -> None:
        p0, p1 = self.chain3()
        b = self.bundle2([p0, p1])
        b["revisions"].append(copy.deepcopy(b["revisions"][1]))
        v = self.vr3(b, [self.receipt3(p0), self.receipt3(p1, at=T1 + SEC)])
        self.assertEqual(v.verdict, "INVALID")
        self.assertEqual(v.errors, ["duplicate revision_index in bundle"])

    def test_two_different_commitments_under_one_index_are_invalid_too(self) -> None:
        p0, p1 = self.chain3()
        twin = self.commit3(4, {**S1, "direction": "neutral"}, T1, prev=p0[0])
        b = self.bundle2([p0, p1])
        b["revisions"].append(self.bundle2([p0, twin])["revisions"][1])
        v = self.vr3(b, [self.receipt3(p0), self.receipt3(p1, at=T1 + SEC)])
        self.assertEqual(v.verdict, "INVALID")
        self.assertEqual(v.errors, ["duplicate revision_index in bundle"])

    def test_the_order_of_the_revisions_array_is_ignored_every_permutation_gives_the_same_verdict(
        self,
    ) -> None:
        (p0, p1, p2), rs = self.three()
        b = self.bundle2([p0, p1, p2])
        base = self.vr3(copy.deepcopy(b), rs)
        self.assertEqual(
            (base.verdict, base.effective_revision),
            ("VALID_ON_TIME", 2),
            (base.errors, base.warnings),
        )
        for perm in itertools.permutations(range(3)):
            with self.subTest(order=perm):
                shuffled = copy.deepcopy(b)
                shuffled["revisions"] = [copy.deepcopy(b["revisions"][i]) for i in perm]
                v = self.vr3(shuffled, rs)
                self.assertEqual(
                    v.as_dict(), base.as_dict()
                )  # the whole verdict, warnings and checks included

    def test_reordering_the_receipts_list_changes_nothing_either(self) -> None:
        (p0, p1, p2), rs = self.three()
        b = self.bundle2([p0, p1, p2])
        closing = self.closing(rs, mapping_id=V3)
        base = self.vr3(copy.deepcopy(b), rs, closing=closing)
        for perm in itertools.permutations(range(3)):
            v = self.vr3(copy.deepcopy(b), [rs[i] for i in perm], closing=closing)
            self.assertEqual(
                (v.verdict, v.effective_revision), (base.verdict, base.effective_revision), perm
            )

    def test_swapping_the_payloads_of_two_revisions_is_not_a_reorder_it_breaks_C(self) -> None:
        p0, p1 = self.chain3()
        b = self.bundle2([p0, p1])
        a, c = b["revisions"][0]["payload"], b["revisions"][1]["payload"]
        b["revisions"][0]["payload"], b["revisions"][1]["payload"] = c, a
        self.assertEqual(
            self.vr3(b, [self.receipt3(p0), self.receipt3(p1, at=T1 + SEC)]).verdict, "INVALID"
        )


@unittest.skipUnless(_FASTAPI, "fastapi / httpx not installed")
class TestCorruptedSeal(V3Base):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls.client = TestClient(app)
        cls.pub = cls.client.get("/pubkey").json()["pubkey"]

    def sealed(self, events):
        body = ("\n".join(json.dumps(e) for e in events) + "\n").encode()
        resp = self.client.post("/seal", content=body)
        self.assertEqual(resp.status_code, 200, resp.text)
        return [json.loads(ln) for ln in resp.text.splitlines() if ln.strip()]

    def flip(self, sig: str) -> str:
        return ("0" if sig[0] != "0" else "1") + sig[1:]

    def test_a_corrupted_seal_signature_is_caught_with_the_key_pinned(self) -> None:
        p0 = self.commit3(3, S0, T0)
        good = self.bundle2([p0], session=self.sealed(self.full))
        ok = self.vr3(good, [self.receipt3(p0)], trusted_seal_pubkey=self.pub)
        self.assertEqual(
            (ok.verdict, ok.evidence_class), ("VALID_ON_TIME", "AUTHORITATIVE_EVIDENCE")
        )
        bad_events = copy.deepcopy(good["session_events"])
        self.assertEqual(bad_events[-1]["event_type"], "CHAIN_SEAL")
        bad_events[-1]["signature"] = self.flip(bad_events[-1]["signature"])
        bad = {**good, "session_events": bad_events}
        v = self.vr3(bad, [self.receipt3(p0)], trusted_seal_pubkey=self.pub)
        self.assertEqual(v.verdict, "INVALID")
        self.assertIn("session trace failed verification", v.errors)
        self.assertTrue(any("CHAIN_SEAL signature invalid" in e for e in v.errors), v.errors)
        self.assertEqual(v.checks["trace"]["status"], "COMPROMISED")

    def test_the_signature_is_outside_the_event_hash_so_only_the_seal_check_can_catch_it(
        self,
    ) -> None:
        from sasana.verifier import compute_event_hash

        p0 = self.commit3(3, S0, T0)
        events = copy.deepcopy(self.sealed(self.full))
        before = events[-1]["event_hash"]
        events[-1]["signature"] = self.flip(events[-1]["signature"])
        self.assertEqual(compute_event_hash(events[-1], "jcs-rfc8785"), before)  # chain intact
        v = self.vr3(
            {**self.bundle2([p0], session=events)},
            [self.receipt3(p0)],
            trusted_seal_pubkey=self.pub,
        )
        self.assertEqual(v.verdict, "INVALID")

    def test_a_corrupted_seal_is_caught_even_with_no_key_pinned(self) -> None:
        # (an embedded-key seal that does not verify is a broken seal, pinned or not)
        p0 = self.commit3(3, S0, T0)
        events = copy.deepcopy(self.sealed(self.full))
        events[-1]["signature"] = self.flip(events[-1]["signature"])
        v = self.vr3(self.bundle2([p0], session=events), [self.receipt3(p0)])
        self.assertEqual(v.verdict, "INVALID")
        self.assertEqual(v.checks["trace"]["status"], "COMPROMISED")

    def test_a_seal_with_the_signature_removed_is_refused_under_a_pin(self) -> None:
        p0 = self.commit3(3, S0, T0)
        events = copy.deepcopy(self.sealed(self.full))
        events[-1].pop("signature")
        v = self.vr3(
            self.bundle2([p0], session=events), [self.receipt3(p0)], trusted_seal_pubkey=self.pub
        )
        self.assertEqual(v.verdict, "INVALID")


if __name__ == "__main__":
    unittest.main()
