"""
sasana.commitment_mapping — versioned mappings from a submission to the payload a commitment binds.

A commitment hash proves "these bytes were fixed before the deadline". It says nothing about whether
those bytes MEAN what the counterparty accepted. A mapping is the explicit, versioned function from
the submission a counterparty accepts to the canonical payload that goes inside C, so that a hash
match cannot hide a change in meaning. The mapping id is bound INSIDE C (commitment v2), so the same
payload hashed under a different mapping is a different commitment.

Mapping `ha-daily-v3` (current) covers the LEGACY daily directional route only (POST
/api/v1/eval/challenges/{challenge_id}/predict), not the canonical /api/v1/agent/ha/predict contract and not
numeric price-event predictions (HA-4). It is DEFAULT-DENY over all seventeen properties of the route's
published request schema (OpenAPI 2.2.9, see docs/pre-outcome-commitment.md Appendix A), keeps an omitted field,
a null field and a present field distinct, and carries numbers as JSON numbers with RFC 8785 serialization
(no rounding and no fractional cap; equality is at the IEEE-754 double level). `ha-daily-v2` is SUPERSEDED by it.

Mapping `ha-daily-v2` covers the daily-market directional family only and is DEFAULT-DENY: it
binds every field the counterparty's daily schema declares, and a field may be left out only by an entry in
EXCLUDED_FIELDS_V2 that carries a written reason (currently there are none). It binds eleven fields, not the
seventeen the route now declares, and caps fractional precision at twelve places (HA-4), hence v3. `ha-daily-v1` is SUPERSEDED: it
bound seven of the eleven fields (so a change to `amount` or `trigger_event_id` was not detected) and accepted
two shapes for `probabilities`. It stays registered so archived v1 bundles verify, with a warning.
The text below describes the shared number rules; the v1 specifics follow in its own section.

Mapping `ha-daily-v1` covers the daily-market directional family only. The field names come from the
public interface the counterparty described to us (see docs/pre-outcome-commitment.md, Appendix A);
the TYPES of those fields are not stated there, so the mapping accepts the plausible types and rejects
everything else rather than guessing. See the note for what it deliberately does not bind.

Numbers. Reals never enter the payload as JSON numbers. They become decimal STRINGS:
  * plain notation, no exponent, no '+', no leading zeros ('0.5' not '.5' or '00.5');
  * no trailing zeros and no trailing '.' ('0.6' for 0.6, 0.60, '0.600' and 6e-1);
  * zero, including negative zero, is '0'; a whole number carries no '.0' ('100' for 100 and 100.0);
  * at most 18 integer digits and 12 fractional digits. More precision is REJECTED, never rounded:
    rounding would silently change what was committed (0.1 + 0.2 is rejected; round it yourself);
  * NaN, +/-Infinity, bool and anything that is not a number or a plain decimal string are rejected.
The whole-number case is the one that bit this project on 2026-10-10: `100.0` and `100` canonicalised
differently across implementations (CHANGELOG 2.0.0, "Canonicalization"). A float enters through its
shortest round-trip repr, so 0.6 is '0.6' on every IEEE-754 platform.
"""

from __future__ import annotations

import dataclasses
import decimal
import math
import re
from decimal import Decimal
from typing import Any, Callable, Mapping, Optional, Sequence

from sasana.jcs import canonicalize

HA_DAILY_V1 = "ha-daily-v1"  # SUPERSEDED by ha-daily-v2
HA_DAILY_V2 = "ha-daily-v2"  # SUPERSEDED by ha-daily-v3
HA_DAILY_V3 = "ha-daily-v3"

# How a mapping spells numbers inside the committed payload (the payload profile of sasana.commitment).
NUMBERS_DECIMAL_STRING = (
    "decimal-string"  # v1, v2: reals are decimal STRINGS, at most 12 fractional digits
)
NUMBERS_IEEE754_RFC8785 = (
    "ieee754-rfc8785"  # v3: JSON numbers, RFC 8785 serialization, no cap, no rounding
)

# Fields of a daily-market submission that the mapping binds into C.
BOUND_FIELDS = (
    "direction",
    "confidence",
    "probabilities",
    "reasoning",
    "summary",
    "is_revision",
    "revision_reason",
)
# Fields the counterparty's daily schema also declares that this mapping DELIBERATELY does not bind.
UNBOUND_FIELDS = ("prompt_hash", "amount", "token_usage", "trigger_event_id")

MAX_INT_DIGITS = 18
MAX_FRACTION_DIGITS = 12
_MAX_TEXT = 64
_MAX_PROBABILITIES = 1000
PROBABILITY_SUM_TOLERANCE = Decimal("0.000001")

_NUM_RE = re.compile(r"-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]{1,4})?\Z")
_CTX = decimal.Context(prec=80)  # inputs are capped at 64 characters, so normalize() is exact

_MAPPING_ID_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}\Z")


class MappingError(ValueError):
    """The submission cannot be mapped (wrong type, unrepresentable number, unknown field...)."""


def validate_mapping_id(mapping_id: Any) -> str:
    if not isinstance(mapping_id, str) or not _MAPPING_ID_RE.match(mapping_id):
        raise ValueError("mapping_id must match [a-z0-9][a-z0-9._-]{0,63}")
    return mapping_id


# --------------------------------------------------------------------------- #
# Numbers                                                                      #
# --------------------------------------------------------------------------- #


def canonical_decimal(value: Any, *, field: str = "value") -> str:
    """Return the ha-daily-v1 decimal string for a number (see the module docstring)."""
    if isinstance(value, bool):
        raise MappingError(f"{field}: a boolean is not a number")
    if isinstance(value, int):
        text = str(value)
    elif isinstance(value, float):
        if not math.isfinite(value):
            raise MappingError(f"{field}: NaN and Infinity are not representable")
        text = repr(value)
    elif isinstance(value, Decimal):
        if not value.is_finite():
            raise MappingError(f"{field}: NaN and Infinity are not representable")
        text = str(value)
    elif isinstance(value, str):
        text = value
    else:
        raise MappingError(
            f"{field}: expected a number or decimal string, got {type(value).__name__}"
        )
    if len(text) > _MAX_TEXT:
        raise MappingError(f"{field}: number is longer than {_MAX_TEXT} characters")
    if not _NUM_RE.match(text):
        raise MappingError(f"{field}: {text!r} is not a plain decimal number")
    d = Decimal(text)
    if d.is_zero():
        return "0"  # also folds negative zero
    d = d.normalize(_CTX)
    if max(0, -d.as_tuple().exponent) > MAX_FRACTION_DIGITS:
        raise MappingError(
            f"{field}: more than {MAX_FRACTION_DIGITS} fractional digits (round it; the mapping never rounds)"
        )
    if d.adjusted() + 1 > MAX_INT_DIGITS:
        raise MappingError(f"{field}: more than {MAX_INT_DIGITS} integer digits")
    return format(d, "f")


# --------------------------------------------------------------------------- #
# ha-daily-v1                                                                  #
# --------------------------------------------------------------------------- #


@dataclasses.dataclass(frozen=True)
class MappedPayload:
    payload: dict
    unbound_present: tuple  # declared-but-unbound fields that the submission carried


def _text(field: str, value: Any, *, nullable: bool) -> Any:
    if value is None and nullable:
        return None
    if not isinstance(value, str):
        raise MappingError(f"{field}: expected a string{' or null' if nullable else ''}")
    try:
        value.encode("utf-8")  # rejects lone surrogates
    except UnicodeEncodeError as exc:
        raise MappingError(f"{field}: not valid UTF-8 ({exc})") from exc
    return value  # byte-exact: no trimming, no Unicode normalisation


def _probabilities(value: Any) -> Any:
    if isinstance(value, Mapping):
        items = list(value.items())
        if not items or len(items) > _MAX_PROBABILITIES:
            raise MappingError("probabilities: must hold between 1 and 1000 entries")
        out = {}
        for k, v in items:
            out[_text("probabilities key", k, nullable=False)] = canonical_decimal(
                v, field=f"probabilities[{k!r}]"
            )
        return out
    if isinstance(value, (list, tuple)):
        if not value or len(value) > _MAX_PROBABILITIES:
            raise MappingError("probabilities: must hold between 1 and 1000 entries")
        return [canonical_decimal(v, field=f"probabilities[{i}]") for i, v in enumerate(value)]
    raise MappingError("probabilities: expected an object or an array of numbers")


def map_ha_daily_v1(submission: Mapping[str, Any]) -> MappedPayload:
    """
    Map a daily-market submission to the canonical payload committed under `ha-daily-v1`.

    Absence is meaningful: a field that is not supplied is OMITTED from the payload, a field supplied
    as null is `null`, and a field supplied as "" is "". These three hash differently. The mapping does
    not decide which fields the counterparty requires; it never invents a default.
    Fields not in BOUND_FIELDS or UNBOUND_FIELDS are rejected (their meaning is unknown to the mapping).
    """
    if not isinstance(submission, Mapping):
        raise MappingError("submission must be an object")
    unknown = sorted(set(submission) - set(BOUND_FIELDS) - set(UNBOUND_FIELDS))
    if unknown:
        raise MappingError(f"unknown field(s) not covered by {HA_DAILY_V1}: {unknown}")
    out: dict = {}
    for name in BOUND_FIELDS:
        if name not in submission:
            continue
        v = submission[name]
        if name in ("direction", "reasoning"):
            out[name] = _text(name, v, nullable=False)
        elif name in ("summary", "revision_reason"):
            out[name] = _text(name, v, nullable=True)
        elif name == "confidence":
            out[name] = canonical_decimal(v, field=name)
        elif name == "probabilities":
            out[name] = _probabilities(v)
        elif name == "is_revision":
            if not isinstance(v, bool):
                raise MappingError("is_revision: expected a boolean")
            out[name] = v
    return MappedPayload(out, tuple(n for n in UNBOUND_FIELDS if n in submission))


def check_canonical_ha_daily_v1(payload: Mapping[str, Any]) -> None:
    """Raise MappingError unless `payload` is exactly what map_ha_daily_v1 would emit for itself."""
    if not isinstance(payload, Mapping):
        raise MappingError("payload must be an object")
    extra = sorted(set(payload) - set(BOUND_FIELDS))
    if extra:
        raise MappingError(f"payload carries field(s) {HA_DAILY_V1} does not bind: {extra}")
    mapped = map_ha_daily_v1(payload).payload
    for name in payload:
        if mapped.get(name) != payload[name] or type(mapped.get(name)) is not type(payload[name]):
            raise MappingError(f"payload is not in canonical {HA_DAILY_V1} form at {name!r}")


def probability_warnings(
    payload: Mapping[str, Any], tolerance: Decimal = PROBABILITY_SUM_TOLERANCE
) -> list:
    """
    Sum policy for `probabilities`: a WARNING, never a rejection. The mapping must be total over whatever
    the counterparty accepted, otherwise a forecast it scored could not be committed. Warns when an entry
    is negative or when |sum - 1| > tolerance (default 1e-6, i.e. 0.0001%).
    """
    probs = payload.get("probabilities")
    if probs is None:
        return []
    values = [Decimal(v) for v in (probs.values() if isinstance(probs, Mapping) else probs)]
    warnings = []
    if any(v < 0 for v in values):
        warnings.append("PROBABILITY_NEGATIVE")
    total = sum(values, Decimal(0))
    if abs(total - 1) > tolerance:
        warnings.append(f"PROBABILITY_SUM:{format(total.normalize(_CTX), 'f')}")
    return warnings


# Fields the counterparty's post-resolution results API returns per prediction (public interface):
# direction, confidence, reasoning, summary. Probabilities, is_revision and revision_reason are not
# returned there, so the revealed values of those three cannot be cross-checked against it.
PUBLISHED_COMPARABLE = ("direction", "confidence", "reasoning", "summary")


def cross_check_published(payload: Mapping[str, Any], published: Mapping[str, Any]) -> dict:
    """
    Compare a revealed payload with a prediction as the counterparty publishes it after resolution.
    Returns {"compared": [...], "mismatches": [...], "not_published": [...]}. Pure; no network.
    """
    compared, mismatches = [], []
    for name in PUBLISHED_COMPARABLE:
        if name not in published:
            continue
        compared.append(name)
        try:
            pub = canonical_decimal(published[name]) if name == "confidence" else published[name]
        except MappingError:
            pub = object()
        if name not in payload or payload[name] != pub:
            mismatches.append(name)
    not_published = [n for n in BOUND_FIELDS_V2 if n not in PUBLISHED_COMPARABLE]
    return {"compared": compared, "mismatches": mismatches, "not_published": not_published}


# --------------------------------------------------------------------------- #
# ha-daily-v2: default-deny                                                    #
# --------------------------------------------------------------------------- #

# Every field the daily-market schema declares, in the order the counterparty listed them (HA-1 §1 in
# docs/pre-outcome-commitment.md, Appendix A.1). The test suite pins this tuple to that list.
DECLARED_FIELDS_V2 = (
    "direction",
    "confidence",
    "probabilities",
    "prompt_hash",
    "amount",
    "reasoning",
    "summary",
    "token_usage",
    "is_revision",
    "trigger_event_id",
    "revision_reason",
)
# A declared field may be excluded from the commitment ONLY with a written reason here. Empty on purpose:
# a field the committer sends is a field the committer knows when it commits (the submission body is fixed
# before C is computed), so "not known at commit time" does not apply to any of them. A field the
# counterparty adds server-side is not in the submission and so is not a field to bind.
EXCLUDED_FIELDS_V2: Mapping[str, str] = {}
BOUND_FIELDS_V2 = tuple(f for f in DECLARED_FIELDS_V2 if f not in EXCLUDED_FIELDS_V2)

_HEX64_RE = re.compile(r"[0-9a-fA-F]{64}\Z")
_MAX_TOKEN_KEYS = 1000
_CORE_FIELDS_V2 = (
    "direction",
    "confidence",
    "probabilities",
    "reasoning",
)  # null is rejected for these


def _probabilities_v2(value: Any) -> dict:
    """
    ONE shape: an object mapping an outcome label to its probability, e.g. {"up": 0.6, "down": 0.4}.

    Why this one: `direction` is a categorical label, so a per-label table is self-describing. An array would
    make the meaning of each entry depend on an index-to-label order the interface does not state, which is a
    change of meaning a hash match could hide. An array is therefore REJECTED, not tolerated. The counterparty's
    exact shape is an open question for them (Appendix A.6); if it differs, that is a new mapping version.
    """
    if not isinstance(value, Mapping):
        raise MappingError(
            "probabilities: expected an object mapping an outcome label to a number "
            "(an array is rejected: its entries would have no stated labels)"
        )
    if not value or len(value) > _MAX_PROBABILITIES:
        raise MappingError("probabilities: must hold between 1 and 1000 entries")
    out = {}
    for k, v in value.items():
        if not isinstance(k, str) or k == "":
            raise MappingError("probabilities: keys must be non-empty strings")
        out[_text("probabilities key", k, nullable=False)] = canonical_decimal(
            v, field=f"probabilities[{k!r}]"
        )
    return out


def _token_usage_v2(value: Any) -> Any:
    """An object of string keys to non-negative integers (an assumed shape; open question for the counterparty)."""
    if value is None:
        return None
    if not isinstance(value, Mapping):
        raise MappingError("token_usage: expected an object of counts (or null)")
    if len(value) > _MAX_TOKEN_KEYS:
        raise MappingError("token_usage: too many entries")
    out = {}
    for k, v in value.items():
        if not isinstance(k, str):
            raise MappingError("token_usage: keys must be strings")
        if isinstance(v, bool) or not isinstance(v, int) or not 0 <= v <= 2**53:
            raise MappingError(f"token_usage[{k!r}]: expected a non-negative integer")
        out[_text("token_usage key", k, nullable=False)] = v
    return out


def _prompt_hash_v2(value: Any) -> Any:
    if value is None:
        return None
    if not isinstance(value, str) or not _HEX64_RE.match(value):
        raise MappingError(
            "prompt_hash: expected a 64-character hexadecimal SHA-256 digest (or null)"
        )
    return value  # bound byte-exact: no case folding


def map_ha_daily_v2(submission: Mapping[str, Any]) -> MappedPayload:
    """
    Map a daily-market submission to the canonical payload committed under `ha-daily-v2` (DEFAULT-DENY).

    Every declared field that is present is bound; a field is absent from the payload only if the submission
    did not carry it (absent, null and "" hash differently). A field outside DECLARED_FIELDS_V2 is rejected,
    because its meaning is unknown. The mapping never invents a default, never rounds, and does not validate
    the forecast (no range, no sum, no label checks: see `probability_warnings`, which only warns).
    """
    if not isinstance(submission, Mapping):
        raise MappingError("submission must be an object")
    unknown = sorted(set(submission) - set(DECLARED_FIELDS_V2))
    if unknown:
        raise MappingError(f"unknown field(s) not covered by {HA_DAILY_V2}: {unknown}")
    out: dict = {}
    for name in DECLARED_FIELDS_V2:
        if name not in submission:
            continue
        v = submission[name]
        if v is None and name in _CORE_FIELDS_V2:
            raise MappingError(f"{name}: null is not accepted")
        if name in EXCLUDED_FIELDS_V2:
            continue
        if name in ("direction", "reasoning"):
            out[name] = _text(name, v, nullable=False)
        elif name in ("summary", "revision_reason", "trigger_event_id"):
            out[name] = _text(name, v, nullable=True)
        elif name == "confidence":
            out[name] = canonical_decimal(v, field=name)
        elif name == "amount":
            out[name] = None if v is None else canonical_decimal(v, field=name)
        elif name == "probabilities":
            out[name] = _probabilities_v2(v)
        elif name == "prompt_hash":
            out[name] = _prompt_hash_v2(v)
        elif name == "token_usage":
            out[name] = _token_usage_v2(v)
        elif name == "is_revision":
            if not isinstance(v, bool):
                raise MappingError("is_revision: expected a boolean")
            out[name] = v
    return MappedPayload(out, tuple(n for n in EXCLUDED_FIELDS_V2 if n in submission))


def check_canonical_ha_daily_v2(payload: Mapping[str, Any]) -> None:
    """Raise MappingError unless `payload` is exactly what map_ha_daily_v2 would emit for itself."""
    if not isinstance(payload, Mapping):
        raise MappingError("payload must be an object")
    extra = sorted(set(payload) - set(BOUND_FIELDS_V2))
    if extra:
        raise MappingError(f"payload carries field(s) {HA_DAILY_V2} does not bind: {extra}")
    mapped = map_ha_daily_v2(payload).payload
    if _typed(mapped) != _typed(dict(payload)):
        for name in payload:
            if _typed(mapped.get(name)) != _typed(payload[name]):
                raise MappingError(f"payload is not in canonical {HA_DAILY_V2} form at {name!r}")
        raise MappingError(f"payload is not in canonical {HA_DAILY_V2} form")


def _typed(v: Any) -> Any:
    """A structure that also distinguishes True from 1 and "0" from 0, for exact equality."""
    if isinstance(v, Mapping):
        return ("d", tuple(sorted((k, _typed(x)) for k, x in v.items())))
    if isinstance(v, (list, tuple)):
        return ("l", tuple(_typed(x) for x in v))
    return (type(v).__name__, v)


# --------------------------------------------------------------------------- #
# ha-daily-v3: the legacy daily directional route, all declared fields, lossless numbers  #
# --------------------------------------------------------------------------- #
#
# SCOPE. This is a mapping for ONE route: the legacy financial REST route
# POST /api/v1/eval/challenges/{challenge_id}/predict. It is NOT a mapping for the canonical
# /api/v1/agent/ha/predict contract (that request is `challenge_id` plus a nested `prediction` matching the
# discovered prediction_schema, and `prompt_hash` and `token_usage` are not declared canonical request fields),
# and not for numeric price-event predictions (HA-4). An endpoint appearing in the OpenAPI document is not
# evidence that its feature gate is enabled (HA-4); nothing here asserts that any route is live.
#
# FIELDS. The seventeen properties of that route's request body (OpenAPI 2.2.9, retrieved 2026-10-27; the
# test suite pins this tuple to the excerpt in docs/sources/). The mapping is DEFAULT-DENY: a field outside
# the tuple is rejected, and every field in it is bound.
DECLARED_FIELDS_V3 = (
    "direction",
    "confidence",
    "probabilities",
    "prompt_hash",
    "amount",
    "reasoning",
    "summary",
    "forecast_context",
    "expected_revision",
    "idempotency_key",
    "model_provider",
    "model_name",
    "model_version",
    "token_usage",
    "is_revision",
    "trigger_event_id",
    "revision_reason",
)
EXCLUDED_FIELDS_V3: Mapping[str, str] = {}  # empty on purpose: see EXCLUDED_FIELDS_V2
BOUND_FIELDS_V3 = tuple(f for f in DECLARED_FIELDS_V3 if f not in EXCLUDED_FIELDS_V3)

_MAX_SAFE_INT = 2**53
PROBABILITY_LABELS_V3 = (
    "bearish",
    "neutral",
    "bullish",
)  # HA-4: "exactly bearish, neutral and bullish"
_MAX_JSON_DEPTH = 64  # nesting limit for the free-form objects (a recursion guard, not an HA rule)
_CONFIDENCE_TOLERANCE = Decimal(
    "0.000001"
)  # for the argmax/maximum cross-check; HA's tolerance is not stated


@dataclasses.dataclass(frozen=True)
class RevisionNumbering:
    """
    The EXPLICIT relation between a counterparty's revision numbers and a commitment's `revision_index`.
    HA's own-prediction readback numbers revisions from 1 (`revision_number`); a commitment's index starts at 0
    (HA-4). A verifier that compares the two must go through this object; it never assumes they are equal.
    """

    counterparty_field: str
    counterparty_first: int
    commitment_first: int

    def counterparty_number(self, revision_index: int) -> int:
        return revision_index - self.commitment_first + self.counterparty_first

    def commitment_index(self, counterparty_number: int) -> int:
        return counterparty_number - self.counterparty_first + self.commitment_first


# revision_number starts at 1; revision_index starts at 0, so revision_number = revision_index + 1 (HA-4).
HA_REVISION_NUMBERING = RevisionNumbering(
    counterparty_field="revision_number", counterparty_first=1, commitment_first=0
)


def _number_v3(value: Any, field: str) -> Any:
    """
    A JSON number under the v3 number rule: an int or a finite float, kept as given. NOT rounded and not
    length-capped. The committed bytes are the RFC 8785 serialization of the IEEE-754 double, so two spellings of
    one double (`0.6`, `0.60`, `6e-1`; `1` and `1.0`) are the same number, and two decimals that round to one
    double are the same number too. An integer beyond +/-2**53 is REJECTED: a double cannot hold it, so
    accepting it would round it, and the mapping never rounds. Booleans and numeric strings are not numbers.
    """
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise MappingError(f"{field}: expected a JSON number, got {type(value).__name__}")
    if isinstance(value, int):
        if abs(value) > _MAX_SAFE_INT:
            raise MappingError(
                f"{field}: integer beyond +/-2**53 is not a unique IEEE-754 double (the mapping never rounds)"
            )
        return value
    if not math.isfinite(value):
        raise MappingError(f"{field}: NaN and Infinity are not JSON numbers")
    return value


def _json_value_v3(value: Any, field: str, depth: int = 0) -> Any:
    """Any JSON value, validated recursively (numbers by the v3 rule, strings as UTF-8). Returns a copy."""
    if depth > _MAX_JSON_DEPTH:
        raise MappingError(f"{field}: nested deeper than {_MAX_JSON_DEPTH} levels")
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, str):
        return _text(field, value, nullable=False)
    if isinstance(value, (int, float)):
        return _number_v3(value, field)
    if isinstance(value, (list, tuple)):
        return [_json_value_v3(v, f"{field}[{i}]", depth + 1) for i, v in enumerate(value)]
    if isinstance(value, Mapping):
        out = {}
        for k, v in value.items():
            if not isinstance(k, str):
                raise MappingError(f"{field}: object keys must be strings")
            out[_text(f"{field} key", k, nullable=False)] = _json_value_v3(
                v, f"{field}.{k}", depth + 1
            )
        return out
    raise MappingError(f"{field}: {type(value).__name__} is not a JSON value")


def _object_or_null_v3(field: str, value: Any) -> Any:
    """`token_usage` and `forecast_context`: an arbitrary JSON object, or null. No value restriction (HA-4)."""
    if value is None:
        return None
    if not isinstance(value, Mapping):
        raise MappingError(f"{field}: expected an object or null")
    return _json_value_v3(value, field)


def _probabilities_v3(value: Any) -> Any:
    """
    null, or an object with EXACTLY the keys bearish, neutral and bullish, each a JSON number. Any other label
    set (fewer, more, renamed, different case), an array, or a non-number value is REJECTED. Whether the values are
    non-negative and sum to 1 is HA's rule, not the commitment's: see `payload_warnings_v3`.
    """
    if value is None:
        return None
    if not isinstance(value, Mapping):
        raise MappingError(
            "probabilities: expected an object with exactly the keys bearish, neutral, bullish (or null)"
        )
    if set(value) != set(PROBABILITY_LABELS_V3):
        got = sorted(repr(k) for k in value)
        raise MappingError(
            f"probabilities: the keys must be exactly {list(PROBABILITY_LABELS_V3)}, got {got}"
        )
    return {k: _number_v3(value[k], f"probabilities[{k!r}]") for k in PROBABILITY_LABELS_V3}


def _amount_v3(value: Any) -> Any:
    """Omitted (the caller never gets here), null, or a number strictly greater than zero. Zero is rejected."""
    if value is None:
        return None
    n = _number_v3(value, "amount")
    if not n > 0:
        raise MappingError(
            "amount: must be strictly greater than zero (zero is not an unstaked submission)"
        )
    return n


def _expected_revision_v3(value: Any) -> Any:
    """null, or an integer >= 1 in HA's numbering (a whole-valued float such as 2.0 is the integer 2)."""
    if value is None:
        return None
    n = _number_v3(value, "expected_revision")
    if isinstance(n, float):
        if not n.is_integer():
            raise MappingError("expected_revision: expected an integer")
        n = int(n)
    if n < 1:
        raise MappingError("expected_revision: must be >= 1 (HA's revision numbers start at 1)")
    return n


def map_ha_daily_v3(submission: Mapping[str, Any]) -> MappedPayload:
    """
    Map a legacy-route daily submission to the canonical payload committed under `ha-daily-v3` (DEFAULT-DENY).

    Omitted, null and present are three different states and stay three different states: a field that is not
    supplied is not in the payload, a field supplied as null is `null`, and a present value is bound as is. The
    mapping never invents a default (not even for `is_revision`, whose schema default is false), never rounds,
    and does not validate the forecast (see `payload_warnings_v3`, which only warns). Every declared field may be
    null except `is_revision`, because the schema declares each of the others nullable (OpenAPI 2.2.9).
    """
    if not isinstance(submission, Mapping):
        raise MappingError("submission must be an object")
    unknown = [k for k in submission if k not in DECLARED_FIELDS_V3]
    if unknown:
        raise MappingError(
            f"unknown field(s) not covered by {HA_DAILY_V3}: {sorted(repr(k) for k in unknown)}"
        )
    out: dict = {}
    for name in DECLARED_FIELDS_V3:
        if name not in submission:
            continue
        v = submission[name]
        if name in EXCLUDED_FIELDS_V3:
            continue
        if name in (
            "direction",
            "reasoning",
            "summary",
            "trigger_event_id",
            "revision_reason",
            "idempotency_key",
            "model_provider",
            "model_name",
            "model_version",
        ):
            out[name] = _text(name, v, nullable=True)
        elif name == "confidence":
            out[name] = None if v is None else _number_v3(v, name)
        elif name == "probabilities":
            out[name] = _probabilities_v3(v)
        elif name == "prompt_hash":
            out[name] = _prompt_hash_v2(v)
        elif name == "amount":
            out[name] = _amount_v3(v)
        elif name in ("forecast_context", "token_usage"):
            out[name] = _object_or_null_v3(name, v)
        elif name == "expected_revision":
            out[name] = _expected_revision_v3(v)
        elif name == "is_revision":
            if not isinstance(v, bool):
                raise MappingError("is_revision: expected a boolean")
            out[name] = v
    return MappedPayload(out, tuple(n for n in EXCLUDED_FIELDS_V3 if n in submission))


def check_canonical_ha_daily_v3(payload: Mapping[str, Any]) -> None:
    """
    Raise MappingError unless `payload` is exactly what map_ha_daily_v3 would emit for itself. Equality is on the
    RFC 8785 bytes, so `1` and `1.0`, or `0.6` and `6e-1`, are the same payload (equality at the double level).
    """
    if not isinstance(payload, Mapping):
        raise MappingError("payload must be an object")
    extra = [k for k in payload if k not in BOUND_FIELDS_V3]
    if extra:
        raise MappingError(
            f"payload carries field(s) {HA_DAILY_V3} does not bind: {sorted(repr(k) for k in extra)}"
        )
    mapped = map_ha_daily_v3(payload).payload
    if canonicalize(mapped) != canonicalize(dict(payload)):
        for name in payload:
            if canonicalize(mapped.get(name)) != canonicalize(payload[name]):
                raise MappingError(f"payload is not in canonical {HA_DAILY_V3} form at {name!r}")
        raise MappingError(f"payload is not in canonical {HA_DAILY_V3} form")


def _dec(v: Any) -> Decimal:
    """The exact decimal of a number's shortest round-trip spelling (so 0.6 + 0.3 + 0.1 sums to exactly 1)."""
    return Decimal(repr(v)) if isinstance(v, float) else Decimal(v)


def payload_warnings_v3(payload: Mapping[str, Any]) -> list:
    """
    Warnings only; the commitment does not validate forecasts. Every rule here is a rule of the route's schema
    that the mapping deliberately does not enforce, so a forecast HA scored can always be committed:

      PROBABILITY_NEGATIVE            an entry is below zero
      PROBABILITY_SUM:<sum>           |sum - 1| > 1e-6
      DIRECTION_ARGMAX_MISMATCH:<d>   `direction` is present next to `probabilities` and is not the argmax
      CONFIDENCE_MAX_MISMATCH:<c>     `confidence` is present next to `probabilities` and is not the maximum
      MODEL_PROVIDER_NAME_NOT_PAIRED  only one of model_provider / model_name is present ("must be sent together")
    """
    warnings: list = []
    probs = payload.get("probabilities")
    if isinstance(probs, Mapping) and probs:
        values = {k: _dec(v) for k, v in probs.items()}
        if any(v < 0 for v in values.values()):
            warnings.append("PROBABILITY_NEGATIVE")
        total = sum(values.values(), Decimal(0))
        if abs(total - 1) > PROBABILITY_SUM_TOLERANCE:
            warnings.append(f"PROBABILITY_SUM:{format(total.normalize(_CTX), 'f')}")
        top = max(values.values())
        direction, confidence = payload.get("direction"), payload.get("confidence")
        if isinstance(direction, str) and values.get(direction) != top:
            warnings.append(f"DIRECTION_ARGMAX_MISMATCH:{direction}")
        if (
            isinstance(confidence, (int, float))
            and abs(_dec(confidence) - top) > _CONFIDENCE_TOLERANCE
        ):
            warnings.append(
                f"CONFIDENCE_MAX_MISMATCH:{format(_dec(confidence).normalize(_CTX), 'f')}"
            )
    if (payload.get("model_provider") is not None) != (payload.get("model_name") is not None):
        warnings.append("MODEL_PROVIDER_NAME_NOT_PAIRED")
    return warnings


@dataclasses.dataclass(frozen=True)
class PayloadMapping:
    mapping_id: str
    map: Callable[[Mapping[str, Any]], MappedPayload]
    check_canonical: Callable[[Mapping[str, Any]], None]
    payload_warnings: Callable[[Mapping[str, Any]], list]
    superseded_by: Optional[str] = (
        None  # set => verifiable, but new commitments should use the successor
    )
    number_profile: str = NUMBERS_DECIMAL_STRING  # how the committed payload spells numbers
    revision_numbering: Optional[RevisionNumbering] = None  # None => the mapping states no relation


MAPPINGS: Mapping[str, PayloadMapping] = {
    HA_DAILY_V1: PayloadMapping(
        HA_DAILY_V1,
        map_ha_daily_v1,
        check_canonical_ha_daily_v1,
        probability_warnings,
        superseded_by=HA_DAILY_V2,
    ),
    HA_DAILY_V2: PayloadMapping(
        HA_DAILY_V2,
        map_ha_daily_v2,
        check_canonical_ha_daily_v2,
        probability_warnings,
        superseded_by=HA_DAILY_V3,
    ),
    HA_DAILY_V3: PayloadMapping(
        HA_DAILY_V3,
        map_ha_daily_v3,
        check_canonical_ha_daily_v3,
        payload_warnings_v3,
        number_profile=NUMBERS_IEEE754_RFC8785,
        revision_numbering=HA_REVISION_NUMBERING,
    ),
}


def get_mapping(mapping_id: str) -> Optional[PayloadMapping]:
    return MAPPINGS.get(mapping_id)


def number_profile_for(mapping_id: Any) -> str:
    """The number profile a mapping commits under; an unknown or absent mapping gets the strict default."""
    m = MAPPINGS.get(mapping_id) if isinstance(mapping_id, str) else None
    return m.number_profile if m is not None else NUMBERS_DECIMAL_STRING


def known_mapping_ids() -> Sequence[str]:
    return tuple(MAPPINGS)
