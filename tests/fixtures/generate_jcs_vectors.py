#!/usr/bin/env python3
"""
Regenerate tests/fixtures/jcs_vectors.json — the canonicalization vectors shared by the Python
and Rust test suites.

    python generate_jcs_vectors.py <path-to-v1.1.0-source-tree>

Where each expectation comes from (nothing is produced by the code under test):
  * "rfc8785" for numbers: Node.js ``JSON.stringify(Number(token))``. That is ECMAScript
    Number::toString, the algorithm RFC 8785 section 3.2.2.3 mandates, in an independent
    implementation.
  * "legacy": the real ``sasana/jcs.py`` of the published 1.1.0 release, loaded from the tree
    given on the command line (identical to 1.0.0's).
  * RFC 8785 Appendix B: the (IEEE-754 bits -> text) table printed in the RFC.
  * "documents": the RFC 8785 section 3.2.4 sorting example and section 3.2.2 example, with the
    expected output transcribed by hand from the RFC.
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

release_tree = Path(sys.argv[1]).resolve()
spec = importlib.util.spec_from_file_location("legacy_jcs", release_tree / "sasana" / "jcs.py")
legacy_jcs = importlib.util.module_from_spec(spec)
spec.loader.exec_module(legacy_jcs)

NUMBER_TOKENS = [
    "0",
    "1",
    "-1",
    "42",
    "9007199254740991",
    "9007199254740992",
    "9007199254740993",
    "9223372036854775807",
    "9223372036854775808",
    "12345678901234567890",
    "0.0",
    "-0.0",
    "0.5",
    "0.1",
    "1.0",
    "100.0",
    "1200.0",
    "1e3",
    "1.5",
    "3.14159",
    "1234.5678",
    "0.30000000000000004",
    "4.50",
    "2e-3",
    "333333333.33333329",
    "0.0001",
    "0.00001",
    "1e-5",
    "2.5e-5",
    "1.5e-7",
    "1e-7",
    "1e-27",
    "0.000001",
    "5e-324",
    "1e15",
    "1e16",
    "1e17",
    "1e20",
    "1e21",
    "1.2e21",
    "1e30",
    "1.7976931348623157e308",
    "123456789.123456789",
    "-100.0",
    "-1.5e-7",
    "-1e21",
]


def node_number(token: str) -> str:
    out = subprocess.run(
        ["node", "-e", "console.log(JSON.stringify(Number(process.argv[1])))", "--", token],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    return "0" if out == "-0" else out  # RFC 8785: negative zero serializes as 0


numbers = []
for tok in NUMBER_TOKENS:
    value = json.loads(tok)
    numbers.append(
        {
            "json": tok,
            "legacy": legacy_jcs.canonicalize(value).decode(),
            "rfc8785": node_number(tok),
        }
    )

# RFC 8785 Appendix B (IEEE-754 bit pattern -> canonical text)
appendix_b = {
    "0000000000000000": "0",
    "8000000000000000": "0",
    "0000000000000001": "5e-324",
    "8000000000000001": "-5e-324",
    "7FEFFFFFFFFFFFFF": "1.7976931348623157e+308",
    "FFEFFFFFFFFFFFFF": "-1.7976931348623157e+308",
    "4340000000000000": "9007199254740992",
    "C340000000000000": "-9007199254740992",
    "4430000000000000": "295147905179352830000",
    "44B52D02C7E14AF5": "9.999999999999997e+22",
    "44B52D02C7E14AF6": "1e+23",
    "44B52D02C7E14AF7": "1.0000000000000001e+23",
    "444B1AE4D6E2EF4E": "999999999999999700000",
    "444B1AE4D6E2EF4F": "999999999999999900000",
    "444B1AE4D6E2EF50": "1e+21",
    "3EB0C6F7A0B5ED8C": "9.999999999999997e-7",
    "3EB0C6F7A0B5ED8D": "0.000001",
    "41B3DE4355555553": "333333333.3333332",
    "41B3DE4355555554": "333333333.33333325",
    "41B3DE4355555555": "333333333.3333333",
    "41B3DE4355555556": "333333333.3333334",
    "41B3DE4355555557": "333333333.33333343",
    "BECBF647612F3696": "-0.0000033333333333333333",
    "43143FF3C1CB0959": "1424953923781206.2",
}

SORT_EXAMPLE = (
    '{"\\u20ac":"Euro Sign","\\r":"Carriage Return","\\ufb33":"Hebrew Letter Dalet With Dagesh",'
    '"1":"One","\\ud83d\\ude00":"Emoji: Grinning Face","\\u0080":"Control",'
    '"\\u00f6":"Latin Small Letter O With Diaeresis"}'
)
SORT_EXPECTED = (
    '{"\\r":"Carriage Return","1":"One","\u0080":"Control","ö":"Latin Small Letter O With '
    'Diaeresis","€":"Euro Sign","\U0001f600":"Emoji: Grinning Face",'
    '"דּ":"Hebrew Letter Dalet With Dagesh"}'
)
SECTION_322_EXAMPLE = (
    '{"numbers":[333333333.33333329,1E30,4.50,2e-3,0.000000000000000000000000001],'
    '"string":"\\u20ac$\\u000F\\u000aA\'\\u0042\\u0022\\u005c\\\\\\"\\/","literals":[null,true,false]}'
)
SECTION_322_EXPECTED = (
    '{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],'
    '"string":"€$\\u000f\\nA\'B\\"\\\\\\\\\\"/"}'
)

documents = [
    {"name": "RFC 8785 3.2.4 sorting example", "json": SORT_EXAMPLE, "rfc8785": SORT_EXPECTED},
    {
        "name": "RFC 8785 3.2.2 example",
        "json": SECTION_322_EXAMPLE,
        "rfc8785": SECTION_322_EXPECTED,
    },
    {
        "name": "nested, unsorted, mixed",
        "json": '{"z":{"b":[1,2.0,{"y":-0.0,"a":"\\u00e9"}],"a":null},"a":true}',
        "rfc8785": None,
    },
    {
        "name": "unicode and escapes",
        "json": '{"s":"Gr\\u00fc\\u00dfe \\u4e16\\u754c \\ud83d\\ude00 \\t \\\\ \\"q\\" \\/ \\u0001"}',
        "rfc8785": None,
    },
    {
        "name": "event-shaped payload",
        "json": '{"payload":{"duration_ms":1200.0,"cost_usd":0.0,"n":9007199254740993},"seq":2}',
        "rfc8785": None,
    },
]
for d in documents:
    value = json.loads(d["json"])
    d["legacy"] = legacy_jcs.canonicalize(value).decode()

# RFC 8785 expectation for documents without a transcribed RFC answer: legacy and RFC 8785 differ
# only in numbers, so derive it from the legacy bytes by substituting each number with the
# Node-computed text. These cases contain only the numbers listed here.
substitutions = {
    '"duration_ms":1200.0': '"duration_ms":1200',
    '"cost_usd":0.0': '"cost_usd":0',
    '"n":9007199254740993': '"n":9007199254740992',
    '"y":-0.0': '"y":0',
    ",2.0,": ",2,",
}
for d in documents:
    if d["rfc8785"] is None:
        out = d["legacy"]
        for a, b in substitutions.items():
            out = out.replace(a, b)
        d["rfc8785"] = out

Path(__file__).with_name("jcs_vectors.json").write_text(
    json.dumps(
        {"numbers": numbers, "appendix_b": appendix_b, "documents": documents},
        indent=1,
        ensure_ascii=False,
    )
    + "\n"
)
print(len(numbers), "number vectors,", len(appendix_b), "appendix B,", len(documents), "documents")
