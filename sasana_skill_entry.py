"""
sasana_skill_entry.py — OpenClaw skill entry point.

openclaw skill install sasana

Every session → ~/.openclaw/sasana/<session_id>.jsonl
Verify: sasana verify ~/.openclaw/sasana/<session_id>.jsonl
"""

from __future__ import annotations

import logging
import os
import sys

_root = os.path.dirname(os.path.abspath(__file__))
if _root not in sys.path:
    sys.path.insert(0, _root)

from sasana.skill import SasanaSkill

logging.basicConfig(level=logging.WARNING)


class SasanaSkillEntry(SasanaSkill):
    """Thin wrapper so OpenClaw finds the class declared in sasanamanifest.json."""

    def __init__(self, config: dict | None = None) -> None:
        super().__init__(config=config)
        logging.getLogger("sasana.skill").info("Sasana loaded → %s", self._output_dir)
