"""ICS/OT triage helpers for ics-dfir-toolkit.

Everything here works offline on files an engineer or responder already
holds. Nothing in this package connects to a controller, a network or a
vendor tool, and nothing is ever executed or imported from an input file.

Subcommands (``python -m icstriage --help``):

    logic-diff   compare two exported controller projects (Rockwell L5X or
                 L5K, PLCopen TC6 XML or Siemens SimaticML) and report every
                 difference, classified.

See docs/logic-compare.md.
"""
from __future__ import annotations

__version__ = "0.1.0"
