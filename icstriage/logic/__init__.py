"""Offline control-logic comparison: does an exported project match the known-good copy?

    from icstriage.logic import load_model, compare, build_report
    base = load_model("good.L5X")
    cur = load_model("suspect.L5X")
    report = build_report(base, cur, compare(base, cur))

Formats are recognised by content, never by file extension: root element
``RSLogix5000Content`` (Rockwell L5X), ``project`` in a
``http://www.plcopen.org/xml/tc6...`` namespace (PLCopen TC6 XML), or
``Document`` holding ``SW.*`` objects (Siemens SimaticML from TIA Portal
Openness). A directory is read as a set of SimaticML files, one per block,
UDT or tag table. Files are screened by safexml before any parsing.
"""
from __future__ import annotations

import os

from . import l5x, plcopen, siemens
from .diff import DiffResult, Difference, FormatMismatch, compare
from .model import Model, local
from .report import DIFFERENCES, NONE_FOUND, build as build_report, to_json, to_markdown
from .safexml import MAX_BYTES_DEFAULT, InputFormatError, UnsafeInputError, load

READERS = {l5x.FORMAT: l5x, plcopen.FORMAT: plcopen, siemens.FORMAT: siemens}


def detect(root) -> str:
    if local(root.tag) == l5x.ROOT and not root.tag.startswith("{"):
        return l5x.FORMAT
    if plcopen.is_plcopen(root):
        return plcopen.FORMAT
    if siemens.is_simaticml(root):
        return siemens.FORMAT
    if local(root.tag) == siemens.ROOT and not root.tag.startswith("{"):
        raise InputFormatError("SimaticML document without a PLC software object (SW.*): HMI and other TIA Portal "
                               "objects are not compared by this tool")
    raise InputFormatError(f"unrecognised export: root element {root.tag!r} is not RSLogix5000Content (L5X), "
                           "a PLCopen TC6 XML project or a SimaticML Document")


def load_model(path: str, *, max_bytes: int = MAX_BYTES_DEFAULT, **limits) -> Model:
    if os.path.isdir(path):
        return siemens.load_directory(path, max_bytes=max_bytes, **limits)
    doc = load(path, max_bytes=max_bytes, **limits)
    reader = READERS[detect(doc.root)]
    try:
        return reader.parse(doc.root, path=path, sha256=doc.sha256, size=doc.size)
    except ValueError as exc:
        raise InputFormatError(f"{path}: {exc}") from None


__all__ = ["DIFFERENCES", "NONE_FOUND", "DiffResult", "Difference", "FormatMismatch", "InputFormatError",
           "Model", "UnsafeInputError", "build_report", "compare", "detect", "load_model", "to_json", "to_markdown"]
