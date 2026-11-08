"""Offline control-logic comparison: does an exported project match the known-good copy?

    from icstriage.logic import load_model, compare, build_report
    base = load_model("good.L5X")
    cur = load_model("suspect.L5X")
    report = build_report(base, cur, compare(base, cur))

Formats are recognised by root element: ``RSLogix5000Content`` (Rockwell
L5X) or ``project`` in a ``http://www.plcopen.org/xml/tc6...`` namespace
(PLCopen TC6 XML). Files are screened by safexml before any parsing.
"""
from __future__ import annotations

from . import l5x, plcopen
from .diff import DiffResult, Difference, FormatMismatch, compare
from .model import Model, local
from .report import DIFFERENCES, NONE_FOUND, build as build_report, to_json, to_markdown
from .safexml import MAX_BYTES_DEFAULT, InputFormatError, UnsafeInputError, load


def detect(root) -> str:
    if local(root.tag) == l5x.ROOT and not root.tag.startswith("{"):
        return l5x.FORMAT
    if plcopen.is_plcopen(root):
        return plcopen.FORMAT
    raise InputFormatError(f"unrecognised export: root element {root.tag!r} is neither RSLogix5000Content (L5X) "
                           "nor a PLCopen TC6 XML project")


def load_model(path: str, *, max_bytes: int = MAX_BYTES_DEFAULT, **limits) -> Model:
    doc = load(path, max_bytes=max_bytes, **limits)
    fmt = detect(doc.root)
    reader = l5x if fmt == l5x.FORMAT else plcopen
    try:
        return reader.parse(doc.root, path=path, sha256=doc.sha256, size=doc.size)
    except ValueError as exc:
        raise InputFormatError(f"{path}: {exc}") from None


__all__ = ["DIFFERENCES", "NONE_FOUND", "DiffResult", "Difference", "FormatMismatch", "InputFormatError",
           "Model", "UnsafeInputError", "build_report", "compare", "detect", "load_model", "to_json", "to_markdown"]
