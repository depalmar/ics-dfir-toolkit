"""Normalised project model shared by the L5X and PLCopen readers.

A project is reduced to three things the comparison understands:

* ``entities`` - named things with fields (tags, data types, modules, tasks,
  programs, add-on instructions, PLCopen POUs and variables, controller
  settings). Every field carries the difference class a change to it
  belongs to, and whether that change counts toward the verdict.
* ``routines`` - executable bodies. Text languages (RLL rungs, ST and IL
  lines) are sequences of units compared in order; graphical or protected
  bodies (FBD, SFC, LD, encoded content) are opaque and compared by hash.
* ``notes`` / ``not_evaluated`` - what the reader saw but could not compare.

Difference classes (see docs/logic-compare.md):
    logic, interface, value, tasking, aoi, module, metadata, documentation-only
"""
from __future__ import annotations

import hashlib
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Union

CLASSES = ("logic", "aoi", "tasking", "interface", "value", "module", "metadata", "documentation-only")
DOC = "documentation-only"

# A field value is either one string, or alternative renderings keyed by
# format (L5X Data: Decorated / String / L5K / raw); the comparison uses the
# first format both sides carry.
Value = Union[str, dict, None]
FORMAT_ORDER = ("Decorated", "String", "L5K", "raw")


@dataclass
class FieldVal:
    cls: str
    value: Value
    counted: bool = True
    opaque: bool = False
    note: str = ""


@dataclass
class Entity:
    path: str
    kind: str
    cls: str
    fields: dict = field(default_factory=dict)

    def set(self, name: str, cls: str, value: Value, *, counted: bool = True, opaque: bool = False, note: str = "") -> None:
        if value is None or value == "" or value == {}:
            return
        if cls == DOC:
            counted = False
        self.fields[name] = FieldVal(cls, value, counted, opaque, note)


@dataclass
class Unit:
    label: str          # rung number or line number, as written in the export
    code: str           # normalised text used for comparison
    raw: str            # text as exported, for the report
    doc: str = ""       # rung comment (documentation-only)
    attrs: dict = field(default_factory=dict)


@dataclass
class Routine:
    path: str
    cls: str                      # "logic" or "aoi"
    language: str
    unit_name: str = "line"       # "rung" or "line"
    units: list = field(default_factory=list)
    opaque_hash: str | None = None
    opaque_doc_hash: str | None = None   # hash with documentation elements removed
    opaque_reason: str = ""
    comments: tuple = ()          # comment texts inside ST/IL bodies
    attrs: dict = field(default_factory=dict)   # name -> FieldVal
    doc: dict = field(default_factory=dict)     # name -> str


@dataclass
class Model:
    fmt: str
    path: str
    sha256: str
    size: int
    entities: dict = field(default_factory=dict)
    routines: dict = field(default_factory=dict)
    notes: list = field(default_factory=list)
    not_evaluated: list = field(default_factory=list)
    scope: str = ""

    def entity(self, path: str, kind: str, cls: str) -> Entity:
        ent = self.entities.get(path)
        if ent is None:
            ent = self.entities[path] = Entity(path, kind, cls)
        return ent

    def add_routine(self, r: Routine) -> None:
        key, n = r.path, 2
        while key in self.routines:
            key = f"{r.path}#{n}"
            n += 1
        r.path = key
        self.routines[key] = r

    def note(self, text: str) -> None:
        if text not in self.notes:
            self.notes.append(text)


# ---------------------------------------------------------------- XML helpers

def local(tag) -> str:
    """Element or attribute name without its namespace."""
    if not isinstance(tag, str):
        return ""
    return tag.rsplit("}", 1)[-1]


def children(elem: ET.Element, name: str | None = None) -> list:
    return [c for c in elem if isinstance(c.tag, str) and (name is None or local(c.tag) == name)]


def child(elem: ET.Element, name: str):
    for c in elem:
        if isinstance(c.tag, str) and local(c.tag) == name:
            return c
    return None


_WS = re.compile(r"\s+")


def squash(text: str | None) -> str:
    """Collapse all whitespace runs to one space and strip."""
    return _WS.sub(" ", text or "").strip()


def text_of(elem) -> str:
    """All text inside an element (CDATA included), whitespace collapsed."""
    if elem is None:
        return ""
    return squash("".join(elem.itertext()))


def canon(elem: ET.Element, drop: frozenset = frozenset(), drop_attrs: frozenset = frozenset()) -> str:
    """Deterministic serialisation: names without namespace, sorted attributes,
    whitespace-collapsed text. Elements whose local name is in ``drop`` are
    left out with their content (their tail text is kept)."""
    parts = [f"<{local(elem.tag)}"]
    for k in sorted(elem.attrib):
        if local(k) not in drop_attrs:
            parts.append(f' {local(k)}="{squash(elem.attrib[k])}"')
    parts.append(">")
    parts.append(squash(elem.text))
    for c in elem:
        if isinstance(c.tag, str) and local(c.tag) not in drop:
            parts.append(canon(c, drop, drop_attrs))
        parts.append(squash(c.tail))
    parts.append(f"</{local(elem.tag)}>")
    return "".join(parts)


def sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def attrs_string(elem, skip: tuple = ()) -> str:
    if elem is None:
        return ""
    return "; ".join(f"{local(k)}={squash(v)}" for k, v in sorted(elem.attrib.items()) if local(k) not in skip)


# ------------------------------------------------------- program-text helpers

def normalise_code(text: str) -> str:
    """Collapse whitespace outside quoted strings. Inside '...' or "..."
    whitespace is kept exactly ($ escapes the next character, as in IEC
    61131-3 string literals)."""
    out = []
    quote = None
    pending_space = False
    i, n = 0, len(text)
    while i < n:
        ch = text[i]
        if quote:
            out.append(ch)
            if ch == "$" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if ch == quote:
                quote = None
        elif ch.isspace():
            pending_space = True
        else:
            if pending_space and out:
                out.append(" ")
            pending_space = False
            out.append(ch)
            if ch in ("'", '"'):
                quote = ch
        i += 1
    return "".join(out)


def strip_st_comments(text: str) -> tuple[str, list]:
    """Blank out ST/IL comments - (* ... *), /* ... */ and // to end of line -
    outside string literals, keeping every newline so line numbers stay put.
    Returns (code_text, [comment texts]). Comments are not treated as nested:
    text after an inner closing marker is kept as code, which can only make a
    comment edit show as a logic change, never hide a logic change."""
    out = []
    comments = []
    i, n = 0, len(text)
    quote = None
    while i < n:
        ch = text[i]
        if quote:
            out.append(ch)
            if ch == "$" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if ch == quote:
                quote = None
            i += 1
            continue
        two = text[i:i + 2]
        if two in ("(*", "/*"):
            end_marker = "*)" if two == "(*" else "*/"
            j = text.find(end_marker, i + 2)
            j = n if j < 0 else j + 2
            chunk = text[i:j]
            comments.append(squash(chunk))
            out.append("".join("\n" if c == "\n" else " " for c in chunk))
            i = j
            continue
        if two == "//":
            j = text.find("\n", i)
            j = n if j < 0 else j
            comments.append(squash(text[i:j]))
            out.append(" " * (j - i))
            i = j
            continue
        if ch in ("'", '"'):
            quote = ch
        out.append(ch)
        i += 1
    return "".join(out), comments


def text_units(lines: list, *, comment_syntax: bool) -> tuple[list, tuple]:
    """Turn (label, raw_line) pairs into Units. With comment_syntax, comments
    are removed before comparison and lines left empty are skipped (they
    carry no logic); the comment texts are returned separately."""
    expanded = []
    for lbl, raw in lines:
        parts = raw.replace("\r\n", "\n").replace("\r", "\n").split("\n")
        for k, part in enumerate(parts):
            expanded.append((lbl if k == 0 else f"{lbl}.{k}", part))
    labels = [lbl for lbl, _ in expanded]
    raws = [raw for _, raw in expanded]
    comments: list = []
    if comment_syntax:
        code_text, comments = strip_st_comments("\n".join(raws))
        codes = code_text.split("\n")
    else:
        codes = list(raws)
    units = []
    for lbl, raw, code in zip(labels, raws, codes):
        norm = normalise_code(code)
        if norm:
            units.append(Unit(label=str(lbl), code=norm, raw=raw.strip()))
    return units, tuple(c for c in comments if c)
