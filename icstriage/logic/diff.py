"""Compare two normalised models and classify every difference.

Classes (docs/logic-compare.md):

    logic               rung / ST line / body added, removed or changed
    aoi                 Add-On Instruction or IEC function / function block changed
                        (CISA AA26-097A: "reusable code modules")
    tasking             task type, period, priority, scheduled programs, program
                        enable / main routine (ATT&CK for ICS T0821)
    interface           tag / variable / data type added, removed or retyped
    value               stored or initial value, force data
    module              I/O tree, module identity, keying, firmware revision
    metadata            dates, revisions, controller settings, export provenance
    documentation-only  descriptions, comments, display radix - never counted

A difference is *counted* unless it is documentation-only or a field the
reader marked as provenance (timestamps, exporter identity). The verdict is
DIFFERENCES-FOUND when at least one counted difference exists.
"""
from __future__ import annotations

import difflib
from dataclasses import dataclass, field

from .model import DOC, FORMAT_ORDER, Entity, Model, Routine

# Candidate ATT&CK for ICS techniques for a reviewer to consider. A difference
# is not by itself evidence of adversary activity.
ATTACK = {"tasking": ("T0821",), "logic": ("T0889",), "aoi": ("T0889",), "value": ("T0836",)}


class FormatMismatch(ValueError):
    pass


@dataclass
class Difference:
    cls: str
    change: str                 # added | removed | changed
    path: str
    field: str = ""
    baseline: object = None
    current: object = None
    counted: bool = True
    opaque: bool = False
    note: str = ""
    attack: tuple = ()

    def as_dict(self) -> dict:
        return {"class": self.cls, "change": self.change, "path": self.path, "field": self.field,
                "baseline": self.baseline, "current": self.current, "counted": self.counted,
                "opaque": self.opaque, "note": self.note, "attack_candidates": list(self.attack)}


@dataclass
class DiffResult:
    differences: list = field(default_factory=list)
    not_evaluated: list = field(default_factory=list)
    notes: list = field(default_factory=list)

    @property
    def counted(self) -> list:
        return [d for d in self.differences if d.counted]


def _add(out: list, d: Difference) -> None:
    if d.cls == DOC:
        d.counted = False
    d.attack = ATTACK.get(d.cls, ()) if d.counted else ()
    out.append(d)


def _pick(v, *, other=None):
    """Resolve a multi-format value. Returns (text, format) or (None, None)."""
    if not isinstance(v, dict):
        return v, None
    if other is not None and isinstance(other, dict):
        common = [f for f in FORMAT_ORDER if f in v and f in other] + sorted(set(v) & set(other) - set(FORMAT_ORDER))
        if not common:
            return None, None
        return v[common[0]], common[0]
    for f in FORMAT_ORDER:
        if f in v:
            return v[f], f
    k = sorted(v)[0]
    return v[k], k


def _member_changes(a: str, b: str, limit: int = 8) -> str:
    """For 'path=value' line values, name the members that differ."""
    if not (isinstance(a, str) and isinstance(b, str) and ("\n" in a or "\n" in b)):
        return ""
    da = dict(line.split("=", 1) for line in a.split("\n") if "=" in line)
    db = dict(line.split("=", 1) for line in b.split("\n") if "=" in line)
    changed = [k for k in list(da) + [k for k in db if k not in da] if da.get(k) != db.get(k)]
    if not changed:
        return ""
    parts = [f"{k}: {da.get(k, '(absent)')} -> {db.get(k, '(absent)')}" for k in changed[:limit]]
    more = f" (+{len(changed) - limit} more)" if len(changed) > limit else ""
    return "members changed: " + "; ".join(parts) + more


def _summary(ent: Entity) -> str:
    parts = []
    for name, f in ent.fields.items():
        if f.cls == DOC or f.opaque:
            continue
        v, _ = _pick(f.value)
        if isinstance(v, str) and len(v) <= 80 and "\n" not in v:
            parts.append(f"{name}={v}")
        if len(parts) == 5:
            break
    return "; ".join(parts)


def _fields(out: list, notev: list, path: str, fb: dict, fc: dict) -> None:
    names = list(fb) + [n for n in fc if n not in fb]
    for name in names:
        a, b = fb.get(name), fc.get(name)
        ref = a or b
        va, vb = (a.value if a else None), (b.value if b else None)
        fmt = None
        if isinstance(va, dict) and isinstance(vb, dict):
            sa, fmt = _pick(va, other=vb)
            if fmt is None:
                notev.append(f"{path} {name}: value formats differ ({', '.join(sorted(va))} vs "
                             f"{', '.join(sorted(vb))}); not compared")
                continue
            sb = vb[fmt]
        else:
            sa, _ = _pick(va)
            sb, _ = _pick(vb)
        if sa == sb:
            continue
        change = "changed" if a and b else ("added" if a is None else "removed")
        counted = (a.counted if a else False) or (b.counted if b else False)
        notes = [ref.note] if ref.note else []
        if fmt and fmt != "Decorated":
            notes.append(f"compared in {fmt} format")
        mc = _member_changes(sa, sb)
        if mc:
            notes.append(mc)
        _add(out, Difference(ref.cls, change, path, name, sa, sb, counted, ref.opaque, "; ".join(notes)))


def _entities(out: list, notev: list, base: Model, cur: Model) -> None:
    for path in sorted(set(base.entities) | set(cur.entities)):
        a, b = base.entities.get(path), cur.entities.get(path)
        if a is None or b is None:
            ent = a or b
            counted = ent.cls != DOC and (not ent.fields or any(f.counted for f in ent.fields.values()))
            summ = _summary(ent)
            _add(out, Difference(ent.cls, "removed" if b is None else "added", path, ent.kind,
                                 summ if b is None else None, summ if a is None else None, counted))
            continue
        _fields(out, notev, path, a.fields, b.fields)


def _unit_label(r: Routine, u) -> str:
    return f"{r.unit_name} {u.label}".strip()


def _unit_note(*units) -> tuple:
    """(opaque, note) for a unit difference: graphical networks compared by hash."""
    if any(u is not None and u.opaque for u in units):
        return True, "graphical network: what changed inside is not shown"
    return False, ""


def _routine(out: list, notev: list, a: Routine, b: Routine) -> None:
    path = a.path
    _fields(out, notev, path, a.attrs, b.attrs)
    for k in list(a.doc) + [k for k in b.doc if k not in a.doc]:
        if a.doc.get(k, "") != b.doc.get(k, ""):
            _add(out, Difference(DOC, "changed", path, k, a.doc.get(k) or None, b.doc.get(k) or None, False))
    if a.language != b.language:
        _add(out, Difference(a.cls, "changed", path, "language", a.language, b.language,
                             note="routine language changed; content not compared line by line"))
        return
    if a.opaque_hash or b.opaque_hash:
        if a.opaque_hash != b.opaque_hash:
            if a.opaque_doc_hash and a.opaque_doc_hash == b.opaque_doc_hash:
                _add(out, Difference(DOC, "changed", path, "content (documentation elements only)",
                                     a.opaque_hash[:16], b.opaque_hash[:16], False, True,
                                     "differs only in descriptions, comments or text boxes; compared by hash"))
            else:
                _add(out, Difference(a.cls, "changed", path, "content", (a.opaque_hash or "")[:16] or None,
                                     (b.opaque_hash or "")[:16] or None, True, True,
                                     a.opaque_reason or b.opaque_reason))
        return
    sm = difflib.SequenceMatcher(None, [u.code for u in a.units], [u.code for u in b.units], autojunk=False)
    for op, i1, i2, j1, j2 in sm.get_opcodes():
        if op == "equal":
            for ua, ub in zip(a.units[i1:i2], b.units[j1:j2]):
                label = _unit_label(a, ua) + ("" if ua.label == ub.label else f" (now {ub.label})")
                for k in list(ua.attrs) + [k for k in ub.attrs if k not in ua.attrs]:
                    if ua.attrs.get(k) != ub.attrs.get(k):
                        _add(out, Difference(a.cls, "changed", path, f"{label} {k}", ua.attrs.get(k), ub.attrs.get(k),
                                             note="rung edit state" if k == "Type" else ""))
                if ua.doc != ub.doc:
                    _add(out, Difference(DOC, "changed", path, f"{label} comment", ua.doc or None, ub.doc or None, False))
            continue
        olds, news = a.units[i1:i2], b.units[j1:j2]
        paired = min(len(olds), len(news)) if op == "replace" else 0
        for ua, ub in zip(olds[:paired], news[:paired]):
            label = _unit_label(a, ua) + ("" if ua.label == ub.label else f" (now {ub.label})")
            opq, note = _unit_note(ua, ub)
            _add(out, Difference(a.cls, "changed", path, label, ua.raw, ub.raw, opaque=opq, note=note))
        for ua in olds[paired:]:
            opq, note = _unit_note(ua)
            _add(out, Difference(a.cls, "removed", path, _unit_label(a, ua), ua.raw, None, opaque=opq, note=note))
        for ub in news[paired:]:
            opq, note = _unit_note(ub)
            _add(out, Difference(a.cls, "added", path, _unit_label(b, ub), None, ub.raw, opaque=opq, note=note))
    if a.comments != b.comments:
        _add(out, Difference(DOC, "changed", path, "comments in code", " | ".join(a.comments) or None,
                             " | ".join(b.comments) or None, False))


def _routines(out: list, notev: list, base: Model, cur: Model) -> None:
    for path in sorted(set(base.routines) | set(cur.routines)):
        a, b = base.routines.get(path), cur.routines.get(path)
        if a is None or b is None:
            r = a or b
            summ = f"{r.language}, " + (f"{len(r.units)} {r.unit_name or 'unit'}s" if not r.opaque_hash else "opaque")
            _add(out, Difference(r.cls, "removed" if b is None else "added", path, "routine",
                                 summ if b is None else None, summ if a is None else None))
            continue
        _routine(out, notev, a, b)


def compare(base: Model, cur: Model) -> DiffResult:
    if base.fmt != cur.fmt:
        hint = ""
        if {base.fmt, cur.fmt} == {"L5K", "L5X"}:
            hint = (": both are Rockwell exports, but 1756-RM014 spells the same attributes differently in the two "
                    "formats (Yes/No against true/false, Major against MajorRev, MODE against TestEdits) and encodes tag "
                    "data differently (value lists against decorated XML), so a cross-format comparison would report "
                    "differences that are not changes; export both sides as L5K or both as L5X")
        raise FormatMismatch(f"cannot compare a {base.fmt} export with a {cur.fmt} export{hint}")
    res = DiffResult()
    _entities(res.differences, res.not_evaluated, base, cur)
    _routines(res.differences, res.not_evaluated, base, cur)
    if base.scope != cur.scope:
        res.notes.append(f"export scopes differ (baseline {base.scope or '?'}, current {cur.scope or '?'}): "
                         "components present in only one export show as added or removed")
    for n in base.notes:
        res.notes.append(f"both exports: {n}" if n in cur.notes else f"baseline: {n}")
    for n in cur.notes:
        if n not in base.notes:
            res.notes.append(f"current: {n}")
    res.not_evaluated.extend(f"baseline: {n}" for n in base.not_evaluated)
    res.not_evaluated.extend(f"current: {n}" for n in cur.not_evaluated)
    return res
