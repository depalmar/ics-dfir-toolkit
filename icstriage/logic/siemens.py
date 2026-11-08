"""Read Siemens TIA Portal Openness exports (SimaticML) into the normalised model.

Sources, read directly on 2026-11-08 (docs/logic-compare.md gives sections
and the exact statements relied on):

* Siemens, *SIMATIC TIA Portal Openness: API for automation of engineering
  workflows*, System Manual, 11/2023 (TIA Portal V19), section 6.1 (p.1207-1213),
  6.4.2 Blocks (p.1295-1400), 6.4.4 Tag tables (p.1426-1430) and 7.6.4 (p.1658-1676);
* the same manual's V20 edition on docs.tia.siemens.cloud (topics "Exporting
  blocks", "XML structure of the block interface section", "Export/Import of
  SCL blocks", "Exporting blocks with know-how protection");
* Siemens FAQ 109480446, "How is the XML file structured for blocks".

What the documentation shows, and therefore what is read:

* ``Document`` root with ``Engineering`` @version, ``DocumentInfo`` and one
  object per start object; objects ``SW.Blocks.*`` (FB, FC, OB, GlobalDB,
  InstanceDB, ArrayDB), ``SW.Types.PlcStruct`` (UDT), ``SW.Tags.*`` (tag tables,
  tags, user constants) and ``SW.Blocks.InterfaceSnapshot``;
* ``AttributeList`` children as attributes (the "Exporting blocks" tables name
  them: ``Name``, ``Number``, ``ProgrammingLanguage``, ``IsKnowHowProtected``,
  the OB attributes ``EventClass``, ``PriorityNumber``, ...);
* ``Interface/Sections/Section`` @Name with ``Member`` (@Name, @Datatype,
  @Remanence, @Accessibility, @Version, @Informative), member ``AttributeList``
  (``BooleanAttribute`` etc. by @Name), ``StartValue``, ``Comment``
  (``MultiLanguageText`` @Lang), nested ``Member`` / ``Sections`` and
  ``Subelement`` @Path;
* ``ObjectList`` with ``MultilingualText`` @CompositionName (Comment, Title)
  and compile units. The FAQ documents a compile unit as an object whose
  ``AttributeList`` holds ``NetworkSource`` and ``ProgrammingLanguage``; the
  compile unit element's own name is not shown in the text read for V14 and
  later, so compile units are recognised by that structure, not by name;
* SCL token elements (``Token`` @Text, ``Blank``/``NewLine`` @Num,
  ``LineComment``, ``Comment``, ``Text``, ``Access`` @Scope with ``Symbol`` /
  ``Component`` / ``Constant`` / ``Address`` / ``CallInfo`` / ``Instruction`` /
  ``Parameter`` / ``NamelessParameter`` / ``Label`` / ``PredefinedVariable``)
  and STL ``StlStatement`` / ``StlToken``.

Opaque (compared by hash): LAD/FBD (``FlgNet``) and GRAPH networks, any
network of another language, the content of know-how-protected blocks, and
every element not listed above. Elements and attributes flagged
``Informative="true"`` are derived data (Siemens: they "are not imported") and
are left out of the comparison; ``ID`` and ``UId`` values are XML-local keys.
"""
from __future__ import annotations

import hashlib
import os
import xml.etree.ElementTree as ET

from .model import DOC, Model, Routine, Unit, canon, child, children, local, normalise_code, sha, squash, text_of
from .safexml import MAX_BYTES_DEFAULT, InputFormatError, UnsafeInputError, load

FORMAT = "SimaticML"
ROOT = "Document"
MAX_FILES = 50_000

# Block object suffix (SW.Blocks.<type>) -> difference class. FB and FC are the
# reusable code modules CISA AA26-097A compares to Rockwell AOIs (ICS-0003).
BLOCK_CLASS = {"OB": "logic", "FB": "aoi", "FC": "aoi",
               "GlobalDB": "interface", "InstanceDB": "interface", "ArrayDB": "interface"}
CODE_BLOCKS = {"OB", "FB", "FC"}
# "Exporting blocks": DateTime attributes, all ReadOnly - provenance, reported only.
PROVENANCE = {"CodeModifiedDate", "CompileDate", "CreationDate", "InterfaceModifiedDate", "ModifiedDate",
              "ParameterModified", "StructureModified"}
# "Exporting blocks", "Attributes applicable for OB block" -> tasking (T0821).
OB_TASKING = {"ApplicationCycle", "AutomaticMinimum", "ConstantName", "CycleTimeDistributedIO",
              "CyclicApplicationCycleTime", "CyclicTime", "DataExchangeMode", "DelayTime", "DistributedIOName",
              "DistributedIONumber", "EnableTimeError", "EventClass", "EventsToBeQueued", "EventThresholdForTimeError",
              "Execution", "Factor", "PhaseOffset", "PriorityNumber", "ProcessImagePartNumber", "ReportEvents",
              "SecondaryType", "StartDate", "SynchronousApplicationCycleTime", "TimeMode", "TimeOfDay",
              "TransformationDBNumber"}
# Which FB / UDT an instance or array DB is built from.
INTERFACE_ATTRS = {"InstanceOfName", "InstanceOfNumber", "InstanceOfType", "OfSystemLibElement",
                   "OfSystemLibVersion", "ArrayDataType", "ArrayLimitUpperBound"}
CODE_ATTRS = {"ProgrammingLanguage", "IsKnowHowProtected"}
KEYS = frozenset({"ID", "UId"})
NOT_COMPARED = frozenset({"ID", "UId", "Informative"})

KHP_QUOTE = "If the block is exported without unlocking, only the public block interface will be exported."


def is_simaticml(root: ET.Element) -> bool:
    return (local(root.tag) == ROOT and not root.tag.startswith("{")
            and any(local(c.tag).startswith("SW.") for c in children(root)))


def _true(v) -> bool:
    return str(v or "").strip().lower() in ("true", "1")


def _informative(e: ET.Element) -> bool:
    return _true(e.get("Informative"))


def _num(e: ET.Element, cap: int) -> int:
    """NewLine/Blank @Num (manual 6.4.2.5: unsigned, default 1), capped so a
    hostile value cannot amplify memory."""
    try:
        n = int(e.get("Num", "1"))
    except ValueError:
        return 1
    return max(1, min(n, cap))


def _lines(text: str):
    """(line number, line) without building a list of every line."""
    start, k = 0, 1
    while True:
        j = text.find("\n", start)
        if j < 0:
            yield k, text[start:]
            return
        yield k, text[start:j]
        start, k = j + 1, k + 1


def _multilang(e) -> str:
    """MultilingualText (ObjectList: MultilingualTextItem/AttributeList/Culture,Text)
    or Comment/StepName (MultiLanguageText @Lang) -> 'culture: text | ...'."""
    if e is None:
        return ""
    items = []
    for it in e.iter():
        if not isinstance(it.tag, str):
            continue
        n = local(it.tag)
        if n == "MultilingualTextItem":
            al = child(it, "AttributeList")
            if al is not None:
                txt = text_of(child(al, "Text"))
                if txt:
                    items.append(f"{text_of(child(al, 'Culture'))}: {txt}")
        elif n == "MultiLanguageText":
            txt = text_of(it)
            if txt:
                items.append(f"{it.get('Lang', '')}: {txt}")
    return " | ".join(items)


def _canon_net(e: ET.Element) -> str:
    """Canonical form of a graphical network for hashing. ID keys dropped;
    children of Wires sorted after dropping each Wire's own UId, because
    Siemens states that in LAD/FBD exports "the order of wires and references
    is still not reliable" (manual 7.6.4.5). Part UIds are kept: wires refer
    to them."""
    n = local(e.tag)
    attrs = "".join(f' {local(k)}="{squash(v)}"' for k, v in sorted(e.attrib.items()) if local(k) != "ID")
    kids = [c for c in e if isinstance(c.tag, str)]
    if n == "Wires":
        rendered = sorted(_canon_net_wire(c) for c in kids)
    else:
        rendered = [_canon_net(c) for c in kids]
    return f"<{n}{attrs}>{squash(e.text)}{''.join(rendered)}</{n}>"


def _canon_net_wire(w: ET.Element) -> str:
    n = local(w.tag)
    attrs = "".join(f' {local(k)}="{squash(v)}"' for k, v in sorted(w.attrib.items()) if local(k) not in KEYS)
    return f"<{n}{attrs}>{squash(w.text)}{''.join(_canon_net(c) for c in w if isinstance(c.tag, str))}</{n}>"


class _Render:
    """Render SCL / STL token elements (manual 6.4.2.5-6.4.2.7, 7.6.4.4-7.6.4.5)
    into comparable text. The result is a canonical rendering for comparison,
    close to but not guaranteed to be the SCL the editor shows. Comments are
    collected separately (documentation-only); elements outside the documented
    vocabulary are kept inline as canonical XML so that a change to them is
    still a difference."""

    def __init__(self) -> None:
        self.comments: list = []
        self.unknown: set = set()

    def run(self, elems, sep: str = "") -> str:
        out = [self.node(e) for e in elems if isinstance(e.tag, str)]
        return sep.join(s for s in out if s)

    def node(self, e: ET.Element, scope: str = "") -> str:
        if _informative(e):
            return ""
        n = local(e.tag)
        if n in ("Token", "StlToken"):
            return e.get("Text", e.get("text", ""))
        if n == "Blank":
            return " "                      # whitespace outside literals is not significant
        if n == "NewLine":
            return "\n" * _num(e, 10)
        if n == "LineComment":
            txt = "".join(child(e, "Text").itertext()) if child(e, "Text") is not None else ""
            # manual 6.4.2.5: Inserted="true" is a (* *) comment, otherwise //
            self.comments.append(f"(* {squash(txt)} *)" if _true(e.get("Inserted")) else f"// {squash(txt)}")
            return ""
        if n == "Comment":
            self.comments.append(_multilang(e))
            return ""
        if n == "Text":
            return "".join(e.itertext())
        if n == "Access":
            return self.access(e)
        if n == "Symbol":
            return self.symbol(e, scope)
        if n == "Component":
            return self.component(e, "")
        if n == "Constant":
            return self.constant(e, scope)
        if n in ("Address", "AbsoluteOffset"):
            return self.address(e)
        if n == "CallInfo":
            return self.callinfo(e)
        if n == "Instance":
            return self.instance(e)
        if n == "Instruction":
            ver = f"@{e.get('Version')}" if e.get("Version") else ""
            return e.get("Name", "") + ver + self.run(children(e))
        if n == "Parameter":
            extra = ",".join(f"{local(k)}={v}" for k, v in sorted(e.attrib.items())
                             if local(k) not in NOT_COMPARED | {"Name"})
            return f" {e.get('Name', '')}" + (f"[{extra}]" if extra else "") + " " + self.run(children(e))
        if n == "NamelessParameter":
            return self.run(children(e))
        if n == "Label":
            return e.get("Name", "") + self.run(children(e))
        if n == "PredefinedVariable":
            return e.get("Name", "")
        if n == "DataType":
            return squash("".join(e.itertext()))
        if n == "TemplateValue":
            return f"<{e.get('Name', '')}={squash(''.join(e.itertext()))}>"
        if n in ("BooleanAttribute", "IntegerAttribute", "StringAttribute", "DateAttribute"):
            return "{" + f"{e.get('Name', '')}={squash(''.join(e.itertext()))}" + "}"
        self.unknown.add(n)
        return canon(e, drop_attrs=KEYS)

    def access(self, e: ET.Element) -> str:
        scope = e.get("Scope", "")
        if scope == "UserType":
            return "".join(f'"{squash("".join(d.itertext()))}"' for d in children(e, "DataType"))
        return "".join(self.node(c, scope) for c in children(e))

    def symbol(self, e: ET.Element, scope: str) -> str:
        out, first = [], True
        for c in children(e):
            if local(c.tag) == "Component" and not _informative(c):
                out.append(self.component(c, scope if first else ""))
                first = False
            else:
                out.append(self.node(c, scope))
        return "".join(out)

    def component(self, c: ET.Element, scope: str) -> str:
        """First component of a local access carries '#', of a global access
        quotes (Siemens: '#' and quotes are "ignored in XML" and added on import);
        BooleanAttribute HasQuotes / HasHash mark the same on later components."""
        name = c.get("Name", "")
        flags = {b.get("Name"): _true("".join(b.itertext())) for b in children(c, "BooleanAttribute")}
        hashed = flags.get("HasHash") or scope == "LocalVariable"
        quoted = flags.get("HasQuotes") or scope == "GlobalVariable"
        s = ("#" if hashed else "") + (f'"{name}"' if quoted else name)
        return s + self.run([k for k in children(c) if local(k.tag) != "BooleanAttribute"])

    def constant(self, c: ET.Element, scope: str) -> str:
        name = c.get("Name")
        if name:
            if scope == "LocalConstant":
                return "#" + name
            if scope == "GlobalConstant":
                return f'"{name}"'
            return name
        value, ctype, rest = "", "", []
        for k in children(c):
            kn = local(k.tag)
            if _informative(k):
                continue
            if kn == "ConstantValue":
                value = "".join(k.itertext()).strip()
            elif kn == "ConstantType":
                ctype = squash("".join(k.itertext()))
            else:
                rest.append(k)
        if any(ch.isspace() for ch in value) or "'" in value:
            value = "'" + value.replace("$", "$$").replace("'", "$'") + "'"   # keep inner whitespace significant
        if ctype and "#" not in value:
            value = f"{ctype}#{value}"
        return value + self.run(rest)

    def address(self, e: ET.Element) -> str:
        attrs = ",".join(f"{local(k)}={v}" for k, v in sorted(e.attrib.items()) if local(k) not in NOT_COMPARED)
        return f"%{local(e.tag)}({attrs})" + self.run(children(e))

    def instance(self, e: ET.Element) -> str:
        scope = e.get("Scope", "")
        return self.symbol(e, scope)

    def callinfo(self, e: ET.Element) -> str:
        name = e.get("Name", "")
        inst = child(e, "Instance")
        head = self.instance(inst) if inst is not None else (f'"{name}"' if name else "")
        if inst is not None and name:
            head += f"<{name}>"
        return head + self.run([k for k in children(e) if k is not inst])


class _Reader:
    def __init__(self, model: Model) -> None:
        self.model = model
        self.origin: dict = {}
        self.unknown: set = set()
        self.settings: set = set()
        self.versions: set = set()

    # ------------------------------------------------------------- objects

    def document(self, root: ET.Element, label: str) -> None:
        for c in children(root):
            n = local(c.tag)
            if n == "Engineering":
                if c.get("version"):
                    self.versions.add(c.get("version"))
            elif n == "DocumentInfo":
                st = text_of(child(c, "ExportSetting"))
                if st:
                    self.settings.add(st)
            elif n.startswith("SW.Blocks."):
                kind = n[len("SW.Blocks."):]
                if kind == "InterfaceSnapshot":
                    self.snapshot(c, label)
                else:
                    self.block(c, kind, label)
            elif n.startswith("SW.Types."):
                self.udt(c, n[len("SW.Types."):], label)
            elif n.startswith("SW.Tags."):
                self.tags(c, n[len("SW.Tags."):], label)
            elif n.startswith("SW."):
                name = self._name(c) or label
                ent = self._claim(f"Object:{n}:{name}", n, "metadata", label)
                ent.set("content", "metadata", sha(canon(c, drop_attrs=KEYS)), opaque=True,
                        note=f"SimaticML object type {n} is not modelled: compared by hash")
            else:
                self.model.entity("Export", "export", "metadata").set(
                    f"{label}:{n}", "metadata", sha(canon(c)), counted=False, opaque=True,
                    note="unmodelled document element: reported, not counted")

    def _name(self, obj: ET.Element) -> str:
        al = child(obj, "AttributeList")
        return text_of(child(al, "Name")) if al is not None else ""

    def _claim(self, key: str, kind: str, cls: str, label: str):
        if key in self.origin:
            raise ValueError(f"{key} is defined twice (in {self.origin[key]} and {label}); compare one export of each object")
        self.origin[key] = label
        return self.model.entity(key, kind, cls)

    def block(self, obj: ET.Element, kind: str, label: str) -> None:
        """Program blocks and data blocks (manual 6.4.2.13 "Exporting blocks")."""
        m = self.model
        name = self._name(obj) or f"?{label}"
        cls = BLOCK_CLASS.get(kind, "logic")
        key = f"Block:{name}"
        ent = self._claim(key, kind, cls, label)
        ent.set("BlockType", cls, kind)
        al = child(obj, "AttributeList")
        lang = ""
        khp = False
        tasking_seen = set()
        if al is not None:
            for c in children(al):
                n = local(c.tag)
                if n == "Name":
                    continue
                if n == "Interface":
                    self.interface(c, key, ent)
                    continue
                value = sha(canon(c, drop_attrs=KEYS)) if children(c) else "".join(c.itertext()).strip()
                opq = bool(children(c))
                if n == "ProgrammingLanguage":
                    lang = value
                if n == "IsKnowHowProtected":
                    khp = _true(value)
                if n in PROVENANCE:
                    ent.set(n, "metadata", value, counted=False, note="timestamp: reported, not counted")
                elif n in OB_TASKING:
                    tasking_seen.add(n)
                    ent.set(n, "tasking", value, opaque=opq)
                elif n in CODE_ATTRS:
                    ent.set(n, cls, value, opaque=opq)
                elif n in INTERFACE_ATTRS:
                    ent.set(n, "interface", value, opaque=opq)
                else:
                    ent.set(n, "metadata", value, opaque=opq, note="compared by hash" if opq else "")
        if lang.startswith("F_"):
            m.note(f"{key}: failsafe block (ProgrammingLanguage {lang}); compared like a standard block")
        if kind == "OB" and not (tasking_seen - {"SecondaryType"}):
            m.not_evaluated.append(f"{key}: no OB event class, priority or cycle attributes in the export. Siemens lists "
                                   "them as read-only, and read-only values are exported only with "
                                   "ExportOptions.WithReadOnly; OB tasking was not compared")
        ol = child(obj, "ObjectList")
        units_el, others = [], []
        if ol is not None:
            for c in children(ol):
                n = local(c.tag)
                if n == "MultilingualText":
                    comp = c.get("CompositionName", "Text")
                    ent.set(comp, DOC, _multilang(c))
                elif self._compile_unit(c):
                    units_el.append(c)
                else:
                    others.append(c)
        if khp:
            content = units_el + others
            m.note(f"{key}: know-how-protected block. Siemens: \"{KHP_QUOTE}\"")
            if content:
                h = sha("".join(_canon_net(c) for c in content))
                m.add_routine(Routine(f"{key}/Code", cls, f"{lang or kind} (know-how protected)", opaque_hash=h,
                                      opaque_doc_hash=h,
                                      opaque_reason="know-how-protected block content: compared by hash only"))
            else:
                m.not_evaluated.append(f"{key}: know-how protected and exported without its code (only the public "
                                       "interface is in the export); the block's logic was not compared")
            return
        for o in others:
            ent.set(f"ObjectList/{local(o.tag)}", cls, sha(canon(o, drop_attrs=KEYS)), opaque=True,
                    note=f"unmodelled object {local(o.tag)}: compared by hash")
        if kind in CODE_BLOCKS or units_el:
            self.networks(key, cls, lang or kind, units_el)

    @staticmethod
    def _compile_unit(e: ET.Element) -> bool:
        al = child(e, "AttributeList")
        return al is not None and (child(al, "NetworkSource") is not None or child(al, "ProgrammingLanguage") is not None)

    def networks(self, key: str, cls: str, block_lang: str, units_el: list) -> None:
        """Compile units in order: SCL lines, STL statements, other languages by hash."""
        units, comments, doc = [], [], {}
        for n, cu in enumerate(units_el, 1):
            al = child(cu, "AttributeList")
            lang = text_of(child(al, "ProgrammingLanguage")) or block_lang
            base = lang[2:] if lang.startswith("F_") else lang
            ns = child(al, "NetworkSource")
            other = [c for c in children(al) if local(c.tag) not in ("NetworkSource", "ProgrammingLanguage")]
            other += [c for c in children(cu) if local(c.tag) not in ("AttributeList", "ObjectList")]
            attrs = {"language": lang}
            if other:
                attrs["other"] = sha("".join(canon(c, drop_attrs=KEYS) for c in other))
            col = child(cu, "ObjectList")
            if col is not None:
                for t in children(col):
                    if local(t.tag) == "MultilingualText":
                        txt = _multilang(t)
                        if txt:
                            doc[f"network {n} {t.get('CompositionName', 'text').lower()}"] = txt
                    else:
                        attrs[f"ObjectList/{local(t.tag)}"] = sha(canon(t, drop_attrs=KEYS))
            body = children(ns) if ns is not None else []
            if not body:
                units.append(Unit(f"network {n}", f"{lang} (empty network)", f"{lang} network, empty", attrs=attrs))
                continue
            if base == "SCL":
                r = _Render()
                text = "".join(r.run(children(container)) for container in body)
                comments += r.comments
                self.unknown |= r.unknown
                added = 0
                for k, line in _lines(text):
                    norm = normalise_code(line)
                    if norm:
                        added += 1
                        units.append(Unit(f"network {n} line {k}", norm, line.strip(), attrs=dict(attrs)))
                if not added:
                    units.append(Unit(f"network {n}", f"{lang} (no statements)", f"{lang} network, no statements",
                                      attrs=attrs))
                continue
            stmts = [s for s in ns.iter() if isinstance(s.tag, str) and local(s.tag) == "StlStatement"] if base == "STL" else []
            if stmts:
                for k, s in enumerate(stmts, 1):
                    r = _Render()
                    code = r.run(children(s), sep=" ")
                    comments += r.comments
                    self.unknown |= r.unknown
                    toks = [t.get("Text", "") for t in children(s, "StlToken")]
                    # manual 7.6.4.5: EMPTY_LINE is an empty statement, COMMENT a comment-only one
                    if normalise_code(code) in ("EMPTY_LINE", "COMMENT") and len(toks) == 1:
                        continue
                    units.append(Unit(f"network {n} statement {k}", normalise_code(code), squash(code), attrs=dict(attrs)))
                continue
            h = sha("".join(_canon_net(c) for c in body))
            units.append(Unit(f"network {n}", f"{lang} sha256:{h}", f"{lang} network, content sha256 {h[:16]}",
                              attrs=attrs, opaque=True))
        self.model.add_routine(Routine(f"{key}/Networks", cls, block_lang, "", units, comments=tuple(c for c in comments if c),
                                       doc=doc))

    # ------------------------------------------------------------ interface

    def interface(self, iface: ET.Element, key: str, owner) -> None:
        """manual 6.4.2.1: Interface/Sections/Section @Name holding Member
        elements (Input, Output, InOut, Static, Temp, Constant, ...; 'None'
        holds the members of a UDT). Members are keyed Block:<name>/<section>.<member>."""
        for secs in children(iface, "Sections"):
            for sec in children(secs, "Section"):
                sname = sec.get("Name", "?")
                order = []
                for mem in children(sec, "Member"):
                    mname = mem.get("Name", "?")
                    order.append(mname)
                    self.member(mem, f"{key}/{mname}" if sname == "None" else f"{key}/{sname}.{mname}", sname)
                if order:
                    owner.set(f"MemberOrder:{sname}", "interface", ", ".join(order))

    def member(self, mem: ET.Element, path: str, section: str) -> None:
        m = self.model
        ent = m.entity(path, "member", "interface")
        for k, v in mem.attrib.items():
            if local(k) not in ("Name",) and local(k) not in KEYS:
                ent.set(local(k), "interface", v)
        note = "constant" if section == "Constant" else ""
        order = []
        for c in children(mem):
            n = local(c.tag)
            if n == "AttributeList":
                for a in children(c):
                    an = a.get("Name")
                    if an and not children(a):
                        ent.set(f"{local(a.tag)}:{an}", "interface", "".join(a.itertext()).strip())
                    else:
                        ent.set(f"AttributeList/{local(a.tag)}", "interface", sha(canon(a, drop_attrs=KEYS)), opaque=True)
            elif n == "StartValue":
                ent.set("StartValue", "value", "".join(c.itertext()).strip(), note=note)
            elif n == "Comment":
                ent.set("Comment", DOC, _multilang(c))
            elif n == "Member":
                order.append(c.get("Name", "?"))
                self.member(c, f"{path}.{c.get('Name', '?')}", section)
            elif n == "Sections":
                for sec in children(c, "Section"):
                    sn = sec.get("Name", "None")
                    sub = []
                    for mm in children(sec, "Member"):
                        sub.append(mm.get("Name", "?"))
                        self.member(mm, f"{path}.{mm.get('Name', '?')}" if sn == "None" else
                                    f"{path}.{sn}.{mm.get('Name', '?')}", section)
                    if sub:
                        ent.set(f"MemberOrder:{sn}", "interface", ", ".join(sub))
            elif n == "Subelement":
                p = c.get("Path", "?")
                for s in children(c):
                    sn = local(s.tag)
                    if sn == "StartValue":
                        ent.set(f"StartValue[{p}]", "value", "".join(s.itertext()).strip(), note=note)
                    elif sn == "Comment":
                        ent.set(f"Comment[{p}]", DOC, _multilang(s))
                    else:
                        ent.set(f"[{p}]/{sn}", "interface", squash("".join(s.itertext())) if not children(s)
                                else sha(canon(s, drop_attrs=KEYS)))
            elif n == "AssignedProDiagFB":
                ent.set(n, "metadata", text_of(c))
            else:
                ent.set(n, "interface", sha(canon(c, drop_attrs=KEYS)), opaque=True,
                        note=f"unmodelled element {n}: compared by hash")
        if order:
            ent.set("MemberOrder", "interface", ", ".join(order))

    # -------------------------------------------------- types, tags, snapshots

    def udt(self, obj: ET.Element, kind: str, label: str) -> None:
        """PLC data types (manual 6.4.2.27 / 6.4.2.30: SW.Types.PlcStruct)."""
        name = self._name(obj) or f"?{label}"
        key = f"Type:{name}"
        ent = self._claim(key, kind, "interface", label)
        al = child(obj, "AttributeList")
        if al is not None:
            for c in children(al):
                n = local(c.tag)
                if n == "Name":
                    continue
                if n == "Interface":
                    self.interface(c, key, ent)
                elif n in PROVENANCE:
                    ent.set(n, "metadata", "".join(c.itertext()).strip(), counted=False)
                else:
                    ent.set(n, "interface", sha(canon(c, drop_attrs=KEYS)) if children(c) else "".join(c.itertext()).strip(),
                            opaque=bool(children(c)))
        ol = child(obj, "ObjectList")
        if ol is not None:
            for c in children(ol):
                if local(c.tag) == "MultilingualText":
                    ent.set(c.get("CompositionName", "Text"), DOC, _multilang(c))
                else:
                    ent.set(f"ObjectList/{local(c.tag)}", "interface", sha(canon(c, drop_attrs=KEYS)), opaque=True)

    def tags(self, obj: ET.Element, kind: str, label: str) -> None:
        """PLC tag tables (manual 6.4.4: "One XML file is exported per PLC tag
        table") and individually exported tags or constants (6.4.4.3). Entries
        are SW.Tags.* objects with an AttributeList; the documented example
        (7.6.4.5) is SW.Tags.PlcTag with DataTypeName, LogicalAddress, Name."""
        entries = [e for e in obj.iter() if e is not obj and isinstance(e.tag, str)
                   and local(e.tag).startswith("SW.Tags.") and child(e, "AttributeList") is not None]
        if not entries:
            self.tag_entry(obj, local(obj.tag)[len("SW.Tags."):], "(individual export)", label)
            return
        name = self._name(obj) or f"?{label}"
        key = f"TagTable:{name}"
        ent = self._claim(key, kind, "interface", label)
        al = child(obj, "AttributeList")
        if al is not None:
            for c in children(al):
                if local(c.tag) != "Name":
                    ent.set(local(c.tag), "metadata", "".join(c.itertext()).strip() if not children(c)
                            else sha(canon(c, drop_attrs=KEYS)), opaque=bool(children(c)))
        for e in entries:
            self.tag_entry(e, local(e.tag)[len("SW.Tags."):], name, label)
        ol = child(obj, "ObjectList")
        if ol is not None:
            for c in children(ol):
                if local(c.tag) == "MultilingualText":
                    ent.set(c.get("CompositionName", "Text"), DOC, _multilang(c))

    def tag_entry(self, e: ET.Element, kind: str, table: str, label: str) -> None:
        name = self._name(e) or "?"
        ent = self._claim(f"TagTable:{table}/{kind}:{name}", "tag", "interface", label)
        al = child(e, "AttributeList")
        for c in children(al) if al is not None else []:
            n = local(c.tag)
            if n == "Name":
                continue
            value = sha(canon(c, drop_attrs=KEYS)) if children(c) else "".join(c.itertext()).strip()
            if n == "Value":
                ent.set(n, "value", value, note="tag-table constant")
            elif n in PROVENANCE:
                ent.set(n, "metadata", value, counted=False)
            else:
                ent.set(n, "interface", value, opaque=bool(children(c)))
        ol = child(e, "ObjectList")
        for c in children(ol) if ol is not None else []:
            if local(c.tag) == "MultilingualText":
                ent.set(c.get("CompositionName", "Text"), DOC, _multilang(c))
            else:
                ent.set(f"ObjectList/{local(c.tag)}", "interface", sha(canon(c, drop_attrs=KEYS)), opaque=True)

    def snapshot(self, obj: ET.Element, label: str) -> None:
        """manual 6.4.2.3 "Exporting DBs with snapshots": SnapshotValues/Value @Path @Type."""
        name = self._name(obj) or f"?{label}"
        ent = self._claim(f"Snapshot:{name}", "snapshot", "value", label)
        for v in obj.iter():
            if isinstance(v.tag, str) and local(v.tag) == "Value" and v.get("Path"):
                ent.set(f"Value:{v.get('Path')}", "value", f"{''.join(v.itertext()).strip()} ({v.get('Type', '?')})")
        al = child(obj, "AttributeList")
        for c in children(al) if al is not None else []:
            if local(c.tag) in ("SnapshotDate", "StructureModified"):
                ent.set(local(c.tag), "metadata", text_of(c), counted=False)
        self.model.note("interface snapshot values are actual values captured at snapshot time; differences are "
                        "expected for live data and need review")

    def finish(self) -> None:
        m = self.model
        exp = m.entity("Export", "export", "metadata")
        if self.versions:
            exp.set("Engineering version", "metadata", ", ".join(sorted(self.versions)), counted=False)
        if self.settings:
            exp.set("ExportSetting", "metadata", ", ".join(sorted(self.settings)), counted=False)
            m.note(f"DocumentInfo ExportSetting {', '.join(sorted(self.settings))}: which attributes an export holds "
                   "depends on the ExportOptions used (manual 6.1.5); export both sides with the same options")
        if len(self.settings) > 1:
            m.note("files in this export were written with different ExportSetting values")
        if self.unknown:
            m.note("SCL/STL elements outside the documentation read were compared as canonical XML: "
                   + ", ".join(sorted(self.unknown)))


def parse(root: ET.Element, *, path: str, sha256: str, size: int) -> Model:
    if not is_simaticml(root):
        raise ValueError(f"not a SimaticML export (root {root.tag!r})")
    model = Model(fmt=FORMAT, path=path, sha256=sha256, size=size, scope="SimaticML file")
    r = _Reader(model)
    _guarded(r.document, root, os.path.basename(path))
    r.finish()
    return model


def _guarded(fn, *args) -> None:
    """Token rendering recurses per XML level; safexml caps nesting at 256, but
    refuse cleanly rather than crash if a file still exhausts the stack."""
    try:
        fn(*args)
    except RecursionError:
        raise UnsafeInputError(f"{args[-1]}: elements nested too deeply to compare") from None


def load_directory(path: str, *, max_bytes: int = MAX_BYTES_DEFAULT, **limits) -> Model:
    """A directory of SimaticML files (TIA Portal Openness writes one file per
    block, UDT or tag table). Every .xml file is screened by safexml; any
    refused file refuses the directory. The size cap applies to the total."""
    files, skipped, ignored = [], [], []
    for dirpath, dirnames, fnames in os.walk(path, followlinks=False):
        dirnames.sort()
        for f in sorted(fnames):
            full = os.path.join(dirpath, f)
            rel = os.path.relpath(full, path).replace(os.sep, "/")
            if os.path.islink(full):
                skipped.append(rel)
            elif f.lower().endswith(".xml"):
                files.append((rel, full))
            else:
                ignored.append(rel)
            if len(files) > MAX_FILES:
                raise UnsafeInputError(f"{path}: more than {MAX_FILES} XML files")
    if not files:
        raise InputFormatError(f"{path}: directory holds no .xml files")
    total = 0
    for _, full in files:
        total += os.path.getsize(full)
        if total > max_bytes:
            raise UnsafeInputError(f"{path}: XML files total more than the {max_bytes}-byte limit")
    model = Model(fmt=FORMAT, path=path, sha256="", size=total, scope="SimaticML directory")
    reader = _Reader(model)
    manifest = []
    for rel, full in files:
        doc = load(full, max_bytes=max_bytes, **limits)
        manifest.append(f"{rel}\0{doc.sha256}")
        fent = model.entity(f"File:{rel}", "file", "metadata")
        fent.set("sha256", "metadata", doc.sha256, counted=False, note="file hash: reported, not counted")
        if not is_simaticml(doc.root):
            model.not_evaluated.append(f"{rel}: not a SimaticML PLC export (root element {local(doc.root.tag)!r}); not compared")
            continue
        try:
            _guarded(reader.document, doc.root, rel)
        except UnsafeInputError:
            raise
        except ValueError as exc:
            raise InputFormatError(f"{path}: {exc}") from None
    reader.finish()
    model.sha256 = hashlib.sha256("\n".join(manifest).encode("utf-8")).hexdigest()
    model.note(f"directory of {len(files)} XML file(s); the SHA-256 shown is of the sorted list of relative paths and "
               "per-file SHA-256 values (each file's hash is listed under File: entries)")
    if skipped:
        model.not_evaluated.append("symbolic links not followed: " + ", ".join(skipped[:20])
                                   + (f" (+{len(skipped) - 20} more)" if len(skipped) > 20 else ""))
    if ignored:
        model.not_evaluated.append("files without an .xml extension not read: " + ", ".join(ignored[:20])
                                   + (f" (+{len(ignored) - 20} more)" if len(ignored) > 20 else ""))
    return model
