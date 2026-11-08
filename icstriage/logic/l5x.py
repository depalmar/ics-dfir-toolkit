"""Read a Rockwell Logix 5000 L5X export into the normalised model.

Element and attribute names follow Rockwell's Logix 5000 Controllers
Import/Export Reference Manual, publication 1756-RM014D-EN-P (September
2025), read directly from literature.rockwellautomation.com. Chapter and
printed-page references are given next to each reader below and in
docs/logic-compare.md, which also lists what is treated opaquely.

Nothing is inferred about instruction semantics: rung text is compared as
the neutral text Rockwell exports, after whitespace normalisation.
"""
from __future__ import annotations

import xml.etree.ElementTree as ET

from .model import (DOC, FieldVal, Model, Routine, Unit, attrs_string, canon, child, children, local,
                    normalise_code, sha, squash, text_of, text_units)

FORMAT = "L5X"
ROOT = "RSLogix5000Content"

# RM014 ch.2 Controller attributes (p.57) - grouping is this tool's.
CONTROLLER_MODULE = {"ProcessorType", "MajorRev", "MinorRev"}
CONTROLLER_TASKING = {"PowerLossProgram", "MajorFaultProgram", "SFCExecutionControl", "SFCRestartPosition", "SFCLastScan"}
# Timestamps, workstation-specific paths and UI language: reported, never counted.
CONTROLLER_UNCOUNTED = {"ProjectCreationDate", "LastModifiedDate", "CommPath", "CommDriver", "CurrentProjectLanguage", "Use"}
# RM014 ch.5 Add-On Instruction attributes (p.98): edit provenance, reported only.
AOI_UNCOUNTED = {"CreatedDate", "CreatedBy", "EditedDate", "EditedBy", "SoftwareRevision", "SignatureTimestamp", "Use"}
AOI_DOC = {"Description", "RevisionNote", "AdditionalHelpText"}
PROGRAM_LOGIC = {"TestEdits"}
PROGRAM_META = {"EquipmentId", "RecipePhaseNames", "Revision", "RevisionExtension", "TrackingGroups", "PermissionSet"}
META_ATTRS = {"TrackingGroups", "PermissionSet"}
# Project documentation per RM014 p.51 (descriptions, rung comments, FBD/SFC
# text boxes) plus the Attachment blocks that tie text boxes to elements (p.243).
DOC_ELEMENTS = frozenset({"Description", "Comment", "Comments", "TextBox", "Attachment", "RevisionNote"})
ENCRYPTED = {"EncryptionInfo", "EncryptedContent", "EncryptedSegments", "EncryptedAOIContent"}


def _flatten_decorated(data: ET.Element) -> tuple[str, str]:
    """Decorated data (RM014 'Data formats', p.42) to 'path=value' lines.
    Paths come from Name and Index attributes, values from Value attributes or
    element text; Radix is display style and ignored. ForceValue attributes
    (decorated force values) are returned separately."""
    vals: list = []
    forces: list = []

    def walk(e: ET.Element, prefix: str) -> None:
        name, idx = e.get("Name"), e.get("Index")
        p = prefix
        if name:
            p = f"{prefix}.{name}" if prefix else name
        elif idx:
            p = f"{prefix}{idx}"
        if "Value" in e.attrib:
            vals.append(f"{p or 'value'}={e.get('Value')}")
        if "ForceValue" in e.attrib:
            forces.append(f"{p or 'value'}={e.get('ForceValue')}")
        txt = (e.text or "").strip()
        if txt:
            vals.append(f"{p or 'value'}={txt}")
        for c in children(e):
            walk(c, p)

    for c in children(data):
        walk(c, "")
    txt = (data.text or "").strip()
    if txt:
        vals.insert(0, f"value={txt}")
    return "\n".join(vals), "\n".join(forces)


def _data_formats(elems: list) -> tuple[dict, dict]:
    """Data / DefaultData / ForceData elements -> ({format: value}, {format: force})."""
    vals: dict = {}
    forces: dict = {}
    for d in elems:
        tag = local(d.tag)
        fmt = d.get("Format") or "raw"
        if fmt == "raw":
            v = squash("".join(d.itertext())).upper()
        elif fmt == "L5K":
            v = squash("".join(d.itertext()))
        elif fmt == "Decorated":
            v, f = _flatten_decorated(d)
            if f and tag != "ForceData":
                forces["Decorated"] = f
        elif fmt == "String":
            v = "".join(d.itertext()).strip()
        else:
            v = canon(d)
        if tag == "ForceData":
            if v:
                forces[fmt] = v
        elif v != "":
            vals[fmt] = v
    return vals, forces


def _taglike(model: Model, elem: ET.Element, path: str, kind: str, cls: str, value_cls: str) -> None:
    """Tags (RM014 ch.6, p.122), AOI parameters (p.101) and AOI local tags
    (p.109) share one shape: attributes, documentation children, Min/Max
    children and Data / DefaultData / ForceData."""
    ent = model.entity(path, kind, cls)
    for k, v in elem.attrib.items():
        k = local(k)
        if k in ("Name", "Use"):
            continue
        if k == "Radix":
            ent.set("Radix", DOC, v, note="display style only")
        elif k in META_ATTRS:
            ent.set(k, "metadata", v)
        else:
            ent.set(k, cls, v)
    data_elems = []
    for c in children(elem):
        name = local(c.tag)
        if name == "Description":
            ent.set("Description", DOC, text_of(c))
        elif name in ("Comments", "EngineeringUnits", "State0s", "State1s"):
            for item in children(c):
                ent.set(f"{local(item.tag)}[{item.get('Operand', '')}]", DOC, text_of(item))
        elif name in ("EngineeringUnit", "State0", "State1"):
            ent.set(name, DOC, text_of(c))
        elif name in ("Mins", "Maxes"):
            for item in children(c):
                ent.set(f"{local(item.tag)}[{item.get('Operand', '')}]", cls, text_of(item))
        elif name in ("ConsumeInfo", "ProduceInfo"):
            ent.set(name, cls, attrs_string(c))
        elif name in ("Data", "DefaultData", "ForceData"):
            data_elems.append(c)
        else:
            ent.set(name, cls, sha(canon(c)), opaque=True, note=f"unmodelled element {name}: compared by hash")
    vals, forces = _data_formats(data_elems)
    note = "constant tag" if elem.get("Constant", "").lower() in ("true", "1", "yes") else ""
    label = "DefaultData" if any(local(d.tag) == "DefaultData" for d in data_elems) else "Value"
    if vals:
        ent.set(label, value_cls, vals, note=note)
    if forces:
        ent.set("Force", value_cls, forces, note="force data")


def _datatype(model: Model, dt: ET.Element) -> None:
    """RM014 ch.3 Datatype component (p.72)."""
    name = dt.get("Name", "?")
    ent = model.entity(f"DataType:{name}", "datatype", "interface")
    for k, v in dt.attrib.items():
        if local(k) not in ("Name", "Use"):
            ent.set(local(k), "interface", v)
    for c in children(dt):
        cname = local(c.tag)
        if cname in ("Description", "EngineeringUnit"):
            ent.set(cname, DOC, text_of(c))
        elif cname == "Members":
            order = []
            for m in children(c, "Member"):
                mname = m.get("Name", "?")
                order.append(mname)
                ent.set(f"Member:{mname}", "interface", attrs_string(m, skip=("Name", "Radix")))
                ent.set(f"Member:{mname}/Radix", DOC, m.get("Radix", ""), note="display style only")
                for d in children(m):
                    dname = local(d.tag)
                    if dname in ("Description", "EngineeringUnit", "State0", "State1"):
                        ent.set(f"Member:{mname}/{dname}", DOC, text_of(d))
                    else:
                        ent.set(f"Member:{mname}/{dname}", "interface", sha(canon(d)), opaque=True)
            ent.set("MemberOrder", "interface", ", ".join(order))
        else:
            ent.set(cname, "interface", sha(canon(c)), opaque=True, note=f"unmodelled element {cname}: compared by hash")


def _module(model: Model, mod: ET.Element) -> None:
    """RM014 ch.4 Module component (p.79). Configuration data is 'module';
    I/O tag data under connections is a snapshot of process values ('value')."""
    name = mod.get("Name", "?")
    ent = model.entity(f"Module:{name}", "module", "module")
    for k, v in mod.attrib.items():
        if local(k) not in ("Name", "Use"):
            ent.set(local(k), "module", v)

    def data_holder(holder: ET.Element, label: str, cls: str) -> None:
        vals, forces = _data_formats([d for d in children(holder) if local(d.tag) in ("Data", "ForceData")])
        ent.set(label, cls, vals)
        if forces:
            ent.set(f"{label}/Force", "value", forces, note="force data")
        ent.set(f"{label}/attributes", "module", attrs_string(holder))
        for d in children(holder):
            dn = local(d.tag)
            if dn in ("Comments", "Description"):
                ent.set(f"{label}/{dn}", DOC, text_of(d))

    for c in children(mod):
        cname = local(c.tag)
        if cname == "Description":
            ent.set("Description", DOC, text_of(c))
        elif cname == "EKey":
            ent.set("EKey", "module", attrs_string(c))
        elif cname == "Ports":
            for p in children(c, "Port"):
                ent.set(f"Port:{p.get('Id', '?')}", "module", canon(p, drop=DOC_ELEMENTS, drop_attrs=frozenset({"Id"})))
        elif cname in ("ConfigTag", "ConfigData"):
            data_holder(c, "ConfigData", "module")
        elif cname == "Communications":
            for cc in children(c):
                ccn = local(cc.tag)
                if ccn in ("ConfigTag", "ConfigData"):
                    data_holder(cc, "ConfigData", "module")
                elif ccn == "Connections":
                    for conn in children(cc, "Connection"):
                        cn = conn.get("Name", "?")
                        ent.set(f"Connection:{cn}", "module", attrs_string(conn, skip=("Name",)))
                        for io in children(conn):
                            ion = local(io.tag)
                            if ion in ("InputTag", "OutputTag"):
                                data_holder(io, f"Connection:{cn}/{ion}", "value")
                            elif ion not in DOC_ELEMENTS:
                                ent.set(f"Connection:{cn}/{ion}", "module", sha(canon(io)), opaque=True)
                else:
                    ent.set(f"Communications/{ccn}", "module", sha(canon(cc, drop=DOC_ELEMENTS)), opaque=True)
        else:
            ent.set(cname, "module", sha(canon(c, drop=DOC_ELEMENTS)), opaque=True,
                    note=f"{cname}: compared by hash")


def _routine(model: Model, r: ET.Element, prefix: str, cls: str) -> None:
    """RM014 ch.8 ladder (p.206), ch.9 FBD (p.223), ch.10 SFC (p.256), ch.11
    structured text (p.285). FBD and SFC are compared by content hash."""
    name = r.get("Name", "?")
    rtype = r.get("Type", "")
    base = f"{prefix}Routine:{name}"
    attrs = {}
    for k, v in r.attrib.items():
        k = local(k)
        if k in ("Name", "Type", "Use"):
            continue
        attrs[k] = FieldVal("metadata" if k in META_ATTRS else cls, v)
    doc = {}
    contents = []
    encrypted = []
    for c in children(r):
        cname = local(c.tag)
        if cname == "Description":
            doc["Description"] = text_of(c)
        elif cname in ENCRYPTED:
            encrypted.append(c)
        else:
            contents.append(c)

    if encrypted:
        h = sha("".join(canon(e) for e in encrypted))
        model.add_routine(Routine(base, cls, rtype or "?", opaque_hash=h, opaque_doc_hash=h,
                                  opaque_reason="source-protected (locked) content: compared by hash only",
                                  attrs=attrs, doc=doc))
        model.note(f"{base}: source-protected content compared by hash only; what changed inside cannot be shown")
        return
    if not contents:
        model.add_routine(Routine(base, cls, rtype or "?", attrs=attrs, doc=doc))
        return
    edits = [c.get("OnlineEditType") for c in contents if c.get("OnlineEditType")]
    if edits:
        model.note(f"{base}: export carries online edits ({', '.join(sorted(set(edits)))}); each edit state is compared separately")
    for c in contents:
        cname = local(c.tag)
        edit = c.get("OnlineEditType") or ""
        path = base if edit in ("", "Original") else f"{base}[{edit}]"
        if cname == "RLLContent":
            units = []
            odd = set()
            for rung in children(c, "Rung"):
                text_el, comment_el = child(rung, "Text"), child(rung, "Comment")
                raw = "".join(text_el.itertext()) if text_el is not None else ""
                rtype_attr = rung.get("Type", "N")
                if rtype_attr != "N":
                    odd.add(rtype_attr)
                extra = [e for e in children(rung) if local(e.tag) not in ("Text", "Comment")]
                u_attrs = {"Type": rtype_attr}
                if extra:
                    u_attrs["other"] = sha("".join(canon(e) for e in extra))
                units.append(Unit(label=rung.get("Number", str(len(units))), code=normalise_code(raw),
                                  raw=squash(raw), doc=text_of(comment_el), attrs=u_attrs))
            if odd:
                model.note(f"{path}: rungs carry online-edit markers (Type {', '.join(sorted(odd))}); "
                           "the export holds pending or test edits, not only the original logic")
            model.add_routine(Routine(path, cls, "RLL", "rung", units, attrs=attrs, doc=doc))
        elif cname == "STContent":
            lines = []
            for ln in children(c, "Line"):
                # whitespace around the CDATA is file formatting (RM014 p.285 example)
                lines.append((ln.get("Number", str(len(lines))), "".join(ln.itertext()).strip()))
            if all(lbl.isdigit() for lbl, _ in lines):
                lines.sort(key=lambda t: int(t[0]))
            units, comments = text_units(lines, comment_syntax=True)
            model.add_routine(Routine(path, cls, "ST", "line", units, comments=comments, attrs=attrs, doc=doc))
        else:
            lang = {"FBDContent": "FBD", "SFCContent": "SFC"}.get(cname, rtype or cname)
            model.add_routine(Routine(path, cls, lang, opaque_hash=sha(canon(c)),
                                      opaque_doc_hash=sha(canon(c, drop=DOC_ELEMENTS)),
                                      opaque_reason=f"{lang} content compared by hash (layout edits also change it)",
                                      attrs=attrs, doc=doc))


def _encoded_routine(model: Model, e: ET.Element, prefix: str, cls: str) -> None:
    """RM014 'Encoded/Unencoded routines' (p.201): source-protected routines
    export as EncodedData with EncodedType="Routine"; the payload is encrypted."""
    name = e.get("Name", "?")
    path = f"{prefix}Routine:{name}"
    desc = child(e, "Description")
    h = sha(canon(e, drop=frozenset({"Description"})))
    model.add_routine(Routine(path, cls, f"{e.get('Type', '?')} (encoded)", opaque_hash=h, opaque_doc_hash=h,
                              opaque_reason="source-protected (encoded) routine: compared by hash only",
                              doc={"Description": text_of(desc)} if desc is not None else {}))
    model.note(f"{path}: source-protected routine compared by hash only. 1756-RM014 does not say whether "
               "two exports of unchanged protected content produce identical encoded text")


def _aoi(model: Model, aoi: ET.Element, encoded: bool) -> None:
    """RM014 ch.5 Add-On Instruction component (p.96), including encoded AOIs (p.111)."""
    name = aoi.get("Name", "?")
    prefix = f"AOI:{name}"
    ent = model.entity(prefix, "aoi", "aoi")
    ent.set("Protection", "aoi", "encoded" if encoded else "none")
    for k, v in aoi.attrib.items():
        k = local(k)
        if k in ("Name", "EncodedType"):
            continue
        if k in AOI_UNCOUNTED:
            ent.set(k, "metadata", v, counted=False)
        else:
            ent.set(k, "aoi", v)
    for kind, holder, item in (("aoi-parameter", "Parameters", "Parameter"), ("aoi-localtag", "LocalTags", "LocalTag")):
        h = child(aoi, holder)
        if h is not None:
            order = []
            for p in children(h, item):
                order.append(p.get("Name", "?"))
                _taglike(model, p, f"{prefix}/{item}:{p.get('Name', '?')}", kind, "aoi", "aoi")
            ent.set(f"{item}Order", "aoi", ", ".join(order))
    for c in children(aoi):
        cname = local(c.tag)
        if cname in ("Parameters", "LocalTags"):
            continue
        if cname in AOI_DOC:
            ent.set(cname, DOC, text_of(c))
        elif cname == "SignatureHistory":
            entries = children(c, "HistoryEntry")
            ent.set("SignatureHistory", "metadata", " | ".join(attrs_string(h) for h in entries))
            for i, h in enumerate(entries):
                ent.set(f"SignatureHistory[{i}]/Description", DOC, text_of(child(h, "Description")))
        elif not encoded and cname in ("Routines", "ScanModeRoutine"):
            found = False
            for r in c.iter():
                if isinstance(r.tag, str) and local(r.tag) == "Routine":
                    found = True
                    _routine(model, r, f"{prefix}/", "aoi")
            if not found and cname == "ScanModeRoutine":
                ent.set(cname, "aoi", sha(canon(c)), opaque=True)
        elif not encoded and cname in ENCRYPTED:
            ent.set(cname, "aoi", sha(canon(c)), opaque=True, note="source-protected content: compared by hash only")
            model.note(f"{prefix}: source-protected content compared by hash only")
        elif not encoded:
            ent.set(cname, "aoi", sha(canon(c, drop=DOC_ELEMENTS)), opaque=True,
                    note=f"unmodelled element {cname}: compared by hash")
    if encoded:
        drop = frozenset(AOI_DOC | {"SignatureHistory", "Parameters", "LocalTags"})
        ent.set("EncodedContent", "aoi", sha(canon(aoi, drop=drop, drop_attrs=frozenset(AOI_UNCOUNTED | {"Name"}))),
                opaque=True, note="encoded Add-On Instruction body: compared by hash only")
        model.note(f"{prefix}: encoded (sealed or source-protected) Add-On Instruction body compared by hash only. "
                   "1756-RM014 does not say whether two exports of an unchanged protected AOI produce identical encoded text")


def _program(model: Model, prog: ET.Element) -> None:
    """RM014 ch.7 Program component (p.194)."""
    name = prog.get("Name", "?")
    prefix = f"Program:{name}"
    ent = model.entity(prefix, "program", "logic")
    for k, v in prog.attrib.items():
        k = local(k)
        if k in ("Name", "Use"):
            continue
        if k in PROGRAM_LOGIC:
            ent.set(k, "logic", v)
        elif k in PROGRAM_META:
            ent.set(k, "metadata", v)
        else:
            ent.set(k, "tasking", v)
    for c in children(prog):
        cname = local(c.tag)
        if cname in ("Description", "RevisionNote"):
            ent.set(cname, DOC, text_of(c))
        elif cname == "Tags":
            for t in children(c, "Tag"):
                _taglike(model, t, f"{prefix}/Tag:{t.get('Name', '?')}", "tag", "interface", "value")
        elif cname == "Routines":
            for r in children(c):
                rn = local(r.tag)
                if rn == "Routine":
                    _routine(model, r, f"{prefix}/", "logic")
                elif rn == "EncodedData":
                    _encoded_routine(model, r, f"{prefix}/", "logic")
                else:
                    ent.set(f"Routines/{rn}", "logic", sha(canon(r)), opaque=True)
        elif cname == "EncodedData":
            _encoded_routine(model, c, f"{prefix}/", "logic")
        elif cname == "ChildPrograms":
            ent.set("ChildPrograms", "metadata", ", ".join(cp.get("Name", "?") for cp in children(c)))
        else:
            ent.set(cname, "logic", sha(canon(c, drop=DOC_ELEMENTS)), opaque=True,
                    note=f"unmodelled element {cname}: compared by hash")


def _task(model: Model, task: ET.Element) -> None:
    """RM014 ch.12 Task component (p.312). Scheduled programs run in the
    order listed, so the list is compared in order."""
    name = task.get("Name", "?")
    ent = model.entity(f"Task:{name}", "task", "tasking")
    for k, v in task.attrib.items():
        if local(k) not in ("Name", "Use"):
            ent.set(local(k), "tasking", v)
    for c in children(task):
        cname = local(c.tag)
        if cname == "Description":
            ent.set("Description", DOC, text_of(c))
        elif cname == "EventInfo":
            for k, v in c.attrib.items():
                ent.set(f"EventInfo/{local(k)}", "tasking", v)
        elif cname == "ScheduledPrograms":
            ent.set("ScheduledPrograms", "tasking", " > ".join(p.get("Name", "?") for p in children(c, "ScheduledProgram")))
        else:
            ent.set(cname, "tasking", sha(canon(c, drop=DOC_ELEMENTS)), opaque=True)


def parse(root: ET.Element, *, path: str, sha256: str, size: int) -> Model:
    if local(root.tag) != ROOT:
        raise ValueError(f"not an L5X export (root element {local(root.tag)!r})")
    model = Model(fmt=FORMAT, path=path, sha256=sha256, size=size)
    exp = model.entity("Export", "export", "metadata")
    for k, v in root.attrib.items():
        exp.set(local(k), "metadata", v, counted=False)
    model.scope = root.get("TargetType", "")
    if model.scope and model.scope != "Controller":
        model.note(f"partial export (TargetType={model.scope}, TargetName={root.get('TargetName', '')}): "
                   "only the exported component and its context are present")

    ctrl = child(root, "Controller")
    if ctrl is None:
        raise ValueError("L5X export has no Controller element")
    cent = model.entity("Controller", "controller", "metadata")
    for k, v in ctrl.attrib.items():
        k = local(k)
        if k in CONTROLLER_MODULE:
            cent.set(k, "module", v)
        elif k in CONTROLLER_TASKING:
            cent.set(k, "tasking", v)
        elif k in CONTROLLER_UNCOUNTED:
            cent.set(k, "metadata", v, counted=False)
        else:
            cent.set(k, "metadata", v)
    for c in children(ctrl):
        cname = local(c.tag)
        if cname == "Description":
            cent.set("Description", DOC, text_of(c))
        elif cname in ("RedundancyInfo", "Security", "SafetyInfo"):
            for k, v in c.attrib.items():
                cent.set(f"{cname}/{local(k)}", "metadata", v)
            for sub in children(c):
                sn = local(sub.tag)
                if sn == "SafetyTagMap":
                    cent.set(f"{cname}/SafetyTagMap", "metadata", text_of(sub))
                else:
                    cent.set(f"{cname}/{sn}", "metadata", sha(canon(sub)), opaque=True)
        elif cname == "DataTypes":
            for dt in children(c, "DataType"):
                _datatype(model, dt)
        elif cname == "Modules":
            for m in children(c, "Module"):
                _module(model, m)
        elif cname == "AddOnInstructionDefinitions":
            for a in children(c):
                an = local(a.tag)
                if an == "AddOnInstructionDefinition":
                    _aoi(model, a, encoded=False)
                elif an == "EncodedData":
                    _aoi(model, a, encoded=True)
        elif cname == "Tags":
            for t in children(c, "Tag"):
                _taglike(model, t, f"Tag:{t.get('Name', '?')}", "tag", "interface", "value")
        elif cname == "Programs":
            for p in children(c, "Program"):
                _program(model, p)
        elif cname == "Tasks":
            for t in children(c, "Task"):
                _task(model, t)
        elif cname == "ParameterConnections":
            cent.set(cname, "interface", sha(canon(c)), opaque=True, note="program parameter connections: compared by hash")
        elif cname == "QuickWatchLists":
            cent.set(cname, "metadata", sha(canon(c)), counted=False, opaque=True,
                     note="engineering watch lists: reported, not counted")
        else:
            cent.set(cname, "metadata", sha(canon(c, drop=DOC_ELEMENTS)), opaque=True,
                     note=f"{cname}: compared by hash")
    return model
