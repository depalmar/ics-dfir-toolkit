"""Read a PLCopen TC6 XML export (IEC 61131-3 exchange format) into the model.

Element and attribute names follow the PLCopen schema TC6_XML_V201.xsd
(namespace http://www.plcopen.org/xml/tc6_0201), read from the schema
documentation PLCopen publishes on plcopen.org. Matching is by local name so
the earlier tc6_0200 namespace reads the same way where the names agree.

Read: fileHeader and contentHeader attributes; types/dataTypes/dataType
(baseType, initialValue); types/pous/pou (@pouType function | functionBlock |
program) with interface variable lists, body, actions and transitions;
instances/configurations/configuration/resource/task (@interval, @priority,
@single) and pouInstance (@name, @typeName).

Opaque (compared by hash): FBD, LD and SFC bodies, vendor addData, accessVars
and configVars lists, and anything the schema allows that is not listed above.

Function and function-block POUs are the IEC 61131-3 reusable code modules,
so changes inside them are classed 'aoi' (reusable module), like Rockwell
Add-On Instructions.
"""
from __future__ import annotations

import xml.etree.ElementTree as ET

from .model import DOC, FieldVal, Model, Routine, canon, child, children, local, sha, text_of, text_units

FORMAT = "PLCopen TC6 XML"
NS_PREFIX = "http://www.plcopen.org/xml/tc6"
VAR_LISTS = ("returnType", "inputVars", "outputVars", "inOutVars", "localVars", "tempVars", "externalVars",
             "globalVars", "accessVars")
LIST_FLAGS = ("constant", "retain", "nonretain", "persistent", "nonpersistent")
# commonObjects/comment is a free-text comment box; documentation is formattedText.
DOC_ELEMENTS = frozenset({"documentation", "comment"})
UNCOUNTED_HEADER = {"creationDateTime", "modificationDateTime", "productName", "productVersion",
                    "productRelease", "companyName", "companyURL", "author"}


def is_plcopen(root: ET.Element) -> bool:
    return local(root.tag) == "project" and root.tag.startswith("{" + NS_PREFIX)


def render_type(t) -> str:
    """dataType (schema: elementaryTypes / derivedTypes) as IEC-like text."""
    if t is None:
        return ""
    kids = children(t)
    if not kids:
        return ""
    k = kids[0]
    n = local(k.tag)
    if n in ("string", "wstring"):
        return f"{n.upper()}[{k.get('length')}]" if k.get("length") else n.upper()
    if n == "derived":
        return k.get("name", "?")
    if n == "array":
        dims = ", ".join(f"{d.get('lower', '?')}..{d.get('upper', '?')}" for d in children(k, "dimension"))
        return f"ARRAY[{dims}] OF {render_type(child(k, 'baseType'))}"
    if n == "pointer":
        return f"POINTER TO {render_type(child(k, 'baseType'))}"
    if n in ("subrangeSigned", "subrangeUnsigned"):
        rng = child(k, "range")
        lo, hi = (rng.get("lower", "?"), rng.get("upper", "?")) if rng is not None else ("?", "?")
        return f"{render_type(child(k, 'baseType'))}({lo}..{hi})"
    if n == "enum":
        vals = child(k, "values")
        items = [f"{v.get('name')}={v.get('value')}" if v.get("value") else str(v.get("name"))
                 for v in (children(vals, "value") if vals is not None else [])]
        base = render_type(child(k, "baseType"))
        return f"ENUM({', '.join(items)})" + (f" OF {base}" if base else "")
    if n == "struct":
        members = [f"{v.get('name')}: {render_type(child(v, 'type'))}" for v in children(k, "variable")]
        return f"STRUCT({'; '.join(members)})"
    if not children(k) and not k.attrib:
        return n
    return canon(k)


def render_value(v) -> str:
    """value (schema complexType 'value'): simpleValue@value, arrayValue with
    @repetitionValue, structValue with @member."""
    if v is None:
        return ""
    for k in children(v):
        n = local(k.tag)
        if n == "simpleValue":
            return k.get("value", "")
        if n == "arrayValue":
            items = []
            for item in children(k, "value"):
                rep = item.get("repetitionValue", "1")
                items.append(f"{rep}({render_value(item)})" if rep != "1" else render_value(item))
            return "[" + ", ".join(items) + "]"
        if n == "structValue":
            return "(" + ", ".join(f"{item.get('member')} := {render_value(item)}" for item in children(k, "value")) + ")"
    return canon(v)


def _variables(model: Model, holder: ET.Element, prefix: str, cls: str, owner) -> None:
    """Interface or global variable lists (schema varList / varListPlain).
    A section may appear in several lists (e.g. localVars and localVars
    constant="true"); declaration order is kept across them."""
    orders: dict = {}
    for vl in children(holder):
        section = local(vl.tag)
        if section not in VAR_LISTS:
            continue
        if section == "returnType":
            owner.set("returnType", cls, render_type(vl))
            continue
        if section == "accessVars" and not children(vl, "variable"):
            owner.set(section, cls, sha(canon(vl)), opaque=True)
            continue
        flags = ", ".join(f for f in LIST_FLAGS if vl.get(f, "false").lower() in ("true", "1"))
        order = orders.setdefault(section, [])
        for var in children(vl, "variable"):
            vname = var.get("name", "?")
            order.append(vname)
            ent = model.entity(f"{prefix}/Var:{vname}", "variable", cls)
            ent.set("section", cls, section)
            ent.set("list", cls, vl.get("name", ""))
            ent.set("flags", cls, flags)
            ent.set("address", cls, var.get("address", ""))
            ent.set("type", cls, render_type(child(var, "type")))
            value_cls = "aoi" if cls == "aoi" else "value"
            ent.set("initialValue", value_cls, render_value(child(var, "initialValue")),
                    note="constant" if "constant" in flags else "")
            ent.set("documentation", DOC, text_of(child(var, "documentation")))
            ad = child(var, "addData")
            if ad is not None:
                ent.set("addData", cls, sha(canon(ad)), opaque=True, note="vendor addData: compared by hash")
        doc = child(vl, "documentation")
        if doc is not None:
            owner.set(f"{section}/documentation", DOC, text_of(doc))
    for section, order in orders.items():
        owner.set(f"VarOrder:{section}", cls, ", ".join(order))


def _body(model: Model, body: ET.Element, path: str, cls: str) -> None:
    """body: one of IL, ST (formattedText) or FBD, LD, SFC (graphical)."""
    doc = {}
    attrs = {}
    d = child(body, "documentation")
    if d is not None:
        doc["documentation"] = text_of(d)
    lang_el = None
    for c in children(body):
        n = local(c.tag)
        if n in ("IL", "ST", "FBD", "LD", "SFC"):
            lang_el = c
        elif n == "addData":
            attrs["addData"] = FieldVal(cls, sha(canon(c)), opaque=True, note="vendor addData: compared by hash")
    if lang_el is None:
        model.add_routine(Routine(path, cls, "?", attrs=attrs, doc=doc))
        return
    lang = local(lang_el.tag)
    if lang in ("IL", "ST"):
        text = "".join(lang_el.itertext())
        lines = [(str(i + 1), ln) for i, ln in enumerate(text.replace("\r\n", "\n").replace("\r", "\n").split("\n"))]
        units, comments = text_units(lines, comment_syntax=True)
        model.add_routine(Routine(path, cls, lang, "line", units, comments=comments, attrs=attrs, doc=doc))
    else:
        model.add_routine(Routine(path, cls, lang, opaque_hash=sha(canon(lang_el)),
                                  opaque_doc_hash=sha(canon(lang_el, drop=DOC_ELEMENTS)),
                                  opaque_reason=f"{lang} body compared by hash (layout edits also change it)",
                                  attrs=attrs, doc=doc))


def _pou(model: Model, pou: ET.Element) -> None:
    name = pou.get("name", "?")
    ptype = pou.get("pouType", "")
    cls = "logic" if ptype == "program" else "aoi"
    prefix = f"POU:{name}"
    ent = model.entity(prefix, "pou", cls)
    ent.set("pouType", cls, ptype)
    bodies = 0
    for c in children(pou):
        n = local(c.tag)
        if n == "interface":
            _variables(model, c, prefix, "aoi" if cls == "aoi" else "interface", ent)
            for extra in children(c):
                en = local(extra.tag)
                if en == "documentation":
                    ent.set("interface/documentation", DOC, text_of(extra))
                elif en == "addData":
                    ent.set("interface/addData", cls, sha(canon(extra)), opaque=True, note="vendor addData: compared by hash")
        elif n == "body":
            bodies += 1
            ws = c.get("WorksheetName")
            path = f"{prefix}/Body:{ws}" if ws else (f"{prefix}/Body" if bodies == 1 else f"{prefix}/Body[{bodies}]")
            _body(model, c, path, cls)
        elif n in ("actions", "transitions"):
            item = n[:-1]
            for a in children(c, item):
                b = child(a, "body")
                apath = f"{prefix}/{item.capitalize()}:{a.get('name', '?')}"
                if b is not None:
                    _body(model, b, apath, cls)
                else:
                    model.add_routine(Routine(apath, cls, "?"))
        elif n == "documentation":
            ent.set("documentation", DOC, text_of(c))
        elif n == "addData":
            ent.set("addData", cls, sha(canon(c)), opaque=True,
                    note="vendor addData (CODESYS may keep methods, properties or plain-text declarations here): compared by hash")
        else:
            ent.set(n, cls, sha(canon(c, drop=DOC_ELEMENTS)), opaque=True, note=f"unmodelled element {n}: compared by hash")


def _datatype(model: Model, dt: ET.Element) -> None:
    name = dt.get("name", "?")
    ent = model.entity(f"DataType:{name}", "datatype", "interface")
    base = child(dt, "baseType")
    ent.set("baseType", "interface", render_type(base))
    ent.set("initialValue", "value", render_value(child(dt, "initialValue")))
    ent.set("documentation", DOC, text_of(child(dt, "documentation")))
    ad = child(dt, "addData")
    if ad is not None:
        ent.set("addData", "interface", sha(canon(ad)), opaque=True, note="vendor addData: compared by hash")
    st = child(base, "struct") if base is not None else None
    if st is not None:
        for v in children(st, "variable"):
            vn = v.get("name", "?")
            ent.set(f"Member:{vn}/initialValue", "value", render_value(child(v, "initialValue")))
            ent.set(f"Member:{vn}/documentation", DOC, text_of(child(v, "documentation")))


def _instances(model: Model, inst: ET.Element) -> None:
    for cfgs in children(inst, "configurations"):
        for cfg in children(cfgs, "configuration"):
            cname = cfg.get("name", "?")
            cpath = f"Configuration:{cname}"
            cent = model.entity(cpath, "configuration", "tasking")
            _variables(model, cfg, cpath, "interface", cent)
            for c in children(cfg):
                n = local(c.tag)
                if n == "resource":
                    rname = c.get("name", "?")
                    rpath = f"Resource:{cname}/{rname}"
                    rent = model.entity(rpath, "resource", "tasking")
                    _variables(model, c, rpath, "interface", rent)
                    rent.set("pouInstances", "tasking",
                             ", ".join(f"{p.get('name')}:{p.get('typeName')}" for p in children(c, "pouInstance")))
                    for t in children(c, "task"):
                        tent = model.entity(f"Task:{cname}/{rname}/{t.get('name', '?')}", "task", "tasking")
                        for k in ("interval", "priority", "single"):
                            tent.set(k, "tasking", t.get(k, ""))
                        tent.set("pouInstances", "tasking",
                                 " > ".join(f"{p.get('name')}:{p.get('typeName')}" for p in children(t, "pouInstance")))
                        tent.set("documentation", DOC, text_of(child(t, "documentation")))
                        ad = child(t, "addData")
                        if ad is not None:
                            tent.set("addData", "tasking", sha(canon(ad)), opaque=True, note="vendor addData: compared by hash")
                    for extra in children(c):
                        en = local(extra.tag)
                        if en == "documentation":
                            rent.set("documentation", DOC, text_of(extra))
                        elif en == "addData":
                            rent.set("addData", "tasking", sha(canon(extra)), opaque=True, note="vendor addData: compared by hash")
                elif n in ("accessVars", "configVars"):
                    cent.set(n, "interface", sha(canon(c, drop=DOC_ELEMENTS)), opaque=True)
                elif n == "documentation":
                    cent.set("documentation", DOC, text_of(c))
                elif n == "addData":
                    cent.set("addData", "metadata", sha(canon(c)), opaque=True, note="vendor addData: compared by hash")


def parse(root: ET.Element, *, path: str, sha256: str, size: int) -> Model:
    if not is_plcopen(root):
        raise ValueError(f"not a PLCopen TC6 XML project (root {root.tag!r})")
    model = Model(fmt=FORMAT, path=path, sha256=sha256, size=size, scope="project")
    exp = model.entity("Export", "export", "metadata")
    exp.set("namespace", "metadata", root.tag[1:].split("}", 1)[0], counted=False)
    proj = model.entity("Project", "project", "metadata")
    for c in children(root):
        n = local(c.tag)
        if n == "fileHeader":
            for k, v in c.attrib.items():
                exp.set(f"fileHeader/{local(k)}", "metadata", v, counted=False)
        elif n == "contentHeader":
            for k, v in c.attrib.items():
                k = local(k)
                proj.set(f"contentHeader/{k}", "metadata", v, counted=k not in UNCOUNTED_HEADER)
            for sub in children(c):
                sn = local(sub.tag)
                if sn == "Comment":
                    proj.set("contentHeader/Comment", DOC, text_of(sub))
                elif sn == "coordinateInfo":
                    proj.set("contentHeader/coordinateInfo", "metadata", sha(canon(sub)), counted=False, opaque=True,
                             note="graphical scaling: reported, not counted")
                else:
                    proj.set(f"contentHeader/{sn}", "metadata", sha(canon(sub)), opaque=True)
        elif n == "types":
            for t in children(c):
                tn = local(t.tag)
                if tn == "dataTypes":
                    for dt in children(t, "dataType"):
                        _datatype(model, dt)
                elif tn == "pous":
                    for p in children(t, "pou"):
                        _pou(model, p)
        elif n == "instances":
            _instances(model, c)
        elif n == "documentation":
            proj.set("documentation", DOC, text_of(c))
        elif n == "addData":
            proj.set("addData", "metadata", sha(canon(c)), opaque=True, note="vendor addData: compared by hash")
        else:
            proj.set(n, "metadata", sha(canon(c)), opaque=True, note=f"unmodelled element {n}: compared by hash")
    if any(f.opaque and "addData" in name for e in model.entities.values() for name, f in e.fields.items()):
        model.note("vendor addData present: compared by hash only. CODESYS documents an option that writes "
                   "plain-text declarations (with comments) into the export as a schema extension, so a "
                   "comment-only edit there shows as an opaque difference")
    return model

