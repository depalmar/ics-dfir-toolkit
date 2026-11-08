#!/usr/bin/env python3
"""build_site.py - generate the GitHub Pages site from the knowledge base.

  python artifacts/scripts/build_site.py          # write docs/site/index.html
  python artifacts/scripts/build_site.py --check  # the page contract only; writes nothing

One self-contained HTML file: vanilla JS and CSS inline, no framework, no CDN,
nothing fetched at view time. The Pages workflow builds it at deploy time and
it is never committed (docs/site/ is gitignored), so it cannot drift from the
YAML it is built from.

Every record goes into one JSON block. js_data() escapes "</" and "<!--", so
no quote, indicator or rule body can close the script element early. The
browser renders the libraries from that block with textContent only - never
innerHTML of record text: search, facet filters with live counts, a drawer per
record that shows every field, its sources with their quotes, and a link for
every id it references. Filter state lives in the URL hash
(#actors?motivation=disruption) so a filtered view can be sent to someone.

Facet values are computed here (FACET_KEYS); the JS defines how each facet is
labelled and ordered. --check fails if the two disagree, if a static
"#lib?key=value" link names an unknown key or value, if an element id repeats,
or if anything external is loaded. Coverage reuses mappings.coverage().

Correlations are computed here from the records' id fields, never from free
text: the actor x platform, malware x platform and malware x protocol
matrices, the incident timeline and the per-record relationship map (both
directions) in data["viz"] and data["rel"]. --check fails if any of them names
an id no library holds. The global search index (_s per record: title, id,
summary, aliases, tags, indicator values and the names of the ids it lists) is built here too.
The page defaults to light; a viewer's choice is kept in localStorage. The
footer's LinkedIn links are read from README.md's byline, and --check fails
when either is missing there.
"""
from __future__ import annotations

import datetime as _dt
import html
import json
import re
import sys
from pathlib import Path
from urllib.parse import unquote

import yaml

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
ART = ROOT / "artifacts"
OUT = ROOT / "docs" / "site" / "index.html"
REPO_URL = "https://github.com/depalmar/ics-dfir-toolkit"

sys.dont_write_bytecode = True  # --check writes nothing, not even a .pyc
sys.path.insert(0, str(HERE))
import mappings  # noqa: E402

e = html.escape

# Record libraries read straight from a directory of <id>-<slug>.yml files.
DIRS = {"platforms": "catalog", "protocols": "protocols", "datasources": "visibility",
        "actors": "intel/actors", "malware": "intel/malware", "incidents": "intel/incidents",
        "iocs": "intel/iocs", "hunts": "hunts", "packs": "packs"}
LIB_LABEL = {"platforms": "Platforms", "protocols": "Protocols", "datasources": "Data sources",
             "actors": "Threat actors", "malware": "Malware", "incidents": "Incidents",
             "iocs": "Indicator sets", "hunts": "Hunts", "packs": "Detection packs", "rules": "Rule files",
             "hardening": "Hardening", "kev": "KEV ledger", "coverage": "Coverage"}
# Tabs that hold more than one library; the tab opens the first.
GROUPS = {"intel": ["actors", "malware", "incidents", "iocs"], "detections": ["packs", "rules"]}
TABS = [("start", "Start"), ("platforms", "Platforms"), ("protocols", "Protocols"),
        ("datasources", "Data sources"), ("intel", "Threat intel"), ("hunts", "Hunts"),
        ("detections", "Detections"), ("hardening", "Hardening"), ("response", "Response"),
        ("coverage", "Coverage"), ("kev", "KEV ledger")]
TITLE_KEY = {"platforms": "name", "protocols": "name", "datasources": "name", "actors": "name",
             "malware": "name", "incidents": "name", "iocs": "title", "hunts": "title", "packs": "name",
             "rules": "title", "hardening": "control", "kev": "id", "coverage": "id"}
CONF_KEY = {"actors": "link_confidence"}
NO_CONF = {"iocs", "rules", "kev", "coverage"}

# Wording from CLAUDE.md, shown on Start and in every badge's tooltip.
IMPACT = {
    "passive": "Copies only: TAP/SPAN capture, logs already forwarded, existing backups.",
    "read-only": "A vendor-documented read path that changes no state.",
    "online-vendor-tool": "Going online with engineering software. Read-only in intent, but the same "
                          "session can download or force, so operations must approve it.",
    "process-risk": "Anything that can change a controller's mode, restart it, or load the network - "
                    "active scans, debug reads. Break-glass only. Active scanning of a live control "
                    "network is process-risk, always.",
}
CONF = {
    "high": "Vendor-documented, a government cyber authority's own words, or verified on a device.",
    "medium": "Multiple independent sources.",
    "low": "Single-source or inferred, and always flagged unverified.",
}
LEDE = {
    "platforms": "Controllers, engineering workstations, HMIs, historians and gateways: what evidence each "
                 "keeps, how to read it without moving the process, and what normal and suspicious look like.",
    "protocols": "Industrial protocols: transport, native authentication, and the open parsers that name "
                 "their operations.",
    "datasources": "What an owner can have before an incident, what must be enabled first, how long it is "
                   "kept, and what it cannot see.",
    "actors": "One record per reporter's cluster. Attribution is reported, never computed: an alias links "
              "clusters a reporter says overlap, and is not a merge unless the reporter equates them.",
    "malware": "ICS malware and attack tools: where they run, what they speak, what they can do to the "
               "process, and the detection gap each one states.",
    "incidents": "Case studies with the chain as the sources describe it and the physical consequence a "
                 "primary source states. An actor's claim of impact is not a confirmed impact.",
    "iocs": "Indicator sets parsed in code from the publisher's own file. Values are defanged on screen and "
            "exported refanged, each with the publisher's role. Most published addresses are compromised "
            "third parties or VPN exits: search logs with them, do not block on them blindly.",
    "hunts": "Hypotheses tested against data the owner already keeps. Hunts never touch a controller.",
    "packs": "Detections tied to the evidence they need. A detection whose evidence was not collected was "
             "not evaluated, and not evaluated is not passed.",
    "rules": "Sigma, YARA and Suricata only, each linked from the pack, hunt or malware record it expresses.",
    "hardening": "Controls with quoted sources, the vendor's own syntax or menu path where one is published, "
                 "and the operational impact where the source gives it.",
    "kev": "Every KEV entry on a watched ICS platform gets a dated decision. deferred means not yet read - "
           "never a decision. Exploitation dates are quoted, never inferred.",
    "coverage": "Every ATT&CK technique a record names: who uses it, which data sources see it, and which "
                "hunts, packs and rules look for it. A technique used with nothing hunting or detecting it "
                "is a gap; the gaps are the detection backlog.",
}
TILE = {"platforms": "controllers, EWS/HMI hosts, gateways", "protocols": "transport, authentication, parsers",
        "datasources": "what exists before an incident", "actors": "one reporter's cluster each",
        "malware": "ICS malware and attack tools", "incidents": "case studies, chain as sourced",
        "iocs": "parsed from publishers' files", "hunts": "over data the owner keeps",
        "packs": "detections tied to evidence", "rules": "Sigma, YARA, Suricata",
        "hardening": "controls with vendor syntax", "kev": "exploited CVEs, triaged",
        "coverage": "ATT&CK techniques mapped"}

XREF = re.compile(r"\b(?:ICS-(?:PROTO|DS|TA|MAL|IOC|INC|HUNT|PACK)-\d{4}|ICS-\d{4}|CVE-\d{4}-\d{4,})\b"
                  r"|\b\d{2}-[a-z0-9-]+/[a-z0-9_]+\.(?:yml|yar|rules)\b")
SIGMA_ATT = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$")
ACRONYM = {"ot": "OT", "ews": "EWS", "hmi": "HMI", "vnc": "VNC", "rdp": "RDP", "ssh": "SSH", "plc": "PLC",
           "cli": "CLI"}
LINKEDIN = {"profile": re.compile(r"https://www\.linkedin\.com/in/[A-Za-z0-9_%-]+/?"),
            "company": re.compile(r"https://www\.linkedin\.com/company/[A-Za-z0-9_%-]+/?")}

# Correlations: the id-list fields that link records, the libraries whose drawers get the
# relationship panel, and the physical-consequence bands the incident timeline colours.
REL_FIELDS = ("platforms", "protocols", "actors", "malware", "incidents", "iocs", "hunts", "packs")
INTEL = ("actors", "malware", "incidents", "iocs")
BAND = {"none-reported": "none", "attempted-no-effect": "none", "unknown": "none",
        "loss-of-view": "manip", "manual-operations": "manip", "process-manipulation": "manip",
        "loss-of-control": "control",
        "service-outage": "outage", "equipment-damage": "outage", "safety-system-trip": "outage"}
BAND_LABEL = {"outage": "Outage, equipment damage or safety trip", "control": "Loss of control",
              "manip": "Loss of view, manual operations or process manipulation",
              "none": "No physical effect reported, attempted or unknown"}
# Search text per record for the global search: the summary-like fields of each library.
SEARCH_FIELDS = ("summary", "hypothesis", "description", "why", "staleness", "location", "ledger", "kev_vendor",
                 "kev_product", "vendor", "set", "spec_owner", "os_base", "matrix")


def js_data(obj) -> str:
    """JSON for a <script> block. "</" and "<!--" are escaped (both stay valid JSON), so no
    string in the corpus can end the element or push the parser into script-escape states."""
    return (json.dumps(obj, separators=(",", ":"), ensure_ascii=False)
            .replace("<!--", "\\u003c!--").replace("</", "<\\/"))


def credit_parts() -> tuple[str, str]:
    """(maintainer, publisher) from NOTICE: the names live only where CLAUDE.md allows them."""
    m = re.search(r"^Copyright \d{4} (.+?) and (.+?)\s*$", (ROOT / "NOTICE").read_text(encoding="utf-8"), re.M)
    return (m.group(1), m.group(2)) if m else ("", "")


def credit() -> str:
    """The credit line as the footer's text reads it."""
    a, b = credit_parts()
    return f"{a} \u00b7 {b}" if a else ""


def linkedin() -> dict[str, str]:
    """The maintainer's profile and the company page, read from README.md's byline (the two
    linkedin.com links) so the page never hardcodes them. A missing one fails --check."""
    txt = (ROOT / "README.md").read_text(encoding="utf-8")
    return {k: m.group(0) for k, p in LINKEDIN.items() if (m := p.search(txt))}


def short(name: str) -> str:
    return re.sub(r"\s*\([^)]*\)", "", name or "").strip()


def humanize(stem: str) -> str:
    s = " ".join(ACRONYM.get(w, w) for w in stem.split("_"))
    return s[:1].upper() + s[1:]


def norm(o):
    """YAML to plain JSON types: dates become ISO strings, keys become strings."""
    if isinstance(o, dict):
        return {str(k): norm(v) for k, v in o.items()}
    if isinstance(o, (list, tuple)):
        return [norm(v) for v in o]
    if isinstance(o, (set, frozenset)):
        return sorted(norm(v) for v in o)
    if isinstance(o, (_dt.date, _dt.datetime)):
        return o.isoformat()
    return o


def _yml(p: Path) -> dict:
    return norm(yaml.safe_load(p.read_text(encoding="utf-8")) or {})


def rel(p: Path) -> str:
    return p.relative_to(ROOT).as_posix()


def refs_in(o, out: set | None = None) -> set:
    out = set() if out is None else out
    if isinstance(o, str):
        out.update(XREF.findall(o))
    elif isinstance(o, dict):
        for k, v in o.items():
            if not k.startswith("_"):
                refs_in(v, out)
    elif isinstance(o, list):
        for v in o:
            refs_in(v, out)
    return out


def n_unverified(o, top: bool = True) -> int:
    """Entries inside a record (artifacts, methods, controls...) that carry unverified: true."""
    n = 0
    if isinstance(o, dict):
        n += int(not top and o.get("unverified") is True)
        n += sum(n_unverified(v, False) for k, v in o.items() if not k.startswith("_"))
    elif isinstance(o, list):
        n += sum(n_unverified(v, False) for v in o)
    return n


# --------------------------------------------------------------------------- facets
def L(v) -> list[str]:
    return [str(x) for x in v or []]


def one(v) -> list[str]:
    return [] if v in (None, "") else [str(v)]


def conf(r: dict) -> list[str]:
    return one(r.get("_conf"))


def impacts(r: dict) -> list[str]:
    found = {c.get("impact") for c in r.get("collection") or []}
    found |= {a.get("collection_impact") for a in r.get("artifacts") or []}
    return [i for i in IMPACT if i in found]


# The facet keys each library understands and how each value is computed. The JS defines a
# facet of the same key, in the same order, for each; --check and the page itself compare them.
FACET_KEYS = {
    "platforms": {"class": lambda r: one(r.get("asset_class")), "purdue": lambda r: L(r.get("purdue_levels")),
                  "vendor": lambda r: one(r.get("vendor")), "impact": impacts,
                  "memory": lambda r: one(r.get("memory_acquisition")), "confidence": conf},
    "protocols": {"transport": lambda r: sorted({t["layer"] for t in r.get("transport") or []}),
                  "auth": lambda r: one((r.get("authentication") or {}).get("native")), "confidence": conf},
    "datasources": {"category": lambda r: one(r.get("category")), "purdue": lambda r: L(r.get("purdue_levels")),
                    "impact": impacts, "confidence": conf},
    "actors": {"motivation": lambda r: one(r.get("motivation")), "reporter": lambda r: L(r.get("reported_by")),
               "stage": lambda r: one(r.get("ics_kill_chain_stage")), "platform": lambda r: L(r.get("platforms")),
               "confidence": conf},
    "malware": {"type": lambda r: one(r.get("type")), "runs": lambda r: L(r.get("runs_on")),
                "effect": lambda r: L(r.get("ics_effects")), "platform": lambda r: L(r.get("platforms")),
                "protocol": lambda r: L(r.get("protocols")),
                "detection": lambda r: ["yes" if r.get("detections") else "none"], "confidence": conf},
    "incidents": {"consequence": lambda r: one(r.get("physical_consequence")),
                  "sector": lambda r: L(r.get("sectors")), "country": lambda r: L(r.get("countries")),
                  "confidence": conf},
    "iocs": {"publisher": lambda r: one(r.get("publisher")),
             "type": lambda r: sorted({i["type"] for i in r.get("indicators") or []}),
             "role": lambda r: sorted({i["role"] for i in r.get("indicators") or []})},
    "hunts": {"platform": lambda r: L(r.get("platforms")), "data": lambda r: L(r.get("data")),
              "actor": lambda r: L(r.get("actors")), "confidence": conf},
    "packs": {"platform": lambda r: L(r.get("platforms")),
              "tier": lambda r: [t for t in ("possible", "likely", "confirmed")
                                 if t in {x["tier"] for x in r.get("detect") or []}],
              "evidence": lambda r: sorted({x["evidence_class"] for x in r.get("detect") or []}),
              "confidence": conf},
    "rules": {"format": lambda r: one(r.get("format")), "dir": lambda r: one(r.get("dir")),
              "attack": lambda r: L(r.get("attack")), "linked": lambda r: L(r.get("_linked"))},
    "hardening": {"platform": lambda r: one(r.get("platform_id")), "category": lambda r: one(r.get("category")),
                  "priority": lambda r: one(r.get("priority")), "confidence": conf},
    "kev": {"decision": lambda r: one(r.get("decision") or "not-in-ledger"), "platform": lambda r: one(r.get("platform")),
            "reported": lambda r: ["quoted" if r.get("exploitation") else "none"]},
    "coverage": {"status": lambda r: L(r.get("status")), "matrix": lambda r: one(r.get("matrix"))},
}
LIBS = list(FACET_KEYS)


# --------------------------------------------------------------------------- data
def load() -> dict:
    d = {lib: [{**_yml(p), "_file": rel(p)} for p in sorted((ART / sub).glob("*.yml"))] for lib, sub in DIRS.items()}
    d["hardening_files"] = [{**_yml(p), "_file": rel(p), "_stem": p.stem} for p in sorted((ART / "hardening").glob("*.yml"))]
    d["response"] = [{**_yml(p), "_file": rel(p), "_id": p.stem} for p in sorted((ART / "response").glob("*.yml"))]
    d["watch"] = _yml(ART / "watch" / "kev-watch.yml")
    d["exploitation"] = _yml(ART / "intel" / "exploitation.yml")
    d["rule_files"] = [{"path": rel(p), "text": p.read_text(encoding="utf-8")}
                       for p in sorted(ROOT.glob("[0-9][0-9]-*/*")) if p.suffix in (".yml", ".yar", ".rules")]
    d["coverage"] = mappings.coverage()
    return d


def comment_text(text: str, path: str) -> str:
    paras, cur = [], []
    for line in text.splitlines():
        if not line.startswith("#"):
            continue
        s = line[1:].strip()
        if s == path:
            continue
        if s:
            cur.append(s)
        elif cur:
            paras.append(" ".join(cur))
            cur = []
    if cur:
        paras.append(" ".join(cur))
    return "\n\n".join(paras)


def rule_item(f: dict) -> dict:
    path, text = f["path"], f["text"]
    p = Path(path)
    fmt = {".yml": "sigma", ".yar": "yara", ".rules": "suricata"}[p.suffix]
    item = {"id": path, "title": humanize(p.stem), "format": fmt, "dir": path.split("/")[0]}
    if fmt == "sigma":
        y = norm(yaml.safe_load(text) or {})
        tags = [str(t) for t in y.get("tags") or []]
        item.update({k: y[k] for k in ("title", "description", "status", "level", "logsource", "falsepositives")
                     if y.get(k)})
        item["attack"] = sorted({m.group(1).upper() for t in tags if (m := SIGMA_ATT.match(t))})
        item["tags"] = tags
        item["references"] = y.get("references") or []
    elif fmt == "suricata":
        item["description"] = comment_text(text, path)
        item["sids"] = re.findall(r"\bsid:\s*(\d+)", text)
        item["msgs"] = re.findall(r'msg:"([^"]*)"', text)
    else:
        item["description"] = comment_text(text.replace("//", "#"), path)
        item["yara_rules"] = re.findall(r"^\s*(?:private\s+|global\s+)*rule\s+(\w+)", text, re.M)
    item["text"] = text
    return item


def build_data(d: dict) -> dict:
    libs = {lib: [dict(r) for r in d[lib]] for lib in DIRS}
    hard_sets = {}
    libs["hardening"] = []
    for f in d["hardening_files"]:
        hard_sets[f["_stem"]] = {"platform_id": f["platform_id"], "name": f["name"]}
        for c in f.get("controls") or []:
            libs["hardening"].append({**c, "platform_id": f["platform_id"], "set": f["name"],
                                      "set_summary": f.get("summary"), "_file": f["_file"]})
    libs["rules"] = [rule_item(f) for f in d["rule_files"]]
    upstream = d["watch"].get("upstream") or {}
    for s in libs["iocs"]:
        if s["id"] in upstream:
            s["upstream_sha256"] = upstream[s["id"]]

    expl = {r["cve"]: r for r in d["exploitation"].get("records") or []}
    pack_cves: dict[str, list[str]] = {}
    for p in libs["packs"]:
        for c in p.get("cves") or []:
            pack_cves.setdefault(c, []).append(p["id"])
    kev = []
    for t in d["watch"].get("triaged") or []:
        x = expl.get(t["cve"], {})
        kev.append({"id": t["cve"], **{k: v for k, v in t.items() if k != "cve"}, "packs": pack_cves.get(t["cve"], []),
                    "exploitation": x.get("reports", []), "searched": x.get("searched", []),
                    "_file": "artifacts/watch/kev-watch.yml"})
    triaged = {k["id"] for k in kev}
    for cve, x in expl.items():
        if cve not in triaged:
            kev.append({"id": cve, "ledger": "No entry in kev-watch.yml; quoted exploitation reports only.",
                        "packs": pack_cves.get(cve, []), "exploitation": x.get("reports", []),
                        "searched": x.get("searched", []), "_file": "artifacts/intel/exploitation.yml"})
    libs["kev"] = kev

    cov = d["coverage"]
    libs["coverage"] = []
    for t in sorted(cov, key=lambda t: (mappings.matrix(t) != "ICS", t)):
        c = cov[t]
        status = (["gap"] if c["used"] and not (c["hunted"] or c["detected"]) else []) \
            + (["blind"] if c["used"] and not c["seen"] else []) + [r for r in mappings.ROLES if c[r]]
        libs["coverage"].append({"id": t, "matrix": mappings.matrix(t), "status": status,
                                 **{r: sorted(c[r]) for r in mappings.ROLES},
                                 "attack_url": "https://attack.mitre.org/techniques/" + t.replace(".", "/") + "/"})

    where, names, short_names, backrefs = {}, {}, {}, {}
    for lib in LIBS:
        for r in libs[lib]:
            r["_title"] = str(r.get(TITLE_KEY[lib]) or r["id"])
            if lib not in NO_CONF:
                r["_conf"] = r.get(CONF_KEY.get(lib, "confidence"))
            r["_unv"] = r.get("unverified") is True
            r["_nunv"] = n_unverified(r)
            where.setdefault(r["id"], lib)
            names[r["id"]] = r["_title"] if lib != "kev" else " ".join(
                str(r[k]) for k in ("kev_vendor", "kev_product") if r.get(k)) or r["id"]
    for r in libs["platforms"]:
        short_names[r["id"]] = short(r["name"])
    for lib in LIBS:
        if lib == "coverage":
            continue
        for r in libs[lib]:
            for ref in refs_in(r) - {r["id"]}:
                if ref in where:
                    backrefs.setdefault(ref, set()).add(r["id"])
    kinds = {"packs": "pack", "hunts": "hunt", "malware": "malware"}
    for r in libs["rules"]:
        linked = sorted({kinds[where[b]] for b in backrefs.get(r["id"], ()) if where[b] in kinds})
        if "ics-dfir.standalone" in r.get("tags", []):
            linked.append("standalone")
        r["_linked"] = linked or ["unlinked"]
    for lib in LIBS:
        for r in libs[lib]:
            r["_f"] = {k: list(dict.fromkeys(fn(r))) for k, fn in FACET_KEYS[lib].items()}
            r.pop("_linked", None)
            r["_s"] = search_text(r, names)
    return {"libs": libs, "facetKeys": {k: list(v) for k, v in FACET_KEYS.items()}, "groups": GROUPS,
            "libLabel": LIB_LABEL, "where": where, "names": names, "short": short_names,
            "backrefs": {k: sorted(v) for k, v in sorted(backrefs.items())}, "hardSets": hard_sets,
            "rel": relationships(libs, where), "viz": viz_data(libs, where),
            "response": [dict(r) for r in d["response"]], "impact": IMPACT, "conf": CONF, "repo": REPO_URL}


def search_text(r: dict, names: dict) -> str:
    """One line per record for the global search: title, id, the summary-like fields, aliases,
    tags, and the names of the ids its list fields carry (a hunt naming ICS-TA-0001 is found by
    "Sandworm"). The per-library search still indexes the whole record."""
    parts = [r["_title"], str(r["id"])]
    parts += [str(r[k]) for k in SEARCH_FIELDS if isinstance(r.get(k), str)]
    parts += [str(x) for x in r.get("products") or [] if isinstance(x, (str, int))]
    parts += [a.get("name", "") if isinstance(a, dict) else str(a) for a in r.get("aliases") or []]
    parts += [str(t) for t in r.get("tags") or []]
    parts += [str(i.get("value", "")) for i in r.get("indicators") or [] if isinstance(i, dict)]   # a pasted address finds its set
    for k in REL_FIELDS:
        parts += [names[x] for x in L(r.get(k)) if x in names and names[x] != x]
    return " ".join(p for p in parts if p)


def relationships(libs: dict, where: dict) -> dict[str, dict[str, list[str]]]:
    """id -> {library: [ids]} for every threat-intel record, from the id-list fields of the
    record itself and of every record that names it: both directions, no free text."""
    rel: dict[str, dict[str, set]] = {}
    for lib in INTEL + ("hunts", "packs"):
        for r in libs[lib]:
            for f in REL_FIELDS:
                for x in L(r.get(f)):
                    if x not in where or x == r["id"]:
                        continue
                    for a, b in ((r["id"], x), (x, r["id"])):
                        if where[a] in INTEL:
                            rel.setdefault(a, {}).setdefault(where[b], set()).add(b)
    return {k: {lib: sorted(v) for lib, v in sorted(g.items())} for k, g in sorted(rel.items())}


def ymd(v) -> float | None:
    """A fuzzy date (YYYY, YYYY-MM or YYYY-MM-DD) as a fractional year, only as precise as given."""
    m = re.match(r"^(\d{4})(?:-(\d{2}))?(?:-(\d{2}))?", str(v or ""))
    if not m:
        return None
    y, mo, dd = int(m.group(1)), int(m.group(2) or 1), int(m.group(3) or 1)
    return y + (mo - 1) / 12 + (dd - 1) / 365


def viz_data(libs: dict, where: dict) -> dict:
    """The matrices and the timeline, from id fields only. A cell is [row, col, direct, via]:
    direct = the row record names the column; via = linked records that name it."""
    def ids(r, k):
        return [x for x in L(r.get(k)) if x in where]
    actors, malware, incidents = libs["actors"], libs["malware"], libs["incidents"]
    plats = [p["id"] for p in libs["platforms"]]
    protos = [p["id"] for p in libs["protocols"]]
    mal_of = {a["id"]: set(ids(a, "malware")) for a in actors}
    inc_of = {a["id"]: set(ids(a, "incidents")) for a in actors}
    for m in malware:
        for a in ids(m, "actors"):
            mal_of.setdefault(a, set()).add(m["id"])
    for i in incidents:
        for a in ids(i, "actors"):
            inc_of.setdefault(a, set()).add(i["id"])
    plat_of = {r["id"]: set(ids(r, "platforms")) for lib in INTEL for r in libs[lib]}
    minc = {m["id"]: set(ids(m, "incidents")) for m in malware}
    for i in incidents:
        for m in ids(i, "malware"):
            minc.setdefault(m, set()).add(i["id"])

    ap = []
    for a in actors:
        for p in plats:
            direct = p in plat_of[a["id"]]
            via = sorted(x for x in mal_of.get(a["id"], ()) | inc_of.get(a["id"], ()) if p in plat_of.get(x, ()))
            if direct or via:
                ap.append([a["id"], p, int(direct), via])
    mp = [[m["id"], p, 1, sorted(x for x in minc.get(m["id"], ()) if p in plat_of.get(x, ()))]
          for m in malware for p in plats if p in plat_of[m["id"]]]
    mx = [[m["id"], x, 1, []] for m in malware for x in protos if x in ids(m, "protocols")]
    tl = [{"id": i["id"], "date": str(i.get("date") or ""), "t": ymd(i.get("date")),
           "consequence": str(i.get("physical_consequence") or "unknown"),
           "band": BAND.get(str(i.get("physical_consequence")), "none")} for i in incidents]
    tl = sorted((x for x in tl if x["t"] is not None), key=lambda x: (x["t"], x["id"]))
    return {"actors_platforms": {"rows": [a["id"] for a in actors], "cols": plats, "cells": ap},
            "malware_platforms": {"rows": [m["id"] for m in malware], "cols": plats, "cells": mp},
            "malware_protocols": {"rows": [m["id"] for m in malware], "cols": protos, "cells": mx},
            "timeline": tl}


# --------------------------------------------------------------------------- server-rendered parts
def facet_values(data: dict) -> dict[str, dict[str, set]]:
    vals = {lib: {k: set() for k in FACET_KEYS[lib]} for lib in LIBS}
    for lib in LIBS:
        for r in data["libs"][lib]:
            for k, vs in r["_f"].items():
                vals[lib][k].update(vs)
    return vals


def flink(data: dict, lib: str, key: str, val: str, text: str, cls: str = "") -> str:
    """A filtered-library link, or plain text when no record carries the value."""
    have = any(val in r["_f"][key] for r in data["libs"][lib])
    c = f' class="{cls}"' if cls else ""
    return f'<a{c} href="#{lib}?{key}={e(val)}">{text}</a>' if have else f"<span{c}>{text}</span>"


def render_start(data: dict) -> str:
    libs = data["libs"]
    tiles = ""
    for lib in ["platforms", "protocols", "datasources", "actors", "malware", "incidents", "iocs", "hunts",
                "packs", "rules", "hardening", "kev", "coverage"]:
        n_unv = sum(1 for r in libs[lib] if r["_unv"] or r["_nunv"])
        unv = (f'<a class="tu" href="#{lib}?unv=1" title="Records that are unverified or hold unverified entries">'
               f'{n_unv} with unverified content</a>') if n_unv else ""
        tiles += (f'<div class="tile"><a class="tl" href="#{lib}"><b>{len(libs[lib])}</b><span>{LIB_LABEL[lib]}</span>'
                  f"<small>{e(TILE[lib])}</small></a>{unv}</div>")
    n_resp = len(data["response"])
    tiles += (f'<div class="tile"><a class="tl" href="#response"><b>{n_resp}</b><span>Response</span>'
              "<small>safety-first playbooks</small></a></div>")
    rungs = ""
    for i, (imp, words) in enumerate(IMPACT.items(), 1):
        n_methods = sum(1 for r in libs["platforms"] for c in r.get("collection") or [] if c.get("impact") == imp) \
            + sum(1 for r in libs["platforms"] for a in r.get("artifacts") or [] if a.get("collection_impact") == imp) \
            + sum(1 for r in libs["datasources"] for c in r.get("collection") or [] if c.get("impact") == imp)
        links = " &#183; ".join(flink(data, lib, "impact", imp, LIB_LABEL[lib].lower()) for lib in ("platforms", "datasources"))
        rungs += (f'<li class="rung rung-{imp}"><span class="rn">{i}</span><div><code class="b imp imp-{imp}">{imp}</code>'
                  f'<p>{e(words)}</p><p class="small muted">{n_methods} collection methods and artifacts rated {imp}: {links}</p></div></li>')
    cov = libs["coverage"]
    n_gap = sum("gap" in t["_f"]["status"] for t in cov)
    n_blind = sum("blind" in t["_f"]["status"] for t in cov)
    n_nodet = sum("none" in m["_f"]["detection"] for m in libs["malware"])
    n_def = sum("deferred" in k["_f"]["decision"] for k in libs["kev"])
    gaps = (f"<li>{flink(data, 'coverage', 'status', 'gap', f'<b>{n_gap}</b> ATT&amp;CK techniques')} recorded in use with "
            "nothing hunting or detecting them: the detection backlog.</li>"
            f"<li>{flink(data, 'coverage', 'status', 'blind', f'<b>{n_blind}</b> techniques')} recorded in use that no "
            "data source here records.</li>"
            f"<li>{flink(data, 'malware', 'detection', 'none', f'<b>{n_nodet}</b> malware families')} with no "
            "detection, each stating why.</li>"
            f"<li>{flink(data, 'kev', 'decision', 'deferred', f'<b>{n_def}</b> KEV entries')} deferred: not yet read "
            "against primary sources.</li>")
    confs = "".join(f'<li><span class="b c-{c}">{c}</span> {e(w)}</li>' for c, w in CONF.items())
    return f"""
<div class="hero">
  <h2>Evidence for industrial control system incidents, with its sources quoted</h2>
  <p>A DFIR knowledge base for industrial control systems and operational technology: what evidence each controller,
  engineering workstation, HMI, historian and gateway keeps; the protocols and data sources that see an intrusion; the
  actors, malware and incidents as their reporters describe them; hunts, Sigma and Suricata detections, hardening and a
  safety-first response playbook. Every claim cites a primary source and quotes it, confidence reflects provenance, and
  a gap is stated rather than filled with a guess.</p>
  <div class="warnbox"><b>Knowledge base first, tooling later.</b> There is no collector or analyzer yet. Nothing here
  should be run against a live control system: where a record describes a collection method it states its impact on
  the process, and anything above <code>passive</code> needs operations' approval.</div>
</div>
<div class="tiles">{tiles}</div>
<div class="cols">
  <section class="box rulebox"><h3>Not evaluated is not passed</h3><p>A detection that lacks the evidence it needs
  says so. A controller whose logic was not compared with a known-good copy has not been shown to be unmodified.</p></section>
  <section class="box rulebox"><h3>Never call a system clean</h3><p>The lowest verdict is
  <code>NO-INDICATORS-FOUND</code>. Controllers cannot be imaged the way hosts can, and every report carries that gap.</p></section>
  <section class="box rulebox"><h3>Most evidence is not on the controller</h3><p>Diagnostic buffers are small ring
  buffers, many PLCs keep no audit log, and the logic itself is the best artifact, so a trusted known-good copy is a
  precondition. The rest is on engineering workstations and HMIs, on the wire, and in remote-access and historian logs.</p></section>
</div>
<div class="cols wide">
  <section class="box" id="safety"><h3>Safety before evidence: collection impact</h3>
    <p class="small">In OT the process outranks the investigation. Every collection method declares its impact on the
    process, and none is rated lower than it is.</p><ol class="ladder">{rungs}</ol></section>
  <div>
    <section class="box" id="confidence"><h3>How confidence works</h3><ul class="plain conf">{confs}</ul>
      <p class="small"><span class="b unvb">unverified</span> marks a record or entry that must be checked before it is
      relied on: every <code>low</code> carries it, and so does a record whose every source came through a summarising
      fetch. Each source says how it was read: <code>read: direct</code> (quote copied from the rendered page) or
      <code>read: summariser</code> (check the quote). A government authority is <code>high</code> for what it
      recommends or reports; press is a lead, never the basis for <code>high</code>.</p>
      <p class="small">Attribution is reported, never computed. Link confidence is ours and measures provenance; stated
      confidence is the attributing party's own words, verbatim.</p></section>
    <section class="box" id="gaps"><h3>Where the gaps are</h3><ul class="plain gapl">{gaps}</ul>
      <p class="small muted">An omitted path, event id or menu location is honest; a guessed one becomes somebody's
      failed collection during an incident.</p></section>
  </div>
</div>"""


def render_kev_head(d: dict) -> str:
    w = d["watch"]
    rows = "".join(f'<tr><td><a href="#platforms/{e(pid)}">{e(pid)}</a></td><td><code>{e(m.get("vendor", ""))}</code></td>'
                   f'<td><code>{e(m.get("product", ""))}</code></td><td><code>{e(m.get("exclude", ""))}</code></td></tr>'
                   for pid, m in (w.get("platforms") or {}).items())
    return (f'<p class="small">Entries added to CISA\'s catalog on or after <b>{e(str(w.get("since", "")))}</b> on a watched '
            f'platform are triaged here; older ones are not reported. Catalog copy: <a href="{e(w.get("kev_url", ""))}" '
            'rel="noopener noreferrer" target="_blank">cisagov/kev-data</a>.</p>'
            '<details class="box small"><summary>What the watch matches (KEV vendorProject and product regexes)</summary>'
            '<div class="tbl"><table><thead><tr><th>Platform</th><th>Vendor</th><th>Product</th><th>Exclude</th></tr></thead>'
            f"<tbody>{rows}</tbody></table></div></details>")


# Cell colour of the ATT&CK grid, in precedence order, and the words its legend and tooltips use.
GRID_STATUS = [("gap", "gap", "gap: used, nothing hunts or detects it"),
               ("blind", "blind spot", "blind spot: used, no data source records it"),
               ("detected", "detected", "detected by a pack or Sigma rule"), ("hunted", "hunted", "hunted"),
               ("seen", "seen", "seen by a data source, not recorded in use")]
DASH = "\u2014"


def render_cov_head(data: dict) -> str:
    cov = data["libs"]["coverage"]
    n_ics = sum(t["matrix"] == "ICS" for t in cov)
    n_gap = sum("gap" in t["_f"]["status"] for t in cov)
    n_blind = sum("blind" in t["_f"]["status"] for t in cov)
    counts = {k: 0 for k, _, _ in GRID_STATUS}
    groups = {"ICS": "", "Enterprise": ""}
    for t in cov:
        st = t["_f"]["status"]
        cls = next(k for k, _, _ in GRID_STATUS if k in st)
        counts[cls] += 1
        words = "; ".join(w for k, _, w in GRID_STATUS if k in st)
        groups[t["matrix"]] += (f'<a class="cc cc-{cls}{" bl" if "blind" in st and cls != "blind" else ""}" '
                                f'href="#coverage/{e(t["id"])}" title="{e(t["id"])}: {e(words)}">{e(t["id"])}</a>')
    legend = "".join(flink(data, "coverage", "status", k, f'<i class="cc-{k}"></i>{e(lab)} <b>{counts[k]}</b>', "lg")
                     for k, lab, _ in GRID_STATUS)
    grid = "".join(f'<section class="cg"><h4>{m} <span class="n">{sum(t["matrix"] == m for t in cov)}</span></h4>'
                   f'<div class="cells">{cells}</div></section>' for m, cells in groups.items())
    return (f'<div class="stats">{flink(data, "coverage", "status", "gap", f"<b>{n_gap}</b> gaps", "stat st-bad")}'
            f'{flink(data, "coverage", "status", "blind", f"<b>{n_blind}</b> blind spots", "stat st-warn")}'
            f'<span class="stat"><b>{len(cov)}</b> techniques: {n_ics} ICS, {len(cov) - n_ics} Enterprise</span></div>'
            '<p class="small muted"><b>Used</b>: malware, actors or incidents recorded using it. <b>Seen</b>: data sources '
            'whose events show it. <b>Hunted</b>: hunts. <b>Detected</b>: packs and Sigma rules. A blind spot is used '
            'with no data source that records it. Technique names are not stored in the repository; each drawer links '
            'to attack.mitre.org. The same table is generated as MAPPINGS.md.</p>'
            '<details class="viz" id="viz-cov" open><summary>Technique grid: every technique shaded by its status, '
            'ICS then Enterprise</summary><div class="vizb">'
            f'<div class="cglg" aria-label="Legend">{legend}<span class="lg"><i class="cc-gap bl"></i>dashed: also a blind spot</span></div>'
            f'<div class="covgrid">{grid}</div>'
            '<p class="small muted">A cell takes the most urgent status it has, in the legend\'s order. Click one for the '
            'technique\'s row and its drawer; click a legend entry for the filtered table.</p></div></details>')


def matrix_html(data: dict, key: str, row_lib: str, facet: str, col_lib: str, noun: str) -> str:
    """One correlation matrix as a table that scrolls inside its own box. Row headers open the
    record, column headers the platform or protocol, a cell the record with the library filtered
    to that column, and the totals the filtered library."""
    mz, names = data["viz"][key], data["names"]
    cells = {(r, c): (d, via) for r, c, d, via in mz["cells"]}
    vendor = {p["id"]: str(p.get("vendor") or "") for p in data["libs"]["platforms"]}

    def col_name(c: str) -> str:
        n = short(names.get(c, c))
        v = vendor.get(c, "")
        return n[len(v):].strip() if v and n.startswith(v) and len(n) > len(v) + 2 else n
    head = "".join(f'<th class="ch" scope="col"><a href="#{col_lib}/{e(c)}" title="{e(c)}: {e(names.get(c, c))}">'
                   f'<span>{e(col_name(c))}</span></a></th>' for c in mz["cols"])
    rows = []
    for r in mz["rows"]:
        tds, n_direct = [], 0
        for c in mz["cols"]:
            d, via = cells.get((r, c), (0, []))
            if not d and not via:
                tds.append('<td class="e"></td>')
                continue
            n_direct += d
            tip = f"{names.get(r, r)} × {col_name(c)}: " + ("named by the record" if d else "not named by the record")
            if via:
                tip += f"; {len(via)} linked record{'s' if len(via) > 1 else ''} name it: {', '.join(via)}"
            if d:
                heat = 28 + round(52 * min(len(via), 4) / 4)
                tds.append(f'<td><a class="mc{" dk" if len(via) >= 3 else ""}" style="--h:{heat}%" '
                           f'href="#{row_lib}/{e(r)}?{facet}={e(c)}" title="{e(tip)}">{len(via) or ""}</a></td>')
            else:
                tds.append(f'<td><a class="mc via" href="#{row_lib}/{e(r)}" title="{e(tip)}">{len(via)}</a></td>')
        rows.append(f'<tr><th class="rh" scope="row"><a href="#{row_lib}/{e(r)}" title="{e(r)}">{e(short(names.get(r, r)))}</a></th>'
                    f'{"".join(tds)}<td class="tot">{n_direct or "—"}</td></tr>')
    foot = "".join(f'<td class="tot">{flink(data, row_lib, facet, c, str(n)) if n else "—"}</td>'
                   for c in mz["cols"] for n in [sum(d for (r, cc), (d, _) in cells.items() if cc == c)])
    return (f'<div class="mxs"><table class="mx" aria-label="{e(noun)} by {col_lib}"><thead><tr><th class="rh corner"></th>{head}'
            f'<th class="tot">named</th></tr></thead><tbody>{"".join(rows)}</tbody>'
            f'<tfoot><tr><th class="rh" scope="row">{e(noun)} naming it</th>{foot}<td></td></tr></tfoot></table></div>')


def timeline_html(data: dict) -> str:
    """Incidents on a year axis: one marker each, placed by the date its sources give, coloured
    and shaped by the band of its physical consequence. Inline SVG, nothing external."""
    tl, names = data["viz"]["timeline"], data["names"]
    if not tl:
        return '<p class="empty">No incident carries a date.</p>'
    lo, hi = int(min(x["t"] for x in tl)), int(max(x["t"] for x in tl)) + 1
    W, H, pl, pr, ay, lanes = 960, 172, 30, 30, 132, (40, 70, 100)

    def X(t):
        return round(pl + (t - lo) / (hi - lo) * (W - pl - pr), 1)
    placed: list[tuple[int, float]] = []
    marks = []
    for i, it in enumerate(tl):
        x = X(it["t"])
        lane = next((ln for ln in range(len(lanes)) if all(abs(x - px) >= 34 for pl_, px in placed if pl_ == ln)), i % len(lanes))
        placed.append((lane, x))
        y = lanes[lane]
        b = it["band"]
        shape = {"outage": f'<rect class="mk mk-{b}" x="{x - 7}" y="{y - 7}" width="14" height="14" rx="2"/>',
                 "control": f'<rect class="mk mk-{b}" x="{x - 7}" y="{y - 7}" width="14" height="14" rx="2" transform="rotate(45 {x} {y})"/>',
                 "manip": f'<circle class="mk mk-{b}" cx="{x}" cy="{y}" r="7"/>',
                 "none": f'<circle class="mk mk-{b}" cx="{x}" cy="{y}" r="6.5"/>'}[b]
        tip = f"{it['id']} · {it['date']} · {names.get(it['id'], it['id'])} · {it['consequence'].replace('-', ' ')}"
        marks.append(f'<a href="#incidents/{e(it["id"])}" class="tm" aria-label="{e(tip)}"><title>{e(tip)}</title>'
                     f'<line class="stem" x1="{x}" y1="{y + 9}" x2="{x}" y2="{ay}"/>{shape}<circle class="hit" cx="{x}" cy="{y}" r="13"/></a>')
    ticks = "".join(f'<line class="tk" x1="{X(y)}" y1="{ay}" x2="{X(y)}" y2="{ay + 5}"/>'
                    f'<text x="{X(y)}" y="{ay + 20}" text-anchor="middle">{y}</text>' for y in range(lo, hi + 1))
    svg = (f'<div class="tlw"><svg class="tlx" viewBox="0 0 {W} {H}" role="img" aria-label="{len(tl)} incidents on a year '
           f'axis from {lo} to {hi}"><line class="ax" x1="{pl}" y1="{ay}" x2="{W - pr}" y2="{ay}"/>{ticks}{"".join(marks)}</svg></div>')
    by_band: dict[str, dict[str, int]] = {}
    for it in tl:
        by_band.setdefault(it["band"], {}).setdefault(it["consequence"], 0)
        by_band[it["band"]][it["consequence"]] += 1
    sw = {"outage": '<rect class="mk mk-outage" x="2" y="2" width="12" height="12" rx="2"/>',
          "control": '<rect class="mk mk-control" x="3.5" y="3.5" width="9" height="9" rx="1.5" transform="rotate(45 8 8)"/>',
          "manip": '<circle class="mk mk-manip" cx="8" cy="8" r="6"/>', "none": '<circle class="mk mk-none" cx="8" cy="8" r="5.5"/>'}
    legend = "".join(
        f'<span class="tll"><svg class="tlx lgm" viewBox="0 0 16 16" aria-hidden="true">{sw[b]}</svg>{e(BAND_LABEL[b])}: '
        + ", ".join(flink(data, "incidents", "consequence", c, f"{e(c.replace('-', ' '))} ({n})") for c, n in sorted(by_band[b].items()))
        + "</span>" for b in ("outage", "control", "manip", "none") if b in by_band)
    return svg + f'<div class="tlg">{legend}</div>'


def render_viz(data: dict) -> str:
    """The correlation block the Threat intel tab carries above whichever of its libraries is open."""
    return ('<details class="viz" id="viz-intel" open><summary>Correlations: actors × platforms, malware × platforms '
            'and protocols, incidents by year</summary><div class="vizb">'
            '<p class="small muted">Computed from the id fields the records carry, never from prose, so a cell is only as good '
            'as the record it comes from and an empty one means no record says so. Row headers open the record, column headers '
            'the platform or protocol, a cell the record with its library filtered to that column, and the totals the filtered library.</p>'
            '<section class="vizs"><h4>Actors × platforms</h4><p class="small muted">A filled cell: the actor record names '
            'the platform; its number counts the actor\'s malware and incident records that name it too. A ring: only linked '
            'records name it, the actor record does not.</p>'
            + matrix_html(data, "actors_platforms", "actors", "platform", "platforms", "actors") + "</section>"
            '<section class="vizs"><h4>Malware × platforms</h4><p class="small muted">The platforms each malware record '
            'names; the number counts its incidents that name the platform too.</p>'
            + matrix_html(data, "malware_platforms", "malware", "platform", "platforms", "malware families") + "</section>"
            '<section class="vizs"><h4>Malware × protocols</h4><p class="small muted">The protocols each malware record '
            'says the family speaks: the operations a passive sensor would have to parse to see it.</p>'
            + matrix_html(data, "malware_protocols", "malware", "protocol", "protocols", "malware families") + "</section>"
            '<section class="vizs"><h4>Incidents by year</h4><p class="small muted">One marker per incident, placed by the '
            'date its sources give (a year alone sits at the start of that year) and coloured by the physical consequence a '
            'primary source states; the shape repeats the band. Hover or focus a marker for the name; click it for the record.</p>'
            + timeline_html(data) + "</section></div></details>")


def lib_panel(lib: str, data: dict, extra: str = "", after: str = "") -> str:
    sub = ""
    for members in GROUPS.values():
        if lib in members:
            sub = '<nav class="subnav" aria-label="Libraries in this tab">' + "".join(
                f'<a href="#{m}" data-go="{m}"{" aria-current=page" if m == lib else ""}>{LIB_LABEL[m]}'
                f'<span class="n">{len(data["libs"][m])}</span></a>' for m in members) + "</nav>"
    noun = LIB_LABEL[lib] if lib == "kev" else LIB_LABEL[lib].lower()
    unv = ('<button type="button" class="btn unvT" aria-pressed="false" title="Only records that are unverified '
           'or hold unverified entries">Unverified only</button>') if any(r["_unv"] or r["_nunv"] for r in data["libs"][lib]) else ""
    return (f'<section class="panel" id="tab-{lib}" role="tabpanel" hidden>{sub}'
            f'<header class="lhead"><h2>{LIB_LABEL[lib]}</h2><p class="lede">{e(LEDE[lib])}</p>{extra}</header>{after}'
            f'<div class="tools"><input type="search" class="q" placeholder="Search {noun}" aria-label="Search {noun}" '
            f'autocomplete="off" spellcheck="false">{unv}<button type="button" class="btn railT" aria-expanded="false">Filters</button>'
            '<span class="count" aria-live="polite"></span></div><div class="active"></div><div class="results"></div></section>')


def page(d: dict) -> tuple[str, dict]:
    data = build_data(d)
    libs = data["libs"]
    tab_n = {"intel": sum(len(libs[m]) for m in GROUPS["intel"]), "detections": len(libs["packs"]),
             "response": len(data["response"])}
    tabbar = "".join(f'<a href="#{t}" data-go="{t}" data-tab="{t}">{label}'
                     + (f'<span class="n">{tab_n.get(t, len(libs[t]) if t in libs else "")}</span>' if t != "start" else "")
                     + "</a>" for t, label in TABS)
    panels = f'<section class="panel" id="tab-start" role="tabpanel" hidden>{render_start(data)}</section>'
    for lib in LIBS:
        extra = render_kev_head(d) if lib == "kev" else render_cov_head(data) if lib == "coverage" else ""
        # the correlation block starts in the first intel library; the JS moves it to whichever is open
        panels += lib_panel(lib, data, extra, render_viz(data) if lib == GROUPS["intel"][0] else "")
    panels += ('<section class="panel" id="tab-response" role="tabpanel" hidden><header class="lhead"><h2>Response</h2>'
               '<p class="lede">Guidance, not automation. The order is fixed: safety first (agree the safe state and the '
               'manual fallback with operations), preserve, contain, rotate credentials, eradicate, recover, verify. '
               'Restoring a controller from a backup taken after the compromise reinstalls the attacker\'s logic.</p>'
               '</header><div id="respBody"></div></section>')
    built = _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%d")
    n_rules = len(libs["rules"])
    icon = ("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Crect width='32' "
            "height='32' rx='7' fill='%230b6b64'/%3E%3Cpath d='M7 22h4v-6h4v6h4V10h4v12h2' stroke='%23fff' "
            "stroke-width='2.4' fill='none' stroke-linejoin='round'/%3E%3C/svg%3E")
    li = linkedin()
    name, publisher = credit_parts()

    def who(key: str, text: str) -> str:
        url = li.get(key)
        return (f'<a href="{e(url)}" rel="noopener noreferrer" target="_blank" title="{e(text)} on LinkedIn">{e(text)}</a>'
                if url else e(text))
    doc = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>ICS DFIR Toolkit</title>
<meta name="description" content="A sourced DFIR knowledge base for industrial control systems and operational technology: platforms, protocols, data sources, threat intel, hunts, detections, hardening and response.">
<meta name="color-scheme" content="light">
<link rel="icon" href="{icon}">
<style>{css()}</style>
<script>try{{if(localStorage.getItem('icsdfir-theme')==='dark')document.documentElement.setAttribute('data-theme','dark')}}catch(e){{}}</script></head>
<body>
<a class="skip" href="#main">Skip to content</a>
<header class="hdr"><div class="hdr-in">
  <div class="brandrow"><a class="brand" href="#start" data-go="start"><span class="mark" aria-hidden="true"></span><h1>ICS DFIR Toolkit</h1></a>
    <span class="tagline">every claim quoted from its source &#183; safety before evidence</span>
    <div class="gs"><svg class="gsi" viewBox="0 0 16 16" aria-hidden="true"><circle cx="6.5" cy="6.5" r="4.5" fill="none" stroke="currentColor" stroke-width="1.8"/><path d="M10 10l4 4" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg>
      <input type="search" id="gq" placeholder="Search everything" aria-label="Search every library: title, id, summary, aliases, tags" role="combobox" aria-expanded="false" aria-controls="gres" aria-autocomplete="list" autocomplete="off" spellcheck="false">
      <kbd class="gsk" aria-hidden="true">/</kbd>
      <div class="gres" id="gres" role="listbox" aria-label="Search results" hidden></div></div>
    <span class="hright"><a class="btn" href="{REPO_URL}" rel="noopener noreferrer" target="_blank">GitHub</a>
    <button type="button" class="btn" id="themeBtn" aria-pressed="false" title="Switch between light and dark; your choice is remembered in this browser">Dark mode</button></span></div>
  <nav class="tabs" aria-label="Sections">{tabbar}</nav>
</div></header>
<div class="shell" id="shell">
  <aside class="rail" aria-label="Filters"><div id="rail"></div></aside>
  <main id="main" tabindex="-1"><noscript><p class="empty">The libraries need JavaScript. Every record is also in the repository as YAML.</p></noscript>{panels}</main>
</div>
<div class="scrim" id="scrim" hidden></div>
<aside class="drawer" id="drawer" hidden role="dialog" aria-modal="true" aria-labelledby="dTitle">
  <div class="dhead"><div class="dtl"><span class="cid" id="dId"></span><h2 id="dTitle" tabindex="-1"></h2></div>
    <div class="dacts"><button type="button" class="btn" id="dLink">Copy link</button><button type="button" class="btn" id="dClose" aria-label="Close (Esc)">&#215;</button></div></div>
  <div class="dbody" id="dBody"></div>
</aside>
<div class="toast" id="toast" role="status" hidden></div>
<footer><p>{len(libs['platforms'])} platforms &#183; {len(libs['protocols'])} protocols &#183; {len(libs['datasources'])} data sources &#183;
  {len(libs['actors'])} actors &#183; {len(libs['malware'])} malware families &#183; {len(libs['incidents'])} incidents &#183;
  {len(libs['iocs'])} indicator sets &#183; {len(libs['hunts'])} hunts &#183; {len(libs['packs'])} packs &#183; {n_rules} rule files &#183;
  {len(libs['hardening'])} hardening controls. Built from the repository on {built}; never edited by hand.
  Detections are Sigma, YARA and Suricata only.</p>
  <p class="credit">{who("profile", name)} · {who("company", publisher)} <span class="muted">(LinkedIn)</span> &#183;
  <a href="{REPO_URL}" rel="noopener noreferrer" target="_blank">source on GitHub</a> &#183; Apache-2.0.
  Keyboard: <kbd>/</kbd> or <kbd>Ctrl</kbd>+<kbd>K</kbd> search everything, <kbd>Esc</kbd> clear or close.</p></footer>
<script type="application/json" id="data">{js_data(data)}</script>
<script>{JS}</script>
</body></html>
"""
    return doc, data


# --------------------------------------------------------------------------- check
def js_facets(js: str) -> dict[str, list[str]]:
    """The facet keys the JS defines: lib('name', ...) followed by its facet('key', ...) calls."""
    out: dict[str, list[str]] = {}
    cur = None
    for m in re.finditer(r"\blib\('([a-z]+)'|\bfacet\('([a-z]+)'", js):
        if m.group(1):
            cur = m.group(1)
            out[cur] = []
        elif cur:
            out[cur].append(m.group(2))
    return out


def check(doc: str, data: dict) -> list[str]:
    problems = []
    want = {k: list(v) for k, v in FACET_KEYS.items()}
    got = js_facets(JS)
    if list(got) != list(want):
        problems.append(f"JS libraries {list(got)} differ from FACET_KEYS {list(want)}")
    for lib in want:
        if got.get(lib) is not None and got[lib] != want[lib]:
            problems.append(f"facets for {lib}: JS defines {got[lib]}, FACET_KEYS has {want[lib]}")
        if f'id="tab-{lib}"' not in doc:
            problems.append(f"no panel for library {lib}")
    static = re.sub(r"<script\b[^>]*>.*?</script>|<style>.*?</style>", "", doc, flags=re.S)
    ids = re.findall(r'\sid="([^"]+)"', static)
    dupes = sorted({i for i in ids if ids.count(i) > 1})
    if dupes:
        problems.append(f"duplicate element ids: {dupes}")
    bad = [i for i in ids if not re.fullmatch(r"[A-Za-z0-9_-]+", i)]
    if bad:
        problems.append(f"element ids that are not URL-safe: {bad}")
    if re.search(r"<script\b[^>]*\bsrc\s*=", doc, re.I) or re.search(r"<link\b[^>]*stylesheet", doc, re.I) \
            or re.search(r"@import|url\(\s*['\"]?(?:https?:)?//", static + css(), re.I):
        problems.append("the page must not load an external script, stylesheet or font")
    item_ids = {lib: [str(r["id"]) for r in data["libs"][lib]] for lib in LIBS}
    seen: dict[str, str] = {}
    for lib, lst in item_ids.items():
        for i in lst:
            if i in seen:
                problems.append(f"id {i} appears in {seen[i]} and {lib}")
            seen[i] = lib
    vals = facet_values(data)
    resp = {r["_id"] for r in data["response"]}

    def check_link(href: str, where: str) -> None:
        m = re.fullmatch(r"#([a-z]+)(?:/([^?]*))?(?:\?(.*))?", href)
        if not m:
            problems.append(f"{where}: malformed link {href}")
            return
        tab, anchor, query = m.groups()
        if not anchor and not query and f'id="{tab}"' in static and tab not in LIBS:
            return  # an in-page anchor such as the skip link
        if tab not in set(LIBS) | set(GROUPS) | {"start", "response"}:
            problems.append(f"{where}: link to unknown tab {href}")
            return
        if anchor and not ((tab in LIBS and anchor in item_ids[tab]) or (tab == "response" and anchor in resp)):
            problems.append(f"{where}: dangling link {href}")
        if query is None:
            return
        lib = GROUPS[tab][0] if tab in GROUPS else tab
        if lib not in LIBS:
            problems.append(f"{where}: filter on a tab that is not a library: {href}")
            return
        for kv in query.split("&"):
            k, _, v = kv.partition("=")
            if k in ("q", "unv"):
                continue
            if k not in FACET_KEYS[lib]:
                problems.append(f"{where}: {lib} has no facet {k!r} ({href})")
                continue
            for val in filter(None, v.split(",")):
                if unquote(val) not in vals[lib][k]:
                    problems.append(f"{where}: no {lib} record has {k}={unquote(val)} ({href})")

    for href in sorted(set(re.findall(r'href="(#[^"]*)"', static))):
        check_link(html.unescape(href), "page")
    for href in sorted(set(re.findall(r"'(#[a-z]+(?:/[^'?]*)?\?[^']*)'", JS))):
        check_link(href, "js")
    block = re.search(r'<script type="application/json" id="data">(.*?)</script>', doc, re.S)
    if not block:
        problems.append("data block missing or closed early")
    elif json.loads(block.group(1)) != data:
        problems.append("embedded data does not round-trip")
    cr = credit()
    footer = static.split("<footer>", 1)[-1]
    plain = re.sub(r"<[^>]+>", "", static)
    if not cr:
        problems.append("no 'Copyright <year> <name> and <publisher>' line in NOTICE for the credit")
    elif plain.count(e(cr)) != 1 or e(cr) not in re.sub(r"<[^>]+>", "", footer):
        problems.append("the credit line must appear once, in the footer")
    li = linkedin()
    for key, what in (("profile", "the maintainer's linkedin.com/in/ profile"), ("company", "the company's linkedin.com/company/ page")):
        if key not in li:
            problems.append(f"README.md's byline has no link to {what}; the footer reads both from there")
        elif f'href="{e(li[key])}"' not in footer:
            problems.append(f"the footer does not link {li[key]}")
    # correlations and the relationship map name only ids a library holds
    for rid, groups in data["rel"].items():
        bad = [x for lib, xs in groups.items() for x in xs if data["where"].get(x) != lib] + ([] if rid in data["where"] else [rid])
        if bad:
            problems.append(f"relationships of {rid} name unknown or misfiled ids: {bad}")
    for key, mz in data["viz"].items():
        if key == "timeline":
            bad = sorted({x["id"] for x in mz if data["where"].get(x["id"]) != "incidents"})
        else:
            bad = sorted({x for x in mz["rows"] + mz["cols"] if x not in data["where"]}
                         | {x for c in mz["cells"] for x in [c[0], c[1], *c[3]] if x not in data["where"]})
        if bad:
            problems.append(f"matrix {key} names unknown ids: {bad}")
    if 'id="viz-intel"' not in doc or doc.count('class="tm"') != len(data["viz"]["timeline"]) \
            or 'id="viz-cov"' not in doc or doc.count('class="cc cc-') != len(data["libs"]["coverage"]):
        problems.append("the correlation block, the timeline markers or the technique grid do not match the data")
    if any("_s" not in r or r["_title"] not in r["_s"] or str(r["id"]) not in r["_s"] for lib in LIBS for r in data["libs"][lib]):
        problems.append("a record is missing its global-search text (_s with title and id)")
    return problems


# --------------------------------------------------------------------------- CSS
DARK = ("--bg:#0f141a;--panel:#18202a;--panel2:#212b37;--ink:#e5eaf0;--muted:#a7b1be;--line:#3d4959;--line2:#2c3644;"
        "--accent:#45c4b5;--accent-bg:#133631;--on-accent:#06201d;--link:#8cc2f5;--ok:#7ad796;--ok-bg:#14301d;"
        "--info:#95c3f7;--info-bg:#152a44;--warn:#f2c46a;--warn-bg:#35290d;--bad:#ff9d92;--bad-bg:#3d1917;"
        "--v-manip:#199e70;--v-control:#3987e5;--v-outage:#d95926;"
        "--shadow:0 10px 30px rgba(0,0,0,.55);color-scheme:dark")
BASE_CSS = r"""
:root{--bg:#f5f6f8;--panel:#fff;--panel2:#eef1f4;--ink:#17202b;--muted:#525e6d;--line:#cfd6de;--line2:#e2e6eb;
--accent:#0b6b64;--accent-bg:#e0f1ef;--on-accent:#fff;--link:#0a5aa0;--ok:#1b6a35;--ok-bg:#e0f2e5;--info:#1a5aa1;
--info-bg:#e2ecf8;--warn:#7a5000;--warn-bg:#fbeecf;--bad:#9e1d15;--bad-bg:#fae3e1;--shadow:0 10px 30px rgba(15,25,40,.18);
--v-manip:#1baf7a;--v-control:#2a78d6;--v-outage:#eb6834;
--mono:ui-monospace,SFMono-Regular,Menlo,Consolas,"Liberation Mono",monospace;
--sans:system-ui,-apple-system,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;
--fs-xs:11.5px;--fs-sm:12.5px;--fs-md:13.5px;--fs-base:15px;--fkw:150px;color-scheme:light}
*{box-sizing:border-box}html{-webkit-text-size-adjust:100%;scroll-padding-top:116px}
body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 var(--sans)}
a{color:var(--link)}code,pre,kbd{font-family:var(--mono);font-size:.88em}
kbd{border:1px solid var(--line);border-radius:4px;padding:0 4px;background:var(--panel2)}
h1,h2,h3,h4{line-height:1.25}.small{font-size:13px}.muted{color:var(--muted)}
.skip{position:absolute;left:-9999px}.skip:focus{left:8px;top:8px;z-index:99;background:var(--panel);padding:6px 10px}
.hdr{position:sticky;top:0;z-index:20;background:var(--panel);border-bottom:1px solid var(--line)}
.hdr-in{max-width:1440px;margin:0 auto;padding:10px 16px 0}
.brandrow{display:flex;align-items:center;gap:12px;min-width:0}
.brand{display:flex;align-items:center;gap:10px;color:var(--ink);text-decoration:none;flex-shrink:0}
.brand h1{font-size:18px;margin:0}.mark{width:22px;height:22px;border-radius:6px;background:var(--accent);
box-shadow:inset 0 -7px 0 rgba(0,0,0,.18)}
.tagline{color:var(--muted);font-size:13px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;min-width:0;flex:0 1 auto}
.hright{margin-left:auto;display:flex;gap:8px;flex-shrink:0}
.btn{font:inherit;font-size:13px;line-height:1.4;padding:5px 10px;border:1px solid var(--line);border-radius:6px;
background:var(--panel);color:var(--ink);cursor:pointer;text-decoration:none;white-space:nowrap}
.btn:hover,.btn:focus-visible{border-color:var(--accent)}.btn[aria-pressed=true]{background:var(--warn-bg);border-color:var(--warn)}
#themeBtn[aria-pressed=true]{background:var(--accent-bg);border-color:var(--accent)}
.gs{position:relative;flex:1 1 200px;max-width:440px;min-width:0;margin-left:auto}
.gs input{width:100%;font:inherit;font-size:14px;padding:6px 30px 6px 30px;border:1px solid var(--line);border-radius:8px;background:var(--bg);color:var(--ink)}
.gs input:focus{outline:2px solid var(--accent);outline-offset:-1px;background:var(--panel)}
.gsi{position:absolute;left:9px;top:50%;width:15px;height:15px;transform:translateY(-50%);color:var(--muted);pointer-events:none}
.gsk{position:absolute;right:8px;top:50%;transform:translateY(-50%);font-size:11px;color:var(--muted);pointer-events:none;line-height:1.3}
.gs input:focus~.gsk{display:none}
.gres{position:absolute;top:calc(100% + 6px);right:0;width:min(560px,calc(100vw - 24px));max-height:min(72vh,620px);overflow:auto;
background:var(--panel);border:1px solid var(--line);border-radius:10px;box-shadow:var(--shadow);z-index:50;padding:6px;text-align:left}
.gres[hidden]{display:none}.gsn{padding:8px 10px;color:var(--muted);font-size:var(--fs-sm);display:flex;justify-content:space-between;gap:8px;flex-wrap:wrap}
.gsg+.gsg{border-top:1px solid var(--line2);margin-top:4px;padding-top:4px}
.gsh{display:flex;justify-content:space-between;padding:6px 10px 2px;font-size:var(--fs-xs);font-weight:700;text-transform:uppercase;letter-spacing:.06em;color:var(--muted)}
.gsr{display:grid;grid-template-columns:fit-content(38%) minmax(0,1fr);gap:2px 10px;padding:6px 10px;border-radius:7px;text-decoration:none;color:var(--ink);align-items:baseline}
.gsr .cid{margin:0;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.gsr .gst{font-size:14px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.gsr .gss{grid-column:2;font-size:var(--fs-sm);color:var(--muted);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.gsr:hover,.gsr.on{background:var(--panel2)}.gsr.on{outline:2px solid var(--accent);outline-offset:-2px}
.gsr mark{background:var(--warn-bg);color:inherit;border-radius:2px;padding:0 1px}
.gsall{display:block;padding:4px 10px 6px;font-size:var(--fs-sm)}
.tabs{display:flex;gap:2px;overflow-x:auto;margin-top:6px;scrollbar-width:thin}
.tabs a{white-space:nowrap;padding:8px 11px 7px;color:var(--muted);text-decoration:none;border-bottom:3px solid transparent;
font-weight:600;font-size:14px}.tabs a:hover{color:var(--ink)}
.tabs a[aria-current]{color:var(--ink);border-bottom-color:var(--accent)}
.n{font-weight:500;color:var(--muted);font-size:12px;margin-left:5px;font-variant-numeric:tabular-nums}
.shell{max-width:1440px;margin:0 auto;padding:18px 16px;display:grid;grid-template-columns:240px minmax(0,1fr);gap:22px;align-items:start}
.shell.norail{grid-template-columns:minmax(0,1fr)}.shell.norail .rail{display:none}
.rail{position:sticky;top:104px;max-height:calc(100vh - 120px);overflow:auto;padding:2px 4px 12px 0}
main{min-width:0}main:focus{outline:none}
/* facet rail: one type scale per level (group header, option label, count), one left edge, one group gap */
.fg{border:0;margin:0 0 18px;padding:0;min-width:0}.fg:last-child{margin-bottom:0}
.fg legend{font-size:var(--fs-xs);line-height:1.4;font-weight:700;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);padding:0;margin:0 0 4px 6px}
.fv{display:flex;align-items:center;gap:8px;padding:3px 6px;border-radius:5px;cursor:pointer;font-size:var(--fs-md);line-height:1.4;min-height:26px}
.fv:hover{background:var(--panel2)}.fv.on{background:var(--accent-bg)}.fv.zero{opacity:.55}
.fv input{margin:0;width:14px;height:14px;accent-color:var(--accent);flex-shrink:0}
.fl{flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:var(--fs-md);text-align:left}
.fc{color:var(--muted);font-size:var(--fs-sm);font-variant-numeric:tabular-nums;min-width:2.5ch;text-align:right;flex-shrink:0}
.lnk{font:inherit;font-size:var(--fs-sm);line-height:1.4;background:none;border:0;padding:3px 6px;color:var(--link);cursor:pointer;text-decoration:underline}
.fg .lnk{padding-left:28px}
.lhead h2{margin:0 0 4px;font-size:22px}.lede{margin:0 0 12px;color:var(--muted);max-width:85ch}
.subnav{display:flex;gap:6px;flex-wrap:wrap;margin-bottom:14px}
.subnav a{padding:4px 12px;border:1px solid var(--line);border-radius:999px;text-decoration:none;color:var(--ink);
font-size:13.5px;background:var(--panel)}.subnav a[aria-current]{background:var(--accent);border-color:var(--accent);color:var(--on-accent)}
.subnav a[aria-current] .n{color:inherit}
.tools{display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-bottom:8px}
.q{flex:1 1 260px;min-width:0;font:inherit;padding:7px 10px;border:1px solid var(--line);border-radius:6px;background:var(--panel);color:var(--ink)}
.q:focus{outline:2px solid var(--accent);outline-offset:-1px}.count{color:var(--muted);font-size:13px}.railT{display:none}
.active{display:flex;gap:6px;flex-wrap:wrap;margin-bottom:10px;align-items:center}
.achip{display:inline-flex;align-items:center;gap:4px;font-size:12.5px;padding:1px 4px 1px 9px;border-radius:999px;background:var(--accent-bg);border:1px solid var(--accent)}
.achip button{border:0;background:none;color:var(--ink);cursor:pointer;font-size:14px;line-height:1;padding:0 4px}
.lgrid{display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:12px}
.card{display:flex;flex-direction:column;gap:6px;background:var(--panel);border:1px solid var(--line);border-radius:8px;
padding:12px 14px;text-decoration:none;color:var(--ink);min-width:0}
.card:hover,.card:focus-visible{border-color:var(--accent)}.card.sel{outline:2px solid var(--accent);outline-offset:-1px}
.card.unv,.sub.unv{border-left:4px solid var(--warn)}.card h3{margin:0;font-size:15.5px}
.cmeta{font-size:12px;color:var(--muted);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.cid{font-family:var(--mono);font-size:11.5px;color:var(--accent);font-weight:700;margin-right:6px}
.clamp{margin:0;font-size:13.5px;color:var(--muted);display:-webkit-box;-webkit-line-clamp:3;-webkit-box-orient:vertical;overflow:hidden;overflow-wrap:anywhere}
.cbadges{display:flex;gap:5px;flex-wrap:wrap;align-items:center;margin-top:auto}
.b{display:inline-block;font-family:var(--sans);font-size:11.5px;font-weight:650;line-height:1.55;padding:0 7px;border-radius:999px;
border:1px solid currentColor;white-space:nowrap;vertical-align:baseline}
.c-high,.imp-passive,.rd-direct,.k-government,.k-vendor{color:var(--ok);background:var(--ok-bg)}
.c-medium,.imp-read-only,.t-possible,.k-researcher,.k-standard{color:var(--info);background:var(--info-bg)}
.imp-online-vendor-tool,.unvb,.rd-summariser,.t-likely,.st-blind,.dec-deferred,.neq,.k-press,.inf{color:var(--warn);background:var(--warn-bg)}
.c-low,.imp-process-risk,.gapb,.st-gap,.t-confirmed,.pri-critical{color:var(--bad);background:var(--bad-bg)}
.unvb{text-transform:uppercase;letter-spacing:.04em}.soft{font-weight:600;text-transform:none;letter-spacing:0}
.chip{display:inline-flex;gap:5px;align-items:baseline;font-size:12.5px;padding:1px 8px;border-radius:5px;background:var(--panel2);
border:1px solid var(--line2);color:var(--ink);text-decoration:none;max-width:100%;min-width:0}
a.chip:hover{border-color:var(--accent)}.chip .cid{margin:0}
.chip .cn{color:var(--muted);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:30ch}
.chips,.idl{display:flex;flex-wrap:wrap;gap:5px}.xref{font-family:var(--mono);font-size:.9em}
.empty{padding:24px;text-align:center;color:var(--muted);background:var(--panel);border:1px dashed var(--line);border-radius:8px}
.tbl{overflow-x:auto;border:1px solid var(--line);border-radius:8px;background:var(--panel)}
table{border-collapse:collapse;width:100%;font-size:13.5px}
th,td{text-align:left;vertical-align:top;padding:7px 10px;border-bottom:1px solid var(--line2)}
th{font-size:11.5px;text-transform:uppercase;letter-spacing:.05em;color:var(--muted);background:var(--panel2);white-space:nowrap}
tr.item{cursor:pointer}tr.item:hover td{background:var(--panel2)}tr.sel td{background:var(--accent-bg)}
td a.open{font-family:var(--mono);font-weight:700;white-space:nowrap}td .b{margin:2px 2px 0 0}
.scrim{position:fixed;inset:0;background:rgba(8,12,18,.38);z-index:30}
.drawer{position:fixed;top:0;right:0;bottom:0;width:min(800px,100%);background:var(--panel);border-left:1px solid var(--line);
box-shadow:var(--shadow);z-index:40;display:flex;flex-direction:column}.drawer[hidden],.scrim[hidden]{display:none}
.dhead{display:flex;gap:10px;align-items:flex-start;padding:14px 18px 12px;border-bottom:1px solid var(--line)}
.dtl{min-width:0}.dhead h2{margin:3px 0 0;font-size:19px;outline:none;overflow-wrap:anywhere}
.dacts{margin-left:auto;display:flex;gap:6px;flex-shrink:0}
.dbody{overflow:auto;padding:12px 18px 48px;overflow-wrap:anywhere;flex:1}
.dbadges{display:flex;gap:6px;flex-wrap:wrap;align-items:center}
/* drawer fields: one label column width at every depth, label and value on one baseline grid */
.fields{display:flex;flex-direction:column;gap:10px;margin:14px 0}
.fld{display:grid;grid-template-columns:var(--fkw) minmax(0,1fr);gap:16px;align-items:start}
.fkey{font-size:var(--fs-sm);line-height:22.5px;font-weight:650;color:var(--muted);overflow-wrap:anywhere}.fval{min-width:0;line-height:22.5px}
.fval .chips,.fval .idl{padding-top:2px}
.txt{margin:0;white-space:pre-line}.fval code.blk{display:inline-block;white-space:pre-wrap;background:var(--panel2);padding:1px 6px;border-radius:4px}
.f-suspicious>.fkey,.f-gap>.fkey{color:var(--bad)}.f-normal>.fkey{color:var(--ok)}.f-safety_note>.fkey{color:var(--warn)}
.callout{margin:0;padding:8px 11px;border-radius:6px;border:1px solid var(--warn);background:var(--warn-bg)}
.subs{display:flex;flex-direction:column;gap:8px}.sub{border:1px solid var(--line2);border-radius:7px;padding:9px 11px;background:var(--panel2)}
.subh{display:flex;gap:6px;flex-wrap:wrap;align-items:baseline}.subh>b{margin-right:4px}
.sub .fields{gap:5px;margin:7px 0 0}.sub .fld{grid-template-columns:calc(var(--fkw) - 12px) minmax(0,1fr)}
blockquote{margin:6px 0 0;padding:6px 10px;border-left:3px solid var(--accent);background:var(--panel2);font-size:13.5px;white-space:pre-line}
.sub blockquote{background:var(--panel)}
.srcs{margin:0;padding-left:20px;display:flex;flex-direction:column;gap:10px}.srch{display:flex;gap:6px;flex-wrap:wrap;align-items:baseline}
.sec h3{font-size:12px;text-transform:uppercase;letter-spacing:.07em;color:var(--muted);border-top:1px solid var(--line2);padding-top:14px;margin:20px 0 8px}
.bul,.plain{margin:0;padding-left:18px}.plain{list-style:none;padding:0}.bul li+li,ol.steps>li+li{margin-top:4px}
pre.code{margin:6px 0;padding:10px 12px;background:var(--panel2);border:1px solid var(--line2);border-radius:6px;overflow:auto;
max-height:540px;font-size:12.5px;line-height:1.45;white-space:pre;overflow-wrap:normal}
details.rule{border:1px solid var(--line2);border-radius:6px;padding:4px 8px;background:var(--panel)}details.rule+details.rule{margin-top:6px}
details.rule summary{cursor:pointer;font-size:13px}.rulelist{display:flex;flex-direction:column}
.iocs table code{font-size:12.5px}.ioc-tools{display:flex;gap:6px;flex-wrap:wrap;margin-bottom:6px}td.ctx{font-size:12.5px;color:var(--muted);min-width:220px}
.hero,.box{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:16px 18px}
.hero{margin-bottom:16px}.hero h2{font-size:22px;margin:0 0 8px}.hero p{margin:0;max-width:95ch}
.warnbox{border:1px solid var(--warn);background:var(--warn-bg);border-radius:8px;padding:9px 13px;margin-top:12px;font-size:14px}
.tiles{display:grid;grid-template-columns:repeat(auto-fill,minmax(165px,1fr));gap:10px;margin:0 0 16px}
.tile{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:10px 12px}
.tile:hover{border-color:var(--accent)}.tl{display:block;text-decoration:none;color:var(--ink)}
.tl b{display:block;font-size:24px;line-height:1.15;font-variant-numeric:tabular-nums}.tl span{font-weight:650}
.tl small{display:block;color:var(--muted);font-size:12px}.tu{display:inline-block;margin-top:4px;font-size:12px;color:var(--warn)}
.cols{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,300px),1fr));gap:14px;margin-bottom:14px}
.cols.wide{grid-template-columns:minmax(0,1.15fr) minmax(0,1fr);align-items:start}.cols.wide>div{display:flex;flex-direction:column;gap:14px}
.box h3{margin:0 0 8px;font-size:16px}.box p{margin:6px 0 0}.rulebox{border-top:4px solid var(--accent)}
.ladder{list-style:none;margin:10px 0 0;padding:0;display:flex;flex-direction:column;gap:8px}
.rung{display:flex;gap:12px;padding:9px 12px;border-radius:7px;border-left:6px solid}.rung p{margin:4px 0 0}
.rn{font-weight:800;font-size:18px;line-height:1.3;min-width:14px}
.rung-passive{border-color:var(--ok);background:var(--ok-bg)}.rung-read-only{border-color:var(--info);background:var(--info-bg)}
.rung-online-vendor-tool{border-color:var(--warn);background:var(--warn-bg)}.rung-process-risk{border-color:var(--bad);background:var(--bad-bg)}
.conf li{margin:4px 0}.gapl li{margin:6px 0}
.stats{display:flex;gap:8px;flex-wrap:wrap;margin:4px 0 8px}
.stat{padding:4px 12px;border-radius:7px;border:1px solid var(--line);background:var(--panel);text-decoration:none;color:var(--ink);font-size:14px}
.st-bad{border-color:var(--bad);color:var(--bad);background:var(--bad-bg)}.st-warn{border-color:var(--warn);color:var(--warn);background:var(--warn-bg)}
details.box{padding:8px 12px;margin-bottom:12px}details.box summary{cursor:pointer}details.box .tbl{margin-top:8px}
.pb{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:16px 18px;margin-bottom:16px;overflow-wrap:anywhere}
.pbh{display:flex;gap:8px;flex-wrap:wrap;align-items:center}.pbh h3{margin:0;font-size:19px}
.phase h4{display:flex;align-items:center;gap:8px;margin:18px 0 6px;font-size:15px}
.pn{display:inline-grid;place-items:center;width:24px;height:24px;border-radius:50%;background:var(--accent);color:var(--on-accent);font-size:13px}
ol.steps{margin:0;padding-left:22px}ol.steps p,ul.steps p{margin:2px 0 4px}.donot h4{color:var(--bad)}
.donot ul{margin:0;padding-left:18px}.donot li{margin-bottom:6px}
.toast{position:fixed;left:50%;bottom:22px;transform:translateX(-50%);background:var(--ink);color:var(--bg);padding:8px 14px;
border-radius:6px;z-index:60;font-size:13px;max-width:calc(100% - 32px);overflow-wrap:anywhere}
footer{max-width:1440px;margin:12px auto 0;padding:14px 16px 28px;border-top:1px solid var(--line);color:var(--muted);font-size:12.5px}
footer p{margin:4px 0}footer .credit a{color:var(--ink);font-weight:600}
/* correlations: matrices scroll inside their box, never the page */
.viz{margin:0 0 14px;border:1px solid var(--line);border-radius:10px;background:var(--panel)}
.viz>summary{cursor:pointer;padding:10px 14px;font-weight:600;font-size:14px;list-style-position:inside}
.vizb{padding:2px 14px 14px;display:flex;flex-direction:column;gap:18px}.vizb>p{margin:0}
.vizs h4{margin:0 0 2px;font-size:15px}.vizs>p{margin:0 0 8px;max-width:95ch}
.mxs{overflow-x:auto;border:1px solid var(--line2);border-radius:8px;max-width:100%}
table.mx{border-collapse:separate;border-spacing:0;font-size:var(--fs-sm);width:auto;min-width:100%;background:var(--panel)}
.mx th,.mx td{padding:2px;border-bottom:1px solid var(--line2);text-align:center;vertical-align:middle;background:var(--panel);
text-transform:none;letter-spacing:0;white-space:nowrap}
.mx thead th{vertical-align:bottom;padding:8px 2px 4px;color:var(--muted);font-size:var(--fs-xs);font-weight:500;background:var(--panel)}
.mx th.ch{width:30px;min-width:30px;max-width:30px}
.mx th.ch span{display:inline-block;writing-mode:vertical-rl;transform:rotate(180deg);max-height:190px;overflow:hidden;text-overflow:ellipsis;line-height:1.15}
.mx th.ch a{color:var(--ink);text-decoration:none}.mx th.ch a:hover span,.mx th.ch a:focus-visible span{color:var(--link);text-decoration:underline}
.mx th.rh{text-align:left;position:sticky;left:0;z-index:1;font-weight:500;font-size:var(--fs-md);padding:2px 10px 2px 8px;color:var(--ink);
max-width:190px;overflow:hidden;text-overflow:ellipsis;box-shadow:1px 0 0 var(--line2)}
.mx th.rh a{color:inherit;text-decoration:none}.mx th.rh a:hover{color:var(--link);text-decoration:underline}
.mx tfoot th.rh{font-size:var(--fs-xs);color:var(--muted);font-weight:500}
.mx tbody tr:hover>*{background:var(--panel2)}
.mx td.e{background:var(--panel)}.mx td.e::after{content:"";display:inline-block;width:4px;height:4px;border-radius:50%;background:var(--line)}
.mx tbody tr:hover td.e{background:var(--panel2)}
.mx td.tot,.mx th.tot{font-variant-numeric:tabular-nums;color:var(--muted);font-size:var(--fs-sm);padding:2px 10px;font-weight:500}
.mc{display:inline-grid;place-items:center;width:26px;height:26px;border-radius:5px;text-decoration:none;color:var(--ink);font-size:var(--fs-xs);
font-weight:700;font-variant-numeric:tabular-nums;background:color-mix(in srgb,var(--accent) var(--h,30%),var(--panel))}
.mc.dk{color:var(--on-accent)}.mc.via{background:transparent;box-shadow:inset 0 0 0 2px color-mix(in srgb,var(--accent) 60%,var(--panel));color:var(--muted)}
a.mc:hover,a.mc:focus-visible{box-shadow:inset 0 0 0 2px var(--ink);outline:none}
.tlw{overflow-x:auto}.tlx{display:block;width:100%;min-width:720px;height:auto}
.tlx text{fill:var(--muted);font-size:12px;font-family:var(--sans)}.tlx .ax{stroke:var(--line);stroke-width:1.2}.tlx .tk{stroke:var(--line)}
.tlx .stem{stroke:var(--line);stroke-width:1;stroke-dasharray:2 3;pointer-events:none}.tlx .hit{fill:transparent;stroke:none}
.tlx .mk{stroke:var(--ink);stroke-width:1}.tlx a.tm:hover .mk,.tlx a.tm:focus .mk{stroke-width:3}.tlx a.tm:focus{outline:none}
.mk-outage{fill:var(--v-outage)}.mk-control{fill:var(--v-control)}.mk-manip{fill:var(--v-manip)}.mk-none{fill:var(--panel);stroke:var(--muted);stroke-width:2}
.tlg{display:flex;flex-direction:column;gap:4px;margin-top:6px;font-size:var(--fs-sm);color:var(--muted)}
.tll{display:flex;gap:6px;align-items:baseline;flex-wrap:wrap}.tlx.lgm{width:16px;height:16px;min-width:0;flex-shrink:0;align-self:center;display:inline-block}
/* ATT&CK grid */
.cglg{display:flex;gap:6px 16px;flex-wrap:wrap;font-size:var(--fs-sm);color:var(--muted);align-items:center}
.cglg .lg{display:inline-flex;align-items:center;gap:6px;text-decoration:none;color:var(--muted)}.cglg a.lg:hover{color:var(--link);text-decoration:underline}
.cglg i{display:inline-block;width:13px;height:13px;border-radius:3px;border:1px solid transparent}.cglg b{color:var(--ink)}
.covgrid{display:flex;flex-direction:column;gap:12px}
.cg h4{margin:0 0 6px;font-size:var(--fs-xs);font-weight:700;color:var(--muted);text-transform:uppercase;letter-spacing:.06em}
.cells{display:grid;grid-template-columns:repeat(auto-fill,minmax(82px,1fr));gap:4px}
.cc{display:block;padding:4px 4px;border-radius:5px;font-family:var(--mono);font-size:var(--fs-xs);font-weight:700;text-decoration:none;text-align:center;
border:1px solid transparent;color:var(--ink);background:var(--panel2);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.cc-gap{background:var(--bad-bg);color:var(--bad);border-color:var(--bad)}
.cc-blind{background:var(--warn-bg);color:var(--warn);border-color:var(--warn);border-style:dashed}
.cc-detected{background:var(--ok-bg);color:var(--ok)}.cc-hunted{background:var(--info-bg);color:var(--info)}
.cc-seen{background:var(--accent-bg);color:var(--accent)}.cc.bl{border-style:dashed;border-color:currentColor}
a.cc:hover,a.cc:focus-visible{border-color:var(--ink);outline:none}.cc.sel{outline:2px solid var(--ink);outline-offset:1px}
@media (max-width:1100px){.tagline{display:none}}
@media (max-width:900px){.shell{grid-template-columns:minmax(0,1fr);padding:12px}
.rail{position:static;max-height:none;display:none;border:1px solid var(--line);border-radius:8px;padding:10px 10px 12px;background:var(--panel)}
.shell.railopen:not(.norail) .rail{display:block}.railT{display:inline-block}.cols.wide{grid-template-columns:minmax(0,1fr)}}
@media (max-width:600px){.fld,.sub .fld{grid-template-columns:minmax(0,1fr);gap:1px}.fkey,.fval{line-height:1.5}
.hdr-in{padding:8px 12px 0;position:relative}.dhead,.dbody{padding-left:12px;padding-right:12px}.lgrid{grid-template-columns:minmax(0,1fr)}
.brandrow{flex-wrap:wrap;gap:8px 10px}.gs{order:3;flex:1 1 100%;max-width:none;position:static}.hright{margin-left:auto}
.gres{left:12px;right:12px;width:auto;top:calc(100% - 44px)}.gs .gsk{display:none}.vizb{padding:2px 10px 12px}.viz>summary{padding:9px 10px}}
"""


def css() -> str:
    """Light by default; dark only when the viewer chose it (the head script restores the choice)."""
    return BASE_CSS + ":root[data-theme=dark]{" + DARK + "}"


# --------------------------------------------------------------------------- JS
JS = r"""
(function(){
'use strict';
var D = JSON.parse(document.getElementById('data').textContent);
var WHERE = D.where, NAMES = D.names, SHORT = D.short, GROUPS = D.groups, RULES = {}, BYID = {}, TABOF = {};
D.libs.rules.forEach(function(r){ RULES[r.id] = r; });
Object.keys(GROUPS).forEach(function(g){ GROUPS[g].forEach(function(m){ TABOF[m] = g; }); });

/* ---------------------------------------------------------------- DOM: text nodes only */
function $(id){ return document.getElementById(id); }
function add(el, k){
  if (k == null || k === false || k === '') return;
  if (Array.isArray(k)){ for (var i = 0; i < k.length; i++) add(el, k[i]); return; }
  el.appendChild(k.nodeType ? k : document.createTextNode(String(k)));
}
function h(tag, a, kids){
  var el = document.createElement(tag);
  if (a) Object.keys(a).forEach(function(k){
    var v = a[k];
    if (v == null || v === false) return;
    if (k === 'class') el.className = v;
    else if (k.slice(0, 2) === 'on') el.addEventListener(k.slice(2), v);
    else el.setAttribute(k, v === true ? '' : String(v));
  });
  add(el, kids);
  return el;
}
function clear(el){ while (el.firstChild) el.removeChild(el.firstChild); return el; }
function nice(v){ return String(v).replace(/[-_]/g, ' '); }
function nm(id){ return NAMES[id] || id; }
function pshort(id){ return id === 'ALL' ? 'All platforms' : (SHORT[id] || nm(id)); }
function lv(l){ return (l || []).length ? 'Purdue ' + l.map(function(x){ return 'L' + x; }).join('/') : ''; }
var LABELS = {attack:'ATT&CK', cves:'CVEs', iocs:'Indicator sets', ics_effects:'ICS effects', purdue_levels:'Purdue levels',
  os_base:'OS base', ics_kill_chain_stage:'ICS kill chain stage', kev_vendor:'KEV vendor', kev_product:'KEV product',
  kev_date_added:'Added to KEV', zeek_field:'Zeek field', attack_url:'ATT&CK page', attack_data_components:'ATT&CK data components',
  datasources:'Data sources', upstream_sha256:'Upstream file SHA-256', sids:'Suricata sids', msgs:'Alert messages', url:'URL',
  page_url:'Advisory page', file_url:'Indicator file', set_summary:'About this set', set:'Control set', platform_id:'Platform',
  runs_on:'Runs on', do_not:'Do not', text:'Rule text', yara_rules:'YARA rules', link_confidence:'Link confidence',
  stated_confidence:'Stated confidence (verbatim)', state_nexus:'State nexus', ledger:'Ledger', tlp:'TLP'};
function label(k){ return LABELS[k] || (k.charAt(0).toUpperCase() + k.slice(1)).replace(/_/g, ' '); }
var XREF = /\b(?:ICS-(?:PROTO|DS|TA|MAL|IOC|INC|HUNT|PACK)-\d{4}|ICS-\d{4}|CVE-\d{4}-\d{4,}|T\d{4}(?:\.\d{3})?)\b|\b\d{2}-[a-z0-9-]+\/[a-z0-9_]+\.(?:yml|yar|rules)\b/g;
function xref(id, text){
  if (!WHERE[id]) return h('span', {class:'xref', title:'No record for this id in the knowledge base yet'}, id);
  return h('a', {class:text ? null : 'xref', href:'#' + WHERE[id] + '/' + id, title:nm(id)}, text || id);
}
function xchip(id){
  if (id === 'ALL') return h('span', {class:'chip'}, 'All platforms');
  if (!WHERE[id]) return h('span', {class:'chip', title:'No record for this id in the knowledge base yet'}, h('span', {class:'cid'}, id));
  var name = SHORT[id] || NAMES[id];
  return h('a', {class:'chip xc', href:'#' + WHERE[id] + '/' + id, title:nm(id)}, [h('span', {class:'cid'}, id), name && name !== id ? h('span', {class:'cn'}, name) : null]);
}
function linkify(s){
  s = String(s); var out = [], last = 0, m; XREF.lastIndex = 0;
  while ((m = XREF.exec(s))){
    if (m.index > last) out.push(s.slice(last, m.index));
    out.push(WHERE[m[0]] ? xref(m[0]) : m[0]);
    last = m.index + m[0].length;
  }
  if (last < s.length) out.push(s.slice(last));
  return out;
}
function ext(u, text){ return /^https:\/\//.test(u) ? h('a', {href:u, rel:'noopener noreferrer', target:'_blank'}, text || u) : h('span', null, text || u); }
function plural(n, w){ return n + ' ' + w + (n === 1 ? '' : 's'); }
function badge(t, cls, tip){ return h('span', {class:'b ' + cls, title:tip || null}, t); }
function chipT(t, tip){ return h('span', {class:'chip', title:tip || null}, t); }
function confB(c){ return c ? badge(c + ' confidence', 'c-' + c, D.conf[c]) : null; }
function unvB(){ return badge('unverified', 'unvb', 'Single-source, inferred, or read only through a summariser: check it before relying on it'); }
function impB(i){ return badge(i, 'imp imp-' + i, D.impact[i]); }
function tierB(t){ return badge(t, 't-' + t, 'Detection tier'); }
function nunvB(r){ return r._nunv ? badge(r._nunv + ' unverified ' + (r._nunv === 1 ? 'entry' : 'entries'), 'unvb soft', 'Entries inside this record carry unverified: true') : null; }
function fileLink(f){ return ext(D.repo + '/blob/main/' + f, f); }

/* ---------------------------------------------------------------- indicators */
function defang(t, v){
  v = String(v);
  if (t === 'url') return v.replace(/^http/i, 'hxxp').replace(/^(hxxps?:\/\/[^\/:?#]*)\.([^.\/:?#]+)/i, '$1[.]$2');
  if (t === 'ipv4' || t === 'cidr' || t === 'domain') return v.replace(/\.(?=[^.]*$)/, '[.]');
  if (t === 'ipv6') return v.replace(':', '[:]');
  if (t === 'account') return v.replace('@', '[@]');
  return v;
}
function refang(s){ return String(s).replace(/\[\.\]|\(\.\)|\[dot\]/gi, '.').replace(/\[:\]/g, ':').replace(/\[@\]/g, '@').replace(/\bhxxp/gi, 'http'); }
var ROLE = {'actor-controlled':'The publisher says the actor controls it', 'compromised-infrastructure':'A compromised third party: its owner may be a victim',
  anonymiser:'An anonymising or VPN exit shared with legitimate users', 'multi-tenant':'Shared hosting or cloud with unrelated tenants',
  suspected:'The publisher marks it suspected', unknown:'The publisher gives no role'};
function csvCell(v){ v = v == null ? '' : String(v); return /[",\n]/.test(v) ? '"' + v.replace(/"/g, '""') + '"' : v; }
function iocCSV(r){
  return ['type,value,role,first_seen,last_seen,context'].concat(r.indicators.map(function(i){
    return [i.type, refang(i.value), i.role, i.first_seen, i.last_seen, i.context].map(csvCell).join(','); })).join('\n') + '\n';
}
function iocJSON(r){
  return JSON.stringify({id:r.id, title:r.title, publisher:r.publisher, published:r.published, page_url:r.page_url, file_url:r.file_url,
    license:r.license, staleness:r.staleness, indicators:r.indicators.map(function(i){ var o = {}; Object.keys(i).forEach(function(k){ o[k] = k === 'value' ? refang(i[k]) : i[k]; }); return o; })}, null, 2) + '\n';
}
function download(name, text, type){
  var a = h('a', {href:URL.createObjectURL(new Blob([text], {type:type})), download:name});
  document.body.appendChild(a); a.click();
  setTimeout(function(){ URL.revokeObjectURL(a.href); a.remove(); }, 0);
}
function indicators(r){
  var rows = r.indicators.map(function(i){
    return h('tr', null, [h('td', null, i.type), h('td', null, h('code', null, defang(i.type, i.value))),
      h('td', null, badge(i.role, i.role === 'actor-controlled' ? 'c-low' : 'k-researcher', ROLE[i.role])),
      h('td', {class:'small'}, (i.first_seen || '') + (i.last_seen && i.last_seen !== i.first_seen ? ' \u2013 ' + i.last_seen : '')),
      h('td', {class:'ctx'}, i.context ? linkify(i.context) : '')]);
  });
  return h('div', {class:'iocs'}, [
    h('div', {class:'ioc-tools'}, [
      h('button', {type:'button', class:'btn', onclick:function(){ download(r.id + '.csv', iocCSV(r), 'text/csv'); }}, 'Export CSV (refanged)'),
      h('button', {type:'button', class:'btn', onclick:function(){ download(r.id + '.json', iocJSON(r), 'application/json'); }}, 'Export JSON (refanged)'),
      h('button', {type:'button', class:'btn', onclick:function(){ copy(r.indicators.map(function(i){ return refang(i.value); }).join('\n') + '\n', 'Values copied, refanged'); }}, 'Copy values (refanged)')]),
    h('p', {class:'small muted'}, 'Defanged on screen so nothing here is clickable; exports and copies are refanged for log searches. Role is the publisher\'s characterisation of each value.'),
    h('div', {class:'tbl'}, h('table', null, [h('thead', null, h('tr', null, ['Type', 'Value', 'Publisher role', 'Seen', 'Context'].map(function(c){ return h('th', null, c); }))), h('tbody', null, rows)]))]);
}

/* ---------------------------------------------------------------- generic record rendering */
var MONO = {pattern:1, check:1, code:1, zeek_field:1, ethertype:1, value:1, path:1, paths:1, rule:1, exclude:1, flags:1, slug:1, upstream_sha256:1};
var HEADK = ['step', 'action', 'title', 'feature', 'capability', 'locator', 'method', 'event', 'operation', 'lesson', 'what',
  'technique', 'name', 'publisher', 'tool', 'control', 'layer'];
var SPECIAL = {
  indicators:function(v, r){ return indicators(r); },
  text:function(v){ return h('pre', {class:'code'}, h('code', null, v)); },
  gap:function(v){ return h('p', {class:'callout'}, linkify(v)); },
  stated_confidence:function(v){ return h('blockquote', null, linkify(v)); },
  quote:function(v){ return h('blockquote', null, v); },
  hardening:function(v){ var s = D.hardSets[v]; return typeof v === 'string' && s ? h('a', {href:'#hardening?platform=' + s.platform_id}, s.name) : undefined; },
  response:function(v){ return typeof v === 'string' && D.response.some(function(p){ return p._id === v; }) ? h('a', {href:'#response/' + v}, 'Response playbook: ' + v) : undefined; }
};
function field(k, v){ return h('div', {class:'fld f-' + k}, [h('div', {class:'fkey'}, label(k)), h('div', {class:'fval'}, v)]); }
function sec(title, body){ return h('section', {class:'sec'}, [h('h3', null, title), body]); }
function isUrl(s){ return /^https:\/\/\S+$/.test(s); }
function str(k, v){
  if (k === 'confidence' || k === 'link_confidence') return confB(v);
  if (k === 'impact' || k === 'collection_impact') return impB(v);
  if (k === 'tier') return tierB(v);
  if (isUrl(v)) return ext(v);
  if (MONO[k]) return h('code', {class:'blk'}, v);
  if (WHERE[v] || v === 'ALL') return xchip(v);
  return h('p', {class:'txt'}, linkify(v));
}
function value(k, v, r){
  if (v == null || v === '') return null;
  if (SPECIAL[k]){ var s = SPECIAL[k](v, r); if (s !== undefined) return s; }
  if (typeof v === 'boolean') return k === 'unverified' ? (v ? unvB() : null) : document.createTextNode(v ? 'yes' : 'no');
  if (typeof v === 'number') return document.createTextNode(String(v));
  if (typeof v === 'string') return str(k, v);
  if (Array.isArray(v)){
    if (!v.length) return k === 'detections' ? h('span', {class:'muted'}, 'none') : null;
    if (k === 'sources' || k === 'references') return sources(v);
    if (v.every(function(x){ return typeof x === 'string' || typeof x === 'number'; })){
      v = v.map(String);
      if (k === 'rules') return h('div', {class:'rulelist'}, v.map(ruleRef));
      if (v.every(isUrl)) return h('ul', {class:'bul'}, v.map(function(u){ return h('li', null, ext(u)); }));
      if (v.every(function(x){ return x.length <= 48; })) return h('div', {class:'chips'}, v.map(function(x){ return WHERE[x] || x === 'ALL' ? xchip(x) : h('span', {class:'chip'}, linkify(x)); }));
      return h(k === 'method' ? 'ol' : 'ul', {class:'bul'}, v.map(function(x){ return h('li', null, linkify(x)); }));
    }
    return h('div', {class:'subs'}, v.map(function(o){ return o && typeof o === 'object' ? sub(o) : value(k, o); }));
  }
  if (typeof v === 'object') return fields(v, {});
  return null;
}
function fields(o, skip){
  var box = h('div', {class:'fields'});
  Object.keys(o).forEach(function(k){ if (skip[k] || k.charAt(0) === '_') return; var x = value(k, o[k], o); if (x) box.appendChild(field(k, x)); });
  return box;
}
function sub(o){
  var hk = HEADK.filter(function(k){ return typeof o[k] === 'string'; })[0];
  var skip = {confidence:1, unverified:1, impact:1, collection_impact:1, tier:1, equated:1};
  if (hk) skip[hk] = 1;
  return h('div', {class:'sub' + (o.unverified ? ' unv' : '')}, [
    h('div', {class:'subh'}, [hk ? h('b', null, linkify(o[hk])) : null, confB(o.confidence), o.unverified ? unvB() : null,
      o.impact ? impB(o.impact) : null, o.collection_impact ? impB(o.collection_impact) : null, o.tier ? tierB(o.tier) : null,
      o.equated === false ? badge('not equated', 'neq', 'The reporter links the clusters but does not say they are the same') : null,
      o.equated === true ? badge('equated by the reporter', 'c-medium') : null]),
    fields(o, skip)]);
}
var KIND = {government:'A government cyber authority', vendor:'The vendor or the research team that did the analysis', researcher:'Independent researcher',
  standard:'Standards body', press:'Press: a lead, never the basis for high confidence'};
function sources(list){
  return h('ol', {class:'srcs'}, list.map(function(s){
    if (typeof s === 'string') return h('li', null, ext(s));
    return h('li', null, [h('div', {class:'srch'}, [s.url ? ext(s.url, s.title || s.url) : h('b', null, s.title || ''),
      s.kind ? badge(s.kind, 'k-' + s.kind, KIND[s.kind]) : null,
      s.read ? badge('read: ' + s.read, 'rd-' + s.read, s.read === 'summariser' ? 'Came through a summarising fetch: check the quote against the page' : 'Quote copied from the rendered page') : null,
      s.accessed ? h('span', {class:'small muted'}, 'accessed ' + s.accessed) : null]),
      s.quote ? h('blockquote', null, s.quote) : null]);
  }));
}
function ruleRef(p){
  var r = RULES[p];
  if (!r) return h('div', null, h('code', null, p));
  return h('details', {class:'rule'}, [h('summary', null, [xref(p), ' ', badge(r.format, 'k-researcher'), ' ', r._title]),
    h('pre', {class:'code'}, h('code', null, r.text))]);
}
function wide(k, v){ return k === 'indicators' || k === 'text' || (Array.isArray(v) && v.some(function(o){ return o && typeof o === 'object'; })); }
/* the relationship panel: every record this one is tied to by an id field, in either direction, grouped by library */
var RELORD = ['actors', 'malware', 'incidents', 'iocs', 'platforms', 'protocols', 'hunts', 'packs'];
function relPanel(r){
  var rel = D.rel[r.id]; if (!rel) return null;
  var rows = RELORD.filter(function(l){ return rel[l] && rel[l].length; }).map(function(l){
    return field(D.libLabel[l] || l, h('div', {class:'chips'}, rel[l].map(xchip))); });
  if (!rows.length) return null;
  return h('section', {class:'sec rel'}, [h('h3', null, 'Linked records'),
    h('p', {class:'small muted', style:'margin:0 0 8px'}, 'From the id fields of this record and of every record that names it, in both directions. A link is a reporter’s statement in one of the two records, not an inference.'),
    h('div', {class:'fields'}, rows)]);
}
function detail(n, r){
  var L = LIB[n], frag = document.createDocumentFragment();
  frag.appendChild(h('div', {class:'dbadges'}, [confB(r._conf), r._unv ? unvB() : null, nunvB(r)].concat(L.chips ? L.chips(r) : [])));
  var rp = relPanel(r); if (rp) frag.appendChild(rp);
  var keys = Object.keys(r).filter(function(k){ return k.charAt(0) !== '_' && k !== 'id' && r[k] !== r._title; });
  var src = keys.filter(function(k){ return k === 'sources' || k === 'references'; }), box = null;
  keys.forEach(function(k){   /* record order; lists of entries, indicators and rule text get the full width */
    if (src.indexOf(k) >= 0) return;
    var x = value(k, r[k], r);
    if (!x) return;
    if (wide(k, r[k])){ frag.appendChild(sec(label(k), x)); box = null; return; }
    if (!box) frag.appendChild(box = h('div', {class:'fields'}));
    box.appendChild(field(k, x));
  });
  src.forEach(function(k){ if ((r[k] || []).length) frag.appendChild(sec(k === 'sources' ? 'Sources, quoted' : 'References', sources(r[k]))); });
  var br = D.backrefs[r.id] || [], by = {};
  br.forEach(function(id){ (by[WHERE[id]] = by[WHERE[id]] || []).push(id); });
  if (br.length) frag.appendChild(sec('Referenced by', h('div', {class:'fields'}, Object.keys(by).map(function(l){
    return field(D.libLabel[l] || l, h('div', {class:'chips'}, by[l].map(xchip))); }))));
  if (r._file) frag.appendChild(h('p', {class:'small muted'}, ['Source file: ', fileLink(r._file)]));
  return frag;
}

/* ---------------------------------------------------------------- libraries */
var LIB = {};
function lib(n, cfg){ cfg.items = D.libs[n]; LIB[n] = cfg; BYID[n] = {}; cfg.items.forEach(function(i){ BYID[n][i.id] = i; }); }
function facet(k, lab, name, order){ return {k:k, label:lab, name:name || function(v){ return v; }, order:order || null}; }
var ORD = {conf:['high', 'medium', 'low'], purdue:['0', '1', '2', '3', '3.5', '4'], impact:['passive', 'read-only', 'online-vendor-tool', 'process-risk'],
  tier:['possible', 'likely', 'confirmed'], priority:['critical', 'high', 'medium'], status:['gap', 'blind', 'used', 'seen', 'hunted', 'detected']};
var STATUS = {gap:'Gap: used, nothing hunts or detects it', blind:'Blind spot: used, no data source sees it', used:'Used by an adversary',
  seen:'Seen by a data source', hunted:'Hunted', detected:'Detected'};
function level(v){ return 'Level ' + v; }
function plats(r){ return (r.platforms || []).map(pshort).join(' \u00b7 '); }
function decB(r){ var d = r.decision; return d ? badge(d === 'deferred' ? 'deferred: not yet read' : d, 'dec-' + d + (d === 'deferred' ? '' : ' k-researcher')) : badge('no ledger entry', 'k-standard'); }
function stB(r){ return r.status.filter(function(s){ return s === 'gap' || s === 'blind'; }).map(function(s){ return badge(s === 'gap' ? 'gap' : 'blind spot', 'st-' + s, STATUS[s]); }); }
function idl(ids){ return ids.length ? h('span', {class:'idl'}, ids.map(function(i){ return xref(i); })) : h('span', {class:'muted'}, '\u2014'); }

lib('platforms', {noun:'platforms',
  facets:[facet('class', 'Asset class', nice), facet('purdue', 'Purdue level', level, ORD.purdue), facet('vendor', 'Vendor'),
    facet('impact', 'Collection impact', null, ORD.impact), facet('memory', 'Memory acquisition', nice), facet('confidence', 'Confidence', null, ORD.conf)],
  meta:function(r){ return [r.vendor, nice(r.asset_class), lv(r.purdue_levels)]; },
  blurb:function(r){ return (r.products || []).join('; ') || r.os_base; },
  chips:function(r){ return r._f.impact.map(impB); }});
lib('protocols', {noun:'protocols',
  facets:[facet('transport', 'Transport'), facet('auth', 'Native authentication', null, ['none', 'optional', 'mandatory']), facet('confidence', 'Confidence', null, ORD.conf)],
  meta:function(r){ return [r.spec_owner]; },
  blurb:function(r){ return (r.authentication || {}).detail; },
  chips:function(r){ return (r.transport || []).map(function(t){ return chipT(t.layer + (t.port ? '/' + t.port : '')); })
    .concat([chipT('auth: ' + ((r.authentication || {}).native || 'not stated'))]); }});
lib('datasources', {noun:'data sources',
  facets:[facet('category', 'Category', nice), facet('purdue', 'Purdue level', level, ORD.purdue), facet('impact', 'Collection impact', null, ORD.impact),
    facet('confidence', 'Confidence', null, ORD.conf)],
  meta:function(r){ return [nice(r.category), lv(r.purdue_levels)]; },
  blurb:function(r){ return r.location; },
  chips:function(r){ return r._f.impact.map(impB).concat([chipT(plural((r.gaps || []).length, 'stated gap'))]); }});
lib('actors', {noun:'actors',
  facets:[facet('motivation', 'Motivation', nice), facet('reporter', 'Reported by'), facet('stage', 'ICS kill chain stage', nice, ['stage-1', 'stage-2', 'unknown']),
    facet('platform', 'Platform named', pshort), facet('confidence', 'Link confidence', null, ORD.conf)],
  meta:function(r){ return [(r.reported_by || []).join(', '), nice(r.motivation)]; },
  blurb:function(r){ return r.summary; },
  chips:function(r){ return (r.aliases || []).slice(0, 3).map(function(a){ return chipT((a.equated ? '= ' : '\u2248 ') + a.name, (a.equated ? 'Equated: ' : 'Alias, not equated: ') + a.by); }); }});
lib('malware', {noun:'malware families',
  facets:[facet('type', 'Type', nice), facet('runs', 'Runs on', nice), facet('effect', 'ICS effect', nice), facet('platform', 'Platform', pshort),
    facet('protocol', 'Protocol', nm),
    facet('detection', 'Detection', function(v){ return v === 'yes' ? 'has a detection' : 'none, gap stated'; }), facet('confidence', 'Confidence', null, ORD.conf)],
  meta:function(r){ return [nice(r.type), r.first_reported ? 'first reported ' + r.first_reported : '']; },
  blurb:function(r){ return r.summary; },
  chips:function(r){ return (r.detections || []).length ? [] : [badge('no detection', 'gapb', 'A malware family with no detection states its gap')]; }});
lib('incidents', {noun:'incidents',
  facets:[facet('consequence', 'Physical consequence', nice), facet('sector', 'Sector', nice), facet('country', 'Country'), facet('confidence', 'Confidence', null, ORD.conf)],
  meta:function(r){ return [r.date, (r.countries || []).join(', ')]; },
  blurb:function(r){ return r.summary; },
  chips:function(r){ return [chipT(nice(r.physical_consequence), 'Physical consequence, as a primary source states it')]; }});
lib('iocs', {noun:'indicator sets',
  facets:[facet('publisher', 'Publisher'), facet('type', 'Indicator type'), facet('role', 'Publisher role', nice)],
  meta:function(r){ return [r.publisher, 'published ' + r.published]; },
  blurb:function(r){ return r.staleness; },
  chips:function(r){ var c = {}; r.indicators.forEach(function(i){ c[i.type] = (c[i.type] || 0) + 1; });
    return [chipT(plural(r.indicators.length, 'indicator'))].concat(Object.keys(c).map(function(t){ return chipT(c[t] + ' ' + t); })); }});
lib('hunts', {noun:'hunts',
  facets:[facet('platform', 'Platform', pshort), facet('data', 'Data needed', nice), facet('actor', 'Actor', nm), facet('confidence', 'Confidence', null, ORD.conf)],
  meta:function(r){ return [plats(r)]; },
  blurb:function(r){ return r.hypothesis; },
  chips:function(r){ return (r.data || []).map(function(x){ return chipT(nice(x)); }); }});
lib('packs', {noun:'packs',
  facets:[facet('platform', 'Platform', pshort), facet('tier', 'Detection tier', null, ORD.tier), facet('evidence', 'Evidence class', nice),
    facet('confidence', 'Confidence', null, ORD.conf)],
  meta:function(r){ return [plats(r)]; },
  blurb:function(r){ return r.summary; },
  chips:function(r){ var rules = {}; (r.detect || []).forEach(function(x){ (x.rules || []).forEach(function(p){ rules[p] = 1; }); });
    return [chipT(plural((r.detect || []).length, 'detection')), chipT(plural(Object.keys(rules).length, 'rule file'))]; }});
lib('rules', {noun:'rule files',
  facets:[facet('format', 'Format'), facet('dir', 'Directory'), facet('attack', 'ATT&CK'), facet('linked', 'Linked from', nice)],
  meta:function(r){ return [r.dir, r.format]; },
  blurb:function(r){ return r.description; },
  chips:function(r){ return [chipT(r.format), r.level ? chipT('level: ' + r.level) : null, (r.sids || []).length ? chipT('sid ' + r.sids.join(', ')) : null]; }});
lib('hardening', {noun:'controls',
  facets:[facet('platform', 'Platform', pshort), facet('category', 'Category', nice), facet('priority', 'Priority', null, ORD.priority),
    facet('confidence', 'Confidence', null, ORD.conf)],
  meta:function(r){ return [r.set, nice(r.category)]; },
  blurb:function(r){ return r.why; },
  chips:function(r){ return [badge(r.priority + ' priority', 'pri-' + r.priority + (r.priority === 'critical' ? '' : ' k-researcher'))]; }});
lib('kev', {noun:'CVEs',
  facets:[facet('decision', 'Decision', function(v){ return v === 'deferred' ? 'deferred (not yet read)' : v === 'not-in-ledger' ? 'no ledger entry' : v; }),
    facet('platform', 'Platform', pshort), facet('reported', 'Exploitation date', function(v){ return v === 'quoted' ? 'quoted from a source' : 'none quoted'; })],
  chips:function(r){ return [decB(r)]; },
  table:[['CVE', function(r){ return h('a', {class:'open', href:'#kev/' + r.id}, r.id); }],
    ['Platform', function(r){ return r.platform ? xref(r.platform, pshort(r.platform)) : '\u2014'; }],
    ['KEV vendor / product', function(r){ return [r.kev_vendor, r.kev_product].filter(Boolean).join(' / ') || '\u2014'; }],
    ['Added to KEV', function(r){ return r.kev_date_added || '\u2014'; }], ['Decision', decB],
    ['Exploitation, earliest quoted', function(r){ return r.exploitation.length ? r.exploitation.map(function(x){ return x.earliest_words || x.earliest; }).join('; ') : '\u2014'; }]]});
lib('coverage', {noun:'techniques',
  facets:[facet('status', 'Status', function(v){ return STATUS[v] || v; }, ORD.status), facet('matrix', 'Matrix', null, ['ICS', 'Enterprise'])],
  chips:stB,
  table:[['Technique', function(r){ return [h('a', {class:'open', href:'#coverage/' + r.id}, r.id), ' '].concat(stB(r)); }],
    ['Matrix', function(r){ return r.matrix; }], ['Used by', function(r){ return idl(r.used); }], ['Seen by', function(r){ return idl(r.seen); }],
    ['Hunted by', function(r){ return idl(r.hunted); }], ['Detected by', function(r){ return idl(r.detected); }]]});

/* the facet keys here must match FACET_KEYS in the generator, which validates links against them */
Object.keys(D.facetKeys).forEach(function(n){
  var a = LIB[n] ? LIB[n].facets.map(function(f){ return f.k; }).join(',') : '(none)', b = D.facetKeys[n].join(',');
  if (a !== b) console.error('facet keys for ' + n + ' differ from FACET_KEYS: ' + a + ' vs ' + b);
});

function texts(o, out){
  if (o == null) return out;
  if (typeof o === 'string' || typeof o === 'number') out.push(String(o));
  else if (Array.isArray(o)) o.forEach(function(x){ texts(x, out); });
  else if (typeof o === 'object') Object.keys(o).forEach(function(k){ if (k !== '_f') texts(o[k], out); });
  return out;
}
var S = {}, cur = null, openId = null, openLib = null, OPEN = {};
function fresh(){ return {q:'', sel:{}, unv:false}; }
Object.keys(LIB).forEach(function(n){
  S[n] = fresh();
  LIB[n].items.forEach(function(it){
    var t = texts(it, []).join(' '), m, extra = []; XREF.lastIndex = 0;
    while ((m = XREF.exec(t))) if (NAMES[m[0]]) extra.push(NAMES[m[0]]);   // a hunt naming ICS-TA-0001 is found by "Sandworm"
    it._t = (t + ' ' + extra.join(' ')).toLowerCase();
  });
});

function pass(n, it, skip){
  var st = S[n];
  if (st.unv && !(it._unv || it._nunv)) return false;
  if (st.q){ var toks = refang(st.q).toLowerCase().split(/\s+/); for (var t = 0; t < toks.length; t++) if (toks[t] && it._t.indexOf(toks[t]) < 0) return false; }
  var fs = LIB[n].facets;
  for (var i = 0; i < fs.length; i++){
    var f = fs[i], sel = st.sel[f.k];
    if (f.k === skip || !sel || !sel.length) continue;
    if (!(it._f[f.k] || []).some(function(v){ return sel.indexOf(v) >= 0; })) return false;
  }
  return true;
}
function card(n, r){
  var L = LIB[n], meta = L.meta(r).filter(Boolean).join(' \u00b7 '), blurb = L.blurb(r);
  return h('a', {class:'card item open' + (r._unv ? ' unv' : '') + (openLib === n && openId === r.id ? ' sel' : ''), href:'#' + n + '/' + r.id, 'data-id':r.id}, [
    h('div', {class:'cmeta', title:meta}, [h('span', {class:'cid'}, r.id), meta]), h('h3', null, r._title),
    blurb ? h('p', {class:'clamp'}, blurb) : null,
    h('div', {class:'cbadges'}, [confB(r._conf), r._unv ? unvB() : null, nunvB(r)].concat(L.chips ? L.chips(r) : []))]);
}
function table(n, items){
  var L = LIB[n];
  return h('div', {class:'tbl'}, h('table', null, [h('thead', null, h('tr', null, L.table.map(function(c){ return h('th', {scope:'col'}, c[0]); }))),
    h('tbody', null, items.map(function(it){
      return h('tr', {class:'item' + (it._unv ? ' unv' : '') + (openLib === n && openId === it.id ? ' sel' : ''), 'data-id':it.id,
        onclick:function(ev){ if (!ev.target.closest('a,button')) go(n + '/' + it.id); }}, L.table.map(function(c){ return h('td', null, c[1](it)); }));
    }))]));
}
function renderRail(n){
  var L = LIB[n], st = S[n], rail = clear($('rail'));
  L.facets.forEach(function(f){
    var tot = {}, cnt = {};
    L.items.forEach(function(it){
      var vs = it._f[f.k] || [], ok = pass(n, it, f.k);
      vs.forEach(function(v){ tot[v] = (tot[v] || 0) + 1; if (ok) cnt[v] = (cnt[v] || 0) + 1; });
    });
    var vals = Object.keys(tot);
    if (!vals.length) return;
    if (f.order) vals.sort(function(a, b){ var x = f.order.indexOf(a), y = f.order.indexOf(b); return (x < 0 ? 99 : x) - (y < 0 ? 99 : y) || (a < b ? -1 : 1); });
    else vals.sort(function(a, b){ return tot[b] - tot[a] || String(f.name(a)).localeCompare(String(f.name(b))); });   // by total, so the list never reorders
    var sel = st.sel[f.k] || [], key = n + ':' + f.k, lim = OPEN[key] || vals.length <= 9 ? vals.length : 7;
    var g = h('fieldset', {class:'fg'}, h('legend', null, f.label));
    vals.forEach(function(v, i){
      var on = sel.indexOf(v) >= 0;
      if (i >= lim && !on) return;
      var inp = h('input', {type:'checkbox', 'data-f':f.k, value:v});
      inp.checked = on;
      g.appendChild(h('label', {class:'fv' + (on ? ' on' : '') + (cnt[v] || on ? '' : ' zero'), title:f.name(v)}, [inp, h('span', {class:'fl'}, f.name(v)), h('span', {class:'fc'}, String(cnt[v] || 0))]));
    });
    if (vals.length > 9) g.appendChild(h('button', {type:'button', class:'lnk', 'data-more':key}, OPEN[key] ? 'Show fewer' : 'Show all ' + vals.length));
    rail.appendChild(g);
  });
}
function renderActive(n, box){
  var st = S[n], L = LIB[n];
  clear(box);
  if (st.q) box.appendChild(h('span', {class:'achip'}, ['\u201c' + st.q + '\u201d', h('button', {type:'button', 'data-rm':'q', 'aria-label':'Clear search'}, '\u00d7')]));
  if (st.unv) box.appendChild(h('span', {class:'achip'}, ['unverified only', h('button', {type:'button', 'data-rm':'unv', 'aria-label':'Remove'}, '\u00d7')]));
  L.facets.forEach(function(f){ (st.sel[f.k] || []).forEach(function(v){
    box.appendChild(h('span', {class:'achip'}, [f.label + ': ' + f.name(v), h('button', {type:'button', 'data-rm':f.k, 'data-v':v, 'aria-label':'Remove'}, '\u00d7')])); }); });
  if (box.firstChild) box.appendChild(h('button', {type:'button', class:'lnk', 'data-act':'reset'}, 'clear all'));
}
function renderLib(n){
  var L = LIB[n], P = $('tab-' + n), items = L.items.filter(function(it){ return pass(n, it, null); });
  P.querySelector('.count').textContent = items.length + ' of ' + L.items.length + ' ' + L.noun + ' shown';
  renderActive(n, P.querySelector('.active'));
  var res = clear(P.querySelector('.results'));
  if (!items.length) res.appendChild(h('p', {class:'empty'}, ['Nothing matches these filters. ', h('button', {type:'button', class:'lnk', 'data-act':'reset'}, 'Clear them')]));
  else if (L.table) res.appendChild(table(n, items));
  else res.appendChild(h('div', {class:'lgrid'}, items.map(function(it){ return card(n, it); })));
  renderRail(n);
  writeHash();
}
function syncControls(n){
  var P = $('tab-' + n), q = P.querySelector('.q');
  if (q.value !== S[n].q) q.value = S[n].q;
  var u = P.querySelector('.unvT'); if (u) u.setAttribute('aria-pressed', String(S[n].unv));
}

/* ---------------------------------------------------------------- drawer */
function openDrawer(n, id){
  var r = BYID[n][id];
  if (!r){ toast('No record ' + id + ' in ' + n); return; }
  openLib = n; openId = id;
  $('dId').textContent = id;
  $('dTitle').textContent = r._title;
  clear($('dBody')).appendChild(detail(n, r));
  $('dBody').scrollTop = 0;
  $('drawer').hidden = false; $('scrim').hidden = false;
  document.querySelectorAll('.item.sel, .cc.sel').forEach(function(x){ x.classList.remove('sel'); });
  var c = $('tab-' + n).querySelector('.item[data-id="' + CSS.escape(id) + '"]');
  if (c){ c.classList.add('sel'); if (c.tagName === 'TR') c.scrollIntoView({block:'nearest'}); }   /* the technique's row, from the grid */
  var cell = n === 'coverage' && $('viz-cov').querySelector('.cc[href="#coverage/' + CSS.escape(id) + '"]');
  if (cell) cell.classList.add('sel');
  $('dTitle').focus({preventScroll:true});
}
function closeDrawer(silent){
  if ($('drawer').hidden && !openId) return;
  var n = openLib, id = openId;
  $('drawer').hidden = true; $('scrim').hidden = true;
  openId = null; openLib = null;
  document.querySelectorAll('.item.sel, .cc.sel').forEach(function(x){ x.classList.remove('sel'); });
  if (!silent){
    writeHash();
    var c = n && id && $('tab-' + n) && $('tab-' + n).querySelector('.item[data-id="' + CSS.escape(id) + '"]');
    if (c && c.focus) c.focus({preventScroll:true});
  }
}
function toast(msg){ var t = $('toast'); t.textContent = msg; t.hidden = false; clearTimeout(toast.t); toast.t = setTimeout(function(){ t.hidden = true; }, 2600); }
function copy(text, ok){
  if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(text).then(function(){ toast(ok); }, function(){ toast('Copy failed: select and copy by hand'); });
  else toast('Copy is not available in this browser');
}

/* ---------------------------------------------------------------- response playbooks */
var PHASES = [['safety_first', 'Safety first'], ['preserve_first', 'Preserve'], ['contain', 'Contain'], ['credential_exposure', 'Rotate credentials'],
  ['eradicate', 'Eradicate'], ['recover', 'Recover'], ['verify', 'Verify']];
var BASIS = {toolkit:'This project\'s inference, with its reasoning given', government:'A government cyber authority', vendor:'The vendor',
  researcher:'Researchers', standard:'A standard'};
function basisB(b){ return b ? badge('basis: ' + b, b === 'toolkit' ? 'inf' : 'k-researcher', BASIS[b]) : null; }
function renderResponse(){
  var box = clear($('respBody'));
  D.response.forEach(function(pb){
    var art = h('article', {class:'pb', id:'resp-' + pb._id}, h('div', {class:'pbh'}, [h('h3', null, pb.name), confB(pb.confidence),
      pb.platform_id === 'ALL' ? chipT('All platforms') : xchip(pb.platform_id)]));
    var i = 0;
    PHASES.forEach(function(ph){
      var steps = pb[ph[0]] || [];
      if (!steps.length) return;
      art.appendChild(h('section', {class:'phase'}, [h('h4', null, [h('span', {class:'pn'}, String(++i)), ph[1]]),
        h('ol', {class:'steps'}, steps.map(function(s){
          if (ph[0] === 'credential_exposure') return h('li', null, [h('b', null, linkify(s.what)), s.why ? h('p', {class:'txt'}, linkify(s.why)) : null, s.action ? h('p', {class:'txt'}, ['Action: ', linkify(s.action)]) : null]);
          return h('li', null, [h('b', null, linkify(s.step)), s.detail ? h('p', {class:'txt'}, linkify(s.detail)) : null,
            h('div', {class:'cbadges'}, [s.owner ? chipT('owner: ' + s.owner, 'Who performs or must approve it') : null, s.when ? chipT('when: ' + s.when) : null, basisB(s.basis)])]);
        }))]));
    });
    if ((pb.do_not || []).length) art.appendChild(h('section', {class:'phase donot'}, [h('h4', null, 'Do not'), h('ul', null, pb.do_not.map(function(x){
      return h('li', null, [h('b', null, linkify(x.action)), x.because ? h('p', {class:'txt'}, linkify(x.because)) : null, basisB(x.basis)]); }))]));
    if (pb.notes) art.appendChild(sec('Notes', h('p', {class:'txt'}, linkify(pb.notes))));
    if ((pb.sources || []).length) art.appendChild(sec('Sources, quoted', sources(pb.sources)));
    art.appendChild(h('p', {class:'small muted'}, ['Source file: ', fileLink(pb._file)]));
    box.appendChild(art);
  });
}

/* ---------------------------------------------------------------- URL state and routing */
function qs(n){
  var st = S[n], parts = [];
  LIB[n].facets.forEach(function(f){ var v = st.sel[f.k]; if (v && v.length) parts.push(f.k + '=' + v.map(encodeURIComponent).join(',')); });
  if (st.q) parts.push('q=' + encodeURIComponent(st.q));
  if (st.unv) parts.push('unv=1');
  return parts.length ? '?' + parts.join('&') : '';
}
function writeHash(){
  if (!LIB[cur]) return;
  var x = '#' + cur + (openLib === cur && openId ? '/' + openId : '') + qs(cur);
  if (location.hash !== x) history.replaceState(null, '', x);
}
function readQuery(n, q){
  var st = fresh();
  q.split('&').forEach(function(kv){
    if (!kv) return;
    var i = kv.indexOf('='), k = i < 0 ? kv : kv.slice(0, i), v = i < 0 ? '' : kv.slice(i + 1);
    if (k === 'q') st.q = decodeURIComponent(v);
    else if (k === 'unv') st.unv = v === '1';
    else st.sel[k] = v.split(',').map(decodeURIComponent).filter(Boolean);
  });
  S[n] = st;
}
function go(path){ var x = '#' + path; if (location.hash === x) route(); else location.hash = x; }
function show(tab, anchor){
  var changed = cur !== tab;
  cur = tab;
  var top = TABOF[tab] || tab;
  document.querySelectorAll('.tabs a').forEach(function(a){ if (a.dataset.tab === top) a.setAttribute('aria-current', 'page'); else a.removeAttribute('aria-current'); });
  document.querySelectorAll('.panel').forEach(function(p){ p.hidden = p.id !== 'tab-' + tab; });
  $('shell').classList.toggle('norail', !LIB[tab]);
  var vz = $('viz-intel');   /* one correlation block, carried into whichever intel library is open */
  if (TABOF[tab] === 'intel'){ var P = $('tab-' + tab); if (vz.parentNode !== P) P.insertBefore(vz, P.querySelector('.tools')); vz.hidden = false; }
  else vz.hidden = true;
  if (changed) window.scrollTo(0, 0);
  if (LIB[tab]){
    if (anchor && BYID[tab][anchor] && !pass(tab, BYID[tab][anchor], null)) S[tab] = fresh();   // a deep link is never hidden by a filter
    syncControls(tab);
    if (anchor){ openLib = tab; openId = anchor; } else if (openId) closeDrawer(true);
    renderLib(tab);
    if (anchor) openDrawer(tab, anchor);
  } else {
    closeDrawer(true);
    var el = anchor && $('resp-' + anchor);
    if (tab === 'response' && el) setTimeout(function(){ el.scrollIntoView({block:'start'}); }, 0);
  }
}
function route(){
  var s = location.hash.slice(1), q = null, i = s.indexOf('?');
  if (i >= 0){ q = s.slice(i + 1); s = s.slice(0, i); }
  var parts = s.split('/'), tab = parts[0] || 'start', anchor = decodeURIComponent(parts.slice(1).join('/'));
  if (GROUPS[tab]){ history.replaceState(null, '', '#' + GROUPS[tab][0] + (q ? '?' + q : '')); route(); return; }
  if (!$('tab-' + tab)){
    var el = $(tab);
    if (el && !anchor){ el.focus(); return; }   // the skip link
    tab = 'start'; anchor = '';
  }
  if (LIB[tab]){ if (q !== null) readQuery(tab, q); else if (!anchor) S[tab] = fresh(); }
  show(tab, anchor);
}

/* ---------------------------------------------------------------- events */
document.addEventListener('click', function(ev){
  var a = ev.target.closest('[data-go]');
  if (a && !ev.ctrlKey && !ev.metaKey && !ev.shiftKey){
    ev.preventDefault();
    var t = a.dataset.go, last = t === 'intel' && TABOF[cur] === 'intel' ? cur : t === 'detections' && TABOF[cur] === 'detections' ? cur : null;
    if (GROUPS[t]) t = last || GROUPS[t][0];
    go(t + (LIB[t] ? qs(t) : ''));
    return;
  }
  var b = ev.target.closest('button');
  if (!b || !LIB[cur]) return;
  var st = S[cur];
  if (b.dataset.rm){ if (b.dataset.rm === 'q') st.q = ''; else if (b.dataset.rm === 'unv') st.unv = false;
    else st.sel[b.dataset.rm] = (st.sel[b.dataset.rm] || []).filter(function(v){ return v !== b.dataset.v; }); syncControls(cur); renderLib(cur); }
  else if (b.dataset.act === 'reset'){ S[cur] = fresh(); syncControls(cur); renderLib(cur); }
  else if (b.dataset.more){ OPEN[b.dataset.more] = !OPEN[b.dataset.more]; renderRail(cur); }
  else if (b.classList.contains('unvT')){ st.unv = !st.unv; syncControls(cur); renderLib(cur); }
  else if (b.classList.contains('railT')){ var open = $('shell').classList.toggle('railopen'); b.setAttribute('aria-expanded', String(open)); }
});
$('rail').addEventListener('change', function(ev){
  var inp = ev.target; if (!inp.dataset.f || !LIB[cur]) return;
  var sel = S[cur].sel[inp.dataset.f] = (S[cur].sel[inp.dataset.f] || []).filter(function(v){ return v !== inp.value; });
  if (inp.checked) sel.push(inp.value);
  renderLib(cur);
});
document.addEventListener('input', function(ev){ if (ev.target.classList.contains('q') && LIB[cur]){ S[cur].q = ev.target.value; renderLib(cur); } });

/* ---------------------------------------------------------------- global search: every library at once, grouped, from _s */
var GS = [], gsFlat = [], gsI = 0, GSMAX = 5;
Object.keys(LIB).forEach(function(n){ LIB[n].items.forEach(function(it){ GS.push({n:n, it:it, s:String(it._s || '').toLowerCase(), t:it._title.toLowerCase(), i:String(it.id).toLowerCase()}); }); });
function gsToks(q){ return refang(q).toLowerCase().split(/\s+/).filter(Boolean); }
function gsearch(toks){
  var by = {};
  if (!toks.length) return [];
  GS.forEach(function(x){
    for (var i = 0; i < toks.length; i++) if (x.s.indexOf(toks[i]) < 0) return;
    var sc = toks.every(function(t){ return x.t.indexOf(t) >= 0; }) ? 3 : toks.some(function(t){ return x.i.indexOf(t) >= 0; }) ? 2 : 1;
    (by[x.n] = by[x.n] || []).push({x:x, sc:sc});
  });
  return Object.keys(LIB).filter(function(n){ return by[n]; }).map(function(n){
    var a = by[n].sort(function(p, q){ return q.sc - p.sc; });
    return {n:n, total:a.length, items:a.slice(0, GSMAX).map(function(o){ return o.x.it; })}; });
}
function hilite(text, toks){   /* text nodes and <mark>, never markup from the record */
  text = String(text); var low = text.toLowerCase(), cuts = [];
  toks.forEach(function(t){ var i = 0; while (t && (i = low.indexOf(t, i)) >= 0){ cuts.push([i, i + t.length]); i += t.length; } });
  cuts.sort(function(a, b){ return a[0] - b[0]; });
  var out = [], pos = 0;
  cuts.forEach(function(c){ if (c[0] < pos) return; if (c[0] > pos) out.push(text.slice(pos, c[0])); out.push(h('mark', null, text.slice(c[0], c[1]))); pos = c[1]; });
  if (pos < text.length) out.push(text.slice(pos));
  return out;
}
function gsClose(){ var box = $('gres'); box.hidden = true; clear(box); gsFlat = []; $('gq').setAttribute('aria-expanded', 'false'); $('gq').removeAttribute('aria-activedescendant'); }
function gsMark(){
  gsFlat.forEach(function(a, i){ var on = i === gsI; a.classList.toggle('on', on); a.setAttribute('aria-selected', String(on)); if (on) a.scrollIntoView({block:'nearest'}); });
  if (gsFlat[gsI]) $('gq').setAttribute('aria-activedescendant', gsFlat[gsI].id); else $('gq').removeAttribute('aria-activedescendant');
}
function gsRender(){
  var q = $('gq').value, toks = gsToks(q), box = clear($('gres'));
  gsFlat = []; gsI = 0;
  if (!toks.length){ gsClose(); return; }
  var groups = gsearch(toks), total = groups.reduce(function(s, g){ return s + g.total; }, 0);
  if (!groups.length) box.appendChild(h('div', {class:'gsn'}, 'Nothing matches every word. Try fewer words, an id, or a defanged indicator.'));
  else box.appendChild(h('div', {class:'gsn'}, [plural(total, 'record') + ' in ' + plural(groups.length, 'library').replace('librarys', 'libraries'), h('span', null, '↑↓ move · Enter opens · Esc clears')]));
  groups.forEach(function(g){
    var sec = h('div', {class:'gsg', role:'group', 'aria-label':D.libLabel[g.n]}, h('div', {class:'gsh'}, [D.libLabel[g.n], h('span', null, String(g.total))]));
    g.items.forEach(function(it){
      var meta = LIB[g.n].meta ? LIB[g.n].meta(it).filter(Boolean).join(' · ') : '';
      var a = h('a', {class:'gsr', role:'option', 'aria-selected':'false', id:'gsr' + gsFlat.length, href:'#' + g.n + '/' + it.id},
        [h('span', {class:'cid'}, it.id), h('span', {class:'gst', title:it._title}, hilite(it._title, toks)), meta ? h('span', {class:'gss'}, meta) : null]);
      gsFlat.push(a); sec.appendChild(a);
    });
    if (g.total > GSMAX) sec.appendChild(h('a', {class:'gsall', href:'#' + g.n + '?q=' + encodeURIComponent(refang(q).trim())}, 'All ' + g.total + ' in ' + D.libLabel[g.n] + ' →'));
    box.appendChild(sec);
  });
  box.hidden = false; $('gq').setAttribute('aria-expanded', 'true'); gsMark();
}
function gsGo(href){ gsClose(); $('gq').blur(); go(href.slice(1)); }
$('gq').addEventListener('input', gsRender);
$('gq').addEventListener('focus', function(){ if ($('gq').value.trim()) gsRender(); });
$('gq').addEventListener('keydown', function(ev){
  if (ev.key === 'ArrowDown' || ev.key === 'ArrowUp'){ if (!gsFlat.length) return; ev.preventDefault(); gsI = (gsI + (ev.key === 'ArrowDown' ? 1 : gsFlat.length - 1)) % gsFlat.length; gsMark(); }
  else if (ev.key === 'Enter'){ if (gsFlat[gsI]){ ev.preventDefault(); gsGo(gsFlat[gsI].getAttribute('href')); } }
  else if (ev.key === 'Escape'){ ev.preventDefault(); ev.stopPropagation(); if ($('gq').value){ $('gq').value = ''; gsClose(); } else $('gq').blur(); }
});
$('gres').addEventListener('click', function(ev){
  var a = ev.target.closest('a'); if (a && !ev.ctrlKey && !ev.metaKey && !ev.shiftKey){ ev.preventDefault(); gsGo(a.getAttribute('href')); }
});
document.addEventListener('click', function(ev){ if (!ev.target.closest('.gs')) gsClose(); });

document.addEventListener('keydown', function(ev){
  if (ev.key === 'Escape' && !$('drawer').hidden){ closeDrawer(false); return; }
  var typing = /INPUT|TEXTAREA|SELECT/.test((document.activeElement || {}).tagName || '');
  if ((ev.key === '/' && !typing && !ev.ctrlKey && !ev.metaKey) || ((ev.key === 'k' || ev.key === 'K') && (ev.ctrlKey || ev.metaKey))){ ev.preventDefault(); $('gq').focus(); $('gq').select(); }
});
$('dClose').addEventListener('click', function(){ closeDrawer(false); });
$('scrim').addEventListener('click', function(){ closeDrawer(false); });
$('dLink').addEventListener('click', function(){ copy(location.href, 'Link copied'); });
/* theme: light unless this viewer chose dark (restored by the head script); the button shows the state */
function themeSync(){ $('themeBtn').setAttribute('aria-pressed', String(document.documentElement.getAttribute('data-theme') === 'dark')); }
$('themeBtn').addEventListener('click', function(){
  var root = document.documentElement, next = root.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
  root.setAttribute('data-theme', next); themeSync();
  try { localStorage.setItem('icsdfir-theme', next); } catch (_){ /* private mode */ }
});
themeSync();
if (window.innerWidth < 900) $('viz-intel').open = false;   /* phones start with the matrices folded */
window.addEventListener('hashchange', route);
renderResponse();
route();
})();
"""


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    d = load()
    doc, data = page(d)
    problems = check(doc, data)
    if problems:
        for p in problems:
            print(f"FAIL  {p}")
        return 1
    n = sum(len(v) for v in data["libs"].values())
    if "--check" in argv:
        print(f"OK  site contract holds ({len(doc) // 1024} KiB, {n} records in {len(LIBS)} libraries)")
        return 0
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(doc, encoding="utf-8")
    print(f"wrote {OUT.relative_to(ROOT)} ({len(doc) // 1024} KiB, {n} records)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
