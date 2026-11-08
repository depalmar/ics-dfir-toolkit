#!/usr/bin/env python3
"""parse_iocs.py - turn a publisher's own indicator file into ICS-IOC indicators.

Indicators are parsed, never retyped. Each file format has one parser
function; each indicator set ("profile") combines those parsers, cross-checks
the publisher's files against each other, and attaches the publisher's role and
context through rules keyed on the publisher's own words (a table column, a
section heading), never on an indicator value. Output is YAML for the
`indicators:` list of an artifacts/intel/iocs/ record; checks go to stderr.

Safety: the inputs are untrusted downloads. Run with `python3 -I`, keep the
downloads in their own directories, pass their paths as arguments and never
run anything from inside a download directory. XML with a DOCTYPE or entity
declaration is refused rather than parsed.

Usage (from the repository root):
  python3 -I artifacts/scripts/parse_iocs.py cisa-aa26-097a \
      --stix2 JULY.json --stix1 JULY.xml --page ADVISORY.html \
      --prior-stix2 APRIL.json --prior-stix1 APRIL.xml
  python3 -I artifacts/scripts/parse_iocs.py eset-dynowiper \
      --readme README.adoc --hashes samples.sha1 samples.sha256 samples.md5
  python3 -I artifacts/scripts/parse_iocs.py eset-industroyer \
      --readme README.adoc --hashes samples.sha1 samples.sha256 samples.md5
  python3 -I artifacts/scripts/parse_iocs.py dump FORMAT FILE   # inspect one file
"""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import re
import sys
import xml.etree.ElementTree as ET
from html.parser import HTMLParser
from pathlib import Path

import yaml

HASH_TYPES = {32: "md5", 40: "sha1", 64: "sha256"}
MONTHS = {m: i for i, m in enumerate(
    ["january", "february", "march", "april", "may", "june", "july",
     "august", "september", "october", "november", "december"], start=1)}


def note(msg: str) -> None:
    print(msg, file=sys.stderr)


def fail(msg: str) -> None:
    raise SystemExit(f"CHECK FAILED: {msg}")


def refang(value: str) -> str:
    """Undo the publisher's defanging: [.] (.) [:] hxxp."""
    v = value.strip()
    v = v.replace("[.]", ".").replace("(.)", ".").replace("[:]", ":")
    v = re.sub(r"^hxxp", "http", v, flags=re.I)
    return v


def classify(value: str) -> str:
    """Indicator type from the value's own shape; refuses anything ambiguous."""
    try:
        ip = ipaddress.ip_address(value)
        return "ipv4" if ip.version == 4 else "ipv6"
    except ValueError:
        pass
    if re.fullmatch(r"[0-9A-Fa-f]+", value) and len(value) in HASH_TYPES:
        return HASH_TYPES[len(value)]
    fail(f"cannot classify indicator value {value!r}")
    return ""


def norm(value: str) -> str:
    """Hashes lower-case so the same hash from two files compares equal."""
    return value.lower() if classify(value) in HASH_TYPES.values() else value


def file_digest(path: str) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def month_to_fuzzy(text: str) -> str:
    """'September 2025' -> '2025-09' (only as precise as the publisher)."""
    m = re.fullmatch(r"\s*([A-Za-z]+)\s+(\d{4})\s*", text)
    if not m or m.group(1).lower() not in MONTHS:
        fail(f"unexpected month text {text!r}")
    return f"{m.group(2)}-{MONTHS[m.group(1).lower()]:02d}"


# ---------------------------------------------------------------- formats --

STIX2_PATTERN = re.compile(
    r"\[\s*(ipv4-addr|ipv6-addr|domain-name|url):value\s*=\s*'([^']+)'\s*\]"
    r"|\[\s*file:hashes\.(?:'(SHA-256|SHA-1)'|(MD5))\s*=\s*'([0-9A-Fa-f]+)'\s*\]")


def parse_stix2_json(path: str) -> list[dict]:
    """STIX 2.x bundle: one entry per indicator object with a simple pattern,
    plus the names of threat-actor objects it 'indicates'."""
    bundle = json.loads(Path(path).read_text(encoding="utf-8"))
    if bundle.get("type") != "bundle":
        fail(f"{path}: not a STIX bundle")
    objs = {o["id"]: o for o in bundle.get("objects", [])}
    indicates: dict[str, list[str]] = {}
    for o in objs.values():
        if o.get("type") == "relationship" and o.get("relationship_type") == "indicates":
            target = objs.get(o.get("target_ref"), {})
            if target.get("type") == "threat-actor":
                indicates.setdefault(o["source_ref"], []).append(target.get("name", "?"))
    out = []
    for o in objs.values():
        if o.get("type") != "indicator":
            continue
        m = STIX2_PATTERN.fullmatch(o.get("pattern", "").strip())
        if not m:
            fail(f"{path}: unsupported pattern {o.get('pattern')!r}")
        value = m.group(2) or m.group(5)
        out.append({
            "value": value,
            "type": classify(value),
            "stix_id": o["id"],
            "name": o.get("name"),
            "valid_from": o.get("valid_from"),
            "indicates": sorted(indicates.get(o["id"], [])),
        })
    return out


def parse_stix1_xml(path: str) -> list[dict]:
    """STIX 1.x package: address values and simple hash values."""
    text = Path(path).read_text(encoding="utf-8")
    if re.search(r"<!DOCTYPE|<!ENTITY", text, re.I):
        fail(f"{path}: refusing XML with DOCTYPE/ENTITY declarations")
    root = ET.fromstring(text)
    out = []
    for el in root.iter():
        tag = el.tag.rsplit("}", 1)[-1]
        if tag in ("Address_Value", "Simple_Hash_Value") and (el.text or "").strip():
            value = el.text.strip()
            out.append({"value": value, "type": classify(value)})
    return out


class _TableParser(HTMLParser):
    """Collects every <table> as caption + rows of cell text. Drops the
    hidden responsive-table labels (tablesaw-cell-label) a browser injects."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.tables: list[dict] = []
        self._cell: list[str] | None = None
        self._caption: list[str] | None = None
        self._row: list[str] | None = None
        self._skip = 0

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if self._skip:
            self._skip += 1
            return
        if "tablesaw-cell-label" in (a.get("class") or ""):
            self._skip = 1
            return
        if tag == "table":
            self.tables.append({"caption": "", "rows": []})
        elif tag == "caption" and self.tables:
            self._caption = []
        elif tag == "tr" and self.tables:
            self._row = []
        elif tag in ("td", "th") and self._row is not None:
            self._cell = []

    def handle_endtag(self, tag):
        if self._skip:
            self._skip -= 1
            return
        if tag == "caption" and self._caption is not None:
            self.tables[-1]["caption"] = " ".join("".join(self._caption).split())
            self._caption = None
        elif tag in ("td", "th") and self._cell is not None and self._row is not None:
            self._row.append(" ".join("".join(self._cell).split()))
            self._cell = None
        elif tag == "tr" and self._row is not None:
            self.tables[-1]["rows"].append(self._row)
            self._row = None

    def handle_data(self, data):
        if self._skip:
            return
        if self._cell is not None:
            self._cell.append(data)
        elif self._caption is not None:
            self._caption.append(data)


def parse_html_tables(path: str, header_contains: str) -> list[dict]:
    """HTML page: every table whose header row contains `header_contains`,
    as {caption, rows: [dict(header -> cell)]} with indicator cells refanged."""
    p = _TableParser()
    p.feed(Path(path).read_text(encoding="utf-8"))
    found = []
    for t in p.tables:
        if not t["rows"] or not any(header_contains in h for h in t["rows"][0]):
            continue
        head = t["rows"][0]
        rows = [dict(zip(head, r)) for r in t["rows"][1:] if len(r) == len(head)]
        for r in rows:
            r["Indicator"] = refang(r["Indicator"])
        found.append({"caption": t["caption"], "rows": rows})
    return found


def parse_eset_adoc(path: str) -> list[dict]:
    """ESET malware-ioc README.adoc: tables (|=== ... |===) keyed by their
    header row, listing blocks (----) and '- value' bullets, each tagged with
    the section heading it sits under."""
    out: list[dict] = []
    section, mode, head = "", None, None
    for raw in Path(path).read_text(encoding="utf-8").splitlines():
        line = raw.rstrip()
        if mode is None and line.startswith("=="):
            section = line.lstrip("= ").strip()
            continue
        if re.fullmatch(r"\|={3,}", line):
            mode, head = (None, None) if mode == "table" else ("table", None)
            continue
        if line == "----":
            mode = None if mode == "listing" else "listing"
            continue
        if mode == "table" and line.startswith("|"):
            cells = [c.strip() for c in line[1:].split("|")]
            if head is None:
                head = cells
                continue
            row = dict(zip(head, cells))
            first = re.sub(r"^`\+?|\+?`$", "", cells[0])
            row["_value"] = refang(first)
            row["_section"] = section
            out.append(row)
        elif mode == "listing" and line.strip():
            out.append({"_value": refang(line.strip()), "_section": section})
        elif mode is None and re.match(r"^- \S", line):
            value = refang(line[2:].strip())
            if re.fullmatch(r"[0-9.]+|[0-9A-Fa-f]{32,64}", value):
                out.append({"_value": value, "_section": section})
    for r in out:
        r["type"] = classify(r["_value"])
    return out


def parse_hash_list(path: str) -> list[dict]:
    """One hash per line (ESET samples.md5 / .sha1 / .sha256)."""
    out = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        if line.strip():
            out.append({"value": line.strip(), "type": classify(line.strip())})
    return out


# --------------------------------------------------------------- profiles --

def profile_cisa_aa26_097a(a) -> list[dict]:
    july = parse_stix2_json(a.stix2)
    july_xml = parse_stix1_xml(a.stix1)
    tables = parse_html_tables(a.page, "Beginning of Actor Association")
    prior = parse_stix2_json(a.prior_stix2) if a.prior_stix2 else []
    prior_xml = parse_stix1_xml(a.prior_stix1) if a.prior_stix1 else []

    s_json = {i["value"] for i in july}
    s_xml = {i["value"] for i in july_xml}
    rows = {r["Indicator"]: (t["caption"], r) for t in tables for r in t["rows"]}
    if len(july) != len(s_json) or s_json != s_xml or s_json != set(rows):
        fail("July STIX JSON, July STIX XML and the advisory tables disagree")
    s_prior = {i["value"] for i in prior}
    if prior and (s_prior != {i["value"] for i in prior_xml} or not s_prior <= s_json):
        fail("April STIX JSON/XML disagree or are not a subset of July")
    note(f"aa26-097a: {len(s_json)} values agree across July JSON, July XML and "
         f"{len(tables)} page tables; April bundle {len(s_prior)} values, all in July")

    out = []
    for ind in sorted(july, key=lambda i: tuple(int(x) for x in i["value"].split("."))):
        caption, row = rows[ind["value"]]
        table = "Table 1 (new in the July 22, 2026 update)" if caption.startswith("Table 1") else "Table 2"
        ctx = (f"AA26-097A {table}: an IP address the FBI observed the Iranian-affiliated APT actors "
               f"using to communicate with PLCs; actor association {row['Beginning of Actor Association']} "
               f"to {row['End of Actor Association']}. Role not stated by the authoring agencies")
        if ind["value"] in s_prior:
            ctx += "; also in the April 7, 2026 STIX bundle"
        if ind["indicates"]:
            names = ", ".join(f"'{n}'" for n in ind["indicates"])
            ctx += (f"; CISA's July 2026 STIX JSON links it by an 'indicates' relationship to "
                    f"threat-actor object(s) {names} (the advisory text does not)")
        out.append({
            "type": ind["type"],
            "value": ind["value"],
            "role": "unknown",
            "first_seen": month_to_fuzzy(row["Beginning of Actor Association"]),
            "last_seen": month_to_fuzzy(row["End of Actor Association"]),
            "context": ctx,
        })
    return out


# ESET DynoWiper: role and context keyed on the README's own Description and
# Details columns; the quoted clauses are ESET's blog wording.
DYNOWIPER_FILE_RULES = {
    "DynoWiper.": ("actor-controlled",
                   "DynoWiper sample; ESET: the attackers deployed DynoWiper to C:\\inetpub\\pub\\ at a Polish "
                   "energy company on 29 December 2025"),
    "ZOV wiper.": ("actor-controlled",
                   "ZOV wiper sample, listed by ESET for comparison and not reported in the Poland intrusion; ESET "
                   "describes ZOV cases at a financial institution in Ukraine (November 2025) and an energy company "
                   "in Ukraine (25 January 2024) without saying which sample came from which, and attributes ZOV to "
                   "Sandworm with high confidence"),
    "rsocx SOCKS5 proxy tool.": ("actor-controlled",
                                 "ESET: the attackers 'tried to download and launch a publicly available SOCKS5 "
                                 "proxy tool called rsocx' in reverse-connect mode in early December 2025"),
    "Rubeus toolset for Kerberos attacks.": ("actor-controlled",
                                             "ESET: 'In early stages of the attack, attackers attempted to "
                                             "download the publicly available Rubeus tool'"),
}
DYNOWIPER_NET_RULES = {
    "SOCKS5 server.": ("compromised-infrastructure",
                       "SOCKS5 server, the rsocx reverse-connect target on port 8008; ESET: 'This server is used "
                       "by ProGame (progamevl[.]ru), a programming school for kids in Vladivostok, Russia, and was "
                       "likely compromised.'"),
}


def _eset_hash_lists(a, readme_hashes: set[str], label: str) -> list[dict]:
    """samples.* entries: a README hash is cross-checked; any other hash is
    kept with role unknown, because the samples files do not map hashes to
    the README's rows."""
    out = []
    for path in a.hashes:
        entries = parse_hash_list(path)
        kinds = {e["type"] for e in entries}
        if len(kinds) != 1:
            fail(f"{path}: mixed hash types")
        kind = kinds.pop()
        values = {norm(e["value"]) for e in entries}
        if kind == "sha1":
            if values != readme_hashes:
                fail(f"{path}: SHA-1 list differs from the README")
            note(f"{label}: samples.sha1 matches the README's {len(values)} SHA-1 values")
            continue
        note(f"{label}: {Path(path).name} has {len(values)} {kind} values (not mapped to README rows)")
        for v in sorted(values):
            out.append({
                "type": kind,
                "value": v,
                "role": "unknown",
                "context": (f"ESET {label} IoCs, samples.{kind}: one of the {len(values)} sample hashes in the "
                            f"same directory as the README; ESET does not map it to a README row"),
            })
    return out


def profile_eset_dynowiper(a) -> list[dict]:
    rows = parse_eset_adoc(a.readme)
    out, readme_sha1 = [], set()
    for r in rows:
        if r["_section"] == "Files":
            role, why = DYNOWIPER_FILE_RULES.get(r.get("Description", ""), ("unknown", "role not stated"))
            readme_sha1.add(norm(r["_value"]))
            out.append({
                "type": r["type"], "value": norm(r["_value"]), "role": role,
                "context": (f"{why}. File name {r.get('Filename')}, ESET detection {r.get('Detection')} "
                            f"(README Files table: '{r.get('Description')}')"),
            })
        elif r["_section"] == "Network":
            role, why = DYNOWIPER_NET_RULES.get(r.get("Details", ""), ("unknown", "role not stated"))
            item = {"type": r["type"], "value": r["_value"], "role": role,
                    "context": f"{why} (README Network table: '{r.get('Details')}')"}
            if re.fullmatch(r"\d{4}-\d{2}-\d{2}", r.get("First seen", "")):
                item["first_seen"] = r["First seen"]
            out.append(item)
        else:
            fail(f"unexpected README section {r['_section']!r}")
    out += _eset_hash_lists(a, readme_sha1, "DynoWiper")
    return out


INDUSTROYER_SECTION_RULES = {
    "SHA-1 hashes": ("actor-controlled",
                     "Win32/Industroyer sample listed in ESET's Industroyer IoCs (README 'SHA-1 hashes'; the "
                     "component is not stated)"),
    "IP addresses of C&C servers": ("unknown",
                                    "C&C server address listed by ESET (README 'IP addresses of C&C servers'); "
                                    "ESET warns: 'Most of the servers with these IP addresses were part of Tor "
                                    "network, which means that the use of these indicators could result in false "
                                    "positives.' Which addresses were Tor relays is not stated"),
}


def profile_eset_industroyer(a) -> list[dict]:
    rows = parse_eset_adoc(a.readme)
    out, readme_sha1 = [], set()
    for r in rows:
        if r["_section"] not in INDUSTROYER_SECTION_RULES:
            fail(f"unexpected README section {r['_section']!r}")
        role, ctx = INDUSTROYER_SECTION_RULES[r["_section"]]
        if r["type"] == "sha1":
            readme_sha1.add(norm(r["_value"]))
        out.append({"type": r["type"], "value": norm(r["_value"]), "role": role, "context": ctx})
    out += _eset_hash_lists(a, readme_sha1, "Industroyer")
    return out


PARSERS = {
    "stix2-json": parse_stix2_json,
    "stix1-xml": parse_stix1_xml,
    "eset-adoc": parse_eset_adoc,
    "hash-list": parse_hash_list,
}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("cisa-aa26-097a")
    c.add_argument("--stix2", required=True)
    c.add_argument("--stix1", required=True)
    c.add_argument("--page", required=True)
    c.add_argument("--prior-stix2")
    c.add_argument("--prior-stix1")
    for name in ("eset-dynowiper", "eset-industroyer"):
        e = sub.add_parser(name)
        e.add_argument("--readme", required=True)
        e.add_argument("--hashes", nargs="*", default=[])
    d = sub.add_parser("dump")
    d.add_argument("format", choices=sorted(PARSERS))
    d.add_argument("file")
    a = ap.parse_args()

    if a.cmd == "dump":
        yaml.safe_dump(PARSERS[a.format](a.file), sys.stdout, sort_keys=False, allow_unicode=True)
        return 0
    profile = {"cisa-aa26-097a": profile_cisa_aa26_097a,
               "eset-dynowiper": profile_eset_dynowiper,
               "eset-industroyer": profile_eset_industroyer}[a.cmd]
    inputs = [v for k, v in vars(a).items() if k not in ("cmd",) and isinstance(v, str)]
    inputs += [h for h in getattr(a, "hashes", [])]
    for path in inputs:
        note(f"input {path} sha256={file_digest(path)}")
    indicators = profile(a)
    values = [(i["type"], i["value"]) for i in indicators]
    if len(values) != len(set(values)):
        fail("duplicate indicator in output")
    counts: dict[str, int] = {}
    for i in indicators:
        key = f"{i['type']}/{i['role']}"
        counts[key] = counts.get(key, 0) + 1
    note("counts: " + ", ".join(f"{k}={v}" for k, v in sorted(counts.items())))
    yaml.safe_dump({"indicators": indicators}, sys.stdout, sort_keys=False, allow_unicode=True, width=110)
    return 0


if __name__ == "__main__":
    sys.exit(main())
