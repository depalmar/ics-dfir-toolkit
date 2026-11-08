#!/usr/bin/env python3
"""validate.py - the gate. Never commit while it reports problems.

Checks every record under artifacts/ against its schema AND against each other:

  * every record validates against its schema (shared vocab in common.schema.json)
  * ids are unique; id-bearing files are named <id>-<slug>.yml
  * anything rated confidence: low carries unverified: true, at any depth
  * a record whose every source was read through a summariser is unverified
  * high confidence never rests on press sources alone
  * every ICS id mentioned anywhere (ICS-NNNN, ICS-TA-, ICS-MAL-, ...) exists
  * platform response/hardening stems exist
  * every rule path a pack, hunt or malware record names exists, and every rule
    file in a numbered directory is linked by something or tagged standalone
  * every numbered rule directory has a README.md
  * pack regexes compile; hardening control ids are unique per file
  * exploitation earliest_words sit inside their quote

Cross-record asymmetries (an actor lists a malware family that does not list
the actor back) are printed as warnings, not failures.

Run from the repository root:  python artifacts/scripts/validate.py
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import yaml
from jsonschema import Draft202012Validator
from referencing import Registry, Resource

ROOT = Path(__file__).resolve().parents[2]
ART = ROOT / "artifacts"
SCHEMA_DIR = ART / "schema"

# directory -> (schema file, id regex or None when the file stem is free)
RECORD_DIRS: dict[str, tuple[str, str | None]] = {
    "catalog": ("platform.schema.json", r"ICS-[0-9]{4}"),
    "protocols": ("protocol.schema.json", r"ICS-PROTO-[0-9]{4}"),
    "visibility": ("datasource.schema.json", r"ICS-DS-[0-9]{4}"),
    "intel/actors": ("actor.schema.json", r"ICS-TA-[0-9]{4}"),
    "intel/malware": ("malware.schema.json", r"ICS-MAL-[0-9]{4}"),
    "intel/iocs": ("ioc.schema.json", r"ICS-IOC-[0-9]{4}"),
    "intel/incidents": ("incident.schema.json", r"ICS-INC-[0-9]{4}"),
    "hunts": ("hunt.schema.json", r"ICS-HUNT-[0-9]{4}"),
    "packs": ("pack.schema.json", r"ICS-PACK-[0-9]{4}"),
    "hardening": ("hardening.schema.json", None),
    "response": ("response.schema.json", None),
}
SINGLE_FILES: dict[str, str] = {
    "intel/exploitation.yml": "exploitation.schema.json",
    "watch/kev-watch.yml": "watch.schema.json",
}
ANY_ID = re.compile(r"^ICS-(?:(?:TA|MAL|IOC|INC|HUNT|PACK|DS|PROTO)-)?[0-9]{4}$")
RULE_PATH = re.compile(r"^[0-9]{2}-[a-z0-9-]+/[a-z0-9_]+\.(?:yml|yar|rules)$")
STANDALONE = "ics-dfir.standalone"

problems: list[str] = []
warnings: list[str] = []


def err(msg: str) -> None:
    problems.append(msg)


def warn(msg: str) -> None:
    warnings.append(msg)


def build_registry() -> tuple[Registry, dict[str, dict]]:
    schemas: dict[str, dict] = {}
    registry: Registry = Registry()
    for p in sorted(SCHEMA_DIR.glob("*.schema.json")):
        try:
            doc = json.loads(p.read_text())
        except json.JSONDecodeError as e:
            err(f"schema/{p.name}: invalid JSON: {e}")
            continue
        Draft202012Validator.check_schema(doc)
        schemas[p.name] = doc
        registry = registry.with_resource(doc["$id"], Resource.from_contents(doc))
    return registry, schemas


def load_yaml(p: Path):
    try:
        return yaml.safe_load(p.read_text())
    except yaml.YAMLError as e:
        err(f"{rel(p)}: YAML error: {e}")
        return None


def rel(p: Path) -> str:
    return str(p.relative_to(ROOT))


def walk(node, path=()):
    """Yield (path, value) for every scalar and dict in a document."""
    yield path, node
    if isinstance(node, dict):
        for k, v in node.items():
            yield from walk(v, path + (k,))
    elif isinstance(node, list):
        for i, v in enumerate(node):
            yield from walk(v, path + (i,))


def check_low_confidence(doc, where: str) -> None:
    for path, node in walk(doc):
        if not isinstance(node, dict) or node.get("unverified"):
            continue
        for key in ("confidence", "link_confidence"):
            if node.get(key) == "low":
                loc = "/".join(str(x) for x in path) or "<root>"
                err(f"{where}: {loc}: {key} low requires unverified: true")


def check_sources(doc, where: str) -> None:
    for path, node in walk(doc):
        if not isinstance(node, dict):
            continue
        srcs = node.get("sources")
        if not isinstance(srcs, list) or not srcs or not all(isinstance(s, dict) for s in srcs):
            continue
        loc = "/".join(str(x) for x in path) or "<root>"
        if all(s.get("read") == "summariser" for s in srcs) and not node.get("unverified"):
            err(f"{where}: {loc}: every source was read through a summariser; mark unverified: true until a direct read")
        if node.get("confidence") == "high" and srcs and all(s.get("kind") == "press" for s in srcs):
            err(f"{where}: {loc}: high confidence cannot rest on press sources alone")


def main() -> int:
    registry, schemas = build_registry()
    validators = {
        name: Draft202012Validator(doc, registry=registry) for name, doc in schemas.items()
    }

    def validate(doc, schema_name: str, where: str) -> None:
        v = validators.get(schema_name)
        if v is None:
            err(f"{where}: schema {schema_name} missing")
            return
        for e in sorted(v.iter_errors(doc), key=lambda e: list(e.path)):
            loc = "/".join(str(x) for x in e.path) or "<root>"
            err(f"{where}: {loc}: {e.message}")

    records: dict[str, tuple[str, dict]] = {}  # id -> (relpath, doc)
    by_dir: dict[str, list[tuple[Path, dict]]] = {}
    stems: dict[str, set[str]] = {"hardening": set(), "response": set()}

    for d, (schema_name, id_re) in RECORD_DIRS.items():
        by_dir[d] = []
        for p in sorted((ART / d).glob("*.yml")):
            doc = load_yaml(p)
            if doc is None:
                continue
            where = rel(p)
            if not isinstance(doc, dict):
                err(f"{where}: top level must be a mapping")
                continue
            validate(doc, schema_name, where)
            check_low_confidence(doc, where)
            check_sources(doc, where)
            by_dir[d].append((p, doc))
            if d in stems:
                stems[d].add(p.stem)
            if id_re:
                rid = doc.get("id")
                if not isinstance(rid, str) or not re.fullmatch(id_re, rid):
                    continue
                if not re.fullmatch(re.escape(rid) + r"-[a-z0-9][a-z0-9-]*", p.stem):
                    err(f"{where}: file must be named {rid}-<slug>.yml")
                if rid in records:
                    err(f"{where}: duplicate id {rid} (also {records[rid][0]})")
                records[rid] = (where, doc)

    singles: dict[str, dict] = {}
    for relpath, schema_name in SINGLE_FILES.items():
        p = ART / relpath
        if not p.exists():
            continue
        doc = load_yaml(p)
        if doc is None:
            continue
        validate(doc, schema_name, rel(p))
        check_low_confidence(doc, rel(p))
        singles[relpath] = doc

    # ---- every id mentioned anywhere exists
    all_docs: list[tuple[str, dict]] = [(rel(p), doc) for items in by_dir.values() for p, doc in items]
    all_docs += [(f"artifacts/{k}", v) for k, v in singles.items()]
    for where, doc in all_docs:
        own = doc.get("id") if isinstance(doc, dict) else None
        for path, node in walk(doc):
            if isinstance(node, str) and ANY_ID.match(node) and node != own and node not in records:
                loc = "/".join(str(x) for x in path)
                err(f"{where}: {loc}: references {node}, which has no record")

    # ---- platform stems
    for p, doc in by_dir["catalog"]:
        for key in ("response", "hardening"):
            stem = doc.get(key)
            if stem and stem not in stems[key]:
                err(f"{rel(p)}: {key} '{stem}' has no artifacts/{key}/{stem}.yml")

    # ---- packs: regexes, detection ids, rules
    detection_ids: set[str] = set()
    linked_rules: set[str] = set()
    for p, doc in by_dir["packs"]:
        seen: set[str] = set()
        for det in doc.get("detect", []):
            did = det.get("id")
            if did in seen:
                err(f"{rel(p)}: duplicate detection id {did}")
            seen.add(did)
            if did in detection_ids:
                err(f"{rel(p)}: detection id {did} is used by another pack")
            detection_ids.add(did)
            for key in ("pattern",):
                if det.get(key):
                    try:
                        re.compile(det[key])
                    except re.error as e:
                        err(f"{rel(p)}: {did}: pattern does not compile: {e}")
            for x in det.get("exclude", []):
                try:
                    re.compile(x)
                except re.error as e:
                    err(f"{rel(p)}: {did}: exclude does not compile: {e}")
            linked_rules.update(det.get("rules", []))
    for p, doc in by_dir["hunts"]:
        linked_rules.update(doc.get("rules", []))
    for p, doc in by_dir["intel/malware"]:
        for d in doc.get("detections", []):
            if RULE_PATH.match(d):
                linked_rules.add(d)
            elif d not in detection_ids:
                err(f"{rel(p)}: detection '{d}' is neither a pack detection id nor a rule path")

    for r in sorted(linked_rules):
        if not (ROOT / r).exists():
            err(f"rule {r} is referenced but does not exist")

    rule_dirs = sorted(d for d in ROOT.glob("[0-9][0-9]-*") if d.is_dir())
    for d in rule_dirs:
        if not (d / "README.md").exists():
            err(f"{d.name}/: numbered rule directory needs a README.md")
        for f in sorted(list(d.glob("*.yml")) + list(d.glob("*.yar")) + list(d.glob("*.rules"))):
            r = rel(f)
            if r not in linked_rules and STANDALONE not in f.read_text(errors="replace"):
                err(f"{r}: not linked by any pack, hunt or malware record and not tagged {STANDALONE}")

    # ---- hardening control ids unique per file
    for p, doc in by_dir["hardening"]:
        ids = [c.get("id") for c in doc.get("controls", [])]
        dup = {i for i in ids if ids.count(i) > 1}
        for i in sorted(dup):
            err(f"{rel(p)}: duplicate control id {i}")

    # ---- exploitation quotes carry their own dates
    for rec in singles.get("intel/exploitation.yml", {}).get("records", []):
        for rep in rec.get("reports", []):
            words = rep.get("earliest_words")
            if words and words not in rep.get("quote", ""):
                err(f"intel/exploitation.yml: {rec.get('cve')}: earliest_words not found inside the quote")

    # ---- asymmetries (warnings)
    pairs = [
        ("intel/actors", "malware", "intel/malware", "actors"),
        ("intel/actors", "incidents", "intel/incidents", "actors"),
        ("intel/malware", "incidents", "intel/incidents", "malware"),
    ]
    for a_dir, a_key, b_dir, b_key in pairs:
        for p, doc in by_dir[a_dir]:
            for ref in doc.get(a_key, []):
                target = records.get(ref)
                if target and doc.get("id") not in target[1].get(b_key, []):
                    warn(f"{rel(p)} lists {ref} in {a_key}, but {target[0]} does not list {doc.get('id')} in {b_key}")

    counts = {d: len(v) for d, v in by_dir.items()}
    summary = ", ".join(f"{d}={n}" for d, n in counts.items() if n)
    for w in warnings:
        print(f"warning: {w}")
    if problems:
        for m in problems:
            print(f"ERROR: {m}")
        print(f"\n{len(problems)} problem(s); {len(warnings)} warning(s). Records: {summary or 'none'}")
        return 1
    print(f"OK - {summary or 'no records yet'}; {len(warnings)} warning(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
