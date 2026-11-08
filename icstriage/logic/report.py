"""Markdown and JSON reports for a logic comparison.

Verdicts are DIFFERENCES-FOUND or NO-DIFFERENCES-FOUND. The second means
only that no counted difference was found in what this tool compares; every
report carries the limits below so that it cannot be read as more.
"""
from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timezone

from .. import __version__
from .diff import DiffResult
from .model import CLASSES, Model

DIFFERENCES = "DIFFERENCES-FOUND"
NONE_FOUND = "NO-DIFFERENCES-FOUND"

LIMITS = [
    "This is an offline comparison of two exported project files. The tool never connects to a controller.",
    "An export reflects the project file it was produced from. It shows the logic running in a controller only "
    "if the engineer uploaded from that controller into a new, empty project and exported that project; an "
    "export of a project file from a workstation, share or repository shows that file, not the controller.",
    "Firmware-level or memory-only modifications (for example TRITON-style implants in controller memory) are "
    "not visible in a project export.",
    "Opaque sections (graphical FBD, SFC and LD bodies, source-protected or encoded content, vendor-specific "
    "data and unmodelled elements) are compared by content hash only: a hash difference says that something "
    "changed, not what, and layout-only edits change the hash too.",
    "The comparison is only as good as the baseline. A known-good copy must come from a controlled source taken "
    "before the period of concern; a baseline exported or backed up after a compromise reproduces the "
    "attacker's logic.",
    "NO-DIFFERENCES-FOUND means no counted difference was found in the elements this tool compares. It does not "
    "show that the controller is uncompromised: controllers cannot be imaged the way hosts can.",
    "Documentation-only differences (descriptions, comments, display radix) and provenance fields (timestamps, "
    "exporting software, export options) are reported but never counted toward the verdict.",
    "Stored tag and variable values are a snapshot taken at export or upload time. Value differences between an "
    "offline baseline and an uploaded project are expected for live process data and need review, not assumption.",
]
FORMAT_LIMITS = {
    "L5X": [
        "L5X elements read follow Rockwell 1756-RM014D (September 2025). Rung text is compared as exported "
        "neutral text after whitespace normalisation; instruction semantics are not interpreted.",
        "Rung comments and descriptions reach the controller only if the project downloads documentation "
        "(RM014 attribute DownloadProjectDocumentationAndExtendedProperties); an uploaded project can therefore "
        "differ from its source in documentation only (toolkit inference, not a Rockwell statement).",
    ],
    "PLCopen TC6 XML": [
        "PLCopen elements read follow the TC6_XML_V201 schema. ST and IL bodies are compared line by line with "
        "comments removed; FBD, LD and SFC bodies and vendor addData are compared by hash.",
        "A PLCopen export is always produced from a project in an engineering tool. For CODESYS, the source "
        "available from a controller is the Archive.prj someone last placed there (ICS-0009), not a "
        "reconstruction of the running application; use the platform record's login comparison for that question.",
    ],
}


def _coverage(m: Model) -> dict:
    kinds = Counter(e.kind for e in m.entities.values() if e.kind not in ("export", "project", "controller"))
    langs = Counter(r.language for r in m.routines.values())
    opaque = sum(1 for r in m.routines.values() if r.opaque_hash)
    return {"entities": dict(sorted(kinds.items())), "routines": dict(sorted(langs.items())),
            "routines_compared_by_hash": opaque}


def _input(m: Model) -> dict:
    exp = m.entities.get("Export")
    provenance = {k: f.value for k, f in exp.fields.items()} if exp else {}
    return {"path": m.path, "sha256": m.sha256, "size": m.size, "format": m.fmt, "scope": m.scope,
            "export": provenance, "coverage": _coverage(m)}


def build(base: Model, cur: Model, res: DiffResult, *, generated: str | None = None) -> dict:
    counted = Counter(d.cls for d in res.differences if d.counted)
    info = Counter(d.cls for d in res.differences if not d.counted)
    verdict = DIFFERENCES if counted else NONE_FOUND
    order = {c: i for i, c in enumerate(CLASSES)}
    diffs = sorted(res.differences, key=lambda d: (not d.counted, order.get(d.cls, 99)))
    return {
        "tool": f"icstriage logic-diff {__version__}",
        "generated": generated or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "verdict": verdict,
        "inputs": {"baseline": _input(base), "current": _input(cur)},
        "summary": {
            "counted": {c: counted[c] for c in CLASSES if counted[c]},
            "informational": {c: info[c] for c in CLASSES if info[c]},
            "total": len(res.differences),
        },
        "differences": [d.as_dict() for d in diffs],
        "not_evaluated": list(res.not_evaluated),
        "notes": list(res.notes),
        "limits": LIMITS + FORMAT_LIMITS.get(base.fmt, []),
    }


def to_json(report: dict) -> str:
    return json.dumps(report, indent=2, ensure_ascii=False) + "\n"


def _code(v, limit: int = 240) -> str:
    """Render untrusted text as a Markdown code span, one line, bounded."""
    if v is None:
        return "(absent)"
    s = str(v).replace("\r", " ").replace("\n", " / ").replace("`", "'")
    if len(s) > limit:
        s = s[:limit] + f"... (+{len(s) - limit} chars)"
    return f"`{s}`" if s else "`(empty)`"


def _plain(v) -> str:
    """Untrusted text outside a code span: one line, no backticks."""
    return str(v).replace("\r", " ").replace("\n", " / ").replace("`", "'")


def to_markdown(report: dict) -> str:
    out = []
    b, c = report["inputs"]["baseline"], report["inputs"]["current"]
    out.append("# Logic comparison report")
    out.append("")
    out.append(f"**Verdict: {report['verdict']}**")
    out.append("")
    if report["verdict"] == DIFFERENCES:
        n = sum(report["summary"]["counted"].values())
        out.append(f"{n} counted difference(s) between the baseline and the current export. Review each one "
                   "against approved change records before drawing conclusions.")
    else:
        out.append("No counted difference was found in the elements compared. Read the limits below: this "
                   "verdict does not show that the controller is uncompromised.")
    out.append("")
    out.append(f"Generated {report['generated']} by {report['tool']}.")
    out.append("")
    out.append("## Inputs")
    out.append("")
    out.append("| | Baseline (known-good) | Current (under review) |")
    out.append("| --- | --- | --- |")
    out.append(f"| File | {_code(b['path'])} | {_code(c['path'])} |")
    out.append(f"| SHA-256 | `{b['sha256']}` | `{c['sha256']}` |")
    out.append(f"| Size (bytes) | {b['size']} | {c['size']} |")
    out.append(f"| Format | {b['format']} | {c['format']} |")
    out.append(f"| Scope | {_code(b['scope'])} | {_code(c['scope'])} |")
    for key in sorted(set(b["export"]) | set(c["export"])):
        out.append(f"| {_code(key, 60)} | {_code(b['export'].get(key), 80)} | {_code(c['export'].get(key), 80)} |")
    out.append("")
    out.append("Compared: " + "; ".join(
        f"{side} {_code(json.dumps(x['coverage'], sort_keys=True), 400)}" for side, x in (("baseline", b), ("current", c))))
    out.append("")
    out.append("## Summary")
    out.append("")
    out.append("| Class | Counted | Informational |")
    out.append("| --- | ---: | ---: |")
    for cls in CLASSES:
        n1 = report["summary"]["counted"].get(cls, 0)
        n2 = report["summary"]["informational"].get(cls, 0)
        if n1 or n2:
            out.append(f"| {cls} | {n1} | {n2} |")
    if not report["differences"]:
        out.append("| (none) | 0 | 0 |")
    out.append("")
    for title, flag in (("Counted differences", True), ("Informational differences (not counted)", False)):
        items = [d for d in report["differences"] if d["counted"] is flag]
        if not items:
            continue
        out.append(f"## {title}")
        out.append("")
        current_cls = None
        for d in items:
            if d["class"] != current_cls:
                current_cls = d["class"]
                out.append(f"### {current_cls}")
                out.append("")
            where = _code(d["path"], 200) + (f" {_code(d['field'], 120)}" if d["field"] else "")
            line = f"- **{d['change']}** {where}: {_code(d['baseline'])} -> {_code(d['current'])}"
            extras = []
            if d["opaque"]:
                extras.append("opaque, compared by hash")
            if d["note"]:
                extras.append(_plain(d["note"]))
            if d["attack_candidates"]:
                extras.append("ATT&CK for ICS candidate: " + ", ".join(d["attack_candidates"]))
            if extras:
                line += " (" + "; ".join(extras) + ")"
            out.append(line)
        out.append("")
    if report["not_evaluated"]:
        out.append("## Not evaluated")
        out.append("")
        out.append("Not evaluated is not passed. These items were seen but could not be compared:")
        out.append("")
        out.extend("- " + _plain(n) for n in report["not_evaluated"])
        out.append("")
    if report["notes"]:
        out.append("## Reader notes")
        out.append("")
        out.extend("- " + _plain(n) for n in report["notes"])
        out.append("")
    out.append("## Limits")
    out.append("")
    out.extend(f"- {n}" for n in report["limits"])
    out.append("")
    out.append("ATT&CK for ICS candidates name techniques a reviewer should consider for a class of change; a "
               "difference is not by itself evidence of adversary activity.")
    out.append("")
    return "\n".join(out)
