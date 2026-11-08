"""Offline tests for the maintenance scripts. No network: fetchers are faked."""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "artifacts" / "scripts"


def load(name: str):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


cq = load("check_quotes")
aw = load("advisory_watch")
mp = load("mappings")


# ---- check_quotes

def test_norm_forgives_only_typography():
    a = cq.norm("The “IP address” – and  program are now   erased ( see SD1790 ).")
    b = cq.norm('the "ip address" - and program are now erased (see SD1790).')
    assert a == b


def test_check_matches_reports_missing_and_rendered():
    page = b"<html><body><p>The IP address and <b>program</b> are now erased.</p></body></html>"
    sources = [
        {"file": "f", "record": "r1", "url": "https://example.org/a", "quote": "The IP address and program are now erased", "read": "summariser"},
        {"file": "f", "record": "r2", "url": "https://example.org/a", "quote": "a sentence that is not there", "read": "direct"},
        {"file": "f", "record": "r3", "url": "https://docs.aveva.com/x", "quote": "built in the browser", "read": "direct"},
        {"file": "f", "record": "r4", "url": "https://example.org/gone", "quote": "anything at all", "read": "direct"},
    ]

    def getter(u: str) -> bytes:
        if u.endswith("/gone"):
            raise TimeoutError("slow")
        return page

    res = {r["record"]: r for r in cq.check(sources, getter)}
    assert res["r1"]["status"] == "ok"
    assert res["r2"]["status"] == "missing" and "closest" in res["r2"]
    assert res["r3"]["status"] == "rendered"
    assert res["r4"]["status"].startswith("unfetched")
    text = cq.report(list(res.values()))
    assert "can become `read: direct`" in text


def test_collect_finds_every_quoted_source_in_the_repository():
    found = cq.collect(ROOT)
    assert len(found) > 500
    assert all(s["url"].startswith("https://") and s["quote"] for s in found)


# ---- advisory_watch

def test_triage_splits_new_ledger_and_covered():
    watch = {"since": "2023-01-01",
             "platforms": {"ICS-0001": {"vendor": "Rockwell", "product": "Logix"},
                           "ICS-0006": {"vendor": "Unitronics", "product": "Vision"}},
             "triaged": [{"cve": "CVE-2023-6448", "platform": "ICS-0006", "decision": "no-indicators",
                          "date": "2026-11-08", "basis": "primary sources read"}]}
    kev = {"vulnerabilities": [
        {"cveID": "CVE-2021-22681", "vendorProject": "Rockwell Automation", "product": "Logix Controllers", "dateAdded": "2026-03-05"},
        {"cveID": "CVE-2023-6448", "vendorProject": "Unitronics", "product": "Vision PLC and HMI", "dateAdded": "2023-12-11"},
        {"cveID": "CVE-2099-0001", "vendorProject": "Rockwell Automation", "product": "Logix Controllers", "dateAdded": "2026-10-01"},
        {"cveID": "CVE-2020-0001", "vendorProject": "Rockwell Automation", "product": "Logix Controllers", "dateAdded": "2020-01-01"},
        {"cveID": "CVE-2025-0002", "vendorProject": "Other", "product": "Thing", "dateAdded": "2025-01-01"},
    ]}
    res = aw.triage(kev, watch, {"CVE-2021-22681": ["ICS-PACK-0001"]})
    assert [r["cve"] for r in res["covered"]] == ["CVE-2021-22681"]
    assert [r["cve"] for r in res["decided"]] == ["CVE-2023-6448"]
    assert [r["cve"] for r in res["new"]] == ["CVE-2099-0001"]   # before `since` and unwatched vendors drop out


def test_upstream_reports_changed_and_unreachable_files():
    watch = {"upstream": {"ICS-IOC-0001": "0" * 64, "ICS-IOC-0002": "0" * 64}}
    files = {"ICS-IOC-0001": "https://example.org/a.json", "ICS-IOC-0002": "https://example.org/b.json"}

    def getter(u: str) -> bytes:
        if u.endswith("b.json"):
            raise OSError("blocked")
        return b"{}"

    out = {c["id"]: c for c in aw.upstream_changes(watch, files, getter)}
    assert len(out["ICS-IOC-0001"]["now"]) == 64
    assert out["ICS-IOC-0002"]["now"].startswith("unreachable")


def test_repository_watch_file_loads_and_every_named_cve_is_well_formed():
    watch = aw.load_watch()
    assert watch["platforms"] and watch["since"]
    assert all(aw.CVE_RE.fullmatch(c) for c in aw.structured_refs())


# ---- mappings

def test_mappings_file_is_current():
    assert (ROOT / "MAPPINGS.md").read_text() == mp.build(), "run python artifacts/scripts/mappings.py"


def test_mappings_classifies_matrices_and_links_subtechniques():
    assert mp.matrix("T0836") == "ICS" and mp.matrix("T1059.004") == "Enterprise"
    assert "techniques/T1059/004/" in mp.link("T1059.004")
