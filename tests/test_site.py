"""Tests for the static site generator (artifacts/scripts/build_site.py).

The static half runs everywhere the core suite runs: the --check contract, a
self-contained page whose data block round-trips, escaping of hostile record
text, and the checks --check is meant to catch. The browser half loads the page
from file:// in Chromium and drives it; it skips cleanly when Playwright or a
browser is not installed, so CI never depends on it.
"""
from __future__ import annotations

import copy
import html
import importlib.util
import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "artifacts" / "scripts" / "build_site.py"
EVIL = "</script><script>alert(1)</script><!--<script>"


def _load():
    spec = importlib.util.spec_from_file_location("build_site", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["build_site"] = mod
    spec.loader.exec_module(mod)
    return mod


bs = _load()


@pytest.fixture(scope="module")
def built():
    d = bs.load()
    doc, data = bs.page(d)
    return d, doc, data


def _block(doc: str) -> str:
    m = re.search(r'<script type="application/json" id="data">(.*?)</script>', doc, re.S)
    assert m, "data block missing"
    return m.group(1)


# ---------------------------------------------------------------- static contract

def test_check_passes_on_the_repository_and_writes_nothing():
    before = bs.OUT.stat().st_mtime_ns if bs.OUT.exists() else None
    r = subprocess.run([sys.executable, str(SCRIPT), "--check"], capture_output=True, text=True, cwd=ROOT)
    assert r.returncode == 0, r.stdout + r.stderr
    assert r.stdout.startswith("OK")
    assert (bs.OUT.stat().st_mtime_ns if bs.OUT.exists() else None) == before


def test_page_is_self_contained_and_data_round_trips(built):
    _, doc, data = built
    assert not re.search(r"<script\b[^>]*\bsrc\s*=", doc, re.I)
    assert not re.search(r"<link\b[^>]*stylesheet", doc, re.I)
    assert "@import" not in doc and not re.search(r"url\(\s*['\"]?(?:https?:)?//", doc)
    assert json.loads(_block(doc)) == data
    for lib in bs.FACET_KEYS:
        assert data["libs"][lib], lib
        assert f'id="tab-{lib}"' in doc


def test_js_data_escapes_the_script_close():
    out = bs.js_data({"x": EVIL})
    assert "</" not in out and "<!--" not in out
    assert json.loads(out) == {"x": EVIL}


def test_hostile_record_text_cannot_close_the_data_block(built):
    d, _, _ = built
    d2 = copy.deepcopy(d)
    d2["actors"][0]["summary"] = EVIL
    doc, data = bs.page(d2)
    assert EVIL not in doc
    assert doc.count("</script>") == 2  # the data block and the code, nothing else
    assert json.loads(_block(doc))["libs"]["actors"][0]["summary"] == EVIL
    assert not bs.check(doc, data)


def test_js_facets_match_facet_keys():
    assert bs.js_facets(bs.JS) == {k: list(v) for k, v in bs.FACET_KEYS.items()}


def test_check_catches_what_it_promises(built):
    _, doc, data = built
    assert not bs.check(doc, data)

    def fails(doc2: str, words: str) -> None:
        problems = bs.check(doc2, data)
        assert any(words in p for p in problems), problems

    fails(doc.replace("<footer>", '<footer><a href="#actors?nosuch=1">x</a>', 1), "no facet 'nosuch'")
    fails(doc.replace("<footer>", '<footer><a href="#actors?motivation=nosuch">x</a>', 1), "motivation=nosuch")
    fails(doc.replace("<footer>", '<footer><a href="#actors/ICS-TA-9999">x</a>', 1), "dangling link")
    fails(doc.replace("<footer>", '<footer><b id="rail"></b>', 1), "duplicate element ids")
    fails(doc.replace("</head>", '<script src="https://cdn.example/x.js"></script></head>', 1), "external")
    fails(doc.replace("</head>", '<link rel="stylesheet" href="https://fonts.example/x.css"></head>', 1), "external")
    # a facet the JS defines that FACET_KEYS does not know
    orig = bs.JS
    try:
        bs.JS = orig.replace("facet('motivation',", "facet('motive',", 1)
        fails(doc, "facets for actors")
    finally:
        bs.JS = orig


def test_static_filter_links_all_resolve(built):
    """Start links into the libraries by facet; every one of them must land on records."""
    _, doc, data = built
    links = set(re.findall(r'href="#([a-z]+)\?([a-z]+)=([^"&]+)"', doc.split('<script type="application/json"')[0]))
    assert ("coverage", "status", "gap") in links
    for lib, key, val in links:
        assert key in bs.FACET_KEYS[lib] or key == "unv", (lib, key)
        if key != "unv":
            assert any(html.unescape(val) in r["_f"][key] for r in data["libs"][lib]), (lib, key, val)


def test_coverage_gaps_agree_with_mappings(built):
    _, _, data = built
    gaps = [t["id"] for t in data["libs"]["coverage"] if "gap" in t["_f"]["status"]]
    m = re.search(r"## Gaps: used, but nothing hunts or detects it \((\d+)\)", bs.mappings.build())
    assert m and len(gaps) == int(m.group(1))
    assert len(data["libs"]["coverage"]) == len(bs.mappings.coverage())


def test_credit_is_read_from_notice_and_appears_once_in_the_footer(built):
    _, doc, _ = built
    credit = html.escape(bs.credit())
    assert credit and "·" in credit
    assert doc.count(credit) == 1
    assert credit in doc.split("<footer>", 1)[1]


def test_start_states_the_verdict_rules_and_the_impact_ladder(built):
    _, doc, _ = built
    start = doc.split('id="tab-start"', 1)[1].split('id="tab-platforms"', 1)[0]
    for words in ("Not evaluated is not passed", "Never call a system clean", "NO-INDICATORS-FOUND", "known-good copy"):
        assert words in start
    assert [m for m in re.findall(r'class="rung rung-([a-z-]+)"', start)] == list(bs.IMPACT)


# ---------------------------------------------------------------- browser

@pytest.fixture(scope="module")
def browser():
    sync_api = pytest.importorskip("playwright.sync_api")
    with sync_api.sync_playwright() as p:
        try:
            b = p.chromium.launch()
        except Exception as exc:  # no browser binary on this machine
            pytest.skip(f"chromium not available: {exc}")
        yield b
        b.close()


@pytest.fixture(scope="module")
def site(built, tmp_path_factory):
    _, doc, _ = built
    out = tmp_path_factory.mktemp("site") / "index.html"
    out.write_text(doc, encoding="utf-8")
    return out.as_uri()


def _page(browser, errors: list | None = None, **kw):
    page = browser.new_page(viewport=kw.pop("viewport", {"width": 1366, "height": 900}), **kw)
    if errors is not None:
        page.on("pageerror", lambda e: errors.append(str(e)))
        page.on("console", lambda m: errors.append(m.text) if m.type == "error" else None)
    return page


def _shown(page, lib: str) -> tuple[int, int]:
    m = re.match(r"(\d+) of (\d+) ", page.locator(f"#tab-{lib} .count").inner_text())
    assert m, "count line missing"
    return int(m.group(1)), int(m.group(2))


def test_every_tab_renders_and_every_library_opens_a_drawer(browser, site, built):
    _, _, data = built
    errors: list[str] = []
    page = _page(browser, errors)
    page.goto(site)
    page.locator("#tab-start").wait_for(state="visible")
    assert page.locator("#tab-start .tile").count() == len(bs.FACET_KEYS) + 1
    for lib in bs.FACET_KEYS:
        page.goto(f"{site}#{lib}")
        page.locator(f"#tab-{lib}").wait_for(state="visible")
        assert page.locator(f"#tab-{lib} .item").count() == len(data["libs"][lib]), lib
        assert _shown(page, lib) == (len(data["libs"][lib]),) * 2
        page.locator(f"#tab-{lib} .item .open, #tab-{lib} a.item.open").first.click()
        page.locator("#drawer").wait_for(state="visible")
        assert page.locator("#dBody").inner_text().strip(), lib
        page.keyboard.press("Escape")
        page.locator("#drawer").wait_for(state="hidden")
    for tab, panel in (("intel", "actors"), ("detections", "packs"), ("response", "response")):
        page.goto(f"{site}#{tab}")
        page.locator(f"#tab-{panel}").wait_for(state="visible")
    assert page.locator("#respBody .phase").count() >= 7  # seven phases, then do-not
    assert not errors, errors


def test_search_and_facets_filter_and_live_in_the_hash(browser, site):
    page = _page(browser)
    page.goto(f"{site}#actors")
    shown, total = _shown(page, "actors")
    assert shown == total
    page.fill("#tab-actors .q", "ELECTRUM")
    shown, _ = _shown(page, "actors")
    assert 0 < shown < total
    assert "q=ELECTRUM" in page.url
    page.goto(f"{site}#actors?motivation=disruption")
    shown, _ = _shown(page, "actors")
    assert 0 < shown < total
    page.locator("#rail label:has(input[value='hacktivism'])").click()
    assert "motivation=disruption,hacktivism" in page.url
    assert _shown(page, "actors")[0] > shown
    # a search through defanged text matches the stored, refanged value
    page.goto(f"{site}#iocs")
    page.fill("#tab-iocs .q", "79.133.46[.]209")
    assert _shown(page, "iocs")[0] == 1


def test_cross_links_open_the_target_drawer(browser, site):
    page = _page(browser)
    page.goto(f"{site}#actors/ICS-TA-0002")
    page.locator("#drawer").wait_for(state="visible")
    assert page.locator("#dId").inner_text() == "ICS-TA-0002"
    page.locator("#dBody a[href='#actors/ICS-TA-0001']").first.click()
    page.wait_for_function("document.getElementById('dId').textContent === 'ICS-TA-0001'")
    assert page.url.split("#", 1)[1].startswith("actors/ICS-TA-0001")
    page.locator("#dBody a[href^='#malware/']").first.click()
    page.wait_for_function("document.getElementById('dId').textContent.indexOf('ICS-MAL-') === 0")
    page.locator("#tab-malware").wait_for(state="visible")
    # a pack's rule opens in the rules library with its text
    page.goto(f"{site}#packs/ICS-PACK-0003")
    page.locator("#dBody details.rule summary a").first.click()
    page.wait_for_function("document.getElementById('dId').textContent.indexOf('02-ot-network/') === 0")
    assert "sid:" in page.locator("#dBody pre").inner_text()


def test_indicators_are_defanged_on_screen_and_refanged_on_export(browser, site, built):
    _, _, data = built
    ioc = next(s for s in data["libs"]["iocs"] if any(i["type"] == "ipv4" for i in s["indicators"]))
    ip = next(i["value"] for i in ioc["indicators"] if i["type"] == "ipv4")
    page = _page(browser, accept_downloads=True)
    page.goto(f"{site}#iocs/{ioc['id']}")
    page.locator("#drawer").wait_for(state="visible")
    body = page.locator("#dBody").inner_text()
    assert ip not in body
    assert ip.rsplit(".", 1)[0] + "[.]" + ip.rsplit(".", 1)[1] in body
    assert "publisher role" in body.lower()  # the column header; CSS sets it in capitals
    with page.expect_download() as dl:
        page.locator("#dBody button", has_text="Export CSV").click()
    text = Path(dl.value.path()).read_text(encoding="utf-8")
    assert ip in text and "[.]" not in text
    assert text.splitlines()[0] == "type,value,role,first_seen,last_seen,context"


def test_hostile_record_text_renders_as_text(browser, built, tmp_path):
    d, _, _ = built
    d2 = copy.deepcopy(d)
    rid = d2["actors"][0]["id"]
    evil = EVIL + '<img src=x onerror="alert(2)">'
    d2["actors"][0]["summary"] = evil
    doc, _ = bs.page(d2)
    out = tmp_path / "index.html"
    out.write_text(doc, encoding="utf-8")
    dialogs: list[str] = []
    page = _page(browser)
    page.on("dialog", lambda dlg: (dialogs.append(dlg.message), dlg.dismiss()))
    page.goto(f"{out.as_uri()}#actors/{rid}")
    page.locator("#drawer").wait_for(state="visible")
    assert evil in page.locator("#dBody").inner_text()
    assert page.locator("#dBody img").count() == 0
    assert not dialogs


def test_phone_width_has_no_horizontal_scroll(browser, site):
    page = _page(browser, viewport={"width": 390, "height": 844})
    for tab in ["start", *bs.FACET_KEYS, "response"]:
        page.goto(f"{site}#{tab}")
        page.locator(f"#tab-{tab}").wait_for(state="visible")
        assert not page.evaluate("document.documentElement.scrollWidth > window.innerWidth"), tab
    page.goto(f"{site}#platforms/ICS-0003")
    page.locator("#drawer").wait_for(state="visible")
    assert page.evaluate("document.getElementById('drawer').scrollWidth <= window.innerWidth")


def test_dark_scheme_is_honoured(browser, site):
    page = _page(browser, color_scheme="dark")
    page.goto(site)
    bg = page.evaluate("getComputedStyle(document.body).backgroundColor")
    r, g, b = (int(x) for x in re.findall(r"\d+", bg)[:3])
    assert r + g + b < 150, bg
