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
    assert doc.count("</script>") == 3  # the theme restore in <head>, the data block and the code, nothing else
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


def _text(fragment: str) -> str:
    return re.sub(r"<[^>]+>", "", fragment)


def test_credit_is_read_from_notice_and_appears_once_in_the_footer(built):
    _, doc, _ = built
    credit = html.escape(bs.credit())
    assert credit and "·" in credit
    static = re.sub(r"<script\b[^>]*>.*?</script>|<style>.*?</style>", "", doc, flags=re.S)
    assert _text(static).count(credit) == 1
    assert credit in _text(doc.split("<footer>", 1)[1])


def test_linkedin_links_are_read_from_readme_and_sit_in_the_footer(built):
    _, doc, data = built
    li = bs.linkedin()
    assert set(li) == {"profile", "company"}
    assert "/in/" in li["profile"] and "/company/" in li["company"]
    footer = doc.split("<footer>", 1)[1]
    name, publisher = bs.credit_parts()
    for key, text in (("profile", name), ("company", publisher)):
        assert f'<a href="{html.escape(li[key])}" rel="noopener noreferrer" target="_blank" title="{html.escape(text)} on LinkedIn">{html.escape(text)}</a>' in footer
    assert doc.count(li["profile"]) == 1 and doc.count(li["company"]) == 1  # the footer only, never the data block
    # --check fails when README loses either link
    orig = bs.linkedin
    try:
        bs.linkedin = lambda: {"profile": li["profile"]}
        assert any("README.md's byline has no link to the company" in p for p in bs.check(doc, data))
    finally:
        bs.linkedin = orig


def test_light_is_the_default_and_dark_is_the_viewers_choice(built):
    _, doc, _ = built
    head = doc.split("<body>", 1)[0]
    assert '<meta name="color-scheme" content="light">' in head
    assert "prefers-color-scheme" not in doc  # the OS setting never flips the page; the viewer's choice does
    assert ":root[data-theme=dark]{" in head
    assert "localStorage.getItem('icsdfir-theme')==='dark'" in head  # restored before first paint, inside try/catch
    assert "try{if(localStorage" in head
    assert 'id="themeBtn" aria-pressed="false"' in doc


def test_global_search_index_is_built_for_every_record(built):
    _, doc, data = built
    for lib in bs.FACET_KEYS:
        for r in data["libs"][lib]:
            assert r["_title"] in r["_s"] and str(r["id"]) in r["_s"], (lib, r["id"])
    by = {r["id"]: r for lib in bs.FACET_KEYS for r in data["libs"][lib]}
    assert "Sandworm" in by["ICS-TA-0002"]["_s"]  # an alias
    assert "Sandworm" in by["ICS-INC-0002"]["_s"]  # the name of an id the record lists
    rule = next(r for r in data["libs"]["rules"] if r.get("tags"))
    assert all(t in rule["_s"] for t in rule["tags"])
    assert 'id="gq"' in doc and 'id="gres"' in doc and 'role="combobox"' in doc


def test_correlations_and_relationships_name_only_known_ids(built):
    _, doc, data = built
    where = data["where"]
    viz = data["viz"]
    for key in ("actors_platforms", "malware_platforms", "malware_protocols"):
        m = viz[key]
        assert m["rows"] and m["cols"] and m["cells"], key
        assert all(x in where for x in m["rows"] + m["cols"])
        for row, col, direct, via in m["cells"]:
            assert where[row] in ("actors", "malware") and where[col] in ("platforms", "protocols")
            assert direct in (0, 1) and all(where[v] in ("malware", "incidents") for v in via)
    assert viz["actors_platforms"]["rows"] == [a["id"] for a in data["libs"]["actors"]]
    dated = [i for i in data["libs"]["incidents"] if bs.ymd(i.get("date")) is not None]
    assert [t["id"] for t in viz["timeline"]] == [i["id"] for i in sorted(dated, key=lambda i: (bs.ymd(i["date"]), i["id"]))]
    assert all(t["band"] in bs.BAND_LABEL for t in viz["timeline"])
    assert doc.count('class="tm"') == len(viz["timeline"])
    assert doc.count('class="cc cc-') == len(data["libs"]["coverage"])
    # both directions: the actor lists the malware, the malware lists the actor; a hunt naming an actor shows on the actor
    rel = data["rel"]
    assert "ICS-MAL-0004" in rel["ICS-TA-0002"]["malware"] and "ICS-TA-0002" in rel["ICS-MAL-0004"]["actors"]
    assert "ICS-HUNT-0001" in rel["ICS-TA-0019"]["hunts"] and "ICS-TA-0019" in rel["ICS-INC-0009"]["actors"]
    for rid, groups in rel.items():
        assert where[rid] in bs.INTEL
        for lib, ids in groups.items():
            assert all(where[x] == lib for x in ids), (rid, lib)
    # --check catches a matrix or relationship that names an unknown id
    bad = copy.deepcopy(data)
    bad["viz"]["malware_protocols"]["cells"].append(["ICS-MAL-0004", "ICS-PROTO-9999", 1, []])
    assert any("matrix malware_protocols names unknown ids" in p for p in bs.check(doc, bad))
    bad = copy.deepcopy(data)
    bad["rel"]["ICS-TA-0002"]["malware"].append("ICS-MAL-9999")
    assert any("relationships of ICS-TA-0002" in p for p in bs.check(doc, bad))


def test_new_facets_back_the_matrix_links(built):
    """A matrix cell links #actors/<id>?platform=<id>; the facet it filters on must exist and hold the value."""
    _, doc, data = built
    assert "platform" in bs.FACET_KEYS["actors"] and {"platform", "protocol"} <= set(bs.FACET_KEYS["malware"])
    viz = doc.split('id="viz-intel"', 1)[1].split("</details>", 1)[0]
    cells = re.findall(r'href="#(actors|malware)/([^"?]+)\?(platform|protocol)=([^"]+)"', viz)
    assert cells
    by = {r["id"]: r for lib in ("actors", "malware") for r in data["libs"][lib]}
    for lib, rid, key, val in cells:
        assert val in by[rid]["_f"][key], (rid, key, val)


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


NO_HSCROLL = "document.documentElement.scrollWidth <= window.innerWidth"


def test_phone_width_has_no_horizontal_scroll(browser, site):
    errors: list[str] = []
    page = _page(browser, errors, viewport={"width": 390, "height": 844})
    for tab in ["start", *bs.FACET_KEYS, "response"]:
        page.goto(f"{site}#{tab}")
        page.locator(f"#tab-{tab}").wait_for(state="visible")
        page.evaluate("document.querySelectorAll('details.viz').forEach(function(d){ d.open = true; })")  # matrices, timeline, grid
        assert page.evaluate(NO_HSCROLL), tab
        if tab in bs.GROUPS["intel"]:
            assert page.locator("#viz-intel").is_visible(), tab
            for sel in ("#viz-intel .mxs", "#viz-intel .tlw"):   # they scroll inside their own box
                assert page.locator(sel).first.evaluate("el => el.scrollWidth > el.clientWidth && getComputedStyle(el).overflowX === 'auto'"), sel
    page.goto(f"{site}#platforms/ICS-0003")
    page.locator("#drawer").wait_for(state="visible")
    assert page.evaluate("document.getElementById('drawer').scrollWidth <= window.innerWidth")
    page.keyboard.press("Escape")
    page.fill("#gq", "plc")
    page.locator("#gres").wait_for(state="visible")
    assert page.evaluate(NO_HSCROLL)
    assert page.locator("#gres").evaluate("el => el.getBoundingClientRect().right <= window.innerWidth && el.getBoundingClientRect().left >= 0")
    assert not errors, errors


def _bg_sum(page) -> int:
    bg = page.evaluate("getComputedStyle(document.body).backgroundColor")
    return sum(int(x) for x in re.findall(r"\d+", bg)[:3])


def test_light_by_default_and_the_theme_choice_is_kept(browser, site):
    page = _page(browser, color_scheme="dark")   # even an OS in dark mode gets light first
    page.goto(site)
    assert _bg_sum(page) > 600
    assert page.get_attribute("#themeBtn", "aria-pressed") == "false"
    page.click("#themeBtn")
    assert _bg_sum(page) < 150
    assert page.get_attribute("#themeBtn", "aria-pressed") == "true"
    assert page.evaluate("localStorage.getItem('icsdfir-theme')") == "dark"
    page.reload()
    page.locator("#tab-start").wait_for(state="visible")
    assert _bg_sum(page) < 150
    page.click("#themeBtn")
    assert _bg_sum(page) > 600 and page.evaluate("localStorage.getItem('icsdfir-theme')") == "light"
    page.context.close()


def test_global_search_spans_the_libraries_and_opens_the_drawer(browser, site, built):
    _, _, data = built
    errors: list[str] = []
    page = _page(browser, errors)
    page.goto(f"{site}#start")
    page.locator("#tab-start").wait_for(state="visible")
    page.keyboard.press("/")
    assert page.evaluate("document.activeElement.id") == "gq"
    page.keyboard.type("sandworm")
    page.locator("#gres").wait_for(state="visible")
    groups = page.locator("#gres .gsg").evaluate_all("els => els.map(e => e.getAttribute('aria-label'))")
    assert {"Threat actors", "Malware", "Incidents", "Hunts"} <= set(groups), groups
    counts = page.locator("#gres .gsh span").all_inner_texts()
    assert all(c.isdigit() and int(c) > 0 for c in counts)
    assert page.get_attribute("#gq", "aria-expanded") == "true"
    page.locator("#gres .gsg[aria-label='Malware'] a.gsr").first.click()
    page.locator("#drawer").wait_for(state="visible")
    assert page.locator("#dId").inner_text().startswith("ICS-MAL-")
    page.locator("#tab-malware").wait_for(state="visible")
    assert page.locator("#gres").is_hidden()
    # Ctrl+K focuses it, the arrow keys move, Enter opens, Esc clears then blurs
    page.keyboard.press("Escape")
    page.locator("#drawer").wait_for(state="hidden")
    page.keyboard.press("Control+k")
    assert page.evaluate("document.activeElement.id") == "gq"
    page.keyboard.type("ICS-INC-0002")
    page.locator("#gres").wait_for(state="visible")
    page.keyboard.press("ArrowDown")
    page.keyboard.press("ArrowUp")
    page.keyboard.press("Enter")
    page.locator("#drawer").wait_for(state="visible")
    assert page.locator("#dId").inner_text() == "ICS-INC-0002"
    page.keyboard.press("Escape")
    page.focus("#gq")
    page.keyboard.type("modbus")
    page.locator("#gres").wait_for(state="visible")
    page.keyboard.press("Escape")
    assert page.input_value("#gq") == "" and page.locator("#gres").is_hidden()
    assert page.evaluate("document.activeElement.id") == "gq"
    page.keyboard.press("Escape")
    assert page.evaluate("document.activeElement.id") != "gq"
    # a defanged indicator pasted into it finds the set that holds the value
    ioc = next(s for s in data["libs"]["iocs"] if any(i["type"] == "ipv4" for i in s["indicators"]))
    page.fill("#gq", "79.133.46[.]209")
    page.locator("#gres").wait_for(state="visible")
    assert "Indicator sets" in page.locator("#gres .gsg").evaluate_all("els => els.map(e => e.getAttribute('aria-label'))")
    assert any(i["value"] == "79.133.46.209" for i in ioc["indicators"]) or "79.133.46.209" in ioc["_s"]
    # the per-library search box keeps working beside it
    page.goto(f"{site}#actors")
    page.fill("#tab-actors .q", "ELECTRUM")
    shown, total = _shown(page, "actors")
    assert 0 < shown < total
    assert not errors, errors


def test_matrix_cells_and_totals_filter_the_target_library(browser, site, built):
    _, _, data = built
    errors: list[str] = []
    page = _page(browser, errors)
    page.goto(f"{site}#actors")
    page.locator("#tab-actors").wait_for(state="visible")
    assert page.locator("#viz-intel").is_visible()
    total = len(data["libs"]["actors"])
    cell = page.locator("#viz-intel .vizs").nth(0).locator("a.mc[href*='?platform=']").first
    href = cell.get_attribute("href")
    m = re.fullmatch(r"#actors/(ICS-TA-\d{4})\?platform=(ICS-\d{4})", href)
    assert m, href
    cell.click()
    page.locator("#drawer").wait_for(state="visible")
    assert page.locator("#dId").inner_text() == m.group(1)
    assert f"platform={m.group(2)}" in page.url
    shown, _ = _shown(page, "actors")
    assert 0 < shown < total
    page.keyboard.press("Escape")
    page.locator("#drawer").wait_for(state="hidden")
    assert page.locator(f"#rail input[value='{m.group(2)}']").is_checked()
    # a column total opens the other library filtered to that column; the block follows the open library
    page.goto(f"{site}#actors")
    tot = page.locator("#viz-intel .vizs").nth(2).locator("tfoot a[href^='#malware?protocol=']").first
    proto = tot.get_attribute("href").split("=", 1)[1]
    tot.click()
    page.locator("#tab-malware").wait_for(state="visible")
    assert page.locator("#tab-malware #viz-intel").count() == 1
    shown, total_m = _shown(page, "malware")
    assert 0 < shown < total_m and f"protocol={proto}" in page.url
    assert not errors, errors


def test_timeline_has_one_marker_per_incident_and_opens_it(browser, site, built):
    _, _, data = built
    page = _page(browser)
    page.goto(f"{site}#incidents")
    page.locator("#tab-incidents").wait_for(state="visible")
    marks = page.locator("#viz-intel svg.tlx a.tm")
    assert marks.count() == len(data["viz"]["timeline"]) == len(data["libs"]["incidents"])
    labels = marks.evaluate_all("els => els.map(e => e.getAttribute('aria-label'))")
    assert all(re.match(r"ICS-INC-\d{4} · \d{4}", lb) for lb in labels), labels[:3]
    ids = {lb.split(" ")[0] for lb in labels}
    assert ids == {i["id"] for i in data["libs"]["incidents"]}
    xs = marks.evaluate_all("els => els.map(e => e.querySelector('.mk').getBoundingClientRect().left)")
    assert xs == sorted(xs)  # left to right is earlier to later
    marks.first.locator(".hit").click()
    page.locator("#drawer").wait_for(state="visible")
    assert page.locator("#dId").inner_text() == data["viz"]["timeline"][0]["id"]
    # the legend links filter the library by consequence
    page.keyboard.press("Escape")
    page.locator("#drawer").wait_for(state="hidden")
    page.locator("#viz-intel .tlg a").first.click()
    page.wait_for_function("/^#incidents\\?consequence=/.test(location.hash) && document.querySelector('#tab-incidents .active .achip')")
    assert 0 < _shown(page, "incidents")[0] < len(data["libs"]["incidents"])


def test_attack_grid_cells_open_the_techniques_row(browser, site, built):
    _, _, data = built
    page = _page(browser)
    page.goto(f"{site}#coverage")
    page.locator("#tab-coverage").wait_for(state="visible")
    cells = page.locator("#viz-cov a.cc")
    assert cells.count() == len(data["libs"]["coverage"])
    gap = page.locator("#viz-cov a.cc.cc-gap").first
    tid = gap.inner_text()
    gap.click()
    page.locator("#drawer").wait_for(state="visible")
    assert page.locator("#dId").inner_text() == tid
    assert page.locator(f"#tab-coverage tr.item.sel[data-id='{tid}']").count() == 1
    assert page.locator("#viz-cov a.cc.sel").inner_text() == tid
    page.keyboard.press("Escape")
    page.locator("#drawer").wait_for(state="hidden")
    page.locator("#viz-cov .cglg a.lg").first.click()
    page.wait_for_function("location.hash === '#coverage?status=gap' && document.querySelector('#tab-coverage .active .achip')")
    assert _shown(page, "coverage")[0] == page.locator("#viz-cov a.cc.cc-gap").count()


def test_relationship_panel_lists_linked_ids_both_ways(browser, site, built):
    _, _, data = built
    page = _page(browser)
    page.goto(f"{site}#actors/ICS-TA-0002")
    page.locator("#drawer").wait_for(state="visible")
    panel = page.locator("#dBody .rel")
    assert panel.count() == 1
    hrefs = set(panel.locator("a.chip").evaluate_all("els => els.map(a => a.getAttribute('href'))"))
    expect = {f"#{lib}/{i}" for lib, ids in data["rel"]["ICS-TA-0002"].items() for i in ids}
    assert hrefs == expect
    assert "#malware/ICS-MAL-0004" in hrefs and "#incidents/ICS-INC-0002" in hrefs
    groups = panel.locator(".fkey").all_inner_texts()
    assert groups[:2] == ["Malware", "Incidents"]  # grouped by type, in a fixed order
    panel.locator("a[href='#malware/ICS-MAL-0004']").click()
    page.wait_for_function("document.getElementById('dId').textContent === 'ICS-MAL-0004'")
    back = set(page.locator("#dBody .rel a.chip").evaluate_all("els => els.map(a => a.getAttribute('href'))"))
    assert "#actors/ICS-TA-0002" in back and "#iocs/ICS-IOC-0003" in back
    page.goto(f"{site}#platforms/ICS-0003")   # not threat intel: no panel, the Referenced by section stays
    page.wait_for_function("document.getElementById('dId').textContent === 'ICS-0003'")
    assert page.locator("#dBody .rel").count() == 0


def test_facet_rail_and_drawer_fields_share_one_type_scale(browser, site):
    page = _page(browser)
    page.goto(f"{site}#platforms")
    page.locator("#tab-platforms").wait_for(state="visible")
    sizes = page.evaluate("""() => {
      const one = (sel, prop) => [...new Set([...document.querySelectorAll(sel)].map(e => getComputedStyle(e)[prop]))];
      return {legend: one('#rail .fg legend', 'fontSize'), label: one('#rail .fv .fl', 'fontSize'), count: one('#rail .fv .fc', 'fontSize'),
              countAlign: one('#rail .fv .fc', 'textAlign'), labelAlign: one('#rail .fv .fl', 'textAlign'),
              gaps: [...new Set([...document.querySelectorAll('#rail .fg')].slice(0, -1).map(e => getComputedStyle(e).marginBottom))],
              legendLeft: [...new Set([...document.querySelectorAll('#rail .fg legend')].map(e => Math.round(e.getBoundingClientRect().left)))],
              boxLeft: [...new Set([...document.querySelectorAll('#rail .fv input')].map(e => Math.round(e.getBoundingClientRect().left)))],
              countRight: [...new Set([...document.querySelectorAll('#rail .fv .fc')].map(e => Math.round(e.getBoundingClientRect().right)))]};
    }""")
    assert len(sizes["legend"]) == 1 and len(sizes["label"]) == 1 and len(sizes["count"]) == 1, sizes
    assert float(sizes["legend"][0][:-2]) < float(sizes["count"][0][:-2]) < float(sizes["label"][0][:-2])
    assert sizes["countAlign"] == ["right"] and sizes["labelAlign"] == ["left"]
    assert len(sizes["gaps"]) == 1 and len(sizes["legendLeft"]) == 1 and len(sizes["boxLeft"]) == 1 and len(sizes["countRight"]) == 1, sizes
    assert sizes["legendLeft"] == sizes["boxLeft"]  # the group header sits on the checkbox column's edge
    page.goto(f"{site}#actors/ICS-TA-0002")
    page.locator("#drawer").wait_for(state="visible")
    d = page.evaluate("""() => {
      const one = (sel, f) => [...new Set([...document.querySelectorAll(sel)].map(f))];
      return {key: one('#dBody .fkey', e => getComputedStyle(e).fontSize),
              keyLeft: one('#dBody > .fields > .fld > .fkey', e => Math.round(e.getBoundingClientRect().left)),
              valLeft: one('#dBody > .fields > .fld > .fval', e => Math.round(e.getBoundingClientRect().left)),
              subValLeft: one('#dBody .sub .fld > .fval', e => Math.round(e.getBoundingClientRect().left))};
    }""")
    assert len(d["key"]) == 1 and len(d["keyLeft"]) == 1 and len(d["valLeft"]) == 1, d
    assert d["subValLeft"] and abs(d["subValLeft"][0] - d["valLeft"][0]) <= 2, d  # values line up at every depth
