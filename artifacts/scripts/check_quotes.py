#!/usr/bin/env python3
"""check_quotes.py - is every quote still on the page it was copied from?

Walks every YAML record under artifacts/ for sources that carry both a `url` and
a `quote` (actor and malware references, platform artifact sources, hunt,
hardening and response sources, exploitation reports...), fetches each page
once, reduces it to text and looks for the quote after normalising whitespace,
quote marks, dashes and the spacing a link or a PDF bullet leaves behind.
Nothing else is forgiven: a reworded sentence is reported, not matched.

It never edits the repository. Pages are untrusted data: they are held in
memory or a temporary directory and only ever searched as text.

    python artifacts/scripts/check_quotes.py --out report.md
    python artifacts/scripts/check_quotes.py --only artifacts/intel/actors/ICS-TA-0002-electrum.yml

Some vendor documentation portals build their text in the browser, so a plain
fetch never sees it. Those hosts are reported as "needs a rendered check" (read
them with a rendering fetch such as Firecrawl), never as changed.

Ported from edge-dfir-toolkit's checker; the host list is ICS-specific.

Exit status: 0 every readable quote matched, 10 a quote is no longer on its page, 1 error.
"""
from __future__ import annotations

import argparse
import difflib
import html
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.parse import urlparse

import yaml

ROOT = Path(__file__).resolve().parents[2]
NEEDS_REVIEW = 10
UA = "Mozilla/5.0 (X11; Linux x86_64) ics-dfir-toolkit quote check (+https://github.com/depalmar/ics-dfir-toolkit)"
# Hosts that build their article text with JavaScript, so a plain fetch can return a
# shell. A quote not found on one of them needs a rendered check; it is not "changed".
RENDERED_HOSTS = {
    "docs.tia.siemens.cloud", "support.industry.siemens.com", "sieportal.siemens.com",
    "www.industry-mobile-support.siemens-info.com", "docs.aveva.com", "www.se.com",
    "x.com", "twitter.com", "www.linkedin.com", "web.archive.org",
}
TR = str.maketrans({"‘": "'", "’": "'", "“": '"', "”": '"', "–": "-", "—": "-",
                    "‐": "-", "‑": "-", " ": " ", " ": " ", " ": " ", "​": ""})
BLOCK = r"p|div|li|ul|ol|h[1-6]|tr|td|th|table|section|article|header|footer|blockquote|pre|figure|figcaption|dt|dd"


def norm(t: str) -> str:
    """Lower-case text with the differences a faithful copy can still have taken out."""
    t = html.unescape(t).translate(TR)
    t = re.sub("[-]", " ", t)        # PDF bullet glyphs live in the private-use area
    t = re.sub(r"[*_`]+", "", t)                  # markdown emphasis a reader may have kept or dropped
    t = " ".join(t.split())
    t = re.sub(r"\s+([),.;:!?])", r"\1", t)       # "(AA26-097A )" from a link boundary
    t = re.sub(r"([(\[])\s+", r"\1", t)
    return t.lower()


def text_of(raw: bytes) -> str:
    """HTML to text: block elements separate, inline tags join their text without a space."""
    h = raw.decode("utf-8", "replace")
    h = re.sub(r"(?is)<(script|style|noscript|svg)\b.*?</\1>", " ", h)
    h = re.sub(rf"(?i)<br\s*/?>|</?({BLOCK})\b[^>]*>", " \n ", h)
    return re.sub(r"(?s)<[^>]+>", "", h)


def pdf_text(raw: bytes) -> str | None:
    if not shutil.which("pdftotext"):
        return None
    with tempfile.TemporaryDirectory() as d:
        src = Path(d) / "page.pdf"
        src.write_bytes(raw)
        out = subprocess.run(["pdftotext", str(src), "-"], capture_output=True, timeout=120)
        return out.stdout.decode("utf-8", "replace") if out.returncode == 0 else None


def fetch(url: str, timeout: int = 45, tries: int = 2) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "text/html,application/pdf,*/*"})
    for n in range(tries):   # one retry: some government sites are slow, not gone
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:   # noqa: S310 - https URLs from the records
                return r.read(16_000_000)
        except TimeoutError:
            if n == tries - 1:
                raise
    raise RuntimeError("unreachable")


def collect(root: Path = ROOT, only: list[Path] | None = None) -> list[dict]:
    """Every source with a url and a quote, with the file and record it belongs to."""
    files = only or sorted((root / "artifacts").rglob("*.yml"))
    out: list[dict] = []

    def walk(x, path: Path, rec: str) -> None:
        if isinstance(x, dict):
            rec = str(x.get("id") or x.get("cve") or rec)
            if isinstance(x.get("url"), str) and isinstance(x.get("quote"), str) and x["url"].startswith("https://"):
                out.append({"file": path.relative_to(root).as_posix() if path.is_relative_to(root) else str(path),
                            "record": rec, "url": x["url"], "quote": x["quote"], "read": x.get("read", "direct")})
            for v in x.values():
                walk(v, path, rec)
        elif isinstance(x, list):
            for v in x:
                walk(v, path, rec)

    for f in files:
        walk(yaml.safe_load(f.read_text()) or {}, f, f.stem)
    return out


def page_texts(urls: list[str], getter=None, workers: int = 8) -> dict[str, tuple[str | None, str]]:
    """url -> (normalised text or None, status). Fetched once each."""
    getter = getter or fetch

    def one(u: str):
        try:
            raw = getter(u)
        except Exception as e:   # noqa: BLE001 - every failure is reported, none is fatal
            return u, (None, f"unfetched: {type(e).__name__}: {str(e)[:80]}")
        if raw[:5] == b"%PDF-":
            t = pdf_text(raw)
            return u, (norm(t), "ok") if t is not None else (None, "unfetched: PDF and no pdftotext")
        return u, (norm(text_of(raw)), "ok")

    with ThreadPoolExecutor(max_workers=workers) as ex:
        return dict(ex.map(one, sorted(set(urls))))


def check(sources: list[dict], getter=None) -> list[dict]:
    pages = page_texts([s["url"] for s in sources], getter)
    res = []
    for s in sources:
        text, st = pages[s["url"]]
        q = norm(s["quote"])
        row = {**s, "status": st if text is None else ("ok" if q in text else "missing")}
        if row["status"] == "missing" and urlparse(s["url"]).netloc in RENDERED_HOSTS:
            row["status"] = "rendered"   # the text may only exist once a browser runs the page
        if row["status"] == "missing":
            m = difflib.SequenceMatcher(None, text, q, autojunk=False).find_longest_match(0, len(text), 0, len(q))
            row["closest"] = round(m.size / max(1, len(q)), 2)
        res.append(row)
    return res


MAX_PER_PAGE = 8


def grouped(rows: list[dict], detail=None) -> list[str]:
    """One bullet per page with its quotes beneath: when a page changes, every quote taken
    from it goes with it, so grouping keeps a 700-quote report readable (and inside GitHub's
    issue-body limit)."""
    by_page: dict[str, list[dict]] = {}
    for r in rows:
        by_page.setdefault(r["url"], []).append(r)
    out: list[str] = []
    for url, rs in sorted(by_page.items(), key=lambda kv: (-len(kv[1]), kv[0])):
        extra = detail(rs[0]) if detail else ""
        out.append(f"- {url} ({len(rs)} quote{'s' if len(rs) != 1 else ''}{extra})")
        out += [f"  - {r['file']} `{r['record']}`" + (f" closest {r['closest']}" if "closest" in r else "")
                for r in rs[:MAX_PER_PAGE]]
        if len(rs) > MAX_PER_PAGE:
            out.append(f"  - and {len(rs) - MAX_PER_PAGE} more from this page")
    return out


def report(res: list[dict]) -> str:
    miss = [r for r in res if r["status"] == "missing"]
    rendered = [r for r in res if r["status"] == "rendered"]
    unf = [r for r in res if r["status"].startswith("unfetched")]
    upgrade = [r for r in res if r["status"] == "ok" and r["read"] == "summariser"]
    ok = sum(r["status"] == "ok" for r in res)
    L = ["# Quote check", "",
         f"{ok} of {len(res)} quotes are on their page word for word. Nothing here changes the repository: read "
         "each page, then fix the quote, the record or the claim it supports through a normal pull request, and "
         "record any correction in `docs/VERIFICATION.md`.", "",
         f"## No longer on the page ({len(miss)})", ""]
    if miss:
        L += ["`closest` is the longest run of the quote found on the page. Near 1.0 is usually a small edit; "
              "near 0 means the passage is gone or the page now builds its text in the browser. Grouped by page, "
              "pages with the most quotes first.", ""]
        L += grouped(miss)
    else:
        L.append("None.")
    L += ["", f"## Needs a rendered check ({len(rendered)})", "",
          "These hosts build their text in the browser. Read them with a rendering fetch before relying on them.", ""]
    L += grouped(rendered) or ["None."]
    L += ["", f"## Could not be fetched ({len(unf)})", ""]
    L += grouped(unf, lambda r: f"; {r['status'][11:]}") or ["None."]
    L += ["", f"## Read through a summariser, now matched word for word ({len(upgrade)})", ""]
    L += [f"- {r['file']} {r['record']}: {r['url']} - can become `read: direct`" for r in upgrade] or ["None."]
    return "\n".join(L) + "\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--only", type=Path, nargs="*", help="check only these YAML files")
    ap.add_argument("--out", type=Path, help="write the Markdown report here")
    a = ap.parse_args(argv)
    only = [p.resolve() for p in a.only] if a.only else None
    sources = collect(ROOT, only)
    if not sources:
        print("no quoted sources found - refusing to report an empty check", file=sys.stderr)
        return 1
    res = check(sources)
    text = report(res)
    if a.out:
        a.out.write_text(text)
    print(text)
    return NEEDS_REVIEW if any(r["status"] == "missing" for r in res) else 0


if __name__ == "__main__":
    sys.exit(main())
