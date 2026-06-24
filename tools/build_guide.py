#!/usr/bin/env python3
"""Build the PSYSMON end-user guide (#64) from one Markdown source into two outputs:

* **multi-page HTML** under ``site/`` — branded to match the daemon's status page (the same navy
  banner + logo + palette), with a sidebar table of contents and working internal cross-links;
* a **consolidated plain-text** ``docs/guide/psysmon-guide.txt`` — clean, wrapped, readable over
  SSH, and bundled in the sdist.

The source of truth is ``docs/guide/src/*.md`` (ordered by the numeric filename prefix). The CLI
and status-code appendices are generated *from the code* (``settings.build_parser`` and
``psysmon.status``) so they can never drift from what the daemon actually does.

Usage::

    pip install -e .[docs]        # one build-only dep: Markdown
    python tools/build_guide.py   # writes site/ and docs/guide/psysmon-guide.txt

Run with ``--check`` to build into a temp dir and fail if anything is missing (the CI gate).
"""

from __future__ import annotations

import argparse
import re
import shutil
import sys
import textwrap
from pathlib import Path

import markdown

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "docs" / "guide" / "src"
SITE = ROOT / "site"
TXT_OUT = ROOT / "docs" / "guide" / "psysmon-guide.txt"
LOGO = ROOT / "psysmon" / "assets" / "psysmon-logo.png"
LOGO_NAME = "psysmon-logo.png"
WRAP = 88  # plain-text wrap column

# --- branding: the status page's palette + banner (psysmon/output/statuspage.py), extended for a
# two-column doc layout (sidebar nav + content), code blocks, tables, and links. --------------
_CSS = """
:root {
  --bg:#15254A; --panel:#1F3158; --border:#2E4470; --text:#E6ECF7; --muted:#93A4C4;
  --glow:#1D708C; --green:#4CD137; --yellow:#F4D03F; --down:#E84118; --link:#7FE0FF;
}
* { box-sizing:border-box; }
body { margin:0; background:var(--bg); color:var(--text);
  font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif; line-height:1.6; }
a { color:var(--link); text-decoration:none; }
a:hover { text-decoration:underline; }
.header { display:flex; align-items:center; gap:22px; padding:18px 26px;
  background:linear-gradient(180deg,#1C2E58,#101D3C); border-bottom:2px solid var(--border); }
.header .glow { display:grid; place-items:center; border-radius:14px;
  background:radial-gradient(circle at center, var(--glow) 0%, transparent 68%); }
.header img.logo { height:84px; width:84px; image-rendering:auto; display:block; }
.header h1 { margin:0; font-size:26px; letter-spacing:1px; }
.header h1 a { color:var(--text); }
.header .sub { margin:3px 0 0; color:var(--muted); font-size:14px; }
.layout { display:flex; align-items:flex-start; gap:0; }
.nav { flex:0 0 280px; align-self:stretch; padding:22px 18px 40px; border-right:1px solid
  var(--border); background:#13213F; min-height:calc(100vh - 124px); position:sticky; top:0;
  max-height:100vh; overflow:auto; }
.nav .navtitle { font-size:12px; text-transform:uppercase; letter-spacing:.6px; color:var(--muted);
  margin:0 0 10px; }
.nav ol { list-style:none; margin:0; padding:0; counter-reset:ch; }
.nav > ol > li { counter-increment:ch; margin:2px 0; }
.nav > ol > li > a::before { content:counter(ch) ". "; color:var(--muted); }
.nav a { display:block; padding:5px 10px; border-radius:7px; color:var(--text); font-size:14px; }
.nav a:hover { background:var(--panel); text-decoration:none; }
.nav li.current > a { background:var(--panel); font-weight:700; }
.nav .toc { list-style:none; margin:3px 0 8px; padding:0 0 0 18px; }
.nav .toc a { color:var(--muted); font-size:13px; padding:3px 10px; }
.main { flex:1 1 auto; min-width:0; padding:14px 38px 60px; max-width:900px; }
.main h1 { font-size:30px; margin:18px 0 8px; }
.main h2 { font-size:22px; margin:34px 0 8px; padding-bottom:6px;
  border-bottom:1px solid var(--border); }
.main h3 { font-size:17px; margin:26px 0 6px; color:#CBD8F2; }
.main h4 { font-size:15px; margin:20px 0 6px; color:var(--muted); text-transform:uppercase;
  letter-spacing:.5px; }
.main code { background:#0F1B38; border:1px solid var(--border); border-radius:5px;
  padding:1px 6px; font-size:13px; font-family:"SF Mono",Consolas,Menlo,monospace; }
.main pre { background:#0F1B38; border:1px solid var(--border); border-radius:10px;
  padding:14px 16px; overflow:auto; }
.main pre code { background:none; border:none; padding:0; font-size:13px; line-height:1.5; }
.main table { width:100%; border-collapse:collapse; background:var(--panel);
  border:1px solid var(--border); border-radius:10px; overflow:hidden; margin:14px 0; }
.main th { text-align:left; font-size:12px; text-transform:uppercase; letter-spacing:.6px;
  color:var(--muted); padding:10px 13px; background:#1A2C54;
  border-bottom:1px solid var(--border); }
.main td { padding:9px 13px; border-bottom:1px solid var(--border); font-size:14px;
  vertical-align:top; }
.main tr:last-child td { border-bottom:none; }
.main blockquote { margin:14px 0; padding:10px 16px; border-left:3px solid var(--glow);
  background:var(--panel); border-radius:0 8px 8px 0; color:#CBD8F2; }
.main blockquote p { margin:6px 0; }
.badge { display:inline-block; padding:1px 9px; border-radius:999px; font-size:12px;
  font-weight:700; background:rgba(76,209,55,.16); color:var(--green); }
.badge.modern { background:rgba(127,224,255,.16); color:var(--link); }
.pager { display:flex; justify-content:space-between; margin:46px 0 0; padding-top:18px;
  border-top:1px solid var(--border); font-size:14px; }
.footer { padding:16px 26px 30px; color:var(--muted); font-size:12px;
  border-top:1px solid var(--border); }
"""

_MD_LINK = re.compile(r"\]\(([0-9A-Za-z._/-]+)\.md(#[^)]*)?\)")  # any .md link in the source
_REPO_BLOB = "https://github.com/IjonTichy1970/Psysmon/blob/main/docs/"


def _rewrite_links(md_text: str, guide_stems: set[str]) -> str:
    """Rewrite ``.md`` links for the HTML build: a link to another guide chapter becomes the local
    ``.html`` page; a link to a repo doc that isn't part of the guide (e.g. control-channel.md,
    modern-config.md) becomes its GitHub URL so it still resolves from the published site."""
    def repl(m: re.Match) -> str:
        path, anchor = m.group(1), m.group(2) or ""
        stem = path.rsplit("/", 1)[-1]
        if stem in guide_stems:
            return f"]({stem}.html{anchor})"
        return f"]({_REPO_BLOB}{stem}.md{anchor})"
    return _MD_LINK.sub(repl, md_text)


class Chapter:
    def __init__(self, path: Path):
        self.path = path
        self.slug = path.stem  # e.g. "01-introduction"
        self.html_name = f"{self.slug}.html"
        text = path.read_text(encoding="utf-8")
        m = re.search(r"^#\s+(.*)$", text, re.MULTILINE)
        self.title = m.group(1).strip() if m else self.slug


def discover() -> list[Chapter]:
    chapters = [Chapter(p) for p in sorted(SRC.glob("*.md"))]
    if not chapters:
        sys.exit(f"build_guide: no chapters found in {SRC}")
    return chapters


# --- from-code appendices (can't drift) ----------------------------------------------------

def gen_cli() -> str:
    from psysmon.config.settings import build_parser

    help_text = build_parser().format_help()
    return "```text\n" + help_text.rstrip() + "\n```\n"


def gen_status() -> str:
    from psysmon.status import Status, errtostr

    # The code -> display-string column is generated from psysmon.status; the meaning column is
    # maintained here next to it. A new Status with no entry trips the assert below (a build gate).
    meanings = {
        Status.OK: "The service answered normally; fully up.",
        Status.CONN_REFUSED: "The host is reachable but refused the connection on that port "
                             "(nothing listening / actively rejected).",
        Status.NET_UNREACH: "No route to the host's network (a router/path is down).",
        Status.HOST_DOWN: "The host itself is down / unreachable on its network.",
        Status.TIMED_OUT: "The connection attempt timed out with no response.",
        Status.NO_DNS: "The hostname did not resolve (no DNS record / lookup failed).",
        Status.UNPINGABLE: "No ICMP echo reply within the retry budget (ping only).",
        Status.THROTTLED: "Rate-limited / throttled by the service.",
        Status.NO_AUTH: "Authentication was required but not provided.",
        Status.NO_RESPONSE: "Connected, but the server sent no (valid) response.",
        Status.IN_PROGRESS: "A connection is still in progress (transient).",
        Status.BAD_AUTH: "Authentication was attempted and rejected (bad credentials).",
        Status.BAD_RESPONSE: "The server responded, but not as expected (e.g. a DNS reply that "
                            "is malformed or from the wrong source; an HTTP body missing the "
                            "expected text).",
        Status.X500_WEDGED: "The service is wedged / stuck (legacy X.500 condition).",
        Status.DEGRADED: "Loss-tolerant ping got some replies but fewer than `min_pings` — "
                        "reachable but lossy. Does not reset an outage; pages only with "
                        "`--page-on-degraded`. (psysmon addition, #22.)",
    }
    rows = ["| Code | Status text | Meaning |", "|---|---|---|"]
    for st in Status:
        assert st in meanings, f"status {st!r} has no documented meaning"  # build gate
        rows.append(f"| `{st.value}` | `{errtostr(st.value)}` | {meanings[st]} |")
    return "\n".join(rows) + "\n"


def inject_generated(md_text: str) -> str:
    md_text = md_text.replace("<!--GEN:cli-->", gen_cli())
    md_text = md_text.replace("<!--GEN:status-->", gen_status())
    return md_text


# --- HTML ----------------------------------------------------------------------------------

def _nav_html(chapters: list[Chapter], current: Chapter, page_toc: str) -> str:
    items = []
    for ch in chapters:
        cls = ' class="current"' if ch is current else ""
        sub = f"\n{page_toc}" if ch is current and page_toc else ""
        items.append(f'<li{cls}><a href="{ch.html_name}">{ch.title}</a>{sub}</li>')
    return '<ol>\n' + "\n".join(items) + "\n</ol>"


def _page(chapters: list[Chapter], current: Chapter, body: str, page_toc: str,
          prev_ch: Chapter | None, next_ch: Chapter | None) -> str:
    nav = _nav_html(chapters, current, page_toc)
    prev_html = (f'<a href="{prev_ch.html_name}">&larr; {prev_ch.title}</a>'
                 if prev_ch else "<span></span>")
    next_html = (f'<a href="{next_ch.html_name}">{next_ch.title} &rarr;</a>'
                 if next_ch else "<span></span>")
    return (
        "<!DOCTYPE html>\n"
        '<html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        f"<title>{current.title} — PSYSMON User Guide</title>"
        f"<style>{_CSS}</style></head><body>\n"
        '<div class="header">'
        f'<div class="glow"><img class="logo" src="{LOGO_NAME}" alt="psysmon logo"></div>'
        '<div><h1><a href="index.html">PSYSMON</a></h1>'
        '<p class="sub">User Guide</p></div></div>\n'
        '<div class="layout">'
        f'<nav class="nav"><p class="navtitle">Contents</p>{nav}</nav>\n'
        f'<main class="main">{body}'
        f'<div class="pager">{prev_html}{next_html}</div>'
        "</main></div>\n"
        '<div class="footer">PSYSMON User Guide · generated from docs/guide/src · '
        "build with <code>python tools/build_guide.py</code></div>\n"
        "</body></html>\n"
    )


def build_html(chapters: list[Chapter], site: Path) -> None:
    site.mkdir(parents=True, exist_ok=True)
    if LOGO.exists():
        shutil.copyfile(LOGO, site / LOGO_NAME)
    guide_stems = {ch.slug for ch in chapters}
    for idx, ch in enumerate(chapters):
        md_text = inject_generated(ch.path.read_text(encoding="utf-8"))
        md_text = _rewrite_links(md_text, guide_stems)
        md = markdown.Markdown(extensions=["tables", "fenced_code", "toc", "attr_list",
                                           "sane_lists", "def_list"])
        body = md.convert(md_text)
        page_toc = getattr(md, "toc", "")
        # md.toc wraps in <div class="toc">…</div>; reuse just the inner <ul> for the sidebar.
        toc_inner = ""
        mt = re.search(r"<ul>.*</ul>", page_toc, re.DOTALL)
        if mt:
            toc_inner = f'<ul class="toc">{mt.group(0)[4:-5]}</ul>'
        prev_ch = chapters[idx - 1] if idx > 0 else None
        next_ch = chapters[idx + 1] if idx < len(chapters) - 1 else None
        html = _page(chapters, ch, body, toc_inner, prev_ch, next_ch)
        # newline="\n": deterministic LF output on every platform (no CRLF churn on a Windows build)
        (site / ch.html_name).write_text(html, encoding="utf-8", newline="\n")
    # index.html -> the first chapter (so the Pages root lands on the guide).
    shutil.copyfile(site / chapters[0].html_name, site / "index.html")


# --- plain text ----------------------------------------------------------------------------

_RE_IMG = re.compile(r"!\[[^\]]*\]\([^)]*\)")
_RE_LINK = re.compile(r"\[([^\]]+)\]\(([^)]+)\)")
_RE_BOLD = re.compile(r"\*\*([^*]+)\*\*")
_RE_CODE = re.compile(r"`([^`]+)`")
_RE_HEADING = re.compile(r"^(#{1,6})\s+(.*?)\s*$")
_HEADING_ATTR = re.compile(r"\s*\{[^}]*\}\s*$")  # trailing attr-list, e.g. ` {#anchor}` (HTML-only)
_UNDERLINE = {1: "=", 2: "-", 3: "~"}
# Fold common typographic characters to ASCII so the TXT is safe on any terminal / over SSH.
_ASCII_FOLD = {
    "—": "--", "–": "-", "‘": "'", "’": "'", "“": '"', "”": '"',
    "…": "...", "→": "->", "←": "<-", "·": "-", "✓": "[ok]",
    " ": " ", "×": "x",
}


def _strip_inline(s: str) -> str:
    s = _RE_IMG.sub("", s)
    s = _RE_LINK.sub(lambda m: (f"{m.group(1)} ({m.group(2)})"
                                if m.group(2).startswith("http") else m.group(1)), s)
    s = _RE_BOLD.sub(r"\1", s)
    s = _RE_CODE.sub(r"\1", s)
    return s


def _is_table(block: list[str]) -> bool:
    return len(block) >= 2 and "|" in block[0] and set(block[1].strip()) <= set("|-: ")


def _is_list(block: list[str]) -> bool:
    return all(re.match(r"^\s*([-*+]|\d+\.)\s+", ln) for ln in block if ln.strip())


def _render_prose(lines: list[str]) -> list[str]:
    out: list[str] = []
    block: list[str] = []

    def flush() -> None:
        if not block:
            return
        h = _RE_HEADING.match(block[0])
        if h and len(block) == 1:
            level = len(h.group(1))
            text = _strip_inline(_HEADING_ATTR.sub("", h.group(2)))
            out.append(text)
            if level in _UNDERLINE:
                out.append(_UNDERLINE[level] * len(text))
        elif _is_table(block):
            out.extend(_strip_inline(ln) for ln in block)  # pipe tables read fine as text
        elif _is_list(block):
            for ln in block:
                stripped = _strip_inline(ln.rstrip())
                indent = len(ln) - len(ln.lstrip())
                wrapped = textwrap.wrap(stripped, WRAP, subsequent_indent=" " * (indent + 2))
                out.extend(wrapped or [stripped])
        elif block[0].lstrip().startswith(">"):
            for ln in block:
                out.append("    " + _strip_inline(ln.lstrip("> ").rstrip()))
        else:
            para = _strip_inline(" ".join(ln.strip() for ln in block))
            out.extend(textwrap.wrap(para, WRAP) or [para])
        out.append("")
        block.clear()

    for ln in lines:
        if not ln.strip():
            flush()
        elif _RE_HEADING.match(ln):
            flush()
            block.append(ln)
            flush()
        else:
            block.append(ln)
    flush()
    return out


def md_to_text(md_text: str) -> str:
    out: list[str] = []
    lines = md_text.splitlines()
    i, n = 0, len(lines)
    while i < n:
        if lines[i].lstrip().startswith("```"):
            i += 1
            out.append("")
            while i < n and not lines[i].lstrip().startswith("```"):
                out.append("    " + lines[i])
                i += 1
            i += 1  # skip the closing fence
            out.append("")
            continue
        region: list[str] = []
        while i < n and not lines[i].lstrip().startswith("```"):
            region.append(lines[i])
            i += 1
        out.extend(_render_prose(region))
    # collapse runs of blank lines
    text, blanks = [], 0
    for ln in out:
        if ln.strip() == "":
            blanks += 1
            if blanks <= 1:
                text.append("")
        else:
            blanks = 0
            text.append(ln.rstrip())
    return _ascii_fold("\n".join(text).strip() + "\n")


# More typographic characters the authored chapters may use: single guillemets, the left-right
# arrow, implies/iff, the (in)equalities, bullet. (The TXT output is folded to ASCII; this source
# file is UTF-8.)
_EXTRA_FOLD = {
    "›": ">", "‹": "<", "↔": "<->", "⇒": "=>", "⇔": "<=>",
    "≤": "<=", "≥": ">=", "≠": "!=", "•": "*", "·": "-",
}


def _ascii_fold(s: str) -> str:
    for mapping in (_ASCII_FOLD, _EXTRA_FOLD):
        for uni, ascii_ in mapping.items():
            s = s.replace(uni, ascii_)
    return s


def build_txt(chapters: list[Chapter], out_path: Path) -> None:
    parts = [
        "PSYSMON — USER GUIDE",
        "=" * 20,
        "",
        "Generated from docs/guide/src by tools/build_guide.py. The HTML edition (with navigation)",
        "is published to GitHub Pages; see README.md.",
        "",
    ]
    toc = ["Contents:", ""]
    for idx, ch in enumerate(chapters, 1):
        toc.append(f"  {idx}. {ch.title}")
    parts.extend(toc)
    parts.append("\n" + "#" * WRAP + "\n")
    for ch in chapters:
        md_text = inject_generated(ch.path.read_text(encoding="utf-8"))
        parts.append(md_to_text(md_text))
        parts.append("\n" + "#" * WRAP + "\n")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(_ascii_fold("\n".join(parts).rstrip() + "\n"), encoding="utf-8",
                        newline="\n")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="build_guide", description="Build the PSYSMON user guide.")
    ap.add_argument("--check", action="store_true",
                    help="build into a temp dir and verify outputs (CI gate); don't write site/")
    args = ap.parse_args(argv)

    chapters = discover()
    if args.check:
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            site = Path(tmp) / "site"
            build_html(chapters, site)
            txt = Path(tmp) / "guide.txt"
            build_txt(chapters, txt)
            pages = list(site.glob("*.html"))
            assert (site / "index.html").exists(), "index.html missing"
            assert len(pages) >= len(chapters), "a chapter page is missing"
            assert txt.read_text(encoding="utf-8").strip(), "empty TXT"
        print(f"build_guide --check OK: {len(chapters)} chapters render cleanly")
        return 0

    build_html(chapters, SITE)
    build_txt(chapters, TXT_OUT)
    print(f"build_guide: {len(chapters)} chapters -> {SITE}/ and {TXT_OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
