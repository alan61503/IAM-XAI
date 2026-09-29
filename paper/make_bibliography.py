"""Render the references cited in main.tex as an APA-style ``thebibliography``.

The paper template (NEJCS-LaTeX-sample.tex) uses a hand-written numbered
bibliography with APA-formatted entries instead of BibTeX. This script keeps
refs.bib as the single verified source: it reads the keys cited in main.tex,
formats those entries, sorts them by first author, and replaces the block
between the ``%%BIBLIOGRAPHY-START%%`` and ``%%BIBLIOGRAPHY-END%%`` markers.

Usage (from the repository root):
    python paper/make_bibliography.py
"""

import re
import sys
from pathlib import Path
from typing import Dict, List

PAPER_DIR = Path(__file__).resolve().parent
TEX_PATH = PAPER_DIR / "main.tex"
BIB_PATH = PAPER_DIR / "refs.bib"
START, END = "%%BIBLIOGRAPHY-START%%", "%%BIBLIOGRAPHY-END%%"
MONTHS = {"jan": "January", "feb": "February", "mar": "March", "apr": "April", "may": "May", "jun": "June",
          "jul": "July", "aug": "August", "sep": "September", "oct": "October", "nov": "November", "dec": "December"}


def _braced(text: str, start: int) -> int:
    """Index just past the brace group opening at ``text[start]``."""
    depth = 0
    for i in range(start, len(text)):
        depth += {"{": 1, "}": -1}.get(text[i], 0)
        if depth == 0:
            return i + 1
    raise ValueError("unbalanced braces in refs.bib")


def parse_bib(text: str) -> Dict[str, Dict[str, str]]:
    entries: Dict[str, Dict[str, str]] = {}
    for match in re.finditer(r"@(\w+)\s*\{\s*([^,\s]+)\s*,", text):
        body_end = _braced(text, text.index("{", match.start())) - 1
        body, pos = text[match.end():body_end], 0
        fields = {"_kind": match.group(1).lower()}
        for field in re.finditer(r"(\w+)\s*=\s*", body):
            if field.start() < pos:
                continue
            value_start = field.end()
            if body[value_start] == "{":
                pos = _braced(body, value_start)
                value = body[value_start + 1:pos - 1]
            else:  # bare macro or number, e.g. month = jun
                pos = value_start + re.match(r"[\w-]+", body[value_start:]).end()
                value = body[value_start:pos]
            fields[field.group(1).lower()] = " ".join(value.split())
        entries[match.group(2)] = fields
    return entries


def _initials(given: str) -> str:
    parts = []
    for name in given.split():
        if name.startswith("{"):  # accented first letter, e.g. {\'E}douard
            parts.append(name[:_braced(name, 0)] + ".")
        else:
            parts.append("-".join(piece[0] + "." for piece in name.split("-") if piece))
    return " ".join(parts)


def split_authors(field: str) -> List[str]:
    """Split on `` and `` outside braces, so {Forum of ... and ... (FIRST)} stays whole."""
    authors, depth, current = [], 0, ""
    for token in re.split(r"(\s+and\s+|[{}])", field):
        if token == "{":
            depth += 1
        elif token == "}":
            depth -= 1
        elif depth == 0 and re.fullmatch(r"\s+and\s+", token or ""):
            authors.append(current.strip())
            current = ""
            continue
        current += token or ""
    return authors + [current.strip()]


def format_authors(field: str) -> str:
    names = []
    for author in split_authors(field):
        if author.startswith("{") and author.endswith("}"):
            names.append(author[1:-1])  # corporate author
        elif "," in author:
            surname, given = (s.strip() for s in author.split(",", 1))
            names.append(f"{surname}, {_initials(given)}")
        else:
            names.append(author)
    if len(names) == 1:
        return names[0]
    return ", ".join(names[:-1]) + ", \\& " + names[-1]


def _sort_key(entry: Dict[str, str]) -> str:
    first = split_authors(entry.get("author", ""))[0]
    return re.sub(r"[^a-z]", "", first.lower()) + entry.get("year", "")


def _venue(name: str) -> str:
    return re.sub(r"^Proc\.\s+", "Proceedings of the ", name)


def _end(text: str) -> str:
    return text if text.endswith((".", "?", "!")) else text + "."


def format_entry(e: Dict[str, str]) -> str:
    year = e.get("year", "n.d.")
    if e.get("month") and e["_kind"] in ("misc", "techreport"):
        year = f"{year}, {MONTHS.get(e['month'].lower()[:3], e['month'])}"
    parts = [f"{_end(format_authors(e['author']))} ({year})."]
    kind, title = e["_kind"], e["title"]

    if kind == "article":
        parts.append(_end(title))
        venue = f"{{\\it {e['journal']}}}"
        if e.get("volume"):
            venue += f", {{\\it {e['volume']}}}"
            if e.get("number"):
                venue += f"({e['number']})"
        if e.get("pages"):
            venue += f", {e['pages']}"
        parts.append(venue + ".")
    elif kind == "inproceedings":
        parts.append(_end(title))
        venue = f"In {{\\it {_venue(e['booktitle'])}}}"
        if e.get("volume") and e.get("series"):
            venue += f" ({e['series']}, Vol.\\ {e['volume']})"
        if e.get("pages"):
            venue += f" (pp.\\ {e['pages']})"
        parts.append(venue + ".")
        if e.get("publisher"):
            parts.append(_end(e["publisher"]))
    elif kind == "book":
        parts.append(f"{{\\it {_end(title)}}}")
        parts.append(_end(e.get("publisher", "")))
    elif kind == "techreport":
        report = f" ({e.get('type', 'Report')} {e['number']})" if e.get("number") else ""
        parts.append(f"{{\\it {title}}}{report}.")
        parts.append(_end(e.get("institution", "")))
    else:  # misc: web pages, repositories, preprints
        parts.append(f"{{\\it {_end(title)}}}")
        if e.get("howpublished"):
            parts.append(_end(e["howpublished"]))
        if e.get("note"):
            parts.append(_end(e["note"]))

    if e.get("doi"):
        parts.append(f"\\url{{https://doi.org/{e['doi']}}}")
    elif e.get("url") and "\\url" not in e.get("howpublished", ""):
        parts.append(f"\\url{{{e['url']}}}")
    return " ".join(p for p in parts if p and p != ".")


def cited_keys(tex: str) -> List[str]:
    keys: List[str] = []
    for group in re.findall(r"\\cite\{([^}]*)\}", tex):
        for key in (k.strip() for k in group.split(",")):
            if key not in keys:
                keys.append(key)
    return keys


def main() -> int:
    tex = TEX_PATH.read_text(encoding="utf-8")
    bib = parse_bib(BIB_PATH.read_text(encoding="utf-8"))
    keys = cited_keys(tex)
    missing = [k for k in keys if k not in bib]
    if missing:
        sys.stderr.write(f"Keys cited in main.tex but missing from refs.bib: {missing}\n")
        return 1

    # thebibliography's argument is only a width template for the widest label.
    items = [f"\\bibitem{{{k}}} {format_entry(bib[k])}" for k in sorted(keys, key=lambda k: _sort_key(bib[k]))]
    block = "\n".join([START + " (generated by make_bibliography.py -- edit refs.bib, not this block)",
                       f"\\begin{{thebibliography}}{{{9 if len(items) < 10 else 99}}}", "",
                       "\n\n".join(items), "", "\\end{thebibliography}", END])
    start, end = tex.index(START), tex.index(END) + len(END)
    TEX_PATH.write_text(tex[:start] + block + tex[end:], encoding="utf-8")
    print(f"[SUCCESS] {len(items)} references written to {TEX_PATH.name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
