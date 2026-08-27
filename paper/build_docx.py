#!/usr/bin/env python3
"""Build main.docx from main.md (a small, predictable Markdown -> Word converter).

Handles the subset of Markdown used in main.md: #/##/### headings, **bold**,
*italic*, `code`, blockquotes, GitHub-style tables, bullet/numbered lists, code
fences, and horizontal rules. Not a general Markdown engine — tuned to this file.

    python build_docx.py    # -> main.docx
"""

from __future__ import annotations

import re
from pathlib import Path

from docx import Document
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.shared import Pt, RGBColor

SRC = Path(__file__).with_name("main.md")
OUT = Path(__file__).with_name("main.docx")

_INLINE = re.compile(r"(\*\*.+?\*\*|\*[^*]+?\*|`[^`]+?`|\[TODO:[^\]]*\])")


def add_runs(paragraph, text: str):
    """Add inline-formatted runs (bold/italic/code/TODO) to a paragraph."""
    for part in _INLINE.split(text):
        if not part:
            continue
        if part.startswith("**") and part.endswith("**"):
            r = paragraph.add_run(part[2:-2]); r.bold = True
        elif part.startswith("`") and part.endswith("`"):
            r = paragraph.add_run(part[1:-1]); r.font.name = "Consolas"; r.font.size = Pt(9.5)
        elif part.startswith("[TODO:"):
            r = paragraph.add_run(part); r.bold = True; r.font.color.rgb = RGBColor(0xC0, 0x00, 0x00)
        elif part.startswith("*") and part.endswith("*"):
            r = paragraph.add_run(part[1:-1]); r.italic = True
        else:
            paragraph.add_run(part)


def flush_table(doc, rows):
    """rows: list of list[str]; row 0 is header, a separator row already removed."""
    if not rows:
        return
    ncols = max(len(r) for r in rows)
    t = doc.add_table(rows=0, cols=ncols)
    t.style = "Light Grid Accent 1"
    for ri, row in enumerate(rows):
        cells = t.add_row().cells
        for ci in range(ncols):
            txt = row[ci] if ci < len(row) else ""
            cells[ci].paragraphs[0].text = ""
            add_runs(cells[ci].paragraphs[0], txt)
            if ri == 0:
                for run in cells[ci].paragraphs[0].runs:
                    run.bold = True
    doc.add_paragraph()


def is_table_sep(line: str) -> bool:
    return bool(re.match(r"^\s*\|?\s*:?-{2,}", line)) and set(line.strip()) <= set("|:- ")


def main() -> None:
    doc = Document()
    doc.core_properties.title = "What a Replay Benchmark Rewards"
    doc.core_properties.author = "Christian Metzl"
    normal = doc.styles["Normal"].font
    normal.name = "Calibri"; normal.size = Pt(10.5)

    lines = SRC.read_text().splitlines()
    i = 0
    in_code = False
    code_buf: list[str] = []
    tbl_buf: list[list[str]] = []

    def flush_code():
        nonlocal code_buf
        if code_buf:
            p = doc.add_paragraph()
            r = p.add_run("\n".join(code_buf))
            r.font.name = "Consolas"; r.font.size = Pt(9)
            code_buf = []

    def flush_tbl():
        nonlocal tbl_buf
        if tbl_buf:
            flush_table(doc, tbl_buf); tbl_buf = []

    while i < len(lines):
        line = lines[i]

        if line.strip().startswith("```"):
            if in_code:
                flush_code(); in_code = False
            else:
                in_code = True
            i += 1; continue
        if in_code:
            code_buf.append(line); i += 1; continue

        # table rows
        if line.strip().startswith("|") and "|" in line.strip()[1:]:
            if is_table_sep(line):
                i += 1; continue
            cells = [c.strip() for c in line.strip().strip("|").split("|")]
            tbl_buf.append(cells); i += 1; continue
        else:
            flush_tbl()

        if not line.strip():
            i += 1; continue

        if line.startswith("### "):
            doc.add_heading(line[4:].strip(), level=2)
        elif line.startswith("## "):
            doc.add_heading(line[3:].strip(), level=1)
        elif line.startswith("# "):
            h = doc.add_heading(line[2:].strip(), level=0)
            h.alignment = WD_ALIGN_PARAGRAPH.CENTER
        elif line.startswith("> "):
            p = doc.add_paragraph(); p.paragraph_format.left_indent = Pt(18)
            add_runs(p, line[2:].strip())
        elif line.strip() == "---":
            pass  # horizontal rule -> skip (spacing handled by blank lines)
        elif re.match(r"^\s*[-*] ", line):
            p = doc.add_paragraph(style="List Bullet"); add_runs(p, re.sub(r"^\s*[-*] ", "", line))
        elif re.match(r"^\s*\d+\. ", line):
            p = doc.add_paragraph(style="List Number"); add_runs(p, re.sub(r"^\s*\d+\. ", "", line))
        else:
            p = doc.add_paragraph(); add_runs(p, line)
        i += 1

    flush_code(); flush_tbl()
    doc.save(OUT)
    print(f"wrote {OUT} ({OUT.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
