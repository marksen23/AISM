"""Render a Markdown document to PDF next to it (Python-Markdown + headless Chrome).
Usage: python tools/build_spec_pdf.py [doc.md ...]   default: AISM-Spezifikation.md
Needs: pip install markdown; google-chrome or chromium."""
import pathlib
import shutil
import subprocess
import sys
import tempfile

import markdown

repo = pathlib.Path(__file__).resolve().parent.parent
docs = [pathlib.Path(a).resolve() for a in sys.argv[1:]] or [repo / "AISM-Spezifikation.md"]


def render(md_path: pathlib.Path) -> None:
  root, stem = md_path.parent, md_path.stem
  src = md_path.read_text(encoding="utf-8")
  import re
  lines, out = src.splitlines(), []
  for i, ln in enumerate(lines):   # Python-Markdown needs a blank line before a list (GitHub does not)
      is_item = re.match(r"\s*([-*]|\d+\.)\s", ln)
      prev = out[-1] if out else ""
      if is_item and prev.strip() and not re.match(r"\s*([-*]|\d+\.)\s", prev) and not prev.startswith("|"):
          out.append("")
      out.append(ln)
  src = "\n".join(out)
  body = markdown.markdown(src, extensions=["extra", "toc", "sane_lists"])
  css = """@page{size:A4;margin:16mm 15mm 18mm}body{font-family:'DejaVu Sans',sans-serif;font-size:9.4pt;line-height:1.45;color:#1d2328}
  h1{color:#0b3b5c;font-size:22pt}h2{color:#0b3b5c;border-bottom:2px solid #1d7a8c;padding-bottom:2pt;margin-top:16pt;page-break-after:avoid}
  h3,h4{color:#1d7a8c;page-break-after:avoid}table{border-collapse:collapse;width:100%;font-size:8.4pt;margin:6pt 0}
  th{background:#0b3b5c;color:#fff;text-align:left;padding:3pt 4pt}td{border-bottom:1px solid #d5dde1;padding:2.5pt 4pt;vertical-align:top}
  tr{page-break-inside:avoid}code{font-family:'DejaVu Sans Mono',monospace;font-size:8.2pt;background:#eef2f4;padding:0 2pt}
  pre{background:#f3f6f8;border-left:3px solid #1d7a8c;padding:5pt;font-size:7.8pt;white-space:pre-wrap;page-break-inside:avoid}pre code{background:none}
  blockquote{background:#e8f1f4;border-left:4px solid #1d7a8c;margin:8pt 0;padding:4pt 8pt}img{max-width:100%}a{color:#1d7a8c;text-decoration:none}"""
  doc = f'<!doctype html><html lang="de"><head><meta charset="utf-8"><title>{stem}</title><style>{css}</style></head><body>{body}</body></html>'
  with tempfile.TemporaryDirectory() as tmp:
      html = root / f".{stem}.render.html"   # next to the source so relative image paths resolve
      html.write_text(doc, encoding="utf-8")
      chrome = shutil.which("google-chrome") or shutil.which("chromium")
      try:
          subprocess.run([chrome, "--headless=new", "--no-sandbox", "--disable-gpu", f"--user-data-dir={tmp}",
                          "--no-pdf-header-footer", f"--print-to-pdf={root / (stem + '.pdf')}", html.as_uri()],
                         check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=120)
      finally:
          html.unlink(missing_ok=True)
  print("written", root / (stem + ".pdf"))


for d in docs:
    render(d)
