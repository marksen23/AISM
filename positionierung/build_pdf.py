import markdown, re, subprocess, pathlib
src = pathlib.Path("AISM-Positionierung.md").read_text(encoding="utf-8")
md = markdown.Markdown(extensions=["extra", "toc", "sane_lists"], extension_configs={"toc": {"toc_depth": "2"}})
html = md.convert(src)
items = md.toc_tokens[0]["children"]
toc_html = '<div class="toc"><div class="toch">Inhalt</div><ol>' + "".join(f'<li><a href="#{t["id"]}">{t["name"]}</a></li>' for t in items) + "</ol></div>"

cover, body = html.split("<!-- PAGEBREAK -->", 1)
cover = cover.replace("<h1", '<div class="kicker">Positionierungspapier</div><h1', 1)
cover = re.sub(r"<p><strong>Positionierungspapier</strong></p>", "", cover)

stages = [("S1","UI &amp; Session"),("S2","Governance-Gateway"),("S3","Orchestrierung"),("S4","Retrieval"),("S5","Grounding"),("S6","Inferenz"),("S7","Compute")]
boxes = "".join(f'<div class="st{" gw" if n=="S2" else ""}"><b>{n}</b><span>{t}</span></div>' for n,t in stages)
fig = f'''<figure class="pipe"><div class="row">{boxes}</div>
<div class="tri"><div><b>AISM</b>Referenzmodell<br><small>Was gelten soll</small></div><div class="plus">+</div>
<div><b>AISM Reference Stack</b>Referenzimplementierung<br><small>Wie es umgesetzt wird</small></div><div class="plus">+</div>
<div><b>Konformitätstests</b>K1 · K2 · K3<br><small>Dass es gilt</small></div><div class="plus">=</div>
<div class="res"><b>Überprüfbare</b>Souveränität</div></div>
<figcaption>Abb. 1: AISM-Request-Pipeline (S2 als zentraler Kontrollpunkt) und das Zusammenspiel der drei Bausteine</figcaption></figure>'''
body = body.replace("<!-- FIG:pipeline -->", fig)
toc_html = re.sub(r'<a href="#quellen">Quellen</a>', '<a href="#quellen">Quellen</a>', toc_html)

css = """
@page { size: A4; margin: 18mm 18mm 20mm 18mm; }
:root { --c:#0b3b5c; --a:#1d7a8c; --l:#e8f1f4; --g:#5b6770; }
body { font-family: 'IBM Plex Sans','Inter','DejaVu Sans',sans-serif; font-size: 9.6pt; line-height: 1.47; color:#1d2328; }
h1 { font-size: 27pt; color: var(--c); line-height:1.15; margin: 0 0 8mm; }
h2 { font-size: 15pt; color: var(--c); border-bottom: 2px solid var(--a); padding-bottom: 2pt; margin-top: 18pt; page-break-after: avoid; }
h3 { font-size: 11.5pt; color: var(--a); margin-top: 12pt; page-break-after: avoid; }
p, li { text-align: justify; hyphens: auto; }
table { width:100%; border-collapse: collapse; margin: 8pt 0 10pt; font-size: 8.7pt; page-break-inside: auto; }
tr { page-break-inside: avoid; }
th { background: var(--c); color:#fff; text-align:left; padding: 3.5pt 5pt; font-weight:600; }
td { padding: 3pt 5pt; border-bottom: 1px solid #d5dde1; vertical-align: top; text-align:left; hyphens:auto; }
tr:nth-child(even) td { background: #f5f8fa; }
code { font-family: 'DejaVu Sans Mono', monospace; font-size: 8.6pt; background:#eef2f4; padding: 0 2pt; border-radius:2px; }
blockquote { margin: 10pt 0; padding: 6pt 10pt; background: var(--l); border-left: 4px solid var(--a); color:#27343c; font-size:9.5pt; }
blockquote p { margin: 2pt 0; }
a { color: var(--a); text-decoration: none; word-break: break-all; }
.cover { height: 247mm; display:flex; flex-direction:column; justify-content:flex-start; padding-top: 30mm; box-sizing:border-box; page-break-after: always; position:relative; }
.cover::before { content:""; position:absolute; top:0; left:0; width:38mm; height:5px; background: var(--a); }
.kicker { text-transform: uppercase; letter-spacing: 3pt; color: var(--a); font-weight:700; font-size: 10pt; margin-bottom: 4mm; }
.cover table { font-size: 9.5pt; margin-top: 10mm; }
.cover table thead { display:none; }
.cover td { background: none !important; border-bottom: 1px solid #d5dde1; }
.cover td:first-child { width: 38mm; color: var(--g); font-weight:600; }
.toc { margin-top: 10mm; border-top: 1px solid #d5dde1; padding-top: 5mm; }
.toch { text-transform: uppercase; letter-spacing: 2pt; color: var(--a); font-weight:700; font-size: 9pt; margin-bottom: 2mm; }
.toc ol { list-style:none; columns: 2; column-gap: 10mm; margin:0; padding-left: 0; font-size: 9.5pt; }
.toc li { padding: 1.5pt 0; break-inside: avoid; text-align:left; }
.toc a { color: #1d2328; word-break: normal; }
figure.pipe { margin: 12pt 0 14pt; page-break-inside: avoid; }
.row { display:flex; gap:4pt; }
.st { flex:1; background: var(--l); border:1px solid #c5d8df; border-radius:4px; padding:5pt 3pt; text-align:center; font-size:8pt; position:relative; }
.st b { display:block; color: var(--c); font-size: 11pt; }
.st.gw { background: var(--c); color:#fff; border-color: var(--c); }
.st.gw b { color:#fff; }
.tri { display:flex; align-items:center; gap:4pt; margin-top: 9pt; }
.tri > div { flex:1; text-align:center; font-size:8.5pt; border:1px solid #c5d8df; border-radius:4px; padding:6pt 3pt; }
.tri b { display:block; color: var(--c); font-size: 10pt; }
.tri small { color: var(--g); }
.tri .plus { flex:0 0 12pt; border:none; font-size: 16pt; color: var(--a); font-weight:700; padding:0; }
.tri .res { background: var(--a); color:#fff; border-color: var(--a); }
.tri .res b { color:#fff; }
figcaption { font-size: 8.5pt; color: var(--g); text-align:center; margin-top: 6pt; font-style: italic; }
ol li a, #quellen ~ ol li { font-size: 9pt; }
"""
doc = f"""<!doctype html><html lang="de"><head><meta charset="utf-8"><title>AISM als Referenz für souveräne KI-Infrastruktur</title><style>{css}</style></head>
<body><section class="cover">{cover}{toc_html}</section>
{body}</body></html>"""
pathlib.Path("AISM-Positionierung.html").write_text(doc, encoding="utf-8")

footer = '<div style="font-size:7.5pt;color:#5b6770;width:100%;padding:0 18mm;display:flex;justify-content:space-between;font-family:sans-serif"><span>AISM als Referenz für souveräne KI-Infrastruktur · Markus Oehring</span><span><span class="pageNumber"></span> / <span class="totalPages"></span></span></div>'
header = '<div></div>'

import json, time, base64, urllib.request, websocket, tempfile, os
port=9444
prof=tempfile.mkdtemp()
proc=subprocess.Popen(["google-chrome","--headless=new","--no-sandbox","--disable-gpu",f"--remote-debugging-port={port}",f"--user-data-dir={prof}","about:blank"],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
for _ in range(50):
    try:
        tabs=json.load(urllib.request.urlopen(f"http://127.0.0.1:{port}/json")); break
    except Exception: time.sleep(0.2)
ws_url=[t for t in tabs if t["type"]=="page"][0]["webSocketDebuggerUrl"]
ws=websocket.create_connection(ws_url, timeout=60, suppress_origin=True)
mid=0
def call(method, **params):
    global mid; mid+=1; ws.send(json.dumps({"id":mid,"method":method,"params":params}))
    while True:
        m=json.loads(ws.recv())
        if m.get("id")==mid: return m
call("Page.enable")
call("Page.navigate", url="file://"+str(pathlib.Path("AISM-Positionierung.html").resolve()))
time.sleep(2)
r=call("Page.printToPDF", printBackground=True, preferCSSPageSize=True, displayHeaderFooter=True,
       headerTemplate=header, footerTemplate=footer)
pathlib.Path("AISM-Positionierung.pdf").write_bytes(base64.b64decode(r["result"]["data"]))
ws.close(); proc.terminate()
print("PDF written")
