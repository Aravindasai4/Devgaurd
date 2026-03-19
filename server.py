from fastapi import FastAPI
from fastapi.responses import JSONResponse, HTMLResponse, StreamingResponse
from pydantic import BaseModel
import io

from devguard import scan_url

app = FastAPI(title="DevGuard Backend", version="0.1")

# ---------- Models ----------
class ScanReq(BaseModel):
    demo: bool | None = None
    url: str | None = None
    http_check: bool = False

# ---------- Root ----------
@app.get("/", response_class=HTMLResponse)
async def root():
    return """
    <html>
      <head><title>DevGuard API</title></head>
      <body style="font-family:system-ui;margin:40px">
        <h2>🛡️ DevGuard API is live</h2>
        <p>Use <a href="/ui"><b>DevGuard UI</b></a> for the demo, or <a href="/docs"><b>/docs</b></a> for Swagger.</p>
        <ul>
          <li>POST <code>/scan</code> — run a demo scan with <code>{ "demo": true }</code></li>
        </ul>
      </body>
    </html>
    """

# ---------- Built-in Frontend (no Fix, no PDF) ----------
@app.get("/ui", response_class=HTMLResponse)
async def ui():
    return """
<!doctype html>
<html>
<head>
  <meta charset="utf-8"/>
  <title>DevGuard — Scan your no-code export</title>
  <style>
    :root{--fg:#111;--muted:#666;--bg:#fafafa;--primary:#ff4d4f;}
    body{font-family:system-ui,Segoe UI,Roboto,Arial,sans-serif;background:#fff;margin:32px;color:var(--fg)}
    h1{margin:0 0 6px}
    .cap{color:var(--muted);margin-bottom:18px}
    .card{border:1px solid #eee;border-radius:12px;padding:16px;margin:12px 0;background:var(--bg)}
    input[type=text]{width:100%;padding:10px 12px;border:1px solid #ddd;border-radius:8px;font-size:14px}
    label{font-size:14px}
    button{background:#ff4d4f;color:#fff;border:0;border-radius:10px;padding:10px 14px;font-size:14px;cursor:pointer}
    button:disabled{opacity:.6;cursor:not-allowed}
    .row{display:flex;gap:12px;align-items:center;flex-wrap:wrap}
    .mt{margin-top:12px}
    .muted{color:var(--muted)}
    .finding{border:1px solid #eee;border-radius:10px;padding:10px;margin:8px 0;background:#fff}
    .sev{font-weight:700}
    .sev.HIGH{color:#b80000}
    .sev.MEDIUM{color:#b8860b}
    .sev.LOW{color:#246}
    .progress{height:10px;background:#eee;border-radius:999px;overflow:hidden}
    .bar{height:100%;background:var(--primary);width:0%}
    .chips{display:flex;gap:8px;flex-wrap:wrap;margin-top:8px}
    .chip{background:#fff;border:1px solid #ddd;border-radius:999px;padding:6px 10px;font-size:13px;cursor:pointer}
    .chip:hover{border-color:#bbb}
    .notice{background:#fff3cd;border:1px solid #ffeeba;padding:12px;border-radius:8px;margin:16px 0;line-height:1.4}
  </style>
</head>
<body>
  <h1>DevGuard — Scan your no-code export</h1>
  <div class="cap">Demo-only UI. Run a scan and view findings. No broken buttons.</div>

  <div class="notice">
    ⚠️ <b>Important Notice</b><br/>
    Remember: <b>DevGuard is for demo/educational purposes only.</b><br/>
    Do not aim it at private apps, production services, or systems you do not own.<br/><br/>
    ✅ For a safe test, keep <b>“Use demo data”</b> checked and click <b>Run Scan</b> — no URL needed.
  </div>

  <div class="card">
    <div class="row">
      <label><input id="demo" type="checkbox" checked /> Use demo data</label>
      <span class="muted">or</span>
      <input id="url" type="text" placeholder="https://example.org" />
      <button id="run">Run Scan</button>
    </div>
    <div class="mt">
      <div class="muted">Quick picks (public test sites): click to auto-fill</div>
      <div class="chips">
        <span class="chip" data-u="https://httpbin.org/cookies/set?mycookie=test">httpbin cookies</span>
        <span class="chip" data-u="https://expired.badssl.com/">expired.badssl.com</span>
        <span class="chip" data-u="https://jsonplaceholder.typicode.com/users">jsonplaceholder users</span>
        <span class="chip" data-u="https://example.org/">example.org</span>
      </div>
    </div>
    <div id="status" class="muted mt"></div>
  </div>

  <div id="results" class="card" style="display:none">
    <div class="row" style="justify-content:space-between">
      <div><b>Security Score:</b> <span id="score">0</span>/100</div>
      <div style="min-width:200px;flex:1">
        <div class="progress"><div id="bar" class="bar"></div></div>
      </div>
    </div>
    <div id="list" class="mt"></div>
  </div>

<script>
const el = (id)=>document.getElementById(id);
const fmt = (n)=>Math.max(0, Math.min(100, parseInt(n||0,10)));

async function post(path, body){
  const r = await fetch(path, {method: "POST", headers: {"Content-Type":"application/json"}, body: JSON.stringify(body)});
  if(!r.ok) throw new Error(await r.text());
  return await r.json();
}

function render(data){
  el("results").style.display = "block";
  const score = fmt(data.score);
  el("score").textContent = score;
  el("bar").style.width = (score) + "%";

  const list = el("list");
  list.innerHTML = "";
  const findings = data.findings || [];
  if(findings.length === 0){
    list.innerHTML = '<div class="muted">No active findings. 🎉</div>';
    return;
  }
  findings.forEach((f, i)=>{
    const sev = (f.severity||"").toUpperCase();
    const t = f.title || f.message || ("Finding " + (i+1));
    const ev = f.evidence ? (typeof f.evidence==="string" ? f.evidence : JSON.stringify(f.evidence, null, 2)) : "";
    const item = document.createElement("div");
    item.className = "finding";
    item.innerHTML = `
      <div><span class="sev ${sev}">${sev||"INFO"}</span> — ${t}</div>
      ${ev ? `<pre style="white-space:pre-wrap;background:#fafafa;border:1px solid #eee;padding:8px;border-radius:8px;margin:8px 0">${ev}</pre>` : ""}
    `;
    list.appendChild(item);
  });
}

el("run").addEventListener("click", async ()=>{
  el("run").disabled = true;
  el("status").textContent = "Scanning… Parsing → Applying rules → Scoring";
  try{
    const demo = el("demo").checked;
    const val = (el("url").value||"").trim();
    const payload = demo || !val ? {demo:true} : {url: val};
    const data = await post("/scan", payload);
    render(data);
    el("status").textContent = "Scan complete";
  }catch(e){
    console.warn(e);
    render({
      url: "https://example.org",
      score: 64,
      verdict: "Yellow",
      stats: {status: 200, content_length: 12345},
      findings: [
        {severity:"medium", type:"https_hsts", message:"Missing Strict-Transport-Security header on HTTPS site"},
        {severity:"medium", type:"csp", message:"Weak CSP: script-src contains 'unsafe-inline'"},
      ],
    });
    el("status").textContent = "Backend not reachable — loaded demo results.";
  }finally{
    el("run").disabled = false;
  }
});

// quick-pick chips -> fill URL + uncheck demo
document.addEventListener("click", (e)=>{
  const chip = e.target.closest(".chip");
  if(!chip) return;
  const u = chip.getAttribute("data-u") || "";
  el("url").value = u;
  const demoBox = document.getElementById("demo");
  if (demoBox) demoBox.checked = false;
});
</script>
</body>
</html>
    """

# ---------- API ----------
@app.post("/scan")
async def scan(req: ScanReq):
    target = "https://example.org" if req.demo else (req.url or "https://example.org")
    result = scan_url(target, http_check=req.http_check)
    return JSONResponse(content=result)

# Keeping /report.pdf to avoid 404s in case something links to it,
# but the UI no longer shows a PDF button.
@app.get("/report.pdf")
async def report_pdf():
    pdf_bytes = (b"%PDF-1.4\n% DevGuard placeholder report\n1 0 obj<<>>endobj\ntrailer<<>>\n%%EOF")
    return StreamingResponse(io.BytesIO(pdf_bytes), media_type="application/pdf")
