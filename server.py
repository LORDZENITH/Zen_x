from fastapi import FastAPI, HTTPException, Header
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel
import os
import json
import asyncio
import time
import hmac
from pathlib import Path

app = FastAPI()

# ======================================================
# CONFIG (Render: set env vars)
# ======================================================
# Required: set this in Render env
GATE_PASS = os.getenv("GATE_PASS", "")
if not GATE_PASS:
    # Keep server runnable locally, but strongly recommended to set in env
    GATE_PASS = "CHANGE_ME"

# Best-effort persistence file (works if filesystem survives; harmless if wiped)
STATE_FILE = Path(os.getenv("STATE_FILE", "/tmp/_g.bin"))

# Optional: prevent unlimited RAM growth / garbage input
MAX_NONCE_LEN = 4096
MAX_DATA_LEN = 16384

# ======================================================
# NUMERIC CODES (web-facing: no hints)
# ======================================================
# 100 = ok
# 200 = need input
# 301 = denied
# 404 = not found/invalid
# 409 = busy/locked
# 503 = not ready
# 520 = internal
C_OK = 100
C_NEED = 200
C_DENY = 301
C_BAD = 404
C_BUSY = 409
C_NR = 503
C_ERR = 520

# ======================================================
# STATE (single payload)
# ======================================================
class Payload(BaseModel):
    nonce: str
    data: str

app.state.lock = asyncio.Lock()
app.state.payload = None  # dict: {"nonce": "...", "data": "..."}
app.state.updated_at = None  # unix ts

# ======================================================
# HELPERS
# ======================================================
def _auth(x_pass: str | None) -> None:
    # Constant-time compare
    if not x_pass or not hmac.compare_digest(x_pass, GATE_PASS):
        raise HTTPException(status_code=403, detail=C_DENY)

def _validate_payload(p: Payload) -> None:
    if not p.nonce or not p.data:
        raise HTTPException(status_code=400, detail=C_BAD)
    if len(p.nonce) > MAX_NONCE_LEN or len(p.data) > MAX_DATA_LEN:
        raise HTTPException(status_code=413, detail=C_BAD)

def _atomic_write_json(path: Path, obj: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as f:
        json.dump(obj, f, separators=(",", ":"))
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)

def _best_effort_load() -> dict | None:
    try:
        if not STATE_FILE.exists():
            return None
        raw = STATE_FILE.read_text(encoding="utf-8")
        obj = json.loads(raw)
        if not isinstance(obj, dict):
            return None
        if "nonce" not in obj or "data" not in obj:
            return None
        # sanity limits
        if (not isinstance(obj["nonce"], str)) or (not isinstance(obj["data"], str)):
            return None
        if len(obj["nonce"]) > MAX_NONCE_LEN or len(obj["data"]) > MAX_DATA_LEN:
            return None
        return {"nonce": obj["nonce"], "data": obj["data"]}
    except Exception:
        return None

def _best_effort_clear_file() -> None:
    try:
        if STATE_FILE.exists():
            STATE_FILE.unlink()
    except Exception:
        pass

# ======================================================
# STARTUP: restore from file if available (optional)
# ======================================================
@app.on_event("startup")
async def _startup_restore():
    restored = _best_effort_load()
    if restored:
        async with app.state.lock:
            app.state.payload = restored
            app.state.updated_at = time.time()

# ======================================================
# 1) UPDATE (password required)
# ======================================================
@app.post("/update")
async def update_tunnel(payload: Payload, x_pass: str = Header(None)):
    _auth(x_pass)
    _validate_payload(payload)

    obj = {"nonce": payload.nonce, "data": payload.data}

    async with app.state.lock:
        # Single payload: replace allowed (simple)
        app.state.payload = obj
        app.state.updated_at = time.time()

    # Best-effort persistence (if FS survives, it restores after spin-down; if not, server behaves like RAM-only)
    try:
        _atomic_write_json(STATE_FILE, obj)
    except Exception:
        # Ignore: compatibility mode
        pass

    return {"c": C_OK}

# ======================================================
# 2) END (password required) - only explicit wipe
# ======================================================
@app.post("/end")
async def end_tunnel(x_pass: str = Header(None)):
    _auth(x_pass)
    async with app.state.lock:
        app.state.payload = None
        app.state.updated_at = None
    _best_effort_clear_file()
    return {"c": C_OK}

# ======================================================
# 3) PAYLOAD (blind fetch)
# ======================================================
@app.get("/payload")
async def get_payload():
    async with app.state.lock:
        if not app.state.payload:
            # No hints
            raise HTTPException(status_code=503, detail=C_NR)
        return JSONResponse(app.state.payload, headers={"Cache-Control": "no-store"})

# ======================================================
# 4) WEB GATE (no readable hints)
# ======================================================
HTML_PAGE = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1, user-scalable=no"/>
<title>200</title>

<style>
:root {
  --bg:#0a0a0a;
  --card:#111111;
  --border:#1f1f1f;
  --text:#d0d0d0;
  --muted:#555;
}

* {
  box-sizing:border-box;
}

* {
  -webkit-user-select:none;
  -webkit-touch-callout:none;
  user-select:none;
}

html, body {
  margin:0;
  width:100%;
  height:100%;
  background:var(--bg);
  color:var(--text);
  font-family:system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
}

body {
  display:flex;
  align-items:center;
  justify-content:center;
}

.container,
.status {
  width:100%;
  max-width:320px;
  padding:22px;
  background:var(--card);
  border-radius:12px;
  border:1px solid var(--border);
  text-align:center;
  display:none;
}

h1 {
  margin:0 0 18px 0;
  font-size:18px;
  font-weight:600;
  letter-spacing:0.08em;
}

.field {
  position:relative;
}

.field input {
  width:100%;
  padding:15px 40px 15px 12px;
  font-size:14px;
  background:#0f0f0f;
  color:var(--text);
  border-radius:8px;
  border:1px solid var(--border);
  outline:none;
  letter-spacing:0.08em;
}

.field input:focus {
  border-color:#2a2a2a;
}

.field label {
  position:absolute;
  left:12px;
  top:50%;
  transform:translateY(-50%);
  font-size:12px;
  color:var(--muted);
  pointer-events:none;
  transition:0.15s ease;
}

.field input:focus + label,
.field input:not(:placeholder-shown) + label {
  top:-8px;
  font-size:10px;
  color:#777;
}

.clear-btn {
  position:absolute;
  right:10px;
  top:50%;
  width:14px;
  height:14px;
  transform:translateY(-50%);
  background:none;
  border:none;
  padding:0;
  cursor:pointer;
  opacity:0.5;
  display:none;
}

.field input:not(:placeholder-shown) ~ .clear-btn {
  display:block;
}

.clear-btn::before,
.clear-btn::after {
  content:"";
  position:absolute;
  top:50%;
  left:50%;
  width:12px;
  height:1px;
  background:#666;
}

.clear-btn::before {
  transform:translate(-50%,-50%) rotate(45deg);
}

.clear-btn::after {
  transform:translate(-50%,-50%) rotate(-45deg);
}

button.main {
  width:100%;
  margin-top:18px;
  padding:12px;
  font-size:13px;
  border-radius:8px;
  background:#1a1a1a;
  color:#aaa;
  border:1px solid var(--border);
  cursor:pointer;
}

button.main:active {
  background:#222;
}

.err {
  margin-top:12px;
  font-size:12px;
  color:#888;
}

input {
  autocomplete:new-password !important;
  autocorrect:off !important;
  autocapitalize:off !important;
  spellcheck:false !important;
}
</style>
</head>

<body>

<input type="password" style="display:none" autocomplete="current-password">
<input type="text" style="display:none" autocomplete="username">

<div id="status" class="status">
  <h1>503</h1>
</div>

<div id="card" class="container">
  <h1>200</h1>

  <div class="field">
    <input id="access" name="f01" type="text" placeholder=" "
           inputmode="latin"
           autocomplete="new-password"
           aria-autocomplete="none"/>
    <label>200</label>
    <span class="clear-btn"></span>
  </div>

  <button class="main" onclick="unlock()">100</button>
  <div id="err" class="err"></div>
</div>

<script>
document.addEventListener("click", function(e) {
  if (e.target.classList.contains("clear-btn")) {
    var input = document.getElementById("access");
    input.value = "";
    input.focus();
  }
});

async function check() {
  try {
    const res = await fetch("/payload", { cache: "no-store" });
    if (res.ok) {
      document.getElementById("card").style.display = "block";
    } else {
      document.getElementById("status").style.display = "block";
    }
  } catch (e) {
    document.getElementById("status").style.display = "block";
  }
}

function hexToBytes(hex) {
  if (hex.length !== 64) return null;
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    const b = parseInt(hex.substr(i * 2, 2), 16);
    if (Number.isNaN(b)) return null;
    out[i] = b;
  }
  return out;
}

async function unlock() {
  const v = document.getElementById("access").value.trim();
  const err = document.getElementById("err");
  err.textContent = "";

  const keyBytes = hexToBytes(v);
  if (!keyBytes) {
    err.textContent = "404";
    return;
  }

  const res = await fetch("/payload", { cache: "no-store" });
  if (!res.ok) {
    err.textContent = "503";
    return;
  }

  const payload = await res.json();

  try {
    const url = await decryptAES(keyBytes, payload.nonce, payload.data);
    window.location.href = url;
  } catch (e) {
    err.textContent = "301";
  }
}

async function decryptAES(keyBytes, nonceB64, dataB64) {
  const nonce = Uint8Array.from(atob(nonceB64), function(c) { return c.charCodeAt(0); });
  const data = Uint8Array.from(atob(dataB64), function(c) { return c.charCodeAt(0); });

  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    keyBytes,
    { name: "AES-GCM" },
    false,
    ["decrypt"]
  );

  const plain = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: nonce },
    cryptoKey,
    data
  );

  return new TextDecoder().decode(plain);
}

check();
</script>

</body>
</html>
"""

@app.get("/", response_class=HTMLResponse)
async def web_gate():
    return HTMLResponse(
        HTML_PAGE,
        headers={
            "Cache-Control": "no-store",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
        },
    )

# ======================================================
# Run (Render uses $PORT)
# ======================================================
if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", "10000"))
    uvicorn.run(app, host="0.0.0.0", port=port)