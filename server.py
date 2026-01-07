from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse

app = FastAPI()

# ======================================================
# GLOBAL STATE — ONLY ONE TUNNEL AT A TIME
# ======================================================
ENCRYPTED_PAYLOAD = None   # { "nonce": "...", "data": "..." }


# ======================================================
# 1️⃣ TUNNEL UPDATE (FROM tunnel_digging.py)
# ======================================================
@app.post("/update")
async def update_tunnel(payload: dict):
    global ENCRYPTED_PAYLOAD

    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="Invalid payload")

    if "nonce" not in payload or "data" not in payload:
        raise HTTPException(status_code=400, detail="Missing fields")

    ENCRYPTED_PAYLOAD = payload
    print("🔄 Tunnel payload updated")

    return {"status": "ok"}


# ======================================================
# 1.5️⃣ TUNNEL END (CLEAR STATE)
# ======================================================
@app.post("/end")
async def end_tunnel():
    global ENCRYPTED_PAYLOAD
    ENCRYPTED_PAYLOAD = None
    print("🧨 Tunnel payload cleared")
    return {"status": "cleared"}


# ======================================================
# 2️⃣ ANDROID CLIENT (BLIND FETCH)
# ======================================================
@app.get("/payload")
async def get_payload():
    if not ENCRYPTED_PAYLOAD:
        raise HTTPException(status_code=503, detail="Tunnel not ready")

    return JSONResponse(
        ENCRYPTED_PAYLOAD,
        headers={"Cache-Control": "no-store"}
    )


# ======================================================
# 3️⃣ WEB CLIENT (HTML + CLIENT-SIDE DECRYPT)
# ======================================================
HTML_PAGE = """

<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta
  name="viewport"
  content="width=device-width, initial-scale=1, maximum-scale=1, user-scalable=no"
/>

<title>Secure Gate</title>

<style>
:root {
  --bg: #000;
  --card: #121212;
  --border: #2a2a2a;
  --text: #fff;
  --muted: #8a8a8a;
  --accent: #e46b7a;
}

* { box-sizing: border-box; }

/* Disable text selection everywhere */
* {
  -webkit-user-select: none;
  -webkit-touch-callout: none;
  user-select: none;
}

html, body {
  margin: 0;
  width: 100%;
  height: 100%;
  background: var(--bg);
  color: var(--text);
  font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
}

body {
  display: flex;
  align-items: center;
  justify-content: center;
}

/* ================== CARDS ================== */

.container {
  width: 100%;
  max-width: 340px;
  padding: 20px;
  background: var(--card);
  border-radius: 14px;
  border: 1px solid var(--border);
  text-align: center;
  display: none;
}

.status {
  width: 100%;
  max-width: 320px;
  padding: 22px;
  background: #0b0b0b;
  border-radius: 14px;
  border: 1px solid var(--border);
  text-align: center;
  display: none;
}

h1 {
  margin: 0 0 6px 0;
  font-size: 17px;
  font-weight: 600;
}

.subtitle {
  font-size: 12px;
  color: var(--muted);
  margin-bottom: 16px;
}

/* ================== INPUT ================== */

.field {
  position: relative;
}

.field input {
  width: 100%;
  padding: 16px 44px 16px 14px;
  font-size: 14px;
  background: #0b0b0b;
  color: var(--text);
  border-radius: 10px;

  border: 1px solid #000;
  outline: 1px solid #ffffff22;

  letter-spacing: 0.05em;
}

.field label {
  position: absolute;
  left: 12px;
  top: 50%;
  transform: translateY(-50%);
  padding: 0 4px;
  font-size: 12px;
  color: #666;
  background: var(--card);
  pointer-events: none;
  transition: 0.15s ease;
}

.field input:focus + label,
.field input:not(:placeholder-shown) + label {
  top: -7px;
  font-size: 10px;
  color: #aaa;
}

/* ================== CLEAR BUTTON ================== */

.clear-btn {
  position: absolute;
  right: 12px;
  top: 50%;
  width: 16px;
  height: 16px;
  transform: translateY(-50%);
  background: none;
  border: none;
  padding: 0;
  cursor: pointer;
  opacity: 0.55;
  display: none;
}

.field input:not(:placeholder-shown) ~ .clear-btn {
  display: block;
}

.clear-btn::before,
.clear-btn::after {
  content: "";
  position: absolute;
  top: 50%;
  left: 50%;
  width: 14px;
  height: 1.4px;
  background: var(--accent);
  border-radius: 1px;
}

.clear-btn::before {
  transform: translate(-50%, -50%) rotate(45deg);
}

.clear-btn::after {
  transform: translate(-50%, -50%) rotate(-45deg);
}

/* ================== BUTTON ================== */

button.main {
  width: 100%;
  margin-top: 16px;
  padding: 13px;
  font-size: 14px;
  font-weight: 600;
  border-radius: 12px;
  background: #fff;
  color: #000;
  border: none;
  cursor: pointer;
}

.err {
  margin-top: 10px;
  font-size: 12px;
  color: #ff4d4d;
}

.footer {
  margin-top: 12px;
  font-size: 10px;
  color: #666;
}

/* ================== AUTOFILL KILL ================== */

input {
  autocomplete: new-password !important;
  autocorrect: off !important;
  autocapitalize: off !important;
  spellcheck: false !important;
}
</style>
</head>

<body>

<!-- Autofill poison (browser-level) -->
<input type="password" style="display:none" autocomplete="current-password">
<input type="text" style="display:none" autocomplete="username">

<!-- STATUS -->
<div id="status" class="status">
  <h1>No Active Tunnel</h1>
  <div class="subtitle">
    Secure connection is offline.<br/>
    Please try again later.
  </div>
</div>

<!-- MAIN -->
<div id="card" class="container">
  <h1>Secure Access</h1>
  <div class="subtitle">Protected session</div>

  <div class="field">
    <input
      id="access"
      name="field-01"
      type="text"
      placeholder=" "
      inputmode="latin"
      autocomplete="new-password"
      aria-autocomplete="none"
    />
    <label for="access">Access code</label>
    <span class="clear-btn" role="button" tabindex="-1"></span>
  </div>

  <button class="main" onclick="unlock()">Continue</button>

  <div id="err" class="err"></div>
  <div class="footer">Zero-knowledge gateway</div>
</div>

<script>

document.addEventListener("click", e => {
  if (e.target.classList.contains("clear-btn")) {
    const input = document.getElementById("access");
    input.value = "";
    input.focus();
  }
});

async function checkTunnel() {
  try {
    const res = await fetch("/payload", { cache: "no-store" });
    if (res.ok) {
      document.getElementById("card").style.display = "block";
    } else {
      document.getElementById("status").style.display = "block";
    }
  } catch {
    document.getElementById("status").style.display = "block";
  }
}

function clearInput() {
  const i = document.getElementById("access");
  i.value = "";
  i.focus();
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
    err.textContent = "Invalid access code";
    return;
  }

  const res = await fetch("/payload", { cache: "no-store" });
  if (!res.ok) {
    err.textContent = "Tunnel not ready";
    return;
  }

  const payload = await res.json();

  try {
    const url = await decryptAES(keyBytes, payload.nonce, payload.data);
    window.location.href = url;
  } catch {
    err.textContent = "Access denied";
  }
}

async function decryptAES(keyBytes, nonceB64, dataB64) {
  const nonce = Uint8Array.from(atob(nonceB64), c => c.charCodeAt(0));
  const data = Uint8Array.from(atob(dataB64), c => c.charCodeAt(0));

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

checkTunnel();
</script>

</body>
</html>
"""


@app.get("/", response_class=HTMLResponse)
async def web_gate():
    return HTML_PAGE
    
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=10000)
    
