import base64
import posixpath
import re
from dataclasses import dataclass
from typing import List, Tuple

from flask import Flask, request, render_template_string, jsonify, make_response

import paramiko
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

app = Flask(__name__)

# ---------------------------------
# ثابت: المسار الحقيقي المطلوب
# ---------------------------------
REMOTE_BASE_DIR = "/root"  # سيتم الحفظ دائمًا هنا: /root/<domain>/dkim.pem

# -----------------------------
# Helpers
# -----------------------------
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)([A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63}$")
SELECTOR_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$")


@dataclass
class ResultItem:
    domain: str
    selector: str
    remote_path: str

    # Host name versions (important for DNS panels)
    record_host_short: str   # selector._domainkey
    record_host_full: str    # selector._domainkey.domain

    record_value: str
    record_value_split: str
    ok: bool
    error: str = ""


def is_valid_domain(d: str) -> bool:
    d = d.strip().lower()
    return bool(DOMAIN_RE.match(d))


def is_valid_selector(s: str) -> bool:
    s = s.strip()
    return bool(SELECTOR_RE.match(s))


def generate_dkim_keypair_local(key_size: int = 2048) -> Tuple[bytes, str]:
    """
    Returns:
      private_key_pem (bytes)
      public_key_base64 (str) suitable for DKIM p= (DER SubjectPublicKeyInfo base64)
    """
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    public_key = private_key.public_key()
    public_der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    public_b64 = base64.b64encode(public_der).decode("ascii")
    return private_pem, public_b64


def split_for_dns(value: str, chunk: int = 200) -> str:
    parts = [value[i:i + chunk] for i in range(0, len(value), chunk)]
    return " ".join([f'"{p}"' for p in parts])


# -----------------------------
# SSH / SFTP Helpers
# -----------------------------
def ssh_connect_sftp(host: str, port: int, user: str, password: str, timeout: int = 20):
    """
    Connect via SSH and open SFTP session.
    Password auth only (simple).
    """
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    client.connect(
        hostname=host,
        port=port,
        username=user,
        password=password,
        timeout=timeout,
        banner_timeout=timeout,
        auth_timeout=timeout,
        look_for_keys=False,
        allow_agent=False,
    )
    sftp = client.open_sftp()
    return client, sftp


def sftp_mkdirs(sftp: paramiko.SFTPClient, path: str):
    """
    Create nested directories if they don't exist.
    Works with absolute (/root/..) or relative paths.
    """
    path = (path or "").replace("\\", "/").strip()
    if not path:
        return

    is_abs = path.startswith("/")
    parts = [p for p in path.split("/") if p]

    cur = "/" if is_abs else "."
    for p in parts:
        nxt = posixpath.join(cur, p) if cur != "." else p
        try:
            sftp.stat(nxt)
        except Exception:
            sftp.mkdir(nxt)
        cur = nxt


def sftp_upload_bytes(sftp: paramiko.SFTPClient, remote_path: str, data: bytes):
    remote_path = (remote_path or "").replace("\\", "/").strip()
    if not remote_path:
        raise ValueError("Empty remote path.")

    remote_dir = posixpath.dirname(remote_path)
    if remote_dir and remote_dir not in (".", "/"):
        sftp_mkdirs(sftp, remote_dir)

    with sftp.open(remote_path, "wb") as f:
        f.write(data)


# -----------------------------
# Cookie Helpers
# -----------------------------
def get_cookie_value(name: str, default: str = "") -> str:
    return request.cookies.get(name, default)


def get_cookie_rows() -> List[dict]:
    rows = []
    try:
        row_count = int(request.cookies.get("row_count", "5"))
    except Exception:
        row_count = 5

    if row_count < 1:
        row_count = 5

    for i in range(row_count):
        default_selector = "dkim" if i == 0 else f"s{i + 1}"
        rows.append({
            "domain": request.cookies.get(f"domain_{i}", ""),
            "selector": request.cookies.get(f"selector_{i}", default_selector),
        })
    return rows


# -----------------------------
# UI Templates
# -----------------------------
INDEX_HTML = r"""
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>DKIM Generator + SSH (SFTP) Uploader</title>
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <style>
    :root{
      --bg0:#070b14;
      --bg1:#0b1220;
      --card:#0f1b34;
      --card2:#0c1730;
      --stroke:#20335f;
      --stroke2:#2a3f73;
      --text:#eaf1ff;
      --muted:#a9b6d6;
      --accent:#4d7cff;
      --accent2:#7aa3ff;
      --ok:#45ff9d;
      --bad:#ff5b6b;
      --warn:#ffcc66;
      --shadow: 0 18px 55px rgba(0,0,0,.35);
      --r:16px;
    }
    *{box-sizing:border-box}
    body{
      font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif;
      background:
        radial-gradient(900px 500px at 15% 0%, rgba(77,124,255,.18), transparent 55%),
        radial-gradient(900px 500px at 90% 15%, rgba(69,255,157,.10), transparent 55%),
        linear-gradient(180deg, var(--bg0), var(--bg1));
      color:var(--text);
      margin:0;
      min-height:100vh;
    }
    .wrap { max-width: 1120px; margin: 0 auto; padding: 24px; }
    .card {
      background: linear-gradient(180deg, rgba(255,255,255,.04), transparent 35%), var(--card);
      border:1px solid var(--stroke);
      border-radius:var(--r);
      padding:16px;
      margin: 14px 0;
      box-shadow: var(--shadow);
    }
    h1 { margin: 0 0 10px; font-size: 22px; letter-spacing:.2px; }
    h2 { margin: 0 0 8px; font-size: 16px; color:#dbe6ff; letter-spacing:.2px; }
    .muted { color:var(--muted); font-size: 13px; line-height:1.35; }
    label { display:block; margin: 10px 0 6px; font-size: 13px; color:#c7d2f0; }
    input, select {
      width:100%;
      padding:11px 12px;
      border-radius:12px;
      border:1px solid var(--stroke2);
      background: rgba(10,17,38,.75);
      color:var(--text);
      outline:none;
      transition: .15s border-color, .15s transform, .15s box-shadow;
    }
    input:focus, select:focus{
      border-color: rgba(122,163,255,.9);
      box-shadow: 0 0 0 4px rgba(77,124,255,.14);
    }
    .row { display:grid; grid-template-columns: 1fr 1fr; gap: 12px; }
    .row3 { display:grid; grid-template-columns: 1fr 1fr 1fr; gap: 12px; }
    .btns { display:flex; gap:10px; flex-wrap: wrap; margin-top: 12px; align-items:center; }
    button {
      border:0;
      border-radius: 12px;
      padding: 10px 14px;
      cursor:pointer;
      font-weight: 800;
      letter-spacing:.2px;
      transition:.15s transform, .15s filter, .15s opacity;
      user-select:none;
    }
    button:hover{ transform: translateY(-1px); filter: brightness(1.05); }
    button:active{ transform: translateY(0px) scale(.99); }
    .primary { background: linear-gradient(180deg, var(--accent2), var(--accent)); color:white; }
    .secondary { background: rgba(255,255,255,.04); color:var(--text); border:1px solid var(--stroke2); }
    .danger { background: linear-gradient(180deg, #ff7b86, var(--bad)); color:white; }
    table { width:100%; border-collapse: collapse; margin-top: 10px; overflow:hidden; border-radius:12px; }
    thead th{
      background: rgba(255,255,255,.03);
      color:#d4e1ff;
      font-size:12px;
      text-transform:uppercase;
      letter-spacing:.8px;
    }
    th, td { padding:10px; border-bottom:1px solid rgba(32,51,95,.75); text-align:left; }
    .small { font-size: 12px; }
    .domain-row td { vertical-align: top; }
    .pill {
      display:inline-block;
      padding:4px 10px;
      border-radius:999px;
      background: rgba(77,124,255,.12);
      color:#cfe0ff;
      font-size:12px;
      border:1px solid rgba(77,124,255,.22);
    }
    code {
      background: rgba(7,11,20,.55);
      border:1px solid rgba(32,51,95,.9);
      border-radius: 12px;
      padding:6px 8px;
    }
    .callout{
      margin-top:10px;
      padding:12px;
      border-radius:14px;
      background: rgba(255,204,102,.08);
      border:1px solid rgba(255,204,102,.20);
      color:#ffe7b3;
      font-size:12px;
      line-height:1.35;
    }
  </style>
</head>
<body>
  <div class="wrap">
<div class="card">
  <h1>DKIM Generator + SSH (SFTP) Uploader</h1>
  <div class="muted">
    It will always be saved to:
    <code>/root/&lt;domain&gt;/dkim.pem</code>
    (the domain folder will be created if it doesn’t already exist).
  </div>
  <div class="callout">
    ⚠️ Make sure the SSH account has permission to write inside <b>/root</b> (usually root).
  </div>
</div>


    <form method="post" action="/generate" class="card" id="mainForm">
      <h2>SSH / SFTP Settings</h2>

      <div class="row3">
        <div>
          <label>SSH Host</label>
          <input name="ssh_host" placeholder="server.example.com" value="{{ saved_form.get('ssh_host', '') }}" required>
        </div>
        <div>
          <label>Port</label>
          <input name="ssh_port" type="number" value="{{ saved_form.get('ssh_port', '22') }}" required>
        </div>
        <div>
          <label>Timeout (sec)</label>
          <input name="ssh_timeout" type="number" value="{{ saved_form.get('ssh_timeout', '20') }}" required>
        </div>
      </div>

      <div class="row">
        <div>
          <label>Username</label>
          <input name="ssh_user" value="{{ saved_form.get('ssh_user', '') }}" required>
        </div>
        <div>
          <label>Password</label>
          <input name="ssh_pass" type="password" value="{{ saved_form.get('ssh_pass', '') }}" required>
        </div>
      </div>

      <div class="btns" style="margin-top:12px;">
        <button type="button" class="secondary" onclick="checkSsh()">Check SSH Connection</button>
        <div id="sshStatus" class="muted small"></div>
      </div>

      <div class="row">
        <div>
          <label>DKIM filename</label>
          <input name="dkim_filename" value="{{ saved_form.get('dkim_filename', 'dkim.pem') }}">
        </div>
        <div>
          <label>Key size</label>
          <select name="key_size">
            <option value="2048" {% if saved_form.get('key_size', '1024') == '2048' %}selected{% endif %}>2048 (recommended)</option>
            <option value="1024" {% if saved_form.get('key_size', '1024') == '1024' %}selected{% endif %}>1024 (legacy)</option>
          </select>
        </div>
      </div>

      <hr style="border:0; border-top:1px solid rgba(32,51,95,.9); margin:16px 0;">

      <h2>Domains + DKIM Selector</h2>
      <div class="muted small">Default 5 rows. You can add more.</div>

      <table id="domainsTable">
        <thead>
          <tr>
            <th style="width:45%;">Domain</th>
            <th style="width:35%;">Selector</th>
            <th style="width:20%;">Action</th>
          </tr>
        </thead>
        <tbody id="domainsBody">
          {% for row in rows %}
          <tr class="domain-row">
            <td><input name="domain_{{loop.index0}}" placeholder="domain.com" value="{{row.domain}}"></td>
            <td><input name="selector_{{loop.index0}}" placeholder="dkim" value="{{row.selector}}"></td>
            <td><button type="button" class="danger" onclick="removeRow(this)">Remove</button></td>
          </tr>
          {% endfor %}
        </tbody>
      </table>

      <div class="btns">
        <button type="button" class="secondary" onclick="addRow()">+ Add domain</button>
        <button type="submit" class="primary">Generate + Upload</button>
      </div>

      <div class="muted small" style="margin-top:10px;">
        Output will show the DNS TXT record <span class="pill">Host (short)</span> and <span class="pill">Host (full)</span> + value with safe copy buttons.
      </div>
    </form>
  </div>

  <script>
    // ابتدينا بـ 5 صفوف، التالي سيكون index=5 => selector s6
    let rowCount = {{ rows|length }};

    function addRow() {
      const tbody = document.getElementById("domainsBody");
      const tr = document.createElement("tr");
      tr.className = "domain-row";

      // default selector: s{rowCount+1} => بعد s5 يأتي s6
      const defaultSel = `s${rowCount + 1}`;

      tr.innerHTML = `
        <td><input name="domain_${rowCount}" placeholder="example.com"></td>
        <td><input name="selector_${rowCount}" placeholder="dkim" value="${defaultSel}"></td>
        <td><button type="button" class="danger" onclick="removeRow(this)">Remove</button></td>
      `;
      tbody.appendChild(tr);
      rowCount++;
    }

    function removeRow(btn) {
      const tr = btn.closest("tr");
      if (tr) tr.remove();
    }

    async function checkSsh() {
      const status = document.getElementById("sshStatus");
      status.textContent = "Checking...";
      status.style.color = "#a9b6d6";

      const fd = new FormData();
      fd.append("ssh_host", document.querySelector('[name="ssh_host"]').value || "");
      fd.append("ssh_port", document.querySelector('[name="ssh_port"]').value || "22");
      fd.append("ssh_timeout", document.querySelector('[name="ssh_timeout"]').value || "20");
      fd.append("ssh_user", document.querySelector('[name="ssh_user"]').value || "");
      fd.append("ssh_pass", document.querySelector('[name="ssh_pass"]').value || "");

      try {
        const res = await fetch("/check_ssh", { method: "POST", body: fd });
        const data = await res.json();

        status.textContent = data.message || (data.ok ? "Connected" : "Failed");
        status.style.color = data.ok ? "#45ff9d" : "#ff5b6b";
      } catch (e) {
        status.textContent = "❌ Error checking connection.";
        status.style.color = "#ff5b6b";
      }
    }
  </script>
</body>
</html>
"""

RESULT_HTML = r"""
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>DKIM Results</title>
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <style>
    :root{
      --bg0:#070b14;
      --bg1:#0b1220;
      --card:#0f1b34;
      --card2:#0c1730;
      --stroke:#20335f;
      --stroke2:#2a3f73;
      --text:#eaf1ff;
      --muted:#a9b6d6;
      --accent:#4d7cff;
      --accent2:#7aa3ff;
      --ok:#45ff9d;
      --bad:#ff5b6b;
      --warn:#ffcc66;
      --shadow: 0 18px 55px rgba(0,0,0,.35);
      --r:16px;
    }
    *{box-sizing:border-box}
    body{
      font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif;
      background:
        radial-gradient(900px 500px at 15% 0%, rgba(77,124,255,.18), transparent 55%),
        radial-gradient(900px 500px at 90% 15%, rgba(69,255,157,.10), transparent 55%),
        linear-gradient(180deg, var(--bg0), var(--bg1));
      color:var(--text);
      margin:0;
      min-height:100vh;
    }
    .wrap { max-width: 1120px; margin: 0 auto; padding: 24px; }
    .card {
      background: linear-gradient(180deg, rgba(255,255,255,.04), transparent 35%), var(--card);
      border:1px solid var(--stroke);
      border-radius:var(--r);
      padding:16px;
      margin: 14px 0;
      box-shadow: var(--shadow);
    }
    h1 { margin: 0 0 10px; font-size: 22px; letter-spacing:.2px; }
    .muted { color:var(--muted); font-size: 13px; line-height:1.35; }
    .ok { color: var(--ok); font-weight: 900; }
    .bad { color: var(--bad); font-weight: 900; }

    .item {
      padding: 14px;
      border:1px solid rgba(32,51,95,.9);
      border-radius: 18px;
      margin: 12px 0;
      background: linear-gradient(180deg, rgba(255,255,255,.03), transparent 40%), var(--card2);
      box-shadow: 0 14px 45px rgba(0,0,0,.25);
    }

    .kv { margin: 6px 0; }
    .meta code.inline{
      display:inline-block;
      padding:4px 10px;
      border-radius:999px;
      border:1px solid rgba(42,63,115,.9);
      background: rgba(7,11,20,.5);
      color:#dbe6ff;
      font-size:12px;
    }

    .grid2{
      display:grid;
      grid-template-columns: 1fr 1fr;
      gap:12px;
      align-items:start;
    }
    @media (max-width: 820px){
      .grid2{ grid-template-columns:1fr; }
    }

    .field{
      border:1px solid rgba(42,63,115,.9);
      border-radius:16px;
      overflow:hidden;
      background: rgba(7,11,20,.35);
    }
    .fieldHead{
      display:flex;
      justify-content:space-between;
      align-items:center;
      gap:10px;
      padding:10px 12px;
      background: rgba(255,255,255,.03);
      border-bottom:1px solid rgba(42,63,115,.7);
    }
    .fieldHead b{
      font-size:12px;
      letter-spacing:.7px;
      text-transform:uppercase;
      color:#d4e1ff;
    }
    .badge{
      display:inline-flex;
      align-items:center;
      gap:6px;
      padding:4px 10px;
      border-radius:999px;
      font-size:12px;
      border:1px solid rgba(42,63,115,.9);
      background: rgba(77,124,255,.10);
      color:#cfe0ff;
      white-space:nowrap;
    }
    pre{
      margin:0;
      padding:12px;
      background: transparent;
      color: var(--text);
      overflow:auto;
      white-space: pre-wrap;
      word-break: break-word;
      font-size: 12.5px;
      line-height: 1.45;
    }

    .btnRow{
      display:flex;
      gap:10px;
      flex-wrap:wrap;
      padding:10px 12px 12px;
      border-top:1px solid rgba(42,63,115,.7);
      background: rgba(255,255,255,.02);
    }

    button {
      border:0;
      border-radius: 12px;
      padding: 10px 14px;
      cursor:pointer;
      font-weight: 900;
      letter-spacing:.2px;
      transition:.15s transform, .15s filter, .15s opacity;
      user-select:none;
    }
    button:hover{ transform: translateY(-1px); filter: brightness(1.05); }
    button:active{ transform: translateY(0px) scale(.99); }
    .primary { background: linear-gradient(180deg, var(--accent2), var(--accent)); color:white; }
    .secondary { background: rgba(255,255,255,.04); color:var(--text); border:1px solid rgba(42,63,115,.9); }
    a { color:#9cc3ff; text-decoration:none; }

    .hint{
      margin-top:10px;
      padding:12px;
      border-radius:16px;
      background: rgba(255,204,102,.08);
      border:1px solid rgba(255,204,102,.20);
      color:#ffe7b3;
      font-size:12px;
      line-height:1.35;
    }

    /* Toast */
    .toastWrap{
      position: fixed;
      right: 16px;
      bottom: 16px;
      display:flex;
      flex-direction:column;
      gap:10px;
      z-index: 9999;
      pointer-events:none;
    }
    .toast{
      pointer-events:auto;
      min-width: 240px;
      max-width: 360px;
      padding: 12px 14px;
      border-radius: 14px;
      border:1px solid rgba(42,63,115,.9);
      background: rgba(15,27,52,.92);
      box-shadow: 0 18px 55px rgba(0,0,0,.45);
      backdrop-filter: blur(10px);
      transform: translateY(10px);
      opacity: 0;
      animation: toastIn .18s ease-out forwards;
      display:flex;
      gap:10px;
      align-items:flex-start;
    }
    .toast .tIcon{
      width: 10px; height: 10px; border-radius: 999px; margin-top: 5px; flex: 0 0 auto;
      background: rgba(122,163,255,.95);
      box-shadow: 0 0 0 4px rgba(77,124,255,.14);
    }
    .toast.ok .tIcon{ background: rgba(69,255,157,.95); box-shadow: 0 0 0 4px rgba(69,255,157,.14); }
    .toast.bad .tIcon{ background: rgba(255,91,107,.95); box-shadow: 0 0 0 4px rgba(255,91,107,.14); }
    .toast b{ font-size: 13px; color:#dbe6ff; }
    .toast div{ font-size: 12px; color: var(--muted); line-height: 1.3; }
    @keyframes toastIn{
      to{ transform: translateY(0); opacity: 1; }
    }
    @keyframes toastOut{
      to{ transform: translateY(10px); opacity: 0; }
    }
  </style>
</head>
<body>
  <div class="wrap">
    <div class="card">
      <h1>DKIM Results</h1>
      <div class="muted">
        Private keys uploaded via SSH/SFTP. Copy the TXT record(s) below into your DNS provider.
      </div>

<div class="hint">
  ✅ <b>Important (Host format):</b><br>
  Some DNS panels require <b>Host only</b>, for example: <code>dkim._domainkey</code><br>
  Others require the <b>full name</b>, for example: <code>dkim._domainkey.domain.com</code><br>
  ⚠️ <b>Do not create two records</b> — just choose the version that matches your DNS panel.
</div>


      <div style="margin-top:12px;">
        <a class="secondary" href="/" style="display:inline-block; padding:10px 14px; border-radius:12px;">← Back</a>
      </div>
    </div>

    <div class="card">
      <div class="muted"><b>SSH summary:</b> {{ssh_summary}}</div>
      <div class="muted"><b>Remote base:</b> /root</div>
    </div>

    {% for r in results %}
      <div class="item">
        <div style="display:flex; justify-content:space-between; gap:12px; flex-wrap:wrap;">
          <div class="meta">
            <div class="kv"><b>Domain:</b> <a href="https://{{r.domain}}" target="_blank">{{r.domain}}</a></div>
            <div class="kv"><b>Selector:</b> <code class="inline">{{r.selector}}</code></div>
            <div class="kv"><b>Private key path:</b> <code class="inline">{{r.remote_path}}</code></div>
          </div>
          <div style="min-width:200px; text-align:right;">
            {% if r.ok %}
              <div class="ok">✅ Uploaded</div>
            {% else %}
              <div class="bad">❌ Failed</div>
              <div class="muted" style="margin-top:6px;">{{r.error}}</div>
            {% endif %}
          </div>
        </div>

        <hr style="border:0; border-top:1px solid rgba(32,51,95,.85); margin:12px 0;">

        <div class="grid2">
          <!-- Host short -->
          <div class="field">
            <div class="fieldHead">
              <b>TXT Host (Short)</b>
              <span class="badge">Example: dkim._domainkey</span>
            </div>
            <pre id="host_short_{{loop.index}}">{{r.record_host_short}}</pre>
            <div class="btnRow">
              <button class="secondary" onclick="copyText('host_short_{{loop.index}}','Host (short) copied ✅','ok')">Copy Host (Short)</button>
            </div>
          </div>

          <!-- Host full -->
          <div class="field">
            <div class="fieldHead">
              <b>TXT Host (Full)</b>
              <span class="badge">Example: dkim._domainkey.domain</span>
            </div>
            <pre id="host_full_{{loop.index}}">{{r.record_host_full}}</pre>
            <div class="btnRow">
              <button class="secondary" onclick="copyText('host_full_{{loop.index}}','Host (full) copied ✅','ok')">Copy Host (Full)</button>
            </div>
          </div>

          <!-- Value -->
          <div class="field" style="grid-column: 1 / -1;">
            <div class="fieldHead">
              <b>TXT Value</b>
              <span class="badge">v=DKIM1; k=rsa; p=...</span>
            </div>
            <pre id="val_{{loop.index}}">{{r.record_value}}</pre>
            <div class="btnRow">
              <button class="primary" onclick="copyText('val_{{loop.index}}','Value copied ✅','ok')">Copy Value</button>
            </div>
          </div>

          <!-- Split -->
          <div class="field" style="grid-column: 1 / -1;">
            <div class="fieldHead">
              <b>Split Value (If DNS rejects long)</b>
              <span class="badge" style="background: rgba(255,204,102,.10); color:#ffe7b3; border-color: rgba(255,204,102,.25);">Use only if needed</span>
            </div>
            <pre id="split_{{loop.index}}">{{r.record_value_split}}</pre>
            <div class="btnRow">
              <button class="secondary" onclick="copyText('split_{{loop.index}}','Split value copied ✅','ok')">Copy Split Value</button>
              <span class="muted" style="font-size:12px;">
                (Still ONE TXT record — just split into quoted chunks)
              </span>
            </div>
          </div>
        </div>
      </div>
    {% endfor %}
  </div>

  <div class="toastWrap" id="toastWrap" aria-live="polite" aria-atomic="true"></div>

  <script>
    function showToast(title, body, type="ok"){
      const wrap = document.getElementById("toastWrap");
      const t = document.createElement("div");
      t.className = `toast ${type}`;
      t.innerHTML = `
        <span class="tIcon"></span>
        <div>
          <b>${escapeHtml(title)}</b>
          ${body ? `<div>${escapeHtml(body)}</div>` : ``}
        </div>
      `;
      wrap.appendChild(t);

      // Auto remove
      const ttl = 2200;
      setTimeout(() => {
        t.style.animation = "toastOut .18s ease-in forwards";
        setTimeout(() => t.remove(), 220);
      }, ttl);
    }

    function escapeHtml(str){
      return String(str || "")
        .replaceAll("&","&amp;")
        .replaceAll("<","&lt;")
        .replaceAll(">","&gt;")
        .replaceAll('"',"&quot;")
        .replaceAll("'","&#039;");
    }

    async function copyText(id, toastTitle="Copied!", type="ok") {
      const el = document.getElementById(id);
      let text = el ? (el.textContent || "") : "";
      // avoid accidental extra newlines/spaces from <pre>
      text = text.replace(/\s+$/g, "");

      if (!text) {
        showToast("Nothing to copy", "The field is empty.", "bad");
        return;
      }

      try {
        await navigator.clipboard.writeText(text);
        showToast(toastTitle, "", type);
      } catch (e) {
        try {
          const ta = document.createElement("textarea");
          ta.value = text;
          ta.style.position = "fixed";
          ta.style.opacity = "0";
          document.body.appendChild(ta);
          ta.focus();
          ta.select();
          document.execCommand("copy");
          ta.remove();
          showToast(toastTitle, "Used fallback copy.", type);
        } catch (e2) {
          showToast("Copy failed", "Your browser blocked clipboard.", "bad");
        }
      }
    }
  </script>
</body>
</html>
"""


# -----------------------------
# Routes
# -----------------------------
@app.get("/")
def index():
    saved_form = {
        "ssh_host": get_cookie_value("ssh_host"),
        "ssh_port": get_cookie_value("ssh_port", "22"),
        "ssh_timeout": get_cookie_value("ssh_timeout", "20"),
        "ssh_user": get_cookie_value("ssh_user"),
        "ssh_pass": get_cookie_value("ssh_pass"),
        "dkim_filename": get_cookie_value("dkim_filename", "dkim.pem"),
        "key_size": get_cookie_value("key_size", "1024"),
    }
    rows = get_cookie_rows()
    return render_template_string(INDEX_HTML, saved_form=saved_form, rows=rows)


@app.post("/check_ssh")
def check_ssh():
    ssh_host = request.form.get("ssh_host", "").strip()
    ssh_user = request.form.get("ssh_user", "").strip()
    ssh_pass = request.form.get("ssh_pass", "")

    try:
        ssh_port = int((request.form.get("ssh_port", "22") or "22").strip())
    except Exception:
        ssh_port = 22

    try:
        ssh_timeout = int((request.form.get("ssh_timeout", "20") or "20").strip())
    except Exception:
        ssh_timeout = 20

    if not ssh_host or not ssh_user:
        return jsonify({"ok": False, "message": "Missing SSH host or username."}), 400

    client = None
    sftp = None
    try:
        client, sftp = ssh_connect_sftp(ssh_host, ssh_port, ssh_user, ssh_pass, timeout=ssh_timeout)
        _ = sftp.listdir(".")
        return jsonify({"ok": True, "message": f"✅ Connected to {ssh_host}:{ssh_port} (SFTP)"}), 200
    except Exception as e:
        return jsonify({"ok": False, "message": f"❌ Connection failed: {str(e)}"}), 200
    finally:
        try:
            if sftp:
                sftp.close()
        except Exception:
            pass
        try:
            if client:
                client.close()
        except Exception:
            pass


@app.post("/generate")
def generate():
    ssh_host = request.form.get("ssh_host", "").strip()
    ssh_user = request.form.get("ssh_user", "").strip()
    ssh_pass = request.form.get("ssh_pass", "")

    try:
        ssh_port = int((request.form.get("ssh_port", "22") or "22").strip())
    except Exception:
        ssh_port = 22

    try:
        ssh_timeout = int((request.form.get("ssh_timeout", "20") or "20").strip())
    except Exception:
        ssh_timeout = 20

    dkim_filename = (request.form.get("dkim_filename", "dkim.pem") or "dkim.pem").strip()
    key_size_raw = (request.form.get("key_size", "2048") or "2048").strip()
    key_size = int(key_size_raw)

    raw_pairs: List[Tuple[str, str]] = []
    for k, v in request.form.items():
        if k.startswith("domain_"):
            idx = k.split("_", 1)[1]
            domain = (v or "").strip().lower()
            selector = (request.form.get(f"selector_{idx}", "") or "").strip()
            if domain or selector:
                raw_pairs.append((domain, selector))

    cleaned: List[Tuple[str, str]] = []
    for d, s in raw_pairs:
        if d.strip() and s.strip():
            cleaned.append((d.strip().lower(), s.strip()))
    pairs = cleaned

    results: List[ResultItem] = []
    ssh_summary = ""

    if not ssh_host or not ssh_user:
        ssh_summary = "Missing SSH host/username."
        response = make_response(render_template_string(RESULT_HTML, results=[], ssh_summary=ssh_summary))
        response.set_cookie("ssh_host", ssh_host, max_age=60 * 60 * 24 * 30)
        response.set_cookie("ssh_port", str(ssh_port), max_age=60 * 60 * 24 * 30)
        response.set_cookie("ssh_timeout", str(ssh_timeout), max_age=60 * 60 * 24 * 30)
        response.set_cookie("ssh_user", ssh_user, max_age=60 * 60 * 24 * 30)
        response.set_cookie("ssh_pass", ssh_pass, max_age=60 * 60 * 24 * 30)
        response.set_cookie("dkim_filename", dkim_filename, max_age=60 * 60 * 24 * 30)
        response.set_cookie("key_size", key_size_raw, max_age=60 * 60 * 24 * 30)
        response.set_cookie("row_count", str(max(len(raw_pairs), 5)), max_age=60 * 60 * 24 * 30)
        for i in range(max(len(raw_pairs), 5)):
            domain_value = raw_pairs[i][0] if i < len(raw_pairs) else ""
            selector_value = raw_pairs[i][1] if i < len(raw_pairs) else ("dkim" if i == 0 else f"s{i + 1}")
            response.set_cookie(f"domain_{i}", domain_value, max_age=60 * 60 * 24 * 30)
            response.set_cookie(f"selector_{i}", selector_value, max_age=60 * 60 * 24 * 30)
        return response

    client = None
    sftp = None
    try:
        client, sftp = ssh_connect_sftp(ssh_host, ssh_port, ssh_user, ssh_pass, timeout=ssh_timeout)
        ssh_summary = f"Connected to {ssh_host}:{ssh_port} (SFTP)."

        for domain, selector in pairs:
            try:
                if not is_valid_domain(domain):
                    raise ValueError(f"Invalid domain format: {domain}")
                if not is_valid_selector(selector):
                    raise ValueError(f"Invalid selector format: {selector}")

                private_pem, public_b64 = generate_dkim_keypair_local(key_size=key_size)

                remote_dir = posixpath.join(REMOTE_BASE_DIR.rstrip("/"), domain)
                remote_path = posixpath.join(remote_dir, dkim_filename)

                sftp_upload_bytes(sftp, remote_path, private_pem)

                record_host_short = f"{selector}._domainkey"
                record_host_full = f"{selector}._domainkey.{domain}"

                record_value = f"v=DKIM1; k=rsa; p={public_b64}"
                record_value_split = split_for_dns(record_value, chunk=200)

                results.append(ResultItem(
                    domain=domain,
                    selector=selector,
                    remote_path=remote_path,
                    record_host_short=record_host_short,
                    record_host_full=record_host_full,
                    record_value=record_value,
                    record_value_split=record_value_split,
                    ok=True
                ))
            except Exception as e:
                record_host_short = f"{selector}._domainkey" if selector else ""
                record_host_full = f"{selector}._domainkey.{domain}" if domain and selector else ""
                results.append(ResultItem(
                    domain=domain or "(empty)",
                    selector=selector or "(empty)",
                    remote_path="",
                    record_host_short=record_host_short,
                    record_host_full=record_host_full,
                    record_value="",
                    record_value_split="",
                    ok=False,
                    error=str(e)
                ))
    except Exception as e:
        ssh_summary = f"SSH connection failed: {e}"
        results = []
    finally:
        try:
            if sftp:
                sftp.close()
        except Exception:
            pass
        try:
            if client:
                client.close()
        except Exception:
            pass

    response = make_response(render_template_string(RESULT_HTML, results=results, ssh_summary=ssh_summary))
    response.set_cookie("ssh_host", ssh_host, max_age=60 * 60 * 24 * 30)
    response.set_cookie("ssh_port", str(ssh_port), max_age=60 * 60 * 24 * 30)
    response.set_cookie("ssh_timeout", str(ssh_timeout), max_age=60 * 60 * 24 * 30)
    response.set_cookie("ssh_user", ssh_user, max_age=60 * 60 * 24 * 30)
    response.set_cookie("ssh_pass", ssh_pass, max_age=60 * 60 * 24 * 30)
    response.set_cookie("dkim_filename", dkim_filename, max_age=60 * 60 * 24 * 30)
    response.set_cookie("key_size", key_size_raw, max_age=60 * 60 * 24 * 30)
    response.set_cookie("row_count", str(max(len(raw_pairs), 5)), max_age=60 * 60 * 24 * 30)
    for i in range(max(len(raw_pairs), 5)):
        domain_value = raw_pairs[i][0] if i < len(raw_pairs) else ""
        selector_value = raw_pairs[i][1] if i < len(raw_pairs) else ("dkim" if i == 0 else f"s{i + 1}")
        response.set_cookie(f"domain_{i}", domain_value, max_age=60 * 60 * 24 * 30)
        response.set_cookie(f"selector_{i}", selector_value, max_age=60 * 60 * 24 * 30)
    return response


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5002, debug=True)
