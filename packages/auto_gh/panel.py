"""panel.py — Zero-dependency dark-themed Web Panel & REST API for auto-gh."""
from __future__ import annotations

import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import time
from urllib.parse import parse_qs, urlparse

from .browser_profile import save_github_cookie_state
from .bundle import SessionBundle, load_dotenv_file
from .dns_doctor import ResolverFn, audit_domain_pool, doh_resolve
from .mailbox import get_mailbox_driver
from .netpool import StickyPortPool
from .store import DEFAULT_DB, log_event, open_db, summary_counts, utcnow

PANEL_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>auto-gh · Control Panel</title>
<style>
  :root {
    --bg: #08090a;
    --card: #131416;
    --border: rgba(255,255,255,0.08);
    --fg: #f3f4f6;
    --muted: #9ca3af;
    --accent: #5e6ad2;
    --accent-hover: #7170ff;
    --ok: #10b981;
    --warn: #f59e0b;
    --bad: #ef4444;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0;
    background: var(--bg);
    color: var(--fg);
    font-family: Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    font-size: 14px;
    line-height: 1.5;
  }
  .wrap { max-width: 1320px; margin: 0 auto; padding: 24px; }
  header {
    display: flex; align-items: center; justify-content: space-between;
    border-bottom: 1px solid var(--border); padding-bottom: 16px; margin-bottom: 24px;
  }
  h1 { font-size: 20px; font-weight: 600; margin: 0; letter-spacing: -0.02em; }
  h2 { font-size: 15px; font-weight: 600; margin: 0 0 12px 0; }
  .pill {
    display: inline-block; padding: 2px 8px; border-radius: 999px;
    font-size: 12px; font-weight: 500; font-variant-numeric: tabular-nums;
  }
  .pill-ok { background: rgba(16,185,129,0.15); color: var(--ok); }
  .pill-warn { background: rgba(245,158,11,0.15); color: var(--warn); }
  .pill-bad { background: rgba(239,68,68,0.15); color: var(--bad); }
  .grid-kpi {
    display: grid; grid-template-columns: repeat(auto-fit, minmax(210px, 1fr));
    gap: 14px; margin-bottom: 24px;
  }
  .card {
    background: var(--card); border: 1px solid var(--border);
    border-radius: 8px; padding: 16px; margin-bottom: 20px;
  }
  .kpi-label { color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: 0.04em; }
  .kpi-val { font-size: 26px; font-weight: 600; margin-top: 4px; font-variant-numeric: tabular-nums; }
  .controls { display: flex; flex-wrap: wrap; gap: 10px; align-items: center; }
  input, select, button {
    background: #0f1011; color: var(--fg); border: 1px solid var(--border);
    border-radius: 6px; padding: 7px 12px; font-size: 13px;
  }
  button {
    background: var(--accent); border-color: transparent; cursor: pointer; font-weight: 500;
  }
  button:hover { background: var(--accent-hover); }
  button.sec { background: #1c1d21; border: 1px solid var(--border); }
  button.sec:hover { background: #27282d; }
  table { width: 100%; border-collapse: collapse; font-variant-numeric: tabular-nums; }
  th, td {
    text-align: left; padding: 10px 8px; border-bottom: 1px solid var(--border);
    font-size: 13px;
  }
  th { color: var(--muted); font-weight: 500; font-size: 12px; }
  code {
    font-family: "JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, monospace;
    font-size: 12px; background: rgba(255,255,255,0.05); padding: 2px 6px; border-radius: 4px;
  }
  .alert {
    border: 1px solid rgba(245,158,11,0.4); background: rgba(245,158,11,0.08);
    color: #fcd34d; padding: 12px; border-radius: 6px; margin-bottom: 14px; font-size: 13px;
  }
</style>
</head>
<body>
<div class="wrap">
  <header>
    <div>
      <h1>auto-gh · Identity &amp; Aging Control Panel</h1>
      <div style="color:var(--muted);font-size:12px;">Standalone GitHub Session Lifecycle · 5h CBAI Aging Queue · Read-Only DNS Doctor</div>
    </div>
    <div class="controls">
      <button class="sec" onclick="refreshAll()">Refresh</button>
      <button onclick="runDnsDoctor()">Audit Domain Legitimacy</button>
    </div>
  </header>

  <div class="grid-kpi">
    <div class="card"><div class="kpi-label">Total Accounts</div><div class="kpi-val" id="k-total">0</div></div>
    <div class="card"><div class="kpi-label">Unique Exit IPs</div><div class="kpi-val" id="k-ips">0</div></div>
    <div class="card"><div class="kpi-label">Verified (Kiro T+0 Ready)</div><div class="kpi-val" id="k-verified">0</div></div>
    <div class="card"><div class="kpi-label">CBAI Aged Ready (&ge;5h05m)</div><div class="kpi-val" id="k-cbai">0</div></div>
  </div>

  <div class="card">
    <h2>Stage New Account Batch</h2>
    <div class="controls">
      <label>Count <input type="number" id="st-count" value="4" min="1" max="50" style="width:70px"></label>
      <label>Mailbox
        <select id="st-mode">
          <option value="mailcx">Mail.cx Disposable (uqu.me / ddker.com / 9k3r.com)</option>
          <option value="gmail_dot">Gmail Dot-Trick IMAP (GMAIL_ADDRESS)</option>
          <option value="catchall">Catch-All Custom Domains (Round-Robin)</option>
          <option value="rest">REST Dedicated Inbox</option>
        </select>
      </label>
      <label>Region
        <select id="st-cc">
          <option value="">Auto Rotate APAC (sg/id/jp/th/my/ph/hk)</option>
          <option value="sg">Singapore (sg)</option>
          <option value="id">Indonesia (id)</option>
          <option value="jp">Japan (jp)</option>
          <option value="th">Thailand (th)</option>
          <option value="my">Malaysia (my)</option>
        </select>
      </label>
      <label><input type="checkbox" id="st-probe" checked> Live Probe Exit IP</label>
      <button onclick="stageBatch()" id="btn-stage">Stage Batch</button>
    </div>
  </div>

  <div class="card">
    <h2>Accounts &amp; 5-Hour Aging Queue</h2>
    <pre id="pair-output" style="display:none;background:#0f1011;border:1px solid var(--border);padding:12px;border-radius:6px;overflow-x:auto;font-size:12px;margin-bottom:14px;"></pre>
    <div style="overflow-x:auto;">
      <table>
        <thead>
          <tr>
            <th>ID</th>
            <th>Username</th>
            <th>Email (Domain)</th>
            <th>Sticky Port / CC</th>
            <th>Exit IP / Timezone</th>
            <th>Status</th>
            <th>Age / CBAI 305m Gate</th>
            <th>Actions &amp; Unix Pipe</th>
          </tr>
        </thead>
        <tbody id="tb-accounts"></tbody>
      </table>
    </div>
  </div>

  <div class="card">
    <h2>Domain Legitimacy Doctor (Read-Only DoH Audit)</h2>
    <div id="dns-alert" style="display:none;" class="alert"></div>
    <div style="overflow-x:auto;">
      <table>
        <thead>
          <tr>
            <th>Domain</th>
            <th>Score</th>
            <th>A Record</th>
            <th>MX Record</th>
            <th>SPF</th>
            <th>DMARC</th>
            <th>Public TXT Forward Leak</th>
            <th>Warnings</th>
          </tr>
        </thead>
        <tbody id="tb-dns">
          <tr><td colspan="8" style="color:var(--muted);">Click "Audit Domain Legitimacy" to inspect DNS records.</td></tr>
        </tbody>
      </table>
    </div>
  </div>
</div>

<script>
async function refreshAll() {
  const [stRes, accRes] = await Promise.all([fetch('/api/status'), fetch('/api/accounts')]);
  const st = await stRes.json();
  const acc = await accRes.json();
  document.getElementById('k-total').textContent = st.total_accounts || 0;
  document.getElementById('k-ips').textContent = st.unique_exit_ips || 0;
  document.getElementById('k-verified').textContent = (st.by_status && st.by_status.verified) || 0;
  document.getElementById('k-cbai').textContent = st.aged_ready_for_cbai || 0;

  const tb = document.getElementById('tb-accounts');
  tb.innerHTML = '';
  for (const a of (acc.accounts || [])) {
    const tr = document.createElement('tr');
    const pillCls = a.cbai_ready ? 'pill-ok' : (a.status === 'verified' ? 'pill-warn' : 'pill-bad');
    const ageLabel = a.status === 'verified'
      ? (a.cbai_ready ? `READY (${a.age_minutes}m)` : `${a.age_minutes}m / 305m (${a.remaining_cbai_minutes}m left)`)
      : 'Not verified';
    tr.innerHTML = `
      <td>#${a.id}</td>
      <td><code>${a.username}</code></td>
      <td><code>${a.email}</code></td>
      <td><code>:${a.proxy_port}</code> (${a.proxy_country})</td>
      <td><code>${a.exit_ip || '-'}</code> <span style="color:var(--muted)">${a.timezone || ''}</span></td>
      <td><span class="pill ${pillCls}">${a.status}</span></td>
      <td>${ageLabel}</td>
      <td class="controls">
        ${a.status !== 'verified' ? `<button onclick="runSignupNow(${a.id})">Run Signup</button>` : ''}
        <button class="sec" onclick="pollOtpNow(${a.id})">Poll OTP</button>
        <button class="sec" onclick="checkProfileNow(${a.id})">Check GH Age</button>
        <button class="sec" onclick="setCookieNow(${a.id})">${a.storage_state ? 'Update Cookie' : 'Set Cookie'}</button>
        ${a.status !== 'verified' ? `<button class="sec" onclick="markStatus(${a.id}, 'verified')">Mark Verified</button>` : ''}
        <button onclick="pairNow(${a.id}, 'kiro', ${Boolean(a.storage_state)})">Pair Kiro Now</button>
        <button onclick="pairNow(${a.id}, 'cbai', ${Boolean(a.storage_state)})">Pair CBAI Now</button>
      </td>
    `;
    tb.appendChild(tr);
  }
}

async function runSignupNow(id) {
  const out = document.getElementById('pair-output');
  out.style.display = 'block';
  out.textContent = `Running automated Camoufox GitHub signup + OTP poll for account #${id} (takes ~35-90s)...`;
  const res = await fetch('/api/signup', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({account_id: id})
  });
  const data = await res.json();
  out.textContent = JSON.stringify(data, null, 2);
  await refreshAll();
}

async function setCookieNow(id) {
  const val = prompt(`Paste GitHub user_session cookie, Cookie header, or storage_state JSON for account #${id}:`);
  if (!val) return;
  const out = document.getElementById('pair-output');
  out.style.display = 'block';
  out.textContent = `Saving GitHub session state for account #${id}...`;
  const res = await fetch('/api/import-cookie', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({account_id: id, cookie: val})
  });
  const data = await res.json();
  out.textContent = JSON.stringify(data, null, 2);
  await refreshAll();
}

async function pollOtpNow(id) {
  const out = document.getElementById('pair-output');
  out.style.display = 'block';
  out.textContent = `Polling BYOP mailbox for account #${id} OTP...`;
  const res = await fetch('/api/inbox-poll', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({account_id: id, timeout: 8})
  });
  const data = await res.json();
  out.textContent = JSON.stringify(data, null, 2);
}

async function checkProfileNow(id) {
  const out = document.getElementById('pair-output');
  out.style.display = 'block';
  out.textContent = `Checking GitHub profile & created_at age for account #${id}...`;
  const res = await fetch('/api/session-check', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({account_id: id})
  });
  const data = await res.json();
  out.textContent = JSON.stringify(data, null, 2);
  await refreshAll();
}

async function pairNow(id, target, execute=false) {
  const out = document.getElementById('pair-output');
  out.style.display = 'block';
  out.textContent = `Running ${target} pairing pipe (execute=${execute}) for account #${id}...`;
  const res = await fetch('/api/pair', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({account_id: id, target, execute})
  });
  const data = await res.json();
  out.textContent = JSON.stringify(data, null, 2);
}

async function stageBatch() {
  const btn = document.getElementById('btn-stage');
  btn.disabled = true;
  btn.textContent = 'Staging...';
  try {
    await fetch('/api/stage', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({
        count: Number(document.getElementById('st-count').value || 4),
        mode: document.getElementById('st-mode').value,
        country: document.getElementById('st-cc').value,
        probe_proxy: document.getElementById('st-probe').checked
      })
    });
    await refreshAll();
  } finally {
    btn.disabled = false;
    btn.textContent = 'Stage Batch';
  }
}

async function markStatus(id, status) {
  await fetch('/api/accounts/status', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({account_id: id, status})
  });
  await refreshAll();
}

async function runDnsDoctor() {
  const tb = document.getElementById('tb-dns');
  tb.innerHTML = '<tr><td colspan="8">Auditing domains via DoH...</td></tr>';
  const res = await fetch('/api/dns-doctor');
  const data = await res.json();
  const alertEl = document.getElementById('dns-alert');
  const shared = data.shared_forward_targets || {};
  const sharedKeys = Object.keys(shared);
  if (sharedKeys.length > 0) {
    alertEl.style.display = 'block';
    alertEl.textContent = 'CROSS-DOMAIN CORRELATION DETECTED: Multiple domains publish the same public TXT forward-email target (' + sharedKeys.join(', ') + '). Isolate each domain to a unique inbox or switch to non-TXT routing.';
  } else {
    alertEl.style.display = 'none';
  }
  tb.innerHTML = '';
  for (const d of (data.domains || [])) {
    const tr = document.createElement('tr');
    const sCls = d.score >= 80 ? 'pill-ok' : (d.score >= 50 ? 'pill-warn' : 'pill-bad');
    tr.innerHTML = `
      <td><code>${d.fqdn}</code></td>
      <td><span class="pill ${sCls}">${d.score}/100</span></td>
      <td>${d.has_a ? 'OK' : 'MISSING'}</td>
      <td>${d.has_mx ? 'OK' : 'MISSING'}</td>
      <td>${d.has_spf ? 'OK' : 'MISSING'}</td>
      <td>${d.has_dmarc ? 'OK' : 'MISSING'}</td>
      <td><code>${(d.forward_targets || []).join(', ') || 'None'}</code></td>
      <td><code>${(d.warnings || []).join(', ') || 'clean'}</code></td>
    `;
    tb.appendChild(tr);
  }
}

function copyCmd(cmd) {
  navigator.clipboard.writeText(cmd);
}

refreshAll();
</script>
</body>
</html>
"""


def _compute_account_row(row: dict) -> dict:
    d = dict(row)
    age_min = 0
    ver_at = d.get("verified_at")
    if ver_at:
        try:
            dt = datetime.datetime.strptime(ver_at, "%Y-%m-%dT%H:%M:%SZ").replace(
                tzinfo=datetime.timezone.utc
            )
            age_min = max(0, int((datetime.datetime.now(datetime.timezone.utc) - dt).total_seconds() // 60))
        except Exception:
            age_min = 0
    d["age_minutes"] = age_min
    d["remaining_cbai_minutes"] = max(0, 305 - age_min) if d.get("status") == "verified" else 305
    d["kiro_ready"] = d.get("status") == "verified" and not d.get("kiro_paired_at")
    d["cbai_ready"] = d.get("status") == "verified" and age_min >= 305 and not d.get("cbai_paired_at")
    return d


def handle_api_request(
    method: str,
    path: str,
    query: dict[str, list[str]] | None = None,
    body: bytes | str | None = None,
    db_path: str | Path = DEFAULT_DB,
    resolver: ResolverFn = doh_resolve,
) -> tuple[int, str, str]:
    """Pure request dispatcher for the panel (returns status_code, content_type, body_str)."""
    load_dotenv_file()
    con = open_db(db_path)
    try:
        if method == "GET" and path in ("/", "/index.html"):
            return 200, "text/html; charset=utf-8", PANEL_HTML

        if method == "GET" and path == "/api/status":
            return 200, "application/json", json.dumps(summary_counts(con))

        if method == "GET" and path == "/api/accounts":
            rows = [
                _compute_account_row(dict(r))
                for r in con.execute(
                    "SELECT id, seed, username, email, email_provider, proxy_port, "
                    "proxy_country, exit_ip, timezone, locale, status, created_at, "
                    "verified_at, cbai_paired_at, kiro_paired_at FROM accounts ORDER BY id DESC"
                ).fetchall()
            ]
            return 200, "application/json", json.dumps({"accounts": rows})

        if method == "GET" and path == "/api/dns-doctor":
            report = audit_domain_pool(resolver=resolver)
            return 200, "application/json", json.dumps(report)

        if method == "POST" and path == "/api/accounts/status":
            payload = json.loads(body.decode("utf-8") if isinstance(body, bytes) else (body or "{}"))
            acc_id = int(payload["account_id"])
            new_status = str(payload.get("status", "verified"))
            now = utcnow()
            if new_status == "verified":
                con.execute(
                    "UPDATE accounts SET status = 'verified', verified_at = COALESCE(verified_at, ?) WHERE id = ?",
                    (now, acc_id),
                )
            else:
                con.execute("UPDATE accounts SET status = ? WHERE id = ?", (new_status, acc_id))
            con.commit()
            log_event(con, acc_id, f"status_{new_status}", "updated via panel")
            return 200, "application/json", json.dumps({"ok": True, "account_id": acc_id, "status": new_status})

        if method == "POST" and path == "/api/stage":
            payload = json.loads(body.decode("utf-8") if isinstance(body, bytes) else (body or "{}"))
            count = max(1, min(int(payload.get("count", 4)), 50))
            mode = str(payload.get("mode", "catchall"))
            country = str(payload.get("country", ""))
            probe = bool(payload.get("probe_proxy", False))
            ttl = int(payload.get("ttl", 30))

            pool = StickyPortPool()
            mb = get_mailbox_driver(mode)
            existing_count = con.execute("SELECT COUNT(*) FROM accounts").fetchone()[0]
            staged = []
            for i in range(count):
                idx = existing_count + i
                seed = f"{int(time.time())}-{idx}"
                cc = country if country else pool.countries[idx % len(pool.countries)]
                if probe:
                    slot = pool.allocate_clean_slot(con, seed=seed, country=cc, ttl_minutes=ttl)
                else:
                    slot = pool.slot_for_seed(seed, index=idx, ttl_minutes=ttl)
                    if country:
                        slot = pool.build_slot(port=slot.port, country=country, ttl_minutes=ttl)
                inbox = mb.create_inbox(seed, index=idx, ttl="30d")
                now = utcnow()
                cur = con.execute(
                    """
                    INSERT INTO accounts (
                        seed, username, email, email_token, email_provider, password,
                        proxy_port, proxy_country, exit_ip, timezone, locale, status, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'staged', ?)
                    """,
                    (
                        seed,
                        inbox["username"],
                        inbox["address"],
                        inbox["token"],
                        inbox["provider"],
                        inbox["password"],
                        slot.port,
                        slot.country,
                        slot.exit_ip,
                        slot.timezone,
                        slot.locale,
                        now,
                    ),
                )
                acc_id = cur.lastrowid
                log_event(con, acc_id, "staged", f"email={inbox['address']} port={slot.port}")
                staged.append({"id": acc_id, "username": inbox["username"], "email": inbox["address"]})
            return 201, "application/json", json.dumps({"ok": True, "staged_count": len(staged), "accounts": staged})

        if method == "POST" and path == "/api/inbox-poll":
            payload = json.loads(body.decode("utf-8") if isinstance(body, bytes) else (body or "{}"))
            acc_id = int(payload["account_id"])
            timeout_sec = max(1, min(int(payload.get("timeout", 8)), 60))
            row = con.execute("SELECT * FROM accounts WHERE id = ?", (acc_id,)).fetchone()
            if not row:
                return 404, "application/json", json.dumps({"error": "account_not_found"})
            mb = get_mailbox_driver(row["email_provider"])
            code, msg = mb.poll_otp(row["email"], row["email_token"], timeout_sec=timeout_sec, poll_sec=1.5)
            return (
                200,
                "application/json",
                json.dumps(
                    {
                        "ok": True,
                        "account_id": acc_id,
                        "email": row["email"],
                        "driver": row["email_provider"],
                        "otp": code,
                        "subject": msg.get("subject") if msg else None,
                    }
                ),
            )

        if method == "POST" and path == "/api/session-check":
            import requests

            payload = json.loads(body.decode("utf-8") if isinstance(body, bytes) else (body or "{}"))
            acc_id = int(payload["account_id"])
            row = con.execute("SELECT * FROM accounts WHERE id = ?", (acc_id,)).fetchone()
            if not row:
                return 404, "application/json", json.dumps({"error": "account_not_found"})
            pool = StickyPortPool()
            slot = pool.build_slot(port=row["proxy_port"], country=row["proxy_country"])
            proxies = {"http": slot.url, "https": slot.url} if slot.url else None
            r = requests.get(
                f"https://api.github.com/users/{row['username']}",
                headers={"Accept": "application/vnd.github+json", "User-Agent": "auto-gh/0.1"},
                proxies=proxies,
                timeout=12,
            )
            if r.status_code == 200:
                gh_data = r.json()
                created_iso = gh_data.get("created_at") or utcnow()
                con.execute(
                    "UPDATE accounts SET status = 'verified', verified_at = ? WHERE id = ?",
                    (created_iso, acc_id),
                )
                con.commit()
                log_event(con, acc_id, "gh_verified", f"created_at={created_iso}")
                return (
                    200,
                    "application/json",
                    json.dumps(
                        {
                            "ok": True,
                            "exists_on_github": True,
                            "username": row["username"],
                            "github_id": gh_data.get("id"),
                            "created_at": created_iso,
                        }
                    ),
                )
            return (
                200,
                "application/json",
                json.dumps(
                    {
                        "ok": True,
                        "exists_on_github": False,
                        "username": row["username"],
                        "http_status": r.status_code,
                    }
                ),
            )

        if method == "POST" and path == "/api/signup":
            import os
            import shutil
            import subprocess
            import sys

            payload = json.loads(body.decode("utf-8") if isinstance(body, bytes) else (body or "{}"))
            acc_id = int(payload["account_id"])
            otp_timeout = int(payload.get("otp_timeout", 90))
            row = con.execute("SELECT * FROM accounts WHERE id = ?", (acc_id,)).fetchone()
            if not row:
                return 404, "application/json", json.dumps({"error": "account_not_found"})

            env = dict(os.environ)
            pkg_root = str(Path(__file__).resolve().parents[1])
            env["PYTHONPATH"] = pkg_root
            cmd = [
                sys.executable,
                "-m",
                "auto_gh.cli",
                "signup",
                "--account-id",
                str(acc_id),
                "--otp-timeout",
                str(otp_timeout),
            ]
            if os.name == "posix" and not env.get("DISPLAY") and shutil.which("xvfb-run"):
                cmd = ["xvfb-run", "-a", *cmd]

            proc = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=otp_timeout + 120)
            if proc.returncode != 0:
                return 502, "application/json", json.dumps({"ok": False, "error": proc.stderr.strip() or proc.stdout.strip()})
            try:
                res_obj = json.loads(proc.stdout.strip())
            except Exception:
                res_obj = {"raw": proc.stdout.strip()}
            return 200, "application/json", json.dumps(res_obj)

        if method == "POST" and path == "/api/import-cookie":
            payload = json.loads(body.decode("utf-8") if isinstance(body, bytes) else (body or "{}"))
            acc_id = int(payload["account_id"])
            cookie_val = payload.get("cookie") or ""
            row = con.execute("SELECT * FROM accounts WHERE id = ?", (acc_id,)).fetchone()
            if not row:
                return 404, "application/json", json.dumps({"error": "account_not_found"})
            st_path = save_github_cookie_state(row["username"], cookie_val)
            ver_at = row["verified_at"] or utcnow()
            con.execute(
                "UPDATE accounts SET storage_state = ?, status = 'verified', verified_at = ? WHERE id = ?",
                (str(st_path), ver_at, acc_id),
            )
            con.commit()
            log_event(con, acc_id, "cookie_imported", str(st_path))
            return (
                200,
                "application/json",
                json.dumps({"ok": True, "account_id": acc_id, "storage_state": str(st_path)}),
            )

        if method == "POST" and path == "/api/pair":
            import os
            import shlex
            import subprocess
            import sys

            payload = json.loads(body.decode("utf-8") if isinstance(body, bytes) else (body or "{}"))
            acc_id = int(payload["account_id"])
            target = str(payload.get("target", "kiro")).lower()
            execute_flag = bool(payload.get("execute", False))
            sink_target = str(payload.get("sink") or os.environ.get("PAIR_SINK", "sqlite"))
            row = con.execute("SELECT * FROM accounts WHERE id = ?", (acc_id,)).fetchone()
            if not row:
                return 404, "application/json", json.dumps({"error": "account_not_found"})

            pool = StickyPortPool()
            slot = pool.build_slot(port=row["proxy_port"], country=row["proxy_country"])
            bundle = SessionBundle.from_row(dict(row), proxy_url=slot.url)
            has_session = bool(bundle.cookies.get("user_session"))

            env = dict(os.environ)
            base_parent = Path(__file__).resolve().parents[3]
            if target == "cbai":
                custom_cmd = os.environ.get("PAIR_CBAI_CMD", "")
                if custom_cmd:
                    cmd = shlex.split(custom_cmd)
                else:
                    env["PYTHONPATH"] = os.environ.get("AUTO_CB_PACKAGES", str(base_parent / "auto-cb" / "packages"))
                    cmd = [sys.executable, "-m", "auto_cb.cli", "pair", "--stdin", "--idp", "github"]
                    if execute_flag or has_session:
                        cmd.extend(["--execute", "--sink", sink_target])
            else:
                custom_cmd = os.environ.get("PAIR_KIRO_CMD", "")
                if custom_cmd:
                    cmd = shlex.split(custom_cmd)
                else:
                    env["PYTHONPATH"] = os.environ.get("AUTO_KR_PACKAGES", str(base_parent / "auto-kr" / "packages"))
                    cmd = [sys.executable, "-m", "auto_kr.cli", "pair", "--stdin", "--mode", "pkce"]
                    if execute_flag or has_session:
                        cmd.extend(["--execute", "--sink", sink_target])

            proc = subprocess.run(
                cmd,
                input=bundle.to_json() + "\n",
                capture_output=True,
                text=True,
                env=env,
                timeout=25,
            )
            if proc.returncode != 0:
                return 502, "application/json", json.dumps({"ok": False, "error": proc.stderr.strip()})
            out_line = proc.stdout.strip().splitlines()[-1] if proc.stdout.strip() else "{}"
            log_event(con, acc_id, f"pair_{target}", "dispatched via panel")
            return 200, "application/json", json.dumps({"ok": True, "target": target, "plan": json.loads(out_line)})

        return 404, "application/json", json.dumps({"error": "not_found"})
    finally:
        con.close()


def run_panel_server(host: str = "127.0.0.1", port: int = 8790, db_path: str | Path = DEFAULT_DB) -> None:
    import os

    load_dotenv_file()
    expected_token = os.environ.get("PANEL_AUTH_TOKEN", "").strip()

    class _Handler(BaseHTTPRequestHandler):
        def _check_auth(self) -> bool:
            if not expected_token:
                return True
            auth = self.headers.get("Authorization", "")
            cookie = self.headers.get("Cookie", "")
            if auth == f"Bearer {expected_token}" or f"panel_token={expected_token}" in cookie:
                return True
            raw = b'{"error":"unauthorized"}'
            self.send_response(401)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
            return False

        def do_GET(self):
            if not self._check_auth():
                return
            parsed = urlparse(self.path)
            code, ctype, payload = handle_api_request(
                "GET", parsed.path, parse_qs(parsed.query), None, db_path=db_path
            )
            raw = payload.encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def do_POST(self):
            if not self._check_auth():
                return
            parsed = urlparse(self.path)
            length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(length) if length > 0 else b"{}"
            code, ctype, payload = handle_api_request(
                "POST", parsed.path, parse_qs(parsed.query), body, db_path=db_path
            )
            raw = payload.encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def log_message(self, format, *args):
            return

    srv = ThreadingHTTPServer((host, port), _Handler)
    print(f"auto-gh panel listening on http://{host}:{port}", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()
