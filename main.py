"""
IntegraChat Cloud Licensing Server
-----------------------------------
Deploy to Railway / Render (free tier).
Validates license keys for IntegraChat Server installations.

Endpoints:
  POST /validate          — called by IntegraChat server on startup
  POST /stripe/webhook    — Stripe events (subscription.created/deleted)
  GET  /admin             — simple admin dashboard (password-protected)
  POST /admin/create      — manually create a license key
  GET  /health            — health check
"""

import hashlib
import hmac
import os
import secrets
import sqlite3
import string
import time
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

import stripe
import resend
from fastapi import FastAPI, Header, HTTPException, Request, Depends
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pydantic import BaseModel

# ── Config ─────────────────────────────────────────────────────────────────────
DB_PATH             = Path(os.getenv("DB_PATH", "licenses.db"))
STRIPE_SECRET_KEY   = os.getenv("STRIPE_SECRET_KEY", "")
STRIPE_WEBHOOK_SEC  = os.getenv("STRIPE_WEBHOOK_SECRET", "")
ADMIN_USER          = os.getenv("ADMIN_USER", "admin")
ADMIN_PASS          = os.getenv("ADMIN_PASS", "changeme")
GRACE_PERIOD_DAYS   = 3   # allow 3-day grace after expiry (internet outage)
RESEND_API_KEY      = os.getenv("RESEND_API_KEY", "")
FROM_EMAIL          = os.getenv("FROM_EMAIL", "licenses@integrachat.com")
DOWNLOAD_URL        = os.getenv("DOWNLOAD_URL", "https://integrachat.com/download")

# Stripe Price IDs — set these as Railway env vars
# Copy them from Stripe Dashboard -> Products -> each price's API ID
STRIPE_STARTER_PRICE_ID = os.getenv("STRIPE_STARTER_PRICE_ID", "")
STRIPE_PRO_PRICE_ID     = os.getenv("STRIPE_PRO_PRICE_ID", "")

# Seat limits per plan
PLAN_DEVICES = {"starter": 5, "professional": 15, "enterprise": 50}

resend.api_key = RESEND_API_KEY


# ── Email ──────────────────────────────────────────────────────────────────────
def send_license_email(to_email: str, customer_name: str, key: str,
                       expires_at: Optional[str], plan: str):
    """Send license key + download instructions to new customer."""
    if not RESEND_API_KEY:
        print(f"[EMAIL] No RESEND_API_KEY set — skipping email to {to_email}")
        return

    expires_str = ""
    if expires_at:
        try:
            dt = datetime.fromisoformat(expires_at)
            expires_str = f"<p>Your license is valid until <strong>{dt.strftime('%B %d, %Y')}</strong>.</p>"
        except Exception:
            expires_str = f"<p>Expires: {expires_at}</p>"

    html = f"""
    <div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;background:#0e0e0e;color:#e0e0e0;border-radius:12px;overflow:hidden;">
      <div style="background:#1a1a1a;padding:32px 40px;text-align:center;border-bottom:1px solid #333;">
        <h1 style="color:#C0C0C0;margin:0;font-size:28px;">IntegraChat</h1>
        <p style="color:#888;margin:4px 0 0;">Office Paging System</p>
      </div>
      <div style="padding:40px;">
        <h2 style="color:#fff;margin-top:0;">Welcome, {customer_name}!</h2>
        <p>Thank you for your purchase. Your <strong>{plan.title()}</strong> license is ready.</p>

        <div style="background:#1a1a1a;border:1px solid #333;border-radius:8px;padding:20px;margin:24px 0;text-align:center;">
          <p style="color:#888;margin:0 0 8px;font-size:12px;text-transform:uppercase;letter-spacing:1px;">Your License Key</p>
          <p style="color:#C0C0C0;font-size:24px;font-family:monospace;letter-spacing:3px;margin:0;"><strong>{key}</strong></p>
        </div>

        {expires_str}

        <h3 style="color:#C0C0C0;">Getting Started</h3>
        <ol style="line-height:2;">
          <li><a href="{DOWNLOAD_URL}" style="color:#C0C0C0;">Download the IntegraChat Server installer</a></li>
          <li>Run <strong>IntegraChat_Setup.exe</strong> on your office Windows PC</li>
          <li>Launch IntegraChat — click <strong>License</strong> in the sidebar</li>
          <li>Paste your license key above and click <strong>Activate</strong></li>
          <li>Install the <strong>IntegraChat app</strong> on your office tablets (Android APK available on the download page)</li>
        </ol>

        <p style="color:#888;font-size:13px;">Need help? Reply to this email or visit our support page.</p>
      </div>
      <div style="background:#1a1a1a;padding:16px 40px;text-align:center;border-top:1px solid #333;">
        <p style="color:#555;font-size:12px;margin:0;">IntegraChat — A.N.T. Dental Integration &nbsp;|&nbsp; antondental@integrachat.com</p>
      </div>
    </div>
    """
    try:
        resend.Emails.send({
            "from": FROM_EMAIL,
            "to": [to_email],
            "subject": f"Your IntegraChat License Key — {key}",
            "html": html,
        })
        print(f"[EMAIL] Sent license to {to_email}")
    except Exception as e:
        print(f"[EMAIL] Failed to send to {to_email}: {e}")

stripe.api_key = STRIPE_SECRET_KEY

# ── Database ───────────────────────────────────────────────────────────────────
def get_db():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    return con

def init_db():
    con = get_db()
    con.executescript("""
    CREATE TABLE IF NOT EXISTS licenses (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        key             TEXT    UNIQUE NOT NULL,
        plan            TEXT    NOT NULL DEFAULT 'professional',
        status          TEXT    NOT NULL DEFAULT 'active',   -- active|suspended|cancelled
        stripe_sub_id   TEXT,
        stripe_cust_id  TEXT,
        customer_email  TEXT,
        customer_name   TEXT,
        max_devices     INTEGER NOT NULL DEFAULT 10,
        created_at      TEXT    NOT NULL,
        expires_at      TEXT                                 -- NULL = perpetual
    );
    CREATE TABLE IF NOT EXISTS activations (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        license_key TEXT NOT NULL,
        machine_id  TEXT NOT NULL,
        hostname    TEXT,
        ip          TEXT,
        first_seen  TEXT NOT NULL,
        last_seen   TEXT NOT NULL,
        UNIQUE(license_key, machine_id)
    );
    CREATE TABLE IF NOT EXISTS events (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        ts          TEXT NOT NULL,
        type        TEXT NOT NULL,
        license_key TEXT,
        detail      TEXT
    );
    """)
    con.commit()
    con.close()

# ── Helpers ────────────────────────────────────────────────────────────────────
def gen_key() -> str:
    """Generate IC-XXXX-XXXX-XXXX-XXXX format key."""
    chars = string.ascii_uppercase + string.digits
    parts = ["".join(secrets.choice(chars) for _ in range(4)) for _ in range(4)]
    return "IC-" + "-".join(parts)

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def log_event(key: Optional[str], etype: str, detail: str = ""):
    con = get_db()
    con.execute("INSERT INTO events(ts,type,license_key,detail) VALUES(?,?,?,?)",
                (now_iso(), etype, key, detail))
    con.commit()
    con.close()

# ── Lifespan ───────────────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    # Create a built-in DEV key if none exist
    con = get_db()
    count = con.execute("SELECT COUNT(*) FROM licenses").fetchone()[0]
    if count == 0:
        dev_key = "IC-DEV0-TEST-0000-0001"
        con.execute("""
            INSERT OR IGNORE INTO licenses
            (key, plan, status, customer_email, customer_name, max_devices, created_at)
            VALUES (?,?,?,?,?,?,?)
        """, (dev_key, "developer", "active", "dev@integrachat.io",
              "Developer", 99, now_iso()))
        con.commit()
        print(f"[BOOT] Dev key created: {dev_key}")
    con.close()
    yield

app = FastAPI(title="IntegraChat License Server", version="1.0.0", lifespan=lifespan)
security = HTTPBasic()

# ── Schemas ────────────────────────────────────────────────────────────────────
class ValidateRequest(BaseModel):
    license_key: str
    machine_id:  str
    hostname:    Optional[str] = None
    version:     Optional[str] = None

class ValidateResponse(BaseModel):
    valid:      bool
    plan:       str = ""
    status:     str = ""
    message:    str = ""
    expires_at: Optional[str] = None
    max_devices: int = 0

class CreateLicenseRequest(BaseModel):
    customer_email: str
    customer_name:  str
    plan:           str = "professional"
    max_devices:    Optional[int] = None   # auto from plan if not set
    expires_days:   Optional[int] = None   # None = perpetual

    @property
    def resolved_devices(self) -> int:
        if self.max_devices is not None:
            return self.max_devices
        return PLAN_DEVICES.get(self.plan.lower(), 10)

# ── Admin auth ─────────────────────────────────────────────────────────────────
def verify_admin(creds: HTTPBasicCredentials = Depends(security)):
    ok_user = hmac.compare_digest(creds.username.encode(), ADMIN_USER.encode())
    ok_pass = hmac.compare_digest(creds.password.encode(), ADMIN_PASS.encode())
    if not (ok_user and ok_pass):
        raise HTTPException(status_code=401, detail="Unauthorized",
                            headers={"WWW-Authenticate": "Basic"})
    return creds.username

# ── Routes ─────────────────────────────────────────────────────────────────────

@app.get("/health")
def health():
    return {
        "status": "ok",
        "ts": now_iso(),
        "build": "v5-fix4",
        "wh_secret_set": bool(STRIPE_WEBHOOK_SEC),
        "wh_secret_prefix": STRIPE_WEBHOOK_SEC[:12] if STRIPE_WEBHOOK_SEC else "MISSING"
    }


@app.post("/debug/webhook-sim")
def debug_webhook_sim(_=Depends(verify_admin)):
    """Simulate a subscription.created event for testing (admin only)."""
    import traceback
    test_data = {
        "id": "sub_debug_001",
        "customer": "cus_debug",
        "status": "active",
        "current_period_end": int(__import__("time").time()) + 2592000,
        "items": {"data": [{"price": {"id": "price_1TLCCO21fYeC9E5lPKg3cDf3", "nickname": "Starter"}}]}
    }
    try:
        _handle_sub_created(test_data)
        con = get_db()
        row = con.execute("SELECT key FROM licenses WHERE stripe_sub_id='sub_debug_001'").fetchone()
        con.close()
        return {"ok": True, "key": row["key"] if row else "not found"}
    except Exception as e:
        return {"ok": False, "error": str(e), "trace": traceback.format_exc()}


@app.post("/validate", response_model=ValidateResponse)
async def validate_license(req: ValidateRequest, request: Request):
    key = req.license_key.strip().upper()
    con = get_db()
    row = con.execute("SELECT * FROM licenses WHERE key=?", (key,)).fetchone()

    if not row:
        con.close()
        log_event(key, "validate_fail", "key_not_found")
        return ValidateResponse(valid=False, message="License key not found.")

    if row["status"] == "suspended":
        con.close()
        log_event(key, "validate_fail", "suspended")
        return ValidateResponse(valid=False, status="suspended",
                                message="License suspended. Contact support.")

    # Expiry check (with grace period)
    if row["expires_at"]:
        exp = datetime.fromisoformat(row["expires_at"])
        grace = exp + timedelta(days=GRACE_PERIOD_DAYS)
        if datetime.now(timezone.utc) > grace:
            con.close()
            log_event(key, "validate_fail", "expired")
            return ValidateResponse(valid=False, status="expired",
                                    message="License expired. Please renew.")

    # Device limit check
    machine_id = req.machine_id.strip()
    existing = con.execute(
        "SELECT COUNT(*) FROM activations WHERE license_key=?", (key,)
    ).fetchone()[0]
    known = con.execute(
        "SELECT id FROM activations WHERE license_key=? AND machine_id=?",
        (key, machine_id)
    ).fetchone()

    if not known and existing >= row["max_devices"]:
        con.close()
        log_event(key, "validate_fail", f"device_limit_{existing}")
        return ValidateResponse(valid=False, status="device_limit",
                                message=f"Device limit ({row['max_devices']}) reached.")

    # Register/update activation
    ip = request.client.host if request.client else "unknown"
    ts = now_iso()
    con.execute("""
        INSERT INTO activations (license_key, machine_id, hostname, ip, first_seen, last_seen)
        VALUES (?,?,?,?,?,?)
        ON CONFLICT(license_key, machine_id) DO UPDATE SET last_seen=?, hostname=?, ip=?
    """, (key, machine_id, req.hostname, ip, ts, ts, ts, req.hostname, ip))
    con.commit()
    con.close()

    log_event(key, "validate_ok", f"machine={machine_id}")
    return ValidateResponse(
        valid       = True,
        plan        = row["plan"],
        status      = row["status"],
        message     = "License valid.",
        expires_at  = row["expires_at"],
        max_devices = row["max_devices"],
    )


@app.post("/stripe/webhook")
async def stripe_webhook(request: Request,
                         stripe_signature: str = Header(None)):
    payload = await request.body()
    try:
        event = stripe.Webhook.construct_event(
            payload, stripe_signature, STRIPE_WEBHOOK_SEC
        )
    except Exception as e:
        print(f"[WEBHOOK] Signature error: {e}")
        raise HTTPException(status_code=400, detail="Invalid signature")

    # Support both Stripe SDK v9+ (attribute access) and dict-style
    raw = event if isinstance(event, dict) else event.to_dict_recursive() if hasattr(event, 'to_dict_recursive') else dict(event)
    etype = raw.get("type", "")
    data  = raw.get("data", {}).get("object", {})

    print(f"[WEBHOOK] Received: {etype}")
    try:
        if etype == "customer.subscription.created":
            _handle_sub_created(data)
        elif etype in ("customer.subscription.updated",):
            _handle_sub_updated(data)
        elif etype in ("customer.subscription.deleted",
                       "customer.subscription.paused"):
            _handle_sub_cancelled(data)
        elif etype == "invoice.payment_failed":
            _handle_payment_failed(data)
        elif etype == "invoice.payment_succeeded":
            _handle_payment_succeeded(data)
        else:
            print(f"[WEBHOOK] Ignored event type: {etype}")
    except Exception as e:
        print(f"[WEBHOOK] Handler error for {etype}: {e}")
        import traceback; traceback.print_exc()

    return {"received": True}


def _sg(obj, key, default=None):
    """Safe getter for Stripe SDK v9+ objects (attribute-based) and plain dicts."""
    # Stripe SDK v9+ uses attribute access; fall back to dict access for plain dicts
    v = getattr(obj, key, _MISSING)
    if v is not _MISSING:
        return v if v is not None else default
    try:
        v = obj[key]
        return v if v is not None else default
    except (KeyError, TypeError, AttributeError):
        return default

_MISSING = object()


def _handle_sub_created(sub):
    con = get_db()
    cust_id  = _sg(sub, "customer")
    sub_id   = _sg(sub, "id")
    email    = ""
    name     = ""
    # Fetch customer details
    try:
        cust  = stripe.Customer.retrieve(cust_id)
        email = _sg(cust, "email", "")
        name  = _sg(cust, "name", "") or email
    except Exception:
        pass

    # Check if key already exists for this subscription
    existing = con.execute(
        "SELECT key FROM licenses WHERE stripe_sub_id=?", (sub_id,)
    ).fetchone()
    if existing:
        con.close()
        return

    plan  = _plan_from_sub(sub)
    key   = gen_key()
    seats = PLAN_DEVICES.get(plan, 10)
    exp   = None
    if _sg(sub, "current_period_end"):
        exp = datetime.fromtimestamp(
            _sg(sub, "current_period_end"), tz=timezone.utc
        ).isoformat()

    con.execute("""
        INSERT INTO licenses
        (key,plan,status,stripe_sub_id,stripe_cust_id,customer_email,customer_name,
         max_devices,created_at,expires_at)
        VALUES (?,?,?,?,?,?,?,?,?,?)
    """, (key, plan, "active", sub_id, cust_id, email, name,
          seats, now_iso(), exp))
    con.commit()
    con.close()
    log_event(key, "created", f"stripe_sub={sub_id} email={email}")
    print(f"[STRIPE] New license {key} for {email}")
    send_license_email(email, name, key, exp, plan)


def _handle_sub_updated(sub):
    sub_id = _sg(sub, "id")
    exp    = None
    if _sg(sub, "current_period_end"):
        exp = datetime.fromtimestamp(
            _sg(sub, "current_period_end"), tz=timezone.utc
        ).isoformat()
    status = "active" if _sg(sub, "status") == "active" else "suspended"
    con = get_db()
    con.execute(
        "UPDATE licenses SET expires_at=?, status=? WHERE stripe_sub_id=?",
        (exp, status, sub_id))
    con.commit()
    con.close()


def _handle_sub_cancelled(sub):
    sub_id = _sg(sub, "id")
    con = get_db()
    row = con.execute(
        "SELECT key FROM licenses WHERE stripe_sub_id=?", (sub_id,)
    ).fetchone()
    if row:
        con.execute(
            "UPDATE licenses SET status='cancelled' WHERE stripe_sub_id=?",
            (sub_id,))
        con.commit()
        log_event(row["key"], "cancelled", f"stripe_sub={sub_id}")
    con.close()


def _handle_payment_failed(invoice):
    sub_id = _sg(invoice, "subscription")
    if not sub_id:
        return
    con = get_db()
    row = con.execute(
        "SELECT key FROM licenses WHERE stripe_sub_id=?", (sub_id,)
    ).fetchone()
    if row:
        log_event(row["key"], "payment_failed", f"invoice={_sg(invoice, 'id')}")
    con.close()


def _handle_payment_succeeded(invoice):
    sub_id = _sg(invoice, "subscription")
    if not sub_id:
        return
    con = get_db()
    row = con.execute(
        "SELECT key FROM licenses WHERE stripe_sub_id=?", (sub_id,)
    ).fetchone()
    if row:
        new_exp = (datetime.now(timezone.utc) + timedelta(days=31)).isoformat()
        con.execute(
            "UPDATE licenses SET expires_at=?, status='active' WHERE stripe_sub_id=?",
            (new_exp, sub_id))
        con.commit()
        log_event(row["key"], "payment_ok", f"extended to {new_exp}")
    con.close()


def _plan_from_sub(sub) -> str:
    """Determine plan from Stripe subscription.
    Checks (in order): price ID env var match -> price nickname -> default."""
    try:
        items = _sg(_sg(sub, "items", {}), "data", [])
        if items:
            price    = _sg(items[0], "price", {})
            price_id = _sg(price, "id", "")
            nickname = (_sg(price, "nickname") or "").lower().strip()

            if STRIPE_STARTER_PRICE_ID and price_id == STRIPE_STARTER_PRICE_ID:
                return "starter"
            if STRIPE_PRO_PRICE_ID and price_id == STRIPE_PRO_PRICE_ID:
                return "professional"

            if "starter" in nickname or "basic" in nickname or "lite" in nickname:
                return "starter"
            if "pro" in nickname or "professional" in nickname:
                return "professional"
            if "enterprise" in nickname:
                return "enterprise"
    except Exception:
        pass
    return "professional"


# ── Admin routes ───────────────────────────────────────────────────────────────

@app.post("/admin/create")
def admin_create(req: CreateLicenseRequest, _=Depends(verify_admin)):
    key = gen_key()
    exp = None
    if req.expires_days:
        exp = (datetime.now(timezone.utc) + timedelta(days=req.expires_days)).isoformat()
    con = get_db()
    con.execute("""
        INSERT INTO licenses
        (key,plan,status,customer_email,customer_name,max_devices,created_at,expires_at)
        VALUES (?,?,?,?,?,?,?,?)
    """, (key, req.plan, "active", req.customer_email, req.customer_name,
          req.resolved_devices, now_iso(), exp))
    con.commit()
    con.close()
    log_event(key, "manual_create", f"email={req.customer_email}")
    send_license_email(req.customer_email, req.customer_name, key, exp, req.plan)
    return {"key": key, "expires_at": exp}


@app.post("/admin/suspend/{key}")
def admin_suspend(key: str, _=Depends(verify_admin)):
    con = get_db()
    con.execute("UPDATE licenses SET status='suspended' WHERE key=?", (key.upper(),))
    con.commit()
    con.close()
    log_event(key.upper(), "suspended", "admin action")
    return {"ok": True}


@app.post("/admin/reinstate/{key}")
def admin_reinstate(key: str, _=Depends(verify_admin)):
    con = get_db()
    con.execute("UPDATE licenses SET status='active' WHERE key=?", (key.upper(),))
    con.commit()
    con.close()
    log_event(key.upper(), "reinstated", "admin action")
    return {"ok": True}


@app.get("/admin", response_class=HTMLResponse)
def admin_dashboard(request: Request, _=Depends(verify_admin)):
    con = get_db()
    licenses = con.execute(
        "SELECT * FROM licenses ORDER BY created_at DESC"
    ).fetchall()
    activations = con.execute(
        "SELECT * FROM activations ORDER BY last_seen DESC LIMIT 100"
    ).fetchall()
    events = con.execute(
        "SELECT * FROM events ORDER BY ts DESC LIMIT 50"
    ).fetchall()
    con.close()

    lic_rows = ""
    for l in licenses:
        badge = {"active": "🟢", "suspended": "🔴", "cancelled": "⚫"}.get(l["status"], "🟡")
        exp   = l["expires_at"][:10] if l["expires_at"] else "∞"
        lic_rows += f"""
        <tr>
          <td><code>{l['key']}</code></td>
          <td>{l['customer_name']}</td>
          <td>{l['customer_email']}</td>
          <td>{l['plan']}</td>
          <td>{badge} {l['status']}</td>
          <td>{exp}</td>
          <td>{l['max_devices']}</td>
          <td>{l['created_at'][:10]}</td>
          <td>
            <button onclick="act('/admin/suspend/{l['key']}','POST')">Suspend</button>
            <button onclick="act('/admin/reinstate/{l['key']}','POST')">Reinstate</button>
          </td>
        </tr>"""

    act_rows = ""
    for a in activations:
        act_rows += f"""
        <tr>
          <td><code>{a['license_key']}</code></td>
          <td>{a['hostname'] or '—'}</td>
          <td>{a['machine_id'][:16]}…</td>
          <td>{a['ip']}</td>
          <td>{a['last_seen'][:19]}</td>
        </tr>"""

    ev_rows = ""
    for e in events:
        ev_rows += f"<tr><td>{e['ts'][:19]}</td><td>{e['type']}</td><td>{e['license_key'] or ''}</td><td>{e['detail']}</td></tr>"

    return f"""<!DOCTYPE html>
<html>
<head>
<title>IntegraChat License Admin</title>
<style>
  body  {{ font-family: Segoe UI, sans-serif; background:#111; color:#eee; margin:0; padding:20px; }}
  h1   {{ color:#fb8c00; }} h2 {{ color:#aaa; margin-top:30px; }}
  table {{ border-collapse:collapse; width:100%; margin-top:10px; }}
  th,td {{ border:1px solid #333; padding:8px 12px; text-align:left; font-size:13px; }}
  th    {{ background:#1e1e1e; color:#fb8c00; }}
  tr:nth-child(even) {{ background:#181818; }}
  code  {{ color:#00bcd4; }}
  button {{ background:#333; color:#eee; border:1px solid #555; padding:4px 10px;
            border-radius:4px; cursor:pointer; margin:2px; }}
  button:hover {{ background:#fb8c00; color:#000; }}
  .create-form {{ background:#1e1e1e; padding:16px; border-radius:8px; margin:20px 0; }}
  .create-form input,select {{ background:#252525; color:#eee; border:1px solid #444;
    padding:6px 10px; margin:4px; border-radius:4px; }}
  .create-form button {{ background:#fb8c00; color:#000; font-weight:bold; padding:8px 18px; }}
</style>
</head>
<body>
<h1>🔑 IntegraChat License Admin</h1>

<div class="create-form">
  <h2 style="margin-top:0">Create License</h2>
  <input id="email" placeholder="customer@email.com" size="30">
  <input id="name"  placeholder="Office Name" size="25">
  <select id="plan">
    <option value="professional">Professional ($99/mo)</option>
    <option value="enterprise">Enterprise ($199/mo)</option>
    <option value="developer">Developer (free)</option>
  </select>
  <input id="days" placeholder="Days (blank=∞)" size="10" type="number">
  <input id="devs" value="10" size="5" type="number">
  <button onclick="createKey()">Generate Key</button>
  <div id="newkey" style="margin-top:10px;font-size:18px;color:#00bcd4"></div>
</div>

<h2>Active Licenses ({len(licenses)})</h2>
<table><tr>
  <th>Key</th><th>Name</th><th>Email</th><th>Plan</th><th>Status</th>
  <th>Expires</th><th>Max Devices</th><th>Created</th><th>Actions</th>
</tr>{lic_rows}</table>

<h2>Device Activations</h2>
<table><tr><th>Key</th><th>Hostname</th><th>Machine ID</th><th>IP</th><th>Last Seen</th></tr>
{act_rows}</table>

<h2>Recent Events</h2>
<table><tr><th>Time</th><th>Type</th><th>Key</th><th>Detail</th></tr>
{ev_rows}</table>

<script>
async function act(url, method) {{
  if(!confirm('Confirm action?')) return;
  const r = await fetch(url, {{method, headers:{{'Authorization':'Basic '+btoa('{ADMIN_USER}:{ADMIN_PASS}')}}  }});
  location.reload();
}}
async function createKey() {{
  const body = {{
    customer_email: document.getElementById('email').value,
    customer_name:  document.getElementById('name').value,
    plan:           document.getElementById('plan').value,
    max_devices:    parseInt(document.getElementById('devs').value)||10,
    expires_days:   parseInt(document.getElementById('days').value)||null
  }};
  const r = await fetch('/admin/create',{{
    method:'POST',
    headers:{{'Content-Type':'application/json',
              'Authorization':'Basic '+btoa('{ADMIN_USER}:{ADMIN_PASS}')}},
    body: JSON.stringify(body)
  }});
  const d = await r.json();
  document.getElementById('newkey').innerHTML = '✅ Key: <b>'+d.key+'</b>';
}}
</script>
</body></html>"""
