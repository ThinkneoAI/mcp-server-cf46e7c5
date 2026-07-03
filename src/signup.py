"""
Signup flow — /mcp/signup page and /mcp/signup/submit endpoint.
Generates free-tier API key, saves to PostgreSQL, sends welcome email via Resend.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import time
import uuid
from collections import defaultdict, deque
from pathlib import Path
from threading import Lock
from typing import Deque

import psycopg

logger = logging.getLogger(__name__)

_DB_HOST = os.getenv("MCP_DB_HOST", "172.17.0.1")
_DB_PORT = int(os.getenv("MCP_DB_PORT", "5432"))
_DB_NAME = os.getenv("MCP_DB_NAME", "thinkneo_mcp")
_DB_USER = os.getenv("MCP_DB_USER", "mcp_user")
# Deferred check: fail loud on first DB connect, not on import — so marketplace
# smoke-tests / stdio wrappers can import the module without a live DB configured.
_DB_PASSWORD = os.getenv("MCP_DB_PASSWORD")
_RESEND_API_KEY = os.getenv("RESEND_API_KEY", "")
_FROM_EMAIL = os.getenv("MCP_FROM_EMAIL", "ThinkNEO <no-reply@thinkneo.ai>")


def _conninfo() -> str:
    if not _DB_PASSWORD:
        raise RuntimeError("MCP_DB_PASSWORD environment variable must be set")
    return f"host={_DB_HOST} port={_DB_PORT} dbname={_DB_NAME} user={_DB_USER} password={_DB_PASSWORD}"

# ── PII helpers ────────────────────────────────────────────────────────────

def _mask_email(email: str) -> str:
    """Return privacy-preserving email for logs: 'ab***@domain.tld'."""
    if "@" not in email:
        return "[invalid-email]"
    local, _, domain = email.partition("@")
    if len(local) <= 2:
        masked_local = local[:1] + "*"
    else:
        masked_local = local[:2] + "*" * (len(local) - 2)
    return f"{masked_local}@{domain}"


# ── Email validation (stricter than @/. check) ─────────────────────────────

# RFC 5321-ish: allows common real-world formats, rejects obvious garbage
_EMAIL_RE = re.compile(
    r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
    r"(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$"
)

def _is_valid_email(email: str) -> bool:
    if not email or len(email) > 254 or len(email) < 5:
        return False
    return bool(_EMAIL_RE.match(email))


# ── Per-IP rate limiter (in-memory sliding window) ─────────────────────────
# 5 attempts per 60s per IP. Simple and sufficient for signup abuse protection.

_RATE_WINDOW_SEC = 60
_RATE_MAX_ATTEMPTS = 5
_rate_lock = Lock()
_rate_buckets: dict[str, Deque[float]] = defaultdict(deque)


def _rate_check(client_ip: str) -> bool:
    """Return True if request allowed, False if rate-limited."""
    now = time.monotonic()
    with _rate_lock:
        bucket = _rate_buckets[client_ip]
        # Trim expired entries
        while bucket and bucket[0] < now - _RATE_WINDOW_SEC:
            bucket.popleft()
        if len(bucket) >= _RATE_MAX_ATTEMPTS:
            return False
        bucket.append(now)
        # Periodic cleanup to avoid unbounded dict growth
        if len(_rate_buckets) > 10000:
            stale = [ip for ip, b in _rate_buckets.items() if not b or b[-1] < now - _RATE_WINDOW_SEC]
            for ip in stale:
                _rate_buckets.pop(ip, None)
    return True


# ── CSRF / Origin allowlist ────────────────────────────────────────────────

_ALLOWED_ORIGINS = {
    "https://mcp.thinkneo.ai",
    "https://thinkneo.ai",
    "https://www.thinkneo.ai",
}

def _origin_allowed(origin: str, referer: str) -> bool:
    """Return True if request origin/referer is an allowed domain."""
    if origin:
        return origin in _ALLOWED_ORIGINS
    if referer:
        return any(referer.startswith(allowed + "/") or referer == allowed for allowed in _ALLOWED_ORIGINS)
    # No Origin/Referer → allow for non-browser clients (curl testing)
    # but only in combination with other protections (rate limit)
    return True


def _generate_api_key() -> str:
    return f"tnk_{uuid.uuid4().hex}"


def _hash_key(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


def _create_key_in_db(api_key: str, email: str) -> bool:
    """Insert new API key into PostgreSQL. Returns True on success.
    Keys created via signup are marked auto_registered=false."""
    try:
        with psycopg.connect(_conninfo(), connect_timeout=5) as conn:
            with conn.cursor() as cur:
                # Check if email already has a key
                cur.execute("SELECT key_prefix FROM api_keys WHERE email = %s", (email,))
                existing = cur.fetchone()
                if existing:
                    return False  # Already registered

                key_hash = _hash_key(api_key)
                cur.execute(
                    """INSERT INTO api_keys (key_hash, key_prefix, email, tier, monthly_limit, auto_registered, last_used_at)
                       VALUES (%s, %s, %s, 'free', 500, false, NOW())
                       ON CONFLICT (key_hash) DO NOTHING""",
                    (key_hash, api_key[:8], email),
                )
                conn.commit()
                return True
    except Exception as e:
        logger.error("DB error creating key: %s", e)
        return False


def _send_welcome_email(email: str, api_key: str) -> bool:
    """Send welcome email via Resend API."""
    if not _RESEND_API_KEY:
        logger.warning("RESEND_API_KEY not set, skipping email")
        return False

    template_path = Path(__file__).parent / "templates" / "welcome_free_tier.html"
    if not template_path.exists():
        # Fallback: check /app/templates
        template_path = Path("/app/templates/welcome_free_tier.html")

    if not template_path.exists():
        logger.error("Email template not found at %s", template_path)
        return False

    html = template_path.read_text()
    html = html.replace("{API_KEY}", api_key)
    html = html.replace("{EMAIL}", email)

    try:
        import urllib.request
        payload = json.dumps({
            "from": _FROM_EMAIL,
            "to": [email],
            "subject": "Your ThinkNEO API Key is ready",
            "html": html,
        }).encode()

        req = urllib.request.Request(
            "https://api.resend.com/emails",
            data=payload,
            headers={
                "Authorization": f"Bearer {_RESEND_API_KEY}",
                "Content-Type": "application/json",
                "User-Agent": "ThinkNEO-MCP/1.0",
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            result = json.loads(resp.read())
            logger.info("Email sent to %s: %s", _mask_email(email), result.get("id", "ok"))
            return True
    except Exception as e:
        logger.error("Failed to send email to %s: %s", _mask_email(email), e)
        return False


# ── Signup HTML Page ────────────────────────────────────────────────────────

SIGNUP_HTML = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Get Free API Key — ThinkNEO MCP</title>
<style>
  :root { --bg: #0F172A; --card: #1E293B; --border: #334155; --primary: #3B82F6; --success: #10B981; --text1: #F8FAFC; --text2: #94A3B8; --text3: #64748B; }
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { background: var(--bg); color: var(--text1); font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 24px; }
  .card { background: var(--card); border: 1px solid var(--border); border-radius: 16px; padding: 48px; max-width: 480px; width: 100%; }
  .logo { font-size: 24px; font-weight: 800; margin-bottom: 8px; }
  .logo span { color: var(--primary); }
  .badge { display: inline-block; padding: 4px 12px; border: 1px solid var(--border); border-radius: 20px; font-size: 10px; font-weight: 600; color: var(--text3); letter-spacing: 0.8px; text-transform: uppercase; margin-bottom: 24px; }
  .divider { height: 2px; background: linear-gradient(90deg, var(--primary), #14B4A0, transparent); border-radius: 2px; margin-bottom: 32px; }
  h1 { font-size: 28px; font-weight: 800; margin-bottom: 8px; letter-spacing: -0.5px; }
  .subtitle { color: var(--text2); font-size: 15px; line-height: 1.6; margin-bottom: 32px; }
  label { display: block; font-size: 12px; font-weight: 700; color: var(--text2); letter-spacing: 1px; text-transform: uppercase; margin-bottom: 8px; }
  input[type="email"] { width: 100%; padding: 14px 16px; background: var(--bg); border: 1px solid var(--border); border-radius: 8px; color: var(--text1); font-size: 15px; outline: none; transition: border-color 0.2s; }
  input[type="email"]:focus { border-color: var(--primary); }
  input[type="email"]::placeholder { color: var(--text3); }
  .btn { display: block; width: 100%; padding: 14px; background: var(--primary); color: #fff; border: none; border-radius: 8px; font-size: 15px; font-weight: 700; cursor: pointer; margin-top: 16px; transition: opacity 0.2s; letter-spacing: 0.2px; }
  .btn:hover { opacity: 0.9; }
  .btn:disabled { opacity: 0.5; cursor: not-allowed; }
  .note { font-size: 12px; color: var(--text3); margin-top: 16px; line-height: 1.5; text-align: center; }
  .note a { color: var(--primary); text-decoration: none; }
  .features { margin-top: 24px; padding-top: 24px; border-top: 1px solid var(--border); }
  .features li { list-style: none; padding: 5px 0; font-size: 13px; color: var(--text2); }
  .features li::before { content: "\\2713"; color: var(--success); font-weight: 700; margin-right: 10px; }
  .plan-matrix { margin-top: 28px; padding-top: 24px; border-top: 1px solid var(--border); }
  .plan-matrix h3 { font-size: 12px; font-weight: 700; color: var(--text2); letter-spacing: 1px; text-transform: uppercase; margin-bottom: 14px; }
  .plan-row { display: grid; grid-template-columns: 80px 1fr 54px; gap: 10px; padding: 10px 0; font-size: 12.5px; color: var(--text2); border-bottom: 1px dashed rgba(148,163,184,0.15); }
  .plan-row:last-child { border-bottom: none; }
  .plan-row .tool { font-family: 'SF Mono', Consolas, monospace; font-size: 11.5px; color: var(--text1); grid-column: 1 / 3; }
  .plan-row .tag { text-align: right; font-size: 10px; font-weight: 700; letter-spacing: 0.8px; text-transform: uppercase; padding: 2px 8px; border-radius: 4px; align-self: center; height: fit-content; }
  .tag.free { background: rgba(16,185,129,0.15); color: var(--success); }
  .tag.pro { background: rgba(59,130,246,0.15); color: var(--primary); }
  .error { background: rgba(239,68,68,0.1); border: 1px solid rgba(239,68,68,0.3); color: #f87171; padding: 12px 16px; border-radius: 8px; font-size: 13px; margin-top: 12px; display: none; }
  /* Success state */
  .success-card { text-align: center; }
  .success-icon { font-size: 48px; margin-bottom: 16px; }
  .key-box { background: var(--bg); border: 1px solid var(--primary); border-radius: 10px; padding: 20px; margin: 24px 0; text-align: left; }
  .key-label { font-size: 10px; font-weight: 700; color: var(--primary); letter-spacing: 1.5px; text-transform: uppercase; margin-bottom: 10px; }
  .key-value { font-family: 'SF Mono', SFMono-Regular, Consolas, monospace; font-size: 14px; color: var(--text1); word-break: break-all; background: var(--card); padding: 12px 14px; border-radius: 6px; border: 1px solid var(--border); cursor: pointer; }
  .key-value:hover { border-color: var(--primary); }
  .key-copied { font-size: 11px; color: var(--success); margin-top: 8px; display: none; }
  .key-warning { font-size: 11px; color: var(--text3); margin-top: 12px; }
  .back-link { display: inline-block; margin-top: 24px; color: var(--primary); text-decoration: none; font-size: 13px; font-weight: 600; }
</style>
</head>
<body>

<div class="card" id="signup-form">
  <div class="logo">Think<span>NEO</span></div>
  <div class="badge">Free Developer Access</div>
  <div class="divider"></div>

  <h1>Get your free API key</h1>
  <p class="subtitle">Start on Free — upgrade to Pro to unlock governance, guardrails, and compliance tools.</p>

  <form id="form" onsubmit="return handleSubmit(event)">
    <label for="email">Email address</label>
    <input type="email" id="email" name="email" placeholder="dev@company.com" required autocomplete="email">
    <div class="error" id="error"></div>
    <button type="submit" class="btn" id="submit-btn">Get My Free API Key</button>
  </form>

  <p class="note">
    By signing up you agree to our <a href="https://thinkneo.ai/terms-of-service">Terms</a> and <a href="https://thinkneo.ai/privacy-policy">Privacy Policy</a>.
  </p>

  <ul class="features">
    <li>500 API calls/month on Free</li>
    <li>Prompt safety checks included (thinkneo_check)</li>
    <li>Usage dashboard & cost tracking</li>
    <li>Works with Claude, ChatGPT, Cursor</li>
    <li>Upgrade to Pro anytime — <a href="mailto:hello@thinkneo.ai?subject=ThinkNEO%20Pro%20upgrade" style="color:var(--primary);text-decoration:none;">hello@thinkneo.ai</a></li>
  </ul>

  <div class="plan-matrix">
    <h3>What you get by plan</h3>
    <div class="plan-row"><span class="tool">thinkneo_check</span><span class="tag free">Free</span></div>
    <div class="plan-row"><span class="tool">thinkneo_provider_status</span><span class="tag free">Free</span></div>
    <div class="plan-row"><span class="tool">thinkneo_read_memory</span><span class="tag free">Free</span></div>
    <div class="plan-row"><span class="tool">thinkneo_usage</span><span class="tag free">Free</span></div>
    <div class="plan-row"><span class="tool">thinkneo_schedule_demo</span><span class="tag free">Free</span></div>
    <div class="plan-row"><span class="tool">thinkneo_check_spend</span><span class="tag pro">Pro</span></div>
    <div class="plan-row"><span class="tool">thinkneo_check_policy</span><span class="tag pro">Pro</span></div>
    <div class="plan-row"><span class="tool">thinkneo_get_budget_status</span><span class="tag pro">Pro</span></div>
    <div class="plan-row"><span class="tool">thinkneo_list_alerts</span><span class="tag pro">Pro</span></div>
    <div class="plan-row"><span class="tool">thinkneo_evaluate_guardrail</span><span class="tag pro">Pro</span></div>
    <div class="plan-row"><span class="tool">thinkneo_get_compliance_status</span><span class="tag pro">Pro</span></div>
  </div>
</div>

<div class="card success-card" id="success-card" style="display:none;">
  <div class="success-icon">&#x1F680;</div>
  <h1>You're in.</h1>
  <p class="subtitle">Your API key has been generated and sent to <strong id="success-email"></strong>.</p>

  <div class="key-box">
    <div class="key-label">Your API Key</div>
    <div class="key-value" id="key-display" onclick="copyKey()" title="Click to copy"></div>
    <div class="key-copied" id="key-copied">Copied!</div>
    <div class="key-warning">&#x1F512; Keep this key safe. Don't share it publicly.</div>
  </div>

  <p class="subtitle" style="font-size:13px;">Check your inbox for setup instructions, or <a href="/mcp/docs" style="color:#3B82F6;text-decoration:none;font-weight:600;">view the docs</a>.</p>

  <a href="/mcp/docs" class="back-link">&larr; Back to Documentation</a>
</div>

<script>
async function handleSubmit(e) {
  e.preventDefault();
  const btn = document.getElementById('submit-btn');
  const errEl = document.getElementById('error');
  const email = document.getElementById('email').value.trim();

  if (!email) return false;

  btn.disabled = true;
  btn.textContent = 'Generating...';
  errEl.style.display = 'none';

  try {
    const res = await fetch('/mcp/signup/submit', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email }),
    });
    const data = await res.json();

    if (data.ok) {
      document.getElementById('signup-form').style.display = 'none';
      document.getElementById('success-card').style.display = 'block';
      document.getElementById('success-email').textContent = email;
      document.getElementById('key-display').textContent = data.api_key;
    } else {
      errEl.textContent = data.error || 'Something went wrong. Try again.';
      errEl.style.display = 'block';
      btn.disabled = false;
      btn.textContent = 'Get My Free API Key';
    }
  } catch (err) {
    errEl.textContent = 'Connection error. Please try again.';
    errEl.style.display = 'block';
    btn.disabled = false;
    btn.textContent = 'Get My Free API Key';
  }
  return false;
}

function copyKey() {
  const key = document.getElementById('key-display').textContent;
  navigator.clipboard.writeText(key).then(() => {
    const el = document.getElementById('key-copied');
    el.style.display = 'block';
    setTimeout(() => el.style.display = 'none', 2000);
  });
}
</script>

</body>
</html>
"""


# ── ASGI Middleware ─────────────────────────────────────────────────────────

from starlette.types import ASGIApp, Receive, Scope, Send
from starlette.responses import HTMLResponse, JSONResponse


class SignupMiddleware:
    """Intercepts /mcp/signup and /mcp/signup/submit before MCP routing."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http":
            path = scope.get("path", "")
            method = scope.get("method", "GET")

            if path == "/mcp/signup" and method == "GET":
                response = HTMLResponse(SIGNUP_HTML)
                await response(scope, receive, send)
                return

            if path == "/mcp/signup/submit" and method == "POST":
                await self._handle_submit(scope, receive, send)
                return

        await self.app(scope, receive, send)

    async def _handle_submit(self, scope: Scope, receive: Receive, send: Send) -> None:
        # Extract client IP — prefer X-Forwarded-For from trusted nginx proxy
        headers_map = {k.decode("latin-1").lower(): v.decode("latin-1")
                       for k, v in scope.get("headers", [])}
        xff = headers_map.get("x-forwarded-for", "")
        client_ip = xff.split(",")[0].strip() if xff else (
            scope.get("client", ("unknown",))[0] or "unknown"
        )

        # CSRF / origin check for browser requests
        origin = headers_map.get("origin", "")
        referer = headers_map.get("referer", "")
        if not _origin_allowed(origin, referer):
            logger.warning("Signup rejected: disallowed origin=%r referer=%r ip=%s",
                           origin[:100], referer[:200], client_ip)
            response = JSONResponse(
                {"ok": False, "error": "Request not allowed from this origin."},
                status_code=403,
            )
            await response(scope, receive, send)
            return

        # Per-IP rate limit
        if not _rate_check(client_ip):
            logger.warning("Signup rate-limited: ip=%s", client_ip)
            response = JSONResponse(
                {"ok": False, "error": "Too many signup attempts. Please try again in a minute."},
                status_code=429,
            )
            await response(scope, receive, send)
            return

        # Read request body (cap size to prevent memory exhaustion)
        body = b""
        max_body = 4096  # 4 KB is more than enough for {"email": "..."}
        while True:
            message = await receive()
            body += message.get("body", b"")
            if len(body) > max_body:
                response = JSONResponse(
                    {"ok": False, "error": "Request body too large."},
                    status_code=413,
                )
                await response(scope, receive, send)
                return
            if not message.get("more_body", False):
                break

        try:
            data = json.loads(body)
            email = str(data.get("email", "")).strip().lower()
        except Exception:
            response = JSONResponse({"ok": False, "error": "Invalid request"}, status_code=400)
            await response(scope, receive, send)
            return

        if not _is_valid_email(email):
            response = JSONResponse(
                {"ok": False, "error": "Please enter a valid email address."},
                status_code=400,
            )
            await response(scope, receive, send)
            return

        # Generate key
        api_key = _generate_api_key()
        created = _create_key_in_db(api_key, email)

        if not created:
            # Email already registered — return GENERIC message to prevent
            # email enumeration. Never reveal key prefix or confirm existence.
            logger.info("Signup duplicate attempt: email=%s ip=%s",
                        _mask_email(email), client_ip)
            response = JSONResponse({
                "ok": False,
                "error": "Could not create API key. If you already signed up, "
                         "please check your inbox or contact hello@thinkneo.ai.",
            })
            await response(scope, receive, send)
            return

        # Send email (non-blocking — don't fail if email fails)
        email_sent = _send_welcome_email(email, api_key)

        logger.info("API key created for %s (email_sent=%s, ip=%s)",
                    _mask_email(email), email_sent, client_ip)

        response = JSONResponse({
            "ok": True,
            "api_key": api_key,
            "email_sent": email_sent,
            "message": "Your API key has been created! Check your email for setup instructions.",
        })
        await response(scope, receive, send)
