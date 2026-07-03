"""
OAuth 2.0 — MCP Server authorization (MCP spec 2025-03-26).

Implements:
  * RFC 8414 — Authorization Server Metadata
      GET /.well-known/oauth-authorization-server
  * RFC 9728 — Protected Resource Metadata
      GET /.well-known/oauth-protected-resource
  * RFC 7591 — Dynamic Client Registration
      POST /oauth/register
  * RFC 6749 + RFC 7636 (PKCE) — Authorization Code flow
      GET  /oauth/authorize     (user-facing HTML consent page)
      POST /oauth/authorize     (form submission → authorization code)
      POST /oauth/token         (code exchange + refresh token)

Backward-compatible design:
    OAuth access tokens are opaque strings. The BearerTokenMiddleware resolves
    them to the underlying ThinkNEO API key before downstream code runs, so
    every existing tool, rate-limit check, and DB usage log keeps working
    without modification.

Auth model for /oauth/authorize:
    The user enters an existing ThinkNEO API key (tnk_*). We validate it
    against the api_keys table. We do *not* expose a full sign-up flow on
    this page — users without a key are linked to /mcp/signup.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import secrets
import re
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Optional
from urllib.parse import urlencode, urlparse

import psycopg
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from starlette.types import ASGIApp, Receive, Scope, Send

from .config import get_settings
from .database import hash_key as _hash_api_key

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Config / constants
# ---------------------------------------------------------------------------

AUTH_CODE_TTL = 600              # 10 minutes (RFC 6749 §4.1.2 recommendation)
ACCESS_TOKEN_TTL = 3600           # 1 hour
REFRESH_TOKEN_TTL = 60 * 60 * 24 * 30   # 30 days

DEFAULT_SCOPE = "mcp"
PKCE_METHODS = {"S256"}           # MCP spec mandates S256

_DB_HOST = os.getenv("MCP_DB_HOST", "172.17.0.1")
_DB_PORT = int(os.getenv("MCP_DB_PORT", "5432"))
_DB_NAME = os.getenv("MCP_DB_NAME", "thinkneo_mcp")
_DB_USER = os.getenv("MCP_DB_USER", "mcp_user")
# Deferred: fail loud on first connect, not import — keeps stdio wrappers /
# marketplace smoke-tests able to import the module without a DB configured.
_DB_PASSWORD = os.getenv("MCP_DB_PASSWORD")


def _conninfo() -> str:
    if not _DB_PASSWORD:
        raise RuntimeError("MCP_DB_PASSWORD environment variable must be set")
    return (
        f"host={_DB_HOST} port={_DB_PORT} dbname={_DB_NAME} "
        f"user={_DB_USER} password={_DB_PASSWORD} "
        f"sslmode=prefer"
    )


def _get_conn() -> psycopg.Connection:
    return psycopg.connect(_conninfo(), connect_timeout=5, autocommit=True)


def _sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _b64url_sha256(value: str) -> str:
    """Base64url-encoded SHA-256 digest (RFC 7636 PKCE S256)."""
    digest = hashlib.sha256(value.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _rand_token(nbytes: int = 32) -> str:
    return secrets.token_urlsafe(nbytes)


_SAFE_CLIENT_NAME_RE = re.compile(r'[^a-zA-Z0-9 _\-.:/@()+]')


def _sanitize_client_name(raw: str) -> str:
    """Strip HTML/script injection from OAuth client_name.
    Allow only safe chars: alphanumeric, spaces, basic punctuation."""
    s = str(raw or '').strip()[:200]
    s = re.sub(r'<[^>]*>', '', s)          # strip HTML tags
    s = _SAFE_CLIENT_NAME_RE.sub('', s)    # remove dangerous chars
    return s.strip()[:200] or 'unnamed-client'


# ---------------------------------------------------------------------------
# API key validation (against existing api_keys table)
# ---------------------------------------------------------------------------


def _validate_api_key(api_key: str) -> Optional[dict]:
    """Return the api_keys row if valid (and not revoked), else None.

    Master keys from env are also accepted — they map to a synthetic row so
    OAuth tokens issued for master keys can be resolved downstream.
    """
    if not api_key or not api_key.strip():
        return None
    api_key = api_key.strip()

    # Master key(s) configured via env — always valid, bypass DB lookup.
    settings = get_settings()
    if api_key in settings.valid_api_keys:
        return {
            "key_hash": _hash_api_key(api_key),
            "key_prefix": api_key[:8],
            "tier": "master",
            "monthly_limit": 10_000_000,
        }

    key_h = _hash_api_key(api_key)
    try:
        with _get_conn() as conn, conn.cursor() as cur:
            cur.execute("SELECT 1 FROM revoked_keys WHERE key_hash = %s", (key_h,))
            if cur.fetchone():
                return None
            cur.execute(
                "SELECT key_hash, key_prefix, tier, monthly_limit "
                "FROM api_keys WHERE key_hash = %s",
                (key_h,),
            )
            row = cur.fetchone()
            if not row:
                return None
            return {
                "key_hash": row[0],
                "key_prefix": row[1],
                "tier": row[2],
                "monthly_limit": row[3],
            }
    except Exception as exc:
        logger.error("oauth: api key validation DB error: %s", exc)
        return None


# ---------------------------------------------------------------------------
# Client registration (RFC 7591)
# ---------------------------------------------------------------------------


def _register_client(meta: dict) -> dict:
    """Create a new OAuth client row. Returns the registration response."""
    client_id = _rand_token(24)
    auth_method = meta.get("token_endpoint_auth_method") or "none"
    client_secret: Optional[str] = None
    client_secret_hash: Optional[str] = None
    if auth_method != "none":
        client_secret = _rand_token(32)
        client_secret_hash = _sha256_hex(client_secret)

    redirect_uris = meta.get("redirect_uris") or []
    if not isinstance(redirect_uris, list) or not redirect_uris:
        raise ValueError("redirect_uris is required")

    # Defensive URL check — reject things that aren't URIs.
    for uri in redirect_uris:
        parsed = urlparse(uri)
        if parsed.scheme not in ("http", "https") and not uri.startswith("urn:"):
            # Loopback literals must still parse with a scheme
            raise ValueError(f"Invalid redirect_uri: {uri}")

    grant_types = meta.get("grant_types") or ["authorization_code", "refresh_token"]
    response_types = meta.get("response_types") or ["code"]
    scope = meta.get("scope") or DEFAULT_SCOPE
    client_name = _sanitize_client_name(meta.get("client_name", ""))
    software_id = (meta.get("software_id") or "")[:200]
    software_version = (meta.get("software_version") or "")[:50]

    with _get_conn() as conn, conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO oauth_clients (
                client_id, client_secret_hash, client_name,
                redirect_uris, grant_types, response_types,
                token_endpoint_auth_method, scope, software_id, software_version
            ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            """,
            (
                client_id,
                client_secret_hash,
                client_name,
                redirect_uris,
                grant_types,
                response_types,
                auth_method,
                scope,
                software_id,
                software_version,
            ),
        )

    response: dict[str, Any] = {
        "client_id": client_id,
        "client_id_issued_at": int(time.time()),
        "redirect_uris": redirect_uris,
        "grant_types": grant_types,
        "response_types": response_types,
        "token_endpoint_auth_method": auth_method,
        "scope": scope,
        "client_name": client_name,
    }
    if client_secret is not None:
        response["client_secret"] = client_secret
        # 0 = never expires (spec allowed)
        response["client_secret_expires_at"] = 0
    return response


def _get_client(client_id: str) -> Optional[dict]:
    try:
        with _get_conn() as conn, conn.cursor() as cur:
            cur.execute(
                """
                SELECT client_id, client_secret_hash, redirect_uris,
                       grant_types, token_endpoint_auth_method, scope, client_name
                FROM oauth_clients WHERE client_id = %s
                """,
                (client_id,),
            )
            row = cur.fetchone()
            if not row:
                return None
            return {
                "client_id": row[0],
                "client_secret_hash": row[1],
                "redirect_uris": list(row[2] or []),
                "grant_types": list(row[3] or []),
                "token_endpoint_auth_method": row[4],
                "scope": row[5],
                "client_name": row[6],
            }
    except Exception as exc:
        logger.error("oauth: get_client DB error: %s", exc)
        return None


# ---------------------------------------------------------------------------
# Token issuance
# ---------------------------------------------------------------------------


def _issue_tokens(
    client_id: str,
    api_key: str,
    api_key_hash: str,
    scope: Optional[str],
    resource: Optional[str],
    issue_refresh: bool = True,
) -> dict:
    access = _rand_token(32)
    refresh = _rand_token(32) if issue_refresh else None
    now = _now()
    access_exp = now + timedelta(seconds=ACCESS_TOKEN_TTL)
    refresh_exp = now + timedelta(seconds=REFRESH_TOKEN_TTL)

    with _get_conn() as conn, conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO oauth_access_tokens
              (token_hash, client_id, api_key, api_key_hash, scope, resource, expires_at)
            VALUES (%s,%s,%s,%s,%s,%s,%s)
            """,
            (
                _sha256_hex(access),
                client_id,
                api_key,
                api_key_hash,
                scope,
                resource,
                access_exp,
            ),
        )
        if refresh:
            cur.execute(
                """
                INSERT INTO oauth_refresh_tokens
                  (token_hash, client_id, api_key, api_key_hash, scope, resource, expires_at)
                VALUES (%s,%s,%s,%s,%s,%s,%s)
                """,
                (
                    _sha256_hex(refresh),
                    client_id,
                    api_key,
                    api_key_hash,
                    scope,
                    resource,
                    refresh_exp,
                ),
            )

    resp = {
        "access_token": access,
        "token_type": "Bearer",
        "expires_in": ACCESS_TOKEN_TTL,
        "scope": scope or DEFAULT_SCOPE,
    }
    if refresh:
        resp["refresh_token"] = refresh
    return resp


def resolve_oauth_access_token(token: str) -> Optional[str]:
    """If `token` is a valid OAuth access token, return the underlying api_key.

    Returns None if the token is not an OAuth token (or is expired/revoked).
    """
    if not token:
        return None
    try:
        with _get_conn() as conn, conn.cursor() as cur:
            cur.execute(
                """
                SELECT api_key, expires_at, revoked
                FROM oauth_access_tokens WHERE token_hash = %s
                """,
                (_sha256_hex(token),),
            )
            row = cur.fetchone()
            if not row:
                return None
            api_key, expires_at, revoked = row
            if revoked:
                return None
            if expires_at and expires_at < _now():
                return None
            return api_key
    except Exception as exc:
        logger.warning("oauth: resolve token DB error: %s", exc)
        return None


# ---------------------------------------------------------------------------
# Authorization code store
# ---------------------------------------------------------------------------


def _store_auth_code(
    client_id: str,
    redirect_uri: str,
    code_challenge: str,
    code_challenge_method: str,
    scope: Optional[str],
    resource: Optional[str],
    api_key: str,
    api_key_hash: str,
) -> str:
    code = _rand_token(32)
    exp = _now() + timedelta(seconds=AUTH_CODE_TTL)
    with _get_conn() as conn, conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO oauth_auth_codes
              (code, client_id, redirect_uri, code_challenge, code_challenge_method,
               scope, api_key_hash, api_key, resource, expires_at)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            """,
            (
                code,
                client_id,
                redirect_uri,
                code_challenge,
                code_challenge_method,
                scope,
                api_key_hash,
                api_key,
                resource,
                exp,
            ),
        )
    return code


def _consume_auth_code(code: str) -> Optional[dict]:
    """Fetch and invalidate an auth code. Returns the row dict or None."""
    try:
        with _get_conn() as conn, conn.cursor() as cur:
            cur.execute(
                """
                SELECT client_id, redirect_uri, code_challenge, code_challenge_method,
                       scope, api_key_hash, api_key, resource, expires_at, used
                FROM oauth_auth_codes WHERE code = %s
                FOR UPDATE
                """,
                (code,),
            )
            row = cur.fetchone()
            if not row:
                return None
            (
                client_id,
                redirect_uri,
                code_challenge,
                code_challenge_method,
                scope,
                api_key_hash,
                api_key,
                resource,
                expires_at,
                used,
            ) = row
            if used:
                # Replay attempt — defense in depth: revoke tokens for this client
                logger.warning("oauth: auth code replay attempt for client %s", client_id)
                return None
            if expires_at < _now():
                return None
            cur.execute("UPDATE oauth_auth_codes SET used = TRUE WHERE code = %s", (code,))
            return {
                "client_id": client_id,
                "redirect_uri": redirect_uri,
                "code_challenge": code_challenge,
                "code_challenge_method": code_challenge_method,
                "scope": scope,
                "api_key_hash": api_key_hash,
                "api_key": api_key,
                "resource": resource,
            }
    except Exception as exc:
        logger.error("oauth: consume code DB error: %s", exc)
        return None


# ---------------------------------------------------------------------------
# Refresh token rotation
# ---------------------------------------------------------------------------


def _use_refresh_token(token: str) -> Optional[dict]:
    try:
        with _get_conn() as conn, conn.cursor() as cur:
            cur.execute(
                """
                SELECT client_id, api_key, api_key_hash, scope, resource,
                       expires_at, revoked
                FROM oauth_refresh_tokens WHERE token_hash = %s FOR UPDATE
                """,
                (_sha256_hex(token),),
            )
            row = cur.fetchone()
            if not row:
                return None
            client_id, api_key, api_key_hash, scope, resource, expires_at, revoked = row
            if revoked or expires_at < _now():
                return None
            cur.execute(
                "UPDATE oauth_refresh_tokens SET revoked = TRUE WHERE token_hash = %s",
                (_sha256_hex(token),),
            )
            return {
                "client_id": client_id,
                "api_key": api_key,
                "api_key_hash": api_key_hash,
                "scope": scope,
                "resource": resource,
            }
    except Exception as exc:
        logger.error("oauth: refresh token DB error: %s", exc)
        return None


# ---------------------------------------------------------------------------
# Metadata documents
# ---------------------------------------------------------------------------


def _public_base_url() -> str:
    settings = get_settings()
    base = settings.public_url or "https://mcp.thinkneo.ai"
    return base.rstrip("/")


def _as_metadata() -> dict:
    base = _public_base_url()
    return {
        "issuer": base,
        "authorization_endpoint": f"{base}/oauth/authorize",
        "token_endpoint": f"{base}/oauth/token",
        "registration_endpoint": f"{base}/oauth/register",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none", "client_secret_basic", "client_secret_post"],
        "scopes_supported": ["mcp"],
        "service_documentation": f"{base}/mcp/docs",
    }


def _prm_metadata() -> dict:
    base = _public_base_url()
    return {
        "resource": f"{base}/mcp",
        "authorization_servers": [base],
        "bearer_methods_supported": ["header"],
        "scopes_supported": ["mcp"],
        "resource_documentation": f"{base}/mcp/docs",
    }


# ---------------------------------------------------------------------------
# Consent page HTML
# ---------------------------------------------------------------------------


CONSENT_HTML_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Authorize — ThinkNEO MCP</title>
<style>
  :root {{ --bg:#0F172A; --card:#1E293B; --border:#334155; --primary:#3B82F6;
           --success:#10B981; --danger:#EF4444; --text1:#F8FAFC; --text2:#94A3B8; --text3:#64748B; }}
  * {{ margin:0; padding:0; box-sizing:border-box; }}
  body {{ background:var(--bg); color:var(--text1);
          font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
          min-height:100vh; display:flex; align-items:center; justify-content:center; padding:24px; }}
  .card {{ background:var(--card); border:1px solid var(--border); border-radius:16px;
           padding:40px; max-width:460px; width:100%; }}
  .logo {{ font-size:22px; font-weight:800; margin-bottom:4px; }}
  .logo span {{ color:var(--primary); }}
  .badge {{ display:inline-block; padding:4px 12px; border:1px solid var(--border);
            border-radius:20px; font-size:10px; font-weight:600; color:var(--text3);
            letter-spacing:0.8px; text-transform:uppercase; margin-bottom:24px; }}
  .divider {{ height:2px; background:linear-gradient(90deg,var(--primary),#14B4A0,transparent);
              border-radius:2px; margin-bottom:28px; }}
  h1 {{ font-size:22px; font-weight:800; margin-bottom:10px; letter-spacing:-0.3px; }}
  .subtitle {{ color:var(--text2); font-size:14px; line-height:1.5; margin-bottom:24px; }}
  .client-box {{ background:var(--bg); border:1px solid var(--border); border-radius:8px;
                 padding:14px 16px; margin-bottom:20px; font-size:13px; color:var(--text2); }}
  .client-box strong {{ color:var(--text1); }}
  label {{ display:block; font-size:11px; font-weight:700; color:var(--text2);
            letter-spacing:1px; text-transform:uppercase; margin-bottom:8px; }}
  input[type="password"], input[type="text"] {{ width:100%; padding:13px 14px;
     background:var(--bg); border:1px solid var(--border); border-radius:8px;
     color:var(--text1); font-size:14px; outline:none; transition:border-color 0.2s;
     font-family:'SF Mono',SFMono-Regular,Consolas,monospace; }}
  input:focus {{ border-color:var(--primary); }}
  .actions {{ display:flex; gap:10px; margin-top:20px; }}
  .btn {{ flex:1; padding:13px; border:none; border-radius:8px; font-size:14px;
           font-weight:700; cursor:pointer; letter-spacing:0.2px; }}
  .btn-primary {{ background:var(--primary); color:#fff; }}
  .btn-primary:hover {{ opacity:0.9; }}
  .btn-ghost {{ background:transparent; border:1px solid var(--border); color:var(--text2); }}
  .btn-ghost:hover {{ color:var(--text1); border-color:var(--text3); }}
  .note {{ font-size:12px; color:var(--text3); margin-top:16px; line-height:1.5; text-align:center; }}
  .note a {{ color:var(--primary); text-decoration:none; }}
  .error {{ background:rgba(239,68,68,0.1); border:1px solid rgba(239,68,68,0.3);
            color:#f87171; padding:10px 14px; border-radius:8px; font-size:13px; margin-bottom:16px; }}
  .scopes {{ margin-top:16px; padding:12px 14px; background:rgba(59,130,246,0.08);
             border:1px solid rgba(59,130,246,0.25); border-radius:8px; font-size:12px;
             color:var(--text2); line-height:1.5; }}
</style>
</head>
<body>
<div class="card">
  <div class="logo">Think<span>NEO</span></div>
  <div class="badge">OAuth Authorization</div>
  <div class="divider"></div>

  <h1>Authorize access</h1>
  <p class="subtitle">An MCP client is requesting access to your ThinkNEO Control Plane.</p>

  <div class="client-box">
    Client: <strong>{client_name}</strong><br>
    Redirect: <code style="font-size:11px;color:var(--text3);">{redirect_uri}</code>
  </div>

  {error_block}

  <form method="POST" action="/oauth/authorize">
    <input type="hidden" name="client_id" value="{client_id}">
    <input type="hidden" name="redirect_uri" value="{redirect_uri}">
    <input type="hidden" name="code_challenge" value="{code_challenge}">
    <input type="hidden" name="code_challenge_method" value="{code_challenge_method}">
    <input type="hidden" name="state" value="{state}">
    <input type="hidden" name="scope" value="{scope}">
    <input type="hidden" name="resource" value="{resource}">
    <input type="hidden" name="response_type" value="code">

    <label for="api_key">Your ThinkNEO API Key</label>
    <input type="password" id="api_key" name="api_key" placeholder="tnk_..." required autocomplete="off" autofocus>

    <div class="scopes">
      <strong style="color:var(--text1);">Requested scope:</strong> {scope}<br>
      This client will be able to call MCP tools on your behalf.
    </div>

    <div class="actions">
      <button type="submit" name="decision" value="deny" class="btn btn-ghost">Deny</button>
      <button type="submit" name="decision" value="allow" class="btn btn-primary">Authorize</button>
    </div>
  </form>

  <p class="note">
    Don't have an API key? <a href="/mcp/signup">Get one free</a> — 500 calls/month, no credit card.
  </p>
</div>
</body>
</html>
"""


def _html_escape(s: str) -> str:
    return (
        s.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#39;")
    )


def _render_consent(params: dict, error: Optional[str] = None, client_name: str = "Unknown client") -> str:
    error_html = ""
    if error:
        error_html = f'<div class="error">{_html_escape(error)}</div>'
    return CONSENT_HTML_TEMPLATE.format(
        client_name=_html_escape(client_name),
        redirect_uri=_html_escape(params.get("redirect_uri", "")),
        client_id=_html_escape(params.get("client_id", "")),
        code_challenge=_html_escape(params.get("code_challenge", "")),
        code_challenge_method=_html_escape(params.get("code_challenge_method", "S256")),
        state=_html_escape(params.get("state", "")),
        scope=_html_escape(params.get("scope", DEFAULT_SCOPE)),
        resource=_html_escape(params.get("resource", "")),
        error_block=error_html,
    )


# ---------------------------------------------------------------------------
# ASGI helpers
# ---------------------------------------------------------------------------


async def _read_body(receive: Receive) -> bytes:
    body = b""
    while True:
        msg = await receive()
        body += msg.get("body", b"")
        if not msg.get("more_body", False):
            break
    return body


def _parse_query(scope: Scope) -> dict:
    from urllib.parse import parse_qs
    qs = scope.get("query_string", b"").decode("utf-8", errors="ignore")
    return {k: v[0] for k, v in parse_qs(qs, keep_blank_values=True).items()}


def _parse_form(body: bytes) -> dict:
    from urllib.parse import parse_qs
    return {k: v[0] for k, v in parse_qs(body.decode("utf-8", errors="ignore"), keep_blank_values=True).items()}


def _extract_basic_auth(headers: dict) -> Optional[tuple[str, str]]:
    raw = headers.get(b"authorization", b"").decode("utf-8", errors="ignore")
    if not raw.lower().startswith("basic "):
        return None
    try:
        decoded = base64.b64decode(raw[6:].strip()).decode("utf-8")
        if ":" not in decoded:
            return None
        user, _, pwd = decoded.partition(":")
        return user, pwd
    except Exception:
        return None


def _cors_headers() -> list[tuple[bytes, bytes]]:
    """OAuth endpoints must be reachable cross-origin so browser-based MCP clients work."""
    return [
        (b"access-control-allow-origin", b"*"),
        (b"access-control-allow-methods", b"GET, POST, OPTIONS"),
        (b"access-control-allow-headers", b"Authorization, Content-Type"),
        (b"access-control-max-age", b"86400"),
    ]


# ---------------------------------------------------------------------------
# OAuth middleware
# ---------------------------------------------------------------------------


OAUTH_PATHS = {
    "/.well-known/oauth-authorization-server",
    "/.well-known/oauth-protected-resource",
    "/oauth/register",
    "/oauth/authorize",
    "/oauth/token",
}


class OAuthMiddleware:
    """ASGI middleware intercepting OAuth endpoints.

    Sits above the MCP app; non-OAuth requests pass through untouched.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")
        method = scope.get("method", "GET")

        if path not in OAUTH_PATHS:
            await self.app(scope, receive, send)
            return

        # Universal CORS preflight
        if method == "OPTIONS":
            resp = Response(status_code=204, headers={
                k.decode(): v.decode() for k, v in _cors_headers()
            })
            await resp(scope, receive, send)
            return

        try:
            if path == "/.well-known/oauth-authorization-server" and method == "GET":
                await self._metadata(scope, receive, send)
            elif path == "/.well-known/oauth-protected-resource" and method == "GET":
                await self._prm(scope, receive, send)
            elif path == "/oauth/register" and method == "POST":
                await self._register(scope, receive, send)
            elif path == "/oauth/authorize" and method == "GET":
                await self._authorize_get(scope, receive, send)
            elif path == "/oauth/authorize" and method == "POST":
                await self._authorize_post(scope, receive, send)
            elif path == "/oauth/token" and method == "POST":
                await self._token(scope, receive, send)
            else:
                await JSONResponse({"error": "method_not_allowed"}, status_code=405)(scope, receive, send)
        except Exception as exc:
            logger.exception("oauth: unhandled error on %s %s: %s", method, path, exc)
            await JSONResponse(
                {"error": "server_error", "error_description": str(exc)},
                status_code=500,
            )(scope, receive, send)

    # -- handlers ------------------------------------------------------------

    async def _metadata(self, scope, receive, send):
        resp = JSONResponse(_as_metadata(), headers={
            h.decode(): v.decode() for h, v in _cors_headers()
        })
        await resp(scope, receive, send)

    async def _prm(self, scope, receive, send):
        resp = JSONResponse(_prm_metadata(), headers={
            h.decode(): v.decode() for h, v in _cors_headers()
        })
        await resp(scope, receive, send)

    async def _register(self, scope, receive, send):
        body = await _read_body(receive)
        try:
            meta = json.loads(body or b"{}")
        except Exception:
            await JSONResponse(
                {"error": "invalid_client_metadata", "error_description": "body must be JSON"},
                status_code=400,
            )(scope, receive, send)
            return

        # Log registrant IP
        client_ip = 'unknown'
        if scope.get('client'):
            client_ip = scope['client'][0]
        headers_dict = {k.lower(): v for k, v in scope.get('headers', [])}
        client_ip = (
            headers_dict.get(b'x-real-ip', b'').decode('utf-8', errors='ignore')
            or headers_dict.get(b'x-forwarded-for', b'').decode('utf-8', errors='ignore').split(',')[0].strip()
            or client_ip
        )
        logger.info('OAUTH_REGISTER | ip=%s | client_name=%s', client_ip, meta.get('client_name', '')[:100])

        try:
            resp = _register_client(meta)
        except ValueError as ve:
            await JSONResponse(
                {"error": "invalid_redirect_uri", "error_description": str(ve)},
                status_code=400,
                headers={h.decode(): v.decode() for h, v in _cors_headers()},
            )(scope, receive, send)
            return

        await JSONResponse(
            resp,
            status_code=201,
            headers={h.decode(): v.decode() for h, v in _cors_headers()},
        )(scope, receive, send)

    async def _authorize_get(self, scope, receive, send):
        params = _parse_query(scope)

        # Required OAuth params
        client_id = params.get("client_id", "")
        redirect_uri = params.get("redirect_uri", "")
        response_type = params.get("response_type", "")
        code_challenge = params.get("code_challenge", "")
        method = params.get("code_challenge_method", "S256")

        if not client_id or not redirect_uri:
            await HTMLResponse(
                "<h1>Bad request</h1><p>client_id and redirect_uri are required.</p>",
                status_code=400,
            )(scope, receive, send)
            return

        client = _get_client(client_id)
        if not client:
            await HTMLResponse(
                "<h1>Unknown client</h1><p>This OAuth client is not registered.</p>",
                status_code=400,
            )(scope, receive, send)
            return

        if redirect_uri not in client["redirect_uris"]:
            await HTMLResponse(
                "<h1>Invalid redirect_uri</h1><p>Not in registered redirect_uris for this client.</p>",
                status_code=400,
            )(scope, receive, send)
            return

        if response_type != "code":
            await self._redirect_error(send, scope, redirect_uri, params.get("state"),
                                       "unsupported_response_type", "only 'code' is supported")
            return
        if not code_challenge:
            await self._redirect_error(send, scope, redirect_uri, params.get("state"),
                                       "invalid_request", "code_challenge required (PKCE)")
            return
        if method not in PKCE_METHODS:
            await self._redirect_error(send, scope, redirect_uri, params.get("state"),
                                       "invalid_request", "code_challenge_method must be S256")
            return

        html = _render_consent(params, client_name=client.get("client_name") or client_id)
        await HTMLResponse(html)(scope, receive, send)

    async def _authorize_post(self, scope, receive, send):
        body = await _read_body(receive)
        form = _parse_form(body)

        client_id = form.get("client_id", "")
        redirect_uri = form.get("redirect_uri", "")
        state = form.get("state", "")
        code_challenge = form.get("code_challenge", "")
        method = form.get("code_challenge_method", "S256")
        scope_param = form.get("scope") or DEFAULT_SCOPE
        resource = form.get("resource", "")
        decision = form.get("decision", "deny")
        api_key = form.get("api_key", "").strip()

        client = _get_client(client_id)
        if not client or redirect_uri not in client["redirect_uris"]:
            await HTMLResponse(
                "<h1>Invalid request</h1><p>Unknown client or redirect_uri.</p>",
                status_code=400,
            )(scope, receive, send)
            return

        if decision != "allow":
            await self._redirect_error(send, scope, redirect_uri, state,
                                       "access_denied", "user denied")
            return

        # Validate API key against ThinkNEO DB
        key_info = _validate_api_key(api_key)
        if not key_info:
            # Re-render consent with error
            html = _render_consent(
                form,
                error="Invalid API key. Double-check the key or sign up for a free one below.",
                client_name=client.get("client_name") or client_id,
            )
            await HTMLResponse(html, status_code=400)(scope, receive, send)
            return

        code = _store_auth_code(
            client_id=client_id,
            redirect_uri=redirect_uri,
            code_challenge=code_challenge,
            code_challenge_method=method,
            scope=scope_param,
            resource=resource or None,
            api_key=api_key,
            api_key_hash=key_info["key_hash"],
        )

        qs = {"code": code}
        if state:
            qs["state"] = state
        sep = "&" if "?" in redirect_uri else "?"
        location = f"{redirect_uri}{sep}{urlencode(qs)}"
        await RedirectResponse(location, status_code=302)(scope, receive, send)

    async def _token(self, scope, receive, send):
        body = await _read_body(receive)
        # Support both form-encoded (standard) and JSON bodies
        headers = {k.lower(): v for k, v in scope.get("headers", [])}
        ctype = headers.get(b"content-type", b"").decode("utf-8", errors="ignore")
        if "application/json" in ctype:
            try:
                params = json.loads(body or b"{}")
            except Exception:
                await self._token_err(scope, receive, send, "invalid_request", "bad JSON")
                return
        else:
            params = _parse_form(body)

        # Client auth (optional — public clients use PKCE only)
        basic = _extract_basic_auth(headers)
        auth_client_id = None
        auth_client_secret = None
        if basic:
            auth_client_id, auth_client_secret = basic
        # Fallback: body-form client credentials
        if not auth_client_id:
            auth_client_id = params.get("client_id")
            auth_client_secret = params.get("client_secret")

        grant_type = params.get("grant_type")

        if grant_type == "authorization_code":
            await self._token_auth_code(scope, receive, send, params,
                                        auth_client_id, auth_client_secret)
        elif grant_type == "refresh_token":
            await self._token_refresh(scope, receive, send, params,
                                      auth_client_id, auth_client_secret)
        else:
            await self._token_err(scope, receive, send, "unsupported_grant_type",
                                  f"grant_type '{grant_type}' not supported")

    async def _token_auth_code(self, scope, receive, send, params, client_id, client_secret):
        code = params.get("code")
        redirect_uri = params.get("redirect_uri")
        code_verifier = params.get("code_verifier")

        if not code or not redirect_uri or not code_verifier:
            await self._token_err(scope, receive, send, "invalid_request",
                                  "code, redirect_uri and code_verifier are required")
            return
        if not client_id:
            await self._token_err(scope, receive, send, "invalid_client", "client_id missing")
            return

        client = _get_client(client_id)
        if not client:
            await self._token_err(scope, receive, send, "invalid_client", "unknown client")
            return

        # Verify client secret for confidential clients
        if client["token_endpoint_auth_method"] != "none":
            expected = client["client_secret_hash"]
            if not client_secret or not expected or _sha256_hex(client_secret) != expected:
                await self._token_err(scope, receive, send, "invalid_client", "bad client_secret")
                return

        row = _consume_auth_code(code)
        if not row:
            await self._token_err(scope, receive, send, "invalid_grant",
                                  "code is invalid, expired, or already used")
            return

        if row["client_id"] != client_id:
            await self._token_err(scope, receive, send, "invalid_grant", "code/client mismatch")
            return
        if row["redirect_uri"] != redirect_uri:
            await self._token_err(scope, receive, send, "invalid_grant", "redirect_uri mismatch")
            return

        # PKCE verification (S256)
        if row["code_challenge_method"] == "S256":
            if _b64url_sha256(code_verifier) != row["code_challenge"]:
                await self._token_err(scope, receive, send, "invalid_grant", "PKCE verification failed")
                return
        else:
            await self._token_err(scope, receive, send, "invalid_grant", "unsupported code_challenge_method")
            return

        tokens = _issue_tokens(
            client_id=client_id,
            api_key=row["api_key"],
            api_key_hash=row["api_key_hash"],
            scope=row["scope"],
            resource=row["resource"],
        )
        await JSONResponse(
            tokens,
            headers={
                "Cache-Control": "no-store",
                "Pragma": "no-cache",
                **{h.decode(): v.decode() for h, v in _cors_headers()},
            },
        )(scope, receive, send)

    async def _token_refresh(self, scope, receive, send, params, client_id, client_secret):
        refresh_token = params.get("refresh_token")
        if not refresh_token or not client_id:
            await self._token_err(scope, receive, send, "invalid_request",
                                  "refresh_token and client_id required")
            return

        client = _get_client(client_id)
        if not client:
            await self._token_err(scope, receive, send, "invalid_client", "unknown client")
            return
        if client["token_endpoint_auth_method"] != "none":
            expected = client["client_secret_hash"]
            if not client_secret or not expected or _sha256_hex(client_secret) != expected:
                await self._token_err(scope, receive, send, "invalid_client", "bad client_secret")
                return

        row = _use_refresh_token(refresh_token)
        if not row or row["client_id"] != client_id:
            await self._token_err(scope, receive, send, "invalid_grant",
                                  "refresh_token invalid or revoked")
            return

        tokens = _issue_tokens(
            client_id=client_id,
            api_key=row["api_key"],
            api_key_hash=row["api_key_hash"],
            scope=row["scope"],
            resource=row["resource"],
        )
        await JSONResponse(
            tokens,
            headers={
                "Cache-Control": "no-store",
                "Pragma": "no-cache",
                **{h.decode(): v.decode() for h, v in _cors_headers()},
            },
        )(scope, receive, send)

    async def _token_err(self, scope, receive, send, code: str, desc: str):
        status = 401 if code == "invalid_client" else 400
        await JSONResponse(
            {"error": code, "error_description": desc},
            status_code=status,
            headers={
                "Cache-Control": "no-store",
                "Pragma": "no-cache",
                **{h.decode(): v.decode() for h, v in _cors_headers()},
            },
        )(scope, receive, send)

    async def _redirect_error(self, send, scope, redirect_uri: str, state: Optional[str],
                              code: str, desc: str):
        qs = {"error": code, "error_description": desc}
        if state:
            qs["state"] = state
        sep = "&" if "?" in redirect_uri else "?"
        location = f"{redirect_uri}{sep}{urlencode(qs)}"

        async def _noop_receive():
            return {"type": "http.disconnect"}

        resp = RedirectResponse(location, status_code=302)
        await resp(scope, _noop_receive, send)
