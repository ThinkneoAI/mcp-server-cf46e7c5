"""
Brain API client — connects MCP tools to the live neo-brain-api gateway.
Uses internal endpoints (no auth required) for metrics and status.
Uses tenant endpoints (with project API key) only when a valid tenant key is available.

Auto-injects tenant_id for /v1/tenant/* and /v1/audit/* and /v1/optimization/*
routes that require it as a query parameter.
"""
from __future__ import annotations

import json
import logging
import os
from typing import Any, Optional

import httpx

logger = logging.getLogger(__name__)

BRAIN_API_BASE = os.environ.get("BRAIN_API_BASE", os.environ.get("THINKNEO_API_BASE_URL", "http://neo-brain-api:8080"))
BRAIN_API_TIMEOUT = float(os.environ.get("BRAIN_API_TIMEOUT", "15"))
BRAIN_TENANT_ID = os.environ.get("THINKNEO_TENANT_ID", "thinkneo-official")

# Paths that require tenant_id as a query parameter
_TENANT_ID_REQUIRED_PREFIXES = (
    "/v1/tenant/",
    "/v1/audit/events",
    "/v1/optimization/",
)


def _inject_tenant_id(path: str, params: Optional[dict]) -> dict:
    """Auto-inject tenant_id for Brain API routes that require it."""
    if params is None:
        params = {}
    if "tenant_id" not in params:
        for prefix in _TENANT_ID_REQUIRED_PREFIXES:
            if path.startswith(prefix):
                params["tenant_id"] = BRAIN_TENANT_ID
                break
    return params


async def brain_get(path: str, params: Optional[dict] = None, token: Optional[str] = None) -> dict[str, Any]:
    """GET request to brain API. For /v1/internal/* paths, no auth is sent."""
    url = f"{BRAIN_API_BASE}{path}"
    headers = {"Accept": "application/json"}
    # Only send auth for non-internal endpoints
    if token and "/internal/" not in path:
        headers["Authorization"] = f"Bearer {token}"
    params = _inject_tenant_id(path, params)
    try:
        async with httpx.AsyncClient(timeout=BRAIN_API_TIMEOUT, verify=False) as client:  # nosec B501 — internal-only brain gateway (http://neo-brain-api), not internet-facing
            resp = await client.get(url, params=params, headers=headers)
            if resp.status_code == 200:
                return resp.json()
            return {"_error": True, "status": resp.status_code, "detail": resp.text[:500]}
    except Exception as exc:
        logger.warning("brain_get %s failed: %s", path, exc)
        return {"_error": True, "status": 0, "detail": str(exc)}


async def brain_post(path: str, body: Optional[dict] = None, token: Optional[str] = None) -> dict[str, Any]:
    """POST request to brain API."""
    url = f"{BRAIN_API_BASE}{path}"
    headers = {"Accept": "application/json", "Content-Type": "application/json"}
    if token and "/internal/" not in path:
        headers["Authorization"] = f"Bearer {token}"
    # For POST, inject tenant_id into the body if applicable
    if body is None:
        body = {}
    if "tenant_id" not in body:
        for prefix in _TENANT_ID_REQUIRED_PREFIXES:
            if path.startswith(prefix):
                body["tenant_id"] = BRAIN_TENANT_ID
                break
    try:
        async with httpx.AsyncClient(timeout=BRAIN_API_TIMEOUT, verify=False) as client:  # nosec B501 — internal-only brain gateway (http://neo-brain-api), not internet-facing
            resp = await client.post(url, json=body, headers=headers)
            if resp.status_code in (200, 201):
                return resp.json()
            return {"_error": True, "status": resp.status_code, "detail": resp.text[:500]}
    except Exception as exc:
        logger.warning("brain_post %s failed: %s", path, exc)
        return {"_error": True, "status": 0, "detail": str(exc)}


def is_error(result: dict) -> bool:
    return bool(result.get("_error"))
