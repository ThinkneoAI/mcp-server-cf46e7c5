"""
NVIDIA NIM provider compatibility tests.

Models verified 2026-04-25:
- nvidia/llama-3.3-nemotron-super-49b-v1 (Nemotron Super — current flagship)
- nvidia/nemotron-mini-4b-instruct

Source: https://build.nvidia.com/nvidia
Note: NVIDIA NIM uses OpenAI-compatible API format.
Note: nvidia/llama-3.1-nemotron-70b-instruct deprecated (404 as of 2026-04-25).
"""

import json
import time
import httpx
import pytest
from .conftest import get_key, measure_call, log_latency, validate_chat_response, check_status

API_URL = "https://integrate.api.nvidia.com/v1/chat/completions"

MODELS = [
    "nvidia/llama-3.3-nemotron-super-49b-v1",
    "nvidia/nemotron-mini-4b-instruct",
]

# Nemotron Super 49B cold-starts around ~30-60s under load. A 60s ceiling covers
# real cold starts without letting hangs pin the CI for minutes.
_CHAT_TIMEOUT = 60

# Provider-side transient conditions: 429 = quota, 503 = overloaded, plus the
# httpx read/connect timeouts. None is a compatibility break — retry once, then
# skip. A 404 decommission still hard-fails via check_status.
_TRANSIENT_STATUSES = (429, 503)
_TRANSIENT_EXCS = (httpx.ReadTimeout, httpx.ConnectTimeout, httpx.RemoteProtocolError)


@pytest.fixture
def api_key():
    return get_key("NVIDIA_API_KEY")


def _chat(api_key: str, model: str, text: str = "Say 'OK' and nothing else.") -> tuple[dict, float]:
    def call():
        resp = httpx.post(API_URL, json={
            "model": model,
            "max_tokens": 50,
            "messages": [{"role": "user", "content": text}],
        }, headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }, timeout=_CHAT_TIMEOUT)
        return resp

    def _run_with_retry():
        try:
            resp, latency = measure_call(call)
        except _TRANSIENT_EXCS as exc:
            time.sleep(2)
            try:
                resp, latency = measure_call(call)
            except _TRANSIENT_EXCS as retry_exc:
                pytest.skip(f"nvidia transient timeout ({model}): {retry_exc!r}")
        if resp.status_code in _TRANSIENT_STATUSES:
            time.sleep(2)
            resp, latency = measure_call(call)
            if resp.status_code in _TRANSIENT_STATUSES:
                pytest.skip(f"nvidia transient status ({model}): {resp.status_code}")
        check_status(resp, "nvidia")
        return resp.json(), latency

    return _run_with_retry()


@pytest.mark.parametrize("model", MODELS)
def test_chat_completion(api_key, model):
    data, latency = _chat(api_key, model)
    validate_chat_response(data, "nvidia")
    log_latency(model, "chat", latency)


def test_response_has_usage(api_key):
    data, _ = _chat(api_key, MODELS[1])
    usage = data.get("usage", {})
    assert "prompt_tokens" in usage or "total_tokens" in usage
