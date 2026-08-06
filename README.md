# ThinkNEO MCP Server

[![MCP Queen operational grade](https://mcpqueen.com/badge/ai.thinkneo/control-plane.svg)](https://mcpqueen.com/s/ai.thinkneo/control-plane)

> Open MCP server with built-in defense layer (ThinkShield).
> Part of the [ThinkNEO Platform](https://thinkneo.ai) — enterprise AI governance.

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![MCP Protocol](https://img.shields.io/badge/MCP-2024--11--05-green.svg)](https://modelcontextprotocol.io)
[![A2A Protocol](https://img.shields.io/badge/A2A-v0.3.0-blue.svg)](https://github.com/google/A2A)
[![Tools](https://img.shields.io/badge/Tools-72-orange.svg)](#mcp-tools)
[![A2A Skills](https://img.shields.io/badge/A2A_Skills-24-blueviolet.svg)](#a2a-capabilities)
[![Glama AAA](https://img.shields.io/badge/Glama-AAA-brightgreen.svg)](https://glama.ai/mcp/servers/@thinkneo-ai/mcp-server)
[![Tests](https://github.com/thinkneo-ai/mcp-server/actions/workflows/tests.yml/badge.svg)](https://github.com/thinkneo-ai/mcp-server/actions/workflows/tests.yml)

---

## What This Is

An open-source MCP server providing 72 tools for AI governance, observability, and security:

- **ThinkShield** — Production defense layer: detection engine, 5 rule packs, runtime middleware. 145 tests, p99 < 1ms.
- **72 MCP Tools** — Governance, guardrails, FinOps, smart routing, observability, compliance, outcome validation, and more.
- **24 A2A Skills** — Bidirectional MCP-A2A bridge for Google's Agent-to-Agent Protocol (v0.3.0, Linux Foundation).
- **Apache-2.0** — Use it, fork it, contribute.

## What This Is Not

- **Not the full ThinkNEO Platform.** Governance orchestration, cryptographic audit chain, tenant management, and enterprise integrations are proprietary and run at [thinkneo.ai](https://thinkneo.ai).
- **Not a standalone security product.** ThinkShield is the defense component of a larger governed platform.

## Why Open

We open-source our defense layer because real security doesn't depend on hidden rules — it depends on tested, audited, continuously improved detection plus a strong governance moat around it.

Snort. Suricata. Falco. OWASP CRS. The security industry runs on open detection. We follow that tradition.

The detection is open. The governance is proprietary. That's where the moat is.

## Architecture

```
                        Open Source (this repo)                    Proprietary (thinkneo.ai)
                   ┌─────────────────────────────────┐     ┌──────────────────────────────────┐
                   │                                 │     │                                  │
  MCP Clients ────>│  72 MCP Tools                   │     │  Governance Orchestration         │
  (Claude, Cursor, │  ├── Guardrails & Safety        │────>│  ├── Policy Engine (AIRGP)        │
   ChatGPT, etc.)  │  ├── FinOps & Smart Routing     │     │  ├── Cryptographic Audit Chain    │
                   │  ├── Observability              │     │  ├── Tenant Management            │
  A2A Agents ─────>│  ├── Compliance & Validation    │     │  ├── Enterprise Integrations      │
  (Google A2A)     │  └── MCP-A2A Bridge (24 skills) │     │  └── SLA & Support                │
                   │                                 │     │                                  │
                   │  ThinkShield Defense Layer       │     │  SHA-256 Hash Chain (949K+ rows)  │
                   │  ├── Detection Engine            │     │  Stripe Billing                   │
                   │  ├── 5 Rule Packs               │     │  Resend Email                     │
                   │  └── ASGI Middleware             │     │  Multi-tenant Auth                │
                   │                                 │     │                                  │
                   └─────────────────────────────────┘     └──────────────────────────────────┘
                          Apache-2.0 License                      Commercial License
```

## Quickstart

```bash
# Clone
git clone https://github.com/thinkneo-ai/mcp-server.git
cd mcp-server

# Install
pip install -r requirements.txt

# Run
python -m uvicorn src.server:app --host 0.0.0.0 --port 8081

# Test
python -m pytest tests/ -q
```

Or with Docker:

```bash
cd deploy
docker compose up -d
```

Connect from Claude Desktop, Cursor, or any MCP client:
```
https://mcp.thinkneo.ai/mcp
```

Free tier: 500 calls/month, auto-provisioned API key. All 72 tools available.

## Components

| Directory | Description | License |
|-----------|-------------|---------|
| `src/tools/` | 72 MCP tools — governance, security, FinOps, observability | Apache-2.0 |
| `src/thinkshield/` | Defense layer — detection engine, 5 rule packs | Apache-2.0 |
| `tests/thinkshield/` | ThinkShield test suite — 145 tests + attack/benign fixtures | Apache-2.0 |
| `agent.json` | A2A Agent Card — 24 skills bridged from MCP | Apache-2.0 |

### ThinkShield Rule Packs

| Pack | Detects |
|------|---------|
| `injection` | SQL injection, XSS, command injection, path traversal |
| `auth` | Credential stuffing, brute force, token replay, privilege escalation |
| `abuse` | Rate abuse, resource exhaustion, API scraping |
| `recon` | Path probing, tool enumeration, method probing, fingerprinting |
| `headers` | Header anomalies, spoofing, missing security headers |

### MCP Tools (72)

Governance (6) | Guardrails (3) | FinOps (4) | Smart Router (4) | Trust Score (2) | Registry (5) | Bridge (4) | Observability (5) | Business Value (6) | A2A Control (4) | Optimization (1) | Outcome Validation (4) | Policy Engine (4) | Benchmarking (3) | Compliance (2) | Agent SLA (4) | Audit Export (3) | Cache (3) | Security (5) | Tokens (1) | Memory (2) | Scheduling (1) | Alerts (1)

Full tool reference: [docs/quickstart.md](docs/quickstart.md)

## MCP Spec Compliance

Complete Model Context Protocol 2024-11-05 implementation. Forward-compatible with MCP 2025-03-26.

| Capability | Status | Details |
|------------|--------|---------|
| tools | 72 tools, full annotations | destructiveHint, readOnlyHint, idempotentHint, openWorldHint |
| resources | 2 resources | Getting Started guide, Supported Providers |
| prompts | 2 prompts with completions | governance_audit, policy_preflight |
| logging | logging/setLevel | 8 levels, per-session, audit trail |
| completions | completion/complete | workspace (auth-scoped), provider, model (provider-aware) |

## Ecosystem

This repo is part of the ThinkNEO ecosystem:

| Project | Description |
|---------|-------------|
| [ThinkNEO Platform](https://thinkneo.ai) | Enterprise AI governance platform |
| [AIRGP](https://airgp.space) | AI Runtime Governance Protocol — open standard |
| [A2ASTC](https://a2astc.space) | A2A Security & Trust Conformance |
| [ThinkNEO SMB Hub](https://thinkneo.app) | Business applications for SMBs |
| [Robotics Governance](https://robots.thinkneo.pro) | Robot fleet governance dashboard |

## Security

See [SECURITY.md](SECURITY.md) for vulnerability reporting.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Related

| Server | Description | Tools |
|--------|-------------|-------|
| [thinkneo-control-plane](https://glama.ai/mcp/servers/thinkneo-ai/mcp-server) | Enterprise AI Control Plane (this repo) | 72 tools |
| [thinkneo-mcp-smb-products](https://glama.ai/mcp/servers/thinkneo-ai/mcp-smb-products) | SMB standalone products — self-serve via TNC credits | 37 tools |

## License

Apache-2.0 — see [LICENSE](LICENSE).

## About

**ThinkNEO AI Technology Co., Ltd.** — Hong Kong CR No. 2296774.

Built by the team behind the ThinkNEO Enterprise AI Control Plane, AIRGP protocol, and A2ASTC conformance suite.

[NVIDIA Inception](https://nvidia.com/inception) | [Anthropic Partner](https://anthropic.com) | [Linux Foundation A2A](https://github.com/google/A2A)
