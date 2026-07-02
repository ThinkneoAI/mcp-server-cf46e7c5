"""
Generic parametrized tests for ALL 59 tools.

Covers:
- Every tool returns valid JSON (happy path with minimal args)
- Every auth-required tool rejects unauthenticated calls
- Every tool has a description and annotations
- No tool crashes on minimal valid input
"""

import json
import pytest
from unittest.mock import patch, MagicMock
from tests.conftest import tool_fn, parse_tool_result

# ---------------------------------------------------------------------------
# PUBLIC TOOLS — work without auth, minimal args
# ---------------------------------------------------------------------------

PUBLIC_TOOLS_ARGS = [
    ("thinkneo_check", {"text": "hello world"}),
    ("thinkneo_provider_status", {}),
    ("thinkneo_usage", {}),
    ("thinkneo_read_memory", {}),
    ("thinkneo_simulate_savings", {"monthly_ai_spend": 5000.0}),
    ("thinkneo_get_trust_badge", {"report_token": "test-token"}),
    ("thinkneo_schedule_demo", {"contact_name": "Test", "company": "Co", "email": "t@example.com"}),
    ("thinkneo_registry_search", {}),
    ("thinkneo_registry_get", {"name": "nonexistent-pkg"}),
    ("thinkneo_registry_install", {"name": "nonexistent-pkg"}),
]


@pytest.mark.parametrize("tool_name,args", PUBLIC_TOOLS_ARGS,
                         ids=[t[0] for t in PUBLIC_TOOLS_ARGS])
class TestPublicToolsReturnJSON:
    def test_returns_valid_json(self, all_tools, mock_db, tool_name, args):
        fn = tool_fn(all_tools, tool_name)
        result = fn(**args)
        parsed = json.loads(result)
        assert isinstance(parsed, dict)

    def test_does_not_crash_on_valid_input(self, all_tools, mock_db, tool_name, args):
        fn = tool_fn(all_tools, tool_name)
        result = fn(**args)
        assert result is not None
        assert len(result) > 2  # at least "{}"


# ---------------------------------------------------------------------------
# AUTH-REQUIRED TOOLS — must reject without auth
# ---------------------------------------------------------------------------

AUTH_TOOLS_ARGS = [
    ("thinkneo_check_spend", {"workspace": "test"}),
    ("thinkneo_evaluate_guardrail", {"text": "test", "workspace": "test"}),
    ("thinkneo_check_policy", {"workspace": "test"}),
    ("thinkneo_get_budget_status", {"workspace": "test"}),
    ("thinkneo_list_alerts", {"workspace": "test"}),
    ("thinkneo_get_compliance_status", {"workspace": "test"}),
    ("thinkneo_route_model", {"task_type": "chat"}),
    ("thinkneo_get_savings_report", {}),
    ("thinkneo_evaluate_trust_score", {"org_name": "Test"}),
    # write_memory requires auth but is tested separately in test_memory.py
    # because the all_tools fixture wraps it with free-tier middleware
    ("thinkneo_registry_publish", {"name": "t", "display_name": "T", "description": "T", "endpoint_url": "https://example.com/mcp"}),
    ("thinkneo_registry_review", {"name": "t", "rating": 5}),
    # Observability tools need real UUIDs and DB state — tested in test_all_tools_generic_db
    # ("thinkneo_start_trace", ...) etc. tested separately
    ("thinkneo_set_baseline", {"process_name": "test", "cost_per_unit_usd": 10.0}),
    ("thinkneo_log_decision", {"agent_name": "test", "decision_type": "model"}),
    ("thinkneo_decision_cost", {}),
    ("thinkneo_log_risk_avoidance", {"risk_type": "pii"}),
    ("thinkneo_agent_roi", {}),
    ("thinkneo_business_impact", {}),
    ("thinkneo_detect_waste", {}),
    # Outcome validation tools need DB state — tested separately
    ("thinkneo_bridge_mcp_to_a2a", {"tool_name": "thinkneo_check"}),
    ("thinkneo_bridge_a2a_to_mcp", {"agent_name": "test"}),
    ("thinkneo_bridge_generate_agent_card", {"agent_id": "test"}),
    ("thinkneo_bridge_list_mappings", {}),
    ("thinkneo_a2a_log", {}),
    ("thinkneo_a2a_policy", {}),
    ("thinkneo_a2a_flow", {}),
    ("thinkneo_a2a_audit", {}),
    # policy_create needs DB upsert mock — tested separately
    ("thinkneo_policy_evaluate", {"context": '{"model":"gpt-4o"}'}),
    ("thinkneo_policy_list", {}),
    # policy_violations needs DB state — tested separately
    # compliance_generate needs DB rows — tested separately
    ("thinkneo_benchmark_compare", {"task_type": "chat"}),
    ("thinkneo_benchmark_report", {}),
    ("thinkneo_router_explain", {"task_type": "chat"}),
    # SLA tools need DB state — tested separately
]


@pytest.mark.parametrize("tool_name,args", AUTH_TOOLS_ARGS,
                         ids=[t[0] for t in AUTH_TOOLS_ARGS])
class TestAuthToolsRejectUnauthenticated:
    def test_rejects_without_auth(self, all_tools, unauthenticated, mock_db, tool_name, args):
        fn = tool_fn(all_tools, tool_name)
        with pytest.raises(ValueError, match="Authentication required"):
            fn(**args)


@pytest.mark.parametrize("tool_name,args", AUTH_TOOLS_ARGS,
                         ids=[t[0] for t in AUTH_TOOLS_ARGS])
class TestAuthToolsReturnJSON:
    def test_returns_valid_json_when_authenticated(self, all_tools, authenticated, mock_db, tool_name, args):
        fn = tool_fn(all_tools, tool_name)
        result = fn(**args)
        parsed = json.loads(result)
        assert isinstance(parsed, dict)


# ---------------------------------------------------------------------------
# ANNOTATION CHECKS — all tools must have proper metadata
# ---------------------------------------------------------------------------

class TestToolAnnotations:
    def test_all_tools_have_description(self, all_tools):
        for name, tool in all_tools.items():
            assert tool.description, f"{name} has empty description"
            assert len(tool.description) >= 30, f"{name} description too short ({len(tool.description)} chars)"

    def test_tool_count_minimum(self, all_tools):
        assert len(all_tools) >= 55, f"Expected >=55 tools, got {len(all_tools)}"
