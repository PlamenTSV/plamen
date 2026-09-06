from __future__ import annotations

import copy
import json

import pytest

import claude_stream_json_evidence as C
from test_claude_stream_json_evidence_p0_am import (
    SESSION,
    _assistant,
    _init,
    _result,
)


def _line(value: object) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
        ).encode("utf-8")
        + b"\n"
    )


def _stream(init: dict[str, object]) -> bytes:
    return b"".join((_line(init), _line(_assistant()), _line(_result())))


def _policy() -> dict[str, object]:
    return {
        "schema": C.EXPECTED_INIT_SECURITY_SCHEMA,
        "claude_code_version": "2.1.220",
        "cwd": "C:\\audit",
        "accepted_models": ["claude-opus-5", "claude-opus-5-20260701"],
        "permission_mode": "dontAsk",
        "allowed_tools": ["Bash", "Edit", "Glob", "Grep", "Read", "Write"],
        "allowed_tool_prefixes": [],
        "required_tools": ["Read", "Write"],
        "forbidden_tools": ["Agent", "Task", "WebFetch", "WebSearch"],
        "allowed_mcp_servers": [],
        "required_mcp_servers": [],
        "expected_plugins": [],
        "expected_skills": [],
        "expected_agents": [],
        "accepted_api_key_sources": ["subscription", "user"],
        "required_capabilities": [],
        "expected_native_capabilities": [],
        "forbidden_capabilities": ["remote-agents"],
        "expected_slash_commands": [],
        "accepted_output_styles": ["default"],
    }


def _matching_init() -> dict[str, object]:
    value = _init()
    value.update(
        {
            "permissionMode": "dontAsk",
            "tools": ["Read", "Write", "Bash", "Edit", "Glob", "Grep"],
            "agents": [],
            "capabilities": [],
        }
    )
    return value


def _reject(
    init: dict[str, object],
    policy: dict[str, object],
    code: str = "INIT_APPLICABILITY_MISMATCH",
) -> None:
    with pytest.raises(C.ClaudeStreamJsonEvidenceError) as caught:
        C.validate_claude_stream_json(
            _stream(init),
            expected_session_id=SESSION,
            expected_init_contract=policy,
        )
    assert caught.value.code == code


def test_v2_accepts_only_the_declared_builtin_surface() -> None:
    summary = C.validate_claude_stream_json(
        _stream(_matching_init()),
        expected_session_id=SESSION,
        expected_init_contract=_policy(),
    )

    assert summary["init_applicability"] == "MATCHED"
    assert summary["expected_init_contract_sha256"]


@pytest.mark.parametrize("tool", ("Agent", "WebSearch", "NotebookEdit"))
def test_v2_rejects_forbidden_or_unlisted_builtin_tools(tool: str) -> None:
    init = _matching_init()
    init["tools"] = [*init["tools"], tool]
    _reject(init, _policy())


def test_v2_rejects_missing_required_tool() -> None:
    init = _matching_init()
    init["tools"] = [
        tool for tool in init["tools"] if tool != "Write"
    ]
    _reject(init, _policy())


def test_v2_accepts_configured_mcp_namespace_and_connected_server() -> None:
    policy = _policy()
    policy["allowed_tool_prefixes"] = ["mcp__"]
    policy["allowed_mcp_servers"] = ["solodit"]
    policy["required_mcp_servers"] = ["solodit"]
    init = _matching_init()
    init["tools"] = [*init["tools"], "mcp__solodit__search_findings"]
    init["mcp_servers"] = [{"name": "solodit", "status": "connected"}]

    summary = C.validate_claude_stream_json(
        _stream(init),
        expected_session_id=SESSION,
        expected_init_contract=policy,
    )
    assert summary["init_applicability"] == "MATCHED"


def test_v2_rejects_mcp_tool_without_configured_server() -> None:
    policy = _policy()
    policy["allowed_tool_prefixes"] = ["mcp__"]
    init = _matching_init()
    init["tools"] = [*init["tools"], "mcp__unbound__search"]
    _reject(init, policy)


def test_v2_rejects_unknown_or_missing_mcp_server() -> None:
    policy = _policy()
    policy["allowed_tool_prefixes"] = ["mcp__"]
    policy["allowed_mcp_servers"] = ["solodit"]
    policy["required_mcp_servers"] = ["solodit"]

    missing = _matching_init()
    _reject(missing, policy)

    unknown = _matching_init()
    unknown["mcp_servers"] = [
        {"name": "solodit", "status": "connected"},
        {"name": "unbound", "status": "connected"},
    ]
    _reject(unknown, policy)


def test_v2_rejects_forbidden_capability() -> None:
    init = _matching_init()
    init["capabilities"] = ["remote-agents"]
    _reject(init, _policy())


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("required_tools", ["Read", "Agent"]),
        ("allowed_tool_prefixes", [""]),
        ("allowed_tool_prefixes", ["custom__"]),
        ("required_mcp_servers", ["unbound"]),
        ("accepted_output_styles", []),
        ("allowed_tools", ["Read", "Read"]),
        ("forbidden_tools", ["Read"]),
    ),
)
def test_v2_configuration_rejects_ambiguous_or_incoherent_policy(
    field: str,
    value: object,
) -> None:
    policy = copy.deepcopy(_policy())
    policy[field] = value
    with pytest.raises(C.ClaudeStreamJsonEvidenceError) as caught:
        C.normalize_expected_init_contract(policy)
    assert caught.value.code == "CONFIG_INVALID"
