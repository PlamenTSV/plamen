from __future__ import annotations

import copy
import json

import pytest

import claude_headless_profile as H
import claude_stream_json_evidence as S


SESSION = "11111111-2222-4333-8444-555555555555"
TOOLS = ("Edit", "Glob", "Grep", "Read", "WebFetch", "WebSearch", "Write")


def _profile(**overrides):
    kwargs = {
        "claude_code_version": "2.1.252",
        "cwd": r"C:\audit",
        "accepted_models": ("claude-opus-5",),
        "permission_mode": "default",
        "builtin_tools": TOOLS,
        "required_tools": ("Read", "Write"),
        "forbidden_tools": ("Agent", "Bash", "PowerShell", "Task"),
        "mcp_server_names": (),
        "customization_mode": "BOUND_SETTINGS",
        "accepted_api_key_sources": ("none",),
        "required_capabilities": (S.RESTRICTED_WEB_ANALYSIS_CAPABILITY,),
        "forbidden_capabilities": ("remote-agents",),
        "accepted_output_styles": ("default",),
    }
    kwargs.update(overrides)
    return H.compile_claude_headless_profile(**kwargs)


def _init():
    return {
        "type": "system",
        "subtype": "init",
        "uuid": "init-web",
        "session_id": SESSION,
        "claude_code_version": "2.1.252",
        "cwd": r"C:\audit",
        "model": "claude-opus-5",
        "permissionMode": "default",
        "apiKeySource": "none",
        "tools": list(TOOLS),
        "mcp_servers": [],
        "slash_commands": [],
        "output_style": "default",
        "skills": [],
        "plugins": [],
        "agents": list(S.REVIEWED_RESTRICTED_INIT_AGENTS),
        "capabilities": list(S.REVIEWED_RESTRICTED_INIT_CAPABILITIES),
    }


def _assistant(uuid: str, message_id: str, content, stop_reason="tool_use"):
    return {
        "type": "assistant",
        "uuid": uuid,
        "session_id": SESSION,
        "parent_tool_use_id": None,
        "message": {
            "id": message_id,
            "type": "message",
            "role": "assistant",
            "content": content,
            "model": "claude-opus-5",
            "stop_reason": stop_reason,
            "usage": {"input_tokens": 10, "output_tokens": 20},
        },
    }


def _user(uuid: str, tool_use_id: str, *, is_error=False):
    return {
        "type": "user",
        "uuid": uuid,
        "session_id": SESSION,
        "parent_tool_use_id": None,
        "message": {
            "role": "user",
            "content": [{
                "type": "tool_result",
                "tool_use_id": tool_use_id,
                "content": "tool result",
                "is_error": is_error,
            }],
        },
    }


def _result():
    return {
        "type": "result",
        "subtype": "success",
        "uuid": "result-web",
        "session_id": SESSION,
        "duration_ms": 101,
        "duration_api_ms": 91,
        "is_error": False,
        "num_turns": 4,
        "result": "worker complete",
        "total_cost_usd": 0.25,
        "usage": {"input_tokens": 10, "output_tokens": 20},
        "modelUsage": {"claude-opus-5": {"inputTokens": 10}},
        "permission_denials": [],
        "stop_reason": "end_turn",
        "origin": {"kind": "human"},
    }


def _stream(*events):
    return b"".join(
        json.dumps(event, sort_keys=True, separators=(",", ":")).encode() + b"\n"
        for event in events
    )


def _valid_events():
    return [
        _init(),
        _assistant("assistant-search", "msg-search", [{
            "type": "tool_use", "id": "toolu-search", "name": "WebSearch",
            "input": {"query": "exact query"},
        }]),
        _user("user-search", "toolu-search"),
        _assistant("assistant-fetch", "msg-fetch", [{
            "type": "tool_use", "id": "toolu-fetch", "name": "WebFetch",
            "input": {"url": "https://example.com/", "prompt": "exact prompt"},
        }]),
        _user("user-fetch", "toolu-fetch"),
        _assistant(
            "assistant-final", "msg-final",
            [{"type": "text", "text": "research complete"}], stop_reason=None,
        ),
        _result(),
    ]


def test_compiles_exact_restricted_web_profile_and_valid_sequence():
    profile = _profile()
    expected = profile["expected_init_contract"]
    assert expected["required_capabilities"] == [
        S.RESTRICTED_WEB_ANALYSIS_CAPABILITY
    ]
    assert expected["allowed_tools"] == list(TOOLS)
    assert expected["permission_mode"] == "default"
    assert profile["cli_flags"][:3] == [
        "--restricted", "--permission-mode", "default",
    ]
    assert profile["cli_flags"][profile["cli_flags"].index("--allowedTools") + 1] == (
        "Glob,Grep,Read"
    )
    summary = S.validate_claude_stream_json(
        _stream(*_valid_events()),
        expected_session_id=SESSION,
        expected_init_contract=expected,
    )
    assert summary["init_applicability"] == "MATCHED"


@pytest.mark.parametrize("mutation", ["version", "tools", "permission", "both_caps"])
def test_restricted_web_profile_mutations_reject(mutation):
    kwargs = {}
    if mutation == "version":
        kwargs["claude_code_version"] = "2.1.251"
    elif mutation == "tools":
        kwargs["builtin_tools"] = tuple(tool for tool in TOOLS if tool != "WebFetch")
    elif mutation == "permission":
        kwargs["permission_mode"] = "dontAsk"
    else:
        kwargs["required_capabilities"] = (
            S.RESTRICTED_ANALYSIS_CAPABILITY,
            S.RESTRICTED_WEB_ANALYSIS_CAPABILITY,
        )
    with pytest.raises((H.ClaudeHeadlessProfileError, S.ClaudeStreamJsonEvidenceError)):
        _profile(**kwargs)


@pytest.mark.parametrize("field,value", [
    ("claude_code_version", "2.1.251"),
    ("permissionMode", "dontAsk"),
    ("tools", ["Edit", "Glob", "Grep", "Read", "Write"]),
])
def test_restricted_web_observed_init_mutations_reject(field, value):
    events = _valid_events()
    events[0][field] = value
    with pytest.raises(S.ClaudeStreamJsonEvidenceError, match="INIT_APPLICABILITY_MISMATCH"):
        S.validate_claude_stream_json(
            _stream(*events),
            expected_session_id=SESSION,
            expected_init_contract=_profile()["expected_init_contract"],
        )


def test_same_message_search_fetch_and_parallel_fetch_reject():
    expected = _profile()["expected_init_contract"]
    events = _valid_events()
    events[1]["message"]["content"].append({
        "type": "tool_use", "id": "toolu-fetch-early", "name": "WebFetch", "input": {},
    })
    with pytest.raises(S.ClaudeStreamJsonEvidenceError, match="WEB_TOOL_SEQUENCE_INVALID"):
        S.validate_claude_stream_json(
            _stream(*events), expected_session_id=SESSION, expected_init_contract=expected,
        )

    events = _valid_events()
    events[3]["message"]["content"].append({
        "type": "tool_use", "id": "toolu-fetch-2", "name": "WebFetch", "input": {},
    })
    with pytest.raises(S.ClaudeStreamJsonEvidenceError, match="WEB_TOOL_SEQUENCE_INVALID"):
        S.validate_claude_stream_json(
            _stream(*events), expected_session_id=SESSION, expected_init_contract=expected,
        )


def test_fetch_before_successful_search_result_rejects():
    events = _valid_events()
    events.pop(2)
    with pytest.raises(S.ClaudeStreamJsonEvidenceError, match="WEB_TOOL_SEQUENCE_INVALID"):
        S.validate_claude_stream_json(
            _stream(*events),
            expected_session_id=SESSION,
            expected_init_contract=_profile()["expected_init_contract"],
        )
    events = _valid_events()
    events[2]["message"]["content"][0]["is_error"] = True
    with pytest.raises(S.ClaudeStreamJsonEvidenceError, match="WEB_TOOL_SEQUENCE_INVALID"):
        S.validate_claude_stream_json(
            _stream(*events),
            expected_session_id=SESSION,
            expected_init_contract=_profile()["expected_init_contract"],
        )


def test_auxiliary_haiku_is_allowed_only_in_restricted_web_result_telemetry():
    expected = _profile()["expected_init_contract"]
    selected_only = _valid_events()
    assert S.validate_claude_stream_json(
        _stream(*selected_only), expected_session_id=SESSION,
        expected_init_contract=expected,
    )["init_applicability"] == "MATCHED"

    events = _valid_events()
    events[-1]["modelUsage"]["claude-haiku-4-5-20251001"] = {
        "inputTokens": 1,
    }
    assert S.validate_claude_stream_json(
        _stream(*events), expected_session_id=SESSION,
        expected_init_contract=expected,
    )["init_applicability"] == "MATCHED"

    for missing_selected in ({}, {
        "claude-haiku-4-5-20251001": {"inputTokens": 1},
    }):
        rejected = _valid_events()
        rejected[-1]["modelUsage"] = missing_selected
        with pytest.raises(
            S.ClaudeStreamJsonEvidenceError,
            match="MODEL_DENOMINATOR_MISMATCH",
        ):
            S.validate_claude_stream_json(
                _stream(*rejected), expected_session_id=SESSION,
                expected_init_contract=expected,
            )

    wrong_usage = copy.deepcopy(events)
    wrong_usage[-1]["modelUsage"]["claude-haiku-4-5-20990101"] = {
        "inputTokens": 1,
    }
    with pytest.raises(S.ClaudeStreamJsonEvidenceError, match="MODEL_DENOMINATOR_MISMATCH"):
        S.validate_claude_stream_json(
            _stream(*wrong_usage), expected_session_id=SESSION,
            expected_init_contract=expected,
        )

    wrong_init = copy.deepcopy(events)
    wrong_init[0]["model"] = "claude-haiku-4-5-20251001"
    with pytest.raises(S.ClaudeStreamJsonEvidenceError, match="INIT_APPLICABILITY_MISMATCH"):
        S.validate_claude_stream_json(
            _stream(*wrong_init), expected_session_id=SESSION,
            expected_init_contract=expected,
        )

    wrong_assistant = copy.deepcopy(events)
    wrong_assistant[1]["message"]["model"] = "claude-haiku-4-5-20251001"
    with pytest.raises(S.ClaudeStreamJsonEvidenceError, match="MODEL_DENOMINATOR_MISMATCH"):
        S.validate_claude_stream_json(
            _stream(*wrong_assistant), expected_session_id=SESSION,
            expected_init_contract=expected,
        )
