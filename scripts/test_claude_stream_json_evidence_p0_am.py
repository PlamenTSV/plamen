from __future__ import annotations

import hashlib
import json
import random
from pathlib import Path

import pytest

import claude_stream_json_evidence as C


SESSION = "11111111-2222-4333-8444-555555555555"


def _init(*, session_id: str = SESSION) -> dict[str, object]:
    return {
        "type": "system",
        "subtype": "init",
        "uuid": "init-uuid",
        "session_id": session_id,
        "claude_code_version": "2.1.220",
        "cwd": "C:\\audit",
        "model": "claude-opus-5",
        "permissionMode": "acceptEdits",
        "apiKeySource": "subscription",
        "tools": ["Read", "Write", "Bash", "Agent"],
        "mcp_servers": [],
        "slash_commands": [],
        "output_style": "default",
        "skills": [],
        "plugins": [],
    }


def _assistant(
    *,
    parent: str | None = None,
    stop_reason: str | None = "end_turn",
    text: str = "done",
    session_id: str = SESSION,
) -> dict[str, object]:
    return {
        "type": "assistant",
        "uuid": f"assistant-{parent or 'root'}-{stop_reason}",
        "session_id": session_id,
        "parent_tool_use_id": parent,
        "message": {
            "id": f"msg-{parent or 'root'}-{stop_reason}",
            "type": "message",
            "role": "assistant",
            "content": [{"type": "text", "text": text}],
            "model": "claude-opus-5",
            "stop_reason": stop_reason,
            "usage": {"input_tokens": 10, "output_tokens": 20},
        },
    }


def _user(
    *,
    parent: str | None = None,
    content: object = "tool result",
    session_id: str = SESSION,
) -> dict[str, object]:
    return {
        "type": "user",
        "uuid": f"user-{parent or 'root'}",
        "session_id": session_id,
        "parent_tool_use_id": parent,
        "message": {"role": "user", "content": content},
    }


def _result(
    *,
    session_id: str = SESSION,
    subtype: str = "success",
    is_error: bool = False,
    result_text: str = "worker complete",
) -> dict[str, object]:
    return {
        "type": "result",
        "subtype": subtype,
        "uuid": "result-uuid",
        "session_id": session_id,
        "duration_ms": 101,
        "duration_api_ms": 91,
        "is_error": is_error,
        "num_turns": 3,
        "result": result_text,
        "total_cost_usd": 0.25,
        "usage": {"input_tokens": 10, "output_tokens": 20},
        "modelUsage": {"claude-opus-5": {"inputTokens": 10}},
        "permission_denials": [],
        "stop_reason": "end_turn",
        "origin": {"kind": "human"},
    }


def _post_result_prompt_suggestion() -> dict[str, object]:
    return {
        "type": "prompt_suggestion",
        "uuid": "post-result-prompt-suggestion",
        "session_id": SESSION,
        "suggestion": "Review the generated artifact",
    }


def _expected_init() -> dict[str, object]:
    return {
        "schema": C.EXPECTED_INIT_SCHEMA,
        "claude_code_version": "2.1.220",
        "cwd": "C:\\audit",
        "accepted_models": ["claude-opus-5"],
        "permission_mode": "acceptEdits",
        "expected_tools": ["Agent", "Bash", "Read", "Write"],
        "expected_mcp_servers": [],
        "expected_plugins": [],
        "expected_skills": [],
        "expected_agents": [],
        "accepted_api_key_sources": ["subscription"],
        "required_capabilities": [],
        "expected_slash_commands": [],
        "expected_output_style": "default",
    }


def _restricted_r42_init() -> dict[str, object]:
    init = _init()
    init.update(
        {
            "claude_code_version": "2.1.252",
            "permissionMode": "default",
            "apiKeySource": "none",
            "tools": ["Read", "Glob", "Grep", "Write", "Edit"],
            "agents": [
                "claude",
                "Explore",
                "general-purpose",
                "Plan",
                "statusline-setup",
            ],
            "capabilities": [
                "interrupt_receipt_v1",
                "interrupt_cancel_queued_v1",
                "msg_lifecycle_v1",
            ],
        }
    )
    return init


def _restricted_r42_expected() -> dict[str, object]:
    return {
        "schema": C.EXPECTED_INIT_SECURITY_SCHEMA,
        "claude_code_version": "2.1.252",
        "cwd": "C:\\audit",
        "accepted_models": ["claude-opus-5"],
        "permission_mode": "default",
        "allowed_tools": ["Edit", "Glob", "Grep", "Read", "Write"],
        "allowed_tool_prefixes": [],
        "required_tools": ["Read", "Write"],
        "forbidden_tools": [
            "Agent",
            "Bash",
            "PowerShell",
            "Task",
            "WebFetch",
            "WebSearch",
        ],
        "allowed_mcp_servers": [],
        "required_mcp_servers": [],
        "expected_plugins": [],
        "expected_skills": [],
        "expected_agents": list(C.REVIEWED_RESTRICTED_INIT_AGENTS),
        "accepted_api_key_sources": ["none"],
        "required_capabilities": ["vendor-restricted-analysis"],
        "expected_native_capabilities": list(
            C.REVIEWED_RESTRICTED_INIT_CAPABILITIES
        ),
        "forbidden_capabilities": ["remote-agents"],
        "expected_slash_commands": [],
        "accepted_output_styles": ["default"],
    }


def _line(event: object) -> bytes:
    return (
        json.dumps(
            event,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
        ).encode("utf-8")
        + b"\n"
    )


def _stream(*events: object) -> bytes:
    return b"".join(_line(event) for event in events)


def _valid_stream(*, result_text: str = "worker complete") -> bytes:
    return _stream(
        _init(),
        _assistant(stop_reason="tool_use", text="calling a tool"),
        _user(content=[{"type": "tool_result", "content": "ok"}]),
        _assistant(parent="toolu-agent", text="subagent answer"),
        _assistant(text="root answer"),
        _result(result_text=result_text),
    )


def _assert_rejected(raw: bytes, code: str, **kwargs: object) -> None:
    with pytest.raises(C.ClaudeStreamJsonEvidenceError) as caught:
        C.validate_claude_stream_json(raw, **kwargs)
    assert caught.value.code == code


def test_valid_stream_emits_canonical_exact_evidence() -> None:
    raw = _valid_stream(result_text="complete \N{LOCK}")

    summary = C.validate_claude_stream_json(
        raw,
        expected_session_id=SESSION,
    )

    assert summary["schema"] == "plamen.claude-stream-json-evidence/v1"
    assert (
        summary["provider_protocol"]
        == "claude-cli-stream-json/no-partials/v1"
    )
    assert summary["producer_exclusivity"] == "NOT_ESTABLISHED_BY_PARSER"
    assert summary["raw_sha256"] == hashlib.sha256(raw).hexdigest()
    assert summary["raw_byte_count"] == len(raw)
    assert summary["line_count"] == 6
    assert summary["session_id"] == SESSION
    assert summary["event_counts"] == {
        "assistant": 3,
        "result": 1,
        "system": 1,
        "user": 1,
    }
    assert summary["root_attributed_event_count"] == 3
    assert summary["subagent_attributed_event_count"] == 1
    assert summary["unattributed_event_count"] == 2
    assert summary["assistant_end_turn_count"] == 2
    assert summary["root_assistant_end_turn_count"] == 1
    assert summary["result_subtype"] == "success"
    assert summary["result_is_error"] is False
    assert summary["result_stop_reason_observed"] == "end_turn"
    assert summary["result_terminal_reason_observed"] is None
    assert (
        summary["terminal_basis"]
        == "FINAL_ROOT_ASSISTANT_END_TURN_AND_RESULT_SUCCESS"
    )
    assert summary["result_text_sha256"] == hashlib.sha256(
        "complete \N{LOCK}".encode("utf-8")
    ).hexdigest()
    core = dict(summary)
    observed_summary_digest = core.pop("canonical_summary_sha256")
    assert observed_summary_digest == hashlib.sha256(
        json.dumps(
            core,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


def test_expected_init_contract_binds_provider_application_state() -> None:
    expected = _expected_init()
    summary = C.validate_claude_stream_json(
        _valid_stream(),
        expected_session_id=SESSION,
        expected_init_contract=expected,
    )

    assert summary["init_applicability"] == "MATCHED"
    assert summary["expected_init_contract_sha256"] == hashlib.sha256(
        json.dumps(
            expected,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


def test_sanitized_r42_restricted_init_matches_pinned_native_denominator() -> None:
    summary = C.validate_claude_stream_json(
        _stream(_restricted_r42_init(), _assistant(), _result()),
        expected_session_id=SESSION,
        expected_init_contract=_restricted_r42_expected(),
    )

    assert summary["init_applicability"] == "MATCHED"


@pytest.mark.parametrize(
    ("field", "mutator"),
    (
        ("permissionMode", lambda value: "dontAsk"),
        ("claude_code_version", lambda value: "2.1.251"),
        ("agents", lambda value: [*value, "rogue-agent"]),
        ("tools", lambda value: [*value, "Agent"]),
        ("capabilities", lambda value: [*value, "remote-agents"]),
        ("capabilities", lambda value: value[:-1]),
    ),
)
def test_r42_restricted_init_rejects_native_surface_drift(
    field: str,
    mutator: object,
) -> None:
    init = _restricted_r42_init()
    init[field] = mutator(init[field])
    _assert_rejected(
        _stream(init, _assistant(), _result()),
        "INIT_APPLICABILITY_MISMATCH",
        expected_session_id=SESSION,
        expected_init_contract=_restricted_r42_expected(),
    )


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("required_capabilities", []),
        ("claude_code_version", "2.1.251"),
        ("permission_mode", "dontAsk"),
    ),
)
def test_r42_default_contract_rejects_missing_restricted_authority(
    field: str,
    value: object,
) -> None:
    expected = _restricted_r42_expected()
    expected[field] = value
    _assert_rejected(
        _stream(_restricted_r42_init(), _assistant(), _result()),
        "CONFIG_INVALID",
        expected_session_id=SESSION,
        expected_init_contract=expected,
    )


@pytest.mark.parametrize("surface", ("root", "subagent", "model_usage"))
def test_expected_init_rejects_silent_model_fallback(surface: str) -> None:
    events = [
        _init(),
        _assistant(stop_reason="tool_use", text="calling a tool"),
        _user(content=[{"type": "tool_result", "content": "ok"}]),
        _assistant(parent="toolu-agent", text="subagent answer"),
        _assistant(text="root answer"),
        _result(),
    ]
    if surface == "root":
        events[4]["message"]["model"] = "claude-opus-4-8"
    elif surface == "subagent":
        events[3]["message"]["model"] = "claude-opus-4-8"
    else:
        events[5]["modelUsage"] = {
            "claude-opus-5": {"inputTokens": 5},
            "claude-opus-4-8": {"inputTokens": 5},
        }
    _assert_rejected(
        _stream(*events),
        "MODEL_DENOMINATOR_MISMATCH",
        expected_session_id=SESSION,
        expected_init_contract=_expected_init(),
    )


def test_explicitly_armed_fallback_model_remains_authorized() -> None:
    fallback = "claude-sonnet-5"
    assistant = _assistant(text="authorized recovery")
    assistant["message"]["model"] = fallback
    result = _result()
    result["modelUsage"] = {
        "claude-opus-5": {"inputTokens": 5},
        fallback: {"inputTokens": 5},
    }
    expected = _expected_init()
    expected["accepted_models"] = ["claude-opus-5", fallback]

    summary = C.validate_claude_stream_json(
        _stream(_init(), assistant, result),
        expected_session_id=SESSION,
        expected_init_contract=expected,
    )

    assert summary["init_applicability"] == "MATCHED"


@pytest.mark.parametrize(
    ("field", "value"),
    (
        (
            "mcp_servers",
            [{"name": "required-provider", "status": "failed"}],
        ),
        (
            "plugin_errors",
            [{"plugin": "required-methods", "error": "load failed"}],
        ),
    ),
)
def test_init_rejects_unavailable_configured_capabilities(
    field: str,
    value: object,
) -> None:
    init = _init()
    init[field] = value
    _assert_rejected(
        _stream(init, _assistant(), _result()),
        "PROVIDER_ADVERSE_EVENT",
    )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("claude_code_version", "2.1.219"),
        ("cwd", "C:\\other"),
        ("accepted_models", ["claude-sonnet-5"]),
        ("permission_mode", "default"),
        ("expected_tools", ["Read"]),
        ("accepted_api_key_sources", ["api-key"]),
    ],
)
def test_expected_init_contract_rejects_provider_application_drift(
    field: str,
    value: object,
) -> None:
    expected = _expected_init()
    expected[field] = value
    _assert_rejected(
        _valid_stream(),
        "INIT_APPLICABILITY_MISMATCH",
        expected_session_id=SESSION,
        expected_init_contract=expected,
    )


def test_every_single_split_and_unicode_byte_boundary_is_deterministic() -> None:
    raw = _valid_stream(result_text="alpha \N{GREEK SMALL LETTER PI} \N{LOCK}")
    expected = C.validate_claude_stream_json(raw)

    for split in range(len(raw) + 1):
        parser = C.ClaudeStreamJsonEvidenceParser()
        parser.feed(raw[:split])
        parser.feed(b"")
        parser.feed(raw[split:])
        assert parser.finish().canonical_summary() == expected


def test_deterministic_random_chunk_partitions_are_equivalent() -> None:
    raw = _valid_stream(result_text="chunk invariant")
    expected = C.validate_claude_stream_json(raw)
    randomizer = random.Random(0xC1A0DE)

    for _ in range(100):
        parser = C.ClaudeStreamJsonEvidenceParser()
        offset = 0
        while offset < len(raw):
            width = randomizer.randint(1, 37)
            parser.feed(raw[offset : offset + width])
            offset += width
        assert parser.finish().canonical_summary() == expected


@pytest.mark.parametrize(
    ("raw", "code"),
    [
        (b"", "ORDER_INIT_REQUIRED"),
        (_stream(_assistant(), _result()), "ORDER_INIT_REQUIRED"),
        (_stream(_result(), _init()), "ORDER_INIT_REQUIRED"),
        (_stream(_init(), _init(), _result()), "ORDER_MULTIPLE_INIT"),
        (_stream(_init()), "ORDER_RESULT_REQUIRED"),
        (_stream(_init(), _assistant()), "ORDER_RESULT_REQUIRED"),
    ],
)
def test_exact_init_progress_result_order_is_required(
    raw: bytes, code: str
) -> None:
    _assert_rejected(raw, code)


def test_root_assistant_end_turn_is_not_a_terminal_event() -> None:
    raw = _stream(_init(), _assistant(stop_reason="end_turn"))
    _assert_rejected(raw, "ORDER_RESULT_REQUIRED")


def test_result_success_without_final_root_assistant_end_turn_is_not_terminal() -> None:
    _assert_rejected(
        _stream(_init(), _result()),
        "ROOT_END_TURN_REQUIRED",
    )


def test_real_2_1_252_null_stop_root_text_shape_is_terminal() -> None:
    raw = _stream(
        _restricted_r42_init(),
        _assistant(stop_reason=None, text="R3 completed and wrote its artifact"),
        _result(result_text="R3 completed and wrote its artifact"),
    )

    summary = C.validate_claude_stream_json(
        raw,
        expected_session_id=SESSION,
        expected_init_contract=_restricted_r42_expected(),
    )

    assert summary["assistant_end_turn_count"] == 0
    assert summary["root_assistant_end_turn_count"] == 0
    assert (
        summary["terminal_basis"]
        == "FINAL_ROOT_ASSISTANT_TEXT_NULL_STOP_AND_RESULT_SUCCESS_2_1_252"
    )


@pytest.mark.parametrize("status", ["allowed", "allowed_warning"])
def test_allowed_rate_limit_telemetry_preserves_terminal_candidate(
    status: str,
) -> None:
    telemetry = {
        "type": "rate_limit_event",
        "rate_limit_info": {
            "status": status,
            "resetsAt": 1788452400,
            "rateLimitType": "five_hour",
        },
        "session_id": SESSION,
        "uuid": f"rate-{status}",
    }
    raw = _stream(
        _restricted_r42_init(),
        _assistant(stop_reason=None, text="R3 completed and wrote its artifact"),
        telemetry,
        _result(result_text="R3 completed and wrote its artifact"),
    )

    summary = C.validate_claude_stream_json(
        raw,
        expected_session_id=SESSION,
        expected_init_contract=_restricted_r42_expected(),
    )

    assert (
        summary["terminal_basis"]
        == "FINAL_ROOT_ASSISTANT_TEXT_NULL_STOP_AND_RESULT_SUCCESS_2_1_252"
    )


@pytest.mark.parametrize(
    ("mutation", "code"),
    [
        ("missing_assistant", "ROOT_END_TURN_REQUIRED"),
        ("subagent_assistant", "ROOT_END_TURN_REQUIRED"),
        ("empty_text", "ROOT_END_TURN_REQUIRED"),
        ("blank_text", "ROOT_END_TURN_REQUIRED"),
        ("missing_text_block", "ROOT_END_TURN_REQUIRED"),
        ("text_and_tool_use", "ROOT_END_TURN_REQUIRED"),
        ("two_text_blocks", "ROOT_END_TURN_REQUIRED"),
        ("missing_stop_reason", "ROOT_END_TURN_REQUIRED"),
        ("other_version", "ROOT_END_TURN_REQUIRED"),
        ("later_root_user", "ROOT_END_TURN_REQUIRED"),
        ("intervening_system", "ROOT_END_TURN_REQUIRED"),
        ("intervening_subagent", "ROOT_END_TURN_REQUIRED"),
        ("other_session", "SESSION_MISMATCH"),
        ("wrong_model", "MODEL_DENOMINATOR_MISMATCH"),
        ("non_success", "RESULT_SUBTYPE_REJECTED"),
        ("error_result", "RESULT_IS_ERROR"),
        ("permission_denial", "RESULT_PERMISSION_DENIED"),
    ],
)
def test_2_1_252_null_stop_terminal_shape_mutations_fail_closed(
    mutation: str,
    code: str,
) -> None:
    init = _restricted_r42_init()
    assistant = _assistant(
        stop_reason=None,
        text="R3 completed and wrote its artifact",
    )
    result = _result(result_text="R3 completed and wrote its artifact")
    events: list[dict[str, object]] = [init, assistant, result]

    if mutation == "missing_assistant":
        events = [init, result]
    elif mutation == "subagent_assistant":
        assistant["parent_tool_use_id"] = "toolu-subagent"
    elif mutation == "empty_text":
        assistant["message"]["content"][0]["text"] = ""  # type: ignore[index]
    elif mutation == "blank_text":
        assistant["message"]["content"][0]["text"] = " \t\r\n"  # type: ignore[index]
    elif mutation == "missing_text_block":
        assistant["message"]["content"] = [  # type: ignore[index]
            {"type": "thinking", "thinking": "not terminal text"}
        ]
    elif mutation == "text_and_tool_use":
        assistant["message"]["content"].append(  # type: ignore[index]
            {"type": "tool_use", "id": "toolu-1", "name": "Read", "input": {}}
        )
    elif mutation == "two_text_blocks":
        assistant["message"]["content"].append(  # type: ignore[index]
            {"type": "text", "text": "second terminal-looking block"}
        )
    elif mutation == "missing_stop_reason":
        del assistant["message"]["stop_reason"]  # type: ignore[index]
    elif mutation == "other_version":
        init["claude_code_version"] = "2.1.253"
    elif mutation == "later_root_user":
        events.insert(2, _user(parent=None, content="new root turn"))
    elif mutation == "intervening_system":
        events.insert(
            2,
            {
                "type": "system",
                "subtype": "informational",
                "content": "benign but breaks adjacency",
                "level": "info",
                "uuid": "intervening-system",
                "session_id": SESSION,
            },
        )
    elif mutation == "intervening_subagent":
        events.insert(
            2,
            _assistant(
                parent="toolu-subagent",
                stop_reason="end_turn",
                text="subagent tail",
            ),
        )
    elif mutation == "other_session":
        assistant["session_id"] = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
    elif mutation == "wrong_model":
        assistant["message"]["model"] = "claude-sonnet-5"  # type: ignore[index]
    elif mutation == "non_success":
        result["subtype"] = "error_during_execution"
    elif mutation == "error_result":
        result["is_error"] = True
    elif mutation == "permission_denial":
        result["permission_denials"] = [
            {"tool_name": "Read", "tool_use_id": "toolu-1", "tool_input": {}}
        ]

    kwargs: dict[str, object] = {
        "expected_session_id": SESSION,
        "expected_init_contract": _restricted_r42_expected(),
    }
    if mutation == "other_version":
        # Isolate the parser's version-pinned terminal rule from the separate
        # expected-init version equality gate.
        kwargs = {"expected_session_id": SESSION}
    _assert_rejected(_stream(*events), code, **kwargs)


def test_2_1_252_null_stop_requires_matched_restricted_v2_authority() -> None:
    raw = _stream(
        _restricted_r42_init(),
        _assistant(stop_reason=None, text="R3 completed"),
        _result(result_text="R3 completed"),
    )
    _assert_rejected(
        raw,
        "ROOT_END_TURN_REQUIRED",
        expected_session_id=SESSION,
    )

    unrestricted = _restricted_r42_init()
    unrestricted.update(
        {
            "permissionMode": "acceptEdits",
            "apiKeySource": "subscription",
            "tools": ["Read", "Write", "Bash", "Agent"],
            "agents": [],
            "capabilities": [],
        }
    )
    expected = _expected_init()
    expected["claude_code_version"] = "2.1.252"
    _assert_rejected(
        _stream(
            unrestricted,
            _assistant(stop_reason=None, text="R3 completed"),
            _result(result_text="R3 completed"),
        ),
        "ROOT_END_TURN_REQUIRED",
        expected_session_id=SESSION,
        expected_init_contract=expected,
    )
    _assert_rejected(
        _stream(_init(), _assistant(parent="toolu-subagent"), _result()),
        "ROOT_END_TURN_REQUIRED",
    )
    _assert_rejected(
        _stream(_init(), _assistant(stop_reason="tool_use"), _result()),
        "ROOT_END_TURN_REQUIRED",
    )


def test_subagent_pseudo_result_is_rejected_as_non_root() -> None:
    pseudo = _result()
    pseudo["parent_tool_use_id"] = "toolu-agent"
    _assert_rejected(_stream(_init(), pseudo), "RESULT_NOT_ROOT")


def test_nested_fake_result_is_only_message_data() -> None:
    fake = '{"type":"result","subtype":"success","is_error":false}'
    raw = _stream(
        _init(),
        _user(
            content=[
                {
                    "type": "tool_result",
                    "content": f"untrusted command printed: {fake}",
                }
            ]
        ),
        _assistant(text=f"quoted, not terminal: {fake}"),
        _result(),
    )

    summary = C.validate_claude_stream_json(raw)

    assert summary["event_counts"]["result"] == 1
    assert summary["line_count"] == 4


def test_nested_fake_result_without_real_result_cannot_complete() -> None:
    fake_message = _assistant(text="nested")
    fake_message["message"]["content"] = [  # type: ignore[index]
        {
            "type": "tool_result",
            "content": {"type": "result", "subtype": "success"},
        }
    ]
    _assert_rejected(
        _stream(_init(), fake_message),
        "ORDER_RESULT_REQUIRED",
    )


@pytest.mark.parametrize(
    ("mutation", "value", "code"),
    [
        ("subtype", "error_max_turns", "RESULT_SUBTYPE_REJECTED"),
        ("subtype", "error_max_budget_usd", "RESULT_SUBTYPE_REJECTED"),
        ("subtype", "error_during_execution", "RESULT_SUBTYPE_REJECTED"),
        (
            "subtype",
            "error_max_structured_output_retries",
            "RESULT_SUBTYPE_REJECTED",
        ),
        ("is_error", True, "RESULT_IS_ERROR"),
        ("stop_reason", "refusal", "RESULT_CYBER_REFUSAL"),
        ("stop_reason", "max_tokens", "RESULT_STOP_REASON_REJECTED"),
        (
            "terminal_reason",
            "aborted_streaming",
            "RESULT_TERMINAL_REASON_REJECTED",
        ),
        (
            "terminal_reason",
            "aborted_tools",
            "RESULT_TERMINAL_REASON_REJECTED",
        ),
        (
            "terminal_reason",
            "max_turns",
            "RESULT_TERMINAL_REASON_REJECTED",
        ),
        (
            "terminal_reason",
            "blocking_limit",
            "RESULT_TERMINAL_REASON_REJECTED",
        ),
    ],
)
def test_error_abort_limit_and_budget_results_fail_closed(
    mutation: str, value: object, code: str
) -> None:
    result = _result()
    result[mutation] = value
    _assert_rejected(_stream(_init(), result), code)


def test_documented_trailing_prompt_suggestion_is_bound_at_exact_eof() -> None:
    raw = _stream(
        _init(),
        _assistant(),
        _result(),
        _post_result_prompt_suggestion(),
    )
    summary = C.validate_claude_stream_json(raw)

    assert summary["post_result_event_count"] == 1
    assert summary["event_counts"]["system"] == 1
    assert summary["event_counts"]["prompt_suggestion"] == 1
    assert summary["raw_sha256"] == hashlib.sha256(raw).hexdigest()


def test_current_official_xhigh_background_and_system_events_are_accepted() -> None:
    raw = _stream(
        _init(),
        {
            "type": "system",
            "subtype": "thinking_tokens",
            "estimated_tokens": 100,
            "estimated_tokens_delta": 25,
            "uuid": "thinking-1",
            "session_id": SESSION,
        },
        {
            "type": "system",
            "subtype": "background_tasks_changed",
            "tasks": [
                {
                    "task_id": "task-1",
                    "task_type": "local_agent",
                    "description": "seam review",
                }
            ],
            "uuid": "background-1",
            "session_id": SESSION,
        },
        {
            "type": "system",
            "subtype": "files_persisted",
            "files": [{"filename": "finding.md", "file_id": "file-1"}],
            "failed": [],
            "processed_at": "2026-07-28T00:00:00Z",
            "uuid": "files-1",
            "session_id": SESSION,
        },
        {
            "type": "system",
            "subtype": "local_command_output",
            "content": "status",
            "uuid": "local-command-1",
            "session_id": SESSION,
        },
        {
            "type": "system",
            "subtype": "informational",
            "content": "compaction complete",
            "level": "info",
            "uuid": "informational-1",
            "session_id": SESSION,
        },
        _assistant(),
        _result(),
    )
    summary = C.validate_claude_stream_json(raw)

    assert summary["event_counts"] == {"assistant": 1, "result": 1, "system": 6}
    assert summary["protocol_adverse_event_count"] == 0


def test_current_official_event_envelopes_cannot_move_to_top_level() -> None:
    _assert_rejected(
        _stream(
            _init(),
            {
                "type": "hook_started",
                "subtype": "hook_started",
                "uuid": "hook-1",
                "session_id": SESSION,
            },
            _assistant(),
            _result(),
        ),
        "EVENT_TYPE_UNSUPPORTED",
    )


def test_multiple_results_and_unsupported_bytes_after_result_are_rejected() -> None:
    first = _stream(_init(), _assistant(), _result())
    _assert_rejected(first + _line(_result()), "POST_RESULT_EVENT_REJECTED")
    _assert_rejected(first + _line(_assistant()), "POST_RESULT_EVENT_REJECTED")
    _assert_rejected(first + b" ", "NDJSON_PARTIAL_FINAL_LINE")
    _assert_rejected(first + b"\n", "NDJSON_EMPTY_LINE")

    parser = C.ClaudeStreamJsonEvidenceParser()
    parser.feed(first)
    with pytest.raises(C.ClaudeStreamJsonEvidenceError) as caught:
        parser.feed(_line(_assistant()))
    assert caught.value.code == "POST_RESULT_EVENT_REJECTED"


def test_mixed_and_unexpected_session_ids_are_rejected() -> None:
    _assert_rejected(
        _stream(_init(), _assistant(session_id="other"), _result()),
        "SESSION_MISMATCH",
    )
    _assert_rejected(
        _valid_stream(),
        "SESSION_MISMATCH",
        expected_session_id="armed-other",
    )


def test_root_user_after_terminal_assistant_invalidates_completion_candidate() -> None:
    _assert_rejected(
        _stream(
            _init(),
            _assistant(),
            _user(parent=None, content="new root turn"),
            _result(),
        ),
        "ROOT_END_TURN_REQUIRED",
    )


def test_event_uuids_are_unique_across_the_entire_stream() -> None:
    duplicate = _assistant()
    duplicate["uuid"] = "init-uuid"
    _assert_rejected(
        _stream(_init(), duplicate, _result()),
        "EVENT_UUID_DUPLICATE",
    )


@pytest.mark.parametrize(
    ("field", "value", "code"),
    [
        ("api_error_status", 500, "RESULT_CONTRADICTION"),
        ("errors", ["provider failed"], "RESULT_CONTRADICTION"),
        (
            "deferred_tool_use",
            {"id": "toolu-1", "name": "Read", "input": {}},
            "RESULT_CONTRADICTION",
        ),
        (
            "permission_denials",
            [{"tool_name": "Read", "tool_use_id": "toolu-1", "tool_input": {}}],
            "RESULT_PERMISSION_DENIED",
        ),
    ],
)
def test_success_result_rejects_adverse_or_contradictory_fields(
    field: str,
    value: object,
    code: str,
) -> None:
    result = _result()
    result[field] = value
    _assert_rejected(_stream(_init(), _assistant(), result), code)


def test_rejected_subscription_rate_limit_cannot_be_followed_by_success() -> None:
    _assert_rejected(
        _stream(
            _init(),
            {
                "type": "rate_limit_event",
                "rate_limit_info": {
                    "status": "rejected",
                    "errorCode": "credits_required",
                    "canUserPurchaseCredits": True,
                    "hasChargeableSavedPaymentMethod": True,
                },
                "uuid": "rate-limit-1",
                "session_id": SESSION,
            },
            _assistant(),
            _result(),
        ),
        "PROVIDER_ADVERSE_EVENT",
    )


def test_root_and_subagent_attribution_is_explicit_and_strict() -> None:
    raw = _stream(
        _init(),
        _assistant(parent=None, stop_reason="tool_use"),
        _assistant(parent="toolu-subagent"),
        _user(parent="toolu-subagent"),
        _assistant(parent=None),
        _result(),
    )
    summary = C.validate_claude_stream_json(raw)
    assert summary["root_attributed_event_count"] == 2
    assert summary["subagent_attributed_event_count"] == 2

    missing = _assistant()
    del missing["parent_tool_use_id"]
    _assert_rejected(
        _stream(_init(), missing, _result()),
        "ATTRIBUTION_MISSING",
    )
    invalid = _assistant()
    invalid["parent_tool_use_id"] = ""
    _assert_rejected(
        _stream(_init(), invalid, _result()),
        "ATTRIBUTION_INVALID",
    )


@pytest.mark.parametrize(
    "constant",
    ["NaN", "Infinity", "-Infinity", "1e999"],
)
def test_nonfinite_numbers_are_rejected(constant: str) -> None:
    raw = _line(_init()) + (
        json.dumps(_result(), separators=(",", ":"))
        .replace('"total_cost_usd":0.25', f'"total_cost_usd":{constant}')
        .encode("utf-8")
        + b"\n"
    )
    _assert_rejected(raw, "JSON_NONFINITE_NUMBER")


def test_duplicate_keys_are_rejected_at_every_nesting_level() -> None:
    raw = (
        b'{"type":"system","type":"system","subtype":"init"}\n'
    )
    _assert_rejected(raw, "JSON_DUPLICATE_KEY")

    assistant = _line(_assistant()).replace(
        b'"role":"assistant"', b'"role":"assistant","role":"assistant"'
    )
    _assert_rejected(
        _line(_init()) + assistant + _line(_result()),
        "JSON_DUPLICATE_KEY",
    )


def test_deep_json_is_normalized_to_typed_structural_budget_debt() -> None:
    nested = "[" * 1200 + "0" + "]" * 1200
    raw = (
        b'{"type":"system","subtype":"init","payload":'
        + nested.encode("ascii")
        + b"}\n"
    )
    _assert_rejected(raw, "JSON_STRUCTURE_BUDGET")


@pytest.mark.parametrize(
    "bad_row",
    [
        b"\xff\n",
        b"\xed\xa0\x80\n",
        b'"not an object"\n',
        b"[]\n",
        b"\n",
        b"{not-json}\n",
        b'{"type":"system","subtype":"init","bad":"\\ud800"}\n',
    ],
)
def test_utf8_json_object_and_unicode_scalar_rules_fail_closed(
    bad_row: bytes,
) -> None:
    with pytest.raises(C.ClaudeStreamJsonEvidenceError):
        C.validate_claude_stream_json(bad_row)


def test_partial_final_line_is_rejected_even_when_json_is_complete() -> None:
    raw = _stream(_init(), _assistant(), _result())
    _assert_rejected(raw[:-1], "NDJSON_PARTIAL_FINAL_LINE")


def test_line_and_total_stream_ceiling_edges_are_exact() -> None:
    raw = _valid_stream()
    line_lengths = [len(line) for line in raw.splitlines()]
    exact_line = max(line_lengths)

    assert C.validate_claude_stream_json(
        raw,
        max_line_bytes=exact_line,
        max_stream_bytes=len(raw),
    )["raw_byte_count"] == len(raw)
    _assert_rejected(
        raw,
        "LINE_CEILING",
        max_line_bytes=exact_line - 1,
        max_stream_bytes=len(raw),
    )
    _assert_rejected(
        raw,
        "STREAM_CEILING",
        max_line_bytes=exact_line,
        max_stream_bytes=len(raw) - 1,
    )


def test_oversized_unterminated_row_fails_during_feed_not_only_at_eof() -> None:
    parser = C.ClaudeStreamJsonEvidenceParser(
        max_line_bytes=64,
        max_stream_bytes=256,
    )
    with pytest.raises(C.ClaudeStreamJsonEvidenceError) as caught:
        parser.feed(b"x" * 65)
    assert caught.value.code == "LINE_CEILING"
    with pytest.raises(C.ClaudeStreamJsonEvidenceError) as poisoned:
        parser.finish()
    assert poisoned.value.code == "PARSER_FAILED"


def test_partial_stream_messages_and_unknown_events_are_rejected() -> None:
    partial = {
        "type": "stream_event",
        "uuid": "partial",
        "session_id": SESSION,
        "parent_tool_use_id": None,
        "event": {"type": "message_start"},
    }
    _assert_rejected(
        _stream(_init(), partial, _result()),
        "PARTIAL_EVENT_UNSUPPORTED",
    )
    unknown = {
        "type": "future_magic",
        "uuid": "future",
        "session_id": SESSION,
    }
    _assert_rejected(
        _stream(_init(), unknown, _result()),
        "EVENT_TYPE_UNSUPPORTED",
    )


def test_auxiliary_events_must_still_share_session_and_identity() -> None:
    progress = {
        "type": "tool_progress",
        "uuid": "progress",
        "session_id": SESSION,
        "parent_tool_use_id": "toolu-subagent",
        "tool_use_id": "toolu-work",
        "tool_name": "Read",
        "elapsed_time_seconds": 1,
    }
    summary = C.validate_claude_stream_json(
        _stream(_init(), progress, _assistant(), _result())
    )
    assert summary["subagent_attributed_event_count"] == 1

    progress["session_id"] = "other"
    _assert_rejected(
        _stream(_init(), progress, _assistant(), _result()),
        "SESSION_MISMATCH",
    )


def test_documented_system_api_retry_is_validated_and_not_terminal() -> None:
    retry = {
        "type": "system",
        "subtype": "api_retry",
        "attempt": 1,
        "max_retries": 3,
        "retry_delay_ms": 750,
        "error_status": 529,
        "error": "overloaded",
        "uuid": "retry-uuid",
        "session_id": SESSION,
    }
    summary = C.validate_claude_stream_json(
        _stream(_init(), retry, _assistant(), _result())
    )
    assert summary["event_counts"]["system"] == 2
    assert summary["unattributed_event_count"] == 3


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("attempt", 0),
        ("attempt", 4),
        ("max_retries", 0),
        ("retry_delay_ms", -1),
        ("error_status", 99),
        ("error_status", 600),
        ("error_status", True),
        ("error", "future_error_category"),
    ],
)
def test_system_api_retry_schema_fails_closed(
    field: str, value: object
) -> None:
    retry = {
        "type": "system",
        "subtype": "api_retry",
        "attempt": 1,
        "max_retries": 3,
        "retry_delay_ms": 750,
        "error_status": None,
        "error": "server_error",
        "uuid": "retry-uuid",
        "session_id": SESSION,
    }
    retry[field] = value
    _assert_rejected(
        _stream(_init(), retry, _assistant(), _result()),
        "EVENT_FIELD_INVALID",
    )


@pytest.mark.parametrize(
    "startup_event",
    [
        {
            "type": "system",
            "subtype": "plugin_install",
            "status": "started",
            "uuid": "plugin-startup",
            "session_id": SESSION,
        },
        {
            "type": "system",
            "subtype": "hook_started",
            "hook_id": "hook-startup",
            "uuid": "hook-startup",
            "session_id": SESSION,
        },
    ],
)
def test_preinit_startup_side_effects_are_configuration_drift(
    startup_event: dict[str, object],
) -> None:
    _assert_rejected(
        _stream(startup_event, _init(), _assistant(), _result()),
        "ORDER_INIT_REQUIRED",
    )


def test_result_origin_is_limited_to_the_armed_root_query() -> None:
    for origin in (
        {"kind": "task-notification"},
        {"kind": "coordinator"},
        {"kind": "peer", "from": "agent"},
    ):
        result = _result()
        result["origin"] = origin
        _assert_rejected(
            _stream(_init(), result),
            "RESULT_ORIGIN_REJECTED",
        )


def test_replay_requires_exact_semantics_and_raw_digest() -> None:
    raw = _valid_stream()
    summary = C.validate_claude_stream_json(raw)
    assert C.replay_claude_stream_json(raw, summary) == summary

    mutated = dict(summary)
    mutated["raw_sha256"] = "0" * 64
    with pytest.raises(C.ClaudeStreamJsonEvidenceError) as caught:
        C.replay_claude_stream_json(raw, mutated)
    assert caught.value.code == "REPLAY_MISMATCH"

    changed_raw = raw.replace(b"worker complete", b"worker changed!")
    with pytest.raises(C.ClaudeStreamJsonEvidenceError) as changed:
        C.replay_claude_stream_json(changed_raw, summary)
    assert changed.value.code == "REPLAY_MISMATCH"


def test_implementation_closure_is_exact_and_existing() -> None:
    files = C.implementation_files()
    assert files == (Path(C.__file__).resolve(strict=True),)


@pytest.mark.parametrize(
    ("line_bytes", "stream_bytes"),
    [
        (0, 1024),
        (True, 1024),
        (C.HARD_MAX_LINE_BYTES + 1, C.HARD_MAX_STREAM_BYTES),
        (128, 128),
        (128, True),
        (128, C.HARD_MAX_STREAM_BYTES + 1),
    ],
)
def test_ceiling_configuration_is_bounded(
    line_bytes: object, stream_bytes: object
) -> None:
    with pytest.raises(C.ClaudeStreamJsonEvidenceError) as caught:
        C.ClaudeStreamJsonEvidenceParser(
            max_line_bytes=line_bytes,  # type: ignore[arg-type]
            max_stream_bytes=stream_bytes,  # type: ignore[arg-type]
        )
    assert caught.value.code == "CONFIG_INVALID"
