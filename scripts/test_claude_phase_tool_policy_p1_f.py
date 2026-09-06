from __future__ import annotations

import json
from pathlib import Path

import pytest

import claude_phase_tool_policy as P


def _fixture(tmp_path: Path):
    project = tmp_path / "project"
    scratchpad = project / ".scratchpad"
    source = project / "src"
    methodology = tmp_path / "methodology"
    receipts = scratchpad / "_tool_receipts"
    for path in (scratchpad, source, methodology, receipts):
        path.mkdir(parents=True, exist_ok=True)
    allowed = scratchpad / "precedent_context.md"
    allowed.write_text("eligible context\n", encoding="utf-8")
    forbidden = scratchpad / "rag_validation.md"
    forbidden.write_text("raw precedent sentinel\n", encoding="utf-8")
    source_file = source / "Contract.sol"
    source_file.write_text("contract Contract {}\n", encoding="utf-8")
    method_file = methodology / "method.md"
    method_file.write_text("methodology\n", encoding="utf-8")
    output = scratchpad / "chain_iteration2.md"
    policy = P.build_policy_manifest(
        run_id="run-policy",
        phase="chain_iter2",
        attempt=1,
        expected_cwd=project,
        project_root=project,
        scratchpad_root=scratchpad,
        methodology_read_roots=(methodology,),
        exact_read_files=(allowed,),
        exact_write_files=(output,),
        forbidden_read_files=(forbidden,),
        receipt_directory=receipts,
    )
    return {
        "project": project,
        "scratchpad": scratchpad,
        "source": source,
        "source_file": source_file,
        "methodology": methodology,
        "method_file": method_file,
        "allowed": allowed,
        "forbidden": forbidden,
        "output": output,
        "receipts": receipts,
        "policy": policy,
    }


def _decision(fx, tool: str, tool_input: dict):
    return P.evaluate_tool_call(
        tool_name=tool,
        tool_input=tool_input,
        cwd=fx["project"],
        policy=fx["policy"],
    )


def test_exact_context_source_and_methodology_reads_are_allowed(tmp_path: Path):
    fx = _fixture(tmp_path)
    assert _decision(
        fx, "Read", {"file_path": str(fx["allowed"])}
    )["reason_code"] == "EXACT_READ"
    assert _decision(
        fx, "Read", {"file_path": str(fx["source_file"])}
    )["reason_code"] == "SOURCE_READ"
    assert _decision(
        fx, "Read", {"file_path": str(fx["method_file"])}
    )["reason_code"] == "METHODOLOGY_READ"


def test_raw_and_unregistered_scratchpad_reads_are_denied(tmp_path: Path):
    fx = _fixture(tmp_path)
    assert _decision(
        fx, "Read", {"file_path": str(fx["forbidden"])}
    )["reason_code"] == "FORBIDDEN_READ"
    other = fx["scratchpad"] / "other.md"
    other.write_text("other\n", encoding="utf-8")
    assert _decision(
        fx, "Read", {"file_path": str(other)}
    )["reason_code"] == "UNREGISTERED_READ"


def test_exact_read_hash_drift_is_denied(tmp_path: Path):
    fx = _fixture(tmp_path)
    fx["allowed"].write_text("mutated\n", encoding="utf-8")
    assert _decision(
        fx, "Read", {"file_path": str(fx["allowed"])}
    )["reason_code"] == "EXACT_READ_DRIFT"


def test_grep_exact_phaseio_input_revalidates_bound_bytes(tmp_path: Path):
    fx = _fixture(tmp_path)
    r59_call = {
        "path": str(fx["allowed"]),
        "pattern": "onlyOwner|onlyGateway|function",
        "output_mode": "count",
    }
    decision = _decision(fx, "Grep", r59_call)
    assert decision["decision"] == "ALLOW"
    assert decision["reason_code"] == "EXACT_READ_SEARCH"

    original = fx["allowed"].read_bytes()
    fx["allowed"].write_bytes(b"X" + original[1:])
    drift = _decision(fx, "Grep", r59_call)
    assert drift["decision"] == "DENY"
    assert drift["reason_code"] == "EXACT_READ_SEARCH_DRIFT"


def test_exact_input_grep_keeps_forbidden_priority_and_glob_denied(
    tmp_path: Path,
):
    fx = _fixture(tmp_path)
    overlap = P.build_policy_manifest(
        run_id="run-policy-exact-read-overlap",
        phase="breadth",
        attempt=1,
        expected_cwd=fx["project"],
        project_root=fx["project"],
        scratchpad_root=fx["scratchpad"],
        methodology_read_roots=(fx["methodology"],),
        exact_read_files=(fx["allowed"],),
        exact_write_files=(fx["output"],),
        forbidden_read_files=(fx["allowed"],),
        receipt_directory=fx["receipts"],
    )
    grep = P.evaluate_tool_call(
        tool_name="Grep",
        tool_input={"path": str(fx["allowed"]), "pattern": "eligible"},
        cwd=fx["project"],
        policy=overlap,
    )
    assert grep["decision"] == "DENY"
    assert grep["reason_code"] == "FORBIDDEN_SEARCH"
    assert _decision(
        fx, "Glob", {"path": str(fx["allowed"]), "pattern": "*"}
    )["reason_code"] == "SEARCH_EXCLUDED_ROOT"
    foreign = fx["scratchpad"] / "foreign-grep.md"
    foreign.write_text("function foreign()\n", encoding="utf-8")
    assert _decision(
        fx, "Grep", {"path": str(foreign), "pattern": "function"}
    )["reason_code"] == "SEARCH_EXCLUDED_ROOT"


def test_only_exact_output_write_and_edit_are_allowed(tmp_path: Path):
    fx = _fixture(tmp_path)
    assert _decision(
        fx, "Write", {"file_path": str(fx["output"]), "content": "x"}
    )["reason_code"] == "EXACT_WRITE"
    foreign = fx["scratchpad"] / "foreign.md"
    assert _decision(
        fx, "Edit", {"file_path": str(foreign), "old_string": "a", "new_string": "b"}
    )["reason_code"] == "UNREGISTERED_WRITE"


def test_exact_attempt_output_can_be_self_checked_after_write(tmp_path: Path):
    fx = _fixture(tmp_path)
    assert _decision(
        fx, "Read", {"file_path": str(fx["output"])}
    )["reason_code"] == "READ_PATH_UNRESOLVABLE"

    fx["output"].write_text("result\n", encoding="utf-8")
    assert _decision(
        fx, "Read", {"file_path": str(fx["output"])}
    )["reason_code"] == "ASSIGNED_OUTPUT_READ"
    assert _decision(
        fx, "Grep", {"path": str(fx["output"]), "pattern": "result"}
    )["reason_code"] == "ASSIGNED_OUTPUT_SEARCH"
    assert _decision(
        fx, "Glob", {"path": str(fx["output"]), "pattern": "*"}
    )["reason_code"] == "SEARCH_EXCLUDED_ROOT"

    overlap = P.build_policy_manifest(
        run_id="run-policy-overlap",
        phase="chain_iter2",
        attempt=1,
        expected_cwd=fx["project"],
        project_root=fx["project"],
        scratchpad_root=fx["scratchpad"],
        methodology_read_roots=(fx["methodology"],),
        exact_read_files=(fx["allowed"],),
        exact_write_files=(fx["output"],),
        forbidden_read_files=(fx["output"],),
        receipt_directory=fx["receipts"],
    )
    for tool, tool_input in (
        ("Read", {"file_path": str(fx["output"])}),
        ("Grep", {"path": str(fx["output"]), "pattern": "result"}),
    ):
        decision = P.evaluate_tool_call(
            tool_name=tool,
            tool_input=tool_input,
            cwd=fx["project"],
            policy=overlap,
        )
        assert decision["decision"] == "DENY"
        assert decision["reason_code"].startswith("FORBIDDEN_")

    foreign = fx["scratchpad"] / "foreign-output.md"
    foreign.write_text("result\n", encoding="utf-8")
    assert _decision(
        fx, "Read", {"file_path": str(foreign)}
    )["reason_code"] == "UNREGISTERED_READ"
    assert _decision(
        fx, "Grep", {"path": str(foreign), "pattern": "result"}
    )["reason_code"] == "SEARCH_EXCLUDED_ROOT"


def test_shell_web_mcp_agent_and_unknown_tools_are_denied(tmp_path: Path):
    fx = _fixture(tmp_path)
    for tool in ("Bash", "WebFetch", "WebSearch", "Task", "Agent", "mcp__x__y"):
        assert _decision(fx, tool, {})["reason_code"] == "TOOL_DENIED"
    assert _decision(fx, "NotebookEdit", {})["reason_code"] == "UNKNOWN_TOOL"


def test_search_requires_safe_source_subtree_when_scratchpad_is_nested(
    tmp_path: Path,
):
    fx = _fixture(tmp_path)
    assert _decision(
        fx, "Grep", {"path": str(fx["source"]), "pattern": "contract"}
    )["reason_code"] == "SAFE_SOURCE_SEARCH"
    assert _decision(
        fx, "Glob", {"path": str(fx["project"]), "pattern": "**/*"}
    )["reason_code"] == "UNSAFE_SEARCH_ROOT"
    assert _decision(
        fx, "Grep", {"path": str(fx["scratchpad"]), "pattern": "sentinel"}
    )["reason_code"] == "SEARCH_EXCLUDED_ROOT"


def test_traversal_ads_and_cwd_mismatch_are_denied(tmp_path: Path):
    fx = _fixture(tmp_path)
    assert _decision(
        fx, "Read", {"file_path": "src/Contract.sol:stream"}
    )["reason_code"] == "PATH_TEXT_INVALID"
    outside = tmp_path / "outside.txt"
    outside.write_text("outside\n", encoding="utf-8")
    assert _decision(
        fx, "Read", {"file_path": "../outside.txt"}
    )["reason_code"] in {"UNREGISTERED_READ", "READ_PATH_UNRESOLVABLE"}
    decision = P.evaluate_tool_call(
        tool_name="Read",
        tool_input={"file_path": str(fx["source_file"])},
        cwd=tmp_path,
        policy=fx["policy"],
    )
    assert decision["reason_code"] == "CWD_MISMATCH"


def test_policy_digest_and_field_denominator_fail_closed(tmp_path: Path):
    fx = _fixture(tmp_path)
    broken = dict(fx["policy"])
    broken["phase"] = "report_index"
    with pytest.raises(P.ClaudePhaseToolPolicyError, match="digest"):
        P.validate_policy_manifest(broken)
    extra = dict(fx["policy"])
    extra["unexpected"] = True
    with pytest.raises(P.ClaudePhaseToolPolicyError, match="denominator"):
        P.validate_policy_manifest(extra)


def test_settings_overlay_uses_all_tool_exec_hook_and_explicit_denies(
    tmp_path: Path,
):
    fx = _fixture(tmp_path)
    policy_path = fx["scratchpad"] / "policy.json"
    policy_path.write_bytes(P.canonical_json_bytes(fx["policy"]))
    settings = P.build_settings_overlay(
        policy=fx["policy"],
        policy_path=policy_path,
        hook_script=Path(P.__file__),
    )
    pre = settings["hooks"]["PreToolUse"][0]
    hook = pre["hooks"][0]
    assert pre["matcher"] == ".*"
    assert hook["type"] == "command"
    assert hook["args"][-2:] == ["--policy", policy_path.resolve().as_posix()]
    assert any("rag_validation.md" in row for row in settings["permissions"]["deny"])
    assert settings["permissions"]["defaultMode"] == "default"
    assert {"Glob", "Grep", "Read"}.issubset(
        settings["permissions"]["allow"]
    )
    exact_rules = P.exact_edit_permission_rules([fx["output"]])
    assert settings["permissions"]["allow"] == sorted(
        {"Glob", "Grep", "Read", *exact_rules}
    )
    assert "Edit" not in settings["permissions"]["allow"]
    assert "Write" not in settings["permissions"]["allow"]
    assert settings["mcpServers"] == {}
    assert settings["enabledPlugins"] == {}


def test_hook_persists_content_free_idempotent_receipt(tmp_path: Path):
    fx = _fixture(tmp_path)
    policy_path = fx["scratchpad"] / "policy.json"
    policy_path.write_bytes(P.canonical_json_bytes(fx["policy"]))
    event = {
        "session_id": "session-1",
        "tool_use_id": "tool-1",
        "cwd": str(fx["project"]),
        "hook_event_name": "PreToolUse",
        "tool_name": "Read",
        "tool_input": {"file_path": str(fx["allowed"])},
    }
    raw = json.dumps(event).encode("utf-8")
    first = P.run_hook(policy_path, raw)
    second = P.run_hook(policy_path, raw)
    assert first == second
    assert first[0] == 0
    assert first[1]["hookSpecificOutput"]["permissionDecision"] == "allow"
    receipts = list(fx["receipts"].glob("*.json"))
    assert len(receipts) == 1
    receipt = json.loads(receipts[0].read_text(encoding="utf-8"))
    assert receipt["decision"] == "ALLOW"
    assert "tool_input" not in receipt
    assert "content" not in receipt


def test_receipt_failure_denies_an_otherwise_allowed_call(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
):
    fx = _fixture(tmp_path)
    policy_path = fx["scratchpad"] / "policy.json"
    policy_path.write_bytes(P.canonical_json_bytes(fx["policy"]))
    monkeypatch.setattr(
        P,
        "_persist_receipt",
        lambda *_a, **_k: (_ for _ in ()).throw(
            P.ClaudePhaseToolPolicyError("synthetic receipt failure")
        ),
    )
    event = {
        "session_id": "session-1",
        "tool_use_id": "tool-1",
        "cwd": str(fx["project"]),
        "hook_event_name": "PreToolUse",
        "tool_name": "Read",
        "tool_input": {"file_path": str(fx["allowed"])},
    }
    code, output = P.run_hook(policy_path, json.dumps(event).encode("utf-8"))
    assert code == 0
    assert output["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert output["hookSpecificOutput"]["permissionDecisionReason"] == (
        "RECEIPT_PERSISTENCE_FAILED"
    )


def test_malformed_or_oversized_hook_event_blocks(tmp_path: Path):
    fx = _fixture(tmp_path)
    policy_path = fx["scratchpad"] / "policy.json"
    policy_path.write_bytes(P.canonical_json_bytes(fx["policy"]))
    code, _ = P.run_hook(policy_path, b"not-json")
    assert code == 2
    code, _ = P.run_hook(
        policy_path,
        b"{" + (b"x" * (P.DEFAULT_MAX_HOOK_INPUT_BYTES + 1)),
    )
    assert code == 2


def test_exact_output_requires_a_valid_allowed_write_receipt(tmp_path: Path):
    fx = _fixture(tmp_path)
    assert P.validate_write_receipt_coverage(fx["policy"]) == [
        "exact model output lacks allowed Write/Edit receipt: "
        + fx["output"].resolve(strict=False).as_posix()
    ]
    policy_path = fx["scratchpad"] / "policy.json"
    policy_path.write_bytes(P.canonical_json_bytes(fx["policy"]))
    event = {
        "session_id": "session-write",
        "tool_use_id": "tool-write",
        "cwd": str(fx["project"]),
        "hook_event_name": "PreToolUse",
        "tool_name": "Write",
        "tool_input": {"file_path": str(fx["output"]), "content": "result"},
    }
    code, output = P.run_hook(policy_path, json.dumps(event).encode("utf-8"))
    assert code == 0
    assert output["hookSpecificOutput"]["permissionDecision"] == "allow"
    assert P.validate_write_receipt_coverage(fx["policy"]) == []


def test_staged_exact_output_gate_requires_matching_policy_and_write_receipt(
    tmp_path: Path,
):
    fx = _fixture(tmp_path)
    policy_path = fx["scratchpad"] / "policy.json"
    policy_path.write_bytes(P.canonical_json_bytes(fx["policy"]))
    context = {
        "schema": "plamen.claude_exact_staged_gate.v1",
        "policy_path": policy_path.resolve().as_posix(),
        "manifest_digest": fx["policy"]["manifest_digest"],
        "output_directory": fx["scratchpad"].resolve().as_posix(),
        "expected_outputs": ["chain_iteration2.md"],
    }
    staged = {"chain_iteration2.md": b"substantive result\n"}
    assert P.staged_exact_output_receipt_validator(staged, context) == [
        "exact model output lacks allowed Write/Edit receipt: "
        + fx["output"].resolve(strict=False).as_posix()
    ]
    event = {
        "session_id": "session-stage",
        "tool_use_id": "tool-stage",
        "cwd": str(fx["project"]),
        "hook_event_name": "PreToolUse",
        "tool_name": "Write",
        "tool_input": {"file_path": str(fx["output"]), "content": "result"},
    }
    code, _ = P.run_hook(policy_path, json.dumps(event).encode("utf-8"))
    assert code == 0
    assert P.staged_exact_output_receipt_validator(staged, context) == []
    assert P.staged_exact_output_receipt_validator(
        {"scratchpad:chain_iteration2.md": b"substantive result\n"},
        context,
    ) == []
    assert P.staged_exact_output_receipt_validator(
        {"foreign.md": b"x"}, context
    ) == ["staged exact-output denominator mismatch"]
    assert P.staged_exact_output_receipt_validator(
        {
            "chain_iteration2.md": b"x",
            "scratchpad:chain_iteration2.md": b"x",
        },
        context,
    ) == ["staged exact-output denominator mismatch"]


def test_staged_exact_output_gate_composes_recon_selection_validation(
    tmp_path: Path,
):
    fx = _fixture(tmp_path)
    policy_path = fx["scratchpad"] / "policy.json"
    policy_path.write_bytes(P.canonical_json_bytes(fx["policy"]))
    event = {
        "session_id": "session-selection-stage",
        "tool_use_id": "tool-selection-stage",
        "cwd": str(fx["project"]),
        "hook_event_name": "PreToolUse",
        "tool_name": "Write",
        "tool_input": {"file_path": str(fx["output"]), "content": "result"},
    }
    code, _ = P.run_hook(policy_path, json.dumps(event).encode("utf-8"))
    assert code == 0
    selection_context = P.recon_selection_signal_staged_context(
        output="chain_iteration2.md",
        allowed_rows=("CENTRALIZATION_RISK",),
    )
    context = {
        "schema": "plamen.claude_exact_staged_gate.v1",
        "policy_path": policy_path.resolve().as_posix(),
        "manifest_digest": fx["policy"]["manifest_digest"],
        "output_directory": fx["scratchpad"].resolve().as_posix(),
        "expected_outputs": ["chain_iteration2.md"],
        "selection_signal": selection_context,
    }
    prefix = b"# substantive recon\n\n"
    invented = {
        "scratchpad:chain_iteration2.md": prefix
        + b'<!-- PLAMEN_SIGNALS: {"required_skills":["UPGRADEABLE_PROXY"]} -->\n'
    }
    issues = P.staged_exact_output_receipt_validator(invented, context)
    assert len(issues) == 1
    assert "UNKNOWN_SKILL_ID" in issues[0]

    empty = {
        "scratchpad:chain_iteration2.md": prefix
        + b'<!-- PLAMEN_SIGNALS: {"required_skills":[]} -->\n'
    }
    assert P.staged_exact_output_receipt_validator(empty, context) == []
    selected = {
        "scratchpad:chain_iteration2.md": prefix
        + b'<!-- PLAMEN_SIGNALS: {"required_skills":["CENTRALIZATION_RISK"]} -->\n'
    }
    assert P.staged_exact_output_receipt_validator(selected, context) == []
