from __future__ import annotations

import json
from pathlib import Path

import pytest

import claude_phase_tool_policy as P
import plamen_driver as D
from test_r10_demotion_gate import _authenticated_r10_report_prework_fixture


def _phase(name: str):
    return next(item for item in D.SC_PHASES if item.name == name)


def _config(project: Path, scratchpad: Path) -> dict:
    return {
        "pipeline": "sc",
        "mode": "thorough",
        "language": "evm",
        "cli_backend": "claude",
        "claude_exec_mode": "headless",
        "project_root": str(project),
        "scratchpad": str(scratchpad),
        "_run_id": "run-boundary-driver",
    }


def _bound_fixture(tmp_path: Path, phase_name: str = "chain_agent2"):
    project = tmp_path / "project"
    scratchpad = project / ".scratchpad"
    project.mkdir()
    scratchpad.mkdir()
    config = _config(project, scratchpad)
    phase = _phase(phase_name)
    contract, _launch = D._typed_model_phase_contract_and_launch(
        phase, scratchpad, config
    )
    assert contract is not None
    for identity in contract.immutable_inputs:
        root, relative = identity.split(":", 1)
        assert root == "scratchpad"
        path = scratchpad / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"input {relative}\n", encoding="utf-8")
    assert D._bind_typed_model_phase_inputs(phase, scratchpad, config) == []
    snapshot = scratchpad / f"_prompt_{phase.name}.attempt1.md"
    snapshot.write_text("bounded prompt\n", encoding="utf-8")
    for name in (
        "rag_validation.md",
        "precedent_evidence_authority.json",
        "precedent_evidence_proposals.json",
        "precedent_source_evidence.json",
        "precedent_finding_facts.json",
        "precedent_report_context.md",
    ):
        (scratchpad / name).write_text(f"FORBIDDEN::{name}\n", encoding="utf-8")
    return project, scratchpad, config, phase, contract, snapshot


def _report_bound_fixture(tmp_path: Path, monkeypatch):
    """Bind report/model only after its real committed R10 predecessor."""
    _V, driver, scratchpad, config, _contract, _launch = (
        _authenticated_r10_report_prework_fixture(
            tmp_path,
            monkeypatch,
            fired=False,
            backend="claude",
            suppress_candidate_inputs=False,
        )
    )
    ready, issues = driver._run_report_index_prework_transaction(
        scratchpad, config
    )
    assert ready is True, issues
    assert issues == []
    assert driver._r10_report_consumer_ready_issues(
        scratchpad, config
    ) == []

    project = Path(config["project_root"])
    phase = next(
        item for item in driver.SC_PHASES if item.name == "report_index"
    )
    contract, _launch = driver._typed_model_phase_contract_and_launch(
        phase, scratchpad, config
    )
    assert contract is not None
    assert len(contract.immutable_inputs) == 7
    assert all(
        (scratchpad / identity.split(":", 1)[1]).is_file()
        for identity in contract.immutable_inputs
    )
    assert driver._bind_typed_model_phase_inputs(
        phase, scratchpad, config
    ) == []
    snapshot = scratchpad / "_prompt_report_index.attempt1.md"
    snapshot.write_text("bounded report prompt\n", encoding="utf-8")
    for name in (
        "rag_validation.md",
        "precedent_context.md",
    ):
        (scratchpad / name).write_text(
            f"FORBIDDEN::{name}\n", encoding="utf-8"
        )
    return driver, project, scratchpad, config, phase, contract, snapshot


def test_driver_compiles_phaseio_inputs_into_fail_closed_claude_boundary(
    tmp_path: Path,
):
    project, scratchpad, config, phase, contract, snapshot = _bound_fixture(
        tmp_path
    )
    state = D._prepare_claude_phase_tool_boundary(
        phase=phase,
        scratchpad=scratchpad,
        config=config,
        attempt=1,
        prompt_snapshot=snapshot,
    )
    assert state is not None
    policy = P.load_policy(Path(state["policy_path"]))
    read_names = {Path(row["path"]).name for row in policy["exact_read_files"]}
    write_names = {Path(path).name for path in policy["exact_write_files"]}
    assert read_names == {
        *(identity.split(":", 1)[1] for identity in contract.immutable_inputs),
        snapshot.name,
    }
    assert write_names == {spec.path for spec in contract.outputs}
    assert "rag_validation.md" not in read_names
    assert "precedent_report_context.md" not in read_names
    assert any(
        Path(path).name == "precedent_report_context.md"
        for path in policy["forbidden_read_files"]
    )
    flags = D._claude_exact_consumer_cli_flags(state)
    assert flags[:4] == (
        "--permission-mode", "dontAsk", "--tools", "Read,Glob,Grep,Write,Edit"
    )
    assert "--dangerously-skip-permissions" not in flags
    assert "--setting-sources=" in flags
    assert "--setting-sources" not in flags
    assert Path(state["settings_path"]).is_file()
    assert json.loads(Path(state["mcp_config_path"]).read_text(encoding="utf-8")) == {
        "mcpServers": {}
    }
    assert project.is_dir()


def test_input_drift_prevents_policy_construction(tmp_path: Path):
    _, scratchpad, config, phase, contract, snapshot = _bound_fixture(tmp_path)
    identity = contract.immutable_inputs[0]
    (scratchpad / identity.split(":", 1)[1]).write_text(
        "tampered after bind\n", encoding="utf-8"
    )
    with pytest.raises(D.ArtifactLedgerError, match="input authority is invalid"):
        D._prepare_claude_phase_tool_boundary(
            phase=phase,
            scratchpad=scratchpad,
            config=config,
            attempt=1,
            prompt_snapshot=snapshot,
        )


def test_model_authority_requires_write_receipt_for_every_exact_output(
    tmp_path: Path,
):
    project, scratchpad, config, phase, contract, snapshot = _bound_fixture(
        tmp_path
    )
    state = D._prepare_claude_phase_tool_boundary(
        phase=phase,
        scratchpad=scratchpad,
        config=config,
        attempt=1,
        prompt_snapshot=snapshot,
    )
    assert state is not None
    issues = D._validate_claude_phase_tool_boundary_outputs(
        phase, config, contract
    )
    assert len(issues) == len(contract.outputs)
    policy_path = Path(state["policy_path"])
    for index, spec in enumerate(contract.outputs, 1):
        output = D._phase_identity_path(
            spec.identity, scratchpad=scratchpad, project_root=project
        )
        event = {
            "session_id": "session-output",
            "tool_use_id": f"write-{index}",
                "cwd": str(project),
                "hook_event_name": "PreToolUse",
                "tool_name": "Write",
            "tool_input": {"file_path": str(output), "content": "result"},
        }
        code, decision = P.run_hook(
            policy_path, json.dumps(event).encode("utf-8")
        )
        assert code == 0
        assert decision["hookSpecificOutput"]["permissionDecision"] == "allow", decision
    assert D._validate_claude_phase_tool_boundary_outputs(
        phase, config, contract
    ) == []


def test_report_boundary_forbids_chain_projection_and_raw_sources(
    tmp_path: Path,
    monkeypatch,
):
    driver, project, scratchpad, config, phase, contract, snapshot = (
        _report_bound_fixture(tmp_path, monkeypatch)
    )
    state = driver._prepare_claude_phase_tool_boundary(
        phase=phase,
        scratchpad=scratchpad,
        config=config,
        attempt=1,
        prompt_snapshot=snapshot,
    )
    assert state is not None
    policy = P.load_policy(Path(state["policy_path"]))
    reads = {Path(row["path"]).name for row in policy["exact_read_files"]}
    assert reads == {
        *(identity.split(":", 1)[1] for identity in contract.immutable_inputs),
        snapshot.name,
    }
    assert len(reads) == 8
    assert not reads & set(driver._R10_REPORT_PREWORK_ROSTER)
    forbidden = {Path(path).name for path in policy["forbidden_read_files"]}
    assert "precedent_context.md" in forbidden
    assert "rag_validation.md" in forbidden
    assert set(policy["exact_write_files"]) == {
        driver._phase_identity_path(
            spec.identity,
            scratchpad=scratchpad,
            project_root=project,
        ).resolve(strict=False).as_posix()
        for spec in contract.outputs
    }
    assert json.loads(
        Path(state["mcp_config_path"]).read_text(encoding="utf-8")
    ) == {"mcpServers": {}}


def test_transactional_boundary_authorizes_only_attempt_owned_outputs(
    tmp_path: Path,
):
    project, scratchpad, config, phase, contract, snapshot = _bound_fixture(
        tmp_path
    )
    staging = scratchpad / ".worker_transactions" / "attempt-output"
    staging.mkdir(parents=True)
    state = D._prepare_claude_phase_tool_boundary(
        phase=phase,
        scratchpad=scratchpad,
        config=config,
        attempt=1,
        prompt_snapshot=snapshot,
        transaction_output_directory=staging,
    )
    assert state is not None
    policy = P.load_policy(Path(state["policy_path"]))
    assert set(policy["exact_write_files"]) == {
        (staging / spec.path).resolve(strict=False).as_posix()
        for spec in contract.outputs
    }
    assert state["write_namespace"] == staging.resolve().as_posix()
    for spec in contract.outputs:
        canonical = D._phase_identity_path(
            spec.identity,
            scratchpad=scratchpad,
            project_root=project,
        )
        decision = P.evaluate_tool_call(
            tool_name="Write",
            tool_input={"file_path": str(canonical), "content": "forbidden"},
            cwd=project,
            policy=policy,
        )
        assert decision["reason_code"] == "UNREGISTERED_WRITE"
