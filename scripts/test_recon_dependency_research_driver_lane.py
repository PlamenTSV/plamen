"""Driver-only tests for the reserved, post-base SC R-EXT lane."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import claude_worker_prompt_consistency as consistency
import plamen_driver as D


def _config(tmp_path: Path, *, backend: str = "claude", mode: str = "core") -> dict:
    project = tmp_path / "project"
    scratchpad = project / ".scratchpad"
    project.mkdir()
    scratchpad.mkdir()
    return {
        "pipeline": "sc",
        "mode": mode,
        "language": "evm",
        "cli_backend": backend,
        "project_root": str(project),
        "scratchpad": str(scratchpad),
        "_run_id": "r-ext-driver-test",
    }


@pytest.mark.parametrize(
    ("attempt", "expected"),
    (
        (1, "dependency_research"),
        (2, "dependency_research.attempt-0002"),
        (9999, "dependency_research.attempt-9999"),
    ),
)
def test_reserved_selector_is_exact_for_initial_and_retry(attempt: int, expected: str) -> None:
    assert D._typed_worker_work_unit_selector(
        pipeline="sc",
        phase_name="recon",
        agent_id="R-EXT",
        role="external_dependency_research",
        output="recon_external_dependency_research.md",
        attempt=attempt,
    ) == expected


@pytest.mark.parametrize(
    "changes",
    (
        {"pipeline": "l1"},
        {"phase_name": "breadth"},
        {"agent_id": "R1"},
        {"role": "design_context"},
        {"output": "recon_design_context.md"},
        {"role": None},
    ),
)
def test_reserved_selector_rejects_partial_or_wrong_tuple(changes: dict[str, Any]) -> None:
    arguments = {
        "pipeline": "sc",
        "phase_name": "recon",
        "agent_id": "R-EXT",
        "role": "external_dependency_research",
        "output": "recon_external_dependency_research.md",
        "attempt": 1,
    }
    arguments.update(changes)
    with pytest.raises(ValueError, match="reserved R-EXT"):
        D._typed_worker_work_unit_selector(**arguments)


@pytest.mark.parametrize("mode", ("light", "core", "thorough"))
def test_prompt_and_runtime_contract_share_reserved_selector(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mode: str,
) -> None:
    config = _config(tmp_path, mode=mode)
    phase = next(row for row in D.SC_PHASES if row.name == "recon")
    # R-EXT has its own closed denominator; even a configured project-level
    # impact map must not leak into the registered dependency-research set.
    (Path(config["project_root"]) / "impact_map.md").write_text(
        "# Impact Map\n", encoding="utf-8"
    )
    monkeypatch.setattr(
        D,
        "_live_phase_runtime_launch_policy",
        lambda *_args: {
            "backend": "claude",
            "model": "fixture-model",
            "timeout_s": 600,
            "exec_mode": "headless",
        },
    )
    prompt = D._compile_typed_worker_prompt(
        "research",
        config=config,
        phase_name="recon",
        agent_id="R-EXT",
        agent_role="external_dependency_research",
        output="recon_external_dependency_research.md",
        attempt=1,
    )
    contract, launch = D._typed_model_worker_contract_and_launch(
        phase=phase,
        config=config,
        scratchpad=Path(config["scratchpad"]),
        project_root=config["project_root"],
        agent_id="R-EXT",
        agent_role="external_dependency_research",
        output="recon_external_dependency_research.md",
        timeout_s=600,
        attempt=1,
    )
    assert contract.work_unit_id == "dependency_research"
    assert "/recon/dependency_research" in prompt
    assert launch.work_unit_key == contract.key
    assert launch.tool_policy == ("filesystem", "network")
    expected_shards = {
        "recon_build_static.md", "recon_inventory_surface.md",
        *(
            {"recon_design_context.md", "recon_templates_patterns.md"}
            if mode != "light" else set()
        ),
    }
    assert set(contract.immutable_inputs) == {
        "scratchpad:external_dependency_obligations.json"
    }
    assert set(contract.bounded_lookup_inputs) == {
        f"scratchpad:{name}" for name in expected_shards
    }
    assert "scratchpad:impact_map_evidence.md" not in prompt


@pytest.mark.parametrize(
    ("mode", "base_shards"),
    (
        ("light", {"recon_build_static.md", "recon_inventory_surface.md"}),
        ("core", {
            "recon_build_static.md", "recon_design_context.md",
            "recon_inventory_surface.md", "recon_templates_patterns.md",
        }),
        ("thorough", {
            "recon_build_static.md", "recon_design_context.md",
            "recon_inventory_surface.md", "recon_templates_patterns.md",
        }),
    ),
)
def test_actual_rext_prelaunch_binds_registered_mode_denominator(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
    base_shards: set[str],
) -> None:
    config = _config(tmp_path, mode=mode)
    project = Path(config["project_root"])
    scratchpad = Path(config["scratchpad"])
    expected = {"external_dependency_obligations.json", *base_shards}
    for name in expected:
        (scratchpad / name).write_text(f"fixture:{name}\n", encoding="utf-8")
    phase = next(row for row in D.SC_PHASES if row.name == "recon")
    monkeypatch.setattr(
        D,
        "_live_phase_runtime_launch_policy",
        lambda *_args: {
            "backend": "claude", "model": "fixture-model",
            "timeout_s": 600, "exec_mode": "headless",
        },
    )

    assert D._prepare_typed_model_worker_launch(
        phase=phase,
        config=config,
        scratchpad=scratchpad,
        project_root=str(project),
        agent_id="R-EXT",
        agent_role="external_dependency_research",
        output="recon_external_dependency_research.md",
        timeout_s=600,
        attempt=1,
    ) == []

    key = f"sc/{mode}/evm/claude/recon/dependency_research"
    unit = D.read_artifact_ledger(scratchpad)["work_units"][key]
    assert set(unit["input_bindings"]) == {
        f"scratchpad:{name}" for name in expected
    }
    assert set(unit["contract_manifest"]["immutable_inputs"]) == {
        "scratchpad:external_dependency_obligations.json"
    }
    assert set(unit["contract_manifest"]["bounded_lookup_inputs"]) == {
        f"scratchpad:{name}" for name in base_shards
    }


def test_rext_prompt_requires_serial_search_then_fetch(
    tmp_path: Path,
) -> None:
    config = _config(tmp_path)
    prompt = D._build_recon_worker_prompt(
        job={
            "agent_id": "R-EXT",
            "role": "external_dependency_research",
            "output": "recon_external_dependency_research.md",
            "focus": "dependency research",
        },
        scratchpad=Path(config["scratchpad"]),
        project_root=config["project_root"],
        config=config,
        attempt=1,
    )
    assert "For each listed query group" in prompt
    assert "every obligation_id listed for the group" in prompt
    assert "Never queue or batch a WebFetch in the same assistant turn" in prompt
    assert "wait for and process its tool_result" in prompt
    assert "Search-to-result-to-Fetch chain" in prompt
    assert "next query group" in prompt
    assert "exact status RESEARCHED" in prompt
    assert "exact status NEEDS_DEPENDENCY_RESEARCH" in prompt
    assert "FETCHED, SUCCESS, prose variants" in prompt
    assert "FETCH_FAILED and no URL in Source" in prompt
    assert "For each obligation issue exactly" not in prompt
    assert "MCP" not in prompt


def test_rext_effective_prompt_matches_bounded_web_policy(
    tmp_path: Path,
) -> None:
    config = _config(tmp_path)
    project = Path(config["project_root"])
    scratchpad = Path(config["scratchpad"])
    obligations = _obligations()
    input_paths = tuple(
        scratchpad / relative
        for relative in D._recon_dependency_research_registered_inputs(config)
    )
    for path in input_paths:
        if path.name == "external_dependency_obligations.json":
            path.write_text(
                json.dumps(obligations, sort_keys=True) + "\n",
                encoding="utf-8",
            )
        else:
            path.write_text(f"# Bound input: {path.name}\n", encoding="utf-8")
    prompt = D._build_recon_worker_prompt(
        job={
            "agent_id": "R-EXT",
            "role": "external_dependency_research",
            "output": "recon_external_dependency_research.md",
            "focus": "dependency research",
        },
        scratchpad=scratchpad,
        project_root=str(project),
        config=config,
        attempt=1,
    )
    snapshot = scratchpad / "_prompt_recon_worker_R-EXT.attempt1.md"
    snapshot.write_text(prompt, encoding="utf-8")
    staged_output = scratchpad / "staged" / "recon_external_dependency_research.md"
    staged_output.parent.mkdir()
    policy, _settings = D.claude_phase_tool_policy.write_dependency_research_policy_bundle(
        obligations=obligations,
        policy_path=scratchpad / "policy.json",
        settings_path=scratchpad / "settings.json",
        hook_script=Path(D.claude_phase_tool_policy.__file__),
        run_id=config["_run_id"],
        phase="recon",
        attempt=1,
        expected_cwd=project,
        project_root=project,
        scratchpad_root=scratchpad,
        methodology_read_roots=(),
        exact_read_files=(*input_paths, snapshot),
        exact_write_files=(staged_output,),
        forbidden_read_files=(),
        receipt_directory=scratchpad / "receipts",
    )
    projection = D.claude_phase_tool_policy.build_model_visible_projection(
        policy,
        phase_io_input_paths=input_paths,
        private_exact_read_paths=(snapshot,),
    )
    effective_prompt = (
        prompt.rstrip()
        + "\n\n"
        + D.claude_phase_tool_policy.render_model_visible_supervisor_block(
            projection
        ).rstrip()
        + "\n"
    )

    tools = D.claude_phase_tool_policy.provider_builtin_tools(policy)
    assert {"WebSearch", "WebFetch"} <= set(tools)
    assert not any(tool.startswith("mcp__") for tool in tools)
    assert "MCP" not in effective_prompt
    assert "only three allowed Fetch Status values" in effective_prompt
    consistency.require_claude_worker_prompt_consistency(
        effective_prompt,
        phase_io_inputs=input_paths,
        phase_io_outputs=(scratchpad / "recon_external_dependency_research.md",),
        policy_tools=tools,
        safe_search_roots=policy["safe_search_roots"],
        project_root=project,
        scratchpad_root=scratchpad,
    )


def test_base_shards_require_one_live_committed_matching_artifact(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config(tmp_path, mode="light")
    scratchpad = Path(config["scratchpad"])
    jobs = D._recon_worker_jobs(config)
    units = {}
    for index, job in enumerate(jobs, 1):
        raw = f"base-{index}\n".encode()
        (scratchpad / job["output"]).write_bytes(raw)
        identity = f"scratchpad:{job['output']}"
        agent_id = str(job.get("agent_id") or job["output"])
        key = (
            "sc/light/evm/claude/recon/"
            + D._typed_worker_unit_id(agent_id, 1)
        )
        units[key] = {
            "run_id": config["_run_id"],
            "semantic_status": "ACTIVE",
            "execution_state": "OUTPUT_COMMITTED",
            "launch_manifest": {"timeout_s": 600},
            "artifacts": {
                identity: {
                    "sha256": hashlib.sha256(raw).hexdigest(),
                    "size": len(raw),
                }
            },
        }
    monkeypatch.setattr(D, "read_artifact_ledger", lambda _root: {"work_units": units})
    monkeypatch.setattr(D, "_recon_worker_complete", lambda *_args: (True, []))
    monkeypatch.setattr(
        D,
        "_typed_model_worker_contract_and_launch",
        lambda **kwargs: (
            SimpleNamespace(
                key=(
                    "sc/light/evm/claude/recon/"
                    + D._typed_worker_unit_id(kwargs["agent_id"], kwargs["attempt"])
                )
            ),
            SimpleNamespace(),
        ),
    )
    validation_calls: list[dict[str, Any]] = []

    def validate_committed_generation(*_args: Any, **kwargs: Any) -> list[str]:
        validation_calls.append(kwargs)
        return []

    monkeypatch.setattr(
        D, "validate_work_unit_artifacts", validate_committed_generation
    )
    assert D._dependency_research_base_shard_issues(scratchpad, config) == []
    assert len(validation_calls) == len(jobs)
    assert all(
        call.get("require_live_input_authority") is False
        for call in validation_calls
    )

    first = jobs[0]
    (scratchpad / first["output"]).write_text("tampered\n", encoding="utf-8")
    assert "bytes drifted" in " ".join(
        D._dependency_research_base_shard_issues(scratchpad, config)
    )


def test_base_shard_invalid_commit_authority_remains_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config(tmp_path, mode="light")
    scratchpad = Path(config["scratchpad"])
    job = {
        "agent_id": "R1",
        "role": "build_static",
        "output": "recon_build_static.md",
    }
    raw = b"committed base shard\n"
    (scratchpad / job["output"]).write_bytes(raw)
    identity = f"scratchpad:{job['output']}"
    key = "sc/light/evm/claude/recon/worker.r1"
    units = {key: {
        "run_id": config["_run_id"],
        "semantic_status": "ACTIVE",
        "execution_state": "OUTPUT_COMMITTED",
        "launch_manifest": {"timeout_s": 600},
        "artifacts": {identity: {
            "sha256": hashlib.sha256(raw).hexdigest(),
            "size": len(raw),
        }},
    }}
    monkeypatch.setattr(D, "_recon_worker_jobs", lambda _config: [job])
    monkeypatch.setattr(
        D, "read_artifact_ledger", lambda _root: {"work_units": units}
    )
    monkeypatch.setattr(
        D,
        "_typed_model_worker_contract_and_launch",
        lambda **_kwargs: (SimpleNamespace(key=key), SimpleNamespace()),
    )
    monkeypatch.setattr(D, "_recon_worker_complete", lambda *_args: (True, []))

    def reject_invalid_commit(*_args: Any, **kwargs: Any) -> list[str]:
        assert kwargs.get("require_live_input_authority") is False
        return ["active producer authority does not replay"]

    monkeypatch.setattr(
        D, "validate_work_unit_artifacts", reject_invalid_commit
    )
    issues = D._dependency_research_base_shard_issues(scratchpad, config)
    assert "active producer authority does not replay" in " ".join(issues)


def test_base_shard_wrong_same_run_producer_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config(tmp_path, mode="light")
    scratchpad = Path(config["scratchpad"])
    jobs = D._recon_worker_jobs(config)
    units = {}
    for index, job in enumerate(jobs, 1):
        raw = f"base-{index}\n".encode()
        (scratchpad / job["output"]).write_bytes(raw)
        identity = f"scratchpad:{job['output']}"
        agent_id = str(job.get("agent_id") or job["output"])
        key = (
            "sc/light/evm/claude/recon/"
            + D._typed_worker_unit_id(agent_id, 1)
        )
        units[key] = {
            "run_id": config["_run_id"],
            "semantic_status": "ACTIVE",
            "execution_state": "OUTPUT_COMMITTED",
            "launch_manifest": {"timeout_s": 600},
            "artifacts": {identity: {
                "sha256": hashlib.sha256(raw).hexdigest(), "size": len(raw),
            }},
        }
    first_key = next(iter(units))
    units["sc/light/evm/claude/recon/worker.attacker"] = units.pop(first_key)
    monkeypatch.setattr(D, "read_artifact_ledger", lambda _root: {"work_units": units})
    monkeypatch.setattr(D, "_recon_worker_complete", lambda *_args: (True, []))
    assert "wrong producer owner" in " ".join(
        D._dependency_research_base_shard_issues(scratchpad, config)
    )


def _obligations() -> dict:
    kind = "solidity-import"
    dependency = "vendor/package"
    source_location = "src/A.sol:L1"
    obligation_id = "DEP-" + hashlib.sha256(
        f"{kind}\0{dependency.casefold()}\0{source_location.casefold()}".encode("utf-8")
    ).hexdigest()[:12].upper()
    return {
        "schema": "plamen.external-dependency-obligations.v1",
        "provider": "deterministic-direct-nonlocal-referenced-v1",
        "obligations": [{
            "obligation_id": obligation_id,
            "dependency": dependency,
            "kind": kind,
            "source_location": source_location,
            "declaration_evidence": "import vendor/package",
            "research_question": "What behavior is relied on?",
        }],
        "observed_count": 1,
        "retained_count": 1,
        "truncated": False,
        "overflow_ids": [],
    }


def _fallback_mocks(monkeypatch: pytest.MonkeyPatch, obligations: dict) -> list[str]:
    calls: list[str] = []
    monkeypatch.setattr(D, "_publish_dependency_obligations", lambda *_a, **_k: obligations)
    monkeypatch.setattr(D, "_dependency_research_base_shard_issues", lambda *_a, **_k: [])
    monkeypatch.setattr(D, "_append_phase_io_debt", lambda *_a, **_k: calls.append("debt"))
    monkeypatch.setattr(
        D,
        "_publish_dependency_reconcile",
        lambda *_a, **_k: {
            "researched": 0,
            "unresolved": len(obligations.get("obligations", [])),
        },
    )
    return calls


def test_empty_obligations_make_zero_provider_calls(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config(tmp_path)
    calls = _fallback_mocks(monkeypatch, {"obligations": [], "truncated": False})
    monkeypatch.setattr(
        D, "_run_one_claude_headless_breadth_worker",
        lambda **_kwargs: pytest.fail("provider must not be invoked"),
    )
    phase = next(row for row in D.SC_PHASES if row.name == "recon")
    result = D._run_recon_dependency_research_headless(
        backend="claude-headless", phase=phase, config=config,
        scratchpad=Path(config["scratchpad"]), attempt=1, timeout=1,
        effective_model="fixture",
    )
    assert result["status"] == "not_applicable"
    assert result["provider_invocations"] == 0
    assert calls == []


def test_codex_rext_invokes_provider_and_degrades_failed_attempt_conservatively(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config(tmp_path, backend="codex")
    calls = _fallback_mocks(monkeypatch, _obligations())
    provider_calls: list[dict] = []

    def _failed_codex_provider(**kwargs: object) -> int:
        provider_calls.append(dict(kwargs))
        return -4

    monkeypatch.setattr(
        D, "_run_one_codex_exec",
        _failed_codex_provider,
    )
    phase = next(row for row in D.SC_PHASES if row.name == "recon")
    result = D._run_recon_dependency_research_headless(
        backend="codex", phase=phase, config=config,
        scratchpad=Path(config["scratchpad"]), attempt=1, timeout=1,
        effective_model="fixture",
    )
    assert result["status"] == "incomplete"
    assert result["provider_invocations"] == 1
    assert result["unresolved"] == 1
    assert calls
    assert len(provider_calls) == 1
    assert provider_calls[0]["label"] == "recon_worker_R-EXT"
    assert provider_calls[0]["expected_outputs"] == [
        "recon_external_dependency_research.md"
    ]


def test_legacy_pty_rext_degrades_without_launch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config(tmp_path)
    calls = _fallback_mocks(monkeypatch, _obligations())
    monkeypatch.setattr(
        D, "_run_single_recon_worker_pty",
        lambda **_kwargs: pytest.fail("legacy PTY R-EXT must not be invoked"),
    )
    phase = next(row for row in D.SC_PHASES if row.name == "recon")
    result = D._run_recon_dependency_research_wave(
        scratchpad=Path(config["scratchpad"]),
        project_root=config["project_root"], config=config, phase=phase,
        base_cmd=[], env={}, timeout=1, quiescence_s=1, attempt=1,
    )
    assert result["status"] == "unsupported_backend_receipts"
    assert result["provider_invocations"] == 0
    assert result["unresolved"] == 1
    assert calls == ["debt"]


def test_parity_repair_never_reuses_stale_unreceipted_research_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config(tmp_path)
    scratchpad = Path(config["scratchpad"])
    obligation_id = _obligations()["obligations"][0]["obligation_id"]
    stale = (
        "| Obligation ID | Source | Fetch Status |\n"
        "|---|---|---|\n"
        f"| {obligation_id} | https://attacker.invalid/fake | RESEARCHED |\n"
    )
    (scratchpad / "recon_external_dependency_research.md").write_text(
        stale, encoding="utf-8"
    )
    (scratchpad / "external_dependency_research.md").write_text(
        stale, encoding="utf-8"
    )
    obligations = _obligations()
    captured: list[str] = []
    monkeypatch.setattr(D, "_publish_dependency_obligations", lambda *_a, **_k: obligations)
    monkeypatch.setattr(
        D, "_dependency_research_authority",
        lambda *_a, **_k: {"state": "EXPLICIT_ABSENCE"},
    )

    def reconcile(*_args, **kwargs):
        captured.append(str(kwargs.get("worker_text") or ""))
        (scratchpad / "external_dependency_research.md").write_text(
            f"| Obligation ID |\n|---|\n| {obligation_id} |\n",
            encoding="utf-8",
        )
        return {"researched": 0, "unresolved": 1}

    monkeypatch.setattr(D, "_publish_dependency_reconcile", reconcile)
    monkeypatch.setattr(D, "validate_dependency_ledger_parity", lambda *_a: (True, []))
    result = D._ensure_recon_dependency_parity(
        scratchpad, config["project_root"], config
    )
    assert captured == [""]
    assert result["researched"] == 0


def test_legacy_active_rext_row_without_transaction_authority_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config(tmp_path)
    scratchpad = Path(config["scratchpad"])
    raw = b"| Obligation ID | Source | Fetch Status |\n"
    (scratchpad / "recon_external_dependency_research.md").write_bytes(raw)
    key = "sc/core/evm/claude/recon/dependency_research"
    monkeypatch.setattr(
        D,
        "read_artifact_ledger",
        lambda _root: {"work_units": {key: {
            "run_id": config["_run_id"],
            "semantic_status": "ACTIVE",
            "execution_state": "OUTPUT_COMMITTED",
            "work_unit_key": key,
            "artifacts": {
                "scratchpad:recon_external_dependency_research.md": {
                    "sha256": hashlib.sha256(raw).hexdigest(),
                    "size": len(raw),
                }
            },
            "commit_authority": {
                "output_authority_source": "LEGACY_DESCRIPTOR_CAPTURE"
            },
        }}},
    )
    with pytest.raises(D.ArtifactLedgerError, match="transactional CAS"):
        D._validated_dependency_research_authority(scratchpad, config)
    authority = D._dependency_research_authority(scratchpad, config)
    assert authority["state"] == "INVALID"
    assert "transactional CAS" in " ".join(authority["issues"])


def test_stale_rext_after_crash_is_not_adopted_when_boundary_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config(tmp_path)
    scratchpad = Path(config["scratchpad"])
    stale = "| Obligation ID | Source | Fetch Status |\n|---|---|---|\n"
    (scratchpad / "recon_external_dependency_research.md").write_text(
        stale, encoding="utf-8"
    )
    obligations = _obligations()
    calls = _fallback_mocks(monkeypatch, obligations)
    monkeypatch.setattr(
        D, "_dependency_research_authority",
        lambda *_a, **_k: {"state": "EXPLICIT_ABSENCE"},
    )
    monkeypatch.setattr(D, "_prepare_typed_model_worker_launch", lambda **_k: [])
    monkeypatch.setattr(D, "_build_recon_worker_prompt", lambda **_k: "research")
    monkeypatch.setattr(
        D,
        "_run_one_claude_headless_breadth_worker",
        lambda **_k: (_ for _ in ()).throw(
            D.claude_phase_tool_policy.ClaudePhaseToolPolicyError(
                "fixture boundary failure"
            )
        ),
    )
    monkeypatch.setattr(
        D, "_record_typed_model_worker_artifact",
        lambda **_k: pytest.fail("stale R-EXT bytes must never be adopted"),
    )
    phase = next(row for row in D.SC_PHASES if row.name == "recon")
    result = D._run_recon_dependency_research_headless(
        backend="claude-headless", phase=phase, config=config,
        scratchpad=scratchpad, attempt=1, timeout=1,
        effective_model="fixture",
    )
    assert result["status"] == "provider_boundary_debt"
    assert result["provider_invocations"] == 0
    assert result["unresolved"] == 1
    assert calls == ["debt"]


def test_invalid_active_rext_row_still_reconciles_full_unresolved(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config(tmp_path)
    scratchpad = Path(config["scratchpad"])
    obligations = _obligations()
    raw = b"| Obligation ID | Source | Fetch Status |\n"
    (scratchpad / "recon_external_dependency_research.md").write_bytes(raw)
    key = "sc/core/evm/claude/recon/dependency_research"
    units = {key: {
        "run_id": config["_run_id"],
        "semantic_status": "ACTIVE",
        "execution_state": "OUTPUT_COMMITTED",
        "work_unit_key": key,
        "artifacts": {
            "scratchpad:recon_external_dependency_research.md": {
                "sha256": hashlib.sha256(raw).hexdigest(), "size": len(raw),
            }
        },
        "commit_authority": {
            "output_authority_source": "LEGACY_DESCRIPTOR_CAPTURE"
        },
    }}
    debts: list[str] = []
    monkeypatch.setattr(D, "read_artifact_ledger", lambda _root: {"work_units": units})
    monkeypatch.setattr(D, "_publish_dependency_obligations", lambda *_a, **_k: obligations)
    monkeypatch.setattr(D, "_dependency_research_base_shard_issues", lambda *_a, **_k: [])
    monkeypatch.setattr(D, "_append_phase_io_debt", lambda *_a, **_k: debts.append("debt"))
    monkeypatch.setattr(D, "_prepare_typed_model_worker_launch", lambda **_k: [])
    monkeypatch.setattr(D, "_build_recon_worker_prompt", lambda **_k: "research")
    monkeypatch.setattr(
        D, "_run_one_claude_headless_breadth_worker",
        lambda **_k: (_ for _ in ()).throw(
            D.claude_phase_tool_policy.ClaudePhaseToolPolicyError(
                "fixture boundary failure"
            )
        ),
    )

    def reconcile(*_args, **_kwargs):
        # This is the exact historical recursive seam: reconciliation asks
        # for authority again while the invalid ACTIVE ledger row persists.
        assert D._dependency_research_authority(scratchpad, config)["state"] == "INVALID"
        return {"researched": 0, "unresolved": 1}

    monkeypatch.setattr(D, "_publish_dependency_reconcile", reconcile)
    phase = next(row for row in D.SC_PHASES if row.name == "recon")
    result = D._run_recon_dependency_research_headless(
        backend="claude-headless", phase=phase, config=config,
        scratchpad=scratchpad, attempt=1, timeout=1,
        effective_model="fixture",
    )
    assert result["status"] == "provider_boundary_debt"
    assert result["provider_invocations"] == 0
    assert result["researched"] == 0
    assert result["unresolved"] == 1
    assert debts == ["debt"]


def test_claude_rext_boundary_uses_written_bounded_web_policy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config(tmp_path, backend="claude", mode="light")
    project = Path(config["project_root"])
    scratchpad = Path(config["scratchpad"])
    for name in ("recon_build_static.md", "recon_inventory_surface.md"):
        (scratchpad / name).write_text(f"{name}\n", encoding="utf-8")
    (scratchpad / "external_dependency_obligations.json").write_text(
        json.dumps(_obligations(), sort_keys=True) + "\n", encoding="utf-8"
    )
    prompt = scratchpad / "_prompt_rext.md"
    prompt.write_text("bounded research\n", encoding="utf-8")
    methodology = tmp_path / "methodology"
    methodology.mkdir()
    phase = next(row for row in D.SC_PHASES if row.name == "recon")
    monkeypatch.setattr(D, "plamen_home", lambda: methodology)
    monkeypatch.setattr(D, "validate_work_unit_inputs", lambda *_a, **_k: [])
    monkeypatch.setattr(
        D,
        "_live_phase_runtime_launch_policy",
        lambda *_args: {
            "backend": "claude", "model": "fixture-model",
            "timeout_s": 600, "exec_mode": "headless",
        },
    )
    contract, launch = D._typed_model_worker_contract_and_launch(
        phase=phase, config=config, scratchpad=scratchpad,
        project_root=str(project), agent_id="R-EXT",
        agent_role="external_dependency_research",
        output="recon_external_dependency_research.md",
        timeout_s=600,
    )
    monkeypatch.setattr(
        D,
        "read_artifact_ledger",
        lambda _root: {
            "work_units": {
                contract.key: {"input_set_digest": "a" * 64}
            }
        },
    )
    boundary = D._prepare_claude_phase_tool_boundary(
        phase=phase,
        scratchpad=scratchpad,
        config=config,
        attempt=1,
        prompt_snapshot=prompt,
        transaction_output_directory=scratchpad / "staged",
        contract=contract,
        launch=launch,
    )
    assert boundary is not None
    policy = D.claude_phase_tool_policy.load_policy(Path(boundary["policy_path"]))
    tools = D.claude_phase_tool_policy.provider_builtin_tools(policy)
    assert set(tools) == {"Read", "Write", "Edit", "Glob", "Grep", "WebSearch", "WebFetch"}
    assert policy["external_network_policy"] == "BOUNDED_RECEIPTS"
    assert not ({"Bash", "PowerShell", "Agent", "Task", "mcp__*"} & set(tools))
    flags = D._claude_exact_consumer_cli_flags(boundary)
    assert set(flags[flags.index("--tools") + 1].split(",")) == set(tools)
    assert flags[flags.index("--allowedTools") + 1] == "Glob,Grep,Read"
    assert "--permission-mode" in flags and "default" in flags
    settings = json.loads(Path(boundary["settings_path"]).read_text(encoding="utf-8"))
    assert set(settings["hooks"]) == {"PreToolUse", "PostToolUse", "PostToolUseFailure"}
    assert settings["mcpServers"] == {}

    captured: dict[str, Any] = {}

    class StopProfileProbe(Exception):
        pass

    def semantic_intent(**kwargs):
        captured["required_capabilities"] = kwargs["required_capabilities"]
        return SimpleNamespace()

    def phase_policy(**kwargs):
        captured["permission_mode"] = kwargs["permission_mode"]
        captured["builtin_tools"] = kwargs["builtin_tools"]
        raise StopProfileProbe

    monkeypatch.setattr(D, "compile_claude_provider_semantic_intent", semantic_intent)
    monkeypatch.setattr(D, "compile_claude_phase_tool_policy", phase_policy)
    with pytest.raises(StopProfileProbe):
        D._compile_claude_driver_provider_authority(
            phase=phase,
            config=config,
            scratchpad=scratchpad,
            project_root=project,
            cwd=project,
            launch=launch,
            session_id="fixture-session",
            startup_authority_binding={},
            source_snapshot_sha256="a" * 64,
        )
    assert captured["required_capabilities"] == (
        "vendor-restricted-web-analysis",
    )
    assert captured["permission_mode"] == "default"
    assert set(captured["builtin_tools"]) == set(tools)
