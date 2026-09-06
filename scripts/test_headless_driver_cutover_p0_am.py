"""Driver compatibility-facade fixtures for the P0-AM headless cutover."""

from __future__ import annotations

import inspect
import hashlib
import json
import os
from pathlib import Path
import sys
from types import SimpleNamespace
import uuid
import venv

import pytest

import artifact_ledger as ledger
import claude_executable_observation as executable_observation
import claude_provider_preparation as provider_preparation
import plamen_driver as D
import recon_prepass as RP
import test_headless_worker_runtime_p0_am as runtime_fixture
from phase_io_contracts import LaunchSpec, resolve_phase_io_contract
from test_claude_launch_authority_fixtures import (
    OFFLINE_OAUTH_TOKEN,
    install_test_only_launch_authority_adapter,
)
from test_claude_mcp_generation_authority import (
    authenticated_mcp_selection_fixture,
)
from test_support_startup_permit import (
    FIXTURE_RUN_ID,
    durable_startup_permit,
)


def _phase() -> D.Phase:
    return D.Phase(
        name="breadth",
        section_markers=["## Breadth"],
        expected_artifacts=["analysis_*.md"],
        base_timeout_s=30,
        model="sonnet",
        min_artifact_bytes=1,
    )


def _config(tmp_path: Path, backend: str) -> dict:
    return {
        "pipeline": "sc",
        "mode": "thorough",
        "language": "evm",
        "cli_backend": backend,
        "project_root": str(tmp_path),
        "_run_id": FIXTURE_RUN_ID,
        "_auxiliary_writable_root_startup_binding": (
            durable_startup_permit(tmp_path)
        ),
        "_audit_snapshot": {"snapshot_digest": "a" * 64},
    }


def _install_offline_driver_provider(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Keep production preparation while replacing only host observations."""

    production_command_template = (
        provider_preparation._command_template
    )
    install_test_only_launch_authority_adapter(monkeypatch.setattr)
    monkeypatch.setattr(
        executable_observation,
        "run_owned_process",
        lambda *_args, **_kwargs: SimpleNamespace(
            returncode=0,
            stdout="2.1.252 (Claude Code)\n",
            stderr="",
            process_tree_terminated=True,
        ),
    )
    monkeypatch.setattr(
        provider_preparation,
        "_command_template",
        production_command_template,
    )
    monkeypatch.setattr(D, "CLAUDE_BIN", sys.executable)
    monkeypatch.setattr(D, "_DIRECT_CLAUDE_MCP_SELECTION", _runtime_selection())
    monkeypatch.setenv(
        "CLAUDE_CODE_OAUTH_TOKEN",
        OFFLINE_OAUTH_TOKEN,
    )


def _runtime_selection() -> dict[str, object]:
    """Current signed-selection shape; signature verification is upstream."""
    return authenticated_mcp_selection_fixture()


def _functional_single_link_python(tmp_path: Path) -> Path:
    """Return a relocatable interpreter with one filesystem name.

    The ordinary Windows development interpreter is commonly hard-linked and
    correctly rejected by the production execution guard.  Prefer the local
    reviewed test runtime when present; otherwise build a copy-based venv so
    the executable keeps a functional stdlib/prefix instead of relocating
    only ``python.exe``.
    """

    reviewed = Path(r"C:\p27rt\python.exe")
    if os.name == "nt" and reviewed.is_file():
        candidate = reviewed.resolve(strict=True)
    else:
        runtime_root = tmp_path / "single-link-python"
        venv.EnvBuilder(with_pip=False, symlinks=False).create(runtime_root)
        candidate = (
            runtime_root / "Scripts" / "python.exe"
            if os.name == "nt"
            else runtime_root / "bin" / "python"
        ).resolve(strict=True)
    metadata = candidate.stat()
    assert int(getattr(metadata, "st_nlink", 1) or 1) == 1
    return candidate


def _breadth_inputs(tmp_path: Path) -> None:
    for name in (
        "recon_summary.md",
        "attack_surface.md",
        "contract_inventory.md",
        "function_list.md",
        "state_variables.md",
        "template_recommendations.md",
        "opengrep_obligations_access_control_unknown.md",
    ):
        (tmp_path / name).write_text(
            f"## {name}\n\nfixture authority\n",
            encoding="utf-8",
        )


def test_codex_leaf_uses_transactional_runtime_when_phaseio_is_armed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _breadth_inputs(tmp_path)
    phase = _phase()
    config = _config(tmp_path, "codex")
    output = "analysis_access_control.md"
    assert D._prepare_typed_model_worker_launch(
        phase=phase,
        config=config,
        scratchpad=tmp_path,
        project_root=str(tmp_path),
        agent_id="access-control",
        output=output,
        timeout_s=30,
    ) == []
    _contract, typed_launch = D._typed_model_worker_contract_and_launch(
        phase=phase,
        config=config,
        scratchpad=tmp_path,
        project_root=str(tmp_path),
        agent_id="access-control",
        output=output,
        timeout_s=30,
    )

    private_python = _functional_single_link_python(tmp_path)
    monkeypatch.setattr(D, "CODEX_BIN", str(private_python))
    monkeypatch.setattr(D, "_codex_auth_available", lambda: True)
    monkeypatch.setattr(D, "_codex_prompt_fits", lambda *_args: True)

    def fake_codex_command(
        _model: str,
        *,
        needs_mcp: bool = False,
        output_last_message: str = "",
        writable_dirs=None,
    ) -> list[str]:
        del needs_mcp, output_last_message
        output_root = str(writable_dirs[0])
        return [
            str(private_python),
            "-I",
            "-c",
            (
                "from pathlib import Path; import sys; "
                "sys.stdin.buffer.read(); "
                "(Path(sys.argv[1])/'analysis_access_control.md').write_text("
                "'## Findings\\n\\nFixture analysis.\\n', encoding='utf-8')"
            ),
            output_root,
        ]

    monkeypatch.setattr(D, "_build_codex_cmd", fake_codex_command)
    rc = D._run_one_codex_exec(
        prompt="Perform the assigned breadth analysis.",
        phase=phase,
        config=config,
        scratchpad=tmp_path,
        attempt=1,
        label="breadth_worker_access-control",
        expected_outputs=[output],
        timeout=30,
        effective_model=typed_launch.model,
        agent_id="access-control",
    )

    assert rc == 0
    assert (tmp_path / output).read_text(encoding="utf-8").startswith(
        "## Findings"
    )
    transaction_completions = list(
        (tmp_path / ".worker_transactions").glob(
            "breadth/**/incorporation/incorporation.json"
        )
    )
    assert len(transaction_completions) == 1
    unit = next(
        value
        for value in ledger.read_artifact_ledger(tmp_path)[
            "work_units"
        ].values()
        if value.get("contract_manifest", {}).get("outputs", [{}])[0].get(
            "identity"
        )
        == f"scratchpad:{output}"
    )
    assert unit["semantic_status"] == "ACTIVE"
    assert unit["execution_authority"]["schema"] == (
        "plamen.worker_execution_authority.v1"
    )
    assert json.loads(transaction_completions[0].read_text(encoding="utf-8"))[
        "projection_state"
    ] == "COMPLETE"
    assert D._record_typed_model_worker_artifact(
        phase=phase,
        config=config,
        scratchpad=tmp_path,
        project_root=str(tmp_path),
        agent_id="access-control",
        output=output,
        timeout_s=30,
    ) == []


@pytest.mark.parametrize("backend", ("claude", "codex"))
def test_fanout_post_record_replays_incorporated_execution_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    backend: str,
) -> None:
    """A fan-out completion hook must not mint attempt ordinal two.

    This executes a real single-link child through the shared transactional
    runtime for both provider identities, incorporates its PhaseIO authority,
    and then exercises the driver's shared fan-out post-record hook.
    """

    private_python = _functional_single_link_python(tmp_path)
    install_test_only_launch_authority_adapter(monkeypatch.setattr)
    monkeypatch.setattr(
        runtime_fixture.sys,
        "executable",
        str(private_python.resolve(strict=True)),
    )

    contract, launch = runtime_fixture._arm(tmp_path, backend=backend)
    startup_permit = durable_startup_permit(tmp_path)
    claude_authority = (
        runtime_fixture._claude_authority(
            tmp_path,
            label="driver-fanout-post-record",
        )
        if backend == "claude"
        else None
    )
    builder = runtime_fixture._writer(
        authority=claude_authority,
        root=tmp_path,
    )
    result = runtime_fixture.runtime.execute_headless_worker(
        scratchpad=tmp_path,
        project_root=tmp_path,
        run_id=FIXTURE_RUN_ID,
        phase_io_contract=contract,
        phase_io_launch=launch,
        prompt="Analyze the assigned role and write its artifact.",
        command_builder=builder,
        cwd=tmp_path,
        environment={},
        environment_allowlist=(
            claude_authority["environment_allowlist"]
            if claude_authority is not None
            else ()
        ),
        source_snapshot_digest="a" * 64,
        methodology_digests=("b" * 64,),
        startup_authority_binding=startup_permit,
        attempt_id=(
            "attempt-" + ("c" if backend == "claude" else "d") * 24
        ),
        **runtime_fixture._claude_kwargs(
            claude_authority,
            root=tmp_path,
            builder=builder,
            startup_authority_binding=startup_permit,
        ),
    )
    before = ledger.read_artifact_ledger(tmp_path)["work_units"][contract.key]
    before_bytes = json.dumps(before, sort_keys=True, separators=(",", ":"))
    before_authority = dict(before["execution_authority"])
    before_history = tuple(before.get("attempt_history", ()))

    monkeypatch.setattr(
        D,
        "_typed_model_worker_contract_and_launch",
        lambda **_kwargs: (contract, launch),
    )
    config = _config(tmp_path, backend)
    assert D._record_typed_model_worker_artifact(
        phase=_phase(),
        config=config,
        scratchpad=tmp_path,
        project_root=str(tmp_path),
        agent_id="role-1",
        output="depth_role_1_findings.md",
        timeout_s=30,
    ) == []

    after = ledger.read_artifact_ledger(tmp_path)["work_units"][contract.key]
    assert json.dumps(after, sort_keys=True, separators=(",", ":")) == before_bytes
    assert after["execution_authority"] == before_authority
    assert tuple(after.get("attempt_history", ())) == before_history
    assert result.incorporation.execution_ref.attempt_id == (
        before_authority["attempt_id"]
    )


def test_claude_facade_selects_same_transactional_boundary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _breadth_inputs(tmp_path)
    phase = _phase()
    config = _config(tmp_path, "claude")
    output = "analysis_access_control.md"
    assert D._prepare_typed_model_worker_launch(
        phase=phase,
        config=config,
        scratchpad=tmp_path,
        project_root=str(tmp_path),
        agent_id="access-control",
        output=output,
        timeout_s=30,
    ) == []
    _contract, typed_launch = D._typed_model_worker_contract_and_launch(
        phase=phase,
        config=config,
        scratchpad=tmp_path,
        project_root=str(tmp_path),
        agent_id="access-control",
        output=output,
        timeout_s=30,
    )
    observed = {}

    def capture(**kwargs):
        observed.update(kwargs)
        return 0

    monkeypatch.setattr(D, "_run_transactional_headless_leaf", capture)
    rc = D._run_one_claude_headless_breadth_worker(
        prompt="Perform the assigned breadth analysis.",
        job={"agent_id": "access-control", "output": output},
        phase=phase,
        config=config,
        scratchpad=tmp_path,
        attempt=1,
        timeout=30,
        effective_model=typed_launch.model,
    )
    assert rc == 0
    assert observed["backend"] == "claude"
    assert observed["contract"].work_unit_id == "worker.access-control"
    assert observed["launch"].backend == "claude"


def test_unarmed_codex_worker_identity_fails_closed_before_spawn(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    phase = _phase()
    config = _config(tmp_path, "codex")
    output = "analysis_access_control.md"
    monkeypatch.setattr(D, "CODEX_BIN", sys.executable)
    monkeypatch.setattr(D, "_codex_auth_available", lambda: True)
    monkeypatch.setattr(D, "_codex_prompt_fits", lambda *_args: True)
    monkeypatch.setattr(
        D.subprocess,
        "Popen",
        lambda *_args, **_kwargs: pytest.fail(
            "unarmed typed Codex worker reached raw Popen"
        ),
    )
    monkeypatch.setattr(
        D,
        "_run_transactional_headless_leaf",
        lambda **_kwargs: pytest.fail(
            "unarmed typed Codex worker reached transactional execution"
        ),
    )

    rc = D._run_one_codex_exec(
        prompt="Perform the assigned breadth analysis.",
        phase=phase,
        config=config,
        scratchpad=tmp_path,
        attempt=1,
        label="breadth_worker_access-control",
        expected_outputs=[output],
        timeout=30,
        effective_model="gpt-5.4",
        agent_id="access-control",
    )

    assert rc == D.EXIT_ERROR
    assert not (tmp_path / output).exists()


def test_unarmed_claude_worker_identity_fails_closed_before_spawn(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    phase = _phase()
    config = _config(tmp_path, "claude")
    output = "analysis_access_control.md"
    monkeypatch.setattr(
        D.subprocess,
        "Popen",
        lambda *_args, **_kwargs: pytest.fail(
            "unarmed typed Claude worker reached raw Popen"
        ),
    )
    monkeypatch.setattr(
        D,
        "_run_transactional_headless_leaf",
        lambda **_kwargs: pytest.fail(
            "unarmed typed Claude worker reached transactional execution"
        ),
    )

    rc = D._run_one_claude_headless_breadth_worker(
        prompt="Perform the assigned breadth analysis.",
        job={"agent_id": "access-control", "output": output},
        phase=phase,
        config=config,
        scratchpad=tmp_path,
        attempt=1,
        timeout=30,
        effective_model="claude-sonnet",
    )

    assert rc == D.EXIT_ERROR
    assert not (tmp_path / output).exists()


def test_armed_codex_account_default_retry_fails_closed_before_execution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _breadth_inputs(tmp_path)
    phase = _phase()
    config = _config(tmp_path, "codex")
    config["_codex_skip_model"] = True
    output = "analysis_access_control.md"
    assert D._prepare_typed_model_worker_launch(
        phase=phase,
        config=config,
        scratchpad=tmp_path,
        project_root=str(tmp_path),
        agent_id="access-control",
        output=output,
        timeout_s=30,
    ) == []
    monkeypatch.setattr(D, "CODEX_BIN", sys.executable)
    monkeypatch.setattr(D, "_codex_auth_available", lambda: True)
    monkeypatch.setattr(D, "_codex_prompt_fits", lambda *_args: True)
    monkeypatch.setattr(
        D.subprocess,
        "Popen",
        lambda *_args, **_kwargs: pytest.fail(
            "account-default retry reached raw Popen"
        ),
    )
    monkeypatch.setattr(
        D,
        "_run_transactional_headless_leaf",
        lambda **_kwargs: pytest.fail(
            "account-default retry reached transactional execution"
        ),
    )

    rc = D._run_one_codex_exec(
        prompt="Perform the assigned breadth analysis.",
        phase=phase,
        config=config,
        scratchpad=tmp_path,
        attempt=1,
        label="breadth_worker_access-control",
        expected_outputs=[output],
        timeout=30,
        effective_model="gpt-5.4",
        agent_id="access-control",
    )

    assert rc == D.EXIT_ERROR
    assert not (tmp_path / output).exists()


@pytest.mark.parametrize(
    ("phase_name", "outputs"),
    (
        ("post_verify_extract", ("post_verify_extract.md",)),
        (
            "skeptic",
            ("skeptic_findings.md", "skeptic_judge_decisions.md"),
        ),
        ("crossbatch", ("cross_batch_consistency.md",)),
        (
            "report_dedup_agent",
            ("report_dedup_agent_decisions.md",),
        ),
        ("report_disposition", ("disposition.md",)),
    ),
)
def test_additional_monolithic_model_phases_have_exact_cross_root_contracts(
    tmp_path: Path,
    phase_name: str,
    outputs: tuple[str, ...],
) -> None:
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    config = _config(tmp_path, "codex")
    config["scratchpad"] = str(scratchpad)
    phase = D.Phase(
        name=phase_name,
        section_markers=["## Fixture"],
        expected_artifacts=list(outputs),
        base_timeout_s=30,
        model="sonnet",
        min_artifact_bytes=1,
    )

    if phase_name == "post_verify_extract":
        for name in (
            "findings_inventory.md",
            "hypotheses.md",
            "verification_queue.md",
            "verify_H-01.md",
        ):
            (scratchpad / name).write_text(f"# {name}\n", encoding="utf-8")
    elif phase_name == "skeptic":
        (scratchpad / "verification_queue.md").write_text(
            "# Queue\n", encoding="utf-8"
        )
        (scratchpad / "verify_H-01.md").write_text(
            "# Verify H-01\n", encoding="utf-8"
        )
        (scratchpad / "skeptic_manifest.json").write_text(
            json.dumps(
                {
                    "phase": "skeptic",
                    "required_count": 1,
                    "findings": [
                        {
                            "finding_id": "H-01",
                            "verify_file": "verify_H-01.md",
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
    elif phase_name == "crossbatch":
        (scratchpad / "verify_H-01.md").write_text(
            "# Verify H-01\n", encoding="utf-8"
        )
        (scratchpad / "crossbatch_manifest.json").write_text(
            json.dumps(
                {
                    "phase": "crossbatch",
                    "required_count": 1,
                    "findings": [
                        {
                            "finding_id": "H-01",
                            "verify_file": "verify_H-01.md",
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
    elif phase_name == "report_dedup_agent":
        (tmp_path / "AUDIT_REPORT.md").write_text(
            "# Audit Report\n", encoding="utf-8"
        )
        for name in (
            "report_index.md",
            "finding_mapping.md",
            "report_dedup_candidate_pairs.json",
        ):
            (scratchpad / name).write_text(f"# {name}\n", encoding="utf-8")
    else:
        (tmp_path / "AUDIT_REPORT.md").write_text(
            "# Audit Report\n", encoding="utf-8"
        )

    contract, launch = D._typed_model_phase_contract_and_launch(
        phase, scratchpad, config
    )

    assert contract is not None
    assert launch is not None
    assert contract.model_invoked is True
    assert {
        spec.identity for spec in contract.outputs
    } == {f"scratchpad:{name}" for name in outputs}
    if phase_name in {"report_dedup_agent", "report_disposition"}:
        assert "project:AUDIT_REPORT.md" in contract.immutable_inputs


def test_crossbatch_driver_does_not_self_certify_omitted_model_rows() -> None:
    import inspect

    source = inspect.getsource(D._run_phase_validators)
    assert "_append_crossbatch_coverage_ledger(" not in source
    assert "_validate_crossbatch_full_coverage(" in source


def test_skeptic_contract_rejects_manifest_verify_file_traversal(
    tmp_path: Path,
) -> None:
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    (scratchpad / "verification_queue.md").write_text(
        "# Queue\n", encoding="utf-8"
    )
    (scratchpad / "skeptic_manifest.json").write_text(
        json.dumps(
            {
                "phase": "skeptic",
                "required_count": 1,
                "findings": [
                    {
                        "finding_id": "H-01",
                        "verify_file": "../verify_H-01.md",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    phase = D.Phase(
        name="skeptic",
        section_markers=["## Fixture"],
        expected_artifacts=[
            "skeptic_findings.md",
            "skeptic_judge_decisions.md",
        ],
        base_timeout_s=30,
        model="sonnet",
        min_artifact_bytes=1,
    )
    config = _config(tmp_path, "codex")
    config["scratchpad"] = str(scratchpad)

    with pytest.raises(D.ArtifactLedgerError):
        D._typed_model_phase_contract_and_launch(
            phase, scratchpad, config
        )


def test_postverify_monolith_arms_and_prepares_same_exact_transaction(
    tmp_path: Path,
) -> None:
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    for name in (
        "findings_inventory.md",
        "hypotheses.md",
        "verification_queue.md",
        "verify_H-01.md",
        "verify_M-02.md",
    ):
        (scratchpad / name).write_text(f"# {name}\n", encoding="utf-8")
    phase = D.Phase(
        name="post_verify_extract",
        section_markers=["## Fixture"],
        expected_artifacts=["post_verify_extract.md"],
        base_timeout_s=30,
        model="sonnet",
        min_artifact_bytes=1,
    )
    config = _config(tmp_path, "codex")
    config["scratchpad"] = str(scratchpad)

    assert D._bind_typed_model_phase_inputs(
        phase, scratchpad, config
    ) == []
    prepared = D._prepared_monolithic_headless_transaction_authority(
        phase=phase,
        config=config,
        scratchpad=scratchpad,
        timeout_s=30,
        attempt=1,
    )

    assert prepared is not None
    contract, launch, outputs = prepared
    assert outputs == ["post_verify_extract.md"]
    assert launch.work_unit_key == contract.key
    assert {
        "scratchpad:verify_H-01.md",
        "scratchpad:verify_M-02.md",
    }.issubset(set(contract.immutable_inputs))


def _armed_inventory_model(
    tmp_path: Path,
    *,
    backend: str,
) -> tuple[D.Phase, dict, object, LaunchSpec]:
    phase = D.Phase(
        name="inventory",
        section_markers=["## Inventory"],
        expected_artifacts=["findings_inventory.md"],
        base_timeout_s=30,
        model="sonnet",
        min_artifact_bytes=1,
    )
    config = _config(tmp_path, backend)
    config["scratchpad"] = str(tmp_path)
    if backend == "claude":
        config["claude_exec_mode"] = "headless"
    contract = resolve_phase_io_contract(
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend=backend,
        phase="inventory",
        work_unit_id="model",
        exact_inputs=(),
    )
    launch = LaunchSpec(
        work_unit_key=contract.key,
        pipeline=contract.pipeline,
        mode=contract.mode,
        ecosystem=contract.ecosystem,
        backend=contract.backend,
        model=("gpt-5.4" if backend == "codex" else "claude-sonnet"),
        timeout_s=30,
        exec_mode=("codex" if backend == "codex" else "headless"),
        tool_policy=("filesystem",),
    )
    ledger.record_work_unit_inputs(
        tmp_path,
        tmp_path,
        contract,
        launch,
        run_id=FIXTURE_RUN_ID,
    )
    return phase, config, contract, launch


def _install_exact_consumer_boundary(
    tmp_path: Path,
    config: dict,
    *,
    phase_name: str,
) -> tuple[bytes, bytes]:
    boundary_root = tmp_path / "_exact-boundary"
    policy_path = boundary_root / "policy.json"
    settings_path = boundary_root / "settings.json"
    mcp_path = boundary_root / "mcp.json"
    source = tmp_path / "exact-input.md"
    source.write_text("exact input\n", encoding="utf-8")
    policy, _settings = D.claude_phase_tool_policy.write_policy_bundle(
        policy_path=policy_path,
        settings_path=settings_path,
        hook_script=Path(D.claude_phase_tool_policy.__file__),
        run_id=FIXTURE_RUN_ID,
        phase=phase_name,
        attempt=1,
        expected_cwd=tmp_path,
        project_root=tmp_path,
        scratchpad_root=tmp_path,
        methodology_read_roots=(tmp_path,),
        exact_read_files=(source,),
        exact_write_files=(tmp_path / "report_index.md",),
        forbidden_read_files=(),
        receipt_directory=boundary_root / "receipts",
    )
    mcp_bytes = D.claude_phase_tool_policy.canonical_json_bytes(
        {"mcpServers": {}}
    )
    mcp_path.write_bytes(mcp_bytes)
    config["_claude_phase_tool_boundaries"] = {
        phase_name: {
            "settings_path": settings_path.resolve().as_posix(),
            "policy_path": policy_path.resolve().as_posix(),
            "mcp_config_path": mcp_path.resolve().as_posix(),
            "manifest_digest": policy["manifest_digest"],
        }
    }
    return settings_path.read_bytes(), mcp_bytes


def test_transactional_claude_leaf_builds_deterministic_stream_json_command(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_offline_driver_provider(monkeypatch)
    phase, config, contract, launch = _armed_inventory_model(
        tmp_path, backend="claude"
    )
    config["claude_auth_route"] = "OAUTH_TOKEN"
    commands: list[list[str]] = []
    runtime_calls: list[dict[str, object]] = []

    def capture_command(**kwargs):
        output_directory = tmp_path / "transaction-output"
        output_directory.mkdir(exist_ok=True)
        runtime_calls.append(dict(kwargs))
        commands.append(list(kwargs["command_builder"](output_directory)))
        return SimpleNamespace(stdout=b"", stderr=b"")

    monkeypatch.setattr(D, "execute_headless_worker", capture_command)
    monkeypatch.setattr(D, "_record_phase_cost", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        D, "detect_background_orphan", lambda *_args, **_kwargs: None
    )

    call = {
        "backend": "claude",
        "prompt": "inventory prompt",
        "phase": phase,
        "config": config,
        "scratchpad": tmp_path,
        "attempt": 1,
        "label": "inventory-model",
        "expected_outputs": ["findings_inventory.md"],
        "timeout": 30,
        "effective_model": launch.model,
        "contract": contract,
        "launch": launch,
        "working_directory": str(tmp_path),
        "analysis_directories": [str(tmp_path)],
    }
    assert D._run_transactional_headless_leaf(**call) == 0
    assert D._run_transactional_headless_leaf(**call) == 0
    assert len(commands) == 2
    assert len(runtime_calls) == 2
    assert commands[0] == commands[1]

    # A deterministic-looking argv is not launch authority.  Claude's shared
    # runtime fails closed unless the driver supplies the independently
    # prepared stream, launch-security, launch-request, transient host inputs,
    # and the attempt-bound restricted settings/MCP denominator.  The durable
    # adapter environment remains empty because WER derives the exact child
    # environment from those authorities.
    for runtime_call in runtime_calls:
        assert runtime_call["environment"] == {}
        assert runtime_call["provider_stdout_evidence_configuration"]
        assert runtime_call["claude_launch_security"]
        assert runtime_call["claude_launch_security_request"]
        assert runtime_call["claude_runtime_local_inputs"]
        assert type(runtime_call["claude_provider_preparation"]) is (
            provider_preparation.ClaudeProviderPreparation
        )
        settings_raw = runtime_call["claude_bound_settings_bytes"]
        assert isinstance(settings_raw, bytes)
        settings = json.loads(settings_raw.decode("utf-8"))
        assert settings["permissions"]["defaultMode"] == "default"
        allow = settings["permissions"]["allow"]
        assert {"Glob", "Grep", "Read"}.issubset(allow)
        assert len([rule for rule in allow if rule.startswith("Edit(")]) == 1
        assert "Write" not in allow
        assert not any(rule.startswith("Write(") for rule in allow)
        empty_mcp = D.claude_phase_tool_policy.canonical_json_bytes(
            {"mcpServers": {}}
        )
        assert runtime_call["claude_selected_mcp_config_bytes"] == empty_mcp
        assert tuple(runtime_call["environment_allowlist"])
        package = runtime_call["claude_provider_preparation"]
        assert package.record["settings_policy"]["mode"] == "BOUND_SETTINGS"
        assert package.record["settings_policy"]["settings_sha256"] == (
            hashlib.sha256(settings_raw).hexdigest()
        )
        assert runtime_call["claude_launch_security"] == package.record[
            "launch_security"
        ]
        assert runtime_call["claude_launch_security_request"] == (
            package.record["launch_security_request"]
        )
        expected_init = package.record["headless_profile"][
            "expected_init_contract"
        ]
        assert runtime_call[
            "provider_stdout_evidence_configuration"
        ]["expected_init_contract"] == expected_init
        assert runtime_call["claude_launch_security"][
            "headless_profile"
        ]["expected_init_contract"] == expected_init

    command = commands[0]
    package = runtime_calls[0]["claude_provider_preparation"]
    final_command = [
        *command,
        *package.record["headless_profile"]["cli_flags"],
    ]
    assert command.count("-p") == 1
    assert command.index("--model") == command.index("-p") + 1
    assert "inventory prompt" not in command
    assert command[command.index("--output-format") + 1] == "stream-json"
    assert command.count("--verbose") == 1
    assert command.count("--session-id") == 1
    session_id = command[command.index("--session-id") + 1]
    assert str(uuid.UUID(session_id)) == session_id
    assert command.count("--no-session-persistence") == 1
    assert "--include-partial-messages" not in command
    assert "--forward-subagent-output" not in command
    assert "--restricted" in final_command
    assert "--safe-mode" not in final_command
    assert final_command[final_command.index("--permission-mode") + 1] == (
        "default"
    )
    assert "--settings" not in final_command
    assert "--mcp-config" not in final_command
    assert "--disallowedTools" not in final_command
    assert "--dangerously-skip-permissions" not in final_command


def test_transactional_leaf_snapshot_collision_fails_closed_without_overwrite(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_offline_driver_provider(monkeypatch)
    phase, config, contract, launch = _armed_inventory_model(
        tmp_path, backend="claude"
    )
    config["claude_auth_route"] = "OAUTH_TOKEN"
    runtime_calls: list[dict[str, object]] = []

    def capture_command(**kwargs):
        runtime_calls.append(dict(kwargs))
        output_directory = tmp_path / "transaction-output"
        output_directory.mkdir(exist_ok=True)
        return SimpleNamespace(stdout=b"", stderr=b"")

    monkeypatch.setattr(D, "execute_headless_worker", capture_command)
    monkeypatch.setattr(D, "_record_phase_cost", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        D, "detect_background_orphan", lambda *_args, **_kwargs: None
    )
    call = {
        "backend": "claude",
        "prompt": "immutable original prompt",
        "phase": phase,
        "config": config,
        "scratchpad": tmp_path,
        "attempt": 2,
        "label": "inventory-snapshot-collision",
        "expected_outputs": ["findings_inventory.md"],
        "timeout": 30,
        "effective_model": launch.model,
        "contract": contract,
        "launch": launch,
        "working_directory": str(tmp_path),
        "analysis_directories": [str(tmp_path)],
    }

    assert D._run_transactional_headless_leaf(**call) == 0
    snapshot = tmp_path / "_prompt_inventory-snapshot-collision.attempt2.md"
    original_bytes = snapshot.read_bytes()
    assert original_bytes == b"immutable original prompt"

    call["prompt"] = "different bytes for the same immutable identity"
    assert D._run_transactional_headless_leaf(**call) == D.EXIT_ERROR
    assert snapshot.read_bytes() == original_bytes
    assert len(runtime_calls) == 1


def test_exact_consumer_propagates_bound_sources_without_driver_paths(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_offline_driver_provider(monkeypatch)
    _inventory_phase, config, contract, launch = _armed_inventory_model(
        tmp_path,
        backend="claude",
    )
    config["claude_auth_route"] = "OAUTH_TOKEN"
    phase = D.Phase(
        name="report_index",
        section_markers=["## Report Index"],
        expected_artifacts=["report_index.md"],
        base_timeout_s=30,
        model="sonnet",
        min_artifact_bytes=1,
    )
    predecessor_settings_bytes, mcp_bytes = _install_exact_consumer_boundary(
        tmp_path,
        config,
        phase_name=phase.name,
    )
    runtime_calls: list[dict[str, object]] = []

    def capture_command(**kwargs):
        output_directory = tmp_path / "transaction-output"
        output_directory.mkdir(exist_ok=True)
        runtime_calls.append(dict(kwargs))
        command = list(kwargs["command_builder"](output_directory))
        assert "--settings" not in command
        assert "--mcp-config" not in command
        return SimpleNamespace(stdout=b"", stderr=b"")

    monkeypatch.setattr(D, "execute_headless_worker", capture_command)
    monkeypatch.setattr(D, "_record_phase_cost", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        D, "detect_background_orphan", lambda *_args, **_kwargs: None
    )
    rc = D._run_transactional_headless_leaf(
        backend="claude",
        prompt="report index prompt",
        phase=phase,
        config=config,
        scratchpad=tmp_path,
        attempt=1,
        label="report-index-model",
        expected_outputs=["report_index.md"],
        timeout=30,
        effective_model=launch.model,
        contract=contract,
        launch=launch,
        working_directory=str(tmp_path),
        analysis_directories=[str(tmp_path)],
    )
    assert rc == 0
    assert len(runtime_calls) == 1
    runtime_call = runtime_calls[0]
    package = runtime_call["claude_provider_preparation"]
    boundary = config["_claude_phase_tool_boundaries"][phase.name]
    regenerated_policy = D.claude_phase_tool_policy.load_policy(
        Path(boundary["policy_path"])
    )
    regenerated_settings = Path(boundary["settings_path"]).read_bytes()
    regenerated_mcp = Path(boundary["mcp_config_path"]).read_bytes()
    assert runtime_call["environment"] == {}
    assert regenerated_settings != predecessor_settings_bytes
    assert runtime_call["claude_bound_settings_bytes"] == regenerated_settings
    assert runtime_call["claude_selected_mcp_config_bytes"] == regenerated_mcp
    assert regenerated_mcp == mcp_bytes
    assert boundary["contract_key"] == contract.key
    assert boundary["contract_digest"] == contract.digest
    assert boundary["manifest_digest"] == regenerated_policy["manifest_digest"]
    assert boundary["write_namespace"] != "canonical"
    assert package.record["settings_policy"]["mode"] == "BOUND_SETTINGS"
    assert package.record["settings_policy"]["settings_sha256"] == (
        hashlib.sha256(regenerated_settings).hexdigest()
    )
    assert package.record["mcp_policy"]["server_names"] == []
    assert package.record["mcp_policy"]["selected_config_sha256"] == (
        hashlib.sha256(mcp_bytes).hexdigest()
    )
    profile_flags = package.record["headless_profile"]["cli_flags"]
    assert "--safe-mode" not in profile_flags
    assert "--permission-mode" in profile_flags
    assert profile_flags[
        profile_flags.index("--permission-mode") + 1
    ] == "default"
    assert "--restricted" in profile_flags
    assert "--dangerously-skip-permissions" not in profile_flags
    assert "--disallowedTools" not in profile_flags


def test_exact_consumer_missing_boundary_is_regenerated_before_launch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_offline_driver_provider(monkeypatch)
    _inventory_phase, config, contract, launch = _armed_inventory_model(
        tmp_path,
        backend="claude",
    )
    config["claude_auth_route"] = "OAUTH_TOKEN"
    phase = D.Phase(
        name="report_index",
        section_markers=["## Report Index"],
        expected_artifacts=["report_index.md"],
        base_timeout_s=30,
        model="sonnet",
        min_artifact_bytes=1,
    )
    runtime_calls: list[dict[str, object]] = []

    def capture_execute(**kwargs):
        runtime_calls.append(dict(kwargs))
        return SimpleNamespace(stdout=b"", stderr=b"")

    monkeypatch.setattr(D, "execute_headless_worker", capture_execute)
    monkeypatch.setattr(D, "_record_phase_cost", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        D, "detect_background_orphan", lambda *_args, **_kwargs: None
    )
    call = {
        "backend": "claude",
        "prompt": "report index prompt",
        "phase": phase,
        "config": config,
        "scratchpad": tmp_path,
        "attempt": 1,
        "label": "report-index-missing-boundary",
        "expected_outputs": ["report_index.md"],
        "timeout": 30,
        "effective_model": launch.model,
        "contract": contract,
        "launch": launch,
        "working_directory": str(tmp_path),
        "analysis_directories": [str(tmp_path)],
    }
    assert D._run_transactional_headless_leaf(**call) == 0
    assert len(runtime_calls) == 1
    first_boundary = dict(
        config["_claude_phase_tool_boundaries"][phase.name]
    )
    first_settings = Path(first_boundary["settings_path"])
    assert runtime_calls[0]["claude_bound_settings_bytes"] == (
        first_settings.read_bytes()
    )
    assert first_boundary["contract_digest"] == contract.digest
    assert D.claude_phase_tool_policy.load_policy(first_boundary["policy_path"])[
        "manifest_digest"
    ] == first_boundary["manifest_digest"]

    # A corrupted prior boundary is never reused as current launch authority;
    # the next attempt compiles a new transaction-bound policy generation.
    first_settings.write_bytes(b"{}\n")
    assert D._run_transactional_headless_leaf(**call) == 0
    assert len(runtime_calls) == 2
    second_boundary = config["_claude_phase_tool_boundaries"][phase.name]
    assert second_boundary["settings_path"] != first_boundary["settings_path"]
    assert runtime_calls[1]["claude_bound_settings_bytes"] == Path(
        second_boundary["settings_path"]
    ).read_bytes()
    assert runtime_calls[1]["claude_bound_settings_bytes"] != b"{}\n"


def test_run_phase_routes_armed_codex_monolith_through_transaction(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    phase, config, contract, launch = _armed_inventory_model(
        tmp_path, backend="codex"
    )
    prompt_file = tmp_path / "pipeline.md"
    prompt_file.write_text("## Inventory\n", encoding="utf-8")
    observed = {}

    monkeypatch.setattr(D, "resolve_v1_prompt", lambda _pipeline: prompt_file)
    monkeypatch.setattr(D, "build_phase_prompt", lambda *_args: "inventory prompt")
    monkeypatch.setattr(
        D,
        "_live_phase_runtime_launch_policy",
        lambda *_args: {
            "backend": "codex",
            "claude_exec_mode": "headless",
            "timeout_s": 30,
            "hypothesis_count": 0,
            "model": launch.model,
            "exec_mode": launch.exec_mode,
        },
    )
    monkeypatch.setattr(D, "phase_model", lambda *_args: launch.model)
    monkeypatch.setattr(
        D,
        "_typed_model_phase_contract_and_launch",
        lambda *_args: (contract, launch),
    )
    monkeypatch.setattr(D, "_precreate_codex_artifacts", lambda *_args: None)

    def capture(**kwargs):
        observed.update(kwargs)
        return 0

    monkeypatch.setattr(D, "_run_one_codex_exec", capture)
    assert D.run_phase(phase, config, attempt=1) == 0
    assert observed["expected_outputs"] == ["findings_inventory.md"]
    assert observed["phase_io_contract"] is contract
    assert observed["phase_io_launch"] is launch


def test_run_phase_routes_armed_claude_headless_monolith_through_transaction(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    phase, config, contract, launch = _armed_inventory_model(
        tmp_path, backend="claude"
    )
    config["claude_exec_mode"] = "headless"
    prompt_file = tmp_path / "pipeline.md"
    prompt_file.write_text("## Inventory\n", encoding="utf-8")
    observed = {}

    monkeypatch.setattr(D, "resolve_v1_prompt", lambda _pipeline: prompt_file)
    monkeypatch.setattr(D, "build_phase_prompt", lambda *_args: "inventory prompt")
    monkeypatch.setattr(
        D,
        "_live_phase_runtime_launch_policy",
        lambda *_args: {
            "backend": "claude",
            "claude_exec_mode": "headless",
            "timeout_s": 30,
            "hypothesis_count": 0,
            "model": launch.model,
            "exec_mode": launch.exec_mode,
        },
    )
    monkeypatch.setattr(D, "phase_model", lambda *_args: launch.model)
    monkeypatch.setattr(
        D,
        "_typed_model_phase_contract_and_launch",
        lambda *_args: (contract, launch),
    )

    def capture(**kwargs):
        observed.update(kwargs)
        return 0

    monkeypatch.setattr(D, "_run_transactional_headless_leaf", capture)
    assert D.run_phase(phase, config, attempt=1) == 0
    assert observed["backend"] == "claude"
    assert observed["expected_outputs"] == ["findings_inventory.md"]
    assert observed["contract"] is contract
    assert observed["launch"] is launch


@pytest.mark.parametrize("backend", ["codex", "claude"])
def test_run_phase_refuses_untyped_headless_monolith_without_spawning(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    backend: str,
) -> None:
    phase = D.Phase(
        name="instantiate",
        section_markers=["## Instantiate"],
        expected_artifacts=["spawn_manifest.md"],
        base_timeout_s=30,
        model="sonnet",
        min_artifact_bytes=1,
    )
    config = _config(tmp_path, backend)
    config["scratchpad"] = str(tmp_path)
    config["claude_exec_mode"] = "headless"
    prompt_file = tmp_path / "pipeline.md"
    prompt_file.write_text("## Instantiate\n", encoding="utf-8")

    monkeypatch.setattr(D, "resolve_v1_prompt", lambda _pipeline: prompt_file)
    monkeypatch.setattr(
        D, "build_phase_prompt", lambda *_args: "instantiate prompt"
    )
    monkeypatch.setattr(
        D,
        "_live_phase_runtime_launch_policy",
        lambda *_args: {
            "backend": backend,
            "claude_exec_mode": "headless",
            "timeout_s": 30,
            "hypothesis_count": 0,
            "model": "fixture-model",
            "exec_mode": (
                "codex" if backend == "codex" else "headless"
            ),
        },
    )
    monkeypatch.setattr(D, "phase_model", lambda *_args: "fixture-model")
    monkeypatch.setattr(
        D,
        "_typed_model_phase_contract_and_launch",
        lambda *_args: (None, None),
    )
    monkeypatch.setattr(
        D,
        "_run_one_codex_exec",
        lambda **_kwargs: pytest.fail("untyped Codex worker was launched"),
    )
    monkeypatch.setattr(
        D,
        "_run_transactional_headless_leaf",
        lambda **_kwargs: pytest.fail(
            "untyped Claude worker was launched"
        ),
    )
    monkeypatch.setattr(
        D.subprocess,
        "Popen",
        lambda *_args, **_kwargs: pytest.fail(
            "raw subprocess was launched"
        ),
    )

    assert D.run_phase(phase, config, attempt=1) == D.EXIT_ERROR


def test_claude_headless_alias_normalizes_to_claude_transaction_policy(
    tmp_path: Path,
) -> None:
    phase = _phase()
    config = _config(tmp_path, "claude-headless")

    policy = D._live_phase_runtime_launch_policy(phase, tmp_path, config)

    assert policy["backend"] == "claude"
    assert policy["claude_exec_mode"] == "headless"
    assert policy["exec_mode"] == "headless"


def test_transport_config_beats_environment_and_fresh_absence_is_headless(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    phase = _phase()
    config = _config(tmp_path, "claude")
    monkeypatch.setenv("PLAMEN_CLAUDE_EXEC_MODE", "headless")
    config["claude_exec_mode"] = "pty"
    policy = D._live_phase_runtime_launch_policy(phase, tmp_path, config)
    assert policy["claude_exec_mode"] == "pty"
    assert policy["claude_exec_mode_source"] == "config"

    monkeypatch.delenv("PLAMEN_CLAUDE_EXEC_MODE")
    config.pop("claude_exec_mode")
    policy = D._live_phase_runtime_launch_policy(phase, tmp_path, config)
    assert policy["claude_exec_mode"] == "headless"
    assert policy["claude_exec_mode_source"] == "fresh-default"


@pytest.mark.parametrize(
    ("backend", "mode"),
    (("claude", "typo"), ("claude", ""), ("claude-headless", "pty")),
)
def test_invalid_explicit_transport_fails_before_phase_startup_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    backend: str,
    mode: str,
) -> None:
    phase = _phase()
    config = _config(tmp_path, backend)
    config["scratchpad"] = str(tmp_path)
    config["claude_exec_mode"] = mode
    before = tuple(tmp_path.iterdir())
    monkeypatch.setattr(
        D,
        "_run_phase_once",
        lambda *_args, **_kwargs: pytest.fail(
            "invalid transport reached phase startup"
        ),
    )
    assert D.run_phase(phase, config, attempt=1) == D.EXIT_ERROR
    assert tuple(tmp_path.iterdir()) == before


def test_explicit_claude_headless_denies_missing_process_scope_before_prompt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_offline_driver_provider(monkeypatch)
    phase, config, contract, launch = _armed_inventory_model(
        tmp_path,
        backend="claude",
    )
    monkeypatch.setattr(
        D.owned_process_scope,
        "windows_job_only_process_tree_capability",
        lambda: {
            "platform": "WINDOWS",
            "provider_owns_tree": True,
            "pre_execution_assignment": True,
            "exhaustive_descendant_termination_authority": False,
            "serialized_low_integrity_stage_authority": True,
            "medium_integrity_source_and_canonical_protection": True,
        },
    )
    monkeypatch.setattr(
        D,
        "execute_headless_worker",
        lambda **_kwargs: pytest.fail("denied scope reached provider"),
    )
    rc = D._run_transactional_headless_leaf(
        backend="claude",
        prompt="inventory prompt",
        phase=phase,
        config=config,
        scratchpad=tmp_path,
        attempt=1,
        label="scope-denial",
        expected_outputs=["findings_inventory.md"],
        timeout=30,
        effective_model=launch.model,
        contract=contract,
        launch=launch,
        working_directory=str(tmp_path),
        analysis_directories=[str(tmp_path)],
    )
    assert rc == D.EXIT_ERROR
    assert not (tmp_path / "_prompt_scope-denial.attempt1.md").exists()
    assert not (tmp_path / ".worker_transactions").exists()


def test_explicit_claude_headless_rechecks_scope_immediately_before_launch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_offline_driver_provider(monkeypatch)
    phase, config, contract, launch = _armed_inventory_model(
        tmp_path,
        backend="claude",
    )
    config["claude_auth_route"] = "OAUTH_TOKEN"
    real_replay = D._replay_explicit_claude_headless_launch_boundary
    calls = 0

    def drifting_replay(**kwargs):
        nonlocal calls
        calls += 1
        binding, capability = real_replay(**kwargs)
        if calls == 2:
            capability = {**capability, "strategy": "DRIFTED"}
        return binding, capability

    monkeypatch.setattr(
        D,
        "_replay_explicit_claude_headless_launch_boundary",
        drifting_replay,
    )
    monkeypatch.setattr(
        D,
        "execute_headless_worker",
        lambda **_kwargs: pytest.fail("drifted scope reached provider"),
    )
    monkeypatch.setattr(D, "_record_phase_cost", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        D, "detect_background_orphan", lambda *_args, **_kwargs: None
    )
    rc = D._run_transactional_headless_leaf(
        backend="claude",
        prompt="inventory prompt",
        phase=phase,
        config=config,
        scratchpad=tmp_path,
        attempt=1,
        label="scope-drift",
        expected_outputs=["findings_inventory.md"],
        timeout=30,
        effective_model=launch.model,
        contract=contract,
        launch=launch,
        working_directory=str(tmp_path),
        analysis_directories=[str(tmp_path)],
    )
    assert rc == D.EXIT_ERROR
    assert calls == 2
    assert not (tmp_path / ".worker_transactions").exists()


def test_run_phase_routes_claude_headless_alias_through_claude_transaction(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    phase, config, contract, launch = _armed_inventory_model(
        tmp_path, backend="claude"
    )
    config["cli_backend"] = "claude-headless"
    prompt_file = tmp_path / "pipeline.md"
    prompt_file.write_text("## Inventory\n", encoding="utf-8")
    observed = {}

    monkeypatch.setattr(D, "resolve_v1_prompt", lambda _pipeline: prompt_file)
    monkeypatch.setattr(
        D, "build_phase_prompt", lambda *_args: "inventory prompt"
    )
    monkeypatch.setattr(D, "phase_model", lambda *_args: launch.model)
    monkeypatch.setattr(
        D,
        "_typed_model_phase_contract_and_launch",
        lambda *_args: (contract, launch),
    )
    monkeypatch.setattr(
        D.subprocess,
        "Popen",
        lambda *_args, **_kwargs: pytest.fail(
            "claude-headless alias reached raw Popen"
        ),
    )

    def capture(**kwargs):
        observed.update(kwargs)
        return 0

    monkeypatch.setattr(D, "_run_transactional_headless_leaf", capture)

    assert D.run_phase(phase, config, attempt=1) == 0
    assert observed["backend"] == "claude"
    assert observed["contract"] is contract
    assert observed["launch"] is launch


def test_sc_thorough_headless_phase_walk_has_no_unclassified_phase() -> None:
    """Every active SC Thorough phase has one explicit governed disposition."""

    active = [
        phase.name
        for phase in D.SC_PHASES
        if phase.modes is None or "thorough" in phase.modes
    ]
    routes = {
        name: D._sc_thorough_headless_phase_route(name)
        for name in active
    }
    assert all(routes.values()), {
        name: route for name, route in routes.items() if route is None
    }
    assert routes["recon"] == "DRIVER_FANOUT"
    assert routes["depth"] == "DRIVER_FANOUT"
    assert routes["inventory"] == "TYPED_MODEL_TRANSACTION"
    assert routes["sc_verify_crithigh"] == (
        "DYNAMIC_VERIFIER_TRANSACTION_OR_DEBT"
    )
    assert routes["report_assemble"] == "DRIVER_ONLY"
    assert D._sc_thorough_headless_phase_route("future_unregistered_phase") is None


@pytest.mark.parametrize(
    ("phase_name", "predicate_name", "runner_name"),
    (
        ("recon", "_should_use_recon_worker_pool", "_run_recon_backend_fanout"),
        ("breadth", "_should_use_breadth_worker_pool", "_run_breadth_backend_fanout"),
        ("rescan", "_should_use_rescan_worker_pool", "_run_rescan_backend_fanout"),
    ),
)
def test_claude_headless_driver_fanout_precedes_pty_denial(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    phase_name: str,
    predicate_name: str,
    runner_name: str,
) -> None:
    phase = D.Phase(
        name=phase_name,
        section_markers=["## Fixture"],
        expected_artifacts=["fixture_*.md"],
        base_timeout_s=30,
        model="sonnet",
        min_artifact_bytes=1,
    )
    config = _config(tmp_path, "claude")
    config["scratchpad"] = str(tmp_path)
    config["claude_exec_mode"] = "headless"
    prompt_file = tmp_path / "pipeline.md"
    prompt_file.write_text("## Fixture\n", encoding="utf-8")
    observed: dict = {}

    monkeypatch.setattr(D, "resolve_v1_prompt", lambda _pipeline: prompt_file)
    monkeypatch.setattr(D, "build_phase_prompt", lambda *_args: "fixture prompt")
    monkeypatch.setattr(D, "phase_model", lambda *_args: "fixture-model")
    monkeypatch.setattr(
        D,
        "_live_phase_runtime_launch_policy",
        lambda *_args: {
            "backend": "claude",
            "claude_exec_mode": "headless",
            "timeout_s": 30,
            "hypothesis_count": 0,
            "model": "fixture-model",
            "exec_mode": "headless",
        },
    )
    monkeypatch.setattr(
        D, "_typed_model_phase_contract_and_launch", lambda *_args: (None, None)
    )
    for name in (
        "_should_use_recon_worker_pool",
        "_should_use_breadth_worker_pool",
        "_should_use_rescan_worker_pool",
    ):
        monkeypatch.setattr(D, name, lambda *_args: False)
    monkeypatch.setattr(D, predicate_name, lambda *_args: True)
    if phase_name == "recon":
        owner = "sc/thorough/evm/claude/recon/prepass"
        config["_recon_prepass_dispatch_owner_key"] = owner
        monkeypatch.setattr(
            RP,
            "assert_recon_prepass_dispatch_authority",
            lambda _config: owner,
        )
        monkeypatch.setattr(
            D,
            "_recon_direct_retry_durable_state",
            lambda *_args: ("ABSENT", None, ""),
        )

    def capture(**kwargs):
        observed.update(kwargs)
        return 0

    monkeypatch.setattr(D, runner_name, capture)
    monkeypatch.setattr(
        D.subprocess,
        "Popen",
        lambda *_args, **_kwargs: pytest.fail("headless fanout reached raw Popen"),
    )

    assert D.run_phase(phase, config, attempt=1) == 0
    assert observed["backend"] == "claude-headless"
    assert observed["phase"] is phase


def test_unregistered_sc_thorough_headless_phase_fails_before_spawn(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    phase = D.Phase(
        name="future_unregistered_phase",
        section_markers=["## Fixture"],
        expected_artifacts=["future.md"],
        base_timeout_s=30,
        model="sonnet",
    )
    config = _config(tmp_path, "claude-headless")
    config["scratchpad"] = str(tmp_path)
    prompt_file = tmp_path / "pipeline.md"
    prompt_file.write_text("## Fixture\n", encoding="utf-8")
    monkeypatch.setattr(D, "resolve_v1_prompt", lambda _pipeline: prompt_file)
    monkeypatch.setattr(D, "build_phase_prompt", lambda *_args: "fixture prompt")
    monkeypatch.setattr(D, "phase_model", lambda *_args: "fixture-model")
    monkeypatch.setattr(
        D.subprocess,
        "Popen",
        lambda *_args, **_kwargs: pytest.fail("unregistered route spawned"),
    )
    assert D.run_phase(phase, config, attempt=1) == D.EXIT_ERROR


def test_unknown_backend_identity_fails_closed_before_spawn(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    phase = D.Phase(
        name="instantiate",
        section_markers=["## Instantiate"],
        expected_artifacts=["spawn_manifest.md"],
        base_timeout_s=30,
        model="sonnet",
        min_artifact_bytes=1,
    )
    config = _config(tmp_path, "cluade")
    config["scratchpad"] = str(tmp_path)
    prompt_file = tmp_path / "pipeline.md"
    prompt_file.write_text("## Instantiate\n", encoding="utf-8")

    monkeypatch.setattr(D, "resolve_v1_prompt", lambda _pipeline: prompt_file)
    monkeypatch.setattr(
        D, "build_phase_prompt", lambda *_args: "instantiate prompt"
    )
    monkeypatch.setattr(
        D.subprocess,
        "Popen",
        lambda *_args, **_kwargs: pytest.fail(
            "unknown backend reached raw Popen"
        ),
    )
    monkeypatch.setattr(
        D,
        "_run_transactional_headless_leaf",
        lambda **_kwargs: pytest.fail(
            "unknown backend reached transactional execution"
        ),
    )

    assert D.run_phase(phase, config, attempt=1) == D.EXIT_ERROR


def test_raw_claude_headless_launch_inventory_is_empty() -> None:
    breadth_source = inspect.getsource(
        D._run_one_claude_headless_breadth_worker
    )
    run_phase_source = inspect.getsource(D.run_phase)

    for source in (breadth_source, run_phase_source):
        assert '"--output-format", "json"' not in source
        assert "subprocess.Popen(" not in source
