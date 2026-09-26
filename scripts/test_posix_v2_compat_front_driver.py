"""Focused admission/routing tests for the explicit POSIX V2 compatibility path."""
from __future__ import annotations

import importlib.util
import hashlib
import json
import os
from pathlib import Path
import sys
import types
import uuid

import pytest

import plamen_driver as D
import posix_v2_compat_claude as compat_claude
import posix_v2_compat_runtime as real_compat
import security_obligation_authority as A


ROOT = Path(__file__).resolve().parents[1]
pytestmark = pytest.mark.skipif(os.name == "nt", reason="POSIX-only route")


def _load_front():
    spec = importlib.util.spec_from_file_location(
        "plamen_posix_v2_compat_front_test", ROOT / "plamen.py"
    )
    module = importlib.util.module_from_spec(spec)
    saved = sys.argv
    sys.argv = ["plamen.py"]
    try:
        spec.loader.exec_module(module)
    finally:
        sys.argv = saved
    return module


def test_temp_installed_front_without_provenance_cannot_claim_compatibility(
    tmp_path, monkeypatch,
):
    home = tmp_path / "home"
    installed = home / ".plamen"
    installed.mkdir(parents=True)
    copied_front = installed / "plamen.py"
    copied_front.write_bytes((ROOT / "plamen.py").read_bytes())
    monkeypatch.setenv("HOME", str(home))
    spec = importlib.util.spec_from_file_location(
        "plamen_temp_installed_posix_compat", copied_front
    )
    module = importlib.util.module_from_spec(spec)
    saved = sys.argv
    sys.argv = [
        str(copied_front),
        "start-config",
        "/project/.scratchpad/config.json",
        "--posix-compat-v2",
    ]
    try:
        with pytest.raises(SystemExit) as stopped:
            spec.loader.exec_module(module)
    finally:
        sys.argv = saved
    assert stopped.value.code == 75


def test_driver_installed_receipt_gates_bypass_only_exact_compat_abi(
    monkeypatch,
):
    exact = [
        "plamen_driver.py",
        "--startup-intent",
        "START_NEW_RUN",
        "--startup-decision-receipt",
        "/tmp/startup-decision.json",
        "/project/.scratchpad/config.json",
        "--posix-compat-v2",
    ]
    monkeypatch.setattr(D.sys, "argv", exact)
    monkeypatch.setattr(
        D,
        "_installed_package_runtime_root",
        lambda: pytest.fail("legacy installed receipt gate was reached"),
    )
    D._admit_installed_driver_before_local_imports()
    D._pin_installed_runtime_scripts_path()
    assert D._early_exact_posix_v2_compat_driver_argv(exact[1:])
    assert not D._early_exact_posix_v2_compat_driver_argv(
        exact[1:-1]
    )


@pytest.mark.parametrize("command", ["start-config", "resume"])
def test_public_front_accepts_only_exact_final_compat_flag(monkeypatch, command):
    front = _load_front()
    calls = []
    monkeypatch.setattr(front, "show_banner", lambda: None)
    monkeypatch.setattr(
        front, "_enforce_public_claude_projection_preflight", lambda: None
    )
    monkeypatch.setattr(front.os.path, "isfile", lambda _path: True)
    target = (
        "start_config_v2" if command == "start-config" else "resume_v2"
    )
    monkeypatch.setattr(
        front,
        target,
        lambda path, *, posix_compat_v2=False: calls.append(
            (path, posix_compat_v2)
        ),
    )
    monkeypatch.setattr(
        front.sys,
        "argv",
        ["plamen.py", command, "/run/config.json", "--posix-compat-v2"],
    )

    front.main()

    assert calls == [("/run/config.json", True)]


def test_admitted_compat_new_run_propagates_exact_driver_abi_without_provider(
    tmp_path, monkeypatch,
):
    front = _load_front()
    target = tmp_path / "project"
    target.mkdir()
    calls = []
    monkeypatch.setattr(front, "_posix_v2_compat_install_active", lambda: True)
    monkeypatch.setattr(front.console, "print", lambda *_a, **_k: None)
    monkeypatch.setattr(
        front,
        "_launch_v2_bound_config_value",
        lambda *_a, **_k: {
            "project_root": str(target),
            "scratchpad": str(target / ".scratchpad"),
            "pipeline": "sc",
            "mode": "core",
            "language": "evm",
            "cli_backend": "codex",
            "claude_exec_mode": "",
            "allow_model_fallback": False,
        },
    )
    monkeypatch.setattr(
        front,
        "_resume_startup_decision_destination",
        lambda *_a, **_k: target / ".scratchpad/startup-decision.json",
    )

    def run(argv, *, env):
        calls.append((list(argv), dict(env)))
        return types.SimpleNamespace(returncode=130)

    monkeypatch.setattr(front.subprocess, "run", run)
    monkeypatch.setattr(front, "_render_driver_result", lambda *a, **k: 130)

    with pytest.raises(SystemExit) as stopped:
        front.launch_v2(
            "sc", "core", str(target), "evm", cli_backend="codex",
            _transport_resolution=object(),
        )

    assert stopped.value.code == 130
    assert len(calls) == 1
    argv, environment = calls[0]
    assert argv[1].endswith("/scripts/plamen_driver.py")
    assert argv[2:] == [
        "--startup-intent",
        "START_NEW_RUN",
        "--startup-decision-receipt",
        str(target / ".scratchpad/startup-decision.json"),
        str(target / ".scratchpad/config.json"),
        "--posix-compat-v2",
    ]
    assert len(environment["PLAMEN_STARTUP_DECISION_MAC_KEY"]) == 64


def test_admitted_compat_existing_audit_resume_propagates_driver_flag(
    tmp_path, monkeypatch,
):
    front = _load_front()
    target = tmp_path / "project"
    scratchpad = target / ".scratchpad"
    scratchpad.mkdir(parents=True)
    config = scratchpad / "config.json"
    config.write_text(
        json.dumps({
            "project_root": str(target),
            "scratchpad": str(scratchpad),
            "pipeline": "sc",
            "mode": "core",
        }),
        encoding="utf-8",
    )
    calls = []
    monkeypatch.setattr(front, "_posix_v2_compat_install_active", lambda: True)
    monkeypatch.setattr(front.console, "print", lambda *_a, **_k: None)
    monkeypatch.setattr(
        front,
        "_resume_startup_decision_destination",
        lambda *_a, **_k: scratchpad / "startup-decision.json",
    )

    def run(argv, *, env):
        calls.append((list(argv), dict(env)))
        return types.SimpleNamespace(returncode=130)

    monkeypatch.setattr(front.subprocess, "run", run)
    monkeypatch.setattr(front, "_render_driver_result", lambda *a, **k: 130)

    with pytest.raises(SystemExit) as stopped:
        front.resume_v2(str(config))

    assert stopped.value.code == 130
    assert calls[0][0][-1] == "--posix-compat-v2"
    assert calls[0][0][2:4] == ["--startup-intent", "RESUME_EXISTING"]


@pytest.mark.parametrize(
    "argv",
    [
        ["plamen.py", "start-config", "--posix-compat-v2", "/run/config.json"],
        ["plamen.py", "resume", "--posix-compat-v2"],
        [
            "plamen.py",
            "resume",
            "/run/config.json",
            "--posix-compat-v2",
            "extra",
        ],
    ],
)
def test_public_front_rejects_nonexact_compat_argv(monkeypatch, argv):
    front = _load_front()
    monkeypatch.setattr(front, "show_banner", lambda: None)
    monkeypatch.setattr(
        front, "_enforce_public_claude_projection_preflight", lambda: None
    )
    monkeypatch.setattr(front.sys, "argv", argv)
    with pytest.raises(SystemExit):
        front.main()


def test_driver_startup_parser_tracks_process_only_flag():
    parsed = D._parse_startup_cli_args(
        [
            "--startup-intent",
            "START_NEW_RUN",
            "/run/config.json",
            "--posix-compat-v2",
        ]
    )
    assert parsed["posix_compat_v2"] is True
    assert parsed["config_path"] == Path("/run/config.json")
    with pytest.raises(ValueError, match="--posix-compat-v2"):
        D._parse_startup_cli_args(
            [
                "/run/config.json",
                "--posix-compat-v2",
                "--posix-compat-v2",
            ]
        )


def _private_auth_home(tmp_path: Path, monkeypatch) -> Path:
    home = tmp_path / "home"
    auth_root = home / ".codex"
    auth_root.mkdir(parents=True)
    auth_root.chmod(0o755)
    auth = auth_root / "auth.json"
    auth.write_text(json.dumps({"auth_mode": "chatgpt"}), encoding="utf-8")
    auth.chmod(0o600)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("CODEX_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    return auth


def test_compat_config_admits_uniform_backend_and_rejects_mixed_or_bad_version(
    tmp_path, monkeypatch,
):
    auth = _private_auth_home(tmp_path, monkeypatch)
    D._admit_posix_v2_compat_config({"cli_backend": "codex"})
    D._admit_posix_v2_compat_config(
        {
            "cli_backend": "codex",
            "phase_backend_overrides": {"skeptic": "CODEX"},
        }
    )
    auth_checks = []
    monkeypatch.setattr(D.shutil, "which", lambda name: f"/bin/{name}")
    monkeypatch.setattr(
        compat_claude,
        "check_claude_native_auth",
        lambda **kwargs: auth_checks.append(kwargs),
    )
    D._admit_posix_v2_compat_config({
        "cli_backend": "claude", "claude_exec_mode": "headless",
    })
    D._admit_posix_v2_compat_config({
        "cli_backend": "claude", "claude_exec_mode": "headless",
        "claude_cli_version": "2.1.263",
        "phase_backend_overrides": {"skeptic": "CLAUDE"},
    })
    assert [call["config_root"] for call in auth_checks] == [None, None]
    with pytest.raises(ValueError, match="mixed-backend"):
        D._admit_posix_v2_compat_config(
            {
                "cli_backend": "codex",
                "phase_backend_overrides": {"skeptic": "claude"},
            }
        )
    with pytest.raises(ValueError, match="headless"):
        D._admit_posix_v2_compat_config({
            "cli_backend": "claude", "claude_exec_mode": "pty",
        })
    with pytest.raises(ValueError, match="semantic version"):
        D._admit_posix_v2_compat_config({
            "cli_backend": "claude", "claude_exec_mode": "headless",
            "claude_cli_version": "latest",
        })
    auth.chmod(0o644)
    with pytest.raises(ValueError, match="safe private file"):
        D._admit_posix_v2_compat_config({"cli_backend": "codex"})


def test_claude_compat_leaf_threads_exact_staging_and_research_profile(
    tmp_path, monkeypatch,
):
    scratchpad = tmp_path / ".scratchpad"
    staging = scratchpad / ".worker_transactions" / "unit" / "output"
    staging.mkdir(parents=True)
    calls = []
    helper = types.ModuleType("posix_v2_compat_runtime")

    def run_claude_exec(**kwargs):
        calls.append(kwargs)
        return 0

    helper.run_claude_exec = run_claude_exec
    monkeypatch.setitem(sys.modules, "posix_v2_compat_runtime", helper)
    monkeypatch.setattr(
        D, "_POSIX_COMPAT_V2_PROCESS_MARKER", D._POSIX_COMPAT_V2_MARKER_TOKEN
    )
    session = object()
    monkeypatch.setattr(D, "_POSIX_COMPAT_V2_SESSION_AUTHORITY", session)
    monkeypatch.setattr(D, "_surface_exact_worker_log_to_phase_canonical", lambda **_k: None)
    monkeypatch.setattr(D, "_record_phase_cost", lambda *_a, **_k: None)
    monkeypatch.setattr(
        D.headless_phase_identity,
        "requires_standard_posix_model_incorporation",
        lambda **_k: False,
    )
    contract = types.SimpleNamespace(phase="recon", backend="claude", work_unit_id="dependency_research")
    launch = types.SimpleNamespace(backend="claude", model="claude-sonnet", timeout_s=17)
    phase = types.SimpleNamespace(name="recon", needs_mcp=False)
    boundary = {"manifest_digest": "a" * 64}

    rc = D._run_posix_v2_compat_claude_leaf(
        prompt="audit", phase=phase,
        config={"project_root": str(tmp_path), "_run_id": "run-1"},
        scratchpad=scratchpad, attempt=1, label="R-EXT",
        expected_outputs=("result.md",), contract=contract, launch=launch,
        session_authority=session,
        staged_output_validator=lambda _o, _c: (), staged_output_context={},
        staged_output_input_identities=(), phase_tool_boundary=boundary,
        output_staging_directory=staging,
        provider_event_profile="CLAUDE_LIVE_WEB_STREAM_V1",
    )

    assert rc == 0
    assert len(calls) == 1
    assert calls[0]["session_authority"] is session
    assert calls[0]["phase_tool_boundary"] is boundary
    assert calls[0]["output_staging_directory"] == staging
    assert calls[0]["provider_event_profile"] == "CLAUDE_LIVE_WEB_STREAM_V1"


def test_codex_exec_compat_dispatch_replays_phaseio_before_compat_runtime(
    tmp_path, monkeypatch,
):
    project = tmp_path / "project"
    scratchpad = project / ".scratchpad"
    scratchpad.mkdir(parents=True)
    session = object()
    contract = types.SimpleNamespace(
        phase="recon",
        backend="codex",
        work_unit_id="worker.r1",
        immutable_inputs=(),
        bounded_lookup_inputs=(),
    )
    launch = types.SimpleNamespace(timeout_s=17, model="gpt-5.6-sol")
    calls = []
    helper = types.ModuleType("posix_v2_compat_runtime")
    helper.COMPAT_EXIT_ERROR = 2
    helper.CODEX_LIVE_WEB_JSONL_PROFILE = (
        real_compat.CODEX_LIVE_WEB_JSONL_PROFILE
    )
    helper.CODEX_RESEARCH_ATTEMPT_COMPLETION_PLACEHOLDER = (
        real_compat.CODEX_RESEARCH_ATTEMPT_COMPLETION_PLACEHOLDER
    )

    def run_codex_exec(**kwargs):
        calls.append(kwargs)
        Path(kwargs["scratchpad"]).joinpath(
            f"_stdio_{kwargs['label']}.attempt{kwargs['attempt']}.log"
        ).write_text("compat provider completed\n", encoding="utf-8")
        return 0

    helper.run_codex_exec = run_codex_exec
    monkeypatch.setitem(sys.modules, "posix_v2_compat_runtime", helper)
    monkeypatch.setattr(
        D, "_POSIX_COMPAT_V2_PROCESS_MARKER", D._POSIX_COMPAT_V2_MARKER_TOKEN
    )
    monkeypatch.setattr(D, "_POSIX_COMPAT_V2_SESSION_AUTHORITY", session)
    monkeypatch.setattr(
        D,
        "_codex_auth_available",
        lambda: pytest.fail("native Codex auth gate was reached"),
    )
    monkeypatch.setattr(
        D,
        "_prepared_headless_transaction_authority",
        lambda **_kwargs: (contract, launch),
    )
    phase = types.SimpleNamespace(name="recon", needs_mcp=True)

    rc = D._run_one_codex_exec(
        prompt="audit",
        phase=phase,
        config={
            "_run_id": "a" * 32,
            "project_root": str(project),
            "scratchpad": str(scratchpad),
            "mode": "core",
            "pipeline": "sc",
            "cli_backend": "codex",
        },
        scratchpad=scratchpad,
        attempt=1,
        label="recon",
        expected_outputs=["recon.md"],
        timeout=10,
        effective_model="gpt-account-default",
    )

    assert rc == 0
    assert len(calls) == 1
    assert calls[0]["session_authority"] is session
    assert calls[0]["phase_name"] == "recon"
    assert calls[0]["expected_outputs"] == ("recon.md",)
    assert calls[0]["working_directory"] == scratchpad.resolve()
    assert calls[0]["writable_directories"] == (scratchpad.resolve(),)
    assert calls[0]["phase_io_contract"] is contract
    assert calls[0]["phase_io_launch"] is launch
    assert calls[0]["timeout"] == 17
    assert calls[0]["effective_model"] == "gpt-5.6-sol"
    assert (scratchpad / "_stdio_recon.log").read_text(encoding="utf-8") == (
        "compat provider completed\n"
    )


def test_isolated_chain_compat_uses_root_session_and_unique_receipt_label(
    tmp_path, monkeypatch,
):
    project = tmp_path / "project"
    root = project / ".scratchpad"
    shard = root / "_chain_tail_shards" / "shard_0007"
    shard.mkdir(parents=True)
    session = object()
    contract = types.SimpleNamespace(
        phase="chain_iter2",
        backend="codex",
        work_unit_id="tail_shard_model.0007",
        immutable_inputs=(),
        bounded_lookup_inputs=(),
    )
    launch = types.SimpleNamespace(timeout_s=19, model="gpt-5.6-sol")
    calls = []
    helper = types.ModuleType("posix_v2_compat_runtime")
    helper.CODEX_LIVE_WEB_JSONL_PROFILE = real_compat.CODEX_LIVE_WEB_JSONL_PROFILE
    helper.CODEX_RESEARCH_ATTEMPT_COMPLETION_PLACEHOLDER = (
        real_compat.CODEX_RESEARCH_ATTEMPT_COMPLETION_PLACEHOLDER
    )

    def run_codex_exec(**kwargs):
        calls.append(kwargs)
        Path(kwargs["scratchpad"]).joinpath(
            f"_stdio_{kwargs['label']}.attempt{kwargs['attempt']}.log"
        ).write_text("isolated provider completed\n", encoding="utf-8")
        return 0

    helper.run_codex_exec = run_codex_exec
    monkeypatch.setitem(sys.modules, "posix_v2_compat_runtime", helper)
    monkeypatch.setattr(
        D, "_POSIX_COMPAT_V2_PROCESS_MARKER", D._POSIX_COMPAT_V2_MARKER_TOKEN
    )
    monkeypatch.setattr(D, "_POSIX_COMPAT_V2_SESSION_AUTHORITY", session)
    monkeypatch.setattr(
        D,
        "_prepared_headless_transaction_authority",
        lambda **_kwargs: (contract, launch),
    )
    monkeypatch.setattr(
        D,
        "_headless_phase_io_authority_scratchpad",
        lambda **_kwargs: root.resolve(),
    )
    monkeypatch.setattr(
        D.headless_phase_identity,
        "requires_standard_posix_model_incorporation",
        lambda **_kwargs: False,
    )
    phase = types.SimpleNamespace(name="chain_iter2", needs_mcp=False)
    config = {
        "_run_id": "b" * 32,
        "project_root": str(project),
        "scratchpad": str(shard),
        "mode": "thorough",
        "pipeline": "sc",
        "cli_backend": "codex",
        "_chain_tail_inner_launch": True,
        "_chain_tail_authority_scratchpad": str(root),
        "_chain_tail_active_isolated": {"shard_index": 7},
    }

    rc = D._run_one_codex_exec(
        prompt="audit",
        phase=phase,
        config=config,
        scratchpad=shard,
        attempt=1,
        label="chain_iter2",
        expected_outputs=[
            "_chain_tail_shards/shard_0007/chain_iteration2.md"
        ],
        timeout=10,
        effective_model="gpt-account-default",
    )

    assert rc == 0
    assert len(calls) == 1
    assert calls[0]["session_authority"] is session
    assert calls[0]["scratchpad"] == root.resolve()
    assert calls[0]["working_directory"] == root.resolve()
    assert calls[0]["writable_directories"] == (root.resolve(),)
    assert calls[0]["label"] == "chain_iter2_shard_0007"
    assert calls[0]["expected_outputs"] == (
        "_chain_tail_shards/shard_0007/chain_iteration2.md",
    )
    assert (shard / "_stdio_chain_iter2.attempt1.log").is_file()


@pytest.mark.parametrize(
    (
        "work_unit_id", "contract_phase", "phase_name", "label", "output",
        "expects_preimage",
    ),
    (
        (
            "evidence_repair.model",
            "report_body",
            "report_body_writer_critical_high",
            "report_evidence_repair",
            "report_evidence_repair_response.json",
            False,
        ),
        (
            "model.report_low_info",
            "report_body",
            "report_body_writer_low_info",
            "report_body_writer_low_info",
            "report_low_info.md",
            True,
        ),
        (
            "model",
            "report_dedup_agent",
            "report_dedup_agent",
            "report_dedup_agent",
            "report_dedup_agent_decisions.md",
            False,
        ),
        (
            "model",
            "report_disposition",
            "report_disposition",
            "report_disposition",
            "disposition.md",
            False,
        ),
    ),
)
def test_report_model_compat_incorporates_only_preimage_eligible_outputs(
    tmp_path, monkeypatch, work_unit_id, contract_phase, phase_name, label,
    output, expects_preimage,
):
    project = tmp_path / "project"
    scratchpad = project / ".scratchpad"
    scratchpad.mkdir(parents=True)
    session = object()
    contract = types.SimpleNamespace(
        phase=contract_phase,
        backend="codex",
        work_unit_id=work_unit_id,
        immutable_inputs=(),
        bounded_lookup_inputs=(),
    )
    launch = types.SimpleNamespace(timeout_s=17, model="gpt-5.6-sol")
    helper = types.ModuleType("posix_v2_compat_runtime")
    helper.COMPAT_EXIT_ERROR = 2
    helper.CODEX_LIVE_WEB_JSONL_PROFILE = (
        real_compat.CODEX_LIVE_WEB_JSONL_PROFILE
    )
    helper.CODEX_RESEARCH_ATTEMPT_COMPLETION_PLACEHOLDER = (
        real_compat.CODEX_RESEARCH_ATTEMPT_COMPLETION_PLACEHOLDER
    )

    def run_codex_exec(**kwargs):
        assert kwargs["phase_name"] == contract.phase
        Path(kwargs["scratchpad"], output).write_bytes(b"exact model output\n")
        Path(kwargs["scratchpad"]).joinpath(
            f"_stdio_{kwargs['label']}.attempt{kwargs['attempt']}.log"
        ).write_text("compat provider completed\n", encoding="utf-8")
        return 0

    helper.run_codex_exec = run_codex_exec
    monkeypatch.setitem(sys.modules, "posix_v2_compat_runtime", helper)
    monkeypatch.setattr(
        D, "_POSIX_COMPAT_V2_PROCESS_MARKER", D._POSIX_COMPAT_V2_MARKER_TOKEN
    )
    monkeypatch.setattr(D, "_POSIX_COMPAT_V2_SESSION_AUTHORITY", session)
    monkeypatch.setattr(
        D, "_prepared_headless_transaction_authority",
        lambda **_kwargs: (contract, launch),
    )
    monkeypatch.setattr(
        D, "_security_obligation_source_snapshot_digest", lambda _config: "d" * 64,
    )
    receipt_path = scratchpad / "compat-receipt.json"
    receipt_path.write_bytes(b"{}\n")
    replay = types.ModuleType("verifier_model_execution_authority")
    replay.replay_posix_v2_compat_dynamic_verifier_receipt = (
        lambda **_kwargs: ({}, receipt_path, [])
    )
    monkeypatch.setitem(sys.modules, "verifier_model_execution_authority", replay)
    incorporated = []
    incorporation = types.ModuleType("posix_compat_model_incorporation")
    incorporation.commit_validated_posix_compat_model_execution = (
        lambda **kwargs: incorporated.append(kwargs) or []
    )
    monkeypatch.setitem(sys.modules, "posix_compat_model_incorporation", incorporation)
    import report_model_preimages
    captured = []
    monkeypatch.setattr(
        report_model_preimages,
        "capture_report_model_preimages",
        lambda *args, **kwargs: captured.append((args, kwargs)),
    )

    rc = D._run_one_codex_exec(
        prompt="exact report model prompt",
        phase=types.SimpleNamespace(
            name=phase_name, needs_mcp=False,
        ),
        config={
            "_run_id": "a" * 32,
            "project_root": str(project),
            "scratchpad": str(scratchpad),
            "mode": "thorough",
            "pipeline": "sc",
            "cli_backend": "codex",
        },
        scratchpad=scratchpad,
        attempt=1,
        label=label,
        expected_outputs=[output],
        timeout=17,
        effective_model="gpt-5.6-sol",
    )

    assert rc == 0
    assert len(incorporated) == 1
    assert incorporated[0]["contract"] is contract
    assert incorporated[0]["label"] == label
    assert incorporated[0]["outputs"] == [
        {
            "canonical_identity": f"scratchpad:{output}",
            "sha256": hashlib.sha256(b"exact model output\n").hexdigest(),
            "size": len(b"exact model output\n"),
        }
    ]
    assert bool(captured) is expects_preimage


@pytest.mark.parametrize("workspace_status", ["READY", "UNSCORED"])
def test_codex_exec_compat_normalizes_nested_fuzz_cwd_to_scratchpad(
    tmp_path, monkeypatch, workspace_status,
):
    project = tmp_path / "project"
    scratchpad = project / ".scratchpad"
    scratchpad.mkdir(parents=True)
    job = {
        "agent_id": f"fuzz-{workspace_status.lower()}",
        "category": "fuzz",
        "output": f"fuzz_{workspace_status.lower()}.md",
        "fuzz_workspace_status": workspace_status,
    }
    if workspace_status == "READY":
        workspace = scratchpad / "_fuzz_workspaces" / "fuzz-ready"
        active = workspace / "active"
        active.mkdir(parents=True)
        job.update({
            "fuzz_workspace_root": str(workspace),
            "fuzz_active_root": str(active),
            "fuzz_authority_digest": "b" * 64,
        })
        monkeypatch.setattr(
            D.fuzz_workspace_authority,
            "resolve_fuzz_workspace_index_row",
            lambda *_args, **_kwargs: {
                "status": "READY",
                "authority_digest": "b" * 64,
            },
        )

    nested_fuzz_cwd = Path(D._depth_worker_launch_cwd(
        job=job,
        scratchpad=scratchpad,
        project_root=str(project),
    )).resolve()
    assert nested_fuzz_cwd != scratchpad.resolve()
    nested_fuzz_cwd.relative_to(scratchpad.resolve())

    calls = []
    helper = types.ModuleType("posix_v2_compat_runtime")
    helper.COMPAT_EXIT_ERROR = 2
    helper.CODEX_LIVE_WEB_JSONL_PROFILE = (
        real_compat.CODEX_LIVE_WEB_JSONL_PROFILE
    )
    helper.CODEX_RESEARCH_ATTEMPT_COMPLETION_PLACEHOLDER = (
        real_compat.CODEX_RESEARCH_ATTEMPT_COMPLETION_PLACEHOLDER
    )

    def run_codex_exec(**kwargs):
        calls.append(kwargs)
        Path(kwargs["scratchpad"]).joinpath(
            f"_stdio_{kwargs['label']}.attempt{kwargs['attempt']}.log"
        ).write_text("compat fuzz provider completed\n", encoding="utf-8")
        return 0

    helper.run_codex_exec = run_codex_exec
    monkeypatch.setitem(sys.modules, "posix_v2_compat_runtime", helper)
    monkeypatch.setattr(
        D, "_POSIX_COMPAT_V2_PROCESS_MARKER", D._POSIX_COMPAT_V2_MARKER_TOKEN
    )
    monkeypatch.setattr(D, "_POSIX_COMPAT_V2_SESSION_AUTHORITY", object())
    monkeypatch.setattr(
        D,
        "_prepared_headless_transaction_authority",
        lambda **_kwargs: (
            types.SimpleNamespace(
                phase="depth",
                backend="codex",
                work_unit_id="worker.fuzz",
                immutable_inputs=(),
                bounded_lookup_inputs=(),
            ),
            types.SimpleNamespace(timeout_s=10, model="gpt-5.6-sol"),
        ),
    )

    rc = D._run_one_codex_exec(
        prompt="run fuzz worker",
        phase=types.SimpleNamespace(name="depth", needs_mcp=False),
        config={
            "_run_id": "a" * 32,
            "project_root": str(project),
            "scratchpad": str(scratchpad),
            "mode": "thorough",
            "pipeline": "sc",
            "cli_backend": "codex",
        },
        scratchpad=scratchpad,
        attempt=1,
        label=f"depth_worker_fuzz_{workspace_status.lower()}",
        expected_outputs=[str(job["output"])],
        timeout=10,
        effective_model="gpt-5.6-sol",
        working_directory=str(nested_fuzz_cwd),
        writable_directories=(str(nested_fuzz_cwd),),
        agent_id=str(job["agent_id"]),
    )

    assert rc == 0
    assert len(calls) == 1
    assert calls[0]["working_directory"] == scratchpad.resolve()
    assert calls[0]["writable_directories"] == (
        scratchpad.resolve(),
        nested_fuzz_cwd,
    )


def test_depth_headless_batch_keeps_additive_fuzz_exit_error_nonterminal(
    tmp_path, monkeypatch,
):
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    run_binding = {
        "run_id": "12345678-1234-4123-8123-123456789abc",
        "source_snapshot_digest": "a" * 64,
        "source_scope_digest": "b" * 64,
        "ecosystem": "evm",
        "mode": "thorough",
        "pipeline": "sc",
    }
    run_binding["binding_digest"] = A._sha256_value(run_binding)
    obligations = []
    authority = {
        "schema_version": A.OBLIGATION_SCHEMA,
        "stage": A.PRE_DEPTH_STAGE,
        "run_binding": run_binding,
        "authority_universe_digest": A._universe_digest(obligations),
        "obligation_count": 0,
        "obligations": obligations,
    }
    authority["authority_digest"] = A._payload_digest(authority)
    (scratchpad / "security_obligation_authority.json").write_text(
        json.dumps(authority, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    jobs = [
        {
            "agent_id": "invariant-fuzz",
            "category": "fuzz",
            "output": "invariant_fuzz_results.md",
        },
        {
            "agent_id": "depth-state-trace",
            "category": "depth",
            "output": "depth_state_trace_findings.md",
        },
    ]
    invoked = []
    monkeypatch.setattr(
        D,
        "_depth_dispatch_plan",
        lambda **kwargs: [
            {"job": dict(job), "prompt": f"run {job['agent_id']}"}
            for job in kwargs["jobs"]
        ],
    )
    monkeypatch.setattr(D, "_write_depth_dispatch_contract", lambda *_a, **_k: None)
    monkeypatch.setattr(
        D, "_quarantine_incomplete_depth_retry_output", lambda *_a, **_k: None
    )
    monkeypatch.setattr(
        D, "_invalidate_derived_step_trace_for_job", lambda *_a, **_k: None
    )
    monkeypatch.setattr(
        D, "_prepare_typed_model_worker_launch", lambda **_kwargs: []
    )
    monkeypatch.setattr(
        D,
        "_depth_worker_launch_cwd",
        lambda **_kwargs: str(scratchpad),
    )

    def run_one(**kwargs):
        invoked.append(kwargs["agent_id"])
        return (
            D.EXIT_ERROR
            if kwargs["agent_id"] == "invariant-fuzz"
            else 0
        )

    monkeypatch.setattr(D, "_run_one_codex_exec", run_one)

    outcomes, terminal = D._run_depth_headless_batch(
        backend="codex",
        phase=types.SimpleNamespace(name="depth"),
        config={"project_root": str(tmp_path)},
        scratchpad=scratchpad,
        jobs=jobs,
        all_jobs=jobs,
        attempt=1,
        timeout=10,
        effective_model="gpt-5.6-sol",
        retry_reasons_by_output={},
    )

    assert terminal is None
    assert set(invoked) == {"invariant-fuzz", "depth-state-trace"}
    assert outcomes["invariant_fuzz_results.md"].rc == D.EXIT_ERROR
    assert outcomes["depth_state_trace_findings.md"].rc == 0


@pytest.mark.parametrize(
    ("category", "rc"),
    [("fuzz", -4), ("fuzz", -3), ("depth", D.EXIT_ERROR)],
)
def test_headless_wave_keeps_containment_interruption_and_nonfuzz_terminal(
    category, rc,
):
    row = {"output": "worker.md", "job": {"category": category}}
    results, terminal = D._run_bounded_headless_provider_wave(
        rows=[row],
        row_key=lambda item: str(item["output"]),
        invoke=lambda _item: rc,
        concurrency=1,
        thread_name_prefix="test-depth-fuzz-terminal-policy",
        exit_error_is_nonterminal=lambda item: (
            D._depth_fuzz_exit_error_is_nonterminal(item["job"])
        ),
    )

    assert results == {"worker.md": rc}
    assert terminal == rc


def test_reduced_isolation_evidence_is_durable_runtime_debt(
    tmp_path, monkeypatch,
):
    checkpoint = D.Checkpoint(run_id=str(uuid.uuid4()))
    monkeypatch.setattr(
        D, "_POSIX_COMPAT_V2_PROCESS_MARKER", D._POSIX_COMPAT_V2_MARKER_TOKEN
    )

    digest = D._record_posix_v2_compat_runtime_debt(tmp_path, checkpoint)

    receipt = tmp_path / D._POSIX_COMPAT_V2_RUNTIME_DEBT_PATH
    payload = json.loads(receipt.read_text(encoding="utf-8"))
    assert payload["security_properties"]["native_guest_isolation"] is False
    assert checkpoint.runtime_debts[D._POSIX_COMPAT_V2_RUNTIME_DEBT_ID] == digest
    assert D._pipeline_terminal_exit_code(checkpoint) == D.EXIT_DEGRADED
