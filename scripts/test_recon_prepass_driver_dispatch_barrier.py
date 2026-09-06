from __future__ import annotations

import json
import sys
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest


SCRIPTS = Path(__file__).resolve().parent
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import plamen_driver as D  # noqa: E402
import recon_prepass as RP  # noqa: E402


BASE_OWNER = "sc/core/evm/claude/recon/prepass"
SUCCESSOR_OWNER = "sc/core/evm/claude/recon/prepass.attempt-0002"


def _config(tmp_path: Path) -> tuple[Path, dict]:
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    config = {
        "pipeline": "sc",
        "mode": "core",
        "language": "evm",
        "cli_backend": "claude",
        "project_root": str(tmp_path),
        "scratchpad": str(scratchpad),
        "_run_id": "driver-prepass-barrier",
    }
    return scratchpad, config


def _live_prepass_workspace(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    language: str = "evm",
) -> tuple[Path, Path, Path, dict]:
    project = tmp_path / "project"
    source = project / "src"
    scratchpad = project / ".scratchpad"
    source.mkdir(parents=True)
    scratchpad.mkdir()
    (source / "Protocol.sol").write_text(
        "pragma solidity ^0.8.20; contract Protocol {}\n",
        encoding="utf-8",
    )
    config = {
        "pipeline": "sc",
        "mode": "core",
        "language": language,
        "cli_backend": "claude",
        "project_root": str(project),
        "scratchpad": str(scratchpad),
        "run_id": "driver-live-verifier",
        "_run_id": "driver-live-verifier",
        "prepass_external_scanners": False,
    }
    monkeypatch.setattr(
        RP.shutil, "which", lambda _name, *args, **kwargs: None
    )
    monkeypatch.setattr(RP, "gate_supply_chain", lambda _root: None)
    monkeypatch.setattr(
        RP,
        "run_owned_process",
        lambda *_args, **_kwargs: SimpleNamespace(
            returncode=127, stdout="", stderr="unavailable"
        ),
    )
    return project, source, scratchpad, config


def _dispatch_after_both_barriers(
    config: dict,
    scratchpad: Path,
    *,
    run_prepass,
    verifier,
    dispatch,
) -> None:
    D._run_recon_prepass_dispatch_barrier(
        config,
        scratchpad,
        run_prepass=run_prepass,
        assert_dispatch_authority=verifier,
    )
    D._enforce_recon_model_prelaunch_barrier(
        config,
        scratchpad,
        assert_dispatch_authority=verifier,
    )
    dispatch()


@pytest.mark.parametrize(
    ("failure_site", "error"),
    (
        ("path", OSError("source path identity changed")),
        ("authority", ValueError("capture authority mismatch")),
        ("orphan", RuntimeError("prepass owner is orphaned")),
    ),
)
def test_escaped_prepass_failures_veto_dispatch_without_checkpoint_advance(
    tmp_path: Path,
    failure_site: str,
    error: Exception,
) -> None:
    scratchpad, config = _config(tmp_path)
    checkpoint = scratchpad / "_v2_checkpoint.json"
    checkpoint.write_text(
        json.dumps({"completed": [], "degraded": []}, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    checkpoint_before = checkpoint.read_bytes()
    dispatches: list[str] = []

    def run_prepass(_config):
        if failure_site == "path":
            raise error
        return {"state": "rendered"}

    def verifier(_config):
        if failure_site != "path":
            raise error
        return BASE_OWNER

    with pytest.raises(D.ReconPrepassDispatchBlocked):
        _dispatch_after_both_barriers(
            config,
            scratchpad,
            run_prepass=run_prepass,
            verifier=verifier,
            dispatch=lambda: dispatches.append("model"),
        )

    assert dispatches == []
    assert checkpoint.read_bytes() == checkpoint_before
    assert json.loads(checkpoint.read_text(encoding="utf-8")) == {
        "completed": [],
        "degraded": [],
    }
    debt = (scratchpad / "recon.degraded").read_text(encoding="utf-8")
    assert debt.startswith("[RECON_PREPASS_DISPATCH_AUTHORITY]")
    assert type(error).__name__ in debt
    assert "_recon_prepass_dispatch_owner_key" not in config


def test_exact_committed_prepass_admits_one_model_dispatch(tmp_path: Path) -> None:
    scratchpad, config = _config(tmp_path)
    dispatches: list[str] = []
    calls = {"run": 0, "verify": 0}

    def run_prepass(_config):
        calls["run"] += 1
        return {"state": "committed"}

    def verifier(_config):
        calls["verify"] += 1
        return BASE_OWNER

    _dispatch_after_both_barriers(
        config,
        scratchpad,
        run_prepass=run_prepass,
        verifier=verifier,
        dispatch=lambda: dispatches.append("model"),
    )

    assert calls == {"run": 1, "verify": 2}
    assert dispatches == ["model"]
    assert config["_recon_prepass_dispatch_owner_key"] == BASE_OWNER
    assert not (scratchpad / "recon.degraded").exists()


@pytest.mark.parametrize(
    "config_update",
    (
        {"language": "solidity"},
        {"language": "ethereum"},
        {"language": " Solidity "},
        {
            "pipeline": " SC ",
            "mode": " CORE ",
            "language": " EVM ",
            "cli_backend": " CLAUDE ",
        },
    ),
)
def test_driver_uses_prepass_canonical_dimensions_for_owner_admission(
    tmp_path: Path,
    config_update: dict[str, str],
) -> None:
    scratchpad, config = _config(tmp_path)
    config.update(config_update)
    assert RP.recon_prepass_expected_owner_prefix(config) == (
        "sc/core/evm/claude/recon"
    )

    _status, owner = D._run_recon_prepass_dispatch_barrier(
        config,
        scratchpad,
        run_prepass=lambda _config: {"state": "committed"},
        assert_dispatch_authority=lambda _config: BASE_OWNER,
    )

    assert owner == BASE_OWNER
    assert config["_recon_prepass_dispatch_owner_key"] == BASE_OWNER


def test_canonical_dimension_mismatch_remains_blocked(tmp_path: Path) -> None:
    scratchpad, config = _config(tmp_path)

    with pytest.raises(
        D.ReconPrepassDispatchBlocked,
        match="invalid owner key",
    ):
        D._run_recon_prepass_dispatch_barrier(
            config,
            scratchpad,
            run_prepass=lambda _config: {"state": "committed"},
            assert_dispatch_authority=lambda _config: (
                "l1/core/evm/claude/recon/prepass"
            ),
        )


def test_recoverable_successor_repair_admits_once(tmp_path: Path) -> None:
    scratchpad, config = _config(tmp_path)
    state = {"owner": None, "run": 0, "verify": 0}
    dispatches: list[str] = []

    def repaired_prepass(_config):
        state["run"] += 1
        state["owner"] = SUCCESSOR_OWNER
        return {"state": "repaired"}

    def verifier(_config):
        state["verify"] += 1
        if state["owner"] is None:
            raise RuntimeError("successor is not committed")
        return state["owner"]

    _dispatch_after_both_barriers(
        config,
        scratchpad,
        run_prepass=repaired_prepass,
        verifier=verifier,
        dispatch=lambda: dispatches.append("model"),
    )

    assert state == {"owner": SUCCESSOR_OWNER, "run": 1, "verify": 2}
    assert dispatches == ["model"]


def test_prelaunch_recheck_blocks_owner_change_after_startup(tmp_path: Path) -> None:
    scratchpad, config = _config(tmp_path)
    dispatches: list[str] = []
    owners = iter((BASE_OWNER, SUCCESSOR_OWNER))

    with pytest.raises(
        D.ReconPrepassDispatchBlocked,
        match="owner changed after startup admission",
    ):
        _dispatch_after_both_barriers(
            config,
            scratchpad,
            run_prepass=lambda _config: {"state": "committed"},
            verifier=lambda _config: next(owners),
            dispatch=lambda: dispatches.append("model"),
        )

    assert dispatches == []
    debt = (scratchpad / "recon.degraded").read_text(encoding="utf-8")
    assert "owner changed after startup admission" in debt


def test_unregistered_seven_component_owner_is_never_admitted(
    tmp_path: Path,
) -> None:
    scratchpad, config = _config(tmp_path)
    dispatches: list[str] = []

    with pytest.raises(
        D.ReconPrepassDispatchBlocked,
        match="invalid owner key",
    ):
        _dispatch_after_both_barriers(
            config,
            scratchpad,
            run_prepass=lambda _config: {"state": "legacy"},
            verifier=lambda _config: BASE_OWNER + "/attempt-2",
            dispatch=lambda: dispatches.append("model"),
        )

    assert dispatches == []


def test_success_clears_only_superseded_barrier_debt(tmp_path: Path) -> None:
    scratchpad, config = _config(tmp_path)
    D._append_phase_io_debt(
        scratchpad,
        "recon",
        "RECON_PREPASS_DISPATCH_AUTHORITY",
        "old transient failure",
    )
    D._append_phase_io_debt(
        scratchpad,
        "recon",
        "UNRELATED_RECON_DEBT",
        "must remain",
    )

    D._run_recon_prepass_dispatch_barrier(
        config,
        scratchpad,
        run_prepass=lambda _config: {"state": "committed"},
        assert_dispatch_authority=lambda _config: BASE_OWNER,
    )

    debt = (scratchpad / "recon.degraded").read_text(encoding="utf-8")
    assert "RECON_PREPASS_DISPATCH_AUTHORITY" not in debt
    assert "[UNRELATED_RECON_DEBT] must remain" in debt


def test_run_phase_turns_prelaunch_veto_into_clean_resume_exit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scratchpad, config = _config(tmp_path)
    checkpoint = scratchpad / "_v2_checkpoint.json"
    checkpoint.write_text(
        '{"completed":[],"degraded":[]}\n', encoding="utf-8"
    )
    checkpoint_before = checkpoint.read_bytes()
    calls = {"phase_once": 0}

    monkeypatch.setattr(
        D,
        "_strict_claude_exec_mode",
        lambda *_args, **_kwargs: "headless",
    )
    monkeypatch.setattr(
        D,
        "_recon_direct_retry_durable_state",
        lambda *_args, **_kwargs: ("ABSENT", None, ""),
    )

    def veto(*_args, **_kwargs):
        calls["phase_once"] += 1
        raise D.ReconPrepassDispatchBlocked("typed prelaunch veto")

    monkeypatch.setattr(D, "_run_phase_once", veto)
    with pytest.raises(SystemExit) as stopped:
        D.run_phase(SimpleNamespace(name="recon"), config, attempt=1)

    assert stopped.value.code == D.EXIT_DEGRADED
    assert calls == {"phase_once": 1}
    assert checkpoint.read_bytes() == checkpoint_before


def test_durable_direct_retry_generation_dispatches_and_finalizes_once(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scratchpad, config = _config(tmp_path)
    bound = {
        "semantic_attempt": 2,
        "generation_digest": "a" * 64,
    }
    calls = {"phase": 0, "provider": 0, "finalize": 0}
    monkeypatch.setattr(
        D,
        "_strict_claude_exec_mode",
        lambda *_args, **_kwargs: "headless",
    )
    monkeypatch.setattr(
        D,
        "_recon_direct_retry_durable_state",
        lambda *_args, **_kwargs: ("ACTIVE", dict(bound), ""),
    )
    monkeypatch.setattr(
        D,
        "validate_recon_direct_retry_launch_authority",
        lambda *_args, **_kwargs: dict(bound),
    )

    def phase_once(_phase, live_config, _attempt):
        calls["phase"] += 1
        assert live_config[
            D._RECON_DIRECT_RETRY_DISPATCH_AUTHORITY_KEY
        ] == bound
        return D._call_recon_provider_with_dispatch_authority(
            live_config,
            scratchpad,
            lambda: calls.__setitem__(
                "provider", calls["provider"] + 1
            ) or 0,
        )

    def finalize(*_args, **_kwargs):
        calls["finalize"] += 1
        return []

    monkeypatch.setattr(D, "_run_phase_once", phase_once)
    monkeypatch.setattr(D, "_finalize_recon_direct_fallback", finalize)

    assert D.run_phase(SimpleNamespace(name="recon"), config, attempt=1) == 0
    assert calls == {"phase": 1, "provider": 1, "finalize": 1}
    assert D._RECON_DIRECT_RETRY_DISPATCH_AUTHORITY_KEY not in config


def test_direct_retry_authority_tamper_vetoes_provider(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scratchpad, config = _config(tmp_path)
    bound = {"semantic_attempt": 2, "generation_digest": "a" * 64}
    changed = {"semantic_attempt": 2, "generation_digest": "b" * 64}
    dispatches: list[str] = []
    monkeypatch.setattr(
        D,
        "validate_recon_direct_retry_launch_authority",
        lambda *_args, **_kwargs: changed,
    )

    with pytest.raises(
        D.ReconPrepassDispatchBlocked,
        match="direct-retry authority changed",
    ):
        D._call_recon_provider_with_dispatch_authority(
            config,
            scratchpad,
            lambda: dispatches.append("provider"),
            direct_retry_authority=bound,
        )

    assert dispatches == []


def test_live_prepass_verifier_interface_admits_exact_committed_owner(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _project, source, scratchpad, config = _live_prepass_workspace(
        tmp_path, monkeypatch, language="solidity"
    )

    _status, owner = D._run_recon_prepass_dispatch_barrier(
        config, scratchpad
    )

    assert owner == BASE_OWNER
    assert RP.assert_recon_prepass_dispatch_authority(config) == BASE_OWNER
    assert D._enforce_recon_model_prelaunch_barrier(
        config, scratchpad
    ) == BASE_OWNER
    (source / "Protocol.sol").write_text(
        "pragma solidity ^0.8.20; contract Mutated {}\n",
        encoding="utf-8",
    )
    with pytest.raises(
        D.ReconPrepassDispatchBlocked,
        match="current capture changed",
    ):
        D._enforce_recon_model_prelaunch_barrier(config, scratchpad)
    assert "current capture changed" in (
        scratchpad / "recon.degraded"
    ).read_text(encoding="utf-8")


def test_headless_fanout_mutation_after_prep_vetoes_provider_and_retry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _project, source, scratchpad, config = _live_prepass_workspace(
        tmp_path, monkeypatch
    )
    D._run_recon_prepass_dispatch_barrier(config, scratchpad)
    checkpoint = scratchpad / "_v2_checkpoint.json"
    checkpoint.write_text(
        '{"completed":[],"degraded":[]}\n', encoding="utf-8"
    )
    checkpoint_before = checkpoint.read_bytes()
    job = {
        "agent_id": "R1",
        "role": "recon",
        "output": "recon_r1.md",
        "focus": "contracts",
    }
    calls = {"prompt": 0, "provider": 0}
    monkeypatch.setattr(D, "_recon_worker_jobs", lambda _config: [job])
    monkeypatch.setattr(
        D,
        "_recon_worker_complete",
        lambda *_args, **_kwargs: (False, ["missing"]),
    )
    monkeypatch.setattr(
        D,
        "_prepare_typed_model_worker_launch",
        lambda **_kwargs: [],
    )
    monkeypatch.setattr(
        D,
        "_validate_typed_model_worker_inputs",
        lambda **_kwargs: [],
    )

    def mutate_after_prep(**_kwargs):
        calls["prompt"] += 1
        (source / "Protocol.sol").write_text(
            "pragma solidity ^0.8.20; contract LateMutation {}\n",
            encoding="utf-8",
        )
        return "recon prompt"

    def provider(**_kwargs):
        calls["provider"] += 1
        return 0

    monkeypatch.setattr(D, "_build_recon_worker_prompt", mutate_after_prep)
    monkeypatch.setattr(
        D, "_run_one_claude_headless_breadth_worker", provider
    )

    with pytest.raises(
        D.ReconPrepassDispatchBlocked,
        match="current capture changed",
    ):
        D._run_recon_backend_fanout(
            backend="claude-headless",
            phase=SimpleNamespace(name="recon"),
            config=config,
            scratchpad=scratchpad,
            attempt=1,
            timeout=30,
            effective_model="sonnet",
        )

    assert calls == {"prompt": 1, "provider": 0}
    assert checkpoint.read_bytes() == checkpoint_before


def test_pty_worker_mutation_after_prep_vetoes_session_spawn(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project, source, scratchpad, config = _live_prepass_workspace(
        tmp_path, monkeypatch
    )
    D._run_recon_prepass_dispatch_barrier(config, scratchpad)
    calls = {"prompt": 0, "spawn": 0, "terminate": 0}
    job = {
        "agent_id": "R1",
        "role": "recon",
        "output": "recon_r1.md",
        "focus": "contracts",
    }
    monkeypatch.setattr(
        D,
        "_prepare_typed_model_worker_launch",
        lambda **_kwargs: [],
    )
    monkeypatch.setattr(
        D,
        "_validate_typed_model_worker_inputs",
        lambda **_kwargs: [],
    )

    def mutate_after_prep(**_kwargs):
        calls["prompt"] += 1
        (source / "Protocol.sol").write_text(
            "pragma solidity ^0.8.20; contract PtyLateMutation {}\n",
            encoding="utf-8",
        )
        return "recon prompt"

    monkeypatch.setattr(D, "_build_recon_worker_prompt", mutate_after_prep)
    monkeypatch.setattr(
        D, "_build_fresh_session_cmd", lambda command, _session: command
    )
    monkeypatch.setattr(
        D, "_rewrite_argv_positional_prompt", lambda command, _prompt: command
    )

    class FakeSession:
        def __init__(self, *_args, **_kwargs):
            self.transcript_path = scratchpad / "absent-transcript.jsonl"

        def spawn(self):
            calls["spawn"] += 1

        def terminate(self, **_kwargs):
            calls["terminate"] += 1

    monkeypatch.setattr(D, "ClaudePtySession", FakeSession)

    with pytest.raises(
        D.ReconPrepassDispatchBlocked,
        match="current capture changed",
    ):
        D._run_single_recon_worker_pty(
            job=job,
            scratchpad=scratchpad,
            project_root=str(project),
            config=config,
            phase=SimpleNamespace(name="recon"),
            base_cmd=["claude"],
            env={},
            timeout=30,
            quiescence_s=0.01,
            attempt=1,
        )

    assert calls == {"prompt": 1, "spawn": 0, "terminate": 1}


def test_missing_only_respawn_rechecks_mutated_capture_before_spawn(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _project, source, scratchpad, config = _live_prepass_workspace(
        tmp_path, monkeypatch
    )
    D._run_recon_prepass_dispatch_barrier(config, scratchpad)
    calls = {"spawn": 0, "bootstrap": 0}
    (source / "Protocol.sol").write_text(
        "pragma solidity ^0.8.20; contract RespawnMutation {}\n",
        encoding="utf-8",
    )
    prompt = scratchpad / "prompt.md"
    prompt.write_text("prompt\n", encoding="utf-8")
    monkeypatch.setattr(
        D,
        "_build_missing_only_prompt",
        lambda *_args, **_kwargs: prompt,
    )
    monkeypatch.setattr(
        D, "_build_fresh_session_cmd", lambda command, _session: command
    )
    monkeypatch.setattr(
        D, "_rewrite_argv_positional_prompt", lambda command, _prompt: command
    )

    class FakeSession:
        def __init__(self, *_args, **_kwargs):
            pass

        def spawn(self):
            calls["spawn"] += 1

        def send_bootstrap(self):
            calls["bootstrap"] += 1

    monkeypatch.setattr(D, "ClaudePtySession", FakeSession)

    with pytest.raises(
        D.ReconPrepassDispatchBlocked,
        match="current capture changed",
    ):
        D._respawn_missing_only(
            phase=SimpleNamespace(name="recon"),
            scratchpad=scratchpad,
            row_statuses=[],
            base_cmd=["claude"],
            cwd=str(tmp_path),
            env={},
            log_file=None,
            prompt_path=prompt,
            provider_dispatch_authority=lambda: (
                D._enforce_recon_current_dispatch_authority(
                    config, scratchpad
                )
            ),
        )

    assert calls == {"spawn": 0, "bootstrap": 0}


def test_missing_only_direct_retry_respawn_uses_bound_generation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scratchpad, config = _config(tmp_path)
    bound = {"semantic_attempt": 2, "generation_digest": "a" * 64}
    calls = {"spawn": 0, "bootstrap": 0}
    prompt = scratchpad / "prompt.md"
    prompt.write_text("prompt\n", encoding="utf-8")
    monkeypatch.setattr(
        D,
        "validate_recon_direct_retry_launch_authority",
        lambda *_args, **_kwargs: dict(bound),
    )
    monkeypatch.setattr(
        D,
        "_build_missing_only_prompt",
        lambda *_args, **_kwargs: prompt,
    )
    monkeypatch.setattr(
        D, "_build_fresh_session_cmd", lambda command, _session: command
    )
    monkeypatch.setattr(
        D, "_rewrite_argv_positional_prompt", lambda command, _prompt: command
    )

    class FakeSession:
        def __init__(self, *_args, **_kwargs):
            pass

        def spawn(self):
            calls["spawn"] += 1

        def send_bootstrap(self):
            calls["bootstrap"] += 1

    monkeypatch.setattr(D, "ClaudePtySession", FakeSession)
    D._respawn_missing_only(
        phase=SimpleNamespace(name="recon"),
        scratchpad=scratchpad,
        row_statuses=[],
        base_cmd=["claude"],
        cwd=str(tmp_path),
        env={},
        log_file=None,
        prompt_path=prompt,
        provider_dispatch_authority=lambda: (
            D._enforce_recon_current_dispatch_authority(
                config,
                scratchpad,
                direct_retry_authority=bound,
            )
        ),
    )

    assert calls == {"spawn": 1, "bootstrap": 1}


def test_external_dependency_worker_replays_canonical_inputs_at_spawn(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scratchpad, config = _config(tmp_path)
    calls = {"validate": 0, "spawn": 0, "terminate": 0}
    job = {
        "agent_id": "R-EXT",
        "role": "external_dependency_research",
        "output": "recon_external_dependency_research.md",
        "focus": "dependencies",
    }
    monkeypatch.setattr(
        D,
        "_prepare_typed_model_worker_launch",
        lambda **_kwargs: [],
    )

    def validate(**_kwargs):
        calls["validate"] += 1
        return [] if calls["validate"] == 1 else ["late input digest mismatch"]

    monkeypatch.setattr(D, "_validate_typed_model_worker_inputs", validate)
    monkeypatch.setattr(
        D, "_typed_worker_input_issue_is_fatal", lambda *_args: False
    )
    monkeypatch.setattr(
        D, "_build_recon_worker_prompt", lambda **_kwargs: "prompt"
    )
    monkeypatch.setattr(
        D, "_build_fresh_session_cmd", lambda command, _session: command
    )
    monkeypatch.setattr(
        D, "_rewrite_argv_positional_prompt", lambda command, _prompt: command
    )
    monkeypatch.setattr(
        D, "_install_recon_command_guard", lambda _scratch, env: env
    )

    class FakeSession:
        def __init__(self, *_args, **_kwargs):
            self.transcript_path = scratchpad / "absent-transcript.jsonl"

        def spawn(self):
            calls["spawn"] += 1

        def terminate(self, **_kwargs):
            calls["terminate"] += 1

    monkeypatch.setattr(D, "ClaudePtySession", FakeSession)

    with pytest.raises(
        D.ReconPrepassDispatchBlocked,
        match="external-dependency spawn authority failed",
    ):
        D._run_single_recon_worker_pty(
            job=job,
            scratchpad=scratchpad,
            project_root=str(tmp_path),
            config=config,
            phase=SimpleNamespace(name="recon"),
            base_cmd=["claude"],
            env={},
            timeout=30,
            quiescence_s=0.01,
            attempt=1,
        )

    assert calls == {"validate": 2, "spawn": 0, "terminate": 1}


def test_concurrent_pool_veto_terminates_live_sibling_and_no_retry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scratchpad, config = _config(tmp_path)
    checkpoint = scratchpad / "_v2_checkpoint.json"
    checkpoint.write_text(
        '{"completed":[],"degraded":[]}\n', encoding="utf-8"
    )
    checkpoint_before = checkpoint.read_bytes()
    sibling_started = threading.Event()
    sibling_stopped = threading.Event()
    calls = {"terminate": 0, "retry": 0}
    jobs = [
        {"agent_id": "R1", "output": "r1.md"},
        {"agent_id": "R2", "output": "r2.md"},
    ]
    monkeypatch.setattr(D, "_recon_worker_jobs", lambda _config: jobs)
    monkeypatch.setattr(
        D,
        "_recon_worker_complete",
        lambda *_args, **_kwargs: (False, ["missing"]),
    )
    monkeypatch.setattr(
        D,
        "_prepare_typed_model_worker_launch",
        lambda **_kwargs: [],
    )
    monkeypatch.setattr(
        D, "_snapshot_worker_input_artifacts", lambda *_args: {}
    )
    monkeypatch.setattr(
        D, "_restore_worker_input_artifacts", lambda *_args: []
    )
    monkeypatch.setattr(
        D.display, "print_phase_heartbeat", lambda *_args, **_kwargs: None
    )
    monkeypatch.setattr(D.display, "spin", lambda *_args, **_kwargs: None)

    class LiveSibling:
        def terminate(self, **_kwargs):
            calls["terminate"] += 1
            sibling_stopped.set()

    sibling = LiveSibling()

    def worker(*, job, **_kwargs):
        if job["agent_id"] == "R1":
            assert sibling_started.wait(5)
            raise D.ReconPrepassDispatchBlocked("concurrent late veto")
        D._register_active_worker_session(sibling)
        sibling_started.set()
        try:
            assert sibling_stopped.wait(5)
            return {"output": job["output"], "rc": -2, "status": "stopped"}
        finally:
            D._unregister_active_worker_session(sibling)

    monkeypatch.setattr(D, "_run_single_recon_worker_pty", worker)
    monkeypatch.setattr(
        D,
        "_merge_recon_worker_shards_and_arm_finalization",
        lambda *_args, **_kwargs: calls.__setitem__(
            "retry", calls["retry"] + 1
        ),
    )

    with pytest.raises(
        D.ReconPrepassDispatchBlocked, match="concurrent late veto"
    ):
        D._run_recon_worker_pool_pty(
            scratchpad=scratchpad,
            project_root=str(tmp_path),
            config=config,
            phase=SimpleNamespace(name="recon"),
            base_cmd=["claude"],
            env={},
            timeout=30,
            quiescence_s=0.01,
            attempt=1,
        )

    assert sibling_stopped.is_set()
    assert calls == {"terminate": 1, "retry": 0}
    assert checkpoint.read_bytes() == checkpoint_before


def test_supervised_recon_respawn_veto_escapes_retry_conversion(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scratchpad, config = _config(tmp_path)
    calls = {"respawn": 0, "authority": 0}

    class FinishedSession:
        transcript_path = scratchpad / "absent-transcript.jsonl"

        def wait_for_turn_complete(self, *_args, **_kwargs):
            return SimpleNamespace(
                rate_limited=False,
                context_thrash=False,
                complete=True,
            )

        def is_alive(self):
            return False

        def terminate(self, **_kwargs):
            return None

    monkeypatch.setattr(
        D, "gate_passes", lambda *_args, **_kwargs: (False, ["missing"])
    )
    monkeypatch.setattr(
        D, "compute_phase_row_statuses", lambda *_args, **_kwargs: []
    )

    def veto() -> None:
        calls["authority"] += 1
        raise D.ReconPrepassDispatchBlocked("respawn generation drift")

    def respawn(**kwargs):
        calls["respawn"] += 1
        kwargs["provider_dispatch_authority"]()
        pytest.fail("a vetoed respawn must not return a provider session")

    monkeypatch.setattr(D, "_respawn_missing_only", respawn)
    with pytest.raises(
        D.ReconPrepassDispatchBlocked, match="respawn generation drift"
    ):
        D._run_supervised_pty_loop(
            session=FinishedSession(),
            scratchpad=scratchpad,
            project_root=str(tmp_path),
            phase=SimpleNamespace(
                name="recon", expected_artifacts=["recon.md"], any_of=[]
            ),
            config={**config, "pty_continuation_budget": 1},
            preflight={},
            timeout=30,
            quiescence_s=0.01,
            on_poll=None,
            base_cmd=["claude"],
            cwd=str(tmp_path),
            env={},
            log_file=None,
            prompt_path=scratchpad / "prompt.md",
            provider_dispatch_authority=veto,
        )

    assert calls == {"respawn": 1, "authority": 1}


def test_external_dependency_veto_escapes_pool_finalization_wrapper(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scratchpad, config = _config(tmp_path)
    calls = {"research": 0, "gate": 0}
    job = {"agent_id": "R1", "output": "r1.md"}
    monkeypatch.setattr(D, "_recon_worker_jobs", lambda _config: [job])
    monkeypatch.setattr(
        D,
        "_recon_worker_complete",
        lambda *_args, **_kwargs: (True, []),
    )
    monkeypatch.setattr(
        D,
        "_merge_recon_worker_shards_and_arm_finalization",
        lambda *_args, **_kwargs: None,
    )

    def research(**_kwargs):
        calls["research"] += 1
        raise D.ReconPrepassDispatchBlocked("R-EXT launch drift")

    monkeypatch.setattr(D, "_run_recon_dependency_research_wave", research)
    monkeypatch.setattr(
        D,
        "gate_passes",
        lambda *_args, **_kwargs: (
            calls.__setitem__("gate", calls["gate"] + 1) or True,
            [],
        ),
    )

    with pytest.raises(
        D.ReconPrepassDispatchBlocked, match="R-EXT launch drift"
    ):
        D._run_recon_worker_pool_pty(
            scratchpad=scratchpad,
            project_root=str(tmp_path),
            config=config,
            phase=SimpleNamespace(name="recon"),
            base_cmd=["claude"],
            env={},
            timeout=30,
            quiescence_s=0.01,
            attempt=1,
        )

    assert calls == {"research": 1, "gate": 0}
