"""Independent adversarial review properties for the P2-A fuzz workspace.

These tests intentionally specify the authority boundary promised by the P2-A
design, rather than memorialising its current implementation.  A red property
is a cutover blocker: it means model-controlled bytes or a fuzz subprocess can
still cross the driver-owned trust/workspace boundary.
"""

from __future__ import annotations

import inspect
import json
import os
from pathlib import Path
import subprocess
import sys
import time

import pytest

import fuzz_workspace_authority as fwa


def _project(tmp_path: Path) -> tuple[Path, Path]:
    root = tmp_path / "project"
    (root / "src").mkdir(parents=True)
    (root / "test" / "invariant").mkdir(parents=True)
    (root / "src" / "Counter.sol").write_text(
        "pragma solidity ^0.8.20; contract Counter {}\n", encoding="utf-8"
    )
    (root / "foundry.toml").write_text(
        "[profile.default]\nsrc = 'src'\ntest = 'test'\n", encoding="utf-8"
    )
    (root / "test" / "invariant" / "Existing.t.sol").write_text(
        "contract ExistingInvariant {}\n", encoding="utf-8"
    )
    scratchpad = root / ".scratchpad"
    scratchpad.mkdir()
    return root, scratchpad


def _materialize(tmp_path: Path) -> dict[str, object]:
    root, scratchpad = _project(tmp_path)
    return fwa.materialize_fuzz_workspace(
        scratchpad=scratchpad,
        build_root=root,
        project_root=root,
        job_id="invariant-fuzz",
        language="evm",
        role="invariant_fuzz",
        run_id="RUN-ADVERSARIAL",
        source_snapshot_digest="a" * 64,
        allowed_tools=(Path(sys.executable).name,),
    )


def _load(path: str | Path) -> dict[str, object]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _rewrite_command_as_forge_campaign(receipt: dict[str, object]) -> None:
    command_path = next(
        (Path(str(receipt["runtime_root"])) / "commands").glob(
            "*-command.json"
        )
    )
    command = _load(command_path)
    command["argv"] = [
        "forge", "test", "--match-contract", "GeneratedInvariant",
    ]
    command["payload_digest"] = fwa.payload_digest(command)
    command_path.write_text(
        json.dumps(command, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def test_model_rewrite_cannot_turn_probe_receipt_into_measured_campaign(
    tmp_path: Path,
) -> None:
    """An unkeyed worker-writable receipt must not self-certify provenance."""

    receipt = _materialize(tmp_path)
    generated = Path(str(receipt["generated_root"]))
    (generated / "GeneratedInvariant.t.sol").write_text(
        "contract GeneratedInvariant {}\n", encoding="utf-8"
    )
    authority = Path(str(receipt["authority_path"]))
    assert fwa.run_recorded_command(
        authority, [sys.executable, "-c", "print('probe only')"], 30
    ) == 0

    # This simulates model authorship of the JSON after a harmless real runner
    # invocation.  Recomputing an unkeyed digest is not provenance.
    _rewrite_command_as_forge_campaign(receipt)
    result = fwa.finalize_fuzz_workspace(authority)

    assert result["status"] == "UNSCORED"
    assert "COMMAND_PROVENANCE_UNAUTHENTICATED" in {
        row["code"] for row in result["issues"]
    }


def test_exact_quarantined_harness_clone_is_not_fresh_generated_provenance(
    tmp_path: Path,
) -> None:
    receipt = _materialize(tmp_path)
    quarantine = (
        Path(str(receipt["quarantine_root"]))
        / "test" / "invariant" / "Existing.t.sol"
    )
    generated = Path(str(receipt["generated_root"]))
    (generated / "GeneratedInvariant.t.sol").write_bytes(quarantine.read_bytes())
    authority = Path(str(receipt["authority_path"]))
    assert fwa.run_recorded_command(
        authority, [sys.executable, "-c", "print('probe only')"], 30
    ) == 0
    _rewrite_command_as_forge_campaign(receipt)

    result = fwa.finalize_fuzz_workspace(authority)
    assert result["status"] == "UNSCORED"
    assert "PREEXISTING_HARNESS_PROVENANCE" in {
        row["code"] for row in result["issues"]
    }


def test_rejected_integrity_attempt_survives_materialization_resume(
    tmp_path: Path,
) -> None:
    receipt = _materialize(tmp_path)
    authority = Path(str(receipt["authority_path"]))
    assert fwa.run_recorded_command(authority, ["not-approved"], 5) == 125
    assert _load(str(receipt["debt_path"]))["status"] == "UNSCORED"

    resumed = fwa.materialize_fuzz_workspace(
        scratchpad=Path(str(receipt["scratchpad_root"])),
        build_root=Path(str(receipt["source_root"])),
        project_root=Path(str(receipt["project_root"])),
        job_id="invariant-fuzz",
        language="evm",
        role="invariant_fuzz",
        run_id="RUN-ADVERSARIAL",
        source_snapshot_digest="a" * 64,
        allowed_tools=(Path(sys.executable).name,),
    )
    assert resumed["status"] == "READY"
    debt = _load(str(receipt["debt_path"]))
    assert debt["status"] == "UNSCORED"
    assert "UNAPPROVED_TOOL" in {row["code"] for row in debt["issues"]}


def test_preexisting_workspace_parent_link_cannot_redirect_driver_writes(
    tmp_path: Path,
) -> None:
    root, scratchpad = _project(tmp_path)
    outside = tmp_path / "redirected-workspaces"
    outside.mkdir()
    workspace_parent = scratchpad / fwa.WORKSPACES_DIR
    try:
        workspace_parent.symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("directory symlink/reparse creation unavailable")

    receipt = fwa.materialize_fuzz_workspace(
        scratchpad=scratchpad,
        build_root=root,
        project_root=root,
        job_id="invariant-fuzz",
        language="evm",
        role="invariant_fuzz",
        run_id="RUN-REDIRECT",
        source_snapshot_digest="b" * 64,
    )

    assert receipt["status"] == "UNSCORED"
    assert not any(outside.iterdir()), "driver published workspace outside scratchpad"


def test_approved_process_cannot_write_outside_workspace_via_inherited_env(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    receipt = _materialize(tmp_path)
    outside = tmp_path / "outside-workspace" / "escaped.txt"
    monkeypatch.setenv("PLAMEN_REVIEW_OUTSIDE_TARGET", str(outside))
    code = (
        "import os,pathlib; p=pathlib.Path("
        "os.environ['PLAMEN_REVIEW_OUTSIDE_TARGET']); "
        "p.parent.mkdir(parents=True,exist_ok=True); p.write_text('escaped')"
    )
    rc = fwa.run_recorded_command(
        Path(str(receipt["authority_path"])),
        [sys.executable, "-c", code],
        30,
    )

    assert rc == 125
    assert not outside.exists()


def test_successful_parent_cannot_leave_detached_child_after_runner_returns(
    tmp_path: Path,
) -> None:
    receipt = _materialize(tmp_path)
    marker = Path(str(receipt["generated_root"])) / "late-orphan-write.txt"
    child = (
        "import pathlib,sys,time; time.sleep(0.8); "
        "pathlib.Path(sys.argv[1]).write_text('orphan')"
    )
    parent = (
        "import os,subprocess,sys; kw={'stdin':subprocess.DEVNULL,"
        "'stdout':subprocess.DEVNULL,'stderr':subprocess.DEVNULL,"
        "'close_fds':True}; "
        "kw.update({'creationflags':subprocess.CREATE_NEW_PROCESS_GROUP|"
        "subprocess.DETACHED_PROCESS} if os.name=='nt' else "
        "{'start_new_session':True}); "
        f"subprocess.Popen([sys.executable,'-c',{child!r},sys.argv[1]],**kw)"
    )
    rc = fwa.run_recorded_command(
        Path(str(receipt["authority_path"])),
        [sys.executable, "-c", parent, str(marker)],
        30,
    )
    assert rc == 0
    time.sleep(1.5)
    assert not marker.exists(), "runner returned while a detached child stayed live"


@pytest.mark.parametrize(
    ("language", "role", "argv"),
    [
        (
            "evm", "invariant_fuzz",
            ["forge", "test", "--match-contract", "Invariant", "--list"],
        ),
        ("evm", "medusa_fuzz", ["medusa", "fuzz", "--help"]),
        ("solana", "invariant_fuzz", ["trident", "fuzz", "run", "--help"]),
        ("soroban", "invariant_fuzz", ["cargo", "test", "--no-run"]),
        ("sui", "invariant_fuzz", ["sui", "move", "test", "--help"]),
    ],
)
def test_nonexecuting_help_list_or_compile_only_commands_are_not_campaigns(
    language: str, role: str, argv: list[str],
) -> None:
    assert fwa._campaign_command_kind(language, role, argv) == ""


def test_result_validator_recomputes_status_debt_and_proof_authority(
    tmp_path: Path,
) -> None:
    receipt = _materialize(tmp_path)
    authority = Path(str(receipt["authority_path"]))
    result = fwa.finalize_fuzz_workspace(authority)
    assert result["status"] == "UNSCORED"

    path = Path(str(receipt["result_path"]))
    forged = _load(path)
    forged["status"] = "MEASURED"
    forged["issues"] = []
    forged["proof_authority"] = "EXECUTION_SCOPE_REQUIRES_CONSUMER"
    forged["payload_digest"] = fwa.payload_digest(forged)
    path.write_text(
        json.dumps(forged, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    assert fwa.validate_fuzz_workspace_result(authority)


def test_all_depth_backends_prepare_fuzz_workspaces_before_prompt_render() -> None:
    import plamen_driver as driver

    headless_and_codex = inspect.getsource(driver._run_depth_codex_fanout)
    assert "_prepare_depth_fuzz_workspaces" in headless_and_codex


def test_production_authority_module_is_present_in_clean_git_package() -> None:
    repo = Path(__file__).parents[1]
    module = Path(fwa.__file__).resolve()
    relative = module.relative_to(repo).as_posix()
    ignored = subprocess.run(
        ["git", "check-ignore", "-q", "--", relative],
        cwd=repo,
        check=False,
    )
    assert ignored.returncode != 0, f"production module is gitignored: {relative}"


def test_phase_io_binds_fuzz_authority_before_worker_and_result_after_driver() -> None:
    from phase_io_contracts import resolve_phase_io_contract

    contract = resolve_phase_io_contract(
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="claude",
        phase="depth",
        work_unit_id="worker.invariant-fuzz",
        exact_outputs=("invariant_fuzz_results.md",),
    )
    immutable = set(contract.immutable_inputs)
    assert "scratchpad:fuzz_workspace_index.json" in immutable

    finalization = resolve_phase_io_contract(
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="claude",
        phase="depth",
        work_unit_id="fuzz_workspace.finalize.all",
        exact_inputs=(
            "fuzz_workspace_index.json",
            "invariant_fuzz_results.md",
        ),
        exact_outputs=("fuzz_workspace_result_index.json",),
        exact_writer="DRIVER",
    )
    outputs = {item.identity for item in finalization.outputs}
    assert "scratchpad:fuzz_workspace_result_index.json" in outputs


def test_nonready_fuzz_leaf_never_launches_from_original_project_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    import plamen_driver as driver

    root, scratchpad = _project(tmp_path)
    observed: dict[str, str] = {}

    class _FakeSession:
        transcript_path = scratchpad / "fake-transcript.log"

        def __init__(self, *args: object, cwd: str, **kwargs: object) -> None:
            del args, kwargs
            observed["cwd"] = cwd

        def spawn(self) -> None:
            raise RuntimeError("stop after cwd observation")

        def send_bootstrap(self) -> None:
            pass

        def terminate(self, grace_s: float) -> None:
            del grace_s

    monkeypatch.setattr(driver, "ClaudePtySession", _FakeSession)
    monkeypatch.setattr(driver, "_register_active_worker_session", lambda _: None)
    monkeypatch.setattr(driver, "_unregister_active_worker_session", lambda _: None)
    job = {
        "agent_id": "invariant-fuzz",
        "role": "invariant_fuzz",
        "output": "invariant_fuzz_results.md",
        "category": "fuzz",
        "fuzz_workspace_status": "UNSCORED",
    }
    driver._run_single_depth_worker_pty(
        job=job,
        scratchpad=scratchpad,
        project_root=str(root),
        config={"pipeline": "sc", "language": "evm", "mode": "thorough"},
        phase=next(item for item in driver.SC_PHASES if item.name == "depth"),
        base_cmd=["claude"],
        env=os.environ.copy(),
        timeout=1,
        quiescence_s=0.1,
        attempt=1,
        rendered_prompt="review fixture",
        inputs_prebound=True,
    )

    assert Path(observed["cwd"]).resolve() != root.resolve()
