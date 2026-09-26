"""Regressions for compatibility prelaunch and recon retry recovery."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import sys
import textwrap

import pytest

from artifact_ledger import record_work_unit_inputs
from phase_io_contracts import (
    ArtifactSpec,
    LaunchSpec,
    PhaseIOContract,
    canonical_work_unit_key,
)
import plamen_driver as driver
import posix_v2_compat_runtime as compat


def _runtime_roots(
    tmp_path: Path,
) -> tuple[
    compat.PosixV2CompatSessionAuthority,
    Path,
    Path,
    Path,
]:
    project = tmp_path / "project"
    scratchpad = project / ".scratchpad"
    writable = scratchpad / "output"
    writable.mkdir(parents=True)
    (scratchpad / "input.md").write_text("bound input\n", encoding="utf-8")
    session = compat.issue_posix_v2_compat_session_for_installed_front(
        run_id="prelaunch-recovery",
        project_root=project,
        scratchpad=scratchpad,
    )
    return session, project, scratchpad, writable


def _phase_io_authority(
    project: Path,
    scratchpad: Path,
) -> tuple[PhaseIOContract, LaunchSpec]:
    key = canonical_work_unit_key(
        "sc", "thorough", "evm", "codex", "recon", "worker.r1"
    )
    contract = PhaseIOContract(
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="codex",
        phase="recon",
        work_unit_id="worker.r1",
        outputs=(ArtifactSpec(
            root="scratchpad",
            path="output/recon.md",
            owner_key=key,
            artifact_class="REQUIRED",
            writer="MODEL",
            write_mode="CREATE",
        ),),
        immutable_inputs=("scratchpad:input.md",),
    )
    launch = LaunchSpec(
        work_unit_key=key,
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="codex",
        model="gpt-test",
        timeout_s=10,
        exec_mode="headless",
        tool_policy=("filesystem",),
    )
    record_work_unit_inputs(
        scratchpad,
        project,
        contract,
        launch,
        run_id="prelaunch-recovery",
    )
    return contract, launch


def _run(
    monkeypatch: pytest.MonkeyPatch,
    *,
    session: compat.PosixV2CompatSessionAuthority,
    project: Path,
    scratchpad: Path,
    writable: Path,
    located_binary: Path | None,
) -> int:
    monkeypatch.setattr(
        compat.shutil,
        "which",
        lambda _name: None if located_binary is None else str(located_binary),
    )
    monkeypatch.setattr(
        compat,
        "_load_ambient_codex_auth",
        lambda: ("PRIVATE_AUTH_JSON_COPY", b'{"tokens":{}}\n', "a" * 64),
    )
    contract, launch = _phase_io_authority(project, scratchpad)
    return compat.run_codex_exec(
        session_authority=session,
        prompt="Produce the assigned artifact.",
        phase_name="recon",
        needs_mcp=False,
        config={
            "_run_id": "prelaunch-recovery",
            "project_root": str(project),
        },
        scratchpad=scratchpad,
        attempt=1,
        label="R1",
        expected_outputs=("output/recon.md",),
        timeout=10,
        effective_model="gpt-test",
        working_directory=scratchpad,
        writable_directories=(writable,),
        phase_io_contract=contract,
        phase_io_launch=launch,
    )


def _fake_codex(path: Path) -> Path:
    path.write_text(
        "#!" + sys.executable + "\n" + textwrap.dedent(
            """
            import json
            from pathlib import Path
            import re
            import sys

            if sys.argv[1:] == ["--version"]:
                print("codex-cli recovery-test")
                raise SystemExit(0)
            prompt = sys.stdin.buffer.read().decode("utf-8")
            blocks = re.findall(r"```json\\n(.*?)\\n```", prompt, re.S)
            route = json.loads(blocks[-1])["output_routes"][0]
            destination = Path(route["path"])
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text("model-owned recon output\\n")
            Path(sys.argv[sys.argv.index("-o") + 1]).write_text(
                "completed\\n"
            )
            print('{"type":"turn.completed"}')
            """
        ),
        encoding="utf-8",
    )
    path.chmod(0o755)
    return path


def test_missing_codex_leaves_expected_output_absent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session, project, scratchpad, writable = _runtime_roots(tmp_path)
    try:
        assert _run(
            monkeypatch,
            session=session,
            project=project,
            scratchpad=scratchpad,
            writable=writable,
            located_binary=None,
        ) == compat.COMPAT_EXIT_ERROR
        assert not (writable / "recon.md").exists()
        receipt_path = next(
            (scratchpad / ".posix_v2_compat_receipts").glob("*.json")
        )
        receipt = json.loads(receipt_path.read_text(encoding="ascii"))
        assert receipt["status"] == "PRELAUNCH_FAILED"
        assert receipt["failure_code"] == "CODEX_BINARY"
        assert receipt["argv"] == []
        assert list((scratchpad / ".posix_v2_compat_private").iterdir()) == []
    finally:
        session.close()


def test_session_issuance_recovers_stale_uuid_and_quarantine_without_following_links(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    scratchpad = project / ".scratchpad"
    private_root = scratchpad / ".posix_v2_compat_private"
    stale = private_root / ("a" * 32)
    quarantine = private_root / (".cleanup-" + "b" * 32)
    stale.mkdir(mode=0o700, parents=True)
    private_root.chmod(0o700)
    quarantine.mkdir(mode=0o700)
    (stale / "nested").mkdir()
    (stale / "nested" / "cache.bin").write_bytes(b"cache")
    (quarantine / "partial.bin").write_bytes(b"partial")
    external = tmp_path / "external"
    external.mkdir()
    sentinel = external / "sentinel.txt"
    sentinel.write_bytes(b"survive\n")
    (stale / "external-link").symlink_to(external, target_is_directory=True)

    session = compat.issue_posix_v2_compat_session_for_installed_front(
        run_id="stale-recovery",
        project_root=project,
        scratchpad=scratchpad,
    )
    try:
        assert list(private_root.iterdir()) == []
        assert sentinel.read_bytes() == b"survive\n"
    finally:
        session.close()


def test_session_issuance_rejects_symlink_private_root(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    scratchpad = project / ".scratchpad"
    scratchpad.mkdir(parents=True)
    external = tmp_path / "external"
    external.mkdir()
    sentinel = external / "sentinel.txt"
    sentinel.write_bytes(b"survive\n")
    (scratchpad / ".posix_v2_compat_private").symlink_to(
        external,
        target_is_directory=True,
    )

    with pytest.raises(compat.PosixV2CompatRuntimeError) as caught:
        compat.issue_posix_v2_compat_session_for_installed_front(
            run_id="unsafe-root",
            project_root=project,
            scratchpad=scratchpad,
        )
    assert caught.value.code == "PRIVATE_RUNTIME"
    assert sentinel.read_bytes() == b"survive\n"


def test_session_issuance_rejects_malformed_private_entry_before_mutation(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    scratchpad = project / ".scratchpad"
    private_root = scratchpad / ".posix_v2_compat_private"
    stale = private_root / ("c" * 32)
    stale.mkdir(mode=0o700, parents=True)
    private_root.chmod(0o700)
    retained = stale / "retained.txt"
    retained.write_bytes(b"retained\n")
    (private_root / "unexpected").mkdir()

    with pytest.raises(compat.PosixV2CompatRuntimeError) as caught:
        compat.issue_posix_v2_compat_session_for_installed_front(
            run_id="malformed-entry",
            project_root=project,
            scratchpad=scratchpad,
        )
    assert caught.value.code == "PRIVATE_RUNTIME"
    assert retained.read_bytes() == b"retained\n"


def test_session_recovery_never_removes_shared_locked_active_invocation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = tmp_path / "project"
    scratchpad = project / ".scratchpad"
    scratchpad.mkdir(parents=True)
    opened = compat._open_private_runtime_root(scratchpad, create=True)
    assert opened is not None
    _private_root, descriptor, _identity = opened
    active_name = "d" * 32
    compat._acquire_private_lock(
        descriptor,
        compat.fcntl.LOCK_SH,
        "fixture shared lock",
    )
    os.mkdir(active_name, mode=0o700, dir_fd=descriptor)
    active = scratchpad / ".posix_v2_compat_private" / active_name
    (active / "active.txt").write_bytes(b"active\n")
    monkeypatch.setattr(compat, "_PRIVATE_LOCK_TIMEOUT_SECONDS", 0.01)
    try:
        with pytest.raises(compat.PosixV2CompatRuntimeError) as caught:
            compat.issue_posix_v2_compat_session_for_installed_front(
                run_id="concurrent-recovery",
                project_root=project,
                scratchpad=scratchpad,
            )
        assert caught.value.code == "PRIVATE_RUNTIME"
        assert (active / "active.txt").read_bytes() == b"active\n"
    finally:
        compat.fcntl.flock(descriptor, compat.fcntl.LOCK_UN)
        os.close(descriptor)
    session = compat.issue_posix_v2_compat_session_for_installed_front(
        run_id="concurrent-recovery",
        project_root=project,
        scratchpad=scratchpad,
    )
    session.close()
    assert list((scratchpad / ".posix_v2_compat_private").iterdir()) == []


def test_stale_recovery_fails_closed_at_nominal_byte_bound(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = tmp_path / "project"
    scratchpad = project / ".scratchpad"
    private_root = scratchpad / ".posix_v2_compat_private"
    stale = private_root / ("e" * 32)
    stale.mkdir(mode=0o700, parents=True)
    private_root.chmod(0o700)
    (stale / "oversized.bin").write_bytes(b"too large for fixture bound")
    monkeypatch.setattr(compat, "_MAX_PRIVATE_CLEANUP_NOMINAL_BYTES", 1)

    with pytest.raises(compat.PosixV2CompatRuntimeError) as caught:
        compat.issue_posix_v2_compat_session_for_installed_front(
            run_id="bounded-recovery",
            project_root=project,
            scratchpad=scratchpad,
        )
    assert caught.value.code == "PRIVATE_CLEANUP_BOUND"
    assert any(private_root.iterdir())


def test_session_recovery_rejects_uuid_quarantine_collision_before_mutation(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    scratchpad = project / ".scratchpad"
    private_root = scratchpad / ".posix_v2_compat_private"
    invocation_id = "f" * 32
    stale = private_root / invocation_id
    quarantine = private_root / (".cleanup-" + invocation_id)
    stale.mkdir(mode=0o700, parents=True)
    private_root.chmod(0o700)
    quarantine.mkdir(mode=0o700)
    stale_sentinel = stale / "stale.txt"
    quarantine_sentinel = quarantine / "quarantine.txt"
    stale_sentinel.write_bytes(b"stale\n")
    quarantine_sentinel.write_bytes(b"quarantine\n")

    with pytest.raises(compat.PosixV2CompatRuntimeError) as caught:
        compat.issue_posix_v2_compat_session_for_installed_front(
            run_id="ambiguous-recovery",
            project_root=project,
            scratchpad=scratchpad,
        )
    assert caught.value.code == "PRIVATE_RUNTIME"
    assert stale_sentinel.read_bytes() == b"stale\n"
    assert quarantine_sentinel.read_bytes() == b"quarantine\n"


def test_session_recovery_rejects_top_level_device_crossing_before_cleanup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = tmp_path / "project"
    scratchpad = project / ".scratchpad"
    private_root = scratchpad / ".posix_v2_compat_private"
    invocation_id = "1" * 32
    stale = private_root / invocation_id
    stale.mkdir(mode=0o700, parents=True)
    private_root.chmod(0o700)
    sentinel = stale / "sentinel.txt"
    sentinel.write_bytes(b"retained\n")
    original_stat = compat.os.stat
    cleanup_called = False

    def cross_device_stat(
        path: object,
        *args: object,
        **kwargs: object,
    ) -> os.stat_result:
        observed = original_stat(path, *args, **kwargs)
        if path == invocation_id and kwargs.get("dir_fd") is not None:
            fields = list(observed)
            fields[2] = int(observed.st_dev) + 1
            return os.stat_result(fields)
        return observed

    def observe_cleanup(*_args: object, **_kwargs: object) -> None:
        nonlocal cleanup_called
        cleanup_called = True

    monkeypatch.setattr(compat.os, "stat", cross_device_stat)
    monkeypatch.setattr(compat, "_cleanup_private_entry", observe_cleanup)
    with pytest.raises(compat.PosixV2CompatRuntimeError) as caught:
        compat.issue_posix_v2_compat_session_for_installed_front(
            run_id="cross-device-recovery",
            project_root=project,
            scratchpad=scratchpad,
        )
    assert caught.value.code == "PRIVATE_RUNTIME"
    assert cleanup_called is False
    assert sentinel.read_bytes() == b"retained\n"


def test_preexisting_expected_output_is_never_altered_on_prelaunch_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session, project, scratchpad, writable = _runtime_roots(tmp_path)
    output = writable / "recon.md"
    original = b"preexisting user bytes\n"
    output.write_bytes(original)
    identity = output.stat()
    try:
        assert _run(
            monkeypatch,
            session=session,
            project=project,
            scratchpad=scratchpad,
            writable=writable,
            located_binary=None,
        ) == compat.COMPAT_EXIT_ERROR
        after = output.stat()
        assert output.read_bytes() == original
        assert (after.st_dev, after.st_ino) == (identity.st_dev, identity.st_ino)
    finally:
        session.close()


def test_successful_provider_still_creates_expected_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session, project, scratchpad, writable = _runtime_roots(tmp_path)
    binary = _fake_codex(tmp_path / "codex")
    try:
        assert _run(
            monkeypatch,
            session=session,
            project=project,
            scratchpad=scratchpad,
            writable=writable,
            located_binary=binary,
        ) == 0
        assert (writable / "recon.md").read_bytes() == (
            b"model-owned recon output\n"
        )
        receipt_path = next(
            (scratchpad / ".posix_v2_compat_receipts").glob("*.json")
        )
        receipt = json.loads(receipt_path.read_text(encoding="ascii"))
        assert receipt["status"] == "COMPLETED"
        assert receipt["codex_version"] == "codex-cli recovery-test"
    finally:
        session.close()


def _recon_failure(
    phase: driver.Phase,
    config: dict[str, object],
) -> driver.GateFailure:
    return driver.GateFailure(
        gate_id="recon.full_validator.0001",
        gate_class="SCHEMA",
        message="repair the failed recon predicate",
        affected_identities=("recon_out.md",),
        input_digest=driver._resolved_phase_input_digest(phase, config),
        output_digest="2" * 64,
        contract_digest=driver._resolved_phase_contract_digest(phase, config),
        evidence_paths=("recon_out.md",),
        repair_owner="recon",
        denominator_count=1,
        denominator_digest="4" * 64,
    )


def test_recon_attempt3_preserves_attempt2_semantic_plan_authority(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    scratchpad = project / ".scratchpad"
    scratchpad.mkdir(parents=True)
    run_id = "recon-transport-successor"
    config: dict[str, object] = {
        "pipeline": "sc",
        "mode": "thorough",
        "language": "evm",
        "cli_backend": "codex",
        "project_root": str(project),
        "_run_id": run_id,
    }
    phase = driver.Phase(
        "recon",
        ["recon"],
        ["recon_out.md"],
        base_timeout_s=120,
    )
    checkpoint = driver.Checkpoint(run_id=run_id)
    failure = _recon_failure(phase, config)

    plan_path = driver._write_retry_plan(
        scratchpad,
        checkpoint,
        phase,
        config,
        (failure,),
        attempt=2,
    )
    attempt2_raw = plan_path.read_bytes()
    attempt2_sha = hashlib.sha256(attempt2_raw).hexdigest()

    successor_path = driver._write_retry_plan(
        scratchpad,
        checkpoint,
        phase,
        config,
        (failure,),
        attempt=3,
    )
    assert successor_path == plan_path
    assert successor_path.read_bytes() == attempt2_raw
    authority = driver._validated_recon_retry_plan(
        scratchpad,
        config,
        worker_attempt=driver._recon_worker_attempt_ordinal(3, 1),
        phase=phase,
    )
    assert authority["state"] == "PRESENT"
    assert authority["plan_attempt"] == 2
    assert authority["transport_successor"] is True
    assert authority["sha256"] == attempt2_sha
