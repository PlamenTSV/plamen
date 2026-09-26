"""Failure-path regressions for POSIX V2 compatibility outputs."""

from __future__ import annotations

import json
from pathlib import Path
import sys
import textwrap

import pytest

from phase_io_contracts import LaunchSpec, PhaseIOContract
import posix_v2_compat_runtime as compat
from test_posix_v2_compat_prelaunch_recovery import (
    _fake_codex,
    _phase_io_authority,
    _runtime_roots,
)


def _invoke(
    *,
    session: compat.PosixV2CompatSessionAuthority,
    project: Path,
    scratchpad: Path,
    writable: Path,
    contract: PhaseIOContract,
    launch: LaunchSpec,
) -> int:
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


def _only_receipt(scratchpad: Path) -> dict[str, object]:
    receipt_path = next(
        (scratchpad / ".posix_v2_compat_receipts").glob("*.json")
    )
    return json.loads(receipt_path.read_text(encoding="ascii"))


def _fake_nonzero_codex(path: Path) -> Path:
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
            destination.write_bytes(b"partial provider bytes\\n")
            Path(sys.argv[sys.argv.index("-o") + 1]).write_bytes(b"failed\\n")
            raise SystemExit(17)
            """
        ),
        encoding="utf-8",
    )
    path.chmod(0o755)
    return path


def test_auth_failure_does_not_manufacture_expected_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session, project, scratchpad, writable = _runtime_roots(tmp_path)
    binary = _fake_codex(tmp_path / "codex")
    contract, launch = _phase_io_authority(project, scratchpad)
    monkeypatch.setattr(compat.shutil, "which", lambda _name: str(binary))

    def reject_auth() -> tuple[str, bytes | None, str]:
        raise compat.PosixV2CompatRuntimeError(
            "CODEX_AUTH", "fixture auth admission failure"
        )

    monkeypatch.setattr(compat, "_load_ambient_codex_auth", reject_auth)
    try:
        assert _invoke(
            session=session,
            project=project,
            scratchpad=scratchpad,
            writable=writable,
            contract=contract,
            launch=launch,
        ) == compat.COMPAT_EXIT_ERROR
        assert not (writable / "recon.md").exists()
        receipt = _only_receipt(scratchpad)
        assert receipt["status"] == "PRELAUNCH_FAILED"
        assert receipt["failure_code"] == "CODEX_AUTH"
    finally:
        session.close()


def test_popen_failure_does_not_manufacture_expected_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session, project, scratchpad, writable = _runtime_roots(tmp_path)
    binary = _fake_codex(tmp_path / "codex")
    contract, launch = _phase_io_authority(project, scratchpad)
    monkeypatch.setattr(
        compat,
        "_resolve_codex_binary",
        lambda: (binary, "codex-cli recovery-test", "b" * 64),
    )
    monkeypatch.setattr(
        compat,
        "_load_ambient_codex_auth",
        lambda: ("PRIVATE_AUTH_JSON_COPY", b'{"tokens":{}}\n', "a" * 64),
    )

    def reject_spawn(*_args: object, **_kwargs: object) -> object:
        raise OSError("fixture Popen failure")

    monkeypatch.setattr(compat.subprocess, "Popen", reject_spawn)
    try:
        assert _invoke(
            session=session,
            project=project,
            scratchpad=scratchpad,
            writable=writable,
            contract=contract,
            launch=launch,
        ) == compat.COMPAT_EXIT_ERROR
        assert not (writable / "recon.md").exists()
        receipt = _only_receipt(scratchpad)
        assert receipt["status"] == "PRELAUNCH_FAILED"
        assert receipt["failure_code"] == "UNEXPECTED_OSERROR"
    finally:
        session.close()


def test_popen_failure_preserves_output_that_appeared_after_binding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session, project, scratchpad, writable = _runtime_roots(tmp_path)
    binary = _fake_codex(tmp_path / "codex")
    contract, launch = _phase_io_authority(project, scratchpad)
    output = writable / "recon.md"
    output.write_bytes(b"concurrent owner bytes\n")
    identity = output.stat()
    monkeypatch.setattr(
        compat,
        "_resolve_codex_binary",
        lambda: (binary, "codex-cli recovery-test", "b" * 64),
    )
    monkeypatch.setattr(
        compat,
        "_load_ambient_codex_auth",
        lambda: ("PRIVATE_AUTH_JSON_COPY", b'{"tokens":{}}\n', "a" * 64),
    )
    monkeypatch.setattr(
        compat.subprocess,
        "Popen",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            OSError("fixture Popen failure")
        ),
    )
    try:
        assert _invoke(
            session=session,
            project=project,
            scratchpad=scratchpad,
            writable=writable,
            contract=contract,
            launch=launch,
        ) == compat.COMPAT_EXIT_ERROR
        after = output.stat()
        assert output.read_bytes() == b"concurrent owner bytes\n"
        assert (after.st_dev, after.st_ino) == (
            identity.st_dev,
            identity.st_ino,
        )
    finally:
        session.close()


def test_symlink_that_appeared_after_binding_is_rejected_and_preserved(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session, project, scratchpad, writable = _runtime_roots(tmp_path)
    binary = _fake_codex(tmp_path / "codex")
    contract, launch = _phase_io_authority(project, scratchpad)
    target = tmp_path / "outside.md"
    target.write_bytes(b"outside owner bytes\n")
    output = writable / "recon.md"
    output.symlink_to(target)
    monkeypatch.setattr(compat.shutil, "which", lambda _name: str(binary))
    monkeypatch.setattr(
        compat,
        "_load_ambient_codex_auth",
        lambda: ("PRIVATE_AUTH_JSON_COPY", b'{"tokens":{}}\n', "a" * 64),
    )
    try:
        assert _invoke(
            session=session,
            project=project,
            scratchpad=scratchpad,
            writable=writable,
            contract=contract,
            launch=launch,
        ) == compat.COMPAT_EXIT_ERROR
        assert output.is_symlink()
        assert output.resolve() == target
        assert target.read_bytes() == b"outside owner bytes\n"
        receipt = _only_receipt(scratchpad)
        assert receipt["status"] == "PRELAUNCH_FAILED"
        assert receipt["failure_code"] == "PHASE_IO_ROUTE"
    finally:
        session.close()


def test_nonzero_provider_never_publishes_partial_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session, project, scratchpad, writable = _runtime_roots(tmp_path)
    binary = _fake_nonzero_codex(tmp_path / "codex")
    contract, launch = _phase_io_authority(project, scratchpad)
    monkeypatch.setattr(compat.shutil, "which", lambda _name: str(binary))
    monkeypatch.setattr(
        compat,
        "_load_ambient_codex_auth",
        lambda: ("PRIVATE_AUTH_JSON_COPY", b'{"tokens":{}}\n', "a" * 64),
    )
    try:
        assert _invoke(
            session=session,
            project=project,
            scratchpad=scratchpad,
            writable=writable,
            contract=contract,
            launch=launch,
        ) == 17
        assert not (writable / "recon.md").exists()
        receipt = _only_receipt(scratchpad)
        assert receipt["status"] == "NONZERO_EXIT"
        assert receipt["failure_code"] == "NONZERO_EXIT"
        assert receipt["completed_output_evidence"] == []
    finally:
        session.close()
