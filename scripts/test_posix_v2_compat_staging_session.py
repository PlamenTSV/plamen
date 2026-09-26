"""Focused sibling staging-session authority regressions."""

from __future__ import annotations

import copy
import os
from pathlib import Path
import pickle

import pytest

import posix_v2_compat_runtime as compat


def _ordinary_session(tmp_path: Path, *, backend: str = "codex"):
    project = tmp_path / "live-project"
    scratch = project / ".scratchpad"
    scratch.mkdir(parents=True)
    return compat.issue_posix_v2_compat_session_for_installed_front(
        run_id="run-staging-test",
        project_root=project,
        scratchpad=scratch,
        backend=backend,
    )


def _stage(tmp_path: Path) -> tuple[Path, Path, Path]:
    stage = tmp_path / "axis-stage"
    project = stage / "project"
    scratch = stage / "scratchpad"
    project.mkdir(parents=True)
    scratch.mkdir()
    stage.chmod(0o700)
    return stage, project, scratch


def test_ordinary_session_still_rejects_sibling_project_and_scratch(
    tmp_path: Path,
) -> None:
    stage, project, scratch = _stage(tmp_path)
    with pytest.raises(
        compat.PosixV2CompatRuntimeError,
        match="scratchpad must be inside the project root",
    ):
        compat.issue_posix_v2_compat_session_for_installed_front(
            run_id="run-staging-test",
            project_root=project,
            scratchpad=scratch,
        )
    assert stage.is_dir()


def test_derived_staging_session_binds_parent_and_exact_sibling_roots(
    tmp_path: Path,
) -> None:
    parent = _ordinary_session(tmp_path)
    stage, project, scratch = _stage(tmp_path)
    derived = compat.derive_posix_v2_compat_staging_session(
        parent_session_authority=parent,
        staging_root=stage,
        project_root=project,
        scratchpad=scratch,
    )
    try:
        binding = dict(derived.binding)
        assert binding["schema"] == compat.DERIVED_STAGING_SESSION_SCHEMA
        assert binding["purpose"] == compat.DERIVED_STAGING_PURPOSE
        assert binding["run_id"] == parent.binding["run_id"]
        assert binding["backend"] == parent.binding["backend"]
        assert binding["parent_session_binding_sha256"] == parent.binding[
            "session_binding_sha256"
        ]
        assert binding["staging_root"] == str(stage.resolve())
        assert binding["project_root"] == str(project.resolve())
        assert binding["scratchpad"] == str(scratch.resolve())
        assert binding["writable_namespace"] == str(scratch.resolve())
        assert binding["population_zero_proven"] is False
        record = compat._execution_session_record(derived)
        assert compat._normalize_writable_directories(
            (scratch,), record=record
        ) == (scratch.resolve(),)
        with pytest.raises(
            compat.PosixV2CompatRuntimeError,
            match="write authority is limited to scratchpad descendants",
        ):
            compat._normalize_writable_directories((project,), record=record)
        with pytest.raises(TypeError):
            copy.copy(derived)
        with pytest.raises(TypeError):
            pickle.dumps(derived)
        with pytest.raises(
            compat.PosixV2CompatRuntimeError,
            match="derived staging sessions are still active",
        ):
            parent.close()
    finally:
        derived.close()
        parent.close()


@pytest.mark.parametrize("shape", ["nested", "cross-root", "same"])
def test_derived_staging_session_rejects_non_sibling_or_overlapping_shapes(
    tmp_path: Path,
    shape: str,
) -> None:
    parent = _ordinary_session(tmp_path)
    stage, project, scratch = _stage(tmp_path)
    if shape == "nested":
        nested = project / "scratchpad"
        nested.mkdir()
        scratch = nested
    elif shape == "cross-root":
        other = tmp_path / "other"
        other.mkdir()
        scratch = other
    else:
        scratch = project
    try:
        with pytest.raises(
            compat.PosixV2CompatRuntimeError,
            match="distinct immediate siblings",
        ):
            compat.derive_posix_v2_compat_staging_session(
                parent_session_authority=parent,
                staging_root=stage,
                project_root=project,
                scratchpad=scratch,
            )
    finally:
        parent.close()


def test_derived_staging_session_rejects_public_common_root(
    tmp_path: Path,
) -> None:
    parent = _ordinary_session(tmp_path)
    stage, project, scratch = _stage(tmp_path)
    stage.chmod(0o755)
    try:
        with pytest.raises(
            compat.PosixV2CompatRuntimeError,
            match="private to the current user",
        ):
            compat.derive_posix_v2_compat_staging_session(
                parent_session_authority=parent,
                staging_root=stage,
                project_root=project,
                scratchpad=scratch,
            )
    finally:
        parent.close()


def test_derived_staging_session_replays_common_root_identity(
    tmp_path: Path,
) -> None:
    parent = _ordinary_session(tmp_path)
    stage, project, scratch = _stage(tmp_path)
    derived = compat.derive_posix_v2_compat_staging_session(
        parent_session_authority=parent,
        staging_root=stage,
        project_root=project,
        scratchpad=scratch,
    )
    original = tmp_path / "original-stage"
    stage.rename(original)
    stage.mkdir(mode=0o700)
    try:
        with pytest.raises(
            compat.PosixV2CompatRuntimeError,
            match="staging root identity changed",
        ):
            _ = derived.binding
    finally:
        stage.rmdir()
        original.rename(stage)
        derived.close()
        parent.close()


def test_derived_staging_session_is_parent_process_local(
    tmp_path: Path,
) -> None:
    if not hasattr(os, "fork"):
        pytest.skip("fork unavailable")
    parent = _ordinary_session(tmp_path)
    stage, project, scratch = _stage(tmp_path)
    derived = compat.derive_posix_v2_compat_staging_session(
        parent_session_authority=parent,
        staging_root=stage,
        project_root=project,
        scratchpad=scratch,
    )
    read_fd, write_fd = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(read_fd)
        try:
            compat._execution_session_record(derived)
        except compat.PosixV2CompatRuntimeError as exc:
            os.write(write_fd, exc.code.encode("ascii"))
        else:
            os.write(write_fd, b"UNSAFE_ACCEPT")
        finally:
            os.close(write_fd)
        os._exit(0)
    os.close(write_fd)
    try:
        assert os.read(read_fd, 64) == b"SESSION_AUTHORITY"
        assert os.waitpid(pid, 0)[1] == 0
    finally:
        os.close(read_fd)
        derived.close()
        parent.close()
