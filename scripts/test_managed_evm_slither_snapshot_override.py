"""Managed Slither snapshot evidence cannot fall back to host Python."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

import audit_snapshot as snapshot
import managed_evm_python_toolchain as managed


def _observation(root: Path) -> dict[str, object]:
    interpreter = root / "python3.12"
    module = root / "slither" / "__init__.py"
    entrypoint = root / "bin" / "slither"
    module.parent.mkdir(parents=True)
    entrypoint.parent.mkdir(parents=True)
    for path, raw in (
        (interpreter, b"python"),
        (module, b"module"),
        (entrypoint, b"entrypoint"),
    ):
        path.write_bytes(raw)
    return {
        "managed_generation_binding_sha256": "0" * 64,
        "interpreter_implementation": "CPython",
        "interpreter_version": "3.12.12",
        "interpreter_path": str(interpreter),
        "interpreter_sha256": hashlib.sha256(b"python").hexdigest(),
        "interpreter_bytes": 6,
        "version": "0.11.5",
        "distribution_files_sha256": "1" * 64,
        "distribution_path_set_sha256": "2" * 64,
        "distribution_file_count": 3,
        "distribution_bytes": 30,
        "record_member_files_sha256": "3" * 64,
        "record_member_path_set_sha256": "4" * 64,
        "record_member_file_count": 4,
        "record_member_native_identity_count": 4,
        "record_member_bytes": 40,
        "record_path": "slither_analyzer-0.11.5.dist-info/RECORD",
        "record_sha256": "5" * 64,
        "record_bytes": 100,
        "record_row_count": 4,
        "record_normalized_rows_sha256": "6" * 64,
        "module_origin": str(module),
        "module_sha256": hashlib.sha256(b"module").hexdigest(),
        "entrypoint_path": str(entrypoint),
        "entrypoint_sha256": hashlib.sha256(b"entrypoint").hexdigest(),
        "entrypoint_bytes": 10,
    }


def _controls() -> tuple[dict, dict, str, str]:
    return ({}, {}, "a" * 64, "b" * 64)


def _patch_projection(
    monkeypatch: pytest.MonkeyPatch, observation: dict[str, object], authority: object,
) -> None:
    monkeypatch.setattr(
        managed,
        "managed_evm_slither_snapshot_observation",
        lambda value: observation
        if value is authority
        else (_ for _ in ()).throw(managed.ToolchainError("foreign")),
    )
    monkeypatch.setattr(snapshot, "_load_toolchain_identity_controls", _controls)
    monkeypatch.setattr(
        snapshot,
        "_runtime_identity_policy",
        lambda *args, **kwargs: (
            {"version": "0.11.5", "content_authority": {"mode": "OBSERVED"}},
            "OBSERVED_NONAUTHORITATIVE",
            False,
            "a" * 64,
            "b" * 64,
        ),
    )


def test_managed_projection_binds_generation_and_entrypoint(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    authority = object()
    observation = _observation(tmp_path / "generation")
    project = tmp_path / "project"
    project.mkdir()
    _patch_projection(monkeypatch, observation, authority)
    raw = snapshot.managed_evm_slither_snapshot_projection(
        authority, project_root=project
    )
    value = json.loads(raw)
    assert value["managed_generation_binding_sha256"] == "0" * 64
    assert value["entrypoint_sha256"] == observation["entrypoint_sha256"]
    assert value["resolved_executable"] == observation["interpreter_path"]
    assert value["deterministic_provider_authority"] is False

    signed = snapshot.capture_managed_evm_slither_provider_authority(
        authority, project_root=project
    )
    unsigned = dict(signed)
    stored = unsigned.pop("authority_digest")
    assert stored == hashlib.sha256(
        snapshot._canonical_json(unsigned)
    ).hexdigest()


def test_managed_runtime_entry_requires_exact_bytes_and_opaque_handle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    authority = object()
    observation = _observation(tmp_path / "generation")
    project = tmp_path / "project"
    project.mkdir()
    _patch_projection(monkeypatch, observation, authority)
    raw = snapshot.managed_evm_slither_snapshot_projection(
        authority, project_root=project
    )
    config = {
        snapshot.MANAGED_EVM_SLITHER_PROJECTION_CONFIG: raw,
        snapshot.MANAGED_EVM_GENERATION_AUTHORITY_CONFIG: authority,
    }
    assert snapshot._managed_evm_slither_runtime_entry(
        config, project_root=project, controls=_controls()
    ) == raw
    with pytest.raises(snapshot.SnapshotInputError, match="together"):
        snapshot._managed_evm_slither_runtime_entry(
            {snapshot.MANAGED_EVM_SLITHER_PROJECTION_CONFIG: raw},
            project_root=project,
            controls=_controls(),
        )
    with pytest.raises(snapshot.SnapshotInputError, match="differs"):
        snapshot._managed_evm_slither_runtime_entry(
            {
                **config,
                snapshot.MANAGED_EVM_SLITHER_PROJECTION_CONFIG: raw + b" ",
            },
            project_root=project,
            controls=_controls(),
        )


def test_ambient_fallback_is_only_used_without_managed_expectation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        snapshot,
        "_runtime_python_distribution_fingerprint",
        lambda *args, **kwargs: b"ambient",
    )
    assert snapshot._managed_evm_slither_runtime_entry(
        {}, project_root=None, controls=_controls()
    ) == b"ambient"
