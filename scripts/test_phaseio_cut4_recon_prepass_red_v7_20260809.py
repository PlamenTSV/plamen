"""V7 RED denominator for the live Cut-4 recon prepass boundary.

Unlike V1/V2, this module enters through the current production functions.  It
does not import a proposed application module, accept a status string as proof,
or replace any ArtifactLedger/transaction helper.  Provider execution may be
made unavailable, but the real prepass, driver startup, ledger reader, and
resume/degrade branch remain in the path.
"""
from __future__ import annotations

import copy
import ctypes
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import sys
from types import SimpleNamespace
from typing import Any, Mapping
import unicodedata

import pytest


SCRIPTS = Path(__file__).resolve().parent
ROOT = SCRIPTS.parent
sys.path.insert(0, str(SCRIPTS))
sys.path.insert(0, str(ROOT))

import artifact_ledger as AL  # noqa: E402
import plamen_driver as D  # noqa: E402
import recon_prepass as RP  # noqa: E402
import test_driver_smoke as DRIVER_SMOKE  # noqa: E402
from phase_io_contracts import (  # noqa: E402
    ArtifactSpec,
    LaunchSpec,
    PhaseIOContract,
    canonical_work_unit_key,
)


RUN_ID = "cut4-recon-v7"
V1_HASHES = {
    "test_phaseio_cut4_recon_prepass_red_20260730.py":
        "50be6f719bde3c0910b9766fdf682824d5a3d4d4ec26cec86cedc48c4a224f2a",
    "test_phaseio_cut4_recon_dependency_merge_red_20260730.py":
        "7abf2efb49123bdcf93732a909ccd0f98f9371688c4bee7a69a5675b970e1bb1",
}
V2_HASHES = {
    "test_phaseio_cut4_recon_prepass_red_v2_20260809.py":
        "103f4c38b3d2f293b70dee127ac81e3c1a0d5fb5f36927873ce2033fe3689f4a",
    "test_phaseio_cut4_recon_dependency_merge_red_v2_20260809.py":
        "0de4ff1d7492416035721ac629cd21258feb0d17987f6b6c7a9ebdf62bd3a57a",
}
V3_HASHES = {
    "test_phaseio_cut4_recon_prepass_red_v3_20260809.py":
        "95046fbd0bb7c05da23b1a668dd6c5baf7d44d9e00bad3bdc9177bc6eff74a77",
    "test_phaseio_cut4_recon_dependency_merge_red_v3_20260809.py":
        "7302948d5b2971fa6adbde3ecdc19acca7990baffeb955e07da2bb851d4fcf81",
}
V4_HASHES = {
    "test_phaseio_cut4_recon_prepass_red_v4_20260809.py":
        "2b94c241acec031177d9c341ab236a06810f9ce0933f6efb4f79c0b41f5baf90",
    "test_phaseio_cut4_recon_dependency_merge_red_v4_20260809.py":
        "427859af20cc0e6c7a1d3f056a5588947eea7ab294f3064b05fb0428e6d3b5a6",
}
V5_HASHES = {
    "test_phaseio_cut4_recon_prepass_red_v5_20260809.py":
        "b195d8862cd2b9197a0a25564fbc4acb747b548282b02fd23ad47d8a8741a026",
    "test_phaseio_cut4_recon_dependency_merge_red_v5_20260809.py":
        "e3d1c3353e2e28d217d5a0d762a98d758a6a0dfd6539935ac5bf763944b295bb",
}
V6_HASHES = {
    "test_phaseio_cut4_recon_prepass_red_v6_20260809.py":
        "ae9784df51fec245bf5cdf0c01b74b8660ae5622697bb008c1b4fb5f4087c58c",
    "test_phaseio_cut4_recon_dependency_merge_red_v6_20260809.py":
        "62828732e7e0bb36fa0ee7fb735c9e354452289a96a0b9c851747eba85e2ac50",
}

_REASON_CODE_RE = re.compile(r"^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)*$")
_PREPASS_REASON_CODES = frozenset({"PREPASS_INPUT_AUTHORITY_CHANGED"})
_DISPOSITION_LINKAGE = {
    "QUARANTINED": frozenset({("QUARANTINED", "OUTPUT_QUARANTINED")}),
    "DEBT": frozenset({("DEBT", "FAILED")}),
    "REJECTED": frozenset({
        ("REJECTED", "INPUT_REJECTED"),
        ("REJECTED", "PUBLICATION_REJECTED"),
    }),
    "FAILED": frozenset({("DEBT", "FAILED")}),
}

SC_PREPASS = (
    "contract_inventory.md",
    "state_variables.md",
    "function_list.md",
    "build_status.md",
    "design_context.md",
    "attack_surface.md",
    "detected_patterns.md",
    "template_recommendations.md",
    "recon_summary.md",
    "meta_buffer.md",
    "external_dependency_research.md",
)
L1_PREPASS = (
    "subsystem_map.md",
    "trust_boundaries.md",
    "attack_surface.md",
    "threat_model.md",
    "template_recommendations.md",
    "recon_summary.md",
    "meta_buffer.md",
    "external_dependency_research.md",
)


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _stable_digest(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _source_capture_digest(project: Path) -> str:
    source = project / "src"
    records = {
        path.relative_to(source).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(source.rglob("*"))
        if path.is_file()
    }
    return _stable_digest(records)


def _expected_attempt_binding(
    old_key: str,
    old: Mapping[str, Any],
    *,
    input_set_digest: str,
    config_digest: str,
    source_capture_digest: str,
) -> dict[str, Any]:
    old_commit = old.get("commit_authority")
    old_attempt = (
        old_commit.get("attempt_ordinal")
        if isinstance(old_commit, Mapping)
        else None
    )
    assert isinstance(old_attempt, int) and not isinstance(old_attempt, bool)
    attempt_ordinal = old_attempt + 1
    attempt_identity = f"{old_key}/attempt-{attempt_ordinal}"
    binding: dict[str, Any] = {
        "producer_attempt_identity": attempt_identity,
        "attempt_ordinal": attempt_ordinal,
        "input_set_digest": input_set_digest,
        "config_digest": config_digest,
        "source_capture_digest": source_capture_digest,
    }
    binding["attempted_authority_digest"] = _stable_digest(binding)
    return binding


def _observed_prepass_attempt_binding(
    project: Path,
    scratchpad: Path,
    config: Mapping[str, Any],
    old_key: str,
    old: Mapping[str, Any],
) -> dict[str, Any]:
    capture = RP._prepass_capture(scratchpad, project, config)
    source_digest = capture["source_capture_digest"]
    config_digest = _stable_digest(dict(config))
    unplanned = {
        path.name: hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(scratchpad.glob("recon_unplanned_semantic*.md"))
        if path.is_file()
    }
    input_digest = _stable_digest(
        {
            "source_capture_digest": source_digest,
            "source_root_authority": capture["source_root_authority"],
            "config_digest": config_digest,
            "unexpected_semantic_outputs": unplanned,
        }
    )
    return _expected_attempt_binding(
        old_key,
        old,
        input_set_digest=input_digest,
        config_digest=config_digest,
        source_capture_digest=source_digest,
    )


def _assert_root_reparse_public_boundary_rejected(
    project: Path,
    scratchpad: Path,
    config: Mapping[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = project / "src"
    metadata = source.lstat()
    assert stat.S_ISLNK(metadata.st_mode) or bool(
        int(getattr(metadata, "st_file_attributes", 0) or 0) & 0x400
    )

    with pytest.raises(
        RP.ReconPrepassAuthorityError,
        match="source root.*(?:link|reparse|unsafe)",
    ):
        RP._prepass_capture(scratchpad, project, config)

    calls: list[str] = []

    def bomb(name: str):
        def fail(*_args: Any, **_kwargs: Any) -> Any:
            calls.append(name)
            raise AssertionError(f"unsafe source root reached {name}")
        return fail

    monkeypatch.setattr(RP, "record_work_unit_inputs", bomb("ledger arm"))
    monkeypatch.setattr(RP, "_render_recon_prepass", bomb("renderer"))
    monkeypatch.setattr(RP.tempfile, "mkdtemp", bomb("stage"))
    monkeypatch.setattr(RP.os, "replace", bomb("public replace"))
    monkeypatch.setattr(RP, "record_work_unit_artifacts", bomb("commit"))
    with pytest.raises(
        RP.ReconPrepassAuthorityError,
        match="source root.*(?:link|reparse|unsafe)",
    ):
        RP.run_recon_prepass(dict(config))
    assert calls == []
    assert not any(str(key).endswith("/recon/prepass") for key in (
        AL.read_artifact_ledger(scratchpad).get("work_units") or {}
    ))


@pytest.mark.skipif(os.name != "nt", reason="real Windows reparse fixture")
def test_live_prepass_rejects_real_source_root_directory_symlink_before_arm(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _disable_external_providers(monkeypatch)
    project, scratchpad, config = _workspace(
        tmp_path, pipeline="sc", mode="core", route="codex"
    )
    source = project / "src"
    external = tmp_path / "external-symlink-target"
    external.mkdir()
    (external / "External.sol").write_text(
        "pragma solidity ^0.8.20; contract External {}\n", encoding="utf-8"
    )
    shutil.rmtree(source)
    source.symlink_to(external, target_is_directory=True)
    try:
        _assert_root_reparse_public_boundary_rejected(
            project, scratchpad, config, monkeypatch
        )
    finally:
        source.unlink()
    assert (external / "External.sol").is_file()


@pytest.mark.skipif(os.name != "nt", reason="real Windows reparse fixture")
def test_live_prepass_rejects_real_source_root_junction_before_arm(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _disable_external_providers(monkeypatch)
    project, scratchpad, config = _workspace(
        tmp_path, pipeline="sc", mode="core", route="codex"
    )
    source = project / "src"
    external = tmp_path / "external-junction-target"
    external.mkdir()
    (external / "External.sol").write_text(
        "pragma solidity ^0.8.20; contract External {}\n", encoding="utf-8"
    )
    shutil.rmtree(source)
    created = subprocess.run(
        ["cmd", "/d", "/c", "mklink", "/J", str(source), str(external)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert created.returncode == 0, created.stderr
    try:
        _assert_root_reparse_public_boundary_rejected(
            project, scratchpad, config, monkeypatch
        )
    finally:
        os.rmdir(source)
    assert (external / "External.sol").is_file()


def test_prepass_capture_signs_exact_source_root_status_and_physical_identity(
    tmp_path: Path,
) -> None:
    project, scratchpad, config = _workspace(
        tmp_path, pipeline="sc", mode="core", route="codex"
    )
    capture = RP._prepass_capture(scratchpad, project, config)
    authority = capture["source_root_authority"]
    observed = os.lstat(project)
    assert authority == {
        "schema": "plamen.recon-prepass-source-root.v1",
        "logical_identity": "project:root",
        "status": "PRESENT",
        "device": (
            int(observed.st_dev) & 0xFFFFFFFF
            if os.name == "nt"
            else int(observed.st_dev)
        ),
        "inode": int(observed.st_ino),
        "mode_type": stat.S_IFMT(observed.st_mode),
        "file_attributes": int(
            getattr(observed, "st_file_attributes", 0) or 0
        ),
        "reparse_tag": int(getattr(observed, "st_reparse_tag", 0) or 0),
    }
    assert capture["input_set_digest"] == _stable_digest({
        "source_capture_digest": capture["source_capture_digest"],
        "production_source_capture_digest": capture[
            "production_source_capture_digest"
        ],
        "source_root_authority": authority,
        "config_digest": capture["config_digest"],
        "snapshot_digest": capture["snapshot_digest"],
        "source_scope_digest": capture["source_scope_digest"],
        "source_path_authority": capture["source_path_authority"],
        "audit_config_authority": capture["audit_config_authority"],
        "unexpected_semantic_outputs": capture["unexpected_semantic_outputs"],
    })


def _native_root_information(
    *,
    volume: object = 7,
    high: object = 1,
    low: object = 9,
    attributes: object = 0x10,
) -> SimpleNamespace:
    return SimpleNamespace(
        dwVolumeSerialNumber=volume,
        nFileIndexHigh=high,
        nFileIndexLow=low,
        dwFileAttributes=attributes,
    )


def _signed_root_authority(
    *,
    device: object = 7,
    inode: object = (1 << 32) | 9,
    attributes: object = 0x10,
) -> dict[str, object]:
    return {
        "schema": "plamen.recon-prepass-source-root.v1",
        "logical_identity": "project:src",
        "status": "PRESENT",
        "device": device,
        "inode": inode,
        "mode_type": stat.S_IFDIR,
        "file_attributes": attributes,
        "reparse_tag": 0,
    }


def _valid_prepass_signed_authority(
    tmp_path: Path,
) -> tuple[dict[str, Any], Path]:
    project, scratchpad, config = _workspace(
        tmp_path, pipeline="sc", mode="core", route="codex"
    )
    pipeline, mode, ecosystem, backend = RP._prepass_dimensions(config)
    contract = RP.resolve_phase_io_contract(
        pipeline=pipeline,
        mode=mode,
        ecosystem=ecosystem,
        backend=backend,
        phase="recon",
        work_unit_id="prepass",
    )
    launch = RP.LaunchSpec(
        work_unit_key=contract.key,
        pipeline=contract.pipeline,
        mode=contract.mode,
        ecosystem=contract.ecosystem,
        backend=contract.backend,
        model="driver",
        timeout_s=RP._PREPASS_TIMEOUT_SECONDS,
        exec_mode="python",
        tool_policy=("filesystem",),
    )
    capture = RP._prepass_capture(scratchpad, project, config)
    return RP._prepass_preexecution_authority(
        contract, launch, run_id=RUN_ID, capture=capture
    ), scratchpad


def _resign_root_authority(
    authority: dict[str, Any],
    field: str,
    value: object,
) -> dict[str, Any]:
    changed = copy.deepcopy(authority)
    capture = changed["authority_capture"]
    capture["source_root_authority"][field] = value
    capture["input_set_digest"] = _stable_digest({
        "source_capture_digest": capture["source_capture_digest"],
        "production_source_capture_digest": capture[
            "production_source_capture_digest"
        ],
        "source_root_authority": capture["source_root_authority"],
        "config_digest": capture["config_digest"],
        "snapshot_digest": capture["snapshot_digest"],
        "source_scope_digest": capture["source_scope_digest"],
        "source_path_authority": capture["source_path_authority"],
        "audit_config_authority": capture["audit_config_authority"],
        "unexpected_semantic_outputs": capture[
            "unexpected_semantic_outputs"
        ],
    })
    unsigned = dict(changed)
    unsigned.pop("authority_sha256")
    changed["authority_sha256"] = _stable_digest(unsigned)
    return changed


def _install_persisted_authority_dominance_bombs(
    monkeypatch: pytest.MonkeyPatch,
) -> dict[str, int]:
    names = (
        "root_authority", "capture", "authority_pair", "contract",
        "generic_validate", "drift_debt", "arm", "renderer", "walk",
        "stage", "receipt", "replace", "commit",
    )
    calls = {name: 0 for name in names}

    def bomb(name: str):
        def fail(*_args: Any, **_kwargs: Any) -> Any:
            calls[name] += 1
            raise AssertionError(
                f"malformed persisted authority reached {name}"
            )
        return fail

    monkeypatch.setattr(RP, "_prepass_source_root_authority", bomb("root_authority"))
    monkeypatch.setattr(RP, "_prepass_capture", bomb("capture"))
    monkeypatch.setattr(RP, "_prepass_authority_pair", bomb("authority_pair"))
    monkeypatch.setattr(RP, "resolve_phase_io_contract", bomb("contract"))
    monkeypatch.setattr(RP, "validate_work_unit_inputs", bomb("generic_validate"))
    monkeypatch.setattr(RP, "_record_prepass_drift_debt", bomb("drift_debt"))
    monkeypatch.setattr(RP, "record_work_unit_inputs", bomb("arm"))
    monkeypatch.setattr(RP, "_render_recon_prepass", bomb("renderer"))
    monkeypatch.setattr(RP.os, "scandir", bomb("walk"))
    monkeypatch.setattr(RP.tempfile, "mkdtemp", bomb("stage"))
    monkeypatch.setattr(RP, "_prepass_receipt", bomb("receipt"))
    monkeypatch.setattr(RP.os, "replace", bomb("replace"))
    monkeypatch.setattr(RP, "record_work_unit_artifacts", bomb("commit"))
    return calls


_PERSISTED_ROOT_INVALID = (
    ("device", False), ("device", True), ("device", None),
    ("device", "1"), ("device", -1), ("device", 0),
    ("device", 2**32), ("device", 2**32 + 1),
    ("inode", False), ("inode", True), ("inode", None),
    ("inode", "1"), ("inode", -1), ("inode", 0),
    ("inode", 2**64), ("inode", 2**64 + 1),
    ("mode_type", False), ("mode_type", 0),
    ("mode_type", stat.S_IFREG), ("mode_type", stat.S_IFLNK),
    ("mode_type", stat.S_IFDIR + 1),
    ("file_attributes", False), ("file_attributes", None),
    ("file_attributes", "16"), ("file_attributes", -1),
    ("file_attributes", 2**32),
    ("file_attributes", 2**32 + 0x10),
    ("file_attributes", 0), ("file_attributes", 0x410),
    ("reparse_tag", False), ("reparse_tag", None),
    ("reparse_tag", "0"), ("reparse_tag", -1),
    ("reparse_tag", 1), ("reparse_tag", 0xA000000C),
    ("reparse_tag", 0xA0000003), ("reparse_tag", 2**32),
)


@pytest.mark.skipif(os.name != "nt", reason="Windows persisted root authority")
@pytest.mark.parametrize(("field", "value"), _PERSISTED_ROOT_INVALID)
def test_prepass_persisted_root_range_rejects_before_all_downstream_actions(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    field: str,
    value: object,
) -> None:
    authority, scratchpad = _valid_prepass_signed_authority(tmp_path)
    changed = _resign_root_authority(authority, field, value)
    ledger_path = scratchpad / "artifact-ledger.v1.json"
    before = ledger_path.read_bytes() if ledger_path.is_file() else None
    calls = _install_persisted_authority_dominance_bombs(monkeypatch)
    with pytest.raises(
        RP.ReconPrepassAuthorityError,
        match="present source-root authority is malformed",
    ):
        RP._validated_prepass_preexecution_authority(changed)
    after = ledger_path.read_bytes() if ledger_path.is_file() else None
    assert before == after
    assert calls == {name: 0 for name in calls}


@pytest.mark.skipif(os.name != "nt", reason="Windows persisted root authority")
@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("device", 1), ("device", 0xFFFFFFFF),
        ("inode", 1), ("inode", 0xFFFFFFFFFFFFFFFF),
        ("file_attributes", 0x10),
        ("file_attributes", 0xFFFFFBFF),
        ("reparse_tag", 0),
    ),
)
def test_prepass_persisted_root_range_accepts_exact_boundaries(
    tmp_path: Path,
    field: str,
    value: object,
) -> None:
    authority, _scratchpad = _valid_prepass_signed_authority(tmp_path)
    changed = _resign_root_authority(authority, field, value)
    assert RP._validated_prepass_preexecution_authority(changed) == changed


def _assert_named_persisted_root_counterexample_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    field: str,
    value: int,
) -> None:
    _disable_external_providers(monkeypatch)
    project, scratchpad, config = _workspace(
        tmp_path, pipeline="sc", mode="core", route="codex"
    )

    class InjectedCrash(RuntimeError):
        pass

    with pytest.raises(InjectedCrash, match="after_arm"):
        RP.run_recon_prepass(
            config,
            failure_injector=lambda point: (
                (_ for _ in ()).throw(InjectedCrash(point))
                if point == "after_arm"
                else None
            ),
        )
    ledger = AL.read_artifact_ledger(scratchpad)
    owner_key, owner = next(
        (key, row)
        for key, row in ledger["work_units"].items()
        if str(key).endswith("/recon/prepass")
        and isinstance(row, Mapping)
        and row.get("semantic_status") == "INPUTS_BOUND"
        and row.get("execution_state") == "INPUTS_BOUND_PREEXECUTION"
    )
    changed = _resign_root_authority(
        copy.deepcopy(owner["preexecution_authority"]), field, value
    )
    owner["preexecution_authority"] = changed
    owner["preexecution_authority_digest"] = changed["authority_sha256"]
    assert changed["work_unit_key"] == owner_key
    AL.write_artifact_ledger(scratchpad, ledger)

    def tree_snapshot(root: Path) -> tuple[tuple[str, str, int, str], ...]:
        rows: list[tuple[str, str, int, str]] = []
        for path in sorted(root.rglob("*")):
            relative = path.relative_to(root).as_posix()
            if path.is_dir():
                rows.append((relative, "dir", 0, ""))
            else:
                raw = path.read_bytes()
                rows.append((
                    relative, "file", len(raw), hashlib.sha256(raw).hexdigest()
                ))
        return tuple(rows)

    ledger_path = scratchpad / AL.LEDGER_NAME
    ledger_bytes = ledger_path.read_bytes()
    before = tree_snapshot(tmp_path)
    calls = {
        name: 0 for name in (
            "ledger_read", "outputs", "contract", "launch",
            "authority_pair", "capture", "root_authority", "project_is_dir",
            "walk", "generic_inputs", "generic_outputs", "drift_debt", "arm",
            "renderer", "stage", "receipt", "replace", "commit", "writer",
            "failure_injector",
        )
    }

    def bomb(name: str):
        def fail(*_args: Any, **_kwargs: Any) -> Any:
            calls[name] += 1
            raise AssertionError(
                f"malformed stored authority reached downstream {name}"
            )
        return fail

    original_read = RP.read_artifact_ledger
    original_is_dir = Path.is_dir
    original_scandir = RP.os.scandir

    def observed_read(root: Path) -> dict[str, Any]:
        calls["ledger_read"] += 1
        return original_read(root)

    def guarded_is_dir(path: Path) -> bool:
        if path == project:
            return bomb("project_is_dir")()
        return original_is_dir(path)

    def guarded_scandir(path: Any = ".") -> Any:
        if Path(path) == project / "src":
            return bomb("walk")()
        return original_scandir(path)

    monkeypatch.setattr(RP, "read_artifact_ledger", observed_read)
    monkeypatch.setattr(RP, "_prepass_output_names", bomb("outputs"))
    monkeypatch.setattr(RP, "resolve_phase_io_contract", bomb("contract"))
    monkeypatch.setattr(RP, "LaunchSpec", bomb("launch"))
    monkeypatch.setattr(RP, "_prepass_authority_pair", bomb("authority_pair"))
    monkeypatch.setattr(RP, "_prepass_capture", bomb("capture"))
    monkeypatch.setattr(
        RP, "_prepass_source_root_authority", bomb("root_authority")
    )
    monkeypatch.setattr(Path, "is_dir", guarded_is_dir)
    monkeypatch.setattr(RP.os, "scandir", guarded_scandir)
    monkeypatch.setattr(RP, "validate_work_unit_inputs", bomb("generic_inputs"))
    monkeypatch.setattr(
        RP, "validate_work_unit_artifacts", bomb("generic_outputs")
    )
    monkeypatch.setattr(RP, "_record_prepass_drift_debt", bomb("drift_debt"))
    monkeypatch.setattr(RP, "record_work_unit_inputs", bomb("arm"))
    monkeypatch.setattr(RP, "_render_recon_prepass", bomb("renderer"))
    monkeypatch.setattr(RP.tempfile, "mkdtemp", bomb("stage"))
    monkeypatch.setattr(RP, "_prepass_receipt", bomb("receipt"))
    monkeypatch.setattr(RP.os, "replace", bomb("replace"))
    monkeypatch.setattr(RP, "record_work_unit_artifacts", bomb("commit"))
    monkeypatch.setattr(RP, "write_artifact_ledger", bomb("writer"))

    with pytest.raises(
        RP.ReconPrepassAuthorityError,
        match="present source-root authority is malformed",
    ):
        RP.run_recon_prepass(
            config,
            failure_injector=bomb("failure_injector"),
        )
    monkeypatch.undo()

    assert ledger_path.read_bytes() == ledger_bytes
    assert tree_snapshot(tmp_path) == before
    assert AL.read_artifact_ledger(scratchpad)["work_units"][owner_key] == owner
    assert calls["ledger_read"] == 1
    assert calls == {
        **{name: 0 for name in calls},
        "ledger_read": 1,
    }


def test_prepass_persisted_root_rejects_self_consistent_zero_device(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    _assert_named_persisted_root_counterexample_rejected(
        tmp_path, monkeypatch, "device", 0
    )


def test_prepass_persisted_root_rejects_self_consistent_uint32_device_overflow(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    _assert_named_persisted_root_counterexample_rejected(
        tmp_path, monkeypatch, "device", 2**32
    )


def test_prepass_persisted_root_rejects_self_consistent_uint64_inode_overflow(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    _assert_named_persisted_root_counterexample_rejected(
        tmp_path, monkeypatch, "inode", 2**64
    )


def test_prepass_persisted_root_rejects_self_consistent_attribute_overflow(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    _assert_named_persisted_root_counterexample_rejected(
        tmp_path, monkeypatch, "file_attributes", 2**32 + 0x10
    )


@pytest.mark.parametrize(
    ("raw_device", "expected"),
    (
        (1, 1), (0xFFFFFFFF, 0xFFFFFFFF),
        (2**32 + 1, 1), (0xFFFFFFFFFFFFFFFF, 0xFFFFFFFF),
    ),
)
def test_prepass_windows_raw_device_canonicalizes_only_supported_uint64(
    raw_device: int,
    expected: int,
) -> None:
    assert RP._prepass_windows_canonical_device(raw_device) == expected


@pytest.mark.parametrize(
    "raw_device",
    (False, True, None, "1", -1, 0, 2**32, 2**64, 2**64 + 1),
)
def test_prepass_windows_raw_device_rejects_before_unsupported_width_mask(
    raw_device: object,
) -> None:
    with pytest.raises(RP.ReconPrepassAuthorityError):
        RP._prepass_windows_canonical_device(raw_device)


@pytest.mark.skipif(os.name != "nt", reason="Windows raw root metadata")
@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("st_dev", False), ("st_dev", -1), ("st_dev", 0),
        ("st_dev", "1"), ("st_dev", 2**32),
        ("st_dev", 2**64), ("st_dev", 2**64 + 1),
        ("st_ino", False), ("st_ino", 0), ("st_ino", -1),
        ("st_ino", 2**64),
        ("st_mode", False), ("st_mode", stat.S_IFREG | 0o644),
        ("st_file_attributes", False), ("st_file_attributes", -1),
        ("st_file_attributes", 2**32), ("st_file_attributes", 0),
        ("st_file_attributes", 0x410),
        ("st_reparse_tag", False), ("st_reparse_tag", -1),
        ("st_reparse_tag", 1), ("st_reparse_tag", 2**32),
    ),
)
def test_prepass_raw_root_metadata_rejects_before_native_or_downstream(
    monkeypatch: pytest.MonkeyPatch,
    field: str,
    value: object,
) -> None:
    row = {
        "st_dev": 1,
        "st_ino": 1,
        "st_mode": stat.S_IFDIR | 0o755,
        "st_file_attributes": 0x10,
        "st_reparse_tag": 0,
    }
    row[field] = value
    calls = {
        name: 0 for name in (
            "native", "walk", "arm", "renderer", "stage", "receipt",
            "replace", "commit",
        )
    }

    def bomb(name: str):
        def fail(*_args: Any, **_kwargs: Any) -> Any:
            calls[name] += 1
            raise AssertionError(f"malformed raw metadata reached {name}")
        return fail

    monkeypatch.setattr(RP.os, "lstat", lambda _path: SimpleNamespace(**row))
    monkeypatch.setattr(
        RP, "_prepass_windows_source_root_native_api", bomb("native")
    )
    monkeypatch.setattr(RP.os, "scandir", bomb("walk"))
    monkeypatch.setattr(RP, "record_work_unit_inputs", bomb("arm"))
    monkeypatch.setattr(RP, "_render_recon_prepass", bomb("renderer"))
    monkeypatch.setattr(RP.tempfile, "mkdtemp", bomb("stage"))
    monkeypatch.setattr(RP, "_prepass_receipt", bomb("receipt"))
    monkeypatch.setattr(RP.os, "replace", bomb("replace"))
    monkeypatch.setattr(RP, "record_work_unit_artifacts", bomb("commit"))
    with pytest.raises(RP.ReconPrepassAuthorityError):
        RP._prepass_source_root_authority(Path("opaque-src"))
    assert calls == {name: 0 for name in calls}


@pytest.mark.skipif(os.name != "nt", reason="Windows raw root metadata")
@pytest.mark.parametrize(
    ("raw_device", "inode", "expected_device"),
    (
        (1, 1, 1),
        (0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFF),
        (2**32 + 1, 1, 1),
        (0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFF),
    ),
)
def test_prepass_raw_root_metadata_accepts_exact_identity_boundaries(
    monkeypatch: pytest.MonkeyPatch,
    raw_device: int,
    inode: int,
    expected_device: int,
) -> None:
    monkeypatch.setattr(
        RP.os,
        "lstat",
        lambda _path: SimpleNamespace(
            st_dev=raw_device,
            st_ino=inode,
            st_mode=stat.S_IFDIR | 0o755,
            st_file_attributes=0x10,
            st_reparse_tag=0,
        ),
    )
    assert RP._prepass_source_root_authority(Path("opaque-src")) == {
        "schema": "plamen.recon-prepass-source-root.v1",
        "logical_identity": "project:src",
        "status": "PRESENT",
        "device": expected_device,
        "inode": inode,
        "mode_type": stat.S_IFDIR,
        "file_attributes": 0x10,
        "reparse_tag": 0,
    }


@pytest.mark.parametrize(
    ("information", "authority", "expected_index"),
    (
        (_native_root_information(volume=1, high=0, low=1),
         _signed_root_authority(device=1, inode=1), 1),
        (_native_root_information(
            volume=0xFFFFFFFF, high=0xFFFFFFFF, low=0xFFFFFFFF
         ), _signed_root_authority(
            device=0xFFFFFFFF, inode=0xFFFFFFFFFFFFFFFF
         ), 0xFFFFFFFFFFFFFFFF),
        (_native_root_information(high=1, low=0),
         _signed_root_authority(inode=0x0000000100000000),
         0x0000000100000000),
    ),
)
def test_prepass_native_root_identity_join_accepts_exact_unsigned_boundaries(
    information: SimpleNamespace,
    authority: Mapping[str, object],
    expected_index: int,
) -> None:
    joined = RP._prepass_validate_native_source_root_identity(
        information, authority
    )
    assert joined == {
        "volume_serial_number": authority["device"],
        "file_index": expected_index,
        "file_attributes": authority["file_attributes"],
    }


@pytest.mark.parametrize(
    ("information", "authority"),
    (
        (_native_root_information(volume=8), _signed_root_authority()),
        (_native_root_information(high=2), _signed_root_authority()),
        (_native_root_information(low=8), _signed_root_authority()),
        (_native_root_information(attributes=0x11), _signed_root_authority()),
        (_native_root_information(attributes=0),
         _signed_root_authority(attributes=0)),
        (_native_root_information(attributes=0x410),
         _signed_root_authority(attributes=0x410)),
        (_native_root_information(volume=0), _signed_root_authority(device=0)),
        (_native_root_information(high=0, low=0),
         _signed_root_authority(inode=0)),
        (_native_root_information(volume=True), _signed_root_authority()),
        (_native_root_information(high=True), _signed_root_authority()),
        (_native_root_information(low=True), _signed_root_authority()),
        (_native_root_information(attributes=True), _signed_root_authority()),
        (_native_root_information(volume=-1), _signed_root_authority()),
        (_native_root_information(high=-1), _signed_root_authority()),
        (_native_root_information(low=-1), _signed_root_authority()),
        (_native_root_information(attributes=-1), _signed_root_authority()),
        (_native_root_information(volume=0x100000000), _signed_root_authority()),
        (_native_root_information(high=0x100000000), _signed_root_authority()),
        (_native_root_information(low=0x100000000), _signed_root_authority()),
        (_native_root_information(attributes=0x100000000),
         _signed_root_authority()),
        (_native_root_information(volume="7"), _signed_root_authority()),
        (_native_root_information(high=1.0), _signed_root_authority()),
        (_native_root_information(low=None), _signed_root_authority()),
        (_native_root_information(attributes=b"16"), _signed_root_authority()),
        (_native_root_information(), _signed_root_authority(device=True)),
        (_native_root_information(), _signed_root_authority(device=-1)),
        (_native_root_information(),
         _signed_root_authority(device=0x100000000)),
        (_native_root_information(), _signed_root_authority(inode=True)),
        (_native_root_information(), _signed_root_authority(inode=-1)),
        (_native_root_information(),
         _signed_root_authority(inode=0x10000000000000000)),
        (_native_root_information(), _signed_root_authority(attributes=True)),
        (_native_root_information(),
         _signed_root_authority(attributes=0x100000000)),
        (_native_root_information(), {
            **_signed_root_authority(), "reparse_tag": 1,
        }),
        (_native_root_information(), {
            **_signed_root_authority(), "mode_type": stat.S_IFREG,
        }),
        (SimpleNamespace(
            nFileIndexHigh=1,
            nFileIndexLow=9,
            dwFileAttributes=0x10,
         ), _signed_root_authority()),
    ),
)
def test_prepass_native_root_identity_join_rejects_invalid_or_drifted_values(
    information: SimpleNamespace,
    authority: Mapping[str, object],
) -> None:
    with pytest.raises(
        RP.ReconPrepassAuthorityError,
        match="native physical identity mismatch",
    ):
        RP._prepass_validate_native_source_root_identity(
            information, authority
        )


def _real_native_root_information(path: Path) -> dict[str, int]:
    information_type, create, query, close = (
        RP._prepass_windows_source_root_native_api()
    )
    handle = create(str(path), 0x80, 0x1 | 0x2, None, 3, 0x02200000, None)
    assert handle not in (None, ctypes.c_void_p(-1).value)
    try:
        information = information_type()
        assert query(handle, ctypes.byref(information))
        return {
            "volume_serial_number": int(information.dwVolumeSerialNumber),
            "file_index": (
                int(information.nFileIndexHigh) << 32
            ) | int(information.nFileIndexLow),
            "file_attributes": int(information.dwFileAttributes),
        }
    finally:
        assert close(handle)


@pytest.mark.skipif(os.name != "nt", reason="native Windows handle authority")
@pytest.mark.parametrize(
    "mutation",
    ("volume", "high", "low", "attributes", "query"),
)
def test_prepass_native_root_guard_rejects_before_yield_and_closes_once(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    source = tmp_path / "src"
    source.mkdir()
    authority = RP._prepass_source_root_authority(source)
    native = _real_native_root_information(source)
    assert native == {
        "volume_serial_number": authority["device"],
        "file_index": authority["inode"],
        "file_attributes": authority["file_attributes"],
    }
    information_type, _create, _query, _close = (
        RP._prepass_windows_source_root_native_api()
    )
    calls = {"open": 0, "query": 0, "close": 0, "yield": 0}

    def create(*_args: Any) -> int:
        calls["open"] += 1
        return 41

    def query(_handle: object, pointer: object) -> bool:
        calls["query"] += 1
        if mutation == "query":
            return False
        information = pointer._obj
        information.dwVolumeSerialNumber = authority["device"]
        information.nFileIndexHigh = int(authority["inode"]) >> 32
        information.nFileIndexLow = int(authority["inode"]) & 0xFFFFFFFF
        information.dwFileAttributes = authority["file_attributes"]
        if mutation == "volume":
            information.dwVolumeSerialNumber = (
                int(authority["device"]) % 0xFFFFFFFF
            ) + 1
        elif mutation == "high":
            information.nFileIndexHigh ^= 1
        elif mutation == "low":
            information.nFileIndexLow ^= 1
        elif mutation == "attributes":
            information.dwFileAttributes ^= 1
        return True

    def close(_handle: object) -> bool:
        calls["close"] += 1
        return True

    monkeypatch.setattr(
        RP,
        "_prepass_windows_source_root_native_api",
        lambda: (information_type, create, query, close),
    )
    with pytest.raises(RP.ReconPrepassAuthorityError):
        with RP._prepass_source_root_guard(source, authority):
            calls["yield"] += 1
    assert calls == {"open": 1, "query": 1, "close": 1, "yield": 0}


@pytest.mark.skipif(os.name != "nt", reason="native Windows handle authority")
def test_prepass_native_root_guard_accepts_real_exact_volume_file_join(
    tmp_path: Path,
) -> None:
    source = tmp_path / "src"
    source.mkdir()
    authority = RP._prepass_source_root_authority(source)
    yielded = 0
    with RP._prepass_source_root_guard(source, authority):
        yielded += 1
    assert yielded == 1
    assert 0 < int(authority["device"]) <= 0xFFFFFFFF
    assert 0 < int(authority["inode"]) <= 0xFFFFFFFFFFFFFFFF


@pytest.mark.skipif(os.name != "nt", reason="native Windows handle authority")
def test_prepass_native_root_guard_rejects_real_replacement_before_yield(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "src"
    replacement = tmp_path / "replacement"
    retired = tmp_path / "retired"
    source.mkdir()
    replacement.mkdir()
    authority = RP._prepass_source_root_authority(source)
    original_native = _real_native_root_information(source)
    replacement_native = _real_native_root_information(replacement)
    assert original_native["volume_serial_number"] == replacement_native[
        "volume_serial_number"
    ]
    assert original_native["file_index"] != replacement_native["file_index"]
    real_api = RP._prepass_windows_source_root_native_api()
    information_type, real_create, real_query, real_close = real_api
    calls = {"open": 0, "query": 0, "close": 0, "yield": 0}

    def replace_then_open(*args: Any) -> object:
        calls["open"] += 1
        source.rename(retired)
        replacement.rename(source)
        return real_create(str(source), *args[1:])

    def query(handle: object, information: object) -> object:
        calls["query"] += 1
        return real_query(handle, information)

    def close(handle: object) -> object:
        calls["close"] += 1
        return real_close(handle)

    monkeypatch.setattr(
        RP,
        "_prepass_windows_source_root_native_api",
        lambda: (information_type, replace_then_open, query, close),
    )
    with pytest.raises(
        RP.ReconPrepassAuthorityError,
        match="native physical identity mismatch",
    ):
        with RP._prepass_source_root_guard(source, authority):
            calls["yield"] += 1
    assert calls == {"open": 1, "query": 1, "close": 1, "yield": 0}
    assert RP._prepass_source_root_authority(retired) == authority


@pytest.mark.skipif(os.name != "nt", reason="native Windows handle authority")
def test_prepass_native_root_guard_rejects_real_handle_after_swap_back(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "src"
    replacement = tmp_path / "replacement"
    retired = tmp_path / "retired"
    source.mkdir()
    replacement.mkdir()
    authority = RP._prepass_source_root_authority(source)
    original_native = _real_native_root_information(source)
    replacement_native = _real_native_root_information(replacement)
    assert original_native["volume_serial_number"] == replacement_native[
        "volume_serial_number"
    ]
    assert original_native["file_index"] != replacement_native["file_index"]
    information_type, real_create, real_query, real_close = (
        RP._prepass_windows_source_root_native_api()
    )
    calls = {"open": 0, "query": 0, "close": 0, "yield": 0}

    def swap_open_and_restore(*args: Any) -> object:
        calls["open"] += 1
        source.rename(retired)
        replacement.rename(source)
        forwarded = list(args)
        forwarded[2] = int(forwarded[2]) | 0x4  # FILE_SHARE_DELETE
        handle = real_create(*forwarded)
        source.rename(replacement)
        retired.rename(source)
        return handle

    def query(handle: object, information: object) -> object:
        calls["query"] += 1
        return real_query(handle, information)

    def close(handle: object) -> object:
        calls["close"] += 1
        return real_close(handle)

    monkeypatch.setattr(
        RP,
        "_prepass_windows_source_root_native_api",
        lambda: (information_type, swap_open_and_restore, query, close),
    )
    with pytest.raises(
        RP.ReconPrepassAuthorityError,
        match="native physical identity mismatch",
    ):
        with RP._prepass_source_root_guard(source, authority):
            calls["yield"] += 1
    assert calls == {"open": 1, "query": 1, "close": 1, "yield": 0}
    assert RP._prepass_source_root_authority(source) == authority


@pytest.mark.skipif(os.name != "nt", reason="native Windows volume capability")
def test_prepass_native_root_records_real_second_volume_capability(
    tmp_path: Path,
) -> None:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    get_drive_type = kernel32.GetDriveTypeW
    get_drive_type.argtypes = (ctypes.c_wchar_p,)
    get_drive_type.restype = ctypes.c_uint
    first = _real_native_root_information(tmp_path)
    different: list[dict[str, object]] = []
    for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
        root = Path(f"{letter}:\\")
        if get_drive_type(str(root)) != 3:  # DRIVE_FIXED
            continue
        probe = root / f"plamen-r127d-{os.getpid()}"
        try:
            probe.mkdir()
            observed = _real_native_root_information(probe)
        except (OSError, AssertionError):
            continue
        finally:
            try:
                probe.rmdir()
            except OSError:
                pass
        if observed["volume_serial_number"] != first["volume_serial_number"]:
            different.append({"root": str(root), "native": observed})
            break
    capability = (
        {"status": "SECOND_LOCAL_VOLUME_PRESENT", "evidence": different[0]}
        if different
        else {"status": "SECOND_LOCAL_VOLUME_ABSENT"}
    )
    print(json.dumps(capability, sort_keys=True))
    assert capability["status"] in {
        "SECOND_LOCAL_VOLUME_PRESENT", "SECOND_LOCAL_VOLUME_ABSENT"
    }


@pytest.mark.parametrize(
    ("mode", "attributes", "tag", "inode"),
    (
        (stat.S_IFLNK | 0o777, 0, 0, 7),
        (stat.S_IFDIR | 0o755, 0x400, 0xA000000C, 7),
        (stat.S_IFDIR | 0o755, 0x400, 0xA0000003, 7),
        (stat.S_IFDIR | 0o755, 0x400, 0x8000001D, 7),
        (stat.S_IFDIR | 0o755, 0, 0xA000000C, 7),
        (stat.S_IFREG | 0o644, 0, 0, 7),
        (stat.S_IFDIR | 0o755, 0, 0, 0),
    ),
)
def test_prepass_source_root_no_follow_metadata_fails_closed_without_fallback(
    monkeypatch: pytest.MonkeyPatch,
    mode: int,
    attributes: int,
    tag: int,
    inode: int,
) -> None:
    calls = {"lstat": 0, "scandir": 0}

    def fake_lstat(_path: Any) -> Any:
        calls["lstat"] += 1
        return SimpleNamespace(
            st_mode=mode,
            st_file_attributes=attributes,
            st_reparse_tag=tag,
            st_dev=3,
            st_ino=inode,
        )

    def traversal_bomb(*_args: Any, **_kwargs: Any) -> Any:
        calls["scandir"] += 1
        raise AssertionError("unsafe root reached traversal")

    monkeypatch.setattr(RP.os, "lstat", fake_lstat)
    monkeypatch.setattr(RP.os, "scandir", traversal_bomb)
    with pytest.raises(RP.ReconPrepassAuthorityError):
        RP._prepass_source_root_authority(Path("opaque-src"))
    assert calls == {"lstat": 1, "scandir": 0}


@pytest.mark.parametrize(
    "fault",
    (FileNotFoundError(), PermissionError("denied"), NotADirectoryError("parent")),
)
def test_prepass_source_root_inspection_has_one_attempt_and_no_fallback(
    monkeypatch: pytest.MonkeyPatch,
    fault: OSError,
) -> None:
    calls = {"lstat": 0, "scandir": 0}

    def failed_lstat(_path: Any) -> Any:
        calls["lstat"] += 1
        raise fault

    monkeypatch.setattr(RP.os, "lstat", failed_lstat)
    monkeypatch.setattr(
        RP.os,
        "scandir",
        lambda *_args, **_kwargs: calls.__setitem__("scandir", 1),
    )
    if isinstance(fault, FileNotFoundError):
        authority = RP._prepass_source_root_authority(Path("opaque-src"))
        assert authority["status"] == "ABSENT"
    else:
        with pytest.raises(RP.ReconPrepassAuthorityError):
            RP._prepass_source_root_authority(Path("opaque-src"))
    assert calls == {"lstat": 1, "scandir": 0}


@pytest.mark.parametrize("mutation_observation", (2, 3, 4, 5, 6))
def test_prepass_source_root_swap_back_is_rejected_at_every_capture_seam(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation_observation: int,
) -> None:
    project, scratchpad, config = _workspace(
        tmp_path, pipeline="sc", mode="core", route="codex"
    )
    # Prepass v7 binds the physical project root; production source identity
    # is supplied by the canonical snapshot/source-path authority.
    source = project
    real_lstat = RP.os.lstat
    approved = real_lstat(source)
    observations = 0

    def lstat_with_one_observation_swap(path: Any) -> Any:
        nonlocal observations
        observed = real_lstat(path)
        if Path(path) != source:
            return observed
        observations += 1
        if observations != mutation_observation:
            return observed
        return SimpleNamespace(
            st_mode=approved.st_mode,
            st_file_attributes=getattr(approved, "st_file_attributes", 0),
            st_reparse_tag=getattr(approved, "st_reparse_tag", 0),
            st_dev=approved.st_dev,
            st_ino=approved.st_ino + 1,
        )

    monkeypatch.setattr(RP.os, "lstat", lstat_with_one_observation_swap)
    with pytest.raises(
        RP.ReconPrepassAuthorityError, match="source root identity drift"
    ):
        RP._prepass_capture(scratchpad, project, config)
    assert observations >= mutation_observation


@pytest.mark.parametrize("mutation", ("replace", "remove"))
def test_live_prepass_source_root_drift_after_capture_never_reaches_arm(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    _disable_external_providers(monkeypatch)
    project, scratchpad, config = _workspace(
        tmp_path, pipeline="sc", mode="core", route="codex"
    )
    source = project / "src"
    retired = project / "retired-src"
    if mutation == "absent_to_present":
        shutil.rmtree(source)

    reached: list[str] = []

    def injector(point: str) -> None:
        if point != "after_capture":
            return
        if mutation == "replace":
            source.rename(retired)
            source.mkdir()
            (source / "Replacement.sol").write_text(
                "contract Replacement {}\n", encoding="utf-8"
            )
        elif mutation == "remove":
            source.rename(retired)
        else:
            source.mkdir()

    def bomb(name: str):
        def fail(*_args: Any, **_kwargs: Any) -> Any:
            reached.append(name)
            raise AssertionError(f"root drift reached {name}")
        return fail

    monkeypatch.setattr(RP, "record_work_unit_inputs", bomb("arm"))
    monkeypatch.setattr(RP, "_render_recon_prepass", bomb("render"))
    monkeypatch.setattr(RP.tempfile, "mkdtemp", bomb("stage"))
    with pytest.raises(
        RP.ReconPrepassAuthorityError, match="source root identity drift"
    ):
        RP.run_recon_prepass(dict(config), failure_injector=injector)
    assert reached == []
    assert not any(str(key).endswith("/recon/prepass") for key in (
        AL.read_artifact_ledger(scratchpad).get("work_units") or {}
    ))


@pytest.mark.skipif(os.name != "nt", reason="Windows handle sharing authority")
def test_prepass_capture_detects_real_root_replacement_during_enumeration(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project, scratchpad, config = _workspace(
        tmp_path, pipeline="sc", mode="core", route="codex"
    )
    source = project
    retired = tmp_path / "retired-project"
    real_scandir = RP._rooted_io.scandir
    replacement_attempted = False

    def adversarial_scandir(path: Any):
        nonlocal replacement_attempted
        if Path(path) == source and not replacement_attempted:
            replacement_attempted = True
            source.rename(retired)
            (source / "src").mkdir(parents=True)
            (source / "src" / "Replacement.sol").write_text(
                "contract Replacement {}\n", encoding="utf-8"
            )
        return real_scandir(path)

    monkeypatch.setattr(RP._rooted_io, "scandir", adversarial_scandir)
    with pytest.raises(
        RP.ReconPrepassAuthorityError, match="source root identity drift"
    ):
        RP._prepass_capture(scratchpad, project, config)
    assert replacement_attempted is True
    assert source.is_dir() and retired.is_dir()


def test_live_prepass_same_bytes_recreated_root_is_signed_identity_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _disable_external_providers(monkeypatch)
    project, scratchpad, config = _workspace(
        tmp_path, pipeline="sc", mode="core", route="codex"
    )

    class InjectedCrash(RuntimeError):
        pass

    with pytest.raises(InjectedCrash):
        RP.run_recon_prepass(
            config,
            failure_injector=lambda point: (
                (_ for _ in ()).throw(InjectedCrash(point))
                if point == "after_arm"
                else None
            ),
        )
    source = project / "src"
    original_raw = (source / "Protocol.sol").read_bytes()
    retired = project / "retired-src"
    source.rename(retired)
    source.mkdir()
    (source / "Protocol.sol").write_bytes(original_raw)

    result = RP.run_recon_prepass(config)
    assert result
    rows = AL.read_artifact_ledger(scratchpad)["work_units"]
    committed = [
        (str(key), row)
        for key, row in rows.items()
        if isinstance(row, Mapping)
        and "/recon/prepass.attempt-" in str(key)
        and row.get("semantic_status") == "ACTIVE"
        and row.get("execution_state") == "OUTPUT_COMMITTED"
    ]
    assert len(committed) == 1
    assert committed[0][0].endswith("/recon/prepass.attempt-0002")
def _workspace(
    tmp_path: Path,
    *,
    pipeline: str,
    mode: str,
    route: str,
) -> tuple[Path, Path, dict[str, Any]]:
    project = tmp_path / "project"
    scratchpad = project / ".scratchpad"
    source = project / "src"
    source.mkdir(parents=True)
    scratchpad.mkdir()
    if pipeline == "l1":
        (source / "node.rs").write_text(
            "pub fn process_block(height: u64) -> bool { height > 0 }\n",
            encoding="utf-8",
        )
        language = "rust"
    else:
        (source / "Protocol.sol").write_text(
            "// SPDX-License-Identifier: MIT\n"
            "pragma solidity ^0.8.20;\n"
            "contract Protocol { uint256 public value; "
            "function set(uint256 x) external { value = x; } }\n",
            encoding="utf-8",
        )
        language = "evm"
    backend = "codex" if route == "codex" else "claude"
    config = {
        "pipeline": pipeline,
        "mode": mode,
        "language": language,
        "cli_backend": backend,
        "project_root": str(project),
        "scratchpad": str(scratchpad),
        "_run_id": RUN_ID,
        "run_id": RUN_ID,
        "prepass_external_scanners": False,
    }
    return project, scratchpad, config


def _assert_nonempty(root: Path, names: tuple[str, ...]) -> None:
    missing = [name for name in names if not (root / name).is_file()]
    empty = [name for name in names if (root / name).is_file() and not (root / name).read_bytes()]
    assert not missing, f"real prepass omitted files: {missing}"
    assert not empty, f"real prepass emitted zero-byte files: {empty}"


def _disable_external_providers(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make only OS/provider execution unavailable; keep prepass logic real."""
    monkeypatch.setattr(RP.shutil, "which", lambda _name: None)
    monkeypatch.setattr(RP, "gate_supply_chain", lambda _root: None)
    monkeypatch.setattr(
        RP,
        "run_owned_process",
        lambda _args, **_kwargs: SimpleNamespace(
            returncode=127, stdout="", stderr="fixture unavailable"
        ),
    )


def _active_unit(root: Path, suffix: str) -> Mapping[str, Any]:
    ledger = AL.read_artifact_ledger(root)
    matches = [
        row for key, row in ledger.get("work_units", {}).items()
        if str(key).endswith(suffix)
        and isinstance(row, Mapping)
        and row.get("semantic_status") == "ACTIVE"
        and row.get("execution_state") == "OUTPUT_COMMITTED"
    ]
    assert len(matches) == 1, f"expected one committed unit *{suffix}, got {len(matches)}"
    return matches[0]


def _assert_committed_outputs(root: Path, unit: Mapping[str, Any], names: tuple[str, ...]) -> None:
    ledger = AL.read_artifact_ledger(root)
    identities = {f"scratchpad:{name}" for name in names}
    assert identities.issubset(set(unit.get("artifacts", {})))
    for identity in identities:
        row = ledger.get("artifact_bindings", {}).get(identity)
        assert isinstance(row, Mapping), f"missing committed binding {identity}"
        assert row.get("status") == "ACTIVE"
        assert row.get("owner_key") == unit.get("work_unit_key")
        record = unit["artifacts"][identity]
        assert int(record.get("size") or 0) > 0


def _publication_rows(ledger: Mapping[str, Any], suffix: str) -> dict[str, Mapping[str, Any]]:
    return {
        str(key): row
        for key, row in ledger.get("work_units", {}).items()
        if isinstance(row, Mapping)
        and (
            str(key).endswith(suffix)
            or f"{suffix}.attempt-" in str(key)
            or f"{suffix}/attempt-" in str(key)
        )
    }


def _valid_reason_codes(value: Any, allowed: frozenset[str]) -> bool:
    if type(value) not in {list, tuple} or not value:
        return False
    codes = tuple(value)
    if not all(type(code) is str for code in codes):
        return False
    return bool(
        len(codes) == len(set(codes))
        and all(
            code == code.strip()
            and code == unicodedata.normalize("NFC", code)
            and _REASON_CODE_RE.fullmatch(code) is not None
            and code in allowed
            for code in codes
        )
    )


def _registered_expected_output_denominator(
    old: Mapping[str, Any],
) -> tuple[Mapping[str, Any], ...]:
    """Replay the ordered, typed output denominator from the old contract."""
    manifest = old.get("contract_manifest")
    outputs = manifest.get("outputs") if isinstance(manifest, Mapping) else None
    old_artifacts = old.get("artifacts")
    if (
        not isinstance(manifest, Mapping)
        or type(outputs) is not list
        or not outputs
        or not isinstance(old_artifacts, Mapping)
        or manifest.get("key") != old.get("work_unit_key")
    ):
        return ()
    encoded = json.dumps(
        manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")
    if old.get("contract_digest") != hashlib.sha256(encoded).hexdigest():
        return ()

    required = {
        "artifact_class",
        "condition_id",
        "consumers",
        "identity",
        "minimum_gate",
        "owner_key",
        "schema_version",
        "write_mode",
        "writer",
    }
    optional = {"external_preimage_validator"}
    typed: list[Mapping[str, Any]] = []
    for value in outputs:
        if not isinstance(value, Mapping) or not (
            required <= set(value) <= required | optional
        ):
            return ()
        if not all(
            type(value.get(field)) is str
            for field in required - {"consumers"}
        ) or type(value.get("consumers")) is not list:
            return ()
        consumers = value["consumers"]
        if not all(type(consumer) is str for consumer in consumers):
            return ()
        identity = value["identity"]
        if (
            not identity.startswith("scratchpad:")
            or identity != identity.strip()
            or identity != unicodedata.normalize("NFC", identity)
            or value.get("owner_key") != manifest.get("key")
        ):
            return ()
        relative = identity.removeprefix("scratchpad:")
        pure = PurePosixPath(relative)
        if (
            not relative
            or pure.is_absolute()
            or str(pure) != relative
            or any(part in {"", ".", ".."} for part in pure.parts)
        ):
            return ()
        typed.append(value)

    identities = tuple(value["identity"] for value in typed)
    if (
        identities != tuple(sorted(identities))
        or len(identities) != len(set(identities))
        or len(identities) != len({identity.casefold() for identity in identities})
        or set(old_artifacts) != set(identities)
    ):
        return ()
    return tuple(typed)


def _owns_committed_expected_output(
    root: Path,
    after: Mapping[str, Any],
    old: Mapping[str, Any],
    row: Mapping[str, Any],
    authority: Mapping[str, Any],
    expected_attempt: Mapping[str, Any],
) -> bool:
    artifacts = row.get("artifacts")
    bindings = after.get("artifact_bindings")
    expected_records = authority.get("expected_output_records")
    recorded = authority.get("recorded_output_identities")
    denominator = _registered_expected_output_denominator(old)
    if (
        not denominator
        or not all(
            isinstance(value, Mapping)
            for value in (artifacts, bindings, expected_records)
        )
        or type(recorded) is not list
    ):
        return False
    expected_identities = tuple(spec["identity"] for spec in denominator)
    if (
        tuple(artifacts) != expected_identities
        or tuple(recorded) != expected_identities
        or tuple(expected_records) != expected_identities
    ):
        return False
    producer = expected_attempt["producer_attempt_identity"]
    attempt = expected_attempt["attempt_ordinal"]
    generation = expected_attempt["attempted_authority_digest"]
    lineage = {
        "producer_attempt_identity": producer,
        "attempt_ordinal": attempt,
        "generation_identity": generation,
    }
    descriptor_fields = (
        "artifact_class",
        "condition_id",
        "consumers",
        "minimum_gate",
        "schema_version",
        "write_mode",
        "writer",
    )
    for spec in denominator:
        identity = spec["identity"]
        record = artifacts.get(identity)
        binding = bindings.get(identity)
        expected = expected_records.get(identity)
        if not all(isinstance(value, Mapping) for value in (record, binding, expected)):
            return False
        relative = identity.removeprefix("scratchpad:")
        path = root / relative
        raw = path.read_bytes() if path.is_file() else b""
        digest = hashlib.sha256(raw).hexdigest() if raw else ""
        size = len(raw)
        if (
            raw
            and set(expected) == {"sha256", "size"}
            and expected.get("sha256") == digest
            and type(expected.get("size")) is int
            and expected.get("size") == size
            and record.get("identity") == identity
            and record.get("root") == "scratchpad"
            and record.get("path") == relative
            and record.get("owner_key") == producer
            and record.get("status") == "ACTIVE"
            and record.get("authority_level") == "ACTIVE_AUTHORITY"
            and record.get("sha256") == digest
            and type(record.get("size")) is int
            and record.get("size") == size
            and binding.get("identity") == identity
            and binding.get("root") == "scratchpad"
            and binding.get("path") == relative
            and binding.get("owner_key") == producer
            and binding.get("status") == "ACTIVE"
            and binding.get("authority_level") == "ACTIVE_AUTHORITY"
            and binding.get("sha256") == digest
            and type(binding.get("size")) is int
            and binding.get("size") == size
            and all(record.get(key) == value for key, value in lineage.items())
            and all(binding.get(key) == value for key, value in lineage.items())
            and all(record.get(key) == spec.get(key) for key in descriptor_fields)
            and all(binding.get(key) == spec.get(key) for key in descriptor_fields)
        ):
            continue
        return False
    return True


def _assert_changed_authority_transition(
    root: Path,
    before: Mapping[str, Any],
    after: Mapping[str, Any],
    *,
    suffix: str,
    mutation: str,
    expected_attempt: Mapping[str, Any],
) -> None:
    """Require exact attempt lineage plus committed or durable authority."""
    before_rows = _publication_rows(before, suffix)
    after_rows = _publication_rows(after, suffix)
    active_before = [
        (key, row) for key, row in before_rows.items()
        if row.get("semantic_status") == "ACTIVE"
        and row.get("execution_state") == "OUTPUT_COMMITTED"
    ]
    assert len(active_before) == 1, "mutation control lacks a genuine first commit"
    old_key, old = active_before[0]
    assert json.dumps(after, sort_keys=True) != json.dumps(before, sort_keys=True), (
        f"{mutation}: second call was a complete ledger no-op"
    )

    current_old = after_rows.get(old_key, {})
    invalidated = (
        current_old.get("semantic_status") != "ACTIVE"
        or current_old.get("execution_state") != "OUTPUT_COMMITTED"
    )
    assert invalidated, (
        f"{mutation}: first ACTIVE generation survived changed authority"
    )

    required = (
        "producer_attempt_identity",
        "attempt_ordinal",
        "input_set_digest",
        "config_digest",
        "source_capture_digest",
        "attempted_authority_digest",
    )
    expected_identity = str(expected_attempt.get("producer_attempt_identity") or "")
    assert expected_identity and all(expected_attempt.get(field) not in (None, "") for field in required)
    candidates = [
        row
        for key, row in after_rows.items()
        if key == expected_identity
        and row.get("work_unit_key") == expected_identity
        and all(row.get(field) == expected_attempt.get(field) for field in required)
    ]

    def _bound_disposition(row: Mapping[str, Any]) -> bool:
        disposition = row.get("durable_disposition")
        state = disposition.get("state") if isinstance(disposition, Mapping) else None
        linkage = (row.get("semantic_status"), row.get("execution_state"))
        return (
            isinstance(disposition, Mapping)
            and disposition.get("schema") == "plamen.recon-mutation-disposition.v1"
            and type(state) is str
            and state in _DISPOSITION_LINKAGE
            and linkage in _DISPOSITION_LINKAGE[state]
            and _valid_reason_codes(
                disposition.get("reason_codes"), _PREPASS_REASON_CODES
            )
            and all(disposition.get(field) == expected_attempt.get(field) for field in required)
        )

    def _registered_successor(row: Mapping[str, Any]) -> bool:
        authority = row.get("commit_authority")
        return (
            row.get("semantic_status") == "ACTIVE"
            and row.get("execution_state") == "OUTPUT_COMMITTED"
            and isinstance(authority, Mapping)
            and authority.get("schema") == "plamen.recon-mutation-authority.v1"
            and authority.get("state") == "ACTIVE"
            and authority.get("work_unit_key") == expected_identity
            and authority.get("reason_codes") == []
            and all(authority.get(field) == expected_attempt.get(field) for field in required)
            and row.get("generation_identity")
            == expected_attempt.get("attempted_authority_digest")
            and authority.get("generation_identity")
            == expected_attempt.get("attempted_authority_digest")
            and authority.get("authority_digest")
            == expected_attempt.get("attempted_authority_digest")
            and _owns_committed_expected_output(
                root, after, old, row, authority, expected_attempt
            )
        )

    assert any(_bound_disposition(row) or _registered_successor(row) for row in candidates), (
        f"{mutation}: no exact bound successor attempt with durable disposition "
        "or registered successor authority"
    )


def _commit_fixture_prepass(root: Path, project: Path) -> None:
    """Create the genuine first generation used only by false-green controls."""
    key = canonical_work_unit_key("sc", "core", "evm", "codex", "recon", "prepass")
    contract = PhaseIOContract(
        pipeline="sc",
        mode="core",
        ecosystem="evm",
        backend="codex",
        phase="recon",
        work_unit_id="prepass",
        outputs=tuple(
            ArtifactSpec(
                root="scratchpad",
                path=name,
                owner_key=key,
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                write_mode="CREATE",
                minimum_gate="V7_FALSE_GREEN_CONTROL",
            )
            for name in SC_PREPASS
        ),
        model_invoked=False,
    )
    launch = LaunchSpec(
        work_unit_key=key,
        pipeline="sc",
        mode="core",
        ecosystem="evm",
        backend="codex",
        model="driver",
        timeout_s=30,
        exec_mode="python",
        tool_policy=("filesystem",),
    )
    AL.record_work_unit_inputs(root, project, contract, launch, run_id=RUN_ID)
    for name in SC_PREPASS:
        (root / name).write_text(
            f"# {name}\n\nfirst committed V7 control generation\n" + "x" * 160 + "\n",
            encoding="utf-8",
        )
    AL.record_work_unit_artifacts(
        root, project, contract, launch, run_id=RUN_ID, actor="DRIVER"
    )
    _active_unit(root, "/recon/prepass")


def _registered_successor_from_committed_readback(
    root: Path,
    before: Mapping[str, Any],
    old_key: str,
    expected_attempt: Mapping[str, Any],
) -> tuple[dict[str, Any], tuple[str, ...]]:
    """Rebind the complete real contract denominator to the future attempt."""
    assert AL.read_artifact_ledger(root) == before
    old = before["work_units"][old_key]
    denominator = _registered_expected_output_denominator(old)
    assert denominator
    expected_identities = tuple(spec["identity"] for spec in denominator)

    producer = expected_attempt["producer_attempt_identity"]
    generation = expected_attempt["attempted_authority_digest"]
    lineage = {
        "producer_attempt_identity": producer,
        "attempt_ordinal": expected_attempt["attempt_ordinal"],
        "generation_identity": generation,
    }
    records: dict[str, dict[str, Any]] = {}
    successor_bindings: dict[str, dict[str, Any]] = {}
    expected_records: dict[str, dict[str, Any]] = {}
    for identity in expected_identities:
        source_record = old["artifacts"][identity]
        source_binding = before["artifact_bindings"][identity]
        raw = (root / identity.removeprefix("scratchpad:")).read_bytes()
        digest = hashlib.sha256(raw).hexdigest()
        assert raw and source_record.get("sha256") == digest
        assert source_binding.get("sha256") == digest
        records[identity] = {
            **copy.deepcopy(source_record),
            **lineage,
            "owner_key": producer,
            "status": "ACTIVE",
            "authority_level": "ACTIVE_AUTHORITY",
        }
        successor_bindings[identity] = {
            **copy.deepcopy(source_binding),
            **lineage,
            "owner_key": producer,
            "status": "ACTIVE",
            "authority_level": "ACTIVE_AUTHORITY",
        }
        expected_records[identity] = {"sha256": digest, "size": len(raw)}
    after = copy.deepcopy(before)
    after["work_units"][old_key]["semantic_status"] = "SUPERSEDED"
    after["work_units"][old_key]["execution_state"] = "FAILED"
    successor = {
        **expected_attempt,
        "generation_identity": generation,
        "work_unit_key": producer,
        "semantic_status": "ACTIVE",
        "execution_state": "OUTPUT_COMMITTED",
        "artifacts": records,
    }
    successor["commit_authority"] = {
        **expected_attempt,
        "schema": "plamen.recon-mutation-authority.v1",
        "state": "ACTIVE",
        "generation_identity": generation,
        "work_unit_key": producer,
        "authority_digest": generation,
        "reason_codes": [],
        "recorded_output_identities": list(expected_identities),
        "expected_output_records": expected_records,
    }
    after["work_units"][producer] = successor
    after["artifact_bindings"].update(successor_bindings)
    return after, expected_identities


def test_v1_v2_v3_v4_v5_v6_fixture_preimages_remain_byte_frozen() -> None:
    for name, expected in {
        **V1_HASHES,
        **V2_HASHES,
        **V3_HASHES,
        **V4_HASHES,
        **V5_HASHES,
        **V6_HASHES,
    }.items():
        path = SCRIPTS / name
        assert path.is_file(), name
        assert _sha(path) == expected


@pytest.mark.parametrize(
    ("pipeline", "mode", "route"),
    (
        ("sc", "light", "codex"),
        ("sc", "core", "claude-headless"),
        ("sc", "thorough", "pty"),
        ("l1", "light", "pty"),
        ("l1", "core", "codex"),
        ("l1", "thorough", "claude-headless"),
    ),
)
def test_live_prepass_matrix_requires_one_committed_selected_publication(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    pipeline: str,
    mode: str,
    route: str,
) -> None:
    _disable_external_providers(monkeypatch)
    project, scratchpad, config = _workspace(
        tmp_path, pipeline=pipeline, mode=mode, route=route
    )

    # This is the current entry point.  Tool discovery/build failure is a real
    # provider outcome; it must not erase the deterministic prepass bytes.
    result = RP.run_recon_prepass(config)
    expected = L1_PREPASS if pipeline == "l1" else SC_PREPASS
    _assert_nonempty(scratchpad, expected)
    assert isinstance(result, dict) and result

    unit = _active_unit(scratchpad, "/recon/prepass")
    assert unit.get("run_id") == RUN_ID
    _assert_committed_outputs(scratchpad, unit, expected)


@pytest.mark.parametrize(
    "failpoint",
    (
        "after_capture",
        "after_arm",
        "after_stage",
        "after_publish",
        "before_commit",
    ),
)
def test_live_prepass_executes_named_crash_and_recovers_same_publisher(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failpoint: str,
) -> None:
    _disable_external_providers(monkeypatch)
    _project, scratchpad, config = _workspace(
        tmp_path, pipeline="sc", mode="thorough", route="codex"
    )
    before = {
        name: ((scratchpad / name).read_bytes() if (scratchpad / name).is_file() else None)
        for name in SC_PREPASS
    }
    hits: list[str] = []

    class InjectedCrash(RuntimeError):
        pass

    def injector(point: str, *_args: Any, **_kwargs: Any) -> None:
        hits.append(str(point))
        if str(point) == failpoint:
            raise InjectedCrash(failpoint)

    try:
        RP.run_recon_prepass(config, failure_injector=injector)
    except InjectedCrash:
        pass
    except TypeError as exc:
        pytest.fail(
            f"real run_recon_prepass cannot execute named injector {failpoint}: {exc}",
            pytrace=False,
        )
    assert failpoint in hits, f"publisher accepted but never executed {failpoint}"

    # Resume through the same current public entry, never a fixture journal.
    RP.run_recon_prepass(config)
    final = {
        name: ((scratchpad / name).read_bytes() if (scratchpad / name).is_file() else None)
        for name in SC_PREPASS
    }
    all_old = final == before
    all_new = all(isinstance(raw, bytes) and raw for raw in final.values())
    assert all_old or all_new, "crash recovery exposed a mixed semantic postimage"
    if all_new:
        unit = _active_unit(scratchpad, "/recon/prepass")
        _assert_committed_outputs(scratchpad, unit, SC_PREPASS)
    else:
        rows = _publication_rows(
            AL.read_artifact_ledger(scratchpad), "/recon/prepass"
        )
        assert any(
            row.get("semantic_status") in {"QUARANTINED", "DEBT", "REJECTED"}
            for row in rows.values()
        )


def test_live_prepass_rejects_mixed_public_generation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _disable_external_providers(monkeypatch)
    _project, scratchpad, config = _workspace(
        tmp_path, pipeline="sc", mode="core", route="codex"
    )
    real_replace = RP._prepass_durable_replace_from_stage
    published = {"count": 0}

    def fail_second_public_replace(
        source: Any, target: Any, **kwargs: Any
    ) -> None:
        if Path(target).parent == scratchpad:
            published["count"] += 1
            if published["count"] == 2:
                raise OSError("fixture mixed publication boundary")
        real_replace(source, target, **kwargs)

    monkeypatch.setattr(
        RP, "_prepass_durable_replace_from_stage", fail_second_public_replace
    )
    with pytest.raises(OSError, match="mixed publication boundary"):
        RP.run_recon_prepass(config)
    assert published["count"] == 2
    monkeypatch.setattr(RP, "_prepass_durable_replace_from_stage", real_replace)
    assert RP.run_recon_prepass(config)
    ledger = AL.read_artifact_ledger(scratchpad)
    assert any(
        (
            str(key).endswith("/recon/prepass")
            or "/recon/prepass.attempt-" in str(key)
        )
        and isinstance(row, Mapping)
        and row.get("semantic_status") == "ACTIVE"
        and row.get("execution_state") == "OUTPUT_COMMITTED"
        for key, row in ledger.get("work_units", {}).items()
    )


@pytest.mark.parametrize("failpoint", ("after_arm", "after_stage"))
@pytest.mark.parametrize(
    "mutation", ("source_edit", "unplanned_output")
)
def test_live_prepass_bound_resume_rejects_post_arm_authority_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failpoint: str,
    mutation: str,
) -> None:
    """The real durable arm, not a fixture journal, pins preexecution bytes."""

    _disable_external_providers(monkeypatch)
    project, scratchpad, config = _workspace(
        tmp_path, pipeline="sc", mode="core", route="codex"
    )

    class InjectedCrash(RuntimeError):
        pass

    def injector(point: str, *_args: Any, **_kwargs: Any) -> None:
        if point == failpoint:
            raise InjectedCrash(point)

    with pytest.raises(InjectedCrash, match=failpoint):
        RP.run_recon_prepass(config, failure_injector=injector)

    before = AL.read_artifact_ledger(scratchpad)
    owners = {
        str(key): row
        for key, row in before.get("work_units", {}).items()
        if str(key).endswith("/recon/prepass")
        and isinstance(row, Mapping)
        and row.get("semantic_status") == "INPUTS_BOUND"
        and row.get("execution_state") == "INPUTS_BOUND_PREEXECUTION"
    }
    assert len(owners) == 1
    old_key, armed = next(iter(owners.items()))
    authority = armed.get("preexecution_authority")
    assert isinstance(authority, Mapping), "durable arm omitted full authority"
    assert armed.get("preexecution_authority_digest") == authority.get(
        "authority_sha256"
    )
    assert authority.get("authority_capture") == RP._prepass_capture(
        scratchpad, project, config
    )
    armed_contract, _armed_launch = RP._prepass_authority_pair(authority)
    assert tuple(authority.get("planned_output_roster") or ()) == tuple(
        item.identity for item in armed_contract.outputs
    )

    if mutation == "source_edit":
        (project / "src" / "Protocol.sol").write_text(
            "pragma solidity ^0.8.20; contract PostArmChanged {}\n",
            encoding="utf-8",
        )
    elif mutation == "config_language":
        config["language"] = "solana"
    else:
        (scratchpad / "recon_unplanned_semantic_post_arm.md").write_text(
            "# post-arm semantic authority\n", encoding="utf-8"
        )

    result = RP.run_recon_prepass(config)
    assert result
    after = AL.read_artifact_ledger(scratchpad)
    rows = after.get("work_units", {})
    old = rows[old_key]
    assert old.get("semantic_status") in {"INVALID", "SUPERSEDED", "QUARANTINED"}
    assert old.get("execution_state") in {"FAILED", "SUPERSEDED", "QUARANTINED"}
    assert old.get("preexecution_authority") == authority
    assert old.get("preexecution_authority_digest") == authority.get(
        "authority_sha256"
    )
    proposed = [
        key
        for key, row in rows.items()
        if "/recon/prepass.attempt-" in str(key)
        and isinstance(row, Mapping)
        and row.get("semantic_status") == "ACTIVE"
        and row.get("execution_state") == "OUTPUT_COMMITTED"
    ]
    assert len(proposed) == 1
    assert str(proposed[0]).endswith("/recon/prepass.attempt-0002")
    attempts = [
        row
        for key, row in rows.items()
        if "/recon/prepass.disposition-" in str(key)
        and isinstance(row, Mapping)
    ]
    assert len(attempts) == 1
    disposition = attempts[0].get("durable_disposition")
    assert isinstance(disposition, Mapping)
    assert disposition.get("reason_codes") == [
        "PREPASS_INPUT_AUTHORITY_CHANGED"
    ]
    assert disposition.get("original_authority_digest") == authority.get(
        "authority_sha256"
    )
    assert disposition.get("attempted_authority_digest") != authority.get(
        "authority_sha256"
    )


@pytest.mark.parametrize("failpoint", ("after_publish", "before_commit"))
def test_live_prepass_published_generation_cannot_commit_after_authority_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failpoint: str,
) -> None:
    _disable_external_providers(monkeypatch)
    project, scratchpad, config = _workspace(
        tmp_path, pipeline="sc", mode="core", route="codex"
    )

    class InjectedCrash(RuntimeError):
        pass

    def injector(point: str, *_args: Any, **_kwargs: Any) -> None:
        if point == failpoint:
            raise InjectedCrash(point)

    with pytest.raises(InjectedCrash, match=failpoint):
        RP.run_recon_prepass(config, failure_injector=injector)
    (project / "src" / "Protocol.sol").write_text(
        "pragma solidity ^0.8.20; contract PostPublishChanged {}\n",
        encoding="utf-8",
    )

    assert RP.run_recon_prepass(config)
    ledger = AL.read_artifact_ledger(scratchpad)
    committed = [
        str(key)
        for key, row in ledger.get("work_units", {}).items()
        if "/recon/prepass.attempt-" in str(key)
        and isinstance(row, Mapping)
        and row.get("semantic_status") == "ACTIVE"
        and row.get("execution_state") == "OUTPUT_COMMITTED"
    ]
    assert len(committed) == 1
    assert committed[0].endswith("/recon/prepass.attempt-0002")


@pytest.mark.parametrize(
    "fault",
    (
        "missing_object",
        "extra_field",
        "reordered_roster",
        "wrong_schema",
        "wrong_row_digest",
        "cross_run",
        "duplicate_owner",
        "self_consistent_capture_tamper",
    ),
)
def test_live_prepass_bound_authority_tamper_fails_before_execution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    fault: str,
) -> None:
    _disable_external_providers(monkeypatch)
    _project, scratchpad, config = _workspace(
        tmp_path, pipeline="sc", mode="core", route="codex"
    )

    class InjectedCrash(RuntimeError):
        pass

    with pytest.raises(InjectedCrash):
        RP.run_recon_prepass(
            config,
            failure_injector=lambda point: (
                (_ for _ in ()).throw(InjectedCrash(point))
                if point == "after_arm"
                else None
            ),
        )
    ledger = AL.read_artifact_ledger(scratchpad)
    key, row = next(
        (key, row)
        for key, row in ledger["work_units"].items()
        if str(key).endswith("/recon/prepass")
    )
    authority = row["preexecution_authority"]
    if fault == "missing_object":
        row.pop("preexecution_authority")
    elif fault == "extra_field":
        authority["unexpected"] = True
    elif fault == "reordered_roster":
        authority["planned_output_roster"] = list(
            reversed(authority["planned_output_roster"])
        )
    elif fault == "wrong_schema":
        authority["schema"] = "plamen.recon-prepass-preexecution-authority.v0"
    elif fault == "wrong_row_digest":
        row["preexecution_authority_digest"] = "0" * 64
    elif fault == "cross_run":
        row["run_id"] = "foreign-run"
    elif fault == "duplicate_owner":
        duplicate = copy.deepcopy(row)
        ledger["work_units"][
            "sc/core/solana/codex/recon/prepass"
        ] = duplicate
    else:
        capture = authority["authority_capture"]
        capture["config_digest"] = "0" * 64
        capture["input_set_digest"] = _stable_digest({
            "source_capture_digest": capture["source_capture_digest"],
            "production_source_capture_digest": capture[
                "production_source_capture_digest"
            ],
            "source_root_authority": capture["source_root_authority"],
            "config_digest": capture["config_digest"],
            "snapshot_digest": capture["snapshot_digest"],
            "source_scope_digest": capture["source_scope_digest"],
            "source_path_authority": capture["source_path_authority"],
            "audit_config_authority": capture["audit_config_authority"],
            "unexpected_semantic_outputs": capture[
                "unexpected_semantic_outputs"
            ],
        })
        unsigned = dict(authority)
        unsigned.pop("authority_sha256")
        authority["authority_sha256"] = _stable_digest(unsigned)
        row["preexecution_authority_digest"] = authority[
            "authority_sha256"
        ]
    AL.write_artifact_ledger(scratchpad, ledger)

    if fault == "self_consistent_capture_tamper":
        assert RP.run_recon_prepass(config)
        ledger = AL.read_artifact_ledger(scratchpad)
        committed = [
            str(candidate_key)
            for candidate_key, candidate in ledger["work_units"].items()
            if "/recon/prepass.attempt-" in str(candidate_key)
            and isinstance(candidate, Mapping)
            and candidate.get("semantic_status") == "ACTIVE"
            and candidate.get("execution_state") == "OUTPUT_COMMITTED"
        ]
        assert committed == [
            "/".join((*str(key).split("/")[:5], "prepass.attempt-0002"))
        ]
    else:
        def bomb(*_args: Any, **_kwargs: Any) -> Any:
            raise AssertionError("tampered arm reached execution")

        monkeypatch.setattr(RP, "_render_recon_prepass", bomb)
        monkeypatch.setattr(RP.tempfile, "mkdtemp", bomb)
        monkeypatch.setattr(RP, "record_work_unit_artifacts", bomb)
        with pytest.raises(RP.ReconPrepassAuthorityError):
            RP.run_recon_prepass(config)


def test_live_prepass_rejects_incomplete_generic_arm_without_backfill(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _disable_external_providers(monkeypatch)
    project, scratchpad, config = _workspace(
        tmp_path, pipeline="sc", mode="core", route="codex"
    )
    pipeline, mode, ecosystem, backend = RP._prepass_dimensions(config)
    contract = RP.resolve_phase_io_contract(
        pipeline=pipeline,
        mode=mode,
        ecosystem=ecosystem,
        backend=backend,
        phase="recon",
        work_unit_id="prepass",
    )
    launch = RP.LaunchSpec(
        work_unit_key=contract.key,
        pipeline=contract.pipeline,
        mode=contract.mode,
        ecosystem=contract.ecosystem,
        backend=contract.backend,
        model="driver",
        timeout_s=RP._PREPASS_TIMEOUT_SECONDS,
        exec_mode="python",
        tool_policy=("filesystem",),
    )
    AL.record_work_unit_inputs(
        scratchpad, project, contract, launch, run_id=RUN_ID
    )
    capture = RP._prepass_capture(scratchpad, project, config)
    authority = RP._prepass_preexecution_authority(
        contract, launch, run_id=RUN_ID, capture=capture
    )
    assert AL.validate_work_unit_inputs(
        scratchpad,
        project,
        contract,
        launch,
        run_id=RUN_ID,
        preexecution_authority=authority,
    )

    def bomb(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("incomplete generic arm was backfilled or executed")

    monkeypatch.setattr(RP, "_render_recon_prepass", bomb)
    monkeypatch.setattr(RP.tempfile, "mkdtemp", bomb)
    with pytest.raises(
        RP.ReconPrepassAuthorityError,
        match="lacks a full authority object",
    ):
        RP.run_recon_prepass(config)
    row = AL.read_artifact_ledger(scratchpad)["work_units"][contract.key]
    assert "preexecution_authority" not in row
    assert "preexecution_authority_digest" not in row


@pytest.mark.parametrize("mutation", ("source_edit", "unexpected_output"))
def test_live_prepass_drift_never_rebinds_the_armed_generation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    _disable_external_providers(monkeypatch)
    project, scratchpad, config = _workspace(
        tmp_path, pipeline="sc", mode="core", route="codex"
    )
    RP.run_recon_prepass(config)
    _assert_nonempty(scratchpad, SC_PREPASS)
    first = {name: _sha(scratchpad / name) for name in SC_PREPASS}
    _active_unit(scratchpad, "/recon/prepass")
    before_ledger = AL.read_artifact_ledger(scratchpad)

    if mutation == "source_edit":
        (project / "src" / "Protocol.sol").write_text(
            "pragma solidity ^0.8.20; contract Changed { function x() external {} }\n",
            encoding="utf-8",
        )
    elif mutation == "config_edit":
        config["language"] = "solana"
    else:
        (scratchpad / "recon_unplanned_semantic.md").write_text(
            "# Unplanned\n\nnonempty semantic output\n", encoding="utf-8"
        )

    before_rows = _publication_rows(before_ledger, "/recon/prepass")
    old_key, _old = next(
        (key, row)
        for key, row in before_rows.items()
        if row.get("semantic_status") == "ACTIVE"
        and row.get("execution_state") == "OUTPUT_COMMITTED"
    )
    RP.run_recon_prepass(config)
    _assert_nonempty(scratchpad, SC_PREPASS)
    after_ledger = AL.read_artifact_ledger(scratchpad)
    old_after = after_ledger["work_units"][old_key]
    assert old_after.get("semantic_status") != "ACTIVE"
    committed = [
        (str(key), row)
        for key, row in after_ledger["work_units"].items()
        if "/recon/prepass.attempt-" in str(key)
        and isinstance(row, Mapping)
        and row.get("semantic_status") == "ACTIVE"
        and row.get("execution_state") == "OUTPUT_COMMITTED"
    ]
    assert len(committed) == 1
    successor_key, _successor = committed[0]
    assert successor_key.endswith("/recon/prepass.attempt-0002")
    dispositions = [
        row.get("durable_disposition")
        for key, row in after_ledger["work_units"].items()
        if "/recon/prepass.disposition-" in str(key)
        and isinstance(row, Mapping)
    ]
    assert len(dispositions) == 1
    assert dispositions[0].get("predecessor_work_unit_key") == old_key
    assert dispositions[0].get("generation_ordinal") == 2
    # The assertion is intentionally unconditional: unchanged bytes are not
    # permission to preserve the old generation after authority drift.
    assert first or after_ledger


@pytest.mark.parametrize("mutation", ("source_edit", "config_edit", "unexpected_output"))
def test_v6_rejects_v3_prepass_second_call_noop_counterexample(
    tmp_path: Path,
    mutation: str,
) -> None:
    project, scratchpad, config = _workspace(
        tmp_path, pipeline="sc", mode="core", route="codex"
    )
    _commit_fixture_prepass(scratchpad, project)
    before = AL.read_artifact_ledger(scratchpad)
    old_key, old = next(iter(_publication_rows(before, "/recon/prepass").items()))
    expected_attempt = _observed_prepass_attempt_binding(
        project, scratchpad, config, old_key, old
    )
    # Fileless mutation model: a broken second publisher returns without any
    # ledger write. V3 accepted this whenever public output hashes were stable.
    after = AL.read_artifact_ledger(scratchpad)
    with pytest.raises(AssertionError, match="complete ledger no-op"):
        _assert_changed_authority_transition(
            scratchpad,
            before,
            after,
            suffix="/recon/prepass",
            mutation=mutation,
            expected_attempt=expected_attempt,
        )


@pytest.mark.parametrize("transition", ("invalidated", "deleted"))
def test_v6_rejects_v4_prepass_invalidation_or_deletion_only_counterexample(
    tmp_path: Path,
    transition: str,
) -> None:
    project, scratchpad, config = _workspace(
        tmp_path, pipeline="sc", mode="core", route="codex"
    )
    _commit_fixture_prepass(scratchpad, project)
    before = AL.read_artifact_ledger(scratchpad)
    old_key, old = next(iter(_publication_rows(before, "/recon/prepass").items()))
    expected_attempt = _observed_prepass_attempt_binding(
        project, scratchpad, config, old_key, old
    )
    after = copy.deepcopy(before)
    if transition == "deleted":
        del after["work_units"][old_key]
    else:
        after["work_units"][old_key]["semantic_status"] = "INVALID"
        after["work_units"][old_key]["execution_state"] = "FAILED"

    with pytest.raises(AssertionError, match="no exact bound successor attempt"):
        _assert_changed_authority_transition(
            scratchpad,
            before,
            after,
            suffix="/recon/prepass",
            mutation="source_edit",
            expected_attempt=expected_attempt,
        )


def test_v7_accepts_complete_registered_prepass_successor_from_real_ledger(
    tmp_path: Path,
) -> None:
    project, scratchpad, config = _workspace(
        tmp_path, pipeline="sc", mode="core", route="codex"
    )
    _commit_fixture_prepass(scratchpad, project)
    before = AL.read_artifact_ledger(scratchpad)
    old_key, old = next(iter(_publication_rows(before, "/recon/prepass").items()))
    expected_attempt = _observed_prepass_attempt_binding(
        project, scratchpad, config, old_key, old
    )
    after, expected_identities = _registered_successor_from_committed_readback(
        scratchpad, before, old_key, expected_attempt
    )
    producer = expected_attempt["producer_attempt_identity"]
    denominator = _registered_expected_output_denominator(old)
    assert len(expected_identities) == len(denominator) > 1
    assert tuple(after["work_units"][producer]["artifacts"]) == expected_identities
    assert tuple(
        after["work_units"][producer]["commit_authority"][
            "recorded_output_identities"
        ]
    ) == expected_identities

    _assert_changed_authority_transition(
        scratchpad,
        before,
        after,
        suffix="/recon/prepass",
        mutation="source_edit",
        expected_attempt=expected_attempt,
    )


@pytest.mark.parametrize(
    "reason_codes",
    (
        [],
        [""],
        ["   "],
        [None],
        [7],
        [["PREPASS_INPUT_AUTHORITY_CHANGED"]],
        ["PREPASS_INPUT_AUTHORITY_CHANGED", "PREPASS_INPUT_AUTHORITY_CHANGED"],
        [" prepass_INPUT_AUTHORITY_CHANGED"],
        ["PREPASS-INPUT-AUTHORITY-CHANGED"],
        ["UNKNOWN_AUTHORITY_CHANGED"],
    ),
    ids=(
        "empty",
        "blank",
        "whitespace",
        "null",
        "number",
        "nested",
        "duplicate",
        "unnormalized",
        "malformed",
        "unknown",
    ),
)
def test_v6_rejects_malformed_prepass_durable_reason_denominator(
    tmp_path: Path,
    reason_codes: Any,
) -> None:
    project, scratchpad, config = _workspace(
        tmp_path, pipeline="sc", mode="core", route="codex"
    )
    _commit_fixture_prepass(scratchpad, project)
    before = AL.read_artifact_ledger(scratchpad)
    old_key, old = next(iter(_publication_rows(before, "/recon/prepass").items()))
    expected_attempt = _observed_prepass_attempt_binding(
        project, scratchpad, config, old_key, old
    )
    after = copy.deepcopy(before)
    after["work_units"][old_key]["semantic_status"] = "INVALID"
    after["work_units"][old_key]["execution_state"] = "FAILED"
    producer = expected_attempt["producer_attempt_identity"]
    after["work_units"][producer] = {
        **expected_attempt,
        "work_unit_key": producer,
        "semantic_status": "DEBT",
        "execution_state": "FAILED",
        "durable_disposition": {
            **expected_attempt,
            "schema": "plamen.recon-mutation-disposition.v1",
            "state": "FAILED",
            "reason_codes": reason_codes,
        },
    }
    with pytest.raises(AssertionError, match="no exact bound successor attempt"):
        _assert_changed_authority_transition(
            scratchpad,
            before,
            after,
            suffix="/recon/prepass",
            mutation="source_edit",
            expected_attempt=expected_attempt,
        )


@pytest.mark.parametrize(
    ("state", "semantic_status", "execution_state"),
    (
        ("FAILED", "QUARANTINED", "OUTPUT_QUARANTINED"),
        ("QUARANTINED", "DEBT", "FAILED"),
        ("REJECTED", "REJECTED", "FAILED"),
    ),
)
def test_v6_rejects_mismatched_prepass_typed_disposition_linkage(
    tmp_path: Path,
    state: str,
    semantic_status: str,
    execution_state: str,
) -> None:
    project, scratchpad, config = _workspace(
        tmp_path, pipeline="sc", mode="core", route="codex"
    )
    _commit_fixture_prepass(scratchpad, project)
    before = AL.read_artifact_ledger(scratchpad)
    old_key, old = next(iter(_publication_rows(before, "/recon/prepass").items()))
    expected_attempt = _observed_prepass_attempt_binding(
        project, scratchpad, config, old_key, old
    )
    after = copy.deepcopy(before)
    after["work_units"][old_key]["semantic_status"] = "INVALID"
    after["work_units"][old_key]["execution_state"] = "FAILED"
    producer = expected_attempt["producer_attempt_identity"]
    after["work_units"][producer] = {
        **expected_attempt,
        "work_unit_key": producer,
        "semantic_status": semantic_status,
        "execution_state": execution_state,
        "durable_disposition": {
            **expected_attempt,
            "schema": "plamen.recon-mutation-disposition.v1",
            "state": state,
            "reason_codes": ["PREPASS_INPUT_AUTHORITY_CHANGED"],
        },
    }
    with pytest.raises(AssertionError, match="no exact bound successor attempt"):
        _assert_changed_authority_transition(
            scratchpad,
            before,
            after,
            suffix="/recon/prepass",
            mutation="source_edit",
            expected_attempt=expected_attempt,
        )


@pytest.mark.parametrize(
    "reason_codes",
    (["PREPASS_INPUT_AUTHORITY_CHANGED"], ("PREPASS_INPUT_AUTHORITY_CHANGED",)),
    ids=("list", "tuple"),
)
def test_v6_accepts_exact_prepass_debt_failed_disposition_control(
    tmp_path: Path,
    reason_codes: list[str] | tuple[str, ...],
) -> None:
    project, scratchpad, config = _workspace(
        tmp_path, pipeline="sc", mode="core", route="codex"
    )
    _commit_fixture_prepass(scratchpad, project)
    before = AL.read_artifact_ledger(scratchpad)
    old_key, old = next(iter(_publication_rows(before, "/recon/prepass").items()))
    expected_attempt = _observed_prepass_attempt_binding(
        project, scratchpad, config, old_key, old
    )
    after = copy.deepcopy(before)
    after["work_units"][old_key]["semantic_status"] = "INVALID"
    after["work_units"][old_key]["execution_state"] = "FAILED"
    producer = expected_attempt["producer_attempt_identity"]
    after["work_units"][producer] = {
        **expected_attempt,
        "work_unit_key": producer,
        "semantic_status": "DEBT",
        "execution_state": "FAILED",
        "durable_disposition": {
            **expected_attempt,
            "schema": "plamen.recon-mutation-disposition.v1",
            "state": "FAILED",
            "reason_codes": reason_codes,
        },
    }
    _assert_changed_authority_transition(
        scratchpad,
        before,
        after,
        suffix="/recon/prepass",
        mutation="source_edit",
        expected_attempt=expected_attempt,
    )


@pytest.mark.parametrize(
    "fault",
    (
        "one_of_n",
        "n_minus_one",
        "n_plus_one",
        "duplicate",
        "alias",
        "wrong_identity",
        "wrong_order",
        "zero_artifacts",
        "zero_byte",
        "unrelated_owner",
        "wrong_attempt",
        "wrong_generation",
        "wrong_path",
        "bad_bytes",
    ),
)
def test_v7_rejects_incomplete_or_misbound_prepass_successor_denominator(
    tmp_path: Path,
    fault: str,
) -> None:
    project, scratchpad, config = _workspace(
        tmp_path, pipeline="sc", mode="core", route="codex"
    )
    _commit_fixture_prepass(scratchpad, project)
    before = AL.read_artifact_ledger(scratchpad)
    old_key, old = next(iter(_publication_rows(before, "/recon/prepass").items()))
    expected_attempt = _observed_prepass_attempt_binding(
        project, scratchpad, config, old_key, old
    )
    after, expected_identities = _registered_successor_from_committed_readback(
        scratchpad, before, old_key, expected_attempt
    )
    producer = expected_attempt["producer_attempt_identity"]
    successor = after["work_units"][producer]
    authority = successor["commit_authority"]
    first = expected_identities[0]
    last = expected_identities[-1]
    assert len(expected_identities) > 2

    def _retain(identities: tuple[str, ...]) -> None:
        successor["artifacts"] = {
            identity: successor["artifacts"][identity] for identity in identities
        }
        authority["recorded_output_identities"] = list(identities)
        authority["expected_output_records"] = {
            identity: authority["expected_output_records"][identity]
            for identity in identities
        }

    if fault == "one_of_n":
        _retain(expected_identities[:1])
    elif fault == "n_minus_one":
        _retain(expected_identities[:-1])
    elif fault == "n_plus_one":
        extra = "scratchpad:v7_unregistered_extra.md"
        raw = b"unregistered but otherwise byte-exact V7 output\n"
        (scratchpad / extra.removeprefix("scratchpad:")).write_bytes(raw)
        digest = hashlib.sha256(raw).hexdigest()
        successor["artifacts"][extra] = {
            **copy.deepcopy(successor["artifacts"][last]),
            "identity": extra,
            "path": extra.removeprefix("scratchpad:"),
            "sha256": digest,
            "size": len(raw),
        }
        after["artifact_bindings"][extra] = {
            **copy.deepcopy(after["artifact_bindings"][last]),
            "identity": extra,
            "path": extra.removeprefix("scratchpad:"),
            "sha256": digest,
            "size": len(raw),
        }
        authority["recorded_output_identities"].append(extra)
        authority["expected_output_records"][extra] = {
            "sha256": digest,
            "size": len(raw),
        }
    elif fault == "duplicate":
        authority["recorded_output_identities"].append(first)
    elif fault == "alias":
        alias = f"scratchpad:./{first.removeprefix('scratchpad:')}"
        successor["artifacts"] = {
            (alias if identity == first else identity): (
                {
                    **record,
                    "identity": alias,
                    "path": alias.removeprefix("scratchpad:"),
                }
                if identity == first else record
            )
            for identity, record in successor["artifacts"].items()
        }
        authority["recorded_output_identities"] = [
            alias if identity == first else identity
            for identity in authority["recorded_output_identities"]
        ]
        authority["expected_output_records"] = {
            (alias if identity == first else identity): record
            for identity, record in authority["expected_output_records"].items()
        }
        after["artifact_bindings"][alias] = {
            **after["artifact_bindings"].pop(first),
            "identity": alias,
            "path": alias.removeprefix("scratchpad:"),
        }
    elif fault == "wrong_identity":
        authority["recorded_output_identities"][0] = (
            "scratchpad:v7_wrong_identity.md"
        )
    elif fault == "wrong_order":
        reordered = (
            expected_identities[1], expected_identities[0], *expected_identities[2:]
        )
        successor["artifacts"] = {
            identity: successor["artifacts"][identity] for identity in reordered
        }
        authority["recorded_output_identities"] = list(reordered)
        authority["expected_output_records"] = {
            identity: authority["expected_output_records"][identity]
            for identity in reordered
        }
    if fault == "zero_artifacts":
        successor["artifacts"] = {}
    elif fault == "zero_byte":
        (scratchpad / first.removeprefix("scratchpad:")).write_bytes(b"")
    elif fault == "unrelated_owner":
        successor["artifacts"][first]["owner_key"] = old_key
        after["artifact_bindings"][first]["owner_key"] = old_key
    elif fault == "wrong_attempt":
        successor["artifacts"][first]["attempt_ordinal"] += 1
        after["artifact_bindings"][first]["attempt_ordinal"] += 1
    elif fault == "wrong_generation":
        successor["artifacts"][first]["generation_identity"] = "f" * 64
        after["artifact_bindings"][first]["generation_identity"] = "f" * 64
    elif fault == "wrong_path":
        successor["artifacts"][first]["path"] = "v7_wrong_path.md"
        after["artifact_bindings"][first]["path"] = "v7_wrong_path.md"
    elif fault == "bad_bytes":
        path = scratchpad / first.removeprefix("scratchpad:")
        path.write_bytes(path.read_bytes() + b"tampered-after-commit\n")
    with pytest.raises(AssertionError, match="no exact bound successor attempt"):
        _assert_changed_authority_transition(
            scratchpad,
            before,
            after,
            suffix="/recon/prepass",
            mutation="source_edit",
            expected_attempt=expected_attempt,
        )


def test_exact_prepass_noop_reuses_same_generation_without_semantic_write(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _disable_external_providers(monkeypatch)
    _project, scratchpad, config = _workspace(
        tmp_path, pipeline="sc", mode="core", route="codex"
    )
    RP.run_recon_prepass(config)
    unit_before = dict(_active_unit(scratchpad, "/recon/prepass"))
    files_before = {
        name: (_sha(scratchpad / name), (scratchpad / name).stat().st_mtime_ns)
        for name in SC_PREPASS
    }
    ledger_before = AL.read_artifact_ledger(scratchpad)
    RP.run_recon_prepass(config)
    unit_after = _active_unit(scratchpad, "/recon/prepass")
    files_after = {
        name: (_sha(scratchpad / name), (scratchpad / name).stat().st_mtime_ns)
        for name in SC_PREPASS
    }
    assert files_after == files_before, "exact retry performed a semantic write"
    assert unit_after.get("publication_generation") == unit_before.get("publication_generation")
    assert AL.read_artifact_ledger(scratchpad) == ledger_before


def _resume_shard(job: Mapping[str, str]) -> str:
    return (
        f"<!-- PLAMEN_ARTIFACT: {job['output']} -->\n"
        f"<!-- PLAMEN_OWNER: {job['agent_id']} -->\n"
        "<!-- PLAMEN_STATUS: IN_PROGRESS -->\n"
        "<!-- PLAMEN_PHASE: recon -->\n"
        "<!-- PLAMEN_VERSION: 1 -->\n"
        f"<!-- RECON_ROLE: {job['role']} -->\n"
        f"<!-- EXPECTED_OUTPUT: {job['output']} -->\n\n"
        f"# Resume worker {job['role']}\n\n"
        "## Evidence\n\nThe completed-recon resume branch replays this "
        "nonempty bounded shard without launching a provider. Source, state, "
        "entry-point, trust, build, and downstream implications are recorded.\n\n"
        "## Canonical Merge Hints\n\n- Preserve bounded evidence.\n\n"
        "<!-- PLAMEN_STATUS: COMPLETE -->\n"
    )


@pytest.mark.integration
@pytest.mark.parametrize("resume_branch", ("marker_strip", "shard_remerge"))
def test_real_second_driver_invocation_uses_completed_recon_resume_branch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    resume_branch: str,
) -> None:
    trace = tmp_path / f"resume_{resume_branch}.jsonl"
    old = '''_stub_mod = types.ModuleType("recon_prepass")\n_stub_mod.run_recon_prepass = lambda cfg: "stub-prepass"'''
    new = f'''import recon_prepass as _real_recon_prepass\n_real_run_recon_prepass = _real_recon_prepass.run_recon_prepass\ndef _observed_real_prepass(cfg):\n    result = _real_run_recon_prepass(cfg)\n    with Path(r"{trace}").open("a", encoding="utf-8") as fh:\n        fh.write(json.dumps({{"event": "prepass", "nonempty": bool(result)}}, sort_keys=True) + "\\n")\n    return result\n_real_recon_prepass.run_recon_prepass = _observed_real_prepass\n_stub_mod = _real_recon_prepass'''
    template = DRIVER_SMOKE.RUNNER_TEMPLATE.replace(old, new)
    template = template.replace('sys.modules["recon_prepass"] = _stub_mod', '')
    anchor = "import plamen_driver as pd\n"
    instrumentation = f'''import plamen_driver as pd\n_resume_trace = Path(r"{trace}")\ndef _record_resume_event(event, payload):\n    with _resume_trace.open("a", encoding="utf-8") as fh:\n        fh.write(json.dumps({{"event": event, "payload": payload}}, sort_keys=True, default=str) + "\\n")\ndef _is_completed_recon_resume(root):\n    checkpoint = Path(root) / "_v2_checkpoint.json"\n    if not checkpoint.is_file():\n        return False\n    try:\n        data = json.loads(checkpoint.read_text(encoding="utf-8"))\n    except Exception:\n        return False\n    return "recon" in set(data.get("completed") or [])\ndef _canonical_snapshot(root):\n    root = Path(root)\n    names = ("recon_summary.md", "design_context.md", "attack_surface.md", "state_variables.md", "function_list.md", "contract_inventory.md", "template_recommendations.md")\n    return {{\n        name: hashlib.sha256((root / name).read_bytes()).hexdigest()\n        for name in names\n        if (root / name).is_file()\n    }}\ndef _has_registered_resume_successor(root, suffix):\n    from artifact_ledger import read_artifact_ledger\n    rows = read_artifact_ledger(Path(root)).get("work_units", {{}})\n    return any(\n        str(key).endswith(suffix)\n        and isinstance(row, dict)\n        and row.get("semantic_status") == "ACTIVE"\n        and row.get("execution_state") == "OUTPUT_COMMITTED"\n        for key, row in rows.items()\n    )\n_real_strip_resume = pd.strip_codex_prepass_markers\ndef _observed_strip_resume(*args, **kwargs):\n    before = _canonical_snapshot(args[0])\n    result = _real_strip_resume(*args, **kwargs)\n    after = _canonical_snapshot(args[0])\n    changed = sorted(name for name in set(before) | set(after) if before.get(name) != after.get(name))\n    resumed = _is_completed_recon_resume(args[0])\n    _record_resume_event("marker_strip", {{"result": list(result or []), "completed_resume": resumed, "changed": changed}})\n    if resumed and not changed:\n        raise SystemExit(93)\n    if resumed and not _has_registered_resume_successor(args[0], "/recon/resume_marker_strip"):\n        raise SystemExit(91)\n    return result\npd.strip_codex_prepass_markers = _observed_strip_resume\n_real_merge_resume = pd._merge_recon_worker_shards\ndef _observed_merge_resume(*args, **kwargs):\n    before = _canonical_snapshot(args[0])\n    result = _real_merge_resume(*args, **kwargs)\n    after = _canonical_snapshot(args[0])\n    changed = sorted(name for name in set(before) | set(after) if before.get(name) != after.get(name))\n    resumed = _is_completed_recon_resume(args[0])\n    _record_resume_event("shard_remerge", {{"result": list(result or []), "completed_resume": resumed, "changed": changed}})\n    if resumed and not changed:\n        raise SystemExit(94)\n    if resumed and not _has_registered_resume_successor(args[0], "/recon/canonical_merge"):\n        raise SystemExit(92)\n    return result\npd._merge_recon_worker_shards = _observed_merge_resume\n'''
    instrumentation = instrumentation.replace(
        "if resumed and not changed:\n"
        "        raise SystemExit(93)\n"
        "    if resumed and not _has_registered_resume_successor("
        "args[0], \"/recon/resume_marker_strip\"):\n",
        "if resumed and result and not changed:\n"
        "        raise SystemExit(93)\n"
        "    if resumed and result and not _has_registered_resume_successor("
        "args[0], \"/recon/resume_marker_strip\"):\n",
    )
    template = template.replace(anchor, instrumentation, 1)
    monkeypatch.setattr(DRIVER_SMOKE, "RUNNER_TEMPLATE", template)

    run_root, _project, scratchpad, config_path, call_log = DRIVER_SMOKE._make_project(
        f"cut4_v6_resume_{resume_branch}_", mode="light", pipeline="sc",
        extra_config={
            "cli_backend": "codex",
            "_run_id": RUN_ID,
            "run_id": RUN_ID,
        },
    )
    try:
        first_rc = DRIVER_SMOKE._run_driver(run_root, config_path, call_log, "A")
        first_capture = capsys.readouterr()
        first_output = first_capture.out + first_capture.err
        assert first_rc == D.EXIT_DEGRADED, first_output
        assert (scratchpad / "_v2_checkpoint.json").is_file(), first_output
        checkpoint_before = json.loads(
            (scratchpad / "_v2_checkpoint.json").read_text(encoding="utf-8")
        )
        assert "recon" in checkpoint_before.get("completed", []), first_output
        assert checkpoint_before.get("run_id")
        calls_before = call_log.read_text(encoding="utf-8").splitlines()
        recon_calls_before = sum(
            line.startswith("recon:") for line in calls_before
        )
        assert recon_calls_before == 1

        design = scratchpad / "design_context.md"
        if resume_branch == "marker_strip":
            design.write_text(
                RP._PREPASS_MARKER + "\n" + design.read_text(encoding="utf-8"),
                encoding="utf-8",
            )
        else:
            # Add the remerge sources through the real MODEL preparation and
            # commit boundary.  Direct post-run file writes are intentionally
            # rejected by startup drift authority before resume dispatch.
            cfg = json.loads(config_path.read_text(encoding="utf-8"))
            cfg["_run_id"] = checkpoint_before["run_id"]
            cfg["run_id"] = checkpoint_before["run_id"]
            phase = next(row for row in D.SC_PHASES if row.name == "recon")
            for job in D._recon_worker_jobs(cfg):
                assert D._prepare_typed_model_worker_launch(
                    phase=phase,
                    config=cfg,
                    scratchpad=scratchpad,
                    project_root=str(_project),
                    agent_id=job["agent_id"],
                    output=job["output"],
                    timeout_s=30,
                ) == []
                (scratchpad / job["output"]).write_text(
                    _resume_shard(job), encoding="utf-8"
                )
                assert D._record_typed_model_worker_artifact(
                    phase=phase,
                    config=cfg,
                    scratchpad=scratchpad,
                    project_root=str(_project),
                    agent_id=job["agent_id"],
                    output=job["output"],
                    timeout_s=30,
                ) == []
                shard_unit = _active_unit(
                    scratchpad,
                    f"/recon/worker.{job['agent_id'].lower()}",
                )
                _assert_committed_outputs(
                    scratchpad, shard_unit, (job["output"],)
                )
            design.write_text(
                RP._PREPASS_MARKER
                + "\n# Design Context\n\n[LLM TO ENRICH] Pre-pass stub.\n",
                encoding="utf-8",
            )

        second_rc = DRIVER_SMOKE._run_driver(run_root, config_path, call_log, "A")
        captured = capsys.readouterr()
        # INFO-level startup branch evidence is intentionally written only to
        # the driver's durable file log; the smoke subprocess exposes WARNING+
        # on stderr.  Inspect both transports rather than requiring an INFO
        # message on the terminal transport.
        driver_log = scratchpad / "_plamen.log"
        second_output = captured.out + captured.err + (
            driver_log.read_text(encoding="utf-8", errors="replace")
            if driver_log.is_file()
            else ""
        )
        expected_missing_successor_rc = 91 if resume_branch == "marker_strip" else 92
        assert second_rc in {0, D.EXIT_DEGRADED, expected_missing_successor_rc}, (
            second_output
        )
        assert "[pre-pass] skipped because recon is already completed" in second_output
        checkpoint_after = json.loads(
            (scratchpad / "_v2_checkpoint.json").read_text(encoding="utf-8")
        )
        assert "recon" in checkpoint_after.get("completed", [])
        assert checkpoint_after.get("run_id") == checkpoint_before.get("run_id")
        calls_after = call_log.read_text(encoding="utf-8").splitlines()
        assert sum(line.startswith("recon:") for line in calls_after) == recon_calls_before

        events = [
            json.loads(line)
            for line in trace.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        assert sum(row.get("event") == "prepass" for row in events) == 1
        resumed_marker = next(
            (
                row for row in events
                if row.get("event") == "marker_strip"
                and (row.get("payload") or {}).get("completed_resume") is True
            ),
            None,
        )
        assert resumed_marker is not None
        if resume_branch == "shard_remerge":
            assert (resumed_marker.get("payload") or {}).get("result") == []
            assert (resumed_marker.get("payload") or {}).get("changed") == []
            assert any(
                row.get("event") == "shard_remerge"
                and (row.get("payload") or {}).get("completed_resume") is True
                and (row.get("payload") or {}).get("changed")
                for row in events
            )
            assert "re-merging recon worker shards" in second_output
            suffix = "/recon/canonical_merge"
        else:
            assert (resumed_marker.get("payload") or {}).get("changed")
            assert not any(
                row.get("event") == "shard_remerge"
                and (row.get("payload") or {}).get("completed_resume") is True
                for row in events
            )
            if second_rc != expected_missing_successor_rc:
                assert "stripped pre-pass marker" in second_output
            suffix = "/recon/resume_marker_strip"
        assert design.read_bytes()
        _active_unit(scratchpad, suffix)
    finally:
        shutil.rmtree(run_root, ignore_errors=True)


@pytest.mark.integration
def test_actual_phase_loop_marker_degrade_requires_canonical_transaction(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    trace = tmp_path / "phase_loop_marker_degrade.json"
    template = DRIVER_SMOKE.RUNNER_TEMPLATE
    anchor = "import plamen_driver as pd\n"
    instrumentation = f'''import plamen_driver as pd\n_marker_degrade_trace = Path(r"{trace}")\n_real_marker_strip = pd.strip_codex_prepass_markers\ndef _blocked_early_marker_strip(*_args, **_kwargs):\n    return []\npd.strip_codex_prepass_markers = _blocked_early_marker_strip\n_real_phase_loop_degrade = pd._try_recon_prepass_marker_degrade\ndef _degrade_snapshot(root):\n    root = Path(root)\n    names = ("recon_summary.md", "design_context.md", "attack_surface.md", "state_variables.md", "function_list.md", "contract_inventory.md", "template_recommendations.md")\n    return {{name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in names if (root / name).is_file()}}\ndef _has_degrade_successor(root):\n    from artifact_ledger import read_artifact_ledger\n    return any(\n        str(key).endswith("/recon/prepass_degrade")\n        and isinstance(row, dict)\n        and row.get("semantic_status") == "ACTIVE"\n        and row.get("execution_state") == "OUTPUT_COMMITTED"\n        for key, row in read_artifact_ledger(Path(root)).get("work_units", {{}}).items()\n    )\ndef _observed_phase_loop_degrade(root, config, missing):\n    before = _degrade_snapshot(root)\n    pd.strip_codex_prepass_markers = _real_marker_strip\n    try:\n        result = _real_phase_loop_degrade(root, config, missing)\n    finally:\n        pd.strip_codex_prepass_markers = _blocked_early_marker_strip\n    after = _degrade_snapshot(root)\n    changed = sorted(name for name in set(before) | set(after) if before.get(name) != after.get(name))\n    attempts = sum(line.startswith("recon:") for line in CALL_LOG.read_text(encoding="utf-8").splitlines())\n    marker_only = bool(missing) and all("pre-pass overwrite marker" in str(item) for item in missing)\n    payload = {{"degraded": bool(result[0]), "changed": changed, "attempts": attempts, "marker_only": marker_only}}\n    _marker_degrade_trace.write_text(json.dumps(payload, sort_keys=True) + "\\n", encoding="utf-8")\n    if result[0] and changed and attempts >= 2 and marker_only and not _has_degrade_successor(root):\n        raise SystemExit(95)\n    return result\npd._try_recon_prepass_marker_degrade = _observed_phase_loop_degrade\n'''
    template = template.replace(anchor, instrumentation, 1)
    assignment = "pd.run_phase = stub_run_phase"
    marker_writer = f'''_unmarked_stub_run_phase = stub_run_phase\ndef _marker_preserving_stub_run_phase(phase, config, attempt):\n    rc = _unmarked_stub_run_phase(phase, config, attempt)\n    if phase.name == "recon":\n        marker = {RP._PREPASS_MARKER!r}\n        for name in _RECON_ARTIFACTS:\n            path = Path(config["scratchpad"]) / name\n            if path.is_file():\n                body = path.read_text(encoding="utf-8")\n                if not body.startswith(marker):\n                    path.write_text(marker + "\\n" + body, encoding="utf-8")\n    return rc\npd.run_phase = _marker_preserving_stub_run_phase'''
    template = template.replace(assignment, marker_writer, 1)
    monkeypatch.setattr(DRIVER_SMOKE, "RUNNER_TEMPLATE", template)

    run_root, _project, scratchpad, config_path, call_log = DRIVER_SMOKE._make_project(
        "cut4_v6_phase_loop_degrade_",
        mode="light",
        pipeline="sc",
        extra_config={
            "cli_backend": "codex",
            "_run_id": RUN_ID,
            "run_id": RUN_ID,
        },
    )
    try:
        rc = DRIVER_SMOKE._run_driver(run_root, config_path, call_log, "A")
        captured = capsys.readouterr()
        output = captured.out + captured.err
        assert rc in {D.EXIT_DEGRADED, 95}, output
        assert trace.is_file(), (
            "real phase-loop degrade caller was not reached\n" + output
        )
        event = json.loads(trace.read_text(encoding="utf-8"))
        assert event == {
            "attempts": event["attempts"],
            "changed": event["changed"],
            "degraded": True,
            "marker_only": True,
        }
        assert event["attempts"] >= 2
        assert event["changed"]
        changed_names = tuple(str(name) for name in event["changed"])
        _assert_nonempty(scratchpad, changed_names)
        # RED target: the real phase-loop caller changed the canonical bytes,
        # but no exact DRIVER successor owns that promotion yet.
        unit = _active_unit(scratchpad, "/recon/prepass_degrade")
        _assert_committed_outputs(scratchpad, unit, changed_names)
    finally:
        shutil.rmtree(run_root, ignore_errors=True)


def test_zero_byte_output_cannot_be_clean_prepass_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _disable_external_providers(monkeypatch)
    _project, scratchpad, config = _workspace(
        tmp_path, pipeline="sc", mode="core", route="claude-headless"
    )
    RP.run_recon_prepass(config)
    _assert_nonempty(scratchpad, SC_PREPASS)
    (scratchpad / "function_list.md").write_bytes(b"")
    before = AL.read_artifact_ledger(scratchpad)

    # Re-enter the singular public boundary so it can validate the durable
    # output authority against the now-zero live byte stream.  Merely reading
    # a mutable ledger snapshot cannot itself observe a filesystem mutation.
    with pytest.raises(
        RP.ReconPrepassAuthorityError,
        match="committed output authority changed",
    ):
        RP.run_recon_prepass(config)
    assert AL.read_artifact_ledger(scratchpad) == before
    with pytest.raises(RP.ReconPrepassAuthorityError):
        RP.assert_recon_prepass_dispatch_authority(config)
