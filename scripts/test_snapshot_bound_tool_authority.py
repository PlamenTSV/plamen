"""Adversarial tests for native snapshot-bound EVM tool execution."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import types
from typing import Iterator

import pytest

import snapshot_bound_tool_authority as LOCAL
import toolchain_control_authority as CONTROL


ROOT = Path(__file__).resolve().parents[1]
AUDIT_SNAPSHOT_SHA256 = "a" * 64
SOURCE_SCOPE_SHA256 = "b" * 64


@pytest.fixture
def tmp_path() -> Iterator[Path]:
    """Use an owned private root; retain it for post-test forensics."""

    parent = Path.home() / ".plamen-snapshot-bound-tool-test-private"
    parent.mkdir(mode=0o700, exist_ok=True)
    parent.chmod(0o700)
    path = Path(tempfile.mkdtemp(prefix="case-", dir=parent))
    path.chmod(0o700)
    yield path


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def _sha_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _controls() -> CONTROL.ToolchainControls:
    return CONTROL.load_toolchain_controls(
        ROOT / "verification_policy" / "toolchain_governance.v1.json"
    )


def _lineage(*, build_system: str = "foundry", **updates: object) -> bytes:
    dependency_schema = {
        "foundry": "plamen.foundry-dependency-materialization-native-result.v1",
        "hardhat": "plamen.js-dependency-materialization-receipt.v2",
        "unresolved": "plamen.no-dependency-materialization-native-result.v1",
    }[build_system]
    source = {
        "schema": "plamen.audit-source-snapshot-binding.v1",
        "snapshot_sha256": SOURCE_SCOPE_SHA256,
        "source_scope_sha256": SOURCE_SCOPE_SHA256,
    }
    projection = {
        "schema": "plamen.private-source-projection.v1",
        "lineage_id": "run-15",
        "source_snapshot_sha256": SOURCE_SCOPE_SHA256,
        "descriptor_sha256": "c" * 64,
        "tree_sha256": "d" * 64,
        "read_only": True,
    }
    dependencies = {
        "schema": "plamen.evm-dependency-materialization-native.v1",
        "lineage_id": "run-15",
        "build_system": build_system,
        "provider_receipt_schema": dependency_schema,
        "provider_receipt_sha256": "e" * 64,
        "closure_sha256": "f" * 64,
        "complete": True,
    }
    compiler = {
        "schema": "plamen.solc-materialization-native.v1",
        "lineage_id": "run-15",
        "provider_receipt_schema": "plamen.managed-evm-python-native-admission.v1",
        "provider_receipt_sha256": "1" * 64,
        "version": "0.8.26",
        "artifact_sha256": "2" * 64,
        "artifact_bytes": 123,
        "complete": True,
    }
    mount = {
        "schema": "plamen.guest-read-only-mount.v1",
        "lineage_id": "run-15",
        "mount_id": "project",
        "guest_path": "/workspace/project",
        "source_projection_sha256": projection["tree_sha256"],
        "read_only": True,
    }
    native_request = {
        "schema": LOCAL.NATIVE_MATERIALIZATION_REQUEST_SCHEMA,
        "lineage_id": "run-15",
        "build_system": build_system,
        "source_snapshot": source,
        "private_source_projection": projection,
        "dependencies": dependencies,
        "compiler": compiler,
        "guest_mount": mount,
    }
    value: dict[str, object] = {
        "schema": LOCAL.MATERIALIZATION_LINEAGE_SCHEMA,
        "lineage_id": "run-15",
        "build_system": build_system,
        "source_snapshot": source,
        "private_source_projection": projection,
        "dependencies": dependencies,
        "compiler": compiler,
        "guest_mount": mount,
        "native_materialization_terminal": {
            "schema": "plamen.native-materialization-terminal.v1",
            "lineage_id": "run-15",
            "request_sha256": _sha_bytes(_canonical(native_request)),
            "terminal_sha256": "3" * 64,
            "complete": True,
        },
    }
    value.update(updates)
    return _canonical(value)


def _executable(path: Path, raw: bytes = b"#!/bin/sh\nexit 0\n") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.parent.chmod(0o700)
    path.write_bytes(raw)
    path.chmod(0o700)
    return path.resolve(strict=True)


def _projection(tool_id: str, executable: Path) -> tuple[bytes, dict[str, object]]:
    controls = _controls()
    raw = executable.read_bytes()
    value = {
        "schema": "plamen.runtime-tool-identity.v2",
        "tool_id": tool_id,
        "identity_kind": "command",
        "command": [tool_id, "--version"],
        "resolved_executable": str(executable),
        "version": f"rc=0\n{tool_id} test-version",
        "executable_sha256": _sha_bytes(raw),
        "executable_bytes": len(raw),
        "expected_identity": {"version": "UNPINNED"},
        "observed_identity": {"resolved_executable": str(executable)},
        "identity_status": "EXTERNAL_MANAGER" if tool_id == "solc" else "DEBT",
        "deterministic_provider_authority": False,
        "toolchain_version_lock_sha256": controls.lock_sha256,
        "toolchain_governance_sha256": controls.governance_sha256,
    }
    encoded = _canonical(value)
    return encoded, {"sha256": _sha_bytes(encoded), "byte_count": len(encoded)}


def _roots(tmp_path: Path) -> tuple[Path, Path, Path]:
    roots = tuple(tmp_path / name for name in ("target", "scratch", "state"))
    for root in roots:
        root.mkdir(parents=True, mode=0o700)
        root.chmod(0o700)
    return roots


def _runtime_identity() -> dict[str, object]:
    return {
        "schema": "plamen.darwin-tool-runtime-identity.v1",
        "platform": "MACOS",
        "extension_path": "/private/native/_plamen_native_supervisor.so",
        "extension_sha256": "4" * 64,
        "extension_byte_count": 1,
        "native_deployment_receipt_sha256": "5" * 64,
        "runtime_closure_sha256": "6" * 64,
        "broker_peer_identity_sha256": "7" * 64,
    }


def _plan(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    tool_id: str = "forge",
    build_system: str = "foundry",
    run_id: str = "run-15",
    audit_snapshot_sha256: str = AUDIT_SNAPSHOT_SHA256,
) -> tuple[LOCAL.SnapshotBoundToolExecutionPlan, tuple[Path, Path, Path]]:
    project, scratch, state = _roots(tmp_path)
    executable = _executable(tmp_path / "tools" / tool_id)
    projection, entry = _projection(tool_id, executable)
    lineage = _lineage(build_system=build_system)
    bridge = object()
    monkeypatch.setattr(LOCAL, "_native_bridge", lambda _initial: bridge)
    monkeypatch.setattr(
        LOCAL, "_extension_file_binding", lambda _bridge, _initial: _runtime_identity()
    )
    plan = LOCAL.build_snapshot_bound_tool_execution_plan(
        native_initial_authority=object(),
        run_id=run_id,
        audit_snapshot_sha256=audit_snapshot_sha256,
        tool_id=tool_id,
        projection_bytes=projection,
        snapshot_entry=entry,
        source_path=executable,
        project_root=project,
        materialization_lineage_bytes=lineage,
        materialization_lineage_entry={
            "sha256": _sha_bytes(lineage), "byte_count": len(lineage)
        },
        argv=[tool_id, "--version"],
        environment={"LANG": "C", "PATH": "/tool"},
        cwd="/workspace/project",
        scratch_root=scratch,
        state_root=state,
        source_scope_sha256=SOURCE_SCOPE_SHA256,
        controls=_controls(),
    )
    return plan, (project, scratch, state)


def _terminal(
    plan: LOCAL.SnapshotBoundToolExecutionPlan, **updates: object
) -> bytes:
    request = dict(plan.request)
    value: dict[str, object] = {
        "schema": LOCAL.TERMINAL_SCHEMA,
        "request_sha256": plan.request_sha256,
        "run_id": request["run_id"],
        "audit_snapshot_sha256": request["audit_snapshot_sha256"],
        "tool_id": plan.tool_id,
        "source_descriptor_sha256": request["source_descriptor"]["descriptor_sha256"],
        "materialization_lineage_sha256": request["materialization_lineage_sha256"],
        "toolchain_governance_sha256": request["toolchain_governance_sha256"],
        "toolchain_version_lock_sha256": request["toolchain_version_lock_sha256"],
        "native_runtime_identity_sha256": _sha_bytes(
            _canonical(request["native_runtime_identity"])
        ),
        "argv_sha256": _sha_bytes(_canonical(request["argv"])),
        "environment_sha256": _sha_bytes(_canonical(request["environment"])),
        "cwd_sha256": _sha_bytes(_canonical(request["cwd"])),
        "mounts_sha256": _sha_bytes(_canonical(request["mounts"])),
        "source_scope_sha256": request["source_scope_sha256"],
        "post_spawn_dynamic_identity_sha256": "8" * 64,
        "egress_policy": "DENY_ALL",
        "egress_denied": True,
        "exit_state": "COMPLETED",
        "returncode": 0,
        "duration_ms": 1,
        "peak_memory_bytes": 1,
        "stdout_sha256": _sha_bytes(b""),
        "stdout_observed_bytes": 0,
        "stdout_retained_bytes": 0,
        "stderr_sha256": _sha_bytes(b""),
        "stderr_observed_bytes": 0,
        "stderr_retained_bytes": 0,
        "output_tree_sha256": "9" * 64,
        "output_file_count": 0,
        "output_bytes": 0,
        "output_limit_exceeded": False,
        "population_zero": True,
        "cleanup_complete": True,
        "truncation_debt": None,
    }
    value.update(updates)
    return _canonical(value)


class _Lease:
    pass


class _Terminal:
    def __init__(self, raw: bytes) -> None:
        self.raw = raw


class _Custody:
    pass


class _Bridge(types.ModuleType):
    def __init__(self, terminal: bytes) -> None:
        super().__init__(LOCAL._BRIDGE_MODULE)
        self.terminal = terminal
        self.prepares = 0
        self.executes = 0
        self.DarwinToolExecutionLease = _Lease
        self.DarwinToolExecutionTerminal = _Terminal
        # Store stable callable objects, matching module-level C functions.
        self.prepare_darwin_tool_execution = self._prepare
        self.execute_darwin_tool = self._execute
        self.project_darwin_tool_execution_terminal = self._project

    def _prepare(self, *_args: object) -> _Lease:
        self.prepares += 1
        return _Lease()

    def _execute(self, *_args: object) -> _Terminal:
        self.executes += 1
        return _Terminal(self.terminal)

    def _project(self, terminal: _Terminal) -> bytes:
        return terminal.raw


def _execute(
    monkeypatch: pytest.MonkeyPatch,
    plan: LOCAL.SnapshotBoundToolExecutionPlan,
    roots: tuple[Path, Path, Path],
    terminal: bytes,
) -> tuple[LOCAL.SnapshotBoundToolExecutionEvidence, _Bridge]:
    bridge = _Bridge(terminal)
    monkeypatch.setattr(LOCAL, "_require_native_custody", lambda *_args: bridge)
    monkeypatch.setattr(LOCAL, "_native_bridge", lambda _initial: bridge)
    evidence = LOCAL.execute_snapshot_bound_tool(
        plan,
        native_initial_authority=object(),
        native_custody=_Custody(),
        project_root=roots[0],
        scratch_root=roots[1],
        state_root=roots[2],
    )
    return evidence, bridge


def test_native_bridge_contract_includes_the_custody_issuer() -> None:
    assert LOCAL._NATIVE_CALLABLE_NAMES == (
        "acquire_darwin_tool_custody",
        "prepare_darwin_tool_execution",
        "execute_darwin_tool",
        "project_darwin_tool_execution_terminal",
        "darwin_tool_runtime_identity",
    )


def test_non_native_platform_has_no_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(LOCAL, "_real_platform_id", lambda: "LINUX")
    assert LOCAL.native_tool_custody_status(object()) == {
        "platform": "LINUX",
        "state": "UNAVAILABLE",
        "reason": "LINUX_NATIVE_TOOL_CUSTODY_NOT_IMPLEMENTED",
    }
    with pytest.raises(LOCAL.NativeToolCustodyUnavailable):
        LOCAL.acquire_native_tool_custody(object())


def test_ordinary_python_module_cannot_forge_production_tool_bridge(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    called = False

    def forbidden(*_args: object) -> object:
        nonlocal called
        called = True
        raise AssertionError("unauthenticated Python hook was invoked")

    substitute = types.ModuleType(LOCAL._BRIDGE_MODULE)
    substitute.acquire_darwin_tool_custody = forbidden
    substitute.prepare_darwin_tool_execution = forbidden
    substitute.execute_darwin_tool = forbidden
    substitute.project_darwin_tool_execution_terminal = forbidden
    substitute.darwin_tool_runtime_identity = forbidden
    monkeypatch.setitem(sys.modules, LOCAL._BRIDGE_MODULE, substitute)
    monkeypatch.setattr(LOCAL, "_real_platform_id", lambda: "MACOS")

    with pytest.raises(
        LOCAL.NativeToolCustodyUnavailable,
        match="DARWIN_TOOL_CUSTODY_EXTENSION_UNAUTHENTICATED",
    ):
        LOCAL.acquire_native_tool_custody(object())
    assert called is False


def _suite_roots(tmp_path: Path) -> tuple[dict[str, Path], dict[str, Path]]:
    scratch: dict[str, Path] = {}
    state: dict[str, Path] = {}
    for tool_id in LOCAL._FOUNDRY_EVM_LANES:
        scratch[tool_id] = tmp_path / f"{tool_id}-scratch"
        state[tool_id] = tmp_path / f"{tool_id}-state"
        scratch[tool_id].mkdir(mode=0o700)
        state[tool_id].mkdir(mode=0o700)
    return scratch, state


def test_foundry_suite_validates_all_lineage_before_native_acquisition(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    project = tmp_path / "project"
    project.mkdir(mode=0o700)
    scratch, state = _suite_roots(tmp_path)
    plans = {
        tool_id: types.SimpleNamespace(tool_id=tool_id)
        for tool_id in LOCAL._FOUNDRY_EVM_LANES
    }
    requests = {
        tool_id: {
            "run_id": "run-15",
            "audit_snapshot_sha256": AUDIT_SNAPSHOT_SHA256,
            "source_scope_sha256": SOURCE_SCOPE_SHA256,
            "materialization_lineage_sha256": "c" * 64,
            "build_system": "foundry",
            "platform": "MACOS",
            "toolchain_governance_sha256": "e" * 64,
            "toolchain_version_lock_sha256": "f" * 64,
            "native_runtime_identity": _runtime_identity(),
            "tool_id": tool_id,
        }
        for tool_id in LOCAL._FOUNDRY_EVM_LANES
    }
    requests["solc"] = dict(requests["solc"])
    requests["solc"]["materialization_lineage_sha256"] = "d" * 64
    monkeypatch.setattr(
        LOCAL,
        "_validate_plan",
        lambda plan, **_kwargs: requests[plan.tool_id],
    )
    monkeypatch.setattr(
        LOCAL,
        "_native_bridge",
        lambda _authority: pytest.fail("native custody acquired before suite validation"),
    )

    with pytest.raises(
        LOCAL.SnapshotBoundToolAuthorityError,
        match="one snapshot lineage",
    ):
        LOCAL.execute_snapshot_bound_foundry_evm_suite(
            plans,
            native_initial_authority=object(),
            project_root=project,
            scratch_roots=scratch,
            state_roots=state,
        )


def test_foundry_suite_has_fixed_lane_order_and_one_native_custody(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    project = tmp_path / "project"
    project.mkdir(mode=0o700)
    scratch, state = _suite_roots(tmp_path)
    original_scratch = dict(scratch)
    original_state = dict(state)
    plans = {
        tool_id: types.SimpleNamespace(tool_id=tool_id)
        for tool_id in reversed(LOCAL._FOUNDRY_EVM_LANES)
    }
    requests = {
        tool_id: {
            "run_id": "run-15",
            "audit_snapshot_sha256": AUDIT_SNAPSHOT_SHA256,
            "source_scope_sha256": SOURCE_SCOPE_SHA256,
            "materialization_lineage_sha256": "c" * 64,
            "build_system": "foundry",
            "platform": "MACOS",
            "toolchain_governance_sha256": "e" * 64,
            "toolchain_version_lock_sha256": "f" * 64,
            "native_runtime_identity": _runtime_identity(),
            "tool_id": tool_id,
        }
        for tool_id in LOCAL._FOUNDRY_EVM_LANES
    }
    bridge = object()
    custody = object()
    acquired: list[object] = []
    executed: list[str] = []
    monkeypatch.setattr(
        LOCAL,
        "_validate_plan",
        lambda plan, **_kwargs: requests[plan.tool_id],
    )
    monkeypatch.setattr(LOCAL, "_native_bridge", lambda _authority: bridge)

    def acquire(authority: object) -> object:
        acquired.append(authority)
        scratch["solc"] = scratch["forge"]
        state["solc"] = state["forge"]
        return custody

    def execute(plan: object, **kwargs: object) -> str:
        assert kwargs["native_custody"] is custody
        assert kwargs["scratch_root"] == original_scratch[plan.tool_id]
        assert kwargs["state_root"] == original_state[plan.tool_id]
        executed.append(plan.tool_id)
        return f"native:{plan.tool_id}"

    monkeypatch.setattr(LOCAL, "acquire_native_tool_custody", acquire)
    monkeypatch.setattr(LOCAL, "execute_snapshot_bound_tool", execute)
    monkeypatch.setattr(
        LOCAL,
        "build_snapshot_bound_tool_evidence_bundle",
        lambda evidence, **kwargs: (tuple(evidence), kwargs["build_system"]),
    )
    initial = object()
    result = LOCAL.execute_snapshot_bound_foundry_evm_suite(
        plans,
        native_initial_authority=initial,
        project_root=project,
        scratch_roots=scratch,
        state_roots=state,
    )
    assert acquired == [initial]
    assert executed == list(LOCAL._FOUNDRY_EVM_LANES)
    assert result == (
        tuple(f"native:{tool_id}" for tool_id in LOCAL._FOUNDRY_EVM_LANES),
        "foundry",
    )


def test_lineage_rejects_mixed_build_materialization_and_stale_terminal() -> None:
    assert LOCAL.parse_materialization_lineage(_lineage())["build_system"] == "foundry"
    value = json.loads(_lineage())
    value["dependencies"]["provider_receipt_schema"] = (
        "plamen.js-dependency-materialization-native-result.v1"
    )
    with pytest.raises(LOCAL.SnapshotBoundToolAuthorityError, match="lineage differs"):
        LOCAL.parse_materialization_lineage(_canonical(value))

    value = json.loads(_lineage())
    value["compiler"]["artifact_sha256"] = "0" * 64
    with pytest.raises(LOCAL.SnapshotBoundToolAuthorityError, match="lineage differs"):
        LOCAL.parse_materialization_lineage(_canonical(value))


def test_plan_is_opaque_snapshot_and_run_bound(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    plan, _roots_value = _plan(monkeypatch, tmp_path)
    assert plan.request["run_id"] == "run-15"
    assert plan.request["audit_snapshot_sha256"] == AUDIT_SNAPSHOT_SHA256
    with pytest.raises(TypeError):
        LOCAL.SnapshotBoundToolExecutionPlan()
    forged = object.__new__(LOCAL.SnapshotBoundToolExecutionPlan)
    forged._tool_id = plan.tool_id
    forged._source_path = plan.source_path
    forged._source_is_directory = False
    forged._request_bytes = plan.request_bytes
    forged._request_sha256 = plan.request_sha256
    with pytest.raises(LOCAL.SnapshotBoundToolAuthorityError, match="not issued"):
        LOCAL._validate_plan(forged)


@pytest.mark.parametrize("tool_id", ["forge", "solc"])
def test_command_plan_seals_analysis_input_without_admitting_symlink_heavy_bin(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, tool_id: str,
) -> None:
    project, scratch, state = _roots(tmp_path)
    executable = _executable(tmp_path / "homebrew-bin" / tool_id)
    os.symlink(executable.name, executable.parent / f"{tool_id}-current")
    projection, entry = _projection(tool_id, executable)
    lineage = _lineage()
    monkeypatch.setattr(LOCAL, "_native_bridge", lambda _initial: object())
    monkeypatch.setattr(
        LOCAL, "_extension_file_binding", lambda *_args: _runtime_identity(),
    )

    # A Homebrew-style bin directory is not a valid recursively reviewed
    # analysis input merely because its selected executable is regular.
    with pytest.raises(
        LOCAL.SnapshotBoundToolAuthorityError,
        match="link or special member",
    ):
        descriptor, _binding = LOCAL._open_source(
            executable.parent, project_root=project, directory=True,
        )
        os.close(descriptor)

    plan = LOCAL.build_snapshot_bound_tool_execution_plan(
        native_initial_authority=object(),
        run_id="run-15",
        audit_snapshot_sha256=AUDIT_SNAPSHOT_SHA256,
        tool_id=tool_id,
        projection_bytes=projection,
        snapshot_entry=entry,
        source_path=executable,
        project_root=project,
        materialization_lineage_bytes=lineage,
        materialization_lineage_entry={
            "sha256": _sha_bytes(lineage), "byte_count": len(lineage),
        },
        argv=[tool_id, "--version"],
        environment={"LANG": "C"},
        cwd="/workspace/project",
        scratch_root=scratch,
        state_root=state,
        source_scope_sha256=SOURCE_SCOPE_SHA256,
        controls=_controls(),
    )
    request = plan.request
    sealed = Path(plan.source_path)
    assert sealed.parent.name == ".plamen-command-analysis-input-v1"
    assert sealed != executable.parent
    assert request["source_descriptor"]["kind"] == "directory"
    assert request["source_descriptor"]["tree_file_count"] == 1
    assert [row["mount_id"] for row in request["mounts"]] == [
        "analysis-input", "project", "scratch", "state",
    ]
    assert request["mounts"][0]["source_sha256"] == (
        request["source_descriptor"]["descriptor_sha256"]
    )
    assert (sealed / "source-binding.json").read_bytes() == _canonical({
        "audit_snapshot_sha256": AUDIT_SNAPSHOT_SHA256,
        "schema": "plamen.snapshot-tool-analysis-input.v1",
        "snapshot_projection_sha256": _sha_bytes(projection),
        "source_scope_sha256": SOURCE_SCOPE_SHA256,
        "tool_id": tool_id,
    })
    assert stat.S_IMODE(sealed.stat().st_mode) == 0o555
    assert stat.S_IMODE((sealed / "source-binding.json").stat().st_mode) == 0o444


def test_plan_binds_snapshot_and_rejects_mutation(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    other, _other_roots = _plan(
        monkeypatch,
        tmp_path / "wrong-snapshot",
        audit_snapshot_sha256="0" * 64,
    )
    assert other.request["audit_snapshot_sha256"] == "0" * 64
    plan, _roots_value = _plan(monkeypatch, tmp_path / "mutable")
    plan._request_bytes = plan.request_bytes + b" "
    with pytest.raises(LOCAL.SnapshotBoundToolAuthorityError, match="canonical"):
        LOCAL._validate_plan(plan)


def test_hardlinked_source_and_aliased_execution_roots_fail_closed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    project, scratch, _state = _roots(tmp_path)
    executable = _executable(tmp_path / "tools" / "forge")
    os.link(executable, executable.with_name("forge-alias"))
    with pytest.raises(LOCAL.SnapshotBoundToolAuthorityError, match="hardlink"):
        LOCAL._open_source(executable, project_root=project, directory=False)

    # A fresh single-link executable reaches the disjoint-root gate.
    executable = _executable(tmp_path / "tools2" / "forge")
    projection, entry = _projection("forge", executable)
    lineage = _lineage()
    monkeypatch.setattr(LOCAL, "_native_bridge", lambda _initial: object())
    monkeypatch.setattr(LOCAL, "_extension_file_binding", lambda *_args: _runtime_identity())
    with pytest.raises(LOCAL.SnapshotBoundToolAuthorityError, match="physical identity"):
        LOCAL.build_snapshot_bound_tool_execution_plan(
            native_initial_authority=object(), run_id="run-15",
            audit_snapshot_sha256=AUDIT_SNAPSHOT_SHA256, tool_id="forge",
            projection_bytes=projection, snapshot_entry=entry,
            source_path=executable, project_root=project,
            materialization_lineage_bytes=lineage,
            materialization_lineage_entry={
                "sha256": _sha_bytes(lineage), "byte_count": len(lineage)
            },
            argv=["forge", "--version"], environment={"LANG": "C"},
            cwd="/workspace/project", scratch_root=scratch,
            state_root=scratch, source_scope_sha256=SOURCE_SCOPE_SHA256,
            controls=_controls(),
        )


def test_distribution_budget_is_checked_before_file_hash(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    tree = tmp_path / "distribution"
    tree.mkdir(mode=0o700)
    (tree / "large.py").write_bytes(b"1234")
    (tree / "large.py").chmod(0o600)
    fd = os.open(tree, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    monkeypatch.setattr(LOCAL, "MAX_DISTRIBUTION_BYTES", 3)
    monkeypatch.setattr(
        LOCAL,
        "_descriptor_hash",
        lambda *_args: pytest.fail("oversized member was hashed before rejection"),
    )
    try:
        with pytest.raises(LOCAL.SnapshotBoundToolAuthorityError, match="file/byte bound"):
            LOCAL._tree_rows(fd)
    finally:
        os.close(fd)


def test_terminal_rejects_cross_run_and_false_truncation_claims(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    plan, _roots_value = _plan(monkeypatch, tmp_path)
    with pytest.raises(LOCAL.SnapshotBoundToolAuthorityError, match="another execution"):
        LOCAL._validate_terminal(_terminal(plan, run_id="run-14"), plan)
    with pytest.raises(LOCAL.SnapshotBoundToolAuthorityError, match="another execution"):
        LOCAL._validate_terminal(
            _terminal(plan, audit_snapshot_sha256="0" * 64), plan
        )
    with pytest.raises(LOCAL.SnapshotBoundToolAuthorityError, match="retained more"):
        LOCAL._validate_terminal(
            _terminal(plan, stdout_observed_bytes=1, stdout_retained_bytes=2), plan
        )
    with pytest.raises(LOCAL.SnapshotBoundToolAuthorityError, match="typed debt"):
        LOCAL._validate_terminal(
            _terminal(plan, stdout_observed_bytes=2, stdout_retained_bytes=1), plan
        )
    debt = {
        "schema": LOCAL.TRUNCATION_DEBT_SCHEMA,
        "streams": ["stdout"],
        "findings_complete": False,
        "can_certify_clean": False,
    }
    admitted = LOCAL._validate_terminal(
        _terminal(
            plan, exit_state="COMPLETED_WITH_TRUNCATION_DEBT",
            stdout_observed_bytes=2, stdout_retained_bytes=1,
            truncation_debt=debt,
        ),
        plan,
    )
    assert admitted["truncation_debt"] == debt


def test_execution_is_one_shot_and_evidence_is_immutable(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    plan, roots = _plan(monkeypatch, tmp_path)
    evidence, bridge = _execute(monkeypatch, plan, roots, _terminal(plan))
    assert bridge.prepares == bridge.executes == 1
    assert evidence.public_receipt()["can_certify_clean"] is False
    with pytest.raises(LOCAL.SnapshotBoundToolAuthorityError, match="already consumed"):
        LOCAL.execute_snapshot_bound_tool(
            plan,
            native_initial_authority=object(), native_custody=_Custody(),
            project_root=roots[0], scratch_root=roots[1], state_root=roots[2],
        )
    evidence._terminal_bytes = _canonical({"forged": True})
    with pytest.raises(LOCAL.SnapshotBoundToolAuthorityError, match="changed"):
        evidence.public_receipt()


def test_execution_rejects_plain_terminal_bytes_from_bridge(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    plan, roots = _plan(monkeypatch, tmp_path)
    bridge = _Bridge(_terminal(plan))
    bridge.execute_darwin_tool = lambda *_args: bridge.terminal
    monkeypatch.setattr(LOCAL, "_require_native_custody", lambda *_args: bridge)
    monkeypatch.setattr(LOCAL, "_native_bridge", lambda _initial: bridge)

    with pytest.raises(
        LOCAL.SnapshotBoundToolAuthorityError,
        match="wrong execution terminal type",
    ):
        LOCAL.execute_snapshot_bound_tool(
            plan,
            native_initial_authority=object(),
            native_custody=_Custody(),
            project_root=roots[0],
            scratch_root=roots[1],
            state_root=roots[2],
        )


def test_truncated_evidence_and_empty_bundle_never_claim_complete(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    plan, roots = _plan(monkeypatch, tmp_path)
    debt = {
        "schema": LOCAL.TRUNCATION_DEBT_SCHEMA,
        "streams": ["stdout"],
        "findings_complete": False,
        "can_certify_clean": False,
    }
    evidence, _bridge = _execute(
        monkeypatch, plan, roots,
        _terminal(
            plan, exit_state="COMPLETED_WITH_TRUNCATION_DEBT",
            stdout_observed_bytes=2, stdout_retained_bytes=1,
            truncation_debt=debt,
        ),
    )
    bundle = LOCAL.build_snapshot_bound_tool_evidence_bundle(
        [evidence], build_system="foundry"
    )
    assert bundle.public_receipt()["findings_complete"] is False
    empty = LOCAL.build_snapshot_bound_tool_evidence_bundle(
        [], build_system="foundry"
    )
    assert empty.public_receipt()["findings_complete"] is False


def test_bundle_rejects_caller_selected_build_system_and_mutation(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    plan, roots = _plan(monkeypatch, tmp_path, build_system="hardhat")
    evidence, _bridge = _execute(monkeypatch, plan, roots, _terminal(plan))
    with pytest.raises(LOCAL.SnapshotBoundToolAuthorityError, match="build system"):
        LOCAL.build_snapshot_bound_tool_evidence_bundle(
            [evidence], build_system="foundry"
        )
    bundle = LOCAL.build_snapshot_bound_tool_evidence_bundle(
        [evidence], build_system="hardhat"
    )
    bundle._receipt_bytes = _canonical({"forged": True})
    with pytest.raises(LOCAL.SnapshotBoundToolAuthorityError, match="changed"):
        bundle.public_receipt()
