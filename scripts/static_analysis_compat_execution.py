"""Receipt-bound reduced-isolation execution for observational static tools.

This lane exists for supported POSIX compatibility audits where the native
guest/custody capability is unavailable.  It does not upgrade locally observed
tool content to authentic or clean-audit authority.  It does ensure that useful
Slither/OpenGrep evidence is produced against the exact immutable EVM workspace
denominator, through the same confined and receipt-producing process transport
used by mechanical PoC/fuzz execution.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
from typing import Any, Mapping, Sequence

import evm_analysis_workspace_authority as evm_workspace
import mechanical_prewarm as prewarm
import posix_v2_compat_runtime as compat
from supply_chain_gate import gate_supply_chain, project_supply_chain_admission


class StaticAnalysisCompatExecutionError(RuntimeError):
    pass


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _safe_path_members(
    *, executable: Path, requested: Sequence[str], project_root: Path
) -> list[str]:
    members: list[str] = []
    for raw in (os.fspath(executable.parent), *requested):
        try:
            directory, _identity = compat._safe_directory(
                raw, "compatibility static-analysis PATH member"
            )
        except Exception:
            continue
        if prewarm._within(directory, project_root):
            continue
        rendered = os.fspath(directory)
        if rendered not in members:
            members.append(rendered)
    if not members:
        raise StaticAnalysisCompatExecutionError(
            "no admitted static-analysis PATH member remains"
        )
    return members


def resolve_compat_foundry_solc(
    *, session_authority: object, build_root: Path,
) -> Path:
    """Resolve the exact native compiler selected by ``foundry.toml``.

    Compatibility execution replaces ``HOME`` so Forge cannot silently reuse
    an ambient SVM cache.  Resolve the explicitly selected compiler before
    launch, then let the caller bind it as an auxiliary executable and pass
    its absolute path through ``FOUNDRY_SOLC``.  The mechanical prewarm
    selector is reused so both compiler lanes enforce the same native-binary,
    non-target-controlled and exact-default-profile policy.
    """

    compat.require_posix_v2_compat_session(session_authority)
    session = compat._session_record(session_authority)
    source = Path(build_root).resolve(strict=True)
    project_root = Path(session.project_root).resolve(strict=True)
    scratchpad = Path(session.scratchpad).resolve(strict=True)
    if not prewarm._within(source, project_root) or prewarm._within(
        source, scratchpad
    ):
        raise StaticAnalysisCompatExecutionError(
            "Foundry build root is outside the compatibility project"
        )
    try:
        selection = prewarm._select_solc(source, "evm", session)
    except prewarm.CompatPrewarmError as exc:
        raise StaticAnalysisCompatExecutionError(
            f"Foundry compiler selection is unavailable: {exc}"
        ) from exc
    if selection is None:
        raise StaticAnalysisCompatExecutionError(
            "Foundry default profile has no explicit compiler selection"
        )
    return Path(str(selection["source_path"])).resolve(strict=True)


def execute_compat_static_analysis(
    *,
    session_authority: object,
    workspace_authority: Mapping[str, Any],
    stage: Path,
    tool_id: str,
    executable: Path,
    argv: Sequence[str],
    environment: Mapping[str, str],
    expected_outputs: Sequence[str],
    timeout_seconds: float,
    policy_inputs: Mapping[str, Any] | None = None,
    auxiliary_executables: Mapping[str, Path] | None = None,
) -> dict[str, Any]:
    """Execute one exact observational scanner command and return its receipt.

    The caller owns ``stage`` and may promote validated outputs afterward.  The
    stage must already be an otherwise disposable directory directly or
    transitively below the current audit scratchpad.
    """

    workspace = evm_workspace.replay_evm_analysis_workspace_execution_closure(
        workspace_authority
    )
    compat.require_posix_v2_compat_session(session_authority)
    session = compat._session_record(session_authority)
    build_root = Path(str(workspace["build_root"]["absolute_path"])).resolve(
        strict=True
    )
    project_root = Path(str(workspace["project_root"]["absolute_path"])).resolve(
        strict=True
    )
    scratchpad = Path(session.scratchpad).resolve(strict=True)
    if (
        workspace.get("run_id") != session.binding.get("run_id")
        or os.fspath(project_root) != session.binding.get("project_root")
        or os.fspath(scratchpad) != session.binding.get("scratchpad")
    ):
        raise StaticAnalysisCompatExecutionError(
            "static-analysis workspace belongs to another compatibility session"
        )

    stage = Path(stage).resolve(strict=True)
    if stage == scratchpad or not prewarm._within(stage, scratchpad):
        raise StaticAnalysisCompatExecutionError(
            "static-analysis stage is outside the audit scratchpad"
        )
    executable = Path(executable).resolve(strict=True)
    if prewarm._within(executable, project_root) or prewarm._within(
        executable, scratchpad
    ):
        raise StaticAnalysisCompatExecutionError(
            "static-analysis executable is target-controlled"
        )
    executable_binding = compat._poc_file_binding(
        executable,
        label="compatibility static-analysis executable",
        maximum=compat._POC_MAX_EXECUTABLE_BYTES,
    )
    command = [str(item) for item in argv]
    if not command:
        raise StaticAnalysisCompatExecutionError("static-analysis argv is empty")
    command[0] = os.fspath(executable)

    auxiliary_bindings: dict[str, dict[str, Any]] = {}
    for raw_name, raw_path in sorted((auxiliary_executables or {}).items()):
        name = str(raw_name)
        if (
            not name
            or not name.isascii()
            or not name.replace("_", "a").isalnum()
        ):
            raise StaticAnalysisCompatExecutionError(
                "static-analysis auxiliary executable name is malformed"
            )
        dependency = Path(raw_path).resolve(strict=True)
        if prewarm._within(dependency, project_root) or prewarm._within(
            dependency, scratchpad
        ):
            raise StaticAnalysisCompatExecutionError(
                "static-analysis auxiliary executable is target-controlled"
            )
        auxiliary_bindings[name] = {
            "path": os.fspath(dependency),
            "binding": compat._poc_file_binding(
                dependency,
                label=f"compatibility static-analysis auxiliary {name}",
                maximum=compat._POC_MAX_EXECUTABLE_BYTES,
            ),
        }

    output_names = sorted(str(item) for item in expected_outputs)
    if len(output_names) != len(set(output_names)):
        raise StaticAnalysisCompatExecutionError(
            "static-analysis output denominator is duplicated"
        )
    for relative in output_names:
        path = stage / relative
        if path.exists() or path.is_symlink():
            raise StaticAnalysisCompatExecutionError(
                f"static-analysis output exists before launch: {relative}"
            )

    home = stage / ".home"
    temporary = stage / ".tmp"
    cache = stage / ".cache"
    for directory in (home, temporary, cache):
        directory.mkdir(mode=0o700, exist_ok=False)

    requested_path = str(environment.get("PATH") or os.environ.get("PATH") or "")
    path_members = _safe_path_members(
        executable=executable,
        requested=tuple(item for item in requested_path.split(os.pathsep) if item),
        project_root=project_root,
    )
    closed_environment = {
        str(key): str(value) for key, value in environment.items()
        if str(key) not in {"PATH", "HOME", "TMP", "TEMP", "TMPDIR"}
    }
    closed_environment.update({
        "HOME": os.fspath(home),
        "LANG": str(environment.get("LANG") or "C"),
        "PATH": os.pathsep.join(path_members),
        "TEMP": os.fspath(temporary),
        "TMP": os.fspath(temporary),
        "TMPDIR": os.fspath(temporary),
        "XDG_CACHE_HOME": os.fspath(cache),
    })

    snapshot = workspace.get("snapshot")
    source = workspace.get("source_closure")
    if not isinstance(snapshot, Mapping) or not isinstance(source, Mapping):
        raise StaticAnalysisCompatExecutionError(
            "static-analysis workspace snapshot binding is malformed"
        )
    policy = {
        "schema": "plamen.compat-static-analysis-policy.v1",
        "tool_id": tool_id,
        "workspace_receipt_sha256": workspace["receipt_sha256"],
        "audit_snapshot_sha256": snapshot["snapshot_sha256"],
        "source_scope_sha256": source["snapshot_source_scope_sha256"],
        "dependency_closure_sha256": workspace["dependency_closure"][
            "closure_sha256"
        ],
        "executable": {
            "path": os.fspath(executable),
            "sha256": executable_binding["sha256"],
            "size": executable_binding["size"],
        },
        "auxiliary_executables": auxiliary_bindings,
        "argv": command,
        "environment": dict(sorted(closed_environment.items())),
        "expected_outputs": output_names,
        "policy_inputs": dict(policy_inputs or {}),
        "timeout_seconds": float(timeout_seconds),
        "authority_tier": "OBSERVATIONAL_REDUCED_ISOLATION",
        "can_certify_clean": False,
    }
    policy_raw = _canonical(policy)
    policy_sha256 = _sha(policy_raw)
    manifest = stage / "static-analysis-manifest.json"
    manifest.write_bytes(policy_raw)
    manifest_binding = compat._poc_file_binding(
        manifest,
        label="compatibility static-analysis manifest",
        maximum=compat._MAX_PHASE_IO_OUTPUT_BYTES,
    )

    admission_authority = gate_supply_chain(
        project_root, posix_compat_session=session_authority
    )
    admission = dict(project_supply_chain_admission(
        admission_authority, posix_compat_session=session_authority
    ))
    source_root, source_identity = compat._safe_directory(
        build_root, "compatibility static-analysis source root"
    )
    workspace_root, workspace_identity = compat._safe_directory(
        stage, "compatibility static-analysis workspace"
    )
    workspace_tree, _workspace_files, _workspace_bytes = compat._poc_tree_digest(
        workspace_root
    )
    work_authority = {
        "schema": "plamen.compat-static-analysis-work-authority.v1",
        "policy_sha256": policy_sha256,
        "workspace_pre_tree_sha256": workspace_tree,
        "workspace_receipt_sha256": workspace["receipt_sha256"],
    }
    request: dict[str, Any] = {
        "schema": compat.POC_REQUEST_SCHEMA,
        "request_sha256": "",
        "session_binding_sha256": session.binding["session_binding_sha256"],
        "run_id": session.binding["run_id"],
        "purpose": "STATIC_ANALYSIS",
        "work_unit_id": "static-" + policy_sha256[:48],
        "finding_id": None,
        "constituent_id": None,
        "attempt_number": 1,
        "work_authority_sha256": _sha(_canonical(work_authority)),
        "policy_sha256": policy_sha256,
        "verifier_receipt_sha256": None,
        "supply_chain_admission_sha256": admission["admission_sha256"],
        "audit_snapshot_sha256": snapshot["snapshot_sha256"],
        "source_census_sha256": source["snapshot_source_scope_sha256"],
        "source_build_root": os.fspath(source_root),
        "source_build_root_identity_sha256": prewarm._mapping_sha(source_identity),
        "workspace_root": os.fspath(workspace_root),
        "workspace_root_identity_sha256": prewarm._mapping_sha(workspace_identity),
        "workspace_pre_tree_sha256": workspace_tree,
        "subject_kind": "STATIC_ANALYSIS_MANIFEST",
        "subject_relative_path": manifest.relative_to(workspace_root).as_posix(),
        "subject_sha256": manifest_binding["sha256"],
        "subject_size": manifest_binding["size"],
        "test_function": None,
        "tool_id": tool_id,
        "executable_path": os.fspath(executable),
        "executable_sha256": executable_binding["sha256"],
        "executable_size": executable_binding["size"],
        "argv": command,
        "cwd_relative_path": ".",
        "environment": dict(sorted(closed_environment.items())),
        "timeout_seconds": float(timeout_seconds),
        "stdout_limit_bytes": min(4 * 1024 * 1024, compat._MAX_STDOUT_BYTES),
        "stderr_limit_bytes": min(4 * 1024 * 1024, compat._MAX_STDOUT_BYTES),
        "expected_outputs": output_names,
        "offline_intent": True,
    }
    unsigned = dict(request)
    unsigned.pop("request_sha256")
    request["request_sha256"] = prewarm._mapping_sha(unsigned)

    terminal = compat.execute_posix_v2_compat_mechanical_poc(
        session_authority=session_authority,
        request_bytes=_canonical(request),
    )
    terminal_raw = compat.project_posix_v2_compat_mechanical_poc_terminal(
        session_authority, terminal
    )
    terminal_value = json.loads(terminal_raw)
    stdout_raw, stderr_raw = compat.project_posix_v2_compat_mechanical_poc_streams(
        session_authority, terminal
    )
    for name, admitted in auxiliary_bindings.items():
        current = compat._poc_file_binding(
            Path(str(admitted["path"])),
            label=f"retained compatibility static-analysis auxiliary {name}",
            maximum=compat._POC_MAX_EXECUTABLE_BYTES,
        )
        if current != admitted["binding"]:
            raise StaticAnalysisCompatExecutionError(
                f"static-analysis auxiliary executable drifted: {name}"
            )
    evm_workspace.replay_evm_analysis_workspace_execution_closure(
        workspace_authority
    )
    if not (
        terminal_value.get("actual_tool_started") is True
        and terminal_value.get("actual_tool_completion_observed") is True
        and terminal_value.get("status") in {"COMPLETED", "NONZERO_EXIT", "TIMED_OUT"}
        and isinstance(terminal_value.get("returncode"), int)
    ):
        raise StaticAnalysisCompatExecutionError(
            "compatibility static-analysis terminal is incomplete: "
            + str(terminal_value.get("status"))
        )
    return {
        "schema": "plamen.compat-static-analysis-execution.v1",
        "authority_tier": "OBSERVATIONAL_REDUCED_ISOLATION",
        "can_certify_clean": False,
        "tool_id": tool_id,
        "workspace_receipt_sha256": workspace["receipt_sha256"],
        "policy_sha256": policy_sha256,
        "request_sha256": request["request_sha256"],
        "terminal_sha256": _sha(terminal_raw),
        "terminal": terminal_value,
        "auxiliary_executables": auxiliary_bindings,
        "stdout": stdout_raw.decode("utf-8", errors="replace"),
        "stderr": stderr_raw.decode("utf-8", errors="replace"),
    }


__all__ = [
    "StaticAnalysisCompatExecutionError",
    "execute_compat_static_analysis",
    "resolve_compat_foundry_solc",
]
