"""Reduced-isolation driver bridge for generated fuzz campaigns on POSIX.

This is a recall-positive execution lane.  It binds the exact MODEL Markdown,
generated harness bytes, source denominator, admitted executable, argv, closed
environment, and compatibility terminal.  Its command receipt deliberately
does not claim native proof authority; consumers must adjudicate the explicit
``EXECUTION_SCOPE_REQUIRES_CONSUMER`` result state.
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
from typing import Any, Mapping

import fuzz_workspace_authority as fwa
from fuzz_harness_bundle import (
    materialize_fuzz_harness_bundle,
    parse_fuzz_harness_bundle,
)
import mechanical_prewarm as prewarm
import posix_v2_compat_runtime as compat
from supply_chain_gate import gate_supply_chain, project_supply_chain_admission


class FuzzCompatExecutionError(RuntimeError):
    pass


def _canonical(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=True, allow_nan=False, sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _iso_from_ns(value: object) -> str:
    try:
        nanoseconds = int(value)
    except (TypeError, ValueError):
        return datetime.now(timezone.utc).isoformat()
    return datetime.fromtimestamp(
        nanoseconds / 1_000_000_000, tz=timezone.utc
    ).isoformat()


def _stable_source_projection(authority_path: Path) -> tuple[dict[str, Any], list[str]]:
    authority = fwa._read_json(authority_path)
    issues = fwa.validate_fuzz_workspace_authority(
        authority_path, check_source=True
    )
    return authority, issues


def _existing_receipt_for_bundle(
    authority: Mapping[str, object],
    *,
    model_output_sha256: str,
    bundle_manifest_digest: str,
) -> dict[str, object] | None:
    receipts, issues = fwa._command_receipts(authority)
    if issues:
        raise FuzzCompatExecutionError(
            "existing fuzz command receipt is invalid: "
            + "; ".join(
                f"{row.get('code')}: {row.get('detail')}" for row in issues
            )
        )
    for value in receipts:
        execution = value.get("posix_v2_compat_execution")
        if (
            isinstance(execution, Mapping)
            and execution.get("model_output_sha256") == model_output_sha256
            and execution.get("bundle_manifest_digest")
            == bundle_manifest_digest
        ):
            return value
    return None


def execute_compat_fuzz_campaign(
    *,
    session_authority: object,
    authority_path: Path,
    model_output_path: Path,
    role: str,
    timeout_seconds: float,
) -> dict[str, object]:
    """Materialize and run one exact fuzz campaign through Seatbelt.

    The function is compare-only on resume.  Any source, bundle, executable,
    workspace, or receipt drift fails closed instead of creating a new command
    identity.
    """

    authority_path = Path(authority_path)
    model_output_path = Path(model_output_path)
    authority, issues = _stable_source_projection(authority_path)
    if issues:
        raise FuzzCompatExecutionError(
            "fuzz workspace is not admissible: " + "; ".join(issues)
        )
    session = compat._session_record(session_authority)
    if authority.get("run_id") != session.binding.get("run_id"):
        raise FuzzCompatExecutionError("fuzz authority belongs to another run")
    raw_model = model_output_path.read_bytes()
    bundle = parse_fuzz_harness_bundle(raw_model, role=role)
    model_output_sha256 = _sha(raw_model)
    bundle_manifest_digest = str(bundle.manifest["payload_digest"])
    active = Path(str(authority["active_root"]))
    subject_path = materialize_fuzz_harness_bundle(
        bundle, active_root=active
    )
    post_materialization_issues = fwa.validate_fuzz_workspace_authority(
        authority_path, check_source=True
    )
    if post_materialization_issues:
        raise FuzzCompatExecutionError(
            "generated harness violates workspace authority: "
            + "; ".join(post_materialization_issues)
        )
    prior = _existing_receipt_for_bundle(
        authority,
        model_output_sha256=model_output_sha256,
        bundle_manifest_digest=bundle_manifest_digest,
    )
    if prior is not None:
        return prior

    source = Path(str(authority["source_root"])).resolve(strict=True)
    if not prewarm._within(source, session.project_root):
        raise FuzzCompatExecutionError("fuzz source root is outside the audit root")
    source_identity, source_mutation = prewarm._identity(source)
    source_digest = str(
        (authority.get("denominators") or {}).get("all", {}).get("set_digest")
        or ""
    )
    if not fwa._HEX64_RE.fullmatch(source_digest):
        raise FuzzCompatExecutionError("fuzz source denominator is unbound")

    auxiliary_executables: dict[str, dict[str, object]] = {}
    try:
        solc_selection = prewarm._select_solc(source, "evm", session)
    except prewarm.CompatPrewarmError as exc:
        raise FuzzCompatExecutionError(
            f"exact Foundry compiler is unavailable: {exc}"
        ) from exc
    if solc_selection is not None:
        solc_path = Path(str(solc_selection["source_path"])).resolve(strict=True)
        solc_binding = compat._poc_file_binding(
            solc_path,
            label="compatibility fuzz auxiliary solc",
            maximum=compat._POC_MAX_EXECUTABLE_BYTES,
        )
        auxiliary_executables["solc"] = {
            "path": os.fspath(solc_path),
            "binding": solc_binding,
        }

    admission_authority = gate_supply_chain(
        source, posix_compat_session=session_authority
    )
    admission = dict(project_supply_chain_admission(
        admission_authority, posix_compat_session=session_authority
    ))
    environment, environment_overrides = fwa._tool_environment(authority)
    environment["FOUNDRY_OFFLINE"] = "true"
    environment_overrides["FOUNDRY_OFFLINE"] = "true"
    if "solc" in auxiliary_executables:
        solc_value = str(auxiliary_executables["solc"]["path"])
        environment["FOUNDRY_SOLC"] = solc_value
        environment_overrides["FOUNDRY_SOLC"] = solc_value
    if str(role).strip().casefold() == "invariant_fuzz":
        invariant_controls = {
            "FOUNDRY_INVARIANT_RUNS": "256",
            "FOUNDRY_INVARIANT_DEPTH": "25",
            "FOUNDRY_INVARIANT_FAIL_ON_REVERT": "false",
        }
        environment.update(invariant_controls)
        environment_overrides.update(invariant_controls)
    located = shutil.which(bundle.argv[0], path=environment.get("PATH"))
    if not located:
        raise FuzzCompatExecutionError(
            f"fuzz executable is unavailable: {bundle.argv[0]}"
        )
    executable = Path(located).resolve(strict=True)
    if prewarm._within(executable, session.project_root) or prewarm._within(
        executable, session.scratchpad
    ):
        raise FuzzCompatExecutionError("fuzz executable is target-controlled")
    # The compatibility request binds a closed PATH whose every member must be
    # an existing, unaliased directory.  Ambient macOS launch environments can
    # retain stale Cryptex entries, so admit only replayable members and always
    # place the already selected executable directory first.
    path_members: list[str] = []
    for raw in (os.fspath(executable.parent), *environment["PATH"].split(os.pathsep)):
        try:
            directory, _directory_identity = compat._safe_directory(
                raw, "compatibility fuzz PATH member"
            )
        except Exception:
            continue
        if prewarm._within(directory, session.project_root):
            continue
        rendered = os.fspath(directory)
        if rendered not in path_members:
            path_members.append(rendered)
    if not path_members:
        raise FuzzCompatExecutionError("no admitted fuzz PATH member remains")
    environment["PATH"] = os.pathsep.join(path_members)
    executable_binding = compat._poc_file_binding(
        executable,
        label="compatibility fuzz executable",
        maximum=compat._POC_MAX_EXECUTABLE_BYTES,
    )
    workspace, workspace_identity = compat._safe_directory(
        Path(str(authority["workspace_root"])),
        "compatibility fuzz workspace",
    )
    active_relative = active.resolve(strict=True).relative_to(workspace).as_posix()
    cwd_relative = (
        active_relative
        if bundle.cwd_relative == "."
        else f"{active_relative}/{bundle.cwd_relative}"
    )
    cwd = workspace / cwd_relative
    compat._safe_directory(cwd, "compatibility fuzz cwd")
    subject_relative = subject_path.relative_to(workspace).as_posix()
    subject_binding = compat._poc_file_binding(
        subject_path,
        label="generated fuzz bundle manifest",
        maximum=compat._MAX_PHASE_IO_OUTPUT_BYTES,
    )
    argv = [os.fspath(executable), *bundle.argv[1:]]
    campaign_policy = {
        "schema": "plamen.compat-fuzz-campaign-policy.v1",
        "authority_digest": authority["payload_digest"],
        "model_output_sha256": model_output_sha256,
        "bundle_manifest": bundle.manifest,
        "argv": argv,
        "cwd_relative": bundle.cwd_relative,
        "timeout_seconds": float(timeout_seconds),
        "auxiliary_executables": auxiliary_executables,
    }
    policy_sha256 = _sha(_canonical(campaign_policy))
    workspace_tree, _workspace_files, _workspace_bytes = compat._poc_tree_digest(
        workspace
    )
    work_authority = {
        "schema": "plamen.compat-fuzz-work-authority.v1",
        "authority_digest": authority["payload_digest"],
        "policy_sha256": policy_sha256,
        "workspace_pre_tree_sha256": workspace_tree,
    }
    role_token = str(role).strip().replace("_", "-").upper()
    job_token = str(authority["job_id"]).strip().replace("_", "-").upper()
    request: dict[str, object] = {
        "schema": compat.POC_REQUEST_SCHEMA,
        "request_sha256": "",
        "session_binding_sha256": session.binding["session_binding_sha256"],
        "run_id": session.binding["run_id"],
        "purpose": "CANDIDATE_FUZZ",
        "work_unit_id": f"fuzz.{authority['job_id']}",
        "finding_id": f"FUZZ-{job_token}",
        "constituent_id": f"ROLE-{role_token}",
        "attempt_number": 1,
        "work_authority_sha256": _sha(_canonical(work_authority)),
        "policy_sha256": policy_sha256,
        "verifier_receipt_sha256": _sha(raw_model),
        "supply_chain_admission_sha256": admission["admission_sha256"],
        "audit_snapshot_sha256": authority["source_snapshot_digest"],
        "source_census_sha256": source_digest,
        "source_build_root": os.fspath(source),
        "source_build_root_identity_sha256": prewarm._mapping_sha(source_identity),
        "workspace_root": os.fspath(workspace),
        "workspace_root_identity_sha256": prewarm._mapping_sha(workspace_identity),
        "workspace_pre_tree_sha256": workspace_tree,
        "subject_kind": "GENERATED_FUZZ_HARNESS",
        "subject_relative_path": subject_relative,
        "subject_sha256": subject_binding["sha256"],
        "subject_size": subject_binding["size"],
        "test_function": None,
        "tool_id": executable.name,
        "executable_path": os.fspath(executable),
        "executable_sha256": executable_binding["sha256"],
        "executable_size": executable_binding["size"],
        "argv": argv,
        "cwd_relative_path": cwd_relative,
        "environment": environment,
        "timeout_seconds": float(timeout_seconds),
        "stdout_limit_bytes": min(
            fwa.MAX_COMMAND_LOG_BYTES, compat._MAX_STDOUT_BYTES
        ),
        "stderr_limit_bytes": min(
            fwa.MAX_COMMAND_LOG_BYTES, compat._MAX_STDOUT_BYTES
        ),
        "expected_outputs": [],
        "offline_intent": True,
    }
    unsigned = dict(request)
    unsigned.pop("request_sha256")
    request["request_sha256"] = prewarm._mapping_sha(unsigned)
    generated_pre = fwa._generated_harness_rows(authority)
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
    for name, admitted in auxiliary_executables.items():
        current = compat._poc_file_binding(
            Path(str(admitted["path"])),
            label=f"retained compatibility fuzz auxiliary {name}",
            maximum=compat._POC_MAX_EXECUTABLE_BYTES,
        )
        if current != admitted["binding"]:
            raise FuzzCompatExecutionError(
                f"compatibility fuzz auxiliary executable drifted: {name}"
            )
    terminal_receipt_relative = Path(
        str(terminal_value["stdout_retained_path"])
    ).with_suffix(".json").as_posix()
    terminal_receipt_raw = (
        Path(str(authority["scratchpad_root"])) / terminal_receipt_relative
    ).read_bytes()
    if not (
        terminal_value.get("actual_tool_started") is True
        and terminal_value.get("actual_tool_completion_observed") is True
        and terminal_value.get("status") in {"COMPLETED", "NONZERO_EXIT", "TIMED_OUT"}
        and isinstance(terminal_value.get("returncode"), int)
    ):
        raise FuzzCompatExecutionError(
            "compatibility terminal did not authenticate a completed campaign: "
            + str(terminal_value.get("status"))
        )
    if fwa.validate_fuzz_workspace_authority(authority_path, check_source=True):
        raise FuzzCompatExecutionError("fuzz workspace/source drifted during campaign")
    if prewarm._identity(source)[1] != source_mutation:
        raise FuzzCompatExecutionError("fuzz source root changed during campaign")

    runtime = Path(str(authority["runtime_root"]))
    receipt_path, stdout_path, stderr_path = fwa._command_receipt_paths(runtime)
    stdout_path.write_bytes(stdout_raw)
    stderr_path.write_bytes(stderr_raw)
    returncode = int(terminal_value["returncode"])
    timed_out = str(terminal_value.get("status")) == "TIMED_OUT"
    receipt: dict[str, object] = {
        "schema_version": fwa.COMMAND_SCHEMA,
        "authority_digest": authority["payload_digest"],
        "run_id": authority["run_id"],
        "job_id": authority["job_id"],
        "status": "TIMEOUT" if timed_out else (
            "COMPLETED" if returncode == 0 else "FAILED"
        ),
        "started_at": _iso_from_ns(terminal_value.get("started_at_unix_ns")),
        "finished_at": _iso_from_ns(terminal_value.get("completed_at_unix_ns")),
        "cwd": os.fspath(cwd),
        "argv": argv,
        "timeout_seconds": float(timeout_seconds),
        "executable": {
            "path": os.fspath(executable),
            "size": executable_binding["size"],
            "sha256": executable_binding["sha256"],
        },
        "auxiliary_executables": auxiliary_executables,
        "tool_version": {
            "provider": "POSIX_V2_COMPAT",
            "request_sha256": request["request_sha256"],
            "model_output_sha256": model_output_sha256,
            "bundle_manifest_digest": bundle_manifest_digest,
        },
        "environment_overrides": dict(sorted(environment_overrides.items())),
        "inherited_environment_fingerprint": {
            "variables": [],
            "set_digest": fwa.record_set_digest([]),
        },
        "process_tree_policy": "POSIX_V2_COMPAT_SEATBELT_REDUCED",
        "generated_pre_set_digest": fwa.record_set_digest(generated_pre),
        "generated_post_set_digest": fwa.record_set_digest(
            fwa._generated_harness_rows(authority)
        ),
        "returncode": returncode,
        "timed_out": timed_out,
        "stdout": fwa._file_receipt(stdout_path, Path(str(authority["workspace_root"]))),
        "stderr": fwa._file_receipt(stderr_path, Path(str(authority["workspace_root"]))),
        "posix_v2_compat_execution": {
            "request_sha256": request["request_sha256"],
            "model_output_sha256": model_output_sha256,
            "bundle_manifest_digest": bundle_manifest_digest,
            "terminal_sha256": _sha(terminal_receipt_raw),
            "terminal_receipt_path": terminal_receipt_relative,
            "terminal_status": terminal_value["status"],
            "actual_tool_started": terminal_value["actual_tool_started"],
            "actual_tool_completion_observed": terminal_value[
                "actual_tool_completion_observed"
            ],
            "network_denial_proven": False,
            "proof_authority": "EXECUTION_SCOPE_REQUIRES_CONSUMER",
        },
    }
    receipt["runner_witness"] = fwa._write_runner_witness(
        receipt_path, receipt, authority
    )
    receipt["payload_digest"] = fwa.payload_digest(receipt)
    fwa._atomic_json(receipt_path, receipt)
    return receipt


__all__ = ["FuzzCompatExecutionError", "execute_compat_fuzz_campaign"]
