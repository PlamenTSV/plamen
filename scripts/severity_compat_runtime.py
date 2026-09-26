"""Explicit reduced-isolation execution for a planned severity shard.

This does not grant native process/WER authority. The standard MODEL ledger and
the separately versioned compatibility worker receipt remain distinct evidence.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
from typing import Any, Callable, Mapping

from artifact_ledger import (
    ArtifactLedgerError, read_artifact_ledger, record_work_unit_inputs,
    validate_work_unit_inputs,
)
import rooted_path_io as rio
import severity_adjudication_work as work
from severity_decision_ledger import parse_severity_adjudication_proposal


FAULT_POINTS = ("after_arm", "after_execution", "before_commit", "after_commit")
_CONTEXT_SCHEMA = "plamen.severity_compat_staged_context.v1"
_CLAUDE_CONTEXT_SCHEMA = "plamen.claude_severity_compat_staged_gate.v1"
_MAX_FILE_BYTES = 256 * 1024 * 1024


def _snapshot_boundary(root: Path, project: Path) -> dict[str, list[Any]]:
    """Observe files and links without following links or hiding unreadable files."""
    result: dict[str, list[Any]] = {}

    def visit(directory: Path, prefix: str, *, project_walk: bool) -> None:
        with rio.scandir(directory) as entries:
            children = sorted(entries, key=lambda entry: entry.name)
        for entry in children:
            path = directory / entry.name
            if project_walk and (entry.name == ".git" or path == root):
                continue
            name = prefix + entry.name
            observed = rio.lstat(path)
            if stat.S_ISLNK(observed.st_mode):
                result[name] = ["LINK", os.readlink(path)]
            elif stat.S_ISDIR(observed.st_mode):
                visit(path, name + "/", project_walk=project_walk)
            elif stat.S_ISREG(observed.st_mode):
                raw = rio.read_bytes(
                    path, label="severity child boundary file",
                    max_bytes=_MAX_FILE_BYTES, require_single_link=True,
                )
                result[name] = [
                    "FILE", len(raw), hashlib.sha256(raw).hexdigest(),
                    observed.st_mtime_ns,
                ]
            else:
                raise ArtifactLedgerError(f"unsupported severity boundary entry: {name}")

    visit(root, "", project_walk=False)
    if project != root:
        visit(project, "../", project_walk=True)
    return result


def severity_compat_staged_validator(
    outputs: Mapping[str, bytes], context: Mapping[str, Any],
) -> list[str]:
    """Apply the existing proposal parser to the exact assigned output roster."""
    if context.get("schema") != _CONTEXT_SCHEMA:
        return ["severity compatibility staged context schema differs"]
    candidates = context.get("output_candidates")
    if not isinstance(candidates, Mapping) or not candidates:
        return ["severity compatibility output denominator is absent"]
    if set(outputs) != set(candidates):
        return ["severity compatibility staged output denominator differs"]
    issues: list[str] = []
    for name, raw in outputs.items():
        try:
            parse_severity_adjudication_proposal(raw)
        except (TypeError, ValueError) as exc:
            issues.append(f"{name}: invalid severity proposal: {exc}")
    return issues


def severity_compat_claude_staged_validator(
    outputs: Mapping[str, bytes], context: Mapping[str, Any],
) -> list[str]:
    """Require both Claude hook receipts and severity proposal semantics."""

    if (
        not isinstance(context, Mapping)
        or set(context) != {"schema", "exact_gate", "semantic_gate"}
        or context.get("schema") != _CLAUDE_CONTEXT_SCHEMA
        or not isinstance(context.get("exact_gate"), Mapping)
        or not isinstance(context.get("semantic_gate"), Mapping)
    ):
        return ["severity Claude staged context is malformed"]
    from claude_phase_tool_policy import staged_exact_output_receipt_validator

    exact = staged_exact_output_receipt_validator(outputs, context["exact_gate"])
    semantic = severity_compat_staged_validator(outputs, context["semantic_gate"])
    return list(dict.fromkeys([*exact, *semantic]))


def _context(
    plan: Mapping[str, Any], shard: Mapping[str, Any],
    boundary_digest: str,
) -> dict[str, Any]:
    return {
        "schema": _CONTEXT_SCHEMA,
        "run_id": plan["run_id"],
        "plan_digest": plan["plan_digest"],
        "manifest_digest": plan["manifest_digest"],
        "shard_id": shard["shard_id"],
        "output_candidates": {
            f"scratchpad:{name}": candidate
            for candidate, name in shard["expected_outputs"].items()
        },
        "boundary_before_sha256": boundary_digest,
    }


def _allowed_runtime_names(shard: Mapping[str, Any], label: str) -> set[str]:
    return {
        *shard["expected_outputs"].values(),
        f"_prompt_{label}.attempt1.md",
        f"_provider_prompt_{label}.attempt1.md",
        f"_codex_output_{label}.attempt1.md",
        f"_stdio_{label}.attempt1.log",
    }


def _boundary_digest(
    snapshot: Mapping[str, Any], allowed: set[str],
    allowed_prefixes: tuple[str, ...] = (),
) -> str:
    raw = json.dumps(
        {
            name: value for name, value in snapshot.items()
            if name not in allowed
            and not any(name.startswith(prefix) for prefix in allowed_prefixes)
        },
        ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":"),
    ).encode("ascii")
    return hashlib.sha256(raw).hexdigest()


def build_severity_compat_staged_gate_binding(
    plan: Mapping[str, Any], shard: Mapping[str, Any], boundary_before_sha256: str,
    *, contract: Any, input_bindings: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    """Replay the exact validator implementation, context and bound read set."""
    from posix_v2_compat_runtime import _freeze_staged_validation_gate

    context = _context(plan, shard, boundary_before_sha256)
    gate = _freeze_staged_validation_gate(
        severity_compat_staged_validator, context, contract.immutable_inputs,
        contract=contract, input_bindings=input_bindings,
    )
    if gate is None:
        raise ArtifactLedgerError("severity compatibility staged gate is absent")
    return (
        context, dict(gate.binding),
        json.loads(gate.input_bindings_raw.decode("ascii"))["bindings"],
    )


def _require_containment(
    root: Path, project: Path, plan: Mapping[str, Any], shard: Mapping[str, Any],
    receipt: Mapping[str, Any], receipt_path: Path, label: str,
) -> None:
    recorded_context = receipt.get("staged_output_context")
    if not isinstance(recorded_context, Mapping):
        raise ArtifactLedgerError("severity compatibility staged context is absent")
    exact_gate = None
    context = recorded_context
    if recorded_context.get("schema") == _CLAUDE_CONTEXT_SCHEMA:
        exact_gate = recorded_context.get("exact_gate")
        context = recorded_context.get("semantic_gate")
    if not isinstance(context, Mapping):
        raise ArtifactLedgerError("severity compatibility semantic context is absent")
    before = context.get("boundary_before_sha256")
    if (
        not isinstance(before, str) or len(before) != 64
        or any(char not in "0123456789abcdef" for char in before)
        or dict(context) != _context(plan, shard, before)
    ):
        raise ArtifactLedgerError("severity compatibility staged context changed")
    # All allowed runtime control names belong to this one label/attempt and
    # the one receipt returned by full execution replay. No directory wildcard
    # grants another shard's receipts or arbitrary worker-transaction writes.
    allowed = _allowed_runtime_names(shard, label)
    allowed.add(receipt_path.relative_to(root).as_posix())
    allowed_prefixes: list[str] = []
    if isinstance(exact_gate, Mapping):
        for raw_path in (
            exact_gate.get("output_directory"),
            Path(str(exact_gate.get("policy_path") or "")).parent,
        ):
            path = Path(str(raw_path)).resolve(strict=False)
            try:
                relative = path.relative_to(root).as_posix().rstrip("/") + "/"
            except ValueError as exc:
                raise ArtifactLedgerError(
                    "severity Claude runtime namespace escaped scratchpad"
                ) from exc
            allowed_prefixes.append(relative)
    after = _snapshot_boundary(root, project)
    if _boundary_digest(after, allowed, tuple(allowed_prefixes)) != before:
        raise ArtifactLedgerError(
            "severity compatibility child containment violation: unassigned files changed"
        )


def run_posix_compat_severity_worker(
    scratchpad: Path, *, config: Mapping[str, Any], shard_id: str,
    session_authority: object,
    fault_hook: Callable[[str], None] | None = None,
    claude_boundary_factory: Callable[
        [Any, Any, Path, Path], Mapping[str, Any]
    ] | None = None,
) -> dict[str, Any]:
    """Arm, execute, incorporate, or replay one exact compatibility MODEL leaf."""
    from severity_compat_authority import (
        commit_severity_compat_worker_run, register_severity_compat_session,
        severity_compat_contract_launch, severity_compat_label,
    )
    from posix_v2_compat_runtime import run_claude_exec, run_codex_exec
    from verifier_model_execution_authority import (
        replay_posix_v2_compat_dynamic_verifier_receipt,
    )

    root = rio.checked_directory(scratchpad, label="severity compat scratchpad")
    project = rio.checked_directory(config["project_root"], label="severity compat project")
    backend = str(config.get("cli_backend") or "").strip().lower()
    if (
        backend not in {"claude", "codex"}
        or rio.checked_directory(config["scratchpad"], label="configured scratchpad") != root
    ):
        raise ArtifactLedgerError("severity compatibility configuration differs")
    run_id = str(config.get("_run_id") or "")
    register_severity_compat_session(
        session_authority, run_id=run_id, scratchpad=root, project_root=project,
    )
    problems = work.validate_prepared_work(root)
    if problems:
        raise ArtifactLedgerError("severity prepared work is invalid: " + "; ".join(problems))
    plan = work._read_json(root / work.WORK_PLAN_NAME)
    matches = [row for row in plan["shards"] if row["shard_id"] == shard_id]
    if (
        len(matches) != 1 or plan["run_id"] != run_id
        or plan["backend"] != backend or plan["transport"] != "posix-v2-compat"
    ):
        raise ArtifactLedgerError("severity compatibility plan/run/transport differs")
    shard = matches[0]
    dimensions = dict(
        pipeline=str(config["pipeline"]), mode=str(config["mode"]),
        ecosystem=str(config["language"]),
    )
    contract, launch = severity_compat_contract_launch(
        root, shard_id=shard_id, **dimensions,
    )
    prompt_raw = rio.read_bytes(
        root / shard["prompt_file"], label="severity bound prompt",
        max_bytes=16 * 1024 * 1024, require_single_link=True,
    )
    prompt_sha = hashlib.sha256(prompt_raw).hexdigest()
    label = severity_compat_label(contract)
    hook = fault_hook or (lambda _point: None)

    def commit() -> dict[str, Any]:
        return commit_severity_compat_worker_run(
            root, project_root=project, shard_id=shard_id, **dimensions,
            label=label, attempt=1, prompt_sha256=prompt_sha,
            session_authority=session_authority,
            atomic_write=rio.durable_write_once_bytes,
        )

    unit = read_artifact_ledger(root).get("work_units", {}).get(contract.key)
    if isinstance(unit, Mapping) and unit.get("execution_state") == "OUTPUT_COMMITTED":
        # Consumer replay reconstructs and validates native/compatibility type,
        # standard MODEL evidence and the nested successful execution receipt.
        return commit()
    if unit is None:
        if rio.lexists(root / work._worker_run_name(shard)):
            raise ArtifactLedgerError("severity compatibility refuses foreign worker receipt")
        for spec in contract.outputs:
            if rio.lexists(root / spec.path):
                raise ArtifactLedgerError("severity compatibility refuses foreign output")
        record_work_unit_inputs(root, project, contract, launch, run_id=run_id)
    problems = validate_work_unit_inputs(root, project, contract, launch, run_id=run_id)
    if problems:
        raise ArtifactLedgerError("severity compatibility input replay failed: " + "; ".join(problems))
    armed = read_artifact_ledger(root).get("work_units", {}).get(contract.key)
    if not (
        isinstance(armed, Mapping)
        and armed.get("semantic_status") == "INPUTS_BOUND"
        and armed.get("execution_state") == "INPUTS_BOUND_PREEXECUTION"
        and armed.get("artifacts") == {}
    ):
        raise ArtifactLedgerError("severity compatibility work unit is not armed")
    hook("after_arm")

    receipt_root = root / ".posix_v2_compat_receipts"
    prior_receipts = []
    if rio.lexists(receipt_root):
        rio.checked_directory(receipt_root, label="severity compat receipt root")
        with rio.scandir(receipt_root) as entries:
            prior_receipts = [
                entry.name for entry in entries
                if entry.name.startswith(f"{contract.phase}.{label}.attempt1.")
            ]
    if not prior_receipts:
        claude_boundary: Mapping[str, Any] | None = None
        claude_staging: Path | None = None
        if backend == "claude":
            if not callable(claude_boundary_factory):
                raise ArtifactLedgerError(
                    "severity Claude compatibility boundary factory is absent"
                )
            from worker_transaction import (
                attempt_output_directory, compile_attempt_write_scope,
            )

            attempt_scope = compile_attempt_write_scope(
                run_id=run_id,
                phase=contract.phase,
                work_unit_id=contract.work_unit_id,
                attempt_id=f"attempt-{os.urandom(12).hex()}",
            )
            claude_staging = attempt_output_directory(root, attempt_scope)
            claude_boundary = claude_boundary_factory(
                contract, launch, root / str(shard["prompt_file"]),
                claude_staging,
            )
            if not isinstance(claude_boundary, Mapping):
                raise ArtifactLedgerError(
                    "severity Claude compatibility boundary is malformed"
                )
        before = _snapshot_boundary(root, project)
        executor = run_claude_exec if backend == "claude" else run_codex_exec
        execution_arguments: dict[str, Any] = {}
        if backend == "claude":
            execution_arguments.update({
                "phase_tool_boundary": claude_boundary,
                "output_staging_directory": claude_staging,
            })
        boundary_prefixes: tuple[str, ...] = ()
        if backend == "claude":
            assert claude_boundary is not None and claude_staging is not None
            boundary_prefixes = tuple(
                path.resolve(strict=False).relative_to(root).as_posix().rstrip("/")
                + "/"
                for path in (
                    claude_staging,
                    Path(str(claude_boundary["policy_path"])).parent,
                )
            )
        staged_context = _context(
            plan, shard,
            _boundary_digest(
                before, _allowed_runtime_names(shard, label), boundary_prefixes,
            ),
        )
        staged_validator = severity_compat_staged_validator
        if backend == "claude":
            assert claude_boundary is not None and claude_staging is not None
            staged_validator = severity_compat_claude_staged_validator
            staged_context = {
                "schema": _CLAUDE_CONTEXT_SCHEMA,
                "exact_gate": {
                    "schema": "plamen.claude_exact_staged_gate.v1",
                    "policy_path": str(claude_boundary["policy_path"]),
                    "manifest_digest": str(claude_boundary["manifest_digest"]),
                    "output_directory": str(claude_staging),
                    "expected_outputs": sorted(
                        str(spec.path) for spec in contract.outputs
                    ),
                },
                "semantic_gate": staged_context,
            }
        status = executor(
            session_authority=session_authority, prompt=prompt_raw.decode("utf-8"),
            phase_name=contract.phase, needs_mcp=False, config=config,
            scratchpad=root, attempt=1, label=label,
            expected_outputs=tuple(spec.path for spec in contract.outputs),
            timeout=launch.timeout_s, effective_model=launch.model,
            working_directory=root, writable_directories=(root,),
            phase_io_contract=contract, phase_io_launch=launch,
            staged_output_validator=staged_validator,
            staged_output_context=staged_context,
            staged_output_input_identities=contract.immutable_inputs,
            **execution_arguments,
        )
        if status != 0:
            raise ArtifactLedgerError(f"severity compatibility worker failed: {status}")
    receipt, receipt_path, problems = replay_posix_v2_compat_dynamic_verifier_receipt(
        scratchpad=root, config=config, contract=contract, launch=launch,
        label=label, attempt=1, prompt_sha256=prompt_sha,
        session_authority=session_authority,
    )
    if problems or receipt is None or receipt_path is None:
        raise ArtifactLedgerError(
            "severity compatibility execution replay failed: "
            + "; ".join(problems or ["successful receipt absent"])
        )
    _require_containment(root, project, plan, shard, receipt, receipt_path, label)
    hook("after_execution")
    hook("before_commit")
    # Repeat after fault injection; a hook cannot change unrelated files and
    # still obtain an ACTIVE model producer from the earlier observation.
    _require_containment(root, project, plan, shard, receipt, receipt_path, label)
    result = commit()
    hook("after_commit")
    return result
