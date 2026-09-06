"""WorkerTransaction-only execution adapter for EVM Program Facts.

This module translates a reviewed logical provider plan into one exact native
WorkPlan.  It never launches a process directly and never publishes canonical
Program Facts sidecars.  The shipped helper is currently disabled, so the
production planning path returns visible blocking debt; the structural compiler
exists to test the complete command/WorkPlan binding without minting execution
authority.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import Path
import re
from types import MappingProxyType
from typing import Any, Callable, Mapping

from program_facts_evm_tool_authority import (
    EvmToolAuthority,
    INSTALLED_PINNED_AUTHORITY,
    STRUCTURAL_TEST_ONLY,
)
from program_facts_provider_api import ProviderPlan, ProviderPlanDecision
from program_facts_types import canonical_json_bytes, derive_stable_id
from provider_command_authority import argv_authority_sha256
import rooted_path_io
from worker_execution_receipts import (
    ParserDigest,
    environment_allowlist_sha256,
    validate_staged_execution,
)
from worker_transaction import (
    ExecutionRef,
    NativeCommandAdapter,
    compile_worker_plan,
    execute_worker_transaction,
)


_HEX64_RE = re.compile(r"^[0-9a-f]{64}$", re.ASCII)
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$", re.ASCII)
_HELPER_ARGUMENTS = ("-I", "{HELPER_SOURCE}", "--stdin-json")


class ProgramFactsEvmWtxError(RuntimeError):
    """An EVM provider attempt could not establish WTx authority."""


def _fail(message: str, exc: BaseException | None = None) -> None:
    if exc is None:
        raise ProgramFactsEvmWtxError(message)
    raise ProgramFactsEvmWtxError(message) from exc


def _hex64(value: Any, label: str) -> str:
    if not isinstance(value, str) or _HEX64_RE.fullmatch(value) is None:
        _fail(f"{label} must be lowercase 64-hex")
    return value


def _identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or _ID_RE.fullmatch(value) is None:
        _fail(f"{label} is invalid")
    return value


@dataclass(frozen=True)
class EvmWtxPhaseBindings:
    run_id: str
    phase: str
    work_unit_id: str
    generation: int
    phase_roster_denominator_digest: str
    phase_io_contract_digest: str
    phase_io_launch_digest: str
    phase_io_input_set_digest: str

    def __post_init__(self) -> None:
        _identifier(self.run_id, "WTx run_id")
        _identifier(self.phase, "WTx phase")
        _identifier(self.work_unit_id, "WTx work_unit_id")
        if (
            isinstance(self.generation, bool)
            or not isinstance(self.generation, int)
            or self.generation < 0
        ):
            _fail("WTx generation must be a nonnegative integer")
        for name in (
            "phase_roster_denominator_digest",
            "phase_io_contract_digest",
            "phase_io_launch_digest",
            "phase_io_input_set_digest",
        ):
            _hex64(getattr(self, name), name)


@dataclass(frozen=True)
class InterpreterObservation:
    resolved_executable: Path
    executable_sha256: str
    version: str

    def __post_init__(self) -> None:
        path = Path(self.resolved_executable).absolute()
        if not path.is_absolute():
            _fail("Python interpreter path must be absolute")
        try:
            raw = rooted_path_io.read_bytes(
                path,
                label="EVM helper Python interpreter",
                require_single_link=False,
            )
        except (OSError, rooted_path_io.RootedPathIOError) as exc:
            _fail("Python interpreter observation cannot replay", exc)
        supplied = _hex64(
            self.executable_sha256,
            "Python interpreter executable digest",
        )
        if hashlib.sha256(raw).hexdigest() != supplied:
            _fail("Python interpreter executable digest drift")
        if (
            not isinstance(self.version, str)
            or not self.version
            or "\n" in self.version
            or "\r" in self.version
        ):
            _fail("Python interpreter version must be one exact line")
        object.__setattr__(self, "resolved_executable", path)


@dataclass(frozen=True)
class EvmWtxDecision:
    ready: bool
    reason: str
    work_plan: Mapping[str, Any] | None
    compiled: "CompiledEvmWorkerTransaction | None" = None
    blocks_reuse: bool = True
    terminal_negative_authority: bool = False


@dataclass(frozen=True)
class CompiledEvmWorkerTransaction:
    provider_plan: ProviderPlan
    work_plan: Mapping[str, Any]
    logical_argv: tuple[str, ...]
    actual_argv: tuple[str, ...]
    command_binding: Mapping[str, str]
    interpreter: InterpreterObservation
    tool_authority: EvmToolAuthority
    production_authority_established: bool

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "work_plan",
            MappingProxyType(dict(self.work_plan)),
        )
        object.__setattr__(
            self,
            "command_binding",
            MappingProxyType(dict(self.command_binding)),
        )


@dataclass(frozen=True)
class ReconciledEvmExecution:
    """Raw provider bytes plus one receipt-schema-compatible WTx reference."""

    raw_output: bytes
    raw_output_sha256: str
    raw_output_size: int
    parsed_output_sha256: str
    worker_transaction_ref: Mapping[str, Any]
    completion: Mapping[str, Any]
    production_authority_established: bool = True

    def __post_init__(self) -> None:
        if type(self.raw_output) is not bytes:
            _fail("reconciled EVM raw output must be exact bytes")
        if hashlib.sha256(self.raw_output).hexdigest() != _hex64(
            self.raw_output_sha256, "reconciled raw-output digest"
        ):
            _fail("reconciled EVM raw-output digest differs from bytes")
        if self.raw_output_size != len(self.raw_output):
            _fail("reconciled EVM raw-output size differs from bytes")
        _hex64(self.parsed_output_sha256, "reconciled parsed-output digest")
        object.__setattr__(
            self,
            "worker_transaction_ref",
            MappingProxyType(dict(self.worker_transaction_ref)),
        )
        object.__setattr__(
            self,
            "completion",
            MappingProxyType(dict(self.completion)),
        )


def _compile(
    *,
    provider_plan: ProviderPlan,
    tool_authority: EvmToolAuthority,
    interpreter: InterpreterObservation,
    phase_bindings: EvmWtxPhaseBindings,
    production: bool,
) -> CompiledEvmWorkerTransaction:
    if type(provider_plan) is not ProviderPlan:
        _fail("EVM WTx compilation requires an exact ProviderPlan")
    if type(tool_authority) is not EvmToolAuthority:
        _fail("EVM WTx compilation requires exact tool authority")
    if type(interpreter) is not InterpreterObservation:
        _fail("EVM WTx compilation requires exact interpreter observation")
    if type(phase_bindings) is not EvmWtxPhaseBindings:
        _fail("EVM WTx compilation requires exact PhaseIO bindings")
    replayed_tool = tool_authority.replay()
    if production and (
        replayed_tool.authority_state != INSTALLED_PINNED_AUTHORITY
        or not replayed_tool.production_ready
    ):
        _fail("EVM helper lacks production semantic authority")

    helper_row = replayed_tool.to_dict()["helper"]
    helper_path = (
        replayed_tool.installed_root
        / Path(str(helper_row["source_identity"]))
    ).absolute()
    try:
        helper_raw = rooted_path_io.read_bytes(
            helper_path,
            label="EVM checked-in helper",
            require_single_link=False,
        )
    except (OSError, rooted_path_io.RootedPathIOError) as exc:
        _fail("EVM helper source cannot replay", exc)
    if hashlib.sha256(helper_raw).hexdigest() != helper_row["sha256"]:
        _fail("EVM helper source changed after tool-authority replay")

    logical_argv = tuple(provider_plan.argv)
    if logical_argv != (
        "plamen-evm-slither-helper",
        "--stdin-json",
    ):
        _fail("EVM provider logical argv is outside the reviewed command")
    actual_argv = (
        str(interpreter.resolved_executable),
        _HELPER_ARGUMENTS[0],
        str(helper_path),
        _HELPER_ARGUMENTS[2],
    )
    command_binding = {
        "logical_argv_sha256": argv_authority_sha256(logical_argv),
        "actual_argv_sha256": argv_authority_sha256(actual_argv),
        "python_executable_sha256": interpreter.executable_sha256,
        "helper_source_sha256": str(helper_row["sha256"]),
        "tool_manifest_file_sha256": (
            replayed_tool.manifest_file_sha256
        ),
    }
    allowlist = environment_allowlist_sha256(())
    provider = {
        "backend": "native",
        "model": "program-facts-evm",
        "transport": "native",
        "resolved_executable": str(interpreter.resolved_executable),
        "executable_sha256": interpreter.executable_sha256,
        "argv": list(actual_argv),
        "environment_allowlist_digest": allowlist,
        "timeout_seconds": provider_plan.resources.time_seconds,
        "stream_limits": {
            "stdout_bytes": provider_plan.resources.output_bytes,
            "stderr_bytes": provider_plan.resources.output_bytes,
            "staged_member_bytes": provider_plan.resources.output_bytes,
        },
    }
    parser_binding = {
        "parser_callable": provider_plan.raw_binding["parser_callable"],
        "parser_source_digest": provider_plan.raw_binding[
            "parser_source_digest"
        ],
        "raw_schema_digest": provider_plan.raw_binding[
            "raw_schema_digest"
        ],
        "command_binding_sha256": hashlib.sha256(
            (
                command_binding["logical_argv_sha256"]
                + command_binding["actual_argv_sha256"]
                + command_binding["python_executable_sha256"]
                + command_binding["helper_source_sha256"]
                + command_binding["tool_manifest_file_sha256"]
            ).encode("ascii")
        ).hexdigest(),
    }
    assignment = {
        "assignment_id": f"{provider_plan.provider_run_id}.raw",
        "members": [
            {
                "staged_relative_path": "evm_slither_raw.json",
                "canonical_identity": (
                    "scratchpad:_program_facts_provider_raw/"
                    f"{provider_plan.provider_run_id}.json"
                ),
                "parser_binding": parser_binding,
                "projection_mode": "CREATE_ABSENT",
                "canonical_prestate": {
                    "status": "MISSING",
                    "sha256": "",
                    "size": 0,
                },
            }
        ],
    }
    try:
        work_plan = compile_worker_plan(
            run_id=phase_bindings.run_id,
            phase=phase_bindings.phase,
            work_unit_id=phase_bindings.work_unit_id,
            generation=phase_bindings.generation,
            phase_roster_denominator_digest=(
                phase_bindings.phase_roster_denominator_digest
            ),
            phase_io_contract_digest=(
                phase_bindings.phase_io_contract_digest
            ),
            phase_io_launch_digest=phase_bindings.phase_io_launch_digest,
            phase_io_input_set_digest=(
                phase_bindings.phase_io_input_set_digest
            ),
            prompt_template_sha256=hashlib.sha256(
                provider_plan.canonical_bytes()
            ).hexdigest(),
            methodology_digests=(
                provider_plan.methodology_authority_digest,
                provider_plan.registry_digest,
                replayed_tool.manifest_file_sha256,
            ),
            source_snapshot_digest=provider_plan.snapshot_digest,
            provider=provider,
            assignment=assignment,
            write_scope={"mode": "ATTEMPT_ONLY", "roots": ["output"]},
            child_denominator={"required": []},
            completion_policy={
                "accepted_signals": ["PROCESS_EXIT_ZERO"],
                "program_facts_command_binding": command_binding,
            },
            retry_policy={"max_attempts": 1},
            terminal_debt_policy={
                "safe_authority": False,
                "terminal_negative_authority": False,
            },
        )
    except Exception as exc:
        _fail("EVM provider WorkerTransaction plan was rejected", exc)
    return CompiledEvmWorkerTransaction(
        provider_plan=provider_plan,
        work_plan=work_plan,
        logical_argv=logical_argv,
        actual_argv=actual_argv,
        command_binding=command_binding,
        interpreter=interpreter,
        tool_authority=replayed_tool,
        production_authority_established=production,
    )


def plan_evm_worker_transaction(
    *,
    provider_plan: ProviderPlan | ProviderPlanDecision,
    tool_authority: EvmToolAuthority,
    interpreter: InterpreterObservation,
    phase_bindings: EvmWtxPhaseBindings,
) -> EvmWtxDecision:
    """Return production work only when both provider and tool are ready."""

    if type(tool_authority) is not EvmToolAuthority:
        _fail("EVM WTx planning requires exact tool authority")
    replayed = tool_authority.replay()
    if not replayed.production_ready:
        return EvmWtxDecision(
            ready=False,
            reason=replayed.unavailable_reason,
            work_plan=None,
            compiled=None,
        )
    if type(provider_plan) is not ProviderPlanDecision:
        _fail("production EVM WTx requires an issued ProviderPlanDecision")
    if not provider_plan.ready or provider_plan.plan is None:
        return EvmWtxDecision(
            ready=False,
            reason="PROVIDER_IDENTITY_UNBOUND",
            work_plan=None,
            compiled=None,
        )
    compiled = _compile(
        provider_plan=provider_plan.plan,
        tool_authority=replayed,
        interpreter=interpreter,
        phase_bindings=phase_bindings,
        production=True,
    )
    return EvmWtxDecision(
        ready=True,
        reason="",
        work_plan=compiled.work_plan,
        compiled=compiled,
        blocks_reuse=False,
    )


def compile_evm_worker_transaction_structural_test_only(
    *,
    authority_mode: str,
    provider_plan: ProviderPlan,
    tool_authority: EvmToolAuthority,
    interpreter: InterpreterObservation,
    phase_bindings: EvmWtxPhaseBindings,
) -> CompiledEvmWorkerTransaction:
    """Exercise the exact WorkPlan mapping without granting execution authority."""

    if authority_mode != STRUCTURAL_TEST_ONLY:
        _fail("structural EVM WTx compilation requires explicit test mode")
    return _compile(
        provider_plan=provider_plan,
        tool_authority=tool_authority,
        interpreter=interpreter,
        phase_bindings=phase_bindings,
        production=False,
    )


def execute_evm_worker_transaction(
    compiled: CompiledEvmWorkerTransaction,
    *,
    scratchpad: Path,
    cwd: Path,
    input_relative_paths: Mapping[str, str],
    parser_digest: ParserDigest,
    cancel_token: Any = None,
) -> ExecutionRef:
    """Execute only a production-issued plan through NativeCommandAdapter."""

    if (
        type(compiled) is not CompiledEvmWorkerTransaction
        or not compiled.production_authority_established
        or not compiled.tool_authority.production_ready
    ):
        _fail("EVM WorkerTransaction execution requires production authority")
    adapter = NativeCommandAdapter(
        scratchpad=Path(scratchpad),
        cwd=Path(cwd),
        input_relative_paths=dict(input_relative_paths),
        parser_digest=parser_digest,
        environment={},
        environment_allowlist=(),
    )
    try:
        return execute_worker_transaction(
            compiled.work_plan,
            adapter,
            cancel_token,
        )
    except Exception as exc:
        _fail("EVM WorkerTransaction execution failed closed", exc)


def reconcile_evm_worker_execution(
    compiled: CompiledEvmWorkerTransaction,
    execution: ExecutionRef,
    *,
    scratchpad: Path,
    parser_digest: ParserDigest,
) -> ReconciledEvmExecution:
    """Replay one terminal EVM attempt and recover its exact raw CAS carrier."""

    if (
        type(compiled) is not CompiledEvmWorkerTransaction
        or not compiled.production_authority_established
        or not compiled.tool_authority.production_ready
    ):
        _fail("EVM execution reconciliation requires production authority")
    if type(execution) is not ExecutionRef:
        _fail("EVM execution reconciliation requires an exact ExecutionRef")
    plan = compiled.work_plan
    expected = (
        plan["run_id"],
        plan["phase"],
        plan["work_unit_id"],
        plan["generation"],
        plan["work_plan_digest"],
    )
    observed = (
        execution.run_id,
        execution.phase,
        execution.work_unit_id,
        execution.generation,
        execution.work_plan_digest,
    )
    if observed != expected:
        _fail("EVM execution reference differs from its WorkPlan")
    try:
        replayed_tool = compiled.tool_authority.replay()
        if (
            not replayed_tool.production_ready
            or replayed_tool.manifest_file_sha256
            != compiled.tool_authority.manifest_file_sha256
        ):
            _fail("EVM tool identity changed after execution")
        executable_raw = rooted_path_io.read_bytes(
            compiled.interpreter.resolved_executable,
            label="EVM WTx interpreter replay",
            require_single_link=False,
        )
        if (
            hashlib.sha256(executable_raw).hexdigest()
            != compiled.interpreter.executable_sha256
        ):
            _fail("EVM WTx interpreter changed after execution")
        completion = validate_staged_execution(
            scratchpad=Path(scratchpad),
            receipt_path=execution.provider_execution.receipt_path,
            parser_digest=parser_digest,
            expected_completion_sha256=(
                execution.provider_execution.completion_sha256
            ),
        )
    except ProgramFactsEvmWtxError:
        raise
    except Exception as exc:
        _fail("EVM WorkerTransaction receipt failed replay", exc)
    members = plan["assignment"]["members"]
    outputs = completion.get("outputs")
    if (
        not isinstance(members, list)
        or len(members) != 1
        or not isinstance(outputs, list)
        or len(outputs) != 1
    ):
        _fail("EVM execution output denominator differs from its WorkPlan")
    member = members[0]
    output = outputs[0]
    if (
        not isinstance(member, Mapping)
        or not isinstance(output, Mapping)
        or output.get("relative_path") != member.get("staged_relative_path")
        or output.get("publish_relative_path")
        != str(member.get("canonical_identity") or "").removeprefix(
            "scratchpad:"
        )
    ):
        _fail("EVM execution output identity differs from its WorkPlan")
    try:
        output_root = rooted_path_io.safe_descendant(
            execution.attempt_directory,
            "output",
            allow_missing=False,
            label="EVM WTx staged output root",
        )
        raw_path = rooted_path_io.safe_descendant(
            output_root,
            str(member["staged_relative_path"]),
            allow_missing=False,
            label="EVM WTx staged raw output",
        )
        raw = rooted_path_io.read_bytes(
            raw_path,
            label="EVM WTx staged raw output",
            require_single_link=False,
        )
    except (OSError, rooted_path_io.RootedPathIOError) as exc:
        _fail("EVM staged raw output cannot replay", exc)
    raw_sha256 = hashlib.sha256(raw).hexdigest()
    if (
        output.get("raw_sha256") != raw_sha256
        or output.get("raw_size") != len(raw)
        or not isinstance(output.get("parsed_sha256"), str)
        or _HEX64_RE.fullmatch(str(output["parsed_sha256"])) is None
    ):
        _fail("EVM staged raw output differs from completion receipt")
    completion_policy = plan.get("completion_policy")
    if (
        not isinstance(completion_policy, Mapping)
        or completion_policy.get("program_facts_command_binding")
        != dict(compiled.command_binding)
    ):
        _fail("EVM command binding changed after WorkPlan compilation")
    cas_manifest_digest = hashlib.sha256(
        canonical_json_bytes(
            {
                "output": {
                    "raw_sha256": raw_sha256,
                    "raw_size": len(raw),
                    "parsed_sha256": output["parsed_sha256"],
                    "cas_blob": output.get("cas_blob"),
                }
            }
        )
    ).hexdigest()
    ref_semantic = {
        "provider_run_id": compiled.provider_plan.provider_run_id,
        "work_plan_digest": execution.work_plan_digest,
        "arm_digest": execution.provider_execution.arm_sha256,
        "completion_digest": (
            execution.provider_execution.completion_sha256
        ),
        "cas_manifest_digest": cas_manifest_digest,
    }
    worker_ref = {
        "ref_id": derive_stable_id("PFW", ref_semantic),
        **ref_semantic,
        "debt_digest": "",
        "incorporation_digest": "",
        "status": "COMPLETED",
        "process_scope_active_zero": True,
    }
    return ReconciledEvmExecution(
        raw_output=raw,
        raw_output_sha256=raw_sha256,
        raw_output_size=len(raw),
        parsed_output_sha256=str(output["parsed_sha256"]),
        worker_transaction_ref=worker_ref,
        completion=completion,
    )


__all__ = [
    "CompiledEvmWorkerTransaction",
    "EvmWtxDecision",
    "EvmWtxPhaseBindings",
    "InterpreterObservation",
    "ProgramFactsEvmWtxError",
    "ReconciledEvmExecution",
    "compile_evm_worker_transaction_structural_test_only",
    "execute_evm_worker_transaction",
    "plan_evm_worker_transaction",
    "reconcile_evm_worker_execution",
]
