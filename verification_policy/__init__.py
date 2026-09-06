"""Shared, immutable verification execution policy (P0-AH substrate).

This module is intentionally side-effect free.  It does not read markdown, invoke a
runner, mutate a scratchpad, or depend on either backend adapter.  Driver wiring is a
separate cutover: both the hard PoC contract and the soft coverage audit can consume
the same policy and receipt records without either becoming the policy authority.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, is_dataclass
from enum import Enum
from hashlib import sha256
import json
from pathlib import PurePosixPath, PureWindowsPath
from typing import Any, Iterable, Optional, Sequence


SCHEMA_VERSION = "verification-execution-policy/v1"


class AuditMode(str, Enum):
    LIGHT = "light"
    CORE = "core"
    THOROUGH = "thorough"


class Backend(str, Enum):
    CLAUDE = "claude"
    CODEX = "codex"


class Pipeline(str, Enum):
    SC = "sc"
    L1 = "l1"


class Ecosystem(str, Enum):
    EVM = "evm"
    SOLANA = "solana"
    APTOS = "aptos"
    SUI = "sui"
    SOROBAN = "soroban"
    GO = "go"
    RUST = "rust"


class Platform(str, Enum):
    WINDOWS = "windows"
    POSIX = "posix"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class ClaimClass(str, Enum):
    UNIT = "unit"
    PROPERTY = "property"
    INTEGRATION = "integration"
    STRUCTURAL = "structural"
    SPEC = "spec"
    DOCS = "docs"


class Decision(str, Enum):
    ATTEMPT_REQUIRED = "attempt_required"
    OPTIONAL_BY_MODE = "optional_by_mode"
    BLOCKED_UNPROVEN = "blocked_unproven"


class ProofScope(str, Enum):
    UNPROVEN = "unproven"
    MECHANISM = "mechanism"
    HARM = "harm"


class AttemptResult(str, Enum):
    NOT_ATTEMPTED = "not_attempted"
    COMPILE_FAILED = "compile_failed"
    RUN_FAILED = "run_failed"
    ASSERTION_FAILED = "assertion_failed"
    MECHANISM_CONFIRMED = "mechanism_confirmed"
    HARM_CONFIRMED = "harm_confirmed"
    BUDGET_EXHAUSTED = "budget_exhausted"


class BlockerAuthority(str, Enum):
    VERIFIER = "verifier"
    DRIVER = "driver"
    ENVIRONMENT_PROBE = "environment_probe"
    INDEPENDENT_ADJUDICATOR = "independent_adjudicator"


class BlockerCode(str, Enum):
    NO_BUILD_ENVIRONMENT = "no_build_environment"
    EXTERNAL_DEPENDENCY_NO_FORK_OR_ADDRESS = (
        "external_dependency_no_fork_or_address"
    )
    DEPLOYMENT_ONLY_REQUIRES_LIVE_EXTERNAL = (
        "deployment_only_requires_live_external"
    )
    PURE_SPEC_OR_DOCS_ONLY = "pure_spec_or_docs_only"
    STRUCTURAL_NO_EXECUTABLE_HARM_ASSERTION = (
        "structural_no_executable_harm_assertion"
    )
    CROSS_VM_ENCODING_NO_RUNTIME = "cross_vm_encoding_no_runtime"
    DEPLOY_OR_TX_ORDERING = "deploy_or_tx_ordering"
    EXTERNAL_DEP_NO_FORK = "external_dep_no_fork"
    LIVE_ARTIFACT_REQUIRED = "live_artifact_required"
    SPEC_DOCS_NO_STATE_DELTA = "spec_docs_no_state_delta"


_SC_ECOSYSTEMS = frozenset(
    {
        Ecosystem.EVM,
        Ecosystem.SOLANA,
        Ecosystem.APTOS,
        Ecosystem.SUI,
        Ecosystem.SOROBAN,
    }
)
_L1_ECOSYSTEMS = frozenset({Ecosystem.GO, Ecosystem.RUST})
_MEDIUM_PLUS = (
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
)
_ALL_SEVERITIES = _MEDIUM_PLUS + (Severity.LOW, Severity.INFORMATIONAL)
_HEX = frozenset("0123456789abcdef")


def _enum_or_value(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if is_dataclass(value):
        return _enum_or_value(asdict(value))
    if isinstance(value, dict):
        return {
            str(_enum_or_value(key)): _enum_or_value(item)
            for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))
        }
    if isinstance(value, (tuple, list, set, frozenset)):
        return [_enum_or_value(item) for item in value]
    return value


def _digest(payload: Any) -> str:
    encoded = json.dumps(
        _enum_or_value(payload), sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return sha256(encoded).hexdigest()


def _valid_digest(value: str) -> bool:
    normalized = value.lower()
    return len(normalized) == 64 and all(char in _HEX for char in normalized)


@dataclass(frozen=True)
class ExecutionPolicy:
    schema_version: str
    mode: AuditMode
    backend: Backend
    pipeline: Pipeline
    ecosystem: Ecosystem
    platform: Platform
    attempt_severities: tuple[Severity, ...]
    fuzz_severities: tuple[Severity, ...]
    max_attempts_per_row: int
    policy_digest: str

    def __post_init__(self) -> None:
        expected_attempts = (
            _ALL_SEVERITIES if self.mode is AuditMode.THOROUGH else _MEDIUM_PLUS
        )
        expected_fuzz = _MEDIUM_PLUS if self.mode is AuditMode.THOROUGH else ()
        expected_budget = {
            AuditMode.LIGHT: 1,
            AuditMode.CORE: 3,
            AuditMode.THOROUGH: 5,
        }[self.mode]
        if self.attempt_severities != expected_attempts:
            raise ValueError("execution severities do not match the audit-mode policy")
        if self.fuzz_severities != expected_fuzz:
            raise ValueError("fuzz severities do not match the audit-mode policy")
        if self.max_attempts_per_row != expected_budget:
            raise ValueError("attempt budget does not match the audit-mode policy")
        if self.pipeline is Pipeline.SC and self.ecosystem not in _SC_ECOSYSTEMS:
            raise ValueError("invalid smart-contract ecosystem projection")
        if self.pipeline is Pipeline.L1 and self.ecosystem not in _L1_ECOSYSTEMS:
            raise ValueError("invalid L1 ecosystem projection")
        payload = {
            "schema_version": self.schema_version,
            "mode": self.mode,
            "backend": self.backend,
            "pipeline": self.pipeline,
            "ecosystem": self.ecosystem,
            "platform": self.platform,
            "attempt_severities": self.attempt_severities,
            "fuzz_severities": self.fuzz_severities,
            "max_attempts_per_row": self.max_attempts_per_row,
        }
        if self.policy_digest != _digest(payload):
            raise ValueError("policy digest does not match the immutable record")

    def requires_attempt(self, severity: Severity) -> bool:
        return severity in self.attempt_severities

    def requires_fuzz(self, severity: Severity) -> bool:
        return severity in self.fuzz_severities


@dataclass(frozen=True)
class VerificationWorkItem:
    finding_id: str
    constituent_id: str
    severity: Severity
    claim_class: ClaimClass
    locally_testable: bool
    harness_available: bool
    group_id: str = ""

    def __post_init__(self) -> None:
        if not self.finding_id.strip():
            raise ValueError("finding_id is required")
        if not self.constituent_id.strip():
            raise ValueError("constituent_id is required")

    @property
    def key(self) -> str:
        return f"{self.finding_id}::{self.constituent_id}"


@dataclass(frozen=True)
class ExecutionBlocker:
    code: BlockerCode
    authority: BlockerAuthority
    evidence_digest: str
    evidence_refs: tuple[str, ...]
    independently_validated: bool
    validated_by: Optional[BlockerAuthority] = None

    def __post_init__(self) -> None:
        if not _valid_digest(self.evidence_digest):
            raise ValueError("blocker evidence_digest must be a SHA-256 digest")
        if not self.evidence_refs or any(not ref.strip() for ref in self.evidence_refs):
            raise ValueError("blocker requires at least one concrete evidence reference")


@dataclass(frozen=True)
class ExecutionObligation:
    work_item_key: str
    policy_digest: str
    decision: Decision
    proof_scope: ProofScope
    fuzz_required: bool
    blocker: Optional[ExecutionBlocker] = None
    debts: tuple[str, ...] = ()


@dataclass(frozen=True)
class ExecutionReceipt:
    finding_id: str
    constituent_id: str
    policy_digest: str
    decision: Decision
    attempted: bool
    attempt_number: Optional[int]
    result: AttemptResult
    proof_scope: ProofScope
    command_argv: tuple[str, ...]
    runner_id: str
    output_digest: str
    blocker: Optional[ExecutionBlocker]
    debts: tuple[str, ...]
    receipt_digest: str

    def __post_init__(self) -> None:
        if not self.finding_id.strip() or not self.constituent_id.strip():
            raise ValueError("receipt identity is required")
        if not _valid_digest(self.policy_digest):
            raise ValueError("receipt policy_digest must be a SHA-256 digest")
        if not _valid_digest(self.receipt_digest):
            raise ValueError("receipt_digest must be a SHA-256 digest")
        payload = {
            "finding_id": self.finding_id,
            "constituent_id": self.constituent_id,
            "policy_digest": self.policy_digest,
            "decision": self.decision,
            "attempted": self.attempted,
            "attempt_number": self.attempt_number,
            "result": self.result,
            "proof_scope": self.proof_scope,
            "command_argv": self.command_argv,
            "runner_id": self.runner_id,
            "output_digest": self.output_digest,
            "blocker": self.blocker,
            "debts": self.debts,
        }
        if self.receipt_digest != _digest(payload):
            raise ValueError("receipt digest does not match the immutable record")
        if self.attempted:
            if self.attempt_number is None or self.attempt_number < 1:
                raise ValueError("attempted receipt requires a positive attempt number")
            if not self.command_argv or any(not part for part in self.command_argv):
                raise ValueError("attempted receipt requires non-empty argv")
            if not self.runner_id.strip():
                raise ValueError("attempted receipt requires a runner_id")
            if not _valid_digest(self.output_digest):
                raise ValueError("attempted receipt requires an output digest")
        elif self.command_argv or self.runner_id or self.output_digest:
            raise ValueError("non-execution receipt cannot claim runner output")

        if self.result in {AttemptResult.COMPILE_FAILED, AttemptResult.RUN_FAILED}:
            if not self.attempted:
                raise ValueError("compile/run failure requires an execution attempt")
            if self.proof_scope is not ProofScope.UNPROVEN:
                raise ValueError(
                    "compile/run failure cannot establish mechanism or harm proof"
                )
        if self.proof_scope is ProofScope.HARM and self.result is not AttemptResult.HARM_CONFIRMED:
            raise ValueError("harm proof requires an executed harm-confirmed result")
        if self.result is AttemptResult.ASSERTION_FAILED:
            if not self.attempted or self.proof_scope is not ProofScope.MECHANISM:
                raise ValueError("assertion failure is mechanism-scoped only")
        if self.result is AttemptResult.MECHANISM_CONFIRMED:
            if not self.attempted or self.proof_scope is not ProofScope.MECHANISM:
                raise ValueError("mechanism confirmation requires mechanism proof scope")
        if self.result is AttemptResult.HARM_CONFIRMED:
            if not self.attempted or self.proof_scope is not ProofScope.HARM:
                raise ValueError("harm confirmation requires an executed harm oracle")
        if self.decision is Decision.BLOCKED_UNPROVEN:
            if self.attempted or self.blocker is None:
                raise ValueError("blocked receipt requires an unexecuted typed blocker")
            if self.proof_scope is not ProofScope.UNPROVEN:
                raise ValueError("blocked receipt must remain UNPROVEN")
            if (
                not self.blocker.independently_validated
                or self.blocker.validated_by is None
                or self.blocker.validated_by is self.blocker.authority
            ):
                raise ValueError("blocked receipt requires independent blocker authority")
        if (
            self.decision is Decision.ATTEMPT_REQUIRED
            and not self.attempted
            and self.result is not AttemptResult.BUDGET_EXHAUSTED
        ):
            raise ValueError("required attempt cannot have a silent non-execution receipt")
        if self.result is AttemptResult.NOT_ATTEMPTED and self.attempted:
            raise ValueError("NOT_ATTEMPTED cannot claim execution")
        if self.result is AttemptResult.BUDGET_EXHAUSTED:
            if self.attempted or "BUDGET_EXHAUSTED" not in self.debts:
                raise ValueError("budget exhaustion must be an unexecuted visible debt")

    @property
    def key(self) -> str:
        return f"{self.finding_id}::{self.constituent_id}"


@dataclass(frozen=True)
class RetryPlan:
    should_attempt: bool
    next_attempt_number: Optional[int]
    reuse_receipt_digest: str = ""
    budget_exhausted: bool = False


@dataclass(frozen=True)
class ReceiptReconciliation:
    policy_digest: str
    queue_count: int
    receipt_count: int
    coverage_complete: bool
    missing_keys: tuple[str, ...]
    extra_keys: tuple[str, ...]
    duplicate_keys: tuple[str, ...]
    debts: tuple[str, ...]
    reconciliation_digest: str


@dataclass(frozen=True)
class RunnerSpec:
    ecosystem: Ecosystem
    platform: Platform
    runner_id: str
    command_argv: tuple[str, ...]


def resolve_execution_policy(
    mode: AuditMode,
    backend: Backend,
    pipeline: Pipeline,
    ecosystem: Ecosystem,
    platform: Platform,
) -> ExecutionPolicy:
    """Resolve one policy; projections are metadata, never severity authorities."""

    if pipeline is Pipeline.SC and ecosystem not in _SC_ECOSYSTEMS:
        raise ValueError(f"{ecosystem.value} is not a smart-contract projection")
    if pipeline is Pipeline.L1 and ecosystem not in _L1_ECOSYSTEMS:
        raise ValueError(f"{ecosystem.value} is not an L1 projection")

    attempts = _ALL_SEVERITIES if mode is AuditMode.THOROUGH else _MEDIUM_PLUS
    fuzz = _MEDIUM_PLUS if mode is AuditMode.THOROUGH else ()
    budgets = {
        AuditMode.LIGHT: 1,
        AuditMode.CORE: 3,
        AuditMode.THOROUGH: 5,
    }
    payload = {
        "schema_version": SCHEMA_VERSION,
        "mode": mode,
        "backend": backend,
        "pipeline": pipeline,
        "ecosystem": ecosystem,
        "platform": platform,
        "attempt_severities": attempts,
        "fuzz_severities": fuzz,
        "max_attempts_per_row": budgets[mode],
    }
    return ExecutionPolicy(
        **payload,
        policy_digest=_digest(payload),
    )


def _blocker_validation_error(
    work_item: VerificationWorkItem, blocker: ExecutionBlocker
) -> str:
    if not blocker.independently_validated or blocker.validated_by is None:
        return "blocker lacks independent validation"
    if blocker.validated_by is blocker.authority:
        return "blocker proposer cannot validate its own non-execution decision"
    if work_item.locally_testable and work_item.harness_available:
        return "a locally testable row cannot be waived"

    if blocker.code in {
        BlockerCode.PURE_SPEC_OR_DOCS_ONLY,
        BlockerCode.SPEC_DOCS_NO_STATE_DELTA,
    }:
        if work_item.claim_class not in {ClaimClass.SPEC, ClaimClass.DOCS}:
            return "spec/docs blocker does not match claim class"
        return ""

    if blocker.code is BlockerCode.STRUCTURAL_NO_EXECUTABLE_HARM_ASSERTION:
        if work_item.claim_class is not ClaimClass.STRUCTURAL:
            return "structural blocker does not match claim class"
        return ""

    environment_codes = {
        BlockerCode.NO_BUILD_ENVIRONMENT,
        BlockerCode.EXTERNAL_DEPENDENCY_NO_FORK_OR_ADDRESS,
        BlockerCode.DEPLOYMENT_ONLY_REQUIRES_LIVE_EXTERNAL,
        BlockerCode.CROSS_VM_ENCODING_NO_RUNTIME,
        BlockerCode.DEPLOY_OR_TX_ORDERING,
        BlockerCode.EXTERNAL_DEP_NO_FORK,
        BlockerCode.LIVE_ARTIFACT_REQUIRED,
    }
    if blocker.code in environment_codes:
        if work_item.harness_available:
            return "environment blocker conflicts with available harness"
        return ""
    return "unknown blocker classification"


def evaluate_obligation(
    policy: ExecutionPolicy,
    work_item: VerificationWorkItem,
    blocker: Optional[ExecutionBlocker] = None,
) -> ExecutionObligation:
    """Determine execution coverage without deciding the finding's verdict."""

    if not policy.requires_attempt(work_item.severity):
        return ExecutionObligation(
            work_item_key=work_item.key,
            policy_digest=policy.policy_digest,
            decision=Decision.OPTIONAL_BY_MODE,
            proof_scope=ProofScope.UNPROVEN,
            fuzz_required=False,
        )

    debts: tuple[str, ...] = ()
    if blocker is not None:
        error = _blocker_validation_error(work_item, blocker)
        if not error:
            return ExecutionObligation(
                work_item_key=work_item.key,
                policy_digest=policy.policy_digest,
                decision=Decision.BLOCKED_UNPROVEN,
                proof_scope=ProofScope.UNPROVEN,
                fuzz_required=False,
                blocker=blocker,
            )
        debts = ("INVALID_BLOCKER", error)

    return ExecutionObligation(
        work_item_key=work_item.key,
        policy_digest=policy.policy_digest,
        decision=Decision.ATTEMPT_REQUIRED,
        proof_scope=ProofScope.UNPROVEN,
        fuzz_required=(
            work_item.claim_class in {ClaimClass.UNIT, ClaimClass.PROPERTY}
            and policy.requires_fuzz(work_item.severity)
        ),
        debts=debts,
    )


def _receipt_payload(
    policy: ExecutionPolicy,
    work_item: VerificationWorkItem,
    obligation: ExecutionObligation,
    *,
    attempted: bool,
    attempt_number: Optional[int],
    result: AttemptResult,
    proof_scope: ProofScope,
    command_argv: tuple[str, ...],
    runner_id: str,
    output_digest: str,
    debts: tuple[str, ...],
) -> dict[str, Any]:
    if obligation.policy_digest != policy.policy_digest:
        raise ValueError("obligation belongs to a different policy")
    if obligation.work_item_key != work_item.key:
        raise ValueError("obligation belongs to a different work item")
    return {
        "finding_id": work_item.finding_id,
        "constituent_id": work_item.constituent_id,
        "policy_digest": policy.policy_digest,
        "decision": obligation.decision,
        "attempted": attempted,
        "attempt_number": attempt_number,
        "result": result,
        "proof_scope": proof_scope,
        "command_argv": command_argv,
        "runner_id": runner_id,
        "output_digest": output_digest,
        "blocker": obligation.blocker,
        "debts": debts,
    }


def _build_receipt(payload: dict[str, Any]) -> ExecutionReceipt:
    return ExecutionReceipt(**payload, receipt_digest=_digest(payload))


def make_execution_receipt(
    policy: ExecutionPolicy,
    work_item: VerificationWorkItem,
    obligation: ExecutionObligation,
    *,
    attempt_number: int,
    command_argv: Sequence[str],
    runner_id: str,
    result: AttemptResult,
    proof_scope: ProofScope,
    output_digest: str,
) -> ExecutionReceipt:
    if obligation.decision is Decision.BLOCKED_UNPROVEN:
        raise ValueError("a blocked obligation cannot claim execution")
    if result in {AttemptResult.NOT_ATTEMPTED, AttemptResult.BUDGET_EXHAUSTED}:
        raise ValueError("execution receipt requires an execution result")
    payload = _receipt_payload(
        policy,
        work_item,
        obligation,
        attempted=True,
        attempt_number=attempt_number,
        result=result,
        proof_scope=proof_scope,
        command_argv=tuple(command_argv),
        runner_id=runner_id,
        output_digest=output_digest,
        debts=obligation.debts,
    )
    return _build_receipt(payload)


def make_nonexecution_receipt(
    policy: ExecutionPolicy,
    work_item: VerificationWorkItem,
    obligation: ExecutionObligation,
) -> ExecutionReceipt:
    if obligation.decision is Decision.ATTEMPT_REQUIRED:
        raise ValueError("required attempt needs execution or an explicit budget debt")
    payload = _receipt_payload(
        policy,
        work_item,
        obligation,
        attempted=False,
        attempt_number=None,
        result=AttemptResult.NOT_ATTEMPTED,
        proof_scope=ProofScope.UNPROVEN,
        command_argv=(),
        runner_id="",
        output_digest="",
        debts=obligation.debts,
    )
    return _build_receipt(payload)


def make_budget_exhausted_receipt(
    policy: ExecutionPolicy,
    work_item: VerificationWorkItem,
    obligation: ExecutionObligation,
    *,
    attempts_consumed: int,
) -> ExecutionReceipt:
    if obligation.decision is not Decision.ATTEMPT_REQUIRED:
        raise ValueError("only a required attempt can create execution debt")
    if attempts_consumed < policy.max_attempts_per_row:
        raise ValueError("attempt budget is not exhausted")
    debts = tuple(dict.fromkeys((*obligation.debts, "BUDGET_EXHAUSTED")))
    payload = _receipt_payload(
        policy,
        work_item,
        obligation,
        attempted=False,
        attempt_number=None,
        result=AttemptResult.BUDGET_EXHAUSTED,
        proof_scope=ProofScope.UNPROVEN,
        command_argv=(),
        runner_id="",
        output_digest="",
        debts=debts,
    )
    return _build_receipt(payload)


def plan_retry(
    policy: ExecutionPolicy,
    work_item: VerificationWorkItem,
    prior_receipts: Iterable[ExecutionReceipt],
) -> RetryPlan:
    matching = tuple(
        receipt
        for receipt in prior_receipts
        if receipt.key == work_item.key
        and receipt.policy_digest == policy.policy_digest
    )
    reusable_results = {
        AttemptResult.ASSERTION_FAILED,
        AttemptResult.MECHANISM_CONFIRMED,
        AttemptResult.HARM_CONFIRMED,
    }
    reusable = tuple(
        receipt
        for receipt in matching
        if receipt.attempted and receipt.result in reusable_results
    )
    if reusable:
        selected = max(reusable, key=lambda receipt: receipt.attempt_number or 0)
        return RetryPlan(
            should_attempt=False,
            next_attempt_number=None,
            reuse_receipt_digest=selected.receipt_digest,
        )

    attempts = sum(1 for receipt in matching if receipt.attempted)
    if attempts >= policy.max_attempts_per_row:
        return RetryPlan(
            should_attempt=False,
            next_attempt_number=None,
            budget_exhausted=True,
        )
    return RetryPlan(should_attempt=True, next_attempt_number=attempts + 1)


def reconcile_receipts(
    policy: ExecutionPolicy,
    queue: Iterable[VerificationWorkItem],
    receipts: Iterable[ExecutionReceipt],
) -> ReceiptReconciliation:
    queue_rows = tuple(queue)
    receipt_rows = tuple(receipts)
    queue_keys = tuple(row.key for row in queue_rows)
    receipt_keys = tuple(row.key for row in receipt_rows)
    queue_set = set(queue_keys)
    receipt_set = set(receipt_keys)

    missing = tuple(sorted(queue_set - receipt_set))
    extra = tuple(sorted(receipt_set - queue_set))
    duplicate = tuple(
        sorted(key for key in receipt_set if receipt_keys.count(key) > 1)
    )
    duplicate_queue = tuple(
        sorted(key for key in queue_set if queue_keys.count(key) > 1)
    )

    debts: list[str] = []
    debts.extend(f"MISSING_RECEIPT:{key}" for key in missing)
    debts.extend(f"EXTRA_RECEIPT:{key}" for key in extra)
    debts.extend(f"DUPLICATE_RECEIPT:{key}" for key in duplicate)
    debts.extend(f"DUPLICATE_QUEUE_ROW:{key}" for key in duplicate_queue)
    queue_by_key = {row.key: row for row in queue_rows}
    for receipt in receipt_rows:
        if receipt.policy_digest != policy.policy_digest:
            debts.append(f"POLICY_DIGEST_MISMATCH:{receipt.key}")
        queued = queue_by_key.get(receipt.key)
        if queued is not None:
            expected = evaluate_obligation(policy, queued, receipt.blocker)
            if expected.decision is not receipt.decision:
                debts.append(f"POLICY_DECISION_MISMATCH:{receipt.key}")
        debts.extend(receipt.debts)

    normalized_debts = tuple(sorted(set(debts)))
    hard_debt = any(
        debt == "BUDGET_EXHAUSTED"
        or debt.startswith(
            (
                "MISSING_RECEIPT:",
                "EXTRA_RECEIPT:",
                "DUPLICATE_RECEIPT:",
                "DUPLICATE_QUEUE_ROW:",
                "POLICY_DIGEST_MISMATCH:",
                "POLICY_DECISION_MISMATCH:",
            )
        )
        for debt in normalized_debts
    )
    coverage_complete = not hard_debt
    payload = {
        "schema_version": SCHEMA_VERSION,
        "policy_digest": policy.policy_digest,
        "queue_keys": sorted(queue_keys),
        "receipt_digests": sorted(row.receipt_digest for row in receipt_rows),
        "missing_keys": missing,
        "extra_keys": extra,
        "duplicate_keys": duplicate,
        "debts": normalized_debts,
        "coverage_complete": coverage_complete,
    }
    return ReceiptReconciliation(
        policy_digest=policy.policy_digest,
        queue_count=len(queue_rows),
        receipt_count=len(receipt_rows),
        coverage_complete=coverage_complete,
        missing_keys=missing,
        extra_keys=extra,
        duplicate_keys=duplicate,
        debts=normalized_debts,
        reconciliation_digest=_digest(payload),
    )


def runner_spec(
    ecosystem: Ecosystem,
    platform: Platform,
    test_file: str,
    *,
    selector: str,
) -> RunnerSpec:
    """Return inert argv metadata; execution remains owned by the driver."""

    if not test_file.strip() or not selector.strip():
        raise ValueError("test_file and selector are required")
    path_type = PureWindowsPath if platform is Platform.WINDOWS else PurePosixPath
    path = path_type(test_file)
    parent = path.parent
    manifest = parent / "Cargo.toml"

    if ecosystem is Ecosystem.EVM:
        runner_id = "evm-forge"
        argv = ("forge", "test", "--match-path", str(path))
    elif ecosystem in {Ecosystem.SOLANA, Ecosystem.SOROBAN, Ecosystem.RUST}:
        runner_id = f"{ecosystem.value}-cargo"
        argv = (
            "cargo",
            "test",
            "--manifest-path",
            str(manifest),
            selector,
        )
    elif ecosystem is Ecosystem.APTOS:
        runner_id = "aptos-move"
        argv = ("aptos", "move", "test", "--package-dir", str(parent))
    elif ecosystem is Ecosystem.SUI:
        runner_id = "sui-move"
        argv = ("sui", "move", "test", "--path", str(parent))
    elif ecosystem is Ecosystem.GO:
        runner_id = "go-test"
        argv = ("go", "test", "./...", "-run", selector)
    else:  # Enum exhaustiveness guard for future ecosystems.
        raise ValueError(f"no generic runner projection for {ecosystem.value}")
    return RunnerSpec(
        ecosystem=ecosystem,
        platform=platform,
        runner_id=runner_id,
        command_argv=argv,
    )


__all__ = [
    "AttemptResult",
    "AuditMode",
    "Backend",
    "BlockerAuthority",
    "BlockerCode",
    "ClaimClass",
    "Decision",
    "Ecosystem",
    "ExecutionBlocker",
    "ExecutionObligation",
    "ExecutionPolicy",
    "ExecutionReceipt",
    "Pipeline",
    "Platform",
    "ProofScope",
    "ReceiptReconciliation",
    "RetryPlan",
    "RunnerSpec",
    "Severity",
    "VerificationWorkItem",
    "evaluate_obligation",
    "make_budget_exhausted_receipt",
    "make_execution_receipt",
    "make_nonexecution_receipt",
    "plan_retry",
    "reconcile_receipts",
    "resolve_execution_policy",
    "runner_spec",
]
