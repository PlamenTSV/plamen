"""Deterministic Program Facts composition and resume validation.

The bake is a pure staging boundary.  Provider processes remain owned by
WorkerTransaction, and this module neither launches a process nor writes a
canonical artifact.  Its result is the exact three-file byte set that the
driver may publish only through the pre-bound ``recon/program_facts_bake``
PhaseIO transaction.
"""

from __future__ import annotations

from dataclasses import dataclass
import re
from types import MappingProxyType
from typing import Any, Mapping, Sequence

from program_facts_evm_provider import (
    EvmProgramFactsEmission,
    emit_evm_unavailable_sidecars,
)
from program_facts_evm_execution_set import (
    validate_execution_set_capture_inputs_v1,
    validate_frozen_build_plan_v1,
)
from program_facts_evm_tool_authority import (
    EvmToolAuthority,
    INSTALLED_PINNED_AUTHORITY,
)
from program_facts_provider_api import ProviderContext
from program_facts_provider_registry import (
    LoadedProgramFactsProviderRegistry,
)
from program_facts_positive_composer import (
    snapshot_sealed_composition_inputs_v1,
    validate_production_composition_candidate,
)
from program_facts_compatibility_delta import (
    validate_compatibility_delta_v1,
)
from program_facts_types import (
    ProgramFactsBundle,
    ProgramFactsTypeError,
    strict_json_loads,
    validate_program_facts_bundle,
)


PAYLOAD_PATH = "mechanical_program_facts.v1.json"
RECEIPT_PATH = "mechanical_program_facts_receipt.v1.json"
DEBT_PATH = "mechanical_program_facts_debt.v1.json"
PROGRAM_FACTS_SIDECAR_PATHS = (
    PAYLOAD_PATH,
    RECEIPT_PATH,
    DEBT_PATH,
)
_HEX64_RE = re.compile(r"^[0-9a-f]{64}$", re.ASCII)
_COMPATIBILITY_VALIDATION_INPUT_KEYS = frozenset(
    {
        "producer_bytes",
        "pre_runtime_manifest_bytes",
        "pre_r2_boundary_manifest",
        "post_runtime_manifest_bytes",
        "post_r2_runtime_manifest",
        "comparator_receipt_bytes",
        "comparator_receipt_binding",
        "compared_output_bytes",
        "component_registry_bytes",
        "component_registry_binding",
        "allowed_change_roster_bytes",
        "allowed_change_roster_binding",
        "semantic_review_bytes",
        "semantic_review_binding",
        "exclusion_authority_bytes",
        "exclusion_authority_binding",
        "trusted_review_keys",
        "runtime_closure_state",
    }
)


class ProgramFactsBakeError(RuntimeError):
    """The deterministic bake could not establish staging authority."""


def _fail(message: str, exc: BaseException | None = None) -> None:
    if exc is None:
        raise ProgramFactsBakeError(message)
    raise ProgramFactsBakeError(message) from exc


def _exact_sidecars(value: Mapping[str, bytes]) -> Mapping[str, bytes]:
    if not isinstance(value, Mapping) or set(value) != set(
        PROGRAM_FACTS_SIDECAR_PATHS
    ):
        _fail("Program Facts sidecar denominator is not the exact three files")
    normalized: dict[str, bytes] = {}
    for identity in PROGRAM_FACTS_SIDECAR_PATHS:
        raw = value.get(identity)
        if type(raw) is not bytes or not raw:
            _fail(f"{identity}: staged sidecar bytes are absent")
        normalized[identity] = bytes(raw)
    return MappingProxyType(normalized)


def _production_registry(
    value: LoadedProgramFactsProviderRegistry,
) -> LoadedProgramFactsProviderRegistry:
    if type(value) is not LoadedProgramFactsProviderRegistry:
        _fail("Program Facts bake requires exact provider-registry authority")
    try:
        value._assert_replayable()
    except Exception as exc:
        _fail("Program Facts provider registry failed replay", exc)
    if not value.production_authority_established:
        _fail("Program Facts bake registry is not installed production authority")
    return value


def _bind_context_to_registry(
    context: ProviderContext,
    registry: LoadedProgramFactsProviderRegistry,
) -> None:
    if type(context) is not ProviderContext:
        _fail("Program Facts bake requires an exact ProviderContext")
    mismatches = (
        context.audit_run_id != registry.audit_run_id,
        context.snapshot_digest != registry.snapshot_digest,
        context.source_scope_digest != registry.source_scope_digest,
        (
            context.methodology_authority_digest
            != registry.methodology_capture_digest
        ),
    )
    if any(mismatches):
        _fail("Program Facts context differs from installed registry capture")


@dataclass(frozen=True)
class ProgramFactsBakePlan:
    context: ProviderContext
    source_manifest: Mapping[str, Any]
    source_bytes_by_id: Mapping[str, bytes]
    build_variants: tuple[Mapping[str, Any], ...]
    audit_snapshot: Mapping[str, Any]
    phase_io: Mapping[str, Any]
    source_manifest_authority: Any
    audit_snapshot_authority: Any
    provider_registry: LoadedProgramFactsProviderRegistry
    tool_authority: EvmToolAuthority
    source_project_root: Any
    source_config: Mapping[str, Any]
    emission: EvmProgramFactsEmission

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "source_manifest",
            MappingProxyType(dict(self.source_manifest)),
        )
        object.__setattr__(
            self,
            "source_bytes_by_id",
            MappingProxyType(
                {
                    str(identity): bytes(raw)
                    for identity, raw in self.source_bytes_by_id.items()
                }
            ),
        )
        object.__setattr__(
            self,
            "build_variants",
            tuple(MappingProxyType(dict(row)) for row in self.build_variants),
        )
        object.__setattr__(
            self,
            "audit_snapshot",
            MappingProxyType(dict(self.audit_snapshot)),
        )
        object.__setattr__(
            self,
            "phase_io",
            MappingProxyType(dict(self.phase_io)),
        )
        object.__setattr__(
            self,
            "source_config",
            MappingProxyType(dict(self.source_config)),
        )


@dataclass(frozen=True)
class ProgramFactsBakeResult:
    bundle: ProgramFactsBundle
    sidecars: Mapping[str, bytes]
    reuse_key: str
    production_authority_established: bool = True
    consumer_activation: bool = False
    publication_authority: str = "STAGED_ONLY"

    def __post_init__(self) -> None:
        if type(self.bundle) is not ProgramFactsBundle:
            _fail("bake result requires an exact production bundle")
        object.__setattr__(self, "sidecars", _exact_sidecars(self.sidecars))
        if _HEX64_RE.fullmatch(self.reuse_key) is None:
            _fail("bake result reuse key is malformed")
        if self.consumer_activation or self.publication_authority != "STAGED_ONLY":
            _fail("Stage-2 Program Facts cannot activate a consumer or publish")


@dataclass(frozen=True)
class ProgramFactsResumeDecision:
    reusable: bool
    state: str
    reason: str
    blocks_reuse: bool
    bundle: ProgramFactsBundle | None = None


def plan_program_facts_bake(
    *,
    context: ProviderContext,
    source_manifest: Mapping[str, Any],
    source_bytes_by_id: Mapping[str, bytes],
    build_variants: Sequence[Mapping[str, Any]],
    audit_snapshot: Mapping[str, Any],
    phase_io: Mapping[str, Any],
    source_manifest_authority: Any,
    audit_snapshot_authority: Any,
    provider_registry: LoadedProgramFactsProviderRegistry,
    tool_authority: EvmToolAuthority,
    source_project_root: Any,
    source_config: Mapping[str, Any],
) -> ProgramFactsBakePlan:
    """Plan the emit-only EVM bake without process or publication authority."""

    registry = _production_registry(provider_registry)
    _bind_context_to_registry(context, registry)
    if context.ecosystem != "evm":
        _fail("Stage-2 Program Facts bake currently supports only EVM")
    if type(tool_authority) is not EvmToolAuthority:
        _fail("EVM bake requires exact tool authority")
    try:
        replayed_tool = tool_authority.replay()
    except Exception as exc:
        _fail("EVM tool authority failed replay", exc)
    if replayed_tool.authority_state != INSTALLED_PINNED_AUTHORITY:
        _fail("EVM tool authority is not installed pinned authority")
    if replayed_tool.production_ready:
        _fail(
            "semantic EVM execution requires a reconciled WorkerTransaction "
            "result; the unavailable compositor cannot consume a live tool"
        )
    reason = replayed_tool.unavailable_reason
    if reason != "PROVIDER_UNAVAILABLE":
        _fail("EVM tool authority returned an unsupported unavailable reason")
    try:
        emission = emit_evm_unavailable_sidecars(
            context=context,
            source_manifest=source_manifest,
            source_bytes_by_id=source_bytes_by_id,
            build_variants=build_variants,
            audit_snapshot=audit_snapshot,
            phase_io=phase_io,
            reason=reason,
            explanation=(
                "The pinned EVM helper is installed but semantic execution "
                "remains disabled pending independent provider review."
            ),
        )
    except Exception as exc:
        _fail("EVM unavailable bundle composition failed", exc)
    return ProgramFactsBakePlan(
        context=context,
        source_manifest=source_manifest,
        source_bytes_by_id=source_bytes_by_id,
        build_variants=tuple(build_variants),
        audit_snapshot=audit_snapshot,
        phase_io=phase_io,
        source_manifest_authority=source_manifest_authority,
        audit_snapshot_authority=audit_snapshot_authority,
        provider_registry=registry,
        tool_authority=replayed_tool,
        source_project_root=source_project_root,
        source_config=source_config,
        emission=emission,
    )


def compose_program_facts_bundle(
    plan: ProgramFactsBakePlan,
) -> ProgramFactsBakeResult:
    """Promote one schema-valid emission only after all production replays."""

    if type(plan) is not ProgramFactsBakePlan:
        _fail("Program Facts composition requires an exact bake plan")
    registry = _production_registry(plan.provider_registry)
    _bind_context_to_registry(plan.context, registry)
    sidecars = _exact_sidecars(plan.emission.sidecars)
    try:
        bundle = validate_program_facts_bundle(
            payload=plan.emission.payload,
            debt=plan.emission.debt,
            receipt=plan.emission.receipt,
            payload_file_bytes=sidecars[PAYLOAD_PATH],
            debt_file_bytes=sidecars[DEBT_PATH],
            receipt_file_bytes=sidecars[RECEIPT_PATH],
            source_bytes_by_id=plan.source_bytes_by_id,
            source_manifest_authority=plan.source_manifest_authority,
            audit_snapshot_authority=plan.audit_snapshot_authority,
            source_project_root=plan.source_project_root,
            source_config=plan.source_config,
            provider_registry=registry,
        )
    except Exception as exc:
        _fail("Program Facts production bundle failed authority replay", exc)
    return ProgramFactsBakeResult(
        bundle=bundle,
        sidecars=sidecars,
        reuse_key=str(bundle.receipt.value["reuse_key"]),
    )


def execute_program_facts_bake(
    plan: ProgramFactsBakePlan,
) -> ProgramFactsBakeResult:
    """Execute the deterministic composer; no native process is launched."""

    return compose_program_facts_bundle(plan)


def validate_program_facts_resume(
    *,
    sidecars: Mapping[str, bytes],
    expected_reuse_key: str,
    context: ProviderContext,
    source_bytes_by_id: Mapping[str, bytes],
    source_manifest_authority: Any,
    audit_snapshot_authority: Any,
    provider_registry: LoadedProgramFactsProviderRegistry,
    source_project_root: Any,
    source_config: Mapping[str, Any],
) -> ProgramFactsResumeDecision:
    """Side-effect-free exact-byte replay of an already staged/committed bake."""

    try:
        if _HEX64_RE.fullmatch(expected_reuse_key) is None:
            _fail("expected Program Facts reuse key is malformed")
        registry = _production_registry(provider_registry)
        _bind_context_to_registry(context, registry)
        exact = _exact_sidecars(sidecars)
        payload = strict_json_loads(
            exact[PAYLOAD_PATH],
            require_final_lf=True,
            require_canonical=True,
        )
        receipt = strict_json_loads(
            exact[RECEIPT_PATH],
            require_final_lf=True,
            require_canonical=True,
        )
        debt = strict_json_loads(
            exact[DEBT_PATH],
            require_final_lf=True,
            require_canonical=True,
        )
        if not all(type(value) is dict for value in (payload, receipt, debt)):
            _fail("Program Facts sidecar root is not an object")
        bundle = validate_program_facts_bundle(
            payload=payload,
            debt=debt,
            receipt=receipt,
            payload_file_bytes=exact[PAYLOAD_PATH],
            debt_file_bytes=exact[DEBT_PATH],
            receipt_file_bytes=exact[RECEIPT_PATH],
            source_bytes_by_id=source_bytes_by_id,
            source_manifest_authority=source_manifest_authority,
            audit_snapshot_authority=audit_snapshot_authority,
            source_project_root=source_project_root,
            source_config=source_config,
            provider_registry=registry,
        )
        actual_reuse_key = str(bundle.receipt.value["reuse_key"])
        if actual_reuse_key != expected_reuse_key:
            return ProgramFactsResumeDecision(
                reusable=False,
                state="STALE",
                reason="REUSE_KEY_MISMATCH",
                blocks_reuse=True,
            )
        snapshot_ref = bundle.payload.value["snapshot_ref"]
        if (
            snapshot_ref["snapshot_digest"] != context.snapshot_digest
            or snapshot_ref["source_scope_digest"]
            != context.source_scope_digest
            or snapshot_ref["source_manifest_digest"]
            != context.source_manifest_digest
        ):
            return ProgramFactsResumeDecision(
                reusable=False,
                state="STALE",
                reason="SNAPSHOT_OR_SOURCE_BINDING_MISMATCH",
                blocks_reuse=True,
            )
        status = str(bundle.receipt.value["status"])
        state = {
            "COMPLETE": "AVAILABLE",
            "DEGRADED": "DEGRADED",
            "UNAVAILABLE": "UNSUPPORTED",
        }[status]
        return ProgramFactsResumeDecision(
            reusable=True,
            state=state,
            reason="",
            blocks_reuse=False,
            bundle=bundle,
        )
    except (
        KeyError,
        ProgramFactsBakeError,
        ProgramFactsTypeError,
        TypeError,
        ValueError,
    ) as exc:
        return ProgramFactsResumeDecision(
            reusable=False,
            state="INVALID",
            reason=str(exc),
            blocks_reuse=True,
        )


def ensure_program_facts_bake(
    *,
    existing_sidecars: Mapping[str, bytes] | None,
    expected_reuse_key: str | None,
    **plan_inputs: Any,
) -> ProgramFactsBakeResult | ProgramFactsResumeDecision:
    """Reuse exact valid bytes or stage a new deterministic bake."""

    if existing_sidecars is not None and expected_reuse_key is not None:
        decision = validate_program_facts_resume(
            sidecars=existing_sidecars,
            expected_reuse_key=expected_reuse_key,
            context=plan_inputs["context"],
            source_bytes_by_id=plan_inputs["source_bytes_by_id"],
            source_manifest_authority=plan_inputs[
                "source_manifest_authority"
            ],
            audit_snapshot_authority=plan_inputs[
                "audit_snapshot_authority"
            ],
            provider_registry=plan_inputs["provider_registry"],
            source_project_root=plan_inputs["source_project_root"],
            source_config=plan_inputs["source_config"],
        )
        if decision.reusable:
            return decision
    return execute_program_facts_bake(plan_program_facts_bake(**plan_inputs))


def accept_program_facts_v2_production_candidate(
    candidate: object,
    *,
    sealed_composition_inputs: Mapping[str, Any],
    activation_permit_document: Mapping[str, Any],
    provider_environment: Mapping[str, Any],
    expected_run_id: str,
    expected_run_generation: int,
    expected_execution_authority_digest: str,
    expected_composition_authority_digest: str,
    expected_methodology_package_digest: str,
    expected_provider_environment_digest: str,
    expected_provider_package_digest: str,
    expected_native_host_receipt_digest: str,
    expected_independent_review_receipts: Mapping[str, str],
    expected_issuer_policy_digest: str,
    expected_issuer_id: str,
    expected_release_id: str,
    expected_activation_decision_digest: str,
) -> dict[str, Any]:
    """Purely replay an untrusted v2 production candidate.

    This seam does not compose, publish, stage, adopt, or otherwise integrate
    v2 bytes.  The later serialized bake/publication cut remains responsible
    for those operations.
    """

    return validate_production_composition_candidate(
        candidate,
        sealed_composition_inputs=sealed_composition_inputs,
        activation_permit_document=activation_permit_document,
        provider_environment=provider_environment,
        expected_run_id=expected_run_id,
        expected_run_generation=expected_run_generation,
        expected_execution_authority_digest=(
            expected_execution_authority_digest
        ),
        expected_composition_authority_digest=(
            expected_composition_authority_digest
        ),
        expected_methodology_package_digest=(
            expected_methodology_package_digest
        ),
        expected_provider_environment_digest=(
            expected_provider_environment_digest
        ),
        expected_provider_package_digest=expected_provider_package_digest,
        expected_native_host_receipt_digest=(
            expected_native_host_receipt_digest
        ),
        expected_independent_review_receipts=(
            expected_independent_review_receipts
        ),
        expected_issuer_policy_digest=expected_issuer_policy_digest,
        expected_issuer_id=expected_issuer_id,
        expected_release_id=expected_release_id,
        expected_activation_decision_digest=(
            expected_activation_decision_digest
        ),
    )


def validate_program_facts_v2_authority_graph_v1(
    *,
    candidate: object,
    sealed_composition_inputs: Mapping[str, Any],
    activation_permit_document: Mapping[str, Any],
    provider_environment: Mapping[str, Any],
    expected_run_id: str,
    expected_run_generation: int,
    expected_execution_authority_digest: str,
    expected_composition_authority_digest: str,
    expected_methodology_package_digest: str,
    expected_provider_environment_digest: str,
    expected_provider_package_digest: str,
    expected_native_host_receipt_digest: str,
    expected_independent_review_receipts: Mapping[str, str],
    expected_issuer_policy_digest: str,
    expected_issuer_id: str,
    expected_release_id: str,
    expected_activation_decision_digest: str,
    build_plan: Mapping[str, Any],
    expected_build_plan_digest: str,
    build_plan_ledger_binding: Mapping[str, Any],
    expected_children: Mapping[str, Any],
    terminal_roster: Mapping[str, Any],
    terminal_roster_ledger_state: str,
    terminal_ledger_rows: Sequence[Mapping[str, Any]],
    raw_cas_manifests: Mapping[str, bytes],
    expanded_inputs: Sequence[Mapping[str, Any]],
    compatibility_document: Mapping[str, Any],
    compatibility_validation_inputs: Mapping[str, Any],
) -> dict[str, Any]:
    """Replay the complete owned v2 authority graph without hidden state."""

    sealed_inputs_snapshot = snapshot_sealed_composition_inputs_v1(
        sealed_composition_inputs
    )
    plan = validate_frozen_build_plan_v1(
        build_plan,
        expected_build_plan_digest=expected_build_plan_digest,
        build_plan_ledger_binding=build_plan_ledger_binding,
    )
    if plan["run_id"] != expected_run_id:
        raise ProgramFactsTypeError("execution plan run_id diverges")
    if plan["run_generation"] != expected_run_generation:
        raise ProgramFactsTypeError("execution plan generation diverges")
    if (
        plan["execution_authority_digest"]
        != expected_execution_authority_digest
    ):
        raise ProgramFactsTypeError("execution plan authority diverges")
    if not isinstance(compatibility_validation_inputs, Mapping):
        raise ProgramFactsTypeError(
            "compatibility validation inputs must be an exact mapping"
        )
    if (
        frozenset(compatibility_validation_inputs)
        != _COMPATIBILITY_VALIDATION_INPUT_KEYS
    ):
        raise ProgramFactsTypeError(
            "compatibility validation input denominator is not exact"
        )
    replayed_candidate = validate_production_composition_candidate(
        candidate,
        sealed_composition_inputs=sealed_inputs_snapshot,
        activation_permit_document=activation_permit_document,
        provider_environment=provider_environment,
        expected_run_id=expected_run_id,
        expected_run_generation=expected_run_generation,
        expected_execution_authority_digest=(
            expected_execution_authority_digest
        ),
        expected_composition_authority_digest=(
            expected_composition_authority_digest
        ),
        expected_methodology_package_digest=(
            expected_methodology_package_digest
        ),
        expected_provider_environment_digest=(
            expected_provider_environment_digest
        ),
        expected_provider_package_digest=expected_provider_package_digest,
        expected_native_host_receipt_digest=(
            expected_native_host_receipt_digest
        ),
        expected_independent_review_receipts=(
            expected_independent_review_receipts
        ),
        expected_issuer_policy_digest=expected_issuer_policy_digest,
        expected_issuer_id=expected_issuer_id,
        expected_release_id=expected_release_id,
        expected_activation_decision_digest=(
            expected_activation_decision_digest
        ),
    )
    if list(plan["selected_variant_ids"]) != list(
        sealed_inputs_snapshot["selected_variant_ids"]
    ):
        raise ProgramFactsTypeError(
            "execution and candidate variant denominators diverge"
        )
    execution = validate_execution_set_capture_inputs_v1(
        build_plan=build_plan,
        expected_build_plan_digest=expected_build_plan_digest,
        build_plan_ledger_binding=build_plan_ledger_binding,
        expected_children=expected_children,
        terminal_roster=terminal_roster,
        terminal_roster_ledger_state=terminal_roster_ledger_state,
        terminal_ledger_rows=terminal_ledger_rows,
        raw_cas_manifests=raw_cas_manifests,
        expanded_inputs=expanded_inputs,
    )
    compatibility = validate_compatibility_delta_v1(
        compatibility_document,
        **dict(compatibility_validation_inputs),
    )
    return {
        "accepted": True,
        "build_plan_digest": execution["build_plan_digest"],
        "expected_wtx_children_digest": execution[
            "expected_wtx_children_digest"
        ],
        "terminal_wtx_roster_digest": execution[
            "terminal_wtx_roster_digest"
        ],
        "expanded_input_count": execution["expanded_input_count"],
        "raw_cas_leaf_denominator_digest": execution[
            "raw_cas_leaf_denominator_digest"
        ],
        "compatibility_receipt_body_sha256": compatibility[
            "receipt_body_sha256"
        ],
        "candidate_digest": replayed_candidate["candidate_digest"],
    }


__all__ = [
    "accept_program_facts_v2_production_candidate",
    "DEBT_PATH",
    "PAYLOAD_PATH",
    "PROGRAM_FACTS_SIDECAR_PATHS",
    "ProgramFactsBakeError",
    "ProgramFactsBakePlan",
    "ProgramFactsBakeResult",
    "ProgramFactsResumeDecision",
    "RECEIPT_PATH",
    "compose_program_facts_bundle",
    "ensure_program_facts_bake",
    "execute_program_facts_bake",
    "plan_program_facts_bake",
    "validate_program_facts_v2_authority_graph_v1",
    "validate_program_facts_resume",
]
