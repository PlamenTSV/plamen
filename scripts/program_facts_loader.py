"""Strict ledger-bound loader for the three Program Facts sidecars."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping

from artifact_ledger import validate_work_unit_artifacts
from phase_io_contracts import LaunchSpec, PhaseIOContract
from program_facts_bake import (
    PROGRAM_FACTS_SIDECAR_PATHS,
    ProgramFactsResumeDecision,
    validate_program_facts_resume,
)
from program_facts_provider_api import ProviderContext
from program_facts_provider_registry import LoadedProgramFactsProviderRegistry
from program_facts_types import (
    ProgramFactsBundle,
    ProgramFactsTypeError,
    strict_json_loads,
)
import rooted_path_io


@dataclass(frozen=True)
class LoadedProgramFacts:
    state: str
    valid: bool
    reusable: bool
    blocks_reuse: bool
    reason_codes: tuple[str, ...]
    sidecars: Mapping[str, bytes]
    bundle: ProgramFactsBundle | None = None
    consumer_activation: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "sidecars",
            MappingProxyType(
                {
                    str(identity): bytes(raw)
                    for identity, raw in self.sidecars.items()
                }
            ),
        )
        object.__setattr__(self, "reason_codes", tuple(self.reason_codes))
        if self.consumer_activation:
            raise ValueError("Stage-2 Program Facts loader cannot activate consumers")


def _invalid(*reasons: str) -> LoadedProgramFacts:
    normalized = tuple(
        sorted({str(reason).strip() for reason in reasons if str(reason).strip()})
    )
    return LoadedProgramFacts(
        state="INVALID",
        valid=False,
        reusable=False,
        blocks_reuse=True,
        reason_codes=normalized or ("PROGRAM_FACTS_INVALID",),
        sidecars={},
    )


def _contract_issues(
    contract: PhaseIOContract,
    launch: LaunchSpec,
) -> tuple[str, ...]:
    if type(contract) is not PhaseIOContract or type(launch) is not LaunchSpec:
        return ("PROGRAM_FACTS_PHASEIO_AUTHORITY_TYPE_INVALID",)
    issues: list[str] = []
    if contract.phase != "recon" or contract.work_unit_id != "program_facts_bake":
        issues.append("PROGRAM_FACTS_PHASEIO_UNIT_MISMATCH")
    if contract.model_invoked:
        issues.append("PROGRAM_FACTS_PHASEIO_MODEL_AUTHORITY_FORBIDDEN")
    if contract.required_commit_actor != "DRIVER":
        issues.append("PROGRAM_FACTS_PHASEIO_DRIVER_AUTHORITY_MISSING")
    if tuple(output.path for output in contract.outputs) != (
        PROGRAM_FACTS_SIDECAR_PATHS
    ):
        issues.append("PROGRAM_FACTS_OUTPUT_DENOMINATOR_MISMATCH")
    if launch.work_unit_key != contract.key:
        issues.append("PROGRAM_FACTS_LAUNCH_CONTRACT_MISMATCH")
    return tuple(issues)


def load_bound_program_facts(
    *,
    scratchpad: Path,
    project_root: Path,
    contract: PhaseIOContract,
    launch: LaunchSpec,
    run_id: str,
    context: ProviderContext,
    source_bytes_by_id: Mapping[str, bytes],
    source_manifest_authority: Any,
    audit_snapshot_authority: Any,
    provider_registry: LoadedProgramFactsProviderRegistry,
    source_project_root: Any,
    source_config: Mapping[str, Any],
) -> LoadedProgramFacts:
    """Load only bytes owned by one live, exact PhaseIO commit.

    Every failure becomes explicit invalid/reuse-blocking state.  Missing,
    stale, or malformed sidecars never mean an empty clean fact set.
    """

    contract_issues = _contract_issues(contract, launch)
    if contract_issues:
        return _invalid(*contract_issues)
    try:
        ledger_issues = validate_work_unit_artifacts(
            Path(scratchpad),
            Path(project_root),
            contract,
            launch,
            run_id=run_id,
            actor="DRIVER",
        )
    except Exception as exc:
        return _invalid(f"PROGRAM_FACTS_LEDGER_REPLAY_FAILED:{exc}")
    if ledger_issues:
        return _invalid(
            *(f"PROGRAM_FACTS_LEDGER:{issue}" for issue in ledger_issues)
        )

    sidecars: dict[str, bytes] = {}
    try:
        for identity in PROGRAM_FACTS_SIDECAR_PATHS:
            path = rooted_path_io.safe_descendant(
                Path(scratchpad),
                identity,
                allow_missing=False,
                label=f"Program Facts sidecar {identity}",
            )
            sidecars[identity] = rooted_path_io.read_bytes(
                path,
                label=f"Program Facts sidecar {identity}",
                require_single_link=False,
            )
        receipt = strict_json_loads(
            sidecars["mechanical_program_facts_receipt.v1.json"],
            require_final_lf=True,
            require_canonical=True,
        )
        if type(receipt) is not dict:
            return _invalid("PROGRAM_FACTS_RECEIPT_ROOT_INVALID")
        reuse_key = receipt.get("reuse_key")
        if not isinstance(reuse_key, str):
            return _invalid("PROGRAM_FACTS_REUSE_KEY_MISSING")
        decision: ProgramFactsResumeDecision = validate_program_facts_resume(
            sidecars=sidecars,
            expected_reuse_key=reuse_key,
            context=context,
            source_bytes_by_id=source_bytes_by_id,
            source_manifest_authority=source_manifest_authority,
            audit_snapshot_authority=audit_snapshot_authority,
            provider_registry=provider_registry,
            source_project_root=source_project_root,
            source_config=source_config,
        )
    except (
        OSError,
        ProgramFactsTypeError,
        rooted_path_io.RootedPathIOError,
        TypeError,
        ValueError,
    ) as exc:
        return _invalid(f"PROGRAM_FACTS_BYTE_REPLAY_FAILED:{exc}")
    if not decision.reusable or decision.bundle is None:
        return LoadedProgramFacts(
            state=decision.state,
            valid=False,
            reusable=False,
            blocks_reuse=True,
            reason_codes=(decision.reason or "PROGRAM_FACTS_RESUME_REJECTED",),
            sidecars=sidecars,
        )
    return LoadedProgramFacts(
        state=decision.state,
        valid=True,
        reusable=True,
        blocks_reuse=False,
        reason_codes=(),
        sidecars=sidecars,
        bundle=decision.bundle,
    )


__all__ = [
    "LoadedProgramFacts",
    "load_bound_program_facts",
]
