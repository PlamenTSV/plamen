"""Thin transactional adapters from typed application authority to negatives."""
from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping

import claude_phase_tool_policy
from artifact_ledger import (
    ArtifactLedgerError,
    read_artifact_ledger,
    record_work_unit_artifacts,
    record_work_unit_inputs,
    validate_work_unit_artifacts,
    validate_work_unit_inputs,
)
from candidate_negative_authority import (
    build_attention_repair_candidate_negative_ledger_from_scratchpad,
    compile_candidate_negative_staged_context,
    parse_candidate_negative_ledger_bytes,
    staged_candidate_negative_receipt_validator,
    validate_attention_repair_candidate_negative_ledger_from_scratchpad,
    write_candidate_negative_ledger,
)
from phase_io_contracts import LaunchSpec, resolve_phase_io_contract


ATTENTION_INPUTS = (
    "attention_repair_queue.md",
    "attention_repair_shard_plan.json",
    "attention_repair_application_receipt.json",
)
ATTENTION_OUTPUT = "candidate_negative_proposals_attention_repair.json"
PREPUBLICATION_PHASES = frozenset({"breadth", "rescan"})
EXACT_PREPUBLICATION_SCHEMA = (
    "plamen.exact_prepublication_candidate_negative_gate.v1"
)


def compile_prepublication_candidate_negative_gate(
    methodology_bytes: bytes,
    output_identity: str,
    producer_identity: str,
    *,
    phase: str,
    invocation_id: str | None = None,
) -> dict[str, Any]:
    """Freeze one breadth/rescan negative gate before provider launch.

    Original producers and their bounded repair producers deliberately share
    this exact contract.  The caller supplies already captured methodology
    bytes, so validation never re-reads mutable files after the model runs.
    """

    phase_name = str(phase).strip().casefold()
    if phase_name not in PREPUBLICATION_PHASES:
        raise ValueError(
            "prepublication candidate-negative phase must be breadth or rescan"
        )
    return compile_candidate_negative_staged_context(
        methodology_bytes,
        output_identity,
        producer_identity,
        phase=phase_name,
        invocation_id=invocation_id,
    )


def staged_prepublication_candidate_negative_validator(
    outputs: Mapping[str, bytes],
    context: Mapping[str, Any],
) -> tuple[str, ...]:
    """Reject producer-authored negative debt before canonical publication."""

    if (
        not isinstance(context, Mapping)
        or str(context.get("phase") or "").casefold()
        not in PREPUBLICATION_PHASES
    ):
        return (
            "prepublication candidate-negative context is not breadth/rescan",
        )
    return staged_candidate_negative_receipt_validator(outputs, context)


def bind_exact_prepublication_candidate_negative_gate(
    semantic_gate: Mapping[str, Any],
    exact_gate: Mapping[str, Any],
) -> dict[str, Any]:
    """Join a restricted-Claude exact-write gate to the semantic gate."""

    if (
        not isinstance(semantic_gate, Mapping)
        or str(semantic_gate.get("phase") or "").casefold()
        not in PREPUBLICATION_PHASES
        or not isinstance(exact_gate, Mapping)
    ):
        raise ValueError("exact candidate-negative gate inputs are invalid")
    return {
        "schema": EXACT_PREPUBLICATION_SCHEMA,
        "exact_gate": dict(exact_gate),
        "semantic_gate": dict(semantic_gate),
    }


def staged_exact_prepublication_candidate_negative_validator(
    outputs: Mapping[str, bytes],
    context: Mapping[str, Any],
) -> tuple[str, ...]:
    """Require both restricted-write and candidate-negative admission."""

    if (
        not isinstance(context, Mapping)
        or set(context) != {"schema", "exact_gate", "semantic_gate"}
        or context.get("schema") != EXACT_PREPUBLICATION_SCHEMA
        or not isinstance(context.get("exact_gate"), Mapping)
        or not isinstance(context.get("semantic_gate"), Mapping)
    ):
        return ("exact prepublication candidate-negative context is invalid",)
    exact = claude_phase_tool_policy.staged_exact_output_receipt_validator(
        outputs, context["exact_gate"]
    )
    semantic = staged_prepublication_candidate_negative_validator(
        outputs, context["semantic_gate"]
    )
    return tuple(dict.fromkeys((*exact, *semantic)))


def run_attention_candidate_negative_adapter(
    scratchpad: Path,
    project_root: Path,
    *,
    run_id: str,
    dimensions: Mapping[str, str],
) -> list[str]:
    """Publish or replay the exact attention application adapter ledger."""

    root = Path(scratchpad)
    project = Path(project_root)
    try:
        contract = resolve_phase_io_contract(
            pipeline=str(dimensions["pipeline"]),
            mode=str(dimensions["mode"]),
            ecosystem=str(dimensions["ecosystem"]),
            backend=str(dimensions["backend"]),
            phase="candidate_negative_authority",
            work_unit_id="harvest.attention_repair",
            exact_inputs=ATTENTION_INPUTS,
            exact_outputs=(ATTENTION_OUTPUT,),
        )
        launch = LaunchSpec(
            work_unit_key=contract.key,
            pipeline=contract.pipeline,
            mode=contract.mode,
            ecosystem=contract.ecosystem,
            backend=contract.backend,
            model="driver",
            timeout_s=120,
            exec_mode="python",
            tool_policy=("filesystem",),
        )
        unit = read_artifact_ledger(root).get("work_units", {}).get(contract.key)
        committed = isinstance(unit, Mapping) and (
            unit.get("semantic_status") == "ACTIVE"
            and unit.get("execution_state") == "OUTPUT_COMMITTED"
        )
        if committed:
            ledger = parse_candidate_negative_ledger_bytes(
                (root / ATTENTION_OUTPUT).read_bytes(),
                expected_phase="attention_repair",
            )
            validate_attention_repair_candidate_negative_ledger_from_scratchpad(
                ledger, scratchpad=root
            )
            return validate_work_unit_artifacts(
                root, project, contract, launch, run_id=run_id, actor="DRIVER"
            )
        record_work_unit_inputs(root, project, contract, launch, run_id=run_id)
        issues = validate_work_unit_inputs(
            root, project, contract, launch, run_id=run_id
        )
        if issues:
            return list(dict.fromkeys(issues))
        ledger = build_attention_repair_candidate_negative_ledger_from_scratchpad(root)
        write_candidate_negative_ledger(root, ledger)
        domain_issues = [
            str(row.get("code") or row)
            for row in ledger.get("issues", ())
            if isinstance(row, Mapping)
        ]
        record_work_unit_artifacts(
            root,
            project,
            contract,
            launch,
            run_id=run_id,
            actor="DRIVER",
            precommit_issues=domain_issues,
        )
        return validate_work_unit_artifacts(
            root, project, contract, launch, run_id=run_id, actor="DRIVER"
        )
    except (ArtifactLedgerError, OSError, TypeError, ValueError) as exc:
        return [
            "typed attention candidate-negative harvest failed haltlessly: "
            f"{type(exc).__name__}: {exc}"
        ]


__all__ = [
    "ATTENTION_INPUTS",
    "ATTENTION_OUTPUT",
    "EXACT_PREPUBLICATION_SCHEMA",
    "PREPUBLICATION_PHASES",
    "bind_exact_prepublication_candidate_negative_gate",
    "compile_prepublication_candidate_negative_gate",
    "run_attention_candidate_negative_adapter",
    "staged_exact_prepublication_candidate_negative_validator",
    "staged_prepublication_candidate_negative_validator",
]
