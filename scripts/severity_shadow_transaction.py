"""Typed setup and finalization for the live severity shadow handler.

Worker/provider execution remains in ``plamen_driver``.  This module owns only
the immutable source/planning boundary and the ordered bind/reconciliation
boundary so the large driver does not regain raw publication code.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping

from artifact_ledger import ArtifactLedgerError
from severity_adjudication_work import (
    DEFAULT_MAX_CONTEXT_BYTES,
    DEFAULT_MAX_ITEMS,
    DEFAULT_MAX_WEIGHT,
    build_adjudication_work_reconciliation,
)
from severity_bind_transaction import run_next_severity_bind_transaction
from severity_final_reconciliation import run_final_severity_reconciliation
from severity_planning import run_severity_planning
from severity_source_selector import select_severity_initial_source
from severity_zero_reconciliation import run_zero_severity_reconciliation


_TERMINAL_STATES = frozenset({"COMPLETED", "COMPLETED_UNRESOLVED"})


def prepare_live_severity_transaction(
    *,
    scratchpad: Path,
    project_root: Path,
    implementation_root: Path,
    config: Mapping[str, Any],
    planning_args: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    """Select the immutable source and publish/replay exact planning."""

    selection = select_severity_initial_source(
        scratchpad=scratchpad, project_root=project_root, config=config,
    )
    selected_digest = selection.get("source_ledger_sha256")
    if (
        type(selected_digest) is not str
        or len(selected_digest) != 64
        or any(
            character not in "0123456789abcdef"
            for character in selected_digest
        )
    ):
        raise ArtifactLedgerError(
            "severity selected source digest is not lowercase SHA-256"
        )
    exact_args = {
        **dict(planning_args),
        "max_items_per_worker": DEFAULT_MAX_ITEMS,
        "max_weight_per_worker": DEFAULT_MAX_WEIGHT,
        "max_context_bytes_per_worker": DEFAULT_MAX_CONTEXT_BYTES,
    }
    plan = run_severity_planning(
        scratchpad=scratchpad,
        project_root=project_root,
        implementation_root=implementation_root,
        config=config,
        planning_args=exact_args,
        expected_source_ledger_digest=selected_digest,
    )
    return (
        plan,
        build_adjudication_work_reconciliation(scratchpad),
        selection,
    )


def finalize_live_severity_transaction(
    *,
    scratchpad: Path,
    project_root: Path,
    config: Mapping[str, Any],
    plan: Mapping[str, Any],
    source_selection: Mapping[str, Any],
) -> dict[str, Any]:
    """Resume ordered binds and publish one typed terminal reconciliation."""

    denominator = tuple(plan.get("denominator_ids") or ())
    if not denominator:
        if not run_zero_severity_reconciliation(
            scratchpad=scratchpad, project_root=project_root, config=config,
        ):
            raise ArtifactLedgerError("zero severity reconciliation did not commit")
        return build_adjudication_work_reconciliation(scratchpad)

    while True:
        reconciliation = build_adjudication_work_reconciliation(scratchpad)
        armed_candidate = source_selection.get("armed_bind_candidate_id")
        if armed_candidate is not None and armed_candidate not in denominator:
            raise ArtifactLedgerError(
                "armed severity bind is outside the planning denominator"
            )
        next_candidate = armed_candidate or next(
            (
                candidate_id
                for candidate_id in denominator
                if reconciliation.get("states", {}).get(candidate_id)
                not in _TERMINAL_STATES
            ),
            None,
        )
        if next_candidate is None:
            break
        next_state = reconciliation.get("states", {}).get(next_candidate)
        if not (next_state == "OUTPUT_READY" or armed_candidate == next_candidate):
            return reconciliation
        bound = run_next_severity_bind_transaction(
            scratchpad=scratchpad, project_root=project_root, config=config,
        )
        if bound != next_candidate:
            raise ArtifactLedgerError(
                "ordered severity bind selected a different candidate"
            )
        # An authenticated armed row can be consumed only once. Subsequent
        # iterations advance from freshly derived semantic state.
        source_selection = {**dict(source_selection), "armed_bind_candidate_id": None}

    if not run_final_severity_reconciliation(
        scratchpad=scratchpad, project_root=project_root, config=config,
    ):
        raise ArtifactLedgerError("final severity reconciliation did not commit")
    return build_adjudication_work_reconciliation(scratchpad)


__all__ = [
    "finalize_live_severity_transaction",
    "prepare_live_severity_transaction",
]
