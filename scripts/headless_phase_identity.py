"""Closed orchestration-to-PhaseIO identities for headless MODEL leaves."""

from __future__ import annotations

import re
from typing import Final

from phase_io_contracts import parse_report_body_attempt_work_unit


_REPORT_BODY_PARENT: Final = re.compile(
    r"report_body_writer_(critical_high|medium|low_info)(_[a-z])?"
)


def _registered_report_body_alias(
    phase_name: str,
    contract_phase: str,
    work_unit_id: str,
    agent_id: str | None,
) -> bool:
    parent = _REPORT_BODY_PARENT.fullmatch(phase_name)
    if parent is None or contract_phase != "report_body":
        return False
    if work_unit_id == "evidence_repair.model":
        return agent_id in {None, "REPORT_EVIDENCE_REPAIR"}
    parsed = parse_report_body_attempt_work_unit(work_unit_id)
    return bool(
        agent_id is None
        and parsed is not None
        and parsed[0] == "model"
        and parsed[1] == "report_" + phase_name.removeprefix(
            "report_body_writer_"
        )
    )


def registered_headless_phase_identity(
    *,
    phase_name: str,
    contract_phase: str,
    work_unit_id: str,
    agent_id: str | None,
) -> bool:
    """Return whether the orchestration phase is the exact sealed leaf phase."""

    if not all(
        isinstance(value, str) and value
        for value in (phase_name, contract_phase, work_unit_id)
    ) or (agent_id is not None and not isinstance(agent_id, str)):
        return False
    return bool(
        phase_name == contract_phase
        or _registered_report_body_alias(
            phase_name,
            contract_phase,
            work_unit_id,
            agent_id,
        )
    )


def requires_standard_posix_model_incorporation(
    *,
    phase_name: str,
    contract_phase: str,
    work_unit_id: str,
    label: str,
    agent_id: str | None,
) -> bool:
    """Classify the existing generic POSIX MODEL incorporation lane."""

    if not registered_headless_phase_identity(
        phase_name=phase_name,
        contract_phase=contract_phase,
        work_unit_id=work_unit_id,
        agent_id=agent_id,
    ):
        return False
    if (
        work_unit_id == "methodology_repair.model"
        and contract_phase in {"breadth", "rescan", "depth"}
    ):
        # Methodology repair is a real MODEL producer even though its public
        # worker ID and parent phase differ from ordinary fan-out leaves. The
        # compatibility runtime already emits an exact execution receipt; it
        # must be incorporated here instead of falling through to legacy
        # canonical-byte adoption. Codex supplies no inferred agent ID with
        # its explicit PhaseIO contract, while Claude carries the dispatch ID.
        expected_label = (
            rf"{re.escape(contract_phase)}_repair_worker_"
            rf"METHODOLOGY_APPLICATION_REPAIR_"
            rf"{re.escape(contract_phase.upper())}"
        )
        return bool(
            re.fullmatch(expected_label, label)
            and agent_id in {
                None,
                "methodology_repair",
                f"METHODOLOGY_APPLICATION_REPAIR_{contract_phase.upper()}",
            }
        )
    chain_unit = re.fullmatch(
        r"tail_shard_model\.(?P<index>[0-9]{4})", work_unit_id
    )
    if contract_phase == "chain_iter2" and chain_unit is not None:
        # Isolated chain-tail leaves execute from a shard-local presentation
        # directory but publish into the audit-root PhaseIO authority. Their
        # POSIX receipt is genuine MODEL evidence and must survive that split.
        return bool(
            agent_id is None
            and label == f"chain_iter2_shard_{chain_unit.group('index')}"
        )
    if contract_phase == "breadth":
        return agent_id is not None
    if contract_phase in {"inventory_chunk_a", "inventory_chunk_b", "inventory_chunk_c"}:
        attempt = re.fullmatch(r"model\.attempt([0-9]{4})", work_unit_id)
        # Inventory MODEL bytes must carry the same genuine child-execution
        # receipt as other ordinary leaves. This is execution authority only;
        # candidate completeness and reconciliation remain separate gates.
        return bool(
            phase_name == contract_phase
            and label == contract_phase
            and agent_id is None
            and attempt is not None
            and int(attempt.group(1)) > 0
        )
    if contract_phase == "report_index":
        return agent_id is None and label == "report_index"
    if contract_phase in {"report_dedup_agent", "report_disposition"}:
        return bool(
            agent_id is None
            and work_unit_id == "model"
            and label == contract_phase
        )
    if contract_phase != "report_body" or agent_id is not None:
        return False
    if work_unit_id == "evidence_repair.model":
        return label == "report_evidence_repair"
    parsed = parse_report_body_attempt_work_unit(work_unit_id)
    return bool(
        parsed is not None
        and parsed[0] == "model"
        and label == phase_name
    )


def requires_report_model_preimage_capture(
    *, contract_phase: str, work_unit_id: str,
) -> bool:
    """Select only report MODEL generations supported by the preimage store."""

    if contract_phase == "report_index":
        attempt = re.fullmatch(r"model\.attempt-([0-9]{4})", work_unit_id)
        return bool(
            work_unit_id == "model"
            or attempt is not None and int(attempt.group(1)) >= 2
        )
    if contract_phase != "report_body":
        return False
    parsed = parse_report_body_attempt_work_unit(work_unit_id)
    return bool(parsed is not None and parsed[0] == "model")
