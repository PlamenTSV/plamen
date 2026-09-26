"""Closed report parent/leaf routing; no generic phase alias permission."""
import pytest

from headless_phase_identity import (
    registered_headless_phase_identity,
    requires_report_model_preimage_capture,
    requires_standard_posix_model_incorporation,
)


@pytest.mark.parametrize("phase", ["report_dedup_agent", "report_disposition"])
def test_report_tail_model_uses_exact_standard_posix_incorporation(phase):
    assert requires_standard_posix_model_incorporation(
        phase_name=phase,
        contract_phase=phase,
        work_unit_id="model",
        label=phase,
        agent_id=None,
    )
    assert not requires_report_model_preimage_capture(
        contract_phase=phase,
        work_unit_id="model",
    )


@pytest.mark.parametrize("phase", ["report_dedup_agent", "report_disposition"])
@pytest.mark.parametrize(
    ("work_unit_id", "label", "agent_id"),
    [
        ("model.extra", None, None),
        ("model", "other", None),
        ("model", None, "worker"),
    ],
)
def test_report_tail_posix_incorporation_rejects_aliases(
    phase, work_unit_id, label, agent_id,
):
    assert not requires_standard_posix_model_incorporation(
        phase_name=phase,
        contract_phase=phase,
        work_unit_id=work_unit_id,
        label=phase if label is None else label,
        agent_id=agent_id,
    )


@pytest.mark.parametrize("tier", ["critical_high", "medium", "low_info", "low_info_a"])
@pytest.mark.parametrize("suffix", ["", ".attempt-0002", ".attempt-9999"])
def test_exact_body_shard_and_retry_identity(tier, suffix):
    assert registered_headless_phase_identity(
        phase_name=f"report_body_writer_{tier}", contract_phase="report_body",
        work_unit_id=f"model.report_{tier}{suffix}", agent_id=None,
    )


@pytest.mark.parametrize("work", [
    "model.report_medium", "model.report_low_info_a",
    "model.report_low_info.attempt-0001", "model.report_low_info.attempt-0000",
    "model.report_low_info.attempt-2", "model.report_low_info.attempt-10000",
    "model.report_low_info.extra", "MODEL.report_low_info",
    "evidence_projection.report_low_info", "evidence_repair.apply",
    "evidence_repair.model.extra",
])
def test_other_shards_roles_and_noncanonical_units_reject(work):
    assert not registered_headless_phase_identity(
        phase_name="report_body_writer_low_info", contract_phase="report_body",
        work_unit_id=work, agent_id=None,
    )


@pytest.mark.parametrize("phase", [
    "report_body_writer_LOW_INFO", "report_body_writer_low_info_aa",
    "report_body_writer_low_info/extra", "report_index", "exploration_skeptic",
])
def test_shared_repair_does_not_allow_arbitrary_parent(phase):
    assert not registered_headless_phase_identity(
        phase_name=phase, contract_phase="report_body",
        work_unit_id="evidence_repair.model", agent_id=None,
    )


@pytest.mark.parametrize("agent", ["REPORT_EVIDENCE_REPAIR_EXTRA", "OTHER", 1])
def test_repair_rejects_other_agent_identity(agent):
    assert not registered_headless_phase_identity(
        phase_name="report_body_writer_low_info", contract_phase="report_body",
        work_unit_id="evidence_repair.model", agent_id=agent,
    )


@pytest.mark.parametrize("phase", ["inventory_chunk_a", "inventory_chunk_b", "inventory_chunk_c"])
@pytest.mark.parametrize("attempt", ["0001", "0002", "9999"])
def test_exact_inventory_child_requires_execution_receipt(phase, attempt):
    assert requires_standard_posix_model_incorporation(
        phase_name=phase, contract_phase=phase,
        work_unit_id=f"model.attempt{attempt}", label=phase, agent_id=None,
    )
    assert not requires_report_model_preimage_capture(
        contract_phase=phase, work_unit_id=f"model.attempt{attempt}",
    )


@pytest.mark.parametrize("changes", [
    {"work_unit_id": "model"},
    {"work_unit_id": "retry"},
    {"work_unit_id": "model.attempt0000"},
    {"work_unit_id": "model.attempt-0001"},
    {"work_unit_id": "model.attempt1"},
    {"work_unit_id": "model.attempt10000"},
    {"work_unit_id": "exact_reconciliation"},
    {"work_unit_id": "canonical_aggregate"},
    {"work_unit_id": "additive_reemit"},
    {"agent_id": "inventory"},
    {"label": "inventory_chunk_b"},
    {"phase_name": "inventory_chunk_b"},
    {"contract_phase": "inventory_chunk_b"},
    {"phase_name": "inventory", "contract_phase": "inventory", "label": "inventory"},
    {"phase_name": "inventory_chunk_d", "contract_phase": "inventory_chunk_d", "label": "inventory_chunk_d"},
])
def test_inventory_incorporation_rejects_other_roles_and_aliases(changes):
    values = dict(phase_name="inventory_chunk_a", contract_phase="inventory_chunk_a",
                  work_unit_id="model.attempt0001", label="inventory_chunk_a", agent_id=None)
    values.update(changes)
    assert not requires_standard_posix_model_incorporation(**values)


@pytest.mark.parametrize("phase", ["breadth", "rescan", "depth"])
def test_methodology_repair_requires_genuine_posix_model_incorporation(phase):
    label = (
        f"{phase}_repair_worker_"
        f"METHODOLOGY_APPLICATION_REPAIR_{phase.upper()}"
    )
    assert requires_standard_posix_model_incorporation(
        phase_name=phase,
        contract_phase=phase,
        work_unit_id="methodology_repair.model",
        label=label,
        agent_id=None,
    )
    assert requires_standard_posix_model_incorporation(
        phase_name=phase,
        contract_phase=phase,
        work_unit_id="methodology_repair.model",
        label=label,
        agent_id="methodology_repair",
    )


@pytest.mark.parametrize("changes", [
    {"phase_name": "depth"},
    {"contract_phase": "depth"},
    {"work_unit_id": "methodology_repair.model.extra"},
    {"label": "breadth_repair_worker"},
    {"agent_id": "METHODOLOGY_APPLICATION_REPAIR_DEPTH"},
])
def test_methodology_repair_incorporation_rejects_identity_aliases(changes):
    values = dict(
        phase_name="breadth",
        contract_phase="breadth",
        work_unit_id="methodology_repair.model",
        label="breadth_repair_worker_METHODOLOGY_APPLICATION_REPAIR_BREADTH",
        agent_id=None,
    )
    values.update(changes)
    assert not requires_standard_posix_model_incorporation(**values)


def test_isolated_chain_tail_requires_unique_shard_incorporation_identity():
    assert requires_standard_posix_model_incorporation(
        phase_name="chain_iter2",
        contract_phase="chain_iter2",
        work_unit_id="tail_shard_model.0007",
        label="chain_iter2_shard_0007",
        agent_id=None,
    )
    for work_unit_id, label, agent_id in (
        ("tail_shard_model.0007", "chain_iter2", None),
        ("tail_shard_model.0007", "chain_iter2_shard_0008", None),
        ("tail_shard_model.7", "chain_iter2_shard_0007", None),
        ("tail_shard_model.0007", "chain_iter2_shard_0007", "worker"),
    ):
        assert not requires_standard_posix_model_incorporation(
            phase_name="chain_iter2",
            contract_phase="chain_iter2",
            work_unit_id=work_unit_id,
            label=label,
            agent_id=agent_id,
        )
