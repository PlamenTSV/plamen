"""Report candidate-universe PhaseIO cutover fixtures.

The candidate universe is dynamic, but the contract denominator is not
optional once a caller selects the typed path.  These tests keep the resolver
filesystem-independent while proving that every caller-supplied universe byte
is bound by the artifact ledger.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from artifact_ledger import (
    record_work_unit_inputs,
    semantic_dependency_invalidation_plan,
    validate_work_unit_inputs,
)
from phase_io_contracts import LaunchSpec, resolve_phase_io_contract
from post_verify_candidate_delta import (
    write_or_validate_post_verify_candidate_delta,
)
from queue_work_items import QueueWorkItem, queue_records_to_json


BASE = {
    "pipeline": "sc",
    "mode": "thorough",
    "ecosystem": "evm",
    "backend": "claude",
    "phase": "report_index",
}
LEGACY_REPORT_INPUTS = (
    "verification_queue.md",
    "finding_mapping.md",
    "dedup_decisions.md",
)
TYPED_BASE = "verification_queue.work_items.json"
DELTA = "post_verify_candidate_delta.json"
LATE_DELIVERY = "post_verify_late_delivery.json"
DELTA_SOURCE = "post_verify_extract.md"
OPERATOR_SOURCE = "verification_operator_consumer_authority.0001.json"


def _contract(work_unit_id: str, exact_inputs: tuple[str, ...]):
    return resolve_phase_io_contract(
        **BASE,
        work_unit_id=work_unit_id,
        exact_inputs=exact_inputs,
    )


def _launch(contract) -> LaunchSpec:
    return LaunchSpec(
        work_unit_key=contract.key,
        pipeline=contract.pipeline,
        mode=contract.mode,
        ecosystem=contract.ecosystem,
        backend=contract.backend,
        model="driver" if not contract.model_invoked else "test-model",
        timeout_s=30,
        exec_mode="python",
        tool_policy=("filesystem",),
    )


def _materialize(root: Path, relative_paths: tuple[str, ...]) -> None:
    for relative in relative_paths:
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"initial:{relative}\n", encoding="utf-8")


@pytest.mark.parametrize(
    "mutated",
    (TYPED_BASE, DELTA, DELTA_SOURCE, OPERATOR_SOURCE, LATE_DELIVERY),
)
def test_report_prework_binds_every_typed_universe_byte_and_detects_tamper(
    tmp_path: Path,
    mutated: str,
):
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    inputs = (
        *LEGACY_REPORT_INPUTS,
        TYPED_BASE,
        DELTA,
        DELTA_SOURCE,
        OPERATOR_SOURCE,
        LATE_DELIVERY,
    )
    _materialize(scratchpad, inputs)
    contract = _contract("prework", inputs)
    launch = _launch(contract)

    record_work_unit_inputs(
        scratchpad,
        tmp_path,
        contract,
        launch,
        run_id="typed-report-run",
    )
    assert validate_work_unit_inputs(
        scratchpad,
        tmp_path,
        contract,
        launch,
        run_id="typed-report-run",
    ) == []

    (scratchpad / mutated).write_text(
        f"mutated:{mutated}\n", encoding="utf-8"
    )
    issues = validate_work_unit_inputs(
        scratchpad,
        tmp_path,
        contract,
        launch,
        run_id="typed-report-run",
    )

    assert (
        f"scratchpad:{mutated}: semantic input hash changed" in issues
    )


@pytest.mark.parametrize("work_unit_id", ("model", "mechanical"))
def test_report_index_successors_bind_the_same_typed_universe_sources(
    work_unit_id: str,
):
    inputs = (
        *LEGACY_REPORT_INPUTS,
        TYPED_BASE,
        DELTA,
        DELTA_SOURCE,
        OPERATOR_SOURCE,
        LATE_DELIVERY,
    )
    contract = _contract(work_unit_id, inputs)

    for relative in (
        TYPED_BASE,
        DELTA,
        DELTA_SOURCE,
        OPERATOR_SOURCE,
        LATE_DELIVERY,
    ):
        assert f"scratchpad:{relative}" in contract.immutable_inputs


@pytest.mark.parametrize("work_unit_id", ("prework", "model", "mechanical"))
@pytest.mark.parametrize(
    "evidence",
    (DELTA_SOURCE, OPERATOR_SOURCE),
)
def test_postverify_evidence_without_delta_cannot_fall_back_to_typed_base(
    work_unit_id: str,
    evidence: str,
):
    with pytest.raises(
        ValueError,
        match="post-verification evidence requires post_verify_candidate_delta.json",
    ):
        _contract(
            work_unit_id,
            (*LEGACY_REPORT_INPUTS, TYPED_BASE, evidence),
        )


@pytest.mark.parametrize("work_unit_id", ("prework", "model", "mechanical"))
def test_late_delivery_requires_the_run_bound_candidate_delta(
    work_unit_id: str,
):
    with pytest.raises(
        ValueError,
        match="post-verification evidence requires post_verify_candidate_delta.json",
    ):
        _contract(
            work_unit_id,
            (*LEGACY_REPORT_INPUTS, TYPED_BASE, LATE_DELIVERY),
        )


@pytest.mark.parametrize("work_unit_id", ("prework", "model", "mechanical"))
def test_typed_delta_requires_typed_base_queue(work_unit_id: str):
    with pytest.raises(
        ValueError,
        match="typed report candidate universe requires "
        "verification_queue.work_items.json",
    ):
        _contract(
            work_unit_id,
            (*LEGACY_REPORT_INPUTS, DELTA),
        )


@pytest.mark.parametrize("work_unit_id", ("prework", "model", "mechanical"))
def test_explicit_clean_zero_delta_is_a_valid_bound_universe(
    work_unit_id: str,
    tmp_path: Path,
):
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    item = QueueWorkItem.from_legacy_row({
        "finding id": "BASE-1",
        "severity": "Medium",
        "title": "Base candidate",
        "bug class": "STATE_TRANSITION",
        "preferred tag": "CODE-TRACE",
        "location": "src/Base.sol:10",
        "primary artifact": "findings_inventory.md",
        "poc class": "structural",
    })
    (scratchpad / TYPED_BASE).write_text(
        queue_records_to_json((item,)) + "\n",
        encoding="utf-8",
    )
    (scratchpad / DELTA_SOURCE).write_text(
        "# Post Verify Extract\n\n**Status**: CLEAN_NO_CANDIDATES\n",
        encoding="utf-8",
    )
    payload = write_or_validate_post_verify_candidate_delta(
        scratchpad,
        run_id="typed-report-run",
        operator_proposals=(),
    )
    assert payload["status"] == "CLEAN"
    assert payload["row_count"] == 0
    contract = _contract(
        work_unit_id,
        (*LEGACY_REPORT_INPUTS, TYPED_BASE, DELTA, DELTA_SOURCE),
    )

    assert f"scratchpad:{TYPED_BASE}" in contract.immutable_inputs
    assert f"scratchpad:{DELTA}" in contract.immutable_inputs
    assert f"scratchpad:{DELTA_SOURCE}" in contract.immutable_inputs


def test_omitted_exact_inputs_preserve_registered_legacy_contract():
    contract = resolve_phase_io_contract(
        **BASE,
        work_unit_id="prework",
    )

    assert set(contract.immutable_inputs) == {
        f"scratchpad:{relative}" for relative in LEGACY_REPORT_INPUTS
    }


def test_candidate_source_drift_propagates_through_index_routing_to_tier_writer():
    """The prework bind is a transitive root, not an isolated tamper alarm."""

    prework = _contract(
        "prework",
        (
            *LEGACY_REPORT_INPUTS,
            TYPED_BASE,
            DELTA,
            DELTA_SOURCE,
        ),
    )
    model = _contract(
        "model",
        ("report_index_coverage_seed.md",),
    )
    routing = resolve_phase_io_contract(
        **BASE,
        work_unit_id="routing",
        exact_outputs=("body_manifests/report_medium.json",),
    )
    tier = resolve_phase_io_contract(
        **{**BASE, "phase": "report_body"},
        work_unit_id="model.report_medium",
        exact_inputs=(
            "body_manifests/report_medium.json",
            "report_evidence_manifests/report_medium.json",
        ),
        exact_outputs=("report_medium.md",),
    )

    def unit(contract, inputs: tuple[str, ...], outputs: tuple[str, ...]):
        return {
            "run_id": "typed-report-run",
            "input_bindings": {identity: {} for identity in inputs},
            "artifacts": {identity: {} for identity in outputs},
        }

    coverage = "scratchpad:report_index_coverage_seed.md"
    report_index = "scratchpad:report_index.md"
    body_manifest = "scratchpad:body_manifests/report_medium.json"
    ledger = {
        "work_units": {
            prework.key: unit(
                prework,
                prework.immutable_inputs,
                (coverage,),
            ),
            model.key: unit(
                model,
                (coverage,),
                (report_index,),
            ),
            routing.key: unit(
                routing,
                (report_index,),
                (body_manifest,),
            ),
            tier.key: unit(
                tier,
                (body_manifest,),
                ("scratchpad:report_medium.md",),
            ),
        },
    }

    plan = semantic_dependency_invalidation_plan(
        ledger,
        [f"scratchpad:{DELTA_SOURCE}"],
        run_id="typed-report-run",
    )

    assert set(plan["invalidated_work_unit_keys"]) == {
        prework.key,
        model.key,
        routing.key,
        tier.key,
    }
    assert "scratchpad:report_medium.md" in plan[
        "invalidated_artifact_identities"
    ]
