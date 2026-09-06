"""R12 contracts for layout-bound skeptic containment reconciliation."""
from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

import plamen_driver as D
from skeptic_execution_work import skeptic_execution_layout


PLAN_DIGEST = "a" * 64
RUN_ID = "00000000-0000-4000-8000-000000000012"


def _names(workflow: str) -> tuple[str, str, str]:
    if workflow == "application_skeptic":
        return (
            "worker.0001",
            "application_skeptic_assessments_0001.json",
            "application_skeptic_provider_authority_0001.json",
        )
    return (
        "negative.worker.0001",
        "candidate_negative_skeptic_assessments_0001.json",
        "candidate_negative_skeptic_provider_authority_0001.json",
    )


def _fixture(tmp_path: Path, workflow: str):
    scratchpad = tmp_path / "scratch"
    project_root = tmp_path / "project"
    scratchpad.mkdir()
    project_root.mkdir()
    work_unit, assessment, authority = _names(workflow)
    layout = skeptic_execution_layout(
        scratchpad,
        workflow=workflow,
        run_id=RUN_ID,
        plan_digest=PLAN_DIGEST,
        shard_id="ASK-0001",
        canonical_output=assessment,
    )
    assert layout.canonical_output_relative == assessment
    assert layout.authority_sidecar_relative == authority
    contract = SimpleNamespace(
        work_unit_id=work_unit,
        outputs=(
            SimpleNamespace(root="scratchpad", path=assessment),
            SimpleNamespace(root="scratchpad", path=authority),
        ),
    )
    return scratchpad, project_root, layout, contract


@pytest.mark.parametrize(
    ("workflow", "provider_exit"),
    [
        ("application_skeptic", "success"),
        ("application_skeptic", "base_exception"),
        ("candidate_negative", "success"),
        ("candidate_negative", "base_exception"),
    ],
)
def test_layout_bound_exact_pair_reconciles_after_snapshot(
    tmp_path: Path, workflow: str, provider_exit: str,
) -> None:
    scratchpad, project_root, layout, contract = _fixture(tmp_path, workflow)
    before = D._snapshot_application_skeptic_child_boundary(
        scratchpad, project_root
    )
    callback_reached: list[bool] = []
    try:
        callback_reached.append(True)
        layout.canonical_output_path.write_text("{}\n", encoding="utf-8")
        layout.authority_sidecar_path.write_text("{}\n", encoding="utf-8")
        if provider_exit == "base_exception":
            raise KeyboardInterrupt("bounded provider BaseException")
    except BaseException:
        pass

    issues = D._reconcile_application_skeptic_provider_attempt(
        scratchpad=scratchpad,
        project_root=project_root,
        config={"_run_id": RUN_ID, "project_root": str(project_root)},
        shard_id="ASK-0001",
        before_state=before,
        phase_io_contract=contract,
        provider_layout=layout,
    )

    assert callback_reached == [True]
    assert issues == []


@pytest.mark.parametrize("pipeline", ["sc", "l1"])
@pytest.mark.parametrize(
    "workflow", ["application_skeptic", "candidate_negative"]
)
def test_both_workflows_quarantine_exact_three_offenders(
    tmp_path: Path, pipeline: str, workflow: str,
) -> None:
    scratchpad, project_root, layout, contract = _fixture(tmp_path, workflow)
    before = D._snapshot_application_skeptic_child_boundary(
        scratchpad, project_root
    )
    layout.canonical_output_path.write_text("{}\n", encoding="utf-8")
    layout.authority_sidecar_path.write_text("{}\n", encoding="utf-8")
    (project_root / "AUDIT_REPORT.md").write_text("rogue\n", encoding="utf-8")
    (scratchpad / "verification_queue.md").write_text("rogue\n", encoding="utf-8")
    (scratchpad / "application_skeptic_notes.md").write_text(
        "rogue\n", encoding="utf-8"
    )

    issues = D._reconcile_application_skeptic_provider_attempt(
        scratchpad=scratchpad,
        project_root=project_root,
        config={
            "_run_id": RUN_ID,
            "pipeline": pipeline,
            "project_root": str(project_root),
        },
        shard_id="ASK-0001",
        before_state=before,
        phase_io_contract=contract,
        provider_layout=layout,
    )

    assert issues == []
    assert layout.canonical_output_path.is_file()
    assert layout.authority_sidecar_path.is_file()
    assert not (project_root / "AUDIT_REPORT.md").exists()
    assert not (scratchpad / "verification_queue.md").exists()
    assert not (scratchpad / "application_skeptic_notes.md").exists()
    receipt = D._load_application_skeptic_containment_receipt(scratchpad)
    assert receipt is not None
    event = receipt["events"][-1]
    assert event["offenders"] == [
        "../AUDIT_REPORT.md",
        "application_skeptic_notes.md",
        "verification_queue.md",
    ]
    assert event["moved"] == event["offenders"]
    assert event["failed"] == []


@pytest.mark.parametrize(
    "mutation",
    [
        "missing_assessment",
        "missing_authority",
        "extra_output",
        "duplicate_assessment",
        "duplicate_authority",
        "wrong_assessment_root",
        "wrong_authority_root",
        "crosswired_assessment",
        "crosswired_authority",
        "future_workflow",
        "unsafe_assessment",
        "unsafe_authority",
    ],
)
def test_layout_contract_pair_mismatch_fails_closed(
    tmp_path: Path, mutation: str,
) -> None:
    scratchpad, project_root, layout, contract = _fixture(
        tmp_path, "candidate_negative"
    )
    assessment = layout.canonical_output_relative
    authority = layout.authority_sidecar_relative
    outputs = list(contract.outputs)
    if mutation == "missing_assessment":
        outputs = outputs[1:]
    elif mutation == "missing_authority":
        outputs = outputs[:1]
    elif mutation == "extra_output":
        outputs.append(SimpleNamespace(root="scratchpad", path="unexpected.json"))
    elif mutation == "duplicate_assessment":
        outputs.append(SimpleNamespace(root="scratchpad", path=assessment))
    elif mutation == "duplicate_authority":
        outputs.append(SimpleNamespace(root="scratchpad", path=authority))
    elif mutation == "wrong_assessment_root":
        outputs[0] = SimpleNamespace(root="project", path=assessment)
    elif mutation == "wrong_authority_root":
        outputs[1] = SimpleNamespace(root="project", path=authority)
    elif mutation == "crosswired_assessment":
        outputs[0] = SimpleNamespace(
            root="scratchpad", path="application_skeptic_assessments_0001.json"
        )
    elif mutation == "crosswired_authority":
        outputs[1] = SimpleNamespace(
            root="scratchpad",
            path="application_skeptic_provider_authority_0001.json",
        )
    elif mutation == "future_workflow":
        layout = replace(layout, workflow="future_skeptic")
    elif mutation == "unsafe_assessment":
        layout = replace(layout, canonical_output_relative="../escape.json")
    elif mutation == "unsafe_authority":
        layout = replace(layout, authority_sidecar_relative="../escape.json")

    issues = D._reconcile_application_skeptic_provider_attempt(
        scratchpad=scratchpad,
        project_root=project_root,
        config={"_run_id": RUN_ID, "project_root": str(project_root)},
        shard_id="ASK-0001",
        before_state=D._snapshot_application_skeptic_child_boundary(
            scratchpad, project_root
        ),
        phase_io_contract=SimpleNamespace(outputs=tuple(outputs)),
        provider_layout=layout,
    )

    assert issues == [
        "application_skeptic containment PhaseIO assessment/authority "
        "denominator is not exact"
    ]
