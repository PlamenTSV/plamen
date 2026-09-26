"""Focused production-semantic checks for the live T0--T8 executor."""
from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path
import tempfile
from typing import Any

import pytest

import test_live_verify_queue_transaction_semantic_closure as acceptance
import verify_queue_transaction as transaction
import live_verify_queue_semantics as semantics
from live_verify_queue_semantics import (
    LiveVerifyQueueSemanticError,
    build_live_verify_queue_semantic_executor,
    live_verify_queue_semantic_gap_map,
)
from queue_work_items import QueueWorkItem


def _run(
    root: Path,
    pipeline: str,
    backend: str = "claude",
) -> tuple[dict[str, Any], Path, dict[str, Any]]:
    plan = dict(acceptance._plan(pipeline, backend))
    scratchpad = root / ".scratchpad"
    acceptance._seed_inputs(scratchpad, root, pipeline, backend)
    result = transaction.execute_live_verify_queue_transaction(
        scratchpad=scratchpad,
        project_root=root,
        plan=plan,
        run_id=str(plan["run_id"]),
        semantic_executor=build_live_verify_queue_semantic_executor(plan),
    )
    return dict(result), scratchpad, plan


@pytest.mark.parametrize(
    "pipeline,backend",
    (
        ("sc", "claude"),
        ("sc", "codex"),
        ("l1", "claude"),
        ("l1", "codex"),
    ),
)
def test_production_semantics_executes_backend_neutral_t0_t9(
    tmp_path: Path,
    pipeline: str,
    backend: str,
) -> None:
    result, root, plan = _run(tmp_path, pipeline, backend)

    assert result["state"] == "OUTPUT_COMMITTED"
    assert result["safe_to_consume"] is True
    assert result["pipeline"] == pipeline
    assert result["backend"] == backend
    assert set(plan["public_output_denominator"]) - {
        # Exactly one compound conditional is inactive.
        "compound_verification_delivery_debt.json",
        "compound_verification_delivery_receipt.json",
    } <= {
        path.name if path.parent == root else path.relative_to(root).as_posix()
        for path in root.rglob("*") if path.is_file()
    }


@pytest.mark.parametrize("pipeline", ("sc", "l1"))
def test_isolated_semantics_is_byte_deterministic_across_temp_roots(
    tmp_path: Path,
    pipeline: str,
) -> None:
    first_result, first_root, first_plan = _run(tmp_path / "first", pipeline)
    second_result, second_root, second_plan = _run(tmp_path / "second", pipeline)

    assert first_result["state"] == second_result["state"] == "OUTPUT_COMMITTED"
    assert first_plan["plan_digest"] == second_plan["plan_digest"]
    active = {
        path for path in first_plan["public_output_denominator"]
        if (first_root / path).is_file()
    }
    second_active = {
        path for path in second_plan["public_output_denominator"]
        if (second_root / path).is_file()
    }
    assert active == second_active
    assert {
        path: (first_root / path).read_bytes() for path in active
    } == {
        path: (second_root / path).read_bytes() for path in active
    }


def test_t0_refuses_legacy_journal_as_semantic_authority() -> None:
    plan = acceptance._plan("sc")
    t0 = plan["children"][0]
    executor = build_live_verify_queue_semantic_executor(plan)

    with pytest.raises(
        LiveVerifyQueueSemanticError,
        match="legacy journal entered",
    ):
        executor(
            unit=t0,
            frozen_inputs={
                "mandatory_reverification_queue_transaction.journal.json":
                    b"{}\n",
            },
        )


def test_missing_p0af_dynamic_authorities_becomes_visible_debt(
    tmp_path: Path,
) -> None:
    result, root, _plan = _run(tmp_path, "sc")

    assert result["state"] == "OUTPUT_COMMITTED"
    status = (
        root / "p0af_v2_queue_delivery_status.json"
    ).read_text(encoding="utf-8")
    debt = (
        root / "p0af_v2_queue_delivery_debt.json"
    ).read_text(encoding="utf-8")
    assert "COMPLETED_WITH_DEBT" in status
    assert "P0_AF_V2" in debt
    # The paired frozen record projection is the identity denominator.  The
    # remaining safe-base path is the deliberately absent pre-arm
    # dynamic-source manifest; semantics may not synthesize it from prose.
    assert any(
        str(value).startswith("_preverify_frozen/generation_")
        and str(value).endswith("/finding_records.json")
        for value in acceptance._upstream_inputs("sc")
    )
    assert (
        "prearm_content_addressed_input_manifest"
        not in acceptance._child_map(_plan)[acceptance.CHILD_IDS[0]]
    )
    gaps = live_verify_queue_semantic_gap_map(_plan)
    assert {
        row["code"] for row in gaps["rows"]
    } >= {
        "SC_P0AF_DYNAMIC_FACT_SOURCES_NOT_ENUMERATED",
        "LEGACY_BRANCH_VALIDATOR_CUTOVER_REQUIRED",
        "T0_PRODUCER_ANCESTRY_ENFORCED_BY_PHASEIO",
    }
    assert gaps["safe_base_execution_supported"] is True
    assert gaps["full_legacy_semantic_parity"] is False


def test_t8_rejects_self_consistent_source_obligation_row_forgery(
    tmp_path: Path,
) -> None:
    _result, root, plan = _run(tmp_path, "sc")
    t8 = plan["children"][8]
    paths = set(map(str, t8["exact_inputs"]))
    conditional = t8.get("conditional_input_groups", {}).get(
        "compound_delivery", {}
    )
    paths.update(
        str(path)
        for path in conditional.get("candidates", ())
        if (root / str(path)).is_file()
    )
    frozen = {
        path: (root / path).read_bytes()
        for path in sorted(paths)
    }
    accounting_path = next(
        path
        for path in frozen
        if path.endswith("/source_obligation_accounting.json")
    )
    forged = json.loads(frozen[accounting_path])
    forged["rows"].append({
        "source": "policy_active",
        "work_item_id": "INV-FORGED",
        "work_item_digest": "0" * 64,
        "disposition": "ACTIVE",
        "delivery_kind": "PRIMARY",
    })
    forged["source_obligation_count"] = len(forged["rows"])
    forged["source_obligation_digest"] = semantics._digest(
        forged["rows"]
    )
    frozen[accounting_path] = semantics._canonical_bytes(forged)

    with pytest.raises(
        LiveVerifyQueueSemanticError,
        match="occurrence denominator drifted",
    ):
        build_live_verify_queue_semantic_executor(plan)(
            unit=t8,
            frozen_inputs=frozen,
        )


def _identity_transition_item(
    work_item_id: str,
    *,
    previous_id: str | None = None,
    queue_priority: int = 1,
) -> QueueWorkItem:
    row = {
        "finding id": work_item_id,
        "candidate identity": work_item_id,
        "queue #": str(queue_priority),
        "severity": "High",
        "title": "Same substantive claim",
        "bug class": "same-bug-class",
        "preferred tag": "CODE-TRACE",
        "location": "contracts/Target.sol:41",
        "primary artifact": "RS-01",
        "poc class": "unit",
    }
    if previous_id is not None:
        row["expected output file"] = f"verify_{previous_id}.md"
    return QueueWorkItem.from_legacy_row(row)


def test_policy_identity_accounting_accepts_only_explicit_lossless_relabel() -> None:
    source = _identity_transition_item("INV-003", queue_priority=3)
    target = _identity_transition_item(
        "H-03", previous_id="INV-003", queue_priority=1
    )

    accounting = semantics._build_policy_identity_accounting(
        (source,), (target,), ()
    )

    assert accounting["exact_partition"] is True
    assert accounting["visible_debt_ids"] == []
    assert accounting["unauthorized_target_ids"] == []
    assert accounting["identity_transitions"] == [
        {
            "source_work_item_id": "INV-003",
            "target_work_item_id": "H-03",
            "target_partition": "ACTIVE",
            "transition_kind": "EXPLICIT_TYPED_RELABEL",
            "source_work_item_digest": source.digest,
            "target_work_item_digest": target.digest,
            "semantic_payload_digest": semantics._digest(
                semantics._identity_neutral_payload(source)
            ),
        }
    ]
    semantics._validate_policy_identity_accounting(
        accounting, (target,), ()
    )


@pytest.mark.parametrize(
    "targets",
    (
        pytest.param(
            lambda target: (replace(target, title="Mutated claim"),),
            id="semantic-mutation",
        ),
        pytest.param(
            lambda target: (
                target,
                _identity_transition_item(
                    "H-04", previous_id="INV-003", queue_priority=2
                ),
            ),
            id="one-source-fanned-to-two-targets",
        ),
        pytest.param(
            lambda _target: (
                _identity_transition_item("H-99", queue_priority=1),
            ),
            id="invented-target-without-lineage",
        ),
    ),
)
def test_policy_identity_accounting_rejects_unsafe_identity_changes(
    targets: Any,
) -> None:
    source = _identity_transition_item("INV-003", queue_priority=3)
    target = _identity_transition_item(
        "H-03", previous_id="INV-003", queue_priority=1
    )

    accounting = semantics._build_policy_identity_accounting(
        (source,), targets(target), ()
    )

    assert accounting["exact_partition"] is False
    assert accounting["visible_debt_ids"] == ["INV-003"]
    assert accounting["unauthorized_target_ids"]


def test_policy_identity_accounting_replay_rejects_transition_tampering() -> None:
    source = _identity_transition_item("INV-003")
    target = _identity_transition_item("H-03", previous_id="INV-003")
    accounting = semantics._build_policy_identity_accounting(
        (source,), (target,), ()
    )
    accounting["identity_transitions"][0]["target_work_item_digest"] = "0" * 64

    with pytest.raises(
        LiveVerifyQueueSemanticError,
        match="digest- and lineage-bound",
    ):
        semantics._validate_policy_identity_accounting(
            accounting, (target,), ()
        )
