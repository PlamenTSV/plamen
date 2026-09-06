"""NC-2 adversarial invariants for denied terminal-negative decisions.

These fixtures deliberately exercise authenticated-looking negative prose and
shape-valid v1 lifecycle labels.  Neither is a replayable terminal provider.
The exact candidate must therefore remain public and carry one stable,
mandatory re-verification obligation.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from finding_lifecycle_authority import build_finding_lifecycle
from inventory_reconciliation import (
    AUTHORITY_SCHEMA,
    NEGATIVE_EVIDENCE_SCHEMA,
    reconcile_inventory,
    write_inventory_reconciliation,
)
from report_disposition_authority import build_report_disposition_authority
from test_finding_lifecycle_authority_p0_g_n_x_y_aa import (
    _candidate,
    _decision,
    _projection,
)
from test_inventory_exact_reconciliation_p0_l import (
    _authority,
    _finding,
    _inventory,
    _manifest,
    _sha,
)
from test_report_disposition_authority_p0_r import RUN_ID, _setup


@pytest.mark.parametrize(
    ("kind", "basis", "scope"),
    [
        ("REFUTED", "INDEPENDENT_ANALYSIS", "FULL_CLAIM"),
        ("REFUTED", "INDEPENDENT_EXECUTION", "FULL_CLAIM"),
        ("REFUTED", "FORMAL_PROOF", "FULL_CLAIM"),
        ("AUTHORIZED_ZERO_HARM", "INDEPENDENT_ANALYSIS", "FULL_CLAIM"),
        ("AUTHORIZED_SCOPE_EXCLUSION", "EXACT_SCOPE_PREDICATE", "SCOPE_ONLY"),
    ],
)
def test_denied_negative_lifecycle_is_exact_recovery_debt_even_when_projected(
    kind: str,
    basis: str,
    scope: str,
) -> None:
    candidate = _candidate()
    decision = _decision(
        candidate,
        kind=kind,
        evidence_basis=basis,
        proof_scope=scope,
        reason_class=(
            "ZERO_SECURITY_CONSEQUENCE"
            if kind == "AUTHORIZED_ZERO_HARM"
            else "EVIDENCE_DISPOSITION"
        ),
        scope_snapshot_sha256=("d" * 64 if kind == "AUTHORIZED_SCOPE_EXCLUSION" else None),
    )
    lifecycle = build_finding_lifecycle(
        run_id=RUN_ID,
        candidates=[candidate],
        decisions=[decision],
        projections=[_projection(candidate)],
        authority_identity="plamen-driver",
        authority_invocation_id="driver-run-1",
    )

    state = lifecycle["candidate_states"][0]
    recovery = [
        row
        for row in lifecycle["obligations"]
        if row["candidate_id"] == "INV-001"
        and row["obligation_kind"] == "RECOVERY_INDEPENDENT_VERIFICATION"
    ]
    assert state["claim_state"] == "UNVERIFIED"
    assert state["retention_target"] == "BODY"
    assert state["terminal_complete"] is False
    assert len(recovery) == 1
    assert recovery[0]["candidate_content_sha256"] == candidate["candidate_content_sha256"]
    assert recovery[0]["obligation_id"].startswith("FLO-")


@pytest.mark.parametrize("status", ["REFUTED", "FALSE_POSITIVE", "INFEASIBLE", "CLEAR"])
def test_report_negative_proposal_has_exact_mandatory_reverification(
    tmp_path: Path,
    status: str,
) -> None:
    sp, _root, item, _original = _setup(
        tmp_path,
        status=status,
        severity="High",
        disposition="BODY",
    )

    authority = build_report_disposition_authority(sp, run_id=RUN_ID)
    row = authority["rows"][0]
    obligations = [
        obligation
        for obligation in authority["finding_lifecycle"]["obligations"]
        if obligation["candidate_id"] == item.work_item_id
        and obligation["obligation_kind"] == "RECOVERY_INDEPENDENT_VERIFICATION"
    ]
    state = authority["finding_lifecycle"]["candidate_states"][0]

    assert row["public_retention_target"] == "BODY"
    assert row["disposition_authorized"] is False
    assert row["mandatory_reverification"] is True
    assert len(obligations) == 1
    assert row["mandatory_reverification_id"] == obligations[0]["obligation_id"]
    assert state["terminal_complete"] is False


def test_confirmed_report_path_is_not_reclassified_as_negative_debt(
    tmp_path: Path,
) -> None:
    sp, _root, _item, _original = _setup(
        tmp_path,
        status="CONFIRMED",
        severity="High",
        disposition="BODY",
    )
    authority = build_report_disposition_authority(sp, run_id=RUN_ID)
    row = authority["rows"][0]
    assert row["mandatory_reverification"] is False
    assert row["mandatory_reverification_id"] == ""
    assert authority["finding_lifecycle"]["candidate_states"][0][
        "terminal_complete"
    ] is False  # the report index is not itself a delivered report projection


def test_inventory_supporting_negative_emits_exact_mandatory_reverification(
    tmp_path: Path,
) -> None:
    source_name = "analysis_evm_flow.md"
    (tmp_path / source_name).write_text(
        _finding("TF-1", "candidate to challenge"), encoding="utf-8"
    )
    _manifest(tmp_path, "inventory_chunk_a", source_name)
    (tmp_path / "findings_inventory_chunk_a.md").write_text(
        "# no retained finding\n", encoding="utf-8"
    )
    _inventory(tmp_path, [])
    candidate = reconcile_inventory(tmp_path)["candidates"][0]
    evidence = {
        "schema_version": NEGATIVE_EVIDENCE_SCHEMA,
        "provider_id": "source-reviewer",
        "records": [
            {
                "record_id": "NEG-1",
                "candidate_key": candidate["candidate_key"],
                "source_artifact": source_name,
                "source_sha256": _sha(tmp_path / source_name),
                "source_finding_id": "TF-1",
                "source_block_sha256": candidate["source_block_sha256"],
                "verdict": "REFUTED",
                "evidence_scope": "IN_SCOPE_EXECUTION",
                "proof_scope": "HARM",
                "evidence_pointer": "src/Module.sol:L10",
                "evidence_digest": hashlib.sha256(b"bounded negative run").hexdigest(),
            }
        ],
    }
    (tmp_path / "inventory_negative_evidence.json").write_text(
        json.dumps(evidence, sort_keys=True) + "\n", encoding="utf-8"
    )
    _authority(
        tmp_path,
        source=source_name,
        source_id="TF-1",
        disposition="SUPPORTED_REFUTATION",
        evidence_file="inventory_negative_evidence.json",
        evidence_record_id="NEG-1",
    )

    receipt = write_inventory_reconciliation(tmp_path)
    row = receipt["candidates"][0]
    review = (tmp_path / "inventory_reconciliation_human_review.md").read_text(
        encoding="utf-8"
    )
    assert row["disposition"] == "HUMAN_REVIEW_DEBT"
    assert row["mandatory_reverification"] is True
    assert row["mandatory_reverification_id"].startswith("INVRV-")
    assert row["mandatory_reverification_id_binding"] == {
        "candidate_key": row["candidate_key"],
        "source_block_sha256": row["source_block_sha256"],
    }
    assert "INDEPENDENT_VERIFICATION_REQUIRED" in review
