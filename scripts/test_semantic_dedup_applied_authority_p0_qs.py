"""P0-Q/P0-S semantic-dedup application authority contracts.

The LLM/heuristic decision artifact is a proposal.  Only the immutable typed
application receipt may authorize an absorbed identity downstream.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
from pathlib import Path

import pytest

from artifact_ledger import ArtifactLedgerError
import semantic_dedup_authority as A
import plamen_driver as D
import plamen_mechanical as M
from plamen_mechanical import (
    _apply_mechanical_dedup_from_pairs,
    _extract_dedup_absorbed_ids,
    apply_llm_dedup_decisions,
)


def _finding(
    fid: str,
    *,
    title: str,
    location: str,
    source_ids: str,
    severity: str = "Medium",
    root: str = "A state transition omits its required guard.",
    description: str = "The transition accepts a state that violates the model.",
    preconditions: str = "A caller reaches the transition at the boundary.",
    impact: str = "The invalid state can affect later value accounting.",
    recommendation: str = "Enforce the guard before committing state.",
    external: str = "The external component may return any documented value.",
    proof_scope: str = "The cited transition and its direct caller.",
) -> str:
    return (
        f"### Finding [{fid}]: {title}\n"
        f"**Severity**: {severity}\n"
        f"**Location**: {location}\n"
        f"**Source IDs**: {source_ids}\n"
        f"**Root Cause**: {root}\n"
        f"**Description**: {description}\n"
        f"**Preconditions**: {preconditions}\n"
        f"**Impact**: {impact}\n"
        f"**Recommendation**: {recommendation}\n"
        f"**External Premises**: {external}\n"
        f"**Evidence Scope**: {proof_scope}\n"
        "[CODE-TRACE]\n\n"
    )


def _decisions(*lines: str) -> str:
    return "# Semantic Dedup Decisions\n\n" + "\n".join(lines) + "\n"


def _canonical_receipt(path: Path) -> dict:
    raw = path.read_bytes()
    payload = json.loads(raw)
    assert raw == A.canonical_json_bytes(payload)
    return payload


def test_exact_superset_live_apply_preserves_every_absorbed_field_and_writes_receipt(
    tmp_path: Path,
) -> None:
    absorbed = _finding(
        "INV-002",
        title="Boundary variant",
        location="contracts/pool.move:44-47",
        source_ids="B-2",
        severity="High",
        root="The boundary branch skips the guard.",
        description="At the exact boundary, the alternate branch commits first.",
        preconditions="The value equals the upper bound.",
        impact="The stronger boundary impact remains independently material.",
        recommendation="Guard both sides of the branch.",
        external="A dependency response is not assumed stable.",
        proof_scope="Only the boundary branch was traced.",
    )
    survivor = _finding(
        "INV-001",
        title="Transition guard omission",
        location="contracts/pool.move:40-55",
        source_ids="A-1, B-2",
        severity="High",
    )
    pre = survivor + absorbed
    (tmp_path / "findings_inventory.md").write_text(pre, encoding="utf-8")
    (tmp_path / "dedup_decisions.md").write_text(
        _decisions("MERGE: INV-001, INV-002\tsame mechanism"),
        encoding="utf-8",
    )

    assert apply_llm_dedup_decisions(tmp_path, "sc_semantic_dedup") == 1
    pre_exact = (tmp_path / "findings_inventory.md").read_bytes().decode("utf-8")
    post = (tmp_path / "findings_inventory_deduped.md").read_bytes().decode("utf-8")
    assert set(A.extract_finding_records(pre_exact)) == {"INV-001", "INV-002"}
    assert set(A.extract_finding_records(post)) == {"INV-001"}
    check = A.assess_field_preservation(
        A.extract_finding_records(pre_exact), post, "INV-002", "INV-001"
    )
    assert check["passed"] is True
    expected = {
        "mechanism_root_cause",
        "description",
        "preconditions",
        "impact",
        "recommendation",
        "external_premises",
        "evidence_scope",
        "locations",
        "source_ids",
        "severity",
    }
    assert expected <= set(check["preserved_fields"])

    receipt = _canonical_receipt(tmp_path / A.PRIMARY_RECEIPT_NAME)
    assert receipt["accepted_absorbed_ids"] == ["INV-002"]
    assert receipt["identity_delta"]["removed_ids"] == ["INV-002"]
    assert receipt["postconditions"]["accepted_equals_identity_delta"] is True
    decision = next(d for d in receipt["decisions"] if d["member_id"] == "INV-002")
    assert decision["status"] == "ACCEPTED"
    assert decision["actual_survivor"] == "INV-001"


def test_lossy_transform_is_vetoed_before_receipt_and_members_remain_separate(
    tmp_path: Path,
) -> None:
    pre = _finding(
        "INV-001", title="Same title", location="src/lib.rs:10-20", source_ids="A-1, B-1"
    ) + _finding(
        "INV-002",
        title="Same title",
        location="src/lib.rs:12-14",
        source_ids="B-1",
        root="A distinct root cause must not disappear.",
        impact="A unique stronger impact must survive.",
        recommendation="A unique repair site must survive.",
    )
    records = A.extract_finding_records(pre)
    lossy = records["INV-001"]["raw"] + "\n"
    check = A.assess_field_preservation(records, lossy, "INV-002", "INV-001")
    assert check["passed"] is False
    assert "preserved-member-card-missing" in check["issues"]

    proposals = A.parse_dedup_proposals(_decisions("MERGE: INV-001, INV-002\tproposal"))
    with pytest.raises(A.DedupAuthorityError, match="field preservation"):
        A.write_applied_receipt(
            tmp_path,
            phase_name="sc_semantic_dedup",
            application_kind="PRIMARY",
            proposal_text=_decisions("MERGE: INV-001, INV-002\tproposal"),
            proposals=proposals,
            input_text=pre,
            output_text=lossy,
            applied_merges=[("INV-002", "INV-001", "proposal")],
        )
    assert not (tmp_path / A.PRIMARY_RECEIPT_NAME).exists()


def test_conflicting_merge_keep_is_vetoed_not_applied(tmp_path: Path) -> None:
    pre = _finding(
        "INV-001", title="A", location="module.move:10-30", source_ids="A-1, B-1"
    ) + _finding(
        "INV-002", title="B", location="module.move:12-20", source_ids="B-1"
    )
    (tmp_path / "findings_inventory.md").write_text(pre, encoding="utf-8")
    (tmp_path / "dedup_decisions.md").write_text(
        _decisions(
            "MERGE: INV-001, INV-002\tproposal",
            "KEEP: INV-002",
            "| INV-002 | PASSTHROUGH | independently live |",
        ),
        encoding="utf-8",
    )
    assert apply_llm_dedup_decisions(tmp_path, "sc_semantic_dedup") == 0
    assert (tmp_path / "findings_inventory_deduped.md").read_text(encoding="utf-8") == pre
    receipt = _canonical_receipt(tmp_path / A.PRIMARY_RECEIPT_NAME)
    assert receipt["accepted_absorbed_ids"] == []
    rejected = [d for d in receipt["decisions"] if d["member_id"] == "INV-002"]
    assert rejected and rejected[0]["status"] == "REJECTED"
    assert rejected[0]["reason"] == "CONFLICTING_PROPOSAL"


def test_conflicting_requested_survivors_veto_ambiguous_absorption(
    tmp_path: Path,
) -> None:
    pre = (
        _finding("INV-001", title="A", location="x.rs:1-40", source_ids="A-1, B-1")
        + _finding("INV-002", title="B", location="x.rs:10-12", source_ids="B-1")
        + _finding("INV-003", title="C", location="x.rs:1-40", source_ids="B-1, C-1")
    )
    (tmp_path / "findings_inventory.md").write_text(pre, encoding="utf-8")
    (tmp_path / "dedup_decisions.md").write_text(
        _decisions("MERGE: INV-001, INV-002", "MERGE: INV-003, INV-002"),
        encoding="utf-8",
    )
    assert apply_llm_dedup_decisions(tmp_path, "sc_semantic_dedup") == 0
    assert (tmp_path / "findings_inventory_deduped.md").read_text(encoding="utf-8") == pre
    receipt = _canonical_receipt(tmp_path / A.PRIMARY_RECEIPT_NAME)
    member_rows = [d for d in receipt["decisions"] if d["member_id"] == "INV-002"]
    assert len(member_rows) == 2
    assert {d["reason"] for d in member_rows} == {"CONFLICTING_PROPOSAL"}


def test_partially_accepted_transitive_group_records_exact_delta(tmp_path: Path) -> None:
    pre = (
        _finding("INV-001", title="A", location="x.rs:10-50", source_ids="A-1, B-1")
        + _finding("INV-002", title="B", location="x.rs:20-30", source_ids="B-1")
        + _finding("INV-003", title="C", location="y.rs:4-8", source_ids="C-1")
    )
    (tmp_path / "findings_inventory.md").write_text(pre, encoding="utf-8")
    (tmp_path / "dedup_decisions.md").write_text(
        _decisions("MERGE: INV-001, INV-002", "MERGE: INV-002, INV-003"),
        encoding="utf-8",
    )
    assert apply_llm_dedup_decisions(tmp_path, "sc_semantic_dedup") == 1
    post = (tmp_path / "findings_inventory_deduped.md").read_text(encoding="utf-8")
    assert set(A.extract_finding_records(post)) == {"INV-001", "INV-003"}
    receipt = _canonical_receipt(tmp_path / A.PRIMARY_RECEIPT_NAME)
    assert receipt["accepted_absorbed_ids"] == ["INV-002"]
    c = next(d for d in receipt["decisions"] if d["member_id"] == "INV-003")
    assert c["status"] == "REJECTED"
    assert c["reason"] in {"SUPERSET_GATE_REJECTED", "NOT_APPLIED"}


def test_survivor_superset_direction_flip_is_explicit_in_receipt(tmp_path: Path) -> None:
    pre = _finding(
        "INV-001", title="Narrow", location="x.rs:20-22", source_ids="B-1"
    ) + _finding(
        "INV-002", title="Complete", location="x.rs:10-40", source_ids="A-1, B-1"
    )
    (tmp_path / "findings_inventory.md").write_text(pre, encoding="utf-8")
    (tmp_path / "dedup_decisions.md").write_text(
        _decisions("MERGE: INV-001, INV-002"), encoding="utf-8"
    )
    assert apply_llm_dedup_decisions(tmp_path, "sc_semantic_dedup") == 1
    receipt = _canonical_receipt(tmp_path / A.PRIMARY_RECEIPT_NAME)
    accepted = next(
        d for d in receipt["decisions"]
        if d["status"] == "ACCEPTED" and d["member_id"] == "INV-001"
    )
    assert accepted["requested_survivor"] == "INV-001"
    assert accepted["actual_survivor"] == "INV-002"
    assert accepted["direction_flipped"] is True


def test_missing_proposal_member_is_rejected_and_existing_member_stays_live(
    tmp_path: Path,
) -> None:
    pre = _finding(
        "INV-001", title="Live", location="x.move:1-20", source_ids="A-1"
    )
    (tmp_path / "findings_inventory.md").write_text(pre, encoding="utf-8")
    (tmp_path / "dedup_decisions.md").write_text(
        _decisions("MERGE: INV-001, INV-999"), encoding="utf-8"
    )
    assert apply_llm_dedup_decisions(tmp_path, "sc_semantic_dedup") == 0
    post = (tmp_path / "findings_inventory_deduped.md").read_text(encoding="utf-8")
    assert post == pre
    receipt = _canonical_receipt(tmp_path / A.PRIMARY_RECEIPT_NAME)
    missing = next(d for d in receipt["decisions"] if d["member_id"] == "INV-999")
    assert missing["status"] == "REJECTED"
    assert missing["reason"] == "MEMBER_NOT_IN_INPUT"
    assert set(A.extract_finding_records(post)) == {"INV-001"}


def test_primary_and_supplemental_receipts_form_one_transitive_live_chain(
    tmp_path: Path,
) -> None:
    pre = (
        _finding(
            "INV-001",
            title="Shared transition",
            location="x.rs:10-60",
            source_ids="A-1, B-1, C-1",
        )
        + _finding(
            "INV-002",
            title="Shared transition",
            location="x.rs:20-25",
            source_ids="B-1",
        )
        + _finding(
            "INV-003",
            title="Shared transition",
            location="x.rs:40-45",
            source_ids="C-1",
        )
    )
    (tmp_path / "findings_inventory.md").write_text(pre, encoding="utf-8")
    (tmp_path / "dedup_decisions.md").write_text(
        _decisions("MERGE: INV-001, INV-002"), encoding="utf-8"
    )
    assert apply_llm_dedup_decisions(tmp_path, "sc_semantic_dedup") == 1
    shutil.copy2(
        tmp_path / "findings_inventory_deduped.md",
        tmp_path / "findings_inventory.md",
    )
    (tmp_path / "dedup_candidate_pairs_full.md").write_text(
        "# Full candidates\n\n"
        "| Finding A | Finding B | Title Score | Signal | Same Sev? |\n"
        "|---|---|---|---|---|\n"
        "| INV-001: Shared transition | INV-003: Shared transition | 1.00 | "
        "location overlap L10-60 vs L40-45 | yes |\n",
        encoding="utf-8",
    )
    assert _apply_mechanical_dedup_from_pairs(
        tmp_path, "sc_semantic_dedup", supplemental=True
    ) == 1
    primary = _canonical_receipt(tmp_path / A.PRIMARY_RECEIPT_NAME)
    supplemental = _canonical_receipt(tmp_path / A.SUPPLEMENTAL_RECEIPT_NAME)
    assert primary["output_artifact"]["sha256"] == supplemental["input_artifact"]["sha256"]
    assert set(A.extract_finding_records((tmp_path / "findings_inventory.md").read_text())) == {
        "INV-001"
    }
    assert A.load_applied_aliases(tmp_path) == {
        "INV-002": {"survivor": "INV-001", "coupled": "field-complete-preserved"},
        "INV-003": {"survivor": "INV-001", "coupled": "field-complete-preserved"},
    }


def test_stale_primary_vetoes_supplemental_and_restores_every_live_member(
    tmp_path: Path,
) -> None:
    pre = (
        _finding(
            "INV-001", title="Shared", location="x.rs:10-60", source_ids="A-1, B-1, C-1"
        )
        + _finding("INV-002", title="Shared", location="x.rs:20-25", source_ids="B-1")
        + _finding("INV-003", title="Shared", location="x.rs:40-45", source_ids="C-1")
    )
    (tmp_path / "findings_inventory.md").write_text(pre, encoding="utf-8")
    (tmp_path / "dedup_decisions.md").write_text(
        _decisions("MERGE: INV-001, INV-002"), encoding="utf-8"
    )
    assert apply_llm_dedup_decisions(tmp_path, "sc_semantic_dedup") == 1
    shutil.copy2(tmp_path / "findings_inventory_deduped.md", tmp_path / "findings_inventory.md")
    canonical = tmp_path / "findings_inventory.md"
    drifted = canonical.read_bytes() + b"\n<!-- independent semantic drift -->\n"
    canonical.write_bytes(drifted)
    (tmp_path / "dedup_candidate_pairs_full.md").write_text(
        "| Finding A | Finding B | Title Score | Signal | Same Sev? |\n"
        "|---|---|---|---|---|\n"
        "| INV-001: Shared | INV-003: Shared | 1.00 | "
        "location overlap L10-60 vs L40-45 | yes |\n",
        encoding="utf-8",
    )
    assert _apply_mechanical_dedup_from_pairs(
        tmp_path, "sc_semantic_dedup", supplemental=True
    ) == 0
    assert canonical.read_bytes() == drifted
    assert set(A.extract_finding_records(drifted.decode("utf-8"))) == {
        "INV-001", "INV-003"
    }
    assert not (tmp_path / A.SUPPLEMENTAL_RECEIPT_NAME).exists()


def test_supplemental_receipt_before_commit_crash_resumes_atomically(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    pre = (
        _finding(
            "INV-001", title="Shared", location="x.rs:10-60", source_ids="A-1, B-1, C-1"
        )
        + _finding("INV-002", title="Shared", location="x.rs:20-25", source_ids="B-1")
        + _finding("INV-003", title="Shared", location="x.rs:40-45", source_ids="C-1")
    )
    (tmp_path / "findings_inventory.md").write_text(pre, encoding="utf-8")
    (tmp_path / "dedup_decisions.md").write_text(
        _decisions("MERGE: INV-001, INV-002"), encoding="utf-8"
    )
    assert apply_llm_dedup_decisions(tmp_path, "sc_semantic_dedup") == 1
    shutil.copy2(tmp_path / "findings_inventory_deduped.md", tmp_path / "findings_inventory.md")
    (tmp_path / "dedup_candidate_pairs_full.md").write_text(
        "| Finding A | Finding B | Title Score | Signal | Same Sev? |\n"
        "|---|---|---|---|---|\n"
        "| INV-001: Shared | INV-003: Shared | 1.00 | "
        "location overlap L10-60 vs L40-45 | yes |\n",
        encoding="utf-8",
    )
    canonical = tmp_path / "findings_inventory.md"
    before = canonical.read_bytes()
    real_replace = M.os.replace

    def crash_commit(source, destination):
        if str(source).endswith(".semantic_dedup.pending"):
            raise OSError("injected crash before canonical replace")
        return real_replace(source, destination)

    monkeypatch.setattr(M.os, "replace", crash_commit)
    assert _apply_mechanical_dedup_from_pairs(
        tmp_path, "sc_semantic_dedup", supplemental=True
    ) == 0
    assert canonical.read_bytes() == before
    assert (tmp_path / A.SUPPLEMENTAL_RECEIPT_NAME).is_file()
    pending = tmp_path / "findings_inventory.md.semantic_dedup.pending"
    assert pending.is_file()

    monkeypatch.setattr(M.os, "replace", real_replace)
    assert _apply_mechanical_dedup_from_pairs(
        tmp_path, "sc_semantic_dedup", supplemental=True
    ) == 1
    assert not pending.exists()
    assert set(A.extract_finding_records(canonical.read_bytes().decode("utf-8"))) == {
        "INV-001"
    }
    assert A.load_applied_aliases(tmp_path)["INV-003"]["survivor"] == "INV-001"


def test_receipt_and_preserved_card_bind_exact_crlf_source_bytes(tmp_path: Path) -> None:
    survivor = _finding(
        "INV-001", title="A", location="x.sol:1-20", source_ids="A-1, B-1"
    ).replace("\n", "\r\n")
    absorbed = _finding(
        "INV-002", title="B", location="x.sol:2-4", source_ids="B-1"
    ).replace("\n", "\r\n")
    pre_bytes = (survivor + absorbed).encode("utf-8")
    (tmp_path / "findings_inventory.md").write_bytes(pre_bytes)
    (tmp_path / "dedup_decisions.md").write_bytes(
        _decisions("MERGE: INV-001, INV-002").replace("\n", "\r\n").encode("utf-8")
    )
    assert apply_llm_dedup_decisions(tmp_path, "sc_semantic_dedup") == 1
    receipt = _canonical_receipt(tmp_path / A.PRIMARY_RECEIPT_NAME)
    assert receipt["input_artifact"]["sha256"] == hashlib.sha256(pre_bytes).hexdigest()
    accepted = next(d for d in receipt["decisions"] if d["status"] == "ACCEPTED")
    assert accepted["field_preservation"]["absorbed_raw_sha256"] == hashlib.sha256(
        absorbed.encode("utf-8")
    ).hexdigest()


def test_non_evm_row_form_preserves_exact_row_before_removal(tmp_path: Path) -> None:
    inventory = (
        "# Findings Inventory\n\n"
        "| Finding ID | Title | Severity | Location | Preferred Tag | Description | Impact |\n"
        "|---|---|---|---|---|---|---|\n"
        "| INV-001 | Consensus transition | High | consensus/state.go:20-40 | [CODE-TRACE] | first path | safety impact |\n"
        "| INV-002 | Consensus transition boundary | High | consensus/state.go:25-26 | [CODE-TRACE] | distinct boundary | liveness impact |\n"
    )
    (tmp_path / "findings_inventory.md").write_text(inventory, encoding="utf-8")
    (tmp_path / "dedup_decisions.md").write_text(
        _decisions("MERGE: INV-001, INV-002"), encoding="utf-8"
    )
    assert apply_llm_dedup_decisions(tmp_path, "semantic_dedup") == 1
    post = (tmp_path / "findings_inventory_deduped.md").read_text(encoding="utf-8")
    assert set(A.extract_finding_records(post)) == {"INV-001"}
    assert "PLAMEN_DEDUP_PRESERVED_MEMBER_BEGIN id=INV-002" in post
    survivor_row = next(
        line for line in post.splitlines()
        if line.strip().startswith("| INV-001")
    )
    assert "coupled INV-002: distinct boundary" in survivor_row
    receipt = _canonical_receipt(tmp_path / A.PRIMARY_RECEIPT_NAME)
    assert receipt["accepted_absorbed_ids"] == ["INV-002"]
    decision = next(d for d in receipt["decisions"] if d["member_id"] == "INV-002")
    assert decision["field_preservation"]["passed"] is True


def test_l1_distinct_primary_artifacts_veto_merge_and_keep_two_verify_jobs(
    tmp_path: Path,
) -> None:
    inventory = (
        "# Findings Inventory\n\n"
        "| Finding ID | Title | Severity | Location | Bug Class | Preferred Tag | Primary Artifact | PoC Class |\n"
        "|---|---|---|---|---|---|---|---|\n"
        "| INV-001 | Shared transition | High | state.rs:10-60 | consensus | [CODE-TRACE] | analysis_a.md | conformance |\n"
        "| INV-002 | Shared transition | High | state.rs:20-25 | consensus | [CODE-TRACE] | analysis_b.md | conformance |\n"
    )
    (tmp_path / "findings_inventory.md").write_text(inventory, encoding="utf-8")
    (tmp_path / "dedup_decisions.md").write_text(
        _decisions("MERGE: INV-001, INV-002"), encoding="utf-8"
    )
    assert apply_llm_dedup_decisions(tmp_path, "semantic_dedup") == 0
    post = (tmp_path / "findings_inventory_deduped.md").read_bytes().decode("utf-8")
    assert set(A.extract_finding_records(post)) == {"INV-001", "INV-002"}
    receipt = _canonical_receipt(tmp_path / A.PRIMARY_RECEIPT_NAME)
    assert receipt["accepted_absorbed_ids"] == []
    rejected = next(d for d in receipt["decisions"] if d["member_id"] == "INV-002")
    assert rejected["status"] == "REJECTED"
    assert rejected["reason"] == "SUPERSET_GATE_REJECTED"
    assert D._dedup_absorbed_survivor_mapping(tmp_path) == {}


def test_receipt_resume_is_idempotent_but_stale_or_tampered_receipt_fails(
    tmp_path: Path,
) -> None:
    pre = _finding(
        "INV-001", title="A", location="a.sol:10-30", source_ids="A-1, B-1"
    ) + _finding(
        "INV-002", title="B", location="a.sol:12-15", source_ids="B-1"
    )
    decisions = _decisions("MERGE: INV-001, INV-002")
    (tmp_path / "findings_inventory.md").write_text(pre, encoding="utf-8")
    (tmp_path / "dedup_decisions.md").write_text(decisions, encoding="utf-8")
    assert apply_llm_dedup_decisions(tmp_path, "sc_semantic_dedup") == 1
    receipt_path = tmp_path / A.PRIMARY_RECEIPT_NAME
    before = receipt_path.read_bytes()
    assert apply_llm_dedup_decisions(tmp_path, "sc_semantic_dedup") == 1
    assert receipt_path.read_bytes() == before

    payload = json.loads(before)
    payload["accepted_absorbed_ids"] = []
    receipt_path.write_bytes(A.canonical_json_bytes(payload))
    with pytest.raises(A.DedupAuthorityError):
        A.load_applied_aliases(tmp_path, canonical_text=(tmp_path / "findings_inventory_deduped.md").read_text())


def test_crash_before_receipt_can_resume_from_source_without_trusting_target(
    tmp_path: Path,
) -> None:
    pre = _finding(
        "INV-001", title="A", location="a.rs:1-20", source_ids="A-1, B-1"
    ) + _finding(
        "INV-002", title="B", location="a.rs:2-4", source_ids="B-1"
    )
    (tmp_path / "findings_inventory.md").write_text(pre, encoding="utf-8")
    (tmp_path / "findings_inventory_deduped.md").write_text("partial crash bytes", encoding="utf-8")
    (tmp_path / "dedup_decisions.md").write_text(
        _decisions("MERGE: INV-001, INV-002"), encoding="utf-8"
    )
    assert not (tmp_path / A.PRIMARY_RECEIPT_NAME).exists()
    assert apply_llm_dedup_decisions(tmp_path, "sc_semantic_dedup") == 1
    assert _canonical_receipt(tmp_path / A.PRIMARY_RECEIPT_NAME)["accepted_absorbed_ids"] == ["INV-002"]


def test_alias_loader_requires_valid_receipt_and_exact_current_output(tmp_path: Path) -> None:
    pre = _finding(
        "INV-001", title="A", location="a.move:1-20", source_ids="A-1, B-1"
    ) + _finding(
        "INV-002", title="B", location="a.move:2-4", source_ids="B-1"
    )
    (tmp_path / "findings_inventory.md").write_text(pre, encoding="utf-8")
    (tmp_path / "dedup_decisions.md").write_text(
        _decisions("MERGE: INV-001, INV-002"), encoding="utf-8"
    )
    assert A.load_applied_aliases(tmp_path, canonical_text=pre) == {}
    assert apply_llm_dedup_decisions(tmp_path, "sc_semantic_dedup") == 1
    post = (tmp_path / "findings_inventory_deduped.md").read_text(encoding="utf-8")
    assert A.load_applied_aliases(tmp_path, canonical_text=post) == {
        "INV-002": {"survivor": "INV-001", "coupled": "field-complete-preserved"}
    }
    with pytest.raises(A.DedupAuthorityError, match="output hash"):
        A.load_applied_aliases(tmp_path, canonical_text=post + "tamper")


def test_live_driver_alias_consumer_uses_accepted_receipt_only(tmp_path: Path) -> None:
    pre = _finding(
        "INV-001", title="A", location="a.sol:1-20", source_ids="A-1, B-1"
    ) + _finding(
        "INV-002", title="B", location="a.sol:2-4", source_ids="B-1"
    )
    decisions = _decisions("MERGE: INV-001, INV-002")
    (tmp_path / "findings_inventory.md").write_text(pre, encoding="utf-8")
    (tmp_path / "dedup_decisions.md").write_text(decisions, encoding="utf-8")

    # Raw proposal alone is never authority.
    assert D._dedup_absorbed_survivor_mapping(tmp_path) == {}
    assert apply_llm_dedup_decisions(tmp_path, "sc_semantic_dedup") == 1
    post_bytes = (tmp_path / "findings_inventory_deduped.md").read_bytes()
    shutil.copy2(
        tmp_path / "findings_inventory_deduped.md",
        tmp_path / "findings_inventory.md",
    )
    assert D._dedup_absorbed_survivor_mapping(tmp_path) == {
        "INV-002": {"survivor": "INV-001", "coupled": "field-complete-preserved"}
    }

    # Canonical artifact tamper/staleness removes authority rather than
    # falling back to proposal prose.
    (tmp_path / "findings_inventory.md").write_bytes(post_bytes + b"tamper")
    assert D._dedup_absorbed_survivor_mapping(tmp_path) == {}


def test_proposal_carry_forward_prevents_repairing_but_grants_no_alias_or_coverage(
    tmp_path: Path,
) -> None:
    (tmp_path / "dedup_decisions.md").write_text(
        _decisions("MERGE: INV-001, INV-002"), encoding="utf-8"
    )
    exclusion = D._build_dedup_round_exclusion_block(tmp_path)
    assert "INV-001" in exclusion and "INV-002" in exclusion
    assert D._dedup_absorbed_survivor_mapping(tmp_path) == {}
    assert _extract_dedup_absorbed_ids(tmp_path) == set()


def test_no_merge_path_still_writes_identity_receipt(tmp_path: Path) -> None:
    pre = _finding(
        "INV-001", title="A", location="a.rs:1-2", source_ids="A-1"
    )
    (tmp_path / "findings_inventory.md").write_text(pre, encoding="utf-8")
    (tmp_path / "dedup_decisions.md").write_text(
        _decisions("KEEP: INV-001"), encoding="utf-8"
    )
    assert apply_llm_dedup_decisions(tmp_path, "sc_semantic_dedup") == 0
    receipt = _canonical_receipt(tmp_path / A.PRIMARY_RECEIPT_NAME)
    assert receipt["accepted_absorbed_ids"] == []
    assert receipt["input_artifact"]["sha256"] == receipt["output_artifact"]["sha256"]


def _sc_phase() -> D.Phase:
    return D.Phase(
        name="sc_semantic_dedup",
        section_markers=[],
        expected_artifacts=["dedup_decisions.md", "findings_inventory_deduped.md"],
        base_timeout_s=1,
        min_artifact_bytes=10,
    )


def _seed_l1_prequeue_fixture(project: Path):
    """Use the canonical current-architecture seed, not a legacy queue shim."""
    from test_l1_semantic_dedup_prequeue_transaction_red import (
        RUN_ID,
        _required_apply,
        _seed,
    )

    scratchpad, config = _seed(project)
    return scratchpad, config, RUN_ID, _required_apply()


def test_sc_live_commit_requires_valid_primary_receipt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    original = (
        _finding("INV-001", title="A", location="x.sol:1-20", source_ids="A-1, B-1")
        + _finding("INV-002", title="B", location="x.sol:2-4", source_ids="B-1")
    )
    original_bytes = original.encode("utf-8")
    (tmp_path / "findings_inventory.md").write_bytes(original_bytes)
    # A stale/worker-authored rewrite proposes destructive output but the
    # mechanical apply crashes before producing applied authority.
    (tmp_path / "findings_inventory_deduped.md").write_text(
        _finding("INV-001", title="A", location="x.sol:1-20", source_ids="A-1, B-1"),
        encoding="utf-8",
    )
    (tmp_path / "dedup_decisions.md").write_text(
        _decisions("MERGE: INV-001, INV-002"), encoding="utf-8"
    )

    def fail_apply(*_args, **_kwargs):
        raise RuntimeError("injected apply crash")

    monkeypatch.setattr(D, "apply_llm_dedup_decisions", fail_apply)
    monkeypatch.setattr(D, "_apply_mechanical_dedup_from_pairs", lambda *a, **k: 0)
    monkeypatch.setattr(D, "_propagate_dedup_absorbed_to_finding_mapping", lambda *a, **k: 0)
    passed, missing = D._run_phase_validators(
        _sc_phase(),
        {"mode": "thorough", "pipeline": "sc", "project_root": str(tmp_path)},
        tmp_path,
        [],
        0,
        {},
    )
    assert passed is True, missing
    assert (tmp_path / "findings_inventory.md").read_bytes() == original_bytes
    assert not (tmp_path / "findings_inventory_pre_dedup.md").exists()
    assert D._dedup_absorbed_survivor_mapping(tmp_path) == {}


def test_sc_live_commit_accepts_exact_receipted_delta_before_propagation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    original = (
        _finding("INV-001", title="A", location="x.sol:1-20", source_ids="A-1, B-1")
        + _finding("INV-002", title="B", location="x.sol:2-4", source_ids="B-1")
    )
    (tmp_path / "findings_inventory.md").write_text(original, encoding="utf-8")
    (tmp_path / "findings_inventory_deduped.md").write_text(original, encoding="utf-8")
    (tmp_path / "dedup_decisions.md").write_text(
        _decisions("MERGE: INV-001, INV-002"), encoding="utf-8"
    )
    observed: list[str] = []

    def inspect_supplement(_scratchpad, _phase, *, supplemental=False):
        assert supplemental is True
        assert set(A.extract_finding_records(
            (tmp_path / "findings_inventory.md").read_bytes().decode("utf-8")
        )) == {"INV-001"}
        assert A.load_applied_aliases(tmp_path)["INV-002"]["survivor"] == "INV-001"
        observed.append("supplement")
        return 0

    def inspect_propagation(_scratchpad):
        assert D._dedup_absorbed_survivor_mapping(tmp_path)["INV-002"]["survivor"] == "INV-001"
        observed.append("propagate")
        return 1

    monkeypatch.setattr(D, "_apply_mechanical_dedup_from_pairs", inspect_supplement)
    monkeypatch.setattr(D, "_propagate_dedup_absorbed_to_finding_mapping", inspect_propagation)
    passed, missing = D._run_phase_validators(
        _sc_phase(),
        {"mode": "thorough", "pipeline": "sc", "project_root": str(tmp_path)},
        tmp_path,
        [],
        0,
        {},
    )
    assert passed is True, missing
    assert observed == ["supplement", "propagate"]


def test_l1_prequeue_apply_commits_receipted_inventory_before_queue_publication(
    tmp_path: Path,
) -> None:
    """The applied receipt authorizes inventory aliases before T0 can exist."""
    project = tmp_path / "project"
    scratchpad, config, run_id, apply = _seed_l1_prequeue_fixture(project)

    result = apply(
        scratchpad=scratchpad,
        project_root=project,
        config=config,
        run_id=run_id,
    )
    assert result["safe_to_consume"] is True
    canonical_bytes = (scratchpad / "findings_inventory.md").read_bytes()
    canonical = canonical_bytes.decode("utf-8")
    assert set(A.extract_finding_records(canonical)) == {"INV-001", "INV-003"}
    assert A.load_applied_aliases(scratchpad) == {
        "INV-002": {
            "survivor": "INV-001",
            "coupled": "field-complete-preserved",
        }
    }
    receipt = _canonical_receipt(scratchpad / A.PRIMARY_RECEIPT_NAME)
    assert receipt["output_artifact"]["sha256"] == hashlib.sha256(
        canonical_bytes
    ).hexdigest()
    assert not any(scratchpad.glob("verification_queue*"))


def test_l1_unowned_receipt_residue_never_changes_prequeue_inventory_authority(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    scratchpad, config, run_id, apply = _seed_l1_prequeue_fixture(project)
    inventory_before = (scratchpad / "findings_inventory.md").read_bytes()
    records_before = (scratchpad / "finding_records.json").read_bytes()
    # A corrupt, unowned create-before-arm residue must block the RMW owner.
    (scratchpad / A.PRIMARY_RECEIPT_NAME).write_text("{}\n", encoding="utf-8")

    with pytest.raises(
        ArtifactLedgerError,
        match="(?i)(prestate|unowned|authority|arm)",
    ):
        apply(
            scratchpad=scratchpad,
            project_root=project,
            config=config,
            run_id=run_id,
        )

    assert (scratchpad / "findings_inventory.md").read_bytes() == inventory_before
    assert (scratchpad / "finding_records.json").read_bytes() == records_before
    assert D._dedup_absorbed_survivor_mapping(scratchpad) == {}


def test_l1_prequeue_apply_never_mutates_existing_queue_or_shards(
    tmp_path: Path,
) -> None:
    """Only the later queue transaction may publish or replace T0--T9."""
    project = tmp_path / "project"
    scratchpad, config, run_id, apply = _seed_l1_prequeue_fixture(project)
    sentinels = {
        "verification_queue.md": b"# already-published queue sentinel\n",
        "verification_queue.work_items.json": b'{"sentinel":true}\n',
        "verification_queue_critical.md": b"# shard sentinel\n",
    }
    for name, raw in sentinels.items():
        (scratchpad / name).write_bytes(raw)

    result = apply(
        scratchpad=scratchpad,
        project_root=project,
        config=config,
        run_id=run_id,
    )
    assert result["safe_to_consume"] is True
    assert {
        name: (scratchpad / name).read_bytes() for name in sentinels
    } == sentinels
    assert set(A.extract_finding_records(
        (scratchpad / "findings_inventory.md").read_text(encoding="utf-8")
    )) == {"INV-001", "INV-003"}


def test_production_module_is_exported_and_not_gitignored() -> None:
    assert {
        "write_applied_receipt",
        "load_applied_aliases",
        "assess_field_preservation",
    } <= set(A.__all__)
    assert {
        "_apply_mechanical_dedup_from_pairs",
        "_extract_dedup_absorbed_ids",
        "apply_llm_dedup_decisions",
    } <= set(M.__all__)
    repo = Path(__file__).resolve().parent.parent
    result = subprocess.run(
        ["git", "check-ignore", "scripts/semantic_dedup_authority.py"],
        cwd=repo,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 1, result.stdout + result.stderr
