"""Reviewer-owned adversarial fixtures for P0-F/I authority boundaries."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
import plamen_driver as D
import plamen_validators as V
from enumgap_disposition import (
    load_enumgap_disposition_receipt,
    residual_enumgap_queue,
)
from exploration_clear_lifecycle import (
    compile_initial_receipt,
    write_lifecycle_artifacts,
)
from plamen_types import Phase


def _phase() -> Phase:
    return Phase(
        "enumgap_exploration",
        ["Phase 4b.7"],
        ["enumgap_exploration_findings.md"],
        base_timeout_s=120,
        modes={"core", "thorough"},
        critical=False,
        model="sonnet",
    )


def _config(project: Path) -> dict[str, object]:
    return {
        "project_root": str(project),
        "pipeline": "sc",
        "mode": "thorough",
        "language": "evm",
        "cli_backend": "claude",
        "_run_id": "32345678-1234-4567-8abc-1234567890ab",
    }


def _enumeration_input(*, second: bool = False) -> dict[str, object]:
    rows = [
        {
            "finding_id": "INV-1",
            "function": "entry",
            "symbol": "state",
            "required_corefs": ["paired"],
        }
    ]
    if second:
        rows.append(
            {
                "finding_id": "INV-2",
                "function": "exit",
                "symbol": "other-state",
                "required_corefs": ["inverse"],
            }
        )
    return {"source": "graph", "obligations": rows}


def _seed_enumgap(project: Path) -> tuple[Path, dict[str, object]]:
    scratch = project / ".scratchpad"
    scratch.mkdir(parents=True)
    (project / "src").mkdir()
    (project / "src" / "Unit.sol").write_text("one\ntwo\n", encoding="utf-8")
    (scratch / "_enumeration_obligations.json").write_text(
        json.dumps(_enumeration_input()), encoding="utf-8"
    )
    worklist, issues = D._prepare_enumgap_disposition_worklist(
        _phase(), _config(project), scratch
    )
    assert issues == [] and worklist["count"] == 1
    work_id = worklist["items"][0]["work_item_id"]
    assert D._bind_typed_model_phase_inputs(
        _phase(), scratch, _config(project)
    ) == []
    (scratch / "enumgap_exploration_findings.md").write_text(
        "# Enumgap\n\n"
        "## Finding [NEXP-1]: candidate\n\n"
        "**Severity**: Low\n\n**Location**: src/Unit.sol:L1\n\n"
        "## Coverage Record\n\n"
        "| Obligation | Relationship | Disposition | Evidence |\n"
        "|---|---|---|---|\n"
        f"| {work_id} | co-reference | FINDING | NEXP-1 |\n",
        encoding="utf-8",
    )
    assert D._record_typed_model_phase_artifacts(
        _phase(), scratch, _config(project)
    ) == []
    receipt, reconcile_issues = D._reconcile_enumgap_dispositions(
        _phase(), _config(project), scratch
    )
    assert reconcile_issues == [] and receipt["status"] == "CLEAN"
    return scratch, receipt


def test_uncommitted_enumgap_receipt_cannot_dispose_exploration_obligation(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    scratch, receipt = _seed_enumgap(project)
    state_path = scratch / "_artifact_state.json"
    if state_path.is_file():
        state = json.loads(state_path.read_text(encoding="utf-8"))
        units = state.get("work_units", {})
        units.pop(
            "sc/thorough/evm/claude/enumgap_exploration/model", None
        )
        units.pop(
            "sc/thorough/evm/claude/enumgap_disposition/reconcile", None
        )
        state_path.write_text(
            json.dumps(state, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    import finding_producer_registry as F

    with pytest.raises(
        F.TypedProducerActionError, match="producer|PhaseIO|committed"
    ):
        F.validated_enumgap_obligation_dispositions(
            scratch, production_root=project
        )
    assert receipt["status"] == "CLEAN"


def _seed_clear(project: Path) -> tuple[Path, str]:
    scratch = project / ".scratchpad"
    scratch.mkdir(parents=True)
    (project / "src").mkdir()
    (project / "src" / "Unit.sol").write_text("one\ntwo\n", encoding="utf-8")
    source = scratch / "exploration_skeptic_findings.md"
    source.write_text(
        "# Exploration\n\n## Coverage Record\n\n"
        "| Finding | Axis | Instance | Disposition | Evidence |\n"
        "|---|---|---|---|---|\n"
        "| BASE-1 | sibling | inverse | NO-GAP | vague wording |\n",
        encoding="utf-8",
    )
    clear_receipt = compile_initial_receipt(
        source, production_root=project, canonical_prior_ids={}
    )
    write_lifecycle_artifacts(scratch, clear_receipt)
    obligation_id = clear_receipt.obligations[0].obligation_id
    (scratch / "findings_inventory.md").write_text(
        "# Findings Inventory\n\n"
        "### Finding [INV-001]: Seed\n"
        "**Source IDs**: [BASE-0]\n"
        "**Severity**: Low\n"
        "**Location**: src/Unit.sol:L1\n"
        "**Description**: retained seed.\n",
        encoding="utf-8",
    )
    return scratch, obligation_id


def _canonical_record(
    *,
    artifact: str,
    local_id: str,
    title: str,
    offset: int = 0,
) -> dict[str, object]:
    """Build the same complete record shape emitted by the mechanical mapper."""
    immutable = {
        "artifact": artifact,
        "local_id": local_id.casefold(),
        "title": title.casefold(),
        "location": "src/unit.sol:l1",
        "root_cause": "",
        "source_ids": "",
    }
    digest = hashlib.sha256(
        json.dumps(immutable, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return {
        "canonical_id": "CID-" + digest[:16].upper(),
        "fingerprint": "sha256:" + digest,
        "artifact": artifact,
        "offset": offset,
        "local_id": local_id,
        "local_id_raw": local_id,
        "title": title,
        "severity": "Low",
        "location": "src/Unit.sol:L1",
        "root_cause": "",
        "source_ids_text": "",
        "referenced_ids": [],
        "raw_block_len": 100,
    }


def _write_identity_map(
    scratch: Path, records: list[dict[str, object]]
) -> Path:
    """Write a production-shaped canonical map, including its denominator."""
    path = scratch / "_canonical_finding_ids.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": "plamen.canonical_finding_ids.v1",
                "generated_at": "2026-07-18T00:00:00+00:00",
                "last_phase": "depth",
                "pipeline": "sc",
                "mode": "thorough",
                "record_count": len(records),
                "records": records,
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    return path


def _write_derived_alias_authority(scratch: Path) -> Path:
    path = scratch / "exploration_clear_prior_aliases.json"
    path.write_text(
        json.dumps(D._exploration_clear_prior_alias_payload(scratch), sort_keys=True),
        encoding="utf-8",
    )
    return path


def _rehash_alias_payload(payload: dict[str, object]) -> None:
    unsigned = {
        key: value
        for key, value in payload.items()
        if key != "alias_receipt_sha256"
    }
    payload["alias_receipt_sha256"] = D._stable_payload_digest(unsigned)


def _reconcile_clear_result(
    project: Path,
    scratch: Path,
    obligation_id: str,
    *,
    disposition: str = "CLEAR",
    evidence: str = "src/Unit.sol:L2",
    finding_body: str = "",
) -> tuple[dict[str, object], list[str]]:
    worklist, issues = D._prepare_enumgap_disposition_worklist(
        _phase(), _config(project), scratch
    )
    assert issues == [] and worklist["count"] == 1
    assert D._bind_typed_model_phase_inputs(
        _phase(), scratch, _config(project)
    ) == []
    (scratch / "enumgap_exploration_findings.md").write_text(
        "# Enumgap\n\n"
        + finding_body
        + "## Coverage Record\n\n"
        "| Obligation | Relationship | Disposition | Evidence |\n"
        "|---|---|---|---|\n"
        f"| {obligation_id} | sibling / inverse | {disposition} | {evidence} |\n",
        encoding="utf-8",
    )
    assert D._record_typed_model_phase_artifacts(
        _phase(), scratch, _config(project)
    ) == []
    receipt, reconcile_issues = D._reconcile_enumgap_dispositions(
        _phase(), _config(project), scratch
    )
    return receipt, reconcile_issues


def _reconcile_clear(
    project: Path,
    scratch: Path,
    obligation_id: str,
    *,
    disposition: str = "CLEAR",
    evidence: str = "src/Unit.sol:L2",
    finding_body: str = "",
) -> None:
    receipt, reconcile_issues = _reconcile_clear_result(
        project,
        scratch,
        obligation_id,
        disposition=disposition,
        evidence=evidence,
        finding_body=finding_body,
    )
    assert reconcile_issues == [] and receipt["status"] == "CLEAN"


def _assert_alias_clear_degraded(
    project: Path,
    scratch: Path,
    obligation_id: str,
    *,
    evidence: str,
    authority_must_be_invalid: bool,
) -> None:
    """No alias anomaly may mint a terminal canonical-prior disposition."""
    receipt, issues = _reconcile_clear_result(
        project, scratch, obligation_id, evidence=evidence
    )
    row = next(
        row
        for row in receipt["dispositions"]
        if row["work_item_id"] == obligation_id
    )
    assert receipt["status"] != "CLEAN"
    assert obligation_id in receipt["unresolved_work_item_ids"]
    assert row["resolution_kind"] == "INVALID_CLEAR"
    assert row["resolved_reference"] == ""
    assert not any(
        item.get("resolution_kind") == "CANONICAL_PRIOR"
        for item in receipt["dispositions"]
    )
    assert issues
    if authority_must_be_invalid:
        assert any(
            "alias" in issue.casefold() or "authority" in issue.casefold()
            for issue in issues
        ), "semantic-authority rejection must remain visible as typed debt"
        assert D._enumgap_disposition_resume_issues(
            scratch, project, mode="thorough"
        ), "forged authority must not become resume-clean"

    V._promote_depth_findings_to_inventory(scratch)
    delivery = json.loads(
        (scratch / "finding_delivery_receipt.json").read_text(encoding="utf-8")
    )
    delivery_row = next(
        item for item in delivery["actions"] if item["action_id"] == obligation_id
    )
    assert delivery_row["disposition"] == "INDEPENDENT_ENUMERATION_REQUIRED"
    assert delivery["accounted_action_count"] == 0


def test_resume_rejects_receipt_after_current_worklist_input_drift(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    scratch, _ = _seed_enumgap(project)
    assert D._enumgap_disposition_resume_issues(
        scratch, project, mode="thorough"
    ) == []
    (scratch / "_enumeration_obligations.json").write_text(
        json.dumps(_enumeration_input(second=True)), encoding="utf-8"
    )
    issues = D._enumgap_disposition_resume_issues(
        scratch, project, mode="thorough"
    )
    assert issues, "a receipt for the old denominator must not resume clean"


def test_exact_valid_enumgap_receipt_clears_only_registry_review_debt(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    scratch, obligation_id = _seed_clear(project)
    _reconcile_clear(project, scratch, obligation_id)
    V._promote_depth_findings_to_inventory(scratch)
    payload = json.loads(
        (scratch / "finding_delivery_receipt.json").read_text(encoding="utf-8")
    )
    row = next(
        row for row in payload["actions"] if row["action_id"] == obligation_id
    )
    assert row["disposition"] == "INDEPENDENT_ENUMERATION_DISPOSED"
    assert row["proof_scope"] == "NONE"
    assert row["content_bearing"] is False
    assert payload["accounted_action_count"] == 1
    assert V._validate_registered_finding_delivery_receipt(scratch) == []


def test_rehashed_semantic_forgery_cannot_clear_registry_debt(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    scratch, obligation_id = _seed_clear(project)
    _reconcile_clear(project, scratch, obligation_id)
    output_path = scratch / "enumgap_exploration_findings.md"
    output_path.write_text(
        output_path.read_text(encoding="utf-8").replace(
            "src/Unit.sol:L2", "reviewed and safe"
        ),
        encoding="utf-8",
    )
    receipt_path = scratch / "enumgap_disposition_receipt.json"
    forged = json.loads(receipt_path.read_text(encoding="utf-8"))
    forged["output_sha256"] = hashlib.sha256(output_path.read_bytes()).hexdigest()
    unsigned = {key: value for key, value in forged.items() if key != "receipt_hash"}
    forged["receipt_hash"] = hashlib.sha256(
        json.dumps(
            unsigned,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    receipt_path.write_text(json.dumps(forged), encoding="utf-8")
    (scratch / "enumgap_residual_obligations.json").write_text(
        json.dumps(residual_enumgap_queue(forged)), encoding="utf-8"
    )
    # Digest-only loading accepts the internally rehashed lie.  The registry
    # must use the independent recomputation boundary instead.
    assert load_enumgap_disposition_receipt(
        receipt_path, output_artifact=output_path
    )["dispositions"][0]["resolution_kind"] == "PRODUCTION_LOCUS"
    V._promote_depth_findings_to_inventory(scratch)
    payload = json.loads(
        (scratch / "finding_delivery_receipt.json").read_text(encoding="utf-8")
    )
    row = next(row for row in payload["actions"] if row["action_id"] == obligation_id)
    assert row["disposition"] == "INDEPENDENT_ENUMERATION_REQUIRED"
    assert payload["accounted_action_count"] == 0
    assert V._validate_registered_finding_delivery_receipt(scratch)


def test_residual_queue_drift_revokes_otherwise_valid_clear(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    scratch, obligation_id = _seed_clear(project)
    _reconcile_clear(project, scratch, obligation_id)
    residual_path = scratch / "enumgap_residual_obligations.json"
    residual = json.loads(residual_path.read_text(encoding="utf-8"))
    residual["tail"] = "ECLR-FORGED"
    residual_path.write_text(json.dumps(residual), encoding="utf-8")
    V._promote_depth_findings_to_inventory(scratch)
    payload = json.loads(
        (scratch / "finding_delivery_receipt.json").read_text(encoding="utf-8")
    )
    row = next(row for row in payload["actions"] if row["action_id"] == obligation_id)
    assert row["disposition"] == "INDEPENDENT_ENUMERATION_REQUIRED"
    assert payload["accounted_action_count"] == 0


def test_emitted_action_must_be_delivery_shaped_before_it_clears_obligation(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    scratch, obligation_id = _seed_clear(project)
    _reconcile_clear(
        project,
        scratch,
        obligation_id,
        disposition="FINDING",
        evidence="NEXP-1",
        finding_body=(
            "## Finding [NEXP-1]: contentless candidate\n\n"
            "**Severity**: Low\n\n**Location**: src/Unit.sol:L1\n\n"
        ),
    )
    V._promote_depth_findings_to_inventory(scratch)
    payload = json.loads(
        (scratch / "finding_delivery_receipt.json").read_text(encoding="utf-8")
    )
    row = next(row for row in payload["actions"] if row["action_id"] == obligation_id)
    assert row["disposition"] == "INDEPENDENT_ENUMERATION_REQUIRED"
    assert payload["accounted_action_count"] == 0


def test_emitted_action_guard_matches_the_actual_inventory_promoter_shape(
    tmp_path: Path,
) -> None:
    """A heading the promoter cannot consume must not dispose ECLR work."""
    import enumeration_gate as EG

    project = tmp_path / "project"
    scratch, obligation_id = _seed_clear(project)
    _reconcile_clear(
        project,
        scratch,
        obligation_id,
        disposition="FINDING",
        evidence="NEXP-1",
        finding_body=(
            # The registry's looser heading parser accepts this, while the
            # live promoter requires `Finding [ID]: non-empty title`.
            "## Finding [NEXP-1]\n\n"
            "**Severity**: Low\n\n"
            "**Location**: src/Unit.sol:L1\n\n"
            "**Description**: A concrete candidate that must reach verification.\n\n"
        ),
    )
    assert EG.promote_enumgap_exploration_to_inventory(scratch) == {
        "parsed": 0,
        "emitted": 0,
    }
    V._promote_depth_findings_to_inventory(scratch)
    payload = json.loads(
        (scratch / "finding_delivery_receipt.json").read_text(encoding="utf-8")
    )
    row = next(row for row in payload["actions"] if row["action_id"] == obligation_id)
    assert row["disposition"] == "INDEPENDENT_ENUMERATION_REQUIRED"
    assert payload["accounted_action_count"] == 0


def test_delivery_shaped_emitted_action_disposes_work_without_granting_proof(
    tmp_path: Path,
) -> None:
    import enumeration_gate as EG

    project = tmp_path / "project"
    scratch, obligation_id = _seed_clear(project)
    _reconcile_clear(
        project,
        scratch,
        obligation_id,
        disposition="FINDING",
        evidence="NEXP-1",
        finding_body=(
            "## Finding [NEXP-1]: traced candidate\n\n"
            "**Severity**: Low\n\n"
            "**Location**: src/Unit.sol:L1\n\n"
            "**Description**: A concrete traced candidate remains for verification.\n\n"
        ),
    )
    assert EG.promote_enumgap_exploration_to_inventory(scratch) == {
        "parsed": 1,
        "emitted": 1,
    }
    V._promote_depth_findings_to_inventory(scratch)
    payload = json.loads(
        (scratch / "finding_delivery_receipt.json").read_text(encoding="utf-8")
    )
    row = next(row for row in payload["actions"] if row["action_id"] == obligation_id)
    assert row["disposition"] == "INDEPENDENT_ENUMERATION_DISPOSED"
    assert row["resolution_kind"] == "EMITTED_ACTION"
    assert row["proof_scope"] == "NONE"
    assert row["content_bearing"] is False


def test_bound_canonical_prior_disposes_but_identity_map_drift_revokes_authority(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    scratch, obligation_id = _seed_clear(project)
    record = _canonical_record(
        artifact="depth_findings.md", local_id="H-1", title="Bound prior"
    )
    identity_map = _write_identity_map(scratch, [record])
    _write_derived_alias_authority(scratch)
    _reconcile_clear(
        project,
        scratch,
        obligation_id,
        evidence="H-1",
    )
    V._promote_depth_findings_to_inventory(scratch)
    payload = json.loads(
        (scratch / "finding_delivery_receipt.json").read_text(encoding="utf-8")
    )
    row = next(row for row in payload["actions"] if row["action_id"] == obligation_id)
    assert row["disposition"] == "INDEPENDENT_ENUMERATION_DISPOSED"
    assert row["resolution_kind"] == "CANONICAL_PRIOR"
    assert row["resolved_reference"] == record["canonical_id"]
    assert D._enumgap_disposition_resume_issues(
        scratch, project, mode="thorough"
    ) == []

    identity_map = _write_identity_map(scratch, [])
    assert D._enumgap_disposition_resume_issues(
        scratch, project, mode="thorough"
    )
    V._promote_depth_findings_to_inventory(scratch)
    payload = json.loads(
        (scratch / "finding_delivery_receipt.json").read_text(encoding="utf-8")
    )
    row = next(row for row in payload["actions"] if row["action_id"] == obligation_id)
    assert row["disposition"] == "INDEPENDENT_ENUMERATION_REQUIRED"
    assert payload["accounted_action_count"] == 0


def test_rehashed_alias_semantic_forgery_cannot_mint_canonical_prior_authority(
    tmp_path: Path,
) -> None:
    """An extra rehashed alias degrades early and remains exact registry debt."""
    project = tmp_path / "project"
    scratch, obligation_id = _seed_clear(project)
    record = _canonical_record(
        artifact="depth_findings.md", local_id="H-1", title="Real prior"
    )
    _write_identity_map(scratch, [record])
    forged = D._exploration_clear_prior_alias_payload(scratch)
    forged["aliases"]["FORGED-1"] = "CID-NOT-IN-BOUND-MAP"
    _rehash_alias_payload(forged)
    (scratch / "exploration_clear_prior_aliases.json").write_text(
        json.dumps(forged), encoding="utf-8"
    )

    _assert_alias_clear_degraded(
        project,
        scratch,
        obligation_id,
        evidence="FORGED-1",
        authority_must_be_invalid=True,
    )


def test_rehashed_alias_redirect_cannot_change_canonical_prior_target(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    scratch, obligation_id = _seed_clear(project)
    first = _canonical_record(
        artifact="depth_first.md", local_id="H-1", title="First prior"
    )
    second = _canonical_record(
        artifact="depth_second.md", local_id="H-2", title="Second prior"
    )
    _write_identity_map(scratch, [first, second])
    forged = D._exploration_clear_prior_alias_payload(scratch)
    forged["aliases"]["H-1"] = second["canonical_id"]
    _rehash_alias_payload(forged)
    (scratch / "exploration_clear_prior_aliases.json").write_text(
        json.dumps(forged), encoding="utf-8"
    )

    _assert_alias_clear_degraded(
        project,
        scratch,
        obligation_id,
        evidence="H-1",
        authority_must_be_invalid=True,
    )


def test_rehashed_alias_denominator_shrink_cannot_hide_a_bound_prior(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    scratch, obligation_id = _seed_clear(project)
    record = _canonical_record(
        artifact="depth_findings.md", local_id="H-1", title="Retained prior"
    )
    _write_identity_map(scratch, [record])
    forged = D._exploration_clear_prior_alias_payload(scratch)
    del forged["aliases"]["H-1"]
    _rehash_alias_payload(forged)
    (scratch / "exploration_clear_prior_aliases.json").write_text(
        json.dumps(forged), encoding="utf-8"
    )

    _assert_alias_clear_degraded(
        project,
        scratch,
        obligation_id,
        evidence="H-1",
        authority_must_be_invalid=True,
    )


def test_rehashed_ambiguity_forgery_cannot_choose_one_colliding_prior(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    scratch, obligation_id = _seed_clear(project)
    first = _canonical_record(
        artifact="depth_first.md", local_id="H-1", title="First collision"
    )
    second = _canonical_record(
        artifact="depth_second.md", local_id="H-1", title="Second collision"
    )
    _write_identity_map(scratch, [first, second])
    forged = D._exploration_clear_prior_alias_payload(scratch)
    forged["aliases"]["H-1"] = first["canonical_id"]
    forged["ambiguous_short_aliases"] = {}
    _rehash_alias_payload(forged)
    (scratch / "exploration_clear_prior_aliases.json").write_text(
        json.dumps(forged), encoding="utf-8"
    )

    _assert_alias_clear_degraded(
        project,
        scratch,
        obligation_id,
        evidence="H-1",
        authority_must_be_invalid=True,
    )


def test_case_only_alias_collision_is_ambiguous_under_resolver_semantics(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    scratch, obligation_id = _seed_clear(project)
    first = _canonical_record(
        artifact="depth_first.md", local_id="H-1", title="Uppercase alias"
    )
    second = _canonical_record(
        artifact="depth_second.md", local_id="h-1", title="Lowercase alias"
    )
    _write_identity_map(scratch, [first, second])
    _write_derived_alias_authority(scratch)

    _assert_alias_clear_degraded(
        project,
        scratch,
        obligation_id,
        evidence="H-1",
        authority_must_be_invalid=False,
    )


def test_duplicate_artifact_qualified_alias_is_not_last_writer_wins(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    scratch, obligation_id = _seed_clear(project)
    first = _canonical_record(
        artifact="depth_findings.md",
        local_id="H-1",
        title="Earlier duplicate",
        offset=10,
    )
    second = _canonical_record(
        artifact="depth_findings.md",
        local_id="H-1",
        title="Later duplicate",
        offset=100,
    )
    _write_identity_map(scratch, [first, second])
    _write_derived_alias_authority(scratch)

    _assert_alias_clear_degraded(
        project,
        scratch,
        obligation_id,
        evidence="depth_findings.md:H-1",
        authority_must_be_invalid=False,
    )


def test_rehashed_alias_receipt_cannot_switch_to_alternate_local_source(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    scratch, obligation_id = _seed_clear(project)
    record = _canonical_record(
        artifact="depth_findings.md", local_id="H-1", title="Bound source"
    )
    identity_map = _write_identity_map(scratch, [record])
    alternate = scratch / "alternate_canonical_finding_ids.json"
    alternate.write_bytes(identity_map.read_bytes())
    forged = D._exploration_clear_prior_alias_payload(scratch)
    forged["source_identity_map"] = alternate.name
    forged["source_identity_map_sha256"] = hashlib.sha256(
        alternate.read_bytes()
    ).hexdigest()
    _rehash_alias_payload(forged)
    (scratch / "exploration_clear_prior_aliases.json").write_text(
        json.dumps(forged), encoding="utf-8"
    )

    _assert_alias_clear_degraded(
        project,
        scratch,
        obligation_id,
        evidence="H-1",
        authority_must_be_invalid=True,
    )
