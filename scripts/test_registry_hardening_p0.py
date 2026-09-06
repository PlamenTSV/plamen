"""Adversarial fixtures for the producer-registry hardening tranche.

The cases are deliberately synthetic and Part-0 generic.  They exercise real
consumer adapters (promotion, finding-record emission, typed queue projection,
and the report appendix) rather than accepting registry unit telemetry alone.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from pathlib import Path

import pytest

import application_skeptic as K
import finding_producer_registry as R
import methodology_application_states as S


def _producer(key: str, pattern: str, local_id: str) -> R.FindingProducer:
    return R.FindingProducer(
        key=key,
        artifact_patterns=(pattern,),
        local_id_patterns=(local_id,),
        owner_phase="depth",
        required_consumers=frozenset(R.REQUIRED_DELIVERY_CONSUMERS),
    )


def _seed_inventory() -> str:
    return (
        "# Findings Inventory\n\n"
        "### Finding [INV-001]: Seed candidate\n"
        "**Source IDs**: [BASE-1]\n"
        "**Severity**: Medium\n"
        "**Location**: src/Core.sol:L10\n"
        "**Description**: A retained seed candidate.\n"
    )


def _write(path: Path, value: str) -> None:
    path.write_text(value, encoding="utf-8")


def _write_exploration_clear_additive(
    tmp_path: Path,
    *,
    action_id: str = "SKEP-8",
    include_bound_finding: bool = False,
) -> Path:
    import exploration_clear_lifecycle as E

    source = tmp_path / "exploration_skeptic_findings.md"
    text = (
        "# Exploration Completeness Findings\n\n"
        "## Coverage Record\n\n"
        "| Finding | Axis | Instance | Disposition | Evidence |\n"
        "|---|---|---|---|---|\n"
        f"| BASE-1 | Direction | inverse transition | GAP-FILLED | {action_id} |\n"
        "\n## Notes\n\nTyped lifecycle source.\n"
    )
    if include_bound_finding:
        text += (
            f"\n### Finding [{action_id}]: Bound additive candidate\n"
            "**Action**: NEW\n"
            "**Severity**: Medium\n"
            "**Location**: src/Module.sol:L18\n"
            "**Description**: A sibling transition can preserve inconsistent state.\n"
        )
    _write(source, text)
    receipt = E.compile_initial_receipt(
        source,
        production_root=tmp_path / "repo",
        canonical_prior_ids={},
    )
    E.write_lifecycle_artifacts(tmp_path, receipt)
    return tmp_path / E.RECEIPT_NAME


def _write_exploration_clear_unresolved(tmp_path: Path) -> Path:
    import exploration_clear_lifecycle as E

    source = tmp_path / "exploration_skeptic_findings.md"
    _write(
        source,
        "# Exploration Completeness Findings\n\n"
        "## Coverage Record\n\n"
        "| Finding | Axis | Instance | Disposition | Evidence |\n"
        "|---|---|---|---|---|\n"
        "| BASE-2 | Neighbour | inverse sibling | NO-GAP | explored |\n",
    )
    receipt = E.compile_initial_receipt(
        source,
        production_root=tmp_path / "repo",
        canonical_prior_ids={},
    )
    assert receipt.obligations
    E.write_lifecycle_artifacts(tmp_path, receipt)
    return tmp_path / E.OBLIGATION_QUEUE_NAME


def test_artifact_resolution_prefers_unique_most_specific_match_and_rejects_ties():
    broad = _producer("broad", "depth_*_findings.md", r"BROAD-\d+")
    exact = _producer("exact", "depth_special_findings.md", r"EXACT-\d+")
    assert R.producer_for_artifact(
        "depth_special_findings.md", producers=(broad, exact)
    ) == exact

    tie = _producer("tie", "depth_special_findings.md", r"TIE-\d+")
    with pytest.raises(R.ProducerResolutionError, match="ambiguous"):
        R.producer_for_artifact(
            "depth_special_findings.md", producers=(exact, tie)
        )


def test_exploration_clear_additive_has_exact_typed_identity_and_lineage(tmp_path: Path):
    receipt_path = _write_exploration_clear_additive(tmp_path)
    rows = R.read_registered_typed_actions(receipt_path)
    assert len(rows) == 1
    row = rows[0]
    assert row.schema_version == R.REGISTERED_TYPED_ACTION_SCHEMA
    assert row.producer_key == "exploration_clear_additive"
    assert row.action_id == "SKEP-8"
    assert row.action_identity.startswith("ECTA-")
    assert row.obligation_id.startswith("ECLR-")
    assert row.proof_scope == "UNVERIFIED_GENERATOR_OUTPUT"
    assert row.requires_independent_consumer is True
    projected = row.delivery_row()
    assert projected["source_identity"] == (
        f"{R.EXPLORATION_CLEAR_RECEIPT}:{row.action_identity}"
    )
    assert projected["effective_proof_scope"] == "ANALYTICAL"
    assert projected["effective_harm_scope"] == "UNPROVEN"
    assert "evidence" not in projected and projected["evidence_sha256"]
    assert not (tmp_path / "exploration_clear_additive_findings.md").exists()


def test_exploration_clear_additive_cannot_self_certify(tmp_path: Path):
    import exploration_clear_lifecycle as E

    receipt_path = _write_exploration_clear_additive(tmp_path)
    receipt = E.load_lifecycle_receipt(receipt_path)
    action = replace(
        receipt.additive_actions[0],
        proof_scope="HARM",
        requires_independent_consumer=False,
    )
    tampered = E._with_receipt_hash(
        replace(receipt, additive_actions=(action,), receipt_hash="")
    )
    E.write_lifecycle_artifacts(tmp_path, tampered)
    with pytest.raises(R.TypedProducerActionError, match="independent verification"):
        R.read_registered_typed_actions(receipt_path)


def test_exploration_clear_typed_action_enters_exact_delivery_once(tmp_path: Path):
    import plamen_validators as V

    _write(tmp_path / "findings_inventory.md", _seed_inventory())
    _write_exploration_clear_additive(tmp_path, include_bound_finding=True)
    assert V._promote_depth_findings_to_inventory(tmp_path) == ["SKEP-8"]
    payload = json.loads(
        (tmp_path / "finding_delivery_receipt.json").read_text(encoding="utf-8")
    )
    rows = [row for row in payload["actions"] if row["action_id"] == "SKEP-8"]
    assert len(rows) == 1
    row = rows[0]
    assert row["producer_key"] == "exploration_clear_additive"
    assert row["action_identity"].startswith("ECTA-")
    assert row["bound_markdown_projection"] == "exploration_skeptic_findings.md"
    assert row["proof_scope"] == "UNVERIFIED_GENERATOR_OUTPUT"
    assert row["requires_independent_consumer"] is True
    assert row["disposition"] == "PROMOTED_FINDING"
    assert payload["source_action_count"] == 1
    assert payload["accounted_action_count"] == 1
    assert V._validate_registered_finding_delivery_receipt(tmp_path) == []


def test_exploration_clear_typed_action_reaches_identity_and_late_harvest_consumers(
    tmp_path: Path,
):
    import plamen_mechanical as M
    import plamen_validators as V

    _write(tmp_path / "findings_inventory.md", _seed_inventory())
    _write(tmp_path / "report_index_coverage_seed.md", "# Coverage Seed\n")
    _write_exploration_clear_additive(tmp_path)

    assert M._write_canonical_finding_identity_map(tmp_path) >= 1
    identity_rows = json.loads(
        (tmp_path / "_canonical_finding_ids.json").read_text(encoding="utf-8")
    )["records"]
    typed = next(row for row in identity_rows if row.get("local_id") == "SKEP-8")
    assert typed["action_identity"].startswith("ECTA-")
    assert typed["requires_independent_consumer"] is True

    orphans = M.compute_promotion_orphans(tmp_path)
    typed_orphans = [row for row in orphans if row["shape"] == "typed_generator_action"]
    assert len(typed_orphans) == 1
    assert typed_orphans[0]["disposition"] == "BODY"
    routed = M.route_promotion_orphans(tmp_path, orphans)
    assert routed["emitted_to_inventory"] == 1
    inventory = (tmp_path / "findings_inventory.md").read_text(encoding="utf-8")
    assert "**Source IDs**: [SKEP-8]" in inventory
    assert "**Primary Artifact**: exploration_clear_receipt.json" in inventory
    V._promote_depth_findings_to_inventory(tmp_path)
    payload = json.loads(
        (tmp_path / "finding_delivery_receipt.json").read_text(encoding="utf-8")
    )
    row = next(row for row in payload["actions"] if row["action_id"] == "SKEP-8")
    assert row["disposition"] == "PROMOTED_FINDING"
    assert V._validate_registered_finding_delivery_receipt(tmp_path) == []


def test_unresolved_exploration_obligation_is_exact_nonfinding_review_debt(
    tmp_path: Path,
):
    import plamen_mechanical as M
    import plamen_validators as V

    _write(tmp_path / "findings_inventory.md", _seed_inventory())
    _write(tmp_path / "report_index_coverage_seed.md", "# Coverage Seed\n")
    queue_path = _write_exploration_clear_unresolved(tmp_path)
    obligations = R.read_registered_enumeration_obligations(queue_path)
    assert len(obligations) == 1
    obligation = obligations[0]
    assert obligation.action_id.startswith("ECLR-")
    assert obligation.action_identity.startswith("ECOA-")
    assert obligation.obligation_queue_count == 1
    assert obligation.obligation_queue_tail == obligation.action_id
    assert obligation.proof_scope == "NONE"
    assert obligation.requires_independent_consumer is True
    queue_bytes = queue_path.read_bytes()
    tampered_queue = json.loads(queue_bytes)
    tampered_queue["count"] = 2
    queue_path.write_text(json.dumps(tampered_queue), encoding="utf-8")
    with pytest.raises(R.TypedProducerActionError, match="exactly match"):
        R.read_registered_enumeration_obligations(queue_path)
    queue_path.write_bytes(queue_bytes)

    V._promote_depth_findings_to_inventory(tmp_path)
    payload = json.loads(
        (tmp_path / "finding_delivery_receipt.json").read_text(encoding="utf-8")
    )
    row = next(
        row for row in payload["actions"]
        if row["producer_key"] == "exploration_clear_obligation"
    )
    assert row["action_id"] == obligation.action_id
    assert row["action_identity"] == obligation.action_identity
    assert row["obligation_queue_hash"] == obligation.obligation_queue_hash
    assert row["obligation_queue_count"] == 1
    assert row["obligation_queue_tail"] == obligation.action_id
    assert row["proof_scope"] == "NONE"
    assert row["content_bearing"] is False
    assert row["disposition"] == "INDEPENDENT_ENUMERATION_REQUIRED"
    assert payload["accounted_action_count"] == 0
    assert "INDEPENDENT_ENUMERATION_REQUIRED" in (
        tmp_path / "report_semantic_finding_delivery.md"
    ).read_text(encoding="utf-8")
    assert V._validate_registered_finding_delivery_receipt(tmp_path)

    orphans = M.compute_promotion_orphans(tmp_path)
    debt = [row for row in orphans if row["shape"] == "typed_enumeration_obligation"]
    assert len(debt) == 1 and debt[0]["disposition"] == "BODY"
    inventory_before = (tmp_path / "findings_inventory.md").read_bytes()
    routed = M.route_promotion_orphans(tmp_path, orphans)
    assert routed["body_candidates"] == 1
    assert routed["emitted_to_inventory"] == 1
    inventory_after = (tmp_path / "findings_inventory.md").read_bytes()
    assert inventory_after != inventory_before
    assert b"PROMOGAP" in inventory_after


def test_registered_artifact_cannot_mint_another_producers_local_id(tmp_path: Path):
    import plamen_validators as V

    _write(tmp_path / "findings_inventory.md", _seed_inventory())
    _write(
        tmp_path / "exploration_skeptic_findings.md",
        "### Finding [FUZZ-1]: Wrong producer identity\n"
        "**Action**: NEW\n"
        "**Severity**: High\n"
        "**Location**: src/Module.sol:L12\n"
        "**Description**: A content-bearing row uses another producer's ID.\n",
    )
    assert V._promote_depth_findings_to_inventory(tmp_path) == []
    receipt = json.loads(
        (tmp_path / "finding_delivery_receipt.json").read_text(encoding="utf-8")
    )
    row = receipt["actions"][0]
    assert row["action_id"] == "FUZZ-1"
    assert row["local_id_valid"] is False
    assert row["disposition"] == "RESIDUAL_DEBT"
    assert "FUZZ-1" not in (
        tmp_path / "findings_inventory.md"
    ).read_text(encoding="utf-8")


def test_same_local_id_from_two_registered_artifacts_keeps_two_action_identities(
    tmp_path: Path,
):
    import plamen_parsers as P
    import plamen_validators as V

    _write(tmp_path / "findings_inventory.md", _seed_inventory())
    for name, location, description in (
        (
            "trident_fuzz_findings.md",
            "fuzz/program.rs:L10",
            "One executor reaches a state-transition mismatch.",
        ),
        (
            "cargo_fuzz_findings.md",
            "fuzz/node.rs:L20",
            "Another executor reaches a distinct lifecycle mismatch.",
        ),
    ):
        _write(
            tmp_path / name,
            "### Finding [FUZZ-1]: Executor-local candidate\n"
            "**Severity**: Medium\n"
            f"**Location**: {location}\n"
            f"**Description**: {description}\n",
        )
    promoted = V._promote_depth_findings_to_inventory(tmp_path)
    assert promoted == ["FUZZ-1", "FUZZ-1"]
    receipt = json.loads(
        (tmp_path / "finding_delivery_receipt.json").read_text(encoding="utf-8")
    )
    rows = [row for row in receipt["actions"] if row["action_id"] == "FUZZ-1"]
    assert len(rows) == 2
    assert {row["source_file"] for row in rows} == {
        "trident_fuzz_findings.md",
        "cargo_fuzz_findings.md",
    }
    assert {row["disposition"] for row in rows} == {"PROMOTED_FINDING"}
    assert receipt["accounted_action_count"] == receipt["source_action_count"]
    P._write_mechanical_verification_queue_from_inventory(tmp_path)
    assert len(P.parse_verification_queue_rows(tmp_path)) == 3
    inventory_before = (tmp_path / "findings_inventory.md").read_bytes()
    assert V._promote_depth_findings_to_inventory(tmp_path) == []
    assert (tmp_path / "findings_inventory.md").read_bytes() == inventory_before
    assert V._validate_registered_finding_delivery_receipt(tmp_path) == []


def test_producer_negative_is_origin_assessment_not_terminal_disposition(tmp_path: Path):
    import plamen_validators as V

    _write(tmp_path / "findings_inventory.md", _seed_inventory())
    _write(
        tmp_path / "exploration_skeptic_findings.md",
        "### Finding [SKEP-71]: Producer-authored negative\n"
        "**Action**: NEW\n"
        "**Verdict**: REFUTED\n"
        "**Severity**: Medium\n"
        "**Location**: src/Module.sol:L20\n"
        "**Description**: The producer assessed this candidate as safe.\n",
    )
    assert V._promote_depth_findings_to_inventory(tmp_path) == []
    receipt = json.loads(
        (tmp_path / "finding_delivery_receipt.json").read_text(encoding="utf-8")
    )
    row = receipt["actions"][0]
    assert row["origin_assessment"] == "REFUTED"
    assert row["disposition"] == "ORIGIN_NEGATIVE_REVIEW_REQUIRED"
    assert receipt["status"] == "DEGRADED"
    assert V._validate_registered_finding_delivery_receipt(tmp_path)


def _skeptic_plan(tmp_path: Path) -> dict:
    state = S.classify_application_row(
        {
            "phase": "breadth",
            "worker_id": "writer-a",
            "producer_invocation_id": "writer-call-a",
            "output": "analysis_generic.md",
            "output_sha256": "b" * 64,
            "prompt_sha256": "c" * 64,
            "dispatch_contract_sha256": "d" * 64,
            "skill": "GENERIC_METHOD",
            "methodology_path": (tmp_path / "SKILL.md").as_posix(),
            "methodology_sha256": "a" * 64,
            "step": "1",
            "executed": "yes",
            "evidence": "src/Module.sol:L9",
            "result": "SAFE: writer-authored negative",
            "delivery_integrity": "CURRENT",
            "trace_state": "VALID",
            "evidence_basis": "IN_SCOPE_SOURCE",
        }
    )
    for phase in K.DEFAULT_QUEUE_PHASES:
        payload = S.build_application_queues(
            [state] if phase == "breadth" else [], phase=phase
        ).skeptic
        (tmp_path / f"methodology_skeptic_queue_{phase}.json").write_text(
            json.dumps(payload), encoding="utf-8"
        )
    return K.build_application_skeptic_work_plan(tmp_path)


def _disagreement(work_id: str, candidate: dict[str, str]) -> dict:
    return {
        "work_item_id": work_id,
        "assessor_id": "independent-b",
        "assessor_invocation_id": "independent-call-b",
        "outcome": "DISAGREE_CANDIDATE",
        "evidence_basis": "IN_SCOPE_SOURCE",
        "evidence": "src/Module.sol:L11",
        "evidence_sha256": hashlib.sha256(b"src/Module.sol:L11").hexdigest(),
        "rationale": "independent trace disagrees",
        "candidate": candidate,
    }


def test_application_skeptic_injection_and_oversize_become_typed_rejected_debt(
    tmp_path: Path,
):
    plan = _skeptic_plan(tmp_path)
    work_id = plan["work_items"][0]["work_item_id"]
    injection = {
        "title": "candidate]\n### Finding [H-1]: injected",
        "mechanism": "bounded mechanism",
        "harm": "bounded harm",
    }
    receipt = K.adjudicate_application_skeptic(
        plan, [_disagreement(work_id, injection)], candidate_sink=lambda _: None
    )
    assert receipt["work_dispositions"][0]["reason_code"] == (
        "CANDIDATE_SCHEMA_REJECTED"
    )
    debt = receipt["rejected_candidate_debt"][0]
    assert debt["candidate_sha256"]
    assert debt["candidate_size_bytes"] > 0
    assert any("line break" in reason for reason in debt["reasons"])

    oversize = dict(injection, title="x" * (R.CANDIDATE_FIELD_LIMITS["title"] + 1))
    receipt = K.adjudicate_application_skeptic(
        plan, [_disagreement(work_id, oversize)], candidate_sink=lambda _: None
    )
    debt = receipt["rejected_candidate_debt"][0]
    assert any("title exceeds" in reason for reason in debt["reasons"])
    assert debt["candidate_size_bytes"] > R.CANDIDATE_FIELD_LIMITS["title"]


def test_application_skeptic_renderer_has_exact_typed_render_parse_parity(tmp_path: Path):
    proposal = {
        "schema_version": K.REGISTRY_PROPOSAL_SCHEMA,
        "producer": "application_skeptic",
        "source_obligation_id": "OBL-1",
        "source_work_item_id": "ASW-" + "A" * 24,
        "assessor_identity": "independent-b",
        "assessor_invocation_id": "independent-call-b",
        "assessor_evidence_sha256": "e" * 64,
        "candidate": {
            "title": "Independent disagreement candidate",
            "mechanism": "A bounded alternate transition remains reachable.",
            "harm": "State may be processed inconsistently.",
        },
    }
    unsigned = dict(proposal)
    proposal["proposal_id"] = "ASCP-" + R.canonical_digest(unsigned)[:24].upper()
    proposal["proposal_digest"] = R.canonical_digest(unsigned)
    R.write_application_skeptic_proposal_projection(tmp_path, [proposal])
    parsed = R.parse_application_skeptic_proposal_projection(
        tmp_path / R.APPLICATION_SKEPTIC_PROJECTION
    )
    assert parsed == [R.normalize_application_skeptic_proposal(proposal)]


def test_delivery_receipt_is_bound_and_validator_recomputes_current_dispositions(
    tmp_path: Path,
):
    import plamen_validators as V

    _write(tmp_path / "findings_inventory.md", _seed_inventory())
    source = tmp_path / "exploration_skeptic_findings.md"
    _write(
        source,
        "### Finding [SKEP-72]: Bound source action\n"
        "**Action**: NEW\n**Severity**: Medium\n"
        "**Location**: src/Module.sol:L30\n"
        "**Description**: A retained source action with material content.\n",
    )
    assert V._promote_depth_findings_to_inventory(tmp_path) == ["SKEP-72"]
    receipt = json.loads(
        (tmp_path / "finding_delivery_receipt.json").read_text(encoding="utf-8")
    )
    for field in (
        "source_artifact_digest",
        "source_action_digest",
        "disposition_digest",
        "inventory_sha256",
        "receipt_digest",
    ):
        assert receipt[field]
    assert V._validate_registered_finding_delivery_receipt(tmp_path) == []

    receipt["actions"][0]["disposition"] = "HUMAN_REVIEW"
    (tmp_path / "finding_delivery_receipt.json").write_text(
        json.dumps(receipt), encoding="utf-8"
    )
    issues = V._validate_registered_finding_delivery_receipt(tmp_path)
    assert any("digest" in issue or "recomputed" in issue for issue in issues)


def test_delivery_receipt_cannot_outlive_changed_source_bytes(tmp_path: Path):
    import plamen_validators as V

    _write(tmp_path / "findings_inventory.md", _seed_inventory())
    source = tmp_path / "exploration_skeptic_findings.md"
    _write(
        source,
        "### Finding [SKEP-73]: First action\n"
        "**Action**: NEW\n**Severity**: Medium\n"
        "**Location**: src/Module.sol:L31\n"
        "**Description**: First content-bearing source action.\n",
    )
    assert V._promote_depth_findings_to_inventory(tmp_path) == ["SKEP-73"]
    assert V._validate_registered_finding_delivery_receipt(tmp_path) == []
    source.write_text(
        source.read_text(encoding="utf-8")
        + "\n### Finding [SKEP-74]: Later action\n"
        "**Action**: NEW\n**Severity**: Low\n"
        "**Location**: src/Module.sol:L40\n"
        "**Description**: A later content-bearing source action.\n",
        encoding="utf-8",
    )
    issues = V._validate_registered_finding_delivery_receipt(tmp_path)
    assert any("source_artifact_digest" in issue for issue in issues)
    assert any("source_action" in issue or "actions differs" in issue for issue in issues)


def test_dxre_typed_authority_projects_to_appendix_even_if_markdown_cache_is_missing(
    tmp_path: Path,
):
    import plamen_mechanical as M
    import plamen_validators as V

    _write(tmp_path / "findings_inventory.md", _seed_inventory())
    _write(
        tmp_path / "depth_selfexcl_reemit_findings.md",
        "### Review Disposition [DXRE-9]: Exact review authority\n"
        "**Source Identity**: depth_generic_findings.md:DX-9\n"
        "**Disposition**: CONTENT_LESS_HUMAN_REVIEW\n"
        "**Reason**: source row has insufficient content for a finding\n",
    )
    assert V._promote_depth_findings_to_inventory(tmp_path) == []
    projection = tmp_path / "report_semantic_finding_delivery.md"
    expected = projection.read_text(encoding="utf-8")
    projection.unlink()
    appendix = M._build_human_review_appendix(tmp_path)
    assert "Exact review authority" in appendix
    assert "depth_generic_findings.md:DX-9" in appendix
    assert R.render_delivery_human_review_projection(
        json.loads(
            (tmp_path / "finding_delivery_receipt.json").read_text(encoding="utf-8")
        )
    ) == expected


def test_effective_scopes_are_closed_capped_and_preserved_to_records_and_queue(
    tmp_path: Path,
):
    import plamen_mechanical as M
    import plamen_parsers as P
    import plamen_validators as V

    _write(tmp_path / "findings_inventory.md", _seed_inventory())
    _write(
        tmp_path / "invariant_fuzz_results.md",
        "### Finding [FUZZ-4]: Executed mechanism candidate\n"
        "**Severity**: High\n"
        "**Location**: test/Invariant.t.sol:L44\n"
        "**Evidence Scope**: IN_SCOPE_EXECUTION\n"
        "**Proof Scope**: HARM\n"
        "**Harm Scope**: MATERIAL_HARM\n"
        "**Description**: Execution reaches a state-transition mismatch.\n",
    )
    assert V._promote_depth_findings_to_inventory(tmp_path) == ["FUZZ-4"]
    M._write_finding_records_from_inventory(tmp_path)
    records = json.loads(
        (tmp_path / "finding_records.json").read_text(encoding="utf-8")
    )["records"]
    record = next(row for row in records if "FUZZ-4" in row["source_ids"])
    assert record["effective_evidence_scope"] == "IN_SCOPE_EXECUTION"
    assert record["effective_proof_scope"] == "MECHANISM"
    assert record["effective_harm_scope"] == "UNPROVEN"

    P._write_mechanical_verification_queue_from_inventory(tmp_path)
    typed = P._read_typed_queue_work_items(tmp_path / "verification_queue.md")
    item = next(row for row in typed if row.work_item_id == record["inventory_id"])
    assert item.effective_evidence_scope == "IN_SCOPE_EXECUTION"
    assert item.effective_proof_scope == "MECHANISM"
    assert item.effective_harm_scope == "UNPROVEN"
    assert "proof scope HARM exceeds" in " ".join(
        json.loads(
            (tmp_path / "finding_delivery_receipt.json").read_text(encoding="utf-8")
        )["residual_debt"]
    )


def test_typed_queue_migrates_v2_scope_less_records_to_closed_defaults():
    import queue_work_items as Q

    current = Q.QueueWorkItem.from_legacy_row(
        {
            "finding id": "INV-9",
            "severity": "Medium",
            "title": "legacy typed row",
            "bug class": "generic",
            "preferred tag": "CODE-TRACE",
            "poc class": "structural",
        }
    ).to_dict()
    legacy = dict(current)
    legacy["schema_version"] = "plamen.queue_work_item.v2"
    for field in (
        "effective_evidence_scope",
        "effective_proof_scope",
        "effective_harm_scope",
    ):
        legacy.pop(field)
    rows = [legacy]
    digest = hashlib.sha256(
        json.dumps(
            rows,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    payload = {
        "schema_version": "plamen.queue_work_items.v2",
        "record_count": 1,
        "record_set_digest": digest,
        "rows": rows,
    }
    migrated = Q.queue_records_from_json(json.dumps(payload))[0]
    assert migrated.effective_evidence_scope == "UNSPECIFIED"
    assert migrated.effective_proof_scope == "ANALYTICAL"
    assert migrated.effective_harm_scope == "UNPROVEN"
    assert json.loads(Q.queue_records_to_json([migrated]))["schema_version"] == (
        "plamen.queue_work_items.v3"
    )
