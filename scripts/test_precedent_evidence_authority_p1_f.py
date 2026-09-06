from __future__ import annotations

import json
from pathlib import Path

import pytest

import precedent_evidence_authority as P


ROOT = Path(__file__).resolve().parents[1]
RUN_ID = "run-precedent-fixture"
SNAPSHOT = "1" * 64
SOURCE_SHA = "2" * 64


def _findings(*ids: str) -> dict:
    return {
        "schema_version": P.FINDING_FACTS_SCHEMA,
        "run_id": RUN_ID,
        "snapshot_digest": SNAPSHOT,
        "findings": [
            {
                "finding_id": finding_id,
                "mechanism_class": "STATE_TRANSITION_MISMATCH",
                "precondition_classes": [
                    "CALLER_CONTROLS_INPUT",
                    "DEPENDENT_STATE_PRESENT",
                ],
                "source_binding_sha256": (str(index + 3) * 64)[:64],
                "mechanism_origin": "EXPLICIT_TYPED_FIELDS",
                "extraction_status": "EXPLICIT_BOUND",
                "fact_issues": [],
            }
            for index, finding_id in enumerate(ids)
        ],
    }


def _proposal(
    *,
    proposal_id: str = "PR-1",
    finding_id: str = "F-1",
    source_kind: str = "PRIMARY_PRECEDENT",
    relation: str = "SUPPORTING",
    mechanism_class: str = "STATE_TRANSITION_MISMATCH",
    preconditions: tuple[str, ...] = (
        "CALLER_CONTROLS_INPUT",
        "DEPENDENT_STATE_PRESENT",
    ),
    availability: str = "AVAILABLE",
) -> dict:
    return {
        "proposal_id": proposal_id,
        "finding_id": finding_id,
        "source_kind": source_kind,
        "source_ref": f"source:{proposal_id.lower()}",
        "source_sha256": SOURCE_SHA,
        "availability": availability,
        "relation": relation,
        "mechanism_class": mechanism_class,
        "precondition_classes": list(preconditions),
        "report_context": "A bounded external source was reviewed.",
    }


def _proposals(*rows: dict) -> dict:
    return {
        "schema_version": P.PROPOSAL_SCHEMA,
        "run_id": RUN_ID,
        "snapshot_digest": SNAPSHOT,
        "proposals": list(rows),
    }


def _source_evidence(*proposals: dict) -> dict:
    sources = []
    for index, proposal in enumerate(proposals, 1):
        row = {
            "source_ref": proposal["source_ref"],
            "source_sha256": proposal["source_sha256"],
            "source_kind": "PRIMARY_PRECEDENT",
            "capture_artifact": f"_precedent_sources/source_{index}.bin",
            "capture_artifact_sha256": proposal["source_sha256"],
        }
        sources.append(row)
    return P.build_precedent_source_evidence_artifact(
        run_id=RUN_ID,
        snapshot_digest=SNAPSHOT,
        sources=sources,
    )


def _by_id(payload: dict) -> dict[str, dict]:
    return {row["finding_id"]: row for row in payload["finding_precedent"]}


def _assert_no_decision_authority(row: dict) -> None:
    assert row["mechanism_confidence_delta"] == 0.0
    assert row["may_clear_or_demote"] is False
    assert row["may_force_contested"] is False
    assert row["may_change_severity"] is False
    assert row["may_reduce_investigation_depth"] is False


def test_generic_methodology_article_is_context_only_with_zero_uplift():
    payload = P.reconcile_precedent_evidence(
        _findings("F-1"),
        _proposals(_proposal(source_kind="GENERIC_METHODOLOGY")),
    )

    row = _by_id(payload)["F-1"]
    assert row["match_status"] == "GENERIC_CONTEXT_ONLY"
    assert row["precedent_strength"] == "NONE"
    assert row["investigation_priority"] == "UNCHANGED"
    _assert_no_decision_authority(row)


def test_exact_primary_precedent_needs_mechanism_and_precondition_identity():
    proposal = _proposal()
    payload = P.reconcile_precedent_evidence(
        _findings("F-1"),
        _proposals(proposal),
        source_evidence_artifact=_source_evidence(proposal),
    )

    row = _by_id(payload)["F-1"]
    assert row["match_status"] == "EXACT_PRIMARY_PRECEDENT"
    assert row["precedent_strength"] == "EXACT"
    assert row["investigation_priority"] == "ELEVATED"
    assert row["report_context_eligible"] is True
    _assert_no_decision_authority(row)


def test_semantic_exact_proposal_without_neutral_source_receipt_is_unbound_context():
    payload = P.reconcile_precedent_evidence(
        _findings("F-1"), _proposals(_proposal())
    )

    row = _by_id(payload)["F-1"]
    assert row["match_status"] == "SOURCE_UNBOUND_CONTEXT_ONLY"
    assert row["precedent_strength"] == "NONE"
    assert row["investigation_priority"] == "UNCHANGED"
    assert row["report_context_eligible"] is False
    _assert_no_decision_authority(row)


def test_secondary_source_with_exact_words_remains_context_not_exact_precedent():
    payload = P.reconcile_precedent_evidence(
        _findings("F-1"),
        _proposals(_proposal(source_kind="SECONDARY_PRECEDENT")),
    )

    row = _by_id(payload)["F-1"]
    assert row["match_status"] == "NO_EXACT_MATCH"
    assert row["precedent_strength"] == "NONE"
    _assert_no_decision_authority(row)


@pytest.mark.parametrize(
    ("mechanism", "preconditions"),
    [
        ("ADJACENT_STATE_PATTERN", ("CALLER_CONTROLS_INPUT", "DEPENDENT_STATE_PRESENT")),
        ("STATE_TRANSITION_MISMATCH", ("CALLER_CONTROLS_INPUT",)),
        (
            "STATE_TRANSITION_MISMATCH",
            ("CALLER_CONTROLS_INPUT", "DIFFERENT_PRECONDITION"),
        ),
    ],
)
def test_superficially_similar_precedent_never_counts_as_exact(
    mechanism: str, preconditions: tuple[str, ...]
):
    payload = P.reconcile_precedent_evidence(
        _findings("F-1"),
        _proposals(
            _proposal(mechanism_class=mechanism, preconditions=preconditions)
        ),
    )

    row = _by_id(payload)["F-1"]
    assert row["match_status"] == "NO_EXACT_MATCH"
    assert row["precedent_strength"] == "NONE"
    assert row["investigation_priority"] == "UNCHANGED"
    _assert_no_decision_authority(row)


def test_refuting_article_is_context_and_cannot_clear_or_demote():
    proposal = _proposal(relation="REFUTING")
    payload = P.reconcile_precedent_evidence(
        _findings("F-1"),
        _proposals(proposal),
        source_evidence_artifact=_source_evidence(proposal),
    )

    row = _by_id(payload)["F-1"]
    assert row["match_status"] == "REFUTING_CONTEXT_ONLY"
    assert row["precedent_strength"] == "NONE"
    assert row["report_context_eligible"] is True
    _assert_no_decision_authority(row)


def test_one_exact_family_member_does_not_score_unbound_siblings():
    proposal = _proposal(finding_id="F-1")
    payload = P.reconcile_precedent_evidence(
        _findings("F-1", "F-2"),
        _proposals(proposal),
        source_evidence_artifact=_source_evidence(proposal),
    )

    rows = _by_id(payload)
    assert rows["F-1"]["precedent_strength"] == "EXACT"
    assert rows["F-2"]["match_status"] == "UNSCORED"
    assert rows["F-2"]["precedent_strength"] == "NONE"


def test_family_propagation_requires_current_typed_equivalence():
    equivalence = {
        "schema_version": P.EQUIVALENCE_SCHEMA,
        "run_id": RUN_ID,
        "snapshot_digest": SNAPSHOT,
        "equivalences": [
            {
                "left_finding_id": "F-1",
                "right_finding_id": "F-2",
                "relation": "MECHANISM_PRECONDITION_EQUIVALENT",
                "status": "CURRENT",
                "mechanism_class": "STATE_TRANSITION_MISMATCH",
                "precondition_classes": [
                    "CALLER_CONTROLS_INPUT",
                    "DEPENDENT_STATE_PRESENT",
                ],
                "evidence_sha256": "9" * 64,
            }
        ],
    }
    proposal = _proposal(finding_id="F-1")
    payload = P.reconcile_precedent_evidence(
        _findings("F-1", "F-2"),
        _proposals(proposal),
        equivalence,
        _source_evidence(proposal),
    )

    row = _by_id(payload)["F-2"]
    assert row["match_status"] == "TYPED_EQUIVALENT_EXACT_PRECEDENT"
    assert row["precedent_strength"] == "EXACT"
    assert row["propagated_from_finding_id"] == "F-1"
    _assert_no_decision_authority(row)


def test_stale_or_inexact_equivalence_is_debt_and_never_propagates():
    equivalence = {
        "schema_version": P.EQUIVALENCE_SCHEMA,
        "run_id": RUN_ID,
        "snapshot_digest": SNAPSHOT,
        "equivalences": [
            {
                "left_finding_id": "F-1",
                "right_finding_id": "F-2",
                "relation": "MECHANISM_PRECONDITION_EQUIVALENT",
                "status": "STALE",
                "mechanism_class": "STATE_TRANSITION_MISMATCH",
                "precondition_classes": [
                    "CALLER_CONTROLS_INPUT",
                    "DEPENDENT_STATE_PRESENT",
                ],
                "evidence_sha256": "9" * 64,
            }
        ],
    }
    payload = P.reconcile_precedent_evidence(
        _findings("F-1", "F-2"),
        _proposals(_proposal(finding_id="F-1")),
        equivalence,
    )

    assert _by_id(payload)["F-2"]["match_status"] == "UNSCORED"
    assert any(
        debt["code"] == "TYPED_EQUIVALENCE_REJECTED"
        for debt in payload["debts"]
    )


@pytest.mark.parametrize("availability", ["OFFLINE", "TIMEOUT"])
def test_offline_and_timeout_fallback_are_unscored_and_idempotent(
    availability: str,
):
    findings = _findings("F-1")
    proposals = _proposals(
        _proposal(availability=availability, source_kind="UNAVAILABLE")
    )

    first = P.reconcile_precedent_evidence(findings, proposals)
    second = P.reconcile_precedent_evidence(findings, proposals)
    row = _by_id(first)["F-1"]

    assert first == second
    assert P.canonical_json_bytes(first) == P.canonical_json_bytes(second)
    assert row["match_status"] == f"SOURCE_{availability}"
    assert row["precedent_strength"] == "NONE"
    _assert_no_decision_authority(row)


def test_duplicate_or_malformed_proposals_become_visible_debt_not_uplift():
    duplicated = _proposal()
    payload = P.reconcile_precedent_evidence(
        _findings("F-1"), _proposals(duplicated, dict(duplicated))
    )

    row = _by_id(payload)["F-1"]
    assert row["match_status"] == "UNMEASURABLE"
    assert row["precedent_strength"] == "NONE"
    assert payload["debts"]
    _assert_no_decision_authority(row)


def test_invalid_transport_normalizes_to_complete_unavailable_denominator():
    findings = _findings("F-1", "F-2")
    normalized = P.normalize_precedent_proposal_transport(
        "not a typed proposal block", findings
    )

    assert {row["finding_id"] for row in normalized["proposals"]} == {
        "F-1",
        "F-2",
    }
    assert all(row["source_kind"] == "UNAVAILABLE" for row in normalized["proposals"])
    assert any(
        row["code"] == "PROPOSAL_TRANSPORT_FAILED"
        for row in normalized["transport_debts"]
    )
    authority = P.reconcile_precedent_evidence(findings, normalized)
    assert all(
        row["precedent_strength"] == "NONE"
        for row in authority["finding_precedent"]
    )


def test_exact_projection_keeps_only_receipt_bound_matching_source():
    exact = _proposal(proposal_id="PR-EXACT")
    refuting = _proposal(proposal_id="PR-REFUTING", relation="REFUTING")
    payload = P.reconcile_precedent_evidence(
        _findings("F-1"),
        _proposals(exact, refuting),
        source_evidence_artifact=_source_evidence(exact),
    )

    row = _by_id(payload)["F-1"]
    assert row["match_status"] == "EXACT_PRIMARY_PRECEDENT"
    assert row["matching_proposal_ids"] == ["PR-EXACT"]
    assert row["context_source_refs"] == [exact["source_ref"]]
    assert [source["proposal_id"] for source in row["context_sources"]] == [
        "PR-EXACT"
    ]


def test_markdown_transport_extracts_one_bounded_typed_proposal_block():
    artifact = _proposals(_proposal())
    markdown = (
        "# Precedent research\n\n"
        f"{P.PROPOSAL_BLOCK_BEGIN}\n"
        f"{json.dumps(artifact, sort_keys=True)}\n"
        f"{P.PROPOSAL_BLOCK_END}\n"
    )

    assert P.extract_proposal_artifact(markdown) == artifact
    with pytest.raises(ValueError, match="exactly one"):
        P.extract_proposal_artifact(markdown + markdown)


def test_written_projection_is_derived_and_tamper_validation_fails(tmp_path: Path):
    findings = _findings("F-1")
    proposals = _proposals(_proposal())
    payload = P.write_precedent_evidence_artifacts(tmp_path, findings, proposals)

    typed = json.loads(
        (tmp_path / P.AUTHORITY_NAME).read_text(encoding="utf-8")
    )
    projection = (tmp_path / P.CONTEXT_NAME).read_text(encoding="utf-8")
    assert typed == payload
    assert payload["authority_digest"] in projection
    assert P.validate_precedent_evidence_authority(
        typed, findings, proposals
    ) == []

    typed["finding_precedent"][0]["may_change_severity"] = True
    assert P.validate_precedent_evidence_authority(typed, findings, proposals)


def test_projection_tamper_is_detected_and_repaired_without_model_input(tmp_path: Path):
    findings = _findings("F-1")
    proposals = _proposals(_proposal())
    payload = P.write_precedent_evidence_artifacts(tmp_path, findings, proposals)
    (tmp_path / P.CONTEXT_NAME).write_text("stale projection\n", encoding="utf-8")

    assert P.validate_precedent_evidence_artifacts(
        tmp_path, payload, findings, proposals
    )
    repaired = P.repair_precedent_evidence_artifacts(
        tmp_path, findings, proposals
    )
    assert P.validate_precedent_evidence_artifacts(
        tmp_path, repaired, findings, proposals
    ) == []


def test_canonical_prompt_and_policy_remove_rag_from_decision_authority():
    paths = [
        ROOT / "rules" / "precedent-evidence-policy.md",
        ROOT / "rules" / "phase4-confidence-scoring.md",
        ROOT / "prompts" / "shared" / "v2" / "phase4b5-rag-sweep.md",
        ROOT / "prompts" / "shared" / "v2" / "phase4b-scoring.md",
        ROOT / "prompts" / "shared" / "v2" / "phase4b-rescore.md",
        ROOT / "prompts" / "shared" / "v2" / "phase4b-final-scoring.md",
        ROOT / "rules" / "phase4c-chain-prompt.md",
        ROOT / "rules" / "phase5-poc-execution.md",
        ROOT / "rules" / "phase6-report-prompts.md",
    ]
    corpus = "\n".join(path.read_text(encoding="utf-8") for path in paths)
    lower = corpus.lower()

    assert "generic methodology literature supplies context only" in lower
    assert "mechanism class" in lower and "matching preconditions" in lower
    assert "may never clear or demote" in lower
    assert "typed equivalence" in lower
    assert "rag confidence override" not in lower
    assert "if historical precedent found → upgrade" not in lower
    assert "rag_match * 0.2" not in lower
    assert "rag_match × 0.2" not in lower


def test_every_ecosystem_verifier_uses_shared_precedent_policy_without_override():
    paths = [
        ROOT / "agents" / "security-verifier.md",
        ROOT / "agents" / "skills" / "evm" / "verification-protocol" / "references" / "advanced.md",
        ROOT / "agents" / "skills" / "aptos" / "verification-protocol" / "references" / "advanced.md",
        ROOT / "agents" / "skills" / "sui" / "verification-protocol" / "references" / "advanced.md",
        ROOT / "agents" / "skills" / "solana" / "verification-protocol" / "SKILL.md",
        ROOT / "agents" / "skills" / "soroban" / "verification-protocol" / "SKILL.md",
        ROOT / "agents" / "skills" / "daml" / "verification-protocol" / "SKILL.md",
    ]
    for path in paths:
        text = path.read_text(encoding="utf-8")
        lower = text.lower()
        assert "precedent-evidence-policy.md" in lower, path
        assert "rag confidence override" not in lower, path
        assert "rag >= 6/8" not in lower, path
        assert "false_positive | **contested**" not in lower, path


def test_no_active_methodology_retains_precedent_as_a_decision_axis():
    roots = [ROOT / "rules", ROOT / "prompts", ROOT / "agents"]
    forbidden = (
        "rag_match * 0.2",
        "rag_match × 0.2",
        "rag_match ã— 0.2",
        "rag confidence override",
        "rag >= 6/8",
        "all findings have rag confidence",
        "if historical precedent found → upgrade",
    )
    failures: list[str] = []
    for base in roots:
        for path in base.rglob("*.md"):
            text = path.read_text(encoding="utf-8", errors="replace").lower()
            for token in forbidden:
                if token in text:
                    failures.append(f"{path.relative_to(ROOT)}: {token}")
    assert failures == []


def test_driver_writes_and_consumes_typed_precedent_authority_without_rag_floor():
    source = (ROOT / "scripts" / "plamen_driver.py").read_text(encoding="utf-8")
    assert "write_precedent_evidence_artifacts" in source
    assert "precedent_evidence_authority.AUTHORITY_NAME" in source
    assert "rag = 0.3" not in source
    assert "RAG_PENDING" not in source
