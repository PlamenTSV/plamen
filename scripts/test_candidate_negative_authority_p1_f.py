from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

import candidate_negative_authority as N


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _method(tmp_path: Path) -> Path:
    path = tmp_path / "finding-output-format.md"
    path.write_text("# Bound negative-proposal methodology\n", encoding="utf-8")
    return path


def _build(
    tmp_path: Path,
    text: str,
    *,
    phase: str = "depth",
    prior: dict[str, object] | None = None,
) -> dict[str, object]:
    method = _method(tmp_path)
    raw = text.encode("utf-8")
    return N.build_candidate_negative_ledger(
        phase=phase,
        artifacts=[
            N.ArtifactInput(
                relative_path="depth_state_trace_findings.md",
                content=raw,
                producer_identity="DEPTH_STATE_TRACE",
                producer_invocation_id="INVOCATION-1",
            )
        ],
        methodology_path=method,
        prior_ledger=prior,
    )


def test_harvests_structured_refuted_finding_with_exact_binding(tmp_path: Path) -> None:
    source = """### Finding [ST-7]: Candidate title

**Verdict**: REFUTED
**Location**: src/Vault.sol:L41
**Refutation Basis**: guarded by the balance relation at the cited locus
**Variants Examined**: zero, equality, maximum
**External Assumption**: upstream token remains standard
"""
    ledger = _build(tmp_path, source)
    N.validate_candidate_negative_ledger(ledger)
    assert ledger["event_count"] == 1
    row = ledger["events"][0]
    assert row["source_item_id"] == "ST-7"
    assert row["legacy_disposition"] == "REFUTED"
    assert row["proposed_disposition"] == "REFUTATION_PROPOSAL"
    assert row["guard_locus"] == "src/Vault.sol:L41"
    assert row["variants_examined"] == ["equality", "maximum", "zero"]
    assert row["external_assumption"] is True
    assert row["proof_scope"] == "NONE"
    assert row["requires_independent_consumer"] is True
    assert row["source_artifact_sha256"] == _sha(source.encode("utf-8"))


def _depth_ci_source(*, declaration: str = "CI:CI-7", ci_blocks: str = "") -> str:
    if not ci_blocks:
        ci_blocks = """committed-invariant [CI-7]
Locus: src/Vault.sol:L41
Shape: CONSERVATION
Assertion: total credited value equals total settled value
Falsify Class: conservation
Provenance: depth REFUTATION_PROPOSAL @ ST-7
"""
    return f"""### Finding [ST-7]: Candidate title

**Verdict**: REFUTATION_PROPOSAL
**Location**: src/Vault.sol:L41
**Refutation Basis**: the local accounting relation blocks value loss
**Invariant Commitment**: {declaration}

{ci_blocks}
"""


def test_depth_negative_missing_ci_is_input_debt_not_closure(tmp_path: Path) -> None:
    source = _depth_ci_source(declaration="")
    ledger = _build(tmp_path, source)
    event = ledger["events"][0]
    assert ledger["status"] == "INPUT_DEBT"
    assert event["invariant_commitment"]["status"] == "DEBT"
    assert any(
        issue["code"] == "DEPTH_COMMITTED_INVARIANT_DEBT"
        for issue in ledger["issues"]
    )


def test_depth_negative_exact_ci_binding_is_complete(tmp_path: Path) -> None:
    ledger = _build(tmp_path, _depth_ci_source())
    event = ledger["events"][0]
    assert ledger["status"] == "CLEAN"
    assert event["invariant_commitment"]["status"] == "COMPLETE"
    assert event["invariant_commitment"]["ci_id"] == "CI-7"
    assert len(event["invariant_commitment"]["binding_digest"]) == 64


def test_depth_negative_duplicate_ci_identity_is_debt(tmp_path: Path) -> None:
    block = _depth_ci_source().split("committed-invariant", 1)[1]
    duplicate_blocks = "committed-invariant" + block + "\ncommitted-invariant" + block
    ledger = _build(tmp_path, _depth_ci_source(ci_blocks=duplicate_blocks))
    assert ledger["events"][0]["invariant_commitment"]["status"] == "DEBT"


def test_depth_non_value_exemption_requires_typed_reason(tmp_path: Path) -> None:
    ledger = _build(
        tmp_path,
        """### Finding [ST-8]: comment clarity

**Verdict**: REFUTATION_PROPOSAL
**Refutation Basis**: wording observation only
**Non-Value-Bearing Category**: DOCUMENTATION_ONLY
**Invariant Commitment**: NOT_REQUIRED_NON_VALUE_BEARING: comment-only observation
""",
    )
    assert ledger["status"] == "CLEAN"
    assert ledger["events"][0]["invariant_commitment"]["status"] == (
        "NOT_REQUIRED_NON_VALUE_BEARING"
    )
    assert ledger["events"][0]["invariant_commitment"][
        "non_value_bearing_category"
    ] == "DOCUMENTATION_ONLY"


def _resign_ledger(ledger: dict[str, object]) -> None:
    ledger["ledger_digest"] = N._digest(
        {key: value for key, value in ledger.items() if key != "ledger_digest"}
    )


def test_ci_identity_is_one_to_one_across_artifacts(tmp_path: Path) -> None:
    method = _method(tmp_path)
    source = _depth_ci_source().encode("utf-8")
    ledger = N.build_candidate_negative_ledger(
        phase="depth",
        artifacts=[
            N.ArtifactInput("depth_a.md", source, "A", "I-A"),
            N.ArtifactInput("depth_b.md", source, "B", "I-B"),
        ],
        methodology_path=method,
    )
    assert ledger["status"] == "INPUT_DEBT"
    assert len(ledger["events"]) == 2
    assert {
        row["invariant_commitment"]["status"] for row in ledger["events"]
    } == {"DEBT"}


def test_stale_source_excerpt_hash_is_rejected_after_envelope_resign(
    tmp_path: Path,
) -> None:
    ledger = json.loads(json.dumps(_build(tmp_path, _depth_ci_source())))
    event = ledger["events"][0]
    event["source_excerpt"] += "\nmutated"
    event["event_digest"] = N._digest(
        {key: value for key, value in event.items() if key != "event_digest"}
    )
    _resign_ledger(ledger)
    with pytest.raises(N.CandidateNegativeAuthorityError, match="excerpt digest"):
        N.validate_candidate_negative_ledger(ledger)


def test_source_artifact_hash_mutation_is_rejected_even_when_resigned(
    tmp_path: Path,
) -> None:
    ledger = json.loads(json.dumps(_build(tmp_path, _depth_ci_source())))
    artifact = ledger["source_artifacts"][0]
    artifact["sha256"] = "f" * 64
    artifact["binding_digest"] = N._digest(
        {key: value for key, value in artifact.items() if key != "binding_digest"}
    )
    _resign_ledger(ledger)
    with pytest.raises(N.CandidateNegativeAuthorityError, match="denominator mismatch"):
        N.validate_candidate_negative_ledger(ledger)


def test_value_bearing_negative_cannot_self_exempt(tmp_path: Path) -> None:
    source = _depth_ci_source(
        declaration="NOT_REQUIRED_NON_VALUE_BEARING: producer says exempt",
        ci_blocks="\n",
    ).replace(
        "**Invariant Commitment**:",
        "**Non-Value-Bearing Category**: DOCUMENTATION_ONLY\n**Invariant Commitment**:",
    )
    ledger = _build(tmp_path, source)
    assert ledger["status"] == "INPUT_DEBT"
    assert ledger["events"][0]["invariant_commitment"]["status"] == "DEBT"


def test_event_not_applicable_cannot_replace_nonzero_denominator(
    tmp_path: Path,
) -> None:
    ledger = _build(
        tmp_path,
        "### Candidate [ST-9]: live path\n\n**Verdict**: NOT_APPLICABLE\n",
    )
    assert ledger["status"] == "INPUT_DEBT"
    assert any(
        issue["code"] == "EVENT_NOT_APPLICABLE_WITH_NONZERO_DENOMINATOR"
        for issue in ledger["issues"]
    )


def test_family_membership_must_be_exactly_one_and_match_event(
    tmp_path: Path,
) -> None:
    ledger = json.loads(json.dumps(_build(tmp_path, _depth_ci_source())))
    duplicate = dict(ledger["families"][0])
    duplicate["family_id"] = "CNF-" + "F" * 24
    ledger["families"].append(duplicate)
    _resign_ledger(ledger)
    with pytest.raises(N.CandidateNegativeAuthorityError, match="family/event"):
        N.validate_candidate_negative_ledger(ledger)


def test_missing_event_field_raises_typed_authority_error(tmp_path: Path) -> None:
    ledger = json.loads(json.dumps(_build(tmp_path, _depth_ci_source())))
    event = ledger["events"][0]
    del event["family_id"]
    event["event_digest"] = N._digest(
        {key: value for key, value in event.items() if key != "event_digest"}
    )
    _resign_ledger(ledger)
    with pytest.raises(N.CandidateNegativeAuthorityError, match="shape invalid"):
        N.validate_candidate_negative_ledger(ledger)


def test_harvests_attention_table_and_strict_dismissal_receipt(tmp_path: Path) -> None:
    ledger = _build(
        tmp_path,
        """## Repair Summary

| Queue # | Kind | Target | Verdict | Evidence | Notes |
|---|---|---|---|---|---|
| 8 | graph-gap | src/Bridge.sol:L90 | SAFE | src/Bridge.sol:L90 | guard exists |

[OBLIG:opengrep_findings.md:12] STATUS:D KEY:rule@src/Fee.sol:L13 -> by design
""",
        phase="attention_repair",
    )
    assert {row["legacy_disposition"] for row in ledger["events"]} == {
        "SAFE",
        "DISMISSED",
    }
    assert len({row["source_item_id"] for row in ledger["events"]}) == 2


@pytest.mark.parametrize(
    ("token", "proposal"),
    [
        ("CLEAR", "REFUTATION_PROPOSAL"),
        ("NO_FINDING", "REFUTATION_PROPOSAL"),
        ("FALSE POSITIVE", "REFUTATION_PROPOSAL"),
        ("NOT EXPLOITABLE", "REFUTATION_PROPOSAL"),
        ("UNREACHABLE", "REFUTATION_PROPOSAL"),
        ("BY DESIGN", "REFUTATION_PROPOSAL"),
        ("DUPLICATE", "REFUTATION_PROPOSAL"),
        ("ABSORBED", "REFUTATION_PROPOSAL"),
        ("NOT_APPLICABLE", "NOT_APPLICABLE_PROPOSAL"),
    ],
)
def test_legacy_terminal_vocabulary_is_never_terminal(
    tmp_path: Path, token: str, proposal: str
) -> None:
    ledger = _build(
        tmp_path,
        f"### Candidate [C-9]: edge\n\n**Disposition**: {token}\n"
        "**Evidence**: src/State.sol:L9\n",
    )
    assert ledger["events"][0]["proposed_disposition"] == proposal


def test_unstructured_methodology_prose_does_not_false_fire(tmp_path: Path) -> None:
    ledger = _build(
        tmp_path,
        """# Notes

Allowed verdicts include SAFE, CLEAR, REFUTED, and NOT_APPLICABLE.
Do not mark a candidate false positive merely because a guard exists.
The word unreachable is discussed here as methodology, not a decision.
""",
    )
    assert ledger["events"] == []


def test_mixed_positive_and_negative_entities_remain_separate(tmp_path: Path) -> None:
    ledger = _build(
        tmp_path,
        """### Finding [A-1]: live
**Verdict**: CONFIRMED
**Location**: src/A.sol:L1

### Finding [A-2]: dismissed
**Verdict**: REFUTED
**Location**: src/A.sol:L2
""",
    )
    assert [row["source_item_id"] for row in ledger["events"]] == ["A-2"]


def test_append_only_resume_is_idempotent_and_preserves_rewritten_event(
    tmp_path: Path,
) -> None:
    first = _build(
        tmp_path,
        "### Finding [A-2]: x\n**Verdict**: REFUTED\n**Evidence**: src/A.sol:L2\n",
    )
    same = _build(
        tmp_path,
        "### Finding [A-2]: x\n**Verdict**: REFUTED\n**Evidence**: src/A.sol:L2\n",
        prior=first,
    )
    assert same == first

    changed = _build(
        tmp_path,
        "### Finding [A-2]: x\n**Verdict**: REFUTED\n**Evidence**: src/A.sol:L3\n",
        prior=first,
    )
    assert changed["event_count"] == 2
    assert len({row["proposal_id"] for row in changed["events"]}) == 1
    assert len({row["event_id"] for row in changed["events"]}) == 2


def test_conflicting_duplicate_event_is_durable_debt(tmp_path: Path) -> None:
    ledger = _build(
        tmp_path,
        "### Finding [A-2]: x\n**Verdict**: REFUTED\n**Evidence**: src/A.sol:L2\n",
    )
    tampered = json.loads(json.dumps(ledger))
    tampered["events"][0]["exact_premise"] = "different"
    with pytest.raises(N.CandidateNegativeAuthorityError):
        _build(
            tmp_path,
            "### Finding [A-2]: x\n**Verdict**: REFUTED\n**Evidence**: src/A.sol:L2\n",
            prior=tampered,
        )


def test_separate_ledger_never_mutates_methodology_step_queue(tmp_path: Path) -> None:
    methodology_queue = tmp_path / "methodology_skeptic_queue_depth.json"
    methodology_queue.write_bytes(b"METHOD-QUEUE-SENTINEL")
    ledger = _build(
        tmp_path,
        "### Finding [A-2]: x\n**Verdict**: REFUTED\n**Evidence**: src/A.sol:L2\n",
    )
    path = N.write_candidate_negative_ledger(tmp_path, ledger)
    assert path.name == "candidate_negative_proposals_depth.json"
    assert methodology_queue.read_bytes() == b"METHOD-QUEUE-SENTINEL"
    assert json.loads(path.read_text(encoding="utf-8")) == ledger


def test_ledger_write_is_byte_idempotent(tmp_path: Path) -> None:
    ledger = _build(
        tmp_path,
        "### Finding [A-2]: x\n**Verdict**: REFUTED\n**Evidence**: src/A.sol:L2\n",
    )
    path = N.write_candidate_negative_ledger(tmp_path, ledger)
    first = path.read_bytes()
    N.write_candidate_negative_ledger(tmp_path, ledger)
    assert path.read_bytes() == first


def test_malformed_prior_ledger_cannot_be_treated_as_empty(tmp_path: Path) -> None:
    ledger = _build(
        tmp_path,
        "### Finding [A-2]: x\n**Verdict**: REFUTED\n**Evidence**: src/A.sol:L2\n",
    )
    malformed = json.loads(json.dumps(ledger))
    malformed["ledger_digest"] = "0" * 64
    with pytest.raises(N.CandidateNegativeAuthorityError):
        _build(
            tmp_path,
            "### Finding [A-2]: x\n**Verdict**: REFUTED\n**Evidence**: src/A.sol:L2\n",
            prior=malformed,
        )


def test_terminal_negative_prompt_contract_rejects_generator_authority() -> None:
    with pytest.raises(N.CandidateNegativeAuthorityError):
        N.validate_generator_prompt_negative_contract(
            "Allowed Verdicts: CONFIRMED | SAFE | NO_FINDING",
            phase="attention_repair",
        )
    N.validate_generator_prompt_negative_contract(
        "Outcome: CANDIDATE | REFUTATION_PROPOSAL | "
        "NOT_APPLICABLE_PROPOSAL | UNRESOLVED",
        phase="attention_repair",
    )
    # Independent consumers retain terminal authority.
    N.validate_generator_prompt_negative_contract(
        "Verdict: CONFIRMED | REFUTED | FALSE_POSITIVE",
        phase="verify_high",
    )


def test_duplicate_explicit_identity_in_one_artifact_is_fail_visible_debt(
    tmp_path: Path,
) -> None:
    ledger = _build(
        tmp_path,
        """### Finding [A-2]: first mechanism
**Verdict**: REFUTED
**Evidence**: src/A.sol:L2

### Finding [A-2]: different mechanism
**Verdict**: SAFE
**Evidence**: src/B.sol:L8
""",
    )
    assert ledger["status"] == "INPUT_DEBT"
    assert {issue["code"] for issue in ledger["issues"]} >= {
        "DUPLICATE_SOURCE_ITEM_ID",
        "CONFLICTING_ENTITY_CLAIM",
    }
    family = ledger["families"][0]
    assert family["identity_state"] == "CONFLICTED"
    assert len(family["event_ids"]) == 2


def test_missing_explicit_identity_is_derived_and_never_clean_authority(
    tmp_path: Path,
) -> None:
    ledger = _build(
        tmp_path,
        """### Candidate without a stable identifier
**Verdict**: REFUTED
**Evidence**: src/A.sol:L2
""",
    )
    assert ledger["status"] == "INPUT_DEBT"
    assert ledger["events"][0]["identity_state"] == "DERIVED"
    assert ledger["families"][0]["identity_state"] == "DERIVED"
    assert ledger["issues"][0]["code"] == "DERIVED_SOURCE_ITEM_ID"


def test_same_local_id_in_distinct_artifacts_is_not_silently_merged(
    tmp_path: Path,
) -> None:
    method = _method(tmp_path)
    common = "### Finding [A-2]: same label\n**Verdict**: REFUTED\n"
    ledger = N.build_candidate_negative_ledger(
        phase="depth",
        artifacts=[
            N.ArtifactInput("one.md", common.encode(), "P1", "I1"),
            N.ArtifactInput("two.md", common.encode(), "P2", "I2"),
        ],
        methodology_path=method,
    )
    assert len(ledger["families"]) == 2
    assert len({event["family_id"] for event in ledger["events"]}) == 2


def test_whitespace_revision_keeps_family_without_claim_conflict(
    tmp_path: Path,
) -> None:
    first = _build(
        tmp_path,
        "### Finding [A-2]: same claim\n**Verdict**: REFUTED\n"
        "**Evidence**: src/A.sol:L2\n",
    )
    second = _build(
        tmp_path,
        "###   Finding [A-2]:   same claim  \n\n"
        "**Verdict**:   REFUTED\n**Evidence**: src/A.sol:L2\n",
        prior=first,
    )
    family = second["families"][0]
    assert family["identity_state"] == "EXACT"
    assert len(family["semantic_claim_sha256s"]) == 1
    assert not any(
        issue["code"] == "CONFLICTING_ENTITY_CLAIM"
        for issue in second["issues"]
    )


def test_reused_id_with_changed_claim_is_conflict_not_overwrite(
    tmp_path: Path,
) -> None:
    first = _build(
        tmp_path,
        "### Finding [A-2]: first claim\n**Verdict**: REFUTED\n"
        "**Evidence**: src/A.sol:L2\n",
    )
    second = _build(
        tmp_path,
        "### Finding [A-2]: materially different claim\n"
        "**Verdict**: REFUTED\n**Evidence**: src/B.sol:L8\n",
        prior=first,
    )
    assert second["status"] == "INPUT_DEBT"
    assert second["families"][0]["identity_state"] == "CONFLICTED"
    assert any(
        issue["code"] == "CONFLICTING_ENTITY_CLAIM"
        for issue in second["issues"]
    )


def test_reused_id_with_same_title_but_changed_premise_or_locus_is_conflicted(
    tmp_path: Path,
) -> None:
    first = _build(
        tmp_path,
        "### Finding [A-2]: same claim\n**Verdict**: REFUTED\n"
        "**Refutation Basis**: first mechanism\n**Evidence**: src/A.sol:L2\n",
    )
    second = _build(
        tmp_path,
        "### Finding [A-2]: same claim\n**Verdict**: REFUTED\n"
        "**Refutation Basis**: different mechanism\n**Evidence**: src/B.sol:L8\n",
        prior=first,
    )
    assert second["status"] == "INPUT_DEBT"
    assert second["families"][0]["identity_state"] == "CONFLICTED"
    assert len(second["families"][0]["semantic_claim_sha256s"]) == 2


@pytest.mark.parametrize(
    ("payload", "expected_detail"),
    [
        ('{"schema_version":"x","schema_version":"y"}', "duplicate JSON"),
        ('{"schema_version":"x","value":NaN}', "nonfinite JSON"),
        ('{"schema_version":"x","value":Infinity}', "nonfinite JSON"),
    ],
)
def test_candidate_ledger_loader_rejects_duplicate_keys_and_nonfinite_numbers(
    tmp_path: Path, payload: str, expected_detail: str
) -> None:
    (tmp_path / "candidate_negative_proposals_depth.json").write_text(
        payload, encoding="utf-8"
    )
    plan = N.build_candidate_negative_application_plan(
        tmp_path, phases=("depth",), max_items_per_shard=4
    )
    assert plan["status"] == "INPUT_DEBT"
    assert plan["issues"][0]["code"] == "INVALID_CANDIDATE_NEGATIVE_LEDGER"
    assert expected_detail in plan["issues"][0]["detail"]


@pytest.mark.parametrize(
    ("token", "proposal"),
    [
        ("REFUTATION_PROPOSAL", "REFUTATION_PROPOSAL"),
        ("NOT_APPLICABLE_PROPOSAL", "NOT_APPLICABLE_PROPOSAL"),
        ("UNRESOLVED", "UNRESOLVED"),
    ],
)
def test_compliant_generator_proposal_enum_is_harvested(
    tmp_path: Path, token: str, proposal: str
) -> None:
    ledger = _build(
        tmp_path,
        f"### Finding [A-2]: candidate\n**Disposition**: {token}\n"
        "**Evidence**: src/A.sol:L2\n",
    )
    assert ledger["event_count"] == 1
    assert ledger["events"][0]["proposed_disposition"] == proposal
