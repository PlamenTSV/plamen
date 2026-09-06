"""P0-0/P0-1/P0-2 producer-registry and delivery-closure contracts.

These fixtures cover the three live Claude-canary loss paths as one generic
architecture seam: post-inventory finding producers must be registered once
and projected into every delivery consumer.  They intentionally contain no
protocol-specific expected finding.
"""
from __future__ import annotations

import base64
import hashlib
import json
import sys
from pathlib import Path

import pytest


SCRIPTS = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS))


def _inventory(*blocks: str) -> str:
    return "# Findings Inventory\n\n" + "\n\n".join(blocks) + "\n"


def _seed_inventory() -> str:
    return _inventory(
        "### Finding [INV-001]: Original candidate\n"
        "**Source IDs**: [BASE-1]\n"
        "**Severity**: High\n"
        "**Location**: src/Core.sol:L10\n"
        "**Description**: Original retained candidate."
    )


def _write(sp: Path, name: str, body: str) -> None:
    (sp / name).write_text(body, encoding="utf-8")


def _receipt(sp: Path) -> dict:
    return json.loads((sp / "finding_delivery_receipt.json").read_text(encoding="utf-8"))


def _queue_ids(sp: Path) -> set[str]:
    import plamen_validators as V

    V._write_mechanical_verification_queue_from_inventory(sp)
    return {
        row["finding id"]
        for row in V.parse_verification_queue_rows(sp)
    }


def test_registry_projects_every_enabled_producer_to_all_required_consumers():
    import finding_producer_registry as R

    assert R.validate_registry_projection_completeness() == []
    required = {
        "canonical_identity",
        "pre_dedup_promotion",
        "late_harvest",
        "containment",
        "resume_hashing",
        "human_review",
    }
    for key in (
        "exploration_skeptic",
        "foundry_invariant_fuzz",
        "depth_self_exclusion_reemit",
        "application_skeptic",
        "sibling_propagation",
        "medusa_fuzz",
        "trident_fuzz",
        "cargo_fuzz",
    ):
        producer = R.PRODUCERS_BY_KEY[key]
        assert required <= set(producer.required_consumers)
        for consumer in required:
            assert set(producer.artifact_patterns) <= set(
                R.producer_patterns(consumer)
            )


def test_driver_percontract_reemit_identity_is_owned_by_its_artifact_registry():
    import finding_producer_registry as R

    producer = R.producer_for_artifact("analysis_percontract_reemit.md")
    assert producer is not None
    assert producer.key == "rescan_and_per_contract"
    assert R.producer_accepts_current_local_id(producer, "PCRE-1")


def test_synthetic_registration_fails_when_one_projection_is_stale():
    import finding_producer_registry as R

    synthetic = R.FindingProducer(
        key="synthetic",
        artifact_patterns=("synthetic_findings.md",),
        local_id_patterns=(r"SYN-\d+",),
        owner_phase="depth",
        required_consumers=frozenset(R.REQUIRED_DELIVERY_CONSUMERS),
    )
    stale = {
        consumer: R.producer_patterns(consumer)
        for consumer in R.REQUIRED_DELIVERY_CONSUMERS
    }
    issues = R.validate_registry_projection_completeness(
        producers=(*R.FINDING_PRODUCERS, synthetic),
        projections=stale,
    )
    assert issues
    assert any("synthetic" in issue for issue in issues)


def test_exploration_new_reaches_inventory_dedup_chain_and_verify(tmp_path: Path):
    import plamen_validators as V
    import plamen_mechanical as M

    _write(tmp_path, "findings_inventory.md", _seed_inventory())
    _write(
        tmp_path,
        "exploration_skeptic_findings.md",
        "# Exploration\n\n"
        "### Finding [SKEP-001]: Adjacent path retains stale state\n"
        "**Action**: NEW\n"
        "**Severity**: Medium\n"
        "**Location**: src/Module.sol:L44\n"
        "**Evidence Scope**: IN_SCOPE_SOURCE\n"
        "**Description**: A sibling transition fails to refresh state and allows inconsistent accounting.\n\n"
        "## Coverage Record\n\n"
        "| Finding | Axis | Instance | Disposition | Evidence |\n"
        "|---|---|---|---|---|\n"
        "| BASE-1 | Neighbour | sibling transition | GAP-FILLED | SKEP-001 |\n",
    )

    assert V._promote_depth_findings_to_inventory(tmp_path) == ["SKEP-001"]
    inv = (tmp_path / "findings_inventory.md").read_text(encoding="utf-8")
    assert "SKEP-001" in inv
    assert "Coverage Record" not in inv
    assert V._compute_dedup_candidate_blocks(tmp_path) >= 0
    focus = tmp_path / "dedup_focus_inventory.md"
    assert "SKEP-001" in inv
    if focus.exists():
        assert "SKEP-001" in focus.read_text(
            encoding="utf-8", errors="replace"
        )
    # The canonical chain prompt consumes findings_inventory.md directly; the
    # compact sidecar contains only optional producer-authored Chain Summaries.
    chain_contract = (
        Path(__file__).resolve().parents[1]
        / "rules" / "phase4c-chain-prompt.md"
    ).read_text(encoding="utf-8", errors="replace")
    assert "findings_inventory.md" in chain_contract
    assert len(_queue_ids(tmp_path)) == 2


def test_exploration_upgrade_is_target_bound_and_bridge_cannot_downgrade(tmp_path: Path):
    import plamen_validators as V

    _write(tmp_path, "findings_inventory.md", _seed_inventory())
    _write(
        tmp_path,
        "exploration_skeptic_findings.md",
        "### Finding [SKEP-002]: Existing impact is broader\n"
        "**Action**: UPGRADE\n"
        "**Target ID**: INV-001\n"
        "**Severity**: Low\n"
        "**Location**: src/Core.sol:L10\n"
        "**Evidence Scope**: IN_SCOPE_SOURCE\n"
        "**Description**: The confirmed mechanism reaches an additional terminal impact.\n",
    )

    assert V._promote_depth_findings_to_inventory(tmp_path) == ["SKEP-002"]
    inv = (tmp_path / "findings_inventory.md").read_text(encoding="utf-8")
    assert inv.count("### Finding [INV-") == 2
    assert "**Action Kind**: UPGRADE" in inv
    assert "**Target ID**: INV-001" in inv
    amendment = inv.split("SKEP-002", 1)[1]
    assert "**Severity**: High" in amendment
    row = _receipt(tmp_path)["actions"][0]
    assert row["target_id"] == "INV-001"
    assert row["disposition"] == "PROMOTED_AMENDMENT"


def test_exploration_reopen_retains_negative_target_and_reaches_verify(tmp_path: Path):
    import plamen_validators as V

    _write(tmp_path, "findings_inventory.md", _seed_inventory())
    _write(
        tmp_path,
        "skeptic_judge_decisions.md",
        "| Finding | Decision | Rationale |\n|---|---|---|\n"
        "| INV-001 | REFUTED | prior negative decision |\n",
    )
    _write(
        tmp_path,
        "exploration_skeptic_findings.md",
        "### Finding [SKEP-003]: Prior negative omitted a reachable branch\n"
        "**Action**: RE-OPEN\n"
        "**Target ID**: INV-001\n"
        "**Severity**: High\n"
        "**Location**: src/Core.sol:L18\n"
        "**Evidence Scope**: IN_SCOPE_SOURCE\n"
        "**Description**: The prior negative did not evaluate a reachable state transition.\n",
    )

    assert V._promote_depth_findings_to_inventory(tmp_path) == ["SKEP-003"]
    assert "prior negative decision" in (
        tmp_path / "skeptic_judge_decisions.md"
    ).read_text(encoding="utf-8")
    assert len(_queue_ids(tmp_path)) == 2
    assert _receipt(tmp_path)["actions"][0]["action_kind"] == "RE-OPEN"


def test_exploration_legacy_substantive_heading_retained_but_coverage_rows_are_not(tmp_path: Path):
    import plamen_validators as V

    _write(tmp_path, "findings_inventory.md", _seed_inventory())
    _write(
        tmp_path,
        "exploration_skeptic_findings.md",
        "## Adjacent path finding\n"
        "**Severity**: Medium\n"
        "**Location**: src/Module.sol:L91\n"
        "**Description**: A paired operation omits a state update and creates inconsistent accounting.\n\n"
        "## Coverage Record\n"
        "| Finding | Axis | Instance | Disposition | Evidence |\n"
        "|---|---|---|---|---|\n"
        "| BASE-1 | Direction | inverse | GAP-FILLED | SKEP-999 |\n",
    )

    promoted = V._promote_depth_findings_to_inventory(tmp_path)
    assert len(promoted) == 1
    assert promoted[0].startswith("SKEP-LEGACY-")
    inv = (tmp_path / "findings_inventory.md").read_text(encoding="utf-8")
    assert "Adjacent path finding" in inv
    assert "SKEP-999" not in inv


def test_exploration_zero_action_is_clean_and_parser_drift_is_loud(tmp_path: Path):
    import plamen_validators as V

    _write(tmp_path, "findings_inventory.md", _seed_inventory())
    _write(
        tmp_path,
        "exploration_skeptic_findings.md",
        "# Exploration\n\nNo new, upgraded, or re-opened findings.\n\n"
        "| Finding | Axis | Instance | Disposition | Evidence |\n"
        "|---|---|---|---|---|\n"
        "| BASE-1 | Direction | forward | NO-GAP | src/Core.sol:L10 |\n",
    )
    assert V._promote_depth_findings_to_inventory(tmp_path) == []
    assert _receipt(tmp_path)["status"] == "CLEAN"

    _write(
        tmp_path,
        "exploration_skeptic_findings.md",
        "### Finding [SKEP-077]\n**Action**: NEW\n",
    )
    V._promote_depth_findings_to_inventory(tmp_path)
    receipt = _receipt(tmp_path)
    assert receipt["status"] == "DEGRADED"
    assert receipt["residual_debt"]
    debt = (tmp_path / "report_semantic_finding_delivery.md").read_text(
        encoding="utf-8"
    )
    assert "SKEP-077" in debt


def test_delivery_is_byte_idempotent_on_resume(tmp_path: Path):
    import plamen_validators as V

    _write(tmp_path, "findings_inventory.md", _seed_inventory())
    _write(
        tmp_path,
        "exploration_skeptic_findings.md",
        "### Finding [SKEP-004]: Retained candidate\n"
        "**Action**: NEW\n**Severity**: Medium\n"
        "**Location**: src/Module.sol:L20\n"
        "**Description**: A missing state transition can leave inconsistent accounting.\n",
    )
    assert V._promote_depth_findings_to_inventory(tmp_path) == ["SKEP-004"]
    before = {
        name: (tmp_path / name).read_bytes()
        for name in (
            "findings_inventory.md",
            "finding_delivery_receipt.json",
            "finding_delivery_receipt.md",
            "depth_promotion_receipt.md",
        )
    }
    assert V._promote_depth_findings_to_inventory(tmp_path) == []
    after = {name: (tmp_path / name).read_bytes() for name in before}
    assert after == before


def test_foundry_violation_preserves_related_identity_and_proof_scope(tmp_path: Path):
    import plamen_validators as V

    _write(tmp_path, "findings_inventory.md", _seed_inventory())
    _write(
        tmp_path,
        "invariant_fuzz_results.md",
        "### Finding [FUZZ-1]: Invariant mechanism violated\n"
        "**Severity**: High\n"
        "**Location**: test/Invariant.t.sol:L88\n"
        "**Related Finding**: INV-001\n"
        "**Evidence Scope**: MECHANISM_ONLY\n"
        "**Proof Scope**: STATE_TRANSITION_ONLY\n"
        "**Description**: Executed invariant falsification demonstrates a state-transition mismatch.\n",
    )

    assert V._promote_depth_findings_to_inventory(tmp_path) == ["FUZZ-1"]
    inv = (tmp_path / "findings_inventory.md").read_text(encoding="utf-8")
    assert "**Related Finding**: INV-001" in inv
    assert "**Evidence Scope**: MECHANISM_ONLY" in inv
    assert "**Proof Scope**: STATE_TRANSITION_ONLY" in inv
    assert "**Harm Confidence**: LOW" in inv
    assert len(_queue_ids(tmp_path)) == 2


def test_foundry_no_violation_is_clean_and_existing_fuzz_routes_unchanged(tmp_path: Path):
    import plamen_validators as V

    _write(tmp_path, "findings_inventory.md", _seed_inventory())
    _write(tmp_path, "invariant_fuzz_results.md", "# Invariant Fuzz\n\nNo violations found.\n")
    _write(
        tmp_path,
        "medusa_fuzz_findings.md",
        "### Finding [MEDUSA-1]: Sequence invariant violated\n"
        "**Severity**: Medium\n**Location**: test/Fuzz.sol:L30\n"
        "**Description**: An executed sequence leaves an inconsistent state transition.\n",
    )
    _write(
        tmp_path,
        "trident_fuzz_findings.md",
        "### Finding [FUZZ-2]: Program invariant violated\n"
        "**Severity**: Medium\n**Location**: fuzz/invariant.rs:L30\n"
        "**Description**: An executed sequence leaves an inconsistent state transition.\n",
    )
    _write(
        tmp_path,
        "cargo_fuzz_findings.md",
        "### Finding [FUZZ-3]: State machine invariant violated\n"
        "**Severity**: Medium\n**Location**: fuzz/state.rs:L30\n"
        "**Description**: An executed sequence leaves an inconsistent state transition.\n",
    )
    assert set(V._promote_depth_findings_to_inventory(tmp_path)) == {
        "MEDUSA-1", "FUZZ-2", "FUZZ-3"
    }
    assert _receipt(tmp_path)["status"] == "CLEAN"


def test_canonical_identity_without_delivery_receipt_is_not_delivery(tmp_path: Path):
    import plamen_mechanical as M
    import plamen_validators as V

    _write(tmp_path, "findings_inventory.md", _seed_inventory())
    _write(
        tmp_path,
        "invariant_fuzz_results.md",
        "### Finding [FUZZ-9]: Violation exists only in producer\n"
        "**Severity**: Medium\n**Location**: test/Invariant.t.sol:L99\n"
        "**Description**: The executed probe reaches an inconsistent transition.\n",
    )
    assert M._write_canonical_finding_identity_map(tmp_path) >= 1
    issues = V._validate_registered_finding_delivery_receipt(tmp_path)
    assert issues
    assert any("FUZZ-9" in issue for issue in issues)


def test_dxre_content_bearing_promotes_but_content_less_is_methodology_debt(tmp_path: Path):
    import plamen_validators as V
    import plamen_mechanical as M

    _write(tmp_path, "findings_inventory.md", _seed_inventory())
    _write(
        tmp_path,
        "depth_selfexcl_reemit_findings.md",
        "### Finding [DXRE-1]: Concrete self-excluded candidate\n"
        "**Verdict**: CONTESTED\n**Severity**: Medium\n"
        "**Location**: src/Module.sol:L73\n"
        "**Source Identity**: depth_edge_case_findings.md:DX-7\n"
        "**Description**: A concrete missing guard can leave inconsistent accounting.\n\n"
        "### Review Disposition [DXRE-2]: Content-less self-exclusion stub\n"
        "**Source Identity**: depth_state_trace_findings.md:DS-4\n"
        "**Disposition**: CONTENT_LESS_HUMAN_REVIEW\n"
        "**Reason**: The recovered row has no concrete location or harm and cannot become a vulnerability finding.\n",
    )

    assert V._promote_depth_findings_to_inventory(tmp_path) == ["DXRE-1"]
    inv = (tmp_path / "findings_inventory.md").read_text(encoding="utf-8")
    assert "DXRE-1" in inv
    assert "DXRE-2" not in inv
    receipt = _receipt(tmp_path)
    rows = {row["action_id"]: row for row in receipt["actions"]}
    assert rows["DXRE-1"]["disposition"] == "PROMOTED_FINDING"
    assert rows["DXRE-2"]["disposition"] == "HUMAN_REVIEW"
    appendix = M._build_human_review_appendix(tmp_path)
    assert "Content-less self-exclusion stub" in appendix
    assert "depth_state_trace_findings.md:DS-4" in appendix
    assert len(_queue_ids(tmp_path)) == 2


def test_dxre_malformed_heading_is_loud_and_mixed_rows_reconcile_exactly(tmp_path: Path):
    import plamen_validators as V

    _write(tmp_path, "findings_inventory.md", _seed_inventory())
    _write(
        tmp_path,
        "depth_selfexcl_reemit_findings.md",
        "### Finding [DXRE-1]: Concrete candidate\n"
        "**Severity**: Low\n**Location**: src/Module.sol:L7\n"
        "**Description**: A concrete state mismatch remains reachable.\n\n"
        "### Review Disposition [DXRE-2]: No concrete candidate\n"
        "**Source Identity**: depth_edge_case_findings.md:DE-8\n"
        "**Disposition**: CONTENT_LESS_HUMAN_REVIEW\n"
        "**Reason**: no concrete location or harm\n\n"
        "### Finding [DXRE-BROKEN]\n",
    )
    V._promote_depth_findings_to_inventory(tmp_path)
    receipt = _receipt(tmp_path)
    assert receipt["source_action_count"] == 3
    assert receipt["accounted_action_count"] == 2
    assert receipt["status"] == "DEGRADED"
    assert any("DXRE-BROKEN" in row for row in receipt["residual_debt"])


def test_late_harvest_independently_sees_registered_exploration_block(tmp_path: Path):
    import plamen_mechanical as M

    _write(tmp_path, "report_index_coverage_seed.md", "# Seed\n\n(no covered IDs)\n")
    _write(tmp_path, "findings_inventory.md", _seed_inventory())
    _write(
        tmp_path,
        "exploration_skeptic_findings.md",
        "### Finding [SKEP-008]: Deliberately unpromoted candidate\n"
        "**Severity**: Medium\n"
        "**Location**: src/Module.sol:L120\n"
        "**Description**: A missing validation allows an inconsistent state transition with material impact.\n",
    )
    orphans = M.compute_promotion_orphans(tmp_path)
    assert any(row.get("orig_id") == "SKEP-008" for row in orphans)


def test_registry_drives_identity_containment_late_harvest_and_resume_projection():
    import finding_producer_registry as R
    import plamen_mechanical as M
    import plamen_validators as V

    canonical = set(M._CANONICAL_ID_PRODUCER_PATTERNS)
    late = set(M._PROMO_FEEDER_GLOBS)
    owned = V._owned_artifact_patterns("sc")
    for producer in (
        R.PRODUCERS_BY_KEY["exploration_skeptic"],
        R.PRODUCERS_BY_KEY["foundry_invariant_fuzz"],
        R.PRODUCERS_BY_KEY["depth_self_exclusion_reemit"],
        R.PRODUCERS_BY_KEY["application_skeptic"],
    ):
        assert set(producer.artifact_patterns) <= canonical
        assert set(producer.artifact_patterns) <= late
        assert set(producer.artifact_patterns) <= set(
            owned[producer.owner_phase]
        )
        assert set(producer.artifact_patterns) <= set(
            R.producer_patterns("resume_hashing")
        )


def test_application_skeptic_typed_proposal_projects_low_confidence_and_delivers(
    tmp_path: Path,
):
    import finding_producer_registry as R
    import plamen_validators as V

    _write(tmp_path, "findings_inventory.md", _seed_inventory())
    unsigned = {
        "schema_version": "plamen.finding_candidate_proposal.v1",
        "producer": "application_skeptic",
        "source_obligation_id": "OBL-1",
        "source_work_item_id": "ASW-" + "B" * 24,
        "assessor_identity": "independent-skeptic",
        "assessor_invocation_id": "independent-call",
        "assessor_evidence_sha256": "e" * 64,
        "candidate": {
            "title": "Independent review disputes a negative disposition",
            "mechanism": "The cited guard does not cover an alternate transition.",
            "harm": "State-dependent value may be processed inconsistently.",
        },
    }
    proposal_digest = R.canonical_digest(unsigned)
    proposal = {
        **unsigned,
        "proposal_id": "ASCP-" + proposal_digest[:24].upper(),
        "proposal_digest": proposal_digest,
    }
    mapping = R.write_application_skeptic_proposal_projection(
        tmp_path, [proposal]
    )
    assert mapping == {proposal["proposal_id"]: "ASKP-1"}
    assert V._promote_depth_findings_to_inventory(tmp_path) == ["ASKP-1"]
    inv = (tmp_path / "findings_inventory.md").read_text(encoding="utf-8")
    assert "**Proof Scope**: LOW_CONFIDENCE_ANALYTICAL_CANDIDATE" in inv
    assert "**Harm Confidence**: LOW" in inv
    assert proposal["proposal_id"] in inv
    assert "OBL-1" in inv
    assert len(_queue_ids(tmp_path)) == 2


# Exact producer prefixes currently emitted by the checked-in skill contracts.
# This fixture is deliberately independent of the runtime manifest: an omitted
# producer must make the test red instead of disappearing from both sides of a
# self-referential equality check.
CURRENTLY_EMITTED_PRODUCER_PREFIXES = (
    "AA", "AL", "AV", "BLS", "CBS", "CCT", "CFG", "CM", "CMI",
    "COS", "CPI", "CR", "CS", "CT", "CU", "DA", "DEP", "DEX",
    "EDA", "EPA", "EVT", "EX", "FA", "FC", "FL", "GCI", "GO",
    "GOV", "HF", "IBC", "IHR", "II", "LC", "LEND", "MG", "MP",
    "MSS", "NFT", "OD", "OF", "OO", "P2P", "PDA", "PSC", "PTB",
    "PV", "RPC", "RS", "SAF", "SC", "SGI", "SIG", "SL", "SLS",
    "SPEC", "SS", "SSC", "ST", "STR", "T22", "TF", "TPS", "TXI",
    "VA", "VL", "WED", "XE", "ZS",
)


def test_every_current_emitted_prefix_has_registry_parser_mechanical_parity():
    import finding_producer_registry as R
    import plamen_mechanical as M
    import plamen_parsers as P

    niche = R.PRODUCERS_BY_KEY["niche"]
    assert R.CURRENT_PRODUCER_ID_PREFIXES == CURRENTLY_EMITTED_PRODUCER_PREFIXES
    assert len(R.PRODUCER_ID_PREFIXES) == len(set(R.PRODUCER_ID_PREFIXES))
    for prefix in CURRENTLY_EMITTED_PRODUCER_PREFIXES:
        finding_id = f"{prefix}-1"
        assert R.producer_accepts_current_local_id(niche, finding_id), prefix
        assert finding_id in P._extract_finding_ids_from_text(finding_id), prefix
        heading = f"## Finding [{finding_id}]: emitted prefix"
        match = M._NICHE_FINDING_HEADING_RE.fullmatch(heading)
        assert match is not None and match.group("bracket_id") == finding_id, prefix


def test_normalized_producer_id_grammar_types_unknown_and_malformed_debt():
    import finding_producer_registry as R

    known = R.classify_producer_id("sc-007")
    assert known.normalized_id == "SC-007"
    assert known.status == "REGISTERED"
    assert known.identity_debt == ""
    assert known.identity_authority is False

    unknown = R.classify_producer_id("ZZQ-7")
    assert unknown.normalized_id == "ZZQ-7"
    assert unknown.status == "UNKNOWN_WELL_FORMED"
    assert unknown.identity_debt == "UNKNOWN_PRODUCER_PREFIX"
    assert unknown.identity_authority is False

    malformed_near_misses = (
        "SC1", "-1", "SC-", "SC--1", "SC-A", "S_C-1", "SC-1x",
        "1SC-1", "SC- 1", "SC-+1", "SC-١",
    )
    for value in malformed_near_misses:
        debt = R.classify_producer_id(value)
        assert debt.status == "MALFORMED", value
        assert debt.identity_debt == "MALFORMED_PRODUCER_ID", value
        assert debt.identity_authority is False


def test_unknown_and_malformed_explicit_findings_are_retained_as_typed_debt(
    tmp_path: Path,
):
    import plamen_mechanical as M
    import plamen_parsers as P

    body = (
        "## Finding [ZZQ-7]: unknown but normalized\n"
        "**Severity**: Medium\n"
        "**Location**: src/Module.sol:L7\n"
        "**Description**: An explicit unknown producer identity remains visible.\n\n"
        "## Finding [SC--1]: malformed identity\n"
        "**Severity**: Medium\n"
        "**Location**: src/Module.sol:L8\n"
        "**Description**: An explicit malformed producer identity remains visible.\n"
    )
    path = tmp_path / "niche_unknown_findings.md"
    _write(tmp_path, path.name, body)

    parser_rows = {row["id"]: row for row in P._parse_depth_finding_blocks(path)}
    assert parser_rows["ZZQ-7"]["_identity_debt"] == "UNKNOWN_PRODUCER_PREFIX"
    assert parser_rows["SC--1"]["_identity_debt"] == "MALFORMED_PRODUCER_ID"
    assert all(
        row["_identity_quarantine"] == "true"
        and row["_identity_authority"] == "false"
        and row["_content_bearing"] == "false"
        for row in parser_rows.values()
    )

    mechanical_rows = {
        row["source_id"]: row for row in M._parse_niche_findings(tmp_path)
    }
    assert mechanical_rows["ZZQ-7"]["identity_debt"] == "UNKNOWN_PRODUCER_PREFIX"
    assert mechanical_rows["SC--1"]["identity_debt"] == "MALFORMED_PRODUCER_ID"
    assert all(
        row["identity_quarantine"] == "true"
        and row["identity_authority"] == "false"
        for row in mechanical_rows.values()
    )

    _write(tmp_path, "findings_inventory.md", _seed_inventory())
    assert M.promote_niche_to_inventory(tmp_path) == (2, 0)
    inventory = (tmp_path / "findings_inventory.md").read_text(encoding="utf-8")
    assert "ZZQ-7" not in inventory
    assert "SC--1" not in inventory
    receipt = (tmp_path / "niche_promotion_receipt.md").read_text(
        encoding="utf-8"
    )
    assert "ZZQ-7 | status=UNKNOWN_WELL_FORMED" in receipt
    assert "debt=UNKNOWN_PRODUCER_PREFIX" in receipt
    assert "SC--1 | status=MALFORMED" in receipt
    assert "debt=MALFORMED_PRODUCER_ID" in receipt
    assert "authority=false | quarantine=true" in receipt
    debt_payload = M.read_niche_identity_debt_sidecar(tmp_path)
    assert debt_payload is not None
    debt_records = {row["raw_id"]: row for row in debt_payload["candidates"]}
    assert debt_records["ZZQ-7"]["normalized_id"] == "ZZQ-7"
    assert debt_records["SC--1"]["normalized_id"] == ""
    assert debt_payload["clean_authority"] is False


def test_niche_identity_debt_sidecar_is_exact_source_bound_and_retry_stable(
    tmp_path: Path,
):
    import plamen_mechanical as M

    _write(tmp_path, "findings_inventory.md", _seed_inventory())
    source_path = tmp_path / "niche_unknown_findings.md"
    source_v1 = (
        "## Finding [ZZQ-7]: exact debt candidate\n"
        "**Severity**: Medium\n"
        "**Location**: src/Module.sol:L7\n"
        "**Description**: Preserve this exact UTF-8 body: café.\n"
        "**Impact**: Candidate loss would create a recall gap.\n"
    ).encode("utf-8")
    source_path.write_bytes(source_v1)

    assert M.promote_niche_to_inventory(tmp_path) == (1, 0)
    sidecar_path = tmp_path / "niche_identity_debt.json"
    first_bytes = sidecar_path.read_bytes()
    first = json.loads(first_bytes)
    assert M.read_niche_identity_debt_sidecar(tmp_path) == first
    assert first["schema_version"] == "plamen.niche_identity_debt.v2"
    assert first["denominator_complete"] is True
    assert first["action_count"] == 1
    assert first["actions"][0]["normalized_local_id"] == "ZZQ-7"
    assert first["blocking_debt_count"] == 1
    assert first["clean_authority"] is False
    assert first["proof_authority"] == "NONE"
    assert first["drop_authority"] is False
    record_v1 = first["candidates"][0]
    assert record_v1["source_file"] == source_path.name
    assert record_v1["source_sha256"] == hashlib.sha256(source_v1).hexdigest()
    assert record_v1["source_byte_start"] == 0
    assert record_v1["source_byte_end"] == len(source_v1)
    assert record_v1["raw_id"] == "ZZQ-7"
    assert record_v1["normalized_id"] == "ZZQ-7"
    assert record_v1["identity_status"] == "UNKNOWN_WELL_FORMED"
    assert record_v1["identity_debt"] == "UNKNOWN_PRODUCER_PREFIX"
    assert record_v1["required_action"] == "RECONCILE_PRODUCER_IDENTITY"
    assert record_v1["identity_authority"] is False
    assert record_v1["proof_authority"] == "NONE"
    assert record_v1["drop_authority"] is False
    captured_v1 = base64.b64decode(record_v1["exact_block_bytes_b64"])
    assert captured_v1 == source_v1
    assert record_v1["source_block_sha256"] == hashlib.sha256(source_v1).hexdigest()

    # An unchanged retry must be byte-for-byte idempotent.
    assert M.promote_niche_to_inventory(tmp_path) == (1, 0)
    assert sidecar_path.read_bytes() == first_bytes

    # A source mutation creates a new live-bound candidate while immutable
    # lifecycle history retains the removed action as blocking tombstone debt.
    # The compatibility projection therefore carries one current candidate and
    # one removal error; the CAS retains the full ordered union.
    source_v2 = source_v1.replace(b"recall gap", b"tampered recall gap")
    source_path.write_bytes(source_v2)
    assert M.promote_niche_to_inventory(tmp_path) == (1, 0)
    second_bytes = sidecar_path.read_bytes()
    second = json.loads(second_bytes)
    assert second["blocking_debt_count"] == 2
    assert second["candidate_count"] == 1
    removed = [
        row for row in second["source_errors"]
        if row["status"] == "SOURCE_ACTION_REMOVED"
    ]
    assert len(removed) == 1
    assert removed[0]["source_sha256"] == hashlib.sha256(source_v1).hexdigest()
    assert {
        row["source_sha256"] for row in second["candidates"]
    } == {hashlib.sha256(source_v2).hexdigest()}
    assert {
        base64.b64decode(row["exact_block_bytes_b64"])
        for row in second["candidates"]
    } == {source_v2}
    assert all(
        row["clean_authority"] is False
        and row["proof_authority"] == "NONE"
        and row["drop_authority"] is False
        for row in second["candidates"]
    )
    assert M.promote_niche_to_inventory(tmp_path) == (1, 0)
    assert sidecar_path.read_bytes() == second_bytes


def test_niche_identity_debt_sidecar_does_not_depend_on_inventory_availability(
    tmp_path: Path,
):
    import plamen_mechanical as M

    source = (
        "## Finding [SC--1]: debt before inventory\n"
        "**Severity**: Medium\n"
        "**Location**: src/Module.sol:L8\n"
        "**Description**: Preserve the candidate even without inventory.\n"
        "**Impact**: Otherwise retry state can silently lose the candidate.\n"
    )
    _write(tmp_path, "niche_unknown_findings.md", source)
    assert M.promote_niche_to_inventory(tmp_path) == (1, 0)
    payload = M.read_niche_identity_debt_sidecar(tmp_path)
    assert payload is not None
    assert payload["blocking_debt_count"] == 1
    assert payload["candidates"][0]["raw_id"] == "SC--1"
    assert payload["candidates"][0]["identity_debt"] == "MALFORMED_PRODUCER_ID"


def test_inventory_floor_excludes_non_authoritative_identity_rows(tmp_path: Path):
    import plamen_mechanical as M

    _write(
        tmp_path,
        "niche_floor_findings.md",
        "## Finding [SC-1]: eligible registered candidate\n"
        "**Severity**: Medium\n"
        "**Location**: src/Module.sol:L1\n"
        "**Description**: This registered candidate is substantive.\n\n"
        "## Finding [ZZQ-7]: unknown candidate\n"
        "**Severity**: Medium\n"
        "**Location**: src/Module.sol:L2\n"
        "**Description**: Unknown identity must remain quarantined.\n\n"
        "## Finding [SC--1]: malformed candidate\n"
        "**Severity**: Medium\n"
        "**Location**: src/Module.sol:L3\n"
        "**Description**: Malformed identity must remain quarantined.\n\n"
        "## Finding [SC-2]: content-less methodology row\n"
        "**Severity**: Medium\n"
        "**Location**: src/Module.sol:L4\n"
        "**Description**: CONTENT_LESS_HUMAN_REVIEW.\n",
    )
    _write(
        tmp_path,
        "findings_inventory_chunk_identity_debt.md",
        "### Finding [SC--9]: malformed chunk identity\n"
        "**Severity**: Medium\n"
        "**Location**: src/Chunk.sol:L1\n"
        "**Source IDs**: SC--9\n"
        "**Description**: A structured shape cannot legitimize malformed identity.\n\n"
        "### Finding [AC-9]: registered local but unknown provenance\n"
        "**Severity**: Medium\n"
        "**Location**: src/Chunk.sol:L2\n"
        "**Source IDs**: ZZQ-9\n"
        "**Description**: Unknown provenance makes the entire row identity debt.\n",
    )

    assert M.ensure_findings_inventory_floor(tmp_path)[0] == 1
    inventory = (tmp_path / "findings_inventory.md").read_text(encoding="utf-8")
    assert "SC-1" in inventory
    assert "ZZQ-7" not in inventory
    assert "SC--1" not in inventory
    assert "SC-2" not in inventory
    assert "SC--9" not in inventory
    assert "AC-9" not in inventory
    assert "ZZQ-9" not in inventory


def test_shared_explicit_heading_and_field_parser_has_no_debt_split(
    tmp_path: Path,
):
    import plamen_mechanical as M
    import plamen_parsers as P

    path = tmp_path / "niche_format_findings.md"
    _write(
        tmp_path,
        path.name,
        "## finding [zzq-7] colonless lowercase title\n"
        "**severity** medium\n"
        "**location** src/Module.sol:L7\n"
        "**description** lowercase colonless fields stay visible\n\n"
        "### [SC--1] - canonical bracket variant\n"
        "Severity Medium\n"
        "Location src/Module.sol:L8\n"
        "Description canonical colonless fields stay visible\n\n"
        "#### FINDING ZZQ-8 bare colonless variant\n"
        "Severity: Low\n"
        "Location: src/Module.sol:L9\n"
        "Description: bare explicit findings stay visible\n",
    )

    parser_rows = {row["id"]: row for row in P._parse_depth_finding_blocks(path)}
    mechanical_rows = {
        row["source_id"]: row for row in M._parse_niche_findings(tmp_path)
    }
    assert set(parser_rows) == {"ZZQ-7", "SC--1", "ZZQ-8"}
    assert set(mechanical_rows) == set(parser_rows)
    assert all(row["_identity_debt"] for row in parser_rows.values())
    assert all(row["identity_debt"] for row in mechanical_rows.values())
    assert mechanical_rows["ZZQ-7"]["description"].startswith("lowercase")
    assert mechanical_rows["SC--1"]["description"].startswith("canonical")


def test_eip_compatibility_identity_is_registered_debt_free_everywhere(
    tmp_path: Path,
):
    import finding_producer_registry as R
    import plamen_mechanical as M
    import plamen_parsers as P

    path = tmp_path / "niche_compat_findings.md"
    _write(
        tmp_path,
        path.name,
        "## [eip-20] compatibility candidate\n"
        "severity medium\n"
        "location src/Module.sol:L20\n"
        "description historical producer identity remains registered\n",
    )
    niche = R.PRODUCERS_BY_KEY["niche"]
    classified = R.classify_producer_id("eip-20", producer=niche)
    assert classified.normalized_id == "EIP-20"
    assert classified.status == "REGISTERED"
    assert classified.identity_debt == ""

    parser_row = P._parse_depth_finding_blocks(path)[0]
    mechanical_row = M._parse_niche_findings(tmp_path)[0]
    assert parser_row["id"] == mechanical_row["source_id"] == "EIP-20"
    assert parser_row["_identity_status"] == "REGISTERED"
    assert parser_row["_identity_debt"] == ""
    assert mechanical_row["identity_status"] == "REGISTERED"
    assert mechanical_row["identity_debt"] == ""

    _write(tmp_path, "findings_inventory.md", _seed_inventory())
    assert M.promote_niche_to_inventory(tmp_path) == (1, 1)
    debt = M.read_niche_identity_debt_sidecar(tmp_path)
    assert debt is not None
    assert debt["candidate_count"] == debt["blocking_debt_count"] == 0


def test_niche_oversize_source_is_bounded_and_published_as_visible_debt(
    tmp_path: Path,
):
    import plamen_mechanical as M

    _write(tmp_path, "findings_inventory.md", _seed_inventory())
    source_path = tmp_path / "niche_oversize_findings.md"
    source_path.write_bytes(b"x" * (M._NICHE_FINDING_ARTIFACT_MAX_BYTES + 1))
    with pytest.raises(RuntimeError, match="SOURCE_OVER_LIMIT"):
        M.promote_niche_to_inventory(tmp_path)
    payload = M.read_niche_identity_debt_sidecar(tmp_path)
    assert payload is not None
    assert payload["schema_version"] == "plamen.niche_identity_debt.v2"
    assert payload["denominator_complete"] is True
    assert payload["action_count"] == 0
    assert payload["actions"] == []
    assert payload["candidate_count"] == 0
    assert payload["source_error_count"] == 1
    assert payload["blocking_debt_count"] == 1
    error = payload["source_errors"][0]
    assert error["source_file"] == source_path.name
    assert error["status"] == "SOURCE_OVER_LIMIT"
    assert error["required_action"] == "REDUCE_AND_REVIEW_SOURCE_ARTIFACT"
    assert error["clean_authority"] is False
    assert error["proof_authority"] == "NONE"
    assert error["drop_authority"] is False
    assert (tmp_path / "niche_identity_debt.json").stat().st_size <= (
        M._NICHE_IDENTITY_DEBT_SIDECAR_MAX_BYTES
    )


def test_niche_oversize_block_uses_bounded_semantics_and_digest_metadata(
    tmp_path: Path,
):
    import plamen_mechanical as M

    _write(tmp_path, "findings_inventory.md", _seed_inventory())
    description = "x" * (M._NICHE_IDENTITY_DEBT_EXACT_BLOCK_MAX_BYTES + 1024)
    _write(
        tmp_path,
        "niche_large_block_findings.md",
        "## Finding [ZZQ-99]: bounded debt\n"
        "Severity: Medium\n"
        "Location: src/Large.sol:L1\n"
        f"Description: {description}\n"
        "Impact: bounded capture must remain reviewable\n",
    )
    assert M.promote_niche_to_inventory(tmp_path) == (1, 0)
    payload = M.read_niche_identity_debt_sidecar(tmp_path)
    assert payload is not None
    record = payload["candidates"][0]
    assert record["exact_block_capture"] == "OMITTED_OVERSIZE"
    assert record["exact_block_bytes_b64"] == ""
    assert record["description_truncated"] is True
    assert record["description_utf8_bytes"] == len(description.encode("utf-8"))
    assert record["description_sha256"] == hashlib.sha256(
        description.encode("utf-8")
    ).hexdigest()
    assert len(record["description"].encode("utf-8")) <= (
        M._NICHE_IDENTITY_DEBT_SEMANTIC_FIELD_MAX_BYTES
    )
    assert (tmp_path / "niche_identity_debt.json").stat().st_size <= (
        M._NICHE_IDENTITY_DEBT_SIDECAR_MAX_BYTES
    )


def test_niche_processor_always_publishes_validated_zero_debt_state(
    tmp_path: Path,
):
    import plamen_mechanical as M

    _write(tmp_path, "findings_inventory.md", _seed_inventory())
    assert M.promote_niche_to_inventory(tmp_path) == (0, 0)
    path = tmp_path / "niche_identity_debt.json"
    assert path.exists()
    payload = M.read_niche_identity_debt_sidecar(tmp_path)
    assert payload is not None
    assert payload["candidate_count"] == 0
    assert payload["source_error_count"] == 0
    assert payload["blocking_debt_count"] == 0


def test_niche_same_source_local_id_content_drift_is_blocking_debt(
    tmp_path: Path,
):
    import plamen_mechanical as M

    _write(tmp_path, "findings_inventory.md", _seed_inventory())
    source = tmp_path / "niche_drift_findings.md"
    source.write_text(
        "## Finding [SC-1]: first source action\n"
        "**Severity**: Medium\n"
        "**Location**: src/Module.sol:L11\n"
        "**Description**: The first exact source action remains reachable.\n",
        encoding="utf-8",
    )

    assert M.promote_niche_to_inventory(tmp_path) == (1, 1)
    first = M.read_niche_identity_debt_sidecar(tmp_path)
    assert first is not None
    assert first["schema_version"] == "plamen.niche_identity_debt.v2"
    assert first["action_count"] == 1
    assert first["blocking_debt_count"] == 0
    first_action = first["actions"][0]
    assert first_action["source_file"] == source.name
    assert first_action["normalized_local_id"] == "SC-1"
    assert first_action["source_byte_start"] == 0
    assert first_action["source_byte_end"] == len(source.read_bytes())
    assert first_action["source_action_identity"].startswith("NACT-")
    inventory = (tmp_path / "findings_inventory.md").read_text(encoding="utf-8")
    assert first_action["source_action_identity"] in inventory

    source.write_text(
        "## Finding [SC-1]: changed source action\n"
        "**Severity**: High\n"
        "**Location**: src/Module.sol:L19\n"
        "**Description**: Mutated bytes must never inherit stale delivery.\n",
        encoding="utf-8",
    )
    assert M.promote_niche_to_inventory(tmp_path) == (1, 0)
    second = M.read_niche_identity_debt_sidecar(tmp_path)
    assert second is not None
    assert second["action_count"] == 1
    assert second["blocking_debt_count"] >= 1
    assert second["clean_authority"] is False
    assert second["actions"][0]["source_action_identity"] != first_action[
        "source_action_identity"
    ]
    assert any(
        row["identity_debt"] == "SOURCE_ACTION_CONTENT_DRIFT"
        for row in second["candidates"]
    )


def test_niche_canonical_block_parser_matches_general_unadorned_and_html(
    tmp_path: Path,
):
    import plamen_mechanical as M
    import plamen_parsers as P

    path = tmp_path / "niche_normalized_findings.md"
    _write(
        tmp_path,
        path.name,
        "## SC-3 unadorned registered action\n"
        "Severity: Medium\n"
        "Location: src/Module.sol:L3\n"
        "Description: The context-free registered grammar is canonical.\n\n"
        "## F&#105;nding [ZZQ-4]: normalized explicit debt action\n"
        "Severity: Low\n"
        "Location: src/Module.sol:L4\n"
        "Description: HTML normalization cannot hide an action from the sidecar.\n",
    )

    general = {row["id"] for row in P._parse_depth_finding_blocks(path)}
    niche = {row["source_id"] for row in M._parse_niche_findings(tmp_path)}
    assert general == niche == {"SC-3", "ZZQ-4"}

    _write(tmp_path, "findings_inventory.md", _seed_inventory())
    assert M.promote_niche_to_inventory(tmp_path) == (2, 1)
    sidecar = M.read_niche_identity_debt_sidecar(tmp_path)
    assert sidecar is not None
    assert sidecar["action_count"] == 2
    assert {row["normalized_local_id"] for row in sidecar["actions"]} == {
        "SC-3",
        "ZZQ-4",
    }
    raw = path.read_bytes()
    assert all(
        row["source_sha256"] == hashlib.sha256(raw).hexdigest()
        and row["source_block_sha256"]
        == hashlib.sha256(
            raw[row["source_byte_start"] : row["source_byte_end"]]
        ).hexdigest()
        for row in sidecar["actions"]
    )
    assert sidecar["blocking_debt_count"] == 1


def test_niche_same_local_id_from_two_sources_delivers_two_exact_actions(
    tmp_path: Path,
):
    import plamen_mechanical as M

    _write(tmp_path, "findings_inventory.md", _seed_inventory())
    for source_name, line in (
        ("niche_alpha_findings.md", 21),
        ("niche_beta_findings.md", 22),
    ):
        _write(
            tmp_path,
            source_name,
            "## Finding [SC-1]: source-local collision\n"
            "**Severity**: Medium\n"
            f"**Location**: src/Module.sol:L{line}\n"
            f"**Description**: Exact action emitted by {source_name}.\n",
        )

    assert M.promote_niche_to_inventory(tmp_path) == (2, 2)
    sidecar = M.read_niche_identity_debt_sidecar(tmp_path)
    assert sidecar is not None
    assert sidecar["action_count"] == 2
    identities = {
        row["source_action_identity"] for row in sidecar["actions"]
    }
    assert len(identities) == 2
    inventory = (tmp_path / "findings_inventory.md").read_text(encoding="utf-8")
    assert all(identity in inventory for identity in identities)
    assert inventory.count("SC-1 (niche-promoted from") == 2

    assert M.promote_niche_to_inventory(tmp_path) == (2, 0)
    receipt = (tmp_path / "niche_promotion_receipt.md").read_text(
        encoding="utf-8"
    )
    assert all(identity in receipt for identity in identities)


def test_niche_row_only_general_parser_action_is_in_denominator_and_drifts(
    tmp_path: Path,
):
    import plamen_mechanical as M
    import plamen_parsers as P

    _write(tmp_path, "findings_inventory.md", _seed_inventory())
    source = tmp_path / "niche_catalog_findings.md"
    original = (
        "# Niche Catalog\r\n\r\n"
        "| Finding ID | Location | Mechanism | Verdict | Severity |\r\n"
        "|---|---|---|---|---|\r\n"
        "| SC-41 | src/Guard.sol:L41 | alpha path bypasses guard | PARTIAL | Low |\r\n"
    ).encode("utf-8")
    source.write_bytes(original)

    general = P._parse_depth_finding_blocks(source)
    assert [row["id"] for row in general] == ["SC-41"]
    assert general[0]["_low_confidence_rowonly"] == "true"
    assert M.promote_niche_to_inventory(tmp_path) == (1, 1)
    first = M.read_niche_identity_debt_sidecar(tmp_path)
    assert first is not None
    assert first["action_count"] == 1
    assert first["blocking_debt_count"] == 0
    first_identity = first["actions"][0]["source_action_identity"]

    mutated = original.replace(b"alpha", b"omega")
    assert len(mutated) == len(original)
    source.write_bytes(mutated)
    with pytest.raises(RuntimeError, match="live source"):
        M.read_niche_identity_debt_sidecar(tmp_path)

    assert M.promote_niche_to_inventory(tmp_path) == (1, 0)
    second = M.read_niche_identity_debt_sidecar(tmp_path)
    assert second is not None
    assert second["action_count"] == 1
    assert second["blocking_debt_count"] >= 1
    assert second["actions"][0]["source_action_identity"] != first_identity
    assert second["actions"][0]["action_status"] == "DEBT"
    assert any(
        row["identity_debt"] == "SOURCE_ACTION_CONTENT_DRIFT"
        for row in second["candidates"]
    )


def test_niche_duplicate_row_only_occurrences_have_distinct_nonempty_ranges(
    tmp_path: Path,
):
    import plamen_mechanical as M
    import plamen_parsers as P

    _write(tmp_path, "findings_inventory.md", _seed_inventory())
    source = tmp_path / "niche_duplicate_findings.md"
    row = "| SC-42 | src/Guard.sol:L42 | exact duplicate row | PARTIAL | Low |\r\n"
    source.write_bytes(
        (
            "| Finding ID | Location | Mechanism | Verdict | Severity |\r\n"
            "|---|---|---|---|---|\r\n"
            + row
            + row
        ).encode("utf-8")
    )

    general = [
        item for item in P._parse_depth_finding_blocks(source)
        if item["id"] == "SC-42"
    ]
    assert len(general) == 2
    assert all(item["_low_confidence_rowonly"] == "true" for item in general)
    assert M.promote_niche_to_inventory(tmp_path) == (2, 2)
    sidecar = M.read_niche_identity_debt_sidecar(tmp_path)
    assert sidecar is not None
    assert sidecar["action_count"] == 2
    actions = sidecar["actions"]
    assert len({row["source_action_identity"] for row in actions}) == 2
    ranges = [
        (row["source_byte_start"], row["source_byte_end"])
        for row in actions
    ]
    assert all(start < end for start, end in ranges)
    assert ranges[0][1] <= ranges[1][0]
    assert actions[0]["source_block_sha256"] == actions[1]["source_block_sha256"]


def test_niche_entity_newlines_cannot_shift_raw_multibyte_heading_range(
    tmp_path: Path,
):
    import plamen_mechanical as M

    _write(tmp_path, "findings_inventory.md", _seed_inventory())
    source = tmp_path / "niche_entity_findings.md"
    raw = (
        "πreamble\r\n"
        "&#10;## F&#105;nding [SC-43]: café heading&#13;\r\n"
        "Severity: Medium\r\n"
        "Location: src/Unicode.sol:L43\r\n"
        "Description: Entity normalization cannot move raw byte authority.\r\n"
    ).encode("utf-8")
    source.write_bytes(raw)

    rows = M._parse_niche_findings(tmp_path)
    assert len(rows) == 1
    row = rows[0]
    expected_start = raw.index(b"&#10;##")
    assert row["source_byte_start"] == expected_start
    assert row["source_byte_start"] < row["source_byte_end"] <= len(raw)
    raw_slice = raw[row["source_byte_start"] : row["source_byte_end"]]
    assert raw_slice.startswith(b"&#10;## F&#105;nding [SC-43]")
    assert hashlib.sha256(raw_slice).hexdigest() == row["source_block_sha256"]


def test_niche_sidecar_replay_rejects_live_source_lifecycle_attacks(
    tmp_path: Path,
):
    import plamen_mechanical as M

    _write(tmp_path, "findings_inventory.md", _seed_inventory())
    source = tmp_path / "niche_lifecycle_findings.md"
    first_block = (
        "## Finding [SC-44]: alpha action\r\n"
        "Severity: Medium\r\n"
        "Location: src/Lifecycle.sol:L44\r\n"
        "Description: First exact action with multibyte café bytes.\r\n"
    ).encode("utf-8")
    second_block = (
        "## Finding [SC-45]: beta action\r\n"
        "Severity: Low\r\n"
        "Location: src/Lifecycle.sol:L45\r\n"
        "Description: Second exact action remains independently bound.\r\n"
    ).encode("utf-8")
    original = first_block + second_block
    source.write_bytes(original)
    assert M.promote_niche_to_inventory(tmp_path) == (2, 2)
    assert M.read_niche_identity_debt_sidecar(tmp_path) is not None
    sidecar_bytes = (tmp_path / "niche_identity_debt.json").read_bytes()

    same_size = original.replace(b"alpha", b"omega")
    assert len(same_size) == len(original)
    source.write_bytes(same_size)
    with pytest.raises(RuntimeError, match="live source"):
        M.read_niche_identity_debt_sidecar(tmp_path)
    source.write_bytes(original)

    source.write_bytes(second_block + first_block)
    with pytest.raises(RuntimeError, match="live source"):
        M.read_niche_identity_debt_sidecar(tmp_path)
    source.write_bytes(original)

    renamed = tmp_path / "niche_lifecycle_renamed_findings.md"
    source.rename(renamed)
    with pytest.raises(RuntimeError, match="live source"):
        M.read_niche_identity_debt_sidecar(tmp_path)
    renamed.rename(source)

    source.unlink()
    with pytest.raises(RuntimeError, match="live source"):
        M.read_niche_identity_debt_sidecar(tmp_path)
    source.write_bytes(original)

    relocated = tmp_path / "relocated"
    relocated.mkdir()
    (relocated / "niche_identity_debt.json").write_bytes(sidecar_bytes)
    with pytest.raises(RuntimeError, match="live source"):
        M.read_niche_identity_debt_sidecar(relocated)


def test_niche_sidecar_rejects_empty_overlapping_and_forged_raw_ranges(
    tmp_path: Path,
):
    import plamen_mechanical as M

    _write(tmp_path, "findings_inventory.md", _seed_inventory())
    source = tmp_path / "niche_ranges_findings.md"
    source.write_text(
        "## Finding [SC-46]: first range\n"
        "Severity: Medium\n"
        "Location: src/Range.sol:L46\n"
        "Description: First raw range remains exact.\n"
        "## Finding [SC-47]: second range\n"
        "Severity: Medium\n"
        "Location: src/Range.sol:L47\n"
        "Description: Second raw range remains exact.\n",
        encoding="utf-8",
    )
    assert M.promote_niche_to_inventory(tmp_path) == (2, 2)
    sidecar_path = tmp_path / "niche_identity_debt.json"
    baseline = json.loads(sidecar_path.read_text(encoding="utf-8"))
    raw = source.read_bytes()

    def _publish(actions: list[dict]) -> None:
        payload = json.loads(json.dumps(baseline))
        payload["actions"] = actions
        payload["action_count"] = len(actions)
        payload["action_set_sha256"] = M._niche_action_set_digest(actions)
        payload["source_snapshots"] = [
            {
                "source_file": source.name,
                "source_sha256": hashlib.sha256(raw).hexdigest(),
                "source_size_bytes": len(raw),
            }
        ]
        payload.pop("artifact_sha256", None)
        payload["artifact_sha256"] = M._niche_identity_debt_digest(payload)
        sidecar_path.write_text(json.dumps(payload), encoding="utf-8")

    def _rebind(action: dict, start: int, end: int, block_hash: str | None = None) -> dict:
        rebound = dict(action)
        rebound["source_byte_start"] = start
        rebound["source_byte_end"] = end
        rebound["source_block_size_bytes"] = end - start
        rebound["source_block_sha256"] = block_hash or hashlib.sha256(
            raw[start:end]
        ).hexdigest()
        rebound["source_action_identity"] = M._niche_source_action_identity(
            source_file=source.name,
            source_sha256=hashlib.sha256(raw).hexdigest(),
            normalized_local_id=rebound["normalized_local_id"],
            source_byte_start=start,
            source_byte_end=end,
            source_block_sha256=rebound["source_block_sha256"],
        )
        rebound.pop("action_record_sha256", None)
        rebound["action_record_sha256"] = M._niche_identity_debt_digest(rebound)
        return rebound

    original_actions = baseline["actions"]
    first = original_actions[0]
    second = original_actions[1]

    empty = _rebind(first, first["source_byte_start"], first["source_byte_start"])
    _publish([empty, second])
    with pytest.raises(RuntimeError, match="byte range"):
        M.read_niche_identity_debt_sidecar(tmp_path)

    overlap = _rebind(
        second,
        first["source_byte_end"] - 1,
        second["source_byte_end"],
    )
    _publish([first, overlap])
    with pytest.raises(RuntimeError, match="overlap"):
        M.read_niche_identity_debt_sidecar(tmp_path)

    forged_hash = _rebind(
        first,
        first["source_byte_start"],
        first["source_byte_end"],
        "f" * 64,
    )
    _publish([forged_hash, second])
    with pytest.raises(RuntimeError, match="raw block"):
        M.read_niche_identity_debt_sidecar(tmp_path)


def test_delivery_receipt_rejects_unique_id_only_legacy_referent(
    tmp_path: Path,
):
    import plamen_validators as V

    inventory = _inventory(
        "### Finding [INV-001]: stale ID-only delivery\n"
        "**Source IDs**: SC-1\n"
        "**Severity**: Medium\n"
        "**Location**: src/Module.sol:L1\n"
        "**Description**: A bare local ID is not an exact action identity."
    )
    _write(tmp_path, "findings_inventory.md", inventory)
    scan = {
        "actions": [
            {
                "source_file": "niche_alpha_findings.md",
                "source_artifact_hash": "sha256:" + "a" * 64,
                "producer_key": "niche",
                "action_id": "SC-1",
                "action_kind": "NEW",
                "disposition": "PENDING",
            }
        ],
        "residual_debt": [],
        "artifacts": [],
    }
    payload = V._build_registered_finding_delivery_receipt_payload(
        tmp_path,
        scan,
        inventory,
    )
    assert payload["status"] == "DEGRADED"
    assert payload["actions"][0]["disposition"] == "RESIDUAL_DEBT"

def test_delivery_receipt_rejects_stale_niche_source_hash_referent(
    tmp_path: Path,
):
    import plamen_validators as V

    inventory = _inventory(
        "### Finding [INV-001]: stale exact niche action\n"
        "**Source IDs**: SC-1\n"
        "**Primary Artifact**: niche_alpha_findings.md\n"
        f"**Source Artifact Hash**: sha256:{'a' * 64}\n"
        f"**Source Action Identity**: NACT-{'A' * 24}\n"
        "**Severity**: Medium\n"
        "**Location**: src/Module.sol:L1\n"
        "**Description**: This inventory row binds the prior source bytes."
    )
    _write(tmp_path, "findings_inventory.md", inventory)
    scan = {
        "actions": [
            {
                "source_file": "niche_alpha_findings.md",
                "source_artifact_hash": "sha256:" + "b" * 64,
                "producer_key": "niche",
                "action_id": "SC-1",
                "action_kind": "NEW",
                "disposition": "PENDING",
            }
        ],
        "residual_debt": [],
        "artifacts": [],
    }
    payload = V._build_registered_finding_delivery_receipt_payload(
        tmp_path,
        scan,
        inventory,
    )
    assert payload["status"] == "DEGRADED"
    assert payload["actions"][0]["disposition"] == "RESIDUAL_DEBT"

    current_scan = json.loads(json.dumps(scan))
    current_scan["actions"][0]["source_artifact_hash"] = "sha256:" + "a" * 64
    current = V._build_registered_finding_delivery_receipt_payload(
        tmp_path,
        current_scan,
        inventory,
    )
    assert current["status"] == "CLEAN"
    assert current["actions"][0]["disposition"] == "PROMOTED_FINDING"
