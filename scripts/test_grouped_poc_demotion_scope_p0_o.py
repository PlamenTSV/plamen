"""P0-O: grouped PoC failures must have constituent-bound demotion scope.

These fixtures deliberately keep the motivating repository out of the test
data.  They exercise the monotonic safety property: less certain proof scope
can never authorize a wider severity reduction.
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

import pytest

import plamen_driver as D
import plamen_types as T
import plamen_validators as V
import execution_scope_runtime as execution_scope_runtime
from evidence_capabilities import (
    EXECUTED_POC_SCOPE_EVIDENCE_SCHEMA,
    issue_executed_poc_scope_assessment,
)
from poc_demotion_scope import (
    build_scope_recovery_plan,
    load_validated_scope_repair,
    recovery_unit_paths,
    validate_recovery_unit_receipt,
    write_recovery_attempt,
    write_recovery_unit_receipt,
)
from severity_decision_ledger import PROPOSAL_SCHEMA


def _sha(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def _authorize_exhaustive_negative(
    monkeypatch: pytest.MonkeyPatch, candidate_id: str
) -> None:
    """Keep P0-O unit tests focused while satisfying the live P1-E gate."""

    assessment = issue_executed_poc_scope_assessment(
        {
            "schema_version": EXECUTED_POC_SCOPE_EVIDENCE_SCHEMA,
            "candidate_id": candidate_id,
            "evidence_id": f"P1E-NEG-{candidate_id}",
            "source_snapshot_sha256": _sha("source"),
            "build_sha256": _sha("build"),
            "command_sha256": _sha("command"),
            "oracle_sha256": _sha("oracle"),
            "output_sha256": _sha("output"),
            "runner_receipt_sha256": _sha("runner"),
            "launch_receipt_sha256": _sha("launch"),
            "execution_status": "COMPLETED",
            "execution_result": "NOT_ESTABLISHED",
            "exit_code": 1,
            "oracle_provenance": "MODEL_GENERATED_ORACLE",
            "oracle_derivation": "IN_SCOPE_CLAIM_BOUND",
            "oracle_author_identity": "verification-worker",
            "oracle_author_invocation_id": "verification-worker-run-1",
            "oracle_review_status": "INDEPENDENTLY_VALIDATED",
            "oracle_reviewer_identity": "independent-scope-reviewer",
            "oracle_reviewer_invocation_id": "independent-scope-reviewer-run-1",
            "reachability": "IN_SCOPE_REACHABLE",
            "environment_fidelity": "FULL_IN_SCOPE",
            "proof_scope": "HARM",
            "negative_exhaustiveness": "EXHAUSTIVE_IN_SCOPE",
            "required_precondition_ids": ["PRE-1"],
            "represented_precondition_ids": ["PRE-1"],
            "external_evidence_receipts": [],
            "external_premises": [],
            "premise_ids": ["PREM-1"],
            "constituent_ids": [candidate_id],
            "source_author_identity": "verification-worker",
            "source_author_invocation_id": "verification-worker-run-1",
            "issuer_identity": "scope-registrar",
            "issuer_invocation_id": "scope-registrar-run-1",
        }
    )

    def _load(_scratchpad: Path, observed_id: str) -> dict:
        if observed_id != candidate_id:
            return {"status": "MISSING", "assessment": None, "issues": []}
        return {"status": "VALID_RICH", "assessment": assessment, "issues": []}

    monkeypatch.setattr(
        execution_scope_runtime, "load_execution_scope_assessment", _load
    )


def _seed_group(scratchpad: Path, *, members: tuple[str, ...] = ("INV-001", "INV-002", "INV-003")) -> None:
    inventory = ["# Finding Inventory\n\n## Findings\n\n"]
    for index, fid in enumerate(members, start=1):
        inventory.append(
            f"### Finding [{fid}]: Distinct mechanism {index}\n"
            f"**Severity**: {'High' if index == 3 else 'Medium'}\n"
            f"**Location**: src/Module.sol:L{index * 10} operation{index}()\n"
            "**Preferred Tag**: [CODE-TRACE]\n"
            f"**Root Cause**: distinct state transition {index}\n"
            f"**Description**: independently actionable condition {index}\n"
            f"**Impact**: distinct material consequence {index}\n\n"
        )
    (scratchpad / "findings_inventory.md").write_text("".join(inventory), encoding="utf-8")
    joined = ", ".join(members)
    (scratchpad / "hypotheses.md").write_text(
        "| Hypothesis ID | Severity | Source Findings |\n"
        "|---|---|---|\n"
        f"| GRP-M-001 | Medium | {joined} |\n",
        encoding="utf-8",
    )
    (scratchpad / "finding_mapping.md").write_text(
        "| Finding ID | Hypothesis ID | Status |\n"
        "|---|---|---|\n"
        + "".join(
            f"| {fid} | GRP-M-001 | SPLIT from H-900 |\n"
            for fid in members
        ),
        encoding="utf-8",
    )
    (scratchpad / "verification_queue.md").write_text(
        "| Finding ID | Severity | Title | Location | PoC Class |\n"
        "|---|---|---|---|---|\n"
        "| GRP-M-001 | Medium | Grouped claim | src/Module.sol | unit |\n",
        encoding="utf-8",
    )


def _scope_table(rows: list[tuple[str, str, str, str, str]]) -> str:
    body = [
        "### PoC Constituent Evidence Scope\n\n",
        "| Constituent ID | Harm Premise ID | Assertion ID | Proof Scope | Binding Kind |\n",
        "|---|---|---|---|---|\n",
    ]
    body.extend("| " + " | ".join(row) + " |\n" for row in rows)
    return "".join(body)


def _write_verify(scratchpad: Path, scope: str = "", *, mechanism_only: bool = False) -> None:
    proof = "MECHANISM_ONLY" if mechanism_only else "HARM"
    (scratchpad / "verify_M-001.md").write_text(
        "# Verification: GRP-M-001\n\n"
        "### Finding Summary\n\n"
        "An intentionally generic verifier summary with no title authority.\n\n"
        "### PoC Attempt\n"
        "- Attempted: YES\n"
        "- Test File: tests/poc_group.rs\n"
        "- Command: cargo test poc_group\n\n"
        "### Execution Result\n"
        "- Compiled: YES\n"
        "- Result: FAIL\n"
        "- Mechanical Status: [FAIL]\n"
        "- Evidence Tag: [POC-FAIL]\n"
        f"- Proof Scope: {proof}\n\n"
        + scope,
        encoding="utf-8",
    )


def _receipt(scratchpad: Path) -> dict:
    return json.loads((scratchpad / "poc_demotion_scope_receipt.json").read_text(encoding="utf-8"))


def _debt(scratchpad: Path) -> dict:
    return json.loads((scratchpad / "poc_demotion_scope_repair.json").read_text(encoding="utf-8"))


def test_ambiguous_summary_demotes_none_and_creates_repair_debt(tmp_path: Path) -> None:
    _seed_group(tmp_path)
    _write_verify(tmp_path)

    assert V._apply_poc_fail_demotions(tmp_path, "thorough") == []
    row = _receipt(tmp_path)["groups"][0]
    assert row["scope_status"] == "AMBIGUOUS"
    assert row["demoted_constituent_ids"] == []
    assert row["preserved_constituent_ids"] == ["INV-001", "INV-002", "INV-003"]
    assert set(_debt(tmp_path)["work_items"][0]["constituent_ids"]) == {
        "INV-001", "INV-002", "INV-003"
    }
    assert not (tmp_path / "poc_demotions.md").exists()


def test_one_explicit_harm_binding_demotes_only_that_constituent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _seed_group(tmp_path)
    _authorize_exhaustive_negative(monkeypatch, "M-001")
    _write_verify(tmp_path, _scope_table([
        ("INV-003", "HP-3", "ASSERT-3", "HARM", "EXACT"),
    ]))

    demotions = V._apply_poc_fail_demotions(tmp_path, "thorough")
    assert [row["finding_id"] for row in demotions] == ["INV-003"]
    assert demotions[0]["original_severity"] == "High"
    assert set(_debt(tmp_path)["work_items"][0]["constituent_ids"]) == {"INV-001", "INV-002"}
    proposal_text = (tmp_path / "poc_demotion_proposals.md").read_text(
        encoding="utf-8"
    )
    assert "M-001" not in proposal_text
    assert "INV-003" in proposal_text
    assert "Non-authoritative" in proposal_text
    assert not (tmp_path / "poc_demotions.md").exists()
    receipt = _receipt(tmp_path)
    assert receipt["authority"] == "SCOPE_PROPOSAL_ONLY"
    assert receipt["severity_mutation_authorized"] is False
    assert receipt["report_authoritative"] is False


def test_lexically_similar_constituents_never_create_shared_authority(tmp_path: Path) -> None:
    _seed_group(tmp_path, members=("INV-011", "INV-012"))
    _write_verify(tmp_path)

    assert V._apply_poc_fail_demotions(tmp_path, "thorough") == []
    assert _receipt(tmp_path)["groups"][0]["demotion_authority"] == "NONE"


def test_raw_composition_alias_cannot_define_grouped_demotion_scope(
    tmp_path: Path,
) -> None:
    _seed_group(tmp_path, members=("INV-061", "INV-062"))
    (tmp_path / "finding_mapping.md").write_text(
        "| Finding ID | Hypothesis ID |\n"
        "|---|---|\n"
        "| INV-061 | GRP-M-001 |\n"
        "| INV-062 | GRP-M-001 |\n",
        encoding="utf-8",
    )
    _write_verify(
        tmp_path,
        _scope_table([
            ("INV-061", "HP-SHARED", "ASSERT-SHARED", "HARM", "SHARED"),
            ("INV-062", "HP-SHARED", "ASSERT-SHARED", "HARM", "SHARED"),
        ]),
    )

    assert V._apply_poc_fail_demotions(tmp_path, "thorough") == []
    row = _receipt(tmp_path)["groups"][0]
    assert row["scope_status"] == "UNPROVEN_GROUP_RELATION"
    assert row["demotion_authority"] == "NONE"
    assert row["reverification_constituent_ids"] == ["INV-061", "INV-062"]


def test_shared_harm_assertion_requires_explicit_binding_for_every_member(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _seed_group(tmp_path)
    _authorize_exhaustive_negative(monkeypatch, "M-001")
    shared = _scope_table([
        ("INV-001", "HP-SHARED", "ASSERT-SHARED", "HARM", "SHARED"),
        ("INV-002", "HP-SHARED", "ASSERT-SHARED", "HARM", "SHARED"),
        ("INV-003", "HP-SHARED", "ASSERT-SHARED", "HARM", "SHARED"),
    ])
    _write_verify(tmp_path, shared)

    demotions = V._apply_poc_fail_demotions(tmp_path, "thorough")
    assert [row["finding_id"] for row in demotions] == ["M-001"]
    row = _receipt(tmp_path)["groups"][0]
    assert row["scope_status"] == "SCOPED_SHARED_ALL"
    assert row["demotion_authority"] == "GROUP_WIDE"
    assert not _debt(tmp_path)["work_items"]


def test_partial_shared_binding_is_ambiguous_not_partial_group_demotion(tmp_path: Path) -> None:
    _seed_group(tmp_path)
    partial = _scope_table([
        ("INV-001", "HP-SHARED", "ASSERT-SHARED", "HARM", "SHARED"),
        ("INV-002", "HP-SHARED", "ASSERT-SHARED", "HARM", "SHARED"),
    ])
    _write_verify(tmp_path, partial)

    assert V._apply_poc_fail_demotions(tmp_path, "thorough") == []
    row = _receipt(tmp_path)["groups"][0]
    assert row["scope_status"] == "AMBIGUOUS_SHARED_SCOPE"
    assert row["demoted_constituent_ids"] == []


@pytest.mark.parametrize("scope", ("MECHANISM_ONLY", "MECHANISM"))
def test_mechanism_only_execution_cannot_authorize_demotion(tmp_path: Path, scope: str) -> None:
    _seed_group(tmp_path)
    _write_verify(tmp_path, _scope_table([
        ("INV-003", "HP-3", "ASSERT-3", scope, "EXACT"),
    ]), mechanism_only=True)

    assert V._apply_poc_fail_demotions(tmp_path, "thorough") == []
    assert _receipt(tmp_path)["groups"][0]["scope_status"] == "MECHANISM_ONLY"


def test_unknown_or_duplicate_constituent_scope_is_invalid_and_recall_safe(tmp_path: Path) -> None:
    _seed_group(tmp_path)
    _write_verify(tmp_path, _scope_table([
        ("INV-003", "HP-3", "ASSERT-3", "HARM", "EXACT"),
        ("INV-003", "HP-OTHER", "ASSERT-OTHER", "HARM", "EXACT"),
        ("INV-999", "HP-X", "ASSERT-X", "HARM", "EXACT"),
    ]))

    assert V._apply_poc_fail_demotions(tmp_path, "thorough") == []
    assert _receipt(tmp_path)["groups"][0]["scope_status"] == "INVALID_SCOPE_LEDGER"


def test_split_parent_alias_and_replay_are_stable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _seed_group(tmp_path, members=("INV-041", "INV-042"))
    _authorize_exhaustive_negative(monkeypatch, "GRP-001A")
    # Preserve the real split-source linkage shape without any protocol names.
    (tmp_path / "finding_mapping.md").write_text(
        "| Finding ID | Hypothesis ID | Status |\n"
        "|---|---|---|\n"
        "| INV-041 | GRP-001A | SPLIT from H-22 |\n"
        "| INV-042 | GRP-001A | SPLIT from H-22 |\n",
        encoding="utf-8",
    )
    (tmp_path / "verification_queue.md").write_text(
        "| Finding ID | Severity | Title | Location | PoC Class |\n"
        "|---|---|---|---|---|\n"
        "| GRP-001A | Medium | Split group | src/Module.sol | unit |\n",
        encoding="utf-8",
    )
    (tmp_path / "verify_GRP-001A.md").write_text(
        "# Verification: GRP-001A\n\n"
        "### PoC Attempt\n- Attempted: YES\n- Test File: tests/poc.rs\n- Command: cargo test poc\n\n"
        "### Execution Result\n- Compiled: YES\n- Result: FAIL\n- Mechanical Status: [FAIL]\n"
        "- Evidence Tag: [POC-FAIL]\n\n"
        + _scope_table([("[INV-041]", "HP-1", "ASSERT-1", "HARM", "EXACT")]),
        encoding="utf-8",
    )

    first = V._apply_poc_fail_demotions(tmp_path, "thorough")
    bytes_before = {
        name: (tmp_path / name).read_bytes()
        for name in (
            "poc_demotion_proposals.md",
            "poc_demotion_proposals.json",
            "poc_demotion_scope_receipt.json",
            "poc_demotion_scope_repair.json",
        )
    }
    second = V._apply_poc_fail_demotions(tmp_path, "thorough")
    assert first == second
    assert first[0]["finding_id"] == "INV-041"
    assert bytes_before == {name: (tmp_path / name).read_bytes() for name in bytes_before}


def test_nonexecuted_group_scope_cannot_demote(tmp_path: Path) -> None:
    _seed_group(tmp_path)
    _write_verify(tmp_path, _scope_table([
        ("INV-003", "HP-3", "ASSERT-3", "HARM", "EXACT"),
    ]))
    text = (tmp_path / "verify_M-001.md").read_text(encoding="utf-8")
    text = text.replace("Attempted: YES", "Attempted: NO").replace("Compiled: YES", "Compiled: NO")
    (tmp_path / "verify_M-001.md").write_text(text, encoding="utf-8")

    assert V._apply_poc_fail_demotions(tmp_path, "thorough") == []
    assert _receipt(tmp_path)["groups"][0]["scope_status"] == "EXECUTION_UNBOUND"


def _valid_severity_proposal(fid: str) -> dict:
    evidence_impact = f"EVID-I-{fid}"
    evidence_likelihood = f"EVID-L-{fid}"
    return {
        "schema_version": PROPOSAL_SCHEMA,
        "candidate_id": fid,
        "constituent_ids": [fid],
        "impact": {
            "class": "Medium",
            "harmed_asset": "protected state",
            "harmed_capability": "integrity",
            "premise_id": f"PREM-I-{fid}",
            "premise_kind": "INTERNAL",
            "evidence_ids": [evidence_impact],
            "proof_scope": "IN_SCOPE_SOURCE",
        },
        "likelihood": {
            "class": "Medium",
            "actor": "unprivileged participant",
            "preconditions": ["reachable state"],
            "premise_id": f"PREM-L-{fid}",
            "premise_kind": "INTERNAL",
            "evidence_ids": [evidence_likelihood],
            "proof_scope": "IN_SCOPE_SOURCE",
        },
        "modifiers": [],
        "proposed_severity": "Medium",
        "adjustment": None,
        "constituent_premise_outcomes": {
            fid: {"impact": "SUPPORTED", "likelihood": "SUPPORTED"}
        },
    }


def _write_recovery_pair(scratchpad: Path, fid: str) -> None:
    (scratchpad / f"verify_{fid}.md").write_text(
        f"# Verification: {fid}\n\n"
        f"Severity: Medium\nEvidence Tag: [CODE-TRACE]\nVerdict: CONFIRMED\n\n"
        "## Analysis\n\n"
        "Independent constituent re-verification traced the exact state "
        "transition and retained the claim for separate adjudication.\n",
        encoding="utf-8",
    )
    (scratchpad / f"verify_{fid}.severity_proposal.json").write_text(
        json.dumps(_valid_severity_proposal(fid), sort_keys=True),
        encoding="utf-8",
    )


def test_recovery_plan_is_exact_bounded_and_source_bound(tmp_path: Path) -> None:
    members = tuple(f"INV-{index:03d}" for index in range(1, 7))
    _seed_group(tmp_path, members=members)
    _write_verify(tmp_path)
    assert V._apply_poc_fail_demotions(tmp_path, "thorough") == []

    scope, repair = load_validated_scope_repair(tmp_path)
    plan = build_scope_recovery_plan(tmp_path)
    assert plan["source_scope_receipt_digest"] == scope["receipt_digest"]
    assert plan["source_repair_receipt_digest"] == repair["receipt_digest"]
    assert plan["ordered_constituent_ids"] == list(members)
    assert [len(unit["rows"]) for unit in plan["units"]] == [4, 2]
    assert all(len(unit["rows"]) <= 4 for unit in plan["units"])


def test_recovery_consumer_runs_once_and_never_mutates_primary_queue(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _seed_group(tmp_path)
    _write_verify(tmp_path)
    V._apply_poc_fail_demotions(tmp_path, "thorough")
    queue_before = (tmp_path / "verification_queue.md").read_bytes()
    launches: list[tuple[str, ...]] = []

    def _fake_recovery(_config: dict, rows: list[tuple[str, dict]]) -> list[str]:
        launches.append(tuple(fid for fid, _row in rows))
        assert len(rows) <= 4
        for fid, _row in rows:
            _write_recovery_pair(tmp_path, fid)
        return []

    monkeypatch.setattr(D, "_run_verify_recovery_shard", _fake_recovery)
    first = D._run_p0o_scope_recovery(
        tmp_path, {"pipeline": "sc", "mode": "thorough"}
    )
    second = D._run_p0o_scope_recovery(
        tmp_path, {"pipeline": "sc", "mode": "thorough"}
    )

    assert launches == [("INV-001", "INV-002", "INV-003")]
    assert first["recovered"] == ["INV-001", "INV-002", "INV-003"]
    assert first["unresolved"] == []
    assert second["attempted"] == []
    assert second["recovered"] == first["recovered"]
    assert (tmp_path / "verification_queue.md").read_bytes() == queue_before


def test_report_seed_retains_pre_demotion_scope_until_exact_recovery_is_bound(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _seed_group(tmp_path)
    _write_verify(tmp_path)
    V._apply_poc_fail_demotions(tmp_path, "thorough")

    D._write_report_index_coverage_seed(tmp_path)
    pending = (tmp_path / "report_index_coverage_seed.md").read_text(
        encoding="utf-8"
    )
    assert re.search(
        r"\| INV-003 \| High \| P0-O REVERIFICATION PENDING \|.*"
        r"P0-O REVERIFICATION PENDING; PRE-DEMOTION SEVERITY RETAINED",
        pending,
    )

    def _recover(_config: dict, rows: list[tuple[str, dict]]) -> list[str]:
        for fid, _row in rows:
            _write_recovery_pair(tmp_path, fid)
        return []

    monkeypatch.setattr(D, "_run_verify_recovery_shard", _recover)
    D._run_p0o_scope_recovery(
        tmp_path, {"pipeline": "sc", "mode": "thorough"}
    )
    D._write_report_index_coverage_seed(tmp_path)
    recovered = (tmp_path / "report_index_coverage_seed.md").read_text(
        encoding="utf-8"
    )
    assert re.search(
        r"\| INV-003 \| High \| P0-O REVERIFIED SUPPLEMENT \|.*"
        r"P0-O REVERIFIED SUPPLEMENT; PRE-DEMOTION SEVERITY RETAINED",
        recovered,
    )

    # A self-edited status marker is not authority. Report routing falls back
    # to PENDING at the same retained severity rather than trusting the marker.
    status_path = tmp_path / "poc_demotion_scope_recovery_status.json"
    tampered = json.loads(status_path.read_text(encoding="utf-8"))
    tampered["state"] = "CLEAN-BUT-UNBOUND"
    status_path.write_text(json.dumps(tampered), encoding="utf-8")
    D._write_report_index_coverage_seed(tmp_path)
    fallback = (tmp_path / "report_index_coverage_seed.md").read_text(
        encoding="utf-8"
    )
    assert "| INV-003 | High | P0-O REVERIFICATION PENDING |" in fallback
    assert "P0-O REVERIFIED SUPPLEMENT" not in fallback


def test_recovery_crash_window_adopts_only_post_arm_valid_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _seed_group(tmp_path, members=("INV-021", "INV-022"))
    _write_verify(tmp_path)
    V._apply_poc_fail_demotions(tmp_path, "thorough")
    plan = build_scope_recovery_plan(tmp_path)
    unit = plan["units"][0]
    from poc_demotion_scope import write_recovery_attempt
    write_recovery_attempt(tmp_path, plan, unit)
    for fid in ("INV-021", "INV-022"):
        _write_recovery_pair(tmp_path, fid)

    monkeypatch.setattr(
        D,
        "_run_verify_recovery_shard",
        lambda *_args, **_kwargs: pytest.fail("crash recovery relaunched provider"),
    )
    result = D._run_p0o_scope_recovery(
        tmp_path, {"pipeline": "sc", "mode": "thorough"}
    )
    assert result["attempted"] == []
    assert result["recovered"] == ["INV-021", "INV-022"]


def test_partial_recovery_failure_stays_visible_debt_and_does_not_loop(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _seed_group(tmp_path, members=("INV-031", "INV-032"))
    _write_verify(tmp_path)
    V._apply_poc_fail_demotions(tmp_path, "thorough")
    launches = 0

    def _partial(_config: dict, rows: list[tuple[str, dict]]) -> list[str]:
        nonlocal launches
        launches += 1
        _write_recovery_pair(tmp_path, rows[0][0])
        return [rows[1][0]]

    monkeypatch.setattr(D, "_run_verify_recovery_shard", _partial)
    first = D._run_p0o_scope_recovery(
        tmp_path, {"pipeline": "sc", "mode": "thorough"}
    )
    second = D._run_p0o_scope_recovery(
        tmp_path, {"pipeline": "sc", "mode": "thorough"}
    )
    assert launches == 1
    assert set(first["unresolved"]) == {"INV-031", "INV-032"}
    assert set(second["unresolved"]) == {"INV-031", "INV-032"}
    assert first["changed"] == ["INV-031", "INV-032"]
    assert second["changed"] == []
    status = json.loads(
        (tmp_path / "poc_demotion_scope_recovery_status.json").read_text(encoding="utf-8")
    )
    assert status["state"] == "COMPLETED_WITH_DEBT"
    assert status["unresolved_retention"] == "PRE_DEMOTION_SEVERITY_REPORT_VISIBLE"


def test_completed_recovery_receipt_requires_complete_bound_outputs(
    tmp_path: Path,
) -> None:
    _seed_group(tmp_path, members=("INV-071", "INV-072"))
    _write_verify(tmp_path)
    V._apply_poc_fail_demotions(tmp_path, "thorough")
    plan = build_scope_recovery_plan(tmp_path)
    unit = plan["units"][0]
    write_recovery_attempt(tmp_path, plan, unit)

    with pytest.raises(ValueError, match="COMPLETED.*output"):
        write_recovery_unit_receipt(
            tmp_path, plan, unit, status="COMPLETED", issues=()
        )

    receipt = write_recovery_unit_receipt(
        tmp_path, plan, unit, status="DEBT", issues=("worker unavailable",)
    )
    assert receipt["proof_authority"] == "NONE"
    validated, issues = validate_recovery_unit_receipt(tmp_path, plan, unit)
    assert not issues
    assert validated and validated["status"] == "DEBT"


def test_scope_artifact_failure_revokes_grouped_cap_on_disk(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _seed_group(tmp_path)
    _authorize_exhaustive_negative(monkeypatch, "M-001")
    _write_verify(tmp_path, _scope_table([
        ("INV-001", "HP-SHARED", "ASSERT-SHARED", "HARM", "SHARED"),
        ("INV-002", "HP-SHARED", "ASSERT-SHARED", "HARM", "SHARED"),
        ("INV-003", "HP-SHARED", "ASSERT-SHARED", "HARM", "SHARED"),
    ]))

    import poc_demotion_scope as scope_module

    monkeypatch.setattr(
        scope_module,
        "write_grouped_poc_scope_artifacts",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("disk full")),
    )
    demotions = V._apply_poc_fail_demotions(tmp_path, "thorough")

    assert demotions == []
    assert not (tmp_path / "poc_demotions.md").exists()
    debt = (tmp_path / "poc_demotion_scope_debt.md").read_text(encoding="utf-8")
    assert "No grouped demotion is authoritative" in debt


def test_tampered_repair_never_launches_and_remains_debt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _seed_group(tmp_path)
    _write_verify(tmp_path)
    V._apply_poc_fail_demotions(tmp_path, "thorough")
    path = tmp_path / "poc_demotion_scope_repair.json"
    value = json.loads(path.read_text(encoding="utf-8"))
    value["work_items"][0]["constituent_ids"].append("INV-999")
    path.write_text(json.dumps(value), encoding="utf-8")
    monkeypatch.setattr(
        D,
        "_run_verify_recovery_shard",
        lambda *_args, **_kwargs: pytest.fail("tampered repair launched provider"),
    )

    result = D._run_p0o_scope_recovery(
        tmp_path, {"pipeline": "sc", "mode": "thorough"}
    )
    assert result["attempted"] == []
    assert result["issues"]


def test_startup_late_repair_consumes_p0o_and_rewinds_only_descendants(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _seed_group(tmp_path)
    _write_verify(tmp_path)
    V._apply_poc_fail_demotions(tmp_path, "thorough")
    phases = [phase for phase in T.SC_PHASES if "thorough" in phase.modes]
    aggregate_index = next(
        index for index, phase in enumerate(phases)
        if phase.name == "sc_verify_aggregate"
    )
    checkpoint = T.Checkpoint(
        completed=[phase.name for phase in phases[aggregate_index:]],
        degraded=[],
    )
    launches = 0

    def _recover(_config: dict, rows: list[tuple[str, dict]]) -> list[str]:
        nonlocal launches
        launches += 1
        for fid, _row in rows:
            _write_recovery_pair(tmp_path, fid)
        return []

    monkeypatch.setattr(D, "_run_verify_recovery_shard", _recover)
    monkeypatch.setattr(D, "backfill_unrouted_inventory_into_queue", lambda _root: [])
    config = {
        "scratchpad": str(tmp_path),
        "project_root": str(tmp_path),
        "pipeline": "sc",
        "language": "evm",
        "mode": "thorough",
        "cli_backend": "claude",
    }
    first = D._repair_late_verification_backfill(
        tmp_path, config, checkpoint, phases, "thorough"
    )
    second = D._repair_late_verification_backfill(
        tmp_path, config, checkpoint, phases, "thorough"
    )

    assert launches == 1
    assert first["backfilled"] == []
    assert first["grouped_poc_recovered"] == ["INV-001", "INV-002", "INV-003"]
    assert "sc_verify_aggregate" in first["rewound"]
    assert "report_index" in first["rewound"]
    assert second["rewound"] == []
    assert "sc_verify_aggregate" in checkpoint.degraded
