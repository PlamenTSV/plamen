"""P0-V fixtures: skeptic proposes; independent authority adjudicates.

Synthetic only.  These fixtures protect the live recall boundary: uncertainty,
negative dispositions, and low-tier supported mechanisms must be reviewed, but
skeptic Markdown can neither dismiss a candidate nor lower its severity.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent
ROOT = SCRIPTS.parent
sys.path.insert(0, str(SCRIPTS))

import plamen_validators as V  # noqa: E402
from plamen_parsers import (  # noqa: E402
    read_skeptic_challenges_json_sidecar,
    write_skeptic_challenges_json_sidecar,
)
from plamen_mechanical import (  # noqa: E402
    _repair_sc_report_index_from_prior,
    _write_mechanical_report_index,
)
from artifact_ledger import (  # noqa: E402
    read_artifact_ledger,
    record_work_unit_artifacts,
    record_work_unit_inputs,
    write_artifact_ledger,
)
from phase_io_contracts import LaunchSpec, resolve_phase_io_contract  # noqa: E402


def _write(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8")


def _queue(sp: Path, rows: list[tuple[str, str]]) -> None:
    lines = [
        "| Finding ID | Severity | Title | Location | Preferred Tag |",
        "|------------|----------|-------|----------|---------------|",
    ]
    for fid, severity in rows:
        lines.append(
            f"| {fid} | {severity} | Generic candidate | src/X.sol:L10 | [CODE-TRACE] |"
        )
    _write(sp / "verification_queue.md", "\n".join(lines) + "\n")


def _verify(sp: Path, fid: str, severity: str, verdict: str) -> None:
    _write(
        sp / f"verify_{fid}.md",
        f"**Verdict**: {verdict}\n"
        f"**Severity**: {severity}\n"
        "**Location**: src/X.sol:L10\n"
        "**Evidence Tag**: [CODE-TRACE]\n",
    )


def _judge(sp: Path, fid: str, original: str, final: str, decision: str) -> None:
    _write(
        sp / "skeptic_judge_decisions.md",
        "| Finding ID | Original Severity | Final Severity | Decision | Rationale |\n"
        "|------------|-------------------|----------------|----------|-----------|\n"
        f"| {fid} | {original} | {final} | {decision} | proposal only |\n",
    )


def _bind_sc_report_index_root(sp: Path, prior: str, *, run_id: str) -> None:
    """Install the real registered DRIVER PhaseIO authority used by SC repair."""
    contract = resolve_phase_io_contract(
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="claude",
        phase="attention_repair",
        work_unit_id="shard_plan",
        exact_inputs=(),
        exact_outputs=("report_index.md",),
        exact_writer="DRIVER",
    )
    launch = LaunchSpec(
        work_unit_key=contract.key,
        pipeline=contract.pipeline,
        mode=contract.mode,
        ecosystem=contract.ecosystem,
        backend=contract.backend,
        model="driver",
        timeout_s=30,
        exec_mode="python",
        tool_policy=("filesystem",),
    )
    record_work_unit_inputs(
        sp,
        sp.parent,
        contract,
        launch,
        run_id=run_id,
    )
    _write(sp / "report_index.md", prior)
    record_work_unit_artifacts(
        sp,
        sp.parent,
        contract,
        launch,
        run_id=run_id,
        actor="DRIVER",
    )


def test_challenge_scope_is_triggered_by_low_supported_and_medium_nonbody(tmp_path):
    _queue(tmp_path, [("INV-001", "Low"), ("INV-002", "Medium"), ("INV-003", "Medium")])
    _verify(tmp_path, "INV-001", "Low", "CONFIRMED")
    _verify(tmp_path, "INV-002", "Medium", "REFUTED")
    _verify(tmp_path, "INV-003", "Medium", "CONFIRMED")

    ordered = V._skeptic_expected_findings(tmp_path)
    rows = {row["finding_id"]: row for row in ordered}
    assert [row["finding_id"] for row in ordered] == ["INV-001", "INV-002", "INV-003"]
    assert "LOW_SEVERITY_SUPPORTED_MECHANISM" in rows["INV-001"]["challenge_triggers"]
    assert "PROPOSED_NONBODY_DISPOSITION" in rows["INV-002"]["challenge_triggers"]
    assert set(rows["INV-003"]["challenge_triggers"]) == {
        "UNRESOLVED_EXTERNAL_PREMISE",
        "EVIDENCE_INTEGRITY_REVIEW",
    }
    assert "COMPUTE_RECEIPT_MISSING" in rows["INV-003"]["mechanical_authority_issue"]

    # The missing-R10 projection is typed debt, not a clean omission. Replays
    # preserve its bytes and current semantic state supersedes a stale prompt
    # manifest that names only the two direct-trigger rows.
    debt = tmp_path / "external_assumption_undemotion_debt.json"
    debt_before = debt.read_bytes()
    assert V._skeptic_expected_findings(tmp_path) == ordered
    assert debt.read_bytes() == debt_before
    _write(
        tmp_path / "skeptic_manifest.json",
        json.dumps({
            "phase": "skeptic",
            "required_count": 2,
            "findings": [
                {"finding_id": "INV-001"},
                {"finding_id": "INV-002"},
            ],
        }),
    )
    assert V._skeptic_manifest_ids(tmp_path) == ["INV-001", "INV-002", "INV-003"]

    # Malformed compute authority and verifier source drift remain fail-closed;
    # neither can remove the otherwise confirmed Medium row from scope.
    compute = tmp_path / "external_assumption_undemotion_compute.json"
    compute.write_text('{"schema_version":"cross-run-tamper"}', encoding="utf-8")
    assert {
        row["finding_id"] for row in V._skeptic_expected_findings(tmp_path)
    } >= {"INV-001", "INV-002", "INV-003"}
    compute.unlink()
    verify3 = tmp_path / "verify_INV-003.md"
    verify3_before = verify3.read_bytes()
    verify3.write_bytes(verify3_before + b"\nlate source drift\n")
    assert "INV-003" in {
        row["finding_id"] for row in V._skeptic_expected_findings(tmp_path)
    }
    verify3.write_bytes(verify3_before)
    assert V._skeptic_expected_findings(tmp_path) == ordered
    assert debt.read_bytes() == debt_before


def test_high_risk_review_is_preserved_without_other_trigger(tmp_path):
    _queue(tmp_path, [("INV-004", "High")])
    _verify(tmp_path, "INV-004", "High", "CONFIRMED")
    rows = V._skeptic_expected_findings(tmp_path)
    assert [row["finding_id"] for row in rows] == ["INV-004"]
    assert "HIGH_RISK_ADVERSARIAL_REVIEW" in rows[0]["challenge_triggers"]


def test_skeptic_downgrade_markdown_is_not_severity_authority(tmp_path):
    _queue(tmp_path, [("INV-005", "High")])
    _verify(tmp_path, "INV-005", "High", "CONFIRMED")
    _judge(tmp_path, "INV-005", "High", "Low", "DOWNGRADE")
    assert V._collect_judge_downgrade_map(tmp_path) == {}
    assert V._expected_report_index_severities(tmp_path)["INV-005"] == "High"


def test_unresolved_is_visible_but_does_not_demote_mechanical_index(tmp_path):
    _queue(tmp_path, [("INV-006", "High")])
    _verify(tmp_path, "INV-006", "High", "CONFIRMED")
    _judge(tmp_path, "INV-006", "High", "Medium", "UNRESOLVED")
    _write(tmp_path / "config.json", json.dumps({"cli_backend": "claude"}))

    assert _write_mechanical_report_index(tmp_path) == 1
    text = (tmp_path / "report_index.md").read_text(encoding="utf-8")
    row = next(line for line in text.splitlines() if "INV-006" in line)
    assert "| High |" in row
    assert "UNRESOLVED" in row


def test_unresolved_does_not_demote_sc_repair(tmp_path):
    prior = (
        "# Report Index\n\n## Master Finding Index\n\n"
        "| Report ID | Title | Severity | Location | Verification | Trust Adj. | Internal Hypothesis ID |\n"
        "|-----------|-------|----------|----------|--------------|------------|------------------------|\n"
        "| H-01 | Generic candidate | High | src/X.sol:L10 | CONFIRMED | - | H-7 |\n"
    )

    def inputs(sp: Path) -> None:
        sp.mkdir()
        _queue(sp, [("H-7", "High")])
        _verify(sp, "H-7", "High", "CONFIRMED")
        _judge(sp, "H-7", "High", "Medium", "UNRESOLVED")

    # Raw live Markdown and backup-only debris have no predecessor authority.
    raw = tmp_path / "raw"
    inputs(raw)
    _write(raw / "report_index.md", prior)
    _write(raw / "report_index.md.bak", prior.replace("H-01", "C-99"))
    raw_before = (raw / "report_index.md").read_bytes()
    backup_before = (raw / "report_index.md.bak").read_bytes()
    assert _repair_sc_report_index_from_prior(raw) == 0
    assert (raw / "report_index.md").read_bytes() == raw_before
    assert (raw / "report_index.md.bak").read_bytes() == backup_before
    assert not (raw / "_artifact_state.json").exists()

    # Positive: the exact live report root is a registered, committed,
    # current-run DRIVER PhaseIO output. The .bak file is a poison sentinel.
    live = tmp_path / "live"
    inputs(live)
    poison = prior.replace("H-01", "C-99").replace("High", "Critical")
    _write(live / "report_index.md.bak", poison)
    _bind_sc_report_index_root(
        live,
        prior,
        run_id="123e4567-e89b-42d3-a456-426614174000",
    )
    assert _repair_sc_report_index_from_prior(live) == 1
    row = next(
        line for line in (live / "report_index.md").read_text(encoding="utf-8").splitlines()
        if "H-7" in line
    )
    assert "| High |" in row
    assert "| Medium |" not in row
    assert "UNRESOLVED(High)" in row
    assert (live / "report_index.md.bak").read_text(encoding="utf-8") == poison

    # Post-commit live-byte tamper rejects without adopting the poison backup.
    tampered = tmp_path / "tampered"
    inputs(tampered)
    _write(tampered / "report_index.md.bak", poison)
    _bind_sc_report_index_root(
        tampered,
        prior,
        run_id="123e4567-e89b-42d3-a456-426614174001",
    )
    tampered_bytes = (tampered / "report_index.md").read_bytes() + b"\npost-commit tamper\n"
    (tampered / "report_index.md").write_bytes(tampered_bytes)
    assert _repair_sc_report_index_from_prior(tampered) == 0
    assert (tampered / "report_index.md").read_bytes() == tampered_bytes
    assert (tampered / "report_index.md.bak").read_text(encoding="utf-8") == poison

    # A canonical ledger with a foreign run binding is likewise rejected and
    # cannot mint repair authority or mutate the live root.
    cross_run = tmp_path / "cross_run"
    inputs(cross_run)
    _bind_sc_report_index_root(
        cross_run,
        prior,
        run_id="123e4567-e89b-42d3-a456-426614174002",
    )
    cross_before = (cross_run / "report_index.md").read_bytes()
    ledger = read_artifact_ledger(cross_run)
    ledger["artifact_bindings"]["scratchpad:report_index.md"]["run_id"] = (
        "123e4567-e89b-42d3-a456-426614174099"
    )
    write_artifact_ledger(cross_run, ledger)
    assert _repair_sc_report_index_from_prior(cross_run) == 0
    assert (cross_run / "report_index.md").read_bytes() == cross_before


def test_skeptic_prompt_is_proposal_only_and_no_uncertainty_discount():
    text = (ROOT / "prompts/shared/v2/phase5-skeptic.md").read_text(encoding="utf-8")
    lower = text.lower()
    assert "proposal only" in lower
    assert "independent adjudicator" in lower
    assert "unresolved is an evidence state" in lower
    assert "one-tier severity demotion" not in lower
    assert "side that cites more specific code locations" not in lower


def test_skeptic_proposal_receipt_is_hash_bound_and_non_authoritative(tmp_path):
    _queue(tmp_path, [("INV-007", "Medium")])
    _verify(tmp_path, "INV-007", "Medium", "REFUTED")
    manifest = {
        "phase": "skeptic",
        "required_count": 1,
        "findings": [{
            "finding_id": "INV-007",
            "challenge_triggers": ["PROPOSED_NONBODY_DISPOSITION"],
            "constituent_ids": ["INV-007"],
        }],
    }
    _write(tmp_path / "skeptic_manifest.json", json.dumps(manifest, indent=2))
    _write(
        tmp_path / "skeptic_findings.md",
        "# Skeptic Challenge Proposals\n\n"
        "## INV-007 - Generic\n\n"
        "Proposal Authority: CHALLENGE_ONLY\n"
        "Proposed Direction: UNRESOLVED\n"
        "Proposed Disposition: CHALLENGE_NONBODY\n"
        "Affected Constituents: INV-007\n"
        "Impact Premise ID: IMP-INV-007\n"
        "Likelihood Premise ID: LIK-INV-007\n"
        "Premise Challenged: full harm was not refuted\n"
        "Evidence Receipt IDs: NONE\n"
        "Proof Scope: UNRESOLVED\n",
    )
    _judge(tmp_path, "INV-007", "Medium", "Medium", "UNRESOLVED")
    assert V._validate_skeptic_challenge_receipt(tmp_path)
    assert write_skeptic_challenges_json_sidecar(tmp_path) == 1
    payload = read_skeptic_challenges_json_sidecar(tmp_path)
    assert payload["authority"] == "CHALLENGE_ONLY"
    assert payload["report_authoritative"] is False
    assert payload["challenges"][0]["schema_status"] == "COMPLETE"
    assert V._validate_skeptic_challenge_receipt(tmp_path) == []

    with (tmp_path / "skeptic_findings.md").open("a", encoding="utf-8") as handle:
        handle.write("\nmutated\n")
    assert read_skeptic_challenges_json_sidecar(tmp_path) == {}
    assert V._validate_skeptic_challenge_receipt(tmp_path)


def test_phase_graph_keeps_distinct_skeptic_and_adjudicator_workers():
    from plamen_types import SC_PHASES

    names = [phase.name for phase in SC_PHASES]
    assert names.index("skeptic") < names.index("severity_adjudication_shadow")
    skeptic = next(phase for phase in SC_PHASES if phase.name == "skeptic")
    adjudicator = next(
        phase for phase in SC_PHASES if phase.name == "severity_adjudication_shadow"
    )
    assert skeptic.model != adjudicator.model or skeptic.name != adjudicator.name


def test_skeptic_driver_projection_has_exact_phase_io_contract():
    from phase_io_contracts import resolve_phase_io_contract

    contract = resolve_phase_io_contract(
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="claude",
        phase="skeptic",
        work_unit_id="challenge_reconcile",
    )
    assert contract.model_invoked is False
    assert {item.identity for item in contract.outputs} == {
        "scratchpad:judge_decisions.json",
        "scratchpad:skeptic_challenges.json",
    }
    assert set(contract.immutable_inputs) == {
        "scratchpad:skeptic_manifest.json",
        "scratchpad:skeptic_findings.md",
        "scratchpad:skeptic_judge_decisions.md",
    }


def test_shared_methodology_does_not_restore_uncertainty_demotion():
    active = [
        ROOT / "rules/report-template.md",
        ROOT / "rules/phase6-report-prompts.md",
        ROOT / "rules/orchestrator-rules.md",
        ROOT / "prompts/shared/v2/phase5-skeptic.md",
        ROOT / "prompts/shared/v2/phase6a-report-index.md",
        ROOT / "prompts/shared/v2/phase6b-tier-writers.md",
        ROOT / "prompts/shared/v2/pipeline-full-audit.md",
        ROOT / "prompts/shared/phase5-skeptic-judge.md",
    ]
    joined = "\n".join(path.read_text(encoding="utf-8") for path in active).lower()
    forbidden = (
        "unresolved demotion",
        "critical unresolved → high",
        "high unresolved → medium",
        "medium unresolved → low",
        "demoted under skeptic disagreement",
        "skeptic-judge for high/crit",
        "skeptic-judge | skip | skip | high/crit",
    )
    assert not [token for token in forbidden if token in joined]
    assert "proposal-only" in joined
    assert "typed severity ledger" in joined
