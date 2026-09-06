"""Recall boundary for negative PoC outcomes.

An executed test that does not establish a claim is useful review evidence, but
it is not itself a severity decision.  Even an exhaustive, exactly-bound P1-E
assessment remains ``ADJUDICATION_REQUIRED``.  These fixtures lock the current
cutover at proposal-only until a separate typed adjudicator/lifecycle receipt is
implemented and enabled.
"""

from __future__ import annotations

import json
import hashlib
from pathlib import Path

import pytest

import plamen_mechanical as M
import plamen_validators as V
from execution_scope_runtime import materialize_execution_scope_assessments
from test_execution_scope_runtime_p1_e import (
    _bound_execution,
    _explicit_scope_rewind,
    _rich_record,
)


def _seed_exhaustive_negative(tmp_path: Path) -> Path:
    project = tmp_path / "project"
    scratch = tmp_path / "scratch"
    _bound_execution(scratch, project, status="FAIL")
    (scratch / "verification_queue.md").write_text(
        "| Finding ID | Severity | Title | Location | PoC Class |\n"
        "|---|---|---|---|---|\n"
        "| H-71 | High | Candidate | src/Module.sol:10 | unit |\n",
        encoding="utf-8",
    )
    materialize_execution_scope_assessments(scratch, build_root=project)
    record = _rich_record(scratch, "H-71", negative=True)
    _explicit_scope_rewind(scratch, "H-71")
    (scratch / "verify_H-71.execution_scope_evidence.json").write_text(
        json.dumps(record, indent=2), encoding="utf-8"
    )
    materialize_execution_scope_assessments(scratch, build_root=project)
    return scratch


def test_exhaustive_negative_is_visible_proposal_not_severity_authority(
    tmp_path: Path,
) -> None:
    scratch = _seed_exhaustive_negative(tmp_path)

    proposals = V._apply_poc_fail_demotions(scratch, "thorough")

    assert [row["finding_id"] for row in proposals] == ["H-71"]
    assert all(row["authority"] == "NONE" for row in proposals)
    assert all(row["action"] == "PROPOSE_NEGATIVE_REVIEW" for row in proposals)
    assert not (scratch / "poc_demotions.md").exists()
    proposal_path = scratch / "poc_demotion_proposals.json"
    payload = json.loads(proposal_path.read_text(encoding="utf-8"))
    assert payload["schema_version"] == "plamen.poc_demotion_proposals.v1"
    assert payload["authority"] == "NONE"
    assert payload["severity_mutation_authorized"] is False
    assert payload["candidate_count"] == 1
    assert payload["candidates"][0]["current_severity"] == "High"
    unsigned = {key: value for key, value in payload.items() if key != "proposal_digest"}
    canonical = json.dumps(
        unsigned,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    assert payload["proposal_digest"] == hashlib.sha256(canonical).hexdigest()

    before = {
        name: (scratch / name).read_bytes()
        for name in ("poc_demotion_proposals.json", "poc_demotion_proposals.md")
    }
    assert V._apply_poc_fail_demotions(scratch, "thorough") == proposals
    assert before == {name: (scratch / name).read_bytes() for name in before}

    assert M._load_poc_demotion_caps(scratch) == {}
    assert V._poc_demotion_caps_for_validator(scratch) == {}
    assert V._expected_report_index_severities(scratch)["H-71"] == "High"


def test_legacy_markdown_cap_is_inert_without_typed_cutover(tmp_path: Path) -> None:
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    (scratch / "verification_queue.md").write_text(
        "| Finding ID | Severity | Title | Location | PoC Class |\n"
        "|---|---|---|---|---|\n"
        "| H-71 | High | Candidate | src/Module.sol:10 | unit |\n",
        encoding="utf-8",
    )
    (scratch / "verify_H-71.md").write_text(
        "# H-71\n\nStatus: CONFIRMED\n\nSeverity: High\n",
        encoding="utf-8",
    )
    (scratch / "poc_demotions.md").write_text(
        "# Legacy PoC Fail Demotions\n\n"
        "| Finding ID | Original Severity | Capped At | PoC Class | Reason |\n"
        "|---|---|---|---|---|\n"
        "| H-71 | High | Informational | unit | one failed attempt |\n",
        encoding="utf-8",
    )

    assert M._load_poc_demotion_caps(scratch) == {}
    assert V._poc_demotion_caps_for_validator(scratch) == {}
    assert V._expected_report_index_severities(scratch)["H-71"] == "High"


def test_positive_execution_authority_is_unchanged(tmp_path: Path) -> None:
    project = tmp_path / "project"
    scratch = tmp_path / "scratch"
    _bound_execution(scratch, project, status="PASS")
    materialize_execution_scope_assessments(scratch, build_root=project)
    record = _rich_record(scratch, "H-71")
    _explicit_scope_rewind(scratch, "H-71")
    (scratch / "verify_H-71.execution_scope_evidence.json").write_text(
        json.dumps(record, indent=2), encoding="utf-8"
    )
    materialize_execution_scope_assessments(scratch, build_root=project)
    (scratch / "verification_queue.md").write_text(
        "| Finding ID | Severity | Title | Location | PoC Class |\n"
        "|---|---|---|---|---|\n"
        "| H-71 | High | Candidate | src/Module.sol:10 | unit |\n",
        encoding="utf-8",
    )

    assert V._expected_report_index_statuses(scratch)["H-71"] == "VERIFIED"
    assert V._apply_poc_fail_demotions(scratch, "thorough") == []


@pytest.mark.parametrize(
    "relative_path",
    (
        "rules/phase6-report-prompts.md",
        "rules/report-template.md",
        "prompts/shared/v2/pipeline-full-audit.md",
        "prompts/shared/v2/phase6a-report-index.md",
        "prompts/shared/v2/phase6b-tier-writers.md",
        "agents/skills/daml/verification-protocol/SKILL.md",
    ),
)
def test_report_methodology_cannot_reintroduce_poc_fail_caps(
    relative_path: str,
) -> None:
    root = Path(__file__).resolve().parent.parent
    text = (root / relative_path).read_text(encoding="utf-8")
    assert "poc_demotions.md" not in text
    assert "POC-FAIL(original_sev)" not in text
    assert "poc_demotion_proposals" in text
    assert "MUST NOT lower severity" in text


def test_validator_retry_guidance_cannot_mint_poc_fail_severity_authority() -> None:
    text = Path(V.__file__).read_text(encoding="utf-8")
    assert "`POC-FAIL(original_sev)`" not in text
    assert "POC-FAIL-PROPOSAL(no-tier-change)" in text
