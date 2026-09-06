"""NC-2: authenticated verifier bytes are not terminal negative proof."""
from __future__ import annotations

from pathlib import Path

import pytest

from report_disposition_authority import (
    authorized_nonbody_internal_ids,
    reconcile_report_dispositions,
    validate_index_dispositions,
)
from test_report_disposition_authority_p0_r import RUN_ID, _setup


@pytest.mark.parametrize(
    "status",
    [
        "REFUTED",
        "FALSE_POSITIVE",
        "DROP_FALSE_POSITIVE",
        "INFEASIBLE",
        "CLEAR",
        "DROP_NON_SECURITY",
        "DROP_DESIGN_CONFIRMATION",
    ],
)
def test_model_only_negative_status_is_proposal_and_retained(
    tmp_path: Path, status: str
) -> None:
    sp, root, _item, original = _setup(
        tmp_path,
        status=status,
        severity="High",
        disposition="APPENDIX",
    )
    result = reconcile_report_dispositions(sp, root, run_id=RUN_ID)
    row = result["authority"]["rows"][0]
    assert result["moved"] == 0
    assert (root / "AUDIT_REPORT.md").read_text(encoding="utf-8") == original
    assert row["upstream_severity"] == "High"
    assert row["public_retention_target"] == "BODY"
    assert row["disposition_authorized"] is False
    assert row["visible_debt"] is True
    assert row["negative_proposal_status"] in {
        "REFUTED",
        "FALSE_POSITIVE",
        "DROP_FALSE_POSITIVE",
        "INFEASIBLE",
        "DROP_NON_SECURITY",
        "DROP_DESIGN_CONFIRMATION",
    }
    assert row["negative_proposal_reason"] == "NO_TYPED_NEGATIVE_CLOSURE_AUTHORITY"
    decisions = result["authority"]["finding_lifecycle"]["source_records"]["decisions"]
    assert all(
        decision["decision_kind"] not in {"REFUTED", "AUTHORIZED_ZERO_HARM"}
        for decision in decisions
    )


def test_unsupported_refutation_cannot_authorize_writer_exclusion(tmp_path: Path):
    sp, root, item, _original = _setup(
        tmp_path, status="REFUTED", disposition="BODY"
    )
    index = (sp / "report_index.md").read_text(encoding="utf-8")
    index = index.replace(
        f"| M-01 | {item.title} | Medium | INV-001 |\n", ""
    ).replace(
        "## Excluded Findings\n"
        "| Internal ID | Severity | Exclusion Reason |\n"
        "|---|---|---|\n",
        "## Excluded Findings\n"
        "| Internal ID | Severity | Exclusion Reason |\n"
        "|---|---|---|\n"
        "| INV-001 | Medium | model claimed refutation |\n",
    )
    (sp / "report_index.md").write_text(index, encoding="utf-8")
    reconcile_report_dispositions(sp, root, run_id=RUN_ID)
    assert "INV-001" not in authorized_nonbody_internal_ids(sp, run_id=RUN_ID)
    assert any(
        "INV-001" in issue and "unauthorized" in issue
        for issue in validate_index_dispositions(sp, run_id=RUN_ID)
    )


def test_positive_and_contested_statuses_keep_existing_body_semantics(tmp_path: Path):
    for status in ("CONFIRMED", "CONTESTED"):
        case = tmp_path / status.lower()
        case.mkdir()
        sp, root, _item, _original = _setup(
            case, status=status, disposition="BODY"
        )
        row = reconcile_report_dispositions(sp, root, run_id=RUN_ID)["authority"][
            "rows"
        ][0]
        assert row["public_retention_target"] == "BODY"
        assert row["negative_proposal_status"] == ""
