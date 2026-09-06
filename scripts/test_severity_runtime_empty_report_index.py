from pathlib import Path

from severity_runtime import _legacy_report_index_rows


def test_empty_master_index_ignores_later_excluded_findings_table(
    tmp_path: Path,
) -> None:
    (tmp_path / "report_index.md").write_text(
        """# Report Index

## Master Finding Index

| Report ID | Title | Severity | Location | Verification | Trust Adj. | Internal Hypothesis ID |
|-----------|-------|----------|----------|--------------|------------|------------------------|

_No reportable findings exist in the authenticated candidate denominator._

## Excluded Findings

| Source ID | Reason |
|-----------|--------|

_No candidate required an excluded or non-body disposition._
""",
        encoding="utf-8",
    )

    assert _legacy_report_index_rows(tmp_path) == []
