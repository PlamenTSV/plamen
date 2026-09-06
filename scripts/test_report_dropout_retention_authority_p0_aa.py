"""P0-AA: report-index dropouts require delivered human-review authority."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from plamen_mechanical import _build_human_review_appendix
from plamen_validators import (
    _backfill_report_coverage_dropouts,
    _report_index_dropped_ids,
)


def _fixture(tmp_path: Path) -> None:
    (tmp_path / "verify_H-1.md").write_text(
        "# Verification H-1\n\n"
        "**Verdict**: CONTESTED\n"
        "**Severity**: High\n"
        "**Location**: src/Vault.sol:L9\n"
        "**Description**: Substantive retained claim requiring review.\n",
        encoding="utf-8",
    )
    (tmp_path / "report_index.md").write_text(
        "# Report Index\n\n"
        "## Master Finding Index\n\n"
        "| Report ID | Title | Severity | Location | Verification | Trust Adj. | Internal Hypothesis |\n"
        "|---|---|---|---|---|---|---|\n"
        "| M-01 | Other | Medium | src/A.sol:L1 | VERIFIED | - | INV-999 |\n\n"
        "## Excluded Findings\n\n"
        "| Internal ID | Severity | Title | Reason |\n"
        "|---|---|---|---|\n",
        encoding="utf-8",
    )


def test_dropout_is_human_review_delivered_not_bare_deferred(tmp_path: Path) -> None:
    _fixture(tmp_path)
    assert _backfill_report_coverage_dropouts(tmp_path) == 1

    coverage = (tmp_path / "report_coverage.md").read_text(encoding="utf-8")
    assert "HUMAN_REVIEW_DELIVERED" in coverage
    assert "DEFERRED" not in coverage
    projection = tmp_path / "report_semantic_report_dropouts.md"
    projection_text = projection.read_text(encoding="utf-8")
    assert "H-1" in projection_text
    assert "Substantive retained claim requiring review" in projection_text
    assert "H-1" in _build_human_review_appendix(tmp_path)

    receipt = json.loads(
        (tmp_path / "report_dropout_retention.json").read_text(encoding="utf-8")
    )
    assert receipt["schema_version"] == "plamen.report_dropout_retention.v1"
    assert receipt["rows"][0]["retention_target"] == "HUMAN_REVIEW"
    assert receipt["rows"][0]["source_sha256"] == hashlib.sha256(
        (tmp_path / "verify_H-1.md").read_bytes()
    ).hexdigest()
    assert _report_index_dropped_ids(tmp_path) == []


def test_missing_or_tampered_delivery_cannot_acknowledge_dropout(tmp_path: Path) -> None:
    _fixture(tmp_path)
    assert _backfill_report_coverage_dropouts(tmp_path) == 1
    projection = tmp_path / "report_semantic_report_dropouts.md"
    projection.write_text("tampered\n", encoding="utf-8")
    assert _report_index_dropped_ids(tmp_path) == ["H-1"]


def test_retention_write_is_idempotent(tmp_path: Path) -> None:
    _fixture(tmp_path)
    assert _backfill_report_coverage_dropouts(tmp_path) == 1
    receipt = (tmp_path / "report_dropout_retention.json").read_bytes()
    projection = (tmp_path / "report_semantic_report_dropouts.md").read_bytes()
    coverage = (tmp_path / "report_coverage.md").read_bytes()
    assert _backfill_report_coverage_dropouts(tmp_path) == 0
    assert (tmp_path / "report_dropout_retention.json").read_bytes() == receipt
    assert (tmp_path / "report_semantic_report_dropouts.md").read_bytes() == projection
    assert (tmp_path / "report_coverage.md").read_bytes() == coverage
