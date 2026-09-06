"""P0-H: inventory trust labels are claims, never downgrade authority."""
from __future__ import annotations

from pathlib import Path

from plamen_validators import _repair_report_index_severity_provenance
from test_l1_report_index_haltless_parity import (
    _write_coverage,
    _write_queue,
    _write_report_index,
    _write_verify,
)


def test_unbound_trusted_actor_tag_restores_upstream_severity(tmp_path: Path) -> None:
    _write_queue(tmp_path, [("INV-001", "High")])
    _write_verify(tmp_path, "INV-001", "High")
    _write_report_index(
        tmp_path,
        [("M-01", "Medium", "TRUSTED-ACTOR(High)", "INV-001")],
    )
    _write_coverage(tmp_path, [("INV-001", "PROMOTED", "M-01")])
    (tmp_path / "findings_inventory.md").write_text(
        "### Finding [INV-001]: privileged transition\n"
        "**Severity**: High\n"
        "**Location**: src/Admin.sol:L9\n"
        "**Assumption-Dep**: TRUSTED-ACTOR\n",
        encoding="utf-8",
    )

    repairs = _repair_report_index_severity_provenance(tmp_path)

    index = (tmp_path / "report_index.md").read_text(encoding="utf-8")
    assert "| H-01 |" in index and "| High |" in index
    assert "unsupported-downgrade-restored" in index
    assert repairs and repairs[0]["upstream_severity"] == "High"


def test_live_report_prompt_requires_typed_trust_evidence() -> None:
    prompt = Path("prompts/shared/v2/phase6a-report-index.md").read_text(
        encoding="utf-8"
    )
    assert "Inventory Agent is the sole authority" not in prompt
    assert "trust classification is a claim" in prompt
    assert "severity decision ledger" in prompt
