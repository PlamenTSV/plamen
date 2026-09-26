from __future__ import annotations

from pathlib import Path

import pytest

import chain_tail_authority
import report_evidence_authority
import worker_transaction
from portable_path_contract import (
    PortablePathContractError,
    assert_lexically_bounded_relative_path,
)
from post_verify_lifecycle import parse_post_verify_candidate_proposals


def test_component_limit_is_encoded_bytes_not_python_characters() -> None:
    # 128 two-byte code points fit under a 255-character check but not under
    # a POSIX NAME_MAX=255 byte boundary.
    component = "é" * 128
    with pytest.raises(PortablePathContractError, match="component"):
        assert_lexically_bounded_relative_path(component + "/leaf.sol")


def test_total_path_and_control_delimiters_are_bounded_before_io() -> None:
    with pytest.raises(PortablePathContractError, match="1024"):
        assert_lexically_bounded_relative_path(("a/" * 520) + "leaf.sol")
    with pytest.raises(PortablePathContractError, match="control"):
        assert_lexically_bounded_relative_path("src/line\ncontracts/Vault.sol")


def test_worker_and_chain_boundaries_reject_overlong_component(tmp_path: Path) -> None:
    value = ("x" * 256) + ".json"
    with pytest.raises(worker_transaction.WorkerTransactionError):
        worker_transaction._relative_path(value, "worker output")
    with pytest.raises(chain_tail_authority.ChainTailAuthorityError):
        chain_tail_authority._safe_relative_path(
            tmp_path, value, field="chain artifact"
        )


def test_report_evidence_rejects_overlong_verify_name_before_stat(
    tmp_path: Path,
) -> None:
    value = "verify_" + ("x" * 256) + ".md"
    with pytest.raises(
        report_evidence_authority.ReportEvidenceError,
        match="lexically representable",
    ):
        report_evidence_authority._assessment_path_for_verify(tmp_path, value)


def test_post_verify_optional_source_name_degrades_without_filesystem_probe(
    tmp_path: Path,
) -> None:
    overlong = "verify_" + ("x" * 256) + ".md"
    (tmp_path / "post_verify_extract.md").write_text(
        "### Finding [VER-1]: Late candidate\n"
        "**Severity**: Medium\n"
        "**Location**: contracts/Vault.sol:L7\n"
        "**Root Cause**: A distinct state transition remains unverified.\n"
        f"**Source Verify File**: {overlong}\n",
        encoding="utf-8",
    )
    payload = parse_post_verify_candidate_proposals(tmp_path)
    assert payload["proposal_count"] == 1
    assert payload["proposals"][0]["primary_artifact"] == (
        "post_verify_extract.md"
    )
    assert payload["proposals"][0]["evidence_debt"] == (
        "source-repair-required"
    )
