"""P1-H contract tests for legacy self-exclusion parsing.

These fixtures are deliberately target-neutral.  They specify the lossless
compatibility behavior required while markdown remains an accepted producer
format:

* parse only actual exclusion entries, not universe/context prose or headers;
* accept bracketed and plain canonical upstream referents;
* fold continuation lines into the owning entry;
* distinguish explicit empty/N/A receipts from suppressed candidates; and
* recover every substantive drop that lacks a real upstream referent.

Typed self-exclusion records are intentionally not exercised here: neither
validator currently exposes a typed input surface.  ``ExclusionDisposition``
is a later lifecycle-decision type and cannot safely stand in for a producer's
self-exclusion record.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

SCRIPTS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS_DIR))

import plamen_driver as D  # noqa: E402
from plamen_validators import (  # noqa: E402
    _validate_depth_self_exclusion,
    _validate_percontract_self_exclusion,
)


UPSTREAM = (
    "# Breadth outputs\n\n"
    "## Finding [B1-4]: First upstream candidate\n\n"
    "**Severity**: Medium\n"
    "**Location**: Alpha.sol:L10\n"
    "**Description**: upstream evidence.\n\n"
    "## Finding [RS1-3]: Second upstream candidate\n\n"
    "**Severity**: Low\n"
    "**Location**: Beta.sol:L20\n"
    "**Description**: upstream evidence.\n"
)


def _write(sp: Path, name: str, body: str) -> None:
    (sp / name).write_text(body, encoding="utf-8")


def _seed_upstream(sp: Path) -> None:
    _write(sp, "analysis_1.md", UPSTREAM)


def _pc(sp: Path, section: str) -> tuple[list[str], list[dict]]:
    _seed_upstream(sp)
    _write(
        sp,
        "analysis_percontract_1.md",
        "# Per-contract output\n\n## Findings\n\n" + section,
    )
    return _validate_percontract_self_exclusion(sp)


def _depth(sp: Path, section: str) -> tuple[list[str], list[dict]]:
    _seed_upstream(sp)
    _write(
        sp,
        "depth_state_findings.md",
        "# Depth output\n\n## Findings\n\n" + section,
    )
    return _validate_depth_self_exclusion(sp)


def test_p1h_percontract_section_scope_does_not_consume_peer_sections(tmp_path: Path):
    warnings, recovered = _pc(
        tmp_path,
        "- EXCLUDED [PC1-2] prose outside an exclusion section\n\n"
        "## Exclusion List\n\n"
        "- EXCLUDED [PC1-3] duplicate of [B1-4]\n\n"
        "## Notes\n\n"
        "- EXCLUDED [PC1-4] more prose outside the section\n",
    )
    assert (warnings, recovered) == ([], [])


def test_p1h_depth_section_scope_does_not_consume_peer_sections(tmp_path: Path):
    warnings, recovered = _depth(
        tmp_path,
        "- ABSORBED prose outside a self-exclusion section\n\n"
        "## Non-Reportable / Absorbed Candidates\n\n"
        "- ABSORBED duplicate of [B1-4]\n\n"
        "## Notes\n\n"
        "- ABSORBED more prose outside the section\n",
    )
    assert (warnings, recovered) == ([], [])


def test_p1h_percontract_suppresses_universe_and_nested_context(tmp_path: Path):
    warnings, recovered = _pc(
        tmp_path,
        "## Exclusion Universe\n\n"
        "- Source files supplied by the orchestrator\n"
        "- Candidate identifiers supplied by the orchestrator\n\n"
        "## Exclusion List\n\n"
        "### Context\n\n"
        "- Rows below are evaluated against the supplied universe\n",
    )
    assert (warnings, recovered) == ([], [])


def test_p1h_depth_suppresses_nested_context_and_universe(tmp_path: Path):
    warnings, recovered = _depth(
        tmp_path,
        "## Non-Reportable / Absorbed Candidates\n\n"
        "### Context and exclusion universe\n\n"
        "- Source files supplied by the orchestrator\n"
        "- Upstream identifiers: B1-4 and RS1-3\n",
    )
    assert (warnings, recovered) == ([], [])


def test_p1h_nested_candidate_heading_inside_universe_stays_suppressed(
    tmp_path: Path,
):
    warnings, recovered = _pc(
        tmp_path,
        "## Exclusion Universe\n\n"
        "### Exclusion List\n\n"
        "- Candidate identifiers supplied by the orchestrator\n",
    )
    assert (warnings, recovered) == ([], [])


def test_p1h_nested_matching_heading_does_not_duplicate_one_real_drop(
    tmp_path: Path,
):
    warnings, recovered = _depth(
        tmp_path,
        "## Non-Reportable / Absorbed Candidates\n\n"
        "### Self-dropped candidates\n\n"
        "- ABSORBED state mismatch at Gamma.sol:L90 can lock funds\n",
    )
    assert warnings and len(recovered) == 1


@pytest.mark.parametrize(
    "row",
    [
        "- EXCLUDED [PC1-7] duplicate of [B1-4]",
        "- EXCLUDED [PC1-7] duplicate of B1-4",
    ],
    ids=["bracketed", "plain"],
)
def test_p1h_percontract_recognizes_canonical_id_forms(
    tmp_path: Path, row: str
):
    warnings, recovered = _pc(tmp_path, f"## Exclusion List\n\n{row}\n")
    assert (warnings, recovered) == ([], [])


@pytest.mark.parametrize(
    "row",
    [
        "- ABSORBED duplicate of [B1-4]",
        "- ABSORBED duplicate of B1-4",
    ],
    ids=["bracketed", "plain"],
)
def test_p1h_depth_recognizes_canonical_id_forms(tmp_path: Path, row: str):
    warnings, recovered = _depth(
        tmp_path, f"## Non-Reportable / Absorbed Candidates\n\n{row}\n"
    )
    assert (warnings, recovered) == ([], [])


def test_p1h_percontract_skips_table_header_and_accounted_plain_row(tmp_path: Path):
    warnings, recovered = _pc(
        tmp_path,
        "## Exclusion List\n\n"
        "| Candidate | Status | Referent | Location | Reason |\n"
        "|---|---|---|---|---|\n"
        "| PC1-7 | EXCLUDED | B1-4 | Alpha.sol:L10 | already covered |\n",
    )
    assert (warnings, recovered) == ([], [])


def test_p1h_depth_skips_table_header_and_accounted_plain_row(tmp_path: Path):
    warnings, recovered = _depth(
        tmp_path,
        "## Non-Reportable / Absorbed Candidates\n\n"
        "| Candidate | Status | Referent | Reason |\n"
        "|---|---|---|---|\n"
        "| TF-7 | ABSORBED | B1-4 | already covered |\n",
    )
    assert (warnings, recovered) == ([], [])


def test_p1h_percontract_groups_continuation_with_upstream_referent(tmp_path: Path):
    warnings, recovered = _pc(
        tmp_path,
        "## Exclusion List\n\n"
        "- EXCLUDED [PC1-7] duplicate of the prior candidate\n"
        "  Referent: B1-4\n"
        "  Evidence: Alpha.sol:L10\n",
    )
    assert (warnings, recovered) == ([], [])


def test_p1h_depth_groups_continuation_with_upstream_referent(tmp_path: Path):
    warnings, recovered = _depth(
        tmp_path,
        "## Non-Reportable / Absorbed Candidates\n\n"
        "- ABSORBED duplicate of the prior candidate\n"
        "  Referent: B1-4\n"
        "  Evidence: Alpha.sol:L10\n",
    )
    assert (warnings, recovered) == ([], [])


def test_p1h_percontract_continuation_preserves_content_bearing_drop(tmp_path: Path):
    warnings, recovered = _pc(
        tmp_path,
        "## Exclusion List\n\n"
        "- EXCLUDED [PC1-8] accounting mismatch can lock assets\n"
        "  Location: Gamma.sol:L77\n"
        "  Impact: balances can become incorrect\n",
    )
    assert warnings and len(recovered) == 1
    assert recovered[0]["content_bearing"] is True
    assert recovered[0]["location"] == "gamma.sol:77"
    assert "Impact:" in recovered[0]["line_text"]


def test_p1h_percontract_skips_explicit_no_candidate_rows(tmp_path: Path):
    warnings, recovered = _pc(
        tmp_path,
        "## Exclusion List\n\n"
        "| Candidate | Status | Referent | Reason |\n"
        "|---|---|---|---|\n"
        "| N/A | NO_CANDIDATE | N/A | no candidates excluded |\n"
        "- No candidates were excluded.\n",
    )
    assert (warnings, recovered) == ([], [])


def test_p1h_depth_skips_explicit_no_candidate_rows(tmp_path: Path):
    warnings, recovered = _depth(
        tmp_path,
        "## Non-Reportable / Absorbed Candidates\n\n"
        "| Candidate | Status | Referent | Reason |\n"
        "|---|---|---|---|\n"
        "| N/A | NO_CANDIDATE | N/A | no candidates absorbed |\n"
        "- No candidates were absorbed or self-dropped.\n",
    )
    assert (warnings, recovered) == ([], [])


def test_p1h_percontract_substantive_referentless_drop_is_recovered(tmp_path: Path):
    warnings, recovered = _pc(
        tmp_path,
        "## Exclusion List\n\n"
        "- EXCLUDED [PC1-9] state mismatch at Gamma.sol:L90 can lock funds\n",
    )
    assert warnings and len(recovered) == 1
    assert recovered[0]["content_bearing"] is True
    assert recovered[0]["own_id"] == "PC1-9"


def test_p1h_depth_substantive_own_location_is_not_an_upstream_referent(
    tmp_path: Path,
):
    warnings, recovered = _depth(
        tmp_path,
        "## Non-Reportable / Absorbed Candidates\n\n"
        "- ABSORBED state mismatch at Gamma.sol:L90 can lock funds\n",
    )
    assert warnings and len(recovered) == 1
    assert recovered[0]["content_bearing"] is True


def test_p1h_percontract_accepts_multiple_plain_upstream_referents(tmp_path: Path):
    warnings, recovered = _pc(
        tmp_path,
        "## Exclusion List\n\n"
        "- EXCLUDED [PC1-7] consolidated into B1-4 and RS1-3\n",
    )
    assert (warnings, recovered) == ([], [])


def test_p1h_depth_accepts_multiple_plain_upstream_referents(tmp_path: Path):
    warnings, recovered = _depth(
        tmp_path,
        "## Non-Reportable / Absorbed Candidates\n\n"
        "- ABSORBED consolidated into B1-4 and RS1-3\n",
    )
    assert (warnings, recovered) == ([], [])


def test_p1h_percontract_replay_is_byte_idempotent(tmp_path: Path):
    first = _pc(
        tmp_path,
        "## Exclusion List\n\n"
        "- EXCLUDED [PC1-9] state mismatch at Gamma.sol:L90 can lock funds\n",
    )
    second = _validate_percontract_self_exclusion(tmp_path)
    assert second == first
    out = D._reemit_percontract_self_exclusions(tmp_path, first[1])
    assert out is not None
    before = out.read_bytes()
    out2 = D._reemit_percontract_self_exclusions(tmp_path, second[1])
    assert out2 == out and out.read_bytes() == before


def test_p1h_depth_replay_is_byte_idempotent(tmp_path: Path):
    first = _depth(
        tmp_path,
        "## Non-Reportable / Absorbed Candidates\n\n"
        "- ABSORBED state mismatch at Gamma.sol:L90 can lock funds, "
        "but assume an external actor repairs it\n",
    )
    second = _validate_depth_self_exclusion(tmp_path)
    assert second == first
    out = D._reemit_depth_self_exclusions(tmp_path, first[1])
    assert out is not None
    before = out.read_bytes()
    out2 = D._reemit_depth_self_exclusions(tmp_path, second[1])
    assert out2 == out and out.read_bytes() == before
