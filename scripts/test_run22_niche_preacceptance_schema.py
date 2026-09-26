"""Run22 regressions for the niche pre-acceptance finding-schema gate."""

from __future__ import annotations

import sys
from pathlib import Path


SCRIPTS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS_DIR))

from plamen_validators import (  # noqa: E402
    _validate_niche_findings_preacceptance,
    _validate_niche_findings_schema,
    _validate_semantic_gap_niche,
)
from recon_prepass import (  # noqa: E402
    _write_interface_parity_findings,
    _write_permissionless_setter_findings,
)


def _trigger(scratchpad: Path) -> None:
    (scratchpad / "semantic_invariants.md").write_text(
        "# Semantic Invariants\n\n- conditional_writes = 1\n",
        encoding="utf-8",
    )


def _sgi_finding(finding_id: str = "SGI-1") -> str:
    return f"""# Semantic Gap Investigation

## Finding [{finding_id}]: conditional tracking write

**Verdict**: UNRESOLVED
**Step Execution**: ✓1,2,3,4,5
**Rules Applied**: [R4:✓, R5:✓, R10:✓]
**Preferred Tag**: CODE-TRACE
**Severity**: Medium
**Location**: contracts/Tracker.sol:L42
**Description**: A conditional branch can leave the tracked total stale.
**Impact**: A later withdrawal can use accounting that excludes live value.
**Investigation Result**: UNRESOLVED because caller exclusivity is external.
**Material Harm** (MANDATORY): A depositor can receive less than their share.
**Evidence**: `tracked += amount` executes only when the branch is true.

Supporting trace: the write and later read are connected through the same
storage variable. This prose keeps the fixture above the historical 500-byte
existence threshold without substituting for any labeled schema field.
"""


def _standard_niche_finding(finding_id: str) -> str:
    return _sgi_finding(finding_id).replace(
        "**Investigation Result**: UNRESOLVED because caller exclusivity is external.\n",
        "",
    )


def test_semantic_gap_rejects_description_and_impact_substitution(
    tmp_path: Path,
) -> None:
    _trigger(tmp_path)
    malformed = _sgi_finding().replace(
        "**Description**: A conditional branch can leave the tracked total stale.\n",
        "",
    ).replace(
        "**Impact**: A later withdrawal can use accounting that excludes live value.\n",
        "",
    )
    (tmp_path / "niche_semantic_gap_findings.md").write_text(
        malformed,
        encoding="utf-8",
    )

    issues = _validate_semantic_gap_niche(tmp_path, "thorough")

    assert len(issues) == 1
    assert "Finding [SGI-1]" in issues[0]
    assert "Description" in issues[0]
    assert "Impact" in issues[0]
    assert "Investigation Result" not in issues[0]
    assert "Material Harm" not in issues[0]


def test_semantic_gap_valid_standard_format_niche_is_accepted(
    tmp_path: Path,
) -> None:
    _trigger(tmp_path)
    (tmp_path / "niche_semantic_gap_findings.md").write_text(
        _sgi_finding(),
        encoding="utf-8",
    )

    assert _validate_semantic_gap_niche(tmp_path, "thorough") == []


def test_refutation_investigation_result_carries_description_semantics(
    tmp_path: Path,
) -> None:
    """Negative proposals need one mechanism explanation, not two labels."""
    _trigger(tmp_path)
    artifact = _sgi_finding().replace(
        "**Verdict**: UNRESOLVED\n", "**Verdict**: REFUTATION_PROPOSAL\n"
    ).replace(
        "**Investigation Result**: UNRESOLVED because caller exclusivity is external.\n",
        "**Investigation Result**: REFUTATION_PROPOSAL. The traced consumer "
        "cannot observe the skipped write, so the hypothesized stale state "
        "has no reachable reader.\n",
    ).replace(
        "**Description**: A conditional branch can leave the tracked total stale.\n",
        "",
    )
    output = tmp_path / "niche_semantic_gap_findings.md"
    output.write_text(artifact, encoding="utf-8")

    assert _validate_semantic_gap_niche(tmp_path, "thorough") == []

    output.write_text(
        artifact.replace(
            "**Impact**: A later withdrawal can use accounting that excludes live value.\n",
            "",
        ),
        encoding="utf-8",
    )
    issues = _validate_semantic_gap_niche(tmp_path, "thorough")
    assert len(issues) == 1 and "Impact" in issues[0]


def test_semantic_gap_specific_fields_are_additive(tmp_path: Path) -> None:
    _trigger(tmp_path)
    output = tmp_path / "niche_semantic_gap_findings.md"
    for field_line, expected in (
        (
            "**Investigation Result**: UNRESOLVED because caller exclusivity is external.\n",
            "Investigation Result",
        ),
        (
            "**Material Harm** (MANDATORY): A depositor can receive less than their share.\n",
            "Material Harm",
        ),
    ):
        output.write_text(
            _sgi_finding().replace(field_line, ""),
            encoding="utf-8",
        )

        issues = _validate_semantic_gap_niche(tmp_path, "thorough")

        assert len(issues) == 1
        assert expected in issues[0]


def test_semantic_gap_valid_sibling_cannot_hide_malformed_candidate(
    tmp_path: Path,
) -> None:
    _trigger(tmp_path)
    malformed_sibling = _sgi_finding("SGI-2").replace(
        "**Impact**: A later withdrawal can use accounting that excludes live value.\n",
        "",
    )
    (tmp_path / "niche_semantic_gap_findings.md").write_text(
        _sgi_finding() + "\n" + malformed_sibling,
        encoding="utf-8",
    )

    issues = _validate_semantic_gap_niche(tmp_path, "thorough")

    assert len(issues) == 1
    assert "Finding [SGI-2]" in issues[0]
    assert "Impact" in issues[0]


def test_all_niches_validate_every_candidate_and_accept_valid_sibling(
    tmp_path: Path,
) -> None:
    malformed_sibling = _standard_niche_finding("EVT-2").replace(
        "**Description**: A conditional branch can leave the tracked total stale.\n",
        "",
    ).replace(
        "**Impact**: A later withdrawal can use accounting that excludes live value.\n",
        "",
    )
    (tmp_path / "niche_event_completeness_findings.md").write_text(
        _standard_niche_finding("EVT-1") + "\n" + malformed_sibling,
        encoding="utf-8",
    )

    issues = _validate_niche_findings_schema(tmp_path)

    assert len(issues) == 1
    assert "niche_event_completeness_findings.md" in issues[0]
    assert "Finding [EVT-2]" in issues[0]
    assert "Description" in issues[0]
    assert "Impact" in issues[0]
    assert "Finding [EVT-1]" not in issues[0]


def test_all_niches_accept_valid_standard_format_artifact(tmp_path: Path) -> None:
    (tmp_path / "niche_callback_receiver_safety_findings.md").write_text(
        _standard_niche_finding("CR-1"),
        encoding="utf-8",
    )

    assert _validate_niche_findings_schema(tmp_path) == []


def test_all_niches_preserve_completion_only_zero_result(tmp_path: Path) -> None:
    (tmp_path / "niche_interface_parity_findings.md").write_text(
        """<!-- PLAMEN_STATUS: COMPLETE -->
# Interface Parity

## No Findings

All externally callable interface selectors were compared against their
implementations. No candidate mismatch was identified in the bounded scope.
""",
        encoding="utf-8",
    )

    assert _validate_niche_findings_schema(tmp_path) == []


def test_combined_preacceptance_deduplicates_semantic_gap_schema_issue(
    tmp_path: Path,
) -> None:
    _trigger(tmp_path)
    (tmp_path / "niche_semantic_gap_findings.md").write_text(
        _sgi_finding().replace(
            "**Impact**: A later withdrawal can use accounting that excludes live value.\n",
            "",
        ),
        encoding="utf-8",
    )

    # Representation defects are deduplicated into visible debt and never
    # returned as a phase-blocking issue.
    assert _validate_niche_findings_preacceptance(tmp_path, "thorough") == []
    debt = (tmp_path / "validator_representation_debt.md").read_text(
        encoding="utf-8"
    )
    rows = [line for line in debt.splitlines() if "Finding [SGI-1]" in line]
    assert len(rows) == 1
    assert "Impact" in rows[0]


def test_permissionless_setter_producer_emits_full_niche_schema(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    scratchpad = project / ".scratchpad"
    scratchpad.mkdir(parents=True)
    (project / "Setter.sol").write_text(
        """contract Setter {
    uint256 public fee;
    function setFee(uint256 value) external { fee = value; }
}
""",
        encoding="utf-8",
    )

    assert _write_permissionless_setter_findings(
        scratchpad, project
    ) == "WRITTEN"
    output = (
        scratchpad / "niche_permissionless_setters_findings.md"
    ).read_text(encoding="utf-8")

    assert "### Finding [PSET-1]:" in output
    for field in (
        "Verdict",
        "Step Execution",
        "Rules Applied",
        "Preferred Tag",
        "Severity",
        "Location",
        "Description",
        "Impact",
        "Material Harm",
        "Evidence",
    ):
        assert f"**{field}**" in output
    assert _validate_niche_findings_schema(scratchpad) == []


def test_interface_parity_producer_emits_full_niche_schema(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    scratchpad = project / ".scratchpad"
    scratchpad.mkdir(parents=True)
    (project / "IParity.sol").write_text(
        "interface IParity { function declaredCall() external; }\n",
        encoding="utf-8",
    )
    (project / "Parity.sol").write_text(
        """contract Parity is IParity {
    function declaredCall() external {}
    function omittedCall() external {}
}
""",
        encoding="utf-8",
    )

    assert _write_interface_parity_findings(
        scratchpad, project
    ) == "WRITTEN"
    output = (
        scratchpad / "niche_interface_parity_findings.md"
    ).read_text(encoding="utf-8")

    assert "### Finding [IFACE-1]:" in output
    assert "**Severity**: Informational" in output
    for field in (
        "Verdict",
        "Step Execution",
        "Rules Applied",
        "Preferred Tag",
        "Severity",
        "Location",
        "Description",
        "Impact",
        "Material Harm",
        "Evidence",
    ):
        assert f"**{field}**" in output
    assert _validate_niche_findings_schema(scratchpad) == []
