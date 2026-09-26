"""Registered producer delivery regressions from the SC Run C layout."""

from __future__ import annotations

import json
import sys
from pathlib import Path
import ast


SCRIPTS = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS))


def _finding(fid: str, title: str, location: str) -> str:
    return (
        f"## Finding [{fid}]: {title}\n\n"
        "**Verdict**: CONFIRMED\n"
        "**Step Execution**: ✓1,2,3,4,5,6,7\n"
        "**Rules Applied**: R4:✓, R5:✓\n"
        "**Preferred Tag**: CODE-TRACE\n"
        "**Severity**: High\n"
        f"**Location**: {location}\n"
        "**Description**: A concrete state transition violates its required invariant.\n"
        "**Impact**: An attacker can cause a material loss of protocol-held assets.\n"
    )


def test_da_contrastive_fields_are_substantive_registered_actions(
    tmp_path: Path,
) -> None:
    """Run86: DA cards must not become contentless at the shared boundary."""
    from plamen_parsers import _parse_depth_finding_blocks
    from plamen_validators import registered_finding_delivery_projection

    source = tmp_path / "depth_da_iter2_findings.md"
    source.write_text(
        "# Devil's Advocate Depth — Iteration 2\n\n"
        "### Finding [DA2-BLIND-A-1]: Unchecked payout on the native branch\n\n"
        "**Verdict**: CANDIDATE\n"
        "**Severity**: Medium\n"
        "**Location**: contracts/GatewaySend.sol:L354\n"
        "**Prior Path**: Compared ERC20 inbound and outbound calls.\n"
        "**Untested Path**: Native input skips transferFrom while a false-return "
        "ERC20 payout is ignored.\n"
        "**Fresh Evidence**: contracts/GatewaySend.sol:L354-L385.\n"
        "**Material Harm**: The recipient receives zero ERC20 on a successful callback.\n\n"
        "### Finding [DA2-REFUND-REENTRANCY]: Refund record survives external call\n\n"
        "**Verdict**: CANDIDATE\n"
        "**Severity**: High\n"
        "**Location**: contracts/GatewayCrossChain.sol:L581\n"
        "**Description**: Refund transfer calls an external token before deleting the record.\n"
        "**Impact**: A callback-capable token can attempt to draw pooled funds twice.\n",
        encoding="utf-8",
    )
    (tmp_path / "findings_inventory.md").write_text(
        "# Findings Inventory\n", encoding="utf-8"
    )
    item = _parse_depth_finding_blocks(source)[0]
    assert item["_content_bearing"] == "true"
    assert item["description"].startswith("Native input skips")
    assert item["_impact"].startswith("The recipient receives zero")
    assert item["_missing_required_fields"] == []
    action = next(
        row for row in registered_finding_delivery_projection(tmp_path)["actions"]
        if row["action_id"] == "DA2-BLIND-A-1"
    )
    assert action["content_bearing"] is True
    assert action["local_id_valid"] is True
    adjacent = next(
        row for row in registered_finding_delivery_projection(tmp_path)["actions"]
        if row["action_id"] == "DA2-REFUND-REENTRANCY"
    )
    assert adjacent["content_bearing"] is True
    assert adjacent["local_id_valid"] is True


def test_incidental_upgrade_prose_is_not_amendment_authority(tmp_path: Path) -> None:
    """Run C breadth layout: trailing coverage prose belongs to the block."""
    from plamen_parsers import _parse_depth_finding_blocks

    source = tmp_path / "analysis_access_control.md"
    source.write_text(
        "# Access-control analysis\n\n"
        + _finding(
            "B2-1",
            "Public helper exposes protocol-held funds",
            "contracts/Gateway.sol:286",
        )
        + "\n## Access-control coverage\n\n"
        "All configuration setters and upgrade authorization were reviewed.\n",
        encoding="utf-8",
    )

    rows = _parse_depth_finding_blocks(source)
    row = next(item for item in rows if item["id"] == "B2-1")
    # Breadth uses the FINDING contract, so its parser-level action remains
    # unset and the registered scan defaults it to NEW.  Crucially, prose may
    # not manufacture UPGRADE authority.
    assert row["action_kind"] == ""
    assert row["target_id"] == ""


def test_bare_inventory_source_id_is_repromoted_with_exact_artifact_identity(
    tmp_path: Path,
) -> None:
    """A semantic merge cannot strand a registered producer action as debt."""
    import plamen_validators as validators

    source_name = "analysis_core_state.md"
    (tmp_path / source_name).write_text(
        "# Core-state analysis\n\n"
        + _finding(
            "B1-1",
            "Duplicate delivery overwrites a live obligation",
            "contracts/Gateway.sol:539",
        )
        + "\n"
        + _finding(
            "B1-2",
            "State is cleared only after an untrusted transfer",
            "contracts/Gateway.sol:581",
        ),
        encoding="utf-8",
    )
    # This is the real Run C failure shape: semantic inventory rows retain
    # producer-local Source IDs but omit the producer artifact identity.
    (tmp_path / "findings_inventory.md").write_text(
        "# Findings Inventory\n\n"
        "### Finding [INV-001]: Duplicate delivery overwrites an obligation\n"
        "**Source IDs**: B1-1, OTHER-1\n"
        "**Severity**: High\n"
        "**Location**: contracts/Gateway.sol:539\n"
        "**Description**: Existing semantic inventory representation.\n\n"
        "### Finding [INV-002]: External call precedes state clearing\n"
        "**Source IDs**: B1-2, OTHER-2\n"
        "**Severity**: High\n"
        "**Location**: contracts/Gateway.sol:581\n"
        "**Description**: Existing semantic inventory representation.\n",
        encoding="utf-8",
    )
    # A stale depth-consensus artifact has no authority over breadth-owned
    # producer identities.  Run C had this exact cross-domain cascade after
    # depth-repair outputs changed its denominator.
    (tmp_path / "confidence_consensus_authority.json").write_text(
        "{}\n", encoding="utf-8"
    )

    promoted = validators._promote_depth_findings_to_inventory(tmp_path)
    assert promoted == ["B1-1", "B1-2"]
    inventory = (tmp_path / "findings_inventory.md").read_text(encoding="utf-8")
    assert inventory.count(f"**Primary Artifact**: {source_name}") == 2

    receipt = json.loads(
        (tmp_path / "finding_delivery_receipt.json").read_text(encoding="utf-8")
    )
    rows = {
        row["action_id"]: row
        for row in receipt["actions"]
        if row["source_file"] == source_name
    }
    assert rows["B1-1"]["disposition"] == "PROMOTED_FINDING"
    assert rows["B1-2"]["disposition"] == "PROMOTED_FINDING"
    assert receipt["residual_debt_count"] == 0

    # Exact action provenance makes a later promotion pass idempotent.
    assert validators._promote_depth_findings_to_inventory(tmp_path) == []
    inventory_after = (tmp_path / "findings_inventory.md").read_text(
        encoding="utf-8"
    )
    assert inventory_after == inventory


def test_explicit_target_bound_upgrade_remains_an_amendment(tmp_path: Path) -> None:
    from plamen_parsers import _parse_depth_finding_blocks

    source = tmp_path / "exploration_skeptic_findings.md"
    source.write_text(
        _finding(
            "SKEP-1",
            "Existing impact reaches an additional terminal state",
            "contracts/Gateway.sol:600",
        )
        + "**Action Kind**: UPGRADE\n"
        "**Target ID**: INV-001\n",
        encoding="utf-8",
    )
    row = _parse_depth_finding_blocks(source)[0]
    assert row["action_kind"] == "UPGRADE"
    assert row["target_id"] == "INV-001"


def test_registered_new_action_survives_low_confidence_and_stale_consensus(
    tmp_path: Path,
) -> None:
    import hashlib
    import plamen_validators as validators

    source = tmp_path / "depth_edge_case_findings.md"
    source.write_text(
        _finding(
            "DE-1",
            "Boundary transition remains unresolved",
            "contracts/Gateway.sol:581",
        ).replace("**Verdict**: CONFIRMED", "**Verdict**: CANDIDATE"),
        encoding="utf-8",
    )
    (tmp_path / "findings_inventory.md").write_text(
        "# Findings Inventory\n", encoding="utf-8"
    )
    (tmp_path / "confidence_scores.md").write_text(
        "| Finding ID | Composite |\n|---|---|\n| DE-1 | 0.10 |\n",
        encoding="utf-8",
    )
    (tmp_path / "confidence_consensus_authority.json").write_text(
        "{}\n", encoding="utf-8"
    )

    assert validators._promote_depth_findings_to_inventory(tmp_path) == ["DE-1"]
    inventory = (tmp_path / "findings_inventory.md").read_text(encoding="utf-8")
    source_sha = "sha256:" + hashlib.sha256(source.read_bytes()).hexdigest()
    assert (
        "**Source Actions**: "
        f"depth_edge_case_findings.md:DE-1@{source_sha}"
    ) in inventory
    receipt = json.loads(
        (tmp_path / "finding_delivery_receipt.json").read_text(encoding="utf-8")
    )
    row = next(item for item in receipt["actions"] if item["action_id"] == "DE-1")
    assert row["disposition"] == "PROMOTED_FINDING"
    assert receipt["residual_debt_count"] == 0


def test_current_delivery_semantics_do_not_trust_superseded_presentation_receipt(
    tmp_path: Path,
) -> None:
    """A coupled successor may supersede a clean receipt without semantic debt."""
    import plamen_validators as validators

    source = tmp_path / "depth_edge_case_findings.md"
    source.write_text(
        _finding(
            "DE-1",
            "Boundary transition remains unresolved",
            "contracts/Gateway.sol:581",
        ),
        encoding="utf-8",
    )
    (tmp_path / "findings_inventory.md").write_text(
        "# Findings Inventory\n", encoding="utf-8"
    )
    assert validators._promote_depth_findings_to_inventory(tmp_path) == ["DE-1"]
    assert validators._validate_registered_finding_delivery_receipt(tmp_path) == []
    assert validators._validate_current_registered_finding_delivery(tmp_path) == []

    # This JSON is a historical presentation of the prior generation, not
    # current semantic authority. Strict downstream receipt validation still
    # rejects it; phase-local current-state admission recomputes from the
    # registered source denominator and canonical inventory.
    receipt_path = tmp_path / "finding_delivery_receipt.json"
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    receipt["status"] = "DEGRADED"
    receipt["residual_debt"] = ["superseded presentation"]
    receipt_path.write_text(
        json.dumps(receipt, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    assert validators._validate_registered_finding_delivery_receipt(tmp_path)
    assert validators._validate_current_registered_finding_delivery(tmp_path) == []


def test_driver_has_no_production_call_to_legacy_raw_finding_promoter() -> None:
    """Canonical inventory transitions have one coupled-successor owner."""
    driver_path = SCRIPTS / "plamen_driver.py"
    tree = ast.parse(driver_path.read_text(encoding="utf-8"))
    calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "_promote_findings_with_semantic_invalidation"
    ]
    assert calls == []


def test_finding_index_heading_is_not_a_registered_action(tmp_path: Path) -> None:
    from plamen_parsers import _parse_depth_finding_blocks

    source = tmp_path / "depth_state_trace_findings.md"
    source.write_text(
        _finding(
            "DS-1",
            "State transition candidate",
            "contracts/Gateway.sol:539",
        )
        + "\n## Finding Index\n\n| ID | Title |\n|---|---|\n| DS-1 | candidate |\n",
        encoding="utf-8",
    )
    assert [row["id"] for row in _parse_depth_finding_blocks(source)] == ["DS-1"]


def test_live_depth_and_skeptic_id_aliases_are_registered(tmp_path: Path) -> None:
    from plamen_parsers import _parse_depth_finding_blocks

    cases = (
        ("depth_da_iter2_findings.md", "DA2-1"),
        ("exploration_skeptic_findings.md", "SKEPTIC-001"),
    )
    for name, finding_id in cases:
        source = tmp_path / name
        source.write_text(
            _finding(
                finding_id,
                "Live producer identity",
                "contracts/Gateway.sol:1",
            ),
            encoding="utf-8",
        )
        row = _parse_depth_finding_blocks(source)[0]
        assert row["id"] == finding_id
        assert row["_identity_status"] == "REGISTERED"
        assert row["_local_id_valid"] == "true"
