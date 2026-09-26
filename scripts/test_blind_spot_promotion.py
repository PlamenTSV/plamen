"""M1 (recall): recover blind-spot scanner findings the inventory merge SCORED
but silently dropped. `promote_blind_spot_to_inventory` appends only the LEAKED
BLIND-* ids (absent from inventory), idempotently, append-only.

Pins a real regression: BLIND-B1/B2 promoted, BLIND-B3 (scored 0.47) dropped.
"""
from __future__ import annotations

import importlib
import os
import sys
from pathlib import Path


def _mech():
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    return importlib.import_module("plamen_mechanical")


def _blind_block(bid: str, title: str) -> str:
    return (
        f"### Finding [{bid}]: {title}\n"
        "**Severity**: Medium\n"
        "**Location**: `core/QOrg.sol:L330`\n"
        "**Description**: claim path reverts when the token is paused.\n"
        "**Impact**: claimants cannot withdraw during a pause.\n\n")


_INV = (
    "# Finding Inventory\n\n"
    "### Finding [INV-001]: renounceOwnership brick\n"
    "**Severity**: Low\n**Location**: `core/UmiaHub.sol:L21`\n"
    "**Source IDs**: BLIND-B1, CC-01\n"
    "**Description**: x\n**Impact**: y\n\n"
    "### Finding [INV-002]: ERC-165 omission\n"
    "**Severity**: Info\n**Location**: `core/QOrg.sol:L407`\n"
    "**Source IDs**: BLIND-B2\n"
    "**Description**: x\n**Impact**: y\n")


def _setup(tmp_path: Path) -> Path:
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    (sp / "findings_inventory.md").write_text(_INV, encoding="utf-8")
    (sp / "blind_spot_b_findings.md").write_text(
        _blind_block("BLIND-B1", "renounceOwnership brick")
        + _blind_block("BLIND-B2", "ERC-165 omission")
        + _blind_block("BLIND-B3", "ERC20Pausable._update blocks liquidation claims"),
        encoding="utf-8")
    return sp


def test_recovers_only_the_leaked_blind_finding(tmp_path: Path):
    m = _mech()
    sp = _setup(tmp_path)
    parsed, recovered = m.promote_blind_spot_to_inventory(sp)
    assert parsed == 3
    assert recovered == 1, "only BLIND-B3 (absent from inventory) should be recovered"
    inv = (sp / "findings_inventory.md").read_text(encoding="utf-8")
    assert "BLIND-B3" in inv
    assert "Blind-Spot-Recovered Findings" in inv
    assert "LEAKED" in inv
    assert "**Primary Artifact**: blind_spot_b_findings.md" in inv
    assert "**Source Artifact Hash**: sha256:" in inv
    # B1/B2 not re-added (still single occurrence each as the original source id)
    assert inv.count("BLIND-B1") == 1 and inv.count("BLIND-B2") == 1


def test_idempotent(tmp_path: Path):
    m = _mech()
    sp = _setup(tmp_path)
    m.promote_blind_spot_to_inventory(sp)
    parsed, recovered = m.promote_blind_spot_to_inventory(sp)
    assert recovered == 0, "second run must not duplicate"
    assert (sp / "findings_inventory.md").read_text(encoding="utf-8").count("BLIND-B3") == 1


def test_all_present_recovers_nothing(tmp_path: Path):
    m = _mech()
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    (sp / "findings_inventory.md").write_text(
        _INV + "\n**Source IDs**: BLIND-B3\n", encoding="utf-8")
    (sp / "blind_spot_b_findings.md").write_text(
        _blind_block("BLIND-B3", "already present"), encoding="utf-8")
    parsed, recovered = m.promote_blind_spot_to_inventory(sp)
    assert recovered == 0


def test_no_blind_files_noop(tmp_path: Path):
    m = _mech()
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    (sp / "findings_inventory.md").write_text(_INV, encoding="utf-8")
    assert m.promote_blind_spot_to_inventory(sp) == (0, 0)


def test_id_regex_matches_letter_digit_suffix():
    m = _mech()
    assert m._BLIND_SPOT_HEADING_RE.search("### Finding [BLIND-B3]: x")
    assert m._BLIND_SPOT_HEADING_RE.search("## Finding [BLIND-A-1]: x")
    assert m._BLIND_SPOT_HEADING_RE.search("## Finding [BLIND-A12]: y")
    assert m._BLIND_SPOT_HEADING_RE.search("### Finding [BLIND-1]: z")


def test_run18_mixed_blind_ids_promote_with_exact_delivery_referents(
    tmp_path: Path,
):
    """Replay the two ID shapes and provenance gap observed in Run18."""
    import plamen_validators as V

    m = _mech()
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    (sp / "findings_inventory.md").write_text(
        "# Finding Inventory\n\n"
        "### Finding [INV-056]: Public helper can spend residual allowances\n"
        "**Severity**: High\n"
        "**Location**: contracts/GatewayTransferNative.sol:L286\n"
        "**Source IDs**: BLIND-B1 (blind-spot-recovered; LEAKED from "
        "blind_spot_b_findings.md)\n"
        "**Description**: Existing Run18-style recovery row lacks an exact "
        "producer-artifact binding.\n"
        "**Impact**: Adapter-held tokens can be redirected.\n\n"
        "### Finding [INV-057]: Privileged state changes lack events\n"
        "**Severity**: Informational\n"
        "**Location**: contracts/GatewayCrossChain.sol:L157\n"
        "**Source IDs**: BLIND-B2 (blind-spot-recovered; LEAKED from "
        "blind_spot_b_findings.md)\n"
        "**Description**: Existing Run18-style recovery row lacks an exact "
        "producer-artifact binding.\n"
        "**Impact**: Monitoring is impaired.\n",
        encoding="utf-8",
    )
    (sp / "blind_spot_a_findings.md").write_text(
        _blind_block(
            "BLIND-A-1",
            "Native-sentinel withdrawals can spend resident ZRC20 without receiving funds",
        ),
        encoding="utf-8",
    )
    (sp / "blind_spot_b_findings.md").write_text(
        _blind_block(
            "BLIND-B1",
            "Public helper can spend residual gateway allowances",
        )
        + _blind_block(
            "BLIND-B2",
            "Six privileged state changes lack protocol events",
        ),
        encoding="utf-8",
    )

    parsed, recovered = m.promote_blind_spot_to_inventory(sp)
    assert (parsed, recovered) == (3, 1)
    inventory = (sp / "findings_inventory.md").read_text(encoding="utf-8")
    assert inventory.count("BLIND-A-1") == 1
    assert inventory.count("BLIND-B1") == 1
    assert inventory.count("BLIND-B2") == 1
    assert inventory.count("**Primary Artifact**: blind_spot_b_findings.md") == 2
    assert inventory.count("**Primary Artifact**: blind_spot_a_findings.md") == 1

    scan = V._scan_registered_finding_delivery_sources(sp)
    payload = V._build_registered_finding_delivery_receipt_payload(
        sp, scan, inventory
    )
    relevant = {
        row["action_id"]: row["disposition"]
        for row in payload["actions"]
        if row["action_id"] in {"BLIND-A-1", "BLIND-B1", "BLIND-B2"}
    }
    assert relevant == {
        "BLIND-A-1": "PROMOTED_FINDING",
        "BLIND-B1": "PROMOTED_FINDING",
        "BLIND-B2": "PROMOTED_FINDING",
    }
    assert payload["residual_debt"] == []


if __name__ == "__main__":
    import pytest
    raise SystemExit(pytest.main([__file__, "-q"]))
