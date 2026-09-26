"""Strict source-action provenance across chunk -> canonical inventory."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import sys

import pytest


SCRIPTS = Path(__file__).resolve().parent
ROOT = SCRIPTS.parent
sys.path.insert(0, str(SCRIPTS))
sys.path.insert(0, str(ROOT))

from inventory_aggregate_authority import (  # noqa: E402
    InventoryAggregateError,
    build_inventory_aggregate_derivation,
    validate_inventory_aggregate_delivery,
)
from inventory_source_action_authority import (  # noqa: E402
    validate_inventory_chunk_source_actions,
)
from inventory_reconciliation import (  # noqa: E402
    _source_candidates,
    reconcile_inventory,
)
from inventory_reemit_authority import build_inventory_reemit_plan  # noqa: E402
from plamen_validators import (  # noqa: E402
    _build_registered_finding_delivery_receipt_payload,
    _inventory_structural_source_action_referents,
    _inventory_structural_source_hash_action_referents,
    _scan_registered_finding_delivery_sources,
)


def _source(fid: str) -> str:
    return (
        "# Breadth findings\n\n"
        f"## Finding [{fid}]: exact candidate\n"
        "**Severity**: Medium\n"
        "**Location**: src/A.sol:L10\n"
        "**Description**: exact candidate mechanism\n"
        "**Impact**: material effect if reachable\n"
    )


def _chunk(source_ref: str) -> str:
    return (
        "# Inventory Chunk\n\n"
        "### Finding [CC-01]: exact candidate\n"
        "**Severity**: Medium\n"
        "**Location**: src/A.sol:L10\n"
        f"**Source IDs**: {source_ref}\n"
        "**Verdict**: NEEDS_VERIFICATION\n"
        "**Root Cause**: exact candidate mechanism\n"
        "**Description**: exact candidate mechanism\n"
        "**Impact**: material effect if reachable\n"
    )


def _derive(tmp_path: Path, source_ref: str) -> str:
    source_name = "analysis_core_state.md"
    manifest_name = "inventory_chunk_a.manifest.md"
    chunk_name = "findings_inventory_chunk_a.md"
    (tmp_path / source_name).write_text(_source("B1-1"), encoding="utf-8")
    (tmp_path / manifest_name).write_text(
        "# manifest\n\n| File | Estimated signals |\n|---|---|\n"
        f"| {source_name} | 1 |\n",
        encoding="utf-8",
    )
    (tmp_path / chunk_name).write_text(_chunk(source_ref), encoding="utf-8")
    names = (source_name, manifest_name, chunk_name)
    bindings = [
        {
            "artifact": name,
            "sha256": hashlib.sha256((tmp_path / name).read_bytes()).hexdigest(),
        }
        for name in names
    ]
    payload = build_inventory_aggregate_derivation(
        tmp_path,
        derivation_kind="single_shard",
        run_id="strict-source-action-fixture",
        source_names=names,
        source_bindings=bindings,
    )
    return str(payload["output_payloads"]["findings_inventory.md"])


def test_aggregate_preserves_exact_registered_source_action_and_hash(
    tmp_path: Path,
) -> None:
    inventory = _derive(tmp_path, "analysis_core_state.md:B1-1")
    digest = "sha256:" + hashlib.sha256(
        (tmp_path / "analysis_core_state.md").read_bytes()
    ).hexdigest()

    assert (
        f"**Source Actions**: analysis_core_state.md:B1-1@{digest}"
        in inventory
    )
    assert _inventory_structural_source_action_referents(inventory) == {
        ("analysis_core_state.md", "B1-1"): {"INV-001"}
    }
    assert _inventory_structural_source_hash_action_referents(inventory) == {
        ("analysis_core_state.md", "B1-1", digest): {"INV-001"}
    }


def test_aggregate_does_not_authorize_nonexistent_or_bare_source_id(
    tmp_path: Path,
) -> None:
    with pytest.raises(
        InventoryAggregateError,
        match="lacks exactly one authenticated source action",
    ):
        _derive(tmp_path, "analysis_core_state.md:B1-2")

    bare_root = tmp_path / "bare"
    bare_root.mkdir()
    with pytest.raises(
        InventoryAggregateError,
        match="lacks exactly one authenticated source action",
    ):
        _derive(bare_root, "B1-1")


def test_chunk_gate_authenticates_source_actions_before_aggregate(
    tmp_path: Path,
) -> None:
    source_name = "analysis_core_state.md"
    chunk_name = "findings_inventory_chunk_a.md"
    (tmp_path / source_name).write_text(_source("B1-1"), encoding="utf-8")
    (tmp_path / chunk_name).write_text(
        _chunk(f"{source_name}:B1-1"), encoding="utf-8"
    )
    assert validate_inventory_chunk_source_actions(
        tmp_path,
        chunk_name=chunk_name,
        source_names=(source_name,),
    ) == []

    (tmp_path / chunk_name).write_text(
        _chunk(f"{source_name}:B1-2"), encoding="utf-8"
    )
    assert validate_inventory_chunk_source_actions(
        tmp_path,
        chunk_name=chunk_name,
        source_names=(source_name,),
    ) == ["source row 1 lacks exactly one authenticated source action"]


@pytest.mark.parametrize(
    "heading",
    (
        "## Candidate [PC2-1]: callback mismatch",
        "### **Candidate [PC2-1]**: callback mismatch",
        "## Issue PC2-1 — callback mismatch",
        "## [PC2-1]: callback mismatch",
    ),
)
def test_run52_candidate_action_grammar_matches_inventory_denominator(
    tmp_path: Path,
    heading: str,
) -> None:
    """A reconciliation-visible producer action must be authenticatable.

    DODO run52 placed ``analysis_percontract_GatewaySend.md:PC2-1`` in the
    driver-owned exact reconciliation set because the source used a Candidate
    heading.  The source-action authenticator recognized only Finding
    headings, making the chunk contract impossible to satisfy on every retry.
    """

    source_name = "analysis_percontract_GatewaySend.md"
    chunk_name = "findings_inventory_chunk_a.md"
    (tmp_path / source_name).write_text(
        "# GatewaySend localized rescan\n\n"
        f"{heading}\n\n"
        "**Disposition**: Excluded under RS-X; not emitted as a new finding.\n"
        "**Candidate Location**: contracts/GatewaySend.sol:L195\n"
        "**Mechanism**: Outer and decoded token domains are unbound.\n"
        "**Material Harm**: Retained user tokens can be lost.\n\n"
        "## No Findings\n\n"
        "No new producer-local finding is emitted.\n",
        encoding="utf-8",
    )
    (tmp_path / chunk_name).write_text(
        _chunk(f"{source_name}:PC2-1"), encoding="utf-8"
    )

    assert validate_inventory_chunk_source_actions(
        tmp_path,
        chunk_name=chunk_name,
        source_names=(source_name,),
    ) == []


def test_candidate_text_inside_fence_grants_no_source_action(
    tmp_path: Path,
) -> None:
    source_name = "analysis_percontract_GatewaySend.md"
    chunk_name = "findings_inventory_chunk_a.md"
    (tmp_path / source_name).write_text(
        "# Notes\n\n```markdown\n"
        "## Candidate [PC2-1]: example only\n"
        "**Mechanism**: This is quoted methodology, not an action.\n"
        "```\n",
        encoding="utf-8",
    )
    (tmp_path / chunk_name).write_text(
        _chunk(f"{source_name}:PC2-1"), encoding="utf-8"
    )

    assert validate_inventory_chunk_source_actions(
        tmp_path,
        chunk_name=chunk_name,
        source_names=(source_name,),
    ) == ["source row 1 lacks exactly one authenticated source action"]


def test_run53_bare_foreign_method_steps_are_not_inventory_actions(
    tmp_path: Path,
) -> None:
    """Registered producer grammar separates findings from RS step headings."""

    source_name = "analysis_percontract_IUniswapV2Router01.md"
    body = (
        "# Router localized rescan\n\n"
        "## Candidate [PC5-1]: explicit producer action\n"
        "**Severity**: Informational\n"
        "**Location**: contracts/interfaces/IUniswapV2Router01.sol:L1\n"
        "**Description**: Interface-only surface requires deployment review.\n"
        "**Impact**: No implementation-side harm is established in scope.\n\n"
        "### RS-1 — Cross-function state\n"
        "No state exists in the interface.\n\n"
        "### RS-2 — Asymmetric operations\n"
        "No implementation is present.\n\n"
        "### RS-3 — Paired encoding\n"
        "No local encoder is present.\n\n"
        "### RS-4 — Economic edges\n"
        "No fee implementation is present.\n\n"
        "### RS-5 — Time/lifecycle\n"
        "No lifecycle state is present.\n"
    )
    path = tmp_path / source_name
    path.write_text(body, encoding="utf-8")
    candidates, issues = _source_candidates(
        tmp_path,
        ({
            "artifact": source_name,
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "producer_key": "rescan_and_per_contract",
        },),
    )

    assert issues == []
    assert [row["source_finding_id"] for row in candidates] == ["PC5-1"]


def test_explicit_foreign_candidate_remains_fail_closed(
    tmp_path: Path,
) -> None:
    source_name = "analysis_percontract_IUniswapV2Router01.md"
    path = tmp_path / source_name
    path.write_text(
        "## Candidate [B1-1]: foreign producer identity\n"
        "**Severity**: Medium\n"
        "**Location**: contracts/interfaces/IUniswapV2Router01.sol:L1\n"
        "**Description**: Explicit candidate must not disappear.\n"
        "**Impact**: A real candidate would require typed disposition.\n",
        encoding="utf-8",
    )
    candidates, issues = _source_candidates(
        tmp_path,
        ({
            "artifact": source_name,
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "producer_key": "rescan_and_per_contract",
        },),
    )

    assert [row["source_finding_id"] for row in candidates] == ["B1-1"]
    assert issues == [
        f"{source_name}:B1-1 violates registered producer "
        "rescan_and_per_contract local-ID grammar"
    ]


def test_run20_shape_preserves_inline_identifiers_and_unicode_without_reemit(
    tmp_path: Path,
) -> None:
    source_name = "analysis_core_state.md"
    manifest_name = "inventory_chunk_a.manifest.md"
    chunk_name = "findings_inventory_chunk_a.md"
    mechanism = (
        "`onCall` authenticates the gateway — but `amount * feePercent` "
        "does not bind `context.sender` to `targetZRC20`."
    )
    (tmp_path / source_name).write_text(
        "## Finding [B1-1]: exact candidate\n"
        "**Severity**: High\n"
        "**Location**: src/A.sol:L10\n"
        f"**Description**: {mechanism}\n"
        "**Impact**: Funds — including refunds — can be drained.\n",
        encoding="utf-8",
    )
    (tmp_path / manifest_name).write_text(
        "# manifest\n\n| File | Signals |\n|---|---|\n"
        f"| {source_name} | 1 |\n",
        encoding="utf-8",
    )
    (tmp_path / chunk_name).write_text(
        "# Inventory Chunk\n\n## Per-Finding Detail\n\n"
        "### Finding [CC-01]: exact candidate\n"
        f"**Source IDs**: {source_name}:B1-1\n"
        "**Severity**: High\n"
        "**Location**: src/A.sol:L10\n"
        "**Preferred Tag**: CODE-TRACE\n"
        "**Verdict**: PARTIAL\n"
        f"**Root Cause**: {mechanism}\n"
        f"**Description**: {mechanism}\n"
        "**Impact**: Funds — including refunds — can be drained.\n",
        encoding="utf-8",
    )
    names = (source_name, manifest_name, chunk_name)
    bindings = [
        {
            "artifact": name,
            "sha256": hashlib.sha256((tmp_path / name).read_bytes()).hexdigest(),
        }
        for name in names
    ]
    payload = build_inventory_aggregate_derivation(
        tmp_path,
        derivation_kind="single_shard",
        run_id="run20-parser-shape",
        source_names=names,
        source_bindings=bindings,
    )
    for name, value in payload["output_payloads"].items():
        (tmp_path / name).write_text(str(value), encoding="utf-8")

    receipt = reconcile_inventory(tmp_path, persist=False)
    assert receipt["summary"] == {
        "AUTHORIZED_MERGE": 0,
        "AUTHORIZED_REFUTATION": 0,
        "HUMAN_REVIEW_DEBT": 0,
        "RETAINED": 1,
        "TOTAL": 1,
    }
    assert build_inventory_reemit_plan(tmp_path)["status"] == "NO_DEBT"
    assert receipt["candidates"][0]["source_root_cause"] == mechanism
    inventory = str(payload["output_payloads"]["findings_inventory.md"])
    assert inventory.count("**Source Actions**:") == 1
    assert mechanism in inventory
    assert "—" in inventory

    lossy = json.loads(json.dumps(payload))
    lossy_inventory = inventory.replace("`", "").replace(" * ", " ")
    lossy["output_payloads"]["findings_inventory.md"] = lossy_inventory
    lossy["output_sha256"]["findings_inventory.md"] = hashlib.sha256(
        lossy_inventory.encode("utf-8")
    ).hexdigest()
    assert any(
        "loses accepted root cause material" in issue
        for issue in validate_inventory_aggregate_delivery(tmp_path, lossy)
    )


def test_run21_shape_preserves_six_precondition_facets_across_29_deliveries(
    tmp_path: Path,
) -> None:
    """A passed chunk cannot acquire one-to-one debt in the DRIVER aggregate."""

    source_name = "analysis_core_state.md"
    manifest_name = "inventory_chunk_a.manifest.md"
    chunk_name = "findings_inventory_chunk_a.md"
    precondition_ids = {2, 7, 11, 16, 23, 29}
    operator_ids = {5, 8, 13, 15, 16, 23}
    source_blocks: list[str] = []
    chunk_blocks: list[str] = []
    for index in range(1, 30):
        source_id = f"B1-{index}"
        mechanism = (
            f"`feePercent{index}` applies `amount * feePercent / 1000` "
            "before delivery"
            if index in operator_ids
            else f"exact mechanism {index} preserves its branch"
        )
        impact = f"exact impact {index} reaches user funds"
        precondition = f"caller controls exact branch predicate {index}"
        source_blocks.append(
            f"## Finding [{source_id}]: exact candidate {index}\n"
            "**Severity**: Medium\n"
            f"**Location**: src/A.sol:L{index}\n"
            f"**Description**: {mechanism}\n"
            f"**Impact**: {impact}\n"
            + (
                f"**Preconditions**: {precondition}\n"
                if index in precondition_ids
                else ""
            )
        )
        chunk_blocks.append(
            f"### Finding [CC-{index:02d}]: exact candidate {index}\n"
            f"**Source IDs**: {source_name}:{source_id}\n"
            "**Severity**: Medium\n"
            f"**Location**: src/A.sol:L{index}\n"
            "**Preferred Tag**: CODE-TRACE\n"
            "**Verdict**: NEEDS_VERIFICATION\n"
            f"**Root Cause**: {mechanism}\n"
            f"**Description**: {mechanism}\n"
            f"**Impact**: {impact}\n"
            + (
                f"**Preconditions**: {precondition}\n"
                if index in precondition_ids
                else ""
            )
        )
    (tmp_path / source_name).write_text(
        "\n".join(source_blocks), encoding="utf-8"
    )
    (tmp_path / manifest_name).write_text(
        "# manifest\n\n| File | Signals |\n|---|---|\n"
        f"| {source_name} | 29 |\n",
        encoding="utf-8",
    )
    (tmp_path / chunk_name).write_text(
        "# Inventory Chunk\n\n## Per-Finding Detail\n\n"
        + "\n".join(chunk_blocks),
        encoding="utf-8",
    )

    chunk_reconciliation = reconcile_inventory(
        tmp_path, phase_name="inventory_chunk_a", persist=False
    )
    assert chunk_reconciliation["denominator_count"] == 29
    assert chunk_reconciliation["summary"]["HUMAN_REVIEW_DEBT"] == 0

    names = (source_name, manifest_name, chunk_name)
    bindings = [
        {
            "artifact": name,
            "sha256": hashlib.sha256((tmp_path / name).read_bytes()).hexdigest(),
        }
        for name in names
    ]
    payload = build_inventory_aggregate_derivation(
        tmp_path,
        derivation_kind="single_shard",
        run_id="run21-six-precondition-regression",
        source_names=names,
        source_bindings=bindings,
    )
    for name, value in payload["output_payloads"].items():
        (tmp_path / name).write_text(str(value), encoding="utf-8")

    final_reconciliation = reconcile_inventory(tmp_path, persist=False)
    assert final_reconciliation["denominator_count"] == 29
    assert final_reconciliation["summary"]["HUMAN_REVIEW_DEBT"] == 0
    assert final_reconciliation["summary"]["RETAINED"] == 29
    assert build_inventory_reemit_plan(tmp_path)["status"] == "NO_DEBT"
    inventory = str(payload["output_payloads"]["findings_inventory.md"])
    assert inventory.count("### Finding [INV-") == 29
    assert inventory.count("**Source Actions**:") == 29
    assert inventory.count("**Preconditions**:") == 6
    assert inventory.count("`amount * feePercent / 1000`") == 12
    for index in sorted(precondition_ids):
        assert f"caller controls exact branch predicate {index}" in inventory
    for index in sorted(operator_ids):
        assert f"`feePercent{index}` applies" in inventory


def test_delivery_replay_rejects_missing_and_duplicate_source_actions(
    tmp_path: Path,
) -> None:
    source_name = "analysis_core_state.md"
    manifest_name = "inventory_chunk_a.manifest.md"
    chunk_name = "findings_inventory_chunk_a.md"
    (tmp_path / source_name).write_text(_source("B1-1"), encoding="utf-8")
    (tmp_path / manifest_name).write_text("# manifest\n", encoding="utf-8")
    (tmp_path / chunk_name).write_text(
        _chunk(f"{source_name}:B1-1"), encoding="utf-8"
    )
    names = (source_name, manifest_name, chunk_name)
    bindings = [
        {
            "artifact": name,
            "sha256": hashlib.sha256((tmp_path / name).read_bytes()).hexdigest(),
        }
        for name in names
    ]
    payload = build_inventory_aggregate_derivation(
        tmp_path,
        derivation_kind="single_shard",
        run_id="delivery-negative-fixture",
        source_names=names,
        source_bindings=bindings,
    )

    missing = json.loads(json.dumps(payload))
    missing_inventory = re.sub(
        r"(?m)^\*\*Source Actions\*\*:.*\n",
        "",
        missing["output_payloads"]["findings_inventory.md"],
    )
    missing["output_payloads"]["findings_inventory.md"] = missing_inventory
    missing["output_sha256"]["findings_inventory.md"] = hashlib.sha256(
        missing_inventory.encode("utf-8")
    ).hexdigest()
    missing_issues = validate_inventory_aggregate_delivery(tmp_path, missing)
    assert any(
        "lacks exactly one Source Actions" in issue
        for issue in missing_issues
    )
    assert any("denominator mismatch" in issue for issue in missing_issues)

    duplicate = json.loads(json.dumps(payload))
    inventory = duplicate["output_payloads"]["findings_inventory.md"]
    block = inventory[inventory.index("### Finding [INV-001]"):]
    duplicate_block = block.replace("INV-001", "INV-002", 1)
    inventory = inventory.rstrip() + "\n\n" + duplicate_block
    duplicate["output_payloads"]["findings_inventory.md"] = inventory
    duplicate["output_sha256"]["findings_inventory.md"] = hashlib.sha256(
        inventory.encode("utf-8")
    ).hexdigest()
    records = json.loads(duplicate["output_payloads"]["finding_records.json"])
    second = dict(records["records"][0])
    second["inventory_id"] = "INV-002"
    records["records"].append(second)
    records_text = json.dumps(
        records,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ) + "\n"
    duplicate["output_payloads"]["finding_records.json"] = records_text
    duplicate["output_sha256"]["finding_records.json"] = hashlib.sha256(
        records_text.encode("utf-8")
    ).hexdigest()
    duplicate_issues = validate_inventory_aggregate_delivery(
        tmp_path, duplicate
    )
    assert any(
        "repeats an upstream source action" in issue
        for issue in duplicate_issues
    )
    assert any("finding count differs" in issue for issue in duplicate_issues)


def test_registered_delivery_requires_current_exact_source_action_hash(
    tmp_path: Path,
) -> None:
    current_hash = "sha256:" + "1" * 64
    stale_hash = "sha256:" + "0" * 64
    inventory = (
        "### Finding [INV-001]: exact candidate\n"
        "**Source IDs**: B1-1\n"
        f"**Source Actions**: analysis_core_state.md:B1-1@{stale_hash}\n"
    )
    (tmp_path / "findings_inventory.md").write_text(
        inventory, encoding="utf-8"
    )
    scan = {
        "actions": [{
            "producer_key": "breadth",
            "source_file": "analysis_core_state.md",
            "source_artifact_hash": current_hash,
            "action_id": "B1-1",
            "action_kind": "NEW",
            "origin_assessment": "",
            "disposition": "PENDING",
        }],
        "residual_debt": [],
        "artifacts": [],
    }

    stale = _build_registered_finding_delivery_receipt_payload(
        tmp_path, scan, inventory
    )
    assert stale["actions"][0]["disposition"] == "RESIDUAL_DEBT"

    exact_inventory = inventory.replace(stale_hash, current_hash)
    (tmp_path / "findings_inventory.md").write_text(
        exact_inventory, encoding="utf-8"
    )
    exact = _build_registered_finding_delivery_receipt_payload(
        tmp_path, scan, exact_inventory
    )
    assert exact["actions"][0]["disposition"] == "PROMOTED_FINDING"


def test_malformed_source_action_hash_and_path_alias_grant_no_referent() -> None:
    malformed = (
        "### Finding [INV-001]: malformed\n"
        "**Source Actions**: analysis_core_state.md:B1-1@sha256:BAD\n"
    )
    assert _inventory_structural_source_action_referents(malformed) == {}
    assert _inventory_structural_source_hash_action_referents(malformed) == {}

    aliased = (
        "### Finding [INV-001]: aliased\n"
        "**Source IDs**: B1-1\n"
        "**Primary Artifact**: shadow/analysis_core_state.md\n"
    )
    assert _inventory_structural_source_action_referents(aliased) == {}
    assert _inventory_structural_source_hash_action_referents(aliased) == {}


def test_duplicate_same_artifact_local_id_fails_aggregate_and_scan(
    tmp_path: Path,
) -> None:
    source_name = "analysis_core_state.md"
    manifest_name = "inventory_chunk_a.manifest.md"
    chunk_name = "findings_inventory_chunk_a.md"
    duplicate_source = _source("B1-1") + "\n" + _source("b1-1")
    (tmp_path / source_name).write_text(duplicate_source, encoding="utf-8")
    (tmp_path / manifest_name).write_text(
        "# manifest\n\n| File | Estimated signals |\n|---|---|\n"
        f"| {source_name} | 2 |\n",
        encoding="utf-8",
    )
    (tmp_path / chunk_name).write_text(
        _chunk(f"{source_name}:B1-1"), encoding="utf-8"
    )
    names = (source_name, manifest_name, chunk_name)
    bindings = [
        {
            "artifact": name,
            "sha256": hashlib.sha256((tmp_path / name).read_bytes()).hexdigest(),
        }
        for name in names
    ]

    # The aggregate still REFUSES a duplicated same-artifact local ID -- that
    # safety property is unchanged and is what this test exists for. What
    # changed is WHERE it refuses. `bind_exact_source_actions` no longer raises
    # on sight, because doing so failed a critical downstream phase over an
    # UPSTREAM artifact's naming that the inventory shard cannot repair (DODO
    # run38 `inventory_chunk_b`, killed by a per-contract worker writing
    # `### RS-1 ...` step labels as four separate finding headings).
    #
    # Instead the ambiguous identity now binds to NOTHING -- never to an
    # arbitrary claimant -- so the row that cited it fails its own
    # authentication check, and every unambiguous identity in the same artifact
    # still binds. The refusal is therefore more precise, not weaker: it names
    # the row that actually depends on the ambiguity.
    with pytest.raises(
        InventoryAggregateError,
        match="lacks exactly one authenticated source action",
    ):
        build_inventory_aggregate_derivation(
            tmp_path,
            derivation_kind="single_shard",
            run_id="duplicate-source-action-fixture",
            source_names=names,
            source_bindings=bindings,
        )

    scan = _scan_registered_finding_delivery_sources(tmp_path)
    assert any(
        "duplicate same-artifact local ID" in str(issue)
        for issue in scan["residual_debt"]
    )
    assert not any(
        row.get("source_file") == source_name
        and row.get("action_id") == "B1-1"
        for row in scan["actions"]
    )


def test_duplicate_source_binding_rows_are_rejected(tmp_path: Path) -> None:
    source_name = "analysis_core_state.md"
    manifest_name = "inventory_chunk_a.manifest.md"
    chunk_name = "findings_inventory_chunk_a.md"
    (tmp_path / source_name).write_text(_source("B1-1"), encoding="utf-8")
    (tmp_path / manifest_name).write_text("# manifest\n", encoding="utf-8")
    (tmp_path / chunk_name).write_text(
        _chunk(f"{source_name}:B1-1"), encoding="utf-8"
    )
    names = (source_name, manifest_name, chunk_name)
    bindings = [
        {
            "artifact": name,
            "sha256": hashlib.sha256((tmp_path / name).read_bytes()).hexdigest(),
        }
        for name in names
    ]
    bindings.append(dict(bindings[0]))

    with pytest.raises(InventoryAggregateError, match="duplicated"):
        build_inventory_aggregate_derivation(
            tmp_path,
            derivation_kind="single_shard",
            run_id="duplicate-source-binding-fixture",
            source_names=names,
            source_bindings=bindings,
        )
