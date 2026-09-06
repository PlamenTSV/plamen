from __future__ import annotations

import json
from pathlib import Path

import pytest

import inventory_reconciliation as reconciliation
import inventory_reemit_authority as R


def test_direct_three_output_materializer_is_not_a_public_production_api() -> None:
    assert "apply_inventory_reemit_repair" not in R.__all__
    assert not hasattr(R, "apply_inventory_reemit_repair")
    driver_source = (
        Path(__file__).with_name("plamen_driver.py")
    ).read_text(encoding="utf-8")
    assert "apply_inventory_reemit_repair" not in driver_source


def _finding(fid: str, title: str) -> str:
    return (
        f"### Finding [{fid}]: {title}\n"
        "**Severity**: Medium\n"
        "**Location**: src/Module.sol:L10\n"
        f"**Root Cause**: exact root for {title}\n"
        f"**Description**: exact description for {title}\n"
        f"**Impact**: exact impact for {title}\n"
        "**Verdict**: NEEDS_VERIFICATION\n\n"
    )


def _debt_fixture(root: Path) -> None:
    (root / "analysis_evm_a.md").write_text(
        _finding("TF-1", "source mechanism"), encoding="utf-8"
    )
    (root / "inventory_chunk_a.manifest.md").write_text(
        "# manifest\n\n"
        "| File | Signals |\n"
        "|---|---|\n"
        "| analysis_evm_a.md | 1 |\n",
        encoding="utf-8",
    )
    chunk = _finding("CC-1", "source mechanism").replace(
        "**Verdict**: NEEDS_VERIFICATION\n",
        "**Source IDs**: TF-1\n"
        "**Verdict**: NEEDS_VERIFICATION\n",
    )
    (root / "findings_inventory_chunk_a.md").write_text(
        "# Chunk\n\n" + chunk, encoding="utf-8"
    )
    inventory = _finding("INV-001", "rewritten mechanism").replace(
        "**Verdict**: NEEDS_VERIFICATION\n",
        "**Source IDs**: TF-1, CC-1\n"
        "**Verdict**: NEEDS_VERIFICATION\n",
    )
    (root / "findings_inventory.md").write_text(
        "# Finding Inventory\n\n## Findings\n\n" + inventory,
        encoding="utf-8",
    )
    assert reconciliation.reconcile_inventory(root, persist=False)["summary"][
        "HUMAN_REVIEW_DEBT"
    ] == 1


def _snapshot(root: Path) -> dict[str, bytes]:
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def _planned(root: Path) -> tuple[dict[str, object], dict[str, bytes]]:
    public_plan = R.build_inventory_reemit_plan(root)
    assert public_plan["status"] == "READY"
    intent = public_plan["intent"]
    assert isinstance(intent, dict)
    planned = R.plan_inventory_reemit_materialization(
        (root / "findings_inventory.md").read_bytes(),
        intent,
    )
    return intent, planned


def _materialize(root: Path, planned: dict[str, bytes]) -> None:
    for name, raw in planned.items():
        (root / name).write_bytes(raw)


def test_pure_planning_writes_nothing_and_matches_apply_exactly(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _debt_fixture(tmp_path)
    public_plan = R.build_inventory_reemit_plan(tmp_path)
    intent = public_plan["intent"]
    before = _snapshot(tmp_path)
    preimage = before["findings_inventory.md"]

    with monkeypatch.context() as patch:
        patch.setattr(
            R,
            "_atomic_write",
            lambda *_args, **_kwargs: (_ for _ in ()).throw(
                AssertionError("pure planning attempted a write")
            ),
        )
        planned = R.plan_inventory_reemit_materialization(preimage, intent)
        assert (
            R.plan_inventory_reemit_materialization(preimage, intent)
            == planned
        )

    assert set(planned) == {
        "inventory_reemit_intent.json",
        "findings_inventory.md",
        "inventory_reemit_receipt.json",
    }
    assert _snapshot(tmp_path) == before

    receipt = R._apply_inventory_reemit_repair_for_tests(
        tmp_path,
        prepared_intent=intent,
    )

    assert receipt == json.loads(
        planned["inventory_reemit_receipt.json"].decode("utf-8")
    )
    assert {
        name: (tmp_path / name).read_bytes()
        for name in planned
    } == planned


def test_pure_planning_rejects_preimage_and_intent_tamper(
    tmp_path: Path,
) -> None:
    _debt_fixture(tmp_path)
    intent, _planned_artifacts = _planned(tmp_path)
    preimage = (tmp_path / "findings_inventory.md").read_bytes()

    with pytest.raises(
        R.InventoryReemitError,
        match="preimage differs from the prepared",
    ):
        R.plan_inventory_reemit_materialization(preimage + b" ", intent)

    tampered_intent = dict(intent)
    tampered_intent["inventory_after_sha256"] = "0" * 64
    with pytest.raises(R.InventoryReemitError, match="intent digest is invalid"):
        R.plan_inventory_reemit_materialization(preimage, tampered_intent)


def test_exact_materialized_resume_validation_is_idempotent_and_write_free(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _debt_fixture(tmp_path)
    _intent, planned = _planned(tmp_path)
    _materialize(tmp_path, planned)
    before = _snapshot(tmp_path)

    with monkeypatch.context() as patch:
        no_write = lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("validation attempted a write")
        )
        patch.setattr(R, "_atomic_write", no_write)
        patch.setattr(reconciliation, "_atomic_write", no_write)
        first = R.validate_inventory_reemit_materialization(tmp_path, planned)
        second = R.validate_inventory_reemit_materialization(tmp_path, planned)

    assert first == second == json.loads(
        planned["inventory_reemit_receipt.json"].decode("utf-8")
    )
    assert _snapshot(tmp_path) == before


@pytest.mark.parametrize(
    "artifact",
    [
        "inventory_reemit_intent.json",
        "findings_inventory.md",
        "inventory_reemit_receipt.json",
    ],
)
def test_materialized_byte_tamper_is_rejected(
    tmp_path: Path,
    artifact: str,
) -> None:
    _debt_fixture(tmp_path)
    _intent, planned = _planned(tmp_path)
    _materialize(tmp_path, planned)
    path = tmp_path / artifact
    path.write_bytes(path.read_bytes() + b" ")

    with pytest.raises(
        R.InventoryReemitError,
        match=rf"{artifact} differs from the planned exact bytes",
    ):
        R.validate_inventory_reemit_materialization(tmp_path, planned)


def test_materialized_reconciliation_tamper_is_rejected(tmp_path: Path) -> None:
    _debt_fixture(tmp_path)
    _intent, planned = _planned(tmp_path)
    _materialize(tmp_path, planned)
    source = tmp_path / "analysis_evm_a.md"
    source.write_bytes(source.read_bytes().replace(b"exact impact", b"altered harm"))

    with pytest.raises(
        R.InventoryReemitError,
        match="does not replay exact candidate delivery",
    ):
        R.validate_inventory_reemit_materialization(tmp_path, planned)
