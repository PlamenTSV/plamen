"""R0-2c: committed-invariant schema drift must recover, not merely warn."""

from __future__ import annotations

import json
import os
from pathlib import Path
from types import SimpleNamespace

import enumeration_gate as E
import plamen_parsers as P
import plamen_driver as D
import plamen_validators as V
from phase_io_contracts import LaunchSpec
from plamen_types import Phase


RUN_ID = "12345678-1234-4567-8abc-1234567890ab"


def _phase() -> Phase:
    return Phase(
        "exploration_skeptic",
        ["Phase 4b.6"],
        ["exploration_skeptic_findings.md"],
        base_timeout_s=120,
        modes={"thorough"},
        critical=False,
        model="sonnet",
    )


def _config(sp: Path) -> dict[str, object]:
    return {
        "project_root": str(sp.parent),
        "pipeline": "sc",
        "mode": "thorough",
        "language": "evm",
        "cli_backend": "codex",
        "_run_id": RUN_ID,
    }


def _scratchpad(tmp_path: Path) -> Path:
    root = tmp_path / "project"
    scratchpad = root / ".scratchpad"
    scratchpad.mkdir(parents=True)
    (scratchpad / "findings_inventory.md").write_text(
        "# Findings Inventory\n\n", encoding="utf-8"
    )
    return scratchpad


def _run_driver_recovery(sp: Path, monkeypatch) -> tuple[list[str], list[object]]:
    """Exercise the driver-owned coupled PhaseIO successor on synthetic inputs."""
    records = sp / "finding_records.json"
    if not records.exists():
        records.write_bytes(
            D.derive_preverify_finding_records_bytes(
                (sp / "findings_inventory.md").read_bytes()
            )
        )
    id_ledger = sp / "_id_ledger.json"
    if not id_ledger.exists():
        id_ledger.write_text(
            json.dumps(
                {"schema_version": "plamen.id_ledger.v1", "allocations": []},
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
    source_name = "exploration_skeptic_findings.md"
    source_identity = f"scratchpad:{source_name}"
    existing = D.read_artifact_ledger(sp).get("artifact_bindings", {}).get(
        source_identity
    )
    if not isinstance(existing, dict) or existing.get("status") != "ACTIVE":
        # Seed the canonical predecessor cohort through an actual DRIVER
        # PhaseIO commit, then seed the late-CI source through the ordinary
        # typed MODEL path.  The hardened recovery transaction intentionally
        # refuses raw fixture bytes without these exact producer authorities.
        canonical = (
            "findings_inventory.md",
            "finding_records.json",
            "_id_ledger.json",
        )
        predecessor = {name: (sp / name).read_bytes() for name in canonical}
        source_raw = (sp / source_name).read_bytes()
        for name in (*canonical, source_name):
            (sp / name).unlink()
        manifest_name = "inventory_floor_source_manifest.json"
        (sp / manifest_name).write_text("{}\n", encoding="utf-8")
        receipt_name = "inventory_floor_receipt.json"
        contract = D.resolve_phase_io_contract(
            pipeline="sc",
            mode="thorough",
            ecosystem="evm",
            backend="codex",
            phase="inventory",
            work_unit_id="late_recall_floor",
            exact_inputs=(manifest_name,),
            exact_outputs=(*canonical, receipt_name),
        )
        launch = LaunchSpec(
            work_unit_key=contract.key,
            pipeline=contract.pipeline,
            mode=contract.mode,
            ecosystem=contract.ecosystem,
            backend=contract.backend,
            model="driver",
            timeout_s=120,
            exec_mode="python",
            tool_policy=(),
        )
        D.record_work_unit_inputs(sp, sp.parent, contract, launch, run_id=RUN_ID)
        for name, raw in predecessor.items():
            (sp / name).write_bytes(raw)
        (sp / receipt_name).write_text("{}\n", encoding="utf-8")
        D.record_work_unit_artifacts(
            sp,
            sp.parent,
            contract,
            launch,
            run_id=RUN_ID,
            actor="DRIVER",
        )
        phase = _phase()
        config = _config(sp)
        assert D._bind_typed_model_phase_inputs(phase, sp, config) == []
        (sp / source_name).write_bytes(source_raw)
        assert D._record_typed_model_phase_artifacts(phase, sp, config) == []
    contracts: list[object] = []

    real_arm = D._arm_deterministic_driver_work_unit

    def arm(**kwargs):
        contracts.append(kwargs["contract"])
        return real_arm(**kwargs)

    monkeypatch.setattr(D, "_arm_deterministic_driver_work_unit", arm)
    issues = D._run_late_ci_recovery_transaction(
        phase=SimpleNamespace(name="exploration_skeptic"),
        config=_config(sp),
        scratchpad=sp,
    )
    return issues, contracts


def _namespaced_ci() -> str:
    return (
        "committed-invariant [C1-CI-1]\n"
        "Locus: src/Accounting.sol:L42\n"
        "Shape: CONSERVATION\n"
        "Assertion: total credited value equals total settled value\n"
        "Falsify Class: conservation\n"
        "Provenance: exploration skeptic clear C1\n"
    )


def test_namespaced_ci_is_harvested_with_exact_identity(tmp_path):
    sp = _scratchpad(tmp_path)
    (sp / "exploration_skeptic_findings.md").write_text(
        "# Exploration Skeptic\n\nNO-GAP at a value boundary\n\n" + _namespaced_ci(),
        encoding="utf-8",
    )
    candidates = E.compute_invariant_assertion_candidates(sp)
    assert len(candidates) == 1
    assert candidates[0]["source_tag"] == "INVARIANT:C1-CI-1"
    assert "C1-CI-1" in candidates[0]["key"]


def test_pure_validator_then_driver_recovers_namespaced_ci_coupled(
    tmp_path, monkeypatch
):
    sp = _scratchpad(tmp_path)
    (sp / "exploration_skeptic_findings.md").write_text(
        "# Exploration Skeptic\n\nNO-GAP at a value boundary\n\n" + _namespaced_ci(),
        encoding="utf-8",
    )
    before = {path.name: path.read_bytes() for path in sp.iterdir()}
    issues = V._validate_invariant_commitment(sp, "thorough", recover=False)
    assert {path.name: path.read_bytes() for path in sp.iterdir()} == before
    assert issues == []

    recovery_issues, contracts = _run_driver_recovery(sp, monkeypatch)
    inventory = (sp / "findings_inventory.md").read_text(encoding="utf-8")
    assert recovery_issues == []
    assert "INVARIANT:C1-CI-1" in inventory
    assert "NEEDS_VERIFICATION" in inventory
    assert not (sp / "invariant_commitment.ci_format_gap").exists()
    successor = contracts[-1]
    assert successor.phase == "inventory"
    assert {row.path for row in successor.outputs} == {
        "findings_inventory.md",
        "finding_records.json",
        "_id_ledger.json",
    }


def test_driver_recovery_ignores_fenced_reemit_source_identities(
    tmp_path, monkeypatch
):
    sp = _scratchpad(tmp_path)
    preserved = (
        "````markdown\n"
        "## Finding [B1-1]: Producer-local identity\n"
        "### Finding [INV-999]: Canonical-looking source decoy\n"
        "````"
    )
    (sp / "findings_inventory.md").write_text(
        "# Findings Inventory\n\n"
        "### Finding [INV-001]: Canonical predecessor\n"
        "**Severity**: Medium\n"
        "**Description**: Existing canonical mechanism.\n"
        "**Preserved Source Block**:\n"
        + preserved
        + "\n",
        encoding="utf-8",
    )
    assert P.id_ledger_register(
        sp,
        finding_id="INV-001",
        owner_phase="inventory",
        owner_attempt=1,
        owning_artifact="findings_inventory.md",
        title="Canonical predecessor",
    )["status"] == "REGISTERED"
    (sp / "exploration_skeptic_findings.md").write_text(
        "# Exploration Skeptic\n\nNO-GAP at a value boundary\n\n" + _namespaced_ci(),
        encoding="utf-8",
    )

    recovery_issues, _contracts = _run_driver_recovery(sp, monkeypatch)

    assert recovery_issues == []
    inventory = (sp / "findings_inventory.md").read_text(encoding="utf-8")
    assert preserved in inventory
    records = json.loads(
        (sp / "finding_records.json").read_text(encoding="utf-8")
    )["records"]
    record_ids = {str(row["inventory_id"]) for row in records}
    assert "INV-001" in record_ids
    assert "B1-1" not in record_ids
    assert "INV-999" not in record_ids
    assert "INVARIANT:C1-CI-1" in inventory
    assert any(
        "Committed invariant C1-CI-1" in str(row.get("title") or "")
        for row in records
    )


def test_driver_recovery_rejects_raw_ci_source_without_producer_authority(
    tmp_path,
):
    sp = _scratchpad(tmp_path)
    source = sp / "exploration_skeptic_findings.md"
    source.write_text(
        "# Exploration Skeptic\n\nNO-GAP at a value boundary\n\n" + _namespaced_ci(),
        encoding="utf-8",
    )
    before = {path.name: path.read_bytes() for path in sp.iterdir()}

    issues = D._run_late_ci_recovery_transaction(
        phase=SimpleNamespace(name="exploration_skeptic"),
        config=_config(sp),
        scratchpad=sp,
    )

    assert issues == [
        "late-CI source producer authority failed: ValueError: "
        "exploration_skeptic_findings.md: producer binding is absent"
    ]
    assert {
        path.name: path.read_bytes()
        for path in sp.iterdir()
        if path.name != "_artifact_state.lock"
    } == before


def test_driver_ci_recovery_is_idempotent_and_validator_preserves_stale_marker(
    tmp_path, monkeypatch
):
    sp = _scratchpad(tmp_path)
    (sp / "exploration_skeptic_findings.md").write_text(
        "# Exploration Skeptic\n\nDOWNGRADE at a value boundary\n\n" + _namespaced_ci(),
        encoding="utf-8",
    )
    stale = sp / "invariant_commitment.ci_format_gap"
    stale.write_text("stale")
    before = {path.name: path.read_bytes() for path in sp.iterdir()}
    assert V._validate_invariant_commitment(
        sp, "thorough", recover=False
    ) == []
    assert {path.name: path.read_bytes() for path in sp.iterdir()} == before
    assert stale.read_text(encoding="utf-8") == "stale"

    first_issues, _contracts = _run_driver_recovery(sp, monkeypatch)
    assert first_issues == []
    canonical = ("findings_inventory.md", "finding_records.json", "_id_ledger.json")
    once = {name: (sp / name).read_bytes() for name in canonical}
    second_issues, _contracts = _run_driver_recovery(sp, monkeypatch)
    assert second_issues == []
    twice = {name: (sp / name).read_bytes() for name in canonical}
    assert once == twice
    assert once["findings_inventory.md"].count(b"INVARIANT:C1-CI-1") == 1
    assert stale.read_text(encoding="utf-8") == "stale"


def test_byte_identical_late_ci_successor_preserves_physical_identity_and_siblings(
    tmp_path, monkeypatch
):
    """A no-op successor cannot poison its predecessor's coupled outputs."""

    sp = _scratchpad(tmp_path)
    (sp / "exploration_skeptic_findings.md").write_text(
        "# Exploration Skeptic\n\nNo additional commitment was emitted.\n",
        encoding="utf-8",
    )
    canonical = (
        "findings_inventory.md",
        "finding_records.json",
        "_id_ledger.json",
    )
    observed: dict[str, object] = {}
    real_vector = D._recoverable_driver_output_vector

    def capture_vector(**kwargs):
        before = {
            name: (
                (sp / name).read_bytes(),
                (sp / name).stat().st_dev,
                (sp / name).stat().st_ino,
                (sp / name).stat().st_mtime_ns,
            )
            for name in canonical
        }
        result = real_vector(**kwargs)
        after = {
            name: (
                (sp / name).read_bytes(),
                (sp / name).stat().st_dev,
                (sp / name).stat().st_ino,
                (sp / name).stat().st_mtime_ns,
            )
            for name in canonical
        }
        observed.update(before=before, after=after)
        return result

    monkeypatch.setattr(D, "_recoverable_driver_output_vector", capture_vector)
    issues, _contracts = _run_driver_recovery(sp, monkeypatch)

    assert issues == []
    assert observed["after"] == observed["before"]
    # The predecessor produced this receipt in the same coupled vector as the
    # canonical inventory trio.  Its strict authority must remain replayable
    # after the byte-identical canonical successor commits.
    assert D.semantic_input_prebind_producer_authority_issues(
        sp,
        sp.parent,
        ("scratchpad:inventory_floor_receipt.json",),
        run_id=RUN_ID,
    ) == []


def test_byte_identical_legacy_replace_is_semantically_idempotent(
    tmp_path, monkeypatch
):
    """Content/provenance authority survives an old exact-byte publisher.

    The shared publisher now avoids this churn, but durable PhaseIO replay
    must not depend on every future call site remembering that optimization.
    This recreates Run69's raw atomic replacement inside an armed successor.
    """

    sp = _scratchpad(tmp_path)
    (sp / "exploration_skeptic_findings.md").write_text(
        "# Exploration Skeptic\n\nNo additional commitment was emitted.\n",
        encoding="utf-8",
    )
    canonical = (
        "findings_inventory.md",
        "finding_records.json",
        "_id_ledger.json",
    )
    before: dict[str, int] = {}

    def legacy_replace(path: Path, raw: bytes) -> None:
        before.setdefault(path.name, path.stat().st_ino)
        temporary = path.with_name(f".{path.name}.legacy-replace.tmp")
        temporary.write_bytes(raw)
        os.replace(temporary, path)

    monkeypatch.setattr(
        D, "_materialize_driver_successor_bytes", legacy_replace
    )
    issues, _contracts = _run_driver_recovery(sp, monkeypatch)

    assert issues == []
    assert set(before) == set(canonical)
    assert all((sp / name).stat().st_ino != before[name] for name in canonical)
    assert D.semantic_input_prebind_producer_authority_issues(
        sp,
        sp.parent,
        ("scratchpad:inventory_floor_receipt.json",),
        run_id=RUN_ID,
    ) == []


def test_namespaced_ci_is_recognized_as_one_internal_id_not_suffix_alias():
    matches = P._INTERNAL_FINDING_ID_RE.findall(
        "committed-invariant [C1-CI-1]"
    )
    assert matches == ["C1-CI-1"]
    assert P._CLIENT_BODY_INTERNAL_ID_RE.search("see C1-CI-1")


def test_bare_and_shard_ci_forms_remain_supported(tmp_path):
    sp = _scratchpad(tmp_path)
    artifact = sp / "depth_token_flow_findings.md"
    artifact.write_text(
        _namespaced_ci().replace("C1-CI-1", "CI-1")
        + "\n"
        + _namespaced_ci().replace("C1-CI-1", "CI-A1"),
        encoding="utf-8",
    )
    tags = {
        candidate["source_tag"]
        for candidate in E.compute_invariant_assertion_candidates(sp)
    }
    assert tags == {"INVARIANT:CI-1", "INVARIANT:CI-A1"}
