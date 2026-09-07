from pathlib import Path
import uuid

import pytest

import plamen_driver as D


def _typed_recon_commit(state: str, run_id: str) -> D.PhaseCommit:
    failure = D.GateFailure(
        gate_id="recon.methodology_selection.binding_manifest",
        gate_class="METHODOLOGY_SELECTION",
        message="typed recon selection debt",
        fallback_policy="CONSUME_WITH_DEBT",
        schema_id="recon.methodology_selection.binding_manifest/v1",
    )
    return D.PhaseCommit(
        phase_name="recon",
        state=state,
        run_id=run_id,
        unresolved_failures=(failure,),
    )


def _phase(name: str, artifacts: list[str]) -> D.Phase:
    return D.Phase(name, ["Section"], artifacts, base_timeout_s=60, min_artifact_bytes=10)


def test_completed_phase_with_missing_artifact_rewinds_downstream(tmp_path: Path):
    checkpoint = D.Checkpoint(
        completed=["recon", "inventory", "report_index"],
        degraded=["report_index"],
    )
    phases = [
        _phase("recon", ["recon_summary.md"]),
        _phase("inventory", ["findings_inventory.md"]),
        _phase("report_index", ["report_index.md"]),
    ]
    (tmp_path / "recon_summary.md").write_text("substantial recon\n", encoding="utf-8")

    removed = D._reconcile_completed_checkpoint_artifacts(
        tmp_path, str(tmp_path), checkpoint, phases, "core"
    )

    assert removed == ["inventory", "report_index"]
    assert checkpoint.completed == ["recon"]
    assert checkpoint.degraded == []


@pytest.mark.parametrize(
    "state,completed",
    [
        ("COMPLETED_WITH_DEBT", ["recon"]),
        ("INCOMPLETE_WITH_DEBT", []),
    ],
)
def test_recon_finalization_preserves_typed_degradation_for_startup_reconciliation(
    tmp_path: Path, state: str, completed: list[str],
):
    run_id = str(uuid.uuid4())
    checkpoint = D.Checkpoint(
        completed=completed,
        degraded=["recon"],
        run_id=run_id,
        phase_commits={"recon": _typed_recon_commit(state, run_id)},
    )
    sentinel = tmp_path / "recon.degraded"
    sentinel.write_text("typed debt\n", encoding="utf-8")

    cleared = D._clear_stale_recon_degradation_after_finalization(
        checkpoint, tmp_path, finalization_authority=True
    )

    assert cleared is False
    assert checkpoint.degraded == ["recon"]
    assert sentinel.exists()
    assert checkpoint.validate_phase_names({"recon"}) == []


def test_recon_finalization_clears_only_legacy_stale_degradation(
    tmp_path: Path,
):
    checkpoint = D.Checkpoint(completed=["recon"], degraded=["recon"])
    sentinel = tmp_path / "recon.degraded"
    sentinel.write_text("legacy stale marker\n", encoding="utf-8")

    cleared = D._clear_stale_recon_degradation_after_finalization(
        checkpoint, tmp_path, finalization_authority=True
    )

    assert cleared is True
    assert checkpoint.degraded == []
    assert not sentinel.exists()
    assert checkpoint.validate_phase_names({"recon"}) == []


def test_completed_phase_reconciliation_keeps_valid_prefix(tmp_path: Path):
    checkpoint = D.Checkpoint(completed=["recon", "inventory"], degraded=[])
    phases = [
        _phase("recon", ["recon_summary.md"]),
        _phase("inventory", ["findings_inventory.md"]),
    ]
    (tmp_path / "recon_summary.md").write_text("substantial recon\n", encoding="utf-8")
    (tmp_path / "findings_inventory.md").write_text("substantial inventory\n", encoding="utf-8")

    removed = D._reconcile_completed_checkpoint_artifacts(
        tmp_path, str(tmp_path), checkpoint, phases, "core"
    )

    assert removed == []
    assert checkpoint.completed == ["recon", "inventory"]


def test_completed_instantiate_reconciliation_rejects_bad_manifest(tmp_path: Path):
    checkpoint = D.Checkpoint(completed=["recon", "instantiate", "breadth"], degraded=[])
    phases = [
        _phase("recon", ["recon_summary.md"]),
        _phase("instantiate", ["spawn_manifest.md"]),
        _phase("breadth", ["analysis_*.md"]),
    ]
    (tmp_path / "recon_summary.md").write_text("substantial recon\n", encoding="utf-8")
    (tmp_path / "spawn_manifest.md").write_text(
        "\n".join([
            "# Spawn Manifest",
            "| Template | Required? | Agent ID | Focus Area | Expected Output | Status |",
            "|---|---|---|---|---|---|",
            "| Verifier Template | YES | | | verify_.md | PENDING |",
        ]),
        encoding="utf-8",
    )

    removed = D._reconcile_completed_checkpoint_artifacts(
        tmp_path, str(tmp_path), checkpoint, phases, "core"
    )

    assert removed == ["instantiate", "breadth"]
    assert checkpoint.completed == ["recon"]


def test_recon_rc_parity_rejects_stub_handoff(tmp_path: Path):
    phase = _phase("recon", ["recon_summary.md", "build_status.md"])
    (tmp_path / "recon_summary.md").write_text(
        "# Recon Summary (stub)\n- Target: {TBD}\n- Skills to load: [LLM TO LIST]\n",
        encoding="utf-8",
    )
    (tmp_path / "build_status.md").write_text("", encoding="utf-8")

    issues = D._validate_rc_parity(phase, tmp_path, -2)

    assert any("recon_summary.md" in issue for issue in issues)
    assert any("build_status.md" in issue for issue in issues)


def test_completed_checkpoint_must_be_prefix_closed(tmp_path: Path):
    checkpoint = D.Checkpoint(completed=["report_index"], degraded=[])
    phases = [
        _phase("recon", ["recon_summary.md"]),
        _phase("inventory", ["findings_inventory.md"]),
        _phase("report_index", ["report_index.md"]),
    ]
    (tmp_path / "report_index.md").write_text("substantial report index\n", encoding="utf-8")

    removed = D._reconcile_completed_checkpoint_artifacts(
        tmp_path, str(tmp_path), checkpoint, phases, "core"
    )

    assert removed == ["report_index"]
    assert checkpoint.completed == []


def test_completed_inventory_uses_content_contract_not_just_size(tmp_path: Path):
    checkpoint = D.Checkpoint(
        completed=["recon", "inventory", "report_index"],
        degraded=["report_index"],
    )
    phases = [
        _phase("recon", ["recon_summary.md"]),
        _phase("inventory", ["findings_inventory.md"]),
        _phase("report_index", ["report_index.md"]),
    ]
    (tmp_path / "recon_summary.md").write_text("substantial recon\n", encoding="utf-8")
    (tmp_path / "findings_inventory.md").write_text(
        "# Inventory\n\nTotal Findings: 10\n\nThis file is large enough to pass a byte gate "
        "but has no detailed finding blocks.\n",
        encoding="utf-8",
    )
    (tmp_path / "report_index.md").write_text("substantial report index\n", encoding="utf-8")

    removed = D._reconcile_completed_checkpoint_artifacts(
        tmp_path, str(tmp_path), checkpoint, phases, "core"
    )

    assert removed == ["inventory", "report_index"]
    assert checkpoint.completed == ["recon"]
    assert checkpoint.degraded == []


def test_completed_report_index_requires_coverage_accounting(tmp_path: Path):
    checkpoint = D.Checkpoint(completed=["report_index"], degraded=[])
    phases = [_phase("report_index", ["report_index.md"])]
    (tmp_path / "report_index.md").write_text("substantial report index\n", encoding="utf-8")

    removed = D._reconcile_completed_checkpoint_artifacts(
        tmp_path, str(tmp_path), checkpoint, phases, "core"
    )

    assert removed == ["report_index"]
    assert checkpoint.completed == []


def test_checkpoint_load_rejects_schema_invalid_json(tmp_path: Path):
    (tmp_path / "_v2_checkpoint.json").write_text(
        '{"completed": "recon", "degraded": [], "rate_limited_at": null}',
        encoding="utf-8",
    )

    with pytest.raises(RuntimeError, match="completed must be a list"):
        D.Checkpoint.load(tmp_path)


def test_checkpoint_load_corrupt_json_keeps_blocking_file(tmp_path: Path):
    checkpoint = tmp_path / "_v2_checkpoint.json"
    checkpoint.write_text('{"completed": ["recon"],', encoding="utf-8")

    with pytest.raises(RuntimeError, match="Corrupt checkpoint"):
        D.Checkpoint.load(tmp_path)

    assert checkpoint.exists()
    assert (tmp_path / "_v2_checkpoint.corrupt").exists()
    assert list(tmp_path.glob("_v2_checkpoint.corrupt-*.json"))


def test_checkpoint_load_accepts_utf8_bom_json(tmp_path: Path):
    """Manual/editor repairs may save JSON with a UTF-8 BOM."""
    (tmp_path / "_v2_checkpoint.json").write_text(
        '{"completed": ["recon"], "degraded": [], "rate_limited_at": null}',
        encoding="utf-8-sig",
    )

    checkpoint = D.Checkpoint.load(tmp_path)

    assert checkpoint.completed == ["recon"]
    assert checkpoint.degraded == []


def test_checkpoint_save_writes_utf8_without_bom(tmp_path: Path):
    checkpoint = D.Checkpoint(
        completed=["recon"],
        degraded=[],
        rate_limited_at="depth",
    )

    checkpoint.save(tmp_path)

    raw = (tmp_path / "_v2_checkpoint.json").read_bytes()
    assert not raw.startswith(b"\xef\xbb\xbf")
    assert D.Checkpoint.load(tmp_path).rate_limited_at == "depth"
