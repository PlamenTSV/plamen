"""Fixture-first REDs for the frozen PhaseIO P0 inventory cut.

These tests intentionally describe authority that does not exist at the
2026-07-30 review boundary.  They cover only independent-review Cuts 0, 1,
and 3: prebind-before-plan fail-closed behavior, all late-floor callers, and
accepted-depth additive finalization.  They are not a general inventory
rewrite specification.
"""
from __future__ import annotations

import ast
import inspect
from pathlib import Path
import sys
import textwrap

import pytest


SCRIPTS = Path(__file__).resolve().parent
ROOT = SCRIPTS.parent
sys.path.insert(0, str(SCRIPTS))
sys.path.insert(0, str(ROOT))

import artifact_ledger as AL  # noqa: E402
import plamen_driver as D  # noqa: E402
import plamen_mechanical as M  # noqa: E402
from phase_io_contracts import resolve_phase_io_contract  # noqa: E402


CONFIG = {
    "pipeline": "sc",
    "mode": "thorough",
    "language": "evm",
    "cli_backend": "claude",
}


def _called_names(callable_object: object) -> set[str]:
    tree = ast.parse(textwrap.dedent(inspect.getsource(callable_object)))
    names: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if isinstance(node.func, ast.Name):
            names.add(node.func.id)
        elif isinstance(node.func, ast.Attribute):
            names.add(node.func.attr)
    return names


def _output_identities(contract: object) -> set[str]:
    return {output.identity for output in contract.outputs}


def test_current_ledger_prebind_marks_inventory_started_before_plan(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Cut 0: a typed prebind is authoritative even before plan materializes."""

    current_ledger = tmp_path / AL.LEDGER_NAME
    current_ledger.write_text("{}\n", encoding="utf-8")
    assert not (tmp_path / "inventory_aggregate_derivation.json").exists()
    assert not (tmp_path / "_artifact_ledger.json").exists()
    key = "sc/thorough/evm/claude/inventory/canonical_aggregate"
    monkeypatch.setattr(
        D,
        "read_artifact_ledger",
        lambda _root: {"work_units": {key: {"execution_state": "INPUT_BOUND"}}},
    )

    assert D._canonical_inventory_transaction_started(tmp_path, CONFIG) is True


def test_unreadable_current_ledger_fails_closed_as_started(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Cut 0: corrupt typed state is never permission for a legacy writer."""

    (tmp_path / AL.LEDGER_NAME).write_bytes(b"{corrupt typed state")

    def _unreadable(_root: Path) -> dict:
        raise AL.ArtifactLedgerError("fixture unreadable ledger")

    monkeypatch.setattr(D, "read_artifact_ledger", _unreadable)
    assert D._canonical_inventory_transaction_started(tmp_path, CONFIG) is True


def test_absent_current_ledger_does_not_invent_started_transaction(
    tmp_path: Path,
) -> None:
    """The fail-closed repair must not manufacture state on a fresh run."""

    assert not (tmp_path / AL.LEDGER_NAME).exists()
    assert D._canonical_inventory_transaction_started(tmp_path, CONFIG) is False


def test_stale_private_ledger_spelling_is_not_transaction_authority(
    tmp_path: Path,
) -> None:
    """Only the artifact-ledger module's canonical filename is authoritative."""

    (tmp_path / "_artifact_ledger.json").write_text("{}\n", encoding="utf-8")
    assert D._canonical_inventory_transaction_started(tmp_path, CONFIG) is False


@pytest.mark.parametrize(
    "control_name",
    (AL.LEDGER_NAME, "inventory_aggregate_derivation.json"),
)
def test_dangling_canonical_control_path_fails_closed(
    tmp_path: Path,
    control_name: str,
) -> None:
    """A broken link/reparse control object is corrupt state, not absence."""

    control = tmp_path / control_name
    try:
        control.symlink_to(tmp_path / "missing-control-target.json")
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"host cannot create test symlink: {exc}")
    assert D._canonical_inventory_transaction_started(tmp_path, CONFIG) is True


def test_inventory_transaction_start_survives_resume_config_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A scratchpad-global transaction cannot be reopened under new config."""

    (tmp_path / AL.LEDGER_NAME).write_text("{}\n", encoding="utf-8")
    old_key = "sc/thorough/evm/claude/inventory/canonical_aggregate"
    monkeypatch.setattr(
        D,
        "read_artifact_ledger",
        lambda _root: {"work_units": {old_key: {"execution_state": "INPUT_BOUND"}}},
    )
    drifted = {**CONFIG, "mode": "core", "cli_backend": "codex"}
    assert D._canonical_inventory_transaction_started(tmp_path, drifted) is True


def test_control_path_observation_error_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An lstat/I/O failure cannot be reinterpreted as a fresh scratchpad."""

    def _unobservable(_path: Path) -> bool:
        raise OSError("fixture control path cannot be observed")

    monkeypatch.setattr(D.rooted_io, "lexists", _unobservable)
    assert D._canonical_inventory_transaction_started(tmp_path, CONFIG) is True


@pytest.mark.parametrize(
    "owner",
    (
        D._inventory_degrade_floor_ok,
        D._prepare_l1_semantic_dedup_inventory,
        D._run_live_verify_queue_phase_boundary,
    ),
)
def test_every_live_late_floor_owner_uses_typed_successor_not_direct_floor(
    owner: object,
) -> None:
    """Cut 1: no production owner may publish the legacy four-file floor."""

    assert "ensure_findings_inventory_floor" not in _called_names(owner)


def test_late_floor_contract_has_capture_predecessor_and_one_postimage() -> None:
    """Cut 1: source capture and publication are separate typed generations."""

    capture = resolve_phase_io_contract(
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="claude",
        phase="inventory",
        work_unit_id="late_recall_floor.source_capture",
        exact_inputs=(
            "depth_fixture_findings.md",
            "findings_inventory.md",
            "finding_records.json",
            "_id_ledger.json",
        ),
        exact_outputs=("inventory_floor_source_manifest.json",),
    )
    publish = resolve_phase_io_contract(
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="claude",
        phase="inventory",
        work_unit_id="late_recall_floor",
        exact_inputs=(
            "inventory_floor_source_manifest.json",
            "findings_inventory.md",
            "finding_records.json",
            "_id_ledger.json",
        ),
        exact_outputs=(
            "findings_inventory.md",
            "finding_records.json",
            "_id_ledger.json",
            "inventory_floor_receipt.json",
        ),
    )

    assert _output_identities(capture) == {
        "scratchpad:inventory_floor_source_manifest.json"
    }
    assert _output_identities(publish) == {
        "scratchpad:findings_inventory.md",
        "scratchpad:finding_records.json",
        "scratchpad:_id_ledger.json",
        "scratchpad:inventory_floor_receipt.json",
    }
    assert all(output.writer == "DRIVER" for output in publish.outputs)


def test_late_floor_transaction_entrypoint_exposes_fault_and_resume_boundary() -> None:
    """Cut 1 fixture seam for the later public-file/ledger fault matrix."""

    runner = getattr(D, "_run_late_recall_floor_successor", None)
    assert callable(runner), (
        "missing typed late-floor successor entrypoint; the fixture matrix "
        "must exercise source CAS, every postimage boundary, and exact resume"
    )
    parameters = inspect.signature(runner).parameters
    assert {"scratchpad", "config", "consumer_phase"}.issubset(parameters)


def test_accepted_depth_owner_does_not_call_public_rmw_processors() -> None:
    """Cut 3: proposals are pure; one successor owns the canonical union."""

    called = _called_names(D._run_accepted_depth_postprocessors)
    assert not {
        "promote_niche_to_inventory",
        "promote_blind_spot_to_inventory",
        "run_enumeration_gate",
        "_run_gate_v_for_phase",
    } & called


def test_accepted_depth_additive_successor_contract_owns_canonical_union() -> None:
    """Cut 3: one typed generation owns inventory, records, IDs, and debt."""

    contract = resolve_phase_io_contract(
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="claude",
        phase="inventory",
        work_unit_id="additive_depth_finalize",
        exact_inputs=(
            "depth_additive_source_manifest.json",
            "findings_inventory.md",
            "finding_records.json",
            "_id_ledger.json",
        ),
        exact_outputs=(
            "findings_inventory.md",
            "finding_records.json",
            "_id_ledger.json",
            "depth_additive_finalization.json",
            "depth_additive_finalization_debt.json",
        ),
    )

    assert {
        "scratchpad:findings_inventory.md",
        "scratchpad:finding_records.json",
        "scratchpad:_id_ledger.json",
        "scratchpad:depth_additive_finalization.json",
        "scratchpad:depth_additive_finalization_debt.json",
    }.issubset(_output_identities(contract))
    assert all(output.writer == "DRIVER" for output in contract.outputs)


def test_failed_id_registration_cannot_return_an_uncommitted_preferred_id(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Cut 3: allocation failure is durable debt, never apparent success."""

    def _fail_registration(*_args: object, **_kwargs: object) -> dict:
        raise OSError("fixture ledger registration failure")

    monkeypatch.setattr(M, "id_ledger_register", _fail_registration)
    with pytest.raises(Exception, match="register|ledger|allocation|fixture"):
        M._allocate_inventory_ledger_id(
            tmp_path,
            preferred_id="INV-001",
            owner_phase="depth_finalize",
            owning_artifact="depth_fixture_findings.md",
            title="fixture candidate",
        )
