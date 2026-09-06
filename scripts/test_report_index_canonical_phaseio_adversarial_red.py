"""Fixture-first RED contracts for report-index canonical PhaseIO.

These tests define the semantic boundary that the staged canonical successor
must eventually enforce.  They intentionally fail against the current
implementation where byte-level transactionality exists without a closed
semantic-input authority or an executable semantic bundle gate.

The fixtures are generic, use only temporary scratchpads, and never modify
production state.
"""
from __future__ import annotations

import json
from pathlib import Path
import shutil
from types import SimpleNamespace
from typing import Any

import pytest

import closure_broker_v2 as C
import plamen_driver as D
import plamen_validators as V
from artifact_ledger import (
    record_work_unit_inputs,
    validate_work_unit_inputs,
)
from phase_io_contracts import PhaseIOContract, resolve_phase_io_contract
from plamen_types import L1_PHASES, SC_PHASES
import test_negative_closure_broker_live_cutover as NEG
import test_report_index_canonical_successor_a0_blocking as BASE
from test_l1_report_index_haltless_parity import _write_queue, _write_verify


def _phase(*, pipeline: str):
    phases = L1_PHASES if pipeline == "l1" else SC_PHASES
    return next(item for item in phases if item.name == "report_index")


def _config(
    project_root: Path,
    *,
    pipeline: str = "sc",
    backend: str = "claude",
    run_id: str | None = None,
) -> dict[str, Any]:
    scratchpad = project_root / ".scratchpad"
    scratchpad.mkdir(parents=True, exist_ok=True)
    return {
        "pipeline": pipeline,
        "mode": "thorough",
        "language": "rust" if pipeline == "l1" else "evm",
        "cli_backend": backend,
        "scratchpad": str(scratchpad),
        "project_root": str(project_root),
        "_run_id": run_id or f"canonical-red-{pipeline}",
        "_phase_io_model_attempts": {"report_index": 1},
    }


def _scratchpad_input_paths(contract: PhaseIOContract) -> set[str]:
    identities = {
        *contract.immutable_inputs,
        *contract.bounded_lookup_inputs,
    }
    return {
        identity.split(":", 1)[1]
        for identity in identities
        if identity.startswith("scratchpad:")
    }


def _copy_declared_scratchpad_inputs(
    source: Path,
    target: Path,
    contract: PhaseIOContract,
) -> None:
    target.mkdir(parents=True, exist_ok=True)
    for relative in sorted(_scratchpad_input_paths(contract)):
        src = source / relative
        if not src.is_file():
            continue
        dst = target / relative
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(src, dst)


def _is_under(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
    except (OSError, ValueError):
        return False
    return True


def _seed_one_completed_verifier(root: Path) -> None:
    _write_queue(root, [("H-1", "Medium")])
    _write_verify(root, "H-1", "Medium")
    assert V._verifier_output_has_completion_authority(root, "H-1")


def _canonical_contract(
    *,
    pipeline: str = "sc",
    backend: str = "claude",
) -> PhaseIOContract:
    return resolve_phase_io_contract(
        pipeline=pipeline,
        mode="thorough",
        ecosystem="rust" if pipeline == "l1" else "evm",
        backend=backend,
        phase="report_index",
        work_unit_id="canonicalize",
        exact_inputs=(
            "verification_queue.md",
            "verification_queue.work_items.json",
            "verification_queue.json",
        ),
    )


def _seed_staged_bundle(root: Path, *, pipeline: str = "sc") -> None:
    root.mkdir(parents=True, exist_ok=True)
    # The report fixture contains one Master row, so its authenticated
    # candidate denominator must contain that same identity.  Otherwise the
    # canonical empty-envelope transform correctly replaces the row before the
    # isolated semantic gate under test can observe it.
    _write_queue(root, [("H-1", "Medium")])
    (root / "report_index.md").write_bytes(
        BASE._report_index_bytes(medium_summary=1, medium_master=1)
    )
    (root / "report_coverage.md").write_bytes(BASE._coverage_bytes())
    if pipeline == "l1":
        # Deliberately inconsistent with the one active report-index row.
        (root / "report_records.json").write_text(
            '{"active":[],"excluded":[]}\n',
            encoding="utf-8",
        )
    # Seed the exact current status-projection receipt so isolation tests reach
    # the transform/denominator boundary they intend to exercise.
    V._project_report_index_status_authority(root)


def _neutralize_canonical_transforms(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # These fixtures isolate later canonical transforms over a deliberately
    # synthetic index row.  The authenticated-empty-denominator projection is
    # covered independently and would replace that row before the intended
    # boundary is reached.
    monkeypatch.setattr(
        D,
        "_ensure_report_index_canonical_zero_row_envelope",
        lambda *_args, **_kwargs: (False, []),
    )
    monkeypatch.setattr(
        D, "_repair_report_index_dropouts", lambda *_args, **_kwargs: []
    )
    monkeypatch.setattr(
        D, "_report_index_dropped_ids", lambda *_args, **_kwargs: []
    )
    monkeypatch.setattr(
        D, "_collect_verify_hypothesis_ids", lambda *_args, **_kwargs: set()
    )
    monkeypatch.setattr(
        D, "_backfill_report_coverage_dropouts", lambda *_args, **_kwargs: 0
    )
    monkeypatch.setattr(
        D, "_project_report_index_status_with_debt",
        lambda *_args, **_kwargs: [],
    )
    monkeypatch.setattr(
        D, "_repair_report_index_severity_provenance",
        lambda *_args, **_kwargs: [],
    )
    monkeypatch.setattr(
        D,
        "derive_report_index_summary_master_parity",
        lambda raw: SimpleNamespace(
            issues=[],
            repair_required=False,
            output_bytes=raw,
        ),
    )


def _derive_staged(
    root: Path,
    *,
    pipeline: str = "sc",
    backend: str = "claude",
) -> list[str]:
    _sealed_target, issues = D._derive_report_index_canonical_staged_target(
        root,
        contract=_canonical_contract(pipeline=pipeline, backend=backend),
        run_id=f"canonical-red-{pipeline}",
        predecessor_records={},
        fault=lambda _point: None,
    )
    return issues


def test_exact_read_trace_is_closed_over_canonical_contract(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Every actual semantic read must be a bound input or output prestate."""

    config = _config(tmp_path)
    root = Path(config["scratchpad"])
    _seed_one_completed_verifier(root)
    # Activate the report projection's strict-completion path without adding
    # the omitted verifier identity sidecar to the canonical denominator.
    (root / "verification_runtime_debt.json").write_text(
        '{"schema_version":"fixture.strict-completion.v1"}\n',
        encoding="utf-8",
    )
    (root / "config.json").write_text(
        json.dumps({"proven_only": True}) + "\n",
        encoding="utf-8",
    )
    contract, _launch = D._report_index_canonical_contract_and_launch(
        root, config
    )
    declared = _scratchpad_input_paths(contract)
    output_prestates = {item.path for item in contract.outputs}
    observed: set[str] = set()
    original_read_bytes = Path.read_bytes
    original_read_text = Path.read_text

    def track(path: Path) -> None:
        candidate = Path(path)
        if _is_under(candidate, root):
            observed.add(candidate.resolve().relative_to(root.resolve()).as_posix())

    def tracked_read_bytes(path: Path) -> bytes:
        track(path)
        return original_read_bytes(path)

    def tracked_read_text(path: Path, *args, **kwargs) -> str:
        track(path)
        return original_read_text(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_bytes", tracked_read_bytes)
    monkeypatch.setattr(Path, "read_text", tracked_read_text)

    expected = V._expected_report_index_severities(root)
    assert "H-1" in expected, "fixture must exercise report severity projection"
    undeclared = observed - declared - output_prestates
    assert undeclared == set(), (
        "canonical transforms performed semantic reads outside the PhaseIO "
        f"denominator: {sorted(undeclared)}"
    )


def test_staged_verifier_completion_authority_matches_live(
    tmp_path: Path,
) -> None:
    """Staging must preserve exact verifier completion, not only Markdown."""

    config = _config(tmp_path)
    root = Path(config["scratchpad"])
    _seed_one_completed_verifier(root)
    contract, _launch = D._report_index_canonical_contract_and_launch(
        root, config
    )
    stage = tmp_path / "staged-verifier"
    _copy_declared_scratchpad_inputs(root, stage, contract)

    assert V._verifier_output_has_completion_authority(root, "H-1")
    assert V._verifier_output_has_completion_authority(stage, "H-1"), (
        "canonical staging dropped a verifier identity/ownership authority "
        "required to reproduce the live completion decision"
    )


def test_staged_negative_closure_authority_matches_live(
    tmp_path: Path,
) -> None:
    """Central closure provider bundles are semantic inputs, not cache detail."""

    config = _config(tmp_path)
    root = Path(config["scratchpad"])
    NEG._materialize_exhaustive_provider_bundle(root)
    live = C.write_central_negative_closure_authority(root).resolve(
        work_item=NEG._work(),
        requested_effect=C.REFUTED_FULL,
    )
    assert live["status"] == C.AUTHORIZED

    contract, _launch = D._report_index_canonical_contract_and_launch(
        root, config
    )
    stage = tmp_path / "staged-negative-closure"
    _copy_declared_scratchpad_inputs(root, stage, contract)
    staged = C.load_central_negative_closure_authority(stage).resolve(
        work_item=NEG._work(),
        requested_effect=C.REFUTED_FULL,
    )

    assert staged == live, (
        "canonical staging did not preserve the provider-bundle denominator "
        "behind the live negative-closure decision"
    )


def test_checkpoint_bookkeeping_does_not_stale_canonical_input_receipt(
    tmp_path: Path,
) -> None:
    """Ordinary phase commits must not invalidate prior semantic receipts."""

    config = _config(tmp_path)
    root = Path(config["scratchpad"])
    checkpoint = root / "_v2_checkpoint.json"
    checkpoint.write_text(
        json.dumps({"run_id": config["_run_id"], "completed": []}) + "\n",
        encoding="utf-8",
    )
    contract, launch = D._report_index_canonical_contract_and_launch(
        root, config
    )
    record_work_unit_inputs(
        root,
        tmp_path,
        contract,
        launch,
        run_id=config["_run_id"],
    )
    assert validate_work_unit_inputs(
        root,
        tmp_path,
        contract,
        launch,
        run_id=config["_run_id"],
    ) == []

    checkpoint.write_text(
        json.dumps(
            {"run_id": config["_run_id"], "completed": ["report_index"]}
        )
        + "\n",
        encoding="utf-8",
    )
    assert validate_work_unit_inputs(
        root,
        tmp_path,
        contract,
        launch,
        run_id=config["_run_id"],
    ) == [], (
        "mutable checkpoint bookkeeping was bound as immutable canonical "
        "semantics; use an immutable run/snapshot authority projection"
    )


def test_downstream_report_disposition_does_not_change_canonical_digest(
    tmp_path: Path,
) -> None:
    """A later report-floor output cannot become a backward dependency."""

    config = _config(tmp_path)
    root = Path(config["scratchpad"])
    before, _launch = D._report_index_canonical_contract_and_launch(root, config)
    (root / "report_disposition_authority.json").write_text(
        '{"schema_version":"fixture.downstream.v1"}\n',
        encoding="utf-8",
    )
    after, _launch = D._report_index_canonical_contract_and_launch(root, config)

    assert after.digest == before.digest, (
        "materializing a downstream report-floor projection changed the "
        "already-defined canonical report-index contract"
    )


def test_canonical_input_enumeration_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Authority enumeration failure must not silently shrink exact_inputs."""

    config = _config(tmp_path)
    root = Path(config["scratchpad"])

    def fail(*_args, **_kwargs):
        raise RuntimeError("synthetic authority enumeration failure")

    monkeypatch.setattr(D, "build_report_disposition_authority", fail)
    with pytest.raises(
        (RuntimeError, ValueError),
        match="synthetic authority enumeration failure",
    ):
        D._report_index_canonical_contract_and_launch(root, config)


def test_status_projection_debt_blocks_canonical_receipt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A conservative output hash cannot erase visible status-projection debt."""

    stage = tmp_path / "status-debt"
    _seed_staged_bundle(stage)
    _neutralize_canonical_transforms(monkeypatch)
    monkeypatch.setattr(
        D,
        "_project_report_index_status_with_debt",
        lambda *_args, **_kwargs: ["SYNTHETIC_STATUS_AUTHORITY_DEBT"],
    )

    issues = _derive_staged(stage)
    assert "SYNTHETIC_STATUS_AUTHORITY_DEBT" in " ".join(issues)


def test_residual_dropout_blocks_canonical_receipt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Backfill returning zero may not bless a still-unaccounted candidate."""

    stage = tmp_path / "dropout-debt"
    _seed_staged_bundle(stage)
    _neutralize_canonical_transforms(monkeypatch)
    monkeypatch.setattr(
        D, "_report_index_dropped_ids", lambda *_args, **_kwargs: ["H-99"]
    )
    monkeypatch.setattr(
        D, "_backfill_report_coverage_dropouts", lambda *_args, **_kwargs: 0
    )

    issues = _derive_staged(stage)
    assert "dropout" in " ".join(issues).lower()


def test_severity_write_error_blocks_canonical_receipt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A repair telemetry row reporting a write error is not successful repair."""

    stage = tmp_path / "severity-write-debt"
    _seed_staged_bundle(stage)
    _neutralize_canonical_transforms(monkeypatch)
    monkeypatch.setattr(
        D,
        "_repair_report_index_severity_provenance",
        lambda *_args, **_kwargs: [
            {
                "report_id": "*",
                "internal": "(write error)",
                "llm_severity": "",
                "upstream_severity": "",
                "action": "could not write patched report_index.md: synthetic",
            }
        ],
    )

    issues = _derive_staged(stage)
    assert "could not write patched report_index.md" in " ".join(issues)


def test_l1_report_records_denominator_mismatch_blocks_canonical_receipt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """L1 report_records must be checked against the canonical index rows."""

    stage = tmp_path / "l1-record-mismatch"
    _seed_staged_bundle(stage, pipeline="l1")
    _neutralize_canonical_transforms(monkeypatch)

    issues = _derive_staged(stage, pipeline="l1")
    assert "report_records" in " ".join(issues)


def _prepare_transaction_case(
    project_root: Path,
    *,
    pipeline: str,
    backend: str,
) -> tuple[dict[str, Any], Path]:
    config = _config(
        project_root,
        pipeline=pipeline,
        backend=backend,
        run_id=f"backend-neutral-{pipeline}",
    )
    root = Path(config["scratchpad"])
    raw_index = BASE._report_index_bytes(
        medium_summary=1,
        medium_master=1,
    )
    if pipeline == "sc":
        BASE._prepare_model_attempt(config, raw_index)
    else:
        for name, payload in {
            "verification_queue.md": b"# Verification Queue\n",
            "finding_mapping.md": b"# Finding Mapping\n",
            "dedup_decisions.md": b"# Dedup Decisions\n",
        }.items():
            (root / name).write_bytes(payload)
        execute, issues = D._arm_report_index_mechanical_artifacts(root, config)
        assert execute and issues == []
        (root / "report_index.md").write_bytes(raw_index)
        (root / "report_coverage.md").write_bytes(BASE._coverage_bytes())
        (root / "report_records.json").write_text(
            json.dumps(
                {
                    "active": [
                        {
                            "finding_id": "H-1",
                            "report_id": "M-01",
                            "title": "Fixture finding H-1",
                        }
                    ],
                    "excluded": [],
                },
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n",
            encoding="utf-8",
        )
        assert D._record_report_index_mechanical_artifacts(root, config) == []
    return config, root


@pytest.mark.parametrize("pipeline", ["sc", "l1"])
def test_full_canonical_transaction_is_backend_neutral(
    tmp_path: Path,
    pipeline: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Claude and Codex must derive identical canonical semantic bundles.

    The upstream MODEL admission boundary has its own focused tests.  This
    fixture begins after equivalent model bytes are admitted and isolates the
    deterministic canonical DRIVER successor.
    """

    bundles: dict[str, dict[str, bytes]] = {}
    monkeypatch.setattr(
        D,
        "_validate_claude_phase_tool_boundary_outputs",
        lambda *_args, **_kwargs: [],
    )
    for backend in ("claude", "codex"):
        case_root = tmp_path / backend
        case_root.mkdir()
        config, root = _prepare_transaction_case(
            case_root,
            pipeline=pipeline,
            backend=backend,
        )
        assert D._run_report_index_canonicalization_transaction(
            _phase(pipeline=pipeline),
            root,
            config,
        ) == []
        contract, _launch = D._report_index_canonical_contract_and_launch(
            root, config
        )
        bundles[backend] = {
            item.path: (root / item.path).read_bytes()
            for item in contract.outputs
            if "canonicalization_receipt" not in item.path
            and item.path != "report_index_canonicalization_journal.json"
        }

    assert bundles["claude"] == bundles["codex"]
