"""Release-A A0/A1: report-index Summary parity authority and recovery.

The model proposal must be recorded before the deterministic Summary repair.
The repair is a separately armed DRIVER successor; it cannot rewrite Master
rows, adopt arbitrary crash-state bytes, or overwrite a prior model attempt.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path

import pytest

from artifact_ledger import read_artifact_ledger
import plamen_driver as D
import plamen_validators as V
from plamen_types import L1_PHASES, SC_PHASES


class _SimulatedCrash(BaseException):
    pass


def _index_bytes(*, medium_summary: int = 1, medium_master: int = 2) -> bytes:
    rows = [
        (
            f"| M-{ordinal:02d} | finding {ordinal} | Medium | "
            f"src/F.sol:L{ordinal} | VERIFIED | - | H-{ordinal} |"
        )
        for ordinal in range(1, medium_master + 1)
    ]
    return (
        "\n".join(
            [
                "# Report Index",
                "",
                "## Summary Counts",
                "",
                "| Severity | Count |",
                "|----------|-------|",
                "| Critical | 0 |",
                "| High | 0 |",
                f"| Medium | {medium_summary} |",
                "| Low | 0 |",
                "| Informational | 0 |",
                f"| Total | {medium_summary} |",
                "",
                "## Master Finding Index",
                "",
                (
                    "| Report ID | Title | Severity | Location | Verification | "
                    "Trust Adj. | Internal Hypothesis |"
                ),
                (
                    "|-----------|-------|----------|----------|--------------|"
                    "-----------|--------------------|"
                ),
                *rows,
                "",
                "## Excluded Findings",
                "",
                "| Source ID | Reason |",
                "|-----------|--------|",
                "| H-99 | explicitly retained outside the body |",
                "",
            ]
        )
        + "\n"
    ).encode("utf-8")


def _phase(config: dict | None = None):
    phases = (
        L1_PHASES
        if config is not None and config.get("pipeline") == "l1"
        else SC_PHASES
    )
    return next(phase for phase in phases if phase.name == "report_index")


def _config(
    tmp_path: Path, *, pipeline: str = "sc", backend: str = "codex"
) -> dict:
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir(parents=True, exist_ok=True)
    return {
        "pipeline": pipeline,
        "mode": "thorough",
        "language": "rust" if pipeline == "l1" else "evm",
        "cli_backend": backend,
        "scratchpad": str(scratchpad),
        "project_root": str(tmp_path),
        "_run_id": f"a0-a1-{pipeline}-{backend}",
        "_phase_io_model_attempts": {"report_index": 1},
    }


def _seed_model_inputs(config: dict) -> None:
    root = Path(config["scratchpad"])
    for name, payload in {
        "verification_queue.md": b"# Verification Queue\n",
        "report_index_coverage_seed.md": b"# Coverage Seed\n",
        "candidate_semantic_facets.md": b"# Candidate Facets\n",
        "candidate_semantic_facets.json": b"{}\n",
    }.items():
        (root / name).write_bytes(payload)


def _write_model_outputs(config: dict, report_index: bytes) -> None:
    root = Path(config["scratchpad"])
    (root / "report_index.md").write_bytes(report_index)
    (root / "report_coverage.md").write_text(
        "# Report Coverage\n\nNo disposition authority is derived here.\n",
        encoding="utf-8",
    )
    if config["pipeline"] == "l1":
        (root / "report_records.json").write_text(
            '{"active":[],"excluded":[]}\n', encoding="utf-8"
        )


def _prepare_model_attempt(
    config: dict,
    raw: bytes,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _seed_model_inputs(config)
    if config["cli_backend"] == "claude":
        # This simulates a successful production Claude write-boundary receipt.
        # Production remains fail-closed; the fixture does not relax it.
        monkeypatch.setattr(
            D, "_validate_claude_phase_tool_boundary_outputs",
            lambda *args, **kwargs: [],
        )
    assert D._bind_typed_model_phase_inputs(
        _phase(config), Path(config["scratchpad"]), config
    ) == []
    _write_model_outputs(config, raw)


def _digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def test_pure_derivation_changes_only_summary_and_preserves_master_bytes():
    raw = _index_bytes(medium_summary=1, medium_master=2)

    derivation = V.derive_report_index_summary_master_parity(raw)

    assert derivation.repair_required is True
    assert derivation.before_sha256 == _digest(raw)
    assert derivation.after_sha256 == _digest(derivation.output_bytes)
    assert derivation.output_bytes != raw
    assert V.validate_report_index_summary_master_parity_derivation(
        raw, derivation
    ) == []
    before_master = raw.split(b"## Master Finding Index", 1)[1]
    after_master = derivation.output_bytes.split(
        b"## Master Finding Index", 1
    )[1]
    assert after_master == before_master
    assert b"| Medium | 2 |" in derivation.output_bytes
    assert b"| Total | 2 |" in derivation.output_bytes


def test_clean_parity_has_no_successor(tmp_path: Path, monkeypatch):
    config = _config(tmp_path)
    raw = _index_bytes(medium_summary=2, medium_master=2)
    _prepare_model_attempt(config, raw, monkeypatch)

    assert D._run_report_index_summary_parity_successor(
        _phase(config), Path(config["scratchpad"]), config
    ) == []

    ledger = read_artifact_ledger(Path(config["scratchpad"]))
    model, _launch = D._typed_model_phase_contract_and_launch(
        _phase(config), Path(config["scratchpad"]), config
    )
    successor, _successor_launch = (
        D._report_index_summary_parity_contract_and_launch(config)
    )
    assert ledger["work_units"][model.key]["artifacts"][
        "scratchpad:report_index.md"
    ]["sha256"] == _digest(raw)
    assert successor.key not in ledger["work_units"]
    assert not (
        Path(config["scratchpad"])
        / "report_index_summary_parity_receipt.json"
    ).exists()


@pytest.mark.parametrize("pipeline", ("sc", "l1"))
@pytest.mark.parametrize("backend", ("claude", "codex"))
def test_model_preimage_then_driver_successor_across_pipeline_and_backend(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    pipeline: str,
    backend: str,
):
    config = _config(tmp_path, pipeline=pipeline, backend=backend)
    raw = _index_bytes(medium_summary=1, medium_master=2)
    _prepare_model_attempt(config, raw, monkeypatch)

    assert D._run_report_index_summary_parity_successor(
        _phase(config), Path(config["scratchpad"]), config
    ) == []

    root = Path(config["scratchpad"])
    repaired = (root / "report_index.md").read_bytes()
    ledger = read_artifact_ledger(root)
    model, _launch = D._typed_model_phase_contract_and_launch(
        _phase(config), root, config
    )
    successor, _successor_launch = (
        D._report_index_summary_parity_contract_and_launch(config)
    )
    model_record = ledger["work_units"][model.key]["artifacts"][
        "scratchpad:report_index.md"
    ]
    successor_record = ledger["work_units"][successor.key]["artifacts"][
        "scratchpad:report_index.md"
    ]
    assert model_record["writer"] == "MODEL"
    assert model_record["sha256"] == _digest(raw)
    assert successor_record["writer"] == "DRIVER"
    assert successor_record["sha256"] == _digest(repaired)
    assert repaired != raw
    assert raw.split(b"## Master Finding Index", 1)[1] == repaired.split(
        b"## Master Finding Index", 1
    )[1]
    assert ledger["artifact_bindings"]["scratchpad:report_index.md"][
        "owner_key"
    ] == successor.key
    receipt = json.loads(
        (root / "report_index_summary_parity_receipt.json").read_text(
            encoding="utf-8"
        )
    )
    assert receipt["model_work_unit_key"] == model.key
    assert receipt["before_sha256"] == _digest(raw)
    assert receipt["after_sha256"] == _digest(repaired)


@pytest.mark.parametrize(
    "crash_point",
    (
        "before_successor_arm",
        "after_successor_arm",
        "after_successor_report_write",
        "before_successor_commit",
    ),
)
def test_successor_resume_is_exact_at_every_crash_boundary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    crash_point: str,
):
    config = _config(tmp_path)
    raw = _index_bytes(medium_summary=1, medium_master=2)
    _prepare_model_attempt(config, raw, monkeypatch)
    fired = False

    def crash(point: str) -> None:
        nonlocal fired
        if point == crash_point and not fired:
            fired = True
            raise _SimulatedCrash(point)

    with pytest.raises(_SimulatedCrash):
        D._run_report_index_summary_parity_successor(
            _phase(config),
            Path(config["scratchpad"]),
            config,
            fault_inject=crash,
        )

    assert D._run_report_index_summary_parity_successor(
        _phase(config), Path(config["scratchpad"]), config
    ) == []
    expected = V.derive_report_index_summary_master_parity(raw).output_bytes
    assert (Path(config["scratchpad"]) / "report_index.md").read_bytes() == expected
    successor, launch = D._report_index_summary_parity_contract_and_launch(
        config
    )
    ledger = read_artifact_ledger(Path(config["scratchpad"]))
    unit = ledger["work_units"][successor.key]
    assert unit["semantic_status"] == "ACTIVE"
    assert unit["launch_digest"] == launch.digest


def test_arbitrary_third_state_is_preserved_as_debt_never_adopted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    config = _config(tmp_path)
    raw = _index_bytes(medium_summary=1, medium_master=2)
    _prepare_model_attempt(config, raw, monkeypatch)

    def crash(point: str) -> None:
        if point == "after_successor_arm":
            raise _SimulatedCrash(point)

    with pytest.raises(_SimulatedCrash):
        D._run_report_index_summary_parity_successor(
            _phase(config),
            Path(config["scratchpad"]),
            config,
            fault_inject=crash,
        )
    root = Path(config["scratchpad"])
    arbitrary = raw.replace(b"finding 1", b"tampered finding")
    (root / "report_index.md").write_bytes(arbitrary)

    issues = D._run_report_index_summary_parity_successor(
        _phase(config), root, config
    )

    assert any("ARBITRARY_THIRD_STATE" in issue for issue in issues)
    assert (root / "report_index.md").read_bytes() == arbitrary
    successor, _launch = D._report_index_summary_parity_contract_and_launch(
        config
    )
    unit = read_artifact_ledger(root)["work_units"][successor.key]
    assert unit["semantic_status"] == "INPUTS_BOUND"
    assert unit["artifacts"] == {}


def test_retry_attempt_identity_is_immutable_and_prior_model_is_not_overwritten(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    config = _config(tmp_path)
    root = Path(config["scratchpad"])
    _seed_model_inputs(config)
    assert D._bind_typed_model_phase_inputs(_phase(config), root, config) == []
    _write_model_outputs(config, b"# incomplete attempt one\n")
    first, _first_launch = D._typed_model_phase_contract_and_launch(
        _phase(config), root, config
    )

    config["_phase_io_model_attempts"]["report_index"] = 2
    assert D._bind_typed_model_phase_inputs(_phase(config), root, config) == []
    second, _second_launch = D._typed_model_phase_contract_and_launch(
        _phase(config), root, config
    )
    assert first.key != second.key
    assert first.work_unit_id == "model"
    assert second.work_unit_id == "model.attempt-0002"
    before = read_artifact_ledger(root)
    assert before["work_units"][first.key]["artifacts"] == {}
    assert before["work_units"][second.key]["output_prestates"][
        "scratchpad:report_index.md"
    ]["status"] == "AUTHORIZED_MODEL_RETRY_PRESTATE"

    raw = _index_bytes(medium_summary=1, medium_master=2)
    _write_model_outputs(config, raw)
    assert D._run_report_index_summary_parity_successor(
        _phase(config), root, config
    ) == []

    after = read_artifact_ledger(root)
    assert after["work_units"][first.key]["artifacts"] == {}
    assert after["work_units"][second.key]["artifacts"][
        "scratchpad:report_index.md"
    ]["sha256"] == _digest(raw)
    assert after["work_units"][second.key]["contract_digest"] == second.digest


def test_retry_after_committed_parity_uses_new_model_and_driver_generations(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """A later report gate may retry after the first parity repair committed."""

    config = _config(tmp_path)
    root = Path(config["scratchpad"])
    first_raw = _index_bytes(medium_summary=1, medium_master=2)
    _prepare_model_attempt(config, first_raw, monkeypatch)
    assert D._run_report_index_summary_parity_successor(
        _phase(config), root, config
    ) == []

    first_model, _first_model_launch = (
        D._typed_model_phase_contract_and_launch(_phase(config), root, config)
    )
    first_driver, _first_driver_launch = (
        D._report_index_summary_parity_contract_and_launch(config)
    )
    first_receipt_path = (
        root / "report_index_summary_parity_receipt.json"
    )
    first_receipt = first_receipt_path.read_bytes()
    before_retry = read_artifact_ledger(root)
    immutable_first_model = deepcopy(
        before_retry["work_units"][first_model.key]
    )
    immutable_first_driver = deepcopy(
        before_retry["work_units"][first_driver.key]
    )

    # A later validator rejects attempt one and the model reruns.  The retry
    # must start a new generation; it may not reactivate or overwrite either
    # historical producer.
    config["_phase_io_model_attempts"]["report_index"] = 2
    assert D._bind_typed_model_phase_inputs(
        _phase(config), root, config
    ) == []
    second_model, _second_model_launch = (
        D._typed_model_phase_contract_and_launch(_phase(config), root, config)
    )
    second_driver, _second_driver_launch = (
        D._report_index_summary_parity_contract_and_launch(config)
    )
    armed = read_artifact_ledger(root)
    assert second_model.work_unit_id == "model.attempt-0002"
    assert second_driver.work_unit_id == "summary_parity.attempt-0002"
    assert armed["work_units"][second_model.key]["output_prestates"][
        "scratchpad:report_index.md"
    ]["status"] == "ACTIVE_REGISTERED_PREDECESSOR"
    assert armed["work_units"][second_model.key]["output_prestates"][
        "scratchpad:report_index.md"
    ]["predecessor_owner_key"] == first_driver.key
    assert armed["work_units"][first_model.key] == immutable_first_model
    assert armed["work_units"][first_driver.key] == immutable_first_driver

    second_raw = _index_bytes(medium_summary=0, medium_master=1)
    _write_model_outputs(config, second_raw)
    assert D._run_report_index_summary_parity_successor(
        _phase(config), root, config
    ) == []

    after_retry = read_artifact_ledger(root)
    assert after_retry["work_units"][first_model.key] == immutable_first_model
    assert after_retry["work_units"][first_driver.key] == immutable_first_driver
    assert after_retry["work_units"][second_model.key]["artifacts"][
        "scratchpad:report_index.md"
    ]["sha256"] == _digest(second_raw)
    assert after_retry["artifact_bindings"]["scratchpad:report_index.md"][
        "owner_key"
    ] == second_driver.key
    retired = [
        row
        for row in after_retry["artifact_bindings"][
            "scratchpad:report_index.md"
        ]["history"]
        if row.get("owner_key") == first_driver.key
    ]
    assert retired
    assert retired[-1]["status"] == "SUPERSEDED"
    assert retired[-1]["superseded_by_owner_key"] == second_model.key
    assert first_receipt_path.read_bytes() == first_receipt
    assert (
        root / "report_index_summary_parity_receipt.attempt-0002.json"
    ).is_file()


@pytest.mark.parametrize(
    "invalidate",
    ("input_drift", "missing_driver_receipt", "skipped_generation"),
)
def test_committed_generation_retry_authorization_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    invalidate: str,
):
    config = _config(tmp_path)
    root = Path(config["scratchpad"])
    raw = _index_bytes(medium_summary=1, medium_master=2)
    _prepare_model_attempt(config, raw, monkeypatch)
    assert D._run_report_index_summary_parity_successor(
        _phase(config), root, config
    ) == []

    if invalidate == "input_drift":
        (root / "verification_queue.md").write_bytes(
            b"# Verification Queue\n\nchanged after generation one\n"
        )
    elif invalidate == "missing_driver_receipt":
        (
            root / "report_index_summary_parity_receipt.json"
        ).unlink()
    elif invalidate == "skipped_generation":
        config["_phase_io_model_attempts"]["report_index"] = 3
    else:  # pragma: no cover - parametrization guard
        raise AssertionError(invalidate)
    if invalidate != "skipped_generation":
        config["_phase_io_model_attempts"]["report_index"] = 2

    issues = D._bind_typed_model_phase_inputs(
        _phase(config), root, config
    )

    assert issues
    retry, _launch = D._typed_model_phase_contract_and_launch(
        _phase(config), root, config
    )
    unit = read_artifact_ledger(root)["work_units"][retry.key]
    assert unit["semantic_status"] == "INPUT_DEBT"
    assert unit["artifacts"] == {}
    assert unit["output_prestates"]["scratchpad:report_index.md"][
        "status"
    ] == "UNREGISTERED_REPLACEMENT_PREDECESSOR"


def test_live_validator_preserves_raw_model_and_commits_canonical_repairs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """A0 attributes raw bytes, then gives repairs one DRIVER successor."""

    config = _config(tmp_path)
    root = Path(config["scratchpad"])
    raw = _index_bytes(medium_summary=1, medium_master=2)
    _prepare_model_attempt(config, raw, monkeypatch)

    monkeypatch.setattr(D, "gate_passes", lambda *args, **kwargs: (True, []))
    monkeypatch.setattr(
        D, "_detect_foreign_phase_writes", lambda *args, **kwargs: []
    )
    def append_repair(target_root: Path, label: str) -> None:
        with (Path(target_root) / "report_index.md").open("ab") as stream:
            stream.write(f"<!-- {label} -->\n".encode("utf-8"))

    monkeypatch.setattr(
        D, "_check_index_completeness", lambda *args, **kwargs: []
    )
    monkeypatch.setattr(
        D,
        "_repair_report_index_dropouts",
        lambda *args, **kwargs: (
            append_repair(args[0], "dropout-driver-repair") or ["H-01"]
        ),
    )
    monkeypatch.setattr(
        D,
        "_project_report_index_status_with_debt",
        lambda *args, **kwargs: (
            append_repair(args[0], "status-driver-repair") or []
        ),
    )
    monkeypatch.setattr(
        D, "_validate_report_index_inputs", lambda *args, **kwargs: []
    )
    monkeypatch.setattr(
        D,
        "_repair_report_index_severity_provenance",
        lambda *args, **kwargs: (
            append_repair(args[0], "severity-driver-repair")
            or [{"action": "applied simulated repair"}]
        ),
    )
    monkeypatch.setattr(
        D, "_validate_report_coverage_accounting", lambda *args, **kwargs: []
    )
    monkeypatch.setattr(
        D,
        "_check_report_index_unresolved_authenticity",
        lambda *args, **kwargs: [],
    )
    monkeypatch.setattr(
        D, "_check_speculative_critical_chains", lambda *args, **kwargs: []
    )
    monkeypatch.setattr(
        D,
        "validate_report_index_canonical_bundle",
        lambda *args, **kwargs: [],
    )

    passed, missing = D._run_phase_validators(
        _phase(config),
        config,
        root,
        list(SC_PHASES),
        0,
        {},
    )

    assert passed is True
    assert missing == []
    assert (root / "report_index.md").read_bytes() != raw
    model, _launch = D._typed_model_phase_contract_and_launch(
        _phase(config), root, config
    )
    ledger = read_artifact_ledger(root)
    unit = ledger["work_units"].get(model.key)
    model_report = (
        unit.get("artifacts", {}).get("scratchpad:report_index.md")
        if isinstance(unit, dict)
        else None
    )
    assert model_report is not None
    assert model_report["sha256"] == _digest(raw)
    canonical, _launch = D._report_index_canonical_contract_and_launch(
        root, config
    )
    canonical_unit = ledger["work_units"][canonical.key]
    assert canonical_unit["semantic_status"] == "ACTIVE"
    assert (
        ledger["artifact_bindings"]["scratchpad:report_index.md"]["owner_key"]
        == canonical.key
    )
