"""R31: Summary parity owns one complete replayable report-head bundle."""
from __future__ import annotations

from copy import deepcopy
from pathlib import Path

import pytest

from artifact_ledger import (
    _output_prestate_digest,
    read_artifact_ledger,
    validate_work_unit_artifacts,
    write_artifact_ledger,
)
from phase_io_contracts import registered_projection_handoff
import plamen_driver as D
import test_report_index_canonical_successor_a0_blocking as C


class _Crash(BaseException):
    pass


def _prepare(tmp_path: Path, pipeline: str) -> tuple[dict, Path, bytes, dict[str, bytes]]:
    config = C._config(tmp_path, pipeline=pipeline)
    root = Path(config["scratchpad"])
    raw = C._report_index_bytes(medium_summary=1, medium_master=2)
    C._prepare_model_attempt(config, raw)
    names = (
        "report_coverage.md",
        *(("report_records.json",) if pipeline == "l1" else ()),
    )
    passthroughs = {name: (root / name).read_bytes() for name in names}
    return config, root, raw, passthroughs


@pytest.mark.parametrize("pipeline", ("sc", "l1"))
def test_summary_parity_commits_one_complete_replayable_report_head(
    tmp_path: Path,
    pipeline: str,
) -> None:
    config, root, raw, passthroughs = _prepare(tmp_path, pipeline)
    phase = C._phase(pipeline=pipeline)

    assert D._run_report_index_summary_parity_successor(
        phase, root, config
    ) == []
    successor, launch = D._report_index_summary_parity_contract_and_launch(
        config
    )
    identities = {
        "scratchpad:report_index.md",
        *(f"scratchpad:{name}" for name in passthroughs),
    }
    ledger = read_artifact_ledger(root)
    unit = ledger["work_units"][successor.key]
    assert unit["semantic_status"] == "ACTIVE"
    assert unit["execution_state"] == "OUTPUT_COMMITTED"
    assert identities <= set(unit["artifacts"])
    assert identities <= set(unit["commit_authority"]["expected_output_records"])
    for identity in identities:
        binding = ledger["artifact_bindings"][identity]
        assert binding["owner_key"] == successor.key
        assert binding["run_id"] == config["_run_id"]
        assert binding["contract_digest"] == successor.digest
        assert binding["launch_digest"] == launch.digest
    for name, before in passthroughs.items():
        assert (root / name).read_bytes() == before
    assert (root / "report_index.md").read_bytes() != raw

    before_replay = (root / "_artifact_state.json").read_bytes()
    assert D._run_report_index_summary_parity_successor(
        phase, root, config
    ) == []
    assert D._run_report_index_summary_parity_successor(
        phase, root, config
    ) == []
    assert validate_work_unit_artifacts(
        root,
        Path(config["project_root"]),
        successor,
        launch,
        run_id=config["_run_id"],
        actor="DRIVER",
    ) == []
    assert (root / "_artifact_state.json").read_bytes() == before_replay
    for name, before in passthroughs.items():
        assert (root / name).read_bytes() == before


@pytest.mark.parametrize(
    ("pipeline", "damage", "target"),
    (
        ("sc", "changed", "report_coverage.md"),
        ("sc", "missing", "report_coverage.md"),
        ("sc", "cross-run", "report_coverage.md"),
        ("sc", "foreign-owner", "report_coverage.md"),
        ("sc", "invalid-predecessor-commit", "report_coverage.md"),
        ("l1", "changed", "report_coverage.md"),
        ("l1", "changed", "report_records.json"),
        ("l1", "missing", "report_records.json"),
        ("l1", "cross-run", "report_records.json"),
        ("l1", "invalid-predecessor-commit", "report_records.json"),
    ),
)
def test_summary_parity_never_commits_damaged_or_foreign_passthrough(
    tmp_path: Path,
    pipeline: str,
    damage: str,
    target: str,
) -> None:
    config, root, raw, passthroughs = _prepare(tmp_path, pipeline)
    phase = C._phase(pipeline=pipeline)
    successor, _launch = D._report_index_summary_parity_contract_and_launch(
        config
    )
    model, _model_launch = D._typed_model_phase_contract_and_launch(
        phase, root, config
    )
    assert model is not None
    fired = False

    def damage_after_arm(point: str) -> None:
        nonlocal fired
        if point != "after_successor_arm" or fired:
            return
        fired = True
        path = root / target
        ledger = read_artifact_ledger(root)
        binding = ledger["artifact_bindings"][f"scratchpad:{target}"]
        if damage == "changed":
            path.write_bytes(path.read_bytes() + b"\npost-arm tamper\n")
        elif damage == "missing":
            path.unlink()
        elif damage == "cross-run":
            binding["run_id"] = "foreign-run"
            write_artifact_ledger(root, ledger)
        elif damage == "foreign-owner":
            binding["owner_key"] = (
                f"{pipeline}/{config['mode']}/{config['language']}/"
                f"{config['cli_backend']}/report_index/foreign"
            )
            write_artifact_ledger(root, ledger)
        elif damage == "invalid-predecessor-commit":
            ledger["work_units"][model.key]["commit_authority"][
                "receipt_digest"
            ] = "0" * 64
            write_artifact_ledger(root, ledger)

    issues = D._run_report_index_summary_parity_successor(
        phase,
        root,
        config,
        fault_inject=damage_after_arm,
    )

    assert fired is True
    assert issues
    ledger = read_artifact_ledger(root)
    unit = ledger["work_units"][successor.key]
    assert unit["semantic_status"] == "INPUTS_BOUND"
    assert unit["execution_state"] == "INPUTS_BOUND_PREEXECUTION"
    assert unit["artifacts"] == {}
    assert (root / "report_index.md").read_bytes() == raw
    if damage not in {"changed", "missing"}:
        assert (root / target).read_bytes() == passthroughs[target]


@pytest.mark.parametrize(
    ("pipeline", "missing"),
    (
        ("sc", "report_coverage.md"),
        ("l1", "report_coverage.md"),
        ("l1", "report_records.json"),
    ),
)
def test_summary_parity_rejects_partial_model_report_head(
    tmp_path: Path,
    pipeline: str,
    missing: str,
) -> None:
    config, root, raw, _passthroughs = _prepare(tmp_path, pipeline)
    (root / missing).unlink()

    issues = D._run_report_index_summary_parity_successor(
        C._phase(pipeline=pipeline), root, config
    )

    assert issues
    assert (root / "report_index.md").read_bytes() == raw
    successor, _launch = D._report_index_summary_parity_contract_and_launch(
        config
    )
    ledger = read_artifact_ledger(root)
    assert successor.key not in ledger["work_units"]


@pytest.mark.parametrize("pipeline", ("sc", "l1"))
def test_summary_parity_contract_and_handoffs_cover_complete_head(
    tmp_path: Path,
    pipeline: str,
) -> None:
    config = C._config(tmp_path, pipeline=pipeline)
    contract, _launch = D._report_index_summary_parity_contract_and_launch(
        config
    )
    expected = {
        "report_index.md",
        "report_coverage.md",
        "report_index_summary_parity_receipt.json",
        *(("report_records.json",) if pipeline == "l1" else ()),
    }
    assert {spec.path for spec in contract.outputs} == expected
    passthrough = {
        spec.path: spec
        for spec in contract.outputs
        if spec.path in {"report_coverage.md", "report_records.json"}
    }
    assert passthrough
    assert all(
        spec.minimum_gate
        == "EXACT_REGISTERED_MODEL_PREDECESSOR_BYTE_PASSTHROUGH"
        for spec in passthrough.values()
    )
    prefix = "/".join(contract.key.split("/")[:4])
    model = f"{prefix}/report_index/model"
    canonical = f"{prefix}/report_index/canonicalize"
    for relative in ("report_index.md", *passthrough):
        identity = f"scratchpad:{relative}"
        assert registered_projection_handoff(model, contract.key, identity)
        assert registered_projection_handoff(contract.key, model, identity)
        assert registered_projection_handoff(contract.key, canonical, identity)


@pytest.mark.parametrize("pipeline", ("sc", "l1"))
@pytest.mark.parametrize(
    "crash_point",
    (
        "before_successor_arm",
        "after_successor_arm",
        "after_successor_receipt_write",
        "after_successor_report_write",
        "before_successor_commit",
    ),
)
def test_summary_parity_crash_recovery_never_splits_complete_head(
    tmp_path: Path,
    pipeline: str,
    crash_point: str,
) -> None:
    config, root, _raw, passthroughs = _prepare(tmp_path, pipeline)
    phase = C._phase(pipeline=pipeline)
    fired = False

    def crash(point: str) -> None:
        nonlocal fired
        if point == crash_point and not fired:
            fired = True
            raise _Crash(point)

    with pytest.raises(_Crash):
        D._run_report_index_summary_parity_successor(
            phase,
            root,
            config,
            fault_inject=crash,
        )
    assert fired is True
    for name, before in passthroughs.items():
        assert (root / name).read_bytes() == before

    assert D._run_report_index_summary_parity_successor(
        phase, root, config
    ) == []
    successor, _launch = D._report_index_summary_parity_contract_and_launch(
        config
    )
    ledger = read_artifact_ledger(root)
    for relative in ("report_index.md", *passthroughs):
        assert ledger["artifact_bindings"][f"scratchpad:{relative}"][
            "owner_key"
        ] == successor.key
    for name, before in passthroughs.items():
        assert (root / name).read_bytes() == before


@pytest.mark.parametrize(
    ("pipeline", "target"),
    (
        ("sc", "report_coverage.md"),
        ("l1", "report_coverage.md"),
        ("l1", "report_records.json"),
    ),
)
def test_summary_parity_precommit_tamper_is_never_blessed(
    tmp_path: Path,
    pipeline: str,
    target: str,
) -> None:
    config, root, _raw, _passthroughs = _prepare(tmp_path, pipeline)
    phase = C._phase(pipeline=pipeline)
    tampered = False

    def tamper(point: str) -> None:
        nonlocal tampered
        if point == "before_successor_commit" and not tampered:
            tampered = True
            path = root / target
            path.write_bytes(path.read_bytes() + b"\nprecommit tamper\n")

    issues = D._run_report_index_summary_parity_successor(
        phase,
        root,
        config,
        fault_inject=tamper,
    )

    assert tampered is True
    assert issues
    successor, _launch = D._report_index_summary_parity_contract_and_launch(
        config
    )
    unit = read_artifact_ledger(root)["work_units"][successor.key]
    assert unit["semantic_status"] == "INPUTS_BOUND"
    assert unit["execution_state"] == "INPUTS_BOUND_PREEXECUTION"
    assert unit["artifacts"] == {}
    assert D._run_report_index_summary_parity_successor(
        phase, root, config
    )


@pytest.mark.parametrize("pipeline", ("sc", "l1"))
def test_summary_parity_retry_advances_one_complete_head_generation(
    tmp_path: Path,
    pipeline: str,
) -> None:
    config, root, _raw, first_passthroughs = _prepare(tmp_path, pipeline)
    phase = C._phase(pipeline=pipeline)
    assert D._run_report_index_summary_parity_successor(
        phase, root, config
    ) == []

    first_model, _first_model_launch = D._typed_model_phase_contract_and_launch(
        phase, root, config
    )
    first_successor, _first_successor_launch = (
        D._report_index_summary_parity_contract_and_launch(config)
    )
    before_retry = read_artifact_ledger(root)
    immutable_first_model = deepcopy(before_retry["work_units"][first_model.key])
    immutable_first_successor = deepcopy(
        before_retry["work_units"][first_successor.key]
    )

    config["_phase_io_model_attempts"]["report_index"] = 2
    assert D._bind_typed_model_phase_inputs(phase, root, config) == []
    second_model, _second_model_launch = D._typed_model_phase_contract_and_launch(
        phase, root, config
    )
    second_successor, second_successor_launch = (
        D._report_index_summary_parity_contract_and_launch(config)
    )
    assert second_model.work_unit_id == "model.attempt-0002"
    assert second_successor.work_unit_id == "summary_parity.attempt-0002"
    for relative in ("report_index.md", *first_passthroughs):
        prestate = read_artifact_ledger(root)["work_units"][second_model.key][
            "output_prestates"
        ][f"scratchpad:{relative}"]
        assert prestate["status"] == "ACTIVE_REGISTERED_PREDECESSOR"
        assert prestate["predecessor_owner_key"] == first_successor.key

    second_raw = C._report_index_bytes(medium_summary=0, medium_master=1)
    (root / "report_index.md").write_bytes(second_raw)
    second_passthroughs = {
        "report_coverage.md": C._coverage_bytes().replace(
            b"H-1 | PROMOTED M-01", b"H-2 | PROMOTED M-01"
        ),
        **(
            {"report_records.json": b'{"active":[],"excluded":["H-2"]}\n'}
            if pipeline == "l1"
            else {}
        ),
    }
    for relative, payload in second_passthroughs.items():
        (root / relative).write_bytes(payload)

    assert D._run_report_index_summary_parity_successor(
        phase, root, config
    ) == []
    after_retry = read_artifact_ledger(root)
    assert after_retry["work_units"][first_model.key] == immutable_first_model
    assert (
        after_retry["work_units"][first_successor.key]
        == immutable_first_successor
    )
    for relative in ("report_index.md", *second_passthroughs):
        binding = after_retry["artifact_bindings"][f"scratchpad:{relative}"]
        assert binding["owner_key"] == second_successor.key
        assert binding["run_id"] == config["_run_id"]
        assert binding["contract_digest"] == second_successor.digest
        assert binding["launch_digest"] == second_successor_launch.digest
    for relative, payload in second_passthroughs.items():
        assert (root / relative).read_bytes() == payload


@pytest.mark.parametrize("pipeline", ("sc", "l1"))
def test_canonical_complete_head_is_one_exact_model_retry_predecessor(
    tmp_path: Path,
    pipeline: str,
) -> None:
    config, root, _raw, passthroughs = _prepare(tmp_path, pipeline)
    phase = C._phase(pipeline=pipeline)
    assert D._run_report_index_summary_parity_successor(
        phase, root, config
    ) == []
    summary, _summary_launch = D._report_index_summary_parity_contract_and_launch(
        config
    )
    assert D._run_report_index_canonicalization_transaction(
        phase, root, config
    ) == []
    canonical, _canonical_launch = D._report_index_canonical_contract_and_launch(
        root, config
    )
    canonical_unit = read_artifact_ledger(root)["work_units"][canonical.key]
    for relative in ("report_index.md", *passthroughs):
        prestate = canonical_unit["output_prestates"][f"scratchpad:{relative}"]
        assert prestate["predecessor_owner_key"] == summary.key

    config["_phase_io_model_attempts"]["report_index"] = 2
    assert D._bind_typed_model_phase_inputs(phase, root, config) == []
    second_model, _launch = D._typed_model_phase_contract_and_launch(
        phase, root, config
    )
    second_unit = read_artifact_ledger(root)["work_units"][second_model.key]
    for relative in ("report_index.md", *passthroughs):
        prestate = second_unit["output_prestates"][f"scratchpad:{relative}"]
        assert prestate["status"] == "ACTIVE_REGISTERED_PREDECESSOR"
        assert prestate["predecessor_owner_key"] == canonical.key


@pytest.mark.parametrize(
    ("pipeline", "damage"),
    (
        ("sc", "legacy_split_head"),
        ("l1", "legacy_split_head"),
        ("sc", "legacy_index_only_manifest"),
        ("l1", "missing_head"),
        ("sc", "partial_summary_prestates"),
        ("l1", "mixed_summary_predecessors"),
        ("sc", "wrong_prestate_digest"),
        ("l1", "live_passthrough_tamper"),
        ("sc", "prior_model_input_drift"),
        ("l1", "invalid_summary_commit"),
        ("sc", "tampered_summary_receipt"),
        ("l1", "boolean_artifact_size"),
        ("sc", "cross_run_binding"),
    ),
)
def test_model_retry_rejects_every_incomplete_or_foreign_prior_head(
    tmp_path: Path,
    pipeline: str,
    damage: str,
) -> None:
    config, root, _raw, passthroughs = _prepare(tmp_path, pipeline)
    phase = C._phase(pipeline=pipeline)
    assert D._run_report_index_summary_parity_successor(
        phase, root, config
    ) == []
    model, _model_launch = D._typed_model_phase_contract_and_launch(
        phase, root, config
    )
    summary, _summary_launch = D._report_index_summary_parity_contract_and_launch(
        config
    )
    coverage = "scratchpad:report_coverage.md"
    target = (
        "scratchpad:report_records.json"
        if pipeline == "l1"
        else coverage
    )
    ledger = read_artifact_ledger(root)
    summary_unit = ledger["work_units"][summary.key]

    if damage == "legacy_split_head":
        ledger["artifact_bindings"][target] = dict(
            ledger["work_units"][model.key]["artifacts"][target]
        )
        ledger["artifact_bindings"][target]["status"] = "ACTIVE"
        write_artifact_ledger(root, ledger)
    elif damage == "legacy_index_only_manifest":
        summary_unit["contract_manifest"]["outputs"] = [
            row
            for row in summary_unit["contract_manifest"]["outputs"]
            if row["identity"]
            in {
                "scratchpad:report_index.md",
                "scratchpad:report_index_summary_parity_receipt.json",
            }
        ]
        write_artifact_ledger(root, ledger)
    elif damage == "missing_head":
        (root / target.split(":", 1)[1]).unlink()
    elif damage == "partial_summary_prestates":
        summary_unit["output_prestates"].pop(coverage)
        write_artifact_ledger(root, ledger)
    elif damage == "mixed_summary_predecessors":
        summary_unit["output_prestates"][target][
            "predecessor_owner_key"
        ] = summary.key
        write_artifact_ledger(root, ledger)
    elif damage == "wrong_prestate_digest":
        summary_unit["output_prestates"][coverage]["sha256"] = "0" * 64
        write_artifact_ledger(root, ledger)
    elif damage == "live_passthrough_tamper":
        (root / target.split(":", 1)[1]).write_bytes(
            (root / target.split(":", 1)[1]).read_bytes() + b"\ntamper\n"
        )
    elif damage == "prior_model_input_drift":
        ledger["work_units"][model.key]["input_set_digest"] = "0" * 64
        write_artifact_ledger(root, ledger)
    elif damage == "invalid_summary_commit":
        summary_unit["commit_authority"]["receipt_digest"] = "0" * 64
        write_artifact_ledger(root, ledger)
    elif damage == "tampered_summary_receipt":
        receipt = root / "report_index_summary_parity_receipt.json"
        receipt.write_bytes(receipt.read_bytes() + b"\ntamper\n")
    elif damage == "boolean_artifact_size":
        summary_unit["artifacts"][target]["size"] = True
        write_artifact_ledger(root, ledger)
    elif damage == "cross_run_binding":
        ledger["artifact_bindings"][target]["run_id"] = "foreign-run"
        write_artifact_ledger(root, ledger)
    else:  # pragma: no cover
        raise AssertionError(damage)

    config["_phase_io_model_attempts"]["report_index"] = 2
    issues = D._bind_typed_model_phase_inputs(phase, root, config)

    assert issues
    retry, _retry_launch = D._typed_model_phase_contract_and_launch(
        phase, root, config
    )
    retry_unit = read_artifact_ledger(root)["work_units"][retry.key]
    assert retry_unit["semantic_status"] == "INPUT_DEBT"
    assert retry_unit["artifacts"] == {}


@pytest.mark.parametrize("recompute_digest", (False, True))
def test_model_retry_rejects_extra_summary_prestate_denominator(
    tmp_path: Path,
    recompute_digest: bool,
) -> None:
    config, root, _raw, _passthroughs = _prepare(tmp_path, "sc")
    phase = C._phase(pipeline="sc")
    assert D._run_report_index_summary_parity_successor(
        phase, root, config
    ) == []
    summary, _launch = D._report_index_summary_parity_contract_and_launch(
        config
    )
    ledger = read_artifact_ledger(root)
    unit = ledger["work_units"][summary.key]
    extra = dict(
        unit["output_prestates"]["scratchpad:report_coverage.md"]
    )
    extra["identity"] = "scratchpad:foreign_extra.md"
    unit["output_prestates"][extra["identity"]] = extra
    if recompute_digest:
        unit["output_prestate_digest"] = _output_prestate_digest(
            unit["output_prestates"]
        )
    write_artifact_ledger(root, ledger)

    config["_phase_io_model_attempts"]["report_index"] = 2
    issues = D._bind_typed_model_phase_inputs(phase, root, config)

    assert issues
    retry, _retry_launch = D._typed_model_phase_contract_and_launch(
        phase, root, config
    )
    retry_unit = read_artifact_ledger(root)["work_units"][retry.key]
    assert retry_unit["semantic_status"] == "INPUT_DEBT"
    assert retry_unit["artifacts"] == {}


@pytest.mark.parametrize(
    "damage",
    (
        "missing_receipt_row",
        "duplicate_case_alias",
        "stale_digest",
        "dirty_status",
        "key_identity_mismatch",
    ),
)
def test_model_retry_rejects_malformed_summary_prestate_receipt(
    tmp_path: Path,
    damage: str,
) -> None:
    config, root, _raw, _passthroughs = _prepare(tmp_path, "sc")
    phase = C._phase(pipeline="sc")
    assert D._run_report_index_summary_parity_successor(
        phase, root, config
    ) == []
    summary, _launch = D._report_index_summary_parity_contract_and_launch(
        config
    )
    ledger = read_artifact_ledger(root)
    unit = ledger["work_units"][summary.key]
    prestates = unit["output_prestates"]
    receipt = "scratchpad:report_index_summary_parity_receipt.json"
    if damage == "missing_receipt_row":
        prestates.pop(receipt)
        unit["output_prestate_digest"] = _output_prestate_digest(prestates)
    elif damage == "duplicate_case_alias":
        alias = "scratchpad:REPORT_COVERAGE.md"
        prestates[alias] = dict(prestates["scratchpad:report_coverage.md"])
        prestates[alias]["identity"] = alias
        unit["output_prestate_digest"] = _output_prestate_digest(prestates)
    elif damage == "stale_digest":
        unit["output_prestate_digest"] = "0" * 64
    elif damage == "dirty_status":
        prestates[receipt]["status"] = "ACTIVE"
        unit["output_prestate_digest"] = _output_prestate_digest(prestates)
    elif damage == "key_identity_mismatch":
        prestates[receipt]["identity"] = "scratchpad:foreign_receipt.json"
        unit["output_prestate_digest"] = _output_prestate_digest(prestates)
    else:  # pragma: no cover
        raise AssertionError(damage)
    write_artifact_ledger(root, ledger)

    config["_phase_io_model_attempts"]["report_index"] = 2
    issues = D._bind_typed_model_phase_inputs(phase, root, config)

    assert issues
    retry, _retry_launch = D._typed_model_phase_contract_and_launch(
        phase, root, config
    )
    retry_unit = read_artifact_ledger(root)["work_units"][retry.key]
    assert retry_unit["semantic_status"] == "INPUT_DEBT"
    assert retry_unit["artifacts"] == {}
