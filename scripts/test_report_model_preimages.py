"""Durable report MODEL preimages from a genuine POSIX worker child."""
from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

import report_model_preimages as P
from phase_io_contracts import canonical_work_unit_key
from test_worker_execution_preimage_authority import real_worker


pytestmark = pytest.mark.integration


def _capture(worker):
    return P.capture_report_model_preimages(
        worker.scratchpad, contract=worker.contract, launch=worker.launch,
        run_id=worker.run_id,
    )


def _read(worker):
    return P.read_report_model_preimages(
        worker.scratchpad, contract=worker.contract, launch=worker.launch,
        run_id=worker.run_id,
    )


def test_capture_read_is_idempotent_and_retains_original_after_successor(
    real_worker,
) -> None:
    first = _capture(real_worker)
    result = _read(real_worker)
    assert first == result.read_set == _capture(real_worker)
    assert set(result.preimages) == {
        "scratchpad:report_index.md", "scratchpad:report_coverage.md",
    }
    originals = dict(result.preimages)
    for identity in originals:
        path = real_worker.scratchpad / identity.removeprefix("scratchpad:")
        path.write_bytes(b"canonical successor\n")
    replay = _read(real_worker)
    assert dict(replay.preimages) == originals
    assert replay.execution_authority_digest == result.execution_authority_digest


@pytest.mark.parametrize("damage", ("missing", "tampered"))
def test_missing_or_tampered_persisted_preimage_fails(real_worker, damage) -> None:
    result = _read(real_worker)
    relative = next(
        path for path in result.read_set
        if path.startswith("_report_model_preimages/")
    )
    target = real_worker.scratchpad / relative
    target.unlink() if damage == "missing" else target.write_bytes(b"tampered\n")
    with pytest.raises(P.ReportModelPreimageError):
        _read(real_worker)


@pytest.mark.parametrize("damage", ("missing", "tampered"))
def test_missing_or_tampered_worker_record_fails(real_worker, damage) -> None:
    result = _read(real_worker)
    relative = next(
        path for path in result.read_set
        if not path.startswith("_report_model_preimages/")
    )
    target = real_worker.scratchpad / relative
    target.unlink() if damage == "missing" else target.write_bytes(b"{}\n")
    with pytest.raises(P.ReportModelPreimageError):
        _read(real_worker)


@pytest.mark.parametrize("field", ("execution_authority", "commit_authority"))
def test_ledger_or_commit_execution_mismatch_fails(real_worker, field) -> None:
    state_path = real_worker.scratchpad / "_artifact_state.json"
    state = json.loads(state_path.read_text(encoding="utf-8"))
    unit = state["work_units"][real_worker.contract.key]
    if field == "execution_authority":
        unit[field]["authority_digest"] = "0" * 64
    else:
        unit[field]["execution_authority"]["authority_digest"] = "0" * 64
    state_path.write_text(json.dumps(state, sort_keys=True), encoding="utf-8")
    with pytest.raises(P.ReportModelPreimageError):
        _read(real_worker)


def test_capture_after_live_mutation_cannot_recreate_missing_preimage(
    real_worker,
) -> None:
    result = _read(real_worker)
    relative = next(
        path for path in result.read_set
        if path.startswith("_report_model_preimages/")
    )
    retained = real_worker.scratchpad / relative
    retained.unlink()
    identity = next(iter(result.preimages))
    live = real_worker.scratchpad / identity.removeprefix("scratchpad:")
    live.write_bytes(b"late successor\n")
    with pytest.raises(P.ReportModelPreimageError):
        _capture(real_worker)
    assert not retained.exists()


class _ProjectionDrift:
    def __init__(self, target, field: str) -> None:
        self._target = target
        self._field = field

    def __getattr__(self, name):
        return getattr(self._target, name)

    def to_dict(self):
        value = dict(self._target.to_dict())
        value[self._field] = "fixture-projection-drift"
        return value


@pytest.mark.parametrize("kind", ("contract", "launch"))
def test_expected_stored_contract_and_launch_projection_is_exact(
    real_worker, kind,
) -> None:
    contract = real_worker.contract
    launch = real_worker.launch
    if kind == "contract":
        contract = _ProjectionDrift(contract, "mode")
    else:
        launch = _ProjectionDrift(launch, "model")
    with pytest.raises(
        P.ReportModelPreimageError, match="stored contract/launch differs"
    ):
        P.read_report_model_preimages(
            real_worker.scratchpad, contract=contract, launch=launch,
            run_id=real_worker.run_id,
        )


@pytest.mark.parametrize(
    "work_unit_id,accepted",
    (("model", True), ("model.attempt-0002", True),
     ("model.attempt-0001", False), ("model.attempt-2", False),
     ("model.retry-0002", False)),
)
def test_only_resolver_shaped_report_model_retry_ids_are_supported(
    real_worker, work_unit_id, accepted,
) -> None:
    key = canonical_work_unit_key(
        "sc", "core", "evm", "codex", "report_index", work_unit_id
    )
    outputs = tuple(
        SimpleNamespace(
            identity=f"scratchpad:{name}", root="scratchpad", writer="MODEL",
            owner_key=key,
        )
        for name in ("report_index.md", "report_coverage.md")
    )
    contract = SimpleNamespace(
        pipeline=real_worker.contract.pipeline,
        phase="report_index",
        work_unit_id=work_unit_id,
        outputs=outputs,
        key=key,
    )
    launch = SimpleNamespace(work_unit_key=contract.key)
    if accepted:
        assert P._expected_identities(contract, launch) == (
            "scratchpad:report_index.md", "scratchpad:report_coverage.md",
        )
    else:
        with pytest.raises(P.ReportModelPreimageError):
            P._expected_identities(contract, launch)
@pytest.mark.parametrize(
    "work_unit_id,output_name,accepted",
    (
        ("model.report_critical_high", "report_critical_high.md", True),
        ("model.report_medium_a", "report_medium_a.md", True),
        ("model.report_low_info_z", "report_low_info_z.md", True),
        ("model.report_medium.attempt-0002", "report_medium.md", True),
        ("model.report_low_info_z.attempt-9999", "report_low_info_z.md", True),
        ("model.report_medium_aa", "report_medium_aa.md", False),
        ("model.report_medium_c2", "report_medium_c2.md", False),
        ("model.report_MEDIUM", "report_MEDIUM.md", False),
        ("model.report_medium.attempt-0001", "report_medium.md", False),
        ("model.report_medium.attempt-2", "report_medium.md", False),
    ),
)
def test_only_exact_report_body_model_ids_are_preimage_eligible(
    work_unit_id, output_name, accepted,
):
    key = canonical_work_unit_key(
        "sc", "core", "evm", "codex", "report_body", work_unit_id,
    )
    contract = SimpleNamespace(
        pipeline="sc",
        phase="report_body",
        work_unit_id=work_unit_id,
        outputs=(
            SimpleNamespace(
                identity=f"scratchpad:{output_name}",
                root="scratchpad",
                writer="MODEL",
                owner_key=key,
            ),
        ),
        key=key,
    )
    launch = SimpleNamespace(work_unit_key=key)
    if accepted:
        assert P._expected_identities(contract, launch) == (
            f"scratchpad:{output_name}",
        )
    else:
        with pytest.raises(P.ReportModelPreimageError):
            P._expected_identities(contract, launch)
