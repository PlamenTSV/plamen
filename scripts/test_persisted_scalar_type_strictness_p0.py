"""Persisted control-plane integers must not accept JSON booleans.

Python's ``bool`` is an ``int`` subclass.  Phase checkpoint and retry-receipt
loaders are authority-bearing boundaries, so their integer fields require the
exact JSON integer type rather than ordinary ``isinstance(value, int)``
acceptance.
"""
from __future__ import annotations

import json
import uuid

import pytest

import methodology_application as methodology
from plamen_types import Checkpoint, GateFailure, PhaseCommit, RetryReceipt


def _gate_failure_payload() -> dict[str, object]:
    return GateFailure(
        gate_id="recon:schema:0000000000000000",
        gate_class="SCHEMA",
        message="persisted scalar fixture",
        schema_version=1,
        denominator_count=0,
    ).to_dict()


def _retry_receipt_payload() -> dict[str, object]:
    return RetryReceipt(
        run_id=str(uuid.uuid4()),
        phase_name="recon",
        work_unit_id="phase",
        attempt=1,
        status="NO_PROGRESS",
        failure_instance_ids_before=(),
        failure_instance_ids_after=(),
        gate_ids_before=(),
        gate_ids_after=(),
        schema_id="plamen.fixture.v1",
        schema_version=1,
        denominator_count=0,
        denominator_digest="0" * 64,
        input_digest="1" * 64,
        output_digest_before="2" * 64,
        output_digest_after="3" * 64,
        predicate_digest_before="4" * 64,
        predicate_digest_after="5" * 64,
        repair_owner="fixture",
        prompt_digest="6" * 64,
        launch_digest="7" * 64,
        contract_digest="8" * 64,
    ).to_dict()


@pytest.mark.parametrize("field", ["schema_version", "denominator_count"])
@pytest.mark.parametrize("ambiguous", [False, True])
def test_gate_failure_rejects_bool_for_persisted_integer(
    field: str,
    ambiguous: bool,
) -> None:
    payload = _gate_failure_payload()
    payload[field] = ambiguous

    with pytest.raises(RuntimeError, match=field):
        GateFailure.from_dict(payload)


@pytest.mark.parametrize(
    "field",
    ["attempt", "schema_version", "denominator_count"],
)
@pytest.mark.parametrize("ambiguous", [False, True])
def test_retry_receipt_rejects_bool_for_persisted_integer(
    field: str,
    ambiguous: bool,
) -> None:
    payload = _retry_receipt_payload()
    payload[field] = ambiguous

    with pytest.raises(RuntimeError, match=field):
        RetryReceipt.from_dict(payload)


@pytest.mark.parametrize("field", ["schema_version", "denominator_count"])
def test_checkpoint_resume_rejects_bool_in_nested_gate_failure(
    tmp_path,
    field: str,
) -> None:
    """Exercise the real checkpoint JSON -> PhaseCommit -> GateFailure path."""
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    run_id = str(uuid.uuid4())
    failure = GateFailure.from_dict(_gate_failure_payload())
    checkpoint = Checkpoint(
        run_id=run_id,
        phase_commits={
            "recon": PhaseCommit(
                phase_name="recon",
                state="INCOMPLETE_WITH_DEBT",
                run_id=run_id,
                unresolved_failures=(failure,),
            )
        },
    )
    checkpoint.save(scratchpad)

    path = scratchpad / "_v2_checkpoint.json"
    persisted = json.loads(path.read_text(encoding="utf-8"))
    persisted["phase_commits"]["recon"]["unresolved_failures"][0][field] = True
    path.write_text(json.dumps(persisted), encoding="utf-8")

    with pytest.raises(RuntimeError, match=field):
        Checkpoint.load(scratchpad)


def test_methodology_embedded_trace_rejects_bool_schema_version() -> None:
    row = {column: "fixture" for column in methodology.TRACE_COLUMNS}
    payload = {"schema_version": True, "rows": [row]}
    text = "\n".join(
        (
            methodology.TRACE_HEADING,
            methodology.TRACE_JSON_BEGIN,
            json.dumps(payload),
            methodology.TRACE_JSON_END,
        )
    )

    assert methodology._trace_rows(text) == []
