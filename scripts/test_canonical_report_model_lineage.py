"""Canonical predecessor selection, actual input arm and staging (not E2E)."""
from copy import deepcopy
import json

import pytest

import artifact_ledger as A
import canonical_report_model_lineage as C
from phase_io_contracts import LaunchSpec, resolve_phase_io_contract
import plamen_driver as D
from test_report_index_summary_parity_successor_a0_a1 import _index_bytes
from test_report_model_lineage import _summary
from test_worker_execution_preimage_authority import real_worker


pytestmark = [pytest.mark.integration, pytest.mark.parametrize(
    "real_worker", [{"report_index.md": _index_bytes().decode(),
                     "report_coverage.md": "# Coverage\n" + "Retained coverage.\n" * 20}],
    indirect=True,
)]


def _read(worker, *, root=None, resolver=None):
    summary, launch = D._report_index_summary_parity_contract_and_launch(worker.config)
    return C.read_canonical_report_model_lineage(
        root or worker.scratchpad, summary_contract=summary, summary_launch=launch,
        canonical_work_unit_id="canonicalize", run_id=worker.run_id,
        resolve_model=resolver or (lambda: (worker.contract, worker.launch)),
    )


def _canonical(worker, lineage):
    contract = resolve_phase_io_contract(
        pipeline="sc", mode="core", ecosystem="evm", backend="codex",
        phase="report_index", work_unit_id="canonicalize", exact_inputs=lineage.read_set,
    )
    launch = LaunchSpec(
        work_unit_key=contract.key, pipeline="sc", mode="core", ecosystem="evm",
        backend="codex", model="driver", timeout_s=120, exec_mode="python",
        tool_policy=("filesystem",),
    )
    execute, issues = D._arm_deterministic_driver_work_unit(
        scratchpad=worker.scratchpad, project_root=worker.project,
        contract=contract, launch=launch, run_id=worker.run_id,
    )
    assert execute and not issues, issues
    return contract, launch


@pytest.mark.parametrize("with_summary", [False, True])
def test_real_canonical_input_arm_and_stage_preserve_model_lineage(real_worker, with_summary):
    if with_summary:
        _summary(real_worker)
    lineage = _read(real_worker)
    contract, launch = _canonical(real_worker, lineage)
    assert _read(real_worker) == lineage
    unit = A.read_artifact_ledger(real_worker.scratchpad)["work_units"][contract.key]
    assert set(contract.immutable_inputs) == {"scratchpad:" + p for p in lineage.read_set}
    stage, issues = D._stage_report_index_canonical_preimage(
        real_worker.scratchpad, real_worker.project, contract=contract, launch=launch,
        run_id=real_worker.run_id, prestates=unit["output_prestates"],
    )
    assert not issues and stage is not None, issues
    for relative in lineage.read_set:
        assert (stage / relative).read_bytes() == (real_worker.scratchpad / relative).read_bytes()
    assert _read(real_worker, root=stage) == lineage


@pytest.mark.parametrize("damage", ["wrong_owner", "mixed_owners", "changed_binding", "changed_bytes", "inactive"])
def test_live_predecessor_cannot_select_wrong_or_changed_model(real_worker, damage):
    state_path = real_worker.scratchpad / "_artifact_state.json"
    state = json.loads(state_path.read_text())
    bindings = state["artifact_bindings"]
    if damage == "wrong_owner":
        for row in bindings.values():
            row["owner_key"] = real_worker.contract.key + ".attempt-0002"
    elif damage == "mixed_owners":
        bindings["scratchpad:report_coverage.md"]["owner_key"] += ".attempt-0002"
    elif damage == "changed_binding":
        bindings["scratchpad:report_coverage.md"]["sha256"] = "0" * 64
    elif damage == "inactive":
        bindings["scratchpad:report_coverage.md"]["status"] = "QUARANTINED"
    else:
        (real_worker.scratchpad / "report_coverage.md").write_bytes(b"changed\n")
    state_path.write_text(json.dumps(state))
    with pytest.raises(ValueError):
        _read(real_worker)


def test_armed_canonical_prestates_do_not_adopt_later_live_bytes(real_worker):
    lineage = _read(real_worker)
    contract, _ = _canonical(real_worker, lineage)
    (real_worker.scratchpad / "report_index.md").write_bytes(b"partial publication\n")
    # Historical join does not claim those arbitrary live bytes as valid output.
    assert _read(real_worker) == lineage
    state_path = real_worker.scratchpad / "_artifact_state.json"
    state = json.loads(state_path.read_text())
    state["work_units"][contract.key]["output_prestates"]["scratchpad:report_index.md"]["sha256"] = "0" * 64
    state_path.write_text(json.dumps(state))
    with pytest.raises(ValueError, match="predecessor differs"):
        _read(real_worker)


def test_mechanical_selection_does_not_resolve_or_claim_model_authority(real_worker):
    # Selection-only test. The canonical caller must separately validate the
    # mechanical producer; these deliberately synthetic bindings prove no commit.
    state_path = real_worker.scratchpad / "_artifact_state.json"
    state = deepcopy(json.loads(state_path.read_text()))
    for identity in ("scratchpad:report_index.md", "scratchpad:report_coverage.md"):
        state["artifact_bindings"][identity]["owner_key"] = real_worker.contract.key.rsplit("/", 1)[0] + "/mechanical"
    state_path.write_text(json.dumps(state))
    def forbidden_resolver():
        pytest.fail("mechanical selection must not resolve a MODEL")
    assert _read(real_worker, resolver=forbidden_resolver) is None
