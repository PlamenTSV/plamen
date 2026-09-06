"""Executable B5-B7 acceptance contract for verify-queue decomposition.

Evidence boundary:

* ``Plamen_Preverify_Successor_Independent_Blocking_Review_2026-07-25.md``
  B5-B7 and its missing crash/resume matrix;
* the canonical rule that a child may publish only its own exact postimage;
* ``finding_records.json`` is an upstream paired-inventory projection.  The
  queue transaction consumes it but never creates or rewrites it.

This is intentionally a red successor specification.  Production must provide
``verify_queue_transaction.py`` with three small public seams:

``resolve_verify_queue_transaction_plan(...)``
    Return the exact mapping-shaped T0..T9 DAG specified below.

``classify_verify_queue_transaction_state(states)``
    Apply the closed five-state precedence used by the transaction.

``execute_verify_queue_transaction(...)``
    Arm, materialize, commit, resume, and finally read-only-commit the plan.
    ``child_executor`` is dependency injection for deterministic fault tests;
    it does not grant authority outside each child's resolved output set.

The driver cutover must call that executor for both SC and L1.  Enlarging the
legacy monolithic ``routing`` contract cannot satisfy these fixtures.
"""
from __future__ import annotations

import hashlib
import importlib.util
import inspect
import json
from pathlib import Path
import sys
from typing import Any, Mapping, Sequence

import pytest

from artifact_ledger import (
    read_artifact_ledger,
    record_work_unit_artifacts,
    record_work_unit_inputs,
)
from phase_io_contracts import (
    ArtifactSpec,
    LaunchSpec,
    PhaseIOContract,
    canonical_work_unit_key,
)
import plamen_driver as D
from plamen_types import L1_VERIFY_SHARD_MANIFESTS, SC_VERIFY_SHARD_MANIFESTS


SCRIPTS = Path(__file__).resolve().parent
SUT_PATH = SCRIPTS / "verify_queue_transaction.py"

TERMINAL_STATES = frozenset({
    "COMMITTED_APPLIED",
    "COMMITTED_CLEAN_NOOP",
    "COMPLETED_WITH_DEBT_SAFE_BASE",
    "PREPARED_NOT_CONSUMABLE",
    "QUARANTINED_FOREIGN_STATE",
})

CHILD_IDS = (
    "t0.input_authority",
    "t1.base_queue",
    "t2.policy_disposition",
    "t3.mandatory_reverification",
    "t4.composition_delivery",
    "t5.compound_projection",
    "t6.final_work_item_plan",
    "t7.context_and_shard_plan",
    "t8.transaction_validation",
    "t9.final_assembler",
)
PARENT_ID = "routing.parent_commit"
STATUS_PATHS = tuple(
    f"_verify_queue_transaction/t{index}/status.json"
    for index in range(10)
)

EXTERNAL_INPUTS = (
    "finding_delivery_successor.json",
    "finding_records.json",
    "findings_inventory.md",
    "preverify_inventory_successor.json",
)
CONTEXT_INPUTS = (
    "caller_map.md",
    "project::module/source.rs",
)
CONTEXT_CAPTURE_SPEC = {
    "exact_inputs": CONTEXT_INPUTS,
    "graph_artifacts": ("caller_map.md",),
    "graph_globs": ("call_graph*.md",),
    "primary_artifacts": ("project::module/source.rs",),
    "project_sibling_directories": ("project::module",),
}

T0_OUTPUTS = (
    "_verify_queue_transaction/t0/input_snapshot.json",
    STATUS_PATHS[0],
    "verify_queue_context_input_status.json",
)
T1_OUTPUTS = (
    "_verify_queue_transaction/t1/base_queue.json",
    "_verify_queue_transaction/t1/base_queue.md",
    "_verify_queue_transaction/t1/base_queue.work_items.json",
    STATUS_PATHS[1],
)
T2_OUTPUTS = (
    "_verify_queue_transaction/t2/active_queue.work_items.json",
    "_verify_queue_transaction/t2/evidence_debt.json",
    "_verify_queue_transaction/t2/evidence_excluded.work_items.json",
    STATUS_PATHS[2],
)
T3_OUTPUTS = (
    "_verify_queue_transaction/t3/queue_delta.json",
    STATUS_PATHS[3],
    "mandatory_reverification_denominator.json",
    "mandatory_reverification_queue_transaction.receipt.json",
    "mandatory_reverification_routing.json",
)
T4_OUTPUTS = (
    STATUS_PATHS[4],
    "compound_verification_delivery_debt.json",
    "compound_verification_delivery_disposition.json",
    "compound_verification_delivery_receipt.json",
)
T4_CONDITIONAL = frozenset({
    "compound_verification_delivery_debt.json",
    "compound_verification_delivery_receipt.json",
})
T5_OUTPUTS = (
    STATUS_PATHS[5],
    "compound_candidates.json",
    "compound_verification_work_plan.json",
)
T6_OUTPUTS = (
    "_verify_queue_transaction/t6/final_work_items.json",
    "_verify_queue_transaction/t6/final_publication_plan.json",
    STATUS_PATHS[6],
)
T7_OUTPUTS = (
    "_verify_queue_transaction/t7/context_input_capture.json",
    "_verify_queue_transaction/t7/context_input_roster.json",
    "_verify_queue_transaction/t7/verification_context_packets.json",
    "_verify_queue_transaction/t7/verification_methodology_reachability.json",
    "_verify_queue_transaction/t7/shard_plan.json",
    STATUS_PATHS[7],
)
T8_OUTPUTS = (
    "_verify_queue_transaction/t8/outer_denominator.json",
    "_verify_queue_transaction/t8/validated_publication.json",
    STATUS_PATHS[8],
)

COMMON_ASSEMBLY_OUTPUTS = frozenset({
    STATUS_PATHS[9],
    "verification_context_packets.json",
    "verification_methodology_reachability.json",
    "verification_queue.json",
    "verification_queue.md",
    "verification_queue.work_items.json",
    "verification_queue.work_plan.json",
    "verification_queue_evidence_debt.json",
    "verification_queue_evidence_debt.md",
    "verification_queue_evidence_excluded.json",
    "verification_queue_evidence_excluded.md",
    "verify_queue_transaction.receipt.json",
})

EXPECTED_FIXED_OUTPUTS = {
    CHILD_IDS[0]: frozenset(T0_OUTPUTS),
    CHILD_IDS[1]: frozenset(T1_OUTPUTS),
    CHILD_IDS[2]: frozenset(T2_OUTPUTS),
    CHILD_IDS[3]: frozenset(T3_OUTPUTS),
    CHILD_IDS[4]: frozenset(T4_OUTPUTS),
    CHILD_IDS[5]: frozenset(T5_OUTPUTS),
    CHILD_IDS[6]: frozenset(T6_OUTPUTS),
    CHILD_IDS[7]: frozenset(T7_OUTPUTS),
    CHILD_IDS[8]: frozenset(T8_OUTPUTS),
}

EXPECTED_INPUTS = {
    CHILD_IDS[0]: frozenset(EXTERNAL_INPUTS),
    CHILD_IDS[1]: frozenset(T0_OUTPUTS),
    CHILD_IDS[2]: frozenset(T1_OUTPUTS),
    CHILD_IDS[3]: frozenset({
        T0_OUTPUTS[0],
        T2_OUTPUTS[0],
        T2_OUTPUTS[2],
        STATUS_PATHS[2],
    }),
    CHILD_IDS[4]: frozenset({
        T0_OUTPUTS[0],
        "verify_queue_context_input_status.json",
        T2_OUTPUTS[0],
        STATUS_PATHS[2],
    }),
    CHILD_IDS[5]: frozenset({
        T2_OUTPUTS[0],
        "compound_verification_delivery_disposition.json",
        STATUS_PATHS[4],
    }),
    CHILD_IDS[6]: frozenset({
        *T2_OUTPUTS,
        *T3_OUTPUTS,
        *T5_OUTPUTS,
    }),
    CHILD_IDS[7]: frozenset({
        *T6_OUTPUTS,
        *CONTEXT_INPUTS,
    }),
}

CASES = (
    ("sc", "sc_verify_queue", "evm", "claude"),
    ("sc", "sc_verify_queue", "evm", "codex"),
    ("l1", "verify_queue", "rust", "claude"),
    ("l1", "verify_queue", "rust", "codex"),
)


def _load_sut():
    if not SUT_PATH.is_file():
        pytest.fail(
            "B5-B7 requires scripts/verify_queue_transaction.py; "
            "the monolithic routing work unit is not an accepted substitute"
        )
    module_name = "_plamen_verify_queue_transaction_b5_b7"
    cached = sys.modules.get(module_name)
    if cached is not None:
        return cached
    spec = importlib.util.spec_from_file_location(module_name, SUT_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


def _shard_manifests(pipeline: str) -> tuple[str, ...]:
    source = (
        SC_VERIFY_SHARD_MANIFESTS
        if pipeline == "sc"
        else L1_VERIFY_SHARD_MANIFESTS
    )
    return tuple(sorted(set(source.values())))


def _projection_triplet(markdown_path: str) -> frozenset[str]:
    path = Path(markdown_path)
    return frozenset({
        path.as_posix(),
        path.with_suffix(".json").as_posix(),
        path.with_suffix(".work_items.json").as_posix(),
    })


def _assembly_outputs(pipeline: str) -> frozenset[str]:
    shards = {
        output
        for manifest in _shard_manifests(pipeline)
        for output in _projection_triplet(manifest)
    }
    return frozenset({*COMMON_ASSEMBLY_OUTPUTS, *shards})


def _plan(
    pipeline: str = "sc",
    backend: str = "claude",
) -> Mapping[str, Any]:
    module = _load_sut()
    resolver = getattr(module, "resolve_verify_queue_transaction_plan", None)
    assert callable(resolver), (
        "verify_queue_transaction must expose "
        "resolve_verify_queue_transaction_plan"
    )
    phase_name = "sc_verify_queue" if pipeline == "sc" else "verify_queue"
    ecosystem = "evm" if pipeline == "sc" else "rust"
    plan = resolver(
        pipeline=pipeline,
        mode="thorough",
        ecosystem=ecosystem,
        backend=backend,
        phase_name=phase_name,
        external_inputs=EXTERNAL_INPUTS,
        shard_manifests=_shard_manifests(pipeline),
        context_capture=CONTEXT_CAPTURE_SPEC,
    )
    assert isinstance(plan, Mapping)
    return plan


def _children(plan: Mapping[str, Any]) -> tuple[Mapping[str, Any], ...]:
    children = plan.get("children")
    assert isinstance(children, Sequence) and not isinstance(
        children, (str, bytes)
    )
    assert all(isinstance(row, Mapping) for row in children)
    return tuple(children)


def _child_map(plan: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    rows = _children(plan)
    result = {str(row.get("work_unit_id") or ""): row for row in rows}
    assert len(result) == len(rows), "child work-unit IDs must be unique"
    return result


def _output_rows(unit: Mapping[str, Any]) -> tuple[Mapping[str, Any], ...]:
    rows = unit.get("outputs")
    assert isinstance(rows, Sequence) and not isinstance(rows, (str, bytes))
    assert all(isinstance(row, Mapping) for row in rows)
    return tuple(rows)


def _output_paths(unit: Mapping[str, Any]) -> frozenset[str]:
    return frozenset(str(row.get("path") or "") for row in _output_rows(unit))


def _input_paths(unit: Mapping[str, Any]) -> frozenset[str]:
    values = unit.get("exact_inputs")
    assert isinstance(values, Sequence) and not isinstance(values, (str, bytes))
    return frozenset(str(value) for value in values)


def _expected_outputs(pipeline: str) -> dict[str, frozenset[str]]:
    return {
        **EXPECTED_FIXED_OUTPUTS,
        CHILD_IDS[9]: _assembly_outputs(pipeline),
    }


def _nonconditional_outputs(
    children: Mapping[str, Mapping[str, Any]],
    through_index: int,
) -> frozenset[str]:
    outputs: set[str] = set()
    for work_id in CHILD_IDS[: through_index + 1]:
        for row in _output_rows(children[work_id]):
            if str(row.get("artifact_class") or "") != "CONDITIONAL":
                outputs.add(str(row.get("path") or ""))
    return frozenset(outputs)


def _canonical_bytes(value: Mapping[str, Any]) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")


class _DeterministicChildExecutor:
    def __init__(
        self,
        *,
        state_overrides: Mapping[str, str] | None = None,
        produced_conditionals: Mapping[str, str] | None = None,
    ) -> None:
        self.calls: list[str] = []
        self.state_overrides = dict(state_overrides or {})
        self.produced_conditionals = dict(produced_conditionals or {})
        self.inputs_by_work_id: dict[str, dict[str, bytes]] = {}

    def __call__(
        self,
        *,
        unit: Mapping[str, Any],
        frozen_inputs: Mapping[str, bytes],
    ) -> Mapping[str, Any]:
        work_id = str(unit["work_unit_id"])
        self.calls.append(work_id)
        self.inputs_by_work_id[work_id] = dict(frozen_inputs)
        final_work_item_ids = (
            "BASE-ACTIVE",
            "MANDATORY-RESTORED",
            "COMPOUND-ADDED",
        )
        outputs: dict[str, bytes] = {}
        for row in _output_rows(unit):
            path = str(row["path"])
            if path in STATUS_PATHS:
                continue
            if str(row.get("artifact_class") or "") == "CONDITIONAL":
                if self.produced_conditionals.get(work_id) == path:
                    outputs[path] = _canonical_bytes({
                        "schema_version": "plamen.fixture_conditional.v1",
                        "work_unit_id": work_id,
                        "path": path,
                    })
                continue
            if path.endswith(".md"):
                outputs[path] = f"# Empty fixture for {work_id}\n".encode()
            elif path == T2_OUTPUTS[0]:
                outputs[path] = _canonical_bytes({
                    "schema_version": "plamen.fixture_work_items.v1",
                    "work_items": [{"work_item_id": "BASE-ACTIVE"}],
                })
            elif path == T3_OUTPUTS[0]:
                outputs[path] = _canonical_bytes({
                    "schema_version": "plamen.fixture_work_items.v1",
                    "work_items": [{
                        "work_item_id": "MANDATORY-RESTORED"
                    }],
                })
            elif path == "compound_verification_work_plan.json":
                outputs[path] = _canonical_bytes({
                    "schema_version": "plamen.fixture_work_items.v1",
                    "work_items": [{"work_item_id": "COMPOUND-ADDED"}],
                })
            elif path in T6_OUTPUTS[:2]:
                outputs[path] = _canonical_bytes({
                    "schema_version": "plamen.fixture_final_denominator.v1",
                    "work_item_ids": list(final_work_item_ids),
                    "work_items": [
                        {"work_item_id": item_id}
                        for item_id in final_work_item_ids
                    ],
                })
            elif path == T7_OUTPUTS[2]:
                outputs[path] = _canonical_bytes({
                    "schema_version": "plamen.fixture_context_packets.v1",
                    "packets": [
                        {"work_item_id": item_id}
                        for item_id in final_work_item_ids
                    ],
                })
            elif path == T7_OUTPUTS[4]:
                outputs[path] = _canonical_bytes({
                    "schema_version": "plamen.fixture_shard_plan.v1",
                    "assignments": [
                        {
                            "work_item_id": item_id,
                            "shard": f"fixture-{index % 2}",
                        }
                        for index, item_id in enumerate(final_work_item_ids)
                    ],
                })
            else:
                outputs[path] = _canonical_bytes({
                    "schema_version": "plamen.fixture_projection.v1",
                    "work_unit_id": work_id,
                    "path": path,
                    "input_digests": {
                        name: hashlib.sha256(raw).hexdigest()
                        for name, raw in sorted(frozen_inputs.items())
                    },
                })
        return {
            "state": self.state_overrides.get(
                work_id, "COMMITTED_CLEAN_NOOP"
            ),
            "outputs": outputs,
            "conditional_states": {
                path: (
                    "PRODUCED"
                    if self.produced_conditionals.get(work_id) == path
                    else "NOT_TRIGGERED"
                )
                for path in sorted(T4_CONDITIONAL)
                if work_id == CHILD_IDS[4]
            },
        }


def _seed_upstream_group(
    root: Path,
    *,
    pipeline: str,
    backend: str,
    phase: str,
    work_unit_id: str,
    paths: Sequence[str],
    run_id: str,
) -> None:
    ecosystem = "evm" if pipeline == "sc" else "rust"
    owner = canonical_work_unit_key(
        pipeline,
        "thorough",
        ecosystem,
        backend,
        phase,
        work_unit_id,
    )
    outputs = []
    for relative in paths:
        if relative.startswith("project::"):
            artifact_root = "project"
            artifact_path = relative[len("project::"):]
        else:
            artifact_root = "scratchpad"
            artifact_path = relative
        outputs.append(ArtifactSpec(
            root=artifact_root,
            path=artifact_path,
            owner_key=owner,
            artifact_class="DRIVER_GENERATED",
            writer="DRIVER",
            write_mode="CREATE",
            schema_version="plamen.fixture_upstream.v1",
            minimum_gate="FIXTURE_EXACT_BYTES",
        ))
    contract = PhaseIOContract(
        pipeline=pipeline,
        mode="thorough",
        ecosystem=ecosystem,
        backend=backend,
        phase=phase,
        work_unit_id=work_unit_id,
        outputs=tuple(outputs),
        model_invoked=False,
    )
    launch = LaunchSpec(
        work_unit_key=contract.key,
        pipeline=contract.pipeline,
        mode=contract.mode,
        ecosystem=contract.ecosystem,
        backend=contract.backend,
        model="fixture-driver",
        timeout_s=30,
        exec_mode="python",
    )
    ledger = read_artifact_ledger(root)
    unit = ledger.get("work_units", {}).get(contract.key)
    if isinstance(unit, Mapping) and unit.get("execution_state") == (
        "OUTPUT_COMMITTED"
    ):
        return
    record_work_unit_inputs(
        root, root.parent, contract, launch, run_id=run_id
    )
    for relative in paths:
        if relative.startswith("project::"):
            path = root.parent / relative[len("project::"):]
        else:
            path = root / relative
        if path.exists():
            continue
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.suffix == ".md":
            raw = b"# Final inventory\n\n_No findings._\n"
        elif path.suffix in {".rs", ".sol", ".move", ".go", ".daml"}:
            raw = b"// fixture source unit\n"
        else:
            raw = _canonical_bytes({
                "schema_version": "plamen.fixture_upstream.v1",
                "artifact": relative,
            })
        path.write_bytes(raw)
    record_work_unit_artifacts(
        root,
        root.parent,
        contract,
        launch,
        run_id=run_id,
        actor="DRIVER",
    )


def _seed_external_inputs(
    root: Path,
    *,
    pipeline: str,
    backend: str,
) -> None:
    root.mkdir(parents=True, exist_ok=True)
    run_id = f"b5-b7-{pipeline}-{backend}"
    _seed_upstream_group(
        root,
        pipeline=pipeline,
        backend=backend,
        phase="inventory",
        work_unit_id="paired_fixture",
        paths=("findings_inventory.md", "finding_records.json"),
        run_id=run_id,
    )
    _seed_upstream_group(
        root,
        pipeline=pipeline,
        backend=backend,
        phase="preverify_fixture",
        work_unit_id="stable_successors",
        paths=(
            "preverify_inventory_successor.json",
            "finding_delivery_successor.json",
        ),
        run_id=run_id,
    )
    _seed_upstream_group(
        root,
        pipeline=pipeline,
        backend=backend,
        phase="context_fixture",
        work_unit_id="exact_sources",
        paths=CONTEXT_INPUTS,
        run_id=run_id,
    )


def _execute(
    root: Path,
    *,
    pipeline: str = "sc",
    backend: str = "claude",
    executor: _DeterministicChildExecutor | None = None,
    failpoint=None,
) -> tuple[Mapping[str, Any], _DeterministicChildExecutor]:
    module = _load_sut()
    run = getattr(module, "execute_verify_queue_transaction", None)
    assert callable(run), (
        "verify_queue_transaction must expose execute_verify_queue_transaction"
    )
    project_root = root.parent
    _seed_external_inputs(root, pipeline=pipeline, backend=backend)
    selected = executor or _DeterministicChildExecutor()
    result = run(
        scratchpad=root,
        project_root=project_root,
        plan=_plan(pipeline, backend),
        run_id=f"b5-b7-{pipeline}-{backend}",
        child_executor=selected,
        failpoint=failpoint,
    )
    assert isinstance(result, Mapping)
    return result, selected


def _declared_bytes(root: Path, plan: Mapping[str, Any]) -> dict[str, bytes]:
    paths = {
        str(row["path"])
        for unit in _children(plan)
        for row in _output_rows(unit)
        if (root / str(row["path"])).is_file()
    }
    return {
        path: (root / path).read_bytes()
        for path in sorted(paths)
    }


def test_closed_terminal_state_vocabulary_is_exported() -> None:
    module = _load_sut()
    assert frozenset(getattr(module, "VERIFY_QUEUE_TERMINAL_STATES", ())) == (
        TERMINAL_STATES
    )


@pytest.mark.parametrize(
    "pipeline,phase_name,ecosystem,backend",
    CASES,
)
def test_plan_has_exact_t0_t9_roster_and_read_only_parent(
    pipeline: str,
    phase_name: str,
    ecosystem: str,
    backend: str,
) -> None:
    plan = _plan(pipeline, backend)
    children = _children(plan)
    parent = plan.get("parent")

    assert tuple(str(row["work_unit_id"]) for row in children) == CHILD_IDS
    assert isinstance(parent, Mapping)
    assert parent.get("work_unit_id") == PARENT_ID
    assert parent.get("outputs") == []
    assert parent.get("read_only") is True
    assert parent.get("model_invoked") is False
    assert plan.get("pipeline") == pipeline
    assert plan.get("phase_name") == phase_name
    assert plan.get("ecosystem") == ecosystem
    assert plan.get("backend") == backend


@pytest.mark.parametrize("pipeline", ("sc", "l1"))
def test_every_child_has_one_exact_disjoint_output_set(
    pipeline: str,
) -> None:
    children = _child_map(_plan(pipeline))
    expected = _expected_outputs(pipeline)
    observed_owner: dict[str, str] = {}

    for work_id in CHILD_IDS:
        unit = children[work_id]
        outputs = _output_paths(unit)
        assert outputs == expected[work_id]
        assert unit.get("model_invoked") is False
        assert outputs.isdisjoint(_input_paths(unit)), (
            f"{work_id} attempts an in-place input mutation"
        )
        for path in outputs:
            assert path and not any(token in path for token in "*?[")
            assert path not in observed_owner, (
                f"{path} is owned by both {observed_owner[path]} and {work_id}"
            )
            observed_owner[path] = work_id

    assert set(observed_owner) == set().union(*expected.values())


def test_child_input_graph_is_exact_topological_and_closed() -> None:
    plan = _plan()
    children = _child_map(plan)
    available = set(map(str, plan["external_input_denominator"]))

    for work_id in CHILD_IDS:
        inputs = _input_paths(children[work_id])
        assert inputs
        assert inputs <= available, (
            f"{work_id} reads an undeclared or future artifact: "
            f"{sorted(inputs - available)}"
        )
        if work_id in EXPECTED_INPUTS:
            assert inputs == EXPECTED_INPUTS[work_id]
        elif work_id == CHILD_IDS[8]:
            assert inputs == _nonconditional_outputs(children, 7)
        elif work_id == CHILD_IDS[9]:
            assert inputs == frozenset(T8_OUTPUTS)
        available.update(_output_paths(children[work_id]))


@pytest.mark.parametrize("pipeline", ("sc", "l1"))
def test_t9_is_sole_owner_of_every_public_queue_and_shard_projection(
    pipeline: str,
) -> None:
    children = _child_map(_plan(pipeline))
    public = _assembly_outputs(pipeline)

    assert _output_paths(children[CHILD_IDS[9]]) == public
    for work_id in CHILD_IDS[:-1]:
        assert _output_paths(children[work_id]).isdisjoint(public)


def test_outer_denominator_covers_all_declared_child_outputs() -> None:
    plan = _plan()
    children = _child_map(plan)
    declared = {
        path
        for unit in children.values()
        for path in _output_paths(unit)
    }
    denominator = plan.get("outer_output_denominator")

    assert isinstance(denominator, Sequence) and not isinstance(
        denominator, (str, bytes)
    )
    assert set(map(str, denominator)) == declared
    assert {
        "compound_verification_delivery_receipt.json",
        "compound_verification_delivery_debt.json",
        "verification_queue_evidence_excluded.md",
        "verification_queue_evidence_excluded.json",
        "verification_queue_evidence_debt.md",
        "verification_queue_evidence_debt.json",
        "mandatory_reverification_queue_transaction.receipt.json",
    } <= declared
    assert "finding_records.json" not in declared
    assert "finding_records.json" in set(plan["external_input_denominator"])
    assert set(CONTEXT_INPUTS) <= set(plan["external_input_denominator"])


def test_inventory_and_finding_records_are_one_upstream_pair_before_capture(
) -> None:
    plan = _plan()
    pair_groups = plan.get("upstream_pair_groups")

    assert isinstance(pair_groups, Mapping)
    assert set(pair_groups.get("paired_inventory_projection", ())) == {
        "findings_inventory.md",
        "finding_records.json",
    }
    assert "finding_records.json" in _input_paths(
        _child_map(plan)[CHILD_IDS[0]]
    )


def test_parent_commit_binds_complete_materialized_authority_and_writes_nothing(
) -> None:
    plan = _plan()
    children = _child_map(plan)
    parent = plan["parent"]
    expected = {
        *STATUS_PATHS,
        T8_OUTPUTS[0],
        "verify_queue_context_input_status.json",
        "mandatory_reverification_denominator.json",
        "mandatory_reverification_queue_transaction.receipt.json",
        "mandatory_reverification_routing.json",
        "compound_verification_delivery_disposition.json",
        "compound_candidates.json",
        "compound_verification_work_plan.json",
        *_assembly_outputs("sc"),
    }

    assert _input_paths(parent) == expected
    assert parent["outputs"] == []
    assert parent["read_only"] is True
    assert set(parent.get("validates_work_units", ())) == set(CHILD_IDS)
    assert all(
        path in set(plan["outer_output_denominator"])
        for path in expected
        if path not in EXTERNAL_INPUTS
    )
    assert children[CHILD_IDS[9]]["work_unit_id"] in parent[
        "validates_work_units"
    ]


def test_compound_disposition_is_typed_atomic_and_binds_empty_fallback() -> None:
    children = _child_map(_plan())
    delivery = children[CHILD_IDS[4]]
    compound = children[CHILD_IDS[5]]
    by_path = {str(row["path"]): row for row in _output_rows(delivery)}

    assert set(by_path) == set(T4_OUTPUTS)
    for path in T4_CONDITIONAL:
        assert by_path[path].get("artifact_class") == "CONDITIONAL"
        assert by_path[path].get("exclusive_group") == (
            "compound_delivery_disposition"
        )
        assert by_path[path].get("condition_id")
    assert (
        by_path["compound_verification_delivery_receipt.json"]["condition_id"]
        != by_path["compound_verification_delivery_debt.json"]["condition_id"]
    )
    assert "compound_verification_delivery_disposition.json" in _input_paths(
        compound
    )
    state_inputs = compound.get("delivery_state_exact_inputs")
    assert isinstance(state_inputs, Mapping)
    assert set(state_inputs) == {
        "COMMITTED_APPLIED",
        "COMMITTED_CLEAN_NOOP",
        "COMPLETED_WITH_DEBT_SAFE_BASE",
    }
    assert set(state_inputs["COMMITTED_APPLIED"]) == {
        "compound_verification_delivery_disposition.json",
        "compound_verification_delivery_receipt.json",
    }
    assert set(state_inputs["COMPLETED_WITH_DEBT_SAFE_BASE"]) == {
        "compound_verification_delivery_debt.json",
        "compound_verification_delivery_disposition.json",
    }
    assert set(state_inputs["COMMITTED_CLEAN_NOOP"]) == {
        "compound_verification_delivery_disposition.json",
    }


def test_t6_merges_every_work_item_source_before_downstream_enrichment(
) -> None:
    children = _child_map(_plan())
    final_plan = children[CHILD_IDS[6]]
    enrichment = children[CHILD_IDS[7]]
    validator = children[CHILD_IDS[8]]

    assert _input_paths(final_plan) == {
        *T2_OUTPUTS,
        *T3_OUTPUTS,
        *T5_OUTPUTS,
    }
    assert final_plan.get("work_item_merge_sources") == {
        "base_active": T2_OUTPUTS[0],
        "mandatory_reverification": T3_OUTPUTS[0],
        "compound_composition": "compound_verification_work_plan.json",
    }
    assert enrichment.get("work_item_denominator_input") == T6_OUTPUTS[0]
    expected_coverage = {
        "relation": "EXACT_WORK_ITEM_ID_SET_EQUALITY",
        "denominator": T6_OUTPUTS[0],
        "context_packets": T7_OUTPUTS[2],
        "shard_assignments": T7_OUTPUTS[4],
    }
    assert enrichment.get("coverage_invariant") == expected_coverage
    assert validator.get("work_item_coverage_validation") == (
        expected_coverage
    )
    assert {
        T6_OUTPUTS[0],
        T7_OUTPUTS[2],
        T7_OUTPUTS[4],
    } <= _input_paths(validator)


def test_t7_has_content_addressed_dynamic_context_capture_and_revalidation(
) -> None:
    context = _child_map(_plan())[CHILD_IDS[7]]
    capture = context.get("dynamic_input_capture")

    assert isinstance(capture, Mapping)
    assert capture.get("content_addressed") is True
    assert capture.get("revalidate_before_commit") is True
    assert capture.get("late_appearance_state") == (
        "QUARANTINED_FOREIGN_STATE"
    )
    assert set(capture.get("exact_inputs", ())) == set(CONTEXT_INPUTS)
    assert set(capture.get("enumerates", ())) == {
        "graph_artifacts",
        "graph_globs",
        "primary_artifacts",
        "project_sibling_directories",
    }
    assert set(capture.get("project_sibling_directories", ())) == {
        "project::module"
    }
    assert set(CONTEXT_INPUTS) <= _input_paths(context)
    assert {
        "_verify_queue_transaction/t7/context_input_capture.json",
        "_verify_queue_transaction/t7/context_input_roster.json",
    } <= _output_paths(context)


def test_queue_context_status_replaces_cross_phase_debt_mutation() -> None:
    plan = _plan()
    children = _child_map(plan)
    all_inputs = {
        path for unit in children.values() for path in _input_paths(unit)
    }
    all_outputs = {
        path for unit in children.values() for path in _output_paths(unit)
    }

    assert "chain.degraded" not in all_inputs | all_outputs
    assert "verify_queue_context_input_status.json" in _output_paths(
        children[CHILD_IDS[0]]
    )


def _normalized_plan_graph(plan: Mapping[str, Any]) -> tuple[tuple[Any, ...], ...]:
    rows = []
    for unit in _children(plan):
        outputs = tuple(sorted(
            (
                str(row.get("path") or "").replace("sc_verify_", "verify_"),
                str(row.get("artifact_class") or ""),
                str(row.get("condition_id") or ""),
            )
            for row in _output_rows(unit)
        ))
        rows.append((
            unit["work_unit_id"],
            tuple(sorted(_input_paths(unit))),
            outputs,
            bool(unit.get("model_invoked")),
        ))
    return tuple(rows)


@pytest.mark.parametrize("pipeline", ("sc", "l1"))
def test_claude_and_codex_resolve_the_same_semantic_transaction(
    pipeline: str,
) -> None:
    assert _normalized_plan_graph(_plan(pipeline, "claude")) == (
        _normalized_plan_graph(_plan(pipeline, "codex"))
    )


def test_sc_and_l1_differ_only_by_declared_shard_projection_names() -> None:
    sc = _child_map(_plan("sc"))
    l1 = _child_map(_plan("l1"))

    for work_id in CHILD_IDS[:-1]:
        assert _input_paths(sc[work_id]) == _input_paths(l1[work_id])
        assert _output_paths(sc[work_id]) == _output_paths(l1[work_id])
    assert (
        _output_paths(sc[CHILD_IDS[9]]) - _assembly_outputs("sc")
        == _output_paths(l1[CHILD_IDS[9]]) - _assembly_outputs("l1")
        == frozenset()
    )
    assert (
        _output_paths(sc[CHILD_IDS[9]]) ^ _output_paths(l1[CHILD_IDS[9]])
    ) == (
        _assembly_outputs("sc") ^ _assembly_outputs("l1")
    )


@pytest.mark.parametrize(
    "states,expected",
    (
        (("COMMITTED_CLEAN_NOOP",) * 10, "COMMITTED_CLEAN_NOOP"),
        (
            ("COMMITTED_CLEAN_NOOP",) * 9 + ("COMMITTED_APPLIED",),
            "COMMITTED_APPLIED",
        ),
        (
            ("COMMITTED_CLEAN_NOOP",) * 8
            + ("COMPLETED_WITH_DEBT_SAFE_BASE", "COMMITTED_APPLIED"),
            "COMPLETED_WITH_DEBT_SAFE_BASE",
        ),
        (
            ("COMMITTED_CLEAN_NOOP",) * 8
            + ("PREPARED_NOT_CONSUMABLE", "COMMITTED_APPLIED"),
            "PREPARED_NOT_CONSUMABLE",
        ),
        (
            ("COMMITTED_CLEAN_NOOP",) * 8
            + ("QUARANTINED_FOREIGN_STATE", "COMMITTED_APPLIED"),
            "QUARANTINED_FOREIGN_STATE",
        ),
    ),
)
def test_closed_state_precedence_is_total_and_deterministic(
    states: tuple[str, ...],
    expected: str,
) -> None:
    module = _load_sut()
    classify = getattr(
        module, "classify_verify_queue_transaction_state", None
    )
    assert callable(classify)
    assert classify(states) == expected
    assert classify(tuple(reversed(states))) == expected


def test_unknown_child_state_is_rejected_not_coerced_to_clean() -> None:
    module = _load_sut()
    classify = getattr(
        module, "classify_verify_queue_transaction_state", None
    )
    assert callable(classify)
    with pytest.raises(ValueError, match="state"):
        classify(("COMMITTED_CLEAN_NOOP", "ARBITRARY_THIRD_STATE"))


def test_clean_execution_writes_every_status_and_commits_outputless_parent(
    tmp_path: Path,
) -> None:
    root = tmp_path / ".scratchpad"
    result, executor = _execute(root)

    assert result["state"] == "COMMITTED_CLEAN_NOOP"
    assert executor.calls == list(CHILD_IDS)
    for path in STATUS_PATHS:
        payload = json.loads((root / path).read_text(encoding="utf-8"))
        assert payload["state"] in TERMINAL_STATES
        assert payload["work_unit_id"] in CHILD_IDS
        assert payload["run_id"] == "b5-b7-sc-claude"
    parent = result["parent_commit"]
    assert parent["work_unit_id"] == PARENT_ID
    assert parent["state"] == "OUTPUT_COMMITTED"
    assert parent["outputs"] == []
    assert parent["read_only"] is True


def test_every_final_work_item_has_one_context_packet_and_shard_assignment(
    tmp_path: Path,
) -> None:
    root = tmp_path / ".scratchpad"
    _result, executor = _execute(root)
    final_work_items = json.loads(
        (root / T6_OUTPUTS[0]).read_text(encoding="utf-8")
    )
    context_packets = json.loads(
        (root / T7_OUTPUTS[2]).read_text(encoding="utf-8")
    )
    shard_plan = json.loads(
        (root / T7_OUTPUTS[4]).read_text(encoding="utf-8")
    )

    denominator_ids = set(final_work_items["work_item_ids"])
    context_ids = {
        str(row["work_item_id"]) for row in context_packets["packets"]
    }
    shard_ids = {
        str(row["work_item_id"]) for row in shard_plan["assignments"]
    }
    assert denominator_ids == {
        "BASE-ACTIVE",
        "MANDATORY-RESTORED",
        "COMPOUND-ADDED",
    }
    assert context_ids == denominator_ids
    assert shard_ids == denominator_ids
    assert len(context_packets["packets"]) == len(denominator_ids)
    assert len(shard_plan["assignments"]) == len(denominator_ids)
    assert executor.inputs_by_work_id[CHILD_IDS[7]][T6_OUTPUTS[0]] == (
        root / T6_OUTPUTS[0]
    ).read_bytes()


@pytest.mark.parametrize(
    "pipeline,phase_name,ecosystem,backend",
    CASES,
)
def test_runtime_has_sc_l1_and_claude_codex_state_parity(
    tmp_path: Path,
    pipeline: str,
    phase_name: str,
    ecosystem: str,
    backend: str,
) -> None:
    root = tmp_path / f"{pipeline}-{backend}" / ".scratchpad"
    result, executor = _execute(
        root, pipeline=pipeline, backend=backend
    )

    assert result["state"] == "COMMITTED_CLEAN_NOOP"
    assert result["pipeline"] == pipeline
    assert result["phase_name"] == phase_name
    assert result["ecosystem"] == ecosystem
    assert result["backend"] == backend
    assert executor.calls == list(CHILD_IDS)


@pytest.mark.parametrize(
    "failpoint_label",
    tuple(f"after_t{index}_commit" for index in range(10))
    + ("before_parent_commit",),
)
def test_every_major_commit_failpoint_resumes_byte_exactly(
    tmp_path: Path,
    failpoint_label: str,
) -> None:
    module = _load_sut()
    injected = getattr(module, "VerifyQueueInjectedFailure", RuntimeError)
    clean_root = tmp_path / "clean" / ".scratchpad"
    resumed_root = tmp_path / "resumed" / ".scratchpad"
    clean_result, _clean_executor = _execute(clean_root)
    plan = _plan()
    clean_bytes = _declared_bytes(clean_root, plan)
    executor = _DeterministicChildExecutor()
    fired = False

    def failpoint(label: str) -> None:
        nonlocal fired
        if label == failpoint_label and not fired:
            fired = True
            raise injected(label)

    with pytest.raises(injected):
        _execute(resumed_root, executor=executor, failpoint=failpoint)
    calls_before_resume = tuple(executor.calls)

    resumed_result, _ = _execute(resumed_root, executor=executor)

    assert fired is True
    assert resumed_result["state"] == clean_result["state"]
    assert _declared_bytes(resumed_root, plan) == clean_bytes
    if failpoint_label.startswith("after_t"):
        committed_through = int(
            failpoint_label.removeprefix("after_t").removesuffix("_commit")
        )
        committed_before_crash = set(CHILD_IDS[: committed_through + 1])
    else:
        committed_before_crash = set(calls_before_resume)
    for work_id in committed_before_crash:
        assert executor.calls.count(work_id) == 1, (
            f"resume re-executed already committed {work_id}"
        )


def test_prepared_child_is_visible_and_never_consumed_by_t9(
    tmp_path: Path,
) -> None:
    module = _load_sut()
    injected = getattr(module, "VerifyQueueInjectedFailure", RuntimeError)
    root = tmp_path / ".scratchpad"
    executor = _DeterministicChildExecutor()

    def failpoint(label: str) -> None:
        if label == "after_t5_arm":
            raise injected(label)

    with pytest.raises(injected):
        _execute(root, executor=executor, failpoint=failpoint)

    status = json.loads(
        (root / STATUS_PATHS[5]).read_text(encoding="utf-8")
    )
    assert status["state"] == "PREPARED_NOT_CONSUMABLE"
    assert CHILD_IDS[9] not in executor.calls
    for public_path in _assembly_outputs("sc"):
        assert not (root / public_path).exists()


def test_stale_external_input_quarantines_without_overwriting_outputs(
    tmp_path: Path,
) -> None:
    module = _load_sut()
    injected = getattr(module, "VerifyQueueInjectedFailure", RuntimeError)
    root = tmp_path / ".scratchpad"
    executor = _DeterministicChildExecutor()

    def failpoint(label: str) -> None:
        if label == "after_t0_commit":
            raise injected(label)

    with pytest.raises(injected):
        _execute(root, executor=executor, failpoint=failpoint)
    snapshot = root / T0_OUTPUTS[0]
    snapshot_before = snapshot.read_bytes()
    (root / "findings_inventory.md").write_text(
        "# Foreign inventory generation\n", encoding="utf-8"
    )

    result, _ = _execute(root, executor=executor)

    assert result["state"] == "QUARANTINED_FOREIGN_STATE"
    assert snapshot.read_bytes() == snapshot_before
    assert CHILD_IDS[1] not in executor.calls
    assert not (root / "verification_queue.md").exists()


def test_foreign_partial_postimage_is_preserved_and_quarantined(
    tmp_path: Path,
) -> None:
    module = _load_sut()
    injected = getattr(module, "VerifyQueueInjectedFailure", RuntimeError)
    root = tmp_path / ".scratchpad"
    executor = _DeterministicChildExecutor()

    def failpoint(label: str) -> None:
        if label == "after_t4_materialize":
            raise injected(label)

    with pytest.raises(injected):
        _execute(root, executor=executor, failpoint=failpoint)
    disposition = root / "compound_verification_delivery_disposition.json"
    disposition.write_bytes(b'{"foreign":"third-state"}\n')
    foreign = disposition.read_bytes()

    result, _ = _execute(root, executor=executor)

    assert result["state"] == "QUARANTINED_FOREIGN_STATE"
    assert disposition.read_bytes() == foreign
    status = json.loads(
        (root / STATUS_PATHS[4]).read_text(encoding="utf-8")
    )
    assert status["state"] == "QUARANTINED_FOREIGN_STATE"
    assert CHILD_IDS[5] not in executor.calls
    assert not (root / "verification_queue.md").exists()


@pytest.mark.parametrize("late_kind", ("graph", "project_sibling"))
def test_t7_late_context_roster_appearance_quarantines_old_capture(
    tmp_path: Path,
    late_kind: str,
) -> None:
    module = _load_sut()
    injected = getattr(module, "VerifyQueueInjectedFailure", RuntimeError)
    root = tmp_path / ".scratchpad"
    executor = _DeterministicChildExecutor()

    def failpoint(label: str) -> None:
        if label == "after_t7_arm":
            raise injected(label)

    with pytest.raises(injected):
        _execute(root, executor=executor, failpoint=failpoint)
    if late_kind == "graph":
        (root / "call_graph_late.md").write_text(
            "# Late graph generation\n", encoding="utf-8"
        )
    else:
        sibling = root.parent / "module" / "late.rs"
        sibling.parent.mkdir(parents=True, exist_ok=True)
        sibling.write_text("// late sibling generation\n", encoding="utf-8")

    result, _ = _execute(root, executor=executor)

    assert result["state"] == "QUARANTINED_FOREIGN_STATE"
    status = json.loads(
        (root / STATUS_PATHS[7]).read_text(encoding="utf-8")
    )
    assert status["state"] == "QUARANTINED_FOREIGN_STATE"
    assert CHILD_IDS[8] not in executor.calls
    assert not (root / "verification_queue.md").exists()


def test_compound_debt_fallback_consumes_exact_owned_debt_bytes(
    tmp_path: Path,
) -> None:
    root = tmp_path / ".scratchpad"
    debt_path = "compound_verification_delivery_debt.json"
    executor = _DeterministicChildExecutor(
        state_overrides={
            CHILD_IDS[4]: "COMPLETED_WITH_DEBT_SAFE_BASE",
        },
        produced_conditionals={CHILD_IDS[4]: debt_path},
    )

    result, _ = _execute(root, executor=executor)

    assert result["state"] == "COMPLETED_WITH_DEBT_SAFE_BASE"
    frozen = executor.inputs_by_work_id[CHILD_IDS[5]]
    assert debt_path in frozen
    assert frozen[debt_path] == (root / debt_path).read_bytes()
    assert "compound_verification_delivery_receipt.json" not in frozen
    assert (root / "compound_candidates.json").is_file()
    assert (root / "compound_verification_work_plan.json").is_file()


def test_debt_safe_base_reaches_assembler_without_claiming_clean(
    tmp_path: Path,
) -> None:
    root = tmp_path / ".scratchpad"
    executor = _DeterministicChildExecutor(state_overrides={
        CHILD_IDS[2]: "COMPLETED_WITH_DEBT_SAFE_BASE",
    })

    result, _ = _execute(root, executor=executor)

    assert result["state"] == "COMPLETED_WITH_DEBT_SAFE_BASE"
    assert CHILD_IDS[9] in executor.calls
    assert (root / "verification_queue.md").is_file()
    assert result["parent_commit"]["state"] == "OUTPUT_COMMITTED"


def test_driver_cutover_delegates_and_contains_no_direct_queue_writers() -> None:
    source = inspect.getsource(D.main)
    forbidden = (
        "_write_finding_records_from_inventory(",
        "_write_mechanical_verification_queue_from_inventory(",
        "_dedup_queue_by_hypothesis(",
        "_filter_verification_queue_by_evidence(",
        "_filter_verification_queue_by_mode(",
        "_filter_sc_verification_queue_by_mode(",
        "_prepare_mandatory_primary_reverification(",
        "ensure_verify_shard_manifests(",
        "ensure_sc_verify_shard_manifests(",
        "_set_verify_queue_optional_context_debt(",
        "_arm_typed_verify_queue_routing_artifacts(",
        "_record_typed_verify_queue_routing_artifacts(",
    )
    l1_start = source.index(
        'if config["pipeline"] == "l1" and phase.name == "verify_queue":'
    )
    l1_end = source.index("# v2.4.1: SC verify queue", l1_start)
    sc_start = source.index(
        'if config.get("pipeline") != "l1" and phase.name == "sc_verify_queue":'
    )
    sc_end = source.index(
        "# v2.4.1", sc_start + len(
            'if config.get("pipeline") != "l1" and '
            'phase.name == "sc_verify_queue":'
        )
    )
    branches = {
        "verify_queue": source[l1_start:l1_end],
        "sc_verify_queue": source[sc_start:sc_end],
    }

    for phase_name, branch in branches.items():
        assert "execute_verify_queue_transaction(" in branch, (
            f"{phase_name} has not cut over to the child transaction"
        )
        for token in forbidden:
            assert token not in branch, (
                f"{phase_name} still performs direct routing mutation: {token}"
            )
