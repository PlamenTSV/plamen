"""Executable acceptance contract for the live verify-queue transaction.

This is intentionally separate from
``test_verify_queue_child_transaction_b5_b7.py``.  That fixture preserves the
first topology scaffold; this one specifies the production cutover that must
replace the live SC/L1 branch mutations.

Production must expose three explicit seams from ``verify_queue_transaction``:

``resolve_live_verify_queue_transaction_plan``
    Resolve the pipeline-specific, exact T0..T9 PhaseIO/CAS transaction.

``execute_live_verify_queue_transaction``
    Execute T0..T8 as private semantic work and perform T9 itself as the sole
    receipt-last public CAS publisher.

``validate_live_verify_queue_publication``
    Admit downstream consumption only after exact T9 PhaseIO ownership and the
    final receipt replay successfully.

The injected semantic executor is a deterministic fixture provider.  It may
materialize only private T0..T8 postimages.  T9 publication is transaction
authority and must not be delegated to it.
"""
from __future__ import annotations

import base64
import hashlib
import importlib.util
import inspect
import json
from pathlib import Path, PurePosixPath
import sys
from typing import Any, Mapping, Sequence

import pytest

from artifact_ledger import (
    record_work_unit_artifacts,
    record_work_unit_inputs,
)
import l1_composition_queue_runtime as L1C
import mandatory_reverification as MR
import p0af_v2_queue_runtime as SCP
from phase_io_contracts import (
    ArtifactSpec,
    LaunchSpec,
    PhaseIOContract,
    canonical_work_unit_key,
)
import plamen_driver as D
from plamen_types import L1_VERIFY_SHARD_MANIFESTS, SC_VERIFY_SHARD_MANIFESTS
from queue_work_items import (
    QueueWorkItem,
    build_queue_work_plan,
    queue_records_to_json,
    render_queue_markdown,
)


SCRIPTS = Path(__file__).resolve().parent
SUT_PATH = SCRIPTS / "verify_queue_transaction.py"
PRIVATE_ROOT = "_live_verify_queue_transaction"
FINAL_RECEIPT = "verify_queue_transaction.receipt.json"

CHILD_IDS = (
    "t0.live_upstream_authority",
    "t1.live_base_queue",
    "t2.live_policy_disposition",
    "t3.live_mandatory_delta",
    "t4.live_pipeline_composition_delta",
    "t5.live_generic_compound_delta",
    "t6.live_final_typed_merge",
    "t7.live_frozen_context_and_shard_plan",
    "t8.live_immutable_publication_bundle",
    "t9.live_receipt_last_cas",
)
PARENT_ID = "routing.live_parent_commit"
STATUS_PATHS = tuple(
    f"{PRIVATE_ROOT}/t{index}/status.json" for index in range(10)
)

REQUIRED_UPSTREAM = frozenset({
    "finding_delivery_successor.json",
    "live_verify_queue_methodology_projection.receipt.json",
    "preverify_inventory_successor.json",
})
SC_REQUIRED_UPSTREAM = frozenset()
COMMON_PRESENCE_ROSTER = frozenset({
    "application_skeptic_proposals.md",
    "candidate_negative_skeptic_proposals.md",
    "security_obligation_authority.json",
})
SC_PRESENCE_ROSTER = frozenset({
    "arm_before_trust_compound_candidates.json",
    "arm_before_trust_compound_work_plan.json",
    "arm_before_trust_p0af_route_debt.json",
    "chain_anti_absorption_applied_receipt.json",
    "chain_composition_verification_candidates.json",
    "chain_grouping_relations.json",
    "chain_hypotheses.md",
    "chain_tail_terminal_snapshot.json",
})
L1_PRESENCE_ROSTER = frozenset({
    "l1_composition_model_dispositions.json",
    "l1_composition_receipt.json",
    "l1_composition_runtime.json",
})

CONTEXT_INPUTS = (
    "caller_map.md",
    "methodology_reachability_manifest.json",
    "methodology_registry.json",
    "project::src/main.unit",
)
CONTEXT_CAPTURE = {
    "exact_inputs": CONTEXT_INPUTS,
    "graph_artifacts": ("caller_map.md",),
    "graph_globs": ("call_graph*.md",),
    "primary_artifacts": ("project::src/main.unit",),
    "project_sibling_directories": ("project::src",),
    "methodology_registry": "methodology_registry.json",
    "methodology_reachability": "methodology_reachability_manifest.json",
}

T0_OUTPUTS = (
    f"{PRIVATE_ROOT}/t0/input_bundle.json",
    f"{PRIVATE_ROOT}/t0/input_presence_roster.json",
    f"{PRIVATE_ROOT}/t0/context_selection.json",
    f"{PRIVATE_ROOT}/t0/resolved_plan.json",
    STATUS_PATHS[0],
)
T1_OUTPUTS = (
    f"{PRIVATE_ROOT}/t1/base_queue.md",
    f"{PRIVATE_ROOT}/t1/base_queue.json",
    f"{PRIVATE_ROOT}/t1/base_queue.work_items.json",
    STATUS_PATHS[1],
)
T2_OUTPUTS = (
    f"{PRIVATE_ROOT}/t2/active_queue.work_items.json",
    f"{PRIVATE_ROOT}/t2/evidence_excluded.work_items.json",
    f"{PRIVATE_ROOT}/t2/evidence_debt.json",
    f"{PRIVATE_ROOT}/t2/identity_accounting.json",
    f"{PRIVATE_ROOT}/t2/policy_disposition.json",
    STATUS_PATHS[2],
)
T3_OUTPUTS = (
    f"{PRIVATE_ROOT}/t3/queue_delta.work_items.json",
    f"{PRIVATE_ROOT}/t3/mandatory_reverification_denominator.json",
    f"{PRIVATE_ROOT}/t3/mandatory_reverification_routing.json",
    f"{PRIVATE_ROOT}/t3/mandatory_reverification_disposition.json",
    STATUS_PATHS[3],
)
T5_OUTPUTS = (
    f"{PRIVATE_ROOT}/t5/compound_candidates.json",
    f"{PRIVATE_ROOT}/t5/compound_verification_work_plan.json",
    f"{PRIVATE_ROOT}/t5/queue_delta.work_items.json",
    f"{PRIVATE_ROOT}/t5/compound_delivery_disposition.json",
    f"{PRIVATE_ROOT}/t5/compound_delivery_receipt.json",
    f"{PRIVATE_ROOT}/t5/compound_delivery_debt.json",
    STATUS_PATHS[5],
)
T5_CONDITIONAL = frozenset(T5_OUTPUTS[-3:-1])
T6_OUTPUTS = (
    f"{PRIVATE_ROOT}/t6/final_work_items.json",
    f"{PRIVATE_ROOT}/t6/final_excluded_work_items.json",
    f"{PRIVATE_ROOT}/t6/final_evidence_debt.json",
    f"{PRIVATE_ROOT}/t6/source_obligation_accounting.json",
    f"{PRIVATE_ROOT}/t6/final_publication_plan.json",
    STATUS_PATHS[6],
)
T7_OUTPUTS = (
    f"{PRIVATE_ROOT}/t7/context_input_capture.json",
    f"{PRIVATE_ROOT}/t7/context_input_roster.json",
    f"{PRIVATE_ROOT}/t7/verification_context_packets.json",
    f"{PRIVATE_ROOT}/t7/verification_methodology_reachability.json",
    f"{PRIVATE_ROOT}/t7/shard_plan.json",
    STATUS_PATHS[7],
)
T8_OUTPUTS = (
    f"{PRIVATE_ROOT}/t8/outer_denominator.json",
    f"{PRIVATE_ROOT}/t8/validated_publication.bundle.json",
    f"{PRIVATE_ROOT}/t8/validation_receipt.json",
    STATUS_PATHS[8],
)

COMMON_PUBLIC = frozenset({
    "compound_candidates.json",
    "compound_verification_delivery_debt.json",
    "compound_verification_delivery_disposition.json",
    "compound_verification_delivery_receipt.json",
    "compound_verification_work_plan.json",
    MR.DENOMINATOR_FILE,
    MR.QUEUE_TRANSACTION_RECEIPT_FILE,
    MR.ROUTING_FILE,
    FINAL_RECEIPT,
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
    "verify_queue_context_input_status.json",
})

L1_COMPATIBILITY_PUBLIC = frozenset({
    L1C.QUEUE_INPUT_NAME,
    L1C.DELIVERY_RECEIPT_NAME,
    L1C.DELIVERY_DEBT_NAME,
    L1C.DELIVERY_STATUS_NAME,
})
SC_COMPATIBILITY_PUBLIC = frozenset({
    SCP.INPUT_SNAPSHOT_FILE,
    SCP.RECEIPT_FILE,
    SCP.DEBT_FILE,
    SCP.STATUS_FILE,
})
NON_AUTHORIZING_LEGACY_JOURNALS = {
    "l1": frozenset({
        MR.QUEUE_TRANSACTION_JOURNAL_FILE,
        L1C.DELIVERY_JOURNAL_NAME,
    }),
    "sc": frozenset({
        MR.QUEUE_TRANSACTION_JOURNAL_FILE,
        SCP.JOURNAL_FILE,
    }),
}

RUNTIME_AUTHORITY_BASE = {
    "audit_snapshot_digest": "a" * 64,
    "trusted_queue_code_digest": "b" * 64,
    "producer_ledger_digest": "c" * 64,
    "methodology_digest": "d" * 64,
}

CASES = (
    ("sc", "sc_verify_queue", "evm", "claude"),
    ("sc", "sc_verify_queue", "evm", "codex"),
    ("l1", "verify_queue", "rust", "claude"),
    ("l1", "verify_queue", "rust", "codex"),
)


def _canonical_bytes(value: Any) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _load_sut():
    if not SUT_PATH.is_file():
        pytest.fail("live verify-queue transaction module is missing")
    name = "_plamen_live_verify_queue_transaction_acceptance"
    cached = sys.modules.get(name)
    if cached is not None:
        return cached
    spec = importlib.util.spec_from_file_location(name, SUT_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _required_callable(name: str):
    candidate = getattr(_load_sut(), name, None)
    assert callable(candidate), f"production must expose {name}"
    return candidate


@pytest.mark.parametrize("pipeline", ("sc", "l1"))
def test_live_driver_can_resolve_exact_base_upstream_roster(
    pipeline: str,
) -> None:
    resolver = _required_callable("live_verify_queue_base_upstream_roster")
    assert resolver(pipeline) == _base_upstream_inputs(pipeline)


def _shard_manifests(pipeline: str) -> tuple[str, ...]:
    source = (
        SC_VERIFY_SHARD_MANIFESTS
        if pipeline == "sc"
        else L1_VERIFY_SHARD_MANIFESTS
    )
    return tuple(sorted(source.values()))


def _projection_triplet(markdown: str) -> frozenset[str]:
    path = PurePosixPath(markdown)
    stem = path.as_posix()[:-3]
    return frozenset({
        path.as_posix(),
        stem + ".json",
        stem + ".work_items.json",
    })


def _shard_outputs(pipeline: str) -> frozenset[str]:
    return frozenset({
        output
        for manifest in _shard_manifests(pipeline)
        for output in _projection_triplet(manifest)
    })


def _pipeline_public(pipeline: str) -> frozenset[str]:
    compatibility = (
        SC_COMPATIBILITY_PUBLIC
        if pipeline == "sc"
        else L1_COMPATIBILITY_PUBLIC
    )
    return frozenset({*COMMON_PUBLIC, *compatibility, *_shard_outputs(pipeline)})


def _base_upstream_inputs(pipeline: str) -> tuple[str, ...]:
    branch = SC_PRESENCE_ROSTER if pipeline == "sc" else L1_PRESENCE_ROSTER
    branch_required = SC_REQUIRED_UPSTREAM if pipeline == "sc" else frozenset()
    return tuple(sorted({
        *REQUIRED_UPSTREAM,
        *branch_required,
        *COMMON_PRESENCE_ROSTER,
        *branch,
    }))


def _upstream_inputs(pipeline: str) -> tuple[str, ...]:
    return tuple(sorted({
        *_base_upstream_inputs(pipeline),
        *_frozen_projection(pipeline, "claude")["required_paths"],
        *(
            _chain_pair_projection(pipeline, "claude") or {}
        ).get("required_paths", ()),
    }))


def _frozen_projection(
    pipeline: str,
    backend: str,
    *,
    run_id: str | None = None,
) -> dict[str, Any]:
    digest = hashlib.sha256(
        f"fixture:{pipeline}".encode("ascii")
    ).hexdigest()
    root = f"_preverify_frozen/generation_{digest}"
    aliases = {
        "findings_inventory.md": f"{root}/findings_inventory.md",
        "finding_records.json": f"{root}/finding_records.json",
    }
    receipt = f"{root}/receipt.json"
    return {
        "schema_version": "plamen.preverify_frozen_projection.v1",
        "state": "OUTPUT_COMMITTED",
        "run_id": run_id or f"live-{pipeline}-{backend}",
        "generation_digest": digest,
        "work_unit_key": (
            f"{pipeline}/thorough/"
            f"{'evm' if pipeline == 'sc' else 'rust'}/{backend}/"
            f"{'sc_verify_queue' if pipeline == 'sc' else 'verify_queue'}/"
            f"preverify_frozen_projection.{digest}"
        ),
        "receipt_path": receipt,
        "logical_to_physical": aliases,
        "required_paths": sorted([*aliases.values(), receipt]),
        "advisory_evidence_path": (
            f"{root}/inventory_evidence_validation.md"
        ),
        "debt": [{
            "reason_code": "FIXTURE_EVIDENCE_NOT_SELECTED",
        }],
        "proof_authority": "NONE",
    }


def _chain_pair_projection(
    pipeline: str,
    backend: str,
    *,
    run_id: str | None = None,
) -> dict[str, Any] | None:
    if pipeline != "sc":
        return None
    digest = hashlib.sha256(b"fixture:sc-chain-pair").hexdigest()
    root = f"_preverify_chain_pair/generation_{digest}"
    aliases = {
        "hypotheses.md": f"{root}/hypotheses.md",
        "finding_mapping.md": f"{root}/finding_mapping.md",
    }
    receipt = f"{root}/receipt.json"
    return {
        "schema_version": "plamen.preverify_chain_pair_projection.v1",
        "state": "OUTPUT_COMMITTED",
        "safe_to_consume": True,
        "run_id": run_id or f"live-{pipeline}-{backend}",
        "generation_digest": digest,
        "work_unit_key": (
            f"sc/thorough/evm/{backend}/sc_verify_queue/"
            f"preverify_chain_pair_projection.{digest}"
        ),
        "receipt_path": receipt,
        "logical_to_physical": aliases,
        "required_paths": sorted([*aliases.values(), receipt]),
        "debt": [],
        "proof_authority": "NONE",
    }


def _required_upstream(pipeline: str) -> frozenset[str]:
    return frozenset({
        *REQUIRED_UPSTREAM,
        *_frozen_projection(pipeline, "claude")["required_paths"],
        *(
            _chain_pair_projection(pipeline, "claude") or {}
        ).get("required_paths", ()),
        *(SC_REQUIRED_UPSTREAM if pipeline == "sc" else ()),
    })


def _runtime_authority(
    pipeline: str,
    backend: str,
) -> dict[str, str]:
    return {
        **RUNTIME_AUTHORITY_BASE,
        "pipeline": pipeline,
        "mode": "thorough",
        "ecosystem": "evm" if pipeline == "sc" else "rust",
        "backend": backend,
        "run_id": f"live-{pipeline}-{backend}",
    }


def _plan(pipeline: str = "sc", backend: str = "claude") -> Mapping[str, Any]:
    resolver = _required_callable("resolve_live_verify_queue_transaction_plan")
    return resolver(
        pipeline=pipeline,
        mode="thorough",
        ecosystem="evm" if pipeline == "sc" else "rust",
        backend=backend,
        phase_name="sc_verify_queue" if pipeline == "sc" else "verify_queue",
        run_id=f"live-{pipeline}-{backend}",
        upstream_inputs=_upstream_inputs(pipeline),
        runtime_authority=_runtime_authority(pipeline, backend),
        shard_manifests=_shard_manifests(pipeline),
        context_capture=CONTEXT_CAPTURE,
        preverify_frozen_projection=_frozen_projection(pipeline, backend),
        preverify_chain_pair_projection=_chain_pair_projection(
            pipeline, backend
        ),
    )


def _children(plan: Mapping[str, Any]) -> tuple[Mapping[str, Any], ...]:
    value = plan.get("children")
    assert isinstance(value, Sequence) and not isinstance(value, (str, bytes))
    return tuple(value)


def _child_map(plan: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    return {str(row["work_unit_id"]): row for row in _children(plan)}


def _outputs(unit: Mapping[str, Any]) -> tuple[Mapping[str, Any], ...]:
    value = unit.get("outputs")
    assert isinstance(value, Sequence) and not isinstance(value, (str, bytes))
    return tuple(value)


def _output_paths(unit: Mapping[str, Any]) -> frozenset[str]:
    return frozenset(str(row["path"]) for row in _outputs(unit))


def _required_input_paths(unit: Mapping[str, Any]) -> frozenset[str]:
    value = unit.get("exact_inputs")
    assert isinstance(value, Sequence) and not isinstance(value, (str, bytes))
    return frozenset(map(str, value))


def _declared_input_paths(unit: Mapping[str, Any]) -> frozenset[str]:
    value = unit.get("declared_input_denominator", unit.get("exact_inputs"))
    assert isinstance(value, Sequence) and not isinstance(value, (str, bytes))
    return frozenset(map(str, value))


def _t4_outputs(pipeline: str) -> tuple[str, ...]:
    prefix = f"{PRIVATE_ROOT}/t4"
    if pipeline == "l1":
        companions = (
            f"{prefix}/l1_queue_input.work_items.json",
            f"{prefix}/l1_delivery_receipt.json",
            f"{prefix}/l1_delivery_debt.json",
            f"{prefix}/l1_delivery_status.json",
        )
    else:
        companions = (
            f"{prefix}/p0af_queue_input.work_items.json",
            f"{prefix}/p0af_delivery_receipt.json",
            f"{prefix}/p0af_delivery_debt.json",
            f"{prefix}/p0af_delivery_status.json",
        )
    return (
        f"{prefix}/queue_delta.work_items.json",
        f"{prefix}/composition_disposition.json",
        *companions,
        STATUS_PATHS[4],
    )


def _expected_outputs(pipeline: str) -> dict[str, frozenset[str]]:
    return {
        CHILD_IDS[0]: frozenset(T0_OUTPUTS),
        CHILD_IDS[1]: frozenset(T1_OUTPUTS),
        CHILD_IDS[2]: frozenset(T2_OUTPUTS),
        CHILD_IDS[3]: frozenset(T3_OUTPUTS),
        CHILD_IDS[4]: frozenset(_t4_outputs(pipeline)),
        CHILD_IDS[5]: frozenset(T5_OUTPUTS),
        CHILD_IDS[6]: frozenset(T6_OUTPUTS),
        CHILD_IDS[7]: frozenset(T7_OUTPUTS),
        CHILD_IDS[8]: frozenset(T8_OUTPUTS),
        CHILD_IDS[9]: frozenset({
            *_pipeline_public(pipeline),
            STATUS_PATHS[9],
        }),
    }


def _nonconditional_outputs(
    unit: Mapping[str, Any],
) -> frozenset[str]:
    return frozenset(
        str(row["path"])
        for row in _outputs(unit)
        if row.get("artifact_class") != "CONDITIONAL"
    )


def _expected_inputs(
    plan: Mapping[str, Any],
    pipeline: str,
) -> dict[str, frozenset[str]]:
    children = _child_map(plan)
    return {
        CHILD_IDS[0]: frozenset(_upstream_inputs(pipeline)),
        CHILD_IDS[1]: frozenset(T0_OUTPUTS),
        CHILD_IDS[2]: frozenset({
            *T1_OUTPUTS,
            T0_OUTPUTS[0],
            T0_OUTPUTS[2],
        }),
        CHILD_IDS[3]: frozenset({
            T0_OUTPUTS[0],
            T0_OUTPUTS[2],
            T2_OUTPUTS[0],
            T2_OUTPUTS[1],
            STATUS_PATHS[2],
        }),
        CHILD_IDS[4]: frozenset({
            T0_OUTPUTS[0],
            T2_OUTPUTS[0],
            STATUS_PATHS[2],
        }),
        CHILD_IDS[5]: frozenset({
            T0_OUTPUTS[0],
            T0_OUTPUTS[2],
            T2_OUTPUTS[0],
            STATUS_PATHS[2],
        }),
        CHILD_IDS[6]: frozenset({
            path
            for work_id in CHILD_IDS[2:6]
            for path in _output_paths(children[work_id])
        }),
        CHILD_IDS[7]: frozenset({
            *T6_OUTPUTS,
            *CONTEXT_INPUTS,
        }),
        CHILD_IDS[8]: frozenset({
            path
            for work_id in CHILD_IDS[:8]
            for path in _output_paths(children[work_id])
        }),
        CHILD_IDS[9]: frozenset(T8_OUTPUTS),
    }


def _plan_normalized(plan: Mapping[str, Any]) -> tuple[Any, ...]:
    return tuple(
        (
            unit["work_unit_id"],
            tuple(sorted(_declared_input_paths(unit))),
            tuple(sorted(
                (
                    str(row["path"]),
                    str(row.get("artifact_class") or ""),
                    str(row.get("condition_id") or ""),
                )
                for row in _outputs(unit)
            )),
        )
        for unit in _children(plan)
    )


def test_live_transaction_exports_three_explicit_cutover_seams() -> None:
    for name in (
        "resolve_live_verify_queue_transaction_plan",
        "execute_live_verify_queue_transaction",
        "validate_live_verify_queue_publication",
    ):
        _required_callable(name)


@pytest.mark.parametrize(
    "pipeline,phase_name,ecosystem,backend",
    CASES,
)
def test_live_plan_has_exact_pipeline_identity_and_t0_t9_roster(
    pipeline: str,
    phase_name: str,
    ecosystem: str,
    backend: str,
) -> None:
    plan = _plan(pipeline, backend)

    assert plan["schema_version"] == "plamen.live_verify_queue_plan.v1"
    assert plan["pipeline"] == pipeline
    assert plan["phase_name"] == phase_name
    assert plan["ecosystem"] == ecosystem
    assert plan["backend"] == backend
    assert tuple(unit["work_unit_id"] for unit in _children(plan)) == CHILD_IDS
    assert plan["parent"]["work_unit_id"] == PARENT_ID
    assert plan["parent"]["outputs"] == []
    assert plan["parent"]["read_only"] is True


@pytest.mark.parametrize("pipeline", ("sc", "l1"))
def test_every_child_has_exact_phaseio_and_disjoint_output_authority(
    pipeline: str,
) -> None:
    children = _child_map(_plan(pipeline))
    expected = _expected_outputs(pipeline)
    owner: dict[str, str] = {}

    for work_id in CHILD_IDS:
        unit = children[work_id]
        assert _output_paths(unit) == expected[work_id]
        phase_io = unit.get("phase_io")
        assert phase_io == {
            "resolve_before_output": True,
            "record_inputs": True,
            "revalidate_inputs_before_commit": True,
            "record_artifacts": True,
            "output_prestate_cas": True,
        }
        for path in _output_paths(unit):
            assert path not in owner, f"{path} owned twice"
            owner[path] = work_id

    assert set(owner) == set().union(*expected.values())


@pytest.mark.parametrize("pipeline", ("sc", "l1"))
def test_t0_binds_complete_real_upstream_presence_and_runtime_authority(
    pipeline: str,
) -> None:
    plan = _plan(pipeline)
    t0 = _child_map(plan)[CHILD_IDS[0]]
    expected = set(_upstream_inputs(pipeline))

    assert _required_input_paths(t0) == expected
    assert set(plan["external_input_denominator"]) == {
        *expected,
        *CONTEXT_INPUTS,
    }
    required = _required_upstream(pipeline)
    assert set(t0["presence_roster"]) == expected - required
    assert t0["required_inputs"] == sorted(required)
    assert t0["runtime_authority"] == _runtime_authority(pipeline, "claude")
    assert t0["producer_binding_policy"] == {
        "owner": True,
        "writer": True,
        "run_id": True,
        "contract_digest": True,
        "launch_digest": True,
        "sha256": True,
        "size": True,
        "explicit_absence": True,
    }


@pytest.mark.parametrize("pipeline", ("sc", "l1"))
def test_declared_input_graph_is_exact_closed_and_topological(
    pipeline: str,
) -> None:
    plan = _plan(pipeline)
    children = _child_map(plan)
    expected = _expected_inputs(plan, pipeline)
    available = set(plan["external_input_denominator"])

    for work_id in CHILD_IDS:
        declared = _declared_input_paths(children[work_id])
        assert declared == expected[work_id]
        assert declared <= available, (
            f"{work_id} reads future/undeclared inputs: "
            f"{sorted(declared - available)}"
        )
        available.update(_output_paths(children[work_id]))


@pytest.mark.parametrize("pipeline", ("sc", "l1"))
def test_outer_denominator_contains_every_child_output_without_exceptions(
    pipeline: str,
) -> None:
    plan = _plan(pipeline)
    declared_outputs = {
        path
        for unit in _children(plan)
        for path in _output_paths(unit)
    }

    assert set(plan["outer_output_denominator"]) == declared_outputs
    assert set(plan["external_input_denominator"]).isdisjoint(
        plan["outer_output_denominator"]
    )
    assert T5_CONDITIONAL <= set(plan["outer_output_denominator"])
    assert _pipeline_public(pipeline) <= set(plan["outer_output_denominator"])


@pytest.mark.parametrize("pipeline", ("sc", "l1"))
def test_t4_is_a_real_pipeline_specific_composition_delta(
    pipeline: str,
) -> None:
    t4 = _child_map(_plan(pipeline))[CHILD_IDS[4]]
    outputs = _output_paths(t4)

    assert outputs == frozenset(_t4_outputs(pipeline))
    assert t4["pipeline_adapter"] == (
        "p0af_v2_queue_adapter" if pipeline == "sc"
        else "l1_composition_queue_adapter"
    )
    assert t4["public_queue_mutation"] is False
    other_tokens = (
        ("l1_",) if pipeline == "sc" else ("p0af_",)
    )
    assert not any(
        token in path for token in other_tokens for path in outputs
    )


@pytest.mark.parametrize("pipeline", ("sc", "l1"))
def test_t5_generic_compound_receipt_or_debt_is_closed_and_exact(
    pipeline: str,
) -> None:
    t5 = _child_map(_plan(pipeline))[CHILD_IDS[5]]
    by_path = {str(row["path"]): row for row in _outputs(t5)}
    group = t5["conditional_groups"]["compound_delivery"]

    assert set(group) == {
        "selection",
        "receipt",
        "debt",
        "disposition",
        "status",
    }
    assert group["selection"] == "EXACTLY_ONE"
    assert {group["receipt"], group["debt"]} == T5_CONDITIONAL
    assert group["disposition"] == T5_OUTPUTS[3]
    assert group["status"] == STATUS_PATHS[5]
    for path in T5_CONDITIONAL:
        assert by_path[path]["artifact_class"] == "CONDITIONAL"
        assert by_path[path]["exclusive_group"] == "compound_delivery"
        assert by_path[path]["condition_id"]


@pytest.mark.parametrize("pipeline", ("sc", "l1"))
def test_t6_is_sole_typed_merge_and_closes_every_source_obligation(
    pipeline: str,
) -> None:
    plan = _plan(pipeline)
    children = _child_map(plan)
    t6 = children[CHILD_IDS[6]]

    assert _declared_input_paths(t6) == {
        path
        for work_id in CHILD_IDS[2:6]
        for path in _output_paths(children[work_id])
    }
    assert t6["merge_sources"] == {
        "policy_active": T2_OUTPUTS[0],
        "policy_excluded": T2_OUTPUTS[1],
        "policy_debt": T2_OUTPUTS[2],
        "mandatory_delta": T3_OUTPUTS[0],
        "pipeline_composition_delta": _t4_outputs(pipeline)[0],
        "generic_compound_delta": T5_OUTPUTS[2],
    }
    assert t6["identity_invariants"] == {
        "unique_work_item_ids": True,
        "additive_collision_becomes_visible_debt": True,
        "source_obligation_partition": [
            "ACTIVE",
            "AUTHORIZED_EXCLUDED",
            "VISIBLE_DEBT",
        ],
        "exact_partition": True,
    }


@pytest.mark.parametrize("pipeline", ("sc", "l1"))
def test_t7_freezes_all_context_and_purely_partitions_final_work(
    pipeline: str,
) -> None:
    t7 = _child_map(_plan(pipeline))[CHILD_IDS[7]]
    capture = t7["dynamic_input_capture"]
    coverage = t7["coverage_invariant"]

    assert capture["content_addressed"] is True
    assert capture["revalidate_before_commit"] is True
    assert set(capture["exact_inputs"]) == set(CONTEXT_INPUTS)
    assert set(capture["enumerates"]) == {
        "graph_artifacts",
        "graph_globs",
        "primary_artifacts",
        "project_sibling_directories",
        "methodology_registry",
        "methodology_reachability",
    }
    assert capture["enumerate_every_primary_artifact"] is True
    assert capture["enumerate_every_project_sibling"] is True
    assert t7["shard_planner"]["pure"] is True
    assert t7["shard_planner"]["may_invoke_compound_delivery"] is False
    assert coverage == {
        "relation": "EXACT_WORK_ITEM_ID_SET_EQUALITY",
        "denominator": T6_OUTPUTS[0],
        "context_packets": T7_OUTPUTS[2],
        "shard_assignments": T7_OUTPUTS[4],
    }


@pytest.mark.parametrize("pipeline", ("sc", "l1"))
def test_t8_replays_full_denominator_including_conditionals(
    pipeline: str,
) -> None:
    plan = _plan(pipeline)
    children = _child_map(plan)
    t8 = children[CHILD_IDS[8]]
    through_t7 = {
        path
        for work_id in CHILD_IDS[:8]
        for path in _output_paths(children[work_id])
    }

    assert _declared_input_paths(t8) == through_t7
    assert T5_CONDITIONAL <= _declared_input_paths(t8)
    assert t8["validates_conditional_groups"] == ["compound_delivery"]
    assert t8["semantic_replay"] is True
    assert t8["bundle"]["immutable"] is True
    assert t8["bundle"]["content_addressed"] is True
    assert set(t8["bundle"]["public_output_denominator"]) == (
        _pipeline_public(pipeline)
    )


@pytest.mark.parametrize("pipeline", ("sc", "l1"))
def test_t9_is_sole_public_owner_and_receipt_last_cas(
    pipeline: str,
) -> None:
    plan = _plan(pipeline)
    children = _child_map(plan)
    t9 = children[CHILD_IDS[9]]
    public = _pipeline_public(pipeline)

    assert _output_paths(t9) == {*public, STATUS_PATHS[9]}
    for work_id in CHILD_IDS[:9]:
        assert _output_paths(children[work_id]).isdisjoint(public)
    publication = t9["publication"]
    assert publication["mode"] == "RECEIPT_LAST_CAS"
    assert publication["source_bundle"] == T8_OUTPUTS[1]
    assert publication["validation_receipt"] == T8_OUTPUTS[2]
    assert publication["output_prestate_cas"] is True
    assert publication["re_read_every_destination"] is True
    assert publication["phase_io_commit_before_parent"] is True
    assert publication["order"][-1] == FINAL_RECEIPT
    assert set(publication["order"]) == public
    assert len(publication["order"]) == len(public)
    assert t9["semantic_executor_invoked"] is False


@pytest.mark.parametrize(
    "pipeline,phase_name,ecosystem,backend",
    CASES,
)
def test_public_denominator_includes_every_real_compatibility_and_shard_output(
    pipeline: str,
    phase_name: str,
    ecosystem: str,
    backend: str,
) -> None:
    del phase_name, ecosystem
    plan = _plan(pipeline, backend)
    public = set(plan["public_output_denominator"])

    assert public == set(_pipeline_public(pipeline))
    assert COMMON_PUBLIC <= public
    assert _shard_outputs(pipeline) <= public
    assert (
        SC_COMPATIBILITY_PUBLIC if pipeline == "sc"
        else L1_COMPATIBILITY_PUBLIC
    ) <= public
    assert FINAL_RECEIPT in public


@pytest.mark.parametrize("pipeline", ("sc", "l1"))
def test_legacy_inner_journals_are_closed_non_authority_not_consumers(
    pipeline: str,
) -> None:
    plan = _plan(pipeline)
    journals = NON_AUTHORIZING_LEGACY_JOURNALS[pipeline]
    all_inputs = {
        path for unit in _children(plan) for path in _declared_input_paths(unit)
    }
    all_outputs = {
        path for unit in _children(plan) for path in _output_paths(unit)
    }

    assert set(plan["non_authorizing_legacy_journals"]) == journals
    assert journals.isdisjoint(plan["public_output_denominator"])
    assert journals.isdisjoint(all_inputs | all_outputs)
    assert plan["conditional_closure"] == {
        "compound_delivery": {
            "receipt": "compound_verification_delivery_receipt.json",
            "debt": "compound_verification_delivery_debt.json",
            "disposition": "compound_verification_delivery_disposition.json",
            "selection": "EXACTLY_ONE",
        },
        "legacy_journal_can_authorize": False,
    }


@pytest.mark.parametrize("pipeline", ("sc", "l1"))
def test_parent_requires_ledger_committed_t9_not_status_self_report(
    pipeline: str,
) -> None:
    parent = _plan(pipeline)["parent"]

    assert parent["requires_committed_child"] == CHILD_IDS[9]
    assert parent["requires_execution_state"] == "OUTPUT_COMMITTED"
    assert parent["status_json_is_authority"] is False
    assert set(parent["exact_inputs"]) == {
        FINAL_RECEIPT,
        STATUS_PATHS[9],
        T8_OUTPUTS[2],
    }


@pytest.mark.parametrize("pipeline", ("sc", "l1"))
def test_claude_codex_have_identical_semantic_topology(
    pipeline: str,
) -> None:
    assert _plan_normalized(_plan(pipeline, "claude")) == (
        _plan_normalized(_plan(pipeline, "codex"))
    )


def test_sc_l1_differ_in_authority_and_composition_not_only_shards() -> None:
    sc = _plan("sc")
    l1 = _plan("l1")
    sc_children = _child_map(sc)
    l1_children = _child_map(l1)
    sc_projection_paths = set(
        sc["preverify_frozen_projection"]["required_paths"]
    )
    sc_projection_paths.update(
        sc["preverify_chain_pair_projection"]["required_paths"]
    )
    l1_projection_paths = set(
        l1["preverify_frozen_projection"]["required_paths"]
    )

    assert (
        (
            _required_input_paths(sc_children[CHILD_IDS[0]])
            - sc_projection_paths
        )
        ^ (
            _required_input_paths(l1_children[CHILD_IDS[0]])
            - l1_projection_paths
        )
    ) == (
        SC_PRESENCE_ROSTER
        ^ L1_PRESENCE_ROSTER
        ^ SC_REQUIRED_UPSTREAM
    )
    assert _output_paths(sc_children[CHILD_IDS[4]]) != (
        _output_paths(l1_children[CHILD_IDS[4]])
    )
    assert (
        set(sc["public_output_denominator"])
        ^ set(l1["public_output_denominator"])
    ) >= (SC_COMPATIBILITY_PUBLIC ^ L1_COMPATIBILITY_PUBLIC)


class _LiveSemanticExecutor:
    def __init__(self, plan: Mapping[str, Any]) -> None:
        self.plan = plan
        self.calls: list[str] = []
        branch = "SC-COMPOSE-1" if plan["pipeline"] == "sc" else "L1-COMPOSE-1"
        self.final_ids = (
            "BASE-1",
            "MANDATORY-REOPEN-1",
            branch,
            "COMPOUND-1",
        )

    def _projection(self, path: str, work_id: str) -> bytes:
        if path.endswith(".md"):
            return f"# Fixture projection for {work_id}\n".encode()
        if path == f"{PRIVATE_ROOT}/t0/resolved_plan.json":
            return _canonical_bytes(self.plan)
        if path == T1_OUTPUTS[2]:
            return _canonical_bytes({"work_item_ids": ["BASE-1"]})
        if path == T2_OUTPUTS[0]:
            return _canonical_bytes({"work_item_ids": ["BASE-1"]})
        if path == T3_OUTPUTS[0]:
            return _canonical_bytes({
                "work_item_ids": ["MANDATORY-REOPEN-1"]
            })
        if path == _t4_outputs(self.plan["pipeline"])[0]:
            branch = (
                "SC-COMPOSE-1"
                if self.plan["pipeline"] == "sc"
                else "L1-COMPOSE-1"
            )
            return _canonical_bytes({"work_item_ids": [branch]})
        if path == T5_OUTPUTS[2]:
            return _canonical_bytes({"work_item_ids": ["COMPOUND-1"]})
        if path == T6_OUTPUTS[0]:
            return _canonical_bytes({"work_item_ids": list(self.final_ids)})
        if path == T7_OUTPUTS[2]:
            return _canonical_bytes({
                "packets": [
                    {"work_item_id": item_id} for item_id in self.final_ids
                ]
            })
        if path == T7_OUTPUTS[4]:
            return _canonical_bytes({
                "assignments": [
                    {"work_item_id": item_id, "shard": "fixture-0"}
                    for item_id in self.final_ids
                ]
            })
        return _canonical_bytes({
            "schema_version": "plamen.live_fixture_projection.v1",
            "path": path,
            "work_unit_id": work_id,
        })

    def _public_bytes(self) -> dict[str, bytes]:
        public = set(self.plan["public_output_denominator"])
        public.remove("compound_verification_delivery_debt.json")
        rows: dict[str, bytes] = {}
        typed_items = tuple(
            QueueWorkItem.from_legacy_row({
                "finding id": work_id,
                "severity": "Medium",
                "title": f"Fixture candidate {work_id}",
                "bug class": "FIXTURE",
                "preferred tag": "CODE-TRACE",
                "location": f"src/Fixture.sol:{index}",
                "primary artifact": "findings_inventory.md",
                "poc class": "structural",
            })
            for index, work_id in enumerate(self.final_ids, start=1)
        )
        typed_plan = build_queue_work_plan(
            typed_items,
            {"fixture-0": tuple(self.final_ids)},
            planner_version="live-fixture-v1",
        )
        shard_work_items = sorted(
            path
            for path in _shard_outputs(self.plan["pipeline"])
            if path.endswith(".work_items.json")
        )
        for path in sorted(public):
            if path == "verification_queue.md":
                rows[path] = render_queue_markdown(typed_items).encode("utf-8")
            elif path.endswith(".md"):
                rows[path] = b"# Live fixture public projection\n"
            elif path == "verification_queue.work_items.json":
                rows[path] = (
                    queue_records_to_json(typed_items) + "\n"
                ).encode("utf-8")
            elif path == "verification_queue.work_plan.json":
                rows[path] = (typed_plan.to_json() + "\n").encode("utf-8")
            elif path == "verification_context_packets.json":
                rows[path] = _canonical_bytes({
                    "packets": [
                        {"work_item_id": item_id}
                        for item_id in self.final_ids
                    ]
                })
            elif path in shard_work_items:
                rows[path] = _canonical_bytes({
                    "work_item_ids": (
                        list(self.final_ids)
                        if path == shard_work_items[0]
                        else []
                    )
                })
            else:
                rows[path] = _canonical_bytes({
                    "schema_version": "plamen.live_fixture_public.v1",
                    "path": path,
                })
        rows[FINAL_RECEIPT] = _canonical_bytes({
            "schema_version": "plamen.live_verify_queue_receipt.v1",
            "state": "OUTPUT_COMMITTED",
            "run_id": self.plan["run_id"],
            "plan_digest": self.plan["plan_digest"],
            "proof_authority": "NONE",
        })
        return rows

    def __call__(
        self,
        *,
        unit: Mapping[str, Any],
        frozen_inputs: Mapping[str, bytes],
    ) -> Mapping[str, Any]:
        del frozen_inputs
        work_id = str(unit["work_unit_id"])
        if work_id == CHILD_IDS[9]:
            raise AssertionError("T9 CAS publication cannot be delegated")
        self.calls.append(work_id)
        outputs: dict[str, bytes] = {}
        conditional_states: dict[str, str] = {}
        for row in _outputs(unit):
            path = str(row["path"])
            if path in STATUS_PATHS:
                continue
            if row.get("artifact_class") == "CONDITIONAL":
                produced = path == T5_OUTPUTS[4]
                conditional_states[path] = (
                    "PRODUCED" if produced else "NOT_TRIGGERED"
                )
                if not produced:
                    continue
            outputs[path] = self._projection(path, work_id)
        if work_id == CHILD_IDS[8]:
            public_rows = self._public_bytes()
            file_rows = {
                path: {
                    "content_b64": base64.b64encode(raw).decode("ascii"),
                    "sha256": _sha(raw),
                    "size": len(raw),
                }
                for path, raw in sorted(public_rows.items())
            }
            bundle = {
                "schema_version": "plamen.live_verify_queue_publication_bundle.v1",
                "plan_digest": self.plan["plan_digest"],
                "public_output_denominator": sorted(
                    self.plan["public_output_denominator"]
                ),
                "active_output_denominator": sorted(public_rows),
                "selected_conditionals": {
                    "compound_delivery": (
                        "compound_verification_delivery_receipt.json"
                    )
                },
                "publication_order": [
                    *sorted(set(public_rows) - {FINAL_RECEIPT}),
                    FINAL_RECEIPT,
                ],
                "files": file_rows,
            }
            outputs[T8_OUTPUTS[1]] = _canonical_bytes(bundle)
        return {
            "state": "COMMITTED_APPLIED",
            "outputs": outputs,
            "conditional_states": conditional_states,
        }


def _seed_inputs(
    scratchpad: Path,
    project: Path,
    pipeline: str,
    backend: str = "claude",
) -> None:
    scratchpad.mkdir(parents=True, exist_ok=True)
    mode = "thorough"
    ecosystem = "evm" if pipeline == "sc" else "rust"
    run_id = f"live-{pipeline}-{backend}"
    phase = "preverify_fixture_authority"
    work_unit_id = "frozen_upstream"
    owner = canonical_work_unit_key(
        pipeline,
        mode,
        ecosystem,
        backend,
        phase,
        work_unit_id,
    )
    contract = PhaseIOContract(
        pipeline=pipeline,
        mode=mode,
        ecosystem=ecosystem,
        backend=backend,
        phase=phase,
        work_unit_id=work_unit_id,
        outputs=tuple(
            ArtifactSpec(
                root="scratchpad",
                path=relative,
                owner_key=owner,
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                write_mode="CREATE",
                schema_version="fixture.live-upstream.v1",
                minimum_gate="STRUCTURAL",
                consumers=(
                    (
                        "sc_verify_queue"
                        if pipeline == "sc"
                        else "verify_queue"
                    )
                    + "/t0.live_upstream_authority",
                ),
            )
            for relative in _upstream_inputs(pipeline)
        ),
        immutable_inputs=(),
        bounded_lookup_inputs=(),
        model_invoked=False,
    )
    launch = LaunchSpec(
        work_unit_key=contract.key,
        pipeline=pipeline,
        mode=mode,
        ecosystem=ecosystem,
        backend=backend,
        model="driver",
        timeout_s=60,
        exec_mode="python",
        tool_policy=("filesystem",),
    )
    record_work_unit_inputs(
        scratchpad,
        project,
        contract,
        launch,
        run_id=run_id,
    )
    for relative in _upstream_inputs(pipeline):
        path = scratchpad / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.suffix == ".md":
            raw = b"# Live upstream fixture\n"
        else:
            raw = _canonical_bytes({"artifact": relative})
        path.write_bytes(raw)
    record_work_unit_artifacts(
        scratchpad,
        project,
        contract,
        launch,
        run_id=run_id,
        actor="DRIVER",
    )
    for relative in CONTEXT_INPUTS:
        if relative.startswith("project::"):
            path = project / relative[len("project::"):]
            raw = b"// fixture source\n"
        else:
            path = scratchpad / relative
            raw = _canonical_bytes({"artifact": relative})
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)


def _execute(
    tmp_path: Path,
    pipeline: str,
    backend: str = "claude",
    *,
    failpoint=None,
) -> tuple[Mapping[str, Any], _LiveSemanticExecutor, Path]:
    plan = _plan(pipeline, backend)
    scratchpad = tmp_path / ".scratchpad"
    _seed_inputs(scratchpad, tmp_path, pipeline, backend)
    executor = _LiveSemanticExecutor(plan)
    execute = _required_callable("execute_live_verify_queue_transaction")
    result = execute(
        scratchpad=scratchpad,
        project_root=tmp_path,
        plan=plan,
        run_id=f"live-{pipeline}-{backend}",
        semantic_executor=executor,
        failpoint=failpoint,
    )
    return result, executor, scratchpad


@pytest.mark.parametrize(
    "pipeline,phase_name,ecosystem,backend",
    CASES,
)
def test_live_runtime_has_pipeline_and_backend_parity(
    tmp_path: Path,
    pipeline: str,
    phase_name: str,
    ecosystem: str,
    backend: str,
) -> None:
    result, executor, _root = _execute(tmp_path, pipeline, backend)

    assert result["state"] == "OUTPUT_COMMITTED"
    assert result["safe_to_consume"] is True
    assert result["pipeline"] == pipeline
    assert result["phase_name"] == phase_name
    assert result["ecosystem"] == ecosystem
    assert result["backend"] == backend
    assert executor.calls == list(CHILD_IDS[:9])
    assert result["parent_commit"]["state"] == "OUTPUT_COMMITTED"


@pytest.mark.parametrize("pipeline", ("sc", "l1"))
def test_every_final_work_id_has_exact_context_and_shard_coverage(
    tmp_path: Path,
    pipeline: str,
) -> None:
    _result, executor, root = _execute(tmp_path, pipeline)
    final_ids = set(executor.final_ids)
    queue = json.loads(
        (root / "verification_queue.work_items.json").read_text()
    )
    context = json.loads(
        (root / "verification_context_packets.json").read_text()
    )
    shard_ids: list[str] = []
    for path in _shard_outputs(pipeline):
        if path.endswith(".work_items.json"):
            payload = json.loads((root / path).read_text())
            shard_ids.extend(map(str, payload["work_item_ids"]))

    assert {
        str(row["work_item_id"]) for row in queue["rows"]
    } == final_ids
    assert {
        str(row["work_item_id"]) for row in context["packets"]
    } == final_ids
    assert set(shard_ids) == final_ids
    assert len(shard_ids) == len(final_ids)


@pytest.mark.parametrize("pipeline", ("sc", "l1"))
def test_no_public_queue_byte_exists_before_t9_begins(
    tmp_path: Path,
    pipeline: str,
) -> None:
    module = _load_sut()
    injected = getattr(module, "LiveVerifyQueueInjectedFailure", RuntimeError)

    def failpoint(label: str) -> None:
        if label == "after_t8_commit":
            raise injected(label)

    with pytest.raises(injected):
        _execute(tmp_path, pipeline, failpoint=failpoint)
    root = tmp_path / ".scratchpad"
    assert all(
        not (root / path).exists() for path in _pipeline_public(pipeline)
    )


@pytest.mark.parametrize("pipeline", ("sc", "l1"))
def test_t9_emits_every_destination_failpoint_and_receipt_is_last(
    tmp_path: Path,
    pipeline: str,
) -> None:
    observed: list[str] = []

    def failpoint(label: str) -> None:
        prefix = "after_t9_replace:"
        if label.startswith(prefix):
            observed.append(label[len(prefix):])

    _execute(tmp_path, pipeline, failpoint=failpoint)
    order = _child_map(_plan(pipeline))[CHILD_IDS[9]]["publication"]["order"]

    assert observed == order
    assert observed[-1] == FINAL_RECEIPT
    assert set(observed) == _pipeline_public(pipeline)


@pytest.mark.parametrize("pipeline", ("sc", "l1"))
def test_downstream_refuses_complete_looking_bytes_without_t9_commit(
    tmp_path: Path,
    pipeline: str,
) -> None:
    module = _load_sut()
    injected = getattr(module, "LiveVerifyQueueInjectedFailure", RuntimeError)

    def failpoint(label: str) -> None:
        if label == f"before_t9_replace:{FINAL_RECEIPT}":
            raise injected(label)

    with pytest.raises(injected):
        _execute(tmp_path, pipeline, failpoint=failpoint)
    root = tmp_path / ".scratchpad"
    validate = _required_callable("validate_live_verify_queue_publication")
    result = validate(
        scratchpad=root,
        plan=_plan(pipeline),
        run_id=f"live-{pipeline}-claude",
    )

    assert result["safe_to_consume"] is False
    assert result["t9_execution_state"] != "OUTPUT_COMMITTED"
    assert not (root / FINAL_RECEIPT).exists()


@pytest.mark.parametrize("pipeline", ("sc", "l1"))
def test_forged_final_receipt_bytes_do_not_replace_phaseio_t9_authority(
    tmp_path: Path,
    pipeline: str,
) -> None:
    module = _load_sut()
    injected = getattr(module, "LiveVerifyQueueInjectedFailure", RuntimeError)

    def failpoint(label: str) -> None:
        if label == f"before_t9_replace:{FINAL_RECEIPT}":
            raise injected(label)

    with pytest.raises(injected):
        _execute(tmp_path, pipeline, failpoint=failpoint)
    root = tmp_path / ".scratchpad"
    bundle = json.loads((root / T8_OUTPUTS[1]).read_text())
    forged = base64.b64decode(
        bundle["files"][FINAL_RECEIPT]["content_b64"], validate=True
    )
    (root / FINAL_RECEIPT).write_bytes(forged)
    result = _required_callable("validate_live_verify_queue_publication")(
        scratchpad=root,
        plan=_plan(pipeline),
        run_id=f"live-{pipeline}-claude",
    )

    assert result["safe_to_consume"] is False
    assert result["t9_execution_state"] != "OUTPUT_COMMITTED"


def test_live_driver_shared_cutover_delegates_once_and_does_not_mutate_public_queue(
) -> None:
    main_source = inspect.getsource(D.main)
    boundary = inspect.getsource(D._run_live_verify_queue_phase_boundary)
    forbidden = (
        "_write_mechanical_verification_queue_from_inventory(",
        "_dedup_queue_by_hypothesis(",
        "_filter_verification_queue_by_evidence(",
        "_filter_verification_queue_by_mode(",
        "_filter_sc_verification_queue_by_mode(",
        "backfill_unrouted_inventory_into_queue(",
        "apply_l1_composition_queue_delivery(",
        "_prepare_mandatory_primary_reverification(",
        "_run_p0af_v2_live_queue_boundary(",
        "ensure_verify_shard_manifests(",
        "ensure_sc_verify_shard_manifests(",
        "_record_typed_verify_queue_routing_artifacts(",
    )

    assert main_source.count("_run_live_verify_queue_phase_boundary(") == 1
    assert "run_live_verify_queue_driver_cutover(" not in main_source
    assert boundary.count("run_live_verify_queue_driver_cutover(") == 1
    assert "safe_to_consume" in boundary
    assert "execute_live_verify_queue_transaction(" not in boundary
    for token in forbidden:
        assert token not in boundary
