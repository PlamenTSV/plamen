"""MC-0A red/green contracts for scalable MethodCard authority semantics."""
from __future__ import annotations

import copy
import hashlib
from pathlib import Path

import pytest

import method_card_application_authority as application
from method_card_application_authority import (
    APPLICATION_AUTHORITY_V3_SCHEMA,
    MethodCardRuntimeReplayWitness,
    PRODUCER_TYPED_OUTPUT_SCHEMA,
    REVIEWER_TYPED_OUTPUT_SCHEMA,
    canonical_method_card_application_authority_v3_bytes,
    reconcile_method_card_application_v3,
    validate_method_card_application_authority_v3,
)
from method_card_runtime_authority import (
    ACTIVATED_AUTHORITY_SCHEMA,
    ACTIVATED_DENOMINATOR_SOURCE_SCHEMA,
    AUTHORITY_SCHEMA,
    MethodCardRuntimeAuthorityError,
    canonical_activated_runtime_authority_bytes,
    compile_activated_method_card_denominator_source,
    compile_activated_method_card_runtime_authority,
    compile_activated_method_card_runtime_input_binding,
    integration_debt_output,
    render_selected_method_fragment,
    validate_activated_method_card_runtime_authority,
)
from program_facts_types import canonical_file_bytes, canonical_json_bytes
import test_method_card_runtime_authority_r2 as fixtures
from test_typed_worker_output_authority_p0 import build_typed_fixture
from typed_worker_output_authority import (
    canonical_typed_worker_output_authority_bytes,
    replay_typed_worker_output,
)


SOURCE_FILES = {
    "contracts/Auth.sol": b"contract Auth { function gate() external {} }\n",
    "contracts/Value.sol": b"contract Value { function move() external {} }\n",
}


def _nodes(*, lower_bound: bool = False) -> list[dict]:
    return [
        {
            "target_id": "target:auth-a",
            "node_kind": "function",
            "boundaries": [],
            "effects": ["authorization"],
            "entity_properties": [],
            "source_paths": ["contracts/Auth.sol"],
        },
        {
            "target_id": "target:auth-b",
            "node_kind": "function",
            "boundaries": [],
            "effects": ["authorization"],
            "entity_properties": [],
            "source_paths": ([] if lower_bound else ["contracts/Auth.sol"]),
        },
        {
            "target_id": "target:value-a",
            "node_kind": "function",
            "boundaries": [],
            "effects": ["asset_transfer"],
            "entity_properties": [],
            "source_paths": ["contracts/Value.sol"],
        },
        {
            "target_id": "target:value-b",
            "node_kind": "function",
            "boundaries": [],
            "effects": ["asset_transfer"],
            "entity_properties": [],
            "source_paths": ["contracts/Value.sol"],
        },
    ]


def _relations() -> list[dict]:
    return [
        {
            "relation_id": "relation:auth",
            "selector": "authorizes",
            "source_target_id": "target:auth-a",
            "destination_target_id": "target:auth-b",
        },
        {
            "relation_id": "relation:value",
            "selector": "flows_value_to",
            "source_target_id": "target:value-a",
            "destination_target_id": "target:value-b",
        },
    ]


def _activated_bundle(tmp_path: Path, *, lower_bound: bool = False) -> dict:
    base = fixtures.runtime_fixture.__wrapped__(tmp_path / "runtime")
    coverage = (
        {
            "coverage_kind": "LOWER_BOUND",
            "unknown_remainder": True,
            "limitation_reason": "one graph node lacks an exact source location",
        }
        if lower_bound
        else {
            "coverage_kind": "EXACT",
            "unknown_remainder": False,
            "limitation_reason": None,
        }
    )
    source = compile_activated_method_card_denominator_source(
        audit_snapshot=base.snapshot,
        producer=base.denominator_producer,
        graph_schema="fixture.program-graph.v2",
        coverage=coverage,
        nodes=_nodes(lower_bound=lower_bound),
        relations=_relations(),
        source_files=SOURCE_FILES,
    )
    assert source["schema"] == ACTIVATED_DENOMINATOR_SOURCE_SCHEMA
    graph_binding = {
        "graph_schema": source["graph_schema"],
        "graph_digest": source["graph_digest"],
    }
    runtime_input = compile_activated_method_card_runtime_input_binding(
        implementation_root=base.root,
        audit_snapshot=base.snapshot,
        selected_methods=base.selections,
        denominator_source=source,
        expected_denominator_producer=base.denominator_producer,
        expected_graph_binding=graph_binding,
        source_files=SOURCE_FILES,
        expected_catalog=base.catalog,
    )
    fragment = render_selected_method_fragment(base.catalog, base.selections)
    plan = fixtures._work_plan(
        base.snapshot,
        (
            base.catalog.digest,
            hashlib.sha256(fragment).hexdigest(),
            runtime_input["runtime_input_binding_digest"],
            base.snapshot["components"]["methodology"]["digest"],
        ),
        prompt_digest=fixtures._sha("mc0a-activated-prompt"),
    )
    runtime = compile_activated_method_card_runtime_authority(
        implementation_root=base.root,
        audit_snapshot=base.snapshot,
        work_plan=plan,
        selected_methods=base.selections,
        denominator_source=source,
        expected_denominator_producer=base.denominator_producer,
        expected_graph_binding=graph_binding,
        source_files=SOURCE_FILES,
        expected_catalog=base.catalog,
    )
    return {
        "base": base,
        "source": source,
        "graph_binding": graph_binding,
        "runtime_input": runtime_input,
        "plan": plan,
        "runtime": runtime,
    }


def _validate(bundle: dict, **overrides: object) -> dict:
    base = bundle["base"]
    values: dict[str, object] = {
        "value": bundle["runtime"],
        "implementation_root": base.root,
        "audit_snapshot": base.snapshot,
        "work_plan": bundle["plan"],
        "denominator_source": bundle["source"],
        "expected_denominator_producer": base.denominator_producer,
        "expected_graph_binding": bundle["graph_binding"],
        "source_files": SOURCE_FILES,
        "expected_catalog": base.catalog,
    }
    values.update(overrides)
    return validate_activated_method_card_runtime_authority(**values)  # type: ignore[arg-type]


def test_activated_v2_keeps_per_card_denominators_disjoint(tmp_path: Path) -> None:
    bundle = _activated_bundle(tmp_path)
    runtime = bundle["runtime"]

    assert runtime["schema"] == ACTIVATED_AUTHORITY_SCHEMA
    assert runtime["schema"] != AUTHORITY_SCHEMA
    methods = runtime["denominators"]["methods"]
    assert [row["method_id"] for row in methods] == [
        row["method_id"] for row in bundle["base"].selections
    ]
    assert [row["target_id"] for row in methods[0]["targets"]] == [
        "target:auth-a",
        "target:auth-b",
    ]
    assert [row["relation_id"] for row in methods[0]["relations"]] == [
        "relation:auth"
    ]
    assert [row["target_id"] for row in methods[1]["targets"]] == [
        "target:value-a",
        "target:value-b",
    ]
    assert [row["relation_id"] for row in methods[1]["relations"]] == [
        "relation:value"
    ]
    assert all(
        step["method_id"] == method["method_id"]
        for method in methods
        for step in method["steps"]
    )
    assert canonical_activated_runtime_authority_bytes(runtime).endswith(b"\n")
    assert _validate(bundle) == runtime


def test_every_exact_target_binds_current_source_identity(tmp_path: Path) -> None:
    bundle = _activated_bundle(tmp_path)
    for method in bundle["runtime"]["denominators"]["methods"]:
        for target in method["targets"]:
            assert target["source_files"]
            for identity in target["source_files"]:
                assert identity == application._file_identity(
                    identity["path"], SOURCE_FILES[identity["path"]]
                )

    stale = dict(SOURCE_FILES)
    stale["contracts/Auth.sol"] += b"// changed\n"
    with pytest.raises(MethodCardRuntimeAuthorityError, match="source|stale|identity"):
        _validate(bundle, source_files=stale)


def test_missing_target_source_is_only_admissible_as_lower_bound(tmp_path: Path) -> None:
    exact = fixtures.runtime_fixture.__wrapped__(tmp_path / "exact")
    with pytest.raises(MethodCardRuntimeAuthorityError, match="source|EXACT"):
        compile_activated_method_card_denominator_source(
            audit_snapshot=exact.snapshot,
            producer=exact.denominator_producer,
            graph_schema="fixture.program-graph.v2",
            coverage={
                "coverage_kind": "EXACT",
                "unknown_remainder": False,
                "limitation_reason": None,
            },
            nodes=_nodes(lower_bound=True),
            relations=_relations(),
            source_files=SOURCE_FILES,
        )

    lower = _activated_bundle(tmp_path / "lower", lower_bound=True)
    assert lower["runtime"]["denominators"]["unknown_remainder"] is True
    assert lower["runtime"]["denominators"]["coverage_kind"] == "LOWER_BOUND"
    assert any(
        not target["source_files"]
        for method in lower["runtime"]["denominators"]["methods"]
        for target in method["targets"]
    )


@pytest.mark.parametrize("stale_kind", ["graph", "snapshot", "revision"])
def test_activated_runtime_rejects_stale_external_binding(
    tmp_path: Path,
    stale_kind: str,
) -> None:
    bundle = _activated_bundle(tmp_path)
    base = bundle["base"]
    if stale_kind == "graph":
        with pytest.raises(MethodCardRuntimeAuthorityError, match="graph|stale"):
            _validate(
                bundle,
                expected_graph_binding={
                    "graph_schema": bundle["graph_binding"]["graph_schema"],
                    "graph_digest": fixtures._sha("stale-graph"),
                },
            )
    elif stale_kind == "snapshot":
        with pytest.raises(MethodCardRuntimeAuthorityError, match="snapshot|stale"):
            _validate(
                bundle,
                audit_snapshot=fixtures._audit_snapshot(
                    base.root,
                    source_label="stale-source",
                ),
            )
    else:
        stale = [dict(row) for row in base.selections]
        stale[0]["method_version"] = "9.9.9"
        with pytest.raises(MethodCardRuntimeAuthorityError, match="version|stale"):
            compile_activated_method_card_runtime_input_binding(
                implementation_root=base.root,
                audit_snapshot=base.snapshot,
                selected_methods=stale,
                denominator_source=bundle["source"],
                expected_denominator_producer=base.denominator_producer,
                expected_graph_binding=bundle["graph_binding"],
                source_files=SOURCE_FILES,
                expected_catalog=base.catalog,
            )


def test_catalog_change_invalidates_activated_authority(tmp_path: Path) -> None:
    bundle = _activated_bundle(tmp_path)
    catalog_path = bundle["base"].root / "methodology" / "method-cards-v1.yaml"
    catalog_path.write_bytes(catalog_path.read_bytes() + b"\n")
    with pytest.raises(MethodCardRuntimeAuthorityError, match="catalog|methodology|stale"):
        _validate(bundle, expected_catalog=None)


def test_activation_is_new_schema_and_does_not_mutate_foundation_receipt(
    tmp_path: Path,
) -> None:
    before = copy.deepcopy(integration_debt_output())
    bundle = _activated_bundle(tmp_path)
    after = integration_debt_output()

    assert before == after
    assert after["status"] == "FOUNDATION_ONLY"
    assert after["driver_cutover"] is False
    assert bundle["runtime"]["integration"]["status"] == (
        "ACTIVATED_AUTHORITY_NOT_PRODUCTION_INTEGRATED"
    )
    assert bundle["runtime"]["integration"]["phase_status_authority"] is False


def test_candidate_evidence_is_many_to_many_but_proposal_union_is_exact() -> None:
    output = b"# Subject\n\n## Finding [SHARED-1]: shared candidate\n"
    claims = [
        {"outcome": {"candidate_ids": ["SHARED-1"]}},
        {"outcome": {"candidate_ids": ["SHARED-1"]}},
    ]
    application._validate_exact_candidate_set(claims, output)

    claims[1]["outcome"]["candidate_ids"] = ["MISSING-2"]
    with pytest.raises(
        application.MethodCardApplicationAuthorityError,
        match="exact parsed candidate set",
    ):
        application._validate_exact_candidate_set(claims, output)


def test_per_card_claim_does_not_require_other_cards_denominator(
    tmp_path: Path,
) -> None:
    bundle = _activated_bundle(tmp_path)
    runtime = bundle["runtime"]
    denominator = application._denominator_projection(runtime)
    selected, cards = application._selected_cards(runtime, bundle["base"].root)
    source = SOURCE_FILES["contracts/Auth.sol"]
    evidence = {
        "path": "contracts/Auth.sol",
        "line_start": 1,
        "line_end": 1,
        "sha256": hashlib.sha256(source).hexdigest(),
    }
    method = selected[0]
    method_denominator = denominator["methods"][0]
    claim = application._normalize_claim(
        {
            "method_id": method["method_id"],
            "method_version": method["method_version"],
            "producer_claim_state": "CLAIMED",
            "status": "CLAIMED_APPLIED",
            "targets_examined": [
                row["target_id"] for row in method_denominator["targets"]
            ],
            "relations_examined": [
                row["relation_id"] for row in method_denominator["relations"]
            ],
            "steps_completed": method_denominator["steps"],
            "evidence": [evidence],
            "outcome": {
                "kind": "NO_CANDIDATE",
                "candidate_ids": [],
                "detail": "applied only this card's exact denominator",
            },
            "unresolved_assumptions": [],
            "not_applicable_reason": None,
        },
        expected_method=method,
        denominator=denominator,
        card=cards[(method["method_id"], method["method_version"])],
        blobs=SOURCE_FILES,
        output_bytes=b"no proposal\n",
        persisted=False,
    )
    assert claim["targets_examined"] == ["target:auth-a", "target:auth-b"]
    assert "target:value-a" not in claim["targets_examined"]


def test_application_runtime_context_replays_activated_source_bindings(
    tmp_path: Path,
) -> None:
    bundle = _activated_bundle(tmp_path)
    base = bundle["base"]
    witness = MethodCardRuntimeReplayWitness(
        audit_snapshot=base.snapshot,
        work_plan=bundle["plan"],
        denominator_source=bundle["source"],
        expected_denominator_producer=base.denominator_producer,
        expected_graph_binding=bundle["graph_binding"],
        expected_catalog=base.catalog,
        source_files=SOURCE_FILES,
    )
    runtime, selected, _cards = application._runtime_context(
        bundle["runtime"],
        base.root,
        witness,
    )
    assert runtime == bundle["runtime"]
    assert len(selected) == 2

    stale = dict(SOURCE_FILES)
    stale["contracts/Value.sol"] += b"// stale\n"
    # Construct explicitly: the dataclass is frozen and the exact witness type
    # is itself part of the trusted replay boundary.
    stale_witness = MethodCardRuntimeReplayWitness(
        audit_snapshot=base.snapshot,
        work_plan=bundle["plan"],
        denominator_source=bundle["source"],
        expected_denominator_producer=base.denominator_producer,
        expected_graph_binding=bundle["graph_binding"],
        expected_catalog=base.catalog,
        source_files=stale,
    )
    with pytest.raises(
        application.MethodCardApplicationAuthorityError,
        match="source|stale|identity",
    ):
        application._runtime_context(bundle["runtime"], base.root, stale_witness)


def test_application_v3_structural_codec_binds_per_card_denominators(
    tmp_path: Path,
) -> None:
    bundle = _activated_bundle(tmp_path)
    denominator = application._denominator_projection(bundle["runtime"])
    states = []
    for index, method in enumerate(denominator["methods"]):
        outcome = {
            "kind": "CANDIDATE_PROPOSED",
            "candidate_ids": ["SHARED-1"],
            "detail": "the same proposal is supported by multiple methods",
        }
        states.append(
            {
                "method_id": method["method_id"],
                "method_version": method["method_version"],
                "producer_claim_state": "CLAIMED",
                "producer_status": "CLAIMED_APPLIED",
                "producer_claim_digest": fixtures._sha(f"claim-{index}"),
                "producer_outcome": outcome,
                "review_digest": fixtures._sha(f"review-{index}"),
                "review_disposition": "CONFIRMED_APPLICATION",
                "application_disposition": "INDEPENDENTLY_CONFIRMED",
            }
        )
    unsigned = {
        "schema": APPLICATION_AUTHORITY_V3_SCHEMA,
        "runtime_authority_digest": bundle["runtime"]["authority_digest"],
        "source_snapshot_digest": bundle["base"].snapshot["snapshot_digest"],
        "producer_typed_output_authority_digest": fixtures._sha("producer-typed"),
        "reviewer_typed_output_authority_digest": fixtures._sha("reviewer-typed"),
        "producer_payload_digest": fixtures._sha("producer-payload"),
        "reviewer_payload_digest": fixtures._sha("reviewer-payload"),
        "denominator": denominator,
        "status": "COMPLETE",
        "application_complete": True,
        "method_states": states,
        "debt": [],
        "typed_output_authorship": dict(application.V2_TYPED_OUTPUT_AUTHORSHIP),
        "authority_limits": dict(application.V2_AUTHORITY_LIMITS),
    }
    authority = application._sign(unsigned, "authority_digest")
    assert application._application_v3_value(authority) == authority
    assert canonical_method_card_application_authority_v3_bytes(authority).endswith(
        b"\n"
    )


def test_application_v3_reconciles_distinct_typed_outputs_with_shared_candidate(
    tmp_path: Path,
) -> None:
    bundle = _activated_bundle(tmp_path / "runtime")
    base = bundle["base"]
    runtime = bundle["runtime"]
    witness = MethodCardRuntimeReplayWitness(
        audit_snapshot=base.snapshot,
        work_plan=bundle["plan"],
        denominator_source=bundle["source"],
        expected_denominator_producer=base.denominator_producer,
        expected_graph_binding=bundle["graph_binding"],
        expected_catalog=base.catalog,
        source_files=SOURCE_FILES,
    )
    runtime_value, selected, cards = application._runtime_context(
        runtime,
        base.root,
        witness,
    )
    denominator = application._denominator_projection(runtime_value)
    subject_path = "analysis_authority.md"
    subject_identity = f"scratchpad:{subject_path}"
    subject = b"# Subject\n\n## Finding [SHARED-1]: shared candidate\n"
    runtime_identity = "scratchpad:method_card_runtime_authority.v2.json"
    snapshot_identity = "scratchpad:audit_snapshot.json"
    producer_authority_identity = (
        "scratchpad:method_card_producer_typed_output_authority.json"
    )
    producer_output_identity = "scratchpad:method_card_producer_claims.v2.json"
    reviewer_output_identity = "scratchpad:method_card_reviewer_dispositions.v2.json"

    scratchpad = base.root / "scratchpad"
    scratchpad.mkdir(parents=True)
    for path, raw in SOURCE_FILES.items():
        destination = base.root / path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(raw)

    blobs = {**SOURCE_FILES, subject_path: subject}
    claims = []
    for method, method_denominator in zip(
        selected,
        denominator["methods"],
        strict=True,
    ):
        source_path = method_denominator["targets"][0]["source_files"][0]["path"]
        source_raw = SOURCE_FILES[source_path]
        raw_claim = {
            "method_id": method["method_id"],
            "method_version": method["method_version"],
            "producer_claim_state": "CLAIMED",
            "status": "CLAIMED_APPLIED",
            "targets_examined": [
                row["target_id"] for row in method_denominator["targets"]
            ],
            "relations_examined": [
                row["relation_id"] for row in method_denominator["relations"]
            ],
            "steps_completed": method_denominator["steps"],
            "evidence": [
                {
                    "path": source_path,
                    "line_start": 1,
                    "line_end": 1,
                    "sha256": hashlib.sha256(source_raw).hexdigest(),
                }
            ],
            "outcome": {
                "kind": "CANDIDATE_PROPOSED",
                "candidate_ids": ["SHARED-1"],
                "detail": "shared proposal supported by this method",
            },
            "unresolved_assumptions": [],
            "not_applicable_reason": None,
        }
        claims.append(
            application._normalize_claim(
                raw_claim,
                expected_method=method,
                denominator=denominator,
                card=cards[(method["method_id"], method["method_version"])],
                blobs=blobs,
                output_bytes=subject,
                persisted=False,
            )
        )
    producer_payload = {
        "schema": PRODUCER_TYPED_OUTPUT_SCHEMA,
        "role": "METHOD_CARD_PRODUCER",
        "runtime_authority_digest": runtime["authority_digest"],
        "source_snapshot_digest": base.snapshot["snapshot_digest"],
        "runtime_input_identity": runtime_identity,
        "snapshot_input_identity": snapshot_identity,
        "subject_output": application._file_identity(subject_path, subject),
        "source_files": application._source_identities(SOURCE_FILES),
        "denominator": denominator,
        "claims": claims,
    }
    semantic_inputs = {
        runtime_identity: canonical_file_bytes(runtime),
        snapshot_identity: canonical_file_bytes(base.snapshot),
        subject_identity: subject,
        **{f"project:{path}": raw for path, raw in SOURCE_FILES.items()},
    }
    producer_execution = build_typed_fixture(
        tmp_path / "typed",
        payload=producer_payload,
        unit="method-card-producer-activated",
        output_name=producer_output_identity.removeprefix("scratchpad:"),
        semantic_inputs=semantic_inputs,
        scratchpad_override=scratchpad,
        project_root_override=base.root,
        run_id_override=bundle["plan"]["run_id"],
        source_snapshot_digest_override=base.snapshot["snapshot_digest"],
    )
    producer_result = replay_typed_worker_output(producer_execution.witness)
    reviews = []
    for claim in claims:
        source_path = claim["evidence"][0]["path"]
        reviews.append(
            application._normalize_review(
                {
                    "method_id": claim["method_id"],
                    "method_version": claim["method_version"],
                    "disposition": "CONFIRMED_APPLICATION",
                    "evidence": [claim["evidence"][0]],
                    "reason": "independently replayed exact per-card application",
                },
                claim=claim,
                blobs=blobs,
                persisted=False,
            )
        )
    reviewer_payload = {
        "schema": REVIEWER_TYPED_OUTPUT_SCHEMA,
        "role": "METHOD_CARD_REVIEWER",
        "runtime_authority_digest": runtime["authority_digest"],
        "source_snapshot_digest": base.snapshot["snapshot_digest"],
        "runtime_input_identity": runtime_identity,
        "snapshot_input_identity": snapshot_identity,
        "producer_authority_input_identity": producer_authority_identity,
        "producer_typed_output_authority_digest": producer_result.authority[
            "authority_digest"
        ],
        "producer_execution_authority_digest": producer_result.authority[
            "worker_execution_authority_digest"
        ],
        "producer_output_identity": producer_result.authority[
            "canonical_output_identity"
        ],
        "producer_output_sha256": producer_result.authority["output_sha256"],
        "producer_payload_digest": producer_result.authority["payload_digest"],
        "denominator": denominator,
        "reviews": reviews,
    }
    reviewer_execution = build_typed_fixture(
        tmp_path / "typed",
        payload=reviewer_payload,
        unit="method-card-reviewer-activated",
        output_name=reviewer_output_identity.removeprefix("scratchpad:"),
        semantic_inputs={
            **semantic_inputs,
            producer_output_identity: producer_result.raw,
            producer_authority_identity: (
                canonical_typed_worker_output_authority_bytes(
                    producer_result.authority
                )
            ),
        },
        scratchpad_override=scratchpad,
        project_root_override=base.root,
        run_id_override=bundle["plan"]["run_id"],
        source_snapshot_digest_override=base.snapshot["snapshot_digest"],
    )
    authority = reconcile_method_card_application_v3(
        validated_runtime_authority=runtime,
        runtime_replay_witness=witness,
        implementation_root=base.root,
        producer_typed_output_witness=producer_execution.witness,
        reviewer_typed_output_witness=reviewer_execution.witness,
        output_bytes=subject,
        source_files=SOURCE_FILES,
    )
    assert authority["schema"] == APPLICATION_AUTHORITY_V3_SCHEMA
    assert authority["status"] == "COMPLETE"
    assert all(
        row["producer_outcome"]["candidate_ids"] == ["SHARED-1"]
        for row in authority["method_states"]
    )
    assert validate_method_card_application_authority_v3(
        canonical_method_card_application_authority_v3_bytes(authority),
        validated_runtime_authority=runtime,
        runtime_replay_witness=witness,
        implementation_root=base.root,
        producer_typed_output_witness=producer_execution.witness,
        reviewer_typed_output_witness=reviewer_execution.witness,
        output_bytes=subject,
        source_files=SOURCE_FILES,
    ) == authority


def test_activated_runtime_cannot_fall_back_to_legacy_receipt_path(
    tmp_path: Path,
) -> None:
    bundle = _activated_bundle(tmp_path)
    base = bundle["base"]
    witness = MethodCardRuntimeReplayWitness(
        audit_snapshot=base.snapshot,
        work_plan=bundle["plan"],
        denominator_source=bundle["source"],
        expected_denominator_producer=base.denominator_producer,
        expected_graph_binding=bundle["graph_binding"],
        expected_catalog=base.catalog,
        source_files=SOURCE_FILES,
    )
    with pytest.raises(
        application.MethodCardApplicationAuthorityError,
        match="typed application v3|fallback authority",
    ):
        application.compile_worker_attempt_identity(
            validated_runtime_authority=bundle["runtime"],
            runtime_replay_witness=witness,
            implementation_root=base.root,
            producer_execution_witness=None,  # type: ignore[arg-type]
            output_path="analysis_authority.md",
            output_bytes=b"legacy markdown\n",
            source_files=SOURCE_FILES,
        )
