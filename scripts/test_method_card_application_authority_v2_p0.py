"""Production-capable MethodCard v2 authority over typed worker outputs."""
from __future__ import annotations

import copy
from dataclasses import dataclass, replace
import hashlib
from pathlib import Path

import pytest

import method_card_application_authority as application
from method_card_application_authority import (
    APPLICATION_AUTHORITY_V2_SCHEMA,
    PRODUCER_TYPED_OUTPUT_SCHEMA,
    REVIEWER_TYPED_OUTPUT_SCHEMA,
    MethodCardApplicationAuthorityError,
    MethodCardRuntimeReplayWitness,
    canonical_method_card_application_authority_v2_bytes,
    reconcile_method_card_application_v2,
    validate_method_card_application_authority_v2,
)
from method_card_runtime_authority import (
    compile_method_card_runtime_input_binding,
)
import program_facts_types as program_types
from program_facts_types import canonical_file_bytes, canonical_json_bytes
from test_typed_worker_output_authority_p0 import build_typed_fixture
from typed_worker_output_authority import (
    TypedWorkerOutputAuthorityError,
    canonical_typed_worker_output_authority_bytes,
    replay_typed_worker_output,
)
import typed_worker_output_authority as typed_authority
import test_method_card_application_authority_p0 as v1_fixtures
import test_method_card_runtime_authority_r2 as runtime_fixtures
import test_typed_worker_output_authority_p0 as T
import worker_execution_receipts as worker_receipts


pytestmark = pytest.mark.integration


RUNTIME_INPUT_IDENTITY = "scratchpad:method_card_runtime_authority.v1.json"
SNAPSHOT_INPUT_IDENTITY = "scratchpad:audit_snapshot.json"
SUBJECT_IDENTITY = "scratchpad:analysis_authority.md"
PRODUCER_AUTHORITY_INPUT_IDENTITY = (
    "scratchpad:method_card_producer_typed_output_authority.json"
)
PRODUCER_OUTPUT_IDENTITY = "scratchpad:method_card_producer_claims.v2.json"
REVIEWER_OUTPUT_IDENTITY = "scratchpad:method_card_reviewer_dispositions.v2.json"


def _digest(value: dict) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _lower_bound_fixture(fixture):
    source = copy.deepcopy(fixture.denominator_source)
    source["coverage"] = {
        "coverage_kind": "LOWER_BOUND",
        "unknown_remainder": True,
        "limitation_reason": "dynamic targets remain outside the typed graph",
    }
    source["graph_digest"] = runtime_fixtures._graph_digest(
        graph_schema=source["graph_schema"],
        coverage=source["coverage"],
        nodes=source["nodes"],
        relations=source["relations"],
    )
    unsigned_source = dict(source)
    unsigned_source.pop("source_digest")
    source["source_digest"] = _digest(unsigned_source)
    graph_binding = {
        "graph_schema": source["graph_schema"],
        "graph_digest": source["graph_digest"],
    }
    runtime_input = compile_method_card_runtime_input_binding(
        implementation_root=fixture.root,
        audit_snapshot=fixture.snapshot,
        selected_methods=fixture.selections,
        denominator_source=source,
        expected_denominator_producer=fixture.denominator_producer,
        expected_graph_binding=graph_binding,
        target_denominator=fixture.targets,
        relation_denominator=fixture.relations,
        step_denominator=fixture.steps,
        expected_catalog=fixture.catalog,
    )
    fragment_digest = hashlib.sha256(fixture.fragment).hexdigest()
    plan = runtime_fixtures._work_plan(
        fixture.snapshot,
        (
            fixture.catalog.digest,
            fragment_digest,
            runtime_input["runtime_input_binding_digest"],
            fixture.snapshot["components"]["methodology"]["digest"],
        ),
        prompt_digest=runtime_fixtures._sha("lower-bound-prompt"),
    )
    return replace(
        fixture,
        denominator_source=source,
        graph_binding=graph_binding,
        plan=plan,
    )


@dataclass(frozen=True)
class MethodCardV2Bundle:
    fixture: object
    runtime: dict
    runtime_witness: MethodCardRuntimeReplayWitness
    scratchpad: Path
    output: bytes
    sources: dict[str, bytes]
    producer_execution: object
    reviewer_execution: object


def build_method_card_v2_bundle(
    tmp_path: Path,
    *,
    candidates: bool = False,
    reviewer_disposition: str = "CONFIRMED_APPLICATION",
    producer_payload_mutator=None,
    reviewer_payload_mutator=None,
    lower_bound: bool = False,
    omit_source_input: bool = False,
) -> MethodCardV2Bundle:
    fixture = runtime_fixtures.runtime_fixture.__wrapped__(tmp_path / "runtime")
    if lower_bound:
        fixture = _lower_bound_fixture(fixture)
    runtime = runtime_fixtures._compile(fixture)
    runtime_witness = MethodCardRuntimeReplayWitness(
        audit_snapshot=fixture.snapshot,
        work_plan=fixture.plan,
        denominator_source=fixture.denominator_source,
        expected_denominator_producer=fixture.denominator_producer,
        expected_graph_binding=fixture.graph_binding,
        expected_catalog=fixture.catalog,
    )
    output = v1_fixtures._output(runtime, with_candidates=candidates)
    sources = {v1_fixtures.SOURCE_PATH: v1_fixtures.SOURCE_BYTES}
    scratchpad = fixture.root / "scratchpad"
    scratchpad.mkdir(parents=True)
    source_path = fixture.root / v1_fixtures.SOURCE_PATH
    source_path.parent.mkdir(parents=True)
    source_path.write_bytes(v1_fixtures.SOURCE_BYTES)

    runtime_value, selected, cards = application._runtime_context(
        runtime,
        fixture.root,
        runtime_witness,
    )
    denominator = application._denominator_projection(runtime_value)
    blobs = {**sources, v1_fixtures.OUTPUT_PATH: output}
    raw_claims = v1_fixtures._claims(runtime, candidates=candidates)
    claims = [
        application._normalize_claim(
            raw,
            expected_method=method,
            denominator=denominator,
            card=cards[(method["method_id"], method["method_version"])],
            blobs=blobs,
            output_bytes=output,
            persisted=False,
        )
        for raw, method in zip(raw_claims, selected, strict=True)
    ]
    producer_payload = {
        "schema": PRODUCER_TYPED_OUTPUT_SCHEMA,
        "role": "METHOD_CARD_PRODUCER",
        "runtime_authority_digest": runtime["authority_digest"],
        "source_snapshot_digest": fixture.snapshot["snapshot_digest"],
        "runtime_input_identity": RUNTIME_INPUT_IDENTITY,
        "snapshot_input_identity": SNAPSHOT_INPUT_IDENTITY,
        "subject_output": application._file_identity(
            v1_fixtures.OUTPUT_PATH,
            output,
        ),
        "source_files": application._source_identities(sources),
        "denominator": denominator,
        "claims": claims,
    }
    if producer_payload_mutator is not None:
        producer_payload_mutator(producer_payload)
    producer_inputs = {
        RUNTIME_INPUT_IDENTITY: canonical_file_bytes(runtime),
        SNAPSHOT_INPUT_IDENTITY: canonical_file_bytes(fixture.snapshot),
        SUBJECT_IDENTITY: output,
    }
    if not omit_source_input:
        producer_inputs[f"project:{v1_fixtures.SOURCE_PATH}"] = (
            v1_fixtures.SOURCE_BYTES
        )
    producer_execution = build_typed_fixture(
        tmp_path / "typed",
        payload=producer_payload,
        unit="method-card-producer-typed",
        output_name=PRODUCER_OUTPUT_IDENTITY.removeprefix("scratchpad:"),
        semantic_inputs=producer_inputs,
        scratchpad_override=scratchpad,
        project_root_override=fixture.root,
        run_id_override=fixture.plan["run_id"],
        source_snapshot_digest_override=fixture.snapshot["snapshot_digest"],
    )
    producer_result = replay_typed_worker_output(producer_execution.witness)
    producer_authority_bytes = canonical_typed_worker_output_authority_bytes(
        producer_result.authority
    )

    reviews = [
        application._normalize_review(
            raw,
            claim=claim,
            blobs=blobs,
            persisted=False,
        )
        for raw, claim in zip(
            v1_fixtures._reviews(
                {"claims": claims},
                disposition=reviewer_disposition,
            ),
            claims,
            strict=True,
        )
    ]
    reviewer_payload = {
        "schema": REVIEWER_TYPED_OUTPUT_SCHEMA,
        "role": "METHOD_CARD_REVIEWER",
        "runtime_authority_digest": runtime["authority_digest"],
        "source_snapshot_digest": fixture.snapshot["snapshot_digest"],
        "runtime_input_identity": RUNTIME_INPUT_IDENTITY,
        "snapshot_input_identity": SNAPSHOT_INPUT_IDENTITY,
        "producer_authority_input_identity": PRODUCER_AUTHORITY_INPUT_IDENTITY,
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
    if reviewer_payload_mutator is not None:
        reviewer_payload_mutator(reviewer_payload)
    reviewer_inputs = {
        RUNTIME_INPUT_IDENTITY: canonical_file_bytes(runtime),
        SNAPSHOT_INPUT_IDENTITY: canonical_file_bytes(fixture.snapshot),
        SUBJECT_IDENTITY: output,
        f"project:{v1_fixtures.SOURCE_PATH}": v1_fixtures.SOURCE_BYTES,
        PRODUCER_OUTPUT_IDENTITY: producer_result.raw,
        PRODUCER_AUTHORITY_INPUT_IDENTITY: producer_authority_bytes,
    }
    reviewer_execution = build_typed_fixture(
        tmp_path / "typed",
        payload=reviewer_payload,
        unit="method-card-reviewer-typed",
        output_name=REVIEWER_OUTPUT_IDENTITY.removeprefix("scratchpad:"),
        semantic_inputs=reviewer_inputs,
        scratchpad_override=scratchpad,
        project_root_override=fixture.root,
        run_id_override=fixture.plan["run_id"],
        source_snapshot_digest_override=fixture.snapshot["snapshot_digest"],
    )
    return MethodCardV2Bundle(
        fixture=fixture,
        runtime=runtime,
        runtime_witness=runtime_witness,
        scratchpad=scratchpad,
        output=output,
        sources=sources,
        producer_execution=producer_execution,
        reviewer_execution=reviewer_execution,
    )


def _reconcile(bundle: MethodCardV2Bundle, **overrides):
    values = {
        "validated_runtime_authority": bundle.runtime,
        "runtime_replay_witness": bundle.runtime_witness,
        "implementation_root": bundle.fixture.root,
        "producer_typed_output_witness": bundle.producer_execution.witness,
        "reviewer_typed_output_witness": bundle.reviewer_execution.witness,
        "output_bytes": bundle.output,
        "source_files": bundle.sources,
    }
    values.update(overrides)
    return reconcile_method_card_application_v2(**values)


def test_v2_complete_consumes_only_two_distinct_typed_worker_outputs(
    tmp_path: Path,
) -> None:
    bundle = build_method_card_v2_bundle(tmp_path)
    authority = _reconcile(bundle)

    assert authority["schema"] == APPLICATION_AUTHORITY_V2_SCHEMA
    assert authority["status"] == "COMPLETE"
    assert authority["application_complete"] is True
    assert authority["authority_limits"]["application_completion_authority"] is True
    assert authority["typed_output_authorship"]["producer"] is True
    assert authority["typed_output_authorship"]["reviewer"] is True
    assert (
        authority["producer_typed_output_authority_digest"]
        != authority["reviewer_typed_output_authority_digest"]
    )

    raw = canonical_method_card_application_authority_v2_bytes(authority)
    validated = validate_method_card_application_authority_v2(
        raw,
        validated_runtime_authority=bundle.runtime,
        runtime_replay_witness=bundle.runtime_witness,
        implementation_root=bundle.fixture.root,
        producer_typed_output_witness=bundle.producer_execution.witness,
        reviewer_typed_output_witness=bundle.reviewer_execution.witness,
        output_bytes=bundle.output,
        source_files=bundle.sources,
    )
    assert validated == authority


def test_reviewer_incorporated_reject_cannot_be_replaced_by_caller_confirm(
    tmp_path: Path,
) -> None:
    bundle = build_method_card_v2_bundle(
        tmp_path,
        reviewer_disposition="REJECTED_APPLICATION",
    )
    authority = _reconcile(bundle)
    assert authority["status"] == "DEBT"
    assert all(
        row["review_disposition"] == "REJECTED_APPLICATION"
        for row in authority["method_states"]
    )
    with pytest.raises(TypeError):
        _reconcile(  # type: ignore[call-arg]
            bundle,
            reviews=v1_fixtures._reviews(
                {"claims": []},
                disposition="CONFIRMED_APPLICATION",
            ),
        )


def test_same_reviewer_bytes_have_one_deterministic_disposition(
    tmp_path: Path,
) -> None:
    bundle = build_method_card_v2_bundle(tmp_path)
    assert _reconcile(bundle) == _reconcile(bundle)


def test_reviewer_parser_side_effect_cannot_publish_complete(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle = build_method_card_v2_bundle(tmp_path)
    source_path = bundle.fixture.root / v1_fixtures.SOURCE_PATH
    stale = v1_fixtures.SOURCE_BYTES + b"// parser-time mutation\n"
    trusted = T.trusted_typed_worker_output_parser(
        typed_role=bundle.reviewer_execution.witness.typed_role,
        payload_schema=bundle.reviewer_execution.witness.payload_schema,
        parser_id=bundle.reviewer_execution.witness.parser_id,
    )
    impostor = T._same_binding_parser_impostor(
        trusted,
        side_effect=lambda: source_path.write_bytes(stale),
    )
    real_resolver = worker_receipts._resolve_registered_callable

    def compromised_resolver(callback, persisted_binding, **kwargs):
        resolved, binding = real_resolver(
            callback,
            persisted_binding,
            **kwargs,
        )
        if callback is trusted:
            return impostor, binding
        return resolved, binding

    monkeypatch.setattr(
        worker_receipts,
        "_resolve_registered_callable",
        compromised_resolver,
    )

    with pytest.raises(MethodCardApplicationAuthorityError, match="parser|input|changed"):
        _reconcile(bundle)


def test_reviewer_parser_dependency_substitution_cannot_change_disposition(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle = build_method_card_v2_bundle(
        tmp_path,
        reviewer_disposition="REJECTED_APPLICATION",
    )
    reviewer_path = (
        bundle.scratchpad
        / bundle.reviewer_execution.witness.expected_output_identity.removeprefix(
            "scratchpad:"
        )
    )
    rejected_raw = reviewer_path.read_bytes()
    original_loads = typed_authority.strict_json_loads
    original_canonical = typed_authority.canonical_json_bytes
    forged_payload = copy.deepcopy(
        original_loads(
            rejected_raw,
            require_final_lf=True,
            require_canonical=True,
        )
    )
    for review in forged_payload["reviews"]:
        review["disposition"] = "CONFIRMED_APPLICATION"
        unsigned = dict(review)
        unsigned.pop("review_digest")
        review["review_digest"] = hashlib.sha256(
            original_canonical(unsigned)
        ).hexdigest()

    def substituted_loads(raw: bytes, **kwargs):
        if raw == rejected_raw:
            return copy.deepcopy(forged_payload)
        return original_loads(raw, **kwargs)

    def substituted_canonical(value) -> bytes:
        if value == forged_payload:
            return rejected_raw.removesuffix(b"\n")
        return original_canonical(value)

    monkeypatch.setattr(
        typed_authority,
        "strict_json_loads",
        substituted_loads,
    )
    monkeypatch.setattr(
        typed_authority,
        "canonical_json_bytes",
        substituted_canonical,
    )

    authority = _reconcile(bundle)
    assert authority["status"] == "DEBT"
    assert all(
        row["review_disposition"] == "REJECTED_APPLICATION"
        for row in authority["method_states"]
    )


def test_reviewer_json_decoder_encoder_swap_cannot_change_disposition(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle = build_method_card_v2_bundle(
        tmp_path,
        reviewer_disposition="REJECTED_APPLICATION",
    )
    reviewer_path = (
        bundle.scratchpad
        / bundle.reviewer_execution.witness.expected_output_identity.removeprefix(
            "scratchpad:"
        )
    )
    rejected_raw = reviewer_path.read_bytes()
    rejected_text = rejected_raw.removesuffix(b"\n").decode("utf-8")
    original_decoder = program_types.json.JSONDecoder
    original_encoder = program_types.json.JSONEncoder
    forged_payload = copy.deepcopy(
        program_types.strict_json_loads(
            rejected_raw,
            require_final_lf=True,
            require_canonical=True,
        )
    )
    for review in forged_payload["reviews"]:
        review["disposition"] = "CONFIRMED_APPLICATION"
        unsigned = dict(review)
        unsigned.pop("review_digest")
        review["review_digest"] = hashlib.sha256(
            program_types.canonical_json_bytes(unsigned)
        ).hexdigest()

    class SubstitutedDecoder:
        def __init__(self, *args, **kwargs) -> None:
            self._delegate = original_decoder(*args, **kwargs)

        def decode(self, text: str):
            if text == rejected_raw.decode("utf-8"):
                return copy.deepcopy(forged_payload)
            return self._delegate.decode(text)

    class SubstitutedEncoder:
        def __init__(self, *args, **kwargs) -> None:
            self._delegate = original_encoder(*args, **kwargs)

        def encode(self, value) -> str:
            if value == forged_payload:
                return rejected_text
            return self._delegate.encode(value)

        def iterencode(self, value, _one_shot=False):
            return self._delegate.iterencode(value, _one_shot)

    monkeypatch.setattr(
        program_types.json,
        "JSONDecoder",
        SubstitutedDecoder,
    )
    monkeypatch.setattr(
        program_types.json,
        "JSONEncoder",
        SubstitutedEncoder,
    )

    authority = _reconcile(bundle)
    assert authority["status"] == "DEBT"
    assert all(
        row["review_disposition"] == "REJECTED_APPLICATION"
        for row in authority["method_states"]
    )


def test_mutated_parser_spec_decoder_cannot_change_incorporated_disposition(
    tmp_path: Path,
) -> None:
    bundle = build_method_card_v2_bundle(
        tmp_path,
        reviewer_disposition="REJECTED_APPLICATION",
    )
    reviewer_path = (
        bundle.scratchpad
        / bundle.reviewer_execution.witness.expected_output_identity.removeprefix(
            "scratchpad:"
        )
    )
    rejected_raw = reviewer_path.read_bytes()
    forged_payload = copy.deepcopy(
        program_types.strict_json_loads(
            rejected_raw,
            require_final_lf=True,
            require_canonical=True,
        )
    )
    for review in forged_payload["reviews"]:
        review["disposition"] = "CONFIRMED_APPLICATION"
        unsigned = dict(review)
        unsigned.pop("review_digest")
        review["review_digest"] = hashlib.sha256(
            program_types.canonical_json_bytes(unsigned)
        ).hexdigest()

    spec = typed_authority._registered_parser_spec(
        typed_role=bundle.reviewer_execution.witness.typed_role,
        payload_schema=bundle.reviewer_execution.witness.payload_schema,
        parser_id=bundle.reviewer_execution.witness.parser_id,
    )
    def substituted_decoder(_path: Path, raw: bytes) -> dict:
        return copy.deepcopy(forged_payload)

    assert not hasattr(spec, "payload_decoder")
    with pytest.raises((AttributeError, TypeError)):
        object.__setattr__(spec, "payload_decoder", substituted_decoder)
    with pytest.raises((AttributeError, TypeError)):
        object.__setattr__(spec, "payload_keys", frozenset())

    replayed = replay_typed_worker_output(
        bundle.reviewer_execution.witness
    )
    authority = _reconcile(bundle)

    assert all(
        review["disposition"] == "REJECTED_APPLICATION"
        for review in replayed.payload["reviews"]
    )
    assert authority["status"] == "DEBT"
    assert all(
        row["review_disposition"] == "REJECTED_APPLICATION"
        for row in authority["method_states"]
    )


def test_reconstructed_closure_cannot_preserve_stale_parser_digest(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle = build_method_card_v2_bundle(
        tmp_path,
        reviewer_disposition="REJECTED_APPLICATION",
    )
    reviewer_path = (
        bundle.scratchpad
        / bundle.reviewer_execution.witness.expected_output_identity.removeprefix(
            "scratchpad:"
        )
    )
    rejected_raw = reviewer_path.read_bytes()
    forged_payload = copy.deepcopy(
        program_types.strict_json_loads(
            rejected_raw,
            require_final_lf=True,
            require_canonical=True,
        )
    )
    for review in forged_payload["reviews"]:
        review["disposition"] = "CONFIRMED_APPLICATION"
        unsigned = dict(review)
        unsigned.pop("review_digest")
        review["review_digest"] = hashlib.sha256(
            program_types.canonical_json_bytes(unsigned)
        ).hexdigest()

    source = (
        "def _registered_canonical_json_payload(_path, raw):\n"
        f"    if raw == {rejected_raw!r}:\n"
        f"        return {forged_payload!r}\n"
        "    return _typed_json_parse_document(raw)\n"
    )
    local_namespace: dict[str, object] = {}
    exec(
        compile(
            source,
            str(Path(typed_authority.__file__).resolve(strict=True)),
            "exec",
        ),
        vars(typed_authority),
        local_namespace,
    )
    substituted_decoder = local_namespace[
        "_registered_canonical_json_payload"
    ]
    assert callable(substituted_decoder)
    monkeypatch.setattr(
        typed_authority,
        "_registered_canonical_json_payload",
        substituted_decoder,
    )

    original_closure = typed_authority._TYPED_PARSER_TRUSTED_CLOSURE
    binding, references = worker_receipts._capture_trusted_callable_closure(
        typed_authority._registered_canonical_json_parser,
        label="reconstructed typed parser closure",
        positional_parameters=2,
        expected_module=typed_authority._TYPED_PARSER_EXPECTED_MODULE,
    )
    reconstructed = worker_receipts._TrustedCallableClosure(
        callback=typed_authority._registered_canonical_json_parser,
        expected_module=typed_authority._TYPED_PARSER_EXPECTED_MODULE,
        binding_bytes=worker_receipts._canonical_json(binding),
        binding_sha256=original_closure.binding_sha256,
        object_references=references,
    )
    monkeypatch.setattr(
        typed_authority,
        "_TYPED_PARSER_TRUSTED_CLOSURE",
        reconstructed,
    )

    with pytest.raises(
        TypedWorkerOutputAuthorityError,
        match="closure digest|registered closure",
    ):
        replay_typed_worker_output(bundle.reviewer_execution.witness)
    with pytest.raises(
        MethodCardApplicationAuthorityError,
        match="closure digest|parser|typed",
    ):
        _reconcile(bundle)


def test_producer_and_reviewer_work_units_cannot_alias(tmp_path: Path) -> None:
    bundle = build_method_card_v2_bundle(tmp_path)
    with pytest.raises(MethodCardApplicationAuthorityError, match="aliased"):
        _reconcile(
            bundle,
            reviewer_typed_output_witness=bundle.producer_execution.witness,
        )


@pytest.mark.parametrize("mutation", ["missing_method", "duplicate_candidate"])
def test_missing_methods_or_duplicate_candidates_are_rejected(
    tmp_path: Path,
    mutation: str,
) -> None:
    def mutate(payload: dict) -> None:
        if mutation == "missing_method":
            payload["claims"] = payload["claims"][:-1]
            return
        first = payload["claims"][0]
        second = payload["claims"][1]
        second["outcome"] = {
            "kind": "CANDIDATE_PROPOSED",
            "candidate_ids": list(first["outcome"]["candidate_ids"]),
            "detail": "duplicate candidate identity",
        }
        unsigned = dict(second)
        unsigned.pop("claim_digest")
        second["claim_digest"] = _digest(unsigned)

    bundle = build_method_card_v2_bundle(
        tmp_path,
        candidates=True,
        producer_payload_mutator=mutate,
    )
    with pytest.raises(
        MethodCardApplicationAuthorityError,
        match="cover every selected method|candidate",
    ):
        _reconcile(bundle)


def test_candidate_disappearance_from_typed_claims_is_rejected(tmp_path: Path) -> None:
    def mutate(payload: dict) -> None:
        claim = payload["claims"][-1]
        claim["outcome"] = {
            "kind": "NO_CANDIDATE",
            "candidate_ids": [],
            "detail": "attempted disappearance",
        }
        unsigned = dict(claim)
        unsigned.pop("claim_digest")
        claim["claim_digest"] = _digest(unsigned)

    bundle = build_method_card_v2_bundle(
        tmp_path,
        candidates=True,
        producer_payload_mutator=mutate,
    )
    with pytest.raises(MethodCardApplicationAuthorityError, match="candidate set"):
        _reconcile(bundle)


def test_empty_typed_claim_denominator_cannot_complete(tmp_path: Path) -> None:
    bundle = build_method_card_v2_bundle(
        tmp_path,
        producer_payload_mutator=lambda payload: payload.__setitem__("claims", []),
    )
    with pytest.raises(MethodCardApplicationAuthorityError, match="cover every selected method"):
        _reconcile(bundle)


@pytest.mark.parametrize("mutation", ["missing", "duplicate"])
def test_reviewer_dispositions_exactly_cover_the_producer_denominator(
    tmp_path: Path,
    mutation: str,
) -> None:
    def mutate(payload: dict) -> None:
        if mutation == "missing":
            payload["reviews"] = payload["reviews"][:-1]
        else:
            payload["reviews"][1] = copy.deepcopy(payload["reviews"][0])

    bundle = build_method_card_v2_bundle(
        tmp_path,
        reviewer_payload_mutator=mutate,
    )
    with pytest.raises(
        MethodCardApplicationAuthorityError,
        match="cover every producer claim|match producer claims",
    ):
        _reconcile(bundle)


def test_lower_bound_runtime_forces_durable_remainder_debt(tmp_path: Path) -> None:
    bundle = build_method_card_v2_bundle(tmp_path, lower_bound=True)
    authority = _reconcile(bundle)
    assert authority["status"] == "DEBT"
    assert authority["application_complete"] is False
    assert {row["code"] for row in authority["debt"]} == {
        "UNKNOWN_DENOMINATOR_REMAINDER"
    }


def test_resigned_empty_v2_complete_is_not_structurally_canonical(
    tmp_path: Path,
) -> None:
    authority = _reconcile(build_method_card_v2_bundle(tmp_path))
    forged = copy.deepcopy(authority)
    forged["method_states"] = []
    forged["debt"] = []
    unsigned = dict(forged)
    unsigned.pop("authority_digest")
    forged["authority_digest"] = _digest(unsigned)
    with pytest.raises(MethodCardApplicationAuthorityError, match="nonempty"):
        canonical_method_card_application_authority_v2_bytes(forged)


def test_stale_runtime_snapshot_or_source_membership_is_rejected(tmp_path: Path) -> None:
    bundle = build_method_card_v2_bundle(tmp_path)
    stale_snapshot = copy.deepcopy(bundle.fixture.snapshot)
    stale_snapshot["components"]["source_scope"]["digest"] = "f" * 64
    stale_runtime_witness = replace(
        bundle.runtime_witness,
        audit_snapshot=stale_snapshot,
    )
    with pytest.raises(MethodCardApplicationAuthorityError, match="runtime.*replay"):
        _reconcile(bundle, runtime_replay_witness=stale_runtime_witness)

    with pytest.raises(MethodCardApplicationAuthorityError, match="source"):
        _reconcile(
            bundle,
            source_files={
                v1_fixtures.SOURCE_PATH: v1_fixtures.SOURCE_BYTES + b"// stale\n"
            },
        )

    missing_source = build_method_card_v2_bundle(
        tmp_path / "missing-source",
        omit_source_input=True,
    )
    with pytest.raises(MethodCardApplicationAuthorityError, match="input denominator|source"):
        _reconcile(missing_source)
