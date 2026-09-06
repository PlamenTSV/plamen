from __future__ import annotations

from dataclasses import fields, replace
import hashlib
import json

import pytest

from review_fixtures import (
    cut4_transactional_recon_publication_r13_reference_model as m,
)


FROZEN_MUTATION_CASES = (
    "source.enum_omission",
    "source.enum_fabrication",
    "source.enum_duplicate",
    "source.anchor_substitution",
    "source.mode_omission",
    "source.mode_fabrication",
    "source.mode_relabel",
    "source.base_omission",
    "source.base_fabrication",
    "source.base_duplicate",
    "source.edge_omission",
    "source.reference_omission",
    "source.vacuous_proved_none",
    "request.prior_swap",
    "request.previous_record_swap",
    "request.invalid_fact_omission",
    "request.private_plan_swap",
    "request.provider_receipt_swap",
    "request.abort_optional_shape",
    "request.publication_terminal_swap",
    "request.cas_stale",
    "request.torn_temp",
    "request.crash_allocation",
    "request.crash_invocation",
    "request.timeout",
    "request.exhausted_cursor_empty",
    "payload.duplicate",
    "payload.partial_without_debt",
    "payload.content_type_swap",
    "payload.byte_sha_swap",
    "payload.zero_normalizer_missing_debt",
    "payload.kp_omission",
    "payload.diff_unknown",
    "payload.m4_extra",
    "payload.r4_missing",
    "payload.receipt_tamper",
)
FROZEN_MUTATION_CASES_SHA256 = (
    "5044d6f029d0d45103fa7ca9c902fa77500049d1ac223ed66f6e97667f96aa80"
)


def _d(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def _assert_code(code: str, fn) -> None:
    with pytest.raises(m.ModelError) as exc:
        fn()
    assert exc.value.code == code


def test_fixture_roster_is_frozen_before_model() -> None:
    encoded = json.dumps(
        FROZEN_MUTATION_CASES,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    assert hashlib.sha256(encoded).hexdigest() == FROZEN_MUTATION_CASES_SHA256
    assert len(FROZEN_MUTATION_CASES) == len(set(FROZEN_MUTATION_CASES)) == 36


def test_bake_adapter_registry_is_explicit_and_total() -> None:
    bundle = m.sample_source_bundle()
    assert bundle.adapters.ecosystems == (
        "aptos", "daml", "evm", "go", "rust", "solana", "soroban", "sui"
    )
    assert all(row.bake_receipt_digest for row in bundle.adapters.rows)
    assert all(row.parser_adapter_id for row in bundle.adapters.rows)


def test_source_vector_authenticates_exact_bytes() -> None:
    bundle = m.sample_source_bundle()
    m.validate_source_vector(bundle.source_vector)
    row = bundle.source_vector.rows[0]
    assert row.raw_sha256 == hashlib.sha256(row.raw_bytes).hexdigest()
    assert row.byte_size == len(row.raw_bytes)


def test_raw_enumeration_receipt_is_deterministic() -> None:
    one = m.sample_source_bundle()
    two = m.sample_source_bundle()
    assert m.canonical_bytes(one.enumeration) == m.canonical_bytes(two.enumeration)
    assert one.enumeration.receipt_digest == two.enumeration.receipt_digest


def test_raw_enumeration_omission_fails() -> None:
    b = m.sample_source_bundle()
    bad = replace(b.enumeration, rows=b.enumeration.rows[:-1])
    _assert_code(
        "RAW_NODE_MULTISET_MISMATCH",
        lambda: m.validate_enumeration_receipt(
            b.source_vector, b.adapters, b.raw_specs, bad
        ),
    )


def test_raw_enumeration_fabrication_fails() -> None:
    b = m.sample_source_bundle()
    forged = m.reidentify_raw_node(
        replace(b.enumeration.rows[0], consumer_id="fabricated")
    )
    bad = replace(b.enumeration, rows=b.enumeration.rows + (forged,))
    _assert_code(
        "RAW_NODE_MULTISET_MISMATCH",
        lambda: m.validate_enumeration_receipt(
            b.source_vector, b.adapters, b.raw_specs, bad
        ),
    )


def test_raw_enumeration_duplicate_fails() -> None:
    b = m.sample_source_bundle()
    bad = replace(b.enumeration, rows=b.enumeration.rows + b.enumeration.rows[:1])
    _assert_code(
        "DUPLICATE_RAW_NODE",
        lambda: m.validate_enumeration_receipt(
            b.source_vector, b.adapters, b.raw_specs, bad
        ),
    )


def test_source_anchor_substitution_fails() -> None:
    b = m.sample_source_bundle()
    forged = replace(b.enumeration.rows[0], source_anchor_digest=_d("wrong"))
    bad = replace(b.enumeration, rows=(forged,) + b.enumeration.rows[1:])
    _assert_code(
        "SOURCE_ANCHOR_MISMATCH",
        lambda: m.validate_enumeration_receipt(
            b.source_vector, b.adapters, b.raw_specs, bad
        ),
    )


def test_mode_mapping_is_independent_and_total() -> None:
    b = m.sample_source_bundle()
    m.validate_mode_mapping(b.enumeration, b.rules, b.mode_mapping)
    assert len(b.mode_mapping.rows) == len(b.enumeration.rows)
    assert b.mode_mapping.rules_digest == b.rules.registry_digest


def test_mode_mapping_omission_fails() -> None:
    b = m.sample_source_bundle()
    bad = replace(b.mode_mapping, rows=b.mode_mapping.rows[:-1])
    _assert_code(
        "MODE_MAPPING_MULTISET_MISMATCH",
        lambda: m.validate_mode_mapping(b.enumeration, b.rules, bad),
    )


def test_mode_mapping_fabrication_fails() -> None:
    b = m.sample_source_bundle()
    forged = m.reidentify_mode_row(
        replace(b.mode_mapping.rows[0], raw_node_id="raw_fabricated")
    )
    bad = replace(b.mode_mapping, rows=b.mode_mapping.rows + (forged,))
    _assert_code(
        "MODE_MAPPING_MULTISET_MISMATCH",
        lambda: m.validate_mode_mapping(b.enumeration, b.rules, bad),
    )


def test_mode_relabel_to_nonreaching_fails() -> None:
    b = m.sample_source_bundle()
    row = b.mode_mapping.rows[0]
    relabeled = m.reidentify_mode_row(
        replace(row, reach_source_mode="NON_REACHING", document_reach="NONE")
    )
    bad = replace(b.mode_mapping, rows=(relabeled,) + b.mode_mapping.rows[1:])
    _assert_code(
        "MODE_MAPPING_RELABEL",
        lambda: m.validate_mode_mapping(b.enumeration, b.rules, bad),
    )


def test_generic_graph_is_small_canonical_and_repeatable() -> None:
    b = m.sample_source_bundle()
    m.validate_generic_graph(b)
    again = m.sample_source_bundle()
    assert b.graph.graph_digest == again.graph.graph_digest
    assert m.canonical_bytes(b.graph) == m.canonical_bytes(again.graph)
    assert len(b.graph.base_rows) == len(b.enumeration.rows)


@pytest.mark.parametrize(
    ("mutation", "code"),
    (
        ("BASE_OMISSION", "BASE_ROW_MULTISET_MISMATCH"),
        ("BASE_FABRICATION", "BASE_ROW_MULTISET_MISMATCH"),
        ("BASE_DUPLICATE", "DUPLICATE_BASE_ROW"),
        ("EDGE_OMISSION", "EDGE_MULTISET_MISMATCH"),
        ("REFERENCE_OMISSION", "REFERENCE_MULTISET_MISMATCH"),
    ),
)
def test_graph_multiset_mutations_fail(mutation: str, code: str) -> None:
    b = m.sample_source_bundle()
    bad = m.mutate_graph_bundle(b, mutation)
    _assert_code(code, lambda: m.validate_generic_graph(bad))


def test_vacuous_proved_none_is_impossible() -> None:
    b = m.sample_source_bundle(include_negative_proof=False)
    m.validate_generic_graph(b)
    absent = [
        row for row in b.graph.denominator_rows
        if row.document_reference_id == "ref_absent"
    ]
    assert len(absent) == 1
    assert absent[0].reach_resolution == "UNRESOLVED"
    assert absent[0].debt_code == "MISSING_WHOLE_GRAPH_NEGATIVE_PROOF"


def test_nonvacuous_negative_proof_binds_whole_graph() -> None:
    b = m.sample_source_bundle(include_negative_proof=True)
    absent = [
        row for row in b.graph.denominator_rows
        if row.document_reference_id == "ref_absent"
    ]
    assert absent[0].reach_resolution == "PROVED_NONE"
    proof = b.negative_proofs[0]
    assert proof.inspected_raw_node_ids == tuple(
        row.raw_node_id for row in b.enumeration.rows
    )


def test_dependency_dag_is_field_total_and_acyclic() -> None:
    result = m.validate_dependency_dag()
    assert result.node_count >= 20
    assert result.edge_count >= 30
    assert result.unmapped_dependency_fields == ()
    assert result.cycle_nodes == ()


def test_prior_envelope_changes_request_digest() -> None:
    q = m.sample_query_bundle()
    changed = replace(q.prior_envelope, envelope_digest=_d("other-envelope"))
    other = m.build_base_request_intent(prior_envelope=changed)
    assert m.request_digest(other) != m.request_digest(q.intent)


def test_phaseio_contract_is_live_shaped_single_state_artifact() -> None:
    q = m.sample_query_bundle()
    contract = q.phase_io_contract
    assert contract.key == "sc/core/evm/codex/recon/transactional_journal_r13"
    assert contract.model_invoked is False
    assert contract.required_commit_actor == "DRIVER"
    assert len(contract.outputs) == 1
    output = contract.outputs[0]
    assert output.identity == (
        "scratchpad:_cut4_r13/private/recon_query_journal_state.v1.json"
    )
    assert output.writer == "DRIVER"
    assert output.write_mode == "REPLACE"
    assert set(contract.immutable_inputs) == {
        "scratchpad:mechanical_program_facts.v1.json",
        "scratchpad:mechanical_program_facts_receipt.v1.json",
        "scratchpad:mechanical_program_facts_debt.v1.json",
    }
    observation = m.live_replace_observation()
    assert contract.validate_writes((observation,), actor="DRIVER").ok
    assert m.REFERENCE_PHASE_IO_REGISTRY[contract.key].digest == contract.digest


def test_attempt_binds_previous_record() -> None:
    q = m.sample_query_bundle()
    bad = replace(q.allocation, previous_record_digest=_d("wrong-record"))
    _assert_code(
        "ALLOCATION_PREVIOUS_RECORD_MISMATCH",
        lambda: m.validate_query_bundle(replace(q, allocation=bad)),
    )


def test_invalid_fact_digest_is_total() -> None:
    q = m.sample_query_bundle(with_torn_temp=True)
    assert q.journal_state.invalid_facts
    bad_state = replace(q.journal_state, invalid_facts=())
    _assert_code(
        "INVALID_FACT_MULTISET_MISMATCH",
        lambda: m.validate_journal_state(bad_state),
    )


def test_private_plan_swap_is_detected() -> None:
    q = m.sample_query_bundle()
    bad_plan = replace(q.private_plan, accept_projected_identity="other.json")
    _assert_code(
        "PRIVATE_PLAN_DIGEST_MISMATCH",
        lambda: m.validate_query_bundle(replace(q, private_plan=bad_plan)),
    )


def test_provider_receipt_swap_is_detected() -> None:
    q = m.sample_query_bundle()
    bad = replace(q.provider_receipt, provider_id="other_provider")
    _assert_code(
        "PROVIDER_RECEIPT_DIGEST_MISMATCH",
        lambda: m.validate_query_bundle(replace(q, provider_receipt=bad)),
    )


def test_aborted_unobserved_has_closed_optional_invocation() -> None:
    q = m.sample_query_bundle(crash_at="ALLOCATION")
    abort = q.abort
    assert abort is not None
    assert abort.invocation_state == "ABSENT"
    assert abort.invocation_digest == ""
    bad = replace(abort, invocation_digest=_d("forbidden"))
    _assert_code("ABORT_OPTIONALITY_INVALID", lambda: m.validate_abort(bad))


def test_crash_after_invocation_allocates_new_attempt() -> None:
    q = m.sample_query_bundle(crash_at="INVOCATION")
    assert q.abort is not None
    assert q.abort.invocation_state == "PRESENT"
    assert q.retry_allocation is not None
    assert q.retry_allocation.attempt_id != q.allocation.attempt_id


def test_publication_link_names_exact_terminal_record() -> None:
    q = m.sample_query_bundle()
    assert q.publication_link.terminal_record_digest == q.terminal_record.record_digest
    bad = replace(q.publication_link, terminal_record_digest=_d("other-terminal"))
    _assert_code("PUBLICATION_TERMINAL_MISMATCH", lambda: m.validate_publication_link(bad, q.terminal_record))


def test_atomic_rewrite_rejects_stale_cas() -> None:
    q = m.sample_query_bundle()
    current = m.canonical_file_bytes(q.preterminal_state)
    _assert_code(
        "JOURNAL_CAS_MISMATCH",
        lambda: m.atomic_rewrite(current, _d("stale"), q.journal_state),
    )


def test_atomic_rewrite_is_deterministic() -> None:
    q = m.sample_query_bundle()
    current = m.canonical_file_bytes(q.preterminal_state)
    expected = hashlib.sha256(current).hexdigest()
    one = m.atomic_rewrite(current, expected, q.journal_state)
    two = m.atomic_rewrite(current, expected, q.journal_state)
    assert one.committed_bytes == two.committed_bytes
    assert one.committed_sha256 == two.committed_sha256


def test_generation_rotation_seals_invalid_fact_once() -> None:
    q = m.sample_query_bundle()
    committed = m.canonical_file_bytes(q.journal_state)
    fact = m.make_invalid_fact("journal.tmp", "TORN_TEMP", b"partial")
    first = m.rotate_generation_once(q.journal_state, committed, (fact,))
    assert first.changed is True
    assert first.state.generation == q.journal_state.generation + 1
    assert first.state.previous_state_sha256 == hashlib.sha256(committed).hexdigest()
    second = m.rotate_generation_once(first.state, m.canonical_file_bytes(first.state), (fact,))
    assert second.changed is False
    assert second.state == first.state


def test_atomic_rewrite_rejects_nonappend_same_generation() -> None:
    q = m.sample_query_bundle()
    current = m.canonical_file_bytes(q.journal_state)
    truncated = m._journal_state(
        q.journal_state.namespace_digest, q.journal_state.request_digest,
        q.journal_state.generation, q.journal_state.previous_state_sha256,
        q.journal_state.invalid_facts, q.journal_state.records[:-1],
    )
    _assert_code(
        "JOURNAL_NONAPPEND_REWRITE",
        lambda: m.atomic_rewrite(
            current, hashlib.sha256(current).hexdigest(), truncated,
        ),
    )


def test_torn_temp_is_typed_and_committed_state_unchanged() -> None:
    q = m.sample_query_bundle()
    committed = m.canonical_file_bytes(q.journal_state)
    result = m.reconcile_torn_temp(committed, b'{"torn":')
    assert result.committed_bytes == committed
    assert result.invalid_fact.classification == "TORN_TEMP"
    assert result.invalid_fact.byte_size == 8


def test_timeout_is_terminal_and_has_no_cursor() -> None:
    q = m.sample_query_bundle(terminal_status="TIMEOUT")
    assert q.terminal.terminal_status == "TIMEOUT"
    assert q.terminal.cursor_out == ""
    assert q.terminal_record is not None


def test_exhausted_success_retains_nonempty_c3_and_replays_exactly() -> None:
    q = m.sample_query_bundle(terminal_status="SUCCESS", exhausted=True)
    assert q.terminal.cursor_out.startswith("c3_")
    assert q.terminal.exhausted is True
    assert m.replay_terminal(q.journal_state, q.intent) == m.canonical_bytes(q.terminal)


def test_payload_record_fields_are_closed() -> None:
    assert tuple(field.name for field in fields(m.PayloadRecord)) == (
        "schema", "payload_id", "provider_id", "private_plan_row_id",
        "invocation_digest", "payload_ordinal", "content_type", "byte_size",
        "raw_sha256", "raw_bytes_b64", "payload_digest",
    )


def test_provider_private_v3_has_all_twelve_kp_fields() -> None:
    names = tuple(field.name for field in fields(m.ProviderPrivateV3))
    assert names[:12] == m.KP_FIELDS
    assert m.NormalizedSemanticRow.__dataclass_fields__.keys() >= set(m.KP_FIELDS)


def test_outcome_payload_and_private_rows_are_exactly_equal() -> None:
    q = m.sample_query_bundle()
    m.validate_payload_conservation(q.provider_receipt, q.provider_private_rows)


def test_duplicate_provider_private_payload_fails() -> None:
    q = m.sample_query_bundle()
    rows = q.provider_private_rows + q.provider_private_rows[:1]
    _assert_code(
        "PAYLOAD_MULTISET_MISMATCH",
        lambda: m.validate_payload_conservation(q.provider_receipt, rows),
    )


def test_payload_content_type_mutation_fails() -> None:
    q = m.sample_query_bundle()
    row = q.provider_private_rows[0]
    payload = replace(row.payload, content_type="TEXT_PLAIN")
    bad = replace(row, payload=payload)
    _assert_code(
        "PAYLOAD_RECORD_INVALID",
        lambda: m.validate_payload_conservation(q.provider_receipt, (bad,)),
    )


def test_payload_byte_sha_mutation_fails() -> None:
    q = m.sample_query_bundle()
    row = q.provider_private_rows[0]
    payload = replace(row.payload, raw_sha256=_d("wrong"))
    bad = replace(row, payload=payload)
    _assert_code(
        "PAYLOAD_RECORD_INVALID",
        lambda: m.validate_payload_conservation(q.provider_receipt, (bad,)),
    )


def test_partial_payload_requires_typed_debt_status() -> None:
    q = m.sample_query_bundle()
    bad = replace(q.provider_receipt, status="FAILURE")
    _assert_code("PROVIDER_STATUS_PAYLOAD_INVALID", lambda: m.validate_provider_receipt(bad))
    debt = replace(q.provider_receipt, status="PARTIAL_DEBT")
    assert m.validate_provider_receipt(m.reidentify_provider_receipt(debt)) is None


def test_normalizer_zero_requires_typed_outcome() -> None:
    q = m.sample_query_bundle(normalizer_status="DEBT")
    outcome = q.normalizer_outcomes[0]
    assert outcome.normalized_row_ids == ()
    assert outcome.debt_code == "NORMALIZER_DEBT"
    bad = replace(outcome, debt_code="")
    _assert_code("NORMALIZER_ZERO_UNTYPED", lambda: m.validate_normalizer_outcome(bad, q.provider_receipt.payload_records[0]))


def test_normalized_rows_conserve_full_kp() -> None:
    q = m.sample_query_bundle()
    m.validate_normalized_conservation(
        q.private_plan, q.provider_private_rows, q.normalizer_outcomes,
        q.normalized_rows,
    )


def test_unknown_diff_kind_is_rejected() -> None:
    _assert_code(
        "UNKNOWN_DIFF_KIND",
        lambda: m.make_diff_row("UNREGISTERED", "EXPECTED", b"x", b"y"),
    )


@pytest.mark.parametrize("kind", sorted(m.DIFF_KINDS))
def test_every_diff_kind_has_exact_source_mapping(kind: str) -> None:
    row = m.make_diff_row(kind, "EXPECTED", b"expected", b"observed")
    assert row.diff_kind == kind
    assert row.expected_source_kind == m.DIFF_SOURCE_MAP[kind][0]
    assert row.observed_source_kind == m.DIFF_SOURCE_MAP[kind][1]


def test_m4_r4_and_receipt_exact_equality() -> None:
    q = m.sample_query_bundle()
    m.validate_completion(q.m4, q.r4, q.completion_receipt)


def test_m4_extra_row_fails() -> None:
    q = m.sample_query_bundle()
    bad = replace(q.m4, provider_private_rows=q.m4.provider_private_rows + q.m4.provider_private_rows[:1])
    _assert_code("M4_DIGEST_MISMATCH", lambda: m.validate_completion(bad, q.r4, q.completion_receipt))


def test_r4_missing_row_fails() -> None:
    q = m.sample_query_bundle()
    bad = replace(q.r4, normalized_rows=())
    _assert_code("R4_DIGEST_MISMATCH", lambda: m.validate_completion(q.m4, bad, q.completion_receipt))


def test_completion_receipt_tamper_fails() -> None:
    q = m.sample_query_bundle()
    bad = replace(q.completion_receipt, r4_digest=_d("tampered"))
    _assert_code("COMPLETION_RECEIPT_MISMATCH", lambda: m.validate_completion(q.m4, q.r4, bad))


def test_fixture_case_denominator_is_covered_by_tests() -> None:
    assert set(FROZEN_MUTATION_CASES) == set(m.FROZEN_CASE_IDS)
