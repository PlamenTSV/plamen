# Cut-4 transactional recon publication R15 preimplementation contract

Date: 2026-08-10
Status: Part-0 architecture-only repair awaiting independent review
Supersedes: only the four rejected R14 preimplementation gates
Authority: all fixture, model, implementation, production, provider,
ArtifactLedger, G3, audit, commit, push, install, cutover, release, readiness,
and protocol-answer authority is false

## 0. Decision boundary

R15 is an executable preimplementation contract, not an implementation. This
turn creates only this contract and its author receipt. It does not create,
edit, import, collect, or run an R15 fixture, parser oracle, model, transcript,
provider, or production path.

R1-R14 ownership, fixed provider slots, MODEL shards, dependency units, legacy
non-adoption, project-root containment, sole canonical publication owner,
nonempty exhausted c3, and Part-0 ceiling remain unchanged except where an R15
clause below replaces one of the four rejected R14 gates.

## 1. Authenticated repair input

The complete R14 independent REPAIR review was authenticated and read end to
end before R15 was authored:

| Artifact | Bytes | SHA-256 |
|---|---:|---|
| `review_fixtures/cut4_transactional_recon_publication_r14_architecture_independent_review_20260810.md` | 24,526 | `5037237575a19c122a1e55cdff709256f14d2a5fda992130e7813afce59133b3` |
| `architecture/cut4-transactional-recon-publication-r14-preimplementation-amendment.md` | 40,913 | `797a3d7d6e549ca4aff405cd00f260d96b5bc4f36660d4a96b2ae682ce7d6e44` |
| `review_fixtures/cut4_transactional_recon_publication_r14_amendment_author_receipt_20260810.md` | 5,544 | `ce1f5f185cce4bbfbca478fa8e09040ac32ef2734e1681a04a2a3ca4dd7e181c` |

The review's four findings are the complete R15 repair boundary.

## 2. Exact versioned artifact registry

Only the first two paths exist in this authoring turn. All other paths are
future single-writer artifacts and may be created only after the preceding
transport gate validates.

```json
{
  "schema": "cut4.r15.path_registry.v1",
  "architecture_contract": "architecture/cut4-transactional-recon-publication-r15-preimplementation-contract.md",
  "architecture_author_receipt": "review_fixtures/cut4_transactional_recon_publication_r15_contract_author_receipt_20260810.md",
  "root_orchestration_receipt": "review_fixtures/cut4_transactional_recon_publication_r15_root_orchestration_receipt.json",
  "architecture_review": "review_fixtures/cut4_transactional_recon_publication_r15_architecture_independent_review_20260810.md",
  "red_oracle_package": "review_fixtures/cut4_transactional_recon_publication_r15_red_oracle.py",
  "red_test": "tests/test_cut4_transactional_recon_publication_r15_preimplementation.py",
  "red_failed_run": "review_fixtures/cut4_transactional_recon_publication_r15_red_failed_run_20260810.json",
  "red_author_receipt": "review_fixtures/cut4_transactional_recon_publication_r15_red_author_receipt_20260810.json",
  "negative_proof_receipt": "review_fixtures/cut4_transactional_recon_publication_r15_independent_negative_proof_receipt_20260810.json",
  "red_review": "review_fixtures/cut4_transactional_recon_publication_r15_red_independent_review_20260810.md",
  "model": "review_fixtures/cut4_transactional_recon_publication_r15_reference_model.py",
  "green_author_receipt": "review_fixtures/cut4_transactional_recon_publication_r15_green_author_receipt_20260810.json",
  "green_review": "review_fixtures/cut4_transactional_recon_publication_r15_green_independent_review_20260810.md",
  "transport_directory": "review_fixtures/cut4_transactional_recon_publication_r15_transport"
}
```

## 3. Closed scalar fields, enums, and self-preimages

The external dependency rows in section 8.1 combine with this scalar registry to form
the complete dataclass byte schema. Every type serializes, in order:
`schema`, `object_id`, the scalar fields listed here, its dependency fields in
FrozenContractFields order, then `object_digest`. `additionalProperties=false`
and missing/duplicate fields are rejected. A scalar named `*_bytes_base64`
must strict-decode and match its paired size/SHA dependency or scalar.

```json
{
  "schema": "cut4.r15.closed_scalar_contract.v1",
  "expanded_kp": ["private_plan_row_id", "semantic_row_id", "private_source_identity", "provider_id", "consumer_id", "flow_instance_id", "multiplicity_key", "multiplicity_ordinal", "applicability_predicate_id", "selection_predicate_id", "accept_disposition", "accept_projected_identity"],
  "kp_types": ["PrivatePlan", "ProviderPrivateV4", "NormalizerExecutionEvidence", "NormalizedSemanticRow", "NormalizerReceipt", "NormalizerOutcome", "DiffSide", "DiffRow", "M4", "R4", "CompletionReceipt"],
  "provider_status": ["NOT_APPLICABLE", "NOT_SELECTED", "SUCCESS", "SUCCESS_EMPTY", "DEBT", "FAILURE", "TIMEOUT", "MALFORMED"],
  "provider_status_debt": [
    ["NOT_APPLICABLE", "NONE"], ["NOT_SELECTED", "NONE"],
    ["SUCCESS", "NONE"], ["SUCCESS_EMPTY", "NONE"],
    ["DEBT", "PROVIDER_DEBT"], ["FAILURE", "PROVIDER_FAILURE"],
    ["TIMEOUT", "PROVIDER_TIMEOUT"], ["MALFORMED", "PROVIDER_MALFORMED"]
  ],
  "normalizer_status_debt": [
    ["ACCEPTED", "NONE"], ["REJECTED", "NORMALIZER_REJECTED"],
    ["DEBT", "NORMALIZER_DEBT"], ["FAILURE", "NORMALIZER_FAILURE"],
    ["TIMEOUT", "NORMALIZER_TIMEOUT"], ["MALFORMED", "NORMALIZER_MALFORMED"]
  ],
  "diff_value_types": ["ROW_MULTIPLICITY", "BOOLEAN", "INTEGER", "COUNT"],
  "diff_kinds": ["MISSING", "SUPERSET", "BODY_MISMATCH", "BOOLEAN_MISMATCH", "INTEGER_MISMATCH", "COUNT_MISMATCH", "MULTIPLICITY_MISMATCH"],
  "type_scalar_fields": {
    "PayloadRecord": ["payload_id", "ordinal", "content_type", "payload_bytes_base64", "byte_size", "payload_sha256", "payload_digest"],
    "ExplicitZeroProof": ["consumer_row_id", "query_id", "query_input_digest", "provider_id", "applicability_predicate_id", "selection_predicate_id", "tool_id", "tool_version", "tool_configuration_digest", "input_snapshot_digests", "bounded_limits_digest", "invocation_exit_class", "stdout_sha256", "stderr_sha256", "enumerated_result_count", "exhausted_cursor", "zero_evidence_digest", "zero_receipt_digest"],
    "ProviderReceipt": ["provider_id", "status", "debt_code", "applicability_result", "selection_result", "payload_count", "payload_roster_digest", "receipt_identity"],
    "ProviderPrivateV4": ["source_snapshot_digest", "payload_count", "payload_roster_digest"],
    "NormalizerExecutionEvidence": ["normalizer_id", "normalizer_version", "normalizer_source_sha256", "configuration_digest", "argv_digest", "input_snapshot_digest", "exit_class", "stdout_byte_size", "stdout_sha256", "stderr_byte_size", "stderr_sha256", "evidence_digest"],
    "NormalizedSemanticRow": ["semantic_kind", "normalized_identity", "normalized_field_array", "payload_id", "payload_digest", "provider_receipt_identity", "source_snapshot_digest", "normalizer_evidence_id", "normalizer_evidence_digest", "row_digest"],
    "NormalizerReceipt": ["status", "debt_code", "normalized_row_count", "normalized_row_roster_digest", "receipt_identity", "receipt_digest"],
    "NormalizerOutcome": ["status", "debt_code", "normalized_row_count", "normalized_row_roster_digest", "outcome_digest"],
    "DiffSide": ["side", "value_type", "source_kind", "source_schema", "source_id", "source_body_bytes_base64", "source_byte_size", "source_sha256", "source_semantic_digest", "boolean_value_present", "boolean_value", "integer_value_present", "integer_value", "count_value_present", "count_value", "multiplicity"],
    "DiffRow": ["diff_kind", "expected_count", "observed_count", "count_delta", "row_digest"],
    "JournalSnapshotAuthority": ["namespace", "request_digest_hex", "generation", "state_bytes_base64", "state_byte_size", "state_sha256", "invalid_fact_roster_digest"],
    "JournalState": ["namespace", "request_digest_hex", "generation", "prior_state_sha256", "record_ordinal", "record_kind", "record_bytes_base64", "record_byte_size", "record_sha256", "state_digest"],
    "TerminalJournalRecord": ["record_ordinal", "record_kind", "request_digest_hex", "attempt_id", "terminal_bytes_base64", "terminal_byte_size", "terminal_sha256", "record_digest"],
    "AbortedUnobservedRecord": ["record_ordinal", "record_kind", "reason", "record_digest"],
    "CommittedPublicationReceipt": ["operation_key", "contract_digest", "launch_digest", "commit_actor", "public_output_count", "public_output_roster_digest", "receipt_digest"],
    "PublicationLink": ["terminal_record_digest", "committed_receipt_digest", "public_output_roster_digest", "link_digest"],
    "PublicationAckJournalRecord": ["record_ordinal", "record_kind", "publication_link_digest", "committed_receipt_digest", "record_digest"],
    "M4": ["provider_private_roster_digest", "normalizer_evidence_roster_digest", "normalizer_receipt_roster_digest", "normalizer_outcome_roster_digest", "normalized_row_roster_digest", "diff_row_roster_digest", "public_output_roster_digest", "manifest_digest"],
    "R4": ["m4_identity", "m4_digest", "repeated_array_digest", "receipt_digest"],
    "CompletionReceipt": ["m4_identity", "m4_digest", "r4_identity", "r4_digest", "terminal_record_digest", "publication_link_digest", "committed_receipt_digest", "public_output_roster_digest", "completion_digest"]
  }
}
```

The exact status shapes are non-vacuous. NOT_APPLICABLE requires applicability
false, selection false, zero payloads, no evidence/debt, and the named
predicate FKs. NOT_SELECTED requires applicability true, selection false, zero
payloads, and authenticated predicate evidence. SUCCESS with nonzero payloads
has no zero proof; SUCCESS with zero payloads requires exactly one validated
ExplicitZeroProof. SUCCESS_EMPTY is query-scoped and requires its prior query
zero receipt and nonempty exhausted c3. Every debt/failure/timeout/malformed
status has zero payloads and exactly the table's nonempty evidence/debt shape.
Normalizer ACCEPTED has at least one row and no debt; every other normalizer
status has zero rows and its exact table debt.

For each dataclass, `object_id` and `object_digest` are fields marked
`SELF_DERIVED`; they create no graph self-edge. Their preimage is generated,
never hand-listed: exact schema plus every scalar and dependency field in the
closed declared order, excluding `object_id` and `object_digest`. The formulas
are:

```text
P_TYPE(T) = UTF8("cut4.r15.type." || snake(T) || ".v1\0")
preimage(T) = CJ(T with object_id/object_digest removed)
object_digest = H(P_TYPE(T) || preimage(T))
object_id = snake(T) || ":" || lowercase_hex(object_digest)
```

Fields such as `payload_id`, `row_digest`, and receipt-specific IDs/digests are
validated by their literal type domain as well as the common object identity;
they are scalar preimage members, not dependency edges. JSON integer checks
use exact runtime type and reject booleans. Inactive DiffSide union fields must
have their `*_present=false` and canonical neutral value; active branches are
type-exact and cross-type coercion is forbidden.

### 3.1 Mechanical reflection and derived DAG

The future MODEL contains no caller-supplied contract registry. The RED oracle
extracts the two exact JSON roots above from this authenticated contract and
freezes their canonical bytes/hash before MODEL authorship. The implemented
dataclasses use immutable metadata containing the full FrozenContractFields
tuple; validators and constructors carry decorators with the same tuple ID.
Introspection walks:

```text
all closed dataclasses
all dataclass fields and metadata
all public constructor callable signatures
all validate_* callable signatures and decorator metadata
all SELF_DERIVED preimage fields
```

It emits `ReflectedContractFields` in frozen tuple order and requires exact
byte equality to `FrozenContractFields`, including all three named surfaces.
It also derives nodes as the union of owner/target types and derives an edge
`target_type -> owner_type` for every non-SELF dependency, then deduplicates by
ordered pair. Missing/extra/unannotated fields, parameters, types, surfaces,
cardinality, order semantics, or preimage members fail. JournalState,
ExplicitZeroProof, every provider/normalizer/diff child, M4, R4, PhaseIO/public
bytes, committed receipt, publication link, and completion are therefore in
the denominator by construction. Kahn elimination must have zero remainder.

The exact registry contains 108 unique field tuples. Its mechanical projection
contains 34 unique types and 107 unique dependency edges with zero Kahn
remainder. These counts are validation checksums; the field tuples, not the
counts or a hand-copied edge list, remain authority.

`JournalSnapshotAuthority` is an authenticated prior-state byte boundary for
one CAS attempt, not a recursively constructed current `JournalState` object.
It is fully parsed and validated before construction, but its previous graph
instance is not reinserted into the new instance's type graph. This explicit
generation boundary permits retries without hiding a type-level cycle.

## 4. Gate J: acyclic terminal, external publication, and optional ACK

### 4.1 Exact fixture-scoped artifact routes

The future reference contract may instantiate, but does not register live, the
following exact PhaseIO-shaped artifacts:

| object | exact identity | writer/mode |
|---|---|---|
| journal state | `scratchpad:_cut4_r15/private/recon_query_journal_state.v3.json` | DRIVER / REPLACE |
| committed receipt | `scratchpad:_cut4_r15/private/committed_publication_receipt.v1.json` | DRIVER / REPLACE |
| publication link | `scratchpad:recon_signal_publication_link.r15.json` | DRIVER / REPLACE |

The journal key is
`sc/core/evm/codex/recon/transactional_journal_r15`. The committed-receipt and
link artifacts are outputs of the sole canonical publication successor, not
provider or MODEL outputs. They are exact registered fixture contracts during
R15 testing only; current PhaseIO resolver and ArtifactLedger remain unchanged.

### 4.2 Acyclic construction order

The only permitted order is:

```text
validated JournalSnapshotAuthority
  -> AttemptAllocation (+1 CAS, one ATTEMPT_ALLOCATION record)
  -> InvocationRecord (+1 CAS, one INVOCATION record)
  -> TerminalEnvelope (+1 CAS, one TERMINAL record)
  -> canonical public bytes + CommittedPublicationReceipt (external bundle)
  -> PublicationLink (same external publication bundle)
  -> optional PublicationAckJournalRecord (+1 CAS, one PUBLICATION_ACK record)
  -> M4 -> R4 -> CompletionReceipt
```

An unobserved invocation instead appends exactly one ABORTED_UNOBSERVED record
at `+1`; a retry begins with a later ATTEMPT_ALLOCATION at another `+1` and a
new attempt ID. Each successful CAS takes exact expected generation/SHA and
produces `generation=current+1`, immutable namespace/request, exact prior-state
SHA, all prior record bytes unchanged, and exactly one appended closed-kind
record. No transition appends two records.

The terminal record embeds and validates TerminalEnvelope plus every upstream
request/attempt/invocation/provider/zero/normalizer/evidence/query object. It
does not require public bytes, a commit receipt, a PublicationLink, or an ACK.
Terminal replay validates the current journal and returns the exact committed
terminal bytes even when no publication exists.

The sole canonical publisher consumes the committed terminal record as an
immutable input. It derives the exact complete public output roster, stages all
bytes, and atomically publishes public outputs, CommittedPublicationReceipt,
and PublicationLink as one bundle. The receipt binds terminal record, PhaseIO
contract/launch, commit actor, and every public identity/size/SHA. The link
binds the already committed terminal record, receipt, and same public roster.
PublicationLink validation never reads or requires a journal record created
after the link. There is no `JournalRecord -> PublicationLink` dependency.

If policy requests durable acknowledgement, a later PUBLICATION_ACK record may
bind the already validated link and receipt. It is optional for link validity
and terminal replay; if present, it is required by completion and must be the
single next legal record. The overloaded R14 `PUBLICATION_LINK` journal kind is
retired.

### 4.3 Closed record kinds and exact crash/retry states

`RecordKind` is exactly `ATTEMPT_ALLOCATION`, `INVOCATION`,
`ABORTED_UNOBSERVED`, `TERMINAL`, or `PUBLICATION_ACK`. A literal decoder table
maps each to its dataclass, schema, ID/digest fields, allowed immediate prior
kinds, request/attempt lineage, and retry rule. Unknown, free, malformed,
noncanonical, extra-field, wrong-request, wrong-attempt, wrong-ordinal, or
wrong-digest bytes fail before CAS/replay.

The only recoverable physical states are:

| state | authoritative interpretation and next action |
|---|---|
| no terminal | validate journal; append exactly the next attempt/invocation/abort/terminal record |
| terminal, no external bundle | replay terminal bytes; rerun canonical publisher with identical immutable inputs |
| terminal plus only temporary bundle | ignore typed temp after authenticating name/parent; rerun publisher |
| terminal plus partial/malformed final bundle | `PUBLICATION_PARTIAL_DEBT`; no link/ACK/completion; deterministic canonical recovery replaces the complete bundle or remains debt |
| terminal plus complete valid receipt/link/public bytes, no ACK | publication is valid; replay is no-op; optionally append one ACK at +1 |
| complete valid bundle plus valid ACK | exact no-op replay and completion validation |
| ACK without valid link/receipt/public bytes | invalid journal state; typed debt; never treated as published |
| crash before invocation observation | append ABORTED_UNOBSERVED at +1, then allocate a distinct attempt at another +1 |
| crash with unknown CAS outcome | reread exact state SHA/generation; if record exists validate/replay, otherwise retry CAS from the reread authority |

External bundle recovery is all-old/all-new at the authoritative namespace.
If the host cannot provide the required atomic namespace swap, it emits typed
`ATOMIC_PUBLICATION_UNAVAILABLE` debt; it never reports success from a partial
set. The exact terminal bytes, output registry, normalizer version, plan,
contract, and launch digests make deterministic recovery inputs immutable.

M4/R4/completion reconstruct and validate every child from independently
supplied upstream objects. They reject stale, invalid, unanchored, missing, or
self-consistently rebuilt children. Completion binds the committed receipt and
link; it binds ACK only when the sealed policy selected ACK. No free caller
receipt/link can satisfy a validator.

## 5. Exact fixture-first RED denominator

### 5.1 Mutation vector schema

Case names alone are not an oracle. Before the MODEL path exists, the RED
author freezes one closed `MutationVector` per exact case ID, the oracle/test
source bytes, exact base input bytes/SHA, mutation operation and bytes, expected
stage/error, and observed failed-run row. The RED receipt binds all 96 vector
bytes and the unchanged collected-node roster. The negative verifier and RED
review independently reconstruct them without importing the absent model.

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "cut4.r15.mutation_vector.schema.v1",
  "type": "object",
  "additionalProperties": false,
  "required": ["schema", "case_id", "base_artifact_identity", "base_bytes_base64", "base_byte_size", "base_sha256", "operation", "mutation_offset", "mutation_delete_count", "mutation_bytes_base64", "mutated_byte_size", "mutated_sha256", "oracle_package_sha256", "expected_stage", "expected_error_code", "observed_exit_class", "observed_error_code", "vector_digest"],
  "properties": {
    "schema": {"const": "cut4.r15.mutation_vector.v1"},
    "case_id": {"type": "string", "pattern": "^[a-z0-9_]+(?:\\.[a-z0-9_]+)+$"},
    "base_artifact_identity": {"type": "string", "minLength": 1},
    "base_bytes_base64": {"type": "string"},
    "base_byte_size": {"type": "integer", "minimum": 0},
    "base_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
    "operation": {"enum": ["REPLACE_BYTES", "DELETE_BYTES", "INSERT_BYTES", "DUPLICATE_ROW", "SWAP_TYPED_ID", "REBUILD_DESCENDANTS"]},
    "mutation_offset": {"type": "integer", "minimum": 0},
    "mutation_delete_count": {"type": "integer", "minimum": 0},
    "mutation_bytes_base64": {"type": "string"},
    "mutated_byte_size": {"type": "integer", "minimum": 0},
    "mutated_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
    "oracle_package_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
    "expected_stage": {"enum": ["TRANSPORT", "DUAL_UNIVERSE", "DEPENDENCY_REFLECTION", "JOURNAL_CAS", "PUBLICATION", "PRIVATE_COMPLETION"]},
    "expected_error_code": {"type": "string", "pattern": "^R15_[A-Z0-9_]+$"},
    "observed_exit_class": {"const": "REJECTED"},
    "observed_error_code": {"type": "string", "pattern": "^R15_[A-Z0-9_]+$"},
    "vector_digest": {"type": "string", "pattern": "^[0-9a-f]{64}$"}
  }
}
```

`mutated_bytes = base[0:offset] || decoded(mutation_bytes_base64) ||
base[offset+delete_count:]`; structured operations additionally require their
typed decoder to reproduce exactly those mutated bytes. Size/SHA are ordinary
byte facts. `vector_digest = H(UTF8("cut4.r15.mutation_vector.v1\0") ||
CJ(vector without vector_digest))`. Expected and observed errors must equal
`R15_` plus uppercase case ID with every dot replaced by underscore.

### 5.2 Closed 96-case roster

```json
{
  "schema": "cut4.r15.red_mutation_denominator.v1",
  "chronology": [
    "chronology.arch_accept_missing",
    "chronology.arch_decision_not_accept",
    "chronology.model_present_at_fixture_freeze",
    "chronology.model_present_at_failed_run",
    "chronology.fixture_hash_transcript_mismatch",
    "chronology.node_roster_digest_mismatch",
    "chronology.mutation_roster_digest_mismatch",
    "chronology.environment_identity_missing",
    "chronology.failure_stage_mismatch",
    "chronology.failed_exit_zero",
    "chronology.stdout_digest_mismatch",
    "chronology.stderr_digest_mismatch",
    "chronology.principal_or_key_reuse",
    "chronology.model_started_before_red_accept",
    "chronology.fixture_changed_after_red",
    "chronology.r13_evidence_used_as_authority"
  ],
  "source_parser": [
    "source.raw_spec_omission_rebuild",
    "source.unenumerated_recognized_suffix",
    "source.unenumerated_recognized_prefix",
    "source.coverage_byte_gap",
    "source.coverage_byte_overlap",
    "source.coverage_reordered",
    "source.empty_file_sentinel_missing",
    "source.invalid_utf8_skipped",
    "source.bake_facts_bytes_substitution",
    "source.bake_receipt_wrong_run",
    "source.bake_debt_slot_omitted",
    "source.parser_version_config_swap",
    "source.parser_package_hash_swap",
    "source.rule_registry_rehashed_relabel",
    "source.mode_mapping_omission_rebuild",
    "source.omission_plus_false_proved_none"
  ],
  "dag_journal": [
    "dag.self_declared_required_field_omission",
    "dag.reflected_extra_dependency",
    "dag.normalized_outcome_direction_reversed",
    "dag.inline_untyped_evidence_digest",
    "journal.same_generation_rewrite",
    "journal.next_generation_namespace_swap",
    "journal.next_generation_request_swap",
    "journal.next_generation_invalid_fact_or_prior_record_swap",
    "journal.generation_skip_plus_two",
    "journal.recovery_request_swap",
    "journal.repeated_sealed_fact_new_generation",
    "journal.unregistered_record_kind",
    "journal.record_request_mismatch",
    "journal.self_hashed_untyped_terminal_replay",
    "journal.mismatched_active_retry_allocation",
    "journal.rehashed_invalid_terminal_roster_replay"
  ],
  "private_completion": [
    "private.success_zero_without_proof",
    "private.zero_proof_query_swap",
    "private.zero_proof_receipt_tamper",
    "private.normalized_payload_id_swap",
    "private.normalized_payload_digest_swap",
    "private.normalized_provider_receipt_swap",
    "private.normalized_evidence_swap",
    "private.free_normalizer_evidence",
    "private.free_normalizer_receipt",
    "private.accepted_zero_normalized_rows",
    "private.rejection_with_nonzero_rows",
    "private.diff_count_boolean_collapse",
    "private.diff_kp_field_missing",
    "private.diff_source_body_schema_id_mismatch",
    "private.rebuilt_m4_with_invalid_private_child",
    "private.completion_stale_unanchored_commit_receipt"
  ],
  "transport_dual": [
    "transport.root_signature_invalid",
    "transport.subject_bytes_hash_mismatch",
    "transport.ordinal_mismatch",
    "transport.predecessor_missing",
    "transport.predecessor_reordered",
    "transport.task_assignment_mismatch",
    "transport.self_review_task_reuse",
    "transport.review_join_omitted",
    "transport.decision_subject_mismatch",
    "transport.r14_evidence_used_as_authority",
    "dual.same_parser_import",
    "dual.parser_a_coverage_gap",
    "dual.parser_b_coverage_gap",
    "dual.common_semantic_omission",
    "dual.nonsemantic_witness_mismatch",
    "dual.negative_receipt_self_issued"
  ],
  "contract_publication": [
    "contract.frozen_field_omitted",
    "contract.reflected_extra",
    "contract.journal_state_missing",
    "contract.self_digest_edge",
    "contract.validator_parameter_omitted",
    "contract.constructor_preimage_omitted",
    "publication.terminal_requires_future_link",
    "publication.link_requires_future_ack",
    "publication.combined_terminal_ack_append",
    "publication.link_before_terminal",
    "publication.unanchored_commit_receipt",
    "publication.partial_final_false_success",
    "publication.ack_without_link",
    "publication.cas_unknown_duplicate_append",
    "publication.retry_same_attempt",
    "publication.completion_missing_committed_receipt"
  ]
}
```

The arithmetic is `16 * 6 = 96` unique mutation vectors. The first 64 retain
the complete R14 denominator, but R14 outputs remain non-authoritative; their
R15 vectors and failed results are newly frozen and transported. Omission,
skip, xfail, duplicate, rename, changed expected code, or changed vector bytes
fails RED review. Positive deterministic/replay tests are additional and do
not alter this denominator.

The future test performs model import inside test bodies so all 96 mutation
nodes and oracle-only positive nodes can be collected while the exact MODEL
path is absent. The bounded RED run must be nonzero for the named absent-model
and unimplemented-model gates, while the model-independent transport,
dual-universe, reflection-denominator, and vector-oracle checks already pass.
The unchanged test SHA/node/vector digests are carried through RED review,
MODEL transport, GREEN author receipt, and GREEN review.

## 6. Review gates, non-goals, and acceptance ceiling

The R15 architecture reviewer authenticates this contract/receipt and R14
REPAIR review, parses every JSON root/schema with duplicate-key and non-finite
rejection, rederives registry digests, validates transport ordinals and
predecessors, validates seven-task no-self-review constraints, computes the
FrozenContractFields node/edge projection and zero Kahn remainder, checks all
96 roster IDs/counts, confirms current references, confirms future R15 paths
absent, and returns ACCEPT or REPAIR. Only ACCEPT permits root transport and
RED authorship.

The RED reviewer verifies the root/envelope chain, exact path absence, oracle
and test frozen bytes, dual independent packages, all mutation vector bytes,
failed transcript, negative receipt, 96 expected failures, no-self-review
joins, and unchanged hashes. Only ACCEPT permits MODEL authorship. The GREEN
reviewer reproduces exact unchanged fixture/oracle/vector hashes, model bytes,
all validators, dependency projection, staged crash/retry states, deterministic
repeat, and complete pass before any claim can advance.

R15 does not prove human, agent, host, or cryptographic-key independence. It
does not prove ecosystem grammar correctness beyond the frozen dual oracle
vectors, host atomicity where unavailable, provider availability, target
protocol security, live PhaseIO/ArtifactLedger integration, production
cutover, audit completion, release, readiness, or a protocol answer. It does
not change provider denominators, MODEL shard ownership, ArtifactLedger, G3,
or any production file.

Part-0 and all fixture, model, implementation, production, provider,
ArtifactLedger, G3, audit, commit, push, install, cutover, release, readiness,
and protocol-answer authority remain false. This author receipt is not an
independent architecture ACCEPT.


## 7. Frozen adapter and semantic registries

The following bodies are the immutable registry authority. The future RED
oracle embeds these exact rows in module constants; the fixture authenticates
its source bytes before the MODEL path exists. Neither parser accepts adapter,
rule, or mode rows from a caller.

```json
{
  "schema": "cut4.r15.adapter_rule_registry.v1",
  "adapters": [
    ["adapter_aptos_v1", "aptos", [".move"], "aptos_move_schema_grammar_v1", "aptos_move_stream_dfa_v1", ["program_facts", "program_facts_receipt", "program_facts_debt"]],
    ["adapter_daml_v1", "daml", [".daml"], "daml_schema_grammar_v1", "daml_stream_dfa_v1", ["program_facts", "program_facts_receipt", "program_facts_debt"]],
    ["adapter_evm_v1", "evm", [".sol", ".vy", ".yul"], "evm_schema_grammar_v1", "evm_stream_dfa_v1", ["program_facts", "program_facts_receipt", "program_facts_debt"]],
    ["adapter_go_v1", "go", [".go"], "go_schema_grammar_v1", "go_stream_dfa_v1", ["program_facts", "program_facts_receipt", "program_facts_debt"]],
    ["adapter_rust_v1", "rust", [".rs"], "rust_schema_grammar_v1", "rust_stream_dfa_v1", ["program_facts", "program_facts_receipt", "program_facts_debt"]],
    ["adapter_solana_v1", "solana", [".rs"], "solana_rust_schema_grammar_v1", "solana_rust_stream_dfa_v1", ["program_facts", "program_facts_receipt", "program_facts_debt"]],
    ["adapter_soroban_v1", "soroban", [".rs"], "soroban_rust_schema_grammar_v1", "soroban_rust_stream_dfa_v1", ["program_facts", "program_facts_receipt", "program_facts_debt"]],
    ["adapter_sui_v1", "sui", [".move"], "sui_move_schema_grammar_v1", "sui_move_stream_dfa_v1", ["program_facts", "program_facts_receipt", "program_facts_debt"]]
  ],
  "rules": [
    ["rule_declaration_v1", "DECLARATION", "MODE_BASE", "BASE_SEMANTIC", "FORBIDDEN"],
    ["rule_import_v1", "IMPORT", "MODE_REFERENCE", "REFERENCE", "FORBIDDEN"],
    ["rule_call_v1", "CALL", "MODE_REFERENCE", "REFERENCE", "FORBIDDEN"],
    ["rule_member_call_v1", "MEMBER_CALL", "MODE_REFERENCE", "REFERENCE", "FORBIDDEN"],
    ["rule_path_literal_v1", "PATH_LITERAL", "MODE_REFERENCE", "REFERENCE", "FORBIDDEN"],
    ["rule_content_instruction_v1", "CONTENT_INSTRUCTION", "MODE_REFERENCE", "REFERENCE", "FORBIDDEN"],
    ["rule_graph_edge_v1", "GRAPH_EDGE", "MODE_EDGE", "EDGE", "FORBIDDEN"],
    ["rule_probe_edge_v1", "PROBE_EDGE", "MODE_EDGE", "EDGE", "FORBIDDEN"],
    ["rule_whitespace_v1", "WHITESPACE", "MODE_NONSEMANTIC", "NONSEMANTIC_PROVED", "REQUIRED"],
    ["rule_comment_v1", "COMMENT", "MODE_NONSEMANTIC", "NONSEMANTIC_PROVED", "REQUIRED"],
    ["rule_punctuation_v1", "PUNCTUATION", "MODE_NONSEMANTIC", "NONSEMANTIC_PROVED", "REQUIRED"],
    ["rule_nonreference_literal_v1", "NONREFERENCE_LITERAL", "MODE_NONSEMANTIC", "NONSEMANTIC_PROVED", "REQUIRED"],
    ["rule_invalid_unknown_v1", "INVALID_OR_UNKNOWN", "MODE_DEBT", "UNRESOLVED_DEBT", "FORBIDDEN"]
  ]
}
```

Row object field orders are those in `AdapterRow` and `RuleRow`; each compact
tuple above expands positionally, then receives its digest. Registry order is
the displayed order. Exact digest domains are:

```text
P_SOURCE       = UTF8("cut4.r15.source_file.v1\0")
P_BAKE         = UTF8("cut4.r15.bake_binding.v1\0")
P_ADAPTER      = UTF8("cut4.r15.adapter_row.v1\0")
P_ADAPTER_REG  = UTF8("cut4.r15.adapter_registry.v1\0")
P_RULE         = UTF8("cut4.r15.rule_row.v1\0")
P_RULE_REG     = UTF8("cut4.r15.rule_registry.v1\0")
P_COVERAGE     = UTF8("cut4.r15.coverage_row.v1\0")
P_CANDIDATE    = UTF8("cut4.r15.candidate_row.v1\0")
P_WITNESS      = UTF8("cut4.r15.nonsemantic_witness.v1\0")
P_DEBT         = UTF8("cut4.r15.parse_debt.v1\0")
P_CLASS        = UTF8("cut4.r15.classification_row.v1\0")
P_EDGE         = UTF8("cut4.r15.edge_row.v1\0")
P_PARSER_RCPT  = UTF8("cut4.r15.parser_receipt.v1\0")
P_NEG_PROOF    = UTF8("cut4.r15.total_negative_proof.v1\0")
P_NEG_RCPT     = UTF8("cut4.r15.independent_negative_receipt.v1\0")

row_digest = H(P_row_kind || CJ(row with its *_digest field removed))
registry_digest = H(P_registry_kind || CJ(ordered expanded rows))
roster_digest = H(P_row_kind || CJ(ordered [row_id,row_digest] pairs))
receipt_digest = H(P_receipt_kind || CJ(receipt without receipt_digest))
proof_digest = H(P_NEG_PROOF || CJ(proof without proof_digest))
```

For byte-bearing rows, strict base64 decode must reproduce byte size and SHA.
`source_vector_digest` is the digest of source rows sorted by
`(canonical_identity, ordinal, source_id)`; physical aliases are rejected
before parsing. BAKE rows sort by the literal three-slot order and must share
run, adapter, ecosystem, contract, and launch authority.

### 7.1 Totality, equality, and PROVED_NONE

For each parser and each nonempty source, coverage is an exact ordered
partition `[0,size)` with no gap, overlap, reordering, or zero-length row. An
empty source has exactly one `[0,0)` EMPTY_FILE witness. Every byte is therefore
accounted for, even if invalid or debt. The parser receipt equations are:

```text
covered_byte_count = source_byte_count
unparsed_remainder_count = 0
coverage disposition XOR = candidate | nonsemantic witness | parse debt
candidate multiset = classification multiset by candidate_id and multiplicity
every edge source_candidate_id exists exactly once
```

Before parser tags and row digests are compared, projection `pi_U` removes only
`parser`, row IDs, and row digests and retains source identity, exact spans/raw
SHA, grammar production, semantic class, rule/mode/classification, witness or
debt code, target identity, edge class, and evidence SHA. Exact ordered
multiset equality is mandatory:

```text
pi_U(A.coverage/candidates/witnesses/debts/classifications/edges)
  =
pi_U(B.coverage/candidates/witnesses/debts/classifications/edges)
```

The independent verifier separately checks every source byte against both
partitions and the frozen grammar/rule tables. `NONSEMANTIC_PROVED` requires
matching A and B witness rows over the identical span, an allowed witness
class, exact grammar production, and the rule whose witness permission is
REQUIRED. A shared omission, fabrication, relabel, duplicate, or mismatch is
DEBT, not an accepted common result.

For target `t`, `PROVED_NONE` additionally requires the complete dual source,
BAKE, adapter, rule, coverage, candidate, witness, debt, classification, and
edge rosters; zero unparsed remainder; zero disagreement; no target-relevant
parse debt; exact negative analyzer package bytes/hash; and a transport-bound
IndependentNegativeReceipt from `P_NEGATIVE_VERIFIER`. The verifier enumerates
all candidate and edge paths to `t`; an empty global universe, reduced roster,
missing BAKE debt slot, relevant unresolved edge, free digest, self-issued
receipt, or receipt/task mismatch yields DEBT. The MODEL consumes the frozen
dual proof bundle but is never its author or oracle.

## 8. Gate D: metadata-generated complete dependency denominator

### 8.1 Single authoritative field registry

There is no hand-copied node or edge list in R15. `FrozenContractFields` below
is the sole dependency authority. Every tuple has exact field order:

```text
[owner_type, field_name, dependency_kind, target_type, cardinality,
 ordering, surfaces]
```

`dependency_kind` is `FK`, `DIGEST`, `EMBEDDED`, `ROSTER`, `PREIMAGE`, or
`VALIDATOR_INPUT`; cardinality is `ONE`, `ZERO_OR_ONE`, or `MANY`; ordering is
`SCALAR`, `CANONICAL_SORT`, or `DECLARED_ORDER`. `surfaces` is the exact subset
of `DATACLASS_FIELD`, `CONSTRUCTOR_PREIMAGE`, and `VALIDATOR_PARAMETER` on
which reflection must find the dependency.

```json
{
  "schema": "cut4.r15.frozen_contract_fields.v1",
  "contract_fields": [
    ["PrivatePlan", "source_snapshot", "DIGEST", "SourceSnapshot", "ONE", "SCALAR", ["DATACLASS_FIELD", "CONSTRUCTOR_PREIMAGE", "VALIDATOR_PARAMETER"]],
    ["PredicateEvidence", "source_snapshot", "DIGEST", "SourceSnapshot", "ONE", "SCALAR", ["DATACLASS_FIELD", "CONSTRUCTOR_PREIMAGE", "VALIDATOR_PARAMETER"]],
    ["BaseRequestIntent", "prior_envelope", "FK", "PriorEnvelope", "ONE", "SCALAR", ["DATACLASS_FIELD", "CONSTRUCTOR_PREIMAGE", "VALIDATOR_PARAMETER"]],
    ["BaseRequestIntent", "private_plan", "FK", "PrivatePlan", "ONE", "SCALAR", ["DATACLASS_FIELD", "CONSTRUCTOR_PREIMAGE", "VALIDATOR_PARAMETER"]],
    ["BaseRequestIntent", "predicate_evidence", "FK", "PredicateEvidence", "ONE", "SCALAR", ["DATACLASS_FIELD", "CONSTRUCTOR_PREIMAGE", "VALIDATOR_PARAMETER"]],
    ["RequestDigest", "base_request_intent", "PREIMAGE", "BaseRequestIntent", "ONE", "SCALAR", ["CONSTRUCTOR_PREIMAGE", "VALIDATOR_PARAMETER"]],
    ["JournalSnapshotAuthority", "phase_io_authority", "FK", "PhaseIOAuthority", "ONE", "SCALAR", ["DATACLASS_FIELD", "CONSTRUCTOR_PREIMAGE", "VALIDATOR_PARAMETER"]],
    ["JournalSnapshotAuthority", "request_digest", "DIGEST", "RequestDigest", "ONE", "SCALAR", ["DATACLASS_FIELD", "VALIDATOR_PARAMETER"]],
    ["AttemptAllocation", "journal_snapshot", "PREIMAGE", "JournalSnapshotAuthority", "ONE", "SCALAR", ["DATACLASS_FIELD", "CONSTRUCTOR_PREIMAGE", "VALIDATOR_PARAMETER"]],
    ["AttemptAllocation", "request_digest", "DIGEST", "RequestDigest", "ONE", "SCALAR", ["DATACLASS_FIELD", "CONSTRUCTOR_PREIMAGE", "VALIDATOR_PARAMETER"]],
    ["InvocationRecord", "attempt_allocation", "FK", "AttemptAllocation", "ONE", "SCALAR", ["DATACLASS_FIELD", "CONSTRUCTOR_PREIMAGE", "VALIDATOR_PARAMETER"]],
    ["InvocationRecord", "private_plan", "FK", "PrivatePlan", "ONE", "SCALAR", ["DATACLASS_FIELD", "CONSTRUCTOR_PREIMAGE", "VALIDATOR_PARAMETER"]],
    ["InvocationRecord", "predicate_evidence", "FK", "PredicateEvidence", "ONE", "SCALAR", ["DATACLASS_FIELD", "CONSTRUCTOR_PREIMAGE", "VALIDATOR_PARAMETER"]],
    ["InvocationRecord", "source_snapshot", "DIGEST", "SourceSnapshot", "ONE", "SCALAR", ["DATACLASS_FIELD", "CONSTRUCTOR_PREIMAGE", "VALIDATOR_PARAMETER"]],
    ["PayloadRecord", "invocation", "FK", "InvocationRecord", "ONE", "SCALAR", ["DATACLASS_FIELD", "CONSTRUCTOR_PREIMAGE", "VALIDATOR_PARAMETER"]],
    ["PayloadRecord", "private_plan", "FK", "PrivatePlan", "ONE", "SCALAR", ["DATACLASS_FIELD", "CONSTRUCTOR_PREIMAGE", "VALIDATOR_PARAMETER"]],
    ["ExplicitZeroProof", "request_digest", "DIGEST", "RequestDigest", "ONE", "SCALAR", ["DATACLASS_FIELD", "CONSTRUCTOR_PREIMAGE", "VALIDATOR_PARAMETER"]],
    ["ExplicitZeroProof", "attempt_allocation", "FK", "AttemptAllocation", "ONE", "SCALAR", ["DATACLASS_FIELD", "CONSTRUCTOR_PREIMAGE", "VALIDATOR_PARAMETER"]],
    ["ExplicitZeroProof", "invocation", "FK", "InvocationRecord", "ONE", "SCALAR", ["DATACLASS_FIELD", "CONSTRUCTOR_PREIMAGE", "VALIDATOR_PARAMETER"]],
    ["ExplicitZeroProof", "private_plan", "FK", "PrivatePlan", "ONE", "SCALAR", ["DATACLASS_FIELD", "CONSTRUCTOR_PREIMAGE", "VALIDATOR_PARAMETER"]],
    ["ExplicitZeroProof", "predicate_evidence", "FK", "PredicateEvidence", "ONE", "SCALAR", ["DATACLASS_FIELD", "CONSTRUCTOR_PREIMAGE", "VALIDATOR_PARAMETER"]],
    ["ProviderReceipt", "invocation", "FK", "InvocationRecord", "ONE", "SCALAR", ["DATACLASS_FIELD", "CONSTRUCTOR_PREIMAGE", "VALIDATOR_PARAMETER"]],
    ["ProviderReceipt", "private_plan", "FK", "PrivatePlan", "ONE", "SCALAR", ["DATACLASS_FIELD", "CONSTRUCTOR_PREIMAGE", "VALIDATOR_PARAMETER"]],
    ["ProviderReceipt", "predicate_evidence", "FK", "PredicateEvidence", "ONE", "SCALAR", ["DATACLASS_FIELD", "CONSTRUCTOR_PREIMAGE", "VALIDATOR_PARAMETER"]],
    ["ProviderReceipt", "payload_records", "ROSTER", "PayloadRecord", "MANY", "DECLARED_ORDER", ["DATACLASS_FIELD", "CONSTRUCTOR_PREIMAGE", "VALIDATOR_PARAMETER"]],
    ["ProviderReceipt", "explicit_zero_proof", "FK", "ExplicitZeroProof", "ZERO_OR_ONE", "SCALAR", ["DATACLASS_FIELD", "CONSTRUCTOR_PREIMAGE", "VALIDATOR_PARAMETER"]],
    ["ProviderPrivateV4", "provider_receipt", "FK", "ProviderReceipt", "ONE", "SCALAR", ["DATACLASS_FIELD", "CONSTRUCTOR_PREIMAGE", "VALIDATOR_PARAMETER"]],
    ["ProviderPrivateV4", "payload_records", "ROSTER", "PayloadRecord", "MANY", "DECLARED_ORDER", ["DATACLASS_FIELD", "CONSTRUCTOR_PREIMAGE", "VALIDATOR_PARAMETER"]],
    ["ProviderPrivateV4", "private_plan", "FK", "PrivatePlan", "ONE", "SCALAR", ["DATACLASS_FIELD", "CONSTRUCTOR_PREIMAGE", "VALIDATOR_PARAMETER"]],
    ["NormalizerExecutionEvidence", "payload", "FK", "PayloadRecord", "ONE", "SCALAR", ["DATACLASS_FIELD", "CONSTRUCTOR_PREIMAGE", "VALIDATOR_PARAMETER"]],
    ["NormalizerExecutionEvidence", "invocation", "FK", "InvocationRecord", "ONE", "SCALAR", ["DATACLASS_FIELD", "CONSTRUCTOR_PREIMAGE", "VALIDATOR_PARAMETER"]],
    ["NormalizerExecutionEvidence", "provider_receipt", "FK", "ProviderReceipt", "ONE", "SCALAR", ["DATACLASS_FIELD", "CONSTRUCTOR_PREIMAGE", "VALIDATOR_PARAMETER"]],
    ["NormalizerExecutionEvidence", "private_plan", "FK", "PrivatePlan", "ONE", "SCALAR", ["DATACLASS_FIELD", "CONSTRUCTOR_PREIMAGE", "VALIDATOR_PARAMETER"]],
    ["NormalizedSemanticRow", "normalizer_evidence", "FK", "NormalizerExecutionEvidence", "ONE", "SCALAR", ["DATACLASS_FIELD", "CONSTRUCTOR_PREIMAGE", "VALIDATOR_PARAMETER"]],
    ["NormalizedSemanticRow", "payload", "FK", "PayloadRecord", "ONE", "SCALAR", ["DATACLASS_FIELD", "CONSTRUCTOR_PREIMAGE", "VALIDATOR_PARAMETER"]],
    ["NormalizedSemanticRow", "provider_receipt", "FK", "ProviderReceipt", "ONE", "SCALAR", ["DATACLASS_FIELD", "CONSTRUCTOR_PREIMAGE", "VALIDATOR_PARAMETER"]],
    ["NormalizedSemanticRow", "private_plan", "FK", "PrivatePlan", "ONE", "SCALAR", ["DATACLASS_FIELD", "CONSTRUCTOR_PREIMAGE", "VALIDATOR_PARAMETER"]],
    ["NormalizerReceipt", "normalizer_evidence", "FK", "NormalizerExecutionEvidence", "ONE", "SCALAR", ["DATACLASS_FIELD", "CONSTRUCTOR_PREIMAGE", "VALIDATOR_PARAMETER"]],
    ["NormalizerReceipt", "normalized_rows", "ROSTER", "NormalizedSemanticRow", "MANY", "CANONICAL_SORT", ["DATACLASS_FIELD", "CONSTRUCTOR_PREIMAGE", "VALIDATOR_PARAMETER"]],
    ["NormalizerOutcome", "normalizer_receipt", "FK", "NormalizerReceipt", "ONE", "SCALAR", ["DATACLASS_FIELD", "CONSTRUCTOR_PREIMAGE", "VALIDATOR_PARAMETER"]],
    ["NormalizerOutcome", "normalized_rows", "ROSTER", "NormalizedSemanticRow", "MANY", "CANONICAL_SORT", ["DATACLASS_FIELD", "CONSTRUCTOR_PREIMAGE", "VALIDATOR_PARAMETER"]],
    ["NormalizerOutcome", "payload", "FK", "PayloadRecord", "ONE", "SCALAR", ["DATACLASS_FIELD", "CONSTRUCTOR_PREIMAGE", "VALIDATOR_PARAMETER"]],
    ["ExecutionEvidence", "provider_receipt", "FK", "ProviderReceipt", "ONE", "SCALAR", ["DATACLASS_FIELD", "CONSTRUCTOR_PREIMAGE", "VALIDATOR_PARAMETER"]],
    ["ExecutionEvidence", "normalizer_outcomes", "ROSTER", "NormalizerOutcome", "MANY", "CANONICAL_SORT", ["DATACLASS_FIELD", "CONSTRUCTOR_PREIMAGE", "VALIDATOR_PARAMETER"]],
    ["ExecutionEvidence", "normalized_rows", "ROSTER", "NormalizedSemanticRow", "MANY", "CANONICAL_SORT", ["DATACLASS_FIELD", "CONSTRUCTOR_PREIMAGE", "VALIDATOR_PARAMETER"]],
    ["ExecutionEvidence", "invocation", "FK", "InvocationRecord", "ONE", "SCALAR", ["DATACLASS_FIELD", "CONSTRUCTOR_PREIMAGE", "VALIDATOR_PARAMETER"]],
    ["QueryReceipt", "execution_evidence", "FK", "ExecutionEvidence", "ONE", "SCALAR", ["DATACLASS_FIELD", "CONSTRUCTOR_PREIMAGE", "VALIDATOR_PARAMETER"]],
    ["QueryReceipt", "request_digest", "DIGEST", "RequestDigest", "ONE", "SCALAR", ["DATACLASS_FIELD", "CONSTRUCTOR_PREIMAGE", "VALIDATOR_PARAMETER"]],
    ["QueryReceipt", "provider_receipt", "FK", "ProviderReceipt", "ONE", "SCALAR", ["DATACLASS_FIELD", "CONSTRUCTOR_PREIMAGE", "VALIDATOR_PARAMETER"]],
    ["TerminalEnvelope", "request_digest", "DIGEST", "RequestDigest", "ONE", "SCALAR", ["DATACLASS_FIELD", "CONSTRUCTOR_PREIMAGE", "VALIDATOR_PARAMETER"]],
    ["TerminalEnvelope", "attempt_allocation", "FK", "AttemptAllocation", "ONE", "SCALAR", ["DATACLASS_FIELD", "CONSTRUCTOR_PREIMAGE", "VALIDATOR_PARAMETER"]],
    ["TerminalEnvelope", "invocation", "FK", "InvocationRecord", "ONE", "SCALAR", ["DATACLASS_FIELD", "CONSTRUCTOR_PREIMAGE", "VALIDATOR_PARAMETER"]],
    ["TerminalEnvelope", "private_plan", "FK", "PrivatePlan", "ONE", "SCALAR", ["DATACLASS_FIELD", "CONSTRUCTOR_PREIMAGE", "VALIDATOR_PARAMETER"]],
    ["TerminalEnvelope", "provider_receipt", "FK", "ProviderReceipt", "ONE", "SCALAR", ["DATACLASS_FIELD", "CONSTRUCTOR_PREIMAGE", "VALIDATOR_PARAMETER"]],
    ["TerminalEnvelope", "provider_private_rows", "ROSTER", "ProviderPrivateV4", "MANY", "CANONICAL_SORT", ["DATACLASS_FIELD", "CONSTRUCTOR_PREIMAGE", "VALIDATOR_PARAMETER"]],
    ["TerminalEnvelope", "normalizer_outcomes", "ROSTER", "NormalizerOutcome", "MANY", "CANONICAL_SORT", ["DATACLASS_FIELD", "CONSTRUCTOR_PREIMAGE", "VALIDATOR_PARAMETER"]],
    ["TerminalEnvelope", "normalized_rows", "ROSTER", "NormalizedSemanticRow", "MANY", "CANONICAL_SORT", ["DATACLASS_FIELD", "CONSTRUCTOR_PREIMAGE", "VALIDATOR_PARAMETER"]],
    ["TerminalEnvelope", "execution_evidence", "FK", "ExecutionEvidence", "ONE", "SCALAR", ["DATACLASS_FIELD", "CONSTRUCTOR_PREIMAGE", "VALIDATOR_PARAMETER"]],
    ["TerminalEnvelope", "query_receipt", "FK", "QueryReceipt", "ONE", "SCALAR", ["DATACLASS_FIELD", "CONSTRUCTOR_PREIMAGE", "VALIDATOR_PARAMETER"]],
    ["TerminalJournalRecord", "journal_snapshot", "PREIMAGE", "JournalSnapshotAuthority", "ONE", "SCALAR", ["DATACLASS_FIELD", "CONSTRUCTOR_PREIMAGE", "VALIDATOR_PARAMETER"]],
    ["TerminalJournalRecord", "terminal_envelope", "EMBEDDED", "TerminalEnvelope", "ONE", "SCALAR", ["DATACLASS_FIELD", "CONSTRUCTOR_PREIMAGE", "VALIDATOR_PARAMETER"]],
    ["AbortedUnobservedRecord", "journal_snapshot", "PREIMAGE", "JournalSnapshotAuthority", "ONE", "SCALAR", ["DATACLASS_FIELD", "CONSTRUCTOR_PREIMAGE", "VALIDATOR_PARAMETER"]],
    ["AbortedUnobservedRecord", "request_digest", "DIGEST", "RequestDigest", "ONE", "SCALAR", ["DATACLASS_FIELD", "CONSTRUCTOR_PREIMAGE", "VALIDATOR_PARAMETER"]],
    ["AbortedUnobservedRecord", "attempt_allocation", "FK", "AttemptAllocation", "ONE", "SCALAR", ["DATACLASS_FIELD", "CONSTRUCTOR_PREIMAGE", "VALIDATOR_PARAMETER"]],
    ["AbortedUnobservedRecord", "invocation", "FK", "InvocationRecord", "ONE", "SCALAR", ["DATACLASS_FIELD", "CONSTRUCTOR_PREIMAGE", "VALIDATOR_PARAMETER"]],
    ["JournalRecord", "attempt_allocation", "EMBEDDED", "AttemptAllocation", "ZERO_OR_ONE", "SCALAR", ["DATACLASS_FIELD", "VALIDATOR_PARAMETER"]],
    ["JournalRecord", "invocation", "EMBEDDED", "InvocationRecord", "ZERO_OR_ONE", "SCALAR", ["DATACLASS_FIELD", "VALIDATOR_PARAMETER"]],
    ["JournalRecord", "aborted_unobserved", "EMBEDDED", "AbortedUnobservedRecord", "ZERO_OR_ONE", "SCALAR", ["DATACLASS_FIELD", "VALIDATOR_PARAMETER"]],
    ["JournalRecord", "terminal_record", "EMBEDDED", "TerminalJournalRecord", "ZERO_OR_ONE", "SCALAR", ["DATACLASS_FIELD", "VALIDATOR_PARAMETER"]],
    ["JournalRecord", "publication_ack", "EMBEDDED", "PublicationAckJournalRecord", "ZERO_OR_ONE", "SCALAR", ["DATACLASS_FIELD", "VALIDATOR_PARAMETER"]],
    ["JournalState", "prior_snapshot", "PREIMAGE", "JournalSnapshotAuthority", "ONE", "SCALAR", ["DATACLASS_FIELD", "CONSTRUCTOR_PREIMAGE", "VALIDATOR_PARAMETER"]],
    ["JournalState", "appended_record", "EMBEDDED", "JournalRecord", "ONE", "SCALAR", ["DATACLASS_FIELD", "CONSTRUCTOR_PREIMAGE", "VALIDATOR_PARAMETER"]],
    ["CommittedPublicationReceipt", "phase_io_authority", "FK", "PhaseIOAuthority", "ONE", "SCALAR", ["DATACLASS_FIELD", "CONSTRUCTOR_PREIMAGE", "VALIDATOR_PARAMETER"]],
    ["CommittedPublicationReceipt", "terminal_record", "FK", "TerminalJournalRecord", "ONE", "SCALAR", ["DATACLASS_FIELD", "CONSTRUCTOR_PREIMAGE", "VALIDATOR_PARAMETER"]],
    ["CommittedPublicationReceipt", "public_output_bytes", "ROSTER", "PublicOutputBytes", "MANY", "CANONICAL_SORT", ["DATACLASS_FIELD", "CONSTRUCTOR_PREIMAGE", "VALIDATOR_PARAMETER"]],
    ["PublicationLink", "terminal_record", "FK", "TerminalJournalRecord", "ONE", "SCALAR", ["DATACLASS_FIELD", "CONSTRUCTOR_PREIMAGE", "VALIDATOR_PARAMETER"]],
    ["PublicationLink", "committed_receipt", "FK", "CommittedPublicationReceipt", "ONE", "SCALAR", ["DATACLASS_FIELD", "CONSTRUCTOR_PREIMAGE", "VALIDATOR_PARAMETER"]],
    ["PublicationLink", "public_output_bytes", "ROSTER", "PublicOutputBytes", "MANY", "CANONICAL_SORT", ["DATACLASS_FIELD", "CONSTRUCTOR_PREIMAGE", "VALIDATOR_PARAMETER"]],
    ["PublicationAckJournalRecord", "journal_snapshot", "PREIMAGE", "JournalSnapshotAuthority", "ONE", "SCALAR", ["DATACLASS_FIELD", "CONSTRUCTOR_PREIMAGE", "VALIDATOR_PARAMETER"]],
    ["PublicationAckJournalRecord", "publication_link", "FK", "PublicationLink", "ONE", "SCALAR", ["DATACLASS_FIELD", "CONSTRUCTOR_PREIMAGE", "VALIDATOR_PARAMETER"]],
    ["PublicationAckJournalRecord", "committed_receipt", "FK", "CommittedPublicationReceipt", "ONE", "SCALAR", ["DATACLASS_FIELD", "CONSTRUCTOR_PREIMAGE", "VALIDATOR_PARAMETER"]],
    ["DiffSide", "private_plan", "FK", "PrivatePlan", "ONE", "SCALAR", ["DATACLASS_FIELD", "CONSTRUCTOR_PREIMAGE", "VALIDATOR_PARAMETER"]],
    ["DiffSide", "provider_receipt", "FK", "ProviderReceipt", "ONE", "SCALAR", ["DATACLASS_FIELD", "CONSTRUCTOR_PREIMAGE", "VALIDATOR_PARAMETER"]],
    ["DiffSide", "provider_private_rows", "ROSTER", "ProviderPrivateV4", "MANY", "CANONICAL_SORT", ["DATACLASS_FIELD", "CONSTRUCTOR_PREIMAGE", "VALIDATOR_PARAMETER"]],
    ["DiffSide", "normalizer_outcomes", "ROSTER", "NormalizerOutcome", "MANY", "CANONICAL_SORT", ["DATACLASS_FIELD", "CONSTRUCTOR_PREIMAGE", "VALIDATOR_PARAMETER"]],
    ["DiffSide", "normalized_rows", "ROSTER", "NormalizedSemanticRow", "MANY", "CANONICAL_SORT", ["DATACLASS_FIELD", "CONSTRUCTOR_PREIMAGE", "VALIDATOR_PARAMETER"]],
    ["DiffRow", "expected_side", "EMBEDDED", "DiffSide", "ONE", "SCALAR", ["DATACLASS_FIELD", "CONSTRUCTOR_PREIMAGE", "VALIDATOR_PARAMETER"]],
    ["DiffRow", "observed_side", "EMBEDDED", "DiffSide", "ONE", "SCALAR", ["DATACLASS_FIELD", "CONSTRUCTOR_PREIMAGE", "VALIDATOR_PARAMETER"]],
    ["M4", "private_plan", "FK", "PrivatePlan", "ONE", "SCALAR", ["DATACLASS_FIELD", "CONSTRUCTOR_PREIMAGE", "VALIDATOR_PARAMETER"]],
    ["M4", "provider_receipt", "FK", "ProviderReceipt", "ONE", "SCALAR", ["DATACLASS_FIELD", "CONSTRUCTOR_PREIMAGE", "VALIDATOR_PARAMETER"]],
    ["M4", "provider_private_rows", "ROSTER", "ProviderPrivateV4", "MANY", "CANONICAL_SORT", ["DATACLASS_FIELD", "CONSTRUCTOR_PREIMAGE", "VALIDATOR_PARAMETER"]],
    ["M4", "normalizer_evidence", "ROSTER", "NormalizerExecutionEvidence", "MANY", "CANONICAL_SORT", ["DATACLASS_FIELD", "CONSTRUCTOR_PREIMAGE", "VALIDATOR_PARAMETER"]],
    ["M4", "normalizer_receipts", "ROSTER", "NormalizerReceipt", "MANY", "CANONICAL_SORT", ["DATACLASS_FIELD", "CONSTRUCTOR_PREIMAGE", "VALIDATOR_PARAMETER"]],
    ["M4", "normalizer_outcomes", "ROSTER", "NormalizerOutcome", "MANY", "CANONICAL_SORT", ["DATACLASS_FIELD", "CONSTRUCTOR_PREIMAGE", "VALIDATOR_PARAMETER"]],
    ["M4", "normalized_rows", "ROSTER", "NormalizedSemanticRow", "MANY", "CANONICAL_SORT", ["DATACLASS_FIELD", "CONSTRUCTOR_PREIMAGE", "VALIDATOR_PARAMETER"]],
    ["M4", "diff_rows", "ROSTER", "DiffRow", "MANY", "CANONICAL_SORT", ["DATACLASS_FIELD", "CONSTRUCTOR_PREIMAGE", "VALIDATOR_PARAMETER"]],
    ["M4", "terminal_record", "FK", "TerminalJournalRecord", "ONE", "SCALAR", ["DATACLASS_FIELD", "CONSTRUCTOR_PREIMAGE", "VALIDATOR_PARAMETER"]],
    ["M4", "publication_link", "FK", "PublicationLink", "ONE", "SCALAR", ["DATACLASS_FIELD", "CONSTRUCTOR_PREIMAGE", "VALIDATOR_PARAMETER"]],
    ["M4", "committed_receipt", "FK", "CommittedPublicationReceipt", "ONE", "SCALAR", ["DATACLASS_FIELD", "CONSTRUCTOR_PREIMAGE", "VALIDATOR_PARAMETER"]],
    ["M4", "public_output_bytes", "ROSTER", "PublicOutputBytes", "MANY", "CANONICAL_SORT", ["DATACLASS_FIELD", "CONSTRUCTOR_PREIMAGE", "VALIDATOR_PARAMETER"]],
    ["R4", "m4", "EMBEDDED", "M4", "ONE", "SCALAR", ["DATACLASS_FIELD", "CONSTRUCTOR_PREIMAGE", "VALIDATOR_PARAMETER"]],
    ["CompletionReceipt", "m4", "FK", "M4", "ONE", "SCALAR", ["DATACLASS_FIELD", "CONSTRUCTOR_PREIMAGE", "VALIDATOR_PARAMETER"]],
    ["CompletionReceipt", "r4", "FK", "R4", "ONE", "SCALAR", ["DATACLASS_FIELD", "CONSTRUCTOR_PREIMAGE", "VALIDATOR_PARAMETER"]],
    ["CompletionReceipt", "terminal_record", "FK", "TerminalJournalRecord", "ONE", "SCALAR", ["DATACLASS_FIELD", "CONSTRUCTOR_PREIMAGE", "VALIDATOR_PARAMETER"]],
    ["CompletionReceipt", "publication_link", "FK", "PublicationLink", "ONE", "SCALAR", ["DATACLASS_FIELD", "CONSTRUCTOR_PREIMAGE", "VALIDATOR_PARAMETER"]],
    ["CompletionReceipt", "committed_receipt", "FK", "CommittedPublicationReceipt", "ONE", "SCALAR", ["DATACLASS_FIELD", "CONSTRUCTOR_PREIMAGE", "VALIDATOR_PARAMETER"]],
    ["CompletionReceipt", "public_output_bytes", "ROSTER", "PublicOutputBytes", "MANY", "CANONICAL_SORT", ["DATACLASS_FIELD", "CONSTRUCTOR_PREIMAGE", "VALIDATOR_PARAMETER"]],
    ["CompletionReceipt", "phase_io_authority", "FK", "PhaseIOAuthority", "ONE", "SCALAR", ["DATACLASS_FIELD", "CONSTRUCTOR_PREIMAGE", "VALIDATOR_PARAMETER"]]
  ]
}
```


No R13 or R14 envelope, receipt, test, transcript, or model result can satisfy
an R15 FK. Historical hashes may occur only in a non-authoritative history
section.

## 9. Gate T: closed transport and time-independent gate order

### 9.1 Exact subject/envelope plan

`RootOrchestrationReceipt.transport_plan` is byte-identical to the following
ordered rows. `predecessors` names immediate subject envelopes, not subject
files. The root receipt itself is sequence zero and is not self-enveloped.

```json
{
  "schema": "cut4.r15.transport_plan.v1",
  "rows": [
    [1, "ARCHITECTURE_CONTRACT", "P_ARCH_AUTHOR", "architecture/cut4-transactional-recon-publication-r15-preimplementation-contract.md", "review_fixtures/cut4_transactional_recon_publication_r15_transport/01_architecture_contract.json", []],
    [2, "ARCHITECTURE_AUTHOR_RECEIPT", "P_ARCH_AUTHOR", "review_fixtures/cut4_transactional_recon_publication_r15_contract_author_receipt_20260810.md", "review_fixtures/cut4_transactional_recon_publication_r15_transport/02_architecture_author_receipt.json", ["ARCHITECTURE_CONTRACT"]],
    [3, "ARCHITECTURE_REVIEW", "P_ARCH_REVIEWER", "review_fixtures/cut4_transactional_recon_publication_r15_architecture_independent_review_20260810.md", "review_fixtures/cut4_transactional_recon_publication_r15_transport/03_architecture_review.json", ["ARCHITECTURE_CONTRACT", "ARCHITECTURE_AUTHOR_RECEIPT"]],
    [4, "RED_ORACLE_PACKAGE", "P_RED_AUTHOR", "review_fixtures/cut4_transactional_recon_publication_r15_red_oracle.py", "review_fixtures/cut4_transactional_recon_publication_r15_transport/04_red_oracle_package.json", ["ARCHITECTURE_REVIEW"]],
    [5, "RED_TEST", "P_RED_AUTHOR", "tests/test_cut4_transactional_recon_publication_r15_preimplementation.py", "review_fixtures/cut4_transactional_recon_publication_r15_transport/05_red_test.json", ["ARCHITECTURE_REVIEW", "RED_ORACLE_PACKAGE"]],
    [6, "RED_FAILED_RUN", "P_RED_AUTHOR", "review_fixtures/cut4_transactional_recon_publication_r15_red_failed_run_20260810.json", "review_fixtures/cut4_transactional_recon_publication_r15_transport/06_red_failed_run.json", ["ARCHITECTURE_REVIEW", "RED_TEST"]],
    [7, "RED_AUTHOR_RECEIPT", "P_RED_AUTHOR", "review_fixtures/cut4_transactional_recon_publication_r15_red_author_receipt_20260810.json", "review_fixtures/cut4_transactional_recon_publication_r15_transport/07_red_author_receipt.json", ["RED_ORACLE_PACKAGE", "RED_TEST", "RED_FAILED_RUN"]],
    [8, "NEGATIVE_PROOF_RECEIPT", "P_NEGATIVE_VERIFIER", "review_fixtures/cut4_transactional_recon_publication_r15_independent_negative_proof_receipt_20260810.json", "review_fixtures/cut4_transactional_recon_publication_r15_transport/08_negative_proof_receipt.json", ["RED_ORACLE_PACKAGE", "RED_TEST", "RED_FAILED_RUN"]],
    [9, "RED_REVIEW", "P_RED_REVIEWER", "review_fixtures/cut4_transactional_recon_publication_r15_red_independent_review_20260810.md", "review_fixtures/cut4_transactional_recon_publication_r15_transport/09_red_review.json", ["ARCHITECTURE_REVIEW", "RED_AUTHOR_RECEIPT", "NEGATIVE_PROOF_RECEIPT"]],
    [10, "MODEL", "P_MODEL_IMPLEMENTER", "review_fixtures/cut4_transactional_recon_publication_r15_reference_model.py", "review_fixtures/cut4_transactional_recon_publication_r15_transport/10_model.json", ["RED_REVIEW"]],
    [11, "GREEN_AUTHOR_RECEIPT", "P_MODEL_IMPLEMENTER", "review_fixtures/cut4_transactional_recon_publication_r15_green_author_receipt_20260810.json", "review_fixtures/cut4_transactional_recon_publication_r15_transport/11_green_author_receipt.json", ["RED_REVIEW", "MODEL", "RED_TEST"]],
    [12, "GREEN_REVIEW", "P_GREEN_REVIEWER", "review_fixtures/cut4_transactional_recon_publication_r15_green_independent_review_20260810.md", "review_fixtures/cut4_transactional_recon_publication_r15_transport/12_green_review.json", ["RED_REVIEW", "MODEL", "GREEN_AUTHOR_RECEIPT"]]
  ]
}
```

The plan has exactly 12 subject nodes and 24 unique immediate predecessor
edges. Every predecessor ordinal is lower than its consumer ordinal, so Kahn
elimination leaves zero nodes.

The required task IDs for `P_ARCH_AUTHOR`, `P_ARCH_REVIEWER`, `P_RED_AUTHOR`,
`P_NEGATIVE_VERIFIER`, `P_RED_REVIEWER`, `P_MODEL_IMPLEMENTER`, and
`P_GREEN_REVIEWER` are seven pairwise-distinct nonempty values assigned by the
root orchestrator. In particular, architecture author/reviewer, RED
author/reviewer, RED author/negative verifier, model implementer/GREEN
reviewer, and every reviewer/reviewed producer task ID must differ. A review
envelope joins the exact producer task IDs it reviews and rejects equality.

### 9.2 Closed root and envelope schemas

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "cut4.r15.transport.schemas.v1",
  "oneOf": [
    {"$ref": "#/$defs/RootOrchestrationReceipt"},
    {"$ref": "#/$defs/TransportEnvelope"}
  ],
  "$defs": {
    "Hex64": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
    "TaskId": {"type": "string", "pattern": "^task_[A-Za-z0-9_-]{8,128}$"},
    "Role": {"enum": ["P_ROOT_ORCHESTRATOR", "P_ARCH_AUTHOR", "P_ARCH_REVIEWER", "P_RED_AUTHOR", "P_NEGATIVE_VERIFIER", "P_RED_REVIEWER", "P_MODEL_IMPLEMENTER", "P_GREEN_REVIEWER"]},
    "SubjectKind": {"enum": ["ARCHITECTURE_CONTRACT", "ARCHITECTURE_AUTHOR_RECEIPT", "ARCHITECTURE_REVIEW", "RED_ORACLE_PACKAGE", "RED_TEST", "RED_FAILED_RUN", "RED_AUTHOR_RECEIPT", "NEGATIVE_PROOF_RECEIPT", "RED_REVIEW", "MODEL", "GREEN_AUTHOR_RECEIPT", "GREEN_REVIEW"]},
    "TaskAssignment": {
      "type": "object", "additionalProperties": false,
      "required": ["task_id", "role", "transport_public_key_fingerprint", "allowed_subject_kinds"],
      "properties": {
        "task_id": {"$ref": "#/$defs/TaskId"},
        "role": {"$ref": "#/$defs/Role"},
        "transport_public_key_fingerprint": {"$ref": "#/$defs/Hex64"},
        "allowed_subject_kinds": {"type": "array", "minItems": 1, "uniqueItems": true, "items": {"$ref": "#/$defs/SubjectKind"}}
      }
    },
    "RootOrchestrationReceipt": {
      "type": "object", "additionalProperties": false,
      "required": ["schema", "campaign_id", "sequence_zero", "root_task_id", "root_role", "root_public_key_fingerprint", "task_assignments", "transport_plan", "transport_plan_digest", "receipt_digest", "signature_algorithm", "signature_base64"],
      "properties": {
        "schema": {"const": "cut4.r15.root_orchestration_receipt.v1"},
        "campaign_id": {"type": "string", "pattern": "^cut4-r15-[A-Za-z0-9_-]{8,128}$"},
        "sequence_zero": {"const": 0},
        "root_task_id": {"$ref": "#/$defs/TaskId"},
        "root_role": {"const": "P_ROOT_ORCHESTRATOR"},
        "root_public_key_fingerprint": {"$ref": "#/$defs/Hex64"},
        "task_assignments": {"type": "array", "minItems": 8, "uniqueItems": true, "items": {"$ref": "#/$defs/TaskAssignment"}},
        "transport_plan": {"type": "array", "minItems": 12, "maxItems": 12, "items": {"type": "array", "minItems": 6, "maxItems": 6}},
        "transport_plan_digest": {"$ref": "#/$defs/Hex64"},
        "receipt_digest": {"$ref": "#/$defs/Hex64"},
        "signature_algorithm": {"const": "Ed25519"},
        "signature_base64": {"type": "string", "pattern": "^[A-Za-z0-9+/]{86}==$"}
      }
    },
    "TransportEnvelope": {
      "type": "object", "additionalProperties": false,
      "required": ["schema", "campaign_id", "sequence_ordinal", "subject_kind", "subject_identity", "subject_bytes_base64", "subject_byte_size", "subject_sha256", "producer_task_id", "producer_role", "producer_transport_key_fingerprint", "reviewed_producer_task_ids", "decision", "predecessor_envelope_digests", "root_orchestration_receipt_digest", "transport_plan_digest", "envelope_digest", "signature_algorithm", "signature_base64"],
      "properties": {
        "schema": {"const": "cut4.r15.transport_envelope.v1"},
        "campaign_id": {"type": "string", "pattern": "^cut4-r15-[A-Za-z0-9_-]{8,128}$"},
        "sequence_ordinal": {"type": "integer", "minimum": 1, "maximum": 12},
        "subject_kind": {"$ref": "#/$defs/SubjectKind"},
        "subject_identity": {"type": "string", "minLength": 1},
        "subject_bytes_base64": {"type": "string", "pattern": "^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$"},
        "subject_byte_size": {"type": "integer", "minimum": 1},
        "subject_sha256": {"$ref": "#/$defs/Hex64"},
        "producer_task_id": {"$ref": "#/$defs/TaskId"},
        "producer_role": {"$ref": "#/$defs/Role"},
        "producer_transport_key_fingerprint": {"$ref": "#/$defs/Hex64"},
        "reviewed_producer_task_ids": {"type": "array", "uniqueItems": true, "items": {"$ref": "#/$defs/TaskId"}},
        "decision": {"enum": ["NOT_APPLICABLE", "ACCEPT", "REPAIR"]},
        "predecessor_envelope_digests": {"type": "array", "uniqueItems": true, "items": {"$ref": "#/$defs/Hex64"}},
        "root_orchestration_receipt_digest": {"$ref": "#/$defs/Hex64"},
        "transport_plan_digest": {"$ref": "#/$defs/Hex64"},
        "envelope_digest": {"$ref": "#/$defs/Hex64"},
        "signature_algorithm": {"const": "Ed25519"},
        "signature_base64": {"type": "string", "pattern": "^[A-Za-z0-9+/]{86}==$"}
      }
    }
  }
}
```

### 9.3 Canonical bytes, signatures, joins, and claim ceiling

`CJ(x)` is RFC 8785 JSON Canonicalization Scheme over Unicode scalar strings;
input strings must be valid UTF-8 and NFC before construction. `H(x)` is
ordinary SHA-256. `B64(x)` is RFC 4648 standard base64 with required padding.
Literal prefixes include their trailing NUL byte.

```text
P_ROOT_PLAN = UTF8("cut4.r15.root.transport_plan.v1\0")
P_ROOT      = UTF8("cut4.r15.root.receipt.v1\0")
P_ENVELOPE  = UTF8("cut4.r15.transport.envelope.v1\0")
P_SIGNATURE = UTF8("cut4.r15.transport.signature.v1\0")

transport_plan_digest = H(P_ROOT_PLAN || CJ(exact transport_plan rows))
root_body = root receipt with receipt_digest/signature_base64 removed
receipt_digest = H(P_ROOT || CJ(root_body))
root_signature_message = H(P_SIGNATURE || raw32(receipt_digest))

subject_bytes = strict_B64_decode(subject_bytes_base64)
subject_byte_size = len(subject_bytes)
subject_sha256 = H(subject_bytes)
envelope_body = envelope with envelope_digest/signature_base64 removed
envelope_digest = H(P_ENVELOPE || CJ(envelope_body))
envelope_signature_message = H(P_SIGNATURE || raw32(envelope_digest))
```

The root signature is verified against a root transport key supplied by the
root orchestrator boundary. Each envelope signature is verified against the
task-bound transport key in the root receipt. Campaign, root digest, plan
digest, ordinal, subject kind/path/role, task assignment, and ordered immediate
predecessor envelope digests must equal the exact plan row. Only review kinds
may carry ACCEPT/REPAIR; all other kinds use NOT_APPLICABLE. An ACCEPT envelope
must parse its subject bytes and reproduce the decision.

Architecture review ACCEPT is required before any RED subject envelope. RED
review ACCEPT is required before the MODEL envelope. GREEN review is last.
The RED author receipt binds two exact-path model-absence snapshot manifests,
the frozen test/oracle bytes, the failed transcript, command/environment, and
the mutation vectors. These facts establish exact-path absence and transport
gate order only.

This signature chain authenticates bytes, task labels, and time-independent
predecessor order under one root transport authority. It does **not** prove
cryptographic independence of people, agents, machines, or key controllers,
and R15 makes no such claim. No-self-review is the narrower mechanically
decidable rule: the root assigns distinct task IDs and review envelopes join
and reject the reviewed producer task IDs. Off-path model preparation and
wall-clock chronology remain unobservable and are not claimed.

## 10. Gate U: dual independent byte universes and negative proof

### 10.1 Independent constructions

The RED oracle package, frozen before MODEL transport, contains two separate
implementations with no shared tokenizer, parser, candidate constructor,
classification function, or negative analyzer:

1. `A_SCHEMA_PARSER`: an ecosystem adapter parses the complete canonical byte
   vector using its deterministic grammar tables and separately emits trivia,
   invalid, and EOF coverage.
2. `B_STREAMING_PARSER`: a single-pass byte DFA/lexer plus an independent
   bounded pushdown recognizer emits the same canonical row vocabulary without
   importing or calling A.

Both receive identical immutable `SourceFile` and `BakeBinding` byte objects.
They emit separate coverage, candidate, nonsemantic-witness, debt,
classification, and edge rows and separate receipts. A third
`P_NEGATIVE_VERIFIER` task reads raw bytes plus both receipts and runs the
contract verifier without importing the future model. Any A/B disagreement is
typed `DUAL_UNIVERSE_DISAGREEMENT_DEBT`; neither `NONSEMANTIC_PROVED` nor
`PROVED_NONE` is then legal.

### 10.2 Closed universe schema

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "cut4.r15.dual_universe.schemas.v1",
  "oneOf": [
    {"$ref": "#/$defs/SourceFile"},
    {"$ref": "#/$defs/AdapterRow"},
    {"$ref": "#/$defs/RuleRow"},
    {"$ref": "#/$defs/BakeBinding"},
    {"$ref": "#/$defs/CoverageRow"},
    {"$ref": "#/$defs/CandidateRow"},
    {"$ref": "#/$defs/NonsemanticWitness"},
    {"$ref": "#/$defs/ParseDebt"},
    {"$ref": "#/$defs/ClassificationRow"},
    {"$ref": "#/$defs/EdgeRow"},
    {"$ref": "#/$defs/ParserReceipt"},
    {"$ref": "#/$defs/TotalNegativeProof"},
    {"$ref": "#/$defs/IndependentNegativeReceipt"}
  ],
  "$defs": {
    "Hex64": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
    "Parser": {"enum": ["A_SCHEMA_PARSER", "B_STREAMING_PARSER"]},
    "Disposition": {"enum": ["SEMANTIC_CANDIDATE", "NONSEMANTIC_PROVED", "PARSE_DEBT"]},
    "SourceFile": {
      "type": "object", "additionalProperties": false,
      "required": ["source_id", "canonical_identity", "ordinal", "ecosystem", "bytes_base64", "byte_size", "sha256", "source_row_digest"],
      "properties": {
        "source_id": {"type": "string", "minLength": 1},
        "canonical_identity": {"type": "string", "minLength": 1},
        "ordinal": {"type": "integer", "minimum": 0},
        "ecosystem": {"enum": ["aptos", "daml", "evm", "go", "rust", "solana", "soroban", "sui"]},
        "bytes_base64": {"type": "string"},
        "byte_size": {"type": "integer", "minimum": 0},
        "sha256": {"$ref": "#/$defs/Hex64"},
        "source_row_digest": {"$ref": "#/$defs/Hex64"}
      }
    },
    "RuleRow": {
      "type": "object", "additionalProperties": false,
      "required": ["rule_id", "input_class", "mode_id", "classification", "witness_permission", "rule_row_digest"],
      "properties": {
        "rule_id": {"type": "string", "pattern": "^rule_[a-z0-9_]+_v1$"},
        "input_class": {"enum": ["DECLARATION", "IMPORT", "CALL", "MEMBER_CALL", "PATH_LITERAL", "CONTENT_INSTRUCTION", "GRAPH_EDGE", "PROBE_EDGE", "WHITESPACE", "COMMENT", "PUNCTUATION", "NONREFERENCE_LITERAL", "INVALID_OR_UNKNOWN"]},
        "mode_id": {"enum": ["MODE_BASE", "MODE_REFERENCE", "MODE_EDGE", "MODE_NONSEMANTIC", "MODE_DEBT"]},
        "classification": {"enum": ["BASE_SEMANTIC", "REFERENCE", "EDGE", "NONSEMANTIC_PROVED", "UNRESOLVED_DEBT"]},
        "witness_permission": {"enum": ["FORBIDDEN", "REQUIRED"]},
        "rule_row_digest": {"$ref": "#/$defs/Hex64"}
      }
    },
    "AdapterRow": {
      "type": "object", "additionalProperties": false,
      "required": ["adapter_id", "ecosystem", "suffixes", "parser_a_grammar_id", "parser_b_dfa_id", "bake_slot_ids", "adapter_row_digest"],
      "properties": {
        "adapter_id": {"type": "string", "pattern": "^adapter_[a-z0-9_]+_v1$"},
        "ecosystem": {"enum": ["aptos", "daml", "evm", "go", "rust", "solana", "soroban", "sui"]},
        "suffixes": {"type": "array", "minItems": 1, "uniqueItems": true, "items": {"type": "string", "pattern": "^\\.[a-z0-9]+$"}},
        "parser_a_grammar_id": {"type": "string", "minLength": 1},
        "parser_b_dfa_id": {"type": "string", "minLength": 1},
        "bake_slot_ids": {"type": "array", "minItems": 3, "maxItems": 3, "prefixItems": [{"const": "program_facts"}, {"const": "program_facts_receipt"}, {"const": "program_facts_debt"}]},
        "adapter_row_digest": {"$ref": "#/$defs/Hex64"}
      }
    },
    "BakeBinding": {
      "type": "object", "additionalProperties": false,
      "required": ["slot_id", "identity", "bytes_base64", "byte_size", "sha256", "schema_id", "run_id", "producer_work_unit_key", "producer_contract_digest", "launch_digest", "adapter_id", "ecosystem", "semantic_digest", "binding_digest"],
      "properties": {
        "slot_id": {"enum": ["program_facts", "program_facts_receipt", "program_facts_debt"]},
        "identity": {"type": "string", "minLength": 1},
        "bytes_base64": {"type": "string"},
        "byte_size": {"type": "integer", "minimum": 0},
        "sha256": {"$ref": "#/$defs/Hex64"},
        "schema_id": {"type": "string", "minLength": 1},
        "run_id": {"type": "string", "minLength": 1},
        "producer_work_unit_key": {"type": "string", "minLength": 1},
        "producer_contract_digest": {"$ref": "#/$defs/Hex64"},
        "launch_digest": {"$ref": "#/$defs/Hex64"},
        "adapter_id": {"type": "string", "minLength": 1},
        "ecosystem": {"type": "string", "minLength": 1},
        "semantic_digest": {"$ref": "#/$defs/Hex64"},
        "binding_digest": {"$ref": "#/$defs/Hex64"}
      }
    },
    "CoverageRow": {
      "type": "object", "additionalProperties": false,
      "required": ["parser", "source_id", "ordinal", "byte_start", "byte_end", "span_sha256", "disposition", "candidate_ids", "witness_id", "debt_id", "row_digest"],
      "properties": {
        "parser": {"$ref": "#/$defs/Parser"},
        "source_id": {"type": "string", "minLength": 1},
        "ordinal": {"type": "integer", "minimum": 0},
        "byte_start": {"type": "integer", "minimum": 0},
        "byte_end": {"type": "integer", "minimum": 0},
        "span_sha256": {"$ref": "#/$defs/Hex64"},
        "disposition": {"$ref": "#/$defs/Disposition"},
        "candidate_ids": {"type": "array", "uniqueItems": true, "items": {"type": "string", "minLength": 1}},
        "witness_id": {"type": "string"},
        "debt_id": {"type": "string"},
        "row_digest": {"$ref": "#/$defs/Hex64"}
      }
    },
    "CandidateRow": {
      "type": "object", "additionalProperties": false,
      "required": ["parser", "candidate_id", "source_id", "byte_start", "byte_end", "raw_sha256", "grammar_production_id", "semantic_class", "rule_id", "mode_id", "candidate_digest"],
      "properties": {
        "parser": {"$ref": "#/$defs/Parser"},
        "candidate_id": {"type": "string", "minLength": 1},
        "source_id": {"type": "string", "minLength": 1},
        "byte_start": {"type": "integer", "minimum": 0},
        "byte_end": {"type": "integer", "minimum": 0},
        "raw_sha256": {"$ref": "#/$defs/Hex64"},
        "grammar_production_id": {"type": "string", "minLength": 1},
        "semantic_class": {"enum": ["DECLARATION", "IMPORT", "CALL", "MEMBER_CALL", "PATH_LITERAL", "CONTENT_INSTRUCTION", "GRAPH_EDGE", "PROBE_EDGE", "UNRESOLVED"]},
        "rule_id": {"type": "string", "minLength": 1},
        "mode_id": {"type": "string", "minLength": 1},
        "candidate_digest": {"$ref": "#/$defs/Hex64"}
      }
    },
    "NonsemanticWitness": {
      "type": "object", "additionalProperties": false,
      "required": ["parser", "witness_id", "source_id", "byte_start", "byte_end", "span_sha256", "grammar_production_id", "witness_class", "rule_id", "witness_digest"],
      "properties": {
        "parser": {"$ref": "#/$defs/Parser"},
        "witness_id": {"type": "string", "minLength": 1},
        "source_id": {"type": "string", "minLength": 1},
        "byte_start": {"type": "integer", "minimum": 0},
        "byte_end": {"type": "integer", "minimum": 0},
        "span_sha256": {"$ref": "#/$defs/Hex64"},
        "grammar_production_id": {"type": "string", "minLength": 1},
        "witness_class": {"enum": ["WHITESPACE", "COMMENT", "PUNCTUATION", "NONREFERENCE_LITERAL", "EMPTY_FILE"]},
        "rule_id": {"type": "string", "minLength": 1},
        "witness_digest": {"$ref": "#/$defs/Hex64"}
      }
    },
    "ParseDebt": {
      "type": "object", "additionalProperties": false,
      "required": ["parser", "debt_id", "source_id", "byte_start", "byte_end", "span_sha256", "debt_code", "debt_digest"],
      "properties": {
        "parser": {"$ref": "#/$defs/Parser"},
        "debt_id": {"type": "string", "minLength": 1},
        "source_id": {"type": "string", "minLength": 1},
        "byte_start": {"type": "integer", "minimum": 0},
        "byte_end": {"type": "integer", "minimum": 0},
        "span_sha256": {"$ref": "#/$defs/Hex64"},
        "debt_code": {"enum": ["INVALID_UTF8", "BINARY", "UNKNOWN_GRAMMAR", "UNSUPPORTED_SYNTAX", "PARSER_FAILURE", "DUAL_UNIVERSE_DISAGREEMENT_DEBT"]},
        "debt_digest": {"$ref": "#/$defs/Hex64"}
      }
    },
    "ClassificationRow": {
      "type": "object", "additionalProperties": false,
      "required": ["parser", "candidate_id", "rule_id", "mode_id", "classification", "row_digest"],
      "properties": {
        "parser": {"$ref": "#/$defs/Parser"},
        "candidate_id": {"type": "string", "minLength": 1},
        "rule_id": {"type": "string", "minLength": 1},
        "mode_id": {"type": "string", "minLength": 1},
        "classification": {"enum": ["BASE_SEMANTIC", "REFERENCE", "EDGE", "UNRESOLVED_DEBT"]},
        "row_digest": {"$ref": "#/$defs/Hex64"}
      }
    },
    "EdgeRow": {
      "type": "object", "additionalProperties": false,
      "required": ["parser", "edge_id", "source_candidate_id", "target_identity", "edge_class", "evidence_span_sha256", "edge_digest"],
      "properties": {
        "parser": {"$ref": "#/$defs/Parser"},
        "edge_id": {"type": "string", "minLength": 1},
        "source_candidate_id": {"type": "string", "minLength": 1},
        "target_identity": {"type": "string", "minLength": 1},
        "edge_class": {"enum": ["IMPORT", "CALL", "MEMBER_CALL", "PATH_REFERENCE", "CONTENT_REFERENCE", "GRAPH", "PROBE", "UNRESOLVED"]},
        "evidence_span_sha256": {"$ref": "#/$defs/Hex64"},
        "edge_digest": {"$ref": "#/$defs/Hex64"}
      }
    },
    "ParserReceipt": {
      "type": "object", "additionalProperties": false,
      "required": ["parser", "package_id", "package_version", "package_source_sha256", "configuration_digest", "source_vector_digest", "bake_binding_roster_digest", "adapter_registry_digest", "rule_registry_digest", "coverage_ids", "coverage_digest", "candidate_ids", "candidate_digest", "witness_ids", "witness_digest", "debt_ids", "debt_digest", "classification_ids", "classification_digest", "edge_ids", "edge_digest", "source_byte_count", "covered_byte_count", "unparsed_remainder_count", "receipt_digest"],
      "properties": {
        "parser": {"$ref": "#/$defs/Parser"},
        "package_id": {"type": "string", "minLength": 1},
        "package_version": {"type": "string", "minLength": 1},
        "package_source_sha256": {"$ref": "#/$defs/Hex64"},
        "configuration_digest": {"$ref": "#/$defs/Hex64"},
        "source_vector_digest": {"$ref": "#/$defs/Hex64"},
        "bake_binding_roster_digest": {"$ref": "#/$defs/Hex64"},
        "adapter_registry_digest": {"$ref": "#/$defs/Hex64"},
        "rule_registry_digest": {"$ref": "#/$defs/Hex64"},
        "coverage_ids": {"type": "array", "items": {"type": "string", "minLength": 1}},
        "coverage_digest": {"$ref": "#/$defs/Hex64"},
        "candidate_ids": {"type": "array", "items": {"type": "string", "minLength": 1}},
        "candidate_digest": {"$ref": "#/$defs/Hex64"},
        "witness_ids": {"type": "array", "items": {"type": "string", "minLength": 1}},
        "witness_digest": {"$ref": "#/$defs/Hex64"},
        "debt_ids": {"type": "array", "items": {"type": "string", "minLength": 1}},
        "debt_digest": {"$ref": "#/$defs/Hex64"},
        "classification_ids": {"type": "array", "items": {"type": "string", "minLength": 1}},
        "classification_digest": {"$ref": "#/$defs/Hex64"},
        "edge_ids": {"type": "array", "items": {"type": "string", "minLength": 1}},
        "edge_digest": {"$ref": "#/$defs/Hex64"},
        "source_byte_count": {"type": "integer", "minimum": 0},
        "covered_byte_count": {"type": "integer", "minimum": 0},
        "unparsed_remainder_count": {"const": 0},
        "receipt_digest": {"$ref": "#/$defs/Hex64"}
      }
    },
    "TotalNegativeProof": {
      "type": "object", "additionalProperties": false,
      "required": ["target_identity", "source_vector_digest", "bake_binding_roster_digest", "adapter_registry_digest", "rule_registry_digest", "parser_a_receipt_digest", "parser_b_receipt_digest", "coverage_multiset_digest", "candidate_multiset_digest", "nonsemantic_witness_multiset_digest", "debt_multiset_digest", "classification_multiset_digest", "edge_multiset_digest", "relevant_candidate_count", "relevant_edge_count", "unparsed_remainder_count", "disagreement_count", "disposition", "proof_digest"],
      "properties": {
        "target_identity": {"type": "string", "minLength": 1},
        "source_vector_digest": {"$ref": "#/$defs/Hex64"},
        "bake_binding_roster_digest": {"$ref": "#/$defs/Hex64"},
        "adapter_registry_digest": {"$ref": "#/$defs/Hex64"},
        "rule_registry_digest": {"$ref": "#/$defs/Hex64"},
        "parser_a_receipt_digest": {"$ref": "#/$defs/Hex64"},
        "parser_b_receipt_digest": {"$ref": "#/$defs/Hex64"},
        "coverage_multiset_digest": {"$ref": "#/$defs/Hex64"},
        "candidate_multiset_digest": {"$ref": "#/$defs/Hex64"},
        "nonsemantic_witness_multiset_digest": {"$ref": "#/$defs/Hex64"},
        "debt_multiset_digest": {"$ref": "#/$defs/Hex64"},
        "classification_multiset_digest": {"$ref": "#/$defs/Hex64"},
        "edge_multiset_digest": {"$ref": "#/$defs/Hex64"},
        "relevant_candidate_count": {"type": "integer", "minimum": 0},
        "relevant_edge_count": {"type": "integer", "minimum": 0},
        "unparsed_remainder_count": {"const": 0},
        "disagreement_count": {"const": 0},
        "disposition": {"enum": ["PROVED_NONE", "FOUND", "DEBT"]},
        "proof_digest": {"$ref": "#/$defs/Hex64"}
      }
    },
    "IndependentNegativeReceipt": {
      "type": "object", "additionalProperties": false,
      "required": ["schema", "producer_task_id", "oracle_package_sha256", "source_vector_digest", "parser_a_receipt_digest", "parser_b_receipt_digest", "proof_ids", "proof_roster_digest", "result", "receipt_digest", "transport_envelope_digest"],
      "properties": {
        "schema": {"const": "cut4.r15.independent_negative_receipt.v1"},
        "producer_task_id": {"type": "string", "pattern": "^task_[A-Za-z0-9_-]{8,128}$"},
        "oracle_package_sha256": {"$ref": "#/$defs/Hex64"},
        "source_vector_digest": {"$ref": "#/$defs/Hex64"},
        "parser_a_receipt_digest": {"$ref": "#/$defs/Hex64"},
        "parser_b_receipt_digest": {"$ref": "#/$defs/Hex64"},
        "proof_ids": {"type": "array", "minItems": 1, "uniqueItems": true, "items": {"type": "string", "minLength": 1}},
        "proof_roster_digest": {"$ref": "#/$defs/Hex64"},
        "result": {"enum": ["ACCEPT", "DEBT"]},
        "receipt_digest": {"$ref": "#/$defs/Hex64"},
        "transport_envelope_digest": {"$ref": "#/$defs/Hex64"}
      }
    }
  }
}
```

## 11. Normative integration rule

Sections 3 through 10 are one indivisible contract. Transport ACCEPT cannot
waive a universe, reflection, journal, publication, mutation, or completion
failure; a valid dual proof cannot waive transport/no-self-review; and a
self-consistent M4/R4/completion tree cannot waive an invalid terminal,
external receipt/link, public byte, or FrozenContractFields join. Every future
receipt names this contract's exact SHA-256 and rejects a changed, partial, or
superseded copy.

No fixture or MODEL path is authorized until the independent R15 architecture
review returns ACCEPT over the exact contract and author-receipt bytes. Until
then Part-0 and all downstream authority remain false.
