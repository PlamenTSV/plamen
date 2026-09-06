# Cut-4 transactional recon publication R20 preimplementation contract

Date: 2026-08-10
Status: Part-0 architecture-only repair awaiting independent review
Supersedes: only the four rejected R19 gates
Authority: all event-source admission, parser, verifier, fixture, source-map,
mutation-catalog, test, model, execution, production, provider, ArtifactLedger,
G3, audit, commit, push, install, cutover, release, readiness, and
protocol-answer authority is false

## 0. Boundary, authentication, and inheritance

This turn creates only this contract and its author receipt. It does not create
or edit any prior artifact, independent review, event ledger, admission/route
record, parser, verifier, fixture, dependency receipt, source map, mutation
catalog, test, execution evidence, model, production/provider file,
ArtifactLedger row, or G3 pin. It runs no fixture, parser, provider, model, or
test.

The exact R19 independent REPAIR review was authenticated and read completely
before R20 was authored:

| Artifact | Bytes | SHA-256 |
|---|---:|---|
| `review_fixtures/cut4_transactional_recon_publication_r19_architecture_independent_review_20260810.md` | 19,000 | `1dd170138bf8a8b25b0ca1f8f041be10dbd2ac6709bb74c3a73cc435a392fd4a` |
| `architecture/cut4-transactional-recon-publication-r19-preimplementation-contract.md` | 74,482 | `66e44cce17e9348d5f5394fb53bda44f37fd3a9c3b84802bdb6b542d82f25229` |
| `review_fixtures/cut4_transactional_recon_publication_r19_contract_author_receipt_20260810.md` | 5,469 | `046f084448d8655131bfb7f7cb534b0a972773582efffa4729545c7b03f1ee43` |

R20 inherits every accepted R1-R19 clause outside the rejected gates: sole
`recon/canonical_merge` public ownership, immutable MODEL seed visibility,
fixed provider slots `source_graph/build_probe/daml_source_graph`, nonempty
typed outcomes, stable registered publication successor, terminal-before-link
journal order, complete SC/L1 tuples, compatibility projection, legacy
non-adoption, exact replay/crash recovery, project-root containment, unchanged
MODEL shards/dependency units, and nonempty exhausted c3. R20 replacements
below control where R19 conflicts. No R13 artifact is evidence authority.

`H` is SHA-256 over bytes. `U` is strict UTF-8 of an NFC string. `CJ` is RFC
8785 canonical JSON after duplicate-key, non-finite, surrogate, and non-NFC
rejection. `D(tag,x)=H(U(tag)||0x00||CJ(x))`. Lowercase hex is strict; arrays
are ordered. `EMPTY_SHA` is
`e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.
Hashes authenticate bytes and joins, not a human identity, signature,
non-collusion, or cryptographic principal independence.

```json
{
  "schema": "cut4.r20.path_registry.v1",
  "contract": "architecture/cut4-transactional-recon-publication-r20-preimplementation-contract.md",
  "author_receipt": "review_fixtures/cut4_transactional_recon_publication_r20_contract_author_receipt_20260810.md",
  "architecture_review": "review_fixtures/cut4_transactional_recon_publication_r20_architecture_independent_review_20260810.md",
  "root_observation_genesis": "review_fixtures/cut4_transactional_recon_publication_r20_root_observations/000000-genesis.json",
  "root_observation_directory": "review_fixtures/cut4_transactional_recon_publication_r20_root_observations",
  "event_source_admission": "review_fixtures/cut4_transactional_recon_publication_r20_route/000_event_source_admission.json",
  "architecture_admission": "review_fixtures/cut4_transactional_recon_publication_r20_route/001_architecture_admission.json",
  "route_directory": "review_fixtures/cut4_transactional_recon_publication_r20_route",
  "fixture_source_bundle": "review_fixtures/cut4_transactional_recon_publication_r20_fixture_source_bundle.json",
  "source_map_receipt": "review_fixtures/cut4_transactional_recon_publication_r20_source_map_receipt.json",
  "mutation_catalog": "review_fixtures/cut4_transactional_recon_publication_r20_mutation_catalog.json",
  "parser_a_package": "review_fixtures/cut4_transactional_recon_publication_r20_parser_a.py",
  "parser_b_package": "review_fixtures/cut4_transactional_recon_publication_r20_parser_b.py",
  "verifier_package": "review_fixtures/cut4_transactional_recon_publication_r20_independent_verifier.py",
  "parser_a_dependency_receipt": "review_fixtures/cut4_transactional_recon_publication_r20_parser_a_dependency_receipt.json",
  "parser_b_dependency_receipt": "review_fixtures/cut4_transactional_recon_publication_r20_parser_b_dependency_receipt.json",
  "verifier_dependency_receipt": "review_fixtures/cut4_transactional_recon_publication_r20_verifier_dependency_receipt.json",
  "red_test": "tests/test_cut4_transactional_recon_publication_r20_preimplementation.py",
  "parser_a_execution_receipt": "review_fixtures/cut4_transactional_recon_publication_r20_parser_a_execution_receipt.json",
  "parser_b_execution_receipt": "review_fixtures/cut4_transactional_recon_publication_r20_parser_b_execution_receipt.json",
  "verifier_execution_receipt": "review_fixtures/cut4_transactional_recon_publication_r20_verifier_execution_receipt.json",
  "negative_proof_receipt": "review_fixtures/cut4_transactional_recon_publication_r20_negative_proof_receipt.json",
  "red_pre_snapshot": "review_fixtures/cut4_transactional_recon_publication_r20_red_pre_snapshot.json",
  "red_process_projection": "review_fixtures/cut4_transactional_recon_publication_r20_red_process_projection.json",
  "red_exit_projection": "review_fixtures/cut4_transactional_recon_publication_r20_red_exit_projection.json",
  "red_author_receipt": "review_fixtures/cut4_transactional_recon_publication_r20_red_author_receipt.json",
  "model": "review_fixtures/cut4_transactional_recon_publication_r20_reference_model.py",
  "green_pre_snapshot": "review_fixtures/cut4_transactional_recon_publication_r20_green_pre_snapshot.json",
  "green_process_projection": "review_fixtures/cut4_transactional_recon_publication_r20_green_process_projection.json",
  "green_exit_projection": "review_fixtures/cut4_transactional_recon_publication_r20_green_exit_projection.json",
  "green_author_receipt": "review_fixtures/cut4_transactional_recon_publication_r20_green_author_receipt.json"
}
```

## 1. Non-caller-mintable root observation source

### 1.1 Construction boundary

R20 removes `RuntimeEvent` from the admission authority. The only authoritative
source is a sealed result value delivered to the root by the collaboration or
shell tool runtime. A worker receives neither that capability nor the writer.
The root adapter has this one-way signature:

```
observe(sealed_root_tool_event: RuntimeCapability,
        expected_tool_call_id: ToolCallId,
        prior_committed_record: RootObservationRecord) -> RootObservationRecord
```

There is deliberately no `observe(bytes)` overload. The runtime capability is
consumed once. The adapter writes one canonical generation record with
`O_CREAT|O_EXCL`; generation is prior+1 and its filename is
`{generation:06d}-{record_digest}.json`. A temp file is outside the committed
roster, and rename succeeds only if the final identity is absent. Reusing one
sealed event, skipping/reordering a generation, changing the previous digest,
or importing a worker-authored JSON file fails before admission. Persisted
records can later be replay-validated but cannot be newly admitted without the
live sealed capability.

The concrete available sources are the root-visible results of
`collaboration.spawn_agent`, root-delivered task completion/notification, and
the root's `shell_command` request/result. The adapter byte contract below is
part of this architecture subject. It consumes exact tool-result fields; an
unsupported runtime shape is `ROOT_EVENT_SOURCE_DEBT`, never guessed.

```json
{
  "schema": "cut4.r20.root_observation_adapter.v1",
  "adapter_id": "cut4.r20.sealed_root_tool_adapter.v1",
  "accepted_sources": [
    ["COLLABORATION_SPAWN", "collaboration.spawn_agent", ["tool_call_id", "agent_id", "canonical_task_name", "parent_task_name", "request_digest"]],
    ["COLLABORATION_RESULT", "collaboration.task_result", ["tool_call_id", "agent_id", "canonical_task_name", "status", "result_bytes", "result_sha256"]],
    ["SHELL_START", "shell_command.request", ["tool_call_id", "process_id", "argv", "environment_rows", "cwd", "stdin_bytes", "request_digest"]],
    ["SHELL_RESULT", "shell_command.result", ["tool_call_id", "process_id", "exit_code", "stdout_bytes", "stderr_bytes", "result_digest"]],
    ["FILESYSTEM_SNAPSHOT", "root.filesystem_snapshot", ["tool_call_id", "path_rows", "enumeration_bytes", "snapshot_digest"]]
  ],
  "canonical_projection_order": ["source_kind", "tool_name", "tool_call_id", "runtime_event_identity", "payload_bytes_base64", "payload_byte_size", "payload_sha256"],
  "unsupported_shape": "ROOT_EVENT_SOURCE_DEBT",
  "writer": "root-only sealed-capability adapter; no worker-callable byte constructor",
  "record_commit": "canonical temp in observation directory, fsync, atomic rename to absent generation path, fsync directory"
}
```

### 1.2 Closed ledger, occurrence, and process records

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "cut4.r20.root_observation.schema.v1",
  "$defs": {
    "Hex64": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
    "TaskHandle": {"type": "string", "pattern": "^/root(?:/[a-z0-9_]+)+$"},
    "ByteSubject": {
      "type": "object", "additionalProperties": false,
      "required": ["identity", "bytes_base64", "byte_size", "sha256"],
      "properties": {"identity": {"type": "string", "minLength": 1}, "bytes_base64": {"type": "string"}, "byte_size": {"type": "integer", "minimum": 1}, "sha256": {"$ref": "#/$defs/Hex64"}}
    },
    "Projection": {
      "type": "object", "additionalProperties": false,
      "required": ["source_kind", "tool_name", "tool_call_id", "runtime_event_identity", "payload_bytes_base64", "payload_byte_size", "payload_sha256"],
      "properties": {
        "source_kind": {"enum": ["COLLABORATION_SPAWN", "COLLABORATION_RESULT", "SHELL_START", "SHELL_RESULT", "FILESYSTEM_SNAPSHOT"]},
        "tool_name": {"enum": ["collaboration.spawn_agent", "collaboration.task_result", "shell_command.request", "shell_command.result", "root.filesystem_snapshot"]},
        "tool_call_id": {"type": "string", "minLength": 1},
        "runtime_event_identity": {"type": "string", "minLength": 1},
        "payload_bytes_base64": {"type": "string"},
        "payload_byte_size": {"type": "integer", "minimum": 1},
        "payload_sha256": {"$ref": "#/$defs/Hex64"}
      }
    },
    "RootObservationRecord": {
      "type": "object", "additionalProperties": false,
      "required": ["schema", "ledger_identity", "generation", "previous_record_digest", "adapter_spec_digest", "sealed_capability_identity", "projection", "raw_runtime_envelope_bytes_base64", "raw_runtime_envelope_byte_size", "raw_runtime_envelope_sha256", "record_digest"],
      "properties": {
        "schema": {"const": "cut4.r20.root_observation_record.v1"},
        "ledger_identity": {"const": "review_fixtures/cut4_transactional_recon_publication_r20_root_observations"},
        "generation": {"type": "integer", "minimum": 1},
        "previous_record_digest": {"$ref": "#/$defs/Hex64"},
        "adapter_spec_digest": {"$ref": "#/$defs/Hex64"},
        "sealed_capability_identity": {"type": "string", "minLength": 1},
        "projection": {"$ref": "#/$defs/Projection"},
        "raw_runtime_envelope_bytes_base64": {"type": "string"},
        "raw_runtime_envelope_byte_size": {"type": "integer", "minimum": 1},
        "raw_runtime_envelope_sha256": {"$ref": "#/$defs/Hex64"},
        "record_digest": {"$ref": "#/$defs/Hex64"}
      }
    },
    "OccurrenceRecord": {
      "type": "object", "additionalProperties": false,
      "required": ["schema", "spawn_record_digest", "result_record_digest", "agent_id", "canonical_task_handle", "parent_task_handle", "occurrence_id", "result_status", "result_subjects", "occurrence_digest"],
      "properties": {
        "schema": {"const": "cut4.r20.occurrence_record.v1"},
        "spawn_record_digest": {"$ref": "#/$defs/Hex64"},
        "result_record_digest": {"$ref": "#/$defs/Hex64"},
        "agent_id": {"type": "string", "minLength": 1},
        "canonical_task_handle": {"$ref": "#/$defs/TaskHandle"},
        "parent_task_handle": {"const": "/root"},
        "occurrence_id": {"type": "string", "pattern": "^occ_[0-9a-f]{64}$"},
        "result_status": {"enum": ["COMPLETED", "FAILED", "INTERRUPTED"]},
        "result_subjects": {"type": "array", "uniqueItems": true, "items": {"$ref": "#/$defs/ByteSubject"}},
        "occurrence_digest": {"$ref": "#/$defs/Hex64"}
      }
    },
    "ProcessObservationRecord": {
      "type": "object", "additionalProperties": false,
      "required": ["schema", "phase", "pre_snapshot_subject_admission_digest", "shell_start_record_digest", "shell_result_record_digest", "process_id", "argv", "environment_rows", "cwd_nfc", "stdin_bytes_base64", "stdin_byte_size", "stdin_sha256", "exit_code", "stdout_bytes_base64", "stdout_byte_size", "stdout_sha256", "stderr_bytes_base64", "stderr_byte_size", "stderr_sha256", "process_observation_digest"],
      "properties": {
        "schema": {"const": "cut4.r20.process_observation_record.v1"}, "phase": {"enum": ["RED", "GREEN"]},
        "pre_snapshot_subject_admission_digest": {"$ref": "#/$defs/Hex64"}, "shell_start_record_digest": {"$ref": "#/$defs/Hex64"}, "shell_result_record_digest": {"$ref": "#/$defs/Hex64"},
        "process_id": {"type": "string", "minLength": 1}, "argv": {"type": "array", "minItems": 1, "items": {"type": "string"}},
        "environment_rows": {"type": "array", "items": {"type": "array", "prefixItems": [{"type": "string"}, {"type": "string"}], "items": false, "minItems": 2, "maxItems": 2}},
        "cwd_nfc": {"type": "string", "minLength": 1}, "stdin_bytes_base64": {"type": "string"}, "stdin_byte_size": {"type": "integer", "minimum": 0}, "stdin_sha256": {"$ref": "#/$defs/Hex64"},
        "exit_code": {"type": "integer"}, "stdout_bytes_base64": {"type": "string"}, "stdout_byte_size": {"type": "integer", "minimum": 1}, "stdout_sha256": {"$ref": "#/$defs/Hex64"},
        "stderr_bytes_base64": {"type": "string"}, "stderr_byte_size": {"type": "integer", "minimum": 0}, "stderr_sha256": {"$ref": "#/$defs/Hex64"},
        "process_observation_digest": {"$ref": "#/$defs/Hex64"}
      }
    },
    "EventSourceAdmission": {
      "type": "object", "additionalProperties": false,
      "required": ["schema", "adapter_spec_subject", "genesis_subject", "ledger_identity", "creation_mode", "writer_authority", "admission_digest"],
      "properties": {
        "schema": {"const": "cut4.r20.event_source_admission.v1"}, "adapter_spec_subject": {"$ref": "#/$defs/ByteSubject"}, "genesis_subject": {"$ref": "#/$defs/ByteSubject"},
        "ledger_identity": {"const": "review_fixtures/cut4_transactional_recon_publication_r20_root_observations"}, "creation_mode": {"const": "SEALED_RUNTIME_CAPABILITY_ONLY"},
        "writer_authority": {"const": "ROOT_TOOL_RUNTIME"}, "admission_digest": {"$ref": "#/$defs/Hex64"}
      }
    }
  },
  "oneOf": [{"$ref": "#/$defs/RootObservationRecord"}, {"$ref": "#/$defs/OccurrenceRecord"}, {"$ref": "#/$defs/ProcessObservationRecord"}, {"$ref": "#/$defs/EventSourceAdmission"}]
}
```

The genesis subject is a create-new canonical record with generation zero and
`EMPTY_SHA` predecessor. Each observation record's raw envelope is supplied
only by the sealed capability and must canonical-project to `projection` with
exact bytes/size/SHA. `record_digest` is the BODY digest. A spawn and result
occurrence must copy the same runtime agent ID/canonical task name; its
`occurrence_id="occ_"+D("cut4.r20.occurrence_id.v1",[spawn_record_digest,
agent_id,canonical_task_handle])`. The stable ID therefore exists at start;
the result later joins it without changing it. Each source record may
participate in exactly one occurrence/process row. Ledger ordinals and tool
call IDs are unique; all records form one exact prefix chain.

Architecture admission FKs the event-source admission plus the actual author
and reviewer occurrence records. Author result subjects equal this contract
and receipt; reviewer result subjects equal the review. Every later producer
start/result and reviewer start/result FK its own occurrence record rather
than accepting raw event bytes. The cumulative 48-role manifest (two
architecture plus two for each of 23 subjects) copies exact occurrence FKs and
requires globally unique `agent_id`, canonical task handle, occurrence ID,
spawn record, and result record. This is a live root-tool transport guarantee,
not a cryptographic human-independence claim.

No R19 raw-event envelope remains in route authority. The route's exact
transport records are closed here. A start is authorized by one ledger spawn
record; completion adds the matching occurrence. Admission appends the two
completed role claims to the prior manifest.

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "cut4.r20.route_records.schema.v1",
  "$defs": {
    "Hex64": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
    "ByteSubject": {"$ref": "cut4.r20.root_observation.schema.v1#/$defs/ByteSubject"},
    "Occurrence": {"$ref": "cut4.r20.root_observation.schema.v1#/$defs/OccurrenceRecord"},
    "SpawnClaim": {
      "type": "object", "additionalProperties": false,
      "required": ["role", "subject_id", "lifecycle_kind", "spawn_record_digest", "agent_id", "canonical_task_handle", "occurrence_id", "claim_digest"],
      "properties": {
        "role": {"type": "string", "pattern": "^[A-Z][A-Z0-9_]{2,63}$"},
        "subject_id": {"type": "string", "pattern": "^(ARCH|S(?:0[1-9]|1[0-9]|2[0-3]))$"},
        "lifecycle_kind": {"enum": ["AUTHOR", "REVIEWER"]},
        "spawn_record_digest": {"$ref": "#/$defs/Hex64"}, "agent_id": {"type": "string", "minLength": 1},
        "canonical_task_handle": {"type": "string", "pattern": "^/root(?:/[a-z0-9_]+)+$"},
        "occurrence_id": {"type": "string", "pattern": "^occ_[0-9a-f]{64}$"}, "claim_digest": {"$ref": "#/$defs/Hex64"}
      }
    },
    "RoleClaim": {
      "type": "object", "additionalProperties": false,
      "required": ["spawn_claim", "occurrence", "claim_digest"],
      "properties": {"spawn_claim": {"$ref": "#/$defs/SpawnClaim"}, "occurrence": {"$ref": "#/$defs/Occurrence"}, "claim_digest": {"$ref": "#/$defs/Hex64"}}
    },
    "ArchitectureAdmission": {
      "type": "object", "additionalProperties": false,
      "required": ["schema", "event_source_admission_digest", "contract", "author_receipt", "review", "author_claim", "reviewer_claim", "role_manifest_rows", "role_manifest_digest", "decision", "admission_digest"],
      "properties": {"schema": {"const": "cut4.r20.architecture_admission.v1"}, "event_source_admission_digest": {"$ref": "#/$defs/Hex64"}, "contract": {"$ref": "#/$defs/ByteSubject"}, "author_receipt": {"$ref": "#/$defs/ByteSubject"}, "review": {"$ref": "#/$defs/ByteSubject"}, "author_claim": {"$ref": "#/$defs/RoleClaim"}, "reviewer_claim": {"$ref": "#/$defs/RoleClaim"}, "role_manifest_rows": {"type": "array", "minItems": 2, "maxItems": 2, "items": {"$ref": "#/$defs/RoleClaim"}}, "role_manifest_digest": {"$ref": "#/$defs/Hex64"}, "decision": {"const": "ACCEPT"}, "admission_digest": {"$ref": "#/$defs/Hex64"}}
    },
    "ProducerStart": {
      "type": "object", "additionalProperties": false,
      "required": ["schema", "subject_id", "subject_identity", "producer_role", "producer_spawn_claim", "architecture_admission_digest", "predecessor_subject_admission_digests", "absence_observation_record_digest", "start_digest"],
      "properties": {"schema": {"const": "cut4.r20.producer_start.v1"}, "subject_id": {"type": "string", "pattern": "^S(?:0[1-9]|1[0-9]|2[0-3])$"}, "subject_identity": {"type": "string", "minLength": 1}, "producer_role": {"type": "string", "minLength": 3}, "producer_spawn_claim": {"$ref": "#/$defs/SpawnClaim"}, "architecture_admission_digest": {"$ref": "#/$defs/Hex64"}, "predecessor_subject_admission_digests": {"type": "array", "uniqueItems": true, "items": {"$ref": "#/$defs/Hex64"}}, "absence_observation_record_digest": {"$ref": "#/$defs/Hex64"}, "start_digest": {"$ref": "#/$defs/Hex64"}}
    },
    "ProducerCompletion": {
      "type": "object", "additionalProperties": false,
      "required": ["schema", "subject_id", "producer_role", "producer_start_digest", "producer_occurrence", "subject", "completion_digest"],
      "properties": {"schema": {"const": "cut4.r20.producer_completion.v1"}, "subject_id": {"type": "string", "pattern": "^S(?:0[1-9]|1[0-9]|2[0-3])$"}, "producer_role": {"type": "string", "minLength": 3}, "producer_start_digest": {"$ref": "#/$defs/Hex64"}, "producer_occurrence": {"$ref": "#/$defs/Occurrence"}, "subject": {"$ref": "#/$defs/ByteSubject"}, "completion_digest": {"$ref": "#/$defs/Hex64"}}
    },
    "ReviewStart": {
      "type": "object", "additionalProperties": false,
      "required": ["schema", "subject_id", "reviewer_role", "producer_completion_digest", "reviewer_spawn_claim", "review_identity", "absence_observation_record_digest", "start_digest"],
      "properties": {"schema": {"const": "cut4.r20.review_start.v1"}, "subject_id": {"type": "string", "pattern": "^S(?:0[1-9]|1[0-9]|2[0-3])$"}, "reviewer_role": {"type": "string", "minLength": 3}, "producer_completion_digest": {"$ref": "#/$defs/Hex64"}, "reviewer_spawn_claim": {"$ref": "#/$defs/SpawnClaim"}, "review_identity": {"type": "string", "minLength": 1}, "absence_observation_record_digest": {"$ref": "#/$defs/Hex64"}, "start_digest": {"$ref": "#/$defs/Hex64"}}
    },
    "ReviewCompletion": {
      "type": "object", "additionalProperties": false,
      "required": ["schema", "subject_id", "reviewer_role", "review_start_digest", "reviewer_occurrence", "review", "decision", "completion_digest"],
      "properties": {"schema": {"const": "cut4.r20.review_completion.v1"}, "subject_id": {"type": "string", "pattern": "^S(?:0[1-9]|1[0-9]|2[0-3])$"}, "reviewer_role": {"type": "string", "minLength": 3}, "review_start_digest": {"$ref": "#/$defs/Hex64"}, "reviewer_occurrence": {"$ref": "#/$defs/Occurrence"}, "review": {"$ref": "#/$defs/ByteSubject"}, "decision": {"enum": ["ACCEPT", "REPAIR"]}, "completion_digest": {"$ref": "#/$defs/Hex64"}}
    },
    "SubjectAdmission": {
      "type": "object", "additionalProperties": false,
      "required": ["schema", "subject_id", "producer_completion_digest", "review_completion_digest", "producer_claim", "reviewer_claim", "decision", "subject_sha256", "prior_role_manifest_digest", "role_manifest_rows", "role_manifest_digest", "subject_admission_digest"],
      "properties": {"schema": {"const": "cut4.r20.subject_admission.v1"}, "subject_id": {"type": "string", "pattern": "^S(?:0[1-9]|1[0-9]|2[0-3])$"}, "producer_completion_digest": {"$ref": "#/$defs/Hex64"}, "review_completion_digest": {"$ref": "#/$defs/Hex64"}, "producer_claim": {"$ref": "#/$defs/RoleClaim"}, "reviewer_claim": {"$ref": "#/$defs/RoleClaim"}, "decision": {"const": "ACCEPT"}, "subject_sha256": {"$ref": "#/$defs/Hex64"}, "prior_role_manifest_digest": {"$ref": "#/$defs/Hex64"}, "role_manifest_rows": {"type": "array", "minItems": 4, "maxItems": 48, "uniqueItems": true, "items": {"$ref": "#/$defs/RoleClaim"}}, "role_manifest_digest": {"$ref": "#/$defs/Hex64"}, "subject_admission_digest": {"$ref": "#/$defs/Hex64"}}
    }
  },
  "oneOf": [{"$ref": "#/$defs/ArchitectureAdmission"}, {"$ref": "#/$defs/ProducerStart"}, {"$ref": "#/$defs/ProducerCompletion"}, {"$ref": "#/$defs/ReviewStart"}, {"$ref": "#/$defs/ReviewCompletion"}, {"$ref": "#/$defs/SubjectAdmission"}]
}
```

Spawn claims are reconstructed from the cited `COLLABORATION_SPAWN` record,
not caller strings. Completion requires byte equality between the spawn claim
and occurrence. Role/subject/lifecycle equal the route row. Manifest prefix
equality and pairwise uniqueness cover agent ID, handle, occurrence ID, spawn
record, and result record. Architecture claims are the first two rows; every
later admission appends producer then reviewer without omission or reuse.

## 2. Closed A/B/verifier execution and negative proof

### 2.1 Dependency closure is an admitted input

Each engine package owns its own lexical parser, semantic matcher, and
`conformance_bake_to_fact` implementation. A dependency receipt is generated
from the admitted package bytes by complete AST imports plus runtime import
probe. It includes every module/source byte subject and exact directed import
edge; dynamic/unknown imports are typed debt. The three local closure sets are
pairwise disjoint. Their only common dependencies may be these frozen data or
stdlib IDs:

```json
{
  "schema": "cut4.r20.engine_dependency_policy.v1",
  "engines": ["PARSER_A", "PARSER_B", "VERIFIER"],
  "required_owned_components": ["lexer", "semantic_matcher", "conformance_bake_to_fact", "tuple_serializer"],
  "allowed_shared_executable_modules": ["__future__", "base64", "dataclasses", "enum", "hashlib", "json", "typing", "unicodedata"],
  "allowed_shared_data_subjects": ["ecosystem_lexical_registry", "grammar_dfa", "semantic_matcher_opcode_registry", "normalization_registry", "error_registry", "conformance_source_vectors", "literal_bake_inputs"],
  "forbidden_edges": [["PARSER_A", "PARSER_B"], ["PARSER_A", "VERIFIER"], ["PARSER_B", "PARSER_A"], ["PARSER_B", "VERIFIER"], ["VERIFIER", "PARSER_A"], ["VERIFIER", "PARSER_B"]],
  "verifier_result_inputs": ["source_bytes", "bake_input_bytes", "frozen_spec_bytes"],
  "verifier_forbidden_result_inputs": ["parser_a_result", "parser_b_result", "accepted_tuple_projection"]
}
```

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "cut4.r20.recognition_evidence.schema.v1",
  "$defs": {
    "Hex64": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
    "ByteSubject": {"type": "object", "additionalProperties": false, "required": ["identity", "bytes_base64", "byte_size", "sha256"], "properties": {"identity": {"type": "string", "minLength": 1}, "bytes_base64": {"type": "string"}, "byte_size": {"type": "integer", "minimum": 1}, "sha256": {"$ref": "#/$defs/Hex64"}}},
    "ModuleRow": {
      "type": "object", "additionalProperties": false,
      "required": ["module_id", "ownership", "source", "ast_node_count", "runtime_probe_count", "module_digest"],
      "properties": {"module_id": {"type": "string", "minLength": 1}, "ownership": {"enum": ["ENGINE_LOCAL", "ALLOWED_SHARED_STDLIB", "ALLOWED_SHARED_DATA"]}, "source": {"$ref": "#/$defs/ByteSubject"}, "ast_node_count": {"type": "integer", "minimum": 0}, "runtime_probe_count": {"type": "integer", "minimum": 0}, "module_digest": {"$ref": "#/$defs/Hex64"}}
    },
    "ImportEdge": {
      "type": "object", "additionalProperties": false,
      "required": ["source_module_id", "target_module_id", "import_kind", "ast_span_digest", "runtime_observed", "edge_digest"],
      "properties": {"source_module_id": {"type": "string", "minLength": 1}, "target_module_id": {"type": "string", "minLength": 1}, "import_kind": {"enum": ["IMPORT", "IMPORT_FROM", "DYNAMIC", "RUNTIME"]}, "ast_span_digest": {"$ref": "#/$defs/Hex64"}, "runtime_observed": {"type": "boolean"}, "edge_digest": {"$ref": "#/$defs/Hex64"}}
    },
    "DependencyClosureReceipt": {
      "type": "object", "additionalProperties": false,
      "required": ["schema", "engine", "package_subject_admission_digest", "package_sha256", "owned_component_rows", "module_rows", "import_edges", "module_roster_digest", "edge_roster_digest", "unknown_dynamic_import_count", "forbidden_cross_engine_edge_count", "closure_digest"],
      "properties": {
        "schema": {"const": "cut4.r20.dependency_closure_receipt.v1"}, "engine": {"enum": ["PARSER_A", "PARSER_B", "VERIFIER"]},
        "package_subject_admission_digest": {"$ref": "#/$defs/Hex64"}, "package_sha256": {"$ref": "#/$defs/Hex64"},
        "owned_component_rows": {"type": "array", "minItems": 4, "maxItems": 4, "items": {"type": "array", "prefixItems": [{"type": "string"}, {"$ref": "#/$defs/Hex64"}], "items": false, "minItems": 2, "maxItems": 2}},
        "module_rows": {"type": "array", "minItems": 4, "items": {"$ref": "#/$defs/ModuleRow"}}, "import_edges": {"type": "array", "items": {"$ref": "#/$defs/ImportEdge"}},
        "module_roster_digest": {"$ref": "#/$defs/Hex64"}, "edge_roster_digest": {"$ref": "#/$defs/Hex64"},
        "unknown_dynamic_import_count": {"const": 0}, "forbidden_cross_engine_edge_count": {"const": 0}, "closure_digest": {"$ref": "#/$defs/Hex64"}
      }
    },
    "VectorResult": {
      "type": "object", "additionalProperties": false,
      "required": ["schema", "engine", "vector_ordinal", "vector_id", "source_byte_size", "source_sha256", "bake_input_digest", "converted_fact_roster_digest", "token_tuple_bytes_base64", "token_tuple_byte_size", "token_tuple_sha256", "token_count", "semantic_tuple_bytes_base64", "semantic_tuple_byte_size", "semantic_tuple_sha256", "candidate_count", "coverage_byte_count", "coverage_gap_count", "coverage_overlap_count", "result_digest"],
      "properties": {
        "schema": {"const": "cut4.r20.vector_result.v1"}, "engine": {"enum": ["PARSER_A", "PARSER_B", "VERIFIER"]}, "vector_ordinal": {"type": "integer", "minimum": 0, "maximum": 31}, "vector_id": {"type": "string", "minLength": 1},
        "source_byte_size": {"type": "integer", "minimum": 0}, "source_sha256": {"$ref": "#/$defs/Hex64"}, "bake_input_digest": {"$ref": "#/$defs/Hex64"}, "converted_fact_roster_digest": {"$ref": "#/$defs/Hex64"},
        "token_tuple_bytes_base64": {"type": "string"}, "token_tuple_byte_size": {"type": "integer", "minimum": 1}, "token_tuple_sha256": {"$ref": "#/$defs/Hex64"}, "token_count": {"type": "integer", "minimum": 1},
        "semantic_tuple_bytes_base64": {"type": "string"}, "semantic_tuple_byte_size": {"type": "integer", "minimum": 0}, "semantic_tuple_sha256": {"$ref": "#/$defs/Hex64"}, "candidate_count": {"type": "integer", "minimum": 0},
        "coverage_byte_count": {"type": "integer", "minimum": 0}, "coverage_gap_count": {"const": 0}, "coverage_overlap_count": {"const": 0}, "result_digest": {"$ref": "#/$defs/Hex64"}
      }
    },
    "ExecutionReceipt": {
      "type": "object", "additionalProperties": false,
      "required": ["schema", "engine", "execution_occurrence_digest", "package_subject_admission_digest", "package_sha256", "dependency_receipt_subject_admission_digest", "dependency_closure_digest", "owned_adapter_component_sha256", "frozen_spec_subjects", "source_vector_root_digest", "bake_input_root_digest", "results", "result_count", "result_roster_digest", "receipt_digest"],
      "properties": {
        "schema": {"const": "cut4.r20.execution_receipt.v1"}, "engine": {"enum": ["PARSER_A", "PARSER_B", "VERIFIER"]}, "execution_occurrence_digest": {"$ref": "#/$defs/Hex64"},
        "package_subject_admission_digest": {"$ref": "#/$defs/Hex64"}, "package_sha256": {"$ref": "#/$defs/Hex64"}, "dependency_receipt_subject_admission_digest": {"$ref": "#/$defs/Hex64"}, "dependency_closure_digest": {"$ref": "#/$defs/Hex64"}, "owned_adapter_component_sha256": {"$ref": "#/$defs/Hex64"},
        "frozen_spec_subjects": {"type": "array", "minItems": 7, "maxItems": 7, "items": {"$ref": "#/$defs/ByteSubject"}}, "source_vector_root_digest": {"$ref": "#/$defs/Hex64"}, "bake_input_root_digest": {"$ref": "#/$defs/Hex64"},
        "results": {"type": "array", "minItems": 32, "maxItems": 32, "items": {"$ref": "#/$defs/VectorResult"}}, "result_count": {"const": 32}, "result_roster_digest": {"$ref": "#/$defs/Hex64"}, "receipt_digest": {"$ref": "#/$defs/Hex64"}
      }
    },
    "VectorProof": {
      "type": "object", "additionalProperties": false,
      "required": ["schema", "vector_ordinal", "vector_id", "source_sha256", "bake_input_digest", "converted_fact_roster_digest", "parser_a_result_digest", "parser_b_result_digest", "verifier_result_digest", "token_tuple_bytes_base64", "token_tuple_sha256", "semantic_tuple_bytes_base64", "semantic_tuple_sha256", "token_count", "candidate_count", "coverage_byte_count", "diff_rows", "diff_count", "verdict", "proof_digest"],
      "properties": {
        "schema": {"const": "cut4.r20.vector_proof.v1"}, "vector_ordinal": {"type": "integer", "minimum": 0, "maximum": 31}, "vector_id": {"type": "string", "minLength": 1}, "source_sha256": {"$ref": "#/$defs/Hex64"}, "bake_input_digest": {"$ref": "#/$defs/Hex64"}, "converted_fact_roster_digest": {"$ref": "#/$defs/Hex64"},
        "parser_a_result_digest": {"$ref": "#/$defs/Hex64"}, "parser_b_result_digest": {"$ref": "#/$defs/Hex64"}, "verifier_result_digest": {"$ref": "#/$defs/Hex64"},
        "token_tuple_bytes_base64": {"type": "string"}, "token_tuple_sha256": {"$ref": "#/$defs/Hex64"}, "semantic_tuple_bytes_base64": {"type": "string"}, "semantic_tuple_sha256": {"$ref": "#/$defs/Hex64"},
        "token_count": {"type": "integer", "minimum": 1}, "candidate_count": {"type": "integer", "minimum": 0}, "coverage_byte_count": {"type": "integer", "minimum": 0},
        "diff_rows": {"type": "array", "maxItems": 0}, "diff_count": {"const": 0}, "verdict": {"const": "EXACT_EQUAL"}, "proof_digest": {"$ref": "#/$defs/Hex64"}
      }
    },
    "NegativeProofReceipt": {
      "type": "object", "additionalProperties": false,
      "required": ["schema", "parser_a_execution_subject_admission_digest", "parser_a_execution_sha256", "parser_a_receipt_digest", "parser_b_execution_subject_admission_digest", "parser_b_execution_sha256", "parser_b_receipt_digest", "verifier_execution_subject_admission_digest", "verifier_execution_sha256", "verifier_receipt_digest", "dependency_closure_digests", "source_vector_root_digest", "bake_input_root_digest", "proof_rows", "proof_count", "proof_roster_digest", "total_source_bytes", "total_token_count", "total_candidate_count", "total_coverage_bytes", "total_diff_count", "proved_none_vector_ids", "receipt_digest"],
      "properties": {
        "schema": {"const": "cut4.r20.negative_proof_receipt.v1"},
        "parser_a_execution_subject_admission_digest": {"$ref": "#/$defs/Hex64"}, "parser_a_execution_sha256": {"$ref": "#/$defs/Hex64"}, "parser_a_receipt_digest": {"$ref": "#/$defs/Hex64"},
        "parser_b_execution_subject_admission_digest": {"$ref": "#/$defs/Hex64"}, "parser_b_execution_sha256": {"$ref": "#/$defs/Hex64"}, "parser_b_receipt_digest": {"$ref": "#/$defs/Hex64"},
        "verifier_execution_subject_admission_digest": {"$ref": "#/$defs/Hex64"}, "verifier_execution_sha256": {"$ref": "#/$defs/Hex64"}, "verifier_receipt_digest": {"$ref": "#/$defs/Hex64"},
        "dependency_closure_digests": {"type": "array", "minItems": 3, "maxItems": 3, "items": {"$ref": "#/$defs/Hex64"}}, "source_vector_root_digest": {"$ref": "#/$defs/Hex64"}, "bake_input_root_digest": {"$ref": "#/$defs/Hex64"},
        "proof_rows": {"type": "array", "minItems": 32, "maxItems": 32, "items": {"$ref": "#/$defs/VectorProof"}}, "proof_count": {"const": 32}, "proof_roster_digest": {"$ref": "#/$defs/Hex64"},
        "total_source_bytes": {"const": 200}, "total_token_count": {"const": 121}, "total_candidate_count": {"const": 31}, "total_coverage_bytes": {"const": 200}, "total_diff_count": {"const": 0},
        "proved_none_vector_ids": {"type": "array", "minItems": 1, "uniqueItems": true, "items": {"type": "string"}}, "receipt_digest": {"$ref": "#/$defs/Hex64"}
      }
    }
  },
  "oneOf": [{"$ref": "#/$defs/DependencyClosureReceipt"}, {"$ref": "#/$defs/VectorResult"}, {"$ref": "#/$defs/ExecutionReceipt"}, {"$ref": "#/$defs/VectorProof"}, {"$ref": "#/$defs/NegativeProofReceipt"}]
}
```

All body/roster digests use the object's literal schema domain and exclude only
the final digest field. Result row `i` must copy vector row `i` source bytes
and the referenced schema-valid BAKE input, then reproduce sizes/hashes.
Execution receipts bind exact admitted package and dependency-receipt subjects;
their engines and all 32 result engines equal. The three owned adapter hashes
must be pairwise different. Dependency closure intersection after removing the
literal allowed shared sets is empty. Verifier closure and execution have no
edge to either parser receipt; only the later negative proof consumes all
three. Each `VectorProof` copies the three source/BAKE/fact joins, independently
checks tuple byte equality, and records exact common bytes. `PROVED_NONE`
equals precisely the full-coverage, zero-semantic vector IDs after three-way
fact accounting; it is not a provider/global zero claim.

The digest preimages are closed by this exact field-order registry. `BODY`
means CJ of those fields in the displayed order (canonical JSON still sorts
object keys); `ROSTER` means CJ of the exact ordered child array. No unnamed
field or digest-only shortcut is an input.

```json
{
  "schema": "cut4.r20.recognition_preimage_registry.v1",
  "rows": [
    ["DependencyClosureReceipt","cut4.r20.dependency_closure_receipt.v1",["schema","engine","package_subject_admission_digest","package_sha256","owned_component_rows","module_rows","import_edges","module_roster_digest","edge_roster_digest","unknown_dynamic_import_count","forbidden_cross_engine_edge_count"],"closure_digest"],
    ["VectorResult","cut4.r20.vector_result.v1",["schema","engine","vector_ordinal","vector_id","source_byte_size","source_sha256","bake_input_digest","converted_fact_roster_digest","token_tuple_bytes_base64","token_tuple_byte_size","token_tuple_sha256","token_count","semantic_tuple_bytes_base64","semantic_tuple_byte_size","semantic_tuple_sha256","candidate_count","coverage_byte_count","coverage_gap_count","coverage_overlap_count"],"result_digest"],
    ["ExecutionReceipt","cut4.r20.execution_receipt.v1",["schema","engine","execution_occurrence_digest","package_subject_admission_digest","package_sha256","dependency_receipt_subject_admission_digest","dependency_closure_digest","owned_adapter_component_sha256","frozen_spec_subjects","source_vector_root_digest","bake_input_root_digest","results","result_count","result_roster_digest"],"receipt_digest"],
    ["VectorProof","cut4.r20.vector_proof.v1",["schema","vector_ordinal","vector_id","source_sha256","bake_input_digest","converted_fact_roster_digest","parser_a_result_digest","parser_b_result_digest","verifier_result_digest","token_tuple_bytes_base64","token_tuple_sha256","semantic_tuple_bytes_base64","semantic_tuple_sha256","token_count","candidate_count","coverage_byte_count","diff_rows","diff_count","verdict"],"proof_digest"],
    ["NegativeProofReceipt","cut4.r20.negative_proof_receipt.v1",["schema","parser_a_execution_subject_admission_digest","parser_a_execution_sha256","parser_a_receipt_digest","parser_b_execution_subject_admission_digest","parser_b_execution_sha256","parser_b_receipt_digest","verifier_execution_subject_admission_digest","verifier_execution_sha256","verifier_receipt_digest","dependency_closure_digests","source_vector_root_digest","bake_input_root_digest","proof_rows","proof_count","proof_roster_digest","total_source_bytes","total_token_count","total_candidate_count","total_coverage_bytes","total_diff_count","proved_none_vector_ids"],"receipt_digest"]
  ],
  "row_count": 5,
  "roster_equations": [
    ["ExecutionReceipt.result_roster_digest","D(cut4.r20.result_roster.v1,[results[0].result_digest,...,results[31].result_digest])"],
    ["NegativeProofReceipt.proof_roster_digest","D(cut4.r20.proof_roster.v1,[proof_rows[0].proof_digest,...,proof_rows[31].proof_digest])"],
    ["DependencyClosureReceipt.module_roster_digest","D(cut4.r20.module_roster.v1,module_rows sorted by module_id)"],
    ["DependencyClosureReceipt.edge_roster_digest","D(cut4.r20.import_edge_roster.v1,import_edges sorted by source_module_id,target_module_id,import_kind,ast_span_digest)"]
  ]
}
```

## 3. Inhabitable provider-specific Kp map

### 3.1 Binding common key versus provider key

R20 removes the impossible single binding Kp. Common fields live in
`BindingKey`; every fixed slot owns a distinct `ProviderKp`. The plan root,
Kp map, exact receipt byte envelopes, and facts all have the same fixed
three-slot order.

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "cut4.r20.provider_binding.schema.v1",
  "$defs": {
    "Hex64": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
    "BindingKey": {
      "type": "object", "additionalProperties": false,
      "required": ["schema", "private_plan_row_id", "consumer_row_id", "consumer_id", "source_snapshot_digest", "provider_plan_roster_digest", "binding_key_digest"],
      "properties": {"schema": {"const": "cut4.r20.binding_key.v1"}, "private_plan_row_id": {"type": "string", "minLength": 1}, "consumer_row_id": {"type": "string", "minLength": 1}, "consumer_id": {"type": "string", "minLength": 1}, "source_snapshot_digest": {"$ref": "#/$defs/Hex64"}, "provider_plan_roster_digest": {"$ref": "#/$defs/Hex64"}, "binding_key_digest": {"$ref": "#/$defs/Hex64"}}
    },
    "ProviderKp": {
      "type": "object", "additionalProperties": false,
      "required": ["schema", "binding_key_digest", "private_plan_row_id", "consumer_row_id", "consumer_id", "provider_id", "provider_ordinal", "applicability_predicate_id", "applicability_result", "selection_predicate_id", "selection_result", "invocation_digest", "plan_digest", "source_snapshot_digest", "provider_kp_digest"],
      "properties": {
        "schema": {"const": "cut4.r20.provider_kp.v1"}, "binding_key_digest": {"$ref": "#/$defs/Hex64"}, "private_plan_row_id": {"type": "string", "minLength": 1}, "consumer_row_id": {"type": "string", "minLength": 1}, "consumer_id": {"type": "string", "minLength": 1},
        "provider_id": {"enum": ["source_graph", "build_probe", "daml_source_graph"]}, "provider_ordinal": {"type": "integer", "minimum": 0, "maximum": 2},
        "applicability_predicate_id": {"type": "string", "minLength": 1}, "applicability_result": {"type": "boolean"}, "selection_predicate_id": {"type": "string", "minLength": 1}, "selection_result": {"type": "boolean"},
        "invocation_digest": {"$ref": "#/$defs/Hex64"}, "plan_digest": {"$ref": "#/$defs/Hex64"}, "source_snapshot_digest": {"$ref": "#/$defs/Hex64"}, "provider_kp_digest": {"$ref": "#/$defs/Hex64"}
      }
    },
    "ProviderPlan": {
      "type": "object", "additionalProperties": false,
      "required": ["schema", "provider_id", "provider_ordinal", "applicability_predicate_id", "selection_predicate_id", "source_snapshot_digest", "configuration_digest", "plan_digest"],
      "properties": {"schema": {"const": "cut4.r20.provider_plan.v1"}, "provider_id": {"enum": ["source_graph", "build_probe", "daml_source_graph"]}, "provider_ordinal": {"type": "integer", "minimum": 0, "maximum": 2}, "applicability_predicate_id": {"type": "string", "minLength": 1}, "selection_predicate_id": {"type": "string", "minLength": 1}, "source_snapshot_digest": {"$ref": "#/$defs/Hex64"}, "configuration_digest": {"$ref": "#/$defs/Hex64"}, "plan_digest": {"$ref": "#/$defs/Hex64"}}
    },
    "ProviderPlanRoot": {
      "type": "object", "additionalProperties": false,
      "required": ["schema", "binding_common_fields_digest", "plans", "plan_roster_digest", "root_digest"],
      "properties": {"schema": {"const": "cut4.r20.provider_plan_root.v1"}, "binding_common_fields_digest": {"$ref": "#/$defs/Hex64"}, "plans": {"type": "array", "minItems": 3, "maxItems": 3, "items": {"$ref": "#/$defs/ProviderPlan"}}, "plan_roster_digest": {"$ref": "#/$defs/Hex64"}, "root_digest": {"$ref": "#/$defs/Hex64"}}
    },
    "PredicateEvidence": {
      "type": "object", "additionalProperties": false,
      "required": ["schema", "provider_kp", "predicate_kind", "predicate_id", "result", "plan_digest", "source_snapshot_digest", "evidence_bytes_base64", "evidence_byte_size", "evidence_sha256", "evidence_digest"],
      "properties": {"schema": {"const": "cut4.r20.predicate_evidence.v1"}, "provider_kp": {"$ref": "#/$defs/ProviderKp"}, "predicate_kind": {"enum": ["APPLICABILITY", "SELECTION"]}, "predicate_id": {"type": "string", "minLength": 1}, "result": {"type": "boolean"}, "plan_digest": {"$ref": "#/$defs/Hex64"}, "source_snapshot_digest": {"$ref": "#/$defs/Hex64"}, "evidence_bytes_base64": {"type": "string"}, "evidence_byte_size": {"type": "integer", "minimum": 1}, "evidence_sha256": {"$ref": "#/$defs/Hex64"}, "evidence_digest": {"$ref": "#/$defs/Hex64"}}
    },
    "PayloadRecord": {
      "type": "object", "additionalProperties": false,
      "required": ["schema", "payload_id", "ordinal", "content_type", "bytes_base64", "byte_size", "sha256", "payload_digest"],
      "properties": {"schema": {"const": "cut4.r20.payload_record.v1"}, "payload_id": {"type": "string", "minLength": 1}, "ordinal": {"type": "integer", "minimum": 0}, "content_type": {"enum": ["application/json", "text/plain", "application/octet-stream"]}, "bytes_base64": {"type": "string"}, "byte_size": {"type": "integer", "minimum": 0}, "sha256": {"$ref": "#/$defs/Hex64"}, "payload_digest": {"$ref": "#/$defs/Hex64"}}
    },
    "ProviderTerminal": {
      "type": "object", "additionalProperties": false,
      "required": ["schema", "provider_kp", "plan_digest", "invocation_digest", "invocation_state", "exit_code", "exhausted", "payloads", "evidence_bytes_base64", "evidence_byte_size", "evidence_sha256", "terminal_digest"],
      "properties": {"schema": {"const": "cut4.r20.provider_terminal.v1"}, "provider_kp": {"$ref": "#/$defs/ProviderKp"}, "plan_digest": {"$ref": "#/$defs/Hex64"}, "invocation_digest": {"$ref": "#/$defs/Hex64"}, "invocation_state": {"enum": ["NOT_INVOKED", "COMPLETED", "APPROXIMATED", "FAILED", "TIMED_OUT", "MALFORMED"]}, "exit_code": {"type": "integer"}, "exhausted": {"type": "boolean"}, "payloads": {"type": "array", "items": {"$ref": "#/$defs/PayloadRecord"}}, "evidence_bytes_base64": {"type": "string"}, "evidence_byte_size": {"type": "integer", "minimum": 1}, "evidence_sha256": {"$ref": "#/$defs/Hex64"}, "terminal_digest": {"$ref": "#/$defs/Hex64"}}
    },
    "ExplicitZeroProof": {
      "type": "object", "additionalProperties": false,
      "required": ["schema", "provider_kp", "provider_terminal_digest", "query_id", "invocation_digest", "exhausted", "payload_count", "cursor_out", "evidence_bytes_base64", "evidence_byte_size", "evidence_sha256", "proof_digest"],
      "properties": {"schema": {"const": "cut4.r20.explicit_zero_proof.v1"}, "provider_kp": {"$ref": "#/$defs/ProviderKp"}, "provider_terminal_digest": {"$ref": "#/$defs/Hex64"}, "query_id": {"type": "string", "minLength": 1}, "invocation_digest": {"$ref": "#/$defs/Hex64"}, "exhausted": {"const": true}, "payload_count": {"const": 0}, "cursor_out": {"type": "string", "minLength": 1}, "evidence_bytes_base64": {"type": "string"}, "evidence_byte_size": {"type": "integer", "minimum": 1}, "evidence_sha256": {"$ref": "#/$defs/Hex64"}, "proof_digest": {"$ref": "#/$defs/Hex64"}}
    },
    "ProviderReceipt": {
      "type": "object", "additionalProperties": false,
      "required": ["schema", "provider_kp", "applicability_evidence_digest", "selection_evidence_digest", "terminal", "status", "payload_count", "payload_roster_digest", "explicit_zero_proof", "debt_code", "receipt_digest"],
      "properties": {"schema": {"const": "cut4.r20.provider_receipt.v1"}, "provider_kp": {"$ref": "#/$defs/ProviderKp"}, "applicability_evidence_digest": {"$ref": "#/$defs/Hex64"}, "selection_evidence_digest": {"$ref": "#/$defs/Hex64"}, "terminal": {"$ref": "#/$defs/ProviderTerminal"}, "status": {"enum": ["NOT_APPLICABLE", "NOT_SELECTED", "SUCCESS", "SUCCESS_EMPTY", "DEBT", "FAILURE", "TIMEOUT", "MALFORMED"]}, "payload_count": {"type": "integer", "minimum": 0}, "payload_roster_digest": {"$ref": "#/$defs/Hex64"}, "explicit_zero_proof": {"oneOf": [{"type": "null"}, {"$ref": "#/$defs/ExplicitZeroProof"}]}, "debt_code": {"enum": ["NONE", "APPROXIMATION", "EXECUTION_FAILURE", "DEADLINE", "SCHEMA_MALFORMED"]}, "receipt_digest": {"$ref": "#/$defs/Hex64"}}
    },
    "ReceiptEnvelope": {
      "type": "object", "additionalProperties": false,
      "required": ["provider_id", "provider_ordinal", "receipt", "receipt_bytes_base64", "receipt_byte_size", "receipt_sha256", "receipt_digest", "envelope_digest"],
      "properties": {"provider_id": {"enum": ["source_graph", "build_probe", "daml_source_graph"]}, "provider_ordinal": {"type": "integer", "minimum": 0, "maximum": 2}, "receipt": {"$ref": "#/$defs/ProviderReceipt"}, "receipt_bytes_base64": {"type": "string"}, "receipt_byte_size": {"type": "integer", "minimum": 1}, "receipt_sha256": {"$ref": "#/$defs/Hex64"}, "receipt_digest": {"$ref": "#/$defs/Hex64"}, "envelope_digest": {"$ref": "#/$defs/Hex64"}}
    },
    "KpMapEntry": {
      "type": "object", "additionalProperties": false,
      "required": ["provider_id", "provider_ordinal", "provider_kp", "entry_digest"],
      "properties": {"provider_id": {"enum": ["source_graph", "build_probe", "daml_source_graph"]}, "provider_ordinal": {"type": "integer", "minimum": 0, "maximum": 2}, "provider_kp": {"$ref": "#/$defs/ProviderKp"}, "entry_digest": {"$ref": "#/$defs/Hex64"}}
    },
    "BakeFactRow": {
      "type": "object", "additionalProperties": false,
      "required": ["schema", "provider_kp", "provider_receipt_digest", "fact_ordinal", "fact_kind", "subject_id", "object_id", "raw_bytes_base64", "raw_byte_size", "raw_sha256", "fact_id", "fact_digest"],
      "properties": {"schema": {"const": "cut4.r20.bake_fact.v1"}, "provider_kp": {"$ref": "#/$defs/ProviderKp"}, "provider_receipt_digest": {"$ref": "#/$defs/Hex64"}, "fact_ordinal": {"type": "integer", "minimum": 0}, "fact_kind": {"enum": ["GRAPH_NODE", "GRAPH_EDGE", "PROBE_RESULT", "TYPED_DEBT"]}, "subject_id": {"type": "string", "minLength": 1}, "object_id": {"type": "string", "minLength": 1}, "raw_bytes_base64": {"type": "string"}, "raw_byte_size": {"type": "integer", "minimum": 1}, "raw_sha256": {"$ref": "#/$defs/Hex64"}, "fact_id": {"type": "string", "pattern": "^bf_[0-9a-f]{64}$"}, "fact_digest": {"$ref": "#/$defs/Hex64"}}
    },
    "BakeBinding": {
      "type": "object", "additionalProperties": false,
      "required": ["schema", "binding_key", "provider_plan_root", "kp_map", "kp_map_digest", "provider_receipts", "provider_receipt_roster_digest", "facts", "fact_count", "fact_roster_digest", "binding_digest"],
      "properties": {"schema": {"const": "cut4.r20.bake_binding.v1"}, "binding_key": {"$ref": "#/$defs/BindingKey"}, "provider_plan_root": {"$ref": "#/$defs/ProviderPlanRoot"}, "kp_map": {"type": "array", "minItems": 3, "maxItems": 3, "items": {"$ref": "#/$defs/KpMapEntry"}}, "kp_map_digest": {"$ref": "#/$defs/Hex64"}, "provider_receipts": {"type": "array", "minItems": 3, "maxItems": 3, "items": {"$ref": "#/$defs/ReceiptEnvelope"}}, "provider_receipt_roster_digest": {"$ref": "#/$defs/Hex64"}, "facts": {"type": "array", "items": {"$ref": "#/$defs/BakeFactRow"}}, "fact_count": {"type": "integer", "minimum": 0}, "fact_roster_digest": {"$ref": "#/$defs/Hex64"}, "binding_digest": {"$ref": "#/$defs/Hex64"}}
    }
  },
  "oneOf": [{"$ref": "#/$defs/BindingKey"}, {"$ref": "#/$defs/ProviderKp"}, {"$ref": "#/$defs/ProviderPlanRoot"}, {"$ref": "#/$defs/PredicateEvidence"}, {"$ref": "#/$defs/ProviderTerminal"}, {"$ref": "#/$defs/ExplicitZeroProof"}, {"$ref": "#/$defs/ProviderReceipt"}, {"$ref": "#/$defs/BakeBinding"}]
}
```

Exact slot order is `(source_graph,0),(build_probe,1),
(daml_source_graph,2)` in plans, Kp map, receipts, and provider-grouped facts.
`BindingKey` equals the five true common fields and its BODY digest. Each Kp
copies those common fields/digest but has its own provider/ordinal,
predicates/results, invocation, and plan. Map entry, plan, receipt envelope,
receipt object, terminal, predicate evidence, zero proof, and every fact in
one slot must carry the same provider-specific Kp bytes; Kps in different
slots must have different provider ID/ordinal and therefore different digests.
Each receipt envelope bytes equal `CJ(receipt)` and reproduce size/SHA/digest.
The three plan digests reproduce the plan-root roster digest used by the
binding key. No binding-wide provider Kp exists.

The inherited status table remains exact. `SUCCESS_EMPTY` alone has a non-null
typed proof and requires selected/applicable, completed/exit-zero/exhausted,
zero payloads, nonempty cursor, and exact invocation evidence. Other statuses
require null. Every fixed slot emits a nonempty receipt envelope.

### 3.2 Closed downstream semantic carriers

R20 removes the open `SemanticData.schema_id` wrapper. These are the complete
versioned carriers; no external schema-store prose is needed.

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "cut4.r20.semantic_carriers.schema.v1",
  "$defs": {
    "Hex64": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
    "BindingKey": {"$ref": "cut4.r20.provider_binding.schema.v1#/$defs/BindingKey"},
    "ProviderKp": {"$ref": "cut4.r20.provider_binding.schema.v1#/$defs/ProviderKp"},
    "PayloadRecord": {"$ref": "cut4.r20.provider_binding.schema.v1#/$defs/PayloadRecord"},
    "KpMapEntry": {"$ref": "cut4.r20.provider_binding.schema.v1#/$defs/KpMapEntry"},
    "TypedValue": {
      "type": "object", "additionalProperties": false,
      "required": ["value_kind", "bool_value", "int_value", "utf8_value", "bytes_base64", "value_digest"],
      "properties": {"value_kind": {"enum": ["NULL", "BOOL", "INT", "COUNT", "UTF8", "BYTES"]}, "bool_value": {"type": ["boolean", "null"]}, "int_value": {"type": ["integer", "null"]}, "utf8_value": {"type": ["string", "null"]}, "bytes_base64": {"type": ["string", "null"]}, "value_digest": {"$ref": "#/$defs/Hex64"}}
    },
    "ProviderPrivateV6": {
      "type": "object", "additionalProperties": false,
      "required": ["schema", "provider_kp", "provider_receipt_envelope_digest", "payloads", "payload_roster_digest", "private_status", "private_digest"],
      "properties": {"schema": {"const": "cut4.r20.provider_private.v6"}, "provider_kp": {"$ref": "#/$defs/ProviderKp"}, "provider_receipt_envelope_digest": {"$ref": "#/$defs/Hex64"}, "payloads": {"type": "array", "items": {"$ref": "#/$defs/PayloadRecord"}}, "payload_roster_digest": {"$ref": "#/$defs/Hex64"}, "private_status": {"enum": ["NOT_APPLICABLE", "NOT_SELECTED", "SUCCESS", "SUCCESS_EMPTY", "DEBT", "FAILURE", "TIMEOUT", "MALFORMED"]}, "private_digest": {"$ref": "#/$defs/Hex64"}}
    },
    "NormalizedSemanticRow": {
      "type": "object", "additionalProperties": false,
      "required": ["schema", "provider_kp", "payload_id", "payload_digest", "normalizer_evidence_digest", "semantic_class", "subject_id", "object_id", "normalized_bytes_base64", "normalized_byte_size", "normalized_sha256", "debt_code", "row_digest"],
      "properties": {"schema": {"const": "cut4.r20.normalized_semantic_row.v1"}, "provider_kp": {"$ref": "#/$defs/ProviderKp"}, "payload_id": {"type": "string", "minLength": 1}, "payload_digest": {"$ref": "#/$defs/Hex64"}, "normalizer_evidence_digest": {"$ref": "#/$defs/Hex64"}, "semantic_class": {"enum": ["GRAPH_NODE", "GRAPH_EDGE", "PROBE_RESULT", "PATH_REFERENCE", "CONTENT_INSTRUCTION", "TYPED_DEBT", "NOT_APPLICABLE"]}, "subject_id": {"type": "string"}, "object_id": {"type": "string"}, "normalized_bytes_base64": {"type": "string"}, "normalized_byte_size": {"type": "integer", "minimum": 0}, "normalized_sha256": {"$ref": "#/$defs/Hex64"}, "debt_code": {"enum": ["NONE", "NORMALIZER_ZERO", "MALFORMED", "UNSUPPORTED"]}, "row_digest": {"$ref": "#/$defs/Hex64"}}
    },
    "ExpectedObservedDiff": {
      "type": "object", "additionalProperties": false,
      "required": ["schema", "binding_key", "expected_kp_map", "observed_kp_map", "field_path", "diff_kind", "expected_value", "observed_value", "diff_digest"],
      "properties": {"schema": {"const": "cut4.r20.expected_observed_diff.v1"}, "binding_key": {"$ref": "#/$defs/BindingKey"}, "expected_kp_map": {"type": "array", "minItems": 3, "maxItems": 3, "items": {"$ref": "#/$defs/KpMapEntry"}}, "observed_kp_map": {"type": "array", "minItems": 3, "maxItems": 3, "items": {"$ref": "#/$defs/KpMapEntry"}}, "field_path": {"type": "string", "minLength": 1}, "diff_kind": {"enum": ["MISSING", "EXTRA", "VALUE", "TYPE", "ORDER", "COUNT", "BOOL", "INT", "ZERO_PROOF", "KP_MAP_MISMATCH"]}, "expected_value": {"$ref": "#/$defs/TypedValue"}, "observed_value": {"$ref": "#/$defs/TypedValue"}, "diff_digest": {"$ref": "#/$defs/Hex64"}}
    },
    "M4": {
      "type": "object", "additionalProperties": false,
      "required": ["schema", "binding_key", "kp_map_digest", "bake_binding_digest", "provider_private_roster_digest", "normalized_roster_digest", "normalizer_receipt_digest", "diff_roster_digest", "public_output_roster_digest", "ack_state_digest", "m4_digest"],
      "properties": {"schema": {"const": "cut4.r20.m4.v1"}, "binding_key": {"$ref": "#/$defs/BindingKey"}, "kp_map_digest": {"$ref": "#/$defs/Hex64"}, "bake_binding_digest": {"$ref": "#/$defs/Hex64"}, "provider_private_roster_digest": {"$ref": "#/$defs/Hex64"}, "normalized_roster_digest": {"$ref": "#/$defs/Hex64"}, "normalizer_receipt_digest": {"$ref": "#/$defs/Hex64"}, "diff_roster_digest": {"$ref": "#/$defs/Hex64"}, "public_output_roster_digest": {"$ref": "#/$defs/Hex64"}, "ack_state_digest": {"$ref": "#/$defs/Hex64"}, "m4_digest": {"$ref": "#/$defs/Hex64"}}
    },
    "R4": {
      "type": "object", "additionalProperties": false,
      "required": ["schema", "binding_key", "kp_map_digest", "m4_digest", "publication_link_digest", "decision", "r4_digest"],
      "properties": {"schema": {"const": "cut4.r20.r4.v1"}, "binding_key": {"$ref": "#/$defs/BindingKey"}, "kp_map_digest": {"$ref": "#/$defs/Hex64"}, "m4_digest": {"$ref": "#/$defs/Hex64"}, "publication_link_digest": {"$ref": "#/$defs/Hex64"}, "decision": {"enum": ["COMPLETE", "REJECT"]}, "r4_digest": {"$ref": "#/$defs/Hex64"}}
    },
    "CompletionReceipt": {
      "type": "object", "additionalProperties": false,
      "required": ["schema", "binding_key", "kp_map", "kp_map_digest", "r4_digest", "terminal_journal_record_digest", "committed_publication_receipt_digest", "publication_link_digest", "ack_state_digest", "provider_private_roster_digest", "normalizer_receipt_digest", "diff_roster_digest", "completion_state", "completion_digest"],
      "properties": {"schema": {"const": "cut4.r20.completion_receipt.v1"}, "binding_key": {"$ref": "#/$defs/BindingKey"}, "kp_map": {"type": "array", "minItems": 3, "maxItems": 3, "items": {"$ref": "#/$defs/KpMapEntry"}}, "kp_map_digest": {"$ref": "#/$defs/Hex64"}, "r4_digest": {"$ref": "#/$defs/Hex64"}, "terminal_journal_record_digest": {"$ref": "#/$defs/Hex64"}, "committed_publication_receipt_digest": {"$ref": "#/$defs/Hex64"}, "publication_link_digest": {"$ref": "#/$defs/Hex64"}, "ack_state_digest": {"$ref": "#/$defs/Hex64"}, "provider_private_roster_digest": {"$ref": "#/$defs/Hex64"}, "normalizer_receipt_digest": {"$ref": "#/$defs/Hex64"}, "diff_roster_digest": {"$ref": "#/$defs/Hex64"}, "completion_state": {"const": "COMPLETE"}, "completion_digest": {"$ref": "#/$defs/Hex64"}}
    }
  },
  "oneOf": [{"$ref": "#/$defs/ProviderPrivateV6"}, {"$ref": "#/$defs/NormalizedSemanticRow"}, {"$ref": "#/$defs/ExpectedObservedDiff"}, {"$ref": "#/$defs/M4"}, {"$ref": "#/$defs/R4"}, {"$ref": "#/$defs/CompletionReceipt"}]
}
```

Per-provider private/normalized rows equal only their owning provider Kp.
Aggregate diff/M4/R4/completion rows bind the common key plus the exact
three-entry Kp-map digest. Expected and observed maps must be byte-equal for a
clean comparison; `KP_MAP_MISMATCH` is rejecting. Typed values close bool,
int/count, text, bytes, and null diffs. Every child object/byte payload is
recursively validated before M4/R4/completion; stale/unanchored/zero-byte
children cannot complete.

## 4. Every mutation operation frozen before the test

### 4.1 Deterministic full catalog

R20 uses the exact ordered 256 IDs from authenticated R15 (96), R16 (32), R17
(64), and R19 (64); their CJ list is 9,308 bytes/SHA
`dba824fd070bc64ef5ed44626f5744f4320f7ee0f39a3f9c455e65c45ba7103e`.
The following closed generator fixes source bytes, selector, operation,
operand, mutated bytes, and expected code for every ordinal. None is chosen by
a future test author.

```json
{
  "schema": "cut4.r20.frozen_mutation_generator.v1",
  "generator_id": "cut4.r20.mutation_generator.v1",
  "ordered_id_source": ["cut4.r15.red_mutation_denominator.v1", "cut4.r16.mutation_additions.v1", "cut4.r17.mutation_additions.v1", "cut4.r19.mutation_additions.v1"],
  "ordered_id_count": 256,
  "ordered_id_cj_byte_size": 9308,
  "ordered_id_cj_sha256": "dba824fd070bc64ef5ed44626f5744f4320f7ee0f39a3f9c455e65c45ba7103e",
  "operation_cycle": ["REPLACE", "DELETE", "INSERT", "DUPLICATE", "REORDER", "RELABEL", "TRUNCATE", "CORRUPT"],
  "source_object_formula": {"case_id": "ID", "control": "CONTROL_ || first16(SHA256(U(ID)))", "order": [0,1,2], "payload": {"original": "ORIGINAL_ || first16(SHA256(U(ID)))", "slot": ""}},
  "source_identity_formula": "review_fixtures/cut4_r20_mutation_sources/{ordinal:03d}.json",
  "selector_operation_rows": [
    [0,"JSON_VALUE","/payload/original","REPLACE","CJ(\"MUTATED_\" || h16)",0],
    [1,"JSON_MEMBER","/payload/original including trailing comma","DELETE","empty",0],
    [2,"JSON_CONTENT_POINT","/payload/slot#content_start","INSERT","U(\"INS_\" || h16)",0],
    [3,"JSON_VALUE","/control","DUPLICATE","empty",1],
    [4,"JSON_ARRAY","/order","REORDER","CJ([0,2])",0],
    [5,"JSON_STRING","/payload/original","RELABEL","CJ(\"RELABEL_\" || h16)",0],
    [6,"FILE_SUFFIX","LAST_BYTE","TRUNCATE","empty",0],
    [7,"JSON_CONTENT_BYTE","/control#0","CORRUPT","01",0]
  ],
  "fixture_source_bundle_cj_byte_size": 145130,
  "fixture_source_bundle_cj_sha256": "a350fd1705c6e616d360f523fee79226de44dc3a8b8dce27ea6d331e3d2d5ab3",
  "fixture_source_total_bytes": 41307,
  "source_map_roster_cj_byte_size": 137886,
  "source_map_roster_cj_sha256": "ec80736f7b7c189621f434e09308915bb7ea9591a51799c7cde25adccebdacca",
  "mutation_catalog_cj_byte_size": 277546,
  "mutation_catalog_cj_sha256": "b99c77d4e3b48d10c82dd407d116b3aebc1a222983d4b6a47c88496d90ef026c",
  "operation_counts": [["REPLACE",32],["DELETE",32],["INSERT",32],["DUPLICATE",32],["REORDER",32],["RELABEL",32],["TRUNCATE",32],["CORRUPT",32]]
}
```

For ID at ordinal `i`, `h16=first16(H(U(ID)))` and source bytes are CJ of the
displayed source object. The selector is row `i mod 8`; its byte span is found
by strict canonical-JSON mapping and must match exactly once. Lowering is the
R18 byte operation, with REORDER moving array index 0 to 2 (result `[1,2,0]`)
and CORRUPT XORing the selected byte with `0x01`. The mutation row contains
ID/ordinal, exact source identity/hex/size/SHA, selector kind/value/start/end/
selected SHA, operation, operand hex, operation parameter, mutated size/SHA,
`expected_rejection_code="R20_"+upper(first16(H(U("code")||0x00||U(ID))))`, and
`row_digest=H(CJ(row without row_digest))`. The catalog is CJ of
`{schema:"cut4.r20.frozen_mutation_catalog.v1",generator_id,rows,row_count}`.
All 256 mutated bytes differ from source bytes and all row tuples are unique.
The exact catalog size/SHA above is a complete compact commitment to every
operation preimage, not only its name.

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "cut4.r20.mutation_catalog.schema.v1",
  "$defs": {
    "Hex64": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
    "Selector": {"type": "object", "additionalProperties": false, "required": ["kind", "value", "byte_start", "byte_end", "selected_sha256"], "properties": {"kind": {"enum": ["JSON_VALUE", "JSON_MEMBER", "JSON_CONTENT_POINT", "JSON_ARRAY", "JSON_STRING", "FILE_SUFFIX", "JSON_CONTENT_BYTE"]}, "value": {"type": "string", "minLength": 1}, "byte_start": {"type": "integer", "minimum": 0}, "byte_end": {"type": "integer", "minimum": 0}, "selected_sha256": {"$ref": "#/$defs/Hex64"}}},
    "MutationRow": {"type": "object", "additionalProperties": false, "required": ["mutation_id", "ordinal", "source_identity", "source_bytes_hex", "source_byte_size", "source_sha256", "selector", "operation", "operand_hex", "operation_parameter", "mutated_byte_size", "mutated_sha256", "expected_rejection_code", "row_digest"], "properties": {"mutation_id": {"type": "string", "minLength": 1}, "ordinal": {"type": "integer", "minimum": 0, "maximum": 255}, "source_identity": {"type": "string", "minLength": 1}, "source_bytes_hex": {"type": "string", "pattern": "^(?:[0-9a-f]{2})+$"}, "source_byte_size": {"type": "integer", "minimum": 1}, "source_sha256": {"$ref": "#/$defs/Hex64"}, "selector": {"$ref": "#/$defs/Selector"}, "operation": {"enum": ["REPLACE", "DELETE", "INSERT", "DUPLICATE", "REORDER", "RELABEL", "TRUNCATE", "CORRUPT"]}, "operand_hex": {"type": "string", "pattern": "^(?:[0-9a-f]{2})*$"}, "operation_parameter": {"type": "integer", "minimum": 0, "maximum": 1}, "mutated_byte_size": {"type": "integer", "minimum": 1}, "mutated_sha256": {"$ref": "#/$defs/Hex64"}, "expected_rejection_code": {"type": "string", "pattern": "^R20_[0-9A-F]{16}$"}, "row_digest": {"$ref": "#/$defs/Hex64"}}},
    "Catalog": {"type": "object", "additionalProperties": false, "required": ["schema", "generator_id", "rows", "row_count"], "properties": {"schema": {"const": "cut4.r20.frozen_mutation_catalog.v1"}, "generator_id": {"const": "cut4.r20.mutation_generator.v1"}, "rows": {"type": "array", "minItems": 256, "maxItems": 256, "items": {"$ref": "#/$defs/MutationRow"}}, "row_count": {"const": 256}}}
  },
  "$ref": "#/$defs/Catalog"
}
```

### 4.2 Acyclic fixture/map/catalog/test route

The fixture source bundle is generated first and independently reviewed. The
source-map receipt is then derived from those admitted bytes. The mutation
catalog is derived from both and must reproduce the frozen 277,546-byte hash.
Only then may the RED test be authored and admitted. The test consumes the
catalog; the source map never depends on test bytes.

```json
{
  "schema": "cut4.r20.subject_route.v1",
  "rows": [
    ["S01","fixture_source_bundle","FIXTURE_SOURCE_AUTHOR","FIXTURE_SOURCE_REVIEWER",[]],
    ["S02","source_map_receipt","SOURCE_MAP_AUTHOR","SOURCE_MAP_REVIEWER",["S01"]],
    ["S03","mutation_catalog","MUTATION_CATALOG_AUTHOR","MUTATION_CATALOG_REVIEWER",["S01","S02"]],
    ["S04","parser_a_package","PARSER_A_AUTHOR","PARSER_A_REVIEWER",[]],
    ["S05","parser_b_package","PARSER_B_AUTHOR","PARSER_B_REVIEWER",[]],
    ["S06","verifier_package","VERIFIER_AUTHOR","VERIFIER_REVIEWER",[]],
    ["S07","parser_a_dependency_receipt","PARSER_A_DEP_AUTHOR","PARSER_A_DEP_REVIEWER",["S04"]],
    ["S08","parser_b_dependency_receipt","PARSER_B_DEP_AUTHOR","PARSER_B_DEP_REVIEWER",["S05"]],
    ["S09","verifier_dependency_receipt","VERIFIER_DEP_AUTHOR","VERIFIER_DEP_REVIEWER",["S06"]],
    ["S10","red_test","RED_TEST_AUTHOR","RED_TEST_REVIEWER",["S03","S04","S05","S06","S07","S08","S09"]],
    ["S11","parser_a_execution_receipt","PARSER_A_RUNNER","PARSER_A_RUN_REVIEWER",["S04","S07","S10"]],
    ["S12","parser_b_execution_receipt","PARSER_B_RUNNER","PARSER_B_RUN_REVIEWER",["S05","S08","S10"]],
    ["S13","verifier_execution_receipt","VERIFIER_RUNNER","VERIFIER_RUN_REVIEWER",["S06","S09","S10"]],
    ["S14","negative_proof_receipt","NEGATIVE_PROOF_AUTHOR","NEGATIVE_PROOF_REVIEWER",["S11","S12","S13"]],
    ["S15","red_pre_snapshot","RED_PRE_AUTHOR","RED_PRE_REVIEWER",["S10","S14"]],
    ["S16","red_process_projection","RED_PROCESS_PROJECTOR","RED_PROCESS_REVIEWER",["S15"]],
    ["S17","red_exit_projection","RED_EXIT_PROJECTOR","RED_EXIT_REVIEWER",["S16"]],
    ["S18","red_author_receipt","RED_RECEIPT_AUTHOR","RED_RECEIPT_REVIEWER",["S03","S10","S14","S15","S16","S17"]],
    ["S19","model","MODEL_IMPLEMENTER","MODEL_REVIEWER",["S18"]],
    ["S20","green_pre_snapshot","GREEN_PRE_AUTHOR","GREEN_PRE_REVIEWER",["S10","S19"]],
    ["S21","green_process_projection","GREEN_PROCESS_PROJECTOR","GREEN_PROCESS_REVIEWER",["S20"]],
    ["S22","green_exit_projection","GREEN_EXIT_PROJECTOR","GREEN_EXIT_REVIEWER",["S21"]],
    ["S23","green_author_receipt","GREEN_RECEIPT_AUTHOR","GREEN_RECEIPT_REVIEWER",["S03","S10","S19","S20","S21","S22"]]
  ],
  "record_expansion": ["PRODUCER_START","PRODUCER_COMPLETION","REVIEW_START","REVIEW_COMPLETION","SUBJECT_ADMISSION"],
  "subject_count": 23,
  "predecessor_edge_count": 46,
  "expanded_node_count": 116,
  "expanded_edge_count": 206,
  "final_role_count": 48
}
```

Expansion is one architecture admission plus five records per subject. Edges
are 23 architecture-to-start, 115 lifecycle, 46 displayed predecessors, and
22 cumulative-manifest prefix edges: 206 total. Dependencies point only to
earlier rows; Kahn remainder is zero. Each lifecycle uses exact occurrence FKs
from Section 1 and final global anti-alias reconciliation covers 48 roles.

## 5. Process output is projected from the root source

The admitted S15/S20 pre-snapshot fixes test/model bytes, mutation catalog,
argv/environment/cwd/stdin, and filesystem state. Root next passes that exact
intent to `shell_command`; the root observation adapter consumes the sealed
SHELL_START and SHELL_RESULT capabilities into consecutive ledger records.
It constructs the typed `ProcessObservationRecord`. S16/S21 are independently
reviewed projections of that admitted root record, not producers of stdout.
S17/S22 parse exact stdout bytes from the projection.

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "cut4.r20.process_projection.schema.v1",
  "$defs": {
    "Hex64": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
    "CaseExitRow": {"type": "object", "additionalProperties": false, "required": ["ordinal", "mutation_id", "request_sha256", "phase", "outcome_kind", "observed_code", "result_bytes_base64", "result_byte_size", "result_sha256", "exception_type", "exception_bytes_base64", "exception_byte_size", "exception_sha256", "row_digest"], "properties": {"ordinal": {"type": "integer", "minimum": 0, "maximum": 255}, "mutation_id": {"type": "string", "minLength": 1}, "request_sha256": {"$ref": "#/$defs/Hex64"}, "phase": {"enum": ["RED", "GREEN"]}, "outcome_kind": {"enum": ["MODEL_ABSENT", "DOMAIN_RESULT", "HARNESS_ERROR"]}, "observed_code": {"type": "string", "minLength": 1}, "result_bytes_base64": {"type": "string"}, "result_byte_size": {"type": "integer", "minimum": 0}, "result_sha256": {"$ref": "#/$defs/Hex64"}, "exception_type": {"type": "string"}, "exception_bytes_base64": {"type": "string"}, "exception_byte_size": {"type": "integer", "minimum": 0}, "exception_sha256": {"$ref": "#/$defs/Hex64"}, "row_digest": {"$ref": "#/$defs/Hex64"}}},
    "ProcessProjection": {"type": "object", "additionalProperties": false, "required": ["schema", "phase", "root_process_observation_record_digest", "shell_start_record_digest", "shell_result_record_digest", "pre_snapshot_subject_admission_digest", "process_id", "argv", "environment_rows", "cwd_nfc", "stdin_sha256", "exit_code", "stdout_bytes_base64", "stdout_byte_size", "stdout_sha256", "stderr_bytes_base64", "stderr_byte_size", "stderr_sha256", "projection_digest"], "properties": {"schema": {"const": "cut4.r20.process_projection.v1"}, "phase": {"enum": ["RED", "GREEN"]}, "root_process_observation_record_digest": {"$ref": "#/$defs/Hex64"}, "shell_start_record_digest": {"$ref": "#/$defs/Hex64"}, "shell_result_record_digest": {"$ref": "#/$defs/Hex64"}, "pre_snapshot_subject_admission_digest": {"$ref": "#/$defs/Hex64"}, "process_id": {"type": "string", "minLength": 1}, "argv": {"type": "array", "minItems": 1, "items": {"type": "string"}}, "environment_rows": {"type": "array", "items": {"type": "array", "prefixItems": [{"type": "string"},{"type": "string"}], "items": false, "minItems": 2, "maxItems": 2}}, "cwd_nfc": {"type": "string", "minLength": 1}, "stdin_sha256": {"$ref": "#/$defs/Hex64"}, "exit_code": {"type": "integer"}, "stdout_bytes_base64": {"type": "string"}, "stdout_byte_size": {"type": "integer", "minimum": 1}, "stdout_sha256": {"$ref": "#/$defs/Hex64"}, "stderr_bytes_base64": {"type": "string"}, "stderr_byte_size": {"type": "integer", "minimum": 0}, "stderr_sha256": {"$ref": "#/$defs/Hex64"}, "projection_digest": {"$ref": "#/$defs/Hex64"}}},
    "ExitProjection": {"type": "object", "additionalProperties": false, "required": ["schema", "phase", "process_projection_subject_admission_digest", "process_projection_digest", "stdout_sha256", "case_rows", "case_count", "case_roster_digest", "exit_projection_digest"], "properties": {"schema": {"const": "cut4.r20.exit_projection.v1"}, "phase": {"enum": ["RED", "GREEN"]}, "process_projection_subject_admission_digest": {"$ref": "#/$defs/Hex64"}, "process_projection_digest": {"$ref": "#/$defs/Hex64"}, "stdout_sha256": {"$ref": "#/$defs/Hex64"}, "case_rows": {"type": "array", "minItems": 256, "maxItems": 256, "items": {"$ref": "#/$defs/CaseExitRow"}}, "case_count": {"const": 256}, "case_roster_digest": {"$ref": "#/$defs/Hex64"}, "exit_projection_digest": {"$ref": "#/$defs/Hex64"}}},
    "ExecutionAuthorReceipt": {"type": "object", "additionalProperties": false, "required": ["schema", "phase", "mutation_catalog_subject_admission_digest", "test_subject_admission_digest", "model_subject_admission_digest", "pre_snapshot_subject_admission_digest", "root_process_observation_record_digest", "process_projection_subject_admission_digest", "exit_projection_subject_admission_digest", "case_projection_rows", "case_roster_digest", "receipt_digest"], "properties": {"schema": {"const": "cut4.r20.execution_author_receipt.v1"}, "phase": {"enum": ["RED", "GREEN"]}, "mutation_catalog_subject_admission_digest": {"$ref": "#/$defs/Hex64"}, "test_subject_admission_digest": {"$ref": "#/$defs/Hex64"}, "model_subject_admission_digest": {"$ref": "#/$defs/Hex64"}, "pre_snapshot_subject_admission_digest": {"$ref": "#/$defs/Hex64"}, "root_process_observation_record_digest": {"$ref": "#/$defs/Hex64"}, "process_projection_subject_admission_digest": {"$ref": "#/$defs/Hex64"}, "exit_projection_subject_admission_digest": {"$ref": "#/$defs/Hex64"}, "case_projection_rows": {"type": "array", "minItems": 256, "maxItems": 256, "items": {"type": "array", "prefixItems": [{"type": "integer"},{"type": "string"},{"$ref": "#/$defs/Hex64"}], "items": false, "minItems": 3, "maxItems": 3}}, "case_roster_digest": {"$ref": "#/$defs/Hex64"}, "receipt_digest": {"$ref": "#/$defs/Hex64"}}}
  },
  "oneOf": [{"$ref": "#/$defs/ProcessProjection"}, {"$ref": "#/$defs/ExitProjection"}, {"$ref": "#/$defs/ExecutionAuthorReceipt"}]
}
```

Every projection field byte-equals the admitted root process observation and
its two source records. The process ID and tool call identity match start to
result; start request equals pre-snapshot argv/environment/cwd/stdin; result
exit/stdout/stderr bytes reproduce exact hashes. Stdout is exactly 256 CJ case
row bodies followed by one LF each, no other bytes. Strict parsing and
canonical reserialization must reproduce stdout before case rows exist. Rows
are gapless and equal the admitted mutation catalog order/requests. RED allows
only `MODEL_ABSENT` plus `ImportError`; GREEN allows only `DOMAIN_RESULT`,
empty exception, and each catalog's exact rejection code. Author receipt rows
are only `(ordinal,mutation_id,exit-row-digest)` projections. A caller-written
stdout, result, ordinal, process ID, partial roster, post-hoc pre-state, or
filesystem-only observation cannot enter the admitted chain.

## 6. Exact dependency DAG and bounded validation

```json
{
  "schema": "cut4.r20.constructor_dag.v1",
  "nodes": [
    "SealedRootToolEvent","RootObservationRecord","OccurrenceRecord","EventSourceAdmission","ArchitectureAdmission","FrozenSpecs","FixtureSourceBundle","SourceMapReceipt","MutationCatalog","RedTest","ParserAPackage","ParserBPackage","VerifierPackage","DependencyClosureA","DependencyClosureB","DependencyClosureV","ParserAReceipt","ParserBReceipt","VerifierReceipt","VectorProof","NegativeProofReceipt",
    "SourceFileBytes","SourceSnapshot","PhaseIOAuthority","AckPolicy","ProviderPlan","ProviderPlanRoot","BindingKey","PredicateEvaluation","InvocationRecord","ProviderKp","PredicateEvidence","PayloadRecord","ProviderTerminal","ExplicitZeroProof","ProviderReceipt","ReceiptEnvelope","KpMapEntry","BakeFactRow","BakeBinding","ProviderPrivateV6","NormalizedSemanticRow","NormalizerEvidence","NormalizerReceipt","ExpectedObservedDiff","JournalState","PriorEnvelope","BaseRequestIntent","AttemptAllocation","TerminalEnvelope","TerminalJournalRecord","PublicOutputBytes","CommittedPublicationReceipt","PublicationLink","PublicationAckJournalRecord","AckState","M4","R4","CompletionReceipt","PreExecutionSnapshot","ProcessObservationRecord","ProcessProjection","ExitProjection","ExecutionAuthorReceipt"
  ],
  "edges": [
    ["SealedRootToolEvent","RootObservationRecord"],["RootObservationRecord","OccurrenceRecord"],["EventSourceAdmission","OccurrenceRecord"],["OccurrenceRecord","ArchitectureAdmission"],
    ["FrozenSpecs","FixtureSourceBundle"],["FixtureSourceBundle","SourceMapReceipt"],["FrozenSpecs","SourceMapReceipt"],["FixtureSourceBundle","MutationCatalog"],["SourceMapReceipt","MutationCatalog"],["MutationCatalog","RedTest"],
    ["FrozenSpecs","ParserAPackage"],["FrozenSpecs","ParserBPackage"],["FrozenSpecs","VerifierPackage"],["ParserAPackage","DependencyClosureA"],["ParserBPackage","DependencyClosureB"],["VerifierPackage","DependencyClosureV"],["FrozenSpecs","DependencyClosureA"],["FrozenSpecs","DependencyClosureB"],["FrozenSpecs","DependencyClosureV"],["DependencyClosureA","ParserAReceipt"],["DependencyClosureB","ParserBReceipt"],["DependencyClosureV","VerifierReceipt"],["ParserAPackage","ParserAReceipt"],["ParserBPackage","ParserBReceipt"],["VerifierPackage","VerifierReceipt"],["FrozenSpecs","ParserAReceipt"],["FrozenSpecs","ParserBReceipt"],["FrozenSpecs","VerifierReceipt"],
    ["ParserAPackage","RedTest"],["ParserBPackage","RedTest"],["VerifierPackage","RedTest"],["DependencyClosureA","RedTest"],["DependencyClosureB","RedTest"],["DependencyClosureV","RedTest"],
    ["ParserAReceipt","VectorProof"],["ParserBReceipt","VectorProof"],["VerifierReceipt","VectorProof"],["VectorProof","NegativeProofReceipt"],["ParserAReceipt","NegativeProofReceipt"],["ParserBReceipt","NegativeProofReceipt"],["VerifierReceipt","NegativeProofReceipt"],
    ["FrozenSpecs","SourceFileBytes"],["SourceFileBytes","SourceSnapshot"],["FrozenSpecs","PhaseIOAuthority"],["FrozenSpecs","AckPolicy"],["PhaseIOAuthority","ProviderPlan"],["SourceSnapshot","ProviderPlan"],["AckPolicy","ProviderPlan"],["ProviderPlan","ProviderPlanRoot"],["ProviderPlanRoot","BindingKey"],["SourceSnapshot","BindingKey"],
    ["ProviderPlan","PredicateEvaluation"],["SourceSnapshot","PredicateEvaluation"],["ProviderPlan","InvocationRecord"],["PredicateEvaluation","InvocationRecord"],["ProviderPlan","ProviderKp"],["ProviderPlanRoot","ProviderKp"],["BindingKey","ProviderKp"],["PredicateEvaluation","ProviderKp"],["InvocationRecord","ProviderKp"],
    ["ProviderPlan","PredicateEvidence"],["SourceSnapshot","PredicateEvidence"],["ProviderKp","PredicateEvidence"],["InvocationRecord","PayloadRecord"],["ProviderPlan","ProviderTerminal"],["InvocationRecord","ProviderTerminal"],["ProviderKp","ProviderTerminal"],["PayloadRecord","ProviderTerminal"],
    ["ProviderTerminal","ExplicitZeroProof"],["InvocationRecord","ExplicitZeroProof"],["ProviderKp","ExplicitZeroProof"],["InvocationRecord","ProviderReceipt"],["PredicateEvidence","ProviderReceipt"],["ProviderTerminal","ProviderReceipt"],["ExplicitZeroProof","ProviderReceipt"],["ProviderKp","ProviderReceipt"],
    ["ProviderReceipt","ReceiptEnvelope"],["ProviderKp","ReceiptEnvelope"],["ProviderKp","KpMapEntry"],["ProviderReceipt","BakeFactRow"],["ProviderKp","BakeFactRow"],["ProviderPlanRoot","BakeBinding"],["BindingKey","BakeBinding"],["KpMapEntry","BakeBinding"],["ReceiptEnvelope","BakeBinding"],["BakeFactRow","BakeBinding"],
    ["ProviderReceipt","ProviderPrivateV6"],["PayloadRecord","ProviderPrivateV6"],["ProviderKp","ProviderPrivateV6"],["PayloadRecord","NormalizedSemanticRow"],["VerifierReceipt","NormalizedSemanticRow"],["ProviderKp","NormalizedSemanticRow"],["NormalizedSemanticRow","NormalizerEvidence"],["NormalizerEvidence","NormalizerReceipt"],
    ["ProviderPrivateV6","ExpectedObservedDiff"],["NormalizedSemanticRow","ExpectedObservedDiff"],["BindingKey","ExpectedObservedDiff"],["KpMapEntry","ExpectedObservedDiff"],
    ["JournalState","PriorEnvelope"],["SourceSnapshot","BaseRequestIntent"],["PriorEnvelope","BaseRequestIntent"],["BaseRequestIntent","AttemptAllocation"],["AttemptAllocation","InvocationRecord"],["ExpectedObservedDiff","TerminalEnvelope"],["InvocationRecord","TerminalEnvelope"],["ProviderReceipt","TerminalEnvelope"],["TerminalEnvelope","TerminalJournalRecord"],
    ["PhaseIOAuthority","PublicOutputBytes"],["TerminalJournalRecord","CommittedPublicationReceipt"],["PublicOutputBytes","CommittedPublicationReceipt"],["TerminalJournalRecord","PublicationLink"],["CommittedPublicationReceipt","PublicationLink"],["PublicationLink","PublicationAckJournalRecord"],["AckPolicy","PublicationAckJournalRecord"],["AckPolicy","AckState"],["PublicationLink","AckState"],["PublicationAckJournalRecord","AckState"],
    ["BakeBinding","M4"],["ProviderPrivateV6","M4"],["NormalizedSemanticRow","M4"],["NormalizerReceipt","M4"],["ExpectedObservedDiff","M4"],["PublicOutputBytes","M4"],["AckState","M4"],["BindingKey","M4"],["KpMapEntry","M4"],["M4","R4"],["PublicationLink","R4"],["BindingKey","R4"],["R4","CompletionReceipt"],["TerminalJournalRecord","CompletionReceipt"],["CommittedPublicationReceipt","CompletionReceipt"],["PublicationLink","CompletionReceipt"],["AckState","CompletionReceipt"],["BindingKey","CompletionReceipt"],["KpMapEntry","CompletionReceipt"],
    ["RedTest","PreExecutionSnapshot"],["NegativeProofReceipt","PreExecutionSnapshot"],["PreExecutionSnapshot","ProcessObservationRecord"],["SealedRootToolEvent","ProcessObservationRecord"],["ProcessObservationRecord","ProcessProjection"],["ProcessProjection","ExitProjection"],["MutationCatalog","ExitProjection"],["ExitProjection","ExecutionAuthorReceipt"],["ProcessObservationRecord","ExecutionAuthorReceipt"],["MutationCatalog","ExecutionAuthorReceipt"],["NegativeProofReceipt","ExecutionAuthorReceipt"]
  ],
  "node_count": 64,
  "edge_count": 147
}
```

Edges point dependency to consumer. The future model generates this projection
from typed fields/constructors/validators/serializers and must equal it byte
for byte. It has exactly 64 unique nodes and 147 unique edges with no unknown
endpoint and zero Kahn remainder. Direct provider plan/source/invocation
relations, separate A/B/V
closures, per-provider Kp mapping, root event/process source, pre-map catalog,
and publication/ACK children are literal. No manual dependency row may be
added by a test.

Independent architecture review must execute this exact 32-check roster:

```json
{
  "schema": "cut4.r20.architecture_check_roster.v1",
  "checks": [
    "R20-01-review-size-sha","R20-02-r19-contract-size-sha","R20-03-r19-receipt-size-sha","R20-04-json-strict-parse","R20-05-metaschema-and-ref-resolution","R20-06-utf8-lf-fences","R20-07-scoped-two-new-files",
    "R20-08-sealed-source-no-byte-constructor","R20-09-ledger-generation-prefix-cas","R20-10-occurrence-spawn-result-exact-join","R20-11-global-role-source-record-no-alias","R20-12-route-116-nodes-206-edges-acyclic",
    "R20-13-dependency-closures-three-distinct","R20-14-verifier-no-parser-result-input","R20-15-execution-receipt-schema-complete","R20-16-vector-proof-schema-and-32-order","R20-17-negative-proof-preimage-total","R20-18-vector-32-200-121-31-derived",
    "R20-19-binding-key-common-fields","R20-20-three-provider-kps-distinct-and-owned","R20-21-receipt-envelope-exact-bytes","R20-22-facts-owning-kp-only","R20-23-zero-proof-exclusive-inhabitable","R20-24-downstream-carriers-closed-no-open-schema-id",
    "R20-25-mutation-id-256-unique","R20-26-generator-reconstructs-256-operations","R20-27-source-bundle-size-sha","R20-28-source-map-size-sha","R20-29-catalog-size-sha-and-32-each-operation","R20-30-source-map-catalog-before-test",
    "R20-31-shell-source-start-result-and-projection-exact","R20-32-stdout-256-case-reparse-and-author-projection"
  ],
  "check_count": 32
}
```

The reviewer recomputes route and constructor node/edge counts and Kahn
remainders rather than trusting prose; reconstructs all three 256-row roots
from authenticated IDs and exact generator rules; validates all JSON schemas
and external embedded `$ref`s; verifies source-ledger and process joins; and
checks only the two R20 authored paths are new in this task's scope.

## 7. Non-goals and claim ceiling

The future order is: contract/receipt; independent architecture review; root
event-source and architecture admissions from sealed tool observations;
fixture source bundle; source map; frozen mutation catalog; three separately
owned parser/verifier packages and dependency receipts; test; three execution
receipts and negative proof; RED process source/projections while model absent;
distinct model/review; GREEN source/projections/review. No worker starts from a
subject that lacks an accepted admission.

R20 is Part-0 architecture only. It grants no authority for the event source,
route, parser, verifier, fixture, source map, mutation catalog, test, execution,
model, provider, production, ArtifactLedger/G3 changes, audit findings,
protocol answers, release, or readiness. Recall is preserved because no recon
output or fixed provider slot is removed; precision improves because workers
cannot mint admitted task/process evidence, A/B/V cannot share an unlisted
oracle, each provider owns a realizable Kp, every operation is frozen before
test admission, and stdout/case rows originate in the root tool result.
