# Cut-4 transactional recon publication R21 preimplementation contract

Date: 2026-08-10
Status: Part-0 architecture-only repair awaiting independent review
Supersedes: only the four rejected R20 gates
Authority: all observation/genesis admission, fixture, parser, verifier,
source-map, mutation-catalog, test, model, execution, production, provider,
ArtifactLedger, G3, audit, commit, push, install, release, readiness, and
protocol-answer authority is false

## 0. Boundary and authenticated predecessor

This turn creates only this contract and its author receipt. It creates or
executes no live observation/genesis, fixture, package, process, test, model,
provider, production, ArtifactLedger, or G3 artifact.

The exact R20 independent REPAIR review was authenticated and read completely
before authoring:

| Artifact | Bytes | SHA-256 |
|---|---:|---|
| `review_fixtures/cut4_transactional_recon_publication_r20_architecture_independent_review_20260810.md` | 19,898 | `6fb3d9cc607a733c431186684a32e5f7699c360daf27473626c62dd285661ee9` |
| `architecture/cut4-transactional-recon-publication-r20-preimplementation-contract.md` | 85,958 | `71ee686fd11237205ff402cf03e312a75e63d4ae85f4f2221ef9af909b00407e` |
| `review_fixtures/cut4_transactional_recon_publication_r20_contract_author_receipt_20260810.md` | 5,844 | `1ab54828e2ca02ccd04eeb28673752378c45851f17b97654350925bc1fb3009c` |

R21 inherits every accepted R1-R20 clause outside the four findings, including
sole canonical public ownership, immutable MODEL visibility, fixed provider
slots, stable publication successor, terminal-before-link order, SC/L1 output
tuples, compatibility/legacy rules, replay/crash containment, unchanged MODEL
shards and dependency units, and nonempty exhausted c3. R21 replacements below
control conflicts.

`H` is SHA-256 bytes; `U` is strict UTF-8 of NFC text; `CJ` is RFC 8785
canonical JSON after duplicate-key/non-finite/surrogate/non-NFC rejection;
`D(tag,x)=H(U(tag)||0x00||CJ(x))`. Hex is lowercase. These joins prove byte
integrity only, never a signature, trusted clock, human identity, non-collusion,
or evidence that root did not fabricate an attestation.

```json
{
  "schema": "cut4.r21.path_registry.v1",
  "contract": "architecture/cut4-transactional-recon-publication-r21-preimplementation-contract.md",
  "author_receipt": "review_fixtures/cut4_transactional_recon_publication_r21_contract_author_receipt_20260810.md",
  "architecture_review": "review_fixtures/cut4_transactional_recon_publication_r21_architecture_independent_review_20260810.md",
  "observation_genesis": "review_fixtures/cut4_transactional_recon_publication_r21_observations/000000-genesis.json",
  "observation_directory": "review_fixtures/cut4_transactional_recon_publication_r21_observations",
  "event_source_admission": "review_fixtures/cut4_transactional_recon_publication_r21_route/000_event_source_admission.json",
  "architecture_admission": "review_fixtures/cut4_transactional_recon_publication_r21_route/001_architecture_admission.json",
  "fixture_source_bundle": "review_fixtures/cut4_transactional_recon_publication_r21_fixture_source_bundle.json",
  "source_map_receipt": "review_fixtures/cut4_transactional_recon_publication_r21_source_map_receipt.json",
  "mutation_catalog": "review_fixtures/cut4_transactional_recon_publication_r21_mutation_catalog.json",
  "runtime_observation_directory": "review_fixtures/cut4_transactional_recon_publication_r21_runtime_observations",
  "route_directory": "review_fixtures/cut4_transactional_recon_publication_r21_route"
}
```

## 1. Inhabitable live root attestation and typed genesis

### 1.1 Claim is narrowed to APIs that exist

R21 withdraws the R20 `RuntimeCapability`, `collaboration.task_result`, split
shell request/result capabilities, and `root.filesystem_snapshot`. The live
inputs are ordinary serializable results the root actually receives from the
available operations: `collaboration.spawn_agent`, `collaboration.list_agents`,
`collaboration.wait_agent`, delivered agent result messages, and
`shell_command`. Root writes an observation at the same call/result boundary;
a worker cannot write the observation directory, but root can fabricate bytes.
The only claim is therefore **ROOT_ATTESTED_LIVE_OBSERVATION**, not
non-caller-mintable evidence.

R21 also makes no retrospective author/reviewer occurrence claim. Contract,
author receipt, and ACCEPT review are authenticated byte subjects in the
architecture admission. Only after ACCEPT does root create the typed genesis;
only later worker occurrences enter the ledger. The author receipt's task name
is descriptive and is not a role-manifest row. The inherited 23-subject route
therefore contains exactly 46 future producer/reviewer roles, while its
116-node/206-edge lifecycle graph is unchanged.

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "cut4.r21.live_observation.schema.v1",
  "$defs": {
    "Hex64": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
    "ByteSubject": {"type": "object", "additionalProperties": false, "required": ["identity","bytes_base64","byte_size","sha256"], "properties": {"identity": {"type": "string", "minLength": 1}, "bytes_base64": {"type": "string"}, "byte_size": {"type": "integer", "minimum": 1}, "sha256": {"$ref": "#/$defs/Hex64"}}},
    "Genesis": {
      "type": "object", "additionalProperties": false,
      "required": ["schema","generation","previous_record_digest","contract","author_receipt","accept_review","adapter_spec_digest","root_task_name","claim_kind","genesis_digest"],
      "properties": {"schema": {"const": "cut4.r21.observation_genesis.v1"}, "generation": {"const": 0}, "previous_record_digest": {"const": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}, "contract": {"$ref": "#/$defs/ByteSubject"}, "author_receipt": {"$ref": "#/$defs/ByteSubject"}, "accept_review": {"$ref": "#/$defs/ByteSubject"}, "adapter_spec_digest": {"$ref": "#/$defs/Hex64"}, "root_task_name": {"const": "/root"}, "claim_kind": {"const": "ROOT_ATTESTED_LIVE_OBSERVATION"}, "genesis_digest": {"$ref": "#/$defs/Hex64"}}
    },
    "ToolObservation": {
      "type": "object", "additionalProperties": false,
      "required": ["schema","generation","previous_record_digest","tool_operation","call_ordinal","request_bytes_base64","request_byte_size","request_sha256","result_kind","result_bytes_base64","result_byte_size","result_sha256","capture_phase","root_attestation","record_digest"],
      "properties": {"schema": {"const": "cut4.r21.tool_observation.v1"}, "generation": {"type": "integer", "minimum": 1}, "previous_record_digest": {"$ref": "#/$defs/Hex64"}, "tool_operation": {"enum": ["collaboration.spawn_agent","collaboration.list_agents","collaboration.wait_agent","shell_command","DELIVERED_AGENT_MESSAGE"]}, "call_ordinal": {"type": "integer", "minimum": 1}, "request_bytes_base64": {"type": "string"}, "request_byte_size": {"type": "integer", "minimum": 1}, "request_sha256": {"$ref": "#/$defs/Hex64"}, "result_kind": {"enum": ["JSON_OBJECT","UTF8_STRING","DELIVERED_MESSAGE"]}, "result_bytes_base64": {"type": "string"}, "result_byte_size": {"type": "integer", "minimum": 1}, "result_sha256": {"$ref": "#/$defs/Hex64"}, "capture_phase": {"enum": ["IMMEDIATE_RETURN","DELIVERED_COMPLETION"]}, "root_attestation": {"const": "ROOT_SERIALIZED_ACTUAL_TOOL_RESULT"}, "record_digest": {"$ref": "#/$defs/Hex64"}}
    },
    "Occurrence": {
      "type": "object", "additionalProperties": false,
      "required": ["schema","spawn_observation_digest","completion_observation_digest","canonical_task_name","spawn_result_projection_digest","completion_projection_digest","occurrence_id","result_subjects","occurrence_digest"],
      "properties": {"schema": {"const": "cut4.r21.occurrence.v1"}, "spawn_observation_digest": {"$ref": "#/$defs/Hex64"}, "completion_observation_digest": {"$ref": "#/$defs/Hex64"}, "canonical_task_name": {"type": "string", "pattern": "^/root(?:/[a-z0-9_]+)+$"}, "spawn_result_projection_digest": {"$ref": "#/$defs/Hex64"}, "completion_projection_digest": {"$ref": "#/$defs/Hex64"}, "occurrence_id": {"type": "string", "pattern": "^occ_[0-9a-f]{64}$"}, "result_subjects": {"type": "array", "uniqueItems": true, "items": {"$ref": "#/$defs/ByteSubject"}}, "occurrence_digest": {"$ref": "#/$defs/Hex64"}}
    },
    "ArchitectureAdmission": {
      "type": "object", "additionalProperties": false,
      "required": ["schema","contract","author_receipt","accept_review","genesis","event_source_admission_digest","decision","admission_digest"],
      "properties": {"schema": {"const": "cut4.r21.architecture_admission.v1"}, "contract": {"$ref": "#/$defs/ByteSubject"}, "author_receipt": {"$ref": "#/$defs/ByteSubject"}, "accept_review": {"$ref": "#/$defs/ByteSubject"}, "genesis": {"$ref": "#/$defs/Genesis"}, "event_source_admission_digest": {"$ref": "#/$defs/Hex64"}, "decision": {"const": "ACCEPT"}, "admission_digest": {"$ref": "#/$defs/Hex64"}}
    }
  },
  "oneOf": [{"$ref": "#/$defs/Genesis"},{"$ref": "#/$defs/ToolObservation"},{"$ref": "#/$defs/Occurrence"},{"$ref": "#/$defs/ArchitectureAdmission"}]
}
```

Root serializes the exact call argument as CJ and the exact returned JSON
object or UTF-8 string without semantic additions. A delivered completion
message is serialized as its exact role/task/payload envelope. The adapter
registry contains literal field projections for the concrete shape observed at
runtime; an unknown shape is `ROOT_OBSERVATION_SHAPE_DEBT`. Genesis digest is
`D("cut4.r21.observation_genesis.v1",fields before genesis_digest)`.
Generation `n` requires a committed `n-1`; canonical temp+fsync+absent atomic
rename+directory fsync commits one record. Gaps, forks, reuse, or observations
written after the corresponding next lifecycle step fail. Occurrence joins the
actual spawn return task name and delivered completion task name; its ID derives
from both observation digests and name. Global exact uniqueness covers task
name, occurrence ID, spawn observation, and completion observation. This is
auditable root attestation with an explicit trust ceiling.

## 2. Root-observed engine process and complete runtime read set

### 2.1 Prospective intent and contained runner

Each A/B/verifier run has a reviewed `EngineCommandIntent` before invocation.
It fixes `python -I -S`, an engine-specific admitted runner/package, exact
source/BAKE/spec inputs, a fresh temp cwd, environment, stdin, and an exact
allowed-read roster. The runner installs `sys.addaudithook` before any engine
import, forbids subprocess/network/native extension/ctypes, and records every
`open`, `import`, `compile`, and `exec` event. Inputs are copied by hash into
the temp root before launch; project-root reads are denied. The verifier
allowlist excludes parser receipts and the accepted tuple projection.

The actual available `shell_command` result is captured as a Section-1
`ToolObservation`. The runner emits exactly one
`CUT4_R21_ENGINE_RESULT:<strict-base64(CJ(EngineProcessEnvelope))>` line.
The root adapter extracts that line from the exact observed result bytes; no
receipt author supplies stdout. A/B/V may still contain copied logic, so R21
claims three separately observed executions and read-set separation, not
algorithmic independence or immunity from common omission.

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "cut4.r21.engine_runtime.schema.v1",
  "$defs": {
    "Hex64": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
    "InputRow": {"type": "object", "additionalProperties": false, "required": ["input_id","identity","byte_size","sha256","allowed_modes"], "properties": {"input_id": {"type": "string", "minLength": 1}, "identity": {"type": "string", "minLength": 1}, "byte_size": {"type": "integer", "minimum": 1}, "sha256": {"$ref": "#/$defs/Hex64"}, "allowed_modes": {"type": "array", "minItems": 1, "uniqueItems": true, "items": {"enum": ["READ","IMPORT","EXEC"]}}}},
    "CommandIntent": {"type": "object", "additionalProperties": false, "required": ["schema","engine","runner_subject_admission_digest","package_subject_admission_digest","dependency_receipt_admission_digest","argv","cwd_identity","environment_rows","stdin_sha256","allowed_inputs","allowed_input_roster_digest","forbidden_identities","audit_policy_digest","intent_digest"], "properties": {"schema": {"const": "cut4.r21.engine_command_intent.v1"}, "engine": {"enum": ["PARSER_A","PARSER_B","VERIFIER"]}, "runner_subject_admission_digest": {"$ref": "#/$defs/Hex64"}, "package_subject_admission_digest": {"$ref": "#/$defs/Hex64"}, "dependency_receipt_admission_digest": {"$ref": "#/$defs/Hex64"}, "argv": {"type": "array", "minItems": 3, "items": {"type": "string"}}, "cwd_identity": {"type": "string", "minLength": 1}, "environment_rows": {"type": "array", "items": {"type": "array", "prefixItems": [{"type": "string"},{"type": "string"}], "items": false, "minItems": 2, "maxItems": 2}}, "stdin_sha256": {"$ref": "#/$defs/Hex64"}, "allowed_inputs": {"type": "array", "minItems": 1, "items": {"$ref": "#/$defs/InputRow"}}, "allowed_input_roster_digest": {"$ref": "#/$defs/Hex64"}, "forbidden_identities": {"type": "array", "minItems": 3, "uniqueItems": true, "items": {"type": "string"}}, "audit_policy_digest": {"$ref": "#/$defs/Hex64"}, "intent_digest": {"$ref": "#/$defs/Hex64"}}},
    "ReadRow": {"type": "object", "additionalProperties": false, "required": ["event_ordinal","event_kind","requested_identity","resolved_identity","input_id","mode","pre_read_sha256","post_read_sha256","byte_count","allowed","row_digest"], "properties": {"event_ordinal": {"type": "integer", "minimum": 0}, "event_kind": {"enum": ["OPEN","IMPORT","COMPILE","EXEC"]}, "requested_identity": {"type": "string", "minLength": 1}, "resolved_identity": {"type": "string", "minLength": 1}, "input_id": {"type": "string", "minLength": 1}, "mode": {"enum": ["READ","IMPORT","EXEC"]}, "pre_read_sha256": {"$ref": "#/$defs/Hex64"}, "post_read_sha256": {"$ref": "#/$defs/Hex64"}, "byte_count": {"type": "integer", "minimum": 0}, "allowed": {"const": true}, "row_digest": {"$ref": "#/$defs/Hex64"}}},
    "ProcessEnvelope": {"type": "object", "additionalProperties": false, "required": ["schema","engine","command_intent_digest","package_sha256","runner_sha256","source_root_digest","bake_root_digest","spec_roster_digest","read_rows","read_count","read_roster_digest","denied_event_count","loaded_module_rows","loaded_module_roster_digest","result_rows","result_roster_digest","exit_code","envelope_digest"], "properties": {"schema": {"const": "cut4.r21.engine_process_envelope.v1"}, "engine": {"enum": ["PARSER_A","PARSER_B","VERIFIER"]}, "command_intent_digest": {"$ref": "#/$defs/Hex64"}, "package_sha256": {"$ref": "#/$defs/Hex64"}, "runner_sha256": {"$ref": "#/$defs/Hex64"}, "source_root_digest": {"$ref": "#/$defs/Hex64"}, "bake_root_digest": {"$ref": "#/$defs/Hex64"}, "spec_roster_digest": {"$ref": "#/$defs/Hex64"}, "read_rows": {"type": "array", "minItems": 1, "items": {"$ref": "#/$defs/ReadRow"}}, "read_count": {"type": "integer", "minimum": 1}, "read_roster_digest": {"$ref": "#/$defs/Hex64"}, "denied_event_count": {"const": 0}, "loaded_module_rows": {"type": "array", "minItems": 1, "items": {"type": "array", "prefixItems": [{"type": "string"},{"$ref": "#/$defs/Hex64"}], "items": false, "minItems": 2, "maxItems": 2}}, "loaded_module_roster_digest": {"$ref": "#/$defs/Hex64"}, "result_rows": {"type": "array", "minItems": 32, "maxItems": 32, "items": {"$ref": "cut4.r20.recognition_evidence.schema.v1#/$defs/VectorResult"}}, "result_roster_digest": {"$ref": "#/$defs/Hex64"}, "exit_code": {"const": 0}, "envelope_digest": {"$ref": "#/$defs/Hex64"}}},
    "RuntimeProof": {"type": "object", "additionalProperties": false, "required": ["schema","engine","command_intent","shell_tool_observation_digest","observed_result_sha256","process_envelope","read_set_exact_equal","forbidden_read_intersection_count","result_line_count","proof_digest"], "properties": {"schema": {"const": "cut4.r21.engine_runtime_proof.v1"}, "engine": {"enum": ["PARSER_A","PARSER_B","VERIFIER"]}, "command_intent": {"$ref": "#/$defs/CommandIntent"}, "shell_tool_observation_digest": {"type": "string", "pattern": "^[0-9a-f]{64}$"}, "observed_result_sha256": {"$ref": "#/$defs/Hex64"}, "process_envelope": {"$ref": "#/$defs/ProcessEnvelope"}, "read_set_exact_equal": {"const": true}, "forbidden_read_intersection_count": {"const": 0}, "result_line_count": {"const": 1}, "proof_digest": {"$ref": "#/$defs/Hex64"}}}
  },
  "oneOf": [{"$ref": "#/$defs/CommandIntent"},{"$ref": "#/$defs/ProcessEnvelope"},{"$ref": "#/$defs/RuntimeProof"}]
}
```

Every read row resolves through one input row with allowed mode and exact
pre/post hash equality. The read-row multiset equals audit events after the
runner's fixed bootstrap set; missing/extra/duplicate paths fail. Loaded
modules equal IMPORT/EXEC rows. The shell observation result bytes contain the
one exact envelope line; base64 decode, CJ reserialization, size/SHA and result
roster all reproduce. The R20 `ExecutionReceipt` gains mandatory
`runtime_proof_subject_admission_digest`, `runtime_proof_digest`,
`command_intent_digest`, `read_roster_digest`, and
`process_envelope_digest`; its results must byte-equal the observed envelope.
The verifier forbidden set contains the two parser receipt identities and the
3,601-byte accepted projection identity. This proves admitted-package use and
read-set containment under the stated Python runner, not independent logic.

## 3. Provider receipt/private ownership of normalized rows

R21 retains the inhabitable common BindingKey and three ProviderKps. It
replaces only the normalized row and adds an exact accounting receipt.

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "cut4.r21.normalized_ownership.schema.v1",
  "$defs": {
    "Hex64": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
    "ProviderKp": {"$ref": "cut4.r20.provider_binding.schema.v1#/$defs/ProviderKp"},
    "Payload": {"$ref": "cut4.r20.provider_binding.schema.v1#/$defs/PayloadRecord"},
    "SemanticItem": {"type": "object", "additionalProperties": false, "required": ["item_ordinal","semantic_class","subject_id","object_id","normalized_bytes_base64","normalized_byte_size","normalized_sha256","debt_code","item_digest"], "properties": {"item_ordinal": {"type": "integer", "minimum": 0}, "semantic_class": {"enum": ["GRAPH_NODE","GRAPH_EDGE","PROBE_RESULT","PATH_REFERENCE","CONTENT_INSTRUCTION","TYPED_ZERO","TYPED_DEBT","NOT_APPLICABLE"]}, "subject_id": {"type": "string"}, "object_id": {"type": "string"}, "normalized_bytes_base64": {"type": "string"}, "normalized_byte_size": {"type": "integer", "minimum": 0}, "normalized_sha256": {"$ref": "#/$defs/Hex64"}, "debt_code": {"enum": ["NONE","NORMALIZER_ZERO","MALFORMED","UNSUPPORTED"]}, "item_digest": {"$ref": "#/$defs/Hex64"}}},
    "NormalizedPayloadRow": {"type": "object", "additionalProperties": false, "required": ["schema","provider_kp","provider_receipt_digest","provider_receipt_envelope_digest","provider_private_digest","payload","payload_ordinal","normalizer_evidence_digest","semantic_items","semantic_item_count","semantic_item_roster_digest","row_digest"], "properties": {"schema": {"const": "cut4.r21.normalized_payload_row.v1"}, "provider_kp": {"$ref": "#/$defs/ProviderKp"}, "provider_receipt_digest": {"$ref": "#/$defs/Hex64"}, "provider_receipt_envelope_digest": {"$ref": "#/$defs/Hex64"}, "provider_private_digest": {"$ref": "#/$defs/Hex64"}, "payload": {"$ref": "#/$defs/Payload"}, "payload_ordinal": {"type": "integer", "minimum": 0}, "normalizer_evidence_digest": {"$ref": "#/$defs/Hex64"}, "semantic_items": {"type": "array", "minItems": 1, "items": {"$ref": "#/$defs/SemanticItem"}}, "semantic_item_count": {"type": "integer", "minimum": 1}, "semantic_item_roster_digest": {"$ref": "#/$defs/Hex64"}, "row_digest": {"$ref": "#/$defs/Hex64"}}},
    "AccountingRow": {"type": "object", "additionalProperties": false, "required": ["provider_receipt_digest","provider_private_digest","provider_receipt_envelope_digest","provider_kp_digest","payload_id","payload_digest","payload_ordinal","normalized_row_digest","semantic_item_count","accounting_digest"], "properties": {"provider_receipt_digest": {"$ref": "#/$defs/Hex64"}, "provider_private_digest": {"$ref": "#/$defs/Hex64"}, "provider_receipt_envelope_digest": {"$ref": "#/$defs/Hex64"}, "provider_kp_digest": {"$ref": "#/$defs/Hex64"}, "payload_id": {"type": "string", "minLength": 1}, "payload_digest": {"$ref": "#/$defs/Hex64"}, "payload_ordinal": {"type": "integer", "minimum": 0}, "normalized_row_digest": {"$ref": "#/$defs/Hex64"}, "semantic_item_count": {"type": "integer", "minimum": 1}, "accounting_digest": {"$ref": "#/$defs/Hex64"}}},
    "OwnershipReceipt": {"type": "object", "additionalProperties": false, "required": ["schema","bake_binding_digest","provider_receipt_roster_digest","provider_receipt_envelope_roster_digest","provider_private_roster_digest","expected_payload_roster_digest","normalized_rows","normalized_row_roster_digest","accounting_rows","accounting_roster_digest","missing_payload_count","extra_payload_count","duplicate_payload_count","foreign_kp_count","receipt_digest"], "properties": {"schema": {"const": "cut4.r21.normalized_ownership_receipt.v1"}, "bake_binding_digest": {"$ref": "#/$defs/Hex64"}, "provider_receipt_roster_digest": {"$ref": "#/$defs/Hex64"}, "provider_receipt_envelope_roster_digest": {"$ref": "#/$defs/Hex64"}, "provider_private_roster_digest": {"$ref": "#/$defs/Hex64"}, "expected_payload_roster_digest": {"$ref": "#/$defs/Hex64"}, "normalized_rows": {"type": "array", "items": {"$ref": "#/$defs/NormalizedPayloadRow"}}, "normalized_row_roster_digest": {"$ref": "#/$defs/Hex64"}, "accounting_rows": {"type": "array", "items": {"$ref": "#/$defs/AccountingRow"}}, "accounting_roster_digest": {"$ref": "#/$defs/Hex64"}, "missing_payload_count": {"const": 0}, "extra_payload_count": {"const": 0}, "duplicate_payload_count": {"const": 0}, "foreign_kp_count": {"const": 0}, "receipt_digest": {"$ref": "#/$defs/Hex64"}}}
  },
  "oneOf": [{"$ref": "#/$defs/NormalizedPayloadRow"},{"$ref": "#/$defs/OwnershipReceipt"}]
}
```

For every fixed-slot ProviderReceipt and receipt envelope, its
ProviderPrivateV6 has equal Kp, provider-receipt digest, receipt-envelope
digest, and exact ordered payload array. Each private payload
appears in exactly one normalized payload row with byte-equal embedded payload,
ordinal, digest, owning receipt digest, private digest, envelope digest, and Kp. Each normalized
row has at least one semantic item; a valid empty semantic result is one typed
`TYPED_ZERO`, never omission. Accounting rows are the exact join projection
sorted `(provider_ordinal,payload_ordinal)` and equal the private payload
multiset. This prevents cross-provider substitution without losing multi-item
payload recall. Constructor ownership is explicitly
`ProviderReceipt/ReceiptEnvelope/ProviderPrivateV6/PayloadRecord/ProviderKp ->
NormalizedPayloadRow -> OwnershipReceipt`.

## 4. Reproducible structured selectors and exact roots

### 4.1 Claim ceiling for the legacy names

The 256 inherited strings remain an exact ordered regression label roster.
R21 explicitly classifies the generated cases as `CODEC_MUTATION_REGRESSION`.
They test eight mutation codecs and transport/accounting, not the semantic
protocol predicate suggested by a historical label. They cannot satisfy a
future semantic RED denominator; that requires separately admitted typed
object/predicate fixtures. This removes the false protocol-coverage claim.

Selector identity is now the tuple `(selector_id,kind,logical_path,
span_policy)`. Logical path never contains prose about spans. In particular,
DELETE stores logical path `/payload/original` and span policy
`MEMBER_WITH_TRAILING_COMMA`. The source-map and catalog copy the same tuple
byte-for-byte.

```json
{
  "schema": "cut4.r21.mutation_generator.v1",
  "ordered_id_count": 256,
  "ordered_id_cj_byte_size": 9308,
  "ordered_id_cj_sha256": "dba824fd070bc64ef5ed44626f5744f4320f7ee0f39a3f9c455e65c45ba7103e",
  "operation_cycle": ["REPLACE","DELETE","INSERT","DUPLICATE","REORDER","RELABEL","TRUNCATE","CORRUPT"],
  "selector_rows": [
    [0,"sel.value.original","JSON_VALUE","/payload/original","VALUE_TOKEN","REPLACE","CJ(MUTATED_||h16)",0],
    [1,"sel.member.original","JSON_MEMBER","/payload/original","MEMBER_WITH_TRAILING_COMMA","DELETE","empty",0],
    [2,"sel.content.slot.start","JSON_CONTENT_POINT","/payload/slot","CONTENT_START","INSERT","U(INS_||h16)",0],
    [3,"sel.value.control","JSON_VALUE","/control","VALUE_TOKEN","DUPLICATE","empty",1],
    [4,"sel.array.order","JSON_ARRAY","/order","ARRAY_TOKEN","REORDER","CJ([0,2])",0],
    [5,"sel.string.original","JSON_STRING","/payload/original","VALUE_TOKEN","RELABEL","CJ(RELABEL_||h16)",0],
    [6,"sel.file.last","FILE_SUFFIX","$","LAST_BYTE","TRUNCATE","empty",0],
    [7,"sel.content.control.first","JSON_CONTENT_BYTE","/control","FIRST_CONTENT_BYTE","CORRUPT","01",0]
  ],
  "fixture_source_bundle_cj_byte_size": 143338,
  "fixture_source_bundle_cj_sha256": "0c7a7a1acb5375d44ef4970b7c402a5815c6393eb0887008cd0780e654411957",
  "fixture_source_total_bytes": 41307,
  "source_map_roster_cj_byte_size": 151827,
  "source_map_roster_cj_sha256": "3ca929921ac5a020eea33140192b3f0cba1596991f3a011f7e4393c26f628e49",
  "mutation_catalog_cj_byte_size": 331414,
  "mutation_catalog_cj_sha256": "fa8791e8baaf238594806bd83abafaf79d1c5145ea6c13984cc6d49700eeee61",
  "operation_counts": [["REPLACE",32],["DELETE",32],["INSERT",32],["DUPLICATE",32],["REORDER",32],["RELABEL",32],["TRUNCATE",32],["CORRUPT",32]]
}
```

For ordinal `i`, `h16=first16(H(U(label)))` and source is CJ of
`{case_id:label,control:"CONTROL_"||h16,order:[0,1,2],payload:{original:
"ORIGINAL_"||h16,slot:""}}`. Identity is
`bundle://cut4.r21.fixture_source_bundle/{i:03d}`. The exact selector row is
`i mod 8`; the canonical JSON adapter applies its literal span policy. Byte
lowering is R20 except for no implicit normalization: REORDER maps `[0,1,2]`
to `[1,2,0]`, and CORRUPT XORs `0x01`. Expected code is
`R21_CODEC_||upper(first16(H(U("code")||0x00||U(label))))`. Row digest is
`H(CJ(row without row_digest))`.

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "cut4.r21.mutation_artifacts.schema.v1",
  "$defs": {
    "Hex64": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
    "SourceRow": {"type": "object", "additionalProperties": false, "required": ["ordinal","mutation_id","source_identity","bytes_hex","byte_size","sha256"], "properties": {"ordinal": {"type": "integer", "minimum": 0, "maximum": 255}, "mutation_id": {"type": "string", "minLength": 1}, "source_identity": {"type": "string", "pattern": "^bundle://cut4\\.r21\\.fixture_source_bundle/[0-9]{3}$"}, "bytes_hex": {"type": "string", "pattern": "^(?:[0-9a-f]{2})+$"}, "byte_size": {"type": "integer", "minimum": 1}, "sha256": {"$ref": "#/$defs/Hex64"}}},
    "Selector": {"type": "object", "additionalProperties": false, "required": ["selector_id","kind","logical_path","span_policy","byte_start","byte_end","selected_sha256","source_map_row_digest"], "properties": {"selector_id": {"type": "string", "minLength": 1}, "kind": {"enum": ["JSON_VALUE","JSON_MEMBER","JSON_CONTENT_POINT","JSON_ARRAY","JSON_STRING","FILE_SUFFIX","JSON_CONTENT_BYTE"]}, "logical_path": {"type": "string", "minLength": 1}, "span_policy": {"enum": ["VALUE_TOKEN","MEMBER_WITH_TRAILING_COMMA","CONTENT_START","ARRAY_TOKEN","LAST_BYTE","FIRST_CONTENT_BYTE"]}, "byte_start": {"type": "integer", "minimum": 0}, "byte_end": {"type": "integer", "minimum": 0}, "selected_sha256": {"$ref": "#/$defs/Hex64"}, "source_map_row_digest": {"$ref": "#/$defs/Hex64"}}},
    "SourceMapRow": {"type": "object", "additionalProperties": false, "required": ["ordinal","mutation_id","source_identity","source_sha256","adapter_id","selector_id","selector_kind","logical_path","span_policy","byte_start","byte_end","selected_sha256","map_row_digest"], "properties": {"ordinal": {"type": "integer", "minimum": 0, "maximum": 255}, "mutation_id": {"type": "string", "minLength": 1}, "source_identity": {"type": "string", "minLength": 1}, "source_sha256": {"$ref": "#/$defs/Hex64"}, "adapter_id": {"const": "cut4.r21.canonical_json_source_map.v1"}, "selector_id": {"type": "string", "minLength": 1}, "selector_kind": {"enum": ["JSON_VALUE","JSON_MEMBER","JSON_CONTENT_POINT","JSON_ARRAY","JSON_STRING","FILE_SUFFIX","JSON_CONTENT_BYTE"]}, "logical_path": {"type": "string", "minLength": 1}, "span_policy": {"enum": ["VALUE_TOKEN","MEMBER_WITH_TRAILING_COMMA","CONTENT_START","ARRAY_TOKEN","LAST_BYTE","FIRST_CONTENT_BYTE"]}, "byte_start": {"type": "integer", "minimum": 0}, "byte_end": {"type": "integer", "minimum": 0}, "selected_sha256": {"$ref": "#/$defs/Hex64"}, "map_row_digest": {"$ref": "#/$defs/Hex64"}}},
    "SourceMapReceipt": {"type": "object", "additionalProperties": false, "required": ["schema","fixture_source_subject_admission_digest","fixture_source_sha256","adapter_subject_admission_digest","adapter_sha256","adapter_id","rows","row_count","row_roster_digest","canonical_row_bytes_base64","canonical_row_byte_size","canonical_row_sha256","receipt_digest"], "properties": {"schema": {"const": "cut4.r21.source_map_receipt.v1"}, "fixture_source_subject_admission_digest": {"$ref": "#/$defs/Hex64"}, "fixture_source_sha256": {"$ref": "#/$defs/Hex64"}, "adapter_subject_admission_digest": {"$ref": "#/$defs/Hex64"}, "adapter_sha256": {"$ref": "#/$defs/Hex64"}, "adapter_id": {"const": "cut4.r21.canonical_json_source_map.v1"}, "rows": {"type": "array", "minItems": 256, "maxItems": 256, "items": {"$ref": "#/$defs/SourceMapRow"}}, "row_count": {"const": 256}, "row_roster_digest": {"$ref": "#/$defs/Hex64"}, "canonical_row_bytes_base64": {"type": "string"}, "canonical_row_byte_size": {"const": 151827}, "canonical_row_sha256": {"const": "3ca929921ac5a020eea33140192b3f0cba1596991f3a011f7e4393c26f628e49"}, "receipt_digest": {"$ref": "#/$defs/Hex64"}}},
    "MutationRow": {"type": "object", "additionalProperties": false, "required": ["mutation_id","ordinal","catalog_class","source_identity","source_bytes_hex","source_byte_size","source_sha256","selector","operation","operand_hex","operation_parameter","mutated_byte_size","mutated_sha256","expected_codec_rejection_code","row_digest"], "properties": {"mutation_id": {"type": "string", "minLength": 1}, "ordinal": {"type": "integer", "minimum": 0, "maximum": 255}, "catalog_class": {"const": "CODEC_MUTATION_REGRESSION"}, "source_identity": {"type": "string", "minLength": 1}, "source_bytes_hex": {"type": "string", "pattern": "^(?:[0-9a-f]{2})+$"}, "source_byte_size": {"type": "integer", "minimum": 1}, "source_sha256": {"$ref": "#/$defs/Hex64"}, "selector": {"$ref": "#/$defs/Selector"}, "operation": {"enum": ["REPLACE","DELETE","INSERT","DUPLICATE","REORDER","RELABEL","TRUNCATE","CORRUPT"]}, "operand_hex": {"type": "string", "pattern": "^(?:[0-9a-f]{2})*$"}, "operation_parameter": {"type": "integer", "minimum": 0, "maximum": 1}, "mutated_byte_size": {"type": "integer", "minimum": 1}, "mutated_sha256": {"$ref": "#/$defs/Hex64"}, "expected_codec_rejection_code": {"type": "string", "pattern": "^R21_CODEC_[0-9A-F]{16}$"}, "row_digest": {"$ref": "#/$defs/Hex64"}}}
  },
  "oneOf": [{"$ref": "#/$defs/SourceRow"},{"$ref": "#/$defs/SourceMapReceipt"},{"$ref": "#/$defs/MutationRow"}]
}
```

Fixture bundle is exactly `{schema,rows,row_count}` with literal schema
`cut4.r21.fixture_source_bundle.v1`; source-map root is exactly
`{schema,adapter_id,rows,row_count}` with literal schema
`cut4.r21.source_map_roster.v1`; catalog is exactly
`{schema,generator_id,catalog_class,rows,row_count}` with literal schema
`cut4.r21.frozen_mutation_catalog.v1` and generator ID
`cut4.r21.mutation_generator.v1`. Map rows contain the
fields shown in schema order and `map_row_digest=H(CJ(row without digest))`.
Catalog selector copies map identity, tuple, offsets, selected SHA and row
digest exactly. Strict regeneration reproduces all three displayed sizes/
hashes, 256 unique rows, 32 of each operation, and no unchanged mutation.

## 5. Exact DAG delta and validation

R21 applies this closed delta to the authenticated R20 64-node/147-edge DAG.

```json
{
  "schema": "cut4.r21.constructor_dag_delta.v1",
  "base_schema": "cut4.r20.constructor_dag.v1",
  "remove_nodes": ["SealedRootToolEvent","RootObservationRecord"],
  "add_nodes": ["ObservationGenesis","RootToolCallResult","RootAttestedObservation","EngineCommandIntent","EngineProcessEnvelope","RuntimeReadSet"],
  "remove_edges": [["SealedRootToolEvent","RootObservationRecord"],["RootObservationRecord","OccurrenceRecord"],["SealedRootToolEvent","ProcessObservationRecord"]],
  "add_edges": [
    ["ObservationGenesis","EventSourceAdmission"],["RootToolCallResult","RootAttestedObservation"],["EventSourceAdmission","RootAttestedObservation"],["RootAttestedObservation","OccurrenceRecord"],
    ["FrozenSpecs","EngineCommandIntent"],["ParserAPackage","EngineCommandIntent"],["ParserBPackage","EngineCommandIntent"],["VerifierPackage","EngineCommandIntent"],["DependencyClosureA","EngineCommandIntent"],["DependencyClosureB","EngineCommandIntent"],["DependencyClosureV","EngineCommandIntent"],
    ["EngineCommandIntent","EngineProcessEnvelope"],["RootToolCallResult","EngineProcessEnvelope"],["EngineProcessEnvelope","RuntimeReadSet"],
    ["EngineCommandIntent","ParserAReceipt"],["EngineCommandIntent","ParserBReceipt"],["EngineCommandIntent","VerifierReceipt"],["EngineProcessEnvelope","ParserAReceipt"],["EngineProcessEnvelope","ParserBReceipt"],["EngineProcessEnvelope","VerifierReceipt"],["RuntimeReadSet","ParserAReceipt"],["RuntimeReadSet","ParserBReceipt"],["RuntimeReadSet","VerifierReceipt"],
    ["RootAttestedObservation","ProcessObservationRecord"],["EngineCommandIntent","ProcessObservationRecord"],
    ["ProviderReceipt","NormalizedSemanticRow"],["ReceiptEnvelope","NormalizedSemanticRow"],["ProviderPrivateV6","NormalizedSemanticRow"]
  ],
  "result_node_count": 68,
  "result_edge_count": 172
}
```

Node replacement maps R20 `NormalizedSemanticRow` to the R21 closed
`NormalizedPayloadRow` without changing the node label used by the inherited
graph. Applying removals before additions yields 68 unique nodes/172 unique
edges, known endpoints, and zero Kahn remainder. The unchanged subject route
remains 116/206, now with 46 post-genesis roles.

Independent review executes this exact 24-check roster:

```json
{
  "schema": "cut4.r21.architecture_check_roster.v1",
  "checks": [
    "R21-01-review-size-sha","R21-02-r20-subject-receipt-hashes","R21-03-json-strict","R21-04-metaschema-refs","R21-05-utf8-lf-fences","R21-06-scoped-two-files",
    "R21-07-genesis-schema-inhabitable","R21-08-no-retrospective-author-occurrence","R21-09-only-live-supported-tool-names","R21-10-root-attestation-claim-ceiling","R21-11-generation-cas-prefix","R21-12-route-116-206-46-roles",
    "R21-13-engine-intent-before-shell","R21-14-observed-result-envelope-exact","R21-15-read-set-total-allowed","R21-16-verifier-forbidden-intersection-zero","R21-17-receipt-results-from-process","R21-18-no-algorithm-independence-claim",
    "R21-19-normalized-owning-envelope-private-payload-kp","R21-20-normalized-accounting-exact-no-orphan",
    "R21-21-selector-structured-delete-reproducible","R21-22-source-map-schema-preimage-and-hash","R21-23-catalog-256-eight-ops-size-sha-generic-ceiling","R21-24-dag-delta-68-172-zero-remainder"
  ],
  "check_count": 24
}
```

## 6. Claim ceiling

Future order is ACCEPT review, typed genesis and architecture admission, then
the inherited route: fixture source, admitted source-map adapter/receipt,
catalog, packages/dependency closures, test, root-attested contained engine
runs/read sets, RED, model, and GREEN. R21 provides architecture only. It does
not authorize or prove observations, fixtures, semantic mutation coverage,
parsers, verifier independence, tests, model, provider/production changes,
ArtifactLedger/G3 edits, audit results, protocol answers, release, or readiness.
Recall is preserved by exact provider-payload accounting and typed zero rows;
precision improves through observed read containment, owning-provider joins,
and byte-reproducible structured selectors.
