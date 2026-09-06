# Cut-4 transactional recon publication R19 preimplementation contract

Date: 2026-08-10
Status: Part-0 architecture-only repair awaiting independent review
Supersedes: only the four rejected R18 gates and the two colliding R18 mutation IDs
Authority: all admission, parser, verifier, fixture, test, model, execution,
production, provider, ArtifactLedger, G3, audit, commit, push, install, cutover,
release, readiness, and protocol-answer authority is false

## 0. Boundary, authentication, and inheritance

This turn creates only this contract and its author receipt. It does not create
or edit a review, route record, parser, verifier, fixture, source-map receipt,
test, execution record, model, production/provider path, ArtifactLedger row, or
G3 pin, and it does not execute any future test or provider.

The exact R18 independent review was authenticated and read completely before
this amendment was written:

| Artifact | Bytes | SHA-256 |
|---|---:|---|
| `review_fixtures/cut4_transactional_recon_publication_r18_architecture_independent_review_20260810.md` | 20,470 | `ecb8306a42bc372eafcef9d8726d5f14f0900eab1eac67e2766d6868318d2b23` |
| `architecture/cut4-transactional-recon-publication-r18-preimplementation-contract.md` | 90,647 | `a3acfbea0077e6698dd1deccc6b5ebc4ddc827f68fa98938c69709697dd2d802` |
| `review_fixtures/cut4_transactional_recon_publication_r18_contract_author_receipt_20260810.md` | 5,203 | `e62e541df6ace7a4ade613644a177a1abdfb0177c162a2251f75b199fcb64055` |

R19 inherits every accepted R1-R18 clause outside the rejected gates: the sole
`recon/canonical_merge` public owner, immutable MODEL seed visibility, fixed
provider slots `source_graph/build_probe/daml_source_graph`, nonempty typed
outcomes, stable registered publication successor, terminal-before-link
journal order, complete SC/L1 tuples, compatibility projection, legacy
non-adoption, exact replay/crash recovery, project-root containment, unchanged
MODEL shards/dependency units, and nonempty exhausted c3. R19 replacements
below control where R18 conflicts. R13 evidence is not authority.

`H` is SHA-256 over bytes. `U` is strict UTF-8 of an NFC string. `CJ` is RFC
8785 canonical JSON after duplicate-key, non-finite, surrogate, and non-NFC
rejection. `D(tag,x)=H(U(tag||"\\0")||CJ(x))`. Hex is lowercase and strict;
arrays are ordered. `EMPTY_SHA` is
`e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.
These hashes authenticate bytes and joins, not a human principal, signature,
non-collusion, or independence.

```json
{
  "schema": "cut4.r19.path_registry.v1",
  "contract": "architecture/cut4-transactional-recon-publication-r19-preimplementation-contract.md",
  "author_receipt": "review_fixtures/cut4_transactional_recon_publication_r19_contract_author_receipt_20260810.md",
  "architecture_review": "review_fixtures/cut4_transactional_recon_publication_r19_architecture_independent_review_20260810.md",
  "architecture_admission": "review_fixtures/cut4_transactional_recon_publication_r19_route/000_architecture_admission.json",
  "route_directory": "review_fixtures/cut4_transactional_recon_publication_r19_route",
  "parser_a_package": "review_fixtures/cut4_transactional_recon_publication_r19_parser_a.py",
  "parser_b_package": "review_fixtures/cut4_transactional_recon_publication_r19_parser_b.py",
  "verifier_package": "review_fixtures/cut4_transactional_recon_publication_r19_independent_verifier.py",
  "red_test": "tests/test_cut4_transactional_recon_publication_r19_preimplementation.py",
  "source_map_receipt": "review_fixtures/cut4_transactional_recon_publication_r19_source_map_receipt.json",
  "parser_a_execution_receipt": "review_fixtures/cut4_transactional_recon_publication_r19_parser_a_execution_receipt.json",
  "parser_b_execution_receipt": "review_fixtures/cut4_transactional_recon_publication_r19_parser_b_execution_receipt.json",
  "verifier_execution_receipt": "review_fixtures/cut4_transactional_recon_publication_r19_verifier_execution_receipt.json",
  "negative_proof_receipt": "review_fixtures/cut4_transactional_recon_publication_r19_negative_proof_receipt.json",
  "red_pre_snapshot": "review_fixtures/cut4_transactional_recon_publication_r19_red_pre_snapshot.json",
  "red_execution_event": "review_fixtures/cut4_transactional_recon_publication_r19_red_execution_event.json",
  "red_observer_receipt": "review_fixtures/cut4_transactional_recon_publication_r19_red_observer_receipt.json",
  "red_author_receipt": "review_fixtures/cut4_transactional_recon_publication_r19_red_author_receipt.json",
  "model": "review_fixtures/cut4_transactional_recon_publication_r19_reference_model.py",
  "green_pre_snapshot": "review_fixtures/cut4_transactional_recon_publication_r19_green_pre_snapshot.json",
  "green_execution_event": "review_fixtures/cut4_transactional_recon_publication_r19_green_execution_event.json",
  "green_observer_receipt": "review_fixtures/cut4_transactional_recon_publication_r19_green_observer_receipt.json",
  "green_author_receipt": "review_fixtures/cut4_transactional_recon_publication_r19_green_author_receipt.json"
}
```

## 1. Actual author occurrence and globally non-aliasing route

### 1.1 The architecture admission authenticates the observed author task

The contract and receipt preexist an independent review. After and only after
an ACCEPT review, root creates the architecture admission with
`O_CREAT|O_EXCL`. Unlike R18, admission carries the root-observed author
`TASK_START` and `TASK_RESULT`, not an author-receipt assertion. The result
payload must contain output observations for the exact contract and receipt.
It also carries the root-observed review result. The two handles and occurrence
IDs must differ. A receipt's task label is descriptive until these event joins
pass.

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "cut4.r19.route_records.schema.v1",
  "$defs": {
    "Hex64": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
    "TaskHandle": {"type": "string", "pattern": "^/root(?:/[a-z0-9_]+)+$"},
    "Role": {"type": "string", "pattern": "^[A-Z][A-Z0-9_]{2,63}$"},
    "ByteSubject": {
      "type": "object", "additionalProperties": false,
      "required": ["identity", "bytes_base64", "byte_size", "sha256"],
      "properties": {
        "identity": {"type": "string", "minLength": 1},
        "bytes_base64": {"type": "string"},
        "byte_size": {"type": "integer", "minimum": 1},
        "sha256": {"$ref": "#/$defs/Hex64"}
      }
    },
    "RuntimeEvent": {
      "type": "object", "additionalProperties": false,
      "required": ["schema", "adapter_id", "event_kind", "raw_event_bytes_base64", "raw_event_byte_size", "raw_event_sha256", "task_handle", "parent_handle", "occurrence_id", "payload_bytes_base64", "payload_byte_size", "payload_sha256", "output_observations", "event_digest"],
      "properties": {
        "schema": {"const": "cut4.r19.runtime_event.v1"},
        "adapter_id": {"const": "codex-orchestration-event-json-v1"},
        "event_kind": {"enum": ["TASK_START", "TASK_RESULT"]},
        "raw_event_bytes_base64": {"type": "string"},
        "raw_event_byte_size": {"type": "integer", "minimum": 1},
        "raw_event_sha256": {"$ref": "#/$defs/Hex64"},
        "task_handle": {"$ref": "#/$defs/TaskHandle"},
        "parent_handle": {"const": "/root"},
        "occurrence_id": {"type": "string", "pattern": "^occ_[a-z0-9_-]{8,128}$"},
        "payload_bytes_base64": {"type": "string"},
        "payload_byte_size": {"type": "integer", "minimum": 0},
        "payload_sha256": {"$ref": "#/$defs/Hex64"},
        "output_observations": {"type": "array", "uniqueItems": true, "items": {"$ref": "#/$defs/ByteSubject"}},
        "event_digest": {"$ref": "#/$defs/Hex64"}
      }
    },
    "RoleClaim": {
      "type": "object", "additionalProperties": false,
      "required": ["role", "subject_id", "lifecycle_kind", "task_handle", "occurrence_id", "start_event_digest", "result_event_digest", "claim_digest"],
      "properties": {
        "role": {"$ref": "#/$defs/Role"},
        "subject_id": {"type": "string", "pattern": "^(ARCH|S[0-9]{2})$"},
        "lifecycle_kind": {"enum": ["AUTHOR", "REVIEWER"]},
        "task_handle": {"$ref": "#/$defs/TaskHandle"},
        "occurrence_id": {"type": "string", "pattern": "^occ_[a-z0-9_-]{8,128}$"},
        "start_event_digest": {"$ref": "#/$defs/Hex64"},
        "result_event_digest": {"$ref": "#/$defs/Hex64"},
        "claim_digest": {"$ref": "#/$defs/Hex64"}
      }
    },
    "ArchitectureAdmission": {
      "type": "object", "additionalProperties": false,
      "required": ["schema", "contract", "author_receipt", "review", "author_start_event", "author_result_event", "review_start_event", "review_result_event", "role_claims", "role_manifest_digest", "decision", "reviewed_subject_digest", "admission_ordinal", "admission_digest"],
      "properties": {
        "schema": {"const": "cut4.r19.architecture_admission.v1"},
        "contract": {"$ref": "#/$defs/ByteSubject"},
        "author_receipt": {"$ref": "#/$defs/ByteSubject"},
        "review": {"$ref": "#/$defs/ByteSubject"},
        "author_start_event": {"$ref": "#/$defs/RuntimeEvent"},
        "author_result_event": {"$ref": "#/$defs/RuntimeEvent"},
        "review_start_event": {"$ref": "#/$defs/RuntimeEvent"},
        "review_result_event": {"$ref": "#/$defs/RuntimeEvent"},
        "role_claims": {"type": "array", "minItems": 2, "maxItems": 2, "items": {"$ref": "#/$defs/RoleClaim"}},
        "role_manifest_digest": {"$ref": "#/$defs/Hex64"},
        "decision": {"const": "ACCEPT"},
        "reviewed_subject_digest": {"$ref": "#/$defs/Hex64"},
        "admission_ordinal": {"const": 0},
        "admission_digest": {"$ref": "#/$defs/Hex64"}
      }
    },
    "ProducerStart": {
      "type": "object", "additionalProperties": false,
      "required": ["schema", "subject_id", "subject_identity", "producer_role", "producer_start_event", "architecture_admission_digest", "predecessor_subject_admission_digests", "subject_absence_digest", "start_digest"],
      "properties": {
        "schema": {"const": "cut4.r19.producer_start.v1"},
        "subject_id": {"type": "string", "pattern": "^S(?:0[1-9]|1[0-8])$"},
        "subject_identity": {"type": "string", "minLength": 1},
        "producer_role": {"$ref": "#/$defs/Role"},
        "producer_start_event": {"$ref": "#/$defs/RuntimeEvent"},
        "architecture_admission_digest": {"$ref": "#/$defs/Hex64"},
        "predecessor_subject_admission_digests": {"type": "array", "uniqueItems": true, "items": {"$ref": "#/$defs/Hex64"}},
        "subject_absence_digest": {"$ref": "#/$defs/Hex64"},
        "start_digest": {"$ref": "#/$defs/Hex64"}
      }
    },
    "ProducerCompletion": {
      "type": "object", "additionalProperties": false,
      "required": ["schema", "subject_id", "producer_role", "producer_start_digest", "producer_result_event", "subject", "completion_digest"],
      "properties": {
        "schema": {"const": "cut4.r19.producer_completion.v1"},
        "subject_id": {"type": "string", "pattern": "^S(?:0[1-9]|1[0-8])$"},
        "producer_role": {"$ref": "#/$defs/Role"},
        "producer_start_digest": {"$ref": "#/$defs/Hex64"},
        "producer_result_event": {"$ref": "#/$defs/RuntimeEvent"},
        "subject": {"$ref": "#/$defs/ByteSubject"},
        "completion_digest": {"$ref": "#/$defs/Hex64"}
      }
    },
    "ReviewStart": {
      "type": "object", "additionalProperties": false,
      "required": ["schema", "subject_id", "reviewer_role", "producer_completion_digest", "producer_task_handle", "producer_occurrence_id", "review_start_event", "review_identity", "review_absence_digest", "start_digest"],
      "properties": {
        "schema": {"const": "cut4.r19.review_start.v1"},
        "subject_id": {"type": "string", "pattern": "^S(?:0[1-9]|1[0-8])$"},
        "reviewer_role": {"$ref": "#/$defs/Role"},
        "producer_completion_digest": {"$ref": "#/$defs/Hex64"},
        "producer_task_handle": {"$ref": "#/$defs/TaskHandle"},
        "producer_occurrence_id": {"type": "string", "minLength": 1},
        "review_start_event": {"$ref": "#/$defs/RuntimeEvent"},
        "review_identity": {"type": "string", "minLength": 1},
        "review_absence_digest": {"$ref": "#/$defs/Hex64"},
        "start_digest": {"$ref": "#/$defs/Hex64"}
      }
    },
    "ReviewCompletion": {
      "type": "object", "additionalProperties": false,
      "required": ["schema", "subject_id", "reviewer_role", "review_start_digest", "review_result_event", "review", "decision", "completion_digest"],
      "properties": {
        "schema": {"const": "cut4.r19.review_completion.v1"},
        "subject_id": {"type": "string", "pattern": "^S(?:0[1-9]|1[0-8])$"},
        "reviewer_role": {"$ref": "#/$defs/Role"},
        "review_start_digest": {"$ref": "#/$defs/Hex64"},
        "review_result_event": {"$ref": "#/$defs/RuntimeEvent"},
        "review": {"$ref": "#/$defs/ByteSubject"},
        "decision": {"enum": ["ACCEPT", "REPAIR"]},
        "completion_digest": {"$ref": "#/$defs/Hex64"}
      }
    },
    "SubjectAdmission": {
      "type": "object", "additionalProperties": false,
      "required": ["schema", "subject_id", "producer_role", "producer_completion_digest", "producer_task_handle", "producer_occurrence_id", "reviewer_role", "review_completion_digest", "review_task_handle", "review_occurrence_id", "decision", "subject_sha256", "prior_role_manifest_digest", "role_manifest_rows", "role_manifest_digest", "subject_admission_digest"],
      "properties": {
        "schema": {"const": "cut4.r19.subject_admission.v1"},
        "subject_id": {"type": "string", "pattern": "^S(?:0[1-9]|1[0-8])$"},
        "producer_role": {"$ref": "#/$defs/Role"},
        "producer_completion_digest": {"$ref": "#/$defs/Hex64"},
        "producer_task_handle": {"$ref": "#/$defs/TaskHandle"},
        "producer_occurrence_id": {"type": "string", "minLength": 1},
        "reviewer_role": {"$ref": "#/$defs/Role"},
        "review_completion_digest": {"$ref": "#/$defs/Hex64"},
        "review_task_handle": {"$ref": "#/$defs/TaskHandle"},
        "review_occurrence_id": {"type": "string", "minLength": 1},
        "decision": {"const": "ACCEPT"},
        "subject_sha256": {"$ref": "#/$defs/Hex64"},
        "prior_role_manifest_digest": {"$ref": "#/$defs/Hex64"},
        "role_manifest_rows": {"type": "array", "minItems": 4, "maxItems": 38, "uniqueItems": true, "items": {"$ref": "#/$defs/RoleClaim"}},
        "role_manifest_digest": {"$ref": "#/$defs/Hex64"},
        "subject_admission_digest": {"$ref": "#/$defs/Hex64"}
      }
    }
  },
  "oneOf": [
    {"$ref": "#/$defs/ArchitectureAdmission"}, {"$ref": "#/$defs/ProducerStart"}, {"$ref": "#/$defs/ProducerCompletion"},
    {"$ref": "#/$defs/ReviewStart"}, {"$ref": "#/$defs/ReviewCompletion"}, {"$ref": "#/$defs/SubjectAdmission"}
  ]
}
```

Strict base64 decode must reproduce every size/SHA. A runtime event is the
canonical projection of immutable raw orchestration bytes at exact pointers
`/event_kind,/task_handle,/parent_handle,/occurrence_id,/payload_base64,
/output_observations`; canonical reserialization must equal the raw bytes.
The start/result events of one lifecycle have equal handle and occurrence,
opposite event kinds, and correct payload/output subjects. Author result
output observations contain the contract and receipt byte subjects exactly;
review result payload equals review bytes. Admission claims are ordered
`ARCHITECTURE_AUTHOR,ARCHITECTURE_REVIEWER`, copied from those events, and
must have distinct task handles and occurrence IDs.

For subject `Snn`, the routed roles are literal below. Its admission appends
exactly two claims to the previous manifest: producer then reviewer. It copies
their handles/occurrences/events and the schema checks that (a) every role
appears once, (b) every handle appears once, (c) every occurrence appears
once, and (d) every claim's subject/role/lifecycle equals the route row. Thus
cross-subject handle aliases, cross-subject occurrence aliases, A/B/V aliases,
and author/reviewer aliases are rejected. There is no boolean distinctness
claim. `S01.prior_role_manifest_digest` equals the architecture manifest;
each later value equals the immediately previous subject admission manifest.
That prefix equality serializes admissions, not task execution, and no
subject becomes usable until its alias-free admission exists.

### 1.2 Exact routed subjects and DAG

```json
{
  "schema": "cut4.r19.subject_route.v1",
  "rows": [
    ["S01", "parser_a_package", "PARSER_A_AUTHOR", "PARSER_A_REVIEWER", []],
    ["S02", "parser_b_package", "PARSER_B_AUTHOR", "PARSER_B_REVIEWER", []],
    ["S03", "verifier_package", "VERIFIER_AUTHOR", "VERIFIER_REVIEWER", []],
    ["S04", "red_test", "RED_TEST_AUTHOR", "RED_TEST_REVIEWER", ["S01", "S02", "S03"]],
    ["S05", "source_map_receipt", "SOURCE_MAP_AUTHOR", "SOURCE_MAP_REVIEWER", ["S04"]],
    ["S06", "parser_a_execution_receipt", "PARSER_A_RUNNER", "PARSER_A_RUN_REVIEWER", ["S01", "S04"]],
    ["S07", "parser_b_execution_receipt", "PARSER_B_RUNNER", "PARSER_B_RUN_REVIEWER", ["S02", "S04"]],
    ["S08", "verifier_execution_receipt", "VERIFIER_RUNNER", "VERIFIER_RUN_REVIEWER", ["S03", "S06", "S07"]],
    ["S09", "negative_proof_receipt", "NEGATIVE_PROOF_AUTHOR", "NEGATIVE_PROOF_REVIEWER", ["S08"]],
    ["S10", "red_pre_snapshot", "RED_PRE_OBSERVER", "RED_PRE_REVIEWER", ["S04", "S09"]],
    ["S11", "red_execution_event", "RED_EVENT_PRODUCER", "RED_EVENT_REVIEWER", ["S10"]],
    ["S12", "red_observer_receipt", "RED_POST_OBSERVER", "RED_POST_REVIEWER", ["S10", "S11"]],
    ["S13", "red_author_receipt", "RED_RECEIPT_AUTHOR", "RED_RECEIPT_REVIEWER", ["S04", "S05", "S06", "S07", "S08", "S09", "S10", "S11", "S12"]],
    ["S14", "model", "MODEL_IMPLEMENTER", "MODEL_REVIEWER", ["S13"]],
    ["S15", "green_pre_snapshot", "GREEN_PRE_OBSERVER", "GREEN_PRE_REVIEWER", ["S04", "S14"]],
    ["S16", "green_execution_event", "GREEN_EVENT_PRODUCER", "GREEN_EVENT_REVIEWER", ["S15"]],
    ["S17", "green_observer_receipt", "GREEN_POST_OBSERVER", "GREEN_POST_REVIEWER", ["S15", "S16"]],
    ["S18", "green_author_receipt", "GREEN_RECEIPT_AUTHOR", "GREEN_RECEIPT_REVIEWER", ["S04", "S14", "S15", "S16", "S17"]]
  ],
  "record_expansion": ["PRODUCER_START", "PRODUCER_COMPLETION", "REVIEW_START", "REVIEW_COMPLETION", "SUBJECT_ADMISSION"],
  "record_identity_template": "review_fixtures/cut4_transactional_recon_publication_r19_route/{subject_id_lower}_{record_kind_lower}.json",
  "review_identity_template": "review_fixtures/cut4_transactional_recon_publication_r19_route/{subject_id_lower}_independent_review.md",
  "subject_count": 18,
  "predecessor_edge_count": 37,
  "global_role_count": 38
}
```

Expansion has 91 nodes: one architecture admission and five records for 18
subjects. It has 162 edges: 18 admission-to-start, 90 five-edge lifecycles,
37 displayed subject-predecessor edges, and 17 previous-manifest-admission to
next-admission edges. All route dependencies point to lower row ordinals;
Kahn remainder is zero. The final manifest has the two architecture claims
plus 36 subject claims, and pairwise uniqueness is checked over all 38.

## 2. Schema-valid literal recognition inputs and derived tuples

R19 retains the exact R18 ecosystem-gated grammar, comment/operator tables,
normalization/error semantics, matcher opcodes, priority order, and full-byte
coverage rules. It replaces only the invalid vector BAKE encoding and makes
tuple derivation an explicit result rather than caller input.

### 2.1 Closed conformance BAKE input

The conformance BAKE input is deliberately a separately named schema; it is
not misrepresented as a production `BakeBinding`. Its deterministic adapter
to the production types is versioned and independently run by A, B, and V.

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "cut4.r19.conformance_bake.schema.v1",
  "$defs": {
    "ProviderSlot": {
      "type": "object", "additionalProperties": false,
      "required": ["provider_id", "provider_ordinal", "status", "fact_count"],
      "properties": {
        "provider_id": {"enum": ["source_graph", "build_probe", "daml_source_graph"]},
        "provider_ordinal": {"type": "integer", "minimum": 0, "maximum": 2},
        "status": {"enum": ["NOT_APPLICABLE", "SUCCESS"]},
        "fact_count": {"type": "integer", "minimum": 0}
      }
    },
    "Fact": {
      "type": "object", "additionalProperties": false,
      "required": ["provider_id", "provider_ordinal", "fact_ordinal", "fact_kind", "subject_id", "object_id", "raw_bytes_hex"],
      "properties": {
        "provider_id": {"enum": ["source_graph", "build_probe", "daml_source_graph"]},
        "provider_ordinal": {"type": "integer", "minimum": 0, "maximum": 2},
        "fact_ordinal": {"type": "integer", "minimum": 0},
        "fact_kind": {"enum": ["GRAPH_NODE", "GRAPH_EDGE", "PROBE_RESULT", "TYPED_DEBT"]},
        "subject_id": {"type": "string", "minLength": 1},
        "object_id": {"type": "string", "minLength": 1},
        "raw_bytes_hex": {"type": "string", "pattern": "^(?:[0-9a-f]{2})+$"}
      }
    },
    "Input": {
      "type": "object", "additionalProperties": false,
      "required": ["schema", "input_id", "provider_slots", "facts"],
      "properties": {
        "schema": {"const": "cut4.r19.conformance_bake_input.v1"},
        "input_id": {"enum": ["BAKE_EMPTY", "BAKE_GRAPH_EDGE"]},
        "provider_slots": {"type": "array", "minItems": 3, "maxItems": 3, "items": {"$ref": "#/$defs/ProviderSlot"}},
        "facts": {"type": "array", "items": {"$ref": "#/$defs/Fact"}}
      }
    }
  },
  "$ref": "#/$defs/Input"
}
```

```json
{
  "schema": "cut4.r19.literal_bake_inputs.v1",
  "inputs": [
    {
      "schema": "cut4.r19.conformance_bake_input.v1",
      "input_id": "BAKE_EMPTY",
      "provider_slots": [
        {"provider_id": "source_graph", "provider_ordinal": 0, "status": "NOT_APPLICABLE", "fact_count": 0},
        {"provider_id": "build_probe", "provider_ordinal": 1, "status": "NOT_APPLICABLE", "fact_count": 0},
        {"provider_id": "daml_source_graph", "provider_ordinal": 2, "status": "NOT_APPLICABLE", "fact_count": 0}
      ],
      "facts": []
    },
    {
      "schema": "cut4.r19.conformance_bake_input.v1",
      "input_id": "BAKE_GRAPH_EDGE",
      "provider_slots": [
        {"provider_id": "source_graph", "provider_ordinal": 0, "status": "SUCCESS", "fact_count": 1},
        {"provider_id": "build_probe", "provider_ordinal": 1, "status": "NOT_APPLICABLE", "fact_count": 0},
        {"provider_id": "daml_source_graph", "provider_ordinal": 2, "status": "NOT_APPLICABLE", "fact_count": 0}
      ],
      "facts": [
        {"provider_id": "source_graph", "provider_ordinal": 0, "fact_ordinal": 0, "fact_kind": "GRAPH_EDGE", "subject_id": "a", "object_id": "b", "raw_bytes_hex": "7b22666163745f6b696e64223a2247524150485f45444745222c226f626a6563745f6964223a2262222c227375626a6563745f6964223a2261227d"}
      ]
    }
  ],
  "input_count": 2
}
```

The input validator requires exact fixed slot order, gapless fact ordinals,
slot `fact_count` equality, facts owned by their slot, `SUCCESS` iff nonzero
facts for this conformance corpus, and no facts for `NOT_APPLICABLE`. The BAKE
adapter `cut4.r19.conformance_bake_to_fact.v1` decodes raw hex, verifies it is
exact CJ of `{fact_kind,object_id,subject_id}`, and emits the production fact
preimage `(provider_id,provider_ordinal,fact_ordinal,fact_kind,subject_id,
object_id,raw_bytes,size,H(raw))`. The Kp/receipt authority fields are supplied
only by the typed construction in Section 3; conformance never self-mints
them. The semantic matcher maps each converted `GRAPH_EDGE` to exactly
`(0,0,GRAPH_EDGE,subject_id||"->"||object_id,NONE)`. A/B/V independently
execute this adapter and bind both `bake_input_digest=D("cut4.r19.
conformance_bake_input.v1",input)` and the converted fact-roster digest.

### 2.2 Exact source-byte denominator

Rows are `[id,ecosystem,source_hex,bake_input_id]`. Source hex is literal,
even-length lowercase. This is the exact R18 32-vector source denominator;
only its invalid BAKE column is replaced.

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "cut4.r19.conformance_source_vectors.schema.v1",
  "type": "object", "additionalProperties": false,
  "required": ["schema", "rows", "row_count", "source_byte_count", "expected_tuple_projection_codec", "expected_tuple_projection_byte_size", "expected_tuple_projection_sha256", "expected_token_count", "expected_semantic_count"],
  "properties": {
    "schema": {"const": "cut4.r19.conformance_source_vectors.v1"},
    "rows": {
      "type": "array", "minItems": 32, "maxItems": 32,
      "items": {
        "type": "array", "minItems": 4, "maxItems": 4, "items": false,
        "prefixItems": [
          {"type": "string", "minLength": 1},
          {"enum": ["aptos", "daml", "evm", "go", "rust", "solana", "soroban", "sui"]},
          {"type": "string", "pattern": "^(?:[0-9a-f]{2})*$"},
          {"enum": ["BAKE_EMPTY", "BAKE_GRAPH_EDGE"]}
        ]
      }
    },
    "row_count": {"const": 32},
    "source_byte_count": {"const": 200},
    "expected_tuple_projection_codec": {"const": "CJ([[vector_id,token_tuple_ascii,semantic_tuple_ascii],...])"},
    "expected_tuple_projection_byte_size": {"const": 3601},
    "expected_tuple_projection_sha256": {"const": "4926231311764bd356f2b86f18d7f4923d59cf8e82275eecbe2ec1e2aef04e30"},
    "expected_token_count": {"const": 121},
    "expected_semantic_count": {"const": 31}
  }
}
```

```json
{
  "schema": "cut4.r19.conformance_source_vectors.v1",
  "rows": [
    ["empty","evm","","BAKE_EMPTY"],
    ["evm_line_comment","evm","2f2f78","BAKE_EMPTY"],
    ["daml_line_comment","daml","2d2d78","BAKE_EMPTY"],
    ["evm_dash_not_comment","evm","2d2d78","BAKE_EMPTY"],
    ["daml_slash_not_comment","daml","2f2f78","BAKE_EMPTY"],
    ["evm_block_comment","evm","2f2a782a2f","BAKE_EMPTY"],
    ["daml_block_comment","daml","7b2d782d7d","BAKE_EMPTY"],
    ["evm_unterminated_comment","evm","2f2a78","BAKE_EMPTY"],
    ["daml_unterminated_comment","daml","7b2d78","BAKE_EMPTY"],
    ["identifier","evm","616263","BAKE_EMPTY"],
    ["evm_declaration","evm","66756e6374696f6e2066","BAKE_EMPTY"],
    ["daml_declaration","daml","646174612058","BAKE_EMPTY"],
    ["evm_import","evm","696d706f7274202278223b","BAKE_EMPTY"],
    ["daml_import","daml","696d706f72742058","BAKE_EMPTY"],
    ["member_call","evm","612e6228","BAKE_EMPTY"],
    ["call","evm","6128","BAKE_EMPTY"],
    ["path_call_context","evm","726561642822782229","BAKE_EMPTY"],
    ["content_call_context","evm","70726f6d70742822782229","BAKE_EMPTY"],
    ["nested_context","evm","726561642870726f6d7074282278222929","BAKE_EMPTY"],
    ["invalid_lead","evm","ff","BAKE_EMPTY"],
    ["invalid_overlong","evm","c0af","BAKE_EMPTY"],
    ["invalid_surrogate","evm","eda080","BAKE_EMPTY"],
    ["invalid_truncated","evm","e282","BAKE_EMPTY"],
    ["nul_byte","evm","00","BAKE_EMPTY"],
    ["double_string","evm","227822","BAKE_EMPTY"],
    ["unterminated_string","evm","2278","BAKE_EMPTY"],
    ["escape_eof","evm","225c","BAKE_EMPTY"],
    ["crlf_whitespace","evm","200d0a","BAKE_EMPTY"],
    ["assignment_path","evm","70617468203d20227822","BAKE_EMPTY"],
    ["keyword_boundary","evm","66756e6374696f6e78","BAKE_EMPTY"],
    ["generic_common_omission","evm","66756e6374696f6e20663b20696d706f7274202278223b20612e6228293b207265616428227022293b2070726f6d70742822632229","BAKE_EMPTY"],
    ["bake_graph_edge","evm","","BAKE_GRAPH_EDGE"]
  ],
  "row_count": 32,
  "source_byte_count": 200,
  "expected_tuple_projection_codec": "CJ([[vector_id,token_tuple_ascii,semantic_tuple_ascii],...])",
  "expected_tuple_projection_byte_size": 3601,
  "expected_tuple_projection_sha256": "4926231311764bd356f2b86f18d7f4923d59cf8e82275eecbe2ec1e2aef04e30",
  "expected_token_count": 121,
  "expected_semantic_count": 31
}
```

`ExpectedVector = DERIVE19(grammar_bytes,dfa_bytes,token_registry_bytes,
normalization_bytes,error_registry_bytes,semantic_matcher_bytes,source_bytes,
validated_bake_input)` is run separately by parser A, parser B, and verifier.
It returns exact ordered token and semantic tuple bytes under the R18 tuple
codec. No expected tuple array is accepted from a caller. Each engine result
contains source size/SHA, bake input digest, converted fact-roster digest,
tuple bytes/size/SHA/count, byte coverage, and result digest. The verifier
receipt contains three independently computed tuples per vector and requires
`CJ(A.tokens)=CJ(B.tokens)=CJ(V.tokens)` and
`CJ(A.semantics)=CJ(B.semantics)=CJ(V.semantics)`; source, BAKE, coverage, and
converted-fact joins also equal. `bake_graph_edge` must derive one EOF token
and exactly `(0,0,GRAPH_EDGE,a->b,NONE)`. `empty` derives one EOF and zero
semantic tuples. The exact ordered projection of all 32 derived token and
semantic tuple ASCII strings must reproduce 3,601 bytes and the displayed
SHA-256, 121 tokens, and 31 semantics. That projection is an authenticated
regression join to the accepted R18 outputs; it is checked only after each
engine derives rows from source/BAKE bytes. These boundary assertions and the
projection are not caller-supplied parser results.

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "cut4.r19.vector_result.schema.v1",
  "type": "object", "additionalProperties": false,
  "required": ["schema", "engine", "vector_id", "source_byte_size", "source_sha256", "bake_input_digest", "converted_fact_roster_digest", "token_tuple_bytes_base64", "token_tuple_byte_size", "token_tuple_sha256", "token_count", "semantic_tuple_bytes_base64", "semantic_tuple_byte_size", "semantic_tuple_sha256", "candidate_count", "coverage_byte_count", "coverage_gap_count", "coverage_overlap_count", "result_digest"],
  "properties": {
    "schema": {"const": "cut4.r19.vector_result.v1"},
    "engine": {"enum": ["PARSER_A", "PARSER_B", "VERIFIER"]},
    "vector_id": {"type": "string", "minLength": 1},
    "source_byte_size": {"type": "integer", "minimum": 0},
    "source_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
    "bake_input_digest": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
    "converted_fact_roster_digest": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
    "token_tuple_bytes_base64": {"type": "string"},
    "token_tuple_byte_size": {"type": "integer", "minimum": 1},
    "token_tuple_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
    "token_count": {"type": "integer", "minimum": 1},
    "semantic_tuple_bytes_base64": {"type": "string"},
    "semantic_tuple_byte_size": {"type": "integer", "minimum": 0},
    "semantic_tuple_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
    "candidate_count": {"type": "integer", "minimum": 0},
    "coverage_byte_count": {"type": "integer", "minimum": 0},
    "coverage_gap_count": {"const": 0},
    "coverage_overlap_count": {"const": 0},
    "result_digest": {"type": "string", "pattern": "^[0-9a-f]{64}$"}
  }
}
```

All 32 rows are executed by all three packages. Each package execution receipt
binds its admitted package subject, grammar/registry byte subjects, this exact
source root, both exact BAKE inputs, the 32 ordered results, and its roster
digest. The negative proof repeats no result; it binds the three admitted
execution receipts and an exact 32-row equality proof. `PROVED_NONE` is only
allowed for a vector whose independently derived semantic tuple bytes are
empty after nonempty EOF, complete source coverage, and exact BAKE accounting.

## 3. Inhabitable Kp, zero proof, and constructor dependencies

### 3.1 One full Kp value everywhere

R19 replaces the R18 expanded-but-absent scalars with one closed value. Its 12
semantic fields, in order, are present in every required object as `kp` and
must be CJ-byte-equal. No consumer may carry only a digest.

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "cut4.r19.provider_authority.schema.v1",
  "$defs": {
    "Hex64": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
    "Kp": {
      "type": "object", "additionalProperties": false,
      "required": ["schema", "private_plan_row_id", "consumer_row_id", "consumer_id", "provider_id", "provider_ordinal", "applicability_predicate_id", "applicability_result", "selection_predicate_id", "selection_result", "invocation_digest", "plan_digest", "source_snapshot_digest", "kp_digest"],
      "properties": {
        "schema": {"const": "cut4.r19.kp.v1"},
        "private_plan_row_id": {"type": "string", "minLength": 1},
        "consumer_row_id": {"type": "string", "minLength": 1},
        "consumer_id": {"type": "string", "minLength": 1},
        "provider_id": {"enum": ["source_graph", "build_probe", "daml_source_graph"]},
        "provider_ordinal": {"type": "integer", "minimum": 0, "maximum": 2},
        "applicability_predicate_id": {"type": "string", "minLength": 1},
        "applicability_result": {"type": "boolean"},
        "selection_predicate_id": {"type": "string", "minLength": 1},
        "selection_result": {"type": "boolean"},
        "invocation_digest": {"$ref": "#/$defs/Hex64"},
        "plan_digest": {"$ref": "#/$defs/Hex64"},
        "source_snapshot_digest": {"$ref": "#/$defs/Hex64"},
        "kp_digest": {"$ref": "#/$defs/Hex64"}
      }
    },
    "SourceSnapshot": {
      "type": "object", "additionalProperties": false,
      "required": ["schema", "project_root_identity", "source_rows", "source_roster_digest", "snapshot_digest"],
      "properties": {
        "schema": {"const": "cut4.r19.source_snapshot.v1"},
        "project_root_identity": {"type": "string", "minLength": 1},
        "source_rows": {"type": "array", "minItems": 1, "items": {"type": "array", "prefixItems": [{"type": "string", "minLength": 1}, {"$ref": "#/$defs/Hex64"}, {"type": "integer", "minimum": 0}], "items": false, "minItems": 3, "maxItems": 3}},
        "source_roster_digest": {"$ref": "#/$defs/Hex64"},
        "snapshot_digest": {"$ref": "#/$defs/Hex64"}
      }
    },
    "ProviderPlan": {
      "type": "object", "additionalProperties": false,
      "required": ["schema", "private_plan_row_id", "consumer_row_id", "consumer_id", "provider_id", "provider_ordinal", "applicability_predicate_id", "selection_predicate_id", "source_snapshot_digest", "phaseio_authority_digest", "plan_digest"],
      "properties": {
        "schema": {"const": "cut4.r19.provider_plan.v1"},
        "private_plan_row_id": {"type": "string", "minLength": 1},
        "consumer_row_id": {"type": "string", "minLength": 1},
        "consumer_id": {"type": "string", "minLength": 1},
        "provider_id": {"enum": ["source_graph", "build_probe", "daml_source_graph"]},
        "provider_ordinal": {"type": "integer", "minimum": 0, "maximum": 2},
        "applicability_predicate_id": {"type": "string", "minLength": 1},
        "selection_predicate_id": {"type": "string", "minLength": 1},
        "source_snapshot_digest": {"$ref": "#/$defs/Hex64"},
        "phaseio_authority_digest": {"$ref": "#/$defs/Hex64"},
        "plan_digest": {"$ref": "#/$defs/Hex64"}
      }
    },
    "PredicateEvaluation": {
      "type": "object", "additionalProperties": false,
      "required": ["schema", "predicate_id", "predicate_kind", "provider_id", "plan_digest", "source_snapshot_digest", "result", "evaluation_bytes_base64", "evaluation_byte_size", "evaluation_sha256", "evaluation_digest"],
      "properties": {
        "schema": {"const": "cut4.r19.predicate_evaluation.v1"},
        "predicate_id": {"type": "string", "minLength": 1},
        "predicate_kind": {"enum": ["APPLICABILITY", "SELECTION"]},
        "provider_id": {"enum": ["source_graph", "build_probe", "daml_source_graph"]},
        "plan_digest": {"$ref": "#/$defs/Hex64"},
        "source_snapshot_digest": {"$ref": "#/$defs/Hex64"},
        "result": {"type": "boolean"},
        "evaluation_bytes_base64": {"type": "string"},
        "evaluation_byte_size": {"type": "integer", "minimum": 1},
        "evaluation_sha256": {"$ref": "#/$defs/Hex64"},
        "evaluation_digest": {"$ref": "#/$defs/Hex64"}
      }
    },
    "InvocationRecord": {
      "type": "object", "additionalProperties": false,
      "required": ["schema", "plan_digest", "source_snapshot_digest", "applicability_evaluation_digest", "selection_evaluation_digest", "provider_id", "invocation_state", "tool_config_digest", "invocation_digest"],
      "properties": {
        "schema": {"const": "cut4.r19.invocation_record.v1"},
        "plan_digest": {"$ref": "#/$defs/Hex64"},
        "source_snapshot_digest": {"$ref": "#/$defs/Hex64"},
        "applicability_evaluation_digest": {"$ref": "#/$defs/Hex64"},
        "selection_evaluation_digest": {"$ref": "#/$defs/Hex64"},
        "provider_id": {"enum": ["source_graph", "build_probe", "daml_source_graph"]},
        "invocation_state": {"enum": ["NOT_INVOKED", "INVOKED"]},
        "tool_config_digest": {"$ref": "#/$defs/Hex64"},
        "invocation_digest": {"$ref": "#/$defs/Hex64"}
      }
    },
    "PredicateEvidence": {
      "type": "object", "additionalProperties": false,
      "required": ["schema", "kp", "predicate_kind", "evaluation_digest", "evidence_bytes_base64", "evidence_byte_size", "evidence_sha256", "evidence_digest"],
      "properties": {
        "schema": {"const": "cut4.r19.predicate_evidence.v1"},
        "kp": {"$ref": "#/$defs/Kp"},
        "predicate_kind": {"enum": ["APPLICABILITY", "SELECTION"]},
        "evaluation_digest": {"$ref": "#/$defs/Hex64"},
        "evidence_bytes_base64": {"type": "string"},
        "evidence_byte_size": {"type": "integer", "minimum": 1},
        "evidence_sha256": {"$ref": "#/$defs/Hex64"},
        "evidence_digest": {"$ref": "#/$defs/Hex64"}
      }
    },
    "PayloadRecord": {
      "type": "object", "additionalProperties": false,
      "required": ["schema", "payload_id", "ordinal", "content_type", "bytes_base64", "byte_size", "sha256", "payload_digest"],
      "properties": {
        "schema": {"const": "cut4.r19.payload_record.v1"},
        "payload_id": {"type": "string", "minLength": 1},
        "ordinal": {"type": "integer", "minimum": 0},
        "content_type": {"enum": ["application/json", "text/plain", "application/octet-stream"]},
        "bytes_base64": {"type": "string"},
        "byte_size": {"type": "integer", "minimum": 0},
        "sha256": {"$ref": "#/$defs/Hex64"},
        "payload_digest": {"$ref": "#/$defs/Hex64"}
      }
    },
    "ProviderTerminal": {
      "type": "object", "additionalProperties": false,
      "required": ["schema", "kp", "plan_digest", "source_snapshot_digest", "invocation_digest", "invocation_state", "exit_code", "exhausted", "payloads", "evidence_bytes_base64", "evidence_byte_size", "evidence_sha256", "terminal_digest"],
      "properties": {
        "schema": {"const": "cut4.r19.provider_terminal.v1"},
        "kp": {"$ref": "#/$defs/Kp"},
        "plan_digest": {"$ref": "#/$defs/Hex64"},
        "source_snapshot_digest": {"$ref": "#/$defs/Hex64"},
        "invocation_digest": {"$ref": "#/$defs/Hex64"},
        "invocation_state": {"enum": ["NOT_INVOKED", "COMPLETED", "APPROXIMATED", "FAILED", "TIMED_OUT", "MALFORMED"]},
        "exit_code": {"type": "integer"},
        "exhausted": {"type": "boolean"},
        "payloads": {"type": "array", "items": {"$ref": "#/$defs/PayloadRecord"}},
        "evidence_bytes_base64": {"type": "string"},
        "evidence_byte_size": {"type": "integer", "minimum": 1},
        "evidence_sha256": {"$ref": "#/$defs/Hex64"},
        "terminal_digest": {"$ref": "#/$defs/Hex64"}
      }
    },
    "ExplicitZeroProof": {
      "type": "object", "additionalProperties": false,
      "required": ["schema", "kp", "provider_terminal_digest", "query_id", "status", "invocation_digest", "exhausted", "payload_count", "cursor_out", "evidence_bytes_base64", "evidence_byte_size", "evidence_sha256", "proof_digest"],
      "properties": {
        "schema": {"const": "cut4.r19.explicit_zero_proof.v1"},
        "kp": {"$ref": "#/$defs/Kp"},
        "provider_terminal_digest": {"$ref": "#/$defs/Hex64"},
        "query_id": {"type": "string", "minLength": 1},
        "status": {"const": "SUCCESS_EMPTY"},
        "invocation_digest": {"$ref": "#/$defs/Hex64"},
        "exhausted": {"const": true},
        "payload_count": {"const": 0},
        "cursor_out": {"type": "string", "minLength": 1},
        "evidence_bytes_base64": {"type": "string"},
        "evidence_byte_size": {"type": "integer", "minimum": 1},
        "evidence_sha256": {"$ref": "#/$defs/Hex64"},
        "proof_digest": {"$ref": "#/$defs/Hex64"}
      }
    },
    "ProviderReceipt": {
      "type": "object", "additionalProperties": false,
      "required": ["schema", "kp", "applicability_evidence_digest", "selection_evidence_digest", "terminal", "terminal_bytes_base64", "terminal_byte_size", "terminal_sha256", "status", "payload_count", "payload_roster_digest", "explicit_zero_proof", "debt_code", "receipt_digest"],
      "properties": {
        "schema": {"const": "cut4.r19.provider_receipt.v1"},
        "kp": {"$ref": "#/$defs/Kp"},
        "applicability_evidence_digest": {"$ref": "#/$defs/Hex64"},
        "selection_evidence_digest": {"$ref": "#/$defs/Hex64"},
        "terminal": {"$ref": "#/$defs/ProviderTerminal"},
        "terminal_bytes_base64": {"type": "string"},
        "terminal_byte_size": {"type": "integer", "minimum": 1},
        "terminal_sha256": {"$ref": "#/$defs/Hex64"},
        "status": {"enum": ["NOT_APPLICABLE", "NOT_SELECTED", "SUCCESS", "SUCCESS_EMPTY", "DEBT", "FAILURE", "TIMEOUT", "MALFORMED"]},
        "payload_count": {"type": "integer", "minimum": 0},
        "payload_roster_digest": {"$ref": "#/$defs/Hex64"},
        "explicit_zero_proof": {"oneOf": [{"type": "null"}, {"$ref": "#/$defs/ExplicitZeroProof"}]},
        "debt_code": {"enum": ["NONE", "APPROXIMATION", "EXECUTION_FAILURE", "DEADLINE", "SCHEMA_MALFORMED"]},
        "receipt_digest": {"$ref": "#/$defs/Hex64"}
      }
    }
  },
  "oneOf": [
    {"$ref": "#/$defs/Kp"}, {"$ref": "#/$defs/SourceSnapshot"}, {"$ref": "#/$defs/ProviderPlan"},
    {"$ref": "#/$defs/PredicateEvaluation"}, {"$ref": "#/$defs/InvocationRecord"}, {"$ref": "#/$defs/PredicateEvidence"},
    {"$ref": "#/$defs/PayloadRecord"}, {"$ref": "#/$defs/ProviderTerminal"}, {"$ref": "#/$defs/ExplicitZeroProof"}, {"$ref": "#/$defs/ProviderReceipt"}
  ]
}
```

`kp_digest=D("cut4.r19.kp.v1",the 12 fields in displayed order)`. It is
constructed only after the two predicate evaluations and the typed invocation
record. `InvocationRecord` always exists: false applicability/selection uses
`NOT_INVOKED`, not `EMPTY_SHA`. The plan and source snapshot values in both
evaluations, both evidence rows, terminal, receipt, and Kp are exact equal
FKs. The predicate IDs/results in Kp equal their typed evaluations and the
immutable provider-plan predicate registry. `predicate_kind` chooses the
matching Kp ID/result; it cannot select the other predicate.

Terminal `kp`, `plan_digest`, `source_snapshot_digest`, and
`invocation_digest` equal the same Kp fields. Receipt terminal bytes equal
`CJ(terminal)` and reproduce size/SHA. Receipt status is the inherited fixed
R18 truth table. `SUCCESS_EMPTY` alone requires a non-null
`ExplicitZeroProof`; every other status requires null. A zero proof requires
terminal `COMPLETED`, exit 0, exhausted true, exact zero payloads, an explicit
nonempty terminal cursor, exact invocation/tool evidence, and full Kp equality.
Thus a caller-selectable zero digest cannot establish success.

The production `BakeFactRow`, `BakeBinding`, provider-private v5 row,
normalized semantic row, expected/observed diff row, M4, R4, and completion
receipt are R18 schemas with this mandatory replacement: each contains the
full `kp` object above; all old duplicate Kp scalars are removed; every direct
provider/plan/source/invocation field still present must equal `kp`; every
provider receipt child must have byte-identical Kp. `BakeBinding` contains
exactly the three fixed receipts in ordinal order, and every fact Kp equals its
owning receipt Kp. Diff and completion rows carry full expected and observed
Kp values and reject if their CJ bytes differ. This versioned replacement is
the combined semantic authority; no R18 scalar fragment is accepted.

The named downstream carriers are not prose aliases. Their complete join
shell is this closed schema; `SemanticData` is the object's already-validated
closed R18 semantic payload with all authority scalars removed. Its exact bytes
are retained, so this wrapper cannot discard fields. The validator store must
resolve the Kp and ProviderReceipt references to the exact schema above.

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "cut4.r19.kp_carriers.schema.v1",
  "$defs": {
    "Hex64": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
    "Kp": {"$ref": "cut4.r19.provider_authority.schema.v1#/$defs/Kp"},
    "SemanticData": {
      "type": "object", "additionalProperties": false,
      "required": ["schema_id", "bytes_base64", "byte_size", "sha256", "semantic_digest"],
      "properties": {
        "schema_id": {"type": "string", "minLength": 1},
        "bytes_base64": {"type": "string"},
        "byte_size": {"type": "integer", "minimum": 1},
        "sha256": {"$ref": "#/$defs/Hex64"},
        "semantic_digest": {"$ref": "#/$defs/Hex64"}
      }
    },
    "BakeFactRow": {
      "type": "object", "additionalProperties": false,
      "required": ["schema", "kp", "provider_receipt_digest", "fact_ordinal", "fact_kind", "subject_id", "object_id", "raw_bytes_base64", "raw_byte_size", "raw_sha256", "fact_id", "fact_digest"],
      "properties": {
        "schema": {"const": "cut4.r19.bake_fact.v1"}, "kp": {"$ref": "#/$defs/Kp"},
        "provider_receipt_digest": {"$ref": "#/$defs/Hex64"}, "fact_ordinal": {"type": "integer", "minimum": 0},
        "fact_kind": {"enum": ["GRAPH_NODE", "GRAPH_EDGE", "PROBE_RESULT", "TYPED_DEBT"]},
        "subject_id": {"type": "string", "minLength": 1}, "object_id": {"type": "string", "minLength": 1},
        "raw_bytes_base64": {"type": "string"}, "raw_byte_size": {"type": "integer", "minimum": 1}, "raw_sha256": {"$ref": "#/$defs/Hex64"},
        "fact_id": {"type": "string", "pattern": "^bf_[0-9a-f]{64}$"}, "fact_digest": {"$ref": "#/$defs/Hex64"}
      }
    },
    "BakeBinding": {
      "type": "object", "additionalProperties": false,
      "required": ["schema", "kp", "provider_receipts", "provider_receipt_roster_digest", "facts", "fact_count", "fact_roster_digest", "binding_digest"],
      "properties": {
        "schema": {"const": "cut4.r19.bake_binding.v1"}, "kp": {"$ref": "#/$defs/Kp"},
        "provider_receipts": {"type": "array", "minItems": 3, "maxItems": 3, "items": {"$ref": "cut4.r19.provider_authority.schema.v1#/$defs/ProviderReceipt"}},
        "provider_receipt_roster_digest": {"$ref": "#/$defs/Hex64"},
        "facts": {"type": "array", "items": {"$ref": "#/$defs/BakeFactRow"}},
        "fact_count": {"type": "integer", "minimum": 0}, "fact_roster_digest": {"$ref": "#/$defs/Hex64"}, "binding_digest": {"$ref": "#/$defs/Hex64"}
      }
    },
    "ProviderPrivateV5": {
      "type": "object", "additionalProperties": false,
      "required": ["schema", "kp", "provider_receipt_digest", "payload_data", "private_digest"],
      "properties": {
        "schema": {"const": "cut4.r19.provider_private.v5"}, "kp": {"$ref": "#/$defs/Kp"},
        "provider_receipt_digest": {"$ref": "#/$defs/Hex64"}, "payload_data": {"$ref": "#/$defs/SemanticData"}, "private_digest": {"$ref": "#/$defs/Hex64"}
      }
    },
    "NormalizedSemanticRow": {
      "type": "object", "additionalProperties": false,
      "required": ["schema", "kp", "payload_id", "normalizer_evidence_digest", "semantic_class", "normalized_data", "row_digest"],
      "properties": {
        "schema": {"const": "cut4.r19.normalized_semantic_row.v1"}, "kp": {"$ref": "#/$defs/Kp"},
        "payload_id": {"type": "string", "minLength": 1}, "normalizer_evidence_digest": {"$ref": "#/$defs/Hex64"},
        "semantic_class": {"enum": ["GRAPH_NODE", "GRAPH_EDGE", "PROBE_RESULT", "PATH_REFERENCE", "CONTENT_INSTRUCTION", "TYPED_DEBT", "NOT_APPLICABLE"]},
        "normalized_data": {"$ref": "#/$defs/SemanticData"}, "row_digest": {"$ref": "#/$defs/Hex64"}
      }
    },
    "ExpectedObservedDiff": {
      "type": "object", "additionalProperties": false,
      "required": ["schema", "expected_kp", "observed_kp", "diff_kind", "field_name", "expected_data", "observed_data", "diff_digest"],
      "properties": {
        "schema": {"const": "cut4.r19.expected_observed_diff.v1"},
        "expected_kp": {"$ref": "#/$defs/Kp"}, "observed_kp": {"$ref": "#/$defs/Kp"},
        "diff_kind": {"enum": ["MISSING", "EXTRA", "VALUE", "TYPE", "ORDER", "COUNT", "BOOL", "INT", "ZERO_PROOF", "KP_MISMATCH"]},
        "field_name": {"type": "string", "minLength": 1}, "expected_data": {"$ref": "#/$defs/SemanticData"}, "observed_data": {"$ref": "#/$defs/SemanticData"},
        "diff_digest": {"$ref": "#/$defs/Hex64"}
      }
    },
    "M4": {
      "type": "object", "additionalProperties": false,
      "required": ["schema", "kp", "bake_binding_digest", "provider_private_digest", "normalized_roster_digest", "normalizer_receipt_digest", "diff_roster_digest", "public_output_roster_digest", "ack_state_digest", "m4_digest"],
      "properties": {
        "schema": {"const": "cut4.r19.m4.v1"}, "kp": {"$ref": "#/$defs/Kp"},
        "bake_binding_digest": {"$ref": "#/$defs/Hex64"}, "provider_private_digest": {"$ref": "#/$defs/Hex64"},
        "normalized_roster_digest": {"$ref": "#/$defs/Hex64"}, "normalizer_receipt_digest": {"$ref": "#/$defs/Hex64"},
        "diff_roster_digest": {"$ref": "#/$defs/Hex64"}, "public_output_roster_digest": {"$ref": "#/$defs/Hex64"},
        "ack_state_digest": {"$ref": "#/$defs/Hex64"}, "m4_digest": {"$ref": "#/$defs/Hex64"}
      }
    },
    "R4": {
      "type": "object", "additionalProperties": false,
      "required": ["schema", "kp", "m4_digest", "publication_link_digest", "decision", "r4_digest"],
      "properties": {
        "schema": {"const": "cut4.r19.r4.v1"}, "kp": {"$ref": "#/$defs/Kp"}, "m4_digest": {"$ref": "#/$defs/Hex64"},
        "publication_link_digest": {"$ref": "#/$defs/Hex64"}, "decision": {"enum": ["COMPLETE", "REJECT"]}, "r4_digest": {"$ref": "#/$defs/Hex64"}
      }
    },
    "CompletionReceipt": {
      "type": "object", "additionalProperties": false,
      "required": ["schema", "kp", "r4_digest", "terminal_journal_record_digest", "committed_publication_receipt_digest", "publication_link_digest", "ack_state_digest", "provider_private_digest", "normalizer_receipt_digest", "diff_roster_digest", "completion_state", "completion_digest"],
      "properties": {
        "schema": {"const": "cut4.r19.completion_receipt.v1"}, "kp": {"$ref": "#/$defs/Kp"}, "r4_digest": {"$ref": "#/$defs/Hex64"},
        "terminal_journal_record_digest": {"$ref": "#/$defs/Hex64"}, "committed_publication_receipt_digest": {"$ref": "#/$defs/Hex64"},
        "publication_link_digest": {"$ref": "#/$defs/Hex64"}, "ack_state_digest": {"$ref": "#/$defs/Hex64"},
        "provider_private_digest": {"$ref": "#/$defs/Hex64"}, "normalizer_receipt_digest": {"$ref": "#/$defs/Hex64"},
        "diff_roster_digest": {"$ref": "#/$defs/Hex64"}, "completion_state": {"const": "COMPLETE"}, "completion_digest": {"$ref": "#/$defs/Hex64"}
      }
    }
  },
  "oneOf": [
    {"$ref": "#/$defs/BakeFactRow"}, {"$ref": "#/$defs/BakeBinding"}, {"$ref": "#/$defs/ProviderPrivateV5"},
    {"$ref": "#/$defs/NormalizedSemanticRow"}, {"$ref": "#/$defs/ExpectedObservedDiff"}, {"$ref": "#/$defs/M4"}, {"$ref": "#/$defs/R4"}, {"$ref": "#/$defs/CompletionReceipt"}
  ]
}
```

`SemanticData` bytes must validate the exact referenced closed object schema,
and its digest is rederived; it is not an escape hatch for unknown fields.
Every wrapper digest is its tagged BODY digest excluding only itself. The
normalizer evidence and receipt are independently validated and every
normalized row joins an exact payload/evidence pair. `ExpectedObservedDiff`
requires CJ-byte equality of `expected_kp` and `observed_kp` for any clean
comparison; `KP_MISMATCH` is rejecting. M4, R4, and completion revalidate every
child object and exact bytes, not digest strings alone. A stale, invalid,
unanchored, or zero-byte child prevents `COMPLETE`.

### 3.2 Exact constructor DAG

```json
{
  "schema": "cut4.r19.constructor_dag.v1",
  "nodes": [
    "FrozenSpecs", "SourceFileBytes", "SourceSnapshot", "PhaseIOAuthority", "AckPolicy", "ProviderPlan", "PredicateEvaluation", "InvocationRecord", "Kp", "PredicateEvidence", "PayloadRecord", "ProviderTerminal", "ExplicitZeroProof", "ProviderReceipt", "BakeFactRow", "BakeBinding",
    "ParserAReceipt", "ParserBReceipt", "VerifierReceipt", "NegativeProofReceipt", "SourceMapReceipt", "InvalidFileFact", "JournalState", "PriorEnvelope", "BaseRequestIntent", "AttemptAllocation", "ProviderPrivateV5", "NormalizedSemanticRow", "NormalizerEvidence", "NormalizerReceipt", "ExpectedObservedDiff", "TerminalEnvelope", "TerminalJournalRecord", "PublicOutputBytes", "CommittedPublicationReceipt", "PublicationLink", "PublicationAckJournalRecord", "AckState", "M4", "R4", "CompletionReceipt", "MutationDefinition", "PreExecutionSnapshot", "SubprocessExitEvent", "ObservationReceipt", "ExecutionAuthorReceipt"
  ],
  "edges": [
    ["FrozenSpecs","SourceFileBytes"], ["SourceFileBytes","SourceSnapshot"], ["FrozenSpecs","PhaseIOAuthority"], ["FrozenSpecs","AckPolicy"],
    ["PhaseIOAuthority","ProviderPlan"], ["SourceSnapshot","ProviderPlan"], ["AckPolicy","ProviderPlan"],
    ["ProviderPlan","PredicateEvaluation"], ["SourceSnapshot","PredicateEvaluation"],
    ["ProviderPlan","InvocationRecord"], ["SourceSnapshot","InvocationRecord"], ["PredicateEvaluation","InvocationRecord"],
    ["ProviderPlan","Kp"], ["SourceSnapshot","Kp"], ["PredicateEvaluation","Kp"], ["InvocationRecord","Kp"],
    ["ProviderPlan","PredicateEvidence"], ["SourceSnapshot","PredicateEvidence"], ["PredicateEvaluation","PredicateEvidence"], ["Kp","PredicateEvidence"],
    ["ProviderPlan","ProviderTerminal"], ["SourceSnapshot","ProviderTerminal"], ["InvocationRecord","ProviderTerminal"], ["Kp","ProviderTerminal"], ["PayloadRecord","ProviderTerminal"],
    ["ProviderTerminal","ExplicitZeroProof"], ["InvocationRecord","ExplicitZeroProof"], ["Kp","ExplicitZeroProof"],
    ["InvocationRecord","ProviderReceipt"], ["ProviderPlan","ProviderReceipt"], ["SourceSnapshot","ProviderReceipt"], ["PredicateEvidence","ProviderReceipt"], ["ProviderTerminal","ProviderReceipt"], ["ExplicitZeroProof","ProviderReceipt"], ["Kp","ProviderReceipt"],
    ["ProviderReceipt","BakeFactRow"], ["Kp","BakeFactRow"], ["ProviderReceipt","BakeBinding"], ["BakeFactRow","BakeBinding"], ["Kp","BakeBinding"],
    ["FrozenSpecs","ParserAReceipt"], ["SourceSnapshot","ParserAReceipt"], ["BakeBinding","ParserAReceipt"],
    ["FrozenSpecs","ParserBReceipt"], ["SourceSnapshot","ParserBReceipt"], ["BakeBinding","ParserBReceipt"],
    ["FrozenSpecs","VerifierReceipt"], ["SourceSnapshot","VerifierReceipt"], ["BakeBinding","VerifierReceipt"], ["ParserAReceipt","VerifierReceipt"], ["ParserBReceipt","VerifierReceipt"],
    ["ParserAReceipt","NegativeProofReceipt"], ["ParserBReceipt","NegativeProofReceipt"], ["VerifierReceipt","NegativeProofReceipt"], ["FrozenSpecs","SourceMapReceipt"], ["SourceSnapshot","SourceMapReceipt"],
    ["InvalidFileFact","JournalState"], ["JournalState","PriorEnvelope"], ["SourceSnapshot","BaseRequestIntent"], ["PriorEnvelope","BaseRequestIntent"], ["BaseRequestIntent","AttemptAllocation"], ["AttemptAllocation","InvocationRecord"],
    ["ProviderReceipt","ProviderPrivateV5"], ["PayloadRecord","ProviderPrivateV5"], ["Kp","ProviderPrivateV5"],
    ["PayloadRecord","NormalizedSemanticRow"], ["VerifierReceipt","NormalizedSemanticRow"], ["Kp","NormalizedSemanticRow"], ["NormalizedSemanticRow","NormalizerEvidence"], ["NormalizerEvidence","NormalizerReceipt"],
    ["ProviderPrivateV5","ExpectedObservedDiff"], ["NormalizedSemanticRow","ExpectedObservedDiff"], ["Kp","ExpectedObservedDiff"],
    ["ExpectedObservedDiff","TerminalEnvelope"], ["InvocationRecord","TerminalEnvelope"], ["ProviderReceipt","TerminalEnvelope"], ["TerminalEnvelope","TerminalJournalRecord"],
    ["PhaseIOAuthority","PublicOutputBytes"], ["TerminalJournalRecord","CommittedPublicationReceipt"], ["PublicOutputBytes","CommittedPublicationReceipt"], ["TerminalJournalRecord","PublicationLink"], ["CommittedPublicationReceipt","PublicationLink"],
    ["PublicationLink","PublicationAckJournalRecord"], ["AckPolicy","PublicationAckJournalRecord"], ["AckPolicy","AckState"], ["PublicationLink","AckState"], ["PublicationAckJournalRecord","AckState"],
    ["ProviderPrivateV5","M4"], ["NormalizedSemanticRow","M4"], ["ExpectedObservedDiff","M4"], ["PublicOutputBytes","M4"], ["AckState","M4"], ["BakeBinding","M4"], ["NormalizerReceipt","M4"], ["Kp","M4"],
    ["M4","R4"], ["PublicationLink","R4"], ["Kp","R4"], ["R4","CompletionReceipt"], ["TerminalJournalRecord","CompletionReceipt"], ["PublicationLink","CompletionReceipt"], ["CommittedPublicationReceipt","CompletionReceipt"], ["AckState","CompletionReceipt"], ["Kp","CompletionReceipt"],
    ["FrozenSpecs","MutationDefinition"], ["SourceMapReceipt","MutationDefinition"], ["PreExecutionSnapshot","SubprocessExitEvent"], ["MutationDefinition","SubprocessExitEvent"], ["SubprocessExitEvent","ObservationReceipt"], ["PreExecutionSnapshot","ObservationReceipt"], ["SubprocessExitEvent","ExecutionAuthorReceipt"], ["ObservationReceipt","ExecutionAuthorReceipt"], ["NegativeProofReceipt","ExecutionAuthorReceipt"], ["SourceMapReceipt","ExecutionAuthorReceipt"]
  ],
  "node_count": 46,
  "edge_count": 114
}
```

The four formerly missing direct relations are literal:
`ProviderPlan/SourceSnapshot -> PredicateEvidence`, `ProviderPlan ->
ProviderTerminal`, and `InvocationRecord -> ProviderReceipt`. Kp and explicit
zero proof are real typed nodes. The future model must generate its dependency
projection from dataclass fields, constructors, validators, and serializers;
it must byte-equal this 46-node/114-edge denominator. Kahn remainder is zero.

## 4. Pre-execution observation and exit-derived cases

### 4.1 Pre-state is admitted before the subprocess

The RED and GREEN pre-snapshot subjects are produced, independently reviewed,
and admitted before their execution subject starts. A post observer cannot
write or replace them. RED requires the model target absent; GREEN requires
the admitted model subject present with equal bytes. Both snapshot the exact
test, model path, cwd, normalized environment, input roster, directory
enumeration bytes, and their hashes.

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "cut4.r19.execution_observation.schema.v1",
  "$defs": {
    "Hex64": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
    "CaseExitRow": {
      "type": "object", "additionalProperties": false,
      "required": ["case_ordinal", "case_id", "phase", "request_bytes_base64", "request_byte_size", "request_sha256", "outcome_kind", "observed_code", "result_bytes_base64", "result_byte_size", "result_sha256", "exception_type", "exception_bytes_base64", "exception_byte_size", "exception_sha256", "row_digest"],
      "properties": {
        "case_ordinal": {"type": "integer", "minimum": 0, "maximum": 255},
        "case_id": {"type": "string", "minLength": 1},
        "phase": {"enum": ["RED", "GREEN"]},
        "request_bytes_base64": {"type": "string"},
        "request_byte_size": {"type": "integer", "minimum": 1},
        "request_sha256": {"$ref": "#/$defs/Hex64"},
        "outcome_kind": {"enum": ["MODEL_ABSENT", "DOMAIN_RESULT", "HARNESS_ERROR"]},
        "observed_code": {"type": "string", "minLength": 1},
        "result_bytes_base64": {"type": "string"},
        "result_byte_size": {"type": "integer", "minimum": 0},
        "result_sha256": {"$ref": "#/$defs/Hex64"},
        "exception_type": {"type": "string"},
        "exception_bytes_base64": {"type": "string"},
        "exception_byte_size": {"type": "integer", "minimum": 0},
        "exception_sha256": {"$ref": "#/$defs/Hex64"},
        "row_digest": {"$ref": "#/$defs/Hex64"}
      }
    },
    "PreExecutionSnapshot": {
      "type": "object", "additionalProperties": false,
      "required": ["schema", "phase", "producer_subject_admission_digest", "test_identity", "test_sha256", "model_identity", "model_membership_count", "model_sha256", "cwd_nfc", "argv", "environment_rows", "input_rows", "enumeration_bytes_base64", "enumeration_byte_size", "enumeration_sha256", "snapshot_digest"],
      "properties": {
        "schema": {"const": "cut4.r19.pre_execution_snapshot.v1"},
        "phase": {"enum": ["RED", "GREEN"]},
        "producer_subject_admission_digest": {"$ref": "#/$defs/Hex64"},
        "test_identity": {"type": "string", "minLength": 1},
        "test_sha256": {"$ref": "#/$defs/Hex64"},
        "model_identity": {"type": "string", "minLength": 1},
        "model_membership_count": {"type": "integer", "minimum": 0, "maximum": 1},
        "model_sha256": {"$ref": "#/$defs/Hex64"},
        "cwd_nfc": {"type": "string", "minLength": 1},
        "argv": {"type": "array", "minItems": 1, "items": {"type": "string"}},
        "environment_rows": {"type": "array", "items": {"type": "array", "prefixItems": [{"type": "string"}, {"type": "string"}], "items": false, "minItems": 2, "maxItems": 2}},
        "input_rows": {"type": "array", "minItems": 1, "items": {"type": "array", "prefixItems": [{"type": "string"}, {"$ref": "#/$defs/Hex64"}, {"type": "integer", "minimum": 0}], "items": false, "minItems": 3, "maxItems": 3}},
        "enumeration_bytes_base64": {"type": "string"},
        "enumeration_byte_size": {"type": "integer", "minimum": 2},
        "enumeration_sha256": {"$ref": "#/$defs/Hex64"},
        "snapshot_digest": {"$ref": "#/$defs/Hex64"}
      }
    },
    "SubprocessExitEvent": {
      "type": "object", "additionalProperties": false,
      "required": ["schema", "phase", "pre_snapshot_subject_admission_digest", "pre_snapshot_digest", "argv", "environment_rows", "cwd_nfc", "stdin_bytes_base64", "stdin_byte_size", "stdin_sha256", "stdout_bytes_base64", "stdout_byte_size", "stdout_sha256", "stderr_bytes_base64", "stderr_byte_size", "stderr_sha256", "exit_code", "case_rows", "case_roster_digest", "process_started_ordinal", "process_exited_ordinal", "exit_event_digest"],
      "properties": {
        "schema": {"const": "cut4.r19.subprocess_exit_event.v1"},
        "phase": {"enum": ["RED", "GREEN"]},
        "pre_snapshot_subject_admission_digest": {"$ref": "#/$defs/Hex64"},
        "pre_snapshot_digest": {"$ref": "#/$defs/Hex64"},
        "argv": {"type": "array", "minItems": 1, "items": {"type": "string"}},
        "environment_rows": {"type": "array", "items": {"type": "array", "prefixItems": [{"type": "string"}, {"type": "string"}], "items": false, "minItems": 2, "maxItems": 2}},
        "cwd_nfc": {"type": "string", "minLength": 1},
        "stdin_bytes_base64": {"type": "string"},
        "stdin_byte_size": {"type": "integer", "minimum": 0},
        "stdin_sha256": {"$ref": "#/$defs/Hex64"},
        "stdout_bytes_base64": {"type": "string"},
        "stdout_byte_size": {"type": "integer", "minimum": 1},
        "stdout_sha256": {"$ref": "#/$defs/Hex64"},
        "stderr_bytes_base64": {"type": "string"},
        "stderr_byte_size": {"type": "integer", "minimum": 0},
        "stderr_sha256": {"$ref": "#/$defs/Hex64"},
        "exit_code": {"type": "integer"},
        "case_rows": {"type": "array", "minItems": 256, "maxItems": 256, "items": {"$ref": "#/$defs/CaseExitRow"}},
        "case_roster_digest": {"$ref": "#/$defs/Hex64"},
        "process_started_ordinal": {"type": "integer", "minimum": 1},
        "process_exited_ordinal": {"type": "integer", "minimum": 2},
        "exit_event_digest": {"$ref": "#/$defs/Hex64"}
      }
    },
    "ObservationReceipt": {
      "type": "object", "additionalProperties": false,
      "required": ["schema", "phase", "pre_snapshot_subject_admission_digest", "pre_snapshot_digest", "exit_event_subject_admission_digest", "exit_event_digest", "after_enumeration_bytes_base64", "after_enumeration_byte_size", "after_enumeration_sha256", "after_model_membership_count", "after_model_sha256", "observation_digest"],
      "properties": {
        "schema": {"const": "cut4.r19.observation_receipt.v1"},
        "phase": {"enum": ["RED", "GREEN"]},
        "pre_snapshot_subject_admission_digest": {"$ref": "#/$defs/Hex64"},
        "pre_snapshot_digest": {"$ref": "#/$defs/Hex64"},
        "exit_event_subject_admission_digest": {"$ref": "#/$defs/Hex64"},
        "exit_event_digest": {"$ref": "#/$defs/Hex64"},
        "after_enumeration_bytes_base64": {"type": "string"},
        "after_enumeration_byte_size": {"type": "integer", "minimum": 2},
        "after_enumeration_sha256": {"$ref": "#/$defs/Hex64"},
        "after_model_membership_count": {"type": "integer", "minimum": 0, "maximum": 1},
        "after_model_sha256": {"$ref": "#/$defs/Hex64"},
        "observation_digest": {"$ref": "#/$defs/Hex64"}
      }
    }
  },
  "oneOf": [{"$ref": "#/$defs/PreExecutionSnapshot"}, {"$ref": "#/$defs/SubprocessExitEvent"}, {"$ref": "#/$defs/ObservationReceipt"}]
}
```

The process receives the admitted pre-snapshot identity and digest. Its argv,
environment, cwd, and input hashes must byte-equal that snapshot; start ordinal
is strictly after pre-snapshot admission and exit ordinal is strictly after
start. Exact stdout is 256 RFC-8785 case-row bodies, in mutation ordinal order,
each followed by one LF, with no blank/trailing non-row bytes. The strict
result parser decodes these immutable stdout bytes, rejects duplicate keys or
case IDs, reserializes each body, and requires byte equality before adding
`row_digest`. Therefore `case_rows` are a derived view of exit bytes, not
producer input. Their gapless ordinals, IDs, requests, outcomes, codes, result
and exception bytes all rederive from stdout; roster digest covers the exact
order. RED rows require `MODEL_ABSENT`, `ImportError`, and a nonempty exception;
GREEN rows require `DOMAIN_RESULT`, empty exception, and the exact post-model
domain code. Exact domain codes are not required or asserted during RED.

The red/green author receipts contain exactly
`[case_ordinal,case_id,event_case_row_digest]` projected from their admitted
exit event; each also binds pre-snapshot, exit-event, post-observer, mutation
root, test subject, and (GREEN only) model subject admissions. No separate
self-reported `RedCase` or `GreenCase` object exists. Crash/no stdout, partial
stdout, 255/257 rows, duplicate/reordered IDs, invented result rows, or an
observer-created pre-state is typed `EXECUTION_OBSERVATION_DEBT` and cannot
form an author receipt.

The routed S05 source-map receipt is constructed from admitted frozen test and
fixture bytes by exact adapters `PY_AST_R19`, `JSON_POINTER_R19`,
`CANONICAL_ROW_R19`, and `RAW_SPAN_R19`. Each map row contains source subject
admission, source SHA, adapter ID/version/source SHA, node kind, canonical
selector path, byte start/end, selected bytes/size/SHA, and row digest. Its
ordered multiset has exact no-omission/no-duplicate coverage. An `AST_NODE`
selector must FK one admitted map row and copy every field. A caller-supplied
source map is invalid.

## 5. Unique fixture-derived mutation denominator

R19 inherits and authenticates the 192 unique R15-R17 IDs. It reauthors the
R18 64 additions with only the two colliding IDs replaced:
`execution.selector_zero_match` becomes
`execution.r19_selector_zero_match_routed`, and
`execution.selector_multiple_match` becomes
`execution.r19_selector_multiple_match_routed`. The exact R19 additions are:

```json
{
  "schema": "cut4.r19.mutation_additions.v1",
  "base_count": 192,
  "groups": {
    "route": [
      "route.review_requires_future_admission", "route.review_retro_start_claim", "route.admission_before_accept", "route.admission_subject_hash_wrong",
      "route.worker_missing_admission", "route.subject_path_not_absent", "route.subject_overwrite", "route.producer_result_handle_wrong",
      "route.review_same_occurrence", "route.review_subject_reused", "route.red_dual_producer_single_relation", "route.review_decision_forged",
      "route.opaque_event_projection", "route.event_payload_mismatch", "route.predecessor_subject_missing", "route.extra_unrouted_subject"
    ],
    "recognition": [
      "recognition.evm_dash_comment", "recognition.daml_slash_comment", "recognition.ecosystem_unknown_clean", "recognition.comment_guard_bypassed",
      "recognition.assignment_token_missing", "recognition.assignment_second_eq_accepted", "recognition.nested_context_outer_wins", "recognition.member_call_double_emission",
      "recognition.vector_source_bytes_changed", "recognition.vector_ecosystem_changed", "recognition.vector_bake_bytes_changed", "recognition.expected_tuple_changed",
      "recognition.parser_a_receipt_missing", "recognition.parser_b_receipt_missing", "recognition.verifier_receipt_missing", "recognition.negative_proof_count_forged"
    ],
    "authority": [
      "authority.provider_receipts_absent", "authority.provider_receipt_order_changed", "authority.zero_slot_receipt_missing", "authority.provider_receipt_bytes_wrong",
      "authority.provider_direct_binding_edge_missing", "authority.payload_record_sha_wrong", "authority.status_terminal_mismatch", "authority.kp_field_mismatch",
      "authority.ack_type_uninhabited", "authority.ack_truth_digest_wrong", "authority.invalid_fact_bytes_absent", "authority.invalid_fact_id_wrong",
      "authority.phaseio_field_alias", "authority.phaseio_registry_self_minted", "authority.semantic_preimage_missing", "authority.semantic_preimage_extra"
    ],
    "execution": [
      "execution.event_contains_future_completion", "execution.observer_contains_future_completion", "execution.author_receipt_contains_future_completion", "execution.red_green_schema_mixed",
      "execution.red_nonempty_domain_code", "execution.green_model_absent", "execution.path_membership_false_present", "execution.path_membership_true_absent",
      "execution.boundary_claim_overstated", "execution.selector_source_map_missing", "execution.r19_selector_zero_match_routed", "execution.r19_selector_multiple_match_routed",
      "execution.delete_with_operand", "execution.insert_nonzero_span", "execution.reorder_invalid_index", "execution.corrupt_mask_length_wrong"
    ]
  },
  "addition_count": 64,
  "total_count": 256,
  "combined_id_codec": "CJ(R15_ids || R16_ids || R17_ids || R19_ids)",
  "combined_id_byte_size": 9308,
  "combined_id_sha256": "dba824fd070bc64ef5ed44626f5744f4320f7ee0f39a3f9c455e65c45ba7103e"
}
```

Every mutation is a typed R18 operation (`REPLACE/DELETE/INSERT/DUPLICATE/
REORDER/RELABEL/TRUNCATE/CORRUPT`) over an admitted source-map or raw-span row.
Its exact mutated bytes are mechanically constructed from admitted frozen
source bytes. In addition to every operation precondition, R19 requires
`mutated_bytes != source_bytes`, `mutated_sha256 != source_sha256`, exactly one
selector match, and a unique `(mutation_id,source_subject_digest,selector_
digest,operation,mutated_sha256)` tuple. The combined 256 IDs and tuples must
be pairwise unique; omission, duplicate, relabel, a zero/multiple selector,
vacuous mutation, or extra row prevents the test subject admission. Each case
is emitted in the exact exit-event stdout roster described above.

## 6. Exact validation and staged claim ceiling

The architecture reviewer must independently perform this closed 30-check
roster. A failure is REPAIR; counts are not discretionary.

```json
{
  "schema": "cut4.r19.architecture_check_roster.v1",
  "checks": [
    "R19-01-review-bytes-size-sha", "R19-02-r18-contract-bytes-size-sha", "R19-03-r18-receipt-bytes-size-sha",
    "R19-04-json-blocks-parse", "R19-05-json-schemas-metaschema", "R19-06-local-references-exist-or-future-versioned", "R19-07-lf-only",
    "R19-08-author-start-result-same-occurrence", "R19-09-author-output-subjects-exact", "R19-10-author-review-handle-distinct",
    "R19-11-role-manifest-prefix", "R19-12-global-handles-unique", "R19-13-global-occurrences-unique", "R19-14-route-91-nodes-162-edges-zero-remainder",
    "R19-15-bake-input-schema-valid", "R19-16-bake-slot-fact-totality", "R19-17-vector-32-count-200-bytes", "R19-18-vector-a-b-v-derived-equality",
    "R19-19-bake-graph-edge-derived-tuple", "R19-20-proved-none-nonvacuous", "R19-21-kp-12-fields-present-equal", "R19-22-zero-proof-inhabitable-exclusive",
    "R19-23-four-missing-direct-edges-present", "R19-24-constructor-46-nodes-114-edges-zero-remainder",
    "R19-25-pre-snapshot-admitted-before-process", "R19-26-case-rows-reparse-exact-exit-stdout", "R19-27-source-map-admitted-no-orphan",
    "R19-28-mutation-64-additions-256-total-unique", "R19-29-two-old-colliding-ids-absent-from-r19-additions", "R19-30-no-production-test-provider-ledger-g3-change"
  ],
  "check_count": 30
}
```

The future order remains strict: R19 architecture plus receipt preexist;
independent architecture review; post-review admission; distinct parser A,
parser B, verifier, RED-test/source-map/execution subjects with independent
reviews; admitted RED evidence while model is absent; distinct model
implementation/review; admitted GREEN evidence/review. Every lifecycle uses a
globally unique observed task handle and occurrence. This is auditable
orchestration integrity and separation of task occurrences, not cryptographic
principal independence or non-collusion.

R19 is Part-0 architecture only. It grants no authority for fixtures, packages,
tests, model, execution evidence, implementation, production/provider edits,
ArtifactLedger/G3 changes, audit findings, protocol answers, release, or
readiness. Recall is preserved because no public or private recon output is
dropped and fixed provider slots remain total; precision improves because
aliases, malformed vector facts, scalar Kp/zero claims, post-hoc pre-state,
self-reported case outcomes, and duplicate mutation cases cannot false-green.
