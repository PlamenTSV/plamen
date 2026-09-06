# Cut-4 transactional recon publication R18 preimplementation contract

Date: 2026-08-10
Status: Part-0 architecture-only repair awaiting independent review
Supersedes: only the four rejected R17 gates
Authority: all admission-route, parser, verifier, fixture, test, model,
implementation, production, provider, ArtifactLedger, G3, audit, commit, push,
install, cutover, release, readiness, and protocol-answer authority is false

## 0. Boundary and authenticated predecessor

This turn creates only this contract and its author receipt. It does not create
or edit an architecture review, admission, route record, parser, verifier,
fixture, test, execution receipt, negative proof, model, production/provider
path, ArtifactLedger row, or G3 pin.

The complete R17 independent REPAIR review was authenticated and read end to
end before authoring:

| Artifact | Bytes | SHA-256 |
|---|---:|---|
| `review_fixtures/cut4_transactional_recon_publication_r17_architecture_independent_review_20260810.md` | 23,590 | `b36f33b643f5da4b0c19b16bd036139e76e7a019c6dea8ac52201a6d207bc580` |
| `architecture/cut4-transactional-recon-publication-r17-preimplementation-contract.md` | 74,769 | `e10bcfe0c72d5afc2124c324ba5ad74dd2927cf1d420a295910ffc073f952d56` |
| `review_fixtures/cut4_transactional_recon_publication_r17_contract_author_receipt_20260810.md` | 5,431 | `dda9fd44bef0c6399a9eeb72f3dabaf34531076ac9063740f110dd2ba3c9ae5a` |

R18 inherits every accepted R1-R17 clause outside the four findings: sole
`recon/canonical_merge` ownership, immutable MODEL visibility, fixed provider
slots `source_graph/build_probe/daml_source_graph`, fixed nonempty provider
outcomes, stable registered publication successor, acyclic terminal-before-
link journal order, complete SC/L1 public tuples, compatibility projection,
legacy non-adoption, exact replay/crash recovery, project-root containment,
MODEL shards, dependency units, and nonempty exhausted c3. R18 replacements
below control where R17 conflicts.

`H` is ordinary SHA-256 bytes. `U` is strict UTF-8 of an NFC string. `CJ` is
RFC 8785 canonical JSON after duplicate-key, non-finite, surrogate, and
non-NFC rejection. `D(tag,x)=H(U(tag||"\\0")||CJ(x))`. Hex is lowercase and
strict; arrays are ordered; `EMPTY_SHA` is
`e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.
Hashes address bytes and joins only; none is a signature or independence proof.

## 1. Acyclic review then admission route

### 1.1 Boundary that can exist

The R18 contract and author receipt preexist the independent architecture
review. That review is deliberately outside the later worker route. It reads
the two exact subjects and writes its unique review path. If and only if the
review says ACCEPT, the root may create one post-review
`ArchitectureAdmissionRecord` with `O_CREAT|O_EXCL`. The record cites the exact
contract bytes, author-receipt bytes, ACCEPT review bytes, and the observed
review result event. Only later worker starts cite the admission. Neither a
root plan nor a worker start purports to dominate or prospectively launch the
review that grants admission.

```json
{
  "schema": "cut4.r18.path_registry.v1",
  "contract": "architecture/cut4-transactional-recon-publication-r18-preimplementation-contract.md",
  "author_receipt": "review_fixtures/cut4_transactional_recon_publication_r18_contract_author_receipt_20260810.md",
  "architecture_review": "review_fixtures/cut4_transactional_recon_publication_r18_architecture_independent_review_20260810.md",
  "architecture_admission": "review_fixtures/cut4_transactional_recon_publication_r18_route/000_architecture_admission.json",
  "route_directory": "review_fixtures/cut4_transactional_recon_publication_r18_route",
  "parser_a_package": "review_fixtures/cut4_transactional_recon_publication_r18_parser_a.py",
  "parser_b_package": "review_fixtures/cut4_transactional_recon_publication_r18_parser_b.py",
  "verifier_package": "review_fixtures/cut4_transactional_recon_publication_r18_independent_verifier.py",
  "red_test": "tests/test_cut4_transactional_recon_publication_r18_preimplementation.py",
  "parser_a_execution_receipt": "review_fixtures/cut4_transactional_recon_publication_r18_parser_a_execution_receipt.json",
  "parser_b_execution_receipt": "review_fixtures/cut4_transactional_recon_publication_r18_parser_b_execution_receipt.json",
  "verifier_execution_receipt": "review_fixtures/cut4_transactional_recon_publication_r18_verifier_execution_receipt.json",
  "negative_proof_receipt": "review_fixtures/cut4_transactional_recon_publication_r18_negative_proof_receipt.json",
  "red_execution_event": "review_fixtures/cut4_transactional_recon_publication_r18_red_execution_event.json",
  "red_observer_receipt": "review_fixtures/cut4_transactional_recon_publication_r18_red_observer_receipt.json",
  "red_author_receipt": "review_fixtures/cut4_transactional_recon_publication_r18_red_author_receipt.json",
  "model": "review_fixtures/cut4_transactional_recon_publication_r18_reference_model.py",
  "green_execution_event": "review_fixtures/cut4_transactional_recon_publication_r18_green_execution_event.json",
  "green_observer_receipt": "review_fixtures/cut4_transactional_recon_publication_r18_green_observer_receipt.json",
  "green_author_receipt": "review_fixtures/cut4_transactional_recon_publication_r18_green_author_receipt.json"
}
```

### 1.2 Closed event and admission schemas

The root observation adapter consumes one immutable orchestration event byte
string and produces the following canonical projection. `raw_event_bytes` is
strict base64. The adapter ID is frozen; a different runtime event shape is
typed `UNSUPPORTED_EVENT_DEBT`, never guessed.

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "cut4.r18.route_records.schema.v1",
  "$defs": {
    "Hex64": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
    "TaskHandle": {"type": "string", "pattern": "^/root(?:/[a-z0-9_]+)+$"},
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
      "required": ["schema", "adapter_id", "event_kind", "raw_event_bytes_base64", "raw_event_byte_size", "raw_event_sha256", "task_handle", "parent_handle", "occurrence_id", "payload_bytes_base64", "payload_byte_size", "payload_sha256", "event_digest"],
      "properties": {
        "schema": {"const": "cut4.r18.runtime_event.v1"},
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
        "event_digest": {"$ref": "#/$defs/Hex64"}
      }
    },
    "PathAbsenceObservation": {
      "type": "object", "additionalProperties": false,
      "required": ["schema", "parent_identity", "target_identity", "directory_entries", "target_membership_count", "enumeration_bytes_base64", "enumeration_byte_size", "enumeration_sha256", "observation_digest"],
      "properties": {
        "schema": {"const": "cut4.r18.path_absence.v1"},
        "parent_identity": {"type": "string", "minLength": 1},
        "target_identity": {"type": "string", "minLength": 1},
        "directory_entries": {"type": "array", "uniqueItems": true, "items": {"type": "string"}},
        "target_membership_count": {"const": 0},
        "enumeration_bytes_base64": {"type": "string"},
        "enumeration_byte_size": {"type": "integer", "minimum": 2},
        "enumeration_sha256": {"$ref": "#/$defs/Hex64"},
        "observation_digest": {"$ref": "#/$defs/Hex64"}
      }
    },
    "ArchitectureAdmissionRecord": {
      "type": "object", "additionalProperties": false,
      "required": ["schema", "contract", "author_receipt", "review", "review_result_event", "decision", "reviewed_subject_digest", "admission_ordinal", "admission_digest"],
      "properties": {
        "schema": {"const": "cut4.r18.architecture_admission.v1"},
        "contract": {"$ref": "#/$defs/ByteSubject"},
        "author_receipt": {"$ref": "#/$defs/ByteSubject"},
        "review": {"$ref": "#/$defs/ByteSubject"},
        "review_result_event": {"$ref": "#/$defs/RuntimeEvent"},
        "decision": {"const": "ACCEPT"},
        "reviewed_subject_digest": {"$ref": "#/$defs/Hex64"},
        "admission_ordinal": {"const": 0},
        "admission_digest": {"$ref": "#/$defs/Hex64"}
      }
    },
    "ProducerStartRecord": {
      "type": "object", "additionalProperties": false,
      "required": ["schema", "subject_id", "subject_identity", "producer_start_event", "architecture_admission_digest", "predecessor_subject_admission_digests", "subject_absence", "start_digest"],
      "properties": {
        "schema": {"const": "cut4.r18.producer_start.v1"},
        "subject_id": {"type": "string", "pattern": "^S[0-9]{2}$"},
        "subject_identity": {"type": "string", "minLength": 1},
        "producer_start_event": {"$ref": "#/$defs/RuntimeEvent"},
        "architecture_admission_digest": {"$ref": "#/$defs/Hex64"},
        "predecessor_subject_admission_digests": {"type": "array", "uniqueItems": true, "items": {"$ref": "#/$defs/Hex64"}},
        "subject_absence": {"$ref": "#/$defs/PathAbsenceObservation"},
        "start_digest": {"$ref": "#/$defs/Hex64"}
      }
    },
    "ProducerCompletionRecord": {
      "type": "object", "additionalProperties": false,
      "required": ["schema", "subject_id", "producer_start_digest", "producer_result_event", "subject", "completion_digest"],
      "properties": {
        "schema": {"const": "cut4.r18.producer_completion.v1"},
        "subject_id": {"type": "string", "pattern": "^S[0-9]{2}$"},
        "producer_start_digest": {"$ref": "#/$defs/Hex64"},
        "producer_result_event": {"$ref": "#/$defs/RuntimeEvent"},
        "subject": {"$ref": "#/$defs/ByteSubject"},
        "completion_digest": {"$ref": "#/$defs/Hex64"}
      }
    },
    "ReviewStartRecord": {
      "type": "object", "additionalProperties": false,
      "required": ["schema", "subject_id", "producer_completion_digest", "producer_task_handle", "review_start_event", "review_identity", "review_absence", "start_digest"],
      "properties": {
        "schema": {"const": "cut4.r18.review_start.v1"},
        "subject_id": {"type": "string", "pattern": "^S[0-9]{2}$"},
        "producer_completion_digest": {"$ref": "#/$defs/Hex64"},
        "producer_task_handle": {"$ref": "#/$defs/TaskHandle"},
        "review_start_event": {"$ref": "#/$defs/RuntimeEvent"},
        "review_identity": {"type": "string", "minLength": 1},
        "review_absence": {"$ref": "#/$defs/PathAbsenceObservation"},
        "start_digest": {"$ref": "#/$defs/Hex64"}
      }
    },
    "ReviewCompletionRecord": {
      "type": "object", "additionalProperties": false,
      "required": ["schema", "subject_id", "review_start_digest", "review_result_event", "review", "decision", "completion_digest"],
      "properties": {
        "schema": {"const": "cut4.r18.review_completion.v1"},
        "subject_id": {"type": "string", "pattern": "^S[0-9]{2}$"},
        "review_start_digest": {"$ref": "#/$defs/Hex64"},
        "review_result_event": {"$ref": "#/$defs/RuntimeEvent"},
        "review": {"$ref": "#/$defs/ByteSubject"},
        "decision": {"enum": ["ACCEPT", "REPAIR"]},
        "completion_digest": {"$ref": "#/$defs/Hex64"}
      }
    },
    "SubjectAdmissionRecord": {
      "type": "object", "additionalProperties": false,
      "required": ["schema", "subject_id", "producer_completion_digest", "producer_task_handle", "review_completion_digest", "review_task_handle", "decision", "subject_sha256", "subject_admission_digest"],
      "properties": {
        "schema": {"const": "cut4.r18.subject_admission.v1"},
        "subject_id": {"type": "string", "pattern": "^S[0-9]{2}$"},
        "producer_completion_digest": {"$ref": "#/$defs/Hex64"},
        "producer_task_handle": {"$ref": "#/$defs/TaskHandle"},
        "review_completion_digest": {"$ref": "#/$defs/Hex64"},
        "review_task_handle": {"$ref": "#/$defs/TaskHandle"},
        "decision": {"const": "ACCEPT"},
        "subject_sha256": {"$ref": "#/$defs/Hex64"},
        "subject_admission_digest": {"$ref": "#/$defs/Hex64"}
      }
    }
  },
  "oneOf": [
    {"$ref": "#/$defs/ArchitectureAdmissionRecord"}, {"$ref": "#/$defs/ProducerStartRecord"}, {"$ref": "#/$defs/ProducerCompletionRecord"},
    {"$ref": "#/$defs/ReviewStartRecord"}, {"$ref": "#/$defs/ReviewCompletionRecord"}, {"$ref": "#/$defs/SubjectAdmissionRecord"}
  ]
}
```

Strict base64 decode reproduces every byte size/SHA. The runtime adapter parses
strict JSON event bytes and extracts exact JSON pointers
`/event_kind,/task_handle,/parent_handle,/occurrence_id,/payload_base64`; it
requires canonical reserialization byte equality. Missing/extra/wrong-type
fields are `UNSUPPORTED_EVENT_DEBT`. The event digest is
`D("cut4.r18.runtime_event.v1", event without event_digest)`.

`reviewed_subject_digest = D("cut4.r18.architecture_subject.v1",
[contract.sha256,author_receipt.sha256])`; admission and every record digest
use its schema tag over the object excluding only that digest. The review
result event must be `TASK_RESULT`, its payload bytes must equal the review
subject bytes, and the review must literally parse `Decision: ACCEPT` under
the frozen review-header parser. For every lifecycle, start/result occurrence
IDs and handles must match; subject/review identity must be absent from the
captured parent-directory entries before start and present exactly once after
completion; paths use create-new/O_EXCL. `producer_task_handle !=
review_task_handle` is computed from the two event projections; there is no
caller-supplied distinctness boolean.

For each path-absence observation, enumeration bytes must equal
`CJ(directory_entries)`, size/SHA must reproduce, parent plus target basename
must equal the routed identity, and membership count is rederived by exact NFC
case-sensitive equality. The observation BODY digest is fixed. Thus absence is
an observed create-new precondition, not a producer assertion.

### 1.3 One producer and one review relation per subject

Each row below is one subject, one producer occurrence, one reviewer
occurrence, and one post-ACCEPT subject admission. No producer completion or
review relation may stand for another subject.

```json
{
  "schema": "cut4.r18.subject_route.v1",
  "rows": [
    ["S01", "parser_a_package", "PARSER_A_AUTHOR", "PARSER_A_REVIEWER", []],
    ["S02", "parser_b_package", "PARSER_B_AUTHOR", "PARSER_B_REVIEWER", []],
    ["S03", "verifier_package", "VERIFIER_AUTHOR", "VERIFIER_REVIEWER", []],
    ["S04", "red_test", "RED_TEST_AUTHOR", "RED_TEST_REVIEWER", ["S01", "S02", "S03"]],
    ["S05", "parser_a_execution_receipt", "PARSER_A_RUNNER", "PARSER_A_RUN_REVIEWER", ["S01", "S04"]],
    ["S06", "parser_b_execution_receipt", "PARSER_B_RUNNER", "PARSER_B_RUN_REVIEWER", ["S02", "S04"]],
    ["S07", "verifier_execution_receipt", "VERIFIER_RUNNER", "VERIFIER_RUN_REVIEWER", ["S03", "S05", "S06"]],
    ["S08", "negative_proof_receipt", "NEGATIVE_PROOF_AUTHOR", "NEGATIVE_PROOF_REVIEWER", ["S07"]],
    ["S09", "red_execution_event", "RED_EVENT_PRODUCER", "RED_EVENT_REVIEWER", ["S04", "S08"]],
    ["S10", "red_observer_receipt", "RED_OBSERVER", "RED_OBSERVER_REVIEWER", ["S09"]],
    ["S11", "red_author_receipt", "RED_RECEIPT_AUTHOR", "RED_RECEIPT_REVIEWER", ["S04", "S05", "S06", "S07", "S08", "S09", "S10"]],
    ["S12", "model", "MODEL_IMPLEMENTER", "MODEL_REVIEWER", ["S11"]],
    ["S13", "green_execution_event", "GREEN_EVENT_PRODUCER", "GREEN_EVENT_REVIEWER", ["S04", "S12"]],
    ["S14", "green_observer_receipt", "GREEN_OBSERVER", "GREEN_OBSERVER_REVIEWER", ["S13"]],
    ["S15", "green_author_receipt", "GREEN_RECEIPT_AUTHOR", "GREEN_RECEIPT_REVIEWER", ["S04", "S12", "S13", "S14"]]
  ],
  "record_expansion": ["PRODUCER_START", "PRODUCER_COMPLETION", "REVIEW_START", "REVIEW_COMPLETION", "SUBJECT_ADMISSION"],
  "record_identity_template": "review_fixtures/cut4_transactional_recon_publication_r18_route/{subject_id_lower}_{record_kind_lower}.json",
  "review_identity_template": "review_fixtures/cut4_transactional_recon_publication_r18_route/{subject_id_lower}_independent_review.md",
  "all_producer_and_reviewer_occurrence_ids_pairwise_distinct": true
}
```

The exact expanded route has 76 nodes: one architecture admission and five
records for each of 15 subjects. It has 119 edges: architecture admission to
15 producer starts; 15 each of producer-start-to-completion,
producer-completion-to-review-start, review-start-to-review-completion,
producer-completion-to-subject-admission, and
review-completion-to-subject-admission; plus the 29 displayed predecessor
subject-admission-to-producer-start edges. All dependency IDs refer to earlier
rows. Kahn remainder is zero. All 30 producer/reviewer occurrence IDs are
pairwise distinct. This is structural task-label separation and byte
transport, not cryptographic principal independence or non-collusion.

## 2. Ecosystem-gated recognition and frozen execution proofs

### 2.1 Exact lexical and matcher overlay

R18 retains R17's UTF-8, NFC, token-span, string, EOF/default, coverage, and
error rules, but replaces comment dispatch and the underdefined semantic
matcher. Comment/opening operators are gated by this immutable table:

```json
{
  "schema": "cut4.r18.ecosystem_lexical_registry.v1",
  "rows": [
    ["aptos", ["//"], [["/*", "*/"]]],
    ["daml", ["--"], [["{-", "-}"]]],
    ["evm", ["//"], [["/*", "*/"]]],
    ["go", ["//"], [["/*", "*/"]]],
    ["rust", ["//"], [["/*", "*/"]]],
    ["solana", ["//"], [["/*", "*/"]]],
    ["soroban", ["//"], [["/*", "*/"]]],
    ["sui", ["//"], [["/*", "*/"]]]
  ],
  "operator_rows": [
    ["aptos", ["/", "*", "-", "{", "}", ".", "(", ")", ",", ":", ";", "[", "]", "="]],
    ["daml", ["/", "*", "-", "{", "}", ".", "(", ")", ",", ":", ";", "[", "]", "="]],
    ["evm", ["/", "*", "-", "{", "}", ".", "(", ")", ",", ":", ";", "[", "]", "="]],
    ["go", ["/", "*", "-", "{", "}", ".", "(", ")", ",", ":", ";", "[", "]", "="]],
    ["rust", ["/", "*", "-", "{", "}", ".", "(", ")", ",", ":", ";", "[", "]", "="]],
    ["solana", ["/", "*", "-", "{", "}", ".", "(", ")", ",", ":", ";", "[", "]", "="]],
    ["soroban", ["/", "*", "-", "{", "}", ".", "(", ")", ",", ":", ";", "[", "]", "="]],
    ["sui", ["/", "*", "-", "{", "}", ".", "(", ")", ",", ":", ";", "[", "]", "="]]
  ],
  "dispatch": "at byte i, test only openers registered for the selected ecosystem, longest opener first; an unregistered slash/dash/brace sequence emits one PUNCT token per byte",
  "operator_totality": "ecosystem must match exactly one comment row and one operator row; comment dispatch precedes operator dispatch; an unregistered operator byte is UNKNOWN and typed debt; unknown ecosystem is MALFORMED_DEBT"
}
```

Parser A checks this table before its comment production. Parser B replaces
unconditional `S_SLASH/S_DASH/DAML` openings with
`GUARD_COMMENT(ecosystem,raw_opener)`: true enters the registered line/block
state; false emits the first opener byte as PUNCT and reconsumes the next byte.
The verifier independently performs the same literal table lookup. There is no
language-agnostic comment transition.

The common semantic matcher is a frozen opcode contract, but A, B, and V must
implement it independently:

```json
{
  "schema": "cut4.r18.semantic_matcher.v1",
  "token_projection": ["source_id", "token_ordinal", "byte_start", "byte_end", "kind", "raw_sha256", "decoded_nfc", "error_code"],
  "candidate_projection": ["source_id", "candidate_ordinal", "byte_start", "byte_end", "semantic_class", "normalized_value", "raw_sha256", "bake_fact_id", "debt_code"],
  "opcodes": [
    [1, "FILTER", "retain all tokens except WS and EOF; comments remain atomic; assign filtered ordinal"],
    [2, "BRACKETS", "walk filtered tokens; LP/LBRACE/LBRACK push exact opener ordinal; matching closer pops; mismatch emits one MALFORMED_DEBT candidate at closer; EOF with stack emits one at each unclosed opener"],
    [3, "STATEMENTS", "statement starts at 0 or byte after SEMI/LF; statement ends immediately before SEMI/LF/EOF at bracket depth zero"],
    [4, "ASSIGNMENT", "within each statement/depth, first EQ with nearest preceding IDENT at same depth creates frame (left_ident,eq_ordinal,depth); second EQ at same depth invalidates that frame"],
    [5, "CALL_FRAME", "IDENT LP or IDENT DOT IDENT LP creates frame with callee, open ordinal, depth; MEMBER form wins over CALL at the same LP"],
    [6, "DECLARATION", "ecosystem declaration-keyword IDENT at same depth emits span keyword.start through ident.end and normalized ident"],
    [7, "IMPORT", "ecosystem import-keyword followed by first STRING or IDENT before statement end emits span keyword.start through value.end and normalized unquoted value"],
    [8, "CALL", "each call frame emits MEMBER_CALL or CALL at its LP; frames order by LP token ordinal"],
    [9, "REFERENCE", "each STRING token chooses innermost containing call frame; its callee maps by exact path/content identifier tables; if no call mapping, nearest active assignment left_ident maps; content wins only when its frame is strictly more deeply nested; otherwise emit no reference"],
    [10, "BAKE", "append one GRAPH_EDGE/PROBE_EDGE candidate for every validated BakeFactRow of matching kind; no source token may synthesize a BAKE candidate"],
    [11, "ORDINAL", "sort by (byte_start,byte_end,semantic_priority,normalized_value,bake_fact_id,raw_sha256); assign candidate_ordinal from zero"],
    [12, "TOTAL", "every malformed token/bracket becomes debt; every BAKE fact maps exactly once; all other tokens may correctly produce no semantic candidate"]
  ],
  "semantic_priority": ["MALFORMED_DEBT", "IMPORT", "DECLARATION", "MEMBER_CALL", "CALL", "PATH_REFERENCE", "CONTENT_INSTRUCTION", "GRAPH_EDGE", "PROBE_EDGE"],
  "path_context_identifiers": ["file", "filename", "include", "input", "manifest", "output", "path", "read", "source", "template", "write"],
  "content_context_identifiers": ["agent", "instruction", "methodology", "prompt", "role", "system", "tool"],
  "assignment_token": "PUNCT whose raw byte is 0x3d",
  "escape_rule": "string normalized value removes matching quotes and decodes only backslash-quote and backslash-backslash; any other escape preserves backslash and scalar"
}
```

### 2.2 Literal conformance bytes frozen before packages

The following root is part of this architecture subject and therefore exists
before admission and every parser/verifier package task. Rows are
`[id,ecosystem,source_hex,bake_hex,expected_token_tuples,expected_semantic_tuples]`.
Hex is even-length lowercase and decodes literally. Tuple codecs use `;`
between rows and `,` between fields; empty string means zero rows. Token fields
are `start,end,kind,error`; semantic fields are
`start,end,class,normalized_value,debt`. Codec strings are ASCII and none of
the closed enum/value strings contains comma or semicolon. The root digest is
`D("cut4.r18.conformance_vector_bytes.v1",root)`; each vector digest is the
same domain over its expanded row, decoded sizes/SHAs, and decoded tuple
arrays. Packages bind the root digest and cannot replace bytes, ecosystem,
BAKE input, or expected tuples.

```json
{
  "schema": "cut4.r18.conformance_vector_bytes.v1",
  "rows": [
    ["empty","evm","","5b5d","0,0,EOF,NONE",""],
    ["evm_line_comment","evm","2f2f78","5b5d","0,3,LINE_COMMENT,NONE;3,3,EOF,NONE",""],
    ["daml_line_comment","daml","2d2d78","5b5d","0,3,LINE_COMMENT,NONE;3,3,EOF,NONE",""],
    ["evm_dash_not_comment","evm","2d2d78","5b5d","0,1,PUNCT,NONE;1,2,PUNCT,NONE;2,3,IDENT,NONE;3,3,EOF,NONE",""],
    ["daml_slash_not_comment","daml","2f2f78","5b5d","0,1,PUNCT,NONE;1,2,PUNCT,NONE;2,3,IDENT,NONE;3,3,EOF,NONE",""],
    ["evm_block_comment","evm","2f2a782a2f","5b5d","0,5,BLOCK_COMMENT,NONE;5,5,EOF,NONE",""],
    ["daml_block_comment","daml","7b2d782d7d","5b5d","0,5,BLOCK_COMMENT,NONE;5,5,EOF,NONE",""],
    ["evm_unterminated_comment","evm","2f2a78","5b5d","0,3,UNTERMINATED_COMMENT,E_COMMENT_EOF;3,3,EOF,NONE","0,3,MALFORMED_DEBT,,UNTERMINATED"],
    ["daml_unterminated_comment","daml","7b2d78","5b5d","0,3,UNTERMINATED_COMMENT,E_COMMENT_EOF;3,3,EOF,NONE","0,3,MALFORMED_DEBT,,UNTERMINATED"],
    ["identifier","evm","616263","5b5d","0,3,IDENT,NONE;3,3,EOF,NONE",""],
    ["evm_declaration","evm","66756e6374696f6e2066","5b5d","0,8,IDENT,NONE;8,9,WS,NONE;9,10,IDENT,NONE;10,10,EOF,NONE","0,10,DECLARATION,f,NONE"],
    ["daml_declaration","daml","646174612058","5b5d","0,4,IDENT,NONE;4,5,WS,NONE;5,6,IDENT,NONE;6,6,EOF,NONE","0,6,DECLARATION,X,NONE"],
    ["evm_import","evm","696d706f7274202278223b","5b5d","0,6,IDENT,NONE;6,7,WS,NONE;7,10,STRING_DQ,NONE;10,11,PUNCT,NONE;11,11,EOF,NONE","0,10,IMPORT,x,NONE"],
    ["daml_import","daml","696d706f72742058","5b5d","0,6,IDENT,NONE;6,7,WS,NONE;7,8,IDENT,NONE;8,8,EOF,NONE","0,8,IMPORT,X,NONE"],
    ["member_call","evm","612e6228","5b5d","0,1,IDENT,NONE;1,2,PUNCT,NONE;2,3,IDENT,NONE;3,4,PUNCT,NONE;4,4,EOF,NONE","0,4,MEMBER_CALL,a.b,NONE"],
    ["call","evm","6128","5b5d","0,1,IDENT,NONE;1,2,PUNCT,NONE;2,2,EOF,NONE","0,2,CALL,a,NONE"],
    ["path_call_context","evm","726561642822782229","5b5d","0,4,IDENT,NONE;4,5,PUNCT,NONE;5,8,STRING_DQ,NONE;8,9,PUNCT,NONE;9,9,EOF,NONE","0,5,CALL,read,NONE;5,8,PATH_REFERENCE,x,NONE"],
    ["content_call_context","evm","70726f6d70742822782229","5b5d","0,6,IDENT,NONE;6,7,PUNCT,NONE;7,10,STRING_DQ,NONE;10,11,PUNCT,NONE;11,11,EOF,NONE","0,7,CALL,prompt,NONE;7,10,CONTENT_INSTRUCTION,x,NONE"],
    ["nested_context","evm","726561642870726f6d7074282278222929","5b5d","0,4,IDENT,NONE;4,5,PUNCT,NONE;5,11,IDENT,NONE;11,12,PUNCT,NONE;12,15,STRING_DQ,NONE;15,16,PUNCT,NONE;16,17,PUNCT,NONE;17,17,EOF,NONE","0,5,CALL,read,NONE;5,12,CALL,prompt,NONE;12,15,CONTENT_INSTRUCTION,x,NONE"],
    ["invalid_lead","evm","ff","5b5d","0,1,INVALID_UTF8,E_UTF8;1,1,EOF,NONE","0,1,MALFORMED_DEBT,,INVALID_UTF8"],
    ["invalid_overlong","evm","c0af","5b5d","0,2,INVALID_UTF8,E_UTF8;2,2,EOF,NONE","0,2,MALFORMED_DEBT,,INVALID_UTF8"],
    ["invalid_surrogate","evm","eda080","5b5d","0,3,INVALID_UTF8,E_UTF8;3,3,EOF,NONE","0,3,MALFORMED_DEBT,,INVALID_UTF8"],
    ["invalid_truncated","evm","e282","5b5d","0,2,INVALID_UTF8,E_UTF8;2,2,EOF,NONE","0,2,MALFORMED_DEBT,,INVALID_UTF8"],
    ["nul_byte","evm","00","5b5d","0,1,UNKNOWN,E_UNKNOWN;1,1,EOF,NONE","0,1,MALFORMED_DEBT,,UNKNOWN_FORM"],
    ["double_string","evm","227822","5b5d","0,3,STRING_DQ,NONE;3,3,EOF,NONE",""],
    ["unterminated_string","evm","2278","5b5d","0,2,UNTERMINATED_STRING,E_STRING_EOF;2,2,EOF,NONE","0,2,MALFORMED_DEBT,,UNTERMINATED"],
    ["escape_eof","evm","225c","5b5d","0,2,UNTERMINATED_STRING,E_ESCAPE_EOF;2,2,EOF,NONE","0,2,MALFORMED_DEBT,,UNTERMINATED"],
    ["crlf_whitespace","evm","200d0a","5b5d","0,3,WS,NONE;3,3,EOF,NONE",""],
    ["assignment_path","evm","70617468203d20227822","5b5d","0,4,IDENT,NONE;4,5,WS,NONE;5,6,PUNCT,NONE;6,7,WS,NONE;7,10,STRING_DQ,NONE;10,10,EOF,NONE","7,10,PATH_REFERENCE,x,NONE"],
    ["keyword_boundary","evm","66756e6374696f6e78","5b5d","0,9,IDENT,NONE;9,9,EOF,NONE",""],
    ["generic_common_omission","evm","66756e6374696f6e20663b20696d706f7274202278223b20612e6228293b207265616428227022293b2070726f6d70742822632229","5b5d","0,8,IDENT,NONE;8,9,WS,NONE;9,10,IDENT,NONE;10,11,PUNCT,NONE;11,12,WS,NONE;12,18,IDENT,NONE;18,19,WS,NONE;19,22,STRING_DQ,NONE;22,23,PUNCT,NONE;23,24,WS,NONE;24,25,IDENT,NONE;25,26,PUNCT,NONE;26,27,IDENT,NONE;27,28,PUNCT,NONE;28,29,PUNCT,NONE;29,30,PUNCT,NONE;30,31,WS,NONE;31,35,IDENT,NONE;35,36,PUNCT,NONE;36,39,STRING_DQ,NONE;39,40,PUNCT,NONE;40,41,PUNCT,NONE;41,42,WS,NONE;42,48,IDENT,NONE;48,49,PUNCT,NONE;49,52,STRING_DQ,NONE;52,53,PUNCT,NONE;53,53,EOF,NONE","0,10,DECLARATION,f,NONE;12,22,IMPORT,x,NONE;24,28,MEMBER_CALL,a.b,NONE;31,36,CALL,read,NONE;36,39,PATH_REFERENCE,p,NONE;42,49,CALL,prompt,NONE;49,52,CONTENT_INSTRUCTION,c,NONE"],
    ["bake_graph_edge","evm","","5b7b22666163745f6964223a2262616b652d67726170682d31222c226b696e64223a2247524150485f45444745222c226f626a6563745f6964223a2262222c227375626a6563745f6964223a2261227d5d","0,0,EOF,NONE","0,0,GRAPH_EDGE,a->b,NONE"]
  ],
  "row_count": 32
}
```

### 2.3 Routed parser/verifier equality and negative proof

Parser A and B execution subjects contain one closed result per displayed
vector. The verifier subject independently derives the same token/semantic
tuples from literal bytes. Tuple arrays compare as exact `CJ` bytes in vector
order; no set conversion is allowed.

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "cut4.r18.recognition_execution.schema.v1",
  "$defs": {
    "Hex64": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
    "VectorResult": {
      "type": "object", "additionalProperties": false,
      "required": ["vector_id", "vector_digest", "source_byte_size", "source_sha256", "bake_byte_size", "bake_sha256", "token_count", "token_tuple_bytes_base64", "token_tuple_sha256", "candidate_count", "semantic_tuple_bytes_base64", "semantic_tuple_sha256", "coverage_byte_count", "coverage_gap_count", "coverage_overlap_count", "result_digest"],
      "properties": {
        "vector_id": {"type": "string", "minLength": 1},
        "vector_digest": {"$ref": "#/$defs/Hex64"},
        "source_byte_size": {"type": "integer", "minimum": 0},
        "source_sha256": {"$ref": "#/$defs/Hex64"},
        "bake_byte_size": {"type": "integer", "minimum": 2},
        "bake_sha256": {"$ref": "#/$defs/Hex64"},
        "token_count": {"type": "integer", "minimum": 1},
        "token_tuple_bytes_base64": {"type": "string"},
        "token_tuple_sha256": {"$ref": "#/$defs/Hex64"},
        "candidate_count": {"type": "integer", "minimum": 0},
        "semantic_tuple_bytes_base64": {"type": "string"},
        "semantic_tuple_sha256": {"$ref": "#/$defs/Hex64"},
        "coverage_byte_count": {"type": "integer", "minimum": 0},
        "coverage_gap_count": {"const": 0},
        "coverage_overlap_count": {"const": 0},
        "result_digest": {"$ref": "#/$defs/Hex64"}
      }
    },
    "ExecutionReceipt": {
      "type": "object", "additionalProperties": false,
      "required": ["schema", "engine", "package_subject_admission_digest", "package_sha256", "conformance_root_digest", "bake_binding_digest", "results", "result_roster_digest", "receipt_digest"],
      "properties": {
        "schema": {"const": "cut4.r18.recognition_execution_receipt.v1"},
        "engine": {"enum": ["PARSER_A", "PARSER_B", "VERIFIER"]},
        "package_subject_admission_digest": {"$ref": "#/$defs/Hex64"},
        "package_sha256": {"$ref": "#/$defs/Hex64"},
        "conformance_root_digest": {"$ref": "#/$defs/Hex64"},
        "bake_binding_digest": {"$ref": "#/$defs/Hex64"},
        "results": {"type": "array", "minItems": 32, "maxItems": 32, "items": {"$ref": "#/$defs/VectorResult"}},
        "result_roster_digest": {"$ref": "#/$defs/Hex64"},
        "receipt_digest": {"$ref": "#/$defs/Hex64"}
      }
    },
    "VectorProof": {
      "type": "object", "additionalProperties": false,
      "required": ["vector_id", "vector_digest", "parser_a_result_digest", "parser_b_result_digest", "verifier_result_digest", "token_count", "candidate_count", "coverage_byte_count", "bake_fact_count", "token_tuple_sha256", "semantic_tuple_sha256", "diff_count", "verdict", "proof_digest"],
      "properties": {
        "vector_id": {"type": "string", "minLength": 1},
        "vector_digest": {"$ref": "#/$defs/Hex64"},
        "parser_a_result_digest": {"$ref": "#/$defs/Hex64"},
        "parser_b_result_digest": {"$ref": "#/$defs/Hex64"},
        "verifier_result_digest": {"$ref": "#/$defs/Hex64"},
        "token_count": {"type": "integer", "minimum": 1},
        "candidate_count": {"type": "integer", "minimum": 0},
        "coverage_byte_count": {"type": "integer", "minimum": 0},
        "bake_fact_count": {"type": "integer", "minimum": 0},
        "token_tuple_sha256": {"$ref": "#/$defs/Hex64"},
        "semantic_tuple_sha256": {"$ref": "#/$defs/Hex64"},
        "diff_count": {"const": 0},
        "verdict": {"const": "EXACT_EQUAL"},
        "proof_digest": {"$ref": "#/$defs/Hex64"}
      }
    },
    "NegativeProofReceipt": {
      "type": "object", "additionalProperties": false,
      "required": ["schema", "conformance_root_digest", "source_vector_count", "source_byte_count", "bake_fact_count", "parser_a_receipt_identity", "parser_a_receipt_sha256", "parser_a_receipt_digest", "parser_b_receipt_identity", "parser_b_receipt_sha256", "parser_b_receipt_digest", "verifier_receipt_identity", "verifier_receipt_sha256", "verifier_receipt_digest", "proof_rows", "proof_roster_digest", "total_token_count", "total_candidate_count", "total_coverage_byte_count", "total_diff_count", "proved_none_vector_ids", "receipt_digest"],
      "properties": {
        "schema": {"const": "cut4.r18.negative_proof_receipt.v1"},
        "conformance_root_digest": {"$ref": "#/$defs/Hex64"},
        "source_vector_count": {"const": 32},
        "source_byte_count": {"type": "integer", "minimum": 1},
        "bake_fact_count": {"type": "integer", "minimum": 1},
        "parser_a_receipt_identity": {"const": "review_fixtures/cut4_transactional_recon_publication_r18_parser_a_execution_receipt.json"},
        "parser_a_receipt_sha256": {"$ref": "#/$defs/Hex64"},
        "parser_a_receipt_digest": {"$ref": "#/$defs/Hex64"},
        "parser_b_receipt_identity": {"const": "review_fixtures/cut4_transactional_recon_publication_r18_parser_b_execution_receipt.json"},
        "parser_b_receipt_sha256": {"$ref": "#/$defs/Hex64"},
        "parser_b_receipt_digest": {"$ref": "#/$defs/Hex64"},
        "verifier_receipt_identity": {"const": "review_fixtures/cut4_transactional_recon_publication_r18_verifier_execution_receipt.json"},
        "verifier_receipt_sha256": {"$ref": "#/$defs/Hex64"},
        "verifier_receipt_digest": {"$ref": "#/$defs/Hex64"},
        "proof_rows": {"type": "array", "minItems": 32, "maxItems": 32, "items": {"$ref": "#/$defs/VectorProof"}},
        "proof_roster_digest": {"$ref": "#/$defs/Hex64"},
        "total_token_count": {"type": "integer", "minimum": 32},
        "total_candidate_count": {"type": "integer", "minimum": 1},
        "total_coverage_byte_count": {"type": "integer", "minimum": 1},
        "total_diff_count": {"const": 0},
        "proved_none_vector_ids": {"type": "array", "minItems": 1, "uniqueItems": true, "items": {"type": "string"}},
        "receipt_digest": {"$ref": "#/$defs/Hex64"}
      }
    }
  },
  "oneOf": [{"$ref": "#/$defs/ExecutionReceipt"}, {"$ref": "#/$defs/NegativeProofReceipt"}]
}
```

Every byte field reproduces size/SHA. Result and proof digests use their
version tag excluding only the terminal digest; rosters hash exact displayed
order. `results[i].vector_id` and `proof_rows[i].vector_id` must equal vector
row `i`; all copied vector/source/BAKE digests/counts are rederived. For each
`i`, A token bytes = B token bytes = V token bytes = frozen expected token
tuples, and the same exact equality holds for semantic bytes. Counts and SHAs
must therefore be equal; otherwise a typed diff row replaces EXACT_EQUAL and
the negative receipt cannot be constructed. `proved_none_vector_ids` equals
exactly the vector IDs whose frozen semantic tuple list is empty, after full
token coverage and BAKE accounting; it is never a global/provider zero claim.
The three execution receipts and negative proof are separately routed subjects
S05-S08, so their internal identities, bytes, and reviews are transported.

## 3. Inhabitable BAKE, semantic, ACK, invalid-file, and PhaseIO types

### 3.1 Closed provider receipts and direct BAKE roster

R18 replaces the mismatched R17 BAKE/authority scalar fragments with these
complete types. The twelve fields from `private_plan_row_id` through
`source_snapshot_digest`, in displayed order, are expanded Kp and must be
byte-equal among plan, predicate evidence, provider receipt, BAKE fact/binding,
provider-private rows, diffs, and completion.

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "cut4.r18.bake_provider.schema.v1",
  "$defs": {
    "Hex64": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
    "PredicateEvidence": {
      "type": "object", "additionalProperties": false,
      "required": ["schema", "predicate_id", "predicate_kind", "provider_id", "plan_digest", "source_snapshot_digest", "result", "evidence_bytes_base64", "evidence_byte_size", "evidence_sha256", "evidence_digest"],
      "properties": {
        "schema": {"const": "cut4.r18.predicate_evidence.v1"},
        "predicate_id": {"enum": ["pred.source_graph.applicable.v1", "pred.source_graph.selected.v1", "pred.build_probe.applicable.v1", "pred.build_probe.selected.v1", "pred.daml_source_graph.applicable.v1", "pred.daml_source_graph.selected.v1"]},
        "predicate_kind": {"enum": ["APPLICABILITY", "SELECTION"]},
        "provider_id": {"enum": ["source_graph", "build_probe", "daml_source_graph"]},
        "plan_digest": {"$ref": "#/$defs/Hex64"},
        "source_snapshot_digest": {"$ref": "#/$defs/Hex64"},
        "result": {"type": "boolean"},
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
        "schema": {"const": "cut4.r18.payload_record.v1"},
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
      "required": ["schema", "provider_id", "invocation_state", "exit_code", "exhausted", "payloads", "evidence_bytes_base64", "evidence_byte_size", "evidence_sha256", "terminal_digest"],
      "properties": {
        "schema": {"const": "cut4.r18.provider_terminal.v1"},
        "provider_id": {"enum": ["source_graph", "build_probe", "daml_source_graph"]},
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
    "ProviderReceipt": {
      "type": "object", "additionalProperties": false,
      "required": ["schema", "private_plan_row_id", "consumer_row_id", "consumer_id", "provider_id", "provider_ordinal", "applicability_predicate_id", "applicability_result", "selection_predicate_id", "selection_result", "invocation_digest", "plan_digest", "source_snapshot_digest", "status", "terminal_bytes_base64", "terminal_byte_size", "terminal_sha256", "payload_count", "payload_roster_digest", "explicit_zero_proof_digest", "debt_code", "receipt_digest"],
      "properties": {
        "schema": {"const": "cut4.r18.provider_receipt.v1"},
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
        "status": {"enum": ["NOT_APPLICABLE", "NOT_SELECTED", "SUCCESS", "SUCCESS_EMPTY", "DEBT", "FAILURE", "TIMEOUT", "MALFORMED"]},
        "terminal_bytes_base64": {"type": "string"},
        "terminal_byte_size": {"type": "integer", "minimum": 1},
        "terminal_sha256": {"$ref": "#/$defs/Hex64"},
        "payload_count": {"type": "integer", "minimum": 0},
        "payload_roster_digest": {"$ref": "#/$defs/Hex64"},
        "explicit_zero_proof_digest": {"$ref": "#/$defs/Hex64"},
        "debt_code": {"enum": ["NONE", "APPROXIMATION", "EXECUTION_FAILURE", "DEADLINE", "SCHEMA_MALFORMED"]},
        "receipt_digest": {"$ref": "#/$defs/Hex64"}
      }
    },
    "BakeFactRow": {
      "type": "object", "additionalProperties": false,
      "required": ["schema", "provider_id", "provider_ordinal", "provider_receipt_digest", "fact_ordinal", "fact_kind", "subject_id", "object_id", "raw_bytes_base64", "raw_byte_size", "raw_sha256", "fact_id", "fact_digest"],
      "properties": {
        "schema": {"const": "cut4.r18.bake_fact.v1"},
        "provider_id": {"enum": ["source_graph", "build_probe", "daml_source_graph"]},
        "provider_ordinal": {"type": "integer", "minimum": 0, "maximum": 2},
        "provider_receipt_digest": {"$ref": "#/$defs/Hex64"},
        "fact_ordinal": {"type": "integer", "minimum": 0},
        "fact_kind": {"enum": ["GRAPH_NODE", "GRAPH_EDGE", "PROBE_RESULT", "TYPED_DEBT"]},
        "subject_id": {"type": "string", "minLength": 1},
        "object_id": {"type": "string", "minLength": 1},
        "raw_bytes_base64": {"type": "string"},
        "raw_byte_size": {"type": "integer", "minimum": 1},
        "raw_sha256": {"$ref": "#/$defs/Hex64"},
        "fact_id": {"type": "string", "pattern": "^bf_[0-9a-f]{64}$"},
        "fact_digest": {"$ref": "#/$defs/Hex64"}
      }
    },
    "BakeBinding": {
      "type": "object", "additionalProperties": false,
      "required": ["schema", "private_plan_row_id", "consumer_row_id", "consumer_id", "plan_digest", "source_snapshot_digest", "provider_receipts", "provider_receipt_roster_bytes_base64", "provider_receipt_roster_byte_size", "provider_receipt_roster_sha256", "provider_receipt_roster_digest", "facts", "fact_count", "fact_roster_digest", "binding_digest"],
      "properties": {
        "schema": {"const": "cut4.r18.bake_binding.v1"},
        "private_plan_row_id": {"type": "string", "minLength": 1},
        "consumer_row_id": {"type": "string", "minLength": 1},
        "consumer_id": {"type": "string", "minLength": 1},
        "plan_digest": {"$ref": "#/$defs/Hex64"},
        "source_snapshot_digest": {"$ref": "#/$defs/Hex64"},
        "provider_receipts": {"type": "array", "minItems": 3, "maxItems": 3, "items": {"$ref": "#/$defs/ProviderReceipt"}},
        "provider_receipt_roster_bytes_base64": {"type": "string"},
        "provider_receipt_roster_byte_size": {"type": "integer", "minimum": 1},
        "provider_receipt_roster_sha256": {"$ref": "#/$defs/Hex64"},
        "provider_receipt_roster_digest": {"$ref": "#/$defs/Hex64"},
        "facts": {"type": "array", "items": {"$ref": "#/$defs/BakeFactRow"}},
        "fact_count": {"type": "integer", "minimum": 0},
        "fact_roster_digest": {"$ref": "#/$defs/Hex64"},
        "binding_digest": {"$ref": "#/$defs/Hex64"}
      }
    }
  },
  "$ref": "#/$defs/BakeBinding"
}
```

Provider receipt order is exactly `(source_graph,0),(build_probe,1),
(daml_source_graph,2)`; every slot contains a nonempty typed terminal byte
record, including neutral/zero/failure states. `provider_receipt_roster_bytes`
must equal `CJ(provider_receipts)`, with exact size/SHA, and
`provider_receipt_roster_digest =
D("cut4.r18.provider_receipt_roster.v1",provider_receipts)`. Thus
`ProviderReceipt -> BakeBinding` is a direct three-child dependency even when
facts are empty.

Each `terminal_bytes_base64` must decode to `CJ(ProviderTerminal)` and validate
the closed schema above. Payload records sort by ordinal from zero without
gaps; their exact decoded bytes reproduce size/SHA and
`payload_digest=D("cut4.r18.payload_record.v1",row without payload_digest)`.
Provider-terminal evidence bytes likewise reproduce size/SHA and its BODY
digest. `NOT_INVOKED` requires exit code 0, exhausted false, and zero payloads;
`COMPLETED` requires exit code 0; `FAILED` requires nonzero exit;
`TIMED_OUT` requires exit code -1; the other states require exit code 0. These
relations, not receipt labels, drive the status table.

The immutable status relation is:

| Applicability | Selection | Terminal evidence | Status | Payload/fact relation |
|---|---|---|---|---|
| false | false | typed no-invocation record | `NOT_APPLICABLE` | payload 0, facts 0, zero proof `EMPTY_SHA`, debt `NONE` |
| true | false | typed no-invocation record | `NOT_SELECTED` | payload 0, facts 0, zero proof `EMPTY_SHA`, debt `NONE` |
| true | true | valid terminal, payload > 0 | `SUCCESS` | fact rows equal decoded payload rows exactly |
| true | true | valid terminal, exhausted payload = 0 | `SUCCESS_EMPTY` | payload/facts 0, nonempty explicit-zero proof |
| true | true | approximation receipt | `DEBT` | exactly one `TYPED_DEBT`, `APPROXIMATION` |
| true | true | nonzero exit | `FAILURE` | exactly one `TYPED_DEBT`, `EXECUTION_FAILURE` |
| true | true | deadline receipt | `TIMEOUT` | exactly one `TYPED_DEBT`, `DEADLINE` |
| true | true | decode/schema mismatch | `MALFORMED` | exactly one `TYPED_DEBT`, `SCHEMA_MALFORMED` |

All other combinations fail. Applicability/selection predicate IDs and results
join exact `PredicateEvidence` objects, Kp plan/source snapshot, and provider.
`terminal_sha256=H(decoded terminal bytes)`; payload digest is the ordered
decoded payload array; receipt digest is the BODY digest. Bake fact raw SHA,
`fact_id="bf_"+D("cut4.r18.bake_fact_id.v1",fields through raw_sha256)`, and
fact BODY digest are rederived. Facts sort by provider ordinal/fact ordinal;
count and roster digest are exact. Binding BODY digest is last. No scalar
digest or clean status is caller authority.

### 3.2 Literal ACK, invalid-file, PhaseIO, and semantic types

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "cut4.r18.authority_types.schema.v1",
  "$defs": {
    "Hex64": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
    "AckPolicy": {
      "type": "object", "additionalProperties": false,
      "required": ["schema", "policy_id", "mode", "truth_table_digest", "policy_digest"],
      "properties": {
        "schema": {"const": "cut4.r18.ack_policy.v1"},
        "policy_id": {"enum": ["cut4-r18-ack-disabled", "cut4-r18-ack-required"]},
        "mode": {"enum": ["DISABLED", "REQUIRED"]},
        "truth_table_digest": {"$ref": "#/$defs/Hex64"},
        "policy_digest": {"$ref": "#/$defs/Hex64"}
      }
    },
    "AckState": {
      "type": "object", "additionalProperties": false,
      "required": ["schema", "policy_digest", "publication_link_digest", "ack_record_digest", "state", "completion_permitted", "state_digest"],
      "properties": {
        "schema": {"const": "cut4.r18.ack_state.v1"},
        "policy_digest": {"$ref": "#/$defs/Hex64"},
        "publication_link_digest": {"$ref": "#/$defs/Hex64"},
        "ack_record_digest": {"$ref": "#/$defs/Hex64"},
        "state": {"enum": ["DISABLED", "REQUIRED_PENDING", "REQUIRED_COMMITTED", "INVALID"]},
        "completion_permitted": {"type": "boolean"},
        "state_digest": {"$ref": "#/$defs/Hex64"}
      }
    },
    "InvalidFileFact": {
      "type": "object", "additionalProperties": false,
      "required": ["schema", "canonical_identity", "fact_kind", "observed_bytes_base64", "observed_byte_size", "observed_sha256", "detected_generation", "fact_id", "fact_digest"],
      "properties": {
        "schema": {"const": "cut4.r18.invalid_file_fact.v1"},
        "canonical_identity": {"type": "string", "minLength": 1},
        "fact_kind": {"enum": ["TORN_TEMP", "ZERO_BYTE", "PARTIAL_FINAL", "MALFORMED_RECORD", "ALIAS_COLLISION"]},
        "observed_bytes_base64": {"type": "string"},
        "observed_byte_size": {"type": "integer", "minimum": 0},
        "observed_sha256": {"$ref": "#/$defs/Hex64"},
        "detected_generation": {"type": "integer", "minimum": 0},
        "fact_id": {"type": "string", "pattern": "^iff_[0-9a-f]{64}$"},
        "fact_digest": {"$ref": "#/$defs/Hex64"}
      }
    },
    "PhaseIOAuthority": {
      "type": "object", "additionalProperties": false,
      "required": ["schema", "mode", "ordinal", "operation", "work_unit", "artifact_key", "identity", "owner", "write_mode", "schema_id", "content_type", "contract_id", "launch_id", "registry_digest", "authority_digest"],
      "properties": {
        "schema": {"const": "cut4.r18.phaseio_authority.v1"},
        "mode": {"enum": ["PRIVATE", "SC", "L1"]},
        "ordinal": {"type": "integer", "minimum": 0, "maximum": 11},
        "operation": {"const": "recon/canonical_publication_successor_v2"},
        "work_unit": {"enum": ["recon/private_seed_v2", "recon/private_journal_v1", "recon/canonical_merge"]},
        "artifact_key": {"type": "string", "minLength": 1},
        "identity": {"type": "string", "minLength": 1},
        "owner": {"const": "DRIVER"},
        "write_mode": {"const": "REPLACE"},
        "schema_id": {"type": "string", "minLength": 1},
        "content_type": {"enum": ["application/json", "text/markdown"]},
        "contract_id": {"const": "cut4-transactional-recon-publication-r18-v1"},
        "launch_id": {"const": "cut4-r18-fixture-launch-v1"},
        "registry_digest": {"$ref": "#/$defs/Hex64"},
        "authority_digest": {"$ref": "#/$defs/Hex64"}
      }
    }
  },
  "oneOf": [{"$ref": "#/$defs/AckPolicy"}, {"$ref": "#/$defs/AckState"}, {"$ref": "#/$defs/InvalidFileFact"}, {"$ref": "#/$defs/PhaseIOAuthority"}]
}
```

The exact inhabited registries and preimages are:

```json
{
  "schema": "cut4.r18.literal_authority_registry.v1",
  "ack_truth_rows": [
    ["DISABLED","NO_LINK","NO_ACK","DISABLED",true], ["DISABLED","LINK","NO_ACK","DISABLED",true],
    ["DISABLED","NO_LINK","ACK","INVALID",false], ["DISABLED","LINK","ACK","INVALID",false],
    ["REQUIRED","NO_LINK","NO_ACK","REQUIRED_PENDING",false], ["REQUIRED","LINK","NO_ACK","REQUIRED_PENDING",false],
    ["REQUIRED","NO_LINK","ACK","INVALID",false], ["REQUIRED","LINK","ACK","REQUIRED_COMMITTED",true]
  ],
  "invalid_transition_rows": [
    ["ABSENT","ABSENT","NOOP",0], ["ABSENT","VALID_NEW","APPEND_ONE",1], ["PRESENT","SAME_VALID","NOOP",0],
    ["PRESENT","VALID_DISTINCT","APPEND_ONE",1], ["ANY","MALFORMED","REJECT",0], ["ANY","DELETE_OR_REWRITE","REJECT",0], ["ANY","GENERATION_NOT_PLUS_ONE","REJECT",0]
  ],
  "private_phaseio_rows": [
    ["PRIVATE",0,"recon/private_seed_v2","seed_manifest",".scratchpad/private/recon_seed_v2/seed_manifest.json","cut4.seed_manifest.v2","application/json"],
    ["PRIVATE",1,"recon/private_seed_v2","provider_receipts",".scratchpad/private/recon_seed_v2/provider_receipts.json","cut4.provider_receipts.v3","application/json"],
    ["PRIVATE",2,"recon/private_journal_v1","journal_state",".scratchpad/private/recon_publication_v2/journal_state.json","cut4.journal_state.v4","application/json"]
  ],
  "sc_phaseio_rows": [["SC",0,"recon_summary.md","text/markdown"],["SC",1,"design_context.md","text/markdown"],["SC",2,"attack_surface.md","text/markdown"],["SC",3,"state_variables.md","text/markdown"],["SC",4,"function_list.md","text/markdown"],["SC",5,"contract_inventory.md","text/markdown"],["SC",6,"template_recommendations.md","text/markdown"],["SC",7,"detected_patterns.md","text/markdown"],["SC",8,"setter_list.md","text/markdown"],["SC",9,"emit_list.md","text/markdown"],["SC",10,"build_status.md","text/markdown"],["SC",11,"recon_signal_transform_receipt.json","application/json"]],
  "l1_phaseio_rows": [["L1",0,"recon_summary.md","text/markdown"],["L1",1,"threat_model.md","text/markdown"],["L1",2,"subsystem_map.md","text/markdown"],["L1",3,"attack_surface.md","text/markdown"],["L1",4,"trust_boundaries.md","text/markdown"],["L1",5,"template_recommendations.md","text/markdown"],["L1",6,"scope_leftover.md","text/markdown"],["L1",7,"recon_signal_transform_receipt.json","application/json"]]
}
```

`ack_truth_digest=D("cut4.r18.ack_truth.v1",ack_truth_rows)`;
`policy_id` must match mode; `policy_digest=D("cut4.r18.ack_policy.v1",
policy without policy_digest)`. Link/ACK absence is exactly `EMPTY_SHA`;
AckState is the unique truth-table lookup and its BODY digest. Invalid bytes
reproduce size/SHA; `fact_id="iff_"+D("cut4.r18.invalid_file_fact_id.v1",
[identity,kind,sha,generation])`; fact digest is BODY. APPEND_ONE preserves all
prior fact/record bytes and performs one generation+1 CAS; other rows are exact.

`phaseio_registry_digest=D("cut4.r18.phaseio_registry.v1",literal registry)`.
Private rows expand directly. SC/L1 rows expand with
`work_unit=recon/canonical_merge`, `artifact_key=identity`,
`schema_id=cut4.canonical_output.v2`, plus the constants in the schema.
`authority_digest=D("cut4.r18.phaseio_authority.v1",expanded row without
authority_digest)`. No caller-created row is accepted. Public bytes must be
nonempty and match the authority's content type; exact registry membership,
physical-path containment, no alias, and complete 12/8 tuple equality are
required.

The complete semantic derivation denominator for these replacement types is
literal, not generated by prefix heuristics:

```json
{
  "schema": "cut4.r18.semantic_preimages.v2",
  "objects": [
    ["PredicateEvidence", ["schema","predicate_id","predicate_kind","provider_id","plan_digest","source_snapshot_digest","result","evidence_bytes_base64","evidence_byte_size","evidence_sha256","evidence_digest"],
      [["schema","CONST","cut4.r18.predicate_evidence.v1"],["predicate_id","REGISTRY","predicate registry row"],["predicate_kind","REGISTRY","predicate registry row"],["provider_id","REGISTRY","same predicate row"],["plan_digest","FK","validated ProviderPlan"],["source_snapshot_digest","FK","validated SourceSnapshot"],["result","EVALUATE","literal predicate over validated plan/snapshot"],["evidence_bytes_base64","INPUT","exact predicate evaluator bytes"],["evidence_byte_size","LEN","evidence bytes"],["evidence_sha256","SHA256","evidence bytes"],["evidence_digest","BODY","fields schema through evidence_sha256"]]],
    ["PayloadRecord", ["schema","payload_id","ordinal","content_type","bytes_base64","byte_size","sha256","payload_digest"],
      [["schema","CONST","cut4.r18.payload_record.v1"],["payload_id","ID","D(cut4.r18.payload_id.v1,[ordinal,content_type,sha256])"],["ordinal","TERMINAL_ORDER","gapless index"],["content_type","TERMINAL_PARSE","closed enum"],["bytes_base64","TERMINAL_PARSE","exact payload bytes"],["byte_size","LEN","payload bytes"],["sha256","SHA256","payload bytes"],["payload_digest","BODY","fields schema through sha256"]]],
    ["ProviderTerminal", ["schema","provider_id","invocation_state","exit_code","exhausted","payloads","evidence_bytes_base64","evidence_byte_size","evidence_sha256","terminal_digest"],
      [["schema","CONST","cut4.r18.provider_terminal.v1"],["provider_id","FK","validated fixed provider plan"],["invocation_state","EVENT_TABLE","exit/deadline/decode/approximation evidence"],["exit_code","EVENT","observed invocation exit"],["exhausted","EVENT","observed cursor terminal flag"],["payloads","ROSTER","validated PayloadRecord rows by ordinal"],["evidence_bytes_base64","EVENT","immutable invocation evidence"],["evidence_byte_size","LEN","evidence bytes"],["evidence_sha256","SHA256","evidence bytes"],["terminal_digest","BODY","fields schema through evidence_sha256"]]],
    ["ProviderReceipt", ["schema","private_plan_row_id","consumer_row_id","consumer_id","provider_id","provider_ordinal","applicability_predicate_id","applicability_result","selection_predicate_id","selection_result","invocation_digest","plan_digest","source_snapshot_digest","status","terminal_bytes_base64","terminal_byte_size","terminal_sha256","payload_count","payload_roster_digest","explicit_zero_proof_digest","debt_code","receipt_digest"],
      [["schema","CONST","cut4.r18.provider_receipt.v1"],["private_plan_row_id","FK","validated PrivatePlan row"],["consumer_row_id","FK","validated semantic consumer row"],["consumer_id","FK","same consumer row"],["provider_id","REGISTRY","fixed provider row"],["provider_ordinal","REGISTRY","fixed provider row"],["applicability_predicate_id","FK","validated applicability evidence"],["applicability_result","FK","same applicability evidence"],["selection_predicate_id","FK","validated selection evidence"],["selection_result","FK","same selection evidence"],["invocation_digest","FK_OR_EMPTY","validated invocation or EMPTY_SHA for no invocation"],["plan_digest","FK","validated ProviderPlan"],["source_snapshot_digest","FK","validated SourceSnapshot"],["status","STATUS_TABLE","two predicate rows plus ProviderTerminal"],["terminal_bytes_base64","CJ_BYTES","validated ProviderTerminal"],["terminal_byte_size","LEN","terminal bytes"],["terminal_sha256","SHA256","terminal bytes"],["payload_count","COUNT","ProviderTerminal.payloads"],["payload_roster_digest","ROSTER","ProviderTerminal.payloads by ordinal"],["explicit_zero_proof_digest","BODY_OR_EMPTY","exhausted zero evidence or EMPTY_SHA"],["debt_code","STATUS_TABLE","same unique status row"],["receipt_digest","BODY","fields schema through debt_code"]]],
    ["BakeFactRow", ["schema","provider_id","provider_ordinal","provider_receipt_digest","fact_ordinal","fact_kind","subject_id","object_id","raw_bytes_base64","raw_byte_size","raw_sha256","fact_id","fact_digest"],
      [["schema","CONST","cut4.r18.bake_fact.v1"],["provider_id","FK","validated ProviderReceipt"],["provider_ordinal","FK","same ProviderReceipt"],["provider_receipt_digest","FK","same ProviderReceipt"],["fact_ordinal","PAYLOAD_OR_DEBT_ORDER","gapless per provider"],["fact_kind","STATUS_PAYLOAD_TABLE","decoded payload or typed debt"],["subject_id","PAYLOAD_PARSE","nonempty"],["object_id","PAYLOAD_PARSE","nonempty"],["raw_bytes_base64","PAYLOAD_PARSE","exact bytes"],["raw_byte_size","LEN","raw bytes"],["raw_sha256","SHA256","raw bytes"],["fact_id","ID","D(cut4.r18.bake_fact_id.v1,fields provider_id through raw_sha256)"],["fact_digest","BODY","fields schema through fact_id"]]],
    ["BakeBinding", ["schema","private_plan_row_id","consumer_row_id","consumer_id","plan_digest","source_snapshot_digest","provider_receipts","provider_receipt_roster_bytes_base64","provider_receipt_roster_byte_size","provider_receipt_roster_sha256","provider_receipt_roster_digest","facts","fact_count","fact_roster_digest","binding_digest"],
      [["schema","CONST","cut4.r18.bake_binding.v1"],["private_plan_row_id","FK","all three ProviderReceipt Kp equal"],["consumer_row_id","FK","all three ProviderReceipt Kp equal"],["consumer_id","FK","all three ProviderReceipt Kp equal"],["plan_digest","FK","all three ProviderReceipt Kp equal"],["source_snapshot_digest","FK","all three ProviderReceipt Kp equal"],["provider_receipts","ROSTER","exact three fixed slots"],["provider_receipt_roster_bytes_base64","CJ_BYTES","provider_receipts"],["provider_receipt_roster_byte_size","LEN","roster bytes"],["provider_receipt_roster_sha256","SHA256","roster bytes"],["provider_receipt_roster_digest","ROSTER","provider_receipts fixed order"],["facts","ROSTER","status/payload-derived facts"],["fact_count","COUNT","facts"],["fact_roster_digest","ROSTER","facts by provider_ordinal,fact_ordinal"],["binding_digest","BODY","fields schema through fact_roster_digest"]]],
    ["AckPolicy", ["schema","policy_id","mode","truth_table_digest","policy_digest"],
      [["schema","CONST","cut4.r18.ack_policy.v1"],["policy_id","REGISTRY","policy/mode row"],["mode","REGISTRY","same row"],["truth_table_digest","ROSTER","literal ack_truth_rows"],["policy_digest","BODY","fields schema through truth_table_digest"]]],
    ["AckState", ["schema","policy_digest","publication_link_digest","ack_record_digest","state","completion_permitted","state_digest"],
      [["schema","CONST","cut4.r18.ack_state.v1"],["policy_digest","FK","validated AckPolicy"],["publication_link_digest","FK_OR_EMPTY","validated link or EMPTY_SHA"],["ack_record_digest","FK_OR_EMPTY","validated ACK or EMPTY_SHA"],["state","TABLE","unique ack_truth_rows result"],["completion_permitted","TABLE","same unique row"],["state_digest","BODY","fields schema through completion_permitted"]]],
    ["InvalidFileFact", ["schema","canonical_identity","fact_kind","observed_bytes_base64","observed_byte_size","observed_sha256","detected_generation","fact_id","fact_digest"],
      [["schema","CONST","cut4.r18.invalid_file_fact.v1"],["canonical_identity","PATH_OBSERVATION","contained canonical path"],["fact_kind","REGISTRY","closed invalid kind"],["observed_bytes_base64","PATH_OBSERVATION","exact bytes"],["observed_byte_size","LEN","observed bytes"],["observed_sha256","SHA256","observed bytes"],["detected_generation","JOURNAL","validated current generation"],["fact_id","ID","D(cut4.r18.invalid_file_fact_id.v1,[identity,kind,sha,generation])"],["fact_digest","BODY","fields schema through fact_id"]]],
    ["PhaseIOAuthority", ["schema","mode","ordinal","operation","work_unit","artifact_key","identity","owner","write_mode","schema_id","content_type","contract_id","launch_id","registry_digest","authority_digest"],
      [["schema","CONST","cut4.r18.phaseio_authority.v1"],["mode","REGISTRY","exact expanded authority row"],["ordinal","REGISTRY","same row"],["operation","REGISTRY","same row"],["work_unit","REGISTRY","same row"],["artifact_key","REGISTRY","same row"],["identity","REGISTRY","same row"],["owner","REGISTRY","same row"],["write_mode","REGISTRY","same row"],["schema_id","REGISTRY","same row"],["content_type","REGISTRY","same row"],["contract_id","REGISTRY","same row"],["launch_id","REGISTRY","same row"],["registry_digest","ROSTER","literal authority registry"],["authority_digest","BODY","fields schema through registry_digest"]]]
  ],
  "object_count": 10,
  "unregistered_or_multiply_registered_field_policy": "REJECT"
}
```

All schemas have `additionalProperties:false`. Every field of all ten
replacement objects appears exactly once in its literal field order and once
in its authority/preimage list. Reflection must equal these object rows plus
the authenticated unchanged inherited denominator. Missing, extra, ambiguous,
cyclic, or caller-overridden fields fail. This is an external contract root,
not a same-model expected registry.

## 4. Noncircular execution observations and fixture-derived mutations

### 4.1 Exit/event bytes precede observation receipts

A subprocess exits first and produces immutable `SubprocessExitEvent` bytes.
It contains the already-existing producer-start digest, never its future
completion digest. A separate observer occurrence starts afterward, reads the
exact event bytes and boundary path state, and writes `ObservationReceipt`.
The later RED/GREEN author receipt joins exact event/observer subject bytes and
its own already-existing producer-start digest. Its task completion is created
only after the receipt exists. No subject contains the completion digest that
will later commit that subject.

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "cut4.r18.execution_observation.schema.v1",
  "$defs": {
    "Hex64": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
    "Subject": {
      "type": "object", "additionalProperties": false,
      "required": ["identity", "bytes_base64", "byte_size", "sha256"],
      "properties": {"identity": {"type": "string", "minLength": 1}, "bytes_base64": {"type": "string"}, "byte_size": {"type": "integer", "minimum": 0}, "sha256": {"$ref": "#/$defs/Hex64"}}
    },
    "PathSnapshot": {
      "type": "object", "additionalProperties": false,
      "required": ["schema", "snapshot_ordinal", "parent_identity", "target_identity", "directory_entries", "target_membership_count", "target_present", "target_bytes_base64", "target_byte_size", "target_sha256", "snapshot_digest"],
      "properties": {
        "schema": {"const": "cut4.r18.path_snapshot.v1"},
        "snapshot_ordinal": {"type": "integer", "minimum": 1},
        "parent_identity": {"type": "string", "minLength": 1},
        "target_identity": {"const": "review_fixtures/cut4_transactional_recon_publication_r18_reference_model.py"},
        "directory_entries": {"type": "array", "uniqueItems": true, "items": {"type": "string"}},
        "target_membership_count": {"type": "integer", "minimum": 0, "maximum": 1},
        "target_present": {"type": "boolean"},
        "target_bytes_base64": {"type": "string"},
        "target_byte_size": {"type": "integer", "minimum": 0},
        "target_sha256": {"$ref": "#/$defs/Hex64"},
        "snapshot_digest": {"$ref": "#/$defs/Hex64"}
      }
    },
    "SubprocessExitEvent": {
      "type": "object", "additionalProperties": false,
      "required": ["schema", "phase", "producer_start_digest", "argv", "environment", "cwd", "stdin_bytes_base64", "stdin_byte_size", "stdin_sha256", "input_subjects", "start_monotonic_ns", "end_monotonic_ns", "duration_ns", "exit_code", "stdout_bytes_base64", "stdout_byte_size", "stdout_sha256", "stderr_bytes_base64", "stderr_byte_size", "stderr_sha256", "output_subjects", "event_digest"],
      "properties": {
        "schema": {"const": "cut4.r18.subprocess_exit_event.v1"},
        "phase": {"enum": ["RED_MODEL_ABSENT", "GREEN_DOMAIN"]},
        "producer_start_digest": {"$ref": "#/$defs/Hex64"},
        "argv": {"type": "array", "minItems": 3, "items": {"type": "string"}},
        "environment": {"type": "array", "items": {"type": "array", "prefixItems": [{"type": "string", "minLength": 1}, {"type": "string"}], "items": false, "minItems": 2, "maxItems": 2}},
        "cwd": {"type": "string", "minLength": 1},
        "stdin_bytes_base64": {"type": "string"},
        "stdin_byte_size": {"type": "integer", "minimum": 0},
        "stdin_sha256": {"$ref": "#/$defs/Hex64"},
        "input_subjects": {"type": "array", "minItems": 1, "items": {"$ref": "#/$defs/Subject"}},
        "start_monotonic_ns": {"type": "integer", "minimum": 0},
        "end_monotonic_ns": {"type": "integer", "minimum": 0},
        "duration_ns": {"type": "integer", "minimum": 0},
        "exit_code": {"type": "integer"},
        "stdout_bytes_base64": {"type": "string"},
        "stdout_byte_size": {"type": "integer", "minimum": 0},
        "stdout_sha256": {"$ref": "#/$defs/Hex64"},
        "stderr_bytes_base64": {"type": "string"},
        "stderr_byte_size": {"type": "integer", "minimum": 0},
        "stderr_sha256": {"$ref": "#/$defs/Hex64"},
        "output_subjects": {"type": "array", "items": {"$ref": "#/$defs/Subject"}},
        "event_digest": {"$ref": "#/$defs/Hex64"}
      }
    },
    "ObservationReceipt": {
      "type": "object", "additionalProperties": false,
      "required": ["schema", "phase", "observer_start_digest", "execution_event", "before_snapshot", "after_snapshot", "observation_scope", "receipt_digest"],
      "properties": {
        "schema": {"const": "cut4.r18.observation_receipt.v1"},
        "phase": {"enum": ["RED_MODEL_ABSENT", "GREEN_DOMAIN"]},
        "observer_start_digest": {"$ref": "#/$defs/Hex64"},
        "execution_event": {"$ref": "#/$defs/Subject"},
        "before_snapshot": {"$ref": "#/$defs/PathSnapshot"},
        "after_snapshot": {"$ref": "#/$defs/PathSnapshot"},
        "observation_scope": {"enum": ["BOUNDARY_SNAPSHOTS_AND_SUBPROCESS_ONLY"]},
        "receipt_digest": {"$ref": "#/$defs/Hex64"}
      }
    },
    "RedCase": {
      "type": "object", "additionalProperties": false,
      "required": ["schema", "case_id", "definition_digest", "test_sha256", "execution_event_digest", "observation_receipt_digest", "exception_type", "exception_bytes_base64", "exception_sha256", "observed_phase_code", "case_digest"],
      "properties": {
        "schema": {"const": "cut4.r18.red_case.v1"},
        "case_id": {"type": "string", "minLength": 1},
        "definition_digest": {"$ref": "#/$defs/Hex64"},
        "test_sha256": {"$ref": "#/$defs/Hex64"},
        "execution_event_digest": {"$ref": "#/$defs/Hex64"},
        "observation_receipt_digest": {"$ref": "#/$defs/Hex64"},
        "exception_type": {"enum": ["ImportError", "ModuleNotFoundError"]},
        "exception_bytes_base64": {"type": "string", "minLength": 4},
        "exception_sha256": {"$ref": "#/$defs/Hex64"},
        "observed_phase_code": {"const": "MODEL_ABSENT"},
        "case_digest": {"$ref": "#/$defs/Hex64"}
      }
    },
    "GreenCase": {
      "type": "object", "additionalProperties": false,
      "required": ["schema", "case_id", "definition_digest", "test_sha256", "model_sha256", "execution_event_digest", "observation_receipt_digest", "request_bytes_base64", "request_sha256", "result_bytes_base64", "result_sha256", "exception_type", "exception_bytes_base64", "exception_sha256", "expected_code", "observed_code", "positive_control", "case_digest"],
      "properties": {
        "schema": {"const": "cut4.r18.green_case.v1"},
        "case_id": {"type": "string", "minLength": 1},
        "definition_digest": {"$ref": "#/$defs/Hex64"},
        "test_sha256": {"$ref": "#/$defs/Hex64"},
        "model_sha256": {"$ref": "#/$defs/Hex64"},
        "execution_event_digest": {"$ref": "#/$defs/Hex64"},
        "observation_receipt_digest": {"$ref": "#/$defs/Hex64"},
        "request_bytes_base64": {"type": "string", "minLength": 4},
        "request_sha256": {"$ref": "#/$defs/Hex64"},
        "result_bytes_base64": {"type": "string"},
        "result_sha256": {"$ref": "#/$defs/Hex64"},
        "exception_type": {"enum": ["NONE", "ValidationError"]},
        "exception_bytes_base64": {"type": "string"},
        "exception_sha256": {"$ref": "#/$defs/Hex64"},
        "expected_code": {"type": "string", "pattern": "^R18_[A-Z0-9_]+$"},
        "observed_code": {"type": "string", "pattern": "^R18_[A-Z0-9_]+$"},
        "positive_control": {"const": "ACCEPTED"},
        "case_digest": {"$ref": "#/$defs/Hex64"}
      }
    },
    "AuthorReceipt": {
      "type": "object", "additionalProperties": false,
      "required": ["schema", "phase", "author_start_digest", "test_subject", "model_subject", "execution_event_subject", "observation_receipt_subject", "definition_count", "definition_roster_digest", "case_count", "case_roster_digest", "cases", "receipt_digest"],
      "properties": {
        "schema": {"const": "cut4.r18.execution_author_receipt.v1"},
        "phase": {"enum": ["RED", "GREEN"]},
        "author_start_digest": {"$ref": "#/$defs/Hex64"},
        "test_subject": {"$ref": "#/$defs/Subject"},
        "model_subject": {"$ref": "#/$defs/Subject"},
        "execution_event_subject": {"$ref": "#/$defs/Subject"},
        "observation_receipt_subject": {"$ref": "#/$defs/Subject"},
        "definition_count": {"const": 256},
        "definition_roster_digest": {"$ref": "#/$defs/Hex64"},
        "case_count": {"const": 256},
        "case_roster_digest": {"$ref": "#/$defs/Hex64"},
        "cases": {"type": "array", "minItems": 256, "maxItems": 256, "items": {"oneOf": [{"$ref": "#/$defs/RedCase"}, {"$ref": "#/$defs/GreenCase"}]}},
        "receipt_digest": {"$ref": "#/$defs/Hex64"}
      },
      "allOf": [
        {"if": {"properties": {"phase": {"const": "RED"}}}, "then": {"properties": {"cases": {"items": {"$ref": "#/$defs/RedCase"}}, "model_subject": {"properties": {"byte_size": {"const": 0}, "sha256": {"const": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}}}}}},
        {"if": {"properties": {"phase": {"const": "GREEN"}}}, "then": {"properties": {"cases": {"items": {"$ref": "#/$defs/GreenCase"}}, "model_subject": {"properties": {"byte_size": {"minimum": 1}}}}}}
      ]
    }
  },
  "oneOf": [{"$ref": "#/$defs/SubprocessExitEvent"}, {"$ref": "#/$defs/ObservationReceipt"}, {"$ref": "#/$defs/RedCase"}, {"$ref": "#/$defs/GreenCase"}, {"$ref": "#/$defs/AuthorReceipt"}]
}
```

```json
{
  "schema": "cut4.r18.phase_condition_registry.v1",
  "rows": [
    ["RED", "RED_MODEL_ABSENT", false, false, "NONZERO", ["ImportError", "ModuleNotFoundError"], "EMPTY_SHA", "RedCase", "MODEL_ABSENT"],
    ["GREEN", "GREEN_DOMAIN", true, true, "ZERO", ["NONE", "ValidationError"], "NONEMPTY_MODEL_SHA", "GreenCase", "R18_CASE_CODE"]
  ],
  "field_order": ["receipt_phase", "event_phase", "before_target_present", "after_target_present", "subprocess_exit_class", "case_exception_types", "model_sha_class", "case_schema", "observed_code_class"],
  "join_rule": "exactly one row must match; zero or multiple matches reject",
  "red_scope": "boundary snapshots plus subprocess ImportError only; no continuous-absence claim"
}
```

For every byte subject/field, strict base64 reproduces size and SHA. Event,
snapshot, case, observer, and author receipt digests use their schema tag and
exclude only their terminal digest. Environment rows sort by unique name;
`end-start=duration`; argv is exact with no shell interpolation; subject paths,
sizes, and SHAs must match fresh reads.

`target_membership_count` is rederived by exact NFC/case-sensitive equality of
the target basename against `directory_entries`. If false, membership=0,
target bytes are empty, size=0, SHA=`EMPTY_SHA`. If true, membership=1,
decoded bytes are nonempty and reproduce size/SHA. RED requires false/false,
nonzero subprocess exit, and an actual ImportError/ModuleNotFoundError per
case. GREEN requires true/true and the model subject SHA to equal both
snapshots. This claim is deliberately only boundary snapshots plus observed
subprocess behavior; it does not claim the path was continuously absent or
present between snapshots.

AuthorReceipt phase validation is disjoint. RED requires 256 `RedCase` rows,
`model_subject.identity` equal the fixed model path with empty bytes, size 0,
and `EMPTY_SHA`, and every case
MODEL_ABSENT. GREEN requires 256 `GreenCase` rows, a nonempty model subject,
unchanged test/definition hashes, and
`expected_code=observed_code="R18_"+uppercase(case_id with '.' -> '_')`.
Case order equals the frozen mutation order. Mixed phase rows, extra/missing/
duplicate cases, stale event/observer subjects, or self/future completion
digests fail.

The receipt validator parses the exact admitted red-test subject and extracts
its canonical `MutationDefinition` array; `definition_count` and roster digest
are rederived from those 256 full definitions. A digest-only caller roster is
not accepted. Every case definition digest must FK-equal the corresponding
extracted definition.

### 4.2 Closed typed selectors and mutation operations

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "cut4.r18.mutation_derivation.schema.v1",
  "$defs": {
    "Hex64": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
    "Selector": {
      "type": "object", "additionalProperties": false,
      "required": ["selector_kind", "source_subject_digest", "source_bytes_base64", "source_byte_size", "source_sha256", "selector_value", "resolved_byte_start", "resolved_byte_end", "resolved_bytes_sha256", "source_map_bytes_base64", "source_map_byte_size", "source_map_sha256", "selector_digest"],
      "properties": {
        "selector_kind": {"enum": ["BYTE_SPAN", "JSON_POINTER", "AST_NODE_ID", "REGISTRY_ROW_ID", "TRANSCRIPT_FIELD"]},
        "source_subject_digest": {"$ref": "#/$defs/Hex64"},
        "source_bytes_base64": {"type": "string"},
        "source_byte_size": {"type": "integer", "minimum": 0},
        "source_sha256": {"$ref": "#/$defs/Hex64"},
        "selector_value": {"type": "string", "minLength": 1},
        "resolved_byte_start": {"type": "integer", "minimum": 0},
        "resolved_byte_end": {"type": "integer", "minimum": 0},
        "resolved_bytes_sha256": {"$ref": "#/$defs/Hex64"},
        "source_map_bytes_base64": {"type": "string"},
        "source_map_byte_size": {"type": "integer", "minimum": 2},
        "source_map_sha256": {"$ref": "#/$defs/Hex64"},
        "selector_digest": {"$ref": "#/$defs/Hex64"}
      }
    },
    "MutationDefinition": {
      "type": "object", "additionalProperties": false,
      "required": ["schema", "case_id", "selector", "operation", "operand_bytes_base64", "operation_parameter", "mutated_bytes_base64", "mutated_byte_size", "mutated_sha256", "expected_stage", "green_expected_code", "definition_digest"],
      "properties": {
        "schema": {"const": "cut4.r18.mutation_definition.v1"},
        "case_id": {"type": "string", "pattern": "^[a-z0-9_]+(?:\\.[a-z0-9_]+)+$"},
        "selector": {"$ref": "#/$defs/Selector"},
        "operation": {"enum": ["REPLACE", "DELETE", "INSERT", "DUPLICATE", "REORDER", "RELABEL", "TRUNCATE", "CORRUPT"]},
        "operand_bytes_base64": {"type": "string"},
        "operation_parameter": {"type": "integer", "minimum": 0},
        "mutated_bytes_base64": {"type": "string"},
        "mutated_byte_size": {"type": "integer", "minimum": 0},
        "mutated_sha256": {"$ref": "#/$defs/Hex64"},
        "expected_stage": {"enum": ["ROUTE", "RECOGNITION", "BAKE_AUTHORITY", "JOURNAL", "PUBLICATION", "RED_EVIDENCE", "GREEN_EVIDENCE"]},
        "green_expected_code": {"type": "string", "pattern": "^R18_[A-Z0-9_]+$"},
        "definition_digest": {"$ref": "#/$defs/Hex64"}
      }
    }
  },
  "$ref": "#/$defs/MutationDefinition"
}
```

Selectors are resolved by these literal algorithms:

| Selector | Source-map bytes and exact unique resolution |
|---|---|
| `BYTE_SPAN` | source map is `CJ({"start":u,"end":v})`; selector value is `u:v`; require `0<=u<=v<=size` |
| `JSON_POINTER` | source map is the strict duplicate-free JSON parser's ordered `[pointer,start,end,value_sha]` table; RFC 6901 pointer must match exactly one row |
| `AST_NODE_ID` | source map is the frozen ecosystem adapter's ordered `[node_id,kind,start,end,raw_sha]` receipt over exact source SHA; node ID matches once |
| `REGISTRY_ROW_ID` | source map is ordered `[row_id,ordinal,start,end,row_sha]` from exact canonical registry bytes; ID/ordinal match once |
| `TRANSCRIPT_FIELD` | source map is the strict transcript JSON pointer table bound to exact transcript SHA; pointer matches once |

The map bytes reproduce their SHA; resolved source slice reproduces
`resolved_bytes_sha256`; zero/multiple/out-of-bounds/mismatched-map results
fail. Fixture construction derives and freezes selector instances from its
already-frozen subject bytes; callers cannot submit a convenient span.

Let `B` be source bytes, `[u,v)` the resolved span, `X` decoded operand, and
`N=operation_parameter`. Operations lower exactly as follows:

| Operation | Preconditions | Result bytes |
|---|---|---|
| `REPLACE` | `N=0` | `B[:u] || X || B[v:]` |
| `DELETE` | `X=empty`, `N=0` | `B[:u] || B[v:]` |
| `INSERT` | `u=v`, `len(X)>0`, `N=0` | `B[:u] || X || B[u:]` |
| `DUPLICATE` | `u<v`, `X=empty`, `N=1` | `B[:v] || B[u:v] || B[v:]` |
| `REORDER` | selected bytes are canonical JSON array, `X=CJ([from,to])`, both indexes valid, `N=0` | move row `from` to `to`, then CJ-reserialize selected array into `B[:u]...B[v:]` |
| `RELABEL` | selected bytes are one JSON string or ASCII identifier; `X` is nonempty valid replacement of same kind, `N=0` | exact span replacement |
| `TRUNCATE` | `X=empty`, `N=0` | `B[:u]` |
| `CORRUPT` | `u<v`, `len(X)=v-u`, `N=0` | `B[:u] || XOR(B[u:v],X) || B[v:]` |

The definition carries exact result bytes; size/SHA are recomputed. Selector
and definition BODY digests exclude only themselves. Operation labels that do
not meet their row are rejected even if final bytes happen to match.

### 4.3 Exact adversarial denominator

R18 reauthors all 192 authenticated predecessor identities as R18 definitions
and adds these 64 disjoint IDs, exactly 16 per repaired gate:

```json
{
  "schema": "cut4.r18.mutation_additions.v1",
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
      "execution.boundary_claim_overstated", "execution.selector_source_map_missing", "execution.selector_zero_match", "execution.selector_multiple_match",
      "execution.delete_with_operand", "execution.insert_nonzero_span", "execution.reorder_invalid_index", "execution.corrupt_mask_length_wrong"
    ]
  },
  "addition_count": 64,
  "total_count": 256
}
```

Every definition must use a nonvacuous selector/operation derived from frozen
fixture bytes, and one byte/result mutation must independently prove its
expected GREEN rejection code. RED observes only MODEL_ABSENT; exact 256 R18
domain codes are checked only after the model subject admission.

## 5. Exact dependency DAG and review gate

The future pure model publishes typed dependency metadata from actual
dataclass fields, constructor parameters/preimages, validators, serializers,
and literal semantic preimages. Its type projection must byte-equal this root.
An edge points from dependency to consumer.

```json
{
  "schema": "cut4.r18.constructor_dag.v1",
  "nodes": [
    "FrozenSpecs", "SourceFileBytes", "SourceSnapshot", "PhaseIOAuthority", "PredicateEvidence", "ProviderPlan", "PayloadRecord", "ProviderTerminal", "ProviderReceipt", "BakeFactRow", "BakeBinding",
    "ParserAReceipt", "ParserBReceipt", "VerifierReceipt", "NegativeProofReceipt", "AckPolicy", "InvalidFileFact", "JournalState", "PriorEnvelope", "BaseRequestIntent", "AttemptAllocation", "InvocationRecord",
    "ProviderPrivateV4", "NormalizedSemanticRow", "DiffRow", "TerminalEnvelope", "TerminalJournalRecord", "PublicOutputBytes", "CommittedPublicationReceipt", "PublicationLink", "PublicationAckJournalRecord", "AckState",
    "M4", "R4", "CompletionReceipt", "MutationDefinition", "SubprocessExitEvent", "ObservationReceipt", "ExecutionAuthorReceipt"
  ],
  "edges": [
    ["SourceFileBytes","SourceSnapshot"], ["PhaseIOAuthority","ProviderPlan"], ["SourceSnapshot","ProviderPlan"], ["AckPolicy","ProviderPlan"],
    ["PredicateEvidence","ProviderReceipt"], ["ProviderPlan","ProviderReceipt"], ["SourceSnapshot","ProviderReceipt"], ["PayloadRecord","ProviderTerminal"], ["InvocationRecord","ProviderTerminal"], ["ProviderTerminal","ProviderReceipt"],
    ["ProviderReceipt","BakeFactRow"], ["ProviderReceipt","BakeBinding"], ["BakeFactRow","BakeBinding"],
    ["FrozenSpecs","ParserAReceipt"], ["SourceSnapshot","ParserAReceipt"], ["BakeBinding","ParserAReceipt"],
    ["FrozenSpecs","ParserBReceipt"], ["SourceSnapshot","ParserBReceipt"], ["BakeBinding","ParserBReceipt"],
    ["FrozenSpecs","VerifierReceipt"], ["SourceSnapshot","VerifierReceipt"], ["BakeBinding","VerifierReceipt"], ["ParserAReceipt","VerifierReceipt"], ["ParserBReceipt","VerifierReceipt"],
    ["ParserAReceipt","NegativeProofReceipt"], ["ParserBReceipt","NegativeProofReceipt"], ["VerifierReceipt","NegativeProofReceipt"],
    ["InvalidFileFact","JournalState"], ["JournalState","PriorEnvelope"], ["SourceSnapshot","BaseRequestIntent"], ["PriorEnvelope","BaseRequestIntent"],
    ["BaseRequestIntent","AttemptAllocation"], ["AttemptAllocation","InvocationRecord"], ["ProviderPlan","InvocationRecord"], ["InvocationRecord","PayloadRecord"],
    ["PayloadRecord","ProviderPrivateV4"], ["ProviderReceipt","ProviderPrivateV4"], ["PayloadRecord","NormalizedSemanticRow"], ["VerifierReceipt","NormalizedSemanticRow"],
    ["ProviderPrivateV4","DiffRow"], ["NormalizedSemanticRow","DiffRow"], ["DiffRow","TerminalEnvelope"], ["InvocationRecord","TerminalEnvelope"],
    ["TerminalEnvelope","TerminalJournalRecord"], ["PhaseIOAuthority","PublicOutputBytes"], ["TerminalJournalRecord","CommittedPublicationReceipt"], ["PublicOutputBytes","CommittedPublicationReceipt"],
    ["TerminalJournalRecord","PublicationLink"], ["CommittedPublicationReceipt","PublicationLink"], ["PublicationLink","PublicationAckJournalRecord"], ["AckPolicy","PublicationAckJournalRecord"],
    ["AckPolicy","AckState"], ["PublicationLink","AckState"], ["PublicationAckJournalRecord","AckState"],
    ["ProviderPrivateV4","M4"], ["NormalizedSemanticRow","M4"], ["DiffRow","M4"], ["PublicOutputBytes","M4"], ["AckState","M4"], ["M4","R4"],
    ["R4","CompletionReceipt"], ["PublicationLink","CompletionReceipt"], ["CommittedPublicationReceipt","CompletionReceipt"], ["AckState","CompletionReceipt"],
    ["FrozenSpecs","MutationDefinition"], ["SubprocessExitEvent","ObservationReceipt"], ["MutationDefinition","ExecutionAuthorReceipt"], ["SubprocessExitEvent","ExecutionAuthorReceipt"], ["ObservationReceipt","ExecutionAuthorReceipt"], ["NegativeProofReceipt","ExecutionAuthorReceipt"]
  ]
}
```

The exact projection has 39 unique nodes and 70 unique edges; Kahn remainder
is zero. It explicitly includes `ProviderReceipt -> BakeBinding`, typed
provider-terminal/payload dependencies, negative proof, ACK state, and
noncircular execution evidence. `SourceSnapshot` is constructed from source
bytes/configuration before provider execution; it does not contain
`BakeBinding`. Provider receipts bind the prior snapshot, while parser inputs
consume snapshot and BAKE separately, avoiding a cycle.

The actual terminal/publication order remains
`BaseRequestIntent -> AttemptAllocation -> InvocationRecord ->
ProviderTerminal -> TerminalEnvelope -> TerminalJournalRecord ->
CommittedPublicationReceipt -> PublicationLink -> optional
PublicationAckJournalRecord -> AckState`. Every journal CAS appends exactly one
validated record at generation+1; terminal/link validation never requires a
future ACK. M4/R4/completion validate every child and committed receipt rather
than aggregate hashes alone.

Independent architecture review must authenticate this contract/receipt and
the exact R17 REPAIR review; strictly parse all JSON roots and Draft 2020-12
schemas; recompute every canonical root/preimage; verify 32 literal vector
rows, hex/tuple codec/derived size/SHA/digests, ecosystem guard totality, and
matcher opcodes; validate the closed execution/negative proof/BAKE/authority
schemas; rederive the 15 lifecycle rows, 29 dependency edges, expanded route
76/119, constructor 39/70, and zero Kahn remainders; check exact ProviderReceipt
three-slot order, ten complete semantic-preimage object rows, ACK 8, invalid transition 7, PhaseIO
3/12/8, mutation 192+64=256, unique identities, local references, future path
absence, LF/no BOM/fences, and Part-0 ceiling. It returns ACCEPT or REPAIR.
ACCEPT permits only creation of the post-review admission; REPAIR permits no
route record.

## 6. Non-goals and claim ceiling

R18 does not prove cryptographic identity, signatures, human independence,
non-collusion, trusted time, continuous path absence/presence, hidden-file
absence outside observed paths, parser/model correctness before future runs,
provider availability, target protocol security, live PhaseIO/ArtifactLedger
installation, target-host atomicity where unavailable, audit completion,
release, readiness, or a protocol answer. No review, admission, parser,
verifier, fixture, test, transcript, model, provider, production path,
ArtifactLedger row, or G3 result is created here. Part-0 and all downstream
authority remain false.
