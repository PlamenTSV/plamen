# Cut-4 transactional recon publication R17 preimplementation contract

Date: 2026-08-10
Status: Part-0 architecture-only repair awaiting independent review
Supersedes: only the four rejected R16 gates
Authority: all orchestration-route, parser, verifier, fixture, model,
implementation, production, provider, ArtifactLedger, G3, audit, commit, push,
install, cutover, release, readiness, and protocol-answer authority is false

## 0. Boundary, predecessor, and inherited contract

This turn creates only this contract and its author receipt. It does not create
or edit a parser, verifier, fixture, test, transcript, reference model,
provider, production path, route record, ArtifactLedger row, or G3 pin.

The complete R16 independent review was authenticated and read end to end:

| Artifact | Bytes | SHA-256 |
|---|---:|---|
| `review_fixtures/cut4_transactional_recon_publication_r16_architecture_independent_review_20260810.md` | 21,055 | `69e2f4aa092839cd2858811db33d0e39cb90d0882c9c8c143441345315c9ff56` |
| `architecture/cut4-transactional-recon-publication-r16-preimplementation-contract.md` | 55,906 | `f2a833d0b671f0b990999b9cbde5036ba022a1fb8da70cb4bca90ded4eadc781` |
| `review_fixtures/cut4_transactional_recon_publication_r16_contract_author_receipt_20260810.md` | 6,166 | `022e66ae3f6aa5f2f15c76cb7986f7786bf229d266f07e444fb1ae6fd1fd811d` |

R17 inherits the accepted R1-R16 provider denominator
`source_graph/build_probe/daml_source_graph`, fixed private slots, immutable
MODEL inputs, sole `recon/canonical_merge` public owner, compatibility
projection, legacy non-adoption, stable registered successor operation,
transaction/journal ordering, nonempty exhausted c3, complete SC/L1 canonical
tuples, MODEL shards, dependency units, project-root containment, and
typed-zero distinctions. The four R16 findings are the complete repair
boundary. Where R17 supplies a replacement schema or rule, R17 controls; all
other inherited clauses remain unchanged.

`H(x)` means ordinary SHA-256 bytes. `U(s)` means strict UTF-8 encoding of NFC
string `s`. `CJ(x)` means RFC 8785 canonical JSON after duplicate-key,
non-finite, surrogate, and non-NFC string rejection. `B64(s)` is strict RFC
4648 base64 with required padding. `D(tag,x) = H(U(tag || "\\0") || CJ(x))`.
Arrays are ordered unless a formula explicitly sorts them. No hash below is a
signature or proof of an independent principal.

## 1. Versioned identities and create-new route

### 1.1 Exact future path registry

Only the first two paths exist in this authoring turn. Every other identity is
a future single-writer subject. Route records use one immutable file per
record, opened with `O_CREAT|O_EXCL`; an existing file is parsed and required
byte-identical, never replaced.

```json
{
  "schema": "cut4.r17.path_registry.v1",
  "architecture_contract": "architecture/cut4-transactional-recon-publication-r17-preimplementation-contract.md",
  "architecture_author_receipt": "review_fixtures/cut4_transactional_recon_publication_r17_contract_author_receipt_20260810.md",
  "architecture_review": "review_fixtures/cut4_transactional_recon_publication_r17_architecture_independent_review_20260810.md",
  "route_root": "review_fixtures/cut4_transactional_recon_publication_r17_route",
  "root_plan": "review_fixtures/cut4_transactional_recon_publication_r17_route/000_root_plan.json",
  "parser_a": "review_fixtures/cut4_transactional_recon_publication_r17_parser_a.py",
  "parser_b": "review_fixtures/cut4_transactional_recon_publication_r17_parser_b.py",
  "verifier": "review_fixtures/cut4_transactional_recon_publication_r17_independent_verifier.py",
  "red_test": "tests/test_cut4_transactional_recon_publication_r17_preimplementation.py",
  "red_transcript": "review_fixtures/cut4_transactional_recon_publication_r17_red_transcript_20260810.json",
  "red_author_receipt": "review_fixtures/cut4_transactional_recon_publication_r17_red_author_receipt_20260810.json",
  "negative_proof_receipt": "review_fixtures/cut4_transactional_recon_publication_r17_negative_proof_receipt_20260810.json",
  "red_review": "review_fixtures/cut4_transactional_recon_publication_r17_red_independent_review_20260810.md",
  "model": "review_fixtures/cut4_transactional_recon_publication_r17_reference_model.py",
  "green_transcript": "review_fixtures/cut4_transactional_recon_publication_r17_green_transcript_20260810.json",
  "green_author_receipt": "review_fixtures/cut4_transactional_recon_publication_r17_green_author_receipt_20260810.json",
  "green_review": "review_fixtures/cut4_transactional_recon_publication_r17_green_independent_review_20260810.md"
}
```

### 1.2 Closed occurrence records

An orchestration task identity is its actual slash-qualified runtime handle,
not an invented `task_*` alias. A task occurrence is a specific input/result
pair under that handle. The root exports the actual orchestration input event
and result event bytes into create-new observations. Export may happen after
the observed event, so it proves only integrity of the exported observation;
it is not a trusted clock. Prospective dominance is instead structural: a
review start record names and validates the already committed author
completion record as an immediate predecessor. No review task can be launched
by this route until that join exists.

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "cut4.r17.orchestration_records.schema.v1",
  "$defs": {
    "Hex64": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
    "B64": {"type": "string", "pattern": "^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$"},
    "TaskHandle": {"type": "string", "pattern": "^/root(?:/[a-z0-9_]+)+$"},
    "Role": {"enum": ["ARCH_AUTHOR", "ARCH_REVIEWER", "PARSER_A", "PARSER_B", "VERIFIER", "RED_AUTHOR", "RED_REVIEWER", "MODEL_IMPLEMENTER", "GREEN_REVIEWER", "ROOT_OBSERVER"]},
    "ByteObservation": {
      "type": "object", "additionalProperties": false,
      "required": ["media_type", "bytes_base64", "byte_size", "sha256"],
      "properties": {
        "media_type": {"enum": ["application/json", "text/markdown; charset=utf-8", "text/plain; charset=utf-8", "application/octet-stream"]},
        "bytes_base64": {"$ref": "#/$defs/B64"},
        "byte_size": {"type": "integer", "minimum": 0},
        "sha256": {"$ref": "#/$defs/Hex64"}
      }
    },
    "OutputObservation": {
      "type": "object", "additionalProperties": false,
      "required": ["identity", "bytes", "path_observation_ordinal"],
      "properties": {
        "identity": {"type": "string", "minLength": 1},
        "bytes": {"$ref": "#/$defs/ByteObservation"},
        "path_observation_ordinal": {"type": "integer", "minimum": 1}
      }
    },
    "RootPlanRecord": {
      "type": "object", "additionalProperties": false,
      "required": ["schema", "route_id", "root_observer_handle", "route_plan_bytes", "architecture_contract", "architecture_author_receipt", "r16_review_identity", "r16_review_sha256", "author_start_digest", "author_completion_digest", "root_plan_digest"],
      "properties": {
        "schema": {"const": "cut4.r17.root_plan.v1"},
        "route_id": {"type": "string", "pattern": "^cut4-r17-[a-z0-9_-]{8,128}$"},
        "root_observer_handle": {"const": "/root"},
        "route_plan_bytes": {"$ref": "#/$defs/ByteObservation"},
        "architecture_contract": {"$ref": "#/$defs/OutputObservation"},
        "architecture_author_receipt": {"$ref": "#/$defs/OutputObservation"},
        "r16_review_identity": {"const": "review_fixtures/cut4_transactional_recon_publication_r16_architecture_independent_review_20260810.md"},
        "r16_review_sha256": {"const": "69e2f4aa092839cd2858811db33d0e39cb90d0882c9c8c143441345315c9ff56"},
        "author_start_digest": {"$ref": "#/$defs/Hex64"},
        "author_completion_digest": {"$ref": "#/$defs/Hex64"},
        "root_plan_digest": {"$ref": "#/$defs/Hex64"}
      }
    },
    "TaskStartRecord": {
      "type": "object", "additionalProperties": false,
      "required": ["schema", "route_id", "route_ordinal", "task_handle", "role", "root_observer_handle", "root_plan_digest", "assignment_bytes", "input_event_bytes", "input_payload_bytes", "predecessor_completion_digests", "start_record_digest"],
      "properties": {
        "schema": {"const": "cut4.r17.task_start.v1"},
        "route_id": {"type": "string", "pattern": "^cut4-r17-[a-z0-9_-]{8,128}$"},
        "route_ordinal": {"type": "integer", "minimum": 1, "maximum": 10},
        "task_handle": {"$ref": "#/$defs/TaskHandle"},
        "role": {"$ref": "#/$defs/Role"},
        "root_observer_handle": {"const": "/root"},
        "root_plan_digest": {"$ref": "#/$defs/Hex64"},
        "assignment_bytes": {"$ref": "#/$defs/ByteObservation"},
        "input_event_bytes": {"$ref": "#/$defs/ByteObservation"},
        "input_payload_bytes": {"$ref": "#/$defs/ByteObservation"},
        "predecessor_completion_digests": {"type": "array", "uniqueItems": true, "items": {"$ref": "#/$defs/Hex64"}},
        "start_record_digest": {"$ref": "#/$defs/Hex64"}
      }
    },
    "TaskCompletionRecord": {
      "type": "object", "additionalProperties": false,
      "required": ["schema", "route_id", "route_ordinal", "task_handle", "role", "start_record_digest", "result_event_bytes", "result_payload_bytes", "outputs", "completion_record_digest"],
      "properties": {
        "schema": {"const": "cut4.r17.task_completion.v1"},
        "route_id": {"type": "string", "minLength": 1},
        "route_ordinal": {"type": "integer", "minimum": 1, "maximum": 10},
        "task_handle": {"$ref": "#/$defs/TaskHandle"},
        "role": {"$ref": "#/$defs/Role"},
        "start_record_digest": {"$ref": "#/$defs/Hex64"},
        "result_event_bytes": {"$ref": "#/$defs/ByteObservation"},
        "result_payload_bytes": {"$ref": "#/$defs/ByteObservation"},
        "outputs": {"type": "array", "minItems": 1, "uniqueItems": true, "items": {"$ref": "#/$defs/OutputObservation"}},
        "completion_record_digest": {"$ref": "#/$defs/Hex64"}
      }
    },
    "ReviewDominanceRecord": {
      "type": "object", "additionalProperties": false,
      "required": ["schema", "route_id", "review_ordinal", "root_plan_digest", "subject_completion_digest", "review_start_digest", "review_completion_digest", "subject_task_handle", "review_task_handle", "decision", "distinct_task_handles", "dominance_digest"],
      "properties": {
        "schema": {"const": "cut4.r17.review_dominance.v1"},
        "route_id": {"type": "string", "minLength": 1},
        "review_ordinal": {"enum": [2, 8, 10]},
        "root_plan_digest": {"$ref": "#/$defs/Hex64"},
        "subject_completion_digest": {"$ref": "#/$defs/Hex64"},
        "review_start_digest": {"$ref": "#/$defs/Hex64"},
        "review_completion_digest": {"$ref": "#/$defs/Hex64"},
        "subject_task_handle": {"$ref": "#/$defs/TaskHandle"},
        "review_task_handle": {"$ref": "#/$defs/TaskHandle"},
        "decision": {"enum": ["ACCEPT", "REPAIR"]},
        "distinct_task_handles": {"const": true},
        "dominance_digest": {"$ref": "#/$defs/Hex64"}
      }
    }
  },
  "oneOf": [
    {"$ref": "#/$defs/RootPlanRecord"},
    {"$ref": "#/$defs/TaskStartRecord"},
    {"$ref": "#/$defs/TaskCompletionRecord"},
    {"$ref": "#/$defs/ReviewDominanceRecord"}
  ]
}
```

For every `ByteObservation`, strict decoding must satisfy both size and SHA.
Outputs sort by `(identity,path_observation_ordinal,bytes.sha256)` and have no
duplicate identity. Formulas are exact:

```text
start_record_digest = D("cut4.r17.task_start.v1", start without start_record_digest)
completion_record_digest = D("cut4.r17.task_completion.v1", completion without completion_record_digest)
dominance_digest = D("cut4.r17.review_dominance.v1", dominance without dominance_digest)
root_plan_digest = D("cut4.r17.root_plan.v1", root plan without root_plan_digest)
```

The completion must reproduce the start's route, ordinal, handle, and role.
Ordinal 1 uses
`root_plan_digest=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`
(`H(empty)`) because its observed task occurrence
precedes the plan. Ordinals 2 through 10 require exact root-plan equality. The
root plan validates the exact route-plan CJ bytes, observed contract/receipt
bytes, and ordinal-1 start/completion before its digest is derived.
The root must prove `input_event_bytes` contains the exact assigned recipient
and payload and `result_event_bytes` contains the result from that same
recipient; output observations are fresh path reads performed after the result
event. The author receipt's task handle is only a claimed join key until these
root observations validate it. Architecture review requires exact output
identities for this contract and receipt. Its start predecessor is the author
completion digest; its completion output is the architecture review; the
dominance row requires different nonempty actual handles and ACCEPT. This is
auditable hash integrity and label separation only. It is not cryptographic
identity, non-collusion, wall-clock chronology, or human independence.

### 1.3 Exact prospective route and joins

The root plan freezes roles, subjects, predecessor ordinals, exact contract and
receipt observations, and the exported ordinal-1 author occurrence. Actual
future handles are learned from actual start events and cannot be predicted by
the plan. Except for the already-running R17 architecture-author occurrence,
every start record is created immediately from the launch event before that
task receives any follow-up. Each completion is created only after exact
result/output observation. Record names are
`{ordinal:03}_{role-lower}_{start|completion}.json`; dominance names are
`gate_{review-ordinal:03}_{role-lower}.json`.

```json
{
  "schema": "cut4.r17.route_plan.v1",
  "rows": [
    [1, "ARCH_AUTHOR", ["architecture_contract", "architecture_author_receipt"], []],
    [2, "ARCH_REVIEWER", ["architecture_review"], [1]],
    [3, "PARSER_A", ["parser_a"], [2]],
    [4, "PARSER_B", ["parser_b"], [2]],
    [5, "VERIFIER", ["verifier"], [2]],
    [6, "RED_AUTHOR", ["red_test", "red_transcript", "red_author_receipt"], [3, 4, 5]],
    [7, "VERIFIER", ["negative_proof_receipt"], [5, 6]],
    [8, "RED_REVIEWER", ["red_review"], [6, 7]],
    [9, "MODEL_IMPLEMENTER", ["model", "green_transcript", "green_author_receipt"], [8]],
    [10, "GREEN_REVIEWER", ["green_review"], [9]]
  ]
}
```

The ten rows contain exactly ten starts, ten completions, nine role principals,
and ten task occurrences. The verifier owns two distinct occurrences: package
construction at ordinal 5 and negative-proof execution at ordinal 7. They may
reuse the same verifier task handle only through a new observed input/result
occurrence; their start/completion digests differ. The predecessor lists
contain exactly 13 route edges. The complete record DAG has exactly 24 nodes:
one root plan, ten starts, ten completions, and three dominance records for
architecture, RED, and GREEN review. It has exactly 46 edges: ten
start-to-completion, 13 predecessor-completion-to-start, one author-completion
to root-plan, nine root-plan-to-post-author-start, nine review
subject/start/completion-to-dominance, three architecture-dominance-to-parser
starts, and one RED-dominance-to-model-start. Kahn remainder must be zero.
`ARCH_AUTHOR != ARCH_REVIEWER`,
`RED_AUTHOR != RED_REVIEWER != MODEL_IMPLEMENTER != GREEN_REVIEWER`, and no
reviewer may equal the task it reviews. Exact task occurrence IDs, rather than
role labels, are compared.

## 2. Frozen recognition authority

### 2.1 Freeze event and byte identities

The following five canonical JSON roots, in this contract, are the only
recognition authority: `lexical_semantics`, `parser_a_algorithm`,
`parser_b_dfa`, `verifier_algorithm`, and `conformance_vectors`. Their exact
bytes are `CJ(root)` and their identities are
`D("cut4.r17.frozen_spec.v1", root)`. The author receipt records the five byte
sizes and identities. Architecture ACCEPT freezes those values before three
different task occurrences are allocated to parser A, parser B, and verifier.
None of those tasks may edit, extend, or normalize a root. Parser packages
bind all five identities and their own source bytes.

```json
{
  "schema": "cut4.r17.lexical_semantics.v1",
  "byte_classes_in_priority_order": [
    ["EOF", []],
    ["UTF8_INVALID", []],
    ["LF", [10]], ["CR", [13]], ["WS", [9, 32]],
    ["ALPHA", [[65, 90], [95, 95], [97, 122]]],
    ["DIGIT", [[48, 57]]],
    ["DQ", [34]], ["SQ", [39]], ["BT", [96]], ["BS", [92]],
    ["SLASH", [47]], ["STAR", [42]], ["DASH", [45]], ["DOT", [46]],
    ["LP", [40]], ["RP", [41]], ["COMMA", [44]], ["COLON", [58]],
    ["SEMI", [59]], ["LBRACE", [123]], ["RBRACE", [125]],
    ["LBRACK", [91]], ["RBRACK", [93]], ["OTHER", [[0, 255]]]
  ],
  "class_rule": "strict UTF-8 span map is built first; a byte in an invalid span is UTF8_INVALID; otherwise first displayed byte membership wins; EOF is a sentinel after the final byte; OTHER receives every unclaimed byte",
  "token_kinds": ["WS", "IDENT", "NUMBER", "STRING_DQ", "STRING_SQ", "STRING_BT", "LINE_COMMENT", "BLOCK_COMMENT", "PUNCT", "INVALID_UTF8", "UNTERMINATED_STRING", "UNTERMINATED_COMMENT", "UNKNOWN"],
  "punctuation": [["SLASH", "/"], ["STAR", "*"], ["DASH", "-"], ["DOT", "."], ["LP", "("], ["RP", ")"], ["COMMA", ","], ["COLON", ":"], ["SEMI", ";"], ["LBRACE", "{"], ["RBRACE", "}"], ["LBRACK", "["], ["RBRACK", "]"]],
  "ecosystem_comment_pairs": [["aptos", "//", "/*", "*/"], ["daml", "--", "{-", "-}"], ["evm", "//", "/*", "*/"], ["go", "//", "/*", "*/"], ["rust", "//", "/*", "*/"], ["solana", "//", "/*", "*/"], ["soroban", "//", "/*", "*/"], ["sui", "//", "/*", "*/"]],
  "declaration_keywords": [["aptos", ["fun", "module", "struct"]], ["daml", ["data", "module", "template"]], ["evm", ["contract", "function", "interface", "library"]], ["go", ["func", "type"]], ["rust", ["enum", "fn", "impl", "mod", "struct", "trait"]], ["solana", ["enum", "fn", "impl", "mod", "struct", "trait"]], ["soroban", ["enum", "fn", "impl", "mod", "struct", "trait"]], ["sui", ["fun", "module", "struct"]]],
  "import_keywords": [["aptos", ["friend", "use"]], ["daml", ["import"]], ["evm", ["import", "using"]], ["go", ["import"]], ["rust", ["extern", "use"]], ["solana", ["extern", "use"]], ["soroban", ["extern", "use"]], ["sui", ["friend", "use"]]],
  "path_context_identifiers": ["file", "filename", "include", "input", "manifest", "output", "path", "read", "source", "template", "write"],
  "content_context_identifiers": ["agent", "instruction", "methodology", "prompt", "role", "system", "tool"],
  "semantic_classes": ["DECLARATION", "IMPORT", "MEMBER_CALL", "CALL", "PATH_REFERENCE", "CONTENT_INSTRUCTION", "GRAPH_EDGE", "PROBE_EDGE", "NONREFERENCE", "MALFORMED_DEBT", "UNRESOLVED_DEBT"],
  "normalization": {
    "source_bytes": "preserved byte-for-byte",
    "utf8": "strict RFC 3629; reject overlong, surrogate, greater-than-U+10FFFF, bad continuation, and truncated sequence",
    "text": "decode strict UTF-8 then NFC; raw spans remain source-byte offsets",
    "identifier": "ASCII exact; keyword comparisons are case-sensitive",
    "path": "replace backslash with slash, reject absolute/drive/NUL/dot-dot, remove dot segments, NFC each segment, retain case",
    "line_column": "one-based Unicode scalar count after strict UTF-8; LF advances line; CRLF is one newline; bare CR is one newline",
    "empty": "zero source bytes produce one zero-width EOF proof row and no semantic candidate"
  },
  "production_priority": ["MALFORMED", "COMMENT", "STRING", "IMPORT", "DECLARATION", "MEMBER_CALL", "CALL", "PATH_REFERENCE", "CONTENT_INSTRUCTION", "GRAPH_EDGE", "PROBE_EDGE", "NONREFERENCE"],
  "production_shapes": [
    ["IMPORT", "IMPORT_KEYWORD (STRING|IDENT) until SEMI|LF|EOF"],
    ["DECLARATION", "DECLARATION_KEYWORD IDENT"],
    ["MEMBER_CALL", "IDENT DOT IDENT LP"],
    ["CALL", "IDENT LP"],
    ["PATH_REFERENCE", "STRING whose nearest preceding non-WS token in the same balanced call or assignment is PATH_CONTEXT_IDENTIFIER"],
    ["CONTENT_INSTRUCTION", "STRING or COMMENT whose nearest preceding non-WS token in the same balanced call or assignment is CONTENT_CONTEXT_IDENTIFIER"],
    ["GRAPH_EDGE", "one authenticated BAKE graph fact row"],
    ["PROBE_EDGE", "one authenticated BAKE probe fact row"],
    ["NONREFERENCE", "every token/candidate not matched above"]
  ],
  "error_rows": [["E_UTF8", "INVALID_UTF8"], ["E_STRING_EOF", "UNTERMINATED_STRING"], ["E_COMMENT_EOF", "UNTERMINATED_COMMENT"], ["E_ESCAPE_EOF", "UNTERMINATED_STRING"], ["E_UNKNOWN", "UNKNOWN"], ["E_SPAN", "MALFORMED_DEBT"], ["E_COVERAGE", "MALFORMED_DEBT"]]
}
```

Parser A uses the following frozen maximal-munch recursive procedure. Each
instruction is an opcode with literal operands; packages translate it without
altering order.

```json
{
  "schema": "cut4.r17.parser_a_algorithm.v1",
  "opcodes": [
    [1, "VALIDATE_SOURCE_VECTOR", "reject duplicate identity/ordinal; verify bytes/size/SHA; canonical sort"],
    [2, "STRICT_UTF8_MAP", "build byte-start/byte-end/scalar table; if any invalid sequence exists emit one INVALID_UTF8 token spanning the complete source, emit one MALFORMED_DEBT semantic row, then skip opcodes 3 through 8"],
    [3, "SCAN_LEFT_TO_RIGHT", "at offset i choose first lexical production in priority COMMENT,STRING,WS,IDENT,NUMBER,PUNCT,UNKNOWN; consume maximal accepted span; never consume zero bytes"],
    [4, "COMMENT", "ecosystem line opener consumes through but excluding LF; block opener consumes through first exact closer; EOF without closer emits UNTERMINATED_COMMENT"],
    [5, "STRING", "matching quote ends; BS escapes exactly next UTF-8 scalar including quote/BS; LF is allowed only for BT; EOF or forbidden LF emits UNTERMINATED_STRING"],
    [6, "IDENT", "ALPHA then zero-or-more ALPHA|DIGIT"],
    [7, "NUMBER", "one-or-more DIGIT"],
    [8, "PUNCT", "one classified punctuation byte"],
    [9, "PARTITION_CHECK", "sorted token spans start at 0, touch without gap/overlap, end at byte_size; empty input has only zero-width EOF proof"],
    [10, "MATCH_PRODUCTIONS", "walk non-WS tokens left-to-right; apply semantic production priority and exact balanced-bracket stack; emit one classification per candidate"],
    [11, "JOIN_BAKE", "append authenticated graph/probe rows in BAKE canonical order; source parser cannot synthesize them"],
    [12, "NORMALIZE", "apply lexical_semantics.normalization exactly and retain raw span SHA"],
    [13, "SERIALIZE", "sort output tuple projection and CJ serialize receipt"]
  ],
  "candidate_key": ["source_ordinal", "byte_start", "byte_end", "candidate_ordinal", "semantic_class", "raw_sha256"],
  "eof_rule": "execute PARTITION_CHECK after final byte; unterminated state emits its error token then EOF proof",
  "priority_rule": "lowest opcode/production priority wins; equal class chooses longest span; equal span is an error"
}
```

Parser B is a streaming DFA. Every state has a transition for every displayed
class through an explicit exception map plus `DEFAULT`; EOF is explicit. A
transition is `[next_state,action]`. `RECONSUME` does not advance; every other
action advances one byte except EOF actions. At most one reconsume is allowed
per offset, making termination mechanical.

```json
{
  "schema": "cut4.r17.parser_b_dfa.v1",
  "start": "S0",
  "states": ["S0", "S_WS", "S_IDENT", "S_NUM", "S_SLASH", "S_DASH", "S_LINE", "S_BLOCK", "S_BLOCK_STAR", "S_DAML_BLOCK", "S_DAML_DASH", "S_DQ", "S_SQ", "S_BT", "S_ESC_DQ", "S_ESC_SQ", "S_ESC_BT", "S_INVALID"],
  "actions": ["START", "APPEND", "EMIT_RECONSUME", "EMIT_ADVANCE", "OPEN_LINE", "OPEN_BLOCK", "CLOSE_BLOCK", "OPEN_STRING", "CLOSE_STRING", "ESCAPE", "EMIT_INVALID_RECONSUME", "EMIT_EOF", "EMIT_UNTERMINATED_STRING", "EMIT_UNTERMINATED_STRING_RECONSUME", "EMIT_UNTERMINATED_COMMENT"],
  "action_semantics": [
    ["START", "set start=i and kind from destination state; consume byte i; i=i+1"],
    ["APPEND", "consume byte i into current token; i=i+1"],
    ["EMIT_RECONSUME", "emit current token over [start,i); set destination; do not advance i"],
    ["EMIT_ADVANCE", "emit PUNCT for registered punctuation class else UNKNOWN over [i,i+1); set destination; i=i+1"],
    ["OPEN_LINE", "retain opener byte already in current token, consume byte i, set kind LINE_COMMENT; i=i+1"],
    ["OPEN_BLOCK", "retain opener byte already in current token, consume byte i, set kind BLOCK_COMMENT; i=i+1"],
    ["CLOSE_BLOCK", "consume closer byte i, emit BLOCK_COMMENT over [start,i+1), set destination; i=i+1"],
    ["OPEN_STRING", "set start=i and kind from quote class, consume byte i; i=i+1"],
    ["CLOSE_STRING", "consume quote byte i, emit current string over [start,i+1), set destination; i=i+1"],
    ["ESCAPE", "consume BS byte i and enter quote-specific escape state; i=i+1"],
    ["EMIT_INVALID_RECONSUME", "emit INVALID_UTF8 over [start,i), set destination; do not advance i"],
    ["EMIT_EOF", "emit zero-width EOF proof at [i,i); halt"],
    ["EMIT_UNTERMINATED_STRING", "emit UNTERMINATED_STRING over [start,i); set destination; halt at EOF"],
    ["EMIT_UNTERMINATED_STRING_RECONSUME", "emit UNTERMINATED_STRING over [start,i); set destination; do not advance i"],
    ["EMIT_UNTERMINATED_COMMENT", "emit UNTERMINATED_COMMENT over [start,i); set destination; halt at EOF"]
  ],
  "rows": [
    ["S0", {"UTF8_INVALID":["S_INVALID","START"],"LF":["S_WS","START"],"CR":["S_WS","START"],"WS":["S_WS","START"],"ALPHA":["S_IDENT","START"],"DIGIT":["S_NUM","START"],"SLASH":["S_SLASH","START"],"DASH":["S_DASH","START"],"DQ":["S_DQ","OPEN_STRING"],"SQ":["S_SQ","OPEN_STRING"],"BT":["S_BT","OPEN_STRING"],"EOF":["S0","EMIT_EOF"],"DEFAULT":["S0","EMIT_ADVANCE"]}],
    ["S_WS", {"LF":["S_WS","APPEND"],"CR":["S_WS","APPEND"],"WS":["S_WS","APPEND"],"EOF":["S0","EMIT_RECONSUME"],"DEFAULT":["S0","EMIT_RECONSUME"]}],
    ["S_IDENT", {"ALPHA":["S_IDENT","APPEND"],"DIGIT":["S_IDENT","APPEND"],"EOF":["S0","EMIT_RECONSUME"],"DEFAULT":["S0","EMIT_RECONSUME"]}],
    ["S_NUM", {"DIGIT":["S_NUM","APPEND"],"EOF":["S0","EMIT_RECONSUME"],"DEFAULT":["S0","EMIT_RECONSUME"]}],
    ["S_SLASH", {"SLASH":["S_LINE","OPEN_LINE"],"STAR":["S_BLOCK","OPEN_BLOCK"],"EOF":["S0","EMIT_RECONSUME"],"DEFAULT":["S0","EMIT_RECONSUME"]}],
    ["S_DASH", {"DASH":["S_LINE","OPEN_LINE"],"EOF":["S0","EMIT_RECONSUME"],"DEFAULT":["S0","EMIT_RECONSUME"]}],
    ["S_LINE", {"LF":["S0","EMIT_RECONSUME"],"CR":["S0","EMIT_RECONSUME"],"EOF":["S0","EMIT_RECONSUME"],"DEFAULT":["S_LINE","APPEND"]}],
    ["S_BLOCK", {"STAR":["S_BLOCK_STAR","APPEND"],"EOF":["S0","EMIT_UNTERMINATED_COMMENT"],"DEFAULT":["S_BLOCK","APPEND"]}],
    ["S_BLOCK_STAR", {"SLASH":["S0","CLOSE_BLOCK"],"STAR":["S_BLOCK_STAR","APPEND"],"EOF":["S0","EMIT_UNTERMINATED_COMMENT"],"DEFAULT":["S_BLOCK","APPEND"]}],
    ["S_DAML_BLOCK", {"DASH":["S_DAML_DASH","APPEND"],"EOF":["S0","EMIT_UNTERMINATED_COMMENT"],"DEFAULT":["S_DAML_BLOCK","APPEND"]}],
    ["S_DAML_DASH", {"RBRACE":["S0","CLOSE_BLOCK"],"DASH":["S_DAML_DASH","APPEND"],"EOF":["S0","EMIT_UNTERMINATED_COMMENT"],"DEFAULT":["S_DAML_BLOCK","APPEND"]}],
    ["S_DQ", {"BS":["S_ESC_DQ","ESCAPE"],"DQ":["S0","CLOSE_STRING"],"LF":["S0","EMIT_UNTERMINATED_STRING_RECONSUME"],"CR":["S0","EMIT_UNTERMINATED_STRING_RECONSUME"],"EOF":["S0","EMIT_UNTERMINATED_STRING"],"DEFAULT":["S_DQ","APPEND"]}],
    ["S_SQ", {"BS":["S_ESC_SQ","ESCAPE"],"SQ":["S0","CLOSE_STRING"],"LF":["S0","EMIT_UNTERMINATED_STRING_RECONSUME"],"CR":["S0","EMIT_UNTERMINATED_STRING_RECONSUME"],"EOF":["S0","EMIT_UNTERMINATED_STRING"],"DEFAULT":["S_SQ","APPEND"]}],
    ["S_BT", {"BS":["S_ESC_BT","ESCAPE"],"BT":["S0","CLOSE_STRING"],"EOF":["S0","EMIT_UNTERMINATED_STRING"],"DEFAULT":["S_BT","APPEND"]}],
    ["S_ESC_DQ", {"EOF":["S0","EMIT_UNTERMINATED_STRING"],"DEFAULT":["S_DQ","APPEND"]}],
    ["S_ESC_SQ", {"EOF":["S0","EMIT_UNTERMINATED_STRING"],"DEFAULT":["S_SQ","APPEND"]}],
    ["S_ESC_BT", {"EOF":["S0","EMIT_UNTERMINATED_STRING"],"DEFAULT":["S_BT","APPEND"]}],
    ["S_INVALID", {"UTF8_INVALID":["S_INVALID","APPEND"],"EOF":["S0","EMIT_INVALID_RECONSUME"],"DEFAULT":["S0","EMIT_INVALID_RECONSUME"]}]
  ],
  "pre_dispatch": ["before DFA start, if strict UTF-8 validation finds any invalid sequence emit one INVALID_UTF8 token spanning the complete source and one MALFORMED_DEBT semantic row, then skip all DFA rows", "if ecosystem=daml and state=S0 and bytes at offset begin '{-' enter S_DAML_BLOCK consuming both"],
  "post_lex": ["apply the exact parser_a production matcher independently over DFA tokens", "join BAKE only from validated BAKE receipts", "apply normalization and canonical tuple order", "serialize CJ"]
}
```

`LF` and `CR` end a line comment without consuming the newline; `S0` then
reconsumes it into whitespace. The exact class rows above are frozen and are
not caller configuration.

The verifier executes a third frozen stack machine over the same source and
BAKE bytes. It may not import either parser package or either parser receipt
constructor.

```json
{
  "schema": "cut4.r17.verifier_algorithm.v1",
  "steps": [
    [1, "VERIFY_SPEC_IDS", "recompute five CJ byte identities"],
    [2, "VERIFY_INPUTS", "strict-decode source and BAKE bytes; recompute size/SHA/row digests"],
    [3, "VERIFY_COVERAGE", "for each source build bit-count array of byte_size; add one for each nonzero token span; require every cell=1; empty source requires one EOF row"],
    [4, "VERIFY_UTF8", "independent scalar decoder table rejects overlong/surrogate/out-of-range/truncated and equals reported scalar spans"],
    [5, "VERIFY_TOKEN_SHAPES", "replay lexical transition predicates from frozen class table and require maximal span/kind/error"],
    [6, "VERIFY_CANDIDATES", "enumerate production anchors at every token index, apply priority/boundary/balance rules, require exact multiset"],
    [7, "VERIFY_BAKE", "derive graph/probe candidates only from exact validated BAKE rows and require one-to-one equality"],
    [8, "VERIFY_NORMALIZATION", "recompute NFC/path/raw span and semantic projection"],
    [9, "COMPARE", "compare canonical tuple projection A=B=V; retain exact missing/extra/mismatch diff rows"],
    [10, "NEGATIVE", "PROVED_NONE only when coverage, candidate, edge, classification, BAKE and pairwise diffs are total and empty"],
    [11, "RECEIPT", "CJ serialize counts, ordered roster digests, diff rows, and verdict"]
  ],
  "tuple_projection": ["source_id", "source_ordinal", "byte_start", "byte_end", "candidate_ordinal", "semantic_class", "normalized_value", "raw_sha256", "bake_fact_id", "debt_code"],
  "tuple_order": ["source_ordinal", "byte_start", "byte_end", "candidate_ordinal", "semantic_class", "normalized_value", "raw_sha256", "bake_fact_id", "debt_code"],
  "diff_kinds": ["MISSING_A", "EXTRA_A", "MISSING_B", "EXTRA_B", "MISSING_V", "EXTRA_V", "FIELD_MISMATCH", "DUPLICATE", "COVERAGE_GAP", "COVERAGE_OVERLAP", "BAKE_ORPHAN"],
  "verdict_table": [["all inputs valid and all diffs empty", "ACCEPT"], ["malformed receipt/spec/source/BAKE", "MALFORMED"], ["otherwise", "REJECT"]]
}
```

### 2.2 Closed parser/verifier transport

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "cut4.r17.recognition_receipts.schema.v1",
  "$defs": {
    "Hex64": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
    "SpanRow": {
      "type": "object", "additionalProperties": false,
      "required": ["source_id", "source_ordinal", "byte_start", "byte_end", "token_ordinal", "token_kind", "raw_sha256", "error_code"],
      "properties": {
        "source_id": {"type": "string", "minLength": 1},
        "source_ordinal": {"type": "integer", "minimum": 0},
        "byte_start": {"type": "integer", "minimum": 0},
        "byte_end": {"type": "integer", "minimum": 0},
        "token_ordinal": {"type": "integer", "minimum": 0},
        "token_kind": {"enum": ["WS", "IDENT", "NUMBER", "STRING_DQ", "STRING_SQ", "STRING_BT", "LINE_COMMENT", "BLOCK_COMMENT", "PUNCT", "INVALID_UTF8", "UNTERMINATED_STRING", "UNTERMINATED_COMMENT", "UNKNOWN", "EOF"]},
        "raw_sha256": {"$ref": "#/$defs/Hex64"},
        "error_code": {"enum": ["NONE", "E_UTF8", "E_STRING_EOF", "E_COMMENT_EOF", "E_ESCAPE_EOF", "E_UNKNOWN"]}
      }
    },
    "SemanticRow": {
      "type": "object", "additionalProperties": false,
      "required": ["source_id", "source_ordinal", "byte_start", "byte_end", "candidate_ordinal", "semantic_class", "normalized_value", "raw_sha256", "bake_fact_id", "debt_code", "row_digest"],
      "properties": {
        "source_id": {"type": "string", "minLength": 1},
        "source_ordinal": {"type": "integer", "minimum": 0},
        "byte_start": {"type": "integer", "minimum": 0},
        "byte_end": {"type": "integer", "minimum": 0},
        "candidate_ordinal": {"type": "integer", "minimum": 0},
        "semantic_class": {"enum": ["DECLARATION", "IMPORT", "MEMBER_CALL", "CALL", "PATH_REFERENCE", "CONTENT_INSTRUCTION", "GRAPH_EDGE", "PROBE_EDGE", "NONREFERENCE", "MALFORMED_DEBT", "UNRESOLVED_DEBT"]},
        "normalized_value": {"type": "string"},
        "raw_sha256": {"$ref": "#/$defs/Hex64"},
        "bake_fact_id": {"type": "string"},
        "debt_code": {"enum": ["NONE", "INVALID_UTF8", "UNTERMINATED", "UNKNOWN_FORM", "UNRESOLVED_REFERENCE", "BAKE_DEBT"]},
        "row_digest": {"$ref": "#/$defs/Hex64"}
      }
    },
    "ParserReceipt": {
      "type": "object", "additionalProperties": false,
      "required": ["schema", "parser_id", "parser_source_sha256", "parser_task_completion_digest", "spec_identities", "source_vector_digest", "bake_binding_digest", "span_rows", "semantic_rows", "span_roster_digest", "semantic_roster_digest", "receipt_digest"],
      "properties": {
        "schema": {"const": "cut4.r17.parser_receipt.v1"},
        "parser_id": {"enum": ["PARSER_A", "PARSER_B"]},
        "parser_source_sha256": {"$ref": "#/$defs/Hex64"},
        "parser_task_completion_digest": {"$ref": "#/$defs/Hex64"},
        "spec_identities": {"type": "array", "minItems": 5, "maxItems": 5, "uniqueItems": true, "items": {"$ref": "#/$defs/Hex64"}},
        "source_vector_digest": {"$ref": "#/$defs/Hex64"},
        "bake_binding_digest": {"$ref": "#/$defs/Hex64"},
        "span_rows": {"type": "array", "items": {"$ref": "#/$defs/SpanRow"}},
        "semantic_rows": {"type": "array", "items": {"$ref": "#/$defs/SemanticRow"}},
        "span_roster_digest": {"$ref": "#/$defs/Hex64"},
        "semantic_roster_digest": {"$ref": "#/$defs/Hex64"},
        "receipt_digest": {"$ref": "#/$defs/Hex64"}
      }
    },
    "DiffRow": {
      "type": "object", "additionalProperties": false,
      "required": ["diff_ordinal", "diff_kind", "canonical_key", "expected_row_digest", "observed_row_digest", "diff_digest"],
      "properties": {
        "diff_ordinal": {"type": "integer", "minimum": 0},
        "diff_kind": {"enum": ["MISSING_A", "EXTRA_A", "MISSING_B", "EXTRA_B", "MISSING_V", "EXTRA_V", "FIELD_MISMATCH", "DUPLICATE", "COVERAGE_GAP", "COVERAGE_OVERLAP", "BAKE_ORPHAN"]},
        "canonical_key": {"type": "array", "minItems": 10, "maxItems": 10},
        "expected_row_digest": {"$ref": "#/$defs/Hex64"},
        "observed_row_digest": {"$ref": "#/$defs/Hex64"},
        "diff_digest": {"$ref": "#/$defs/Hex64"}
      }
    },
    "VerifierReceipt": {
      "type": "object", "additionalProperties": false,
      "required": ["schema", "verifier_source_sha256", "verifier_task_completion_digest", "spec_identities", "parser_a_receipt_digest", "parser_b_receipt_digest", "source_vector_digest", "bake_binding_digest", "derived_semantic_roster_digest", "diff_rows", "diff_roster_digest", "verdict", "negative_proof_digest", "receipt_digest"],
      "properties": {
        "schema": {"const": "cut4.r17.verifier_receipt.v1"},
        "verifier_source_sha256": {"$ref": "#/$defs/Hex64"},
        "verifier_task_completion_digest": {"$ref": "#/$defs/Hex64"},
        "spec_identities": {"type": "array", "minItems": 5, "maxItems": 5, "uniqueItems": true, "items": {"$ref": "#/$defs/Hex64"}},
        "parser_a_receipt_digest": {"$ref": "#/$defs/Hex64"},
        "parser_b_receipt_digest": {"$ref": "#/$defs/Hex64"},
        "source_vector_digest": {"$ref": "#/$defs/Hex64"},
        "bake_binding_digest": {"$ref": "#/$defs/Hex64"},
        "derived_semantic_roster_digest": {"$ref": "#/$defs/Hex64"},
        "diff_rows": {"type": "array", "items": {"$ref": "#/$defs/DiffRow"}},
        "diff_roster_digest": {"$ref": "#/$defs/Hex64"},
        "verdict": {"enum": ["ACCEPT", "REJECT", "MALFORMED"]},
        "negative_proof_digest": {"$ref": "#/$defs/Hex64"},
        "receipt_digest": {"$ref": "#/$defs/Hex64"}
      }
    }
  },
  "oneOf": [{"$ref": "#/$defs/ParserReceipt"}, {"$ref": "#/$defs/VerifierReceipt"}]
}
```

`row_digest = D("cut4.r17.semantic_row.v1", row without row_digest)`;
roster digests hash the ordered arrays of full row objects. Receipt digests use
their schema tag and exclude only their own terminal digest. All five spec
identities, source-vector digest, BAKE binding, parser task completion, and
package SHA must equal route observations. Pairwise equality is byte equality
of `CJ(tuple_projection(rows))`; set equality is insufficient and duplicates
are retained as diffs. `PROVED_NONE` is legal only when both parser semantic
arrays and verifier derivation are empty, every source byte has exact token
coverage, every BAKE row is classified, and `diff_rows=[]`.

### 2.3 Total conformance denominator

Before parser authorship, the architecture review freezes these exact 32 vector
IDs and their source bytes in the RED fixture. Each vector is run through A,
B, and V; expected output is derived by the verifier rules, not a parser copy.

```json
{
  "schema": "cut4.r17.conformance_vectors.v1",
  "ids": [
    "empty", "ascii_identifier", "ascii_number", "all_punctuation", "all_ascii_bytes", "utf8_nfc", "utf8_nfd", "utf8_multibyte_boundary",
    "invalid_utf8_lead", "invalid_utf8_continuation", "invalid_utf8_overlong", "invalid_utf8_surrogate", "invalid_utf8_too_large", "invalid_utf8_truncated", "nul_byte", "bare_cr",
    "crlf", "line_comment_eof", "line_comment_crlf", "block_comment", "block_comment_unterminated", "daml_block_comment", "daml_block_unterminated", "double_string_escape",
    "single_string_escape", "backtick_multiline", "string_unterminated", "escape_at_eof", "keyword_boundary", "member_call_boundary", "path_content_overlap", "generic_common_omission"
  ],
  "required_outcomes": ["ACCEPT", "MALFORMED_DEBT"],
  "multiplicity": "exactly one SourceFileBytes row per id and exactly one A, B, and V receipt result per id"
}
```

The fixture supplies literal bytes for every ID and a mutation proving a
wrong expected result fails. `all_ascii_bytes` is the ordered byte string
`00..ff`; `generic_common_omission` concatenates one valid example of every
production and every BAKE fact kind. A package that special-cases only the
other 31 cannot pass that combined vector plus mutation denominator.

## 3. BAKE, digest, policy, and publication authority

### 3.1 Typed BAKE inputs

BAKE is an authenticated build-time dependency, not a caller field. Only the
three fixed provider slots exist. A fact is constructed from exact provider
receipt bytes already bound to PhaseIO plan and source snapshot; callers pass
those bytes, never a `clean=true` object.

```json
{
  "schema": "cut4.r17.bake_registry.v1",
  "provider_slots": ["source_graph", "build_probe", "daml_source_graph"],
  "fact_kinds": ["GRAPH_NODE", "GRAPH_EDGE", "PROBE_RESULT", "TYPED_DEBT"],
  "provider_statuses": ["NOT_APPLICABLE", "NOT_SELECTED", "SUCCESS", "SUCCESS_EMPTY", "DEBT", "FAILURE", "TIMEOUT", "MALFORMED"],
  "applicability_predicates": [["source_graph", "ecosystem in {aptos,evm,go,rust,solana,soroban,sui}"], ["build_probe", "selected build plan exists"], ["daml_source_graph", "ecosystem=daml"]],
  "selection_predicates": [["source_graph", "applicable and source_graph enabled"], ["build_probe", "applicable and build_probe enabled"], ["daml_source_graph", "applicable and daml_source_graph enabled"]],
  "fact_order": ["provider_ordinal", "fact_ordinal", "fact_kind", "subject_id", "object_id", "raw_sha256"],
  "success_empty_rule": "selected provider invocation terminal receipt proves zero payload rows and exact exhausted cursor; NOT_APPLICABLE is neutral and not evidence or debt"
}
```

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "cut4.r17.bake_binding.schema.v1",
  "$defs": {
    "Hex64": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
    "BakeFactRow": {
      "type": "object", "additionalProperties": false,
      "required": ["schema", "provider_id", "provider_ordinal", "fact_ordinal", "fact_kind", "subject_id", "object_id", "raw_bytes_base64", "raw_byte_size", "raw_sha256", "predicate_evidence_digest", "provider_receipt_digest", "fact_digest"],
      "properties": {
        "schema": {"const": "cut4.r17.bake_fact.v1"},
        "provider_id": {"enum": ["source_graph", "build_probe", "daml_source_graph"]},
        "provider_ordinal": {"type": "integer", "minimum": 0, "maximum": 2},
        "fact_ordinal": {"type": "integer", "minimum": 0},
        "fact_kind": {"enum": ["GRAPH_NODE", "GRAPH_EDGE", "PROBE_RESULT", "TYPED_DEBT"]},
        "subject_id": {"type": "string", "minLength": 1},
        "object_id": {"type": "string", "minLength": 1},
        "raw_bytes_base64": {"type": "string"},
        "raw_byte_size": {"type": "integer", "minimum": 1},
        "raw_sha256": {"$ref": "#/$defs/Hex64"},
        "predicate_evidence_digest": {"$ref": "#/$defs/Hex64"},
        "provider_receipt_digest": {"$ref": "#/$defs/Hex64"},
        "fact_digest": {"$ref": "#/$defs/Hex64"}
      }
    },
    "BakeBinding": {
      "type": "object", "additionalProperties": false,
      "required": ["schema", "source_file_roster_digest", "configuration_digest", "phaseio_plan_digest", "provider_plan_digest", "fact_count", "fact_roster_digest", "provider_receipt_roster_digest", "facts", "binding_digest"],
      "properties": {
        "schema": {"const": "cut4.r17.bake_binding.v1"},
        "source_file_roster_digest": {"$ref": "#/$defs/Hex64"},
        "configuration_digest": {"$ref": "#/$defs/Hex64"},
        "phaseio_plan_digest": {"$ref": "#/$defs/Hex64"},
        "provider_plan_digest": {"$ref": "#/$defs/Hex64"},
        "fact_count": {"type": "integer", "minimum": 0},
        "fact_roster_digest": {"$ref": "#/$defs/Hex64"},
        "provider_receipt_roster_digest": {"$ref": "#/$defs/Hex64"},
        "facts": {"type": "array", "items": {"$ref": "#/$defs/BakeFactRow"}},
        "binding_digest": {"$ref": "#/$defs/Hex64"}
      }
    }
  },
  "$ref": "#/$defs/BakeBinding"
}
```

`BakeFactRow` fields, in order, are
`schema,provider_id,provider_ordinal,fact_ordinal,fact_kind,subject_id,object_id,raw_bytes_base64,raw_byte_size,raw_sha256,predicate_evidence_digest,provider_receipt_digest,fact_digest`.
`BakeBinding` fields are
`schema,source_file_roster_digest,configuration_digest,phaseio_plan_digest,provider_plan_digest,fact_count,fact_roster_digest,provider_receipt_roster_digest,binding_digest`.
Exact formulas are:

```text
fact.raw = strict_base64_decode(raw_bytes_base64)
raw_byte_size = len(fact.raw); raw_sha256 = H(fact.raw)
fact_digest = D("cut4.r17.bake_fact.v1", fact without fact_digest)
fact_roster_digest = D("cut4.r17.bake_fact_roster.v1", facts sorted by fact_order)
provider_receipt_roster_digest = D("cut4.r17.bake_provider_receipts.v1", receipts in fixed provider-slot order)
binding_digest = D("cut4.r17.bake_binding.v1", binding without binding_digest)
```

The binding validator independently validates applicability/selection evidence,
provider receipt terminal status, payload/fact equality, PhaseIO plan, source
snapshot, and all three fixed slots. `SUCCESS_EMPTY` contributes no fact but
does contribute its nonempty receipt. `DEBT/FAILURE/TIMEOUT/MALFORMED`
contributes one `TYPED_DEBT` fact. `NOT_APPLICABLE/NOT_SELECTED` contributes no
fact and cannot support semantic evidence. Omission, fabrication, duplicate,
wrong-slot, or orphan fact fails the binding.

### 3.2 Universal semantic preimage registry

No field ending `_digest`, `_sha256`, `_id`, `_count`, `_state`, `_status`, or
`_authority` is accepted merely because its scalar shape is valid. The future
model generates `ObservedSemanticFields` by reflection over every dataclass,
constructor, validator dependency, and serializer. Exact equality to
`FrozenSemanticDerivations` is required. Each row is
`[owner,field,kind,domain_tag,ordered_source_paths,sort_key_or_empty]` where
kind is `BODY`, `BYTES`, `ROSTER`, `FK`, `COUNT`, `ENUM_TABLE`, or
`REGISTRY_LOOKUP`. `BODY` excludes only its own digest; `FK` must byte-equal an
already validated child's identity; `COUNT` is the exact roster length;
`ENUM_TABLE` and `REGISTRY_LOOKUP` must match the frozen rows below. Missing,
extra, duplicate, circular, or caller-overridden rows fail construction.

The following closed rows are mandatory additions to the inherited R16
denominator; inherited digest fields are mechanically reauthored under the
same rules rather than trusted as free HEX64 scalars.

```json
{
  "schema": "cut4.r17.semantic_derivation_additions.v1",
  "rows": [
    ["BakeFactRow", "raw_sha256", "BYTES", "raw", ["raw_bytes_base64", "raw_byte_size"], ""],
    ["BakeFactRow", "fact_digest", "BODY", "cut4.r17.bake_fact.v1", ["*"], ""],
    ["BakeBinding", "fact_count", "COUNT", "", ["facts"], ""],
    ["BakeBinding", "fact_roster_digest", "ROSTER", "cut4.r17.bake_fact_roster.v1", ["facts"], "provider_ordinal,fact_ordinal,fact_kind,subject_id,object_id,raw_sha256"],
    ["BakeBinding", "binding_digest", "BODY", "cut4.r17.bake_binding.v1", ["*"], ""],
    ["AckPolicy", "policy_digest", "BODY", "cut4.r17.ack_policy.v1", ["policy_id", "mode", "truth_table_digest"], ""],
    ["AckState", "state", "ENUM_TABLE", "", ["policy", "publication_link", "ack_record"], "ack_transition_table"],
    ["InvalidFileFact", "observed_sha256", "BYTES", "invalid_file_bytes", ["observed_bytes_base64", "observed_byte_size"], ""],
    ["InvalidFileFact", "fact_digest", "BODY", "cut4.r17.invalid_file_fact.v1", ["*"], ""],
    ["PhaseIOAuthority", "authority_digest", "REGISTRY_LOOKUP", "cut4.r17.phaseio_authority.v1", ["work_unit", "artifact_key", "identity", "owner", "write_mode", "schema_id", "contract_id", "launch_id", "ordinal"], "phaseio_authority_registry"],
    ["PublicOutputBytes", "sha256", "BYTES", "public_output", ["bytes_base64", "byte_size"], ""],
    ["PublicOutputBytes", "semantic_digest", "BODY", "cut4.r17.public_output.v1", ["*"], ""],
    ["CommittedPublicationReceipt", "public_output_roster_digest", "ROSTER", "cut4.r17.public_roster.v1", ["public_output_bytes"], "authority.ordinal"],
    ["PublicationLink", "link_digest", "BODY", "cut4.r17.publication_link.v1", ["terminal_record_digest", "committed_receipt_digest", "public_output_roster_digest"], ""],
    ["CompletionReceipt", "completion_digest", "BODY", "cut4.r17.completion.v1", ["*"], ""]
  ]
}
```

For every inherited object, the same exact general formulas apply:

```text
BODY(owner.field) = D(domain_tag, CJ projection of ordered_source_paths with field omitted)
BYTES(owner.field) = H(strict_base64_decode(source bytes)); declared size must equal len
ROSTER(owner.field) = D(domain_tag, array sorted by registered key); duplicates retained and rejected
FK(owner.field) = validated child identity/digest byte equality
COUNT(owner.field) = exact integer length of validated child roster
ENUM_TABLE(owner.field) = exact lookup result in immutable table
REGISTRY_LOOKUP(owner.field) = D(domain_tag, exact matched immutable registry row)
```

The contract generator rejects a reflected semantic field for which no unique
row exists. This converts the R16 scalar labels into derivations and prevents a
caller from minting a clean digest, status, ACK, invalid fact, or authority.

The generator itself is closed; callers cannot supply derivation rows. For
each reflected semantic field, it applies this first-match table:

```json
{
  "schema": "cut4.r17.derivation_selection_algorithm.v1",
  "ordered_rules": [
    [1, "field ends _sha256", "BYTES", "require exactly one same-owner bytes/base64 dependency and its size field"],
    [2, "FCF marks field FK/PREIMAGE/EMBEDDED to validated child identity or digest", "FK", "exact child field equality"],
    [3, "field ends _count", "COUNT", "require exactly one same-owner FCF roster dependency named by singularized prefix"],
    [4, "field ends _roster_digest", "ROSTER", "require exactly one same-owner FCF roster dependency named by prefix and its frozen order key"],
    [5, "field is authority_digest", "REGISTRY_LOOKUP", "exact PhaseIO authority row"],
    [6, "field ends _state or _status", "ENUM_TABLE", "exact registered evidence/status truth-table row"],
    [7, "field is an immutable registry key or fixed provider/predicate/operation ID", "REGISTRY_LOOKUP", "exact immutable registry row"],
    [8, "field ends _id", "BODY", "domain cut4.r17.auto.<owner>.<field>.v1 over all validated nonsemantic constructor inputs in FCF order"],
    [9, "field ends _digest", "BODY", "domain cut4.r17.auto.<owner>.<field>.v1 over every validated scalar and dependency field in FCF order, excluding only this field and fields transitively depending on it"],
    [10, "field ends _authority", "REGISTRY_LOOKUP", "exact immutable registry row"],
    [11, "otherwise", "NOT_SEMANTIC", "no semantic derivation row"]
  ],
  "ambiguity_rule": "zero or multiple required sources, a cycle, a transitive exclusion other than the registered one, or a reflected semantic field selected as NOT_SEMANTIC is fatal",
  "domain_rule": "every BODY/ROSTER registry tag is literal UTF-8 with trailing NUL and cannot be caller input",
  "equality_rule": "generated rows sorted by owner then field must byte-equal FrozenSemanticDerivations; both missing and extra rows fail"
}
```

Provider/query/terminal status selection is also closed: false applicability
maps only to `NOT_APPLICABLE`; true applicability plus false selection maps
only to `NOT_SELECTED`; selected valid terminal evidence maps to `SUCCESS` for
positive payload count or `SUCCESS_EMPTY` for an explicit exhausted zero
proof; approximation evidence maps to `DEBT`; nonzero exit maps to `FAILURE`;
deadline evidence maps to `TIMEOUT`; parse/schema/equality failure maps to
`MALFORMED`. A status with no matching unique evidence row is invalid. ACK
state uses only the table below. This table plus the BAKE applicability and
selection predicate IDs are immutable contract bytes.

### 3.3 Exact ACK and invalid-file state machines

```json
{
  "schema": "cut4.r17.state_tables.v1",
  "ack_transition_table": [
    ["DISABLED", "NO_LINK", "NO_ACK", "DISABLED", false],
    ["DISABLED", "LINK", "NO_ACK", "DISABLED", true],
    ["DISABLED", "NO_LINK", "ACK", "INVALID", false],
    ["DISABLED", "LINK", "ACK", "INVALID", false],
    ["REQUIRED", "NO_LINK", "NO_ACK", "REQUIRED_PENDING", false],
    ["REQUIRED", "LINK", "NO_ACK", "REQUIRED_PENDING", false],
    ["REQUIRED", "NO_LINK", "ACK", "INVALID", false],
    ["REQUIRED", "LINK", "ACK", "REQUIRED_COMMITTED", true]
  ],
  "invalid_file_kinds": ["TORN_TEMP", "ZERO_BYTE", "PARTIAL_FINAL", "MALFORMED_RECORD", "ALIAS_COLLISION"],
  "invalid_transition_table": [
    ["ABSENT", "ABSENT", "NOOP", 0],
    ["ABSENT", "VALID_NEW", "APPEND_ONE_FACT", 1],
    ["PRESENT", "SAME_VALID", "NOOP", 0],
    ["PRESENT", "VALID_DISTINCT", "APPEND_ONE_FACT", 1],
    ["ANY", "MALFORMED", "REJECT", 0],
    ["ANY", "DELETE_OR_REWRITE_PRIOR", "REJECT", 0],
    ["ANY", "GENERATION_NOT_PLUS_ONE", "REJECT", 0]
  ],
  "ack_policy_ids": [["cut4-r17-ack-disabled", "DISABLED"], ["cut4-r17-ack-required", "REQUIRED"]],
  "fact_id_formula": "D(cut4.r17.invalid_file_fact_id.v1,[canonical_identity,fact_kind,observed_sha256,detected_generation])",
  "journal_rule": "an APPEND_ONE_FACT transition preserves namespace, request, all earlier record bytes and facts, performs exactly generation+1 CAS, and appends exactly one immutable INVALID_FACT record"
}
```

`truth_table_digest = D("cut4.r17.ack_transition_table.v1", exact
ack_transition_table)`. `policy_digest` then follows the registered BODY row.
An ACK record is valid only if it follows a committed PublicationLink and its
link/receipt digests match; the link never depends on a later ACK. Completion
must use the exact table's final boolean. Invalid facts require observed bytes,
size, SHA, path, kind, detected generation, and the fact-ID formula; enum
labels alone have no authority.

### 3.4 Exact PhaseIO and public authority

The fixture reference model uses this closed registry. It is not installed in
live PhaseIO. `owner=DRIVER` and `write_mode=REPLACE` are constants; no caller
may supply a row. The canonical tuple is selected solely by ecosystem mode.

```json
{
  "schema": "cut4.r17.phaseio_authority_registry.v1",
  "operation": "recon/canonical_publication_successor_v2",
  "contract": "cut4-transactional-recon-publication-r17-v1",
  "launch": "cut4-r17-fixture-launch-v1",
  "private_rows": [
    [0, "recon/private_seed_v2", "seed_manifest", ".scratchpad/private/recon_seed_v2/seed_manifest.json", "cut4.seed_manifest.v2"],
    [1, "recon/private_seed_v2", "provider_receipts", ".scratchpad/private/recon_seed_v2/provider_receipts.json", "cut4.provider_receipts.v3"],
    [2, "recon/private_journal_v1", "journal_state", ".scratchpad/private/recon_publication_v2/journal_state.json", "cut4.journal_state.v4"]
  ],
  "sc_public_rows": [
    [0, "recon_summary.md", "text/markdown"], [1, "design_context.md", "text/markdown"], [2, "attack_surface.md", "text/markdown"], [3, "state_variables.md", "text/markdown"],
    [4, "function_list.md", "text/markdown"], [5, "contract_inventory.md", "text/markdown"], [6, "template_recommendations.md", "text/markdown"], [7, "detected_patterns.md", "text/markdown"],
    [8, "setter_list.md", "text/markdown"], [9, "emit_list.md", "text/markdown"], [10, "build_status.md", "text/markdown"], [11, "recon_signal_transform_receipt.json", "application/json"]
  ],
  "l1_public_rows": [
    [0, "recon_summary.md", "text/markdown"], [1, "threat_model.md", "text/markdown"], [2, "subsystem_map.md", "text/markdown"], [3, "attack_surface.md", "text/markdown"],
    [4, "trust_boundaries.md", "text/markdown"], [5, "template_recommendations.md", "text/markdown"], [6, "scope_leftover.md", "text/markdown"], [7, "recon_signal_transform_receipt.json", "application/json"]
  ],
  "private_row_expansion": ["ordinal", "operation", "work_unit", "artifact_key", "identity", "owner=DRIVER", "write_mode=REPLACE", "schema_id", "contract", "launch"],
  "public_row_expansion": ["ordinal", "operation", "work_unit=recon/canonical_merge", "artifact_key=canonical_identity", "identity=canonical_identity", "owner=DRIVER", "write_mode=REPLACE", "schema_id=cut4.canonical_output.v2", "content_type", "contract", "launch", "mode"]
}
```

`PhaseIOAuthority.authority_digest =
D("cut4.r17.phaseio_authority.v1", expanded matched row)`. Physical identity,
artifact key, operation, unit, schema/content type, contract, launch, ordinal,
owner, and write mode must all match. SC publishes exactly 12 nonempty outputs;
L1 exactly eight. The data roster excludes manifest/receipt control rows from
its own data digest; the transform receipt hashes the data manifest identity
and completed data set. Public output bytes hash exact nonempty bytes. Canonical
merge alone constructs the registry-derived tuple and atomically publishes the
whole set plus committed receipt and link. Provider or direct project-root
writes, glob discovery, zero bytes, aliases, partial/superset sets, and
unregistered authority all fail.

## 4. Fixture-first derivation and observed RED/GREEN runs

### 4.1 Derivable mutation records

The RED author freezes the test bytes and complete mutation definitions before
the model path exists. A mutation is a deterministic byte transform, not a
caller-provided final SHA.

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "cut4.r17.execution_evidence.schema.v1",
  "$defs": {
    "Hex64": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
    "B64": {"type": "string"},
    "MutationDefinition": {
      "type": "object", "additionalProperties": false,
      "required": ["schema", "case_id", "base_subject_id", "base_bytes_base64", "base_byte_size", "base_sha256", "selector_kind", "selector_value", "byte_start", "byte_end", "delete_count", "insert_bytes_base64", "operation", "mutated_bytes_base64", "mutated_byte_size", "mutated_sha256", "expected_stage", "green_expected_code", "definition_digest"],
      "properties": {
        "schema": {"const": "cut4.r17.mutation_definition.v1"},
        "case_id": {"type": "string", "pattern": "^[a-z0-9_]+(?:\\.[a-z0-9_]+)+$"},
        "base_subject_id": {"type": "string", "minLength": 1},
        "base_bytes_base64": {"$ref": "#/$defs/B64"},
        "base_byte_size": {"type": "integer", "minimum": 0},
        "base_sha256": {"$ref": "#/$defs/Hex64"},
        "selector_kind": {"enum": ["BYTE_SPAN", "JSON_POINTER", "AST_NODE_ID", "REGISTRY_ROW_ID", "TRANSCRIPT_FIELD"]},
        "selector_value": {"type": "string", "minLength": 1},
        "byte_start": {"type": "integer", "minimum": 0},
        "byte_end": {"type": "integer", "minimum": 0},
        "delete_count": {"type": "integer", "minimum": 0},
        "insert_bytes_base64": {"$ref": "#/$defs/B64"},
        "operation": {"enum": ["REPLACE", "DELETE", "INSERT", "DUPLICATE", "REORDER", "RELABEL", "TRUNCATE", "CORRUPT"]},
        "mutated_bytes_base64": {"$ref": "#/$defs/B64"},
        "mutated_byte_size": {"type": "integer", "minimum": 0},
        "mutated_sha256": {"$ref": "#/$defs/Hex64"},
        "expected_stage": {"enum": ["ORCHESTRATION", "RECOGNITION", "BAKE_AUTHORITY", "JOURNAL_STATE", "PUBLICATION", "RED_EVIDENCE", "GREEN_EVIDENCE"]},
        "green_expected_code": {"type": "string", "pattern": "^R17_[A-Z0-9_]+$"},
        "definition_digest": {"$ref": "#/$defs/Hex64"}
      }
    },
    "PathObservation": {
      "type": "object", "additionalProperties": false,
      "required": ["schema", "observation_ordinal", "parent_identity", "target_identity", "directory_entries", "target_present", "target_size", "target_sha256", "observer_task_completion_digest", "observation_digest"],
      "properties": {
        "schema": {"const": "cut4.r17.path_observation.v1"},
        "observation_ordinal": {"type": "integer", "minimum": 1},
        "parent_identity": {"type": "string", "minLength": 1},
        "target_identity": {"const": "review_fixtures/cut4_transactional_recon_publication_r17_reference_model.py"},
        "directory_entries": {"type": "array", "uniqueItems": true, "items": {"type": "string"}},
        "target_present": {"type": "boolean"},
        "target_size": {"type": "integer", "minimum": 0},
        "target_sha256": {"$ref": "#/$defs/Hex64"},
        "observer_task_completion_digest": {"$ref": "#/$defs/Hex64"},
        "observation_digest": {"$ref": "#/$defs/Hex64"}
      }
    },
    "SubprocessTranscript": {
      "type": "object", "additionalProperties": false,
      "required": ["schema", "phase", "invocation_id", "runner_task_completion_digest", "argv", "environment", "cwd", "stdin_bytes_base64", "stdin_sha256", "input_subjects", "start_monotonic_ns", "end_monotonic_ns", "duration_ns", "exit_code", "stdout_bytes_base64", "stdout_byte_size", "stdout_sha256", "stderr_bytes_base64", "stderr_byte_size", "stderr_sha256", "output_subjects", "transcript_digest"],
      "properties": {
        "schema": {"const": "cut4.r17.subprocess_transcript.v1"},
        "phase": {"enum": ["RED_COLLECTION", "RED_MODEL_ABSENT", "RED_ORACLE", "GREEN_DOMAIN", "GREEN_FULL"]},
        "invocation_id": {"type": "string", "pattern": "^r17-inv-[a-z0-9_-]+$"},
        "runner_task_completion_digest": {"$ref": "#/$defs/Hex64"},
        "argv": {"type": "array", "minItems": 1, "items": {"type": "string"}},
        "environment": {"type": "array", "items": {"type": "array", "prefixItems": [{"type": "string", "minLength": 1}, {"type": "string"}], "items": false, "minItems": 2, "maxItems": 2}},
        "cwd": {"type": "string", "minLength": 1},
        "stdin_bytes_base64": {"$ref": "#/$defs/B64"},
        "stdin_sha256": {"$ref": "#/$defs/Hex64"},
        "input_subjects": {"type": "array", "minItems": 1, "items": {"type": "array", "minItems": 3, "maxItems": 3}},
        "start_monotonic_ns": {"type": "integer", "minimum": 0},
        "end_monotonic_ns": {"type": "integer", "minimum": 0},
        "duration_ns": {"type": "integer", "minimum": 0},
        "exit_code": {"type": "integer"},
        "stdout_bytes_base64": {"$ref": "#/$defs/B64"},
        "stdout_byte_size": {"type": "integer", "minimum": 0},
        "stdout_sha256": {"$ref": "#/$defs/Hex64"},
        "stderr_bytes_base64": {"$ref": "#/$defs/B64"},
        "stderr_byte_size": {"type": "integer", "minimum": 0},
        "stderr_sha256": {"$ref": "#/$defs/Hex64"},
        "output_subjects": {"type": "array", "items": {"type": "array", "minItems": 3, "maxItems": 3}},
        "transcript_digest": {"$ref": "#/$defs/Hex64"}
      }
    },
    "CaseObservation": {
      "type": "object", "additionalProperties": false,
      "required": ["schema", "phase", "case_id", "definition_digest", "test_sha256", "model_sha256", "request_bytes_base64", "request_sha256", "result_bytes_base64", "result_sha256", "exception_type", "exception_bytes_base64", "exception_sha256", "observed_code", "positive_control_code", "transcript_digest", "observation_digest"],
      "properties": {
        "schema": {"const": "cut4.r17.case_observation.v1"},
        "phase": {"enum": ["RED", "GREEN"]},
        "case_id": {"type": "string", "minLength": 1},
        "definition_digest": {"$ref": "#/$defs/Hex64"},
        "test_sha256": {"$ref": "#/$defs/Hex64"},
        "model_sha256": {"$ref": "#/$defs/Hex64"},
        "request_bytes_base64": {"$ref": "#/$defs/B64"},
        "request_sha256": {"$ref": "#/$defs/Hex64"},
        "result_bytes_base64": {"$ref": "#/$defs/B64"},
        "result_sha256": {"$ref": "#/$defs/Hex64"},
        "exception_type": {"enum": ["NONE", "ImportError", "ModuleNotFoundError", "ValidationError"]},
        "exception_bytes_base64": {"$ref": "#/$defs/B64"},
        "exception_sha256": {"$ref": "#/$defs/Hex64"},
        "observed_code": {"type": "string"},
        "positive_control_code": {"type": "string"},
        "transcript_digest": {"$ref": "#/$defs/Hex64"},
        "observation_digest": {"$ref": "#/$defs/Hex64"}
      }
    }
  },
  "oneOf": [{"$ref": "#/$defs/MutationDefinition"}, {"$ref": "#/$defs/PathObservation"}, {"$ref": "#/$defs/SubprocessTranscript"}, {"$ref": "#/$defs/CaseObservation"}]
}
```

For a byte-span selector, `byte_start <= byte_end <= base_byte_size`,
`delete_count = byte_end-byte_start`, and:

```text
mutated = base[0:byte_start] || strict_base64_decode(insert_bytes_base64) || base[byte_end:]
mutated_bytes_base64 = strict_base64_encode(mutated)
mutated_byte_size = len(mutated); mutated_sha256 = H(mutated)
definition_digest = D("cut4.r17.mutation_definition.v1", definition without definition_digest)
```

Typed selectors first resolve to one unique canonical byte span using the
frozen source map; zero or multiple matches fail. `DUPLICATE/REORDER/RELABEL`
must lower to a displayed byte transform and reproduce the final bytes. A
fixture cannot supply only a final hash.

Transcript validation strict-decodes all byte fields, checks their sizes/SHAs,
requires environment rows sorted by unique name, exact cwd, exact argv without
shell interpolation, `end-start=duration`, subject triples
`[identity,size,sha256]`, and hashes the object excluding only
`transcript_digest`. Timing is captured evidence, not an ordering authority.

### 4.2 Honest chronology and exact joins

RED requires this exact order:

1. Freeze test bytes, all mutation definitions, five spec identities, and 32
   conformance source vectors.
2. Root observes the exact model parent directory and target path with
   `target_present=false`, zero size, and `H(empty)` before collection.
3. Run an external subprocess with exact argv/environment/cwd/input subjects;
   collection and oracle-only cases pass, while every model-dependent node
   fails by actual `ImportError` or `ModuleNotFoundError`.
4. Observe the same path again after the run with `target_present=false` and a
   later observation ordinal. Directory-entry arrays and subprocess output
   make absence externally observed rather than an author boolean.
5. RED receipt joins exactly one definition and one RED case observation per
   model-dependent case, both path observations, all transcripts, parser and
   verifier receipts, test SHA, and route task completion. RED observations
   carry empty model SHA/result/code and may claim only `MODEL_ABSENT`.
6. Independent RED review reproduces the subprocess and joins its distinct
   task occurrence before the model implementer starts.

GREEN occurs only after the model completion record exists. Each case has one
actual request, result or exception, exact observed domain code, unchanged
definition/test hashes, model SHA, transcript, and positive control. The final
code is specified by `R17_ + uppercase(case_id with '.' changed to '_')`, but
is never asserted as an observed RED result; exact expected/observed equality
is checked only post-model. GREEN receipt arrays are 1:1 by `case_id`, with no
missing, extra, duplicate, or stale definition. Independent GREEN review
replays the same frozen tests and binds its distinct task occurrence.

The negative-proof receipt is transported as a verifier output observation.
It contains all source/parser/BAKE/verifier receipt digests, exact coverage and
candidate counts, empty diff roster, route predecessor completion digests, and
its own BODY digest. RED/GREEN author receipts similarly contain exact
transcript and case-observation roster digests; reviews reject an unjoined
receipt. No AST scan alone proves absence; the claim is limited to the exact
frozen test/model path and observed invocations.

### 4.3 Exact mutation denominator

R17 reauthors the exact 128 R16 case identities as R17 definitions; no R16
fixture or run is evidence. It appends these exact 64 IDs, 16 per finding:

```json
{
  "schema": "cut4.r17.mutation_additions.v1",
  "base_count": 128,
  "groups": {
    "orchestration": [
      "route.author_assignment_missing", "route.author_handle_invented", "route.start_input_unobserved", "route.completion_result_unobserved",
      "route.output_bytes_unobserved", "route.assignment_join_free", "route.result_observation_free", "route.review_start_before_author_completion",
      "route.review_same_task_handle", "route.negative_receipt_unjoined", "route.review_receipt_unjoined", "route.retrospective_overwrite",
      "route.author_receipt_handle_unjoined", "route.predecessor_identity_wrong", "route.completion_output_missing", "route.review_decision_not_accept"
    ],
    "recognition": [
      "recognition.byte_class_gap", "recognition.byte_class_overlap_priority_changed", "recognition.dfa_state_class_missing", "recognition.dfa_eof_missing",
      "recognition.reconsume_loop", "recognition.comment_boundary_wrong", "recognition.string_escape_wrong", "recognition.invalid_utf8_accepted",
      "recognition.token_gap", "recognition.token_overlap", "recognition.production_priority_changed", "recognition.keyword_boundary_changed",
      "recognition.parser_a_b_common_omission", "recognition.verifier_imports_parser", "recognition.parser_receipt_untransported", "recognition.proved_none_vacuous"
    ],
    "authority": [
      "authority.bake_binding_absent", "authority.bake_fact_fabricated", "authority.bake_fact_omitted", "authority.provider_slot_replaced",
      "authority.semantic_digest_free", "authority.unregistered_digest_field", "authority.ack_policy_self_minted", "authority.ack_state_wrong_table",
      "authority.invalid_fact_self_minted", "authority.invalid_generation_not_plus_one", "authority.phaseio_row_self_minted", "authority.public_path_unregistered",
      "authority.public_zero_byte", "authority.public_partial_tuple", "authority.public_superset", "authority.public_alias_collision"
    ],
    "execution": [
      "execution.mutation_final_hash_free", "execution.selector_zero_match", "execution.selector_multiple_match", "execution.mutated_bytes_mismatch",
      "execution.model_absent_boolean_only", "execution.before_path_observation_missing", "execution.after_path_observation_missing", "execution.model_created_during_red",
      "execution.argv_missing", "execution.environment_missing", "execution.cwd_changed", "execution.stdout_hash_wrong",
      "execution.exit_code_wrong", "execution.green_request_missing", "execution.green_code_claimed_in_red", "execution.green_receipt_extra_case"
    ]
  },
  "total_count": 192
}
```

Every group has exactly 16 IDs. Additions are therefore 64 and the complete
R17 denominator is exactly 128+64=192 unique identities.

## 5. Constructor/dependency DAG and review gate

The executable model must publish typed dependency metadata. Reflection over
actual dataclass fields, constructor parameters/preimages, validators,
serializers, and the universal semantic derivation registry yields the graph.
The contract denominator is the following ordered type DAG; field-level edges
expand from it and must contain every inherited R16 edge plus the R17 typed
edges. There may be no hidden or caller-only constructor.

```json
{
  "schema": "cut4.r17.constructor_dag.v1",
  "nodes": [
    "FrozenSpecs", "TaskStartRecord", "TaskCompletionRecord", "ReviewDominanceRecord", "SourceFileBytes", "PhaseIOAuthority", "PredicateEvidence", "ProviderPlan", "ProviderReceipt", "BakeFactRow", "BakeBinding", "SourceSnapshot", "ParserAReceipt", "ParserBReceipt", "VerifierReceipt", "AckPolicy", "InvalidFileFact", "JournalState", "PriorEnvelope", "BaseRequestIntent", "AttemptAllocation", "InvocationRecord", "PayloadRecord", "ProviderPrivateV4", "NormalizedSemanticRow", "DiffRow", "TerminalEnvelope", "TerminalJournalRecord", "PublicOutputBytes", "CommittedPublicationReceipt", "PublicationLink", "PublicationAckJournalRecord", "M4", "R4", "CompletionReceipt"
  ],
  "edges": [
    ["FrozenSpecs", "ParserAReceipt"], ["FrozenSpecs", "ParserBReceipt"], ["FrozenSpecs", "VerifierReceipt"],
    ["TaskStartRecord", "TaskCompletionRecord"], ["TaskCompletionRecord", "ReviewDominanceRecord"],
    ["PhaseIOAuthority", "ProviderPlan"], ["PredicateEvidence", "ProviderReceipt"], ["ProviderPlan", "ProviderReceipt"], ["ProviderReceipt", "BakeFactRow"], ["BakeFactRow", "BakeBinding"],
    ["SourceFileBytes", "SourceSnapshot"], ["BakeBinding", "SourceSnapshot"], ["SourceSnapshot", "ParserAReceipt"], ["SourceSnapshot", "ParserBReceipt"],
    ["BakeBinding", "ParserAReceipt"], ["BakeBinding", "ParserBReceipt"], ["ParserAReceipt", "VerifierReceipt"], ["ParserBReceipt", "VerifierReceipt"],
    ["AckPolicy", "ProviderPlan"], ["InvalidFileFact", "JournalState"], ["JournalState", "PriorEnvelope"], ["SourceSnapshot", "BaseRequestIntent"], ["PriorEnvelope", "BaseRequestIntent"],
    ["BaseRequestIntent", "AttemptAllocation"], ["AttemptAllocation", "InvocationRecord"], ["ProviderPlan", "InvocationRecord"], ["InvocationRecord", "PayloadRecord"],
    ["PayloadRecord", "ProviderPrivateV4"], ["ProviderReceipt", "ProviderPrivateV4"], ["VerifierReceipt", "NormalizedSemanticRow"], ["PayloadRecord", "NormalizedSemanticRow"],
    ["ProviderPrivateV4", "DiffRow"], ["NormalizedSemanticRow", "DiffRow"], ["DiffRow", "TerminalEnvelope"], ["InvocationRecord", "TerminalEnvelope"],
    ["TerminalEnvelope", "TerminalJournalRecord"], ["PhaseIOAuthority", "PublicOutputBytes"], ["TerminalJournalRecord", "CommittedPublicationReceipt"], ["PublicOutputBytes", "CommittedPublicationReceipt"],
    ["CommittedPublicationReceipt", "PublicationLink"], ["TerminalJournalRecord", "PublicationLink"], ["PublicationLink", "PublicationAckJournalRecord"], ["AckPolicy", "PublicationAckJournalRecord"],
    ["ProviderPrivateV4", "M4"], ["NormalizedSemanticRow", "M4"], ["DiffRow", "M4"], ["PublicOutputBytes", "M4"], ["AckPolicy", "M4"], ["PublicationAckJournalRecord", "M4"],
    ["M4", "R4"], ["R4", "CompletionReceipt"], ["PublicationLink", "CompletionReceipt"], ["CommittedPublicationReceipt", "CompletionReceipt"], ["AckPolicy", "CompletionReceipt"], ["PublicationAckJournalRecord", "CompletionReceipt"]
  ]
}
```

This projection has exactly 35 unique nodes and 55 unique edges. All edges
point from dependency to consumer; Kahn remainder is zero. Actual field-level
metadata may have more edges but must project to exactly these 55 type pairs,
and every digest semantic field must have one derivation row. The executable
constructor order follows any stable lexical Kahn order and preserves the
acyclic `BaseRequestIntent -> AttemptAllocation -> InvocationRecord ->
TerminalEnvelope -> TerminalJournalRecord -> CommittedPublicationReceipt ->
PublicationLink -> optional PublicationAckJournalRecord` sequence. The link
does not depend on the optional future ACK.

Independent architecture review authenticates this contract/receipt and R16
review; parses every JSON root/schema with duplicate/non-finite rejection;
recomputes all canonical root hashes; checks the complete DFA default/EOF
coverage; validates schema references; checks route 24/46 and constructor
35/55 DAGs; checks 32 vectors and 128+64=192 mutation IDs; verifies exact SC
12/L1 8/private 3 authorities, BAKE three-slot denominator, ACK/invalid truth
tables, all local paths, future path absence, LF/no BOM, balanced fences, and
Part-0 ceiling. It returns ACCEPT or REPAIR. ACCEPT alone permits the root to
write the create-new plan/occurrence records and begin the strict staged route.

## 6. Non-goals and claim ceiling

R17 proves no cryptographic identity, signature, human independence,
non-collusion, trusted wall clock, hidden-file absence outside the observed
paths, parser implementation correctness before the future route runs,
target-host atomicity where unavailable, provider availability, target
protocol security, production PhaseIO/ArtifactLedger integration, audit
completion, release, readiness, or protocol answer. The hashes authenticate
only exact transported bytes and declared structural joins. Part-0 and all
route, parser, verifier, fixture, test, model, implementation, production,
provider, ArtifactLedger, G3, audit, commit, push, install, cutover, release,
readiness, and protocol-answer authority remain false.
