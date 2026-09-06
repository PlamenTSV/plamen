# Cut-4 transactional recon publication R10 amendment

Date: 2026-08-10
Status: Part-0 R10 architecture repair only
Supersedes: only the repaired clauses of the R9 amendment
Authority: design for independent review; no fixture, production, test,
ArtifactLedger, G3, provider, audit, commit, push, install, cutover, release,
or audit-readiness authority

## 0. Decision and inherited boundary

R10 closes only the three blockers in the mandatory R9 independent review.
All R1-R9 artifacts remain immutable. R10 preserves R9's six authenticated
source roots, immutable query-session core, acyclic page-before-cursor
construction, neutral private NOT_APPLICABLE state, and static-S versus
post-provider-M/R time split. It preserves R8's one-to-one `pi_S_to_M`,
membership-body -> D -> final-membership order, deliberate D rederivation,
common multiplicity key, query-zero/provider-zero separation, and ordinary
owner/debt gates. It preserves R7/R6 ownership, provider denominator, PhaseIO,
publication transition, state, compatibility, crash, legacy, and containment
contracts.

The three R10 repairs are:

1. The document analyzer has a byte-covering segment denominator and emits a
   candidate for every semantic segment and every instruction/path/content
   reference. Exact source, identity, grammar, segment, and candidate
   registries replace R9's positive-only extraction. Unrecognized forms and
   parse gaps become typed debt. `pi_instruction.v2` includes every R9
   candidate/reach/role/source field, so PATH-to-CONTENT changes cannot pass.
2. Every continuation binds the current session-authority preimage to the
   prior envelope, receipt, c3 cursor, and currently validated M/R/L/publication
   authority before a page is appended. Replay means the byte-identical
   cursor-in request returns the byte-identical cursor-out. An exhausted
   cursor-out is never valid cursor-in; replay of a terminal invocation uses
   its original request bytes.
3. The private key includes both predicate IDs and the accepted-target fields.
   Exact foreign keys join S consumer, plan, predicate, provider outcome,
   provider-private row, M evidence/disposition/projection, and R completion.
   M3, R3, projection, completion, and diff objects now have closed fields,
   IDs, orders, digest domains, and empty-value rules.

Section 8 is a new exact **180-node** R10 roster. No R1-R9 node is counted in
180.

## 1. Authenticated repair input

The mandatory R9 independent review was read end to end before authoring. It is
19,737 bytes and SHA-256
`23654a4e25f82c6c8e9b31dfa9e408931eb124f3f485eeb30029c70599af120e`:

`review_fixtures/cut4_transactional_recon_publication_r9_amendment_independent_review_20260810.md`.

The reviewed R9 amendment is 52,330 bytes and SHA-256
`039784ed389cab0e52a6cba992be1a180e94a87956ba41cc12b41f6ca8003a40`.
Its author receipt is 3,515 bytes and SHA-256
`8f577455098edb66a1034ec9da5f5809b3f1f03d6d7bfeb23dad6eedb215bb3a`.
The review accepted R9's source-byte authentication, stable session core and
page mechanics, and mutually exclusive private status table. R10 does not
reopen those accepted parts.

## 2. Canonical encoding and added closed enums

R9 canonical JSON and hashing remain exact. Every object rejects missing or
extra fields; every array has the order stated here; optional absence is only
the specified `""`, `[]`, or `{}`. R10 adds these closed enums:

```json
{
  "document_segment_kind": ["YAML_LINE", "HEADING", "LIST_ITEM", "TABLE_CELL", "FENCE_DELIMITER", "FENCED_CODE_LINE", "INLINE_CODE", "LINK_LABEL", "LINK_TARGET", "BLOCKQUOTE", "PROSE_SENTENCE", "TRIVIA", "UNRECOGNIZED"],
  "document_candidate_kind": ["SEGMENT_COVERAGE", "PATH_REFERENCE", "CONTENT_REFERENCE", "CONTENT_INSTRUCTION", "PROHIBITION", "NO_RECON_REFERENCE", "UNRECOGNIZED_FORM_DEBT", "PARSE_DEBT"],
  "identity_kind": ["PUBLIC_OUTPUT", "PRIVATE_SEED", "PROVIDER_SLOT", "RETIRED_ALIAS", "CLI_MODULE", "PROMPT_PLACEHOLDER", "PRODUCER_ID", "CONSUMER_ID", "CONTENT_TERM"],
  "identity_match_mode": ["EXACT", "PATH_COMPONENT", "MODULE_COMPONENT", "PLACEHOLDER", "TOKEN_SEQUENCE"],
  "predicate_kind": ["APPLICABILITY", "SELECTION"],
  "private_diff_kind": ["MISSING_CONSUMER_PLAN_REF", "EXTRA_CONSUMER_PLAN_REF", "PLAN_SEMANTIC_MISMATCH", "PREDICATE_FOREIGN_KEY_MISMATCH", "PROVIDER_FOREIGN_KEY_MISMATCH", "MISSING_PROVIDER_PRIVATE_ROW", "EXTRA_PROVIDER_PRIVATE_ROW", "MISSING_EVIDENCE_ROW", "EXTRA_EVIDENCE_ROW", "EVIDENCE_DISPOSITION_MISMATCH", "MISSING_COMPLETION_ROW", "EXTRA_COMPLETION_ROW", "PRIVATE_MULTIPLICITY_MISMATCH"],
  "r10_semantic_debt_code": ["DOCUMENT_PARSE_DEBT", "DOCUMENT_UNRECOGNIZED_FORM_DEBT", "DOCUMENT_SEGMENT_COVERAGE_DEBT", "DOCUMENT_CANDIDATE_TOTALITY_DEBT", "DOCUMENT_INSTRUCTION_PROJECTION_DEBT", "PRIVATE_FOREIGN_KEY_DEBT", "PRIVATE_SCHEMA_DEBT"]
}
```

Every R9 enum, including NOT_APPLICABLE and the six provider terminal states,
remains closed and unchanged.

## 3. Mechanically total document extraction

### 3.1 Exact source and identity registries

S v3 replaces R9's implicit root policy with a literal source-root registry.
It has exactly these six rows, in `root_id` order:

| root_id | relative root | source class | file policy | document parser |
|---|---|---|---|---|
| `agents` | `agents` | METHODOLOGY | ALL_REGULAR_FILES | MARKDOWN_TOTAL_V2_OR_NOT_APPLICABLE |
| `commands` | `commands` | COMMAND_TEMPLATE | ALL_REGULAR_FILES | MARKDOWN_TOTAL_V2_OR_NOT_APPLICABLE |
| `docs` | `docs` | OPERATOR_DOCUMENT | ALL_REGULAR_FILES | MARKDOWN_TOTAL_V2 |
| `plamen_l1` | `plamen_l1` | CODE | ALL_REGULAR_FILES | NOT_APPLICABLE |
| `prompts` | `prompts` | PROMPT_TEMPLATE | ALL_REGULAR_FILES | MARKDOWN_TOTAL_V2_OR_NOT_APPLICABLE |
| `scripts` | `scripts` | CODE | ALL_REGULAR_FILES | NOT_APPLICABLE |

A source-root row has exactly `schema=cut4.s.source_root.v1`, `root_id`,
`relative_root`, `source_class`, `file_policy`, and `document_parser`. Its ID is
its unique `root_id`. Rows are lexical by root ID; their digest is
`H("cut4.s.source_roots.v1", rows)`.

Each recursively reached regular file has exactly:

```text
schema=cut4.s.source_file.v3, source_file_id, root_id, relative_path,
source_class, parser_id, size, sha256
```

`source_file_id = "sf:" + H("cut4.s.source_file.v3",
row_without_source_file_id)`. Files sort by relative path. Symlink traversal,
path escape, unreadable bytes, duplicate physical alias, or a file not assigned
to exactly one root is blocking source debt. All file bytes remain in the
source-tree digest, whether text parsing succeeds or not.

`MARKDOWN_TOTAL_V2_OR_NOT_APPLICABLE` selects MARKDOWN_TOTAL_V2 iff the final
canonical path suffix is exactly `.md` (case-sensitive); every other suffix is
NOT_APPLICABLE. `docs` has no suffix predicate: every regular file is attempted
under MARKDOWN_TOTAL_V2, and non-UTF-8/binary content receives PARSE_DEBT.

Before parsing, the DRIVER compiles the exact identity registry from the sealed
output bundle, provider plan, retired-alias migration table, CLI/query registry,
prompt-placeholder registry, producer/consumer plan, and content-term registry.
Every input registry digest is named in P0. An identity row has exactly:

```text
schema=cut4.s.document_identity.v1, identity_row_id, identity_kind,
canonical_identity, accepted_spellings, match_mode, source_registry_id
```

Spellings are nonempty NFC strings, lexical and unique globally after pairing
with match mode. `identity_row_id = "doci:" +
H("cut4.s.document_identity.v1", row_without_id)`. Rows sort by
`(identity_kind, canonical_identity, match_mode, identity_row_id)` and use
`H("cut4.s.document_identities.v1", rows)`. There is no ambient basename,
unregistered synonym, or post-write discovery.

The exact candidate-form registry has eight rows, one per
`document_candidate_kind`. Each row has exactly `schema`, `candidate_kind`,
`allowed_segment_kinds`, `required_identity_kinds`,
`allowed_instruction_roles`, `allowed_reaches`, `debt_code`, and
`recognizer_id`. `ALL` below means the literal full enum array from section 2,
not a serialized wildcard. The rows are exactly:

| kind | segments | required identities | allowed roles | allowed reaches | debt | recognizer |
|---|---|---|---|---|---|---|
| SEGMENT_COVERAGE | ALL | `[]` | `[NONE]` | `[NONE]` | empty | SEGMENT_COVERAGE_V1 |
| PATH_REFERENCE | ALL | `[PUBLIC_OUTPUT,PRIVATE_SEED,RETIRED_ALIAS,PROMPT_PLACEHOLDER]` | `[PATH_INSTRUCTION,REFERENCE]` | `[NONE,MODEL,TOOL,RUNTIME,CONTROL]` | empty | PATH_TOKEN_V1 |
| CONTENT_REFERENCE | ALL | full `identity_kind` enum | `[REFERENCE]` | `[NONE,MODEL,TOOL,RUNTIME,CONTROL]` | empty | CONTENT_TOKEN_V1 |
| CONTENT_INSTRUCTION | ALL | full `identity_kind` enum | `[CONTENT_INSTRUCTION]` | `[MODEL,TOOL,RUNTIME,CONTROL]` | empty | DIRECTIVE_GRAMMAR_V1 |
| PROHIBITION | ALL | full `identity_kind` enum | `[PROHIBITION]` | `[CONTROL]` | empty | PROHIBITION_GRAMMAR_V1 |
| NO_RECON_REFERENCE | ALL | `[]` | `[NONE]` | `[NONE]` | empty | NEGATIVE_PROOF_V1 |
| UNRECOGNIZED_FORM_DEBT | ALL | `[]` | `[NONE]` | `[UNRESOLVED]` | DOCUMENT_UNRECOGNIZED_FORM_DEBT | UNKNOWN_DEBT_V1 |
| PARSE_DEBT | ALL | `[]` | `[NONE]` | `[UNRESOLVED]` | DOCUMENT_PARSE_DEBT | PARSE_DEBT_V1 |

Enum arrays use their section-2 order. Rows sort by candidate kind and use
`H("cut4.s.document_candidate_forms.v1", rows)`. A candidate outside its form
row is schema-invalid.

### 3.2 Byte-covering segmentation and exact grammar

For every file assigned MARKDOWN_TOTAL_V2, strict UTF-8 decoding preserves raw
byte offsets. The tokenizer emits ordered, nonoverlapping segment rows whose
half-open byte ranges partition exactly `[0,file_size)`. Zero-length segments
are forbidden. Empty files have one TRIVIA row at `(0,0)` solely by explicit
empty-file rule. A segment row has exactly:

```text
schema=cut4.s.document_segment.v1, segment_id, source_file_id,
source_file_sha256, byte_start, byte_end, segment_ordinal, segment_kind,
raw_bytes_digest, nfc_text_digest, parse_state
```

`parse_state` is `PARSED` or `DEBT`. The two digest domains are
`cut4.s.document_segment_raw.v1` and `cut4.s.document_segment_text.v1`.
`segment_id = "docs:" + H("cut4.s.document_segment.v1",
row_without_segment_id)`. Rows sort by `(relative_path, byte_start, byte_end,
segment_ordinal, segment_id)`. Their domain is
`cut4.s.document_segments.v1`.

The tokenizer precedence is YAML line, fence delimiter/body line, heading,
blockquote, list item, table cell, link target/label, inline code, prose
sentence, trivia, then UNRECOGNIZED. Container rows are split into semantic
child spans, so an inline-code or link-target byte belongs to that child, not
also to surrounding prose. Delimiters and intervening whitespace receive
their own TRIVIA or delimiter segments. The partition equation is checked from
raw bytes; a decoder/parser gap produces PARSE_DEBT and cannot disappear.

Within every non-TRIVIA segment, the token grammar is longest-match, then
leftmost, with these exact forms:

```text
PLACEHOLDER := "{" [A-Z][A-Z0-9_]{0,63} "}"
CLI_OPTION  := "--" [a-z][a-z0-9-]{0,63}
MODULE      := [A-Za-z_][A-Za-z0-9_]{0,63}
               ("." [A-Za-z_][A-Za-z0-9_]{0,63})+
PATH_PART   := [A-Za-z0-9_{}.-]{1,128}
PATH        := PATH_PART (("/" | "\\") PATH_PART)+
WORD        := [A-Za-z][A-Za-z0-9_-]{0,127}
PUNCT       := one Unicode code point not matched above
```

A PATH composition may resolve only by exact ordered component joins to one
or more identity rows; placeholder substitution remains symbolic and must
match a registered placeholder row. CONTENT_REFERENCE is an exact registered
CONTENT_TERM token or TOKEN_SEQUENCE. CONTENT_INSTRUCTION uses the sealed
DIRECTIVE_GRAMMAR_V1 finite verb/modal/imperative table plus an identity or
content-term match. PROHIBITION uses the sealed negation table plus an
instruction match. Registry versions and their exact row digests are P0 inputs.
If tokens suggest path/content/directive structure but do not resolve under
these grammars, the result is UNRECOGNIZED_FORM_DEBT, not negative absence.

### 3.3 Total candidate rows and equations

Every segment has a mandatory SEGMENT_COVERAGE base candidate. In addition,
every distinct recognized path/content/instruction reference has one candidate,
ordered by the reference's byte start/end and identity-row ID. If there is no
recognized reference, there is exactly one classification candidate:
NO_RECON_REFERENCE, UNRECOGNIZED_FORM_DEBT, or PARSE_DEBT. A candidate has
exactly:

```text
schema=cut4.s.document_candidate.v2, candidate_id, source_file_id,
segment_id, candidate_ordinal, candidate_kind, reference_byte_start,
reference_byte_end, identity_row_id, canonical_identity, identity_match_mode,
composition_component_ids, source_class, document_reach, instruction_role,
semantic_class, flow_instance_id, raw_reference_digest, debt_code
```

The SEGMENT_COVERAGE candidate uses ordinal 0 and an empty byte range/identity
fields, `document_reach=NONE`, `instruction_role=NONE`, and empty debt. Other
candidates begin at ordinal 1. NO_RECON_REFERENCE is allowed only when the
complete token stream satisfies NEGATIVE_PROOF_V1: no identity/content match,
no unresolved PATH/MODULE/PLACEHOLDER composition, no directive/prohibition
signal, parse_state PARSED, and either segment kind TRIVIA/FENCE_DELIMITER or
an exact `(segment_id,nfc_text_digest,negative_rule_id,evidence_digest)` row in
the sealed negative-disposition registry. That registry has one exact row
schema `cut4.s.document_negative_disposition.v1`, lexical segment-ID order,
and digest domain `cut4.s.document_negative_dispositions.v1`; its digest is a
P0/S input. An unmatched nontrivia segment is UNRECOGNIZED_FORM_DEBT, not
NO_RECON_REFERENCE. A segment with a parse gap gets one PARSE_DEBT
classification candidate. UNRECOGNIZED segment/form gets one
UNRECOGNIZED_FORM_DEBT classification candidate. TRIVIA receives one
NO_RECON_REFERENCE classification candidate by the explicit trivia rule.

`candidate_id = "docc:" + H("cut4.s.document_candidate.v2",
row_without_candidate_id)`. Rows sort by `(source_file_id, segment_ordinal,
candidate_ordinal, reference_byte_start, reference_byte_end, identity_row_id,
candidate_id)`. The digest domain is `cut4.s.document_candidates.v2`.

S v3 contains exact arrays/digests for source roots, source files, identity
rows, candidate-form rows, document segments, document candidates, ordinary
semantic rows, query registry, private plans, and every R9 projection digest.
Its body has exactly:

```text
schema=cut4.recon_consumer_manifest.v3, analyzer_version,
normalization_version=cut4.semantic_normalization.v3,
source_root_rows, source_root_rows_digest, source_files,
source_tree_digest, document_identity_rows, document_identity_rows_digest,
document_candidate_form_rows, document_candidate_form_rows_digest,
document_negative_disposition_rows,
document_negative_disposition_rows_digest, document_segment_rows,
document_segment_rows_digest, document_candidate_rows,
document_candidate_rows_digest, query_registry, query_registry_digest,
rows, row_set_digest, exec_tuple_set_digest,
instruction_tuple_set_digest, debt_tuple_set_digest,
owner_tuple_set_digest, private_plan_rows, private_plan_rows_digest,
private_tuple_set_digest
```

The file envelope schema/domain are `cut4.recon_consumer_manifest_file.v3` and
`cut4.s.manifest.v3`. `source_tree_digest =
H("cut4.s.source_tree.v3", source_files)`. Each other array digest uses the
literal domain specified in this section; ordinary row/projection digests use
their inherited domain except `pi_instruction.v2`. It validates:

```text
raw segment byte ranges partition every authenticated MARKDOWN_TOTAL_V2 file
count(SEGMENT_COVERAGE candidates grouped by segment_id) = 1 for every segment
count(noncoverage candidates grouped by segment_id) >= 1 for every segment
every recognized reference token has exactly one noncoverage candidate
every positive noncoverage candidate resolves one identity row and one segment
every debt segment/candidate projects to one semantic DEBT row
every positive instruction candidate projects to one INSTRUCTION_ONLY row
SEGMENT_COVERAGE and NO_RECON_REFERENCE project to no executable consumer but remain in S
```

Any missing/extra row is DOCUMENT_SEGMENT_COVERAGE_DEBT or
DOCUMENT_CANDIDATE_TOTALITY_DEBT. Thus even an unknown prose instruction is
represented and blocks; source hashing is not treated as extraction proof.

### 3.4 `pi_instruction.v2` and independent rescan

R10 versions the instruction tuple to:

```text
(consumer_id, operation, exact_identity, direction, projection_row_id,
 source_file, source_anchor_digest, semantic_class, source_class,
 document_segment_id, document_candidate_id, document_candidate_kind,
 document_reach, instruction_role, identity_row_id,
 composition_component_ids, flow_instance_id, multiplicity_key,
 multiplicity_ordinal)
```

Arrays inside the tuple remain lexical. The digest is
`H("cut4.s.pi_instruction.v2", sorted_tuples)`. The S row schema v3 adds
`document_segment_id`, `document_candidate_kind`, `identity_row_id`, and
`composition_component_ids` to R9's document fields. A PATH_REFERENCE under a
model/tool/runtime/control directive maps to PATH_INSTRUCTION; a descriptive
PATH_REFERENCE maps to REFERENCE. CONTENT_REFERENCE maps to REFERENCE;
CONTENT_INSTRUCTION maps to CONTENT_INSTRUCTION; PROHIBITION maps to
PROHIBITION. A mismatch is rejected, not normalized. Candidate kind, reach,
source class, and role are independent tuple fields, so flipping any one
changes the projection.

After authorized edits, the final rescan uses a separately implemented
byte-range walker but the same sealed source/identity/form registries. It must
recompute exactly equal source-file, segment, candidate, and `pi_instruction`
multisets/digests. Equality requirements are:

```text
S source_files                 = final-rescan source_files
S document_segments            = final-rescan document_segments
S document_candidates          = final-rescan document_candidates
multiset(pi_instruction.v2(S)) = multiset(pi_instruction.v2(final rescan))
```

Equal nonempty parse/extraction debt still fails acceptance. P0, M3, and R3
bind the v3 S file/hash and all new registry/segment/candidate/instruction
digests. D9/membership are rederived after S freeze as R9 requires; no prior S,
M, R, membership, or D digest is assumed unchanged.

## 4. Continuation authority and realizable replay

### 4.1 Session-authority preimage v2

R9's immutable session core and `query_session_digest` remain unchanged. R10
versions the stable authority preimage to the exact body:

```text
schema=cut4.scip_query_session_preimage.v2, session_core,
query_session_digest, publication_contract_digest,
publication_commit_receipt_digest, p0_file_sha256,
semantic_manifest_file_sha256, authority_manifest_file_sha256,
authority_receipt_file_sha256, ledger_work_unit_key, ledger_attempt_key,
ledger_input_set_digest, ledger_output_set_digest,
ledger_completion_receipt_digest, index_size, index_sha256,
provider_outcome_status, provider_outcome_digest,
provider_explicit_zero_digest, materialized_consumer_row_digest,
query_registry_digest
```

`query_session_preimage_digest = H("cut4.query.session_preimage.v2", body)`.
Repeated session-core fields must be byte-equal. The ledger fields are read
from the existing completed registered publication operation; no new ledger
row or field is introduced. P0/S/M/R/L/publication bytes are validated at START
and again before every non-START page append.

### 4.2 c3 cursor and continuation equality

R10 c3 cursor body has exactly R9's c2 fields plus
`query_session_preimage_digest`, in the following schema:

```text
schema=cut4.query.cursor_body.v3, query_session_digest,
query_session_preimage_digest, consumer_row_id, query_id, index_identity,
index_sha256, next_page_ordinal, last_canonical_key, prior_page_digest,
cumulative_result_count, exhausted
```

The token is
`c3.<base64url(canonical_cursor_body)>.<cursor_integrity_digest>`, where the
digest domain is `cut4.query.cursor_integrity.v3`. Page construction remains
R9's nonrecursive page-body -> page-digest -> cursor-out order, with page-body
and record schemas versioned to v3 to repeat the session-preimage digest.

For every non-START invocation, before reader/index access, all of these must
hold simultaneously:

```text
current recomputed query_session_digest
  = request session digest
  = cursor-in session digest
  = prior envelope session digest
  = prior receipt session digest

current recomputed query_session_preimage_digest
  = request session-preimage digest
  = cursor-in session-preimage digest
  = prior envelope session-preimage digest
  = prior receipt session-preimage digest

current P0/S/M/R file hashes and current L/publication ledger fields
  = fields in current session preimage
  = authority fields committed by the prior envelope/receipt
```

The prior envelope is a declared PhaseIO immutable input and its full digest is
still checked as R9 requires. A change only to M, R, L, publication contract,
publication completion, or any other preimage-only field is
`CONTINUATION_AUTHORITY_CHANGED`, exit 3, with no evidence/receipt. It is never
a different invocation within the old chain. A new authority starts a new
START chain and cannot reuse an old c3 cursor.

### 4.3 Exact replay and terminal contract

The R10 invocation preimage is R9's exact preimage with c3 cursor bytes and the
v2 session-preimage digest. Define its canonical request digest as
`request_digest = H("cut4.query.invocation_request.v2", request_body)` and its
invocation digest as R9 specifies over that exact request authority.

Replay is total:

| input state | behavior |
|---|---|
| exact request digest already has a completed consumer-owned PhaseIO envelope | verify envelope authority/digest and return its exact bytes; no reader execution |
| exact request digest has no completed envelope because the first execution crashed before consumer commit | deterministic reexecution over the same index/session snapshot must emit byte-identical pages, evidence, receipt, and cursor-out |
| same cursor-in with any changed limit, argv, prior envelope, session preimage, or authority | different request; continuation authority must still match; never reuses prior invocation bytes |
| exhausted c3 token supplied as new cursor-in | reject `CURSOR_EXHAUSTED`, exit 2, no evidence or receipt |
| original final invocation request replayed with its original nonexhausted cursor-in and prior envelope | return the byte-identical final envelope and same exhausted cursor-out |

The deterministic reader fixes normalizer/parser/tool versions, index SHA,
query/scopes, result sort, page split, and all counters in the session and
request preimages. Time values are not output fields; timeout is a fixed input
limit and terminal class. Thus identical cursor-in request means identical
cursor-out, including after a pre-commit crash. The terminal exhausted
cursor-out is evidence, not a lookup handle. There is no ambient envelope
discovery, cursor cache, or exhausted-token replay exception.

The continuation-authority body has exactly:

```text
schema=cut4.query.continuation_authority.v1, request_digest,
query_session_digest, query_session_preimage_digest,
cursor_in_integrity_digest, prior_envelope_digest, prior_receipt_digest,
current_p0_file_sha256, current_s_file_sha256, current_m_file_sha256,
current_r_file_sha256, current_ledger_completion_receipt_digest,
current_publication_contract_digest, authority_equal=true
```

START uses `{}` and an empty digest. Non-START computes
`continuation_authority_digest = H("cut4.query.continuation_authority.v1",
body)`. Execution evidence v4 is exactly R9 evidence v3 with c3 cursor fields,
`request_digest`, `continuation_authority_body`, and
`continuation_authority_digest` appended before `terminal_error_code`. Receipt
v4 is exactly R9 receipt v3 with c3 cursor fields, `request_digest`, prior
envelope/receipt digests, and `continuation_authority_digest` appended before
`terminal_error_code`. Their digest domains are
`cut4.query.execution_evidence.v3` and `cut4.query.receipt.v4`. R9 terminal,
zero-proof, exit, argv/message, and provider-failure semantics remain unchanged.

## 5. Exact private authority graph

### 5.1 Predicate-inclusive Kp and plan rows

R10 private plan rows use schema `cut4.s.private_plan_row.v2`. Their exact
fields are:

```text
schema, private_plan_row_id, semantic_row_id, private_source_identity,
provider_id, consumer_id, flow_instance_id, multiplicity_key,
multiplicity_ordinal, applicability_predicate_id, selection_predicate_id,
accept_disposition, accept_projected_identity
```

The row ID is `"ppr:" + H("cut4.s.private_plan_row.v2", row_without_id)`.
R10's common key is exactly:

```text
Kp = (private_plan_row_id, semantic_row_id, private_source_identity,
      provider_id, consumer_id, flow_instance_id, multiplicity_key,
      multiplicity_ordinal, applicability_predicate_id,
      selection_predicate_id, accept_disposition,
      accept_projected_identity)
```

Every schema below explicitly described as carrying expanded Kp serializes
these twelve fields literally in that order; no nested `Kp` shorthand is
serialized. Registry, provider-outcome, and predicate-evidence rows instead
use their complete field lists below and join to Kp through their foreign keys.
Kp-ordered arrays reject a tie. Including both predicate IDs makes substitution
change the key. Including accepted disposition/target makes a changed target
fail the join before outcome mapping.

### 5.2 Exact registry/provider/evidence rows

The sealed provider plan has predicate-registry rows with exactly:

```text
schema=cut4.private_predicate_registry_row.v1, predicate_registry_row_id,
predicate_id, predicate_kind, provider_id, evaluator_id,
input_schema_digest, expression_digest, provider_plan_digest
```

`predicate_registry_row_id = "preg:" +
H("cut4.private.predicate_registry_row.v1", row_without_id)`. Rows sort by
`(provider_id,predicate_kind,predicate_id)` and use
`cut4.private.predicate_registry_rows.v1`.

Every fixed provider slot has exactly one provider-outcome row:

```text
schema=cut4.m.provider_outcome_row.v1, provider_outcome_row_id, provider_id,
provider_plan_digest, applicability_registry_digest,
selection_registry_digest, outcome_status, outcome_receipt_identity,
outcome_receipt_digest, explicit_zero_digest
```

The row ID/digest domains are `cut4.m.provider_outcome_row.v1` and
`cut4.m.provider_outcome_rows.v1`; rows sort by the inherited nine-provider
registry order, not discovery order. Receipt identity/digest are nonempty for
all six statuses. Explicit zero is nonempty only for a typed successful zero.

A predicate-evidence row has exactly:

```text
schema=cut4.m.predicate_evidence_row.v1, predicate_evidence_row_id,
private_plan_row_id, predicate_registry_row_id, predicate_id,
predicate_kind, provider_id, provider_outcome_row_id, predicate_result,
predicate_input_digest, evaluator_id, evaluator_version, evidence_digest
```

Its row/array domains are `cut4.m.predicate_evidence_row.v1` and
`cut4.m.predicate_evidence_rows.v1`; order is
`(private_plan_row_id,predicate_kind,predicate_id)`. Applicability has exactly
one evidence row per plan. Selection has exactly one iff applicability is TRUE;
otherwise its row ID/digest are empty in downstream rows and its result is
NOT_EVALUATED.

Each private candidate actually emitted by a successful provider has exactly:

```text
schema=cut4.m.provider_private_row.v1, provider_private_row_id,
private_plan_row_id, semantic_row_id, private_source_identity, provider_id,
consumer_id, flow_instance_id, multiplicity_key, multiplicity_ordinal,
applicability_predicate_id, selection_predicate_id, accept_disposition,
accept_projected_identity, provider_outcome_row_id,
provider_private_identity, provider_private_digest
```

Its row/array domains are `cut4.m.provider_private_row.v1` and
`cut4.m.provider_private_rows.v1`; rows sort by Kp projected from their resolved
plan, then provider-private identity. ACCEPTED/REJECTED evidence requires
exactly one such row. UNKNOWN and NOT_APPLICABLE require none. Every provider
private row must resolve exactly one plan of the same provider/outcome;
unplanned output is not ignored.

R10 private evidence rows use `cut4.m.private_evidence_row.v2`. They expand Kp
then contain exactly:

```text
applicability_predicate_registry_row_id,
applicability_predicate_evidence_row_id,
applicability_predicate_evidence_digest, applicability_result,
selection_predicate_registry_row_id,
selection_predicate_evidence_row_id,
selection_predicate_evidence_digest, selection_result,
provider_outcome_row_id, provider_outcome_status,
provider_private_row_id, private_row_status, private_normalizer_status,
provider_evidence_identity, provider_evidence_digest,
normalizer_evidence_digest
```

The full row begins `schema, private_evidence_row_id`, then expanded Kp, then
the listed fields. Its ID/domain are `cut4.m.private_evidence_row.v2` and
`cut4.m.private_evidence_rows.v2`. Empty fields follow the R9 state table:
`selection_predicate_registry_row_id` is always nonempty and resolves the
plan's selection predicate; selection evidence row ID/digest are empty only
when NOT_EVALUATED. Provider-private row is nonempty only for
ACCEPTED/REJECTED; normalizer evidence is nonempty only for ACCEPTED/REJECTED.
All named IDs and repeated predicate/provider/status fields must equal their
foreign rows byte-for-byte.

### 5.3 Exact consumer-plan-provider foreign keys

Define `pi_consumer_plan_ref` over every nonempty S consumer
`private_plan_row_ids` entry:

```text
(s_row_id, private_plan_row_id, consumer_id, provider_id, flow_instance_id,
 multiplicity_key, multiplicity_ordinal)
```

Define `pi_plan_ref` from every plan row using
`s_row_id=semantic_row_id` and the same remaining fields. Acceptance requires
exact multiset equality. Additionally, each plan's semantic row must exist,
list that plan ID exactly once, and match consumer, provider, flow instance,
multiplicity key, and ordinal. No plan is unreferenced and no S reference is
dangling.

For every plan:

```text
applicability_predicate_id resolves exactly one APPLICABILITY registry row
selection_predicate_id resolves exactly one SELECTION registry row
both predicate rows have plan.provider_id and the sealed provider-plan digest
plan.provider_id resolves exactly one fixed provider-outcome row
evidence.provider_outcome_row_id resolves that same row
evidence predicate IDs/registry IDs/evaluator IDs/results resolve exact rows
ACCEPTED/REJECTED resolves exactly one provider-private row
UNKNOWN/NOT_APPLICABLE resolves zero provider-private rows
```

The provider outcome roster remains the inherited fixed nine slots. Its
provider IDs, outcome status, and receipt digest are joined, not copied on
trust. An extra provider-private row, a predicate substitution, an accepted
target change, or a missing/extra plan reference creates an exact private diff
and semantic PRIVATE_FOREIGN_KEY_DEBT.

### 5.4 Exact disposition and projection rows

The disposition row schema is `cut4.m.private_disposition_row.v2`. It contains
`schema, private_disposition_row_id`, expanded Kp, every predicate/provider/
evidence reference and result field from the evidence row, then exactly:

```text
private_disposition, projected_identity, private_debt_id, private_debt_code
```

Its row/array domains are `cut4.m.private_disposition_row.v2` and
`cut4.m.private_disposition_rows.v2`. R9's total status table is unchanged and
derives these final four fields from the plan and joined evidence.

`pi_private` materializes rather than serializes an anonymous tuple. Each
projection row has exactly:

```text
schema=cut4.m.private_projection_row.v1, private_projection_row_id,
<expanded Kp>, applicability_predicate_registry_row_id,
applicability_predicate_evidence_row_id,
applicability_predicate_evidence_digest, applicability_result,
selection_predicate_registry_row_id, selection_predicate_evidence_row_id,
selection_predicate_evidence_digest, selection_result,
provider_outcome_row_id, provider_outcome_status, provider_private_row_id,
private_row_status, private_normalizer_status, provider_evidence_identity,
provider_evidence_digest, normalizer_evidence_digest, private_disposition,
projected_identity, private_debt_id, private_debt_code
```

`private_projection_row_id = "pprj:" +
H("cut4.m.private_projection_row.v1", row_without_id)`. Rows sort by expanded
Kp and use `H("cut4.m.private_projection_rows.v1", rows)`. Projection derived
from evidence joined to plan/registries/provider must equal projection derived
from disposition, field for field. NOT_APPLICABLE still requires the neutral
row and nonempty applicability evidence but no selection/provider/private/
normalizer evidence, projection, or debt.

### 5.5 Closed private diff and completion bytes

A diff row has exactly the following expanded object; `expected_row_digest`
or `observed_row_digest` is empty only when that side is absent:

```json
{
  "schema": "cut4.m.private_diff_row.v2",
  "private_diff_row_id": "pdiff:<sha256>",
  "private_plan_row_id": "ppr:<sha256>",
  "semantic_row_id": "row:<sha256>",
  "private_source_identity": "<identity>",
  "provider_id": "source_graph",
  "consumer_id": "<id>",
  "flow_instance_id": "<id>",
  "multiplicity_key": "mul:<sha256>",
  "multiplicity_ordinal": 0,
  "applicability_predicate_id": "<id>",
  "selection_predicate_id": "<id>",
  "accept_disposition": "COMPATIBILITY_PROJECTED",
  "accept_projected_identity": "<identity>",
  "diff_kind": "PREDICATE_FOREIGN_KEY_MISMATCH",
  "expected_row_digest": "<sha256-or-empty>",
  "observed_row_digest": "<sha256-or-empty>",
  "expected_count": 1,
  "observed_count": 1,
  "debt_code": "PRIVATE_FOREIGN_KEY_DEBT"
}
```

`private_diff_row_id = "pdiff:" + H("cut4.m.private_diff_row.v2",
row_without_id)`. Rows sort by `(expanded Kp,diff_kind,private_diff_row_id)`;
array domain is `cut4.m.private_diff_rows.v2`. An empty diff array is encoded
as `[]` and hashed, never as an empty string.

An R private completion row has exactly:

```text
schema=cut4.r.private_completion_row.v2, private_completion_row_id,
<expanded Kp>, provider_outcome_row_id,
applicability_predicate_evidence_row_id,
selection_predicate_evidence_row_id, provider_private_row_id,
private_evidence_row_id, private_disposition_row_id,
private_projection_row_id, private_row_status, private_disposition,
completion_status=MATERIALIZED
```

`private_completion_row_id = "pcomp:" +
H("cut4.r.private_completion_row.v2", row_without_id)`. Rows sort by expanded
Kp; array domain is `cut4.r.private_completion_rows.v2`. Every ID is a foreign
key to M3; empty selection/provider-private IDs are allowed only by the R9
state table.

### 5.6 Complete M3 and R3 bodies

M3 has exactly the following top-level fields. This list is field membership;
wire encoding still code-point-sorts object keys:

```text
schema=cut4.recon_compatibility_projection_manifest.v3,
run_id, publication_work_unit_key, publication_contract_digest,
p0_binding, semantic_manifest_binding, query_registry_digest,
data_roster, data_roster_digest, data_rows, data_set_digest,
consumer_rows, consumer_rows_digest, membership_rows, membership_rows_digest,
provider_outcome_rows, provider_outcome_rows_digest,
predicate_registry_rows, predicate_registry_rows_digest,
predicate_evidence_rows, predicate_evidence_rows_digest,
provider_private_rows, provider_private_rows_digest,
private_evidence_rows, private_evidence_rows_digest,
private_disposition_rows, private_disposition_rows_digest,
private_projection_rows, private_projection_rows_digest,
private_diff_rows, private_diff_rows_digest,
has_open_private_debt, control_slots
```

P0/S bindings are the exact R9 bindings plus R10 source-root, identity/form,
segment, candidate, `pi_instruction.v2`, predicate-registry, and private-plan
digests. R8/R9 data, consumer, membership, and control-slot schemas remain
exact. The new array domains are those specified above.
`has_open_private_debt=true` iff at least one projection row has OPEN_DEBT;
neutral NOT_APPLICABLE does not set it. M contains no M/R self hash; its final
ordinary file SHA is recorded externally by PhaseIO/L.

R3 has exactly:

```text
schema=cut4.recon_compatibility_projection_receipt.v3,
run_id, publication_work_unit_key, publication_contract_digest,
p0_binding, semantic_manifest_binding, query_registry_digest,
manifest_binding, data_completion_rows, data_completion_rows_digest,
consumer_completion_rows, consumer_completion_rows_digest,
membership_completion_rows, membership_completion_rows_digest,
provider_outcome_rows_digest, predicate_registry_rows_digest,
predicate_evidence_rows_digest, provider_private_rows_digest,
private_evidence_rows_digest, private_disposition_rows_digest,
private_projection_rows_digest, private_diff_rows_digest,
private_completion_rows, private_completion_rows_digest,
data_set_digest, consumer_rows_digest, membership_rows_digest,
has_open_private_debt, control_slots
```

`manifest_binding` has M identity, size, and file SHA. R's inherited data,
consumer, and membership completion rows remain exact. R repeats every listed
M digest and flag byte-for-byte, and its private completion array must have
exactly the M projection Kp multiset. Control slots remain self-excluded as in
R8. SP atomically seals D9+M3+R3; L remains the existing outer completion
authority.

Acceptance requires all of these independently:

```text
multiset(pi_consumer_plan_ref(S consumer refs)) = multiset(pi_plan_ref(S plans))
every plan predicate/provider foreign key resolves exactly once
every provider-private row resolves exactly one successful plan/outcome
multiset(expanded Kp: S plans) = evidence = disposition = projection = completion
projection(evidence + plan + registries + provider) = projection(disposition)
all M3/R3 repeated digests and has_open_private_debt flags are equal
private_diff_rows = []
```

Equal nonempty semantic debt still fails. Correctly reconciled REJECTED/UNKNOWN
OPEN debt may publish with the flag but is never positive/absence evidence.
Neutral NOT_APPLICABLE is neither evidence nor debt and still occupies its
fixed key.

## 6. Supported construction order and ownership

R10 does not change the supported PhaseIO/ArtifactLedger order:

1. DRIVER classifies the scratchpad read-only before mutation.
2. The single cutover owner edits all registered paths/instructions.
3. It compiles/seals source, identity, form, predicate, provider, and output
   registries; performs the total final rescan; freezes S v3; seals P0.
4. Fixed providers receive exact P0/private inputs and emit typed outcomes only.
5. The DRIVER canonical-publication-v2 owner validates all foreign keys,
   constructs D9/M3/R3/SP, and completes the existing registered operation.
6. Query consumers bind P0/S/M/R/L and prior envelopes as PhaseIO inputs and
   persist returned bytes only in their own PhaseIO outputs.

No manual attempt key, frozen-ledger mutation, public glob, post-write
discovery, query session file, co-owned request, provider/direct project-root
mutation, or new writer exists. MODEL shards, dependency units, fixed provider
IDs, public paths, compatibility ownership, state branches, and legacy
nonadoption are unchanged.

## 7. Recall, precision, failures, and non-goals

Recall improves because authenticated document bytes now have an exhaustive
segment/candidate denominator. A matcher miss becomes a row and debt rather
than absence; independent `pi_instruction.v2` equality detects every
candidate/reach/role/source mutation. Private recall is one-to-one from S
consumer reference through provider evidence and R completion, so no found
private output or consumer can be orphaned.

Precision remains bounded by exact byte offsets, sealed identity/grammar rows,
explicit NO_RECON_REFERENCE proofs, independent rescan equality, pinned query
snapshots, deterministic cursor order, predicate evidence, and typed neutral/
debt states. Unrecognized documentation and provider/query failure, timeout,
malformation, or authority drift never degrade to empty success.

R10 authorizes no code, test, fixture execution, prior edit, ArtifactLedger,
G3, provider, audit, project-root mutation, commit, push, install, cutover,
release, or readiness action. It does not change methodology prose/roles,
MODEL shards, dependency units, provider IDs, output paths, public/canonical
ownership, or legacy bytes.

## 8. Exact R10 test roster

The JSON object contains exactly **180** unique literal pytest node IDs: 48
document-totality, 42 continuation/replay, 78 private-authority, and 12
regression nodes. There are no wildcards or implied/predecessor nodes.

```json
{
  "document_totality": [
    "tests/test_cut4_r10_document_totality.py::test_source_root_registry_exact_six",
    "tests/test_cut4_r10_document_totality.py::test_source_root_registry_order_digest",
    "tests/test_cut4_r10_document_totality.py::test_source_file_v3_exact_schema",
    "tests/test_cut4_r10_document_totality.py::test_source_file_v3_id_domain",
    "tests/test_cut4_r10_document_totality.py::test_source_file_single_root_membership",
    "tests/test_cut4_r10_document_totality.py::test_docs_all_regular_files_denominator",
    "tests/test_cut4_r10_document_totality.py::test_source_symlink_alias_debt",
    "tests/test_cut4_r10_document_totality.py::test_identity_registry_exact_schema",
    "tests/test_cut4_r10_document_totality.py::test_identity_registry_all_input_digests_bound",
    "tests/test_cut4_r10_document_totality.py::test_identity_registry_order_digest",
    "tests/test_cut4_r10_document_totality.py::test_identity_spelling_collision_rejected",
    "tests/test_cut4_r10_document_totality.py::test_candidate_form_registry_exact_eight",
    "tests/test_cut4_r10_document_totality.py::test_candidate_form_registry_order_digest",
    "tests/test_cut4_r10_document_totality.py::test_segment_schema_exact",
    "tests/test_cut4_r10_document_totality.py::test_segment_id_domain",
    "tests/test_cut4_r10_document_totality.py::test_segment_raw_digest_domain",
    "tests/test_cut4_r10_document_totality.py::test_segment_text_digest_domain",
    "tests/test_cut4_r10_document_totality.py::test_segment_byte_partition_complete",
    "tests/test_cut4_r10_document_totality.py::test_segment_overlap_rejected",
    "tests/test_cut4_r10_document_totality.py::test_segment_gap_becomes_debt",
    "tests/test_cut4_r10_document_totality.py::test_empty_file_segment_rule",
    "tests/test_cut4_r10_document_totality.py::test_segment_precedence_deterministic",
    "tests/test_cut4_r10_document_totality.py::test_path_token_grammar_exact",
    "tests/test_cut4_r10_document_totality.py::test_placeholder_composition_exact",
    "tests/test_cut4_r10_document_totality.py::test_module_token_grammar_exact",
    "tests/test_cut4_r10_document_totality.py::test_content_token_sequence_exact",
    "tests/test_cut4_r10_document_totality.py::test_directive_grammar_digest_bound",
    "tests/test_cut4_r10_document_totality.py::test_prohibition_grammar_digest_bound",
    "tests/test_cut4_r10_document_totality.py::test_candidate_v2_exact_schema",
    "tests/test_cut4_r10_document_totality.py::test_candidate_v2_id_domain",
    "tests/test_cut4_r10_document_totality.py::test_one_base_candidate_per_segment",
    "tests/test_cut4_r10_document_totality.py::test_every_reference_has_candidate",
    "tests/test_cut4_r10_document_totality.py::test_positive_matcher_miss_becomes_debt",
    "tests/test_cut4_r10_document_totality.py::test_unrecognized_instruction_becomes_debt",
    "tests/test_cut4_r10_document_totality.py::test_parse_failure_becomes_debt",
    "tests/test_cut4_r10_document_totality.py::test_negative_proof_exact_conditions",
    "tests/test_cut4_r10_document_totality.py::test_negative_disposition_registry_bound",
    "tests/test_cut4_r10_document_totality.py::test_candidate_totality_equations",
    "tests/test_cut4_r10_document_totality.py::test_s_v3_binds_all_candidate_registries",
    "tests/test_cut4_r10_document_totality.py::test_pi_instruction_v2_exact_tuple",
    "tests/test_cut4_r10_document_totality.py::test_pi_instruction_v2_digest_domain",
    "tests/test_cut4_r10_document_totality.py::test_pi_instruction_path_content_flip_detected",
    "tests/test_cut4_r10_document_totality.py::test_pi_instruction_candidate_id_flip_detected",
    "tests/test_cut4_r10_document_totality.py::test_pi_instruction_reach_flip_detected",
    "tests/test_cut4_r10_document_totality.py::test_pi_instruction_source_class_flip_detected",
    "tests/test_cut4_r10_document_totality.py::test_independent_rescan_segment_equality",
    "tests/test_cut4_r10_document_totality.py::test_independent_rescan_candidate_equality",
    "tests/test_cut4_r10_document_totality.py::test_equal_nonempty_document_debt_fails"
  ],
  "continuation_replay": [
    "tests/test_cut4_r10_continuation_replay.py::test_session_preimage_v2_exact_schema",
    "tests/test_cut4_r10_continuation_replay.py::test_session_preimage_v2_digest_domain",
    "tests/test_cut4_r10_continuation_replay.py::test_preimage_binds_p0_s_m_r",
    "tests/test_cut4_r10_continuation_replay.py::test_preimage_binds_ledger_publication_fields",
    "tests/test_cut4_r10_continuation_replay.py::test_preimage_repeated_core_equality",
    "tests/test_cut4_r10_continuation_replay.py::test_cursor_v3_exact_schema",
    "tests/test_cut4_r10_continuation_replay.py::test_cursor_v3_integrity_domain",
    "tests/test_cut4_r10_continuation_replay.py::test_cursor_binds_session_preimage",
    "tests/test_cut4_r10_continuation_replay.py::test_page_v3_repeats_session_preimage",
    "tests/test_cut4_r10_continuation_replay.py::test_nonstart_current_prior_preimage_equal",
    "tests/test_cut4_r10_continuation_replay.py::test_nonstart_cursor_preimage_equal",
    "tests/test_cut4_r10_continuation_replay.py::test_nonstart_envelope_preimage_equal",
    "tests/test_cut4_r10_continuation_replay.py::test_nonstart_receipt_preimage_equal",
    "tests/test_cut4_r10_continuation_replay.py::test_nonstart_current_m_hash_revalidated",
    "tests/test_cut4_r10_continuation_replay.py::test_nonstart_current_r_hash_revalidated",
    "tests/test_cut4_r10_continuation_replay.py::test_nonstart_current_l_authority_revalidated",
    "tests/test_cut4_r10_continuation_replay.py::test_nonstart_publication_contract_revalidated",
    "tests/test_cut4_r10_continuation_replay.py::test_changed_only_m_rejected",
    "tests/test_cut4_r10_continuation_replay.py::test_changed_only_r_rejected",
    "tests/test_cut4_r10_continuation_replay.py::test_changed_only_l_rejected",
    "tests/test_cut4_r10_continuation_replay.py::test_changed_only_publication_receipt_rejected",
    "tests/test_cut4_r10_continuation_replay.py::test_authority_change_exit3_no_receipt",
    "tests/test_cut4_r10_continuation_replay.py::test_old_cursor_for_new_start_rejected",
    "tests/test_cut4_r10_continuation_replay.py::test_request_digest_v2_domain",
    "tests/test_cut4_r10_continuation_replay.py::test_identical_request_completed_replay",
    "tests/test_cut4_r10_continuation_replay.py::test_identical_request_crash_reexecution",
    "tests/test_cut4_r10_continuation_replay.py::test_identical_request_same_pages",
    "tests/test_cut4_r10_continuation_replay.py::test_identical_request_same_evidence",
    "tests/test_cut4_r10_continuation_replay.py::test_identical_request_same_receipt",
    "tests/test_cut4_r10_continuation_replay.py::test_identical_request_same_cursor_out",
    "tests/test_cut4_r10_continuation_replay.py::test_changed_invocation_limit_new_request",
    "tests/test_cut4_r10_continuation_replay.py::test_changed_argv_new_request",
    "tests/test_cut4_r10_continuation_replay.py::test_changed_prior_envelope_new_request",
    "tests/test_cut4_r10_continuation_replay.py::test_exhausted_cursor_in_rejected",
    "tests/test_cut4_r10_continuation_replay.py::test_exhausted_cursor_exit2_no_receipt",
    "tests/test_cut4_r10_continuation_replay.py::test_final_replay_uses_original_cursor_in",
    "tests/test_cut4_r10_continuation_replay.py::test_final_replay_same_exhausted_cursor_out",
    "tests/test_cut4_r10_continuation_replay.py::test_no_ambient_terminal_lookup",
    "tests/test_cut4_r10_continuation_replay.py::test_evidence_v4_binds_authority_chain",
    "tests/test_cut4_r10_continuation_replay.py::test_receipt_v4_binds_authority_chain",
    "tests/test_cut4_r10_continuation_replay.py::test_start_partial_resume_end_preserved",
    "tests/test_cut4_r10_continuation_replay.py::test_success_empty_requires_same_authority_chain"
  ],
  "private_authority": [
    "tests/test_cut4_r10_private_authority.py::test_private_plan_v2_exact_schema",
    "tests/test_cut4_r10_private_authority.py::test_private_plan_v2_id_domain",
    "tests/test_cut4_r10_private_authority.py::test_kp_includes_applicability_predicate",
    "tests/test_cut4_r10_private_authority.py::test_kp_includes_selection_predicate",
    "tests/test_cut4_r10_private_authority.py::test_kp_includes_accept_disposition",
    "tests/test_cut4_r10_private_authority.py::test_kp_includes_accept_target",
    "tests/test_cut4_r10_private_authority.py::test_private_plan_order_by_expanded_kp",
    "tests/test_cut4_r10_private_authority.py::test_predicate_registry_exact_schema",
    "tests/test_cut4_r10_private_authority.py::test_predicate_registry_id_domain",
    "tests/test_cut4_r10_private_authority.py::test_predicate_registry_order_digest",
    "tests/test_cut4_r10_private_authority.py::test_predicate_provider_plan_bound",
    "tests/test_cut4_r10_private_authority.py::test_provider_outcome_exact_schema",
    "tests/test_cut4_r10_private_authority.py::test_provider_outcome_exact_nine",
    "tests/test_cut4_r10_private_authority.py::test_provider_outcome_id_domain",
    "tests/test_cut4_r10_private_authority.py::test_provider_outcome_registry_order",
    "tests/test_cut4_r10_private_authority.py::test_provider_receipt_nonempty_all_statuses",
    "tests/test_cut4_r10_private_authority.py::test_predicate_evidence_exact_schema",
    "tests/test_cut4_r10_private_authority.py::test_predicate_evidence_id_domain",
    "tests/test_cut4_r10_private_authority.py::test_applicability_evidence_exactly_one",
    "tests/test_cut4_r10_private_authority.py::test_selection_evidence_true_only",
    "tests/test_cut4_r10_private_authority.py::test_predicate_substitution_detected",
    "tests/test_cut4_r10_private_authority.py::test_predicate_evaluator_mismatch_detected",
    "tests/test_cut4_r10_private_authority.py::test_provider_private_exact_schema",
    "tests/test_cut4_r10_private_authority.py::test_provider_private_id_domain",
    "tests/test_cut4_r10_private_authority.py::test_provider_private_success_join",
    "tests/test_cut4_r10_private_authority.py::test_provider_private_extra_detected",
    "tests/test_cut4_r10_private_authority.py::test_provider_private_missing_detected",
    "tests/test_cut4_r10_private_authority.py::test_provider_private_wrong_plan_detected",
    "tests/test_cut4_r10_private_authority.py::test_private_evidence_v2_exact_schema",
    "tests/test_cut4_r10_private_authority.py::test_private_evidence_v2_id_domain",
    "tests/test_cut4_r10_private_authority.py::test_evidence_predicate_fields_equal_plan",
    "tests/test_cut4_r10_private_authority.py::test_evidence_accept_target_equal_plan",
    "tests/test_cut4_r10_private_authority.py::test_evidence_provider_outcome_foreign_key",
    "tests/test_cut4_r10_private_authority.py::test_evidence_provider_private_foreign_key",
    "tests/test_cut4_r10_private_authority.py::test_consumer_plan_ref_projection_exact",
    "tests/test_cut4_r10_private_authority.py::test_plan_ref_projection_exact",
    "tests/test_cut4_r10_private_authority.py::test_consumer_plan_ref_equality",
    "tests/test_cut4_r10_private_authority.py::test_missing_consumer_plan_ref_detected",
    "tests/test_cut4_r10_private_authority.py::test_extra_consumer_plan_ref_detected",
    "tests/test_cut4_r10_private_authority.py::test_orphan_plan_detected",
    "tests/test_cut4_r10_private_authority.py::test_dangling_plan_reference_detected",
    "tests/test_cut4_r10_private_authority.py::test_plan_semantic_row_id_mismatch",
    "tests/test_cut4_r10_private_authority.py::test_plan_consumer_id_mismatch",
    "tests/test_cut4_r10_private_authority.py::test_plan_provider_id_mismatch",
    "tests/test_cut4_r10_private_authority.py::test_plan_flow_instance_mismatch",
    "tests/test_cut4_r10_private_authority.py::test_plan_multiplicity_mismatch",
    "tests/test_cut4_r10_private_authority.py::test_disposition_v2_exact_schema",
    "tests/test_cut4_r10_private_authority.py::test_disposition_v2_id_domain",
    "tests/test_cut4_r10_private_authority.py::test_projection_row_exact_schema",
    "tests/test_cut4_r10_private_authority.py::test_projection_row_id_domain",
    "tests/test_cut4_r10_private_authority.py::test_projection_row_order_digest",
    "tests/test_cut4_r10_private_authority.py::test_evidence_disposition_projection_equal",
    "tests/test_cut4_r10_private_authority.py::test_not_applicable_foreign_keys_total",
    "tests/test_cut4_r10_private_authority.py::test_not_applicable_neutral_fields_empty",
    "tests/test_cut4_r10_private_authority.py::test_unknown_no_provider_private_row",
    "tests/test_cut4_r10_private_authority.py::test_accepted_requires_provider_private_row",
    "tests/test_cut4_r10_private_authority.py::test_rejected_requires_provider_private_row",
    "tests/test_cut4_r10_private_authority.py::test_private_diff_v2_exact_schema",
    "tests/test_cut4_r10_private_authority.py::test_private_diff_v2_id_domain",
    "tests/test_cut4_r10_private_authority.py::test_private_diff_order_digest",
    "tests/test_cut4_r10_private_authority.py::test_private_diff_empty_array_digest",
    "tests/test_cut4_r10_private_authority.py::test_completion_v2_exact_schema",
    "tests/test_cut4_r10_private_authority.py::test_completion_v2_id_domain",
    "tests/test_cut4_r10_private_authority.py::test_completion_order_digest",
    "tests/test_cut4_r10_private_authority.py::test_completion_all_foreign_keys",
    "tests/test_cut4_r10_private_authority.py::test_m3_exact_top_level_fields",
    "tests/test_cut4_r10_private_authority.py::test_m3_rejects_extra_field",
    "tests/test_cut4_r10_private_authority.py::test_m3_all_private_digest_domains",
    "tests/test_cut4_r10_private_authority.py::test_m3_open_debt_flag_derived",
    "tests/test_cut4_r10_private_authority.py::test_r3_exact_top_level_fields",
    "tests/test_cut4_r10_private_authority.py::test_r3_rejects_extra_field",
    "tests/test_cut4_r10_private_authority.py::test_r3_repeats_every_m3_digest",
    "tests/test_cut4_r10_private_authority.py::test_r3_completion_matches_projection_kp",
    "tests/test_cut4_r10_private_authority.py::test_independent_m3_encoder_equality",
    "tests/test_cut4_r10_private_authority.py::test_independent_r3_encoder_equality",
    "tests/test_cut4_r10_private_authority.py::test_private_all_key_multisets_equal",
    "tests/test_cut4_r10_private_authority.py::test_private_complete_no_orphan",
    "tests/test_cut4_r10_private_authority.py::test_equal_nonempty_private_debt_fails"
  ],
  "regression": [
    "tests/test_cut4_r10_regression.py::test_r9_docs_root_preserved",
    "tests/test_cut4_r10_regression.py::test_r9_immutable_session_core_preserved",
    "tests/test_cut4_r10_regression.py::test_r9_neutral_not_applicable_preserved",
    "tests/test_cut4_r10_regression.py::test_r8_s_to_m_projection_preserved",
    "tests/test_cut4_r10_regression.py::test_r8_membership_d_order_preserved",
    "tests/test_cut4_r10_regression.py::test_r8_query_zero_separation_preserved",
    "tests/test_cut4_r10_regression.py::test_r7_single_owner_preserved",
    "tests/test_cut4_r10_regression.py::test_r6_state_machine_preserved",
    "tests/test_cut4_r10_regression.py::test_r6_provider_roster_preserved",
    "tests/test_cut4_r10_regression.py::test_legacy_nonadoption_preserved",
    "tests/test_cut4_r10_regression.py::test_artifact_ledger_unchanged",
    "tests/test_cut4_r10_regression.py::test_no_project_root_mutation"
  ]
}
```

Execution is document totality, continuation/replay, private authority, then
regressions. A future fixture worker may own only the new R10 RED fixtures and
evidence. The single future implementation owner retains atomic ownership of
all callsite edits, S/P0 freeze, D/M/R construction, and canonical commit.
