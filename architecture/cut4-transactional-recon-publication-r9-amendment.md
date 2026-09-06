# Cut-4 transactional recon publication R9 amendment

Date: 2026-08-10
Status: Part-0 R9 architecture repair only
Supersedes: only the repaired clauses of the R8 amendment
Authority: design for independent review; no fixture, production, test,
ArtifactLedger, G3, provider, audit, commit, push, install, cutover, release,
or audit-readiness authority

## 0. Decision and inherited boundary

R9 closes the three blockers in the mandatory R8 independent review. Except
where this amendment explicitly versions a schema or digest, R8 remains the
controlling design. In particular, R9 preserves R8's exact S-to-M projection,
membership-before-D construction, deliberately rederived D commitment,
canonical multiplicity, query-zero/provider-zero separation, and exact
equality/diff gates. It also preserves the accepted R7 post-edit S freeze and
single owner and every earlier R6 state, provider-roster, PhaseIO, publication,
compatibility, crash, legacy, and containment repair.

R9 makes only these repairs:

1. `docs/` is an authenticated member of the closed semantic source universe.
   Every path/content candidate in an operator document is classified as an
   exact model, tool, runtime, control, nonexecuting-reference, or unresolved
   reach. Omission is impossible: unresolved reach is typed blocking debt.
2. Query session identity is computed only from immutable session core fields.
   START establishes that content-addressed identity; every later invocation
   recomputes it unchanged. A non-START cursor binds the session, next page,
   last canonical key, prior page, cumulative count, exhaustion, and its own
   integrity digest, while a prior PhaseIO receipt authenticates continuation.
3. `NOT_APPLICABLE` is an inhabitable neutral private state. Static private
   plans live in frozen S; run-dependent evidence, dispositions, diffs, and
   digests live in post-provider M/R. Exact schemas and a total field mapping
   make every private state one-to-one and no-orphan checkable.

Section 8 is a new, closed **160-node** R9 roster. R8's 140 nodes and all older
rosters remain predecessor regressions and are not counted in 160.

## 1. Authenticated repair input

The mandatory R8 independent review was read end to end before this amendment
was written. It is 20,172 bytes and SHA-256
`3f0c3c6fa7072f422359efb406dd725acdd273dec7cd975ac161bfe21659394`:

`review_fixtures/cut4_transactional_recon_publication_r8_amendment_independent_review_20260810.md`.

The reviewed R8 amendment is 41,201 bytes and SHA-256
`6ab8a189149cc99ea4055ad2e2d1aa48798bc505df6ff3b9c7f1a2cb36c66d76`.
Its receipt is 2,724 bytes and SHA-256
`6a90050c48e7a1516a925a8df6ebe52332a98fb0515eabc07f5f1960177edc8f`.
The review accepted R8's S/M/R row mechanics, acyclic membership-to-D
construction, initial query expressibility, and non-private multiplicity and
projection domains. R9 does not reopen them.

The review mechanically reproduced 574 relevant literals in 68 files and 24
hits in these authenticated operator documents:

```text
docs/design/recall-build-plan.md
docs/internals.md
docs/l1-mode/design.md
```

Those files are not special exceptions. They demonstrate why the whole closed
`docs` root must be authenticated and classified.

## 2. Canonical encoding and closed enums

R8 canonical JSON and `H(domain, value)` remain exact: UTF-8, NFC strings, LF,
no BOM, code-point-sorted object keys, schema-ordered arrays, integers only,
lowercase 64-hex SHA-256, and no duplicate key, nonfinite number, implicit
null, or extra field.

R9 replaces only the affected closed enums. All unlisted R8 enum members remain
unchanged.

```json
{
  "source_class": ["CODE", "METHODOLOGY", "PROMPT_TEMPLATE", "COMMAND_TEMPLATE", "OPERATOR_DOCUMENT"],
  "document_reach": ["NONE", "MODEL", "TOOL", "RUNTIME", "CONTROL", "UNRESOLVED"],
  "instruction_role": ["NONE", "PATH_INSTRUCTION", "CONTENT_INSTRUCTION", "PROHIBITION", "REFERENCE"],
  "semantic_class": ["RUNTIME_IO", "PHASEIO_INPUT", "PHASEIO_OUTPUT", "PROMPT_PATH", "MECHANICAL_COMMAND", "SUBPROCESS_QUERY", "VALIDATOR", "NONEXECUTING_EXAMPLE", "PROHIBITION", "CONTROL_AUTHORITY", "DOC_MODEL_INSTRUCTION", "DOC_TOOL_INSTRUCTION", "DOC_RUNTIME_INSTRUCTION", "DOC_CONTROL_INSTRUCTION", "DOC_NONEXECUTING_REFERENCE", "DOC_REACHABILITY_DEBT"],
  "private_row_status": ["ACCEPTED", "REJECTED", "UNKNOWN", "NOT_APPLICABLE"],
  "private_disposition": ["CANONICAL_PROJECTED", "COMPATIBILITY_PROJECTED", "RETAINED_PRIVATE", "OPEN_DEBT", "NEUTRAL_NOT_APPLICABLE"],
  "predicate_result": ["TRUE", "FALSE", "NOT_EVALUATED"],
  "provider_outcome_status": ["NOT_APPLICABLE", "NOT_SELECTED", "SUCCESS", "FAILURE", "TIMEOUT", "MALFORMED"],
  "private_normalizer_status": ["ACCEPTED", "REJECTED", "NOT_EVALUATED"],
  "private_debt_code": ["NONE", "PRIVATE_REJECTED", "PRIVATE_NOT_SELECTED", "PRIVATE_PROVIDER_FAILURE", "PRIVATE_PROVIDER_TIMEOUT", "PRIVATE_PROVIDER_MALFORMED"],
  "query_terminal_state": ["SUCCESS", "PARTIAL", "NOT_APPLICABLE", "DEBT", "FAILURE", "TIMEOUT", "MALFORMED"],
  "query_start_state": ["NOT_STARTED", "STARTED"],
  "r9_added_semantic_debt_code": ["UNRESOLVED_DOC_REACHABILITY_DEBT", "DOC_CANDIDATE_OMISSION_DEBT", "PRIVATE_DISPOSITION_DEBT", "PRIVATE_MULTIPLICITY_DEBT"]
}
```

The two private enums are distinct: `private_debt_code` describes a completely
accounted provider/application outcome and may be published as typed OPEN debt;
R8/R9 semantic `debt_code` describes a reconciliation defect and blocks
acceptance. `NOT_APPLICABLE` is never a debt code.

## 3. Closed S source universe and document semantics

### 3.1 S v2 body and source authentication

S is still generated and frozen only after all authorized callsite and path
instruction edits. The R9 body is versioned and has exactly:

```json
{
  "schema": "cut4.recon_consumer_manifest.v2",
  "analyzer_version": "<pinned>",
  "normalization_version": "cut4.semantic_normalization.v2",
  "source_roots": ["agents", "commands", "docs", "plamen_l1", "prompts", "scripts"],
  "source_files": [],
  "source_tree_digest": "<sha256>",
  "document_candidate_rows": [],
  "document_candidate_rows_digest": "<sha256>",
  "query_registry": [],
  "query_registry_digest": "<sha256>",
  "rows": [],
  "row_set_digest": "<sha256>",
  "exec_tuple_set_digest": "<sha256>",
  "instruction_tuple_set_digest": "<sha256>",
  "debt_tuple_set_digest": "<sha256>",
  "owner_tuple_set_digest": "<sha256>",
  "private_plan_rows": [],
  "private_plan_rows_digest": "<sha256>",
  "private_tuple_set_digest": "<sha256>"
}
```

The final file schema is `cut4.recon_consumer_manifest_file.v2`, and
`semantic_manifest_digest = H("cut4.s.manifest.v2", S_body)`. P0 v3 binds the
ordinary S file size/SHA-256, manifest digest, source-tree digest, document
candidate digest, row-set digest, four ordinary tuple digests, private-plan
rows digest, private-plan tuple digest, and query-registry digest.

For all six roots, `source_files` contains every recursively reachable regular
file after canonical project-relative path normalization. There is no extension
allowlist for `docs`, no ignored doc subtree, no glob-derived exclusion, and no
symlink traversal. A symlink, unreadable file, invalid UTF-8 text candidate, or
unparseable instruction container produces typed debt; it is not skipped. The
only exclusions remain S itself and registered generated output/test roots,
whose exact paths are sealed before the walk. Rows have exact `path`, `size`,
and `sha256`, sort by path, and use
`H("cut4.s.source_tree.v2", source_files)`.

### 3.2 Exact document candidate and semantic row

The analyzer tokenizes every UTF-8 operator document into fenced-code,
inline-code, table-cell, link-target, heading, list-item, blockquote, and prose
spans. Every literal or composed reference to a registered private/public recon
identity, basename, path prefix, CLI/module, prompt placeholder, producer,
consumer, or retired alias creates exactly one candidate per source span and
referenced identity. A candidate has exactly:

```text
schema, candidate_id, source_file, source_file_sha256, source_anchor_digest,
span_kind, span_ordinal, referenced_identity, identity_origin,
instruction_role, candidate_text_digest
```

The schema is `cut4.s.document_candidate.v1`.
`candidate_id = "docc:" + H("cut4.s.document_candidate.v1",
candidate_without_id)`. `candidate_text_digest` hashes the NFC span with domain
`cut4.s.document_candidate_text.v1`; raw prose is not copied into S. Candidate
rows sort by `(source_file, span_ordinal, referenced_identity, candidate_id)`;
their array digest uses `cut4.s.document_candidates.v1`.

R8's S consumer row is versioned to `cut4.recon_consumer_row.v2`. It has
exactly these fields, in schema order:

```text
schema, row_id, row_kind, consumer_id, operation, exact_identity, direction,
producer_id, owner_kind, projection_row_id, required_phase_gate, probe_id,
flow_edge_id, flow_instance_id, endpoint, multiplicity_key,
multiplicity_ordinal, identity_origin, source_file, source_anchor_digest,
semantic_class, allowed_query_ids, scope_ids, provider_id, debt_id, debt_code,
source_class, document_candidate_id, document_reach, instruction_role,
private_plan_row_ids
```

`private_plan_row_ids` is a lexical unique array of static S private-plan IDs,
or empty. Run-dependent `private_row_status` and `private_disposition` are not S
consumer-row fields in v2. The other field meanings, empty-value rules, row-ID
construction, common multiplicity calculation, and R8 canonical row key are
unchanged, with `(source_class, document_candidate_id, document_reach,
instruction_role, private_plan_row_ids)` appended to that key before `row_id`.

Non-document rows use `document_candidate_id=""`, `document_reach=NONE`, and
the instruction role justified by their existing source class. Every document
candidate produces one row per distinct reach edge, or exactly one
nonexecuting/debt row. Thus one candidate that reaches a model render and a
subprocess argument produces two rows with different preauthorized
`flow_instance_id` values. It is never grouped away.

Classification is the following total table; no precedence guess is used
because multiple live reaches become multiple rows:

| mechanically proved reach | row kind | semantic class | document reach | required evidence |
|---|---|---|---|---|
| content/path is loaded into a MODEL prompt or input binding | `INSTRUCTION_ONLY` plus the loader's `EXECUTABLE` row | `DOC_MODEL_INSTRUCTION` | `MODEL` | loader/callsite and render-placeholder edge |
| an operator instruction invokes/configures a tool or names its consumed path | `INSTRUCTION_ONLY` | `DOC_TOOL_INSTRUCTION` | `TOOL` | command grammar or operator-to-tool edge |
| content/path is read by runtime behavior or defines a current runtime contract | `INSTRUCTION_ONLY` plus reader row | `DOC_RUNTIME_INSTRUCTION` | `RUNTIME` | import/call/read dataflow edge |
| content prescribes or prohibits ownership, path, gate, or authority | `INSTRUCTION_ONLY` | `DOC_CONTROL_INSTRUCTION` | `CONTROL` | control rule and affected authority edge |
| history, comparison, example, or reference has no live model/tool/runtime/control reach | `INSTRUCTION_ONLY` | `DOC_NONEXECUTING_REFERENCE` | `NONE` | negative runtime probe plus final-source rescan |
| reach cannot be proved absent or assigned | `DEBT` | `DOC_REACHABILITY_DEBT` | `UNRESOLVED` | `UNRESOLVED_DOC_REACHABILITY_DEBT` |

`PATH_INSTRUCTION` and `CONTENT_INSTRUCTION` are not interchangeable.
Prohibitions use `instruction_role=PROHIBITION` and CONTROL reach. Descriptive
references use REFERENCE. A candidate cannot be NONE merely because it is in
Markdown. `docs/design/recall-build-plan.md`, `docs/internals.md`, and
`docs/l1-mode/design.md` must each appear in `source_files`, and every one of
their 24 authenticated candidate spans must have one or more semantic rows.
The exact counts may change after authorized edits, so S authenticates the
post-edit count and set rather than pinning the predecessor count.

The candidate-to-row reconciliation is:

```text
set(candidate_id in document_candidate_rows)
  = set(nonempty document_candidate_id in S rows)
and count(S rows for each candidate_id) >= 1
```

Zero rows for a candidate emits `DOC_CANDIDATE_OMISSION_DEBT`; no false-green
source denominator is possible. Final static rows and runtime probes retain
R8's common multiplicity key and ordinal.

### 3.3 R9 projection and publication rederivation

R8 `pi_S_to_M` remains one-to-one. It accepts an S v2 executable SCIP QUERY
row and copies the same R8 fields plus `source_class` and
`document_candidate_id` into `cut4.m.scip_consumer_row.v2`. Its row ID domain
is `cut4.m.scip_consumer_row.v2`; array domain is
`cut4.m.scip_consumer_rows.v2`. No doc row is projected unless it is an actual
SCIP QUERY consumer, but its instruction row remains covered by
`pi_instruction`.

All post-edit commitments are recomputed. D9 data rows use
`cut4.d.data_row.v3`, `d9:` IDs, and the domains `cut4.d.data_row.v3`,
`cut4.d.roster.v3`, and `cut4.d.data_set.v3`. SCIP membership-body and final
membership rows use the R8 acyclic order but v2 schemas/domains because their
consumer IDs have changed. M/R are respectively
`cut4.recon_compatibility_projection_manifest.v3` and
`cut4.recon_compatibility_projection_receipt.v3`. Their semantic-manifest
bindings add the document candidate and private-plan digests. R completion
rows use the corresponding v2/v3 row identities. No R8 S, M, R, membership, or
D digest is asserted unchanged; unchanged byte values, if any, must be
recomputed and compared.

## 4. Stable session, continuation, and exact query bytes

### 4.1 Immutable session core

The session core contains exactly:

```text
schema, run_id, publication_work_unit_key, p0_plan_digest,
semantic_manifest_digest, consumer_id, consumer_row_id, query_id,
query_input, query_input_digest, scope_ids, scope_digest, index_identity,
index_size, index_sha256, provider_outcome_status, provider_outcome_digest,
materialized_consumer_row_digest, query_registry_digest,
tool_version, reader_version, parser_version, session_limits
```

Its schema is `cut4.scip_query_session_core.v1`. `session_limits` has exactly
`schema=cut4.query.session_limits.v1`, `page_size`, `max_session_pages`,
`max_session_results`, and `require_exhaustion`. The R8 bounds remain exact:
page size 1..2000, total pages 1..1024, total results 1..2000000; STATS uses
1/1/1/true.

```text
query_session_digest = H("cut4.query.session.v2", session_core)
```

The session core has no cursor, page ordinal, previous page, cumulative count,
per-invocation budget, argv, evidence identity, or receipt identity. START
establishes the digest by recomputing it from the validated core. Every page
and every non-START invocation recomputes the same digest from the byte-identical
core before accepting a cursor. No mutable request can redefine a session.

The stable authority preimage has exactly `schema`, `session_core`,
`query_session_digest`, publication contract digest, publication commit
receipt digest, P0/S/M/R file SHA-256 values, index size/SHA-256, provider
outcome status/digest, provider explicit-zero digest or empty string,
materialized consumer-row digest, and query-registry digest. Its schema and
domain are `cut4.scip_query_session_preimage.v1` and
`cut4.query.session_preimage.v1`; specifically,
`query_session_preimage_digest = H("cut4.query.session_preimage.v1",
session_preimage)`. Repeated values must be equal to the session core;
disagreement is authority-invalid, never a new session.

### 4.2 Cursor, pages, and chain construction

A cursor is the literal `START` or
`c2.<base64url(canonical_cursor_body)>.<cursor_integrity_digest>`. The cursor
body has exactly:

```text
schema=cut4.query.cursor_body.v2, query_session_digest, consumer_row_id,
query_id, index_identity, index_sha256, next_page_ordinal,
last_canonical_key, prior_page_digest, cumulative_result_count, exhausted
```

`last_canonical_key` is `[]` only before any result; otherwise it is the exact
tagged result canonical-key array from R8. The integrity digest is
`H("cut4.query.cursor_integrity.v2", cursor_body)`. There is no bare END token:
the last output is a c2 token with `exhausted=true`. A continuation invocation
requires `exhausted=false`; an exhausted token can only participate in exact
PhaseIO replay of its already committed receipt.

For page ordinal `n`, first build a page body with exactly:

```text
schema=cut4.scip_query_page_body.v2, query_session_digest, page_ordinal,
cursor_in_integrity_digest, result_rows, page_result_digest,
first_canonical_key, last_canonical_key, cumulative_result_count,
scope_visited, documents_visited, symbols_visited, occurrences_visited,
exhausted
```

The START input uses an empty cursor-in integrity digest. Results are strictly
ordered by the R8 tagged-union key; for a continuation, the first key is
strictly greater than the input cursor's last key. A nonexhausted page cannot
be empty. `page_result_digest = H("cut4.query.page_results.v2", result_rows)`
and `page_digest = H("cut4.query.page.v2", page_body)`.

Only after `page_digest` exists is cursor-out constructed. It has
`next_page_ordinal=n+1`, the new last key, that page digest as
`prior_page_digest`, the new cumulative count, and the page's exhaustion bit.
The final page record has exactly:

```text
schema=cut4.scip_query_page_record.v2, page_body, page_digest,
cursor_out, cursor_out_integrity_digest
```

Thus neither page nor cursor hashing is recursive. The ordered page-chain
digest is `H("cut4.query.page_chain.v2", page_digests)`. Replayed ordinal,
nonmonotonic key, skipped ordinal, wrong prior digest/count, wrong index,
changed session core, result duplication, or a page after exhausted is
`CURSOR_CHAIN_INVALID`, never empty evidence.

### 4.3 Invocation request, continuation authority, and bounds

An invocation has an independently bounded `invocation_limits` object with
exact schema, `max_new_pages`, `max_new_results`, and `timeout_ms`. Values are
positive integers and cannot exceed the remaining stable session limits. They
bound one process call but do not change session identity.

The request has exactly:

```text
schema=cut4.scip_query_invocation_request.v1, session_core,
query_session_digest, query_session_preimage_digest, cursor,
invocation_limits, prior_receipt_identity, prior_receipt_digest,
argv_tokens, argv_digest, invocation_digest, evidence_identity,
receipt_identity
```

START requires empty prior receipt fields. A non-START request requires the
exact preceding successful/PARTIAL query envelope as a PhaseIO immutable input.
Its receipt identity/digest, session digest, last page/cursor, page-chain
digest, cumulative count, and consumer/query IDs must equal the cursor and
request. A hash-correct forged cursor without that receipt has no authority.

`argv_tokens` is exactly the post-interpreter token array beginning
`["-m","plamen_l1.scip_reader",...]`, with options in the CLI order below and
canonical absolute roots plus canonical JSON argument bytes. It excludes only
the platform-specific Python executable. `argv_digest =
H("cut4.query.argv.v1", argv_tokens)`.

The invocation preimage contains exactly
`schema=cut4.scip_query_invocation_preimage.v1`, session digest/preimage
digest, cursor body and integrity digest (or START/empty), invocation limits,
prior receipt identity/digest, and argv digest.
`invocation_digest = H("cut4.query.invocation.v1", invocation_preimage)`.
Evidence and receipt identities are
`scip-evidence:<query_session_digest>:<invocation_digest>` and
`scip-receipt:<query_session_digest>:<invocation_digest>`. They therefore do
not collide across continuations, and exact request replay derives identical
identities.

The exact CLI is:

```text
python -m plamen_l1.scip_reader <index> <command> \
  --scratchpad-root <root> --project-root <root> --plan <P0> \
  --semantic-manifest <S> --authority-manifest <M> --authority-receipt <R> \
  --ledger-receipt <L> --session-core-json <canonical-json> \
  --session-preimage-json <canonical-json> --cursor <START-or-c2-token> \
  --max-new-pages <n> --max-new-results <n> --timeout-ms <n> \
  --continuation-envelope <empty-or-PhaseIO-bound-path> --format json
```

Unknown, repeated, missing, or reordered semantic option input is rejected;
the parser canonicalizes it into the one argv array above. The current
30/50/200/2000 calls remain expressible. Their legacy one-shot limit maps to a
same-sized page/session/invocation bound with `require_exhaustion=false`. A
truly exhaustive consumer selects larger finite session bounds and may use a
smaller invocation bound to resume.

For example, START under a 3-page session and 1-page invocation emits page 0
and a PARTIAL receipt/c2 cursor. Invocation two presents that receipt and
cursor, recomputes the unchanged session digest, emits page 1 and another
PARTIAL. Invocation three repeats the check, emits exhausted page 2 and a
SUCCESS or SUCCESS_EMPTY receipt. The concatenated ordinal chain is 0,1,2;
only the final START-to-exhausted chain may support absence.

Reaching only an invocation limit is resumable PARTIAL. Reaching a stable
session limit before exhaustion emits `SESSION_CAP_REACHED`, is not resumable
under that session, and cannot prove absence. Partial positive rows remain
usable exactly as R8 allows. Exact PhaseIO replay returns the committed bytes;
a changed cursor, limit, argv, prior receipt, session preimage, or authority
hash is a different invocation or fails authority. No query-session file,
manual ledger row, ambient cursor cache, or public discovery is introduced.

### 4.4 Total evidence, error, and exit-4 bytes

R9 execution evidence has exactly:

```text
schema=cut4.scip_query_execution_evidence.v3, evidence_identity,
query_session_digest, query_session_preimage_digest, invocation_digest,
argv_digest, cursor_in_integrity_digest, cursor_out_integrity_digest,
start_state, terminal_state, timeout_ms, tool_version, reader_version,
parser_version, index_parse_complete, scope_expected, scope_visited,
scope_skipped, documents_visited, symbols_visited, occurrences_visited,
resolution_candidates, rejected_fragment_digests, page_records,
page_chain_digest, exhausted, result_count, result_set_digest,
terminal_error_code
```

Arrays are lexical unique except `page_records`, which contains the entire
authenticated session chain in ordinal order: a continuation copies and
validates the prior envelope's records before appending its new records.
`page_chain_digest` hashes only ordered page digests.
`execution_evidence_digest = H("cut4.query.execution_evidence.v2",
evidence_body)`. The digest is outside the body in the envelope.

The following terminal mapping is exhaustive:

| condition | start | terminal | required terminal code | pages/results | evidence meaning |
|---|---|---|---|---|---|
| exhausted with rows | STARTED | SUCCESS | empty | complete | positive |
| exhausted with zero proof | STARTED | SUCCESS | empty | complete empty | absence |
| invocation bound with rows | STARTED | PARTIAL | QUERY_NOT_EXHAUSTED | nonempty | positive only |
| session cap with rows | STARTED | PARTIAL | SESSION_CAP_REACHED | nonempty | positive only |
| provider NOT_APPLICABLE | NOT_STARTED | NOT_APPLICABLE | PROVIDER_NOT_APPLICABLE | empty | neutral/non-evidentiary |
| provider NOT_SELECTED | NOT_STARTED | DEBT | PROVIDER_NOT_SELECTED | empty | debt/non-evidentiary |
| unresolved input | STARTED | DEBT | QUERY_INPUT_UNRESOLVED | empty | debt/non-evidentiary |
| ambiguous input | STARTED | DEBT | QUERY_INPUT_AMBIGUOUS | empty | debt/non-evidentiary |
| incomplete scope with no usable row | STARTED | DEBT | SCOPE_INCOMPLETE | empty | debt/non-evidentiary |
| session cap with no usable row | STARTED | DEBT | SESSION_CAP_REACHED | empty | debt/non-evidentiary |
| provider failure before query | NOT_STARTED | FAILURE | PROVIDER_FAILURE | empty | failure |
| reader failure after start | STARTED | FAILURE | READER_FAILURE | empty | failure |
| provider timeout before query | NOT_STARTED | TIMEOUT | PROVIDER_TIMEOUT | empty | failure |
| reader deadline after start | STARTED | TIMEOUT | READER_TIMEOUT | empty | failure |
| malformed provider/index before query | NOT_STARTED | MALFORMED | PROVIDER_MALFORMED | empty | failure |
| malformed result after start | STARTED | MALFORMED | RESULT_MALFORMED | empty | failure |

NOT_APPLICABLE and NOT_SELECTED validate the provider outcome receipt before
creating a query receipt. Their evidence uses empty page/result arrays, the
empty result-set digest, `index_parse_complete=false`, all visited counts zero,
`exhausted=false`, and the exact NOT_STARTED terminal above. Unresolved,
ambiguous, and scope-debt branches use STARTED, record their attempted
resolution/scope counters, and remain non-evidentiary. None can carry a zero
proof.

The R9 receipt body has exactly:

```text
schema=cut4.scip_query_receipt.v3, receipt_identity, evidence_identity,
query_session_digest, query_session_preimage_digest, invocation_digest,
consumer_id, consumer_row_id, query_id, query_input_digest, index_identity,
index_sha256, p0_plan_digest, manifest_sha256, authority_receipt_sha256,
publication_commit_receipt_digest, cursor_in_integrity_digest,
cursor_out_integrity_digest, last_page_digest, page_chain_digest,
cumulative_result_count, query_status, positive_evidence_usable,
absence_evidence_usable, exhausted, result_count, result_set_digest,
execution_evidence_digest, query_zero_proof_digest, debt_ids,
terminal_error_code
```

`query_receipt_digest = H("cut4.query.receipt.v3", receipt_body)`. Results
across a continued session are the canonical union of the authenticated chain;
a final zero proof requires START at page 0 and an exhausted final token with
zero results over the whole chain. The R9 zero-proof body is the exact R8 v2
body with `query_session_preimage_digest`, `invocation_digest`, and final
page-chain/cursor-out integrity digests in place of the R8 query preimage; its
schema/domain are `cut4.scip_query_zero_proof.v3` and
`cut4.query.zero_proof.v3`. Provider/global zero is still insufficient.

The successful/stateful envelope has exactly
`schema=cut4.scip_query_envelope.v3`, request body/digest, session preimage
body/digest, invocation preimage, execution evidence body/digest, canonical
session result rows, zero-proof body/digest or exact empty object/string,
receipt body/digest, and no other field. Its request digest is
`H("cut4.query.invocation_request.v1", request_body)`.

NOT_APPLICABLE and DEBT exit 4 with this valid non-evidentiary evidence and
receipt. SUCCESS/SUCCESS_EMPTY exit 0; PARTIAL follows R8's 0-or-8 policy;
FAILURE/TIMEOUT/MALFORMED exit 5/6/7. Request and authority failures remain
2/3 with no evidence/receipt identity.

The terminal-code enum adds `PROVIDER_NOT_APPLICABLE` and
`SESSION_CAP_REACHED` to R8's terminal codes. The error envelope retains R8's
exact shape. Its message is not free text:
`message_id = "cut4.query.error." + lowercase(error_code)` and
`message_digest = H("cut4.query.error_message.v1",
{"error_code":error_code,"message_id":message_id})`. R9 adds closed request
codes `CURSOR_CHAIN_INVALID`, `CURSOR_EXHAUSTED`, `SESSION_CORE_CHANGED`,
`CONTINUATION_RECEIPT_INVALID`, and `SESSION_LIMIT_INVALID`. No implementation
may choose a different message preimage.

## 5. Total private plan, evidence, disposition, and no-orphan domain

### 5.1 Static private plan in S

S is pre-provider, so it contains no run outcome. Each exact expected private
slot instead has a plan row:

```text
schema=cut4.s.private_plan_row.v1, private_plan_row_id,
private_source_identity, semantic_row_id, provider_id, consumer_id,
flow_instance_id, multiplicity_key, multiplicity_ordinal,
applicability_predicate_id, selection_predicate_id,
accept_disposition, accept_projected_identity
```

`accept_disposition` is only CANONICAL_PROJECTED,
COMPATIBILITY_PROJECTED, or RETAINED_PRIVATE. Projected identity is nonempty
for the two projected cases and empty for RETAINED_PRIVATE. Provider ID is one
of R6's fixed nine slots; applicability and selection predicate IDs come from
that sealed provider plan. `private_plan_row_id = "ppr:" +
H("cut4.s.private_plan_row.v1", row_without_id)`.

Define the common private key:

```text
Kp = (private_plan_row_id, private_source_identity, semantic_row_id,
      provider_id, consumer_id, flow_instance_id, multiplicity_key,
      multiplicity_ordinal)
```

Rows sort by Kp and are unique. `private_plan_rows_digest =
H("cut4.s.private_plan_rows.v1", rows)`. `private_tuple_set_digest =
H("cut4.s.pi_private_plan.v2", sorted_Kp)`. This is the only private digest in
frozen S; it commits expected multiplicity, not future outcome.

### 5.2 Run-dependent evidence and disposition

After each fixed provider slot reaches its typed terminal state, the DRIVER
canonical publication owner creates one evidence row per plan row. It has
exactly:

```text
schema=cut4.m.private_evidence_row.v1, private_evidence_row_id,
private_plan_row_id, private_source_identity, semantic_row_id, provider_id,
consumer_id, flow_instance_id, multiplicity_key, multiplicity_ordinal,
applicability_predicate_id, applicability_result,
applicability_evidence_digest, selection_predicate_id, selection_result,
selection_evidence_digest, provider_outcome_status,
private_row_status, private_normalizer_status,
provider_evidence_identity, provider_evidence_digest,
normalizer_evidence_digest
```

Every digest required below is a nonempty lowercase SHA-256. Evidence rows sort
by Kp. Their row ID uses `cut4.m.private_evidence_row.v1`; their array digest
uses `cut4.m.private_evidence_rows.v1`.

The canonical owner independently materializes the disposition row:

```text
schema=cut4.m.private_disposition_row.v1, private_disposition_row_id,
private_plan_row_id, private_source_identity, semantic_row_id, provider_id,
consumer_id, flow_instance_id, multiplicity_key, multiplicity_ordinal,
applicability_predicate_id, applicability_result,
applicability_evidence_digest, selection_predicate_id, selection_result,
selection_evidence_digest, provider_outcome_status,
private_row_status, private_normalizer_status,
provider_evidence_identity, provider_evidence_digest,
normalizer_evidence_digest, private_disposition, projected_identity,
private_debt_id, private_debt_code
```

Disposition rows sort by Kp; row/array domains are
`cut4.m.private_disposition_row.v1` and
`cut4.m.private_disposition_rows.v1`. The source evidence row is immutable and
cannot write this disposition or M/R.

### 5.3 Total state mapping and evidence requirements

The following table is the only valid mapping:

| private status | predicate/results | provider outcome | normalizer | required disposition | projected identity | private debt |
|---|---|---|---|---|---|---|
| ACCEPTED | applicability TRUE; selection TRUE; both evidence digests nonempty | SUCCESS with identity/digest | ACCEPTED, digest nonempty | plan accept disposition | exact plan target | empty / NONE |
| REJECTED | applicability TRUE; selection TRUE; both evidence digests nonempty | SUCCESS with identity/digest | REJECTED, digest nonempty | OPEN_DEBT | empty | derived / PRIVATE_REJECTED |
| UNKNOWN, not selected | applicability TRUE; selection FALSE; both evidence digests nonempty | NOT_SELECTED; provider identity/digest empty | NOT_EVALUATED; digest empty | OPEN_DEBT | empty | derived / PRIVATE_NOT_SELECTED |
| UNKNOWN, failure | applicability TRUE; selection TRUE; both evidence digests nonempty | FAILURE with identity/digest | NOT_EVALUATED; digest empty | OPEN_DEBT | empty | derived / PRIVATE_PROVIDER_FAILURE |
| UNKNOWN, timeout | applicability TRUE; selection TRUE; both evidence digests nonempty | TIMEOUT with identity/digest | NOT_EVALUATED; digest empty | OPEN_DEBT | empty | derived / PRIVATE_PROVIDER_TIMEOUT |
| UNKNOWN, malformed | applicability TRUE; selection TRUE; both evidence digests nonempty | MALFORMED with identity/digest | NOT_EVALUATED; digest empty | OPEN_DEBT | empty | derived / PRIVATE_PROVIDER_MALFORMED |
| NOT_APPLICABLE | applicability FALSE and evidence digest nonempty; selection NOT_EVALUATED and digest empty | NOT_APPLICABLE; provider identity/digest empty | NOT_EVALUATED; digest empty | NEUTRAL_NOT_APPLICABLE | empty | empty / NONE |

There is no SUCCESS-to-UNKNOWN shortcut and no NOT_SELECTED neutral. A FALSE
applicability predicate is positive applicability evidence, not provider
evidence. Neutral NOT_APPLICABLE is neither evidence for a query nor debt, but
its required row prevents denominator shrinkage. Any status/disposition pair
outside the table is schema-invalid and emits semantic
`PRIVATE_DISPOSITION_DEBT`.

For every non-NONE private debt code:

```text
private_debt_id = "pdebt:" + H("cut4.private.debt.v1",
                               [Kp, private_debt_code,
                                provider_outcome_status])
```

For ACCEPTED and NOT_APPLICABLE, the ID is empty and code is NONE.

### 5.4 Exact pi_private mapping, order, and equality

`pi_private(evidence)` first joins the evidence row to its unique S plan row
by `private_plan_row_id` and exact Kp. It derives disposition, projected
identity, and private debt ID/code exclusively from the table above.
`pi_private(disposition)` reads those fields directly. Both output exactly:

```text
(Kp, applicability_predicate_id, applicability_result,
 applicability_evidence_digest, selection_predicate_id, selection_result,
 selection_evidence_digest, provider_outcome_status, private_row_status,
 private_normalizer_status, provider_evidence_identity,
 provider_evidence_digest, normalizer_evidence_digest,
 private_disposition, projected_identity, private_debt_id,
 private_debt_code)
```

Field mapping is literal by same-named field except the evidence-side final
four fields, which are derived by the total table and plan target. No default,
basename, provider-global zero, or empty-value coercion is allowed.

All plan, evidence, disposition, projected tuple, completion, and diff arrays
use Kp as their common primary order; ties are forbidden rather than broken by
observation order. The tuple array digest is
`H("cut4.m.pi_private.v2", sorted_pi_private)`. A private diff row has exactly
schema `cut4.private_diff.v1`, Kp, expected tuple or empty, observed tuple or
empty, expected count, observed count, and semantic debt code. Rows sort by Kp
and their array domain is `cut4.m.private_diffs.v1`.

M v3 is created after providers and contains exact private evidence rows,
evidence digest, disposition rows, disposition digest, projected tuple digest,
diff rows/digest, and `has_open_private_debt`. R v3 repeats those digests and
adds one completion row per Kp with evidence-row ID, disposition-row ID, status,
and completion=`MATERIALIZED`; its array domain is
`cut4.r.private_completion_rows.v1`. SP atomically seals D9+M3+R3, and L remains
the existing outer ledger authority.

Acceptance requires:

```text
multiset(Kp from S private plans)
  = multiset(Kp from M private evidence)
  = multiset(Kp from M private dispositions)
  = multiset(Kp from R private completions)

multiset(pi_private(M evidence joined to S plan))
  = multiset(pi_private(M dispositions))

M private digests = R repeated private digests
private diff rows = []
```

An ACCEPTED row without its exact canonical/compatibility/retained disposition
halts. A NOT_APPLICABLE row without its neutral disposition halts. A neutral
row with evidence/debt/projection data halts. REJECTED/UNKNOWN OPEN debt is
allowed to publish only with `has_open_private_debt=true`; it is never positive
or absence evidence and cannot be silently omitted. Duplicate Kp, missing
consumer, extra provider outcome, or multiple consumers collapsed into one row
emits `PRIVATE_MULTIPLICITY_DEBT` and fails no-orphan reconciliation.

The R8 ordinary `pi_debt` and `pi_owner` equalities remain unchanged. Static S
now authenticates only private plan multiplicity, while the first object able
to know outcomes, M, authenticates the run-dependent private projection. This
removes the pre-provider time contradiction without weakening S freeze.

## 6. PhaseIO, publication order, and ownership

The supported R6/R8 API order remains:

1. DRIVER performs read-only admission before mutation.
2. The one authorized cutover owner edits all registered callsites and path
   instructions, including operator documents.
3. It performs the contradiction/candidate rescan, freezes S v2, then seals P0
   v3 as the registered immutable PhaseIO input.
4. Providers receive their fixed plan/seed inputs and emit only typed private
   outcomes. Every provider slot remains present.
5. The DRIVER canonical-publication-v2 work unit verifies S/P0 and provider
   outcomes, constructs private evidence/dispositions, M3/R3/D9, SP, and then
   completes through the existing ArtifactLedger API.
6. Query consumers receive P0/S/M/R/L and any prior continuation envelope as
   declared PhaseIO inputs. The reader returns an envelope; each consumer
   persists it only in that consumer's own PhaseIO output.

The sole canonical owner, compatibility public projection, source/provider
private root, and exact R6 state-machine/legacy branches are unchanged. There
is no provider/direct project-root mutation, public glob, post-write discovery,
manual attempt key, query-session file, co-owned request file, or ArtifactLedger
change. MODEL shards and dependency units are unchanged.

## 7. Recall, precision, failure, and non-goals

Recall improves because the semantic denominator now authenticates operator
documents as well as code, prompts, methodologies, and commands; every
candidate is a live edge, an authenticated negative classification, or debt.
No found output or private slot can disappear through source-root omission,
provider status, pagination, or writer disagreement. Resumable enumeration
preserves every prior page and only permits zero after a complete START-to-END
chain.

Precision remains bounded by exact source anchors, reach edges, provider/query
IDs, tagged result rows, stable session bytes, strict canonical key ordering,
and typed neutral/debt states. Historical doc prose does not become executable
merely because it is scanned; it becomes an authenticated
DOC_NONEXECUTING_REFERENCE backed by a negative runtime probe. Provider failure,
timeout, malformed output, unresolved reach, invalid cursor, or private
rejection can never degrade to empty success.

R9 authorizes no code, test, fixture execution, prior-artifact edit,
ArtifactLedger/G3/provider/audit/project-root mutation, commit, push, install,
cutover, release, or readiness claim. It does not change methodology prose,
roles, MODEL shards, dependency units, the nine provider IDs, 39 public data
identities, public/canonical ownership, or legacy nonadoption.

## 8. Exact R9 test roster

The JSON object below contains exactly **160** unique literal pytest node IDs:
32 document/consumer nodes, 44 session/cursor nodes, 28 evidence/exit nodes,
44 private-projection nodes, and 12 regressions. There are no wildcards,
implied cases, or predecessor nodes in this count.

```json
{
  "document_consumer": [
    "tests/test_cut4_r9_document_consumer.py::test_source_roots_exact_with_docs",
    "tests/test_cut4_r9_document_consumer.py::test_docs_all_regular_files_authenticated",
    "tests/test_cut4_r9_document_consumer.py::test_docs_no_extension_exclusion",
    "tests/test_cut4_r9_document_consumer.py::test_docs_symlink_rejected",
    "tests/test_cut4_r9_document_consumer.py::test_docs_unreadable_debt",
    "tests/test_cut4_r9_document_consumer.py::test_recall_plan_present",
    "tests/test_cut4_r9_document_consumer.py::test_internals_present",
    "tests/test_cut4_r9_document_consumer.py::test_l1_design_present",
    "tests/test_cut4_r9_document_consumer.py::test_candidate_schema_exact",
    "tests/test_cut4_r9_document_consumer.py::test_candidate_id_domain",
    "tests/test_cut4_r9_document_consumer.py::test_candidate_text_digest_domain",
    "tests/test_cut4_r9_document_consumer.py::test_candidate_order_digest",
    "tests/test_cut4_r9_document_consumer.py::test_fenced_code_candidate",
    "tests/test_cut4_r9_document_consumer.py::test_inline_code_candidate",
    "tests/test_cut4_r9_document_consumer.py::test_table_path_candidate",
    "tests/test_cut4_r9_document_consumer.py::test_link_target_candidate",
    "tests/test_cut4_r9_document_consumer.py::test_doc_model_classification",
    "tests/test_cut4_r9_document_consumer.py::test_doc_tool_classification",
    "tests/test_cut4_r9_document_consumer.py::test_doc_runtime_classification",
    "tests/test_cut4_r9_document_consumer.py::test_doc_control_classification",
    "tests/test_cut4_r9_document_consumer.py::test_doc_nonexecuting_classification",
    "tests/test_cut4_r9_document_consumer.py::test_doc_unresolved_reach_debt",
    "tests/test_cut4_r9_document_consumer.py::test_doc_multiple_reaches_not_grouped",
    "tests/test_cut4_r9_document_consumer.py::test_doc_candidate_omission_debt",
    "tests/test_cut4_r9_document_consumer.py::test_doc_candidate_row_reconciliation",
    "tests/test_cut4_r9_document_consumer.py::test_s_v2_exact_body",
    "tests/test_cut4_r9_document_consumer.py::test_p0_v3_binds_doc_digest",
    "tests/test_cut4_r9_document_consumer.py::test_pi_s_to_m_v2_one_to_one",
    "tests/test_cut4_r9_document_consumer.py::test_d9_rederived_after_docs",
    "tests/test_cut4_r9_document_consumer.py::test_m3_r3_repeat_doc_commitments",
    "tests/test_cut4_r9_document_consumer.py::test_each_source_class_injection_detected",
    "tests/test_cut4_r9_document_consumer.py::test_docs_exclusion_false_green_rejected"
  ],
  "query_session": [
    "tests/test_cut4_r9_query_session.py::test_session_core_exact_schema",
    "tests/test_cut4_r9_query_session.py::test_session_core_excludes_cursor",
    "tests/test_cut4_r9_query_session.py::test_session_core_excludes_page_fields",
    "tests/test_cut4_r9_query_session.py::test_session_core_excludes_invocation_limits",
    "tests/test_cut4_r9_query_session.py::test_session_limits_exact_bounds",
    "tests/test_cut4_r9_query_session.py::test_session_digest_domain",
    "tests/test_cut4_r9_query_session.py::test_start_establishes_session",
    "tests/test_cut4_r9_query_session.py::test_nonstart_recomputes_same_session",
    "tests/test_cut4_r9_query_session.py::test_changed_core_rejected",
    "tests/test_cut4_r9_query_session.py::test_session_preimage_exact_schema",
    "tests/test_cut4_r9_query_session.py::test_session_preimage_repeated_field_equality",
    "tests/test_cut4_r9_query_session.py::test_cursor_body_exact_schema",
    "tests/test_cut4_r9_query_session.py::test_cursor_integrity_domain",
    "tests/test_cut4_r9_query_session.py::test_cursor_binds_consumer_query_plan",
    "tests/test_cut4_r9_query_session.py::test_cursor_binds_index_sha",
    "tests/test_cut4_r9_query_session.py::test_cursor_binds_next_ordinal",
    "tests/test_cut4_r9_query_session.py::test_cursor_binds_last_key",
    "tests/test_cut4_r9_query_session.py::test_cursor_binds_prior_page",
    "tests/test_cut4_r9_query_session.py::test_cursor_binds_cumulative_count",
    "tests/test_cut4_r9_query_session.py::test_cursor_binds_exhaustion",
    "tests/test_cut4_r9_query_session.py::test_exhausted_cursor_not_continuable",
    "tests/test_cut4_r9_query_session.py::test_page_body_exact_schema",
    "tests/test_cut4_r9_query_session.py::test_page_digest_nonrecursive",
    "tests/test_cut4_r9_query_session.py::test_cursor_constructed_after_page_digest",
    "tests/test_cut4_r9_query_session.py::test_page_record_exact_schema",
    "tests/test_cut4_r9_query_session.py::test_page_chain_digest_domain",
    "tests/test_cut4_r9_query_session.py::test_nonfinal_empty_page_rejected",
    "tests/test_cut4_r9_query_session.py::test_key_order_across_pages",
    "tests/test_cut4_r9_query_session.py::test_duplicate_across_pages_rejected",
    "tests/test_cut4_r9_query_session.py::test_skipped_page_rejected",
    "tests/test_cut4_r9_query_session.py::test_replayed_page_rejected",
    "tests/test_cut4_r9_query_session.py::test_continuation_receipt_required",
    "tests/test_cut4_r9_query_session.py::test_continuation_receipt_digest_tamper",
    "tests/test_cut4_r9_query_session.py::test_forged_cursor_without_receipt_rejected",
    "tests/test_cut4_r9_query_session.py::test_invocation_limits_exact_schema",
    "tests/test_cut4_r9_query_session.py::test_invocation_digest_domain",
    "tests/test_cut4_r9_query_session.py::test_argv_tokens_exact_preimage",
    "tests/test_cut4_r9_query_session.py::test_argv_digest_domain",
    "tests/test_cut4_r9_query_session.py::test_continuation_identities_distinct",
    "tests/test_cut4_r9_query_session.py::test_exact_invocation_replay_same_identity",
    "tests/test_cut4_r9_query_session.py::test_start_partial_nonstart_end",
    "tests/test_cut4_r9_query_session.py::test_session_cap_nonresumable",
    "tests/test_cut4_r9_query_session.py::test_enumerate_all_resumable",
    "tests/test_cut4_r9_query_session.py::test_live_limits_30_50_200_2000"
  ],
  "query_evidence": [
    "tests/test_cut4_r9_query_evidence.py::test_execution_evidence_v3_schema",
    "tests/test_cut4_r9_query_evidence.py::test_execution_evidence_digest_domain",
    "tests/test_cut4_r9_query_evidence.py::test_receipt_v3_binds_cursor_chain",
    "tests/test_cut4_r9_query_evidence.py::test_receipt_v3_digest_domain",
    "tests/test_cut4_r9_query_evidence.py::test_success_positive_mapping",
    "tests/test_cut4_r9_query_evidence.py::test_success_empty_mapping",
    "tests/test_cut4_r9_query_evidence.py::test_partial_invocation_mapping",
    "tests/test_cut4_r9_query_evidence.py::test_partial_session_cap_mapping",
    "tests/test_cut4_r9_query_evidence.py::test_not_applicable_terminal_mapping",
    "tests/test_cut4_r9_query_evidence.py::test_not_selected_debt_mapping",
    "tests/test_cut4_r9_query_evidence.py::test_unresolved_input_debt_mapping",
    "tests/test_cut4_r9_query_evidence.py::test_ambiguous_input_debt_mapping",
    "tests/test_cut4_r9_query_evidence.py::test_incomplete_scope_debt_mapping",
    "tests/test_cut4_r9_query_evidence.py::test_zero_row_session_cap_debt_mapping",
    "tests/test_cut4_r9_query_evidence.py::test_failure_terminal_mapping",
    "tests/test_cut4_r9_query_evidence.py::test_timeout_terminal_mapping",
    "tests/test_cut4_r9_query_evidence.py::test_malformed_terminal_mapping",
    "tests/test_cut4_r9_query_evidence.py::test_exit4_has_non_evidentiary_envelope",
    "tests/test_cut4_r9_query_evidence.py::test_not_applicable_has_no_zero_proof",
    "tests/test_cut4_r9_query_evidence.py::test_debt_has_no_zero_proof",
    "tests/test_cut4_r9_query_evidence.py::test_final_zero_requires_full_chain",
    "tests/test_cut4_r9_query_evidence.py::test_provider_zero_not_query_zero",
    "tests/test_cut4_r9_query_evidence.py::test_error_message_preimage_exact",
    "tests/test_cut4_r9_query_evidence.py::test_error_message_digest_domain",
    "tests/test_cut4_r9_query_evidence.py::test_cursor_chain_error_never_empty",
    "tests/test_cut4_r9_query_evidence.py::test_request_error_no_receipt",
    "tests/test_cut4_r9_query_evidence.py::test_authority_error_no_receipt",
    "tests/test_cut4_r9_query_evidence.py::test_all_terminal_states_total"
  ],
  "private_projection": [
    "tests/test_cut4_r9_private_projection.py::test_private_status_enum_includes_na",
    "tests/test_cut4_r9_private_projection.py::test_private_disposition_enum_closed",
    "tests/test_cut4_r9_private_projection.py::test_private_debt_enum_closed",
    "tests/test_cut4_r9_private_projection.py::test_predicate_result_enum_closed",
    "tests/test_cut4_r9_private_projection.py::test_provider_outcome_enum_closed",
    "tests/test_cut4_r9_private_projection.py::test_private_plan_schema_exact",
    "tests/test_cut4_r9_private_projection.py::test_private_plan_id_domain",
    "tests/test_cut4_r9_private_projection.py::test_private_plan_accept_target_rules",
    "tests/test_cut4_r9_private_projection.py::test_private_kp_exact",
    "tests/test_cut4_r9_private_projection.py::test_private_plan_order_digest",
    "tests/test_cut4_r9_private_projection.py::test_s_private_digest_is_plan_only",
    "tests/test_cut4_r9_private_projection.py::test_private_evidence_schema_exact",
    "tests/test_cut4_r9_private_projection.py::test_private_evidence_order_digest",
    "tests/test_cut4_r9_private_projection.py::test_private_disposition_schema_exact",
    "tests/test_cut4_r9_private_projection.py::test_private_disposition_order_digest",
    "tests/test_cut4_r9_private_projection.py::test_accepted_mapping_canonical",
    "tests/test_cut4_r9_private_projection.py::test_accepted_mapping_compatibility",
    "tests/test_cut4_r9_private_projection.py::test_accepted_mapping_retained",
    "tests/test_cut4_r9_private_projection.py::test_rejected_mapping_open_debt",
    "tests/test_cut4_r9_private_projection.py::test_unknown_not_selected_mapping",
    "tests/test_cut4_r9_private_projection.py::test_unknown_failure_mapping",
    "tests/test_cut4_r9_private_projection.py::test_unknown_timeout_mapping",
    "tests/test_cut4_r9_private_projection.py::test_unknown_malformed_mapping",
    "tests/test_cut4_r9_private_projection.py::test_not_applicable_neutral_mapping",
    "tests/test_cut4_r9_private_projection.py::test_not_applicable_evidence_requirements",
    "tests/test_cut4_r9_private_projection.py::test_not_selected_not_neutral",
    "tests/test_cut4_r9_private_projection.py::test_invalid_status_disposition_rejected",
    "tests/test_cut4_r9_private_projection.py::test_private_debt_id_domain",
    "tests/test_cut4_r9_private_projection.py::test_pi_private_evidence_exact_tuple",
    "tests/test_cut4_r9_private_projection.py::test_pi_private_disposition_exact_tuple",
    "tests/test_cut4_r9_private_projection.py::test_pi_private_field_mapping_complete",
    "tests/test_cut4_r9_private_projection.py::test_pi_private_order_digest",
    "tests/test_cut4_r9_private_projection.py::test_plan_evidence_key_equality",
    "tests/test_cut4_r9_private_projection.py::test_evidence_disposition_key_equality",
    "tests/test_cut4_r9_private_projection.py::test_disposition_completion_key_equality",
    "tests/test_cut4_r9_private_projection.py::test_pi_private_multiset_equality",
    "tests/test_cut4_r9_private_projection.py::test_private_diff_schema_exact",
    "tests/test_cut4_r9_private_projection.py::test_private_diff_order_digest",
    "tests/test_cut4_r9_private_projection.py::test_private_multiple_consumers_preserved",
    "tests/test_cut4_r9_private_projection.py::test_private_duplicate_kp_debt",
    "tests/test_cut4_r9_private_projection.py::test_m3_binds_private_digests",
    "tests/test_cut4_r9_private_projection.py::test_r3_repeats_private_digests",
    "tests/test_cut4_r9_private_projection.py::test_open_private_debt_flag_total",
    "tests/test_cut4_r9_private_projection.py::test_private_complete_no_orphan"
  ],
  "regression": [
    "tests/test_cut4_r9_regression.py::test_r8_s_to_m_projection_preserved",
    "tests/test_cut4_r9_regression.py::test_r8_membership_d_order_preserved",
    "tests/test_cut4_r9_regression.py::test_r8_common_multiplicity_preserved",
    "tests/test_cut4_r9_regression.py::test_r8_query_zero_separation_preserved",
    "tests/test_cut4_r9_regression.py::test_r7_postedit_single_owner_preserved",
    "tests/test_cut4_r9_regression.py::test_r6_state_machine_preserved",
    "tests/test_cut4_r9_regression.py::test_r6_provider_roster_preserved",
    "tests/test_cut4_r9_regression.py::test_r6_phaseio_launch_preserved",
    "tests/test_cut4_r9_regression.py::test_stable_publication_preserved",
    "tests/test_cut4_r9_regression.py::test_legacy_nonadoption_preserved",
    "tests/test_cut4_r9_regression.py::test_artifact_ledger_unchanged",
    "tests/test_cut4_r9_regression.py::test_no_project_root_mutation"
  ]
}
```

The exact execution order is document/consumer, session/cursor,
evidence/exit, private projection, then regressions. A later fixture worker may
own only these new R9 RED fixtures and evidence. The future implementation
owner is the same single bounded recon cutover/publication owner; workers must
not split S edits, private disposition, D/M/R generation, or canonical commit
ownership.
