# Cut-4 transactional recon publication R8 amendment

Date: 2026-08-10
Status: Part-0 R8 architecture repair only
Supersedes: only the repaired clauses of the R7 amendment
Authority: design for independent review; no fixture, production, test,
ArtifactLedger, G3, provider, audit, commit, push, install, cutover, release,
or audit-readiness authority

## 0. Decision and inherited boundary

R8 closes three R7 schema gaps. It preserves the accepted R7 ownership and
post-edit S-freeze order, query-scoped zero separation, explicit P0/M/R/L
authority arguments, and mechanical command migration. It also preserves every
earlier R6 fix: read-only admission, one private root, exact nine-provider/
39-file denominator, real PhaseIO inputs and LaunchSpec, one-time registered
publication, sole public/canonical owner, compatibility projection, crash
replay, fresh-run-on-completed-drift, legacy nonadoption, containment, and no
ArtifactLedger or G3 change.

R8 makes three exact repairs:

1. S, `pi_S_to_M`, M consumer/membership rows, D8 data rows, and R completion
   rows have closed schemas, canonical keys/orders, literal digest domains, and
   no grouping ambiguity. SCIP membership deliberately versions and rederives
   the D digest after final callsite edits; R8 makes no stale “unchanged D”
   claim.
2. The query CLI and preimage use a tagged input union and required bounded
   pagination policy. ENUMERATE_ALL, page limits, cursor chaining, exhaustion,
   partial results, exact execution evidence, result unions, identities,
   receipt storage, hash domains, and error/exit semantics are total.
3. Every semantic enum is closed. Static and runtime observations share one
   explicit `flow_instance_id`/multiplicity key and canonical order.
   `pi_debt`, `pi_owner`, and `pi_private` give exact equality/diff/no-orphan
   domains, and acceptance requires zero blocking reconciliation debt.

Section 8 defines a new exact 140-node roster. R7's 130 nodes and earlier
rosters remain predecessor regressions, not members of this count.

## 1. Authenticated repair input

The mandatory R7 independent review was read end to end. It is 19,293 bytes
and has SHA-256
`9466b87439f958ef1c4a90628382052690ac2589c2b6129758848bb5635f9e4c`:

`review_fixtures/cut4_transactional_recon_publication_r7_amendment_independent_review_20260810.md`.

The reviewed R7 amendment is 30,510 bytes and SHA-256
`e684ac0c32047a8a9883cb68adf3c46ac8f18f5396617e67181e87ca5db8f8c3`.
Its receipt is 2,696 bytes and SHA-256
`affa9cdcb05574701d199b1feb96798872a5822d4b7ab52a27a0508da37392d1`.
The review accepted R7's single post-edit manifest owner/freeze order and
query-zero/provider-zero separation. R8 does not reopen them.

## 2. Canonical encoding and closed enums

Every R8 digest uses UTF-8 canonical JSON: NFC strings; no BOM; LF only; object
keys sorted by Unicode code point; arrays in their schema-defined order;
integers only; lowercase 64-hex SHA-256; no duplicate key, float, NaN,
Infinity, implicit null, or extra field. Empty optional values are `""`, `[]`,
or `{}` exactly as specified. Hash syntax is:

```text
H(domain, value) = SHA256(UTF8(domain) || 0x00 || canonical_json(value))
```

The closed semantic enums are:

```json
{
  "row_kind": ["EXECUTABLE", "INSTRUCTION_ONLY", "DEBT"],
  "operation": ["READ", "WRITE", "PRODUCE", "QUERY", "VALIDATE", "PROMPT_RENDER", "SUBPROCESS_ARG"],
  "direction": ["READ", "WRITE", "CONTROL"],
  "identity_origin": ["LITERAL", "REGISTRY_EXPANSION", "PATH_COMPOSITION", "PARAMETER", "RETURN_FLOW", "ARGV_FLOW", "PROMPT_PLACEHOLDER"],
  "endpoint": ["SOURCE", "CALLER", "CALLEE", "TEMPLATE", "RENDER", "SINK", "INSTRUCTION"],
  "semantic_class": ["RUNTIME_IO", "PHASEIO_INPUT", "PHASEIO_OUTPUT", "PROMPT_PATH", "MECHANICAL_COMMAND", "SUBPROCESS_QUERY", "VALIDATOR", "NONEXECUTING_EXAMPLE", "PROHIBITION", "CONTROL_AUTHORITY"],
  "owner_kind": ["DRIVER", "MODEL", "RAW_INPUT", "NONE"],
  "private_row_status": ["ACCEPTED", "REJECTED", "UNKNOWN"],
  "private_disposition": ["CANONICAL_PROJECTED", "COMPATIBILITY_PROJECTED", "RETAINED_PRIVATE", "OPEN_DEBT", "NEUTRAL_NOT_APPLICABLE"],
  "debt_code": ["DYNAMIC_PATH_DEBT", "UNPROBED_CONSUMER_DEBT", "UNMANIFESTED_RUNTIME_CONSUMER_DEBT", "INDIRECT_OR_DYNAMIC_CONSUMER_DEBT", "ORPHAN_SEMANTIC_ROW_DEBT", "CO_WRITER_DEBT", "UNRESOLVED_IMPORT_DEBT", "UNRESOLVED_CALL_DEBT", "DUPLICATE_RUNTIME_OBSERVATION_DEBT", "STATIC_RUNTIME_MULTIPLICITY_DEBT", "STALE_SOURCE_ANCHOR_DEBT", "AUTHORITY_JOIN_DEBT", "MISSING_OWNER_DEBT", "PRIVATE_DISPOSITION_DEBT"]
}
```

All debt codes are acceptance-blocking. Equality of two nonempty debt sets is
accounting, not success.

## 3. Exact S and S-to-M authority

### 3.1 S top-level and row schema

S is generated only after the authorized R7 callsite cutover. Its body has
exactly:

```json
{
  "schema": "cut4.recon_consumer_manifest.v1",
  "analyzer_version": "<pinned>",
  "normalization_version": "cut4.semantic_normalization.v1",
  "source_roots": ["agents", "commands", "plamen_l1", "prompts", "scripts"],
  "source_files": [],
  "source_tree_digest": "<sha256>",
  "query_registry": [],
  "query_registry_digest": "<sha256>",
  "rows": [],
  "row_set_digest": "<sha256>",
  "exec_tuple_set_digest": "<sha256>",
  "instruction_tuple_set_digest": "<sha256>",
  "debt_tuple_set_digest": "<sha256>",
  "owner_tuple_set_digest": "<sha256>",
  "private_tuple_set_digest": "<sha256>"
}
```

The final S file has exactly
`{"schema":"cut4.recon_consumer_manifest_file.v1","body":S_body,
"semantic_manifest_digest":H("cut4.s.manifest.v1",S_body)}`. Its ordinary
file SHA-256 is `semantic_manifest_file_sha256`. P0 v2 names exactly S project
identity, file schema, semantic-manifest digest, file size/SHA-256,
source-tree digest, row-set digest, exec/instruction/debt/owner/private tuple-set
digests, and query-registry digest. The former ambiguous singular tuple field
is not accepted.

Each `source_files` row has exactly `path`, `size`, and `sha256`, ordered by
canonical relative path. `source_tree_digest = H("cut4.s.source_tree.v1",
source_files)`. S itself and generated test/output roots are excluded by the
closed source-root registry, not a glob.

Every S row has exactly the R7 fields plus the now-required common instance and
ownership fields:

```json
{
  "schema": "cut4.recon_consumer_row.v1",
  "row_id": "row:<sha256>",
  "row_kind": "EXECUTABLE",
  "consumer_id": "<id>",
  "operation": "QUERY",
  "exact_identity": "scip_rust.index",
  "direction": "READ",
  "producer_id": "recon/canonical_publication_v2",
  "owner_kind": "DRIVER",
  "projection_row_id": "compat.scip_rust.index",
  "required_phase_gate": "RECON_COMPATIBILITY_CONSUMER_DENOMINATOR",
  "probe_id": "<id>",
  "flow_edge_id": "<id>",
  "flow_instance_id": "<stable authorized literal>",
  "endpoint": "SINK",
  "multiplicity_key": "mul:<sha256>",
  "multiplicity_ordinal": 0,
  "identity_origin": "ARGV_FLOW",
  "source_file": "<relative path>",
  "source_anchor_digest": "<sha256>",
  "semantic_class": "MECHANICAL_COMMAND",
  "allowed_query_ids": ["REFERENCES"],
  "scope_ids": ["<closed lexical scope>"],
  "private_source_identity": "",
  "semantic_row_id": "",
  "provider_id": "scip_rust",
  "private_row_status": "ACCEPTED",
  "private_disposition": "COMPATIBILITY_PROJECTED",
  "debt_id": "",
  "debt_code": ""
}
```

Fields not applicable to a row use the exact empty value. Allowed-query and
scope arrays are nonempty only for QUERY and are lexical, unique arrays.
`flow_instance_id` is assigned in the pre-edit authorization plan, embedded in
the final consumer context, observed at runtime, and immutable across line
moves. It is not generated from runtime scheduling.

All consumer/probe/flow/scope/instance IDs match
`^[a-z][a-z0-9._-]{0,127}$`; query IDs use only their five uppercase enum
values. No Unicode confusable or implicit case normalization is admitted.

Define the multiplicity base tuple:

```text
B = (consumer_id, operation, exact_identity, direction, producer_id,
owner_kind, projection_row_id, required_phase_gate, probe_id, flow_edge_id,
endpoint)
```

`multiplicity_key = "mul:" + H("cut4.semantic.multiplicity.v1",
[B, flow_instance_id])`. Keys must be unique within each B group. Ordinal is
the zero-based rank after bytewise sorting multiplicity keys in that group.
Static and runtime use this same calculation. `row_id` is
`"row:" + H("cut4.s.row.v1", row_without_row_id)`.

S rows are sorted by the tuple
`(row_kind, consumer_id, operation, exact_identity, direction, producer_id,
projection_row_id, required_phase_gate, probe_id, flow_edge_id, endpoint,
multiplicity_key, source_file, source_anchor_digest, row_id)`.
`row_set_digest = H("cut4.s.row_set.v1", rows)`.

### 3.2 Closed query registry

S has exactly five query-registry rows, sorted by query ID. Each row has
exactly `schema`, `query_id`, `cli_command`, `input_tag`, `result_tag`,
`allowed_purpose`, `pagination_policy`, and `normalizer_version`:

| query_id | command | input tag | result tag | purpose |
|---|---|---|---|---|
| `DEFINITION` | `definition` | `SYMBOL` | `OCCURRENCE` | `MATCH` |
| `FILE_SYMBOLS` | `file` | `FILE` | `FILE_SYMBOL` | `MATCH` |
| `REFERENCES` | `references` | `SYMBOL` | `OCCURRENCE` | `MATCH` |
| `STATS` | `stats` | `NONE` | `STATS` | `STATS` |
| `WORKSPACE_SEARCH` | `search` | `SEARCH` | `SEARCH_SYMBOL` | `MATCH` or `ENUMERATE_ALL` |

Every row uses pagination policy `BOUNDED_CURSOR_V1` except STATS, which uses
`SINGLETON_V1`. `query_registry_digest = H("cut4.s.query_registry.v1",
query_registry)`.

### 3.3 Exact pi_S_to_M and M consumer rows

`pi_S_to_M` accepts exactly an S row satisfying `row_kind=EXECUTABLE`,
`operation=QUERY`, `direction=READ`, a SCIP index identity, and no debt. It
produces one row; there is no grouping or plural-index synthesis:

```json
{
  "schema": "cut4.m.scip_consumer_row.v1",
  "consumer_row_id": "mcr:<sha256>",
  "s_row_id": "row:<sha256>",
  "consumer_id": "<id>",
  "index_identity": "scip_rust.index",
  "allowed_query_ids": ["REFERENCES"],
  "scope_ids": ["<scope>"],
  "producer_id": "recon/canonical_publication_v2",
  "projection_row_id": "compat.scip_rust.index",
  "required_phase_gate": "RECON_COMPATIBILITY_CONSUMER_DENOMINATOR",
  "probe_id": "<id>",
  "flow_edge_id": "<id>",
  "endpoint": "SINK",
  "multiplicity_key": "mul:<sha256>",
  "multiplicity_ordinal": 0
}
```

`consumer_row_id = "mcr:" + H("cut4.m.scip_consumer_row.v1",
row_without_consumer_row_id)`. Rows sort by
`(index_identity, consumer_id, allowed_query_ids, scope_ids, probe_id,
flow_edge_id, endpoint, multiplicity_key, s_row_id)`.
`consumer_rows_digest = H("cut4.m.scip_consumer_rows.v1", consumer_rows)`.

## 4. R8 D, M, membership, and R schemas

### 4.1 Membership and deliberately rederived D8

For each SCIP index, first form the membership body:

```json
{
  "schema": "cut4.m.scip_membership_body.v1",
  "index_identity": "scip_rust.index",
  "consumer_row_ids": ["mcr:<sha256>"],
  "index_consumer_ids_digest": "<sha256>"
}
```

IDs are lexical and unique.
`index_consumer_ids_digest = H("cut4.m.index_consumer_ids.v1",
consumer_row_ids)` and
`membership_body_digest = H("cut4.m.scip_membership_body.v1", body)`.

R8 then rederives every D authority row after final S freeze. Physical output
paths remain the R6/R7 registry, but the authority schema and set digest are
versioned. Each D8 row is exactly:

```json
{
  "schema": "cut4.d.data_row.v2",
  "data_row_id": "d8:<sha256>",
  "identity": "scip_rust.index",
  "size": 1,
  "sha256": "<sha256>",
  "semantic_source_row_digest": "<sha256>",
  "projection_disposition": "COMPATIBILITY_PROJECTED",
  "membership_body_digest": "<sha256 or empty>"
}
```

Only the two SCIP index rows have a nonempty membership digest. `data_row_id =
"d8:" + H("cut4.d.data_row.v2", row_without_data_row_id)`. Rows sort by
identity. `data_roster_digest = H("cut4.d.roster.v2", lexical_identities)` and
`data_set_digest = H("cut4.d.data_set.v2", data_rows)`. This explicitly changes
the D authority digest after callsite edits; no R6 digest is reused.

Now construct each final membership row:

```json
{
  "schema": "cut4.m.scip_membership_row.v1",
  "membership_row_id": "mmr:<sha256>",
  "index_identity": "scip_rust.index",
  "data_row_id": "d8:<sha256>",
  "membership_body_digest": "<sha256>",
  "consumer_row_ids": ["mcr:<sha256>"],
  "index_consumer_ids_digest": "<sha256>"
}
```

`membership_row_id` uses domain `cut4.m.scip_membership_row.v1`. Rows sort by
index identity. `membership_rows_digest = H("cut4.m.scip_membership_rows.v1",
membership_rows)`. There is no cycle: membership body precedes D8; final
membership references D8; D8 hashes only the body digest.

### 4.2 Exact M and R bodies

M body has exactly:

```text
schema, run_id, publication_work_unit_key, publication_contract_digest,
p0_binding, semantic_manifest_binding, query_registry_digest,
data_roster, data_roster_digest, data_rows, data_set_digest,
consumer_rows, consumer_rows_digest,
membership_rows, membership_rows_digest, control_slots
```

`p0_binding` has identity, p0 plan digest, size, file SHA, producer key,
contract digest, and launch digest. `semantic_manifest_binding` has explicit
project-root-relative S identity, S schema, manifest digest, file size/file
SHA, source-tree digest, row-set digest, five tuple-set digests, and query
registry digest. M data/consumer/membership rows are the exact arrays above.
Control slots remain M-self-excluded and R-excluded. M contains no M/R hash.
`manifest_file_sha256` hashes final canonical M bytes.
M's schema value is `cut4.recon_compatibility_projection_manifest.v2`.

R body has exactly:

```text
schema, run_id, publication_work_unit_key, publication_contract_digest,
p0_binding, semantic_manifest_binding, query_registry_digest,
manifest_binding, data_completion_rows, data_completion_rows_digest,
consumer_completion_rows, consumer_completion_rows_digest,
membership_completion_rows, membership_completion_rows_digest,
data_set_digest, consumer_rows_digest, membership_rows_digest, control_slots
```

`manifest_binding` has M identity/size/SHA. Completion row schemas are:

```text
data:       (schema, data_row_id, identity, size, sha256, status=PLANNED_FINAL)
consumer:   (schema, consumer_row_id, index_identity, status=MATERIALIZED)
membership:(schema, membership_row_id, index_identity, status=MATERIALIZED)
```

Each array uses the corresponding M order and domain tags
`cut4.r.data_completion_rows.v1`, `cut4.r.consumer_completion_rows.v1`, and
`cut4.r.membership_completion_rows.v1`. R repeats the three set digests and
P0/S/query bindings exactly; any mismatch fails. R has no self hash or SP
digest. SP seals exact D8+M+R bytes and L is the outer completion authority.
R's schema is `cut4.recon_compatibility_projection_receipt.v2`; the three row
schemas are respectively `cut4.r.data_completion_row.v1`,
`cut4.r.consumer_completion_row.v1`, and
`cut4.r.membership_completion_row.v1`.

## 5. Exact query request, CLI, and pagination

### 5.1 Tagged input union

`query_input` is exactly one object with no extras:

```json
[
  {"tag": "NONE"},
  {"tag": "SYMBOL", "symbol_kind": "FULL", "value": "<NFC>", "resolution": "REQUIRE_UNIQUE"},
  {"tag": "FILE", "relative_path": "<canonical captured path>"},
  {"tag": "SEARCH", "query": "<NFC, may be empty>", "purpose": "MATCH", "case": "SENSITIVE"},
  {"tag": "SEARCH", "query": "", "purpose": "ENUMERATE_ALL", "case": "SENSITIVE"}
]
```

SYMBOL `symbol_kind` is `FULL` or `DISPLAY`; both require unique resolution.
SEARCH case is `SENSITIVE` or `FOLDED`; ENUMERATE_ALL requires exactly empty
query and SENSITIVE. Query ID must match the registry input tag.
`query_input_digest = H("cut4.query.input.v1", query_input)`.

### 5.2 Required pagination policy and cursor

Every request contains:

```json
{
  "schema": "cut4.query.pagination.v1",
  "start_cursor": "START",
  "page_size": 2000,
  "max_pages": 1024,
  "max_results": 2000000,
  "require_exhaustion": true
}
```

Bounds are exact: `1 <= page_size <= 2000`, `1 <= max_pages <= 1024`, and
`1 <= max_results <= 2000000`. STATS must use 1/1/1/true. No cap may be
omitted or represented as unlimited. Existing `--limit N` command rows are
mechanically translated to `page_size=N`, `max_pages=1`, `max_results=N`, and
`require_exhaustion=false`; if more data exists, the result is typed PARTIAL
with debt. An explicitly exhaustive migrated command chooses larger bounded
maxima and `require_exhaustion=true`. The old token is never silently ignored.

A cursor is `START`, `END`, or
`c1.<base64url(canonical_cursor_body)>.<sha256>`. The cursor body has exactly
query-session digest, index SHA, page index, next canonical result sort key,
prior page digest, and emitted-result count. Its SHA uses domain
`cut4.query.cursor.v1`. Wrong query/index/order/prior digest fails authority.
Pages are ordered by their result-union canonical key. A page record has exact
schema, query-session digest, page index, cursor-in/out, lexical result rows,
page-result digest, cumulative count, visited coverage counters, and
`exhausted` boolean; `page_digest = H("cut4.query.page.v1", page_without_digest)`.
The schema is `cut4.scip_query_page.v1`, and the page-result digest uses domain
`cut4.query.page_results.v1` over that page's result rows.

The reader paginates internally. Starting at START, it follows its own cursor
chain until END or a bound. A non-START request is allowed only with the exact
prior-page digest/cumulative count in the request and can never support an
absence claim unless the final receipt proves a contiguous START-to-END chain.
`exhausted=true` iff cursor-out is END, every authorized scope member was
visited, and there was no skip/rejection.

### 5.3 Exact request and CLI

The request body has exactly:

```text
schema, run_id, publication_work_unit_key, p0_plan_digest,
semantic_manifest_digest, consumer_id, consumer_row_id, query_id,
query_input, query_input_digest, scope_ids, scope_digest, index_identity,
pagination, prior_page_digest, prior_cumulative_count, tool_version,
reader_version, parser_version, evidence_identity, receipt_identity
```

Its schema value is `cut4.scip_query_request.v2`.

Scopes are lexical unique and `scope_digest = H("cut4.query.scope.v1",
scope_ids)`. Evidence and receipt logical identities are respectively
`scip-evidence:<query-session-digest>` and
`scip-receipt:<query-session-digest>`. `query_session_digest =
H("cut4.query.session.v1", request_without_evidence_and_receipt_identities)`;
the two identities are then derived and validated. The final query preimage
adds publication contract/commit digest, P0/M/R file hashes, index size/SHA,
provider outcome/digest, materialized consumer-row digest, query registry
digest, and normalized versions. `query_preimage_digest =
H("cut4.query.preimage.v2", preimage)`.

The word “adds” is exact: the preimage object contains only `schema`, the full
request body, query-session digest, publication contract digest, publication
commit-receipt digest, P0 file SHA-256, M file SHA-256, R file SHA-256, S file
SHA-256, index size/SHA-256, provider outcome status/digest, provider
explicit-zero digest or empty string, materialized consumer-row digest,
query-registry digest, and tool/reader/parser versions. It has no extra field.
Its schema value is `cut4.scip_query_preimage.v2`.

The CLI is exact:

```text
python -m plamen_l1.scip_reader <index> <command> \
  --scratchpad-root <root> --project-root <root> --plan <P0> \
  --semantic-manifest <S> --authority-manifest <M> --authority-receipt <R> \
  --consumer-id <id> --consumer-row-id <mcr:id> --query-id <id> \
  --query-input-json <canonical-json> --scope-id <id> [--scope-id <id>...] \
  --start-cursor <START-or-token> --page-size <n> --max-pages <n> \
  --max-results <n> --require-exhaustion <true|false> \
  --prior-page-digest <empty-or-sha256> --prior-cumulative-count <n> \
  --format json
```

This can express the live empty-search ENUMERATE_ALL and every bounded 30/50/
200/2000 call without inventing semantics. S is explicit, so the reader can
recompute final S and project roots; no ambient lookup remains.

## 6. Evidence, result, receipt, and total semantics

### 6.1 Closed result union and execution evidence

Every result row is exactly one tagged schema:

```text
STATS:         tag, documents, symbols, definitions, reference_symbols
OCCURRENCE:    tag, symbol, relative_path, start_line, start_col, end_line, end_col, role
FILE_SYMBOL:   tag, symbol, display_name, kind, relative_path, definition_row_digest
SEARCH_SYMBOL: tag, symbol, display_name, kind, definition_row_digest
```

Integers are nonnegative; paths/symbols are NFC; role is `DEFINITION` or
`REFERENCE`; an absent definition digest is empty. Canonical order keys are
respectively tag; `(relative_path,start_line,start_col,end_line,end_col,
symbol,role)`; `(relative_path,symbol,display_name,kind)`; and
`(symbol,display_name,kind)`. Duplicate rows are forbidden.
`result_set_digest = H("cut4.query.result_set.v1", result_rows)`.

Execution evidence has exactly:

```text
schema, evidence_identity, query_session_digest, query_preimage_digest,
argv_digest, start_state, terminal_state, timeout_ms,
tool_version, reader_version, parser_version, index_parse_complete,
scope_expected, scope_visited, scope_skipped, documents_visited,
symbols_visited, occurrences_visited, resolution_candidates,
rejected_fragment_digests, page_records, page_chain_digest,
exhausted, result_count, result_set_digest, terminal_error_code
```

Its schema is `cut4.scip_query_execution_evidence.v2`.

Arrays are lexical unique except ordered page records. Start is `STARTED`.
Terminal is `SUCCESS`, `PARTIAL`, `FAILURE`, `TIMEOUT`, or `MALFORMED`.
`terminal_error_code` is exactly empty string or one of
`QUERY_NOT_EXHAUSTED`, `QUERY_INPUT_UNRESOLVED`, `QUERY_INPUT_AMBIGUOUS`,
`SCOPE_INCOMPLETE`, `PROVIDER_NOT_SELECTED`, `PROVIDER_FAILURE`,
`PROVIDER_TIMEOUT`, `PROVIDER_MALFORMED`, `READER_FAILURE`, `READER_TIMEOUT`,
or `RESULT_MALFORMED`.
`page_chain_digest = H("cut4.query.page_chain.v1", page_digests)` and
`execution_evidence_digest = H("cut4.query.execution_evidence.v1",
evidence_without_its_digest)`. The envelope embeds the evidence body and digest;
there is no filesystem discovery or extra reader-written file.

### 6.2 Query zero and receipt

`SUCCESS_EMPTY` still requires provider SUCCESS, START-to-END exhaustion,
valid resolved input where applicable, zero result rows, complete scope, no
skipped/rejected fragment, and terminal SUCCESS. The zero proof body has
exactly schema, query preimage/session digest, evidence identity/digest,
invocation argv digest, tool/reader/parser versions, scope digest and counters,
page-chain digest, exhaustion=true, empty result-set digest, and status. Its
digest is `H("cut4.query.zero_proof.v2", body)`. Provider explicit-zero digest
is only a preimage provenance field.

The receipt body has exactly:

```text
schema, receipt_identity, evidence_identity, query_session_digest,
query_preimage_digest, consumer_id, consumer_row_id, query_id,
query_input_digest, index_identity, index_sha256, p0_plan_digest,
manifest_sha256, authority_receipt_sha256, publication_commit_receipt_digest,
query_status, positive_evidence_usable, absence_evidence_usable,
exhausted, result_count, result_set_digest, execution_evidence_digest,
query_zero_proof_digest, debt_ids, terminal_error_code
```

Its schema is `cut4.scip_query_receipt.v2`; `debt_ids` are lexical unique IDs
matching `^debt:[a-z0-9._-]{1,128}$`.

`query_receipt_digest = H("cut4.query.receipt.v2", receipt_body)`. The output
envelope contains exact evidence body/digest, result rows, zero-proof body/
digest or empty object/string, receipt body/digest, and no extra field. A
durable consumer copies these exact logical identities/digests into only its
own PhaseIO output.

### 6.3 Total statuses, caps, and exits

| Condition | status | positive usable | absence usable | exhausted |
|---|---|---:|---:|---:|
| complete rows > 0 | `SUCCESS` | true | false | true |
| complete rows = 0 + zero proof | `SUCCESS_EMPTY` | false | true | true |
| cap/budget before END, valid returned rows | `PARTIAL` | true | false | false |
| NOT_APPLICABLE | `NOT_APPLICABLE` | false | false | false |
| NOT_SELECTED, unresolved/ambiguous input, incomplete scope with no usable row | `DEBT` | false | false | false |
| execution failure | `FAILURE` | false | false | false |
| deadline | `TIMEOUT` | false | false | false |
| malformed provider/index/result | `MALFORMED` | false | false | false |

PARTIAL always carries `QUERY_NOT_EXHAUSTED` debt and can never prove zero or
completeness. If `require_exhaustion=true`, PARTIAL exits 8; otherwise it exits
0 with mandatory debt. SUCCESS/SUCCESS_EMPTY exit 0; NOT_APPLICABLE/DEBT exit
4 with a valid non-evidentiary receipt; FAILURE 5; TIMEOUT 6; MALFORMED 7.
Invalid CLI/schema/query ID is exit 2 and produces only a non-evidentiary
error envelope; failed P0/S/M/R/L/path authority is exit 3. Exit 2/3 has no
evidence or receipt identity. Omitted caps, broken cursor/page order, result
schema violation, or receipt/evidence digest mismatch cannot degrade to empty.
That error envelope has exactly schema `cut4.scip_query_error.v1`,
`error_class` (`INVALID_REQUEST` or `AUTHORITY_INVALID`), closed error code,
message digest, and exit code; it contains no query/result/evidence/receipt
field. The successful/stateful envelope schema is
`cut4.scip_query_envelope.v2`.
The error-code enum is `UNKNOWN_ARGUMENT`, `INVALID_SCHEMA`,
`INVALID_QUERY_ID`, `INVALID_INPUT`, `INVALID_LIMIT`, `INVALID_CURSOR`,
`PATH_ESCAPE`, `P0_INVALID`, `S_INVALID`, `M_INVALID`, `R_INVALID`,
`LEDGER_INVALID`, `CONSUMER_UNAUTHORIZED`, `QUERY_UNAUTHORIZED`, or
`INDEX_UNAUTHORIZED`.

## 7. Exact semantic projections, ordering, and no-orphan gates

`pi_exec` and `pi_instruction` inherit R7, adding `owner_kind` and the common
multiplicity key/ordinal. Arrays on both sides sort by canonical JSON encoding
of the projected tuple, then compare as multisets.

S tuple digests are exactly
`H("cut4.s.pi_exec.v1", sorted_pi_exec)`,
`H("cut4.s.pi_instruction.v1", sorted_pi_instruction)`,
`H("cut4.s.pi_debt.v1", sorted_pi_debt)`,
`H("cut4.s.pi_owner.v1", sorted_pi_owner)`, and
`H("cut4.s.pi_private.v1", sorted_pi_private)`.

`pi_debt` maps an S DEBT row and an analyzer/runtime debt observation to:

```text
(debt_code, consumer_id, operation, exact_identity-or-UNRESOLVED,
projection_row_id, required_phase_gate, probe_id, flow_edge_id, endpoint,
multiplicity_key, multiplicity_ordinal)
```

`pi_owner` maps an S WRITE/PRODUCE row and a PhaseIO owner registry row to:

```text
(exact_identity, producer_id, owner_kind, operation, direction,
projection_row_id, required_phase_gate, flow_edge_id, multiplicity_key,
multiplicity_ordinal)
```

`pi_private` maps both a private evidence/disposition row and its canonical/
compatibility/retained/debt projection to:

```text
(private_source_identity, semantic_row_id, provider_id, private_row_status,
private_disposition, projected_identity-or-empty, consumer_id,
debt_id-or-empty)
```

For `pi_private`, ACCEPTED must be projected canonical/compatibility or retained
private; REJECTED/UNKNOWN must be OPEN_DEBT; NOT_APPLICABLE alone may be neutral.
No NOT_SELECTED neutral exists. `pi_S_to_M` is the publication-consumer
projection. Each function rejects wrong row kind or enum rather than filling a
default.

Common ordering uses the full tuple's canonical JSON bytes. Same B with two
static occurrences must have distinct authorized `flow_instance_id` and thus
distinct multiplicity keys. Runtime context carries the identical key. A
duplicate runtime emission with one key is not paired by observation order; it
emits `DUPLICATE_RUNTIME_OBSERVATION_DEBT` and a count diff. Scheduling
permutations leave sorted arrays unchanged.

Every diff row has exactly:

```json
{
  "schema": "cut4.semantic_diff.v1",
  "projection": "pi_owner",
  "tuple": [],
  "expected_count": 1,
  "observed_count": 0,
  "debt_code": "MISSING_OWNER_DEBT"
}
```

Diff rows sort by projection then canonical tuple. Acceptance requires:

```text
multiset(pi_exec(S EXECUTABLE))       = multiset(pi_exec(runtime))
multiset(pi_instruction(S))           = multiset(pi_instruction(final rescan))
multiset(pi_S_to_M(S SCIP QUERY))      = multiset(M consumer rows)
multiset(pi_owner(S WRITE/PRODUCE))    = multiset(pi_owner(PhaseIO owners))
multiset(pi_private(private rows))     = multiset(pi_private(all dispositions))
multiset(pi_debt(S/analyzer debt))     = multiset(pi_debt(runtime debt))
```

and then requires **all diff rows empty and all `pi_debt` multisets empty**.
Dynamic/indirect flows therefore remain visible but cannot produce a false
green merely because both sides recorded the same debt. D8 membership rows,
M/R commitments, public readers, private evidence/debt, PhaseIO writers, and
runtime queries all participate in the no-orphan gate.

`pi_debt` contains only semantic consumer/ownership reconciliation debt from
the closed enum in section 2. Provider and application OPEN debt remains in
`pi_private` and may be haltlessly present when exactly dispositioned; it is
never confused with an unresolved consumer graph.

## 8. Exact R8 test roster

The JSON below contains exactly **140** unique pytest node IDs: 32 consumer
schema, 32 query request/pagination, 28 evidence/receipt, 36 semantic
projection, and 12 regression nodes. There are no wildcards, implied nodes, or
hidden parameterizations.

```json
{
  "consumer_schema": [
    "tests/test_cut4_r8_consumer_schema.py::test_s_top_schema_exact",
    "tests/test_cut4_r8_consumer_schema.py::test_s_source_file_schema",
    "tests/test_cut4_r8_consumer_schema.py::test_s_source_tree_digest",
    "tests/test_cut4_r8_consumer_schema.py::test_s_row_schema_exact",
    "tests/test_cut4_r8_consumer_schema.py::test_s_row_extra_rejected",
    "tests/test_cut4_r8_consumer_schema.py::test_s_row_id_domain",
    "tests/test_cut4_r8_consumer_schema.py::test_s_row_canonical_order",
    "tests/test_cut4_r8_consumer_schema.py::test_s_row_set_digest",
    "tests/test_cut4_r8_consumer_schema.py::test_query_registry_exact_five",
    "tests/test_cut4_r8_consumer_schema.py::test_query_registry_row_schema",
    "tests/test_cut4_r8_consumer_schema.py::test_query_registry_order_digest",
    "tests/test_cut4_r8_consumer_schema.py::test_pi_s_to_m_one_to_one",
    "tests/test_cut4_r8_consumer_schema.py::test_pi_s_to_m_rejects_grouping",
    "tests/test_cut4_r8_consumer_schema.py::test_m_consumer_row_schema",
    "tests/test_cut4_r8_consumer_schema.py::test_m_consumer_row_id_domain",
    "tests/test_cut4_r8_consumer_schema.py::test_m_consumer_rows_order_digest",
    "tests/test_cut4_r8_consumer_schema.py::test_membership_body_schema_digest",
    "tests/test_cut4_r8_consumer_schema.py::test_d8_data_row_schema",
    "tests/test_cut4_r8_consumer_schema.py::test_d8_membership_digest_present",
    "tests/test_cut4_r8_consumer_schema.py::test_d8_non_scip_membership_empty",
    "tests/test_cut4_r8_consumer_schema.py::test_d8_data_set_rederived",
    "tests/test_cut4_r8_consumer_schema.py::test_r6_data_digest_not_reused",
    "tests/test_cut4_r8_consumer_schema.py::test_membership_row_schema",
    "tests/test_cut4_r8_consumer_schema.py::test_membership_no_digest_cycle",
    "tests/test_cut4_r8_consumer_schema.py::test_m_body_exact_fields",
    "tests/test_cut4_r8_consumer_schema.py::test_m_s_binding_exact_fields",
    "tests/test_cut4_r8_consumer_schema.py::test_m_p0_binding_exact_fields",
    "tests/test_cut4_r8_consumer_schema.py::test_r_body_exact_fields",
    "tests/test_cut4_r8_consumer_schema.py::test_r_data_completion_schema",
    "tests/test_cut4_r8_consumer_schema.py::test_r_consumer_completion_schema",
    "tests/test_cut4_r8_consumer_schema.py::test_r_membership_completion_schema",
    "tests/test_cut4_r8_consumer_schema.py::test_m_r_all_digest_equality"
  ],
  "query_request": [
    "tests/test_cut4_r8_query_request.py::test_none_input_schema",
    "tests/test_cut4_r8_query_request.py::test_full_symbol_input_schema",
    "tests/test_cut4_r8_query_request.py::test_display_symbol_unique_resolution",
    "tests/test_cut4_r8_query_request.py::test_file_input_schema",
    "tests/test_cut4_r8_query_request.py::test_search_match_input_schema",
    "tests/test_cut4_r8_query_request.py::test_search_enumerate_all_input_schema",
    "tests/test_cut4_r8_query_request.py::test_enumerate_all_requires_empty_query",
    "tests/test_cut4_r8_query_request.py::test_query_id_input_tag_join",
    "tests/test_cut4_r8_query_request.py::test_query_input_digest_domain",
    "tests/test_cut4_r8_query_request.py::test_pagination_schema_exact",
    "tests/test_cut4_r8_query_request.py::test_page_size_bounds",
    "tests/test_cut4_r8_query_request.py::test_max_pages_bounds",
    "tests/test_cut4_r8_query_request.py::test_max_results_bounds",
    "tests/test_cut4_r8_query_request.py::test_omitted_cap_rejected",
    "tests/test_cut4_r8_query_request.py::test_stats_singleton_policy",
    "tests/test_cut4_r8_query_request.py::test_live_limit_30_migration",
    "tests/test_cut4_r8_query_request.py::test_live_limit_50_migration",
    "tests/test_cut4_r8_query_request.py::test_live_limit_200_migration",
    "tests/test_cut4_r8_query_request.py::test_live_limit_2000_enumerate_all",
    "tests/test_cut4_r8_query_request.py::test_cursor_schema_digest",
    "tests/test_cut4_r8_query_request.py::test_cursor_wrong_query_rejected",
    "tests/test_cut4_r8_query_request.py::test_cursor_wrong_index_rejected",
    "tests/test_cut4_r8_query_request.py::test_cursor_prior_page_rejected",
    "tests/test_cut4_r8_query_request.py::test_page_schema_digest",
    "tests/test_cut4_r8_query_request.py::test_page_order_canonical",
    "tests/test_cut4_r8_query_request.py::test_page_replay_rejected",
    "tests/test_cut4_r8_query_request.py::test_exhaustion_start_to_end",
    "tests/test_cut4_r8_query_request.py::test_nonstart_absence_forbidden",
    "tests/test_cut4_r8_query_request.py::test_request_schema_exact",
    "tests/test_cut4_r8_query_request.py::test_evidence_receipt_identities_derived",
    "tests/test_cut4_r8_query_request.py::test_cli_explicit_project_and_s",
    "tests/test_cut4_r8_query_request.py::test_cli_unknown_argument_rejected"
  ],
  "query_evidence": [
    "tests/test_cut4_r8_query_evidence.py::test_stats_result_schema",
    "tests/test_cut4_r8_query_evidence.py::test_occurrence_result_schema",
    "tests/test_cut4_r8_query_evidence.py::test_file_symbol_result_schema",
    "tests/test_cut4_r8_query_evidence.py::test_search_symbol_result_schema",
    "tests/test_cut4_r8_query_evidence.py::test_result_union_rejects_extra",
    "tests/test_cut4_r8_query_evidence.py::test_result_canonical_order",
    "tests/test_cut4_r8_query_evidence.py::test_duplicate_result_rejected",
    "tests/test_cut4_r8_query_evidence.py::test_result_set_digest_domain",
    "tests/test_cut4_r8_query_evidence.py::test_execution_evidence_exact_schema",
    "tests/test_cut4_r8_query_evidence.py::test_execution_evidence_digest_domain",
    "tests/test_cut4_r8_query_evidence.py::test_execution_evidence_schema_tamper",
    "tests/test_cut4_r8_query_evidence.py::test_page_chain_digest",
    "tests/test_cut4_r8_query_evidence.py::test_zero_proof_exact_schema",
    "tests/test_cut4_r8_query_evidence.py::test_zero_proof_digest_domain",
    "tests/test_cut4_r8_query_evidence.py::test_provider_zero_not_query_zero",
    "tests/test_cut4_r8_query_evidence.py::test_receipt_exact_schema",
    "tests/test_cut4_r8_query_evidence.py::test_receipt_digest_domain",
    "tests/test_cut4_r8_query_evidence.py::test_receipt_identity_tamper",
    "tests/test_cut4_r8_query_evidence.py::test_partial_cap_status",
    "tests/test_cut4_r8_query_evidence.py::test_partial_positive_only",
    "tests/test_cut4_r8_query_evidence.py::test_partial_require_exhaustion_exit",
    "tests/test_cut4_r8_query_evidence.py::test_success_empty_absence_only",
    "tests/test_cut4_r8_query_evidence.py::test_debt_exit_semantics",
    "tests/test_cut4_r8_query_evidence.py::test_failure_exit_semantics",
    "tests/test_cut4_r8_query_evidence.py::test_timeout_exit_semantics",
    "tests/test_cut4_r8_query_evidence.py::test_malformed_exit_semantics",
    "tests/test_cut4_r8_query_evidence.py::test_invalid_cli_no_receipt",
    "tests/test_cut4_r8_query_evidence.py::test_authority_invalid_no_receipt"
  ],
  "semantic_projection": [
    "tests/test_cut4_r8_semantic_projection.py::test_row_kind_enum",
    "tests/test_cut4_r8_semantic_projection.py::test_operation_enum",
    "tests/test_cut4_r8_semantic_projection.py::test_direction_enum",
    "tests/test_cut4_r8_semantic_projection.py::test_identity_origin_enum",
    "tests/test_cut4_r8_semantic_projection.py::test_endpoint_enum",
    "tests/test_cut4_r8_semantic_projection.py::test_semantic_class_enum",
    "tests/test_cut4_r8_semantic_projection.py::test_owner_kind_enum",
    "tests/test_cut4_r8_semantic_projection.py::test_private_status_enum",
    "tests/test_cut4_r8_semantic_projection.py::test_private_disposition_enum",
    "tests/test_cut4_r8_semantic_projection.py::test_debt_code_enum",
    "tests/test_cut4_r8_semantic_projection.py::test_flow_instance_required",
    "tests/test_cut4_r8_semantic_projection.py::test_multiplicity_key_domain",
    "tests/test_cut4_r8_semantic_projection.py::test_multiplicity_ordinal_static",
    "tests/test_cut4_r8_semantic_projection.py::test_multiplicity_ordinal_runtime",
    "tests/test_cut4_r8_semantic_projection.py::test_runtime_order_permutation",
    "tests/test_cut4_r8_semantic_projection.py::test_duplicate_runtime_observation_debt",
    "tests/test_cut4_r8_semantic_projection.py::test_pi_exec_owner_extension",
    "tests/test_cut4_r8_semantic_projection.py::test_pi_instruction_owner_extension",
    "tests/test_cut4_r8_semantic_projection.py::test_pi_debt_exact_shape",
    "tests/test_cut4_r8_semantic_projection.py::test_pi_debt_static_runtime_equality",
    "tests/test_cut4_r8_semantic_projection.py::test_dynamic_debt_multiplicity",
    "tests/test_cut4_r8_semantic_projection.py::test_indirect_debt_multiplicity",
    "tests/test_cut4_r8_semantic_projection.py::test_equal_nonempty_debt_fails",
    "tests/test_cut4_r8_semantic_projection.py::test_pi_owner_exact_shape",
    "tests/test_cut4_r8_semantic_projection.py::test_pi_owner_phaseio_equality",
    "tests/test_cut4_r8_semantic_projection.py::test_missing_owner_debt",
    "tests/test_cut4_r8_semantic_projection.py::test_pi_private_exact_shape",
    "tests/test_cut4_r8_semantic_projection.py::test_pi_private_projection_equality",
    "tests/test_cut4_r8_semantic_projection.py::test_private_accepted_totality",
    "tests/test_cut4_r8_semantic_projection.py::test_private_rejected_debt",
    "tests/test_cut4_r8_semantic_projection.py::test_not_selected_not_neutral",
    "tests/test_cut4_r8_semantic_projection.py::test_diff_row_exact_schema",
    "tests/test_cut4_r8_semantic_projection.py::test_diff_canonical_order",
    "tests/test_cut4_r8_semantic_projection.py::test_all_diff_rows_empty",
    "tests/test_cut4_r8_semantic_projection.py::test_all_acceptance_debt_empty",
    "tests/test_cut4_r8_semantic_projection.py::test_complete_no_orphan_reconciliation"
  ],
  "regression": [
    "tests/test_cut4_r8_regression.py::test_r7_postedit_freeze_preserved",
    "tests/test_cut4_r8_regression.py::test_r7_single_owner_preserved",
    "tests/test_cut4_r8_regression.py::test_r7_query_zero_separation_preserved",
    "tests/test_cut4_r8_regression.py::test_r6_state_machine_preserved",
    "tests/test_cut4_r8_regression.py::test_r6_provider_roster_preserved",
    "tests/test_cut4_r8_regression.py::test_r6_phaseio_launch_preserved",
    "tests/test_cut4_r8_regression.py::test_stable_publication_preserved",
    "tests/test_cut4_r8_regression.py::test_compatibility_projection_preserved",
    "tests/test_cut4_r8_regression.py::test_crash_resume_preserved",
    "tests/test_cut4_r8_regression.py::test_legacy_nonadoption_preserved",
    "tests/test_cut4_r8_regression.py::test_artifact_ledger_unchanged",
    "tests/test_cut4_r8_regression.py::test_no_project_root_mutation"
  ]
}
```

Run groups in the listed order with unique system-temp roots, then all 140
nodes together, then the exact R7/R6 and accepted predecessor regressions. All
fixtures are copy-on-write; this Part-0 amendment authorizes no code or test
implementation.

## 9. Ownership and non-goals

R7's single serialized consumer-cutover/S owner and post-edit final-source
freeze remain the only future edit authority. R8 adds schema generation,
pagination, and projection implementation to that same bounded owner; it does
not authorize methodology-role or analytic-semantic changes. A fixture worker
may later own only new R8 RED tests and evidence.

No production/test/prior architecture or review is edited here. No
ArtifactLedger/G3/pin/provider/audit/project-root/commit/push/install/cutover/
release action is authorized. MODEL shards, dependency units, provider IDs,
public paths, canonical ownership, legacy bytes, state machine, and LaunchSpec
remain unchanged.
