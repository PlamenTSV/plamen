# Cut-4 transactional recon publication R7 amendment

Date: 2026-08-10
Status: Part-0 R7 architecture repair only
Supersedes: only the repaired clauses of the R6 amendment
Authority: design for independent review; no fixture, production, test,
ArtifactLedger, G3, provider, audit, commit, push, install, cutover, release,
or audit-readiness authority

## 0. Decision and inherited boundary

R7 changes exactly two R6 areas: SCIP query authority and semantic-consumer
manifest cutover. It preserves R6's read-only seven-state admission machine,
single `_recon/prepass_seed/` root, exact 39-file/nine-provider denominator,
real PhaseIO configuration preimages, ordinary live `LaunchSpec`, nonrecursive
data/control/successor/ledger domains, stable one-time
`recon/canonical_publication_v2` operation, public compatibility projection,
sole canonical/public writer, crash recovery, fresh-run-on-completed-drift,
legacy nonadoption, containment, and no ArtifactLedger or G3 change.

R7 closes the two remaining blockers:

1. M and R now bind the exact prepass plan digest, final semantic-consumer
   manifest digest, and materialized SCIP consumer rows. The reader receives
   P0/M/R, the scratchpad ledger root, consumer ID, query ID, and normalized
   query input. A canonical query preimage and result receipt make
   `SUCCESS_EMPTY` query-scoped, rather than reusing a provider-global zero.
2. One serialized consumer-cutover owner is explicitly authorized to make
   mechanical path/command/authority edits in prompts, skills, commands,
   compiler callsites, and the reader while preserving roles and analytic
   meaning. The semantic manifest is generated and frozen only from final
   post-edit bytes. Static, runtime, and instruction rows use one closed schema
   and exact canonical projections with defined multiplicity.

Section 7 contains a new exact 130-node roster. The R6 266 nodes and earlier
accepted/reviewed rosters remain predecessor regressions, not members of this
count.

## 1. Authenticated repair input

The mandatory R6 independent review was read end to end. It is 19,474 bytes
and has the required SHA-256
`d3fa5aae01c681843630729d20285b0b6692849dac84ed53f47ba02450755fc3`:

`review_fixtures/cut4_transactional_recon_publication_r6_amendment_independent_review_20260810.md`.

The reviewed R6 amendment is 42,441 bytes and SHA-256
`a58d37d0b6ea7327a4088a62ae442054ed2d3f30f7f5d6822f5b6d1b44808753`.
Its receipt is 2,928 bytes and SHA-256
`8ab43341557280c753ab211c96aa0b35035458d73be58616c255457d31471bcf`.
The review independently accepted R6 fixes 1-4 and authenticated the live
PhaseIO, ArtifactLedger, driver, prepass, prompt, mechanical, validator,
enumeration, chain, and SCIP-reader bytes. R7 does not reopen them.

## 2. Closed SCIP publication and consumer authority

### 2.1 Nonrecursive objects and M/R bindings

To avoid confusing two plans, R7 uses:

- `P0`: `_recon/prepass_seed/plan.json`, the committed prepass input plan;
- `S`: checked-in `recon_consumer_manifest.v1.json`, generated from final
  consumer source bytes;
- `D`: R6's exact publication data-output set;
- `M`: `recon_compatibility_projection_manifest.json`;
- `R`: `recon_compatibility_projection_receipt.json`;
- `SP`: the live `DriverSuccessorPlan` for D+M+R; and
- `L`: the existing ArtifactLedger work-unit/commit authority.

`P0_body` contains no publication output hash. It includes the registry,
normalizer, provider/source/config digests, S schema/version/digest,
`semantic_tuple_set_digest`, and `scip_query_registry_digest`.
`p0_plan_digest = SHA256("cut4.p0.plan.v1\0" || canonical_json(P0_body))`.
The P0 file contains `P0_body` plus that digest; `p0_file_sha256` hashes its
final file bytes. Publication binds P0 with exact same-run producer authority.

`S_body` contains the closed rows in section 5 and the final source-tree
snapshot, but no self digest. `semantic_manifest_digest` is domain-separated
SHA-256 of canonical `S_body`; the S file contains body plus digest and has a
separate `semantic_manifest_file_sha256`. S is an exact raw project PhaseIO
input, and both values must equal P0.

R6's data rows and `data_set_digest` remain unchanged. M adds this exact
non-output authority block:

```json
{
  "prepass_plan": {
    "identity": "_recon/prepass_seed/plan.json",
    "p0_plan_digest": "<sha256>",
    "file_size": 1,
    "file_sha256": "<sha256>",
    "producer_work_unit_key": "<six-component recon/prepass key>",
    "producer_contract_digest": "<sha256>",
    "producer_launch_digest": "<sha256>"
  },
  "semantic_manifest": {
    "identity": "recon_consumer_manifest.v1.json",
    "schema_version": "cut4.recon_consumer_manifest.v1",
    "manifest_digest": "<sha256>",
    "file_sha256": "<sha256>",
    "semantic_tuple_set_digest": "<sha256>"
  },
  "scip_query_authority": {
    "query_registry_digest": "<sha256>",
    "consumer_rows": [],
    "consumer_rows_digest": "<sha256>"
  }
}
```

Each materialized consumer row is copied byte-for-byte from the final S row
projection and contains `consumer_id`, row digest, allowed index identities,
allowed query IDs, required scope IDs, producer, projection row, phase gate,
and runtime probe/flow IDs. Each SCIP index data row lists the exact permitted
consumer-row digests. M still contains no M or R hash.

R repeats the exact P0/S/query-authority block and additionally hashes M and
the final D set under R6's receipt domain. M/R equality for P0 plan digest, P0
file hash, S digest/file hash, tuple-set digest, query-registry digest, and
consumer-row-set digest is mandatory. R contains no R hash or SP digest. SP
then seals exact D+M+R bytes; L validates P0 producer authority, publication
inputs, SP progress, exact output records, and the publication commit. There
is no recursion:

```text
P0 + final S -> M -> R -> SP -> L
```

A consumer never trusts files merely because their internal hashes agree.

### 2.2 Exact transactional CLI and reader checks

Every transactional invocation has this argument contract:

```text
python -m plamen_l1.scip_reader <index> <command> [query-input] \
  --scratchpad-root <scratchpad> \
  --plan <scratchpad>/_recon/prepass_seed/plan.json \
  --authority-manifest <scratchpad>/recon_compatibility_projection_manifest.json \
  --authority-receipt <scratchpad>/recon_compatibility_projection_receipt.json \
  --consumer-id <registered-id> --query-id <registered-id> --format json
```

The five query IDs are `STATS`, `DEFINITION`, `REFERENCES`, `FILE_SYMBOLS`,
and `WORKSPACE_SEARCH`; CLI spellings `stats`, `definition`, `references`,
`file`, and `search` map one-to-one. Old `find_references` command text is
mechanically corrected to `references`. `STATS` has the canonical NONE input.
Symbol queries require a full SCIP symbol or a display name resolving to
exactly one symbol. `FILE_SYMBOLS` requires an exact captured document path.
`WORKSPACE_SEARCH` carries canonical UTF-8 query bytes; the empty string is
allowed only with purpose `ENUMERATE_ALL`.

Before parsing results, the reader:

1. physically contains every path beneath the explicit scratchpad/project
   roots and rejects aliases;
2. parses and recomputes P0, S-binding, M, R, data, and control digest domains;
3. loads L from the fixed scratchpad ledger path, uses existing validation
   helpers, and requires same-run ACTIVE P0 and publication commit authority;
4. proves the passed index's size/hash/producer/projection row;
5. selects exactly one M materialized consumer row, proves its digest is in
   both M/R and permitted by the index row, and rejects an unknown or merely
   syntactically present ID;
6. proves `query_id` is allowed for that row and its normalized input and scope
   are closed; and
7. binds tool, reader, protobuf/parser, normalization, and query-registry
   versions before executing.

No implicit manifest, plan, ledger, current directory, environment, or default
consumer lookup exists. Forged mutually consistent P0/M/R bytes fail L; a
cross-run or stale producer fails; a consumer/query allowed for another index
fails.

## 3. Query-scoped result and explicit-zero proof

### 3.1 Query preimage

The canonical query preimage is:

```json
{
  "schema": "cut4.scip_query_preimage.v1",
  "run_id": "<run>",
  "publication_work_unit_key": "<key>",
  "publication_contract_digest": "<sha256>",
  "publication_commit_receipt_digest": "<sha256>",
  "p0_plan_digest": "<sha256>",
  "manifest_sha256": "<sha256>",
  "receipt_sha256": "<sha256>",
  "semantic_manifest_digest": "<sha256>",
  "consumer_id": "<id>",
  "consumer_row_digest": "<sha256>",
  "query_id": "REFERENCES",
  "normalized_query_input": {"kind": "SCIP_SYMBOL", "value": "<symbol>"},
  "query_input_digest": "<sha256>",
  "scope_ids": ["<closed lexical scope>"],
  "scope_digest": "<sha256>",
  "index_identity": "scip_rust.index",
  "index_size": 1,
  "index_sha256": "<sha256>",
  "provider_outcome_status": "SUCCESS",
  "provider_outcome_digest": "<sha256>",
  "provider_explicit_zero_digest": "<empty or sha256>",
  "tool_version": "<version>",
  "reader_version": "cut4.scip_reader.v1",
  "parser_version": "<version>"
}
```

`query_preimage_digest` is domain-separated SHA-256 of its canonical bytes,
and `query_instance_id` is the same digest prefixed `scipq:`. It binds query,
consumer, index, P0/M/R/L, scope, tool, and parser; it cannot replay against a
different value in any dimension.

### 3.2 Execution evidence and result row

Execution records invocation start/terminal state, exact argv digest, timeout,
reader/tool/parser versions, index parse completion, total documents/symbols/
occurrences visited, scope members expected/visited/skipped, resolution
candidates, rejected fragments, canonical result rows, and terminal error/debt
IDs. Results are lexically sorted and canonical JSON encoded.

The output envelope has one result row:

```json
{
  "schema": "cut4.scip_query_result.v1",
  "query_instance_id": "scipq:<sha256>",
  "query_preimage_digest": "<sha256>",
  "query_status": "SUCCESS_EMPTY",
  "provider_status": "SUCCESS",
  "evidence_usable": true,
  "result_count": 0,
  "result_rows": [],
  "result_set_digest": "<sha256 of canonical empty list>",
  "execution_evidence_digest": "<sha256>",
  "query_zero_proof": {"proof_digest": "<sha256>"},
  "debt_ids": [],
  "query_receipt_digest": "<sha256>"
}
```

The receipt digest covers the preimage digest, status, evidence usability,
canonical result set, execution evidence, zero proof or debt IDs, and terminal
state; it excludes only its own digest field. A durable downstream consumer
records this exact row/digest in its own PhaseIO-owned output. It is not a new
publication output or co-writer.

### 3.3 Total status semantics

`SUCCESS_EMPTY` is permitted only when provider status is `SUCCESS`, the query
input is valid and resolved as required, the complete authorized scope was
visited with no skipped/malformed fragment, execution terminated normally,
and the canonical result set is empty. Its `query_zero_proof` hashes:

```text
query_preimage_digest + invocation/argv digest + terminal-success record
+ tool/reader/parser versions + exact coverage counters/scope digest
+ empty result_set_digest + query_status
```

This proof is query-scoped. A provider-wide explicit-zero digest may appear in
the preimage as provenance but never substitutes for it. A successful nonempty
index can therefore prove that an exact resolved symbol has zero references or
an exact document has zero symbols. A missing/unknown symbol, misspelling,
ambiguous display name, unknown file, unbounded scope, incomplete visit, or
parser skip is `DEBT`, not `SUCCESS_EMPTY`. A schema-invalid query ID or CLI is
`AUTHORITY_INVALID` and yields no evidentiary row.

The total query mapping is:

| Condition | Query status | Evidence usable |
|---|---|---:|
| successful complete query, rows > 0 | `SUCCESS` | true |
| successful complete query, rows = 0, valid query proof | `SUCCESS_EMPTY` | true |
| provider NOT_APPLICABLE | `NOT_APPLICABLE` | false |
| provider NOT_SELECTED, unresolved/ambiguous input, or incomplete coverage | `DEBT` | false |
| provider/reader execution failure | `FAILURE` | false |
| provider/reader deadline | `TIMEOUT` | false |
| provider payload/protobuf/result malformed | `MALFORMED` | false |

Only `SUCCESS` result rows and `SUCCESS_EMPTY` zero claims may be cited.

## 4. Authorized callsite cutover and final manifest freeze

### 4.1 Resolving the R6 section 6/8 contradiction

R6 section 6's requirement to update every path-only command is retained. R6
section 8's blanket methodology freeze is narrowed precisely:

- methodology role names, analytic duties, threat models, severity logic,
  models, shard/output identities, phase order, and non-path substantive prose
  remain byte/semantically unchanged;
- exact command tokens, path placeholders, authority arguments, consumer/query
  IDs, generated authority blocks, and false-zero/fallback instructions are
  mechanically editable where required to make the same analytic action use
  authenticated inputs; and
- fallback analysis such as grep may remain, but SCIP failure/debt must stay
  visible and cannot be relabeled as SCIP zero evidence.

One `consumer_cutover_and_manifest` worker owns all such edits and the final S
file. Its pre-edit authorization plan is generated against current source
hashes and lists exact source-node digests/spans, permitted edit class, and
postcondition. At minimum it owns the current direct command/authority rows in:

```text
plamen_l1/scip_reader.py:423-450
commands/plamen-l1.md:213,325-380
prompts/l1/phase4b-depth-driver.md:26,67,116
prompts/l1/phase05-bake.md:34,56,103
prompts/l1/phase1-recon-prompt.md:116,372
prompts/l1/v2/phase1-recon-prompt.md:193,503
prompts/l1/phase5-verification-prompt.md:269
scripts/plamen_prompt.py:3781-3804
agents/depth-consensus-invariant.md:32,129-142
agents/depth-network-surface.md:32,133
```

The semantic analyzer adds any other exact SCIP path/command flow to that
closed pre-edit plan before changes. An unplanned span or nonmechanical semantic
diff is rejected. This authorization does not permit general methodology
rewriting.

### 4.2 Serialized cutover order

The only allowed order is:

1. finish provider/publication/PhaseIO schemas and reader argument contract;
2. generate and independently approve the pre-edit callsite authorization plan
   from current bytes;
3. under the single owner, edit all approved reader/compiler/prompt/skill/
   command/path rows and bindings as one change set;
4. instantiate every pipeline/mode/ecosystem/backend prompt and dry-run every
   mechanical command through the instrumented path/query boundary;
5. run the static AST/dataflow compiler on the **final post-edit source tree**;
6. generate S, recompute final source-node/tree digests, compare static/runtime/
   instruction projections, and resolve every debt/orphan/co-writer row;
7. independently diff final source against the edit plan and review S; then
   freeze S bytes/digest;
8. run a no-change rescan. Any post-freeze relevant source edit, formatting
   change, stale anchor, changed analyzer version, or tuple difference invalidates
   S and returns to step 5; and
9. only after freeze may prepass P0 bind S and transactional execution begin.

No worker edits a manifest-owned source after step 7. The same owner regenerates
S; there is no earlier worker-4/later-worker-5 split.

## 5. One closed semantic row and comparison projection

### 5.1 Exact row schema and identity

Every S row has exactly these required fields; no extra field is allowed:

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
  "projection_row_id": "compat.scip_rust.index",
  "required_phase_gate": "RECON_COMPATIBILITY_CONSUMER_DENOMINATOR",
  "probe_id": "<id>",
  "flow_edge_id": "<id>",
  "endpoint": "SINK",
  "multiplicity_ordinal": 0,
  "identity_origin": "ARGV_FLOW",
  "source_file": "<relative path>",
  "source_anchor_digest": "<sha256>",
  "semantic_class": "MECHANICAL_COMMAND",
  "allowed_query_ids": ["REFERENCES"],
  "scope_ids": ["<closed scope>"],
  "debt_code": ""
}
```

Enums are closed. `row_kind` is `EXECUTABLE`, `INSTRUCTION_ONLY`, or `DEBT`;
operation/origin/direction use R6's closed enums plus endpoint
`SOURCE`, `CALLER`, `CALLEE`, `TEMPLATE`, `RENDER`, or `SINK`.
Nonapplicable strings/arrays use canonical empty values. `row_id` is the
domain-separated hash of all other fields. S rows are lexically ordered by
`row_id` and duplicate row IDs are forbidden.

### 5.2 Canonical projections and multiplicity

Both a static executable row and runtime observation project through the same
function `pi_exec` to this exact tuple:

```text
(consumer_id, operation, exact_identity, direction, producer_id,
 projection_row_id, required_phase_gate, probe_id, flow_edge_id, endpoint,
 multiplicity_ordinal)
```

Runtime instrumentation carries a sealed consumer context so it observes every
field; absence is runtime debt. Acceptance is exact **multiset** equality
between `pi_exec(final static EXECUTABLE rows)` and
`pi_exec(all-cell runtime/fixture observations)`. Equal tuples are not
deduplicated: their lexical source/observation order assigns stable
`multiplicity_ordinal`, and counts must match.

One interprocedural flow has distinct CALLER and CALLEE rows sharing
`flow_edge_id`; runtime emits both. One prompt flow has TEMPLATE and RENDER rows
sharing its edge; runtime prompt probes emit both. Mechanical commands are
EXECUTABLE and run under a no-provider/no-project-mutation dry-run wrapper.

Pure nonexecuting documentation projects through `pi_instruction`:

```text
(consumer_id, operation, exact_identity, direction, projection_row_id,
 source_file, source_anchor_digest, semantic_class, multiplicity_ordinal)
```

It is compared exactly to an independent regeneration from final source, not
to runtime rows. If an instruction becomes executable, it needs a separate
EXECUTABLE row and probe. Instruction duplicates retain multiplicity.

DEBT rows use `exact_identity="UNRESOLVED"`, an exact debt code, source anchor,
flow/probe IDs, and the otherwise applicable fields. Static-only executable,
runtime-only, dynamic, indirect, unresolved, orphan, or co-writer cases produce
the R6 debt codes and cannot CLEAR. Final reconciliation requires:

```text
multiset(pi_exec(S executable)) = multiset(pi_exec(runtime observations))
multiset(pi_instruction(S instruction)) = multiset(pi_instruction(rescan))
multiset(S debt rows) = multiset(analyzer/probe debt observations)
consumer query tuple digest in S = P0 = M = R
publication consumer rows = S READ/QUERY projection rows
PhaseIO owner rows = S WRITE/PRODUCE projection rows
private evidence/debt dispositions = canonical + compatibility + retained-private
```

Any difference emits a canonical sorted diff with missing/extra tuple,
multiplicity, source/observation anchor, and debt disposition. No literal file
count or empty read can satisfy these equations.

## 6. Implementation boundary and non-goals

The consumer-cutover owner may modify only the approved path/command/authority
spans, reader/compiler bindings, semantic analyzer, and final S artifact during
future implementation. A separate fixture worker may add only R7 RED tests and
review evidence after S freeze. Both preserve concurrent changes and never
revert others.

All R6 non-goals remain: no ArtifactLedger/G3/pin changes; no provider install
or execution in this Part-0; no project-root mutation; no MODEL shard,
dependency-unit, role, analytic-duty, canonical-owner, compatibility-path,
state-machine, provider-universe, or LaunchSpec change; no legacy adoption;
no audit, commit, push, cutover, or release. This amendment and receipt are the
only authored files in this turn.

## 7. Exact R7 test roster

The JSON below contains exactly **130** unique pytest node IDs: 28 SCIP
authority, 32 SCIP query, 30 manifest-cutover, 28 tuple-reconcile, and 12 R6
regression nodes. There are no wildcards, implied nodes, or hidden
parameterizations.

```json
{
  "scip_authority": [
    "tests/test_cut4_r7_scip_authority.py::test_manifest_binds_p0_identity",
    "tests/test_cut4_r7_scip_authority.py::test_manifest_binds_p0_digest",
    "tests/test_cut4_r7_scip_authority.py::test_receipt_binds_p0_identity",
    "tests/test_cut4_r7_scip_authority.py::test_receipt_binds_p0_digest",
    "tests/test_cut4_r7_scip_authority.py::test_manifest_receipt_p0_equality",
    "tests/test_cut4_r7_scip_authority.py::test_manifest_binds_semantic_manifest",
    "tests/test_cut4_r7_scip_authority.py::test_manifest_binds_consumer_set",
    "tests/test_cut4_r7_scip_authority.py::test_materialized_consumer_row_digest",
    "tests/test_cut4_r7_scip_authority.py::test_index_row_consumer_membership",
    "tests/test_cut4_r7_scip_authority.py::test_cli_requires_explicit_plan",
    "tests/test_cut4_r7_scip_authority.py::test_cli_requires_explicit_manifest",
    "tests/test_cut4_r7_scip_authority.py::test_cli_requires_explicit_receipt",
    "tests/test_cut4_r7_scip_authority.py::test_cli_requires_scratchpad_ledger_root",
    "tests/test_cut4_r7_scip_authority.py::test_cli_requires_consumer_id",
    "tests/test_cut4_r7_scip_authority.py::test_cli_requires_query_id",
    "tests/test_cut4_r7_scip_authority.py::test_p0_producer_current_run",
    "tests/test_cut4_r7_scip_authority.py::test_publication_commit_current_run",
    "tests/test_cut4_r7_scip_authority.py::test_unknown_consumer_rejected",
    "tests/test_cut4_r7_scip_authority.py::test_present_but_unauthorized_consumer",
    "tests/test_cut4_r7_scip_authority.py::test_forged_manifest_consumer_row",
    "tests/test_cut4_r7_scip_authority.py::test_forged_receipt_binding",
    "tests/test_cut4_r7_scip_authority.py::test_forged_p0_binding",
    "tests/test_cut4_r7_scip_authority.py::test_cross_run_p0_rejected",
    "tests/test_cut4_r7_scip_authority.py::test_stale_p0_rejected",
    "tests/test_cut4_r7_scip_authority.py::test_wrong_index_for_consumer",
    "tests/test_cut4_r7_scip_authority.py::test_disallowed_query_for_consumer",
    "tests/test_cut4_r7_scip_authority.py::test_implicit_authority_lookup_forbidden",
    "tests/test_cut4_r7_scip_authority.py::test_authority_path_escape_rejected"
  ],
  "scip_query": [
    "tests/test_cut4_r7_scip_query.py::test_success_with_results",
    "tests/test_cut4_r7_scip_query.py::test_rust_nonempty_index_success_empty",
    "tests/test_cut4_r7_scip_query.py::test_go_nonempty_index_success_empty",
    "tests/test_cut4_r7_scip_query.py::test_provider_zero_distinct_from_query_zero",
    "tests/test_cut4_r7_scip_query.py::test_zero_proof_binds_invocation",
    "tests/test_cut4_r7_scip_query.py::test_zero_proof_binds_tool_version",
    "tests/test_cut4_r7_scip_query.py::test_zero_proof_binds_parser_version",
    "tests/test_cut4_r7_scip_query.py::test_zero_proof_binds_terminal_status",
    "tests/test_cut4_r7_scip_query.py::test_zero_proof_binds_coverage",
    "tests/test_cut4_r7_scip_query.py::test_preimage_binds_index_digest",
    "tests/test_cut4_r7_scip_query.py::test_preimage_binds_command",
    "tests/test_cut4_r7_scip_query.py::test_preimage_binds_normalized_input",
    "tests/test_cut4_r7_scip_query.py::test_preimage_binds_consumer",
    "tests/test_cut4_r7_scip_query.py::test_preimage_binds_scope",
    "tests/test_cut4_r7_scip_query.py::test_result_set_digest",
    "tests/test_cut4_r7_scip_query.py::test_result_rows_canonical",
    "tests/test_cut4_r7_scip_query.py::test_query_receipt_digest",
    "tests/test_cut4_r7_scip_query.py::test_replay_against_different_index",
    "tests/test_cut4_r7_scip_query.py::test_replay_against_different_query",
    "tests/test_cut4_r7_scip_query.py::test_replay_against_different_consumer",
    "tests/test_cut4_r7_scip_query.py::test_replay_against_different_scope",
    "tests/test_cut4_r7_scip_query.py::test_replay_against_different_tool_version",
    "tests/test_cut4_r7_scip_query.py::test_unknown_symbol_is_debt",
    "tests/test_cut4_r7_scip_query.py::test_ambiguous_symbol_is_debt",
    "tests/test_cut4_r7_scip_query.py::test_malformed_input_rejected",
    "tests/test_cut4_r7_scip_query.py::test_incomplete_coverage_is_debt",
    "tests/test_cut4_r7_scip_query.py::test_failure_not_evidence",
    "tests/test_cut4_r7_scip_query.py::test_timeout_not_evidence",
    "tests/test_cut4_r7_scip_query.py::test_malformed_provider_not_evidence",
    "tests/test_cut4_r7_scip_query.py::test_not_selected_is_debt",
    "tests/test_cut4_r7_scip_query.py::test_not_applicable_is_neutral",
    "tests/test_cut4_r7_scip_query.py::test_misspelled_query_id_rejected"
  ],
  "manifest_cutover": [
    "tests/test_cut4_r7_manifest_cutover.py::test_preedit_plan_source_hashes",
    "tests/test_cut4_r7_manifest_cutover.py::test_preedit_plan_exact_file_set",
    "tests/test_cut4_r7_manifest_cutover.py::test_preedit_plan_exact_spans",
    "tests/test_cut4_r7_manifest_cutover.py::test_command_edit_grammar",
    "tests/test_cut4_r7_manifest_cutover.py::test_path_placeholder_edit_grammar",
    "tests/test_cut4_r7_manifest_cutover.py::test_authority_argument_edit_grammar",
    "tests/test_cut4_r7_manifest_cutover.py::test_consumer_query_id_edit_grammar",
    "tests/test_cut4_r7_manifest_cutover.py::test_methodology_roles_unchanged",
    "tests/test_cut4_r7_manifest_cutover.py::test_analytic_duties_unchanged",
    "tests/test_cut4_r7_manifest_cutover.py::test_output_identities_unchanged",
    "tests/test_cut4_r7_manifest_cutover.py::test_models_unchanged",
    "tests/test_cut4_r7_manifest_cutover.py::test_severity_semantics_unchanged",
    "tests/test_cut4_r7_manifest_cutover.py::test_reader_usage_rows_cut_over",
    "tests/test_cut4_r7_manifest_cutover.py::test_plamen_l1_command_rows_cut_over",
    "tests/test_cut4_r7_manifest_cutover.py::test_l1_depth_driver_rows_cut_over",
    "tests/test_cut4_r7_manifest_cutover.py::test_generated_prompt_rows_cut_over",
    "tests/test_cut4_r7_manifest_cutover.py::test_l1_bake_rows_cut_over",
    "tests/test_cut4_r7_manifest_cutover.py::test_l1_recon_rows_cut_over",
    "tests/test_cut4_r7_manifest_cutover.py::test_l1_v2_recon_rows_cut_over",
    "tests/test_cut4_r7_manifest_cutover.py::test_l1_verification_rows_cut_over",
    "tests/test_cut4_r7_manifest_cutover.py::test_depth_agent_rows_cut_over",
    "tests/test_cut4_r7_manifest_cutover.py::test_unplanned_span_rejected",
    "tests/test_cut4_r7_manifest_cutover.py::test_all_edits_precede_generation",
    "tests/test_cut4_r7_manifest_cutover.py::test_final_source_regeneration",
    "tests/test_cut4_r7_manifest_cutover.py::test_manifest_final_source_digest",
    "tests/test_cut4_r7_manifest_cutover.py::test_stale_anchor_rejected",
    "tests/test_cut4_r7_manifest_cutover.py::test_postfreeze_edit_rejected",
    "tests/test_cut4_r7_manifest_cutover.py::test_independent_final_diff_review",
    "tests/test_cut4_r7_manifest_cutover.py::test_frozen_manifest_bound_by_p0",
    "tests/test_cut4_r7_manifest_cutover.py::test_single_serialized_owner"
  ],
  "tuple_reconcile": [
    "tests/test_cut4_r7_tuple_reconcile.py::test_row_schema_exact_fields",
    "tests/test_cut4_r7_tuple_reconcile.py::test_row_schema_rejects_extra",
    "tests/test_cut4_r7_tuple_reconcile.py::test_row_id_domain",
    "tests/test_cut4_r7_tuple_reconcile.py::test_static_exec_projection",
    "tests/test_cut4_r7_tuple_reconcile.py::test_runtime_exec_projection",
    "tests/test_cut4_r7_tuple_reconcile.py::test_projection_shapes_equal",
    "tests/test_cut4_r7_tuple_reconcile.py::test_exec_multiset_equality",
    "tests/test_cut4_r7_tuple_reconcile.py::test_duplicate_multiplicity_preserved",
    "tests/test_cut4_r7_tuple_reconcile.py::test_caller_endpoint",
    "tests/test_cut4_r7_tuple_reconcile.py::test_callee_endpoint",
    "tests/test_cut4_r7_tuple_reconcile.py::test_flow_edge_multiplicity",
    "tests/test_cut4_r7_tuple_reconcile.py::test_prompt_template_endpoint",
    "tests/test_cut4_r7_tuple_reconcile.py::test_prompt_render_endpoint",
    "tests/test_cut4_r7_tuple_reconcile.py::test_mechanical_command_dry_run",
    "tests/test_cut4_r7_tuple_reconcile.py::test_instruction_projection",
    "tests/test_cut4_r7_tuple_reconcile.py::test_instruction_schema_exact",
    "tests/test_cut4_r7_tuple_reconcile.py::test_instruction_duplicate_multiplicity",
    "tests/test_cut4_r7_tuple_reconcile.py::test_instruction_not_runtime_equaled",
    "tests/test_cut4_r7_tuple_reconcile.py::test_static_only_executable_debt",
    "tests/test_cut4_r7_tuple_reconcile.py::test_runtime_only_debt",
    "tests/test_cut4_r7_tuple_reconcile.py::test_dynamic_flow_debt",
    "tests/test_cut4_r7_tuple_reconcile.py::test_indirect_flow_debt",
    "tests/test_cut4_r7_tuple_reconcile.py::test_orphan_semantic_row_debt",
    "tests/test_cut4_r7_tuple_reconcile.py::test_cowriter_debt",
    "tests/test_cut4_r7_tuple_reconcile.py::test_control_identity_rows",
    "tests/test_cut4_r7_tuple_reconcile.py::test_public_private_projection_rows",
    "tests/test_cut4_r7_tuple_reconcile.py::test_no_orphan_equations",
    "tests/test_cut4_r7_tuple_reconcile.py::test_frozen_tuple_set_digest"
  ],
  "regression": [
    "tests/test_cut4_r7_regression.py::test_r6_state_machine_preserved",
    "tests/test_cut4_r7_regression.py::test_r6_provider_roster_preserved",
    "tests/test_cut4_r7_regression.py::test_r6_phaseio_config_preserved",
    "tests/test_cut4_r7_regression.py::test_r6_launchspec_preserved",
    "tests/test_cut4_r7_regression.py::test_r6_digest_domains_preserved",
    "tests/test_cut4_r7_regression.py::test_stable_publication_operation_preserved",
    "tests/test_cut4_r7_regression.py::test_compatibility_projection_preserved",
    "tests/test_cut4_r7_regression.py::test_crash_resume_preserved",
    "tests/test_cut4_r7_regression.py::test_legacy_nonadoption_preserved",
    "tests/test_cut4_r7_regression.py::test_model_dependency_units_preserved",
    "tests/test_cut4_r7_regression.py::test_artifact_ledger_unchanged",
    "tests/test_cut4_r7_regression.py::test_no_project_root_mutation"
  ]
}
```

Run groups in the listed order with unique system-temp roots, then all 130
nodes together, then the exact R6 and accepted predecessor regressions. The
manifest-cutover tests operate on copy-on-write fixtures; they do not authorize
source edits in this Part-0 turn.
