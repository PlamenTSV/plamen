# Cut-4 transactional recon publication R6 amendment

Date: 2026-08-10
Status: Part-0 R6 architecture repair only
Supersedes: only the repaired clauses of the R1-R5 amendments
Authority: design for independent review; no fixture, production, test,
ArtifactLedger, G3, provider, audit, commit, push, install, cutover, release,
or audit-readiness authority

## 0. Decision

R6 preserves the sound R5 direction: a fresh run uses the one stable registered
DRIVER operation `recon/canonical_publication_v2` once; an identical armed plan
can resume; completed semantic drift requires a new run in a fresh scratchpad;
and the same operation retains the authenticated public compatibility
projection until every semantic consumer is atomically migrated.

R6 closes the six R5 review blockers:

1. one read-only pre-mutation classifier distinguishes `EMPTY_FRESH`,
   `CURRENT_OWNED_INFLIGHT`, `CURRENT_OWNED_PARTIAL`,
   `CURRENT_OWNED_COMPLETE`, `LEGACY_COMPLETE`, `LEGACY_PARTIAL`, and
   `AMBIGUOUS` over the single inherited `_recon/prepass_seed/` root;
2. the exact inherited provider denominator is restored to
   `source_graph`, `build_probe`, `slither`, `opengrep`, `sec3`, `scip_rust`,
   `scip_go`, `daml_source_graph`, and `dependency_audit`;
3. operation configuration is bound as exact PhaseIO input bytes; no
   nonexistent `LaunchSpec` field is claimed;
4. data, manifest, receipt, successor-plan, and ledger-commit hash domains are
   nonrecursive and explicit;
5. every transactional SCIP query consumes manifest and receipt authority and
   returns a typed status, so successful empty evidence cannot collapse into
   provider debt; and
6. the R5 literal census becomes drift seed only. Coverage authority is a
   machine-readable per-callsite semantic manifest produced by AST/dataflow
   analysis and reconciled with instantiated runtime/fixture probes.

The exact R6 successor roster has 266 unique node IDs in section 9. R5's 316
nodes and the accepted predecessor/V7 sets remain regression evidence, not
members of the R6 count.

## 1. Authenticated input and live API truth

The mandatory R5 independent review was read end to end and authenticates at
20,121 bytes and SHA-256
`9027390d0bef11e82a9b09a44c702f5c1f32532c21c65cd8bc15966cc08e7583`:

`review_fixtures/cut4_transactional_recon_publication_r5_amendment_independent_review_20260810.md`.

The reviewed R5 amendment is 53,599 bytes and SHA-256
`277f7ca38c4f3f873217081b8bb968edf38fe5653605b8ea5a2a02f30c8722fa`.
Its receipt is 3,294 bytes and SHA-256
`791f39241886e13de0358e55bf369b6b38742edbab91233fddca6678bf1fd1f7`.
The R1-R4 chain remains authenticated at the identities in R5 section 1.

The live API constraints are controlling, not illustrative:

- `LaunchSpec` in `scripts/phase_io_contracts.py:1374-1436` has only
  `work_unit_key`, four dimensions, `model`, `timeout_s`, `exec_mode`,
  `tool_policy`, and `launch_version`.
- `InputAuthorityRequirement` at lines 993 onward supports either an explicit
  raw boundary (`allow_raw=true`) or exact producer key/writer/contract/launch
  authority. `_strict_dynamic_input_authorities()` requires the latter for
  dynamic DRIVER inputs.
- `_input_binding_record()` snapshots exact live bytes and producer authority;
  `record_work_unit_inputs()` binds that exact input set before execution.
- `plan_driver_successor_transaction()` seals exact output bytes and prestates;
  `record_work_unit_inputs(..., successor_plan=plan)` arms them;
  `load_driver_successor_plan()`, `begin_driver_successor_step()`, and
  `complete_driver_successor_step()` replay the same plan; and
  `record_work_unit_artifacts()` commits only its planned records.
- The completed successor authority is frozen. R6 never calls semantic
  invalidation/reexecution authorization for publication-v2.
- `plamen_l1/scip_reader.py` currently accepts only an argv index path and
  reports counts; it must become an owned semantic consumer, not merely receive
  a parseable empty index.

## 2. Read-only admission state machine

### 2.1 One protected namespace and one snapshot

The only transactional private root is
`scratchpad:_recon/prepass_seed/`. The R5 spelling `_recon_seed/` is retired as
an error and is never an alias. The private output denominator remains the
exact 39 nonempty paths inherited from R4: the twelve base paths below plus
three fixed files for each of nine providers.

```text
plan.json
source_capture.json
base_evidence.json
design_evidence.json
template_pattern_evidence.json
build_evidence.json
mechanical_graph.json
niche_findings.json
dependency_seed.json
tool_coverage.json
render_seed.json
namespace_capture.json
providers/<nine exact IDs>/outcome.json
providers/<nine exact IDs>/evidence.json
providers/<nine exact IDs>/debt.json
```

Before creating a ledger, recording a warning, running a provider, making a
directory, normalizing a marker, or writing staging bytes,
`classify_recon_publication_state_read_only()` takes one stable snapshot:

1. validate the admitted config path and bytes without changing them;
2. `lstat` each exact SC/DAML/L1/OS canonical identity and each of the 37 R5
   compatibility identities;
3. perform the exact sorted private-root walk against the closed 39-path set;
4. read the existing ledger bytes if present without an ensure/create helper;
5. capture types, sizes, SHA-256 values, physical file IDs, NFC/casefold keys,
   symlink/junction/reparse status, owner/run/contract/launch records, successor
   authority, and progress events; and
6. repeat metadata reads and reject an unstable snapshot.

The walk is state classification, not output discovery. Its expected names
come from the registry. Unknown names are evidence of ambiguity, never adopted
outputs.

### 2.2 Total states and transitions

| State | Exact predicate | Only permitted next action |
|---|---|---|
| `EMPTY_FRESH` | admitted config valid; no protected private/canonical/compatibility path; no recon work unit/binding/version; ledger may be absent or contain only recognized pre-recon bootstrap state | initialize the new run, compile registry, then plan/arm the 39-file private prepass |
| `CURRENT_OWNED_INFLIGHT` | current run/version; exact prepass or publication successor authority exists; contract/launch/plan replay; live bytes equal the all-old prefix, completed-step prefix, or one armed step's exact old/postimage state; no unowned/extras/aliases | load and resume the identical plan; never re-render or re-arm |
| `CURRENT_OWNED_PARTIAL` | a nonempty proper subset has exact current-run owner/binding records, but no valid replayable successor plan/progress proves that physical subset | preserve everything, emit in-memory recovery debt, and require a fresh scratchpad; do not classify as legacy or resume |
| `CURRENT_OWNED_COMPLETE` | exact 39-file committed prepass with publication absent, or exact full committed publication; all receipts current-run ACTIVE and namespace capture exact | continue to MODEL/publication, or validate completed publication and no-op |
| `LEGACY_COMPLETE` | exact complete selected legacy canonical/compatibility/private registry under old/unowned authority and no current-run claim | print loud compatibility debt, retain old ownership/read behavior, never invoke transactional writers |
| `LEGACY_PARTIAL` | nonempty proper legacy subset with only old/unowned authority, no current-run claim, and no alias/unknown path | same haltless legacy behavior and nonadoption; offer only fresh-run upgrade |
| `AMBIGUOUS` | mixed current/legacy owners, wrong run/version, unknown/superset path, invalid ledger, zero/wrong type, alias/hardlink/symlink/junction/reparse/escape, unstable snapshot, conflicting progress, or both private roots | fail closed before mutation; preserve bytes; require operator-selected fresh scratchpad |

Classification precedence is `AMBIGUOUS`, exact current-owned states, exact
legacy states, then `EMPTY_FRESH`. There is no default-to-fresh branch. The
in-memory classification record contains the exact observation digest and is
bound into the first prepass `plan.json`; it is not written before the
decision.

For `EMPTY_FRESH`, prepass itself uses an exact DRIVER successor transaction.
A crash before arm leaves `EMPTY_FRESH`; after arm it is
`CURRENT_OWNED_INFLIGHT`; an exact applied prefix remains inflight; complete
commit becomes `CURRENT_OWNED_COMPLETE`. A physical partial set without valid
progress is `CURRENT_OWNED_PARTIAL`, never silently repaired. Publication uses
the same all-old/all-new step semantics. A changed input after either arm makes
resume fail and preserves the run; after completed publication it requires a
new run and fresh scratchpad as in R5.

Legacy warnings go to stderr/in-memory UI until old behavior begins. No
checkpoint or compatibility marker is written by admission. Fresh-run upgrade
copies no ledger, private, canonical, or compatibility output.

## 3. Restored provider registry

R6's ordered provider tuple is exactly:

```json
[
  "source_graph",
  "build_probe",
  "slither",
  "opengrep",
  "sec3",
  "scip_rust",
  "scip_go",
  "daml_source_graph",
  "dependency_audit"
]
```

Every plan cell has the same three nonempty files per ID and the inherited six
provider outcome statuses: `NOT_APPLICABLE`, `NOT_SELECTED`, `SUCCESS`,
`FAILURE`, `TIMEOUT`, and `MALFORMED`. Applicability, selection, status, and
row count change bytes, never the 39-path membership. R4's exact applicability
and explicit-zero predicates remain authoritative.

`graph`, `foundry`, and `os_scanner` are not R6 provider IDs. A graph adapter
records under `source_graph`, except DAML records under `daml_source_graph`.
Foundry is an isolated system-temp implementation of the `build_probe` slot,
not a replacement identity, and it cannot modify project-root config. R6 adds
no OS scanner provider. If a later version adds literal IDs `graph`,
`foundry`, or `os_scanner`, it must append each ID to a new versioned registry,
add its three fixed files for every cell, define all six outcome states and
zero proof, expand the namespace count and tests, and conserve every old row.
An alias, rename, or nine-for-nine substitution is invalid.

For `SUCCESS`, every provider still requires terminal capture, input/config
denominators, whole-payload parsing, and either accepted evidence or its exact
provider-specific `SCHEMA_VALID_EXPLICIT_ZERO` proof. `build_probe` cannot
succeed with zero capability/result rows. `NOT_SELECTED`, `FAILURE`, `TIMEOUT`,
and `MALFORMED` carry OPEN debt; `NOT_APPLICABLE` is neutral.

## 4. Supported configuration and publication authority

### 4.1 Exact PhaseIO inputs

`resolve_phase_io_contract(..., phase="recon",
work_unit_id="canonical_publication_v2")` is the one new stable branch. It
receives exact lexical input/output tuples and exact input authorities. Its
configuration preimages are:

1. the admitted scratchpad-relative CLI config identity as an immutable input
   with `InputAuthorityRequirement(identity=..., allow_raw=True)`; and
2. `_recon/prepass_seed/plan.json` as an immutable input with the exact
   same-run `recon/prepass` DRIVER producer key, writer, contract digest, launch
   digest, and exact-contract/exact-launch requirements; and
3. the checked-in canonical `recon_consumer_manifest.v1.json` as an exact raw
   project input, with its live SHA-256 required to equal the digest recorded
   in `plan.json`.

`plan.json` canonically records operation, registry, normalizer, projection,
semantic-consumer-manifest, admitted-config SHA-256, source-input digests, and
the sole action `INITIAL_PUBLICATION`. All 38 remaining private outputs, exact
MODEL shard outputs/receipts, and dependency-reconcile inputs are likewise
producer-backed PhaseIO inputs. Publication output/prestate, staging paths,
mtimes, markers, and its receipt are not inputs.

The resolver does not pass this mixed set blindly to
`_strict_dynamic_input_authorities()`, because that helper correctly forbids
raw inputs. It canonically constructs the two explicit admitted raw
requirements first, uses the strict helper for every producer-backed path,
then requires exact identity equality with the lexical `exact_inputs` tuple.
This is ordinary `InputAuthorityRequirement` behavior, not a new API.

The input-set digest therefore binds both raw configuration bytes and their
committed normalized prepass projection. A mismatch is caught before arm; an
after-arm change prevents exact input replay and cannot load/re-arm a different
successor plan.

### 4.2 The actual LaunchSpec

The launch contains only supported fields:

```text
LaunchSpec(
  work_unit_key=contract.key,
  pipeline=<resolved pipeline>,
  mode=<resolved mode>,
  ecosystem=<resolved ecosystem>,
  backend=<resolved backend>,
  model="driver",
  timeout_s=300,
  exec_mode="python",
  tool_policy=(),
  launch_version="plamen.launch.v1"
)
```

No configuration field/digest, encoded `model`, changed `launch_version`,
dynamic slash key, manual ledger row, or self-output input is permitted. The
closed `DRIVER_PYTHON_NO_TOOLS` profile passes the live ledger check.

The operational order remains: read-only admission; predecessor transactions;
exact render in system temp; resolve contract/launch; plan exact bytes; arm
with that plan; begin/write/complete each ordinal; commit expected records;
then open consumer gates. Inflight recovery loads and supplies the identical
stored plan. Completed exact replay is a validation-only no-op. Marker/degrade
or semantic drift after arm never produces a second publication in that run.

## 5. Nonrecursive publication digest domains

Let `D` be the exact deduplicated data-output identities: selected canonical
SC/DAML/L1/OS outputs plus the 35 compatibility data paths inherited from R5.
Let controls be exactly:

```text
M = recon_compatibility_projection_manifest.json
R = recon_compatibility_projection_receipt.json
O = D union {M, R}
```

The following domains are disjoint and ordered:

1. `data_roster` is the lexical list of identities in `D`. For each final
   canonical byte string, `data_row=(identity,size,sha256,semantic source row,
   projection disposition)`. `data_set_digest` is SHA-256 over the domain tag
   `cut4.recon.data_set.v1\0` plus canonical JSON of the lexical rows.
2. Manifest body `M_body` contains the exact `data_roster`, its roster digest,
   all data rows, `data_set_digest`, and a two-row `control_slots` array:
   `(M, MANIFEST_SELF_EXCLUDED)` and `(R, RECEIPT_EXCLUDED)`. It contains no
   digest/size of M or R. Canonical JSON bytes of `M_body` produce
   `manifest_sha256`.
3. Receipt body `R_body` contains the manifest identity/size/SHA-256, the exact
   expected-final data rows and `data_set_digest`, and the same two control slots,
   with R marked `RECEIPT_SELF_EXCLUDED`. It contains no receipt size/hash and
   no plan digest. Canonical JSON bytes produce the final receipt bytes.
4. `plan_driver_successor_transaction()` sees exact bytes for all identities
   in `O`, so its transition/expected-output records hash D, M, and R.
5. ordered step completion plus `record_work_unit_artifacts()` makes the live
   ArtifactLedger commit receipt the outer authority for the full O set.

Thus M authenticates data only, R hashes M plus the exact final data set, and R
becomes a completed-data receipt only when the successor progress and ledger
commit below validate; staged R bytes alone never assert completion. The plan
authenticates D+M+R prestates/postimages,
and the ledger commit authenticates the completed plan. Nothing hashes itself. Controls have typed
self-slot rows, not projection/source rows. Missing, extra, duplicated,
reordered, or digest-bearing self slots fail schema. Consumers independently
recompute D, M, R, successor authority, and ledger commit rather than trusting
an embedded `complete_set_digest`.

## 6. Typed SCIP query authority

Both public SCIP index paths remain stable compatibility data outputs. A
non-success provider may still project a deterministic nonzero metadata-only
protobuf, but parseability is not semantic authority.

Transactional commands change atomically from a path-only invocation to:

```text
python -m plamen_l1.scip_reader <index> <command> [query] \
  --authority-manifest <scratchpad>/recon_compatibility_projection_manifest.json \
  --authority-receipt <scratchpad>/recon_compatibility_projection_receipt.json \
  --consumer-id <registered-consumer-id> --format json
```

`plamen_l1/scip_reader.py`, its driver/compiler callsites, and every prompt or
skill command row are one serialized ownership unit. The reader canonicalizes
the index identity, verifies M/R canonical bytes and hash domains, selects the
exact manifest data row and consumer row, checks the index size/hash, and emits
one typed envelope:

```json
{
  "query_status": "SUCCESS_EMPTY",
  "provider_status": "SUCCESS",
  "evidence_usable": true,
  "result_count": 0,
  "result_rows": [],
  "explicit_zero_proof_sha256": "<sha256>",
  "debt_ids": []
}
```

The query status enum and mapping are exact:

| Provider outcome | Query status | Evidence usable | Meaning |
|---|---|---:|---|
| SUCCESS, rows > 0 | `SUCCESS` | true | returned rows may be cited |
| SUCCESS, rows = 0, valid explicit-zero proof | `SUCCESS_EMPTY` | true | zero references is evidence |
| NOT_APPLICABLE | `NOT_APPLICABLE` | false | neutral, neither evidence nor debt |
| NOT_SELECTED or required payload unavailable | `DEBT` | false | OPEN debt, never zero evidence |
| FAILURE | `FAILURE` | false | OPEN failure debt |
| TIMEOUT | `TIMEOUT` | false | OPEN timeout debt |
| MALFORMED | `MALFORMED` | false | OPEN malformed debt |

Missing/invalid M, R, consumer ID, index join, or status proof is a hard
`AUTHORITY_INVALID` error and produces no query result envelope. The prompt
compiler requires `evidence_usable=true` before a MODEL role may cite result
rows or a zero. Legacy mode retains the old path-only CLI only behind explicit
`LEGACY_COMPLETE`/`LEGACY_PARTIAL` admission and makes no transactional claim.

## 7. Semantic consumer manifest

### 7.1 Row schema and source authority

R5's C001-C069 list remains a useful lexical regression seed, not coverage
authority. Future implementation checks in a canonical
`recon_consumer_manifest.v1.json` and its schema. Every occurrence/flow has one
row keyed by at least:

```json
{
  "consumer_id": "depth.l1.scip.consensus",
  "source_file": "prompts/l1/phase4b-depth-driver.md",
  "callsite_anchor": "table:SCIP_INDEX_PATH/line-digest:<sha256>",
  "operation": "QUERY",
  "identity_origin": "PROMPT_PLACEHOLDER",
  "exact_identity": "scip_rust.index",
  "direction": "READ",
  "producer_id": "recon/canonical_publication_v2",
  "projection_row_id": "compat.scip_rust.index",
  "required_phase_gate": "RECON_COMPATIBILITY_CONSUMER_DENOMINATOR",
  "runtime_probe_id": "l1.depth.scip.rust",
  "legacy_policy": "EXPLICIT_ADMISSION_ONLY"
}
```

Allowed operations are `READ`, `WRITE`, `PRODUCE`, `QUERY`, `VALIDATE`,
`PROMPT_RENDER`, and `SUBPROCESS_ARG`. Identity origins are `LITERAL`,
`REGISTRY_EXPANSION`, `PATH_COMPOSITION`, `PARAMETER`, `RETURN_FLOW`,
`ARGV_FLOW`, and `PROMPT_PLACEHOLDER`. Every row names one exact physical
identity or one closed registry expansion whose members are materialized as
rows. `WRITE`/`PRODUCE` is allowed only for the registered owner; all other
writes are co-writer debt.

### 7.2 Static semantic compilation

For Python, a pinned-version AST analyzer builds a bounded interprocedural
call graph and follows scratchpad/project roots, path constants/collections,
assignments, parameters, returns, f-strings/format calls, `/` joins,
`Path` constructors, rooted I/O, `open`, reads/writes, globs, subprocess argv,
prompt construction, PhaseIO exact tuples, and validator inputs from source to
sink. It records the AST qualname, node span, normalized source-node digest,
operation, exact identity, and dataflow chain. A generic/dynamic path that
cannot expand to the closed registry emits `DYNAMIC_PATH_DEBT`; it can never be
silently absent from the manifest.

For Markdown prompts, skills, commands, and operator documents, a structural
parser classifies placeholders, tables, fenced commands, prose reads/writes,
prohibitions, and nonexecuting examples. Prompt placeholder expansion is
joined to its compiler dataflow row. `ARGV_FLOW`, wrapper tools such as SCIP,
and helper parameters receive both caller and callee rows. The two M/R control
identities and the single `_recon/prepass_seed/` root are in the scan domain.

The analyzer examines the exact runtime/methodology source registry, not a
filename grep and not tests. Its canonical output digest is bound in prepass
`plan.json`. Source changes require regeneration and review; unknown syntax,
unresolved imports/calls, generic path construction, or unbounded registry
expansion produces typed OPEN debt.

### 7.3 Runtime and fixture reconciliation

Static rows are necessary but not sufficient. Instrumented fixtures patch the
rooted filesystem boundary, built-in path/open boundary, subprocess launch,
prompt compiler, PhaseIO resolver, and SCIP reader. They instantiate every
pipeline/mode/ecosystem/backend/provider-status cell and every recon-dependent
phase: recon MODEL/R-EXT, instantiate, breadth, inventory, depth, graph sweep,
chain, verification, and report. Each observed read/write/query/render becomes
`(consumer_id, operation, physical identity, producer, gate, probe_id)`.

Acceptance requires exact multiset equality:

```text
static semantic rows
  = runtime-observed rows + statically-proven nonruntime instruction rows
manifest READ/QUERY identities
  = publication consumer rows
manifest WRITE/PRODUCE identities
  = PhaseIO owner rows
private accepted evidence rows
  = canonical projection rows + compatibility-only rows + retained-private rows
private unresolved rows
  = canonical debt rows + compatibility debt rows
```

Any static-only executable row is `UNPROBED_CONSUMER_DEBT`; runtime-only is
`UNMANIFESTED_RUNTIME_CONSUMER_DEBT`; unresolved indirect/dynamic flow is
`INDIRECT_OR_DYNAMIC_CONSUMER_DEBT`; an evidence/debt row without a consumer is
`ORPHAN_SEMANTIC_ROW_DEBT`; and a write without the sole owner is
`CO_WRITER_DEBT`. None can be waived by an empty result. A future removal of
the public compatibility projection is allowed only when one atomic manifest
version contains zero public-path consumer rows and all runtime probes agree.

## 8. Implementation ownership, order, and non-goals

Future implementation is serialized:

1. state/registry worker: PhaseIO registry, read-only classifier, one private
   root, restored provider table, and exact semantic-manifest schema;
2. prepass worker: exact 39-output transaction, provider isolation, config
   projection, namespace capture, and no project-root mutation;
3. publication worker: render, digest domains, successor lifecycle, complete
   compatibility projection, and fresh-run disposition;
4. semantic-manifest worker: AST/dataflow compiler and canonical checked-in
   row manifest;
5. consumer worker: prompt compiler, validators, instantiate/breadth/all
   downstream gates, `plamen_l1/scip_reader.py`, and every manifest-owned
   callsite in one coordinated change;
6. fixture worker: only new copy-on-write R6 RED fixtures and receipt.

Workers must preserve concurrent changes and write only owned files. MODEL
shard identities, dependency units, methodology roles/prose, ArtifactLedger,
G3/pins, prior architecture/reviews/fixtures, providers, project-root config,
and audit outputs are not changed. R6 performs no code/test edit, provider
execution/install, audit, commit, push, cutover, or release. Legacy bytes are
never adopted/deleted/overwritten. External snapshot migration remains future
and inactive.

## 9. Exact R6 test roster

This JSON is the complete R6 roster: exactly **266** unique pytest node IDs.
Group counts are state 30, provider 54, provider-zero 12, launch-config 16,
digest 20, SCIP 20, semantic-consumer 30, publication 24, compatibility 22,
MODEL 18, existing 12, and platform 8. There are no implied nodes, wildcards,
or hidden parameterizations; loop-style failpoint nodes assert the exact
registry ordinal count internally.

```json
{
  "state": [
    "tests/test_cut4_r6_state.py::test_empty_fresh_without_ledger",
    "tests/test_cut4_r6_state.py::test_empty_fresh_with_bootstrap_ledger",
    "tests/test_cut4_r6_state.py::test_classify_before_ledger_create",
    "tests/test_cut4_r6_state.py::test_classify_before_prepass_write",
    "tests/test_cut4_r6_state.py::test_current_prepass_armed_no_step",
    "tests/test_cut4_r6_state.py::test_current_prepass_applied_prefix",
    "tests/test_cut4_r6_state.py::test_current_prepass_armed_postimage",
    "tests/test_cut4_r6_state.py::test_current_prepass_complete",
    "tests/test_cut4_r6_state.py::test_current_publication_armed_no_step",
    "tests/test_cut4_r6_state.py::test_current_publication_applied_prefix",
    "tests/test_cut4_r6_state.py::test_current_publication_armed_postimage",
    "tests/test_cut4_r6_state.py::test_current_publication_complete",
    "tests/test_cut4_r6_state.py::test_current_partial_seed_without_plan",
    "tests/test_cut4_r6_state.py::test_current_partial_publication_without_plan",
    "tests/test_cut4_r6_state.py::test_legacy_complete_canonical",
    "tests/test_cut4_r6_state.py::test_legacy_complete_compatibility",
    "tests/test_cut4_r6_state.py::test_legacy_complete_private",
    "tests/test_cut4_r6_state.py::test_legacy_partial_canonical",
    "tests/test_cut4_r6_state.py::test_legacy_partial_compatibility",
    "tests/test_cut4_r6_state.py::test_legacy_partial_private",
    "tests/test_cut4_r6_state.py::test_ambiguous_mixed_current_legacy",
    "tests/test_cut4_r6_state.py::test_ambiguous_extra_private",
    "tests/test_cut4_r6_state.py::test_ambiguous_extra_public",
    "tests/test_cut4_r6_state.py::test_ambiguous_hardlink_alias",
    "tests/test_cut4_r6_state.py::test_ambiguous_symlink",
    "tests/test_cut4_r6_state.py::test_ambiguous_junction_reparse",
    "tests/test_cut4_r6_state.py::test_ambiguous_casefold_alias",
    "tests/test_cut4_r6_state.py::test_ambiguous_unicode_alias",
    "tests/test_cut4_r6_state.py::test_ambiguous_zero_or_wrong_type",
    "tests/test_cut4_r6_state.py::test_ambiguous_wrong_run_or_version"
  ],
  "provider": [
    "tests/test_cut4_r6_provider.py::test_source_graph_not_applicable",
    "tests/test_cut4_r6_provider.py::test_source_graph_not_selected",
    "tests/test_cut4_r6_provider.py::test_source_graph_success",
    "tests/test_cut4_r6_provider.py::test_source_graph_failure",
    "tests/test_cut4_r6_provider.py::test_source_graph_timeout",
    "tests/test_cut4_r6_provider.py::test_source_graph_malformed",
    "tests/test_cut4_r6_provider.py::test_build_probe_not_applicable",
    "tests/test_cut4_r6_provider.py::test_build_probe_not_selected",
    "tests/test_cut4_r6_provider.py::test_build_probe_success",
    "tests/test_cut4_r6_provider.py::test_build_probe_failure",
    "tests/test_cut4_r6_provider.py::test_build_probe_timeout",
    "tests/test_cut4_r6_provider.py::test_build_probe_malformed",
    "tests/test_cut4_r6_provider.py::test_slither_not_applicable",
    "tests/test_cut4_r6_provider.py::test_slither_not_selected",
    "tests/test_cut4_r6_provider.py::test_slither_success",
    "tests/test_cut4_r6_provider.py::test_slither_failure",
    "tests/test_cut4_r6_provider.py::test_slither_timeout",
    "tests/test_cut4_r6_provider.py::test_slither_malformed",
    "tests/test_cut4_r6_provider.py::test_opengrep_not_applicable",
    "tests/test_cut4_r6_provider.py::test_opengrep_not_selected",
    "tests/test_cut4_r6_provider.py::test_opengrep_success",
    "tests/test_cut4_r6_provider.py::test_opengrep_failure",
    "tests/test_cut4_r6_provider.py::test_opengrep_timeout",
    "tests/test_cut4_r6_provider.py::test_opengrep_malformed",
    "tests/test_cut4_r6_provider.py::test_sec3_not_applicable",
    "tests/test_cut4_r6_provider.py::test_sec3_not_selected",
    "tests/test_cut4_r6_provider.py::test_sec3_success",
    "tests/test_cut4_r6_provider.py::test_sec3_failure",
    "tests/test_cut4_r6_provider.py::test_sec3_timeout",
    "tests/test_cut4_r6_provider.py::test_sec3_malformed",
    "tests/test_cut4_r6_provider.py::test_scip_rust_not_applicable",
    "tests/test_cut4_r6_provider.py::test_scip_rust_not_selected",
    "tests/test_cut4_r6_provider.py::test_scip_rust_success",
    "tests/test_cut4_r6_provider.py::test_scip_rust_failure",
    "tests/test_cut4_r6_provider.py::test_scip_rust_timeout",
    "tests/test_cut4_r6_provider.py::test_scip_rust_malformed",
    "tests/test_cut4_r6_provider.py::test_scip_go_not_applicable",
    "tests/test_cut4_r6_provider.py::test_scip_go_not_selected",
    "tests/test_cut4_r6_provider.py::test_scip_go_success",
    "tests/test_cut4_r6_provider.py::test_scip_go_failure",
    "tests/test_cut4_r6_provider.py::test_scip_go_timeout",
    "tests/test_cut4_r6_provider.py::test_scip_go_malformed",
    "tests/test_cut4_r6_provider.py::test_daml_source_graph_not_applicable",
    "tests/test_cut4_r6_provider.py::test_daml_source_graph_not_selected",
    "tests/test_cut4_r6_provider.py::test_daml_source_graph_success",
    "tests/test_cut4_r6_provider.py::test_daml_source_graph_failure",
    "tests/test_cut4_r6_provider.py::test_daml_source_graph_timeout",
    "tests/test_cut4_r6_provider.py::test_daml_source_graph_malformed",
    "tests/test_cut4_r6_provider.py::test_dependency_audit_not_applicable",
    "tests/test_cut4_r6_provider.py::test_dependency_audit_not_selected",
    "tests/test_cut4_r6_provider.py::test_dependency_audit_success",
    "tests/test_cut4_r6_provider.py::test_dependency_audit_failure",
    "tests/test_cut4_r6_provider.py::test_dependency_audit_timeout",
    "tests/test_cut4_r6_provider.py::test_dependency_audit_malformed"
  ],
  "provider_zero": [
    "tests/test_cut4_r6_provider_zero.py::test_source_graph_success_empty",
    "tests/test_cut4_r6_provider_zero.py::test_build_probe_zero_rejected",
    "tests/test_cut4_r6_provider_zero.py::test_slither_success_empty",
    "tests/test_cut4_r6_provider_zero.py::test_opengrep_success_empty",
    "tests/test_cut4_r6_provider_zero.py::test_sec3_success_empty",
    "tests/test_cut4_r6_provider_zero.py::test_scip_rust_success_empty",
    "tests/test_cut4_r6_provider_zero.py::test_scip_go_success_empty",
    "tests/test_cut4_r6_provider_zero.py::test_daml_source_graph_success_empty",
    "tests/test_cut4_r6_provider_zero.py::test_dependency_audit_success_empty",
    "tests/test_cut4_r6_provider_zero.py::test_r5_alias_ids_forbidden",
    "tests/test_cut4_r6_provider_zero.py::test_future_provider_is_additive",
    "tests/test_cut4_r6_provider_zero.py::test_provider_namespace_always_39"
  ],
  "launch_config": [
    "tests/test_cut4_r6_launch.py::test_launch_exact_supported_fields",
    "tests/test_cut4_r6_launch.py::test_launch_driver_python_no_tools",
    "tests/test_cut4_r6_launch.py::test_raw_config_exact_input",
    "tests/test_cut4_r6_launch.py::test_plan_exact_producer_input",
    "tests/test_cut4_r6_launch.py::test_config_in_input_set_digest",
    "tests/test_cut4_r6_launch.py::test_config_tamper_before_arm",
    "tests/test_cut4_r6_launch.py::test_config_tamper_after_arm",
    "tests/test_cut4_r6_launch.py::test_changed_config_cannot_load_plan",
    "tests/test_cut4_r6_launch.py::test_no_launch_config_field",
    "tests/test_cut4_r6_launch.py::test_no_model_field_encoding",
    "tests/test_cut4_r6_launch.py::test_no_launch_version_encoding",
    "tests/test_cut4_r6_launch.py::test_no_dynamic_work_unit_key",
    "tests/test_cut4_r6_launch.py::test_no_output_as_input",
    "tests/test_cut4_r6_launch.py::test_exact_config_replay",
    "tests/test_cut4_r6_launch.py::test_raw_config_alias_rejected",
    "tests/test_cut4_r6_launch.py::test_normalized_plan_matches_raw_config"
  ],
  "digest": [
    "tests/test_cut4_r6_digest.py::test_data_control_domains_disjoint",
    "tests/test_cut4_r6_digest.py::test_data_roster_exact",
    "tests/test_cut4_r6_digest.py::test_data_rows_exclude_controls",
    "tests/test_cut4_r6_digest.py::test_data_set_independent_recompute",
    "tests/test_cut4_r6_digest.py::test_manifest_canonical_bytes",
    "tests/test_cut4_r6_digest.py::test_manifest_self_digest_rejected",
    "tests/test_cut4_r6_digest.py::test_manifest_control_slots_exact",
    "tests/test_cut4_r6_digest.py::test_receipt_hashes_manifest",
    "tests/test_cut4_r6_digest.py::test_receipt_hashes_data_set",
    "tests/test_cut4_r6_digest.py::test_receipt_self_excluded",
    "tests/test_cut4_r6_digest.py::test_receipt_self_hash_rejected",
    "tests/test_cut4_r6_digest.py::test_control_slot_omitted",
    "tests/test_cut4_r6_digest.py::test_control_rows_reordered",
    "tests/test_cut4_r6_digest.py::test_data_row_omitted",
    "tests/test_cut4_r6_digest.py::test_data_row_extra",
    "tests/test_cut4_r6_digest.py::test_data_bytes_tampered",
    "tests/test_cut4_r6_digest.py::test_manifest_bytes_tampered",
    "tests/test_cut4_r6_digest.py::test_receipt_bytes_tampered",
    "tests/test_cut4_r6_digest.py::test_successor_plan_covers_all_outputs",
    "tests/test_cut4_r6_digest.py::test_ledger_commit_authenticates_all_outputs"
  ],
  "scip": [
    "tests/test_cut4_r6_scip.py::test_rust_success",
    "tests/test_cut4_r6_scip.py::test_rust_success_empty",
    "tests/test_cut4_r6_scip.py::test_rust_not_applicable",
    "tests/test_cut4_r6_scip.py::test_rust_debt",
    "tests/test_cut4_r6_scip.py::test_rust_failure",
    "tests/test_cut4_r6_scip.py::test_rust_timeout",
    "tests/test_cut4_r6_scip.py::test_rust_malformed",
    "tests/test_cut4_r6_scip.py::test_go_success",
    "tests/test_cut4_r6_scip.py::test_go_success_empty",
    "tests/test_cut4_r6_scip.py::test_go_not_applicable",
    "tests/test_cut4_r6_scip.py::test_go_debt",
    "tests/test_cut4_r6_scip.py::test_go_failure",
    "tests/test_cut4_r6_scip.py::test_go_timeout",
    "tests/test_cut4_r6_scip.py::test_go_malformed",
    "tests/test_cut4_r6_scip.py::test_manifest_required",
    "tests/test_cut4_r6_scip.py::test_receipt_required",
    "tests/test_cut4_r6_scip.py::test_consumer_id_required",
    "tests/test_cut4_r6_scip.py::test_debt_result_not_citable",
    "tests/test_cut4_r6_scip.py::test_success_empty_is_citable_zero",
    "tests/test_cut4_r6_scip.py::test_index_digest_tamper"
  ],
  "semantic_consumer": [
    "tests/test_cut4_r6_consumers.py::test_ast_read_sink",
    "tests/test_cut4_r6_consumers.py::test_ast_write_sink",
    "tests/test_cut4_r6_consumers.py::test_ast_producer_sink",
    "tests/test_cut4_r6_consumers.py::test_subprocess_argv_sink",
    "tests/test_cut4_r6_consumers.py::test_argv_callee_flow",
    "tests/test_cut4_r6_consumers.py::test_path_composition_flow",
    "tests/test_cut4_r6_consumers.py::test_constant_collection_expansion",
    "tests/test_cut4_r6_consumers.py::test_function_parameter_flow",
    "tests/test_cut4_r6_consumers.py::test_return_value_flow",
    "tests/test_cut4_r6_consumers.py::test_fstring_format_flow",
    "tests/test_cut4_r6_consumers.py::test_prompt_placeholder_flow",
    "tests/test_cut4_r6_consumers.py::test_markdown_command_classification",
    "tests/test_cut4_r6_consumers.py::test_prohibition_classification",
    "tests/test_cut4_r6_consumers.py::test_nonexecuting_example_classification",
    "tests/test_cut4_r6_consumers.py::test_control_identities_in_domain",
    "tests/test_cut4_r6_consumers.py::test_public_identity_rows",
    "tests/test_cut4_r6_consumers.py::test_private_identity_rows",
    "tests/test_cut4_r6_consumers.py::test_dynamic_path_debt",
    "tests/test_cut4_r6_consumers.py::test_indirect_path_debt",
    "tests/test_cut4_r6_consumers.py::test_unresolved_call_debt",
    "tests/test_cut4_r6_consumers.py::test_runtime_instantiate_probe",
    "tests/test_cut4_r6_consumers.py::test_runtime_breadth_probe",
    "tests/test_cut4_r6_consumers.py::test_runtime_inventory_probe",
    "tests/test_cut4_r6_consumers.py::test_runtime_depth_probe",
    "tests/test_cut4_r6_consumers.py::test_runtime_chain_probe",
    "tests/test_cut4_r6_consumers.py::test_runtime_verification_probe",
    "tests/test_cut4_r6_consumers.py::test_runtime_report_probe",
    "tests/test_cut4_r6_consumers.py::test_fixture_all_cells_probe",
    "tests/test_cut4_r6_consumers.py::test_static_runtime_multiset_diff",
    "tests/test_cut4_r6_consumers.py::test_no_orphan_or_cowriter"
  ],
  "publication": [
    "tests/test_cut4_r6_publication.py::test_registered_literal_key",
    "tests/test_cut4_r6_publication.py::test_fresh_only_initial_operation",
    "tests/test_cut4_r6_publication.py::test_render_before_plan",
    "tests/test_cut4_r6_publication.py::test_plan_before_arm",
    "tests/test_cut4_r6_publication.py::test_arm_exact_plan",
    "tests/test_cut4_r6_publication.py::test_begin_before_each_write",
    "tests/test_cut4_r6_publication.py::test_complete_after_each_write",
    "tests/test_cut4_r6_publication.py::test_commit_expected_records",
    "tests/test_cut4_r6_publication.py::test_crash_before_prepass_arm",
    "tests/test_cut4_r6_publication.py::test_crash_each_prepass_ordinal",
    "tests/test_cut4_r6_publication.py::test_prepass_all_old_recovery",
    "tests/test_cut4_r6_publication.py::test_prepass_all_new_recovery",
    "tests/test_cut4_r6_publication.py::test_crash_before_publication_arm",
    "tests/test_cut4_r6_publication.py::test_crash_each_publication_ordinal",
    "tests/test_cut4_r6_publication.py::test_publication_all_old_recovery",
    "tests/test_cut4_r6_publication.py::test_publication_all_new_recovery",
    "tests/test_cut4_r6_publication.py::test_resume_exact_stored_plan",
    "tests/test_cut4_r6_publication.py::test_retry_idempotent",
    "tests/test_cut4_r6_publication.py::test_completed_exact_noop",
    "tests/test_cut4_r6_publication.py::test_completed_drift_fresh_run",
    "tests/test_cut4_r6_publication.py::test_no_same_key_reexecution",
    "tests/test_cut4_r6_publication.py::test_no_manual_attempt_key",
    "tests/test_cut4_r6_publication.py::test_no_legacy_adoption",
    "tests/test_cut4_r6_publication.py::test_namespace_capture_receipt"
  ],
  "compatibility": [
    "tests/test_cut4_r6_compat.py::test_fixed_37_path_set",
    "tests/test_cut4_r6_compat.py::test_sc_canonical_set",
    "tests/test_cut4_r6_compat.py::test_daml_canonical_set",
    "tests/test_cut4_r6_compat.py::test_l1_canonical_set",
    "tests/test_cut4_r6_compat.py::test_os_canonical_set",
    "tests/test_cut4_r6_compat.py::test_complete_output_set",
    "tests/test_cut4_r6_compat.py::test_partial_output_set",
    "tests/test_cut4_r6_compat.py::test_superset_output_set",
    "tests/test_cut4_r6_compat.py::test_zero_byte_output",
    "tests/test_cut4_r6_compat.py::test_alias_output",
    "tests/test_cut4_r6_compat.py::test_project_root_containment",
    "tests/test_cut4_r6_compat.py::test_source_projection_row_conservation",
    "tests/test_cut4_r6_compat.py::test_unresolved_debt_conservation",
    "tests/test_cut4_r6_compat.py::test_nonapplicable_neutral",
    "tests/test_cut4_r6_compat.py::test_valid_zero_nonvacuous",
    "tests/test_cut4_r6_compat.py::test_provider_failure_nonvacuous",
    "tests/test_cut4_r6_compat.py::test_no_public_glob",
    "tests/test_cut4_r6_compat.py::test_no_postwrite_discovery",
    "tests/test_cut4_r6_compat.py::test_no_public_cowriter",
    "tests/test_cut4_r6_compat.py::test_no_private_orphan",
    "tests/test_cut4_r6_compat.py::test_literal_census_is_not_authority",
    "tests/test_cut4_r6_compat.py::test_atomic_future_retirement_only"
  ],
  "model": [
    "tests/test_cut4_r6_model.py::test_evm_base_visibility",
    "tests/test_cut4_r6_model.py::test_evm_rext_visibility",
    "tests/test_cut4_r6_model.py::test_solana_base_visibility",
    "tests/test_cut4_r6_model.py::test_solana_rext_visibility",
    "tests/test_cut4_r6_model.py::test_aptos_base_visibility",
    "tests/test_cut4_r6_model.py::test_aptos_rext_visibility",
    "tests/test_cut4_r6_model.py::test_sui_base_visibility",
    "tests/test_cut4_r6_model.py::test_sui_rext_visibility",
    "tests/test_cut4_r6_model.py::test_soroban_base_visibility",
    "tests/test_cut4_r6_model.py::test_soroban_rext_visibility",
    "tests/test_cut4_r6_model.py::test_daml_base_visibility",
    "tests/test_cut4_r6_model.py::test_daml_rext_visibility",
    "tests/test_cut4_r6_model.py::test_l1_rust_base_visibility",
    "tests/test_cut4_r6_model.py::test_l1_rust_rext_visibility",
    "tests/test_cut4_r6_model.py::test_l1_go_base_visibility",
    "tests/test_cut4_r6_model.py::test_l1_go_rext_visibility",
    "tests/test_cut4_r6_model.py::test_os_base_visibility",
    "tests/test_cut4_r6_model.py::test_os_rext_visibility"
  ],
  "existing": [
    "tests/test_cut4_r6_existing.py::test_legacy_warning_is_read_only",
    "tests/test_cut4_r6_existing.py::test_legacy_old_reads_continue",
    "tests/test_cut4_r6_existing.py::test_legacy_old_writers_not_adopted",
    "tests/test_cut4_r6_existing.py::test_fresh_upgrade_new_scratchpad",
    "tests/test_cut4_r6_existing.py::test_fresh_upgrade_new_run_id",
    "tests/test_cut4_r6_existing.py::test_no_ledger_copy",
    "tests/test_cut4_r6_existing.py::test_no_private_copy",
    "tests/test_cut4_r6_existing.py::test_no_canonical_copy",
    "tests/test_cut4_r6_existing.py::test_no_compatibility_copy",
    "tests/test_cut4_r6_existing.py::test_transform_receipt_legacy_state",
    "tests/test_cut4_r6_existing.py::test_orphan_second_private_root",
    "tests/test_cut4_r6_existing.py::test_ambiguous_requires_operator_fresh_run"
  ],
  "platform": [
    "tests/test_cut4_r6_platform.py::test_linux",
    "tests/test_cut4_r6_platform.py::test_macos",
    "tests/test_cut4_r6_platform.py::test_windows",
    "tests/test_cut4_r6_platform.py::test_provider_disabled",
    "tests/test_cut4_r6_platform.py::test_provider_failure",
    "tests/test_cut4_r6_platform.py::test_provider_timeout",
    "tests/test_cut4_r6_platform.py::test_foundry_system_temp_overlay",
    "tests/test_cut4_r6_platform.py::test_no_project_root_mutation"
  ]
}
```

Run each group in the listed order with unique system-temp roots, then all 266
nodes together. The R5, R4, accepted V7, and applicable existing regression
suites run afterward as predecessor checks. Any source/manifest drift expands
the semantic manifest and requires an explicit new test before acceptance.
