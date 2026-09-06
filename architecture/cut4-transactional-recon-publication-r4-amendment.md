# Cut-4 transactional recon publication R4 amendment

Date: 2026-08-10
Status: Part-0 R4 architecture repair only
Supersedes: only the repaired clauses of the R1-R3 amendments
Authority: design for independent review; no fixtures, production/tests,
ArtifactLedger, cutover, G3, provider execution/install, audit, commit, push,
release, or audit-readiness authority

## 0. R4 decision

R4 inherits the accepted R3 core: one DRIVER-owned immutable private seed
namespace; registry-compiled exact bundles; one canonical DRIVER owner; fixed
provider slots; deterministic/canonical encoding; zero-byte, complete-set,
alias, containment, namespace-capture, crash, exact replay, and all-old/all-new
consumer gates; stable same-key config-input authority with no output snapshot;
non-adoption of legacy bytes; unchanged MODEL shard identities and dependency
units; and no ArtifactLedger or G3 change.

R4 closes every authenticated R3 blocker:

1. The live post-base `R-EXT` dependency-research role is registered alongside
   the base roles, and the same sealed recon authority reaches the prompt
   renderer/compiler, prelaunch arm, executor, and postcommit recorder on PTY,
   Codex, and Claude-headless routes. Recon-only validation cannot affect
   generic workers.
2. Prompt input order is explicitly the lexical order already sealed by
   `PhaseIOContract`; R4 makes no claim that normalized immutable inputs retain
   registry declaration order.
3. Legacy detection includes `recon_signal_transform_receipt.json`,
   `scip_go.index`, dependency-audit output, and exact complete/partial/extra/
   invalid orphan private-seed states.
4. Every selected graph/scanner/dependency-audit provider executes inside the
   prepass transaction. Fresh transactional late hooks become exact private
   consumers and never run providers or fall back to retired public paths.
5. Provider `SUCCESS` requires a provider-specific terminal capture proof;
   valid zero, missing capture, neutral nonapplicability, and consumer joins are
   non-vacuous and exact.
6. Canonical replacement renders and stages first, seals the exact
   `DriverSuccessorPlan`, passes it to `record_work_unit_inputs`, publishes only
   through armed ordered steps, and commits the exact planned records.

The R3 187-ID roster remains authenticated predecessor evidence, not an R4
target or successor denominator. Section 9 defines a new literal 248-ID
roster.

## 1. Authenticated history and current API trace

The mandatory R3 independent REPAIR review was read end to end and matched
14,988 bytes and SHA-256
`8c6c2f917c695be1911f501010fc32540b40d63f30d8880a6ec22a84daa432fe`:

`review_fixtures/cut4_transactional_recon_publication_r3_amendment_independent_review_20260810.md`.

The complete R1-R3 architecture/review chain was authenticated:

| Artifact | Bytes | SHA-256 |
|---|---:|---|
| R1 amendment | 26,307 | `98032f3fbd33987bf5ff4c6d035c088fe6eab34cc9c8b8425b2ff9280e19356e` |
| R1 REPAIR review | 10,865 | `3b6ff6ff20d2ac1aa6b7128cb0b5ddfe941b17a8bb8631d8f1021f48199078f5` |
| R2 amendment | 30,919 | `7400193cb40771ce61910b14b3d34830584f76b86219ee41ab4c2f0fc21c0f73` |
| R2 REPAIR review | 8,991 | `5039a4f4ba09a253cba7cca27e55cf6b8f0fe94d0cacfef9bdfd5580c949f855` |
| R3 amendment | 40,006 | `583039a2eb7a8a2c496333d7438505461f03e14d870dd339160085d5b23fd715` |
| R3 REPAIR review | 14,988 | `8c6c2f917c695be1911f501010fc32540b40d63f30d8880a6ec22a84daa432fe` |
| accepted V7 review | 13,633 | `c8e19b0f089b3e671e5191244aed2e56e277b20190b6db7d06087b1e4fd39223` |

The repair follows the authenticated live seams:

- `_compile_typed_worker_prompt()` currently resolves a new contract without a
  role, independently of prelaunch and postcommit construction.
- `_run_single_recon_worker_pty()` performs prelaunch, prompt build, execution,
  and postcommit for base roles and for PTY `R-EXT`.
- `_run_recon_dependency_research_wave()` creates PTY `R-EXT`; the headless
  `_run_recon_dependency_research_headless()` separately performs its
  prelaunch, prompt build, Codex/Claude execution, and postcommit.
- `_run_recon_worker_pool_pty()` and the headless recon loop prebind base jobs,
  run them, then sequence `R-EXT` after the base wave.
- `PLAMEN_DISABLE_RECON_WORKER_POOL=1` currently exposes the monolithic route,
  whose `build_phase_prompt()` handoff permits recon artifact overwrite.
- `PhaseIOContract.__post_init__()` normalizes immutable and bounded inputs as
  sorted sets. The only recoverable input order is lexical.
- The pre-breadth hook currently executes OpenGrep, Rust/Go SCIP, Sec3, and L1
  dependency audit; breadth sharding falls back to `opengrep_findings.md`.
  Axis planning, Gate V, and depth finalization still name public graph files.
- `plan_driver_successor_transaction()` is read-only and seals exact planned
  bytes and prestates. `record_work_unit_inputs(..., successor_plan=plan)`
  creates successor-consumption authority. `begin_driver_successor_step()` and
  `complete_driver_successor_step()` enforce order, and
  `record_work_unit_artifacts()` requires complete successor progress and the
  planned output records.

No frozen API is broadened or edited by this amendment.

## 2. Closed ownership, bundles, and execution order

Fresh transactional execution is:

```text
admitted config + exact project capture
               |
               v
recon/prepass (DRIVER, 39 immutable private outputs)
               |
               +--> base recon MODEL wave
               |           |
               |           v
               +--> R-EXT post-base MODEL wave (SC, conditional)
               |           |
               +--> unchanged dependency reconcile
                           |
                           v
recon/canonical_merge (DRIVER, sole canonical owner)
                           |
                           +--> exact typed private consumer bindings
                                      |
                                      v
                    breadth / axis / graph / depth / verify
```

The base seed bundle remains the exact 12 R3 files. R4's provider universe is
the exact nine-ID tuple:

```text
source_graph
build_probe
slither
opengrep
sec3
scip_rust
scip_go
daml_source_graph
dependency_audit
```

Every plan cell contains the outcome/evidence/debt triple for every provider,
including nonapplicable providers. The immutable seed denominator is therefore
exactly `12 + (9 x 3) = 39` files. Provider state never changes membership.

SC canonical publication remains the R3 12-path tuple; L1 remains the R3
eight-path tuple. Both include `recon_signal_transform_receipt.json`.
`recon/canonical_merge` is the sole owner of every canonical path and publishes
the complete selected tuple plus receipt under one sealed successor plan.
Marker normalization, degrade, and resume reconciliation are same-key
reexecutions, never additional owners.

## 3. Recon-only MODEL authority through every live callsite

### 3.1 One sealed authority object

Add a frozen driver-local `ResolvedReconWorkerAuthority` containing:

```text
wave_id
agent_id
role
output
attempt
PhaseIOContract
LaunchSpec
lexical_readable_identities
role_binding_digest
```

`resolve_recon_worker_authority(job, wave_id, ...)` validates one of two closed
registries:

- `BASE`: the exact tuples returned by `_recon_worker_jobs(config)` for the
  selected pipeline/mode; or
- `POST_BASE_DEPENDENCY`: only SC
  `(R-EXT, external_dependency_research,
  recon_external_dependency_research.md)` after the exact applicable base
  MODEL outputs are committed.

`R-EXT` is deliberately not inserted into `_recon_worker_jobs()` and is not
concurrent with base roles. Its immutable inputs are:

```text
scratchpad:_recon/prepass_seed/plan.json
scratchpad:_recon/prepass_seed/source_capture.json
scratchpad:_recon/prepass_seed/base_evidence.json
scratchpad:_recon/prepass_seed/design_evidence.json
scratchpad:_recon/prepass_seed/dependency_seed.json
scratchpad:external_dependency_obligations.json
the exact committed base MODEL shard tuple for the selected SC mode
```

The obligations retain their existing DRIVER producer authority; base shards
retain their existing MODEL owners. R-EXT retains its current output, MCP
policy, conditional applicability, dependency parity, reconciliation, and
failure behavior. It cannot run before those producers commit.

### 3.2 Compiler and callsite plumbing

For recon only, `_compile_typed_worker_prompt()` accepts the already resolved
authority and calls `compile_phase_io_prompt()` with that exact contract. It
must not resolve another contract. The generated `Bound Recon Evidence` block,
compiled PhaseIO block, prelaunch receipt, executor, and postcommit recorder all
receive the same authority object. `_build_recon_worker_prompt()` and
`_build_l1_recon_worker_prompt()` accept it and render only its readable
identities.

The exact callsite changes are:

| Live route | Required authority flow |
|---|---|
| `_run_single_recon_worker_pty()` base leaf | resolve BASE once -> prelaunch arm -> build/compile prompt with same authority -> execute -> postcommit with same authority |
| `_run_recon_worker_pool_pty()` serialized base prebind | resolve each BASE authority before concurrency; pass the same object into its leaf with `inputs_prebound=True` |
| headless base loop | resolve each BASE authority -> prelaunch -> prompt compiler -> Codex/Claude executor -> postcommit |
| `_run_recon_dependency_research_wave()` | after base commits and obligations exist, resolve POST_BASE_DEPENDENCY and pass it into `_run_single_recon_worker_pty()` |
| `_run_recon_dependency_research_headless()` | after base commits and obligations exist, resolve POST_BASE_DEPENDENCY once -> prelaunch -> prompt compiler -> Codex/Claude executor -> postcommit |
| retries | resolve a new authority for the existing retry attempt key; prompt/prelaunch/postcommit remain identical within that attempt |

The generic helper behavior is unchanged. If `phase_name != "recon"`, no
recon role/wave parameter is accepted or checked and the existing generic
resolution path runs byte-for-byte as before. If `phase_name == "recon"`, a
sealed recon authority is mandatory. This prevents recon membership checks
from rejecting breadth, depth, report, methodology-repair, or any other
generic worker.

### 3.3 Lexical order and contradiction closure

R4 adopts PhaseIO lexical order. After `PhaseIOContract` normalization, the
prompt renders `contract.immutable_inputs` followed by
`contract.bounded_lookup_inputs`, each in their already sealed lexical order.
The role-binding digest covers these exact tuples. Registry declaration order
is used only while compiling sets and is never claimed as runtime prompt order.

The generated SC `templates_patterns` clause no longer says to use the
concurrent `inventory_surface` narrative “when present.” It names only its
bound private seed/provider inputs. If later architecture wants that MODEL
shard, it must add an explicit second wave; R4 does not.

All R3 positive-path replacements remain. Negative canonical-output
prohibitions remain negative. The compiled prompt contradiction scan proves a
bijection between positive readable paths and the resolved PhaseIO denominator
and rejects any retired-prepass positive authority. Static methodology files
and roles remain byte-unchanged.

Fresh transactional admission rejects
`PLAMEN_DISABLE_RECON_WORKER_POOL=1` with
`TRANSACTIONAL_RECON_WORKER_POOL_REQUIRED` before prepass or public writes.
The monolithic `build_phase_prompt()` recon route is unreachable in fresh
transactional mode. The explicit legacy branch may retain that old route and
its old ownership behavior without a transactional claim.

### 3.4 Role visibility and recall

The 14 R3 base-role mappings remain, rendered lexically. R-EXT adds exact
post-base dependency visibility, not a concurrent opportunistic read. Every
accepted provider row is visible to a named base role or downstream consumer;
every rejected fragment is visible as OPEN debt. Every row is later
`PROJECTED`, `EXPLICIT_ZERO`, or `RETAINED_PRIVATE` with an exact consumer ID in
the transform receipt. Private paths therefore lose no found output, while
typed producer joins prevent stale/noisy public bytes from becoming evidence.

## 4. Complete provider registry and non-vacuous receipts

### 4.1 Exact applicability and selection

Applicability is a pure predicate over the compiled pipeline/ecosystem and the
already captured source/manifest denominator. Selection is a pure predicate
over normalized configuration/mode/environment switches. Both predicate IDs
and input digests are stored in `plan.json` before execution; `selected =>
applicable` is mandatory.

| Provider | Applicability predicate |
|---|---|
| `source_graph` | nonempty source capture in SC EVM/Aptos/Sui/Solana/Soroban, or L1 mixed fallback |
| `build_probe` | supported SC/L1 cell with a captured source/build-root denominator; lack of executable is FAILURE, not nonapplicability |
| `slither` | SC EVM with at least one captured Solidity source |
| `opengrep` | non-DAML SC with at least one captured supported source |
| `sec3` | SC Solana with captured Rust/Cargo source root |
| `scip_rust` | SC Solana/Soroban or L1 Rust/mixed with captured Rust source root |
| `scip_go` | L1 Go/mixed with captured Go module/source root |
| `daml_source_graph` | SC DAML with at least one captured DAML source |
| `dependency_audit` | L1 Go/Rust/mixed with a captured applicable module/lockfile denominator |

The exact status predicates remain:

```text
NOT_APPLICABLE = applicable false, selected false, attempted false
NOT_SELECTED   = applicable true, selected false, attempted false
SUCCESS        = applicable true, selected true, terminal capture proof valid
FAILURE        = applicable true, selected true, start/exit/isolation/tool failure
TIMEOUT        = applicable true, selected true, deadline terminal
MALFORMED      = applicable true, selected true, capture/schema/encoding invalid
```

`NOT_APPLICABLE` is neutral: its evidence has
`evidence_semantics=NONE_NOT_APPLICABLE`, its debt disposition is `NEUTRAL`,
and no consumer counts it in either evidence or debt. `NOT_SELECTED` is OPEN
debt. Failure/timeout/malformed may retain independently valid rows, but never
become CLEAR.

### 4.2 Non-vacuous SUCCESS and valid zero

Every selected adapter writes a terminal envelope in its attempt-private root.
`SUCCESS` requires all of:

1. provider start and terminal state observed under the registered timeout;
2. a nonempty raw terminal envelope with digest and byte count;
3. exact captured target/source/package denominator and provider/config/rule or
   query digest;
4. parser completion over the entire envelope with no unaccounted bytes or
   fragments; and
5. either one or more accepted rows, or provider-specific
   `SCHEMA_VALID_EXPLICIT_ZERO` proof.

Missing, empty, truncated, unterminated, or denominator-free capture cannot be
`SUCCESS` and cannot have CLEAR debt. The provider-specific zero rules are:

- `build_probe`: zero capability rows is invalid; SUCCESS has one typed build
  capability/result row.
- graph providers (`source_graph`, `slither` graph projection, `scip_rust`,
  `scip_go`, `daml_source_graph`): zero edges is valid only with a complete
  nonempty captured node/source denominator and terminal parser proof.
- scanners (`slither`, `opengrep`, `sec3`): zero findings is valid only when the
  exact target and rule/analyzer denominator completed successfully.
- `dependency_audit`: zero vulnerabilities is valid only when the exact
  captured package/lockfile denominator and query completed successfully.

### 4.3 Exact triple and consumer join

All three nonempty files include `provider_id`, `plan_digest`, status,
`applicability_predicate_digest`, `selection_predicate_digest`, attempt ID, and
a shared `join_key`. The join key hashes those nonrecursive fields plus the raw
capture digest. `outcome.json` additionally stores the canonical payload
digests of `evidence.json` and `debt.json`; evidence/debt do not embed the
outcome file digest, avoiding a cycle.

Before any MODEL/downstream consumer:

```text
plan provider slot = outcome provider/status/predicate digests
outcome evidence_payload_digest = canonical evidence payload digest
outcome debt_payload_digest = canonical debt payload digest
outcome/evidence/debt join_key = identical
observed fragments = accepted rows + rejected fragment digests
```

The consumer contract binds the complete triple with exact prepass producer
authority. Its consumer receipt records the three ledger binding digests,
accepted row IDs, rejected debt digests, and each disposition. A mismatch is
input debt, never partial evidence. `recon_signal_transform_receipt.json`
performs the same join for canonical projection and names the exact private
consumer for every retained row.

## 5. Move all late recon providers into prepass

Fresh transactional mode executes all nine selected providers in
`recon/prepass` against attempt-private copied inputs before any MODEL launch.
OpenGrep, Rust/Go SCIP, Sec3, and dependency audit are no longer executed in
the pre-breadth hook. `tool_coverage.json` composes all nine fixed triples
inside the same prepass transaction. Environment disable switches participate
in the sealed selection predicate and produce `NOT_SELECTED`, not a missing
late outcome.

`dependency_audit` is distinct from MODEL `R-EXT`: the provider scans captured
Go/Rust dependency metadata, while R-EXT researches SC external semantic
obligations. Its former public `dependency_audit_findings.md` becomes a retired
legacy path; its rows live in the fixed private triple.

Fresh callsites are redirected exactly:

| Current seam | Transactional behavior and exact private binding |
|---|---|
| pre-breadth OpenGrep branch | no execution; validate `providers/opengrep/{outcome,evidence,debt}.json` and pass the triple to `shard_opengrep_obligations()` |
| OpenGrep sharder/fallback | shard only accepted provider row IDs; bind outcome/evidence/debt and plan; remove fallback to public `opengrep_findings.md` |
| pre-breadth Rust/Go SCIP and Sec3 branches | no execution or primitive-status mutation; validate their fixed triples and continue with typed debt on nonsuccess |
| pre-breadth dependency-audit branch | no execution; bind `providers/dependency_audit/{outcome,evidence,debt}.json` |
| pre-breadth tool reconciliation | no public ledger mutation; consume prepass `tool_coverage.json` and all nine outcome/debt joins |
| axis planning source inputs | replace `_mechanical_graph.json` and `function_summary.md` with `mechanical_graph.json` plus the applicable graph-provider triples |
| Gate V / enumeration derivation | bind `mechanical_graph.json` and exact chain-candidate input; no public graph fallback |
| depth finalization source denominator | remove public graph patterns; add exact `mechanical_graph.json`, scanner triples, and graph triples through PhaseIO, not a glob |
| L1 graph-sweep coverage preparation | bind `mechanical_graph.json`, `scip_rust`/`scip_go` triples as applicable, and their debt |
| depth/verify dependency-audit consumer | bind the dependency-audit triple; every accepted advisory row is dispositioned or debt-carried |

The registry exposes exact lexical `private_inputs_for_consumer(consumer_id)`
tuples for:

```text
recon.model.<role>
recon.dependency_research
breadth.opengrep_shard
breadth.worker
axis_planning.worklist
depth.variant_gate
depth.finalization
graph_sweeps.coverage_prepare
depth.dependency_audit
verify.dependency_audit
tool_coverage.compose
recon.canonical_merge
```

The appropriate existing PhaseIO contract includes each tuple as immutable,
same-run prepass-produced input. No public alias is generated. In
`LEGACY_COMPATIBILITY_DEBT`, old late callsites and public readers may retain
their old behavior without transactional claims, and never write into the new
private namespace.

## 6. Exact legacy and private-state predicate

### 6.1 Public and auxiliary registry

The exact SC canonical legacy array is:

```json
[
  "recon_summary.md",
  "design_context.md",
  "attack_surface.md",
  "state_variables.md",
  "function_list.md",
  "contract_inventory.md",
  "template_recommendations.md",
  "detected_patterns.md",
  "setter_list.md",
  "emit_list.md",
  "build_status.md",
  "recon_signal_transform_receipt.json"
]
```

The exact L1 canonical legacy array is:

```json
[
  "recon_summary.md",
  "threat_model.md",
  "subsystem_map.md",
  "attack_surface.md",
  "trust_boundaries.md",
  "template_recommendations.md",
  "scope_leftover.md",
  "recon_signal_transform_receipt.json"
]
```

The exact auxiliary registry is the R3 array plus
`scip_go.index` and `dependency_audit_findings.md`:

```json
[
  "_recon_static_probe.md",
  "meta_buffer.md",
  "slither/primitive_status.md",
  "_mechanical_graph.json",
  "_mechanical_graph_generation.json",
  "caller_map.md",
  "callee_map.md",
  "state_write_map.md",
  "function_summary.md",
  "niche_interface_parity_findings.md",
  "niche_permissionless_setters_findings.md",
  "tool_coverage_ledger.json",
  "tool_coverage_ledger.md",
  "tool_coverage_ledger_repair_required.md",
  "opengrep_results.sarif",
  "opengrep_findings.md",
  "sec3_results.sarif",
  "sec3_findings.md",
  "scip_rust.index",
  "scip_go.index",
  "dependency_audit_findings.md",
  "daml_prepass_noop.md",
  ".sec3-output"
]
```

`primitive_status.md` at scratchpad root remains an L1 Bake input and is not a
recon legacy indicator. Exact `lstat` checks, type/physical identity capture,
and nonmutation rules from R3 remain; no public glob or suffix discovery is
allowed. A receipt-only crash remnant is therefore legacy debt rather than a
false fresh run.

### 6.2 Exact private namespace state

The global 39-file seed set makes pre-plan detection possible. The driver
compares an exact sorted recursive walk of `_recon/prepass_seed/` with those 39
file identities and the fixed required directory identities. This private walk
is a containment/state check, never output discovery or adoption.

```text
PRIVATE_STATE =
  ABSENT
  CURRENT_OWNED_COMPLETE
  CURRENT_OWNED_INFLIGHT
  ORPHAN_COMPLETE
  ORPHAN_PARTIAL
  ORPHAN_SUPERSET
  INVALID_ZERO_TYPE_ALIAS_ESCAPE
```

Complete/current requires every file nonempty, exact same-run prepass ownership,
and valid namespace capture. Inflight additionally requires replayable sealed
successor progress. Any bytes without the exact current producer are ORPHAN;
extras are SUPERSET; zero, wrong type, casefold/hardlink/symlink/junction or
escape is INVALID. None is adopted, deleted, normalized, or overwritten.

### 6.3 Version source and total classification

`VERSION_STATE` is read only from the exact
`scratchpad:_recon/prepass_seed/plan.json` bytes:

- empty new run: file absent -> `ABSENT`;
- prepass-only: committed producer-owned plan -> `CUT4_RECON_V4`;
- canonical committed: the same plan input -> `CUT4_RECON_V4`;
- canonical inflight: the same exact plan input plus replayable successor arm
  -> `CUT4_RECON_V4`;
- unowned, malformed, unknown-version, or digest-mismatched plan ->
  `OLD_UNKNOWN_OR_MALFORMED`.

Checkpoint text may report compatibility debt but is never registry-version
authority. `UNIT_STATE` still examines only the closed pre-v4/current recon key
sets. The total predicate is:

| Condition | Classification |
|---|---|
| admitted config; no public/aux path; `PRIVATE=ABSENT`; `VERSION=ABSENT`; no recon unit; canonical absent | `FRESH_TRANSACTIONAL` new |
| admitted config; no aux legacy object; `PRIVATE=CURRENT_OWNED_COMPLETE` or valid `CURRENT_OWNED_INFLIGHT`; `VERSION=CUT4_RECON_V4`; only exact current units; canonical absent/current committed/valid inflight with exact owner | `FRESH_TRANSACTIONAL` resume/recover |
| every other combination, including any public unowned/partial receipt, auxiliary object, orphan private state, old/mixed unit, bad version, bad inflight, alias/zero/type issue, or unadmitted config | `LEGACY_COMPATIBILITY_DEBT` |

Compatibility is loud and haltless by itself. It preserves old read/ownership
behavior and never binds, adopts, strips, repairs, moves, deletes, or overwrites
legacy/private orphan bytes. Upgrade remains a fresh archived run. External
snapshot migration remains FUTURE / NOT ACTIVE / NO AUTHORITY.

## 7. Stable transform request

R4 retains R3's admitted scratchpad configuration, exact raw input binding,
closed `DRIVER_PYTHON_NO_TOOLS` launch, nonrecursive request digest, bounded
action/reason enum, exact source-input digest, prior commit receipt, prior
history-prefix, and request chain. It still excludes canonical outputs,
prestates, mtimes, staging paths, and its own request member.

The history boundary is corrected to the frozen API: a prior history length of
31 may append the 32nd authorization; a prior length of 32 rejects the next
request. R4 adopts that exact boundary and does not impose an earlier cap.

## 8. Actual successor-plan and reexecution order

Initial publication omits step 2; a semantic refresh performs every step:

1. Persist the changed typed request atomically in the admitted scratchpad
   config; parse it back; validate action/reason, source-input digest, sequence,
   prior request, prior canonical commit receipt, and prior history-prefix.
2. Resolve/replay the unchanged canonical contract/launch and call
   `authorize_deterministic_work_unit_reexecution()`. It must return the exact
   same-key invalidation for real config/seed/shard/dependency drift; output-only
   drift rejects.
3. Purely render the entire SC/L1 postimage, including transform receipt, and
   write complete nonempty bytes only to the transaction-private staging root.
   No public path changes.
4. Call `plan_driver_successor_transaction(...,
   planned_output_bytes=complete_map, merge_events=exact_map)`. Replay the
   returned `DriverSuccessorPlan`; its transitions, ordinals, contract/launch,
   prestates, and expected postimage records are now sealed.
5. Call `record_work_unit_inputs(..., successor_plan=sealed_plan)`. This is the
   input arm and must occur before any public write. On reexecution it consumes
   the stale authorization and appends semantic history; on initial execution
   it creates the first successor authority.
6. Revalidate inputs and staged bytes. For each sealed transition ordinal,
   call `begin_driver_successor_step()`, durably replace exactly that output
   with its staged bytes, then call `complete_driver_successor_step()`.
   Consumers remain blocked while successor progress is incomplete.
7. Call `record_work_unit_artifacts(actor="DRIVER",
   expected_output_records=sealed_plan.expected_output_records,
   merge_events=sealed_events)`. The API requires complete successor progress
   and exact planned bytes. Then validate artifacts, namespace/row conservation,
   and consumer readiness.

If an arm already exists on resume, call `load_driver_successor_plan()`, replay
its authority, pass that exact plan again to
`record_work_unit_inputs(..., successor_plan=plan)`, and resume at the first
unapplied ordinal. A missing, omitted, changed, rebuilt-from-live-postwrite, or
different plan rejects before another public write. No direct replacement is
permitted outside armed steps.

This order provides exact same-key semantic history and successor consumption
authority together. Exact completed replay loads the committed receipt and is
byte/mtime/config/history no-op. Crash recovery yields the prior authoritative
tuple or completes the sealed new tuple before any PhaseIO consumer proceeds.

## 9. Exact R4 successor test roster

The literal JSON array below contains exactly **248** unique pytest node IDs:

- 9 plan cells;
- 54 provider terminal-status nodes (9 x 6);
- 15 provider-zero/join semantic nodes;
- 23 complete-set/path/physical nodes;
- 35 MODEL/prompt/callsite nodes;
- 17 transaction/successor-arm nodes;
- 20 stable-request/reexecution nodes;
- 40 compatibility/path/private-state nodes;
- 15 deferred-provider/downstream consumer nodes;
- 12 unchanged fanout/dependency/downstream controls; and
- 8 platform/provider-isolation nodes.

```json
[
  "cut4_r4.plan.sc_evm",
  "cut4_r4.plan.sc_aptos",
  "cut4_r4.plan.sc_sui",
  "cut4_r4.plan.sc_solana",
  "cut4_r4.plan.sc_soroban",
  "cut4_r4.plan.sc_daml",
  "cut4_r4.plan.l1_go",
  "cut4_r4.plan.l1_rust",
  "cut4_r4.plan.l1_mixed",
  "cut4_r4.provider.source_graph.not_applicable",
  "cut4_r4.provider.source_graph.not_selected",
  "cut4_r4.provider.source_graph.success",
  "cut4_r4.provider.source_graph.failure",
  "cut4_r4.provider.source_graph.timeout",
  "cut4_r4.provider.source_graph.malformed",
  "cut4_r4.provider.build_probe.not_applicable",
  "cut4_r4.provider.build_probe.not_selected",
  "cut4_r4.provider.build_probe.success",
  "cut4_r4.provider.build_probe.failure",
  "cut4_r4.provider.build_probe.timeout",
  "cut4_r4.provider.build_probe.malformed",
  "cut4_r4.provider.slither.not_applicable",
  "cut4_r4.provider.slither.not_selected",
  "cut4_r4.provider.slither.success",
  "cut4_r4.provider.slither.failure",
  "cut4_r4.provider.slither.timeout",
  "cut4_r4.provider.slither.malformed",
  "cut4_r4.provider.opengrep.not_applicable",
  "cut4_r4.provider.opengrep.not_selected",
  "cut4_r4.provider.opengrep.success",
  "cut4_r4.provider.opengrep.failure",
  "cut4_r4.provider.opengrep.timeout",
  "cut4_r4.provider.opengrep.malformed",
  "cut4_r4.provider.sec3.not_applicable",
  "cut4_r4.provider.sec3.not_selected",
  "cut4_r4.provider.sec3.success",
  "cut4_r4.provider.sec3.failure",
  "cut4_r4.provider.sec3.timeout",
  "cut4_r4.provider.sec3.malformed",
  "cut4_r4.provider.scip_rust.not_applicable",
  "cut4_r4.provider.scip_rust.not_selected",
  "cut4_r4.provider.scip_rust.success",
  "cut4_r4.provider.scip_rust.failure",
  "cut4_r4.provider.scip_rust.timeout",
  "cut4_r4.provider.scip_rust.malformed",
  "cut4_r4.provider.scip_go.not_applicable",
  "cut4_r4.provider.scip_go.not_selected",
  "cut4_r4.provider.scip_go.success",
  "cut4_r4.provider.scip_go.failure",
  "cut4_r4.provider.scip_go.timeout",
  "cut4_r4.provider.scip_go.malformed",
  "cut4_r4.provider.daml_source_graph.not_applicable",
  "cut4_r4.provider.daml_source_graph.not_selected",
  "cut4_r4.provider.daml_source_graph.success",
  "cut4_r4.provider.daml_source_graph.failure",
  "cut4_r4.provider.daml_source_graph.timeout",
  "cut4_r4.provider.daml_source_graph.malformed",
  "cut4_r4.provider.dependency_audit.not_applicable",
  "cut4_r4.provider.dependency_audit.not_selected",
  "cut4_r4.provider.dependency_audit.success",
  "cut4_r4.provider.dependency_audit.failure",
  "cut4_r4.provider.dependency_audit.timeout",
  "cut4_r4.provider.dependency_audit.malformed",
  "cut4_r4.provider_zero.source_graph_valid_explicit_zero",
  "cut4_r4.provider_zero.build_probe_nonzero_required",
  "cut4_r4.provider_zero.slither_valid_explicit_zero",
  "cut4_r4.provider_zero.opengrep_valid_explicit_zero",
  "cut4_r4.provider_zero.sec3_valid_explicit_zero",
  "cut4_r4.provider_zero.scip_rust_valid_explicit_zero",
  "cut4_r4.provider_zero.scip_go_valid_explicit_zero",
  "cut4_r4.provider_zero.daml_source_graph_valid_explicit_zero",
  "cut4_r4.provider_zero.dependency_audit_valid_explicit_zero",
  "cut4_r4.provider_zero.missing_capture_not_success",
  "cut4_r4.provider_zero.empty_truncated_capture_not_success",
  "cut4_r4.provider_zero.forged_clear_zero_rejected",
  "cut4_r4.provider_zero.triple_payload_digest_disagreement_rejected",
  "cut4_r4.provider_zero.applicability_selection_mismatch_rejected",
  "cut4_r4.provider_zero.consumer_join_mismatch_rejected",
  "cut4_r4.set.seed_complete_39",
  "cut4_r4.set.seed_partial",
  "cut4_r4.set.seed_superset",
  "cut4_r4.set.seed_duplicate",
  "cut4_r4.set.seed_wrong_order",
  "cut4_r4.set.seed_zero_member",
  "cut4_r4.set.seed_casefold_alias",
  "cut4_r4.set.seed_dot_parent_alias",
  "cut4_r4.set.seed_hardlink_same_file",
  "cut4_r4.set.seed_symlink_junction_escape",
  "cut4_r4.set.seed_absolute_path",
  "cut4_r4.set.seed_namespace_extra",
  "cut4_r4.set.canonical_complete_sc",
  "cut4_r4.set.canonical_complete_l1",
  "cut4_r4.set.canonical_partial",
  "cut4_r4.set.canonical_superset",
  "cut4_r4.set.canonical_duplicate",
  "cut4_r4.set.canonical_wrong_order",
  "cut4_r4.set.canonical_zero_member",
  "cut4_r4.set.canonical_casefold_alias",
  "cut4_r4.set.canonical_hardlink_same_file",
  "cut4_r4.set.canonical_symlink_junction_escape",
  "cut4_r4.set.transform_row_conservation",
  "cut4_r4.model.sc_build_static",
  "cut4_r4.model.sc_design_context",
  "cut4_r4.model.sc_inventory_surface",
  "cut4_r4.model.sc_templates_patterns",
  "cut4_r4.model.sc_light_context_static",
  "cut4_r4.model.sc_light_inventory_templates",
  "cut4_r4.model.l1_threat_fork",
  "cut4_r4.model.l1_subsystem_scope",
  "cut4_r4.model.l1_attack_trust",
  "cut4_r4.model.l1_build_static",
  "cut4_r4.model.l1_templates_patterns",
  "cut4_r4.model.l1_light_threat_fork",
  "cut4_r4.model.l1_light_subsystem_attack_trust",
  "cut4_r4.model.l1_light_build_templates",
  "cut4_r4.model.sc_external_dependency_research",
  "cut4_r4.model.missing_seed_rejected",
  "cut4_r4.model.tampered_seed_rejected",
  "cut4_r4.model.wrong_prepass_owner_rejected",
  "cut4_r4.model.provider_rejected_fragment_visible_debt",
  "cut4_r4.model.prompt_sc_inventory_surface_rewritten",
  "cut4_r4.model.prompt_sc_templates_patterns_rewritten",
  "cut4_r4.model.prompt_sc_light_inventory_templates_rewritten",
  "cut4_r4.model.prompt_sc_readable_block_exact",
  "cut4_r4.model.prompt_l1_build_static_rewritten",
  "cut4_r4.model.prompt_l1_light_build_templates_rewritten",
  "cut4_r4.model.prompt_l1_readable_block_exact",
  "cut4_r4.model.prompt_retired_positive_authority_absent",
  "cut4_r4.model.prompt_contract_visibility_bijection",
  "cut4_r4.model.rext_pty_prompt_prelaunch_postcommit_parity",
  "cut4_r4.model.rext_headless_prompt_prelaunch_postcommit_parity",
  "cut4_r4.model.rext_postbase_sequence_enforced",
  "cut4_r4.model.phaseio_lexical_input_order",
  "cut4_r4.model.generic_worker_helpers_unaffected",
  "cut4_r4.model.disabled_pool_fresh_transaction_rejected",
  "cut4_r4.model.templates_no_unbound_inventory_shard_read",
  "cut4_r4.txn.prepass.after_capture",
  "cut4_r4.txn.prepass.after_arm",
  "cut4_r4.txn.prepass.after_stage",
  "cut4_r4.txn.prepass.after_publish",
  "cut4_r4.txn.prepass.before_commit",
  "cut4_r4.txn.canonical.after_capture",
  "cut4_r4.txn.canonical.after_arm",
  "cut4_r4.txn.canonical.after_stage",
  "cut4_r4.txn.canonical.after_publish",
  "cut4_r4.txn.canonical.before_commit",
  "cut4_r4.txn.prepass_exact_noop",
  "cut4_r4.txn.canonical_exact_noop",
  "cut4_r4.txn.prepass_all_old_or_all_new",
  "cut4_r4.txn.canonical_all_old_or_all_new",
  "cut4_r4.txn.consumer_blocked_armed_partial_mixed",
  "cut4_r4.txn.successor_plan_sealed_before_input_arm",
  "cut4_r4.txn.input_arm_without_successor_plan_rejected",
  "cut4_r4.request.initial_stable_preimage",
  "cut4_r4.request.marker_same_key_history",
  "cut4_r4.request.degrade_same_key_history",
  "cut4_r4.request.resume_same_key_history",
  "cut4_r4.request.source_input_change",
  "cut4_r4.request.model_shard_change",
  "cut4_r4.request.dependency_change",
  "cut4_r4.request.normalizer_version_change",
  "cut4_r4.request.previous_commit_history_chain",
  "cut4_r4.request.no_output_snapshot_or_self_reference",
  "cut4_r4.request.exact_replay_no_config_or_history_change",
  "cut4_r4.request.config_tamper_rejected",
  "cut4_r4.request.sequence_action_reason_rejected",
  "cut4_r4.request.source_digest_rejected",
  "cut4_r4.request.previous_receipt_history_rejected",
  "cut4_r4.request.manual_dynamic_key_rejected",
  "cut4_r4.request.changed_successor_plan_rejected",
  "cut4_r4.request.armed_resume_replays_exact_plan",
  "cut4_r4.request.history_length_31_appends_32",
  "cut4_r4.request.history_length_32_rejects_next",
  "cut4_r4.compat.empty_absent_fresh",
  "cut4_r4.compat.current_prepublish_fresh",
  "cut4_r4.compat.current_sc_committed_fresh",
  "cut4_r4.compat.current_l1_committed_fresh",
  "cut4_r4.compat.old_version_no_paths_debt",
  "cut4_r4.compat.old_unit_no_paths_debt",
  "cut4_r4.compat.unowned_canonical_debt",
  "cut4_r4.compat.partial_mixed_canonical_debt",
  "cut4_r4.compat.invalid_inflight_debt",
  "cut4_r4.compat.unadmitted_config_debt",
  "cut4_r4.compat.path.sc.recon_summary",
  "cut4_r4.compat.path.sc.design_context",
  "cut4_r4.compat.path.sc.attack_surface",
  "cut4_r4.compat.path.sc.state_variables",
  "cut4_r4.compat.path.sc.function_list",
  "cut4_r4.compat.path.sc.contract_inventory",
  "cut4_r4.compat.path.sc.template_recommendations",
  "cut4_r4.compat.path.sc.detected_patterns",
  "cut4_r4.compat.path.sc.setter_list",
  "cut4_r4.compat.path.sc.emit_list",
  "cut4_r4.compat.path.sc.build_status",
  "cut4_r4.compat.path.sc.transform_receipt",
  "cut4_r4.compat.path.l1.recon_summary",
  "cut4_r4.compat.path.l1.threat_model",
  "cut4_r4.compat.path.l1.subsystem_map",
  "cut4_r4.compat.path.l1.attack_surface",
  "cut4_r4.compat.path.l1.trust_boundaries",
  "cut4_r4.compat.path.l1.template_recommendations",
  "cut4_r4.compat.path.l1.scope_leftover",
  "cut4_r4.compat.path.l1.transform_receipt",
  "cut4_r4.compat.aux_registry_all_members_nonmutating",
  "cut4_r4.compat.scip_go_index_explicit_disposition",
  "cut4_r4.compat.dependency_audit_public_output_disposition",
  "cut4_r4.compat.private_orphan_complete_debt",
  "cut4_r4.compat.private_orphan_partial_debt",
  "cut4_r4.compat.private_orphan_extra_debt",
  "cut4_r4.compat.private_orphan_zero_debt",
  "cut4_r4.compat.private_orphan_alias_escape_debt",
  "cut4_r4.compat.private_current_owned_complete_fresh",
  "cut4_r4.compat.private_current_inflight_replay_fresh",
  "cut4_r4.consumer.late_opengrep_no_execution",
  "cut4_r4.consumer.late_scip_rust_no_execution",
  "cut4_r4.consumer.late_scip_go_no_execution",
  "cut4_r4.consumer.late_sec3_no_execution",
  "cut4_r4.consumer.late_dependency_audit_no_execution",
  "cut4_r4.consumer.legacy_late_provider_behavior_preserved",
  "cut4_r4.consumer.opengrep_breadth_shard_row_conservation",
  "cut4_r4.consumer.graph_axis_planning_private_binding",
  "cut4_r4.consumer.graph_variant_gate_private_binding",
  "cut4_r4.consumer.graph_depth_finalization_private_binding",
  "cut4_r4.consumer.graph_sweep_private_binding",
  "cut4_r4.consumer.dependency_audit_depth_private_binding",
  "cut4_r4.consumer.dependency_audit_verify_private_binding",
  "cut4_r4.consumer.tool_coverage_all_nine_joined",
  "cut4_r4.consumer.no_retired_public_fallback",
  "cut4_r4.existing.fanout.sc_light_codex",
  "cut4_r4.existing.fanout.sc_core_claude_headless",
  "cut4_r4.existing.fanout.sc_thorough_pty",
  "cut4_r4.existing.fanout.l1_light_pty",
  "cut4_r4.existing.fanout.l1_core_codex",
  "cut4_r4.existing.fanout.l1_thorough_claude_headless",
  "cut4_r4.existing.dependency_wave.codex",
  "cut4_r4.existing.dependency_wave.claude_headless",
  "cut4_r4.existing.dependency_wave.pty",
  "cut4_r4.existing.dependency_typed_zero",
  "cut4_r4.existing.instantiate_exact_binding",
  "cut4_r4.existing.breadth_exact_binding",
  "cut4_r4.platform.windows_locked_replace",
  "cut4_r4.platform.windows_long_path",
  "cut4_r4.platform.posix_rename_failure",
  "cut4_r4.platform.posix_permission_failure",
  "cut4_r4.platform.provider_no_project_root_path_or_handle",
  "cut4_r4.platform.foundry_temp_overlay_only",
  "cut4_r4.platform.project_root_unchanged",
  "cut4_r4.platform.private_namespace_extra_rejected"
]
```

Each string is exactly one pytest node with no hidden parametrization. Execute
groups in array order using injected providers/platform adapters, cache
disabled, and unique system-temp roots. Then run all 248 together, frozen V7
hash/control selectors, and the bounded recon adjacency smoke suite. The R3
187 nodes are predecessor evidence only; no wildcard or inherited prose family
adds to the R4 count.

## 10. Implementation ownership and non-goals

Implementation remains serialized:

1. contract/registry worker: `scripts/phase_io_contracts.py` and planned
   `scripts/recon_publication_transaction.py`;
2. prepass/provider worker: `scripts/recon_prepass.py`;
3. canonical renderer worker: `scripts/plamen_mechanical.py`;
4. driver/prompt/callsite worker: `scripts/plamen_driver.py` and only the
   runtime-generated prompt plumbing in that file; and
5. fixture worker: only new copy-on-write R4 RED fixtures and receipt.

No concurrent shared-file editing is permitted. Static prompt/methodology
files, prior fixtures/reviews, production in this Part-0 turn,
`scripts/artifact_ledger.py`, G3 artifacts/pins, MODEL outputs, dependency-unit
identities, and canonical public filenames remain unchanged.

R4 accepts only a future implementation that proves all 248 nodes, exact
provider and consumer joins, R-EXT parity, lexical prompt order, unreachable
fresh monolithic route, complete legacy/private-state classification, stable
request history, sealed successor authority before writes, and zero
project-root/provider mutation.

Non-goals are protocol hints/findings, methodology prose/role changes, generic
worker redesign, ArtifactLedger changes, legacy adoption/migration, provider
execution or installation, audit work, G3 authority/pins, report/severity/
dedup authority, production/test edits now, commit, push, release, and
audit-readiness claims.
