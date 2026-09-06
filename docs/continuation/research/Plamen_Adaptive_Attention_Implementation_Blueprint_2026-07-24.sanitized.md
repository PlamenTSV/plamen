# Plamen Adaptive Attention and Agent-Count Controller

**Implementation blueprint — 2026-07-24**

**Repository inspected:** `<LOCAL_USER_ROOT>\plamen-codex-implementation`  
**Scope of this artifact:** architecture and implementation plan only. No repository changes, audit execution, tests, configuration changes, ground-truth access, or web research were performed.

## 1. Decision

Replace the opt-in, raw-finding-count `breadth_wave_gating` experiment with a backend-neutral, deterministic **obligation-to-evidence-channel compiler**.

The controller does not ask “did the last wave find enough findings?” It asks:

1. What exact analysis, evidence, challenge, verification, merge, and reporting obligations exist?
2. Which obligations are still uncovered, disputed, or in debt?
3. What is the smallest admissible set of independent evidence channels that can advance those obligations?
4. Which channels fit the frozen per-run and per-phase resource budgets?
5. Can the phase stop cleanly, or must it stop with explicit, report-visible debt?

An agent is one possible executor of one evidence channel. Agent count is therefore an output of the compiled work denominator, not a mode-wide constant and not a response to finding volume.

The design has these non-negotiable properties:

- No raw finding count, Markdown finding-block count, severity count, or “yield” median is a scheduling input.
- Candidate discovery is monotonic. Later stages may alias, challenge, verify, centrally deduplicate, or centrally authorize a negative disposition, but may not erase an earlier candidate.
- A worker cannot close an obligation and cannot authoritatively say `SAFE`.
- Missing graph capability, missing evidence, failed execution, budget exhaustion, cancellation, and uncertainty remain typed debt.
- Total channel caps and maximum concurrency are separate. Changing concurrency changes execution order only, never the semantic roster.
- Every worker has one exact output, one exact input denominator, a stable channel identity, a transaction receipt, and a join receipt.
- Graph/CPG information is additive. It may add obligations, promote priority, or refine slices; it may not demote baseline work, remove candidates, or authorize a negative.
- Claude and Codex receive the same semantic channel roster and resource grants. Backend adapters affect transport, not work selection.
- Clean stopping is a driver-owned proof over exact state. Budgeted stopping with debt is allowed, but it forbids a clean/full-assurance claim.

## 2. Sources and requirements carried forward

This blueprint incorporates the requirements in:

- `Plamen_CPG_and_Adaptive_Attention_Research_2026-07-24.md`
- `Plamen_Plan_Completion_Audit_2026-07-24.md`
- `Plamen_Goal_Acceptance_Ledger_2026-07-17.md`

The important resulting constraints are:

- bind the plan to the audit snapshot, phase graph, methodology bytes, backend/model/tool capability, graph treatment, predecessor receipts, phase, and dependency generation;
- represent exact methodology steps, axis cells, components, relations, provider gaps, candidate challenges, chain pairs, verifier rows, report rows, and merge ownership as obligations;
- use stable channel IDs derived from semantic work, not roster ordinal;
- preserve an immutable base roster and append changes through content-bound roster amendments;
- preserve every uncovered or failed item in a stop receipt and the final assurance projection;
- keep invariant pass 2 behind the completed pass-1 join and chain generations sequential;
- shard the current attention-repair tail instead of silently truncating it at 32 items;
- keep ground truth and evaluation identifiers outside all audit workspaces, prompts, configs, receipts, and model-visible artifacts;
- evaluate graph and adaptive attention independently in a 2x2 design.

## 3. Current implementation inventory

### 3.1 Phase graph and fixed scheduling

`scripts/plamen_types.py` owns the static phase graph:

- `Phase` at line 1204
- `phase_model` at line 1257
- `validate_phase_graph` at line 1710
- `expand_shard_phases` at line 1846
- `SC_PHASES` at line 1926
- `L1_PHASES` at line 2310

The SC graph includes recon, instantiate, breadth, rescan preparation and workers, inventory preparation/chunks/merge, invariant passes, depth, attention repair, skeptic/axis/dedup/RAG work, three chain stages, queue compilation, fixed verification stages, adjudication, report indexing/body/merge/assembly/dedup/disposition/floor.

The L1 graph has the corresponding bake, recon, breadth, graph sweeps, inventory, location recovery, invariant, depth, attention, skeptic, queue, RAG, verification, adjudication, and report stages.

Dynamic report phases are expanded from manifests, but recon/breadth/rescan/depth worker counts are still produced by phase-specific code paths.

### 3.2 Existing pool and fanout implementations

`scripts/plamen_driver.py` contains four separate discovery runtimes:

| Area | Current symbols | Current behavior |
|---|---|---|
| Generic typed worker | `_typed_worker_unit_id` (5165), `_compile_typed_worker_prompt` (5171), `_typed_model_worker_contract_and_launch` (5221), `_bind_typed_model_worker_inputs` (5276), `_prepare_typed_model_worker_launch` (5327), `_record_typed_model_worker_artifact` (5382) | Good reusable PhaseIO binding, but not a complete worker transaction. |
| Recon | `_recon_worker_jobs` (23744), `_run_recon_worker_pool_pty` (24596) | Fixed 2-worker Light or 4-worker Core/Thorough SC roster; concurrency 4; external-dependency wave follows the pool. |
| Breadth | `_breadth_worker_jobs` (25098), `_breadth_dispatch_plan` (25661), `_write_breadth_dispatch_contract` (25708), `_run_breadth_worker_pool_pty_core` (30351) | Manifest-driven SC or layer-driven L1 roster; concurrency 3; up to four PTY attempts with the default continuation budget. |
| Rescan | `_rescan_worker_jobs` (30977), `_run_rescan_worker_pool_pty` (31596) | Manifest rows partition fixed methods and per-contract rows; concurrency 3; Claude PTY-specific pool path. |
| Depth | `_depth_worker_jobs` (32995), `_depth_dispatch_plan` (34202), `_run_depth_worker_pool_pty` (35683) | Fixed standard roles plus mode/flag-triggered scanners, niches, sibling, and Thorough sidecars; concurrency 3; producer barrier before perturbation/checklist. |
| Serial backend parity | `_run_breadth_backend_fanout` (37029), `_should_use_depth_codex_fanout` (37177), `_run_depth_codex_fanout` (37205) | Breadth uses the same rendered rows on Codex/headless Claude, but serially. Depth mirrors jobs on Codex/headless Claude, also serially. |
| Phase launch | `run_phase` (37742) | Selects backend and then branches into the pool- or backend-specific runtimes around lines 38126–38234 and 38632–38710. |

`_NonBlockingWorkerPool` at line 3312 and `_cancel_pending_worker_futures` at line 3360 provide useful cancellation primitives, but current workers publish directly to canonical scratchpad files. There is no `WorkerTransaction` symbol or generic attempt/lease/commit state machine.

### 3.3 Exact authority that should be reused

The controller should build on, not bypass, these authorities:

| Module | Reusable authority |
|---|---|
| `scripts/phase_io_contracts.py` | `canonical_artifact_identity` (82), `canonical_work_unit_key` (99), `ArtifactSpec` (220), `PhaseIOContract` (354), `LaunchSpec` (533), `resolve_phase_io_contract` (990). |
| `scripts/artifact_ledger.py` | `record_work_unit_artifacts` (1390), `record_work_unit_inputs` (2283), `validate_work_unit_inputs` (2517), `detect_semantic_input_drift` (2630), `semantic_dependency_invalidation_plan` (2769), `apply_semantic_invalidation` (2824), `authorize_deterministic_work_unit_reexecution` (2899), semantic mutation arm/finalize (3135/3186), `validate_work_unit_artifacts` (3431). |
| `scripts/queue_work_items.py` | `QueueWorkItem` (473), `QueueWorkPlan` (1413), `build_queue_work_plan` (1587). |
| `scripts/verifier_work_roster.py` | `VerifierRuntimePolicy` (244), `VerifierWorkUnit` (399), `VerifierWorkRoster` (621), `build_verifier_work_roster` (870), `write_or_validate_verifier_work_roster` (1101). Current limits are four findings per verifier, concurrency four, and a 262,144-byte prompt ceiling. |
| `scripts/methodology_application_states.py` | Stable `MAO-*` methodology obligations and orthogonal delivery/application/outcome/evidence states; `build_application_queues` (252) and `build_application_receipt` (271). |
| `scripts/methodology_application.py` | Exact dispatch/methodology/prompt/output validation through `write_phase_dispatch` (161) and `validate_phase_application` (385). |
| `scripts/security_obligation_authority.py` | Stable rule-owned `SOBL-*` parents and `SOT-*` aliases, typed feature facts, PRE/POST depth separation, and non-terminal producer receipts. Readers at lines 3141, 3239, and 3288 expose repairable, queueable, and pending obligations. |
| `scripts/security_obligation_lifecycle.py` | Independent lifecycle authority with `OPEN_REPAIR`, `VERIFY_PENDING`, `VERIFICATION_DEBT`, `VERIFIED_CONFIRMED`, `VERIFIED_CONTESTED`, `NEGATIVE_PROPOSAL_RETAINED`, `AUTHORIZED_NEGATIVE`, and `CONFLICTED_REVIEW`. Only exact mandatory-denominator → routing → assignment → verifier completion plus the central closure broker can authorize a negative. |
| `scripts/coverage_shortfalls.py` | Stable `CS-*` lower-bound/unknown shortfall rows and lossless/report projections. This is a migration input, not a closure authority. |
| `scripts/assurance_limitations.py` | Lossless typed assurance manifest and bounded report projection through `build_current_assurance_manifest` (1232), `build_assurance_projection_manifest` (1250), `assurance_projection_input_paths` (1376), `project_assurance_limitations` (1605), and `validate_assurance_projection` (1640). |
| `scripts/terminal_audit_launch.py` | Pre-launch isolation, prior-evidence sealing, forbidden-input identity checks, and preparation receipts. It already proves that private evaluator bytes and paths are not copied or read by an audit workspace. |

### 3.4 Current methodology and attention call sites

- `_methodology_application_mode` at driver line 25815 selects off/observe/repair.
- `_run_methodology_application_boundary` at line 26159 runs after accepted breadth, rescan, and depth at line 51159. It is haltless and currently launches one bounded repair producer.
- `_prepare_attention_repair` in `scripts/plamen_mechanical.py` at line 9210 creates one queue for one phase worker.
- `_ATTENTION_REPAIR_MAX_ITEMS = 32` at line 8411 caps the general tail. Security obligations are kept, but other valid items are projected into coverage shortfalls when capacity is exhausted.
- The main phase loop calls `_prepare_attention_repair` around driver line 45814 and skips or runs one `attention_repair` phase.

### 3.5 Obsolete breadth gating to delete

The following contiguous block in `scripts/plamen_driver.py` is obsolete:

- `_breadth_wave_gating_enabled` (30581)
- `_breadth_wave_count_above_info` (30601)
- `_breadth_wave_yield_threshold` (30629)
- `_breadth_wave_should_spawn_next` (30641)
- `_breadth_wave_extra_jobs` (30677)
- `_breadth_wave_completed_extra_yields` (30714)
- `_breadth_wave_decide` (30743)
- `_breadth_wave_plan` (30787)
- `_breadth_run_wave_extension` (30821)
- the wave wrapper behavior in `_run_breadth_worker_pool_pty` (30923)

Its problems are structural:

- it is SC Thorough-only and opt-in;
- it runs two extra jobs per wave for at most two waves;
- it counts above-Info Markdown finding blocks;
- it uses zero yield and a median prior-yield threshold;
- extra rows are not part of the original manifest denominator;
- it has no obligation ownership, stable channel identity, exact stop receipt, independent closure, or complete debt projection;
- it is best-effort and cannot prove either coverage or safe stopping.

Delete, rather than retain, the raw-count helpers after the new breadth-only cutover passes acceptance. A deprecated config translation may remain for one release, but no old decision code should remain callable.

### 3.6 Evaluator inventory

There is no neutral `RunBundle` or adaptive-attention evaluator in the current repository. The user-facing compare command can accept a ground-truth report, and some validation comments mention benchmark history, but the audit driver has no grader boundary.

The closest reusable privacy substrate is `scripts/terminal_audit_launch.py` plus `scripts/test_terminal_audit_launch_readiness.py`, which already test forbidden external files, hardlink aliases, escaping symlinks, prior-evidence isolation, and omission of sensitive paths and bytes from receipts.

## 4. New semantic model

### 4.1 Obligation

Add `AttentionObligation` with schema `plamen.attention_obligation.v1`.

Required fields:

| Field | Meaning |
|---|---|
| `obligation_id` | Existing canonical ID when one exists (`MAO-*`, `SOT-*`, queue/candidate/axis ID); otherwise `AOB-<KIND>-<24 hex>`. |
| `kind` | `METHOD_STEP`, `AXIS_CELL`, `COMPONENT`, `RELATION`, `PROVIDER_DEBT`, `CANDIDATE_CHALLENGE`, `CHAIN_PAIR`, `VERIFIER_ITEM`, `REPORT_ITEM`, `MERGE_ITEM`, or `EXPLORATION_ITEM`. |
| `pipeline`, `mode`, `ecosystem`, `phase` | Frozen run and phase scope. |
| `dependency_generation` | Semantic generation, not execution-wave ordinal. |
| `subject_ids` | Exact component/symbol/relation/candidate identities. |
| `source_bindings` | Exact artifact identities and SHA-256 digests from which the obligation was compiled. |
| `methodology_bindings` | Method path, file digest, step ID/text digest, and application authority ID. |
| `predecessor_receipt_digests` | Exact joins/authorities that must be current before assignment. |
| `closure_policy` | Named driver-owned policy for this obligation kind. |
| `mandatory` | Boolean derived from phase/method authority, never from a model. |
| `impact_rank` | Deterministic integer 0–4 from rule/queue authority, with 4 highest. Unknown is not zero. |
| `uncertainty_class` | `KNOWN_GAP`, `MISSING_EVIDENCE`, `CONFLICT`, `UNKNOWN_DENOMINATOR`, or `NONE`. |
| `graph_origin` | `NONE`, `BASELINE`, or `TYPED_ADDITIVE`. |
| `state` | Derived controller state; never accepted from worker prose. |
| `row_digest` | SHA-256 of the canonical row excluding `row_digest`. |

New IDs are:

```text
AOB-<KIND>-UPPER(SHA256(canonical_json({
  schema, snapshot_digest, pipeline, ecosystem, phase,
  dependency_generation, kind, sorted(subject_ids),
  sorted(source_binding_digests), sorted(methodology_step_digests),
  closure_policy
}))[:24])
```

Input ordering, manifest row order, and concurrency are excluded. Snapshot, semantic generation, sources, methodology, and phase are included.

### 4.2 Obligation state

Use exactly six public states:

1. `UNCOVERED` — in the denominator with no valid completed evidence channel.
2. `ASSIGNED` — owned by at least one active roster channel.
3. `EVIDENCED` — valid evidence exists, but the closure policy is not yet satisfied.
4. `DISPUTED` — valid channels conflict, or a negative/safety proposal requires independent challenge.
5. `DEBT` — no admissible work can currently advance the obligation because of a typed failure, missing capability, exhausted budget, invalid evidence, cancellation, or incomplete denominator.
6. `CLOSED` — the named independent driver authority has replayed all required bindings and authorized closure.

The state is a projection from immutable receipts. Allowed transitions are:

```text
UNCOVERED -> ASSIGNED
ASSIGNED -> EVIDENCED | DISPUTED | DEBT
EVIDENCED -> ASSIGNED | DISPUTED | CLOSED | DEBT
DISPUTED -> ASSIGNED | CLOSED | DEBT
DEBT -> ASSIGNED                    # only after a roster amendment or valid retry
CLOSED -> UNCOVERED | DISPUTED      # dependency-scoped invalidation/reopen only
```

There is no worker transition to `CLOSED`. An invalidated closure is retained in history and reopened; it is never edited in place.

Closure policy examples:

- methodology step: independently validated application receipt;
- positive candidate: verifier receipt plus current queue/roster/PhaseIO chain;
- negative candidate: central negative-closure broker only;
- security alias: `security_obligation_lifecycle` only;
- merge item: exact denominator reconciliation by the central driver join;
- report item: exact central index/disposition/assembly validation;
- provider debt: never “cleanly” closed by a producer; it closes only when the provider becomes current and a new exact denominator is compiled.

### 4.3 Evidence slice and channel

Add `EvidenceSlice` (`plamen.evidence_slice.v1`) containing:

- `slice_id`;
- exact source artifact bindings;
- component, symbol, relation, candidate, and line/locus IDs;
- method-step IDs;
- graph binding or graph-off marker;
- predecessor receipt digests;
- permitted tool capability classes;
- a maximum prompt projection digest.

Add `EvidenceChannel` (`plamen.evidence_channel.v1`) with:

- `channel_semantic_id`;
- `channel_id`;
- sorted `obligation_ids`;
- `evidence_slice_id`;
- `role_id` and `role_family`;
- `source_class`;
- methodology bindings;
- `graph_treatment_digest`;
- `runtime_semantic_policy_digest`;
- `independence_signature`;
- exact expected output;
- resource reservation;
- prerequisite channel/join IDs;
- state and digest.

Two identities are useful:

```text
channel_semantic_id = ACHS-<hash of semantic work, excluding backend/model>
channel_id          = ACH-<hash of semantic work plus backend/model/tool/context policy>
```

`channel_id` binds:

- the exact obligation set;
- evidence slice;
- role;
- evidence source class;
- methodology paths/digests/steps;
- graph treatment;
- snapshot/phase/dependency generation through the slice;
- backend family, model capability tier, allowed tool classes, context floor, output ceiling, and timeout class.

Maximum concurrency and dispatch batch number are deliberately excluded. They affect scheduling, not semantic work, so a concurrency change cannot rewrite the roster.

### 4.4 Worker dispositions

Workers may emit only:

- `EVIDENCE_PROPOSED`
- `CANDIDATE_PROPOSED`
- `NO_EVIDENCE_WITH_TRACE`
- `INCONCLUSIVE`
- `BLOCKED`

Every row binds an obligation ID, evidence locations, method steps, and output digest. `NO_EVIDENCE_WITH_TRACE` is a negative proposal, not closure.

The strings `SAFE`, `NO ISSUE`, `NOT VULNERABLE`, and equivalent generic negatives are parsed as `NEGATIVE_PROPOSAL_RETAINED`, move the obligation to `DISPUTED`, and create an independent skeptic/verification obligation. They never add novelty credit, coverage credit, or closure credit.

## 5. Deterministic controller

### 5.1 Exact inputs

`compile_attention_plan(...)` receives only:

1. current audit snapshot/run binding;
2. pipeline, mode, ecosystem, phase, and semantic dependency generation;
3. phase graph digest and active-phase list;
4. exact current PhaseIO/artifact-ledger input bindings;
5. methodology catalog paths, file digests, step IDs, and application receipts;
6. typed security-obligation authority/lifecycle;
7. typed queue, chain, axis, inventory, component, relation, and report authorities applicable to the phase;
8. graph treatment plus typed graph capability/binding/debt;
9. backend/model/tool capability policy;
10. immutable base roster, ordered roster amendments, worker receipts, and join receipts;
11. frozen budget policy and current reservation ledger.

Forbidden inputs include:

- raw finding count;
- Markdown finding heading count;
- count above a severity;
- prior wave “yield”;
- report length;
- ground truth, benchmark labels, private case names, evaluator outputs, or evaluator paths;
- untyped worker assertions of completeness or safety.

### 5.2 Exact outputs

For phase `<phase>`, write:

- `attention_denominator_<phase>.json`
- `attention_plan_<phase>.json`
- `attention_roster_<phase>.json`
- `attention_amendments/<phase>/<sequence>-<amendment_id>.json`
- `attention_receipts/<phase>/<channel_id>/<attempt>.json`
- `attention_join_<phase>.json`
- `attention_stop_<phase>.json`

At run level, write:

- `adaptive_attention_coverage.json`
- `adaptive_attention_debt.json`
- `adaptive_attention_telemetry.json`
- `adaptive_attention_assurance.json`

JSON is authoritative. Markdown summaries are projections only.

### 5.3 Compile and schedule algorithm

Implement the following pure algorithm:

1. **Load and validate sources.** Reject duplicate keys, invalid digests, unbound paths, unsupported schemas, or source drift. Convert the affected scope to provider debt rather than dropping it.
2. **Compile the exact denominator.** Adapters emit obligations in stable-ID order. Existing authority IDs are preserved.
3. **Replay receipts.** Derive all six obligation states. Invalid, stale, or unauthoritative receipts add debt and never count as evidence.
4. **Compile eligible channel templates.** Templates are phase-owned combinations of role, method family, evidence source, graph treatment, proof environment, and maximum obligations per channel.
5. **Rank open obligations lexicographically:**
   - mandatory before optional;
   - closure-blocking before enrichment;
   - impact rank descending;
   - `CONFLICT`, `UNKNOWN_DENOMINATOR`, `MISSING_EVIDENCE`, `KNOWN_GAP`, `NONE`;
   - dependency fanout descending;
   - uncovered before disputed re-challenge before retryable debt;
   - graph additive promotion;
   - obligation ID ascending.
6. **Pack channels deterministically.** Choose the admissible template covering the highest-ranked open item. Fill it only with compatible obligations up to the phase payload cap. Compatibility requires the same role family, method/tool capability, proof environment, dependency generation, and closure-policy family. Ties use `channel_semantic_id`.
7. **Enforce independence.** When an obligation requires a challenge, choose a channel whose independence signature is admissible. Correlated duplicates do not satisfy the challenge and are not scheduled merely to inflate diversity.
8. **Reserve resources before roster publication.** A channel that cannot obtain its full grant is not dispatched. Its obligations become exact budget/capability debt.
9. **Publish an immutable base roster.** Later discovered obligations produce an append-only `RosterAmendment`; the base roster is never rewritten.
10. **Dispatch ready channels in channel-ID order subject to prerequisite joins and maximum concurrency.**
11. **Join centrally.** Union candidates and evidence rows first, preserve aliases, then invoke one dedup/reconciliation authority. Never let a worker edit a shared inventory or final report.
12. **Recompile after a semantic join.** New obligations may add an amendment. Existing channel IDs and completed receipts remain unchanged.
13. **Emit a stop receipt.** Stop cleanly only under the clean predicate below; otherwise emit bounded stop with every unresolved identity and reason.

This is deterministic given identical frozen inputs and receipts. Model output remains nondeterministic evidence, but the work selected from that evidence is replayable.

### 5.4 Novelty

Novelty is a vector, not a finding count:

- new canonical candidate root-cause identity;
- new alias attached to an existing root cause;
- new valid obligation-to-evidence edge;
- new exact component/relation/method-step coverage;
- new state transition toward closure;
- newly exposed dispute or provider debt.

Only the first, third, fourth, and fifth dimensions can justify optional follow-up. An alias-only duplicate, repeated prose, or correlated worker agreement has zero extension credit. A newly exposed dispute/debt increases urgency but is not counted as positive discovery.

Optional exploration may saturate only when two consecutive completed amendments produce:

- zero new canonical candidates;
- zero new valid evidence edges;
- zero closure-progress transitions;
- zero new high-priority obligations;

and all mandatory obligations for the phase are `CLOSED` or explicitly `DEBT`, the required heterogeneity condition is met, and the denominator is exact. This rule cannot stop mandatory work and cannot produce a clean stop when debt exists.

### 5.5 Coverage, uncertainty, and debt

Publish separate metrics:

```text
evidence_coverage  = (EVIDENCED + DISPUTED + CLOSED) / exact_denominator
closure_coverage   = CLOSED / exact_denominator
debt_rate          = DEBT / exact_denominator
assignment_backlog = (UNCOVERED + ASSIGNED) / exact_denominator
```

Never count `DEBT` as covered. If the denominator is lower-bound or unknown because an input provider is unavailable, publish `coverage_kind = LOWER_BOUND` or `UNKNOWN`, not 100%.

Uncertainty is categorical and source-derived. Do not convert it into a low score that suppresses work. Unknown denominator and conflicts sort before ordinary missing evidence.

Every debt row includes:

- obligation ID;
- phase and dependency generation;
- source/provider;
- reason code;
- failed or unavailable channel IDs;
- attempts and reserved/consumed resources;
- affected identities;
- whether clean assurance is forbidden;
- exact clearing condition.

### 5.6 Heterogeneity and independence

An independence signature contains:

- backend/provider family;
- model family/capability tier;
- role family;
- methodology family;
- evidence source class;
- evidence slice ID;
- tool/proof environment class.

Two channels receive diversity credit only when:

- they do not share the same output or evidence slice;
- they differ in at least two of role, methodology, source, tool/proof environment, or provider/model;
- neither consumed the other’s conclusion before producing its own evidence.

Provider diversity is useful when available, but not mandatory for every positive discovery. Negative closure always requires the existing independent central authority; two agreeing workers are not a vote and cannot substitute for it.

## 6. Budget and cap policy

### 6.1 Resource unit

Define one **Attention Unit (AU)** as a reservation, not an observed average:

- maximum 65,536 model input tokens;
- maximum 8,192 model output tokens;
- maximum 24 tool invocations;
- one phase-policy timeout slot.

Verifier/fuzz proof channels cost 2 AU and receive at most 131,072 input tokens, 12,288 output tokens, and 48 tool invocations. Report-body channels cost 1 AU but are limited to 12 tool invocations. Mechanical-only work costs 0 AU.

No model channel may dispatch with less than:

- 32,768 available input/context tokens;
- 2,048 output tokens;
- the exact tools required by its template.

If a backend cannot expose enforceable token limits, reserve the full AU before launch and refund only unused capacity proven by a valid provider receipt. Missing usage telemetry receives no refund.

### 6.2 Global defaults

These are ceilings, not targets:

| Mode | Maximum model channels | Maximum AU | Maximum concurrency | Maximum attempts/channel |
|---|---:|---:|---:|---:|
| Light | 32 | 40 | 2 | 2 |
| Core | 96 | 128 | 4 | 2 |
| Thorough | 192 | 288 | 4 | 2 |

Retries consume another full reservation. Rate-limit waits do not consume an attempt; an actual provider launch does. A config may lower ceilings. Raising them is a new frozen run policy and is forbidden during ordinary resume.

### 6.3 Per-phase defaults

`max channels` means the total phase ceiling after amendments, not “extra agents.” `D` means denominator-derived with no smaller phase cap; the global cap still applies.

| Profile / phases | Obligations per channel | Max channels Light/Core/Thorough | Phase max concurrency | AU/channel |
|---|---:|---:|---:|---:|
| Bake tools | tool shard | 0/0/0 model channels | 4 tools | 0 |
| Recon components/dependencies | 6 | 2/4/6 | 4 | 1 |
| Instantiate compiler | exact compiler | 1/1/1 | 1 | 1 |
| Breadth axis/component cells | 4 | 4/10/16 | 4 | 1 |
| Rescan/per-contract seams | 4 | 0/8/16 | 4 | 1 |
| Inventory capacity shards | 64 candidates | 3/6/8 | 4 | 1 |
| Invariant pass 1 or pass 2 | 6 | 2/8/12 | 4 | 1 |
| Depth evidence slices | 3 | 4/12/20 | 4 | 1; proof channels 2 |
| Attention repair | 4 | 0/12/24 | 4 | 1 |
| Skeptic/negative challenge | 4 compatible premises | 0/8/12 | 4 | 1 |
| RAG exact query groups | 6 | 0/6/10 | 4 | 1 |
| Chain generation | 6 compatible pairs | 0/6/10 per generation | 4 | 1 |
| Verifier | 4 compatible proof premises | D | 4 | 2 |
| Mechanical/dedup/merge/adjudication | exact denominator | 0 model channels unless a named independent provider is required | 1 driver | 0 |
| Report body | 4 findings | D | 4 | 1 |

The compiler may legitimately select zero channels for a phase. Required fixed roles become obligations; they are not implemented as a blanket minimum-agent count.

## 7. Per-phase behavior

### 7.1 Bake

Parallelize independent deterministic tools only. The controller records tool capability and exact output debt. It does not add model workers to compensate for a missing tool. Missing graph/SCIP/OpenGrep/ast-grep capability becomes provider debt and baseline analysis continues.

### 7.2 Recon

Compile obligations from unresolved components, external dependencies, build roots, entry points, privilege boundaries, and missing typed facts. Do not send multiple workers across the whole repository by default. Slice by exact component/dependency. Run an external-dependency channel only for unresolved external facts.

### 7.3 Instantiate

Keep exactly one central compiler. It materializes the methodology/axis denominator and stable IDs. It may create debt, but it cannot launch children or make findings.

### 7.4 Breadth

This is the first enforcement cutover. Compile obligations from axis cells × components × relations × required method steps. Pack compatible cells into small channels. A new high-priority cell discovered after a zero-candidate channel creates an amendment. Duplicate findings do not extend work.

This directly replaces `breadth_wave_gating`; no wave-yield code remains.

### 7.5 Rescan and per-contract work

Schedule only uncovered components, seams, siblings, variants, and exact method gaps. Broad rows and per-contract rows use the same channel schema. Codex, Claude PTY, and headless Claude use one runtime instead of separate semantic plans.

### 7.6 Inventory

Capacity-shard the monotonic candidate union by stable candidate ID, not source file ordering. Workers write one shard each; one driver-owned join validates the complete candidate denominator, aliases, locations, and provenance. Workers never share-write `findings_inventory.md`.

### 7.7 Semantic invariants

Pass 1 partitions exact state/write/component clusters. Its central join is a hard predecessor. Pass 2 is compiled only after that join and receives cross-cluster or disputed obligations. Pass 2 must not start speculatively while pass 1 channels are active.

### 7.8 Depth

Turn standard roles, scanners, niches, siblings, semantic gaps, design stress, perturbation, checklist, and fuzz tasks into evidence-channel templates. Preserve the producer barrier for perturbation/checklist. Schedule different slices; same-slice duplicates require an explicit independent-challenge obligation.

Do not synthesize `COMPLETE` stubs for an unexecuted never-cut role. An unexecuted role is debt and remains report-visible.

### 7.9 Attention repair

Replace the single `_prepare_attention_repair` queue and `_ATTENTION_REPAIR_MAX_ITEMS = 32` behavior with:

- an exact denominator containing every security alias, methodology gap, perturbation gap, SCIP/graph/dependency gap, and typed shortfall;
- stable four-item channels;
- a content-addressed tail with amendments;
- an exact stop/debt receipt when the 24-channel Thorough ceiling is exhausted.

No item disappears because it was item 33. Existing `CS-*` shortfalls migrate into provider/coverage obligations and remain until independently cleared.

### 7.10 Skeptic, axis, semantic dedup, and RAG

Skeptic channels are premise-specific and independent. Axis coverage and semantic dedup remain central authorities, not majority votes. RAG queries are exact dependency/candidate obligations; a timeout is recorded once and switches to the documented fallback without retrying the MCP call.

### 7.11 Chain analysis

Compile stable relation/candidate pairs. Parallelize within a dependency generation; require the central generation join before compiling the next generation. Preserve a monotonic chain candidate union. Tail/cap stops are exact debt, not a clean “no chains” result.

### 7.12 Verification and adjudication

Keep `QueueWorkPlan` as queue/output ownership authority. Upgrade `VerifierWorkRoster` through a v2 adapter:

- use content-addressed channel IDs rather than ordinal `verify-...-0001` identity;
- retain legacy `work_unit_id` as a compatibility alias;
- add append-only roster amendments for late candidates;
- keep four compatible findings per verifier;
- partition by proof premise/environment before packing;
- reuse exact unit, output, gate, and PhaseIO receipts.

Skeptic and severity adjudication remain independent providers with distinct outputs. They are not votes and cannot close their own producer rows.

### 7.13 Reporting

Only report-body prose is capacity-sharded. Central driver authorities own:

- report index;
- candidate disposition;
- dedup/root-cause identity;
- severity binding;
- assembly order;
- assurance/debt projection;
- final floor/integrity validation.

A report worker writes one exact body shard and cannot edit the index, another shard, disposition state, or `AUDIT_REPORT.md`.

## 8. PhaseIO and `WorkerTransaction`

### 8.1 New transaction boundary

Add `scripts/worker_transaction.py` with:

- `WorkerTransactionPolicy`
- `WorkerLease`
- `WorkerAttemptReceipt`
- `WorkerCommitReceipt`
- `WorkerTransaction`
- `recover_worker_transaction`
- `validate_worker_transaction`

States:

```text
PLANNED -> PREPARED -> DISPATCHED -> EXITED -> VALIDATED -> COMMITTED
                         |            |           |
                         +----------> DEBT <------+
DISPATCHED -> CANCEL_REQUESTED -> CANCELLED
any nonterminal old lease output -> QUARANTINED
```

`WorkerTransaction` owns process/attempt mechanics only. PhaseIO and the artifact ledger remain semantic authority.

### 8.2 Exact ownership

Before launch:

1. resolve one `PhaseIOContract`;
2. bind the exact input denominator with `record_work_unit_inputs`;
3. snapshot output prestate;
4. create an immutable lease ID and attempt staging directory;
5. reserve the full resource grant;
6. persist `PREPARED` before starting a process.

The model writes one exact attempt-scoped staging artifact. After exit:

1. revoke the live lease;
2. validate process status, output grammar, channel/obligation bindings, methodology trace, and containment;
3. publish one immutable channel artifact;
4. record it through `record_work_unit_artifacts`;
5. validate it through `validate_work_unit_artifacts`;
6. atomically persist the commit receipt;
7. only then expose it to the central join.

The worker runtime cannot mint candidate disposition, negative closure, merge completion, or report authority.

### 8.3 Crash and late-write semantics

- Crash before process start: recover `PREPARED`, release or reuse the reservation, and retry under a new attempt/lease.
- Crash during process: old lease is revoked; process tree is terminated; partial staging bytes are quarantined; retry if budget remains.
- Crash after output validation but before ledger commit: replay validation and commit idempotently.
- Crash after ledger commit but before transaction receipt: reconstruct the receipt only when exact ledger/output/lease digests agree.
- Cancelled or timed-out work is `DEBT` until a valid retry/amendment.
- Output arriving after lease revocation is quarantined and has no semantic authority.
- A duplicate launch for the same channel is refused while a current lease exists.
- A late worker cannot overwrite canonical evidence because it never writes the canonical artifact directly.
- Retry attempts preserve `channel_id`; attempt ID, lease ID, launch digest, and output digest are distinct.

### 8.4 Central join

Add a driver-owned join transaction with:

- exact roster + amendment denominator;
- one terminal transaction receipt per scheduled channel;
- exact completed artifact bindings;
- explicit debt rows for every non-completed channel;
- monotonic candidate/evidence union;
- alias map;
- central dedup/reconciliation result;
- downstream obligation amendments;
- join digest.

The join passes with debt only when every scheduled channel is terminal (`COMMITTED`, `DEBT`, or `CANCELLED`) and every unresolved obligation is represented in debt. It passes cleanly only when the clean stop predicate is satisfied.

## 9. Roster, resume, invalidation, and concurrency

### 9.1 Immutable roster and amendments

`AttentionRoster` is immutable. `RosterAmendment` contains:

- `sequence`;
- `amendment_id`;
- prior effective roster digest;
- triggering join/event digest;
- new obligation IDs;
- new channel rows;
- budget reservations;
- uncovered/debt rows not schedulable;
- resulting effective roster digest.

The amendment ID is content-addressed. Sequence is validated but excluded from channel identity. A missing, duplicate, reordered, forked, or torn amendment chain fails closed.

### 9.2 Resume algorithm

On resume:

1. validate audit snapshot and config freeze;
2. replay base roster and every amendment;
3. replay PhaseIO inputs, leases, attempts, worker receipts, and join receipts;
4. accept `COMMITTED` only when current artifact bytes and ledger receipts agree;
5. quarantine bytes from revoked/unknown leases;
6. recover or convert nonterminal attempts to debt;
7. recompile the denominator from current authorized sources;
8. use `semantic_dependency_invalidation_plan` and `apply_semantic_invalidation` for only affected obligations/channels;
9. append an amendment for new/reopened work;
10. dispatch only open channels.

A row reorder produces the same obligation/channel IDs. A new unrelated obligation appends work without invalidating completed siblings. A changed methodology file, source binding, graph treatment, backend/model/tool semantic policy, or predecessor digest invalidates only dependent channels.

### 9.3 Concurrency

The base semantic roster is compiled before any dispatch. Runtime batches are projections over ready channel IDs. Therefore concurrency 1 and concurrency 4 produce:

- identical obligation denominator;
- identical channel IDs;
- identical total resource reservations;
- potentially different completion order;
- the same join semantics.

The pool must not schedule replacement work until cancellation/lease revocation is durable. Maximum concurrency is enforced centrally across phases and providers. Nested worker orchestration remains forbidden.

## 10. Safe stopping

### 10.1 Clean stop

`CLEAN_STOP` requires all of:

- exact denominator is known;
- every mandatory obligation is `CLOSED`;
- every optional obligation is either `CLOSED` or validly outside the named phase policy;
- no obligation is `UNCOVERED`, `ASSIGNED`, `DISPUTED`, or `DEBT`;
- all channels and amendments are terminal and replayable;
- all joins pass exact denominator reconciliation;
- candidate/evidence unions are monotonic;
- no unauthorized negative or `SAFE` disposition exists;
- no active lease, orphan process, late write, containment violation, or uncommitted semantic mutation exists;
- report-visible assurance has no discovery/verification/report-integrity debt attributable to the phase.

Zero findings is neither necessary nor sufficient.

### 10.2 Bounded stop with debt

`BOUNDED_STOP_WITH_DEBT` is allowed when:

- phase/global channel or AU cap is exhausted;
- an exact required capability is unavailable;
- no admissible independent channel exists;
- retry budget is exhausted;
- the user cancels;
- an emergency wall-time/process safety boundary fires.

It requires an exact unresolved-obligation list and a valid assurance projection. It forbids a clean/full-audit claim.

### 10.3 Halt

`HALT` is required when semantic authority itself is ambiguous: corrupt/forked roster chain, snapshot mismatch, unknown canonical output ownership, uncontainable late writer, artifact-ledger conflict, or inability to publish the lossless debt denominator.

## 11. Backend parity and cost fairness

Compile one backend-neutral semantic prompt per `channel_semantic_id`. Store:

- semantic prompt digest;
- backend adapter digest;
- final launch prompt digest;
- runtime policy digest;
- model/tool capability;
- reserved and observed tokens/tools/time/cost.

Claude PTY, Claude headless, and Codex use the same roster and semantic prompt. Backend translation may add transport instructions only. A missing backend capability becomes debt; the controller does not silently add more agents on the cheaper or more available backend.

For experiments, use two independent fairness regimes:

1. **Matched-total:** identical AU, channel, token, tool, and timeout ceilings per 2x2 cell.
2. **Matched-per-agent:** identical resource grant for corresponding `channel_semantic_id`; total cost is an outcome.

Dollar cost remains telemetry because subscription/provider accounting is not uniformly available. Scheduling uses reservations, not observed dollar price. Compare providers by semantic channel ID and normalized resources.

## 12. Configuration and CLI compatibility

Add to generated `config.json`:

```json
{
  "adaptive_attention": {
    "mode": "off",
    "algorithm_version": "aa-v1",
    "scope": "all",
    "graph_treatment": "legacy_off",
    "max_total_channels": 96,
    "max_attention_units": 128,
    "max_concurrency": 4,
    "max_attempts_per_channel": 2,
    "min_context_tokens": 32768,
    "min_output_tokens": 2048
  }
}
```

`mode` is `off`, `observe`, or `enforce`. `scope` is `breadth` or `all`.

CLI additions in `plamen.py`:

- `--adaptive-attention` → `mode=enforce, scope=all`
- `--adaptive-attention-observe` → `mode=observe`
- `--fixed-attention` → `mode=off`
- `--graph-sidecar` and `--no-graph-sidecar` control the independent graph factor

Do not add driver startup flags; the driver should continue to accept one config path plus its current startup/resume authority flags. This preserves existing resume invocation.

Compatibility for one release:

- absent `adaptive_attention` and absent old flag: `off`;
- `breadth_wave_gating_enabled=false`: `off`, deprecation warning;
- `breadth_wave_gating_enabled=true` with no new block: translate to `enforce, scope=breadth`, persist an explicit migration receipt, and never execute the old raw-count code;
- specifying both old and new controls inconsistently: fail startup configuration validation;
- a resume may not change mode, algorithm version, graph treatment, or budgets without the existing new-run/migration authority.

Rollout may later change new Core/Thorough defaults to `enforce` only after held-out acceptance. Do not silently change existing saved configs.

## 13. Telemetry and reporting

### 13.1 Required telemetry

`adaptive_attention_telemetry.json` contains:

- denominator counts by kind/state/phase;
- planned, amended, dispatched, committed, cancelled, retried, quarantined, and debt channel counts;
- AU/tokens/tools/time/cost reserved and observed;
- novelty vector per join;
- evidence and closure coverage;
- exact overlap matrix and correlated-duplicate count;
- independence/heterogeneity coverage;
- candidate union size, alias count, and found-then-lost invariant status;
- backend/model/tool capability debt;
- stop classifications and reasons.

No telemetry value is closure authority.

### 13.2 Assurance integration

Add an adapter in `scripts/assurance_limitations.py`:

- `_adaptive_attention_assurance_rows(...)`
- include `adaptive_attention_assurance.json` in `_supplemental_assurance_rows(...)`;
- include every current controller input in `assurance_projection_input_paths(...)`;
- classify discovery/coverage debt as `DISCOVERY_RECALL`, verifier/negative debt as `VERIFICATION_CONFIDENCE`, report ownership/assembly debt as `REPORT_INTEGRITY`, and optional enrichment-only debt narrowly.

The lossless JSON retains every obligation/channel. The existing bounded projection may group it, but must bind omitted rows through digests. Any non-enrichment controller debt makes `clean_full_audit_claim_allowed=false`.

## 14. Exact implementation worklist

### 14.1 New modules

1. `scripts/adaptive_attention_types.py`
   - strict schemas, canonical JSON/digests, IDs, states, transition validator;
   - `AttentionObligation`, `EvidenceSlice`, `EvidenceChannel`, `AttentionBudget`, `AttentionRoster`, `RosterAmendment`, `AttentionStopReceipt`.
2. `scripts/adaptive_attention_sources.py`
   - adapters for methodology, security aliases, axes, components, relations, inventory/candidates, chains, verifier queue, report rows, graph capability, and legacy `CS-*` debt;
   - no process launch or closure.
3. `scripts/adaptive_attention_controller.py`
   - `compile_attention_denominator`;
   - `compile_channel_templates`;
   - `compile_attention_plan`;
   - `apply_attention_receipts`;
   - `compile_roster_amendment`;
   - `classify_attention_stop`;
   - pure deterministic logic only.
4. `scripts/worker_transaction.py`
   - attempt/lease/process/validation/commit/recovery state machine described above.
5. `scripts/adaptive_attention_runtime.py`
   - backend-neutral prompt compilation, ready queue, bounded pool, resource reservations, central joins, and phase adapter.
6. `scripts/adaptive_attention_reporting.py`
   - coverage/debt/telemetry/assurance artifacts and validators.
7. `scripts/adaptive_attention_evaluator.py`
   - offline `RunBundle` validation and blinded scoring only; never imported by the driver.

### 14.2 Existing modules to change

`scripts/plamen_types.py`

- add `attention_profile: str = "fixed"` to `Phase`;
- assign profiles to phase declarations;
- validate profile names in `validate_phase_graph`;
- keep channel children internal so `expand_shard_phases` need not expand agent count.

`scripts/plamen_driver.py`

- import the new controller/runtime/reporting modules;
- add `_adaptive_attention_enabled_for_phase`;
- add `_run_adaptive_attention_phase`;
- add `_finalize_adaptive_attention_phase`;
- call the runtime in `run_phase` after `_live_phase_runtime_launch_policy` is resolved and before current recon/breadth/rescan/depth backend branches;
- replace the main-loop `attention_repair` preparation branch around line 45814 with exact denominator compilation;
- feed accepted breadth/rescan/depth methodology receipts into the controller at the existing line-51159 boundary;
- adapt `_prepare_dynamic_verifier_roster` (14046) and its call sites (15062, 15517) to v2 channel IDs/amendments;
- make `_record_phase_cost` (16038) also emit structured per-channel usage without using it as scheduling authority;
- add controller debt to final assurance refresh paths around 48349–48686 and 51495–51510;
- delete the obsolete functions listed in section 3.5;
- remove pool-specific semantic planning after each phase is cut over, retaining only backend transport helpers temporarily;
- do not treat unexecuted depth stubs as evidence.

`scripts/plamen_mechanical.py`

- retire `_ATTENTION_REPAIR_MAX_ITEMS`;
- replace `_build_attention_repair_items` and `_prepare_attention_repair` with a compatibility projection over the exact denominator;
- retain Markdown queue/summary output only while old report/validator consumers migrate.

`scripts/plamen_validators.py`

- validate denominator/roster/amendment/transaction/join/stop chains;
- make current attention summary checks projections, not authority;
- reject generic SAFE/negative closure;
- reject unrepresented tail/debt and candidate loss.

`scripts/phase_io_contracts.py`

- add exact dynamic child-contract constructors for attention worker, join, and projection work units;
- retain one exact model output per child and driver-only join outputs.

`scripts/verifier_work_roster.py`

- add v2 content-addressed IDs and append-only amendments;
- retain v1 migration/validation and legacy aliases;
- exclude concurrency from semantic resume digest while binding runtime capabilities and resource grants.

`scripts/assurance_limitations.py`

- add the lossless controller debt adapter described above.

`plamen.py`

- extend `_parse_cli_opts` (6082), help, wizard state, and `launch_v2` config generation (5945);
- preserve current backend CLI behavior.

### 14.3 Removal order

1. Land types/compiler and observe-only fixtures.
2. Cut over breadth in enforce mode.
3. Delete raw-count breadth gating and its tests.
4. Cut over recon/rescan/depth/attention.
5. Cut over chain/verifier/report adapters.
6. Remove superseded pool-specific semantic planners only after backend parity tests pass.

## 15. Test and fault-injection fixtures

Add at least:

- `scripts/test_adaptive_attention_types.py`
- `scripts/test_adaptive_attention_sources.py`
- `scripts/test_adaptive_attention_controller.py`
- `scripts/test_worker_transaction.py`
- `scripts/test_adaptive_attention_runtime.py`
- `scripts/test_adaptive_attention_reporting.py`
- `scripts/test_adaptive_attention_experiments.py`

Required fixtures:

1. Denominator row reorder produces identical obligation/channel IDs.
2. Inserting an unrelated obligation appends one amendment without invalidating siblings.
3. A changed methodology digest invalidates only dependent channels.
4. A changed source artifact uses artifact-ledger dependency-scoped invalidation.
5. Concurrency 1 and 4 produce identical semantic rosters and reservations.
6. Phase/global cap exhaustion retains every unscheduled obligation as debt.
7. Zero candidates followed by a new high-priority obligation still schedules work.
8. Correlated duplicate outputs add no novelty or heterogeneity credit.
9. Generic `SAFE` becomes a disputed negative proposal and cannot close.
10. Candidate union and alias map are monotonic across joins/resume.
11. More than 32 attention items are all sharded or explicitly debt; none vanish.
12. Missing/invalid graph sidecar adds provider debt and cannot demote baseline work.
13. Graph-on candidate/evidence union is a superset of graph-off for identical model receipts.
14. Invariant pass 2 cannot launch before the pass-1 join.
15. Chain generation N+1 cannot launch before generation N join.
16. Verifier rows pack by compatible premise and preserve exact output ownership.
17. Report workers cannot edit index/disposition/assembly/final report.
18. Worker crash at every transaction boundary recovers idempotently.
19. Cancellation revokes lease, kills process tree, and preserves debt.
20. A late write after cancellation is quarantined and never reaches a join.
21. Duplicate launch fencing prevents two live leases for one channel.
22. Torn/forked/reordered roster amendment chain fails closed.
23. Crash after ledger commit but before receipt reconstructs only from exact digests.
24. Backend adapters preserve semantic prompt and resource parity.
25. Usage telemetry missing means no reservation refund.
26. An unexecuted depth role cannot pass through a `COMPLETE` stub.
27. Clean-stop predicate fails for every unresolved/debt/disputed state.
28. Bounded-stop receipt enumerates all unresolved identities and reaches assurance.
29. Final report clean claim is false when controller discovery/verification/report debt exists.
30. Run config, prompts, manifests, receipts, logs, and bundles contain no ground-truth path, bytes, benchmark name, or private evaluator ID.

Run existing PhaseIO, artifact-ledger, verifier-roster, assurance, terminal-launch-readiness, security-obligation, methodology-application, PTY-supervision, and report-integrity suites as regression gates.

## 16. 2x2 experimental design

### 16.1 Cells

Use:

| Cell | Graph | Attention |
|---|---|---|
| G0A0 | legacy/off | fixed current schedule |
| G1A0 | typed sidecar additive | fixed current schedule |
| G0A1 | legacy/off | adaptive controller |
| G1A1 | typed sidecar additive | adaptive controller |

Graph and attention are frozen independent config fields. No cell may infer the other.

### 16.2 Isolation

For every run:

- prepare a clean isolated workspace with `terminal_audit_launch`;
- seal prior evidence externally;
- pass private evaluation material as `forbidden_input_paths`;
- use an opaque random case token with no protocol/contest/benchmark semantics;
- freeze source snapshot, mode, ecosystem, backend capability tier, tool versions, methodology digests, and budgets;
- never place ground truth in source, docs, scope notes, config, environment, prompt, scratchpad, log, receipt, or report.

The audit produces a grader-neutral `RunBundle` only.

### 16.3 `RunBundle`

Schema `plamen.adaptive_attention_run_bundle.v1`:

- opaque run and case tokens;
- cell and budget regime;
- source snapshot digest;
- config/methodology/graph-treatment digests;
- backend/model/tool capability labels;
- report and canonical candidate-union digests;
- obligation/coverage/debt/stop manifests;
- verifier and report dispositions;
- cost/resource telemetry;
- containment/resume integrity results;
- bundle digest.

It contains no ground-truth path, hash, case name, expected count, or grader-derived label.

### 16.4 Budget regimes

Run both:

1. matched-total AU/token/tool/timeout/model budget;
2. matched per-semantic-channel grant.

In the matched-total regime, reservations must be equal before launch; unused fixed-schedule budget is not transferred from one cell after seeing results. In the per-agent regime, total resource use is measured rather than equalized.

### 16.5 Measures

Primary safety/quality:

- methodology-step completeness;
- exact component/relation/axis coverage;
- unique confirmed root causes;
- confirmed Critical/High root causes;
- found-then-lost count;
- false-safe/unauthorized-negative count;
- verifier confirmation yield;
- unsupported-negative reopen count;
- report-disposition and severity correctness;
- omitted debt/assurance count.

Efficiency/architecture:

- AU, input/output tokens, tools, elapsed time, and dollar telemetry;
- channels and retries;
- overlap/correlated duplicate ratio;
- alias-to-root fragmentation;
- amendment count;
- orphan/late-write/containment incidents;
- coverage gained per AU;
- confirmed root causes per AU.

Graph-specific:

- graph-added obligations/evidence;
- baseline demotions or candidate removals, which must be zero;
- graph-provider debt;
- G×A interaction on coverage and confirmed root causes.

### 16.6 Analysis

Use paired comparisons by case and seed. Report every cell, not only averages. Use bootstrap 95% confidence intervals over case-level paired deltas and retain raw per-case tables. Do not tune thresholds on held-out results.

Primary comparisons:

- A1 vs A0 within G0 and G1;
- G1 vs G0 within A0 and A1;
- interaction `(G1A1-G1A0) - (G0A1-G0A0)`.

Backend parity is a blocking factor, not a fifth experimental factor.

## 17. Held-out acceptance

### 17.1 Dataset and run count

Before implementation tuning, freeze:

- 12 held-out cases: eight SC cases spanning all supported SC ecosystems and four L1 cases spanning Go/Rust and distinct subsystem shapes;
- three predetermined model seeds/run nonces for the matched-total regime;
- one predetermined seed for the matched-per-agent regime;
- a four-case backend-parity subset run on both Claude and Codex.

This yields:

- 144 primary held-out runs: 12 cases × 4 cells × 3 seeds;
- 48 matched-per-agent runs: 12 × 4 × 1;
- 48 additional backend-parity runs: 4 × 4 × 3 on the alternate backend.

Ground truth is opened only by a separate offline grader after all `RunBundle` digests are frozen.

### 17.2 Absolute gates

Any of these fails release:

- ground-truth/private evaluator leakage;
- unauthorized `SAFE` or negative closure;
- found-then-lost candidate;
- omitted unscheduled/failed obligation;
- graph-derived demotion or candidate removal;
- late/cancelled/invalid worker output consumed as authority;
- budget reservation above the frozen cap;
- non-replayable roster/amendment/transaction/join;
- clean assurance while discovery, verification, or report-integrity debt exists;
- final report ownership violation.

### 17.3 Quantitative gates

On matched-total held-out runs:

- adaptive unique-confirmed-root-cause recall is non-inferior to fixed scheduling: paired aggregate delta ≥ 0 and bootstrap 95% lower bound ≥ -2 percentage points;
- no fixed-schedule confirmed Critical/High root cause is systematically lost by adaptive scheduling; aggregate Critical/High recall delta ≥ 0;
- methodology completeness improves by at least 3 percentage points in median paired delta and its 95% lower bound is ≥ 0;
- verifier confirmation yield per AU is at least fixed baseline;
- correlated duplicate/overlap AU is at most 85% of fixed baseline;
- unsupported-negative reopen rate does not increase;
- report disposition/severity accuracy does not decrease by more than 1 percentage point;
- reserved total resources differ by 0%; observed token/tool use is reported and must remain within 5% unless the adaptive cell uses less.

Graph-on acceptance:

- graph-on candidate/evidence union never loses a graph-off item attributable to scheduling;
- graph-added obligations are either processed or exact debt;
- graph-on confirmed-root-cause recall is non-inferior with the same -2-point lower-bound margin.

Backend parity:

- corresponding semantic rosters and grants match;
- backend-specific missing capability appears as debt, not extra/hidden work;
- no backend has a higher authorization privilege.

### 17.4 Release progression

1. Observe-only telemetry passes deterministic fixtures.
2. Breadth-only enforce passes repository regression and development experiments.
3. Breadth raw-count gate is deleted.
4. Core all-phase enforce passes held-out absolute and quantitative gates.
5. Thorough all-phase enforce passes the same gates and long-tail fault fixtures.
6. Only then make adaptive attention the default for new Core/Thorough configs. Keep an explicit fixed-attention option for continuing ablations and emergency rollback.

## 18. Definition of done

The implementation is complete only when:

- no live scheduling decision reads raw finding count or old wave yield;
- every eligible phase compiles exact obligations and channels;
- all channels have stable IDs, exact PhaseIO, resource reservations, transaction receipts, and central joins;
- roster amendments and dependency-scoped resume replay deterministically;
- agent count can decrease, remain zero, or increase only as a consequence of exact uncovered work;
- every cap/failure produces visible debt;
- SAFE/negative worker prose never closes work;
- graph remains additive;
- Claude/Codex semantic plans are equivalent;
- attention repair has no silent 32-item tail;
- candidate union is monotonic;
- final assurance consumes controller debt losslessly;
- all fault, 2x2, privacy, and held-out acceptance gates pass.

