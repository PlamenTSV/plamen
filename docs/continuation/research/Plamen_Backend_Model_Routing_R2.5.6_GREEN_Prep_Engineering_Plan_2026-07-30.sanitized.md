# Plamen backend/model routing R2.5.6 — offline GREEN-preparation engineering plan

Date: 2026-07-30  
Disposition: **R2 fixture-first design package; production bindings intentionally RED**  
Repository: `<LOCAL_USER_ROOT>/plamen-codex-implementation`  
Branch: `codex/recall-app-benchmark-r10_1`  
HEAD: `67a0f85adc7a8169d79a286908b00bef7adb764a`  
Worktree rule: the exact current bytes recorded in the source registry override HEAD.

> **HOLD — INTERIM SOURCE MANIFEST IS NON-EVIDENCE.** R2 oracle/schema/vector
> logic is prepared, but the exact driver and recursively closed production-Python
> manifest must not be accepted or reviewed yet. The final one-time rebind occurs
> only after every production-Python-writing lane is quiescent (including Program
> Facts through C3, PhaseIO P0/Cut-4, chain P1-F/full regression, and false-safe/
> severity work), immediately before backend production binding. Until that global
> freeze, the source registry hashes and any validator result are intentionally
> non-authoritative. Do not repeatedly rebind a moving worktree.

## 1. Decision and boundary

This R2 package supersedes the R1 freeze blocked by independent review. R1
accepted five materially malformed self-resealed denominators. R2 makes the
semantic rosters normative outside the candidate payload, adds 11 regression
probes for those oracle failures, closes the production Python source scope, and
uses strict JSON. It is not implemented by this package. The production adapter
is deliberately absent, all 217 binding/branch/crash/model operations remain
RED, and no provider, network, or audit execution is authorized.

This work closes the planning ambiguity around seven real consumers. It does not
claim improved audit recall or precision. Those claims require neutral, held-out
audit evaluation after a separate implementation and cutover decision.

The non-negotiable compatibility constraints are:

- Claude remains the default backend.
- The legacy Claude defaults remain `sonnet`, `haiku`, and
  `claude-opus-4-8` at their existing phase positions.
- Codex retains the current tier mapping: Opus→`gpt-5.5`,
  Sonnet→`gpt-5.4`, Haiku→`gpt-5.4-mini`, until a separately reviewed
  model-policy change is approved.
- Max is absent. This program must not introduce Max.
- Unknown consumers, missing consumers, duplicate consumers, roster reordering,
  or source drift fail closed. They never select a default model.
- Crash recovery must not treat an attempted spawn as proof of which provider/model
  actually ran.
- Windows/Linux/macOS differences may change process primitives, never authority
  semantics.
- Candidate JSON cannot choose its own semantic denominator: the exact branch,
  model, crash, applicability, record, landmark, source-scope, registry, and
  operation contracts are independently pinned by the validator and reviewer.
- Duplicate JSON keys and non-finite JSON values are rejected before schema
  validation.

Normative machine-readable artifacts:

- `Plamen_Backend_Model_Routing_R2.5.6_GREEN_Prep_Schemas_2026-07-30.json`
- `Plamen_Backend_Model_Routing_R2.5.6_GREEN_Prep_Source_Registry_2026-07-30.json`
- `Plamen_Backend_Model_Routing_R2.5.6_GREEN_Prep_RED_Vectors_2026-07-30.json`
- `validate_plamen_model_routing_r2_5_6_green_prep.py`

## 2. Evidence: the seven production consumers

| Consumer | Stage | Exact current entry point | Current role | Structural gap |
|---|---|---|---|---|
| `launch_replay_validator` | LAUNCH | `scripts/headless_worker_runtime.py::prepare_headless_worker` | Normalizes launch inputs and compiles a worker plan | No typed selected-route/replay authority binding effective backend, model, effort, service tier, fallback policy, and source decision |
| `proof_mint` | LAUNCH | `scripts/backend_capability_registry.py::promote_backend_capability_receipt` | Promotes a capability receipt | Has no non-test production caller; substrate exists but does not protect the live launch path |
| `spawn_authentication` | INTENT | `scripts/worker_transaction.py::execute_worker_transaction` | Validates plan/roster, arms transaction, starts observed execution | Does not authenticate a durable selected route at the last pre-spawn boundary |
| `provider_spool_acceptance` | SPAWNED | `scripts/worker_execution_receipts.py::validate_staged_execution` | Replays staged provider completion | Proves staged execution structure, not actual backend/model/effort/service/fallback identity |
| `completed_current_construction` | CURRENT | `scripts/worker_transaction.py::incorporate_worker_execution` | Replays completion, incorporates PhaseIO outputs, writes ledger | Does not construct one authoritative current route from launch, attempt, provider terminal evidence, and neutral reconciliation |
| `current_replay_validator` | CURRENT | `scripts/worker_transaction.py::validate_worker_execution_authority` | Replays current canonical execution for ledger and BB consumers | Current authority omits route lifecycle ancestry and actual route observation |
| `resume_authorization` | RESUME | `scripts/plamen_driver.py::_reconcile_completed_checkpoint_artifacts` | Reconciles checkpoint/ledger/semantic state and rewinds invalid descendants | Does not call `recover_worker_transactions` and cannot bind resumed work to the prior completed-current route identity |

Every row is bound to its whole-file SHA-256, AST line span, normalized signature,
AST source-segment SHA-256, required direct calls, and exact non-test caller set.
The source registry is the normative detail; this prose is explanatory only.

Caller closure is evaluated across the recursively enumerated production Python
scope: root `*.py`, `scripts`, `custom-mcp`, `plamen_l1`,
`verification_policy`, and `mcp-packages`, excluding tests, `conftest.py`, and
cache directories. The canonical `{path, sha256, size}` manifest and file count
are independently pinned. Imports and aliases are resolved; ambiguous
same-basename references and undeclared callback references reject the package.

Two findings materially constrain the implementation:

1. `promote_backend_capability_receipt` is disconnected from non-test production.
   A proof type or validator that no live launch consumer calls is not a control.
2. `worker_transaction.recover_worker_transactions` is also disconnected from
   non-test production. Resume currently reconciles completed artifacts without
   first running worker-transaction crash recovery.

These are RED gaps, not reasons to silently widen an existing function’s meaning.

## 3. Current call graph and authority breaks

The current dominant execution path is:

```text
plamen_driver phase/model selection
  -> PhaseIO ContractV2 / LaunchSpecV2
  -> headless_worker_runtime.execute_headless_worker
     -> prepare_headless_worker
        -> compile_worker_plan
     -> _execute_prepared_headless_worker
        -> worker_transaction.execute_worker_transaction
           -> worker_execution_receipts.run_observed_worker
              -> direct provider process, or
              -> isolated_execution_host.isolated_wer_provider_lifecycle
                 -> staged child execution/completion replay
           -> provider/staged completion
        -> worker_transaction.incorporate_worker_execution
           -> validate_staged_execution
           -> validate_worker_execution_authority
           -> PhaseIO projection
           -> ArtifactLedger publication
  -> checkpoint completion
```

Additional consumers:

```text
ArtifactLedger -> validate_worker_execution_authority
BB wrapper replay -> validate_worker_execution_authority
program_facts_evm_wtx -> execute_worker_transaction / validate_staged_execution
```

Resume is a separate path:

```text
plamen_driver.main
  -> _reconcile_completed_checkpoint_artifacts
     -> semantic issues + ArtifactLedger + phase validators
     -> checkpoint save / rewind

worker_transaction.recover_worker_transactions
  -> currently no non-test caller
```

The break is therefore not merely “model metadata is missing.” Route intent is
selected before launch, process creation happens inside WER/isolated execution,
terminal evidence is staged elsewhere, canonical current state is published during
incorporation, and resume is yet another authority boundary. A trustworthy route
must be carried and replayed through all of them.

## 4. Target architecture

Add one source-owned module:

`scripts/model_routing_runtime_adapter.py`

It owns exactly seven public adapter functions:

1. `validate_launch_replay`
2. `mint_capability_proof`
3. `authenticate_spawn`
4. `accept_provider_spool`
5. `construct_completed_current`
6. `validate_current_replay`
7. `authorize_resume`

The first, third, fourth, fifth, sixth, and seventh current entry points call the
adapter at the insertion order recorded in the registry. The proof direction is
intentionally reversed: `mint_capability_proof` calls the existing
`promote_backend_capability_receipt`. This makes the adapter the source-owned live
consumer while reusing the already-hardened capability promotion substrate.

The adapter owns a closed registry with these exact consumer IDs and no
auto-discovery. Importing a plugin or adding an ecosystem does not implicitly add
a consumer. A new consumer requires:

- a registry version increment;
- a source binding;
- branch/crash/resume vectors;
- a reviewer-visible migration;
- fixture parity before production binding.

Each adapter row carries typed pre/post landmarks. Required record sets,
direction, applicability families, and landmarks are exact per-consumer
contracts; free-form insertion prose is explanatory and cannot authorize a
binding.

The adapter must be pure or dry-run by default: parsing, normalization, authority
construction, and replay must not spawn a process. Only the already-owned process
launcher may spawn, and only after `authenticate_spawn` returns a durable authority.

### Required authority records

The exact record names are pinned in each source-registry row. Their semantic roles
are:

- `SelectedRouteAuthorityV1`: requested/effective backend, model, reasoning effort,
  service tier, allowed fallback set, fallback cause, decision-source identity, and
  immutable route-policy digest.
- `ExecutionAttemptAuthorityV1`: attempt/generation identity, consumed launch,
  capability proof, pre-spawn intent, platform launcher identity.
- `ProviderSpoolAuthorityV1`: bounded provider frames/terminal observation tied to
  the attempt, never inferred from prose or desired route.
- `TerminalAttemptAuthorityV1`: terminal class for all success, failure, timeout,
  cancellation, transport, malformed, empty, spawn-failed, and ambiguity branches.
- `NeutralReconciliationAuthorityV1`: independent comparison of requested,
  selected, observed, and terminal route facts.
- `CompletedCurrentAuthorityV1`: the sole atomic current route after neutral
  reconciliation and before PhaseIO/ledger publication.
- `PriorResumeIdentityAuthorityV1`: digest-bound prior current identity and
  generation used to authorize resume, retry, or rewind.

Record names are not sufficient. Each schema must be closed, versioned, canonical,
bounded, reject duplicate keys/non-finite numbers, bind all parents by digest, and
bind the exact source snapshot/methodology/run/work/phase/generation identities
already used by PhaseIO and WTx.

## 5. Closed-world route semantics

The source registry is authoritative, not advisory.

- Unknown backend, consumer, phase route, model alias, effort, service tier, or
  fallback reason is rejected.
- A missing route value is not filled with a production default after launch
  compilation.
- An unavailable Codex model does not silently mutate an individual phase. It
  creates a declared fallback decision with an allowed edge and fresh route digest,
  or the attempt does not spawn.
- A skeptic or breadth override is a signed/typed input to selection, not a later
  lookup that can diverge from the compiled plan.
- Desired model identity and observed provider identity are separate fields.
- Provider output cannot certify itself. Reconciliation consumes independently
  captured launcher/provider evidence.
- Ambiguous spawn state cannot be relabeled as “not spawned.” It requires platform
  observation or durable terminal debt.
- Resume never accepts a completed phase merely because Markdown/status files
  exist. It first recovers WTx, then replays completed-current route authority.

## 6. Branch and crash denominator

The 17 branch fixtures cover:

- direct and observed spawn:
  provider terminal, process exit without provider frame, timeout, cancellation,
  transport failure, empty provider output, malformed provider output;
- spawn failed;
- ambiguity aborted before spawn;
- unresolved ambiguity debt.

All consumers cover all 17 branches except provider-spool acceptance, which covers
the 14 branches where a process was directly or observably spawned. This produces
116 consumer/branch binding operations.

The 18 crash vectors use exact typed cutpoint IDs and span:

1. before launch replay;
2. launch replay→proof;
3. proof→consumed launch publication;
4. consumed launch→spawn intent;
5. durable intent→process creation;
6. process may exist→spawn authority;
7. observed-spawn resolution→spawn authority;
8. spawn authority→provider spool;
9. provider bytes→terminal authority;
10. launcher terminal observation→terminal authority;
11. terminal→neutral reconciliation;
12. reconciliation→completed current;
13. current temp fsync→replace;
14. replace→directory fsync;
15. current publication→PhaseIO arm;
16. PhaseIO/ledger incorporation;
17. incorporation→checkpoint save;
18. prior resume replay→completed-phase acceptance.

The recovery invariant is monotonic:

```text
no authority
  -> durable selected route / capability
  -> durable intent
  -> spawned or ambiguity authority
  -> provider/launcher terminal evidence
  -> neutral reconciliation
  -> one atomic completed current
  -> incorporation
  -> resume identity
```

No later record may be synthesized only because an earlier marker exists. A crash
before an atomic authority is durable either retries with a new generation, requires
ambiguity resolution, records terminal debt, or rejects resume as specified by the
RED vector.

## 7. Fixture-first implementation sequence

Each checkpoint begins with RED fixtures and ends with narrow tests plus the frozen
offline regression selection. A checkpoint must not be merged into the next one
while any source binding silently bypasses the adapter.

### G0 — accept and seal the RED denominator

- Independently reproduce seven source bindings and caller sets.
- Re-run 71 closed-registry/source mutation probes.
- Verify 217-operation count and canonical manifest digest.
- Verify the production adapter is absent and each binding fails with
  `MODEL_ROUTING_PRODUCTION_BINDING_MISSING`.

### G1 — adapter types and dry-run compiler

- Add the closed registry and seven call signatures.
- Add strict authority record parsers/serializers.
- Prohibit spawn, filesystem publication, provider calls, config mutation, and
  fallback selection in dry-run tests.
- Add unknown/missing/duplicate/reordered/drift tests before implementation.

### G2 — launch replay and capability proof

- Bind `prepare_headless_worker` after existing launch normalization and before
  worker-plan compilation.
- Make `mint_capability_proof` the sole live caller of existing capability
  promotion.
- Bind the resulting proof/route to work plan, LaunchSpec, source snapshot,
  methodology digests, run, phase, work ID, and generation.
- Prove legacy Claude selections are byte/semantic compatible where no new
  authority sidecar is considered.

### G3 — last pre-spawn authentication

- Bind `execute_worker_transaction` after plan/roster validation and durable intent
  preparation, but before process creation can occur.
- Authenticate launch, capability, route, attempt, platform, environment
  allowlist, and command fingerprint.
- All failures occur before spawn.

### G4 — provider spool and terminal observation

- Bind direct and isolated execution paths to the same adapter contract.
- Capture actual backend/model/effort/service/fallback evidence without trusting
  provider prose.
- Accept bounded frames and terminal evidence for the 14 spawned branches.
- Preserve timeout/cancel/transport/malformed/empty terminal distinctions.
- Do not convert lack of provider evidence into proof of the requested route.

### G5 — completed current and replay

- Reconcile requested, selected, attempted, observed, and terminal route facts.
- Atomically publish exactly one `CompletedCurrentAuthorityV1`.
- Validate it before PhaseIO projection and ArtifactLedger/BB consumption.
- Reject ancestry mismatch, stale generation, conflicting current records, partial
  replace, and provider self-certification.

### G6 — resume and crash recovery

- Call `recover_worker_transactions` before completed-checkpoint reconciliation.
- Construct/replay `PriorResumeIdentityAuthorityV1`.
- Accept, retry, rewind, or produce durable debt according to the 18 cutpoints.
- A retry gets a new generation and may not inherit ambiguous observed-route facts.

### G7 — driver, BB, RunBundle, and evaluator propagation

- Carry typed route/current/resume authorities through PhaseIO, ArtifactLedger,
  BB wrapper receipts, RunBundle export, and neutral evaluator inputs.
- Keep Markdown as a projection only.
- Reject report/evaluator route claims that cannot replay the current authority.
- Verify BB repository pulling/organization paths remain independent of backend
  selection and that BB provider replay consumes the same current validator.

### G8 — cross-platform native validation

- Windows: low-integrity lease, no-follow/reparse behavior, long paths, atomic
  replace/directory durability, kill/reap, provider crash recovery.
- Linux: cgroup/process-tree ownership, symlink/no-follow, fsync/rename durability,
  signals, timeout/cancel.
- macOS: process-group ownership, symlink/no-follow, fsync/rename behavior,
  timeout/cancel.
- Cross-platform behavior is compared at authority/state-transition level, not by
  forcing identical OS syscalls.

### G9 — separately authorized shadow/canary

- Shadow only after all offline gates pass and independent review accepts the diff.
- Preserve Claude as default; no model-policy or Max change.
- Compare route decisions and runtime debt without allowing the shadow authority to
  publish audit artifacts.
- Live audits and held-out recall/precision evaluation remain human-authorized.

## 8. Schema and work-plan migration

Do not reinterpret existing records in place. Use additive, explicitly versioned
schemas and adapters:

- read old PhaseIO/WorkPlan/LaunchSpec/Execution records through their existing
  validators;
- derive a new route authority only when every required old input is replayable;
- write new sidecars/fields under a new schema version;
- dual-read only for a bounded migration period;
- never let “old record lacks route authority” mean “use current defaults”;
- old completed work without replayable route evidence is legacy/unproven and is
  handled by explicit compatibility policy, not silently upgraded;
- cutover only after neutral evaluator and BB wrapper consume the new record.

If WorkPlan V2, PhaseIO ContractV2/LaunchSpecV2, WER, or WTx cannot add the required
digest bindings without changing semantics, introduce their next versions in
parallel. Do not overload an existing optional mapping with authoritative route
state.

## 9. Test and acceptance matrix

At every checkpoint:

1. Source/schema unit fixtures.
2. Per-consumer branch matrix.
3. Mutation/adversarial fixtures.
4. Crash-cutpoint fixtures.
5. Fake-provider direct and isolated paths.
6. Resume and generation-transition fixtures.
7. BB replay and ArtifactLedger projection fixtures.
8. Native platform fixtures where available.
9. Full relevant fast lane.
10. Independent source/call-graph and diff review.

The acceptance oracle additionally executes 71 stable-error registry/source
mutations and 11 R1-blocker probes: collapsed crash references, rewritten
CR-06, arbitrary branch/model rosters, disconnected applicability/record/
landmark semantics, source-scope drift, duplicate-key JSON, non-finite JSON,
and a nested dead call-edge false positive.

The current offline regression selection has 24 node IDs and 35 parametrized cases.
It covers transactional Claude/Codex driver cutover, pre-spawn failure, neutral
headless success/failure, WTx recovery, sole canonical publication, WER replay/fsync/
timeout, Windows long paths, offline Claude runtime failure cutpoints, low-integrity
process ownership, and no-follow behavior. It is necessary but not sufficient for
GREEN: all new 217 operations must transition from missing binding to the exact
expected authority/result.

Those tests are selected as fake-provider/offline fixtures, but the current
launcher does not enforce an OS network boundary. The validator therefore
reports provider and network observations as `UNOBSERVED`; it does not print
or certify zero calls. A future sandboxed launcher may upgrade that claim only
with a separately replayable observation receipt.

Checkpoint acceptance requires:

- zero unbound consumer/branch operations;
- exact closed registry and source binding;
- no adapter bypass;
- no provider self-certification;
- no resume without WTx recovery/current replay;
- no legacy Claude route/default change;
- no Max;
- no fake-provider/native regression;
- deterministic canonical record hashes;
- independent PASS;
- no production cutover, provider call, network call, audit run, merge, commit, or
  push without the next explicit authority.
- no validator claim that provider/network activity was observed absent an
  enforceable launcher receipt.

## 10. What this plan does and does not solve

It directly addresses backend/model execution truth, fallback drift, crash ambiguity,
and resume replay. Those defects can create silent quality variation and make A/B
results untrustworthy, so closing them is prerequisite measurement infrastructure.

It does not itself improve vulnerability methodology application, severity judgment,
or finding retention. It makes those experiments attributable: a run can prove which
route actually produced each artifact and whether resume/fallback changed it.
Recall and precision improvement must still be demonstrated on governed held-out
corpora with a neutral, out-of-tree evaluator. <PRIVATE_REGRESSION_TARGET> remains regression-only and
must not be scored as independent evidence for a gate inspired by <PRIVATE_REGRESSION_TARGET>.

## 11. Current verdict

Proceed to independent R2 review after the final driver/source-scope rebind. If
it passes, the
separate implementation should follow G0→G8 in order, with G9 requiring explicit
human authorization. Do not skip directly to production wiring: the disconnected
proof mint and recovery seams, the seven-way cross-layer call graph, and crash
ambiguity make an all-at-once cutover unnecessarily risky.
