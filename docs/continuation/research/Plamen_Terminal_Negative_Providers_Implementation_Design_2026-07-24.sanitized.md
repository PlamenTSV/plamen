# Plamen Terminal-Negative Providers — Implementation Design

**Date:** 2026-07-24  
**Status:** Read-only architecture and staged implementation plan  
**Repository inspected:** `<LOCAL_USER_ROOT>\plamen-codex-implementation`

No repository files were changed and no tests or audits were run while preparing this design. The design follows Plamen's existing phase sequence and artifact-gated pipeline.

## 1. Current implementation inventory

| Capability | Current state | Production status |
|---|---|---|
| Central broker write/load/replay | Implemented in `scripts/closure_broker_v2.py`, despite most persisted schemas still being `v1` | Live through driver and several consumers |
| Applied lossless equivalence | Deterministic adapter feeds the central authority | Live and potentially authoritative |
| Terminal provider registration | `register_completed_negative_closure_provider` exists | Test-only; no production caller |
| Mechanical/exhaustive provider records | Registry, schemas, validation, replay, and tests exist | No launcher, PhaseIO unit, transaction, or registration path |
| Legacy negative evidence authority | `issue_*`, `validate_*`, and `classify_*` APIs | Dead outside tests; unsafe for terminal authority |
| WER process observation | Pins executable, argv, parser, inputs, environment, outputs, and containment | Live, but launches one worker only |
| WER `assessors` | Metadata labels | Not evidence that a reviewer executed |
| Application skeptic | Claude WER path | Live proposal source |
| Codex skeptic | Raises unsupported debt | No live transport; fixture subprocess is test-only |
| Compound plan compilation | Typed plan and queue adapters | Live |
| Compound evaluation/report binding | Generic evaluator, binder, validator | Test-only; no production call sites |
| L1 composition | Fact production, code graph, disposition production, reconciliation, queue delivery | Live but shadow/proposal-only |
| L1 negative receipts | Normalize/validate support exists | Test/library-only in the live driver path |
| Report disposition | Consults central broker | Live, currently with an effectively empty terminal-provider denominator |
| Negative-authority phase | None in `SC_PHASES` or `L1_PHASES` | Missing |
| Provider transaction journal | None | Missing |

### 1.1 Exact live and dead/test-only API inventory

The live central authority path is:

1. The driver refreshes the central ledger through `write_central_negative_closure_authority`.
2. The driver and consumers load it through `load_central_negative_closure_authority`.
3. Application skeptic, inventory reconciliation, finding lifecycle, security-obligation lifecycle, report disposition, and related consumers resolve proposals through the central authority.
4. The applied-equivalence adapter can contribute decisions to the denominator.

The following APIs or paths have no non-test production call site:

- the legacy shadow `ClosureAuthorityBrokerV2` class;
- `register_completed_negative_closure_provider`;
- public legacy `issue_negative_closure_authority`;
- public legacy `validate_negative_closure_authority`;
- public legacy `classify_negative_evidence_basis`;
- `evaluate_compound_work_item`;
- `bind_compound_report`;
- `validate_compound_report_bindings`;
- the L1 negative-receipt path when the live driver invokes composition without supplying those receipts.

The production broker therefore consumes applied-equivalence authority, but has no live path that launches, reviews, or registers terminal providers.

### 1.2 Binding mismatch in current consumers

A critical mismatch exists across all current consumers:

- application-skeptic and candidate-negative work items supply premise IDs but no canonical candidate-content digest;
- inventory reconciliation, finding lifecycle, security-obligation lifecycle, and report-disposition callers supply candidate content but no exact premise identities.

The broker currently falls back from one binding form to the other. No existing consumer can satisfy the required exact `content AND premise identities` predicate.

### 1.3 Unsafe current validation behavior

The current central bundle validation:

- accepts provider-declared `exhaustive=true`;
- relies on legacy provider-output scope/exhaustiveness labels;
- treats a reviewer identity appearing in WER `assessors` as review evidence;
- does not bind execution to a code-owned executable/module/parser/enumerator/oracle registry entry;
- can let unrelated malformed evidence create global debt;
- matches exact decisions by premises or content instead of both.

The current application-skeptic capability also declares model terminal-negative authority, and Claude eligibility conflates process containment with semantic exhaustiveness. Both declarations must be removed before any live cutover.

## 2. Terminal authority boundary

The only terminal-negative predicate should be:

```text
terminal_authorized =
    registry_supports_exact_subject
    AND exact_content_binding
    AND exact_premise_set_binding
    AND implementation_matches_registry
    AND domain_is_broker_proven_complete
    AND oracle_is_decisive_for_every_obligation
    AND independent_review_passed
    AND provider_transaction_committed
    AND broker_replay_succeeds
```

### 2.1 Permitted terminal provider classes

1. Applied, lossless semantic equivalence.
2. Decidable mechanical scope exclusion over a structured, code-owned boundary.
3. Complete enumeration of a finite, code-owned domain with a code-owned oracle.
4. Checked proof/model-checking where exact obligations and certificate checker are pinned.

### 2.2 Always proposal-only or unsupported

- Claude or Codex conclusions;
- verifier or analyst refutations;
- fuzzing, bounded exploration, failed PoCs, and “no witness found”;
- temporal, economic, environmental, external-system, or open-world absence claims;
- confidence, precedent, trust, or severity labels;
- L1 model fact/disposition outputs;
- compound analyst conclusions;
- provider-declared exhaustiveness.

Unknown, unsupported, malformed, incomplete, conflicting, timed-out, or unreviewed results must reopen or retain the candidate.

### 2.3 Effect-specific predicates

#### `OUT_OF_SCOPE`

Authorize only through a code-owned decidable boundary. Any in-scope cross-boundary consumer prevents authorization. Natural-language interpretation or model scope classification is insufficient.

#### `REFUTED_FULL`

Authorize only when the exact overall claim formula is proven false, or every sufficient harm branch is refuted. A list of individually rejected premises does not imply rejection of the overall claim unless the formula explicitly makes them exhaustive and sufficient.

#### `ZERO_HARM`

Authorize only after exhaustive evaluation of the exact harm property, with no relevant unrepresented temporal, environmental, economic, or external dimensions.

#### `ALIAS`

Authorize only through applied, lossless equivalence with exact identity and representation binding.

Every other requested effect normalizes to `UNSUPPORTED`.

## 3. Required v2 artifacts

All v1 artifacts remain readable as supporting evidence only. They must never be auto-promoted to v2 terminal authority.

### 3.1 Negative challenge ledger v2

Create one immutable ledger per run/snapshot with an explicit input denominator and exactly one final planning disposition per challenge.

Root fields:

- schema/version;
- run ID;
- pipeline;
- mode;
- ecosystem;
- backend;
- snapshot identity/digest;
- source/build identity;
- input-denominator count/digest;
- challenge-denominator count/digest;
- registry digest;
- ordered challenge rows;
- ledger digest.

Each challenge row needs:

- challenge ID;
- candidate and work identifiers;
- candidate content SHA-256;
- canonical sorted premise IDs;
- premise-set digest;
- premise-manifest digest;
- origin artifact, record, and content digests;
- producer identity and observed invocation receipt;
- supporting evidence identifiers/digests;
- requested effect;
- challenge-row digest;
- final planning state: `READY`, `UNSUPPORTED`, or `DEBT`;
- reason code.

Models may emit typed challenge rows but cannot select a provider, declare readiness, completeness, or terminal effect.

### 3.2 Terminal provider registry v2

A code-owned registry entry must pin:

- provider ID, version, and kind;
- allowed effects;
- support predicate and planner module;
- executable or module identity and digest;
- argv-template digest;
- parser identity, version, source digest, and implementation digest;
- enumerator identity, version, source digest, and implementation digest;
- oracle identity, version, source digest, and implementation digest;
- reviewer identity, version, source digest, and implementation digest;
- supported pipelines, ecosystems, modes, subject kinds, and domain kinds;
- environment allowlist;
- timeout, stream, and output limits;
- review mode: `BROKER_RECOMPUTE` or `OBSERVED_REVIEWER_WER`;
- reviewer independence policy;
- entry digest;
- whole-registry digest.

A work plan or provider bundle cannot broaden registry support.

### 3.3 Provider work plan v2

Each item binds:

- exact challenge, candidate, and work IDs;
- content digest;
- exact premise IDs and premise-set digest;
- premise-manifest digest;
- requested effect;
- registry entry and registry digest;
- support state and reason;
- subject, domain, oracle, worker, and reviewer manifest IDs/digests;
- expected output locations and schemas.

The work plan root binds the run, pipeline, mode, ecosystem, backend, snapshot, source/build identity, challenge-ledger digest, provider denominator, and registry digest.

### 3.4 Subject manifest v2

Bind:

- exact candidate/work/challenge identity;
- subject kind;
- source snapshot and build/environment identity;
- current source artifacts and record digests;
- candidate content digest;
- exact premise IDs and premise-set digest;
- premise manifest;
- requested effect;
- manifest digest.

### 3.5 Domain manifest v2

Represent every relevant dimension explicitly:

- input;
- state;
- actor;
- ordering;
- temporal;
- external;
- environment.

Each dimension is one of:

- `FINITE_VALUES`;
- `PARTITIONS`;
- `FORMAL_ABSTRACTION`;
- `UNREPRESENTED`.

The manifest contains:

- ordered members/obligations;
- exact denominator, count, and digest;
- premise-to-domain/property mapping;
- abstraction/checker identities where used;
- coverage witnesses;
- all unrepresented dimensions;
- planned output schema;
- manifest digest.

The planner may declare `PLANNED`; only the broker/reviewer may derive `COMPLETE`.

### 3.6 Oracle manifest v2

Pin the oracle implementation and exact claim formula:

- identity and version;
- source and code digests;
- independent author/owner;
- property per premise or harm branch;
- overall claim formula;
- result interpretation;
- environment-fidelity requirements;
- positive and negative controls;
- ambiguity and conflict rules;
- manifest digest.

### 3.7 Raw provider result v2

Provider output contains member-level facts only:

- member/obligation ID;
- exact input/property binding;
- outcome;
- evidence or certificate digest;
- error/unknown state.

It must not contain an authoritative `exhaustive`, `complete`, or terminal-effect field.

### 3.8 Review receipt v2

The reviewer or broker recomputation derives:

- expected members;
- observed members;
- missing members;
- duplicate members;
- unexpected members;
- positive and negative control results;
- unknowns, errors, and conflicts;
- implementation-pin comparison;
- source/build/environment comparison;
- derived coverage state;
- derived effect state;
- worker completion/publish receipt bindings;
- reviewer completion/publish receipt bindings where applicable;
- receipt digest.

Completeness is exact set equality, not a provider assertion.

### 3.9 Provider bundle v2

The committed bundle includes:

- subject, domain, and oracle manifests;
- registry entry and registry digest;
- PhaseIO planner receipts;
- actual WER worker receipt;
- actual reviewer WER or broker-recomputation receipt;
- raw result;
- review result;
- exact implementation pins;
- challenge/snapshot/source/build binding;
- provider-transaction journal digest;
- bundle digest.

### 3.10 Central decision v2

Decision identity is keyed by:

```text
(run, snapshot, challenge, candidate, work,
 candidate_content_sha256, candidate_premise_set_sha256, effect)
```

The decision also binds the subject/domain/oracle manifests, registry entry, worker/reviewer receipts, provider bundle, challenge ledger, and central-ledger digest.

No content/premise fallback is permitted.

## 4. Completeness and review predicates

The broker derives domain completeness as:

```text
domain_complete =
    expected_member_ids == observed_member_ids
    AND missing_member_ids == {}
    AND duplicate_member_ids == {}
    AND unexpected_member_ids == {}
    AND every_premise_maps_to_exact_property_obligations
    AND every_relevant_dimension_is_represented
    AND controls_pass
    AND unknowns == {}
    AND errors == {}
    AND conflicts == {}
    AND no_positive_witness_invalidates_the_requested_effect
```

`FORMAL_ABSTRACTION` counts as represented only when the pinned checker validates the abstraction against the exact obligation. `UNREPRESENTED` prevents any terminal claim that depends on that dimension.

Independent review requires either:

1. deterministic broker recomputation from immutable raw facts; or
2. a second observed reviewer execution with an allowed independent principal and invocation.

WER `assessors` metadata does not satisfy this predicate.

## 5. Runtime ownership and transaction model

Ownership must remain explicit:

- **Driver:** phase scheduling, denominator construction, support planning, resume decisions.
- **PhaseIO:** immutable input/output artifact identity and commit protocol.
- **WER:** observation of one subprocess and raw completion/publish state only.
- **Provider worker:** member-level computation only.
- **Reviewer:** separate observed process or deterministic broker recomputation.
- **Broker:** completeness, scope, oracle, independence, and terminal authority.
- **Report mutation transaction:** atomic report and binding-sidecar publication.
- **Models:** challenge generation only.

Add a `TerminalProviderTransaction` journal:

```text
PLANNED
→ PHASEIO_ARMED
→ WER_ARMED
→ WORKER_RUNNING
→ WORKER_PUBLISHED
→ REVIEW_PUBLISHED
→ REGISTER_PREPARED
→ COMMITTED
```

Each transition binds exact current digests and is idempotent. One transaction owns one work item and one output scope. No provider or reviewer writes shared report artifacts.

An observed reviewer is a second WER with a distinct principal/invocation and, where required by the registry independence policy, a distinct implementation. WER `assessors` are ignored for semantic authority.

## 6. Pipeline and PhaseIO integration

Add an explicit `negative_authority` phase immediately after `severity_adjudication_shadow` and before `report_index` in both SC and L1 phase sequences.

This placement gives the phase all verification and challenge sources while allowing report construction to consume the final central ledger. Earlier negative consumers continue to emit challenges and retain work; they do not destructively suppress work before terminal authority exists.

Recommended work units:

1. `challenge.plan` — construct the typed challenge ledger and exact denominator.
2. `provider.plan` — apply code-owned registry support predicates.
3. `manifest.<shard>` — construct subject/domain/oracle manifests.
4. `provider.<provider_id>` — execute the observed code/tool worker.
5. `review.<provider_id>` — execute a second observed reviewer or broker recomputation.
6. `register.<provider_id>` — validate the bundle and atomically register it.
7. `broker.replay` — recompute the central ledger from immutable bundles.
8. `compound.evaluate` — consume actual verifier artifacts.
9. `l1.finalize` — recompute L1 eligibility from exact central decisions.
10. `deliver` — write exact consumer projections, debt, and human-review rows.

Every unit needs an explicit PhaseIO contract with exact dynamic inputs and outputs. Empty or entirely unsupported denominators still produce committed receipts and must not launch workers.

The phase should be haltless for analysis continuity: provider failure retains work rather than aborting the audit. A final report that cannot establish exact report/binding consistency may be quarantined as no-ship.

## 7. Closure broker v2 changes

Refactor `scripts/closure_broker_v2.py` or split its schemas into supporting modules.

Required changes:

- Replace legacy self-declared provider completeness with broker-derived set equality.
- Compare observed WER executable, argv, parser, enumerator, oracle, and reviewer pins with the code-owned registry.
- Require content and premise-set identity for every exact negative decision.
- Persist the complete challenge denominator, including unsupported and unexecuted rows.
- Scope debt to subject/work/bundle.
- Prevent an unrelated corrupt bundle from vetoing all decisions.
- Reserve global debt for root, registry, denominator, or concurrent-mutation corruption.
- Localize duplicate/conflicting authority to affected subjects.
- Ensure legacy issuance APIs cannot mint v2 authority.
- Preserve applied equivalence through a v2 adapter.
- Give applied equivalence a distinct explicit alias rule rather than exploiting missing premises.
- Reject bundles that add provider capabilities, supported ecosystems, effects, or implementation identities not present in the registry.

The central authority loader remains the only production replay boundary. Consumers do not accept direct provider bundles or callbacks.

## 8. Consumer migration

Update all central-authority callers to use one canonical subject-binding sidecar.

- Application skeptic and candidate-negative work items gain candidate-content digest, premise manifest, and premise-set digest.
- Inventory reconciliation gains exact premise binding.
- Finding lifecycle gains exact premise binding.
- Security-obligation lifecycle gains exact premise binding.
- Report disposition gains exact premise binding and report-block binding.
- Existing early-phase negative results remain challenges and cannot destructively suppress work.
- Typed candidate-negative sidecars become primary.
- Markdown harvesting is retained only as `LEGACY_UNBOUND` proposal evidence.
- Missing legacy content or premises always means retain/BODY/reverify.

The central resolver must accept only exact v2 subject bindings for terminal decisions. Any legacy call missing content or premises receives no authority.

Severity cannot be lowered merely because central negative authority exists. Exact exclusion/refutation/zero-harm affects lifecycle and disposition; a lower severity still requires independent positive evidence.

## 9. Compound verification

### 9.1 Constituent bindings

Extend compound constituent bindings so every constituent records:

- constituent ID and kind;
- source artifact/path and record digest;
- candidate content and premise-set digests;
- lifecycle authority;
- queue/work-plan digest;
- verifier PhaseIO/WER result and status;
- fact/authority digests where applicable.

Compound candidates need explicit premises for:

- composition edge;
- ordering;
- reachability;
- combined harm.

These premises and the exact compound claim formula become part of the subject identity.

### 9.2 Live compound evidence

Replace caller-created evidence booleans with a live runtime that parses actual verifier artifacts and binds:

- harness/source/build/environment;
- executable, argv, and parser;
- completion and publish receipts;
- exact result artifacts;
- composition and harm outcomes.

Wire `evaluate_compound_work_item` into the new negative-authority phase.

Negative compound evidence remains a challenge until the broker authorizes the same exact content and premise set. Positive confirmation still requires independent composition and harm evidence.

### 9.3 Report binding

Upgrade compound report binding to include:

- run and snapshot;
- report artifact SHA-256;
- exact report block ID and block digest;
- candidate/work/plan/content/premises;
- constituent binding digests;
- evidence and evaluation digests;
- central bundle/reviewer/decision/ledger digests for exclusions;
- final disposition.

Run binding after report assembly and after every report mutation/floor operation. Publish the report and compound-binding sidecar atomically through the report mutation transaction.

Validation uses exact set equality:

- every compound work item has exactly one disposition/binding;
- every compound report row has exactly one binding;
- no substitution, collision, or omission;
- BODY requires confirmed positive evidence;
- EXCLUDED requires exact central authority.

Unsafe mismatch results in BODY/human-review retention or final report quarantine.

## 10. L1 composition

Keep L1 model facts and dispositions proposal-only.

Add a post-verification L1 adapter that:

- loads exact central decisions;
- binds decisions to constituent content and premises;
- recomputes composition eligibility and graph delta;
- binds every removed obligation to its central decision;
- emits a final typed L1 projection.

Producer `REFUTED` alone remains eligible. A terminally refuted constituent can be removed only through the post-verification adapter.

Already-delivered compound handoffs must not silently disappear. They become constituent-refuted/human-review unless the compound candidate itself has exact terminal authority.

Compound handoffs flow through the same live compound evaluator and report binder.

Go/Rust core and thorough paths should be live. Light mode should record explicit `NOT_TRIGGERED`. Unsupported ecosystems or languages produce `UNSUPPORTED` plus retained obligations.

## 11. Proposed file layout

New production modules:

- `scripts/negative_challenge_authority.py`
- `scripts/terminal_negative_provider_schemas.py`
- `scripts/terminal_negative_provider_registry.py`
- `scripts/terminal_negative_provider_planner.py`
- `scripts/terminal_negative_provider_runtime.py`
- `scripts/terminal_negative_provider_review.py`
- `scripts/negative_authority_delivery.py`
- `scripts/compound_verification_runtime.py`
- `scripts/compound_report_authority.py`
- `scripts/l1_composition_negative_adapter.py`

Primary edits:

- `scripts/plamen_types.py`
- `scripts/phase_io_contracts.py`
- `scripts/closure_broker_v2.py`
- `scripts/negative_closure_policy.py`
- `scripts/work_unit_capabilities.py`
- `scripts/skeptic_execution_work.py`
- all central-authority consumer modules;
- `scripts/compound_verification.py`;
- compound plan/queue adapters;
- L1 composition authority/runtime;
- report mutation/floor integration;
- `.gitignore` and packaging manifests.

Because `scripts/*` is ignored and selectively re-included, every new runtime module requires an explicit unignore rule and clean-checkout packaging coverage.

## 12. Staged rollout

### Stage 0 — Freeze unsafe authority

- Remove `terminal_negative_authority=True` from model discriminator capabilities.
- Rename Claude eligibility to challenge-transport/process-containment eligibility.
- Require content and premises together.
- Scope broker debt.
- Keep all existing provider records shadow-only.

### Stage 1 — Artifact and transaction foundation

- Add v2 schemas, challenge ledger, registry, PhaseIO units, and transaction journal.
- Migrate consumers to canonical subject bindings.
- Make legacy missing bindings retain work.

### Stage 2 — Live execution in shadow

- Add support planner, manifests, WER worker/reviewer execution, registration, and broker replay.
- Run with no report suppression.
- Compare replay with expected retention and debt behavior.

### Stage 3 — Mechanical scope cutover

- Enable only exact structured scope providers.
- Require multi-ecosystem, fault, resume, and held-out semantic evidence.
- Keep applied equivalence live.

### Stage 4 — Finite/checker providers

- Enable one explicit registry adapter/domain at a time.
- Make generic or unrepresented domains return `UNSUPPORTED`.
- Never add a generic model-based closure provider.

### Stage 5 — Compound live path

- Wire live evidence parsing, evaluation, report binding, mutation integration, and exact-set validation.

### Stage 6 — L1 finalization

- Add central-decision projection, final graph recomputation, and compound handoff binding.

### Stage 7 — Backend parity

- Implement Codex challenge transport with equivalent observed receipts.
- If unavailable, retain explicit debt.
- Keep terminal authority backend-neutral.

### Stage 8 — Migration and controlled cutover

- Validate clean-checkout packaging and installation.
- Run synthetic transport canaries.
- Run a non-GT fresh legacy Claude EVM canary.
- Run a representative non-EVM canary.
- Run Go/Rust L1 canaries.
- Run a resume canary with independent observation.
- Do not automatically merge, push, install, or cut over authority.

## 13. Failure behavior

At every destructive boundary, anything other than exact authorization normalizes to `UNKNOWN` and causes retain, reopen, BODY, reverify, or human review.

Fault coverage must include:

- planning/manifest failure;
- PhaseIO prepare/commit failure;
- WER arm/launch failure;
- timeout;
- nonzero exit;
- partial output;
- completion without publish;
- publish without completion;
- reviewer failure;
- registration failure;
- ledger-write failure;
- malformed JSON or Unicode;
- oversized streams;
- missing executable or parser;
- executable/parser/enumerator/oracle pin mismatch;
- missing, duplicate, or unexpected enumeration members;
- pre-existing or stale outputs;
- stale inputs;
- path/case issues;
- lock contention;
- disk failure;
- concurrent mutation;
- unrelated bundle corruption.

Model/tool timeout must not be retried by the authority path. Record the timeout and retain the subject. Deterministic transaction recovery may replay committed artifacts without re-invoking the timed-out worker.

## 14. Resume behavior

- Reuse a worker result only if all registry, input, environment, source, build, and implementation pins remain exact.
- Reviewer and registration transitions are independently idempotent.
- Immutable conflicts create debt and are never overwritten.
- Registry/source/snapshot changes invalidate only affected descendants.
- Deterministic recovery replays the transaction without rerunning a completed subprocess.
- Do not duplicate authority or denominator rows on resume.
- Do not automatically archive, restart recon, or relaunch models.
- A completion receipt without the required publish receipt is not reusable authority.
- A published output without a matching completion receipt is quarantined.

## 15. Migration rules

- V1 bundles and legacy authorities remain readable supporting evidence only.
- Do not automatically promote v1 evidence to v2 terminal authority.
- New runs write v2 exclusively.
- Resumed legacy runs emit an explicit migration manifest.
- Typed sidecars may be converted into challenges.
- Markdown-only evidence remains `LEGACY_UNBOUND`.
- Re-adapt applied equivalence only from current valid receipts.
- If exact candidate premises cannot be reconstructed, retain/BODY.
- Existing non-BODY report decisions are not silently grandfathered.
- Rebuild affected reports from immutable pre-report artifacts or mark them no-ship.
- Schema/registry digest mismatch triggers non-destructive startup debt.
- A fresh restart after an incompatible schema/registry change requires explicit authorization.
- Recompute only negative-authority and report descendants where inputs remain valid; do not relaunch model producers merely to migrate deterministic artifacts.

## 16. Support matrix

### 16.1 Pipelines and ecosystems

- Smart-contract pipeline: EVM, Solana, Aptos, Sui, Soroban, and Daml where structured subject/scope manifests are exact.
- L1 pipeline: Go and Rust.
- Modes: light, core, and thorough, with explicit `NOT_TRIGGERED` or `UNSUPPORTED` receipts where a provider is not enabled.

Mechanical structured-scope providers may be enabled only where the source/scope representation is exact. Finite enumeration and checked-proof providers require an explicit registry adapter per domain. Generic fallback always returns `UNSUPPORTED`.

### 16.2 Backends

- Claude: retain the existing observed challenge transport after removing terminal capability semantics.
- Codex: implement equivalent observed challenge transport later; until then emit backend debt.
- Terminal providers: backend-neutral code/checkers only.

### 16.3 Operating systems

Validate deterministic path, executable, digest, environment, timeout, stream, and transaction behavior on Windows, Linux, and macOS.

## 17. Acceptance matrix

### 17.1 Semantic red cases

At minimum:

- same candidate ID, different content;
- same content, different premises;
- premise reordering versus canonical set;
- sibling candidate substitution;
- stale snapshot;
- stale source;
- stale build;
- stale environment;
- provider self-declared exhaustive;
- missing domain member;
- duplicate domain member;
- unexpected domain member;
- unrepresented relevant dimension;
- oracle ambiguity;
- oracle conflict;
- reviewer identity label without execution;
- worker implementation mismatch;
- reviewer implementation mismatch;
- unrelated corrupt bundle;
- exact report-block substitution;
- L1 producer refuted without central decision;
- cross-boundary in-scope consumer;
- incomplete overall-claim formula;
- applied-equivalence identity mismatch;
- challenge-ledger denominator omission;
- duplicate authority for one subject;
- valid decision for one subject plus malformed evidence for an unrelated subject.

### 17.2 Fault and resume acceptance

Cover every failure in Sections 13 and 14, including interruption at every transaction transition, exact replay, no duplicate authority, scoped invalidation, and safe retention.

### 17.3 Denominator and support acceptance

Cover:

- empty challenge denominator;
- non-empty but entirely unsupported denominator;
- partially supported denominator;
- fully supported finite denominator;
- provider unavailable;
- reviewer unavailable;
- mixed valid and corrupt bundles;
- mixed ecosystems and modes.

### 17.4 Compound and L1 acceptance

- Every compound work item has exactly one final binding.
- Every compound report block has an exact report digest binding.
- No constituent substitution or omission is accepted.
- Producer `REFUTED` alone never removes an L1 obligation.
- Every L1 graph removal is bound to an exact central decision.
- Previously delivered compound handoffs remain traceable after constituent disposition changes.

### 17.5 Packaging and installation acceptance

- Clean checkout contains every new production module.
- New modules are explicitly unignored and tracked.
- Imports work from installed copies, not only the developer worktree.
- Driver entry points resolve the same modules and registry digests.
- Registry code digests match installed runtime implementations.
- Claude and Codex installation surfaces do not create different terminal authority.

### 17.6 Final completion gates

Completion requires:

- generic semantic red fixtures;
- Part-0 acceptance-ledger gates;
- focused and full test suites;
- fault, migration, and resume suites;
- fresh legacy Claude-path evidence;
- multi-ecosystem and L1 evidence;
- no loss of candidate identity;
- no loss of premise identity;
- no loss of obligations;
- no loss of independently authorized negative evidence;
- no model self-certification path;
- no report exclusion without exact broker authority.

Ground truth must remain forbidden as audit input. <PRIVATE_AUDIT_TARGET>/<PRIVATE_REGRESSION_TARGET> are user-run post-handoff only, not implementation canaries or closure evidence.

## 18. Non-negotiable production invariant

The provider computes facts. The observed worker receipt proves only what process ran. The reviewer or broker derives completeness. The central broker alone grants terminal authority. Models, labels, confidence, legacy evidence, and provider self-assertions can never cross that boundary.
