# Method-application architecture

Status: normative migration contract
Scope: smart-contract and L1 pipelines, all supported ecosystems, Claude and
Codex backends
Authority: architecture only; this document does not certify a method,
provider, worker result, negative conclusion, finding, severity, or benchmark
outcome

This RFC supersedes the physical SQLite-first, universal SQL event stream, and
global SQL/Markdown dual-write design in the 2026-07-15 plan. Plamen semantic
authorities are versioned typed artifacts published through PhaseIO. SQLite
may be an unrelated cache or projection, but it is not semantic authority
without a new reviewed supersession.

## 1. Purpose

Plamen must distinguish three questions that prose-only audit pipelines tend to
collapse:

1. Was a security method selected for this exact subject?
2. Was every required operation of that method actually attempted against the
   selected subject with the bound inputs?
3. What did the resulting evidence support?

A worker saying that it followed a skill is not proof of question 2, and an
empty result is not proof of question 3. The method-application system therefore
uses typed, digest-bound obligations and receipts. Markdown remains a worker
interface and human projection; it is not the authority store.

The design is recall-open:

- incomplete, malformed, stale, contradictory, or missing application evidence
  creates repair or review debt;
- a producer may propose a negative outcome but cannot authorize it;
- application failure never becomes `SAFE`, `NO_FINDING`, or a demotion;
- every candidate and independently issued challenge remains represented until
  a typed disposition covers its exact identity; and
- bounded execution preserves the unprocessed denominator as durable debt.

## 2. Existing implementation boundary

The current strangler implementation is distributed across these canonical
components:

| Concern | Current authority |
|---|---|
| Normative method-content catalog | `methodology/method-cards-v1.yaml` |
| Phase-5 verification consumer profile | `verification_policy/verification_method_registry.v1.json` |
| Catalog compiler and reachability | `scripts/verification_method_compiler.py` |
| Phase/skill dispatch binding | `scripts/methodology_application.py` |
| Application/outcome state separation | `scripts/methodology_application_states.py` |
| Independent negative challenge | `scripts/application_skeptic.py` |
| Security-obligation lifecycle | `scripts/security_obligation_lifecycle.py` |
| Driver-owned work identity | `scripts/semantic_work_plan.py` |
| Phase transaction and artifact authority | `scripts/phase_io_contracts.py` and `scripts/artifact_ledger.py` |
| Worker execution authority | `scripts/worker_transaction.py` and `scripts/worker_execution_receipts.py` |
| Premise-bound severity | `scripts/severity_decision_ledger.py` |
| Final disposition authority | `scripts/report_disposition_authority.py` |

These sidecars supersede the original proposal for an immediate monolithic
finding database. They do not waive any lifecycle invariant that the database
was intended to enforce. The migration crosswalk is specified in
`architecture/finding-ledger-migration.md`.

## 3. Canonical concepts

### 3.1 Method definition

A method definition is a generic, versioned analysis operator. It declares:

- a stable method and revision identity;
- applicability selectors for pipeline, ecosystem, mode, role, phase, and
  evidence capability;
- generic analysis operations and the evidence class expected for each;
- required input classes and optional enrichment classes;
- explicit unsupported and not-applicable semantics;
- bounded cost and overflow behavior;
- application, repair, and independent-challenge consumers; and
- source bytes and transitive reference digests.

Method definitions must not contain target names, known target findings,
ground-truth wording, motivating locations, or protocol-specific answers.

`methodology/method-cards-v1.yaml` is the sole normative source for method
identities, semantic operators, selectors, required steps and receipts,
not-applicable policy, and capability/fidelity requirements.
`verification_policy/verification_method_registry.v1.json` is a Phase-5
consumer profile. Until cutover it may remain runtime-active, but it must
reference catalog method IDs, versions, and digest and cannot redefine method
semantics. Runtime activation and normative ownership are separate facts.

### 3.2 Subject

A subject is the smallest stable unit to which a method operation applies. It
may be a source entity, state relation, boundary, externally controlled input,
asset flow, role transition, cross-domain seam, candidate constituent, or
finding consequence.

Subject identity is derived from normalized typed fields and immutable source
or artifact bindings. A Markdown heading, filename, list position, display
title, severity label, or agent-local identifier is not a canonical identity.

Aliases remain explicit. Consolidating two aliases never proves that both were
examined, verified, or delivered.

### 3.3 Obligation

An obligation binds:

- method revision;
- operation identifier;
- exact subject identity;
- source and methodology digests;
- producer and consumer identities;
- required evidence capability;
- selector decision and its evidence;
- attempt budget and stable shard;
- prerequisite identities; and
- lifecycle state.

The obligation denominator is enumerated before worker output is interpreted.
If enumeration is incomplete, the denominator records an explicit lower bound,
unknown remainder, and reason. Unknown remainder is not zero.

### 3.4 Obligation application evidence receipt

An application receipt answers whether an operation was applied, independently
of its semantic result. The canonical `ObligationApplicationEvidenceReceipt` is
one closed, atomic composition over the obligation, execution observation,
application attestation, evidence validation, and semantic proposal. It is not
valid when those bindings exist only in separate Markdown sections or can be
joined by a display ID. Its receipt identity is the digest of a canonical
serialization that binds all of:

- the `RunManifestBinding` digest;
- the exact obligation identity and digest;
- the work-unit identity, generation, shard, attempt, and work-plan digest;
- the worker-execution receipt identity, worker/backend identity, and
  independence class;
- the compiled prompt-bundle digest, MethodCard ID and version, catalog digest,
  rendered-operation digest, and source/methodology digests;
- the ordered target denominator and the exact target, relation, path,
  boundary, and pair identities selected for this obligation;
- every required step ID with its typed state and evidence references;
- the evidence-validation-record identity and every accepted evidence
  reference;
- the typed semantic outcome, stable candidate identities, canonical finding
  references, and premise identities used by that outcome; and
- every staged output object's PhaseIO identity, generation, media type,
  canonical digest, raw byte digest, and commit receipt.

All constituent identities and digests are mandatory even when one physical
artifact carries several constituents. The composition validator resolves each
constituent through its owning authority, proves the subject and generation
joins, and then computes the composite identity. A missing, stale, ambiguous,
or unauthorized constituent makes the composite receipt `INVALID`; it may not
be repaired by prose, filename inference, nearest-row matching, or a consumer's
private join.

The application state is one of:

- `APPLIED`
- `MISSING`
- `INVALID`
- `UNKNOWN`

The application, execution-observation, evidence-validation, and semantic-
authority states remain orthogonal fields. `APPLIED` requires complete required
step coverage and exact target-denominator reconciliation, but it never turns a
producer's semantic proposal into a verified finding. A producer trace is
evidence input, not final authority.

### 3.5 Semantic outcome

The outcome is orthogonal to application completeness. Current closed outcomes
include positive, negative-proposal, inconclusive, blocked, and not-applicable
forms. A negative producer outcome is retained as a proposal until an
independent authorized discriminator binds the same obligation, subject,
premises, and evidence.

`APPLIED` does not imply that the conclusion is correct. Conversely, a missing
application receipt does not refute a candidate.

### 3.6 Evidence receipt

Evidence is typed by capability and proof scope. At minimum, a receipt binds:

- issuer and independence class;
- exact input, source, tool, command, methodology, and output digests;
- execution status and terminal state;
- subject and constituent coverage;
- oracle and premise scope;
- replay or freshness authority;
- limitations, contradictions, and unknowns; and
- receipt identity.

Only actually executed PoCs may receive execution-proof status. Execution alone
does not establish reachability, material harm, production equivalence, or
severity.

#### 3.6.1 Common evidence-validation interface

Every MethodCard consumer calls the same fail-closed validation interface before
an application receipt can become valid. The interface accepts the immutable
run binding, source snapshot, obligation, work plan, MethodCard/catalog binding,
provider capability receipts, worker-execution receipt, staged output objects,
premise registry, and canonical candidate/finding identity map. It returns a
typed validation record; it cannot conclude vulnerability, safety, severity, or
report eligibility.

The validation record is valid only when all applicable predicates hold:

1. Each source location names a path in the bound source snapshot, has a valid
   byte/line range, and resolves to the declared source-content digest. Artifact
   locations resolve through PhaseIO to the declared object generation and raw
   byte digest.
2. Every examined target belongs to the obligation's frozen target denominator
   and subject scope. Every relation, path, boundary, pair, constituent, and
   alias reference joins to an enumerated typed identity rather than display
   text.
3. Every MethodCard step occurs exactly once with state `APPLIED`,
   `NOT_APPLICABLE`, `BLOCKED`, or `UNKNOWN`. `APPLIED` binds evidence;
   `NOT_APPLICABLE` binds an allowed reason and selector evidence; `BLOCKED` and
   `UNKNOWN` bind explicit debt and cannot satisfy application completeness.
4. Complete-coverage claims prove set equality against the frozen target,
   relation/path/boundary/pair, and required-step denominators. A lower bound,
   unknown remainder, missing target, duplicate target, or privately expanded
   denominator prevents a complete claim.
5. Every execution claim binds the exact normalized command/argument vector,
   tool and toolchain identity, working-directory identity, environment-policy
   digest, input hashes, exit/termination status, stdout/stderr or result
   object hashes, and freshness/replay authority. Text that merely states a
   command ran is not execution evidence.
6. Every external premise binds its stable premise identity, direction,
   source class, citation or research-object identity, retrieval/freshness
   status, contradiction status, and unresolved limitations. An absent,
   unreachable, stale, or stub citation remains explicit external-evidence debt
   and cannot support a favorable demotion.
7. Every candidate or finding reference resolves through the canonical identity
   map, preserves origin and parent lineage, and names the exact claim or
   constituent supported. Titles, severities, Markdown anchors, and phase-local
   IDs are never sufficient references.
8. All prompt, method, catalog, work-plan, obligation, source, provider,
   evidence, output, premise, and commit hashes match the objects named by the
   atomic receipt composition in section 3.4.

The validator returns per-predicate results plus the complete expected and
observed denominators. It never silently drops invalid evidence: failures are
recorded as typed repair or human-review debt, preserve upstream candidates, and
keep the application state `INVALID` or `UNKNOWN`.

### 3.7 Disposition

A disposition is a separate decision event. It identifies the upstream state,
proposed change, decision authority, premises, evidence, direction, affected
aliases and constituents, and retained debt.

Missing or invalid authority preserves the upstream candidate, severity, proof
state, or report eligibility. Report rendering may project a disposition but
must not author one.

### 3.8 RunManifestBinding

The run binding is a closed envelope over:

- run and generation identities;
- repository revision and frozen content/source snapshot;
- scope, mode, pipeline, and ecosystem set;
- driver and configuration digests;
- MethodCard catalog and compiled prompt-bundle digests;
- provider registry, provider treatment, and toolchain identities;
- backend, model/capability tier, operating system, architecture, and
  containment profile; and
- PhaseIO, WorkerTransaction, and schema-package versions.

Every semantic artifact binds this envelope directly or through an exact
transitive digest. A descriptive run label is not a binding.

### 3.9 ObligationEnvelope

The common obligation envelope contains the method/card revision, operation
and required-step IDs, exact subject, target, relation, path, boundary, and
paired-operation sets, source and methodology digests, origin and parent
obligations, materiality and uncertainty, provider capability/fidelity
requirements, application and evidence completion predicates, worker strategy,
attempt/resource policy, prerequisites, and semantic idempotency key.

An unavailable provider produces explicit capability debt and an honest
lower-bound denominator. It does not remove source-derived targets. Niche
workers receive only the selected MethodCards plus the common application and
evidence protocol; they cannot introduce a competing method definition.

### 3.10 ClaimReference

A claim is not a finding, severity, or disposition. A `ClaimReference` binds:

- `claim_id`, subject identity, and exact content digest;
- mechanism and reachability;
- preconditions and the violated or preserved invariant;
- effect, external behavior, and material harm;
- likelihood and remediation;
- evidence and premise IDs;
- confidence separated by dimension;
- issuer and execution identity; and
- predecessor and generation.

Supported mechanism with unresolved harm remains an unresolved claim. It
cannot be collapsed to safe, zero harm, or a severity decision.

### 3.11 FindingIdentity and FindingEvent

Every candidate-producing receipt names a stable candidate identity, and every
candidate has exactly one current projected state. Candidate, canonical
finding, alias/root, claim, evidence, premise, severity, and report identities
occupy separate namespaces. Content-derived identity has precedence over
display IDs. A collision between unequal content is invalid; it never merges
implicitly.

Per-domain immutable events and generations replace one universal SQL event
table. Every `FindingEvent` binds event ID, candidate/finding ID, predecessor
digest, generation, event kind, exact before and after state, decision,
evidence and premise references, issuer, and artifact digest. Current state is
a deterministic fold over one unambiguous predecessor chain. Merge and split
events retain all parents, constituents, original evidence, and consequences.
Markdown edits are never history.

### 3.12 ReportProjection

A report is a deterministic projection whose envelope binds:

- projection ID and exact authoritative input-state hash;
- the eligible finding set;
- body, tier, appendix, explicit-exclusion, and unresolved-review placement;
- alias/root membership and every affected constituent;
- severity, evidence, premise, and disposition decisions;
- method/application/coverage/debt summary;
- renderer and schema versions;
- exact output hashes; and
- set-equality and no-ship receipts.

Every eligible identity appears exactly once in body, appendix, explicit
exclusion, or unresolved review. A writer cannot add a finding, drop a
consequence, choose a disposition, or change severity.

### 3.13 Authority precedence and lifecycle adapters

Authority precedence is:

1. committed PhaseIO/WorkerTransaction execution and artifact authority;
2. domain-specific evidence, premise, lifecycle, severity, and disposition
   decisions;
3. deterministic typed projections;
4. legacy adapters and Markdown;
5. model prose and status markers.

A lower layer cannot override a higher one. Independence is proven by linked
issuer, worker, attempt, and reviewer execution identities, not role names.

| Common lifecycle | Accepted domain projections | Invalid shortcut |
|---|---|---|
| `DERIVED` | enumerated target, candidate, axis, relation, chain successor | filename or heading observed |
| `SCHEDULED` | immutable roster/work-plan membership | proposed task in prose |
| `ACTIVE` / `ATTEMPTED` | armed transaction and observed execution | child spawned or marker present |
| `SUBMITTED` | staged exact output with provisional receipt | worker says complete |
| `VALIDATED` | schema, denominator, identity, evidence, and prestate checks | parse success alone |
| `SUPPORTED` / `REFUTED` / `NOT_APPLICABLE` | independent obligation-specific decision | generic confidence |
| `FOLLOW_UP` / `RETRY` | content-addressed amendment with predecessor | anonymous extra agent |
| `INVALID` / `DEBT` | typed affected-subject failure or unknown remainder | empty set |
| `DISPOSITIONED` | committed exact decision covering every alias/constituent | report placement |

No unqualified `completed` state and no file-presence test has semantic
authority. Axis, mechanical-gate, program-facts, worker, negative-provider,
scheduler, lifecycle, and report debt are projected losslessly into one
assurance view while retaining their domain-specific records.

## 4. Compilation and execution flow

The normative flow is:

1. Freeze source, scope, configuration, methodology package, provider
   manifests, and run identity.
2. Select applicable methods from typed selectors.
3. Enumerate the exact or explicitly lower-bound subject denominator.
4. Compile obligations and stable work identities.
5. Register every input, output, receipt, and debt artifact in PhaseIO.
6. Arm the worker transaction before any model, tool, or native child begins.
7. Execute a bounded work unit against only the registered inputs.
8. Join the worker and every registered descendant before interpreting output.
9. Validate immutable inputs, output prestates, output bytes, and execution
   receipt before commit.
10. Parse producer proposals into typed application and outcome records.
11. Reconcile the obligation denominator against application receipts.
12. Route only missing, invalid, conflicted, or unknown rows to repair.
13. Route negative proposals to an independent challenge path.
14. Route positive candidates through verification and material-harm analysis.
15. Reconcile every obligation and candidate into lifecycle and final
   disposition projections.
16. Render Markdown and reports from authoritative typed artifacts.

No later phase may infer completion solely from a status marker or the presence
of a Markdown file.

## 5. Stable identity and digest rules

- Canonical JSON is UTF-8, NFC-normalized, duplicate-key rejecting,
  float-free, key-sorted, and terminated by exactly one LF.
- Paths are normalized project-relative POSIX paths in artifacts; host-native
  paths are resolved only by an authorized boundary.
- Identifiers are case-sensitive canonical strings. A portability check also
  rejects case-fold collisions where supported filesystems would alias them.
- Method, subject, obligation, attempt, application, evidence, candidate,
  disposition, and report identities occupy distinct namespaces.
- A retry reuses the obligation identity but receives a new attempt identity.
- A migration preserves predecessor identity and records the migration event;
  it does not silently rewrite history.
- A resume may reuse authority only when every transitive input and execution
  binding matches. Partial equality creates targeted invalidation or debt.

## 6. Premises and negative authority

### Premises

A premise is a closed, direction-aware record containing:

- stable premise ID, subject ID, exact normalized content, content digest, and
  premise-set digest;
- truth value, polarity, harm direction, counterfactual, and decision use;
- exact scope and affected candidate, claim, constituent, and severity IDs;
- source class, source authority, citations, and evidence IDs;
- external-research status and immutable query/result references;
- challenge state, challenger execution identity, and contradiction state;
- issuer, version, predecessor, generation, and artifact digest.

The closed source classes and maximum conversions are:

| Source class | Maximum use |
|---|---|
| `REPOSITORY_FACT` | exact only within the bound source snapshot and proof scope |
| `EXECUTED_EVIDENCE` | exact only for the executed command, oracle, inputs, and observed result |
| `CITED_EXTERNAL_FACT` | cited scope with freshness, provenance, and challenge status |
| `ASSUMED_FACT` | explicit conditional reasoning; never proof |
| `UNRESOLVED_FACT` | debt and follow-up only |
| `MODEL_HYPOTHESIS` | proposal only |
| `PROVIDER_FACT` | bounded by provider capability, precision, coverage, and receipt |

No conversion widens proof scope or turns approximate, unavailable, stale, or
unsupported evidence into exact evidence. Assertion-side adverse assumptions
and demotion-side favorable assumptions receive the same all-severity challenge
denominator.

### Disposition policy

The system uses generator/discriminator separation:

- discovery, breadth, depth, niche, static-analysis, graph, and mechanical
  generators can add candidates or evidence;
- their own scope decision cannot exclude the candidates they generated;
- a worker can propose `SAFE`, `NO_FINDING`, refutation, exclusion, merge,
  alias, zero harm, or a demotion but cannot authorize it;
- lexical confidence language and absence of output have no negative authority;
- an independent discriminator must bind the exact candidate content,
  premise set, claims, proof scope, evidence, and counterfactual used;
- unresolved disagreement remains visible and recall-open; and
- destructive decisions fall back to the upstream state when authority is
  missing, stale, malformed, contradicted, partial, timed out, unsupported,
  unreviewed, or out of scope.

A `DispositionDecision` contains decision ID and policy version; candidate,
finding, claim, alias, and constituent identities; exact candidate-content and
premise-set digests; requested effect; mechanism and harm states; before/after
proof, severity, likelihood, impact, and report state; decisive evidence and
counterfactual; issuer and independent reviewer execution identities; policy
predicate result; retained debt; predecessor; generation; and committed
transaction/artifact identities.

Impact and likelihood are evaluated separately from mechanism and proof. An
independent severity challenge is mandatory for:

- a supported mechanism with Low/Informational/zero-harm treatment;
- any downward severity change;
- a decisive favorable or external premise;
- inconsistent severities within an alias/root cluster;
- cross-contract, cross-domain, compound, or L1-composition effects;
- prose impact inconsistent with the numeric/tier decision; or
- discovery, depth, verifier, skeptic, and report-stage disagreement.

Missing challenge authority retains the higher/upstream state as contested
review debt; it does not automatically inflate severity.

### Terminal negatives

Terminal negative authority is limited to:

1. applied lossless equivalence;
2. decidable mechanical scope;
3. a complete finite domain with a decisive oracle; or
4. checked proof.

All other negative conclusions are proposals. In particular, model judgment,
bounded tests or fuzzing, a failed PoC or no witness, confidence, precedent,
trust, L1 model facts, and compound analyst conclusions are proposal-only.

The only terminal predicates are:

| Decision | Required predicate |
|---|---|
| `OUT_OF_SCOPE` | exact scope policy excludes every bound subject and constituent; no material in-scope effect remains |
| `REFUTED_FULL` | complete bound domain examined by a decisive oracle or checked proof contradicts the exact claim under every material premise |
| `ZERO_HARM` | mechanism may hold, but an independently recomputed complete harm domain proves no material affected asset/capability under the exact premise set |
| `ALIAS` | applied lossless equivalence proves the entire claim, evidence, premise, consequence, remediation, and proof-scope content is preserved by the retained identity |

Each predicate requires a registered pinned provider or checked-proof profile;
exact expected/observed set equality; no missing, duplicate, unexpected,
unknown, errored, conflicting, or unreviewed member; decisive oracle and proof
scope; and a committed replayable transaction. A named reviewer or assessor
field is not evidence.

The central negative broker is the sole production replay and decision
boundary. It recomputes the predicate or binds a second independently observed
execution. Direct callback, parser, bundle, worker, or report acceptance cannot
mint the decision. Every consumer supplies exact candidate-content and
premise-set identities; a missing binding forces retain, body, reverification,
or human review.

Compound and L1 decisions additionally bind every constituent, content digest,
premise set, verifier decision, composition formula, consequence, report
block, and the central broker decision. A terminal negative never automatically
lowers severity. Unknown, malformed, stale, partial, timed-out, conflicting,
unsupported, or unreviewed inputs retain or reopen every affected subject and
publish exact debt.

### R10 migration

R10/R10.1 is a recall-open floor against unsupported demotion, not a severity
recovery or inflation mechanism. It remains active and dual-evaluated until
the typed premise/disposition path proves exact frozen replay parity,
direction-neutral precision, fault/resume parity, and independent review.
Retirement is per consumer and cannot precede that evidence.

## 7. Boundedness and convergence

Application is obligation-driven, not finding-count-driven. Scheduling may use
uncovered obligations, axes, components, seams, evidence capabilities,
contradictions, and lifecycle debt. It must not use the number or severity of
findings as a proxy for safety or completion.

When a cap is reached:

- processed identities remain stable;
- omitted identities are persisted in deterministic order;
- the remainder receives an explicit overflow state;
- repair resumes the persisted backlog first; and
- final assurance reports the unresolved denominator.

Adaptive expansion is permitted only through the separately governed policy in
the adaptive-attention contracts. Static blanket worker-count increases are
not an architectural substitute for method application.

## 8. Failure semantics

The pipeline remains haltless only after preserving semantic truth:

- pre-side-effect authority failure blocks execution;
- post-side-effect uncertainty quarantines output;
- unavailable optional enrichment records typed debt and uses the declared
  fallback;
- malformed application evidence routes to repair;
- an unavailable discriminator retains the upstream state and flags review;
- receipt-write failure prevents canonical output authority;
- a timeout records the attempted subject and unknown remainder;
- a crash or cancellation joins or terminates descendants before retry; and
- an exact completed resume performs no model launch or semantic mutation.

There is no generic catch-all path from an exception to `CLEAR`, `SAFE`,
`COMPLETE`, or zero obligations.

## 9. Backend and ecosystem parity

Claude and Codex may use different transports, but normalized obligations,
attempts, application states, evidence capabilities, negative-authority rules,
and final lifecycle semantics are identical. Backend-specific prompt syntax is
normalized before citation and reachability checks.

Ecosystem providers may enrich the subject graph, but unsupported, partial, or
stale graph facts:

- cannot authorize a negative;
- cannot prove method application;
- cannot remove a source-derived obligation; and
- must produce explicit provider debt and fidelity metadata.

The minimum product matrix covers smart-contract and L1 pipelines; Light, Core,
and Thorough modes; EVM, Solana, Aptos, Sui, Soroban, Daml, Go L1, and Rust L1;
Claude and Codex; tool-present and tool-absent paths; clean run, crash, retry,
and exact resume.

## 10. Precision and anti-bloat

Recall-safe retention does not require a fragmented report:

- raw candidates and aliases remain immutable;
- root-cause clustering is a reversible relation, not deletion;
- distinct exploitability, affected boundary, proof scope, remediation, or
  consequence remains separately represented;
- report views may consolidate only when every member identity and consequence
  is accounted for;
- severity is calculated from typed impact and likelihood facts, then
  independently challenged; and
- unsupported inflation and unsupported demotion both create adjudication
  debt.

Report quality is evaluated separately from candidate survival.

## Typed authority storage and migration

Each domain owns one versioned closed authority schema and one reviewed
migration reader. A newer writer cannot reinterpret old bytes in place. Every
semantic mutation appends an immutable generation/event with predecessor
digest, exact before/after state, issuer, decision/evidence/premise references,
and artifact digest. Cross-artifact references are validated as one closed
identity graph before any consumer receives authority.

Migration uses a typed-sidecar strangler:

1. Continue emitting byte-compatible legacy Markdown/client/API surfaces and
   typed sidecars while legacy consumers remain.
2. Declare the legacy artifact a one-way projection or bounded adapter, never
   a competing authority.
3. Add a typed consumer, per-consumer activation receipt, and frozen
   identity/field parity row before changing its read path.
4. Prove exact identity, application, outcome, evidence, premise, severity,
   disposition, and report parity under crash, concurrency, and resume.
5. Preserve referent-less or unparseable historical records as explicit
   migration debt.
6. Move authority one consumer at a time; never perform a global cutover.
7. Retire reconciliation only after the typed path proves it preserves every
   record and consequence that recovery currently restores.

The canonical consumer parity matrix records, for every authority and
consumer, its legacy input, typed input, projection, activation generation,
identity/field equality, crash/resume result, rollback target, and independent
review receipt.

A portable export/import/replay bundle binds schemas, source/run manifest,
domain artifacts, immutable event histories, cross-reference graph,
projections, receipts, and object digests. Import validates the entire closure
before making any projection readable. JSONL may be an optional transport; it
is never authority by itself. The neutral evaluator RunBundle is evidence for
measurement and is not a backup that can restore production authority.

Byte-compatible migration surfaces include public CLI/config contracts,
checkpoint/resume inputs, required scratchpad/report filenames, and documented
machine-readable outputs until their consumers have individually cut over.
Internal Markdown prose and deterministic human projections may change only
when their stable identities, typed content, and compatibility contract remain
preserved.

## Rollback/parser retirement

Rollback is non-destructive and per authority and consumer. It restores the
prior consumer projection, retains typed artifacts and activation evidence,
records affected identities and the failed activation, and cannot grant
retroactive authority or rewrite accepted history.

A legacy parser, reconciliation path, or recovery path may retire only after
frozen identity and field parity, recall, precision, crash/fault, concurrency,
migration, and exact-resume evidence. The retirement receipt binds every
consumer and compatible surface, the replacement projection, held-out and
fault evidence, rollback procedure, and independent approval. Deleting a
parser or compatibility file without that receipt reopens migration debt.

## 12. Conformance evidence

Completion requires more than unit tests. The acceptance set includes:

- generic positive, precision no-fire, absent, malformed, stale, split,
  duplicate, contradictory, overflow, timeout, and exception fixtures;
- application/outcome orthogonality;
- producer-negative without discriminator;
- discriminator input and premise mismatch;
- alias and constituent coverage;
- source and methodology drift;
- crash at every transaction boundary;
- cancellation, timeout, process death, retry, and exact resume;
- serial and parallel execution;
- backend-normalized receipt parity;
- ecosystem and mode selection parity;
- clean checkout, source archive, installed package, read-only install, and
  Windows copy fallback;
- neutral real-run lifecycle localization and P0-P5 comparison; and
- independent review of the frozen source and evidence manifests.

A neutral grader also samples apparently clean application and negative
receipts. Sampling is stratified by method, ecosystem, phase, provider
fidelity, backend, and clean/positive control; the sample plan is frozen before
outcomes are opened. It reports false-application, false-safe, and
unsupported-negative rates with exact denominators and confidence intervals.
No subsystem may self-certify its own sample, and a clean sample cannot convert
unknown remainder to zero. Promotion budgets for these rates live only in the
neutral evaluation policy, never in prompts or runtime configuration.

A motivating audit is a regression fixture, not held-out recall evidence.
Ground truth remains forbidden from runtime inputs and becomes available only
to the neutral post-run grader.

## 13. Current migration debt

This RFC is normative but does not claim the current worktree has completed the
contract. At final freeze the implementation handoff must resolve or explicitly
retain at least:

- full driver/PhaseIO/WTx reachability for every declared consumer;
- MethodCard catalog digest binding, consumer rendering, and application
  denominator cutover;
- adaptive-attention runtime integration and equal-budget evaluation;
- mechanical-gate registry and receipt governance;
- neutral RunBundle V2 harvesting, blinding, lifecycle localization, and
  comparison;
- package and cross-OS parity; and
- a hash-stamped requirement-to-evidence crosswalk.

## 14. Requirement ownership and residual matrix

This matrix assigns the supersession-crosswalk identifiers without claiming
runtime completion. `REPRESENTED` means the normative contract exists;
`RESIDUAL` means the contract is represented but implementation or held-out
evidence remains open.

The machine-readable per-ID ownership projection is
`canonical-requirement-ownership.v1.json`. Each row binds an owner, resolvable
content anchor, and design status; each owner is bound by an LF/NFC-normalized
content digest so an empty, drifted, or substituted owner cannot satisfy the
ownership lint.

| IDs | Normative owner | Design status |
|---|---|---|
| `MA-01`–`MA-33` | this RFC, especially sections 3–12 | `REPRESENTED`; runtime consumer cutover is `RESIDUAL` |
| `GP-01`–`GP-18` | `ecosystem-graph-provider-contract.md` | `REPRESENTED`; provider rollout and cross-OS evidence are `RESIDUAL` |
| `MC-01`–`MC-14` | `methodology/method-cards-v1.yaml`; ownership rules in this RFC | `REPRESENTED`; runtime digest/render/receipt cutover is `RESIDUAL` |
| `FL-01`–`FL-16` | Typed authority storage and migration; Rollback/parser retirement | `REPRESENTED`; per-consumer parity/retirement evidence is `RESIDUAL` |
| `EV-01`–`EV-19` | `benchmarks/application-coverage-evaluation-plan.md` | `REPRESENTED`; B1 is externally blocked and user audits are `USER_RUN` |
| `WS-01`–`WS-24` | `work-unit-scheduler.md` | `REPRESENTED`; generic phase cutover is `RESIDUAL` |
| `PD-01`–`PD-22` | Premises; Disposition policy; Terminal negatives; R10 migration | `REPRESENTED`; terminal-provider and per-consumer migration are `RESIDUAL` |

The machine-checkable ownership/link lint must enumerate each individual ID,
resolve every owner and redirect anchor in a clean package, prove the two
historical notices contain no policy, and reject competing method, premise,
provider-fidelity, or worker-lifecycle authority.
