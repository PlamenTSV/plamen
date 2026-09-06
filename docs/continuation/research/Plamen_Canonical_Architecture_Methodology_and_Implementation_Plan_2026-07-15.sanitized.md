<!-- PORTABLE SANITIZED RESEARCH COPY
Source identity: Plamen_Canonical_Architecture_Methodology_and_Implementation_Plan_2026-07-15.md
Raw bytes remain outside Git. Architecture, methodology, execution, acceptance, and comparison semantics are retained; personal paths, private target identities, target-specific candidate/artifact identifiers, artifact digests, and concrete private finding descriptions use deterministic placeholders. See CORPUS_MANIFEST.json and research/PRIVATE_GAP_INDEX.json for provenance and the redaction rule.
-->

# Plamen canonical architecture, methodology, and implementation plan

**Date:** 2026-07-15  
**Status:** Canonical synthesis for independent technical review  
**Scope:** Defensive audit methodology and system architecture only  
**Repository:** Plamen smart-contract and L1 security-audit pipeline  
**Primary inspected baseline:** commit SOURCE-REVISION-004  
**R10 follow-up commits reviewed:** SOURCE-REVISION-005 and SOURCE-REVISION-002  

This document consolidates the prior architecture reviews, the deep repository and private regression target scratchpad forensic, the methodology-application and Solodit research, the completed R10 gate review, and the final implementation verdict. It is intended to be self-contained enough for an independent reviewer to grade both the diagnosis and the proposed engineering program.

It does not contain exploit code, target-specific attack instructions, or operational offensive content.

---

## 1. Executive decision

### 1.1 Build verdict

The proposed architecture is worthy of implementation and controlled testing.

The strongest evidence does not support replacing Plamen with a simpler prompt bundle, adding indiscriminate agents, or creating a large custom query language first. It supports preserving the battle-tested discovery pipeline while introducing a typed control plane underneath it:

~~~text
versioned MethodCards + typed source/relation graph
                         |
                         v
                 obligation compiler
                         |
                         v
             explicit analysis work units
                         |
                         v
                  evidence receipts
                         |
                         v
          independent verification/disposition
                         |
                         v
           append-only finding-event ledger
                         |
                         v
             deterministic report projection
~~~

This architecture directly targets the two empirically dominant miss modes:

1. **Found, then lost or incorrectly declared safe.** A candidate that enters the canonical ledger cannot disappear without an explicit, evidence-bearing lifecycle event.
2. **Methodology exists, but is not applied.** Applicable target/method pairs become enumerated obligations whose execution status is based on evidence receipts rather than worker self-description.

### 1.2 Confidence statement

The conclusions should be stated with precise boundaries:

- **High confidence:** found-then-dropped failures can be reduced close to an architectural invariant for every candidate that enters the canonical ledger.
- **High confidence:** methodology non-application can be made measurable and substantially reduced for methods and source facts represented by the obligation system.
- **Moderate-to-high confidence:** precision, root-cause consolidation, severity consistency, and report quality will improve if structured claims become canonical and prose becomes a rendered view.
- **No honest basis for certainty:** the system cannot prove that every vulnerability class is covered. Novel bugs, missing method cards, incomplete source models, unavailable external facts, and incorrect semantic judgment remain possible.

The correct claim is therefore not “all recall gaps will be closed.” It is:

> The two observed structural gap classes can be closed as control-system defects, while residual misses can be localized to methodology coverage, extractor fidelity, external evidence, or semantic judgment.

That is a material improvement over the current state, where these causes are often entangled and only recoverable through scratchpad forensics.

### 1.3 Single highest-leverage change

Build one canonical, typed, append-only lifecycle for obligations, candidates, findings, premises, evidence, dispositions, and report projections. Make every phase consume and append to this lifecycle instead of treating markdown artifacts as independent truth.

The obligation compiler and source-graph improvements are the next layer. They should not precede the canonical lifecycle because better discovery is wasted if downstream stages can still silently erase, misjoin, or misclassify it.

---

## 2. Existing review artifacts

The following documents already exist in <PRIVATE_DOWNLOADS_ROOT>:

1. **plamen_methodology_architecture_review.md**  
   Original seven-part design review covering methodology soundness, architecture, prior art, the mechanical layer, recall, precision, and blind spots.

2. **plamen-methodology-review-CLAUDE.md**  
   Independent Claude methodology and architecture review.

3. **Plamen_Deep_Forensic_Architecture_Review_2026-07-15.md**  
   Detailed driver, phase, artifact, worker-inheritance, private regression target scratchpad, report-lifecycle, and preliminary R10 forensic. This is the strongest repository-evidence document.

4. **Plamen_Methodology_Application_and_Solodit_Research_2026-07-15.md**  
   Supplemental review focused on methodology binding, skill application, markdown/regex encoding, obligation design, Solodit validation, competitor evidence, and the ranked application-improvement plan.

This canonical document supersedes those files as the recommended handoff. They remain useful as supporting review records and for checking whether this synthesis omitted or distorted an earlier observation.

### 2.1 R10 implementation artifacts

Commit 9ca8861 changed:

- CHANGELOG.md
- scripts/plamen_driver.py
- scripts/plamen_validators.py
- scripts/test_r10_demotion_gate.py

Commit 5011416 changed:

- rules/post-audit-improvement-protocol.md

The recorded validation evidence is:

- 15 of 15 focused R10 fixtures passing;
- 492 blast-radius tests passing;
- 4,502 fast-lane tests passing with zero failures;
- private regression target isolation replay firing on exactly PRIVATE-FINDING-005, PRIVATE-FINDING-006, PRIVATE-FINDING-007, and PRIVATE-FINDING-002;
- corrected hypothesis-to-inventory joining;
- idempotent external-assumption and unproven-external annotations;
- guards against cited external evidence, in-scope-grounded demotion, executed in-scope PoC outcomes, depth-refuted mechanisms, and proof-grade evidence.

The important limitation is equally explicit: R10 floors to the depth-claimed severity. In the private regression target case that was Low. It restored in-body visibility but did not restore the missed High severity. That remaining defect is depth-side harm/severity reasoning, not something the demotion gate can manufacture safely.

---

## 3. Scope, assumptions, and evidence standard

### 3.1 Reviewed system

Plamen is a deterministic, resumable, multi-phase LLM audit pipeline supporting EVM, Solana, Aptos, Sui, Soroban, Move, Daml, and Go/Rust L1 clients. A Python driver orchestrates PTY-supervised pools, single-session phases, and deterministic Python phases. Disk artifacts and markers control phase completion and resumption.

The semantic pipeline includes:

- recon and repository instantiation;
- parallel role-scoped breadth sweeps;
- optional re-scan and per-contract passes;
- inventory construction;
- semantic-invariant pre-pass;
- adaptive depth iterations with depth, blind-spot, and niche agents;
- exploration skepticism;
- chain and composition analysis;
- mandatory verification and PoC execution according to mode/risk;
- skeptic judgment;
- report indexing, tier writing, and assembly.

Under the LLM phases is a deterministic mechanical substrate:

- **BAKE providers** construct ecosystem-specific reference graphs;
- **recall generators** enumerate low-confidence gaps and candidates;
- **gates** reconcile candidate promotion, verification evidence, and report survival.

### 3.2 Governing design principles

The design commits to:

- methodology describing how to analyze rather than encoding protocol answers;
- injectable or conditional capabilities instead of universal prompt growth;
- repair-then-degrade behavior rather than global halting;
- separation between candidate generators and independent discriminators;
- proof-grade status only for executed evidence;
- recall safety over cosmetic deduplication.

These principles are directionally sound. The main defect is that several are not represented as enforceable data invariants. “Recall-safe,” “method applied,” “proof executed,” and “candidate retained” are often inferred from markdown and artifact presence rather than canonical state.

### 3.3 Evidence hierarchy

Conclusions in this document use the following hierarchy:

1. Current repository code and tests.
2. Real audit scratchpad and final-report artifacts, particularly the private regression target run.
3. Reproducible open-source competitor methodology and benchmark artifacts.
4. Official documentation for program-analysis systems and language toolchains.
5. Self-published competitor claims.
6. Private founder statements supplied by the user.

The lower two categories may guide hypotheses but do not establish comparative superiority.

### 3.4 Important assumptions

- The inspected private regression target scratchpad is representative enough to expose real lifecycle failure modes, but one audit cannot quantify their full frequency.
- The user’s estimate that roughly half of misses are false-safe dispositions and half are methodology non-application is treated as operational evidence, not a statistically validated population estimate.
- Proprietary systems such as Solace cannot be architecturally compared beyond public claims.
- The reported private semantic-query claim/private semantic-query claim direction comes from the user’s private research and founder conversation. It could not be independently verified from public technical material and is therefore not treated as a public fact.

---

## 4. Priority findings

### P0-1 — Candidate and finding lifecycle is not truly closed

Multiple markdown artifacts, IDs, routers, harvesters, verifier outputs, indexes, and report files can represent the same underlying issue. Reconciliation exists, but it is reconciliation among lossy projections rather than transactions over one source of truth.

Consequences:

- a discovered mechanism can be absent from a later queue;
- identifiers can drift between hypothesis and inventory namespaces;
- a demotion can be recorded without its decisive premise being represented;
- report assembly can omit an issue even though an earlier artifact contains it;
- resume behavior can preserve a stale downstream interpretation;
- duplicate handling can accidentally merge distinct consequences or delete the stronger formulation.

The private regression target PRIVATE-FINDING-001/PRIVATE-FINDING-005 lifecycle is direct evidence that this is not theoretical.

### P0-2 — The same semantic record is repeatedly reconstructed from prose

Regex and markdown parsers recover severity, identifiers, verification claims, external assumptions, and relationships after agents have serialized them into prose.

This is fragile because:

- formatting variance looks like semantic variance;
- absent syntax is confused with absent analysis;
- new wording can silently bypass a gate;
- identifiers are joined heuristically;
- test fixtures can validate recognized phrases without validating the underlying decision;
- resume invalidation has no precise dependency graph.

Markdown is suitable for human-readable explanation. It is unsuitable as the transactional database or type system of an audit pipeline.

### P0-3 — Live breadth methodology binding is weaker than the repository suggests

The live breadth worker treats prompts/shared/v2/phase3-breadth.md as vulnerability coverage, even though that document is primarily coordinator, spawning, and output protocol. Actual vulnerability methodology depends on recon-selected skill routing.

This makes recon routing a single point of failure for breadth recall. A rich skill library does not create coverage if the work unit does not bind an exact skill version and applicable target set.

### P0-4 — Skill execution is inferred rather than observed

The current skill-checking approach can ask an LLM to recall steps from a skill name and infer that those steps were performed from narrative output. In the private regression target artifacts, an implausibly perfect execution summary was produced without hard, direct binding between:

- the exact skill content/version;
- the targets to which it applied;
- each required step;
- source or artifact evidence;
- unresolved or inapplicable steps.

This directly explains a major part of the methodology non-application problem.

### P0-5 — False-safe reasoning is not represented as a first-class object

Verification can dismiss or downgrade a candidate by relying on an unstated or weakly researched favorable premise. The current system records the verdict more strongly than it records the premise that caused the verdict.

R10 repairs one external-assumption subtype, but the general problem includes:

- favorable environmental behavior;
- trusted governance or operator action;
- assumed atomicity or sequencing;
- assumed liquidity, liveness, or market behavior;
- assumed integrator conformance;
- assumed ledger, runtime, or dependency stability;
- assumed user behavior;
- assumed deployment configuration.

Every safety-bearing premise must be explicit, sourced, challenged, and assigned a confidence state.

### P0-6 — Severity is allowed to control whether skepticism occurs

If a candidate is initially underrated, severity-conditioned verification or skeptic coverage can preserve the underrating. This creates a circular failure:

~~~text
weak initial harm model
        |
        v
low severity
        |
        v
less independent challenge
        |
        v
low severity survives
~~~

Mechanism confirmation and harm assessment must be separable. A confirmed mechanism with unresolved external or compositional harm should receive targeted harm analysis regardless of its provisional severity label.

### P1-1 — Semantic stages are mixed with execution shards

The phase model contains many implementation-specific shard objects that behave like phases. This complicates dependency tracking, resume invalidation, observability, and reasoning about whether a semantic stage actually completed.

The architecture should distinguish:

- a small semantic stage graph;
- dynamically scheduled work units within each stage;
- workers that lease those work units;
- artifacts/evidence attached to the work units.

### P1-2 — Fixed phase order is weaker than obligation-driven convergence

The current pipeline can add iterations, re-scans, and niche agents, but its high-level sequence remains fixed. Real audit work is not strictly linear: unresolved invariants, new relations, external research, or a verifier’s challenge should be able to create new scoped obligations.

The desired scheduler converges when:

- all material obligations are resolved;
- remaining unresolved obligations are explicitly degraded to human review;
- budget or iteration limits are recorded as coverage limitations.

### P1-3 — Composition is too pairwise and pre-filter constrained

Pairwise chain candidates selected before full relation expansion miss paths involving:

- three or more state transitions;
- time/order dependence;
- privilege or capability movement;
- shared accounting variables;
- cross-domain messages;
- callbacks and asynchronous completion;
- configuration changes followed by ordinary operations;
- dependency assumptions used at multiple sites.

Composition should be graph-driven and capable of bounded multi-hop enumeration, with the LLM judging semantic exploitability and material harm.

### P1-4 — Current mechanical obligations are a prototype, not a compiler

The present security-obligation output uses a small set of regex-derived classes and produces useful telemetry. It does not yet establish:

- the full target universe;
- applicability criteria per method;
- target/method coverage;
- evidence quality;
- relation coverage;
- graph fidelity;
- convergence.

It should be retained as a prototype and migrated into typed obligations rather than expanded indefinitely through prose patterns.

### P1-5 — Universal methodology is duplicated and uneven

Generic reasoning appears across ecosystem skills, niche prompts, depth roles, shared rules, and injected sidecars. This creates drift and increases the chance that one ecosystem or execution path receives a weaker version.

The universal semantic kernel should be represented once as versioned method cards. Ecosystem adapters should define source facts, target types, and applicability—not duplicate the full generic reasoning method.

### P2 — Shared source workspace creates reproducibility and isolation risk

Workers operating against a shared mutable repository may observe or produce different states. Even if agents are instructed not to edit source, tools, generated files, test artifacts, or builds can interfere.

Work units that execute tests or instrument code should receive isolated worktrees or containers. Read-only analysis may share a content-addressed snapshot.

---

## 5. Root-cause model for the observed misses

The user’s 50/50 operational split should be decomposed further so changes can be measured.

### 5.1 Discovery-side miss taxonomy

A ground-truth issue is never represented as a candidate because:

1. **Method absent:** no current method describes the relevant reasoning.
2. **Applicability failure:** method exists but the system does not determine that it applies.
3. **Scheduling failure:** applicable method is not assigned to a work unit.
4. **Binding failure:** worker receives an orchestration prompt but not the required methodology.
5. **Execution failure:** worker receives it but skips or incompletely performs steps.
6. **Evidence capture failure:** reasoning occurs but is not written into the required artifact.
7. **Graph failure:** necessary target, relation, or effect is missing or wrong.
8. **Semantic judgment failure:** method is applied to the correct facts but the model reaches the wrong conclusion.
9. **Exploration stopping failure:** worker stops before resolving a promising branch.

The obligation system directly addresses items 2 through 6 and makes item 7 observable. It does not automatically solve items 1, 8, or 9.

### 5.2 Pipeline-loss miss taxonomy

A candidate exists but does not survive because:

1. it is not harvested into the canonical queue;
2. its identifier changes or is joined incorrectly;
3. anti-absorption or grouping loses a constituent;
4. a verifier dismisses it using an unsupported premise;
5. provisional severity prevents deeper review;
6. PoC execution status is inferred incorrectly;
7. deduplication merges distinct mechanisms or consequences;
8. report indexing omits it;
9. report tiering or assembly filters it;
10. resume reuses stale downstream state;
11. malformed artifacts trigger a silent no-op;
12. human-review degradation is not visible in the final deliverable.

A canonical event ledger, premise model, report projection, and dependency-aware resume can make all twelve detectable and most mechanically preventable.

### 5.3 Why more prompting alone is insufficient

Prompt improvements can reduce execution and judgment failures, but cannot reliably enforce:

- uniqueness or stable identity;
- append-only history;
- relational integrity;
- dependency invalidation;
- exact target enumeration;
- structured premise provenance;
- report completeness;
- cross-phase state invariants.

Those are software architecture responsibilities.

---

## 6. Methodology soundness

### 6.1 What is sound

The discover, independently verify, challenge, and report shape is fundamentally appropriate for defensive smart-contract auditing.

Strengths worth retaining:

- multiple independent discovery perspectives;
- adaptive depth and niche activation;
- mandatory execution for proof-grade claims;
- mechanical recall generators that cannot directly assert findings;
- verifier and skeptic separation;
- explicit Impact × Likelihood severity framing;
- cross-contract and composition analysis;
- deterministic phase orchestration and resumability;
- low-confidence mechanical candidates routed through normal verification;
- haltless degradation rather than throwing away the entire audit.

### 6.2 Structural problems in the present shape

The pipeline has generator/discriminator separation at the agent-role level but not complete separation at the claim level. A verifier can simultaneously:

- reinterpret the mechanism;
- decide whether a test was adequate;
- introduce favorable assumptions;
- judge impact;
- assign severity;
- decide final survival.

That is too much semantic authority in one prose artifact.

The improved model separates:

1. mechanism claim;
2. reachability/precondition claim;
3. invariant violation;
4. observable effect;
5. external premises;
6. harm claim;
7. likelihood;
8. severity;
9. evidence strength;
10. final disposition.

Each can be independently supported, disputed, or left unresolved.

### 6.3 Whole classes under-served by the current pipeline

The present architecture is comparatively weaker at:

- multi-step, multi-contract, and multi-domain compositions;
- temporal and asynchronous behavior;
- cross-transaction state machines;
- economic and incentive failures requiring scenario comparison;
- liveness/resource exhaustion under adversarial scheduling;
- deployment, upgrade, initialization, feature-flag, and build-configuration behavior;
- runtime semantics hidden by macros, generated code, or compiler lowering;
- governance and operational processes outside source;
- external dependency semantics;
- concurrency, finality, reorganization, and replay behavior in node clients;
- cryptographic/serialization mismatches across implementations;
- emergent failures requiring three or more otherwise-safe components.

Some can be improved mechanically through better facts and relation enumeration. Others require external specifications, simulation, formal properties, or model judgment.

### 6.4 PoC execution is necessary but not sufficient

Executed tests raise evidence quality, but “a PoC ran” is not equivalent to “the decisive claim was tested.”

The system must bind a PoC receipt to:

- the exact claim or premise under test;
- repository/source revision;
- build configuration;
- command and environment;
- test selector;
- observed assertions;
- outcome;
- coverage or trace evidence when available;
- limitations and unmodeled conditions.

A test that executes but never reaches the relevant state must not upgrade proof confidence.

### 6.5 Haltless behavior needs semantic states

Repair-then-degrade is sound only if degradation remains visible and cannot be mistaken for success.

Every obligation and finding should support states such as:

- resolved-supported;
- resolved-refuted;
- resolved-not-applicable;
- unresolved-artifact-failure;
- unresolved-tool-failure;
- unresolved-external-fact;
- unresolved-budget-exhausted;
- unresolved-model-disagreement;
- human-review-required.

The audit can continue, but the report and coverage summary must expose unresolved material work.

---

## 7. Is the methodology complete?

No methodology can be proven to cover every possible vulnerability class. Solodit, professional reports, benchmark suites, and competitor systems contain only vulnerabilities that somebody discovered or deliberately seeded.

The correct goal is a methodology that is:

- semantically broad;
- compact enough to apply reliably;
- mechanically instantiated against the codebase;
- extensible without prompt duplication;
- measurable at the target/method level;
- continuously tested against post-cutoff evidence;
- able to identify unmodeled target or relation classes.

### 7.1 Universal semantic kernel

Rather than hundreds of always-on vulnerability labels, use a compact set of semantic operators. A practical initial kernel is:

1. **Authority and capability:** who can cause a transition, directly or transitively?
2. **Value and accounting conservation:** what enters, leaves, accrues, is owed, or can become unbacked?
3. **State-transition legality:** which states and transitions exist, and which transitions must be impossible?
4. **Lifecycle and ordering:** what happens before initialization, after closure, during upgrade, or under reordered actions?
5. **Boundary and numerical behavior:** zero, one, maxima, minima, rounding direction, truncation, precision, overflow domains, and discontinuities.
6. **Symmetry and reversibility:** do paired operations, mirrored branches, and inverse transitions preserve equivalent properties?
7. **Identity and domain separation:** are subjects, assets, modules, chains, epochs, nonces, and serialized messages bound to the intended domain?
8. **External interaction and assumption:** what behavior is trusted across calls, runtimes, or services, and what if it is delayed, malformed, adversarial, or merely different?
9. **Availability and resource control:** can progress, cleanup, execution, storage, or consensus be prevented or made uneconomic?
10. **Configuration, governance, and upgrade:** how can mutable policy change ordinary safety properties?
11. **Composition and shared-state interference:** which individually valid operations interact through shared state or dependency paths?
12. **Concurrency, finality, and replay:** what changes under concurrent execution, retries, forks, reordering, replay, or partial completion?

Cryptographic, serialization, language-runtime, and ecosystem-specific methods should be conditionally injected underneath these operators when relevant.

### 7.2 MethodCard design

Each method should be a versioned record rather than only a prompt paragraph.

Illustrative schema:

~~~yaml
method_id: value.conservation.v1
title: Value and accounting conservation
method_version: 1.0.0
semantic_operator: value_accounting
applies_to:
  node_kinds: [function, entrypoint, instruction, choice]
  required_capabilities: [symbols, writes, reads]
  optional_capabilities: [call_graph, value_flow, storage_layout]
target_selector:
  effects_any: [asset_transfer, balance_write, supply_write, debt_write]
relation_selectors:
  - reads_same_state
  - writes_same_state
  - calls
required_steps:
  - identify value sources and sinks
  - derive local and aggregate conservation equations
  - enumerate boundary and failure paths
  - compare paired operations
required_receipts:
  - targets_examined
  - invariants_considered
  - evidence_locations
  - unresolved_assumptions
completion_policy:
  allow_not_applicable: true
  material_unresolved_requires_human_review: true
prompt_fragment: prompts/methods/value-conservation.md
~~~

The method card says how to analyze. It does not encode a protocol-specific expected bug.

### 7.3 Application versus judgment

The architecture must distinguish:

- **Application coverage:** Was the method correctly instantiated and executed against the applicable targets?
- **Finding correctness:** Did the worker interpret the result correctly?

The first is largely an engineering/control problem and can be improved substantially. The second remains a semantic reasoning problem requiring redundancy, evidence, tools, and independent challenge.

---

## 8. Prior art and what should be borrowed

### 8.1 Human audit practice

Leading human audits combine architecture understanding, line-by-line review, threat modeling, adversarial scenario construction, tooling, tests, discussion with developers, and iterative reconciliation. OpenZeppelin describes audits as more than automated issue detection and emphasizes contextual analysis, communication, and remediation. Trail of Bits similarly combines manual assurance with static and dynamic analysis.

What Plamen should borrow:

- explicit architectural and trust-boundary models;
- auditor-owned invariants;
- repeated cross-checking by independent reviewers;
- live uncertainty tracking;
- developer questions as first-class unresolved evidence;
- final reconciliation against every review note, not only promoted findings.

Sources:

- https://www.openzeppelin.com/news/what-is-a-smart-contract-audit-lessons-from-openzeppelins-1000-audits
- https://www.trailofbits.com/services/software-assurance

### 8.2 CodeQL

CodeQL represents code as queryable data and supports alert, path, diagnostic, and metric queries, with language libraries for dataflow, control flow, and taint tracking.

What Plamen should borrow:

- stable rule/method identities;
- structured source facts rather than textual reconstruction;
- explicit path and evidence outputs;
- versioned query/method packs;
- query coverage and diagnostics.

What CodeQL cannot supply alone:

- protocol-specific economic intent;
- unstated invariants;
- material-harm judgment;
- external operational facts;
- full business-logic composition.

Source: https://codeql.github.com/docs/writing-codeql-queries/about-codeql-queries/

### 8.3 Code-property graphs and Joern

Joern’s CPG combines syntax, control flow, and intra-procedural dataflow into a typed graph and provides traversal/dataflow operations across language frontends.

What Plamen should borrow:

- one normalized graph contract;
- overlays for progressively richer facts;
- bounded multi-hop relation queries;
- provider capability metadata;
- graph queries that enumerate candidates while leaving semantic judgment to agents.

Sources:

- https://docs.joern.io/code-property-graph/
- https://docs.joern.io/cpgql/data-flow-steps/

### 8.4 Declarative policy systems

OPA separates policy decision from enforcement and evaluates declarative rules over structured data.

What Plamen should borrow:

- declarative obligation and gate predicates;
- explicit input/output contracts;
- testable policy bundles;
- policy versioning independent of the driver.

Plamen does not need to adopt Rego immediately. Typed Python predicates or SQL are sufficient until the method schema stabilizes.

Source: https://www.openpolicyagent.org/docs

### 8.5 SARIF

SARIF provides machine-readable rules, locations, fingerprints, code flows, and result metadata for static-analysis findings.

What Plamen should borrow:

- stable rule and result identities;
- structured locations and traces;
- partial fingerprints for cross-run continuity;
- separation between rule metadata and result instances;
- portable result serialization.

Source: https://docs.github.com/en/code-security/concepts/code-scanning/sarif-files

### 8.6 OpenRewrite

OpenRewrite uses versioned, composable recipes over semantic program representations.

What Plamen should borrow:

- small composable methods;
- declarative applicability;
- versioned catalogs;
- separation between generic recipes and language-specific adapters.

Source: https://docs.openrewrite.org/concepts-and-explanations/recipes

### 8.7 Static analysis, symbolic execution, formal verification, and fuzzing

These tools offer guarantees or search capabilities an LLM pipeline cannot reproduce through prose:

- static analyzers enumerate syntactic and semantic patterns consistently;
- symbolic execution searches path conditions;
- formal verification checks explicit properties across modeled states;
- fuzzers explore runtime behavior and can minimize counterexamples;
- mutation testing checks whether properties actually detect controlled defects.

Plamen should orchestrate these as evidence providers, not try to emulate them through agents.

Relevant sources:

- Slither: https://github.com/crytic/slither
- Echidna: https://github.com/crytic/echidna
- Certora invariants: https://docs.certora.com/en/latest/docs/cvl/invariants.html
- Certora mutation testing: https://docs.certora.com/en/latest/docs/prover/checking/mutation.html
- Solidity SMTChecker: https://docs.soliditylang.org/en/latest/smtchecker.html

### 8.8 LLM audit systems and competitor claims

Publicly inspectable systems demonstrate several viable patterns:

- Pashov’s public skill system uses a much smaller multi-agent bundle with shared reasoning methods and specialist seam hunters.
- Krait describes tailored checks backed by Solodit references and publishes methodology material.
- Grego publicly claims AST/IR, call/dataflow, and invariant-oriented analysis.
- EVMbench demonstrates both the current potential and incompleteness of frontier coding agents on real audit findings, including early stopping and partial detection.

Useful implications:

- compact methods can outperform bloated checklists when actually applied;
- structured program representations matter;
- multiple independent agents do not by themselves prove coverage;
- benchmark design and stopping behavior are as important as raw model choice;
- public percentages without run artifacts, leakage controls, and failure-level outputs are not sufficient evidence.

Sources:

- https://github.com/pashov/skills
- https://www.pashov.com/solidity-auditor-v3
- https://github.com/ZealynxSecurity/krait/blob/main/METHODOLOGY.md
- https://grego.ai/
- https://openai.com/index/introducing-evmbench/
- https://github.com/paradigmxyz/evmbench

### 8.9 private semantic-query claim/private semantic-query claim interpretation

No public technical source located during this review established the exact private semantic-query claim/private semantic-query claim architecture described by the user. If the private information refers to a CodeQL-like semantic query layer, it validates only part of the recommended direction:

- a query layer improves fact and relation enumeration;
- it does not enforce methodology execution;
- it does not provide a candidate lifecycle;
- it does not challenge favorable premises;
- it does not determine material harm.

The strongest design is hybrid: compiler-derived facts and queries for enumeration, explicit obligations for application, LLM/tool workers for semantic analysis, and a typed ledger for disposition.

---

## 9. Mechanical derivation and gates

### 9.1 General verdict

Converting recurring, enumerable recall misses from prose instructions into deterministic generators or gates is sound when the rule operates over reliable artifacts and does not claim semantic certainty.

The mechanical layer helps most with:

- set reconciliation;
- coverage gaps;
- missing pairings;
- unmatched identifiers;
- boundary enumeration;
- co-reference and shared-state relationships;
- symmetry differences;
- unexecuted proof claims;
- report survival;
- unresolved premise detection;
- stale dependency detection.

### 9.2 When it becomes theater

A mechanical gate is theater when:

- it parses flexible prose without a typed semantic source;
- its input artifact is itself an unverified model assertion;
- “no match” is treated as safety rather than parser uncertainty;
- it claims a method was applied from section headings;
- it adds more sidecar state without establishing a canonical record;
- it encodes protocol-specific wording;
- its fixtures validate phrases rather than semantic relationships;
- it duplicates logic that should be a schema invariant.

### 9.3 Mechanization qualification test

A recurring miss should become a deterministic rule only if all of the following hold:

1. **Enumerability:** inputs and expected relation can be mechanically enumerated.
2. **Artifact sufficiency:** the necessary facts already exist or can be derived reliably.
3. **Judgment independence:** firing does not require a new semantic security judgment.
4. **Genericity:** the rule is protocol-independent and reusable.
5. **Monotonic safety:** the rule creates work, preserves visibility, or constrains unsupported disposition; it does not assert a vulnerability.
6. **Verification routing:** any security conclusion still passes independent verification.
7. **Observable failure:** unavailable or malformed inputs produce a coverage flag, not false success.
8. **Benchmarkability:** positive and precision no-fire fixtures can be defined.

The Part-2.5/3a RC-AGENT-MECHANIZABLE carve-out moves in this direction. The qualification test above should be the canonical contract.

### 9.4 R10 assessment

R10 is a good narrow gate because it:

- uses a confirmed or partial depth mechanism as an anchor;
- detects an external favorable premise used in demotion;
- checks for cited external grounding and research-ledger evidence;
- preserves the candidate for verification/human review;
- does not manufacture a new finding;
- is protected by positive and no-fire fixtures.

R10 is not the complete solution because:

- the external-best-case concept is still partly recognized from prose cues;
- it applies post-verification;
- it floors only to the existing depth severity;
- it does not correct depth-side harm modeling;
- a family of R11/R12/R13 regex gates would recreate the current fragmentation.

The migration target is a generic premise/disposition policy over typed records. R10 should remain active until that replacement demonstrates equivalent replay behavior.

---

## 10. Target architecture

### 10.1 Architectural principles

The target should preserve Plamen’s deterministic driver while changing what the driver considers authoritative.

1. **One canonical state store.** Markdown files are views and evidence attachments, not competing databases.
2. **Append-only semantic history.** Changes in belief are events. Previous states remain inspectable.
3. **Stable identities.** Methods, source entities, obligations, claims, candidates, findings, premises, evidence, and clusters have stable IDs.
4. **Content-addressed provenance.** Every derived object records the source revision, graph version, method version, prompt version, model/tool version, and parent inputs.
5. **Idempotent work.** A work unit can be retried without duplicating semantic state.
6. **Explicit uncertainty.** Tool failure, parse failure, missing external facts, and budget exhaustion are states, not absence.
7. **Report as projection.** Final markdown is rendered from canonical finding state plus human-readable narratives.
8. **Capability-aware scheduling.** Methods declare graph/tool requirements; providers declare fidelity; the scheduler chooses precise, approximate, or human-review paths.
9. **No protocol-answer encoding.** Deterministic components enumerate facts, targets, relations, and lifecycle consistency. Semantic vulnerability conclusions remain evidence-tested.
10. **Incremental migration.** Existing phases and artifacts dual-write into the new model until parity tests pass.

### 10.2 Control plane and data plane

Separate two concerns that are currently mixed.

**Control plane**

- run configuration and mode;
- semantic stage graph;
- work-unit queue and leases;
- retries and budgets;
- dependency invalidation;
- capability/fidelity routing;
- stage convergence;
- human-review escalation.

**Data plane**

- source snapshot and build metadata;
- graph facts;
- method cards;
- obligations;
- evidence receipts;
- claims and premises;
- candidates and finding events;
- PoC/tool results;
- clusters and report projections.

Worker processes should communicate through typed records and immutable artifact references, not by discovering each other’s markdown files.

### 10.3 Semantic stage graph

Retain a small number of meaningful stages:

1. **Acquire and model:** source snapshot, build configurations, ecosystem providers, architecture and trust facts.
2. **Enumerate obligations:** instantiate generic and ecosystem methods against graph targets and relations.
3. **Discover:** breadth/depth/niche/tool work units generate claims and candidates.
4. **Expand:** unresolved claims generate composition, external-research, invariant, or scenario obligations.
5. **Verify and challenge:** execute tests/tools, challenge premises, and assess mechanism/harm.
6. **Reconcile:** enforce lifecycle completeness, root-cause clustering, severity consistency, and unresolved-work policy.
7. **Render:** produce report, coverage appendix, unresolved-review appendix, and machine-readable export.

Recon, breadth roles, per-contract passes, blind-spot scanners, and niche agents become work-unit strategies inside these stages rather than separate sources of truth.

### 10.4 Work-unit scheduler

Each work unit should include:

- immutable run/source snapshot ID;
- semantic stage;
- exact method-card ID and version;
- exact target IDs and relation/path IDs;
- required inputs and artifact hashes;
- graph capabilities and fidelity;
- worker role/model/tool policy;
- output schema;
- materiality and priority;
- retry/budget policy;
- parent obligation and reason for scheduling;
- exclusive output namespace.

Workers lease units. Completion requires a schema-valid receipt. A status marker without a receipt is not semantic completion.

### 10.5 Storage layout

Use a small transactional database, preferably SQLite initially, plus an immutable artifact directory.

**SQLite should contain**

- identities and relationships;
- lifecycle events;
- status and dependency indexes;
- structured claims, premises, severity, and evidence references;
- work-unit leasing and idempotency keys;
- graph-provider manifests;
- report inclusion decisions.

**Artifact storage should contain**

- full markdown reasoning;
- source extracts;
- tool logs;
- PoC code and execution logs;
- traces and coverage;
- external research captures;
- generated reports.

Large artifacts are referenced by content hash. The database should not require the full prose body to enforce lifecycle invariants.

### 10.6 Why SQLite first

SQLite provides transactions, foreign keys, unique constraints, indexes, migrations, and straightforward local portability. It is materially safer than inventing an event store from flat files and much simpler than deploying a service database.

JSONL can be retained as an append-only export and recovery format. It should not be the only authoritative store if concurrent workers write events.

---

## 11. Canonical data contracts

The schemas below are illustrative. Exact field names can change, but the semantic separations should not.

### 11.1 RunManifest

~~~yaml
run_id: run-uuid
source_snapshot_id: sha256
repository_uri: local-or-remote-reference
commit: git-commit-or-content-hash
mode: thorough
ecosystems: [soroban, rust]
driver_version: git-commit
method_catalog_version: sha256
prompt_bundle_version: sha256
provider_manifests: [provider-manifest-id]
toolchains:
  rustc: version-and-hash
  cargo: version-and-hash
host:
  os: windows
  execution_backend: native-plus-wsl
created_at: timestamp
~~~

### 11.2 GraphProviderManifest

~~~yaml
provider_id: rust-mir-provider
provider_version: 1.0.0
ecosystem: rust
toolchain: rustc-version
source_snapshot_id: sha256
build_matrix:
  targets: [x86_64-pc-windows-msvc, x86_64-unknown-linux-gnu]
  features: [default, production]
capabilities:
  symbols: precise
  types: precise
  call_graph: partial
  control_flow: precise
  read_write_effects: precise
  macro_expansion: precise
  cross_crate_calls: partial
  generated_code: partial
limitations:
  - dynamic dispatch has conservative targets
  - optional feature set X did not build
artifact_hashes: [...]
~~~

Capability values should use a controlled vocabulary such as precise, conservative, approximate, unavailable, and failed.

### 11.3 SourceEntity and GraphFact

~~~yaml
entity_id: stable-source-entity-id
kind: function
qualified_name: crate::module::function
location:
  file: src/module.rs
  start_line: 120
  start_column: 1
  end_line: 168
  end_column: 2
symbol_identity:
  provider: rustc
  provider_symbol: opaque-id
attributes: {...}
provenance:
  provider_manifest_id: ...
  confidence: precise
~~~

Graph facts should be typed edges or properties:

~~~yaml
fact_id: fact-uuid
predicate: writes_state
subject_id: function-id
object_id: storage-field-id
qualifiers:
  conditional: true
  path_class: error-branch
provenance:
  provider_manifest_id: ...
  evidence_artifact: ...
~~~

The graph contract should support layered overlays so a parser, compiler, static analyzer, and LLM-derived architecture model can contribute facts with distinct provenance and confidence.

### 11.4 Obligation

~~~yaml
obligation_id: obl-uuid
method_id: value.conservation.v1
method_version: 1.0.0
target_ids: [function-a, storage-b]
relation_ids: [fact-1, fact-2]
source_snapshot_id: sha256
origin:
  kind: method_compiler
  parent_obligations: []
priority:
  materiality: high
  uncertainty: medium
required_capabilities:
  reads: precise-or-conservative
status: scheduled
completion_requirement:
  receipt_kinds: [analysis]
  independent_review: false
idempotency_key: sha256-of-semantic-inputs
~~~

### 11.5 EvidenceReceipt

~~~yaml
receipt_id: receipt-uuid
obligation_id: obl-uuid
work_unit_id: work-uuid
worker:
  role: depth-accounting
  model: model-id
  prompt_hash: sha256
method_binding:
  method_id: value.conservation.v1
  method_hash: sha256
targets_examined: [function-a, function-c]
steps:
  identify_sources_sinks:
    status: completed
    evidence_refs: [artifact-location]
  derive_equations:
    status: partial
    evidence_refs: [artifact-location]
    limitation: aggregate supply defined externally
outcome: candidate_generated
candidate_ids: [candidate-uuid]
unresolved_premises: [premise-uuid]
artifact_hash: sha256
schema_valid: true
~~~

A receipt is not automatically truthful. It makes the claim of execution explicit and auditable. Mechanical checks and independent samplers can compare receipts with artifacts and source coverage.

### 11.6 Claim

Candidates should be decomposed into typed claims:

~~~yaml
claim_id: claim-uuid
claim_type: mechanism
statement: structured-short-description
subjects: [entity-id]
parents: []
status: supported
confidence: 0.78
evidence_refs: [receipt-id, tool-result-id]
counterevidence_refs: []
author: worker-or-gate-id
~~~

Useful claim types include:

- mechanism;
- reachability;
- precondition;
- invariant;
- state/economic effect;
- external behavior;
- material harm;
- likelihood;
- remediation.

### 11.7 Premise

~~~yaml
premise_id: premise-uuid
statement: external component remains stable for the relevant interval
scope: external_dependency
polarity:
  effect_if_true: reduces_harm
  effect_if_false: increases_harm
source_class: assumed
evidence_refs: []
research_status: not_researched
challenge_status: required
used_by_decisions: [decision-uuid]
~~~

Premises should be direction-aware. The system must guard both:

- assertions of harm based on an unsupported adverse premise; and
- dismissal of harm based on an unsupported favorable premise.

### 11.8 Candidate and Finding

Use one stable semantic record with evolving status rather than converting between unrelated document IDs.

~~~yaml
finding_id: finding-uuid
origin_candidate_ids: [candidate-a, candidate-b]
root_cause_cluster_id: cluster-uuid
mechanism_claim_ids: [...]
harm_claim_ids: [...]
premise_ids: [...]
affected_entities: [...]
status: verified_inconclusive_external
severity:
  impact: high
  likelihood: medium
  final: high
  confidence: medium
  rationale_claim_ids: [...]
report_disposition: body
~~~

Human-friendly labels such as PRIVATE-FINDING-001 can remain display IDs. They should not be join keys.

### 11.9 FindingEvent

~~~yaml
event_id: event-uuid
finding_id: finding-uuid
event_type: verification_disposition
previous_state: verification_pending
new_state: verified_inconclusive_external
actor: verifier-worker-id
reason_claim_ids: [...]
premise_ids: [...]
evidence_refs: [...]
created_at: timestamp
idempotency_key: sha256
~~~

No stage edits history. It appends a new event. Current state is a deterministic fold over validated events.

### 11.10 DispositionDecision

~~~yaml
decision_id: decision-uuid
finding_id: finding-uuid
decision: downgrade
from_severity: high
to_severity: low
mechanism_status: supported
decisive_claims: [...]
decisive_premises: [premise-uuid]
evidence_refs: [...]
counterfactual:
  if_premise_false: high-harm-remains-plausible
independent_challenge: required
policy_result: veto_pending_external_research
~~~

R10’s eventual replacement should operate on records like this.

### 11.11 RootCauseCluster

~~~yaml
cluster_id: cluster-uuid
canonical_mechanism_claims: [...]
shared_state_entities: [...]
shared_preconditions: [...]
member_findings: [...]
consequences:
  - harm-claim-a
  - harm-claim-b
merge_confidence: high
human_review_required: false
~~~

Clustering should preserve multiple consequences and affected components. It should never destroy member records.

### 11.12 ReportProjection

~~~yaml
projection_id: report-v1
run_id: run-uuid
included_findings: [...]
appendix_findings: [...]
unresolved_review_items: [...]
excluded_findings:
  - finding_id: ...
    disposition_decision_id: ...
coverage_summary:
  obligations_total: ...
  resolved: ...
  unresolved_material: ...
renderer_version: ...
source_state_hash: ...
~~~

The promotion-completeness gate becomes a database invariant plus a report-projection reconciliation query.

---

## 12. Lifecycle state machines and invariants

### 12.1 Obligation lifecycle

~~~text
derived
  |
  v
scheduled --> leased --> receipt_submitted --> validated
   |            |               |                 |
   |            |               |                 +--> resolved_supported
   |            |               |                 +--> resolved_refuted
   |            |               |                 +--> resolved_not_applicable
   |            |               |                 +--> unresolved_followup
   |            |               |
   |            |               +--> rejected_invalid_receipt --> rescheduled
   |            |
   |            +--> lease_expired --> rescheduled
   |
   +--> degraded_human_review
~~~

“Completed” should not exist as an unqualified semantic state.

### 12.2 Finding lifecycle

~~~text
candidate
  |
  v
triaged --> verification_pending --> mechanism_supported
  |                    |                    |
  |                    |                    +--> harm_supported
  |                    |                    +--> harm_inconclusive
  |                    |                    +--> external_fact_unresolved
  |                    |
  |                    +--> mechanism_refuted
  |                    +--> test_inconclusive
  |
  +--> non_material_recorded

Any terminal semantic state
  |
  v
report_body | report_appendix | excluded_with_decision | human_review
~~~

The exact states can be simplified, but mechanism, harm, evidence, and report inclusion must not collapse into one label.

### 12.3 Required hard invariants

1. Every candidate-producing receipt references at least one stable finding/candidate record.
2. Every candidate has a current lifecycle state.
3. Every dismissal, downgrade, merge, split, or exclusion has an explicit decision event.
4. Every decision references evidence and any decisive premises.
5. No report body/index/tier entry exists without a canonical finding.
6. Every report-eligible finding is included, appended, or explicitly excluded.
7. A merge never deletes member records.
8. A split records parentage and preserves the original evidence.
9. Proof-grade status requires a valid execution receipt bound to the decisive claim.
10. Missing or malformed evidence cannot produce proof-grade or safe-dismissal status.
11. Unresolved material obligations appear in the coverage or human-review output.
12. Resume cannot reuse a result whose semantic input hash changed.
13. Display IDs are never relational join keys.
14. Provider fidelity is propagated into obligation and evidence confidence.
15. A worker cannot be its own required independent challenger.
16. Report rendering is deterministic from a fixed canonical state hash.

### 12.4 Resume and invalidation

Every derived object should have a semantic input hash covering:

- source snapshot;
- build configuration;
- graph-provider version and facts used;
- method-card version;
- prompt version;
- relevant parent claims/evidence;
- tool/model policy where outcome comparability depends on it.

When an input changes, descendants are marked stale through recorded dependencies. Resumption schedules only invalidated work.

Artifact existence alone must not authorize reuse.

### 12.5 Haltless degradation

A failed gate or provider should not necessarily stop the entire run. It must:

- emit a typed failure event;
- identify affected obligations/findings;
- prevent false completion;
- schedule fallback when available;
- surface material unresolved work to human review;
- reduce the run’s coverage confidence.

This preserves availability without pretending that missing analysis succeeded.

---

## 13. Methodology-application engine

### 13.1 Compilation

For each method card:

1. inspect provider capabilities;
2. select applicable entity kinds;
3. enumerate target entities;
4. enumerate required relations, paths, boundaries, or pairings;
5. create stable obligations;
6. choose worker/tool strategy based on fidelity and materiality;
7. record obligations that could not be instantiated because facts were unavailable.

Example:

~~~text
Method: paired-operation symmetry
Entities: deposit(), withdraw(), mint(), burn()
Facts: writes_same_state, inverse_semantic_tag, authorization
Output:
  O1 compare deposit/withdraw over shared accounting fields
  O2 compare mint/burn over supply and authorization
  O3 inspect unpaired write path emergencyWithdraw
~~~

The deterministic layer does not conclude that an asymmetry is vulnerable. It guarantees that the asymmetry is considered.

### 13.2 Evidence validation

Receipts should be checked mechanically where possible:

- referenced files and source locations exist;
- target IDs belong to the obligation;
- required steps have a valid status;
- cited tool artifacts exist and match hashes;
- claimed PoC execution has a command/result record;
- a “not applicable” result includes a reason consistent with target facts;
- no required target silently disappears;
- external claims have citation or research status;
- findings named in prose exist in canonical state.

Random independent audits of “completed with no candidate” receipts should be sampled because false-negative receipts are otherwise hard to detect.

### 13.3 Convergence

The scheduler should create follow-up obligations when:

- a new shared-state relation appears;
- a candidate introduces an unresolved external premise;
- a verifier disputes reachability but not mechanism;
- a confirmed mechanism lacks material-harm analysis;
- a tool result contradicts a model claim;
- a cluster contains inconsistent severities;
- graph fidelity is too low for a material target;
- a report writer introduces a claim absent from canonical evidence.

The loop ends when all material obligations are resolved or explicitly degraded.

### 13.4 Niche agents without prompt bloat

Niche methods should be activated by facts and flags:

- cryptographic operations;
- cross-domain messaging;
- upgrade/delegate patterns;
- token-standard hooks;
- concurrency primitives;
- unsafe/native boundaries;
- serialization/deserialization;
- governance and timelock structures;
- oracle/dependency calls;
- consensus/finality code.

The universal prompt remains compact. The work unit references the exact niche card and its version. A worker reads only the relevant cards plus the common evidence protocol.

### 13.5 The honest skill checker

Replace a prose-based “did this skill run?” reviewer with deterministic coverage plus sampled audit:

~~~text
method expected?
  |
  +-- no --> not applicable, with compiler reason
  |
  +-- yes --> obligation exists?
                 |
                 +-- no --> scheduling defect
                 |
                 +-- yes --> valid receipt?
                                  |
                                  +-- no --> execution/artifact defect
                                  |
                                  +-- yes --> step evidence complete?
                                                   |
                                                   +-- no --> partial
                                                   |
                                                   +-- yes --> applied
~~~

An LLM can judge the quality of the reasoning, but it should not invent the coverage universe.

---

## 14. Program-model and AST/IR roadmap

### 14.1 General provider contract

Every ecosystem provider should emit a common graph core:

- packages/modules/contracts;
- source entities and stable symbol identities;
- types and inheritance/implementation relations;
- entry points and visibility;
- calls and potential dispatch targets;
- reads, writes, creates, deletes, emits, transfers, and invokes;
- control-flow summaries;
- data/value-flow summaries where available;
- privilege/capability requirements;
- storage/account/resource/object relationships;
- external boundaries;
- configuration/build provenance;
- provider confidence and limitations.

Ecosystem-specific extensions are expected. They should not fork the universal methodology.

### 14.2 EVM

Priority sources:

- solc Standard JSON AST;
- storage layout;
- ABI and event/error metadata;
- inheritance and override resolution;
- source maps and bytecode/deployed bytecode;
- Yul/IR where available;
- Slither call/dataflow and detector outputs as enrichment;
- build/deployment/proxy metadata when in scope.

Required improvements:

- distinguish precise compiler facts from compilation-free regex fallbacks;
- model delegate/proxy relationships and initialization;
- represent low-level and external calls;
- track asset/accounting state effects;
- preserve modifier and inherited-call semantics;
- record compiler version and optimizer settings.

Solidity recommends Standard JSON as the automated compiler interface and exposes AST/storage/build outputs through it:

https://docs.soliditylang.org/en/latest/using-the-compiler.html

### 14.3 Rust, Solana, Soroban, and Rust L1 clients

SCIP/rust-analyzer provides a useful symbol baseline but not a complete semantic model.

Add:

- macro-expanded identities through compiler/rust-analyzer integration;
- HIR or typed intermediate facts;
- MIR control-flow and read/write/effect summaries;
- trait and dynamic-dispatch target approximation;
- cross-crate call relationships;
- feature-flag and target build matrices;
- unsafe/native/FFI boundaries;
- concurrency primitives and lock/channel relationships for node clients.

Solana extensions:

- instructions and account constraints;
- signer/writable/owner relationships;
- PDA derivation and seed domains;
- CPI call edges;
- account initialization, realloc, close, and rent behavior;
- Anchor-generated code and constraint expansion.

Soroban extensions:

- contractspec types and entry points;
- authorization trees and invoker relationships;
- instance/persistent/temporary storage and TTL behavior;
- cross-contract calls;
- token/client interfaces;
- host/environment boundaries.

Rust compiler references:

- https://rustc-dev-guide.rust-lang.org/hir.html
- https://rustc-dev-guide.rust-lang.org/mir/index.html

### 14.4 Aptos and Sui Move

Replace regex-only approximation with compiler AST, typed bytecode, or equivalent semantic facts.

Common Move facts:

- packages, modules, functions, structs;
- abilities;
- public/entry visibility;
- generic/type instantiations where available;
- resource creation, move, borrow, read, write, destroy;
- acquires relationships;
- call graph;
- signer/capability flows;
- abort conditions and constants.

Aptos extensions:

- account/resource addressing;
- signer and entry-function semantics;
- module upgrade policy;
- event/resource-group relationships;
- framework/native boundaries.

Sui extensions:

- object identity and ownership;
- shared, owned, immutable, and wrapped objects;
- capabilities and transfer;
- transaction context;
- programmable transaction composition;
- dynamic fields and object versioning;
- package upgrades.

### 14.5 Go L1 clients

Use:

- go/packages for build-aware package loading;
- go/types for resolved identities and types;
- x/tools/go/ssa for SSA;
- static, CHA, RTA, and VTA call-graph algorithms as appropriate.

Add facts for:

- goroutines;
- channels;
- locks and critical sections;
- context cancellation and timeouts;
- error and panic paths;
- serialization boundaries;
- consensus/network/state-machine entry points;
- build tags, GOOS, GOARCH, and generated code.

Source: https://pkg.go.dev/golang.org/x/tools/go/ssa

### 14.6 Daml

Prefer Daml-LF/DAR/package metadata over source regex:

- templates and interfaces;
- choices;
- controllers and observers;
- signatories;
- keys and maintainers;
- create/exercise/archive relationships;
- cross-package references;
- authorization and disclosure structure.

### 14.7 Cross-OS strategy

Do not create separate methodologies per operating system.

Use:

- one provider output schema;
- per-OS runner adapters;
- pinned compiler/analyzer binaries;
- normalized repository-relative paths;
- content-addressed caches keyed by source, toolchain, target, features, and provider version;
- hermetic containers or WSL where native tools differ;
- explicit tool availability and failure events;
- parity fixtures that compare semantic output across Windows and Linux.

OS-specific planning is required for installation, invocation, paths, process supervision, and sandboxing. The semantic graph should be OS-neutral.

### 14.8 Fidelity-aware fallback

Implementation should proceed before every provider is perfect.

For each obligation:

- precise facts permit narrow target assignment;
- conservative facts permit broader assignment and lower evidence confidence;
- approximate regex facts trigger expanded agent context and a coverage warning;
- unavailable facts generate explicit unresolved obligations or alternate tool work.

This avoids two bad extremes: blocking all architecture work on perfect ASTs, or allowing approximate graphs to claim exact coverage.

---

## 15. Ranked recall-improvement program

The ranking weights expected recall gain against complexity and separates discovery from pipeline survival.

### 15.1 Combined ranking

| Rank | Change | Primary miss side | Expected gain | Complexity | Rationale |
|---:|---|---|---|---|---|
| 1 | Canonical append-only finding/claim lifecycle | Pipeline loss | Very high | Medium | Makes silent disappearance, join drift, and unrecorded disposition mechanically detectable |
| 2 | Typed safety-premise and disposition challenge | Pipeline loss | Very high | Medium | Directly addresses false-safe decisions, including but broader than R10 |
| 3 | MethodCard, obligation, and evidence-receipt system | Discovery | Very high | Medium-high | Converts methodology application from prose intent to enumerated work |
| 4 | Fix live breadth/sidecar binding and skill checker | Discovery | High immediate | Low-medium | Removes demonstrated non-application paths before larger migration |
| 5 | Capability/fidelity-aware graph-provider contract | Discovery | High | High | Establishes reliable target and relation universes |
| 6 | Confirmed-mechanism harm-analysis obligation | Both | High | Medium | Prevents provisional Low severity from suppressing independent harm review |
| 7 | Bounded multi-hop relation/composition enumeration | Discovery | High | Medium-high | Expands beyond pairwise pre-filtered chains |
| 8 | Dependency-aware resume invalidation | Both | Medium-high | Medium | Prevents stale downstream interpretations |
| 9 | Root-cause clustering with preserved consequences | Precision/loss | Medium-high | Medium | Reduces bloat without deleting evidence |
| 10 | Tool/property/mutation expansion | Discovery/verification | Medium-high | High | Adds evidence classes LLM reasoning cannot supply |

### 15.2 Immediate discovery-side fixes

Before the full architecture lands:

1. Bind each breadth and sidecar worker to exact methodology files and hashes.
2. Stop treating orchestration prompts as vulnerability coverage.
3. Mark skills without explicit step checklists as not mechanically coverage-checkable.
4. Repair generic sidecar fall-through so design-stress, perturbation, and skill-execution work receive explicit builders.
5. Make “skill executed” require target, step, and evidence references.
6. Add a material confirmed-mechanism harm review independent of provisional severity.
7. Record target universes and unexamined targets in existing scratchpad output.

### 15.3 Immediate pipeline-loss fixes

1. Preserve R10.
2. Add one stable internal UUID to every harvested candidate while existing display IDs remain.
3. Generate a lifecycle reconciliation table across inventory, queue, depth, verification, skeptic, index, and report.
4. Require explicit reasons for every disappearance or severity decrease.
5. Make malformed reconciliation input produce a human-review coverage item.
6. Prevent report writers from deleting or inventing canonical findings.
7. Verify that report index, tier files, and assembled report are exact projections.

### 15.4 Discovery versus survival metrics

For every ground-truth issue, record:

~~~text
method present
  -> applicable
  -> obligation generated
  -> work scheduled
  -> evidence receipt valid
  -> candidate discovered
  -> candidate harvested
  -> mechanism verified
  -> harm correctly assessed
  -> included in final report
~~~

This creates an actionable loss location instead of one final recall number.

---

## 16. Precision, anti-bloat, severity, and report quality

### 16.1 Preserve raw observations

Recall safety does not require presenting every observation as a separate report issue.

Maintain three layers:

1. **Observation/candidate layer:** append-only, permissive, low confidence.
2. **Canonical finding layer:** verified mechanism and harm claims.
3. **Report layer:** consolidated communication organized around root cause and remediation.

This allows aggressive report consolidation without deleting discovery evidence.

### 16.2 Two-stage clustering

First cluster mechanically on:

- shared affected state;
- shared write/call paths;
- common violated invariant;
- common privilege/capability;
- common external premise;
- common remediation surface.

Then ask an independent semantic reviewer whether the mechanism is truly the same.

Do not cluster solely on:

- prose embedding similarity;
- common contract/file;
- common vulnerability label;
- similar impact wording.

### 16.3 Preserve distinct consequences

One root cause may produce:

- loss of funds;
- accounting corruption;
- denial of service;
- privilege escalation;
- cross-domain inconsistency.

The report may use one parent finding with multiple consequence sections. The ledger must preserve each harm claim and its evidence.

### 16.4 Precision through evidence tiers

Use evidence classifications such as:

- mechanically observed fact;
- compiler/static-analysis fact;
- executed behavioral evidence;
- formal/symbolic proof;
- source-supported semantic inference;
- externally cited fact;
- unresolved assumption;
- model hypothesis.

The prose can remain readable while the evidence tier controls confidence and report placement.

### 16.5 Severity model

Keep Impact × Likelihood, but separate its inputs:

**Impact**

- affected assets/properties;
- maximum plausible scope;
- reversibility;
- privilege required;
- blast radius;
- composition with other mechanisms.

**Likelihood**

- reachability;
- attacker control;
- prerequisites;
- frequency/window;
- environmental/external dependencies;
- detectability and intervention assumptions.

Also record:

- mechanism confidence;
- premise confidence;
- evidence strength;
- severity confidence.

A confirmed mechanism with uncertain external harm should not be labeled simply “safe.” It may be High-impact/unknown-likelihood and require external validation.

### 16.6 Independent severity challenge

Trigger a severity challenge when:

- mechanism is supported but severity is Informational/Low;
- severity decreases between stages;
- a favorable premise is decisive;
- similar cluster members have materially different severity;
- a multi-hop composition increases scope;
- report prose describes stronger harm than the structured rating;
- depth and verification disagree.

### 16.7 Report as a renderer

Writers should be allowed to:

- improve explanation;
- select supporting code excerpts;
- organize consequences;
- explain remediation;
- normalize terminology.

They should not be allowed to:

- create or delete findings;
- change severity without a decision event;
- introduce unsupported mechanism or harm claims;
- omit unresolved premises;
- convert inconclusive evidence into proof.

The renderer should generate:

- executive summary;
- scope and limitations;
- findings;
- severity table;
- unresolved external/human-review items;
- methodology coverage summary;
- tool/build limitations;
- machine-readable JSON/SARIF-like export.

---

## 17. Research-backed evaluation program

### 17.1 What Solodit can establish

Solodit is useful for:

- sampling real professional findings;
- constructing a vulnerability-reasoning taxonomy;
- checking whether method cards can explain known findings generically;
- selecting post-cutoff evaluation audits;
- measuring whether the system applies relevant methods;
- examining same-root-cause fragmentation and severity calibration.

Sources:

- https://docs.cyfrin.io/solodit/overview
- https://docs.solodit.cyfrin.io/findings-explorer/search-for-a-finding
- https://github.com/solodit/solodit_content

### 17.2 What Solodit cannot establish

Solodit cannot prove:

- that every vulnerability in an audited repository was reported;
- that its category distribution represents all ecosystems;
- that a method catalog is complete;
- that a pipeline would have discovered a finding without leakage;
- that competitor retrieval from the same corpus is genuine reasoning;
- that “no reported finding” is a safe negative example.

The public corpus is also disproportionately useful for EVM compared with Plamen’s full language scope.

### 17.3 Corpus construction

Create four evaluation tracks.

#### Track A — Real-report chronological holdout

- Freeze a methodology-development cutoff.
- Select audits published after the cutoff.
- Exclude projects, forks, and protocol families used during development.
- Preserve repository commits and build instructions where available.
- Blind the audit report until pipeline execution is locked.

#### Track B — EVMbench

Use EVMbench as a reproducible real-audit benchmark and retain its issue-level artifacts. Measure not only final detection but also early stopping, tool execution, and lifecycle survival.

Sources:

- https://openai.com/index/introducing-evmbench/
- https://github.com/paradigmxyz/evmbench

#### Track C — Non-EVM real and seeded suites

Build ecosystem-balanced cases for:

- Solana;
- Soroban;
- Aptos;
- Sui;
- generic Move;
- Rust L1/client code;
- Go L1/client code;
- Daml.

Because public report volume varies, combine real findings with expert-seeded defects and source-preserving mutations.

#### Track D — Precision/adversarial-safe suite

Construct:

- correctly protected variants;
- intentionally safe asymmetries;
- externally cited safe behavior;
- unreachable or privilege-constrained cases;
- expected rounding and bounded-loss cases;
- duplicate manifestations of one root cause;
- similar prose with different mechanisms;
- mechanisms with multiple distinct harms.

This is essential for validating premise gates and clustering without suppressing recall.

### 17.4 Leakage controls

1. Hash and version the method catalog before opening holdout reports.
2. Do not retrieve the ground-truth finding text during evaluation.
3. Separate protocol families, not only repositories.
4. Track whether model pretraining may contain the report.
5. Prefer newly published post-cutoff audits for decisive claims.
6. If Solodit examples are used to generate a method, exclude those examples and close variants from scoring that method.
7. Record all external retrieval and research queries.
8. Compare no-retrieval and retrieval-assisted modes separately.

### 17.5 Ground-truth annotation

For each finding, annotate:

- root cause;
- required source entities and relations;
- universal semantic operators involved;
- ecosystem-specific knowledge required;
- external facts required;
- minimum reasoning depth;
- whether runtime, symbolic, formal, or fuzzing evidence is required;
- expected impact and likelihood;
- acceptable same-root-cause consolidation;
- likely application and lifecycle failure points.

At least two independent reviewers should annotate difficult cases and reconcile disagreement.

### 17.6 Required lifecycle metrics

#### Recall

- issue-level discovery recall;
- root-cause recall;
- material-harm recall;
- severity-within-one-band recall;
- final-report recall;
- chain/composition recall;
- non-EVM recall by ecosystem.

#### Application

- applicable obligations generated;
- obligation scheduling coverage;
- valid receipt coverage;
- required-step evidence coverage;
- target coverage;
- relation/path coverage;
- unresolved material obligation rate;
- false “method applied” rate from sampled independent review.

#### Pipeline survival

- candidate harvest survival;
- verification survival;
- skeptic survival;
- report-index survival;
- final-assembly survival;
- unsupported-demotion rate;
- identifier/reconciliation error rate.

#### Precision and quality

- verified precision;
- report precision;
- false-safe rate;
- false-positive candidates per true positive;
- same-root-cause fragmentation;
- incorrect cluster-merge rate;
- unsupported severity rate;
- report evidence completeness;
- reviewer edit distance or adjudication effort.

#### Efficiency

- tokens and wall time per applicable obligation;
- tool cost;
- number of follow-up obligations;
- cache/reuse rate;
- agent failure and retry rate;
- graph-provider build success.

### 17.7 Ablation matrix

Do not ship the entire redesign and compare only before/after. Test:

| Variant | Ledger | Premise model | Obligations | Improved graph | Multi-hop | Purpose |
|---|---:|---:|---:|---:|---:|---|
| Baseline | No | R10 only | No | Current | Current | Existing driver |
| A | Yes | R10 only | No | Current | Current | Isolate lifecycle survival |
| B | Yes | General | No | Current | Current | Isolate false-safe reduction |
| C | Yes | General | Yes | Current | Current | Isolate methodology application |
| D | Yes | General | Yes | Selected providers | Current | Isolate source-model benefit |
| E | Yes | General | Yes | Selected providers | Yes | Full target architecture |

Measure both recovered ground truth and newly introduced noise at each step.

### 17.8 Acceptance thresholds

Exact numeric thresholds should be set from the frozen baseline, but release gates should include:

- zero silent loss of seeded candidates after canonical ingestion;
- zero report omissions without an explicit decision event;
- zero proof-grade claims without bound execution evidence;
- no material increase in false-safe rate;
- statistically meaningful reduction in non-application misses;
- no material precision regression at final report;
- no incorrect re-inflation in R10/general-premise precision fixtures;
- stable results under resume/retry;
- cross-OS provider parity within declared capability differences;
- all material unresolved obligations visible in the final coverage appendix.

For recall, report confidence intervals and issue-level results. Small benchmarks should not be summarized by a single percentage.

### 17.9 Competitor comparison

Competitor claims should be evaluated only when a reproducible run interface and raw outputs are available.

For each system:

- run identical source commits;
- use equivalent time/tool budgets;
- prevent report retrieval;
- preserve raw outputs;
- adjudicate root cause rather than keyword overlap;
- score final report and pre-report candidate recall separately;
- record model/version/date;
- disclose whether proprietary retrieval or fine-tuning prevents a clean comparison.

Pashov’s public skills are a valuable reproduction target because the methodology is inspectable. Self-published result summaries remain hypothesis-generating evidence, not proof that Plamen is behind or ahead.

### 17.10 How to determine whether methodology or application is the bottleneck

For each missed ground-truth issue:

1. Could a current method card generically derive the required question?
2. Did the compiler mark it applicable?
3. Was the correct target/relation present?
4. Was a work unit scheduled?
5. Did a valid receipt show the required steps?
6. Did the worker produce the decisive intermediate claim?
7. Was the claim incorrectly judged?
8. Was it later lost?

Only misses answering “no” at step 1 are true methodology-content gaps. This is the evidence needed before concluding that enumeration/application is the only remaining weakness.

---

## 18. Implementation program

This should be an incremental migration with measurable rollback points.

### Release 0 — Immediate binding and observability corrections

**Purpose:** remove known non-application defects without waiting for the new state model.

Changes:

- bind breadth workers to exact methodology content rather than coordinator prose;
- add explicit builders for design-stress, perturbation, and skill-execution sidecars;
- require skill path/hash, targets, steps, and evidence in the checker;
- mark skills lacking structured steps as unverified rather than executed;
- add lifecycle reconciliation output with stable temporary IDs;
- add confirmed-mechanism harm-review routing;
- preserve R10 unchanged.

Acceptance:

- real scratchpad replay shows no false all-executed summary;
- intentionally omitted skill step is detected;
- breadth run records exact method bindings;
- no new final-report false positives in benchmark replay.

### Release 1 — Schema package and canonical event ledger

**Purpose:** make lifecycle survival enforceable.

Create:

- schema definitions and migrations;
- SQLite run database;
- append-only FindingEvent API;
- stable semantic IDs;
- artifact hash/provenance service;
- read-only report/lifecycle queries;
- JSONL export.

Dual-write existing candidate, inventory, depth, verifier, skeptic, and report events.

Acceptance:

- all existing tests pass;
- old markdown outputs remain byte-compatible where required;
- database and markdown lifecycle reconciliation match;
- a seeded candidate cannot disappear without a validation failure;
- retry and resume are idempotent.

### Release 2 — Report projection and disposition policy

**Purpose:** close downstream loss before expanding discovery.

Changes:

- report index/body/appendix rendered from canonical state;
- explicit merge/split/exclude/downgrade events;
- structured severity;
- report completeness query;
- human-review appendix;
- writer claims validated against canonical findings.

Acceptance:

- seeded inventory-to-report cases have complete survival;
- mismatched display IDs do not affect joins;
- report writer cannot silently delete, create, or rerate a finding;
- existing report style remains acceptable.

### Release 3 — General premise and challenge model

**Purpose:** generalize R10 and address false-safe decisions.

Changes:

- Claim, Premise, Evidence, and DispositionDecision schemas;
- direction-aware assumption policy;
- independent challenge work unit;
- external-research ledger integration;
- mechanism/harm split;
- confirmed-mechanism harm obligation.

Migration:

- keep R10 active;
- dual-evaluate R10 fixtures through new policy;
- remove or reduce R10 only after exact replay parity and precision validation.

Acceptance:

- private regression target external-best-case cases remain visible;
- correctly demoted precision cases remain demoted;
- unsupported in-scope and external safety premises are flagged;
- no severity is raised beyond supported harm evidence;
- the depth-side Low limitation is exposed and routed.

### Release 4 — MethodCard and obligation compiler

**Purpose:** close methodology-application gaps.

Changes:

- method-card schema/catalog;
- typed obligation table;
- work-unit binding;
- evidence receipts;
- honest application coverage;
- unresolved-obligation scheduling;
- common universal kernel extracted from duplicated prompts.

Begin with methods whose target universe is already reliable:

- boundary values;
- paired/symmetric operations;
- shared-state writers/readers;
- authorization/capability entry points;
- local invariant assertions;
- external interaction inventory;
- lifecycle/initialization entry points.

Acceptance:

- seeded omission of an applicable target is detected;
- no-receipt and partial-receipt paths remain unresolved;
- “not applicable” requires a validated reason;
- prompt size does not grow materially;
- application recall improves on holdout without report precision loss.

### Release 5 — Graph-provider contract and selected precise adapters

**Purpose:** raise the ceiling on enumerability.

Order:

1. EVM solc/Slither typed provider.
2. Go packages/types/SSA provider.
3. Rust HIR/MIR or best available compiler-backed provider.
4. Aptos/Sui Move typed provider.
5. Soroban semantic extensions.
6. Daml-LF provider.

The exact order may change based on benchmark value and toolchain feasibility.

Acceptance:

- provider capability manifests are truthful;
- precise and fallback outputs are distinguishable;
- provider conformance fixtures pass on Windows and Linux;
- target/relation coverage rises on ecosystem holdouts;
- low-fidelity fallback never reports precise completion.

### Release 6 — Relation graph and adaptive convergence

**Purpose:** improve composition and long-path reasoning.

Changes:

- bounded two-to-four-hop path enumeration;
- shared-state, capability, external-premise, lifecycle, and cross-domain relations;
- follow-up obligation triggers;
- uncertainty/materiality-prioritized scheduler;
- chain receipts and evidence paths.

Acceptance:

- seeded three-step compositions are scheduled;
- path explosion is bounded;
- candidate precision remains controlled through verification;
- unresolved material paths appear in coverage output.

### Release 7 — Tool expansion and property synthesis

**Purpose:** add evidence classes that LLM reasoning cannot replace.

Changes:

- property/invariant registry;
- fuzzing and mutation-testing providers;
- symbolic/formal tool adapters;
- coverage and vacuity checks;
- differential and metamorphic test generation;
- tool-result receipts bound to claims.

Acceptance:

- seeded properties fail under mutation;
- vacuous proofs/tests are detected;
- tool failure degrades visibly;
- executed evidence improves verification confidence without automatically determining business harm.

### Release 8 — Isolation and operational hardening

**Purpose:** make parallel and resumed execution reproducible.

Changes:

- immutable source snapshots;
- isolated worktrees/containers for mutating work;
- worker lease recovery;
- resource limits;
- content-addressed build cache;
- dependency invalidation;
- database backup/recovery;
- deterministic run manifest.

Acceptance:

- concurrent workers cannot interfere;
- interrupted runs resume without duplicate semantic events;
- source or method changes invalidate correct descendants;
- identical snapshots produce equivalent obligation universes within declared nondeterminism.

---

## 19. Files to design before implementation

The current four reports are sufficient to justify the program. They are not a substitute for implementation contracts.

Create these repository documents before Release 1:

1. **architecture/method-application-rfc.md**  
   MethodCard, Obligation, EvidenceReceipt, Claim, Premise, FindingEvent, DispositionDecision, lifecycle states, invariants, concurrency, and error semantics.

2. **architecture/ecosystem-graph-provider-contract.md**  
   Common graph types, overlays, provider capabilities, fidelity vocabulary, provenance, build matrices, provider conformance tests, and fallback policy.

3. **methodology/method-cards-v1.yaml**  
   Initial universal semantic kernel, applicability selectors, required steps/receipts, prompt fragments, and ecosystem capability requirements.

4. **architecture/finding-ledger-migration.md**  
   SQLite schema, dual-write stages, ID migration, reconciliation, report projection, rollback, backup, and removal criteria for old parsers.

5. **benchmarks/application-coverage-evaluation-plan.md**  
   Frozen corpora, ground-truth schema, leakage controls, lifecycle metrics, ablations, competitor protocol, thresholds, and adjudication.

6. **architecture/work-unit-scheduler.md**  
   Semantic stages, unit leases, idempotency, retries, budgets, convergence, follow-up triggers, and human-review degradation.

7. **architecture/premise-and-disposition-policy.md**  
   Safety/adverse premise polarity, source classes, research status, challenge requirements, severity interaction, and R10 migration.

These are engineering specifications, not additional broad research reports.

---

## 20. Engineering validation matrix

### 20.1 Schema and ledger tests

- foreign-key and unique-identity tests;
- append-only event enforcement;
- invalid state-transition rejection;
- idempotent retry;
- concurrent writer behavior;
- database recovery;
- JSONL export/import round trip;
- stable display-ID changes;
- merge/split preservation;
- report projection completeness.

### 20.2 Property-based lifecycle tests

Generate random event sequences and assert:

- no candidate disappears;
- every current state is derivable;
- invalid transitions fail closed to review;
- report inclusion is total over eligible states;
- merge/split preserves lineage;
- retry does not duplicate state;
- stale dependencies cannot be treated as current.

### 20.3 Method-application fixtures

For each MethodCard:

- positive applicability;
- valid not-applicable;
- missing target;
- missing relation;
- incomplete receipt;
- invalid evidence reference;
- approximate-provider route;
- provider failure;
- material unresolved route;
- prompt-version invalidation.

### 20.4 Premise/disposition fixtures

- cited adverse external premise;
- uncited adverse external premise;
- cited favorable external premise;
- uncited favorable external premise;
- repository-grounded premise;
- executed in-scope evidence;
- mechanism refuted;
- mechanism supported/harm unresolved;
- depth/verifier severity disagreement;
- multiple premises with mixed confidence;
- R10 replay parity;
- no spurious re-inflation.

### 20.5 Report tests

- all eligible findings rendered;
- every exclusion explained;
- no writer-created finding;
- no writer severity mutation;
- evidence and unresolved premises visible;
- stable ordering;
- deterministic rendering;
- machine-readable and markdown consistency;
- same-root-cause parent with preserved consequences.

### 20.6 Graph-provider conformance

For each provider and OS:

- stable symbol identity;
- location normalization;
- build-feature matrix;
- call/read/write fixture;
- macro/generated-code fixture;
- dynamic-dispatch/conservative edge fixture;
- failed-build fallback;
- capability manifest truthfulness;
- source-change cache invalidation;
- parity against a second OS where supported.

### 20.7 End-to-end replay

Required replays:

- private regression target, including PRIVATE-FINDING-001/PRIVATE-FINDING-005 lifecycle;
- clean precision repos used for R10;
- representative EVM project;
- representative Soroban/Rust project;
- Aptos and Sui samples;
- Go L1/client sample;
- interrupted/resumed run;
- intentionally malformed artifact/run;
- seeded method non-application;
- seeded report disappearance.

---

## 21. Migration and rollback strategy

### 21.1 No big-bang rewrite

The existing pipeline is battle-tested. Replace its control assumptions incrementally.

During dual-write:

- markdown remains available to existing agents;
- structured state is written alongside it;
- deterministic reconciliation compares both;
- divergences fail to a visible review item;
- benchmark results compare old and new projections.

### 21.2 Strangler pattern

Replace components in this order:

1. lifecycle observation;
2. canonical identities/events;
3. report projection;
4. premise/disposition;
5. application obligations;
6. graph providers;
7. scheduler convergence.

This order closes downstream recall loss before increasing upstream candidate volume.

### 21.3 Feature flags

Use run-level flags:

- ledger_dual_write;
- ledger_authoritative;
- report_from_ledger;
- premise_policy_shadow;
- premise_policy_enforce;
- obligations_shadow;
- obligations_schedule;
- provider_name/version;
- relation_scheduler.

Every benchmark report must record flags.

### 21.4 Rollback

Each release must preserve:

- the original source snapshot;
- old markdown artifacts;
- database migrations with tested downgrade/export;
- ability to render from the previous authoritative source;
- policy version used for each decision;
- replay tooling.

Never remove a legacy gate/parser until shadow results show equivalent or better recall and precision on frozen replays.

---

## 22. Risks in the proposed architecture

### 22.1 Schema bureaucracy

Risk: workers spend tokens filling fields rather than reasoning.

Mitigation:

- keep receipts compact;
- store full reasoning as one artifact;
- auto-populate run/method/target metadata;
- require only fields used by an invariant or metric;
- measure token and latency overhead.

### 22.2 False confidence from obligations

Risk: a completed obligation is mistaken for correct analysis.

Mitigation:

- distinguish application coverage from finding correctness;
- sample negative receipts;
- run independent challenge;
- use tool evidence;
- publish provider fidelity.

### 22.3 Graph incompleteness

Risk: the compiler omits targets and then reports perfect coverage over an incomplete universe.

Mitigation:

- capability manifests;
- multiple providers/overlays;
- source-file and entrypoint reconciliation;
- graph-delta tests;
- low-fidelity warnings;
- raw-source blind-spot agents;
- compiler versus fallback comparisons.

### 22.4 Obligation explosion

Risk: target × method × relation combinations become unaffordable.

Mitigation:

- applicability predicates;
- risk/materiality scoring;
- equivalence classes;
- representative sampling plus hotspot expansion;
- bounded path lengths;
- cache shared facts;
- budgeted unresolved state rather than silent skipping.

### 22.5 Overfitting to Solodit

Risk: method cards become disguised answers to public findings.

Mitigation:

- semantic operators rather than named bug checks;
- chronological and family holdouts;
- independent reviewer rejection of protocol-specific hints;
- mutation and metamorphic tests;
- post-cutoff evaluation.

### 22.6 Gate proliferation

Risk: every miss produces another regex gate.

Mitigation:

- qualification test;
- general typed policies;
- deprecate redundant gates after parity;
- count gates and parser dependencies as architectural debt.

### 22.7 Database corruption or contention

Risk: a new canonical store becomes a single point of failure.

Mitigation:

- WAL mode and short transactions;
- one writer service if contention warrants it;
- append-only JSONL backup;
- checksums and migrations;
- repair-then-degrade with preserved artifacts;
- recovery tests.

### 22.8 Model gaming of receipts

Risk: an agent produces plausible structured completion without doing the work.

Mitigation:

- prebound target lists;
- required evidence locations;
- artifact/source consistency checks;
- sampled independent replay;
- compare reasoning coverage with graph facts;
- do not use receipt completion as proof of security correctness.

### 22.9 Precision regression

Risk: better enumeration produces overwhelming low-value candidates.

Mitigation:

- obligations are coverage tasks, not findings;
- candidate materiality floor;
- independent verification;
- root-cause clustering;
- final report thresholds;
- measure candidate and report precision separately.

### 22.10 Severity inflation

Risk: premise vetoes keep speculative issues at high severity.

Mitigation:

- veto unsupported dismissal without manufacturing unsupported harm;
- separate impact, likelihood, and confidence;
- use inconclusive/human-review states;
- require harm evidence for severity increases;
- retain R10’s monotonic visibility principle.

---

## 23. What not to build

1. **Do not build a large custom private semantic-query claim/CodeQL clone first.** Use existing compiler outputs and a replaceable predicate layer.
2. **Do not add hundreds of always-on vulnerability prompts.** Use a compact semantic kernel plus conditional cards.
3. **Do not create methodology forks per OS.** Fork runners/providers only where tool invocation differs.
4. **Do not make report writers another verification layer.** Render canonical state.
5. **Do not treat executed PoC as universal proof.** Bind execution to claims and coverage.
6. **Do not expand regex parsing as the canonical semantic interface.** Keep it only for legacy/fallback ingestion.
7. **Do not use LLM self-report as application coverage.**
8. **Do not delete duplicate candidates.** Cluster and project them.
9. **Do not permit silent haltless degradation.**
10. **Do not claim “best pipeline” from competitor marketing or a single benchmark.**

---

## 24. Blind spots and assumptions most likely to be wrong

### 24.1 “Additive” is not automatically recall-safe

Adding a candidate is monotonic only at the point of insertion. It can still:

- consume verification budget;
- change grouping;
- alter severity comparisons;
- displace another candidate from context;
- trigger a merge;
- change report-tier allocation;
- increase reviewer stopping pressure.

Recall safety must be measured across the complete lifecycle, not inferred from generator behavior.

### 24.2 A disk artifact does not prove application

An artifact proves that bytes were written. It does not prove:

- the correct methodology was read;
- all applicable targets were examined;
- required steps were performed;
- evidence supports the conclusion;
- the artifact corresponds to current inputs.

This is the central reason to introduce obligations and receipts.

### 24.3 Mandatory PoC execution does not make all verification proof-oriented

A test can execute the wrong path, assert the wrong property, use an unrealistic harness, or leave the decisive external leg unmodeled. Proof grade requires claim binding, reachability evidence, and limitations—not merely a passing command.

### 24.4 More phases do not monotonically increase recall

Additional phases can:

- create correlated summaries instead of new analysis;
- compress earlier nuance;
- introduce more demotion points;
- increase ID and schema drift;
- exhaust context/budget;
- make it harder to identify the authoritative conclusion.

New phases should be justified by a distinct evidence product or obligation class.

### 24.5 Duplicate loss is not merely cosmetic

Two apparently duplicate observations may encode:

- different preconditions;
- different affected functions;
- different consequences;
- stronger evidence;
- different remediation;
- a compositional escalation.

Clustering must preserve all member evidence before presentation-level consolidation.

### 24.6 Haltless degradation is not always recall-safe

Continuing after failure is useful only when the failure is visible and downstream stages know which claims or obligations are unreliable. Silent no-op behavior can produce a polished but incomplete audit.

### 24.7 A complete-looking method catalog is not complete methodology

Coverage labels can create false confidence. The actual test is whether post-cutoff findings can be mapped to generic methods and whether those methods were instantiated without protocol-specific hints.

### 24.8 Competitors are not necessarily built this way

There is insufficient public evidence to assume proprietary tools use CodeQL-like graphs, obligation compilers, or closed finding ledgers. Similar outputs can arise from:

- prompt bundles;
- retrieval over audit corpora;
- fine-tuning;
- static detectors plus LLM explanation;
- multi-agent orchestration;
- semantic query layers;
- manual analyst intervention.

Plamen’s design should be driven by its own observed failure modes and reproducible comparisons.

### 24.9 The proposed architecture can itself over-engineer the wrong layer

The ledger and obligations are justified only if they improve measured outcomes. If most residual errors after lifecycle closure are pure semantic judgment failures, further schema expansion will have declining returns. The ablation program is therefore a required part of the architecture, not an optional validation step.

### 24.10 What I would do differently

I would stop treating the phase tree and markdown artifact family as the conceptual architecture. I would model the audit as:

- a source/relation graph;
- a set of unresolved obligations;
- a set of evolving evidence-backed claims;
- a queue of experiments/reviews;
- a deterministic projection into a report.

Agents and tools become interchangeable executors of work units. Phases remain useful for operational batching and user-facing progress, but no longer define semantic truth.

---

## 25. Traceability from observed defects to proposed controls

| Observed defect | Primary control | Verification |
|---|---|---|
| PRIVATE-FINDING-001/PRIVATE-FINDING-005 demoted on unsupported external assumption | Typed premise/disposition policy; R10 retained during migration | private regression target replay plus favorable/adverse premise fixtures |
| R10 only restores depth severity | Confirmed-mechanism harm-analysis obligation | Seeded supported-mechanism/underrated-harm cases |
| Queue H-NN versus inventory INV-NNN join mismatch | Stable internal UUID and explicit lineage | Display-ID mutation/property tests |
| Router schema mismatch and KeyError noise | Schema validation and typed work-unit contract | Invalid payload fixtures; visible degradation |
| Skill checker reports perfect application without hard evidence | Obligations and EvidenceReceipts | Seeded skipped-step and missing-target cases |
| Breadth prompt mistaken for coverage methodology | Exact MethodCard binding | Prompt/method hash recorded in receipts |
| Sidecar categories fall through generic builder | Typed work-unit strategy registry | Builder dispatch fixtures |
| Markdown/regex as state/type system | SQLite canonical state and schemas | Dual-write reconciliation |
| Artifact existence treated as completion | Receipt validation and semantic state | Empty/stub artifact fixtures |
| Fixed phase graph misses follow-up work | Obligation-driven convergence | Follow-up scheduling fixtures |
| Pairwise composition pre-filter | Bounded multi-hop relation enumeration | Three/four-step seeded paths |
| Severity gates skepticism | Mechanism/harm split and challenge triggers | Low-severity confirmed-mechanism fixtures |
| Dedup can drop distinct consequences | Preserving root-cause clusters | One-root/multiple-harm fixtures |
| Report assembly can omit findings | Deterministic report projection | Total inclusion property |
| Resume can reuse stale outputs | Semantic dependency hashes | Source/method/provider change tests |
| Regex/SCIP provider uncertainty hidden | Provider capability/fidelity manifest | Cross-provider and fallback fixtures |
| More agents create correlated repetition | Method-target obligations and independent sampling | Application coverage and marginal-yield metrics |

---

## 26. Decision criteria for continuing, changing, or stopping

### Continue the program if

- Release 1 eliminates seeded lifecycle disappearance without destabilizing runs;
- Release 3 reduces unsupported false-safe decisions with no material severity inflation;
- Release 4 measurably reduces non-application misses;
- structured state reduces forensic effort;
- prompt/token overhead remains bounded;
- provider improvements raise target/relation recall.

### Change direction if

- receipts are mostly bureaucratic and poorly correlated with actual application;
- obligation volume cannot be controlled without skipping material work;
- graph providers fail frequently enough to dominate audits;
- report quality declines because structured claims are too rigid;
- SQLite contention or schema migrations materially impair resumability.

Possible adjustments include smaller receipts, per-stage stores with a canonical event API, more sampling, or using an established CPG/query backend.

### Stop or roll back a component if

- it decreases final-report recall on frozen holdouts;
- it hides unresolved work;
- it introduces unrecoverable state;
- it materially increases false-safe decisions;
- it cannot be replayed or versioned;
- its benefit exists only on the motivating protocol.

---

## 27. Independent-grader checklist

An independent reviewer should grade this plan against evidence rather than agreement with its terminology.

### Diagnosis

1. Do repository and private regression target artifacts support the claim that candidates can be found and then lost or demoted?
2. Is methodology application currently inferred more than mechanically observed?
3. Is markdown/regex genuinely acting as canonical state?
4. Are breadth and sidecar bindings described accurately?
5. Are severity and verification coupled in a recall-reducing way?

### Architecture

6. Does the proposed ledger create a real source of truth or merely another sidecar?
7. Are identities, events, claims, premises, and evidence separated correctly?
8. Are hard invariants implementable?
9. Is the migration incremental enough for a battle-tested system?
10. Does repair-then-degrade remain visible?

### Methodology

11. Is the twelve-operator kernel broad but non-overfit?
12. Can method cards be instantiated generically?
13. Does the system distinguish application coverage from reasoning correctness?
14. Are there important vulnerability/reasoning classes absent from the kernel?
15. Are niche methods activated without prompt bloat?

### Program analysis

16. Is the common graph contract sufficient across EVM, Move, Rust, Go, and Daml?
17. Are compiler-backed integrations technically feasible?
18. Is fidelity propagation strong enough to avoid false coverage?
19. Are there better existing CodeQL/Joern/SCIP-based backends that should replace custom work?
20. Is the cross-OS strategy realistic?

### Recall and precision

21. Does the plan directly address both halves of the reported miss split?
22. Can premise challenge reduce false-safe errors without severity inflation?
23. Can clustering reduce report bloat without deleting evidence?
24. Are the benchmark metrics capable of locating lifecycle loss?
25. Are acceptance criteria strong enough to reject a harmful implementation?

### Research and claims

26. Are competitor comparisons appropriately qualified?
27. Are Web2 analogies structurally relevant?
28. Are Solodit and EVMbench limitations correctly handled?
29. Is the confidence statement honest?
30. What evidence would falsify the build recommendation?

---

## 28. Final verdict

### 28.1 Are the existing files enough?

They are enough to justify building and testing the proposed direction. They were not enough as a single engineering handoff because:

- the main evidence was split across reports;
- the R10 final outcome postdated part of the forensic;
- schemas and lifecycle invariants were not fully specified;
- the ecosystem/OS extractor roadmap was distributed across discussion;
- benchmark and migration acceptance criteria were not consolidated.

This document closes that documentation gap.

### 28.2 Can methodology application be fixed?

Yes, substantially.

It can be changed from an unreliable emergent behavior into a controlled process by:

- enumerating applicable target/method obligations;
- binding exact method versions to work units;
- requiring evidence receipts;
- tracking unresolved work;
- sampling negative conclusions;
- using typed source/relation facts;
- generating follow-up obligations when uncertainty remains.

The residual application error will be measurable rather than invisible.

### 28.3 Can all vulnerability classes be guaranteed?

No.

No audit methodology, human or automated, can prove completeness against an open-ended set of business-logic, economic, external, and novel vulnerabilities. Formal methods can prove stated properties under stated models; they do not prove that every important property was stated.

The correct objective is continuous empirical dominance:

- higher root-cause and final-report recall;
- lower false-safe rate;
- stable or improved report precision;
- explicit application coverage;
- transparent unresolved work;
- reproducible performance on post-cutoff, ecosystem-balanced holdouts.

### 28.4 Is more AST/IR planning required?

Yes, but it should be a provider-contract and implementation roadmap, not a redesign of methodology per ecosystem or OS.

Begin ledger and obligation work using current facts. In parallel, improve provider fidelity and expose limitations. Do not wait for perfect ASTs, and do not let regex approximations claim precise coverage.

### 28.5 Overall recommendation

Proceed with the staged program.

The current Plamen architecture contains valuable, battle-tested discovery diversity and deterministic repair mechanisms. Its limiting weakness is that methodology application and candidate disposition are still too dependent on prose, heuristic joins, and phase-local artifacts.

The proposed change does not discard the pipeline. It gives the pipeline a real semantic control plane.

If implemented with dual-write migration, independent ablations, frozen holdouts, precision-safe premise policies, and ecosystem fidelity manifests, it has a strong research-backed chance of:

- materially increasing recall;
- preventing silent downstream loss;
- reducing unsupported safe judgments;
- improving methodology application;
- reducing same-root-cause report fragmentation;
- improving severity and evidence consistency;
- making remaining misses diagnosable.

The highest-leverage engineering order remains:

1. immediate methodology-binding and checker corrections;
2. canonical append-only finding/claim ledger;
3. report projection and disposition invariants;
4. generalized premise challenge and confirmed-mechanism harm review;
5. MethodCards, obligations, and EvidenceReceipts;
6. capability-aware ecosystem graph providers;
7. multi-hop composition and adaptive convergence;
8. formal/fuzzing/mutation evidence expansion.

This is the strongest defensible path toward the best version of the driver. Its success must be earned through lifecycle-level measurement, not asserted from architecture or competitor claims.

---

## 29. Reference index

### Plamen

- Repository: https://github.com/PlamenTSV/plamen
- Reviewed architecture baseline: https://github.com/PlamenTSV/plamen/tree/SOURCE-REVISION-004
- Architecture overview: https://github.com/PlamenTSV/plamen/blob/SOURCE-REVISION-004/docs/architecture.md
- Internals: https://github.com/PlamenTSV/plamen/blob/SOURCE-REVISION-004/docs/internals.md
- Confidence scoring: https://github.com/PlamenTSV/plamen/blob/SOURCE-REVISION-004/rules/phase4-confidence-scoring.md

### Human audit practice

- OpenZeppelin audit lessons: https://www.openzeppelin.com/news/what-is-a-smart-contract-audit-lessons-from-openzeppelins-1000-audits
- Trail of Bits software assurance: https://www.trailofbits.com/services/software-assurance

### Structured program analysis

- CodeQL documentation: https://codeql.github.com/docs/
- About CodeQL queries: https://codeql.github.com/docs/writing-codeql-queries/about-codeql-queries/
- Joern code-property graph: https://docs.joern.io/code-property-graph/
- Joern dataflow steps: https://docs.joern.io/cpgql/data-flow-steps/
- Semgrep Pro Engine: https://semgrep.dev/products/pro-engine/
- OpenRewrite recipes: https://docs.openrewrite.org/concepts-and-explanations/recipes
- OPA documentation: https://www.openpolicyagent.org/docs
- OPA Rego: https://www.openpolicyagent.org/docs/policy-language
- SARIF concepts: https://docs.github.com/en/code-security/concepts/code-scanning/sarif-files
- SARIF support: https://docs.github.com/en/enterprise-cloud@latest/code-security/reference/code-scanning/sarif-files/sarif-support

### Compiler and ecosystem sources

- Solidity compiler/Standard JSON: https://docs.soliditylang.org/en/latest/using-the-compiler.html
- Solidity SMTChecker: https://docs.soliditylang.org/en/latest/smtchecker.html
- Rust compiler overview: https://rustc-dev-guide.rust-lang.org/overview.html
- Rust HIR: https://rustc-dev-guide.rust-lang.org/hir.html
- Rust MIR: https://rustc-dev-guide.rust-lang.org/mir/index.html
- Go SSA: https://pkg.go.dev/golang.org/x/tools/go/ssa

### Static, dynamic, and formal security tools

- Slither: https://github.com/crytic/slither
- Echidna: https://github.com/crytic/echidna
- Certora rules: https://docs.certora.com/en/latest/docs/cvl/rules.html
- Certora invariants: https://docs.certora.com/en/latest/docs/cvl/invariants.html
- Certora coverage: https://docs.certora.com/en/latest/docs/prover/checking/coverage-info.html
- Certora mutation testing: https://docs.certora.com/en/latest/docs/prover/checking/mutation.html
- Certora sanity checks: https://docs.certora.com/en/latest/docs/prover/checking/sanity.html
- Secure Contracts program analysis: https://secure-contracts.com/program-analysis/

### Corpora and benchmarks

- Solodit overview: https://docs.cyfrin.io/solodit/overview
- Solodit finding search: https://docs.solodit.cyfrin.io/findings-explorer/search-for-a-finding
- Solodit content repository: https://github.com/solodit/solodit_content
- EVMbench announcement: https://openai.com/index/introducing-evmbench/
- EVMbench repository: https://github.com/paradigmxyz/evmbench
- Cyfrin audit checklist: https://github.com/Cyfrin/audit-checklist/blob/main/checklist.json
- EthTrust Security Levels: https://entethalliance.org/groups/EthTrust/

### Public LLM audit systems

- Pashov skills: https://github.com/pashov/skills
- Pashov Solidity Auditor V3 results: https://www.pashov.com/solidity-auditor-v3
- Krait methodology: https://github.com/ZealynxSecurity/krait/blob/main/METHODOLOGY.md
- Grego: https://grego.ai/

---

## 30. Repository evidence map

The following areas should be rechecked against the current branch before implementation because line numbers can move:

- scripts/plamen_driver.py — stage orchestration, worker builders, resume behavior, post-verification wiring, report assembly;
- scripts/plamen_types.py — phase definitions, schemas/contracts, semantic versus shard phase representation;
- scripts/plamen_validators.py — artifact validation, R10, report and lifecycle gates;
- scripts/plamen_mechanical.py — mechanical graph consumers, generators, reconciliation, and gate logic;
- scripts/mechanical_verify.py — proof/test integrity logic;
- scripts/recon_prepass.py — EVM, Move, Daml, Rust, Go, and SCIP graph construction/fallbacks;
- rules/phase4-confidence-scoring.md — confidence and promotion semantics;
- rules/post-audit-improvement-protocol.md — mechanical-gate qualification and R10 carve-out;
- prompts/shared/v2/phase3-breadth.md — actual breadth worker binding;
- agents/skills — ecosystem/injectable skill structures and step checklists;
- private regression target scratchpad — PRIVATE-FINDING-001/PRIVATE-FINDING-005 lifecycle, external research ledger, depth/inventory/verification/report artifacts.

Any implementation RFC should cite current branch lines rather than relying on baseline line numbers in the earlier reports.

---

## 31. Revision note

This synthesis incorporates the completed R10 verdict:

- R10 is accepted as a precision-conscious visibility recovery;
- the fixed ID join and router defects are recognized;
- its validation evidence is recorded;
- it is not credited with restoring the High severity;
- depth-side harm analysis is treated as a separate required lever;
- the long-term architecture subsumes R10 into typed premise/disposition policy only after replay parity.

No proprietary competitor architecture is asserted without public evidence. The recommendation rests on Plamen’s own observed failures and on established engineering patterns from whole-program analysis, policy-as-code, structured result formats, formal methods, fuzzing, and resumable workflow systems.
