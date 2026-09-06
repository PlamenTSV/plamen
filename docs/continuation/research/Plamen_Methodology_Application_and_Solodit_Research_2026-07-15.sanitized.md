<!-- PORTABLE SANITIZED RESEARCH COPY
Source identity: Plamen_Methodology_Application_and_Solodit_Research_2026-07-15.md
Raw bytes remain outside Git. Architecture, methodology, execution, acceptance, and comparison semantics are retained; personal paths, private target identities, target-specific candidate/artifact identifiers, artifact digests, and concrete private finding descriptions use deterministic placeholders. See CORPUS_MANIFEST.json and research/PRIVATE_GAP_INDEX.json for provenance and the redaction rule.
-->

# Plamen methodology application, architecture, and Solodit validation review

**Date:** 2026-07-15  
**Scope:** Current `<PLAMEN_SOURCE_ROOT>` driver/toolchain, the private regression target scratchpad at `<PRIVATE_REGRESSION_SCRATCHPAD>`, the completed R10 gate, public Solodit material, Pashov Solidity Auditor V3, and published benchmark/standards material.  
**Purpose:** Defensive audit-methodology and systems-architecture review only.

## Executive verdict

There are still material architecture, encoding, phase-binding, and methodology gaps to close. The largest newly confirmed problem is not that Plamen lacks prompts. It is that its executable methodology is not a reliable projection of those prompts.

The live smart-contract breadth worker says that `prompts/shared/v2/phase3-breadth.md` contains “breadth audit methodology and vulnerability coverage.” It does not: it is mainly a coordinator/spawn/output protocol. The actual private regression target worker prompts contain that same binding. Therefore recon-selected skill injection—not a universal breadth methodology—is carrying much of breadth recall. A missed recon trigger can silently remove an entire reasoning lens. This is a direct structural cause of the reported “methodology existed but the agent did not apply it” misses.

The second critical result is that the current skill-application checker is not a trustworthy control. It tells an agent to “read the skill name and recall its core analysis steps,” then infer execution from prose in other agents' outputs. In private regression target it announced 22 EXECUTED, zero PARTIAL, and zero NOT_EXECUTED, even though it had not been hard-bound to the standalone checklist prompt and did not read the actual skill files as its declared method. That is coverage theater: an LLM certifying another LLM's compliance from similar prose.

The recommended typed event ledger, obligation compiler, and demotion-premise closure directly attack the two dominant empirical failures, but they are not sufficient alone:

1. An append-only finding/evidence ledger closes found-then-lost transitions.
2. Source-derived `(method_id, target_id)` obligations close a large part of non-application.
3. A premise/evidence ledger closes the general class represented by R10: safety or demotion based on an ungrounded assumption.
4. A continuously held-out finding corpus is still required to detect methodology classes that are absent, weak, or incorrectly scoped.

It is not possible to establish that Plamen covers “all possible bug classes.” Security review is open-world, and even the EEA EthTrust specification explicitly says no review can guarantee absence of all vulnerabilities. It is also not currently supportable to claim that Plamen has a methodology edge and only an enumeration problem. The public evidence shows substantial methodology strength, but also some under-served reasoning domains and at least one live baseline-method binding defect.

The single highest-leverage architectural change remains: **compile a small, versioned semantic methodology into source-derived obligations, execute those obligations through typed work items, and preserve every candidate and disposition in an append-only state store. Markdown becomes a rendered view, not machine state.**

## Priority findings

### P0 — The breadth workers are bound to the wrong kind of methodology document

Evidence:

- `scripts/plamen_driver.py:7608-7612` selects `prompts/shared/v2/phase3-breadth.md` as the smart-contract breadth methodology.
- `scripts/plamen_driver.py:7707-7714` describes that file as “breadth audit methodology and vulnerability coverage.”
- The referenced document's headings are Spawn Rule, Discovery Stance, Post-Spawn Verification, Subagent Prompt Template, Output Conventions, Context Protection, and termination/scope contracts. It is primarily orchestration protocol, not a generic security reasoning kernel.
- The driver itself acknowledges at `scripts/plamen_driver.py:7663-7669` that R13 lived only in `generic-security-rules.md` and “was never surfaced to the breadth worker,” then injects only that rule as a special case.
- Every inspected private regression target `_prompt_breadth_worker_*.md` repeats the same incorrect methodology declaration.

Consequences:

- Baseline roles such as core-state, access-control, or `GENERAL` do not have an independently guaranteed universal semantic floor.
- Coverage depends on recon choosing the correct skill and instantiate binding it to the correct role.
- Regex/custom-name/macro/generated-code misses in recon are now class-level routing misses, not merely prioritization errors.
- Fixing individual rules such as R13 does not fix the architecture; it creates an expanding series of prompt patches.

Required correction:

- Every breadth job must receive an explicit, machine-generated methodology manifest.
- A concise universal semantic kernel must always be present, independent of recon.
- Recon may add conditional scenario packs; it must not be able to remove the universal floor.
- The driver must fail the job into `coverage_unknown/human_review`, not silently continue, if a required method card does not resolve.

### P0 — “Skill executed” is presently inferred rather than observed

Evidence:

- `prompts/shared/v2/phase4b-skill-checklist.md:27-33` tells the checker to identify steps by reading the skill name and recalling its core steps, then search output prose for evidence.
- The skill library is not normalized around executable step identifiers. Exact `Step Execution Checklist` sections are absent from 4/18 EVM skills, 3/20 Solana skills, 2/22 Aptos skills, 2/22 Sui skills, 2/19 Soroban skills, 1/12 Daml skills, 24/33 injectable skills, and all 9 niche skills.
- The three Thorough side jobs—design stress, perturbation, and skill-execution checklist—are all categorized as `sidecar` (`scripts/plamen_driver.py:9439-9460`). `_build_depth_worker_prompt` has dedicated branches for standard, fuzz, niche, scanner, and sibling roles, but sidecars fall through to a generic block at `scripts/plamen_driver.py:10643-10649`.
- The saved private regression target skill-checker prompt does not directly bind `phase4b-skill-checklist.md`; it only points at the full depth coordinator document.
- The private regression target output says its method was to “recall” each skill's core steps and reports 22 EXECUTED, 0 PARTIAL, 0 NOT_EXECUTED. That is not independent execution evidence.

Required correction:

Each method must be compiled to a schema such as:

```text
method_id
method_version
trigger_predicate
target_enumerator
analysis_operator
required_evidence_fields
allowed_na_predicate
output_relation
routing_policy
```

Before workers run, deterministic source adapters enumerate concrete targets. A required unit is `(run_id, method_id, target_id)`. The only valid terminal transitions are:

- `reported(finding_id, evidence_refs)`
- `dismissed(evidence_refs, premise_refs)`
- `carried(work_item_id)`
- `not_applicable(predicate_id, evidence_refs)`

“Executed: yes,” output-file presence, generic tags, or an LLM's recollection must never satisfy a unit. A carried unit is not complete until the named work item reaches a terminal state.

### P0 — Markdown/regex is being used as a database and a type system

The production Python surface is approximately 80,000 lines across driver, validators, parsers, mechanical logic, prompts, types, and contracts. The driver alone contains hundreds of broad exception handlers and reads mutable Markdown with `errors="replace"` throughout. Validators and mechanical logic use hundreds of regular-expression operations against free-form documents.

This is not an objection to regex itself. Regex is appropriate for lexical recall generators and compatibility parsing. It is inappropriate as the authoritative representation of:

- finding identity;
- parent/child and dedup relations;
- evidence provenance;
- verdict/severity transitions;
- queue membership;
- obligation completion;
- carried-work closure;
- whether a proof actually executed.

`scripts/plamen_contracts.py` defines useful Pydantic contracts such as `SpawnManifest`, but no production module imports those models; current references outside tests are comments. Typed contracts therefore do not yet protect the live path.

Required correction:

- Use SQLite or an append-only JSONL/event store as canonical state.
- Validate all events with versioned Pydantic models.
- Generate Markdown views from canonical records.
- Treat an invalid structured transition as quarantined human review. “Haltless” must not mean “accept an unreadable transition as valid.”
- Keep regex-based Markdown ingestion only as a migration/compatibility boundary.

### P0 — Found-then-dropped needs one canonical lifecycle, not more reconciliation sidecars

The current architecture attempts to repair loss with multiple inventories, queues, promotion harvests, identity sidecars, dedup maps, verification files, report indexes, cross-batch checks, and report floors. Those controls are sensible locally, but the number of representations creates the failure surface they are intended to police.

Use one immutable finding identity from first observation:

```text
candidate_observed -> analyzed -> verified/contested/refuted
                   -> severity_assessed -> report_dispositioned
                   -> rendered
```

Every transition is appended with actor, method, evidence, premises, timestamp, input hashes, and predecessor event. No stage deletes or rewrites a finding. Dedup creates `same_root_as` / `subsumed_by` edges; it does not erase a node. Report rendering is a query over terminal state. A finding may be hidden from the main body only through an explicit, reviewable disposition event.

This directly addresses the empirically dominant pipeline-loss half.

### P0 — False-safe reasoning needs a general premise gate, not only R10

R10 is a useful, well-tested local control. The completed commits add 15 focused fixtures, pass the broad fast-lane, and correctly join hypothesis IDs to inventory constituents. The current code also accurately records its limitations:

- It restores the queue-claimed severity, not the missed High severity.
- For the private regression target rate finding, that floor is Low.
- It stamps `[UNPROVEN-EXTERNAL]` and keeps the item in-body.
- `plamen_validators.py:21435-21444` explicitly states that it cannot re-verify in the same run and leaves queue re-emission as future work.

Therefore R10 is a precision-safe visibility improvement, not full recovery of PRIVATE-FINDING-001. The remaining error is depth-side impact/severity assessment.

Structurally, R10 should become one policy in a general premise ledger:

```text
claim: finding F is safe / unreachable / Low / refuted
premise: P
premise type: in-scope code | external behavior | configuration | deployment | economic assumption
evidence: source/test/citation/build/deployed-state reference
status: grounded | contradicted | unknown
```

Any safety-reducing transition that depends on an unknown premise is vetoed into `contested/human_review`. This generalizes beyond external stability to assumed initialization, role setup, token behavior, liveness, compiler/deployment conditions, cross-chain ordering, and economic behavior. Retain R10 now, but do not grow a forest of R11/R12 prose detectors.

### P1 — The phase graph confuses semantic stages with implementation shards

`SC_PHASES` currently contains 73 `Phase` objects. Many are queue shards or report-tier implementation units: ten High, ten Medium, ten Low verification shards; multiple report body/merge/dedup/disposition/floor stages; and several repair/meta-passes.

This is over-engineered because resumability is being modeled through a long static phase list. A cleaner system has roughly these semantic stages:

1. bake/source model;
2. reconnaissance/specification;
3. obligation generation;
4. parallel analysis work queue;
5. composition/path analysis;
6. evidence verification;
7. independent disposition/severity;
8. report rendering;
9. benchmark/telemetry export.

Verification and reporting shards are work items inside stages, not separate phase types. Their retry/resume state belongs in the work-item store. Convergence should depend on unresolved obligations and open evidence premises, not finding-count deltas or fixed iteration caps.

### P1 — Composition analysis is pairwise and pre-filter constrained

`phase4c-chain-agent2.md` instructs the agent to analyze only pairs in `chain_candidate_pairs.md`, and to exclude all unlisted pairs as having no shared state/type. That is unsafe as a completeness statement. Meaningful chains can be:

- three or more hops;
- connected through actor capability, value provenance, time/order, configuration, or external dependency rather than a shared identifier;
- composed from individually Low enablers;
- lexically disconnected across adapters and domains.

Replace pair-only Markdown analysis with a typed relation graph and bounded path search over relations such as `writes`, `reads`, `authorizes`, `calls`, `prices`, `mints`, `burns`, `configures`, `finalizes`, `depends_on`, and `shares_actor`. Enumerate 2–4-hop paths with risk-guided pruning, then ask agents for semantic judgment. Mechanical enumeration proposes candidates; it does not claim vulnerability.

### P1 — `security_obligations.md` is a useful prototype but not an obligation compiler

The existing mechanical rules at `scripts/plamen_mechanical.py:6860-6901` cover only eight classes: asset binding, swap execution, refund/revert, cross-domain message, native/wrapped asset, external calls, privileged exits, and encoding schema.

They are triggered by regex over recon, graph, inventory, and static-analysis Markdown, each file truncated to 120,000 characters. If recon omitted a feature, the obligation generator can omit it too. In private regression target all eight fired, but trigger snippets include irrelevant tool/path prose. Receipts are telemetry and are not required for phase completion. Several Scanner A receipts use `STATUS:D` while saying the concern is “owned by” or “carried” to another depth output; those should be `C` transitions with a target work item.

Keep this sidecar as a precursor, but rebuild obligations from source adapters and the mechanical reference graph. Text signals can add candidates; they cannot be the only feature detector or closure mechanism.

### P1 — Universal methodology is duplicated, uneven, and sometimes cross-domain

Per-ecosystem generic rule files range from roughly 459 to 816 lines. Shared R-rules are copied and adapted across trees; Soroban has 16 where other trees have 17. That violates the anti-bloat single-source principle and invites semantic drift.

`agents/depth-state-trace.md` also contains an always-on node-client cache lifecycle set-cover section, including L1-specific consensus/client examples, while the same role runs in smart-contract audits. Its broad cache/map/set trigger risks spending contract-analysis attention on an L1-specific method.

Required correction:

- One concise universal semantic kernel.
- Ecosystem adapters define source enumerators and evidence extraction, not duplicate universal prose.
- Protocol/scenario packs remain conditional.
- L1-only methods are bound only to L1 work items.

## A compact methodology that avoids prompt bloat

The core should be semantic operators, not a growing vulnerability checklist. A practical universal kernel is:

1. **Authorization/capability binding** — who may cause each effect, including delegated and indirect authority.
2. **Value conservation/entitlement** — assets, shares, debt, fees, rewards, and claims across every transition.
3. **State-transition completeness/reversibility** — all lifecycle legs, error paths, cancel/recover/migrate paths, and coupled stores.
4. **Input/output/identity binding** — values checked in one context must be the values used in the effecting context.
5. **Temporal freshness/order/finality** — stale state, expiry, epochs, reorg/finality, transaction ordering, multi-step windows.
6. **External/adversarial behavior** — callbacks, return values, nonstandard tokens, dependency failure, boundary trust.
7. **Numeric/dimensional/boundary reasoning** — scale, sign, rounding, overflow, zero/extreme values, monotonicity.
8. **Uniqueness/replay/idempotency** — nonces, identifiers, duplicate processing, retries, cross-domain replay.
9. **Liveness/resource/recovery** — unbounded work/storage, blocked queues, griefing, recovery and progress guarantees.
10. **Upgrade/configuration/deployment parity** — initialization, roles, parameters, compiler/linking, source-to-bytecode and proxy state.
11. **Composition/cross-domain semantics** — multi-contract, multi-transaction, cross-chain and off-chain components.
12. **Incentive/MEV/game-theoretic behavior** — ordering, manipulation, sybil/collusion, externalized cost, liquidation and auction incentives.

These operators are short. Their target enumeration is ecosystem-specific and deterministic. Conditional cards then add standards, cryptography/proofs/randomness, AMMs, lending, governance, bridges, account abstraction, ZK, privacy, or node-client consensus when the source model supports the trigger.

This design is smaller than today's duplicated prose while being more observable. Workers receive only the applicable cards and concrete target IDs, but the universal twelve are always represented in the obligation matrix.

## Are current methodologies complete?

No. They are broad and often strong, but completeness has not been demonstrated and cannot be inferred from skill count.

### Strong or well-represented today

- token/value-flow and vault/share accounting;
- lifecycle/state tracing and paired-operation asymmetry;
- input, authorization, and ecosystem account/type validation;
- boundary and numeric reasoning;
- external dependency/integration hazards;
- cross-chain message/serialization/timing;
- upgrade/storage migration and oracle/staleness methods;
- numerous ecosystem-specific Solana, Move, Soroban, Daml, and L1 concerns.

### Present but not reliably guaranteed

- signature/replay/proof semantics: the signature niche is substantive, but trigger/application remains feature-routing dependent;
- standard/interface conformance: dedicated packs exist for some standards, but there is no universal conformance obligation over every implemented/consumed interface;
- events/off-chain behavior: event methods exist, but keepers, relayers, indexers, and operational state are not modeled as first-class system components;
- MEV/economic/game-theoretic reasoning: many skills mention these concepts, but no universal source-derived obligation ensures application;
- deployment/build/compiler/deployed-state parity: discussed in places, not a first-class audit object for all ecosystems;
- cryptographic proofs, randomness, privacy, and ZK: covered in selected niches/ecosystems, not as a general trigger→target→receipt system;
- multi-hop semantic composition: pairwise chain analysis is not enough.

### Structural classes that source-only review cannot settle

- actual proxy implementation and initialized storage;
- production roles, parameter values, allowlists, and dependency addresses;
- exact compiler/optimizer/linker settings and source-bytecode parity;
- off-chain relayer/keeper/indexer behavior;
- external dependency contracts not present in scope;
- economic assumptions requiring market/state data;
- undocumented intended behavior where code-derived invariants are circular.

These require an explicit environment/deployment evidence pack or an `unknown premise` disposition, not a safety conclusion.

## What the Solodit comparison can and cannot establish

Solodit is suitable as one corpus source, not as a completeness oracle. Its documentation says it aggregates over 20,000 findings and supports filters for source, severity, protocol category, date, rarity, and quality. The public `solodit_content` repository is a smaller, skewed subset and explicitly accepts community/custom report imports.

I cloned public commit `a8ab1ebc...` dated 2026-07-04. The snapshot contained 618 Markdown audit reports from 16 firms. Parsing severity sections yielded 5,105 Critical/High/Medium/Low finding headings: 34 Critical, 1,003 High, 1,644 Medium, and 2,424 Low. The corpus is heavily skewed toward Zokyo, Cyfrin, and Pashov reports and is mostly EVM-oriented.

A broad multi-label keyword pass—not a ground-truth classifier—found substantial populations for accounting, liveness/DoS, lifecycle/time, validation/data structures, numerics, AMM, staking/rewards, governance/configuration, authorization, events/off-chain behavior, standards/interfaces, oracle behavior, MEV/order, upgrades, deployment/build, external calls/tokens, signatures/crypto, and cross-chain behavior. Even title-only High/Medium scans produced many MEV/order, deployment/initialization, standards/interface, off-chain, proof/replay, liveness, and temporal findings.

That result does **not** prove a Plamen miss. It proves these domains need explicit coverage labels and held-out evaluation. A methodology may express a finding without a dedicated skill filename; conversely, a skill may exist but never be scheduled or executed.

For every corpus finding, label four separate states:

1. **Expressible:** at least one method card contains the necessary reasoning operator.
2. **Scheduled:** the driver generated the required method-target work item from the hidden source.
3. **Applied:** the worker produced evidence addressing that work item.
4. **Preserved:** a correct candidate survived verification, dedup, severity, and reporting.

Only this decomposition can distinguish methodology gaps from enumeration, reasoning, false-safe demotion, and pipeline loss.

Public sources used:

- [Solodit overview](https://docs.cyfrin.io/solodit/overview)
- [Solodit search/filter fields](https://docs.solodit.cyfrin.io/findings-explorer/search-for-a-finding)
- [Public Solodit content repository](https://github.com/solodit/solodit_content)
- [Cyfrin audit checklist](https://github.com/Cyfrin/audit-checklist/blob/main/checklist.json)

## Competitor evidence and what it really says

### Proprietary systems

Do not assume Solace, Grego AI, or another proprietary product uses the proposed architecture. Public claims are not enough to infer internal state management, independence, coverage guarantees, or benchmark hygiene.

Grego's public site claims AST/IR parsing, call/dataflow graphs, invariants, and state-transition analysis. That is directionally consistent with the recommendation to ground target enumeration in source structure, but it reveals nothing about typed finding lifecycle, negative-verdict audit, or evaluation methodology. Solace has no public architecture or reproducible benchmark sufficient for this comparison. A creator's statement that methodology was “leached” and improved is a useful competitive signal, not evidence of coverage or architecture.

### Pashov Solidity Auditor V3 is a concrete counterexample

The open V3 at commit `c577eb7...` is architecturally much simpler than Plamen:

- concatenate all in-scope Solidity source into each agent bundle;
- run 12 parallel agents once;
- nine use direct specialties such as math, access, economic, trace, invariant, boundary, and asymmetry;
- three are explicit seam hunters: numerical-gap, trust-gap, and flow-gap;
- all share a short Feynman/Socratic/inversion discipline;
- dedup and four validation gates occur in one final pass.

This is closer to the proposed compact semantic kernel and seam-operator model than to a 73-phase disk-artifact pipeline. It reduces navigation and method-binding failure by giving every worker source + SOP + specialty in one immutable bundle. It does not provide Plamen's execution-backed verification, multi-ecosystem reach, resumability, or mechanical lifecycle controls, and its marker requirements are still LLM-generated evidence rather than a typed obligation ledger.

Pashov's June 2026 article reports V3 leading Plamen on four codebases. Treat this as a serious reproduction target, not a settled result:

- the page says 14/17 private acceptance target A findings (82.4%) in one place, while its chart reports 68.6% for V3 in another;
- it says more than 150 experimental runs, creating benchmark-selection/overfitting risk;
- it does not publish run artifacts, exact commits/configurations, multiple-seed distributions, or independent adjudication;
- Plamen Core is shown only for one codebase while Light is used for others.

Nevertheless, the result invalidates complacency. A much smaller system may outperform Plamen by making reasoning operators direct, source context complete, and seam analysis explicit.

Public sources:

- [Pashov Solidity Auditor V3 methodology and results](https://www.pashov.com/solidity-auditor-v3)
- [Pashov open skills repository](https://github.com/pashov/skills)
- [Grego AI public architecture claims](https://grego.ai/)

## Research-backed benchmark program

No architecture should be trusted from one private regression target replay or one vendor chart. Use this promotion protocol.

### Corpus construction

- Populate the authenticated Solodit API and collect a stratified sample by year, firm/source, severity, protocol category, rarity, and quality.
- Deduplicate report revisions and same-root-cause copies.
- Add non-EVM professional reports for Solana, Move/Aptos/Sui, Soroban/Stellar, Daml, and Go/Rust node clients; Solodit alone cannot validate those ecosystems.
- Maintain repository, protocol-family, audit-firm, and future-time holdouts.
- Exclude from test sets any findings used to author or revise method cards.
- Include fixed/clean versions and deliberately seeded semantic mutations for precision measurement.

### Ground-truth annotation

Two independent security reviewers should label each finding's minimal reasoning obligations and adjudicate disagreements. Do not label with protocol-specific answers. Label reusable operators, required target relations, environmental premises, and evidence needed.

### Replay and ablation

Run the exact vulnerable commit with the report hidden. Compare, under equal model, token, wall-time, and tool budgets:

1. current driver;
2. current + breadth binding repair;
3. current + source-derived obligations;
4. current + append-only lifecycle;
5. current + premise/demotion closure;
6. combined architecture;
7. direct Pashov V3 baseline;
8. plain frontier-agent baseline;
9. static/fuzz/formal tool ensemble where supported.

Use multiple seeds. Published EVMbench work shows that agents stop early in detection and that detection remains below full coverage; later re-evaluation also reports sensitivity to scaffold and dataset. EVMbench itself uses 117 curated vulnerabilities from 40 audits and explicitly lists single-chain, clean-local-state, timing, and extra-finding grading limitations. Therefore it should be included, not treated as sufficient.

Relevant sources:

- [OpenAI EVMbench introduction and limitations](https://openai.com/index/introducing-evmbench/)
- [EVMbench repository](https://github.com/paradigmxyz/evmbench)
- [EEA EthTrust Security Levels](https://entethalliance.org/groups/EthTrust/)
- [Trail of Bits Building Secure Contracts](https://secure-contracts.com/)

### Required metrics

- root-cause recall and impact-weighted recall;
- expressible/scheduled/applied/preserved recall at each stage;
- false-safe demotion rate;
- found-to-report lineage-loss rate;
- obligation completion and carried-work closure;
- precision on independently adjudicated extra findings;
- same-root fragmentation and report compression ratio;
- severity calibration, separate from evidence confidence;
- run-to-run variance, cost, tokens, and wall time;
- method-card marginal gain through ablation.

Promote a change only with confidence intervals, non-regression constraints, and a future-time shadow set. “Found PRIVATE-FINDING-001 in private regression target” is a regression fixture, not evidence of general recall improvement.

## Ranked implementation plan

| Rank | Change | Dominant failure addressed | Expected gain | Complexity |
|---|---|---|---:|---:|
| 1 | Repair breadth and sidecar methodology bindings; generate explicit per-job manifests | Non-application | Very high | Low |
| 2 | Canonical append-only finding/evidence/disposition ledger | Found-then-dropped | Very high | Medium-high |
| 3 | Compile universal method cards to source-derived `(method,target)` obligations | Non-application and class coverage | Very high | Medium-high |
| 4 | General premise/evidence closure for every safety-reducing verdict | False-safe demotion | High | Medium |
| 5 | Ban synthetic/post-hoc execution receipts; require typed terminal transitions | Non-application | High | Medium |
| 6 | Separate evidence confidence, reachability, impact, likelihood, and report disposition | Under/over-severity | High | Medium |
| 7 | Relation graph + bounded 2–4-hop composition search | Never-found chains | Medium-high | Medium |
| 8 | Deployment/build/environment evidence pack | Source-only blind spots | Medium-high | Medium-high |
| 9 | Root-cause graph dedup after verification | Precision/report bloat | Medium | Medium |
| 10 | Solodit/EVMbench/future-time continuous benchmark | Detects all of the above | Enabling | Medium-high |

### Immediate P0 patch set

Before a major rewrite:

1. Bind breadth workers directly to a concise universal security kernel plus their selected skills.
2. Give every sidecar role its exact standalone methodology path; reject unknown role→method bindings.
3. Change the skill checker from “recall the skill” to “read the exact versioned skill and reconcile required step IDs.” Mark all skills without step IDs as `unmeasurable`, never EXECUTED.
4. Correct obligation `D` versus `C` semantics and require carried target IDs.
5. Add an always-on source-derived universal obligation floor independent of recon.
6. Preserve R10, but surface its output as `premise_unknown`, keep severity confidence separate, and add the depth-side impact reassessment work item.

### Migration sequence

Do not rewrite 80,000 lines in one cutover. Introduce the typed store beside current artifacts:

1. dual-write observations and transitions;
2. compare generated Markdown against current artifacts;
3. switch one lifecycle at a time—finding identity, queue, verification, disposition;
4. make typed state authoritative;
5. retire compatibility parsers and redundant sidecars only after replay parity.

## Direct answers to the user's trust questions

**Are there additional gaps?** Yes. The breadth binding defect, sidecar binding fallthrough, unobservable skill application, Markdown-as-state, pair-only composition, recon-trigger single point, duplicated methodology, deployment/environment omissions, and severity/evidence conflation are material.

**Do the proposed changes directly address methodology application?** Yes, if “obligation compiler” means deterministic source enumeration plus stable method IDs and typed receipts. A generic checklist or another LLM compliance pass does not.

**Are the methodologies known to cover every missed class?** No. Current coverage is broad, but this has not been established. Some important domains are present only conditionally or incidentally. The universal semantic kernel plus held-out corpus is the least-bloated way to improve and measure it.

**Can Solodit prove Plamen has the methodology edge and enumeration is the only weakness?** No. It can falsify and compare coverage hypotheses, but only with hidden-commit replay and four-stage labels. The current public subset is skewed, and Solodit is not a complete multi-ecosystem oracle.

**Can the recommendations be trusted to make the best driver?** They are high-confidence directions because they directly remove observed failure mechanisms. They cannot honestly be guaranteed to produce “the best” system until the ablations beat current Plamen and competitors on held-out, future-time, multi-ecosystem data with equal budgets and independent adjudication.

**Does this structurally cover the completed R10 work?** Yes. R10 is the correct immediate instance of the proposed safety-premise closure, and its tests/replay justify keeping it. Its own reviewed result demonstrates why the general architecture is needed: it prevents disappearance but cannot repair the earlier Low impact rating or re-run verification in the same phase graph. The next lever is not a larger R10 regex; it is typed premise tracking plus an independent impact-reassessment obligation for confirmed mechanisms.

## Final recommendation

Keep Plamen's valuable components—multi-ecosystem source bakes, independent verification, executable evidence, recall-safe promotion harvests, deterministic resume, and rich forensic artifacts. Stop using more Markdown passes to compensate for state and application ambiguity.

The best attainable design is a hybrid:

- Pashov-like direct, concise reasoning operators and seam hunters;
- Plamen-like deterministic source graph, multi-ecosystem adapters, evidence execution, and recall-safe lifecycle;
- a typed append-only state machine underneath both;
- continuously measured coverage against hidden, held-out professional findings.

That architecture targets the actual two-part error distribution: it makes application enumerably complete and makes loss mechanically impossible, while preserving independent verification and giving precision controls explicit evidence rather than prose authority.

