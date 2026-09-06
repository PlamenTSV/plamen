# Design review: Plamen audit pipeline

Reviewed repository commit: `795962b96e254f2e423a2635fe7f8cb8ea1e6d69`

## Executive verdict

The high-level `discover → verify → report` decomposition is sound. The implementation is not yet recall-safe or proof-sound enough to support its stated guarantees.

The most serious problem is architectural: findings are represented as mutable Markdown moving through a mostly linear phase sequence. That makes lifecycle completeness an emergent property of hundreds of parsers, prompts, gates, receipts, and phase-order assumptions. The two dominant empirical failures—non-application and found-then-lost—are exactly what this representation encourages.

Where documentation and executable phase definitions disagree, this review treats code as authoritative. Raw run telemetry and the benchmark corpus were not available, so empirical performance claims are assumed rather than independently reproduced.

### Highest-priority defects

| Priority | Finding | Consequence |
|---|---|---|
| P0 | Gate P creates new `NEEDS_VERIFICATION` candidates after depth, chain, and verification have completed. | A candidate may reach reporting without the promised independent verification. |
| P0 | Non-executed or ambiguous PoCs can retain `[POC-PASS]` and therefore `VERIFIED` status. | “Only executed PoCs are proof-grade” is false in the current implementation. |
| P0 | Resume state authenticates output artifacts, but apparently not the audited source snapshot or each phase’s inputs. | A resumed audit can mix analysis of different code states. |
| P1 | Disk markers are written by the worker being judged. | The system has converted model self-report into structured self-report, not eliminated it. |
| P1 | Confidence combines correlated, self-generated signals and historical similarity; confidence is monotonic. | Novel true findings are penalized, familiar claims are over-rewarded, and disconfirming evidence cannot lower confidence normally. |
| P1 | Mechanical “completeness” is bounded by regexes, feeder globs, approximate graphs, location windows, and silent caps. | Determinism is being mistaken for semantic completeness. |
| P1 | The L1 pipeline removes chain analysis because L1 bugs are assumed to be point vulnerabilities. | Cross-layer, temporal, consensus/network/storage compositions are systematically under-served. |

---

## 1. Methodology soundness

The shape is conditionally sound:

1. Generators maximize candidate recall.
2. Independent discriminators test validity.
3. Reporting projects verified dispositions without changing them.

Plamen violates conditions 2 and 3 in several places.

### The candidate lifecycle is not closed

Gate P’s own driver comment says it appends fresh `NEEDS_VERIFICATION` candidates after `report_index_coverage_seed.md` exists. Its call site also states that depth, chain, and verify have already completed. It backfills those new IDs into report-index coverage, but there is no remaining verification pass. This contradicts the internals’ claim that every mechanical candidate passes through the normal chain/verify/report path. See the [Gate P implementation contract](https://github.com/PlamenTSV/plamen/blob/795962b96e254f2e423a2635fe7f8cb8ea1e6d69/scripts/plamen_driver.py#L4019-L4035) and its [report-index call site](https://github.com/PlamenTSV/plamen/blob/795962b96e254f2e423a2635fe7f8cb8ea1e6d69/scripts/plamen_driver.py#L19373-L19401).

The same defect is explicit in `post_verify_extract`: new verifier observations are promoted after verification and “NOT re-queued for verification.” A regression test deliberately locks in that behavior. See the [phase definition](https://github.com/PlamenTSV/plamen/blob/795962b96e254f2e423a2635fe7f8cb8ea1e6d69/scripts/plamen_types.py#L1437-L1447) and [test contract](https://github.com/PlamenTSV/plamen/blob/795962b96e254f2e423a2635fe7f8cb8ea1e6d69/scripts/test_post_verify_extract_wiring.py#L101-L115).

The correct invariant is:

> No reportable candidate may be created unless the scheduler automatically creates every missing downstream obligation for it.

“Verification phase completed” should mean the candidate ledger has reached a fixed point, not merely that one phase ran.

### Proof-grade status is unsound

The integrity classifier preserves an upstream proof tag when execution is unavailable, skipped, or ambiguous. It also preserves `[POC-PASS]` after `NO_TEST_FILE` when the verifier’s prose contains any recognized assertion token. That check is syntactic—it recognizes `assert!`, `assertEq`, `expectRevert`, and similar strings—but does not establish that the assertion tests the claimed harm. See [`_classify_integrity`](https://github.com/PlamenTSV/plamen/blob/795962b96e254f2e423a2635fe7f8cb8ea1e6d69/scripts/mechanical_verify.py#L1490-L1617).

Downstream, any occurrence of `[POC-PASS]` is proof-grade, and a confirmed verdict plus that boolean becomes `VERIFIED`. See the [evidence-tag and canonical-status functions](https://github.com/PlamenTSV/plamen/blob/795962b96e254f2e423a2635fe7f8cb8ea1e6d69/scripts/plamen_types.py#L175-L210).

A local unit-level probe confirmed:

- `TOOLCHAIN_UNAVAILABLE + [POC-PASS]` remains proof-grade.
- `NO_TEST_FILE + assert!(...) + [POC-PASS]` remains proof-grade.
- A compile failure is correctly demoted.

Even a genuinely executed passing test is insufficient by itself. The verifier creates both the claim and its oracle, so a tautological, mis-scoped, or self-fulfilling harness can pass. Proof-grade should require a machine attestation tied to:

- Immutable source and test hashes.
- Exact command, environment, exit status, and isolated test identity.
- An independently reviewed harm oracle.
- At least one negative or mutation control showing the test fails when the alleged defect is removed or the critical condition is reversed.

Unavailable execution may preserve `CONFIRMED_BY_CODE_TRACE`; it must never preserve `VERIFIED_BY_EXECUTION`.

### Structurally under-served vulnerability classes

The pipeline is strongest on code-local state and data-flow bugs. It is weaker where the security property does not exist in the code itself:

- Economic and mechanism-design failures.
- Market, liquidity, oracle, or incentive assumptions.
- Governance operations, key management, deployment, migration, initialization, and upgrade procedures.
- Cross-chain and off-chain components, relayers, front ends, keepers, signers, and monitoring.
- Temporal and concurrency behavior: reorgs, finality, asynchronous queues, races, retries, and partial failure.
- L1 compositions across consensus, networking, mempool, storage, state sync, VM, and RPC layers.
- Cryptographic protocol correctness and compiler/runtime divergence.
- Multi-transaction and multi-component sequences longer than pairwise chain matching or bounded fuzz depth.
- Specification omissions: code cannot reveal behavior that stakeholders intended but never documented.

Requiring a PoC for all serious conclusions also under-serves architectural, liveness, specification, and operational findings that may be valid without a compact executable exploit. PoC execution should be an evidence class, not the sole validity ontology.

---

## 2. Architecture correctness

### What is sound

The driver provides useful operational properties:

- Idempotent phase execution.
- Bounded retries.
- Per-worker output ownership.
- Crash recovery.
- Artifact provenance hashes.
- Isolation of worker write scopes.
- Deterministic set reconciliation where the input universe is trustworthy.

These are valuable workflow-engine properties.

### Where it is fragile

#### Disk completion is still model self-report

The worker writes the artifact, its owner marker, its completion marker, and much of the content that validators inspect. The gate verifies presence, marker shape, and selected fields—not that the required reasoning was actually performed. The architecture explicitly describes the marker envelope as part of the worker output contract. See the [disk-gate design](https://github.com/PlamenTSV/plamen/blob/795962b96e254f2e423a2635fe7f8cb8ea1e6d69/docs/architecture.md#L245-L287).

This is better than trusting a chat “done” message, but it solves premature process termination, not methodology non-application.

Application needs externally checkable receipts: functions inspected, paths traced, properties instantiated, tool runs performed, counter-hypotheses considered, and evidence references. Even those receipts prove coverage activity—not analytical correctness—so random independent audits of receipts remain necessary.

#### Markdown is being used as a transactional database

Stable identity, lifecycle state, provenance, deduplication, verification, severity, and report routing are encoded across mutable Markdown blocks, regexes, sidecars, receipts, and content hashes. That creates:

- Parser drift and alias proliferation.
- Identity collisions and fragile remapping.
- Phase-order dependence.
- Non-atomic multi-artifact updates.
- Late-candidate problems.
- Difficulty expressing invariants such as “every candidate has exactly one terminal disposition.”

The 22,280-line driver and 11,177-line mechanical module are symptoms of the state model being embedded in orchestration code.

#### Resume lacks input invalidation

The checkpoint records completed/degraded phase names and configuration. Artifact state records ownership and hashes of outputs. I did not find an equivalent immutable snapshot ID or source-tree/input hash that invalidates completed phases when audited code, dependencies, configuration, or upstream artifacts change. See [Checkpoint](https://github.com/PlamenTSV/plamen/blob/795962b96e254f2e423a2635fe7f8cb8ea1e6d69/scripts/plamen_types.py#L831-L935) and [artifact ownership validation](https://github.com/PlamenTSV/plamen/blob/795962b96e254f2e423a2635fe7f8cb8ea1e6d69/scripts/plamen_validators.py#L2772-L2842).

Every task needs an input digest containing:

- Audited commit/tree hash.
- Included dependencies and lockfiles.
- Toolchain/container versions.
- Prompt/methodology version.
- Upstream artifact hashes.
- Task configuration and random seed where relevant.

A mismatch must invalidate the task and all descendants.

#### “Haltless” is semantically ambiguous

The documentation’s actual driver loop is repair → degrade → halt for critical phases, while late-stage paths degrade. The implementation can also prompt interactively after a critical failure. That differs from a global haltless principle.

More importantly, continuing is safe only if the final product says `COMPLETE_WITH_GAPS`, enumerates every missing obligation, and prevents degraded evidence from being rendered as conclusive. Availability of a report is not more important than honesty about its assurance level.

### Cleaner architecture

```text
Immutable audit snapshot
        ↓
Typed ecosystem index + declared specifications
        ↓
Append-only candidate/event ledger
        ↓
Scheduler creates missing obligations
  explore → verify → oracle-review → disposition
        ↖ late/new candidate automatically loops back
        ↓
Root-cause consolidation view
        ↓
Report projection
```

Use a transactional database or append-only event store as the source of truth. Markdown should be a rendered view.

Each candidate should receive one immutable ID and lifecycle:

`GENERATED → TRIAGED → EXPLORED → VERIFIED | REFUTED | UNRESOLVED → CONSOLIDATED → REPORTED | APPENDIX`

Every transition should record actor, evidence, input hashes, reason, and timestamp. Dispositions are appended, not overwritten. A workflow engine can then schedule tasks from state queries rather than hard-coded phase position.

---

## 3. Prior-art and competitor comparison

### Leading human audits

OpenZeppelin describes confirming an exact commit, reviewing documentation and architecture, holding pre-audit and kickoff discussions, assigning at least two auditors to the same code, maintaining client check-ins, and performing fix review. Those interactions supply intent and resolve ambiguities that an autonomous code-only pipeline cannot infer. [OpenZeppelin audit process](https://www.openzeppelin.com/news/what-is-a-smart-contract-audit-lessons-from-openzeppelins-1000-audits)

Trail of Bits describes tailored, multidisciplinary assessments combining manual, static, and dynamic analysis, client communication, threat modeling, and specialists in blockchain, systems, and cryptography. [Trail of Bits software assurance](https://www.trailofbits.com/services/software-assurance)

Plamen borrows breadth, specialization, and independent review in form, but not fully in epistemic independence:

- Agents commonly share the same base model, prompt family, generated recon, RAG corpus, and intermediate artifacts.
- There is no equivalent interactive requirements channel.
- Multiple correlated agents are scored as consensus.
- A protocol-specific expert cannot challenge undocumented business assumptions unless those assumptions appear in supplied material.

Borrow: two genuinely independent full-code reviews, an assumption register, scheduled client questions, specialist escalation, and fix-review/differential-review phases.

### Static analysis

Slither operates on a typed intermediate representation and supports precise custom analyses, source localization, and structured code facts. [Slither](https://github.com/crytic/slither)

Plamen’s EVM Slither tier is directionally correct, but fallback regex graphs are not equivalent. Move is currently approximate-only, and Rust/Go can degrade to source parsing. Graph quality must be a first-class confidence and coverage dimension; a fallback cannot silently satisfy the same completeness obligations as a typed index.

### Fuzzing and symbolic/formal verification

Echidna generates stateful call sequences to falsify user-defined invariants and reports coverage. [Echidna](https://github.com/crytic/echidna)

Certora quantifies over unspecified inputs and initial states, returns counterexamples, and provides proof-coverage/vacuity information showing when code or assumptions were irrelevant to a proof. [Certora rules](https://docs.certora.com/en/latest/docs/cvl/rules.html), [coverage information](https://docs.certora.com/en/latest/docs/prover/checking/coverage-info.html)

These approaches capture something agent prose cannot: mechanically explored state spaces relative to explicit properties. Plamen should borrow:

- Property synthesis as a first-class phase.
- Stateful sequence fuzzing in all supported modes where tooling exists.
- Symbolic execution for suitable path-local properties.
- Formal rules for high-value invariants.
- Coverage, vacuity, reachability, and mutation checks.
- Differential and conformance testing across implementations and upgrades.

The hard part remains property quality. That is where humans and LLMs are useful; the checker should remain mechanical.

### Other LLM systems

GPTScan deliberately uses the LLM for semantic recognition, then validates recognized variables/statements using control- and data-flow analysis. [GPTScan paper](https://arxiv.org/abs/2308.03314)

PropertyGPT uses LLMs to generate properties but sends them to a dedicated symbolic prover; its evaluation also found that many apparent “false-positive” properties were valid but absent from the human ground truth. [PropertyGPT paper](https://www.ndss-symposium.org/wp-content/uploads/2025-1357-paper.pdf)

That is a cleaner generator/discriminator boundary than “LLM writes finding and PoC; subprocess observes that its test returned success.”

Recent agent evaluations also report substantial sensitivity to scaffold and dataset contamination, with materially different results on post-training incidents. [Re-Evaluating EVMBench](https://arxiv.org/abs/2603.10795) This directly supports isolating RAG from scoring and maintaining cold, contamination-resistant evaluation sets.

---

## 4. Mechanical deriver/gate layer

The strategy is sound only for obligations with a finite, authoritative universe.

### Where it helps most

Excellent mechanical applications include:

- Every candidate ID must have a terminal disposition.
- Every public entry point must have a coverage record.
- Every verification-queue item must have a machine result or explicit unresolved reason.
- Every report item must trace to source candidates and evidence.
- Every late candidate must receive downstream tasks.
- Interface/implementation and ABI/schema conformance.
- Upgrade storage-layout diffs.
- Read/write, caller/callee, privilege, and event/state-update matrices.
- Paired-operation enumeration when the pairing comes from typed semantics.
- Build, dependency, compiler, source-snapshot, and test-isolation integrity.
- Diffing reviewed and unreviewed code between audit revisions.

These directly address non-application and pipeline loss.

### Where it becomes theater

Gate P scans at most 60 files, harvests at most 12 candidates per file and 30 per run, requires a file:line plus a fixed mechanism vocabulary, and suppresses candidates within a ±30-line window of existing findings. Calling those limits “recall-safe” is incorrect. See the [caps and cue rules](https://github.com/PlamenTSV/plamen/blob/795962b96e254f2e423a2635fe7f8cb8ea1e6d69/scripts/plamen_mechanical.py#L4364-L4431) and [location suppression](https://github.com/PlamenTSV/plamen/blob/795962b96e254f2e423a2635fe7f8cb8ea1e6d69/scripts/plamen_mechanical.py#L4507-L4562).

It will systematically miss:

- Findings without a single source location.
- Novel mechanisms outside its vocabulary.
- Findings in omitted artifact families.
- More than 30 orphans.
- Distinct nearby defects.
- Findings whose raw prose format changed.

Likewise, a deterministic diff over an approximate regex graph is deterministic, but not authoritative. The internals explicitly document approximate fallbacks for Solidity, Move, DAML, Rust, and Go. [Graph providers](https://github.com/PlamenTSV/plamen/blob/795962b96e254f2e423a2635fe7f8cb8ea1e6d69/docs/internals.md#L286-L305)

The better solution to promotion completeness is not better Markdown harvesting. It is minting a structured candidate event at the moment any worker emits one. Gate P should eventually disappear, replaced by a ledger query.

### What cannot be reduced to enumerate/diff

Model or expert judgment remains necessary for:

- Deriving intended properties from ambiguous requirements.
- Economic exploitability.
- Realistic actor incentives and preconditions.
- Cross-system trust assumptions.
- Root-cause equivalence.
- Remediation quality.
- Likelihood and severity.
- Determining whether a passing oracle actually represents material harm.

Mechanical tools can organize evidence for these decisions, but should not pretend to decide them.

---

## 5. Ranked recall improvements

| Rank | Change | Failure side | Expected gain | Complexity |
|---|---|---|---|---|
| 1 | Canonical append-only candidate ledger with mandatory terminal disposition and automatic late-task scheduling | Found-then-lost | Very high | Medium |
| 2 | Freeze source/dependency/toolchain snapshot; hash task inputs and invalidate descendants on change | Pipeline correctness/loss | High | Medium |
| 3 | Add requirements, threat-model, assumption-register, and client-question workflow | Never-found | Very high | Low–medium |
| 4 | Property factory feeding stateful fuzzing, symbolic execution, formal rules, differential tests, and mutation/vacuity checks | Never-found | High | High |
| 5 | Two genuinely independent full-code reviews using different model/tool/context paths | Never-found | High | Medium |
| 6 | Typed AST/IR/indexer support for every ecosystem; expose graph quality and uncovered regions | Never-found | High, especially non-EVM | High |
| 7 | General n-step state-machine/composition analysis, including L1 and cross-domain components | Never-found | High | High |
| 8 | Replace confidence formula with explicit evidence/precondition states; remove RAG from validity scoring | Both | Medium–high | Low |
| 9 | Cold evaluation corpus, retriever denylist, expert adjudication of novel findings | Measurement | High indirect gain | Medium |
| 10 | Explicit overflow queues instead of silent generator/scanner caps | Found-then-lost | Medium | Low |

Measure the stages separately:

- **Discovery recall:** ground-truth findings present in any raw candidate artifact.
- **Retention recall:** true discovered candidates still represented after every transformation.
- **Verification recall:** valid candidates not incorrectly refuted or abandoned.
- **Report recall:** valid candidates represented in body or clearly delivered appendix.
- **Application rate:** required analysis obligations with substantive evidence receipts.
- **Dedup-loss rate:** valid atoms hidden by incorrect consolidation.
- **Novel-valid rate:** expert-confirmed findings absent from the reference report.

A professional report is not exhaustive ground truth. Treating every unmatched pipeline finding as a false positive biases precision downward and rewards imitation. PropertyGPT observed this exact issue: many “false-positive” generated properties were valid but undocumented in the reference set.

---

## 6. Precision and anti-bloat

Recall-safe analysis does not require a bloated client report. Separate the internal candidate universe from the report-item view.

### Candidate consolidation

Preserve all candidate atoms and cluster them without deleting them. Merge into one report root cause only when all three match:

- Same violated security property.
- Same causal defect and remediation boundary.
- Compatible actors, preconditions, and affected state.

Different impact manifestations become child scenarios under the same report item. Different preconditions or fixes remain separate, even when locations overlap.

Location proximity, titles, and embeddings may nominate clusters; they should not decide equivalence.

### Evidence and disposition

Replace overloaded tags with orthogonal fields:

- Execution: `NOT_RUN | EXECUTED_PASS | EXECUTED_FAIL | UNAVAILABLE`.
- Harness: `UNREVIEWED | REVIEWED | MUTATION_VALIDATED`.
- Semantic evidence: `SOURCE_TRACE | SPEC_DEVIATION | FORMAL_COUNTEREXAMPLE | PRODUCTION_STATE`.
- Validity: `CONFIRMED | REFUTED | UNRESOLVED`.
- Confidence: calibrated probability or ordinal judgment.
- Report priority: severity plus remediation urgency.

Remove historical/RAG precedent from confidence. RAG is useful for generating hypotheses, identifying known mitigations, and finding analogous test ideas. It is not evidence that the current code has the defect.

The current confidence formula gives weight to agent consensus, checklist/tags, and RAG similarity, then enforces monotonic confidence. These signals are correlated and partly self-reported; monotonicity prevents new contrary evidence from lowering belief. See the [confidence model](https://github.com/PlamenTSV/plamen/blob/795962b96e254f2e423a2635fe7f8cb8ea1e6d69/rules/phase4-confidence-scoring.md#L8-L77) and [monotonic rescoring rule](https://github.com/PlamenTSV/plamen/blob/795962b96e254f2e423a2635fe7f8cb8ea1e6d69/rules/phase4-confidence-scoring.md#L153-L158).

### Severity

Do not collapse evidence strength into severity. Report separately:

- Impact.
- Reachable actor.
- Preconditions and their plausibility.
- Blast radius.
- Recoverability.
- Evidence strength.
- Confidence.
- Recommended priority.

Use the severity matrix only after validity adjudication. An independent severity reviewer should calibrate against a written ecosystem/client rubric, not against whether similar public findings received a high severity.

---

## 7. Blind spots and what I would do differently

The largest questionable assumptions are:

1. **An autonomous audit can infer enough intent from code and optional documentation.** It cannot. Missing intent is not a reasoning failure; it is missing input.

2. **More role-scoped agents provide independent coverage.** Shared models, recon, prompts, RAG, and artifacts create correlated blind spots. Agent count is not reviewer independence.

3. **An executed PoC is sufficient proof, and a missing PoC limits validity.** Execution proves only what its harness and oracle encode. Some valid architectural findings are not naturally PoC-shaped.

4. **Deterministic gates over approximate artifacts are recall-safe.** They are reproducible heuristics, not completeness proofs.

5. **L1 bugs are point vulnerabilities.** The explicit removal of chain analysis for L1 is backwards: distributed clients are particularly exposed to cross-layer and temporal compositions. See the [L1 phase difference](https://github.com/PlamenTSV/plamen/blob/795962b96e254f2e423a2635fe7f8cb8ea1e6d69/docs/architecture.md#L387-L397).

6. **Confidence should be monotonic.** Sound reasoning must allow confidence to decrease when assumptions fail or contrary evidence appears.

7. **A professional audit report is exhaustive ground truth.** It is a useful reference set, not a complete oracle.

8. **Haltless degradation is inherently recall-safe.** It is safe only when gaps are terminally visible and cannot inherit strong assurance labels.

9. **Documentation and executable configuration will remain aligned.** They already do not: architecture says the axis-coverage meta-pass runs in all modes, while the executable phase definition restricts it to Thorough. See [architecture](https://github.com/PlamenTSV/plamen/blob/795962b96e254f2e423a2635fe7f8cb8ea1e6d69/docs/architecture.md#L131-L145) versus [phase configuration](https://github.com/PlamenTSV/plamen/blob/795962b96e254f2e423a2635fe7f8cb8ea1e6d69/scripts/plamen_types.py#L1295-L1307).

### Single highest-leverage change

Replace the Markdown/phase-centric finding lifecycle with a typed, append-only candidate ledger and obligation scheduler.

That one redesign directly attacks the stated dominant failure:

- Findings cannot silently vanish.
- Deduplication becomes a reversible view.
- Late discoveries automatically trigger verification.
- Every candidate has an auditable terminal disposition.
- Pipeline-loss recall becomes an exact database query.
- Report assembly cannot invent or omit lifecycle state.
- Mechanical gates become simple relational invariants.
- Resume correctness can bind tasks to immutable input hashes.

Immediately before that larger migration, make three stop-ship corrections: remove proof-grade status from every non-executed outcome, requeue all Gate P and post-verification discoveries, and pin the full audited input snapshot.
