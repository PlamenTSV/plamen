<!-- PORTABLE SANITIZED RESEARCH COPY
Source identity: Plamen_Codex-to-Claude_Implementation_Review_Handoff_2026-07-16.md
Raw bytes remain outside Git. Architecture, methodology, execution, acceptance, and comparison semantics are retained; personal paths, private target identities, target-specific candidate/artifact identifiers, artifact digests, and concrete private finding descriptions use deterministic placeholders. See CORPUS_MANIFEST.json and research/PRIVATE_GAP_INDEX.json for provenance and the redaction rule.
-->

# Plamen Codex-to-Claude implementation review handoff

**Date:** 2026-07-16  
**Implementer/integrator:** Codex  
**Independent reviewer requested:** Claude  
**Scope:** Release-0 application/soundness fixes, R10.1, neutral benchmark control plane, and the P0-P5 experiment campaign  
**Cutover status:** **NOT APPROVED** pending independent review  
**Benchmark status:** B0 mechanics exercised; live B1 benchmark and comparative claims are **NOT EXECUTED / NOT ESTABLISHED**

---

## 0. Executive verdict and claim boundary

The requested engineering is implemented in two clean local worktrees and passes the current deterministic test boundaries:

- production Plamen fast lane: **4,504 passed, 4 skipped, 245 deselected**;
- production Plamen full suite: **4,747 passed, 5 skipped, 1 xfailed**;
- focused Release-0/R10.1 pack: **273 passed**;
- neutral evaluator full suite: **93 passed, 3 subtests passed**;
- isolated private regression target replay: exactly **PRIVATE-FINDING-005, PRIVATE-FINDING-006, PRIVATE-FINDING-007, PRIVATE-FINDING-002** fire, each restored only to its existing Low floor;
- seven additional historical EVM/L1/Solana/Soroban scratchpads produce zero R10.1 fires;
- one additional historical EVM scratchpad produces one structurally qualifying candidate. It is unscored and requires independent adjudication; it is not counted as a false positive or a success;
- the synthetic P0-P5 campaign control path schedules **168 jobs** and emits a schema-valid `B0_TEST_ONLY` receipt.

These results support an **implementation-ready-for-adversarial-review** verdict. They do **not** support any of the following claims:

1. that Plamen now has higher recall or precision on a genuinely held-out corpus;
2. that Plamen beats Pashov V3, Solace, Grego, private semantic-query claim, or another auditor;
3. that the P0-P5 treatments have been run against real repositories under a secure launcher;
4. that all vulnerability classes are covered;
5. that private regression target is benchmark evidence (it is regression-only);
6. that the implementing model has independently certified its own work;
7. that the broader Release-1-through-Release-8 canonical architecture migration has been implemented.

The correct current decision is:

- review Release-0 and R10.1 for cutover;
- review the evaluator as a B0 control-plane implementation and a B1 evidence validator;
- do not publish comparative results until the external B1 prerequisites in Section 10 exist;
- do not begin the finding-ledger migration merely because this packet is green. The benchmark must first measure whether lifecycle loss justifies that migration.

---

## 1. Operating agreement and review independence

The governing handoff is `Plamen_Claude-to-Codex_Implementation_Handoff_2026-07-15.md`.

The applicable invariants are preserved:

1. Codex implemented and integrated the changes. Claude is asked to review and may block cutover.
2. The neutral evaluator is outside the production Plamen tree at `<PRIVATE_EVALUATOR_ROOT>`.
3. private regression target is used only as a regression replay and is not represented in a score or B1 suite.
4. The production driver does not contain the held-out ground truth.
5. No core change has been pushed or cut over by this handoff.

Important qualification: the planned Codex specialist-agent swarm could not run because the available subagents encountered their service usage limit. Codex completed the implementation directly. Deterministic tests are evidence, but they do not substitute for the agreed non-implementing-model review. This packet intentionally asks Claude to perform that review rather than implying it already happened.

The user remains the final human acceptance gate.

---

## 2. Authoritative inputs reviewed

The following files were treated as the design and review inputs. SHA-256 values are included so later edits cannot be mistaken for the reviewed versions.

| File | Bytes | SHA-256 |
|---|---:|---|
| `Plamen_Claude-to-Codex_Implementation_Handoff_2026-07-15.md` | 22,548 | `PRIVATE-HASH-017` |
| `Plamen_Canonical_Architecture_Methodology_and_Implementation_Plan_2026-07-15.md` | 112,624 | `PRIVATE-HASH-008` |
| `Plamen_Deep_Forensic_Architecture_Review_2026-07-15.md` | 58,113 | `PRIVATE-HASH-011` |
| `Plamen_Methodology_Application_and_Solodit_Research_2026-07-15.md` | 33,686 | `PRIVATE-HASH-010` |
| `plamen_methodology_architecture_review.md` | 26,723 | `PRIVATE-HASH-016` |
| `plamen-methodology-review-CLAUDE.md` | 15,158 | `PRIVATE-HASH-004` |
| `Plamen_B0_P0-P5_Dry_Run_Receipt_2026-07-16.json` | 904 | `PRIVATE-HASH-014` |

The canonical plan's research/reference index remains the source bibliography for CodeQL, Joern/CPG, OPA, SARIF, OpenRewrite, compiler IRs, Slither, Echidna, Certora, Solodit, EVMbench, Pashov, Krait, Grego, human-audit practice, and ecosystem-specific AST/IR choices. This implementation packet does not duplicate its 2,975 lines of architectural and research analysis.

---

## 3. Worktree and commit state

### 3.1 Production Plamen

- path: `<PLAMEN_DEVELOPMENT_ROOT>`
- branch: `codex/recall-app-benchmark-r10_1`
- HEAD: `SOURCE-REVISION-003`
- baseline R10 commits already present: `9ca8861`, `5011416`
- worktree: clean
- `git diff --check`: clean
- delta from `9ca8861` through HEAD: **49 files, +11,354 / -670**
- split: tests **+4,552 / -35**; non-test code/docs **+6,802 / -635**

Implementation commits after the R10 baseline:

| Commit | Purpose |
|---|---|
| `816132a` | Bind the breadth semantic kernel and make proof labels honest |
| `4087b4f` | Scope finding-mapping provenance to typed markdown tables |
| `6dfe5f2` | Require exact identifier coverage references and govern gate lifecycle |
| `2aef656` | Bound startup scans and make recovery fixtures hermetic |
| `4c22f8b` | Add mechanical-gate registry/budget governance |
| `bdf1f24` | Preserve hypothesis identity across lifecycle transitions |
| `7b17b69` | Emit durable coverage-shortfall and promotion-overflow receipts |
| `6bb9a79` | Bind audit inputs and expose methodology-application gaps |
| `67a0f85` | Narrow and complete the R10.1 external-demotion veto |

The implementation is materially larger than the handoff's “small Release-0” framing. This is a review risk, not something to hide: `6bb9a79` alone adds broad snapshot, dependency-obligation, graph-health, prompt-binding, and honesty machinery. Claude should review whether the robustness gained justifies the extra surface or whether any part should be split before cutover.

### 3.2 Neutral evaluator

- path: `<PRIVATE_EVALUATOR_ROOT>`
- branch: `main`
- HEAD: `SOURCE-REVISION-001`
- worktree: clean
- `git diff --check`: clean
- repository: 14 commits, 69 tracked files

Commits:

| Commit | Purpose |
|---|---|
| `83b3f0b` | Establish authenticated neutral evaluator control plane |
| `4a3764b` | Localize lifecycle losses and bind score metrics |
| `ebe80a2` | Bind independent reusable-method annotations into cases |
| `0764095` | Compile and measure methodology-application obligations |
| `9a0e9e3` | Add stratified clean and seeded benchmark controls |
| `5e2e960` | Precommit paired benchmark promotion analysis |
| `54e5061` | Authenticate portable B1 publication gates |
| `90a4e89` | Bind experiment factors to distinct artifacts |
| `ad128e0` | Freeze fair P0-P5 campaign schedules |
| `2e1329b` | Analyze authenticated P0-P5 campaigns |
| `7fac81f` | Expose authenticated campaign control CLI |
| `cd22000` | Specify B1 campaign evidence and limitations |
| `7d46541` | Retain explicit B0 P0-P5 dry-run evidence |
| `345d016` | Preserve Student-t intervals above 30 degrees of freedom |

---

## 4. Release-0 requirement-to-evidence matrix

### R0-1: unconditional breadth security-kernel floor

**Implemented:** a compact generic semantic-operator kernel is injected into breadth even when recon selects no skills. Skill material remains additive.

Primary files:

- `prompts/shared/v2/breadth-semantic-operator-kernel.md`
- `prompts/shared/v2/phase3-breadth.md`
- `scripts/plamen_driver.py`
- `scripts/plamen_prompt.py`
- `scripts/codex_adapter.py`
- `codex-adapter/agents/breadth.toml`

Fixture:

- `scripts/test_breadth_semantic_kernel.py`

Review questions:

- Is the kernel truly HOW-oriented and protocol-neutral?
- Is it present with empty skill selection and additive with non-empty selection?
- Does Codex adapter behavior match the main driver?
- Is prompt-size growth bounded?

### R0-2a: typed/table-scoped finding-mapping parser

**Implemented:** mapping provenance is parsed from recognized table schemas rather than any prose line containing multiple IDs. Split-parent information in real status cells remains available to the R10 join.

Primary files:

- `scripts/plamen_parsers.py`
- `scripts/plamen_mechanical.py`

Fixture:

- `scripts/test_finding_mapping_parser_r0_2a.py`

Review questions:

- Can prose IDs still create a false merge?
- Are producer table variants handled without accepting arbitrary tables?
- Does status-cell split provenance survive?

### R0-2b: shared hypothesis identity and split grammar

**Implemented:** lifecycle parsing preserves ordinary, grouped, suffixed split, constituent, and report identities through queue/mapping/report consumers.

Primary files:

- `scripts/plamen_parsers.py`
- `scripts/plamen_driver.py`
- `scripts/plamen_validators.py`

Fixture:

- `scripts/test_hypothesis_identity_r0_2b.py`

Review questions:

- Are suffixes normalized without collapsing distinct children?
- Are aliases bounded to explicit split-parent relations?
- Does the R10 constituent join remain stable?

### R0-2c: committed-invariant ID drift recovery

**Implemented:** CI identifier variants are parsed and recovered; drift is represented as a durable application gap instead of a warning-only sentinel.

Primary files:

- `scripts/plamen_parsers.py`
- `scripts/plamen_driver.py`
- `scripts/plamen_validators.py`

Fixture:

- `scripts/test_ci_drift_recovery_r0_2c.py`

Review questions:

- Does recovery distinguish a real committed-invariant block from incidental text?
- Does malformed input degrade loudly without inventing a finding?

### R0-3: honest proof status

**Implemented:** proof-looking tags accompanied by `MECHANICAL-UNAVAILABLE` or `POC-UNVERIFIED-HARNESS` yield `CONFIRMED`, not execution-grade `VERIFIED`. Severity and report-body placement remain unchanged. Genuine executed and production evidence remains proof-grade.

Primary files:

- `scripts/plamen_validators.py`
- `rules/report-template.md`

Fixture:

- `scripts/test_fix1_fix3_status_and_external_assumption.py`

Review questions:

- Is this exactly a label correction, with no hidden severity/body demotion?
- Are production-fork evidence tags unaffected?

### R0-4: external-dependency research owner and parity

**Implemented:** recon has an explicit external-dependency research shard; dependency surfaces become researched rows or unresolved obligations even when fetching fails.

Primary files:

- `scripts/recon_prepass.py`
- `scripts/dependency_obligations.py`
- `scripts/plamen_driver.py`

Fixture:

- `scripts/test_recon_dependency_research_owner_r0_4.py`

Review questions:

- Does every non-vendored dependency get either evidence or an unresolved obligation?
- Is failure represented without halting the audit?
- Can path or import noise create unbounded obligations?

### R0-5: cap, overflow, and popularity-skip receipts

**Implemented:** bounded enumeration and promotion paths emit durable shortfall receipts. High-fan-in symbols receive one loud coverage flag rather than an arbitrary 6-of-N obligation explosion.

Primary files:

- `scripts/coverage_shortfalls.py`
- `scripts/enumeration_gate.py`
- `scripts/plamen_mechanical.py`

Fixture:

- `scripts/test_coverage_shortfall_receipts.py`

Review questions:

- Does every relevant truncation path emit exactly one bounded receipt?
- Is the receipt durable through report/human-review routing?
- Can repeated resume duplicate or amplify receipts?
- Does the popularity path remain a flag rather than generating arbitrary pairs?

### R0-6: smart-contract graph-health self-check

**Implemented:** missing or under-resolved graph state becomes a graph-health obligation rather than an indistinguishable empty result. Ecosystem-specific and startup behavior is bounded.

Primary files:

- `scripts/enumeration_gate.py`
- `scripts/plamen_driver.py`

Fixtures:

- `scripts/test_enumeration_graph_health_r0_6.py`
- `scripts/test_ecosystem_path_fixes.py`

Review questions:

- Are thresholds meaningful across EVM, Solana, Move, Soroban, and L1 clients?
- Does the gate distinguish genuinely empty projects from extractor failure?
- Does it flag rather than halt?

### R0-7: exact co-referencer coverage matching

**Implemented:** identifier-boundary matching replaces substring acceptance.

Primary file:

- `scripts/enumeration_gate.py`

Fixture:

- `scripts/test_enumeration_gate.py`

Review questions:

- Are language-qualified and Unicode identifiers handled safely?
- Can punctuation or qualified names create avoidable re-emission noise?

### R0-8a: sidecar-to-method prompt binding

**Implemented:** depth sidecars bind to their intended perturbation/checklist methodology; unknown role/method combinations fail into an explicit state rather than silently receiving the generic depth prompt.

Primary files:

- `scripts/plamen_driver.py`
- `prompts/shared/phase4b-da-iter2.md`
- `prompts/shared/phase4b-skill-checklist.md`
- `prompts/shared/v2/phase4b-depth.md`
- `prompts/shared/v2/phase4b-skill-checklist.md`

Fixture:

- `scripts/test_r0_8_prompt_and_trace_honesty.py`

### R0-8b: honest skill-application receipts

**Implemented:** the validator no longer treats the mere presence of a tag/large artifact as proof that a method step executed. Step-ID-less evidence becomes unmeasurable rather than `EXECUTED`.

Primary files:

- `scripts/plamen_validators.py`
- prompt files listed under R0-8a

Fixture:

- `scripts/test_r0_8_prompt_and_trace_honesty.py`

Review questions:

- Is any synthesis path still capable of manufacturing application success?
- Does `unmeasurable` route to human review/degradation without becoming a false miss or false pass?

### R0-8c: resumable source/config/prompt snapshot

**Implemented:** checkpoints bind an audit snapshot; stale descendants are invalidated on material input changes. Scan scope and recovery are bounded and tested hermetically.

Primary files:

- `scripts/audit_snapshot.py`
- `scripts/plamen_types.py`
- `scripts/plamen_driver.py`

Fixtures:

- `scripts/test_audit_snapshot_r0_8cd.py`
- `scripts/test_snapshot_startup_rewind_r0_8cd.py`
- `scripts/test_driver_smoke.py`

Review questions:

- Is invalidation neither too narrow nor a full unnecessary restart?
- Are prompt/config/tool/source changes separated correctly?
- Does haltless degradation remain visible?
- Are generated scratchpad and PoC files excluded from the source identity?

### R0-8d: frozen production source scope

**Implemented:** in-scope production files are hashed separately from generated PoC/harness output, preventing a verification artifact from entering the audited source set.

Primary files:

- `scripts/production_source_scope.py`
- `scripts/audit_snapshot.py`
- `scripts/plamen_driver.py`

Fixture:

- `scripts/test_audit_snapshot_r0_8cd.py`

### R0-8e: mechanical-gate governance and budget

**Implemented:** gate creation is no longer presumed tiny/low-risk. A registry and lifecycle contract records seam, direction, inputs, failure behavior, runtime envelope, evidence, false-fire budget, consolidation, review, and sunset.

Primary files:

- `rules/mechanical-gate-registry.json`
- `rules/post-audit-improvement-protocol.md`

Fixture:

- `scripts/test_post_audit_gate_budget.py`

### R0-8f: axis-coverage documentation alignment

**Implemented:** architecture documentation now matches the actual Thorough-only deterministic-plus-conditional-worker behavior. Core/Light were not silently enabled as part of a documentation correction.

Primary files:

- `docs/architecture.md`
- `README.md`
- `docs/internals.md`
- `docs/design/recall-build-plan.md`

Review question: is leaving the pass Thorough-only the right product decision, or should a later measured experiment separately evaluate the zero/low-cost deterministic portion in other modes?

---

## 5. R10.1 requirement-to-evidence matrix

Primary runtime file: `scripts/plamen_validators.py`  
Primary focused fixture: `scripts/test_r10_1_external_undemotion.py`  
Baseline fixture extended: `scripts/test_r10_demotion_gate.py`

### Defect 8: unsupported favorable premise used for `REFUTED`

Implemented conservatively:

- `REFUTED` can reopen only with a positive depth anchor;
- the external premise must be decisive to the disposition;
- matching external citation/research suppresses the veto;
- `FALSE_POSITIVE`, `DROP_FALSE_POSITIVE`, and `DUPLICATE` never reopen;
- all-depth-refuted remains blocked;
- proof-grade or executed evidence remains blocked by the existing guards.

Required positive and negative fixtures are present.

### Defect 5: internal stability text mistaken for external provenance

Implemented conservatively:

- stability wording alone is insufficient;
- mapped constituent inventory blocks must contain external provenance;
- the existing explicit-tag route is not widened through arbitrary constituent aggregation.

Required internal-invariant no-fire and source-backed external-stability fire fixtures are present.

### Defect 7: executed PoC scope ambiguity

The handoff explicitly allowed deferral if no mechanically trustworthy premise-to-execution signal exists. The current verification schema contains only agent-authored scope prose and proof that a test ran. It does not attest which premise the executed assertion resolved.

Therefore R10.1 preserves G3 for:

- local-mechanism-only executions;
- executions labeled as external-premise by agent prose;
- ambiguous executions.

This is the required conservative interim behavior, not a completed premise-binding model. The general `Premise -> assertion -> observed result -> disposition` model remains a later, separately reviewed architectural change.

### Severity boundary

R10.1 does not manufacture severity. It restores only the depth-claimed floor. The private regression target replay therefore restores four Low in-body/human-review items, not the missed High. The depth-side severity under-rating remains a separate methodology/decision-model issue.

### Fresh replay evidence

The live private regression target scratchpad was not modified. A temporary copy of the required queue, inventory, mapping, hypotheses, external-research, and verifier artifacts produced:

```json
{"count":4,"fired_ids":["PRIVATE-FINDING-002","PRIVATE-FINDING-005","PRIVATE-FINDING-006","PRIVATE-FINDING-007"],"ledger_written":true,"restored_floors":{"PRIVATE-FINDING-002":"Low","PRIVATE-FINDING-005":"Low","PRIVATE-FINDING-006":"Low","PRIVATE-FINDING-007":"Low"}}
```

Seven additional historical scratchpads produced `[]` across EVM, L1/Rust, Solana, and Soroban. An eighth EVM scratchpad produced one candidate whose verifier disposition appears to depend on an uncited favorable external/trust premise. It should be independently adjudicated. This exploratory item is not part of the held-out benchmark and is not a release success metric.

---

## 6. Neutral evaluator architecture

The evaluator is intentionally separate from the Plamen production tree. It implements contracts and validation; it does not pretend that same-user local directories create organizational isolation.

### 6.1 Closed RunBundle and lifecycle lineage

The runner boundary accepts a fixed payload:

1. run manifest;
2. phase events;
3. candidate findings;
4. raw-output index;
5. harvest receipt;
6. generated seal/index artifacts.

Unknown files, symlinks, missing files, mutation during seal/import, digest mismatch, foreign run IDs, and incomplete payloads fail closed.

Primary module: `src/plamen_eval/bundle.py`.

Lifecycle events are normalized deterministically. Frozen stage observations bind each issue/milestone state to sealed artifact provenance and candidate lineage. The grader measures:

- expressible;
- scheduled;
- applied;
- discovered;
- retained;
- verified;
- reported;
- severity calibration;
- earliest failing lifecycle stage;
- dedup-loss kind;
- unobservable state count.

Primary modules:

- `src/plamen_eval/events.py`
- `src/plamen_eval/matches.py`
- `src/plamen_eval/scoring.py`
- `src/plamen_eval/contracts.py`

### 6.2 Independent reusable-method annotations

Ground truth is represented as reusable operators, required target relations, environmental premises, and required evidence - not target-specific hints injected into Plamen. Independent votes and reviewer rosters are frozen and hashed.

Primary modules:

- `src/plamen_eval/annotations.py`
- `src/plamen_eval/benchmark.py`
- `src/plamen_eval/matches.py`

Compiled obligations permit exact application measurement rather than “methodology file existed” inference. Contract checks enforce subset relations between expressible, scheduled, and applied obligations.

### 6.3 B1 publication boundary

The evaluator requires three authenticated layers:

1. corpus authority signs the pre-run suite;
2. distinct score/evaluator authority signs each deterministic score;
3. publication authority signs the exact aggregate publication gate.

Self-hashes alone do not upgrade evidence. Missing, stale, wrong-key, incomplete, foreign, denominator-drifting, unobservable, or self-certified evidence remains non-publishable.

Primary modules:

- `src/plamen_eval/publication.py`
- `src/plamen_eval/isolation.py`
- `src/plamen_eval/contracts.py`

Residual governance limitation: HMAC authenticates possession of configured keys; it cannot prove that real people/organizations applied an independent governance process. The publication-principal separation policy must be enforced by the external benchmark operator as well as reviewed in the evidence.

### 6.4 Statistical policy

The analysis is precommitted before suite lock. It uses paired case-cluster deltas:

- repetitions are averaged within a case and never inflate `n`;
- constraints cover `ALL` and `FUTURE_TIME` scopes;
- a lower 95% confidence bound drives pass/fail;
- insufficient case clusters yield `INSUFFICIENT`, not pass;
- campaign failure is monotone across staged, factorial, and comparator components;
- result contracts recompute and reject decisions that disagree with intervals.

The initial implementation used 1.96 after 30 degrees of freedom while labeling the interval Student-t. Commit `345d016` fixes that precision defect with a deterministic third-order Cornish-Fisher approximation above the exact lookup table. The boundary is fixture-locked at df=30, df=31, and df=1000.

Primary module: `src/plamen_eval/analysis.py`.

### 6.5 Factor-real P0-P5 campaign

The campaign has three related but distinct plans:

- staged screen: `P0` through `P4`;
- full factorial: `F000` through `F111`;
- external comparator: `X-PASHOV`, represented as variant `P5`.

The factors are:

- full/component-complete context;
- compact SOP;
- explicit seam roles.

Each factor must bind distinct control/treatment artifact hashes. Model, tools, budgets, runner, policies, and seeds remain invariant within the Plamen experiment. Corresponding staged and factorial cells must have identical run contracts. The comparator must use a distinct, exact `PASHOV_V3` adapter with provenance and license hashes.

The campaign freezes:

- 14 logical cells;
- exact case x cell x repetition schedule;
- unique job IDs and digests;
- seed binding;
- separate staged, factorial, and comparator analysis-policy digests;
- campaign digest inside each suite lock.

With four synthetic cases, 14 cells, and three repetitions, the B0 dry run schedules 168 jobs.

Primary modules:

- `src/plamen_eval/experiments.py`
- `src/plamen_eval/campaign.py`
- `src/plamen_eval/analysis.py`
- `src/plamen_eval/cli.py`

### 6.6 CLI and atomicity

The CLI exposes digest, validation, bundle sealing/import, event normalization, experiment planning, case/observation/match freezing, scoring, isolation proof assessment, suite/score/publication signing, experiment analysis, campaign construction/scheduling, and campaign analysis.

Writes are atomic. Signing consumes file-backed key registries, not secrets on argv. Malformed/authentication failures return exit 2; valid but non-promotable evidence returns exit 3.

Primary module: `src/plamen_eval/cli.py`.

---

## 7. B0 receipt and exact interpretation

Artifact:

`<PRIVATE_DOWNLOADS_ROOT>\Plamen_B0_P0-P5_Dry_Run_Receipt_2026-07-16.json`

Bindings:

- evaluator git commit: `SOURCE-REVISION-001`;
- evaluator revision SHA-256 (SHA-256 of the commit string): `PRIVATE-HASH-013`;
- canonical receipt digest: `PRIVATE-HASH-006`;
- file SHA-256: `PRIVATE-HASH-014`;
- schema validation: `VALID`;
- component statuses: STAGED/PASS, FACTORIAL/PASS, COMPARATOR/PASS;
- simulated jobs: 168;
- assurance tier: `B0_TEST_ONLY`;
- synthetic: `true`.

The receipt contains all four mandatory limitations:

- `NO_SECURE_LAUNCHER`;
- `SYNTHETIC_CORPUS`;
- `SYNTHETIC_AUTHORITIES`;
- `NO_COMPARATIVE_CLAIM`.

The component `PASS` values mean only that the synthetic control path and its contracts functioned. They are not measurements of Plamen or Pashov.

---

## 8. Verification evidence and commands

All commands below ran on 2026-07-16 against the recorded HEADs.

### Production fast lane

```powershell
cd <PLAMEN_DEVELOPMENT_ROOT>
python -m pytest -q -m "not integration"
```

Result: `4504 passed, 4 skipped, 245 deselected in 123.06s`.

### Production full suite

```powershell
cd <PLAMEN_DEVELOPMENT_ROOT>
python -m pytest -q
```

Result: `4747 passed, 5 skipped, 1 xfailed in 346.87s`.

### Focused Release-0/R10.1 suite

```powershell
python -m pytest -q `
  scripts\test_breadth_semantic_kernel.py `
  scripts\test_fix1_fix3_status_and_external_assumption.py `
  scripts\test_finding_mapping_parser_r0_2a.py `
  scripts\test_hypothesis_identity_r0_2b.py `
  scripts\test_ci_drift_recovery_r0_2c.py `
  scripts\test_recon_dependency_research_owner_r0_4.py `
  scripts\test_coverage_shortfall_receipts.py `
  scripts\test_enumeration_graph_health_r0_6.py `
  scripts\test_enumeration_gate.py `
  scripts\test_r0_8_prompt_and_trace_honesty.py `
  scripts\test_audit_snapshot_r0_8cd.py `
  scripts\test_snapshot_startup_rewind_r0_8cd.py `
  scripts\test_post_audit_gate_budget.py `
  scripts\test_r10_demotion_gate.py `
  scripts\test_r10_1_external_undemotion.py
```

Result: `273 passed in 45.71s`.

### Evaluator

```powershell
cd <PRIVATE_EVALUATOR_ROOT>
python -m compileall -q src tests scripts
python -m pytest -q
git diff --check
```

Result: `93 passed, 3 subtests passed in 8.63s`; compile and diff checks passed.

### Receipt validation

```powershell
$env:PYTHONPATH='src'
python -m plamen_eval.cli validate b0_campaign_dry_run_receipt `
  <PRIVATE_DOWNLOADS_ROOT>\Plamen_B0_P0-P5_Dry_Run_Receipt_2026-07-16.json
```

Result:

```json
{"schema_version":"plamen.eval.b0_campaign_dry_run_receipt.v1","status":"VALID"}
```

### Fixture-first evidence qualification

The current tree proves green behavior and the commit series cleanly separates major fixes. It does not retain a machine-readable pre-fix failure transcript for every historical fixture. The newest statistical boundary did have an observed red state (`ImportError` for the missing `_t_critical_975`) before its implementation and then passed focused/full suites.

Claude should not infer “fixture-first” merely because a test file exists. For high-risk seams (identity parsing, snapshot invalidation, coverage receipts, R10.1), review the parent/current diff and, if desired, replay the new fixture against a temporary parent worktree. Lack of a durable red transcript is a review-evidence limitation, not a runtime failure.

---

## 9. Precision and anti-bloat assessment

Controls added or preserved:

- additive candidates still flow through normal verification;
- caps become receipts rather than silently widening enumeration;
- popularity skip emits one bounded flag, not N-way pairs;
- exact identifier matching reduces false coverage;
- table-scoped mapping reduces false root-cause merges;
- `FALSE_POSITIVE` and `DUPLICATE` remain terminal for R10.1;
- executed/proof-grade evidence suppresses R10.1 until premise binding is trustworthy;
- R10.1 restores the existing floor rather than inflating severity;
- case clustering prevents repeated-run pseudoreplication;
- `INSUFFICIENT` cannot be published as a pass;
- synthetic evidence cannot silently become B1;
- report/proof labels now distinguish execution from trace evidence.

Residual risks Claude should attack:

1. **Implementation size:** 6,802 non-test additions are substantial for Release-0. Look for duplicated parsing, hidden phase coupling, and expensive scans.
2. **Markdown remains a source format:** typed table parsers improve it but do not turn all lifecycle records into canonical data. False negatives from unseen format variants remain possible.
3. **R10 lexical semantics:** the decisive-premise predicate remains text-derived. Its precision is bounded by explicit anchors but not formally semantic.
4. **R10 G3 deferral:** legitimate external-premise demotions can still escape when any PoC executed, because premise-to-evidence binding is not yet trustworthy.
5. **Severity under-rating:** R10.1 visibility restoration does not repair a bad depth severity.
6. **Graph thresholds:** a universal resolution ratio may behave differently across generated code, macros, dynamic dispatch, and cross-language call boundaries.
7. **Obligation noise:** loud degradation is better than silence, but receipt growth can still burden human review.
8. **Authority governance:** HMAC validates configured trust, not the real independence of people or systems.
9. **Statistical multiplicity:** the frozen constraints are separately gated; the current policy does not implement family-wise or false-discovery correction. Because promotion requires every configured non-regression constraint to pass, the practical risk is often conservatism, but reviewer analysis is warranted before public claims.
10. **Competitor adapter fidelity:** no exact Pashov V3 adapter is present, so comparator fairness is a contract only.

---

## 10. Unsatisfied live-B1/P5 prerequisites

A filesystem audit found development repositories and prior Plamen-generated reports under `<PRIVATE_USER_ROOT>\plamen-benchmarks`, including geth, Cosmos SDK, and Irys trees. Those are not a B1 corpus because they lack the required independently governed, pre-run annotations, authority attestations, holdout policy, and launcher isolation. Ordinary fuzz corpora are not professional audit ground truth.

No current local asset satisfies all of these prerequisites:

1. genuinely held-out, stratified professional corpus with multi-ecosystem coverage;
2. repository, firm, and future-time holdout assignments;
3. vulnerable, clean, and seeded controls;
4. two-reviewer reusable-operator/relation/premise/evidence annotations;
5. methodology-exclusion ledger proving fix-authoring examples are excluded;
6. secure external launcher with trusted denial probes and no audit-agent/RAG access to ground truth;
7. separately governed corpus, score, and publication authorities/keys;
8. exact pinned Pashov V3 adapter plus provenance and license digests;
9. real context/SOP/seam-role control and treatment artifacts;
10. pinned models, tools, budgets, seeds, runner revisions, and measurement policies;
11. sufficient case count for `ALL` and `FUTURE_TIME` confidence constraints.

Therefore the live P0-P5 experiment cannot be honestly completed on the current machine. This is an external-evidence prerequisite, not a reason to weaken the B1 gate or relabel B0 output.

Recommended next external work order:

1. corpus owner constructs and signs the pre-run suite outside Plamen;
2. benchmark operator deploys the secure launcher and runs denial probes;
3. Pashov V3 adapter owner pins the exact public release and license/provenance;
4. treatment artifact owner supplies and hashes full-context, compact-SOP, and seam-role levels;
5. independent reviewers freeze annotations and exclusion policy;
6. run the staged screen first;
7. proceed to full factorial and P5 only if the staged evidence is complete and publishable;
8. publish only the signed evidence package and paired analysis, including failed/insufficient outcomes.

---

## 11. Deferred architecture - deliberately not smuggled into this release

The canonical plan proposes a larger Release-1-through-Release-8 program. This handoff does not claim it is implemented.

Deferred and benchmark-gated:

- passive observer over existing structured sidecars;
- one inventory-to-report dual-write identity slice;
- fault-injection parity before any canonical-ledger cutover;
- general Claim/Premise/EvidenceReceipt/DispositionDecision model;
- canonical finding-event ledger and report projection;
- MethodCard compiler and obligation-driven convergence;
- relation-graph scheduler;
- ecosystem-specific graph-provider contract and AST/IR expansion;
- broader formal/fuzz/property synthesis;
- stronger execution isolation and operational hardening.

The evaluator makes these choices measurable; it does not pre-approve them. In particular, the finding ledger remains gated on observed lifecycle loss. The Pashov hypothesis remains an experiment, not an argument for either more or less orchestration.

---

## 12. Complete changed-file inventory

### 12.1 Production delta from R10 baseline (`9ca8861..67a0f85`)

Runtime, methodology, configuration, and documentation:

- `.gitignore`
- `README.md`
- `codex-adapter/agents/breadth.toml`
- `docs/architecture.md`
- `docs/design/recall-build-plan.md`
- `docs/internals.md`
- `prompts/shared/phase4b-da-iter2.md`
- `prompts/shared/phase4b-skill-checklist.md`
- `prompts/shared/v2/breadth-semantic-operator-kernel.md`
- `prompts/shared/v2/phase3-breadth.md`
- `prompts/shared/v2/phase4b-depth.md`
- `prompts/shared/v2/phase4b-skill-checklist.md`
- `rules/mechanical-gate-registry.json`
- `rules/post-audit-improvement-protocol.md`
- `scripts/audit_snapshot.py`
- `scripts/codex_adapter.py`
- `scripts/coverage_shortfalls.py`
- `scripts/dependency_obligations.py`
- `scripts/enumeration_gate.py`
- `scripts/plamen_driver.py`
- `scripts/plamen_mechanical.py`
- `scripts/plamen_parsers.py`
- `scripts/plamen_prompt.py`
- `scripts/plamen_types.py`
- `scripts/plamen_validators.py`
- `scripts/production_source_scope.py`
- `scripts/recon_prepass.py`

Fixtures/regressions:

- `scripts/test_audit_snapshot_r0_8cd.py`
- `scripts/test_breadth_semantic_kernel.py`
- `scripts/test_ci_drift_recovery_r0_2c.py`
- `scripts/test_coverage_shortfall_receipts.py`
- `scripts/test_driver_helpers.py`
- `scripts/test_driver_smoke.py`
- `scripts/test_ecosystem_path_fixes.py`
- `scripts/test_enumeration_gate.py`
- `scripts/test_enumeration_graph_health_r0_6.py`
- `scripts/test_finding_mapping_parser_r0_2a.py`
- `scripts/test_fix1_fix3_status_and_external_assumption.py`
- `scripts/test_hypothesis_identity_r0_2b.py`
- `scripts/test_phase_bc_tier_bc_migrations.py`
- `scripts/test_post_audit_gate_budget.py`
- `scripts/test_r0_8_prompt_and_trace_honesty.py`
- `scripts/test_r10_1_external_undemotion.py`
- `scripts/test_r10_demotion_gate.py`
- `scripts/test_recon_dependency_research_owner_r0_4.py`
- `scripts/test_report_index_coverage_seed.py`
- `scripts/test_snapshot_startup_rewind_r0_8cd.py`
- `scripts/test_structural_integrity.py`
- `scripts/test_v2_recall_fixes.py`

### 12.2 Neutral evaluator tracked files

Top-level/docs:

- `.gitignore`
- `README.md`
- `pyproject.toml`
- `docs/RFC-0001-neutral-benchmark-control-plane.md`
- `scripts/run_b0_campaign_dry_run.py`

Runtime package:

- `src/plamen_eval/__init__.py`
- `src/plamen_eval/__main__.py`
- `src/plamen_eval/analysis.py`
- `src/plamen_eval/annotations.py`
- `src/plamen_eval/benchmark.py`
- `src/plamen_eval/bundle.py`
- `src/plamen_eval/campaign.py`
- `src/plamen_eval/canonical.py`
- `src/plamen_eval/cli.py`
- `src/plamen_eval/contracts.py`
- `src/plamen_eval/events.py`
- `src/plamen_eval/experiments.py`
- `src/plamen_eval/isolation.py`
- `src/plamen_eval/matches.py`
- `src/plamen_eval/publication.py`
- `src/plamen_eval/scoring.py`

Schemas:

- `schemas/b0_campaign_dry_run_receipt.v1.schema.json`
- `schemas/benchmark_case_lock.v1.schema.json`
- `schemas/campaign_analysis.v1.schema.json`
- `schemas/campaign_run_schedule.v1.schema.json`
- `schemas/candidate_finding.v1.schema.json`
- `schemas/case_private.v1.schema.json`
- `schemas/case_public.v1.schema.json`
- `schemas/corpus_suite_attestation.v1.schema.json`
- `schemas/corpus_suite_lock.v1.schema.json`
- `schemas/experiment_analysis.v1.schema.json`
- `schemas/experiment_analysis_policy.v1.schema.json`
- `schemas/experiment_campaign.v1.schema.json`
- `schemas/experiment_plan.v1.schema.json`
- `schemas/frozen_match.v1.schema.json`
- `schemas/ground_truth_annotation_set.v1.schema.json`
- `schemas/ground_truth_annotation_vote.v1.schema.json`
- `schemas/ground_truth_issue.v1.schema.json`
- `schemas/harvest_receipt.v1.schema.json`
- `schemas/isolation_receipt.v1.schema.json`
- `schemas/phase_event.v1.schema.json`
- `schemas/publication_gate.v1.schema.json`
- `schemas/publication_gate_attestation.v1.schema.json`
- `schemas/raw_output_index.v1.schema.json`
- `schemas/reviewer_roster.v1.schema.json`
- `schemas/run_manifest.v1.schema.json`
- `schemas/score.v1.schema.json`
- `schemas/score_attestation.v1.schema.json`
- `schemas/stage_observation.v1.schema.json`
- `schemas/stage_observation_set.v1.schema.json`

Tests/goldens:

- `tests/__init__.py`
- `tests/golden/lifecycle_events_reordered.jsonl`
- `tests/golden/lifecycle_normalized.json`
- `tests/test_adversarial_boundaries.py`
- `tests/test_analysis.py`
- `tests/test_annotations.py`
- `tests/test_benchmark.py`
- `tests/test_bundle.py`
- `tests/test_campaign.py`
- `tests/test_campaign_analysis.py`
- `tests/test_cli.py`
- `tests/test_contracts.py`
- `tests/test_dry_run.py`
- `tests/test_events.py`
- `tests/test_experiments.py`
- `tests/test_golden.py`
- `tests/test_isolation.py`
- `tests/test_matches_and_scoring.py`
- `tests/test_publication_gate.py`

---

## 13. Claude blocking-review checklist

Claude is asked to review against the original Section 6 checklist and specifically answer each item with PASS, BLOCK, or NEEDS-EVIDENCE.

### Production

1. Does each Release-0 fix match the stated gap without narrowing recall elsewhere?
2. Are production predicates Part-0 generic, with protocol-specific material confined to regression artifacts where unavoidable?
3. Does the breadth kernel add a floor without duplicating large ecosystem prompts?
4. Are mapping/identity parsers typed enough to stop false joins while accepting legitimate producer variants?
5. Do all caps and graph failures produce bounded, durable, idempotent receipts?
6. Does snapshot invalidation cover source/config/prompt/tool changes without unnecessary full rewinds?
7. Is production source scope protected from generated PoC/harness files?
8. Are skill-application receipts honest and useful rather than merely stricter prose?
9. Does R10.1 defect 8 remain narrow around positive depth + decisive uncited external premise?
10. Does R10.1 defect 5 require real external provenance?
11. Is preserving G3 the correct interim choice for defect 7?
12. Is the one extra historical R10 candidate legitimate, noisy, or evidence of a lexical false-fire class?
13. Is the 6,802-line non-test delta acceptable as one cutover, or should commits/modules be split?

### Evaluator

14. Can any self-hash-only or same-authority evidence become B1?
15. Can suite/score/campaign denominators or rosters drift after precommitment?
16. Can repetitions inflate statistical `n`?
17. Can `INSUFFICIENT` or a failed component become campaign PASS?
18. Are `ALL` and `FUTURE_TIME` constraints enforced as frozen?
19. Can a factor label remain inert while its artifact hash stays unchanged?
20. Are P0/P5 cross-plan seeds, budgets, models, tools, and case rosters fair and bound?
21. Is the Pashov release/provenance/license contract sufficient for an exact adapter?
22. Does the Student-t approximation remain conservative and correctly labeled?
23. Can target-specific ground truth enter any public/runner-visible payload?
24. Are sealed-bundle import and symlink/file-set rules fail-closed on Windows and POSIX?
25. Are authority-governance limitations stated strongly enough?
26. Does the B0 receipt make a B1/comparative misreading impossible in normal use?

### Decision

27. Approve, block, or request changes for Release-0 cutover.
28. Approve, block, or request changes for R10.1 cutover.
29. Approve the evaluator only as B0 mechanics/B1 validator, or identify a contract defect.
30. Confirm that live P0-P5 remains blocked on external prerequisites rather than code relabeling.

---

## 14. Final implementation verdict

The implementation directly targets the two measured miss families:

- **non-application:** unconditional breadth floor, prompt-role binding, external-research ownership, honest application receipts, CI recovery, graph-health/coverage shortfalls, and exact obligations;
- **found-then-lost or false-safe:** typed identity parsing, hypothesis preservation, overflow receipts, honest proof labels, R10.1, and lifecycle-stage scoring.

It does not prove that those controls increase real recall. The neutral evaluator is the mechanism for establishing that on held-out evidence. The B0 dry run proves the control plane can represent and reject evidence correctly; it does not score the system.

My recommendation is:

1. Claude performs the blocking diff review in Section 13.
2. Any production defect is fixed fixture-first and the focused/full suites rerun.
3. If Claude approves, Release-0 and R10.1 may be considered for local cutover as robustness fixes, with the extra historical R10 candidate monitored.
4. The evaluator may be retained now as a separate B0/B1 validation tool.
5. No recall, precision, or superiority claim is made until the external B1 campaign runs.
6. The ledger and AST/IR expansion remain benchmark-driven follow-ons, not automatic next steps.

This is the strongest honest handoff: the code boundaries are green, the evidence contracts are in place, and the remaining uncertainty is made explicit rather than converted into a synthetic success claim.
