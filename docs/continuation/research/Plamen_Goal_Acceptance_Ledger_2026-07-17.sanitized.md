<!-- PORTABLE SANITIZED RESEARCH COPY
Source identity: Plamen_Goal_Acceptance_Ledger_2026-07-17.md
Raw bytes remain outside Git. Architecture, methodology, execution, acceptance, and comparison semantics are retained; personal paths, private target identities, target-specific candidate/artifact identifiers, artifact digests, and concrete private finding descriptions use deterministic placeholders. See CORPUS_MANIFEST.json and research/PRIVATE_GAP_INDEX.json for provenance and the redaction rule.
-->

# Plamen Goal Acceptance Ledger

Date: 2026-07-17  
Status: active; not a completion claim  
Canonical defect specification: `Plamen_Live_Claude_Canary_Defect_and_Fixture_Map_2026-07-17.md`

## Evidence rule

`DONE` requires all of: a generic red fixture; a Part-0-clean implementation; focused and full-suite passes; fault/migration/resume evidence where applicable; a fresh legacy-Claude path exercise; and no identity, obligation, candidate, or independently authorized negative-disposition loss. A frozen-canary reproduction proves reachability only, never recall improvement.

## Program gates

| Gate | Current state | Required completion evidence |
|---|---|---|
| Frozen Claude EVM baseline | TERMINAL FAILED; EVIDENCE SEALED — reached 70/75 phases, with `report_assemble` degraded; stopped at `report_dedup_agent:post-execution` on false source drift from backend runtime state. Dedup decisions were written but never phase-committed; mechanical dedup, disposition, and floor never ran. Authoritative receipt SHA-256 `PRIVATE-HASH-007`, manifest `PRIVATE-HASH-001` | Preserve as regression evidence only; do not resume or score. Corrected fresh canary supersedes it after integrated P0 fixes |
| Frozen identical resume | FAIL — ordinary resume silently archived/reset the run and relaunched recon. Independent comparator: `FAIL`, `no_model_relaunch=false`, `no_semantic_mutation=false`; SHA-256 `PRIVATE-HASH-015` | P0-AO red fixture; corrected resume must stop without authorization and later prove zero model/semantic mutation |
| Release-0 + R10.1 | IMPLEMENTED IN DIRTY WORKTREE; PRE-CUTOVER REVIEWED | Re-run after integrated P0 substrate; full suite; corrected Claude canaries; user acceptance |
| Neutral evaluator B0 | PASS — clean evaluator HEAD `345d016`; fresh 2026-07-17 suite: 93 passed + 3 subtests in 12.70s; exact-input replay produced a byte-identical preserved receipt SHA-256 `PRIVATE-HASH-014` (`B0_TEST_ONLY`) | Preserve authenticated receipt and evaluator independence |
| Neutral evaluator B1 | EXTERNAL PREREQUISITES PENDING | Governed corpus, secure launcher/denial probes, authorities, pinned comparator adapter |
| P0–P5 experiments | B0 ONLY | Authenticated controlled campaigns; neutral scoring; private regression target excluded from scoring |
| PR #21 CPG/dataflow integration | PENDING; RESEARCH-FIRST | Independently review the docs-only RFC and spike against primary sources and the current typed/PhaseIO/trust architecture; define precision-scoped schemas and neutral red fixtures; implement only after the current authority boundary is stable; independently review and regress before any Claude canary |
| Agent attention/count policy | PENDING; EXPERIMENTAL | Compare current fixed counts with coverage-debt-triggered adaptive expansion under equal model/tool/token budgets; measure marginal unique discovery, application completeness, verification yield, duplicate/root-cause fragmentation, wall-clock, and report signal; no blanket count increase without positive held-out evidence |
| Corrected Claude EVM integration canary | PENDING | Bounded fresh non-ground-truth run, lifecycle parity, no silent debt, clean resume |
| Corrected non-EVM Claude canaries | PENDING | Bounded representative non-ground-truth Solana/Aptos/Sui/Soroban and Go/Rust-L1 path exercises plus clean resumes |
| Final handoff | PENDING | Hash-stamped diffs, tests, receipts, known limitations, independent review boundary; unpushed/unmerged/uninstalled |

### Open integration invariants discovered during final review

- `P0-AE-COMMIT-CAS`: a PhaseIO output must never be recorded `ACTIVE` from bytes that differ from its exact pre-execution input receipt. The final security-obligation lifecycle must prove exact byte-vector stabilization and crash recovery before commit. After that local fix, the shared `record_work_unit_artifacts` boundary must be adversarially assessed for the same invariant across every caller; caller-side logging alone is not acceptance evidence. Output bytes must be preserved as explicit debt/quarantine on drift rather than silently trusted or deleted.
- `P1-C-REPORT-EXACT`: every non-authorized exact security-obligation alias and every non-row authority issue must survive to a JSON-authoritative, client-safe report projection unless an exact alias-level delivery receipt proves coverage. Shared candidate/work-item identity alone cannot close sibling aliases.
- `P1-C-REPRESENTATION-TRUST`: scratchpad-local attestations, checkpoint hashes, provider-name strings, and self-declared graph-v3 edges are nonterminal until an out-of-tree authorized principal/provider receipt and frozen-source occurrence proof exist. Valid v1/v2 absence remains localized metadata; malformed v3 evidence must be queueable debt, never zero-clean.

## User acceptance audits added 2026-07-18

These are user-run post-handoff acceptance stages, not implementation shortcuts
and not training fixtures. Per the user's 2026-07-24 scope change, Codex prepares
and validates the preservation, launch, resume, firewall, and blinded-scoring
tooling but does not launch these two expensive audits. The user launches them
after the architecture handoff.

| Acceptance ID | Target / authority | Required execution and evidence |
|---|---|---|
| UA-CLAUDE-PRIVATE-A | `<PRIVATE_ACCEPTANCE_TARGET_A_ROOT>`; user-supplied PRIVATE-FINDING-001..PRIVATE-FINDING-008 and PRIVATE-FINDING-012..PRIVATE-FINDING-013 ground truth | Codex delivers a tested prepare-only recipe that hash-seals every prior scratchpad/archive, creates a fresh isolated workspace, pins legacy Claude Thorough through the driver, and excludes the ground truth. The user launches and lets it finish; blinded scoring runs only afterward. |
| UA-CLAUDE-PRIVATE-B | `<PRIVATE_REGRESSION_TARGET_ROOT>`; `<PRIVATE_DOWNLOADS_ROOT>\Certora - private regression target Core - Snapshot Draft Report (3).pdf` | Codex delivers the same tested prepare-only, preservation, resume, and grader workflow. The user launches the fresh audit. Earlier private regression target evidence remains regression-only and never becomes independent improvement evidence. |
| UA-COMPARISON | Both future user-run audits | The handoff explains exact/partial/missed recall, found-then-lost and false-safe classes, dedup/root-cause fragmentation, severity, explicit precision denominators, and report quality. No merge, push, install, or cutover follows automatically; the user remains the acceptance gate. |

Frozen evaluation-input identities (never audit inputs):

- private acceptance target A user-supplied reference: `<PRIVATE_DOWNLOADS_ROOT>\PRIVATE_ACCEPTANCE_TARGET_A_GROUND_TRUTH.md`; 4,315 bytes; SHA-256 `PRIVATE-HASH-012`.
- private regression target report: `<PRIVATE_DOWNLOADS_ROOT>\Certora - private regression target Core - Snapshot Draft Report (3).pdf`; 916,744 bytes; SHA-256 `PRIVATE-HASH-018`.
- Both paths must be passed as `--forbidden-input` to terminal preparation. Their bytes are read only by the post-run blinded grader.

## Pre-audit CPG/dataflow and attention-policy gate added 2026-07-24

The latest upstream proposal is PR #21,
`https://github.com/PlamenTSV/plamen/pull/21`, currently a documentation RFC,
evidence appendix, and Slither reproduction spike rather than pipeline code. It
is a required research-and-implementation wave after the current authority and
full-regression work, but before any non-ground-truth Claude canary or user
acceptance audit.

Acceptance requires:

1. Primary-source review of the proposed Slither/CPG facts and ecosystem
   generalizations, plus an exact compatibility audit against PhaseIO,
   representation trust, source/build manifests, resume freshness, and
   proposal-only mechanical authority.
2. Typed, versioned, capability-scoped enrichment facts. Partial or unsupported
   facts may add candidates and disagreements, but may never authorize a
   negative, demotion, clean application receipt, or safe conclusion.
3. Fixture-first producer and consumer work with legacy semantic parity,
   deterministic/idempotent output, stale-build rejection, bounded
   failure/degradation, and independent adversarial review.
4. A neutral A/B for worker-count policy. The treatment is adaptive expansion
   from exact uncovered obligations/axes/components with role/evidence-slice
   diversity; the control is the current count policy. Static blanket increases
   are not accepted on intuition alone.
5. Equal backend/model/tool/token constraints within each comparison and
   separate measurements for raw discovery, found-then-lost retention,
   application completeness, verifier yield, duplicate/root-cause
   fragmentation, severity calibration, report signal, cost, and wall-clock.
6. Ground-truth identities remain grader-only. private acceptance target A and private regression target remain
   user-run post-handoff acceptance audits and cannot be used to tune the CPG
   producer, consumers, or worker-count policy.

### Frozen resume evidence contract

The pre/post proof is independent of driver self-report. `capture_frozen_run_state.ps1` hashes every readable file under the run root, classifies semantic/model/checkpoint artifacts, excludes only the active driver lock and append-only driver log, and marks a receipt inadmissible if any other file is unreadable. `compare_frozen_run_state.ps1` requires zero added/removed/changed model and semantic artifacts and identical prompt/stdio counts. `run_frozen_resume_observed.ps1` launches the identical driver command in a hidden process, polls its process tree, and records whether any Claude/Codex-like child was observed. The final resume claim requires all three independent conditions: admissible before/after manifests, no semantic mutation, and no model child/relaunch evidence.

Current tool SHA-256 values:

- `capture_frozen_run_state.ps1`: `PRIVATE-HASH-019`
- `compare_frozen_run_state.ps1`: `PRIVATE-HASH-005`
- `run_frozen_resume_observed.ps1`: `PRIVATE-HASH-009`

The provisional capture deliberately returned `unreadable_count=1` while the active verifier held its stdio file open, and the comparator correctly returned `INADMISSIBLE` even when comparing that receipt with itself. A separate clean-root double capture produced the identical manifest digest `PRIVATE-HASH-003` twice and the comparator returned `PASS`, `exact_equal=true`, `no_model_relaunch=true`, and `no_semantic_mutation=true` with zero additions, removals, or changes. A one-file semantic-tamper fixture then returned `FAIL`, `exact_equal=false`, and `no_semantic_mutation=false`, identifying exactly one changed `SEMANTIC_ARTIFACT` while leaving `no_model_relaunch=true`. A separate added-prompt fixture returned `FAIL`, increased the prompt count from zero to one, and set `no_model_relaunch=false` while preserving `no_semantic_mutation=true`. These dry runs validate fail-closed, clean-success, semantic-tamper, and model-relaunch detection paths of the observer; they are not evidence about the audit's resume parity. Authoritative audit manifests are captured only after the driver exits.

The process observer was separately adversarially exercised. A synthetic driver that spawned a child whose command line was marked `claude-code` produced `driver_exit_code=0`, `model_cli_child_count=1`, and `no_model_cli_child_observed=false`; a clean synthetic driver produced exit code zero, zero children, and `no_model_cli_child_observed=true`. The initial PowerShell `Start-Process` implementation failed to retain its redirected child's exit code and was rejected; the accepted implementation uses a hidden `System.Diagnostics.Process` with asynchronous stdout/stderr draining and records a populated exit code on both fixtures.

The first real identical-resume observation disproved the desired property. Startup auto-archived the original scratchpad, reset the active checkpoint, removed/moved root outputs, and launched fresh recon workers. The observer was manually terminated with the launched process tree before its wrapper could write a final receipt. Independent disk evidence is nevertheless admissible: the pre-resume scratchpad archive hash-matches 701/701 expected files with zero missing/changed; the post-abort root capture has zero unreadable files; and the comparator reports 706 added paths, 747 removed paths, 28 changed paths, removal of `AUDIT_REPORT.md`, five active prompts, four active model logs, and a fresh empty checkpoint. The incident record is `Plamen_Frozen_Claude_Resume_Incident_2026-07-17.md`, SHA-256 `PRIVATE-HASH-002`. The original root is now evidence-only and must not be resumed again.

## Priority-0 obligations

| ID | Short requirement | Current state | Proof still required |
|---|---|---|---|
| P0-0 | Promote exploration-skeptic NEW/UPGRADE/RE-OPEN actions | LIVE REPRODUCED; SPEC READY | Red fixture → registry promotion → Claude-path delivery |
| P0-1 | Promote Foundry invariant-fuzz violations | CODE REPRODUCED; SPEC READY | Producer-registry fixture and end-to-end queue delivery |
| P0-2 | Deliver depth self-exclusion re-emissions | LIVE REPRODUCED; SPEC READY | Content-bearing vs debt split and exact reconciliation |
| P0-A | Close selected-skill-to-all-declared-consumers graph | LIVE REPRODUCED; PARTIAL DIRTY IMPLEMENTATION | Typed consumer parity across ecosystem/mode/backend |
| P0-B | Separate application completeness from semantic outcome | LIVE REPRODUCED; SPEC READY | Orthogonal schema; only missing/invalid rows repaired |
| P0-C | Independently adjudicate unsupported SAFE/NO_FINDING | LIVE REPRODUCED; SPEC READY | Application-skeptic phase and valid-negative precision controls |
| P0-D | Bind attention/application work to exact methodology bytes | LIVE REPRODUCED; SPEC READY | Typed queue/hash fixtures and legacy parser containment |
| P0-E | Deliver recall-bearing degradation in final report | CODE REPRODUCED; SPEC READY | Assurance-limitations projection and resume parity |
| P0-F | Repair/consume invalid exploration clears | LIVE REPRODUCED; SPEC READY | Exact failed-clear routing and no silent completion |
| P0-G | Re-verify post-verification side findings | CODE REPRODUCED; SPEC READY | Candidate registry, late queue, independent evidence |
| P0-H | Make trust tags challengeable facts, not severity authority | CODE REPRODUCED; SPEC READY | Typed trust evidence and independent adjudication |
| P0-I | Reconcile enumeration/axis input-to-disposition exactly | LIVE REPRODUCED; SPEC READY | Exact denominator/tail/overflow receipts |
| P0-J | Stop recursive variant generation over generated candidates | LIVE REPRODUCED; SPEC READY | First-generation-only fixture and bounded recall comparison |
| P0-K | Preserve structured Source-ID lineage | LIVE REPRODUCED; SPEC READY | Typed lineage grammar and consumer parity |
| P0-L | Prove raw discovery-to-inventory disposition before chunk authority | LIVE REPRODUCED; SPEC READY | Exact set reconciliation and no threshold acceptance |
| P0-M | Prevent methodology headings from becoming findings | LIVE REPRODUCED; SPEC READY | Schema-bound parser and malformed legacy fixtures |
| P0-N | Ensure resume-detected queue dropouts are actually verified | CODE REPRODUCED; SPEC READY | Targeted invalidation/late shard plus clean resume |
| P0-O | Bind grouped PoC evidence per constituent | CODE REPRODUCED; SPEC READY | Ambiguous/mixed constituent evidence fixtures |
| P0-P | Remove one-way blind-first downgrade authority | CODE REPRODUCED; SPEC READY | Direction-neutral premise/evidence decision ledger |
| P0-Q | Make semantic dedup lossless or veto removal | LIVE REPRODUCED; SPEC READY | Field-aware pre/post diff and alias-preserving groups |
| P0-R | Require authorized disposition, not lexical appendix/exclusion accounting | CODE REPRODUCED; SPEC READY | Exact decision authority and report parity |
| P0-S | Consume applied dedup decisions only | LIVE REPRODUCED; SPEC READY | Proposal/applied receipt split and set-equality postcondition |
| P0-T | Close real-signal chain-composition worklists | LIVE REPRODUCED; CLIENT-BLOAT CONSEQUENCE REPRODUCED; SPEC READY | Exact pair denominator, overflow debt, bounded continuation, lossless sidecar plus digest-bound client summary |
| P0-U | Stop report-index repair from legitimizing unsupported downgrades | CODE REPRODUCED; SPEC READY | Restore prior tier or adjudicate; report cannot author decision |
| P0-V | Separate skeptic from judge; unresolved is not a demotion | CODE REPRODUCED; SPEC READY | Independent identities and premise-bound decision events |
| P0-W | Replace destructive chain anti-absorption rewrite | LIVE REPRODUCED; SPEC READY | Relation-only repair and lossless field diff |
| P0-X | Prevent producer verdicts from excluding their own candidates | CODE REPRODUCED; SPEC READY | Independent discriminator or typed mechanical scope decision |
| P0-Y | Separate citation repair from finding validity and preserve identity | LIVE REPRODUCED; SPEC READY | Alias-aware citation repair and no validity deletion |
| P0-Z | Add semantic dependency freshness to resume | CODE REPRODUCED; SPEC READY | Input/output digest DAG and targeted invalidation fixtures |
| P0-AA | Verify report-index dropouts instead of acknowledging DEFERRED | CODE REPRODUCED; SPEC READY | Late verification or visible unresolved body/debt |
| P0-AB | Normalize state-symbol schema before chain coverage | LIVE REPRODUCED; SPEC READY | Alias/field parser parity and exact state-pair receipts |
| P0-AC | Replace FC4 false completion with typed persistent debt | LIVE REPRODUCED TWICE; SPEC READY | Shared gate state machine, quarantine retention, resume parity |
| P0-AD | Preserve recon selection polarity and schema authority | LIVE REPRODUCED; SPEC READY | Exact YES/NO/N/A parser and driver-owned catalog |
| P0-AE | Unify prompt, ownership, containment, gate, and launch policy contracts | LIVE REPRODUCED; SPEC READY | `PhaseIOContract`, compiled-prompt linter, all phase/backend matrix |
| P0-AF | Independently verify compound chains | LIVE REPRODUCED; SPEC READY | `CH-*` promotion, composition-specific work/evidence, report binding |
| P0-AG | Make severity adjudication direction-neutral and premise-bound | LIVE REPRODUCED; SPEC READY | Typed axes/evidence ledger and independent arbitration |
| P0-AH | Honor Thorough all-severity execution policy | CODE + LIVE PROCESS REPRODUCED; SPEC READY | Shared mode policy, Low/Info attempts, valid blocker controls |
| P0-AI | Compile live verifier methodology and prove reachability | LIVE REPRODUCED; SPEC READY | Registry/modules, ACTIVE/MOVED/RETIRED manifest, prompt-consumer parity |
| P0-AJ | Make typed queue identity/rendering authoritative and round-trip safe | LIVE REPRODUCED; SPEC READY | `QueueWorkItem`, zero stale filenames/width drift, digest-bound prompts |
| P0-AK | Enforce the verifier attention budget with a dynamic bounded work plan | LIVE REPRODUCED; SPEC READY | `VerifyWorkPlan`, exact queue partition, no oversized shard, resume-stable dynamic work identities |
| P0-AL | Prevent raw-substring privacy matching from rejecting valid reports | LIVE REPRODUCED; SPEC READY | Ledger-bound ASCII token boundaries, benign-hyphen fixtures, report commit/resume parity |
| P0-AM | Make required child-agent work driver-owned and transactionally joined | LIVE REPRODUCED; SPEC READY | `WorkPlan`, enforceable foreground/tool policy, exact child closure, no late writes, retry reuse |
| P0-AN | Separate backend runtime state from immutable audit inputs | LIVE REPRODUCED; SPEC READY | `BackendRuntimeContract`, exact runtime isolation, stable instruction binding, snapshot/containment parity |
| P0-AO | Make resume mismatch non-destructive and explicitly authorized | LIVE REPRODUCED; HASH-SEALED INCIDENT; SPEC READY | Typed startup intent/run ID, stop-before-model mismatch receipt, distinct-destination restart, migration lineage, report/test preservation, observer abort receipt |

## Priority-1 obligations

| ID | Short requirement | Current state | Proof still required |
|---|---|---|---|
| P1-A | Anchor enumeration to finding-local exact symbols | LIVE REPRODUCED; SPEC READY | AST/reference fixtures, hub bounds, recall/noise A/B |
| P1-B | Make boundary generation type-aware | CODE REPRODUCED; SPEC READY | Ecosystem type resolvers and boundary-class fixtures |
| P1-C | Replace broad prose triggers with structured obligations | CODE REPRODUCED; SPEC READY | Trigger provenance and precision-negative fixtures |
| P1-D | Derive semantic invariant receipt from typed sources | LIVE REPRODUCED; SPEC READY | Multi-source reconciliation and conflict debt |
| P1-E | Separate execution authenticity from harm proof scope | LIVE REPRODUCED; SPEC READY | Oracle provenance/reachability/proof-scope schema |
| P1-F | Separate precedent strength from code confidence | LIVE REPRODUCED; SPEC READY | Exact precedent matching and no confidence/disposition coupling |
| P1-G | Prevent single-domain consensus from becoming full agreement | CODE REPRODUCED; SPEC READY | Domain diversity/independence facts and calibration fixtures |
| P1-H | Stop self-exclusion parser context/already-accounted re-emission | LIVE REPRODUCED; SPEC READY | Exact row grammar and disposition reconciliation |
| P1-I | Accept resolvable backend citation forms | LIVE REPRODUCED; SPEC READY | Claude/Codex syntax-normalization fixtures |
| P1-J | Preserve structured recon authority during signal stripping | LIVE REPRODUCED; SPEC READY | Typed authority projection and lossless transform diff |
| P1-K | Enforce evidence quality and proof scope structurally | CODE REPRODUCED; SPEC READY | Typed evidence schema, validator/report parity |
| P1-L | Restore L1 composition analysis conditionally | CODE REPRODUCED; SPEC READY | L1 state/message/lifecycle seam operators and canaries |
| P1-M | Make arm-before-trust/mutual-zero methodology actually reachable and typed | LIVE NON-REACHABILITY REPRODUCED; PARTIAL DIRTY IMPLEMENTATION | Live EVM operator receipt, typed role facts, external-boundary route, distinct compound verification, and >=2-repo/>=2-ecosystem activation gate |

## Completion boundary

The ledger remains active until every row is either `DONE` with authoritative evidence or explicitly removed by a reviewed superseding requirement with rationale and no scope loss. Green unit tests, one regression repository, or a clean report do not by themselves close a row.
