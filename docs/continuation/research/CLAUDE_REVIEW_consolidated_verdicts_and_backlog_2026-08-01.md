# CLAUDE_REVIEW — Consolidated Verdicts & Post-Handoff Backlog

**Date:** 2026-08-01 · **Audience:** Codex (post-handoff planning input) · **Author:** Claude Fable 5

**Source documents** (detail lives there; this file is the decision layer):
- `CLAUDE_REVIEW_codex_architecture_audit_2026-07-31.md` — 8-slice audit of the uncommitted Codex architecture
- `CLAUDE_RESEARCH_recall_architecture_2026-08-01.md` — 6-thread research round

**How to read this file.** Every item carries a confidence tag. Act on tags in this order and do not silently promote one:

| Tag | Meaning | Action |
|---|---|---|
| `[CONFIRMED]` | Re-verified directly against the tree by the reviewer, with file:line | Act on it |
| `[REPORTED]` | Sub-agent finding, internally consistent, not independently re-verified | Verify, then act |
| `[VERIFY-FIRST]` | Mechanism plausible but the original citation was **wrong** | Re-derive before touching code |
| `[INFERRED]` | Structural reasoning, not observed at runtime | Treat as hypothesis |

**Standing constraint (applies to every item below):** the audited change added **+370,000 lines with 0 removed**, all three god-functions grew, and 24 modules / 39,824 LOC are unreachable from any entry point. **Each item lands with its legacy counterpart deleted; driver LOC and god-function lengths must not increase.** An item that cannot meet that is not ready.

---

## 1. The two diagnoses

**D-1 — Provenance was built; anchors were not.** The Codex architecture invested enormously in *recording and governing* decisions (ledgers, receipts, authorities, digests, debt rows, replay bindings). Every one of them ultimately records an LLM's judgment with a hash attached. Six independent research threads converged on the conclusion that the missing layer is **verdicts produced outside agent judgment**.

**D-2 — The anchors that exist are enumeration anchors, not judgement anchors.** Mechanically-true verdicts exist in ~four places: PoC re-execution, recon's build/Slither/SCIP/OpenGrep subprocesses, driver-built ID sets, and the fuzz *scheduling* decision. **Every artifact carrying a security verdict** — severity, status, PoC outcome, confidence, disposition, precedent score, every fuzz *result* — is LLM-written or Python arithmetic over an LLM-typed field. Mechanical truth is computed and then discarded at the seams.

**Not a deception finding.** Gates are honestly, deliberately warning-only; "bounded retry, then ship" is the right posture for a haltless recall-first pipeline. The defect is that `CLAUDE.md`, `orchestrator-rules.md` Rule 15, and `report-template.md`'s token tables describe a **mechanically-enforced** system while the code implements an **advisory** one. Close the gap or state the posture honestly.

**The illustrative artifact:** `mechanical_gate_*` is 9,653 LOC — schema, activation baseline, seam budgets, a gate-count governance equation — with **36 gate records, 0 driver references, `baseline_review_status: UNREVIEWED`, and all six `seam_budgets` ceilings `null`**. `[CONFIRMED]` The governance frame for anchors was built before the anchors, and cannot enforce a budget. The socket exists and is unplugged.

---

## 2. Release blockers — close before the handoff counts as done

| ID | Item | Confidence | Evidence |
|---|---|---|---|
| **B-1** | **Run the full test suite.** One targeted slice showed **36 failures**, concentrated in Codex's own new suites. Nothing else here is assessable against an unknown baseline. | `[CONFIRMED]` | `-k "report_index or severity or index_completeness or repair"` → 36 failed / 1161 passed |
| **B-2** | **Remove `write_dedup.py`** from both trees; decide history rewrite + client notification. Tracked, public since 2026-07-03, 273 stars / **54 forks** (a rewrite will not reach forks). Contains a named client's unfixed High-severity findings with file:line — also a Part 0 violation. | `[CONFIRMED]` | `gh api` visibility + tracked in both trees |
| **B-3** | **Fix the commit boundary.** Track `requirements-ci.constraints` / `requirements-ci.lock` / `scripts/ci_dependency_authority.py` (otherwise `pip install -r requirements-dev.txt` hard-fails for everyone); normalize the `scripts.bounty` import; add repo root to `pythonpath`; commit tracked+untracked halves **together** (driver has **72** top-level imports of untracked modules). | `[CONFIRMED]` | `requirements-dev.txt:5`; `git ls-files` empty for all three |
| **B-4** | **Repair SC report-index recovery.** Intentional redesign, half-landed: the replacement needs a ledger binding written only at *commit*, never at pre-spawn *arm*; the author's own replacement test fails because the canonical-head exemption omits `report_coverage.md`. | `[REPORTED]` | `plamen_validators.py:20535-20545`; 3 failing author tests |
| **B-5** | **Gitignore `review_fixtures/`** (271 files staged by `git add -A` today; the repo's own `test_public_packaging_freeze.py:25` already declares it private, in the same tuple as `write_dedup.py`). Relocate its **5 load-bearing modules** to `scripts/_test_support/` and update the 24 importers. | `[CONFIRMED]` | `git status --porcelain` → `?? review_fixtures/` |
| **B-6** | **Decide on the two halts.** `--fresh` now refuses to start on any project with a prior `AUDIT_REPORT.md`; terminal `REPORT_INTEGRITY` **moves the deliverable out of the project root**. Both contradict the haltless contract this same diff reasserted in `CLAUDE.md`. | `[REPORTED]` | `plamen_driver.py:69676`, `:78102` |
| **B-7** | **Declare `cryptography`** (+ PyYAML, packaging). Bare `from cryptography import x509`, absent from every requirements file. | `[CONFIRMED]` | `claude_executable_observation.py:364,585` |

Security items S-1…S-5 (Windows `.cmd` argv injection, `CLAUDE_BIN` hijack, pre-gate credential exposure, fuzz allowlist, global settings mutation) are in the audit doc §3. They are not audit-correctness blockers but are real risk; schedule after B-1…B-7.

---

## 3. Post-handoff backlog

Ordered by value-per-effort. **Acceptance criterion** is what makes each item *done* — not "code exists."

### 3.0 Hard ordering constraints — read before extracting tasks

These are **blocking edges, not preferences**. Each one exists because violating it reproduces a failure mode this review documented. The value-per-effort ordering of the table below does **not** override them.

| Edge | Constraint | Why — the failure it prevents |
|---|---|---|
| **B-1 → everything** | Run the full suite before starting any P-item | 36 failures already measured in one slice; every other item is unassessable against an unknown baseline |
| **P-8 → P-2** | Give the gate registry a floor (or delete it) **before** registering the mutation gate | Registering a new gate into a registry with 0 driver references, `UNREVIEWED` baseline and `null` ceilings reproduces the exact pattern §12.4 documents — a gate that governs nothing and reports assurance you don't have |
| **P-13 → P-2** | The no-zero-count assertion pattern must exist **before** the mutation gate ships | The empty-harvest silent-pass class already cost **14 findings including a High** in the axis-coverage phase. A mutation gate without it becomes the 9th unguarded instance |
| **P-13 → P-7** | Fix prompt/parser divergence **before** generalizing any coverage pattern | Generalizing a pattern whose prompt and parser disagree propagates the divergence to every new instance |
| **P-11 audit → P-11 fix** | Audit which text each of the 19 call sites passes **before** changing `has_mechanical_proof` | The originally-reported citation and quoted string were **wrong**; fixing on that citation would change deliberate, documented behavior (`plamen_types.py:200-210`) |
| **vacuity guard → P-6** | The `assert(false)` guard must land **before** any symbolic result is consumed | Foundry's symbolic lane ships with no vacuity check; without the guard, a vacuous property reads as a passing one |

Everything else in §3 is independently schedulable.

| ID | Item | Effort | Conf. | Where it plugs in | Acceptance criterion |
|---|---|---|---|---|---|
| **P-1** | **Remove output caps + severity-prioritization from producer prompts.** 48 instances of `Maximum N findings` / `prioritize by severity`. Keep *input* caps (context mgmt); remove *output* caps. Also remove the self-certification in `self-check-checklists.md` (`Anti-dilution: max 5 findings per agent per iteration?`). | hours | `[CONFIRMED]` | `prompts/*/phase4b-scanner-templates.md`, `phase4b-loop.md`, `rules/phase3b-rescan-prompt.md` | Zero output-cap instructions remain in producer prompts; every dropped finding is ledgered by `report_disposition_authority`, not suppressed by an agent |
| **P-2** | **Mutation gate on invariants → `[SPEC-KILL: n/m]`.** An invariant killing zero mutants is vacuous and supports no disposition. Calibration: 2,623 human-written formal rules in Certora contests, **only 23–28% killed a mutant.** | 2–3 d | research | Register as a live gate in `mechanical_gate_registry.json`; record outcomes via `tool_coverage_ledger` (already stdlib-only, schema-validated) | Experiment first: hand-translate one completed audit's invariants, run Gambit, report kill rate. Ships only with a **no-zero-count assertion** (see P-13) |
| **P-3** | **Mechanical read-coverage from `tool_calls.jsonl`.** Replace the self-attested `Opened? YES/NO` checkpoint with driver-computed per-worker file coverage; auto-spawn follow-ups for under-covered in-scope files. | 1–2 w | `[CONFIRMED]` | File is already written at `plamen_driver.py:39523`; only consumers today are `max_tool_calls_total` budget caps | The `Opened?` column is deleted; coverage is computed, not reported by the agent |
| **P-9** | **Move PoC-fail demotions after mechanical verification.** `sc_verify_aggregate` (`plamen_types.py:1423`) precedes `sc_mechanical_verify` (`:1433`), and demotions apply at `plamen_driver.py:15361/15367` under the aggregate guard — so `poc_demotions.md` is built **before any test has run**, triggered by the literal `[POC-FAIL]` string in LLM prose. | small | `[CONFIRMED]` | Phase ordering only | `poc_demotions.md` is derived from executed-test results, not prose |
| **P-4** | **Cross-model skeptic + brocard pre-PoC triage.** Route skeptic/judge to a different model family than the verifier. Add the seven brocards as ACCEPT / DISMISS / NEEDS-MORE-INFO before PoC spend; brocard #2 ("no exploit from the heavens") replaces the ad-hoc trusted-actor modifier. | small–med | research | Skeptic phase routing; new gate between chain analysis and verification | Skeptic model ≠ verifier model; DISMISS routes to appendix, never to a drop |
| **P-5** | **Composition class — 3-line always-on extend first, then the injectable skill.** Extend the pre-auth panic directive: *"…or before the generic decoder/validator whose guarantees the consumer assumes. Name the file:line that owns the check. 'The framework validates it' without a file:line is not an owner."* Then the full skill, framed as **ownership, not ordering**. | 3 lines → ~150 | research | `prompts/{l1,go,rust}/phase4b-depth-templates.md`; then injectable into `depth-consensus-invariant`. 0 budget slots — synthesizes `trust_boundaries.md`, which the pipeline already produces and never analyzes | Skill emits a per-layer ownership matrix; every `ABSENT` cell carries a dispositioned 3-synonym grep; shared-fate gate applied |
| **P-10** | **Decide Light/Core mechanical coverage.** Invariant-fuzz returns `[]` unless mode is `thorough`; combined with the reported OpenGrep skip, **Light may have no mechanical detector pass at all** — findings rest entirely on LLM judgment with zero anchors. | small | `[CONFIRMED]` | `plamen_driver.py:11267` | Either Light gains an anchor, or the mode table says plainly that Light has no mechanical evidence |
| **P-6** | **Symbolic as a PoC *generator*, EVM only, refutation-only.** For Medium+ `[CODE-TRACE]` findings: restate the harm assertion, `forge test --symbolic --json`, and on FAIL feed the emitted **concrete** regression test through the existing PoC path. **Never consume a PASS.** | 1 w pilot | research | Phase 5, optional step | Blocking prerequisite: an `assert(false)` vacuity guard. Expect ~zero conversion on AMM/lending/economic findings — that is the expected result, not a tuning target |
| **P-7** | **Narrow-then-widen variant analysis.** Pattern matching *only* the confirmed bug → generalize one element at a time → validate each widening mechanically (fires on the known-vulnerable site, silent on a known-correct sibling). | med | research | Replaces the current sibling sweep | Each widening step has a recorded fire/silent validation pair |
| **P-8** | **Give the gate registry a floor, or delete it.** All six `seam_budgets` ceilings are `null`, `baseline_review_status: UNREVIEWED`, 0 driver references. **Do this before P-2 lands** — do not register a new gate into a registry that governs nothing. | small | `[CONFIRMED]` | `rules/mechanical-gate-registry.json`; `_run_phase_validators` | Either `evaluate_registered_gate` is wired and ceilings are numeric, or 9,653 LOC is deleted |
| **P-12** | **Sweep for gates that cannot fail.** Pattern instances reported: a validator whose `issues` list is never appended before return; an SC scan harvesting `[HALT]`/`[GATE FAIL]` tokens only *L1* prompts emit; `plamen_contracts.py` — a complete fail-closed typed-contract layer with **zero production imports** that `CLAUDE.md` still calls "the shared mechanical substrate." Also: two gates with comments promising to graduate to fail-closed "after one clean audit cycle" that never did. | med | `[REPORTED]` (`plamen_contracts.py` dead-code independently `[CONFIRMED]` in the first audit) | Repo-wide | Every fail-closed gate has a fixture proving it *can* fail; the `CLAUDE.md` substrate claim is either made true or removed |
| **P-13** | **Fix prompt/parser divergence before generalizing any coverage pattern.** The axis-coverage phase once had an ID regex that silently dropped three-part headings, **losing 14 findings including a High**; the parser was fixed, the prompt still shows the old format. **8 unguarded empty-harvest instances** reported repo-wide. | med | `[REPORTED]` | `phase4b8-axis-coverage.md:142` + the 8 instances | Every ID-harvesting gate fails non-zero on an empty harvest and ships a fixture proving it still matches real producer output |
| **P-11** | **Proof-tag substring leakage — VERIFY BEFORE FIXING.** `has_mechanical_proof` is a naive `any(tag in text)` (`plamen_types.py:195-197`), and `mechanical_verify.py:1341-1343` documents a demotion annotation of the form `"[CODE-TRACE] (was [POC-PASS], integrity downgrade: …)"` and says the regex **preserves the line** — so a demoted tag can carry the literal `[POC-PASS]` substring. **The originally-reported citation and quoted string were wrong**, and the two-function split (`has_mechanical_proof` vs `has_proof_grade_evidence`) is deliberate and documented at `plamen_types.py:200-210`, not a bug. | small, after audit | `[VERIFY-FIRST]` | 19 call sites | Audit which text each call site passes; then make the check anchored (tag at a line/field boundary) rather than a substring scan |

---

## 3.9 Corpus-wave additions (P-14 … P-23)

*Added after a capture audit against 84 real contest findings + one complete Thorough run. Full detail in `CLAUDE_REVIEW_corpus_capture_wave_2026-08-01.md`.*

**The governing result:** one Python deriver produced **74 candidate findings**; all ~30 LLM discovery agents combined produced **93**. LLM sweep agents under-produce by 3–12× against their own caps (Validation Sweep: cap 12 → produced **1**), and the failure is silent. Hence:

> **Rule 0 — enumeration always goes to Python, never to an LLM. Route only the *decision* to an LLM, and only when it requires protocol intent.**

| ID | Item | Cost |
|---|---|---|
| **P-14** | Port `UNSAFE_CAST` to EVM (recon trigger + narrowing-cast deriver + inventory hypothesis). ✅ verified: 4 non-EVM trees have it, EVM has **zero** | XS |
| **P-15** | Deriver liveness telemetry — `sites_scanned` / `candidates_emitted`, `DERIVER_DEAD` when zero | XS |
| **P-16** | Route interface-parity-class derivers through `enumgap_exploration` instead of an Informational file (74 dead rows → 74 decided obligations) | XS |
| **P-17** | Shard the enumgap worklist (k≈5) + mechanical disposition reconciliation | S |
| **P-18** | Fuzz evidence gate — `[MEDUSA-PASS]` is ✅ verified at weight 1.0 in `EVIDENCE_TAGS_PROOF` but is prose-asserted with no artifact check | S |
| **P-19** | Three structural derivers: nested-loop index reuse, same-type-param distinctness, in-band error sentinel (use SlithIR — verified idle) | M |
| **P-20** | Mechanize the Validation Sweep's enumeration step, feed sharded deciders | M |
| **P-21** | Positive-control mechanism — CI meta-test + in-memory inverse mutation | S–M |
| **P-22** | Gate `chain`/`chain_agent2` to Thorough (Light spends ~22% of discovery agents on a 5% shape) | S |
| **P-23** | Fix injectable trigger vocabulary (`staking`/`dex`/`bridge` classify to zero injectables; 7 of 9 injectables unregistered) | S |

**Additional hard ordering edges** (append to §3.0):

| Edge | Constraint |
|---|---|
| **P-15 → P-14, P-19, P-20** | Liveness telemetry ships *before* new derivers, or a dead deriver is indistinguishable from a clean codebase |
| **P-17 → P-16, P-19** | Shard the worklist *before* feeding it more rows, or a 74-row list returns ~3 dispositions and reproduces the failure inside its own fix |
| **P-21 → after P-14/P-19/P-20** | Positive controls protect derivers that must exist first |

**Revised from §3:** P-1 (remove output caps) is **downgraded**. Caps are measured non-binding; drop the severity-prioritization language but expect little from it. The real fix is Rule 0.

## 4. Do NOT build

This list matters as much as §3. Each is a plausible-sounding, expensive detour, and the failure mode this codebase already exhibits is accretion.

| Rejected | Why | Evidence |
|---|---|---|
| **A mutation-based recall benchmark** | Falsified. Only **3.9%** of generic mutants semantically mimic a vulnerability; in the decisive experiment (LAVA's own authors, 80+ CPU-years) **no fuzzer found any of 50 organic bugs while routinely finding synthetic bugs in the same binaries.** Zero transfer. A mutant is a bug that contradicts its surrounding code — a local anomaly, which is what LLMs are already good at. Real findings are bugs the developer *believed correct*. | arXiv:2303.04247; arXiv:2208.11088 |
| **Certora AutoProver** | 6 GitHub stars three weeks post-launch, Solidity-only beta, five PostgreSQL databases + RAG index, **zero published benchmarks**. Its parallel property-extraction phases **duplicate what Plamen already does**; the discharge engine you'd actually want is available free (2,000 prover-min/month, 4 of 6 ecosystems) without the agent layer. Its "revise failed specs" loop has **no documented vacuity gate** — textbook reward hacking. | certora.com/blog 2026-07-15; GitHub |
| **Any standalone symbolic tool** | Category consolidating into Foundry. Manticore + Optik archived (Trail of Bits exited symbolic execution entirely), Halmos dormant since 2025-08-06, greed/ityfuzz/Pyrometer dead. Adopting Halmos a year ago would have bought a dormant dependency. | repo state verified 2026-08-01 |
| **Fan-out-then-debate as an architecture** | Six compute-matched studies (2024–2026): single-agent matches or beats multi-agent at equal token budget; debate induces sycophancy up to **85.5%**, ~70% of agents abandon correct reasoning after peer exposure. **Does not refute parallel scope partition** — different agents reading different code — which is what Plamen does and should keep. | Tran & Kiela 2026; MAST NeurIPS 2025 |
| **Verification scaffolding in prompts** | "double-check your answer" reduces output quality on current models. **Verified clean in this tree — keep it that way.** | `[CONFIRMED]` zero hits |
| **SMTChecker migration** | Verified unused; BMC deprecation is a non-issue here. | `[CONFIRMED]` zero hits |

---

## 5. Honest yield accounting

For prioritization, not modesty. The research round's threads paid out very unevenly:

| Thread | Yield |
|---|---|
| **Trail of Bits corpus** | **Carried the round.** P-1, P-3, P-4, P-7 + the class-level-not-root-cause principle. Alone it produces ~60% of the actionable output |
| **Mutation testing** | Second-most valuable, **inverted from the original hypothesis**: the obvious use (recall benchmark) is falsified; the non-obvious use (invariant vacuity gate, P-2) is the round's only genuine new capability |
| **Composition class** | One new detection capability with a drafted skill and 14 verified cross-ecosystem instances |
| **Graph/topology** | The article's framing mostly **does not apply** (the literature refutes the part you don't do, and you already do the part it doesn't refute). But applying its lens found P-9, P-10, and diagnosis D-2 — the sharpest framing produced |
| **Symbolic testing** | **Thin.** One narrow EVM-only lane, gated on a guard that doesn't exist. Main value was negative (don't adopt a standalone tool) |
| **Certora / AutoProver** | **Purely negative** — and worth it at that |

**If only one item ships:** P-2's one-day experiment. If the invariants land below ~25% kill rate, an entire pipeline phase is producing decorative output — a bigger finding than everything else combined.

---

## 6. Verification register

Claims in these documents that were **overturned or corrected** during review, recorded so they are not re-propagated:

1. **"CI runs zero tests"** — my own error. `scripts/bounty/` is gitignored, so it's absent from a CI checkout and CI does not abort. The real issue is different: CI tests the tracked subset, which excludes essentially all of this work. *Lesson: a reproduced local failure is not evidence about CI until you check what CI checks out.*
2. **"No producer prompt mandates `**Source IDs**`"** — partly wrong; five ecosystem inventory prompts do. R-1 still stands for the narrower reason that the *depth* worker contract does not.
3. **`review_fixtures/` ignore status** — my first `git check-ignore` was misleading (trailing-slash behavior); `git status --porcelain` is authoritative and shows it **would** be committed.
4. **`has_mechanical_proof` "bug"** — citation and quoted string wrong; two-function split is deliberate. Mechanism survives; see P-11.
5. **`isolated_execution_host` `exec(compile(...))`** — investigated and **refuted**; source is a digest-verified, handle-sealed CAS copy.

**Blanket caveat:** neither the audit nor the research executed the pipeline. Structural claims are measured; frequency claims (how often a branch fires in production) are `[INFERRED]` from guard conditions.

---

## 7. Suggested sequencing

This sequence already satisfies every edge in §3.0. If you reorder it, re-check §3.0 first — those edges are blocking.

1. **B-1** (run the suite) — everything else is unassessable without it
2. **B-2, B-3, B-5, B-7** — confidentiality + commit boundary; mechanical
3. **B-4, B-6** — recovery path + halt decisions
4. **P-1, P-9, P-10** — hours-to-small, all `[CONFIRMED]`, no new subsystems
5. **P-8** — *gates P-2*. Registry gets a floor or is deleted
6. **P-13** — *gates P-2 and P-7*. No-zero-count assertion + prompt/parser divergence
7. **P-2 experiment** (one day, decision-grade) → then P-2 proper if it clears, now that 5 and 6 are in place
8. **P-3, P-4, P-5 (3-line version)** — one month
9. **P-11**: call-site audit first, then the anchored-match fix
10. **P-6** (after the vacuity guard), **P-7**, **P-12**, **P-5 (full skill)** — next quarter

**Budget:** this backlog should cost **thousands** of lines, not hundreds of thousands. P-8 exists so there is a live registry to enforce that against.
