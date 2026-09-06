<!-- PORTABLE SANITIZED RESEARCH COPY
Source identity: Plamen_Claude-to-Codex_Implementation_Handoff_2026-07-15.md
Raw bytes remain outside Git. Architecture, methodology, execution, acceptance, and comparison semantics are retained; personal paths, private target identities, target-specific candidate/artifact identifiers, artifact digests, and concrete private finding descriptions use deterministic placeholders. See CORPUS_MANIFEST.json and research/PRIVATE_GAP_INDEX.json for provenance and the redaction rule.
-->

# Plamen — Claude → Codex Implementation Handoff

**Date:** 2026-07-15
**From:** Claude (independent reviewer / spec author for this program)
**To:** Codex (program lead / architect / integrator)
**Status:** Reviewable spec. No core-file edits were made producing this. Fixtures are given as **designs** (code blocks), not live files — Codex implements them as real `scripts/test_*.py`.

---

## 0. Operating agreement (agreed by user)

- **Ownership:** Codex leads — architecture, integration, branch discipline, acceptance gates, benchmark-runner design, A/B runners, and the ledger program. Bounded Codex specialist agents do forensics / fixtures / modules / providers and **must not concurrently edit the same core driver file**.
- **Claude:** independent plan/diff reviewer, adversarial failure analysis, one blinded adjudicator. **Will not author core-file diffs** for the items below.
- **Two load-bearing invariants (non-negotiable):**
  1. **No model author self-certifies its own implementation.** Every diff is reviewed by the *non-implementing* model **and** must pass the deterministic grader. (This is why Claude specs+reviews R10.1 but does not implement it — Claude authored R10.)
  2. **The benchmark/grader + held-out corpus live OUTSIDE the production Plamen tree**, with no audit-agent or RAG read access. **private regression target is development/regression data only — it never counts toward a scored result.**
- **Reviewer contract:** adversarial review has **blocking authority on cutovers**, not advisory. Collapse the rest of the org chart: the *user* is the human tie-breaker + acceptance gate; the deterministic grader is code; the "blinded adjudicator" is simply whichever model did not implement the piece.

---

## 1. Corrected execution sequence

Amended from Codex's draft in one place: **steps 1 and 2 run in parallel** (the Release-0 fixes are fixtures-first + ≥2-repo/ecosystem-safe by construction; they do not need the bench to be safe to ship — the bench gates the *architectural* bets, not the parser/binding/soundness fixes).

1. Benchmark + lifecycle-stage harness (§4) — **parallel with 2**.
2. Release-0 cheap application/soundness fixes (§2) — **parallel with 1**.
3. R10.1 fixtures + fix (§3): defect 8, defect 5, conservative defect 7.
4. Factorial full-context / compact-SOP / seam-role A/B (§5).
5. Passive finding-identity observer over the existing structured sidecars.
6. One inventory→report dual-write identity slice.
7. Benchmark + fault-injection parity gate.
8. General premise/disposition model (extract the shared premise-veto policy behind R10).
9. Expand the ledger **only if** measured lifecycle loss justifies it.
10. Prioritize AST/graph providers by **measured** extractor misses.

**Hard gate:** nothing past step 3 ships without the §4 harness producing per-stage numbers on a held-out set.

---

## 2. Release-0 fix specs

Every item is: independently verified against the code, ≤~80 LOC, recall-safe or precision-safe (stated), and Part-0 clean (no protocol names). Order by ROI. Each carries a **fixture (red→green)** design and the **acceptance gate** Claude will review against.

### R0-1 — Breadth security-kernel floor  *(highest-value discovery fix)*
- **Gap:** `prompts/shared/v2/phase3-breadth.md:93-291` is 100% procedural; `generic-security-rules.md` is **never injected** into a breadth worker (`plamen_driver.py:7506,7657,7664,7670` — comments admit it "lives only in that file"; only R13 was special-cased). A missed recon skill trigger silently removes an entire reasoning lens with **no floor**. Matches the documented "SC skill-injection never ported from L1" root cause.
- **Fix:** author one compact, universal security-reasoning kernel (vuln-class checklist, generic HOW, no protocol names) and inject it unconditionally into `_build_breadth_worker_prompt` alongside the recon-selected skills. Keep it short (injectable-first discipline: this is the *floor*, skills add depth).
- **Fixture:** build a breadth prompt with an **empty** recon skill selection → assert the kernel block is present; build one with skills → assert kernel **and** skills both present (kernel is additive, never replaces skill injection).
- **Safety:** recall-positive, drops nothing. **Part-0:** kernel must be generic; a reviewer greps it for protocol/token names → must be zero.
- **Acceptance gate (Claude reviews):** kernel content is HOW-not-WHAT; injection is unconditional; no regression in existing breadth-prompt tests.

### R0-2 — Schema-drift parser fixes  *(directly recovers the private regression target losses)*
- **Gap (three drifts):**
  1. `finding_mapping` provenance parsed **line-scoped, not table-scoped** — `ids = _INTERNAL_FINDING_ID_RE.findall(line)` at `plamen_mechanical.py:2859-2865`; any line with ≥2 IDs is treated as co-sourced. **This is the PRIVATE-FINDING-011→PRIVATE-FINDING-004 false-merge root cause.**
  2. Hypothesis-ID grammar `GRP-\d+` rejects anti-absorption splits `GRP-NNx` (`PRIVATE-GROUP-001`) — the **first** private regression target loss (PRIVATE-FINDING-005 collapse at the queue parser).
  3. CI-ID drift (`PRIVATE-ARTIFACT-ID-001` vs `CI-\d+`) dark-drops skeptic committed-invariant blocks.
- **Fix:** one shared ID grammar/schema accepted by producer **and** consumer; parse `finding_mapping` by **actual table rows** (header-bound columns), never co-occurring prose IDs; extend the CI grammar. Detection≠recovery: the existing CI drift detector only warns (`.ci_gap` sentinel) — make it **recover**.
- **⚠ Interaction with shipped R10 id-join:** the R10 gate's depth-verdict join deliberately relies on `_parse_hypothesis_constituents` picking up `PRIVATE-FINDING-005` from the `"SPLIT from PRIVATE-FINDING-005"` **status cell** (that is the desired link). When you table-scope `finding_mapping`, preserve that split-source→constituent linkage (it lives in a real table row's status column, so table-scoping keeps it) — add a regression fixture asserting `PRIVATE-FINDING-005 → {PRIVATE-INVENTORY-001,042,116,239}` still resolves after the parser change.
- **Fixture:** (a) a `finding_mapping` table where two unrelated IDs co-occur in one row's prose → assert they are **not** co-merged (table-scoping); (b) a `PRIVATE-GROUP-001` split row → assert it parses and joins; (c) the R10 split-source regression above.
- **Safety:** precision-safe (stops false co-merges) **and** recall-safe (recovers dropped falsification obligations). **Part-0:** clean.
- **Acceptance gate:** the three fixtures; plus a private regression target-artifact replay asserting PRIVATE-FINDING-011 is **not** absorbed into PRIVATE-FINDING-004 and PRIVATE-FINDING-005 is not collapsed.

### R0-3 — PoC label: `VERIFIED` → `CONFIRMED` on unexecuted proof tags  *(soundness)*
- **Gap:** `has_mechanical_proof` (`plamen_types.py:200-210`) is a naive substring test, so `[POC-PASS] [MECHANICAL-UNAVAILABLE]` and `[POC-PASS] [POC-UNVERIFIED-HARNESS]` (harness/toolchain miss, **never executed** — `mechanical_verify.py:1577-1584,1611-1613`) still return proof-grade → ship `VERIFIED`. The honesty flags are cosmetic to that function.
- **Fix — LABEL ONLY:** when a proof tag co-occurs with `[MECHANICAL-UNAVAILABLE]` or `[POC-UNVERIFIED-HARNESS]`, the canonical status maps to **`CONFIRMED`** (by-trace), **not** `VERIFIED` (by-execution). **Keep the severity and body placement unchanged** — this is the v2.8.17 recall carve-out's whole point (a toolchain miss is not disproof). Do **not** demote severity; do **not** import the heavier machine-attestation scope.
- **Fixture:** `[POC-PASS] [MECHANICAL-UNAVAILABLE]` → status `CONFIRMED`, severity unchanged, stays in body; a genuinely executed `[POC-PASS]` (status `PASS`) → status `VERIFIED`; a `[PROD-FORK]` → `VERIFIED` (production tags are proof-grade, never capped).
- **Safety:** recall-safe (severity/body preserved), honesty-positive. **Part-0:** clean.
- **Acceptance gate:** the label changes exactly on the two flagged branches and nowhere else; no severity movement; proven-only mode unaffected.

### R0-4 — Recon external-dependency research owner  *(the b_rate stub root cause)*
- **Gap:** no live recon worker owns `external_dependency_research.md`; the four live roles (`build_static/design_context/inventory_surface/templates_patterns`, `plamen_driver.py:6405-6430`) own none of it, and the file is written only as a **prepass stub** (`recon_prepass.py:1838-1864`). Methodology assigns TASK 11 to Agent 1B but the worker roster dropped it. This is the dominant private regression target external-integration RC-METHOD miss.
- **Fix:** restore an explicit recon external-research owner shard in the roster; require dependency-row **parity** even on fetch failure (an unfetched dependency becomes a `NEEDS_DEPENDENCY_RESEARCH` obligation row, not a silent empty ledger).
- **Fixture:** a repo with a named non-vendored external dependency → assert a research row (or explicit unresolved obligation) exists post-recon; a fetch failure → assert an obligation row, not an empty stub.
- **Safety:** recall-positive. **Part-0:** the detector keys on "non-vendored external import," never a named protocol.
- **Acceptance gate:** dependency-set parity holds even under simulated fetch failure; downstream `[EXT-CITED]`/`NEEDS_DEPENDENCY_RESEARCH` gate now has a populated ledger to cite.

### R0-5 — Loud caps / overflow receipts  *(found-then-lost)*
- **Gap:** the enumeration caps truncate with **zero emission** — `_MAX_COREFS_PER_VAR=6`, `_SKIP_VAR_REF_THRESHOLD=25`, `_MAX_PER_DERIVER=15` (`enumeration_gate.py:69-71,321,720,1631`); Gate P breaks at ≤30/run (`plamen_mechanical.py:4364-4366,4373`). A silent break-at-cap is exactly the found-then-lost class the net exists to prevent.
- **Fix:** count-at-cap + one obligation writer → emit a `COVERAGE-SHORTFALL` / `promotion_overflow` receipt into the Appendix-B human-review lane whenever any cap truncates.
- **Also folds R0-5b (popularity skip):** `_SKIP_VAR_REF_THRESHOLD=25` silently drops the highest-fan-in (global accounting) variable — the highest-value cross-function-invariant target (`enumeration_gate.py:224-225`). **Do NOT invert to more gating** (with `_MAX_COREFS_PER_VAR=6` that emits an arbitrary 6-of-30 set → combinatorial blow-up, precision-unsafe). **Instead emit one loud "high-fan-in accounting variable unaudited by co-ref gate" flag** into the same shortfall receipt.
- **Fixture:** force each cap to truncate → assert a shortfall receipt row exists; a >25-fan-in symbol → assert the loud flag, and assert **no** 6-of-N co-ref explosion.
- **Safety:** recall-safe (converts invisible loss to a visible flag). **Part-0:** clean.
- **Acceptance gate:** every cap path emits a receipt; the popularity path emits a flag, not obligations.

### R0-6 — SC enumeration-gate graph-resolution self-check
- **Gap:** `if graph is None: return 0` silent no-ops at `enumeration_gate.py:198-199,674,1006,1615` — an under-resolved call graph emits zero, indistinguishable from "nothing to find." The existing loud check is **L1-only** (`plamen_driver.py:15446`, gated on `pipeline=='l1'`).
- **Fix:** add a resolution-ratio sanity check to the SC gate; below a threshold, **fail loud** (a graph-health obligation), do not silently return 0. Pairs with R0-5's receipt.
- **Fixture:** a `None`/degenerate graph → assert a loud graph-health obligation, not a silent 0.
- **Safety:** recall-safe (silent under-generation is the most dangerous mode for a recall-starved system). **Part-0:** clean.

### R0-7 — Axis-1 co-referencer word-boundary matching
- **Gap:** `enumeration_gate.py:275-276` reconciles coverage with `c.lower() not in text` — pure substring, so an incidental mention **false-confirms** coverage (recall leak).
- **Fix:** word-boundary / identifier matching. ~5-15 LOC.
- **Fixture:** a co-referencer name appearing only as a substring of an unrelated identifier → assert it re-emits as a GAP (not false-confirmed).
- **Safety:** recall-safe (tightening turns incidental matches back into GAP candidates that verify-then-dispose).

### R0-8 — Compact items (full specs on request; each independently verified)
| ID | Gap (file:line) | Fix | Class |
|----|-----------------|-----|-------|
| R0-8a Sidecar depth-prompt binding | `plamen_driver.py:9439-9460,10643-10649` — the 3 Thorough sidecars fall through to generic `phase4b-depth.md` though `phase4b-perturbation.md`/`phase4b-skill-checklist.md` exist | sidecar→prompt map; reject unknown role→method | recall |
| R0-8b Delete false "applied" receipt | `plamen_validators.py:9145-9259,4726-4732` — `_synthesize_step_execution_trace` marks any tag `Executed=yes`; gate accepts >200 bytes | delete the synthesis; mark step-ID-less skills `unmeasurable`, never EXECUTED | precision/honesty |
| R0-8c Resume source-snapshot digest | `plamen_types.py:831-935` — checkpoint stores completed/degraded/config only, no tree/commit/toolchain/prompt hash | hash git-tree+config+prompt-version; invalidate descendants on mismatch | correctness |
| R0-8d Freeze commit + hash in-scope | `mechanical_verify.py:357` isolation is test-name-filter only; `plamen_driver.py:5272` `_snapshot` is phase-artifacts, not source | freeze audited commit, hash in-scope files so generated `poc_*` can't enter scope | precision/repro |
| R0-8e Gate-budget cap (protocol text) | `post-audit-improvement-protocol.md` Appendix A caps file **size**, not gate **count** | one paragraph: apply the RC-AGENT presumption + a budget cap to mechanical gates | anti-bloat |
| R0-8f Axis-coverage mode doc-drift | `docs/architecture.md` ("all modes") vs `plamen_types.py:1293-1305` ("Thorough only") | align doc to code; since the pass is zero-LLM-cost, consider enabling in Core/Light as a free recall gate | correctness |

---

## 3. R10.1 spec (Claude specs; Codex implements; Claude + bench review)

R10 (shipped: `_apply_external_assumption_undemotions` + consume-side floor in `_expected_report_index_severities`) is a **backstop detector**, not a lifecycle repair. It floors to the depth-claimed severity and does not re-verify. Keep it; fix three residuals **fixture-first**. All three were independently confirmed by the code review.

### Defect 8 — verifier `REFUTED` exclusion  *(highest-priority R10 residual)*
- **Gap:** the gate fires only on `CONTESTED/PARTIAL/UNRESOLVED` (`plamen_validators.py` ~:21380). A verifier that **REFUTES** on an unsupported favorable external premise (depth CONFIRMED, verifier REFUTED) escapes entirely.
- **Fix — narrow:** also fire on verifier `REFUTED` **only when ALL hold:** depth is positively CONFIRMED/PARTIAL (via the constituent join); the favorable **external** premise is decisive to the refutation; there is no matching citation/research; the decision is **not** grounded by premise-resolving execution. **Do NOT** include `FALSE_POSITIVE` or `DUPLICATE`. This is distinct from the legitimate all-depth-REFUTED guard (G4), which stays.
- **Fixtures:** (pos) depth CONFIRMED + verifier REFUTED on uncited external premise → fires; (neg) verifier REFUTED with depth REFUTED → no fire (G4); (neg) verifier REFUTED with an `[EXT-CITED]` premise → no fire; (neg) `FALSE_POSITIVE`/`DUPLICATE` → no fire.

### Defect 5 — lexical stability cue precision
- **Gap:** the stability regex (`plamen_validators.py` ~:17553) matches internal statements like "invariant within a transaction" with **no external provenance** — accepted as an external cue.
- **Fix — narrow:** for the stability-only route, aggregate the **mapped constituent inventory blocks** and require **source-backed external provenance** (the stability claim must reference an external dependency, not an internal invariant) before the cue counts.
- **Fixtures:** an **internal-invariant** "stable within block" with no external dependency → **no fire**; an actual **private-external-dependency-shaped** external-stability positive → fires.

### Defect 7 — any executed PoC suppresses the gate  *(conservative interim only)*
- **Gap:** every `Attempted:YES` result suppresses R10 (`plamen_validators.py` ~:21369). A PoC may prove only the **local mechanism** while leaving the **external premise** unresolved.
- **Correct condition:** not "a PoC ran" but **"evidence resolved the premise used to dismiss the finding."** This needs premise-to-evidence binding.
- **Fix — CONSERVATIVE INTERIM ONLY** (do the full binding later, step 8): keep G3 as-is **unless** the verify record carries an explicit, structured signal that the executed PoC targeted the **external premise** (not merely the local mechanism). **⚠ Do NOT blindly remove G3** — that reinflates genuinely-refuted findings. If premise-scope cannot be distinguished from available fields, **leave G3 untouched** and defer to step 8. This defect only ships in R10.1 *if* a clean premise-scope signal exists.
- **Fixtures:** local-mechanism-only PoC pass with unresolved external premise → (if signal exists) fires; premise-resolving PoC pass → no fire; ambiguous → no fire (conservative).

### R10.1 severity note
R10 floors to the depth-claimed severity by design; recovering the **depth-side under-rating** (the private regression target High) is **out of scope for R10.1** — it belongs to R0's "confirmed-mechanism harm review independent of provisional severity" and step 8. Do not try to make R10 manufacture severity.

### R10.1 acceptance gate (Claude reviews, does not implement)
All fixtures above pass; the shipped `{PRIVATE-FINDING-005,PRIVATE-FINDING-006,PRIVATE-FINDING-007,PRIVATE-FINDING-002}` private regression target fire-set is unchanged or grows only by legitimate REFUTED cases; **zero** new fires on the ≥4 clean bench repos; Part-0 clean (structural predicates only). private regression target remains regression data, not a scored result.

---

## 4. Benchmark + lifecycle-stage harness spec  *(the gate for everything architectural)*

- **Location:** a **separate evaluation workspace outside the Plamen tree**, with **no audit-agent or RAG read access** (else anti-overfit is undone). private regression target lives here as **regression/dev data only**.
- **Corpus:** stratified professional findings (year, firm, severity, protocol category, rarity, quality); **multi-ecosystem** (EVM, Solana, Move/Aptos/Sui, Soroban, DAML, Go/Rust L1 — Solodit alone cannot validate non-EVM); repository/firm/**future-time holdouts**; clean+seeded-mutation versions for precision; **exclude any finding used to author/revise method cards.**
- **Ground-truth annotation:** two independent reviewers label **reusable operators, required target relations, environmental premises, evidence needed** — **never** protocol-specific answers.
- **Per-lifecycle-stage metrics (the core deliverable):** expressible → scheduled → **applied** → **discovery recall** → **retention recall** → verification recall → **report recall** → severity calibration; plus application-rate, dedup-loss rate, novel-valid rate, found-to-report lineage-loss. The **stage localizer** classifies each miss's *earliest* failing stage → this is what mechanically separates RC-METHOD from RC-AGENT from pipeline-loss and stops "adding discovery prose to fix a report parser."
- **Grader:** **deterministic, owns all mechanically-decidable scoring**, neither model can edit it. Promote a change only with CIs, non-regression constraints, and a future-time shadow set. "Found PRIVATE-FINDING-001 in private regression target" is a **fixture, not evidence.**
- **Part-0:** the harness stores stage labels/counts only — never the bugs, never file:line answers.

---

## 5. A/B factorial spec (discovery hypothesis — Pashov)

Run **before** the migration; **do not** assume Pashov is better, **do not** dismiss it. Separate the variables (Codex's matrix, adopted verbatim):

| Variant | Context | SOP | Seam roles |
|---|---|---|---|
| P0 | Current Plamen | Current | Current |
| P1 | Full-source bundle | Current | Current |
| P2 | Current retrieval | Compact SOP | Current |
| P3 | Current retrieval | Current | Explicit seams |
| P4 | Full-source bundle | Compact SOP | Explicit seams |
| P5 | Exact pinned Pashov V3 | Pashov | Pashov |

Identical model versions, budgets, tools; fresh repos; **no ground-truth retrieval**; ≥3 independent runs; **score raw discovery separately from verification and report.** For large projects, test **component-complete architectural bundles**, not the whole repo past useful context density. Note Pashov's own hygiene caveats (82.4% vs 68.6% chart conflict; 150+ runs; Core vs Light mismatch; UNCERTAIN=ALLOWS + no source reverification + no cross-function merges → possibly higher apparent recall, weaker precision) — these are why it is a **reproduction target, not a conclusion.**

---

## 6. What Claude will adversarially review (per-diff checklist)

For every diff Codex (or a Codex specialist) produces, Claude checks and can **block cutover** on:
1. **Fixture-first honored** — the red→green fixture exists and genuinely fails pre-fix.
2. **Recall/precision-safety** — matches the stated class; no silent coverage narrowing on a recall-starved system.
3. **Part-0** — grep the diff for protocol/token/contract/function names used as check-for-X hints or stored answers → must be zero.
4. **No self-certification** — the implementing model is not also the sole scorer; the bench/grader ran.
5. **Blast radius** — targeted + full-suite green; ≥2-repo/ecosystem replay for anything touching enumeration/dedup/severity/report.
6. **R10.1 specifically** — Claude reviews the diff against §3 without having authored it, per the no-self-certify invariant (Claude authored R10).

---

## Appendix — factual corrections carried into this handoff

- The `_canonical_finding_hash` / identity map is **already refreshed from `breadth` onward** (`plamen_driver.py:16809-16817` phase set includes breadth/rescan/inventory/depth/…/report_index), **not** only at report assembly. The "move the CID upstream" premise is already satisfied; the ledger is a **maintainability/precision** North Star **mis-ranked as a #1 recall lever**, and is **gated behind** the cheap parser fixes + the bench (steps 5-9).
- The eight existing structured sidecars (`_id_ledger.json`, `finding_records.json`, `verification_queue.json`, `verdict_manifest.json`, `judge_decisions.json`, `obligation_ledger.json`, `report_index_candidates.json`, `report_index_actions.json`) mean the ledger's first step is **passive observation + extend existing sidecars**, not SQLite + phase rewrite.
- The confidence-monotonicity / remove-RAG recommendation is **REJECTED**: the composite scores depth-routing/budget only (never validity/severity); low-RAG → UNCERTAIN → *more* depth for novel findings; monotonicity is a deliberate guard against the iteration-2 dilution regression (AD-1/AD-5).
