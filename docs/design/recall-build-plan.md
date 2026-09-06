# Recall Build Plan — Assumption-Commitment Falsifier (M1) + Multi-Axis Coverage Meta-Pass (M2)

> **STATUS: IMPLEMENTED & SHIPPED in v2.2.2 (historical record).**
> Two mechanisms, each a single-seam extension of the existing deriver / soft-phase / promotion framework. No new schedule slots beyond one soft phase (M2); no LLM-clobberable target sets; full anti-overfit compliance.
> **Owner subsystems**: `scripts/enumeration_gate.py` (derivers + promotion), `scripts/plamen_driver.py` (hooks + phase dispatch), `scripts/plamen_types.py` (phase decl), `scripts/plamen_validators.py` (soft validators), `scripts/chain_prep.py` (STEP-0a-LC enabling — read-only, already compatible), `prompts/shared/v2/*` (commit hooks + deriver worker prompt).

---

## 1. Overview + core principle + the 5 target missed-bug classes

### 1.1 The decouple-generation-from-verification principle

Both mechanisms obey one invariant: **the driver mechanically GENERATES falsifiable candidates; verify/fuzz/PoC execution gathers evidence.** Generation is recall-biased (emit on doubt); verification is precision-preserving only when a distinct, exact, typed lifecycle decision consumes that evidence. Neither a generator nor a failed/non-established execution decides truth: a candidate flows through `inventory → sc_semantic_dedup (4e) → chain (4c) → verify (5) → skeptic-judge (5.1)`, and negative PoC outcomes remain visible as `poc_demotion_proposals`. They MUST NOT lower severity or dispose of the candidate by themselves. This preserves generator/discriminator separation without letting the evidence producer self-certify a negative conclusion.

The two mechanisms are the two halves of a completeness argument:
- **M1 (assumption-commitment-then-falsify)** closes gaps *within a verdict*: every time an axis rules a value-bearing path SAFE or REFUTES a finding, it commits the **tacit local invariant** behind that verdict as an executable assertion and routes it to the falsifier. Survived → sharpened spec; triggered → real bug.
- **M2 (multi-axis coverage meta-pass)** closes gaps *across functions*: it builds a `function × axis` completeness matrix over mechanically-ranked hot functions and spawns a targeted deriver ONLY for orthogonal axes that were never examined.

They compose sequentially and dedup against each other (§4).

### 1.2 The 5 target missed-bug classes (generic — HOW-shaped, no protocol signatures)

| # | Class | Which mechanism primarily catches it |
|---|-------|--------------------------------------|
| **B1** | **Silent conservation / accounting break** — a value/supply/share invariant a verdict tacitly assumed holds, but doesn't at a boundary. | M1 (CONSERVATION, REQUESTED_EQ_DELIVERED shapes) + M2 accounting axis |
| **B2** | **Stale / mis-provenanced input** — a price/timestamp/external read a domain lens never interrogated for freshness or source. | M2 provenance/freshness axis + M1 FRESHNESS shape |
| **B3** | **Boundary revert / liveness brick** — 0/1/MAX/empty/first/last actor path that permanently reverts or locks and was ruled "fine". | M1 NO_REVERT_AT_BOUNDARY + M2 liveness & zero/boundary axes |
| **B4** | **Approve/authorize ≠ spend/effect asymmetry** — a guard committed as equal that diverges (approve_eq_spend, roundtrip). | M1 APPROVE_EQ_SPEND, ROUNDTRIP shapes |
| **B5** | **Unexamined-axis theft on an un-flagged hot function** — a core function no breadth agent flagged, seen by only one domain lens, never checked for value-extraction. | M2 theft axis on the hot-function set |

Every row is a **question shape** (how to interrogate any function), never a named function/token/protocol. This clears the Part-0 gate (post-audit-improvement-protocol §0): each is stateable in one sentence with no finding referent.

---

## 2. File-level change list

### 2.1 MECHANISM 1 — assumption-commitment-then-falsify

**No new phase, no new schedule slot.** Prompt-side commit hooks + one gate-side deriver + one soft validator.

#### 2.1.1 `prompts/shared/v2/phase4b6-exploration-skeptic.md` (249 lines; cap 350)
- **Add** a "Committed-Invariant Emission" subsection immediately after the `NO-GAP` disposition rule (current NO-GAP region ~L171–225). When the skeptic records `NO-GAP` for a value-bearing instance, it MUST additionally emit a `committed-invariant [CI-n]` block naming the **local guard it believes makes the instance safe**, expressed as ONE of the six generic shapes (§3.3), with symbols resolved at the locus (`file:Lnn`, variable/function names) but **no protocol constants baked as "the answer"**.
- The block is *additive-only* and inherits the phase's existing additive authority (ADD/UPGRADE only; may not drop/merge/downgrade). ~18 lines.

#### 2.1.2 `prompts/shared/v2/phase5-skeptic.md` (Defense Identified at L72)
- **Extend** the `### Defense Identified` field contract (L72–79): when a defense/precondition is named as blocking exploitation (i.e. a DOWNGRADE/refute), the skeptic MUST also emit a `committed-invariant [CI-n]` block encoding that defense as a falsifiable shape. "The defense holds" becomes "assert the defense; hand to falsifier." ~10 lines.

#### 2.1.3 `prompts/shared/v2/phase4b-depth.md`
- **Add** to the depth finding-emission contract: on a `CLEAR`/REFUTED verdict for a value-bearing path, optionally emit a `committed-invariant [CI-n]` block (same shape vocab). Optional at depth (skeptic phases are the primary emitters) to avoid depth-agent context bloat. ~8 lines.

#### 2.1.4 `scripts/enumeration_gate.py` — NEW deriver `compute_invariant_assertion_candidates(scratchpad) -> list`
- Sits alongside the three existing shape-derivers (`compute_critical_asset_mover_candidates` @L595, `compute_array_uniqueness_candidates` @L699, `compute_unbounded_input_candidates` @L763).
- **Input**: scans skeptic/depth artifacts for `committed-invariant [CI-n]` blocks; resolves each block's locus to its enclosing function via `_fn_at_location` (@L137) over `_load_graph` (@L118).
- **Output**: for each block, an inventory candidate carrying (a) the falsifiable assertion text, (b) a **Falsify Class** (§3.4), (c) chain pre/post metadata via `_chain_metadata_lines` (@L80) so it is a STEP-0a-LC enabler for free.
- **Budget**: register in `run_enumeration_gate` (@L1675) tuple, gets its own `_MAX_PER_DERIVER` (15) slot pool — INDEPENDENT of the co-ref `_MAX_ENUMGAP_PER_RUN` (40) pool, exactly as the existing three derivers do (per the @L1657 docstring rationale). Bounded sum stays recall-safe.
- **Emit**: via the existing `_emit_candidates(... _MAX_PER_DERIVER)` call already in `run_enumeration_gate`. No new promotion path — reuses the ENUMGAP stamping (candidates are `Source IDs: INVARIANT`, `Verdict: NEEDS_VERIFICATION`, `ENUMGAP`-tagged). ~70 lines. (Shipped as `compute_invariant_assertion_candidates` @L864.)

#### 2.1.5 `scripts/plamen_driver.py` — routing to the falsifier
- **No new hook.** The deriver runs inside `run_enumeration_gate`, already invoked at the inventory post-hook (@L15107) and its sibling (@L15333). M1 candidates therefore materialise pre-depth and flow into:
  1. **invariant-fuzz ingestion** — the `invariants` phase (`plamen_types.py` @L1220) already ingests finding-derived invariants; INVARIANT candidates carrying a Falsify Class are picked up as fuzz targets.
  2. **PoC gate** — via standard verify (`phase5-verification-sc.md` / `-l1.md`); an un-executable assertion caps at `[CODE-TRACE]`/CONTESTED per the PoC Testability Ledger (never a silent pass).
  3. **chain enabling** — `chain_prep._is_unverified_enabler` (@L590) already admits ENUMGAP/deriver candidates into `## STEP 0a-LC` (@L805); INVARIANT candidates qualify with zero change.

#### 2.1.6 `scripts/plamen_validators.py` — NEW `_validate_invariant_commitment(scratchpad, mode) -> list[str]`
- Clone of `_validate_exploration_skeptic` (@L6671): **warning-only**, never `passed=False`. Checks that when skeptic phases produced `NO-GAP`/DOWNGRADE verdicts on value-bearing loci, corresponding `[CI-n]` blocks exist; writes a `.ci_gap` sentinel + warning for visibility. Soft — mirrors the exploration-skeptic gate. ~40 lines. (Shipped as `_validate_invariant_commitment` @L6816.)

### 2.2 MECHANISM 2 — multi-axis coverage meta-pass

One driver module extension + one soft phase decl + one deriver-worker prompt (clone) + one promotion clone + one soft validator.

#### 2.2.1 `scripts/enumeration_gate.py` — NEW `compute_hot_function_set(scratchpad) -> list[dict]`
- Ranks functions mechanically off `_mechanical_graph.json` (`recon_prepass._write_mechanical_graph_json` @L1813) + `function_summary.md` (@L1711), reusing `_load_graph` (@L83), `_iter_functions` (@L436), `_production_source_files`.
- **Hotness predicate** (all mechanical proxies already present in the graph):
  ```
  hot(f) := f external/public
            AND ( #callers ≥ CALLER_THRESHOLD
                  OR writes ≥ 1 state var
                  OR carries an [ELEVATE] tag (attack_surface.md)
                  OR matches _LANG value-effect/mover regex )
            AND f is production (tests excluded)
  ```
- Cap `_MAX_HOT_FUNCTIONS = 40` (mirrors `_MAX_ENUMGAP_PER_RUN`), ranked by score desc → budget lands on the genuine core. **Driver-owned & deterministic → the LLM cannot clobber the target set** (the property that makes the gate load-bearing).
- Fallback: "all external state-mutating functions" if `function_summary.md` absent (degrade, never halt). ~55 lines.

#### 2.2.2 `scripts/enumeration_gate.py` — NEW `compute_axis_coverage_gaps(scratchpad) -> list[dict]`
- Builds the `function × axis` matrix over the hot set. The shipped implementation treats CLOSED structured depth-evidence as the primary signal and narrowly bounded Description/Impact cues as a secondary signal for tag-light findings:
  | Axis | Mechanical EXAMINED signal at f's locus |
  |------|-----------------------------------------|
  | theft | `[TRACE:…→transfer/mint/withdraw]` OR Postcondition Type `BALANCE`/`ACCESS` |
  | liveness/DoS | `[TRACE:…→revert]` OR `[BOUNDARY:…]` → revert/lock; Material-Harm names liveness |
  | accounting/arithmetic | `[VARIATION:…]` OR `[BOUNDARY:…]` on numeric param; `[REGRESS:…]` |
  | provenance/freshness | `[EXTERNAL-ASSUMPTION:…]` OR a trace anchored to a staleness/provenance cue; `[CROSS-DOMAIN-DEP: external]` is an admission, not EXAMINED |
  | zero/boundary | `[BOUNDARY:X=0/1/MAX]` |
  | identity | access postcondition or a caller/subject authority cue anchored to a trace |
- Secondary coverage is limited to the existing mechanical cue regexes in Description/Impact (plus stated BALANCE/ACCESS postcondition types); arbitrary prose does not attest coverage. No cue remains `GAP`.
- Enclosing-function mapping via `_fn_at_location` (@L137). Cell → `EXAMINED` / `N/A` (mechanically provable: pure view + no value-effect regex ⇒ theft `N/A`) / `GAP`. **Ambiguous ⇒ GAP not EXAMINED** (recall-safe default).
- Writes `hot_function_axes.md` + `_hot_function_axes.json`. Returns the `GAP` rows. ~90 lines.

#### 2.2.3 `scripts/enumeration_gate.py` — NEW `promote_axis_findings_to_inventory(scratchpad) -> dict`
- Clone of `promote_enumgap_exploration_to_inventory` (@L799). Appends each new axis-deriver finding as a fresh `INV-*` block, `Source IDs: AXISGAP`, `Verdict: NEEDS_VERIFICATION`, idempotent via receipt. Chain metadata via `_chain_metadata_lines` (a freshness gap is naturally `EXTERNAL`/`TIMING`-typed → STEP-0a-LC enabler). ~40 lines.

#### 2.2.4 `scripts/plamen_types.py` — NEW soft phase `axis_coverage`
- Registered in BOTH the SC phase list (near @L1259–1298) and, if applicable, L1 list (not applied to L1 in the shipped version — axis_coverage is SC-only). Placement: **after** the depth post-hook AND **after** `exploration_skeptic` (@L1259) / `enumgap_exploration` (@L1276) so their findings count as coverage, **before** `sc_semantic_dedup` (@L1295) / `chain` (@L1298).
  ```python
  Phase("axis_coverage", ["Phase 4b.8: Multi-Axis Coverage Meta-Pass"],
        ["axis_coverage_findings.md"],
        base_timeout_s=3600, modes={"thorough"}, critical=False, model="sonnet")
  ```
- `critical=False` → degrade-and-continue (never halts, matching every skeptic/enumgap phase). Thorough-only → Light/Core pay nothing.

#### 2.2.5 `scripts/plamen_driver.py` — phase dispatch + skip-when-clean
- **Add** an `axis_coverage` dispatch branch modeled on the `enumgap_exploration` branch (skip guard `_enumgap_exploration_has_no_obligations`, called at plamen_driver.py:18247; defined in scripts/plamen_parsers.py:2656). New helper `_axis_coverage_has_no_gaps(scratchpad)`: runs `compute_hot_function_set` + `compute_axis_coverage_gaps` mechanically FIRST, writes the matrix, and **only spawns the worker if `GAP` cells exist**; else stubs `axis_coverage_findings.md` and skips.
- **Add** post-hook call to `promote_axis_findings_to_inventory` after the phase completes (parallel to the enumgap promotion @L14167). ~50 lines across the two edits.

#### 2.2.6 `prompts/shared/v2/phase4b8-axis-coverage.md` — NEW deriver-worker prompt
- Clone of `phase4b7-enumgap-exploration.md`. One bounded executor (per CLAUDE.md worker contract: one role, one output file, `PLAMEN_STATUS: COMPLETE`). Handed ONLY `GAP` rows: "For function `f`, axis = `<A>` was never examined. Open `f` at `<loc>`, interrogate on THIS axis only; emit a standard-format finding (Material-Harm + Rules-Applied + closed depth-evidence tags) OR a reasoned `CLEAR` naming a concrete safety locus." **Strictly additive** (ADD/UPGRADE only). ~120 lines.

#### 2.2.7 `scripts/plamen_validators.py` — NEW `_validate_axis_coverage(scratchpad, mode) -> list[str]`
- Clone of `_validate_exploration_skeptic` (@L6671): warning-only, writes `.axis_gap` sentinel + warning; never halts. ~40 lines. (Shipped as `_validate_axis_coverage` @L6904.)

### 2.3 Shared / cross-cutting
- `scripts/plamen_types.py`: register the new phase name in any phase-name allowlist / ID-catalog used by validators (per MEMORY "ID regex must catalog all formats" — add `AXISGAP` and `INVARIANT`/`CI-` shapes to the internal-finding-ID recognizers so completeness gates don't silently zero them).
- No per-language duplication: both mechanisms reuse the `_LANG` registry, `_iter_functions`, `_fn_at_location`, `_chain_metadata_lines`, the ENUMGAP promotion pattern, and the soft-validator idiom. **No file approaches its Appendix-A cap** (enumeration_gate is the only substantially-grown module; the prompts are clones at ~120 lines each, well under 350).

---

## 3. I/O / artifact contracts + finding-schema compliance

### 3.1 New artifacts
| Artifact | Writer | Contents |
|----------|--------|----------|
| `hot_function_axes.md` + `_hot_function_axes.json` | driver (`compute_hot_function_set`+`compute_axis_coverage_gaps`) | one row per hot function × 6 axis cells (`EXAMINED`/`N/A`/`GAP`) |
| `axis_coverage_findings.md` | axis-deriver worker (or stub) | standard-format findings for GAP cells |
| `.ci_gap`, `.axis_gap` sentinels | soft validators | visibility markers, warning-only |

### 3.2 Committed-invariant `[CI-n]` block (M1 emitter output; deriver input)
```
committed-invariant [CI-3]
Locus: src/Pricing.sol:L142  (fn: getQuote)
Shape: FRESHNESS
Assertion: assert(block.timestamp - lastUpdate <= MAX_STALENESS) holds on every getQuote read path
Falsify Class: property   # property | boundary | roundtrip | conservation
Provenance: skeptic NO-GAP @ CI-source
```

### 3.3 The six generic invariant SHAPES (M1) — HOW, symbols resolved at locus, never protocol constants
`CONSERVATION` (Σin == Σout ± fee) · `REQUESTED_EQ_DELIVERED` · `APPROVE_EQ_SPEND` · `NO_REVERT_AT_BOUNDARY` (min/mid/max) · `ROUNDTRIP` (decode∘encode == id) · `FRESHNESS` (input age ≤ bound / source == expected).

### 3.4 Falsify Class → fuzzer ladder (degrade, never silent pass)
Inherits the pipeline's fuzzer ladder verbatim (Soroban: cargo-fuzz → proptest → boundary; EVM: forge invariant → boundary). `NO_REVERT_AT_BOUNDARY` degrades losslessly (already a min/mid/max parameterized assertion). Un-executable ⇒ `[CODE-TRACE]`/CONTESTED via PoC Testability Ledger.

### 3.5 Finding-schema compliance (both mechanisms)
Every emitted candidate/finding uses the standard format from `rules/finding-output-format.md`: `Verdict`, `Severity` (default Low at emission), `Location` (`file:Lnn`), `Description`, `Impact`, **`Material Harm` (MANDATORY — WHO loses WHAT)**, `Evidence`, `Rules Applied`, and only the **closed depth-evidence tags** (`[TRACE]`/`[BOUNDARY]`/`[VARIATION]`/`[EXTERNAL-ASSUMPTION]`/`[CROSS-DOMAIN-DEP]`/`[REGRESS]`) — invents no new tag vocabulary. Promotion stamps distinct `Source IDs` (`INVARIANT` for M1, `AXISGAP` for M2) so dedup and coverage accounting keep them traceable.

---

## 4. Sequencing + independent shippability

### 4.1 Run order within an audit
`inventory (M1 deriver fires in run_enumeration_gate) → invariants/invariant-fuzz (ingests M1) → depth → exploration_skeptic (4b.6, M1 emits CI blocks) → enumgap_exploration (4b.7) → axis_coverage (4b.8, M2; sees M1's fuzz + skeptic findings as coverage → shrinks worklist) → sc_semantic_dedup (4e) → chain (4c) → verify (5) → skeptic (5.1, M1 emits more CI) → report`.

### 4.2 Composition / no double-work (dedup boundary)
- **M2 vs depth**: M2 only targets `GAP` cells; EXAMINED pairs are skipped (coverage detected FROM depth's own tags). Zero re-analysis.
- **M2 vs 4b.6/4b.7**: ordered after both; their added findings flip `GAP→EXAMINED`, shrinking the worklist before any worker spawns. Orthogonal dimension (axis-completeness vs finding-neighbour-completeness) → no overlap.
- **M1 vs M2**: M1 emits `INVARIANT`-stamped invariant candidates (pre-depth, feeds fuzzer); M2 emits `AXISGAP`-stamped axis candidates (post-depth). If M1's accounting invariant and M2's accounting-axis finding collide on the same function, **`sc_semantic_dedup` (4e)** absorbs one via location+fix-pattern — no double-report. M2 runs after M1's fuzz findings land, so it never re-derives an invariant M1 already asserted.

### 4.3 Build sequencing (implement M1 first, then M2)
- **M1 is independently shippable** and lands first: it is prompt hooks + one deriver + one soft validator, entirely inside the already-invoked `run_enumeration_gate` — **no new phase, no dispatch surgery, no schedule change.** Ship M1, validate (§6), then start M2.
- **M2 depends only on the shared graph artifacts** (not on M1) but is sequenced second because it is the larger change (new phase decl + driver dispatch branch + worker prompt + promotion clone). M2's worklist-shrink benefit is *larger* once M1 exists (M1's fuzz findings pre-fill accounting-axis coverage), so M1-first is also the higher-yield order.

---

## 5. Test plan

### 5.1 Unit — M1 (new `scripts/test_invariant_assertion_deriver.py`)
- `compute_invariant_assertion_candidates`: fixture scratchpad with skeptic `NO-GAP` + `[CI-n]` blocks for each of the 6 shapes → asserts one candidate per block, correct Falsify Class, chain metadata present, `Source IDs: INVARIANT`.
- Budget isolation: 20 CI blocks → capped at `_MAX_PER_DERIVER` (15), co-ref pool untouched (regression-guards the @L917 starvation bug).
- Idempotency: re-run → no duplicate candidates (receipt honored).
- Degrade: missing graph / un-executable assertion → candidate still emitted, Falsify Class marked un-executable → caps at CODE-TRACE downstream.
- Soft validator `_validate_invariant_commitment`: NO-GAP without `[CI-n]` → warning + `.ci_gap` sentinel, `passed` stays True.

### 5.2 Unit — M2 (new `scripts/test_axis_coverage_gate.py`)
- `compute_hot_function_set`: graph fixture with mixed visibility/callers/writes/ELEVATE → asserts deterministic ranked hot set, cap at 40, tests excluded, `function_summary.md`-absent fallback.
- `compute_axis_coverage_gaps`: fixture findings carrying each depth-evidence tag at known loci → asserts correct `EXAMINED`/`N/A`/`GAP` per axis; **ambiguous cell ⇒ GAP** (recall-safe assertion); pure-view ⇒ theft `N/A`.
- `promote_axis_findings_to_inventory`: clone-parity with existing enumgap promotion test (`test_enumgap_exploration_routing.py`); `Source IDs: AXISGAP`, idempotent.
- Skip-when-clean: all cells EXAMINED/`N/A` → `_axis_coverage_has_no_gaps` True → stub written, no spawn (parallel to `test_enumgap_separator_glue`/enumgap skip tests).
- Soft validator `_validate_axis_coverage`: warning-only, `.axis_gap` sentinel.

### 5.3 Integration
- Extend `test_phase_graph.py` / `test_v1_v2_phase_wiring_drift.py`: assert `axis_coverage` is registered Thorough-only, `critical=False`, ordered after 4b.7 and before 4e/chain, with the correct expected artifact.
- Extend `test_enum_gate_derivers.py`: `run_enumeration_gate` now returns the M1 deriver's emitted count in its aggregate; independent-pool accounting holds.
- Extend `test_chain_baseline_regroup.py` / STEP-0a-LC coverage: `INVARIANT` and `AXISGAP` candidates appear as low-confidence enablers.
- Extend `test_sc_subsystem_coverage_typeonly.py` or add a dedup test: an M1-invariant and an M2-axis candidate on the same function+fix-pattern are merged by 4e (no double-report).
- `test_prompt_validator_alignment.py`: the two new/edited prompts pass the mechanical prompt-gate consistency checker (example_tokens = finding-ID shapes, not shard numbers).
- Full-suite gate: `pytest scripts/` must stay green (4282 passing).

---

## 6. Validation plan — rerun the EVM + Soroban benchmark targets, un-primed via `--fresh`

### 6.1 Setup (un-priming)
Both targets are now **un-primed** (the v2.2.1 overfit archive removed prior-audit finding descriptions + file:line, and same-contest judging RAG). Rerun with `--fresh` so `_ensure_fresh_audit_sentinel` (`plamen_driver.py` @L11055) + `_archive_prior_audit_artifacts` (@L15527) archive any prior scratchpad, guaranteeing a clean generation. Score the delivered `AUDIT_REPORT.md` against each target's **existing ground truth** (`scripts/bounty/_realdata/index.json` and the per-target GT), NOT against any same-contest judging repo (anti-overfit).

### 6.2 What to measure
- **Per-class recall on B1–B5**: for each GT finding tagged to one of the 5 classes, matched / missed.
- **Overall recall + precision**: matched÷GT and matched÷(pipeline body findings). Watch precision because both mechanisms ADD candidates.
- **Emission→refutation funnel**: how many `INVARIANT`/`AXISGAP` candidates were emitted, verified, refuted, and how many reached the client body — to confirm the verify-the-positives filter is doing its job.

### 6.3 Pass / regression bar
- **PASS**: recall on B1–B5 strictly ≥ the pre-change baseline on the SAME target, **AND** overall precision drops by **≤ 3 percentage points** (recall-safe: an extra refuted Low candidate is acceptable; a false client-body finding is not), **AND** at least ONE previously-missed GT finding in classes B1–B5 is newly recalled across the two targets combined.
- **REGRESSION (block ship)**: any pre-existing GT finding that was recalled at baseline is now missed, OR precision drops > 3 pp, OR a mechanism emits a client-body finding that is a false positive the verify gate should have refuted (indicates the generation/verification decouple leaked).
- **NO-CHANGE (investigate, don't ship)**: 0 new B1–B5 recalls on both targets → the mechanism is inert on these codebases; re-examine the hot-set threshold / CI-emission trigger before shipping (do not "tune to the target" — that is overfitting).
- Record the outcome as a one-line MEMORY.md entry: version, recall%, precision%, RC-distribution (never finding descriptions/IDs/file:line).

---

## 7. Anti-overfit self-audit (every element = HOW, no protocol signatures)

Applying the Part-0 gating test ("teaches a general method, or names a specific codebase's answer?") to every element:

| Element | HOW / WHAT | Verdict |
|---------|-----------|---------|
| 6 invariant shapes (M1) | generic relational forms, symbols resolved at locus at runtime | HOW ✓ |
| Falsify Class ladder | mechanism-agnostic fuzzer routing | HOW ✓ |
| 6 orthogonal axes (M2) | question-shapes ("can value leave to an unauthorized party?") | HOW ✓ |
| Hot-function predicate | derived from graph metrics (#callers/writes/ELEVATE/effect-regex), never a hardcoded fn list | HOW ✓ |
| Axis-EXAMINED detection | structured evidence primary; bounded generic Description/Impact cues secondary; ambiguity remains GAP | HOW ✓ |
| CI/AXIS candidates | emitted at runtime from live graph/verdicts; nothing stored | HOW ✓ |
- **No stored findings**: neither mechanism persists a bug description, finding ID, or file:line. Memory records only recall%/precision%/RC-counts.
- **No same-contest priming**: validation scores against the target's own GT + `_realdata`, never a `*-judging` repo; RAG (if it fires) uses generic vuln-class queries only.
- **Step-2.5 methodology-gap statement (stateable without naming any finding)**: M1 — "no rule tells the agent to convert a SAFE/REFUTE verdict's tacit local guard into an executable falsifiable assertion." M2 — "no rule enforces that every mechanically-hot function is interrogated on all orthogonal risk axes, not just the one axis its owning domain lens happened to use." Both hold without a finding referent.
- **Anti-bloat**: one shared driver module + two clone prompts + one phase decl; reuses `_LANG`, `_iter_functions`, `_fn_at_location`, `_chain_metadata_lines`, promotion + soft-validator idioms. No 4–9× per-tree duplication; no file near its cap.

---

## 8. Risks + rollback

| # | Risk | Mitigation | Rollback |
|---|------|-----------|----------|
| R1 | Deriver budget starvation (co-ref pool eats M1's slots) | M1 gets its OWN `_MAX_PER_DERIVER` pool, independent of `_MAX_ENUMGAP_PER_RUN` (per @L917) | remove deriver from `run_enumeration_gate` tuple → no-op |
| R2 | Precision drop from over-emission | candidates are Low/`NEEDS_VERIFICATION`; verify + skeptic-judge + Material-Harm floor gate them; ≤3pp bar (§6.3) | lower `_MAX_PER_DERIVER`/`_MAX_HOT_FUNCTIONS`; both are one-constant edits |
| R3 | Un-executable dodge (agent claims safe without falsifying) | PoC Testability Ledger caps un-executable at CODE-TRACE/CONTESTED; soft validators sentinel it | validators are warning-only; no halt risk |
| R4 | Heuristic symbol/locus drift in `_fn_at_location` | graph-provenance fallback: unresolved locus ⇒ candidate emitted at file-scope, still verifiable | mechanical, self-contained |
| R5 | **N/A miscalibration (M2)** — falsely EXAMINED hides a true gap (recall loss = the unacceptable error) | `N/A` requires mechanical justification; **ambiguous ⇒ GAP not EXAMINED** | conservative default is already the safe error |
| R6 | Soft phase halts the pipeline | `critical=False` + skip-when-clean stub, matching every skeptic/enumgap phase | remove `axis_coverage` from phase list → pipeline reverts exactly |
| R7 | New IDs silently zeroed by completeness gates | catalog `INVARIANT`/`CI-`/`AXISGAP` in internal-ID recognizers with a fixture test (per MEMORY ID-regex rule) | fixture test blocks ship if uncatalogued |

**Global rollback**: M1 is removable by deleting its deriver from the `run_enumeration_gate` tuple + reverting the prompt hooks (pure additions). M2 is removable by deleting the `axis_coverage` Phase decl + its driver dispatch branch (the phase then simply never runs). Neither removal touches any existing consumer — both are strictly-additive seams on the deriver/soft-phase framework.
