# Phase 4c: Chain Analysis - Split Agent Architecture

> **Usage**: Orchestrator reads this file and spawns 2 sequential chain agents.
> Replace placeholders `{SCRATCHPAD}`, `{list...}`, etc. with actual values.
> Split into Agent 1 (enabler + grouping) and Agent 2 (chain matching + composition coverage).
> Each agent stays under security-analyzer context limits.

---

## Pre-Step: Chain Summary Extraction (Orchestrator Inline)

Before spawning agents, the orchestrator extracts Chain Summary sections into a compact file.
This prevents agents from reading 5000+ lines of full depth/scanner output.

```
For each file in [depth_*_findings.md, blind_spot_*_findings.md, validation_sweep_findings.md,
                   niche_*_findings.md, design_stress_findings.md, sibling_propagation_findings.md]:
  Extract ONLY the '## Chain Summary' table section
  Append to {SCRATCHPAD}/chain_summaries_compact.md with a header per source file
```

This produces ~200-400 lines instead of 5000+.

`chain_summaries_compact.md` is orchestrator-owned. Chain agents must read it,
not generate it. If it is missing, that is a pre-step failure by the
orchestrator, not a task for Chain Agent 1 or 2.

**Artifact discipline**: `chain_summaries_compact.md`, `enabler_results.md`,
and `composition_coverage.md` are REQUIRED standalone artifacts. If you
also include their contents inline elsewhere, still write the dedicated files.

---

## Agent 1: Enabler Enumeration + Grouping (security-analyzer)

```
Task(subagent_type="security-analyzer", prompt="
You are Chain Agent 1: Enabler Enumeration and Grouping.

## Your Inputs
Read:
- {SCRATCHPAD}/findings_inventory.md (breadth summary + Chain Summary table)
- {SCRATCHPAD}/chain_summaries_compact.md (extracted chain summaries from depth/scanner agents)
- {SCRATCHPAD}/confidence_scores.md (for prioritization)
- {SCRATCHPAD}/attack_surface.md (for enabler enumeration)
- {SCRATCHPAD}/depth_*_findings.md (for STEP 0-pre: scan for [CROSS-DOMAIN-DEP] tags)
- {SCRATCHPAD}/chain_enabler_baseline.md (driver-owned, read-only STEP 0a baseline)

For specific findings referenced in enabler enumeration, read the relevant source files directly.

## Mandatory First Action

Before semantic grouping, physically create all three handoff files on disk:

- `{SCRATCHPAD}/hypotheses.md`
- `{SCRATCHPAD}/finding_mapping.md`
- `{SCRATCHPAD}/enabler_results.md`

A `**Status**: MECHANICAL_BASELINE` stamp in `hypotheses.md` /
`finding_mapping.md` / `enabler_results.md` is a driver-written scaffold and is
NOT prior completion. You MUST perform PHASE 1 grouping and PHASE 0 enabler
enumeration and OVERWRITE all three files, removing the `MECHANICAL_BASELINE`
stamp. Returning `DONE` while any of these files still carries the
`MECHANICAL_BASELINE` stamp is a phase failure that the driver will detect and
retry. Do not merely return a summary saying the files were written. Only
return `DONE` after all three files exist on disk, carry no `MECHANICAL_BASELINE`
stamp, and contain the final grouped/enumerated content for this phase.

## PHASE 0: ENABLER ENUMERATION (Rule 12)

Before grouping, exhaustively enumerate all paths to each dangerous precondition state.

### STEP 0-pre: Cross-Domain Dependency Scan

Search ALL depth agent output files (`depth_*_findings.md`) for `[CROSS-DOMAIN-DEP: {domain}]` tags. These are assumptions a depth agent identified as outside its own domain — potential compound exploit paths invisible to single-domain analysis. For each tag found:
1. Check if ANY finding in the referenced domain addresses that assumption
2. If NO finding covers it → add to the enabler enumeration as a candidate dangerous state
3. If a finding DOES cover it → check whether the finding's postcondition could break the tagged assumption

### STEP 0a: Extract Dangerous States

From all CONFIRMED, PARTIAL, and CONTESTED findings, extract each dangerous precondition state:

| Finding ID | Dangerous State S | Current Known Path(s) to S | Actor Category of Known Path |

**Low-confidence candidate enablers (ENABLER-ONLY relaxation).** A finding may serve as a candidate ENABLER (a postcondition provider) or a blocked-finding even when its verdict is UNVERIFIED / NEEDS_VERIFICATION / LOW_CONFIDENCE — not only CONFIRMED/PARTIAL/CONTESTED. This is exactly the class of "individually-invalid observation that enables another finding" that chain analysis exists to catch, and chain runs BEFORE verify. The driver pre-fills these in the read-only `chain_enabler_baseline.md` under `## STEP 0a-LC: Low-Confidence Potential Enablers (unverified — ENUMGAP/derivers)`, carrying each candidate's `Postconditions Created` / `Missing Precondition` type tags. Copy and build on that denominator in the final `enabler_results.md`. Treat STEP 0a-LC rows as candidate enablers ONLY: do NOT add them to the dangerous-state baseline above, and do NOT report them as standalone findings. Any chain you build on a STEP 0a-LC enabler is LOW-CONFIDENCE until its constituents verify — and like every chain hypothesis it is sent to verification (see PHASE 3 / verification handoff), which refutes spurious enabler chains. So include them as enabler candidates freely; precision is preserved downstream by the verify-the-positives filter.

### STEP 0b: Enumerate Missing Paths (Rule 12)

For EACH dangerous state S, fill the 5-actor-category table:

| # | Actor Category | Path to State S? | Reachable? | Existing Finding? | If Missing: New Finding |
|---|----------------|-------------------|------------|-------------------|------------------------|
| 1 | External attacker (permissionless) | {path or 'No path'} | YES/NO | {ID or NONE} | {[EN-N] or N/A} |
| 2 | Semi-trusted role (within permissions) | {path or 'No path'} | YES/NO | {ID or NONE} | {[EN-N] or N/A} |
| 3 | Natural operation (normal protocol flow) | {path or 'No path'} | YES/NO | {ID or NONE} | {[EN-N] or N/A} |
| 4 | External event (slash, pause, governance) | {path or 'No path'} | YES/NO | {ID or NONE} | {[EN-N] or N/A} |
| 5 | User action sequence (normal usage) | {path or 'No path'} | YES/NO | {ID or NONE} | {[EN-N] or N/A} |

**Rules**:
- 'No path' requires a brief explanation of WHY this actor category cannot reach state S
- If reachable but no existing finding → create [EN-N] finding
- New findings inherit the IMPACT severity of the original finding
- New findings may have DIFFERENT likelihood

### STEP 0c: Cross-State Interactions

Check if reaching state S1 (from Finding A) also reaches state S2 (from Finding B):
- If YES → document the combined attack path

## PHASE 1: GROUPING AND DEDUP

### Grouping Steps

1. MERGE depth findings, enabler findings ([EN-N]), and breadth findings
2. CROSS-CORRELATE findings across agents - deduplicate same root cause
3. GROUP by root cause into hypotheses
4. RECOVER dismissed findings if contradicted by depth agents
5. ANALYZE compound exploits
6. VERIFY coverage - every finding has a status

### GROUPING RULES (MANDATORY)
1. **Max 5 findings per hypothesis**. If grouping would exceed 5, split by exploit path.
2. **No catch-all hypotheses**. Every finding must map to a hypothesis with a specific root cause. 'Miscellaneous' groupings are PROHIBITED.
3. **Group by exploit path, not component**. Two findings affecting the same component but using different exploit mechanisms → separate hypotheses.
4. **Orphan findings** each become their own single-finding hypothesis.
5. **LOW_CONFIDENCE orphans**: each becomes a standalone hypothesis at its original severity.
6. **Anti-absorption**: Before grouping two findings, apply this check:
   (a) Same fix required for both (if fixes differ → separate hypotheses)
   (b) Grouping does not obscure a severity difference > 1 tier
   (c) Reader can understand BOTH attack paths from a single description
   (d) **Fix comparison test**: Write a 1-line fix for each. If fixes modify DIFFERENT functions → separate hypotheses.
   (e) A group is an additive composition proposal, not identity authority.
       Preserve every exact constituent as an independently addressable claim
       and verification obligation. Locus/title/Jaccard/severity and an
       `Anti-absorption override` are proposal signals only. Only a separately
       applied typed decision proving the same mechanism, preconditions,
       effect, impact, and remediation scope may share one verification work
       identity; the chain worker cannot authorize its own exception.
7. **Severity inheritance**: When grouping findings of different severities, the hypothesis inherits the HIGHEST severity from its constituent findings.

**Confidence-aware grouping**: Group LOW_CONFIDENCE findings with CONFIDENT findings of the same root cause where possible. Flag CONTESTED findings for verification priority.

## Output

Write:
- {SCRATCHPAD}/hypotheses.md - hypothesis table (grouped findings)
- {SCRATCHPAD}/finding_mapping.md - finding → hypothesis mapping
- {SCRATCHPAD}/enabler_results.md - enabler enumeration results (dangerous states, 5-actor tables, cross-state interactions)

Do NOT fold `enabler_results.md` into `hypotheses.md` as the only copy. Both
files must exist separately.

Return: 'DONE: {N} hypotheses, {E} enabler paths enumerated'

Only return `DONE` after `hypotheses.md`, `finding_mapping.md`, and
`enabler_results.md` exist on disk.
")
```

---

## Agent 2: Chain Matching + Composition Coverage (security-analyzer)

> **Spawned AFTER Agent 1 completes.** Reads Agent 1's output.

```
Task(subagent_type="security-analyzer", prompt="
You are Chain Agent 2: Chain Matching and Composition Coverage.

## Your Inputs
Read:
- {SCRATCHPAD}/hypotheses.md (grouped hypotheses from Agent 1)
- {SCRATCHPAD}/finding_mapping.md (finding → hypothesis mapping from Agent 1)
- {SCRATCHPAD}/enabler_results.md (enabler enumeration + cross-state interactions from Agent 1)
- {SCRATCHPAD}/variable_finding_map.md (qualified state-symbol→finding cross-reference from the driver-owned graph resolver; if missing, grep is only a degraded recall fallback and cannot establish enumeration completeness)
- {SCRATCHPAD}/chain_candidate_pairs.md (pre-filtered pairs with shared state/type — if present, evaluate ONLY these pairs)
- {SCRATCHPAD}/findings_inventory.md (for full finding details when needed)

For specific chain candidates, read the relevant source files directly.

## PHASE 2: CHAIN ANALYSIS - Match Postconditions to Preconditions

### Step 2.0: Load Pre-Filtered Pairs (if available)

Read {SCRATCHPAD}/chain_candidate_pairs.md. If present:
- Evaluate ONLY the pairs listed in the STATE Pairs and TYPE Pairs tables
- For each pair: read both findings' full details, verify the mechanical match is semantically valid
- A `role: mutual-zero` row is nomination-only: confirm an authentication
  anchor is operational while zero/unarmed AND a degenerate input derives to
  zero/null and is accepted. Reject atomic/inert-until-armed initialization or
  fail-closed zero rejection; compose only when the conjunction reaches a
  privileged or otherwise harmful effect not established by either half alone.
- Create CHAIN HYPOTHESIS for valid matches
- Mark each evaluated pair as EXPLORED in composition_coverage.md
- Do not disposition out-of-packet pairs from the bounded file. The driver
  reconciles the complete set: real-signal tail rows route through
  `chain_candidate_pairs_iter2.md`, and any unconsumed remainder stays in
  `chain_composition_coverage_gaps.md`, never silently called excluded.

If chain_candidate_pairs.md is MISSING, fall back to the original algorithm below.

### Step 2.1: Original Algorithm (fallback if no pre-filter)

For each PARTIAL or REFUTED finding:
1. Extract its missing precondition and type (STATE/ACCESS/TIMING/EXTERNAL/BALANCE)
2. **For STATE-type preconditions**: extract the specific qualified state symbol(s). Use variable_finding_map.md to find ALL findings mechanically bound to the SAME symbol (declaration/read/write/reference). Do not merge same-bare fields from different contracts/modules and do not infer extra pairs outside the driver-owned bounded ledgers.
3. Search ALL CONFIRMED/PARTIAL findings for matching postconditions - across ALL severity tiers and vulnerability classes. **Also search the low-confidence candidate enablers** (UNVERIFIED / NEEDS_VERIFICATION / LOW_CONFIDENCE findings, including the driver's `## STEP 0a-LC` rows in `enabler_results.md` — ENUMGAP/deriver candidates carry `Postconditions Created` + type tags for exactly this match). A blocked finding may ALSO be one of these unverified candidates.
4. If found: Create CHAIN HYPOTHESIS with combined attack sequence. **If either constituent is an unverified candidate enabler, mark the chain LOW-CONFIDENCE** (Match Strength WEAK unless the postcondition→precondition match is exact) — it remains a hypothesis sent to verification, which confirms or refutes it. Never report such a chain as confirmed without verification.

### Chain Hypothesis Format

## Chain Hypothesis CH-{N}
### Blocked Finding (A)
- **ID**: [XX-N], **Title**: [Attack that was blocked]
- **Original Verdict**: REFUTED/PARTIAL, **Missing Precondition**: [What was missing], **Type**: [TYPE]
### Enabler Finding (B)
- **ID**: [YY-M], **Title**: [Finding that creates the precondition]
- **Original Verdict**: CONFIRMED/PARTIAL, **Postcondition Created**: [What it creates], **Type**: [TYPE]
### Chain Match
- **Match Strength**: STRONG / MODERATE / WEAK
- **Match Reasoning**: B creates the exact precondition A needs
### Combined Attack Sequence
1. [Step from B]: Execute enabler action
2. [Step from A]: Execute previously-blocked attack
3. [Impact]: Combined effect
### Severity Reassessment
Chain Severity Matrix:
| Original A | Original B | Chain Severity |
|------------|------------|----------------|
| REFUTED | Any | Re-evaluate A with B's postcondition |
| LOW | LOW | MEDIUM |
| LOW | MEDIUM+ | HIGH |
| MEDIUM | MEDIUM | HIGH |
| MEDIUM | HIGH | HIGH |
| HIGH | Any | HIGH or CRITICAL |
| CRITICAL | Any | CRITICAL |
Chain severity is NEVER lower than the higher of Finding A or Finding B.
Upgrade if: combined impact > $100k AND profitability > 2x → CRITICAL
Upgrade if: combined impact > $10k AND profitability > 2x → minimum HIGH

### Chain Self-Containment Guard (MANDATORY — anti-restatement)

A chain hypothesis is **INVALID** if it is merely a restatement of a single
constituent. Before emitting ANY chain hypothesis, apply this guard:

1. **Single-actor satisfiability**: If the Combined Attack Sequence is
   satisfiable by a single constituent finding acting ALONE (i.e. Finding B's
   step is not actually required to reach Finding A's impact, or vice versa),
   the candidate is NOT a new finding.
2. **Same-root-cause restatement**: If Finding A and Finding B resolve to the
   SAME root cause / SAME fix / overlapping location (same file and function),
   the "chain" is two descriptions of one bug, not a composition.

For an INVALID candidate: do **NOT** emit a chain hypothesis. Instead record it
in `composition_coverage.md` with `Result=SELF-CONTAINED` and leave the
constituent(s) at their original severity.

A chain may be reported at a tier **ABOVE** the highest constituent **only**
when you state an explicit **Combined-Impact Justification**: a concrete
loss / privilege / liveness consequence that NEITHER constituent produces
alone, quantified per Rule 10. Absent that justification, the chain INHERITS
the highest constituent severity and is MERGED into that constituent — emit no
separate hypothesis.

**Machine-parseable chain line (REQUIRED for every chain you DO emit)**: add
exactly one line in that chain's section of `chain_hypotheses.md`, in this
form:

    Constituents: <A-id>,<B-id> | Severity-Upgrade-Justified: YES/NO | Combined-Impact: <one line or NONE>

`Severity-Upgrade-Justified: YES` is permitted ONLY when `Combined-Impact` is a
non-empty concrete consequence absent from both constituents. Otherwise use
`Severity-Upgrade-Justified: NO` and `Combined-Impact: NONE`.

### Composition Coverage Map

After chain matching, write a coverage map of finding pairs you considered:

| Finding A | Finding B | Explored? | Result | Notes |
|-----------|-----------|-----------|--------|-------|

Rules: List pairs where at least one has a postcondition or missing precondition. Cross-class pairs (state + token, access + external) are HIGH PRIORITY.

## PHASE 3: ADDITIVE PRECEDENT TEST IDEAS (AFTER CODE PLAN)

First finish and record every code-derived chain hypothesis, negative/unknown
pair disposition, combined-impact claim, and verification plan from Phases 1-2.
Only after that plan is sealed may you read the centralized, driver-derived
`{SCRATCHPAD}/precedent_context.md`. Do not run fresh RAG/database/web searches
inside this discriminator.

Use supporting/context rows only to append extra positive chain paths or test
ideas under a separate `Precedent-suggested additions` subsection. They cannot
erase a pair, support a negative disposition, change confidence/verdict/severity,
or replace code-derived evidence. Refuting precedent is deliberately withheld
from this projection because the pipeline's measured failure mode is mistaken
safe demotion. An empty or unavailable projection changes nothing.

## Output

Do not update {SCRATCHPAD}/hypotheses.md. It is an immutable Agent-1 output;
downstream consumers read the dedicated chain delta directly.
Write:
- {SCRATCHPAD}/synthesis_full.md - full analysis (enabler + grouping + chain results)
- {SCRATCHPAD}/chain_hypotheses.md - chain summary with:
  1. Chain summary table: Chain ID | Finding A | Missing Precondition | Finding B | Postcondition Match | Chain Severity
  2. Detailed chain hypotheses
  3. Findings status update (which findings upgraded)
  4. Verification priority order
- {SCRATCHPAD}/composition_coverage.md - composition coverage map

Do NOT rely on `chain_hypotheses.md` to implicitly serve as composition
coverage. `composition_coverage.md` must be written as its own file.

Return: 'DONE: {M} chains identified, {K} severity upgrades, {U} unexplored pairs remaining, verification priority: [list]'
")
```

---

## Iterative Chain Composition (Orchestrator Logic)

After Agent 2 completes, the orchestrator checks for unexplored cross-class pairs:

```
ITERATIVE_CHAIN_COMPOSITION(SCRATCHPAD):
  // Agent 1 + Agent 2 run sequentially (above)

  // ═══ EARLY EXIT CHECK ═══
  // If Agent 2 reported 0 new chains AND 0 unexplored cross-class Medium+ pairs → skip iteration 2
  // Read Agent 2's return message for chain count and unexplored pair count
  // This prevents spawning a redundant iteration 2 agent when composition is already complete

  // Read composition coverage map
  coverage = read(SCRATCHPAD + "/composition_coverage.md")
  unexplored = [pair for pair in coverage if pair.explored == NO]

  cross_class_unexplored = [p for p in unexplored
                            if p.finding_a.class != p.finding_b.class
                            and max(p.finding_a.severity, p.finding_b.severity) >= MEDIUM]
  if len(cross_class_unexplored) == 0:
    goto DONE

  // Spawn targeted iteration 2 agent for unexplored pairs only
  spawn chain_iteration2_agent(SCRATCHPAD, cross_class_unexplored)
  await chain_iteration2_agent

  DONE:
    // Proceed to Phase 5 verification
```

### Iteration 2 Chain Agent Template

```
Task(subagent_type="security-analyzer", prompt="
You are the Chain Composition Agent - ITERATION 2 (targeted cross-class pass).

The first chain analysis identified {M} chains. Analyze every pair in the
bounded iteration-2 tail packet for compound attack paths.

## Your Inputs
- {SCRATCHPAD}/chain_candidate_pairs_iter2.md (authoritative bounded shard from the exact typed tail manifest)
- {SCRATCHPAD}/composition_coverage.md (focus on NOT EXPLORED rows)
- {SCRATCHPAD}/chain_hypotheses.md (do NOT duplicate existing chains)
- {SCRATCHPAD}/findings_inventory.md (full finding details)

## Unexplored Pairs
{CURRENT MANIFEST-BOUND SHARD - normally max 15}

## Your Task
For EACH pair:
1. Read both findings' full details
2. Check: does A's postcondition enable B's precondition? And vice versa?
3. If YES: create CHAIN HYPOTHESIS (use Chain Hypothesis Format from chain_hypotheses.md)
4. After sealing all code-derived dispositions, optionally read the centralized
   `precedent_context.md` for additive positive paths/test ideas only. Do not
   run fresh RAG and never change confidence, verdict, severity, proof status,
   negative dispositions, or remaining investigation depth from precedent.

## Output
Write to {SCRATCHPAD}/chain_iteration2.md
Write every new chain and every coverage disposition into
{SCRATCHPAD}/chain_iteration2.md only. Treat chain_hypotheses.md and
composition_coverage.md as immutable inputs; the driver applies a digest-bound
merge after the delta passes its gates.
In chain_iteration2.md, write `## Tail Pair Dispositions` with exact columns
`Pair ID | Finding A | Finding B | Disposition | Evidence`, one row per shard
pair. Copy Pair ID exactly. A COMPOSED row cites its new CH-N identity and
routes to ordinary independent verification; it is not self-certified.

Return: 'DONE: {N} new chains from {U} unexplored pairs'
")
```

| Condition | Effect |
|-----------|--------|
| Exact typed tail denominator is 0 | Clean no-op; skip worker launch |
| More rows remain after one shard | Driver advances the hash-bound cursor and launches the next bounded shard |
| Declared time/shard budget stops continuation | Preserve exact unresolved-composition debt and a report-visible assurance limitation; never call clean |

---

### Chain-Specific PoC Requirements

Chain hypotheses receive PRIORITY in verification:

```solidity
function test_CH1_full_chain() public {
    // === STEP 1: Enabler (Finding B) - create the postcondition ===
    // === VERIFY POSTCONDITION - assert precondition for Finding A is now met ===
    // === STEP 2: Blocked Finding (Finding A) - execute previously-blocked attack ===
    // === VERIFY CHAIN IMPACT - assert combined impact > either alone ===
}
```

---

## Iterative Depth Pass

> The separate Phase 4d iterative depth pass is handled by the Adaptive Depth Loop in Phase 4b (iterations 2-3).
> However, if chain analysis discovers NEW chains that upgrade severity AND the upgraded findings were not covered by the adaptive loop, the orchestrator MAY spawn one additional targeted depth pass:

**Trigger**: Chain analyzer returned K > 0 severity upgrades where the upgraded finding was previously CONFIDENT (≥ 0.7) and thus was NOT re-analyzed in iterations 2-3.

```
Task(subagent_type="depth-{relevant-type}", prompt="
## Iterative Depth Pass (Post-Chain)

Chain analysis upgraded these findings:
{list of upgraded findings from chain_hypotheses.md}

For EACH upgraded finding:
1. Re-analyze with the CHAIN CONTEXT (the enabler finding is now known)
2. Trace the COMPLETE attack sequence (enabler → blocked finding → impact)
3. After sealing the code-derived chain trace, use centralized
   `precedent_context.md` only for additional positive test ideas; do not run
   fresh RAG and do not use precedent to reject or demote the chain
4. Compute impact with REAL constants for the COMBINED attack
5. Apply Rule 10: Use worst realistic operational parameters for severity

Write to {SCRATCHPAD}/depth_iterative_{type}_findings.md

Return: 'DONE: {N} chain-enabled findings analyzed'
")
```

If iterative depth reveals NEW chains, feed back to chain analysis agent for a final update to `chain_hypotheses.md`.
