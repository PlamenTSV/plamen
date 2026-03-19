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
                   niche_*_findings.md, design_stress_findings.md]:
  Extract ONLY the '## Chain Summary' table section
  Append to {SCRATCHPAD}/chain_summaries_compact.md with a header per source file
```

This produces ~200-400 lines instead of 5000+.

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

For specific findings referenced in enabler enumeration, read the relevant source files directly.

## PHASE 0: ENABLER ENUMERATION (Rule 12)

Before grouping, exhaustively enumerate all paths to each dangerous precondition state.

### STEP 0a: Extract Dangerous States

From all CONFIRMED, PARTIAL, and CONTESTED findings, extract each dangerous precondition state:

| Finding ID | Dangerous State S | Current Known Path(s) to S | Actor Category of Known Path |

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
7. **Severity inheritance**: When grouping findings of different severities, the hypothesis inherits the HIGHEST severity from its constituent findings.

**Confidence-aware grouping**: Group LOW_CONFIDENCE findings with CONFIDENT findings of the same root cause where possible. Flag CONTESTED findings for verification priority.

## Output

Write:
- {SCRATCHPAD}/hypotheses.md - hypothesis table (grouped findings)
- {SCRATCHPAD}/finding_mapping.md - finding → hypothesis mapping
- {SCRATCHPAD}/enabler_results.md - enabler enumeration results (dangerous states, 5-actor tables, cross-state interactions)

Return: 'DONE: {N} hypotheses, {E} enabler paths enumerated'
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
- {SCRATCHPAD}/variable_finding_map.md (variable→finding cross-reference for variable-level matching - if missing, fall back to grep-based variable name matching in findings_inventory.md)
- {SCRATCHPAD}/findings_inventory.md (for full finding details when needed)

For specific chain candidates, read the relevant source files directly.

## PHASE 2: CHAIN ANALYSIS - Match Postconditions to Preconditions

For each PARTIAL or REFUTED finding:
1. Extract its missing precondition and type (STATE/ACCESS/TIMING/EXTERNAL/BALANCE)
2. **For STATE-type preconditions**: extract the specific state variable name(s). Use variable_finding_map.md to find ALL findings that write to the SAME variable - match on variable names, not just descriptions.
3. Search ALL CONFIRMED/PARTIAL findings for matching postconditions - across ALL severity tiers and vulnerability classes
4. If found: Create CHAIN HYPOTHESIS with combined attack sequence

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

### Composition Coverage Map

After chain matching, write a coverage map of finding pairs you considered:

| Finding A | Finding B | Explored? | Result | Notes |
|-----------|-----------|-----------|--------|-------|

Rules: List pairs where at least one has a postcondition or missing precondition. Cross-class pairs (state + token, access + external) are HIGH PRIORITY.

## PHASE 3: RAG VALIDATION FOR CHAINS

For each chain hypothesis:
1. assess_hypothesis_strength(hypothesis='Chain: {B title} enables {A title}')
2. get_similar_findings(pattern='{combined attack description}')
3. If local results < 5: search_solodit_live(keywords='{chain pattern}', impact=['HIGH','MEDIUM'], quality_score=3, max_results=20)
4. If historical precedent found → upgrade chain severity

## Output

Update {SCRATCHPAD}/hypotheses.md - add chain hypotheses to the hypothesis table
Write:
- {SCRATCHPAD}/synthesis_full.md - full analysis (enabler + grouping + chain results)
- {SCRATCHPAD}/chain_hypotheses.md - chain summary with:
  1. Chain summary table: Chain ID | Finding A | Missing Precondition | Finding B | Postcondition Match | Chain Severity
  2. Detailed chain hypotheses
  3. Findings status update (which findings upgraded)
  4. Verification priority order
- {SCRATCHPAD}/composition_coverage.md - composition coverage map

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

The first chain analysis identified {M} chains. {U} cross-class finding pairs were NOT explored.
Analyze ONLY these unexplored pairs for compound attack paths.

## Your Inputs
- {SCRATCHPAD}/composition_coverage.md (focus on NOT EXPLORED rows)
- {SCRATCHPAD}/chain_hypotheses.md (do NOT duplicate existing chains)
- {SCRATCHPAD}/findings_inventory.md (full finding details)

## Unexplored Pairs
{PASTE UNEXPLORED CROSS-CLASS PAIRS - max 15}

## Your Task
For EACH pair:
1. Read both findings' full details
2. Check: does A's postcondition enable B's precondition? And vice versa?
3. If YES: create CHAIN HYPOTHESIS (use Chain Hypothesis Format from chain_hypotheses.md)
4. Validate via RAG

## Output
Write to {SCRATCHPAD}/chain_iteration2.md
Append new chains to {SCRATCHPAD}/chain_hypotheses.md
Update {SCRATCHPAD}/composition_coverage.md

Return: 'DONE: {N} new chains from {U} unexplored pairs'
")
```

| Condition | Effect |
|-----------|--------|
| 0 unexplored cross-class Medium+ pairs | Skip iteration 2 |
| Hard cap | 2 iterations maximum |

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
3. Validate the chain with RAG: search_solodit_live(keywords='<chain pattern>')
4. Compute impact with REAL constants for the COMBINED attack
5. Apply Rule 10: Use worst realistic operational parameters for severity

Write to {SCRATCHPAD}/depth_iterative_{type}_findings.md

Return: 'DONE: {N} chain-enabled findings analyzed'
")
```

If iterative depth reveals NEW chains, feed back to chain analysis agent for a final update to `chain_hypotheses.md`.
