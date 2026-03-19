# Phase 4b: Adaptive Depth Loop - Solana

> **Usage**: Orchestrator reads this file and runs the Adaptive Depth Loop for Solana audits.
> Iteration 1 spawns ALL 8 agents (4 depth + 3 blind spot + 1 validation sweep) + niche agents. Iterations 2-3 are targeted and autonomous.
> Replace placeholders `{SCRATCHPAD}`, `{TYPE}`, etc. with actual values.

---

## Orchestrator: Autonomous Adaptive Depth Loop

> **Coverage-first design**: Iteration 1 ALWAYS spawns all 8 agents.
> Iterations 2-3 are targeted, autonomous, and anti-dilution protected.
> **The orchestrator runs the ENTIRE loop without user intervention.**
> Timeout-aware split-and-retry, severity-weighted budget, dynamic cap, loop dynamics detection, post-verification error trace feedback.
> **Reference**: `~/.claude/rules/phase4-confidence-scoring.md` for scoring model and anti-dilution rules.

## Depth Agent Domain Mapping - Solana

| Agent | Solana Focus |
|-------|-------------|
| depth-token-flow | Vault token account balance, unsolicited SPL/SOL transfers, Token-2022 extensions |
| depth-state-trace | Cross-account state, PDA invariants, CPI state mutations, instruction ordering |
| depth-edge-case | Zero-state, account initialization ordering, CU boundary testing, rent-exempt thresholds |
| depth-external | CPI side effects, program upgrade risk, instruction introspection, external program behavior |

### Loop Pseudocode (Orchestrator Executes This)

```
ADAPTIVE_DEPTH_LOOP(findings_inventory):
  max_iterations = 3
  total_findings = len(findings_inventory)
  breadth_savings = max(0, 4 - actual_breadth_agent_count)  // breadth-to-depth redirect
  depth_floor = 12 + breadth_savings  // Simple codebases (2 breadth) get floor=14
  max_depth_spawns = min(max(depth_floor, ceil(total_findings / 5) + 7), 20)
  dst_reserved = 1  // Design Stress Testing always gets 1 slot
  depth_available = max_depth_spawns - dst_reserved  // depth agents share the rest
  max_findings_per_agent = 5  // anti-dilution rule AD-3
  depth_spawns_used = 0

  // ═══ PHASE 4a.5: Semantic Invariant Pre-Computation ═══
  // Sonnet agent enumerates write sites, semantic invariants, conditional/sync/accumulation annotations
  // Produces {SCRATCHPAD}/semantic_invariants.md - consumed by depth-state-trace and Validation Sweep
  // See CLAUDE.md Phase 4a.5 for full prompt template
  spawn semantic_invariant_agent(model="sonnet", SCRATCHPAD, state_variables, function_list, source_files)
  await semantic_invariant_agent  // MUST complete before depth agents spawn (they consume its output)

  // ═══ INVARIANT FUZZ CAMPAIGN (Solana/Trident) ═══
  // Read template: ~/.claude/prompts/solana/phase4b-invariant-fuzz.md
  // Trigger: semantic_invariants.md exists AND trident_available == true in build_status.md
  // If trident_available == false → skip (proptest fallback handled in Phase 5)
  if trident_available AND file_exists(SCRATCHPAD + "/semantic_invariants.md"):
    spawn invariant_fuzz_agent(model="sonnet", SCRATCHPAD, PROJECT_ROOT)
    await invariant_fuzz_agent  // 5-min timeout built into template

  // ═══ ITERATION 1: Full coverage (ALWAYS) ═══
  // Read template_recommendations.md for REQUIRED niche agents
  niche_agents = read_niche_agent_requirements(SCRATCHPAD + "/template_recommendations.md")
  // ═══ MANDATORY NICHE AGENT GATE ═══
  // Read semantic_invariants.md summary. If sync_gaps >= 1 OR accumulation_exposures >= 1
  // OR conditional_writes >= 1, SEMANTIC_GAP_INVESTIGATOR MUST be in niche_agents.
  // If missing → add it before proceeding. This gate prevents orchestrator omission.
  // Spawn ALL 8 standard agents + niche agents in a SINGLE message as parallel Task calls
  // (4 depth + 3 blind spot scanners + 1 validation sweep + N niche agents)
  // For each niche agent: read definition from ~/.claude/agents/skills/niche/{name}/SKILL.md, spawn as general-purpose
  // Niche agents write to {SCRATCHPAD}/niche_{name}_findings.md
  //
  // ═══ MODEL DIVERSITY ═══
  // Assign models to maximize decorrelation between depth agents:
  //   depth-token-flow: opus   (highest reasoning demand - balance invariants)
  //   depth-state-trace: opus  (highest reasoning demand - cross-function state)
  //   depth-edge-case: sonnet  (pattern-matching - boundary values, zero state)
  //   depth-external: sonnet   (pattern-matching - external call effects)
  //   Blind Spot Scanner A: sonnet, Scanner B: sonnet, Scanner C: sonnet
  //   Validation Sweep: sonnet
  //   Niche agents: sonnet
  // Rationale: Same-model agents have correlated attention patterns. Mixing opus/sonnet
  // increases decorrelation (CodeX-Verify: +39.7pp accuracy from low-correlation aggregation).
  // Cost impact: swapping 2 opus→sonnet is cost-neutral or savings.

  // ═══ DEPTH INPUT FILTERING ═══
  // Each depth agent reads ONLY findings from its domain (from consensus_map.md)
  // This prevents context dilution: a token-flow agent should not read state-trace findings
  // Orchestrator pre-filters findings_inventory.md into domain-specific views:
  //   depth-token-flow: findings tagged token-flow, balance, transfer, mint/burn
  //   depth-state-trace: findings tagged state-trace, accumulator, invariant, sync
  //   depth-edge-case: findings tagged edge-case, boundary, zero-state, overflow
  //   depth-external: findings tagged external, oracle, cross-chain, CPI/cross-module
  // Write domain-filtered views to {SCRATCHPAD}/depth_input_{domain}.md (max 15 findings each)
  // Depth agents read their filtered view instead of full findings_inventory.md

  // ═══ INJECTABLE INVESTIGATION AGENTS ═══
  // If an injectable skill was loaded, spawn dedicated sonnet agents for each domain
  // that has injectable investigation questions. These run IN PARALLEL with depth agents.
  // Main depth agents no longer contain PART 4 (injectable questions) - they focus on
  // PART 1-3 only. Injectable agents get a clean context with ONLY the decomposed questions.
  // Max 4 injectable agents (one per domain with questions). Each = 1 depth budget slot.
  // When no injectable is loaded: 0 agents spawned, 0 budget cost.
  injectable_agents = []
  if injectable_skill_loaded:
    for domain in [token-flow, state-trace, edge-case, external]:
      questions = get_injectable_questions_for_domain(domain)
      if len(questions) > 0:
        spawn injectable_investigation_agent(model="sonnet", domain, questions, SCRATCHPAD)
        injectable_agents.append(domain)

  // ═══ COMPACTION-RESILIENT MANIFEST ═══
  // Write manifest to DISK before spawning. After agents return (or after compaction
  // recovery), verify every expected output file exists. Re-spawn any missing agents.
  // This survives orchestrator context compaction - disk state, not memory state.
  // Cost: 1 Write + 1 Glob verification pass. Zero context cost to agents.
  expected_outputs = [
    ("depth-token-flow", "depth_token_flow_findings.md"),
    ("depth-state-trace", "depth_state_trace_findings.md"),
    ("depth-edge-case", "depth_edge_case_findings.md"),
    ("depth-external", "depth_external_findings.md"),
    ("scanner-A", "blind_spot_A_findings.md"),
    ("scanner-B", "blind_spot_B_findings.md"),
    ("scanner-C", "blind_spot_C_findings.md"),
    ("validation-sweep", "validation_sweep_findings.md"),
  ] + [(n.name, f"niche_{n.name}_findings.md") for n in niche_agents]
    + [(f"injectable-{d}", f"depth_{d}_injectable_findings.md") for d in injectable_agents]
  write_manifest(SCRATCHPAD + "/phase4b_manifest.md", expected_outputs,
    also_required=["confidence_scores.md"])  // post-step requirements

  depth_spawns_used = 8 + len(niche_agents) + len(injectable_agents)
  await all results  // includes injectable agents

  // ═══ TIMEOUT-AWARE SPLIT-AND-RETRY ═══
  for agent in completed_agents:
    if agent.timed_out:
      lite_a, lite_b = split_findings(agent.findings, max_per_lite=3)
      spawn depth-{agent.domain}-lite(lite_a, no_static_analysis=true, max_files=5)
      spawn depth-{agent.domain}-lite(lite_b, no_static_analysis=true, max_files=5)
      depth_spawns_used += 1  // 2 lite agents = 1 budget unit
  if any_lite_spawned: await lite results

  // Merge depth output into findings
  all_findings = merge(findings_inventory, depth_outputs, blind_spot, validation_sweep, injectable_outputs)

  // ═══ MANIFEST VERIFICATION ═══
  // Read phase4b_manifest.md. For each expected output: check file exists AND is non-empty.
  // If missing → re-spawn that agent with fresh prompt from scratchpad artifacts.
  // This catches agents silently dropped by orchestrator compaction mid-phase.
  // Do NOT re-read completed output files (context cost). Only check existence.
  manifest = read(SCRATCHPAD + "/phase4b_manifest.md")
  for (agent_name, output_file) in manifest.expected_outputs:
    if not exists(SCRATCHPAD + "/" + output_file) or is_empty(SCRATCHPAD + "/" + output_file):
      log("MANIFEST RECOVERY: re-spawning " + agent_name)
      respawn_agent(agent_name, SCRATCHPAD)  // rebuild prompt from scratchpad artifacts
      depth_spawns_used += 1
  if any_respawned: await respawned results; re-merge

  // ═══ SCORE all findings ═══
  // NOTE: Sibling Propagation merged back into Validation Sweep as CHECK 9.
  // Saves 1 depth budget slot. Validation Sweep already reads findings_inventory.md.
  // Spawn scoring agent (haiku - use Scoring Agent Template below)
  // Writes {SCRATCHPAD}/confidence_scores.md
  await scoring_agent

  // Write confidence distribution to {SCRATCHPAD}/confidence_distribution.md:
  //   CONFIDENT (≥0.7): N findings - [list]
  //   UNCERTAIN (0.4-0.7): M findings - [list with domains]
  //   LOW CONFIDENCE (<0.4): K findings - [list with domains]
  //   EXIT CONDITIONS: [which apply]

  // ═══ CHECK: Should we continue? ═══
  uncertain = [f for f in all_findings if f.confidence < 0.7]
  if len(uncertain) == 0:
    write {SCRATCHPAD}/adaptive_loop_log.md (1 iteration, exit: all confident)
    goto DONE
  if depth_spawns_used >= max_depth_spawns:
    write {SCRATCHPAD}/adaptive_loop_log.md (1 iteration, exit: budget exhausted)
    goto DONE
  // MANDATORY: Always proceed to iteration 2 if uncertain findings exist AND any uncertain
  // finding has severity Medium or above. Skip iteration 2 ONLY IF all uncertain findings
  // are Low/Info severity. "Pragmatic" skips are PROHIBITED for Medium+ uncertain findings.

  // ═══ ITERATION 2: Micro-Niche Targeted Depth ═══
  // Instead of spawning broad domain agents with up to 5 findings each,
  // spawn micro-niche agents with 1-3 findings each for maximum focus.
  // This prevents the attention dilution that caused regression.
  // Compute spawn_priority = (1 - confidence) * severity_weight for each uncertain finding
  // Use effective_severity from depth_candidates.md for CHAIN_ESCALATED findings
  // (Low findings that enable Medium+ chains get Medium weight=2 instead of Low weight=1)
  // Sort by spawn_priority descending, group into micro-niches of 1-3 findings
  prioritized_findings = sort_by_spawn_priority(uncertain)
  micro_niches = group_into_niches(prioritized_findings, max_per_niche=3)
  for niche in micro_niches:
    if depth_spawns_used >= max_depth_spawns: break
    clean_input = extract_evidence_only(niche.findings, niche.domain, max=3)
    spawn depth-{niche.domain}-micro(clean_input, iteration=2, max_findings=3)
    depth_spawns_used += 1
  await all results

  // Re-score with new-evidence-only rule (AD-5)
  spawn scoring_agent(require_new_evidence=true)
  await scoring_agent

  // ═══ LOOP DYNAMICS DETECTION ═══
  dynamics = classify_loop_dynamics(score_changes):
    // CONTRACTIVE: scores converging (>50% improved or stable)
    // OSCILLATORY: >50% of score changes are reversals
    // EXPLORATORY: new findings keep appearing
  if dynamics == OSCILLATORY:
    for f in uncertain: f.verdict = CONTESTED
    write {SCRATCHPAD}/adaptive_loop_log.md (2 iterations, exit: OSCILLATORY)
    goto DONE

  // ═══ CHECK: Progress made? ═══
  still_uncertain = [f for f in all_findings if f.confidence < 0.7]
  if len(still_uncertain) == 0 OR depth_spawns_used >= max_depth_spawns:
    write {SCRATCHPAD}/adaptive_loop_log.md (2 iterations, exit reason)
    goto DONE
  if no_confidence_improvement(still_uncertain):
    for f in still_uncertain: f.verdict = CONTESTED
    write {SCRATCHPAD}/adaptive_loop_log.md (2 iterations, exit: no progress)
    goto DONE

  // ═══ ITERATION 3: Final micro-niche pass ═══
  prioritized_findings = sort_by_spawn_priority(still_uncertain)
  micro_niches = group_into_niches(prioritized_findings, max_per_niche=2)  // even smaller niches for final pass
  for niche in micro_niches:
    if depth_spawns_used >= max_depth_spawns: break
    clean_input = extract_evidence_only(niche.findings, niche.domain, max=2)
    spawn depth-{niche.domain}-micro(clean_input, iteration=3, max_findings=2)
    depth_spawns_used += 1
  await results

  // Final re-score
  spawn scoring_agent(require_new_evidence=true)
  await scoring_agent

  // Force any still-uncertain to CONTESTED
  for f in all_findings:
    if f.confidence < 0.4: f.verdict = CONTESTED

  write {SCRATCHPAD}/adaptive_loop_log.md (3 iterations, exit: max iterations)

  DONE:
    // ═══ RESERVED: Design Stress Testing (1 slot pre-allocated) ═══
    // DST catches design-level issues (parameter bounds, constraint coherence) that depth agents
    // structurally miss. Runs unconditionally - its 1 reserved slot has negligible depth impact.
    spawn design_stress_agent(SCRATCHPAD, constraint_variables, function_list, attack_surface)
    depth_spawns_used += 1

    // Loop complete

    // ═══ VARIABLE-FINDING CROSS-REFERENCE ═══
    // Sonnet agent pre-computes a compact variable→finding map for chain analysis.
    // This surfaces semantic_invariants.md data WITHOUT loading it into the chain agent.
    spawn variable_map_agent(model="sonnet", prompt="
      Read {SCRATCHPAD}/semantic_invariants.md and {SCRATCHPAD}/findings_inventory.md.
      For each state variable in semantic_invariants.md, grep the findings inventory
      for finding IDs whose Location or Evidence references that variable name.
      Write to {SCRATCHPAD}/variable_finding_map.md a compact table:
      | Variable | Write Sites (with flags) | Findings | Chain Hint |
      Preserve these flags from semantic_invariants.md on each write site:
      - CONDITIONAL(expr): write only executes when expr is true - skip path leaves variable stale
      - SYNC_GAP(other_var): mirror variable that can diverge - note the paired variable
      - ACCUMULATION_EXPOSURE: time-weighted calc with controllable input
      The Chain Hint column states in one phrase why this variable may link findings
      (e.g., 'stale when condition false', 'diverges from paired_var after loss').
      One row per variable. Max 30 rows. Omit variables with 0 finding references.
      Return: 'DONE: {N} variables mapped to {M} findings'
    ")
    await variable_map_agent  // sonnet for chain relevance assessment quality

    // - proceed to Chain Analysis (Phase 4c)

  // ═══ POST-VERIFICATION ERROR TRACE FEEDBACK ═══
  // After Phase 5 verification completes (orchestrator handles this AFTER chain analysis):
  // 1. Read all verify_*.md files
  // 2. Extract error traces from CONTESTED/FALSE_POSITIVE verdicts
  // 3. Write to {SCRATCHPAD}/verification_error_traces.md
  // 4. If budget remaining (depth_spawns_used < max_depth_spawns) AND error traces exist:
  //    Spawn targeted depth agent with error traces as investigation questions (AD-6)
  //    This is the ONLY path that can trigger depth after iteration 3
```

### Exit Conditions Summary

| Condition | When | Effect |
|-----------|------|--------|
| All CONFIDENT | 0 findings < 0.7 | Exit immediately |
| Budget exhausted | depth_spawns_used ≥ max_depth_spawns | Exit, accept current scores |
| No progress | No new evidence in iteration 2 or 3 | Force CONTESTED on uncertain, exit |
| OSCILLATORY | >50% score changes are reversals after iteration 2 | Force CONTESTED on uncertain, exit |
| Max iterations | 3 iterations completed | Force CONTESTED on < 0.4, exit |
| DST Reserved | Always at DONE | Spawn Design Stress agent (1 pre-allocated slot), then proceed |
| POST_VERIFICATION_FEEDBACK | Error traces from Phase 5 + remaining budget | Additional targeted depth, then exit |

**CRITICAL**: "No progress" can ONLY trigger after iteration 2, never after iteration 1. Iteration 2 is always mandatory when uncertain findings exist. "No progress" means the iteration produced zero new evidence items - not that the scoring formula can't improve.

---

## Scoring Pipeline

> **Spawn after**: Each iteration of the depth loop.
> **Model**: Always haiku (formula application, not reasoning).
> Pre-compute consensus inline, then batch findings for parallel scoring to prevent single-agent overload on large audits.

### Pre-Score: Consensus Pre-Computation (Orchestrator Inline)

Before spawning scoring agents, orchestrator produces `{SCRATCHPAD}/consensus_map.md`:
1. Read `findings_inventory.md` - extract each finding's ID, Location, Agent source
2. Group by Location (program:Line range). For each group:
   - Agents flagging = unique agents with finding at this location
   - Agents covering = agents whose domain scope includes this program
   - Consensus = flagging / covering (cap at 1.0; +0.2 if specialized agent, cap 1.0)
3. Write table: `| Finding ID | Agents Flagging | Agents Covering | Consensus Score | Specialized? |`

### Batch Scoring

Split all findings into domain batches of ≤15 findings each (token-flow, state-trace, edge-case, external, access-control, misc).
Spawn parallel haiku scoring agents per batch. Each receives:
- Its batch of findings ONLY (extracted from source files)
- `{SCRATCHPAD}/consensus_map.md` (pre-computed Axis 2, shared across all batches)
- Scoring formula (unchanged - Axes 1,3,4 from finding data; Axis 2 from consensus_map)

After all return: merge `confidence_scores_batch_*.md` into `confidence_scores.md`.

### Scoring Agent Template (per batch)

```
Task(subagent_type="general-purpose", model="haiku", prompt="
You are the Confidence Scoring Agent (Batch: {DOMAIN}). You compute confidence scores for a batch of Solana audit findings using a fixed formula.

## Your Inputs
Read:
- {SCRATCHPAD}/consensus_map.md (pre-computed Axis 2 scores for ALL findings)
- Your batch of findings extracted from the relevant source files (provided below)
{IF ITERATION 2+: - {SCRATCHPAD}/confidence_scores.md (previous scores - for monotonic check)}

## Your Batch
{PASTE FINDING DATA FOR THIS BATCH - max 15 findings, extracted from findings_inventory.md + depth/blind_spot/validation files}

## Your Task

For EACH finding in your batch, compute 4 axis scores:

### Axis 1: Evidence (0.0–1.0)
Use the BEST evidence tag found for this finding:
- [PROD-ONCHAIN] = 1.0
- [PROD-SOURCE] = 0.9
- [PROD-FORK] = 0.9
- [CODE] = 0.8
- [DOC] = 0.4
- [MOCK] = 0.2
- [EXT-UNV] = 0.1
- No tag / unclear = 0.3
If finding has no explicit evidence tags, infer: code snippets from source = [CODE] = 0.8.

### Axis 2: Consensus (0.0–1.0)
Read from `{SCRATCHPAD}/consensus_map.md` - use the pre-computed score for each finding ID.
(Pre-computed by orchestrator: domain-aware agreement with specialized agent bonus.)

### Axis 3: Analysis Quality (0.0–1.0) - DUAL MODE

**Mode A - Depth agent findings** (finding ID starts with [DEPTH-*], [BLIND-*], or [VS-*]):
Count Depth Evidence tags ([BOUNDARY:*], [VARIATION:*], [TRACE:*]):
- 0 tags = 0.1
- 1 tag = 0.4
- 2 tags = 0.7
- 3+ tags = 1.0

**Mode B - All other findings** (breadth agents, chain findings, enabler findings):
From Step Execution field:
- Count steps marked ✓ or ✗(valid reason) as COMPLETE
- Count steps marked ✗(no reason) or ? as INCOMPLETE
- Score = COMPLETE / (COMPLETE + INCOMPLETE)
If no Step Execution field: score = 0.3

### Axis 4: RAG Match (0.0–1.0)
If finding has RAG validation result: use RAG confidence / 10
If no RAG validation: score = 0.3 (floor - missing RAG is a coverage gap, not negative evidence)

### Composite Score
composite = Evidence × 0.25 + Consensus × 0.25 + Analysis_Quality × 0.3 + RAG_Match × 0.2

### Classification
- composite ≥ 0.7: CONFIDENT
- 0.4 ≤ composite < 0.7: UNCERTAIN
- composite < 0.4: LOW_CONFIDENCE

{IF ITERATION 2+ WITH require_new_evidence=true:
### Monotonic Check
For each finding that existed in the previous confidence_scores.md:
- If this iteration's agent produced NEW evidence (new code ref, new tool output, new RAG match not in previous iteration): allow score increase
- If NO new evidence: keep previous score (do not increase)
- Score can NEVER decrease
}

## Output

Write to {SCRATCHPAD}/confidence_scores.md:

| Finding ID | Evidence | Consensus | Analysis Quality | RAG Match | Composite | Classification | Domain |
|------------|----------|-----------|--------------|-----------|-----------|---------------|--------|
| [XX-1] | 0.8 | 0.5 | 0.7 | 0.3 | 0.59 | UNCERTAIN | token-flow |
| ... | ... | ... | ... | ... | ... | ... | ... |

## Summary
- CONFIDENT (≥0.7): {N} findings
- UNCERTAIN (0.4-0.7): {M} findings
- LOW_CONFIDENCE (<0.4): {K} findings
- Total: {N+M+K} findings scored

Return: 'DONE: {total} findings scored - {N} CONFIDENT, {M} UNCERTAIN, {K} LOW_CONFIDENCE'
")
```

## MCP Soft Redirect

After iteration 1 scoring, the orchestrator checks for systematic RAG failure:

**Detection**: If `confidence_scores.md` shows RAG_Match axis = 0.3 (floor) for > 80% of findings:
1. Log to `adaptive_loop_log.md`: "MCP RAG FLOOR DETECTED - {N}% of findings at 0.3 floor"
2. For each UNCERTAIN finding, generate a targeted manual investigation question based on:
   - Fork ancestry patterns from `meta_buffer.md`
   - Protocol type common vulnerabilities (e.g., "vault: trace share price after fee harvest + loss event")
   - Attack surface signals tagged [ELEVATE] (see recon signal elevation)
3. Add these questions to the `depth_candidates.md` as `[RAG-COMPENSATE]` investigation targets
4. Iteration 2+ depth agents receive these as additional investigation questions (compatible with AD-1 evidence-only format)

**NOT a hard gate**: Pipeline continues normally. The redirect adds investigation breadth to compensate for missing historical pattern matching.

---

## Iteration 2+ Depth Agent Input Template (ANTI-DILUTION)

> **Purpose**: Clean finding cards for iteration 2-3 depth agents. Evidence only, no prior reasoning.
> **Anti-dilution rules**: AD-1 (evidence-only), AD-2 (no reasoning contamination), AD-3 (max 5), AD-4 (fresh tools), AD-5 (new evidence only).

> Iteration 2+ agents receive 1-3 findings (micro-niche) instead of up to 5. This maximizes per-finding depth and prevents the attention regression observed when broad agents receive too many findings.

For each iteration 2+ depth agent, use this prompt structure:

```
Task(subagent_type="depth-{type}", prompt="
You are the {TYPE} Devil's Advocate Depth Agent - ITERATION {N} (targeted pass) for a Solana program audit.

**YOUR ROLE**: You are the Devil's Advocate. Your PRIMARY job is to find what the previous analysis MISSED - not to re-confirm what it found. For each finding:
- Read the 'Prior Path' field to understand what was already explored. Your job is to explore what was NOT.
- For each prior conclusion: ask 'what adjacent bug does this analysis OBSCURE?' What is the OPPOSITE interpretation of the same code?
- You MUST produce at least one finding or observation that CONTRADICTS or EXTENDS the previous analysis. If you agree with everything, you have not done your job.
- Make your OWN tool calls. Produce NEW evidence that was not in iteration 1.

## Your Inputs

Read {SCRATCHPAD}/attack_surface.md and the source files referenced below.
Do NOT read prior depth agent output files (depth_*_findings.md from iteration 1).

## Findings to Investigate

{FOR EACH FINDING (max 5, lowest confidence first):}

### Finding [XX-N]: {Title}
- **Location**: {program.rs:L45-L67}
- **Evidence**: {[CODE] - relevant code snippet at L45}
- **Confidence**: {0.35}
- **Evidence Gap**: {What specific evidence is missing}
- **Prior Path**: {1-2 sentence summary of what the previous agent explored and how - NOT what it concluded. E.g., "Traced CPI state reload path; did not explore bump seed collision or PDA derivation variant."}
- **Investigate**: {Focused question - e.g., 'Can set_max_validators() be called with value below current validator count? Trace what happens to the loop at L120.'}

{END FOR EACH}

## MANDATORY DEPTH DIRECTIVE
For EVERY finding you re-analyze, apply at least 2 of these 3 techniques:
1. **Boundary Substitution**: Substitute boundary values into expressions. Tag: `[BOUNDARY:X=val → outcome]`
   Solana examples: `[BOUNDARY:lamports=0 → account garbage collected]`, `[BOUNDARY:CU=200000 → tx fails]`
2. **Parameter Variation**: Vary inputs across valid range. Tag: `[VARIATION:param A→B → outcome]`
   Solana examples: `[VARIATION:bump 255→254 → different PDA address]`, `[VARIATION:mint Token→Token-2022 → transfer fee applied]`
3. **Trace to Termination**: Follow execution to terminal state. When a boundary value produces weight=0, contribution=0, or amount=0 in a computation, trace whether the zero-value entry still INCREMENTS a counter or PASSES a gate that downstream code relies on for correctness. **Nested call resolution**: When tracing through a CPI, also trace what happens when control returns to the caller - does it reload account data and verify post-CPI state? Tag: `[TRACE:path→outcome at L{N}]`

## Your Task

For EACH finding above:
1. Read the source code at the specified location YOURSELF
2. Make your OWN tool calls:
   - Use Read/Grep tools for the relevant functions
   - validate_hypothesis() for RAG validation
   - search_solodit_live() if local results < 5
3. Answer the investigation question with NEW evidence
4. Produce a verdict: CONFIRMED / PARTIAL / REFUTED / CONTESTED
5. If you discover a NEW attack path not described in the finding card: document it as [DEPTH-{TYPE}-IT{N}-M]

## Output
Write to {SCRATCHPAD}/depth_{type}_iteration{N}_findings.md:
- Per-finding analysis with NEW evidence (tag all evidence sources)
- Updated verdicts (with justification from YOUR analysis, not prior agents)
- Any new findings discovered

Return: 'DONE: {N} findings re-analyzed, {M} new evidence items, {K} verdict changes, {J} new findings'
")
```
