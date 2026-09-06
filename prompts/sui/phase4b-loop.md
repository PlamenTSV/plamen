# Phase 4b: Adaptive Depth Loop -- Sui Move

> **Usage**: Orchestrator reads this file and runs the Adaptive Depth Loop for Sui Move audits.
> Iteration 1 spawns ALL 8 agents (4 depth + 3 blind spot + 1 validation sweep). Iterations 2-3 are targeted and autonomous.
> Replace placeholders `{SCRATCHPAD}`, `{TYPE}`, etc. with actual values.

---

## Orchestrator: Autonomous Adaptive Depth Loop

> **Coverage-first design**: Iteration 1 ALWAYS spawns all 8 agents.
> Iterations 2-3 are targeted, autonomous, and anti-dilution protected.
> **The orchestrator runs the ENTIRE loop without user intervention.**
> Timeout-aware split-and-retry, severity-weighted budget, dynamic cap, loop dynamics detection, post-verification error trace feedback.
> **Reference**: `~/.claude/rules/phase4-confidence-scoring.md` for scoring model and anti-dilution rules.

### Loop Pseudocode (Orchestrator Executes This)

```
ADAPTIVE_DEPTH_LOOP(findings_inventory):
  max_iterations = 3
  total_findings = len(findings_inventory)
  breadth_savings = max(0, 5 - actual_breadth_agent_count)  // breadth-to-depth redirect
  depth_floor = 12 + breadth_savings  // Simple codebases (3 breadth) get floor=14
  niche_injectable_count = len(niche_agents)
  niche_overflow = max(0, niche_injectable_count - 3)
  thorough_bonus = 5 if MODE == THOROUGH else 0
  hard_cap = 20 + niche_overflow + thorough_bonus
  iter1_fixed = 10 + niche_injectable_count + 1
  iter23_reserve = 3 if MODE == THOROUGH else 0
  effective_floor = max(depth_floor, iter1_fixed + iter23_reserve)
  max_depth_spawns = min(max(effective_floor, ceil(total_findings / 5) + 7), hard_cap)
  dst_reserved = 1  // Design Stress Testing always gets 1 slot
  perturbation_reserved = 1 if MODE == THOROUGH else 0  // Finding Perturbation Agent (Thorough only)
  depth_available = max_depth_spawns - dst_reserved - perturbation_reserved  // depth agents share the rest
  max_findings_per_agent = 5  // anti-dilution rule AD-3
  depth_spawns_used = 0

  // â•â•â• PHASE 4a.5: Semantic Invariant Pre-Computation â•â•â•
  // Sonnet agent enumerates write sites, semantic invariants, conditional/sync/accumulation annotations
  // Produces {SCRATCHPAD}/semantic_invariants.md - consumed by depth-state-trace and Validation Sweep
  // See CLAUDE.md Phase 4a.5 for full prompt template
  spawn semantic_invariant_agent(model="sonnet", SCRATCHPAD, state_variables, function_list, source_files)
  await semantic_invariant_agent  // MUST complete before depth agents spawn (they consume its output)

  // â•â•â• INVARIANT FUZZ CAMPAIGN - Sui random-input tests â•â•â•
  // NOTE (V2): the fuzz campaign runs as a driver-scheduled depth fuzz sidecar
  // worker, not a coordinator spawn. See prompts/sui/v2/phase4b-invariant-fuzz.md.
  // The driver always emits the invariant worker in Thorough; the worker prefers
  // #[random_test] with `sui move test --rand-num-iters` and falls back to
  // boundary-value parameterized tests when the invariant cannot be expressed in
  // the Sui test harness. It degrade-continues without halting depth. Do NOT
  // spawn an agent from here.

  // â•â•â• ITERATION 1: Full coverage (ALWAYS) â•â•â•
  // Read template_recommendations.md for REQUIRED niche agents
  niche_agents = read_niche_agent_requirements(SCRATCHPAD + "/template_recommendations.md")
  // â•â•â• MANDATORY NICHE AGENT GATE â•â•â•
  // Read semantic_invariants.md summary. If sync_gaps >= 1 OR accumulation_exposures >= 1
  // OR conditional_writes >= 1 OR cluster_gaps >= 1, SEMANTIC_GAP_INVESTIGATOR MUST be in niche_agents.
  // If missing â†’ add it before proceeding. This gate prevents orchestrator omission.
  // Spawn ALL 8 standard agents + niche agents in a SINGLE message as parallel Task calls
  // (4 depth + 3 blind spot scanners + 1 validation sweep + N niche agents)
  // For each niche agent: read definition from ~/.claude/agents/skills/niche/{name}/SKILL.md, spawn as general-purpose
  // Niche agents write to {SCRATCHPAD}/niche_{name}_findings.md
  //
  // â•â•â• MODEL DIVERSITY â•â•â•
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
  // Cost impact: swapping 2 opusâ†’sonnet is cost-neutral or savings.

  // â•â•â• DEPTH INPUT FILTERING â•â•â•
  // Each depth agent reads ONLY findings from its domain (from consensus_map.md)
  // This prevents context dilution: a token-flow agent should not read state-trace findings
  // Orchestrator pre-filters findings_inventory.md into domain-specific views:
  //   depth-token-flow: findings tagged token-flow, balance, transfer, mint/burn
  //   depth-state-trace: findings tagged state-trace, accumulator, invariant, sync
  //   depth-edge-case: findings tagged edge-case, boundary, zero-state, overflow
  //   depth-external: findings tagged external, oracle, cross-chain, CPI/cross-module
  // Write domain-filtered views to {SCRATCHPAD}/depth_input_{domain}.md (max 15 findings each)
  // Depth agents read their filtered view instead of full findings_inventory.md

  // â•â•â• SYMMETRIC OPERATION PAIRING (Thorough only) â•â•â•
  // Pre-compute symmetric operation pairs from function_list.md and inject into
  // depth agent prompts. Removes discovery burden " agents verify both sides of
  // each pair mechanically instead of reasoning about which pairs exist.
  // Evidence: AdverTest (2026), Meta mutation-guided test gen (FSE 2025).
  if MODE == THOROUGH:
    // Orchestrator or haiku agent reads function_list.md, identifies pairs:
    // deposit/withdraw, borrow/repay, mint/burn, stake/unstake, lock/unlock,
    // approve/revoke, enable/disable, pause/unpause, add/remove
    // Writes compact table (~10-15 lines) to {SCRATCHPAD}/symmetric_pairs.md:
    //   | Pair # | Positive Op | Negative Op | Shared State Variables |
    // This table is injected at the END of each depth agent's prompt with directive:
    //   "For EACH pair, you MUST analyze BOTH operations. A finding about one side
    //    WITHOUT analysis of the other is INCOMPLETE. Include in your output:
    //    | Pair # | Positive Analyzed? | Negative Analyzed? | Both Rounding? | Both Boundary? |"
    symmetric_pairs = extract_symmetric_pairs(SCRATCHPAD + "/function_list.md")
    write(SCRATCHPAD + "/symmetric_pairs.md", symmetric_pairs)

  // â•â•â• INJECTABLE INVESTIGATION AGENTS â•â•â•
  // If an injectable skill was loaded, append its registered methodology to the
  // target depth roles listed in rules/skill-registry.json. Do not spawn
  // injectable-specific agents and do not create injectable-specific outputs.
  // When no injectable is loaded: 0 agents spawned, 0 budget cost.
  loaded_injectable_skills = []
  if injectable_skill_loaded:
    for domain in [token-flow, state-trace, edge-case, external]:
      questions = get_injectable_questions_for_domain(domain)
      if len(questions) > 0:
        append_injectable_methodology_to_registered_depth_role(domain, questions)
        loaded_injectable_skills.append(domain)

  // â•â•â• COMPACTION-RESILIENT MANIFEST â•â•â•
  // Write manifest to DISK before spawning. After agents return (or after compaction
  // recovery), verify every expected output file exists. Re-spawn any missing agents.
  // This survives orchestrator context compaction - disk state, not memory state.
  // Cost: 1 Write + 1 Glob verification pass. Zero context cost to agents.
  expected_outputs = [
    ("depth-token-flow", "depth_token_flow_findings.md"),
    ("depth-state-trace", "depth_state_trace_findings.md"),
    ("depth-edge-case", "depth_edge_case_findings.md"),
    ("depth-external", "depth_external_findings.md"),
    ("scanner-A", "blind_spot_a_findings.md"),
    ("scanner-B", "blind_spot_b_findings.md"),
    ("scanner-C", "blind_spot_c_findings.md"),
    ("validation-sweep", "validation_sweep_findings.md"),
  ] + [(n.name, f"niche_{n.name}_findings.md") for n in niche_agents]
  write_manifest(SCRATCHPAD + "/phase4b_manifest.md", expected_outputs,
    also_required=[])  // canonical confidence is a post-wave DRIVER output

  depth_spawns_used = 8 + len(niche_agents)
  await all results

  // â•â•â• TIMEOUT-AWARE SPLIT-AND-RETRY â•â•â•
  for agent in completed_agents:
    if agent.timed_out:
      lite_a, lite_b = split_findings(agent.findings, max_per_lite=3)
      spawn depth-{agent.domain}-lite(lite_a, no_static_analysis=true, max_files=5)
      spawn depth-{agent.domain}-lite(lite_b, no_static_analysis=true, max_files=5)
      depth_spawns_used += 1  // 2 lite agents = 1 budget unit
  if any_lite_spawned: await lite results

  // Merge depth output into findings. Injectable methodology is already inside depth outputs.
  all_findings = merge(findings_inventory, depth_outputs, blind_spot, validation_sweep)

  // â•â•â• MANIFEST VERIFICATION â•â•â•
  // Read phase4b_manifest.md. For each expected output: check file exists AND is non-empty.
  // If missing â†’ re-spawn that agent with fresh prompt from scratchpad artifacts.
  // This catches agents silently dropped by orchestrator compaction mid-phase.
  // Do NOT re-read completed output files (context cost). Only check existence.
  manifest = read(SCRATCHPAD + "/phase4b_manifest.md")
  for (agent_name, output_file) in manifest.expected_outputs:
    if not exists(SCRATCHPAD + "/" + output_file) or is_empty(SCRATCHPAD + "/" + output_file):
      log("MANIFEST RECOVERY: re-spawning " + agent_name)
      respawn_agent(agent_name, SCRATCHPAD)  // rebuild prompt from scratchpad artifacts
      depth_spawns_used += 1
  if any_respawned: await respawned results; re-merge

  // â•â•â• NICHE AGENT COVERAGE VERIFICATION (Thorough only) â•â•â•
  // Post-hoc mechanical check: did each niche agent process every in-scope entity?
  // Haiku judge compares function_list.md against each niche output.
  // Cost: 1 haiku call. Only re-prompts if gaps found.
  if MODE == THOROUGH AND len(niche_agents) > 0:
    spawn coverage_judge(model="haiku", prompt="
      You are the Niche Agent Coverage Judge. For each niche agent output file, mechanically
      verify that every in-scope entity was processed.

      Read {SCRATCHPAD}/function_list.md (master function list).
      Read {SCRATCHPAD}/contract_inventory.md (in-scope contracts).

      For EACH niche output file (niche_*_findings.md):
      1. Determine which functions/entities fall within that agent's scope
      2. Check: is each in-scope entity mentioned in the output (by name or location)?
      3. If an entity is missing: record as GAP

      Write to {SCRATCHPAD}/niche_coverage_gaps.md:
      | Niche Agent | In-Scope Entities | Analyzed | Gaps | Missing Entities |

      If 0 gaps across all agents: write 'COVERAGE: COMPLETE' and return.
      If gaps found: list each (agent, missing_entity) pair.

      Return: 'COVERAGE: {COMPLETE or N gaps across M agents}'
    ")
    await coverage_judge
    if coverage_judge.gaps > 0 AND depth_spawns_used < max_depth_spawns:
      for (agent_name, missing_entities) in coverage_gaps:
        spawn niche_gap_filler(model="sonnet", prompt="
          You are a targeted gap-filler for {agent_name}. Analyze ONLY these entities
          that the original agent missed: {missing_entities}.
          Apply the same methodology from ~/.claude/agents/skills/niche/{agent_name}/SKILL.md.
          Write to {SCRATCHPAD}/niche_{agent_name}_gaps.md
        ")
        depth_spawns_used += 1
      await gap_fillers; re-merge

  // â•â•â• FINDING PERTURBATION AGENT (Thorough only) â•â•â•
  // Reads depth findings and applies 5 structured mutation operators to test adjacent
  // vulnerability space. Catches "single-hit satisfaction" where agents find one variant
  // of a bug class then stop (e.g., deposit rounding found but not withdrawal rounding).
  // Evidence: AdverTest (Feb 2026, +8.56% FDR), Meta mutation-guided test gen (FSE 2025).
  // Cost: 1 sonnet agent, 1 depth budget slot. Runs parallel with checklist agent.
  if MODE == THOROUGH AND depth_spawns_used < max_depth_spawns:
    spawn perturbation_agent(model="sonnet", prompt="
      You are the Finding Perturbation Agent. You systematically test whether
      ADJACENT vulnerabilities exist near each confirmed depth finding.

      Read all depth_*_findings.md and blind_spot_*_findings.md in {SCRATCHPAD}/.

      For EACH CONFIRMED or PARTIAL finding (max 15, prioritize by severity):

      Step 1: Classify the finding's dimensions:
        - Operation direction (deposit/withdraw/borrow/repay/mint/burn)
        - Boundary value tested (0, MAX, specific threshold)
        - Condition checked/missing (zero, negative, staleness, bounds)
        - Rounding direction (floor/ceil, favors user/protocol)

      Step 2: Apply ALL applicable perturbation operators:
        | Operator | Action |
        |----------|--------|
        | DIRECTION_FLIP | Finding about op X -> read inverse op, check same class |
        | BOUNDARY_SHIFT | Finding at value V -> check region between 0 and V |
        | CONDITION_NEGATE | Missing check for C -> also check !C and related conditions |
        | OPERAND_SWAP | A op B -> check B op A (different rounding/precision) |
        | TEMPORAL_INVERT | Pre-action state bug -> check post-action state |

      Step 3: For each probe, read the actual source code and determine:
        - Is the perturbation a real vulnerability? (YES -> write finding)
        - Is there a defense? (YES -> note briefly, move on)

      Step 4: Coverage table (MANDATORY):
        | Source Finding | Perturbation | Operator | Source File Checked | Result | New Finding? |

      Write to {SCRATCHPAD}/perturbation_findings.md
      Use finding IDs [PERT-1], [PERT-2]... Max 8 new findings.
      Use standard finding format from ~/.claude/rules/finding-output-format.md.

      SCOPE: Write ONLY to your assigned output file. Return your findings and stop.
      Return: 'DONE: {P} perturbations tested, {N} new findings'
    ")
    depth_spawns_used += 1

  // â•â•â• DEPTH SKILL EXECUTION CHECKLIST (Thorough only) â•â•â•
  // Cheap post-hoc verification: did each depth agent execute each step of its skill?
  // Gaps become investigation questions for DA iteration 2.
  // Evidence: Verifiable Checklist Module pattern (2026). Extends Processing Protocol
  // (0 misses for scanners) to depth agents via post-hoc checking.
  // Cost: 1 haiku agent (~0.1x sonnet). Runs parallel with perturbation agent.
  if MODE == THOROUGH:
    spawn checklist_agent(model="haiku", prompt="
      You are the Depth Skill Execution Checklist Agent.

      For each depth agent, verify that it executed each step of its assigned skill.

      Depth Agent -> Skill Mapping:
        depth-token-flow -> ~/.claude/agents/skills/sui/token-flow-tracing/SKILL.md
        depth-state-trace -> ~/.claude/agents/skills/sui/type-safety/SKILL.md
        depth-edge-case -> ~/.claude/agents/skills/sui/zero-state-return/SKILL.md
        depth-external -> ~/.claude/agents/skills/sui/external-precondition-audit/SKILL.md

      For EACH depth agent:
      1. Read the skill file. Extract each numbered step, section, or CHECK.
      2. Read the depth agent output ({SCRATCHPAD}/depth_{domain}_findings.md).
      3. For each skill step: is there evidence the agent performed it?
         Evidence = specific code location analyzed + result stated.
      4. Produce a coverage table:
         | Agent | Skill Step | Description | Evidence in Output? | Gap? |

      5. For each GAP, generate an investigation question:
         'Skill step {N} ({description}) not evidenced. Check: {what to verify}'

      Also check the MANDATORY DEPTH DIRECTIVE for each finding:
         | Finding ID | Depth Tags Count (>=2?) | Dual-Extreme Applied? | Gap? |

      Write to {SCRATCHPAD}/skill_execution_gaps.md
      Return: 'DONE: {N} skill step gaps, {M} depth directive gaps across {K} agents'
    ")
    // Await both perturbation and checklist agents
    await perturbation_agent, checklist_agent
    // Merge perturbation findings into all_findings
    if perturbation_findings exist: merge into all_findings
    // Feed checklist gaps into iteration 2 targeting (read by DA agents)

  // â•â•â• SCORE all findings â•â•â•
  // NOTE: Sibling Propagation is a standalone agent (scanner-tier, parallel with Validation Sweep).
  // It reads findings_inventory.md and writes sibling_propagation_findings.md.
  // Ask the routing helper for an in-memory proposal (template below).
  // It has no scratchpad write authority; the driver publishes canonical scores.
  await routing_helper

  // Write confidence distribution to {SCRATCHPAD}/confidence_distribution.md:
  //   CONFIDENT (â‰¥0.7): N findings - [list]
  //   UNCERTAIN (0.4-0.7): M findings - [list with domains]
  //   LOW CONFIDENCE (<0.4): K findings - [list with domains]
  //   EXIT CONDITIONS: [which apply]

  // â•â•â• CHECK: Should we continue? â•â•â•
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

  // â•â•â• ITERATION 2: Micro-Niche Targeted Depth â•â•â•
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

  // Re-route with new-evidence-only rule (AD-5); return table in memory.
  ask routing_helper(require_new_evidence=true)
  await routing_helper

  // â•â•â• LOOP DYNAMICS DETECTION â•â•â•
  dynamics = classify_loop_dynamics(score_changes):
    // CONTRACTIVE: scores converging (>50% improved or stable)
    // OSCILLATORY: >50% of score changes are reversals
    // EXPLORATORY: new findings keep appearing
  if dynamics == OSCILLATORY:
    for f in uncertain: retain_candidate_and_record_routing_debt(f)
    write {SCRATCHPAD}/adaptive_loop_log.md (2 iterations, exit: OSCILLATORY)
    goto DONE

  // â•â•â• CHECK: Progress made? â•â•â•
  still_uncertain = [f for f in all_findings if f.confidence < 0.7]
  if len(still_uncertain) == 0 OR depth_spawns_used >= max_depth_spawns:
    write {SCRATCHPAD}/adaptive_loop_log.md (2 iterations, exit reason)
    goto DONE
  if no_confidence_improvement(still_uncertain):
    for f in still_uncertain: retain_candidate_and_record_routing_debt(f)
    write {SCRATCHPAD}/adaptive_loop_log.md (2 iterations, exit: no progress)
    goto DONE

  // â•â•â• ITERATION 3: Final micro-niche pass â•â•â•
  prioritized_findings = sort_by_spawn_priority(still_uncertain)
  micro_niches = group_into_niches(prioritized_findings, max_per_niche=2)  // even smaller niches for final pass
  for niche in micro_niches:
    if depth_spawns_used >= max_depth_spawns: break
    clean_input = extract_evidence_only(niche.findings, niche.domain, max=2)
    spawn depth-{niche.domain}-micro(clean_input, iteration=3, max_findings=2)
    depth_spawns_used += 1
  await results

  // Final transient re-routing proposal
  ask routing_helper(require_new_evidence=true)
  await routing_helper

  // Confidence telemetry cannot change verdicts.
  for f in all_findings:
    if f.confidence < 0.4: retain_candidate_and_require_verification(f)

  write {SCRATCHPAD}/adaptive_loop_log.md (3 iterations, exit: max iterations)

  DONE:
    // â•â•â• RESERVED: Design Stress Testing (1 slot pre-allocated) â•â•â•
    // DST catches design-level issues (parameter bounds, constraint coherence) that depth agents
    // structurally miss. Runs unconditionally - its 1 reserved slot has negligible depth impact.
    spawn design_stress_agent(SCRATCHPAD, constraint_variables, function_list, attack_surface)
    depth_spawns_used += 1

    // Loop complete

    // â•â•â• COVERED-FUNCTION RE-SWEEP â•â•â•
    // Counters finding-level attention saturation: once a function has a finding,
    // other vulnerability classes in that function are masked. This re-sweep forces
    // lens rotation on functions that already have findings.
    // 1 sonnet agent, 1 depth budget slot. Runs after DST, before chain prep.
    covered = extract_functions_with_findings(depth_*_findings, blind_spot_*_findings, niche_*_findings)
    if len(covered) > 0 AND depth_spawns_used < max_depth_spawns:
      spawn resweep_agent(model="sonnet", prompt="
        You are the Covered-Function Re-Sweep Agent.

        These functions already have findings. For each, the KNOWN topic is listed.
        Analyze each for vulnerability classes OUTSIDE the known topic.

        {COVERED_FUNCTION_TABLE: function_name | file:line | known_topic_to_EXCLUDE}

        Read {SCRATCHPAD}/state_dependency_map.md for cross-function state dependencies.

        For each function:
        1. Read the function source code
        2. What OTHER vulnerability classes could affect this function?
           (state dependency breaks, input validation gaps, authorization/approval
           side effects, object ownership violations, return value mishandling)
        3. If the function modifies state that other functions depend on (check
           state_dependency_map.md): can calling this function break those consumers?

        CALIBRATION:
        - Finding nothing new is a valid and expected output
        - Do NOT fabricate findings to justify your existence
        - Every finding MUST have a specific code location (file:line)
        - Every finding MUST NOT overlap with the excluded topic
        - Max 5 findings total across all re-examined functions

        Write to {SCRATCHPAD}/resweep_findings.md
        Use finding IDs [RSW-1], [RSW-2], etc. with standard finding format.

        SCOPE: Write ONLY to your assigned output file. Do NOT proceed to subsequent
        pipeline phases. Return your findings and stop.

        Return: 'DONE: {N} new findings from {M} re-examined functions'
      ")
      depth_spawns_used += 1
      await resweep_agent

    // â•â•â• VARIABLE-FINDING CROSS-REFERENCE â•â•â•
    // Sonnet agent pre-computes a compact variableâ†’finding map for chain analysis.
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

  // â•â•â• POST-VERIFICATION ERROR TRACE FEEDBACK â•â•â•
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
| Budget exhausted | depth_spawns_used â‰¥ max_depth_spawns | Exit, accept current scores |
| No progress | No new evidence in iteration 2 or 3 | Force CONTESTED on uncertain, exit |
| OSCILLATORY | >50% score changes are reversals after iteration 2 | Force CONTESTED on uncertain, exit |
| Max iterations | 3 iterations completed | Force CONTESTED on < 0.4, exit |
| DST Reserved | Always at DONE | Spawn Design Stress agent (1 pre-allocated slot), then proceed |
| POST_VERIFICATION_FEEDBACK | Error traces from Phase 5 + remaining budget | Additional targeted depth, then exit |

**CRITICAL**: "No progress" can ONLY trigger after iteration 2, never after iteration 1. Iteration 2 is always mandatory when uncertain findings exist. "No progress" means the iteration produced zero new evidence items - not that the scoring formula can't improve.

---

## Scoring Pipeline

> **Spawn after**: Each iteration of the depth loop.
> **Model**: Always sonnet (formula application with per-finding differentiation).
> The driver pre-computes typed consensus authority, then findings may be batched for scoring.

### Pre-Score: Typed Consensus Authority (Deterministic Driver)

The driver writes `confidence_consensus_authority.json` and its exact
`consensus_map.md` projection. One observer = 0.0. Corroboration requires
distinct current worker/prompt/dispatch identities explicitly tied to the same
upstream finding identity. Location overlap, retry/copy prose, stale authority,
and specialized-skill assignment do not count as agreement.

### Batch Scoring

Split all findings into domain batches of â‰¤15 findings each (token-flow, state-trace, edge-case, external, access-control, misc).
Ask parallel sonnet-class routing helpers per batch. Each receives:
- Its batch of findings ONLY (extracted from source files)
- A current driver-owned `consensus_map.md` only if exact authority is already
  available; otherwise Consensus is `0.0`
- Scoring formula (unchanged - Axes 1,3,4 from finding data; Axis 2 from consensus_map)

After all return: merge the returned batch tables in coordinator memory. If
any batch is absent, treat its unresolved Medium+ findings as UNCERTAIN.

### Transient Routing Helper Template (per batch)

```
Task(subagent_type="general-purpose", model="sonnet", prompt="
You are the Confidence Scoring Agent (Batch: {DOMAIN}). You compute confidence scores for a batch of Sui Move audit findings using a fixed formula.

## Your Inputs
Read:
- {SCRATCHPAD}/consensus_map.md only when current and authority-bound;
  otherwise use 0.0 for every Consensus row
- Your batch of findings extracted from the relevant source files (provided below)
{IF ITERATION 2+: - the parent-supplied previous routing table}

## Your Batch
{PASTE FINDING DATA FOR THIS BATCH - max 15 findings, extracted from findings_inventory.md + depth/blind_spot/validation files}

## Your Task

For EACH finding in your batch, compute 4 axis scores:

### Axis 1: Evidence (0.0—1.0)
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

### Axis 2: Consensus (0.0—1.0)
Read from `{SCRATCHPAD}/consensus_map.md` - use the pre-computed score for each finding ID.
(Driver-derived independent corroboration; missing/unbound rows score 0.0.)

### Axis 3: Analysis Quality (0.0—1.0) - DUAL MODE

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

### External Precedent (not a confidence axis)
Do not emit a precedent column. Under
`~/.claude/rules/precedent-evidence-policy.md`, external precedent never changes
mechanism confidence or reduces depth.

### Composite Score
composite = Evidence Ã— 0.25 + Consensus Ã— 0.25 + Analysis_Quality Ã— 0.3

### Classification
- composite â‰¥ 0.7: CONFIDENT
- 0.4 â‰¤ composite < 0.7: UNCERTAIN
- composite < 0.4: LOW_CONFIDENCE

{IF ITERATION 2+ WITH require_new_evidence=true:
### Monotonic Check
For each finding that existed in the previous routing table:
- If this iteration's agent produced NEW code/production evidence (new code ref or code-analysis/test output): allow score increase
- If NO new evidence: keep previous score (do not increase)
- Score can NEVER decrease
}

### Per-Finding Differentiation (MANDATORY)
Each finding's composite MUST be computed from its individual evidence tags, consensus map entry, and analysis quality indicators. If two findings have different evidence profiles, their composites MUST differ. Identical composites for 4+ consecutive findings indicates formulaic stub scoring — re-read each finding's actual data before continuing.

## Output

Return this table to the parent coordinator. MUST NOT modify
`{SCRATCHPAD}/confidence_scores.md`; the driver publishes it after the
depth wave:

| Finding ID | Evidence | Consensus | Analysis Quality | Composite | Classification | Domain |
|------------|----------|-----------|------------------|-----------|----------------|--------|
| [XX-1] | 0.8 | 0.5 | 0.7 | 0.56 | UNCERTAIN | token-flow |
| ... | ... | ... | ... | ... | ... | ... |

## Summary
- CONFIDENT (â‰¥0.7): {N} findings
- UNCERTAIN (0.4-0.7): {M} findings
- LOW_CONFIDENCE (<0.4): {K} findings
- Total: {N+M+K} findings scored

Return: 'DONE: {total} findings scored - {N} CONFIDENT, {M} UNCERTAIN, {K} LOW_CONFIDENCE'
")
```

---

## MCP Soft Redirect

After iteration 1 scoring, the orchestrator checks for systematic code-evidence gaps:

**Detection**: If more than 80% of findings remain UNCERTAIN/LOW from code-derived axes:
1. Log to `adaptive_loop_log.md`: "SYSTEMATIC CODE-EVIDENCE GAP - {N}% remain open"
2. For each UNCERTAIN finding, generate a targeted manual investigation question based on:
   - Fork ancestry patterns from `meta_buffer.md` (e.g., "Cetus concentrated liquidity: does this pool handle tick boundary edge cases?")
   - Protocol type common vulnerabilities (e.g., "vault: trace share price after fee harvest + loss event")
   - Attack surface signals tagged [ELEVATE] (see recon signal elevation)
3. Add these questions to `depth_candidates.md` as `[EVIDENCE-GAP]` investigation targets
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
You are the {TYPE} Devil's Advocate Depth Agent - ITERATION {N} (targeted pass) for a Sui Move package audit.

**YOUR ROLE**: You are the Devil's Advocate. Your PRIMARY job is to find what the previous analysis MISSED - not to re-confirm what it found. For each finding:
- Read the 'Prior Path' field to understand what was already explored. Your job is to explore what was NOT.
- For each prior conclusion: ask 'what adjacent bug does this analysis OBSCURE?' What is the OPPOSITE interpretation of the same code?
- You MUST produce at least one finding or observation that CONTRADICTS or EXTENDS the previous analysis. If you agree with everything, you have not done your job.
- Make your OWN MCP tool calls. Produce NEW evidence that was not in iteration 1.

## Your Inputs

Read {SCRATCHPAD}/attack_surface.md and the source files referenced below.
Do NOT read prior depth agent output files (depth_*_findings.md from iteration 1).

## Findings to Investigate

{FOR EACH FINDING (max 5, lowest confidence first):}

### Finding [XX-N]: {Title}
- **Location**: {module.move:L45-L67}
- **Evidence**: {[CODE] - relevant code snippet at L45}
- **Confidence**: {0.35}
- **Evidence Gap**: {What specific evidence is missing}
- **Prior Path**: {1-2 sentence summary of what the previous agent explored and how - NOT what it concluded. E.g., "Traced object ownership transfer in PTB; did not explore shared object contention or version mismatch."}
- **Investigate**: {Focused question - e.g., 'Can set_max_capacity() be called with new_value < current_count? Trace what happens to the vector iteration at L120 - does the abort cascade?'}

{END FOR EACH}

## MANDATORY DEPTH DIRECTIVE
For EVERY finding you re-analyze, apply at least 2 of these 3 techniques:
1. **Boundary Substitution**: Substitute boundary values into expressions. Tag: `[BOUNDARY:X=val â†’ outcome]`
   Sui examples: `[BOUNDARY:coin_value=0 â†’ empty coin abort at balance::split]`, `[BOUNDARY:shared_obj_version=OLD â†’ stale state in PTB cmd2]`
2. **Parameter Variation**: Vary inputs across valid range. Tag: `[VARIATION:param Aâ†’B â†’ outcome]`
   Sui examples: `[VARIATION:object ownedâ†’shared â†’ any tx can mutate]`, `[VARIATION:package V1â†’V2 â†’ new abort conditions in external call]`
3. **Trace to Termination**: Follow execution to terminal state. When a boundary value produces weight=0, contribution=0, or amount=0 in a computation, trace whether the zero-value entry still INCREMENTS a counter or PASSES a gate that downstream code relies on for correctness. **Nested call resolution**: When tracing an extraction path through an inner function (e.g., external module call, PTB command result routing), also trace what happens when control returns to the OUTER calling function - does it perform a post-execution state check (balance comparison, total verification, assert) that atomically aborts the entire transaction if the extraction exceeds bounds? **PTB multi-command trace**: Trace through ALL commands in sequence - earlier commands produce results consumed by later commands. Tag: `[TRACE:pathâ†’outcome at L{N}]`

## Your Task

For EACH finding above:
1. Read the source code at the specified location YOURSELF
2. Make your OWN MCP tool calls:
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
