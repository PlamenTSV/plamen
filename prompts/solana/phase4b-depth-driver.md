---
description: "Phase 4b: Depth Loop Driver -- spawns depth agents, scanners, niche agents, and support agents for Solana audits"
---

# Phase 4b: Adaptive Depth Loop Driver (Solana)

This prompt tells the `claude -p` session how to spawn ALL depth iteration 1 agents. The session reads instantiation data, spawns agents via the Agent tool, waits for them, and verifies artifacts.

---

## Light Mode Override

When `{MODE}` is `light`, skip the standard 8-agent spawn. Instead spawn 4 merged sonnet agents:
- (a) Combined token-flow + state-trace
- (b) Combined edge-case + external
- (c) Combined scanner A+B+C
- (d) Validation sweep

Skip niche agents, skip confidence scoring, skip iterations 2-3. After iteration 1 completes, proceed directly to Phase 4c.

---

## Step 1: Read Instantiation Data

Read the following files:

- `{SCRATCHPAD}/template_recommendations.md` -- niche agents (## Niche Agents section) and injectable skills
- `{SCRATCHPAD}/findings_inventory.md` -- all breadth findings (first 100 lines for summary)
- `{SCRATCHPAD}/semantic_invariants.md` -- semantic invariant data (if exists; Light mode won't have this)
- `{SCRATCHPAD}/design_context.md` -- protocol design (for invariant consistency check directive)
- `{SCRATCHPAD}/confidence_scores.md` -- only exists for iteration 2+; absent for iteration 1
- `~/.claude/prompts/solana/phase4b-depth-templates.md` -- depth agent role definitions and methodology
- `~/.claude/prompts/solana/phase4b-scanner-templates.md` -- scanner agent definitions

---

## Step 2: Compute Agent Roster

### Standard Agents (always spawn in Core/Thorough)

| Agent | Role | Model | Output File |
|-------|------|-------|-------------|
| Depth 1 | depth-token-flow | opus | `depth_token_flow_findings.md` |
| Depth 2 | depth-state-trace | opus | `depth_state_trace_findings.md` |
| Depth 3 | depth-edge-case | sonnet | `depth_edge_case_findings.md` |
| Depth 4 | depth-external | sonnet | `depth_external_findings.md` |
| Scanner A | Tokens & Parameters | sonnet | `blind_spot_a_findings.md` |
| Scanner B | Guards, Visibility & Inheritance | sonnet | `blind_spot_b_findings.md` |
| Scanner C | Role Lifecycle, Capability & Reachability | sonnet | `blind_spot_c_findings.md` |
| Validation Sweep | Cross-cutting validation | sonnet | `validation_sweep_findings.md` |

**Model diversity rule**: depth-token-flow and depth-state-trace use `model="opus"` (token flow tracing and state transition analysis require highest reasoning). All others use `model="sonnet"`.

### Niche Agents (flag-triggered)

Read `{SCRATCHPAD}/template_recommendations.md` -> `## Niche Agents` section. For each niche agent marked `Required: YES`:

1. Read its definition from `~/.claude/agents/skills/niche/{name}/SKILL.md`
2. Add to the spawn roster
3. Each niche agent = 1 depth budget slot
4. Model: sonnet
5. Output file: `niche_{name}_findings.md`

### Injectable Investigation Agents

Read `{SCRATCHPAD}/template_recommendations.md` -> `## Injectable Skills` section. Injectable skills are append-only methodology from `rules/skill-registry.json`: merge each injectable into its registered target depth roles, do not spawn dedicated injectable agents, do not allocate extra depth budget slots, and do not create injectable-specific output files.

### Design Stress Testing Agent (Thorough only, UNCONDITIONAL)

In Thorough mode, ALWAYS spawn a Design Stress Testing agent. 1 slot is pre-reserved and UNCONDITIONAL -- it runs regardless of remaining budget.

| Agent | Model | Output File |
|-------|-------|-------------|
| Design Stress Testing | sonnet | `design_stress_findings.md` |

### Sibling Propagation Agent

| Agent | Model | Output File |
|-------|-------|-------------|
| Sibling Propagation | sonnet | `sibling_propagation_findings.md` |

---

## Step 3: Build Agent Prompts

### Depth Agent Prompt Template

Each depth agent reads its role definition from `~/.claude/prompts/solana/phase4b-depth-templates.md` and its full methodology from `~/.claude/agents/depth-{role}.md`.

```
You are Depth Agent: {ROLE} (e.g., depth-token-flow).

## Your Role Definition
Read: ~/.claude/agents/depth-{role}.md

## Depth Methodology
Read: ~/.claude/prompts/solana/phase4b-depth-templates.md -- follow the {ROLE} section

## Protocol Context
Read: {SCRATCHPAD}/design_context.md

## Your Inputs
- {SCRATCHPAD}/findings_inventory.md (breadth findings -- your analysis targets)
- {SCRATCHPAD}/semantic_invariants.md (variable write sites and clusters)
- {SCRATCHPAD}/state_variables.md (all state variables)
- {SCRATCHPAD}/function_list.md (all functions)
- {SCRATCHPAD}/attack_surface.md (attack surface)
- Source files in scope

## INVARIANT CONSISTENCY CHECK (HARD GATE)
Before CONFIRMING any finding at Medium+ severity, check {SCRATCHPAD}/design_context.md Operational Implications section. If your finding contradicts a documented operational implication, you MUST explain the contradiction or downgrade to CONTESTED.

## Finding Format
Read and follow: ~/.claude/rules/finding-output-format.md
MANDATORY: Every finding MUST include at least one Depth Evidence tag: [BOUNDARY:X=val], [VARIATION:param A->B], or [TRACE:path->outcome]. A finding without any evidence tag is INCOMPLETE and will be flagged for re-analysis in iteration 2. Do not submit findings without tags.

## Chain Summary (MANDATORY)
At the end of your output, include a Chain Summary table for chain analysis:
| Finding ID | Preconditions (Missing) | Precondition Types | Postconditions (Created) | Postcondition Types | Cross-Domain Dependencies |

## Output
Write your output directly to {SCRATCHPAD}/{OUTPUT_FILE} using the Write tool.
Return ONLY a one-line summary: "DONE: {N} findings written to {OUTPUT_FILE}"
Do NOT return your full output as text -- the orchestrator's context budget is limited.

SCOPE: Write ONLY to your assigned output file. Do NOT read or write other agents' output files. Do NOT proceed to subsequent pipeline phases (chain analysis, verification, report). Return your findings and stop.
```

### Scanner Agent Prompt Template

Each scanner reads its checks from `~/.claude/prompts/solana/phase4b-scanner-templates.md`.

```
You are Blind Spot Scanner {LETTER}: {SCANNER_NAME}.

## Scanner Methodology
Read: ~/.claude/prompts/solana/phase4b-scanner-templates.md -- follow Scanner {LETTER} section

## Your Inputs
- {SCRATCHPAD}/findings_inventory.md
- {SCRATCHPAD}/state_variables.md
- {SCRATCHPAD}/function_list.md
- {SCRATCHPAD}/contract_inventory.md
- Source files in scope

## Finding Format
Read and follow: ~/.claude/rules/finding-output-format.md

## Output
Write your output directly to {SCRATCHPAD}/{OUTPUT_FILE} using the Write tool.
Return ONLY a one-line summary: "DONE: {N} findings written to {OUTPUT_FILE}"
Do NOT return your full output as text.

SCOPE: Write ONLY to your assigned output file. Do NOT read or write other agents' output files. Do NOT proceed to subsequent pipeline phases. Return your findings and stop.
```

### Validation Sweep Agent Prompt Template

```
You are the Validation Sweep Agent. You perform cross-cutting validation checks.

## Methodology
Read: ~/.claude/prompts/solana/phase4b-scanner-templates.md -- follow the Validation Sweep section

## Your Inputs
- {SCRATCHPAD}/findings_inventory.md
- {SCRATCHPAD}/semantic_invariants.md (if exists)
- {SCRATCHPAD}/state_variables.md
- Source files in scope

## Output
Write your output directly to {SCRATCHPAD}/validation_sweep_findings.md using the Write tool.
Return ONLY a one-line summary: "DONE: {N} findings written to validation_sweep_findings.md"
Do NOT return your full output as text.

SCOPE: Write ONLY to your assigned output file. Do NOT proceed to subsequent phases. Return your findings and stop.
```

### Niche Agent Prompt Template

```
You are Niche Agent: {NICHE_NAME}.

## Your Methodology
Read: ~/.claude/agents/skills/niche/{niche_name}/SKILL.md

## Your Inputs
- {SCRATCHPAD}/findings_inventory.md
- {SCRATCHPAD}/state_variables.md
- {SCRATCHPAD}/function_list.md
- Source files in scope

## Finding Format
Read and follow: ~/.claude/rules/finding-output-format.md

## Output
Write your output directly to {SCRATCHPAD}/niche_{niche_name}_findings.md using the Write tool.
Return ONLY a one-line summary: "DONE: {N} findings written to niche_{niche_name}_findings.md"
Do NOT return your full output as text.

SCOPE: Write ONLY to your assigned output file. Do NOT proceed to subsequent phases. Return your findings and stop.
```

### Design Stress Testing Agent (Thorough only)

```
You are the Design Stress Testing Agent. You stress-test the protocol's design limits and constraint coherence.

## Your Task
1. Identify all configurable parameters and their stated/implied valid ranges
2. For each parameter: what happens at the boundary of its valid range?
3. Check constraint coherence: do independently-settable parameters interact? Can valid values of A + valid values of B produce an invalid system state?
4. Check design limits: what is the maximum number of users/positions/iterations? What breaks first?
5. Check adequacy: are the design limits adequate for the stated use case?

## Your Inputs
- {SCRATCHPAD}/design_context.md
- {SCRATCHPAD}/state_variables.md
- {SCRATCHPAD}/findings_inventory.md
- Source files in scope

## Finding Format
Read and follow: ~/.claude/rules/finding-output-format.md
Use finding IDs: [DST-1], [DST-2], ...

## Output
Write your output directly to {SCRATCHPAD}/design_stress_findings.md using the Write tool.
Return ONLY a one-line summary: "DONE: {N} findings written to design_stress_findings.md"
Do NOT return your full output as text.

SCOPE: Write ONLY to your assigned output file. Do NOT proceed to subsequent phases. Return your findings and stop.
```

---

## Step 4: Spawn All Agents

**CRITICAL**: Spawn ALL iteration 1 agents in a SINGLE message as parallel Task calls. This includes:
- 4 depth agents
- 3 scanners
- 1 validation sweep
- N niche agents (from template_recommendations.md)
- Injectables appended to registered depth roles (0 extra agents)
- 1 design stress testing agent (Thorough only)
- 1 sibling propagation agent

Each agent is `subagent_type="general-purpose"` with the model specified in Step 2.

**Never spawn only a subset** -- if only 1 of N agents is spawned, it may complete the entire remaining pipeline solo, skipping the other N-1 agents' domains.

**ROSTER COMPLETENESS**: Spawn ALL agents listed in the roster above in a SINGLE message. Do not reason about whether each agent is needed — spawn them all. Every output file is required by downstream phases (chain analysis, verification, report). Spawn subagents simultaneously when fanning across independent analysis domains. You SHOULD use tools aggressively: Read source files, Grep for patterns, Glob for file discovery. Do not reason about code you haven't read.

---

## Step 5: Verify Artifacts

After ALL agents return, verify each expected output file:

```bash
for file in \
  depth_token_flow_findings.md \
  depth_state_trace_findings.md \
  depth_edge_case_findings.md \
  depth_external_findings.md \
  blind_spot_a_findings.md \
  blind_spot_b_findings.md \
  blind_spot_c_findings.md \
  validation_sweep_findings.md \
  ; do
  FILE="{SCRATCHPAD}/$file"
  if [ -f "$FILE" ] && [ "$(wc -c < "$FILE")" -gt 100 ]; then
    echo "[VERIFY OK] $FILE ($(wc -l < "$FILE") lines)"
  else
    echo "[VERIFY FAIL] $FILE missing or empty"
  fi
done
```

Also verify niche agent outputs and design_stress_findings.md (Thorough). Injectable methodology is part of the normal depth outputs.

If ANY required file is missing:
1. Re-spawn the responsible agent
2. If re-spawn fails: prompt the agent to return full output as text, then write it manually
3. Log failures to `{SCRATCHPAD}/violations.md`

---

## Step 6: Write Phase 4b Manifest

Write `{SCRATCHPAD}/phase4b_manifest.md`:

```markdown
# Phase 4b Manifest

## Iteration 1 Agents Spawned
| Agent | Model | Output File | Status |
|-------|-------|-------------|--------|

## Niche Agents
| Name | Trigger | Output File | Status |

## Budget
- Total depth spawns: {N}
- Budget used: {N}
- Budget remaining: {R}

## Next Step
- If MODE == light: proceed to Phase 4c (no scoring)
- If MODE == core: proceed to confidence scoring (2-axis)
- If MODE == thorough: proceed to confidence scoring (4-axis), then iteration 2 if uncertain Medium+ exist
```

---

## THOROUGH CHECKPOINT: Pre-Depth Fuzz Campaigns

When `{MODE}` is `thorough`, run these BEFORE spawning depth agents:

### Invariant Fuzz Campaign (MANDATORY, zero budget cost)
Read template: `~/.claude/prompts/solana/phase4b-invariant-fuzz.md`
Spawn agent. Await completion. Results written to `{SCRATCHPAD}/invariant_fuzz_results.md`.
The template has a 5-minute timeout built in.

### Trident Campaign (if trident_available, zero budget cost)
Read Trident section from `~/.claude/prompts/solana/phase4b-loop.md`.
Spawn agent IN PARALLEL with the invariant fuzz agent. Await completion.
Results written to `{SCRATCHPAD}/trident_fuzz_findings.md`.
If `trident_available: false` in build_status.md, skip and log `TRIDENT_UNAVAILABLE`.

### Assert Completion
```
ASSERT: invariant_fuzz_results.md exists (or COMPILATION_FAILED logged)
ASSERT: trident_fuzz_findings.md exists (or TRIDENT_UNAVAILABLE logged)
IF either missing AND no failure logged -> log VIOLATION to violations.md
```

After all agents return, verify output files exist on disk and stop.
