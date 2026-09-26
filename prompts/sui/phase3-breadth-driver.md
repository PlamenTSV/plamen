---
description: "Phase 3: Breadth Analysis Driver -- spawns parallel breadth agents for Sui audits"
---

# Phase 3: Parallel Breadth Analysis (Sui)

This prompt tells the `claude -p` session how to spawn breadth agents. The session reads instantiation data, spawns agents via the Agent tool, waits for them, and verifies artifacts.

---

## Step 1: Read Instantiation Data

Read the following files to understand what to spawn:

- `{SCRATCHPAD}/template_recommendations.md` -- BINDING MANIFEST with required templates and flags
- `{SCRATCHPAD}/design_context.md` -- protocol context (first 50 lines for brief)
- `{SCRATCHPAD}/attack_surface.md` -- attack surface areas
- `{SCRATCHPAD}/recon_summary.md` -- themes and risk areas
- `{SCRATCHPAD}/spawn_manifest.md` -- planned agent roster (written by Phase 2 or the Python driver)

---

## Step 2: Determine Agent Count

| Condition | Agent Count |
|-----------|-------------|
| Simple (<5 deps, <2000 lines) | 3 agents |
| Medium (5-10 deps, 2000-5000 lines) | 5-7 agents |
| Complex (>10 deps or >5000 lines) | 7-9 agents |

**Minimum always**: 1 core state, 1 access control, 1 per major external dependency.

**Light mode override**: Cap at 3-4 sonnet agents. Use `model="sonnet"` for all.
**Core/Thorough**: Use `model="opus"` for all breadth agents.

---

## Step 3: Template Instantiation

For each template in `template_recommendations.md` marked `Required: YES`:
1. Read the skill file from `~/.claude/agents/skills/sui/{template-name}/SKILL.md` (folder name is lowercase-hyphenated)
2. Replace `{PLACEHOLDERS}` with instantiation parameters from `template_recommendations.md`
3. Strip sections wrapped in `<!-- LOAD_IF: FLAG -->...<!-- END_LOAD_IF: FLAG -->` when the flag was NOT detected

### Merge Hierarchy (when templates exceed target agent count)

| Priority | Merge | Rationale |
|----------|-------|-----------|
| M1 | TEMPORAL_PARAMETER_STALENESS + core state agent | Cached params are state mutations |
| M2 | SEMI_TRUSTED_ROLES + access control agent | Roles are access control |
| M3 | SHARE_ALLOCATION_FAIRNESS + core state agent | Allocation fairness is state correctness |
| M4 | ECONOMIC_DESIGN_AUDIT + core state agent | Monetary params are state correctness |
| M5 | EXTERNAL_PRECONDITION_AUDIT + external dependency agent | External preconditions are external dep analysis |

**Merge rules**:
- Never merge two skills both requiring >5 analysis steps
- Never merge across incompatible domains
- **Never merge FLASH_LOAN_INTERACTION or ORACLE_ANALYSIS with any other skill**
- **Max 2 templates per agent AND max 300 combined SKILL.md lines**
- If a 2-template merge would exceed 300 lines, split into an additional breadth agent

### Move-Safety Agent (Sui only)

The 4 always-required skills (ABILITY_ANALYSIS, BIT_SHIFT_SAFETY, TYPE_SAFETY, OBJECT_OWNERSHIP) total ~900-950 lines — exceeding the 300-line breadth agent cap. Split delivery:

1. **Core directives** (~130 lines): Load `~/.claude/agents/skills/sui/move-safety-core-directives/SKILL.md` into EVERY breadth agent. Counts toward the 300-line cap.
2. **Move-Safety Agent** (1 dedicated agent): Spawn alongside breadth agents. Loads ALL 4 full skill files (~950 lines). Costs 1 breadth agent slot. Output: `analysis_move_safety.md`.

### Merge Cap Enforcement (MANDATORY)

Before composing any agent prompt, verify the 300-line cap mechanically:

```bash
for each planned agent:
  combined_lines = 0
  for each SKILL.md assigned:
    wc -l ~/.claude/agents/skills/sui/{skill-name}/SKILL.md
    combined_lines += result
  ASSERT: combined_lines <= 300
  If FAIL: split the largest skill into its own dedicated agent
```

### Injectable Skill Delivery (Split)

For injectable skills from `template_recommendations.md` -> `## Injectable Skills`:
- **Breadth agents**: Extract ONLY section headers + key questions (1-line per section, ~200 tokens max)
- **Depth agents (Phase 4b)**: Full injectable investigation via dedicated agents (handled in phase4b-depth-driver)

---

## Step 4: Compose Agent Prompts

Each breadth agent prompt follows this structure:

```
You are Analysis Agent #{N}: {FOCUS_AREA}

## Protocol Context
{Brief from design_context.md -- first 30-50 lines only}

## Your Analysis Task
{INSTANTIATED_TEMPLATE -- the skill methodology with placeholders replaced}

## Analysis Strategy -- Targeted Sweeps
Do NOT attempt to find all vulnerability types in a single pass.
Instead, for each vulnerability class in your methodology:
1. Sweep the ENTIRE scope for THIS class specifically
2. Write findings for this class before moving on
3. Proceed to the next vulnerability class

## Artifacts Available
- {SCRATCHPAD}/design_context.md (protocol design)
- {SCRATCHPAD}/attack_surface.md (attack surface)
- {SCRATCHPAD}/state_variables.md (state variables)
- {SCRATCHPAD}/function_list.md (all functions)
- {SCRATCHPAD}/contract_inventory.md (contract list)
- {SCRATCHPAD}/meta_buffer.md (historical vulnerability patterns)
- Source files in scope

## Finding Format
Read and follow: ~/.claude/rules/finding-output-format.md

## Output Requirements
Write your output directly to {SCRATCHPAD}/analysis_{focus_area}.md using the Write tool.
Return ONLY a one-line summary: "DONE: {N} findings written to analysis_{focus_area}.md"
Do NOT return your full output as text -- the orchestrator's context budget is limited.

Use finding IDs: [{PREFIX}-1], [{PREFIX}-2]...

SCOPE: Write ONLY to your assigned output file. Do NOT read or write other agents' output files. Do NOT proceed to subsequent pipeline phases (chain analysis, verification, report). Return your findings and stop.
```

### MCP Timeout Directive (for agents making MCP calls)

If an agent makes MCP tool calls, append to its prompt:

```
When an MCP tool call returns a timeout error or fails, do NOT retry the same call. Record [MCP: TIMEOUT] and skip ALL remaining calls to that provider -- switch immediately to fallback (code analysis, grep, WebSearch).
```

---

## Step 5: Spawn All Agents

**CRITICAL**: Spawn ALL breadth agents in a SINGLE message as parallel Task calls. Each agent is `subagent_type="general-purpose"`.

**ROSTER COMPLETENESS**: You MUST spawn exactly the number of agents determined in Step 2. Do not consolidate, skip, or handle analysis yourself. Your role is orchestration — spawn agents and verify artifacts. If you believe fewer agents would suffice, spawn them all anyway. Missing output files cause gate failures, retries, and lost coverage. Spawn subagents simultaneously — they are independent analysis domains.

Model selection:
- **Light**: `model="sonnet"` for all
- **Core/Thorough**: `model="opus"` for all

---

## Step 6: Verify Artifacts

After ALL agents return:

1. Check each expected output file exists and is non-empty:
```bash
for file in {SCRATCHPAD}/analysis_*.md; do
  if [ -f "$file" ] && [ "$(wc -c < "$file")" -gt 100 ]; then
    echo "[VERIFY OK] $file ($(wc -l < "$file") lines)"
  else
    echo "[VERIFY FAIL] $file missing or empty"
  fi
done
```

2. For each REQUIRED template in `spawn_manifest.md`, verify its corresponding `analysis_{focus_area}.md` exists and contains findings.

3. If ANY required file is missing or empty:
   - Re-spawn that specific agent with the same prompt
   - If re-spawn fails: prompt the agent to return its full output as text, then write it manually

4. Update `spawn_manifest.md` with completion status for each agent.

5. Do NOT read analysis files at this point -- the Phase 4a inventory agent reads them.

---

## Step 7: Overreach Detection

If any breadth agent wrote files outside the expected `analysis_*.md` pattern (e.g., inventory, depth, chain, verify, or report files):
- Treat those files as invalid for sequencing purposes
- Record a violation in `{SCRATCHPAD}/violations.md`
- Continue the pipeline using only valid `analysis_*` outputs

After all agents return, verify output files exist on disk and stop.
