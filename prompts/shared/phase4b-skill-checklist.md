---
description: "Phase 4b: Skill Execution Checklist (Thorough only) -- verify depth agents executed loaded skills"
---

# Phase 4b: Skill Execution Checklist

> **Efficiency**: This is a mechanical verification task. Check step completion directly without re-analyzing findings.
> **Mode gate**: Thorough mode only. Skip in Light and Core.
> **Trigger**: Runs after depth iteration 1 completes, before iteration 2.
> **Budget**: 1 haiku agent (not counted against depth budget).
> **Purpose**: Identify gaps where depth agents were assigned skills but did not show evidence of executing them. Gaps become investigation questions for iteration 2 DA agents.

---

## Agent

**Model**: haiku (mechanical verification task)

```
Task(subagent_type="general-purpose", model="haiku", prompt="
You are the Skill Execution Checklist Agent. You verify that depth agents executed the methodology steps from their assigned skills.

## Your Inputs
Read (in order):
- **{SCRATCHPAD}/step_execution_gaps_mechanical.md** (driver-aggregated
  mechanical gap list from digest-bound rows embedded in each assigned depth
  findings artifact). **If this file lists `no`, `partial`, or `unknown` gaps,
  those gaps are authoritative — do not upgrade them from findings prose.** An
  `agent-trace` UNKNOWN requires rerunning the original assigned role
  methodology and injected skills; it is not evidence that any step closed.
- {SCRATCHPAD}/template_recommendations.md (lists which skills were loaded into which agents)
- {SCRATCHPAD}/depth_*_findings.md (all depth agent outputs)
- {SCRATCHPAD}/step_execution_trace_*.md (per-agent traces — only needed if mechanical aggregate is missing or you need supporting context)
- {SCRATCHPAD}/blind_spot_*_findings.md or scanner_*_findings.md (scanner outputs)
- {SCRATCHPAD}/validation_sweep_findings.md or scanner_validation_findings.md
- {SCRATCHPAD}/niche_*_findings.md (if any exist)

## Your Task

**If `step_execution_gaps_mechanical.md` is present and non-empty** (v2.2.0+ runs):
1. Take its rows as the canonical gap list. Do NOT second-guess Executed=yes rows in the source traces.
2. For each row, formulate a specific investigation question for iteration 2 DA agents — the question must name the file(s) and the specific check the (skill, step) requires.
3. Add coverage for any depth/scanner/niche agent that has findings but no trace file (legacy or pre-v2.2.0 outputs) by re-inferring from finding content per the legacy steps below.

**Legacy path** (only when mechanical aggregate is absent or empty AND there exist agents-with-findings-but-no-trace):

For each skill listed in template_recommendations.md as loaded into a depth/scanner agent:

1. **Identify the skill's key methodology steps**: Read the skill name and recall its core analysis steps (e.g., ORACLE_ANALYSIS requires staleness check, decimal verification, zero-price handling, failure mode analysis).

2. **Search agent output for evidence**: In the assigned agent's output file, look for:
   - Explicit mention of the skill's analysis steps
   - Findings that reference the skill's domain
   - Evidence tags that correspond to the skill's methodology
   - Code references in the skill's target area

3. **Classify execution**:
   - EXECUTED: Agent output shows clear evidence of following the skill methodology
   - PARTIAL: Some steps executed, others missing
   - NOT_EXECUTED: No evidence the skill methodology was applied
   - N/A: Skill's trigger conditions were not met in the codebase

4. **For PARTIAL and NOT_EXECUTED**: Formulate a specific investigation question for iteration 2 DA agents. The question should target what was NOT analyzed.

## Output

Write to {SCRATCHPAD}/skill_execution_gaps.md:

### Execution Summary
| Skill | Assigned Agent | Execution Status | Evidence | Gap Description |

### Investigation Questions for Iteration 2
| Gap # | Skill | Missing Step | Investigation Question | Target Files |

Write your output directly to {SCRATCHPAD}/skill_execution_gaps.md using the Write tool.
Return ONLY a one-line summary: 'DONE: {T} skills checked -- {E} executed, {P} partial, {N} not_executed, {G} investigation questions generated'
Do NOT return your full output as text.
")
```

After the agent returns, verify `{SCRATCHPAD}/skill_execution_gaps.md` exists on disk.

Write your output to {SCRATCHPAD}/skill_execution_gaps.md and stop.
