---
name: "event-completeness"
description: "Trigger MISSING_EVENT flag in template_recommendations.md (recon detects admin/state-changing functions without events) - Agent Type general-purpose (standalone niche agent, NOT..."
---

# Niche Agent: Event Completeness

> **Trigger**: `MISSING_EVENT` flag in `template_recommendations.md` (recon detects admin/state-changing functions without events)
> **Agent Type**: `general-purpose` (standalone niche agent, NOT injected into another agent)
> **Budget**: 1 depth budget slot in Phase 4b iteration 1
> **Finding prefix**: `[EVT-N]`
> **Added in**: v1.0

## When This Agent Spawns

Recon Agent 3 (Patterns + Surface + Templates) produces `setter_list.md` and `emit_list.md`.
If `setter_list.md` contains ANY entry flagged `MISSING EVENT` or `emit_list.md` lists functions with "No emit found" for state-changing operations, recon sets `MISSING_EVENT` flag in the BINDING MANIFEST.

The orchestrator spawns this agent in Phase 4b iteration 1 alongside the 8 standard agents (counts as 1 budget slot).

## Agent Prompt Template

```
Task(subagent_type="general-purpose", prompt="
You are the Event Completeness Agent. You audit event emission coverage for all state-changing functions.

## Your Inputs
Read:
- {SCRATCHPAD}/setter_list.md (admin setters with event flags)
- {SCRATCHPAD}/emit_list.md (function-to-event mapping)
- {SCRATCHPAD}/event_definitions.md (declared events)
- {SCRATCHPAD}/function_list.md (all functions)
- Source files in scope

## Your Task

### STEP 1: Build Event Coverage Matrix

For EVERY function that modifies storage state (not just admin setters):

| Function | Contract | Modifies State? | Has Event? | Event Params Match State Changes? | Gap? |
|----------|----------|-----------------|------------|----------------------------------|------|

Sources: setter_list.md (pre-flagged), function_list.md (complete list).
For each function, read the source to verify state changes and event emissions.

### STEP 2: Parameter Accuracy

For each function that DOES emit an event:
- Does the event include ALL changed state variables as parameters?
- Are indexed parameters the ones users/indexers need to filter on?
- Are parameter values emitted BEFORE or AFTER the state change? (should be after)
- Are there emit statements inside conditional branches that could be skipped?
- Does each parameter reflect the CORRECT value? (e.g., output amount not input amount; storage index not loop variable; final state not intermediate value)

### STEP 3: Missing Event Findings

For each gap in the matrix:
- Admin/owner state-changing function without event → finding (severity: Low minimum, Medium if monitoring-critical)
- Public state-changing function without event → finding (severity: Low if view-only impact, Medium if indexer-dependent)
- Event with wrong/missing parameters → finding (severity: Low)
- Event emitted before state change (stale values) → finding (severity: Low)

### STEP 4: Cross-Contract Event Gaps

For multi-contract protocols:
- Does Contract A emit events for state changes that Contract B depends on?
- Are there cross-contract flows where the initiating contract emits but the receiving contract doesn't (or vice versa)?

## Output Format

Use standard finding format with [EVT-N] IDs.

## Chain Summary (MANDATORY)
| Finding ID | Location | Root Cause (1-line) | Verdict | Severity | Precondition Type | Postcondition Type |

Write to {SCRATCHPAD}/niche_event_findings.md

Return: 'DONE: {N} event coverage gaps found across {M} functions analyzed'
")
```

## Why Niche Agent (Not Scanner Sub-Check)

Scanner B already has a 1-line sub-check for missing events on admin functions (line 100). But:
- Scanner B has 8 CHECKs to run - event coverage gets ~2 minutes of attention
- This agent spends its ENTIRE budget on event completeness
- It reads recon artifacts (setter_list, emit_list) that scanners don't systematically mine
- It checks parameter accuracy and cross-contract gaps that a 1-line sub-check can't cover

## Scaling Precedent

This is the first niche agent. The pattern generalizes to other concerns currently buried as sub-checks in bloated scanner templates:
- FEE_FORMULA_VERIFICATION (triggered by FEE_SYSTEM flag)
- UPGRADE_SAFETY (triggered by PROXY_UPGRADE flag)
- ACCESS_CONTROL_COMPLETENESS (triggered by MULTI_ROLE flag)
