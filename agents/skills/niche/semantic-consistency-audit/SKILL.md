---
name: "semantic-consistency-audit"
description: "Trigger HAS_MULTI_CONTRACT flag in template_recommendations.md (recon detects 2+ in-scope contracts/modules sharing parameters or formulas) - Agent Type general-purpose (standal..."
---

# Niche Agent: Semantic Consistency Audit

> **Trigger**: `HAS_MULTI_CONTRACT` flag in `template_recommendations.md` (recon detects 2+ in-scope contracts/modules sharing parameters or formulas)
> **Agent Type**: `general-purpose` (standalone niche agent, NOT injected into another agent)
> **Budget**: 1 depth budget slot in Phase 4b iteration 1
> **Finding prefix**: `[SC-N]`
> **Added in**: v1.1

## When This Agent Spawns

Recon Agent 3 (Patterns + Surface + Templates) produces `contract_inventory.md` and `constraint_variables.md`.
If `contract_inventory.md` lists 2+ in-scope contracts/modules AND `constraint_variables.md` shows parameters or formulas appearing in multiple contracts (same variable name, same constant, or same formula pattern), recon sets `HAS_MULTI_CONTRACT` flag in the BINDING MANIFEST.

The orchestrator spawns this agent in Phase 4b iteration 1 alongside the 8 standard agents (counts as 1 budget slot).

## Agent Prompt Template

```
Task(subagent_type="general-purpose", prompt="
You are the Semantic Consistency Agent. You audit cross-contract consistency of config variables, formulas, and magic numbers.

## Your Inputs
Read:
- {SCRATCHPAD}/constraint_variables.md (all constraint/config variables with setters)
- {SCRATCHPAD}/contract_inventory.md (all contracts/modules in scope)
- {SCRATCHPAD}/state_variables.md (all state variables)
- {SCRATCHPAD}/function_list.md (all functions)
- Source files in scope

## Your Task

### CHECK 1: Config Variable Unit Consistency

For EVERY config variable that appears in 2+ contracts/modules (same name or same semantic role - e.g., `feeRate`, `maxDelay`, `precision`):

1. **Extract usage context**: In each contract, how is the variable used in arithmetic? What unit does the surrounding math assume? (e.g., BPS vs WAD vs percentage vs seconds vs blocks)
2. **Compare units**: Do all contracts agree on the unit?
3. **Check setter constraints**: If the variable is set by a shared admin function, do all consumers interpret the value identically?

| Variable | Contract A | Unit in A | Contract B | Unit in B | Match? | Finding? |
|----------|-----------|-----------|-----------|-----------|--------|----------|

**Finding criteria**: If Contract A treats `feeRate` as BPS (divide by 10000) but Contract B treats it as WAD (divide by 1e18), the same setter value produces wildly different behavior. This is a semantic unit mismatch - severity Medium minimum if it affects fund calculations.

### CHECK 2: Formula Semantic Drift

For EVERY formula pattern that appears in 2+ locations (copy-pasted or structurally similar arithmetic):

1. **Identify formula pairs**: Find functions with structurally similar arithmetic (same operators, same variable roles) across different contracts or within the same contract for different operations
2. **Compare semantics**: Do the formulas compute the same concept? Or has one been adapted with altered semantics?
3. **Check for silent divergence**: Does one formula handle edge cases (zero, overflow, rounding direction) differently from its sibling?

| Formula Pattern | Location A | Location B | Same Semantics? | Divergence | Finding? |
|----------------|-----------|-----------|-----------------|------------|----------|

**Finding criteria**: If `calculateReward()` in Contract A rounds down but the structurally identical `calculateReward()` in Contract B rounds up, users can arbitrage the difference. If one handles zero-input gracefully but the other reverts, there is an inconsistency that may cause DoS. Severity depends on whether the divergence affects fund flows (Medium+) or only view functions (Low).

### CHECK 3: Magic Number Consistency

For EVERY magic number (literal constant not assigned to a named constant - e.g., `10000`, `1e18`, `86400`, `365`):

1. **Catalog all magic numbers**: Find all numeric literals used in arithmetic across all in-scope contracts. Exclude obvious safe cases (0, 1, 2 used for simple conditions).
2. **Group by semantic role**: Which magic numbers represent the same concept? (e.g., multiple `10000` for BPS denominator, multiple `1e18` for WAD precision)
3. **Check consistency within each group**: Do all instances use the same value for the same concept?
4. **Check for drift**: Has a magic number been updated in one location but not another? (e.g., fee denominator changed from `10000` to `1000000` in Contract A but not Contract B)

| Magic Number | Semantic Role | Locations | Consistent? | Finding? |
|-------------|--------------|-----------|-------------|----------|

**Finding criteria**: If the BPS denominator is `10000` in 3 locations but `100000` in a 4th (typo or intentional change that wasn't propagated), this is a consistency bug. Severity: High if it affects fund calculations by 10x+, Medium if smaller impact, Low if view-only.

## Output Format

Use standard finding format with [SC-N] IDs.

For each finding, include:
- **Consistency Type**: UNIT_MISMATCH / FORMULA_DRIFT / MAGIC_NUMBER_DRIFT
- Both (or all) locations with code snippets showing the inconsistency
- Concrete example of how the inconsistency manifests (e.g., 'Setting feeRate=100 means 1% in Contract A but 0.00001% in Contract B')

## Chain Summary (MANDATORY)
| Finding ID | Location | Root Cause (1-line) | Verdict | Severity | Precondition Type | Postcondition Type |

Write to {SCRATCHPAD}/niche_semantic_consistency_findings.md

Return: 'DONE: {N} consistency issues found - {U} unit mismatches, {F} formula drifts, {M} magic number inconsistencies'
")
```

## Why Niche Agent (Not Scanner Sub-Check)

- Cross-contract consistency requires reading and comparing multiple files simultaneously - scanner sub-checks operate within a single pass
- Unit mismatch detection requires understanding arithmetic context (what does `/ 10000` mean here?) - not a simple grep pattern
- Formula drift detection requires structural comparison of code blocks across contracts - exceeds scanner complexity budget
- The concern is protocol-agnostic: applies to any multi-contract system regardless of chain (EVM, Solana, Aptos, Sui)
