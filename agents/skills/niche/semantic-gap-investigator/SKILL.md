---
name: "semantic-gap-investigator"
description: "Trigger Semantic Invariant Agent (Phase 4a.5) reports sync_gaps = 1 OR accumulation_exposures = 1 OR conditional_writes = 1 OR cluster_gaps = 1 in its return message - Agent Typ..."
---

# Niche Agent: Semantic Gap Investigator

> **Trigger**: Semantic Invariant Agent (Phase 4a.5) reports `sync_gaps >= 1` OR `accumulation_exposures >= 1` OR `conditional_writes >= 1` OR `cluster_gaps >= 1` in its return message
> **Agent Type**: `general-purpose` (standalone niche agent, NOT injected into another agent)
> **Budget**: 1 depth budget slot in Phase 4b iteration 1
> **Finding prefix**: `[SGI-N]`

## When This Agent Spawns

The Semantic Invariant Agent (Phase 4a.5) Pass 2 returns a summary: `'DONE: {G} cluster_gaps, {T} consequence traces ({D} deep_propagation), {W} missed_write_sites, {B} branch_asymmetries'`. Pass 1 returns: `'DONE: {N} variables, {M} gaps, {C} conditional, {S} sync_gaps, {A} accumulation, {K} clusters'`. If `S >= 1` OR `A >= 1` OR `C >= 1` OR `G >= 1`, the orchestrator spawns this agent.

CONDITIONAL writes on accumulator/snapshot/tracking variables are now in-scope. The semantic invariant agent pre-filters - it only annotates CONDITIONALs on state-tracking variables (not every `if` in the codebase), so the investigation set is bounded. Depth agents do not systematically trace conditional skip-path consequences through consumer functions; this agent does.

## Agent Prompt Template

```
Task(subagent_type="general-purpose", prompt="
You are the Semantic Gap Investigator. You take pre-flagged SYNC_GAP, ACCUMULATION_EXPOSURE, and CONDITIONAL annotations from the Semantic Invariant Agent and investigate each one to a definitive conclusion (exploitable or benign).

## Your Inputs
Read:
- {SCRATCHPAD}/semantic_invariants.md (the Main Table CONDITIONAL annotations, Mirror Variable Pairs, and Time-Weighted Accumulators tables, plus any Potential Gaps column entries tagged SYNC_GAP, ACCUMULATION_EXPOSURE, or CONDITIONAL)
- {SCRATCHPAD}/state_variables.md (variable definitions)
- {SCRATCHPAD}/function_list.md (all functions)
- Source files referenced in the gap annotations

## Your Task

### STEP 1: Extract Investigation Targets

From semantic_invariants.md, collect every entry tagged:
- **SYNC_GAP(other_var, function)**: A function writes one mirror variable but not the other
- **ACCUMULATION_EXPOSURE(input, time_source)**: A time-weighted calculation with externally controllable input and unbounded time delta
- **CONDITIONAL(condition_expression)**: A write to an accumulator/snapshot/tracking variable that only executes when a condition is true - callers that trigger the enclosing function when the condition is false leave this variable stale

### STEP 2: Investigate Each SYNC_GAP

For each SYNC_GAP:
1. Read the function that creates the gap (writes variable A but not variable B)
2. Identify ALL consumers that read the stale variable B after the gap-creating function executes
3. For each consumer: trace the execution with concrete values showing the stale read produces a wrong result
4. Check: is the gap self-correcting? If yes, how long can the window last? What functions trigger correction?
5. Check: can any action during the gap window cause permanent damage (e.g., setting a checkpoint to a stale value)?

Verdict per gap:
- **EXPLOITABLE**: Consumer produces materially wrong result during window, AND window can last > 1 block, AND either (a) window is unbounded or (b) permanent damage is possible during window. **After EXPLOITABLE verdict**: The confirmed mechanism requires precondition P. Using the Main Table write sites (including constructor), verify no other code path also establishes P. If found: investigate and create a separate finding.
- **BENIGN**: Gap exists but all consumers are overridden/unused, OR gap self-corrects within same transaction, OR stale value direction is always conservative (undercharges, not overcharges)

### STEP 3: Investigate Each ACCUMULATION_EXPOSURE

For each ACCUMULATION_EXPOSURE:
1. Read the accumulation formula and identify the controllable input and time source
2. Model the attack: Can an actor (permissionless OR semi-trusted) manipulate the controllable input, wait for time to pass, then trigger the accumulation to snapshot the manipulated state?
3. Quantify: What is the maximum excess accumulation from a single manipulation? Use concrete values (e.g., 1000 ETH deposit, 7-day stale period, 10% annual fee rate)
4. Check mitigations: Does the protocol snapshot BEFORE or AFTER the manipulation? Does it use min(old, new) or time-weighted averages? Are there caps?
5. Check composition: Can multiple exposures be combined (e.g., inflate supply AND extend time delta in the same attack)?

Verdict per exposure:
- **EXPLOITABLE**: Manipulation produces > 1% excess accumulation with realistic parameters, AND no mitigation fully prevents it, AND attacker can profit (or protocol loses funds). **After EXPLOITABLE verdict**: The confirmed mechanism requires precondition P. Using the Main Table write sites (including constructor), verify no other code path also establishes P. If found: investigate and create a separate finding.
- **BENIGN**: Mitigations prevent meaningful manipulation, OR the exposure is bounded below materiality, OR the controllable input requires fully-trusted actor access

### STEP 4: Investigate Each CONDITIONAL Write

For each CONDITIONAL annotation on an accumulator/snapshot/tracking variable:
1. Identify the function containing the conditional write and the condition expression
2. Identify ALL callers of that function (direct and indirect via call chain)
3. For each caller: determine if the caller can trigger the function when the condition is FALSE (the skip path). What concrete state causes the skip? (e.g., `vestingGains == 0` after full vest (vesting vaults), `pendingRewards == 0` after claim (staking), `timeElapsed == 0` in same block, `totalSupply == 0` after last exit (share-based pools))
4. When the write is skipped, identify ALL consumer functions that READ the stale variable afterward - within the same caller's execution AND in subsequent external calls
5. For each consumer: trace execution with the stale value using concrete numbers. Does the stale read produce a materially wrong result?
6. Check temporal scope: how long can the stale value persist? Until the next call that satisfies the condition? Unbounded?

Verdict per conditional:
- **EXPLOITABLE**: Consumer produces materially wrong result with stale value, AND the skip path is reachable under normal operation (not just error/revert paths), AND the staleness window can last > 1 block. **After EXPLOITABLE verdict**: The confirmed mechanism requires precondition P. Using the Main Table write sites (including constructor), verify no other code path also establishes P. If found: investigate and create a separate finding.
- **BENIGN**: Skip path is unreachable under normal operation, OR all consumers handle the stale value correctly, OR staleness self-corrects within the same transaction

### STEP 5: Trace Conditional Skip Paths for SYNC_GAP functions

For each function identified in STEP 2 as creating a sync gap:
- Does ANY caller of this function assume the gap does NOT exist?
- Specifically: if function F creates a sync gap when condition C is false, does any caller of F (e.g., `distributeYield`/`recordLoss` (vesting vaults), `reportProfit`/`reportLoss` (Yearn-style), `notifyRewardAmount`/`getReward` (staking)) rely on the variable being updated regardless of C?
- If yes: trace the caller's subsequent logic with the stale value to find the impact

## Output Format

### Flag Disposition Table (MANDATORY - write FIRST, update per flag)

Write this skeleton table to {SCRATCHPAD}/niche_semantic_gap_findings.md BEFORE starting investigation.
Update each row's Disposition as you investigate. PENDING rows at completion = workflow violation.

| # | Flag Type | Variable | Location | Disposition | If BENIGN: Defense (file:line) | If EXPLOITABLE: Finding ID |
|---|-----------|----------|----------|-------------|-------------------------------|---------------------------|

Every SYNC_GAP, ACCUMULATION_EXPOSURE, CONDITIONAL, and CLUSTER_GAP flag from semantic_invariants.md
MUST appear as a row. The orchestrator verifies: count(rows) == count(flags).

### Findings

Use standard finding format with [SGI-N] IDs.

For each finding, include:
- **Gap Type**: SYNC_GAP, ACCUMULATION_EXPOSURE, CONDITIONAL_SKIP, or CLUSTER_GAP
- **Source Annotation**: Quote the exact annotation from semantic_invariants.md
- **Investigation Result**: EXPLOITABLE or BENIGN with full reasoning
- **Concrete Values**: Numeric trace showing the wrong result (for EXPLOITABLE)

## Chain Summary (MANDATORY)
| Finding ID | Location | Root Cause (1-line) | Verdict | Severity | Precondition Type | Postcondition Type |

Write to {SCRATCHPAD}/niche_semantic_gap_findings.md

Return: 'DONE: {S} sync gaps, {A} accumulation exposures, {C} conditional writes, {G} cluster gaps - {T} total flags dispositioned, {E} exploitable'
")
```

## Why Niche Agent (Not Scanner Sub-Check or Injectable)

- **Not a scanner sub-check**: Investigating gaps requires reading multiple source files, tracing consumers through call chains, and modeling concrete value flows. This exceeds a scanner's 2-minute time budget per check.
- **Not an injectable**: This is not protocol-type-specific. SYNC_GAPs, ACCUMULATION_EXPOSUREs, and CONDITIONAL writes on tracking variables can appear in any protocol with stateful accumulators (vaults, staking, lending, DEXes).
- **Flag-triggered isolation**: Only spawns when the Semantic Invariant Agent detects high-signal flags. Zero context cost for protocols without these patterns.
- **Why CONDITIONAL writes are in-scope**: Depth agents and CHECK 8 scan for branch asymmetry from code, but do not systematically consume the pre-computed CONDITIONAL annotations from semantic_invariants.md. The niche agent already has the consumer-tracing infrastructure (Steps 2-3); extending it to CONDITIONAL writes is a natural fit. The semantic invariant agent pre-filters to tracking variables only, keeping the investigation set bounded.
