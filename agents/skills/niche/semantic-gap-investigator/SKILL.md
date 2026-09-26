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
You are the Semantic Gap Investigator. You take pre-flagged SYNC_GAP, ACCUMULATION_EXPOSURE, and CONDITIONAL annotations from the Semantic Invariant Agent and investigate each one to an exact producer state: CANDIDATE, REFUTATION_PROPOSAL, or UNRESOLVED.

## Your Inputs
Read:
- {SCRATCHPAD}/semantic_invariants.md (the Main Table CONDITIONAL annotations, Mirror Variable Pairs, and Time-Weighted Accumulators tables, plus any Potential Gaps column entries tagged SYNC_GAP, ACCUMULATION_EXPOSURE, or CONDITIONAL)
- {SCRATCHPAD}/state_variables.md (variable definitions)
- {SCRATCHPAD}/function_list.md (all functions)
- Source files referenced in the gap annotations

## Processing Protocol (MANDATORY)

For each analysis step below, execute in order:
1. **ENUMERATE targets**: List every entity the step applies to (gaps, variables, functions) as a numbered list before analysis begins.
2. **PROCESS exhaustively**: Analyze each numbered entity. Mark each "DONE" or "N/A (reason)" before moving to the next.
3. **COVERAGE GATE**: Count enumerated vs processed. If any entity lacks a marker, process it before proceeding to the next step.

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

Analysis conclusion per gap:
- **CANDIDATE**: Consumer produces materially wrong result during window, AND window can last > 1 block, AND either (a) window is unbounded or (b) permanent damage is possible during window. Emit the corresponding standard finding block using the same allocated SGI-N ID and a positive finding verdict allowed by `finding-output-format.md`. The confirmed mechanism requires precondition P. Using the Main Table write sites (including constructor), verify no other code path also establishes P. If found: investigate it under a new SGI-N ID.
- **REFUTATION_PROPOSAL**: Current evidence supports that all consumers are overridden/unused, the gap self-corrects within the same transaction, or the stale-value direction is always conservative. This is a producer proposal, never terminal BENIGN/SAFE closure. Include the committed-invariant material required by `finding-output-format.md`.
- **UNRESOLVED**: Evidence cannot yet support either state. Preserve the candidate and the missing evidence; never translate uncertainty into a negative proposal.

### STEP 3: Investigate Each ACCUMULATION_EXPOSURE

For each ACCUMULATION_EXPOSURE:
1. Read the accumulation formula and identify the controllable input and time source
2. Model the attack: Can an actor (permissionless OR semi-trusted) manipulate the controllable input, wait for time to pass, then trigger the accumulation to snapshot the manipulated state?
3. Quantify: What is the maximum excess accumulation from a single manipulation? Use concrete values (e.g., 1000 ETH deposit, 7-day stale period, 10% annual fee rate)
4. Check mitigations: Does the protocol snapshot BEFORE or AFTER the manipulation? Does it use min(old, new) or time-weighted averages? Are there caps?
5. Check composition: Can multiple exposures be combined (e.g., inflate supply AND extend time delta in the same attack)?

Analysis conclusion per exposure:
- **CANDIDATE**: Manipulation produces > 1% excess accumulation with realistic parameters, no mitigation fully prevents it, and the attacker can profit (or the protocol loses funds). Emit the corresponding standard finding block using the same allocated SGI-N ID and a positive finding verdict allowed by `finding-output-format.md`. The confirmed mechanism requires precondition P. Using the Main Table write sites (including constructor), verify no other code path also establishes P. If found: investigate it under a new SGI-N ID.
- **REFUTATION_PROPOSAL**: Current evidence supports that mitigations prevent meaningful manipulation, the exposure is bounded below materiality, or the controllable input requires fully trusted access. This is not terminal BENIGN/SAFE closure and requires the committed-invariant material from `finding-output-format.md`.
- **UNRESOLVED**: Evidence cannot yet support either state; retain the candidate and state the missing evidence.

### STEP 4: Investigate Each CONDITIONAL Write

For each CONDITIONAL annotation on an accumulator/snapshot/tracking variable:
1. Identify the function containing the conditional write and the condition expression
2. Identify ALL callers of that function (direct and indirect via call chain)
3. For each caller: determine if the caller can trigger the function when the condition is FALSE (the skip path). What concrete state causes the skip? (e.g., `vestingGains == 0` after full vest (vesting vaults), `pendingRewards == 0` after claim (staking), `timeElapsed == 0` in same block, `totalSupply == 0` after last exit (share-based pools))
4. When the write is skipped, identify ALL consumer functions that READ the stale variable afterward - within the same caller's execution AND in subsequent external calls
5. For each consumer: trace execution with the stale value using concrete numbers. Does the stale read produce a materially wrong result?
6. Check temporal scope: how long can the stale value persist? Until the next call that satisfies the condition? Unbounded?

Analysis conclusion per conditional:
- **CANDIDATE**: Consumer produces materially wrong result with a stale value, the skip path is reachable under normal operation (not just error/revert paths), and the staleness window can last > 1 block. Emit the corresponding standard finding block using the same allocated SGI-N ID and a positive finding verdict allowed by `finding-output-format.md`. The confirmed mechanism requires precondition P. Using the Main Table write sites (including constructor), verify no other code path also establishes P. If found: investigate it under a new SGI-N ID.
- **REFUTATION_PROPOSAL**: Current evidence supports that the skip path is unreachable under normal operation, all consumers handle the stale value correctly, or staleness self-corrects in the same transaction. This is not terminal BENIGN/SAFE closure and requires the committed-invariant material from `finding-output-format.md`.
- **UNRESOLVED**: Evidence cannot yet support either state; retain the candidate and state the missing evidence.

### STEP 5: Trace Conditional Skip Paths for SYNC_GAP functions

For each function identified in STEP 2 as creating a sync gap:
- Does ANY caller of this function assume the gap does NOT exist?
- Specifically: if function F creates a sync gap when condition C is false, does any caller of F (e.g., `distributeYield`/`recordLoss` (vesting vaults), `reportProfit`/`reportLoss` (Yearn-style), `notifyRewardAmount`/`getReward` (staking)) rely on the variable being updated regardless of C?
- If yes: trace the caller's subsequent logic with the stale value to find the impact

**Coverage assertion**: Before returning, verify every entity enumerated under each step has been processed. Report enumerated vs analyzed counts in your return message.

## Output Format

### Flag Disposition Table (MANDATORY - write FIRST, update per flag)

Enumerate every real input flag first and allocate one unique, stable `SGI-N` ID
to each flag before analysis. The same ID MUST be used in this table and in any
corresponding finding block. Write this skeleton table to
{SCRATCHPAD}/niche_semantic_gap_findings.md BEFORE starting investigation.
Update each row's Disposition as you investigate. Allowed table dispositions
are exactly `REFUTATION_PROPOSAL`, `CANDIDATE`, or `UNRESOLVED`; terminal
`BENIGN`, `SAFE`, `REFUTED`, and `EXPLOITABLE` table states are forbidden.
PENDING rows at completion are a workflow violation.

| Finding ID | Flag Type | Variable | Location | Disposition | If REFUTATION_PROPOSAL: Defense (file:line) | If CANDIDATE: Finding Block |
|------------|-----------|----------|----------|-------------|-----------------------------------------------|-----------------------------|

Every SYNC_GAP, ACCUMULATION_EXPOSURE, CONDITIONAL, and CLUSTER_GAP flag from semantic_invariants.md
MUST appear as a row. The orchestrator verifies: count(rows) == count(flags).

### Findings

Use standard finding format with [SGI-N] IDs.

For each finding, include:
- The complete standard envelope explicitly: **Verdict**, **Step Execution**,
  **Rules Applied**, **Preferred Tag**, **Severity**, **Location**,
  **Description**, **Impact**, **Material Harm**, and **Evidence**. Do not treat
  the phase-specific fields below as a reason to omit the standard fields.
- **Gap Type**: SYNC_GAP, ACCUMULATION_EXPOSURE, CONDITIONAL_SKIP, or CLUSTER_GAP
- **Source Annotation**: Quote the exact annotation from semantic_invariants.md
- **Investigation Result**: CANDIDATE, REFUTATION_PROPOSAL, or UNRESOLVED with full reasoning
- **Concrete Values**: Numeric trace showing the wrong result (for CANDIDATE)

For every value- or liveness-bearing `REFUTATION_PROPOSAL`, put this exact
one-to-one block inside that finding (replace every placeholder; do not merely
refer to `finding-output-format.md`):

```markdown
**Invariant Commitment**: CI:CI-SGI-N

committed-invariant [CI-SGI-N]
Locus: relative/production/file.ext:L123
Shape: CONSERVATION / REQUESTED_EQ_DELIVERED / APPROVE_EQ_SPEND / NO_REVERT_AT_BOUNDARY / ROUNDTRIP / FRESHNESS
Assertion: concrete property whose violation would falsify this proposal
Falsify Class: property / boundary / roundtrip / conservation
Provenance: SGI-N
```

The commitment ID and `Provenance` must use this finding's exact `SGI-N`.
Do not share a commitment between findings. A missing, malformed, duplicated,
or borrowed block leaves the proposal open as input debt.

## Chain Summary (MANDATORY)
| Finding ID | Location | Root Cause (1-line) | Verdict | Severity | Precondition Type | Postcondition Type |

Write to {SCRATCHPAD}/niche_semantic_gap_findings.md

Return: 'DONE: {S} sync gaps, {A} accumulation exposures, {C} conditional writes, {G} cluster gaps - {T} total flags dispositioned, {E} candidates'
")
```

## Why Niche Agent (Not Scanner Sub-Check or Injectable)

- **Not a scanner sub-check**: Investigating gaps requires reading multiple source files, tracing consumers through call chains, and modeling concrete value flows. This exceeds a scanner's 2-minute time budget per check.
- **Not an injectable**: This is not protocol-type-specific. SYNC_GAPs, ACCUMULATION_EXPOSUREs, and CONDITIONAL writes on tracking variables can appear in any protocol with stateful accumulators (vaults, staking, lending, DEXes).
- **Flag-triggered isolation**: Only spawns when the Semantic Invariant Agent detects high-signal flags. Zero context cost for protocols without these patterns.
- **Why CONDITIONAL writes are in-scope**: Depth agents and CHECK 8 scan for branch asymmetry from code, but do not systematically consume the pre-computed CONDITIONAL annotations from semantic_invariants.md. The niche agent already has the consumer-tracing infrastructure (Steps 2-3); extending it to CONDITIONAL writes is a natural fit. The semantic invariant agent pre-filters to tracking variables only, keeping the investigation set bounded.
