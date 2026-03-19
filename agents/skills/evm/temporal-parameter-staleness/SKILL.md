---
name: "temporal-parameter-staleness"
description: "Type Thought-template (instantiate before use) - Research basis Cached parameters in multi-step operations become stale when governance changes them mid-operation"
---

# Skill: Temporal Parameter Staleness Analysis

> **Type**: Thought-template (instantiate before use)
> **Research basis**: Cached parameters in multi-step operations become stale when governance changes them mid-operation

## Trigger Patterns
```
interval|epoch|period|duration|delay|cooldown|lockPeriod|timelock|
unbondingPeriod|claimDelay|withdrawDelay|maturityTime
```

## Reasoning Template

### Step 1: Enumerate Multi-Step Operations

Find all operations that span multiple transactions:

| Operation | Step 1 (Initiate) | Wait Condition | Step N (Complete) |
|-----------|-------------------|----------------|-------------------|
| {op_name} | {initiate_fn}() | {wait_condition} | {complete_fn}() |

For each multi-step operation:
- What parameters are read/cached at Step 1?
- What parameters are re-read at Step N?
- What parameters are used but NOT re-read at Step N?

### Step 2: Identify Cached Parameters

For each parameter used across steps:

| Parameter | Read At Step | Cached? | Governance-Changeable? | Re-Validated At Completion? |
|-----------|-------------|---------|------------------------|----------------------------|
| {param} | initiate() L{N} | YES/NO | YES/NO | YES/NO |

**Red flags**: Parameter is cached at Step 1 AND governance-changeable AND NOT re-validated at Step N.

### Step 3: Model Staleness Impact

For each cached parameter that can become stale:

```
Scenario A: Parameter INCREASES between steps
1. User initiates at Step 1 with param = X
2. Governance changes param to X + delta
3. User completes at Step N
4. Impact: {what happens with stale value X when current is X + delta}

Scenario B: Parameter DECREASES between steps
1. User initiates at Step 1 with param = X
2. Governance changes param to X - delta
3. User completes at Step N
4. Impact: {what happens with stale value X when current is X - delta}
```

**BOTH directions are mandatory** -- increase and decrease often have different impacts.

### Step 3b: Update Source Audit
For each parameter updated from an external source:
- Is the source (e.g., balanceOf, oracle, timestamp) the correct
  representation of what this parameter tracks?
- Should this parameter be fixed for a period (e.g., per epoch, per
  cycle) rather than continuously refreshed?
- Which functions update it? Which functions SHOULD update it?
  Any mismatch?

### Step 4: Retroactive Application Analysis

For fee/rate parameters that apply to existing state:

| Parameter | Applies To | Retroactive? | Impact |
|-----------|-----------|--------------|--------|
| {fee_param} | {what it affects} | YES/NO | {if retroactive: who is harmed} |

**Pattern**: Fee changes that affect already-accrued rewards or already-initiated operations are retroactive.

### Step 5: Assess Severity

For each staleness issue:
- **Who is affected?** (single user, all users with pending operations, protocol)
- **Is the impact bounded?** (capped by fee range, max delay, etc.)
- **Can it be exploited intentionally?** (governance front-running)
- **Is there a recovery path?** (re-initiate, admin override)

## Key Questions (must answer all)

1. What multi-step operations exist? (request/claim, deposit/lock/withdraw, propose/vote/execute)
2. For each cached parameter: can governance change it between steps?
3. What happens if a delay DECREASES after initiation? (users locked longer than necessary)
4. What happens if a delay INCREASES after initiation? (users can claim too early)
5. Are fees applied retroactively to existing positions or only to new ones?
6. Is there a maximum parameter range that bounds the staleness impact?

## Common False Positives

- **Immutable parameters**: If the parameter cannot be changed after deployment, no staleness
- **Bounded ranges**: If min/max bounds limit the change magnitude, impact may be Low
- **User can re-initiate**: If users can cancel and restart with new parameters, reduced severity
- **Timelock protection**: If parameter changes require timelock, users have time to react

## Instantiation Parameters
```
{CONTRACTS}           - Contracts to analyze
{MULTI_STEP_OPS}      - Identified multi-step operations
{CACHED_PARAMS}       - Parameters cached at initiation
{GOVERNANCE_PARAMS}   - Governance-changeable parameters
{DELAY_PARAMS}        - Delay/cooldown parameters
{FEE_PARAMS}          - Fee/rate parameters that may apply retroactively
```

## Output Schema
| Field | Required | Description |
|-------|----------|-------------|
| multi_step_ops | yes | List of multi-step operations found |
| cached_params | yes | Parameters cached across steps |
| staleness_vectors | yes | How cached params can become stale |
| retroactive_fees | yes | Fees applied retroactively |
| finding | yes | CONFIRMED / REFUTED / CONTESTED |
| evidence | yes | Code locations with line numbers |
| step_execution | yes | Status for each step |

---

## Step Execution Checklist (MANDATORY)

| Step | Required | Completed? | Notes |
|------|----------|------------|-------|
| 1. Enumerate Multi-Step Operations | YES | | |
| 2. Identify Cached Parameters | YES | | |
| 3. Model Staleness Impact (both directions) | YES | | |
| 3b. Update Source Audit | YES | | |
| 4. Retroactive Application Analysis | YES | | |
| 5. Assess Severity | YES | | |

### Cross-Reference Markers

**After Step 2**: If cached parameters are governance-changeable -> MUST complete Step 3 with BOTH increase and decrease scenarios.

**After Step 4**: Cross-reference with SEMI_TRUSTED_ROLES.md for admin functions that change these parameters.
