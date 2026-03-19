---
name: "temporal-parameter-staleness"
description: "Trigger Pattern TEMPORAL flag (required) - Inject Into Breadth agents, depth-state-trace"
---

# TEMPORAL_PARAMETER_STALENESS Skill

> **Trigger Pattern**: TEMPORAL flag (required)
> **Inject Into**: Breadth agents, depth-state-trace
> **Purpose**: Analyze cached parameters in multi-step operations that can become stale when admin/capability holders change them mid-operation, and external state stored and relied upon without re-verification

## Trigger Patterns
```
epoch|period|duration|delay|cooldown|lock_period|timelock|
unbonding_period|claim_delay|withdraw_delay|maturity_time|
pending_|request_|fulfill_|complete_|finalize_
```

## Reasoning Template

### Step 1: Enumerate Multi-Step Operations

Find all operations that span multiple transactions:

| Operation | Step 1 (Initiate) | Wait Condition | Step N (Complete) | Resource Storing State |
|-----------|-------------------|----------------|-------------------|-----------------------|
| {op_name} | {initiate_fn}() | {wait_condition} | {complete_fn}() | {PendingRequest / similar} |

**Aptos multi-step patterns**:
- Request/fulfill patterns: `request_withdraw()` -> wait for epoch/time -> `fulfill_withdraw()`
- Lock/unlock patterns: `lock()` -> cooldown expires -> `unlock()`
- Proposal/execute patterns: `propose()` -> voting period -> `execute()`
- Unstaking: `request_unstake()` -> unbonding period -> `claim()`
- Pending operations stored in `Table<address, PendingRequest>` or `SmartTable` or per-user resource

For each multi-step operation:
- What parameters are read/cached at Step 1 (stored in the pending resource)?
- What parameters are re-read at Step N?
- What parameters are used but NOT re-read at Step N?

### Step 2: Identify Cached Parameters

For each parameter used across steps:

| Parameter | Read At Step | Stored In | Admin-Changeable? | Re-Validated At Completion? |
|-----------|-------------|-----------|-------------------|----------------------------|
| {param} | initiate() L{N} | {PendingRequest.field} | YES/NO | YES/NO |
| {param} | initiate() L{N} | Not stored (read at completion from resource) | YES/NO | YES (re-read) |

**Red flags**: Parameter is cached in pending resource at Step 1 AND admin-changeable AND NOT re-validated at Step N.

**Aptos-specific caching patterns**:
- Parameters stored in global resource (`move_to` at initiation, `move_from` at completion)
- Parameters stored in `Table` entries keyed by user address
- Parameters stored in Object resources
- Parameters read from a separate config resource (may change between steps)

### Step 3: Model Staleness Impact

For each cached parameter that can become stale:

```
Scenario A: Parameter INCREASES between steps
1. User initiates at Step 1 with param = X (cached in PendingRequest)
2. Admin/capability holder changes param to X + delta in config resource
3. User completes at Step N
4. Impact: {what happens with stale value X when current is X + delta}

Scenario B: Parameter DECREASES between steps
1. User initiates at Step 1 with param = X (cached in PendingRequest)
2. Admin/capability holder changes param to X - delta in config resource
3. User completes at Step N
4. Impact: {what happens with stale value X when current is X - delta}
```

**BOTH directions are mandatory** -- increase and decrease often have different impacts.

**Common staleness impacts on Aptos**:
- Fee rate decreased after initiation -> user pays old (higher) fee at completion
- Withdrawal delay increased -> user can complete earlier than current policy allows
- Exchange rate changed -> user's pending operation uses outdated rate
- Collateral ratio changed -> user's pending position evaluated against stale threshold

### Step 3b: Update Source Audit (External State Staleness)

For each parameter updated from an external source:

| Parameter | External Source | Read When | Stored Where | Re-Read At Use? | Staleness Window |
|-----------|---------------|-----------|-------------|-----------------|-----------------|
| {param} | {oracle / other module / timestamp} | {read_fn} | {resource.field} | YES/NO | {time between read and use} |

**Analysis questions**:
- Is the source (e.g., oracle price, external module state, `timestamp::now_seconds()`) the correct representation of what this parameter tracks?
- Should this parameter be fixed for a period (e.g., per epoch, per cycle) rather than continuously refreshed?
- Which functions update it? Which functions SHOULD update it? Any mismatch?
- If external state is validated at entry point A, stored, then relied upon at entry point B without re-verification -> FINDING (R8 attack vector 4)
- **Unit consistency**: Verify all timestamp arithmetic uses consistent units. `timestamp::now_seconds()` returns seconds; `timestamp::now_microseconds()` returns microseconds. Mixing these without ×1_000_000 conversion in comparisons, subtractions, or staleness checks → FINDING.

### Step 4: Retroactive Application Analysis

For fee/rate parameters that apply to existing state:

| Parameter | Applies To | Retroactive? | Impact |
|-----------|-----------|--------------|--------|
| {fee_param} | {what it affects} | YES/NO | {if retroactive: who is harmed} |

**Pattern**: Fee changes that affect already-accrued rewards or already-initiated operations are retroactive.

**Aptos-specific retroactive risks**:
- Global fee rate stored in config resource, applied to ALL pending operations at completion
- Reward rate change affecting accumulated but unclaimed rewards
- Staking parameters changing for users already in unbonding period
- Exchange rate formula change applied to pending withdrawals

### Step 5: Assess Severity

For each staleness issue:

| Factor | Assessment |
|--------|-----------|
| Who is affected? | {single user / all users with pending ops / protocol} |
| Is the impact bounded? | {capped by fee range / max delay / parameter bounds} |
| Can it be exploited intentionally? | {admin front-running / user timing manipulation} |
| Is there a recovery path? | {re-initiate / admin override / cancel pending} |
| Worst-case fund impact? | {quantified amount or percentage} |

## Key Questions (must answer ALL)

1. What multi-step operations exist? (request/claim, deposit/lock/withdraw, propose/vote/execute)
2. For each cached parameter: can admin change it between steps?
3. What happens if a delay DECREASES after initiation? (users locked longer than necessary with old delay)
4. What happens if a delay INCREASES after initiation? (users can claim too early with old delay)
5. Are fees applied retroactively to existing positions or only to new ones?
6. Is there a maximum parameter range that bounds the staleness impact?

## Common False Positives

- **Immutable parameters**: If the parameter is set once at initialization and never changed, no staleness
- **Bounded ranges**: If min/max bounds limit the change magnitude, impact may be Low
- **User can re-initiate**: If users can cancel and restart with new parameters, reduced severity
- **Timelock protection**: If parameter changes require timelock, users have time to react
- **Epoch-bound parameters**: If parameters only change at epoch boundaries and operations complete within an epoch, no mid-operation staleness

## Instantiation Parameters
```
{CONTRACTS}           -- Move modules to analyze
{MULTI_STEP_OPS}      -- Identified multi-step operations
{CACHED_PARAMS}       -- Parameters cached at initiation (stored in pending resources)
{ADMIN_PARAMS}        -- Admin-changeable parameters (in config resources)
{DELAY_PARAMS}        -- Delay/cooldown parameters
{FEE_PARAMS}          -- Fee/rate parameters that may apply retroactively
```

## Output Schema

| Field | Required | Description |
|-------|----------|-------------|
| multi_step_ops | yes | List of multi-step operations found |
| cached_params | yes | Parameters cached across steps |
| staleness_vectors | yes | How cached params can become stale |
| external_staleness | yes | External state stored and relied upon without re-verification |
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
| 3b. Update Source Audit (external state) | YES | | |
| 4. Retroactive Application Analysis | YES | | |
| 5. Assess Severity | YES | | |

### Cross-Reference Markers

**After Step 2**: If cached parameters are admin-changeable -> MUST complete Step 3 with BOTH increase and decrease scenarios.

**After Step 3b**: If external state is stored and re-used without re-verification -> cross-reference with ORACLE_ANALYSIS.md for oracle-sourced state.

**After Step 4**: Cross-reference with SEMI_TRUSTED_ROLES.md for admin functions that change these parameters and whether users can grief the parameter update mechanism.
