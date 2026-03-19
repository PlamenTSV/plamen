---
name: "temporal-parameter-staleness"
description: "Trigger Pattern TEMPORAL flag (required) - Inject Into Breadth agents, depth-state-trace"
---

# Skill: Temporal Parameter Staleness Analysis (Sui)

> **Trigger Pattern**: TEMPORAL flag (required)
> **Inject Into**: Breadth agents, depth-state-trace
> **Purpose**: Analyze cached parameters in multi-step operations on Sui for staleness when capability holders change them mid-operation. Time source on Sui is the shared Clock object at address 0x6.

## Trigger Patterns
```
epoch|period|duration|delay|cooldown|lock_period|timelock|
unbonding_period|claim_delay|withdraw_delay|maturity_time|
clock::timestamp_ms|tx_context::epoch
```

## Reasoning Template

### Step 1: Enumerate Multi-Step Operations

Find all operations that span multiple transactions:

| Operation | Step 1 (Initiate) | Wait Condition | Step N (Complete) |
|-----------|-------------------|----------------|-------------------|
| {op_name} | {module::initiate_fn}() | {wait_condition} | {module::complete_fn}() |

**Sui-specific multi-step patterns**:
- Unstaking: request_withdraw() -> wait epochs -> complete_withdraw()
- Governance: propose() -> wait voting period -> execute()
- Vesting: create_vest() -> wait lock period -> claim()
- Cooldowns: initiate_action() -> wait cooldown (clock-based) -> finalize_action()

**Time sources on Sui**:
- `clock::timestamp_ms(clock: &Clock)`: Real-time milliseconds. Shared object at `0x6`. Monotonically increasing. Used for time-based delays.
- `tx_context::epoch(ctx: &TxContext)`: Epoch number. Incremented roughly every 24 hours. Used for epoch-based staking/unstaking.

For each multi-step operation:
- What parameters are read/cached at Step 1?
- What parameters are re-read at Step N?
- What parameters are used but NOT re-read at Step N? (stored in user's owned object or shared object field)

### Step 2: Identify Cached Parameters

For each parameter used across steps:

| Parameter | Stored In | Read At Step | Cached? | Admin-Changeable? | Re-Validated At Completion? |
|-----------|----------|-------------|---------|-------------------|----------------------------|
| {param} | Shared config object | initiate() L{N} | YES/NO | YES/NO (requires {CapType}) | YES/NO |
| {delay_param} | User's receipt object | initiate() L{N} | YES (in receipt) | YES/NO | YES/NO |

**Sui caching patterns**:
- Parameter stored in shared config object: read at initiation, may change before completion
- Parameter stored in user's receipt/ticket object (owned): cached at initiation, immutable until completion
- Parameter in dynamic field: may be updated independently of the operation

**Red flags**: Parameter is cached at Step 1 AND changeable via admin capability AND NOT re-validated at Step N.

### Step 3: Model Staleness Impact

For each cached parameter that can become stale:

```
Scenario A: Parameter INCREASES between steps
1. User initiates at Step 1 with param = X (stored in receipt)
2. Admin (via AdminCap) changes param to X + delta in shared config
3. User completes at Step N
4. Impact: {what happens with stale value X when current is X + delta}

Scenario B: Parameter DECREASES between steps
1. User initiates at Step 1 with param = X
2. Admin changes param to X - delta
3. User completes at Step N
4. Impact: {what happens with stale value X when current is X - delta}
```

**BOTH directions are mandatory** -- increase and decrease often have different impacts.

**Sui-specific staleness vectors**:
- Epoch-based operations: If unstaking delay is cached as "epoch + N" and N is changed, the cached deadline may be too early or too late
- Clock-based cooldowns: If cooldown duration changes, users with in-flight operations may bypass or be locked longer
- Fee parameters: If fee rate changes between request and execution, user pays stale rate

**PTB bypass check (CRITICAL)**: Can Steps 1 and N both be executed within a single PTB?
- If YES with time-based waits (`clock::timestamp_ms` comparisons): bypassed -- same Clock timestamp within a PTB
- If YES with epoch-based waits (`tx_context::epoch` comparisons): bypassed -- same epoch within a PTB
- Only hot-potato receipts (zero-ability structs) or consumed/destroyed objects can enforce multi-transaction separation
- If PTB bypass is possible -> escalate severity (time controls are ineffective)

### Step 3b: Update Source Audit
For each parameter updated from an external source:
- Is the source (e.g., oracle, clock, epoch) the correct representation of what this parameter tracks?
- Should this parameter be fixed for a period (e.g., per epoch, per cycle) rather than continuously refreshed?
- Which functions update it? Which functions SHOULD update it? Any mismatch?
- **Sui-specific**: Does the parameter depend on `clock::timestamp_ms` (continuous) vs `tx_context::epoch` (discrete)? Is the choice appropriate?
- **Unit consistency**: Verify all timestamp arithmetic uses consistent units. `clock::timestamp_ms()` returns milliseconds; external sources (Pyth `publish_time`, cross-chain timestamps) typically use seconds. Any comparison or subtraction without ×1000 conversion → FINDING.

### Step 4: Retroactive Application Analysis

For fee/rate parameters that apply to existing state:

| Parameter | Applies To | Retroactive? | Impact |
|-----------|-----------|--------------|--------|
| {fee_param} | {what it affects} | YES/NO | {if retroactive: who is harmed} |

**Pattern**: Fee changes that affect already-accrued rewards or already-initiated operations are retroactive.

**Sui-specific retroactive patterns**:
- Staking reward rate changed -> applies to already-staked positions?
- Fee rate changed -> applies to in-flight withdrawals?
- Slippage tolerance changed -> applies to pending swap requests?

### Step 5: Assess Severity

For each staleness issue:
- **Who is affected?** (single user with pending operation, all users with pending operations, protocol)
- **Is the impact bounded?** (capped by fee range, max delay, etc.)
- **Can it be exploited intentionally?** (admin front-running users, users racing admin changes)
- **Is there a recovery path?** (cancel and re-initiate, admin override)

**Severity factors specific to Sui**:
- Epoch transitions are infrequent (~24h) -- staleness impact per epoch change is bounded
- Clock-based parameters can change at any time -- more exploitable
- Shared object contention may delay admin parameter changes, creating a natural buffer

## Key Questions (must answer all)

1. What multi-step operations exist? (request/claim, deposit/lock/withdraw, propose/vote/execute)
2. For each cached parameter: can admin (via capability) change it between steps?
3. What happens if a delay DECREASES after initiation? (users locked longer than necessary)
4. What happens if a delay INCREASES after initiation? (users can claim too early)
5. Are fees applied retroactively to existing positions or only to new ones?
6. Is there a maximum parameter range (enforced bounds) that limits the staleness impact?

## Common False Positives

- **Immutable parameters**: If the parameter is set at object creation and has no setter function, no staleness
- **Bounded ranges**: If min/max bounds limit the change magnitude, impact may be Low
- **User can cancel and re-initiate**: If users can abort pending operations with new parameters, reduced severity
- **Timelock on parameter changes**: If parameter changes require a delay (e.g., governance proposal), users have time to react
- **Per-operation snapshots**: If each operation stores its own copy of the parameter (in receipt/ticket object), it is isolated from changes

## Instantiation Parameters
```
{CONTRACTS}           -- Move modules to analyze
{MULTI_STEP_OPS}      -- Identified multi-step operations
{CACHED_PARAMS}       -- Parameters cached at initiation
{ADMIN_PARAMS}        -- Admin-changeable parameters (via capability)
{DELAY_PARAMS}        -- Delay/cooldown parameters (clock or epoch based)
{FEE_PARAMS}          -- Fee/rate parameters that may apply retroactively
{CLOCK_USAGE}         -- Functions using clock::timestamp_ms
{EPOCH_USAGE}         -- Functions using tx_context::epoch
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
| 3 (PTB bypass check) | YES | | Can Steps 1+N execute in same PTB? |
| 3b. Update Source Audit | YES | | |
| 4. Retroactive Application Analysis | YES | | |
| 5. Assess Severity | YES | | |

### Cross-Reference Markers

**After Step 2**: If cached parameters are admin-changeable via capability -> MUST complete Step 3 with BOTH increase and decrease scenarios.

**After Step 3 (PTB bypass)**: If PTB bypass is possible -> escalate severity (time controls are ineffective). Only hot-potato receipts enforce multi-transaction separation.

**After Step 4**: Cross-reference with SEMI_TRUSTED_ROLES.md for capability holders that change these parameters -- is the parameter change within or outside the role's stated trust boundary?
