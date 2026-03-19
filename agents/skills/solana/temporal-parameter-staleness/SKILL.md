---
name: "temporal-parameter-staleness"
description: "Trigger Pattern interval|epoch|period|duration|delay|cooldown|lock_period|timelock|unbonding|claim_delay|withdraw_delay|maturity - Inject Into Breadth agents, depth-state-trace"
---

# TEMPORAL_PARAMETER_STALENESS Skill (Solana)

> **Trigger Pattern**: `interval|epoch|period|duration|delay|cooldown|lock_period|timelock|unbonding|claim_delay|withdraw_delay|maturity`
> **Inject Into**: Breadth agents, depth-state-trace
> **Finding prefix**: `[TPS-N]`
> **Rules referenced**: R2, R8, R10, R13, R14

Cached parameters in multi-step operations become stale when authority changes them mid-operation. On Solana, timing has unique properties: 400ms slot time, Clock sysvar shared across all instructions in a transaction, Solana epoch boundaries (~2-3 days, 432k slots), and leader schedule predictability.

---

## Step 1: Enumerate Multi-Step Operations

Find all operations that span multiple transactions:

| Operation | Step 1 (Initiate) | Wait Condition | Step N (Complete) | Clock Source |
|-----------|-------------------|----------------|-------------------|-------------|
| {op_name} | {initiate_ix}() | {wait_condition} | {complete_ix}() | slot / unix_timestamp / epoch |

For each multi-step operation:
- What parameters are read/cached at Step 1 (stored in an account)?
- What parameters are re-read at Step N?
- What parameters are used but NOT re-read at Step N?
- **Which clock source is used?** (`Clock::get()?.unix_timestamp`, `Clock::get()?.slot`, `Clock::get()?.epoch`)

### Solana Clock Semantics

| Clock Field | Resolution | Monotonicity | Accuracy | Use Case |
|-------------|-----------|-------------|----------|----------|
| `slot` | ~400ms | Strictly increasing | Exact (validator-produced) | Short-duration timing, cooldowns |
| `unix_timestamp` | ~400ms | Mostly increasing (can drift +-1-2s) | +/- 1-2 seconds (estimated by validator) | Human-readable delays, longer durations |
| `epoch` | ~2-3 days (432k slots) | Strictly increasing | Exact | Staking epoch boundaries, long cycles |

**Critical property**: Within a single transaction, ALL instructions see the same `Clock` values. Unlike EVM where multi-block operations have timing variation per block, a Solana transaction's instructions share identical timing. Multi-step timing attacks require separate transactions.

---

## Step 2: Identify Cached Parameters

For each parameter used across steps:

| Parameter | Account Stored In | Read At Step | Cached in User Account? | Authority-Changeable? | Re-Validated At Completion? |
|-----------|------------------|-------------|------------------------|----------------------|----------------------------|
| {param} | {config_account} | initiate() | YES/NO | YES/NO (which authority) | YES/NO |

**Solana caching patterns**:
- **Config account cache**: User's request account stores a snapshot of config params at initiation time (e.g., `request.fee_rate = config.fee_rate`)
- **Inline cache**: Parameter copied into instruction data or user PDA during Step 1
- **Re-read pattern**: Step N re-reads from the config/global account (no staleness possible for that param)
- **Epoch snapshot**: Protocol snapshots state at epoch boundary, uses snapshot until next epoch

**Red flags**: Parameter is cached in a user account at Step 1 AND authority can change the source account AND Step N does NOT re-read from source.

---

## Step 3: Model Staleness Impact

For each cached parameter that can become stale:

```
Scenario A: Parameter INCREASES between steps
1. User initiates at Step 1 - user PDA stores param = X (read from config account)
2. Authority updates config account: param = X + delta
3. User completes at Step N - uses cached X from user PDA
4. Impact: {what happens with stale value X when current is X + delta}

Scenario B: Parameter DECREASES between steps
1. User initiates at Step 1 - user PDA stores param = X
2. Authority updates config account: param = X - delta
3. User completes at Step N - uses cached X
4. Impact: {what happens with stale value X when current is X - delta}
```

**BOTH directions are mandatory** - increase and decrease often have different impacts.

### Solana-Specific Staleness Vectors

| Vector | Description | Severity Modifier |
|--------|-------------|-------------------|
| **Epoch boundary crossing** | Operation initiated in epoch N, completed in epoch N+1. Staking yields, validator rewards, inflation rate change at epoch boundary. | Higher if protocol depends on epoch-specific rates |
| **Slot leader timing** | Leader schedule known ~2 epochs ahead. Authority can time parameter changes to specific slots with high precision. | Increases likelihood for timing-sensitive parameters |
| **Same-tx guarantee** | Within one tx, Clock is constant. Cannot have intra-tx staleness. Multi-instruction composition is safe from timing drift. | Reduces severity for single-tx operations |
| **Clock drift** | `unix_timestamp` can drift +-1-2s from wall clock. If protocol uses tight timestamp comparisons (<5s), drift can cause unexpected behavior. | Medium if tight comparisons used |

---

## Step 3b: Update Source Audit

For each parameter updated from an external source (oracle account, other program's state):
- Is the source the correct representation of what this parameter tracks?
- **Is the source account ownership validated?** (Solana-specific: can a fake account be substituted?)
- Should this parameter be fixed for a period (e.g., per epoch, per cycle) rather than continuously refreshed?
- Which instructions update it? Which instructions SHOULD update it? Any mismatch?
- **Is there a `refresh` or `crank` instruction?** If yes, who calls it and when? Can staleness occur if the crank is not called?

---

## Step 4: Retroactive Application Analysis

For fee/rate parameters that apply to existing state:

| Parameter | Stored In | Applies To | Retroactive? | Impact |
|-----------|----------|-----------|--------------|--------|
| {fee_param} | {config PDA} | {what it affects} | YES/NO | {if retroactive: who is harmed} |

**Solana retroactive patterns**:
- **Global config update**: Authority changes `fee_bps` in a global config account. All pending claims calculated at completion time using new rate - retroactively changes expected returns.
- **Epoch-based rate**: Protocol sets rate per epoch. Users who entered mid-epoch may have their partial-epoch calculation affected by next-epoch rate change.
- **Account closure incentive**: If `close_fee` changes, users with pending close requests pay different amount than expected.

**Rule 2 direction check**: Can the authority's parameter change make a user-facing instruction behave unexpectedly? (e.g., setting `cooldown_slots = 0` removes timing protection, setting `max_deviation = 0` disables oracle bounds). Does the change retroactively affect users in active positions?

---

## Step 5: Assess Severity

For each staleness issue:
- **Who is affected?** (single user, all users with pending operations, protocol)
- **Is the impact bounded?** (capped by fee range, max delay, etc.)
- **Can it be exploited intentionally?** (authority front-running via leader schedule knowledge)
- **Is there a recovery path?** (re-initiate, cancel instruction, admin override)
- **Slot-level precision**: Given Solana's ~400ms slots and predictable leader schedule, how precisely can an attacker time the exploitation?

### Severity Assessment (Rule 10 - Worst-State)

Use worst realistic operational state, not current on-chain snapshot:
```
Severity assessed at: pending_claims=MAX_USERS, fee_delta=MAX_FEE-MIN_FEE, tvl=$XXM
Rationale: Protocol designed for up to {N} concurrent pending operations per documentation
```

---

## Key Questions (must answer all)

1. What multi-step operations exist? (request/claim, stake/cooldown/unstake, propose/vote/execute)
2. For each cached parameter: can authority change it between steps?
3. What happens if a delay DECREASES after initiation? (users locked longer than necessary vs original expectation)
4. What happens if a delay INCREASES after initiation? (users can claim too early relative to new policy)
5. Are fees applied retroactively to existing positions or only to new ones?
6. Is there a maximum parameter range that bounds the staleness impact?
7. **Solana-specific**: Does the protocol use `slot` or `unix_timestamp` for timing? If `unix_timestamp`, is the +-1-2s drift handled?
8. **Solana-specific**: Do any operations span Solana epoch boundaries? If so, what changes at the boundary?
9. **Solana-specific**: Is there a crank/refresh instruction? What happens if it is never called?

---

## Common False Positives

- **Immutable config**: If the config account has no update instruction or authority is revoked, no staleness
- **Bounded ranges**: If min/max bounds limit the change magnitude (enforced on-chain), impact may be Low
- **User can cancel**: If users can cancel pending operations and re-initiate with new parameters, reduced severity
- **Timelock protection**: If parameter changes require a Clockwork/Squads timelock, users have time to react
- **Same-transaction operations**: Operations that complete within a single transaction cannot have Clock staleness between steps
- **Re-read at completion**: If Step N re-reads the parameter from the source config account (not a cached copy), no staleness for that parameter

---

## Instantiation Parameters
```
{CONTRACTS}           - Programs to analyze
{MULTI_STEP_OPS}      - Identified multi-step operations
{CACHED_PARAMS}       - Parameters cached at initiation (stored in user PDAs/accounts)
{AUTHORITY_PARAMS}    - Authority-changeable parameters
{DELAY_PARAMS}        - Delay/cooldown parameters (in slots, timestamps, or epochs)
{FEE_PARAMS}          - Fee/rate parameters that may apply retroactively
{CLOCK_SOURCE}        - Clock field used (slot/unix_timestamp/epoch)
```

---

## Output Schema

| Field | Required | Description |
|-------|----------|-------------|
| multi_step_ops | yes | List of multi-step operations found |
| cached_params | yes | Parameters cached across steps (stored in which account) |
| staleness_vectors | yes | How cached params can become stale |
| retroactive_fees | yes | Fees applied retroactively |
| clock_source_audit | yes | Which Clock field is used and whether appropriate |
| epoch_boundary_effects | yes | Operations spanning epoch boundaries |
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

**After Step 2**: If cached parameters are authority-changeable -> MUST complete Step 3 with BOTH increase and decrease scenarios.

**After Step 4**: Cross-reference with SEMI_TRUSTED_ROLES (Solana version) for authority functions that change these parameters.

**After Step 3**: If protocol uses `unix_timestamp` for comparisons tighter than 5 seconds -> FLAG clock drift concern.

**After Step 1**: If any operation spans Solana epoch boundaries -> cross-reference with staking/inflation rate changes.
