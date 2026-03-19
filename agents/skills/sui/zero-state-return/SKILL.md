---
name: "zero-state-return"
description: "Trigger Vault/first-depositor pattern detected - Inject Into Depth-edge-case agent (extends existing ZERO_STATE_ECONOMICS)"
---

# ZERO_STATE_RETURN Skill (Sui)

> **Trigger**: Vault/first-depositor pattern detected
> **Inject Into**: Depth-edge-case agent (extends existing ZERO_STATE_ECONOMICS)
> **Purpose**: Check protocol return-to-zero state in Sui shared objects, not just initial zero state. Covers first depositor manipulation, residual assets, and re-entry after full exit.

## Overview

ZERO_STATE_ECONOMICS checks initial zero state. This skill EXTENDS it to cover:
- Protocol returning to zero after normal operations
- Residual assets in shared objects when supply returns to zero
- Re-entry vulnerabilities after full exit
- Sui-specific: shared objects persist even when economically empty

## 1. Identify Zero-State Transitions

| State | Trigger | Shared Object Behavior | Check |
|-------|---------|----------------------|-------|
| `total_supply == 0` | All users withdrew/burned shares | Shared pool object persists | Does this recreate first-depositor conditions? |
| `balance::value(&pool.balance) == 0` | No funds deposited | Balance<T> field is zero but exists | Are there residual rewards? |
| Empty participant set | All participants removed | Shared object fields still allocated | Can protocol still function? |
| Zero liquidity | All LP withdrawn | Pool shared object persists | What happens to accumulated fees? |

**Sui-specific**: Unlike EVM contracts (which always exist at their address), Sui shared objects CANNOT be deleted -- they persist forever once created. This means a pool/vault that reaches zero state ALWAYS allows re-entry, and its state fields retain their last values.

## 2. First Depositor Analysis

Can the first depositor manipulate the share price?

### 2a. Classic First-Depositor Attack (adapted for PTBs)

```
PTB Attack Sequence:
  1. Deposit minimum amount (1 unit) -> receive 1 share
  2. Donate large amount to inflate balance (if donation vector exists -- see TOKEN_FLOW_TRACING Section 5)
  3. Next depositor's shares are calculated against inflated balance
  4. Shares round to 0 or near-0, value captured by attacker
```

**Sui-specific considerations**:
- Steps 1-2 can happen in the SAME PTB (atomic) if donation is possible
- `balance::join` to the shared pool balance may or may not be accessible
- Check: does the protocol enforce a minimum first deposit? (`assert!(amount >= MIN_FIRST_DEPOSIT)`)
- Check: does the protocol use virtual shares/offset (e.g., mint initial phantom shares)?

### 2b. Share Price Calculation

| State | Formula | With Residual | Division by Zero? |
|-------|---------|--------------|-------------------|
| total_supply = 0, balance = 0 | {show formula} | N/A | {YES/NO -- how handled?} |
| total_supply = 0, balance > 0 | {show formula} | {inflated rate?} | {YES/NO} |
| total_supply > 0, balance = 0 | {show formula} | N/A | {YES/NO} |

**Check**: What constant is returned when total_supply = 0? Is it 1:1? Is it configurable? Can it be manipulated?

## 3. Return-to-Zero Scenarios

After normal operations, can the protocol return to zero?

### 3a. Full Exit Path

- Can ALL users withdraw their full balance? Or do rounding/dust prevent complete exit?
- After all withdrawals, what is the state of the shared pool object?
- Are there any pending operations (unlocking, vesting) that prevent zero state?

### 3b. What Persists at Zero State

| Persistent State | Value After Full Exit | Impact on Next Depositor |
|-----------------|----------------------|-------------------------|
| Accumulated rewards | {amount or 0} | {inflates rate for next depositor?} |
| Protocol fees | {amount or 0} | {captured by next depositor?} |
| Dust balances | {0 or nonzero} | {affects exchange rate?} |
| Epoch/timestamp state | {last epoch value} | {stale values used?} |
| Configuration parameters | {unchanged} | {potentially stale?} |

### 3c. Pending Operations at Zero

- Are there pending withdrawal requests that persist?
- Are there unclaimed rewards allocated to zero-address or burned shares?
- What happens to in-flight operations (epoch transitions, rebalances) when supply hits zero?

## 4. Residual Asset Check

When supply returns to zero:

### 4a. Accrued Rewards
- Do rewards persist when total_supply = 0?
- If yes -> inflates exchange rate for next depositor
- Example: Protocol accrues 100 SUI rewards, last user exits, total_supply = 0, next deposit of 1 MIST receives claim to 100 SUI

### 4b. Unclaimed Fees
- Are there fee balances stored in the shared object that persist?
- Can first new depositor capture accumulated fees?
- Example: Protocol fees = 10 SUI in Balance<SUI>, users exit, new depositor's shares priced against total balance including fees

### 4c. Dust Balances
- Can dust (tiny amounts) remain in the shared object's Balance<T>?
- Does `balance::split` leave remainder when amount cannot be evenly divided?
- Example: total_supply = 0, balance::value = 1 MIST, exchange rate undefined or manipulable

### 4d. Shared Object Storage
- Do dynamic fields persist that affect calculations?
- Are there objects stored in `Table`, `Bag`, `ObjectTable`, `ObjectBag` that survive full exit?
- Can orphaned dynamic field entries affect the next epoch of deposits?

## 5. Re-Entry Vulnerability Analysis

Does re-entering zero state recreate first-depositor attack conditions?

| Scenario | Initial State | Return-to-Zero State | Same Vulnerability? |
|----------|---------------|---------------------|---------------------|
| First depositor attack | total_supply=0, balance=0 | total_supply=0, balance=X (residual) | **WORSE** if residual > 0 |
| Exchange rate manipulation | No shares exist | No shares, but balance exists | YES + amplified |
| Donation attack | Clean shared object | Dirty shared object | YES + pre-seeded |

**Key insight**: On Sui, shared objects persist indefinitely. A pool that was active, drained, and re-entered has DIFFERENT state than a freshly created pool -- even if both have total_supply = 0.

## 5b. Default/Uninitialized State Values

For each state field used in arithmetic or control flow, check its **initial value** before any user interaction:

- **Default zero**: Move initializes struct fields to their declared defaults (typically 0 for integers, `@0x0` for addresses). If a function uses `last_timestamp`, `start_time`, or `last_update` in subtraction or division BEFORE it has ever been set, the result may be unexpected (e.g., `clock::timestamp_ms(clock) - 0` = enormous elapsed time, or division by a value derived from 0).
- **First-call path**: Trace the FIRST invocation of each state-modifying function. Does it assume a prior call already initialized dependent fields?
- **Check**: For each field read in a function, is there a code path where that field still holds its default value (0, @0x0, false)? If yes, does the function behave correctly with that default?

## 6. Protocol Reset Functions

Check for admin functions that can force zero state:

| Reset Function | Requires Cap? | Clears ALL State? | Residual After Reset |
|---------------|---------------|-------------------|---------------------|
| emergency_withdraw() | {AdminCap/OwnerCap} | {YES/NO -- which fields?} | {list remaining state} |
| rescue_tokens() | {cap type} | {NO -- only moves tokens} | {accounting mismatch?} |
| pause() | {cap type} | {NO -- just sets flag} | {all state preserved} |
| migrate() | {cap type} | {NO -- copies to new object} | {old object residual?} |

For each: what state persists in the shared object after the "reset"? Can the shared object be re-entered after reset?

## 7. Finding Template

```markdown
**ID**: [ZS-N]
**Severity**: [typically HIGH if funds extractable]
**Step Execution**: check1,2,3,4,5,6 | x(reasons) | ?(uncertain)
**Rules Applied**: [R10:check, R4:check]
**Location**: module::function:LineN
**Title**: Return-to-zero state allows [attack] due to [residual state]
**Description**:
- Protocol can return to total_supply=0 via [mechanism]
- When this happens, [state variable] retains value of [amount]
- A new depositor can [exploit path]
**Impact**: [Fund extraction / exchange rate manipulation / unfair distribution]
**PoC Scenario**:
1. Users deposit and earn rewards
2. All users withdraw, total_supply = 0
3. Rewards remain in shared object: balance::value = X
4. Attacker deposits 1 MIST
5. Attacker claims X rewards
```

## 8. Integration with ZERO_STATE_ECONOMICS

This skill does NOT replace ZERO_STATE_ECONOMICS. It EXTENDS it:

| Check | ZERO_STATE_ECONOMICS | ZERO_STATE_RETURN |
|-------|---------------------|-------------------|
| Initial zero state | YES | - |
| First depositor attack | YES | - |
| Return to zero | - | YES |
| Residual assets | - | YES |
| Re-entry vulnerability | - | YES |
| Shared object persistence | - | YES (Sui-specific) |

When applying ZERO_STATE_ECONOMICS, ALSO apply ZERO_STATE_RETURN.

## Instantiation Parameters
```
{CONTRACTS}           -- Move modules to analyze
{POOL_OBJECTS}        -- Shared pool/vault objects
{SHARE_TYPE}          -- Share/LP token type
{BALANCE_FIELDS}      -- Balance<T> fields in shared objects
{RATE_FORMULA}        -- Exchange rate calculation
{RESET_FUNCTIONS}     -- Admin reset/emergency functions
```

## Output Schema
| Field | Required | Description |
|-------|----------|-------------|
| zero_transitions | yes | How protocol can reach zero state |
| first_depositor | yes | First depositor attack analysis |
| residual_assets | yes | What persists at zero state |
| reentry_analysis | yes | Re-entry vulnerability assessment |
| reset_functions | yes | Admin reset function audit |
| finding | yes | CONFIRMED / REFUTED / CONTESTED |
| evidence | yes | Code locations with line numbers |
| step_execution | yes | Status for each step |

---

## Step Execution Checklist (MANDATORY)

| Step | Required | Completed? | Notes |
|------|----------|------------|-------|
| 1. Identify Zero-State Transitions | YES | check/x/? | |
| 2. First Depositor Analysis | YES | check/x/? | PTB atomic attack |
| 3. Return-to-Zero Scenarios | YES | check/x/? | Full exit path + persistent state |
| 4. Residual Asset Check | YES | check/x/? | Rewards, fees, dust, storage |
| 5. Re-Entry Vulnerability Analysis | YES | check/x/? | Compare initial vs return-to-zero |
| 6. Protocol Reset Functions | IF admin reset exists | check/x(N/A)/? | |

### Cross-Reference Markers

**After Step 2**: Cross-reference with TOKEN_FLOW_TRACING Section 5 for donation vectors that amplify first-depositor attacks.

**After Step 4**: If residual assets found -> check if FLASH_LOAN_INTERACTION can be used to exploit them atomically.
