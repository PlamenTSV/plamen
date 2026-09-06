---
name: "zero-state-return"
description: "Trigger Always inject into Arithmetic agent (extends existing ZERO_STATE_ECONOMICS) - Purpose Check protocol return-to-zero state, not just initial zero state"
---

# ZERO_STATE_RETURN Skill (Soroban)

> **Trigger**: Always inject into Arithmetic agent (extends existing ZERO_STATE_ECONOMICS)
> **Inject Into**: depth-edge-case
> **Purpose**: Check protocol return-to-zero state, not just initial zero state
> **Finding prefix**: `[ZS-N]`
> **Rules referenced**: R5, R10, R13

## Overview

ZERO_STATE_ECONOMICS checks initial zero state. This skill EXTENDS it to cover:
- Protocol returning to zero after normal operations
- Residual assets when LP/share supply returns to zero
- Re-entry vulnerabilities after full exit
- Soroban-specific: i128 division edge cases at zero, empty Instance/Persistent storage states

## 1. Return-to-Zero Scenarios

After normal operations, can the protocol return to:

| State | Trigger | Check |
|-------|---------|-------|
| `total_shares == 0` (i128) | All users burned shares / withdrew | Recreates first-depositor conditions? |
| `total_deposited == 0` | All funds withdrawn | Residual rewards or time-decay state in Persistent storage? |
| Empty Instance storage keys | All operational state cleared | Can protocol still function on next call? |
| Zero liquidity | All LP positions closed | What happens to accumulated fees / ratio snapshots? |

## 2. Residual Asset Check

When LP/share supply returns to zero, check for:

### 2a. Accrued Rewards / Time-Decay State
- Do rewards or time-decay state persist in Instance/Persistent storage when `total_shares = 0`?
- If YES → inflates exchange rate for next depositor

### 2b. Unclaimed Fees / Ratio Snapshot State
- Fee accumulators (performance/management fees) in Instance storage that persist?
- Ratio snapshots (high water marks, benchmarks) reset when all shares burned?
- Can first new depositor capture accumulated fees?

### 2c. Token Balance Dust
- Can dust remain in contract's token balance after all shares burned?
- Does dust affect exchange rate when `total_shares = 0`?
- **Soroban note**: No separate token account to close — balance is in the SEP-41 token's Persistent storage for the contract's address.

### 2d. Pending Operations
- Pending withdrawal receipts / claim tickets in Persistent storage that persist when `total_shares = 0`?
- Do sub-contract or cross-contract positions retain allocated funds after all shares burned?

## 3. Re-Entry Vulnerability Analysis

Does re-entering zero state recreate first-depositor attack conditions?

| Scenario | Initial State | Return-to-Zero State | Same Vulnerability? |
|----------|---------------|---------------------|---------------------|
| First depositor attack | total_shares=0, total_value=0 | total_shares=0, total_value=X (residual) | **WORSE** if residual > 0 |
| Exchange rate manipulation | No shares exist | No shares, but token balance > 0 | YES + amplified |
| Donation attack | Clean state | Dirty state (residual, unsolicited dust) | YES + pre-seeded |

**Key question**: Does first-depositor protection apply only on initial `initialize()` or also on return-to-zero re-deposits?

**Soroban-specific**: If protection is `if total_shares == 0 { require(amount >= MIN_FIRST_DEPOSIT) }`, does it fire on return-to-zero? Is `MIN_FIRST_DEPOSIT` in Instance storage (accessible) or hardcoded?

## 4. Protocol Reset Functions

Check for admin functions that can force zero state:
- `emergency_withdraw()` — clears ALL tracked state (totals, accumulators, snapshots)?
- `close_vault()` — what Persistent/Instance keys persist after calling?
- `migrate()` — old contract retains residual token balances?
- `force_deallocate()` — creates accounting mismatch between state and token balance?

**Soroban-specific**: Instance storage has no single "close all" operation. Verify each `DataKey` variant is explicitly cleared during reset, not just main accounting keys.

## 5. Zero-State Return Checklist

```markdown
## Zero-State Return Analysis for [Contract / Vault]

### Can protocol return to zero state?
- [ ] All users can withdraw / burn shares (no locked funds)
- [ ] total_shares (i128) can reach exactly 0

### What persists when total_shares = 0?
- [ ] Accrued rewards / time-decay state: [amount / none]
- [ ] Protocol fees / ratio snapshots: [amount / none / resets]
- [ ] Token balance dust: [yes / no]
- [ ] Pending operations in Persistent storage: [list / none]
- [ ] Sub-contract allocations: [zeroed / residual]

### Re-entry vulnerability?
- [ ] Initial zero state protected: [yes / no / how]
- [ ] Return-to-zero state protected: [yes / no / how]
- [ ] Same protection mechanism: [yes / no]

### Exchange rate at return-to-zero:
- [ ] Formula: [show calculation using i128 values]
- [ ] With residual X: [panic? wrong value?]
- [ ] Can attacker inflate rate before re-entry: [yes / no]
```

## 5b. Default / Uninitialized State Values

For each state variable used in arithmetic or control flow, check its **initial value** before any user interaction:

- **Missing key returns None**: `e.storage().instance().get::<_, i128>(&DataKey::X)` returns `None` if never written. `unwrap()` panics; `unwrap_or(0)` silently treats as 0.
- **First-call path**: Trace FIRST invocation of each state-modifying function. Does it assume `initialize()` already set dependent keys?
- **Signed zero vs missing**: Soroban storage does NOT default to 0 — absent keys return `None`. Confusion between "key present with value 0" and "key absent" can cause bugs.

## 6. Code Patterns to Check

```rust
// Pattern 1: Guard covers initial zero only — what about return-to-zero?
if vault.total_shares == 0i128 {
    return Ok(1_000_000i128); // 1:1 rate
}
// QUESTION: What if total_shares returns to 0 but token balance > 0?

// Pattern 2: i128 exchange rate with division by zero
let rate = vault.total_value
    .checked_div(vault.total_shares)
    .ok_or(Error::DivisionByZero)?;
// QUESTION: What if total_value > 0 and total_shares = 0?

// Pattern 3: First deposit protection
if vault.total_shares == 0i128 {
    require!(deposit_amount >= MIN_FIRST_DEPOSIT, Error::DepositTooSmall);
}
// QUESTION: Does this fire for RE-deposits after full exit?

// Pattern 4: Time-decay state
let unlocked = vault.decay_amount * elapsed_ledgers / DECAY_DURATION_LEDGERS;
// QUESTION: Does decay_amount persist when total_shares = 0?
```

## 7. Finding Template

```markdown
**ID**: [ZS-N]
**Severity**: [typically HIGH if funds extractable]
**Location**: src/{file}.rs:LineN
**Title**: Return-to-zero state allows [attack] due to [residual state in storage]
**Description**:
- Protocol can return to total_shares=0 via [mechanism]
- When this happens, [storage key] retains value of [amount] (i128)
- A new depositor can [exploit path]
**Impact**: [Fund extraction / exchange rate manipulation / unfair distribution]
**PoC Scenario**:
1. Users deposit and earn rewards
2. All users withdraw, total_shares = 0i128
3. Residual state remains: {DataKey::DecayAmount} = X in Instance storage
4. Attacker deposits minimum amount
5. Attacker claims X rewards via inflated share-to-value ratio
```

## 8. Integration with ZERO_STATE_ECONOMICS

This skill does NOT replace ZERO_STATE_ECONOMICS. It EXTENDS it:

| Check | ZERO_STATE_ECONOMICS | ZERO_STATE_RETURN |
|-------|---------------------|-------------------|
| Initial zero state / first depositor | YES | — |
| Return to zero | — | YES |
| Residual assets (time-decay, fees, dust) | — | YES |
| Re-entry vulnerability | — | YES |
| i128 division-by-zero guards | YES (partial) | YES (both initial and return paths) |
| Missing storage key defaults | — | YES |

When applying ZERO_STATE_ECONOMICS, ALSO apply ZERO_STATE_RETURN.
