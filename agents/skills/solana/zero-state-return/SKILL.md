---
name: "zero-state-return"
description: "Trigger Always inject into Arithmetic agent (extends existing ZERO_STATE_ECONOMICS) - Purpose Check protocol return-to-zero state, not just initial zero state"
---

# ZERO_STATE_RETURN Skill (Solana)

> **Trigger**: Always inject into Arithmetic agent (extends existing ZERO_STATE_ECONOMICS)
> **Purpose**: Check protocol return-to-zero state, not just initial zero state

## Overview

ZERO_STATE_ECONOMICS checks initial zero state. This skill EXTENDS it to cover:
- Protocol returning to zero after normal operations
- Residual assets when LP supply returns to zero
- Re-entry vulnerabilities after full exit

## 1. Return-to-Zero Scenarios

After normal operations, can the protocol return to:

| State | Trigger | Check |
|-------|---------|-------|
| `lp_supply == 0` | All users burned LP tokens / withdrew | Does this recreate first-depositor conditions? |
| `{protocol}.{total_tracked} == 0` | No funds deposited | Are there residual rewards or time-decay state? |
| Empty strategy set | All strategies removed / deallocated | Can protocol still function? |
| Zero liquidity | All LP withdrawn | What happens to accumulated fees / ratio snapshots? |

## 2. Residual Asset Check

When LP supply returns to zero, check for:

### 2a. Accrued Rewards / Time-Decay State
- Do rewards or time-decay state (locked profit, vesting, streaming) persist when LP supply = 0?
- If yes -> inflates exchange rate for next depositor
- Example: Protocol accrues 100 SOL in rewards, last user exits, LP supply = 0, next deposit of 1 lamport receives claim to 100 SOL

### 2b. Unclaimed Fees / Ratio Snapshot State
- Are there fee balances (performance fees, management fees) that persist?
- Do ratio snapshots (high water marks, benchmark prices) reset when all LP is burned?
- Can first new depositor capture accumulated fees?

### 2c. Dust in Token Accounts
- Can dust (tiny lamport/token amounts) remain in PDA-owned token accounts?
- Does dust affect exchange rate calculations when LP supply = 0?
- Example: LP supply = 0, vault token account has 1 lamport dust, exchange rate undefined or manipulable

### 2d. Pending Operations
- Are there pending withdrawal receipts or claim tickets that persist?
- What happens to in-flight strategy deallocations when LP supply hits zero?
- Do strategy accounts retain allocated funds after all LP is burned?

## 3. Re-Entry Vulnerability Analysis

Does re-entering zero state recreate first-depositor attack conditions?

| Scenario | Initial State | Return-to-Zero State | Same Vulnerability? |
|----------|---------------|---------------------|---------------------|
| First depositor attack | lp_supply=0, total_tracked=0 | lp_supply=0, total_tracked=X (residual) | **WORSE** if residual > 0 |
| Exchange rate manipulation | No LP exists | No LP, but token account has balance | YES + amplified |
| Donation attack | Clean state | Dirty state (dust, residual) | YES + pre-seeded |

**Key question**: Does first-depositor protection (minimum deposit, burned shares) apply only on first `initialize` or also on return-to-zero re-deposits?

## 4. Protocol Reset Functions

Check for admin/authority instructions that can force zero state:

- `emergency_withdraw()` - does it clear ALL state (total tracked, time-decay state, ratio snapshots)?
- `close_vault()` - what state persists in remaining accounts?
- `migrate()` - does old program retain residual token account balances?
- `force_deallocate()` - can it create accounting mismatch between vault state and token accounts?

For each: what state persists after the "reset"?

## 5. Zero-State Return Checklist

```markdown
## Zero-State Return Analysis for [ProgramName / Vault]

### Can protocol return to zero state?
- [ ] All users can withdraw / burn LP (no locked funds)
- [ ] All LP tokens can be burned
- [ ] LP supply can reach exactly zero

### What persists when LP supply = 0?
- [ ] Accrued rewards / time-decay state: [amount/none]
- [ ] Protocol fees / ratio snapshots: [amount/none/resets]
- [ ] Dust in token accounts: [yes/no]
- [ ] Pending operations / withdrawal receipts: [list/none]
- [ ] Strategy allocations: [zeroed/residual]

### Re-entry vulnerability?
- [ ] Initial zero state protected: [yes/no/how]
- [ ] Return-to-zero state protected: [yes/no/how]
- [ ] Same protection mechanism: [yes/no]

### Exchange rate at return-to-zero:
- [ ] Formula: [show calculation]
- [ ] With residual X: [show calculation]
- [ ] Can attacker inflate rate before re-entry: [yes/no]
```

## 5b. Default/Uninitialized State Values

For each state variable used in arithmetic or control flow, check its **initial value** before any user interaction:

- **Default zero**: Uninitialized account fields default to 0. If a function uses `last_timestamp`, `start_time`, or `last_update` in subtraction or division BEFORE it has ever been set, the result may be unexpected (e.g., `clock.unix_timestamp - 0` = enormous elapsed time, or division by a value derived from 0).
- **First-call path**: Trace the FIRST invocation of each state-modifying instruction. Does it assume a prior instruction already initialized dependent fields?
- **Check**: For each field read in an instruction, is there a code path where that field still holds its default value (0, Pubkey::default(), false)? If yes, does the instruction behave correctly with that default?

## 6. Code Patterns to Check

```rust
// Pattern 1: Check covers initial zero only
if vault.total_shares == 0 {
    return Ok(1_000_000); // 1:1 rate (scaled)
}
// QUESTION: What if total_shares returns to 0 with token_account.amount > 0?

// Pattern 2: Exchange rate with balance
let rate = vault.total_value
    .checked_div(vault.total_shares)
    .ok_or(ErrorCode::DivisionByZero)?;
// QUESTION: What if total_value > 0 and total_shares = 0?
// QUESTION: What if both return to 0 but at different slots?

// Pattern 3: First deposit protection
require!(
    vault.total_shares > 0 || ctx.accounts.deposit_amount >= MIN_FIRST_DEPOSIT,
    ErrorCode::DepositTooSmall
);
// QUESTION: Does this check exist for RE-deposits after full exit?

// Pattern 4: Time-decay state
let unlocked = vault.decay_state * elapsed / DECAY_DURATION;
// QUESTION: Does decay state persist when total_shares = 0?
// QUESTION: Next depositor inherits unlocked value?
```

## 7. Finding Template

```markdown
**ID**: [ZS-N]
**Severity**: [typically HIGH if funds extractable]
**Location**: programs/{program}/src/instructions/{file}.rs:LineN
**Title**: Return-to-zero state allows [attack] due to [residual state]
**Description**:
- Protocol can return to lp_supply=0 via [mechanism]
- When this happens, [state variable] retains value of [amount]
- A new depositor can [exploit path]
**Impact**: [Fund extraction / exchange rate manipulation / unfair distribution]
**PoC Scenario**:
1. Users deposit and earn rewards
2. All users withdraw, LP supply = 0
3. Residual state remains: {time_decay_var} = X
4. Attacker deposits minimum amount
5. Attacker claims X rewards via inflated exchange rate
```

## 8. Integration with ZERO_STATE_ECONOMICS

This skill does NOT replace ZERO_STATE_ECONOMICS. It EXTENDS it:

| Check | ZERO_STATE_ECONOMICS | ZERO_STATE_RETURN |
|-------|---------------------|-------------------|
| Initial zero state | YES | - |
| First depositor attack | YES | - |
| Return to zero | - | YES |
| Residual assets (time-decay state, fees, dust) | - | YES |
| Re-entry vulnerability | - | YES |

When applying ZERO_STATE_ECONOMICS, ALSO apply ZERO_STATE_RETURN.
