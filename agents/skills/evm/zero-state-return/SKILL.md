---
name: "zero-state-return"
description: "Trigger Always inject into Arithmetic agent (extends existing ZERO_STATE_ECONOMICS) - Purpose Check protocol return-to-zero state, not just initial zero state"
---

# ZERO_STATE_RETURN Skill

> **Trigger**: Always inject into Arithmetic agent (extends existing ZERO_STATE_ECONOMICS)
> **Purpose**: Check protocol return-to-zero state, not just initial zero state

## Overview

ZERO_STATE_ECONOMICS checks initial zero state. This skill EXTENDS it to cover:
- Protocol returning to zero after normal operations
- Residual assets when supply returns to zero
- Re-entry vulnerabilities after full exit

## 1. Return-to-Zero Scenarios

After normal operations, can the protocol return to:

| State | Trigger | Check |
|-------|---------|-------|
| `totalSupply == 0` | All users withdrew/burned | Does this recreate first-depositor conditions? |
| `totalPooledAmount == 0` | No funds staked | Are there residual rewards? |
| Empty validator set | All validators removed | Can protocol still function? |
| Zero liquidity | All LP withdrawn | What happens to accumulated fees? |

## 2. Residual Asset Check

When supply returns to zero, check for:

### 2a. Accrued Rewards
- Do rewards persist when totalSupply = 0?
- If yes → inflates exchange rate for next depositor
- Example: Protocol accrues 100 ETH rewards, last user exits, totalSupply = 0, next deposit of 1 wei receives claim to 100 ETH

### 2b. Unclaimed Fees
- Are there fee balances that persist?
- Can first new depositor capture accumulated fees?
- Example: Protocol fees = 10 ETH, users exit, new depositor claims all fees

### 2c. Dust Balances
- Can dust (tiny amounts) affect exchange rate calculations?
- Example: totalSupply = 0, dust balance = 1 wei, exchange rate undefined or manipulable

### 2d. Pending Operations
- Are there pending withdrawals/claims that persist?
- What happens to in-flight operations when supply hits zero?

## 3. Re-Entry Vulnerability Analysis

Does re-entering zero state recreate first-depositor attack conditions?

| Scenario | Initial State | Return-to-Zero State | Same Vulnerability? |
|----------|---------------|---------------------|---------------------|
| First depositor attack | totalSupply=0, totalAssets=0 | totalSupply=0, totalAssets=X (residual) | **WORSE** if residual > 0 |
| Exchange rate manipulation | No shares exist | No shares, but balance exists | YES + amplified |
| Donation attack | Clean state | Dirty state | YES + pre-seeded |

## 4. Protocol Reset Functions

Check for admin functions that can force zero state:

- `emergencyWithdraw()` - does it clear ALL state?
- `rescueTokens()` - can it create accounting mismatch?
- `pause()` + `drain()` - what state remains after?
- `migrate()` - does old contract have residuals?

For each: what state persists after the "reset"?

## 5. Zero-State Return Checklist

```markdown
## Zero-State Return Analysis for [ContractName]

### Can protocol return to zero state?
- [ ] All users can withdraw (no locked funds)
- [ ] All shares can be burned
- [ ] Supply can reach exactly zero

### What persists when supply = 0?
- [ ] Accrued rewards: [amount/none]
- [ ] Protocol fees: [amount/none]
- [ ] Dust balances: [yes/no]
- [ ] Pending operations: [list/none]

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

- **Default zero**: Solidity initializes to 0. If a function uses `lastTimestamp`, `startTime`, or `lastUpdate` in subtraction or division BEFORE it has ever been set, the result may be unexpected (e.g., `block.timestamp - 0` = enormous elapsed time, or division by a value derived from 0).
- **First-call path**: Trace the FIRST invocation of each state-modifying function. Does it assume a prior call already initialized dependent variables?
- **Check**: For each variable read in a function, is there a code path where that variable still holds its default value (0, address(0), false)? If yes, does the function behave correctly with that default?

## 6. Code Patterns to Check

```solidity
// Pattern 1: Check covers initial zero only
if (totalSupply == 0) {
    return 1e18; // 1:1 rate
}
// QUESTION: What if totalSupply returns to 0 with balance > 0?

// Pattern 2: Exchange rate with balance
uint256 rate = totalAssets / totalSupply;
// QUESTION: What if totalAssets > 0 and totalSupply = 0 (division by zero)
// QUESTION: What if both return to 0 but at different times?

// Pattern 3: First deposit protection
require(totalSupply > 0 || msg.value >= MIN_FIRST_DEPOSIT);
// QUESTION: Does this check exist for RE-deposits after full exit?
```

## 7. Finding Template

```markdown
**ID**: [AR-N]
**Severity**: [typically HIGH if funds extractable]
**Location**: Contract.sol:LineN
**Title**: Return-to-zero state allows [attack] due to [residual state]
**Description**:
- Protocol can return to totalSupply=0 via [mechanism]
- When this happens, [state variable] retains value of [amount]
- A new depositor can [exploit path]
**Impact**: [Fund extraction / exchange rate manipulation / unfair distribution]
**PoC Scenario**:
1. Users deposit and earn rewards
2. All users withdraw, totalSupply = 0
3. Rewards remain: totalRewards = X
4. Attacker deposits 1 wei
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

When applying ZERO_STATE_ECONOMICS, ALSO apply ZERO_STATE_RETURN.
