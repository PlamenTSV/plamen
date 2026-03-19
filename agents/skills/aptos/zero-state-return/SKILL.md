---
name: "zero-state-return"
description: "Trigger Pattern Vault/pool/first-depositor pattern detected - Inject Into Depth-edge-case"
---

# ZERO_STATE_RETURN Skill

> **Trigger Pattern**: Vault/pool/first-depositor pattern detected
> **Inject Into**: Depth-edge-case
> **Purpose**: Analyze zero-state transitions in Aptos Move protocols -- initial zero state, return to zero after operations, residual assets, and re-entry vulnerabilities

## Overview

This skill covers BOTH initial zero state AND return-to-zero-state analysis:
- Protocol initialization and first deposit conditions
- Protocol returning to zero after normal operations
- Residual assets when supply returns to zero
- Re-entry vulnerabilities after full exit

## 1. Identify Zero-State Transitions

Find all vault/pool/staking mechanisms and their zero-state boundaries:

| State | Resource / Variable | Zero Condition | Trigger | Code Location |
|-------|-------------------|----------------|---------|---------------|
| Total shares | {resource.total_supply} | `== 0` | All users withdrew/burned | {module:line} |
| Total assets | {resource.total_assets} | `== 0` | No funds deposited | {module:line} |
| Pool liquidity | {resource.reserves} | Both reserves `== 0` | All LP withdrawn | {module:line} |
| Staking pool | {resource.total_staked} | `== 0` | All unstaked | {module:line} |

For each state: what is the protocol behavior when this condition is true?

## 2. First Depositor Analysis

Can the first depositor manipulate share price?

### 2a. Share Minting Formula at Zero State

| Protocol | Formula | When totalShares == 0 | First Deposit Behavior |
|----------|---------|----------------------|----------------------|
| {name} | `shares = amount * totalShares / totalAssets` | {special case?} | {describe} |

**Classic first depositor attack on Aptos**:
1. First depositor deposits minimal amount (e.g., 1 unit)
2. Attacker directly deposits tokens to the protocol's FungibleStore (unsolicited -- bypasses accounting)
3. Exchange rate inflates: `totalAssets` increases but `totalShares` stays at 1
4. Next depositor receives 0 shares due to rounding (their deposit amount < inflated share price)
5. First depositor withdraws, capturing the second depositor's funds

**Checks**:
- [ ] Is there a minimum first deposit requirement?
- [ ] Does the protocol use virtual shares/assets (e.g., add 1 to both numerator and denominator)?
- [ ] Is there a dead shares mechanism (burn initial shares to zero address)?
- [ ] Can unsolicited deposits to the protocol's store inflate `totalAssets`?
- [ ] Does the protocol use internal accounting (resistant) or direct balance queries (vulnerable)?

### 2b. First Deposit Protection Mechanisms

| Protection | Present? | Implementation | Bypass Possible? |
|-----------|----------|----------------|-----------------|
| Minimum first deposit | YES/NO | {code ref} | {analysis} |
| Virtual shares/assets offset | YES/NO | {code ref} | {analysis} |
| Dead shares (initial mint to zero) | YES/NO | {code ref} | {analysis} |
| Internal accounting (not balance-based) | YES/NO | {code ref} | {analysis} |
| Decimal offset in share calculation | YES/NO | {code ref} | {analysis} |

## 3. Return to Zero Analysis

After normal operations, can the protocol return to zero state?

### 3a. Return-to-Zero Scenarios

| Scenario | Trigger | Residual State After | Re-entry Safe? |
|----------|---------|---------------------|---------------|
| All shares redeemed | Last user withdraws | {what remains?} | YES/NO |
| Emergency withdraw | Admin drains | {what remains?} | YES/NO |
| All stakers unstake | Last unstake | {what remains?} | YES/NO |
| Pool fully drained | All LP removed | {what remains?} | YES/NO |

### 3b. Can Total Shares Reach Exactly Zero?

Trace the withdrawal/burn path:
- Can the last user withdraw ALL their shares? (no minimum balance lock?)
- Does the protocol enforce a minimum share amount that prevents reaching zero?
- If dead shares exist, `totalShares` never reaches 0 -- is this protection consistent?

## 4. Residual Asset Check

When supply returns to zero, check for stranded value:

### 4a. Accrued Rewards

| Reward Source | Persists When totalShares = 0? | Claimable By Next Depositor? | Amount Bounded? |
|-------------|-------------------------------|-----------------------------:|----------------|
| {reward_source} | YES/NO | YES/NO | {max amount or UNBOUNDED} |

If rewards persist AND next depositor can claim -> FINDING (severity based on amount).

### 4b. Unclaimed Fees

| Fee Type | Persists When totalShares = 0? | Captured By Next Depositor? | Reconciliation Mechanism? |
|----------|-------------------------------|----------------------------|--------------------------|
| {fee_type} | YES/NO | YES/NO | {mechanism or NONE} |

### 4c. Dust Balances

- Can dust (sub-unit amounts) remain in FungibleStore after all withdrawals?
- Does dust affect exchange rate calculations on re-entry? (e.g., `totalAssets = 1 wei, totalShares = 0`)
- Does the protocol handle `totalAssets > 0 AND totalShares == 0` explicitly?

### 4d. Pending Operations

- Are there pending withdrawals/claims that persist after zero state?
- What happens to in-flight multi-step operations when supply hits zero?
- Are there resources or objects that reference the pool/vault state that become orphaned?

## 5. Re-Entry Vulnerability Analysis

Does re-entering zero state recreate first-depositor attack conditions?

| Scenario | Initial State | Return-to-Zero State | Same Vulnerability? |
|----------|---------------|---------------------|---------------------|
| First depositor attack | totalSupply=0, totalAssets=0 | totalSupply=0, totalAssets=X (residual) | **WORSE** if residual > 0 |
| Exchange rate manipulation | No shares exist | No shares, but balance exists | YES + amplified |
| Donation attack | Clean state | Dirty state | YES + pre-seeded |

**Key question**: Is the first-deposit protection (from Section 2b) applied ONLY on initial deployment, or does it also trigger when `totalShares` returns to 0?

Trace the share minting code:
```
// Pattern: Protection covers initial AND return-to-zero
if (total_shares == 0) {
    // First deposit logic with protection
}

// vs Pattern: Protection only on first-ever deposit
if (!initialized) {
    // Protection here
} else if (total_shares == 0) {
    // NO protection -- vulnerable on return-to-zero
}
```

## 5b. Default/Uninitialized State Values

For each state field used in arithmetic or control flow, check its **initial value** before any user interaction:

- **Default zero**: Move initializes struct fields to their declared defaults (typically 0 for integers, `@0x0` for addresses). If a function uses `last_timestamp`, `start_time`, or `last_update` in subtraction or division BEFORE it has ever been set, the result may be unexpected (e.g., `timestamp::now_seconds() - 0` = enormous elapsed time, or division by a value derived from 0).
- **First-call path**: Trace the FIRST invocation of each state-modifying function. Does it assume a prior call already initialized dependent fields?
- **Check**: For each field read in a function, is there a code path where that field still holds its default value (0, @0x0, false)? If yes, does the function behave correctly with that default?

## 6. Empty Pool Edge Cases

### 6a. Division by Zero

| Expression | When totalShares = 0 | Behavior | Impact |
|-----------|---------------------|----------|--------|
| `amount * totalShares / totalAssets` | 0 / totalAssets | Returns 0 | {impact} |
| `amount * totalAssets / totalShares` | amount * X / 0 | **ABORT** | {DoS, broken withdrawal} |
| `rewards / totalShares` | rewards / 0 | **ABORT** | {reward distribution broken} |

For each division: is there a zero-check guard? If not, what transaction aborts?

### 6b. Zero-Amount Operations at Zero State

| Operation | At Zero State | Result | Expected? |
|-----------|--------------|--------|-----------|
| deposit(0) at totalShares=0 | {behavior} | {shares issued?} | {analysis} |
| withdraw(0) at totalShares=0 | {behavior} | {aborts?} | {analysis} |
| claim_rewards() at totalShares=0 | {behavior} | {rewards distributed?} | {analysis} |

## 7. Protocol Reset Functions

Check for admin functions that can force zero state:

| Function | Access Control | Clears All State? | Residual After Reset |
|----------|---------------|-------------------|---------------------|
| {emergency_withdraw_fn} | {who} | YES/NO | {what remains} |
| {rescue_tokens_fn} | {who} | YES/NO | {what remains} |
| {pause + drain_fn} | {who} | YES/NO | {what remains} |
| {migrate_fn} | {who} | YES/NO | {what remains in old module} |

For each: what state persists after the "reset"? Can it be exploited?

## Instantiation Parameters
```
{CONTRACTS}              -- Move modules containing vault/pool logic
{SHARE_VARIABLES}        -- Variables tracking total shares/supply
{ASSET_VARIABLES}        -- Variables tracking total assets/deposits
{SHARE_MINT_FORMULA}     -- Share calculation formula at deposit
{FIRST_DEPOSIT_GUARDS}   -- Existing first-deposit protections
```

## Finding Template

```markdown
**ID**: [ZS-N]
**Severity**: [typically HIGH if funds extractable, MEDIUM if DoS]
**Step Execution**: checkmark1,2,3,4,5,6,7 | x(reasons) | ?(uncertain)
**Rules Applied**: [R4:Y, R10:Y, R11:Y]
**Location**: module::function:LineN
**Title**: [Zero-state type] allows [attack] due to [residual state / missing protection]
**Description**:
- Protocol can reach totalShares=0 via [mechanism]
- When this happens, [state variable] retains value of [amount]
- A new depositor can [exploit path]
**Impact**: [Fund extraction / exchange rate manipulation / DoS]
```

## Output Schema

| Field | Required | Description |
|-------|----------|-------------|
| zero_state_transitions | yes | All paths to zero state |
| first_depositor_analysis | yes | First deposit attack assessment |
| residual_assets | yes | What persists after zero state |
| re_entry_vulnerability | yes | Whether return-to-zero recreates first-depositor conditions |
| edge_cases | yes | Division by zero and zero-amount operations |
| finding | yes | CONFIRMED / REFUTED / CONTESTED |
| evidence | yes | Code locations with line numbers |
| step_execution | yes | Status for each step |

---

## Step Execution Checklist (MANDATORY)

| Section | Required | Completed? | Notes |
|---------|----------|------------|-------|
| 1. Identify Zero-State Transitions | YES | Y/x/? | |
| 2. First Depositor Analysis | YES | Y/x/? | Including 2a formula + 2b protections |
| 3. Return to Zero Analysis | YES | Y/x/? | Including 3a scenarios + 3b exact zero trace |
| 4. Residual Asset Check | YES | Y/x/? | All sub-checks: 4a rewards, 4b fees, 4c dust, 4d pending |
| 5. Re-Entry Vulnerability Analysis | YES | Y/x/? | Compare initial vs return-to-zero protections |
| 6. Empty Pool Edge Cases | YES | Y/x/? | Division by zero + zero-amount ops |
| 7. Protocol Reset Functions | IF admin reset exists | Y/x(N/A)/? | |

### Cross-Reference Markers

**After Section 2** (First Depositor): Cross-reference with `TOKEN_FLOW_TRACING.md` Section 5 for unsolicited deposit vectors that amplify first-depositor attacks.

**After Section 4** (Residual Assets): If residual rewards/fees found, cross-reference with `ECONOMIC_DESIGN_AUDIT.md` for whether fee/reward accumulation is bounded.

**After Section 5** (Re-Entry): If return-to-zero is possible AND first-deposit protection is initial-only -> FINDING (minimum Medium, upgrade to High if unsolicited deposits can amplify).
