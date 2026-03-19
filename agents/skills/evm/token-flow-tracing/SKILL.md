---
name: "token-flow-tracing"
description: "Trigger Pattern transfer\|transferFrom\|safeTransfer\|mint\|burn\|balanceOf.this - Inject Into Lifecycle, External-Env agents"
---

# TOKEN_FLOW_TRACING Skill

> **Trigger Pattern**: `transfer\|transferFrom\|safeTransfer\|mint\|burn\|balanceOf.*this`
> **Inject Into**: Lifecycle, External-Env agents

For every token the protocol handles:

## 1. Token Entry Points

Where can tokens enter?
- `deposit()` / `stake()` functions - standard entry points
- Unsolicited transfers - direct `transfer()` to contract address (bypasses deposit logic)
- Callback receipts - `onERC721Received`, `onERC1155Received`, `onERC1155BatchReceived`
- `receive()` / `fallback()` for native ETH
- Side-effect receipts - tokens sent as part of external call (e.g., unstake returns tokens)

## 2. Token State Tracking

For each entry point:
- What state variable tracks the balance?
- Is `balanceOf(address(this))` used directly? → **Donation attack vector**
- Are tracked balances vs actual balances compared anywhere?
- Can tracked balance get out of sync with actual balance?

**Red flags**:
- Exchange rate calculations using `balanceOf(address(this))` directly
- No "skim" or "sync" function to reconcile discrepancies
- Accounting variables updated BEFORE token transfer completes

## 3. Token Exit Points

Where can tokens leave?
- `withdraw()` / `unstake()` functions
- Fee distributions to treasury/stakers
- Reward claims
- Emergency withdrawals / rescue functions
- Liquidation transfers

For each exit: does the tracked balance decrease BEFORE or AFTER the actual transfer?
For each transfer call: can the source address be underfunded at execution time? (funds deployed externally, locked, or lent out → transfer reverts)

### 3b. Self-Transfer Accounting
For each transfer function: can the sender and recipient be the same address?
If YES: does a self-transfer update accounting state (fees credited, rewards claimed, snapshots updated, share ratios changed) without net token movement? Flag as FINDING.

## 4. Token Type Separation (Multi-Token Protocols)

For protocols handling multiple token types:
- Are different token types handled by different code paths?
- Can one token type's code path be triggered with another type?
- Are approvals/allowances type-specific or shared?
- Does the protocol distinguish between:
  - Native vs wrapped (e.g., ETH vs WETH)
  - Legacy vs upgraded tokens (e.g., token migrations)
  - Base vs receipt tokens (e.g., underlying vs yield-bearing)
  - Staking receipt tokens (e.g., validator shares, LP tokens, delegation receipts)

**Check**: If function A handles TokenX and function B handles TokenY, can TokenX reach function B's logic? Also: within a single function, if some code paths branch on token type (e.g., input handling), do ALL code paths branch consistently (e.g., refund, fee, return)?

## 5. Unsolicited Transfer Analysis

Can tokens be sent to the contract without calling `deposit()`?

If **YES**:
- Does this break accounting? (tracked balance != actual balance)
- Does this inflate exchange rates? (more assets per share)
- Does this enable first-depositor attack amplification?
- Are there "skim" or "sync" functions to reconcile?
- Can an attacker front-run deposits with unsolicited transfers?

If **NO**:
- Why not? (rebasing token? transfer hook? access control?)
- Is the protection reliable? (can it be bypassed?)

## 5b. Unsolicited Transfer Matrix (All Token Types)

For EVERY external token type the protocol holds, queries, or receives as side effects - not just the protocol's primary token:

| Token Type | Can Transfer To Protocol? | Changes Protocol Accounting? | Blocks Operations? | Triggers Side Effects? |
|------------|--------------------------|-----------------------------|--------------------|----------------------|
| {token_a} | YES/NO | YES/NO | YES/NO | YES/NO |

**RULE**: If ANY token type is transferable to the protocol AND affects state → analyze each consequence:
- Accounting impact: Does tracked vs actual balance diverge?
- Iteration impact: Does the protocol iterate over sources of this token? (gas DoS vector)
- Operation blocking: Does non-zero balance of this token prevent admin operations?
- Side effect chain: Does receiving this token trigger further side effects (reward claims, state changes)?

## 6. Token Flow Checklist

For each token identified:

| Token | Entry Points | Exit Points | Tracking Var | balanceOf(this) Used? | Unsolicited Possible? |
|-------|--------------|-------------|--------------|----------------------|----------------------|
| [Name] | deposit, receive | withdraw, claim | totalDeposited | YES/NO | YES/NO |

## 7. Cross-Token Interactions

For protocols with multiple tokens:
- Can operations on TokenA affect TokenB's accounting?
- Are there exchange rate dependencies between tokens?
- Can withdrawing TokenA affect availability of TokenB?

## 8. External Call Return Type Verification

For every external call that returns tokens or values:

### 8a. Return Type Mismatch Check
- What token type does the protocol EXPECT to receive?
- What token type does the external contract ACTUALLY return?
- Are these the same token, or different representations?

**Common mismatches**:
- Legacy vs upgraded tokens (e.g., TokenV1 vs TokenV2 after migration)
- Native vs wrapped (e.g., ETH vs WETH)
- Bridged vs canonical (e.g., bridged USDC vs native USDC)
- Different decimal precision tokens

**Check**: `interface.function() returns (TokenA)` - verify TokenA is what's actually returned, not TokenB

### 8b. Return Value Validation
- Does the protocol validate return values before use?
- Can zero/max/unexpected returns cause issues?
- Is there a mismatch between documented and actual returns?

## 9. Transfer Side Effects Analysis

For every `transfer()` / `transferFrom()` call to external contracts:

### 9a. On-Transfer Behavior
- Does the token have transfer hooks? (ERC777, ERC1363)
- Does transfer trigger reward claims or state changes?
- Can transfer revert under certain conditions?

### 9b. Side Effect Inventory

| Token | On Transfer Side Effect | Impact on Protocol |
|-------|------------------------|-------------------|
| [Token] | Claims pending rewards | Unexpected balance increase |
| [Token] | Updates delegation state | Accounting mismatch |
| [Token] | Triggers rebase | Exchange rate affected |

### 9c. Specific Checks for Staking Receipts
- Does transferring staking receipts claim rewards automatically?
- Does transfer change the token's internal delegation accounting?
- Can side effects be exploited to inflate/deflate balances?

**Example**: Transferring staking receipt tokens (e.g., stETH, aTokens) may trigger rebases or reward claims as a side effect

### 9d. Side Effect Token Type Analysis

For each documented side effect that produces or claims tokens:

| External Call / Event | Side Effect | Token Type Produced | Protocol Handles This Type? | Mismatch? |
|-----------------------|-------------|--------------------|-----------------------------|-----------|
| {call_or_event} | {side_effect} | {token_type_or_UNKNOWN} | YES/NO | YES/NO |

**RULE**: If side effect token type != protocol's expected token type → FINDING (stranded tokens of wrong type)
**RULE**: If side effect token type is UNKNOWN → CONTESTED (assume adversarial per Rule 4)
**RULE**: Check BOTH direct calls AND unsolicited transfers for side effect token types

## Example Application

```solidity
// RED FLAG: Direct balance usage
uint256 rate = token.balanceOf(address(this)) / totalShares;

// BETTER: Tracked balance
uint256 rate = totalPooledTokens / totalShares;

// But check: is totalPooledTokens updated correctly on ALL entry paths?
```

## Finding Template

When this skill identifies an issue:

```markdown
**ID**: [LC-N] or [EX-N]
**Severity**: [based on fund impact]
**Step Execution**: ✓1,2,3,4,5,6,7,8,9 | ✗(reasons) | ?(uncertain)
**Location**: Contract.sol:LineN
**Title**: [Token type] can enter/exit via [path] without [expected accounting update]
**Description**: [Trace the token flow and where it diverges from expected]
**Impact**: [What breaks: exchange rates, user balances, protocol insolvency]
```

---

## Step Execution Checklist (MANDATORY)

> **CRITICAL**: You MUST report completion status for ALL sections. Findings with incomplete sections will be flagged for depth review.

| Section | Required | Completed? | Notes |
|---------|----------|------------|-------|
| 1. Token Entry Points | YES | ✓/✗/? | |
| 2. Token State Tracking | YES | ✓/✗/? | |
| 3. Token Exit Points | YES | ✓/✗/? | |
| 4. Token Type Separation | IF multi-token | ✓/✗(N/A)/? | |
| 5. Unsolicited Transfer Analysis | YES | ✓/✗/? | |
| 5b. Unsolicited Transfer Matrix (All Types) | **YES** | ✓/✗/? | **MANDATORY** - never skip |
| 6. Token Flow Checklist | YES | ✓/✗/? | |
| 7. Cross-Token Interactions | IF multi-token | ✓/✗(N/A)/? | |
| 8. External Call Return Type | **YES** | ✓/✗/? | **MANDATORY** - never skip |
| 9. Transfer Side Effects | **YES** | ✓/✗/? | **MANDATORY** - never skip |
| 9d. Side Effect Token Type | **YES** | ✓/✗/? | **MANDATORY** - never skip |

### Cross-Reference Markers

**After Section 5** (Unsolicited Transfer Analysis):
- IF staking receipts identified → **MUST complete Sections 8-9**
- IF external calls return tokens → **MUST verify return type in Section 8**

**After Section 8** (External Call Return Type):
- Cross-reference with `STAKING_RECEIPT_TOKENS.md` Section 8 for on-transfer side effects
- IF return type UNKNOWN in production → mark finding as CONTESTED

**After Section 9** (Transfer Side Effects):
- IF side effects UNKNOWN → assume YES (adversarial default per Rule 5)
- MUST document: "Assumed adversarial: [effect]. Impact if true: [trace]"

### Mandatory Forced Output

For Sections 8 and 9, you MUST produce output even if uncertain:

**Section 8 Output** (always required):
```markdown
### 8. External Call Return Type Verification
| External Call | Expected Return | Verified Production Return | Match? |
|--------------|-----------------|---------------------------|--------|
| [call] | [expected] | [verified/UNVERIFIED] | ✓/✗/? |

**If UNVERIFIED**: Finding verdict cannot be REFUTED. Use CONTESTED.
```

**Section 9 Output** (always required):
```markdown
### 9. Transfer Side Effects Analysis
| Token | On Transfer Side Effect | Verified? | Assumed Impact |
|-------|------------------------|-----------|----------------|
| [token] | [effect or UNKNOWN] | YES/NO | [impact trace] |

**Adversarial Default Applied**: [list assumptions made]
```
