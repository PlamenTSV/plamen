---
name: "token-flow-tracing"
description: "Trigger Pattern SPL token CPI transfers, token_account.amount, invoke/invoke_signed, Transfer/TransferChecked - Inject Into Lifecycle, External-Env agents"
---

# TOKEN_FLOW_TRACING Skill (Solana)

> **Trigger Pattern**: SPL token CPI transfers, `token_account.amount`, `invoke`/`invoke_signed`, `Transfer`/`TransferChecked`
> **Inject Into**: Lifecycle, External-Env agents

For every token the protocol handles:

## 1. Token Entry Points

Where can tokens enter?
- `deposit()` / `stake()` instructions - standard entry points via CPI to Token Program
- Unsolicited SPL transfers - anyone can transfer SPL tokens to any known token account address
- SOL lamport donations - anyone can transfer lamports to any account (system_program::transfer or direct)
- CPI return tokens - tokens sent back as part of external CPI (e.g., unstake returns tokens, swap output)
- PDA-owned token accounts - tokens arriving at program-derived token accounts

## 2. Token State Tracking

For each entry point:
- What state variable tracks the balance? (e.g., `vault.total_value`, `pool.total_deposited`)
- Is `token_account.amount` read directly for calculations? -> **Donation attack vector**
- Are tracked balances vs actual `token_account.amount` compared anywhere?
- Can tracked balance get out of sync with actual token account balance?

**Red flags**:
- Exchange rate calculations using `token_account.amount` directly
- No reconciliation mechanism to handle discrepancies
- Internal accounting updated BEFORE CPI transfer completes
- PDA token accounts readable by anyone - balance is public state

## 3. Token Exit Points

Where can tokens leave?
- `withdraw()` / `unstake()` instructions
- Fee distributions to treasury/authority accounts
- Reward claim instructions
- Emergency withdrawal / rescue instructions
- CPI transfers to external adaptors or strategy programs
- Liquidation transfers

For each exit: does the tracked balance decrease BEFORE or AFTER the CPI transfer?
For each transfer call: can the source account be underfunded at execution time? (funds deployed externally, locked, or lent out → transfer reverts)

### 3b. Self-Transfer Accounting
For each transfer instruction: can the source and destination token accounts belong to the same owner/authority, or be the same account?
If YES: does a self-transfer update accounting state (fees credited, rewards claimed, snapshots updated, share ratios changed) without net token movement? Flag as FINDING. Note: this check targets accounting manipulation from self-transfers, distinct from the account key uniqueness validation in ACCOUNT_VALIDATION.md's Self-Transfer Risk column.

## 4. Token Type Separation (Multi-Token Protocols)

For protocols handling multiple token types:
- Are different SPL tokens handled by different code paths?
- Can one token type's instruction be triggered with another token's accounts?
- Are account constraints (mint, authority) properly validated per token type?
- Does the protocol distinguish between:
  - SOL (native lamports) vs SPL tokens (token accounts)
  - Base SPL vs Token-2022 tokens (different program IDs)
  - Base token vs LP/receipt token (underlying vs yield-bearing)
  - Staking receipt tokens (validator stake, LP shares, delegation receipts)

**Check**: If instruction A handles MintX and instruction B handles MintY, can MintX accounts be passed to instruction B's logic?

## 5. Unsolicited Transfer Analysis

Can tokens be sent to the protocol's token accounts without calling `deposit()`?

If **YES** (almost always YES on Solana):
- Does this break accounting? (tracked balance != actual `token_account.amount`)
- Does this inflate exchange rates? (more assets per share)
- Does this enable first-depositor attack amplification?
- Are there reconciliation instructions to sync state?
- Can an attacker front-run deposits with unsolicited transfers?

If **NO**:
- Why not? (Token-2022 TransferHook rejecting? PDA authority required for receives?)
- Is the protection reliable? (can it be bypassed?)

## 5b. Unsolicited Transfer Matrix (All Token Types)

For EVERY token type the protocol holds, queries, or receives - including SOL lamports:

| Token Type | Can Transfer To Protocol? | Changes Accounting? | Blocks Operations? | Triggers Side Effects? |
|------------|--------------------------|--------------------|--------------------|----------------------|
| SOL (lamports) | YES (always) | YES/NO | YES/NO | YES/NO |
| {spl_token_a} | YES/NO | YES/NO | YES/NO | YES/NO |

**RULE**: If ANY transferable token affects state -> analyze: accounting divergence, rent impact, operation blocking, side effect chains.

## 6. Token Flow Checklist

For each token identified:

| Token | Entry Points | Exit Points | Tracking Var | token_account.amount Used? | Unsolicited Possible? |
|-------|--------------|-------------|--------------|---------------------------|----------------------|
| [Name/Mint] | deposit, CPI return | withdraw, claim | total_deposited | YES/NO | YES/NO |

## 7. Cross-Token Interactions

For protocols with multiple tokens:
- Can operations on TokenA affect TokenB's accounting?
- Are there exchange rate dependencies between tokens (SOL vs SPL, base vs LP)?
- Can withdrawing TokenA affect availability of TokenB?
- Can SOL lamport balance affect SPL token operations (rent exemption)?

## 8. CPI Return Type Verification

For every CPI call that returns tokens or modifies accounts:

### 8a. CPI Target Verification
- What program does the CPI target? Is the program ID validated?
- What accounts does the CPI expect modified? Are they verified post-CPI?

**Common mismatches**:
- Token Program vs Token-2022 Program (different program IDs, different behavior)
- Spoofed program ID (attacker-controlled program mimicking expected interface)
- Wrong mint account (different token received than expected)
- Different decimal precision tokens

**Check**: `invoke_signed(&instruction, &[accounts...])` - verify the target program and returned account state match expectations.

### 8b. Return Value / Account State Validation
- Does the protocol validate account state after CPI completes?
- Can zero/max/unexpected balances cause issues?
- Is there a mismatch between expected and actual post-CPI state?

## 9. Transfer Side Effects Analysis

For every CPI transfer to external programs:

### 9a. On-Transfer Behavior
- Does the token use Token-2022 TransferHook extension? (arbitrary code execution on transfer)
- Does the token use TransferFee extension? (amount received != amount sent)
- Does the token have PermanentDelegate? (delegate can transfer without owner approval)
- Can CPI transfer trigger state mutations in external programs?

### 9b. Side Effect Inventory

| Token / Mint | On Transfer Side Effect | Impact on Protocol |
|--------------|------------------------|-------------------|
| [Token] | TransferHook executes arbitrary CPI | Potential reentrancy / state corruption |
| [Token] | TransferFee withholds portion | Accounting mismatch (sent != received) |
| [Token] | PermanentDelegate can move tokens | Tokens can leave without protocol consent |

### 9c. Token-2022 Extension Checks
- TransferHook: unexpected CU consumption (DoS)? TransferFee: accounting drift? PermanentDelegate: unauthorized drains? ConfidentialTransfer: hidden balances?

### 9d. Side Effect Token Type Analysis

| CPI Call / Event | Side Effect | Token Type Produced | Protocol Handles This Type? | Mismatch? |
|------------------|-------------|--------------------|-----------------------------|-----------|
| {cpi_call} | {side_effect} | {token_type_or_UNKNOWN} | YES/NO | YES/NO |

**RULES**: Side effect type != expected -> FINDING. Type UNKNOWN -> CONTESTED (Rule 4). Check BOTH CPI calls AND unsolicited transfers.

## Example Application

```rust
// RED FLAG: Direct balance usage - donatable
let rate = ctx.accounts.vault_token.amount / vault.total_shares;
// BETTER: Tracked balance - but verify total_deposited updated on ALL entry paths
let rate = vault.total_deposited / vault.total_shares;
```

## Finding Template

When this skill identifies an issue:

```markdown
**ID**: [TF-N]
**Severity**: [based on fund impact]
**Step Execution**: S1,2,3,4,5,6,7,8,9 | X(reasons) | ?(uncertain)
**Location**: program/src/instructions/file.rs:LineN
**Title**: [Token type] can enter/exit via [path] without [expected accounting update]
**Description**: [Trace the token flow and where it diverges from expected]
**Impact**: [What breaks: exchange rates, user balances, protocol insolvency]
```

---

## Step Execution Checklist (MANDATORY)

> **CRITICAL**: You MUST report completion status for ALL sections. Findings with incomplete sections will be flagged for depth review.

| Section | Required | Completed? | Notes |
|---------|----------|------------|-------|
| 1. Token Entry Points | YES | Y/X/? | |
| 2. Token State Tracking | YES | Y/X/? | |
| 3. Token Exit Points | YES | Y/X/? | |
| 4. Token Type Separation | IF multi-token | Y/X(N/A)/? | |
| 5. Unsolicited Transfer Analysis | YES | Y/X/? | |
| 5b. Unsolicited Transfer Matrix (All Types) | **YES** | Y/X/? | **MANDATORY** - never skip |
| 6. Token Flow Checklist | YES | Y/X/? | |
| 7. Cross-Token Interactions | IF multi-token | Y/X(N/A)/? | |
| 8. CPI Return Type Verification | **YES** | Y/X/? | **MANDATORY** - never skip |
| 9. Transfer Side Effects (Token-2022) | **YES** | Y/X/? | **MANDATORY** - never skip |
| 9d. Side Effect Token Type | **YES** | Y/X/? | **MANDATORY** - never skip |

### Cross-Reference Markers

- **After Section 5**: IF staking receipts identified -> MUST complete Sections 8-9. IF CPI calls return tokens -> MUST verify return state in Section 8.
- **After Section 8**: Cross-reference with `TOKEN_2022_EXTENSIONS.md` for TransferHook/TransferFee. IF program ID UNVERIFIED -> mark CONTESTED.
- **After Section 9**: IF side effects UNKNOWN -> assume YES (adversarial default per Rule 5). Document: "Assumed adversarial: [effect]. Impact if true: [trace]"

### Mandatory Forced Output

Sections 8 and 9 MUST produce tabular output even if uncertain. If UNVERIFIED: verdict cannot be REFUTED, use CONTESTED. If side effects UNKNOWN: apply adversarial default and document assumptions.
