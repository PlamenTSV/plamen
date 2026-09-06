---
name: "token-flow-tracing"
description: "Trigger Pattern SEP-41 token transfers, TokenClient::new, transfer/transfer_from/burn, XLM native balance - Inject Into Lifecycle, External-Env agents"
---

# TOKEN_FLOW_TRACING Skill (Soroban)

> **Trigger Pattern**: SEP-41 `transfer`/`transfer_from`/`approve`/`burn`, `TokenClient::new`, XLM native balance, SAC interactions
> **Inject Into**: Breadth agents, depth-token-flow
> **Finding prefix**: `[TF-N]`
> **Rules referenced**: R4, R5, R10, R11

For every token the protocol handles:

## 1. Token Entry Points

Where can tokens enter?

- `deposit()` / `stake()` functions — explicit entry via `token_client.transfer_from(user, contract, amount)` or `token_client.transfer(user, contract_address, amount)`
- Unsolicited SEP-41 transfers — anyone can call `token.transfer(sender, contract_address, amount)` directly; the contract has no hook to reject it
- XLM native balance — anyone can send XLM to the contract's Stellar account; the contract reads this via `e.current_contract_address().balance()` or a token client wrapping the XLM SAC
- Return tokens from cross-contract calls — tokens returned as output of `invoke_contract` (e.g., swap output, unstake return)
- Allowance-based pulls — contract holds an approved allowance; tokens pulled via `transfer_from` into the contract

**Soroban-specific note**: Unlike Solana, there are no token account PDAs. The contract address IS the recipient. Unsolicited transfers arrive directly to `e.current_contract_address()` and are undetectable without an explicit balance snapshot before and after calls.

## 2. Token State Tracking

For each entry point:
- What state variable tracks the balance? (e.g., `e.storage().instance().get(&DataKey::TotalDeposited)`)
- Is `token_client.balance(contract_address)` read directly for calculations? → **Donation attack vector**
- Are tracked balances vs actual `token_client.balance()` compared anywhere?
- Can tracked balance get out of sync with actual on-chain balance?

**Red flags**:
- Exchange rate calculations using `token_client.balance(e.current_contract_address())` directly
- No reconciliation mechanism to handle unsolicited-transfer discrepancies
- Internal accounting updated BEFORE the cross-contract token transfer executes
- Balance read at function start, transfer happens mid-function, balance read again — reentrancy window (Soroban is reentrant via `invoke_contract`)

## 3. Token Exit Points

Where can tokens leave?

- `withdraw()` / `unstake()` functions
- Fee distributions to treasury address
- Reward claim functions
- Emergency withdrawal / rescue functions
- Cross-contract `invoke_contract` calls that transfer tokens as part of the call
- Liquidation transfers

For each exit:
- Does the tracked balance decrease BEFORE or AFTER `token_client.transfer()` executes?
- Can the contract be underfunded at execution time? (funds lent to external contracts, reserved for pending withdrawals)
- Does the function re-read the live balance after transferring, creating a post-transfer snapshot inconsistency?

### 3b. Self-Transfer Accounting

For each transfer instruction: can the source and destination be the same address?
If YES: does a self-transfer update accounting state (fees credited, rewards claimed, share ratios updated) without net token movement? Flag as FINDING. This targets accounting manipulation, distinct from input validation.

## 4. Token Type Separation (Multi-Token Protocols)

For protocols handling multiple token types:
- Are different SEP-41 tokens handled by different code paths?
- Can one token's function be triggered with another token's contract address?
- Is the token address validated against a stored allowlist or configured token?
- Does the protocol distinguish between:
  - XLM native (via `e.current_contract_address().balance()` or XLM SAC address) vs SEP-41 tokens
  - SAC-wrapped assets (Stellar classic assets bridged to Soroban) vs pure Soroban tokens
  - Base token vs LP/receipt token (underlying vs yield-bearing)
  - Tokens with different decimal precisions (XLM is 7 decimals; many SEP-41 tokens use 7 or 18)

**Check**: If function A handles TokenX and function B handles TokenY, can TokenX's address be passed to function B?

## 5. Unsolicited Transfer Analysis

Can tokens be sent to the protocol's address without calling `deposit()`?

If **YES** (always YES in Soroban — any SEP-41 holder can call `token.transfer(self, contract_addr, amount)`):
- Does this break accounting? (tracked balance != `token_client.balance(contract_addr)`)
- Does this inflate exchange rates? (more assets per share)
- Does this enable first-depositor attack amplification?
- Are there reconciliation functions to sync tracked state?
- Can an attacker front-run deposits with unsolicited transfers?

If the protocol claims NO:
- Why not? (Is there a TransferHook equivalent? There is none in standard SEP-41.)
- Is the protection reliable? Can it be bypassed?

## 5b. Unsolicited Transfer Matrix (All Token Types)

For EVERY token type the protocol holds, queries, or receives:

| Token Type | Can Transfer To Protocol? | Changes Accounting? | Blocks Operations? | Triggers Side Effects? |
|------------|--------------------------|--------------------|--------------------|----------------------|
| XLM (native) | YES (always) | YES/NO | YES/NO | YES/NO |
| {sep41_token_a} | YES (always) | YES/NO | YES/NO | YES/NO |
| SAC-{asset} | YES (always) | YES/NO | YES/NO | YES/NO |

**RULE**: If ANY transferable token affects state → analyze: accounting divergence, rent impact, operation blocking, side effect chains.

## 6. Token Flow Checklist

For each token identified:

| Token | Entry Points | Exit Points | Tracking Var | balance() Used Directly? | Unsolicited Possible? |
|-------|--------------|-------------|--------------|--------------------------|----------------------|
| [Name/Address] | deposit, cross-contract return | withdraw, claim | total_deposited | YES/NO | YES (always) |

## 7. Cross-Token Interactions

For protocols with multiple tokens:
- Can operations on TokenA affect TokenB's accounting?
- Are there exchange rate dependencies between tokens (XLM vs SEP-41, base vs LP)?
- Can withdrawing TokenA affect availability of TokenB?
- Can XLM balance affect SEP-41 token operations (base reserve requirements)?

## 8. Cross-Contract Call Return Verification

For every `invoke_contract` call that returns tokens or modifies state:

### 8a. Contract Address Verification
- What contract does the call target? Is the contract address validated against a stored trusted address?
- What return value / state change is expected? Is it verified post-call?

**Common mismatches**:
- Wrong token address: attacker passes a fake SEP-41 contract that mints freely
- Decimal mismatch: token with 7 decimals vs token with 18 decimals — amounts differ by 10^11
- Return value ignored: `invoke_contract` succeeded but returned unexpected amount
- Reentrancy: callee calls back into this contract before this contract's state is updated

**Check**: Every `TokenClient::new(&e, &token_address)` — is `token_address` validated against the configured/expected token, or accepted from user-supplied input?

### 8b. Return Value / Post-Call State Validation
- Does the protocol validate contract state after `invoke_contract` completes?
- Can zero/max/unexpected return values cause issues?
- Is there a mismatch between expected and actual post-call state?

**Soroban reentrancy note**: Soroban DOES allow reentrant `invoke_contract` calls unless the contract explicitly guards against them. If a cross-contract call can call back into this contract before the current function completes, check for reentrancy vectors.

## 9. Allowance Expiry Analysis (Soroban-Specific)

Soroban SEP-41 allowances are stored in **Temporary** ledger storage with a TTL (expressed as a ledger number deadline, not an amount-only approval like EVM). This creates unique staleness vectors:

### 9a. Allowance Storage Type
- Is the allowance stored in Temporary storage? (expires automatically if TTL is not extended)
- What is the approved `expiration_ledger`? Is it far enough in the future?
- Who sets the expiration? Can it be set to 0 (immediate expiry)?

### 9b. Allowance Expiry Attack Scenarios

| Scenario | Description | Impact |
|----------|-------------|--------|
| **Expired allowance** | Contract holds an approved allowance; TTL expires before it is consumed; subsequent `transfer_from` fails | DoS: operation reverts, user funds locked pending reapproval |
| **Short TTL front-run** | User approves with short TTL; attacker delays their own transaction until allowance expires; then calls function that relies on the allowance | Griefing: operation fails after attacker delays it |
| **Allowance amount != i128** | Approved amount stored as `i64` in older code; overflow at amounts > 2^63 | Accounting mismatch: partial approval silently truncated |

### 9c. Token Side Effects (SAC-specific)
- Is this token a SAC (Stellar Asset Contract)? If YES, the Stellar issuer may have freeze/clawback rights.
- Can a SAC clawback from the contract mid-operation? (balance disappears; tracked state diverges)
- Does the protocol handle SAC freeze/clawback gracefully, or does it panic?

### 9d. Side Effect Token Type Analysis

| Call / Event | Side Effect | Token Type Produced | Protocol Handles This Type? | Mismatch? |
|-------------|-------------|--------------------|-----------------------------|-----------|
| {cross_contract_call} | {side_effect} | {token_type_or_UNKNOWN} | YES/NO | YES/NO |

**RULES**: Side effect type != expected → FINDING. Type UNKNOWN → CONTESTED (Rule 4). Check BOTH cross-contract calls AND unsolicited transfers.

## Example Application

```rust
// RED FLAG: Direct balance usage — donatable
let rate = token_client.balance(&e.current_contract_address()) / vault.total_shares;

// BETTER: Tracked balance — but verify total_deposited is updated on ALL entry paths
let rate = vault.total_deposited / vault.total_shares;

// RED FLAG: Token address from user input — not validated
let token_client = TokenClient::new(&e, &token_address); // token_address from fn args
token_client.transfer_from(&e.current_contract_address(), &from, &to, &amount);

// BETTER: Validated against configured token
let configured_token: Address = e.storage().instance().get(&DataKey::Token).unwrap();
require!(token_address == configured_token, Error::InvalidToken);
```

## Finding Template

```markdown
**ID**: [TF-N]
**Severity**: [based on fund impact]
**Step Execution**: S1,2,3,4,5,6,7,8,9 | X(reasons) | ?(uncertain)
**Location**: src/{file}.rs:LineN
**Title**: [Token type] can enter/exit via [path] without [expected accounting update]
**Description**: [Trace the token flow and where it diverges from expected]
**Impact**: [What breaks: exchange rates, user balances, protocol insolvency]
```

---

## Step Execution Checklist (MANDATORY)

> **CRITICAL**: Report completion status for ALL sections. Findings with incomplete sections will be flagged for depth review.

| Section | Required | Completed? | Notes |
|---------|----------|------------|-------|
| 1. Token Entry Points | YES | Y/X/? | |
| 2. Token State Tracking | YES | Y/X/? | |
| 3. Token Exit Points | YES | Y/X/? | |
| 4. Token Type Separation | IF multi-token | Y/X(N/A)/? | |
| 5. Unsolicited Transfer Analysis | YES | Y/X/? | |
| 5b. Unsolicited Transfer Matrix (All Types) | **YES** | Y/X/? | **MANDATORY** — never skip |
| 6. Token Flow Checklist | YES | Y/X/? | |
| 7. Cross-Token Interactions | IF multi-token | Y/X(N/A)/? | |
| 8. Cross-Contract Call Return Verification | **YES** | Y/X/? | **MANDATORY** — never skip |
| 9. Allowance Expiry Analysis | **YES** | Y/X/? | **MANDATORY** — Soroban-specific, never skip |
| 9d. Side Effect Token Type | **YES** | Y/X/? | **MANDATORY** — never skip |

### Cross-Reference Markers

- **After Section 5**: IF LP/receipt tokens identified → MUST complete Sections 8-9. IF cross-contract calls return tokens → verify return state in Section 8.
- **After Section 8**: IF token address is user-supplied → mark CONTESTED until validated. IF reentrancy path exists → escalate to depth-state-trace.
- **After Section 9**: IF allowance TTL is shorter than expected operation window → FINDING (at minimum Medium). IF SAC with clawback → document clawback handling or flag missing guard.

### Mandatory Forced Output

Sections 8 and 9 MUST produce tabular output even if uncertain. If UNVERIFIED: verdict cannot be REFUTED, use CONTESTED. If side effects UNKNOWN: apply adversarial default and document assumptions.
