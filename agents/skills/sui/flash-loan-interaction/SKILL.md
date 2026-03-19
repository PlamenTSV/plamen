---
name: "flash-loan-interaction"
description: "Trigger Pattern FLASH_LOAN flag (required) or BALANCE_DEPENDENT flag (optional complement) - Inject Into Breadth agents, depth-token-flow, depth-edge-case"
---

# FLASH_LOAN_INTERACTION Skill (Sui)

> **Trigger Pattern**: FLASH_LOAN flag (required) or BALANCE_DEPENDENT flag (optional complement)
> **Inject Into**: Breadth agents, depth-token-flow, depth-edge-case
> **Purpose**: Analyze flash loan attack vectors in Sui Move protocols, focusing on hot potato receipt patterns and PTB-based atomic composition

For every flash-loan-accessible state variable or precondition in the protocol:

**STEP PRIORITY**: Steps 5 (Defense Audit) and 5b (Defense Parity) are where HIGH/CRITICAL severity findings most commonly hide. Do NOT rush these steps. If constrained, skip conditional sections (0c, 4) before skipping 5, 5b, or 3d.

## 0. External Flash Susceptibility Check

Before analyzing the protocol's OWN flash loan paths, check whether external protocols the contract interacts with are susceptible to third-party flash manipulation.

### 0a: External Interaction Inventory

| External Protocol | Interaction Type | State Read by Our Protocol | Can 3rd Party Flash-Manipulate That State? |
|-------------------|-----------------|---------------------------|-------------------------------------------|
| {DEX/pool/vault} | {swap/deposit/query} | {reserves, price, balance} | {YES if spot state / NO if TWAP or time-weighted} |

**Sui-specific**: Check interactions with known flash loan providers on the target chain (e.g., CLMM DEXs, lending protocols, orderbook DEXs). Each may provide flash loan functionality via hot potato receipts within PTBs.

### 0b: Third-Party Flash Attack Modeling

For each external state marked YES in 0a, model:
1. **Before**: Protocol reads external state X (e.g., pool reserves, spot price)
2. **Flash manipulate**: Attacker flash-borrows from {source} and trades on the external protocol to move state X
3. **Victim call**: Attacker calls OUR protocol function that reads manipulated state X -- all within the SAME PTB
4. **Restore**: Attacker reverses the external manipulation
5. **Impact**: What did the attacker gain from our protocol acting on manipulated state?

**Key question**: Does our protocol use **spot state** (manipulable) or **time-weighted state** (resistant)?

<!-- LOAD_IF: DEX_INTERACTION -->
### 0c: DEX Price Manipulation Cost Estimation

For each external DEX/pool whose spot state is read by the protocol, estimate manipulation cost:

| Pool | Liquidity (USD) | Target Price Change | Est. Trade Size | Slippage Cost | Protocol Extractable Value | Profitable? |
|------|----------------|--------------------:|----------------|--------------|---------------------------|-------------|
| {pool} | {TVL} | {%} | {USD} | {USD} | {USD} | {YES/NO} |

**Sui DEX types**:
- **CLOB (DeepBook)**: Manipulation via limit order placement + market orders. Cost depends on order book depth.
- **CLMM DEXs**: Concentrated liquidity -- manipulation cost depends on liquidity in active tick range, not total TVL.
- **AMM (other)**: Standard constant-product -- `price_impact = trade_size / (reserve + trade_size)`.
<!-- END_LOAD_IF: DEX_INTERACTION -->

## 1. Flash-Loan-Accessible State Inventory

Enumerate ALL protocol state that can be manipulated within a single PTB via flash-borrowed capital:

| State Variable / Query | Location | Read By | Write Path | Flash-Accessible? | Manipulation Cost |
|------------------------|----------|---------|------------|-------------------|-------------------|
| `balance::value(&pool.balance)` | {module} | {functions} | deposit/withdraw | YES | Deposit amount |
| `pool.total_supply` | {module} | {functions} | mint/burn | YES if permissionless | Deposit amount |
| DEX pool reserves | {external} | {functions} | Swap | YES | Slippage cost |
| Oracle spot price | {external} | {functions} | Trade on source | YES | Market depth |
| Threshold/quorum state | {module} | {functions} | Deposit/stake | YES | Threshold amount |

**Sui-specific flash loan mechanics**:
- Flash loans on Sui use the **hot potato pattern**: a `FlashLoanReceipt` struct with NO abilities (no `key`, `store`, `copy`, or `drop`). It MUST be consumed by the repay function in the same PTB.
- PTBs allow up to **1024 commands** -- an attacker can compose: borrow -> N manipulations -> exploit -> repay in a single atomic transaction.
- No callback mechanism needed -- PTB command sequencing handles atomicity.
- Flash loan sources: lending protocols (`flash_loan` / `repay_flash_loan` patterns), DEX flash swaps, flash mint mechanisms.

**For each YES entry**: trace all functions that READ this state and make decisions based on it.

**Rule 15 check**: For each balance/oracle/threshold/rate precondition, model the flash loan atomic sequence within a PTB.

## 2. Atomic Attack Sequence Modeling

For each flash-loan-accessible state identified in Step 1:

### Attack Template (PTB-Based)
```
PTB Commands:
  1. BORROW: Call flash_loan({amount}, {token}) on {source} -> receive Coin<T> + FlashLoanReceipt
  2. MANIPULATE: {action} to change {state_variable} from {value_before} to {value_after}
  3. CALL: Invoke {target_function} on our protocol which reads manipulated state
  4. EXTRACT: {what_is_gained} -- quantify: {amount}
  5. RESTORE: {action} to return state (if needed for repayment)
  6. REPAY: Call repay_flash_loan(receipt, coin) -- consumes hot potato receipt
  7. PROFIT: {extract - fee - gas} = {net_profit}
```

**Profitability gate**: If net_profit <= 0 for all realistic amounts -> document as NON-PROFITABLE but check Step 3 for multi-call chains.

**For each sequence, verify**:
- [ ] Can steps 2-5 execute within a single PTB (max 1024 commands)?
- [ ] Does any step abort under normal conditions?
- [ ] Is the manipulation detectable/preventable by the protocol?
- [ ] What is the minimum flash loan amount needed?
- [ ] Does the hot potato receipt enforce correct repayment (amount + fee)?

## 3. Cross-Function Flash Loan Chains

Model multi-call atomic sequences within a single PTB:

| PTB Cmd | Function Called | Shared Object State Before | State After | Enables Next Step? |
|---------|---------------|---------------------------|------------|-------------------|
| 1 | {function_A} | {state} | {state'} | YES -- changes {X} |
| 2 | {function_B} | {state'} | {state''} | YES -- enables {Y} |
| N | {function_N} | {state^N} | {final} | EXTRACT profit |

**Key question**: Can calling function A then function B in the same PTB produce a state that neither function alone could create?

**Common Sui multi-call patterns**:
- Deposit -> manipulate share price -> withdraw (sandwich own deposit)
- Stake -> trigger reward calculation -> unstake (flash-stake rewards)
- Flash borrow -> inflate collateral value -> borrow against inflated collateral -> repay flash loan
- Deposit to inflate shares -> withdraw deflated shares
- Flash borrow -> manipulate oracle state -> liquidate others -> repay

### 3b. Flash-Loan-Enabled Debounce DoS
For each permissionless function with a cooldown/debounce stored in a shared object:
Can attacker flash-borrow -> call debounced function -> trigger cooldown, blocking legitimate callers?

| Function | Cooldown Scope | Shared Across Users? | Flash-Triggerable? | DoS Duration |
|----------|---------------|---------------------|-------------------|-------------|

**Sui-specific**: Cooldowns on Sui typically use `clock::timestamp_ms(clock)` comparisons stored in shared objects. If the cooldown timestamp is global (not per-user), a flash loan can trigger it for all users.

If cooldown is global/shared AND function is permissionless AND flash-triggerable -> FINDING (R2, minimum Medium).

### 3c. No-Op Resource Consumption
For each state-modifying function with a limited-use resource (cooldown, one-time flag, epoch-bound action):
Can it be called with parameters producing zero economic effect (amount=0, same-token swap, self-transfer) while consuming the resource?

| Function | Resource Consumed | No-Op Parameters | Resource Wasted? | Impact |
|----------|------------------|-----------------|-----------------|--------|

If a no-op call consumes a resource blocking legitimate use -> FINDING (R2, resource waste).

### 3d. External Flash x Debounce Cross-Reference (MANDATORY)

For EACH external protocol flagged as flash-susceptible in Section 0:

| External Protocol | Flash-Accessible Action | Debounce/Cooldown Affected (from 3b) | Combined Severity |
|-------------------|------------------------|--------------------------------------|-------------------|

Cross-reference: Can the external flash loan trigger ANY debounce/cooldown found in Step 3b?
If YES:
1. Is the debounce consumption **permanent** (no admin reset) or **temporary** (auto-expires)?
2. If permanent: is there ANY on-chain path to reset? (admin cap function, epoch reset, time-based expiry)
3. Combined finding inherits the HIGHER severity of the two individual findings
4. Tag: `[TRACE:flash({external}) -> call({debounce_fn}) -> cooldown consumed -> {duration/permanent}]`

If no debounce functions exist from 3b: mark N/A and skip.

## 4. Hot Potato Receipt Integrity

For every flash loan implementation in the protocol (or external flash loan receipt consumed by the protocol):

### 4a. Receipt Struct Analysis

| Receipt Struct | Abilities | Can Be Constructed Outside Module? | Fields Validated on Repay? | Amount+Fee Enforced? |
|----------------|-----------|-----------------------------------|--------------------------|---------------------|
| {struct_name} | {none / key / store / etc.} | YES/NO | {list fields checked} | YES/NO |

**Critical checks**:
- Receipt struct MUST have zero abilities (no `key`, `store`, `copy`, `drop`). If it has `drop` -> borrower can discard receipt without repaying (free flash loan).
- Receipt struct MUST be defined in the lending module with no public constructor. If any public function returns a freshly created receipt -> attacker can fabricate receipts.
- Repayment function MUST validate returned `Coin<T>` value >= borrowed amount + fee. If it only checks receipt existence -> underpayment.

### 4b. Receipt Replay / Fabrication

- Can the receipt be split or partially consumed? (e.g., paying back in multiple calls)
- Can two receipts from different borrows be combined or swapped?
- Is the receipt tied to a specific pool/object ID? If not -> cross-pool receipt confusion.
- Can a receipt be constructed via `test_utils` or `test_scenario` in production? (should be test-only)

### 4c. PTB Receipt Composition

- Can multiple flash loan receipts from different pools coexist in the same PTB?
- If two receipts exist, can the repayment coins be swapped (pay Pool A's receipt with Pool B's funds)?
- Does the receipt encode the borrow pool's ID to prevent cross-pool repayment?

<!-- LOAD_IF: BALANCE_DEPENDENT -->
## 5. Flash Loan + Donation Compound Attacks

Combine flash loan capital with unsolicited token transfers:

| Donation Target | Flash Loan Action | Combined Effect | Profitable? |
|-----------------|-------------------|-----------------|-------------|
| Shared pool object balance | Deposit/withdraw | Rate manipulation | {YES/NO} |
| DEX pool reserves | Swap | Price oracle manipulation | {YES/NO} |
| Governance voting power | Vote/propose | Quorum manipulation | {YES/NO} |

**Sui-specific donation vectors**:
- `transfer::public_transfer(coin, @pool_address)` sends Coin<T> to a shared object's address -- but this creates a NEW owned object at that address, NOT added to the shared object's `Balance<T>`. However, some protocols use `dynamic_field` or accept arbitrary coins.
- Check: Does the protocol have a function that accepts arbitrary `Coin<T>` and adds to its `Balance<T>` without proper accounting? (e.g., a `donate()` or `top_up()` function)
- Check: Does the protocol read `balance::value()` of its own balance and use it for exchange rate calculation? If so, any path to increase the balance without minting shares is a donation attack vector.
<!-- END_LOAD_IF: BALANCE_DEPENDENT -->

## 6. Flash Loan Defense Audit

For each flash-loan-accessible attack path identified:

| Defense | Present? | Effective? | Bypass? |
|---------|----------|------------|---------|
| Hot potato receipt validation (amount + fee) | YES/NO | {analysis} | {if YES: how} |
| Same-epoch prevention (epoch comparison) | YES/NO | {analysis} | Multi-epoch possible? |
| TWAP instead of spot price | YES/NO | TWAP window length: {N} | Short TWAP vulnerable? |
| Minimum lock period / cooldown | YES/NO | Duration: {N epochs/seconds} | Bypass via partial? |
| Balance snapshot (before/after in same function) | YES/NO | {analysis} | {if YES: how} |
| Flash loan fee exceeds profit | YES/NO | Fee: {X}, max profit: {Y} | Fee < profit? |
| PTB command limit (1024) constrains attack | YES/NO | Commands needed: {N} | N < 1024? |

**Sui-specific defenses**:
- Hot potato pattern inherently prevents cross-transaction flash loans -- but does NOT prevent within-PTB manipulation.
- `tx_context::epoch()` checks prevent cross-epoch attacks but NOT same-PTB attacks.
- Shared object contention: high-contention shared objects may naturally serialize, but this is NOT a reliable defense.

## 6b. Defense Parity Audit (Cross-Module)

For each user-facing action that exists in multiple modules (stake, withdraw, claim, exit):

| Action | Module A | Flash Defense | Module B | Flash Defense | Parity? |
|--------|---------|---------------|---------|---------------|---------|
| {action} | {module} | {defense list} | {module} | {defense list} | {GAP if different} |

**Key question**: If ModuleA::stake() has a cooldown that prevents flash-stake-claim-withdraw, but ModuleB::stake() has NO cooldown for the same economic action -- can an attacker use ModuleB as the undefended path to extract the same value?

For each GAP found:
1. Can the undefended module be used to achieve the same economic outcome?
2. Does the defended module's protection become meaningless if the undefended path exists?
3. Is the defense difference intentional (documented) or accidental?

## Finding Template

```markdown
**ID**: [FL-N]
**Severity**: [based on profitability and fund impact]
**Step Execution**: check0,1,2,3,4,5,6 | x(reasons) | ?(uncertain)
**Rules Applied**: [R2:check, R4:check, R10:check, R15:check]
**Location**: module::function:LineN
**Title**: Flash loan enables [manipulation] via [mechanism] within PTB
**Description**: [Full atomic PTB attack sequence with amounts]
**Impact**: [Quantified profit/loss with realistic flash loan amounts]
```

## Instantiation Parameters
```
{CONTRACTS}           -- Move modules to analyze
{FLASH_SOURCES}       -- Flash loan providers identified during recon (lending protocols, DEXs, etc.)
{SHARED_OBJECTS}      -- Shared objects with flash-accessible state
{BALANCE_VARS}        -- Balance<T> fields readable by protocol
{DEX_POOLS}           -- External DEX pools interacted with
{PTB_COMPOSABLE}      -- Functions composable within PTBs
```

## Output Schema
| Field | Required | Description |
|-------|----------|-------------|
| flash_state_inventory | yes | All flash-loan-accessible state |
| atomic_sequences | yes | PTB-based attack sequences modeled |
| cross_function_chains | yes | Multi-call chains within PTBs |
| defense_audit | yes | Defenses present and effectiveness |
| defense_parity | yes | Cross-module defense consistency |
| finding | yes | CONFIRMED / REFUTED / CONTESTED |
| evidence | yes | Code locations with line numbers |
| step_execution | yes | Status for each step |

---

## Step Execution Checklist (MANDATORY)

| Section | Required | Completed? | Notes |
|---------|----------|------------|-------|
| 0. External Flash Susceptibility Check | YES | check/x/? | For each external protocol interaction |
| 1. Flash-Loan-Accessible State Inventory | YES | check/x/? | |
| 2. Atomic Attack Sequence Modeling | YES | check/x/? | For each accessible state |
| 3. Cross-Function Flash Loan Chains | YES | check/x/? | |
| 3b. Flash-Loan-Enabled Debounce DoS | YES | check/x/? | Shared cooldown functions |
| 3c. No-Op Resource Consumption | YES | check/x/? | Zero-effect calls consuming resources |
| 3d. External Flash x Debounce Cross-Ref | YES | check/x/? | Cross-reference 0 x 3b |
| 4. Hot Potato Receipt Integrity | YES | check/x/? | Receipt abilities + repayment validation |
| 5. Flash Loan + Donation Compounds | IF BALANCE_DEPENDENT | check/x(N/A)/? | |
| 6. Flash Loan Defense Audit | YES | check/x/? | For each attack path |
| 6b. Defense Parity Audit | YES | check/x/? | For each action in multiple modules |
