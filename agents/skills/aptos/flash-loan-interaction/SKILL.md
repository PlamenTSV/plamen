---
name: "flash-loan-interaction"
description: "Trigger Pattern FLASH_LOAN flag (required) or BALANCE_DEPENDENT flag (optional complement) - Inject Into Breadth agents, depth-token-flow, depth-edge-case"
---

# FLASH_LOAN_INTERACTION Skill

> **Trigger Pattern**: FLASH_LOAN flag (required) or BALANCE_DEPENDENT flag (optional complement)
> **Inject Into**: Breadth agents, depth-token-flow, depth-edge-case
> **Purpose**: Analyze flash loan attack surfaces in Aptos Move protocols, focusing on the hot potato receipt pattern, state manipulation during flash loan windows, and defense parity

For every flash-loan-accessible state variable or precondition in the protocol:

**STEP PRIORITY**: Steps 5 (Defense Audit) and 5b (Defense Parity) are where HIGH/CRITICAL severity findings most commonly hide. Do NOT rush these steps. If constrained, skip conditional sections (0c, 4) before skipping 5, 5b, or 3d.

## 0. External Flash Susceptibility Check

Before analyzing the protocol's OWN flash loan paths, check whether external protocols the contract interacts with are susceptible to third-party flash manipulation.

### 0a: External Interaction Inventory

| External Protocol | Interaction Type | State Read by Our Protocol | Can 3rd Party Flash-Manipulate That State? |
|-------------------|-----------------|---------------------------|-------------------------------------------|
| {DEX/pool/vault} | {swap/deposit/query} | {reserves, price, balance} | {YES if spot state / NO if TWAP or time-weighted} |

### 0b: Third-Party Flash Attack Modeling

For each external state marked YES in 0a, model:
1. **Before**: Protocol reads external state X (e.g., pool reserves, spot price from AMM)
2. **Flash manipulate**: Attacker flash-borrows and trades on the external protocol to move state X
3. **Victim call**: Attacker calls OUR protocol function that reads manipulated state X
4. **Restore**: Attacker reverses the external manipulation
5. **Impact**: What did the attacker gain from our protocol acting on manipulated state?

**Key question**: Does our protocol use **spot state** (manipulable) or **time-weighted state** (resistant)?

<!-- LOAD_IF: DEX_INTERACTION -->
### 0c: DEX Price Manipulation Cost Estimation

For each external DEX/pool whose spot state is read by the protocol, estimate manipulation cost:

| Pool | Liquidity (USD) | Target Price Change | Est. Trade Size | Slippage Cost | Protocol Extractable Value | Profitable? |
|------|----------------|--------------------:|----------------|--------------|---------------------------|-------------|
| {pool} | {TVL} | {%} | {USD} | {USD} | {USD} | {YES/NO} |

**For Aptos AMMs**: Most use constant-product (xy=k) or stableswap curves. Identify the specific AMM type from the protocol's swap function signatures (weighted pools, stableswap, or standard xy=k).
<!-- END_LOAD_IF: DEX_INTERACTION -->

## 1. Flash-Loan-Accessible State Inventory

Enumerate ALL protocol state that can be manipulated within a single transaction via flash-borrowed capital:

| State Variable / Query | Location | Read By | Write Path | Flash-Accessible? | Manipulation Cost |
|------------------------|----------|---------|------------|-------------------|-------------------|
| `fungible_asset::balance(store)` | {module} | {functions} | Direct deposit to store | YES if store accepts | 0 (unsolicited) |
| `coin::balance<T>(addr)` | {module} | {functions} | Direct `coin::deposit` | YES if CoinStore exists | 0 (unsolicited) |
| Pool reserves | {pool module} | {functions} | Swap on pool | YES | Slippage cost |
| Oracle spot price | {oracle} | {functions} | Trade on source DEX | YES | Market depth |
| Threshold/quorum state | {module} | {functions} | Deposit/stake | YES | Threshold amount |

**Aptos flash loan mechanics (hot potato pattern)**:
- Flash loan providers (Thala, Echelon, etc.) issue a `FlashLoanReceipt` struct with NO abilities (no `copy`, no `drop`, no `store`, no `key`)
- The receipt MUST be consumed by `repay()` in the same transaction -- Move's type system enforces this
- No callback mechanism: caller receives receipt, performs operations, then passes receipt to repay
- The receipt struct often contains the borrowed amount for repayment validation

**For each YES entry**: trace all functions that READ this state and make decisions based on it.

**Rule 15 check**: For each balance/oracle/threshold/rate precondition, model the flash loan atomic sequence.

## 2. Atomic Attack Sequence Modeling

For each flash-loan-accessible state identified in Step 1:

### Attack Template
```
1. BORROW: Flash-borrow {amount} of {CoinType/FA} from {source}
   -> Receive FlashLoanReceipt (hot potato, no abilities)
2. MANIPULATE: {action} to change {state_variable} from {value_before} to {value_after}
3. CALL: Invoke {target_function} which reads manipulated state
4. EXTRACT: {what_is_gained} -- quantify: {amount}
5. RESTORE: {action} to return state (if needed before repayment)
6. REPAY: Call repay() with FlashLoanReceipt + {amount + fee}
7. PROFIT: {extract - fee - gas} = {net_profit}
```

**Profitability gate**: If net_profit <= 0 for all realistic amounts -> document as NON-PROFITABLE but check Step 3 for multi-call chains.

**For each sequence, verify**:
- [ ] Can steps 2-5 execute atomically (same transaction entry function)?
- [ ] Does any step abort under normal conditions?
- [ ] Is the manipulation detectable/preventable by the protocol?
- [ ] What is the minimum flash loan amount needed?
- [ ] Does the hot potato receipt constrain the call sequence? (receipt must be threaded through all calls)

## 3. Cross-Function Flash Loan Chains

Model multi-call atomic sequences within a single flash loan:

| Step | Function Called | State Before | State After | Enables Next Step? |
|------|---------------|-------------|------------|-------------------|
| 1 | {function_A} | {state} | {state'} | YES -- changes {X} |
| 2 | {function_B} | {state'} | {state''} | YES -- enables {Y} |
| N | {function_N} | {state^N} | {final} | EXTRACT profit |

**Key question**: Can calling function A then function B in the same transaction produce a state that neither function alone could create?

**Aptos-specific multi-call patterns**:
- Deposit to pool -> manipulate price via swap -> withdraw at inflated rate
- Flash-stake to meet threshold -> trigger reward calculation -> unstake
- Borrow from protocol A -> manipulate collateral oracle via AMM trade -> liquidate on protocol B -> repay A
- Inflate FungibleStore balance via deposit -> trigger share price recalculation -> withdraw

### 3b. Flash-Loan-Enabled Debounce DoS

For each permissionless function with a cooldown/debounce that affects OTHER users (global cooldown, shared timestamp, epoch-bound action):
Can attacker flash-borrow -> call debounced function -> trigger cooldown, blocking legitimate callers?

| Function | Cooldown Scope | Shared Across Users? | Flash-Triggerable? | DoS Duration |
|----------|---------------|---------------------|-------------------|-------------|

If cooldown is global/shared AND function is permissionless AND flash-triggerable -> FINDING (R2, minimum Medium).

### 3c. No-Op Resource Consumption

For each state-modifying function with a limited-use resource (cooldown, one-time flag, nonce, epoch-bound action):
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
2. If permanent: is there ANY on-chain path to reset? (admin function, governance, time-based expiry)
3. Combined finding inherits the HIGHER severity of the two individual findings
4. Tag: `[TRACE:flash({external}) -> call({debounce_fn}) -> cooldown consumed -> {duration/permanent}]`

If no debounce functions exist from 3b: mark N/A and skip.

<!-- LOAD_IF: BALANCE_DEPENDENT -->
## 4. Flash Loan + Donation Compound Attacks

Combine flash loan capital with unsolicited token transfers:

| Donation Target | Flash Loan Action | Combined Effect | Profitable? |
|-----------------|-------------------|-----------------|-------------|
| FungibleStore balance | Deposit/withdraw | Rate manipulation | {YES/NO} |
| CoinStore<T> balance | Swap on DEX pool | Price oracle manipulation | {YES/NO} |
| Governance token balance | Vote/propose | Quorum manipulation | {YES/NO} |

**Aptos-specific donation vectors**:
- `primary_fungible_store::deposit()` -- can deposit to any address's primary store if the store exists
- `coin::deposit<T>()` -- can deposit to any address with a registered CoinStore<T>
- Direct `fungible_asset::deposit()` with a FungibleStore reference
- Object-based stores may have different deposit access patterns

**Check**: Can a flash-borrowed amount be deposited (not through protocol's deposit logic) to the protocol's FungibleStore to manipulate `balance()` accounting, and then extracted via a subsequent protocol call within the same transaction?
<!-- END_LOAD_IF: BALANCE_DEPENDENT -->

## 5. Flash Loan Defense Audit

For each flash-loan-accessible attack path identified:

| Defense | Present? | Effective? | Bypass? |
|---------|----------|------------|---------|
| Reentrancy guard (Move has no native) | YES/NO | {analysis} | {if YES: how} |
| Same-transaction detection (custom) | YES/NO | {analysis} | {bypass vector?} |
| TWAP instead of spot price | YES/NO | TWAP window length: {N} | Short TWAP vulnerable? |
| Minimum lock period / cooldown | YES/NO | Duration: {N seconds/epochs} | Bypass via partial? |
| Balance snapshot (before/after comparison) | YES/NO | {analysis} | {if YES: how} |
| Flash loan fee exceeds profit | YES/NO | Fee: {X}, max profit: {Y} | Fee < profit? |
| Hot potato receipt threading requirement | YES/NO | Receipt must flow through {path} | Can bypass receipt checks? |

**Aptos-specific defense notes**:
- Move does NOT have native reentrancy guards (no `nonReentrant` modifier)
- Move's borrow checker prevents some reentrancy patterns at compile time (cannot borrow `&mut` twice)
- However, inter-module calls can create reentrancy-like patterns via public functions
- Hot potato pattern enforces same-transaction completion but does NOT prevent state manipulation between borrow and repay
- `timestamp::now_seconds()` granularity is per-second, not per-block -- same-second detection is unreliable

## 5b. Defense Parity Audit (Cross-Module)

For each user-facing action that exists in multiple modules or paths (stake, withdraw, claim, swap):

| Action | Module A | Flash Defense | Module B | Flash Defense | Parity? |
|--------|----------|---------------|----------|---------------|---------|
| {action} | {module} | {defense list} | {module} | {defense list} | {GAP if different} |

**Key question**: If ModuleA::stake() has a cooldown that prevents flash-stake-claim-withdraw,
but ModuleB::stake() has NO cooldown for the same economic action -- can an attacker use
ModuleB as the undefended path to extract the same value?

For each GAP found:
1. Can the undefended module be used to achieve the same economic outcome?
2. Does the defended module's protection become meaningless if the undefended path exists?
3. Is the defense difference intentional (documented via friend declarations) or accidental?

## Instantiation Parameters
```
{CONTRACTS}              -- Move modules to analyze
{FLASH_LOAN_SOURCES}     -- Flash loan providers (Thala, Echelon, custom)
{RECEIPT_STRUCTS}         -- Hot potato receipt struct definitions
{FLASH_ACCESSIBLE_STATE} -- State variables manipulable via flash-borrowed capital
{EXTERNAL_PROTOCOLS}     -- External protocols whose state the contract reads
```

## Finding Template

```markdown
**ID**: [FL-N]
**Severity**: [based on profitability and fund impact]
**Step Execution**: checkmark1,2,3,4,5 | x(reasons) | ?(uncertain)
**Rules Applied**: [R2:Y, R4:Y, R10:Y, R15:Y]
**Location**: module::function:LineN
**Title**: Flash loan enables [manipulation] via [mechanism]
**Description**: [Full atomic attack sequence with amounts]
**Impact**: [Quantified profit/loss with realistic flash loan amounts]
```

## Output Schema

| Field | Required | Description |
|-------|----------|-------------|
| external_susceptibility | yes | External protocols susceptible to flash manipulation |
| flash_accessible_state | yes | All state manipulable within a transaction |
| attack_sequences | yes | Modeled atomic attack sequences with profitability |
| cross_function_chains | yes | Multi-call chains within flash loan window |
| defense_audit | yes | Defenses present and their effectiveness |
| defense_parity | yes | Cross-module defense comparison |
| finding | yes | CONFIRMED / REFUTED / CONTESTED |
| evidence | yes | Code locations with line numbers |
| step_execution | yes | Status for each step |

---

## Step Execution Checklist (MANDATORY)

| Section | Required | Completed? | Notes |
|---------|----------|------------|-------|
| 0. External Flash Susceptibility Check | YES | Y/x/? | For each external protocol interaction |
| 1. Flash-Loan-Accessible State Inventory | YES | Y/x/? | |
| 2. Atomic Attack Sequence Modeling | YES | Y/x/? | For each accessible state |
| 3. Cross-Function Flash Loan Chains | YES | Y/x/? | |
| 3b. Flash-Loan-Enabled Debounce DoS | YES | Y/x/? | Shared cooldown functions |
| 3c. No-Op Resource Consumption | YES | Y/x/? | Zero-effect calls consuming resources |
| 3d. External Flash x Debounce Cross-Ref | YES | Y/x/? | Cross-reference 0 x 3b |
| 4. Flash Loan + Donation Compounds | IF BALANCE_DEPENDENT | Y/x(N/A)/? | |
| 5. Flash Loan Defense Audit | YES | Y/x/? | For each attack path |
| 5b. Defense Parity Audit | YES | Y/x/? | For each action in multiple modules |
