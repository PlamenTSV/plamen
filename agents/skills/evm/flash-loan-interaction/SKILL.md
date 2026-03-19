---
name: "flash-loan-interaction"
description: "Trigger Pattern FLASH_LOAN flag (required) or BALANCE_DEPENDENT flag (optional complement) - Inject Into Breadth agents, depth-token-flow, depth-edge-case"
---

# FLASH_LOAN_INTERACTION Skill

> **Trigger Pattern**: FLASH_LOAN flag (required) or BALANCE_DEPENDENT flag (optional complement)
> **Inject Into**: Breadth agents, depth-token-flow, depth-edge-case

For every flash-loan-accessible state variable or precondition in the protocol:

**⚠ STEP PRIORITY**: Steps 5 (Defense Audit) and 5b (Defense Parity) are where HIGH/CRITICAL severity findings most commonly hide. Do NOT rush these steps. If constrained, skip conditional sections (0c, 4) before skipping 5, 5b, or 3d.

## 0. External Flash Susceptibility Check

Before analyzing the protocol's OWN flash loan paths, check whether external protocols the contract interacts with are susceptible to third-party flash manipulation.

### 0a: External Interaction Inventory

| External Protocol | Interaction Type | State Read by Our Protocol | Can 3rd Party Flash-Manipulate That State? |
|-------------------|-----------------|---------------------------|-------------------------------------------|
| {DEX/pool/vault} | {swap/deposit/query} | {reserves, price, balance} | {YES if spot state / NO if TWAP or time-weighted} |

### 0b: Third-Party Flash Attack Modeling

For each external state marked YES in 0a, model:
1. **Before**: Protocol reads external state X (e.g., pool reserves, spot price)
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

**Cost formula**: `manipulation_cost = slippage * trade_size` where `trade_size = (target_price_change / price_impact_per_unit) * pool_liquidity`. If `manipulation_cost < extractable_value` → VIABLE.

**For Uniswap V2-style**: `price_impact = trade_size / (reserve + trade_size)`. For V3 concentrated liquidity: impact depends on tick range - use actual liquidity in the affected range, not total TVL.
<!-- END_LOAD_IF: DEX_INTERACTION -->

## 1. Flash-Loan-Accessible State Inventory

Enumerate ALL protocol state that can be manipulated within a single transaction via flash-borrowed capital:

| State Variable / Query | Location | Read By | Write Path | Flash-Accessible? | Manipulation Cost |
|------------------------|----------|---------|------------|-------------------|-------------------|
| `balanceOf(address(this))` | {contract} | {functions} | Direct transfer | YES | 0 (donation) |
| `totalSupply` | {contract} | {functions} | mint/burn | YES if permissionless | Deposit amount |
| `getReserves()` | {pool} | {functions} | Swap | YES | Slippage cost |
| Oracle spot price | {oracle} | {functions} | Trade on source | YES | Market depth |
| Threshold/quorum state | {contract} | {functions} | Deposit/stake | YES | Threshold amount |

**For each YES entry**: trace all functions that READ this state and make decisions based on it.

**Rule 15 check**: For each balance/oracle/threshold/rate precondition, model the flash loan atomic sequence.

## 2. Atomic Attack Sequence Modeling

For each flash-loan-accessible state identified in Step 1:

### Attack Template
```
1. BORROW: Flash-borrow {amount} of {token} from {source}
2. MANIPULATE: {action} to change {state_variable} from {value_before} to {value_after}
3. CALL: Invoke {target_function} which reads manipulated state
4. EXTRACT: {what_is_gained} - quantify: {amount}
5. RESTORE: {action} to return state (if needed for repayment)
6. REPAY: Return {amount + fee} to flash loan source
7. PROFIT: {extract - fee - gas} = {net_profit}
```

**Profitability gate**: If net_profit ≤ 0 for all realistic amounts → document as NON-PROFITABLE but check Step 3 for multi-call chains.

**For each sequence, verify**:
- [ ] Can steps 2-5 execute atomically (same transaction)?
- [ ] Does any step revert under normal conditions?
- [ ] Is the manipulation detectable/preventable by the protocol?
- [ ] What is the minimum flash loan amount needed?

## 3. Cross-Function Flash Loan Chains

Model multi-call atomic sequences within a single flash loan:

| Step | Function Called | State Before | State After | Enables Next Step? |
|------|---------------|-------------|------------|-------------------|
| 1 | {function_A} | {state} | {state'} | YES - changes {X} |
| 2 | {function_B} | {state'} | {state''} | YES - enables {Y} |
| N | {function_N} | {state^N} | {final} | EXTRACT profit |

**Key question**: Can calling function A then function B in the same transaction produce a state that neither function alone could create?

**Common multi-call patterns**:
- Deposit → manipulate rate → withdraw (sandwich own deposit)
- Stake → trigger reward calculation → unstake (flash-stake rewards)
- Borrow → manipulate collateral price → liquidate others → repay
- Deposit to inflate shares → withdraw deflated shares

### 3b. Flash-Loan-Enabled Debounce DoS
For each permissionless function with a cooldown/debounce that affects OTHER users (global cooldown, shared timestamp):
Can attacker flash-borrow → call debounced function → trigger cooldown, blocking legitimate callers?

| Function | Cooldown Scope | Shared Across Users? | Flash-Triggerable? | DoS Duration |
|----------|---------------|---------------------|-------------------|-------------|

If cooldown is global/shared AND function is permissionless AND flash-triggerable → FINDING (R2, minimum Medium).

### 3c. No-Op Resource Consumption
For each state-modifying function with a limited-use resource (cooldown, one-time flag, nonce, epoch-bound action):
Can it be called with parameters producing zero economic effect (amount=0, same-token swap, self-transfer) while consuming the resource?

| Function | Resource Consumed | No-Op Parameters | Resource Wasted? | Impact |
|----------|------------------|-----------------|-----------------|--------|

If a no-op call consumes a resource blocking legitimate use → FINDING (R2, resource waste).

### 3d. External Flash × Debounce Cross-Reference (MANDATORY)

For EACH external protocol flagged as flash-susceptible in Section 0:

| External Protocol | Flash-Accessible Action | Debounce/Cooldown Affected (from 3b) | Combined Severity |
|-------------------|------------------------|--------------------------------------|-------------------|

Cross-reference: Can the external flash loan trigger ANY debounce/cooldown found in Step 3b?
If YES:
1. Is the debounce consumption **permanent** (no admin reset) or **temporary** (auto-expires)?
2. If permanent: is there ANY on-chain path to reset? (admin function, governance, time-based expiry)
3. Combined finding inherits the HIGHER severity of the two individual findings
4. Tag: `[TRACE:flash({external}) → call({debounce_fn}) → cooldown consumed → {duration/permanent}]`

If no debounce functions exist from 3b: mark N/A and skip.

<!-- LOAD_IF: BALANCE_DEPENDENT -->
## 4. Flash Loan + Donation Compound Attacks

Combine flash loan capital with unsolicited token transfers:

| Donation Target | Flash Loan Action | Combined Effect | Profitable? |
|-----------------|-------------------|-----------------|-------------|
| {contract}.balanceOf | Deposit/withdraw | Rate manipulation | {YES/NO} |
| {pool}.reserves | Swap | Price oracle manipulation | {YES/NO} |
| {governance}.balance | Vote/propose | Quorum manipulation | {YES/NO} |

**Check**: Can a flash-borrowed amount be donated (not deposited) to the protocol to manipulate `balanceOf(this)` accounting, and then extracted via a subsequent protocol call within the same transaction?
<!-- END_LOAD_IF: BALANCE_DEPENDENT -->

## 5. Flash Loan Defense Audit

For each flash-loan-accessible attack path identified:

| Defense | Present? | Effective? | Bypass? |
|---------|----------|------------|---------|
| Reentrancy guard (`nonReentrant`) | YES/NO | {analysis} | {if YES: how} |
| Same-block prevention (`block.number` check) | YES/NO | {analysis} | Multi-block possible? |
| TWAP instead of spot price | YES/NO | TWAP window length: {N} | Short TWAP vulnerable? |
| Minimum lock period / cooldown | YES/NO | Duration: {N blocks/seconds} | Bypass via partial? |
| Balance snapshot (before/after comparison) | YES/NO | {analysis} | {if YES: how} |
| Flash loan fee exceeds profit | YES/NO | Fee: {X}, max profit: {Y} | Fee < profit? |

**TWAP-specific**: If TWAP window < 30 minutes AND pool liquidity < $10M → flag as potentially manipulable.

## 5b. Defense Parity Audit (Cross-Contract)

For each user-facing action that exists in multiple contracts (stake, withdraw, claim, exit):

| Action | Contract A | Flash Defense | Contract B | Flash Defense | Parity? |
|--------|-----------|---------------|-----------|---------------|---------|
| {action} | {contract} | {defense list} | {contract} | {defense list} | {GAP if different} |

**Key question**: If ContractA.stake() has a cooldown that prevents flash-stake-claim-withdraw,
but ContractB.stake() has NO cooldown for the same economic action - can an attacker use
ContractB as the undefended path to extract the same value?

For each GAP found:
1. Can the undefended contract be used to achieve the same economic outcome?
2. Does the defended contract's protection become meaningless if the undefended path exists?
3. Is the defense difference intentional (documented) or accidental?

## Finding Template

```markdown
**ID**: [FL-N]
**Severity**: [based on profitability and fund impact]
**Step Execution**: ✓1,2,3,4,5 | ✗(reasons) | ?(uncertain)
**Rules Applied**: [R2:✓, R4:✓, R10:✓, R15:✓]
**Location**: Contract.sol:LineN
**Title**: Flash loan enables [manipulation] via [mechanism]
**Description**: [Full atomic attack sequence with amounts]
**Impact**: [Quantified profit/loss with realistic flash loan amounts]
```

---

## Step Execution Checklist (MANDATORY)

| Section | Required | Completed? | Notes |
|---------|----------|------------|-------|
| 0. External Flash Susceptibility Check | YES | ✓/✗/? | For each external protocol interaction |
| 1. Flash-Loan-Accessible State Inventory | YES | ✓/✗/? | |
| 2. Atomic Attack Sequence Modeling | YES | ✓/✗/? | For each accessible state |
| 3. Cross-Function Flash Loan Chains | YES | ✓/✗/? | |
| 3b. Flash-Loan-Enabled Debounce DoS | YES | ✓/✗/? | Shared cooldown functions |
| 3c. No-Op Resource Consumption | YES | ✓/✗/? | Zero-effect calls consuming resources |
| 3d. External Flash × Debounce Cross-Ref | YES | ✓/✗/? | Cross-reference 0 × 3b |
| 4. Flash Loan + Donation Compounds | IF BALANCE_DEPENDENT | ✓/✗(N/A)/? | |
| 5. Flash Loan Defense Audit | YES | ✓/✗/? | For each attack path |
| 5b. Defense Parity Audit | YES | ✓/✗/? | For each action in multiple contracts |
