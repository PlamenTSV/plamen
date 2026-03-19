---
name: "flash-loan-interaction"
description: "Trigger Pattern FLASH_LOAN flag (required) or BALANCE_DEPENDENT flag (optional complement) - Inject Into Breadth agents, depth-token-flow, depth-edge-case"
---

# FLASH_LOAN_INTERACTION Skill (Solana)

> **Trigger Pattern**: FLASH_LOAN flag (required) or BALANCE_DEPENDENT flag (optional complement)
> **Inject Into**: Breadth agents, depth-token-flow, depth-edge-case

**Key Solana difference**: There is no callback model. Flash loans work via instruction composition in a single transaction. The attack pattern is: IX1 borrow -> IX2 manipulate -> IX3 exploit -> IX4 repay - all sequential instructions in one transaction.

For every flash-loan-accessible state variable or precondition in the protocol:

**Step Priority**: Steps 5 (Defense Audit) and 5b (Defense Parity) are where HIGH/CRITICAL severity findings most commonly hide. Do NOT rush these steps. If constrained, skip conditional sections (0c, 4) before skipping 5, 5b, or 3d.

## 0. External Flash Susceptibility Check

Before analyzing the protocol's OWN flash loan paths, check whether external programs the protocol CPIs to have state manipulable by a third party within the same transaction.

### 0a: External Interaction Inventory

| External Program | Interaction Type | State Read by Our Program | Can 3rd Party Manipulate That State in Same Tx? |
|------------------|-----------------|---------------------------|------------------------------------------------|
| {DEX/AMM/vault} | {swap/deposit/price query} | {reserves, price, balance} | {YES if spot state / NO if TWAP or slot-gated} |

### 0b: Third-Party Flash Attack Modeling (Instruction Composition)

For each external state marked YES in 0a, model:
1. **IX1 - BORROW**: Flash-borrow via lending program instruction
2. **IX2 - MANIPULATE**: Instruction to external program that changes state X (e.g., swap to move pool reserves)
3. **IX3 - VICTIM CALL**: Instruction to OUR program that reads manipulated state X
4. **IX4 - RESTORE**: Instruction to reverse external manipulation (reverse swap)
5. **IX5 - REPAY**: Instruction to repay flash loan
6. **IMPACT**: What did the attacker gain from our program acting on manipulated state?

**Key question**: Does our program use **spot state** (manipulable within tx) or **time-weighted/slot-gated state** (resistant)?

<!-- LOAD_IF: DEX_INTERACTION -->
### 0c: DEX Price Manipulation Cost Estimation

For each external DEX/AMM whose spot state is read by the program, estimate manipulation cost:

| Pool | Liquidity (USD) | Target Price Change | Est. Trade Size | Slippage Cost | Program Extractable Value | Profitable? |
|------|----------------|--------------------:|----------------|--------------|---------------------------|-------------|
| {pool} | {TVL} | {%} | {USD} | {USD} | {USD} | {YES/NO} |

**Cost formula**: `manipulation_cost = slippage * trade_size`. If `manipulation_cost < extractable_value` -> VIABLE.
<!-- END_LOAD_IF: DEX_INTERACTION -->

## 1. Flash-Loan-Accessible State Inventory

Enumerate ALL program state that can be manipulated within a single transaction via flash-borrowed capital or instruction composition:

| State Variable / Account | Location | Read By | Write Path | Flash-Accessible? | Manipulation Cost |
|--------------------------|----------|---------|------------|-------------------|-------------------|
| `token_account.amount` | {account} | {instructions} | SPL transfer (anyone) | YES | 0 (unsolicited) |
| `vault.total_value` | {PDA} | {instructions} | deposit instruction | YES if permissionless | Deposit amount |
| AMM pool reserves | {pool account} | {instructions} | Swap instruction | YES | Slippage cost |
| Oracle price account | {oracle PDA} | {instructions} | Oracle update IX | YES if same-slot | Market depth |
| Threshold/quorum state | {governance PDA} | {instructions} | Stake/vote IX | YES | Threshold amount |

**For each YES entry**: trace all instructions that READ this state and make decisions based on it.

**Rule 15 check**: For each balance/oracle/threshold/rate precondition, model the instruction composition atomic sequence.

## 2. Atomic Attack Sequence Modeling (Instruction Composition)

For each flash-loan-accessible state identified in Step 1:

### Attack Template (Solana Transaction with Multiple Instructions)
```
TX containing ordered instructions:
  IX1 - BORROW:     Flash-borrow {amount} of {token} from {lending program}
  IX2 - MANIPULATE:  {action} to change {state_variable} from {value_before} to {value_after}
  IX3 - CALL:        Invoke {target_instruction} on our program which reads manipulated state
  IX4 - EXTRACT:     {what_is_gained} - quantify: {amount}
  IX5 - RESTORE:     {action} to return state (if needed for repayment)
  IX6 - REPAY:       Return {amount + fee} to flash loan source

  PROFIT: {extract - fee - tx_fee} = {net_profit}
```

**Profitability gate**: If net_profit <= 0 for all realistic amounts -> document as NON-PROFITABLE but check Step 3 for multi-instruction chains.

**For each sequence, verify**:
- [ ] Can IX2-IX5 execute atomically in one transaction?
- [ ] Does any instruction fail under normal conditions?
- [ ] Is the manipulation detectable/preventable by the program?
- [ ] What is the minimum flash loan amount needed?
- [ ] Does compute unit budget allow the full sequence?

## 3. Cross-Instruction Flash Loan Chains

Model multi-instruction atomic sequences within a single transaction:

| Step | Instruction | State Before | State After | Enables Next Step? |
|------|-------------|-------------|------------|-------------------|
| IX1 | {program_A.instruction_X} | {state} | {state'} | YES - changes {X} |
| IX2 | {program_B.instruction_Y} | {state'} | {state''} | YES - enables {Y} |
| IXN | {program_N.instruction_Z} | {state^N} | {final} | EXTRACT profit |

**Key question**: Can calling instruction A then instruction B in the same transaction produce a state that neither instruction alone could create?

**Common multi-instruction patterns**: Deposit->manipulate oracle->withdraw, stake->trigger reward->unstake, transfer to inflate balance->price-dependent IX->transfer back, multiple CPIs with state mutation between.

### 3b. Flash-Loan-Enabled Debounce DoS
For each permissionless instruction with a cooldown affecting OTHER users (epoch/slot/global timestamp): can attacker compose borrow->debounced IX->trigger cooldown, blocking legitimate callers?

| Instruction | Cooldown Scope | Shared Across Users? | Flash-Triggerable? | DoS Duration |
|-------------|---------------|---------------------|-------------------|-------------|

If global/shared AND permissionless AND flash-triggerable -> FINDING (R2, minimum Medium). **Solana-specific**: `Clock::get()?.slot`/`epoch` cooldowns shorter than 1 slot are ineffective against same-slot composition.

### 3c. No-Op Resource Consumption
For each state-modifying instruction with a limited-use resource (cooldown, one-time flag, nonce, epoch-bound action):
Can it be called with parameters producing zero economic effect (amount=0, same-token swap, self-transfer) while consuming the resource?

| Instruction | Resource Consumed | No-Op Parameters | Resource Wasted? | Impact |
|-------------|------------------|-----------------|-----------------|--------|

If a no-op call consumes a resource blocking legitimate use -> FINDING (R2, resource waste).

### 3d. External Flash x Debounce Cross-Reference (MANDATORY)

For EACH external program flagged as flash-susceptible in Section 0:

| External Program | Flash-Accessible Action | Debounce/Cooldown Affected (from 3b) | Combined Severity |
|------------------|------------------------|--------------------------------------|-------------------|

If YES: (1) permanent or temporary consumption? (2) on-chain reset path? (3) combined severity = HIGHER of the two. Tag: `[TRACE:flash({external})->ix({debounce_fn})->cooldown consumed->{duration}]`. If no debounce from 3b: N/A.

<!-- LOAD_IF: BALANCE_DEPENDENT -->
## 4. Flash Loan + Donation Compound Attacks

Combine flash loan capital with unsolicited SPL/SOL transfers:

| Donation Target | Flash Loan Action | Combined Effect | Profitable? |
|-----------------|-------------------|-----------------|-------------|
| vault token_account.amount | Deposit/withdraw | Rate manipulation | {YES/NO} |
| AMM pool token account | Swap | Price oracle manipulation | {YES/NO} |
| governance staking account | Vote/propose | Quorum manipulation | {YES/NO} |

**Check**: Can a flash-borrowed amount be transferred (not deposited) to the protocol's token account to manipulate `token_account.amount` accounting, and then extracted via a subsequent instruction within the same transaction?

**Solana-specific**: Unsolicited SPL transfers are trivially cheap (no function call needed on receiver side). Anyone who knows the token account address can transfer tokens to it.
<!-- END_LOAD_IF: BALANCE_DEPENDENT -->

## 5. Flash Loan Defense Audit

For each flash-loan-accessible attack path identified:

| Defense | Present? | Effective? | Bypass? |
|---------|----------|------------|---------|
| Anchor reentrancy guard (`#[access_control]`) | YES/NO | {analysis} | {if YES: how} |
| Same-slot prevention (`last_slot` check) | YES/NO | {analysis} | Multi-slot possible? |
| TWAP instead of spot price | YES/NO | TWAP window length: {N slots} | Short TWAP vulnerable? |
| Epoch-based cooldown | YES/NO | Duration: {N epochs} | Bypass via epoch boundary? |
| Balance snapshot (pre/post CPI comparison) | YES/NO | {analysis} | {if YES: how} |
| Flash loan fee exceeds profit | YES/NO | Fee: {X}, max profit: {Y} | Fee < profit? |
| Instruction introspection (sysvar check) | YES/NO | Checks for: {what} | Spoofable? |

**Solana-specific defenses**: `Clock::get()?.slot` comparison, instruction sysvar introspection (detect flash loan IX in tx), CPI depth limits (max 4), compute unit limits as implicit protection.

### 5b. Defense Parity Audit (Cross-Instruction)

For each user-facing action in multiple instructions or program versions:

| Action | Instruction A | Flash Defense | Instruction B | Flash Defense | Parity? |
|--------|--------------|---------------|--------------|---------------|---------|
| {action} | {ix_name} | {defense list} | {ix_name} | {defense list} | {GAP if different} |

**Key question**: If `deposit` has a slot-based cooldown but `deposit_v2` has NONE for the same economic action -- can attacker use `deposit_v2` as the undefended path? For each GAP: can undefended IX achieve same outcome? Does defended IX's protection become meaningless? Intentional or accidental?

## Finding Template

```markdown
**ID**: [FL-N]
**Severity**: [based on profitability and fund impact]
**Step Execution**: S0,1,2,3,4,5 | X(reasons) | ?(uncertain)
**Rules Applied**: [R2:Y, R4:Y, R10:Y, R15:Y]
**Location**: programs/vault/src/instructions/file.rs:LineN
**Title**: Instruction composition enables [manipulation] via [mechanism]
**Description**: [Full atomic instruction sequence with amounts]
**Impact**: [Quantified profit/loss with realistic flash loan amounts]
```

---

## Step Execution Checklist (MANDATORY)

| Section | Required | Completed? | Notes |
|---------|----------|------------|-------|
| 0. External Flash Susceptibility Check | YES | Y/X/? | For each external program interaction |
| 1. Flash-Loan-Accessible State Inventory | YES | Y/X/? | |
| 2. Atomic Attack Sequence Modeling | YES | Y/X/? | For each accessible state |
| 3. Cross-Instruction Flash Loan Chains | YES | Y/X/? | |
| 3b. Flash-Loan-Enabled Debounce DoS | YES | Y/X/? | Shared cooldown instructions |
| 3c. No-Op Resource Consumption | YES | Y/X/? | Zero-effect calls consuming resources |
| 3d. External Flash x Debounce Cross-Ref | YES | Y/X/? | Cross-reference 0 x 3b |
| 4. Flash Loan + Donation Compounds | IF BALANCE_DEPENDENT | Y/X(N/A)/? | |
| 5. Flash Loan Defense Audit | YES | Y/X/? | For each attack path |
| 5b. Defense Parity Audit | YES | Y/X/? | For each action in multiple instructions |
