---
name: "ptb-composability"
description: "Trigger Pattern PTB flag (always for Sui -- Programmable Transaction Blocks are the Sui transaction model) - Inject Into Breadth agents, depth-external, depth-state-trace"
---

# Skill: PTB_COMPOSABILITY (Sui)

> **Trigger Pattern**: PTB flag (always for Sui -- Programmable Transaction Blocks are the Sui transaction model)
> **Inject Into**: Breadth agents, depth-external, depth-state-trace
> **Finding prefix**: `[PTB-N]`
> **Rules referenced**: R4, R5, R8, R10, R15

Programmable Transaction Blocks (PTBs) are Sui's transaction composition primitive. A single PTB can contain up to 1024 commands, each calling a different function, with return values routed between commands. This enables atomic multi-step sequences that are fundamentally different from EVM's single-entry-point model. Every `public` function is a potential PTB command -- there is no "internal only" visibility equivalent to Solidity's `internal`.

**STEP PRIORITY**: Steps 1 (Single-Call Assumption Audit) and 4 (Atomic Read-Modify-Write) are where HIGH/CRITICAL severity findings most commonly hide. Do NOT rush these steps. If constrained, skip conditional sections (6, 7) before skipping 1, 3, or 4.

---

## 1. Entry Point Inventory

For EVERY `public` and `entry` function in the protocol, classify composability:

| # | Function | Module | Visibility | Returns Value? | Takes Shared Obj? | Composable in PTB? | Notes |
|---|----------|--------|-----------|---------------|-------------------|-------------------|-------|
| 1 | {func} | {mod} | public / entry / public(package) | YES / NO | YES / NO | YES / NO | {context} |

**Sui visibility semantics**:
- `entry` functions: callable from PTB but return values CANNOT be used by subsequent commands (consumed or discarded within the command). Objects can only be transferred, not returned.
- `public` functions: fully composable -- return values pass between commands. This is the primary composability surface.
- `public(package)`: callable only by other modules in the same package. NOT callable from PTB. Safe from external composition.
- `fun` (private): Not callable from outside the module. Safe.

**Key observation**: Any function that is `public` (not `entry`, not `public(package)`) is fully composable. Its return values can be routed to ANY other function in the same PTB.

### 1b. Single-Call Assumption Audit

For EVERY `public` and `entry` function, check whether its security model implicitly assumes it is the ONLY function called in the transaction:

| # | Function | Assumes Single-Call? | What Assumption? | Breakable via PTB? | Impact |
|---|----------|---------------------|-----------------|-------------------|--------|
| 1 | {func} | YES/NO | {describe assumption} | YES/NO | {impact} |

**Common single-call assumptions that PTBs break**:
- **Post-call state check**: Function reads state, performs action, then a SEPARATE function checks the result. Attacker inserts commands between action and check.
- **Balance snapshot**: Function reads a balance at start, assumes balance changed only due to its work. Another PTB command could have changed the balance.
- **One-operation-per-transaction**: Protocol assumes a user can only deposit OR withdraw in a single transaction. PTB allows deposit + borrow + withdraw atomically.
- **Temporal separation**: Protocol assumes time must pass between action A and action B (cooldown). If both functions are callable, PTB executes them in the same transaction with zero time delta.
- **Reentrancy-like patterns**: Function A updates state partially, function B reads partial state. PTBs naturally enable "call A then call B" -- state IS updated between commands.

**Key question for each function**: "If an attacker calls this function as command N in a PTB, and can execute arbitrary commands 1..N-1 before it and N+1..1024 after it, what can go wrong?"

---

## 2. Multi-Step Composition Analysis

For each `public` function that returns objects:

| # | Function | Input Objects | Output Objects | Can Output Be Routed To? | Can Be Called Multiple Times? |
|---|----------|-------------|---------------|-------------------------|----------------------------|
| 1 | {func} | {owned/shared/immutable} | {Coin<T> / Object / HotPotato} | {any function accepting this type} | YES/NO |

**Return value routing checks**:
- **Coin routing**: If function A returns `Coin<T>`, can it be routed to function C (external) instead of intended function B?
- **Coin splitting**: PTB has native `SplitCoins` command. Returned `Coin<T>` can be split. Does protocol assume full amount passed?
- **Coin merging**: PTB has native `MergeCoins` command. Can attacker merge extra coins to inflate amounts?
- **Mutable reference routing**: `&mut Object` references are borrowed for a command and released after. Same object can be passed to multiple commands sequentially. Does command N assume the object wasn't modified by command N-1?
- **Recipient mismatch**: If function returns a value-bearing object, the final `TransferObjects` command determines the recipient.

### 2b. Value Interception Pattern

Model this specific attack for each function returning value:

```
1. Attacker calls protocol_function_A() -> returns Coin<USDC> (intended for pool)
2. Attacker routes Coin<USDC> to their own address via TransferObjects
3. Protocol expects the Coin was consumed by the next step but it was intercepted
```

**Check**: Does the protocol rely on PTB command ordering to ensure returned values reach the right destination? If YES -> the user controls the ordering, not the protocol.

---

## 3. Flash Loan via PTB

Without explicit flash loan protocols, PTBs enable flash-loan-like patterns:

```
1. [Command 1] Split large Coin<SUI> from attacker's balance
2. [Command 2] Deposit into protocol (inflates TVL/balance)
3. [Command 3] Trigger reward distribution (calculated on inflated balance)
4. [Command 4] Withdraw from protocol
5. [Command 5] Join coins back (net zero capital, captured rewards)
```

**Can protocol state be manipulated between PTB commands?**

| Function Pair | Shared State | Deposit-Action-Withdraw Possible? | Defense? |
|--------------|-------------|----------------------------------|---------|
| {deposit, claim} | {pool balance} | YES/NO | {cooldown? same-epoch check? minimum lock?} |

**Hot potato flash loan pattern**:
```
1. borrow(pool, amount) -> (Coin<T>, FlashReceipt)     // Creates hot potato
2. [attacker does arbitrary operations with Coin<T>]
3. repay(pool, coin, receipt)                            // Consumes hot potato
```

**Checks for hot potato flash loans**:
- Does `repay()` verify returned amount >= borrowed amount + fee?
- Can attacker call OTHER protocol functions between borrow and repay that benefit from temporarily inflated balance?
- Is `FlashReceipt` type-parameterized to prevent cross-pool receipt reuse?
- Verify hot potato struct has NO abilities (no `key`, `store`, `drop`, `copy`)

---

## 4. Shared Object Mutation Ordering

Within a PTB touching shared objects:

### 4a. Oracle Manipulation Within PTB

```
1. [Command 1] Call DEX swap to move on-chain price
2. [Command 2] Call protocol function that reads manipulated price
3. [Command 3] Reverse DEX swap to restore price
4. Net effect: Protocol acted on manipulated price, attacker profited
```

**Check**: Does protocol read spot prices (manipulable) or TWAP/oracle prices (resistant)?

### 4b. Balance Manipulation Within PTB

```
1. [Command 1] Deposit large amount (inflate balance/shares)
2. [Command 2] Trigger reward distribution (on inflated balance)
3. [Command 3] Withdraw deposited amount
4. Net effect: Captured rewards with zero time commitment
```

### 4c. State Toggling Within PTB

```
1. [Command 1] Set state to value A (e.g., via AdminCap function)
2. [Command 2] Perform action requiring state A
3. [Command 3] Reset state back to original value B
4. Net effect: Privileged action performed, state appears unchanged
```

**Check**: Possible if attacker controls an AdminCap? (Rule 6: semi-trusted role analysis)

### 4d. Shared Object Reorder Sensitivity

| Shared Object | Invariant | Commands That Mutate It | Sequence-Dependent? | Exploitable? |
|--------------|-----------|------------------------|-------------------|-------------|
| {obj} | {invariant description} | {cmd1, cmd2, cmd3} | YES/NO | {if YES, describe exploit} |

**Check for each shared object**: Write down the invariant. Can a sequence of 2-3 valid individual operations (each maintaining the invariant) produce a combined state that violates the invariant?

---

## 5. Hot Potato Enforcement

For each zero-ability struct (hot potato):

| # | Hot Potato Type | Created By | Consumed By | Abilities | Bypass Possible? |
|---|----------------|-----------|-------------|-----------|-----------------|
| 1 | {Receipt} | {borrow()} | {repay()} | NONE (confirmed) | {analysis} |

**Checks**:
- [ ] Verify struct has NO abilities. If it has `drop` -> NOT a hot potato.
- [ ] Is the consuming function the ONLY function accepting this type?
- [ ] Can multiple hot potatoes be created in a single PTB? Does consumption order matter?
- [ ] Does consuming function validate the hot potato matches the creating context?
- [ ] Can attacker cause consumption precondition to fail AFTER hot potato created? (entire PTB aborts -- griefing vector)
- [ ] Can a wrapper with `store` ability store the hot potato? (bypass via external module -- check for public generic wrappers)

---

## 6. Object Wrapping/Unwrapping in PTB

Can objects be wrapped, manipulated, and unwrapped within a single PTB to bypass checks?

| Wrap Operation | Unwrap Operation | What's Inside | Check Bypassed? |
|---------------|-----------------|-------------|----------------|
| {wrap_func} | {unwrap_func} | {object with restrictions} | {describe bypass or NONE} |

**Pattern**: Object has transfer restrictions (`key` only, no `store`). Attacker wraps it inside a `store`-capable struct, transfers the wrapper, then unwraps on the other side. If wrap and unwrap are both `public` functions -> transfer restriction bypassed within a single PTB.

---

## 7. Gas Budget Manipulation

PTB gas budget is shared across all commands.

| Attack Vector | Description | Check |
|--------------|-------------|-------|
| **Many-small-operations** | 1000+ tiny operations to circumvent aggregate limits | Do aggregate limits track across PTB commands? |
| **Object creation spam** | PTB creates many objects (up to 1024 per PTB) | Unbounded object creation paths? |
| **Gas exhaustion griefing** | Craft PTB that consumes max gas on revert | Gas charged on abort -- attacker pays |

**Typically lower severity**: Sui's gas model charges the sender, so resource attacks are self-penalizing. Focus on aggregate limit bypass.

---

## Output Schema

```markdown
## Finding [PTB-N]: Title

**Verdict**: CONFIRMED / PARTIAL / REFUTED / CONTESTED
**Step Execution**: check1,2,3,4,5,6,7 | skip(reason) | uncertain
**Rules Applied**: [R4:___, R5:___, R8:___, R10:___, R15:___]
**Severity**: Critical/High/Medium/Low/Info
**Location**: sources/{module}.move:LineN

**PTB Attack Type**: SINGLE_CALL_ASSUMPTION / RETURN_VALUE_ROUTING / FLASH_LOAN_VIA_PTB / ATOMIC_MANIPULATION / HOT_POTATO_BYPASS / WRAP_UNWRAP_BYPASS / AGGREGATE_LIMIT
**Attack Sequence**:
1. [Command 1]: {what attacker does}
2. [Command 2]: {what attacker does}
3. [Command N]: {what attacker does}
**Net Effect**: {what the attacker gained}

**Description**: What is wrong
**Impact**: What can happen (fund loss, unfair value capture, invariant violation)
**Evidence**: Code showing vulnerability + PTB command sequence
```

---

## Step Execution Checklist (MANDATORY)

| Step | Required | Completed? | Notes |
|------|----------|------------|-------|
| 1. Entry Point Inventory | YES | | All public/entry functions classified |
| 1b. Single-Call Assumption Audit | YES | | **HIGH PRIORITY** -- every public function checked |
| 2. Multi-Step Composition Analysis | YES | | All return values checked |
| 2b. Value Interception Pattern | YES | | Value-returning functions modeled |
| 3. Flash Loan via PTB | YES | | Deposit-action-withdraw patterns |
| 4. Shared Object Mutation Ordering | YES | | **HIGH PRIORITY** -- oracle, balance, state toggle |
| 4d. Shared Object Reorder Sensitivity | YES | | Invariant + multi-command sequences |
| 5. Hot Potato Enforcement | IF hot potatoes exist | | Zero-ability verified |
| 6. Object Wrapping/Unwrapping | IF wrap/unwrap functions exist | | Transfer restriction bypass |
| 7. Gas Budget Manipulation | IF aggregate limits exist | | |

### Cross-Reference Markers

**After Step 1b**: If single-call assumption found on fund-critical function -> immediate HIGH finding.

**After Step 3**: Cross-reference with SHARE_ALLOCATION_FAIRNESS for deposit-action-withdraw reward capture.

**After Step 4a**: Cross-reference with ORACLE_ANALYSIS if on-chain DEX prices are used.

**After Step 5**: Cross-reference with ABILITY_ANALYSIS Section 5 (Hot Potato Enforcement).

If any step skipped, document valid reason (N/A, no hot potatoes, no external calls, no aggregate limits).
