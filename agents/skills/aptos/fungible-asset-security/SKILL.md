---
name: "fungible-asset-security"
description: "Trigger FA_STANDARD flag detected (protocol uses FungibleAsset standard) - Used by Breadth agents, depth-token-flow"
---

# Skill: FUNGIBLE_ASSET_SECURITY

> **Trigger**: FA_STANDARD flag detected (protocol uses FungibleAsset standard)
> **Used by**: Breadth agents, depth-token-flow
> **Covers**: FungibleAsset metadata validation, zero-value exploitation, store ownership, dispatchable hooks, Ref safety, Coin-to-FA migration

## Purpose

Audit FungibleAsset standard usage for Aptos-specific vulnerabilities. The FA standard introduces object-based token management with capabilities (MintRef, BurnRef, TransferRef, FreezeRef) and optional dispatchable hooks. Incorrect usage creates counterfeit token acceptance, forced transfers, reentrancy, and accounting mismatches.

## Methodology

### STEP 1: Metadata Validation Audit

For EVERY function that accepts a `FungibleAsset` parameter or reads from a `FungibleStore`:

| # | Function | Accepts FA/Reads Store | Validates Metadata? | Expected Metadata | Bypass Possible? |
|---|----------|----------------------|--------------------|--------------------|-----------------|
| 1 | {func} | FungibleAsset param | YES/NO | {expected_metadata_obj} | YES/NO |

**How metadata validation works**:
```move
// CORRECT: validates the asset is the expected type
let metadata = fungible_asset::metadata(&fa);
assert!(metadata == expected_metadata, ERROR_WRONG_ASSET);

// VULNERABLE: no validation - accepts ANY FungibleAsset
public fun deposit(fa: FungibleAsset) {
    // Attacker can pass a worthless FA created from their own metadata
    fungible_asset::deposit(store, fa);
}
```

**MANDATORY SEARCH**: Grep all `.move` files for:
1. `FungibleAsset` in function signatures (parameters)
2. For each hit: trace whether `fungible_asset::metadata(&fa)` is called and compared
3. Functions that ONLY use `fungible_asset::amount(&fa)` without metadata check -> FLAG

**Severity**: Accepting unvalidated FungibleAsset = accepting counterfeit tokens. If the function credits the user or modifies protocol state based on the FA amount -> HIGH/CRITICAL.

### STEP 2: Zero-Value Exploitation

Analyze zero-value FungibleAsset paths:

| # | Zero-Value Source | Code Path Triggered | State Modified? | Cleanup Correct? |
|---|------------------|-------------------|----------------|-----------------|
| 1 | `fungible_asset::zero(metadata)` | {trace what happens} | YES/NO | YES/NO |
| 2 | Withdrawal of 0 amount | {trace} | YES/NO | YES/NO |

**Check for each**:
1. Can `fungible_asset::zero(metadata)` be used to trigger code paths that modify state? (e.g., register a user, set a flag, emit an event)
2. Does `fungible_asset::destroy_zero(fa)` clean up properly, or does it leave dangling state?
3. Can zero-value deposits/withdrawals:
   - Register a new FungibleStore where one shouldn't exist?
   - Trigger reward distribution checkpoints?
   - Bypass minimum deposit requirements (checked after or before deposit)?
   - Create entries in tracking data structures (SmartTable, vector)?
4. Does `amount == 0` get explicitly checked and rejected at entry points?

**Pattern**: Zero-value operations often bypass `amount > 0` checks that were assumed but never written, allowing state modifications without economic cost.

### STEP 3: Store Creation and Ownership Analysis

Audit FungibleStore creation, ownership chains, and access control:

#### 3a. Store Creation Inventory

| Store Type | Created By | Creation Permissionless? | Owner | Can Attacker Create? |
|-----------|-----------|-------------------------|-------|---------------------|
| Primary store | `primary_fungible_store::ensure_primary_store_exists()` | YES - anyone can create for any address | Address owner | YES (for any address) |
| Custom store | `fungible_asset::create_store()` on ConstructorRef | Only during object construction | Object owner | Depends on who can construct |

**CRITICAL**: `primary_fungible_store::ensure_primary_store_exists(addr, metadata)` is permissionless. An attacker can create a primary store for ANY address for ANY metadata. If the protocol assumes a store's existence means the user has interacted with the protocol -> FINDING.

#### 3b. Transitive Ownership

| Object A | Owns Object B | B Has FungibleStore | A Can Withdraw from B? |
|----------|-------------|--------------------|-----------------------|
| {object} | {child_object} | YES/NO | YES - via object ownership chain |

**Check**: If Object A owns Object B which owns a FungibleStore, the owner of Object A can withdraw from B's store through the ownership chain. Trace all object ownership hierarchies for unintended fund access paths.

#### 3c. Store Address Confusion

| Function | Expects Store At | Actually Reads From | Match? |
|----------|-----------------|--------------------|---------|
| {func} | Protocol-controlled store | User-supplied address | VERIFY |

**Pattern**: Protocol calculates expected store address but user can supply a different store address. If the function doesn't verify the store belongs to the expected object/address -> FINDING.

### STEP 4: Dispatchable Hook Analysis

If the protocol uses dispatchable FungibleAsset (custom `withdraw`, `deposit`, or `derived_balance` hooks):

#### 4a. Hook Inventory

| Hook Type | Registered? | Implementation Module | Can Reenter? | Can Revert? | Can Manipulate? |
|-----------|-------------|---------------------|-------------|------------|-----------------|
| withdraw | YES/NO | {module::func} | ANALYZE | ANALYZE | ANALYZE |
| deposit | YES/NO | {module::func} | ANALYZE | ANALYZE | ANALYZE |
| derived_balance | YES/NO | {module::func} | ANALYZE | N/A | ANALYZE |

#### 4b. Reentrancy via Hooks

For each registered hook:
1. Does the hook call back into the registering module's public functions?
2. Does the hook call into any other module that reads/writes shared state?
3. Is `#[module_lock]` applied to the registering module? (prevents indirect reentrancy but NOT direct)
4. What state has been modified BEFORE the hook executes? Can the hook see inconsistent state?

**Reentrancy sequence**:
```
Module::transfer() {
    1. Read balance (CHECK)
    2. Deduct from source store → triggers withdraw hook (INTERACTION before EFFECT completion)
    3. Withdraw hook reenters Module::another_function()
    4. another_function() sees partially-updated state
    // ...
}
```

#### 4c. Deposit Hook Blocking

Can a `deposit` hook unconditionally revert to prevent deposits into a specific store?
- If YES: can this be used to DoS the protocol? (e.g., prevent liquidations, block reward distribution)
- Who controls the hook? (protocol, user, external party)

#### 4d. Derived Balance Manipulation

If `derived_balance` hook is registered:
1. Does the protocol call `fungible_asset::balance(store)` expecting the real balance?
2. `balance()` calls `derived_balance` hook if registered - the returned value may differ from actual stored amount
3. Can the hook return inflated values to trick the protocol? (e.g., appear to have more collateral)
4. Can the hook return deflated values? (e.g., trigger incorrect liquidation)

### STEP 5: Ref Safety Analysis

Audit the lifecycle and access control of FungibleAsset capability references:

#### 5a. Ref Inventory

| Ref Type | Stored Where | Who Has Access | Can Be Extracted? | Impact If Leaked |
|----------|-------------|---------------|------------------|-----------------|
| MintRef | {object/resource} | {module/address} | YES/NO | Infinite token minting |
| BurnRef | {object/resource} | {module/address} | YES/NO | Destroy any user's tokens |
| TransferRef | {object/resource} | {module/address} | YES/NO | Bypass freeze, forced transfers |
| FreezeRef | {object/resource} | {module/address} | YES/NO | Freeze any user's store |

**MANDATORY CHECK** for each Ref:
1. Is the Ref stored in a resource with `key` only? (safe - not extractable)
2. Is the Ref stored in a struct with `store` ability? (dangerous - can be moved out)
3. Is the Ref stored in an Object? Who owns the Object? Can ownership be transferred?
4. Are there public functions that return the Ref or pass it to external code?

#### 5b. TransferRef Bypass Analysis

TransferRef allows transfers that bypass freeze status:
1. Is there a TransferRef for the protocol's main token?
2. Can TransferRef be used to force-transfer tokens FROM users? (`fungible_asset::transfer_with_ref(ref, from_store, to_store, amount)`)
3. Who holds the TransferRef? Is this documented as a trust assumption?
4. Can TransferRef bypass any protocol-level transfer restrictions (not just freeze)?

#### 5c. Ref Destruction Audit

| Ref Type | Can Be Destroyed? | Destruction Function | Consequences of Destruction |
|----------|------------------|---------------------|---------------------------|
| MintRef | NO (no destroy function) | N/A | Permanent minting capability |
| BurnRef | YES (burn_ref::destroy) | {if exists} | Cannot burn tokens anymore |
| TransferRef | {check} | {if exists} | Cannot force-transfer anymore |

### STEP 6: Coin-to-FA Migration Accounting

If the protocol handles both `Coin<T>` and `FungibleAsset`:

| # | Check | Status | Impact |
|---|-------|--------|--------|
| 1 | Are Coin and FA treated equivalently in balance accounting? | YES/NO | {if NO: describe discrepancy} |
| 2 | Does `total_supply` track both representations? | YES/NO | {if NO: supply tracking broken} |
| 3 | Can user deposit as Coin, then withdraw as FA (or vice versa), exploiting accounting difference? | YES/NO | {describe path} |
| 4 | Are there functions that only accept Coin but credit FA internally (or vice versa)? | YES/NO | {conversion correct?} |
| 5 | If protocol converts Coin<T> to FA: does `coin::coin_to_fungible_asset()` preserve exact amount? | VERIFY | {check for fees or rounding} |

**Pattern**: When a protocol accepts both Coin<T> and FungibleAsset for the same underlying token, internal accounting that tracks only one representation can be exploited by depositing in one form and withdrawing in the other.

## Key Questions (Must Answer All)

1. **Metadata validation**: Does every FA-accepting function verify the asset type?
2. **Zero-value**: Are zero-amount operations explicitly guarded?
3. **Store creation**: Can permissionless store creation be exploited?
4. **Hooks**: If dispatchable, can hooks reenter, block, or manipulate balances?
5. **Refs**: Where are MintRef/BurnRef/TransferRef/FreezeRef stored, and who can access them?
6. **Coin-FA parity**: If both types supported, is accounting consistent?

## Common False Positives

1. **Framework-enforced metadata**: Some framework functions internally validate metadata - verify before flagging
2. **Primary store determinism**: Primary store addresses are deterministic (`primary_fungible_store_address(owner, metadata)`) - "unexpected address" may be intentional
3. **Intentional TransferRef usage**: Protocol may document that TransferRef is needed for authorized transfers (e.g., liquidation)
4. **Zero-value guards in framework**: Some framework functions (e.g., `deposit`) may already reject zero amounts internally - verify

## Output Schema

```markdown
## Finding [FA-N]: Title

**Verdict**: CONFIRMED / PARTIAL / REFUTED / CONTESTED
**Step Execution**: ✓1,2,3,4,5,6 | ✗N(reason) | ?N(uncertain)
**Rules Applied**: [R1:✓/✗, R4:✓/✗, R10:✓/✗, R11:✓/✗]
**Severity**: Critical/High/Medium/Low/Info
**Location**: module_name.move:LineN

**FA Component**: {metadata/store/hook/ref/accounting}
**Attack Vector**: {counterfeit deposit / reentrancy via hook / forced transfer via TransferRef / ...}

**Description**: What's wrong
**Impact**: What can happen (fund theft, accounting mismatch, DoS)
**Evidence**: Code snippets showing the vulnerability
**Recommendation**: How to fix

### Precondition Analysis (if PARTIAL/REFUTED)
**Missing Precondition**: [What blocks exploitation]
**Precondition Type**: STATE / ACCESS / TIMING / EXTERNAL / BALANCE

### Postcondition Analysis (if CONFIRMED/PARTIAL)
**Postconditions Created**: [What conditions this creates]
**Postcondition Types**: [List applicable types]
**Who Benefits**: [Who can use these]
```

## Step Execution Checklist (MANDATORY)

| Step | Required | Completed? | Notes |
|------|----------|------------|-------|
| 1. Metadata Validation Audit | YES | ✓/✗/? | Every FA-accepting function checked |
| 2. Zero-Value Exploitation | YES | ✓/✗/? | |
| 3. Store Creation and Ownership | YES | ✓/✗/? | Primary store permissionless creation checked |
| 3b. Transitive Ownership | YES | ✓/✗/? | Object ownership chains traced |
| 4. Dispatchable Hook Analysis | IF dispatchable FA used | ✓/✗(N/A)/? | |
| 4b. Reentrancy via Hooks | IF hooks registered | ✓/✗(N/A)/? | |
| 4c. Deposit Hook Blocking | IF deposit hook registered | ✓/✗(N/A)/? | |
| 4d. Derived Balance Manipulation | IF derived_balance hook | ✓/✗(N/A)/? | |
| 5. Ref Safety Analysis | YES | ✓/✗/? | All 4 Ref types located and access traced |
| 5b. TransferRef Bypass | IF TransferRef exists | ✓/✗(N/A)/? | |
| 6. Coin-to-FA Migration Accounting | IF both Coin and FA supported | ✓/✗(N/A)/? | |

If any step skipped, document valid reason (N/A, no dispatchable hooks, no Coin support, no TransferRef).
