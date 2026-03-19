---
name: "migration-analysis"
description: "Trigger Protocol has migration patterns (reinitialize, V2/V3, deprecated, upgrade, legacy, Coin-to-FA) - Covers Token type mismatches, stranded assets, interface incompatibiliti..."
---

# Skill: MIGRATION_ANALYSIS

> **Trigger**: Protocol has migration patterns (reinitialize, V2/V3, deprecated, upgrade, legacy, Coin-to-FA)
> **Covers**: Token type mismatches, stranded assets, interface incompatibilities, module upgrade safety
> **Required**: YES when MIGRATION flag detected

## Aptos Migration Context

Aptos modules are upgradeable by default under the `compatible` upgrade policy. Key differences from EVM:
- Module upgrades are **in-place** (same address, same module name)
- Resources in global storage **persist** across upgrades unchanged
- New functions can be added; existing public function signatures **must remain compatible**
- Storage layout must be compatible: new fields only at end of structs, existing fields unchanged
- `immutable` policy freezes module permanently; `compatible` allows additive changes
- The `Coin<T>` to `FungibleAsset` migration is a major ecosystem-wide transition

## Trigger Patterns

```
V2|V3|_deprecated|migrat|upgrade|legacy|old_token|new_token|coin_to_fungible|fungible_asset_to_coin|reinitialize
```

## Reasoning Template

### Step 1: Identify Token Transitions

Find all token migration patterns:
- `Coin<T>` to `FungibleAsset` migration (ecosystem-wide)
- Legacy module interfaces still referenced
- Deprecated functions still callable
- V1 -> V2 module patterns within the protocol

For each transition:

| Old Standard/Type | New Standard/Type | Migration Function | Bidirectional? | Framework Support? |
|-------------------|-------------------|-------------------|----------------|-------------------|
| Coin<CoinType> | FungibleAsset | coin::coin_to_fungible_asset | YES (coin::fungible_asset_to_coin) | aptos_framework |
| ModuleV1::Resource | ModuleV2::Resource | custom migrate() | {YES/NO} | N/A |

### Step 2: Check Interface Compatibility

For each external call that involves migrated tokens or upgraded modules:
1. What type does the CALLER expect? (`Coin<T>` or `FungibleAsset` or `Object<Metadata>`)
2. What type does the CALLEE actually return/accept?
3. Are they the same?
4. Has the external module upgraded to use a different standard?

```move
// Example mismatch:
// Protocol still uses Coin<USDC>
public fun deposit(coin: Coin<USDC>) { ... }
// But external DEX now returns FungibleAsset
public fun swap(...): FungibleAsset { ... }
// Mismatch: protocol receives FA but expects Coin
```

**Aptos-specific**: Check if external modules have migrated from `coin` to `primary_fungible_store` while the protocol still uses the `coin` interface. The aptos_framework provides automatic pairing between `Coin<T>` and its corresponding FungibleAsset, but this pairing has edge cases.

### Step 3: Trace Token Flow Paths

For each function that interacts with migrated tokens:

1. **Entry point**: What token standard does the user provide?
2. **Internal flow**: What standard does the protocol track internally?
3. **External call**: What standard does the external module expect?
4. **Return value**: What standard is returned?

| Function | User Provides | Protocol Tracks | External Expects | Mismatch? |
|----------|---------------|-----------------|------------------|-----------|

### Step 3b: External Side Effect Token Compatibility

When migration changes token types or interaction patterns, check whether external call side effects produce tokens that the current logic handles correctly.

For each external call that returns tokens or triggers side effects:

| External Call | Pre-Migration Side Effect | Post-Migration Side Effect | Logic Handles Both? | Mismatch? |
|---------------|--------------------------|---------------------------|---------------------|-----------|
| {ext_call} | Returns Coin<T> | Returns FungibleAsset | YES/NO | {describe} |

**Pattern**: Migration changes the primary token standard (e.g., Coin -> FA), but external modules still return the old standard as rewards, receipts, or side effects. The new logic may not handle the old token type.

**Check**: For each external dependency, does the post-migration logic correctly handle ALL token types that external calls can produce -- including legacy types from pre-migration interactions still in flight?

### Step 3c: Pre-Upgrade Resource Inventory

Before analyzing stranded asset paths, inventory what resources CURRENTLY EXIST in global storage:

| Resource Type | Published At | How It Arrived | Post-Upgrade Logic Handles? | Exit Path Post-Upgrade? |
|---------------|-------------|---------------|----------------------------|------------------------|
| Coin<T> store | User addresses | User deposits via coin::register + deposit | YES/NO | {function or NONE} |
| FungibleStore | Object addresses | primary_fungible_store::deposit | YES/NO | {function or NONE} |
| Custom resource | @protocol | Module initialization | YES/NO | {function or NONE} |

**Pattern**: Upgrade changes which token standard the protocol uses, but global storage still holds resources from pre-upgrade operations. If the new logic only handles FungibleAsset, Coin<T> balances at user addresses are stranded.

**Check**: For every resource type the protocol can create pre-upgrade:
1. Does the post-upgrade logic reference this resource type?
2. Is there a migration or sweep function that covers it?
3. If NEITHER -> STRANDED ASSET FINDING (apply Rule 9 severity floor)

### Step 4: Stranded Asset Analysis (Exhaustive)

> **CRITICAL**: This step uses exhaustive methodology. Every sub-step is MANDATORY.

#### 4a. Asset Inventory by Era

List ALL assets the protocol handles, categorized by migration era:

| Asset | V1 Entry Path | V2 Entry Path | V1 Exit Path | V2 Exit Path |
|-------|---------------|---------------|--------------|--------------|
| Coin<T> balance | deposit_coin() | N/A (removed) | withdraw_coin() | withdraw() converts? |
| FungibleAsset balance | N/A | deposit_fa() | N/A | withdraw_fa() |

**Rule**: If V1 Entry exists but V2 Exit does not handle V1 state -> potential stranding

#### 4b. Cross-Era Path Matrix

For EACH asset and EACH possible state combination:

| Asset Era | State Condition | Available Exit Paths | Works? | Reason |
|-----------|-----------------|---------------------|--------|--------|
| V1 Coin deposit | V2 logic active | withdraw() | Y/N | {does V2 read CoinStore?} |
| V1 Coin deposit | V1 functions removed in upgrade | withdraw_coin() | Y/N | {removed in compatible upgrade?} |
| V1 resource | In-flight during upgrade | ??? | Y/N | {resource persists but handler changed} |

**Aptos-specific**: Under `compatible` upgrade policy, public functions cannot be removed -- only new functions can be added. However, the function logic CAN change. A V1 function that previously handled Coin<T> might be updated to expect FungibleAsset internally, breaking for users with V1 state.

**STRANDING RULE**: If ALL exit paths = N for any state -> **STRANDED ASSETS FINDING**

#### 4c. Recovery Function Inventory

Document ALL functions that could recover stranded assets:

| Function | Who Can Call | What Assets Can Recover | Limitations |
|----------|--------------|------------------------|-------------|
| admin_rescue() | Admin signer | All resources at @protocol | Requires admin action |
| migrate_user() | Any user | User own Coin -> FA | One-time conversion |
| sweep() | Admin | Unaccounted tokens | Cannot recover user resources at their addresses |

**Question**: Is there a recovery path for EVERY stranding scenario in 4b?

#### 4d. Worst-Case Scenarios (MANDATORY)

Model these specific scenarios with code traces:

**Scenario 1: V1 Deposit + V2 Logic**
```
State: User deposited via V1 function, CoinStore<T> has balance
Event: Protocol upgraded to V2 (now uses FungibleAsset internally)
Question: Can user withdraw via V2 withdraw()?
Trace: [document code path -- does V2 read CoinStore or only FungibleStore?]
Result: [SUCCESS/STRANDED + amount]
```

**Scenario 2: Resource Persistence After Upgrade**
```
State: Custom resource R published at user address by V1 logic
Event: V2 module changes struct R layout (adds new field at end)
Question: Can V2 functions read/use the old R?
Trace: [compatible upgrade -- struct deserialization with new fields defaulting]
Result: [SUCCESS/ABORT + which functions break]
```

**Scenario 3: Paired Coin/FA Migration**
```
State: Protocol has Coin<T> and paired FungibleAsset for same underlying
Event: External module migrates to FA only, stops accepting Coin<T>
Question: Can protocol still interact with external module?
Trace: [does protocol auto-convert via coin::coin_to_fungible_asset?]
Result: [SUCCESS/STRANDED + which paths break]
```

#### 4e. Step 4 Completion Checklist

- [ ] 4a: ALL assets inventoried with entry/exit paths per era
- [ ] 4b: Cross-era path matrix completed for all state combinations
- [ ] 4c: Recovery functions enumerated with limitations
- [ ] 4d: All three worst-case scenarios modeled with code traces
- [ ] For EVERY stranding possibility: recovery path exists OR finding created

**Step Execution Output**: `check4a,4b,4c,4d,4e` or `?4X(incomplete reason)`

### Step 4f: User-Blocks-Admin Scenarios

Check whether user actions can create state that prevents admin migration or management operations:

| Admin/Migration Function | Precondition Required | User Action That Blocks It | Timing Window | Severity |
|--------------------------|----------------------|---------------------------|---------------|----------|
| {admin_func} | {precondition} | {user_action creating conflicting state} | {window size} | {assess} |

**Pattern**: Admin migration or management functions require certain state conditions (e.g., "no pending operations", "all users migrated", "no active borrows"). Users performing normal operations (deposits, withdrawals, claims) may create state that blocks these admin functions.

**Aptos-specific**: Resource existence checks (`exists<R>(addr)`) used as preconditions -- can a user create or destroy a resource to block admin functions?

**Check for each admin/migration function**:
1. What state preconditions does this function require?
2. Can a user create conflicting state using normal operations?
3. Is the blocking permanent or temporary?
4. Can the user be griefed into blocking (e.g., unsolicited resource creation at user address)?

If blocking is possible AND permanent -> minimum MEDIUM severity
If blocking is temporary but repeatable -> assess with Rule 10 worst-state

### Step 5: External Call Verification

For each external call:

1. Identify the ACTUAL external module version deployed (if verifiable)
2. Verify token standard accepted/returned
3. Compare with what the protocol sends/expects

| External Module | Function | Protocol Sends | Module Expects | Match? |
|----------------|----------|----------------|-----------------|--------|
| aptos_framework::coin | withdraw<T> | signer + amount | signer must have CoinStore<T> | VERIFY |
| dex_module::swap | swap() | FungibleAsset | FungibleAsset with correct metadata | VERIFY |
| oracle::get_price | get_price() | - | Returns u64 or FixedPoint64? | VERIFY |

### Step 6: Downstream Integration Compatibility

When the protocol changes token standards, interfaces, or behavior during migration, check how downstream consumers are affected:

| Protocol Change | Downstream Consumer Type | Expected Interface/Token | Actual Post-Migration | Breaking Change? |
|-----------------|--------------------------|--------------------------|----------------------|-----------------|
| {what changed} | DeFi integrations (DEX, lending) | {expected Coin<T>?} | {actual FA?} | YES/NO |
| {what changed} | Indexers/APIs | {expected events} | {actual events} | YES/NO |
| {what changed} | Other protocol modules | {expected function sig} | {actual -- compatible?} | YES/NO |
| {what changed} | View functions | {expected return type} | {actual return type} | YES/NO |

**Pattern**: Protocol migrates from Coin<T> to FungibleAsset, but downstream integrators still call the old Coin<T> interface. Under compatible upgrade policy, old functions remain callable but may behave differently internally.

**Check**:
1. What external systems consume this protocol outputs (tokens, events, view functions)?
2. Does the migration change what those systems receive?
3. Are downstream systems notified or do they auto-detect the change?
4. If breaking -> FINDING with severity based on downstream impact scope

## Key Questions (Must Answer All)

1. **Token Standard**: For each interaction, what standard is ACTUALLY used? (Coin<T> vs FungibleAsset)
2. **Migration Completeness**: Can ALL V1 assets be accessed/withdrawn via V2 paths?
3. **Interface Drift**: Have external modules upgraded their interfaces independently?
4. **Stranded Path**: Is there any combination of (old_state + new_logic) that traps funds?

## Common False Positives

1. **Intentional deprecation**: Old functions deliberately made no-op with clear migration path
2. **Framework auto-pairing**: Coin<T> and FungibleAsset are automatically paired by aptos_framework -- verify pairing handles the specific case
3. **Admin-controlled migration**: Stranded assets recoverable via admin functions with no trust issue
4. **Compatible upgrade guarantee**: Under `compatible` policy, public function signatures cannot change -- but internal behavior CAN

## Instantiation Parameters

```
{CONTRACTS}           -- List of modules to analyze
{MIGRATION_TYPE}      -- Coin-to-FA / V1-to-V2 / Module upgrade
{OLD_STANDARD}        -- What the protocol used before
{NEW_STANDARD}        -- What the protocol uses now
{EXTERNAL_MODULES}    -- External modules that may have migrated independently
```

## Output Schema

For each finding:

```markdown
## Finding [MG-N]: Title

**Verdict**: CONFIRMED / PARTIAL / REFUTED / CONTESTED
**Step Execution**: check1,2,3,4,5 | X(reason) | ?(uncertain)
**Severity**: Critical/High/Medium/Low/Info
**Location**: module::function (source_file.move:LineN)

**Token Transition**:
- Old: {old_standard/type}
- New: {new_standard/type}
- Mismatch Point: {where types diverge}

**Description**: What is wrong
**Impact**: What can happen (stranded funds, wrong accounting, DoS)
**Evidence**: Code showing mismatch

### Precondition Analysis (if PARTIAL/REFUTED)
**Missing Precondition**: [What blocks exploitation]
**Precondition Type**: STATE / ACCESS / TIMING / EXTERNAL / BALANCE

### Postcondition Analysis (if CONFIRMED/PARTIAL)
**Postconditions Created**: [What conditions this creates]
**Postcondition Types**: [List applicable types]
```

## Step Execution Checklist

After completing analysis, verify:
- [ ] Step 1: All token transitions identified
- [ ] Step 2: Interface compatibility checked for each
- [ ] Step 3: Token flow traced through all paths
- [ ] Step 3b: External side effect token compatibility checked
- [ ] Step 3c: Pre-upgrade resource inventory completed
- [ ] Step 4: Stranded asset scenarios enumerated (4a-4e)
- [ ] Step 4f: User-blocks-admin scenarios checked
- [ ] Step 5: External modules verified against actual behavior
- [ ] Step 6: Downstream integration compatibility assessed

If any step skipped, document valid reason (N/A, single token, no external deps, no downstream consumers).
