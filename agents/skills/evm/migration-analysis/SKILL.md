---
name: "migration-analysis"
description: "Trigger Protocol has migration patterns (reinitializer, V2/V3, deprecated, upgrade, legacy) - Covers Token type mismatches, stranded assets, interface incompatibilities"
---

# Skill: MIGRATION_ANALYSIS

> **Trigger**: Protocol has migration patterns (reinitializer, V2/V3, deprecated, upgrade, legacy)
> **Covers**: Token type mismatches, stranded assets, interface incompatibilities

## Trigger Patterns

```
reinitializer|V2|V3|_deprecated|migrat|upgrade|legacy|oldToken|newToken
```

## Reasoning Template

### Step 1: Identify Token Transitions

Find all token migration patterns:
- Old token -> New token (e.g., USDC v1 -> v2, DAI -> sDAI, TokenV1 -> TokenV2)
- Legacy interfaces still referenced
- Deprecated functions still callable

For each transition:
| Old Token | New Token | Migration Function | Bidirectional? |

### Step 2: Check Interface Compatibility

For each external call that involves migrated tokens:
1. What token type does the CALLER expect?
2. What token type does the CALLEE actually return/accept?
3. Are they the same?

```
// Example mismatch:
interface IExternalProtocol {
    function deposit(address asset, uint256 amount) external returns (uint256);
    // Expects: canonical token
    // Actually returns: receipt token denominated in bridged variant?
}
```

### Step 3: Trace Token Flow Paths

For each function that interacts with migrated tokens:

1. **Entry point**: What token does the user provide?
2. **Internal flow**: What token does the protocol track?
3. **External call**: What token does the external contract expect?
4. **Return value**: What token denomination is returned?

| Function | User Provides | Protocol Tracks | External Expects | Mismatch? |

### Step 3b: External Side Effect Token Compatibility

When migration changes token types or interaction patterns, check whether external call side effects produce tokens that the current logic handles correctly.

For each external call that returns tokens or triggers side effects:

| External Call | Pre-Migration Side Effect | Post-Migration Side Effect | Logic Handles Both? | Mismatch? |
|---------------|--------------------------|---------------------------|---------------------|-----------|
| {ext_call} | Returns Token A | Returns Token B (or same token, different accounting) | YES/NO | {describe} |

**Pattern**: Migration changes the primary token (e.g., V1 -> V2), but external contracts still return the old token as rewards, receipts, or side effects. The new logic may not handle the old token type.

**Check**: For each external dependency, does the post-migration logic correctly handle ALL token types that external calls can produce -- including legacy types from pre-migration interactions still in flight?

### Step 3c: Pre-Upgrade Balance Inventory

Before analyzing stranded asset paths, inventory what the contract CURRENTLY HOLDS:

| Asset Type | How It Arrived | Current Balance Query | Post-Upgrade Logic Handles? | Exit Path Post-Upgrade? |
|------------|---------------|----------------------|----------------------------|------------------------|
| {token_A} | User deposits | `tokenA.balanceOf(this)` | YES/NO | {function or NONE} |
| {token_B} | External rewards | Claimed via {ext_call} | YES/NO | {function or NONE} |
| {token_C} | Legacy operations | Held from V1 interactions | YES/NO | {function or NONE} |

**Pattern**: Upgrade changes which token the protocol uses (V1 -> V2), but the contract still holds V1 tokens from pre-upgrade operations. If the new logic only handles V2, V1 balances are stranded.

**Check**: For every asset type the contract can hold pre-upgrade:
1. Does the post-upgrade logic reference this asset type?
2. Is there a sweep/rescue function that covers it?
3. If NEITHER -> STRANDED ASSET FINDING (apply Rule 9 severity floor)

### Step 4: Stranded Asset Analysis

> **CRITICAL**: This step uses exhaustive methodology to ensure no stranded asset scenarios are missed. Every sub-step is MANDATORY.

#### 4a. Asset Inventory by Era

List ALL assets the protocol handles, categorized by migration era:

| Asset | V1 Entry Path | V2 Entry Path | V1 Exit Path | V2 Exit Path |
|-------|---------------|---------------|--------------|--------------|
| Token A | deposit_v1() | deposit() | withdraw_v1() | withdraw() |
| Token B | stake_v1() | stake() | unstake_v1() | unstake() |

**Rule**: If V1 Entry exists but V2 Exit doesn't handle V1 state -> potential stranding

#### 4b. Cross-Era Path Matrix

For EACH asset and EACH possible state combination:

| Asset Era | State Condition | Available Exit Paths | Works? | Reason |
|-----------|-----------------|---------------------|--------|--------|
| V1 deposit | V2 logic active | withdraw() | Y/N | {why} |
| V1 deposit | V1 logic deprecated | withdraw_v1() | Y/N | {why} |
| V1 deposit | In-flight during upgrade | ??? | Y/N | {why} |

**STRANDING RULE**: If ALL exit paths = N for any state -> **STRANDED ASSETS FINDING**

#### 4c. Recovery Function Inventory

Document ALL functions that could recover stranded assets:

| Function | Who Can Call | What Assets Can Recover | Limitations |
|----------|--------------|------------------------|-------------|
| emergencyWithdraw() | Admin only | All tokens | Requires admin action |
| migrate() | Anyone | V1 balances | One-time only |
| sweep() | Admin only | Unaccounted tokens | Cannot recover user deposits |

**Question**: Is there a recovery path for EVERY stranding scenario in 4b?

#### 4d. Worst-Case Scenarios (MANDATORY)

Model these specific scenarios with code traces:

**Scenario 1: V1 Deposit + V2 Logic**
```
State: User deposited 100 tokens via V1 deposit()
Event: Protocol upgraded to V2
Question: Can user withdraw via V2 withdraw()?
Trace: [document code path]
Result: [SUCCESS/STRANDED + amount]
```

**Scenario 2: In-Flight During Upgrade**
```
State: User initiated withdrawal at V1 block N
Event: Upgrade happened at block N+1
Question: Can user complete withdrawal at block N+2?
Trace: [document code path]
Result: [SUCCESS/STRANDED + amount]
```

**Scenario 3: External Token Type Mismatch**
```
State: Protocol received TokenA from external contract
Event: External contract now returns TokenB
Question: Can protocol process/withdraw TokenA?
Trace: [document code path]
Result: [SUCCESS/STRANDED + amount]
```

#### 4e. Step 4 Completion Checklist

- [ ] 4a: ALL assets inventoried with entry/exit paths per era
- [ ] 4b: Cross-era path matrix completed for all state combinations
- [ ] 4c: Recovery functions enumerated with limitations
- [ ] 4d: All three worst-case scenarios modeled with code traces
- [ ] For EVERY stranding possibility: recovery path exists OR finding created

**Step Execution Output**: `checkmark4a,4b,4c,4d,4e` or `?4X(incomplete reason)`

### Step 5: External Call Token Verification

For each external call:

1. Read the PRODUCTION external contract (not mock)
2. Verify actual token type accepted/returned
3. Compare with what the protocol sends/expects

```markdown
| External Contract | Function | Protocol Sends | Contract Expects | Match? |
|-------------------|----------|----------------|------------------|--------|
| ExternalPool | deposit | depositAsset | depositAsset | YES |
| ExternalPool | withdraw | receiptTokens | receiptTokens | YES |
| PriceOracle | getPrice | - | Returns USD or ETH? | VERIFY |
```

### Step 4f: User-Blocks-Admin Scenarios

Check whether user actions can create state that prevents admin migration or management operations:

| Admin/Migration Function | Precondition Required | User Action That Blocks It | Timing Window | Severity |
|--------------------------|----------------------|---------------------------|---------------|----------|
| {admin_func} | {precondition} | {user_action creating conflicting state} | {window size} | {assess} |

**Pattern**: Admin migration or management functions require certain state conditions (e.g., "no pending operations", "all users migrated", "no active requests"). Users performing normal operations (withdrawals, deposits, claims) may create state that blocks these admin functions.

**Check for each admin/migration function**:
1. What state preconditions does this function require?
2. Can a user create conflicting state using normal operations?
3. Is the blocking permanent or temporary?
4. Can the user be griefed into blocking (e.g., front-run with a small operation)?

If blocking is possible AND permanent -> minimum MEDIUM severity
If blocking is temporary but repeatable -> assess with Rule 10 worst-state

### Step 6: Downstream Integration Compatibility

When the protocol changes token types, interfaces, or behavior during migration, check how downstream consumers are affected:

| Protocol Change | Downstream Consumer Type | Expected Interface/Token | Actual Post-Migration | Breaking Change? |
|-----------------|--------------------------|--------------------------|----------------------|-----------------|
| {what changed} | DeFi integrations (lending, DEX) | {expected} | {actual} | YES/NO |
| {what changed} | Indexers/subgraphs | {expected events/signatures} | {actual} | YES/NO |
| {what changed} | Frontend/UI | {expected token type} | {actual} | YES/NO |
| {what changed} | Other protocol contracts | {expected interface} | {actual} | YES/NO |

**Pattern**: Protocol migrates from TokenV1 to TokenV2, but downstream integrators (other protocols, composability layers, frontends) still expect TokenV1 behavior. This creates silent failures or incorrect accounting in the integration layer.

**Check**:
1. What external systems consume this protocol's outputs (tokens, events, view functions)?
2. Does the migration change what those systems receive?
3. Are downstream systems notified or do they auto-detect the change?
4. If breaking -> FINDING with severity based on downstream impact scope

## Key Questions (Must Answer All)

1. **Token Type**: For each external interaction, what token type is ACTUALLY used in production?
2. **Migration Completeness**: Can ALL V1 assets be migrated/withdrawn via V2 paths?
3. **Interface Drift**: Have external contracts upgraded their interfaces independently?
4. **Stranded Path**: Is there any combination of (old_state + new_logic) that traps funds?

## Common False Positives

1. **Intentional deprecation**: Old paths deliberately disabled with clear migration
2. **Wrapper equivalence**: Old and new tokens are 1:1 wrapped versions
3. **Admin-controlled migration**: Stranded assets recoverable via admin functions

## Output Schema

For each finding:

```markdown
## Finding [MG-N]: Title

**Verdict**: CONFIRMED / PARTIAL / REFUTED / CONTESTED
**Step Execution**: checkmark1,2,3,4,5 | xN(reason) | ?N(uncertain)
**Severity**: Critical/High/Medium/Low/Info
**Location**: Contract.sol:LineN

**Token Transition**:
- Old: {old_token}
- New: {new_token}
- Mismatch Point: {where types diverge}

**Description**: What's wrong
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
- [ ] Step 3c: Pre-upgrade balance inventory completed
- [ ] Step 4: Stranded asset scenarios enumerated (4a-4e)
- [ ] Step 4f: User-blocks-admin scenarios checked
- [ ] Step 5: External contracts verified against production
- [ ] Step 6: Downstream integration compatibility assessed

If any step skipped, document valid reason (N/A, single token, no external deps, no downstream consumers).
