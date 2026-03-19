---
name: "migration-analysis"
description: "Trigger Pattern Package upgrades, version transitions, deprecated functions, object layout changes - Inject Into Breadth agents, depth-state-trace"
---

# Skill: Migration Analysis (Sui)

> **Trigger Pattern**: Package upgrades, version transitions, deprecated functions, object layout changes
> **Inject Into**: Breadth agents, depth-state-trace
> **Finding prefix**: `[MG-N]`
> **Rules referenced**: R4, R8, R9, R10, R13

```
upgrade|UpgradeCap|UpgradeTicket|version|v2|V2|deprecated|migrat|legacy|old_coin|new_coin|
compatible|additive|dependency_only|package::authorize_upgrade
```

Sui packages are immutable once published. "Upgrades" create new package versions at new addresses via the UpgradeCap mechanism. Old objects may reference old package versions, and mixed-version state is a primary Sui migration concern. Unlike EVM proxy upgrades where old code is replaced, Sui old package code remains callable forever.

---

## Step 1: Identify Token Transitions

Find all token/object migration patterns:
- Old `Coin<OldType>` -> New `Coin<NewType>` (token rebranding, coin type changes)
- Old object layouts -> New object layouts (fields added via upgrade)
- Deprecated functions still callable via old package version
- Shared objects created by V1 that must work with V2 functions

For each transition:

| Old Entity | New Entity | Migration Function | Bidirectional? | Entity Type |
|------------|-----------|-------------------|----------------|-------------|

**Sui-specific check**: Is this a true package upgrade (same package lineage via UpgradeCap) or a separate package deployment (new address, no lineage)? True upgrades maintain type compatibility; separate deployments create entirely new types -- `pkg_v1::module::Type` != `pkg_v2::module::Type`.

---

## Step 2: Check Interface Compatibility

For each function in the new package version interacting with existing objects:

1. What fields does the OLD object layout have?
2. What fields does the NEW version's functions expect?
3. Are new fields appended (compatible upgrade) or does the layout change (breaking)?
4. Does the struct definition change in a way that breaks `compatible` upgrade rules?

```move
// Example: V1 object layout
struct Pool has key, store {
    id: UID,
    balance: Balance<SUI>,
    fee_bps: u64,
}
// V2 cannot change this layout under `compatible` policy.
// New fields require a new struct or dynamic fields.
```

| Object Type | V1 Fields | V2 Fields | Compatible Upgrade? | Breaking Change? |
|-------------|-----------|-----------|--------------------|--------------------|

**Sui upgrade compatibility rules**:
- `compatible`: Can change function implementations, add new functions, add new types. CANNOT change existing struct layouts, remove public functions, or change function signatures.
- `additive`: Can only add new modules/functions. Cannot change existing code.
- `dependency_only`: Can only change dependency versions.
- `immutable`: No changes possible (`UpgradeCap` destroyed).

---

## Step 3: Trace Token Flow Paths

For each function that interacts with migrated tokens/objects:

1. **Entry point**: What object version does the user provide?
2. **Internal flow**: What version does the protocol logic expect?
3. **External call**: What version do external packages expect?
4. **Return value**: What version is returned?

| Function | User Provides | Protocol Expects | External Expects | Mismatch? |

### Step 3b: External Side Effect Compatibility

When migration changes token types or interaction patterns, check whether external package side effects produce tokens/objects the current logic handles:

| External Call | Pre-Migration Side Effect | Post-Migration Side Effect | Logic Handles Both? | Mismatch? |
|---------------|--------------------------|---------------------------|---------------------|-----------|

**Pattern**: Migration changes the primary coin type (e.g., V1 -> V2), but external packages still return the old type as rewards or receipts.

### Step 3c: Pre-Upgrade Object Inventory

Before analyzing stranded asset paths, inventory what shared objects and owned objects exist on-chain:

| Object Type | Ownership | How Created | Current Contents | Post-Upgrade Logic Handles? | Exit Path Post-Upgrade? |
|-------------|-----------|------------|-----------------|----------------------------|------------------------|
| {pool_obj} | Shared | `init()` | Balance<SUI> + config | YES/NO | {function or NONE} |
| {user_position} | Owned | `open_position()` | Balance + tracking | YES/NO | {function or NONE} |
| {legacy_receipt} | Owned | V1 `deposit()` | Receipt token | YES/NO | {function or NONE} |

**Sui-specific**: Unlike EVM where contract storage persists across upgrades, Sui objects are typed. If a new package is published (not a lineage upgrade), V1 objects CANNOT be read by new package functions because the types differ.

---

## Step 4: Stranded Asset Analysis (ENHANCED)

> **CRITICAL**: This step uses exhaustive methodology. Every sub-step is MANDATORY.

#### 4a. Asset Inventory by Version

| Asset/Object | V1 Entry Path | V2 Entry Path | V1 Exit Path | V2 Exit Path |
|--------------|---------------|---------------|--------------|--------------|
| {shared_pool} | `create_pool()` | `create_pool()` (same) | N/A (shared) | N/A (shared) |
| {user_receipt} | `deposit()` | `deposit_v2()` | `redeem()` | `redeem_v2()` |

**Rule**: If V1 Entry exists but V2 Exit doesn't handle V1-created objects -> potential stranding.

**Sui-specific**: Shared objects persist across compatible upgrades. For new package publications (not upgrades), the type is a DIFFERENT type even if structurally identical.

#### 4b. Cross-Version Path Matrix

| Object Version | State Condition | Available Exit Paths | Works? | Reason |
|----------------|----------------|---------------------|--------|--------|
| V1 user receipt | V2 package active | `redeem_v2()` with V1 receipt | Y/N | {struct type compatibility} |
| V1 shared pool | V2 functions called on it | V2 `withdraw()` | Y/N | {field access compatibility} |
| V1 owned object | New package published (not upgraded) | ANY V2 function | Y/N | {type mismatch} |

**STRANDING RULE**: If ALL exit paths = N for any object state -> **STRANDED ASSETS FINDING** (apply Rule 9: minimum MEDIUM)

#### 4c. Recovery Function Inventory

| Function | Who Can Call | What Objects Can Recover | Limitations |
|----------|------------|------------------------|-------------|
| `migrate_v1()` | Object owner | V1 owned objects | One-time per object |
| `admin_sweep()` | AdminCap holder | Shared object balances | Requires active AdminCap |

**Question**: Is there a recovery path for EVERY stranding scenario in 4b?

#### 4d. Worst-Case Scenarios (MANDATORY)

**Scenario 1: V1 Object + V2 Package (Compatible Upgrade)**
```
State: User holds Receipt object created by V1 package
Event: Package upgraded to V2 via compatible upgrade
Question: Can user call V2 redeem() with V1 Receipt?
Trace: [document type compatibility and field access]
Result: [SUCCESS/STRANDED + amount]
```

**Scenario 2: V1 Object + New Package (Non-Upgrade Publication)**
```
State: User holds Receipt<OldPackage::COIN> object
Event: Protocol publishes new package at new address
Question: Can user interact with new package using old object?
Trace: [OldPackage::Receipt != NewPackage::Receipt -- different types]
Result: [STRANDED unless explicit migration exists]
```

**Scenario 3: Old Package Bypass After Upgrade**
```
State: Protocol upgrades to V2 with new security checks
Event: Attacker calls V1 functions on shared objects
Question: Do V1 functions bypass V2 security checks?
Trace: [document old function code path]
Result: [SAFE/BYPASS POSSIBLE]
```

**Scenario 4: Dynamic Field Key Type Mismatch**
```
State: Objects have dynamic fields with V1 key types
Event: V2 changes key type or field structure
Question: Can V2 code read/remove V1-era dynamic fields?
Trace: [document dynamic field access path]
Result: [SUCCESS/STRANDED + orphaned dynamic fields]
```

#### 4e. Step 4 Completion Checklist
- [ ] 4a: ALL objects inventoried with entry/exit paths per version
- [ ] 4b: Cross-version path matrix completed for all state combinations
- [ ] 4c: Recovery functions enumerated with limitations
- [ ] 4d: All four worst-case scenarios modeled with code traces
- [ ] For EVERY stranding possibility: recovery path exists OR finding created

### Step 4f: User-Blocks-Admin Scenarios

| Admin/Migration Function | Precondition Required | User Action That Blocks It | Timing Window | Severity |
|--------------------------|----------------------|---------------------------|---------------|----------|
| {admin_func} | {precondition} | {user_action} | {window} | {assess} |

**Sui-specific patterns**:
- Admin migration requires exclusive access to shared object, but users continuously submit transactions against it (consensus ordering interleaves admin with user txs)
- Migration function requires all user positions withdrawn, but users can re-deposit between admin's check and migration
- Owned objects (user positions) cannot be accessed by admin functions -- migration requires user cooperation
- Dynamic fields on shared objects added by users must be cleaned up before object deletion

If blocking is possible AND permanent -> minimum MEDIUM severity
If blocking is temporary but repeatable -> assess with Rule 10 worst-state

---

## Step 5: External Package Verification

For each external package dependency:

| External Package | Published Version | Upgrade Policy | Our Package Pins To | Compatible With Our Usage? |
|-----------------|-------------------|---------------|---------------------|---------------------------|
| {package_id} | {version} | {compatible/additive/immutable} | {specific version or latest} | YES/NO |

**Check**:
- If external package upgrades, do our function calls still work?
- Are we using types from the external package that could change?
- Does the external package's `UpgradeCap` holder pose a risk?

---

## Step 6: Downstream Integration Compatibility

| Protocol Change | Downstream Consumer Type | Expected Interface/Type | Actual Post-Migration | Breaking Change? |
|----------------|------------------------|------------------------|----------------------|-----------------|
| {change} | Other Sui packages (composability) | {expected type} | {actual type} | YES/NO |
| {change} | Indexers/explorers | {expected event structure} | {actual} | YES/NO |
| {change} | Frontend/SDK | {expected PTB structure} | {actual} | YES/NO |
| {change} | PTB composers (DeFi aggregators) | {expected function signature} | {actual} | YES/NO |

**Sui-specific**: PTB composability means other protocols may compose our public functions into their PTBs. If function signatures or return types change, ALL downstream PTB composers break silently.

---

## Key Questions (Must Answer All)

1. **Type Identity**: For each shared object, is the type from the old package or new? Are they the same type (upgrade lineage) or different?
2. **Old Code Still Callable**: What old package functions remain callable post-upgrade? Can any be used maliciously against shared objects?
3. **Migration Completeness**: Can ALL V1-era objects and assets be migrated to or accessed by V2 paths?
4. **Dynamic Field Compatibility**: Are all dynamic field key types accessible from the new package version?
5. **Stranded Path**: Is there any combination of (old_object + new_logic) that traps funds?

## Common False Positives

1. **True upgrade with type preservation**: Package upgrade via UpgradeCap with `compatible` policy preserves existing types
2. **Intentional immutability**: Old package deliberately left callable as a legacy compatibility layer
3. **Version guard pattern**: Shared objects contain a version field, old functions abort on version mismatch
4. **Admin-controlled migration**: Stranded assets recoverable via AdminCap-gated functions

## Output Schema

```markdown
## Finding [MG-N]: Title

**Verdict**: CONFIRMED / PARTIAL / REFUTED / CONTESTED
**Step Execution**: checkmark1,2,3,4,5,6 | xN(reason) | ?N(uncertain)
**Rules Applied**: [R4:___, R9:___, R10:___, R13:___]
**Severity**: Critical/High/Medium/Low/Info
**Location**: sources/{module}.move:LineN

**Object Transition**:
- Old: {old_package::module}
- New: {new_package::module}
- Mismatch Point: {where types/versions diverge}

**Description**: What is wrong
**Impact**: What can happen (stranded funds, bypassed security, broken composability)
**Evidence**: Code showing mismatch

### Precondition Analysis (if PARTIAL/REFUTED)
**Missing Precondition**: [What blocks exploitation]
**Precondition Type**: STATE / ACCESS / TIMING / EXTERNAL / BALANCE

### Postcondition Analysis (if CONFIRMED/PARTIAL)
**Postconditions Created**: [What conditions this creates]
**Postcondition Types**: [List applicable types]
```

---

## Step Execution Checklist (MANDATORY)

| Step | Required | Completed? | Notes |
|------|----------|------------|-------|
| 1. Identify Token Transitions | YES | | Upgrade lineage vs separate deployment |
| 2. Check Interface Compatibility | YES | | Sui upgrade policy rules |
| 3. Trace Token Flow Paths | YES | | |
| 3b. External Side Effect Compatibility | YES | | |
| 3c. Pre-Upgrade Object Inventory | YES | | |
| 4. Stranded Asset Analysis (4a-4e) | YES | | All four scenarios modeled |
| 4f. User-Blocks-Admin Scenarios | YES | | |
| 5. External Package Verification | YES | | |
| 6. Downstream Integration Compatibility | YES | | |

If any step skipped, document valid reason (N/A, immutable package, single version, no downstream consumers).
