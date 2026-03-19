---
name: "package-version-safety"
description: "Trigger Pattern PACKAGE_UPGRADE flag (UpgradeCap detected, multiple package versions, upgrade policy references) - Inject Into Breadth agents, depth-external"
---

# Skill: PACKAGE_VERSION_SAFETY (Sui)

> **Trigger Pattern**: PACKAGE_UPGRADE flag (UpgradeCap detected, multiple package versions, upgrade policy references)
> **Inject Into**: Breadth agents, depth-external
> **Finding prefix**: `[PV-N]`
> **Rules referenced**: R4, R8, R9, R10

Sui packages are immutable once published. "Upgrading" a package means publishing a NEW version at a NEW on-chain address, linked to the original via the UpgradeCap lineage. The old version's code remains callable forever. This creates a fundamentally different upgrade risk model compared to EVM proxies: instead of replacing logic in-place, Sui packages accumulate versions -- and shared objects may be accessible by ALL versions simultaneously.

---

## Trigger Patterns

```
UpgradeCap|upgrade_policy|package::make_immutable|compatible|additive|dep_only|version|
migrate|old_version|new_version
```

---

## Step 1: Upgrade Policy Inventory

For each package in scope:

| # | Package | UpgradeCap Location | UpgradeCap Holder | Has `store`? | Upgrade Policy | Destroyed? |
|---|---------|--------------------|--------------------|-------------|---------------|-----------|
| 1 | {pkg_name} | {init function:line} | {address / shared / wrapped in governance} | YES/NO | {compatible/additive/dep_only} | YES (immutable) / NO |

**Checks**:
- **Where is UpgradeCap stored?**
  - Owned by deployer address: Single point of failure. Key loss -> permanent immutability. Key theft -> attacker can upgrade.
  - Shared object: DANGEROUS -- anyone can pass it to upgrade functions.
  - Wrapped in governance object: Good pattern -- upgrade requires governance approval.
  - Destroyed via `make_immutable()`: Package is permanently immutable. No upgrade risk.
  - Transferred to `@0x0` or burn address: Effectively immutable.

- **Can UpgradeCap be transferred?**
  - UpgradeCap has `key + store` by default -> freely transferable via `public_transfer`.
  - Is there a custom wrapper restricting transfer? (e.g., `GovernanceCap` wrapping `UpgradeCap`)
  - If transferable and held by EOA -> attacker stealing key can transfer UpgradeCap.

- **Can UpgradeCap be destroyed?**
  - `sui::package::make_immutable(cap)` consumes UpgradeCap -> permanent immutability.
  - If UpgradeCap has `drop` via wrapper -> accidental destruction possible.

### 1b. UpgradeCap Governance Assessment

| Governance Model | Risk Level | Assessment |
|-----------------|------------|------------|
| Single EOA | CRITICAL | One key compromise replaces all package logic |
| Multisig (2/3 or lower) | HIGH | Low collusion threshold |
| Multisig (3/5+) | MEDIUM | Requires majority collusion |
| Multisig + timelock | LOW | Users can exit before malicious upgrade takes effect |
| DAO/governance contract | LOW | Distributed control, but check voter distribution |
| Destroyed (immutable) | NONE | Cannot upgrade, but also cannot patch bugs |

---

## Step 2: Version Consistency Check

For shared objects created by this package:

| Shared Object | Created By (Version) | Current Version Field? | V1 Functions Access? | V2 Functions Access? | Consistency Risk |
|--------------|---------------------|----------------------|---------------------|---------------------|-----------------|
| {obj_type} | V1 `init()` | YES: `version: u64` / NO | {list funcs} | {list funcs} | {describe} |

**What happens when package is upgraded?**
- Existing shared objects created by V1 remain at their original address
- V2 functions CAN access V1-created shared objects (types are preserved in compatible upgrades)
- V1 functions are STILL callable and CAN access the same shared objects
- This dual-access is the primary version safety concern

**Can old-version and new-version calls on same shared object create inconsistency?**
- V1 function writes field A based on formula F1
- V2 function writes field A based on formula F2
- User calls V1 then V2 in separate transactions -> field A has inconsistent state
- **Especially dangerous**: V2 adds a new check that V1 lacks. Attacker calls V1 to bypass V2's check.

---

## Step 3: Dependency Version Pinning

For each dependency in `Move.toml`:

| Dependency | Source | Pinned To | Immutable? | Upgrade Risk |
|-----------|--------|-----------|-----------|-------------|
| Sui Framework | `sui = "..."` | {git rev or latest} | Upgraded by validators | Framework upgrade could change behavior |
| MoveStdlib | `MoveStdlib = "..."` | {git rev} | Upgraded with framework | Same as above |
| {third_party} | {git url or on-chain} | {specific rev / branch / on-chain version} | YES/NO | {describe} |

**Checks**:
- Are third-party dependencies pinned to specific git revisions? If pinned to `main` -> upstream changes included on recompile.
- For on-chain published dependencies: is the dependency package immutable? If it has active UpgradeCap -> behavior can change.
- Can a dependency upgrade break our package's invariants?
- Are there transitive dependencies with their own upgrade risks?

**Can dependency upgrade break our package?**
- Compatible dependency upgrade: function implementations can change but signatures preserved. Our calls still compile but behavior may differ.
- Additive dependency upgrade: only new functions/types added. Existing behavior frozen.
- Framework upgrades: `sui::*` packages upgraded by validators. Can change Move VM behavior, gas costs, object model rules.

---

## Step 4: Type Compatibility Across Versions

When package V2 adds new types or fields:

| Type | V1 Definition | V2 Changes | Compatible Upgrade Rule | Migration Needed? |
|------|-------------|-----------|------------------------|------------------|
| {struct_name} | {fields} | {cannot change for compatible} | Struct layouts FROZEN | NO -- same layout |
| {new_struct} | N/A | {new in V2} | New types allowed | N/A |

**Sui type rules for compatible upgrades**:
- Existing struct field layouts CANNOT change (enforced by validator during upgrade)
- New structs CAN be added
- Existing function signatures CANNOT change
- Function bodies CAN change (this is where logic vulnerabilities occur)
- Generic type parameters must remain the same

**Can V1 objects be used with V2 functions?**
- YES for compatible upgrades: types are identical, V2 functions accept V1 objects.
- NO for separate package deployment: different package address = different types.

**Can V2 objects be used with V1 functions?**
- V2 does not create new object types that V1 knows about (V1 code is frozen).
- But V2 functions can modify shared objects that V1 functions then read -- state corruption possible.

**Dynamic field implications**:
- Dynamic fields keyed by type. If V2 changes key/value types for dynamic fields -> V1-era entries orphaned.
- Check: does V2 change any dynamic field key types?

---

## Step 5: Upgrade Migration Safety

Does the package have migration functions to update shared objects from V1->V2 state?

| Migration Function | Trigger | What It Updates | Reversible? | Access Control |
|-------------------|---------|----------------|-----------|---------------|
| {migrate_func} | {admin call / automatic} | {version field, new state} | NO | {AdminCap / anyone} |

**Version guard pattern**: Shared objects contain `version: u64`. V1 functions check `assert!(version == 1)`. V2 migration function sets `version = 2`. After migration, V1 functions abort because version != 1.

**Check**:
- Is version guard implemented? If NOT -> old functions remain callable indefinitely -> FINDING.
- Can migration be triggered by unauthorized parties?
- Is migration atomic? Can it be partially completed?
- What happens to user-owned objects during migration? (Owned objects cannot be modified by admin migration)

---

## Step 6: UpgradeCap Governance

If UpgradeCap is owned by a single address:

| Risk | Description | Severity |
|------|-------------|----------|
| **Full logic replacement** | Attacker upgrades package with malicious code. All shared objects now interact with attacker's logic. | CRITICAL |
| **Subtle parameter change** | Attacker upgrades to change a fee calculation or threshold in function body. Hard to detect. | HIGH |
| **Dependency manipulation** | Attacker upgrades to change dependency versions, pulling in vulnerable code. | HIGH |
| **Policy escalation blocked** | Upgrade policies can only be tightened (compatible -> additive -> dep_only -> immutable). Attacker cannot escalate from additive to compatible. | Mitigation |

**Mitigations to check**:
- [ ] Is UpgradeCap behind multisig?
- [ ] Is there an upgrade timelock (users can exit before upgrade takes effect)?
- [ ] Is there a multi-party approval mechanism for upgrades?
- [ ] Has the upgrade policy been tightened from the default `compatible`?
- [ ] Is `make_immutable()` called in `init()` for packages that should never upgrade?

---

## Key Questions (Must Answer All)

1. **UpgradeCap security**: Who holds it? What is the attack surface if compromised?
2. **Upgrade policy**: Is the policy appropriate? Could it be tightened without losing needed functionality?
3. **Cross-version bypass**: Can old functions bypass security checks added in new versions?
4. **Version guard**: Is there a mechanism to disable old functions after upgrade?
5. **Type compatibility**: Are all types compatible? Are dynamic fields accessible across versions?

---

## Common False Positives

1. **Immutable package**: UpgradeCap destroyed or `make_immutable` called -> no upgrade risk
2. **No shared objects**: If old and new packages share no objects, cross-version interaction impossible
3. **Version guard implemented**: Shared objects check version field, old functions abort after migration
4. **Capability migrated**: Old package's capabilities consumed by new package, old functions uncallable
5. **`additive` or `dep_only` policy**: Existing logic frozen (but new functions can still access shared objects -- check Step 3c)

---

## Output Schema

```markdown
## Finding [PV-N]: Title

**Verdict**: CONFIRMED / PARTIAL / REFUTED / CONTESTED
**Step Execution**: check1,2,3,4,5,6 | skip(reason) | uncertain
**Rules Applied**: [R4:___, R8:___, R9:___, R10:___]
**Severity**: Critical/High/Medium/Low/Info
**Location**: sources/{module}.move:LineN

**Upgrade Risk Type**: UPGRADECAP_MANAGEMENT / POLICY_INAPPROPRIATE / CROSS_VERSION_BYPASS / TYPE_INCOMPATIBILITY / DEPENDENCY_RISK / MISSING_VERSION_GUARD
**Package Version**: V{N} -> V{N+1}
**Shared Objects Affected**: {list}

**Description**: What is wrong
**Impact**: What can happen (logic replacement, security bypass, stranded assets, type mismatch)
**Evidence**: Code showing vulnerability
**Recommendation**: How to fix (tighten policy, add version guard, migrate capabilities, destroy UpgradeCap)
```

---

## Step Execution Checklist (MANDATORY)

| Step | Required | Completed? | Notes |
|------|----------|------------|-------|
| 1. Upgrade Policy Inventory | YES | | UpgradeCap location, holder, policy |
| 1b. UpgradeCap Governance Assessment | YES | | Risk level for each package |
| 2. Version Consistency Check | YES | | All shared objects checked for dual-version access |
| 3. Dependency Version Pinning | YES | | Move.toml analyzed |
| 4. Type Compatibility Across Versions | YES | | Dynamic fields included |
| 5. Upgrade Migration Safety | YES | | Version guard pattern checked |
| 6. UpgradeCap Governance | IF single-address holder | | Multisig/timelock/approval checks |

### Cross-Reference Markers

**After Step 1**: If UpgradeCap held by single address -> immediate finding (minimum HIGH).

**After Step 2**: If cross-version bypass possible -> cross-reference with MIGRATION_ANALYSIS Step 5 for shared object function enumeration.

**After Step 3**: Feed dependency risks to DEPENDENCY_AUDIT for transitive dependency analysis.

**After Step 5**: If no version guard AND shared objects hold user funds -> minimum HIGH finding.

If any step skipped, document valid reason (N/A, package is immutable, no shared objects, no third-party dependencies).
