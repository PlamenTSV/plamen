---
name: "centralization-risk"
description: "Trigger Pattern Protocol has privileged capabilities (AdminCap, OwnerCap, UpgradeCap, TreasuryCap, custom caps) - Inject Into Breadth agents (optional), depth-state-trace"
---

# Skill: CENTRALIZATION_RISK (Sui)

> **Trigger Pattern**: Protocol has privileged capabilities (AdminCap, OwnerCap, UpgradeCap, TreasuryCap, custom caps)
> **Inject Into**: Breadth agents (optional), depth-state-trace
> **Finding prefix**: `[CR-N]`
> **Rules referenced**: R2, R6, R9, R10, R13
> **Required**: NO (recommended when protocol has 3+ distinct privileged capability types)

Covers: single points of failure, privilege escalation, capability object management, external governance dependencies, emergency powers. On Sui, centralization risk has unique dimensions: capability objects (AdminCap) are first-class owned objects that can be transferred, UpgradeCap controls full package replacement, TreasuryCap controls token supply, and shared objects can be the target of admin-gated mutations. The ownership and lifecycle of capability objects IS the access control model.

---

## Trigger Patterns

```
AdminCap|OwnerCap|UpgradeCap|TreasuryCap|GovernanceCap|OperatorCap|PauserCap|MinterCap|
Cap\b|_cap|admin|authority|privilege
```

---

## Step 1: Capability Inventory

Enumerate ALL capability objects and ALL functions requiring capabilities:

| # | Capability Type | Module | Abilities | Created Where | Holder | What It Controls | Impact If Lost/Stolen |
|---|----------------|--------|-----------|---------------|--------|------------------|----------------------|
| 1 | {CapType} | {module} | {key, store, ...} | {init or func} | {address/shared} | {list functions} | {worst case} |

**Key question for each capability**: Is it OWNED (by a single address) or SHARED (accessible via reference in any transaction)?
- **Owned AdminCap**: Only the owner can pass it as a tx argument. Strongest access control, but single point of failure.
- **Shared config with admin field**: Admin address stored in shared object. More flexible but requires `assert!(sender == admin)` checks -- verify these are present on ALL admin functions.
- **Shared capability object**: DANGEROUS -- anyone can pass a shared `AdminCap` as a transaction argument without ownership.

**Categorize each by impact**:
- **FUND_CONTROL**: Can move, lock, or destroy user funds (e.g., emergency withdraw, treasury drain)
- **PARAMETER_CONTROL**: Can change fees, rates, thresholds, delays (e.g., set_fee, set_max_leverage)
- **OPERATIONAL_CONTROL**: Can pause, unpause, add/remove pools, whitelist/blacklist
- **UPGRADE_CONTROL**: UpgradeCap -- controls package upgrades, policy changes
- **MINT_CONTROL**: TreasuryCap -- controls token supply (mint/burn)

**Sui-specific ability checks**:
- Does the capability have `store` ability? If YES -> anyone holding it can `public_transfer` it, meaning the privilege is freely transferable. Is this intentional?
- Does the capability have `drop` ability? If YES -> it can be silently discarded. For AdminCap, dropping it means admin functions become permanently uncallable. For UpgradeCap, dropping makes the package permanently immutable.
- Is the capability created ONLY in `init()`? If created elsewhere, can unauthorized parties mint new capabilities?

---

## Step 2: Capability Hierarchy and Separation

Map the capability hierarchy:

| Capability | Created By | Can Create Other Caps? | Transferable (has `store`)? | Destructible (has `drop`)? | Timelock/Delay? |
|-----------|-----------|----------------------|---------------------------|---------------------------|-----------------|
| {cap} | {init / admin_func} | YES/NO | YES/NO | YES/NO | YES/NO |

**Check**:
- [ ] Are FUND_CONTROL and UPGRADE_CONTROL separated into different capability types?
- [ ] Does any single capability type grant both PARAMETER_CONTROL and FUND_CONTROL?
- [ ] Are capability transfers behind timelocks or governance mechanisms?
- [ ] Can capabilities be destroyed, and what happens when they are?
- [ ] Is there a master capability that can create all other capabilities?

**Sui-specific separation patterns**:
- Best practice: UpgradeCap held by governance multisig, AdminCap held by operations team, TreasuryCap held by treasury
- Anti-pattern: single `init` function creates ALL caps and transfers them to `tx_context::sender()` -- single point of failure at deployment
- Two-step transfer: propose new admin -> new admin accepts. Prevents accidental transfer to wrong address.

### UpgradeCap Analysis (CRITICAL)

| Package | UpgradeCap Holder | Upgrade Policy | Destroyed? | Risk Level |
|---------|------------------|---------------|-----------|------------|
| {package_id} | {address or description} | {compatible/additive/dep_only} | YES (immutable) / NO | {assessment} |

**Risk levels**:
- **UpgradeCap destroyed (`make_immutable`)**: No upgrade risk.
- **UpgradeCap held by governance multisig with timelock**: Low risk.
- **UpgradeCap held by multisig (no timelock)**: Low-Medium risk.
- **UpgradeCap held by single address**: **CRITICAL** risk -- one compromised key replaces entire package. All shared objects now interact with attacker code.
- **UpgradeCap stored in shared object**: Check access control carefully. If extraction is possible -> same as single address risk.

---

## Step 3: Single Points of Failure

For each capability type:

| Capability | Key Compromise Impact | Current Protection | Residual Risk |
|-----------|----------------------|-------------------|---------------|
| {cap} | {what attacker can do with it} | {multisig holder? timelock wrapper?} | {what remains} |

### Sui-Specific SPOF Analysis

| Risk | Description | Severity |
|------|-------------|----------|
| **UpgradeCap compromise** | Attacker publishes malicious upgrade. All shared objects now interact with attacker code. ALL user funds at risk. | CRITICAL if single address, HIGH if multisig without timelock |
| **AdminCap compromise** | Attacker calls admin functions: drain pools, change parameters, pause protocol. | HIGH if AdminCap controls fund extraction |
| **TreasuryCap compromise** | Attacker mints unlimited tokens, diluting all holders. | HIGH if supply-sensitive protocol |
| **AdminCap with `store`** | Holder (or compromised key) can transfer AdminCap to anyone via `public_transfer`. New holder has full admin access. | Adds transfer risk to any compromise scenario |
| **AdminCap with `drop`** | Admin can accidentally destroy the capability. Admin functions become permanently uncallable. | MEDIUM -- permanent loss of admin access (Rule 9 if admin functions needed for user fund recovery) |
| **Phantom ownership** | Capability transferred to an address nobody controls (e.g., `@0x0`). Object is permanently inaccessible -- equivalent to destroying it. | Same as destruction if holding value or needed for operations |

**Severity assessment**:
- Single address with FUND_CONTROL or UPGRADE_CONTROL -> **HIGH** (minimum)
- Multisig holds capability + timelock -> **LOW** (but document)
- UpgradeCap destroyed + no admin fund extraction -> **INFO**

---

## Step 4: External Governance Dependencies

Identify parameters or behaviors controlled by EXTERNAL governance:

| Dependency | External Entity | What They Control | Protocol Impact If Changed | Notification? |
|------------|----------------|-------------------|---------------------------|---------------|
| {dep} | {entity} | {parameter/behavior} | {impact} | YES/NO |

**Sui-specific external governance**:
- **Sui framework upgrades**: Validators upgrade `sui::*` packages via governance. Can framework changes break this protocol?
- **Oracle provider changes**: If protocol reads from oracle shared object, oracle admin can change prices, feeds, or parameters
- **DeFi protocol governance**: External pools, vaults, or DEXes may change parameters
- **Bridge governance**: Wormhole guardian set rotation, Sui Bridge committee changes
- **Dependency package upgrades**: If a dependency has active UpgradeCap, its owner can publish new versions. Our package pins to specific version at compile time, but compatible upgrades preserve types that we import.

**Check**:
- Can external governance changes break protocol invariants?
- Does the protocol have circuit breakers for external changes?
- **Does the protocol verify external package addresses at call sites?** Types from compatible-upgraded packages remain the same, but behavior may change.

---

## Step 5: Emergency Powers

Document emergency/pause capabilities:

| Emergency Function | Required Capability | What It Affects | Recovery Path | Time to Recover |
|-------------------|-------------------|-----------------|---------------|-----------------|
| {func} | {cap_type} | {scope: all operations / specific pool} | {how to resume} | {estimate} |

### Sui Emergency Patterns

| Pattern | Description | Risk |
|---------|-------------|------|
| **Global pause field** | Shared config object has `paused: bool`. All user functions check it. | Standard -- check: can users withdraw when paused? |
| **Capability destruction** | Admin destroys their own capability to "renounce" control. | Irreversible -- if needed later for recovery, funds stranded |
| **Object freeze** | Admin calls `transfer::public_freeze_object` on a config. Permanent immutability. | If done to wrong object, permanent loss of admin access |
| **Package policy tightening** | UpgradeCap holder restricts policy (compatible -> additive -> immutable). | Good for security, but irreversible. Cannot loosen policy. |

**Check**:
- [ ] Can pausing strand user funds permanently? (Rule 9 -- stranded asset severity floor: minimum MEDIUM)
- [ ] Is there a maximum pause duration or automatic unpause?
- [ ] Can users emergency-withdraw during pause?
- [ ] What happens if the PauserCap/AdminCap is lost or destroyed?
- [ ] Can the protocol be permanently bricked by destroying a critical capability?
- [ ] If no exit during pause -> apply Rule 9 (minimum MEDIUM)

---

## Output Schema

```markdown
## Finding [CR-N]: Title

**Verdict**: CONFIRMED / PARTIAL / REFUTED
**Step Execution**: check1,2,3,4,5 | skip(reason) | uncertain
**Rules Applied**: [R2:___, R6:___, R9:___, R10:___, R13:___]
**Severity**: Critical/High/Medium/Low/Info
**Location**: sources/{module}.move:LineN

**Centralization Type**: FUND_CONTROL / PARAMETER_CONTROL / OPERATIONAL_CONTROL / UPGRADE_CONTROL / MINT_CONTROL
**Affected Capability**: {cap_type}
**Mitigation Present**: {multisig / timelock / UpgradeCap destroyed / governance / NONE}

**Description**: What is wrong
**Impact**: What can happen if capability is compromised, lost, or holder acts maliciously
**Recommendation**: How to mitigate (destroy UpgradeCap, use multisig, add timelock, remove `store` ability, wrap in governance)
```

---

## Step Execution Checklist (MANDATORY)

| Step | Required | Completed? | Notes |
|------|----------|------------|-------|
| 1. Capability Inventory (all cap-gated functions) | YES | | Owned vs shared, abilities checked |
| 2. Capability Hierarchy and Separation | YES | | `store`/`drop` analysis, UpgradeCap assessment |
| 3. Single Points of Failure (per capability) | YES | | |
| 4. External Governance Dependencies | YES | | |
| 5. Emergency Powers and Recovery Paths | YES | | |

### Cross-Reference Markers

**After Step 1**: Cross-reference with ABILITY_ANALYSIS Section 4 (Capability Pattern Audit) -- capabilities with `store` enable unrestricted transfer.

**After Step 2**: If UpgradeCap held by single address -> immediate finding (minimum HIGH).

**After Step 3**: If AdminCap has `drop` and is needed for fund recovery -> Rule 9 stranded asset finding.

**After Step 5**: If no emergency withdraw exists AND pause is possible -> Rule 9 stranded asset finding.

**After Step 5**: If protocol claims trustlessness but retains UpgradeCap/AdminCap -> Rule 13 anti-normalization finding.

If any step skipped, document valid reason (N/A, no external governance, no emergency functions, single capability only).
