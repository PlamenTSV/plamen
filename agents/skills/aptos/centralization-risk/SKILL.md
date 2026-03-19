---
name: "centralization-risk"
description: "Trigger Protocol has privileged roles (admin, operator, governance, resource account owner) - Covers Single points of failure, privilege escalation, external governance dependen..."
---

# Skill: CENTRALIZATION_RISK

> **Trigger**: Protocol has privileged roles (admin, operator, governance, resource account owner)
> **Covers**: Single points of failure, privilege escalation, external governance dependencies
> **Required**: NO (optional -- recommended when protocol has 3+ distinct privileged roles)
> **Inject Into**: Breadth agents

## Trigger Patterns

```
admin|owner|operator|governance|signer_cap|SignerCapability|resource_account|
has_role|is_admin|only_admin|assert_admin|get_signer
```

## Aptos Capability Model Context

Aptos Move uses a capability-based access control model fundamentally different from EVM modifiers:
- **Signer-based**: Functions receive `&signer` and check `signer::address_of(account) == @admin`
- **Capability pattern**: `SignerCapability` stored in resources grants signing rights to resource accounts
- **No modifiers**: Access control is enforced via `assert!` checks inside function bodies
- **Resource accounts**: Accounts controlled by `SignerCapability` rather than a private key
- **Object ownership**: `Object<T>` has an owner chain; ownership transfers control access

## Reasoning Template

### Step 1: Privilege Inventory

Enumerate ALL capability-gated functions by searching for signer checks and capability usage:

| # | Function | Module | Access Gate | What It Controls | Impact If Abused |
|---|----------|--------|------------|------------------|-----------------|
| 1 | {func} | {module} | `assert!(addr == @admin)` | {parameter/state} | {worst case} |
| 2 | {func} | {module} | `SignerCapability` stored in {resource} | {operation} | {worst case} |
| 3 | {func} | {module} | `Object<T>` ownership check | {asset control} | {worst case} |

**MANDATORY GREP**: Search all `.move` files for:
- `signer::address_of` followed by equality checks
- `SignerCapability` usage (creation, storage, `account::create_signer_with_capability`)
- `object::is_owner` and ownership assertions
- Named address references (`@admin`, `@operator`, `@governance`, `@protocol`)

**Categorize each by impact**:
- **FUND_CONTROL**: Can move, lock, freeze, or destroy user funds/assets
- **PARAMETER_CONTROL**: Can change fees, rates, thresholds, delays
- **OPERATIONAL_CONTROL**: Can pause, unpause, add/remove components, whitelist/blacklist
- **UPGRADE_CONTROL**: Can upgrade module code (publish new version)

### Step 2: Role Hierarchy and Capability Delegation

Map the capability hierarchy:

| Role/Capability | Granted By | Can Delegate? | Stored Where? | Revocable? | Timelock? |
|----------------|-----------|---------------|--------------|-----------|-----------|
| Admin signer | Deployment (named address) | NO (fixed) | N/A -- address-based | NO (immutable) | NO |
| SignerCapability | account::create_resource_account | YES (if stored with `store`) | {resource at @addr} | {depends on module logic} | {YES/NO} |
| Object owner | object::transfer | YES (transfer ownership) | Object metadata | YES (transfer away) | NO |

**Aptos-specific checks**:
- [ ] Are FUND_CONTROL and UPGRADE_CONTROL separated into different addresses/capabilities?
- [ ] Does any single address have both PARAMETER_CONTROL and FUND_CONTROL?
- [ ] Can `SignerCapability` be duplicated? (if the resource containing it has `copy` ability -- CRITICAL)
- [ ] Can capabilities be extracted from the storing resource by anyone? (check resource field visibility)
- [ ] Is the resource account SignerCapability stored behind proper access control?

### Step 3: Single Points of Failure

For each privileged role:

| Role | Key Compromise Impact | Mitigation | Residual Risk |
|------|----------------------|------------|---------------|
| @admin (EOA) | {what attacker can do} | {multisig? module-level checks?} | {what remains} |
| Resource account | {what attacker can do if SignerCapability leaked} | {capability stored in immutable resource?} | {what remains} |
| Object owner | {what attacker can do with object control} | {ownership transfer gated?} | {what remains} |

**Severity assessment**:
- Single EOA address with FUND_CONTROL -> HIGH centralization risk
- Multisig controlling admin address (off-chain, not verifiable on-chain) -> MEDIUM
- Resource account with properly guarded SignerCapability -> LOW (but document)
- Module published as `immutable` -> eliminates UPGRADE_CONTROL risk entirely

**Aptos-specific risk**: `SignerCapability` is the most dangerous capability -- it grants FULL control over the resource account, including publishing modules and transferring all assets. If the resource containing the capability has improper access control, it is equivalent to leaking a private key.

### Step 4: External Governance Dependencies

Identify parameters or behaviors controlled by EXTERNAL governance:

| Dependency | External Entity | What They Control | Protocol Impact If Changed | Notification? |
|------------|----------------|-------------------|---------------------------|---------------|
| {dep} | {entity} | {parameter/behavior} | {impact on this protocol} | YES/NO |

**Aptos-specific patterns**:
- **Framework governance**: `aptos_framework` parameters controlled by Aptos governance (staking, gas, transaction limits)
- **External module upgrades**: Modules the protocol depends on upgrading under `compatible` policy -- new abort conditions, changed behavior
- **Oracle operator changes**: Oracle price feed operators changing configs, adding latency, pausing feeds
- **Bridge governance**: Wormhole guardian set changes, LayerZero oracle/relayer config

**Check**:
- Can external governance changes break protocol invariants?
- Does the protocol have circuit breakers for external changes?
- Are external governance timelines aligned with this protocol operational timelines?

### Step 5: Emergency Powers

Document emergency/pause capabilities:

| Emergency Function | Who Can Call | What It Affects | Recovery Path | Time to Recover |
|-------------------|-------------|-----------------|---------------|-----------------|
| {func} | {role/address} | {scope} | {how to resume} | {estimate} |

**Aptos-specific checks**:
- [ ] Can pausing strand user funds permanently? (resources stay in global storage but no exit path)
- [ ] Is there a maximum pause duration enforced on-chain?
- [ ] Can users exit during pause (emergency withdraw function)?
- [ ] If module is published as `immutable` and paused -> permanent freeze? (no upgrade possible)
- [ ] Can the freeze/blacklist mechanism on FungibleAsset be used as an emergency power?
- [ ] If no exit during pause -> apply Rule 9 (stranded asset severity floor)

## Instantiation Parameters

```
{CONTRACTS}           -- List of modules to analyze
{ADMIN_ADDRESSES}     -- Named addresses with privileged access (@admin, @operator, etc.)
{CAPABILITY_RESOURCES} -- Resources that store SignerCapability or other capabilities
{EXTERNAL_DEPS}       -- External modules with governance dependencies
```

## Output Schema

```markdown
## Finding [CR-N]: Title

**Verdict**: CONFIRMED / PARTIAL / REFUTED
**Step Execution**: check1,2,3,4,5 | X(reason) | ?(uncertain)
**Severity**: Critical/High/Medium/Low/Info
**Location**: module::function (source_file.move:LineN)

**Centralization Type**: FUND_CONTROL / PARAMETER_CONTROL / OPERATIONAL_CONTROL / UPGRADE_CONTROL
**Affected Role**: {role_name / address / capability}
**Mitigation Present**: {multisig/timelock/immutable module/NONE}

**Description**: What is wrong
**Impact**: What can happen if role is compromised or acts maliciously
**Recommendation**: How to mitigate (add timelock module, separate capabilities, publish immutable)
```

## Step Execution Checklist

- [ ] Step 1: ALL privileged functions enumerated (via grep for signer checks + capabilities)
- [ ] Step 2: Capability hierarchy mapped with delegation analysis
- [ ] Step 3: Single points of failure identified for each role/capability
- [ ] Step 4: External governance dependencies documented
- [ ] Step 5: Emergency powers and recovery paths assessed
