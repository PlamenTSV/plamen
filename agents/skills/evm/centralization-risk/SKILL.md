---
name: "centralization-risk"
description: "Trigger Protocol has privileged roles (admin, owner, operator, governance, multisig) - Covers Single points of failure, privilege escalation, external governance dependencies"
---

# Skill: CENTRALIZATION_RISK

> **Trigger**: Protocol has privileged roles (admin, owner, operator, governance, multisig)
> **Covers**: Single points of failure, privilege escalation, external governance dependencies
> **Required**: NO (optional -- recommended when protocol has 3+ distinct privileged roles)

## Trigger Patterns

```
onlyOwner|onlyAdmin|onlyGovernance|DEFAULT_ADMIN_ROLE|OPERATOR_ROLE|timelock|multisig|governance
```

## Reasoning Template

### Step 1: Privilege Inventory

Enumerate ALL privileged functions using Slither (`list_functions` + `analyze_modifiers`):

| # | Function | Contract | Modifier/Role | What It Controls | Impact If Abused |
|---|----------|----------|---------------|------------------|-----------------|
| 1 | {func} | {contract} | {role} | {parameter/state} | {worst case} |

**Categorize each by impact**:
- **FUND_CONTROL**: Can move, lock, or destroy user funds
- **PARAMETER_CONTROL**: Can change fees, rates, thresholds, delays
- **OPERATIONAL_CONTROL**: Can pause, unpause, add/remove components
- **UPGRADE_CONTROL**: Can change contract logic

### Step 2: Role Hierarchy and Separation

Map the role hierarchy:

| Role | Granted By | Can Grant Others? | Revocable? | Timelock? |
|------|-----------|-------------------|-----------|-----------|
| {role} | {grantor} | YES/NO | YES/NO | YES/NO ({duration}) |

**Check**:
- [ ] Are FUND_CONTROL and UPGRADE_CONTROL separated into different roles?
- [ ] Does any single role have both PARAMETER_CONTROL and FUND_CONTROL?
- [ ] Are role assignments behind timelocks?
- [ ] Can roles be revoked, and by whom?

### Step 3: Single Points of Failure

For each privileged role:

| Role | Key Compromise Impact | Mitigation | Residual Risk |
|------|----------------------|------------|---------------|
| {role} | {what attacker can do} | {multisig? timelock? guardian?} | {what remains} |

**Severity assessment**:
- Single EOA with FUND_CONTROL -> HIGH centralization risk
- Multisig with FUND_CONTROL but no timelock -> MEDIUM
- Multisig + timelock with FUND_CONTROL -> LOW (but document)
- No FUND_CONTROL -> INFO

### Step 4: External Governance Dependencies

Identify parameters or behaviors controlled by EXTERNAL governance:

| Dependency | External Entity | What They Control | Protocol Impact If Changed | Notification? |
|------------|----------------|-------------------|---------------------------|---------------|
| {dep} | {entity} | {parameter/behavior} | {impact on this protocol} | YES/NO |

**Pattern**: Protocol depends on external governance decisions (e.g., external protocol upgrades, token migrations, parameter changes) that can silently affect this protocol's behavior without any on-chain notification.

**Check**:
- Can external governance changes break protocol invariants?
- Does the protocol have circuit breakers for external changes?
- Are external governance timelines aligned with this protocol's operational timelines?

### Step 5: Emergency Powers

Document emergency/pause capabilities:

| Emergency Function | Who Can Call | What It Affects | Recovery Path | Time to Recover |
|-------------------|-------------|-----------------|---------------|-----------------|
| {func} | {role} | {scope} | {how to resume} | {estimate} |

**Check**:
- [ ] Can pausing strand user funds permanently?
- [ ] Is there a maximum pause duration?
- [ ] Can users exit during pause (emergency withdraw)?
- [ ] If no exit during pause -> apply Rule 9 (stranded asset severity floor)

## Output Schema

```markdown
## Finding [CR-N]: Title

**Verdict**: CONFIRMED / PARTIAL / REFUTED
**Step Execution**: checkmark1,2,3,4,5 | xN(reason) | ?N(uncertain)
**Severity**: Critical/High/Medium/Low/Info
**Location**: Contract.sol:LineN

**Centralization Type**: FUND_CONTROL / PARAMETER_CONTROL / OPERATIONAL_CONTROL / UPGRADE_CONTROL
**Affected Role**: {role_name}
**Mitigation Present**: {multisig/timelock/guardian/NONE}

**Description**: What's wrong
**Impact**: What can happen if role is compromised or acts maliciously
**Recommendation**: How to mitigate (add timelock, separate roles, add guardian)
```

## Step Execution Checklist

- [ ] Step 1: ALL privileged functions enumerated (via Slither, not manual scan)
- [ ] Step 2: Role hierarchy mapped with separation analysis
- [ ] Step 3: Single points of failure identified for each role
- [ ] Step 4: External governance dependencies documented
- [ ] Step 5: Emergency powers and recovery paths assessed
