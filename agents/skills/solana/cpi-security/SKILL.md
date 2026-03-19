---
name: "cpi-security"
description: "Trigger Pattern CPI flag detected (invoke/invoke_signed/CpiContext usage) - Inject Into Breadth agents, depth agents"
---

# CPI_SECURITY Skill

> **Trigger Pattern**: CPI flag detected (invoke/invoke_signed/CpiContext usage)
> **Inject Into**: Breadth agents, depth agents
> **Finding prefix**: `[CPI-N]`
> **Rules referenced**: S3, S5, R1, R4

For every Cross-Program Invocation (CPI) in the Solana program:

## 1. CPI Target Inventory

Enumerate ALL CPI calls:

| # | Location | CPI Type | Target Program | Target Instruction | Accounts Forwarded | Signers Forwarded |
|---|----------|----------|----------------|-------------------|--------------------|-------------------|
| 1 | {file:line} | invoke/invoke_signed/CpiContext | {program_id} | {instruction} | {list} | {list} |

## 2. Target Program Validation

For each CPI call, verify the target program ID:

| CPI | Program ID Source | Hardcoded/Validated? | Spoofable? |
|-----|------------------|---------------------|-----------|
| {cpi} | {where program_id comes from} | Hardcoded constant / Validated against known / FROM USER INPUT | {if from input: CRITICAL finding} |

**Attack (S3)**: If program ID comes from user input without validation, attacker substitutes a malicious program that mimics the expected interface but steals funds.
**Defense**: Always validate program ID against a hardcoded constant or well-known program address.

## 3. Signer Privilege Tracing

For each CPI that forwards signers:

| CPI | Signer Source | Privilege Level | Should Forward? | Over-Privileged? |
|-----|--------------|----------------|-----------------|------------------|
| {cpi} | {PDA / user wallet / authority} | {what the signer can do in target} | YES/NO | {if forwarding more privilege than needed} |

**Attack**: Forwarding user's wallet as signer to a CPI target that uses it for unintended operations.
**Pattern**: PDA signers via `invoke_signed` are safe (program-controlled). User wallet forwarding needs careful scoping.

## 4. Account Reload Audit (S5 - CRITICAL)

For each CPI call, check what accounts are read AFTER the CPI returns:

| CPI | Accounts Modified by Target | Read After CPI? | reload() Called? | Owner Re-checked? |
|-----|---------------------------|----------------|-----------------|-------------------|
| {cpi} | {list accounts CPI can modify} | YES/NO | YES/NO | YES/NO |

**Attack (S5)**: CPI target modifies account data. Caller reads stale cached data without `reload()`.
**CRITICAL**: Anchor's `reload()` refreshes data but does NOT re-verify the account owner. A CPI target could `assign` the account to a different program. After `reload()`, the data is fresh but the owner may have changed.
**Full defense**: After CPI, both `reload()` AND re-check `account.owner`.

## 5. Lamport Balance Conservation

For each CPI that transfers SOL:

| CPI | Expected Lamport Change | Actual Change Verified? | Drain Risk? |
|-----|------------------------|------------------------|------------|
| {cpi} | {expected delta} | YES/NO | {if NO: CPI could drain more than expected} |

**Attack**: CPI target drains more lamports than expected from accounts owned by the caller's program.
**Defense**: Check lamport balances before and after CPI; verify delta matches expected amount.

## 6. Account Owner Check Post-CPI

For each CPI that could modify account ownership:

| CPI | Can Target Call system_program::assign? | Owner Checked After CPI? | Risk |
|-----|----------------------------------------|------------------------|------|
| {cpi} | YES/NO | YES/NO | {if YES and NO: account hijacking} |

**Attack**: CPI target uses `system_program::assign` to change account owner to attacker-controlled program. Caller continues using the account assuming it's still owned by its program.

## 7. CPI Depth Analysis

For each code path with nested CPIs:

| Entry Point | CPI Chain | Max Depth | CU Cost Estimate | Risk |
|-------------|-----------|-----------|-----------------|------|
| {instruction} | {A → B → C} | {depth} | {estimate} | {CU exhaustion?} |

**Solana limit**: CPI depth capped at 4 levels. Check if deep chains approach this limit.

## Finding Template

```markdown
**ID**: [CPI-N]
**Severity**: [based on impact: fund theft via program spoofing = Critical, stale data = High]
**Step Execution**: ✓1,2,3,4,5,6,7 | ✗(reasons) | ?(uncertain)
**Rules Applied**: [S3:✓, S5:✓, R1:✓, R4:✓/✗]
**Location**: program/src/{file}.rs:LineN
**Title**: [CPI issue type] in [instruction] enables [attack]
**Description**: [Specific CPI vulnerability with call chain trace]
**Impact**: [Fund theft / state corruption / privilege escalation]
```

---

## Step Execution Checklist (MANDATORY)

| Section | Required | Completed? | Notes |
|---------|----------|------------|-------|
| 1. CPI Target Inventory | YES | ✓/✗/? | For every CPI |
| 2. Target Program Validation | YES | ✓/✗/? | For every CPI |
| 3. Signer Privilege Tracing | YES | ✓/✗/? | For every CPI with signers |
| 4. Account Reload Audit | YES | ✓/✗/? | **CRITICAL** - most common CPI bug |
| 5. Lamport Balance Conservation | IF SOL transfers | ✓/✗(N/A)/? | |
| 6. Account Owner Check Post-CPI | YES | ✓/✗/? | assign attack prevention |
| 7. CPI Depth Analysis | IF nested CPIs | ✓/✗(N/A)/? | CU exhaustion risk |
