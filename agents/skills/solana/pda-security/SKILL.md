---
name: "pda-security"
description: "Trigger Pattern PDA flag detected (seeds/bump/find_program_address usage) - Inject Into Breadth agents, depth agents"
---

# PDA_SECURITY Skill

> **Trigger Pattern**: PDA flag detected (seeds/bump/find_program_address usage)
> **Inject Into**: Breadth agents, depth agents
> **Finding prefix**: `[PDA-N]`
> **Rules referenced**: S2, S1

For every PDA in the Solana program:

## 1. PDA Seed Inventory

List all PDA seed declarations:

| # | PDA Name | Seeds | Purpose | Anchor Constraint | Location |
|---|----------|-------|---------|------------------|----------|
| 1 | {name} | `[b"prefix", user.key().as_ref(), &[bump]]` | {what it stores} | `seeds = [...], bump` | {file:line} |

## 2. Canonical Bump Enforcement

For each PDA:

| PDA | Bump Source | Canonical? | Risk if Non-Canonical |
|-----|-----------|-----------|---------------------|
| {name} | Anchor auto (`bump`) / `find_program_address` / USER INPUT | YES/NO | {if NO: multiple valid addresses} |

**Attack (S2)**: If bump is user-supplied, attacker can use a non-canonical bump to derive a DIFFERENT address that still passes `create_program_address`. This creates a separate PDA from the intended one.
**Defense**: Always use `find_program_address` (returns canonical bump) or Anchor's `bump` constraint.

## 3. Seed Collision Analysis

For each PAIR of PDA seed schemas:

| PDA A Seeds | PDA B Seeds | Can Byte Sequences Overlap? | Collision Risk? |
|-------------|-------------|---------------------------|----------------|
| `[b"vault", mint.as_ref()]` | `[b"vaultm", ...]` | CHECK: "vault" + mint_bytes could equal "vaultm" + other_bytes? | YES/NO |

**Attack**: Two different PDA types with seeds that can produce identical byte sequences → one PDA masquerades as another.
**Defense**: Use unique fixed-length prefixes (e.g., `b"vault\x00"`) or ensure seed structures cannot collide.

## 4. Seed Uniqueness

For each PDA type, verify seeds include sufficient uniqueness:

| PDA | Unique Per | Seeds Include User/Entity Key? | Could Two Users Share PDA? |
|-----|-----------|-------------------------------|--------------------------|
| {name} | User / Mint / Pool / Global | YES/NO | {if YES: shared state corruption} |

**Pattern**: User-specific PDAs MUST include the user's pubkey in seeds. Omitting it means all users share the same PDA.

## 5. PDA Isolation

For each PDA used as an authority or signer:

| PDA | Signs For | Isolated to Scope? | Can Different Instruction Misuse? |
|-----|-----------|-------------------|----------------------------------|
| {name} | {what operations} | YES/NO | {if NO: cross-instruction authority sharing} |

**Attack**: A PDA authority used across multiple instructions where one instruction has weaker validation → attacker uses the weak path.

## 6. PDA Sharing Detection

Check if multiple account types share the same PDA seed schema:

| Seed Schema | Account Types Using It | Type Confusion Risk? |
|-------------|----------------------|---------------------|
| `[b"data", key.as_ref()]` | {list all account types} | {if >1: type confusion possible} |

## 7. Initialization Front-Running

For each PDA created with `init`:

| PDA | Created By | Front-Runnable? | Impact if Front-Run |
|-----|-----------|----------------|---------------------|
| {name} | {instruction} | YES/NO | {attacker initializes with malicious data} |

**Attack (S2)**: Attacker front-runs PDA initialization, creating the account with attacker-controlled data before the legitimate initialization transaction.
**Defense**: `init` (not `init_if_needed`) + seeds that include the authorized initializer's pubkey.
**Warning**: `init_if_needed` is explicitly dangerous - it silently succeeds if account already exists with potentially malicious data.

## Finding Template

```markdown
**ID**: [PDA-N]
**Severity**: [based on impact: seed collision = Critical, non-canonical bump = High]
**Step Execution**: ✓1,2,3,4,5,6,7 | ✗(reasons) | ?(uncertain)
**Rules Applied**: [S2:✓, S1:✓]
**Location**: program/src/{file}.rs:LineN
**Title**: [PDA issue type] in [context] enables [attack]
**Description**: [Specific PDA vulnerability with seed analysis]
**Impact**: [Fund theft via PDA confusion / state corruption / front-running]
```

---

## Step Execution Checklist (MANDATORY)

| Section | Required | Completed? | Notes |
|---------|----------|------------|-------|
| 1. PDA Seed Inventory | YES | ✓/✗/? | For every PDA |
| 2. Canonical Bump Enforcement | YES | ✓/✗/? | For every PDA |
| 3. Seed Collision Analysis | YES | ✓/✗/? | For every PDA pair |
| 4. Seed Uniqueness | YES | ✓/✗/? | User-specific PDAs |
| 5. PDA Isolation | IF PDA used as authority | ✓/✗(N/A)/? | Cross-instruction misuse |
| 6. PDA Sharing Detection | YES | ✓/✗/? | Type confusion |
| 7. Initialization Front-Running | IF init used | ✓/✗(N/A)/? | init_if_needed is dangerous |
