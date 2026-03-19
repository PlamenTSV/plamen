---
name: "account-validation"
description: "Trigger Pattern Always required for Solana audits - Inject Into Breadth agents, depth agents"
---

# ACCOUNT_VALIDATION Skill

> **Trigger Pattern**: Always required for Solana audits
> **Inject Into**: Breadth agents, depth agents
> **Finding prefix**: `[AV-N]`
> **Rules referenced**: S1, S6, S7, S8, R4

For every instruction handler in the Solana program:

## 1. Account Type Inventory

For EACH instruction, list every account with expected constraints:

| # | Account Name | Expected Owner | Expected Type (Discriminator) | Mutable? | Signer? | Constraints (has_one, seeds, etc.) |
|---|-------------|----------------|-------------------------------|----------|---------|-----------------------------------|
| 1 | {name} | {program_id / system / token} | {Account<T> / UncheckedAccount / etc.} | YES/NO | YES/NO | {list all} |

**Anchor auto-checks**: Anchor's `Account<T>` validates owner + discriminator automatically. `UncheckedAccount` / `AccountInfo` do NOT - manual validation required.

## 2. Owner Check Audit

For each `AccountInfo` or `UncheckedAccount` usage:

| Account | Owner Validated? | Validation Location | Correct Owner? | Missing? |
|---------|-----------------|---------------------|---------------|----------|
| {name} | YES/NO | {line} | {expected vs actual} | FLAG if NO |

**Critical pattern**: Any `AccountInfo` deserialized without prior owner check → arbitrary data injection.
**Anchor pattern**: `#[account(owner = expected_program)]` or manual `require!(account.owner == &expected_id)`.

## 3. Discriminator Check

For all accounts deserialized from raw data:

| Account | Uses Account<T>? | Discriminator Checked? | Can Substitute Different Account Type? |
|---------|------------------|----------------------|---------------------------------------|
| {name} | YES/NO | YES/NO (Anchor auto) | {if NO: what types could be substituted} |

**Attack**: Pass an account of Type B where Type A is expected - different data layout, fields interpreted incorrectly.
**Safe**: Anchor's `Account<T>` checks the 8-byte discriminator. Manual programs must check explicitly.

## 4. Data Matching (Cross-Account References)

For each cross-account reference (has_one, constraint, seeds):

| Instruction | Account A | Account B | Relationship | Validated? | Bypass? |
|-------------|-----------|-----------|-------------|-----------|---------|
| {ix} | {a} | {b} | {a.field == b.key()} | YES/NO | {if NO: how to exploit} |

**Pattern**: Ensure that when Account A references Account B (e.g., `vault.mint == mint.key()`), the relationship is enforced on-chain.
**Attack**: Substitute a different mint account that the vault doesn't actually belong to.

## 5. Remaining Accounts Audit

For each use of `ctx.remaining_accounts`:

| Instruction | Remaining Account Usage | Owner Validated? | Type Validated? | Signer Checked? | Data Validated? |
|-------------|------------------------|-----------------|----------------|-----------------|-----------------|
| {ix} | {purpose} | YES/NO | YES/NO | YES/NO | YES/NO |

**Critical**: `remaining_accounts` bypass Anchor's automatic validation. Every field must be checked manually.
**Attack**: Inject attacker-controlled accounts via remaining_accounts to redirect funds or corrupt state.

## 6. Duplicate Account Detection

For each instruction with 2+ mutable accounts:

| Instruction | Mutable Account A | Mutable Account B | Key Uniqueness Enforced? | Self-Transfer Risk? |
|-------------|-------------------|-------------------|------------------------|-------------------|
| {ix} | {a} | {b} | YES/NO | {if NO: impact of a==b} |

**Attack (S7)**: Pass the same account as both `from` and `to` in a transfer → potential balance inflation.
**Defense**: `require!(account_a.key() != account_b.key())` or Anchor `constraint`.

## 7. Sysvar Validation

For each sysvar account passed as input:

| Sysvar | Passed As | Address Validated? | Could Be Spoofed? |
|--------|-----------|-------------------|-------------------|
| Clock | AccountInfo | YES/NO | {if NO: attacker controls time} |
| Rent | AccountInfo | YES/NO | {if NO: attacker controls rent} |
| Instructions | AccountInfo | YES/NO | {if NO: Wormhole-style attack} |

**Safe pattern**: Use `Sysvar::from_account_info()` or `_checked` variants.
**Unsafe pattern**: Raw deserialization of sysvar data from unchecked AccountInfo.

## 8. Trust Chain Analysis

For each account validation chain, trace to its root:

| Account | Validated Against | Root Trust Anchor | Chain Complete? |
|---------|------------------|-------------------|----------------|
| {account} | {what validates it} | PDA / Program ID / Hardcoded pubkey / NONE | YES/NO |

**Pattern**: Validation chain must root in a known-good value. If chain roots in user input → FINDING.
**Example**: `authority` validated against `vault.authority`, `vault` validated against PDA seeds → chain roots in PDA (good).

## Finding Template

```markdown
**ID**: [AV-N]
**Severity**: [based on what attacker can do with invalid account]
**Step Execution**: ✓1,2,3,4,5,6,7,8 | ✗(reasons) | ?(uncertain)
**Rules Applied**: [S1:✓, S6:✓/✗, S7:✓/✗, S8:✓/✗, R4:✓/✗]
**Location**: program/src/instructions/{file}.rs:LineN
**Title**: Missing [validation type] for [account] in [instruction] enables [attack]
**Description**: [Specific missing validation with code reference]
**Impact**: [What attacker can achieve: fund theft, state corruption, DoS]
```

---

## Step Execution Checklist (MANDATORY)

| Section | Required | Completed? | Notes |
|---------|----------|------------|-------|
| 1. Account Type Inventory | YES | ✓/✗/? | For every instruction |
| 2. Owner Check Audit | YES | ✓/✗/? | For every AccountInfo/UncheckedAccount |
| 3. Discriminator Check | YES | ✓/✗/? | For all deserialized accounts |
| 4. Data Matching | YES | ✓/✗/? | For all cross-account references |
| 5. Remaining Accounts Audit | IF remaining_accounts used | ✓/✗(N/A)/? | Manual validation check |
| 6. Duplicate Account Detection | YES | ✓/✗/? | For all mutable account pairs |
| 7. Sysvar Validation | IF sysvars passed as AccountInfo | ✓/✗(N/A)/? | Address validation |
| 8. Trust Chain Analysis | YES | ✓/✗/? | Chain to root trust anchor |
