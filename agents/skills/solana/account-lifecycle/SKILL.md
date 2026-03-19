---
name: "account-lifecycle"
description: "Trigger Pattern ACCOUNT_CLOSING flag detected (close/CloseAccount usage) - Inject Into Breadth agents, depth agents"
---

# ACCOUNT_LIFECYCLE Skill

> **Trigger Pattern**: ACCOUNT_CLOSING flag detected (close/CloseAccount usage)
> **Inject Into**: Breadth agents, depth agents
> **Finding prefix**: `[AL-N]`
> **Rules referenced**: S4, R9

For every account close operation in the Solana program:

## 1. Close Operation Inventory

List all account closing operations:

| # | Instruction | Account Closed | Close Method | Lamport Recipient | Location |
|---|------------|---------------|-------------|-------------------|----------|
| 1 | {ix} | {account} | Anchor `close` / manual | {recipient} | {file:line} |

## 2. Close Completeness

For each close operation, verify ALL steps:

| Close Op | Data Zeroed? | Lamports Transferred? | Discriminator Set to CLOSED? | Owner Transferred to System? |
|----------|-------------|----------------------|-----------------------------|-----------------------------|
| {op} | YES/NO | YES/NO | YES/NO | YES/NO |

**Anchor `close`**: Handles all 4 steps automatically. Manual closing MUST do all 4.
**Missing step impact**:
- Data not zeroed → residual data readable by other programs
- Lamports not fully transferred → rent-exempt lamports stranded (Rule 9)
- Discriminator not set → account can be "reopened" with stale type
- Owner not transferred → program still has authority over closed account

## 3. Revival Attack Analysis (S4 - CRITICAL)

For each close operation:

| Close Op | Same-Tx Refund Possible? | Revival Guard? | Attack Sequence |
|----------|------------------------|---------------|-----------------|
| {op} | YES/NO | YES/NO | {if YES: describe} |

**Attack (S4)**: Within the SAME transaction, after an account is closed (lamports drained, data zeroed):
1. Close account (lamports go to attacker)
2. In same tx, re-fund account with lamports (becomes rent-exempt again)
3. Account data is all zeros but account exists again
4. Next instruction that checks `account.data_len() > 0` or assumes "closed accounts don't exist" fails

**Defense**: Set discriminator to a CLOSED sentinel value. Check discriminator on every access, not just data length.

## 4. Rent Recovery

For each close operation:

| Account | Rent-Exempt Lamports | Fully Recovered? | Recipient Correct? |
|---------|--------------------:|-----------------|-------------------|
| {account} | {amount} | YES/NO | {who gets the lamports} |

**Check**: Are ALL lamports transferred? Partial transfer leaves lamports stranded.

## 5. Token Account Closure

For each SPL Token account closure:

| Token Account | Balance Checked Zero? | Withheld Fees Harvested? (Token-2022) | Close Authority Correct? |
|--------------|----------------------|--------------------------------------|------------------------|
| {account} | YES/NO | YES/NO/N/A | {who can close it} |

**SPL Token rule**: Token accounts can only be closed when balance == 0.
**Token-2022**: Accounts with TransferFeeConfig may have withheld fees. Must harvest before close.

## 6. Reinitialization Prevention

For each account type that can be initialized:

| Account Type | Init Method | Can Be Re-Initialized? | Guard |
|-------------|------------|----------------------|-------|
| {type} | `init` / `init_if_needed` / manual | YES/NO | {what prevents it} |

**`init_if_needed` WARNING**: This attribute allows reinitialization if the account already exists. It is a known footgun.
**Safe pattern**: Use `init` (fails if account exists) + manual `is_initialized` flag for manual programs.
**Attack**: Re-initialize an account to reset its state (e.g., reset reward counter, change authority).

## Finding Template

```markdown
**ID**: [AL-N]
**Severity**: [revival = High, stranded rent = Medium, reinit = High]
**Step Execution**: ✓1,2,3,4,5,6 | ✗(reasons) | ?(uncertain)
**Rules Applied**: [S4:✓, R9:✓/✗]
**Location**: program/src/{file}.rs:LineN
**Title**: [Lifecycle issue] in [instruction] enables [attack]
**Description**: [Specific lifecycle vulnerability with code trace]
**Impact**: [Fund theft via revival / stranded assets / state reset]
```

---

## Step Execution Checklist (MANDATORY)

| Section | Required | Completed? | Notes |
|---------|----------|------------|-------|
| 1. Close Operation Inventory | YES | ✓/✗/? | For every close |
| 2. Close Completeness | YES | ✓/✗/? | All 4 steps verified |
| 3. Revival Attack Analysis | YES | ✓/✗/? | **CRITICAL** - same-tx refund |
| 4. Rent Recovery | YES | ✓/✗/? | Full lamport transfer |
| 5. Token Account Closure | IF token accounts closed | ✓/✗(N/A)/? | Balance + withheld fees |
| 6. Reinitialization Prevention | YES | ✓/✗/? | init_if_needed is dangerous |
