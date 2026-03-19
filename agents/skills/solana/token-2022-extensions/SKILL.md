---
name: "token-2022-extensions"
description: "Trigger Pattern TOKEN_2022 flag detected (token_2022/spl_token_2022/transfer_checked usage) - Inject Into Breadth agents, depth agents"
---

# TOKEN_2022_EXTENSIONS Skill

> **Trigger Pattern**: TOKEN_2022 flag detected (token_2022/spl_token_2022/transfer_checked usage)
> **Inject Into**: Breadth agents, depth agents
> **Finding prefix**: `[T22-N]`
> **Rules referenced**: S9, R3, R11

For every token mint the program interacts with that may use Token-2022:

## 1. Extension Inventory

For each mint:

| Mint | Token Program | Extensions Detected | Extension Impact |
|------|--------------|--------------------:|-----------------|
| {mint} | token / token-2022 | {list: TransferFee, TransferHook, PermanentDelegate, MintCloseAuthority, DefaultAccountState, etc.} | {brief per-extension impact} |

**Detection**: Check if program uses `spl_token_2022` or `token_2022` imports. Check mint account data length (Token-2022 mints are larger due to extension data).

## 2. Extension Allowlist

Does the program explicitly check which extensions are supported?

| Check | Present? | Location | Missing Extensions Handled? |
|-------|---------|----------|---------------------------|
| Extension allowlist / blocklist | YES/NO | {line} | {what happens with unsupported extension} |

**Attack (S9)**: Program designed for basic SPL Token interacts with Token-2022 mint that has unexpected extensions (e.g., PermanentDelegate). Program doesn't check → extension silently affects behavior.
**Defense**: Explicitly check mint extensions and reject unsupported ones.

## 3. Permanent Delegate Risk

For each mint with PermanentDelegate extension:

| Mint | Permanent Delegate | Trust Level | Vault Drain Scenario | Mitigation |
|------|-------------------|------------|---------------------|-----------|
| {mint} | {delegate pubkey} | {trusted/untrusted/unknown} | {can delegate drain vault?} | {what prevents it} |

**Attack**: Permanent delegate can transfer tokens FROM any token account of that mint, without the account owner's approval. If protocol holds tokens of a PermanentDelegate mint → delegate can drain them at any time.

## 4. Transfer Hook Analysis

For each mint with TransferHook extension:

| Mint | Hook Program | Hook Verified? | CU Budget Impact | Recursion Risk? |
|------|-------------|---------------|-----------------|----------------|
| {mint} | {program_id} | YES/NO | {estimated CU} | YES/NO |

**Risks**:
- Hook program can consume significant CU, causing transactions to fail
- Hook program can revert, blocking all transfers of this token
- Hook program may have its own CPI chain, adding depth
- Hook may read additional accounts not provided by the caller

## 5. Transfer Fee Accounting

For each mint with TransferFeeConfig:

| Mint | Fee Rate | Fee Accounted in Protocol Math? | Amount Received < Amount Sent? |
|------|---------|-------------------------------|-------------------------------|
| {mint} | {bps} | YES/NO | {if NO: accounting mismatch} |

**Attack**: Protocol calculates expected amounts without deducting transfer fee → accounting mismatch, potential insolvency.
**Pattern**: `transfer_checked` returns the gross amount. The net amount received is `gross - fee`. Protocol must use net amount in accounting.

## 6. CPI Guard Handling

For transfers through delegation (CPI transfers):

| Transfer Type | Uses CPI? | CPI Guard Enabled on Mint? | Transfer Works? |
|--------------|-----------|---------------------------|----------------|
| {type} | YES/NO | YES/NO/Unknown | {if CPI Guard + delegation: may fail} |

**CPI Guard**: When enabled, prevents token account delegates from transferring via CPI. Programs that rely on delegated transfers via CPI will fail silently.

## 7. Default Account State

For mints with DefaultAccountState extension:

| Mint | Default State | Protocol Handles Frozen? | Impact |
|------|-------------|------------------------|--------|
| {mint} | Frozen / Initialized | YES/NO | {if frozen: new token accounts start frozen, need thaw} |

## 8. Mint Existence Verification (MintCloseAuthority)

For mints with MintCloseAuthority extension:

| Mint | Close Authority | Checked Before Read? | Impact if Mint Closed |
|------|----------------|---------------------|---------------------|
| {mint} | {authority} | YES/NO | {if NO: reading zeroed data, incorrect decimals/supply} |

**Attack**: Mint with MintCloseAuthority can be closed (if supply == 0). Protocol reads closed mint → gets zeroed data → decimals = 0, incorrect calculations.

## Finding Template

```markdown
**ID**: [T22-N]
**Severity**: [PermanentDelegate drain = Critical, transfer fee mismatch = High, CPI Guard = Medium]
**Step Execution**: ✓1,2,3,4,5,6,7,8 | ✗(reasons) | ?(uncertain)
**Rules Applied**: [S9:✓, R3:✓, R11:✓/✗]
**Location**: program/src/{file}.rs:LineN
**Title**: Token-2022 [extension] in [context] enables [attack]
**Description**: [Specific extension vulnerability with data flow]
**Impact**: [Fund drain / accounting mismatch / DoS]
```

---

## Step Execution Checklist (MANDATORY)

| Section | Required | Completed? | Notes |
|---------|----------|------------|-------|
| 1. Extension Inventory | YES | ✓/✗/? | For every mint |
| 2. Extension Allowlist | YES | ✓/✗/? | Explicit check present? |
| 3. Permanent Delegate Risk | IF PermanentDelegate | ✓/✗(N/A)/? | Vault drain scenario |
| 4. Transfer Hook Analysis | IF TransferHook | ✓/✗(N/A)/? | CU + revert risk |
| 5. Transfer Fee Accounting | IF TransferFee | ✓/✗(N/A)/? | Net vs gross |
| 6. CPI Guard Handling | IF delegated CPI transfers | ✓/✗(N/A)/? | Delegation + CPI Guard |
| 7. Default Account State | IF DefaultAccountState | ✓/✗(N/A)/? | Frozen by default |
| 8. Mint Existence Verification | IF MintCloseAuthority | ✓/✗(N/A)/? | Closed mint reads |
