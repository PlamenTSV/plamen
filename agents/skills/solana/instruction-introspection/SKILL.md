---
name: "instruction-introspection"
description: "Trigger Pattern INSTRUCTION_INTROSPECTION flag detected (load_instruction_at/Sysvar1nstructions) - Inject Into Breadth agents, depth agents"
---

# INSTRUCTION_INTROSPECTION Skill

> **Trigger Pattern**: INSTRUCTION_INTROSPECTION flag detected (load_instruction_at/Sysvar1nstructions)
> **Inject Into**: Breadth agents, depth agents
> **Finding prefix**: `[II-N]`
> **Rules referenced**: S10, S8, R15

For every use of instruction introspection in the Solana program:

## 1. Introspection Usage Inventory

List all instruction introspection usage:

| # | Location | Function Used | Purpose | Instructions Sysvar Source |
|---|----------|--------------|---------|---------------------------|
| 1 | {file:line} | `load_instruction_at_checked` / `load_instruction_at` / `get_instruction_relative` | {what it checks} | {account source} |

## 2. Sysvar Address Validation (Wormhole Pattern - CRITICAL)

For each Instructions sysvar account:

| Usage | Sysvar Source | Address Validated? | Validation Method |
|-------|-------------|-------------------|-------------------|
| {usage} | {account param name} | YES/NO | {hardcoded check / Anchor constraint / NONE} |

**Attack pattern (sysvar address spoofing)**: If Instructions sysvar address is NOT validated, attacker passes a fake account containing crafted "instruction" data. The introspection reads attacker-controlled data instead of real transaction instructions.
**Defense**: `require!(sysvar_account.key() == sysvar::instructions::ID)` or use Anchor `#[account(address = sysvar::instructions::ID)]`.

## 3. Checked Function Usage

For each `load_instruction_at*` call:

| Call | Uses `_checked` Variant? | Risk if Unchecked |
|------|------------------------|-------------------|
| {call} | YES/NO | {if NO: deprecated function, potential ABI issues} |

**Rule**: Always use `load_instruction_at_checked` (validates the sysvar account) over the deprecated `load_instruction_at` (does not validate).

## 4. Instruction Sequence Validation

For flash loan and atomic operation patterns:

| Pattern | Borrow Instruction Checked? | Repay Instruction Checked? | Gap Between Checks? |
|---------|---------------------------|---------------------------|---------------------|
| Flash loan repay check | YES/NO | YES/NO | {can attacker insert instructions between borrow and repay?} |

**Attack (marginfi pattern)**: Protocol checks that a repay instruction exists in the transaction but doesn't verify that no state-modifying instructions execute BETWEEN the borrow and repay. Attacker inserts exploit instructions in the gap.
**Defense**: Verify the COMPLETE instruction sequence, not just the presence of specific instructions.

## 5. State Change Coverage

For each introspection-based check:

| Check | State Changes Between Checked Instructions | All Changes Accounted? | Gap? |
|-------|------------------------------------------|----------------------|------|
| {check} | {list possible state changes} | YES/NO | {if NO: what's unaccounted} |

**Pattern**: Introspection checks often verify instruction A and instruction B exist, but ignore what happens in between. Any state changes between A and B can be exploited.

## 6. Program ID Verification

For each instruction inspected via introspection:

| Inspected Instruction | Program ID Checked? | Expected Program | Spoofable? |
|----------------------|---------------------|-----------------|-----------|
| {instruction} | YES/NO | {expected} | {if NO: attacker deploys mimicking program} |

**Attack**: Introspection check verifies an instruction with matching function signature exists, but doesn't verify it belongs to the expected program. Attacker deploys a program with the same instruction signature that does nothing.

## Finding Template

```markdown
**ID**: [II-N]
**Severity**: [sysvar spoofing = Critical, sequence gap = High, missing program check = Medium]
**Step Execution**: ✓1,2,3,4,5,6 | ✗(reasons) | ?(uncertain)
**Rules Applied**: [S10:✓, S8:✓/✗, R15:✓/✗]
**Location**: program/src/{file}.rs:LineN
**Title**: [Introspection issue] in [instruction] enables [attack]
**Description**: [Specific introspection vulnerability with sequence analysis]
**Impact**: [Flash loan bypass / fake instruction acceptance / state manipulation]
```

---

## Step Execution Checklist (MANDATORY)

| Section | Required | Completed? | Notes |
|---------|----------|------------|-------|
| 1. Introspection Usage Inventory | YES | ✓/✗/? | For every introspection use |
| 2. Sysvar Address Validation | YES | ✓/✗/? | **CRITICAL** - sysvar address spoofing |
| 3. Checked Function Usage | YES | ✓/✗/? | _checked vs deprecated |
| 4. Instruction Sequence Validation | IF flash loan / atomic pattern | ✓/✗(N/A)/? | Gap between checks |
| 5. State Change Coverage | YES | ✓/✗/? | Between checked instructions |
| 6. Program ID Verification | YES | ✓/✗/? | For every inspected instruction |
