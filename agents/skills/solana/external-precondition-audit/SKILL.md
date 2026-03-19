---
name: "external-precondition-audit"
description: "Trigger Pattern Any CPI (Cross-Program Invocation) detected in program - Inject Into Breadth agents (merged via M5 hierarchy)"
---

# Skill: External Precondition Audit (Solana)

> **Trigger Pattern**: Any CPI (Cross-Program Invocation) detected in program
> **Inject Into**: Breadth agents (merged via M5 hierarchy)
> **Finding prefix**: `[EPA-N]`
> **Rules referenced**: S1, S3, S5, S9, R1, R4
> **Constraint**: IDL/interface-level inference only -- no production fetch required

```
invoke|invoke_signed|CpiContext|cpi::|anchor_spl|spl_token|system_program|
associated_token|token_2022|program::invoke
```

For every CPI target program the protocol invokes:

## 1. CPI Target Inventory and Validation

| CPI Target | Program ID Source | Hardcoded? | Validated Against Constant? | Upgradeable? | Risk if Substituted |
|-----------|------------------|-----------|---------------------------|-------------|-------------------|

**Rule S3 check**: For each CPI call, is the target program ID:
- Hardcoded as a constant (`spl_token::ID`, known program address)? -> SAFE
- Read from an account field without validation? -> CRITICAL: attacker substitutes malicious program
- Passed as an `AccountInfo` and checked via `constraint = program.key() == expected_id`? -> SAFE if constraint present

**Upgradeability assessment**: Is the CPI target program upgradeable?
- If YES: its behavior can change after audit. Apply Rule 4 (adversarial assumption).
- If NO (immutable / upgrade authority revoked): behavior is fixed, trust boundary is clear.

## 2. Signer Privilege Propagation

For each `invoke_signed` / CPI call, trace signer propagation:

| CPI Call | Signers Forwarded | PDA Seeds Used | Should This Signer Be Forwarded? | Privilege Escalation Risk |
|----------|------------------|---------------|----------------------------------|--------------------------|

**Checks**:
- Does the CPI forward `signer` privileges that should NOT be forwarded? (e.g., forwarding user signer to an external program that can drain their accounts)
- Are PDA signer seeds constructed correctly? (wrong seeds = wrong PDA = different authority)
- Can an attacker control any of the PDA seed components to derive a different PDA?
- Does `invoke_signed` pass accounts the CPI target can mutate that should not be mutated?

## 3. Account Reload After CPI (Rule S5 -- CRITICAL)

For each CPI call that modifies accounts used by subsequent logic:

| CPI Call | Accounts Modified by CPI | Reloaded After CPI? | Subsequent Read Location | Stale Data Risk |
|----------|------------------------|--------------------|-----------------------|----------------|

**Rule S5**: After a CPI call, any account that the CPI target may have modified MUST be reloaded before the calling program reads it again. Anchor's `reload()` method handles this. Without reload, the program reads cached (pre-CPI) data.

**Attack pattern**:
1. Program reads account balance (cached)
2. CPI transfers tokens out of account
3. Program reads account balance again -- gets STALE pre-CPI value
4. Program makes decisions based on stale balance

**Check for each CPI**:
- [ ] All mutable accounts passed to CPI are reloaded after return
- [ ] Lamport balances are re-read after CPI (lamports can change via CPI)
- [ ] Token account balances are re-read after SPL Token CPI
- [ ] If NOT reloaded: trace what stale data is used for and compute impact

## 4. Return Data Consumption

| CPI Call | Return Data Expected | How Protocol Uses Return | Failure Mode if Unexpected |
|----------|---------------------|-------------------------|---------------------------|

For each return value:
- What happens if CPI returns 0? (division by zero, incorrect accounting)
- What happens if CPI returns MAX_U64? (overflow in subsequent arithmetic)
- What happens if CPI does NOT set return data? (Solana's `get_return_data()` returns None)
- What happens if the CPI reverts? Does the calling program handle the error or propagate it?

**Solana-specific**: `sol_get_return_data` returns the program ID that set the data. Verify the caller checks that the return data comes from the expected program, not a previously-invoked program's stale return data.

## 5. State Dependency Mapping

| Protocol State | Depends on CPI Target State | External State Can Change Without Our Knowledge? |
|---------------|---------------------------|--------------------------------------------------|

For each dependency: model what happens when the external state changes between our program's read and use.

**Solana-specific concerns**:
- Another instruction in the SAME transaction can modify the CPI target's state between our instructions
- An attacker can construct a transaction: [attacker_ix_1 (modify external state)] -> [our_ix (reads stale external state)]
- Oracle accounts (Pyth, Switchboard) can be updated by their respective programs between instructions

### 5b. Oracle Data Quality Checks (IF Pyth/Switchboard/other oracle consumed)

| Oracle Account | Type | Confidence Checked? | Staleness Checked? | First-Update Bypass? | Account Owner Validated? |
|---------------|------|--------------------|--------------------|---------------------|------------------------|

Checks:
1. Is `confidence_interval` (Pyth) or deviation threshold (Switchboard) validated before price is used?
2. Is staleness enforced? (`publish_time` vs `Clock::get()` compared against max age)
3. Can the first price read bypass confidence/staleness checks? (no prior reference → no comparison baseline)
4. Can the oracle account be substituted with a stale or attacker-controlled account? (check `owner == pyth_program_id`)
Tag: `[TRACE:oracle read → confidence={X} vs threshold={Y} → {accepted/rejected}]`

## 6. Lamport Conservation Audit

After each CPI call, verify lamport conservation:

| CPI Call | Accounts Passed (Mutable) | Lamports Before | Lamports After | Conservation Checked? |
|----------|--------------------------|----------------|---------------|---------------------|

**Attack**: A malicious CPI target (if program ID is not validated per Section 1) can drain lamports from any mutable account passed to it. Even for trusted CPI targets, verify that lamport changes are expected and accounted for.

**Check**: For each mutable account passed to CPI:
- Is it acceptable for this account's lamports to change?
- If NOT: is there a post-CPI lamport check?
- If the CPI target is upgradeable: lamport behavior could change in future versions

## Finding Template

```markdown
**ID**: [EPA-N]
**Verdict**: CONFIRMED / PARTIAL / REFUTED / CONTESTED
**Step Execution**: (see checklist below)
**Rules Applied**: [S1:___, S3:___, S5:___, S9:___, R1:___, R4:___]
**Severity**: Critical/High/Medium/Low/Info
**Location**: programs/{program}/src/instructions/{file}.rs:LineN
**Title**: {missing CPI validation / stale data after CPI / privilege escalation}
**Description**: {specific issue with code reference}
**Impact**: {what attacker can achieve via the CPI weakness}
```

---

## Step Execution Checklist (MANDATORY)

| Section | Required | Completed? | Notes |
|---------|----------|------------|-------|
| 1. CPI Target Inventory and Validation | YES | | Rule S3 check for every CPI |
| 2. Signer Privilege Propagation | YES | | Every invoke_signed traced |
| 3. Account Reload After CPI (Rule S5) | YES | | Every mutable account checked |
| 4. Return Data Consumption | IF return data used | | |
| 5. State Dependency Mapping | YES | | |
| 5b. Oracle Data Quality Checks | IF oracle consumed | | Pyth confidence, staleness, first-update bypass |
| 6. Lamport Conservation Audit | YES | | Every mutable account passed to CPI |

If any step skipped, document valid reason (N/A, no CPI, no return data, immutable target).
