---
name: "migration-analysis"
description: "Trigger Pattern Program upgrades, account data layout changes, deprecated instructions, token migrations - Inject Into Breadth agents, depth-state-trace"
---

# Skill: Migration Analysis (Solana)

> **Trigger Pattern**: Program upgrades, account data layout changes, deprecated instructions, token migrations
> **Inject Into**: Breadth agents, depth-state-trace
> **Finding prefix**: `[MG-N]`
> **Rules referenced**: S1, S3, S4, S9, R4, R9, R10

```
upgrade|authority|reinitialize|deprecated|migrat|legacy|v2|V2|old_mint|new_mint|
BPFLoaderUpgradeable|set_authority|close_account
```

## Reasoning Template

### Step 1: Identify Token and Account Transitions

Find all migration patterns:
- Old mint -> New mint (SPL Token migrations, token rebranding, Token-2022 migration)
- Deprecated instructions still callable
- Account data layout changes across program versions
- PDA seed schema changes

For each transition:
| Old Entity | New Entity | Migration Instruction | Bidirectional? | Account Type |
|------------|-----------|----------------------|----------------|-------------|

### Step 2: Check Account Data Layout Compatibility

For each program upgrade that changes account data structures:

1. What fields exist in the OLD account data layout?
2. What fields exist in the NEW account data layout?
3. Are new fields APPENDED (safe) or INSERTED/REORDERED (breaking)?
4. Does the discriminator change between versions? (Anchor uses first 8 bytes)

```rust
// Example mismatch:
// V1 layout: [discriminator(8)][authority(32)][amount(8)]  = 48 bytes
// V2 layout: [discriminator(8)][authority(32)][new_field(8)][amount(8)] = 56 bytes
// BREAKING: V1 accounts read `amount` at offset 40, but V2 expects it at offset 48
```

| Account Type | V1 Layout (fields + offsets) | V2 Layout (fields + offsets) | Compatible? | Migration Path |
|-------------|---------------------------|---------------------------|-------------|---------------|

### Step 3: Trace Account Flow Paths

For each instruction that interacts with migrated accounts:

1. **Entry point**: What account data version does the user provide?
2. **Internal flow**: What version does the program expect?
3. **CPI calls**: What version do CPI target programs expect?
4. **Return data**: What version does the program write back?

| Instruction | Account Expected | Actual Account Version | CPI Target Expects | Mismatch? |
|-------------|-----------------|----------------------|--------------------|-----------|

### Step 3b: CPI Side Effect Compatibility

When migration changes program behavior, check whether CPI callers handle the changes:

| CPI Call | Pre-Migration Behavior | Post-Migration Behavior | Caller Handles Both? | Mismatch? |
|----------|----------------------|------------------------|---------------------|-----------|

**Pattern**: Program upgrade changes return data or account mutations from a CPI, but callers were written for the old behavior. After upgrade, CPI results are misinterpreted.

### Step 3c: Pre-Upgrade Account Inventory

Before analyzing stranded asset paths, inventory all accounts the program owns:

| Account Type | How Created | Current Lamports/Tokens | Post-Upgrade Logic Handles? | Close Path Post-Upgrade? |
|-------------|------------|------------------------|----------------------------|-------------------------|
| {pda_vault} | PDA init | SOL + SPL tokens | YES/NO | {instruction or NONE} |
| {user_state} | User init | Rent-exempt SOL | YES/NO | {instruction or NONE} |
| {legacy_acct} | V1 init | Held from V1 ops | YES/NO | {instruction or NONE} |

**Pattern**: Upgrade changes which accounts the program reads/writes, but old accounts still hold SOL (rent) and tokens. If new logic cannot close or drain old accounts, assets are stranded.

### Step 4: Stranded Asset Analysis (ENHANCED)

#### 4a. Asset Inventory by Era

| Asset/Account | V1 Creation Path | V2 Creation Path | V1 Close Path | V2 Close Path |
|---------------|-----------------|-----------------|--------------|--------------|
| {pda_vault} | initialize() | initialize_v2() | close_vault() | close_vault_v2() |
| {user_account} | create_user() | create_user() | close_user() | close_user() |

**Rule**: If V1 Creation exists but V2 Close doesn't handle V1 state -> potential stranding.

#### 4b. Cross-Era Path Matrix

| Account Era | State Condition | Available Close/Drain Paths | Works? | Reason |
|-------------|----------------|---------------------------|--------|--------|
| V1 PDA vault | V2 program deployed | close_vault_v2() | Y/N | {why} |
| V1 PDA vault | V1 instruction removed | close_vault() | Y/N | {why} |
| V1 user state | In-flight during upgrade | ??? | Y/N | {why} |

**STRANDING RULE**: If ALL close/drain paths fail for any account state -> **STRANDED ASSETS FINDING**

#### 4c. Recovery Function Inventory

| Function | Who Can Call | What Accounts Can Recover | Limitations |
|----------|------------|--------------------------|-------------|
| close_account() | Authority only | Program-owned accounts | Requires active authority |
| migrate_v1() | Any user | V1 user accounts | One-time per account |
| sweep_lamports() | Authority | Unclaimed rent | Cannot recover user deposits |

#### 4d. Worst-Case Scenarios (MANDATORY)

**Scenario 1: V1 Account + V2 Program**
```
State: User created account via V1 initialize() with deposited tokens
Event: Program upgraded to V2 with new data layout
Question: Can user close/withdraw via V2 instructions?
Trace: [document instruction path and deserialization]
Result: [SUCCESS/STRANDED + amount]
```

**Scenario 2: In-Flight During Upgrade**
```
State: User initiated multi-instruction operation (e.g., unstake request) at slot N
Event: Program upgrade deployed at slot N+1
Question: Can user complete operation at slot N+2?
Trace: [document instruction path]
Result: [SUCCESS/STRANDED + amount]
```

**Scenario 3: PDA Seed Change**
```
State: PDA derived with seeds [b"vault", user.key()] in V1
Event: V2 changes seeds to [b"vault_v2", user.key()]
Question: Can V2 program access the V1 PDA? Are V1 tokens recoverable?
Trace: [document PDA derivation and account lookup]
Result: [SUCCESS/STRANDED + amount]
```

#### 4e. Step 4 Completion Checklist
- [ ] 4a: ALL accounts inventoried with creation/close paths per era
- [ ] 4b: Cross-era path matrix completed for all state combinations
- [ ] 4c: Recovery instructions enumerated with limitations
- [ ] 4d: All three worst-case scenarios modeled with traces
- [ ] For EVERY stranding possibility: recovery path exists OR finding created

### Step 4f: User-Blocks-Admin Scenarios

| Admin/Migration Instruction | Precondition Required | User Action That Blocks It | Timing Window | Severity |
|----------------------------|----------------------|---------------------------|---------------|----------|
| {admin_ix} | {precondition} | {user_action} | {window} | {assess} |

**Solana-specific patterns**:
- User creates token accounts owned by program PDA -> non-zero balance prevents PDA closure
- User initiates pending operations (unstake, withdrawal request) -> in-flight state blocks migration
- User creates many small accounts -> iteration over accounts exceeds CU limit for admin migration instruction

### Step 5: Upgrade Authority Lifecycle

| Check | Status | Evidence |
|-------|--------|----------|
| Upgrade authority identified? | {pubkey or multisig} | {source location} |
| Is authority a multisig (Squads)? | YES/NO | |
| Can authority be revoked (program made immutable)? | YES/NO | |
| If revoked: are all config parameters frozen? | YES/NO | |
| If revoked: can stranded assets be recovered? | YES/NO | Apply Rule 9 |
| Buffer validation during upgrade? | YES/NO | Can malicious buffer be substituted? |
| IDL discriminator stability? | YES/NO | Changed discriminators break all callers |

### Step 6: Downstream Integration Compatibility

| Program Change | Downstream Consumer | Expected Interface | Post-Migration Actual | Breaking? |
|---------------|--------------------|--------------------|----------------------|-----------|
| {change} | CPI callers | {expected IDL} | {actual IDL} | YES/NO |
| {change} | Indexers (Geyser, Helius) | {expected account layout} | {actual layout} | YES/NO |
| {change} | Frontend/SDK | {expected instruction format} | {actual} | YES/NO |

**Pattern**: Program upgrade changes instruction discriminators, account layouts, or CPI behavior, but downstream consumers (other programs calling via CPI, indexers, SDKs) were built for the old interface.

## Key Questions (Must Answer All)
1. **Data Layout**: Are ALL existing accounts readable by the new program version?
2. **PDA Stability**: Do ALL PDAs remain derivable with the same seeds after upgrade?
3. **Migration Completeness**: Can ALL V1 accounts be migrated/closed via V2 paths?
4. **Stranded Assets**: Is there any combination of (old_account_state + new_program) that traps funds?
5. **Authority Lifecycle**: Is the upgrade authority appropriately secured and revocable?

## Common False Positives
1. **Append-only layout changes**: New fields added at end with defaults -- backward compatible
2. **Versioned deserialization**: Program explicitly handles both V1 and V2 layouts
3. **Admin-controlled migration**: Stranded accounts recoverable via authority instructions

## Finding Template

```markdown
**ID**: [MG-N]
**Verdict**: CONFIRMED / PARTIAL / REFUTED / CONTESTED
**Step Execution**: (see checklist below)
**Rules Applied**: [S1:___, S3:___, S4:___, S9:___, R4:___, R9:___, R10:___]
**Severity**: Critical/High/Medium/Low/Info
**Location**: programs/{program}/src/{file}.rs:LineN

**Account Transition**:
- Old: {old_layout/mint/PDA}
- New: {new_layout/mint/PDA}
- Mismatch Point: {where layouts/seeds diverge}

**Description**: {what is wrong}
**Impact**: {stranded funds, corrupted state, broken CPI callers}
**Evidence**: {code showing mismatch}
```

---

## Step Execution Checklist (MANDATORY)

| Step | Required | Completed? | Notes |
|------|----------|------------|-------|
| 1. Identify Token and Account Transitions | YES | | |
| 2. Check Account Data Layout Compatibility | YES | | |
| 3. Trace Account Flow Paths | YES | | |
| 3b. CPI Side Effect Compatibility | YES | | |
| 3c. Pre-Upgrade Account Inventory | YES | | |
| 4. Stranded Asset Analysis (4a-4e) | YES | | |
| 4f. User-Blocks-Admin Scenarios | YES | | |
| 5. Upgrade Authority Lifecycle | YES | | |
| 6. Downstream Integration Compatibility | YES | | |

If any step skipped, document valid reason (N/A, immutable program, single version, no CPI callers).
