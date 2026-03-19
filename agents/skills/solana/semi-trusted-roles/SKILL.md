---
name: "semi-trusted-roles"
description: "Trigger Pattern Crank/bot/operator signer checks, authority-gated instructions - Inject Into Breadth agents, depth-state-trace"
---

# Skill: Semi-Trusted Role Analysis (Solana)

> **Trigger Pattern**: Crank/bot/operator signer checks, authority-gated instructions
> **Inject Into**: Breadth agents, depth-state-trace
> **Finding prefix**: `[STR-N]`
> **Rules referenced**: S1, S3, S9, R2, R6, R10, R13

```
crank|bot|operator|keeper|authority|admin|has_one\s*=\s*authority|
constraint\s*=\s*.*signer|role|guardian|relayer
```

## Reasoning Template

### Step 1: Inventory Role Permissions
- In {CONTRACTS}, find all instructions callable by {ROLE_NAME}
- For each instruction at {ROLE_FUNCTIONS}:
  - What accounts does it modify (mutable accounts)?
  - What CPI calls does it make?
  - What instruction data parameters does it accept?
  - Is the signer validated via `has_one`, `Signer` type, or custom constraint?

| Instruction | Signer Check | Mutable Accounts | CPI Calls | Parameters |
|-------------|-------------|------------------|-----------|------------|

### Step 2: Analyze Within-Scope Abuse
For each permitted action, ask:

**Timing Abuse** (400ms slots):
- Can {ROLE_NAME} execute at harmful times? (front-run users via MEV bundles or priority fee ordering, during epoch transitions)
- Can {ROLE_NAME} delay execution to harm users? (skip slots, withhold cranking)
- With 400ms slot times, timing windows are ~30x tighter than EVM - but MEV bundles enable precise ordering

**Parameter Abuse**:
- Can {ROLE_NAME} pass harmful instruction data? (max slippage, wrong recipient pubkey, inflated amounts)
- Are instruction parameters validated via Anchor constraints, or trusted implicitly?
- Can {ROLE_NAME} supply attacker-controlled accounts in `remaining_accounts`?

**Sequence Abuse**:
- Can {ROLE_NAME} execute instructions out of order? (claim before distribute, settle before finalize)
- Can {ROLE_NAME} skip required instructions? (skip epoch advancement, skip oracle update)

**Omission Abuse**:
- Can {ROLE_NAME} harm users by NOT cranking? (skip reward distribution, delay settlement)
- What is the protocol degradation timeline if crank stops? (1 slot? 1 epoch? indefinite?)

### Step 3: Model Attack Scenarios

```
Scenario A: Timing Attack (MEV Bundle)
1. {ROLE_NAME} monitors pending transactions in mempool
2. {ROLE_NAME} creates MEV bundle: [role_instruction, user_instruction]
3. Role instruction executes first within same slot, changing state
4. User instruction executes with worse conditions
5. Impact: {TIMING_IMPACT}

Scenario B: Parameter Attack
1. {ROLE_NAME} calls {ROLE_INSTRUCTION} with {MALICIOUS_PARAMS}
2. Instruction data is not validated against {EXPECTED_CONSTRAINTS}
3. Impact: {PARAM_IMPACT}

Scenario C: Key Compromise
1. {ROLE_NAME} keypair is compromised
2. Attacker can call: {ROLE_FUNCTIONS}
3. Maximum extractable value: {MAX_DAMAGE}
4. Recovery: {RECOVERY_PATH} - can authority be rotated? Timelock?
```

### Step 4: Assess Mitigations
- Is there a timelock on {ROLE_NAME} actions? (multi-instruction sequence with delay)
- Is {ROLE_NAME} a multisig (Squads, Snowflake)?
- **Does a removal/rotation function for {ROLE_NAME} EXIST?** If NO -> FINDING: authority is irrevocable without program upgrade. Severity: minimum Medium if role can modify user-facing state.
- Can admin rotate {ROLE_NAME} authority quickly?
- Are there rate limits, cooldowns, or per-slot caps?
- Is the program immutable (upgrade authority revoked)? If so, can a compromised role be replaced at all?

### Step 5: Model User-Side Exploitation (Direction 2 - MANDATORY)

**Predictability Analysis**:
- Is the crank's behavior predictable? (epoch boundaries, price movements, queue-processing cadence)
- Can users observe when the crank will act? (monitoring on-chain state, slot timing)
- Can users front-run or back-run the crank via MEV bundles or priority fees?

**Scenario D: User Exploits Crank Timing**
```
1. User observes that {ROLE_NAME} executes {ROLE_INSTRUCTION} at predictable times
2. User submits transaction with high priority fee to land BEFORE crank in same slot
3. {ROLE_INSTRUCTION} executes, changing state (e.g., reward distribution, rate update)
4. User benefits from known state change
5. Impact: {USER_EXPLOIT_IMPACT}
```

**Scenario E: User Griefs Crank Preconditions**
```
1. {ROLE_INSTRUCTION} requires account state: {PRECONDITION}
2. User manipulates account state to violate {PRECONDITION}
3. {ROLE_NAME} sends transaction, instruction fails
4. Protocol enters degraded state (no crank actions possible)
5. Impact: {GRIEF_IMPACT}
```

**Scenario F: User Forces Suboptimal Crank Action**
```
1. {ROLE_NAME} must choose between options based on on-chain state
2. User manipulates state (deposits/withdrawals) to make worst option appear best
3. {ROLE_NAME} (following honest behavior) chooses suboptimal path
4. User profits from forced suboptimal execution
5. Impact: {SUBOPTIMAL_IMPACT}
```

**Scenario G: Same-Chain Rate Staleness via Discrete Updates**
```
1. Protocol's exchange rate only updates when {ROLE_NAME} cranks (discrete updates)
2. Between crank calls, rate is stale (does not reflect accumulated value)
3. User monitors for {ROLE_NAME} pending transaction
4. User enters at stale rate (favorable), crank executes, rate updates
5. User exits at updated rate (or holds appreciating position)
6. Impact: {RATE_ARBIT_IMPACT}
```

### Step 6: Precondition Griefability Check

For each instruction callable by {ROLE_NAME}:

| Instruction | Preconditions | User Can Manipulate? | Grief Impact |
|-------------|--------------|---------------------|--------------|
| {ix} | account balance > 0 | YES - withdraw all | Crank stuck |
| {ix} | Clock timestamp > last_crank + interval | NO - time-based | N/A |
| {ix} | threshold met | YES - partial withdraw | Delayed execution |

**CU budget griefing**: Can a user submit CU-heavy transactions to fill the leader's block and delay crank execution? Priority fee escalation can push crank costs above economic viability.

### Step 6b: Admin/Privileged Instruction Griefability (EXHAUSTIVE)

Enumerate ALL authority-gated instructions across the program:

| Instruction | Authority Type | Preconditions | User Can Manipulate? | Grief Impact |
|-------------|---------------|--------------|---------------------|--------------|
| {admin_ix} | {owner/admin/operator} | {preconditions} | YES/NO | {impact} |

**Enumeration completeness check**:
- [ ] Total authority-gated instructions in program: {N}
- [ ] Instructions analyzed in this table: {M}
- [ ] If M < N -> INCOMPLETE - analyze missing instructions before proceeding

**Solana-specific checks**:
- Can users create PDA accounts that block admin operations? (unexpected PDA state preventing closure/migration)
- Can users create token accounts owned by the protocol PDA that block operations? (non-zero balances preventing account closure)
- Can users initiate multi-instruction operations (partial unstake, pending withdrawal) whose in-flight state blocks admin actions?
- Can a user create so many accounts that iterating over them exceeds CU limits for admin instructions?

## Common False Positives
- **View-only / read instructions**: If role only reads state, no abuse vector
- **Idempotent instructions**: If calling twice has same effect as once, timing abuse is limited
- **User-initiated dependency**: If role action requires user to initiate first, front-running may not apply
- **Economic alignment**: If crank is economically aligned (staked collateral, tip-funded), malicious action has cost

## Finding Template

```markdown
**ID**: [STR-N]
**Severity**: Critical/High/Medium/Low/Info
**Step Execution**: (see below)
**Rules Applied**: [S1:___, S3:___, S9:___, R2:___, R6:___, R10:___, R13:___]
**Location**: programs/{program}/src/instructions/{file}.rs:LineN
**Title**: {what role can do / what user can exploit}
**Description**: {specific abuse vector with code reference}
**Impact**: {quantified damage at worst-state parameters}
```

---

## Step Execution Checklist (MANDATORY)

| Step | Required | Completed? | Notes |
|------|----------|------------|-------|
| 1. Inventory Role Permissions | YES | | |
| 2. Analyze Within-Scope Abuse | YES | | |
| 3. Model Attack Scenarios (A,B,C) | YES | | |
| 4. Assess Mitigations | YES | | |
| 5. Model User-Side Exploitation (D,E,F,G) | **YES** | | **MANDATORY** -- never skip |
| 6. Precondition Griefability Check | **YES** | | **MANDATORY** -- never skip |
| 6b. Admin Instruction Griefability | **YES** | | **MANDATORY** -- never skip |

### Cross-Reference Markers

**After Step 4**: DO NOT STOP HERE -- Steps 5-6 analyze the reverse direction.
**After Step 5**: Cross-reference with TOKEN_FLOW_TRACING for token-related griefing vectors. IF crank actions are predictable -> document Jito MEV vectors.
**After Step 6**: IF any precondition is user-griefable -> severity >= MEDIUM. Document protocol degradation timeline if crank is blocked.

### Output Format for Step Execution
```markdown
**Step Execution**: check1,2,3,4,5,6,6b | (no skips for this skill)
```
