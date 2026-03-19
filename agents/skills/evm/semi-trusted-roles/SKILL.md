---
name: "semi-trusted-roles"
description: "Type Thought-template (instantiate before use) - Research basis Insider threat modeling, keeper/bot abuse vectors"
---

# Skill: Semi-Trusted Role Analysis

> **Type**: Thought-template (instantiate before use)
> **Research basis**: Insider threat modeling, keeper/bot abuse vectors

## Trigger Patterns
```
onlyBot|onlyOperator|onlyKeeper|BOT_ROLE|OPERATOR_ROLE|KEEPER_ROLE|
hasRole.*BOT|hasRole.*OPERATOR|hasRole.*KEEPER|automated|keeper
```

## Reasoning Template

### Step 1: Inventory Role Permissions
- In {CONTRACTS}, find all functions callable by {ROLE_NAME}
- For each function at {ROLE_FUNCTIONS}:
  - What state does it modify?
  - What external calls does it make?
  - What parameters does it accept?

### Step 2: Analyze Within-Scope Abuse
For each permitted action, ask:

**Timing Abuse**:
- Can {ROLE_NAME} execute at harmful times? (front-run users, during rebalance)
- Can {ROLE_NAME} delay execution to harm users?

**Parameter Abuse**:
- Can {ROLE_NAME} pass harmful parameters? (max slippage, wrong recipient)
- Are parameters validated, or trusted implicitly?

**Sequence Abuse**:
- Can {ROLE_NAME} execute operations out of order?
- Can {ROLE_NAME} skip required operations?

**Omission Abuse**:
- Can {ROLE_NAME} harm users by NOT acting? (skip sync, delay distribution)

### Step 3: Model Attack Scenarios
```
Scenario A: Timing Attack
1. {ROLE_NAME} monitors mempool for user transaction {USER_ACTION}
2. {ROLE_NAME} front-runs with {ROLE_ACTION}
3. User's transaction executes with worse conditions
4. Impact: {TIMING_IMPACT}

Scenario B: Parameter Attack
1. {ROLE_NAME} calls {ROLE_FUNCTION} with {MALICIOUS_PARAMS}
2. Parameters are not validated against {EXPECTED_CONSTRAINTS}
3. Impact: {PARAM_IMPACT}

Scenario C: Key Compromise
1. {ROLE_NAME} private key is compromised
2. Attacker can call: {ROLE_FUNCTIONS}
3. Maximum extractable value: {MAX_DAMAGE}
4. Recovery options: {RECOVERY_PATH}
```

### Step 4: Assess Mitigations
- Is there a timelock on {ROLE_NAME} actions?
- Is {ROLE_NAME} a multisig?
- **Does a removal/revocation function for {ROLE_NAME} EXIST?** If NO -> FINDING: role is irrevocable without contract upgrade/migration. Severity: minimum Medium if role can modify user-facing state.
- Can admin revoke {ROLE_NAME} quickly?
- Are there rate limits or cooldowns?

## Key Questions (must answer all)
1. What is the maximum damage if {ROLE_NAME} acts maliciously?
2. What is the maximum damage if {ROLE_NAME} key is compromised?
3. Are there time-sensitive operations where {ROLE_NAME} timing matters?
4. What user funds or protocol state can {ROLE_NAME} affect?

## Common False Positives
- **View-only operations**: If role can only read state, no abuse vector
- **Idempotent operations**: If calling twice has same effect as once, timing abuse is limited
- **User-initiated dependency**: If role action requires user to initiate first, front-running may not apply
- **Economic alignment**: If role is economically aligned (staked collateral), malicious action has cost

## Reverse Perspective: User Exploitation of Roles

> **Critical insight**: Don't just analyze how the role can harm users -- analyze how USERS can exploit predictable role behavior.

### Step 5: Model User-Side Exploitation

**Predictability Analysis**:
- Is the role's behavior predictable? (scheduled tasks, triggered by events)
- Can users observe when the role will act?
- Can users front-run or back-run the role's actions?

**Scenario D: User Exploits Keeper Timing**
```
1. User observes that {ROLE_NAME} executes {ROLE_ACTION} at predictable times
2. User positions themselves before {ROLE_ACTION} (front-running the keeper)
3. {ROLE_ACTION} executes, changing state
4. User benefits from known state change
5. Impact: {USER_EXPLOIT_IMPACT}
```

**Scenario E: User Griefs Role Preconditions**
```
1. {ROLE_FUNCTION} has precondition: {PRECONDITION}
2. User can manipulate state to violate {PRECONDITION}
3. {ROLE_NAME} calls {ROLE_FUNCTION}, which reverts
4. System enters degraded state (no keeper actions possible)
5. Impact: {GRIEF_IMPACT}
```

**Scenario F: User Forces Suboptimal Role Action**
```
1. {ROLE_NAME} must choose between options based on state
2. User manipulates state to make worst option appear best
3. {ROLE_NAME} (following honest behavior) chooses suboptimal path
4. User profits from forced suboptimal execution
5. Impact: {SUBOPTIMAL_IMPACT}
```

**Scenario G: Same-Chain Rate Staleness via Discrete Updates**
```
1. Protocol's exchange rate only updates when {ROLE_NAME} acts (discrete updates)
2. Between role actions, rate is stale -- does not reflect accumulated value
3. User monitors for {ROLE_NAME} pending transaction
4. User enters at stale rate (favorable), {ROLE_NAME} executes, rate updates
5. User exits at updated rate (or holds appreciating position)
6. Impact: {RATE_ARBIT_IMPACT}
```
Note: This differs from cross-chain staleness. This applies when the rate is stale ON THE SAME CHAIN because updates only happen on specific role actions (compounding, rebalancing, harvesting), not on every user interaction.

### Step 6: Precondition Griefability Check

For each function callable by {ROLE_NAME}:

| Function | Preconditions | User Can Manipulate? | Grief Impact |
|----------|--------------|---------------------|--------------|
| {func} | balance > 0 | YES - withdraw all | Keeper stuck |
| {func} | cooldown passed | NO - time-based | N/A |
| {func} | threshold met | YES - partial withdraw | Delayed execution |

**Generic Rule**: Any admin/keeper function precondition that depends on user-manipulable state is potentially griefable.

### Step 6b: Admin/Privileged Function Griefability (EXHAUSTIVE)

**MANDATORY**: Use Slither (`list_functions` with role modifiers, `analyze_modifiers`) to enumerate ALL privileged functions. Do NOT rely on manual scanning -- manual scanning misses functions. Validate your count against the Slither output.

Extend griefability analysis beyond the semi-trusted role to ALL admin/privileged functions:

For each function callable by DEFAULT_ADMIN_ROLE or equivalent:

| Function | Preconditions | External State Dependency? | User Can Manipulate? | Grief Impact |
|----------|--------------|---------------------------|---------------------|--------------|
| {admin_fn} | {preconditions} | YES/NO | YES/NO | {impact if griefed} |

**Enumeration completeness check**:
- [ ] Slither `list_functions` count for role-restricted functions: {N}
- [ ] Functions analyzed in this table: {M}
- [ ] If M < N -> INCOMPLETE -- analyze missing functions before proceeding

**Specific checks**:
- Can users create state that blocks admin operations? (pending withdrawals blocking migration, non-zero balances blocking entity removal)
- Can users transfer tokens to the protocol that block operations? (unsolicited token transfers creating non-zero balances -- see Rule 11)
- Can users initiate multi-step operations whose in-flight state blocks admin actions?

**RULE**: If ANY admin function has a user-griefable precondition -> severity >= MEDIUM if it blocks critical protocol operations.

### Key Questions
5. Can users predict when {ROLE_NAME} will act?
6. Can users manipulate preconditions to block {ROLE_NAME}?
7. Can users profit by positioning around {ROLE_NAME}'s scheduled actions?
8. What happens if {ROLE_NAME} cannot execute? (system degradation)
9. Can users block admin operations via state manipulation or token transfers?

## Instantiation Parameters
```
{CONTRACTS}           -- Contracts to analyze
{ROLE_NAME}           -- Specific role (BOT_ROLE, OPERATOR, etc.)
{ROLE_FUNCTIONS}      -- Functions this role can call
{USER_ACTION}         -- User action that could be front-run
{ROLE_ACTION}         -- Role action used in attack
{TIMING_IMPACT}       -- Impact of timing attack
{MALICIOUS_PARAMS}    -- Harmful parameter values
{EXPECTED_CONSTRAINTS}-- What params should be validated against
{PARAM_IMPACT}        -- Impact of parameter attack
{MAX_DAMAGE}          -- Maximum extractable value
{RECOVERY_PATH}       -- How to recover from compromise
```

## Output Schema
| Field | Required | Description |
|-------|----------|-------------|
| role_permissions | yes | Functions callable by role |
| timing_vectors | yes | Timing-based abuse opportunities |
| parameter_vectors | yes | Parameter-based abuse opportunities |
| omission_vectors | yes | Harm from inaction |
| user_exploit_vectors | yes | How users can exploit the role |
| max_damage | yes | Worst-case damage assessment |
| mitigations | yes | Existing protections |
| finding | yes | CONFIRMED / REFUTED / CONTESTED / NEEDS_DEPTH |
| evidence | yes | Code locations with line numbers |
| step_execution | yes | Status for each step |

---

## Step Execution Checklist (MANDATORY)

> **CRITICAL**: You MUST report completion status for ALL steps. Both directions (role->user AND user->role) are equally important.

| Step | Required | Completed? | Notes |
|------|----------|------------|-------|
| 1. Inventory Role Permissions | YES | | |
| 2. Analyze Within-Scope Abuse | YES | | |
| 3. Model Attack Scenarios (A,B,C) | YES | | |
| 4. Assess Mitigations | YES | | |
| 5. Model User-Side Exploitation (D,E,F) | **YES** | | **MANDATORY** -- never skip |
| 6. Precondition Griefability Check | **YES** | | **MANDATORY** -- never skip |
| 6b. Admin Function Griefability | **YES** | | **MANDATORY** -- never skip |

### Cross-Reference Markers

**After Step 4** (Assess Mitigations):
- **DO NOT STOP HERE** -- Steps 5-6 analyze the reverse direction
- IF role has any preconditions depending on user state -> **MUST complete Step 6**

**After Step 5** (User-Side Exploitation):
- Cross-reference with `TOKEN_FLOW_TRACING.md` for token-related griefing vectors
- IF keeper actions are predictable -> document MEV/front-running vectors

**After Step 6** (Precondition Griefability):
- IF any precondition is user-griefable -> severity >= MEDIUM
- Document system degradation if keeper is blocked

### Output Format for Step Execution

```markdown
**Step Execution**: checkmark1,2,3,4,5,6 | (no skips for this skill)
```

OR if incomplete:

```markdown
**Step Execution**: checkmark1,2,3,4 | ?5,6(user exploitation not analyzed)
**FLAG**: Incomplete analysis -- requires depth review (missing reverse direction)
```
