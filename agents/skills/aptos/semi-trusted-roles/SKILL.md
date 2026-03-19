---
name: "semi-trusted-roles"
description: "Trigger Pattern SEMI_TRUSTED_ROLE flag (required) - Inject Into Breadth agents, depth-state-trace"
---

# SEMI_TRUSTED_ROLES Skill

> **Trigger Pattern**: SEMI_TRUSTED_ROLE flag (required)
> **Inject Into**: Breadth agents, depth-state-trace
> **Purpose**: Analyze semi-trusted roles in Aptos Move protocols using capability-based access control, modeling both role-to-user and user-to-role attack vectors

## Trigger Patterns
```
signer|SignerCapability|AdminCap|OperatorCap|KeeperCap|has_role|
assert_admin|assert_operator|friend|acquires|ExtendRef|
DeleteRef|TransferRef|MintRef|BurnRef
```

## Reasoning Template

### Step 1: Inventory Role Permissions

Enumerate ALL privileged roles in the protocol:

| Role | Capability / Check | Module | Functions Callable | State Modifiable | External Calls |
|------|-------------------|--------|-------------------|-----------------|----------------|
| {role} | {SignerCapability / custom Cap struct / signer check / friend} | {module} | {fn list} | {state list} | {calls list} |

**Aptos capability patterns to inventory**:
- **SignerCapability**: Stored in resource, allows generating a signer for the capability's address. Can call any function requiring that signer.
- **Custom capability structs**: `AdminCap`, `OperatorCap` etc. -- often stored in the deployer's account or an Object
- **Signer checks**: `assert!(signer::address_of(account) == @admin, E_NOT_ADMIN)` -- direct address comparison
- **Friend declarations**: `friend module::other` -- allows `other` to call `public(friend)` functions
- **Object Refs**: `ExtendRef`, `DeleteRef`, `TransferRef`, `MintRef`, `BurnRef` -- object-level capabilities
- **Resource account patterns**: Module creates a resource account and stores its `SignerCapability`

For each role at {ROLE_FUNCTIONS}:
- What state does it modify?
- What external calls does it make (via CPI or module calls)?
- What parameters does it accept?

### Step 2: Analyze Within-Scope Abuse (Direction A: Malicious Role)

For each permitted action, ask:

**Timing Abuse**:
- Can {ROLE_NAME} execute at harmful times? (front-run users via transaction ordering, during rebalance)
- Can {ROLE_NAME} delay execution to harm users? (withhold keeper actions)

**Parameter Abuse**:
- Can {ROLE_NAME} pass harmful parameters? (max slippage, wrong recipient address, extreme fee values)
- Are parameters validated on-chain, or trusted implicitly from the role?

**Sequence Abuse**:
- Can {ROLE_NAME} execute operations out of order?
- Can {ROLE_NAME} skip required operations in a multi-step process?

**Omission Abuse**:
- Can {ROLE_NAME} harm users by NOT acting? (skip price updates, delay distributions, never trigger harvest)

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
1. {ROLE_NAME} private key is compromised (or SignerCapability is leaked)
2. Attacker can call: {ROLE_FUNCTIONS}
3. Maximum extractable value: {MAX_DAMAGE}
4. Recovery options: {RECOVERY_PATH}
```

### Step 4: Assess Mitigations

| Mitigation | Present? | Implementation | Effective? |
|-----------|----------|----------------|-----------|
| Timelock on role actions | YES/NO | {code ref} | {analysis} |
| Multisig requirement | YES/NO | {code ref} | {analysis} |
| Role revocation function | YES/NO | {code ref} | {analysis} |
| Rate limits / cooldowns | YES/NO | {code ref} | {analysis} |
| Parameter bounds validation | YES/NO | {code ref} | {analysis} |
| Event emission for monitoring | YES/NO | {code ref} | {analysis} |

**Does a removal/revocation function for {ROLE_NAME} EXIST?** If NO -> FINDING: role is irrevocable without module upgrade. Severity: minimum Medium if role can modify user-facing state.

### Step 4b: Capability Escalation Analysis

| Capability | Stored Where | Can Be Duplicated? | Can Escalate? | Escalation Path |
|-----------|-------------|-------------------|---------------|----------------|
| {cap} | {resource/object} | YES/NO (`copy` ability?) | YES/NO | {if YES: how} |

**Aptos-specific escalation vectors**:
- `SignerCapability` has `copy` + `store` abilities -- can it be extracted and stored elsewhere?
- `ExtendRef` allows adding resources to an Object -- can a role add capabilities it shouldn't have?
- `TransferRef` allows ungated transfer of an Object -- can a role transfer an Object holding other capabilities?
- `MintRef` / `BurnRef` -- can a role with mint capability effectively drain the protocol?
- Friend module access -- can a friend module be upgraded to abuse `public(friend)` functions?

### Step 4c: Capability Transfer and Duplication

| Capability | Has `copy`? | Has `drop`? | Has `store`? | Transfer Function Exists? | Risk |
|-----------|------------|------------|-------------|--------------------------|------|
| {cap} | YES/NO | YES/NO | YES/NO | YES/NO | {assessment} |

**Key checks**:
- If capability has `copy` -> it can be duplicated, creating multiple holders
- If capability has `store` -> it can be placed in global storage, potentially accessible by others
- If capability has `drop` -> it can be silently discarded (may not be a risk, but check if protocol assumes it persists)
- If a `transfer_cap()` function exists -> trace who can call it and whether it validates the recipient

## Reverse Perspective: User Exploitation of Roles

### Step 5: Model User-Side Exploitation (Direction B: Malicious Users)

**Predictability Analysis**:
- Is the role's behavior predictable? (scheduled tasks, triggered by events, MEV-visible)
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
3. {ROLE_NAME} calls {ROLE_FUNCTION}, which aborts
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

### Step 6: Precondition Griefability Check

For each function callable by {ROLE_NAME}:

| Function | Preconditions | User Can Manipulate? | Grief Impact |
|----------|--------------|---------------------|--------------|
| {func} | balance > 0 | YES - withdraw all | Keeper stuck |
| {func} | cooldown passed | NO - time-based | N/A |
| {func} | threshold met | YES - partial withdraw | Delayed execution |
| {func} | resource exists | YES - can delete? | Function aborts |

**Generic Rule**: Any privileged function precondition that depends on user-manipulable state is potentially griefable.

### Step 6b: Admin/Privileged Function Griefability (EXHAUSTIVE)

**MANDATORY**: Enumerate ALL privileged functions by scanning for signer checks, capability acquires, and friend-only visibility. Do NOT rely on manual scanning.

For each function callable by admin or equivalent role:

| Function | Preconditions | External State Dependency? | User Can Manipulate? | Grief Impact |
|----------|--------------|---------------------------|---------------------|--------------|
| {admin_fn} | {preconditions} | YES/NO | YES/NO | {impact if griefed} |

**Enumeration completeness check**:
- [ ] Total role-restricted functions found: {N}
- [ ] Functions analyzed in this table: {M}
- [ ] If M < N -> INCOMPLETE -- analyze missing functions before proceeding

**Specific Aptos checks**:
- Can users create resources that block admin `move_from` operations?
- Can users deposit unsolicited tokens that prevent admin operations expecting zero balance?
- Can users initiate multi-step operations whose pending state blocks admin actions?
- Can users create Objects in a namespace that conflicts with admin Object creation?

## Key Questions (must answer ALL)

1. What is the maximum damage if {ROLE_NAME} acts maliciously?
2. What is the maximum damage if {ROLE_NAME} key/capability is compromised?
3. Are there time-sensitive operations where {ROLE_NAME} timing matters?
4. What user funds or protocol state can {ROLE_NAME} affect?
5. Can users predict when {ROLE_NAME} will act?
6. Can users manipulate preconditions to block {ROLE_NAME}?
7. Can users profit by positioning around {ROLE_NAME}'s scheduled actions?
8. What happens if {ROLE_NAME} cannot execute? (system degradation)
9. Can users block admin operations via state manipulation or unsolicited deposits?

## Common False Positives

- **View-only operations**: If role can only read state, no abuse vector
- **Idempotent operations**: If calling twice has same effect as once, timing abuse is limited
- **User-initiated dependency**: If role action requires user to initiate first, front-running may not apply
- **Economic alignment**: If role is economically aligned (staked collateral), malicious action has cost
- **Module upgrade authority**: Separate from in-protocol roles -- module upgrade is a governance concern, not a semi-trusted role issue (unless the protocol treats it as semi-trusted)

## Instantiation Parameters
```
{CONTRACTS}           -- Move modules to analyze
{ROLE_NAME}           -- Specific role (operator, keeper, admin, etc.)
{ROLE_FUNCTIONS}      -- Functions this role can call
{ROLE_CAPABILITIES}   -- Capability structs held by this role
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
| role_permissions | yes | Functions and capabilities per role |
| timing_vectors | yes | Timing-based abuse opportunities |
| parameter_vectors | yes | Parameter-based abuse opportunities |
| omission_vectors | yes | Harm from inaction |
| capability_escalation | yes | Capability escalation and duplication risks |
| user_exploit_vectors | yes | How users can exploit the role (Direction B) |
| max_damage | yes | Worst-case damage assessment |
| mitigations | yes | Existing protections |
| finding | yes | CONFIRMED / REFUTED / CONTESTED / NEEDS_DEPTH |
| evidence | yes | Code locations with line numbers |
| step_execution | yes | Status for each step |

---

## Step Execution Checklist (MANDATORY)

| Step | Required | Completed? | Notes |
|------|----------|------------|-------|
| 1. Inventory Role Permissions | YES | | |
| 2. Analyze Within-Scope Abuse | YES | | |
| 3. Model Attack Scenarios (A,B,C) | YES | | |
| 4. Assess Mitigations | YES | | |
| 4b. Capability Escalation Analysis | YES | | Aptos-specific |
| 4c. Capability Transfer and Duplication | YES | | Aptos-specific |
| 5. Model User-Side Exploitation (D,E,F,G) | **YES** | | **MANDATORY** -- never skip |
| 6. Precondition Griefability Check | **YES** | | **MANDATORY** -- never skip |
| 6b. Admin Function Griefability | **YES** | | **MANDATORY** -- never skip |

### Cross-Reference Markers

**After Step 4** (Assess Mitigations):
- **DO NOT STOP HERE** -- Steps 5-6 analyze the reverse direction
- IF role has any preconditions depending on user state -> **MUST complete Step 6**

**After Step 4c** (Capability Transfer):
- IF capability has `copy` ability -> document duplication risk explicitly
- IF `SignerCapability` is stored -> trace ALL code paths that access it

**After Step 5** (User-Side Exploitation):
- Cross-reference with `TOKEN_FLOW_TRACING.md` for token-related griefing vectors
- IF keeper actions are predictable -> document MEV/front-running vectors

**After Step 6** (Precondition Griefability):
- IF any precondition is user-griefable -> severity >= MEDIUM
- Document system degradation if keeper is blocked
