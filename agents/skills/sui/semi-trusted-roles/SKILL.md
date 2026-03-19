---
name: "semi-trusted-roles"
description: "Trigger Pattern SEMI_TRUSTED_ROLE flag (required) - Inject Into Breadth agents, depth-state-trace"
---

# Skill: Semi-Trusted Role Analysis (Sui)

> **Trigger Pattern**: SEMI_TRUSTED_ROLE flag (required)
> **Inject Into**: Breadth agents, depth-state-trace
> **Purpose**: Analyze capability-based privilege model in Sui Move protocols for both role-to-user and user-to-role attack vectors

## Trigger Patterns
```
AdminCap|OwnerCap|TreasuryCap|OperatorCap|KeeperCap|GovernanceCap|
MinterCap|ManagerCap|UpgradeCap|PublisherCap|has_cap|assert_cap|
capability|cap_check|admin_only
```

## Reasoning Template

### Step 1: Inventory Role Permissions

Enumerate ALL capability objects in the protocol:

| Capability Type | Abilities | Holder | Functions Callable | State Modifiable | Transferable? |
|----------------|-----------|--------|-------------------|-----------------|---------------|
| {AdminCap} | {key, store?} | {deployer/multisig} | {list all functions requiring &AdminCap} | {list state} | {YES if has store / NO if only key} |

**Sui capability model**:
- Capabilities are owned objects. Holding the object = having the role.
- `key` ability: object can exist on-chain. Transferred with `transfer::transfer` (module-only) or `transfer::public_transfer` (if also has `store`).
- `key + store`: freely transferable by anyone. **High risk** -- capability can be sent to arbitrary addresses.
- `key` only: transferable only by the defining module's functions. **Lower risk** -- controlled transfer.
- Capabilities are checked by reference: `fun admin_action(cap: &AdminCap, ...)` -- presence of reference proves ownership.

For each capability at {CAPABILITY_OBJECTS}:
- What state does it grant access to modify?
- What external calls does it authorize?
- What parameters does it allow setting?
- Is the capability shared (`share_object`) or owned? Shared caps are NOT single-holder.

### Step 2: Analyze Within-Scope Abuse

For each permitted action, ask:

**Timing Abuse**:
- Can {ROLE_NAME} execute at harmful times? (front-run users via shared object contention, during rebalance)
- Can {ROLE_NAME} delay execution to harm users? (withhold keeper actions)

**Parameter Abuse**:
- Can {ROLE_NAME} pass harmful parameters? (max slippage, wrong recipient, extreme fee)
- Are parameters validated against bounds, or trusted implicitly?

**Sequence Abuse**:
- Can {ROLE_NAME} execute operations out of order?
- Can {ROLE_NAME} skip required operations in a multi-step flow?

**Omission Abuse**:
- Can {ROLE_NAME} harm users by NOT acting? (skip price update, delay distribution, not calling keeper function)

### Step 3: Model Attack Scenarios
```
Scenario A: Timing Attack
1. {ROLE_NAME} monitors pending transactions on shared objects
2. {ROLE_NAME} submits transaction to modify shared object state
3. Due to Sui's object-based execution, contention determines ordering
4. User's transaction executes with worse conditions
5. Impact: {TIMING_IMPACT}

Scenario B: Parameter Attack
1. {ROLE_NAME} calls {ROLE_FUNCTION} with {MALICIOUS_PARAMS}
2. Parameters are not validated against {EXPECTED_CONSTRAINTS}
3. Impact: {PARAM_IMPACT}

Scenario C: Key Compromise / Capability Theft
1. {ROLE_NAME} capability object is transferred to attacker
2. If cap has `store` ability: attacker can receive it via `transfer::public_transfer`
3. Attacker can call: {ROLE_FUNCTIONS}
4. Maximum extractable value: {MAX_DAMAGE}
5. Recovery options: {RECOVERY_PATH}
   - Can a higher-level cap revoke or re-create the compromised cap?
   - Is there an UpgradeCap that can patch the module?

Scenario C2: Shared Capability Abuse
1. {ROLE_NAME} capability is a shared object (created via `transfer::share_object`)
2. ANY user can include the shared cap in their PTB as `&SharedCap` reference
3. Attacker calls admin functions by passing the shared cap reference
4. Attacker can atomically compose admin operations with exploitation in a single PTB
5. Maximum extractable value: {MAX_DAMAGE}
6. NOTE: Shared caps effectively give EVERYONE the admin role -- this is almost always a critical finding
```

### Step 4: Assess Mitigations

| Mitigation | Present? | Effective? |
|------------|----------|------------|
| Timelock on {ROLE_NAME} actions | YES/NO | {clock-based delay?} |
| Multisig ownership (Sui multisig or custom) | YES/NO | {threshold?} |
| Removal/revocation function for {ROLE_NAME} | YES/NO | {who can revoke?} |
| Rate limits or cooldowns (clock-based) | YES/NO | {duration?} |
| Parameter bounds enforcement | YES/NO | {min/max checked?} |
| UpgradeCap held separately | YES/NO | {who holds it?} |

**Does a removal/revocation function for {ROLE_NAME} EXIST?** If NO -> FINDING: capability is irrevocable without module upgrade. Severity: minimum Medium if cap can modify user-facing state.

**Capability transfer control**:
- If cap has `store`: anyone holding it can transfer freely. Is this intended?
- If cap has only `key`: only module functions can transfer. Are those functions properly access-controlled?
- Is there a `destroy` function for the capability? If NO and cap has `store`: it can never be burned.
- Is the capability frozen (immutable via `transfer::freeze_object`)? Frozen caps can be read (`&Cap`) but not consumed or mutated -- limits authorized actions to read-only gating.

**PTB composition risk**: Can the capability holder compose a PTB that atomically: (1) changes parameters via admin function, (2) exploits the changed parameters via user function? If YES and cap is owned by a semi-trusted role -> the role can atomically manipulate + exploit without time for users to react.

### Step 5: Model User-Side Exploitation (Reverse Direction)

**Predictability Analysis**:
- Is the role's behavior predictable? (scheduled tasks, triggered by events, epoch-based)
- Can users observe when the role will act via on-chain state?
- Can users front-run or back-run the role's actions via shared object contention?

**Scenario D: User Exploits Keeper Timing**
```
1. User observes that {ROLE_NAME} executes {ROLE_ACTION} at predictable times (e.g., epoch boundaries)
2. User positions themselves before {ROLE_ACTION} (deposit/stake before reward distribution)
3. {ROLE_ACTION} executes, changing state
4. User benefits from known state change
5. Impact: {USER_EXPLOIT_IMPACT}
```

**Scenario E: User Griefs Role Preconditions**
```
1. {ROLE_FUNCTION} has precondition: {PRECONDITION} (stored in shared object)
2. User calls a permissionless function that modifies the shared object to violate {PRECONDITION}
3. {ROLE_NAME} calls {ROLE_FUNCTION}, which aborts
4. System enters degraded state (no keeper actions possible)
5. Impact: {GRIEF_IMPACT}
```

**Scenario F: User Forces Suboptimal Role Action**
```
1. {ROLE_NAME} must choose between options based on shared object state
2. User manipulates shared object state to make worst option appear best
3. {ROLE_NAME} (following honest behavior) chooses suboptimal path
4. User profits from forced suboptimal execution
5. Impact: {SUBOPTIMAL_IMPACT}
```

**Scenario G: Same-Chain Rate Staleness via Discrete Updates**
```
1. Protocol's exchange rate only updates when {ROLE_NAME} acts (discrete updates)
2. Between role actions, rate is stale -- does not reflect accumulated value
3. User monitors for {ROLE_NAME} pending transaction on shared object
4. User enters at stale rate (favorable), {ROLE_NAME} executes, rate updates
5. User exits at updated rate (or holds appreciating position)
6. Impact: {RATE_ARBIT_IMPACT}
```

### Step 6: Precondition Griefability Check

For each function callable by {ROLE_NAME}:

| Function | Preconditions | Stored In | User Can Manipulate? | Grief Impact |
|----------|--------------|-----------|---------------------|--------------|
| {func} | balance > 0 | Shared pool object | YES - withdraw all | Keeper stuck |
| {func} | epoch elapsed | Clock (0x6) | NO - time-based | N/A |
| {func} | threshold met | Shared config object | YES - partial withdraw | Delayed execution |

**Generic Rule**: Any admin/keeper function precondition that depends on user-modifiable shared object state is potentially griefable.

**Sui-specific griefability**: Shared object contention can cause transaction ordering issues. If a keeper transaction and a user transaction both touch the same shared object, Sui's consensus determines ordering -- neither party can guarantee priority.

### Step 6b: Admin/Privileged Function Griefability (EXHAUSTIVE)

**MANDATORY**: Enumerate ALL functions that require a capability parameter. Do NOT rely on manual scanning -- grep for all capability types found in Step 1.

For each function requiring ANY capability:

| Function | Required Cap | Preconditions | Shared Object Dependency? | User Can Manipulate? | Grief Impact |
|----------|-------------|--------------|---------------------------|---------------------|--------------|
| {admin_fn} | {AdminCap} | {preconditions} | YES/NO | YES/NO | {impact if griefed} |

**Enumeration completeness check**:
- [ ] Grep count for functions accepting capability references: {N}
- [ ] Functions analyzed in this table: {M}
- [ ] If M < N -> INCOMPLETE -- analyze missing functions before proceeding

**Specific checks**:
- Can users create shared object state that blocks admin operations? (pending withdrawals blocking migration, non-zero balances blocking cleanup)
- Can users create dynamic field entries that block operations? (table entries preventing deletion)
- Can users initiate multi-step operations whose in-flight state blocks admin actions?

**RULE**: If ANY admin function has a user-griefable precondition -> severity >= MEDIUM if it blocks critical protocol operations.

### Key Questions (must answer all)
1. What is the maximum damage if {ROLE_NAME} acts maliciously?
2. What is the maximum damage if {ROLE_NAME} capability is stolen?
3. Are there time-sensitive operations where {ROLE_NAME} timing matters?
4. What user funds or protocol state can {ROLE_NAME} affect?
5. Can users predict when {ROLE_NAME} will act?
6. Can users manipulate preconditions to block {ROLE_NAME}?
7. Can users profit by positioning around {ROLE_NAME}'s scheduled actions?
8. What happens if {ROLE_NAME} cannot execute? (system degradation)
9. Can users block admin operations via shared object state manipulation?

## Common False Positives

- **View-only operations**: If role can only read state, no abuse vector
- **Idempotent operations**: If calling twice has same effect as once, timing abuse is limited
- **User-initiated dependency**: If role action requires user to initiate first, front-running may not apply
- **Economic alignment**: If role is economically aligned (staked collateral), malicious action has cost
- **Module-locked capability**: If cap has only `key` and no transfer function exists, theft requires module compromise

## Instantiation Parameters
```
{CONTRACTS}           -- Move modules to analyze
{ROLE_NAME}           -- Specific capability type (AdminCap, OperatorCap, etc.)
{CAPABILITY_OBJECTS}  -- Capability object types and their abilities
{ROLE_FUNCTIONS}      -- Functions this capability grants access to
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
| capability_inventory | yes | All capability objects and their permissions |
| timing_vectors | yes | Timing-based abuse opportunities |
| parameter_vectors | yes | Parameter-based abuse opportunities |
| omission_vectors | yes | Harm from inaction |
| user_exploit_vectors | yes | How users can exploit the role (reverse direction) |
| transfer_risk | yes | Capability transferability analysis |
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
| 3. Model Attack Scenarios (A,B,C,C2) | YES | | Including shared cap scenario |
| 4. Assess Mitigations | YES | | |
| 5. Model User-Side Exploitation (D,E,F,G) | **YES** | | **MANDATORY** -- never skip |
| 6. Precondition Griefability Check | **YES** | | **MANDATORY** -- never skip |
| 6b. Admin Function Griefability | **YES** | | **MANDATORY** -- never skip |

### Cross-Reference Markers

**After Step 4** (Assess Mitigations):
- **DO NOT STOP HERE** -- Steps 5-6 analyze the reverse direction
- IF role has any preconditions depending on shared object state -> **MUST complete Step 6**

**After Step 5** (User-Side Exploitation):
- Cross-reference with `TOKEN_FLOW_TRACING.md` for token-related griefing vectors
- IF keeper actions are predictable -> document MEV/front-running vectors

**After Step 6** (Precondition Griefability):
- IF any precondition is user-griefable -> severity >= MEDIUM
- Document system degradation if keeper is blocked
