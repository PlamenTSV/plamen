# Phase 4b: Scanner & Sweep Templates

> **Usage**: Orchestrator reads this file to spawn the 3 Blind Spot Scanners, Validation Sweep Agent, and Design Stress Testing Agent in iteration 1.
> Replace placeholders `{SCRATCHPAD}`, etc. with actual values.

---

## Processing Protocol (ALL Scanner & Sweep Agents)

Every agent spawned from this file MUST follow this protocol for each CHECK/step in their section:
1. **ENUMERATE targets**: List every entity the CHECK applies to as a numbered list before analysis begins.
2. **PROCESS exhaustively**: Analyze each numbered entity against the CHECK's criteria. Mark each "DONE" or "N/A (reason)" before moving to the next.
3. **COVERAGE GATE**: Count enumerated vs processed. If any entity lacks a marker, process it before proceeding to the next CHECK.

Agents MAY add optional `Discovery Steer: ...` text inside live finding blocks
or Chain Summary notes when it gives a compact generic pairing hint (shared
variable/function, branch, terminal effect, or candidate ID). It is not proof,
not required, and must not create additional output files.

---

## Blind Spot Scanner A: Tokens & Parameters

> **Trigger**: Always runs IN PARALLEL with depth agents (iteration 1 only).
> **Purpose**: Check what breadth agents missed in token coverage and parameter analysis.

```
Task(subagent_type="general-purpose", prompt="
You are Blind Spot Scanner A. Find what breadth agents NEVER LOOKED AT for tokens and parameters.

## Your Inputs
Read:
- {SCRATCHPAD}/attack_surface.md (Token Flow Matrix)
- {SCRATCHPAD}/findings_inventory.md (what WAS analyzed)
- {SCRATCHPAD}/constraint_variables.md (governance-changeable parameters)

## Processing Protocol (MANDATORY " applies to every CHECK below)

For each CHECK, execute three steps in order:
1. **ENUMERATE targets**: List every entity the CHECK applies to (tokens, parameters, call sites, contracts) as a numbered list before analysis begins.
2. **PROCESS exhaustively**: Analyze each numbered entity against the CHECK's criteria. Mark each "DONE" or "N/A (reason)" before moving to the next.
3. **COVERAGE GATE**: Count enumerated vs processed. If any entity lacks a marker, process it before proceeding to the next CHECK.

## CHECK 1: External Token Coverage
Cross-reference attack_surface.md Token Flow Matrix against findings_inventory.md:

For each external token in the Token Flow Matrix:
| External Token | Analyzed by Agent? | Finding IDs | Dimensions Covered (R11) | Missing Dimensions |
|----------------|-------------------|-------------|--------------------------|-------------------|

If ANY external token has 0 findings AND is transferable to the protocol â†’ BLIND SPOT.
If ANY external token has findings covering â‰¤2 of 5 R11 dimensions AND uncovered dimensions are applicable â†’ PARTIAL BLIND SPOT.

**Dimension coverage gate**: For each token with â‰¥1 finding, verify coverage breadth:

| External Token | R11-D1: Transferability | R11-D2: Accounting | R11-D3: Op Blocking | R11-D4: Loop/Gas | R11-D5: Side Effects | Dimensions Covered |
|----------------|------------------------|--------------------:|--------------------:|-----------------|---------------------|-------------------|

If ANY token has findings covering â‰¤2 of 5 dimensions AND the uncovered dimensions are applicable â†’ PARTIAL BLIND SPOT.
Applicable = the token type supports that interaction (e.g., NFTs don't have D4:Loop/Gas unless enumerable).

## CHECK 1b: Unchecked ERC20 Transfer Return Values (Slither fallback)
Skip this check if `SLITHER: AVAILABLE` in build_status.md (Slither's `unchecked-transfer` detector covers this).
Grep for raw `.transfer(` and `.transferFrom(` calls (NOT `safeTransfer`/`safeTransferFrom`) on external token addresses. For each: is the return value checked (`require(token.transfer(...))`) or is SafeERC20 used? If neither, tokens like USDT that return false on failure will silently fail " state updates proceed but no tokens move.

| Call Site | Token | Uses SafeERC20? | Return Value Checked? | Gap? |
|-----------|-------|-----------------|----------------------|------|

If raw `.transfer()`/`.transferFrom()` without return-value handling found â†’ FINDING (MEDIUM: silent transfer failure with non-reverting tokens like USDT).

## CHECK 2: Governance-Changeable Parameter Coverage
From constraint_variables.md, for each parameter with a setter function:

| Parameter | Setter Function | Can Affect Active Operations? | Analyzed by Agent? | Finding ID |
|-----------|----------------|-------------------------------|-------------------|------------|

**Apply Rule 13**: For each parameter change, model BOTH directions:
- Parameter INCREASES: who is harmed?
- Parameter DECREASES: who is harmed?
- If either direction harms users AND no finding covers it â†’ BLIND SPOT

**Apply Rule 14**: For each parameter:
- Does its setter enforce bounds? (min/max checks before writing storage)
- Can the new value be set below accumulated state? (setter regression)
- Is there a related parameter that must maintain coherence? (constraint coherence)
- **Silent misconfiguration**: If the setter has NO bounds check, trace downstream math with an accepted-but-extreme value. Does the system revert, or does it silently produce wrong results? A setter that accepts any value AND downstream math silently breaks for part of the accepted range is a finding " even without an attacker.

## CHECK 2b: Native Value in Loops (IF msg.value detected in scope)
Skip this check if `msg.value` is not detected in the scoped contracts.
Grep for `msg.value` inside `for`/`while` loops or in functions called by `multicall`/`batch`:

| Function | Contains msg.value? | Inside Loop/Batch? | Total msg.value Uses | Gap? |
|----------|--------------------|--------------------|---------------------|------|

If msg.value is read more than once in a single call context (loop iteration, multicall delegate) â†’ each iteration reuses the same msg.value â†’ FINDING (HIGH: direct fund theft via double-spend).

## CHECK 2c: Unbounded Return Data (IF .call{|.call(|.delegatecall( detected in scope)
Skip this check if low-level `.call{`, `.call(`, or `.delegatecall(` is not detected in the scoped contracts.
Grep for low-level `.call(` where the return data is copied without size cap:

| External Call Site | Return Data Bounded? | Copy Method | Gap? |
|-------------------|---------------------|-------------|------|

Vulnerable pattern: `(bool success, bytes memory data) = target.call(...)` where `data` is unbounded and caller pays gas for copy. Safe pattern: `ExcessivelySafeCall` or `assembly { returndatacopy(..., ..., min(returndatasize(), CAP)) }`. If unbounded AND in a loop or user-triggered path â†’ FINDING (MEDIUM: gas griefing / DoS).

## CHECK 2d: Relay/Meta-tx Gas Griefing (IF gasleft()|relayer|forwarder detected in scope)
Skip this check if `gasleft()`, `relayer`, `forwarder`, or meta-transaction patterns are not detected in the scoped contracts.
Grep for `gasleft()`, `meta-transaction`, `relayer`, `forwarder`, or functions that execute on behalf of another user:

| Relay Function | Gas Forwarding Pattern | Minimum Gas Check? | Refund on Failure? | Gap? |
|---------------|----------------------|-------------------|-------------------|------|

If a relay function forwards a user-specified call without ensuring sufficient gas remains for post-call logic â†’ FINDING (MEDIUM: relayer can be griefed into paying gas for failed txs, or insufficient gas causes silent partial execution).

## CHECK 2e: Approval/Delegate Sequence Conflicts (IF approve/safeApprove/increaseAllowance detected in scope)
Skip this check if no `approve`, `safeApprove`, `increaseAllowance`, or `permit` patterns are detected in the scoped contracts. If `{SCRATCHPAD}/niche_multi_step_safety_findings.md` exists and is non-empty, limit this to listing affected functions in a table [Function | Pattern | Note] " do NOT trace execution, compute impacts, or construct exploitation scenarios. The niche agent handles deep analysis.
For each multi-step operation (batch calls, multicall, loops over tokens), enumerate all approve/increaseAllowance/safeApprove calls. If the same (spender, token) pair is approved more than once in the same sequence, verify amounts are additive or the second accounts for the first. Sequential overwrites â†’ FINDING.

## CHECK 2f: Infrastructure Address Targeting (IF depositFor/stakeFor/delegateTo detected in scope)
Skip this check if no `depositFor`, `stakeFor`, `delegateTo`, `mintFor`, `withdrawFor`, or similar on-behalf-of function patterns are detected. If `{SCRATCHPAD}/niche_multi_step_safety_findings.md` exists and is non-empty, limit this to listing affected functions in a table [Function | Target Param | Note] " do NOT trace execution or compute impacts.
For each public/external function that writes state keyed by an address parameter (e.g., `depositFor(target)`, `stakeFor(target)`, `delegateTo(target)`): can any protocol infrastructure contract (router, vault, pool, strategy) be used as the target? If yes, what state is imposed on it, and does it break protocol operations? â†’ FINDING.

## CHECK 2g: Missing Native ETH Receiver
For each contract in scope, determine whether it is **designed to accept native ETH**. Evidence of design intent (any one is sufficient): (1) design_context.md or docs state it handles native tokens/ETH, (2) code branches on native-ETH sentinel values (`Currency.isAddressZero()`, `token == address(0)`, `isNative`, `NATIVE_TOKEN`), (3) operational implications indicate ETH inflows from external sources (sweeps, refunds, WETH unwraps, Uniswap V4 native currency support), (4) a parent or caller contract sends ETH to `address(this)` via `.transfer()`, `.send()`, or `.call{value:}`. If the contract is designed to accept native ETH but declares no `receive()` or `fallback() payable` â†’ FINDING (MEDIUM if it breaks a core lifecycle flow; LOW if convenience path only).

**Coverage assertion**: Before returning, verify every entity enumerated under each CHECK has been processed. Report enumerated vs analyzed counts in your return message.

## Output
- Maximum 5 findings [BLIND-A1] through [BLIND-A5]
- Use standard finding format
- Note WHY breadth agents likely missed each

## Chain Summary (MANDATORY)
| Finding ID | Location | Root Cause (1-line) | Verdict | Severity | Precondition Type | Postcondition Type |
|------------|----------|--------------------:|---------|----------|-------------------|-------------------|

Write to {SCRATCHPAD}/blind_spot_a_findings.md

Return: 'DONE: {N} blind spots - Check1: {A} token gaps, Check2: {B} parameter gaps'
")
```


---

## Blind Spot Scanner B: Guards, Visibility & Inheritance

> **Trigger**: Always runs IN PARALLEL with depth agents (iteration 1 only).
> **Purpose**: Check what breadth agents missed in access control, visibility, and inheritance.

```
Task(subagent_type="general-purpose", prompt="
You are Blind Spot Scanner B. Find what breadth agents NEVER LOOKED AT for guards, visibility, and inheritance.

## Your Inputs
Read:
- {SCRATCHPAD}/findings_inventory.md (what WAS analyzed)
- {SCRATCHPAD}/function_list.md (complete function inventory)
- {SCRATCHPAD}/state_variables.md (all state variables)

## Processing Protocol (MANDATORY " applies to every CHECK below)

For each CHECK, execute three steps in order:
1. **ENUMERATE targets**: List every entity the CHECK applies to (guards, modifiers, overrides, functions) as a numbered list before analysis begins.
2. **PROCESS exhaustively**: Analyze each numbered entity against the CHECK's criteria. Mark each "DONE" or "N/A (reason)" before moving to the next.
3. **COVERAGE GATE**: Count enumerated vs processed. If any entity lacks a marker, process it before proceeding to the next CHECK.

## CHECK 3: Admin Function Griefability (Rule 2)
From function_list.md, for each function with access control modifiers:

| Admin Function | Preconditions | User-Manipulable? | Analyzed by Agent? | Finding ID |
|----------------|---------------|-------------------|-------------------|------------|

If precondition is user-manipulable AND no finding covers it â†’ BLIND SPOT.

## CHECK 4: Permissionless Function Visibility Audit
From function_list.md, for each public/external function WITHOUT access control modifiers:

| Function | Contract | Emits Events? | Modifies State? | Should Be Internal? | Analyzed? |
|----------|----------|---------------|-----------------|---------------------|-----------|

Flag if: can forge events, manipulate shared state, or should clearly be internal AND no finding covers it.
Also flag: public/external functions that emit events but have NO access control AND do NOT modify meaningful state - these allow anyone to forge events that mislead off-chain indexers, monitoring, and UIs. Exclude standard ERC events (Transfer, Approval) which are designed to be emitted by anyone.
Also flag: any `onlyOwner`/admin state-changing function that does NOT emit an event. Admin parameter changes without events are unmonitorable.

## CHECK 5: Inherited Capability Completeness
From function_list.md and contract source, for each inherited base (Pausable, AccessControl, Ownable, ReentrancyGuard, etc.):

| Contract | Inherited Base | Capability Provided | Exposure Function Exists? | Finding ID |
|----------|---------------|--------------------|--------------------------:|------------|

Flag if: capability is referenced in modifiers/logic but has no external exposure function. Also flag: contract overrides base function but omits a modifier the base had.

Also flag: capability that has a CONFIGURABLE PARAMETER (e.g., `cooldownPeriod`, `pauseDelay`, `minDelay`) but the parameter's setter is NOT exposed via any public/external function. If the parameter affects user behavior and is hardcoded at deployment, ask: is the hardcoded value appropriate for all future states? Can the protocol adapt if conditions change?

## CHECK 5b: Upward Inheritance - Override Safety

For each base contract with virtual functions:

| Base Contract | Virtual Function | Overridden By | Base Modifiers | Override Modifiers | Modifier Dropped? |
|---------------|-----------------|---------------|----------------|-------------------|-------------------|

**Check**:
- Does the override maintain ALL base modifiers? (e.g., base has `nonReentrant` but override omits it)
- Does the override maintain equivalent access control? (e.g., base is `onlyOwner` but override is `public`)
- Are there virtual functions in base that SHOULD be overridden but are NOT? (default behavior may be unsafe)
- Does the override ADD behavior the base did not have? (e.g., base `_beforeTokenTransfer` is a no-op, override adds validation that can revert - does this break callers?)
- Does the override REMOVE behavior the base provided? (e.g., base enforces a pause check, override silently continues)
- Does the override change the REVERT CONDITIONS? (e.g., base reverts on X, override does not - what if another contract relies on the revert?)

**Coverage assertion**: Before returning, verify every entity enumerated under each CHECK has been processed. Report enumerated vs analyzed counts in your return message.

## Output
- Maximum 5 findings [BLIND-B1] through [BLIND-B5]
- Use standard finding format
- Note WHY breadth agents likely missed each

## Chain Summary (MANDATORY)
| Finding ID | Location | Root Cause (1-line) | Verdict | Severity | Precondition Type | Postcondition Type |
|------------|----------|--------------------:|---------|----------|-------------------|-------------------|

Write to {SCRATCHPAD}/blind_spot_b_findings.md

Return: 'DONE: {N} blind spots - Check3: {A} admin gaps, Check4: {B} visibility gaps, Check5: {C} inheritance gaps, Check5b: {D} override gaps'
")
```

---

## Blind Spot Scanner C: Role Lifecycle, Capability Exposure & Reachability

> **Trigger**: Always runs IN PARALLEL with depth agents (iteration 1 only).
> **Purpose**: Check what breadth agents missed in role lifecycle completeness, inherited capability exposure, and function reachability.

```
Task(subagent_type="general-purpose", prompt="
You are Blind Spot Scanner C. Find what breadth agents NEVER LOOKED AT for role lifecycle, capability exposure, and function reachability.

## Your Inputs
Read:
- {SCRATCHPAD}/findings_inventory.md (what WAS analyzed)
- {SCRATCHPAD}/function_list.md (complete function inventory)
- {SCRATCHPAD}/modifiers.md (modifier application map)
- {SCRATCHPAD}/state_variables.md (all state variables)
- Source files for all in-scope contracts

## Processing Protocol (MANDATORY " applies to every CHECK below)

For each CHECK, execute three steps in order:
1. **ENUMERATE targets**: List every entity the CHECK applies to (roles, capabilities, functions, call paths) as a numbered list before analysis begins.
2. **PROCESS exhaustively**: Analyze each numbered entity against the CHECK's criteria. Mark each "DONE" or "N/A (reason)" before moving to the next.
3. **COVERAGE GATE**: Count enumerated vs processed. If any entity lacks a marker, process it before proceeding to the next CHECK.

## CHECK 6: Role Lifecycle Completeness

For each role identified in the codebase (via AccessControl, custom role mappings, or modifier-gated functions):

| Role | Grant Function | Revoke Function | Revoke Exists? | Circular Dependency? | Finding? |
|------|---------------|-----------------|----------------|---------------------|----------|

**Methodology**:
- For each role granted via `grantRole`, `_setupRole`, constructor assignment, or custom setter: does a corresponding `revokeRole` or removal function exist?
- If NO revocation function exists â†’ FINDING: irrevocable role (minimum Medium if role modifies user-facing state)
- Check for circular dependencies: does revoking Role A require Role B, and granting Role B require Role A?
- Check: can a role holder block their own removal? (e.g., role can pause the contract, and revocation requires unpaused state)

## CHECK 7: Inherited Capability Exposure Gaps

For each base contract inherited by in-scope contracts:

| Base Contract | Internal Function | Purpose | Called by Any In-Scope Function? | Externally Reachable? | Gap? |
|---------------|------------------|---------|----------------------------------|----------------------|------|

**Methodology**:
- List ALL internal/private functions provided by inherited base contracts (e.g., `_setPeriod`, `_pause`, `_setOracle`, `_mint`)
- For each: is there a public/external function in the inheriting contract that exposes this capability?
- If a base provides a critical configuration function (e.g., `_setPeriod`) but no in-scope contract exposes it â†’ FINDING: inherited capability is unreachable post-deployment
- Severity: Medium if the unreachable function controls a parameter that affects protocol correctness; Low if it's a convenience function

## CHECK 8: Function Reachability Audit

For each public/external function in all in-scope contracts:

| Function | Contract | Called By (internal) | Called By (external/test) | Reachable in Production? | Dead Code? |
|----------|----------|---------------------|--------------------------|-------------------------|------------|

**Methodology**:
- Trace callers for each function using function_list.md and source grep
- Identify functions that are defined but NEVER called by any other in-scope contract or expected external caller
- For dead code with security implications: does the dead function have access control? Could it be called by anyone if discovered? Does it modify state?
- Special focus: functions that WERE reachable in a previous version but became unreachable after refactoring (look for commented-out callers, TODO comments, or version indicators)
- Flag: public functions with no callers that modify critical state â†’ potential backdoor or forgotten migration artifact

**Coverage assertion**: Before returning, verify every entity enumerated under each CHECK has been processed. Report enumerated vs analyzed counts in your return message.

## Output
- Maximum 8 findings [BLIND-C1] through [BLIND-C8]
- Use standard finding format
- Note WHY breadth agents likely missed each

## Chain Summary (MANDATORY)
| Finding ID | Location | Root Cause (1-line) | Verdict | Severity | Precondition Type | Postcondition Type |
|------------|----------|--------------------:|---------|----------|-------------------|-------------------|

Write to {SCRATCHPAD}/blind_spot_c_findings.md

Return: 'DONE: {N} blind spots - Check6: {A} role lifecycle gaps, Check7: {B} capability exposure gaps, Check8: {C} reachability gaps'
")
```

---

## Validation Sweep Agent

> **Trigger**: Always runs IN PARALLEL with the 4 depth agents and Blind Spot Scanner (iteration 1 only).
> **Purpose**: Mechanical sweep of ALL validation logic for three specific deficit patterns that reasoning-based agents consistently miss: boundary operator precision, validation reachability gaps, and guard coverage completeness.

```
Task(subagent_type="general-purpose", prompt="
You are the Validation Sweep Agent. You perform mechanical checks across every function in scope. You do NOT analyze business logic or economic attacks - you check that existing validation code is correct, reachable, and complete.

## Your Inputs
Read:
- {SCRATCHPAD}/function_list.md (complete function inventory)
- {SCRATCHPAD}/depth_inventory_snapshot.md (immutable Inventory-to-Depth snapshot; avoid duplicates)
- {SCRATCHPAD}/modifiers.md (modifier application map)
- Source files for all in-scope contracts

## INPUT FILTERING
When cross-referencing against depth_inventory_snapshot.md, focus on Medium+ severity findings only. Low/Info findings do not need cross-validation sweeps - the attention cost of processing 50+ findings outweighs the marginal value of sweeping Low/Info patterns.

## Processing Protocol (MANDATORY " applies to every CHECK below)

For each CHECK, execute three steps in order:
1. **ENUMERATE targets**: List every entity the CHECK applies to (validations, operators, guards, functions) as a numbered list before analysis begins.
2. **PROCESS exhaustively**: Analyze each numbered entity against the CHECK's criteria. Mark each "DONE" or "N/A (reason)" before moving to the next.
3. **COVERAGE GATE**: Count enumerated vs processed. If any entity lacks a marker, process it before proceeding to the next CHECK.

## CHECK 1: Boundary Operator Precision

For EVERY comparison operator in validation logic (`require`, `if`, `assert`, modifiers):

| Location | Expression | Operator | Should Be | Off-by-One? |
|----------|-----------|----------|-----------|-------------|

**Methodology**:
- For each `>` ask: should this be `>=`? What happens at the exact boundary value?
- For each `<` ask: should this be `<=`? What happens at the exact boundary value?
- For each `==` in a range check: does it exclude a valid boundary?
- For timestamp comparisons: does `>` vs `>=` on `block.timestamp` create a 1-block window where the check fails?

**Concrete test**: Substitute the boundary value into the expression. Does the function behave correctly AT the boundary? If the boundary value should be valid but the operator rejects it (or vice versa), flag it.

Only flag findings where the off-by-one produces a CONCRETE impact (DoS, fund lock, bypass). Do NOT flag stylistic preferences.
Also check: for each `while`/`for` loop with accumulator variables, verify ALL accumulators are updated per iteration. A loop that increments one counter but not a co-dependent tracking variable produces double-counting on subsequent iterations.

## CHECK 2: Validation Reachability

For EVERY validation check (require/revert/assert) in a function:

| Function | Validation | Can Be Bypassed Via Alternative Path? | Bypass Path |
|----------|-----------|---------------------------------------|-------------|

**Methodology**:
- Trace ALL callers of each function (use call graph from function_list.md)
- For each validation: is there an alternative code path that reaches the same state change WITHOUT this validation?
- Check: can a multi-step sequence (deposit then partial withdraw, split then merge, etc.) skip a validation that a single-step path enforces?
- Check: do internal functions assume a validation was applied by the caller, but some callers skip it?

**Concrete test**: For each validation, enumerate the function(s) that call the validated function. Does every caller satisfy the precondition, or can some callers reach the protected code without the check?

## CHECK 3: Guard Coverage Completeness

For EVERY modifier or access control guard applied to at least one function:

| Guard/Modifier | Applied To | NOT Applied To (same state writes) | Missing? |
|---------------|-----------|--------------------------------------|----------|

**Methodology**:
- For each modifier (e.g., `nonReentrant`, `whenNotPaused`, `onlyRole(X)`), list ALL functions it protects
- Identify ALL other functions that write to the SAME state variables
- If any function writes to the same state but lacks the guard â†’ flag as potential gap
- For access-controlled write functions: check if there is a permissionless function that achieves the same state mutation through a different path

**Concrete test**: If `functionA` has `onlyOperator` and writes `stateVar`, and `functionB` also writes `stateVar` but has no access control, that is a guard gap.

## CHECK 4: Cross-Contract Action Parity

For each user-facing action verb (stake, withdraw, claim, exit, getReward):

| Action | Contract A | Protection | Contract B | Has Same Protection? | Gap? |
|--------|-----------|------------|-----------|---------------------|------|

**Methodology**:
- Enumerate ALL contracts that expose a function for this user action
- For each pair, compare: access control, timing guards (delays, cooldowns), reentrancy guards, state validation
- If Contract A has a protection that Contract B lacks for the SAME user action â†’ flag

**Concrete test**: If `ContractA.withdraw()` checks `block.number >= lastActionBlock + delay` but `ContractB.withdraw()` has no such delay for the same economic action, that is a parity gap.

## CHECK 5: External Call Parameter Validation

For EVERY external call that passes user-supplied or caller-controlled parameters:

| Function | External Call | Parameter Source | Validated? | What's Unvalidated? |
|----------|-------------|-----------------|-----------|-------------------|

**Methodology**:
- For each external call, trace parameters backward to their source
- If any parameter comes from msg.sender input (function args, calldata, structs) WITHOUT validation, flag it
- Special focus: struct parameters passed through to external protocols - are ALL fields validated?
- Common pattern: `swap(FundManagement memory funds)` where `funds.recipient` is caller-controlled and passed directly to external DEX

**Concrete test**: Can the caller set parameter X to an attacker-controlled value that redirects funds, changes swap direction, or modifies the recipient of external call outputs?

**Struct field enumeration**: For every struct parameter passed to an external call:
1. List ALL fields of the struct by reading the struct definition
2. For each field: trace backward to its source (caller input, storage, computed)
3. For each field sourced from caller input: is it validated? Document:

| Struct | Field | Source | Validated? | Impact if Attacker-Controlled |
|--------|-------|--------|-----------|-------------------------------|

**Common missed pattern**: `swap(FundManagement memory funds)` where `funds.recipient`
or `funds.sender` is caller-supplied and passed directly to external DEX without validation.

**Untrusted call target check**: For every `InterfaceName(addr).function()` call where `addr` is decoded from calldata, function parameters, or user-supplied structs:
1. Is `addr` validated against a registry, factory, or known-good set BEFORE being called?
2. If NOT validated: the call target is attacker-deployable. All return values from the call are UNTRUSTED " an attacker can deploy a contract implementing the expected interface that returns arbitrary values to bypass validation logic.
3. For each untrusted return value: trace how it is used downstream. If it gates access control, token movement, or accounting â†’ FINDING (High if funds at risk, Medium if DoS only).

## CHECK 6: Helper Function Call-Site Parity

For EVERY internal helper that transforms values (normalization, scaling, encoding, formatting):

| Helper Function | Purpose | Call Sites | Consistent Usage? | Missing/Inconsistent Site |
|----------------|---------|-----------|-------------------|--------------------------|

**Methodology**:
- Grep for ALL call sites of each helper (normalize, denormalize, scale, unscale, toWei, fromWei, toShares, toAssets, encodeX, decodeX, or any protocol-specific transform pair)
- For each PAIR of inverse helpers (normalize/denormalize, encode/decode): verify every value that passes through one also passes through its inverse at the appropriate point
- For each call site: does it apply the helper to the same variable type with the same parameters as other call sites?
- Flag: a value that is normalized at entry but not denormalized at exit (or vice versa)
- Flag: a helper called with different parameters at different sites when the same parameters are expected
- For paired operations that share state (create/consume, deposit/refund, lock/unlock, open/close): if either operation transforms an input before use, verify the paired operation applies the same transformation at the same logical point - not later, not earlier, not skipped

**Concrete test**: If `normalizeAmount(amount, decimals)` is called at 3 deposit sites but `denormalizeAmount(amount, decimals)` is called at only 2 of 3 corresponding withdrawal sites, the missing site produces values at the wrong scale.

## CHECK 7: Write Completeness for Accumulators (uses pre-computed invariants)

Read `{SCRATCHPAD}/semantic_invariants.md` (pre-computed by Phase 4a.5 agent). For each variable with POTENTIAL GAP flagged:

| Variable | Flagged Gap | Confirmed? | Finding? |
|----------|-----------|-----------|----------|

Verify each flagged gap: does the value-changing function actually modify the tracked value without updating the variable? Filter false positives (e.g., view-only reads, functions that indirectly trigger an update elsewhere). Confirmed gaps â†’ FINDING.

## CHECK 8: Conditional Branch State Completeness

For EVERY state-modifying function that contains an if/else or early return:

| Function | Branch Condition | State Written in TRUE Branch | State Written in FALSE Branch | Asymmetry? |
|----------|-----------------|-----------------------------|-----------------------------|------------|

**Methodology**:
- For each conditional branch in a state-modifying function, enumerate ALL state writes in the TRUE path
- Enumerate ALL state writes in the FALSE path (including the implicit "nothing happens" path for early returns)
- If a state variable is written in one branch but NOT the other, and both branches represent valid execution paths (not error/revert) â†’ flag as potential stale state
- Special focus: functions where fee accrual, timestamp updates, or checkpoint writes are inside a conditional block but downstream consumers assume they always executed
- Special focus: functions where a "pause" or "skip" branch updates timestamps/counters but NOT accumulators, or vice versa

**Concrete test**: If `functionA` writes `lastUpdate = now` inside an `if (amount > 0)` block, what value does `lastUpdate` retain when `amount == 0`? Trace all consumers of `lastUpdate` - do they produce correct results with the stale value?

Tag: [TRACE:branch=false â†’ stateVar={old_value} â†’ consumer computes {wrong_result}]

## CHECK 9: Validation Semantic Adequacy

For EVERY validation that protects against value loss (slippage checks, balance thresholds, minimum output assertions):

| Validation | What It Measures | What It Should Measure | Match? |
|-----------|-----------------|----------------------|--------|

**Classification** " for each validation, determine:
- Does it check ABSOLUTE state (total balance) or RELATIVE change (delta per operation)?
- Does it check AGGREGATE result (batch total) or PER-ITEM result (individual operation)?
- Does it check a PROXY metric (correlated value) or the DIRECT metric (actual value at risk)?

If the validation uses absolute/aggregate/proxy AND the protected operation is per-item or requires delta measurement â†’ FINDING: validation measures the wrong granularity. A batch of operations where each individually loses value but the aggregate stays flat (cross-subsidized by profitable operations or prior balance) passes an aggregate check but fails a per-item check.

**Coverage assertion**: Before returning, verify every entity enumerated under each CHECK has been processed. Report enumerated vs analyzed counts in your return message.

## SELF-CONSISTENCY CHECK (MANDATORY before output)

For each finding you produce: if your own analysis identifies that the missing pattern/modifier/guard is FUNCTIONALLY REQUIRED to be absent (e.g., adding it would cause reverts, break composability, or make the function unreachable), your verdict MUST be REFUTED, not CONFIRMED with caveats. A finding that says "X is missing" and also explains "adding X would break Y" is self-contradictory - resolve the contradiction before outputting.

## Output
Write to {SCRATCHPAD}/validation_sweep_findings.md:

### Sweep Summary
| Check | Functions Scanned | Findings | False Positives Filtered |
|-------|------------------|----------|-------------------------|

### Findings
Use finding IDs [VS-1], [VS-2], etc. with standard finding format.
For each finding, include:
- The exact code location and operator/validation/guard
- The concrete impact (not just 'could be wrong')
- Whether any existing finding in findings_inventory.md already covers this

Maximum 12 findings (prioritize by impact). Filter out findings already covered by breadth agents.

## Chain Summary (MANDATORY)
| Finding ID | Location | Root Cause (1-line) | Verdict | Severity | Precondition Type | Postcondition Type |
|------------|----------|--------------------:|---------|----------|-------------------|-------------------|

Return: 'DONE: {N} functions swept, {M} boundary issues, {K} reachability gaps, {J} guard gaps, {P} parity gaps, {Q} parameter validation gaps, {R} helper parity gaps, {S} conditional branch gaps'
")
```

---

## Sibling Propagation Agent

> **Trigger**: Always runs IN PARALLEL with Validation Sweep (iteration 1 only).
> **Purpose**: Propagate confirmed root cause patterns to sibling functions. Extracted from Validation Sweep to avoid positional attention degradation (was CHECK 9 of 9 " highest cognitive load in worst attention position).
> **Budget**: Scanner-tier (part of fixed base count, not depth budget).

```
Task(subagent_type="general-purpose", model="sonnet", prompt="
You are the Sibling Propagation Agent. For each Medium+ CONFIRMED or PARTIAL finding, you search the entire codebase for sibling functions exhibiting the SAME root cause pattern.

## Your Inputs
Read:
- {SCRATCHPAD}/findings_inventory.md (all findings with verdicts)
- Source files for all in-scope contracts

## Methodology

For each Medium+ CONFIRMED or PARTIAL finding in findings_inventory.md:

1. Extract the ROOT CAUSE PATTERN in one sentence (e.g., 'state variable updated inside conditional block that can be skipped', 'paired operation asymmetry between deposit/withdraw paths')
2. Grep ALL other functions AND contracts in scope for the SAME pattern (same variable types, same code structure, same operation sequence). Sweep EVERY other in-scope contract/sibling, not just sibling functions in the same contract — a repeat instance left unreported is an audit miss.
3. For each sibling function found: does it exhibit the SAME bug?
4. If YES and no existing finding covers it â†’ new finding [SP-N]

| Finding | Root Cause Pattern | Sibling Functions | Same Bug? | New Finding? |
|---------|-------------------|-------------------|-----------|-------------|

## Output
Write to {SCRATCHPAD}/sibling_propagation_findings.md
Use finding IDs [SP-1], [SP-2], etc. with standard finding format.
Maximum 8 findings " prioritize by severity.

## Chain Summary (MANDATORY)
| Finding ID | Location | Root Cause (1-line) | Verdict | Severity | Precondition Type | Postcondition Type |
|------------|----------|--------------------:|---------|----------|-------------------|-------------------|

Return: 'DONE: {N} root cause patterns extracted, {M} sibling functions found, {K} new findings'
")
```

---

## Design Stress Testing Agent (Budget Redirect)

> **Trigger**: `remaining_budget >= 3` at adaptive loop exit.
> **Purpose**: System-level design analysis that per-function agents miss. Checks design limits, Rule 13 adequacy, and Rule 14 constraint coherence.
> **Budget**: Counts as 1 budget unit.

```
Task(subagent_type="general-purpose", prompt="
You are the Design Stress Testing Agent. You analyze protocol-level design limits and constraint coherence,
NOT individual function bugs. Per-function analysis was done by depth and breadth agents - your job is
system-level design review.

## Your Inputs
Read:
- {SCRATCHPAD}/constraint_variables.md
- {SCRATCHPAD}/function_list.md
- {SCRATCHPAD}/attack_surface.md
- {SCRATCHPAD}/findings_inventory.md (avoid duplicates with existing findings)

## CHECK 1: Design Limit Stress
For each bounded parameter (max array length, max users, capacity limits, max validators, max pools):

| Parameter | Design Limit | At Limit: Behavior | Admin Usable? | Gas at Limit | Block Limit OK? |
|-----------|-------------|-------------------:|-------------|-------------|----------------|

1. What happens AT the design limit? (OOG? infinite loop? graceful degradation? revert?)
2. Are administrative functions still usable at design limit? (emergency withdraw, pause, parameter update)
3. Gas cost at limit vs block gas limit - does any function become uncallable?
Tag: [BOUNDARY:param=MAX_VALUE â†’ outcome]

## CHECK 2: Rule 13 Design Adequacy
For each user-facing function:

| Function | Stated Purpose | Fulfills Completely? | User States Without Exit? | Gap Description |
|----------|---------------|---------------------|--------------------------|-----------------|

1. Does it fulfill its stated purpose COMPLETELY? (e.g., `emergencyWithdraw` that only handles LP tokens but not individual deposits)
2. Are there user states with no exit path? (deposited but cannot withdraw, staked but cannot unstake)
3. Does the function name promise something the implementation does not deliver?
If incomplete â†’ FINDING (Rule 13, design gap)

## CHECK 3: Constraint Coherence (Rule 14)
For each pair of independently-settable limits in constraint_variables.md:

| Limit A | Limit B | Mathematical Relationship Required? | Enforced On-Chain? | What Breaks if Desync? |
|---------|---------|------------------------------------:|-------------------|----------------------|

1. Must they satisfy a mathematical relationship for correctness? (e.g., `globalCap >= sum(localCaps)`, `maxTotal == sum(maxPerCategory)`)
2. Can one be changed via setter without updating the other?
3. Trace what breaks if desynchronized: infinite loops, underflows, bypasses, wasted gas
Tag: [TRACE:limitA=X, limitB=Y â†’ outcome at L{N}]

## CHECK 4: Yield/Reward Timing Fairness
For each yield distribution, reward streaming, or vesting mechanism:

| Mechanism | Distribution Event | Entry Window | Sandwich Possible? | Fairness Gap? |
|-----------|-------------------|-------------|-------------------|--------------|

1. Can a user deposit IMMEDIATELY BEFORE a yield/reward distribution and capture a disproportionate share?
2. Is there a cooldown, lock period, or time-weighted balance that prevents sandwich timing attacks?
3. For streaming/vesting: can a user enter AFTER streaming starts but before it ends and capture already-vested gains at the current (inflated) share price?
4. For multi-step distributions (vest â†’ claim â†’ transfer): can timing between steps be exploited?
5. Trace: if user deposits at T, distribution occurs at T+1 block, user withdraws at T+2 - what is the user's profit vs a user who was deposited for the full period? If disproportionate â†’ FINDING

Tag: [TRACE:deposit_at=T, distribution_at=T+1, withdraw_at=T+2 â†’ profit={X} vs long_term_user={Y} â†’ fairness_ratio={Z}]

## Output
Write to {SCRATCHPAD}/design_stress_findings.md:
- Maximum 8 findings [DST-1] through [DST-8]
- Use standard finding format with Depth Evidence tags ([BOUNDARY:*], [TRACE:*])

## Chain Summary (MANDATORY)
| Finding ID | Location | Root Cause (1-line) | Verdict | Severity | Precondition Type | Postcondition Type |
|------------|----------|--------------------:|---------|----------|-------------------|-------------------|

Return: 'DONE: {N} design stress findings'
")
```
