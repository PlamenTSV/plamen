# Phase 4b: Scanner & Sweep Templates -- Sui Move

> **Usage**: Orchestrator reads this file to spawn the 3 Blind Spot Scanners, Validation Sweep Agent, and Design Stress Testing Agent in iteration 1.
> Replace placeholders `{SCRATCHPAD}`, etc. with actual values.

---

## Blind Spot Scanner A: Tokens & Parameters

> **Trigger**: Always runs IN PARALLEL with depth agents (iteration 1 only).
> **Purpose**: Check what breadth agents missed in Coin<T>/Balance<T>/object-with-store coverage and parameter analysis.

```
Task(subagent_type="general-purpose", prompt="
You are Blind Spot Scanner A for a Sui Move audit. Find what breadth agents NEVER LOOKED AT for tokens and parameters.

## Your Inputs
Read:
- {SCRATCHPAD}/attack_surface.md (Token/Coin Mapping, Object Inventory Matrix)
- {SCRATCHPAD}/findings_inventory.md (what WAS analyzed)
- {SCRATCHPAD}/constraint_variables.md (admin-settable parameters)

## CHECK 1: External Coin<T> / Object with `store` Coverage
Cross-reference attack_surface.md Token/Coin Mapping against findings_inventory.md:

For each external coin type or object with `store` the protocol handles:
| External Coin<T> / Object | Analyzed by Agent? | Finding IDs | Dimensions Covered (R11) | Missing Dimensions |
|---------------------------|-------------------|-------------|--------------------------|-------------------|

If ANY external coin/object type has 0 findings AND is transferable to the protocol -> BLIND SPOT.
If ANY external coin/object type has findings covering <=2 of 5 R11 dimensions AND uncovered dimensions are applicable -> PARTIAL BLIND SPOT.

**Sui note**: Unlike EVM, unsolicited coins arrive as separate objects and must be explicitly joined via `coin::join`. However, `transfer::public_transfer` can send any `Coin<T>` (which has `store`) to any address without recipient consent. Objects with `store` ability can also be transferred unsolicited.

**Dimension coverage gate**: For each coin/object type with >=1 finding, verify coverage breadth:

| External Coin<T> / Object | R11-D1: Transferability (unsolicited `transfer::public_transfer` of Coin<T> or objects with `store`) | R11-D2: Accounting (Balance<T> value vs internal tracking discrepancy, phantom coin injection) | R11-D3: Op Blocking (external module abort causing transaction failure) | R11-D4: Collection Growth (iteration over coin objects, vector/dynamic field bloat from token entries) | R11-D5: Side Effects (object ownership transfers, dynamic field changes, event emissions on transfer/join/split) | Dimensions Covered |
|---------------------------|------------------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------|-----------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------|--------------------|

If ANY coin/object type has findings covering <=2 of 5 dimensions AND the uncovered dimensions are applicable -> PARTIAL BLIND SPOT.
Applicable = the coin/object type supports that interaction (e.g., frozen/soul-bound objects without `store` do not have D1:Transferability risk; `Balance<T>` inside owned objects without `store` cannot be transferred unsolicited; objects without collection semantics may not have D4 risk).

## CHECK 2: Capability-Gated Parameter Coverage
From constraint_variables.md, for each parameter with a setter function:

| Parameter | Setter Function | Required Capability | Can Affect Active Operations? | Analyzed by Agent? | Finding ID |
|-----------|----------------|-------------------|-------------------------------|-------------------|------------|

**Apply Rule 13**: For each parameter change, model BOTH directions:
- Parameter INCREASES: who is harmed?
- Parameter DECREASES: who is harmed?
- If either direction harms users AND no finding covers it -> BLIND SPOT

## Output
- Maximum 5 findings [BLIND-A1] through [BLIND-A5]
- Use standard finding format
- Note WHY breadth agents likely missed each

## Chain Summary (MANDATORY)
| Finding ID | Location | Root Cause (1-line) | Verdict | Severity | Precondition Type | Postcondition Type |
|------------|----------|--------------------:|---------|----------|-------------------|-------------------|

Write to {SCRATCHPAD}/blind_spot_A_findings.md

Return: 'DONE: {N} blind spots -- Check1: {A} token gaps, Check2: {B} parameter gaps'
")
```

---

## Blind Spot Scanner B: Guards, Visibility & Package Dependencies

> **Trigger**: Always runs IN PARALLEL with depth agents (iteration 1 only).
> **Purpose**: Check what breadth agents missed in access control, function visibility, package dependency completeness, upgrade safety, and object ownership classification.

```
Task(subagent_type="general-purpose", prompt="
You are Blind Spot Scanner B for a Sui Move audit. Find what breadth agents NEVER LOOKED AT for guards, visibility, and package dependencies.

## Your Inputs
Read:
- {SCRATCHPAD}/findings_inventory.md (what WAS analyzed)
- {SCRATCHPAD}/function_list.md (complete function inventory)
- {SCRATCHPAD}/state_variables.md (all structs and their abilities)
- {SCRATCHPAD}/modifiers.md (access control / guard map)

## CHECK 3: Capability-Gated Function Griefability (Rule 2)
From function_list.md, for each function requiring a capability reference (&AdminCap, &OwnerCap, &TreasuryCap, etc.) or sender-address check (`tx_context::sender(ctx) == ...`):

| Capability Function | Preconditions (assert! checks) | User-Manipulable? | Analyzed by Agent? | Finding ID |
|--------------------|-------------------------------|-------------------|-------------------|------------|

If precondition reads shared object state that users can modify AND no finding covers it -> BLIND SPOT.

Sui-specific griefability vectors:
- Shared object state that the capability-gated function reads can be modified by any transaction touching that shared object
- Balance thresholds in shared objects can be manipulated via deposits/withdrawals before the admin tx executes
- PTB composition allows users to set up state immediately before the admin's function runs (within the same checkpoint)
- Object version changes: any mutation of a shared object increments its version, which can cause equivocation-based griefing if admin transactions depend on a specific version

## CHECK 4: Visibility Audit (`public` vs `public(package)` vs `entry`)
From function_list.md, for each function:

| Function | Module | Visibility | Emits Events? | Modifies Shared State? | Should Be More Restricted? | Analyzed? |
|----------|--------|-----------|---------------|----------------------|--------------------------|-----------|

**Checks**:
- `public` functions that modify critical state: should they be `public(package)` or `entry` instead? `public` functions cannot be removed in `compatible` package upgrades and can be called by any external package via PTBs.
- `entry` functions that return values consumed by other protocol functions: should they be `public` instead? (`entry` cannot be called by other Move code, only from PTB transaction commands directly)
- Functions that should clearly be private but are `public(package)` or `public` -> flag
Also flag: `public` or `entry` functions that emit events but have NO access control AND do NOT modify meaningful state -- these allow anyone to forge events that mislead off-chain indexers and UIs.
Also flag: any admin-gated function that modifies shared objects but does NOT emit an event. Admin parameter changes without events are unmonitorable.
- `public` functions with no external callers (no other package calls them) -> recommend `public(package)` for upgrade flexibility
- `public` functions that should be `entry` only to prevent PTB composition (e.g., functions that rely on being the only operation in a transaction for security)

Flag if: function visibility is over-exposed AND no finding covers it.

## CHECK 5: Package Dependency Capability Completeness
From external_interfaces.md and Move.toml dependencies:

| Dependency | Source | Version Pinned? | Upgrade Policy (if known) | Functions Used | Configuration Accessible? | Finding ID |
|-----------|--------|----------------|--------------------------|---------------|--------------------------|------------|

**Checks**:
- Dependencies without `rev` pinning (floating git deps) -> BLIND SPOT (upstream changes can break protocol)
- Dependencies on packages with known `compatible` upgrade policy -> HIGH RISK (implementation of `public` functions can change behavior)
- Dependencies importing `public` functions that the upstream package may modify semantics of during upgrade
- Protocol using `public(package)` functions from a dependency it does not control -> if dependency upgrades, those functions may be removed or changed
- For each imported package, check if needed configuration capabilities are exposed. If the protocol depends on behavior configured by the dependency's admin, but has no way to respond to configuration changes -> flag

Also flag: dependency that has a CONFIGURABLE PARAMETER the protocol relies on but cannot control. If the dependency changes that parameter via its own admin, the protocol's behavior changes without its knowledge.

## CHECK 5b: Package Upgrade Safety

For each package in scope and each dependency:

| Package | Upgrade Policy | Public Functions | Behavioral Contracts | Risk if Upgraded |
|---------|---------------|-----------------|---------------------|-----------------|

**Check**:
- Does upgrading the package change behavior of `public` functions that other packages depend on? (Under `compatible` policy, function signatures are preserved but implementations can change)
- Are there `public` functions whose behavioral contracts are implicitly relied upon by dependents? (e.g., a `public` function that currently reverts on zero input -- dependents may rely on this, but an upgrade could remove the revert)
- Does the upgrade policy (`compatible`, `additive`, `immutable`) match the risk profile?
  - `immutable`: safest -- no upgrades possible, behavior is permanent
  - `additive`: new modules/functions can be added but existing cannot change -- moderate risk
  - `compatible`: existing function implementations CAN change -- highest risk for dependents
- Are there `public(package)` functions that should be `public` so external dependents can access them? Or vice versa?
- If the protocol is upgradeable: does upgrading break invariants that users or downstream packages rely on? (e.g., adding a new field to a shared object struct, changing abort codes, modifying event schemas)

## CHECK 5c: Object Ownership Model Audit

For each object type in the protocol:

| Object Type | Current Ownership | Should Be | Justification | Finding? |
|-------------|------------------|-----------|---------------|----------|

**Check**:
- For each **shared object**: should it be owned instead?
  - Shared objects have consensus overhead and contention risk
  - If only one entity (admin, protocol) ever mutates it, owned is cheaper and prevents griefing
  - If shared for read-only access: consider if the data could be stored in an immutable object or emitted as events
- For each **owned object**: should it be shared instead?
  - If multiple users need to mutate the same object, owned objects create a bottleneck (only the owner can submit transactions with it)
  - If the owner needs to coordinate with other users (e.g., user receipts that the protocol must redeem), owned objects force a two-step flow where shared would be simpler
- For each **object with `store`**: is the `store` ability intentional?
  - `store` allows the object to be wrapped inside other objects or transferred via `public_transfer`
  - If the protocol does not intend for the object to be transferable or wrappable, `store` is over-permissive
  - AdminCap/OwnerCap with `store` can be transferred to anyone; without `store`, only the module that defines it can transfer it (via `transfer::transfer`)
- For each **object used in dynamic fields**: should it be a standalone object instead?
  - Dynamic fields are not discoverable via standard indexing unless explicitly queried
  - If users need to enumerate or discover these objects, standalone objects with events are more appropriate

Misclassified ownership is a Sui-specific blind spot that breadth agents typically miss because they focus on function logic, not object model design.

## Output
- Maximum 5 findings [BLIND-B1] through [BLIND-B5]
- Use standard finding format
- Note WHY breadth agents likely missed each

## Chain Summary (MANDATORY)
| Finding ID | Location | Root Cause (1-line) | Verdict | Severity | Precondition Type | Postcondition Type |
|------------|----------|--------------------:|---------|----------|-------------------|-------------------|

Write to {SCRATCHPAD}/blind_spot_B_findings.md

Return: 'DONE: {N} blind spots -- Check3: {A} capability-gated gaps, Check4: {B} visibility gaps, Check5: {C} dependency gaps, Check5b: {D} upgrade safety gaps, Check5c: {E} ownership model gaps'
")
```

---

## Blind Spot Scanner C: Role Lifecycle, Capability Exposure & Reachability

> **Trigger**: Always runs IN PARALLEL with depth agents (iteration 1 only).
> **Purpose**: Check what breadth agents missed in capability lifecycle, exposed/unexposed functionality, and function reachability.

```
Task(subagent_type="general-purpose", prompt="
You are Blind Spot Scanner C for a Sui Move audit. Find what breadth agents NEVER LOOKED AT for capability lifecycle, capability exposure, and function reachability.

## Your Inputs
Read:
- {SCRATCHPAD}/findings_inventory.md (what WAS analyzed)
- {SCRATCHPAD}/function_list.md (complete function inventory)
- {SCRATCHPAD}/modifiers.md (access control / guard map)
- {SCRATCHPAD}/state_variables.md (all structs and abilities)
- Source files for all in-scope modules

## CHECK 6: Capability Lifecycle Completeness

For each capability type identified in the codebase (AdminCap, OwnerCap, TreasuryCap, Publisher, UpgradeCap, custom capabilities):

| Capability Type | Abilities | Create Function | Transfer/Share? | Revoke/Destroy Function | Revoke Exists? | Circular Dep? | Finding? |
|----------------|-----------|----------------|-----------------|------------------------|---------------|--------------|----------|

**Methodology**:
- For each capability created in `init()`, constructor, or admin function: does a corresponding `destroy`/`burn`/revoke function exist?
- If NO revocation/destruction function exists AND capability has `store` (can be transferred via `public_transfer`) -> FINDING: irrevocable transferable capability (minimum Medium if capability modifies user-facing state)
- If capability has `key` without `store`: the module can still transfer it via `transfer::transfer` internally, but external holders cannot transfer it. Check: is there a module function that transfers the capability? If not, it is permanently bound to the initial recipient.
- Check for circular dependencies: does revoking Capability A require holding Capability B, and creating Capability B require Capability A?
- Check: can a capability holder block their own removal? (e.g., admin can pause via the capability, and revocation function checks that the protocol is not paused)
- Check: is `TreasuryCap` properly protected? Can it be used to mint unlimited tokens? Is it shared (dangerous) or owned?
- Check: is `UpgradeCap` properly handled? If stored in a shared object, can anyone trigger an upgrade? If `store` ability is present, can it be extracted and transferred?
- AdminCap without `store` cannot be transferred externally but also cannot be recovered if the owner loses access -- flag this tradeoff if not documented

## CHECK 7: Unexposed Module Capabilities

For each module in scope:

| Module | Internal Function | Purpose | Called by Any Public/Entry Function? | Externally Reachable? | Gap? |
|--------|------------------|---------|--------------------------------------|----------------------|------|

**Methodology**:
- List ALL private (non-public, non-entry) functions in each module
- For each: is there a public/entry function in the same module that exposes this capability?
- If a module has a private function for critical configuration (e.g., `set_oracle_price`, `update_fee_rate`, `mint_reward`) but no public/entry function calls it -> FINDING: unreachable capability post-deployment
- Severity: Medium if the unreachable function controls a parameter that affects protocol correctness; Low if convenience only
- Special check: functions that SET parameters on shared objects -- if no public/entry path to call them, the parameter is permanently locked to its initial value
- For `public(package)` functions: check if the package boundary correctly limits access. Are there `public(package)` functions that perform dangerous operations (capability creation, shared object mutation) but are accessible from other modules in the same package that have `public` wrappers with insufficient validation?

## CHECK 8: Function Reachability Audit

For each public and entry function in all in-scope modules:

| Function | Module | Visibility | Called By (internal) | Called By (external/test) | Reachable in Production? | Dead Code? |
|----------|--------|-----------|---------------------|--------------------------|-------------------------|------------|

**Methodology**:
- Trace callers for each function using function_list.md and source grep
- Identify functions that are defined but NEVER called by any other in-scope module or expected external caller
- For dead code with security implications: does the dead function modify shared objects? Could it be called by anyone if discovered?
  - `public` functions: callable by ANY external package -- highest risk if dead but state-modifying
  - `entry` functions: callable directly from transactions -- moderate risk
  - `public(package)` functions: callable only from same package -- lower risk but still reachable from package modules
- Special focus: `public` functions that are dead code -> these are callable by ANY external package even if the protocol never uses them. If they modify state -> potential backdoor or forgotten artifact.
- Flag: `public` functions with no callers that modify critical shared state -> potential unintended entry point
- Flag: `entry` functions that appear to be for testing only (references to test scenarios, test addresses, `#[test_only]` logic patterns) but are NOT marked `#[test_only]` and are included in production code
- Flag: `public` functions that should be `entry` only -- functions that are meant to be called directly by users but not composed within PTBs. If a function's security relies on being the sole operation (e.g., it checks balances before and after), making it `public` allows PTB composition that may break this assumption.

## Output
- Maximum 8 findings [BLIND-C1] through [BLIND-C8]
- Use standard finding format
- Note WHY breadth agents likely missed each

## Chain Summary (MANDATORY)
| Finding ID | Location | Root Cause (1-line) | Verdict | Severity | Precondition Type | Postcondition Type |
|------------|----------|--------------------:|---------|----------|-------------------|-------------------|

Write to {SCRATCHPAD}/blind_spot_C_findings.md

Return: 'DONE: {N} blind spots -- Check6: {A} capability lifecycle gaps, Check7: {B} capability exposure gaps, Check8: {C} reachability gaps'
")
```

---

## Validation Sweep Agent

> **Trigger**: Always runs IN PARALLEL with the 4 depth agents and Blind Spot Scanners (iteration 1 only).
> **Purpose**: Mechanical sweep of ALL validation logic for specific deficit patterns that reasoning-based agents consistently miss: boundary operator precision, validation reachability gaps, guard coverage completeness, cross-module action parity, external call parameter validation, object type verification, and helper function call-site parity.

```
Task(subagent_type="general-purpose", prompt="
You are the Validation Sweep Agent for a Sui Move audit. You perform mechanical checks across every function in scope. You do NOT analyze business logic or economic attacks -- you check that existing validation code is correct, reachable, and complete.

## INPUT FILTERING
When cross-referencing against findings_inventory.md, focus on Medium+ severity findings only. Low/Info findings do not need cross-validation sweeps -- the attention cost of processing 50+ findings outweighs the marginal value of sweeping Low/Info patterns.

## Your Inputs
Read:
- {SCRATCHPAD}/function_list.md (complete function inventory)
- {SCRATCHPAD}/findings_inventory.md (what was already found -- avoid duplicates)
- {SCRATCHPAD}/modifiers.md (access control / guard map)
- Source files for all in-scope modules

## CHECK 1: Boundary Operator Precision

For EVERY comparison operator in validation logic (`assert!`, `if` conditions, conditional `abort`):

| Location | Expression | Operator | Should Be | Off-by-One? |
|----------|-----------|----------|-----------|-------------|

**Methodology**:
- For each `>` ask: should this be `>=`? What happens at the exact boundary value?
- For each `<` ask: should this be `<=`? What happens at the exact boundary value?
- For each `==` in a range check: does it exclude a valid boundary?
- For timestamp comparisons using `clock::timestamp_ms()`: does `>` vs `>=` create a window at the exact millisecond where the check fails?
- For bit-shift operations: does the bounds check use `<` vs `<=` vs `< bit_width`? (shift amount must be STRICTLY less than type bit-width in Move)
- For u64/u128 arithmetic: does the check prevent overflow at `MAX_U64` or `MAX_U128`? Does `>=` vs `>` at the boundary cause an arithmetic overflow on the next operation?

**Concrete test**: Substitute the boundary value into the expression. Does the function behave correctly AT the boundary? If the boundary value should be valid but the operator rejects it (or vice versa), flag it.

Only flag findings where the off-by-one produces a CONCRETE impact (DoS via abort, fund lock, bypass). Do NOT flag stylistic preferences.
Also check: for each `while`/`for` loop with accumulator variables, verify ALL accumulators are updated per iteration. A loop that increments one counter but not a co-dependent tracking variable produces double-counting on subsequent iterations.

## CHECK 2: Validation Reachability

For EVERY validation check (assert!/abort) in a function:

| Function | Validation | Can Be Bypassed Via Alternative Path? | Bypass Path |
|----------|-----------|---------------------------------------|-------------|

**Methodology**:
- Trace ALL callers of each function (use call graph from function_list.md)
- For each validation: is there an alternative code path that reaches the same state change WITHOUT this validation?
- Check: can a multi-step sequence (deposit then partial withdraw, split then merge, etc.) skip a validation that a single-step path enforces?
- Check: do private functions assume a validation was applied by the public/entry caller, but some callers skip it?
- Sui-specific: Can a PTB compose multiple entry-point calls to bypass validation? (e.g., function A validates, function B does not but achieves the same state change; or function A validates at the start but function B modifies the validated state within the same PTB before function A uses it)

**Concrete test**: For each validation, enumerate the function(s) that call the validated function. Does every caller satisfy the precondition, or can some callers reach the protected code without the check?

## CHECK 3: Guard Coverage Completeness

For EVERY capability guard or `assert!` pattern applied to at least one function:

| Guard/Capability | Applied To | NOT Applied To (same state writes) | Missing? |
|-----------------|-----------|--------------------------------------|----------|

**Methodology**:
- For each capability guard (e.g., `&AdminCap`, `&TreasuryCap`, sender == address check), list ALL functions it protects
- Identify ALL other functions that write to the SAME shared objects or state fields
- If any function writes to the same state but lacks the guard -> flag as potential gap
- For capability-controlled write functions: check if there is a permissionless function that achieves the same state mutation through a different path
- Sui-specific: Check that `public(package)` functions called by `public` wrappers maintain the same guard level. A `public` function that calls a `public(package)` function effectively escalates the access of the package-private function.
- Sui-specific: For shared object mutation guards -- who can mutate which shared objects? If a shared object's field is written by both a capability-gated function and a permissionless function, that is a guard gap even if they write different fields (the shared object version changes in both cases).

**Concrete test**: If `admin_set_fee(&AdminCap, pool, fee)` writes `pool.fee_rate` and `permissionless_swap(pool)` also modifies state based on `pool.fee_rate` in a way that effectively changes the fee outcome, that is NOT a guard gap (the permissionless function reads, not writes, the admin-set value). But if `another_function(pool)` WRITES to `pool.fee_rate` without requiring `&AdminCap`, THAT is a guard gap.

## CHECK 4: Cross-Module Action Parity

For each user-facing action verb (deposit, withdraw, claim, stake, unstake, swap, redeem):

| Action | Module A | Protection | Module B | Has Same Protection? | Gap? |
|--------|----------|------------|----------|---------------------|------|

**Methodology**:
- Enumerate ALL modules that expose a function for this user action
- For each pair, compare: capability requirements, timing guards (epoch checks, timestamp cooldowns), state validation, abort conditions
- If Module A has a protection that Module B lacks for the SAME user action -> flag

**Concrete test**: If `module_a::withdraw(pool, receipt, clock)` checks `assert!(clock::timestamp_ms(clock) >= receipt.unlock_time, E_TOO_EARLY)` but `module_b::emergency_withdraw(pool, receipt)` has no such time check for the same economic action, that is a parity gap.

## CHECK 5: External Call Parameter Validation

For EVERY call to an external module that passes user-supplied or caller-controlled parameters:

| Function | External Call | Parameter Source | Validated? | What's Unvalidated? |
|----------|-------------|-----------------|-----------|-------------------|

**Methodology**:
- For each external module call, trace parameters backward to their source
- If any parameter comes from function arguments WITHOUT validation, flag it
- Special focus: struct parameters passed through to external modules -- are ALL fields validated?
- Common pattern: user-controlled address passed to external protocol that transfers assets to it

**Struct field enumeration**: For every struct parameter passed to an external call:
1. List ALL fields of the struct by reading the struct definition
2. For each field: trace backward to its source (function arg, shared object field, computed)
3. For each field sourced from function arg: is it validated? Document:

| Struct | Field | Source | Validated? | Impact if Attacker-Controlled |
|--------|-------|--------|-----------|-------------------------------|

**Common missed pattern**: Generic type parameter `T` passed to external module without `T` being constrained beyond ability bounds. Attacker may instantiate with a type that causes the external module to behave unexpectedly (e.g., a custom coin type with manipulated supply).

## CHECK 5c: Object Type Verification

For each function accepting a generic type parameter `T` or accepting objects by type:

| Function | Generic Parameter | Type Constraint | Verified Against Expected? | Impact if Wrong Type |
|----------|------------------|----------------|---------------------------|---------------------|

**Methodology**:
- For each function with generic `T`: does it verify `T` is the expected type? Can a PTB caller pass a different type that satisfies the ability constraints but is not the intended type?
- Common pattern: `public fun deposit<T>(pool: &mut Pool<T>, coin: Coin<T>)` -- if `Pool<T>` is a shared object, the type `T` is fixed at pool creation. But if the function creates a NEW object parameterized by `T`, the caller controls `T`.
- For functions that accept `&mut UID` or `ID` parameters: does the function verify the object type via dynamic field keys or type-tagged lookups? Can a caller pass an object ID of a different type that happens to have the right dynamic field?
- For witness pattern usage: does the function verify one-time-witness (OTW) properties? Can a non-OTW type satisfy the constraints?
- Flag: functions where type parameter `T` is used for coin operations but the function does not verify `T` matches the protocol's expected coin type stored in configuration

## CHECK 6: Helper Function Call-Site Parity

For EVERY internal helper that transforms values (normalization, scaling, encoding, formatting):

| Helper Function | Purpose | Call Sites | Consistent Usage? | Missing/Inconsistent Site |
|----------------|---------|-----------|-------------------|--------------------------|

**Methodology**:
- Grep for ALL call sites of each helper (normalize, denormalize, scale, unscale, to_shares, to_assets, encode, decode, mul_div, div_round_up, or any protocol-specific transform pair)
- For each PAIR of inverse helpers (e.g., `deposit_to_shares`/`shares_to_withdraw`): verify every value that passes through one also passes through its inverse at the appropriate point
- For each call site: does it apply the helper to the same variable type with the same parameters as other call sites?
- Flag: a value that is normalized at entry but not denormalized at exit (or vice versa)
- Flag: a helper called with different parameters at different sites when the same parameters are expected
- For paired operations that share state (create/consume, deposit/refund, lock/unlock, open/close): if either operation transforms an input before use, verify the paired operation applies the same transformation at the same logical point - not later, not earlier, not skipped

**Concrete test**: If `to_shares(amount, total_supply, total_assets)` is called at 3 deposit sites but `to_assets(shares, total_supply, total_assets)` is called at only 2 of 3 corresponding withdrawal sites, the missing site produces values at the wrong scale.

## CHECK 7: Write Completeness for Accumulators (uses pre-computed invariants)

Read `{SCRATCHPAD}/semantic_invariants.md` (pre-computed by Phase 4a.5 agent). For each variable with POTENTIAL GAP flagged:

| Variable | Flagged Gap | Confirmed? | Finding? |
|----------|-----------|-----------|----------|

Verify each flagged gap: does the value-changing function actually modify the tracked value without updating the variable? Filter false positives (e.g., view-only reads, functions that indirectly trigger an update). Confirmed gaps → FINDING.

## CHECK 8: Conditional Branch State Completeness

For EVERY state-modifying function that contains an if/else or early abort:

| Function | Branch Condition | State Written in TRUE Branch | State Written in FALSE Branch | Asymmetry? |
|----------|-----------------|-----------------------------|-----------------------------|------------|

**Methodology**:
- For each conditional branch in a state-modifying function, enumerate ALL state writes in the TRUE path
- Enumerate ALL state writes in the FALSE path (including the implicit "nothing happens" path for early aborts)
- If a state variable is written in one branch but NOT the other, and both branches represent valid execution paths (not error/abort) → flag as potential stale state
- Special focus: functions where fee accrual, timestamp updates, or checkpoint writes are inside a conditional block but downstream consumers assume they always executed
- Special focus: functions where a "pause" or "skip" branch updates timestamps/counters but NOT accumulators, or vice versa

**Concrete test**: If `function_a` writes `last_update = now` inside an `if (amount > 0)` block, what value does `last_update` retain when `amount == 0`? Trace all consumers of `last_update` -- do they produce correct results with the stale value?

Tag: [TRACE:branch=false → stateVar={old_value} → consumer computes {wrong_result}]

## CHECK 9: Sibling Propagation

For each Medium+ CONFIRMED or PARTIAL finding in findings_inventory.md:

1. Extract the ROOT CAUSE PATTERN in one sentence (e.g., 'state variable updated inside conditional block that can be skipped', 'paired operation asymmetry between deposit/withdraw paths')
2. Grep ALL other functions in scope for the SAME pattern (same variable types, same code structure, same operation sequence)
3. For each sibling function found: does it exhibit the SAME bug?
4. If YES and no existing finding covers it → new finding [VS-N]

| Finding | Root Cause Pattern | Sibling Functions | Same Bug? | New Finding? |
|---------|-------------------|-------------------|-----------|-------------|

## SELF-CONSISTENCY CHECK (MANDATORY before output)

For each finding you produce: if your own analysis identifies that the missing pattern/guard/check is FUNCTIONALLY REQUIRED to be absent (e.g., adding it would cause aborts, break PTB composability, or make the function unreachable), your verdict MUST be REFUTED, not CONFIRMED with caveats. A finding that says 'X is missing' and also explains 'adding X would break Y' is self-contradictory -- resolve the contradiction before outputting.

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

Return: 'DONE: {N} functions swept, {M} boundary issues, {K} reachability gaps, {J} guard gaps, {P} parity gaps, {Q} parameter validation gaps, {S} type verification gaps, {R} helper parity gaps, {U} conditional branch gaps, {T} sibling propagations'
")
```

---

## Design Stress Testing Agent (Budget Redirect)

> **Trigger**: `remaining_budget >= 3` at adaptive loop exit.
> **Purpose**: System-level design analysis that per-function agents miss. Checks design limits, Rule 13 adequacy, and Rule 14 constraint coherence.
> **Budget**: Counts as 1 budget unit.

```
Task(subagent_type="general-purpose", prompt="
You are the Design Stress Testing Agent for a Sui Move audit. You analyze protocol-level design limits and constraint coherence,
NOT individual function bugs. Per-function analysis was done by depth and breadth agents -- your job is
system-level design review.

## Your Inputs
Read:
- {SCRATCHPAD}/constraint_variables.md
- {SCRATCHPAD}/function_list.md
- {SCRATCHPAD}/attack_surface.md
- {SCRATCHPAD}/findings_inventory.md (avoid duplicates with existing findings)

## CHECK 1: Design Limit Stress
For each bounded parameter (max vector length, max pool count, capacity limits, dynamic field count, max validators):

| Parameter | Design Limit | At Limit: Behavior | Admin Usable? | Gas at Limit | Within Budget? |
|-----------|-------------|-------------------:|-------------|-------------|---------------|

1. What happens AT the design limit? (abort? infinite loop? graceful degradation? Move VM out-of-gas?)
2. Are administrative functions still usable at design limit? (emergency withdraw, pause, parameter update)
3. Gas cost at limit vs Sui transaction gas budget (~50 SUI / 50 billion MIST) -- does any function become uncallable?
4. Does the function exceed the 1024 PTB command limit or ~2048 object access limit at design limit?

Sui-specific limits to stress:
- **Shared object contention**: At high transaction volume on a shared object, latency increases due to consensus ordering. What if 100+ transactions in a single checkpoint all touch the same shared object? Can this cause user-visible delays or timeouts?
- **Dynamic field iteration**: If protocol stores data as dynamic fields and iterates over them (e.g., via sequential key lookup), what is the gas cost at N=100, N=1000, N=10000? Dynamic fields require one read per access -- no batch loading.
- **PTB command limit**: If a batch operation requires one command per element (e.g., claiming rewards from N positions), at what N does it exceed 1024 commands?
- **Transaction serialized size**: At what data size does a transaction exceed ~128KB serialized limit? Large vectors or many object inputs can hit this.
- **Object input limit**: Transactions are limited in the number of objects they can access. If a function requires N object inputs (e.g., N position NFTs), at what N does the transaction become invalid?
- **Max Pure argument size**: Pure byte arguments (vectors, strings) are limited to ~16KB per argument. If a function accepts a large vector as a pure argument, at what size does it fail?

Tag: [BOUNDARY:param=MAX_VALUE -> outcome]

## CHECK 2: Rule 13 Design Adequacy
For each user-facing function:

| Function | Stated Purpose | Fulfills Completely? | User States Without Exit? | Gap Description |
|----------|---------------|---------------------|--------------------------|-----------------|

1. Does it fulfill its stated purpose COMPLETELY? (e.g., `emergency_withdraw` that only handles primary balance but not accrued rewards or dynamic field assets)
2. Are there user states with no exit path? (deposited but cannot withdraw, receipt/position object exists but no redemption function, staked but cannot unstake)
3. Does the function name promise something the implementation does not deliver?
4. Are there user-owned objects (receipts, positions, tickets, NFTs) that become worthless if protocol shared objects are paused, frozen, or if the package is upgraded?
5. Can users be trapped by object ownership? (e.g., user holds a receipt that can only be redeemed by calling a function on a shared object that has been made immutable or destroyed)
If incomplete -> FINDING (Rule 13, design gap)

## CHECK 3: Constraint Coherence (Rule 14)
For each pair of independently-settable limits in constraint_variables.md:

| Limit A | Limit B | Mathematical Relationship Required? | Enforced On-Chain? | What Breaks if Desync? |
|---------|---------|------------------------------------:|-------------------|----------------------|

1. Must they satisfy a mathematical relationship for correctness? (e.g., `global_cap >= sum(pool_caps)`, `max_borrow_rate >= base_rate`, `total_weight == sum(pool_weights)`)
2. Can one be changed via admin function without updating the other?
3. Trace what breaks if desynchronized: infinite loops, underflows, aborts, wasted gas, incorrect pricing, stuck state
Tag: [TRACE:limitA=X, limitB=Y -> outcome at L{N}]

## CHECK 4: Yield/Reward Timing Fairness
For each yield distribution, reward streaming, or vesting mechanism:

| Mechanism | Distribution Event | Entry Window | Sandwich Possible? | Fairness Gap? |
|-----------|-------------------|-------------|-------------------|--------------|

1. Can a user deposit IMMEDIATELY BEFORE a yield/reward distribution and capture a disproportionate share?
2. Is there a cooldown, lock period, or time-weighted balance that prevents sandwich timing attacks?
3. For streaming/vesting: can a user enter AFTER streaming starts but before it ends and capture already-vested gains at the current (inflated) share price?
4. For multi-step distributions (vest -> claim -> transfer): can timing between steps be exploited?
5. Trace: if user deposits at T, distribution occurs at T+1 block, user withdraws at T+2 -- what is the user's profit vs a user who was deposited for the full period? If disproportionate -> FINDING

Tag: [TRACE:deposit_at=T, distribution_at=T+1, withdraw_at=T+2 -> profit={X} vs long_term_user={Y} -> fairness_ratio={Z}]

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
