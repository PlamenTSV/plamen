# Phase 4b: Scanner & Sweep Templates -- Aptos Move

> **Usage**: Orchestrator reads this file to spawn the 3 Blind Spot Scanners, Validation Sweep Agent, and Design Stress Testing Agent in iteration 1.
> Replace placeholders `{SCRATCHPAD}`, etc. with actual values.

---

## Blind Spot Scanner A: Tokens & Parameters (Aptos)

> **Trigger**: Always runs IN PARALLEL with depth agents (iteration 1 only).
> **Purpose**: Check what breadth agents missed in FungibleAsset/Coin coverage and parameter analysis.

```
Task(subagent_type="general-purpose", prompt="
You are Blind Spot Scanner A for an Aptos Move module audit. Find what breadth agents NEVER LOOKED AT for tokens, FungibleAsset/Coin coverage, and parameters.

## Your Inputs
Read:
- {SCRATCHPAD}/attack_surface.md (Token Account Mapping, Reference Lifecycle Tracking)
- {SCRATCHPAD}/findings_inventory.md (what WAS analyzed)
- {SCRATCHPAD}/constraint_variables.md (admin-changeable parameters)

## CHECK 1: FungibleAsset/Coin Coverage
Cross-reference attack_surface.md Token Account Mapping against findings_inventory.md:

For each external FungibleAsset/Coin<T> the protocol interacts with:
| Token | Standard (Coin/FA) | Analyzed by Agent? | Finding IDs | Dimensions Covered (R11) | Missing Dimensions |
|-------|-------------------|-------------------|-------------|--------------------------|-------------------|

If ANY token has 0 findings AND can be sent to the protocol unsolicited (via `primary_fungible_store::deposit`, `coin::deposit`, or `aptos_account::transfer`) -> BLIND SPOT.
If ANY token has findings covering <=2 of 5 R11 dimensions AND uncovered dimensions are applicable -> PARTIAL BLIND SPOT.

**Dimension coverage gate**: For each token with >=1 finding, verify coverage breadth:

| Token | R11-D1: Transferability | R11-D2: Accounting | R11-D3: Op Blocking | R11-D4: Collection/Gas | R11-D5: Side Effects | Dimensions Covered |
|-------|------------------------|--------------------:|--------------------:|----------------------|---------------------|-------------------|

**R11 Dimension Definitions (Aptos Move)**:
- **D1: Transferability** -- Can the token be sent to the protocol unsolicited? Via `primary_fungible_store::deposit` (FungibleAsset), `coin::deposit` (Coin), or `aptos_account::transfer` (APT). Includes resource creation front-running via `move_to`.
- **D2: Accounting** -- Is the FungibleStore/CoinStore balance consistent with the protocol's internal tracking? Can donations or direct transfers desync internal accounting?
- **D3: Op Blocking** -- Can dispatchable hooks (`DepositHandler`, `WithdrawHandler`, `TransferHandler`) abort and block protocol operations? Can a token with hooks cause DoS of a critical function?
- **D4: Collection/Gas** -- Does the protocol iterate over token entries (FungibleStore enumeration, SmartVector of token addresses)? Can an attacker inflate the collection size to cause gas exhaustion?
- **D5: Side Effects** -- Do dispatchable hooks execute arbitrary code during deposit/withdraw/transfer? Can `derived_balance` return manipulated values? Can metadata changes affect in-flight operations?

If ANY token has findings covering <=2 of 5 dimensions AND the uncovered dimensions are applicable -> PARTIAL BLIND SPOT.
Applicable = the token type supports that interaction (e.g., basic Coin<T> without CoinStore hooks lacks D3:Op Blocking and D5:Side Effects unless it has a CoinStore deposit event consumer; non-fungible tokens don't have D4:Collection/Gas unless the protocol iterates over them).

**FungibleAsset specific**: For each FA the protocol handles:
| FA Metadata | Dispatchable Hooks Registered? | Hook Side Effects Checked? | Bypass via Direct Call Checked? | Metadata Validation Checked? |
|-------------|-------------------------------|---------------------------|-------------------------------|------------------------------|

**Coin-to-FA parity**: If protocol handles both Coin<T> and FungibleAsset:
| Operation | Coin<T> Path | FungibleAsset Path | Equivalent Accounting? | Gap? |
|-----------|-------------|-------------------|----------------------|------|

## CHECK 2: Admin-Changeable Parameter Coverage
From constraint_variables.md, for each parameter with a setter function:

| Parameter | Setter Function | Stored In Resource | Can Affect Active Operations? | Analyzed by Agent? | Finding ID |
|-----------|----------------|-------------------|-------------------------------|-------------------|------------|

**Apply Rule 13**: For each parameter change, model BOTH directions:
- Parameter INCREASES: who is harmed?
- Parameter DECREASES: who is harmed?
- If either direction harms users AND no finding covers it -> BLIND SPOT

**Apply Rule 14**: For each parameter:
- Does its setter enforce bounds? (min/max checks before updating resource)
- Can the new value be set below accumulated state? (setter regression)
- Is there a related parameter that must maintain coherence? (constraint coherence)

## Output
- Maximum 5 findings [BLIND-A1] through [BLIND-A5]
- Use standard finding format with Aptos rules (R1-R17, MR1-MR5, AR1-AR4)
- Note WHY breadth agents likely missed each

## Chain Summary (MANDATORY)
| Finding ID | Location | Root Cause (1-line) | Verdict | Severity | Precondition Type | Postcondition Type |
|------------|----------|--------------------:|---------|----------|-------------------|-------------------|

Write to {SCRATCHPAD}/blind_spot_A_findings.md

Return: 'DONE: {N} blind spots -- Check1: {A} token gaps, Check2: {B} parameter gaps'
")
```

---

## Blind Spot Scanner B: Guards, Visibility & Module Dependencies (Aptos)

> **Trigger**: Always runs IN PARALLEL with depth agents (iteration 1 only).
> **Purpose**: Check what breadth agents missed in access control, visibility, and module structure. Note: Move has no inheritance -- CHECK 5 covers module dependency completeness and upgrade compatibility. CHECK 5b covers friend module trust boundaries.

```
Task(subagent_type="general-purpose", prompt="
You are Blind Spot Scanner B for an Aptos Move module audit. Find what breadth agents NEVER LOOKED AT for guards, visibility, and module dependencies.

## Your Inputs
Read:
- {SCRATCHPAD}/findings_inventory.md (what WAS analyzed)
- {SCRATCHPAD}/function_list.md (complete function inventory)
- {SCRATCHPAD}/state_variables.md (all resources and structs)
- {SCRATCHPAD}/modifiers.md (access control patterns)
- Source files for all in-scope modules

## CHECK 3: Capability-Gated Function Griefability (Rule 2)
For each entry function or public function with capability/signer-based access control:

| Function | Module | Guard Type (signer/capability) | Preconditions | User-Manipulable? | Analyzed by Agent? | Finding ID |
|----------|--------|-------------------------------|---------------|-------------------|-------------------|------------|

If precondition is user-manipulable AND no finding covers it -> BLIND SPOT.

Aptos-specific griefability vectors:
- **Resource existence griefing**: Can an attacker call `move_to` to create a resource at an address before the protocol, causing the protocol's `move_to` to abort?
- **FungibleStore donation**: Can an attacker inflate a FungibleStore balance the function relies on as a precondition via `primary_fungible_store::deposit`?
- **Named object front-running**: Can an attacker create a named object at the predictable address (via `object::create_named_object`) before the protocol?
- **Balance-dependent admin functions**: Does an admin function check a balance/threshold that users can manipulate (via Coin/FA donation)?

## CHECK 4: Function Visibility Audit (MR5)
From function_list.md, for each function by visibility level:

### Public Entry Functions (externally callable AND composable)
| Function | Module | Modifies State? | Has Access Control? | Should Be Entry-Only? | Analyzed? |
|----------|--------|-----------------|---------------------|----------------------|-----------|

Flag if: a function is `public entry` but should be `entry`-only (not composable) to prevent flash loan / atomic composition attacks via Move scripts.

### Public Functions (composable, not directly callable from transactions)
| Function | Module | Modifies Sensitive State? | Should Be public(friend)? | Analyzed? |
|----------|--------|--------------------------|--------------------------|-----------|

Flag if: can modify sensitive state and is callable by ANY module without access control.
Also flag: public entry functions that emit events but have NO access control AND do NOT modify meaningful state -- these allow anyone to forge events that mislead off-chain indexers and UIs.

### Friend Declarations
| Module | Declared Friends | Functions Exposed via public(friend) | All Friends Need ALL Exposed Functions? |
|--------|-----------------|--------------------------------------|----------------------------------------|

Flag if: a friend module is granted access to functions it does not need (over-broad friend declaration).

Also flag: any admin-gated function that modifies state but does NOT emit an event. Admin parameter changes without events are unmonitorable.

Also flag: `public(friend)` function that has a CONFIGURABLE PARAMETER (e.g., `cooldown_period`, `min_delay`) stored in a resource but the parameter's setter is NOT exposed via any `public entry` function. If the parameter affects user behavior and is hardcoded at deployment, ask: is the hardcoded value appropriate for all future states? Can the protocol adapt if conditions change?

## CHECK 5: Module Dependency Capability Completeness
For each `use`d module that provides configuration or management functions:

| Used Module | Configuration Function | Purpose | Exposed by In-Scope Module? | Missing? |
|-------------|----------------------|---------|----------------------------|----------|

**Check**:
- For each imported module's configuration/management capabilities: is there a corresponding `public entry` wrapper in the in-scope code that exposes it?
- If the used module provides a critical configuration function (e.g., updating oracle settings, adjusting fee parameters, pausing operations) but no in-scope module exposes a wrapper -> FINDING: capability is unreachable post-deployment
- Severity: Medium if the unreachable function controls a parameter that affects protocol correctness; Low if it's a convenience function

### Module Upgrade Compatibility
For each module with `upgrade_policy = compatible`:

| Module | Upgrade Policy | Functions That Can Change | Resources That Must Be Preserved | Compatibility Constraints |
|--------|---------------|--------------------------|--------------------------------|--------------------------|

**Check**:
- Can an upgraded module change function signatures that other modules depend on?
- Can an upgraded module add new abilities to existing structs?
- Can an upgraded module change resource layouts in ways that corrupt existing stored data?
- Can an upgraded module add new public functions that bypass existing access control?
- Is the upgrade authority a single signer (centralization risk) or governance-controlled?

## CHECK 5b: Friend Module Trust Boundary

For each `friend` declaration in scope:

| Module | Friend Module | Functions Exposed via public(friend) | Friend Module Audited? | Trust Boundary Documented? |
|--------|--------------|-------------------------------------|----------------------|--------------------------|

**Check**:
- Does each friend module actually need access to ALL `public(friend)` functions? If not, this is over-broad friend access.
- Can a friend module call `public(friend)` functions in an order that creates an inconsistent state? (e.g., calling `set_balance` without calling `update_accounting`)
- If the friend module is upgradeable, can a future version of the friend abuse the `public(friend)` functions?
- Are there `public(friend)` functions that modify critical state (balances, configs, capabilities) that should have additional guards beyond the friend check?
- Does any friend module expose a `public entry` function that directly wraps a `public(friend)` call without adding access control? (friend trust bypass)

## Output
- Maximum 5 findings [BLIND-B1] through [BLIND-B5]
- Use standard finding format
- Note WHY breadth agents likely missed each

## Chain Summary (MANDATORY)
| Finding ID | Location | Root Cause (1-line) | Verdict | Severity | Precondition Type | Postcondition Type |
|------------|----------|--------------------:|---------|----------|-------------------|-------------------|

Write to {SCRATCHPAD}/blind_spot_B_findings.md

Return: 'DONE: {N} blind spots -- Check3: {A} capability griefability gaps, Check4: {B} visibility gaps, Check5: {C} dependency/upgrade gaps, Check5b: {D} friend trust gaps'
")
```

---

## Blind Spot Scanner C: Role Lifecycle, Capability Exposure & Reachability (Aptos)

> **Trigger**: Always runs IN PARALLEL with depth agents (iteration 1 only).
> **Purpose**: Check what breadth agents missed in role/capability lifecycle, ref exposure, and function reachability.

```
Task(subagent_type="general-purpose", prompt="
You are Blind Spot Scanner C for an Aptos Move module audit. Find what breadth agents NEVER LOOKED AT for role/capability lifecycle, reference exposure, and function reachability.

## Your Inputs
Read:
- {SCRATCHPAD}/findings_inventory.md (what WAS analyzed)
- {SCRATCHPAD}/function_list.md (complete function inventory)
- {SCRATCHPAD}/modifiers.md (access control patterns)
- {SCRATCHPAD}/state_variables.md (all resources and structs)
- Source files for all in-scope modules

## CHECK 6: Capability/Role Lifecycle Completeness

For each capability or role identified in the codebase (via stored capabilities, signer checks, or custom role structs):

| Role/Capability | Grant Mechanism | Revoke Mechanism | Revoke Exists? | Circular Dependency? | Finding? |
|----------------|----------------|-----------------|----------------|---------------------|----------|

**Methodology**:
- For each capability struct (AdminCapability, OperatorCapability, custom caps) stored via `move_to`: is there a corresponding `move_from` or destruction function?
- For each `SignerCapability` stored: is there a revocation path? Can the stored `SignerCapability` be extracted and transferred?
- If NO revocation function exists -> FINDING: irrevocable capability (minimum Medium if capability modifies user-facing state)
- Check for circular dependencies: does revoking Capability A require Capability B, and granting Capability B require Capability A?
- Check: can a capability holder block their own removal? (e.g., capability holder can update the module, and revocation requires the old module version)
- For resource account `SignerCapability`: is it stored? Can it be lost? If lost, the resource account becomes permanently uncontrollable.

**Capability transfer analysis**:
- Does the capability struct have `store` ability? If yes, it can be transferred between resources -- is this intended?
- Does the capability struct have `copy` ability? If yes, capabilities can be duplicated -- is this intended?
- Does the capability struct have `drop` ability? If yes, capabilities can be silently discarded -- does this create orphaned state?
- For capability structs with ONLY `key` ability: these are non-transferable, non-copyable, non-droppable -- verify there is an explicit destruction function (`move_from` + field destructuring)

## CHECK 7: Reference and Capability Exposure Gaps (AR1)

For each `ConstructorRef`, `MintRef`, `TransferRef`, `BurnRef`, `DeleteRef`, `ExtendRef`, and `FreezeRef` in the codebase:

| Ref Type | Created In | Stored In Resource | Storage Address | Access Path | Externally Reachable? | Gap? |
|----------|-----------|-------------------|----------------|-------------|----------------------|------|

**Methodology**:
- For each ref creation (`object::generate_*_ref`): trace where the ref is stored
- Is the storage resource at a predictable/known address? Can anyone call `borrow_global` on it?
- Is there a `public` or `public entry` function that returns or exposes the ref?
- Is `ConstructorRef` consumed within the creation function, or does it escape? (ConstructorRef should NEVER be stored -- it has no `store`/`key` ability by design)
- If `ExtendRef` is accessible: attacker can call `object::generate_signer_for_extending` to get the object's signer and control the entire object
- If `MintRef` is accessible: attacker can call `fungible_asset::mint` to mint unlimited tokens
- If `TransferRef` is accessible: attacker can call `object::transfer_with_ref` to transfer any object of that type, bypassing `ungated_transfer` settings
- If `BurnRef` is accessible: attacker can call `fungible_asset::burn` to destroy any token holdings
- Flag: Any ref that is extractable or readable via a public function path without proper access control
- Severity: Critical for MintRef/BurnRef/ExtendRef leaks, High for TransferRef/DeleteRef leaks

**For used modules that provide internal capabilities**: List ALL internal/private functions provided by `use`d modules that grant capabilities or refs. For each: is there a `public entry` function in the inheriting module that exposes this capability? If a used module provides a critical configuration function but no in-scope module exposes it -> FINDING: module capability is unreachable post-deployment. Severity: Medium if the unreachable function controls a parameter that affects protocol correctness; Low if it's a convenience function.

## CHECK 8: Function Reachability Audit

For each entry function and public function in all in-scope modules:

| Function | Module | Visibility | Called By (internal) | Called By (external/test) | Reachable in Production? | Dead Code? |
|----------|--------|-----------|---------------------|--------------------------|-------------------------|------------|

**Methodology**:
- Trace callers for each function using function_list.md and source grep
- Identify functions that are defined but NEVER called by any other in-scope module or expected external caller
- For dead code with security implications: does the dead function modify state? Could it be called by anyone if discovered (public/public entry)?
- Special focus: entry functions with no callers in tests or documentation -- potential forgotten migration artifacts or backdoors
- Flag: public/entry functions with no callers that modify critical state -> potential backdoor or forgotten migration artifact
- Check: are there helper functions that should be called (for cleanup, validation, accounting updates) but are never actually invoked in any code path?
- Special focus: functions that WERE reachable in a previous version but became unreachable after refactoring (look for commented-out callers, TODO comments, or version indicators)

## Output
- Maximum 8 findings [BLIND-C1] through [BLIND-C8]
- Use standard finding format
- Note WHY breadth agents likely missed each

## Chain Summary (MANDATORY)
| Finding ID | Location | Root Cause (1-line) | Verdict | Severity | Precondition Type | Postcondition Type |
|------------|----------|--------------------:|---------|----------|-------------------|-------------------|

Write to {SCRATCHPAD}/blind_spot_C_findings.md

Return: 'DONE: {N} blind spots -- Check6: {A} capability lifecycle gaps, Check7: {B} ref exposure gaps, Check8: {C} reachability gaps'
")
```

---

## Validation Sweep Agent -- Aptos Move

> **Trigger**: Always runs IN PARALLEL with the 4 depth agents and Blind Spot Scanners (iteration 1 only).
> **Purpose**: Mechanical sweep of ALL validation logic for specific deficit patterns that reasoning-based agents consistently miss: boundary operator precision, validation reachability gaps, guard coverage completeness, cross-module parity, parameter validation, and helper parity.

```
Task(subagent_type="general-purpose", prompt="
You are the Validation Sweep Agent for an Aptos Move module audit. You perform mechanical checks across every function in scope. You do NOT analyze business logic or economic attacks -- you check that existing validation code is correct, reachable, and complete.

## INPUT FILTERING
When cross-referencing against findings_inventory.md, focus on Medium+ severity findings only. Low/Info findings do not need cross-validation sweeps -- the attention cost of processing 50+ findings outweighs the marginal value of sweeping Low/Info patterns.

## Your Inputs
Read:
- {SCRATCHPAD}/function_list.md (complete function inventory)
- {SCRATCHPAD}/findings_inventory.md (what was already found -- avoid duplicates)
- {SCRATCHPAD}/modifiers.md (access control patterns)
- Source files for all in-scope modules

## CHECK 1: Boundary Operator Precision

For EVERY comparison operator in validation logic (`assert!`, `if`, inline checks):

| Location | Expression | Operator | Should Be | Off-by-One? |
|----------|-----------|----------|-----------|-------------|

**Methodology**:
- For each `>` ask: should this be `>=`? What happens at the exact boundary value?
- For each `<` ask: should this be `<=`? What happens at the exact boundary value?
- For each `==` in a range check: does it exclude a valid boundary?
- For timestamp comparisons: does `>` vs `>=` on `timestamp::now_seconds()` create a 1-second window where the check fails?
- For bit-shift checks: does `shift_amount < bit_width` correctly prevent abort, or should it be `<=`?
- For Move-specific integer arithmetic: does `a - b` abort on underflow when `a == b` but the operator check allows `a >= b`? (Move unsigned subtraction aborts on underflow)

**Concrete test**: Substitute the boundary value into the expression. Does the function behave correctly AT the boundary? If the boundary value should be valid but the operator rejects it (or vice versa), flag it.

Only flag findings where the off-by-one produces a CONCRETE impact (DoS, fund lock, bypass). Do NOT flag stylistic preferences.
Also check: for each `while`/`for` loop with accumulator variables, verify ALL accumulators are updated per iteration. A loop that increments one counter but not a co-dependent tracking variable produces double-counting on subsequent iterations.

## CHECK 2: Validation Reachability

For EVERY validation check (assert!, abort, explicit error return) in a function:

| Function | Validation | Can Be Bypassed Via Alternative Path? | Bypass Path |
|----------|-----------|---------------------------------------|-------------|

**Methodology**:
- Trace ALL callers of each function (use call graph from function_list.md)
- For each validation: is there an alternative code path that reaches the same state change WITHOUT this validation?
- Check: can a multi-entry-function sequence (deposit then partial withdraw, stake then partial unstake) skip a validation that a single call path enforces?
- Check: do internal functions assume a validation was applied by the calling function, but some callers skip it?
- Check: can a Move script compose multiple `public entry` calls to bypass a validation that assumes sequential transaction execution? (Aptos Move scripts can call multiple entry functions atomically)

**Concrete test**: For each validation, enumerate the function(s) that call the validated function. Does every caller satisfy the precondition, or can some callers reach the protected code without the check?

## CHECK 3: Guard Coverage Completeness

For EVERY access control guard (signer check, capability requirement, state flag check) applied to at least one function:

| Guard | Applied To | NOT Applied To (same state writes) | Missing? |
|-------|-----------|--------------------------------------|----------|

**Methodology**:
- For each signer check (e.g., `assert!(signer::address_of(account) == @admin, E_NOT_ADMIN)`), list ALL functions it protects
- Identify ALL other functions that write to the SAME resources (via `borrow_global_mut`, `move_to`, `move_from`)
- If any function writes to the same resource but lacks the guard -> flag as potential gap
- For capability-gated write functions: check if there is a permissionless function that achieves the same state mutation through a different path
- For state flag checks (e.g., `assert!(config.is_paused == false, E_PAUSED)`): verify ALL state-mutating functions check the flag, not just some

**Concrete test**: If `function_a` requires admin signer and writes `Config` resource, and `function_b` also writes `Config` but has no access control, that is a guard gap.

**Note on reentrancy**: Move does not have Solidity-style reentrancy (no callbacks during execution). However, Move scripts CAN compose multiple `public entry` function calls atomically. Check whether state flag guards (e.g., `is_locked`) that protect multi-step operations are checked by ALL entry points that read intermediate state.

## CHECK 4: Cross-Module Action Parity

For each user-facing action verb (deposit, withdraw, stake, unstake, claim, swap):

| Action | Module A | Protection | Module B | Has Same Protection? | Gap? |
|--------|---------|------------|---------|---------------------|------|

**Methodology**:
- Enumerate ALL modules that expose an entry function for this user action
- For each pair, compare: signer checks, timing guards (delays, cooldowns), capability requirements, state validation
- If Module A has a protection that Module B lacks for the SAME user action -> flag

**Concrete test**: If `module_a::withdraw()` checks `timestamp::now_seconds() >= request.unlock_time` but `module_b::withdraw()` has no such delay for the same economic action, that is a parity gap.

## CHECK 5: External Call Parameter Validation

For EVERY cross-module call that passes user-supplied or caller-controlled parameters:

| Function | Target Module::Function | Parameter Source | Validated? | What's Unvalidated? |
|----------|------------------------|-----------------|-----------|-------------------|

**Methodology**:
- For each cross-module call, trace parameters backward to their source
- If any parameter comes from entry function arguments (user input) WITHOUT validation, flag it
- Special focus: struct parameters passed through to external modules -- are ALL fields validated?
- Common pattern: passing a user-supplied `Object<T>` to an external module without verifying the object's type, owner, or metadata
- Common pattern: passing a user-supplied metadata `Object<Metadata>` to `fungible_asset::*` functions without validating it matches the expected asset type

**Struct field enumeration**: For every struct parameter passed to an external module call:
1. List ALL fields of the struct by reading the struct definition
2. For each field: trace backward to its source (caller input, global storage, computed)
3. For each field sourced from caller input: is it validated? Document:

| Struct | Field | Source | Validated? | Impact if Attacker-Controlled |
|--------|-------|--------|-----------|-------------------------------|

**Concrete test**: Can the caller set parameter X to an attacker-controlled value that redirects funds, changes swap direction, passes wrong metadata, or modifies the recipient of external module outputs?

## CHECK 6: Helper Function Call-Site Parity

For EVERY internal helper that transforms values (normalization, scaling, encoding, formatting):

| Helper Function | Purpose | Call Sites | Consistent Usage? | Missing/Inconsistent Site |
|----------------|---------|-----------|-------------------|--------------------------|

**Methodology**:
- Grep for ALL call sites of each helper (normalize, denormalize, scale, unscale, to_coin, from_coin, to_shares, to_assets, coin_to_fa, fa_to_coin, or any protocol-specific transform pair)
- For each PAIR of inverse helpers (normalize/denormalize, encode/decode, coin_to_fa/fa_to_coin): verify every value that passes through one also passes through its inverse at the appropriate point
- For each call site: does it apply the helper to the same variable type with the same parameters as other call sites?
- Flag: a value that is normalized at entry but not denormalized at exit (or vice versa)
- Flag: a helper called with different parameters at different sites when the same parameters are expected
- For paired operations that share state (create/consume, deposit/refund, lock/unlock, open/close): if either operation transforms an input before use, verify the paired operation applies the same transformation at the same logical point - not later, not earlier, not skipped
- Flag: inconsistent decimal scaling between Coin<T> (which has fixed decimals via `CoinInfo<T>`) and FungibleAsset (which has decimals in `Metadata`)

**Concrete test**: If `normalize_amount(amount, decimals)` is called at 3 deposit sites but `denormalize_amount(amount, decimals)` is called at only 2 of 3 corresponding withdrawal sites, the missing site produces values at the wrong scale.

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

For each finding you produce: if your own analysis identifies that the missing pattern/modifier/guard is FUNCTIONALLY REQUIRED to be absent (e.g., adding it would cause aborts, break composability, or make the function unreachable), your verdict MUST be REFUTED, not CONFIRMED with caveats. A finding that says 'X is missing' and also explains 'adding X would break Y' is self-contradictory -- resolve the contradiction before outputting.

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

Return: 'DONE: {N} functions swept, {M} boundary issues, {K} reachability gaps, {J} guard gaps, {P} parity gaps, {Q} parameter validation gaps, {R} helper parity gaps, {S} conditional branch gaps, {T} sibling propagations'
")
```

---

## Design Stress Testing Agent -- Aptos Move (Budget Redirect)

> **Trigger**: `remaining_budget >= 3` at adaptive loop exit.
> **Purpose**: System-level design analysis that per-function agents miss. Checks design limits, Rule 13 adequacy, and Rule 14 constraint coherence.
> **Budget**: Counts as 1 budget unit.

```
Task(subagent_type="general-purpose", prompt="
You are the Design Stress Testing Agent for an Aptos Move module audit. You analyze protocol-level design limits and constraint coherence,
NOT individual function bugs. Per-function analysis was done by depth and breadth agents -- your job is
system-level design review.

## Your Inputs
Read:
- {SCRATCHPAD}/constraint_variables.md
- {SCRATCHPAD}/function_list.md
- {SCRATCHPAD}/attack_surface.md
- {SCRATCHPAD}/findings_inventory.md (avoid duplicates with existing findings)

## CHECK 1: Design Limit Stress (Gas Focus)
For each bounded parameter (max SmartVector length, max Table size, max SimpleMap entries, max pools, max positions, max iterations):

| Parameter | Design Limit | At Limit: Behavior | Admin Usable? | Gas at Limit | Tx Gas Limit OK? |
|-----------|-------------|-------------------:|-------------|-------------|------------------|

1. What happens AT the design limit? (abort? infinite loop? graceful degradation? revert via gas exhaustion?)
2. Are administrative functions still usable at design limit? (emergency withdraw, parameter update, pause equivalent)
3. Gas cost at limit vs Aptos transaction gas limit (~2M gas units on mainnet) -- does any function become uncallable?
4. For SmartVector/SimpleMap/Table iterations: what's the max entries before the loop exceeds the transaction gas limit?
5. For `vector::for_each` / `vector::enumerate` / manual `while` loops: is there a hard cap on iteration count? If the bound comes from user-growable state, can an attacker inflate it to DoS admin functions?
Tag: [BOUNDARY:param=MAX_VALUE -> outcome]

## CHECK 2: Rule 13 Design Adequacy
For each user-facing entry function:

| Function | Stated Purpose | Fulfills Completely? | User States Without Exit? | Gap Description |
|----------|---------------|---------------------|--------------------------|-----------------|

1. Does it fulfill its stated purpose COMPLETELY? (e.g., `emergency_withdraw` that only handles Coin<T> but not FungibleAsset tokens is incomplete)
2. Are there user states with no exit path? (deposited but cannot withdraw, staked but cannot unstake, resource created but cannot be destroyed)
3. Does the function name promise something the implementation does not deliver?
4. For resource accounts: if `SignerCapability` is lost or not stored, can assets in the resource account still be recovered?
5. For immutable modules (`upgrade_policy = immutable`): were all necessary admin/recovery functions included before the upgrade policy was set to immutable?
If incomplete -> FINDING (Rule 13, design gap)

## CHECK 3: Constraint Coherence (Rule 14)
For each pair of independently-settable limits in constraint_variables.md:

| Limit A | Limit B | Mathematical Relationship Required? | Enforced On-Chain? | What Breaks if Desync? |
|---------|---------|------------------------------------:|-------------------|----------------------|

1. Must they satisfy a mathematical relationship for correctness? (e.g., `global_cap >= sum(pool_caps)`, `max_total == sum(max_per_category)`)
2. Can one be changed via its setter without updating the other?
3. Trace what breaks if desynchronized: infinite loops (with Move abort on underflow since all integers are unsigned), abort on arithmetic overflow, bypasses, wasted gas
4. For constraints stored across DIFFERENT resources: is there an atomic update mechanism, or can they be desynced between transactions?
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
