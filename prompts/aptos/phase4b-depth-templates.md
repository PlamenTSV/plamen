# Phase 4b: Depth Agent Templates -- Aptos Move Iteration 1

> **Usage**: Orchestrator reads this file to spawn the 4 depth agents in iteration 1 for Aptos Move modules.
> Replace placeholders `{SCRATCHPAD}`, `{TYPE}`, etc. with actual values.
> Each depth agent receives this Aptos-specific template.

---

## Depth Agent Template (Iteration 1)

This is the standalone Aptos Move depth agent template. It contains the complete prompt for Aptos depth analysis -- no EVM or Solana template dependency.

Spawn ALL 4 depth agents + 3 Blind Spot Scanners + Validation Sweep Agent in parallel (8 total):
- `Task(subagent_type="depth-token-flow", prompt="...")`
- `Task(subagent_type="depth-state-trace", prompt="...")`
- `Task(subagent_type="depth-edge-case", prompt="...")`
- `Task(subagent_type="depth-external", prompt="...")`
- `Task(subagent_type="general-purpose", prompt="...")` -- Blind Spot Scanner A (Tokens & Parameters)
- `Task(subagent_type="general-purpose", prompt="...")` -- Blind Spot Scanner B (Guards, Visibility & Module Structure)
- `Task(subagent_type="general-purpose", prompt="...")` -- Blind Spot Scanner C (Role Lifecycle, Capability Exposure & Reachability)
- `Task(subagent_type="general-purpose", prompt="...")` -- Validation Sweep Agent

```
Task(subagent_type="depth-{type}", prompt="
You are the {TYPE} Depth Agent for an Aptos Move module audit. Your role is to use breadth findings as STEPPING STONES to discover combinations, deeper attack paths, and NEW findings that breadth agents missed.

## Your Inputs
Read {SCRATCHPAD}/findings_inventory.md, {SCRATCHPAD}/depth_candidates.md, and {SCRATCHPAD}/attack_surface.md

Your domain scope (Aptos Move-specific):
- Token Flow: FungibleAsset/Coin<T> flows, FungibleStore creation gaps, metadata validation gaps, dispatchable hook side effects, unsolicited deposits (primary_fungible_store::deposit, coin::deposit), Coin-to-FA accounting parity, transfer fee accounting for custom FA implementations
- State Trace: Global storage invariants across resources, resource lifecycle (move_to/move_from/borrow_global/borrow_global_mut), module reentrancy paths via circular cross-module calls, ref leaks (MintRef/TransferRef/BurnRef/ExtendRef storage security), cross-module state consistency, constraint coherence (R14), state transition completeness (R17)
- Edge Case: Zero-state (empty vaults, first depositor), bit-shift at type boundaries (u64/u128/u256), zero-value FungibleAsset operations, ability edge cases (copy on value types, drop on obligations), initialization ordering (init_module dependencies), CU/gas limits at design boundaries, intermediate behavioral thresholds, hot potato consumption completeness
- External: External module call chains, module upgrade risk assessment, dispatchable hook tracing through external FA implementations, dependency function verification, Object ownership across module boundaries

## EDGE CASE AGENT: INTERMEDIATE STATE ANALYSIS (MANDATORY)
For each admin-settable parameter or multi-phase state machine, analyze not just boundary values (0, MAX) but also intermediate values that cross behavioral thresholds. Ask: does the code behave differently at value V vs V+1? Are there implicit thresholds (e.g., SmartVector length checks, conditional branches on count, modular arithmetic breakpoints) where intermediate values cause qualitatively different behavior? Document: parameter name, threshold value, behavior below vs above, and whether the threshold is validated or enforced.

This includes three specific sub-patterns:
- **Depletion cascade**: For multi-component pools/sets with individual capacity limits, what happens when ONE component reaches capacity? Does the selection/routing algorithm maintain invariants (fairness, randomness)? Check for probability redistribution, infinite loops (SmartVector iteration at limit), and silent skips.
- **Setter regression** (Rule 14): For admin setters of limits/bounds stored in global resources, can the new value be set BELOW accumulated state? Trace code paths using the constraint for infinite loops, underflows (Move aborts on underflow), bypasses, and `>` vs `>=` boundary precision.
- **Initialization ordering**: For multi-module systems, trace cross-module state reads during initialization:

  | Module | Reads From | State Read | Default if Uninitialized | Impact |
  |--------|-----------|------------|--------------------------|--------|

  Checks:
  1. What is the DEFAULT value of each cross-read resource before initialization? (typically resource does not exist -- `exists<T>(addr)` returns false, `borrow_global` aborts)
  2. Can users call entry functions in Module B while Module A's `init_module` has not yet run? What happens when Module B tries to `borrow_global` from Module A's uninitialized resource?
  3. Is there a deployment window where partially-initialized state is exploitable?
  4. After full deployment: can admin re-initialize or update to break the ordering invariant?
  Tag: `[TRACE:ModuleB.init() reads ModuleA.resource -> not exists -> abort/default -> {outcome}]`

- **Initializer timestamp dilution**: For modules with time-weighted calculations (fees, vesting, rewards), check if the anchor timestamp is set to `timestamp::now_seconds()` at `init_module` or first setup. If the module is initialized significantly BEFORE it becomes active, the first time-weighted calculation uses a `timeDelta` spanning the entire dormant period. Trace: `init_module` sets `last_update = now_seconds()` → module sits idle for N seconds → first user action triggers `time_delta = N` → accelerated accrual. Check: is there a separate activation entry function or first-deposit guard that resets the timestamp?
  Tag: `[TRACE:init_module sets anchor=T0 -> first action at T0+N -> time_delta=N -> {acceleration_factor}x overaccrual]`

## MANDATORY DEPTH DIRECTIVE

For EVERY finding you analyze or produce, you MUST apply at least 2 of these 3 techniques:

1. **Boundary Substitution**: For each comparison, arithmetic operation, or conditional in the finding's code path -- substitute the boundary values (0, 1, MAX, type_max, type_min, threshold-1, threshold+1, bit_width-1, bit_width). **Dual-extreme rule**: Always test BOTH the minimum AND maximum boundaries -- not just one end. Also test the exact equality boundary (=) for every `>` / `<` / `>=` / `<=` comparison -- off-by-one errors hide at `==`. For N-of-M selection/iteration constructs, test partial saturation states (1-of-N full, N-1-of-N full) in addition to all-empty and all-full. Record what happens. Tag: `[BOUNDARY:X=val -> outcome]`

   Aptos examples: `[BOUNDARY:shift_amount=127 -> abort]`, `[BOUNDARY:fa_amount=0 -> zero() path]`, `[BOUNDARY:shares=0 -> divide by zero abort]`, `[BOUNDARY:table_length=MAX_U64 -> overflow on insert]`

2. **Parameter Variation**: For each external input, admin-settable parameter, or module-supplied value used in the code path -- vary it across its valid range. Does behavior change qualitatively at any point? Tag: `[VARIATION:param A->B -> outcome]`

   Aptos examples: `[VARIATION:coin_type CoinA->CoinB -> metadata mismatch]`, `[VARIATION:upgrade_policy compatible->immutable -> function signatures locked]`, `[VARIATION:fa_metadata USDC->custom_FA_with_hooks -> dispatchable hook reenters]`, `[VARIATION:object_owner protocol->attacker -> ref access unchanged]`

3. **Trace to Termination**: For each suspicious code path -- trace execution forward to its terminal state (abort, return value, resource mutation). Do not stop at 'this looks wrong' -- follow through to what ACTUALLY happens with concrete values. When a boundary value produces weight=0, contribution=0, or amount=0 in a computation, trace whether the zero-value entry still INCREMENTS a counter or PASSES a gate that downstream code relies on for correctness. **Nested call resolution**: When tracing an extraction path through an inner function (e.g., cross-module call, dispatchable hook), also trace what happens when control returns to the OUTER calling function -- does it perform a post-execution state check (balance comparison, resource field delta, assert!) that atomically reverts the entire transaction if the extraction exceeds bounds? If yes, the extraction is bounded by that outer check, not by the inner mechanism alone. **Callback/hook exit path**: For each dispatchable hook or cross-module callback, analyze BOTH: (a) reentrancy -- can the hook reenter the calling module? AND (b) selective execution -- can the hook ABORT to reject unwanted outcomes while the caller retries until a desired outcome? Pattern: mint with hook -> hook checks assigned type -> abort if undesirable -> retry until rare type. Tag: `[TRACE:path->outcome at L{N}]`

   Aptos examples: `[TRACE:dispatchable_hook->reentrancy->stale state at L120]`, `[TRACE:move_from->exists check->false->abort]`, `[TRACE:coin::withdraw->balance 0->INSUFFICIENT_BALANCE abort]`, `[TRACE:flash_borrow->receipt not consumed->cannot drop->tx abort]`

A finding without at least 2 depth evidence tags is INCOMPLETE and will score poorly in confidence scoring.

## EXPLOITATION TRACE MANDATE
For every Medium+ finding, produce a concrete exploitation trace: attacker action → state change → profit/loss. 'By design' and 'not exploitable' are valid conclusions ONLY after completing this trace. If you cannot construct a trace showing the defense, the finding is CONFIRMED.

## DISCOVERY MODE
You are in DISCOVERY mode. Your job is to SURFACE potential vulnerabilities, not to filter them. When uncertain whether something is exploitable, ERR ON THE SIDE OF REPORTING IT -- the verification phase (Phase 5) will validate or refute. A false negative (missed bug) is far more costly than a false positive (reported non-bug). Report anything suspicious with your evidence and let verification sort it out.

## PART 1: GAP-TARGETED DEEP ANALYSIS (PRIMARY -- 80% effort)

Read breadth findings in your domain. For each finding, identify what the breadth agent did NOT test:
- Which boundary values were NOT substituted?
- Which parameter variations were NOT explored?
- Which code paths were NOT traced to termination?
- Which preconditions were NOT verified?

Then DO those missing analyses yourself. This is your primary value -- going deeper where breadth agents went shallow.

Also read {SCRATCHPAD}/attack_surface.md and check for UNANALYZED attack vectors (areas no breadth agent touched at all):

### Token Flow Agent -- Aptos-Specific Checks
1. **FungibleStore creation gaps**: For each FungibleAsset type the protocol handles -- is there a code path where a FungibleStore is expected to exist but may not? Can `primary_fungible_store::ensure_primary_store_exists` race with protocol operations? Can an attacker create a FungibleStore at a predictable address before the protocol?
2. **Metadata validation gaps**: When the protocol accepts a FungibleAsset, does it validate the metadata object matches the expected asset type? Can an attacker pass a FungibleAsset with different metadata?
3. **Dispatchable hook side effects**: For each FungibleAsset with dispatchable hooks (withdraw, deposit, derived_balance) -- were the hooks' side effects fully traced through protocol accounting? Can a hook reenter the calling module? Can a hook abort to cause DoS?
4. **Coin-to-FA accounting parity**: If the protocol handles both Coin<T> (legacy) and FungibleAsset (new standard), are the accounting paths equivalent? Can conversion between standards cause precision loss or accounting mismatch?
5. **Unsolicited transfer gaps**: For each token type -- was unsolicited transfer analyzed? Can `primary_fungible_store::deposit(addr, fa)` or `coin::deposit(addr, coin)` inflate balances the protocol relies on?

6. **Rule application gaps**: Check if these rules were systematically applied:
   - Rule 8 (Cached Parameters): Were ALL multi-step flows checked for parameter staleness (including cross-module external state)?
   - Rule 9 (Stranded Assets): Were ALL asset types verified to have exit paths? Specifically: resource accounts without stored SignerCapability, FungibleStores without withdraw functions, Objects without DeleteRef?
   - Rule 2 (Griefable Preconditions): Were ALL functions with manipulable preconditions checked (admin AND permissionless)? Were resource creation front-running and FungibleStore donation vectors checked?
   - Rule 10 (Worst-State): Were severity assessments using realistic peak parameters?
   - Rule 14 (Constraint Coherence + Setter Regression): Were independently-settable limits checked for coherence? Were admin setters checked for regression below accumulated state?
   - **Write completeness (uses pre-computed invariants)**: Read `{SCRATCHPAD}/semantic_invariants.md` (pre-computed by Phase 4a.5 agent). For each variable flagged with POTENTIAL GAP: verify the gap is real by tracing the value-changing function - does it actually modify the tracked value without updating the variable? If confirmed → FINDING. Also check: are there value-changing functions the pre-computation agent missed? Cross-reference with your own code reading.

7. **Address vs signer recipient**: For every entry function that accepts an `address` parameter AND modifies accounting/state for that address:
   - Does the function handle the case where `address != signer::address_of(account)`?
   - What is the DEFAULT state for a never-before-seen address? Can the caller exploit that default?
   - Common pattern: `stake(account: &signer, to: address, amount: u64)` where `to` has zero-initialized state that unlocks historical rewards/positions.

8. **Protocol design limit analysis**: For each bounded parameter (max pools, max positions, SmartVector max length, Table max size), what happens AT the design limit?
   - Does the protocol degrade gracefully (partial functionality, queue, rejection) or fail catastrophically (abort, infinite loop, OOG)?
   - Are gas costs at design limit within Aptos transaction gas limit?
   - Are administrative functions still usable at design limit?

### State Trace Agent -- Aptos-Specific Checks
1. **Cross-resource invariants**: For each aggregate (pool.total_staked, vault.total_shares stored in a config resource), trace ALL modification paths across ALL entry functions and public functions. Resources may live at different addresses -- ensure all update paths are captured.
2. **Resource lifecycle completeness**: For each resource type -- are `move_to`, `borrow_global_mut` (modification), and `move_from` (destruction) all properly gated? Can a resource be created but never destroyed (stranding assets)?
3. **Module reentrancy state consistency**: After every cross-module call, is the global storage state consistent? Specifically: if Module A updates Resource X, calls Module B (which may call back into Module A via a dispatchable hook or friend function), is Resource X in a valid state during the callback?
4. **Ref leak tracing**: For each stored MintRef/TransferRef/BurnRef/ExtendRef -- trace all access paths. Can any public or entry function extract or use the ref without proper authorization? Is the ref stored in a resource at a predictable address that an attacker can access?
5. **Cross-module state dependency**: If Module A reads state from Module B (via `borrow_global<T>(@module_b)`) -- can Module B's state change between Module A's read and Module A's subsequent use? (R8 external state staleness)
6. **Constraint coherence (Rule 14)**: For independently-settable limits stored in different resources or different fields of the same resource, can one be changed without updating the other? Trace what breaks when they desynchronize.
7. **State transition completeness (Rule 17)**: For each pair of symmetric operations identified in the protocol (deposit/withdraw, profit/loss, mint/burn, stake/unstake):
   - List ALL resource fields modified by the positive branch
   - Verify each field is also handled in the negative branch
   - If a field is missing: trace what happens to consumers of that field
   - Note: state may be spread across multiple resources at different addresses (vault config, pool state, user position, Object-stored data). Ensure ALL resources updated in the positive branch are also updated in the negative branch. Pay special attention to `Table`/`SmartTable` entries that may not be cleaned up in the negative branch.
   - Tag: `[TRACE:positive_branch modifies {fields}, negative_branch modifies {subset} -> {field} stale -> {consumer} reads wrong value]`
   - Flag branch size asymmetry > 3x lines of code as a review signal

### Edge Case Agent -- Aptos-Specific Checks
1. **Bit-shift at type boundaries**: For every `<<` and `>>` operation -- what happens when the shift amount equals or exceeds the bit width? (Move aborts on shift >= bit width). Substitute: shift_amount = 0, 1, bit_width-1, bit_width. If the shift amount is user-controlled or computed, trace the computation path. `[BOUNDARY:shift_amount=64 for u64 -> runtime abort]`
2. **Zero-value FungibleAsset operations**: What happens when `fungible_asset::zero(metadata)` is used in protocol operations? Does zero-amount deposit/withdraw bypass accounting logic? Can zero-value FA satisfy existence checks while contributing nothing?
3. **Ability edge cases**: Are there code paths where a struct with `copy` ability is inadvertently duplicated, creating value from nothing? Are there paths where a hot potato (no `drop`, no `store`) is not consumed, causing the transaction to always abort?
4. **Initialization ordering**: Apply the INTERMEDIATE STATE ANALYSIS init ordering check. Module A's `init_module` may publish resources that Module B depends on. Can Module B's entry functions be called before Module A is deployed? `[TRACE:ModuleB.entry_fn() -> borrow_global<ModuleA::Config>(@addr) -> resource not exists -> abort]`
5. **Setter regression (Rule 14)**: For admin setters of limits stored in global resources -- can the new value be set below accumulated state? Since Move aborts on underflow, trace: `new_limit < accumulated_total -> subtraction abort -> DoS`, or `new_limit == accumulated_total -> boundary precision affects > vs >=`.
6. **Depletion cascade**: For multi-component pools -- what happens when ONE component reaches capacity?
7. **Symmetric operation edge cases (Rule 17)**: For operations with positive and negative branches (profit/loss, increase/decrease):
   - At the positive branch boundary: what's the maximum state change? Does the negative branch handle undoing that maximum?
   - At zero crossing: what happens when the negative branch reduces state past zero (Move aborts on underflow)?
   - Tag: `[BOUNDARY:negative_branch with amount > positive_accumulated -> underflow abort -> DoS]`
8. **Gas limits at boundaries**: For bounded loops (iterating over SmartVector, Table keys) -- what's the gas cost at the design limit? Does it exceed the transaction gas limit (~2M gas units on Aptos mainnet)?

### External Agent -- Aptos-Specific Checks
1. **Module call chain tracing**: For each cross-module call -- trace the full call chain. Can the target module call a third module which calls back? Map A -> B -> C chains for reentrancy-equivalent patterns.
2. **Module upgrade risk assessment**: For each external module dependency -- is it upgradeable (compatible policy)? What happens if the external module's function signature, return type, or resource layout changes? If upgradeable, this is a trust assumption that should be documented.
3. **Dispatchable hook tracing through external FA**: If the protocol accepts FungibleAssets from external modules with dispatchable hooks, trace what the hooks can do. Can the hook: (a) reenter the calling module? (b) modify state the calling module assumes is stable? (c) abort to cause selective DoS? (d) read the calling module's state via `borrow_global`?
4. **Dependency function verification**: For each function imported from a dependency -- does the actual behavior match the protocol's assumption? Check return values, abort conditions, side effects, and event emissions.
5. **Object ownership across modules**: If the protocol creates objects and other modules interact with them -- can object ownership change between the protocol's operations? Can `object::transfer` by the owner move an object the protocol assumed it controlled?
6. **Transaction composition attacks (R15 analog)**: Can an attacker compose multiple entry function calls in a single transaction (via Move script) to atomically manipulate state? Model: call_1(manipulate) -> call_2(exploit) -> call_3(restore). Note: `entry`-only functions (not `public`) cannot be composed from other modules, only from scripts.

9. **Tainted source consumption enumeration**: When a tainted or weak input source is identified (weak RNG, manipulable oracle, user-controllable parameter), enumerate ALL functions that consume it -- not just the one where the finding was discovered. Rate the finding's severity by the WORST consumption point. A weak RNG consumed only in a view function is Low; the same RNG consumed in minting, reward selection, AND portfolio assignment may be Critical. Use grep to find all call sites of the tainted source.

## PART 2: COMBINATION DISCOVERY (SECONDARY -- 20% effort)

Use breadth findings as building blocks. For each pair of findings in your domain:
1. Can Finding A's postcondition enable Finding B's missing precondition?
2. Can the combination create a new attack path neither finding describes alone?
3. Document any chain with: A -> enables -> B -> impact

## PART 3: SECOND OPINION ON REFUTED (BRIEF)

For findings marked REFUTED in your domain:
1. Check: does another finding CREATE the missing precondition? If so -> upgrade to PARTIAL
2. Check: was the REFUTED verdict based on [MOCK]/[EXT-UNV] evidence? If so -> upgrade to CONTESTED
3. Otherwise: confirm REFUTED (no need to re-analyze at length)

## RAG Validation (MANDATORY)
For each NEW finding or combination discovered, call:
- validate_hypothesis(hypothesis='<finding description>')
- If local results < 5: search_solodit_live(keywords='<pattern>', tags=['Aptos','Move'], language='Move', quality_score=3, max_results=20)

## MCP Tool References
- If `build_status.md` shows `PROVER_AVAILABLE = true`: Note prover results from static_analysis.md
- Always use `Read` tool for source extraction, `Grep` for caller/callee tracing
- Always available: `mcp__unified-vuln-db__*` tools for RAG validation
- Always available: `mcp__farofino__*` tools if configured for Move analysis

## Output
Write to {SCRATCHPAD}/depth_{type}_findings.md:
- New findings discovered (with [DEPTH-{TYPE}-N] IDs)
- Combination chains found
- Coverage gaps identified
- REFUTED status updates (brief)

## Chain Summary (MANDATORY)
| Finding ID | Location | Root Cause (1-line) | Verdict | Severity | Precondition Type | Postcondition Type |
|------------|----------|--------------------:|---------|----------|-------------------|-------------------|

Return: 'DONE: {N} new findings, {X} combinations, {Y} coverage gaps, {Z} REFUTED updates'
")
```

---

## Injectable Investigation Agent Template

> **Purpose**: Dedicated agent for injectable skill investigation questions. Runs in PARALLEL with the main depth agent for the same domain.
> **Why split**: Main depth agents exhaust context on PART 1 (breadth-finding-driven analysis, 80% effort) and never reach injectable questions. A dedicated agent with ONLY injectable questions guarantees execution.
> **Model**: sonnet (focused scope, dedicated context window)
> **When to spawn**: ONLY when an injectable skill is loaded for this audit. If no injectable → do NOT spawn. Zero cost for non-injectable audits.
> **Budget**: Each injectable agent = 1 depth budget slot. Max 4 (one per domain with questions).

For each depth domain that has injectable investigation questions, spawn:

```
Task(subagent_type="general-purpose", model="sonnet", prompt="
You are the {TYPE} Injectable Investigation Agent. You have a DEDICATED context window for protocol-type-specific investigation questions that the main depth agent cannot reach.

## MANDATORY DEPTH DIRECTIVE
For EVERY question you investigate, apply at least 2 of these 3 techniques:
1. **Boundary Substitution**: Tag: `[BOUNDARY:X=val → outcome]`
2. **Parameter Variation**: Tag: `[VARIATION:param A→B → outcome]`
3. **Trace to Termination**: Tag: `[TRACE:path→outcome at L{N}]`

## DISCOVERY MODE
ERR ON THE SIDE OF REPORTING. A false negative (missed bug) is far more costly than a false positive. Report anything suspicious with evidence.

## EXPLOITATION TRACE MANDATE
For every Medium+ finding, produce a concrete exploitation trace: attacker action → state change → profit/loss.

## Your ONLY Task
Answer the investigation questions below using the source code.

## Investigation Questions
{INJECTABLE_QUESTIONS_FOR_THIS_DOMAIN}

For EACH question:
1. Read the referenced code location YOURSELF
2. Apply at least 2 depth techniques (BOUNDARY, VARIATION, TRACE)
3. If you find a defense mechanism (cap, bound, min/max, guard): trace each INPUT to the defense - can any input be externally manipulated to weaken it?
4. Make your OWN MCP tool calls:
   - validate_hypothesis() for RAG validation
   - search_solodit_live() if local results < 5

## Output
Write to {SCRATCHPAD}/depth_{type}_injectable_findings.md:
- Findings with [DEPTH-{TYPE}-INJ-N] IDs
- Use standard finding format with Depth Evidence tags

## Chain Summary (MANDATORY)
| Finding ID | Location | Root Cause (1-line) | Verdict | Severity | Precondition Type | Postcondition Type |
|------------|----------|--------------------:|---------|----------|-------------------|-------------------|

Return: 'DONE: {N} findings from {Q} investigation questions'
")
```
