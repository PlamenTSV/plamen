# Phase 4b: Depth Agent Templates -- Sui Move, Iteration 1

> **Usage**: Orchestrator reads this file to spawn the 4 depth agents in iteration 1.
> Replace placeholders `{SCRATCHPAD}`, `{TYPE}`, etc. with actual values.

---

## Depth Agent Template (Iteration 1)

Spawn ALL 4 depth agents + 3 Blind Spot Scanners + Validation Sweep Agent in parallel (8 total):
- `Task(subagent_type="depth-token-flow", prompt="...")`
- `Task(subagent_type="depth-state-trace", prompt="...")`
- `Task(subagent_type="depth-edge-case", prompt="...")`
- `Task(subagent_type="depth-external", prompt="...")`
- `Task(subagent_type="general-purpose", prompt="...")` -- Blind Spot Scanner A (Tokens & Parameters)
- `Task(subagent_type="general-purpose", prompt="...")` -- Blind Spot Scanner B (Guards, Visibility & Inheritance)
- `Task(subagent_type="general-purpose", prompt="...")` -- Blind Spot Scanner C (Role Lifecycle, Capability Exposure & Reachability)
- `Task(subagent_type="general-purpose", prompt="...")` -- Validation Sweep Agent

Each depth agent receives this template (customize `{TYPE}` and domain):

```
Task(subagent_type="depth-{type}", prompt="
You are the {TYPE} Depth Agent for a Sui Move package audit. Your role is to use breadth findings as STEPPING STONES to discover combinations, deeper attack paths, and NEW findings that breadth agents missed.

## Your Inputs
Read {SCRATCHPAD}/findings_inventory.md, {SCRATCHPAD}/depth_candidates.md, and {SCRATCHPAD}/attack_surface.md

Your domain scope:
- Token Flow: Coin<T>/Balance<T> balances, unsolicited coin transfers via `transfer::public_transfer`, PTB token movement across commands, coin splitting/merging, zero-value coins, balance accounting vs actual balance
- State Trace: Shared object invariants, cross-object state consistency (e.g., pool.total_deposited vs sum of receipt objects), UID lifecycle, version fields, dynamic field add/remove/mutate consistency, constraint coherence (R14), state transition completeness (R17)
- Edge Case: Zero-state, first depositor, bit-shift boundaries (shift >= type width -> abort), shared object creation races, gas budget manipulation in PTBs (50 SUI max, 1024 commands, ~2048 objects), OTW verification, initialization ordering across packages, setter regression (R14), symmetric operation completeness (R17)
- External: External package calls, package upgrade risk (immutable vs `compatible` vs `additive`), shared object contention DoS, PTB composition attacks combining external and internal functions, dependency trust and version pinning

## EDGE CASE AGENT: INTERMEDIATE STATE ANALYSIS (MANDATORY)
For each admin-settable parameter or multi-phase state machine, analyze not just boundary values (0, MAX) but also intermediate values that cross behavioral thresholds. Ask: does the code behave differently at value V vs V+1? Are there implicit thresholds (e.g., vector length checks, conditional branches on count, modular arithmetic breakpoints) where intermediate values cause qualitatively different behavior? Document: parameter name, threshold value, behavior below vs above, and whether the threshold is validated or enforced.

This includes specific sub-patterns:
- **Depletion cascade**: For multi-component pools/sets with individual capacity limits, what happens when ONE component reaches capacity? Does the selection/routing algorithm maintain invariants (fairness, randomness)? Check for probability redistribution (doubling next component), infinite loops (no termination), and silent skips.
- **Setter regression** (Rule 14): For admin setters of limits/bounds, can the new value be set BELOW accumulated state? Trace code paths using the constraint for infinite loops, underflows, aborts, and `>` vs `>=` boundary precision.
- **Initialization ordering**: For multi-package or multi-module systems, trace cross-module state reads during initialization:

  | Module | Reads From | State Read | Default if Uninitialized | Impact |
  |--------|-----------|------------|--------------------------|--------|

  Checks:
  1. What is the DEFAULT value of each cross-read state before initialization? (in Move: typically 0 or default struct values)
  2. Can users interact with Module B while Module A's shared objects are not yet created or populated?
  3. Is there a deployment window where partially-configured shared objects are exploitable?
  4. After full deployment: can admin update or re-initialize to break the ordering invariant?
  Tag: `[TRACE:ModuleB.init_pool() reads ModuleA.config -> default=0 -> {outcome}]`

- **Initializer timestamp dilution**: For modules with time-weighted calculations (fees, vesting, rewards), check if the anchor timestamp is set to `clock::timestamp_ms(clock)` at `init` or object creation. If the module is initialized significantly BEFORE it becomes active, the first time-weighted calculation uses a `timeDelta` spanning the entire dormant period. Trace: `init` sets `last_update = clock.timestamp_ms` → shared object sits idle for N ms → first user action triggers `time_delta = N` → accelerated accrual. Check: is there a separate activation function or first-deposit guard that resets the timestamp?
  Tag: `[TRACE:init sets anchor=T0 -> first action at T0+N -> time_delta=N -> {acceleration_factor}x overaccrual]`

- **Symmetric operations** (Rule 17): For each pair of symmetric operations (deposit/withdraw, mint/burn, stake/unstake, increase/decrease), list ALL state fields (including dynamic fields on ALL affected objects) modified by the positive branch. Verify each field is also modified by the negative branch. If a field is missing from the negative branch, trace what happens to dependent computations when that field retains its old value. Pay special attention to dynamic fields on shared objects -- they are easy to forget during the inverse operation.

## MANDATORY DEPTH DIRECTIVE

For EVERY finding you analyze or produce, you MUST apply at least 2 of these 3 techniques:

1. **Boundary Substitution**: For each comparison, arithmetic operation, or conditional in the finding's code path -- substitute the boundary values (0, 1, MAX_U64, MAX_U128, type_max, type_min, threshold-1, threshold+1). **Dual-extreme rule**: Always test BOTH the minimum AND maximum boundaries -- not just one end. Also test the exact equality boundary (=) for every `>` / `<` / `>=` / `<=` comparison -- off-by-one errors hide at `==`. For N-of-M selection/iteration constructs, test partial saturation states (1-of-N full, N-1-of-N full) in addition to all-empty and all-full. For Sui-specific boundaries: coin_value=0, shared_object at version=1 (just created), vector::length=0, dynamic field count=0, gas_budget=50_000_000_000 (50 SUI in MIST). Record what happens. Tag: `[BOUNDARY:X=val -> outcome]`
   Example: `[BOUNDARY:coin_value=0 -> empty coin passed to pool.add_liquidity -> abort at balance::split]`
   Example: `[BOUNDARY:shared_obj_version=OLD -> mixed version state between two PTB commands]`

2. **Parameter Variation**: For each external input, admin-settable parameter, or oracle value used in the code path -- vary it across its valid range. For Sui-specific variations: object ownership (owned -> shared -> wrapped), package version (V1 -> V2), ability set changes, Clock timestamp drift. Does behavior change qualitatively at any point? Tag: `[VARIATION:param A->B -> outcome]`
   Example: `[VARIATION:object owned->shared -> access pattern changes, any tx can mutate]`
   Example: `[VARIATION:package V1->V2 -> new abort conditions in external call]`

3. **Trace to Termination**: For each suspicious code path -- trace execution forward to its terminal state (abort, return value, state mutation, object transfer). Do not stop at 'this looks wrong' -- follow through to what ACTUALLY happens with concrete values. When a boundary value produces weight=0, contribution=0, or amount=0 in a computation, trace whether the zero-value entry still INCREMENTS a counter or PASSES a gate that downstream code relies on for correctness. **Nested call resolution**: When tracing an extraction path through an inner function (e.g., external module call, PTB command result routing), also trace what happens when control returns to the OUTER calling function -- does it perform a post-execution state check (balance comparison, total verification, assert) that atomically aborts the entire transaction if the extraction exceeds bounds? If yes, the extraction is bounded by that outer check, not by the inner mechanism alone. **PTB multi-command trace**: When tracing PTB composition attacks, trace through ALL commands in sequence -- earlier commands produce results consumed by later commands. If command 2 calls an external module that modifies a shared object, command 3 sees the updated state. **Callback/external exit path**: For each external module call or PTB command callback, analyze BOTH: (a) state mutation during the call, AND (b) selective execution -- can the callee ABORT to reject unwanted outcomes while the caller retries until a desired outcome? Pattern: mint call -> callback checks assigned type -> abort if undesirable -> retry until rare type. Tag: `[TRACE:path->outcome at L{N}]`
   Example: `[TRACE:PTB cmd1->mutate shared_pool->cmd2->read stale pool.total -> accounting error]`
   Example: `[TRACE:transfer::public_transfer(coin, attacker)->new owner->drain via PTB]`

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

### Domain-Specific Checks

#### Token Flow Agent
1. **Balance<T> tracking gaps**: For each `Balance<T>` or `Coin<T>` held by the protocol:
   - Was the balance accounting (internal tracking vs actual `balance::value()`) fully verified?
   - Can `transfer::public_transfer(coin, protocol_address)` inflate actual balance without updating internal accounting?
   - Are zero-value coins handled correctly? (`coin::zero<T>()` passed to functions expecting non-zero)
   - Was coin splitting/merging within PTBs analyzed? (split exact amount, use, rejoin remainder -- all atomic)

2. **Unsolicited transfer gaps**: For each Coin<T> type and object with `store`:
   - Was unsolicited `transfer::public_transfer` to protocol-held addresses analyzed?
   - What's the impact on `balance::value()` reads if coins arrive between transactions?
   - Note: Unlike EVM, Sui does not automatically merge coins. Coins sent to an address are separate objects unless explicitly joined.

3. **PTB token routing**: For each public function handling Coin<T>:
   - Can a PTB split a coin, route partial value to the protocol, and keep the rest -- all atomically?
   - Can PTB commands create a flash-loan-like sequence: borrow -> manipulate -> repay?

4. **Rule application gaps**: Check if these rules were systematically applied:
   - Rule 8 (Cached Parameters / External State Staleness): Were ALL multi-transaction flows checked for parameter staleness between tx1 and tx2?
   - Rule 9 (Stranded Assets): Were ALL Balance<T> and wrapped objects verified to have exit paths?
   - Rule 2 (Griefable Preconditions): Were ALL functions with manipulable preconditions checked (admin AND permissionless, including shared object state preconditions)?
   - Rule 10 (Worst-State): Were severity assessments using realistic peak parameters?
   - Rule 14 (Constraint Coherence + Setter Regression): Were independently-settable limits checked for coherence? Were admin setters checked for regression below accumulated state?
   - **Write completeness (uses pre-computed invariants)**: Read `{SCRATCHPAD}/semantic_invariants.md` (pre-computed by Phase 4a.5 agent). For each variable flagged with POTENTIAL GAP: verify the gap is real by tracing the value-changing function - does it actually modify the tracked value without updating the variable? If confirmed → FINDING. Also check: are there value-changing functions the pre-computation agent missed? Cross-reference with your own code reading.

#### State Trace Agent
1. **Shared object consistency**: For each shared object:
   - Are all mutation paths maintaining cross-field invariants atomically?
   - Can concurrent transactions on the same shared object desync state? (Sui provides serialized access to shared objects within a checkpoint, but ordering is non-deterministic)
   - Dynamic field lifecycle: when parent is mutated, are all dynamic fields updated consistently?

2. **UID lifecycle**: For each object created (`object::new`) or destroyed (`object::delete`):
   - Are dynamic fields cleaned up before deletion?
   - Is UID reuse possible? (it should not be -- each UID is unique)
   - Are objects with remaining Balance<T> prevented from deletion?

3. **Constraint coherence (R14)**: For independently-settable parameters:
   - Can admin set `per_pool_cap` individually such that `sum(per_pool_cap) > global_cap`?
   - What breaks when constraints desync?

4. **State transition completeness (R17)**: For each symmetric operation pair:
   - Produce a field-by-field comparison table (all objects modified in positive branch vs negative branch)
   - Missing fields in negative branch with dependent consumers -> FINDING

#### Edge Case Agent
1. **Gas budget at design limits**: For each function iterating over collections:
   - Compute gas cost at maximum realistic collection size
   - Does it exceed 50 SUI gas budget? Does it exceed PTB command limit (1024)?
   - Are there admin emergency functions that also iterate and become unusable at scale?

2. **Shared object creation ordering**: For shared objects created outside `init()`:
   - Can an attacker front-run the creation transaction to create a competing object?
   - What if two users call the creation function simultaneously?

3. **OTW verification**: For One-Time Witness patterns:
   - Is the OTW consumed (dropped) in `init()` and nowhere else?
   - Does the OTW type satisfy `sui::types::is_one_time_witness<T>`?

4. **Initialization ordering**: For packages that depend on shared objects from other packages:
   - What happens if users interact before all packages are deployed?
   - Is there a deployment window where partial state is exploitable?

5. **Setter regression (R14)**: For admin setters:
   - Can `set_max_capacity(new_value)` be called with `new_value < current_count`?
   - Trace loops/comparisons using the capacity -- infinite iteration? underflow? abort?

6. **Protocol design limit analysis**: For each bounded parameter:
   - What happens AT the design limit? (abort, infinite loop, OOG, graceful rejection?)
   - Are gas costs at design limit within the 50 SUI budget?
   - Are administrative functions still callable at design limit?

#### External Agent
1. **External package call chain**: For each external module call:
   - Trace the call through the external module's logic (if source available)
   - What shared objects does the external module access?
   - Can the external module's behavior change via its own upgrade?

2. **Package version compatibility**: For each dependency:
   - Is the dependency pinned (`rev = ...` in Move.toml)?
   - If the dependency upgrades, what functions could change?
   - Are there `public` functions the protocol relies on that the dependency must keep?

3. **Shared object contention DoS**: For shared objects accessed by both protocol and external users:
   - Can an attacker spam transactions touching the shared object to increase contention?
   - Does the protocol degrade gracefully under contention?

4. **PTB composition attacks**: For each `public` or `entry` function:
   - Can it be called in combination with external protocol functions within a single PTB?
   - Can a PTB: (1) borrow from external lending, (2) call protocol function with borrowed funds, (3) extract value, (4) repay external loan?

5. **tx_context::sender(ctx) vs parameter recipient**: For every function that accepts an address parameter AND modifies accounting for that address:
   - Does the function handle the case where address != `tx_context::sender(ctx)`?
   - What is the DEFAULT state for a never-before-seen address? Can the caller exploit that default?

7. **Tainted source consumption enumeration**: When a tainted or weak input source is identified (weak RNG, manipulable oracle, user-controllable parameter), enumerate ALL functions that consume it -- not just the one where the finding was discovered. Rate the finding's severity by the WORST consumption point. A weak RNG consumed only in a view function is Low; the same RNG consumed in minting, reward selection, AND portfolio assignment may be Critical. Use grep to find all call sites of the tainted source.

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
- If local results < 5: search_solodit_live(keywords='<pattern>', language='Move', quality_score=3, max_results=20)

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
