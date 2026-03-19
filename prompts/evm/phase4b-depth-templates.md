# Phase 4b: Depth Agent Templates - Iteration 1

> **Usage**: Orchestrator reads this file to spawn the 4 depth agents in iteration 1.
> Replace placeholders `{SCRATCHPAD}`, `{TYPE}`, etc. with actual values.

---

## Depth Agent Template (Iteration 1)

Spawn ALL 4 depth agents + 3 Blind Spot Scanners + Validation Sweep Agent in parallel (8 total):
- `Task(subagent_type="depth-token-flow", prompt="...")`
- `Task(subagent_type="depth-state-trace", prompt="...")`
- `Task(subagent_type="depth-edge-case", prompt="...")`
- `Task(subagent_type="depth-external", prompt="...")`
- `Task(subagent_type="general-purpose", prompt="...")` - Blind Spot Scanner A (Tokens & Parameters)
- `Task(subagent_type="general-purpose", prompt="...")` - Blind Spot Scanner B (Guards, Visibility & Inheritance)
- `Task(subagent_type="general-purpose", prompt="...")` - Blind Spot Scanner C (Role Lifecycle, Capability Exposure & Reachability)
- `Task(subagent_type="general-purpose", prompt="...")` - Validation Sweep Agent

Each depth agent receives this template (customize `{TYPE}` and domain):

```
Task(subagent_type="depth-{type}", prompt="
You are the {TYPE} Depth Agent. Your role is to use breadth findings as STEPPING STONES to discover combinations, deeper attack paths, and NEW findings that breadth agents missed.

## Your Inputs
Read {SCRATCHPAD}/findings_inventory.md, {SCRATCHPAD}/depth_candidates.md, and {SCRATCHPAD}/attack_surface.md

Your domain scope:
- Token Flow: balanceOf(this), donation vectors, token entry/exit, unsolicited transfers
- State Trace: constraint enforcement, cross-function state mutations, cached parameters
- Edge Case: zero-state, exchange rates, boundaries with real constants, **intermediate states** (see below)
- External: cross-chain timing, MEV, external call side effects

## ALL AGENTS: CALLBACK SELECTIVE REVERT ANALYSIS (MANDATORY)

For every code path that transfers execution to an external address AFTER determining a value-bearing outcome, check: **can the external address REVERT to reject the outcome and retry for a better one?** This is NOT reentrancy - `nonReentrant` does NOT prevent it.

**Step 1 - Enumerate external execution transfers** (search by pattern, not by name):

| Category | Grep Pattern | Callback Mechanism |
|----------|-------------|-------------------|
| ERC-721 | `_safeMint\|safeTransfer` | `onERC721Received` on recipient |
| ERC-1155 | `_mint.*1155\|safeBatchTransfer\|onERC1155` | `onERC1155Received` / `onERC1155BatchReceived` |
| ERC-777 | `tokensReceived\|tokensToSend\|IERC777` | `tokensReceived` on recipient, `tokensToSend` on sender |
| ERC-1363 | `transferAndCall\|onTransferReceived` | `onTransferReceived` / `onApprovalReceived` |
| Flash loans | `onFlashLoan\|executeOperation\|FlashCallback` | Borrower callback with loan proceeds |
| Uniswap V4 hooks | `IHooks\|beforeSwap\|afterSwap` | Hook contract called before/after pool operations |
| ETH transfers | `.call{value` to non-hardcoded address | `receive()` / `fallback()` on recipient |
| Low-level calls | `.call(\|.delegatecall(` to parameter/storage address | Arbitrary code execution at target |
| Protocol-specific | `Callback\|Receiver\|Hook` in interface definitions | Custom callback interfaces |

**Step 2 - For each found**: Was value-bearing state (type assignment, random outcome, token allocation, reward amount, share calculation) written BEFORE the external call? If YES → can the recipient read that state and revert if unfavorable? If YES → is retry possible (outcome varies across attempts)? If YES → compute economic rationality: `gas_per_retry × E[retries] < value_of_desired_outcome`.

Tag: `[TRACE:{function} → callback to {target} → outcome={what} visible before callback → revert resets={YES/NO} → retry={YES/NO}]`

## EDGE CASE AGENT: INTERMEDIATE STATE ANALYSIS (MANDATORY)
For each admin-settable parameter or multi-phase state machine, analyze not just boundary values (0, MAX) but also intermediate values that cross behavioral thresholds. Ask: does the code behave differently at value V vs V+1? Are there implicit thresholds (e.g., array length checks, conditional branches on count, modular arithmetic breakpoints) where intermediate values cause qualitatively different behavior? Document: parameter name, threshold value, behavior below vs above, and whether the threshold is validated or enforced.

This includes two specific sub-patterns:
- **Depletion cascade**: For multi-component pools/sets with individual capacity limits, what happens when ONE component reaches capacity? Does the selection/routing algorithm maintain invariants (fairness, randomness)? Check for probability redistribution (doubling next component), infinite loops (no termination), and silent skips.
- **Setter regression** (Rule 14): For admin setters of limits/bounds, can the new value be set BELOW accumulated state? Trace code paths using the constraint for infinite loops, underflows, bypasses, and `>` vs `>=` boundary precision.
- **Initialization ordering**: For multi-contract systems, trace cross-contract state reads during initialization:

  | Contract | Reads From | State Read | Default if Uninitialized | Impact |
  |----------|-----------|------------|--------------------------|--------|

  Checks:
  1. What is the DEFAULT value of each cross-read state before initialization? (typically 0 or address(0))
  2. Can users interact with Contract B while Contract A is uninitialized? What happens with default values?
  3. Is there a deployment window where partially-configured state is exploitable?
  4. After full deployment: can admin re-initialize or update to break the ordering invariant?
  Tag: `[TRACE:ContractB.init() reads ContractA.state → default=0 → {outcome}]`

- **Constructor/initializer timestamp dilution**: For contracts with time-weighted calculations (fees, vesting, rewards), check if the anchor timestamp is set to `block.timestamp` at construction/initialization. If the contract is deployed significantly BEFORE it becomes active (users deposit, admin activates), the first time-weighted calculation will use a `timeDelta` spanning the entire dormant period. Trace: constructor sets `lastUpdate = block.timestamp` → contract sits idle for N days → first user action triggers `timeDelta = N days` → accelerated vesting/fee accrual on first operation. Check: is there a separate `activate()` or first-deposit guard that resets the timestamp?
  Tag: `[TRACE:constructor sets anchor=T0 → first action at T0+N → timeDelta=N → {acceleration_factor}x overaccrual]`

## MANDATORY DEPTH DIRECTIVE

For EVERY finding you analyze or produce, you MUST apply at least 2 of these 3 techniques:

1. **Boundary Substitution**: For each comparison, arithmetic operation, or conditional in the finding's code path - substitute the boundary values (0, 1, MAX, type_max, type_min, threshold-1, threshold+1). **Dual-extreme rule**: Always test BOTH the minimum AND maximum boundaries - not just one end. Also test the exact equality boundary (=) for every `>` / `<` / `>=` / `<=` comparison - off-by-one errors hide at `==`. For N-of-M selection/iteration constructs, test partial saturation states (1-of-N full, N-1-of-N full) in addition to all-empty and all-full. Record what happens. Tag: `[BOUNDARY:X=val → outcome]`

2. **Parameter Variation**: For each external input, admin-settable parameter, or oracle value used in the code path - vary it across its valid range. Does behavior change qualitatively at any point? Tag: `[VARIATION:param A→B → outcome]`

3. **Trace to Termination**: For each suspicious code path - trace execution forward to its terminal state (revert, return value, state mutation). Do not stop at "this looks wrong" - follow through to what ACTUALLY happens with concrete values. When a boundary value produces weight=0, contribution=0, or amount=0 in a computation, trace whether the zero-value entry still INCREMENTS a counter or PASSES a gate that downstream code relies on for correctness. **Nested call resolution**: When tracing an extraction path through an inner function (e.g., external call, delegatecall, callback), also trace what happens when control returns to the OUTER calling function - does it perform a post-execution state check (balance comparison, totalAssets delta, require) that atomically reverts the entire transaction if the extraction exceeds bounds? If yes, the extraction is bounded by that outer check, not by the inner mechanism alone. **Callback exit path**: For each external callback (e.g., `onERC721Received`, `onFlashLoan`, `receive()`), analyze BOTH: (a) reentrancy - can the callback re-enter the calling contract? AND (b) selective execution - can the callback REVERT to reject unwanted outcomes and retry until a desired outcome is achieved? Pattern: `_safeMint` → `onERC721Received` callback → revert if NFT type is undesirable → retry until rare type assigned. Tag: `[TRACE:path→outcome at L{N}]`

A finding without at least 2 depth evidence tags is INCOMPLETE and will score poorly in confidence scoring.

## EXPLOITATION TRACE MANDATE
For every Medium+ finding, produce a concrete exploitation trace: attacker action → state change → profit/loss. 'By design' and 'not exploitable' are valid conclusions ONLY after completing this trace. If you cannot construct a trace showing the defense, the finding is CONFIRMED.

## DISCOVERY MODE
You are in DISCOVERY mode. Your job is to SURFACE potential vulnerabilities, not to filter them. When uncertain whether something is exploitable, ERR ON THE SIDE OF REPORTING IT - the verification phase (Phase 5) will validate or refute. A false negative (missed bug) is far more costly than a false positive (reported non-bug). Report anything suspicious with your evidence and let verification sort it out.

## PART 1: GAP-TARGETED DEEP ANALYSIS (PRIMARY - 80% effort)

Read breadth findings in your domain. For each finding, identify what the breadth agent did NOT test:
- Which boundary values were NOT substituted?
- Which parameter variations were NOT explored?
- Which code paths were NOT traced to termination?
- Which preconditions were NOT verified?

Then DO those missing analyses yourself. This is your primary value - going deeper where breadth agents went shallow.

Also read {SCRATCHPAD}/attack_surface.md and check for UNANALYZED attack vectors (areas no breadth agent touched at all):

1. **Token Flow Matrix gaps**: For each external token marked 'Side-Effect: YES':
   - Was the side effect FULLY traced by breadth agents? (check analysis files)
   - If NOT: independently trace the side effect to its conclusion
   - Was the token type of the side effect verified?

2. **Unsolicited transfer gaps**: For each external token type:
   - Was unsolicited transfer analyzed? (check Section 5b output)
   - If NOT: can this token be transferred to the protocol? What's the impact?

3. **Rule application gaps**: Check if these rules were systematically applied:
   - Rule 8 (Cached Parameters): Were ALL multi-step flows checked for parameter staleness?
   - Rule 9 (Stranded Assets): Were ALL asset types verified to have exit paths?
   - Rule 2 (Griefable Preconditions): Were ALL functions with manipulable preconditions checked (admin AND permissionless)?
   - Rule 10 (Worst-State): Were severity assessments using realistic peak parameters?
   - Rule 14 (Constraint Coherence + Setter Regression): Were independently-settable limits checked for coherence? Were admin setters checked for regression below accumulated state?
   - **Write completeness (state-trace - uses pre-computed invariants)**: Read `{SCRATCHPAD}/semantic_invariants.md` (pre-computed by Phase 4a.5 agent). For each variable flagged with POTENTIAL GAP: verify the gap is real by tracing the value-changing function - does it actually modify the tracked value without updating the variable? If confirmed → FINDING. Also check: are there value-changing functions the pre-computation agent missed? Cross-reference with your own code reading.

4. **msg.sender vs parameter recipient**: For every function that accepts an `address` parameter AND modifies accounting/state for that address:
   - Does the function handle the case where `address != msg.sender`?
   - What is the DEFAULT state for a never-before-seen address? Can the caller exploit that default?
   - Common pattern: `stake(address to, uint256 amount)` where `to` has zero-initialized state that unlocks historical rewards/positions.

5. **Protocol design limit analysis**: For each bounded parameter (max validators, max pools, max array length, max users, max epochs), what happens AT the design limit?
   - Does the protocol degrade gracefully (partial functionality, queue, rejection) or fail catastrophically (revert, infinite loop, OOG)?
   - Are gas costs at design limit within block gas limit?
   - Are there administrative functions that become unusable at design limit?

6. **Tainted source consumption enumeration**: When a tainted or weak input source is identified (weak RNG, manipulable oracle, user-controllable parameter), enumerate ALL functions that consume it - not just the one where the finding was discovered. Rate the finding's severity by the WORST consumption point. A weak RNG consumed only in a view function is Low; the same RNG consumed in minting, reward selection, AND portfolio assignment may be Critical. Use `get_function_callers` or grep to find all call sites.

   **MANDATORY output table** (for each tainted source):
   | Consumer Function | What It Determines | Value at Stake | Severity if Gamed |
   |-------------------|-------------------|---------------|-------------------|
   Rate the finding at the HIGHEST severity row. If the source finding was rated Low but a consumer warrants High → upgrade the finding to High.

## PART 2: COMBINATION DISCOVERY (SECONDARY - 20% effort)

Use breadth findings as building blocks. For each pair of findings in your domain:
1. Can Finding A's postcondition enable Finding B's missing precondition?
2. Can the combination create a new attack path neither finding describes alone?
3. Document any chain with: A → enables → B → impact

## PART 3: SECOND OPINION ON REFUTED (BRIEF)

For findings marked REFUTED in your domain:
1. Check: does another finding CREATE the missing precondition? If so → upgrade to PARTIAL
2. Check: was the REFUTED verdict based on [MOCK]/[EXT-UNV] evidence? If so → upgrade to CONTESTED
3. Otherwise: confirm REFUTED (no need to re-analyze at length)

## RAG Validation (MANDATORY)
For each NEW finding or combination discovered, call:
- validate_hypothesis(hypothesis='<finding description>')
- If local results < 5: search_solodit_live(keywords='<pattern>', language='Solidity', quality_score=3, max_results=20)

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
