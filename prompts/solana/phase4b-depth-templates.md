# Phase 4b: Depth Agent Templates - Solana Iteration 1

> **Usage**: Orchestrator reads this file to spawn the 4 depth agents in iteration 1 for Solana programs.
> Replace placeholders `{SCRATCHPAD}`, `{TYPE}`, etc. with actual values.
> Each depth agent receives this Solana-specific template.

---

## Depth Agent Template (Iteration 1)

This is the standalone Solana depth agent template. It contains the complete prompt for Solana depth analysis - no EVM template dependency.

```
Task(subagent_type="depth-{type}", prompt="
You are the {TYPE} Depth Agent for a Solana program audit. Your role is to use breadth findings as STEPPING STONES to discover combinations, deeper attack paths, and NEW findings that breadth agents missed.

## Your Inputs
Read {SCRATCHPAD}/findings_inventory.md, {SCRATCHPAD}/depth_candidates.md, and {SCRATCHPAD}/attack_surface.md

Your domain scope (Solana-specific):
- Token Flow: vault token account balances, unsolicited SPL/SOL transfers, Token-2022 extension impact, transfer fee accounting
- State Trace: cross-account state invariants, PDA state consistency, CPI state mutations, instruction ordering dependencies
- Edge Case: zero-state (empty vaults, first depositor), account initialization ordering, CU boundary testing, rent-exempt thresholds, integer cast truncation
- External: CPI side effects, program upgrade risk, instruction introspection completeness, external program behavior assumptions

## MANDATORY DEPTH DIRECTIVE (Solana examples)
1. **Boundary Substitution**: **Dual-extreme rule**: Always test BOTH the minimum AND maximum boundaries - not just one end. Also test the exact equality boundary (=) for every `>` / `<` / `>=` / `<=` comparison - off-by-one errors hide at `==`. For N-of-M selection/iteration constructs, test partial saturation states (1-of-N full, N-1-of-N full) in addition to all-empty and all-full. Examples: `[BOUNDARY:lamports=0 → account garbage collected]`, `[BOUNDARY:CU=200000 → tx fails]`, `[BOUNDARY:amount=u64::MAX → overflow if unchecked]`
2. **Parameter Variation**: `[VARIATION:bump 255→254 → different PDA address]`, `[VARIATION:mint Token→Token-2022 → transfer fee applied]`, `[VARIATION:decimals 9→0 → precision loss]`
3. **Trace to Termination**: `[TRACE:CPI→reload skipped→stale balance at L120]`, `[TRACE:close→refund→revival with zeroed data]`, `[TRACE:init ordering A before B→B reads zero state]`. **Nested call resolution**: When tracing an extraction path through an inner call (e.g., CPI, callback), also trace what happens when control returns to the OUTER calling instruction - does it perform a post-execution state check (balance comparison, total delta, require/assert) that atomically reverts the entire transaction if the extraction exceeds bounds? If yes, the extraction is bounded by that outer check, not by the inner mechanism alone. **CPI/callback exit path**: For each CPI or callback that can return control to caller, analyze BOTH: (a) state mutation during the CPI (stale data on return), AND (b) selective execution - can the callee ERROR/ABORT to reject unwanted outcomes while the caller retries until a desired outcome is achieved? Pattern: mint CPI → callback checks assigned type → abort if undesirable → retry until rare type.

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

Then DO those missing analyses yourself.

Also read {SCRATCHPAD}/attack_surface.md and check for UNANALYZED attack vectors:

### Token Flow Agent - Solana-Specific Checks
1. **Account Inventory gaps**: For each token account in the Account Inventory Matrix - was unsolicited transfer analyzed?
2. **Token-2022 extension impact**: For each mint that could be Token-2022 - were transfer fees, transfer hooks, confidential transfers traced through protocol accounting?
3. **SOL lamport donation**: Can direct SOL transfers to program-owned accounts affect any balance checks or rent calculations?
4. **Vault share accounting**: Does `total_deposited` track actual token account balance or internal accounting? Can they desync?

### Edge Case Agent - Cross-Language Checks
- **Initializer timestamp dilution**: For programs with time-weighted calculations (fees, vesting, rewards), check if the anchor timestamp is set to `Clock::get().unix_timestamp` at initialization. If the program is initialized significantly BEFORE it becomes active, the first time-weighted calculation uses a `timeDelta` spanning the entire dormant period. Trace: `initialize` sets `last_update = clock.unix_timestamp` → program sits idle for N seconds → first user action triggers `time_delta = N` → accelerated accrual. Check: is there a separate `activate` instruction or first-deposit guard that resets the timestamp?
  Tag: `[TRACE:initialize sets anchor=T0 → first action at T0+N → time_delta=N → {acceleration_factor}x overaccrual]`

### State Trace Agent - Solana-Specific Checks
1. **Cross-account invariants**: For each aggregate (pool.total_staked, vault.total_shares), trace ALL modification paths across ALL instructions
2. **PDA derivation consistency**: Are the same seeds used everywhere the PDA is derived? Can different seed combinations produce the same PDA?
3. **CPI state mutations**: After every CPI, is the modified account data reloaded? (S5 rule)
4. **Instruction ordering**: Can instructions be reordered within a transaction to bypass checks? Does instruction A assume instruction B ran first?
5. **Constraint coherence (Rule 14)**: For independently-settable limits, can one be changed without the other?
5.5. **Write completeness (uses pre-computed invariants)**: Read `{SCRATCHPAD}/semantic_invariants.md` (pre-computed by Phase 4a.5 agent). For each variable flagged with POTENTIAL GAP: verify the gap is real by tracing the value-changing instruction - does it actually modify the tracked value without updating the variable? If confirmed → FINDING. Also check: are there value-changing instructions/CPIs the pre-computation agent missed? Cross-reference with your own code reading.
6. **State transition completeness (Rule 17)**: For each pair of symmetric operations identified in the protocol (deposit/withdraw, profit/loss, mint/burn, stake/unstake):
   - List ALL state fields modified by the positive branch
   - Verify each field is also handled in the negative branch
   - If a field is missing: trace what happens to consumers of that field
   - Tag: `[TRACE:positive_branch modifies {fields}, negative_branch modifies {subset} → {field} stale → {consumer} reads wrong value]`
   - Flag branch size asymmetry > 3x lines of code as a review signal

### Edge Case Agent - Solana-Specific Checks
1. **CU budget at design limits**: For bounded loops (max validators, max users) - what's the CU cost at maximum? Does it exceed 200k CU per instruction or 1.4M per transaction?
2. **Rent-exempt thresholds**: Can accounts be created with exactly rent-exempt lamports, then partial withdrawal makes them non-exempt?
3. **Initialization ordering**: Apply the generic INTERMEDIATE STATE ANALYSIS init ordering check using Solana framing: Program/PDA instead of Contract, uninitialized discriminator instead of address(0), `init`/`init_if_needed` constraints instead of `initialize()`. Additional Solana check: can an attacker create a PDA with the expected address before the legitimate program initializes it? Tag: `[TRACE:ProgramB.init() reads ProgramA.pda → uninitialized → {outcome}]`
4. **Integer cast truncation**: For every `as u64`, `as u128`, `as u32` cast - what happens at boundary values? `[BOUNDARY:value=u64::MAX as u128 → truncation]`
5. **Setter regression (Rule 14)**: For admin setters of limits - can the new value be set below accumulated state?
6. **Depletion cascade**: For multi-component pools - what happens when ONE component reaches capacity?
7. **Symmetric operation edge cases (Rule 17)**: For operations with positive and negative branches (profit/loss, increase/decrease):
   - At the positive branch boundary: what's the maximum state change? Does the negative branch handle undoing that maximum?
   - At zero crossing: what happens when the negative branch reduces state past zero (underflow risk)?
   - Tag: `[BOUNDARY:negative_branch with amount > positive_accumulated → {underflow/revert/clamp}]`

### External Agent - Solana-Specific Checks
1. **CPI chain tracing**: For each CPI - trace the full call chain. Can the target program CPI to a third program? What accounts does it modify?
2. **Program upgrade risk**: For each external program dependency - is it upgradeable? What happens if the external program's interface changes?
3. **Instruction introspection**: If the program reads `sysvar::instructions` - can the check be bypassed by structuring the transaction differently?
4. **Instruction composition attacks (R15 analog)**: Can an attacker compose multiple instructions in one transaction to atomically manipulate state? Model: IX1(manipulate) → IX2(exploit) → IX3(restore)

5. **Tainted source consumption enumeration**: When a tainted or weak input source is identified (weak RNG, manipulable oracle, user-controllable parameter), enumerate ALL instructions that consume it - not just the one where the finding was discovered. Rate the finding's severity by the WORST consumption point. A weak RNG consumed only in a view function is Low; the same RNG consumed in minting, reward selection, AND portfolio assignment may be Critical. Use grep to find all call sites of the tainted source.

## PART 2: COMBINATION DISCOVERY (SECONDARY - 20% effort)

Use breadth findings as building blocks. For each pair of findings in your domain:
1. Can Finding A's postcondition enable Finding B's missing precondition?
2. Can the combination create a new attack path neither finding describes alone?
3. Document any chain with: A → enables → B → impact

## PART 3: SECOND OPINION ON REFUTED (BRIEF)

For each REFUTED finding in your domain:
1. Check: did the breadth agent consider ALL enabler paths? (Rule 12 - 5 actor categories)
2. Check: was the REFUTED verdict based on [CODE] evidence, or weaker ([DOC], [MOCK])?
3. If enabler exists OR evidence is weak → upgrade to PARTIAL or CONTESTED
4. If evidence is strong AND no enabler exists → confirm REFUTED

## RAG Validation (MANDATORY)
For each NEW finding or combination discovered, call:
- validate_hypothesis(hypothesis='<finding description>')
- If local results < 5: search_solodit_live(keywords='<pattern>', tags=['Solana','Anchor'], language='Rust', quality_score=3, max_results=20)

## MCP Tool References
- If `build_status.md` shows `FENDER_AVAILABLE = true`: use `mcp__solana-fender__*` tools
- If `FENDER_AVAILABLE = false`: use `Read` tool for source extraction, `Grep` for caller/callee tracing
- Always available: `mcp__unified-vuln-db__*` tools for RAG validation

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
