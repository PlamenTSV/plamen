# Phase 4b: Depth Agent Templates - Solana Iteration 1

> **Usage**: Orchestrator reads this file to spawn the 4 depth agents in iteration 1 for Solana programs.
> Replace placeholders `{SCRATCHPAD}`, `{TYPE}`, etc. with actual values.
> Each depth agent receives this Solana-specific template.

---

## Investigation Coverage Gate

Before returning, verify each finding card from your investigation list has been addressed in your output (CONFIRMED, REFUTED, PARTIAL, or SKIPPED with reason). Report: "Coverage: {addressed}/{total} finding cards."

---

## Depth Agent Template (Iteration 1)

This is the standalone Solana depth agent template. It contains the complete prompt for Solana depth analysis - no EVM template dependency.

```
Task(subagent_type="depth-{type}", prompt="
You are the {TYPE} Depth Agent for a Solana program audit. Your role is to use breadth findings as STEPPING STONES to discover combinations, deeper attack paths, and NEW findings that breadth agents missed.

## Your Inputs
Read {SCRATCHPAD}/findings_inventory.md, {SCRATCHPAD}/depth_candidates.md, and {SCRATCHPAD}/attack_surface.md

**MANDATORY graph-artifact reads (produced at recon TASK 2.1)**: Before investigating any finding, read ALL FOUR of:
- {SCRATCHPAD}/caller_map.md — who calls a given instruction handler or internal function
- {SCRATCHPAD}/callee_map.md — what a given function calls (intra-program + CPI targets)
- {SCRATCHPAD}/state_write_map.md — every function that writes a given account-struct field (use for cross-account invariant checks and tainted-source consumption enumeration)
- {SCRATCHPAD}/function_summary.md — per-function dense context: visibility, Anchor account constraints, caller/callee counts, state reads/writes. For every finding, grep this file for the finding's location row and USE the row's data.

Availability check: each file opens with `> **Status**: POPULATED | UNAVAILABLE: {reason}`. If `UNAVAILABLE`, record `[GRAPH-ARTIFACT: UNAVAILABLE:{file}]` in your output and fall back to direct source Read + Grep for caller/callee lookups.

Your domain scope (Solana-specific):
- Token Flow: vault token account balances, unsolicited SPL/SOL transfers, Token-2022 extension impact, transfer fee accounting
- State Trace: cross-account state invariants, PDA state consistency, CPI state mutations, instruction ordering dependencies
- Edge Case: zero-state (empty vaults, first depositor), account initialization ordering, CU boundary testing, rent-exempt thresholds, integer cast truncation
- External: CPI side effects, program upgrade risk, instruction introspection completeness, external program behavior assumptions

## MANDATORY DEPTH DIRECTIVE (Solana examples)
1. **Boundary Substitution**: **Dual-extreme rule**: Always test BOTH the minimum AND maximum boundaries - not just one end. Also test the exact equality boundary (=) for every `>` / `<` / `>=` / `<=` comparison - off-by-one errors hide at `==`. For N-of-M selection/iteration constructs, test partial saturation states (1-of-N full, N-1-of-N full) in addition to all-empty and all-full. Examples: `[BOUNDARY:lamports=0 → account garbage collected]`, `[BOUNDARY:CU=200000 → tx fails]`, `[BOUNDARY:amount=u64::MAX → overflow if unchecked]`
2. **Parameter Variation**: `[VARIATION:bump 255→254 → different PDA address]`, `[VARIATION:mint Token→Token-2022 → transfer fee applied]`, `[VARIATION:decimals 9→0 → precision loss]`
3. **Trace to Termination**: `[TRACE:CPI→reload skipped→stale balance at L120]`, `[TRACE:close→refund→revival with zeroed data]`, `[TRACE:init ordering A before B→B reads zero state]`. **Nested call resolution**: When tracing an extraction path through an inner call (e.g., CPI, callback), also trace what happens when control returns to the OUTER calling instruction - does it perform a post-execution state check (balance comparison, total delta, require/assert) that atomically reverts the entire transaction if the extraction exceeds bounds? If yes, the extraction is bounded by that outer check, not by the inner mechanism alone. **CPI/callback exit path**: For each CPI or callback that can return control to caller, analyze BOTH: (a) state mutation during the CPI (stale data on return), AND (b) selective execution - can the callee ERROR/ABORT to reject unwanted outcomes while the caller retries until a desired outcome is achieved? Pattern: mint CPI → callback checks assigned type → abort if undesirable → retry until rare type.

4. **Root-Cause Regression**: When a finding's impact VARIES across inputs (different thresholds per token type, different timing per parameter value, different severity per state), trace backward: WHY does it vary? Follow the variance source until you reach a missing normalization, a hardcoded assumption, or an external dependency. The variance is the symptom — what causes it is the root cause. Tag: `[REGRESS:symptom→cause]`.

A finding without at least 2 depth evidence tags is INCOMPLETE and will score poorly in confidence scoring.

## EXPLOITATION TRACE MANDATE
For every Medium+ finding, produce a concrete exploitation trace: attacker action → state change → concrete profit/loss in dollar terms. 'Validation bypassed' or 'state corrupted' is NOT a terminal state — trace until tokens move to an attacker-controlled address, users lose measurable value, OR the attacker gains a privileged state that enables further exploitation (document the enabled capabilities). 'By design' and 'not exploitable' are valid conclusions ONLY after completing this trace. If you cannot construct a trace showing the defense, the finding is CONFIRMED.

## INVARIANT CONSISTENCY CHECK (HARD GATE)
For each finding you CONFIRM at Medium+ severity, you MUST:
1. Read the Operational Implications section in design_context.md
2. Check: does this finding's claimed impact contradict any documented implication?
3. If the finding claims tokens are locked, lost, or desynchronized — trace the ACTUAL token/account flow (source → destination → balance checks) and verify the claim against the documented accounting model
4. If the claim contradicts a documented implication and you cannot demonstrate with concrete code evidence why the invariant is insufficient or broken, downgrade to CONTESTED with the contradiction noted

This is a HARD GATE that applies to every Medium+ finding. You cannot CONFIRM a finding whose impact contradicts documented operational implications without explaining the contradiction with code references. "Looks suspicious" is not sufficient for CONFIRMED — trace the actual state to prove the harm.

## ANCHORING REJECTION LIST
Before marking REFUTED/CONTESTED, verify you are NOT relying on these insufficient rationalizations. If you are → upgrade to CONTESTED or complete the evidence trace:
- "Formula appears correct" → prove with boundary substitution, don't describe
- "Standard/known pattern" → standard patterns carry standard bugs; verify invariants at THIS call site
- "Tests pass" → tests miss boundary values and non-standard tokens; check what they don't cover
- "By design" → mechanism ≠ impact; trace terminal user consequence before closing
- "Unlikely to be exploited" → address with code evidence, not intuition; likelihood belongs to the severity matrix
- "Only internal accounting" → trace if consumed for transfers, mints, liquidations, or redemptions
- "All tokens use N decimals" → verify per-token; custom tokens may use different decimals

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
5. **Claim idempotency**: For each reward/fee claim instruction — verify the state marker preventing re-claiming is updated BEFORE the transfer. Can the same epoch/period be accumulated into claimable amount twice via any instruction sequence? Tag: `[TRACE:claim→state_reset→transfer vs claim→transfer→state_reset]`

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

4b. **Infrastructure PDA/account targeting**: For every public instruction that accepts a target pubkey/address parameter AND writes state keyed by that parameter (e.g., `deposit_for(target)`, `stake_for(target)`, `delegate_to(target)`): can any protocol PDA or singleton account be used as the target? If yes, what state is imposed on it, and does it break protocol operations?
   Tag: `[TRACE:attacker calls deposit_for(pool_pda, amount) → pool_pda.cooldown = now + 7d → pool operations revert for 7d]`

5. **Tainted source consumption enumeration**: When a tainted or weak input source is identified (weak RNG, manipulable oracle, user-controllable parameter), enumerate ALL instructions that consume it - not just the one where the finding was discovered. Rate the finding's severity by the WORST consumption point. A weak RNG consumed only in a view function is Low; the same RNG consumed in minting, reward selection, AND portfolio assignment may be Critical. Use grep to find all call sites of the tainted source.

## PART 2: COMBINATION DISCOVERY (SECONDARY - 20% effort)

Use breadth findings as building blocks. For each pair of findings in your domain:
1. Can Finding A's postcondition enable Finding B's missing precondition?
2. Can the combination create a new attack path neither finding describes alone?
3. Document any chain with: A → enables → B → impact

## PART 3: SECOND OPINION ON REFUTED (INDEPENDENT PROPOSAL ONLY)

For each REFUTED finding in your domain:
1. Check: did the breadth agent consider ALL enabler paths? (Rule 12 - 5 actor categories)
2. Check: was the REFUTED verdict based on [CODE] evidence, or weaker ([DOC], [MOCK])?
3. If enabler exists OR evidence is weak → upgrade to PARTIAL or CONTESTED
4. If evidence is strong AND no enabler exists, emit a
   `REFUTATION_PROPOSAL` carrying the exact premise, guard locus, paths checked,
   and evidence tags. Do not confirm terminal `REFUTED`; an independent
   discriminator must bind premise to evidence before closure.

## External Precedent Boundary (MANDATORY)
Do not call vulnerability-database, RAG, WebSearch, or WebFetch tools in this
worker. Seal findings, clears, combinations, and depth evidence from the
current code first. The driver runs a separate post-freeze precedent proposer;
external similarity can add later investigation paths but cannot validate,
refute, demote, score, or severity-rate this worker's code-derived result.

## Tool References
- This depth worker receives no MCP authority. Consume any driver-produced
  Fender/static-analysis artifacts as local files.
- Use `Read`/`Grep` for source extraction and caller/callee tracing.
- Do not perform precedent/RAG research here; the separate post-freeze
  `rag_sweep` phase owns that decision-neutral context.

## Severity / Disposition Contract (MANDATORY)

For every live finding block, `**Severity**:` MUST be exactly one canonical value:
`Critical`, `High`, `Medium`, `Low`, or `Informational`. Do not write `N/A`,
`absorbed into ...`, `REFINED`, `duplicate`, or `refuted` in the severity field.
If a candidate is absorbed/refined/not independently reportable, put that in
the Verdict or Notes/Chain Summary, not in `**Severity**`, and do not emit it as
a live finding block unless it has a canonical severity.

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

SCOPE: Write ONLY to your assigned output file. Do NOT read or write other agents' output files. Do NOT proceed to subsequent pipeline phases. Return your findings and stop.
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

## INVARIANT CONSISTENCY CHECK (HARD GATE)
For each finding you CONFIRM at Medium+ severity, you MUST check: does this finding's claimed impact contradict any Operational Implication in design_context.md? If the finding claims tokens are locked, lost, or desynchronized — trace the ACTUAL token/account flow and verify against the documented accounting model. If the claim contradicts a documented implication and you cannot demonstrate with concrete code evidence why the invariant is broken, downgrade to CONTESTED.

## EXPLOITATION TRACE MANDATE
For every Medium+ finding, produce a concrete exploitation trace: attacker action → state change → concrete profit/loss in dollar terms. Trace until tokens move, users lose measurable value, OR the attacker gains a privileged state that enables further exploitation.

## Your ONLY Task
Answer the investigation questions below using the source code.

## Investigation Questions
{INJECTABLE_QUESTIONS_FOR_THIS_DOMAIN}

For EACH question:
1. Read the referenced code location YOURSELF
2. Apply at least 2 depth techniques (BOUNDARY, VARIATION, TRACE)
3. If you find a defense mechanism (cap, bound, min/max, guard): trace each INPUT to the defense - can any input be externally manipulated to weaken it?
4. Do not call external precedent/RAG tools. Answer from current source and
   explicit execution evidence; the post-freeze precedent phase is separate.

## Output
Write to {SCRATCHPAD}/depth_{type}_injectable_findings.md:
- Findings with [DEPTH-{TYPE}-INJ-N] IDs
- Use standard finding format with Depth Evidence tags

## Chain Summary (MANDATORY)
| Finding ID | Location | Root Cause (1-line) | Verdict | Severity | Precondition Type | Postcondition Type |
|------------|----------|--------------------:|---------|----------|-------------------|-------------------|

Return: 'DONE: {N} findings from {Q} investigation questions'

SCOPE: Write ONLY to your assigned output file. Do NOT read or write other agents' output files. Do NOT proceed to subsequent pipeline phases. Return your findings and stop.
")
```
