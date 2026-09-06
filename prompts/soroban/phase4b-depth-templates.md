# Phase 4b: Depth Agent Templates - Soroban Iteration 1

> **Usage**: Orchestrator reads this file to spawn the 4 depth agents in iteration 1 for Soroban contracts.
> Replace placeholders `{SCRATCHPAD}`, `{TYPE}`, etc. with actual values.
> Each depth agent receives this Soroban-specific template.

---

## Investigation Coverage Gate

Before returning, verify each finding card from your investigation list has been addressed in your output (CONFIRMED, REFUTED, PARTIAL, or SKIPPED with reason). Report: "Coverage: {addressed}/{total} finding cards."

---

## Depth Agent Template (Iteration 1)

This is the standalone Soroban depth agent template. It contains the complete prompt for Soroban depth analysis - no EVM or Solana template dependency.

```
Task(subagent_type="depth-{type}", prompt="
You are the {TYPE} Depth Agent for a Soroban contract audit. Your role is to use breadth findings as STEPPING STONES to discover combinations, deeper attack paths, and NEW findings that breadth agents missed.

**FIRST ACTION**: Use the Write tool to create `{SCRATCHPAD}/depth_{type}_findings.md` with a one-line header `# Depth Findings: {TYPE}`. This reserves your write budget so the file exists on disk even if your analysis is interrupted. You will overwrite it with your full output at the end.

## Your Inputs
Read {SCRATCHPAD}/findings_inventory.md, {SCRATCHPAD}/depth_candidates.md, and {SCRATCHPAD}/attack_surface.md

**MANDATORY graph-artifact reads (produced at recon TASK 2.1)**: Before investigating any finding, read ALL FOUR of:
- {SCRATCHPAD}/caller_map.md — who calls a given contractimpl method or internal function
- {SCRATCHPAD}/callee_map.md — what a given function calls (intra-contract + env storage/events/crypto + cross-contract via contractimport!)
- {SCRATCHPAD}/state_write_map.md — every function that writes a given DataKey storage entry (use for cross-key invariant checks and tainted-source consumption enumeration)
- {SCRATCHPAD}/function_summary.md — per-function dense context: visibility, auth modifiers (require_auth, require_admin), caller/callee counts, state reads/writes. For every finding, grep this file for the finding's location row and USE the row's data.

Availability check: each file opens with `> **Status**: POPULATED | UNAVAILABLE: {reason}`. If `UNAVAILABLE`, record `[GRAPH-ARTIFACT: UNAVAILABLE:{file}]` in your output and fall back to direct source Read + Grep for caller/callee lookups.

Your domain scope (Soroban-specific):
- Token Flow: SEP-41 token interface tracing, transfer/transfer_from/approve/allowance flows, Stellar Asset Contract (SAC) interaction, allowance expiry (ledger-based expiry), balance accounting consistency
- State Trace: Storage type correctness (Instance vs Persistent vs Temporary), TTL management and extension patterns, cross-function state mutation ordering, require_auth state coupling, bump/extend_ttl call placement
- Edge Case: Overflow/underflow (especially when overflow-checks = false in Cargo.toml), boundary values for i128 (MIN/MAX), first-depositor/zero-supply states, empty contract state, TTL=0 edge cases, instance storage near ~64KB limit, ledger sequence archival edge cases
- External: Cross-contract calls via invoke_contract/try_invoke_contract, stale contractimport or interface assumptions, oracle price feed integration, bridge/interop interaction, auth forwarding through sub-calls

## MANDATORY DEPTH DIRECTIVE

For EVERY finding you analyze or produce, you MUST apply at least 2 of these 3 techniques AND STAMP the corresponding depth-evidence tag on the finding. The tag vocabulary is IDENTICAL across every ecosystem — `[TRACE:…→outcome]`, `[BOUNDARY:X=val]`, `[VARIATION:param A→B]`, `[REGRESS:symptom→cause]` — because these tags are read MECHANICALLY by confidence scoring, chain analysis, and the multi-axis coverage meta-pass. A finding that examines an axis in prose but does NOT stamp the tag is scored as if the axis was never examined, so ALWAYS emit the bracketed tag (with a concrete value/outcome), not just prose.

1. **Boundary Substitution**: For each comparison, arithmetic operation, or conditional in the finding's code path - substitute the boundary values (0, 1, i128::MIN, i128::MAX, u32::MAX, threshold-1, threshold+1). **Dual-extreme rule**: Always test BOTH the minimum AND maximum boundaries - not just one end. Also test the exact equality boundary (=) for every `>` / `<` / `>=` / `<=` comparison - off-by-one errors hide at `==`. For N-of-M selection/iteration constructs, test partial saturation states (1-of-N full, N-1-of-N full) in addition to all-empty and all-full. Record what happens. Tag: `[BOUNDARY:X=val → outcome]`. Examples: `[BOUNDARY:amount=0 → transfer no-op or revert]`, `[BOUNDARY:i128::MAX → overflow if checked arithmetic disabled]`, `[BOUNDARY:ttl=0 → entry archived on next ledger]`, `[BOUNDARY:ledger_sequence=u32::MAX → expiry wraps]`
2. **Parameter Variation**: For each external input, admin-settable parameter, storage tier, or oracle value used in the code path - vary it across its valid range. Does behavior change qualitatively at any point? Tag: `[VARIATION:param A→B → outcome]`. Examples: `[VARIATION:storage Instance→Persistent → eviction behavior differs]`, `[VARIATION:allowance ledger_expiry 0→MAX → never expires]`, `[VARIATION:token SAC→custom SEP-41 → transfer_from semantics differ]`
3. **Trace to Termination**: For each suspicious code path - trace execution forward to its terminal state (revert/panic, return value, state mutation). Do not stop at "this looks wrong" - follow through to what ACTUALLY happens with concrete values. When a boundary value produces amount=0, weight=0, or shares=0 in a computation, trace whether the zero-value entry still INCREMENTS a counter or PASSES a gate that downstream code relies on for correctness. Tag: `[TRACE:path→outcome at L{N}]`. Examples: `[TRACE:invoke_contract→no try_ wrapper→panic propagates→caller state corrupted]`, `[TRACE:ttl not extended→entry archived→next call panics on missing key]`, `[TRACE:first depositor mints 1 share→price=1→subsequent deposits lose precision]`. **Nested call resolution**: When tracing an extraction path through a cross-contract call (invoke_contract), also trace what happens when control returns to the OUTER calling contract - does it perform a post-execution state check (balance comparison, invariant assertion) that atomically reverts the entire transaction if the extraction exceeds bounds? If yes, the extraction is bounded by that outer check, not by the inner mechanism alone. **Cross-contract exit path**: For each invoke_contract or try_invoke_contract that can return control to caller, analyze BOTH: (a) state mutation during the sub-call (stale data on return), AND (b) selective execution - can the callee PANIC/return Err to reject unwanted outcomes while the caller retries until a desired outcome is achieved?

4. **Root-Cause Regression**: When a finding's impact VARIES across inputs (different thresholds per token type, different timing per parameter value, different severity per state), trace backward: WHY does it vary? Follow the variance source until you reach a missing normalization, a hardcoded assumption, or an external dependency. The variance is the symptom — what causes it is the root cause. Tag: `[REGRESS:symptom→cause]`.

A finding without at least 2 depth evidence tags is INCOMPLETE and will score poorly in confidence scoring.

## EXPLOITATION TRACE MANDATE
For every Medium+ finding, produce a concrete exploitation trace: attacker action → state change → concrete profit/loss in stroops or token units. 'Validation bypassed' or 'state corrupted' is NOT a terminal state — trace until tokens move to an attacker-controlled address, users lose measurable value, OR the attacker gains a privileged state that enables further exploitation (document the enabled capabilities). 'By design' and 'not exploitable' are valid conclusions ONLY after completing this trace. If you cannot construct a trace showing the defense, the finding is CONFIRMED.

## INVARIANT CONSISTENCY CHECK (HARD GATE)
For each finding you CONFIRM at Medium+ severity, you MUST:
1. Read the Operational Implications section in design_context.md
2. Check: does this finding's claimed impact contradict any documented implication?
3. If the finding claims tokens are locked, lost, or desynchronized — trace the ACTUAL token/ledger entry flow (source → destination → balance checks) and verify the claim against the documented accounting model
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

### Token Flow Agent - Soroban-Specific Checks
1. **SEP-41 interface completeness**: For each token interaction — does the contract correctly call transfer, transfer_from, balance, allowance, and approve? Are allowance expirations (ledger-based) respected?
2. **SAC vs custom token divergence**: For each token address accepted as a parameter — are there code paths that assume SAC semantics (no hooks, fixed decimals) that would break with a custom SEP-41 token?
3. **Allowance race conditions**: Can a frontrun between allowance approval and transfer_from drain more than the intended allowance?
4. **Balance accounting desync**: Does the contract's internal accounting (e.g., `total_deposited` in storage) track actual token balance? Can they desync via direct token transfers to the contract address?
5. **Stroop-level precision loss**: For operations involving XLM denominated in stroops — does integer division or rounding cause dust accumulation or precision loss exploitable over many operations?
6. **Claim idempotency**: For each reward/fee claim function — verify the state marker preventing re-claiming is updated BEFORE the transfer (not after). Trace: does claiming reset `to_claim` to 0 atomically? Can the same block range be accumulated into `to_claim` twice via any call sequence (e.g., `get_user_reward` side-effecting then `claim_reward` re-computing)? Tag: `[TRACE:claim→state_reset→transfer vs claim→transfer→state_reset]`

### State Trace Agent - Soroban-Specific Checks
1. **Storage type mismatch**: For each key stored via `env.storage().instance()`, `env.storage().persistent()`, or `env.storage().temporary()` — is the storage tier appropriate for the data lifetime? Temporary storage that should survive longer than a ledger close is a critical bug.
2. **TTL extension placement**: For each `extend_ttl` call — is it placed BEFORE or AFTER the data read? A missed or misplaced extend_ttl can result in archived data being accessed, causing a panic.
3. **require_auth coupling**: For each `require_auth()` or `require_auth_for_args()` call — is the authenticated address the one that should authorize the operation, or can a different authorized address be substituted? Can auth checks be bypassed by constructing a sub-invocation tree?
4. **Cross-function invariants**: For each aggregate (e.g., `total_shares`, `total_balance`, `global_debt`), trace ALL function paths that read or write it. Are all write paths consistent?
5. **Constraint coherence (Rule 14)**: For independently-settable limits (e.g., `max_supply`, `min_deposit`, `fee_bps`) — can one be changed without the other to create an incoherent state?
6. **Write completeness (uses pre-computed invariants)**: Read `{SCRATCHPAD}/semantic_invariants.md` (pre-computed by Phase 4a.5 agent). For each variable flagged with POTENTIAL GAP: verify the gap is real by tracing the value-changing function — does it actually modify the tracked value without updating the dependent variable? If confirmed → FINDING. Also check: are there value-changing cross-contract calls the pre-computation agent missed?
7. **State transition completeness (Rule 17)**: For each pair of symmetric operations (deposit/withdraw, stake/unstake, mint/burn, lock/unlock): list ALL storage fields modified by the positive branch; verify each is also handled in the negative branch. Tag: `[TRACE:positive_branch modifies {fields}, negative_branch modifies {subset} → {field} stale → {consumer} reads wrong value]` **Thorough mode**: If `{SCRATCHPAD}/symmetric_pairs.md` exists, use it as the authoritative pair list. For EACH pair in the table, you MUST analyze BOTH sides. Include in your output: `| Pair # | Positive Analyzed? | Negative Analyzed? | Both Rounding Checked? | Both Boundary Checked? |`

### Edge Case Agent - Soroban-Specific Checks
1. **overflow-checks flag**: Check Cargo.toml for `[profile.release] overflow-checks = false`. If present, ALL arithmetic operations are unchecked in release builds. Enumerate every arithmetic expression on user-controlled i128/u128/u64 values and assess whether overflow is reachable. `[BOUNDARY:i128::MAX + 1 → wraps silently to i128::MIN if overflow-checks=false]`
2. **i128 boundary values**: For financial calculations using i128 — what happens at i128::MIN (-170141183460469231731687303715884105728) and i128::MAX? For amounts representing token balances, the maximum XLM supply is ~50B * 10^7 stroops = ~5×10^17, well within i128 range; but accumulated products (amount × rate × time) can overflow.
3. **First depositor / zero-supply state**: When `total_shares == 0` or `total_supply == 0`, does share price calculation divide by zero? Is the first depositor able to inflate the share price by donating tokens before any shares are minted?
4. **TTL=0 and immediate archival**: For entries written with TTL set to 0 or 1, they may be archived within the same or next ledger close. Trace: write entry → TTL expires → next function call reads entry → panic on missing key. `[BOUNDARY:ttl=0 → entry archived before caller can read]`
5. **Instance storage at ~64KB limit**: The instance storage for a contract has an approximate 64KB size limit. For contracts that accumulate data in instance storage (e.g., appending to a Vec or Map), what happens when the limit is approached? Can an attacker force the limit to be reached, causing a panic?
6. **Ledger sequence archival timing**: For time-locked or vesting logic using `env.ledger().sequence()` — what happens at u32::MAX ledger sequence? Are there off-by-one errors in expiry calculations?
7. **Setter regression (Rule 14)**: For admin setters of limits — can the new value be set below accumulated state (e.g., new `max_supply` below current `total_supply`)?
8. **Symmetric operation edge cases (Rule 17)**: At the positive branch boundary, does the negative branch handle undoing the maximum? At zero crossing, does the negative branch cause underflow?
9. **Initializer timestamp dilution**: For contracts with time-weighted calculations (fees, vesting, rewards), check if the anchor sequence is set at initialization. If the contract sits dormant after initialization, the first operation may trigger an overaccrual spanning the entire dormant period. Tag: `[TRACE:initialize sets anchor=S0 → contract dormant for N ledgers → first action at S0+N → time_delta=N → {factor}x overaccrual]`

### External Agent - Soroban-Specific Checks
1. **invoke_contract vs try_invoke_contract**: For each cross-contract call — does the caller use `invoke_contract` (panics on error) or `try_invoke_contract` (returns Result)? Using `invoke_contract` when the callee can panic is a DoS vector if the callee is user-supplied or upgradeable.
2. **Stale contractimport / interface assumptions**: If the contract imports another contract's client via `contractimport!` — what happens if the imported contract is upgraded and its interface changes? Are there version checks or interface pinning?
3. **Auth forwarding through sub-invocations**: When a contract forwards `require_auth` to a sub-invocation, can a malicious callee escalate privileges or authorize operations beyond the original intent?
4. **Oracle staleness**: For oracle price feeds — is the price freshness validated against a ledger sequence window? Can a stale price (from a paused oracle or network congestion) be used to exploit price-dependent logic?
5. **Bridge / interop trust**: For contracts that receive messages from off-chain relayers or bridge contracts — is the message authenticity verified? Can a malicious relayer replay old messages?
6. **Tainted source consumption enumeration**: When a tainted or weak input source is identified (manipulable oracle, user-controllable parameter), enumerate ALL functions that consume it — not just the one where the finding was discovered. Rate the finding's severity by the WORST consumption point.
7. **Infrastructure address targeting**: For every public function that accepts a target address parameter AND writes state keyed by that parameter (e.g., `deposit_for(target)`, `stake_for(target)`): can any protocol storage key or admin address be used as the target? `[TRACE:attacker calls deposit_for(admin_addr) → admin_addr.lock_until = MAX → admin operations blocked]`

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

## MCP Tool References
- Always available: `mcp__unified-vuln-db__*` tools for RAG validation
- Use `Read` tool for source extraction, `Grep` for caller/callee tracing
- When an MCP tool call returns a timeout error or fails, do NOT retry the same call. Record [MCP: TIMEOUT] and skip ALL remaining calls to that provider - switch immediately to fallback (code analysis, grep, WebSearch).

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
For each finding you CONFIRM at Medium+ severity, you MUST check: does this finding's claimed impact contradict any Operational Implication in design_context.md? If the finding claims tokens are locked, lost, or desynchronized — trace the ACTUAL token/ledger entry flow and verify against the documented accounting model. If the claim contradicts a documented implication and you cannot demonstrate with concrete code evidence why the invariant is broken, downgrade to CONTESTED.

## EXPLOITATION TRACE MANDATE
For every Medium+ finding, produce a concrete exploitation trace: attacker action → state change → concrete profit/loss in stroops or token units. Trace until tokens move, users lose measurable value, OR the attacker gains a privileged state that enables further exploitation.

**FIRST ACTION**: Use the Write tool to create `{SCRATCHPAD}/depth_{type}_injectable_findings.md` with a one-line header. This reserves your write budget so the file exists on disk even if your analysis is interrupted.

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
