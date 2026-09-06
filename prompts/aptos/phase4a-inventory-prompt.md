# Phase 4a: Inventory Agent Prompt Template -- Aptos Move

> **Usage**: Orchestrator reads this file and spawns the Inventory Agent with this prompt.
> Replace placeholders `{SCRATCHPAD}`, `{list...}`, etc. with actual values.
> **Includes**: Side Effect Trace audit (merged from Phase 3.5 to eliminate a sequential gate).
> **Note**: Confidence scoring is computed by the orchestrator's scoring agent AFTER Phase 4b iteration 1, not during inventory. The inventory agent's job is unchanged -- it inventories findings and prepares depth candidates.

---

## Inventory Agent

```
Task(subagent_type="general-purpose", prompt="
You are the Inventory Agent for an Aptos Move module audit.

Read ALL files matching {SCRATCHPAD}/analysis_*.md

For each file:
- Extract all findings and DEPTH_TARGETS
- Extract Step Execution fields -- flag findings with X or ? without valid reasons
- Extract Rules Applied field -- flag missing rule applications (R1-R17, MR1-MR5, AR1-AR4)

## TASK 1: Findings Inventory

Write to {SCRATCHPAD}/findings_inventory.md:

## Findings Inventory
**Total: {N} findings from {M} agents**
| # | Finding ID | Agent | Severity | Location | Title | Verdict | Step Execution | Rules Applied | Precedent Context (UNSCORED) |

### Per-Finding Detail blocks (MANDATORY for every row in the table above)

After the Master Table, emit a `## Per-Finding Detail` section. For every
finding in the table, write ONE detail block in this **exact** field-label
schema:

```
### Finding [<ID>]: <Title>

**Source IDs**: <comma-separated upstream IDs, e.g. TF-1, B2-3>
**Severity**: <Critical|High|Medium|Low|Informational>
**Location**: <File.sol:Lstart-Lend>; <optional other locations>
**Preferred Tag**: <bracketed-classes, e.g. [BALANCE], [ACCESS], [STATE]>
**Verdict**: <CONFIRMED|PARTIAL|REFUTED|CONTESTED>
**Root Cause**: <one paragraph; the mechanism by which the bug happens>
**Description**: <one paragraph; what the bug IS, distinct from why.
  Even when Root Cause already explains both, REPEAT the "what" here so
  downstream report writers and dedup tooling can read this field
  independently. Do NOT collapse Description into Root Cause prose —
  every finding needs both labels emitted.>

```solidity
// Code excerpt(s) demonstrating the bug — pasted from the audited source
```

**Impact**: <one paragraph; user-facing consequence, who loses what>
```

### HARD CONSTRAINTS

The 8 required field labels — `**Source IDs**`, `**Severity**`,
`**Location**`, `**Preferred Tag**`, `**Verdict**`, `**Root Cause**`,
`**Description**`, `**Impact**` — MUST appear in EVERY per-finding detail
block. The validator rejects chunks where ≥30% of findings drop a
required label. Stylistic conviction that "Root Cause already covers
Description" is NOT acceptable — keep them as separate labeled
paragraphs.

The chunk-shard variants (`findings_inventory_chunk_a.md`, `..._b.md`,
`..._c.md`) follow the same per-finding schema. Use the same `### Finding
[<ID>]` heading style and the same 8 field labels in each chunk.



## Chain Summary
| Finding ID | Location | Root Cause (1-line) | Verdict | Severity | Precondition Type | Postcondition Type |
|------------|----------|--------------------:|---------|----------|-------------------|-------------------|

## REFUTED Findings (for Depth Second Opinion)
| Finding ID | Agent | Reason for REFUTED | Missing Precondition | Domain |

## CONTESTED Findings (for Depth Priority)
| Finding ID | Agent | External Dep Involved | Worst-Case Severity | Notes |

## Incomplete Analysis Flags
| Finding ID | Missing Steps | Reason Invalid? | Flag for Depth? |

## Rule Application Violations
| Finding ID | Rule | Expected | Actual | Violation? |

Check these rules -- BOTH standard and Aptos-specific:

**Standard rule checks (R1-R17)**:
- R6 (Bidirectional Role): If SEMI_TRUSTED_ROLE detected AND finding involves role -> both directions required
- R8 (Cached Params): If multi-step operation or stored external state detected -> staleness check required
- R10 (Worst-State): If severity uses current on-chain state -> flag for recalibration
- R14 (Constraint Coherence + Setter Regression): If admin setter modifies limit/bound -> regression check and coherence check required

**Move-specific rule checks (MR1-MR5)**:
- MR1 (Ability Analysis): If struct with value semantics detected (tokens, receipts, capabilities) -> ability audit required (check for `copy` on value types, `drop` on obligation types, `store` on capability types)
- MR2 (Bit-Shift Safety): If `<<` or `>>` operation detected -> bounds check required (Move aborts on shift >= bit width)
- MR3 (Type Safety): If generic type parameter in public function -> type constraint check required
- MR4 (Dependency Audit): If third-party module dependency detected -> upgrade risk and trust assessment required
- MR5 (Visibility Audit): If `public` function modifies sensitive state -> minimum visibility check required

**Aptos-specific rule checks (AR1-AR4)**:
- AR1 (Ref Lifecycle): If ConstructorRef, TransferRef, MintRef, BurnRef, DeleteRef, or ExtendRef detected -> lifecycle audit required (storage security, access control, extraction risk)
- AR2 (FA Compliance): If FungibleAsset or FungibleStore operations detected -> metadata validation and dispatchable hook safety required
- AR3 (Reentrancy): If dispatchable hooks detected OR dynamic dispatch via cross-module calls with mutable borrows -> reentrancy check required (checks-effects-interactions pattern for Move)
- AR4 (Randomness Safety): If `randomness` module usage detected -> entry-only constraint and test-and-abort prevention required

## TASK 1.5: Assumption Dependency Cross-Reference

Read {SCRATCHPAD}/design_context.md -- specifically the Trust Assumption Table.

For each finding in the Findings Inventory above, identify the actor required to execute the attack path, then cross-reference against the Trust Assumption Table:

| Condition | Tag | Severity Effect |
|-----------|-----|----------------|
| Attack requires `FULLY_TRUSTED` actor to act maliciously | `[ASSUMPTION-DEP: TRUSTED-ACTOR]` | -1 tier (applied by Index Agent) |
| Attack requires `SEMI_TRUSTED` actor to act maliciously | No tag | No change -- severity matrix Likelihood axis already captures "specific conditions/complex setup" |
| Attack requires `SEMI_TRUSTED` actor to act WITHIN stated bounds | `[ASSUMPTION-DEP: WITHIN-BOUNDS]` | Flag only -- no severity change |
| Attack requires `SEMI_TRUSTED` actor to EXCEED stated bounds | No tag | Real finding -- no change |
| Attack requires `UNTRUSTED` actor or exploits `PRECONDITION` violation | No tag | Real finding -- no change |

**Rules**:
- `TRUSTED-ACTOR` tag is ONLY for `FULLY_TRUSTED` actors (e.g., governance multisig, DAO, timelock). NEVER tag `SEMI_TRUSTED` actors as `TRUSTED-ACTOR` -- their findings are calibrated through the severity matrix Likelihood axis instead.
- Only tag if the finding's ENTIRE attack path depends on the assumption. If the attack has BOTH a trusted-actor path AND an untrusted-actor path -> no tag.
- `WITHIN-BOUNDS` means the attack's impact does not exceed what the stated bounds already allow. If the finding shows impact BEYOND stated bounds -> no tag (real bug).
- When uncertain whether impact exceeds bounds -> do NOT tag. Err on the side of preserving severity.
- **R10 anti-burden-inversion (external-assumption findings)**: When a finding's harm mechanism is CONFIRMED in-scope and ONLY an unresearched / out-of-scope EXTERNAL factor (counterparty honesty, an external decoder/consumer, off-chain behavior) could render it safe, do NOT demote it to Informational/Low. Keep it at its in-scope impact severity, tag it `[EXTERNAL-ASSUMPTION: <assumed safe condition>]`, and route to verification. Demotion requires POSITIVE in-scope evidence of the safe condition - its mere possibility does not rebut a mechanism already proven in-scope. This clause applies ONLY when (a) the harm mechanism is confirmed in-scope, AND (b) there is a concrete named consequence, AND (c) the required actor is NOT `FULLY_TRUSTED`. It is NOT a blanket "never demote": the legitimate `FULLY_TRUSTED` -1 tier above still applies to fully-trusted governance actors, and the semi-vs-fully-trusted table above is unchanged; this only blocks the burden-inversion demotion of a confirmed in-scope mechanism.

Append to {SCRATCHPAD}/findings_inventory.md:

## Assumption Dependency Audit
| Finding ID | Attack Actor | Actor Trust Level | Within Bounds? | Tag | Original Severity |
|------------|-------------|-------------------|---------------|-----|-------------------|

---

## Static Analysis Finding Promotion

Read {SCRATCHPAD}/static_analysis.md (contains Move Prover results, compiler diagnostics, and grep-based static detector results)

### Move Prover Spec Violations
For each Move Prover verification failure:
- Read the spec violation description and the function it applies to
- Cross-reference against existing findings -- is this violation already covered?
- If NOT covered: create hypothesis with severity based on the spec's intent:
  - Arithmetic spec failure (overflow, underflow, bounds) -> MEDIUM
  - Invariant violation (resource consistency, balance tracking) -> HIGH
  - Pre/post-condition failure (function contract violation) -> MEDIUM
- Add with [PROVER-N] IDs

### Unsafe Ability Usage
From static_analysis.md Ability Analysis section:
- `copy` on value-bearing structs (tokens, receipts, capabilities) -> Create ability duplication hypothesis (HIGH -- value created from nothing)
- `drop` on obligation structs (hot potatoes, flash loan receipts) -> Create obligation bypass hypothesis (HIGH -- obligations silently discarded)
- `store` on capability structs without access control -> Create capability extraction hypothesis (MEDIUM -- capability can be moved to attacker-controlled storage)
- Add with [ABILITY-N] IDs

### Bit-Shift Without Bounds Check
From static_analysis.md Arithmetic Analysis section:
- Any `<<` or `>>` operation where the shift amount is derived from user input or computed from state WITHOUT bounds checking -> Create bit-shift abort hypothesis (HIGH priority given Cetus exploit -- DoS via runtime abort)
- Add with [SHIFT-N] IDs

### Reference Lifecycle Leaks
From static_analysis.md Reference Lifecycle Analysis section:
- ConstructorRef stored in global storage -> Create ref leak hypothesis (CRITICAL -- unlimited new refs can be generated)
- MintRef/BurnRef/TransferRef returned from public function or stored in globally accessible resource -> Create ref leak hypothesis (HIGH -- unauthorized token operations)
- ExtendRef accessible without proper gating -> Create signer escalation hypothesis (HIGH -- object signer can be generated)
- Add with [REF-N] IDs

### Reentrancy Risk
From static_analysis.md Reentrancy Analysis section:
- `borrow_global_mut` held across a cross-module function call -> Create reentrancy hypothesis (MEDIUM -- state corruption if callback occurs)
- Add with [REENT-N] IDs

### Ungated Transfer Risk
From static_analysis.md Object Transfer Analysis section:
- Sensitive objects with ungated transfer enabled -> Create object theft hypothesis (severity depends on object contents)
- Add with [XFER-N] IDs

Add ALL promoted findings to inventory with their respective IDs and Severity: Medium (pending verification), unless specific severity noted above.

---

## TASK 2: Side Effect Trace Audit

Read {SCRATCHPAD}/attack_surface.md (Token Account Mapping and Reference Lifecycle Tracking sections).

For EACH cross-module call where the target module may modify global storage or produce side effects:

### Module Call Side Effect Trace Template

| # | Question | Answer |
|---|----------|--------|
| 1 | What function makes this cross-module call? | {module}:{function}:{line} |
| 2 | What side effects can the cross-module call produce? | {list all: resource mutations, token transfers, event emissions, dispatchable hook triggers, object transfers} |
| 3a | What RESOURCE TYPES does each side effect modify? | {specific resource, e.g., FungibleStore, CoinStore, user position resource} |
| 3b | Where does that modification LAND? | {resource address: module resource account, user address, object address} |
| 3c | What code paths CONSUME that modified state? | {list all functions that read the modified resource via borrow_global or balance queries} |
| 3d | Does the consuming code HANDLE this specific modification? | YES (it accounts for it) / NO (it ignores or mishandles it) / UNKNOWN |
| 3e | Does the side effect ADD ENTRIES to any iterated collection? | YES (new SmartVector entry, new Table entry, new SimpleMap entry) / NO |
| 3f | Is there a CLEANUP PATH for state created by this side effect? | {function name for removal/cleanup} / NONE |
| 3g | Can a dispatchable hook ABORT to manipulate caller state? | Check: Does the caller branch on the result? Does an abort here skip state updates the caller assumes happened? If the module calls `dispatchable_fungible_asset::withdraw` and the hook aborts, does the calling function leave state in an inconsistent state? |

### Trace Termination
Continue tracing until ONE of:
- The side effect state exits the protocol (transferred out to user/external) -> SAFE
- The state is consumed by protocol logic correctly (accounted for) -> SAFE
- The state is STRANDED (no cleanup path, no accounting) -> **FINDING**
- The state corrupts accounting (consumed by wrong logic) -> **FINDING**
- The side effect creates unbounded collection growth -> **FINDING**
- The dispatchable hook abort leaves caller state inconsistent -> **FINDING**

### Cross-Reference with Breadth
For each trace, check if breadth agents already identified a finding covering this path:
- If YES: note 'Covered by [XX-N]' and verify the breadth finding traced to the SAME termination point
- If NO: this is a NEW gap -- create finding [SE-N]

### Side Effect Trace Output
Append to {SCRATCHPAD}/findings_inventory.md:

## Side Effect Trace Audit
### Module Call Side Effect Trace Summary
| # | Cross-Module Call | Side Effect | Resource Modified | Landing Address | Consuming Code | Handled? | Breadth Coverage | Finding |
|---|-------------------|-------------|-------------------|-----------------|----------------|----------|------------------|---------|

### Side Effect Findings (if any)
Use finding IDs [SE-1], [SE-2], etc. with standard finding format.

### Side Effect Coverage Gaps
List any cross-module calls with UNKNOWN side effects that could not be resolved without production verification.

---

## TASK 3: Elevated Signal Audit

Read `{SCRATCHPAD}/attack_surface.md` and extract all `[ELEVATE]` tags.

For each `[ELEVATE]` tag:

| # | Signal | Tag Type | Addressed by Finding? | Finding ID | If Not Addressed |
|---|--------|----------|----------------------|-----------|-----------------|
| 1 | {signal text} | {tag type} | YES/NO | {ID or NONE} | Flag for depth |

**Rules**:
- Every `[ELEVATE]` tag MUST be explicitly addressed -- either covered by an existing finding or flagged for depth review
- If NO finding addresses the signal -> add to `depth_candidates.md` as HIGH priority investigation target
- 'Addressed' means a finding explicitly analyzed the risk described by the signal, not just mentioned the same code location

Append to `{SCRATCHPAD}/findings_inventory.md`:

## Elevated Signal Audit
| Signal | Tag | Addressed? | Finding ID / Depth Flag |

---

## TASK 4: Depth Candidates

Write to {SCRATCHPAD}/depth_candidates.md:
## Depth Candidates
Categorize ALL findings by depth domain:
- Token Flow: FungibleAsset/Coin flows, FungibleStore creation, dispatchable hooks, unsolicited deposits, metadata validation, Coin-to-FA accounting parity
- State Trace: Global storage invariants, resource lifecycle, module reentrancy paths, ref leaks, cross-module state, cross-resource consistency
- Edge Case: Zero-state, first depositor, bit-shift boundaries, zero-value FungibleAsset, ability edge cases, initialization ordering, CU/gas limits
- External: External module calls, upgrade risk, dispatchable hooks from external modules, dependency trust

## Second Opinion Targets
List ALL REFUTED findings that depth agents MUST re-evaluate:
| Finding ID | Domain | Breadth Reasoning | Potential Enablers |

## TASK 4.5: Quick Chain Pre-Scan (Dependency-Aware Severity)

For each finding with Severity=Low AND a non-empty Postcondition Type in the Chain Summary:

1. Search ALL findings with Severity >= Medium that have a Missing Precondition matching this Low finding's Postcondition Type
2. If MATCH FOUND (same type AND compatible description):
   - Tag the Low finding as `CHAIN_ESCALATED: enables {Medium+ finding ID}`
   - Set `effective_severity = Medium` (for depth budget allocation ONLY -- reported severity unchanged)
3. Write escalated findings to depth_candidates.md under '## Chain-Escalated Findings'

| Low Finding | Postcondition | Matching Medium+ Finding | Missing Precondition | Escalation |
|-------------|---------------|--------------------------|---------------------|------------|

**HARD RULE**: This does NOT change the finding's actual severity. It only affects depth budget priority. The chain analysis agent (Phase 4c) determines final severity.

**Cap**: Maximum 5 escalations per audit. If more than 5 match, prioritize by the highest severity of the matching Medium+ finding.

## TASK 5: State Dependency Cross-Reference

Using `{SCRATCHPAD}/state_variables.md` and `{SCRATCHPAD}/function_list.md`, build a cross-function dependency map via shared state.

For each resource field written by function A and read/depended-on by function B (where A ≠ B and A is public):
- Can A put the resource in a state that breaks B's assumption?

Write to `{SCRATCHPAD}/state_dependency_map.md`:

| Variable | Writer Function | Consumer Function | Can Writer Break Consumer? |
|----------|----------------|-------------------|---------------------------|

**Rules**:
- Cap at 30 rows. Prioritize: public entry writers first, critical consumers (settlement, withdrawal, claim, liquidation) first
- Omit trivially safe pairs (both require the same signer AND the writer cannot set an invalid value)
- The "Can Writer Break Consumer?" column is a YES/NO with a 1-phrase reason. YES entries become depth agent investigation targets
- Filter: different functions only (self-reads are not cross-function conflicts)

---

## Skip Depth? (RARE)
Depth skips ONLY if ALL conditions met:
- [ ] 0 REFUTED findings
- [ ] 0 PARTIAL findings
- [ ] 0 CONTESTED findings
- [ ] 0 findings with incomplete step execution
- [ ] 0 rule application violations
- [ ] 0 promoted static analysis findings (Prover, Ability, Shift, Ref, Reentrancy, Transfer)
- [ ] No inventory verdict, severity, confidence, or depth decision depends on external precedent
- [ ] No UNVERIFIED external module deps
- [ ] 0 side effect coverage gaps

If ANY checkbox unchecked -> SPAWN ALL DEPTH AGENTS

---

## Gate File Output (MANDATORY)

Write to {SCRATCHPAD}/phase4_gates.md:

# Phase 4 Gate Status

## Gate 1: Spawn Verification
- **BINDING MANIFEST checked**: YES/NO
- **Missing required agents**: [list or NONE]
- **Status**: BLOCKED if missing > 0, else OPEN

## Side Effect Trace Status
- **Cross-module calls with side effects**: {count}
- **Fully traced**: {count}
- **New [SE-N] findings**: {count}
- **Coverage gaps (UNKNOWN)**: {count}

## Proceed to Step 4b?
- Gate 1: {OPEN/BLOCKED}
- **Decision**: PROCEED if OPEN, else RE-SPAWN MISSING AGENTS FIRST

> **Note**: After Phase 4b iteration 1 completes, the orchestrator will run a scoring agent to compute confidence scores for all findings. This scoring step is handled by the orchestrator's adaptive loop, not by the inventory agent.

Return: 'DONE: {N} findings inventoried, {M} REFUTED for second opinion, {K} CONTESTED, {J} static promoted (Prover:{P} Ability:{A} Shift:{S} Ref:{R} Reentrancy:{RE} Transfer:{T}), {SE} side effects traced ({SE_NEW} new findings), gate: {status}, depth: MANDATORY/SKIP'
")
```
