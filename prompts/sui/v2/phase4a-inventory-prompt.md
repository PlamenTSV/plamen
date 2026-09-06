# Phase 4a Inventory Agent (SUI)

You are the Inventory Agent for a Sui Move audit. You inventory ALL breadth findings AND audit side effect trace coverage in a single pass.
Execute the instructions below directly and stop. Do not spawn subagents.

> **Note**: Confidence scoring is computed by the `confidence` phase
> AFTER Phase 4b iteration 1, not during inventory. Your job is to
> inventory findings and prepare depth candidates.

---

Read ALL files matching {SCRATCHPAD}/analysis_*.md
Before parsing, build and record an explicit source-file manifest:
- List every existing first-pass `analysis_*.md` file.
- Include `analysis_rescan_*.md` and `analysis_percontract_*.md` if they exist;
  they are discovery producer outputs consumed by inventory, not later phases.
- Exclude report, verification, chain, depth, and non-discovery artifacts even
  if their names are mentioned in prose.
- In `## Source Summary`, include one row per source file with the number of
  finding blocks parsed from that exact file.
- The merge receipt/source summary must account for every parsed source finding
  block. Do not return until parsed source blocks, source summary counts, and
  inventory finding blocks reconcile.

For each file:
- Extract all findings from ## FINDING INDEX or scan for [{XX}-N] patterns
- Extract ## DEPTH_TARGETS section
- Extract Step Execution fields -- flag findings with X or ? without valid reasons
- Extract Rules Applied field -- flag missing rule applications

## TASK 1: Findings Inventory

Write to {SCRATCHPAD}/findings_inventory.md:
## Findings Inventory
**Total: {N} findings from {M} agents**
| # | Finding ID | Agent | Severity | Location | Title | Verdict | Step Execution | Rules Applied | Precedent Context (UNSCORED) |

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
Check these rules:
- R6 (Bidirectional Role): If SEMI_TRUSTED_ROLE detected AND finding involves capability holder -> both directions required
- R8 (Cached Params): If multi-step operation or multi-transaction flow detected -> staleness check required
- R10 (Worst-State): If severity uses current on-chain state -> flag for recalibration
- R14 (Constraint Coherence + Setter Regression): If admin setter modifies limit/bound -> regression check and coherence check required
- MR1 (Ability Analysis): If struct has `key` or `store` or value fields -> ability audit required. If finding involves a struct and does not confirm ability appropriateness -> VIOLATION
- MR2 (Bit-Shift Safety): If `<<` or `>>` operator found in finding's code path -> bounds check on shift amount required. If no bounds check documented -> VIOLATION
- SR1 (Object Ownership): If finding involves a shared object or a capability like `AdminCap` with `store` -> ownership model audit required. If shared object has unguarded mutation and finding does not address it -> VIOLATION
- SR2 (PTB Composability): If finding involves a `public` or `entry` function that modifies shared state -> PTB composition check required. If multi-step composition not considered -> VIOLATION
- SR3 (Package Version): If `UpgradeCap` detected and finding involves dependency behavior -> version safety check required
- SR4 (Hot Potato): If finding involves a struct with zero abilities -> consumption enforcement check required. If not all consumption paths documented -> VIOLATION

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

## Sui-Specific Static Finding Promotion

Read {SCRATCHPAD}/static_analysis.md
For each detector finding:
- UNSAFE_COPY_ON_VALUE -> Create VALUE_TOKEN_COPY hypothesis (Critical -- copy on value-bearing struct enables duplication)
- UNSAFE_DROP_ON_OBLIGATION -> Create OBLIGATION_BYPASS hypothesis (High -- drop on receipt/obligation struct enables skipping required action)
- BIT_SHIFT_RISK -> Create BIT_SHIFT_DOS hypothesis (High priority -- shift by >= type width causes Move VM abort, DoS vector). Trace shift amount to source: if user-controlled or computed without bounds check -> HIGH, if constant -> likely safe but verify.
- UNCHECKED_DESTROY_ZERO -> Create ABORT_DOS hypothesis (Medium -- `balance::destroy_zero` without preceding zero check will abort if non-zero)
- ORPHANED_OBJECT_RISK -> Create RESOURCE_LEAK hypothesis (Medium -- object::new without transfer/share/freeze/delete)
- ORPHANED_DYNAMIC_FIELDS -> Create STRANDED_ASSET hypothesis (Medium -- dynamic fields surviving parent deletion are permanently inaccessible; Rule 9 applies)
- UNBOUNDED_LOOP + VECTOR_LOOP -> Check if loop iterates over any growable vector. If user-controllable growth -> GAS_DOS hypothesis (Medium). If admin-controlled -> check if deletion leaves gaps (e.g., `vector::swap_remove` changes order, sentinel values).
- SHARED_OBJECT_CREATION in non-init contexts -> Create SHARED_OBJECT_FRONTRUN hypothesis (Medium -- shared objects created outside init may allow front-running)
- UNRESTRICTED_STORE on capability structs -> Create CAPABILITY_TRANSFER hypothesis (Medium -- capability with `store` can be transferred to unauthorized parties)
- BUILD WARNINGS -> For each compilation warning from build_status.md: create hypothesis if the warning relates to unused results, unassigned values, or deprecated patterns
- UNSAFE_CAST -> Create TRUNCATION_OVERFLOW hypothesis (Medium -- casting between u64/u128/u256/u8 may truncate or lose precision in critical arithmetic)

Add promoted findings to inventory with [STATIC-N] IDs and Severity as noted above (pending verification).

---

## TASK 2: Side Effect Trace Audit

Read {SCRATCHPAD}/attack_surface.md (Object Inventory Matrix, Token/Coin Mapping -- look for external package calls and unsolicited transfer vectors).

For Sui Move, side effects come from:
- Object transfers via `transfer::public_transfer` or `transfer::transfer` (object moves to new owner)
- Dynamic field mutations (adding/removing fields on shared objects)
- External module calls that modify state on shared objects
- Coin operations (`coin::split`, `coin::join`, `coin::into_balance`, `balance::join`) that change Balance values
- Event emissions that affect off-chain indexers

For EACH external module call or object transfer where the protocol relies on state consistency, cross-reference against the breadth analysis files you already read:

### Trace Template (fill for each side effect)

| # | Question | Answer |
|---|----------|--------|
| 1 | What function triggers this external interaction? | {module}::{function}::{line} |
| 2 | What side effects can the external call produce? | {list all: state changes on shared objects, Balance modifications, object transfers, events, dynamic field mutations} |
| 3a | What OBJECT or VALUE does each side effect produce/modify? | {specific object type, e.g., Coin<SUI>, Balance<T>, shared pool state} |
| 3b | Where does that object/value LAND? | {shared object field, function return value, transferred to address, dynamic field on parent} |
| 3c | What code paths CONSUME that landing location? | {list all functions that read balance::value() or borrow the modified object} |
| 3d | Does the consuming code HANDLE this specific object/value type correctly? | YES (it processes it) / NO (it ignores or mishandles it) / UNKNOWN |
| 3e | Does the side effect ADD ENTRIES to any dynamic field set or vector? | YES (new dynamic field, new vector entry) / NO |
| 3f | Is there an EXIT PATH for this object/value if it lands in the protocol? | {function name} / NONE |
| 3g | Can the external call ABORT to manipulate caller state? | Check: Does the caller branch on abort/success of this call? Does an abort here skip state updates the caller assumes happened? If YES -> trace what state the caller leaves in on abort vs success. In Sui Move, aborts in external calls abort the entire transaction unless using option-returning patterns. |

### Trace Termination
Continue tracing until ONE of:
- The object/value exits the protocol (transferred out to user/external address)
- The object/value is consumed by protocol logic correctly (accounted for, Balance joined, object destroyed)
- The object/value is STRANDED (no exit path, no accounting) -> **FINDING**
- The object/value corrupts accounting (consumed by wrong logic, Balance mismatch) -> **FINDING**
- The side effect creates unbounded dynamic field growth -> **FINDING**
- The external call abort causes incomplete state update in caller -> **FINDING**

### Cross-Reference with Breadth
For each trace, check if breadth agents already identified a finding covering this path:
- If YES: note 'Covered by [XX-N]' and verify the breadth finding traced to the SAME termination point
- If NO: this is a NEW gap -- create finding [SE-N]

### Side Effect Trace Output
Append to {SCRATCHPAD}/findings_inventory.md:

## Side Effect Trace Audit
### Side Effect Trace Summary
| # | External Call/Transfer | Side Effect | Object/Value Type | Landing | Consuming Code | Handled? | Breadth Coverage | Finding |
|---|----------------------|-------------|-------------------|---------|----------------|----------|------------------|---------|

### Side Effect Findings (if any)
Use finding IDs [SE-1], [SE-2], etc. with standard finding format.

### Side Effect Coverage Gaps
List any interactions that could not be resolved without production verification (e.g., behavior of upgradeable external packages).

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
- Token Flow: Coin<T>/Balance<T> flows, donation vectors, unsolicited coin transfers, balance accounting
- State Trace: Object state invariants, cross-object state, shared object mutations, UID lifecycle, dynamic field integrity, version consistency
- Edge Case: Zero-state, first depositor, bit-shift boundaries, shared object creation races, gas budget limits, PTB command limits
- External: External package calls, package versioning, shared object contention, dependency trust, upgrade compatibility

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

For each object field written by function A and read/depended-on by function B (where A â‰  B and A is public):
- Can A put the object in a state that breaks B's assumption?

Write to `{SCRATCHPAD}/state_dependency_map.md`:

| Variable | Writer Function | Consumer Function | Can Writer Break Consumer? |
|----------|----------------|-------------------|---------------------------|

**Rules**:
- Cap at 30 rows. Prioritize: public entry writers first, critical consumers (settlement, withdrawal, claim, liquidation) first
- Omit trivially safe pairs (both require the same capability AND the writer cannot set an invalid value)
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
- [ ] 0 promoted static findings
- [ ] No inventory verdict, severity, confidence, or depth decision depends on external precedent
- [ ] No UNVERIFIED external packages
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
- **Objects/values with external interactions**: {count}
- **Fully traced**: {count}
- **New [SE-N] findings**: {count}
- **Coverage gaps (UNKNOWN)**: {count}

## Proceed to Step 4b?
- Gate 1: {OPEN/BLOCKED}
- **Decision**: PROCEED if OPEN, else RE-SPAWN MISSING AGENTS FIRST

> **Note**: After Phase 4b iteration 1 completes, the orchestrator will run a scoring agent to compute confidence scores for all findings. This scoring step is handled by the orchestrator's adaptive loop, not by the inventory agent.

Return: 'DONE: {N} findings inventoried, {M} REFUTED for second opinion, {K} CONTESTED, {J} static promoted, {S} side effects traced ({SE} new findings), gate: {status}, depth: MANDATORY/SKIP'

---

SCOPE: Write ONLY to `{SCRATCHPAD}/findings_inventory.md`, `{SCRATCHPAD}/depth_candidates.md`, `{SCRATCHPAD}/file_coverage.md`, `{SCRATCHPAD}/state_dependency_map.md`, and `{SCRATCHPAD}/phase4_gates.md`. MAY read discovery producer outputs listed above as read-only inputs. MUST NOT modify other agents' output files. Do NOT proceed to Phase 4a.5 semantic invariants, Phase 4b depth, chain analysis, or report. Return and stop.
