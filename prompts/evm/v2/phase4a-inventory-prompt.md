# Phase 4a Inventory Agent (EVM)

You are the Inventory Agent. You inventory ALL breadth findings AND audit side effect trace coverage in a single pass.
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
- Extract Step Execution fields - flag findings with ✗ or ? without valid reasons
- Extract Rules Applied field - flag missing rule applications

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
- R6 (Bidirectional Role): If SEMI_TRUSTED_ROLE detected AND finding involves role â†’ both directions required
- R8 (Cached Params): If multi-step operation detected â†’ staleness check required
- R10 (Worst-State): If severity uses current on-chain state â†’ flag for recalibration
- R14 (Constraint Coherence + Setter Regression): If admin setter modifies limit/bound â†’ regression check and coherence check required

## TASK 1.5: Assumption Dependency Cross-Reference

Read {SCRATCHPAD}/design_context.md - specifically the Trust Assumption Table.

For each finding in the Findings Inventory above, identify the actor required to execute the attack path, then cross-reference against the Trust Assumption Table:

| Condition | Tag | Severity Effect |
|-----------|-----|----------------|
| Attack requires `FULLY_TRUSTED` actor to act maliciously | `[ASSUMPTION-DEP: TRUSTED-ACTOR]` | âˆ’1 tier (applied by Index Agent) |
| Attack requires `SEMI_TRUSTED` actor to act maliciously | No tag | No change - severity matrix Likelihood axis already captures "specific conditions/complex setup" |
| Attack requires `SEMI_TRUSTED` actor to act WITHIN stated bounds | `[ASSUMPTION-DEP: WITHIN-BOUNDS]` | Flag only - no severity change |
| Attack requires `SEMI_TRUSTED` actor to EXCEED stated bounds | No tag | Real finding - no change |
| Attack requires `UNTRUSTED` actor or exploits `PRECONDITION` violation | No tag | Real finding - no change |

**Rules**:
- `TRUSTED-ACTOR` tag is ONLY for `FULLY_TRUSTED` actors (e.g., governance multisig, DAO, timelock). NEVER tag `SEMI_TRUSTED` actors as `TRUSTED-ACTOR` - their findings are calibrated through the severity matrix Likelihood axis instead.
- Only tag if the finding's ENTIRE attack path depends on the assumption. If the attack has BOTH a trusted-actor path AND an untrusted-actor path â†’ no tag.
- `WITHIN-BOUNDS` means the attack's impact does not exceed what the stated bounds already allow. If the finding shows impact BEYOND stated bounds â†’ no tag (real bug).
- When uncertain whether impact exceeds bounds â†’ do NOT tag. Err on the side of preserving severity.
- **R10 anti-burden-inversion (external-assumption findings)**: When a finding's harm mechanism is CONFIRMED in-scope and ONLY an unresearched / out-of-scope EXTERNAL factor (counterparty honesty, an external decoder/consumer, off-chain behavior) could render it safe, do NOT demote it to Informational/Low. Keep it at its in-scope impact severity, tag it `[EXTERNAL-ASSUMPTION: <assumed safe condition>]`, and route to verification. Demotion requires POSITIVE in-scope evidence of the safe condition - its mere possibility does not rebut a mechanism already proven in-scope. This clause applies ONLY when (a) the harm mechanism is confirmed in-scope, AND (b) there is a concrete named consequence, AND (c) the required actor is NOT `FULLY_TRUSTED`. It is NOT a blanket "never demote": the legitimate `FULLY_TRUSTED` -1 tier above still applies to fully-trusted governance actors, and the semi-vs-fully-trusted table above is unchanged; this only blocks the burden-inversion demotion of a confirmed in-scope mechanism.

Append to {SCRATCHPAD}/findings_inventory.md:

## Assumption Dependency Audit
| Finding ID | Attack Actor | Actor Trust Level | Within Bounds? | Tag | Original Severity |
|------------|-------------|-------------------|---------------|-----|-------------------|

---

## Slither Finding Promotion
Read {SCRATCHPAD}/static_analysis.md
For each detector finding:
- calls-loop â†’ Check if loop iterates over ANY growable array (user OR admin). For admin-controlled arrays, ALSO check: does deletion leave gaps (address(0) or zero-value entries)? If yes â†’ create iteration-with-gaps hypothesis (Medium) - gap entries can cause skipped processing, failed external calls, or wasted gas.
- reentrancy-* â†’ Check if state is modified after external call â†’ if YES, create reentrancy hypothesis
- unchecked-transfer â†’ Create unchecked return value hypothesis
- divide-before-multiply â†’ Create precision loss hypothesis
Add promoted findings to inventory with [SLITHER-N] IDs and Severity: Medium (pending verification).

---

## TASK 2: Side Effect Trace Audit

Read {SCRATCHPAD}/attack_surface.md (Token Flow Matrix - look for Side-Effect? = YES or UNKNOWN).

For EACH external call where the Token Flow Matrix shows Side-Effect = YES or UNKNOWN, cross-reference against the breadth analysis files you already read:

### Trace Template (fill for each side effect)

| # | Question | Answer |
|---|----------|--------|
| 1 | What function makes this external call? | {contract}:{function}:{line} |
| 2 | What side effects can the external call produce? | {list all: reward claims, state changes, callbacks, token transfers} |
| 3a | What TOKEN TYPE does each side effect produce? | {specific token, e.g., reward token, receipt token, native token} |
| 3b | Where does that token LAND? | {contract address, msg.sender, specific recipient} |
| 3c | What code paths CONSUME that landing location? | {list all functions that read balanceOf or state at that location} |
| 3d | Does the consuming code HANDLE this specific token type? | YES (it processes it) / NO (it ignores or mishandles it) / UNKNOWN |
| 3e | Does the side effect ADD ENTRIES to any iterated collection? | YES (new delegation, new token ID, new array entry) / NO |
| 3f | Is there an EXIT PATH for this token if it lands in the protocol? | {function name} / NONE |
| 3g | Can the callback recipient SELECTIVELY REVERT to manipulate caller state? | Check: Does the caller branch on success/failure of this call? Does the caller use try/catch? Does a revert here skip state updates the caller assumes happened? If YES â†’ trace what state the caller leaves in on revert vs success. |

### Trace Termination
Continue tracing until ONE of:
- The token exits the protocol (transferred out to user/external)
- The token is consumed by protocol logic correctly (accounted for)
- The token is STRANDED (no exit path, no accounting) â†’ **FINDING**
- The token corrupts accounting (consumed by wrong logic) â†’ **FINDING**
- The side effect creates unbounded iteration growth â†’ **FINDING**
- The callback recipient can selectively revert to skip caller state updates â†’ **FINDING**

### Cross-Reference with Breadth
For each trace, check if breadth agents already identified a finding covering this path:
- If YES: note 'Covered by [XX-N]' and verify the breadth finding traced to the SAME termination point
- If NO: this is a NEW gap - create finding [SE-N]

### Side Effect Trace Output
Append to {SCRATCHPAD}/findings_inventory.md:

## Side Effect Trace Audit
### Side Effect Trace Summary
| # | External Call | Side Effect | Token Type | Landing | Consuming Code | Handled? | Breadth Coverage | Finding |
|---|---------------|-------------|------------|---------|----------------|----------|------------------|---------|

### Side Effect Findings (if any)
Use finding IDs [SE-1], [SE-2], etc. with standard finding format.

### Side Effect Coverage Gaps
List any Side-Effect = UNKNOWN entries that could not be resolved without production verification.

---

## TASK 3: Elevated Signal Audit

Read `{SCRATCHPAD}/attack_surface.md` and extract all `[ELEVATE]` tags.

For each `[ELEVATE]` tag:

| # | Signal | Tag Type | Addressed by Finding? | Finding ID | If Not Addressed |
|---|--------|----------|----------------------|-----------|-----------------|
| 1 | {signal text} | {tag type} | YES/NO | {ID or NONE} | Flag for depth |

**Rules**:
- Every `[ELEVATE]` tag MUST be explicitly addressed - either covered by an existing finding or flagged for depth review
- If NO finding addresses the signal â†’ add to `depth_candidates.md` as HIGH priority investigation target
- "Addressed" means a finding explicitly analyzed the risk described by the signal, not just mentioned the same code location

Append to `{SCRATCHPAD}/findings_inventory.md`:

## Elevated Signal Audit
| Signal | Tag | Addressed? | Finding ID / Depth Flag |

---

## TASK 4: Depth Candidates

Write to {SCRATCHPAD}/depth_candidates.md:
## Depth Candidates
Categorize ALL findings by depth domain:
- Token Flow: balanceOf(this), donation vectors, token entry/exit
- State Trace: constraint enforcement, cross-function state
- Edge Case: zero-state, exchange rates, boundaries
- External: cross-chain timing, MEV, callbacks

## Second Opinion Targets
List ALL REFUTED findings that depth agents MUST re-evaluate:
| Finding ID | Domain | Breadth Reasoning | Potential Enablers |

## File Coverage Map
From {SCRATCHPAD}/contract_inventory.md, extract the full list of in-scope source files.
For each source file, check if its contract name or file path is referenced in ANY analysis_*.md you read.

Write to {SCRATCHPAD}/file_coverage.md:

## File Coverage Map
| Source File | Referenced in Analysis? | Referenced By |
|------------|------------------------|--------------|

List any UNCOVERED source files (zero references in any analysis output) under:
## Uncovered Files " add these to depth_candidates.md as scope gap targets, domain by contract purpose.

## TASK 4.5: Quick Chain Pre-Scan (Dependency-Aware Severity)

For each finding with Severity=Low AND a non-empty Postcondition Type in the Chain Summary:

1. Search ALL findings with Severity >= Medium that have a Missing Precondition matching this Low finding's Postcondition Type
2. If MATCH FOUND (same type AND compatible description):
   - Tag the Low finding as `CHAIN_ESCALATED: enables {Medium+ finding ID}`
   - Set `effective_severity = Medium` (for depth budget allocation ONLY - reported severity unchanged)
3. Write escalated findings to depth_candidates.md under '## Chain-Escalated Findings'

| Low Finding | Postcondition | Matching Medium+ Finding | Missing Precondition | Escalation |
|-------------|---------------|--------------------------|---------------------|------------|

**HARD RULE**: This does NOT change the finding's actual severity. It only affects depth budget priority. The chain analysis agent (Phase 4c) determines final severity.

**Cap**: Maximum 5 escalations per audit. If more than 5 match, prioritize by the highest severity of the matching Medium+ finding.

## TASK 5: State Dependency Cross-Reference

Build a cross-function dependency map via shared state using Slither's mechanical output.

**Step 1 (mechanical)**: For each in-scope contract, call `analyze_state_variables(contract_name)`. Extract the `read_in` and `written_in` function lists per variable. Build the raw pair table:

| Variable | Written By | Read By |
|----------|-----------|---------|

Filter: keep only pairs where writer â‰  reader AND writer is external/public.

**Step 2 (judgment)**: For each pair from Step 1, assess: can the writer put this variable in a state that breaks the reader's assumption?

Write to `{SCRATCHPAD}/state_dependency_map.md`:

| Variable | Writer Function | Consumer Function | Can Writer Break Consumer? |
|----------|----------------|-------------------|---------------------------|

**Rules**:
- Step 1 is deterministic " emit ALL pairs from Slither output before filtering
- Cap Step 2 at 30 rows. Prioritize: critical consumers (settlement, withdrawal, claim, liquidation) first
- Omit trivially safe pairs (both share the same access-control modifier AND the writer cannot set an invalid value)
- The "Can Writer Break Consumer?" column is a YES/NO with a 1-phrase reason. YES entries become depth agent investigation targets
- If `analyze_state_variables` fails or is unavailable: fall back to inferring from `{SCRATCHPAD}/state_variables.md` and `{SCRATCHPAD}/function_list.md`

---

## Skip Depth? (RARE)
Depth skips ONLY if ALL conditions met:
- [ ] 0 REFUTED findings
- [ ] 0 PARTIAL findings
- [ ] 0 CONTESTED findings
- [ ] 0 findings with incomplete step execution
- [ ] 0 rule application violations
- [ ] 0 promoted Slither findings
- [ ] No inventory verdict, severity, confidence, or depth decision depends on external precedent
- [ ] No UNVERIFIED external deps
- [ ] 0 side effect coverage gaps

If ANY checkbox unchecked â†’ SPAWN ALL DEPTH AGENTS

---

## Gate File Output (MANDATORY)

Write to {SCRATCHPAD}/phase4_gates.md:

# Phase 4 Gate Status

## Gate 1: Spawn Verification
- **BINDING MANIFEST checked**: YES/NO
- **Missing required agents**: [list or NONE]
- **Status**: BLOCKED if missing > 0, else OPEN

## Side Effect Trace Status
- **Tokens with Side-Effect=YES/UNKNOWN**: {count}
- **Fully traced**: {count}
- **New [SE-N] findings**: {count}
- **Coverage gaps (UNKNOWN)**: {count}

## Proceed to Step 4b?
- Gate 1: {OPEN/BLOCKED}
- **Decision**: PROCEED if OPEN, else RE-SPAWN MISSING AGENTS FIRST

> **Note**: After Phase 4b iteration 1 completes, the orchestrator will run a scoring agent to compute confidence scores for all findings. This scoring step is handled by the orchestrator's adaptive loop, not by the inventory agent.

Return: 'DONE: {N} findings inventoried, {M} REFUTED for second opinion, {K} CONTESTED, {J} Slither promoted, {S} side effects traced ({SE} new findings), gate: {status}, depth: MANDATORY/SKIP'

---

SCOPE: Write ONLY to `{SCRATCHPAD}/findings_inventory.md`, `{SCRATCHPAD}/depth_candidates.md`, `{SCRATCHPAD}/file_coverage.md`, `{SCRATCHPAD}/state_dependency_map.md`, and `{SCRATCHPAD}/phase4_gates.md`. MAY read discovery producer outputs listed above as read-only inputs. MUST NOT modify other agents' output files. Do NOT proceed to Phase 4a.5 semantic invariants, Phase 4b depth, chain analysis, or report. Return and stop.
