# Phase 4a: Inventory Agent Prompt Template

> **Usage**: Orchestrator reads this file and spawns the Inventory Agent with this prompt.
> Replace placeholders `{SCRATCHPAD}`, `{list...}`, etc. with actual values.
> **Includes**: Side Effect Trace audit (merged from Phase 3.5 to eliminate a sequential gate).
> **Note**: Confidence scoring is computed by the orchestrator's scoring agent AFTER Phase 4b iteration 1, not during inventory. The inventory agent's job is unchanged - it inventories findings and prepares depth candidates.

---

## Inventory Agent

```
Task(subagent_type="general-purpose", prompt="
You are the Inventory Agent. You inventory ALL breadth findings AND audit side effect trace coverage in a single pass.

Read ALL files matching {SCRATCHPAD}/analysis_*.md

For each file:
- Extract all findings from ## FINDING INDEX or scan for [{XX}-N] patterns
- Extract ## DEPTH_TARGETS section
- Extract Step Execution fields - flag findings with ✗ or ? without valid reasons
- Extract Rules Applied field - flag missing rule applications

## TASK 1: Findings Inventory

Write to {SCRATCHPAD}/findings_inventory.md:
## Findings Inventory
**Total: {N} findings from {M} agents**
| # | Finding ID | Agent | Severity | Location | Title | Verdict | Step Execution | Rules Applied | RAG Confidence |

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
- R6 (Bidirectional Role): If SEMI_TRUSTED_ROLE detected AND finding involves role → both directions required
- R8 (Cached Params): If multi-step operation detected → staleness check required
- R10 (Worst-State): If severity uses current on-chain state → flag for recalibration
- R14 (Constraint Coherence + Setter Regression): If admin setter modifies limit/bound → regression check and coherence check required

## TASK 1.5: Assumption Dependency Cross-Reference

Read {SCRATCHPAD}/design_context.md - specifically the Trust Assumption Table.

For each finding in the Findings Inventory above, identify the actor required to execute the attack path, then cross-reference against the Trust Assumption Table:

| Condition | Tag | Severity Effect |
|-----------|-----|----------------|
| Attack requires `FULLY_TRUSTED` actor to act maliciously | `[ASSUMPTION-DEP: TRUSTED-ACTOR]` | −1 tier (applied by Index Agent) |
| Attack requires `SEMI_TRUSTED` actor to act maliciously | No tag | No change - severity matrix Likelihood axis already captures "specific conditions/complex setup" |
| Attack requires `SEMI_TRUSTED` actor to act WITHIN stated bounds | `[ASSUMPTION-DEP: WITHIN-BOUNDS]` | Flag only - no severity change |
| Attack requires `SEMI_TRUSTED` actor to EXCEED stated bounds | No tag | Real finding - no change |
| Attack requires `UNTRUSTED` actor or exploits `PRECONDITION` violation | No tag | Real finding - no change |

**Rules**:
- `TRUSTED-ACTOR` tag is ONLY for `FULLY_TRUSTED` actors (e.g., governance multisig, DAO, timelock). NEVER tag `SEMI_TRUSTED` actors as `TRUSTED-ACTOR` - their findings are calibrated through the severity matrix Likelihood axis instead.
- Only tag if the finding's ENTIRE attack path depends on the assumption. If the attack has BOTH a trusted-actor path AND an untrusted-actor path → no tag.
- `WITHIN-BOUNDS` means the attack's impact does not exceed what the stated bounds already allow. If the finding shows impact BEYOND stated bounds → no tag (real bug).
- When uncertain whether impact exceeds bounds → do NOT tag. Err on the side of preserving severity.

Append to {SCRATCHPAD}/findings_inventory.md:

## Assumption Dependency Audit
| Finding ID | Attack Actor | Actor Trust Level | Within Bounds? | Tag | Original Severity |
|------------|-------------|-------------------|---------------|-----|-------------------|

---

## Slither Finding Promotion
Read {SCRATCHPAD}/static_analysis.md
For each detector finding:
- calls-loop → Check if loop iterates over ANY growable array (user OR admin). For admin-controlled arrays, ALSO check: does deletion leave gaps (address(0) or zero-value entries)? If yes → create iteration-with-gaps hypothesis (Medium) - gap entries can cause skipped processing, failed external calls, or wasted gas.
- reentrancy-* → Check if state is modified after external call → if YES, create reentrancy hypothesis
- unchecked-transfer → Create unchecked return value hypothesis
- divide-before-multiply → Create precision loss hypothesis
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
| 3g | Can the callback recipient SELECTIVELY REVERT to manipulate caller state? | Check: Does the caller branch on success/failure of this call? Does the caller use try/catch? Does a revert here skip state updates the caller assumes happened? If YES → trace what state the caller leaves in on revert vs success. |

### Trace Termination
Continue tracing until ONE of:
- The token exits the protocol (transferred out to user/external)
- The token is consumed by protocol logic correctly (accounted for)
- The token is STRANDED (no exit path, no accounting) → **FINDING**
- The token corrupts accounting (consumed by wrong logic) → **FINDING**
- The side effect creates unbounded iteration growth → **FINDING**
- The callback recipient can selectively revert to skip caller state updates → **FINDING**

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
- If NO finding addresses the signal → add to `depth_candidates.md` as HIGH priority investigation target
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

## Skip Depth? (RARE)
Depth skips ONLY if ALL conditions met:
- [ ] 0 REFUTED findings
- [ ] 0 PARTIAL findings
- [ ] 0 CONTESTED findings
- [ ] 0 findings with incomplete step execution
- [ ] 0 rule application violations
- [ ] 0 promoted Slither findings
- [ ] All findings have RAG confidence > 0.8
- [ ] No UNVERIFIED external deps
- [ ] 0 side effect coverage gaps

If ANY checkbox unchecked → SPAWN ALL DEPTH AGENTS

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
")
```
