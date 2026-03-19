# Phase 4a: Inventory Agent Prompt Template - Solana

> **Usage**: Orchestrator reads this file and spawns the Inventory Agent for a Solana program audit.
> Replace placeholders `{SCRATCHPAD}`, `{list...}`, etc.
> **Includes**: CPI Side Effect Trace audit (merged from Phase 3.5 to eliminate a sequential gate).
> **Note**: Confidence scoring is computed by the orchestrator's scoring agent AFTER Phase 4b iteration 1, not during inventory. The inventory agent's job is unchanged - it inventories findings and prepares depth candidates.

---

## Inventory Agent

```
Task(subagent_type="general-purpose", prompt="
You are the Inventory Agent for a Solana program audit.

Read ALL files matching {SCRATCHPAD}/analysis_*.md

For each file:
- Extract all findings and DEPTH_TARGETS
- Extract Step Execution fields - flag findings with ✗ or ? without valid reasons
- Extract Rules Applied field - flag missing rule applications (R1-R16, S1-S10)

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

Check these Solana-specific rules IN ADDITION to R1-R16:
- S1 (Account Validation): If UncheckedAccount/AccountInfo used → validation check required
- S3 (CPI Security): If CPI detected → target validation + reload check required
- S5 (Stale Data After CPI): If CPI detected → reload audit required
- S6 (Remaining Accounts): If remaining_accounts used → manual validation required
- S7 (Duplicate Mutable): If 2+ mutable accounts → uniqueness check required
- S9 (Token-2022): If Token-2022 mint → extension check required

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

## Fender Finding Promotion
Read {SCRATCHPAD}/static_analysis.md (contains Fender or grep results)
For each detector finding:
- account-validation → Create account validation hypothesis
- cpi-security → Create CPI security hypothesis
- pda-security → Create PDA hypothesis
- missing-signer → Create signer check hypothesis
- duplicate-mutable-accounts → Create duplicate account hypothesis
Add promoted findings with [FENDER-N] IDs, Severity: Medium (pending verification).

---

## TASK 2: Side Effect Trace Audit

Read {SCRATCHPAD}/attack_surface.md (Account Inventory Matrix - look for CPI targets with mutable accounts).

For EACH CPI where the target program may modify accounts, cross-reference against the breadth analysis files you already read:

### CPI Side Effect Trace Template

| # | Question | Answer |
|---|----------|--------|
| 1 | What instruction makes this CPI? | {program}:{instruction}:{line} |
| 2 | What external program is invoked? | {program_id or interface} |
| 3 | What accounts are passed to the CPI? | {list all accounts with mut/signer flags} |
| 4 | What accounts can the external program modify? | {list mutable accounts passed} |
| 5 | Are modified accounts RELOADED after CPI returns? | YES (reload_mut/explicit deserialize) / NO |
| 6 | Is the external program's owner RE-CHECKED after CPI? | YES / NO / N/A (known program) |
| 7 | Can the CPI target be substituted (non-hardcoded program_id)? | YES (user-supplied) / NO (hardcoded) |
| 8 | Does the CPI return data that is used without validation? | YES / NO |

### Trace Termination
Continue tracing until ONE of:
- Account data is reloaded and re-validated after CPI → SAFE
- Account data is used stale after CPI → **FINDING** (S5)
- CPI target can be substituted with malicious program → **FINDING** (S3)
- CPI return data used without validation → **FINDING**

### Cross-Reference with Breadth
For each trace, check if breadth agents already identified a finding covering this path:
- If YES: note 'Covered by [XX-N]' and verify same termination point
- If NO: this is a NEW gap - create finding [SE-N]

### Side Effect Trace Output
Append to {SCRATCHPAD}/findings_inventory.md:

## Side Effect Trace Audit
### CPI Side Effect Trace Summary
| # | CPI Site | Target Program | Accounts Modified | Reloaded? | Owner Checked? | Breadth Coverage | Finding |
|---|----------|---------------|-------------------|-----------|---------------|------------------|---------|

### Side Effect Findings (if any)
Use finding IDs [SE-1], [SE-2], etc. with standard finding format.

### Side Effect Coverage Gaps
List any CPI targets that could not be fully analyzed without production verification.

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
- Token Flow: vault token accounts, unsolicited transfers, Token-2022 extensions
- State Trace: cross-account invariants, PDA state, CPI state mutations
- Edge Case: zero-state, initialization ordering, CU boundaries, rent thresholds
- External: CPI chains, program upgrades, instruction introspection

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
- [ ] 0 promoted Fender findings
- [ ] All findings have RAG confidence > 0.8
- [ ] No UNVERIFIED external deps
- [ ] 0 CPI side effect coverage gaps

If ANY checkbox unchecked → SPAWN ALL DEPTH AGENTS

---

## Gate File Output (MANDATORY)

Write to {SCRATCHPAD}/phase4_gates.md:

# Phase 4 Gate Status

## Gate 1: Spawn Verification
- **BINDING MANIFEST checked**: YES/NO
- **Missing required agents**: [list or NONE]
- **Status**: BLOCKED if missing > 0, else OPEN

## CPI Side Effect Trace Status
- **CPI sites with mutable accounts**: {count}
- **Fully traced**: {count}
- **New [SE-N] findings**: {count}
- **Coverage gaps**: {count}

## Proceed to Step 4b?
- Gate 1: {OPEN/BLOCKED}
- **Decision**: PROCEED if OPEN, else RE-SPAWN MISSING AGENTS FIRST

Return: 'DONE: {N} findings inventoried, {M} REFUTED for second opinion, {K} CONTESTED, {J} Fender promoted, {S} CPI side effects traced ({SE} new findings), gate: {status}, depth: MANDATORY/SKIP'
")
```
