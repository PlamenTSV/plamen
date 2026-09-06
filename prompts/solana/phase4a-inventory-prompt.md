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
- **R10 anti-burden-inversion (external-assumption findings)**: When a finding's harm mechanism is CONFIRMED in-scope and ONLY an unresearched / out-of-scope EXTERNAL factor (counterparty honesty, an external decoder/consumer, off-chain behavior) could render it safe, do NOT demote it to Informational/Low. Keep it at its in-scope impact severity, tag it `[EXTERNAL-ASSUMPTION: <assumed safe condition>]`, and route to verification. Demotion requires POSITIVE in-scope evidence of the safe condition - its mere possibility does not rebut a mechanism already proven in-scope. This clause applies ONLY when (a) the harm mechanism is confirmed in-scope, AND (b) there is a concrete named consequence, AND (c) the required actor is NOT `FULLY_TRUSTED`. It is NOT a blanket "never demote": the legitimate `FULLY_TRUSTED` -1 tier above still applies to fully-trusted governance actors, and the semi-vs-fully-trusted table above is unchanged; this only blocks the burden-inversion demotion of a confirmed in-scope mechanism.

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

## TASK 5: State Dependency Cross-Reference

Using `{SCRATCHPAD}/state_variables.md` and `{SCRATCHPAD}/function_list.md`, build a cross-function dependency map via shared state.

For each state variable (account field) written by instruction A and read/depended-on by instruction B (where A ≠ B and A is externally callable):
- Can A put the variable in a state that breaks B's assumption?

Write to `{SCRATCHPAD}/state_dependency_map.md`:

| Variable | Writer Function | Consumer Function | Can Writer Break Consumer? |
|----------|----------------|-------------------|---------------------------|

**Rules**:
- Cap at 30 rows. Prioritize: externally callable writers first, critical consumers (settlement, withdrawal, claim, liquidation, close) first
- Omit trivially safe pairs (both share the same signer constraint AND the writer cannot set an invalid value)
- The "Can Writer Break Consumer?" column is a YES/NO with a 1-phrase reason. YES entries become depth agent investigation targets
- Filter: different instructions only (self-reads are not cross-function conflicts)

---

## Skip Depth? (RARE)
Depth skips ONLY if ALL conditions met:
- [ ] 0 REFUTED findings
- [ ] 0 PARTIAL findings
- [ ] 0 CONTESTED findings
- [ ] 0 findings with incomplete step execution
- [ ] 0 rule application violations
- [ ] 0 promoted Fender findings
- [ ] No inventory verdict, severity, confidence, or depth decision depends on external precedent
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
