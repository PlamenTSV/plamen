---
description: "Phase 4b Step 3: Devil's Advocate Iteration 2 -- targeted adversarial depth for uncertain findings"
---

# Phase 4b: Devil's Advocate Iteration 2

> **Mode gate**: Thorough mode only. Core mode skips iteration 2 entirely.
> **Trigger**: After iteration 1 scoring completes AND at least one UNCERTAIN finding exists at Medium+ severity.
> **Skip condition**: If ALL uncertain findings are Low/Info severity, iteration 2 may be skipped. If ANY uncertain finding is Medium or above, iteration 2 is MANDATORY.

---

## Anti-Dilution Rules (MANDATORY)

These rules prevent iteration 2 from merely restating iteration 1 conclusions:

### AD-1: Evidence-Only Carryover (+ Contrastive Path Summaries)
Between iterations, carry forward ONLY:
- Finding ID, title, location
- Evidence code references (file:line)
- Evidence source tags ([CODE], [PROD-ONCHAIN], etc.)
- Current confidence score
- A focused investigation question
- **Analysis path summary**: 1-2 sentences describing WHAT the previous agent analyzed and HOW it reasoned -- not what it concluded.

**Explicitly excluded**: All prior agent verdicts, confidence assessments, and cross-references.

### AD-2: Hard Devil's Advocate Role
Iteration 2 agents receive a STRUCTURAL adversarial role, not a soft "think critically" instruction. See the DA Role Framing below.

### AD-3: Focused Input Cap
Each iteration 2 agent receives at most **5 uncertain findings** in its domain. If more than 5 exist, prioritize by lowest confidence score.

### AD-4: Fresh Tool Calls Mandatory
Iteration 2 agents MUST make their own tool calls rather than relying on summaries from iteration 1.

### AD-5: New-Evidence-Only Re-Scoring
Re-scoring after iteration 2 only upgrades confidence if the agent produced NEW evidence (new code reference, new tool output, new production verification). Restating the same analysis with different words = zero confidence change.

### AD-6: Error Trace Injection
Error traces from failed PoCs (Phase 5) become investigation questions for post-verification targeted depth. Error traces are mechanical output, not agent reasoning -- they bypass AD-2.

---

## Finding Card Format (extract_evidence_only)

Each finding card sent to iteration 2 agents contains ONLY:

```markdown
## Finding [XX-N]: Title
- **Location**: SourceFile:L45-L67
- **Evidence**: [CODE] - validation check at L45; [CODE] - state update at L52
- **Confidence**: 0.35
- **Evidence Gap**: [What specific evidence is missing]
- **Prior Path**: [1-2 sentence analysis path summary -- what was explored, not what was concluded]
- **Investigate**: [Focused question targeting what was NOT explored]
```

Maximum ~250 chars per finding card (excluding code refs).

---

## DA Role Framing (include verbatim in every iteration 2 agent prompt)

```
You are the Devil's Advocate Depth Agent. Your PRIMARY job is to find what the previous analysis MISSED -- not to re-confirm what it found. For each finding you investigate:
1. Read the analysis path summary (what was explored). Your job is to explore what was NOT.
2. For each CONFIRMED conclusion from iteration 1: ask 'what adjacent bug does this analysis OBSCURE?' What is the OPPOSITE interpretation of the same code?
3. For each REFUTED conclusion from iteration 1: ask 'what enabler makes this exploitable after all?'
4. You MUST explore at least one path that the previous analysis did NOT. If you find no new vulnerability after exploring that path, state what you explored and why it is safe -- that is a valid output.
```

Point 4 requires EXPLORATION, not PRODUCTION. A DA agent that explores a new path and concludes "this is safe because X" has done its job. A DA agent that fabricates a finding to satisfy a quota has not.

---

## Spawning Logic

1. Read `{SCRATCHPAD}/confidence_scores.md` to identify UNCERTAIN and LOW_CONFIDENCE findings.
2. Read `{SCRATCHPAD}/skill_execution_gaps.md` (if exists) for additional investigation questions.
2a. Read `{SCRATCHPAD}/step_execution_gaps_mechanical.md` (if it exists) for
driver-aggregated `no`, `partial`, and `unknown` rows extracted from each iter1
agent's assigned findings artifact. **Each row is an iter2 directive.** For a
named (skill, step), execute that exact step and CONFIRM a finding or write a
cited `<safe: justification>`. For an `agent-trace` UNKNOWN, rerun the original
assigned role methodology and every injected skill; absence/malformed trace
cannot be treated as closure. Every affirmative disposition needs a resolvable
project source `file:Lline`.
2b. Read `{SCRATCHPAD}/notread_priority_gaps.md` (if exists) for files flagged NOTREAD by recon that received zero citations after iter1. iter2 MUST cover each listed file directly.
3. Read `{SCRATCHPAD}/perturbation_findings.md` (if exists) for adjacency context.
4. **Pre-step: Compute mechanical iter1 coverage gap.** AD-1 Prior Path is agent-written natural language and is lossy — iter1 can claim comprehensive coverage while having produced zero evidence tags for many in-scope locations. Derive a set-based ground truth:
   - (a) Read all `depth_*_findings.md` (iter1 output). Extract every `file:line` or `file::function` reference from Depth Evidence tags (`[BOUNDARY:...]`, `[TRACE:...]`, `[VARIATION:...]`). Call this set `covered_locations`.
   - (b) Read `{SCRATCHPAD}/function_list.md` (or `findings_inventory.md` if function_list is absent) for the in-scope function set. Call this `scope_locations`.
   - (c) Compute `gap = scope_locations − covered_locations` and classify each entry by domain (token-flow, state-trace, edge-case, external).
   - (d) Write `{SCRATCHPAD}/iter1_coverage_gap.md` with one section per domain, one line per uncovered location. This is the mechanical complement to AD-1's Prior Path summary.
5. Group uncertain findings by depth domain: token-flow, state-trace, edge-case, external.
6. For each domain with uncertain findings, build finding cards using extract_evidence_only format.
7. Compute spawn priority per finding: `spawn_priority = (1 - composite) * severity_weight`
   - Severity weights: Critical=4, High=3, Medium=2, Low=1, Info=0.5
8. Spawn targeted DA agents in parallel (one per domain that has uncertain findings).

### DA Agent Prompt Template

```
Task(subagent_type="general-purpose", model="sonnet", prompt="
{DA_ROLE_FRAMING -- paste the DA Role Framing text above}

## INVARIANT CONSISTENCY CHECK (HARD GATE)
Before CONFIRMING any finding at Medium+ severity, check {SCRATCHPAD}/design_context.md Operational Implications section. If your finding contradicts a documented operational implication, you MUST explain the contradiction or downgrade to CONTESTED.

## Your Domain: {DOMAIN}

## Uncertain Findings (max 5)
{FINDING_CARDS -- extract_evidence_only format, sorted by spawn_priority descending}

## Investigation Questions from Skill Execution Gaps
{SKILL_GAPS -- from skill_execution_gaps.md, filtered to this domain}

## Your Inputs
- {SCRATCHPAD}/semantic_invariants.md (if exists)
- {SCRATCHPAD}/state_variables.md
- Source files referenced by your findings
- {SCRATCHPAD}/design_context.md (for invariant consistency check)

## Rules
- You receive analysis path summaries but NOT conclusions from iteration 1
- Make your own tool calls -- do not rely on iteration 1 summaries (AD-4)
- Produce NEW evidence or state what you explored and why it is safe
- Use standard finding format from ~/.claude/rules/finding-output-format.md
- MANDATORY: Tag new evidence with Depth Evidence tags: [BOUNDARY:X=val], [VARIATION:param A->B], or [TRACE:path->outcome]. Every finding MUST have at least one tag.

## Output
Write to {SCRATCHPAD}/depth_da_{DOMAIN}_findings.md

SCOPE: Write ONLY to your assigned output file. Do NOT read or write other agents' output files. Do NOT proceed to subsequent pipeline phases (chain analysis, verification, report). Return your findings and stop.

Write your output directly to {SCRATCHPAD}/depth_da_{DOMAIN}_findings.md using the Write tool.
Return ONLY a one-line summary: 'DONE: {N} findings re-analyzed, {E} new evidence produced written to depth_da_{DOMAIN}_findings.md'
Do NOT return your full output as text.
")
```

Spawn ALL DA agents for all affected domains in a SINGLE message as parallel Task calls.

After all agents return, verify output files exist on disk and stop.
