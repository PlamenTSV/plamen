---
description: "Improve Plamen after a missed finding. Usage: /plamen-feedback [bug description] [lang:evm|solana|aptos|sui]"
---

# Plamen Feedback Loop — Backward Reflection Pipeline

## Overview

This command automates the Post-Audit Improvement Protocol from `~/.claude/rules/post-audit-improvement-protocol.md`. It takes a missed bug description, runs each pipeline layer backward (report → recon), asks "why didn't I catch this?", and proposes minimal targeted improvements.

---

## Step 0: Argument Parsing

Parse `$ARGUMENTS` for pre-filled values:
- If it contains `lang:evm`, `lang:solana`, `lang:aptos`, or `lang:sui` → set `LANGUAGE` accordingly, skip language prompt.
- If it contains `scratchpad:` followed by a path → set `SCRATCHPAD` to that path (allows referencing a prior audit's artifacts for richer analysis).
- Remaining text after stripping known prefixes → treat as `FINDING_DESCRIPTION` (the missed bug).
- If `$ARGUMENTS` is empty → run interactive wizard starting at Step 1.

---

## Step 1: Intake — Interactive or Argument-Driven

### Step 1a: Get Bug Description

If `FINDING_DESCRIPTION` is not set from arguments, output:

```
> **Plamen Feedback Loop**
>
> Describe the bug that was missed. Be specific:
> - What vulnerability class? (e.g., reentrancy, integer overflow, access control)
> - What contract/function was affected?
> - What was the root cause in one sentence?
```

Use `AskUserQuestion` to collect the description if not already set.

### Step 1b: Detect Language

If `LANGUAGE` is not set, use `AskUserQuestion`:

```
AskUserQuestion(questions=[{
  question: "What language/chain is the missed finding from?",
  header: "Language",
  multiSelect: false,
  options: [
    { label: "EVM / Solidity", description: "Ethereum, Arbitrum, Base, etc." },
    { label: "Solana / Anchor", description: "Solana programs (Rust)" },
    { label: "Aptos Move", description: "Aptos smart contracts" },
    { label: "Sui Move", description: "Sui smart contracts" }
  ]
}])
```

Set `LANGUAGE` to `evm`, `solana`, `aptos`, or `sui` based on selection.

### Step 1c: Intake Agent — Classification + RC-AGENT Exclusion Test

Spawn an intake agent (sonnet) to classify the finding and run the mandatory exclusion test BEFORE any reflection agents spawn.

```
Task(subagent_type="general-purpose", model="sonnet", prompt="
You are the Plamen Feedback Intake Agent.

## Missed Finding
{FINDING_DESCRIPTION}
Language: {LANGUAGE}

## Your Task

### STEP 1: Classify the Vulnerability
Extract:
- vulnerability_class: (e.g., 'reentrancy', 'integer overflow', 'missing access control', 'price oracle manipulation')
- severity_estimate: Critical / High / Medium / Low / Info
- affected_area: (e.g., 'withdrawal logic', 'reward distribution', 'price calculation')
- key_terms: 3-5 searchable keywords for grep queries

### STEP 2: RC-AGENT Exclusion Test (MANDATORY — from post-audit-improvement-protocol.md §2.5)

Run ALL 3 gates. If ANY gate fails → classify as RC-AGENT and stop.

**Gate 1 — Methodology Search**:
Grep the following files for keywords from the vulnerability class:
- ~/.claude/prompts/{LANGUAGE}/generic-security-rules.md
- ~/.claude/prompts/{LANGUAGE}/phase4b-scanner-templates.md
- ~/.claude/prompts/{LANGUAGE}/phase4b-depth-templates.md
- ~/.claude/rules/finding-output-format.md (R4-R16 rules)

Search for: {key_terms from Step 1}

Result: Did you find ZERO relevant coverage?
- If coverage found → Gate 1 FAILS → RC-AGENT. Explain what coverage exists.
- If no coverage → Gate 1 PASSES.

**Gate 2 — Reasoning Trace** (skip if no scratchpad available):
If SCRATCHPAD is set, check analysis_*.md files for the affected_area.
Did the agent analyze the area and reach the wrong conclusion? → RC-AGENT
Did the agent skip the area entirely with no methodology covering it? → PASS

If SCRATCHPAD is not set: record Gate 2 as UNKNOWN (cannot verify without scratchpad).

**Gate 3 — Methodology Gap Proof**:
State in ONE sentence what specific methodology instruction is missing — NOT 'the agent should have checked X' (that is a pattern) but 'no existing rule tells the agent HOW to systematically discover this CLASS of bug.'

Can you state this without referencing the specific missed finding?
- If NO → Gate 3 FAILS → RC-AGENT
- If YES → Gate 3 PASSES

### STEP 3: Determine Root Cause Class

Apply the classification from post-audit-improvement-protocol.md §2:
- RC-AGENT: Agent had methodology but made a reasoning mistake → NO PIPELINE CHANGES
- RC-METHOD: No rule/skill/check covers this vulnerability class
- RC-DEPTH: Correct area analyzed but too shallow
- RC-SCOPE: File/function not analyzed by any agent
- RC-CONTEXT: Lacked domain knowledge
- RC-NOVEL: Unprecedented vulnerability class

### STEP 4: Output

Write to /tmp/plamen_feedback_intake.md:

```markdown
# Intake Classification

## Finding
- **Description**: {FINDING_DESCRIPTION}
- **Vulnerability Class**: {vulnerability_class}
- **Severity Estimate**: {severity_estimate}
- **Affected Area**: {affected_area}
- **Key Terms**: {key_terms}
- **Language**: {LANGUAGE}

## RC-AGENT Exclusion Test
- **Gate 1 (Methodology Search)**: PASS / FAIL — {evidence}
- **Gate 2 (Reasoning Trace)**: PASS / FAIL / UNKNOWN — {evidence}
- **Gate 3 (Methodology Gap Proof)**: PASS / FAIL — {one-sentence gap statement or N/A}

## Root Cause Classification
- **Class**: RC-{CODE}
- **Rationale**: {1-2 sentences}

## Proceed to Reflection Agents?
- **Decision**: YES / NO (RC-AGENT)
- **If NO**: {explanation for user}
```

Return: 'DONE: RC-{CLASS} — {proceed_or_stop}'
")
```

After intake agent returns:
1. Read `/tmp/plamen_feedback_intake.md`
2. Extract `CLASSIFICATION`, `ROOT_CAUSE_CLASS`, `VULNERABILITY_CLASS`, `PROCEED` flag
3. If `PROCEED = NO` (RC-AGENT): Display the explanation to the user. **STOP here — no reflection agents spawn.**
4. If `PROCEED = YES`: Continue to Step 2.

---

## Step 2: Parallel Backward Reflection Agents

**Spawn ALL 8 reflection agents simultaneously in ONE message.**

Each agent reads its own pipeline layer's prompt/template files and answers:
1. Would I have caught this? YES / NO / PARTIAL
2. If NO/PARTIAL: What single addition (≤10 lines) to my prompt would have caught it?
3. Is this change universal (always-on) or protocol-specific (injectable)?

Set these variables from the intake output before spawning:
- `FINDING_DESCRIPTION` = full description
- `VULNERABILITY_CLASS` = classified class
- `ROOT_CAUSE_CLASS` = RC-{CODE}
- `LANGUAGE` = detected language

### Reflection Agent Template (instantiate for each layer)

Each agent writes to `/tmp/plamen_feedback_{LAYER_ID}.md` and returns a structured result.

---

### R7: Report Layer

```
Task(subagent_type="general-purpose", model="sonnet", prompt="
You are the R7 Report Layer Reflection Agent.

## Missed Finding
{FINDING_DESCRIPTION}
Vulnerability class: {VULNERABILITY_CLASS}
Language: {LANGUAGE}

## Your Responsibility
Read your layer's template files:
- ~/.claude/rules/phase6-report-prompts.md
- ~/.claude/rules/report-template.md

Answer:
1. Does the report template's quality gate or finding format enforce coverage of this class? YES / NO / PARTIAL
2. If NO/PARTIAL: What text addition (≤10 lines) to report-prompts.md or report-template.md would have surfaced this? (E.g., a quality gate check, a mandatory section, a cross-reference requirement)
3. RC-AGENT check: Is this a report FORMATTING issue (agent had info but didn't write it up) or a DETECTION gap (info was never surfaced)? If formatting → RC-AGENT for this layer.
4. Is the proposed change universal (all protocols) or injectable?

Write to /tmp/plamen_feedback_R7.md:
```markdown
# R7 Report Layer

verdict: WOULD_CATCH | WOULD_MISS | PARTIAL
rc_class: RC-AGENT | RC-METHOD | RC-DEPTH | RC-SCOPE
proposed_diff: |
  [exact text to add, or null]
target_file: ~/.claude/rules/phase6-report-prompts.md (or null)
injectable: true/false
rationale: [1-2 sentences]
```

Return: 'DONE R7: {verdict}'
")
```

---

### R6: Verification Layer

```
Task(subagent_type="general-purpose", model="sonnet", prompt="
You are the R6 Verification Layer Reflection Agent.

## Missed Finding
{FINDING_DESCRIPTION}
Vulnerability class: {VULNERABILITY_CLASS}
Language: {LANGUAGE}

## Your Responsibility
Read your layer's template files:
- ~/.claude/prompts/{LANGUAGE}/phase5-verification-prompt.md
- ~/.claude/rules/phase5-poc-execution.md

Answer:
1. Does the verification template include a PoC pattern for this vulnerability class? YES / NO / PARTIAL
2. If NO/PARTIAL: What PoC template addition (≤10 lines) would catch this? (Note: verification runs AFTER detection — if detection never flagged it, verification cannot help. Flag this as RC-AGENT for this layer if so.)
3. Is the gap in verification methodology or in detection (upstream)?
4. Is the proposed change universal or language-specific?

Write to /tmp/plamen_feedback_R6.md with the same schema as R7.
Return: 'DONE R6: {verdict}'
")
```

---

### R5: Chain Analysis Layer

```
Task(subagent_type="general-purpose", model="sonnet", prompt="
You are the R5 Chain Analysis Layer Reflection Agent.

## Missed Finding
{FINDING_DESCRIPTION}
Vulnerability class: {VULNERABILITY_CLASS}
Language: {LANGUAGE}

## Your Responsibility
Read your layer's template files:
- ~/.claude/rules/phase4c-chain-prompt.md

Answer:
1. Does the chain analysis (enabler enumeration, composition coverage, severity reassessment) cover conditions that would surface this finding?
2. Would this finding have appeared as a chain between two simpler findings? If so, does the chain matching logic handle it?
3. If NO/PARTIAL: What addition to the enabler enumeration or chain matching logic would have caught it?

Write to /tmp/plamen_feedback_R5.md with the same schema as R7.
Return: 'DONE R5: {verdict}'
")
```

---

### R4b: Depth Layer

```
Task(subagent_type="general-purpose", model="sonnet", prompt="
You are the R4b Depth Layer Reflection Agent.

## Missed Finding
{FINDING_DESCRIPTION}
Vulnerability class: {VULNERABILITY_CLASS}
Language: {LANGUAGE}

## Your Responsibility
Read your layer's template files:
- ~/.claude/prompts/{LANGUAGE}/phase4b-depth-templates.md
- ~/.claude/prompts/{LANGUAGE}/phase4b-scanner-templates.md
- ~/.claude/agents/depth-token-flow.md
- ~/.claude/agents/depth-state-trace.md
- ~/.claude/agents/depth-edge-case.md
- ~/.claude/agents/depth-external.md

Answer:
1. Does any depth agent template (token-flow, state-trace, edge-case, external) have methodology that covers this vulnerability class? YES / NO / PARTIAL
2. Does any scanner template (A, B, C) have a check that covers this class?
3. If NO/PARTIAL: What single addition (≤10 lines) to which depth/scanner template would have caught it?
4. Is this better as a scanner sub-check (≤5 lines, universal) or a new/extended depth directive?
5. Apply the injectable-first test: is this vulnerability class seen in <50% of audits? If so, propose as injectable, not always-on.

Write to /tmp/plamen_feedback_R4b.md with the same schema as R7.
Include: target_depth_agent (token-flow | state-trace | edge-case | external | scanner-A | scanner-B | scanner-C | validation-sweep | none)
Return: 'DONE R4b: {verdict}'
")
```

---

### R4a: Inventory Layer

```
Task(subagent_type="general-purpose", model="sonnet", prompt="
You are the R4a Inventory Layer Reflection Agent.

## Missed Finding
{FINDING_DESCRIPTION}
Vulnerability class: {VULNERABILITY_CLASS}
Language: {LANGUAGE}

## Your Responsibility
Read your layer's template files:
- ~/.claude/prompts/{LANGUAGE}/phase4a-inventory-prompt.md

Answer:
1. Does the inventory grouping logic, side-effect trace audit, or hypothesis formation methodology handle this vulnerability class?
2. Would the inventory agent have created a hypothesis from a breadth-level finding in this class?
3. If NO/PARTIAL: What addition to the inventory prompt would have promoted/grouped this correctly?

Write to /tmp/plamen_feedback_R4a.md with the same schema as R7.
Return: 'DONE R4a: {verdict}'
")
```

---

### R3b: Re-scan Layer

```
Task(subagent_type="general-purpose", model="sonnet", prompt="
You are the R3b Re-scan Layer Reflection Agent.

## Missed Finding
{FINDING_DESCRIPTION}
Vulnerability class: {VULNERABILITY_CLASS}
Language: {LANGUAGE}

## Your Responsibility
Read your layer's template files:
- ~/.claude/rules/phase3b-rescan-prompt.md

Answer:
1. Does the re-scan prompt include this vulnerability class in its 'What To Look For' section (cross-function inconsistencies, asymmetric operations, parameter encoding mismatches, economic boundary conditions, time-dependent staleness)?
2. Would the re-scan's exclusion list mechanism have forced attention to this class?
3. If NO/PARTIAL: What addition to the re-scan 'What To Look For' section would include this class?

Write to /tmp/plamen_feedback_R3b.md with the same schema as R7.
Return: 'DONE R3b: {verdict}'
")
```

---

### R3: Scanner / Breadth Layer

```
Task(subagent_type="general-purpose", model="sonnet", prompt="
You are the R3 Scanner and Breadth Layer Reflection Agent.

## Missed Finding
{FINDING_DESCRIPTION}
Vulnerability class: {VULNERABILITY_CLASS}
Language: {LANGUAGE}

## Your Responsibility
Read your layer's template files:
- ~/.claude/prompts/{LANGUAGE}/phase4b-scanner-templates.md
- ~/.claude/rules/finding-output-format.md (R4-R16 rules)

Answer:
1. Do the blind-spot scanner checks (Scanner A: Tokens & Parameters, Scanner B: Guards & Inheritance, Scanner C: Role Lifecycle) cover this vulnerability class?
2. Do the R4-R16 rules in finding-output-format.md enforce analysis that would catch this?
3. If NO/PARTIAL: What scanner sub-check addition (≤5 lines, following 'CHECK N:' format) would catch it?
4. Is this better as a new scanner check or as an enforcement rule (R-code)?

Write to /tmp/plamen_feedback_R3.md with the same schema as R7.
Include: target_scanner (Scanner-A | Scanner-B | Scanner-C | Validation-Sweep | R-rule | none)
Return: 'DONE R3: {verdict}'
")
```

---

### R1: Recon Layer

```
Task(subagent_type="general-purpose", model="sonnet", prompt="
You are the R1 Recon Layer Reflection Agent.

## Missed Finding
{FINDING_DESCRIPTION}
Vulnerability class: {VULNERABILITY_CLASS}
Language: {LANGUAGE}

## Your Responsibility
Read your layer's template files:
- ~/.claude/prompts/{LANGUAGE}/phase1-recon-prompt.md
- ~/.claude/prompts/{LANGUAGE}/generic-security-rules.md

Answer:
1. Does the recon prompt include attack surface detection for this vulnerability class (flag detection, pattern recognition, skill triggering)?
2. Would recon have set a flag that triggers the relevant skill/niche-agent for this class?
3. Does generic-security-rules.md (R1-R16) cover the conditions that enable this vulnerability?
4. If NO/PARTIAL: What addition to the recon attack surface mapping or flag detection would have triggered coverage of this class?
5. Is this better as a new recon flag, a trigger for an existing skill, or a new generic security rule?

Write to /tmp/plamen_feedback_R1.md with the same schema as R7.
Include: proposed_flag (e.g., 'MISSING_ACCOUNTING_UPDATE' or null), triggers_skill (skill name or null)
Return: 'DONE R1: {verdict}'
")
```

---

## Step 3: Improvement Proposal Agent

After ALL reflection agents return, spawn the Improvement Proposal Agent.

```
Task(subagent_type="general-purpose", model="opus", prompt="
You are the Plamen Improvement Proposal Agent.

## Missed Finding
{FINDING_DESCRIPTION}
Vulnerability class: {VULNERABILITY_CLASS}
Language: {LANGUAGE}
Root Cause Class: {ROOT_CAUSE_CLASS}

## Reflection Layer Outputs
Read ALL reflection files:
- /tmp/plamen_feedback_R7.md  (Report Layer)
- /tmp/plamen_feedback_R6.md  (Verification Layer)
- /tmp/plamen_feedback_R5.md  (Chain Analysis Layer)
- /tmp/plamen_feedback_R4b.md (Depth Layer)
- /tmp/plamen_feedback_R4a.md (Inventory Layer)
- /tmp/plamen_feedback_R3b.md (Re-scan Layer)
- /tmp/plamen_feedback_R3.md  (Scanner Layer)
- /tmp/plamen_feedback_R1.md  (Recon Layer)

Also read:
- ~/.claude/rules/post-audit-improvement-protocol.md (Anti-Bloat Gates, Fix Decision Tree, Change Type Risk Tiers)

## Your Task

### STEP 1: Find the Earliest Layer Gap

Scan from R1 (recon) to R7 (report). The EARLIEST layer that returns WOULD_MISS is the root cause fix location — downstream layers cannot compensate for upstream gaps.

Record:
- earliest_miss_layer: R{N}
- layers_that_would_miss: [list]
- fix_priority: earliest layer first

### STEP 2: Apply Fix Decision Tree (post-audit-improvement-protocol.md §3)

For each layer that returned WOULD_MISS or PARTIAL:

```
Is the gap covered by existing rules? (if yes → RC-AGENT for this layer, skip)
  └── NO → Is it generalizable (applies to 2+ protocol types)?
      ├── YES → Does it extend an existing component?
      │   ├── YES → extend (type: extend, ~5-10 lines)
      │   └── NO  → new injectable skill (type: new-injectable)
      └── NO  → RAG entry only (type: rag-entry)
```

### STEP 3: Anti-Bloat Gates (MANDATORY for any 'extend' or higher)

For each proposed change, check ALL gates:
1. **Line budget**: Will any file exceed its cap? (caps in post-audit-improvement-protocol.md Appendix A)
2. **Duplication**: Does this touch 4+ files with identical text? → move to shared component
3. **Marginal value**: Is this methodology-level (HOW to look), not pattern-level (WHAT to find)?
4. **Overlap**: Does >60% overlap with existing checks? → merge instead

### STEP 4: Methodology Test (MANDATORY)
- Does the proposed change teach HOW to analyze? → YES = PROCEED
- Does it tell agents WHAT to find? → YES = REJECT, add to RAG only

### STEP 5: Produce Improvement Proposals

For each approved change, produce an improvement proposal using this exact format:

```markdown
## Improvement Proposal {N}: {title}

### Source
- **Root cause code**: {RC-CODE}
- **Earliest gap layer**: R{N} {Layer Name}
- **Missed class** (generic): {generic vulnerability class description}

### Proposed Change
- **Type**: {trigger-fix | extend | new-injectable | new-rule | rag-entry}
- **Target file**: {exact file path}
- **Change location**: {section or line range in the file}
- **Lines added/removed**: +{N} / -{N}
- **Risk tier**: {Low | Medium | High}

### Anti-Bloat Gates
- [ ] Line budget: {result}
- [ ] Duplication: {result}
- [ ] Marginal value (methodology, not pattern): {result}
- [ ] Overlap check: {result}

### Methodology Test
- Teaches HOW to look: {YES/NO}
- Tells WHAT to find: {YES/NO — if YES, gate fails}

### Proposed Diff
\`\`\`
{exact text to add or modify — max 15 lines}
\`\`\`

### False Positive Risk
{Could this produce false positives? Which protocol types are affected?}

### Decision
- [ ] APPROVED
- [ ] APPROVED AS INJECTABLE
- [ ] DEFERRED (RAG only)
- [ ] REJECTED: {reason}
```

### STEP 6: Rank Proposals

Sort proposals by:
1. Change type risk (rag-entry first, new-rule last)
2. Layer priority (R1 gap before R7 gap)
3. Line cost (smaller changes first)

### Output

Write to /tmp/plamen_feedback_proposals.md:
- Executive summary (1 paragraph)
- All improvement proposals in ranked order
- Skip list: layers that returned WOULD_CATCH (no change needed)
- RC-AGENT layers: layers where agent had methodology but failed to apply it

Return: 'DONE: {N} proposals ({approved} approved, {deferred} deferred, {rejected} rejected)'
")
```

---

## Step 4: User Review

After the proposal agent returns:

1. Read `/tmp/plamen_feedback_proposals.md`
2. Display to the user:
   - Executive summary
   - Each proposal with its diff, risk tier, and false positive assessment
3. For each proposal with Decision = APPROVED or APPROVED AS INJECTABLE, use `AskUserQuestion` to confirm:

```
AskUserQuestion(questions=[{
  question: "Apply this improvement to your Plamen pipeline?",
  header: "Proposal {N}: {title}",
  multiSelect: false,
  options: [
    { label: "Apply", description: "Edit the target file with the proposed diff" },
    { label: "Apply as injectable", description: "Convert to conditional injectable skill instead of always-on" },
    { label: "Defer (add to RAG knowledge only)", description: "Record but do not modify pipeline files" },
    { label: "Reject", description: "Do not apply this change" }
  ]
}])
```

Collect decisions for all proposals before proceeding to Step 5.

---

## Step 5: Apply Approved Changes

For each proposal the user approved:

### Step 5a: Edit Target File

Read the target file. Apply the proposed diff exactly as specified.
After editing, verify the change is present by reading the modified section.

### Step 5b: Version Bump

Add or update a version comment at the top of each modified file:
```
<!-- Last modified: {YYYY-MM-DD} by plamen-feedback (RC-{CODE}: {vulnerability_class}) -->
```

### Step 5c: Update MEMORY.md

Append one line to `~/.claude/MEMORY.md`:
```
- Pipeline v{auto-increment} ({today's date}): RC-{CODE} fix for {vulnerability_class} in {LANGUAGE} ({change_type}, {target_file_basename}). {N} proposal(s) applied.
```

If no prior version exists in MEMORY.md, start at v1.

### Step 5d: Cleanup Temp Files

```bash
rm -f /tmp/plamen_feedback_*.md
```

### Step 5e: Confirm to User

Output:
```
**Plamen Feedback Complete**

Applied: {N} change(s)
Modified files:
  - {file1} (+{lines} lines)
  - {file2} (+{lines} lines)

Deferred: {N} change(s) → RAG knowledge only (no file modifications)
Rejected: {N} change(s)

MEMORY.md updated with one-line version entry.

> Reminder: The pipeline learns methodology, not patterns. No missed bug descriptions were saved.
```

---

## Error Handling

- **Intake agent returns RC-AGENT**: Stop immediately. Explain to user why this is a reasoning error, not a pipeline gap. Output: `> **No pipeline changes needed** — the Plamen methodology covers this vulnerability class. The missed finding was a reasoning error (RC-AGENT), which cannot be fixed by adding rules.`
- **Reflection agent fails/times out**: Mark that layer as UNKNOWN in the proposal agent input. Proceed with remaining layers.
- **Proposal agent produces 0 approved changes**: Inform user: `> All proposed changes were either RAG-only or rejected as RC-AGENT. This finding represents either a novel vulnerability class or a reasoning error — no pipeline modifications are recommended.`
- **Target file at line budget cap**: Proposal agent will flag this. Do NOT exceed the cap. Either compress existing content first or downgrade the change to injectable.
