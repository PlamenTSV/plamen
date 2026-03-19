# Post-Audit Improvement Protocol

> **When**: Optionally, after an audit completes AND a human/ground-truth report exists for comparison.
> **Who**: The orchestrator runs this as a standalone session - NOT during the audit itself.
> **Goal**: Identify gaps, classify root causes, propose minimal targeted fixes, and prevent regression and bloat.
> **Principle**: The pipeline should grow logarithmically, not linearly, with each post-mortem.

---

## Part 1: The Problem This Protocol Solves

### Current state
- **125 files**, **31,278 lines** across agents/, rules/, prompts/, skills/
- **78 skill files** across 4 language trees + 1 injectable
- **~80 scanner checks** across 4 trees (19-21 per tree)
- **Every improvement is additive**: each version adds files, rules, and lines without removing old ones
- **Cross-tree duplication**: Each fix must be applied to 4-9 files (EVM, Solana, Aptos, Sui)

### Failure modes this protocol prevents
1. **Prompt bloat** - scanner templates growing from 300→500+ lines, agent context windows saturating
2. **Regression** - a fix for Audit N's gap breaks detection of Audit N-1's findings
3. **Overfitting** - encoding a specific bug pattern rather than the methodology to find a class of bugs
4. **Duplication tax** - every 2-line fix costs 8-18 lines across trees (4× scanner + 4× depth + 1× shared)
5. **Diminishing returns** - adding the 80th scanner check produces less value than tuning the 10 most important ones
6. **Anchoring bias** - storing past audit findings in persistent memory biases future audits toward those specific patterns

### Ephemeral-Session Principle

**NOTHING from the comparison persists except approved methodology changes.** The gap analysis, finding alignment matrix, root cause evidence chains, and ground truth data all exist only within this conversation session. Only two things survive:

1. **Approved edits** to rules/skills/prompts (methodology, never specific bug patterns)
2. **One-line MEMORY.md entry** recording version, recall %, and root cause distribution (e.g., "v1.1 - 75% recall, 2×RC-DEPTH, 1×RC-METHOD")

No benchmark directory. No ground truth files. No finding descriptions stored. The agent must approach each new audit with zero knowledge of previous audit findings.

---

## Part 2: Gap Analysis Framework

### Step 1: Structured Comparison (in-session only)

The user provides both reports. The orchestrator creates the alignment matrix **in conversation context only** - never written to disk:

```
Finding Alignment Matrix (ephemeral)

| GT ID | GT Sev | GT Title | Match? | Pipeline ID | Pipeline Sev | Delta |
|-------|--------|----------|--------|-------------|-------------|-------|
| GT-1  | High   | [title]  | MATCHED | H-01       | High        | -     |
| GT-2  | High   | [title]  | MISSED  | -          | -           | FN    |
| GT-3  | Medium | [title]  | PARTIAL | M-03       | Low         | SEV   |
| -     | -      | -        | EXTRA   | M-05       | Medium      | FP    |

Metrics:
- Recall: {matched + partial} / {total GT} = X%
- Precision: {matched + partial} / {total pipeline} = X%
- Severity accuracy: {exact sev match} / {matched} = X%
```

### Step 2: Root Cause Classification (per missed finding)

For each FALSE_NEGATIVE, classify into exactly ONE root cause:

| Code | Root Cause | What Failed | Fix Strategy |
|------|-----------|-------------|-------------|
| **RC-SCOPE** | Scope gap | File/function not analyzed by any agent | Recon improvements (attack surface mapping) |
| **RC-METHOD** | Methodology gap | No rule/skill/check covers this vulnerability class | New skill OR new scanner check (see Part 3) |
| **RC-DEPTH** | Depth gap | Correct area analyzed but too shallow | Adjust depth directive, add boundary/variation hint |
| **RC-CONTEXT** | Context gap | Lacked domain knowledge or documentation | Recon doc ingestion improvements |
| **RC-NOVEL** | Novel vector | Unprecedented vulnerability class, no prior art | RAG entry only. Escalate to RC-METHOD only if user confirms the same class appeared in 3+ audits |
| **RC-AGENT** | Agent error | Agent had methodology but made a reasoning mistake | **NO PIPELINE CHANGE** - LLM reasoning errors are not fixable by adding rules |
| **RC-ANCHOR** | Anchoring bias | Agent found the area but anchored on a different interpretation | **NO PIPELINE CHANGE** - inherent LLM limitation |

**Classification rules:**
- RC-AGENT and RC-ANCHOR produce NO pipeline changes. They are noted in the session summary only.
- RC-NOVEL defaults to RAG entry. The user decides whether prior occurrence count justifies escalation.
- RC-SCOPE is the highest-priority fix (nothing downstream can compensate for missing scope).
- When in doubt between RC-METHOD and RC-DEPTH, prefer RC-DEPTH (smaller change footprint).
- **When in doubt between RC-AGENT and any fix-eligible code, default to RC-AGENT.** See Step 2.5.

### Step 2.5: RC-AGENT Presumption Gate (MANDATORY)

> **Why this exists**: LLM orchestrators are biased toward fixable root causes. When they see a miss, they want to classify it as RC-METHOD or RC-DEPTH because those have actionable fixes. RC-AGENT feels like "giving up." In practice, many misses initially classified as methodology gaps turn out to be agent reasoning errors when examined more carefully. Adding rules for RC-AGENT errors creates bloat without improving recall.

**Before classifying ANY miss as RC-METHOD, RC-DEPTH, or RC-CONTEXT, the orchestrator MUST pass the RC-AGENT Exclusion Test:**

```
RC-AGENT EXCLUSION TEST (all 3 must be YES to proceed past RC-AGENT):

1. METHODOLOGY SEARCH: Grep existing rules (R1-R16), scanner checks,
   depth templates, skills, and security rules for keywords related
   to this vulnerability class.
   → Did the search find ZERO relevant coverage? [YES/NO]
   → If NO (coverage exists): DEFAULT TO RC-AGENT.
     The agent had methodology and failed to apply it.

2. REASONING TRACE: Read the agent's actual analysis output for the
   relevant function/area.
   → Did the agent SKIP the area entirely (no mention)? [YES/NO]
   → If NO (agent analyzed it but reached wrong conclusion):
     DEFAULT TO RC-AGENT. This is a reasoning error, not a gap.

3. METHODOLOGY GAP PROOF: State in ONE sentence what specific
   methodology instruction is missing - not "the agent should have
   checked X" (that's a pattern) but "no existing rule tells the
   agent HOW to systematically discover this class of bug."
   → Can you state this without referencing the specific missed finding? [YES/NO]
   → If NO: DEFAULT TO RC-AGENT. You are describing a pattern, not methodology.
```

**If any answer is NO → classify as RC-AGENT. No pipeline change.**

**Reclassification rule**: If the user challenges a non-RC-AGENT classification during the session, re-run the exclusion test. The user's challenge is evidence that the orchestrator's bias is active. Track reclassifications in the session summary: *"Reclassified: {N} findings from RC-{original} → RC-AGENT after user challenge."*

### Step 3: Root Cause Evidence (in-session only)

For each miss that PASSED the RC-AGENT Exclusion Test, document the evidence chain:

```
Miss: {GT finding title}

RC-AGENT Exclusion Test:
1. Methodology search: [PASS - zero coverage found for {class}] / [FAIL → RC-AGENT]
2. Reasoning trace: [PASS - agent skipped area entirely] / [FAIL → RC-AGENT]
3. Methodology gap proof: "{the missing instruction}" / [FAIL → RC-AGENT]

Classification: RC-DEPTH
Evidence chain:
1. Was the file in scope? YES/NO
2. Was a relevant agent assigned? YES/NO - which one
3. Did the agent analyze the relevant function? YES/NO
4. What did the agent conclude?
5. What did the agent miss?
6. Root cause: {specific methodology gap}
7. Existing coverage: {what rule/skill/check comes closest}
```

This evidence chain is used to walk the decision tree. It is NOT persisted.

---

## Part 3: Fix Decision Tree

For each fix-eligible root cause (RC-SCOPE, RC-METHOD, RC-DEPTH, RC-CONTEXT):

> **Prerequisite**: The miss MUST have passed the RC-AGENT Exclusion Test (Step 2.5) before entering this tree. If not yet tested, go back to Step 2.5.

```
Is the gap covered by an EXISTING rule/skill/check?
├── YES → STOP. Re-run RC-AGENT Exclusion Test question 1.
│         If coverage exists, this is likely RC-AGENT.
│   ├── Coverage exists but fails to trigger → Fix trigger condition
│   │         [CHANGE TYPE: trigger-fix, ~2 lines, low risk]
│   └── Coverage exists and triggered but agent still missed
│       → RC-AGENT, no fix (agent reasoning error)
│
└── NO → Is the vulnerability class generalizable (applies to 2+ protocol types)?
    ├── YES → Is there an existing skill/rule it naturally extends?
    │   ├── YES → Add a section/check to the existing component
    │   │         [CHANGE TYPE: extend, ~5-10 lines, medium risk]
    │   └── NO → Create injectable skill (Part 4)
    │             [CHANGE TYPE: new-injectable, ~50-100 lines, high risk]
    │
    └── NO → Protocol-specific, not generalizable
            → Add to RAG knowledge base only
              [CHANGE TYPE: rag-entry, 0 pipeline lines, zero risk]
```

### Change Type Risk Tiers

| Type | Lines | Files Modified | Regression Risk |
|------|-------|---------------|----------------|
| rag-entry | 0 | 0 | Zero |
| trigger-fix | ~2 | 1-4 (recon) | Low |
| extend | ~3-10 | 1-9 (per-tree) | Medium |
| new-injectable | ~50-100 | 1 new + skill-index | Medium (isolated) |
| new-rule | ~20-40 | 4-8 (security-rules + enforcement) | High |

### Anti-Bloat Gates (MANDATORY before any `extend` or higher)

Before applying ANY change of type `extend` or higher:

1. **Line budget check**: Will this change push any single file past its size cap? (See Appendix A)
   - If YES → must compress/consolidate existing content first

2. **Duplication check**: Does this change require touching 4+ files with near-identical text?
   - If YES → consider whether the change belongs in a shared component (depth-state-trace.md, rules/, or CLAUDE.md) rather than per-tree files
   - Language-specific phrasing differences are fine; identical logic should not be duplicated

3. **Marginal value check**: Would this check have caught the missed finding AND is it unlikely to produce false positives in general?
   - If uncertain → add as injectable/conditional, not always-on
   - If likely noisy → add to RAG only

4. **Overlap check**: Does a similar check already exist under a different name?
   - Grep all scanner checks, depth checks, and skill steps for keyword overlap
   - If >60% overlap → merge into existing check, don't create new one

---

## Part 4: Injectable-First Architecture

### Principle

New methodology should be **injectable** (loaded conditionally) rather than **always-on** (appended to core files). This prevents context bloat for audits where the methodology is irrelevant.

### Injectable skill criteria
A new check/methodology should be an injectable skill if:
- It applies to a specific protocol type (vault, DEX, lending, bridge, staking, NFT marketplace)
- It applies to a specific pattern (oracle-dependent, cross-chain, governance, upgradeable proxy)
- It adds >10 lines of methodology
- It would be irrelevant for >50% of audits

### Always-on criteria
A new check should be always-on (in scanner/depth templates) ONLY if:
- It applies universally to ALL smart contracts regardless of type
- It is ≤5 lines
- The cost of missing it (when applicable) outweighs the context cost of always loading it

### Injectable skill format

```markdown
# {SKILL_NAME}

> **Trigger**: {pattern flag from recon}
> **Inject Into**: {which agent type receives this}
> **Protocol Types**: {vault, DEX, lending, etc.}
> **Added in**: v{version}

## Methodology
[methodology steps - WHAT to analyze, not WHAT to find]

## Integration Point
[which agent prompt section this appends to]
```

### Decision examples

| Gap Found | Lines | Universal? | Decision |
|-----------|-------|-----------|----------|
| Missing event on admin setter | 1 line | Yes | Always-on (Scanner B sub-check) |
| Loop accumulator co-dependency | 1 line | Yes | Always-on (Validation Sweep sub-check) |
| Write completeness for accumulators | 8 lines | Yes | Always-on (Validation Sweep CHECK) |
| Vault share inflation via first depositor | 100 lines | No, vaults only | Injectable skill |
| Oracle TWAP manipulation | 50 lines | No, oracle users only | Injectable skill |
| Cross-chain message replay | 80 lines | No, bridges only | Injectable skill |

---

## Part 5: Regression Protection

### How regression is prevented WITHOUT storing audit data

1. **Methodology over patterns**: Changes encode HOW to analyze, never WHAT to find. "Enumerate all write sites for accumulator variables" is methodology. "Check if updateReward() is called in emergencyWithdraw()" is a pattern - it belongs in RAG, not in pipeline rules.

2. **Anti-bloat gates**: Every change is checked for overlap, duplication, and line budget before implementation. This prevents the accumulation of redundant checks.

3. **User as regression oracle**: The improvement proposal template (Part 6) asks "could this produce false positives?" - the user, who has context from multiple audits, makes this judgment. The pipeline itself stores no audit history.

4. **Injectable isolation**: New skills loaded conditionally cannot affect audits where they don't trigger. A vault-specific injectable can never regress a DEX audit.

5. **Consolidation sweeps** (Part 7): Periodic review of the pipeline removes dead weight without requiring stored audit data - the user's experience is the input.

### What MEMORY.md records (the only persistent trace)

One line per improvement version:

```
## Pipeline v{X} (date)
{1-2 sentence description of methodology changes}. {N}×RC-{code} fixes, {R}×RC-AGENT reclassified. Recall: {X}% on {project type}.
```

This gives enough trend data ("recall is improving on vaults") without storing any specific findings, locations, or vulnerability descriptions that could anchor future audits. The reclassification count tracks how often the orchestrator's initial classification was overridden - a persistently high count signals the exclusion test needs strengthening.

---

## Part 6: Improvement Proposal Format

Each proposed change goes through this template before implementation:

```markdown
# Improvement Proposal: {title}

## Source
- **Root cause code**: {RC-SCOPE | RC-METHOD | RC-DEPTH | RC-CONTEXT}
- **Missed class** (generic): {e.g., "missing state update in asymmetric operations"}

## Proposed Change
- **Type**: {trigger-fix | extend | new-injectable | new-rule | rag-entry}
- **Files modified**: {list with line count deltas}
- **Total lines added/removed**: +{N} / -{N}

## Anti-Bloat Gates
- [ ] Line budget: No file exceeds cap after change
- [ ] Duplication: Change is in the most shared possible location
- [ ] Marginal value: Methodology-level fix, not pattern-level
- [ ] Overlap: No >60% overlap with existing checks

## Methodology Test
- Does this teach the agent HOW to look? → YES (proceed)
- Does this tell the agent WHAT to find? → NO (proceed) / YES → REJECT, add to RAG instead

## Regression Risk
- **Could this produce false positives for unrelated protocols?**: {assessment}
- **Does this change agent behavior for non-target protocol types?**: {yes/no}

## Decision
- [ ] APPROVED - implement
- [ ] APPROVED AS INJECTABLE - convert to injectable skill instead of always-on
- [ ] DEFERRED - add to RAG only, revisit if user reports recurrence
- [ ] REJECTED - {reason}
```

---

## Part 7: Consolidation Sweeps

When any file approaches its line budget cap OR the user requests it, run a consolidation sweep:

### What to consolidate

1. **Redundant cross-tree content**: If a scanner/depth check is identical across all 4 trees, extract to a shared location (`rules/shared-checks.md`). The per-tree file retains only language-specific phrasing.

2. **Overlapping checks**: If two checks cover >60% of the same space, merge the smaller into the larger. Fewer focused checks > many overlapping ones.

3. **Superseded checks**: If a newer check fully subsumes an older one (e.g., CHECK 7 makes a line in CHECK 1 redundant), remove the redundant piece.

4. **User-reported noise**: If the user reports a check consistently produces false positives, move it from always-on to injectable or remove it.

### Consolidation output (in-session)

```
Consolidation Sweep

Before: {N} total lines, {N} scanner checks/tree, {N} skills/tree
Actions:
| Action | Component | Reason | Lines Saved |
|--------|-----------|--------|-------------|
After: {N} total lines
Net: -{N} lines
```

---

## Part 8: Protocol Execution Checklist

When running this protocol after an audit:

### Phase A: Compare (~30 min)
- [ ] User provides ground truth report in conversation
- [ ] Create Finding Alignment Matrix (in conversation, not written to disk)
- [ ] Compute recall, precision, severity accuracy
- [ ] Present metrics to user

### Phase B: Classify (~30 min)
- [ ] For each FALSE_NEGATIVE: run RC-AGENT Exclusion Test (Step 2.5) FIRST
- [ ] Only if exclusion test passes all 3 → apply root cause classification
- [ ] Document evidence chain (in conversation), including exclusion test results
- [ ] Count: how many of each RC-code? How many reclassified to RC-AGENT?
- [ ] Filter: only RC-SCOPE, RC-METHOD, RC-DEPTH, RC-CONTEXT proceed to Phase C

### Phase C: Decide (~20 min per fix)
- [ ] For each fix-eligible miss: walk the decision tree
- [ ] Determine change type
- [ ] Run anti-bloat gates
- [ ] Apply methodology test (HOW vs WHAT)
- [ ] Fill out improvement proposal
- [ ] **User approval required** before any implementation

### Phase D: Implement (only approved changes)
- [ ] Apply changes per proposal
- [ ] Version bump affected files
- [ ] Grep verify key phrases
- [ ] Update MEMORY.md with one-line version entry (metrics + RC distribution, no findings)

---

## Appendix A: File Size Budget Caps

| File Category | Current Range | Cap | Rationale |
|---------------|-------------|-----|-----------|
| Scanner templates | 340-526 lines | 600 | Agent context budget |
| Depth templates | 117-212 lines | 250 | Depth agents need room for analysis output |
| Generic security rules | 436-938 lines | 1000 | Reference doc, not fully loaded into agents |
| Individual skills | 31-309 lines | 300 | Injected into agent prompts alongside other content |
| Recon prompt | 388-994 lines | 1100 | Largest per-tree file; recon agent gets dedicated context |
| Inventory prompt | 222-287 lines | 350 | Single-purpose agent |
| CLAUDE.md | 424 lines | 500 | Loaded into every conversation |
| Confidence scoring | 146 lines | 200 | Reference doc for scoring agent |
| Chain prompt | 209 lines | 250 | Single-purpose agent |
| Report prompts | 400 lines | 500 | Template for 3 parallel writers |

## Appendix B: Change Type Impact Matrix

| Change Type | Files Modified | Lines Added | Cross-Tree? | Regression Surface |
|-------------|---------------|-------------|-------------|-------------------|
| rag-entry | 0 | 0 | No | Zero |
| trigger-fix | 1-4 | ~2 | Recon only | Minimal |
| extend (shared file) | 1 | 3-10 | No | Low |
| extend (per-tree) | 4-9 | 12-90 | Yes | Medium |
| new-injectable | 1-5 new | 50-100 | Per-language | Low (isolated) |
| new-rule | 4-8 | 80-320 | Yes | High |
| new-scanner-check | 4 | 12-40 | Yes | Medium |
