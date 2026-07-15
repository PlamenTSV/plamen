# Post-Audit Improvement Protocol

> **When**: Optionally, after an audit completes AND a human/ground-truth report exists for comparison.
> **Who**: The orchestrator runs this as a standalone session - NOT during the audit itself.
> **Goal**: Identify gaps, classify root causes, propose minimal targeted fixes, and prevent regression and bloat.
> **Principle**: The pipeline should grow logarithmically, not linearly, with each post-mortem.

---

## Part 0: HARD RULE — NO CODEBASE OVERFITTING (NEVER NEVER NEVER)

Audit methodology (skills, rules, prompts, scanner checks) and persistent memory MUST encode **HOW to analyze**, NEVER **WHAT to find in a specific protocol**.

**Forbidden:**
- A specific project/protocol/token/contract/struct/function name used as a "check for X" hint, a floor-catalog row, or a dedicated section (e.g. a "Bridge X: check native GAS vs wrapped GAS" row). Naming the answer is overfitting.
- Storing specific past-audit FINDING descriptions, finding IDs, or file:line locations in memory. Memory may store ONLY recall %, precision %, and RC-distribution counts — never the bugs themselves.
- RAG/web queries that pull the SAME-CONTEST judging/answer repo (`*-judging`, the contest's own issues) when measuring recall.

**Allowed:** a generic mechanism with ONE illustrative example (e.g. "native vs wrapped gas token, like ETH/WETH") — never a dedicated protocol row, never the protocol whose audit motivated it as the example.

**The test, applied before adding ANY skill/rule/memory content:** "Does this teach a general method, or does it name a specific codebase's answer?" If the latter → genericize it, route it to RAG-as-generic-vuln-class, or drop it.

**Why this exists (permanent record):** a cross-chain DEX benchmark was found primed by (a) a chain-specific HARD_OVERFIT floor row + a dedicated integration-hazard-research section, (b) RAG electing the same-contest judging/answer repo as precedent, and (c) memory files storing prior-audit finding descriptions + a file:line. The generic methodology found the bugs on its own (none of the recalls were load-bearing on the overfit) — so overfitting adds NO recall and only fakes the benchmark. Never again.

---

## Part 1: The Problem This Protocol Solves

### Current state
- **330+ markdown files**, **80,000+ lines** across agents/, rules/, prompts/, skills/
- **150+ skill files** across 6 SC language trees (EVM, Solana, Aptos, Sui, Soroban, DAML) + 1 L1 tree + injectable/niche
- **~160 scanner checks** across 6 SC trees (25-30 per tree)
- **Every improvement is additive**: each version adds files, rules, and lines without removing old ones
- **Cross-tree duplication**: Each fix must be applied to 4-9 files (EVM, Solana, Aptos, Sui, Soroban, DAML)

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
- RC-AGENT misses MAY still route to a driver-level fix (`mechanical-gate`) instead of no-fix — but ONLY through the RC-AGENT-MECHANIZABLE escape hatch in Step 2.5, gated by all 4 M-gates. This is not a reclassification of root cause; RC-AGENT stands.

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

#### RC-AGENT-MECHANIZABLE Escape Hatch (NARROW — does not weaken RC-AGENT)

A miss classified RC-AGENT still gets **no prose/methodology-instruction
change** — Step 2.5's "no pipeline change" holds. But a small number of
RC-AGENT misses are not "the LLM should try harder next time" — they are
cases where the correct disposition is **fully computable from artifacts the
pipeline already produces** (PoC ledgers, verification verdicts, disposition
tags) without any agent judgment call at all. For exactly this narrow case,
reclassify the FIX (not the root cause) as **RC-AGENT-MECHANIZABLE** and
route it to `[CHANGE TYPE: mechanical-gate]` (Part 3a) instead of "no
pipeline change" — ONLY if ALL four gates below pass. Root cause stays
RC-AGENT in the session summary; only the fix disposition changes.

**M-Gates (all 4 required — any NO keeps the miss at RC-AGENT / no fix):**

- **M1 — Recurring ≥3 audits**: The same failure PATTERN (not the same
  finding) has been observed independently in 3+ prior audits. A one-off is
  RC-AGENT with no fix, full stop — same bar as RC-NOVEL escalation.
- **M2 — Deterministic without agent judgment**: The correct disposition can
  be computed by a Python driver check reading structured artifacts already
  on disk (PoC ledger, verify verdict, disposition tag, citation ledger) —
  with NO step that asks an LLM agent to "remember," "apply judgment," or
  "try harder." If the fix is still a sentence added to an agent prompt, it
  is prose, not mechanizable — reject to RC-AGENT.
- **M3 — Generic**: The gate keys ONLY on structural/evidence relations
  (e.g. confirmed-in-scope-mechanism, external-gated-demotion,
  citation-ledger-stub, PoC-not-attempted-taxonomy) — never a
  protocol/token/contract/function name. Must independently pass Part 0.
- **M4 — Verify-filtered**: The gate fires only on findings that have already
  passed through the verification funnel (has a verify verdict / PoC ledger
  entry) — never a raw, pre-verification severity or disposition assignment.

If all four pass, the fix is a `mechanical-gate` change: driver code
(`plamen_contracts.py`/`plamen_markdown.py` or the phase's computed-ledger
layer, e.g. `severity_binding.md`/`disposition.md`-style outputs), never a
rule/skill/prompt sentence. This is why it does not contradict "RC-AGENT = no
pipeline change" — that prohibition targets prose instructions the agent must
apply via judgment, which is precisely the class of fix Step 2.5 exists to
block.

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

### Part 3a: RC-AGENT-MECHANIZABLE Path (bypasses the tree above)

This path does NOT enter the Fix Decision Tree above — that tree is scoped to
fix-eligible root causes (RC-SCOPE/RC-METHOD/RC-DEPTH/RC-CONTEXT). A miss that
cleared the RC-AGENT-MECHANIZABLE escape hatch (Step 2.5) routes directly to:

```
RC-AGENT miss + M1 + M2 + M3 + M4 all PASS
  → [CHANGE TYPE: mechanical-gate; scope and risk set by the owning seam and
     lifecycle review, never inferred from line count]
```

`mechanical-gate` changes are implemented ONLY in the Python driver layer
(computed ledgers such as `severity_binding.md`/`disposition.md`/
`status_binding.md`, or an equivalent mechanical gate) — never as an addition
to an agent prompt, skill, or rule file. If implementation requires touching
an agent prompt to explain a NEW concept the agent must apply, the change is
not `mechanical-gate` — reclassify under the normal tree (most likely
`new-rule`) or back it out to RC-AGENT/no-fix.

#### Mandatory Mechanical-Gate Lifecycle Registry and Review Contract

Every proposed or shipped mechanical gate MUST have exactly one registry record
in the improvement proposal or the canonical gate registry. Do not create a
per-gate methodology document. A gate is a protocol component, not a presumed
10–30-line/low-risk patch: identity joins, parser changes, phase ordering, and
report disposition can make a short predicate system-wide and high risk.

Each registry record MUST define:

1. **Identity and seam** — stable gate ID/name, owning phase/hook, execution
   order, owner, and an independent reviewer who did not author the gate.
2. **Purpose and direction** — generic miss class, whether the gate generates,
   reconciles, caps, floors, flags, or routes, and the monotonicity claim.
3. **Input/output contract** — authoritative artifacts and schema versions,
   identifier/join rules, emitted artifacts/receipts, and downstream consumers.
4. **M1–M4 evidence** — recurrence evidence, proof the predicate is
   deterministic without model judgment, Part-0 genericity result, and the
   verify-filter boundary. Passing M1–M4 admits design review; it does not prove
   the implementation safe.
5. **Failure/degrade contract** — behavior for absent, malformed, stale, split,
   duplicate, or contradictory inputs; haltless behavior must surface UNKNOWN or
   human review and must not masquerade as CLEAR.
6. **Runtime and cost envelope** — expected and worst-case work, caps/truncation
   receipts, phase budget, and any external/tool/worker cost.
7. **Evidence for release** — fixture-first red→green cases, precision no-fire
   controls, idempotence/resume and fault-injection coverage, blast-radius tests,
   and held-out replay evidence separate from the audit that motivated the gate.
8. **False-fire budget** — a measurable maximum count/rate on the named held-out
   corpus, the observation window, and the action when exceeded (disable,
   narrow, or return to review). Zero observed fires is evidence only for that
   corpus, not a universal guarantee.
9. **Consolidation relationship** — overlapping gates, shared parsers/ledgers,
   why this belongs at this seam, and the merge/replace plan if another gate
   subsumes it.
10. **Review and sunset** — lifecycle state, review date/owner, telemetry to
    inspect, and explicit retirement criteria (superseded, persistently noisy,
    unused, or no longer justified by recurrence evidence).

Lifecycle states are `PROPOSED → FIXTURED → SHADOW/REPLAY → ACTIVE →
CONSOLIDATED|SUNSET`. Promotion to `ACTIVE` requires independent review of the
record and diff. The motivating audit is regression evidence only; it cannot be
the sole held-out validation. Any schema/cutover change reopens review at
`PROPOSED`, even when the predicate itself is unchanged.

### Change Type Risk Tiers

| Type | Lines | Files Modified | Regression Risk |
|------|-------|---------------|----------------|
| rag-entry | 0 | 0 | Zero |
| trigger-fix | ~2 | 1-4 (recon) | Low |
| extend | ~3-10 | 1-9 (per-tree) | Medium |
| new-injectable | ~50-100 | 1 new + skill-index | Medium (isolated) |
| new-rule | ~20-40 | 4-8 (security-rules + enforcement) | High |
| mechanical-gate | Measured, not presumed | Owning seam + shared schema/parser/tests as required | Seam-dependent; high for identity, disposition, or cutover changes |

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

> **MANDATORY GATE — applies before ANY skill/rule/memory change**: Every proposed change MUST first pass the **Part 0: HARD RULE — NO CODEBASE OVERFITTING** test. If the change names a specific codebase's answer (protocol/token/contract/struct/function as a check-for-X hint or floor row, a stored finding description/ID/file:line, or a same-contest judging/answer source), it is REJECTED here — genericize it, route it to RAG-as-generic-vuln-class, or drop it. No change proceeds past this gate without clearing Part 0.

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
- **Type**: {trigger-fix | extend | new-injectable | new-rule | rag-entry | mechanical-gate}
- **Files modified**: {list with line count deltas}
- **Total lines added/removed**: +{N} / -{N}
- **Mechanical-gate registry ID/state**: {required for mechanical-gate; otherwise N/A}

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

1. **Redundant cross-tree content**: If a scanner/depth check is identical across all SC trees, extract to a shared location (e.g. a `rules/shared-checks.md`). The per-tree file retains only language-specific phrasing.

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
- [ ] For a mechanical gate: complete its lifecycle registry record and independent review plan
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
| Scanner templates | 514-671 lines | 700 | Agent context budget |
| Depth templates | 230-326 lines | 350 | Depth agents need room for analysis output |
| Generic security rules | 459-816 lines | 1000 | Reference doc, not fully loaded into agents |
| Individual skills | 37-500 lines | 550 | Injected into agent prompts alongside other content |
| Recon prompt | 653-1143 lines | 1200 | Largest per-tree file; recon agent gets dedicated context |
| Inventory prompt | 299-379 lines | 400 | Single-purpose agent |
| CLAUDE.md | ~90 lines (canonical `.plamen/CLAUDE.md`) | 500 | Loaded into every conversation |
| Confidence scoring | 236 lines | 250 | Reference doc for scoring agent |
| Chain prompt | 413 lines | 450 | Single-purpose agent |
| Report prompts | 737 lines | 800 | Template for 3 parallel writers |

## Appendix B: Change Type Impact Matrix

| Change Type | Files Modified | Lines Added | Cross-Tree? | Regression Surface |
|-------------|---------------|-------------|-------------|-------------------|
| rag-entry | 0 | 0 | No | Zero |
| trigger-fix | 1-4 | ~2 | Recon only | Minimal |
| extend (shared file) | 1 | 3-10 | No | Low |
| extend (per-tree) | 4-9 | 12-90 | Yes | Medium |
| new-injectable | 1-5 new | 50-100 | Per-language | Low (isolated) |
| new-rule | 4-8 | 80-320 | Yes | High |
| mechanical-gate | Owning seam + shared contracts/tests | Measured | No methodology-tree duplication | Seam-dependent; highest at identity/disposition/cutover seams |
| new-scanner-check | 4 | 12-40 | Yes | Medium |
