# Phase 4: Confidence Scoring & Adaptive Depth

> **Usage**: The orchestrator may ask a lightweight helper to return a
> transient routing proposal during the Adaptive Depth Loop. The deterministic
> driver independently applies the formulas below and publishes the canonical
> confidence authority after the depth wave. No model may pre-create or modify
> that canonical authority.

---

## Code-Confidence Model + Separate Precedent Context

Every finding is scored on three code-derived axes after Phase 4b iteration 1.
External precedent is reconciled separately under
`precedent-evidence-policy.md`; it is never a confidence axis.

| Axis | What It Measures | Scoring |
|------|-----------------|---------|
| **Evidence** | Quality of supporting evidence | Best evidence tag: [PROD-ONCHAIN]=1.0, [PROD-SOURCE]=0.9, [PROD-FORK]=0.9, [MEDUSA-PASS]=1.0, [CODE]=0.8, [DOC]=0.4, [MOCK]=0.2, [EXT-UNV]=0.1 |
| **Consensus** | Independently corroborated analysis | Read the driver-derived `consensus_map.md`, which projects `confidence_consensus_authority.json`. One current observer = 0.0; one current, separately dispatched corroborator = 0.5; two = 0.75; three or more = 1.0. Corroborators must have distinct worker, prompt, and dispatch identities and explicitly reference the same upstream finding identity. Location coincidence, copied/retry prose, stale/unbound artifacts, and skill assignment are not agreement. |
| **Analysis Quality** | Depth of analytical work performed | **Mode A** (depth agent findings, including [DST-*]): Count Depth Evidence tags - 0 tags=0.1, 1 tag=0.4, 2 tags=0.7, 3+ tags=1.0. **Mode B** (all other findings): Legacy step execution - (steps marked ✓) / (total applicable steps). Steps marked ✗(valid reason) count as ✓. Steps marked ✗(no reason) or ? count as 0. |
| **Precedent Context (not scored)** | Investigation priority/report context only | Read only from driver-derived `precedent_evidence_authority.json`. Generic literature, exact precedent, refuting sources, timeouts, and unavailable research all contribute `0.0` to mechanism/code confidence. |

### Composite Score Formula

```
composite = Evidence × 0.25 + Consensus × 0.25 + Analysis_Quality × 0.3
```

**Rationale**: Analysis Quality uses dual-mode scoring: depth agents are scored
on concrete evidence tags (boundary substitution, parameter variation, trace to
termination); breadth agents retain step-execution scoring. Consensus measures
independent corroboration, not source quality or methodology assignment. The
coefficient sum intentionally remains `0.8`: removing the historical `0.2` RAG
slot must not silently normalize weak code evidence upward and stop depth.

### Severity-Weighted Spawn Priority

Used by the orchestrator to allocate budget in iterations 2-3. Does NOT modify the composite score.

```
spawn_priority = (1 - composite) * severity_weight + exact_precedent_priority_bonus
```

| Severity | Weight |
|----------|--------|
| Critical | 4 |
| High | 3 |
| Medium | 2 |
| Low | 1 |
| Info | 0.5 |

`exact_precedent_priority_bonus` is non-negative and exists only for a current
typed exact-precedent row. It can move work earlier; it can never reduce, skip,
or close work. Generic/similar/refuting/unavailable research gets zero bonus.
Spawn highest-priority domains first within remaining budget.

---

## Routing Thresholds

| Composite Score | Classification | Action |
|----------------|---------------|--------|
| ≥ 0.7 | **CONFIDENT** | No more depth needed for routing; verification and lifecycle gates remain unchanged |
| 0.4–0.7 | **UNCERTAIN** | Spawn targeted depth agent for this finding's domain |
| < 0.4 | **LOW CONFIDENCE** | Spawn depth agent + force production verification; precedent research is optional investigation context |

---

## Convergence Criteria

1. **Hard iteration cap**: Maximum 3 iterations (iteration 1 = full coverage, iterations 2-3 = targeted)
2. **Dynamic spawn cap**: `depth_floor = 12 + max(0, 5 - actual_breadth_count)`, then:
   ```
   niche_injectable_count = len(niche_agents)
   niche_overflow = max(0, niche_injectable_count - 3)
   thorough_bonus = 5 if MODE == THOROUGH else 0
   hard_cap = 20 + niche_overflow + thorough_bonus
   // Raise the floor to guarantee iteration 2-3 budget:
   iter1_fixed = 10 + niche_injectable_count + 1  // 10 base + niche/injectable + DST
   iter23_reserve = 3 if MODE == THOROUGH else 0
   effective_floor = max(depth_floor, iter1_fixed + iter23_reserve)
   max_depth_spawns = min(max(effective_floor, ceil(total_findings / 5) + 7), hard_cap)
   ```
   The base cap (20) applies to Core/Light. In Thorough mode, the cap scales with niche+injectable demand AND the floor rises to guarantee iteration 2-3 budget. Base iter1 consumption: 10 fixed (4 depth + 3 scanners + 1 validation sweep + 1 sibling propagation + 1 DST) + niche + injectable. The `effective_floor` ensures max_depth_spawns is always >= iter1 consumption + 3 reserved slots in Thorough mode. Examples: Core, 6 breadth + 25 findings + 2 niche → floor=12, max=12, iter1=13, remaining=0 (redirect saves 0). Thorough, 8 breadth + 68 findings + 11 niche/injectable → iter1_fixed=22, reserve=3, effective_floor=25, cap=33, max_depth_spawns=25, iter1=22, remaining=3.
3. **Progress check**: If NO finding's confidence improved in an iteration → exit loop early
3a. **Iteration 2 skip policy**: Iteration 2 may ONLY be skipped if all UNCERTAIN findings are Low/Info severity. If ANY uncertain finding is Medium or above, iteration 2 is MANDATORY. "Pragmatic" skips of iteration 2 for Medium+ findings are a workflow violation.
4. **Zero uncertain**: If 0 findings score < 0.7 after any iteration → exit loop
5. **Unresolved after cap**: Any finding still below the routing threshold
   remains a candidate and routes to mandatory verification or visible
   human-review debt. Confidence telemetry never changes a verdict.
6. **Oscillation detection**: If more than half of score changes reverse,
   classify the loop as OSCILLATORY, retain every unresolved candidate,
   record routing debt, and exit the depth loop.

---

## Anti-Dilution Rules

### Rule AD-1: Evidence-Only Carryover (+ Contrastive Path Summaries)

Between iterations, carry forward ONLY:
- Finding ID, title, location
- Evidence code references (file:line)
- Evidence source tags ([CODE], [PROD-ONCHAIN], etc.)
- Current confidence score
- A focused investigation question
- **Analysis path summary**: A 1-2 sentence description of WHAT the previous agent analyzed and HOW it reasoned - not what it concluded. Example: *"Iteration 1 agent traced the numerator manipulation path through supply changes; did not explore divisor staleness or timestamp anchor."* This summary is used for contrastive conditioning: telling the next agent what was already explored so it can deliberately diverge.

**Explicitly excluded**: All prior agent verdicts, confidence assessments, and cross-references. Analysis path summaries describe the EXPLORATION PATH (what was looked at), not the REASONING OUTPUT (what was concluded).

### Rule AD-2: Hard Devil's Advocate Role

Iteration 2+ agent prompts include a STRUCTURAL adversarial role, not just a soft freshness instruction. Research shows soft instructions ("think critically", "do fresh analysis") produce <50% divergence, while hard DA role assignment produces >99% divergence.

Iteration 2+ agents receive this framing:
*"You are the Devil's Advocate Depth Agent. Your PRIMARY job is to find what the previous analysis MISSED - not to re-confirm what it found. For each finding you investigate:*
*1. Read the analysis path summary (what was explored). Your job is to explore what was NOT.*
*2. For each CONFIRMED conclusion from iteration 1: ask 'what adjacent bug does this analysis OBSCURE?' What is the OPPOSITE interpretation of the same code?*
*3. For each REFUTED conclusion from iteration 1: ask 'what enabler makes this exploitable after all?'*
*4. You MUST explore at least one path that the previous analysis did NOT. If you find no new vulnerability after exploring that path, state what you explored and why it is safe — that is a valid output."*

**IMPORTANT**: Point 4 requires EXPLORATION, not PRODUCTION. A DA agent that explores a new path and concludes "this is safe because X" has done its job. A DA agent that fabricates a finding to satisfy a quota has not. The value of iteration 2 is the unexplored path coverage, not the finding count.

Iteration 2+ agents are told the analysis path (what was explored) but NOT the conclusions (what was decided). They receive analysis path summaries from AD-1 but no verdicts.

**MANDATORY**: The orchestrator MUST include the INVARIANT CONSISTENCY CHECK (HARD GATE) directive from the depth templates in every iteration 2+ agent prompt. DA agents are not exempt from the gate — they must check their findings against documented operational implications before CONFIRMING at Medium+. The orchestrator copies the directive from `phase4b-depth-templates.md` § INVARIANT CONSISTENCY CHECK into the DA agent prompt.

### Rule AD-3: Focused Input Cap

Each iteration 2+ agent receives at most **5 uncertain findings** in its domain. If more than 5 exist, prioritize by lowest confidence score.

### Rule AD-4: Fresh Tool Calls Mandatory

Iteration 2+ agents MUST make their own code-analysis/static-analysis calls
rather than relying on summaries from iteration 1. External precedent calls may
suggest test ideas but are not confidence evidence.

### Rule AD-5: New-Evidence-Only Re-Scoring

Re-scoring after iteration 2+ only upgrades confidence if the agent produced NEW evidence - defined as:
- A new code reference not in the iteration 1 output
- A new code-analysis/static-analysis tool output
- A new production verification result

External precedent, literature, match counts, and RAG scores never qualify as
new mechanism-confidence evidence. An exact typed precedent can only raise the
investigation-priority signal described above.

Merely restating the same analysis with different words = zero confidence change.

### Rule AD-6: Error Trace Injection

Error traces from failed PoCs (Phase 5 verification) become investigation questions for post-verification targeted depth. Error traces bypass AD-2 (no reasoning contamination) because they are mechanical output from test execution, not agent reasoning. The orchestrator extracts error traces from `verify_*.md` files, writes them to `{SCRATCHPAD}/verification_error_traces.md`, and uses them as investigation questions for post-verification depth agents (only if budget remaining > 0).

---

## `extract_evidence_only()` - Finding Card Format for Iteration 2+

Each finding card sent to iteration 2+ agents contains ONLY:

```markdown
## Finding [XX-N]: Title
- **Location**: SourceFile:L45-L67
- **Evidence**: [CODE] - validation check at L45; [CODE] - state update at L52
- **Confidence**: 0.35
- **Evidence Gap**: [What specific evidence is missing - e.g., "No production verification of external behavior"]
- **Prior Path**: [1-2 sentence analysis path summary - what the previous agent explored and how. E.g., "Traced numerator manipulation via supply inflation; did not explore divisor staleness or timestamp anchor."]
- **Investigate**: [Focused question - e.g., "Can setMaxBond() be called with value below current totalBonded? Trace what happens to the while loop at L120."]
```

**Max ~250 chars per finding card** (excluding code refs). The Prior Path field enables contrastive conditioning without prescribing the approach.

---

## Re-Scoring Rules

1. **Monotonic confidence**: Confidence can only increase or stay flat between iterations. Evidence from prior iterations is preserved.
2. **New evidence required**: Score increase requires at least one NEW evidence tag not present in the previous iteration's scoring input.
3. **No self-referential scoring**: A transient routing proposal and the
   driver derivation both score evidence artifacts, never a depth worker's
   self-reported confidence.
4. **Transient helper model**: When the coordinator needs a mid-session
   routing proposal, use sonnet-class. The helper returns a compact table to
   the coordinator and has no scratchpad write authority. If it fails, route
   every unresolved Medium+ candidate as UNCERTAIN rather than skipping depth.

---

## Phase 4b.5: Mandatory External Precedent Research

> **Trigger**: Always, after the depth loop exits.
> **Purpose**: Build bounded investigation/report context. It does not re-score
> findings or alter how much depth they receive.
> **Model**: sonnet.
> **Budget**: 1 agent (not counted against depth budget).

The worker follows `prompts/shared/v2/phase4b5-rag-sweep.md` and the shared
`precedent-evidence-policy.md`. It writes one row per finding plus one bounded
typed proposal block in `rag_validation.md`. Generic methodology literature
supplies context only. Exactness requires a primary precedent with the same
mechanism class and matching preconditions. Family propagation requires typed
equivalence.

If the research worker fails, do not retry a failing provider. Write complete
`UNAVAILABLE` proposal rows, reconcile them to visible debt, and continue.
There is no numeric floor and confidence scores remain unchanged.

The deterministic driver extracts the proposal block and reconciles it against
typed finding mechanism/precondition facts into
`precedent_evidence_authority.json`; `precedent_context.md` is its investigation projection
and `precedent_report_context.md` contains only receipt-bound report-eligible rows.

---

## Scratchpad Artifacts

| File | Written By | Contents |
|------|-----------|----------|
| `confidence_consensus_authority.json` | Deterministic driver (before scoring) | Hash-bound observations, explicit upstream semantic anchors, dispatch provenance, independence disposition, and Axis 2 scores |
| `consensus_map.md` | Deterministic driver (before scoring) | Exact Markdown projection of the typed consensus authority; never an independent source of authority |
| `confidence_scores.md` | Deterministic driver confidence transaction | Canonical per-finding code-derived scores + composite + classification; no precedent contribution |
| `confidence_distribution.md` | Orchestrator (after scoring) | CONFIDENT/UNCERTAIN/LOW counts + exit condition check |
| `adaptive_loop_log.md` | Orchestrator (after loop exits) | Iteration count, spawns used, exit condition triggered, per-iteration summary |
| `verification_error_traces.md` | Orchestrator (after Phase 5) | Error traces from failed PoCs, formatted as investigation questions for post-verification depth |
| `rag_validation.md` | External precedent research worker | Human table plus typed proposal block; no decision authority |
| `precedent_evidence_authority.json` | Deterministic driver | Exact/context/unavailable reconciliation, typed caps, input digests, and debt |
| `precedent_context.md` | Deterministic driver | Read-only investigation-priority projection; not a report citation source |
| `precedent_report_context.md` | Deterministic driver | Receipt-bound, report-eligible context only |
| `design_stress_findings.md` | Design Stress Testing Agent | Design limit, adequacy, and constraint coherence findings |
| `composition_coverage.md` | Chain Analysis Agent | Finding-pair composition coverage map (explored/unexplored) |
| `violations.md` | Orchestrator (on skip) | Thorough mode workflow violations - skipped mandatory steps (Rule 12) |
| `checkpoint_postdepth.md` | Orchestrator (after depth) | Post-depth assertion results for Thorough mode completeness |
