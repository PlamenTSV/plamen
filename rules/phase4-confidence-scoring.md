# Phase 4: Confidence Scoring & Adaptive Depth

> **Usage**: Orchestrator references this file during the Adaptive Depth Loop in Phase 4b.
> The scoring agent (haiku) uses the formulas below. The orchestrator uses the thresholds for routing.

---

## 4-Axis Confidence Model

Every finding is scored on 4 axes after Phase 4b iteration 1 completes:

| Axis | What It Measures | Scoring |
|------|-----------------|---------|
| **Evidence** | Quality of supporting evidence | Best evidence tag: [PROD-ONCHAIN]=1.0, [PROD-SOURCE]=0.9, [PROD-FORK]=0.9, [MEDUSA-PASS]=1.0, [CODE]=0.8, [DOC]=0.4, [MOCK]=0.2, [EXT-UNV]=0.1 |
| **Consensus** | Domain-aware agreement | (agents that flagged same root cause) / (agents whose domain covers this location). If only 1 agent's domain covers the location → Consensus = 1.0 if that agent found it. **Specialized agent bonus**: +0.2 when finding discovered by an agent instantiated from a Required skill template (capped at 1.0). |
| **Analysis Quality** | Depth of analytical work performed | **Mode A** (depth agent findings, including [DST-*]): Count Depth Evidence tags - 0 tags=0.1, 1 tag=0.4, 2 tags=0.7, 3+ tags=1.0. **Mode B** (all other findings): Legacy step execution - (steps marked ✓) / (total applicable steps). Steps marked ✗(valid reason) count as ✓. Steps marked ✗(no reason) or ? count as 0. |
| **RAG Match** | Historical precedent strength | RAG confidence from `rag_validation.md` (written by Phase 4b.5 RAG Sweep). Score = validate_hypothesis result / 10. If RAG Sweep tool call failed for a finding: 0.3 (floor). |

### Composite Score Formula

```
composite = Evidence × 0.25 + Consensus × 0.25 + Analysis_Quality × 0.3 + RAG_Match × 0.2
```

**Rationale**: Weighted average ensures no single axis can gate the score. Analysis Quality uses dual-mode scoring: depth agents are scored on concrete evidence tags (boundary substitution, parameter variation, trace to termination) to incentivize actual analytical work; breadth agents retain step execution scoring to avoid regression.

### Severity-Weighted Spawn Priority

Used by the orchestrator to allocate budget in iterations 2-3. Does NOT modify the composite score.

```
spawn_priority = (1 - composite) * severity_weight
```

| Severity | Weight |
|----------|--------|
| Critical | 4 |
| High | 3 |
| Medium | 2 |
| Low | 1 |
| Info | 0.5 |

Spawn highest-priority domains first within remaining budget. This ensures a Critical finding at 0.5 confidence (priority = 0.5 × 4 = 2.0) gets depth before a Low finding at 0.4 confidence (priority = 0.6 × 1 = 0.6).

---

## Routing Thresholds

| Composite Score | Classification | Action |
|----------------|---------------|--------|
| ≥ 0.7 | **CONFIDENT** | No more depth needed for this finding |
| 0.4–0.7 | **UNCERTAIN** | Spawn targeted depth agent for this finding's domain |
| < 0.4 | **LOW CONFIDENCE** | Spawn depth agent + force production verification + RAG deep search |

---

## Convergence Criteria

1. **Hard iteration cap**: Maximum 3 iterations (iteration 1 = full coverage, iterations 2-3 = targeted)
2. **Dynamic spawn cap**: `depth_floor = 12 + max(0, 4 - actual_breadth_count)`, then `max_depth_spawns = min(max(depth_floor, ceil(total_findings / 5) + 7), 20)`. Simple codebases (2 breadth agents) get floor=14. Examples: 2 breadth + 20 findings → 14, 4 breadth + 20 findings → 12, 4 breadth + 40 findings → 15, any + 68 findings → 20 (cap).
3. **Progress check**: If NO finding's confidence improved in an iteration → exit loop early
3a. **Iteration 2 skip policy**: Iteration 2 may ONLY be skipped if all UNCERTAIN findings are Low/Info severity. If ANY uncertain finding is Medium or above, iteration 2 is MANDATORY. "Pragmatic" skips of iteration 2 for Medium+ findings are a workflow violation.
4. **Zero uncertain**: If 0 findings score < 0.7 after any iteration → exit loop
5. **Forced CONTESTED**: After all iterations, any finding still < 0.4 → forced to CONTESTED verdict
6. **Oscillation detection**: If >50% of score changes in iteration N are reversals (a finding that went up now goes down, or vice versa) → classify as OSCILLATORY → force all uncertain to CONTESTED, exit loop

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
*4. You MUST produce at least one finding or observation that CONTRADICTS or EXTENDS the previous analysis. If you agree with everything, you have not done your job."*

Iteration 2+ agents are told the analysis path (what was explored) but NOT the conclusions (what was decided). They receive analysis path summaries from AD-1 but no verdicts.

### Rule AD-3: Focused Input Cap

Each iteration 2+ agent receives at most **5 uncertain findings** in its domain. If more than 5 exist, prioritize by lowest confidence score.

### Rule AD-4: Fresh Tool Calls Mandatory

Iteration 2+ agents MUST make their own MCP tool calls (static analyzer, RAG) rather than relying on summaries from iteration 1. Fresh tool output prevents stale-data regression.

### Rule AD-5: New-Evidence-Only Re-Scoring

Re-scoring after iteration 2+ only upgrades confidence if the agent produced NEW evidence - defined as:
- A new code reference not in the iteration 1 output
- A new MCP tool output (static analyzer function source, RAG match)
- A new production verification result

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
3. **No self-referential scoring**: The scoring agent scores based on evidence artifacts in the scratchpad files, not on the depth agent's self-reported confidence.
4. **Scoring agent model**: Always haiku (mechanical task - formula application, not reasoning).

---

## Phase 4b.5: Mandatory RAG Validation Sweep

> **Trigger**: Always, after depth loop exits (Phase 4b DONE) and before confidence scoring.
> **Purpose**: Ensures every finding gets RAG validation as a PIPELINE STAGE, not an optional agent tool call.
> **Model**: sonnet (haiku rejects unified-vuln-db MCP tool schemas containing oneOf/allOf - see v1.0.1 fix)
> **Budget**: 1 agent (not counted against depth budget)

### Pre-check: RAG_TOOLS_AVAILABLE flag

Before spawning, the orchestrator reads `{SCRATCHPAD}/build_status.md` for `RAG_TOOLS_AVAILABLE`. This flag is set by the recon agent's unified-vuln-db probe (Phase 1).

- If `RAG_TOOLS_AVAILABLE = true` → spawn RAG sweep agent normally
- If `RAG_TOOLS_AVAILABLE = false` → spawn RAG sweep agent with **web search fallback mode** (see fallback chain below)
- If flag is missing (recon probe was skipped) → assume `true`, let the agent handle failures via its fallback chain

### Orchestrator spawns:

```
Task(subagent_type="general-purpose", model="sonnet", prompt="
You are the RAG Validation Sweep Agent.

## Your Task
For EVERY finding in {SCRATCHPAD}/findings_inventory.md:
1. Call validate_hypothesis(hypothesis='{finding title}: {1-line root cause}')
2. Call search_solodit_live(keywords='{vulnerability class}', max_results=10)
3. Record the result

If a tool call fails, record [RAG: TOOL_ERROR] for that finding - do NOT silently skip.

## Fallback Chain (if MCP tools fail)
If validate_hypothesis or search_solodit_live fails (API error, schema error, timeout):
1. Try get_similar_findings(pattern='{finding description}')
2. If that also fails: try get_common_vulnerabilities(category='{vulnerability class}')
3. If ALL MCP tools fail: use WebSearch fallback - search 'site:solodit.xyz {vulnerability class} {key term}' for each finding and extract match count + relevance
4. If WebSearch also fails: record [RAG: ALL_TOOLS_FAILED] and score = 0.3

**IMPORTANT**: If the FIRST MCP call fails with a schema/API error, assume ALL MCP calls will fail. Switch immediately to WebSearch fallback for remaining findings instead of retrying each one. This prevents N×timeout delays.

## Output
Write to {SCRATCHPAD}/rag_validation.md:
| Finding ID | validate_hypothesis Score | solodit_live Matches | Final RAG Score | Notes |

Return: 'DONE: {N} findings validated, {E} tool errors, fallback={MCP|WEB|NONE}'
")
```

### Retry on agent failure (orchestrator inline)

If the RAG sweep agent itself fails (API error, crash, 0 output):
1. **Do NOT retry with the same model** - the failure is likely schema-level, not transient
2. Log: `"RAG sweep failed: {error}. Writing floor scores."`
3. Write `{SCRATCHPAD}/rag_validation.md` with 0.3 floor for all findings
4. Continue to confidence scoring - the floor score preserves pipeline progress
```

The scoring agent reads `rag_validation.md` for Axis 4 instead of checking individual agent outputs.

---

## Scratchpad Artifacts

| File | Written By | Contents |
|------|-----------|----------|
| `consensus_map.md` | Orchestrator (before scoring) | Pre-computed Axis 2 consensus scores for all findings |
| `confidence_scores.md` | Scoring agent batches (after each iteration) | Per-finding 4-axis scores + composite + classification |
| `confidence_distribution.md` | Orchestrator (after scoring) | CONFIDENT/UNCERTAIN/LOW counts + exit condition check |
| `adaptive_loop_log.md` | Orchestrator (after loop exits) | Iteration count, spawns used, exit condition triggered, per-iteration summary |
| `verification_error_traces.md` | Orchestrator (after Phase 5) | Error traces from failed PoCs, formatted as investigation questions for post-verification depth |
| `rag_validation.md` | RAG Validation Sweep Agent (Phase 4b.5) | Per-finding RAG scores from validate_hypothesis + search_solodit_live |
| `design_stress_findings.md` | Design Stress Testing Agent | Design limit, adequacy, and constraint coherence findings |
| `composition_coverage.md` | Chain Analysis Agent | Finding-pair composition coverage map (explored/unexplored) |
| `violations.md` | Orchestrator (on skip) | Thorough mode workflow violations - skipped mandatory steps (Rule 12) |
| `checkpoint_postdepth.md` | Orchestrator (after depth) | Post-depth assertion results for Thorough mode completeness |
