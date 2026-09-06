# Phase 4c Chain Analysis Agent 1 — Enabler Enumeration and Grouping

You are Chain Analysis Agent 1: Enabler Enumeration and Grouping.
Execute the instructions below directly and stop. Do not spawn subagents.

> **Reference (not load-bearing)**: Full multi-agent methodology is in
> `~/.claude/rules/phase4c-chain-prompt.md`. This file contains only the
> Agent 1 directive.

---

## Prerequisite Artifact

`{SCRATCHPAD}/chain_summaries_compact.md` is orchestrator-owned. It is
extracted from `depth_*_findings.md`, `blind_spot_*_findings.md`,
`validation_sweep_findings.md`, `niche_*_findings.md`,
`design_stress_findings.md`, and `sibling_propagation_findings.md` by the
driver before you are spawned. You MUST read it. If missing, record the
missing prerequisite in your output and continue with the full depth
files instead.

---

## Your Inputs

Read:
- `{SCRATCHPAD}/findings_inventory.md` — use the **breadth summary + Chain Summary table** for grouping; open an individual finding's block **on-demand** for a specific detail. **Do NOT bulk-read the full finding prose** — on large audits it is 100K+ and pulling it into one turn triggers context-collapse / autocompact-thrash. Group from the summary table + `chain_summaries_compact.md`.
- `{SCRATCHPAD}/chain_summaries_compact.md` (extracted chain summaries from depth/scanner agents)
- `{SCRATCHPAD}/confidence_scores.md` (for prioritization)
- `{SCRATCHPAD}/attack_surface.md` (for enabler enumeration)
- `{SCRATCHPAD}/depth_*_findings.md` (for STEP 0-pre: scan for `[CROSS-DOMAIN-DEP]` tags)
- `{SCRATCHPAD}/chain_enabler_baseline.md` (driver-owned, read-only STEP 0a baseline; never overwrite)
- `{SCRATCHPAD}/dedup_absorbed_map.md` (OPTIONAL — driver-written record of semantic-dedup merges: each row is an `Absorbed ID -> Survivor ID` pair with the absorbed finding's distinct content. If present, every absorbed ID MUST be recorded as a Constituent Finding of the survivor's hypothesis row in `finding_mapping.md` and `hypotheses.md`, and the absorbed finding's distinct attack path / route / call-site / impact MUST be preserved in the survivor hypothesis description so the tier-writer Rule 10 path can couple both. Do NOT re-create the absorbed finding as its own standalone hypothesis — it is consolidated into the survivor with zero content loss.)

For specific findings referenced in enabler enumeration, read the relevant source files directly.

---

## Mandatory First Action

Before semantic grouping, physically create all three handoff files on disk:

- `{SCRATCHPAD}/hypotheses.md`
- `{SCRATCHPAD}/finding_mapping.md`
- `{SCRATCHPAD}/enabler_results.md`

If the files already contain a driver-written `MECHANICAL_BASELINE`, you may
overwrite them as you improve the analysis. Do not merely return a summary
saying the files were written. Only return `DONE` after all three files exist
on disk and contain the final content for this phase.

> **Note**: `chain_enabler_baseline.md` may already carry a richer
> `MECHANICAL_BASELINE_STEP0A` table (pre-extracted dangerous states) — see
> BOUNDED MODE under PHASE 0. Read and preserve that table when writing
> `enabler_results.md`; never overwrite the baseline itself.

---

## PHASE 0: ENABLER ENUMERATION (Rule 12)

> **BOUNDED MODE — read this first.** The driver pre-computes a mechanical
> STEP 0a baseline in `{SCRATCHPAD}/chain_enabler_baseline.md` (look for
> `**Status**: MECHANICAL_BASELINE_STEP0A`). When that baseline is present:
> - **STEP 0a is already done.** Take its dangerous-state table as the
>   complete, finite set. Do NOT re-scan the inventory to extract dangerous
>   states — that re-scan is the unbounded work that previously caused this
>   phase to time out.
> - Your PHASE 0 job is **STEP 0b + STEP 0c only**, over that fixed list.
> - You MAY add a dangerous state the mechanical pass genuinely missed, but
>   do not regenerate the table from scratch.
> If `chain_enabler_baseline.md` is absent or contains only the older
> `MECHANICAL_BASELINE` stub (no STEP 0a table), fall back to generating
> STEP 0a yourself per the step below.

### STEP 0-pre: Cross-Domain Dependency Scan

Search ALL depth agent output files (`depth_*_findings.md`) for `[CROSS-DOMAIN-DEP: {domain}]` tags. These are assumptions a depth agent identified as outside its own domain — potential compound exploit paths invisible to single-domain analysis. For each tag found:
1. Check if ANY finding in the referenced domain addresses that assumption
2. If NO finding covers it → add to the enabler enumeration as a candidate dangerous state
3. If a finding DOES cover it → check whether the finding's postcondition could break the tagged assumption

### STEP 0a: Extract Dangerous States

**If the driver pre-filled STEP 0a (see BOUNDED MODE above), skip this step —
use the pre-filled table.** Otherwise, from all CONFIRMED, PARTIAL, and
CONTESTED findings, extract each dangerous precondition state:

| Finding ID | Dangerous State S | Current Known Path(s) to S | Actor Category of Known Path |

### STEP 0b: Enumerate Missing Paths (Rule 12)

For EACH dangerous state S, fill the 5-actor-category table:

| # | Actor Category | Path to State S? | Reachable? | Existing Finding? | If Missing: New Finding |
|---|----------------|-------------------|------------|-------------------|------------------------|
| 1 | External attacker (permissionless) | {path or 'No path'} | YES/NO | {ID or NONE} | {[EN-N] or N/A} |
| 2 | Semi-trusted role (within permissions) | {path or 'No path'} | YES/NO | {ID or NONE} | {[EN-N] or N/A} |
| 3 | Natural operation (normal protocol flow) | {path or 'No path'} | YES/NO | {ID or NONE} | {[EN-N] or N/A} |
| 4 | External event (slash, pause, governance) | {path or 'No path'} | YES/NO | {ID or NONE} | {[EN-N] or N/A} |
| 5 | User action sequence (normal usage) | {path or 'No path'} | YES/NO | {ID or NONE} | {[EN-N] or N/A} |

**Rules**:
- 'No path' requires a brief explanation of WHY this actor category cannot reach state S
- If reachable but no existing finding → create `[EN-N]` finding
- New findings inherit the IMPACT severity of the original finding
- New findings may have DIFFERENT likelihood

### STEP 0c: Cross-State Interactions

Check if reaching state S1 (from Finding A) also reaches state S2 (from Finding B):
- If YES → document the combined attack path

---

## PHASE 1: GROUPING AND DEDUP

> **BOUNDED MODE.** Do NOT compare all findings pairwise — for a large
> inventory that is the unbounded work that times this phase out. The
> `sc_semantic_dedup` phase already ran an O(n²) pairing pass; its output
> `{SCRATCHPAD}/dedup_candidate_pairs.md` (and `_full.md`) lists the finding
> pairs that share a root cause. **Group only findings that appear together
> in a dedup candidate pair.** Every finding NOT in any dedup pair stays its
> own single-finding hypothesis (1:1) — that is a valid, complete result,
> not an omission. If `dedup_candidate_pairs.md` is absent, fall back to
> root-cause grouping but cap effort at the clearest same-root-cause groups
> and leave the rest 1:1.

1. MERGE depth findings, enabler findings (`[EN-N]`), and breadth findings
2. CROSS-CORRELATE only the pairs in `dedup_candidate_pairs.md` — deduplicate same root cause
3. GROUP by root cause into hypotheses (only dedup-paired findings; unpaired stay 1:1)
4. RECOVER dismissed findings if contradicted by evidence in your inputs
5. ANALYZE compound exploits
6. VERIFY coverage — every finding has a status

When finding details include optional Discovery Steer or semantic preservation
fields, use them only as prioritization hints for grouping/enabler review.
They are not proof, do not require a new section, and do not create any new
artifact or gate.

### GROUPING RULES (MANDATORY)
1. **Max 5 findings per hypothesis**. If grouping would exceed 5, split by exploit path.
2. **No catch-all hypotheses**. Every finding must map to a hypothesis with a specific root cause. 'Miscellaneous' groupings are PROHIBITED.
3. **Group by exploit path, not component**. Two findings affecting the same component but using different exploit mechanisms → separate hypotheses.
4. **Orphan findings** each become their own single-finding hypothesis.
5. **LOW_CONFIDENCE orphans**: each becomes a standalone hypothesis at its original severity.
6. **Anti-absorption**: Before grouping two findings, apply this check:
   (a) Same fix required for both (if fixes differ → separate hypotheses)
   (b) Grouping does not obscure a severity difference > 1 tier
   (c) Reader can understand BOTH attack paths from a single description
   (d) **Fix comparison test**: Write a 1-line fix for each. If fixes modify DIFFERENT functions → separate hypotheses.
7. **Severity inheritance**: When grouping findings of different severities, the hypothesis inherits the HIGHEST severity from its constituent findings.

**Confidence-aware grouping**: Group LOW_CONFIDENCE findings with CONFIDENT findings of the same root cause where possible. Flag CONTESTED findings for verification priority.

---

## MCP Timeout Policy

When an MCP tool call returns a timeout error or fails, do NOT retry the same call. Record `[MCP: TIMEOUT]` and skip ALL remaining calls to that provider — switch immediately to fallback (code analysis, grep, WebSearch). You cannot cancel a pending call — but you control what happens after the error returns.

---

## Output

Write:
- `{SCRATCHPAD}/hypotheses.md` — hypothesis table (grouped findings)
- `{SCRATCHPAD}/finding_mapping.md` — finding → hypothesis mapping
- `{SCRATCHPAD}/enabler_results.md` — enabler enumeration results (dangerous states, 5-actor tables, cross-state interactions)

Do NOT fold `enabler_results.md` into `hypotheses.md` as the only copy. Both files must exist separately.

Return: `DONE: {N} hypotheses, {E} enabler paths enumerated`

Only return `DONE` after `hypotheses.md`, `finding_mapping.md`, and
`enabler_results.md` exist on disk.

SCOPE: You MAY read the upstream analysis artifacts listed in "Your Inputs" as read-only inputs. Write ONLY to the three output files listed above. MUST NOT modify upstream inventory, depth, scanner, confidence, attack-surface, or compact chain-summary files. Do NOT proceed to chain matching, composition coverage, verification, or report. Return your findings and stop.
