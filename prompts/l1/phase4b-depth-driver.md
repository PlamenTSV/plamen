---
description: "Phase 4b: L1 Depth Loop — 5-Agent Architecture with SCIP Pre-Bake"
---

# Phase 4b: L1 Depth Loop

> **Purpose**: Spawn 5 depth agents in parallel for deep analysis of L1 codebase.
> L1 mode uses 5 depth agents (not 4 like smart-contract mode), adding
> `depth-consensus-invariant` and `depth-network-surface` while retaining
> `depth-state-trace`, `depth-external`, and `depth-edge-case`.
>
> **Invoked by**: `claude -p` with this file as the prompt. The driver resolves placeholders
> and appends skill files via `--append-system-prompt-file`.
> **Outputs**: `{SCRATCHPAD}/depth_{role}_findings.md` per agent, plus scanner and niche outputs.

---

## Placeholders

| Placeholder | Source |
|-------------|--------|
| `{SCRATCHPAD}` | Driver: `--scratchpad` arg |
| `{PROJECT_ROOT}` | Driver: `--project-root` arg |
| `{MODE}` | Driver: `core` or `thorough` |
| `{LANGUAGE}` | From `{SCRATCHPAD}/recon_summary.md` |
| `{SCIP_INDEX_PATH}` | `{SCRATCHPAD}/scip_go.index` or `{SCRATCHPAD}/scip_rust.index` |

---

## Depth Agent Roster (5 agents, all parallel)

| Agent Role | Model | SCIP Flat Files to Read | Skills (injected by driver via --append-system-prompt-file) |
|------------|-------|------------------------|-----------------------------------------------------------|
| `depth-consensus-invariant` | opus | `call_graph_consensus.md`, `repo_map.md`, `xref_map.md` | consensus-safety, fork-choice, light-client, BLS, validator-lifecycle, hardfork, data-availability-enforcement (if `DATA_AVAILABILITY=true`) |
| `depth-network-surface` | opus | `call_graph_p2p.md`, `concurrency_inventory.md`, `panic_sites.md` | p2p-dos, mempool, RPC |
| `depth-state-trace` | opus | `call_graph_execution.md`, `type_hierarchy.md` | state-sync-pruning, execution-client-hardening |
| `depth-external` | sonnet | `xref_map.md`, `type_hierarchy.md` | dependency-audit-nodeclient, cross-environment-semantic-drift |
| `depth-edge-case` | sonnet | `repo_map.md`, `xref_map.md` | zero-state, boundary checks |

### Skill Load Warning (1060-line threshold)

The `depth-consensus-invariant` agent currently loads ~1060 lines across 6 skills
(consensus-safety-invariants, fork-choice-audit, light-client-proof-verification,
bls-aggregation-audit, validator-lifecycle-and-slashing, hardfork-activation-and-protocol-upgrade).
This is at the attention saturation limit for a single agent context.

**If a depth agent's total skill load exceeds 800 lines** (sum of all assigned SKILL.md files):
- Consider splitting the agent's scope or dropping the lowest-priority skill
- In Thorough mode, accept the load but expect some attention degradation
- In Core mode, prefer splitting over overloading
- The driver computes total skill lines and logs a warning if >800

---

## SCIP Pre-Bake Directive (included verbatim in every depth agent prompt)

Every depth agent receives this block in its prompt:

```
Read {SCRATCHPAD}/scip/repo_map.md + your domain-specific call_graph_*.md + xref_map.md
+ type_hierarchy.md + concurrency_inventory.md + panic_sites.md.
DO NOT call mcp__scip-reader__*, mcp__ast-grep__*, or mcp__opengrep__* tools.
They are unavailable in subagent contexts.
Cite scip/*.md files for [LSP-TRACE] evidence. Findings without SCIP file citations
use [CODE-TRACE].
For targeted queries not in pre-baked files, use Bash:
  python -m plamen_l1.scip_reader {SCIP_INDEX_PATH} find_references "SymbolName"
```

### Expected SCIP Flat Files

| File | Contents | Typical Size |
|------|----------|-------------|
| `{SCRATCHPAD}/scip/repo_map.md` | Per-file symbol listing (capped at 2000 lines) | ~50 KB |
| `{SCRATCHPAD}/scip/repo_map_full.md` | Uncapped version for targeted reads | 50 KB - 17 MB |
| `{SCRATCHPAD}/scip/xref_map.md` | Cross-file reference map (top 50 exported symbols) | ~20 KB |
| `{SCRATCHPAD}/scip/call_graph_consensus.md` | 2-hop call graph from consensus entry points | ~10 KB |
| `{SCRATCHPAD}/scip/call_graph_p2p.md` | 2-hop call graph from network entry points | ~10 KB |
| `{SCRATCHPAD}/scip/call_graph_execution.md` | 2-hop call graph from execution entry points | ~10 KB |
| `{SCRATCHPAD}/scip/concurrency_inventory.md` | Go goroutine spawns + mutex usage | ~5 KB |
| `{SCRATCHPAD}/scip/panic_sites.md` | All `panic()` call sites | ~5 KB |
| `{SCRATCHPAD}/scip/type_hierarchy.md` | Interface implementations | ~10 KB |
| `{SCRATCHPAD}/scip/all_symbols.txt` | Full symbol list (for targeted reads) | ~20 KB |

If any file is missing or empty, the agent falls back to Grep-based analysis.
This is expected and acceptable — log `fallback_to_grep: true` in the YAML header.

---

## Depth Agent Spawn Template

For each agent, the driver spawns a `general-purpose` agent:

```
You are the L1 {ROLE} Depth Agent.

PROJECT_ROOT: {PROJECT_ROOT}
SCRATCHPAD: {SCRATCHPAD}
LANGUAGE: {LANGUAGE}
ITERATION: 1

## Methodology

Read ~/.claude/agents/depth-{ROLE}.md for your full analysis methodology.
Follow every section and step — do not summarize or skip.

## SCIP Pre-Bake Directive

Read {SCRATCHPAD}/scip/repo_map.md + your domain-specific call_graph_*.md + xref_map.md
+ type_hierarchy.md + concurrency_inventory.md + panic_sites.md.
DO NOT call mcp__scip-reader__*, mcp__ast-grep__*, or mcp__opengrep__* tools.
They are unavailable in subagent contexts.
Cite scip/*.md files for [LSP-TRACE] evidence. Findings without SCIP file citations
use [CODE-TRACE].
For targeted queries not in pre-baked files, use Bash:
  python -m plamen_l1.scip_reader {SCIP_INDEX_PATH} find_references "SymbolName"

## Artifacts Available

- {SCRATCHPAD}/threat_model.md (threat model with actor enumeration)
- {SCRATCHPAD}/subsystem_map.md (SCIP-backed symbol map)
- {SCRATCHPAD}/attack_surface.md (per-layer attack surface)
- {SCRATCHPAD}/trust_boundaries.md (actor trust boundaries)
- {SCRATCHPAD}/findings_inventory.md (breadth findings for cross-reference)
- {SCRATCHPAD}/semantic_invariants.md (L1 invariants)
- {SCRATCHPAD}/opengrep_hits_ranked.md (static analysis baseline)
- Your domain-specific SCIP flat files (see table above)
- Source files in your assigned scope

## YAML Header (MANDATORY — first content in output file)

Your output file MUST begin with:

---
agent: {ROLE}
model: {MODEL}
iteration: 1
prebaked_files_read:
  - file: scip/{FILE1}
    size_kb: {SIZE}
    symbols_cited: ["{SYM1}", "{SYM2}"]
  - file: scip/{FILE2}
    size_kb: {SIZE}
primitive_calls_bash: []
fallback_to_grep: false
---

## Output Requirements

**FIRST ACTION**: Write a one-line header to {SCRATCHPAD}/depth_{ROLE}_findings.md
to reserve the file.

Write all findings to {SCRATCHPAD}/depth_{ROLE}_findings.md.
Use finding IDs: [D{ROLE_ABBREV}-1], [D{ROLE_ABBREV}-2], ...
Use standard finding format from ~/.claude/rules/finding-output-format.md.

Include Depth Evidence tags on every finding:
  [BOUNDARY:X=val], [VARIATION:param A->B], [TRACE:path->outcome], [LSP-TRACE]

If `{SCRATCHPAD}/security_obligations.md` exists, emit the listed exact-alias
receipt for every obligation you evaluate. For each `STATUS:R`, copy the
complete generated `PLAMEN_SECURITY_OBLIGATION_EVIDENCE` marker into the
referenced finding section, preserving the alias/relation/subject/object/symbol
tuple in its original case. Normalized prose cannot bind an alias; an absent or
changed marker leaves that exact row queueable.

## Chain Summary (MANDATORY at end of file)

After all findings, write a Chain Summary table:

| Finding ID | Postconditions Created | Preconditions Required | Cross-Domain Dependencies |

Tag any cross-domain assumptions with [CROSS-DOMAIN-DEP: {domain}].

SCOPE: Write ONLY to your assigned output file. Do NOT read or write other agents'
output files. Do NOT proceed to subsequent pipeline phases (chain analysis, verification,
report). Return your findings and stop.

Write your output directly to {SCRATCHPAD}/depth_{ROLE}_findings.md using the Write tool.
Return ONLY a one-line summary: "DONE: {N} findings written to depth_{ROLE}_findings.md"
Do NOT return your full output as text — the orchestrator's context budget is limited.
```

---

## Scanners and Niche Agents

In addition to the 5 depth agents, the driver spawns scanners and niche agents from
`{SCRATCHPAD}/instantiation.json` (produced by Phase 2).

**Scanner agents**: Use L1 scanner templates from `~/.claude/prompts/l1/phase4b-scanner-templates.md`.
Use `{LANGUAGE}` only as the implementation language for toolchain/build commands.
(L1 mode uses the same scanner infrastructure as smart-contract mode, adapted for Go/Rust).

**Niche agents**: Spawned based on flags in `{SCRATCHPAD}/template_recommendations.md`.
Each niche agent reads its SKILL.md from `~/.claude/agents/skills/niche/{NAME}/SKILL.md`.
Each costs 1 depth budget slot.

All scanners and niche agents use the same SCIP Pre-Bake Directive and
SCOPE CONTAINMENT as depth agents.

---

## Telemetry Gate (after all depth agents return)

The driver runs this check after all depth agents complete:

```bash
for f in "{SCRATCHPAD}"/depth_*_findings.md; do
  AGENT=$(basename "$f" _findings.md | sed 's/depth_//')
  HEADER=$(awk '/^---$/{c++; if(c==2) exit; next} c==1' "$f")
  [ -z "$HEADER" ] && echo "[GATE FAIL] $AGENT: no YAML header" | tee -a "{SCRATCHPAD}/violations.md" && continue
  PREBAKED=$(echo "$HEADER" | grep -c '^\s*- file:.*scip/')
  [ "$PREBAKED" -lt 2 ] && echo "[GATE FAIL] $AGENT: $PREBAKED pre-baked reads (need >=2)" | tee -a "{SCRATCHPAD}/violations.md"
done
```

If a depth agent's YAML header shows `fallback_to_grep: true` or `prebaked_files_read`
has fewer than 2 entries, the agent degraded. Log but do not block.

---

## Mode-Specific Behavior

| Aspect | Core | Thorough |
|--------|------|----------|
| Depth iterations | 1 only | Up to 3 (DA role for iter 2-3) |
| Confidence scoring | Required 4-axis after iter 1 | 4-axis after iter 1 |
| Design Stress Testing | Skip | 1 reserved slot, UNCONDITIONAL |
| Finding Perturbation | Skip | 1 sonnet (structured mutations) |
| Skill Execution Checklist | Skip | 1 haiku (gap verification) |
| Iter 2 skip policy | N/A | MANDATORY if ANY uncertain finding >= Medium |

### Thorough-Only: Iteration 2 (Devil's Advocate)

Per `~/.claude/rules/phase4-confidence-scoring.md` "Hard Devil's Advocate Role":

For each UNCERTAIN finding (composite < 0.7) in `{SCRATCHPAD}/confidence_scores.md`:
1. Extract evidence-only card (no verdicts, no reasoning contamination)
2. Spawn DA agent with contrastive prompt
3. DA agent receives analysis path summary but NOT conclusions
4. DA agent MUST explore at least one path the previous analysis did NOT
5. Max 5 findings per DA agent
6. Re-scoring uses new-evidence-only rule (AD-5)

If iter 2 produces progress on any finding, spawn iter 3. Hard cap: 3 iterations.

### Thorough-Only: Iteration 2 Gate

If ANY uncertain finding is Medium+ severity, iteration 2 is MANDATORY.
Skipping is a WORKFLOW VIOLATION. Log to `{SCRATCHPAD}/violations.md`.
