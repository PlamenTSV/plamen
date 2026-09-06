# Phase 2: Orchestrator Instantiation

> **Loaded by**: The V2 driver's Phase 2 subprocess (instantiation).
> **Purpose**: Determine agent count, apply merge hierarchy, instantiate templates,
> load injectable skills, enforce merge cap, append MCP timeout directive, and
> verify spawn readiness. Self-contained methodology for the instantiation phase.

---

## Step 2a: Determine Agent Count

**Mode policy is authoritative and evaluated first**:

| Mode | Breadth worker contract | Size-tier rule |
|------|-------------------------|----------------|
| Light | **3-4 Sonnet breadth AGENT rows** | Simple/Medium/Complex tiers do not raise this cap |
| Core / Thorough | 5-9 breadth AGENT rows | Apply the size tiers below, including their floors |

For Light mode, preserve every `Required=YES` methodology even when more than
four skills are triggered: bind the highest-value compatible skills to the 3-4
breadth workers under the normal merge/cap rules, then record every overflow
skill in `## Skill Bindings` with an explicit compatible `depth-*` role. The
driver injects those bindings into the depth worker. A skill absent from both a
breadth `Template` cell and an explicit depth binding is a hard schema error.
This is a delivery deferral, not permission to mark a triggered skill optional.

| Condition | Agent Count |
|-----------|-------------|
| Simple (<5 deps, <2000 lines) | 3 agents |
| Medium (5-10 deps, 2000-5000 lines) | 5-7 agents |
| Complex (>10 deps or >5000 lines) | 7-9 agents |

**Minimum always**: 1 core state, 1 access control, 1 per major external dep (overrides Simple tier if needed)

**Core/Thorough tier floor (HARD)**: the Merge Hierarchy (Step 2a.1) reduces toward the tier's agent count but **NEVER below its lower bound** — **Complex never below 7**, Medium never below 5. If merges would drop the AGENT-row count below the floor, keep skills in **separate** AGENT rows instead (the 300-line cap is an upper bound on per-agent payload, NOT a license to collapse below the tier floor). Merging away whole lenses on a large codebase is a recall loss. The driver mechanically enforces the Complex floor (>=7) for Core/Thorough. **It does not apply that floor in Light mode; Light remains 3-4 and uses explicit depth-role carryover for overflow skills.**

**Breadth-to-depth redirect**: When actual breadth agent count is below the Medium baseline (5), the saved slots increase the depth budget floor: `depth_floor = 12 + (5 - actual_breadth_count)`.

---

## Step 2a.1: Merge Hierarchy (when required templates exceed target count)

| Priority | Merge | Rationale |
|----------|-------|-----------|
| M1 | TEMPORAL_PARAMETER_STALENESS + core state agent | Cached params are state mutations |
| M2 | SEMI_TRUSTED_ROLES + access control agent | Roles are access control |
| M3 | SHARE_ALLOCATION_FAIRNESS + core state agent | Allocation fairness is state correctness |
| M4 | ECONOMIC_DESIGN_AUDIT + core state agent | Monetary params are state correctness |
| M5 | EXTERNAL_PRECONDITION_AUDIT + external dependency agent | External preconditions are external dep analysis |

**Rules**: Never merge two skills both requiring >5 analysis steps. Never merge across incompatible domains. **Never merge FLASH_LOAN_INTERACTION or ORACLE_ANALYSIS with any other skill.** **Max 2 templates per agent (including injectables) AND max 300 combined SKILL.md lines.** If a 2-template merge would exceed 300 lines, split into an additional breadth agent instead. Narrower scope per agent improves depth — agents reliably execute ~300 lines of skill payload but degrade on larger prompts (validated by multi-agent audit research: LLMBugScanner, iAudit).

---

## Step 2a.2: Move-Safety Agent (Aptos/Sui only)

For Aptos and Sui audits, the 4 always-required skills (ABILITY_ANALYSIS, BIT_SHIFT_SAFETY, TYPE_SAFETY, REF_LIFECYCLE/OBJECT_OWNERSHIP) total ~900-950 lines — far exceeding the 300-line breadth agent cap. These are split into two delivery layers:

1. **Core directives** (~130 lines): Loaded into EVERY breadth agent via `~/.claude/agents/skills/{LANGUAGE}/move-safety-core-directives/SKILL.md`. Contains inventory greps + flag tables. Counts toward the 300-line cap but leaves ~170 lines for conditional skills.
2. **Move-Safety Agent** (1 dedicated agent): Spawned in Phase 3 alongside breadth agents. Loads ALL 4 full skill files (~950 lines). Runs the complete trace methodology that breadth agents cannot fit. Costs 1 breadth agent slot.

The Move-Safety Agent prompt: load all 4 always-required SKILLs into a single agent with scope = "full Move-specific safety analysis." It is a breadth producer and MUST write exactly one first-pass analysis file, `analysis_move_safety.md`. Its findings feed into `findings_inventory.md` because inventory reads `analysis_*.md`; it must not write `findings_inventory.md` directly. Depth agents still receive full skills per their injection rules (depth agents have separate context windows, not subject to the breadth merge cap).

**EVM/Solana**: No Move-Safety Agent needed. EVM has no always-required skills. Solana has ACCOUNT_VALIDATION (130 lines) which fits within the 300-line cap.

---

## Step 2a.3: Breadth Floor-Fill — NEVER invent skill templates

In Core/Thorough, the Complex tier requires >=7 breadth agents (Step 2a). When the recon-recommended REAL skills yield FEWER agents than the floor, you MUST reach the floor **without inventing skill names**. This floor-fill section does not apply to Light mode. The `Template` column of every AGENT row must contain ONLY:
- a **real breadth-eligible** skill/template name that exists at `~/.claude/agents/skills/{LANGUAGE|injectable|niche}/<lowercase-hyphenated-name>/SKILL.md` (the names in `skill-index.md` and your `template_recommendations.md`) and declares a compatible breadth consumer in `skill_selection_catalog.json`, a baseline focus (`CORE_STATE`, `ACCESS_CONTROL`), **or**
- the literal sentinel `GENERAL` — a focus-only breadth pass with no skill methodology (the driver runs it as a general agent over that focus area; this is expected, not an error).

To fill extra agents up to the floor, **in this order**:
1. **Split a broad real breadth-eligible skill's scope** across multiple agents by file/subsystem (e.g. `ORACLE_ANALYSIS` on RNG contracts as one agent, on price contracts as another) — same real `Template`, different `Focus Area` + file scope.
2. **Bind the closest applicable real breadth-eligible skill** to an under-covered domain. Examples: reward/payout accounting -> `ECONOMIC_DESIGN_AUDIT` or `SHARE_ALLOCATION_FAIRNESS`; game/round/RNG outcome logic -> `OUTCOME_DETERMINISM`; auxiliary swap/pricing -> the relevant real skill (`ORACLE_ANALYSIS`, `TOKEN_FLOW_TRACING`, ...). Never use a depth-only skill for breadth floor-fill.
3. **Only if no real skill applies**, create a focus-only agent with `Template = GENERAL`.

**Retry floor repair is narrower:** when the driver reports that an otherwise
typed proposal missed only the breadth-row floor, add `GENERAL` rows for the
deficit. The retry predicate is conjunctive with consumer compatibility:
depth-only skills are forbidden in breadth `Template` cells and `B#` bindings.

**PROHIBITED**: inventing a skill-like `Template` name that has no `SKILL.md` (e.g. `REWARD_ACCOUNTING`, `GAME_LOGIC_CORRECTNESS`, `MINIGAME_AUXILIARY`). A fabricated `Template` silently drops methodology and emits a binding-loss warning. The manifest schema gate rejects fabricated templates and you will be asked to retry — bind a real skill (split scope or closest-fit) or use `GENERAL`.

---

## Step 2b: Instantiate Templates

The driver reconciles positive recon recommendation prose/signals into the
`BINDING MANIFEST` table before this phase. Treat the resulting Required column
as canonical; do not override it from a second prose interpretation.

For each template marked `Required? = YES` in `template_recommendations.md`:
1. Read that skill's `index_consumers` from `skill_selection_catalog.json` and
   assign the canonical template identifier only to a compatible declared
   consumer. A breadth `Template` cell or `B#` binding is permitted only when
   the skill declares a `breadth:*` consumer (including the specific
   cross-chain/encoding breadth declaration). A depth-only skill MUST appear
   only in `## Skill Bindings`, bound to every scheduled declared `depth-*`
   role, and MUST NOT appear in a breadth `Template` cell or `B#` binding.
   Methodology loading and path resolution are driver-owned at worker launch.

   Convert catalog consumer roles to manifest destinations exactly as follows;
   the catalog spelling itself is not a valid `Inject Into` destination:

   | Catalog `index_consumers` role | Manifest `Inject Into` destination |
   |---|---|
   | `depth:token_flow` | `depth-token-flow` |
   | `depth:state_trace` | `depth-state-trace` |
   | `depth:edge_case` | `depth-edge-case` |
   | `depth:external` | `depth-external` |

   Never write `depth_state_trace`, `depth_edge_case`, or another `depth_*`
   token. The manifest destination denominator is exactly the four hyphenated
   values above.
2. For Aptos/Sui breadth agents: load `move-safety-core-directives/SKILL.md` instead of the 4 individual always-required skills. The full skills go to the Move-Safety Agent only.
3. Replace `{PLACEHOLDERS}` with instantiation parameters
4. **Conditional loading**: Strip sections wrapped in `<!-- LOAD_IF: FLAG -->...<!-- END_LOAD_IF: FLAG -->` when the flag was NOT detected
5. Compose agent prompt with instantiated template

---

## Step 2b.1: Load Injectable Skills (Append-Only Delivery)

1. Read protocol type from `{scratchpad}/template_recommendations.md` -> `## Injectable Skills`
2. For each recommended injectable: Read from `~/.claude/agents/skills/injectable/{skill-name}/SKILL.md`
3. **Breadth agents**: Only when the injectable declares a compatible breadth
   consumer, extract section headers + key questions (1-line per section,
   ~200 tokens max). Never route a depth-only injectable to breadth.
4. **Depth agents (Phase 4b)**: Append the relevant skill methodology to every
   scheduled compatible declared depth-agent prompt.
5. Injectable skills do NOT spawn dedicated agents. The spawn manifest must record which existing agent received each injectable skill.

---

## Step 2b.2: Merge Cap Enforcement Gate (MANDATORY)

**BEFORE composing any agent prompt**, the orchestrator MUST verify the 300-line cap mechanically:

```
For each planned breadth agent:
  combined_lines = 0
  For each SKILL.md assigned to this agent:
    line_count = wc -l ~/.claude/agents/skills/{LANGUAGE}/{skill-name}/SKILL.md
    combined_lines += line_count
  ASSERT: combined_lines <= 300
  If FAIL:
    Log: "MERGE CAP VIOLATED: Agent {N} has {combined_lines} lines ({skill_list}). Splitting."
    Split the largest skill into its own dedicated agent.
    Re-run this gate.
```

**This is a mechanical check — run `wc -l` on actual files, do not estimate.** The 300-line cap was validated by multi-agent audit research (LLMBugScanner, iAudit): agents reliably execute ~300 lines of skill payload but degrade on larger prompts. Violations of this cap directly cause RC-AGENT misses where methodology exists but agents don't execute it.

**Soroban note**: Soroban skills average 30% larger than Solana equivalents. Merges that fit at Solana sizes often exceed 300 lines at Soroban sizes. Always check — never assume a merge that works for one language works for another.

---

## Step 2c: Agent Prompt Structure

```
You are Analysis Agent #{N}: {FOCUS_AREA}

## Protocol Context
{Brief from design_context.md}

## Your Analysis Task
{INSTANTIATED_TEMPLATE}

## Analysis Strategy — Targeted Sweeps
Do NOT attempt to find all vulnerability types in a single pass.
Instead, for each vulnerability class in your methodology:
1. Sweep the ENTIRE scope for THIS class specifically
2. Write findings for this class before moving on
3. Proceed to the next vulnerability class

## Artifacts Available
{list scratchpad files}

## Output Requirements
Expected output: {SCRATCHPAD}/analysis_{focus_area}.md
Use finding IDs: [{PREFIX}-1], [{PREFIX}-2]...

SCOPE: Write ONLY to your assigned output file. Do NOT read or write other agents' output files. Do NOT spawn additional Task subagents. Return your findings and stop.
```

---

## Step 2c.1: MCP Timeout Directive (MANDATORY — Rule 11)

Every breadth-agent prompt you generate that makes MCP tool calls MUST include this directive at the end of its prompt:

*"When an MCP tool call returns a timeout error or fails, do NOT retry the same call. Record [MCP: TIMEOUT] and skip ALL remaining calls to that provider — switch immediately to fallback (code analysis, grep, WebSearch). Claude Code's tool timeout is set to 300s (5 min) via MCP_TOOL_TIMEOUT in settings.json to accommodate ChromaDB cold start. You cannot cancel a pending call — but you control what happens after the error returns."*

Append this text when composing prompts for MCP-calling breadth agents. Pure code-analysis breadth agents (no MCP) do not need it.

---

## Step 2d: Spawn Verification Gate (MANDATORY)

**BEFORE spawning agents**:
1. Read BINDING MANIFEST from `{scratchpad}/template_recommendations.md`
2. Verify agent queued for EACH template marked `Required? = YES` or `Required = YES` (plain or Markdown-decorated YES is accepted on input)
3. If ANY required template missing -> **HALT and add**

**Write spawn manifest** to `{scratchpad}/spawn_manifest.md`:
```markdown
# Spawn Manifest
## Breadth Agents
| Row Type | Template | Required? | Agent ID | Focus Area | Expected Output | Status |
|----------|----------|-----------|----------|------------|-----------------|--------|
| AGENT | CORE_STATE | YES | B1 | core_state | analysis_core_state.md | QUEUED |
**Gate Check**: All REQUIRED templates have agents? [YES/NO]
```

`spawn_manifest.md` is a machine-read contract, not narrative notes.
Rules:
- The first markdown table in the file with both `Template` and `Required?`
  columns MUST be the spawned breadth-agent AGENT table shown above.
- Put spawned breadth agents only in rows with `Row Type = AGENT`.
- Every `AGENT` row MUST have `Required? = YES`, a unique `Agent ID`, a
  non-empty `Focus Area`, and an `Expected Output` filename matching
  `analysis_<focus>.md`.
- Optional templates marked `NO` are not spawned and must not appear as AGENT
  rows. If an optional template is intentionally folded into a spawned agent,
  record it under `## Skill Bindings`, not the AGENT table.
- Do NOT put `verify_*.md`, `analysis_rescan_*.md`,
  `analysis_percontract_*.md`, `analysis_merged_into_*.md`, inventory,
  depth, chain, verification, or report artifacts in the AGENT table.
- Record skill/injectable bindings in a separate section titled
  `## Skill Bindings`; those rows are not spawned agents and must not be
  mixed into the machine-read AGENT table.
- The `## Skill Bindings` table MUST use these exact columns:
  `Skill | Type | Inject Into | Delivery Mode`.
  `Inject Into` MUST be a parseable breadth agent id such as `B2` or a depth
  role such as `depth-external`; do not use prose-only targets.
- If recon evidence includes `NON_EVM_TARGET`, Solana, Bitcoin,
  pubkey/base58/bech32/Borsh, or any EVM-to-foreign-VM outbound encoding,
  `CROSS_VM_SERIALIZATION_CONFORMANCE` is REQUIRED and MUST appear in
  `## Skill Bindings` twice: once injected into the cross-chain/encoding
  breadth agent by `B#`, and once injected into `depth-external`.
- Before the final Write, confirm in memory that the number of AGENT rows
  equals the number of first-pass breadth output files the breadth phase must
  produce. Write the complete proposal once; the supervisor validates the
  exact staged bytes, so no output re-read is required.

If the gate check is NO, do NOT proceed to Phase 3. Add the missing agent and re-verify.
