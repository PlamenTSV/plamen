# Phase 3b/3c: Breadth Re-Scan & Per-Contract Analysis

> **Purpose**: Counter LLM attention saturation by re-running breadth analysis with an exclusion list of already-found findings. Finds vulnerabilities masked by attention to prominent bugs in pass 1.
> **Model**: sonnet (discovery task - surfaces candidates for depth loop to verify; also provides implicit model diversity vs opus pass 1)
> **Trigger**: Always runs at least 1 iteration after Phase 4a inventory completes.
> **Protocol-agnostic**: No language-specific logic. Uses the same scope and artifacts as pass 1.

---

## Orchestrator Flow

```
Phase 3 (pass 1) → Phase 4a (inventory) → Phase 3b (re-scan loop) → Phase 3c (per-contract) → Phase 4a merge → Phase 4a.5 → Phase 4b
```

Phase 4a runs FIRST to produce the exclusion list (findings_inventory.md). Then Phase 3b re-scans. Then inventory is updated with new findings before proceeding to semantic invariants and depth.

---

## Convergence Criteria

| Criterion | Value |
|-----------|-------|
| **Hard cap** | 2 iterations (configurable) |
| **Exit early** | Iteration N produces 0 new findings above Info severity |
| **Hard exit** | If iteration 1 produces 0 new findings above Info severity → **skip iteration 2 unconditionally**. Do NOT spawn iteration 2 agents "just to be thorough." |
| **Quality gate** | New findings must reference specific code locations (file:line). Vague speculation without code reference is not a valid new finding. |
| **Agent count** | 2-3 agents per iteration (fewer than pass 1) |
| **Scope per agent** | Broader than pass 1 - each agent covers half the codebase, not a narrow focus area. Overlapping scope is intentional. |

---

## Iteration 1 (ALWAYS)

### Step 1: Build Exclusion List

Read `{SCRATCHPAD}/findings_inventory.md`. Extract for each finding:
- Finding ID, title, location (file:line), 1-line root cause

Format as a compact exclusion list (~1 line per finding).

### Step 2: Spawn Re-Scan Agents

Spawn 2-3 agents in parallel as `general-purpose` with `model="sonnet"`:

```
Task(subagent_type="general-purpose", model="sonnet", prompt="
You are Breadth Re-Scan Agent #{N}.

## Context
You are performing a SECOND PASS analysis of a smart contract codebase. A first pass already identified {F} findings. Your job is to find vulnerabilities that the first pass MISSED.

## CRITICAL INSTRUCTION
The following findings are ALREADY KNOWN. You MUST NOT report any of these. If you identify something that matches an existing finding's root cause or location, SKIP IT.

### Already-Known Findings (Exclusion List)
{EXCLUSION_LIST}

## Your Scope
{SCOPE_DESCRIPTION - half the codebase per agent, with overlap}

## Artifacts Available
- {SCRATCHPAD}/design_context.md (protocol design)
- {SCRATCHPAD}/attack_surface.md (attack surface from recon)
- {SCRATCHPAD}/state_variables.md (all state variables)
- {SCRATCHPAD}/function_list.md (all functions)
- Source files in scope

## What To Look For
Focus on vulnerability classes that attention saturation typically masks:
1. Cross-function state inconsistencies (function A assumes invariant that function B breaks)
2. Asymmetric operations (deposit path handles X but withdraw path doesn't)
3. Parameter encoding mismatches between paired functions (create/consume, deposit/refund, lock/unlock)
4. Economic assumptions violated under edge conditions (first user, last user, zero state, max state)
5. Time-dependent state that goes stale under specific operation sequences

Do NOT re-analyze the same patterns the first pass already covered. Look in the gaps BETWEEN what was analyzed.

## Output Requirements
Write to {SCRATCHPAD}/analysis_rescan_{N}.md
Use finding IDs: [RS{N}-1], [RS{N}-2]...
Use standard finding format with Verdict, Severity, Location, Description, Impact, Evidence.

## Quality Gate
Every finding MUST include a specific code location (file:line). Findings without code references will be discarded.

Return: 'DONE: {N} new findings identified'
")
```

### Step 3: Evaluate Results

After all re-scan agents return:
1. Read each `analysis_rescan_*.md`
2. Count new findings above Info severity
3. Verify no finding duplicates an exclusion list entry (same location + same root cause = duplicate, discard)
4. If 0 new findings above Info → **EXIT loop, proceed to inventory merge**
5. If new findings found → **proceed to iteration 2**

### MANDATORY EXIT ASSERTION (orchestrator inline)
```
new_findings_above_info = count(iteration 1 findings where severity > Info)
ASSERT: if new_findings_above_info > 0 → iteration 2 MUST be spawned
Violation is a workflow error. Log: "Rescan exit check: {N} new findings above Info → CONTINUE/EXIT"
```

---

## Iteration 2 (CONDITIONAL - only if iteration 1 found new findings)

### Step 1: Update Exclusion List

Add iteration 1's new findings to the exclusion list.

### Step 2: Spawn Re-Scan Agents

Same as iteration 1, but with:
- Updated exclusion list (pass 1 + iteration 1 findings)
- Same 2-3 agents, same scope split
- Added instruction: "Two prior passes found {F1 + F2} findings. You are the THIRD set of eyes. Focus on the LEAST obvious vulnerabilities."

### Step 3: Evaluate Results

Same as iteration 1 step 3. After iteration 2, proceed to inventory merge regardless of results (hard cap reached).

---

## Inventory Merge

After Phase 3b re-scan loop AND Phase 3c per-contract analysis both exit:

1. If re-scan or per-contract analysis produced new findings:
   - Re-run Phase 4a inventory agent with ADDITIONAL input: `{SCRATCHPAD}/analysis_rescan_*.md` and `{SCRATCHPAD}/analysis_percontract_*.md`
   - Or: spawn a lightweight merge agent (haiku) that reads findings_inventory.md + rescan files + per-contract files and appends new entries
2. If neither produced new findings: skip merge, proceed to Phase 4a.5

The merge must complete BEFORE Phase 4a.5 (semantic invariants) so that new findings are included in the invariant analysis and depth agent inputs.

---

## Budget Impact

| Component | Cost |
|-----------|------|
| Iteration 1 | 2-3 sonnet agents |
| Iteration 2 (conditional) | 2-3 sonnet agents |
| Inventory merge | 1 haiku agent (if new findings) |
| **Total max** | **7 sonnet + 1 haiku** |

Sonnet agents are ~3-5x cheaper than opus. Total re-scan cost is roughly equivalent to 1-2 opus breadth agents from pass 1.

---

## Why Sonnet (Not Opus)

1. **Discovery, not verification**: Re-scan surfaces candidates; the depth loop (iteration 1-3, potentially opus) verifies them
2. **Cost efficiency**: Allows 2 full iterations within reasonable budget
3. **Implicit model diversity**: If pass 1 used opus, sonnet has different attention patterns - provides some of the multi-model diversity benefit without requiring external APIs
4. **Quality floor is acceptable**: Sonnet can identify code-level bugs with specific locations; it doesn't need opus-level reasoning for breadth discovery

---

## Phase 3c: Per-Contract Focused Analysis

> **Purpose**: Counter attention-spread by assigning one agent per contract/inheritance cluster. Where breadth agents analyze the entire codebase (catching cross-contract bugs) and re-scan agents look for masked findings, per-contract agents analyze each file at maximum depth with zero distraction from other contracts.
> **Model**: sonnet (focused analysis within narrow scope)
> **Trigger**: Always runs after Phase 3b re-scan completes, before Phase 4a merge.
> **Prerequisite**: Recon must have produced `contract_inventory.md` with dependency data.

### Orchestrator Flow

```
Phase 3b (re-scan) → Phase 3c (per-contract) → Phase 4a merge → Phase 4a.5 → Phase 4b
```

Phase 3c runs after Phase 3b. Its findings are merged into inventory alongside re-scan findings before proceeding to semantic invariants and depth.

### Step 0: Feed Exclusion List to Per-Contract Agents

Per-contract agents MUST receive the same exclusion list as Phase 3b re-scan agents. This prevents duplicate findings between 3c and breadth pass 1. Build the exclusion list from `{SCRATCHPAD}/findings_inventory.md` (same format as Phase 3b Step 1) and include it in every per-contract agent prompt.

### Step 1: Build Contract Clusters

Read `{SCRATCHPAD}/contract_inventory.md` and group contracts by inheritance/dependency:

| Cluster | Contracts | Lines | Agent Assignment |
|---------|-----------|-------|-----------------|

**Clustering rules**:
- Contracts in the same inheritance chain → same cluster (e.g., base + derived)
- Standalone contracts with no inheritance → own cluster
- **Parent conditional override**: If `contract_inventory.md` flags any parent with `PARENT_CONDITIONAL_OVERRIDE`, include that parent in the cluster even if it is out of the primary audit scope. The per-contract agent MUST analyze the parent's conditional branches and virtual functions as part of the cluster - child contract behavior depends on parent branch paths.
- **Parent standalone analysis (v9.9.5)**: When a parent contract is independently in the audit scope AND a child contract overrides its virtual functions, the parent MUST ALSO be analyzed as a **standalone cluster** (in addition to appearing in the child's inheritance cluster). The standalone agent examines the parent's own logic as if no child exists - this catches bugs in the parent's unconditional code paths (e.g., timestamp updates, fee calculations, state transitions that execute regardless of which child override is active) that are invisible when analyzing through the child's override lens.
- Cluster size cap: max 1500 lines per cluster. If a cluster exceeds this, split by logical boundary.
- Target: 1 agent per cluster. Max 8 agents total (cap for cost control).

### Step 2: Build Cross-Contract Flag List

From `{SCRATCHPAD}/attack_surface.md` and contract_inventory.md, extract for each cluster:
- **Inbound dependencies**: which other contracts call functions in this cluster?
- **Outbound dependencies**: which external contracts does this cluster call?
- **Shared state**: which state variables are read/written by multiple clusters?

Format as a compact cross-contract flag list per cluster (~3-5 lines).

### Step 3: Spawn Per-Contract Agents

Spawn all per-contract agents in parallel as `general-purpose` with `model="sonnet"`:

```
Task(subagent_type="general-purpose", model="sonnet", prompt="
You are Per-Contract Agent #{N}: focused on {CLUSTER_NAME}.

## CRITICAL INSTRUCTION
You are analyzing ONLY the following contract(s). Do NOT analyze other contracts.
Your goal is MAXIMUM DEPTH on this narrow scope - find bugs that broad-scope agents miss.

### Your Contracts
{CONTRACT_LIST with file paths and line ranges}

### Already-Known Findings (Exclusion List)
{EXCLUSION_LIST - from findings_inventory.md + rescan, same format as Phase 3b}

### Cross-Contract Context (flags only - do NOT analyze these contracts)
{CROSS_CONTRACT_FLAGS - inbound/outbound deps, shared state}

When you find a potential issue at a cross-contract boundary, describe the issue from YOUR contract's perspective and note which external contract is involved. Do NOT attempt to trace into the external contract - that is another agent's job.

### Your Artifacts
- {SCRATCHPAD}/design_context.md (protocol design)
- {SCRATCHPAD}/state_variables.md (all state variables - focus on YOUR contracts' variables)
- Source files for YOUR cluster ONLY

## Analysis Methodology

For EACH function in your cluster:
1. **State completeness**: Does every state-modifying path update ALL related state variables? (timestamps, accumulators, snapshots, mirrors)
2. **Conditional branch audit**: For each if/else, what state is written in each branch? Is any state stale in the skip path?
3. **Boundary values**: What happens at 0, 1, MAX, and type-boundary values for each parameter?
4. **Pairing audit**: For each encode/normalize/hash operation, trace the inverse (decode/denormalize/verify) - do they use the same inputs in the same order?
5. **Fee/reward trace**: If the function involves fees or rewards, trace the full flow: accrual → accumulation → claim → transfer. At each step, verify assets and shares remain consistent.

## Output Requirements
Write to {SCRATCHPAD}/analysis_percontract_{N}.md
Use finding IDs: [PC{N}-1], [PC{N}-2]...
Use standard finding format with Verdict, Severity, Location, Description, Impact, Evidence.
Maximum 5 findings per agent - prioritize by severity.

## Quality Gate
Every finding MUST include a specific code location (file:line). Findings without code references will be discarded.
Do NOT re-report findings from the exclusion list.

Return: 'DONE: {N} new findings in {CLUSTER_NAME}'
")
```

### Step 4: Evaluate Results

After all per-contract agents return:
1. Read each `analysis_percontract_*.md`
2. Verify no finding duplicates an exclusion list entry
3. Cross-reference: if two per-contract agents flagged the same cross-contract boundary from opposite sides, merge into one finding
4. Count new findings above Info severity

### Budget Impact

| Component | Cost |
|-----------|------|
| Contract clustering | Orchestrator inline (free) |
| Per-contract agents | 3-8 sonnet agents (1 per cluster) |
| **Total** | **3-8 sonnet agents** |

### No Iteration Needed

Per-contract analysis does NOT iterate. The narrow scope (single contract/cluster) IS the mechanism that provides depth - there is no attention saturation to counter via re-scanning. One pass per contract is sufficient.
