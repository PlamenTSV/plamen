# Plamen V2 Pipeline — Phase-by-Phase Reference

> 40+ phases, executed sequentially by `plamen_driver.py`.
> Phases run in one of three execution shapes: **LLM phase session** (single `claude -p` or `codex exec` subprocess), **Python mechanical** (no LLM), or **Direct PTY worker pool** (driver supervises one Claude PTY per worker artifact). Each phase's table below shows its shape. Checkpoint after every phase enables crash-resume; the driver re-enters the worker pool to retry only missing/bad rows, not whole phases.

---

## Phase 1: Recon

### `recon` — Language Detection + Scratchpad + Reconnaissance
**Model**: opus | **Timeout**: 25min | **Critical**: yes
**Execution**: LLM phase session

Detects the smart contract language (EVM/Solana/Aptos/Sui/Soroban/DAML), initializes the scratchpad directory, then spawns 4 parallel recon agents. Agent 1A does RAG meta-buffer lookup (fire-and-forget), 1B analyzes protocol design and operational implications, Agent 2 maps the attack surface and state variables, Agent 3 scans for feature flags (oracles, flash loans, cross-chain, etc.) and recommends skills/niche agents/injectables. This is the foundation phase — every subsequent phase reads recon artifacts to understand what the protocol does, what its trust boundaries are, and what analysis lanes are relevant. Without recon, breadth agents would analyze code blind with no protocol context.

**Produces**: `recon_summary.md`, `design_context.md`, `attack_surface.md`, `state_variables.md`, `function_list.md`, `contract_inventory.md`, `template_recommendations.md`, `build_status.md`

**Why it's first**: Everything downstream depends on understanding the protocol. Breadth agents need `design_context.md` to know what the code is supposed to do. Depth agents need `attack_surface.md` to know where to focus. Skill injection needs `template_recommendations.md` to know which skills are relevant.

---

## Phase 2: Instantiation

### `instantiate` — Orchestrator Instantiation
**Model**: sonnet | **Timeout**: 10min | **Critical**: yes
**Execution**: LLM phase session

Reads recon artifacts (especially `template_recommendations.md` and `contract_inventory.md`) and the AUDIT MODES table to compute the exact agent roster for the current mode (light/core/thorough). Determines how many breadth agents to spawn, which depth agents are needed, which skills to inject into which agents, and which niche agents to activate based on detected flags. Writes a spawn manifest that downstream phases use as their marching orders — the breadth phase reads it to know its agent count and domain assignments, and the depth phase reads it for skill injection lists.

**Produces**: `spawn_manifest.md`

**Why it follows recon**: Can't compute the agent roster without knowing what flags recon detected (ORACLE, FLASH_LOAN, CROSS_CHAIN, etc.) and what the protocol type is (vault, DEX, lending). The manifest bridges recon's observations into concrete agent assignments.

---

## Phase 3: Breadth Analysis

### `breadth` — Parallel Breadth Analysis
**Model**: sonnet | **Timeout**: 60min | **Critical**: yes
**Execution**: Direct PTY worker pool

When `spawn_manifest.md` exists, the driver runs a **direct PTY worker pool** — one Claude PTY per breadth artifact (named per `Expected Output` in the manifest). No Claude breadth coordinator. The Python driver supervises spawn, completion (via `PLAMEN_STATUS` markers on disk), and retry (only missing or `IN_PROGRESS` rows). Worker prompts are shaped from `prompts/shared/v2/phase3-breadth.md`'s Subagent Prompt Template. Each worker covers a different domain of the codebase — core state, access control, token flow, external interactions, economic design, etc. — reads source files directly, applies the generic security rules and any injected skills from the spawn manifest, and writes its findings to a separate `analysis_*.md` file. The driver gate checks that at least 3 analysis files were produced with substantial content. Fallback path (worker pool gating returns False): single coordinator subprocess that spawns parallel Task subagents per the same prompt file. This is a wide-net discovery phase — it sacrifices depth for coverage, casting as many eyes on the code as the budget allows.

**Produces**: `analysis_*.md` (3-9 files, one per breadth agent)

**Why it follows instantiation**: Needs the spawn manifest to know how many agents to create and what domain each covers. Without it, the breadth subprocess would have to re-derive the roster from raw recon artifacts, duplicating work and risking inconsistency.

### `rescan` — Breadth Re-Scan + Per-Contract Analysis *(Thorough only)*
**Model**: sonnet | **Timeout**: 40min | **Critical**: no
**Execution**: Direct PTY worker pool

The driver runs a **direct PTY worker pool** — one Claude PTY per re-scan / per-contract artifact, supervised by Python via on-disk `PLAMEN_STATUS` markers. No Claude coordinator. Worker prompts are shaped from `prompts/shared/v2/phase3b-rescan.md`. The pool re-enters on retry to refill only missing or `IN_PROGRESS` rows. Counters LLM attention saturation — a phenomenon where pass-1 agents fixate on the most prominent bugs and miss subtler ones nearby. Builds an exclusion list of all findings from pass 1, then spawns 2-3 re-scan workers instructed to find what the first pass MISSED. The exclusion list forces workers to look past already-found issues. Also runs per-contract focused analysis — one worker per contract/inheritance cluster examining each file at maximum depth with zero distraction from other contracts. Up to 2 re-scan iterations; exits early if iteration 1 finds nothing new above Informational severity. Fallback path (worker pool gating returns False): single coordinator subprocess.

**Produces**: `analysis_rescan_*.md`, `analysis_percontract_*.md`

**Why it follows breadth**: Re-scan explicitly needs pass-1 findings to build the exclusion list. It's a second pass that depends on knowing what the first pass already found. Per-contract analysis also needs the breadth findings to avoid duplicating them. Running before breadth would defeat its purpose — there'd be nothing to exclude.

---

## Phase 4a: Inventory

### `inventory_prepare` — Shard Planning
**Model**: haiku | **Timeout**: 1min | **Critical**: yes
**Execution**: Python mechanical (no LLM)

A deterministic Python step (not LLM-driven). Counts finding IDs and code blocks in each `analysis_*.md` file, estimates signal density, and splits the source files into 1-3 balanced chunks targeting ~70 signals per shard. This exists because the inventory task is too large for a single LLM context window on big audits — a breadth phase producing 9 analysis files with 200+ findings would overwhelm a single inventory agent. Sharding splits the work so each chunk agent gets a manageable subset.

**Produces**: `inventory_shard_plan.md`, `inventory_chunk_{a,b,c}.manifest.md`

**Why it follows rescan**: Must wait for ALL analysis files (breadth + rescan + per-contract) to exist before it can count signals and plan shards. If it ran before rescan, it would miss the re-scan findings and under-allocate shards.

### `inventory_chunk_a` / `inventory_chunk_b` / `inventory_chunk_c` — Inventory Shards
**Model**: sonnet | **Timeout**: 40min each | **Critical**: yes
**Execution**: LLM phase session (one subprocess per shard)

Each shard receives its assigned analysis files (per the manifest) and produces a structured inventory of all findings within those files. Deduplicates within-chunk duplicates, normalizes finding IDs to a standard format, extracts locations (file:line), severities, verdicts (CONFIRMED/PARTIAL/REFUTED), precondition/postcondition analysis, and trust-assumption tags (`[ASSUMPTION-DEP: TRUSTED-ACTOR]`). This is the transformation step that converts free-form agent prose into structured data that downstream phases can parse mechanically. If a chunk has 0 assigned files (shard plan created fewer than 3 chunks), the phase is skipped automatically.

**Produces**: `findings_inventory_chunk_{a,b,c}.md`

**Why chunks run in sequence (not parallel)**: These phases are **LLM phase sessions** — one subprocess per shard. Each chunk is independent though — chunk B doesn't need chunk A's output. They're sequential only because of the driver's subprocess model. Only breadth, rescan, and depth use the **Direct PTY worker pool** shape.

### `inventory` — Inventory Merge
**Model**: opus | **Timeout**: 40min | **Critical**: yes
**Execution**: LLM phase session

Merges all chunk inventories into a single canonical `findings_inventory.md`. The critical task here is resolving cross-chunk duplicates — the same vulnerability found by breadth Agent 2 (in chunk A's manifest) and breadth Agent 5 (in chunk B's manifest) is the same root cause and must become one inventory entry, not two. Assigns final internal finding IDs and produces the master inventory that every downstream phase reads. This is the single source of truth for "what did the breadth analysis find?" — chain analysis, depth agents, verification, and the report all consume this file.

**Produces**: `findings_inventory.md`

**Why it follows all chunks**: Can't merge partial results. All chunks must complete so the merge agent sees the full picture and can correctly identify cross-chunk duplicates that individual shards couldn't detect.

---

## Phase 4a.5: Semantic Invariants

### `invariants` — Semantic Invariant Analysis *(Core/Thorough)*
**Model**: opus | **Timeout**: 20min | **Critical**: no
**Execution**: LLM phase session

Extracts protocol invariants from `design_context.md` and source code, then checks each invariant for enforcement completeness across all code paths. Identifies sync gaps (state variables that should update together but one path misses one), accumulation exposures (accumulators that grow but never shrink — potential overflow or stuck-state), conditional write gaps (state updated in one branch of an if/else but stale in the other), and cluster gaps (related variables missing co-update after changes). These aren't findings themselves — they're structural observations that guide depth agents toward the most likely vulnerability locations. Outputs flags that trigger the Semantic Gap Investigator niche agent in the depth phase.

**Produces**: `semantic_invariants.md`

**Why it follows inventory**: Needs the merged inventory to know which invariants are already covered by existing findings (don't flag what's already found). Also benefits from knowing the complete finding set to identify which state variables are involved in confirmed bugs — their invariants deserve extra scrutiny.

---

## Phase 4b: Depth Loop

### `depth` — Adaptive Depth Loop
**Model**: opus | **Timeout**: 60min | **Critical**: yes
**Execution**: Direct PTY worker pool

The heaviest and most expensive phase. Where breadth was wide and shallow, depth is narrow and deep — each worker focuses on one analytical dimension and traces execution paths to their conclusion. The driver runs a **direct PTY worker pool** — one Claude PTY per depth worker artifact, supervised by Python via on-disk `PLAMEN_STATUS` markers. No Claude coordinator. Worker prompts are shaped from `prompts/shared/v2/phase4b-depth.md` (the depth worker contract). The pool spawns 4 specialized depth roles in parallel: `depth-token-flow` (token entry/exit paths, donation attacks, type separation), `depth-state-trace` (cross-function state mutation tracing, constraint enforcement), `depth-edge-case` (zero-state, dust analysis, boundary conditions with real constants), `depth-external` (external call side effects, MEV, cross-chain timing windows). Also spawns 3 blind-spot scanners (mechanical checklist-based sweeps), a validation sweep, any triggered niche agents (event completeness, signature verification, etc.), injectable skills, and a design stress test worker — each as its own PTY worker. Each worker produces structured findings with depth evidence tags (`[BOUNDARY:X=0→overflow]`, `[TRACE:path→revert at L120]`, `[VARIATION:decimals 18→6]`). On retry, the driver re-enters the pool to refill only missing or `IN_PROGRESS` rows — completed worker output survives. In Thorough mode, runs up to 3 iterations — iterations 2-3 use Devil's Advocate roles that receive ONLY the analysis path (what was explored) but NOT the conclusions (what was decided), forcing genuinely fresh analysis. Fallback path (worker pool gating returns False): single coordinator subprocess.

**Produces**: `depth_*_findings.md` (4+ files), `blind_spot_*_findings.md`, `validation_sweep_findings.md`, `niche_*_findings.md`, `design_stress_findings.md`

**Why it follows invariants**: Depth agents receive `semantic_invariants.md` as input — the sync gaps and cluster gaps tell depth agents WHERE to focus their limited attention. Without invariant analysis first, depth agents would spread their effort evenly across the codebase instead of concentrating on structurally suspicious locations. Depth also needs the complete `findings_inventory.md` to know what breadth already found — depth agents investigate uncertain breadth findings at full depth rather than re-discovering confirmed ones.

### `attention_repair` — Attention Repair *(Thorough only)*
**Model**: sonnet | **Timeout**: 25min | **Critical**: yes
**Execution**: LLM phase session

Detects and repairs depth agent attention failures — agents that were assigned a scope but produced 0 findings for entire files, or skipped functions that their domain should have covered. Reads the depth phase manifest (which files each agent was responsible for) and each depth output file, cross-references to identify uncovered scope segments, then spawns targeted repair agents to fill those specific gaps. This exists because even opus-level agents sometimes "forget" parts of their assignment when the scope is large — attention repair is the safety net that catches dropped coverage.

**Produces**: `attention_repair_summary.md`

**Why it follows depth**: By definition — it audits the depth agents' output for completeness. Can't repair what hasn't been produced yet.

### `rag_sweep` — External Precedent Sweep *(Core/Thorough)*
**Model**: sonnet | **Timeout**: 40min | **Critical**: no | **Needs MCP**: Claude headless only
**Execution**: LLM phase session

Researches bounded historical precedent for every finding. Claude headless receives a receipt-bound singleton `unified-vuln-db` server plus Web fallback. Claude PTY and Codex receive no MCP server and use governed Web research. The phase records typed source, relation, mechanism, and precondition context; it does not turn precedent absence into a numeric penalty or invent a fallback score.

**Produces**: `rag_validation.md`

**Why it follows depth (not earlier)**: It needs the complete finding set (breadth + depth). Running earlier would omit depth-discovered findings. Precedent remains separate context for later reconciliation rather than a validity oracle.

---

## Phase 4e: Semantic Dedup

### `sc_semantic_dedup` — Semantic Deduplication
**Model**: sonnet (Opus in SC Thorough since v2.1.1) | **Timeout**: 15min | **Critical**: no
**Execution**: LLM phase session

The pipeline produces findings from 10-20+ agents across breadth, rescan, per-contract, and depth. Despite within-chunk dedup in inventory, semantic duplicates survive — the same root cause described with different words by a breadth agent and a depth agent, or the same bug caught by both a scanner and a niche agent. This phase detects and merges those duplicates using title overlap scoring (cosine-like), location overlap detection (same file+line range), function-name extraction (same function targeted), and source-ID subset signals (one finding's evidence is a subset of another's). An LLM pass makes the final semantic decision on each candidate pair — mechanical signals nominate, the LLM confirms. In SC Thorough mode this per-pair adjudication runs on Opus (since v2.1.1), where the precision of the merge/keep decision matters most. On a large inventory, if a context compaction interrupts the turn while live candidate pairs remain, the phase now spends its in-session continuation budget to keep working rather than accepting a pre-written `PASSTHROUGH` result unchanged (the prior large-inventory no-op). Without this phase, the report would contain inflated finding counts that waste the reader's time on what is effectively the same bug reported twice.

**Produces**: `dedup_decisions.md`, `findings_inventory_deduped.md`

**Why it follows depth + RAG (not earlier)**: Needs ALL findings to exist (breadth + depth + niche + scanner) before deduplicating. Running before depth would miss depth-vs-breadth duplicates. Running before RAG doesn't strictly matter but the pipeline ordering keeps "all analysis" → "all cleanup" → "chain reasoning" as a clean logical flow.

---

## Phase 4c: Chain Analysis

### `chain` — Chain Agent 1: Enabler Enumeration + Grouping
**Model**: opus | **Timeout**: 25min | **Critical**: no
**Execution**: LLM phase session

This is where isolated findings become compound exploit paths. Performs Rule 12 (Exhaustive Enabler Enumeration): for each dangerous precondition state in confirmed findings, fills a 5-actor-category table asking "who can reach this dangerous state?" — external attackers, semi-trusted roles, natural operations, external events, or user action sequences. If a path exists but no finding covers it, creates a new enabler finding ([EN-N]). Then groups all findings by root cause into hypotheses (H-1, H-2, ...) — the unit of analysis for verification and reporting. Also scans depth agent output for `[CROSS-DOMAIN-DEP]` tags — assumptions one depth agent flagged as outside its domain that another depth agent's findings might break.

**Produces**: `hypotheses.md`, `finding_mapping.md`, `enabler_results.md`

**Why it follows dedup**: Must operate on the deduplicated finding set — otherwise it would create chains between findings that are actually the same bug described twice, producing nonsensical compound exploits. Also needs depth findings for the `[CROSS-DOMAIN-DEP]` scan and for the postcondition/precondition data that enables chain matching.

### `chain_agent2` — Chain Agent 2: Chain Matching + Composition Coverage
**Model**: opus | **Timeout**: 20min | **Critical**: no
**Execution**: LLM phase session

The creative reasoning phase of chain analysis. Takes Agent 1's grouped hypotheses and systematically checks: for each REFUTED or PARTIAL finding whose precondition is missing, does ANY other confirmed finding's postcondition create that exact precondition? If Finding B creates state X, and Finding A was refuted because state X was "unreachable" — then B enables A, and together they form a chain hypothesis (CH-N) with combined severity. This is how "individually low-risk bugs" become "critical compound exploits." Builds a composition coverage map tracking every finding pair considered and whether it was explored or skipped, enabling iteration 2 to fill gaps. Validates discovered chains against RAG for historical precedent.

**Produces**: `chain_hypotheses.md`, `composition_coverage.md`, updates `hypotheses.md`

**Why it's split into 2 agents**: Context budget. Agent 1 does the N-finding enabler enumeration (O(N×5) actor-category fills) which is already context-heavy. Agent 2 does the N×N pair matching which is a different kind of reasoning. Splitting also means Agent 2 can read Agent 1's clean output instead of raw depth/scanner files — information compression between phases.

---

## Phase 5: Verification

### `sc_verify_queue` — Verification Queue Manifest
**Model**: haiku | **Timeout**: 10min | **Critical**: yes
**Execution**: LLM phase session

Deterministic triage: reads `hypotheses.md` and assigns each hypothesis to a verification shard by severity tier. Critical+High hypotheses go to `verify_crithigh`, remaining High overflow to shards b-d, Medium to shards a-d, Low to shards a-b (Thorough only). Each shard gets a manifest listing which hypothesis IDs it's responsible for verifying. This exists because a single verification subprocess couldn't handle 80+ hypotheses within its timeout — the original monolithic verifier hit a 2700s ceiling on 81 hypotheses, verifying only 32 before timeout. Sharding gives each severity tier its own subprocess and timeout budget.

**Produces**: `verification_queue.md`

**Why it follows chain**: Must assign ALL hypotheses — including chain hypotheses (CH-N) created by chain analysis. If it ran before chain, chain hypotheses would be unverified.

### `sc_verify_crithigh` / `sc_verify_high_*` / `sc_verify_medium_*` / `sc_verify_low_*` — Verification Shards
**Model**: sonnet | **Timeout**: 35min (crit/high/med), 30min (low) | **Critical**: yes
**Execution**: LLM phase session (one subprocess per shard)

Each shard receives its assigned hypotheses and attempts to write and execute PoC tests that prove the claimed harm. For EVM: Foundry tests compiled with `forge build` and run with `forge test -vvv`. The critical constraint is the Impact Premise Verification gate — a PoC that merely proves "a function can be called" or "a state can be reached" is NOT valid evidence. The PoC must assert the HARM: "user receives 15% less than their pro-rata share" or "withdrawal reverts permanently." On assertion failure, the Assertion Retry Protocol allows one retry where only the setup changes (not the target function or harm assertion). Evidence tags: `[POC-PASS]` = mechanical proof (highest confidence), `[POC-FAIL]` = attack doesn't work as described, `[CODE-TRACE]` = manual reasoning without execution (fallible, caps at CONTESTED). For `[POC-PASS]` findings, the verifier also generates a minimal fix diff.

**Produces**: `verify_*.md` per hypothesis (e.g., `verify_H-01.md`, `verify_CH-1.md`)

**Why shards run sequentially**: These phases are **LLM phase sessions** — one subprocess per shard. But the sharding ensures no single subprocess is overwhelmed. Each shard typically handles 3-10 hypotheses within its timeout budget. Only breadth, rescan, and depth use the **Direct PTY worker pool** shape.

### `sc_verify_aggregate` — Verification Aggregation
**Model**: haiku | **Timeout**: 15min | **Critical**: yes
**Execution**: LLM phase session

Mechanically aggregates all `verify_*.md` files into a single `verify_core.md` summary table. Extracts verdict, evidence tag, final severity, and PoC status for each hypothesis. This is pure plumbing — no analysis, no judgment calls. It exists so that downstream phases (skeptic, crossbatch, report index) can read ONE file instead of globbing 30+ individual verify files. Also enables the completeness assertion: count of hypotheses in verify_core must equal count in hypotheses.md.

**Produces**: `verify_core.md`

**Why it follows all verify shards**: Can't aggregate partial results — must wait for every shard to complete (or degrade) before producing the summary.

### `skeptic` — Skeptic-Judge *(Thorough only)*
**Model**: opus | **Timeout**: 30min | **Critical**: yes
**Execution**: LLM phase session

Adversarial second opinion on HIGH and CRITICAL verified findings — the pipeline's built-in false-positive filter. For each high-severity finding, a Skeptic agent receives the finding description and source code but NOT the verifier's analysis, then independently argues the OPPOSITE case ("this is not exploitable because..."). If the Skeptic agrees with the verifier, the finding passes. If the Skeptic disagrees, a Judge agent reads both arguments side-by-side and decides who is right. Findings where the Judge cannot resolve the disagreement are tagged `UNRESOLVED` — severity demoted by 1 tier but the finding remains in the report body flagged for human review (not excluded). This prevents confident-but-wrong verifiers from polluting the report with false positives at the highest severity tiers.

**Produces**: `skeptic_*.md`, `judge_*.md`

**Why it follows verification**: Explicitly adversarial to the verifier's conclusions — needs those conclusions to exist first. Also runs only on findings that PASSED verification (arguing against a `[POC-FAIL]` finding would be pointless).

### `crossbatch` — Cross-Batch Consistency *(Core/Thorough)*
**Model**: sonnet | **Timeout**: 15min | **Critical**: yes
**Execution**: LLM phase session

Detects contradictions between verification shards that individually passed their gates but collectively make inconsistent claims. Example: shard A's verify_H-03.md says "the access control check at L45 prevents exploitation" while shard B's verify_H-07.md says "the access control check at L45 can be bypassed via flash loan" — these can't both be true. Also catches severity inconsistencies where the same code pattern is rated HIGH in one shard and LOW in another. This is the last quality gate before the report — ensuring internal consistency across all verification work.

**Produces**: `cross_batch_consistency.md`

**Why it's last in Phase 5**: Needs ALL verification outputs (shards + aggregate + skeptic) to cross-reference. It's the "final sanity check" before findings become report-ready.

---

## Phase 6: Report

### `report_index` — Index Agent
**Model**: sonnet | **Timeout**: 25min | **Critical**: yes
**Execution**: LLM phase session

The translation layer between the pipeline's internal world and the client-facing report. Creates the master mapping from internal hypothesis IDs (H-1, H-2, CH-3) to clean sequential report IDs (C-01, H-01, M-01, L-01, I-01). Applies only typed, separately authorized severity decisions. A failed/non-established PoC is emitted as `poc_demotion_proposals` review evidence and MUST NOT lower severity or dispose of the candidate. Root-cause consolidation is likewise proposal-only until an exact typed decision applies it. The phase assigns each still-live identity to a tier writer and runs a promotion coverage audit so no finding silently disappears during grouping-to-index projection.

**Produces**: `report_index.md`, `report_coverage.md`

**Why it follows crossbatch**: Needs the final, consistent, skeptic-reviewed verification results before assigning report IDs. If it ran earlier, severity adjustments from skeptic/crossbatch would require re-indexing.

### `report_body_writer_critical_high` — Critical+High Tier Writer
**Model**: sonnet | **Timeout**: 40min | **Critical**: yes
**Execution**: LLM phase session

Writes full finding sections for all Critical and High severity findings using the exact format from `report-template.md`. Each finding gets its own `### [C-01] Title [VERIFIED]` section with Severity, Location, Confidence, Description (3-5 sentences with code snippets pulled from actual source files), Impact (quantified where possible), PoC Result (from verify files), and Recommendation (paste verifier-generated fix diffs when available). For chain findings, the Description must narrate the complete multi-step attack sequence so a reader understands the full exploit without needing other findings. Zero internal pipeline IDs appear anywhere — the reader has never seen the audit infrastructure and never should.

**Produces**: `report_critical_high.md`

**Why Critical+High gets its own writer**: These are the findings that matter most to the client. A dedicated agent with full attention (no distraction from 20 Medium/Low findings) produces higher-quality write-ups for the bugs that demand immediate remediation.

### `report_body_writer_medium` — Medium Tier Writer
**Model**: sonnet | **Timeout**: 40min | **Critical**: yes
**Execution**: LLM phase session

Same format and quality standard as Critical+High writer, but for all Medium severity findings. Every finding gets equal treatment — no catch-all tables, no grouped summaries, no "remaining findings" dumps. A finding that only appears in a table row is effectively invisible to the reader. Includes a clear Recommendation with specific fix guidance for each finding. When the Medium tier exceeds ~12 findings, the driver shards this phase into multiple writers (a/b/c) to prevent context-window saturation.

**Produces**: `report_medium.md`

### `report_body_writer_low_info` — Low+Informational Tier Writer
**Model**: sonnet | **Timeout**: 40min | **Critical**: yes
**Execution**: LLM phase session

Writes Low and Informational findings with a classification step: each finding is either full-section (has any plausible security implication — missing validation, missing events, access control, centralization) or Quality Observation (unambiguously cosmetic — dead code, unused imports, naming inconsistencies, typos, gas optimization). Full-section findings get the standard format. Quality Observations go into a compact megasection table with ID, Title, Severity, Location, Class, and 1-sentence Description. This keeps the report readable without burying cosmetic observations alongside real security concerns, while still documenting everything the pipeline found.

**Produces**: `report_low_info.md`

**Why tier writers run sequentially (not parallel)**: These phases are **LLM phase sessions** — one subprocess per writer. They're independent — each tier writer reads only its assigned portion of report_index.md plus its relevant verify files. They could theoretically run in parallel in a future architecture. Only breadth, rescan, and depth use the **Direct PTY worker pool** shape.

### `report_critical_high` / `report_medium` / `report_low_info` — Tier Confirmation
**Model**: haiku | **Timeout**: 5min | **Critical**: yes
**Execution**: LLM phase session (one subprocess per tier)

Lightweight validation pass after each tier writer completes. Checks that the tier file exists, has the correct section structure (`### [X-NN] Title` headers), meets minimum length requirements (400 chars per finding section body — anything shorter is a stub that fails the gate), and contains no internal ID leakage. If the tier was sharded (large finding count split across multiple writers), these phases confirm all shard outputs are present and well-formed before the merge step. A failed confirmation triggers a tier-writer retry — the most common failure mode is a tier writer that produces stub sections ("See verify file") instead of full write-ups.

**Produces**: confirms `report_*.md`

### `report_*_merge` — Tier Merge *(conditional)*
**Model**: haiku | **Timeout**: 2min | **Critical**: yes
**Execution**: LLM phase session

Only runs when a tier was split into multiple shards (e.g., 30+ Medium findings split across 3 writers because a single writer would exceed context budget). Mechanically concatenates shard outputs into a single tier file, maintaining the ID ordering from report_index.md. No analysis, no rewriting — pure plumbing. The assembler downstream expects exactly 3 tier files (critical_high, medium, low_info), so the merge normalizes sharded output back into that expected shape.

**Produces**: merged `report_*.md`

### `report_assemble` — Final Report Assembly
**Execution**: Python mechanical (no LLM) | **Runtime**: <1s | **Critical**: yes

The final phase. Fully deterministic Python assembler since v2.3.11 (no LLM call — prior LLM-driven concat would thrash for 1+ hour on large tier files). Merges the three tier files into `AUDIT_REPORT.md` in the project root with tier content pasted verbatim. Generates deterministically from `report_index.md` counts and the Master Finding Index: the Executive Summary, Priority Remediation Order (numbered list using report IDs), Summary Table (severity counts), Components Audited Table (from `contract_inventory.md`), and Appendix A (internal traceability — optional). Runs 5 quality checks before finalizing: finding count matches summary table, no internal ID patterns in the report body, all cross-references point to existing findings, no duplicate sections, no control characters leaked from tool output. If any check fails, the assembler auto-fixes and documents what it changed.

**Produces**: `AUDIT_REPORT.md` (in project root)

**Why it's last**: The report is the deliverable. Everything before this phase exists to produce the inputs the report needs — verified findings, clean IDs, correct severities, written sections. The assembler touches every prior phase's output and is the final quality gate before the client sees results.

### `report_dedup_agent` — Final Report Consolidation Proposer *(Phase 6d, since v2.1.1)*
**Execution**: LLM phase session | **Critical**: no (never halts)

A post-assembly pass that reads the fully assembled `AUDIT_REPORT.md` and PROPOSES consolidations the mechanical signals cannot make on their own: cross-tier and no-/mismatched-location duplicate MERGES (the same underlying bug surfaced at two severity tiers, or whose `Location` is missing or written at different granularity), plus Quality-Observation reclassifications of unambiguously cosmetic Low/Info findings. The agent **proposes only** — it never edits, renumbers, or deletes report content. The existing deterministic Python `report_dedup` then executes those proposals through its unchanged zero-data-loss embed + data-loss gate (agent proposes, Python disposes), so a proposal that would lose information is rejected mechanically. Both the pre-dedup snapshot (`AUDIT_REPORT.pre-dedup.md`) and the deduped `AUDIT_REPORT.md` are kept. Because the phase is non-critical, a failed or empty proposal degrades to the assembled report unchanged rather than halting the run.

**Applied-authority correction**: similarity, Markdown, source-subset heuristics,
and zero-loss embedding are proposal/safety signals, not merge authority. A
standalone report ID is removed only when both IDs resolve to the exact same
current source identity and a typed applied-alias receipt is staged inside the
crash-safe report transaction. Missing, stale, cyclic, dead-survivor, lossy, or
incomplete authority leaves both findings standalone.

**Produces**: `report_dedup_agent_decisions.md` (proposals), `report_dedup_applied_alias_receipt.json` (typed authority), `AUDIT_REPORT.pre-dedup.md` (snapshot), updated `AUDIT_REPORT.md`

---

## The Pipeline's Logic: Why This Order?

The ordering follows a funnel from **wide discovery** → **structured cataloging** → **deep investigation** → **creative composition** → **mechanical verification** → **adversarial challenge** → **client presentation**:

```
DISCOVER (breadth, rescan)
    "Find everything that MIGHT be a bug — cast wide, accept noise"
         ↓
CATALOG (inventory, dedup)  
    "Structure the raw findings into a canonical format, remove duplicates"
         ↓
INVESTIGATE (invariants → depth → attention repair → RAG)
    "Go deep on each finding's domain — trace paths, test boundaries, validate against history"
         ↓
COMPOSE (chain analysis)
    "Connect findings together — do isolated bugs combine into compound exploits?"
         ↓
VERIFY (PoC shards)
    "Prove or disprove each hypothesis mechanically — write code, run it, record the result"
         ↓
CHALLENGE (skeptic, crossbatch)
    "Argue against the verification — catch false positives, ensure consistency"
         ↓
PRESENT (index → tier writers → assemble)
    "Transform internal pipeline data into a professional audit report"
```

Each layer REDUCES uncertainty for the next. Breadth produces noisy candidates. Inventory structures them. Depth resolves uncertain ones. Chain combines them. Verification provides ground truth. Skeptic filters false positives. Report presents the surviving findings clearly.

---

## Under the Hood: Driver Mechanics

### Subprocess Isolation
Claude phases run through either the isolated headless transport or the PTY transport; Codex phases run through isolated `codex exec`. Plugins, hooks, and ambient MCP servers are disabled. Only Claude headless `rag_sweep` can receive the receipt-bound singleton RAG server. Claude PTY and Codex `rag_sweep` use Web fallback. Every subprocess receives only its phase-specific contract.

### Checkpoint & Resume
After every successful phase, `_v2_checkpoint.json` is atomically updated (write to `.tmp` then `os.replace()` — atomic on POSIX, same-volume on Windows). On crash or rate-limit exhaustion, `python plamen_driver.py config.json` auto-resumes from the last completed phase. The checkpoint tracks: `completed` (phases done), `degraded` (phases that failed and were skipped), `rate_limited_at` (timestamp if paused for rate limit).

### Retry & Degrade
Each phase gets 2 attempts (1 original + 1 retry with delta-injected hints — the retry prompt includes what went wrong on attempt 1). Critical phases that fail both attempts offer an interactive 3-option menu: Enter=retry (attempt 3), S=skip and degrade (continue pipeline without this phase's artifacts), Esc=exit. Non-critical phases silently degrade on failure and the pipeline continues — downstream phases handle missing optional artifacts gracefully.

### Rate Limit Handling
On rate limit detection (from subprocess output or API response codes), the driver pauses with a visible countdown timer, then resumes the same phase. If a rate limit consumed the retry budget (the phase was already on its second attempt when rate-limited), the same interactive menu appears for critical phases.

### Timeout Scaling
Base timeouts from phase definitions scale with: codebase size (line count), hypothesis count (+90s per hypothesis above 8 for verify shards), and mode (Thorough applies a 1.5x multiplier). The `scale_timeout()` function ensures small codebases don't over-budget and large codebases don't under-budget.

### PTY Worker Pools
For `breadth`, `rescan`, and `depth`, the driver spawns one Claude PTY per worker artifact via a `ThreadPoolExecutor`. Each worker writes a single `analysis_*.md` / `depth_*_findings.md` / similar file with `PLAMEN_STATUS` markers. Completed rows survive retries; only missing or structurally invalid rows are re-spawned. Escape/halt (`_cancel_pending_worker_futures`) cancels queued workers immediately and terminates in-flight workers with 2-second grace (`_HALT_TERMINATE_GRACE_S = 2.0`) before SIGKILL.

### Compaction tolerance
Claude context auto-compaction during a worker turn is **informational, not a failure**. The driver detects compaction via `transcript_shows_compaction` and emits a single heartbeat line ("Claude compacted context; continuing normally (disk gate is source of truth)"). Disk markers — not Claude's `DONE` text — determine completion.

### Run lock
Each scratchpad has a `.plamen_run.lock` that prevents concurrent driver invocations against the same audit. If a stale process owns the lock, the driver refuses to start until the operator clears it.

---

## Phase Counts by Mode

Durations and costs below are **typical for complex codebases** — small audits finish in a fraction of these times (see `getting-started.md` for the small/medium/large breakdown).

| Mode | Phases | Typical Duration | Typical Cost |
|------|--------|-----------------|-------------|
| Light | ~15 (skip rescan, invariants, attention repair, RAG, skeptic, crossbatch, low verify) | 1-2 hours | $15-30 |
| Core | ~25 (skip rescan, attention repair, skeptic, low verify) | 3-5 hours | $40-80 |
| Thorough | ~40+ (everything, up to 3 depth iterations, all verify tiers) | 6-12 hours | $80-200 |

---

**See also**: [architecture.md](architecture.md) · [internals.md](internals.md) · [audit-modes.md](audit-modes.md) · [glossary.md](glossary.md) · [docs index](README.md)
