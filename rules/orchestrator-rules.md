# Plamen Orchestration Rules

> **Audience**: The V1 orchestrator (commands/plamen.md or commands/plamen-l1.md running in a full Claude Code session).
> **NOT loaded by**: V2 subprocess phases — they receive only their phase-specific section of the V1 prompt.
> This file is NOT in CLAUDE.md and is NOT auto-loaded by `claude -p` subprocesses.

---

## Orchestration Modes

> **Two orchestration modes**:
>
> | Command | Architecture | Resume on crash? | Status |
> |---------|-------------|-----------------|--------|
> | `/plamen` | V2 — routes to the same Python driver as `/plamen-wizard` (`commands/plamen.md` Step -1 redirects all interactive invocations) | **Yes** (auto-checkpoint) | Default |
> | `/plamen-wizard` | V2 — Python outer loop, one `claude -p` subprocess per phase | **Yes** (auto-checkpoint) | Rewritten 2026-04-20 |
>
> **`/plamen*` (default)**: `/plamen light`, `/plamen core`, `/plamen thorough`, `/plamen compare` all route through Step -1 of `commands/plamen.md` to the V2 driver — there is no standalone single-conversation V1 path left.
> **V2 (resumable)**: `/plamen-wizard` — interactive setup, then launches `plamen_driver.py`. Same prompt (`commands/plamen.md` or `commands/plamen-l1.md`) is executed one phase at a time, each in a fresh `claude -p` context. This prevents the legacy single-conversation "context saturation → phase skipping" failure mode while reusing the same orchestrator logic verbatim. Python's job: outer loop, checkpoint, gate-check, retry-once-then-degrade, rate-limit pause + resume.
>
> If usage runs out mid-audit, re-run: `python3 ~/.claude/scripts/plamen_driver.py {project}/.scratchpad/config.json` — auto-resumes from last successful phase.
>
> **V2 design rule**: Python does NOT compose subagent prompts, manage subagent parallelism, or second-guess the LLM. That's Claude Code's Task tool inside each phase (the prior "Python composes prompts" misarchitecture was scrapped).
>
> **Ownership boundary**: V1 prompts (`commands/plamen.md`, `commands/plamen-l1.md`) own audit **methodology** — what agents analyze, how findings are structured, when skills inject, how severity is assigned. The Python driver owns **runtime policy** — phase scheduling, artifact gating, rate-limit handling, resume, subprocess isolation, and model routing. Model routing (e.g. Thorough-breadth=sonnet, Thorough-depth=opus) is runtime policy, not methodology — but its *outputs* affect finding quality, so policy changes require validation against recall benchmarks. Neither layer is the "single source of truth" for audits; they are orthogonal and both are authoritative within their scope.

---

## AUDIT MODES

| Dimension | Light | Core | Thorough |
|-----------|-------|------|----------|
| Target plan | Pro | Max | Max |
| Orchestrator model | User's session model (Pro default: Sonnet) | Opus | Opus |
| Agent models | All Sonnet/Haiku | Opus + Sonnet | Opus + Sonnet |
| Recon | 2 sonnet (no RAG, no fork) | 4 agents (RAG fire-and-forget) | 4 agents (full RAG) |
| Breadth agents | 3-4 sonnet | 5-9 opus | 5-9 opus |
| Breadth re-scan (3b/3c) | Skip | Skip | Full (sonnet, 2 iters + per-contract) |
| Depth loop | 4 merged sonnet, iter 1 | 8+ agents, iter 1 | Iter 1-3 (DA role) |
| Niche agents | Skip | Flag-triggered | Flag-triggered |
| Semantic invariants | Skip | Pass 1 only | Pass 1 + Pass 2 (recursive trace) |
| Confidence scoring | None (verdicts only) | 2-axis (Evidence + Quality) | 3 code-derived axes (Evidence, Consensus, Quality) + separate precedent context |
| Invariant fuzz (EVM) | Skip | Skip | Yes (zero budget cost) |
| Medusa stateful fuzz (EVM) | Skip | Skip | Yes (parallel, if installed) |
| Design stress testing | Skip | Skip | 1 reserved slot, UNCONDITIONAL |
| Finding perturbation | Skip | Skip | 1 sonnet (structured mutations of depth findings) |
| Skill execution checklist | Skip | Skip | 1 haiku (depth step verification → iter2 input) |
| Symmetric pairs directive | Skip | Skip | Pre-computed pairs table in depth prompts |
| RAG Sweep | Skip | 1 sonnet | 1 sonnet |
| Chain analysis | 1 sonnet (merged) | 2 agents | 2 agents + iteration 2 |
| Verification scope | Chains + ALL Medium+ (sonnet) | Chains + ALL Medium+ | ALL severities (with fuzz) |
| Independent skeptic proposals + typed adjudication | Skip | Skip | Trigger-based all-severity denominator |
| Cross-batch consistency | Skip | 1 sonnet | 1 sonnet |
| Report | 2 agents (sonnet + haiku) | 5 agents (opus + sonnet + haiku) | 5 agents |
| Agent count | ~18-22 | ~30-50 | ~40-100 |

---

## CRITICAL RULES

1. **YOU ARE THE ORCHESTRATOR** - Spawn agents directly, don't delegate orchestration
2. **MCP AUTHORITY IS PHASE-BOUND** - Only Claude headless `rag_sweep` may
   receive MCP, and only the receipt-bound singleton `unified-vuln-db`.
   Claude PTY and Codex use governed Web precedent research. All other phases
   use direct local tools and MUST NOT infer MCP authority from ambient config.
3. **INSTANTIATE, DON'T INJECT** - Templates get {PLACEHOLDERS} replaced. **For phase templates with embedded agent prompts** (phase4b-invariant-fuzz.md, phase4b-loop.md Medusa section), pass the template file path TO THE AGENT — the agent reads and follows the full methodology including all STEP sections. The orchestrator MUST NOT replace these templates with summarized or hardcoded property lists.
4. **DYNAMIC AGENT COUNT** - Based on protocol complexity
5. **PARALLEL ANALYSIS** - All analysis agents for a phase spawn in ONE message (one tool call per agent, all in the same response). This is critical for depth agents: if only 1 of N agents is spawned, it may complete the entire remaining pipeline solo, skipping the other N-1 agents' domains.
5a. **AGENT SCOPE CONTAINMENT** - Every agent prompt for phases 3/4b MUST end with: `"SCOPE: Write ONLY to your assigned output file. Do NOT read or write other agents' output files. Do NOT proceed to subsequent pipeline phases (chain analysis, verification, report). Return your findings and stop."`
6. **CONTEXT PROTECTION** - Don't read large files; agents read them
7. **METHODOLOGY NOT ANSWERS** - Tell agents WHAT to analyze, not WHAT to find
8. **NO REPORT BEFORE VERIFICATION** - Verify before reporting
9. **SEVERITY MATRIX** - Use Impact x Likelihood from report-template.md
10. **PLATFORM AWARENESS** - Detect the user's platform from the Environment section. On Windows: use forward slashes, `pushd` prefix for directory commands, `$env:VAR` for env vars, `python` not `python3`. On macOS/Linux: use `export VAR=value` for env vars, `python3`, standard Unix paths. Never hardcode platform-specific syntax without checking.
11. **MCP TIMEOUT POLICY** - If the typed transport receipt grants MCP (current
    V2: Claude headless `rag_sweep` only), include: `"When an MCP tool call
    returns a timeout error or fails, do NOT retry the same call. Record
    [MCP: TIMEOUT], stop using that provider, and switch to governed WebSearch.
    If Web research also fails, record typed UNAVAILABLE context."` Recon,
    depth, chain, verification, and report phases do not receive MCP.
12. **THOROUGH MODE COMPLETENESS** - In Thorough mode, EVERY step in the Thorough column of the AUDIT MODES table MUST execute. The orchestrator MUST NOT skip, defer, combine, or simplify any step for ANY reason - including speed, efficiency, time, context limits, budget, pragmatism, "findings are well-characterized", or "the codebase is small." If a step fails (timeout, MCP error), document the failure and use the fallback defined in the template. Silently skipping ≠ fallback. **MANDATORY THOROUGH STEPS (non-negotiable):** Invariant fuzz campaign (phase4b-invariant-fuzz.md) - 5min timeout built-in; Medusa fuzz campaign (if MEDUSA_AVAILABLE) - 15min timeout built-in; three-axis code-confidence scoring after iteration 1; Depth iteration 2 (if ANY uncertain finding >= Medium); Depth iteration 3 (if progress made in iter 2); external precedent research + deterministic typed reconciliation (Phase 4b.5, governed by `precedent-evidence-policy.md`, never a confidence/disposition/severity input); Design Stress Testing (1 reserved slot, UNCONDITIONAL); Finding Perturbation Agent (1 sonnet, post-depth, structured mutations); Skill Execution Checklist (1 haiku, post-depth, gap→iter2 input); Symmetric Pairs Directive (pre-computed table in depth prompts); Variable-finding cross-reference (for chain analysis); independent skeptic proposals plus separate typed severity adjudication for every finding selected by the driver-owned all-severity trigger manifest (Phase 5.1); Depth input filtering (domain-specific views); Model diversity (opus for token-flow/state-trace, sonnet for others); Compaction-resilient manifest (phase4b_manifest.md). **VIOLATION**: Skipping any of these is a WORKFLOW VIOLATION. Log the violation to `{SCRATCHPAD}/violations.md` and continue - but the violation is permanent record.
13. **NO SPEED OPTIMIZATION IN THOROUGH MODE** - The orchestrator MUST NOT use these phrases when deciding to skip a pipeline step: "for time efficiency", "let me be pragmatic", "for efficiency", "skip for now", "the codebase is small enough", "already well-characterized", "good enough", "sufficient coverage", "context budget", "practical constraints", "fast-track", "focused depth loop", "given the extensive analysis". If any of these appear in reasoning about whether to execute a step → EXECUTE THE STEP. The user chose Thorough mode specifically because they want every step to run. Thorough mode optimizes for COMPLETENESS, not speed.
13a. **CONTEXT BUDGET TRIAGE (THOROUGH MODE)** - If the orchestrator is approaching context limits, apply this priority: **COMPRESS** (shorter prompts, fewer re-scan iterations, merge Phase 3c clusters) before **NEVER-CUT** agents. The following are **NEVER-CUT** in Thorough mode — the orchestrator MUST spawn them even if every other step is compressed to a single sentence: (a) ALL 4 depth agents (depth-token-flow, depth-state-trace, depth-edge-case, depth-external) as SEPARATE agents with SEPARATE output files matching the manifest names; (b) ALL 3 Blind Spot Scanners (A, B, C) — Scanner C CHECK 5 contains the untrusted-call-target check that catches guard parameter injection; (c) ALL niche agents marked Required in template_recommendations.md — CALLBACK_RECEIVER_SAFETY catches permissionless callback state inflation, MULTI_STEP_OPERATION_SAFETY catches infrastructure-address-targeting via depositFor/stakeFor; (d) Validation Sweep; (e) Design Stress Testing; (f) Confidence scoring (at least 2-axis); (g) RAG Validation Sweep. **If context is truly exhausted before NEVER-CUT agents run**: HALT the pipeline, inform the user "Context exhausted at Phase {X} — {N} NEVER-CUT agents remain unspawned. Continue in a new conversation or reduce scope." Do NOT silently degrade to Core-equivalent coverage while claiming Thorough mode. **VIOLATION**: Merging depth agents (e.g., "combined token-flow + state-trace"), skipping Scanner C, or skipping niche agents to "save context" is a WORKFLOW VIOLATION that directly caused 6/7 misses in a prior audit post-mortem.
14. **OPERATIONAL IMPLICATIONS QUALITY GATE** - After Recon Agent 1B completes, the orchestrator MUST verify that `design_context.md` contains an `## Operational Implications` section with at least one implication per documented Key Invariant. If the section is missing or contains fewer implications than invariants, re-prompt Agent 1B: `"The Operational Implications section in design_context.md is incomplete. For each Key Invariant, state what it means for how the system's accounting works — not what it checks, but what it tells you about the system's model. Derive from invariant formulas and data structure signatures."` This gate prevents downstream agents from analyzing a protocol they don't understand.
15. **PHASE 5 COMPLETION ASSERTION** - Before spawning ANY Phase 6 (Report) agents, the orchestrator MUST verify Phase 5 verification AND Phase 5.1/5.2 secondary verification completed. Required checks: (a) At least one `verify_*.md` file exists with the standard verification scope; (b) **Core/Thorough**: `cross_batch_consistency.md` exists (Phase 5.2 — manifest gate enforces this); (c) **Thorough only**: the driver-owned skeptic trigger manifest, `skeptic_findings.md`, proposal-only `skeptic_judge_decisions.md`, and hash-bound `skeptic_challenges.json` cover the exact all-severity trigger denominator; every severity-changing challenge is routed to a separate typed adjudicator, and only the validated typed severity ledger may change report tier. If any artifact or exact-ID receipt is missing, the driver MUST repair/retry or retain the upstream severity with visible human-review debt before Phase 6. "All PoCs passed so skeptic is unnecessary" is NOT a valid skip reason. Skipping Phase 5.1 or 5.2 is a WORKFLOW VIOLATION logged to `{SCRATCHPAD}/violations.md`.

16. **COMPACTION SURVIVAL** - When Claude Code compacts this conversation, CLAUDE.md is re-read from disk. In-context state (current phase, completed steps, agent return messages) is NOT preserved. After any compaction event, the orchestrator MUST read `{SCRATCHPAD}/pipeline_checkpoint.md` to recover pipeline state before taking any action. Do NOT rely on in-context memory of what phases completed — read the checkpoint file. The checkpoint is written by the orchestrator at every phase boundary per §WRITE-THEN-VERIFY in plamen.md.
