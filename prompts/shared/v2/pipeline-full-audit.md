# Plamen Pipeline Full Audit — Master Prompt

> **Purpose**: Spawn parallel subagents to audit every dimension of the Plamen V2 audit pipeline from first principles.
> **Scope**: 7 Python modules (~20K LOC), 37 V2 prompt templates, 6 command files (~3K LOC), 10 rule files, 8 agent definitions, 140 skill files, 9 niche agents, 30 injectable skills, 36 test files (~22K LOC).
> **Output**: Each subagent writes a structured findings file. The orchestrator merges into a prioritized master problem list.

---

## File Map (for all subagents)

### Python Runtime (~/.claude/scripts\)
| File | Lines | Responsibility |
|------|-------|---------------|
| `plamen_driver.py` | 2612 | Main loop, subprocess launch, checkpoint, retry, phase orchestration |
| `plamen_validators.py` | 6988 | All gate checks, format validation, report quality, completeness |
| `plamen_parsers.py` | 4094 | LLM output parsing — IDs, sections, tables, markdown structures |
| `plamen_mechanical.py` | 1974 | Deterministic transforms — sharding, dedup, graph, inventory merge |
| `plamen_prompt.py` | 1966 | Prompt composition — section extraction, placeholder replacement, isolation |
| `plamen_types.py` | 915 | Phase definitions, constants, severity/evidence enums, phase graph |
| `plamen_display.py` | 1136 | TUI rendering, interactive prompts, progress tracking |
| `test_*.py` (36 files) | 22046 | Unit and integration tests |

### Methodology (~/.claude/commands\)
| File | Lines | Responsibility |
|------|-------|---------------|
| `plamen.md` | 1254 | V1 SC orchestrator prompt (read by V2 phases as methodology source) |
| `plamen-l1.md` | 1212 | V1 L1 orchestrator prompt |
| `plamen-wizard.md` | 258 | V2 SC entry point |
| `plamen-l1-wizard.md` | 288 | V2 L1 entry point |

### Rules (~/.claude/rules\) — 10 files, all loaded via CLAUDE.md
### V2 Prompt Templates (~/.claude/prompts\shared\v2\) — 37 files, ~3500 lines total
### Language-Specific Prompts (~/.claude/prompts\{evm,solana,aptos,sui,soroban,daml,l1}\) — ~7-12 files per tree
### Agent Definitions (~/.claude/agents\) — 8 files (6 depth + security-analyzer + security-verifier)
### Skills — 155 SKILL.md files across 6 language trees + 9 niche + 30 injectable (including 16 L1)

---

## Subagent Architecture

Spawn ALL 10 subagents in parallel. Each writes findings to `{SCRATCHPAD}/audit_{domain}.md`. After all return, merge into `{SCRATCHPAD}/pipeline_audit_master.md`.

---

### SUBAGENT 1: Architecture & Design Integrity

**Scope**: Overall system design, ownership boundaries, single-source-of-truth violations, layering

**Read**: `plamen_driver.py` (full), `plamen_types.py` (full), `CLAUDE.md`, `orchestrator-rules.md`, `plamen-wizard.md`, `plamen-l1-wizard.md`

**Audit dimensions**:

1. **Ownership boundary violations**: The driver's documented boundary is "Python owns runtime policy, LLM owns methodology." Grep for places where Python makes methodology decisions (severity assessment, finding deduplication logic that isn't purely mechanical, prompt content that prescribes WHAT to find instead of HOW to analyze). Also grep for places where LLM prompts contain runtime policy (timeout values, retry counts, subprocess commands).

2. **Single-source-of-truth audit**: For each of these concepts, identify EVERY location that defines it and flag duplicates:
   - Internal finding ID regex patterns (should be one canonical source)
   - Severity levels and their ordering
   - Evidence tag definitions and weights
   - Phase names and their ordering
   - Expected artifact filename patterns
   - Model assignments per phase/mode

3. **V1/V2 prompt architecture**: V2 phases receive sections of the V1 prompt (`plamen.md` / `plamen-l1.md`) via `build_phase_prompt()`. But V2 also has its own prompt templates in `prompts/shared/v2/`. Audit: which phases use V1 sections, which use V2 templates, which use both? Are there contradictions between V1 methodology and V2 overrides? Is the V1 prompt still the true source of methodology or has V2 drifted into its own parallel universe?

4. **Dead architecture**: Identify code paths, functions, classes, imports, and constants that are unreachable or unused. Look for:
   - Functions defined but never called (grep function definitions against their names in the rest of the codebase)
   - Constants defined but never referenced
   - Imports that are unused
   - Phase definitions in `plamen_types.py` that can never be reached by the phase graph
   - Command files that are never loaded (`plamen-v1-archive.md`, `plamen-l1-post-depth.md`)

5. **Circular dependency / import structure**: Map the import graph between plamen_*.py modules. Are there circular imports? Are there imports that could be avoided by restructuring? Is the module boundary clean (types→parsers→validators→mechanical→prompt→driver→display)?

6. **Configuration sprawl**: How many places define "what mode X does"? The AUDIT MODES table in orchestrator-rules.md, the phase definitions in plamen_types.py, the V1 prompt, the V2 prompt templates, CLAUDE.md — do they all agree? Find contradictions.

**Output format**: Write to `audit_architecture.md`. For each finding:
```
## [ARCH-N] Title
**Category**: OWNERSHIP_VIOLATION | SSOT_VIOLATION | DEAD_CODE | V1_V2_DRIFT | CIRCULAR_DEP | CONFIG_SPRAWL
**Severity**: P0 (breaks correctness) | P1 (breaks maintainability) | P2 (tech debt)
**Location**: file:line
**Evidence**: [code snippet or grep result]
**Root cause**: [WHY this exists — not just what's wrong but what structural flaw allowed it]
**Fix class**: [What kind of fix — delete, consolidate, restructure, document]
```

---

### SUBAGENT 2: Driver Control Flow & State Machine

**Scope**: `plamen_driver.py` — every code path, error handling, state transitions, checkpoint management

**Read**: `plamen_driver.py` (full — all 2612 lines), `plamen_types.py` (Phase class, phase graph)

**Audit dimensions**:

1. **Main loop completeness**: Trace every path through the main `for phase in phases:` loop. For each combination of:
   - Phase passes on attempt 1
   - Phase fails attempt 1, passes attempt 2
   - Phase fails both attempts (critical vs non-critical)
   - Rate limit during phase
   - Rate limit consuming retry budget
   - User Esc-halt during phase
   - User retry after Esc-halt
   - Subprocess returns rc=0 but artifacts missing
   - Subprocess returns rc≠0
   - Phase is already completed (in checkpoint)
   - Phase is already degraded (in checkpoint)
   
   Verify: Does the code reach `checkpoint.mark_completed()`? Does `continue` skip it? Does a `sys.exit` fire prematurely? Are there fall-through bugs where code meant for one branch executes in another?

2. **Checkpoint atomicity**: Read the checkpoint save/load logic. Is it atomic (write-temp-then-rename)? What happens if the process is killed mid-write? What happens if the checkpoint file is corrupted JSON? What happens if the checkpoint lists a phase as completed but its artifacts are missing?

3. **Retry logic audit**: For each phase, trace the retry behavior:
   - `max_retries` (from phase definition) — is it always 1 (giving 2 total attempts)?
   - Retry hints (delta injection) — what exactly gets injected on retry? Is the retry prompt substantively different?
   - Rate-limit retry (the rate_limited_at / second attempt path) — does this correctly interact with the normal retry path, or can a phase get 3+ attempts via separate mechanisms?
   - Critical phase interactive retry (the new v2.6.2 code) — does attempt 3 correctly fall through to mark_completed on success?
   - Does `_clear_retry_hint` always fire on success? Can stale hints accumulate?

4. **Subprocess launch correctness**: Read `run_phase()` and all subprocess construction code. Verify:
   - stdin is file-based (not PIPE — v2.1.3 fix)
   - stdout/stderr capture works on both Windows and Unix
   - `_subprocess_isolation.json` is correctly applied
   - `--output-format` flag and its interaction with stdio capture
   - Process timeout (`scale_timeout`) — are the scaling factors correct for each mode × phase?
   - Environment variables passed to subprocess
   - Return code interpretation (0=success, non-zero=failure, -3=halt)

5. **Race conditions and file system assumptions**: The driver reads/writes scratchpad files while subprocesses also write to them. Are there TOCTOU races? Does the driver assume a file exists that a subprocess might not have written yet? Does `_snapshot_file_state()` correctly capture pre-phase state vs post-phase state?

6. **Error handling completeness**: For every `try/except` block, verify:
   - Is the exception type specific enough (not bare `except:` or `except Exception:`)?
   - Is the error logged with enough context to diagnose?
   - Does the error path leave the system in a consistent state (checkpoint not corrupted, no half-written files)?
   - Are there `except: pass` blocks that silently swallow errors?

**Output format**: Same as Subagent 1, category = CONTROL_FLOW | CHECKPOINT | RETRY | SUBPROCESS | RACE | ERROR_HANDLING

---

### SUBAGENT 3: Gate & Validator Correctness

**Scope**: `plamen_validators.py` (6988 lines) + `plamen_parsers.py` (4094 lines) — format assumptions, regex fragility, edge cases

**Read**: Both files in full.

**Audit dimensions**:

1. **Regex inventory**: Extract EVERY regex pattern in both files. For each:
   - What LLM output format does it assume?
   - What happens when the LLM deviates (extra whitespace, bold markers, different casing, missing columns)?
   - Is the regex anchored (`^`) or floating? Does it use `re.IGNORECASE`?
   - Is `_llm_norm()` applied to the input before the regex runs? (v2.5.3 mandated this at all 26 entry points — verify completeness)
   - Can the regex match partial/wrong content (false positive)?
   - Can the regex miss valid content (false negative)?

2. **Parser-validator contract**: For each validator function, identify which parser function it depends on. Then verify:
   - Does the parser produce the exact data structure the validator expects?
   - Are there type mismatches (parser returns `List[str]` but validator expects `List[Tuple[str,str]]`)?
   - Does the parser handle empty input gracefully?
   - Does the parser handle malformed input (truncated markdown, missing columns, extra rows)?

3. **Gate ordering dependencies**: Some validators depend on artifacts from earlier phases. Map each validator to its required input artifacts and verify:
   - Are the artifacts guaranteed to exist when the validator runs?
   - What happens if an artifact exists but is empty (0 bytes)?
   - What happens if an artifact exists but has wrong format?
   - Are there circular dependencies (validator A needs output of validator B, which needs output of validator A)?

4. **Vacuous pass detection**: A gate that passes because it found 0 items to check is a silent failure. For each validator:
   - What does it do when the input set is empty?
   - Does it distinguish "0 violations found (good)" from "0 items checked (bad)"?
   - Is there an explicit ≥1 item assertion before the check loop?
   - Has the v2.3.5/v2.5.3 vacuous-pass hardening been applied everywhere?

5. **Report quality gate**: Read the report quality validation code. Does it:
   - Correctly count finding sections per severity?
   - Detect internal ID leakage (all patterns, not just common ones)?
   - Validate cross-references between findings?
   - Check minimum section length (400 chars per finding)?
   - Handle the Quality Observations megasection correctly?

6. **LLM normalization completeness**: v2.5.3 added `_llm_norm()` at entry points. Verify:
   - Is it applied at ALL 26+ entry points (not just the ones found in the v2.5.3 audit)?
   - Does `_llm_norm()` itself handle all common deviations (bold markers, extra spaces, Unicode variants, control characters)?
   - Are there parser paths that bypass normalization?

**Output format**: Same structure, category = REGEX_FRAGILITY | CONTRACT_MISMATCH | ORDERING_DEP | VACUOUS_PASS | REPORT_GATE | NORM_GAP

---

### SUBAGENT 4: Prompt Composition & Isolation

**Scope**: `plamen_prompt.py` (1966 lines) + all V2 templates in `prompts/shared/v2/` + V1 commands (`plamen.md`, `plamen-l1.md`)

**Read**: `plamen_prompt.py` (full), all 37 V2 template files, both V1 command files

**Audit dimensions**:

1. **Section extraction correctness**: `build_phase_prompt()` extracts sections from the V1 prompt for V2 phases. For each phase:
   - What section markers does it look for?
   - Does it use exact string match, regex, or substring?
   - Can it extract the WRONG section (ambiguous markers)?
   - Can it extract NOTHING (marker not found, fails silently)?
   - Does it handle V1 prompt changes gracefully (if someone edits plamen.md, does extraction break)?

2. **Placeholder replacement**: V2 templates use `{SCRATCHPAD}`, `{PROJECT_ROOT}`, `{LANGUAGE}`, etc. For each template:
   - List every placeholder used
   - Verify the prompt builder replaces ALL of them (no unreplaced `{VARIABLE}` in output)
   - Verify no placeholder is double-replaced or replaced with the wrong value
   - Check for template injection: can a PROJECT_ROOT path containing `{` break replacement?

3. **Phase isolation (v2.4.6)**: Each subprocess should only see its own prompt. Verify:
   - Forward-reference sanitization: does the prompt mention phases AFTER the current one?
   - Routing table stripping: are the phase-routing tables (which list ALL phases) removed?
   - Foreign subsection cuts: are subsections from other phases removed?
   - HARD STOP directive: is it present in every V2 phase prompt?
   - Can a subprocess "read ahead" by examining scratchpad files from future phases?

4. **Prompt-to-artifact contract**: For each V2 template, extract:
   - What files does the prompt tell the LLM to WRITE?
   - What filenames does the corresponding `Phase.expected_artifacts` expect?
   - Do these match exactly? (This is the exact class of bug that caused v2.3.4, v2.3.7, v2.1.4)
   - Are there prompts that tell the LLM to write files that aren't in `expected_artifacts`?
   - Are there `expected_artifacts` that no prompt tells the LLM to write?

5. **Cross-prompt consistency**: For concepts that appear in multiple prompts:
   - Finding ID format: does every prompt that references finding IDs use the same format?
   - Severity levels: does every prompt use the same severity names and ordering?
   - File naming conventions: do prompts agree on artifact filenames?
   - Read-before-write: does every prompt tell agents to read prerequisites?
   - Scope containment: does every breadth/depth prompt end with the scope containment directive?

6. **Prompt size and context budget**: For each phase, compute:
   - V1 section size + V2 template size + injected skills + injected context = total prompt tokens (estimate)
   - Does any phase exceed estimated context limits for its assigned model?
   - Thorough mode bonus: how much extra content gets injected?
   - Skill injection: how many skills can stack on a single breadth agent before context saturation?

**Output format**: Same structure, category = EXTRACTION_BUG | PLACEHOLDER_GAP | ISOLATION_LEAK | ARTIFACT_MISMATCH | CROSS_PROMPT_DRIFT | CONTEXT_BUDGET

---

### SUBAGENT 5: Phase Definitions & Graph

**Scope**: `plamen_types.py` — phase definitions, dependencies, timeouts, critical flags, model assignments, mode conditions

**Read**: `plamen_types.py` (full), `orchestrator-rules.md` (AUDIT MODES table)

**Audit dimensions**:

1. **Phase graph completeness**: Extract the complete phase ordering for each mode (light/core/thorough) × pipeline (sc/l1). For each:
   - Is every phase reachable?
   - Are dependencies correct (does phase B depend on phase A's artifacts)?
   - Are there phases that should be conditional (mode-dependent) but are always-on?
   - Are there phases that should be always-on but are conditional?
   - Does the graph match the documented ordering in orchestrator-rules.md?

2. **Timeout analysis**: For each phase:
   - What is `base_timeout_s`?
   - How does `scale_timeout()` modify it?
   - What is the ACTUAL timeout for a typical codebase (500 LOC, 5000 LOC, 50000 LOC)?
   - Which phases have historically timed out (check MEMORY.md entries)?
   - Are there phases where the timeout is clearly too short or too long?
   - Does hypothesis-count scaling (+90s/hyp above 8) apply correctly?

3. **Model assignment correctness**: For each phase × mode:
   - What model is assigned?
   - Does it match the AUDIT MODES table in orchestrator-rules.md?
   - Are there phases where the model changes between modes but shouldn't (or vice versa)?
   - Does `phase_model()` correctly resolve aliases?

4. **Critical flag audit**: For each phase:
   - Is it marked `critical=True`?
   - What happens downstream if this phase degrades?
   - Are there phases marked critical that could reasonably degrade without blocking the pipeline?
   - Are there phases NOT marked critical that would actually block downstream phases?
   - Does the phase containment logic (v2.3.14) correctly handle non-critical phases?

5. **Expected artifacts accuracy**: For each phase:
   - What are the expected artifacts (glob patterns)?
   - Are the patterns specific enough (won't match wrong files)?
   - Are the patterns broad enough (won't miss valid output from the LLM)?
   - Do `example_tokens` match the actual output filenames?
   - Is `min_artifact_size_bytes` appropriate (100 bytes default — too low? too high?)?

6. **Shard/chunk phases**: For sharded phases (inventory_chunk_a/b/c, verify_batch_*, report_tier_*):
   - How is the shard count determined?
   - What happens when a shard has 0 items to process?
   - What happens when ALL shards fail?
   - Is there a mechanical fallback for empty-shard scenarios?

**Output format**: Same structure, category = GRAPH_GAP | TIMEOUT | MODEL_MISMATCH | CRITICAL_FLAG | ARTIFACT_PATTERN | SHARD_LOGIC

---

### SUBAGENT 6: Mechanical Transforms & Algorithms

**Scope**: `plamen_mechanical.py` — sharding, dedup, graph artifacts, inventory merge, deterministic transforms

**Read**: `plamen_mechanical.py` (full), `plamen_types.py` (evidence/severity enums)

**Audit dimensions**:

1. **Inventory sharding algorithm**: `ensure_inventory_shard_plan()`:
   - Signal density counting: are finding ID patterns and code block counts accurate?
   - `target_per_shard=70`: is this empirically validated? What happens with 0 signals? 500 signals?
   - Shard assignment: is the algorithm stable (same input → same output)?
   - Edge cases: 0 source files, 1 source file, files with 0 signals, all signals in one file

2. **Semantic dedup algorithm**: 
   - Title overlap scoring: is it case-sensitive? Does it handle punctuation?
   - Location overlap detection: does it work across different location formats (`file:L42` vs `file:42` vs `file:L42-L50`)?
   - Function-name extraction: regex-based — does it handle all naming conventions?
   - O(n²) pair reduction: is there a ceiling? What happens with 200 findings (200²=40K pairs)?
   - Merge correctness: when two findings merge, is severity inheritance correct?

3. **Graph artifact generation**: `caller_map.md`, `callee_map.md`, `state_write_map.md`, `function_summary.md`:
   - Are these generated for ALL languages or only some?
   - Are they consumed by downstream phases?
   - Is the format stable (column ordering, separators)?
   - What happens if the source code is too large to process?

4. **Report assembly** (`report_assemble.py` or mechanical report assembly):
   - Tier file concatenation: is ordering preserved?
   - Section deduplication: does it handle duplicate section headers?
   - Internal ID stripping: does it catch all formats?
   - Summary count computation: does it match actual section counts?
   - Does it handle missing tier files (empty tier)?

5. **PoC classification** (the v2.4.0 bidirectional classifier):
   - Evidence tag extraction: does it catch all tag formats?
   - Harm test vs mechanism test distinction: is it codified or heuristic?
   - Demotion rules: are they correctly applied per poc_class?
   - Interaction with verify file parsing: does it correctly pair tags with findings?

6. **Determinism audit**: For every function that transforms data:
   - Is the output deterministic (same input → same output)?
   - Are there hidden dependencies on file system ordering, dict ordering, or time?
   - Are there floating-point operations that could produce platform-dependent results?
   - Does `set()` usage anywhere affect output ordering?

**Output format**: Same structure, category = SHARDING | DEDUP | GRAPH | REPORT_ASSEMBLE | POC_CLASS | NONDETERMINISM

---

### SUBAGENT 7: Cross-Language Parity

**Scope**: 6 language trees (evm, solana, aptos, sui, soroban, daml) + L1 — check for drift, missing ports, inconsistencies

**Read**: For each tree, read: `phase1-recon-prompt.md`, `phase4a-inventory-prompt.md`, `phase4b-depth-templates.md`, `phase4b-scanner-templates.md`, `phase5-verification-prompt.md`, `generic-security-rules.md`, `self-check-checklists.md`. Also read the `v2/` variants where they exist.

**Audit dimensions**:

1. **Feature parity matrix**: Build a table:
   | Feature | EVM | Solana | Aptos | Sui | Soroban | DAML | L1 |
   For each of: recon tasks, breadth methodology, scanner checks, depth directives, verification templates, fuzz support, invariant fuzz, Medusa, skill count, v2 prompt variants.
   Flag any feature present in one tree but missing from another where it should apply.

2. **Scanner check alignment**: Extract all scanner checks from each tree's `phase4b-scanner-templates.md`. For each check:
   - Is the check concept universal (should exist in all trees)?
   - Is the check concept language-specific (correctly absent from other trees)?
   - If universal: is the implementation consistent across trees (same check number, same methodology)?
   - Are there checks with the same number but different content across trees?

3. **V1 vs V2 prompt parity**: Some trees have V2 prompt variants (in `{lang}/v2/`), some don't. For those that do:
   - Does the V2 variant supersede or supplement the V1 variant?
   - Which prompt does the driver actually use for each phase?
   - Are there V2 variants that are never loaded?

4. **Depth template consistency**: Compare depth template directives across trees:
   - §STEP-TRACE directive: present in all trees? Same format?
   - INVARIANT CONSISTENCY CHECK: same logic?
   - Chain Summary output format: same structure?
   - Evidence tag expectations: same tags?

5. **Skill count and trigger consistency**: From `skill-index.md`, verify:
   - Are all skills listed actually present on disk?
   - Are there skills on disk not listed in the index?
   - Do trigger patterns match between the index and the SKILL.md files?
   - Are trigger flags consistently named across trees (e.g., `ORACLE` in EVM vs Aptos)?

6. **Build/test command consistency**: From `phase5-poc-execution.md`:
   - Are the build commands correct for each ecosystem?
   - Are the fuzz commands correct?
   - Have any toolchain versions changed since these were written?

**Output format**: Same structure, category = MISSING_PORT | SCANNER_DRIFT | V1_V2_CONFLICT | DEPTH_DRIFT | SKILL_GAP | TOOLCHAIN

---

### SUBAGENT 8: Skill & Agent Definition Audit

**Scope**: 8 agent definitions, 140 skill files, 9 niche agents, 30 injectable skills

**Read**: All 8 agent definitions in `agents/`. Sample 20 skill files across trees. All 9 niche agent SKILLs. All non-L1 injectable SKILLs.

**Audit dimensions**:

1. **Trigger accuracy**: For each skill/niche/injectable:
   - Is the trigger pattern actually detectable by recon?
   - Could the trigger false-positive (trigger on irrelevant code)?
   - Could the trigger false-negative (miss relevant code)?
   - Are trigger flags consistently named between recon output and skill definitions?

2. **Injection target correctness**: For injectable skills:
   - Does the skill append to the correct agent type?
   - Could injecting the skill exceed the agent's context budget?
   - Are there combinatorial explosions (5 injectables × 1 agent = too much)?
   - Does the merge hierarchy (M4/M5) correctly prioritize?

3. **Niche agent scope boundaries**: For niche agents:
   - Does the agent's output filename match what the pipeline expects?
   - Does the agent read the correct input artifacts?
   - Does the agent stay within its scope (doesn't duplicate depth agent work)?
   - Is the budget cost (1 slot) correctly accounted for in the depth budget formula?

4. **Depth agent completeness**: For the 4 standard depth agents (token-flow, state-trace, edge-case, external):
   - Is each agent's scope clearly defined and non-overlapping?
   - Are there vulnerability classes that fall between agents (no agent covers them)?
   - Does each agent produce the expected output structure (Chain Summary, finding format)?
   - Are the L1 depth agents (consensus-invariant, network-surface) well-defined?

5. **Skill overlap audit**: Across all skills:
   - Are there skills with >60% methodology overlap?
   - Are there skills that should be consolidated?
   - Are there skills that reference concepts not relevant to their language tree?
   - Post-audit-improvement-protocol anti-bloat gates: are they being followed?

6. **Agent model assignment**: For each agent role:
   - What model is assigned in each mode?
   - Is the assignment optimal (opus for complex reasoning, sonnet for discovery, haiku for mechanical)?
   - Are there agents running on opus that could run on sonnet without quality loss?
   - Are there agents on haiku that should be on sonnet (haiku rejects complex schemas)?

**Output format**: Same structure, category = TRIGGER_ERROR | INJECTION_BUG | SCOPE_OVERLAP | DEPTH_GAP | SKILL_BLOAT | MODEL_ASSIGNMENT

---

### SUBAGENT 9: Report Pipeline & ID System

**Scope**: Phase 6 (report generation), `report-template.md`, `phase6-report-prompts.md`, V2 report templates, ID system end-to-end

**Read**: `report-template.md`, `phase6-report-prompts.md`, `phase6a-report-index.md`, `phase6b-tier-writers.md`, `phase6c-assembler.md`, `plamen_mechanical.py` (report_assemble sections)

**Audit dimensions**:

1. **ID system end-to-end trace**: Trace finding IDs from creation to report:
   - Breadth: `[CS-1]`, `[AC-1]`, `[TF-1]` → inventory: internal format → hypotheses: `H-N` → chains: `CH-N` → report: `C-01`/`H-01`/`M-01`/`L-01`/`I-01`
   - At each boundary: what parser converts? What regex matches? What can break?
   - Find every regex in the codebase that matches internal IDs. Do they all use the same pattern?
   - What happens if a new ID prefix is introduced (e.g., a new agent creates `[FOO-1]`)?

2. **Report index completeness**: The Index Agent must map EVERY hypothesis + standalone finding to a report ID.
   - What completeness checks exist?
   - What happens if a finding exists in inventory but not in hypotheses?
   - What happens if a chain hypothesis references a finding that was excluded?
   - How does consolidation (STEP 1.5) interact with completeness counting?

3. **Tier writer scoping**: Each tier writer receives only its assigned findings.
   - How is the assignment communicated (report_index.md parsing)?
   - What happens if the tier assignment format changes?
   - What happens if a finding is assigned to no tier?
   - What happens if a finding is assigned to two tiers?
   - Does the chunk scoping (driver-imposed sharding) correctly partition without gaps?

4. **Report quality gate**: The assembler and post-assembly validators check:
   - Finding count vs summary table
   - Internal ID leakage
   - Cross-reference validity
   - Section minimum length (400 chars)
   - Control character stripping
   
   For each check: is it mechanical (Python) or LLM-based? If LLM-based, can it be made mechanical? What false positives/negatives does each check produce?

5. **Severity adjustment pipeline**: Multiple adjustments can stack:
   - Trust assumption downgrade (`TRUSTED-ACTOR` → -1)
   - Proven-only demotion (`CODE-TRACE` only → cap at Low)
   - UNRESOLVED/PARTIAL visibility (no automatic tier change; separate typed adjudication only)
   - PoC-fail proposal (from `poc_demotion_proposals.json`; MUST NOT lower severity or dispose of the candidate)
   - Chain upgrade (postcondition enables precondition → upgrade)
   
   Can these stack in contradictory ways? What's the precedence? Can a finding be both upgraded and downgraded? Is there a minimum severity floor?

6. **Appendix A correctness**: The excluded findings table:
   - Does it capture ALL excluded findings (not just some)?
   - Does it include the reason for exclusion?
   - Does the traceability table correctly map report IDs to internal IDs?
   - Is the traceability table visible in client-facing reports (it shouldn't be)?

**Output format**: Same structure, category = ID_SYSTEM | COMPLETENESS | TIER_SCOPE | QUALITY_GATE | SEVERITY_STACK | APPENDIX

---

### SUBAGENT 10: Test Coverage & Regression Gaps

**Scope**: 36 test files (~22K LOC) — what's tested, what's not, regression protection

**Read**: All test_*.py file headers and test function names (use grep for `def test_`). Read full content of: `test_driver_failure_scenarios.py`, `test_pipeline_contracts.py`, `test_driver_helpers.py`, `test_structural_integrity.py`

**Audit dimensions**:

1. **Coverage map**: Build a table:
   | Python module | Functions | Tested functions | Coverage % |
   For each module, list functions that have ZERO test coverage. Prioritize by risk: untested functions in the driver's main loop and validators are P0 gaps.

2. **Regression test inventory**: For each version in MEMORY.md (v2.0.0 through v2.6.1):
   - Was a regression test added?
   - Does the test actually exercise the bug that was fixed?
   - Could the bug recur without failing the test?
   - Are there tests that test implementation details rather than behavior?

3. **Test quality audit**: For each test file:
   - Are assertions specific (not `assertTrue(result)` but `assertEqual(result, expected)`)?
   - Are edge cases tested (empty input, None, malformed data, boundary values)?
   - Are error paths tested (not just happy paths)?
   - Do tests use mocking appropriately (not mocking what they should test)?
   - Are tests independent (no ordering dependencies)?

4. **Missing test categories**: Identify gaps:
   - End-to-end: is there a test that runs the full pipeline (even on a trivial codebase)?
   - Checkpoint: is save/load/resume tested?
   - Cross-platform: are Windows-specific paths tested?
   - Interactive prompts: are the TUI functions tested?
   - Subprocess launch: is the actual `claude -p` invocation tested (or just the prompt building)?
   - Report assembly: is the mechanical assembler tested?

5. **Test-to-code ratio analysis**: 
   - `plamen_validators.py` (6988 lines) — how many test lines?
   - `plamen_parsers.py` (4094 lines) — how many test lines?
   - `plamen_driver.py` (2612 lines) — how many test lines?
   - Are the most complex modules also the most tested?

6. **Flaky test detection**: Are there tests that:
   - Depend on file system state or ordering?
   - Use `time.sleep()` or time-dependent assertions?
   - Depend on network access?
   - Could pass on one platform but fail on another?
   - Use random data without fixed seeds?

**Output format**: Same structure, category = COVERAGE_GAP | REGRESSION_GAP | TEST_QUALITY | MISSING_CATEGORY | RATIO_IMBALANCE | FLAKY

---

## Orchestrator Merge Logic

After all 10 subagents return:

1. **Read** all `audit_{domain}.md` files
2. **Deduplicate**: If two subagents found the same issue (e.g., ARCH-3 and PROMPT-7 both flag the same SSOT violation), merge under the more specific finding
3. **Classify** by fix class:
   - **DELETE**: Dead code, unused features, redundant checks → simplest fix, do first
   - **CONSOLIDATE**: SSOT violations, cross-tree drift, skill overlap → reduces surface area
   - **RESTRUCTURE**: Architecture issues, module boundaries, layering → highest impact, most risk
   - **HARDEN**: Gate fragility, regex gaps, vacuous passes → prevents future regressions
   - **DOCUMENT**: Configuration sprawl, implicit contracts → aids maintenance
4. **Prioritize** within each class: P0 > P1 > P2
5. **Write** `pipeline_audit_master.md` with:
   - Executive summary (metrics: total findings, P0/P1/P2 counts, fix class distribution)
   - Prioritized problem list grouped by fix class
   - Architectural recommendations (systemic fixes, not point patches)
   - Estimated effort per fix (trivial/small/medium/large)
   - Dependencies between fixes (which must come first)

---

## Anti-Patterns This Audit Must Detect

These are the systemic failure modes that 40+ versions of patching have revealed. If the audit finds instances, they are P0:

1. **Regex-as-contract**: Using regex to parse LLM output that has no enforced format. Every regex is a bet that the LLM will format consistently. The audit should find every such bet and ask: can this be made format-agnostic, or can the format be mechanically enforced?

2. **Gate-on-gate collision**: Two validation gates that individually pass but together create an impossible requirement (v2.3.1 class: step-trace gate rejected coverage-fill agents). The audit should find all gate pairs that could conflict.

3. **Filename nondeterminism**: The LLM writes `depth_perturbation_findings.md`, the gate expects `perturbation_findings.md` (v2.3.4 class). Every expected_artifacts pattern should be tested against the actual filenames the prompt tells the LLM to write.

4. **Silent vacuous pass**: A gate checks 0 items and returns "all passed" (v2.3.5 class). Every gate should distinguish "0 violations in N items" from "0 items checked."

5. **Configuration amnesia**: A value is defined in 3 places, changed in 1, and the other 2 are now wrong. Every multiply-defined value should be traced to its canonical source.

6. **Implicit format contracts**: Parser A writes data in format X. Parser B reads it assuming format X. Neither documents format X. A V2 update changes A's output, B breaks silently. Every parser-consumer pair should have an explicit contract.

7. **Context-budget blindness**: A phase's prompt + injected context exceeds the model's effective context window. The LLM truncates silently. There is no detection mechanism. Every phase should have an estimated token budget and a warning threshold.

8. **Recovery path asymmetry**: The happy path is well-tested. The recovery path (retry, degrade, resume) is not. Every recovery path should be traced to verify it returns to a valid state.
