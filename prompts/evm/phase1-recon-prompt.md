# Phase 1: Recon Agent Prompt Template

> **Usage**: Orchestrator reads this file and spawns recon agents with these prompts.
> Replace `{path}`, `{scratchpad}`, `{docs_path_or_url_if_provided}`, `{network_if_provided}`, `{scope_file_if_provided}`, `{scope_notes_if_provided}` with actual values. Omit lines for empty placeholders.
>
> **ORCHESTRATOR SPLIT DIRECTIVE**: Do NOT spawn a single monolithic recon agent.
> Split into **4 parallel agents** to prevent timeout (confirmed failure on 22-contract projects):
>
> | Agent | Tasks | Model | Why Separate |
> |-------|-------|-------|-------------|
> | **1A: RAG-only** | TASK 0 steps 1-5 (vuln-db + Solodit) | **sonnet** | MCP calls can be slow; isolate from file I/O. Sonnet sufficient - mechanical query+format task. |
> | **1B: Docs + External + Fork** | TASK 0 step 6 (fork ancestry), TASK 3, TASK 11 | opus | Tavily web search can hang; separate from RAG |
> | **2: Build + Slither + Tests** | TASK 1, 2, 8, 9 | **sonnet** | Build/compile is blocking; Slither is fail-fast. Sonnet sufficient - tool execution + output formatting. |
> | **3: Patterns + Surface + Templates** | TASK 4, 5, 6, 7, 10 | opus | Pure codebase analysis, no external deps. Opus needed - attack surface + template selection requires reasoning. |
>
> **CRITICAL - RAG TIMEOUT POLICY (v9.9.6)**:
> Agent 1A is **FIRE-AND-FORGET**. The orchestrator MUST NOT block on Agent 1A completion.
> - Spawn Agent 1A with `run_in_background: true`
> - **DO NOT await Agent 1A** before proceeding to Phase 2. Wait ONLY for Agents 1B, 2, and 3.
> - After Agents 1B/2/3 complete, check Agent 1A status:
>   - If complete → read its `meta_buffer.md` output
>   - If still running → **ABANDON IT**. Write a minimal empty `meta_buffer.md` with `# Meta-Buffer\n## RAG: UNAVAILABLE - agent timed out\nPhase 4b.5 RAG Validation Sweep will compensate.`
> - **Rationale**: RAG MCP calls (unified-vuln-db, Solodit) can hang indefinitely (observed: 100+ minutes with 0 output). The pipeline's real RAG safety net is Phase 4b.5 (RAG Validation Sweep), which runs after depth analysis when the pipeline has time budget. Early RAG is nice-to-have, not blocking.
>
> Agent 1A writes: `meta_buffer.md`
> Agent 1B writes: `design_context.md`, `external_production_behavior.md`, fork section of `meta_buffer.md`
> Agent 2 writes: `build_status.md`, `function_list.md`, `call_graph.md`, `state_variables.md`, `modifiers.md`, `event_definitions.md`, `external_interfaces.md`, `static_analysis.md`, `test_results.md`
> Agent 3 writes: `contract_inventory.md`, `attack_surface.md`, `detected_patterns.md`, `setter_list.md`, `emit_list.md`, `constraint_variables.md`, `template_recommendations.md`
> Orchestrator writes: `recon_summary.md` (after Agents 1B, 2, 3 complete - NOT waiting for 1A)

```
Task(subagent_type="general-purpose", prompt="
You are the Reconnaissance Agent. Gather ALL information needed for the security audit.

PROJECT_PATH: {path}
SCRATCHPAD: {scratchpad}
DOCUMENTATION: {docs_path_or_url_if_provided}
NETWORK: {network_if_provided}
SCOPE_FILE: {scope_file_if_provided}
SCOPE_NOTES: {scope_notes_if_provided}

## RESILIENCE RULES (apply to ALL tasks)
1. **MCP call fails/times out?** → Document the failure in the relevant output file and CONTINUE to the next task. Never retry more than once.
2. **Web search (Tavily/Solodit) fails?** → Note "UNAVAILABLE - web search failed" in output and CONTINUE. Analysis agents will compensate.
3. **Write-first principle**: Before making any slow external call (MCP, web), write whatever results you already have to the scratchpad file FIRST. This ensures partial results survive if the agent is killed.
4. **No task is blocking**: If any task is stuck, skip it, document why, and move to the next. Partial recon is better than no recon.

Execute these tasks IN ORDER:

## TASK 0: RAG Meta-Buffer Retrieval

### Step 1: Classify Protocol Type

| Protocol Type | Key Indicators | Query |
|---------------|----------------|-------|
| staking | stake, unstake, validator, delegation, shares | `get_common_vulnerabilities(protocol_type='staking')` |
| lending | borrow, lend, collateral, liquidation | `get_common_vulnerabilities(protocol_type='lending')` |
| dex | swap, liquidity, pool, reserves | `get_common_vulnerabilities(protocol_type='dex')` |
| vault/erc4626 | deposit, withdraw, shares, strategy | `get_common_vulnerabilities(protocol_type='vault')` |
| bridge | L1, L2, tunnel, message, relay | `get_common_vulnerabilities(protocol_type='bridge')` |
| governance | vote, propose, timelock, quorum | `get_common_vulnerabilities(protocol_type='governance')` |

### Step 2: Query unified-vuln-db for attack patterns

> **PROBE FIRST**: Before batch calls, make ONE probe call to detect MCP schema incompatibility:
> `mcp__unified-vuln-db__get_knowledge_stats()`
> - If probe **succeeds** → set `RAG_TOOLS_AVAILABLE = true`, proceed with batches below
> - If probe **fails** (API error, schema error, timeout) → set `RAG_TOOLS_AVAILABLE = false`, **skip ALL unified-vuln-db calls**, append to `{SCRATCHPAD}/build_status.md`: `RAG_TOOLS_AVAILABLE: false - unified-vuln-db MCP probe failed: {error}. Phase 4b.5 RAG Sweep will use WebSearch fallback.`
> - If probe succeeds, also append: `RAG_TOOLS_AVAILABLE: true`

> **PARALLELIZATION DIRECTIVE**: Make MCP calls in PARALLEL batches, not sequentially.
> **Batch 1** (single message, all in parallel): calls 1-3 below.
> **Batch 2** (single message, all in parallel): calls 4-5 below.
> Do NOT wait for Batch 1 results before starting Batch 2 unless results from Batch 1 determine Batch 2 parameters.

**If RAG_TOOLS_AVAILABLE = false**: Skip Batch 1 and Batch 2 entirely. Write to `{SCRATCHPAD}/meta_buffer.md`: `## RAG: UNAVAILABLE - MCP tools failed probe. Phase 4b.5 will compensate.`

**Batch 1** - call ALL of these in a single message:
1. mcp__unified-vuln-db__get_common_vulnerabilities(protocol_type='{TYPE}')
2. mcp__unified-vuln-db__get_attack_vectors(bug_class='{relevant pattern}')
   → For each external dependency (e.g., 'staking receipt donation', 'cross-chain timing')
3. mcp__unified-vuln-db__get_root_cause_analysis(bug_class='{detected pattern}')

**Batch 2** - call ALL of these in a single message:
4. **MANDATORY**: mcp__unified-vuln-db__search_solodit_live(protocol_category=['{DeFi/Bridge/etc.}'], tags=['{relevant}'], language='Solidity', quality_score=3, sort_by='Quality', max_results=20)
5. If SEMI_TRUSTED_ROLE detected: search_solodit_live(keywords='reward compound timing front-run keeper', impact=['HIGH','MEDIUM'], max_results=15)

### Step 6: Fork Ancestry Research
Read ~/.claude/agents/skills/evm/fork-ancestry/SKILL.md and execute all 4 steps:
1. Detect fork indicators (grep for known parent signatures)
2. Query known parent issues via Solodit + Tavily
3. Analyze divergences between fork and parent
4. Append results to {SCRATCHPAD}/meta_buffer.md under "## Fork Ancestry Analysis"

> **SKIP POLICY**: If Tavily or Solodit calls fail in step 2, write "Fork ancestry: web search unavailable - manual review needed" and continue to step 3 using only code-level divergence analysis.

### Step 3: Synthesize into {SCRATCHPAD}/meta_buffer.md

Use this output format:
```markdown
# Meta-Buffer: {PROTOCOL_NAME} ({PROTOCOL_TYPE})
## Protocol Classification
- **Type**: {protocol_type}
- **Key Indicators**: {what patterns led to classification}
## Common Vulnerabilities for {PROTOCOL_TYPE}
| Category | Frequency | Key Functions to Check |
## Attack Vectors for External Dependencies
### {DEP_NAME}
- **Bug Class**: {relevant bug class}
- **Attack Steps**: {from get_attack_vectors}
## Root Cause Analysis
### {BUG_CLASS}
- **Why This Happens**: {root cause}
- **What to Look For**: {methodology hints}
## Questions for Analysis Agents
1. {question derived from common vulnerabilities}
2. {question derived from attack vectors}
## Timing-Sensitive Operations (if SEMI_TRUSTED_ROLE detected)
| Operation | Timing Pattern | User Exploitation Vector | RAG Matches |
## Code Patterns to Grep
- `{pattern}` - related to {vulnerability class}
```

## TASK 1: Build Environment

> **PATH note**: On Windows, `forge`/`anvil`/`cast` may not be in Claude Code's default PATH. Prefix Bash calls with: `export PATH="$HOME/.foundry/bin:$HOME/.cargo/bin:$PATH" &&` if `forge` is not found on first attempt.

1. Check for foundry.toml or hardhat.config.js
2. If Hardhat only: create minimal foundry.toml scaffold
3. Run `npm install` or `yarn` if needed
3b. **Dependency Recovery** (before first build attempt):
   - Run `git submodule update --init --recursive` (resolves lib/ dependencies)
   - If lib/ directory is missing or empty after submodule update: run `forge install`
   - Install forge-std if not present: `forge install foundry-rs/forge-std --no-git`
4. Run `forge build`
5. If build fails: read error output, apply targeted fix from this recovery ladder:
   - **Missing import/dependency** → `forge install {dep} --no-git` (extract dep name from error)
   - **Remapping error** → Verify remappings.txt against lib/ subdirectories, auto-generate if missing
   - **Compiler version mismatch** → Check pragma, run `forge build --use {required_version}`
   - **Stack too deep** → Add `--via-ir` flag to foundry.toml `[profile.default]`
   - **Interface mismatch / abstract contract** → May need stub implementation, document and skip
   Retry after each fix (max 5 attempts total, was 3)
6. If build fails after 5 attempts, document failure reason and continue
7. Probe Medusa availability: run `medusa --version`. If available, record version. If not found, record unavailable.

Write build result to {SCRATCHPAD}/build_status.md
Include: `MEDUSA_AVAILABLE: true/false` (and version if available)

## TASK 2: Static Analysis Artifacts

### Slither Fail-Fast Policy
Slither can crash on projects with namespace imports (`import X as Y`), mixed compiler versions, or unusual AST structures. Do NOT retry endlessly.

**Procedure**:
1. Make ONE probe call: `mcp__slither-analyzer__list_contracts(path={path})`
2. If the probe **succeeds** → proceed with all MCP calls below
3. If the probe **fails** (error, timeout, crash) → set `SLITHER_AVAILABLE = false`, skip ALL remaining MCP Slither calls, jump directly to **grep fallback** below
4. If any subsequent MCP call fails after probe succeeded → skip remaining MCP calls, use grep fallback for what's left

**If SLITHER_AVAILABLE = true**, call MCP tools:
- mcp__slither-analyzer__list_functions → {SCRATCHPAD}/function_list.md
- mcp__slither-analyzer__export_call_graph → {SCRATCHPAD}/call_graph.md
- mcp__slither-analyzer__analyze_state_variables → {SCRATCHPAD}/state_variables.md
- mcp__slither-analyzer__analyze_modifiers → {SCRATCHPAD}/modifiers.md
- mcp__slither-analyzer__analyze_events → {SCRATCHPAD}/event_definitions.md

**If SLITHER_AVAILABLE = false**, use grep fallback (ALL of these):
- Grep `function ` in all .sol files (exclude mocks/, node_modules/) → {SCRATCHPAD}/function_list.md
- Grep `modifier ` → {SCRATCHPAD}/modifiers.md
- Grep `event ` → {SCRATCHPAD}/event_definitions.md
- Grep state variable declarations → {SCRATCHPAD}/state_variables.md
- Note "Call graph unavailable - Slither failed" in {SCRATCHPAD}/call_graph.md
- Append to {SCRATCHPAD}/build_status.md: "SLITHER: UNAVAILABLE - {error message}. Grep fallback used. Depth agents must compensate for missing static analysis."

**Farofino fallback**: When SLITHER_AVAILABLE = false, also run:
- mcp__farofino__aderyn_audit(contract_path={path_with_forward_slashes}) → append results to {SCRATCHPAD}/static_analysis.md under "## Aderyn Static Analysis"
- mcp__farofino__pattern_analysis(contract_path={path_with_forward_slashes}) → append results to {SCRATCHPAD}/static_analysis.md under "## Pattern Analysis"

**CRITICAL (Windows)**: The `contract_path` parameter MUST use forward slashes only.
If `{path}` contains backslashes, convert them: `D:\foo\bar` → `D:/foo/bar`.
Farofino's contract resolution fails with backslash paths on Windows.

If farofino tools also fail, document and continue with grep-only fallback.

Grep interfaces directory → {SCRATCHPAD}/external_interfaces.md (always, regardless of Slither status)

## TASK 3: Documentation Context
1. Read README.md, docs/ folder, or fetch provided URL
2. Extract: protocol purpose, key invariants, trust model, external dependencies
3. If no docs: note 'Inferring purpose from code'
4. **Trust Assumption Table** (MANDATORY): From ASSUMPTIONS.txt, docs, README, code comments, and access control patterns, extract ALL trust assumptions into a structured table in design_context.md:

| # | Actor | Trust Level | Assumption | Source |
|---|-------|-------------|------------|--------|
| 1 | {role} | FULLY_TRUSTED | Will not act maliciously | {source} |
| 2 | {role} | SEMI_TRUSTED(bounds: {on-chain limit}) | Cannot exceed {stated bounds} | {source} |
| 3 | - | PRECONDITION | {config state assumed at launch} | {source} |

Trust levels: `FULLY_TRUSTED` (will not act maliciously - e.g., multisig, governance, DAO), `SEMI_TRUSTED(bounds: ...)` (bounded by on-chain parameters), `PRECONDITION` (deployment/config state assumption), `UNTRUSTED` (default for users, external contracts).
If no explicit trust documentation exists, infer from access control patterns (onlyOwner, role modifiers, multisig references) and note `Source: inferred`.

Write to {SCRATCHPAD}/design_context.md

## TASK 4: Contract Inventory
1. Run `wc -l` on all .sol files (exclude lib/, node_modules/)
2. List contracts with line counts
3. **Scope filtering**: If SCOPE_FILE is set, read it and mark contracts as IN_SCOPE or OUT_OF_SCOPE accordingly. Only IN_SCOPE contracts are primary audit targets. If SCOPE_NOTES is set, use them to further refine scope (e.g., "focus on vault module" → prioritize vault-related contracts). If neither is set, all non-library contracts are in scope.
4. **Inheritance chain analysis**: For each contract, extract its `is` clause. Build a dependency tree:
   - Identify parent contracts that are NOT in scope but ARE inherited by in-scope contracts
   - For each such parent: check if it contains conditional logic (if/else, modifiers with conditions) or virtual functions that child contracts override
   - Flag parents with conditional logic as `PARENT_CONDITIONAL_OVERRIDE` - these require standalone analysis because child behavior depends on parent branch paths that breadth agents may not trace
5. **Parent standalone flag**: If any `PARENT_CONDITIONAL_OVERRIDE` parents exist, list them with:
   | Parent Contract | Path | In Scope? | Overridden By | Conditional Logic? | Flag |
Write to {SCRATCHPAD}/contract_inventory.md

## TASK 5: Attack Surface Discovery
For EACH external dependency found in code:
1. Identity (name, interface, type: token/staking/bridge/oracle/etc.)
2. Interaction points (functions called, locations)
3. Token nature (ERC20? Can be transferred to protocol unsolicited?)
4. Return-value tokens (Does calling this return transferable tokens?)
5. Side effects (auto-claimed rewards, state changes)
6. State coupling (what protocol state depends on this)

Create Token Flow Matrix:
| Token | Type | Entry Functions | State Tracking | Accounting Queries Affected? | Unsolicited Transfer? | Side-Effect? | Return-Value? |

For **Accounting Queries Affected?**: List ALL protocol queries whose return value changes if this token is transferred unsolicited - not just `balanceOf(this)` but also delegation queries, staking queries, share balance queries, reward queries, etc.
For **Unsolicited Transfer?**: Can this token be sent to the protocol contract without calling any protocol function? (direct ERC20 transfer, staking on behalf of, delegation to)

### Signal Elevation Tags

During attack surface analysis, tag risk signals that warrant explicit follow-up with `[ELEVATE]`:

Apply `[ELEVATE]` when you observe:
- Proxy/upgradeable storage layout (delegatecall with storage slots) → `[ELEVATE:STORAGE_LAYOUT] Verify storage slot alignment across proxy and implementation`
- Single mapping entry per user (no nonce/epoch key) → `[ELEVATE:SINGLE_ENTRY] Analyze user-level DoS from single entry constraint`
- Fork ancestry match (Yearn, Compound, Aave pattern detected) → `[ELEVATE:FORK_ANCESTRY:{parent}] Verify known {parent} vulnerability classes addressed`
- Asymmetric branch sizes in profit/loss or deposit/withdraw logic → `[ELEVATE:BRANCH_ASYMMETRY] Verify state completeness in shorter branch (Rule 17)`
- MULTI_TOKEN_STANDARD detected AND function takes both token address + id parameter → `[ELEVATE:TYPE_DISCRIMINATOR] Verify all token operations in function branch on type, not just the primary one`
- `initialize()` without `initializer` modifier → `[ELEVATE:REINIT_RISK] Verify reinitialization protection`
- Assembly blocks (`assembly { }`) → `[ELEVATE:INLINE_ASSEMBLY] Verify memory safety and return data handling in assembly`

Write `[ELEVATE]` tags directly into the relevant section of `attack_surface.md`.

Write to {SCRATCHPAD}/attack_surface.md

## TASK 6: Pattern Detection
Grep for these patterns (exclude lib/, test/, mocks/):

| Pattern | Flag |
|---------|------|
| `interval\|epoch\|period\|duration` | TEMPORAL |
| `oracle\|latestRoundData\|TWAP\|chainlink` | ORACLE |
| `random\|keccak256.*block\|prevrandao\|VRF` | RANDOMNESS_WEAK_SOURCE |
| `keccak256.*%\|uint.*%.*length\|modulo\|select.*index\|pick.*winner` | RANDOMNESS_DETERMINISTIC_SELECTION |
| `flashLoan\|flash\|callback.*amount` | FLASH_LOAN |
| `IUniswapV2Router\|IUniswapV3Pool\|IBalancerVault\|swap.*token\|addLiquidity\|removeLiquidity\|getReserves\|IVault.*swap\|IPool.*swap` | FLASH_LOAN_EXTERNAL |
| `ERC4626\|vault\|deposit.*shares` | ERC4626 |
| `balanceOf.*this\|address.*balance` | BALANCE_DEPENDENT |
| `bridge\|L1\|L2\|tunnel\|messenger\|crossChain` | CROSS_CHAIN |
| `onlyBot\|onlyOperator\|onlyKeeper\|BOT_ROLE` | SEMI_TRUSTED_ROLE |
| `reinitializer\|V2\|V3\|_deprecated\|migrat\|upgrade\|legacy` | MIGRATION |
| `shares\|allocation\|distribute\|pro.rata\|proportional\|vest` | SHARE_ALLOCATION |
| `rate\|rebase\|supply\|mint.*burn\|emission\|inflation\|peg\|price.*cap\|price.*floor` | MONETARY_PARAMETER |
| `IERC6909\|ERC6909\|IERC1155\|ERC1155\|onERC1155Received` | MULTI_TOKEN_STANDARD |
| `ecrecover\|ECDSA.recover\|SignatureChecker\|isValidSignature\|EIP712\|domainSeparator\|_domainSeparatorV4\|permit(` | HAS_SIGNATURES |
| `_safeMint\|safeTransfer\|onERC721Received\|onERC1155Received\|tokensReceived\|onTransferReceived\|onFlashLoan\|executeOperation\|FlashCallback\|beforeSwap\|afterSwap` | OUTCOME_CALLBACK |
| `.call{value\|.call(\|.delegatecall(` targeting non-hardcoded address after state change | OUTCOME_CALLBACK_LOW_LEVEL |
| `deadline\|claimPeriod\|default.*selection\|fallback.*assign\|getDefault\|expir` AND time-gated with fallback path | OUTCOME_DELAY |

Write detected flags to {SCRATCHPAD}/detected_patterns.md

## TASK 7: Prep Artifacts
From function_list.md, extract:
- Setter/admin functions → {SCRATCHPAD}/setter_list.md
- Emit statements → {SCRATCHPAD}/emit_list.md
- min/max/cap/limit/rate/fee/threshold/factor/multiplier/ratio/weight/duration/delay/period variables → {SCRATCHPAD}/constraint_variables.md
  Mark ⚠️ UNENFORCED for variables with setters but no enforcement
- Permissionless public/external functions that emit events or modify shared state → append to {SCRATCHPAD}/setter_list.md under "## Permissionless State-Modifiers"

### Setter×Emit Cross-Reference (append to setter_list.md)
For each setter function in setter_list.md, check if it emits an event:
| Setter Function | Contract | Emits Event? | Event Name | Missing? |
If a setter modifies a parameter used in user-facing logic but emits NO event → flag as ⚠️ SILENT SETTER (potential monitoring blind spot, Info-level signal for report).

## TASK 8: Run Slither Detectors

**If SLITHER_AVAILABLE = true** (from TASK 2 probe):
Run: reentrancy-eth, reentrancy-no-eth, unchecked-transfer, divide-before-multiply,
     costly-loop, calls-loop, dead-code, unused-state

**If SLITHER_AVAILABLE = false**:
Skip Slither detectors entirely. Instead, run targeted grep checks:
- Grep for `.call{` or `.call(` after state changes (manual reentrancy check)
- Grep for `/ ` followed by `* ` on same variable (divide-before-multiply)
- Grep for loops containing `.length` on storage arrays (costly-loop)
- Grep for external calls inside loops (calls-loop)
Write grep results to {SCRATCHPAD}/static_analysis.md with header: "SLITHER UNAVAILABLE - grep-based fallback. Coverage is limited."

Also grep for unused struct fields (defined but never read) → append to static_analysis.md
Write to {SCRATCHPAD}/static_analysis.md

## TASK 9: Run Test Suite
Detect framework and run: `forge test` or `npx hardhat test`
If tests fail, note count and names at top of output as TEST HEALTH WARNING (Info-level signal).
Write to {SCRATCHPAD}/test_results.md

## TASK 10: Template Recommendations
Based on detected patterns and attack surface, recommend analysis templates.

For EACH recommended template, provide instantiation parameters:

### Template: [TEMPLATE_NAME]
**Trigger**: [what pattern triggered this]
**Relevance**: [why this matters for this protocol]
**Instantiation Parameters**:
- {PARAM_1}: [specific value from this protocol]
- {PARAM_2}: [specific value]
...
**Key Questions**:
1. [Protocol-specific question]
2. [Protocol-specific question]

Available templates (in ~/.claude/agents/skills/):
- CROSS_CHAIN_TIMING - for cross-chain messaging, rate sync
- STAKING_RECEIPT_TOKENS - for delegation/staking receipts
- SEMI_TRUSTED_ROLES - for BOT/OPERATOR/KEEPER analysis
- TOKEN_FLOW_TRACING - for balanceOf(this) dependencies
- ZERO_STATE_RETURN - for first depositor, empty state
- MIGRATION_ANALYSIS - for token migrations, V1/V2 upgrades, stranded assets
- TEMPORAL_PARAMETER_STALENESS - for cached parameters in multi-step operations
- EVENT_CORRECTNESS - for protocols with >15 events (optional, verify emit parameter accuracy)
- SHARE_ALLOCATION_FAIRNESS - for share/token allocation fairness, late-entry attacks, queue gaming
- FLASH_LOAN_INTERACTION - for flash loan attack modeling, atomic sequence analysis
- ORACLE_ANALYSIS - for oracle staleness, decimals, TWAP, failure modes
- ECONOMIC_DESIGN_AUDIT - for monetary parameter analysis, rate/emission sustainability
- EXTERNAL_PRECONDITION_AUDIT - for external contract interface-level precondition inference
- VERIFICATION_PROTOCOL - always used by verifiers

---

## BINDING MANIFEST (MANDATORY)

> **CRITICAL**: This manifest BINDS pattern detection to agent spawning. The orchestrator MUST spawn an agent for every template marked `Required: YES`.

After listing all recommended templates, output this binding manifest:

```markdown
## BINDING MANIFEST

| Template | Pattern Trigger | Required? | Reason |
|----------|-----------------|-----------|--------|
| SEMI_TRUSTED_ROLES | SEMI_TRUSTED_ROLE flag | {YES/NO} | {if YES: specific pattern found} |
| TOKEN_FLOW_TRACING | BALANCE_DEPENDENT flag | {YES/NO} | {if YES: balanceOf(this) count} |
| MIGRATION_ANALYSIS | MIGRATION flag | {YES/NO} | {if YES: patterns found} |
| CROSS_CHAIN_TIMING | CROSS_CHAIN flag | {YES/NO} | {if YES: bridge patterns} |
| STAKING_RECEIPT_TOKENS | Receipt token detected | {YES/NO} | {if YES: token type} |
| ZERO_STATE_RETURN | ERC4626/first-depositor pattern | {YES/NO} | {if YES: vault pattern} |
| TEMPORAL_PARAMETER_STALENESS | TEMPORAL flag | {YES/NO} | {if YES: multi-step ops with cached params} |
| EVENT_CORRECTNESS | >15 events in event_definitions.md | {YES/NO} | {if YES: event count} |
| SHARE_ALLOCATION_FAIRNESS | SHARE_ALLOCATION flag | {YES/NO} | {if YES: share/allocation pattern found} |
| FLASH_LOAN_INTERACTION | FLASH_LOAN flag | {YES/NO} | {if YES: flash loan patterns found} |
| FLASH_LOAN_INTERACTION | FLASH_LOAN_EXTERNAL flag | {YES/NO} | {if YES: external DEX/pool/vault interactions detected} |
| ORACLE_ANALYSIS | ORACLE flag | {YES/NO} | {if YES: oracle patterns found} |
| ECONOMIC_DESIGN_AUDIT | MONETARY_PARAMETER flag | {YES/NO} | {if YES: monetary parameter setters found} |
| EXTERNAL_PRECONDITION_AUDIT | External interactions detected | {YES/NO} | {if YES: external contract count} |

### Binding Rules
- SEMI_TRUSTED_ROLE flag detected → SEMI_TRUSTED_ROLES **REQUIRED**
- BALANCE_DEPENDENT flag detected → TOKEN_FLOW_TRACING **REQUIRED**
- MIGRATION flag detected → MIGRATION_ANALYSIS **REQUIRED**
- CROSS_CHAIN flag detected → CROSS_CHAIN_TIMING **REQUIRED**
- TEMPORAL flag detected → TEMPORAL_PARAMETER_STALENESS **REQUIRED**
- SHARE_ALLOCATION flag detected → SHARE_ALLOCATION_FAIRNESS **REQUIRED**
- FLASH_LOAN flag detected → FLASH_LOAN_INTERACTION **REQUIRED**
- FLASH_LOAN_EXTERNAL flag detected → FLASH_LOAN_INTERACTION **REQUIRED**
- ORACLE flag detected → ORACLE_ANALYSIS **REQUIRED**
- MONETARY_PARAMETER flag detected → ECONOMIC_DESIGN_AUDIT **REQUIRED**
- External interactions detected in attack_surface.md → EXTERNAL_PRECONDITION_AUDIT **REQUIRED**

### Niche Agent Binding Rules
- MISSING_EVENT flag detected (setter_list.md has MISSING EVENT entries OR emit_list.md shows state-changing functions without events) → EVENT_COMPLETENESS **niche agent** REQUIRED
- HAS_SIGNATURES flag detected (ecrecover/ECDSA.recover/permit/EIP712/domainSeparator/nonces/isValidSignature patterns found) → SIGNATURE_VERIFICATION_AUDIT **niche agent** REQUIRED
- HAS_MULTI_CONTRACT flag detected (2+ in-scope contracts AND constraint_variables.md shows shared parameters/formulas across contracts) → SEMANTIC_CONSISTENCY_AUDIT **niche agent** REQUIRED

### Niche Agents (Phase 4b - standalone focused agents, 1 budget slot each)

| Niche Agent | Trigger | Required? | Reason |
|-------------|---------|-----------|--------|
| EVENT_COMPLETENESS | MISSING_EVENT flag (setter_list.md / emit_list.md) | {YES/NO} | {if YES: N setters without events found} |
| SIGNATURE_VERIFICATION_AUDIT | HAS_SIGNATURES flag (detected_patterns.md) | {YES/NO} | {if YES: signature patterns found - ecrecover/ECDSA/permit/EIP712} |
| SEMANTIC_CONSISTENCY_AUDIT | HAS_MULTI_CONTRACT flag (contract_inventory.md + constraint_variables.md) | {YES/NO} | {if YES: N shared parameters/formulas across M contracts} |

### Manifest Summary
- **Total Required Breadth Agents**: {count of YES in skill templates}
- **Total Required Niche Agents**: {count of YES in niche agents}
- **Total Optional Agents**: {count of NO with recommendation}
- **HARD GATE**: Orchestrator MUST spawn agent for each REQUIRED template AND each REQUIRED niche agent
```

---

Write to {SCRATCHPAD}/template_recommendations.md

## TASK 11: External Contract Verification (MANDATORY)

> **SKIP POLICY**: Steps 2-3 and 5-6 depend on external calls (EVM chain data, farofino, tavily). If ANY external call fails, skip that step, document "UNAVAILABLE" for that dependency, and continue. The "addresses unavailable" fallback below covers this case. Do NOT let a failed ABI fetch block the entire task.

For EACH critical external contract:
1. **Find production address**: Search codebase for deployed addresses, configs, deployment scripts. If NETWORK is set, use it as the default network for all chain data queries. Otherwise infer from codebase (chainId, RPC URLs, deployment configs).
2. **Fetch ABI/source**: mcp__evm-chain-data__get_contract_abi(address, network=NETWORK) - **skip if call fails**
3. **Compare mock vs production**: For each function the protocol calls:
   | Function | Mock Behavior | Production Behavior | DIFFERS? |
4. **Document token transferability**: Can tokens be sent TO protocol unsolicited?
5. **Use farofino if Slither MCP fails**: mcp__farofino__read_contract as fallback - **skip if call fails**
6. **Use tavily for documentation**: mcp__tavily-search__tavily_search for protocol docs - **skip if call fails**

Write to {SCRATCHPAD}/external_production_behavior.md

**If addresses unavailable** (no deployed contracts found):
- Mark all external deps as 'UNVERIFIED' in attack_surface.md
- Add severity note: UNVERIFIED deps trigger Rule 4 (adversarial assumption)
- Analysis agents MUST NOT use mock behavior as evidence to REFUTE findings
- Verifiers MUST return CONTESTED (not REFUTED) for external dep related hypotheses
- **Severity floor**: UNVERIFIED external deps with HIGH worst-case → minimum MEDIUM

---

Write COMPLETE summary to {SCRATCHPAD}/recon_summary.md:
1. Build Status: [success/failed]
2. Contracts: [count] totaling [lines] lines
3. External Dependencies: [count] - [names]
4. Detected Patterns: [list flags]
5. Recommended Templates: [list with brief reason each]
6. Artifacts Written: [list all files]

Return: 'RECON COMPLETE: {N} contracts, {M} dependencies, {K} templates recommended, patterns: [flags]'
")
```

## After Recon Agent Returns

1. **Verify artifacts exist**: `ls {scratchpad}/` - must have all files
2. **Read summary**: `{scratchpad}/recon_summary.md` (small, safe to read)
3. **Read template recommendations**: `{scratchpad}/template_recommendations.md`
4. **Read attack surface**: `{scratchpad}/attack_surface.md`

**Hard gate**: ALL artifacts must exist before Phase 2.
