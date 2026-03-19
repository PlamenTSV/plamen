# Phase 1: Recon Agent Prompt Template - Aptos Move

> **Usage**: Orchestrator reads this file and spawns recon agents with these prompts for Aptos Move modules.
> Replace `{path}`, `{scratchpad}`, `{docs_path_or_url_if_provided}`, `{network_if_provided}`, `{scope_file_if_provided}`, `{scope_notes_if_provided}` with actual values. Omit lines for empty placeholders.
>
> **ORCHESTRATOR SPLIT DIRECTIVE**: Same 4-agent split as EVM/Solana to prevent timeout:
>
> | Agent | Model | Tasks | Why Separate |
> |-------|-------|-------|-------------|
> | **1A: RAG-only** | sonnet | TASK 0 steps 1-5 (vuln-db + Solodit) | Mechanical query+format - no deep reasoning needed |
> | **1B: Docs + External + Fork** | opus | TASK 0 step 6 (fork ancestry), TASK 3, TASK 11 | Tavily can hang; fork ancestry needs reasoning |
> | **2: Build + Static + Tests** | sonnet | TASK 1, 2, 8, 9 | Tool execution+output formatting - no deep reasoning needed |
> | **3: Patterns + Surface + Templates** | opus | TASK 4, 5, 6, 7, 10 | Pure codebase analysis, fast; pattern detection needs reasoning |
>
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

---

## Agent 1A: RAG-only

```
Task(subagent_type="general-purpose", prompt="
You are Recon Agent 1A (RAG-only) for an Aptos Move module audit.

PROJECT_PATH: {path}
SCRATCHPAD: {scratchpad}

## RESILIENCE RULES
1. **MCP call fails/times out?** -> Document the failure and CONTINUE. Never retry more than once.
2. **Write-first principle**: Write partial results before slow external calls.
3. **No task is blocking**: Skip stuck tasks, document why, move on.

## TASK 0: RAG Meta-Buffer Retrieval

### Step 1: Classify Protocol Type
Scan Move source files (*.move, excluding build/ and .aptos/) to determine protocol type:

| Protocol Type | Key Indicators | Query |
|---------------|----------------|-------|
| staking | stake, unstake, delegation, validator, delegation_pool, reward, tAPT, stAPT | `get_common_vulnerabilities(protocol_type='staking')` |
| lending | borrow, lend, collateral, liquidation, obligation, interest_rate, lending_market | `get_common_vulnerabilities(protocol_type='lending')` |
| dex | swap, liquidity, pool, reserves, amm, curve, router | `get_common_vulnerabilities(protocol_type='dex')` |
| vault | deposit, withdraw, shares, strategy, vault, receipt_token | `get_common_vulnerabilities(protocol_type='vault')` |
| bridge | bridge, wormhole, layerzero, relay, message, portal | `get_common_vulnerabilities(protocol_type='bridge')` |
| governance | vote, propose, timelock, quorum, dao, multisig, voting_escrow | `get_common_vulnerabilities(protocol_type='governance')` |
| gsm | gsm, stability, buy_asset, sell_asset, fee_strategy, move_dollar | `get_common_vulnerabilities(protocol_type='stablecoin')` |
| nft | collection, token_v2, digital_asset, mint_nft, royalty | `get_common_vulnerabilities(protocol_type='nft')` |

### Step 2: Query unified-vuln-db

> **PROBE FIRST**: Before batch calls, make ONE probe call to detect MCP schema incompatibility:
> `mcp__unified-vuln-db__get_knowledge_stats()`
> - If probe **succeeds** → set `RAG_TOOLS_AVAILABLE = true`, proceed with batches below
> - If probe **fails** (API error, schema error, timeout) → set `RAG_TOOLS_AVAILABLE = false`, **skip ALL unified-vuln-db calls**, append to `{SCRATCHPAD}/build_status.md`: `RAG_TOOLS_AVAILABLE: false - unified-vuln-db MCP probe failed: {error}. Phase 4b.5 RAG Sweep will use WebSearch fallback.`
> - If probe succeeds, also append: `RAG_TOOLS_AVAILABLE: true`

> **PARALLELIZATION DIRECTIVE**: Make MCP calls in PARALLEL batches.

**If RAG_TOOLS_AVAILABLE = false**: Skip Batch 1 and Batch 2 entirely. Write to `{SCRATCHPAD}/meta_buffer.md`: `## RAG: UNAVAILABLE - MCP tools failed probe. Phase 4b.5 will compensate.`

**Batch 1** (single message, all in parallel):
1. mcp__unified-vuln-db__get_common_vulnerabilities(protocol_type='{TYPE}')
2. mcp__unified-vuln-db__get_attack_vectors(bug_class='{relevant pattern}')
3. mcp__unified-vuln-db__get_root_cause_analysis(bug_class='{detected pattern}')

**Batch 2** (single message, all in parallel):
4. **MANDATORY**: mcp__unified-vuln-db__search_solodit_live(protocol_category=['{DeFi/Bridge/etc.}'], tags=['{relevant}', 'Aptos', 'Move'], language='Move', quality_score=3, sort_by='Quality', max_results=20)
5. If SEMI_TRUSTED_ROLE detected: search_solodit_live(keywords='reward compound timing front-run keeper operator admin', impact=['HIGH','MEDIUM'], max_results=15)
6. search_solodit_live(keywords='Move aptos module ability type safety resource object fungible_asset', impact=['HIGH','CRITICAL'], max_results=15)

### Step 3: Classify Aptos-Specific Vulnerability Classes

In addition to protocol-type vulnerabilities, always check for Aptos Move-specific vulnerability classes:

| Class | Description | What to Check |
|-------|-------------|---------------|
| Ability misuse | Struct has copy/drop when it shouldn't (hot potato, receipts, capabilities) | All struct definitions -- verify ability annotations match semantic intent |
| Bit shift overflow | `<<`/`>>` without bounds check (Cetus $223M hack pattern) | All shift operations |
| Type confusion | Generic type parameter accepts wrong Coin<T>/FA type | All generic functions -- check type constraints |
| Reentrancy via hooks | Dispatchable FA hooks or closures executing during state transition | All FA operations -- check dispatch vs direct paths |
| Missing signer check | public function modifies state without `&signer` verification | All state-modifying functions |
| Ref capability leak | ConstructorRef/MintRef/TransferRef/BurnRef stored insecurely | All object/FA creation -- verify storage access control |
| Module upgrade risk | Upgradeable module with no upgrade policy restriction | All external module deps |
| Resource not found | `borrow_global` on address that may not have the resource | All global storage access |
| Phantom type bypass | `phantom T` parameter not validated at runtime | All generic structs with phantom params |
| mem::swap attack | Mutable reference to valuable struct exposed to untrusted caller | All `&mut` parameters in public functions |
| Object ownership bypass | Object transferred or manipulated without proper ownership check | All object::transfer calls |
| init_module replay | Module initialization without idempotency guard | All init_module functions |
| Unchecked arithmetic | Division by zero, overflow/underflow in u64/u128/u256 (Move aborts, no wrap) | All arithmetic operations |
| Event emission gap | State-changing function does not emit corresponding event | All state mutations |
| Friend function abuse | `public(friend)` grants excessive access to friend modules | All friend declarations and public(friend) functions |
| Hot potato violation | Struct without `drop`+`store` not consumed in all code paths | All hot potato structs -- trace all paths |
| Module reentrancy via circular calls | Module A calls Module B which calls back into Module A while A holds mutable state | All cross-module calls after borrow_global_mut |

### Step 4: Synthesize into {SCRATCHPAD}/meta_buffer.md

```markdown
# Meta-Buffer: {PROTOCOL_NAME} ({PROTOCOL_TYPE}) -- Aptos Move
## Protocol Classification
- **Type**: {protocol_type}
- **Runtime**: Aptos Move VM
- **Key Indicators**: {what patterns led to classification}
## Common Vulnerabilities for {PROTOCOL_TYPE} on Aptos
| Category | Frequency | Key Functions to Check |
## Aptos Move-Specific Vulnerability Classes
| Class | Description | Check |
|-------|-------------|-------|
| Ability misuse | copy on value tokens, drop on receipts/capabilities | All struct definitions |
| Bit shift overflow | <</ >> without bounds check (Cetus $223M) | All shift operations |
| Type confusion | Generic type accepts wrong Coin<T>/FA | All generic public functions |
| Reentrancy via hooks | Dispatchable FA hooks during state transition | All FA operations |
| Missing signer check | State mutation without &signer | All state-modifying functions |
| Ref capability leak | MintRef/TransferRef stored insecurely | All Ref creation + storage |
| Module upgrade risk | Upgradeable dep without policy restriction | All external module deps |
| Resource not found | borrow_global on missing resource | All global storage access |
| Phantom type bypass | phantom T not runtime-enforced | All generic structs |
| mem::swap attack | &mut to valuable struct in public function | All public &mut parameters |
| Object ownership bypass | Object transferred without ownership check | All object::transfer sites |
| init_module replay | Initialization without idempotency guard | All init_module functions |
| Unchecked arithmetic | Overflow/underflow causes runtime abort | All unchecked math |
| Event emission gap | State change without event emission | All state mutations |
| Friend function abuse | public(friend) grants excessive access | All friend declarations |
| Hot potato violation | Struct without drop not consumed | All hot potato code paths |
| Module reentrancy | Circular calls with mutable borrows | All cross-module calls |
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
2. {question derived from Aptos-specific vulnerability classes}
## Timing-Sensitive Operations (if SEMI_TRUSTED_ROLE detected)
| Operation | Timing Pattern | User Exploitation Vector | RAG Matches |
## Code Patterns to Grep
- `{pattern}` -- related to {vulnerability class}
```

Return: 'DONE: meta_buffer.md written with {N} vulnerability classes, {M} attack vectors, {K} Solodit matches'
")
```

---

## Agent 1B: Docs + External + Fork

```
Task(subagent_type="general-purpose", prompt="
You are Recon Agent 1B (Docs + External + Fork) for an Aptos Move module audit.

PROJECT_PATH: {path}
SCRATCHPAD: {scratchpad}
DOCUMENTATION: {docs_path_or_url_if_provided}
NETWORK: {network_if_provided}
SCOPE_FILE: {scope_file_if_provided}
SCOPE_NOTES: {scope_notes_if_provided}

## RESILIENCE RULES
1. **MCP/Tavily call fails?** -> Document failure and CONTINUE. Never retry more than once.
2. **Write-first principle**: Write partial results before slow external calls.
3. **No task is blocking**: Skip stuck tasks, document why, move on.

## TASK 0 Step 6: Fork Ancestry Research -- Aptos Move Parent Programs

Read ~/.claude/agents/skills/aptos/fork-ancestry/SKILL.md (if it exists) or apply the FORK_ANCESTRY methodology with Aptos-specific parent detection:

### Known Aptos Move Parent Programs

| Parent | Detection Patterns |
|--------|-------------------|
| Thala | `thala\|MOD\|move_dollar\|stability_pool\|thala_swap\|ThalaLabs\|weighted_pool\|stable_pool` |
| Echelon | `echelon\|lending_market\|lending_pool\|echelon_market\|supply_and_borrow` |
| Aries | `aries\|aries_markets\|lending\|borrow_and_deposit\|aries_lending` |
| Liquidswap | `liquidswap\|pontem\|curves::Stable\|curves::Uncorrelated\|liquidity_pool\|LiquidityPool` |
| PancakeSwap | `pancake\|pancakeswap\|master_chef\|smart_router\|cake\|PancakeSwap` |
| Tortuga | `tortuga\|tAPT\|liquid_staking\|staking_pool\|TortugaStakePool` |
| Amnis | `amnis\|amAPT\|stAPT\|liquid_staking\|AmnisRouter` |
| Merkle Trade | `merkle\|merkle_trade\|perp\|trading_pair\|MerkleTradingPair` |
| Hippo | `hippo\|aggregator\|dex_router\|trade_step\|HippoAggregator` |
| Aptin | `aptin\|aptin_finance\|lending\|flash_loan\|AptinFlashLoan` |
| Cellana | `cellana\|ve_token\|gauge\|voting_escrow\|VeToken\|GaugeController` |
| Cetus | `cetus\|clmm\|tick\|pool_manager\|CetusPool\|open_position\|add_liquidity\|position_manager` |
| Abel | `abel\|abel_finance\|vault\|strategy\|AbelVault` |
| Ditto | `ditto\|stDitto\|ditto_staking\|ditto_vault` |
| Aptos Framework | `aptos_framework\|aptos_std\|aptos_token\|0x1::\|0x3::\|0x4::` |

**Detection procedure**:
1. Grep Move source files for patterns above (exclude build/, .aptos/, tests/)
2. Check Move.toml `[dependencies]` and `[addresses]` for parent package names or addresses
3. Check README or docs for fork attribution, upstream references
4. Compare module names, struct names, and function signatures against parent patterns

**For each detected parent**:
1. Query Solodit: `search_solodit_live(keywords='{parent_name} aptos move', impact=['HIGH','CRITICAL'], sort_by='Quality', max_results=15)` -- skip if fails
2. Query Solodit: `search_solodit_live(keywords='{parent_name} fork modified divergence', impact=['HIGH','MEDIUM'], sort_by='Rarity', max_results=10)` -- skip if fails
3. Query Tavily: `tavily_search(query='{parent_name} Aptos Move vulnerability exploit audit finding 2024 2025 2026')` -- skip if fails
4. Analyze divergences: modified struct abilities, changed access control, added/removed functions, modified resource storage patterns, changed signer requirements, altered module dependencies

### Hardcoded Known-Issue Floor (Web Search Fallback)

If Solodit AND Tavily BOTH fail, use this minimum catalog -- check EACH applicable parent:

| Parent | Critical Known Issue | Root Cause | Search Keywords |
|--------|---------------------|------------|-----------------|
| Cetus | Bit shift overflow in liquidity math ($223M exploit, 2025) | Unchecked `<<` shift with value >= bit width causes overflow | `cetus bit shift overflow liquidity exploit` |
| Thala | Stability pool reward calculation manipulation | Reward timing attack via strategic deposit/withdraw around distribution | `thala stability pool reward timing attack` |
| AMM DEX | Curve calculation precision loss at extreme reserves | Integer division truncation in swap calculation at boundary values | `amm curve precision reserves swap calculation` |
| Echelon/Aries (lending) | Oracle price staleness enabling unfair liquidation | Stale price feed used for health factor calculation | `aptos lending oracle stale liquidation health` |
| Tortuga/Amnis (liquid staking) | Exchange rate manipulation via direct APT transfer | Unsolicited APT deposit inflates exchange rate | `aptos liquid staking exchange rate donation attack` |
| Cellana (ve-token) | Voting power calculation error at epoch boundary | Checkpoint staleness during epoch transition | `ve_token voting power epoch boundary checkpoint` |
| DEX yield farm | Reward per share overflow with small deposits | Large multiplier applied to tiny deposit amounts | `masterchef reward overflow small deposit` |
| Aptos Framework | FA dispatchable hook reentrancy (2024 framework update) | Dispatchable function hooks can execute arbitrary code during FA operations | `aptos fungible_asset dispatchable hook reentrancy` |

### Divergence Focus Areas for Aptos Move (ordered by criticality)

#### Ability Changes (HIGHEST PRIORITY)
- Did the fork add `copy` or `drop` to structs that are value-bearing or enforce consumption (hot potato pattern)?
- Did the fork remove `store` from structs that need to be stored in global storage?
- Did the fork add `key` to structs without proper access control on `move_to`?
- Ability changes are the **#1 Aptos Move vulnerability class** -- they control what can be done with struct instances at the type system level.

#### Signer/Authority Changes
- Did the fork add or remove `&signer` parameters from public functions?
- Did the fork change which address holds `SignerCapability` or `resource_account` authority?
- Were admin functions made public without signer checks?
- Did the fork change `friend` module declarations (expanding or reducing trust boundary)?

#### Module Dependency Changes
- Did the fork add dependencies on upgradeable third-party modules?
- Did the fork change `0x1::` framework calls (e.g., switching from `coin` to `fungible_asset`)?
- Are new dependencies pinned to specific addresses or resolved at runtime?

#### Type Parameter Changes
- Did the fork change generic type constraints?
- Are `phantom` type parameters validated at usage sites?
- Did the fork add or remove type assertions (`assert!` on type identity)?

#### Resource Access Changes
- Did the fork change `acquires` annotations (may indicate changed global storage access)?
- Did the fork modify `borrow_global`/`borrow_global_mut` access patterns?
- Did the fork add `move_from` (resource extraction) without proper authorization?

Append to {SCRATCHPAD}/meta_buffer.md under '## Fork Ancestry Analysis':
```markdown
## Fork Ancestry Analysis

### Detected Parents
| Parent | Confidence | Patterns Found | Move Version |
|--------|-----------|---------------|-------------|

### Inherited Vulnerabilities to Verify
| # | Parent Issue | Severity | Location in Fork | Status |
|---|-------------|----------|------------------|--------|
| 1 | {issue} | {severity} | {fork location: file:line} | CHECK / VERIFIED_SAFE / VULNERABLE |

### Fork Divergences (Security-Critical)
| # | Component | Change Type | Change Description | New Risk? |
|---|-----------|------------|-------------------|-----------|
| 1 | {component} | ABILITY_CHANGE / SIGNER_CHANGE / MODULE_DEP / TYPE_PARAM / RESOURCE_ACCESS / OTHER | {what changed} | YES/NO/CHECK |

### Questions for Breadth Agents
1. {derived from inherited vulnerabilities}
2. {derived from divergence analysis}
```

> **SKIP POLICY**: If web searches fail, write 'Fork ancestry: web search unavailable' and continue with code-level divergence analysis only.

## TASK 3: Documentation Context

1. Read README.md, docs/ folder, or fetch provided URL
2. Read Move.toml for module metadata: package name, dependencies, named addresses, upgrade policy
3. Extract: protocol purpose, key invariants, trust model, external module dependencies
4. Identify:
   - Authority model: admin/operator signer-based, capability-based (using stored capabilities), governance via multisig module
   - Upgradeability: Is the package upgradeable? Check Move.toml for `upgrade_policy` (compatible, immutable). Check for `aptos_framework::code` usage.
   - External module dependencies: verified framework modules vs third-party
   - Resource/Object model: What resources are published? What objects are created?
   - Token model: Coin<T> (legacy) or FungibleAsset (new standard) or both?
5. If no docs: note 'Inferring purpose from code'
6. **Trust Assumption Table** (MANDATORY): From docs, README, code comments, and access control patterns, extract ALL trust assumptions into a structured table in design_context.md:

| # | Actor | Trust Level | Assumption | Source |
|---|-------|-------------|------------|--------|
| 1 | {role, e.g., 'package deployer / module upgrade authority'} | FULLY_TRUSTED | Will not act maliciously | {source} |
| 2 | {role, e.g., 'operator signer'} | SEMI_TRUSTED(bounds: {on-chain limit}) | Cannot exceed {stated bounds} | {source} |
| 3 | - | PRECONDITION | {config state assumed at launch, e.g., 'init_module called once by framework'} | {source} |

Trust levels: `FULLY_TRUSTED` (will not act maliciously -- e.g., multisig deployer, governance module, module upgrade authority), `SEMI_TRUSTED(bounds: ...)` (bounded by on-chain parameters or capability restrictions), `PRECONDITION` (deployment/config state assumption), `UNTRUSTED` (default for users, external modules).

**Aptos-specific trust signals**:
- `SignerCapability` holder -> typically FULLY_TRUSTED (can sign as resource account)
- Module upgrade authority -> FULLY_TRUSTED unless upgrade policy is `immutable`
- `friend` module declarations -> SEMI_TRUSTED (bounded by declared interface)
- `public(friend)` functions -> access bounded by friend list
- `public entry fun` with `&signer` -> per-user authorization
- `public fun` without `&signer` -> UNTRUSTED callable (anyone can invoke via another module)
- Resource account (`resource_account::create_resource_account`) -> trust depends on who holds the SignerCapability

If no explicit trust documentation exists, infer from signer checks, capability patterns, and friend declarations. Note `Source: inferred`.

Write to {SCRATCHPAD}/design_context.md

## TASK 11: External Module Verification (MANDATORY)

> **SKIP POLICY**: If Tavily or API calls fail, skip that step, document 'UNAVAILABLE', and continue.

For EACH external module the protocol depends on:

1. **Find module addresses**: Search codebase for `use {address}::module` patterns, Move.toml `[dependencies]` and `[addresses]` sections
2. **Classify known vs unknown modules**:
   - **Known framework modules** (LOW risk): `0x1::` = aptos_framework (coin, account, fungible_asset, object, event, timestamp, signer, etc.)
   - **Known standard modules** (LOW risk): `0x3::` = aptos_token (legacy token standard), `0x4::` = aptos_token_objects (token v2 / digital asset standard)
   - **Third-party modules** (VERIFY): Any address not in {0x1, 0x3, 0x4}
3. **For each third-party module**:
   - Check Move.toml for source URL (git dependency vs local)
   - Search Tavily for audit history: `tavily_search(query='{module_name} Aptos Move audit security')` -- skip if fails
   - Mark as UNVERIFIED if no audit found
   - Check if module is upgradeable (can the dependency author change behavior post-deployment?)
4. **Verify on-chain** (if Aptos REST API or CLI available):
   - Check module bytecode existence at the declared address
   - Verify module upgrade policy (immutable, compatible, arbitrary)
   - **Skip if calls fail** -- document 'UNAVAILABLE'
5. **Document token transferability**:
   - **Coin<T>**: Can be deposited into any CoinStore<T> via `coin::deposit`. Tokens CAN be sent unsolicited if CoinStore exists.
   - **FungibleAsset**: Can be deposited into any FungibleStore via `fungible_asset::deposit` or `primary_fungible_store::deposit` (creates store if needed). Tokens CAN be sent unsolicited.
   - **Object<T>**: Objects can be transferred via `object::transfer` if ungated_transfer is enabled or if TransferRef is used. Check transfer configuration.
   - Does the protocol use direct balance queries or internal accounting?
6. **Check for dispatchable hooks**: If protocol uses FungibleAsset with dispatchable functions, verify that the registered withdraw/deposit hooks cannot be bypassed by calling the underlying module directly.

Write to {SCRATCHPAD}/external_production_behavior.md:
```markdown
# External Module Verification -- Aptos Move

## Framework Dependencies (verified)
| Module | Address | Functions Used | Risk Level |
|--------|---------|---------------|------------|
| {module} | 0x1 | {functions} | LOW (framework) |

## Third-Party Dependencies
| Module | Address/Source | Functions Used | Audited? | Upgradeable? | Risk Level |
|--------|---------------|---------------|----------|-------------|------------|
| {module} | {addr} | {functions} | {YES/NO/UNVERIFIED} | {YES/NO} | {level} |

## Token Transferability Matrix
| Token Type | Standard | Can Send Unsolicited? | Mechanism | Protocol Tracking |
|------------|----------|----------------------|-----------|-------------------|
| {token} | Coin<T>/FA | YES/NO | {how} | internal/balance-based |

## Module Upgrade Risk
| Dependency | Upgradeable? | Impact If Upgraded | Trust Assumption |
|------------|-------------|-------------------|------------------|
```

**If module addresses unavailable**: Mark all external deps as 'UNVERIFIED', add severity note (Rule 4 adversarial assumption), set severity floor MEDIUM for HIGH worst-case.

Return: 'DONE: design_context.md, external_production_behavior.md written. Fork ancestry: {found/none}. External modules: {N} verified, {M} unverified'
")
```

---

## Agent 2: Build + Static Analysis + Tests

```
Task(subagent_type="general-purpose", prompt="
You are Recon Agent 2 (Build + Static + Tests) for an Aptos Move module audit.

PROJECT_PATH: {path}
SCRATCHPAD: {scratchpad}

## RESILIENCE RULES
1. **Build/tool call fails?** -> Document failure and CONTINUE. Never retry more than once.
2. **Write-first principle**: Write partial results before slow operations.
3. **No task is blocking**: Skip stuck tasks, document why, move on.

## TASK 1: Build Environment

> **PATH note**: On Windows, `aptos` may not be in Claude Code's default PATH. Prefix Bash calls with: `export PATH="$HOME/.aptoscli/bin:$PATH" &&` if not found on first attempt.

1. Check for Move.toml (package manifest), look for multiple Move.toml files (workspace with sub-packages)
2. Read Move.toml for:
   - Package name and version
   - Named addresses: `[addresses]` section (e.g., `deployer = '_'` or `deployer = '0x...'`)
   - Dependencies: `[dependencies]` section (AptosFramework, AptosStdlib, AptosToken, third-party)
   - Upgrade policy: `upgrade_policy` field if present (compatible, immutable)
3. Verify toolchain availability:
   - `aptos --version` -- if missing, document as TOOLCHAIN WARNING
   - `aptos move --help` -- verify move subcommand available
   If required tool is missing, document in build_status.md and attempt build anyway.
3b. **Dependency Recovery** (before first build attempt):
   - Run `git submodule update --init --recursive`
   - If Move.toml references git dependencies: verify network access, run `aptos move compile` once to trigger dependency resolution
4. Build: `aptos move compile --save-metadata` (from the package root where Move.toml lives)
   - If named addresses use `_` (placeholder), try: `aptos move compile --named-addresses deployer=0xCAFE`
   - If multiple placeholders: provide all in comma-separated format `--named-addresses pkg=0xCAFE,admin=0xBEEF`
   - If multiple packages exist, build each
5. Check for Move Prover spec annotations: grep for `spec ` blocks in .move source files
   - If spec blocks found, run: `aptos move prove`
   - Set `PROVER_AVAILABLE = true/false` based on whether prover ran successfully
   - If specs exist but prover is unavailable, flag as COVERAGE_GAP
6. Check Move.toml for:
   - Dependency versions/git revisions -- note pinned vs unpinned
   - `[dev-addresses]` and `[dev-dependencies]` -- note test-only dependencies
7. If build fails after 3 attempts, document failure reason and continue

Write to {SCRATCHPAD}/build_status.md:
```markdown
# Build Status -- Aptos Move
- **Package**: {name} (from Move.toml)
- **Named Addresses**: {list addresses and whether resolved or placeholder}
- **Dependencies**: {list with versions/sources}
- **Upgrade Policy**: {compatible/immutable/not specified}
- **Build Result**: success/failed ({error})
- **Move Prover**: {available and passed / available but failed / specs not found / toolchain unavailable}
- **PROVER_AVAILABLE**: {true/false}
- **Token Standard**: {Coin<T> / FungibleAsset / both / neither detected}
```

## TASK 2: Static Analysis Artifacts

### Move Prover (Primary Static Analyzer)
The Move Prover is the primary static analysis tool for Move. It verifies spec annotations against code.

**Procedure**:
1. If PROVER_AVAILABLE = true from TASK 1, prover results are already captured
2. If PROVER_AVAILABLE = false but spec blocks exist, document 'Prover failed -- see build_status.md'
3. If no spec blocks exist, document 'No formal specifications found -- prover not applicable'

**If PROVER_AVAILABLE = true**: Extract prover results (verification errors, timeout specs, passed specs) and write to {SCRATCHPAD}/static_analysis.md under '## Move Prover Results'.

### Compiler Diagnostics
If available, run `aptos move compile --check` to get type errors, ability violations, and warnings without full build output. Capture any diagnostics.

### Grep Fallback (ALWAYS run, regardless of Prover status)

**Function inventory**:
- Grep `public fun \|public entry fun \|public(friend) fun \|entry fun \|fun ` in .move files (exclude build/, .aptos/, tests/)
- For each function: capture visibility (public/public entry/public(friend)/private), name, parameters, return type
- Categorize: entry functions (user-callable), public functions (module-callable), friend functions, private functions
Write to {SCRATCHPAD}/function_list.md:
```markdown
# Function Inventory -- Aptos Move

## Entry Functions (user-callable via transaction)
| Module | Function | Parameters | Return | Access Control |
|--------|----------|------------|--------|---------------|

## Public Functions (callable by any module)
| Module | Function | Parameters | Return | Notes |
|--------|----------|------------|--------|-------|

## Friend Functions (callable by declared friends only)
| Module | Function | Parameters | Return | Friend Modules |
|--------|----------|------------|--------|---------------|

## Private Functions
| Module | Function | Parameters | Return | Called By |
|--------|----------|------------|--------|----------|
```

**State (resource/struct) inventory**:
- Grep `struct ` in .move files, capture: struct name, abilities (has copy, drop, store, key), fields
- Classify: resources (has `key`), objects (stored in ObjectCore), plain structs, hot potatoes (no `drop` + no `store`)
Write to {SCRATCHPAD}/state_variables.md:
```markdown
# State Inventory -- Aptos Move

## Resources (key ability -- stored in global storage)
| Module | Struct | Abilities | Fields | Published Where |
|--------|--------|-----------|--------|----------------|

## Objects (via object::create_*)
| Module | Struct | Abilities | Fields | Transfer Config |
|--------|--------|-----------|--------|----------------|

## Hot Potatoes (no drop, no store -- must be consumed)
| Module | Struct | Abilities | Creation Site | Consumption Site |
|--------|--------|-----------|--------------|-----------------|

## Plain Structs (local only)
| Module | Struct | Abilities | Usage |
|--------|--------|-----------|-------|
```

**Cross-module call graph (resource operations)**:
- Grep `borrow_global\|borrow_global_mut\|move_from\|move_to\|exists<` in .move files
- For each site: capture module, function, resource type, operation (read/write/move/check)
- Grep `use .*::` to map module dependency graph
- Note: Move does not have arbitrary external calls like Solidity, but cross-module function calls through `use` imports create trust boundaries
Write to {SCRATCHPAD}/call_graph.md:
```markdown
# Call Graph -- Aptos Move

## Resource Operations
| Module | Function | Resource | Operation | Line |
|--------|----------|----------|-----------|------|

## Cross-Module Call Graph
| Caller Module | Caller Function | Target Module | Target Function | Line |
|--------------|----------------|---------------|----------------|------|

## Module Dependency Graph
| Module | Dependencies (use statements) |
|--------|------------------------------|
```

**Access control patterns (modifiers equivalent)**:
- Grep `assert!.*signer\|assert!.*address_of\|assert!.*==.*@\|abort ` for signer-based access control
- Grep for capability patterns: `MintCapability\|BurnCapability\|FreezeCapability\|AdminCapability\|OwnerCapability\|SignerCapability`
- Grep for `acquires ` annotations (functions that access global storage)
- Document: which functions require which signers, which capabilities gate access
Write to {SCRATCHPAD}/modifiers.md:
```markdown
# Access Control Patterns -- Aptos Move

## Signer-Based Access Control
| Module | Function | Required Signer | Assertion | Line |
|--------|----------|----------------|-----------|------|

## Capability-Based Access Control
| Module | Capability Struct | Functions Gated | Storage Location | Who Can Acquire |
|--------|------------------|----------------|-----------------|-----------------|

## Acquires Annotations
| Module | Function | Resources Acquired | Mutable? |
|--------|----------|--------------------|----------|
```

**Events**:
- Grep `emit\|event::emit\|event::emit_event\|EventHandle\|#\[event\]` in .move files
Write to {SCRATCHPAD}/event_definitions.md

**External interfaces**:
- Grep `use .*::{` and `friend ` declarations in .move files
- List all imported modules and which functions are used from each
Write to {SCRATCHPAD}/external_interfaces.md

## TASK 8: Run Static Detectors (grep-based)

Run targeted grep checks for Aptos Move-specific vulnerability patterns:

### Ability Checks
- Structs with `has copy` that hold value or represent tokens/receipts/capabilities -> COPY_ON_VALUE
- Structs with `has drop` that should be consumed (hot potato pattern, receipts, obligations) -> DROP_ON_RECEIPT
- Structs with `has store` holding capability refs (MintRef, TransferRef, BurnRef, SignerCapability) -> CAPABILITY_LEAK
- Structs with `key` but missing `store` where transferability is expected -> MISSING_STORE

### Shift Safety
- `<<\|>>` without preceding assert or bounds check on shift amount -> UNCHECKED_SHIFT
- Cross-reference with Cetus $223M hack pattern: shift overflow in liquidity math

### Access Control
- `public fun` or `public entry fun` that calls `move_to\|move_from\|borrow_global_mut` without `&signer` parameter -> MISSING_SIGNER
- `public fun` that modifies global state (`borrow_global_mut\|move_to\|move_from`) -> STATE_MUTATION_CHECK
- Entry functions with `&signer` that never call `signer::address_of` -> UNUSED_SIGNER

### Resource Safety
- `borrow_global<` without preceding `exists<` check on same address -> RESOURCE_NOT_FOUND_RISK
- `move_from<` without cleanup of dependent resources -> INCOMPLETE_RESOURCE_REMOVAL
- `move_to<` without checking `!exists<` -> RESOURCE_ALREADY_EXISTS_RISK
- `borrow_global_mut` returned or passed to external function -> MUT_REF_EXPOSURE

### Type Safety
- `phantom` type parameters in struct definitions -> PHANTOM_TYPE_CHECK
- Generic functions accepting any `CoinType` or `T` without type assertion -> TYPE_VALIDATION_CHECK
- Functions with generic `<T>` that operate on `Coin<T>` or `FungibleAsset` without type registry validation -> UNVALIDATED_GENERIC

### Arithmetic
- `as u64\|as u128\|as u256\|as u8\|as u16\|as u32` -> UNSAFE_CAST
- `/ ` followed by `* ` on same/subsequent line -> DIVIDE_BEFORE_MULTIPLY
- Division operations without preceding zero-check on divisor -> DIVISION_BY_ZERO_RISK
- Large literal constants in arithmetic (potential overflow) -> OVERFLOW_RISK

### FungibleAsset/Object
- `constructor_ref\|ConstructorRef` usage -- verify ref is consumed or stored securely -> REF_LIFECYCLE_CHECK
- `dispatchable` or `deposit_with_ref\|withdraw_with_ref` -> HOOK_REENTRANCY_CHECK
- `object::transfer\|object::transfer_with_ref` without ownership validation -> OBJECT_TRANSFER_CHECK
- `TransferRef\|MintRef\|BurnRef` stored in global storage accessible by public functions -> CAPABILITY_EXPOSURE

### Misc
- `assert!(false\|abort ` -> UNREACHABLE_CODE
- Unbounded `vector::` operations (`vector::for_each\|vector::length` in loop without bound) -> UNBOUNDED_ITERATION
- `init_module` functions -> INIT_MODULE_CHECK (verify idempotency)
- `#[view]` functions that read sensitive state -> VIEW_FUNCTION_EXPOSURE
- `timestamp::now_seconds\|timestamp::now_microseconds` -> TIMESTAMP_DEPENDENCY

Write to {SCRATCHPAD}/static_analysis.md:
```markdown
# Static Analysis -- Aptos Move

## Move Prover Results
{prover results or 'N/A'}

## Compiler Diagnostics
{compile --check results or 'N/A'}

## Reference Lifecycle Analysis
| Ref Type | Creation Site | Storage Location | Access Control | Risk |
|----------|--------------|-----------------|---------------|------|

## Ability Analysis
| Struct | Abilities | Semantic Role | Risk | Notes |
|--------|-----------|--------------|------|-------|

## Arithmetic Analysis
| Operation | Location | Type | Checked? | Risk |
|-----------|----------|------|----------|------|

## Reentrancy Analysis
| Module | Function | Mut Borrow | Cross-Module Call | Risk |
|--------|----------|-----------|------------------|------|

## Initialization Analysis
| Module | Init Function | Idempotent? | Resources Published | Risk |
|--------|--------------|-------------|--------------------|----|

## Object Transfer Analysis
| Object Type | Transfer Mode | Gating | Risk |
|-------------|--------------|--------|------|

## Flagged Issues Summary
| Flag | Count | Locations | Severity |
|------|-------|-----------|----------|
```

## TASK 9: Run Test Suite

1. Run: `aptos move test` (from package root where Move.toml lives)
   - If multiple packages, run tests in each
   - Capture: passed count, failed count, failed test names
2. If tests have named address requirements, try: `aptos move test --named-addresses deployer=0xCAFE`
3. If tests fail, note count and names as TEST HEALTH WARNING (Info-level signal)
4. Check for `#[expected_failure]` tests -- these document known abort conditions
5. Check for Move Prover test specs: `spec` blocks that serve as formal test assertions
6. Note any `#[test_only]` modules or functions that indicate test infrastructure

Write to {SCRATCHPAD}/test_results.md:
```markdown
# Test Results -- Aptos Move
- **Test Command**: {command used}
- **Result**: {passed/failed}
- **Passed**: {N} tests
- **Failed**: {N} tests
- **Failed Tests**: {list names and error messages}
- **Expected Failures**: {N} tests with #[expected_failure]
- **Prover Specs**: {N specs verified / N specs failed / no specs}
- **Test Coverage Notes**: {which modules have tests, which lack them}
```

Return: 'DONE: Build {success/failed}, Prover {available/unavailable}, {N} functions, {M} structs, {K} resource operations, {J} static issues, tests: {pass/fail/skip}'
")
```

---

## Agent 3: Patterns + Surface + Templates

```
Task(subagent_type="general-purpose", prompt="
You are Recon Agent 3 (Patterns + Surface + Templates) for an Aptos Move module audit.

PROJECT_PATH: {path}
SCRATCHPAD: {scratchpad}

## RESILIENCE RULES
1. **Write-first principle**: Write partial results before any slow operation.
2. **No task is blocking**: Skip stuck tasks, document why, move on.

## TASK 4: Contract Inventory

1. Count lines of all .move files (exclude build/, .aptos/, tests/ directories)
2. List each module with: file path, line count, function count, struct count, resource count, entry function count
3. List helper/utility modules separately (modules with no public entry functions)
4. Note the Move edition if specified in Move.toml
5. **Scope filtering**: If SCOPE_FILE is set, read it and mark modules as IN_SCOPE or OUT_OF_SCOPE. If SCOPE_NOTES is set, use them to refine scope. If neither is set, all non-library modules are in scope.

Write to {SCRATCHPAD}/contract_inventory.md:
```markdown
# Module Inventory -- Aptos Move

| Module | File Path | Lines | Functions | Entry Fns | Structs | Resources | Objects |
|--------|-----------|-------|-----------|-----------|---------|-----------|---------|

## Summary
- **Total Modules**: {N}
- **Total Lines**: {N} (excluding build/tests)
- **Entry Functions**: {N} (user-callable attack surface)
- **Resources**: {N} (global state)
- **Objects**: {N} (object model usage)

## Utility/Helper Modules
| Module | File Path | Lines | Purpose |
```

## TASK 5: Attack Surface Discovery

### Part A: External Module Calls (cross-module interaction table)
For each function that calls into another module (via `use` imports):

| Caller Module | Caller Function | Target Module | Target Function | Parameters Forwarded | Return Value Used | State Modified? |
|--------------|----------------|---------------|----------------|---------------------|-------------------|----------------|

For each cross-module call:
1. Is the target module a framework module (0x1) or third-party?
2. Are the parameters validated before forwarding?
3. Is the return value checked/validated?
4. Does the caller hold a mutable borrow when making the call (reentrancy risk)?
5. Does the target function have side effects (events, state changes)?

### Part B: Resource/Object Inventory Matrix
For each resource (struct with `key`) and object:

| Resource/Object | Module | Published At | Who Can Create | Who Can Modify | Who Can Destroy | Global/Per-User |
|----------------|--------|-------------|---------------|---------------|----------------|----------------|

### Part C: Token/FA Account Mapping
For each token the protocol interacts with:

| Token | Standard | Store Type | Protocol Reads Balance? | Uses Balance Directly? | Internal Tracking? | Unsolicited Transfer Impact |
|-------|----------|-----------|------------------------|----------------------|-------------------|-----------------------------|

- **Coin<T>**: Protocol holds via `CoinStore<T>`. Balance readable via `coin::balance<T>(addr)`. Unsolicited deposits via `coin::deposit(addr, coin)`.
- **FungibleAsset**: Protocol holds via `FungibleStore` at an object address. Balance readable via `fungible_asset::balance(store)`. Unsolicited deposits via `primary_fungible_store::deposit(addr, fa)` or `fungible_asset::deposit(store, fa)`.
- Document whether protocol uses direct balance queries or internal accounting.

### Part D: Signer/Authority Analysis
For each authority the protocol uses:

| Authority | Source (param/SignerCapability/resource_account) | Functions Requiring | Multi-sig? | Upgrade Control? |
|-----------|------------------------------------------------|---------------------|-----------|-----------------|

For each authority:
1. Is it a direct `&signer` parameter or a stored `SignerCapability`?
2. Can the authority be rotated/transferred?
3. Is the authority address hardcoded or configurable?
4. Does the authority control module upgrade?

### Part E: Reference Lifecycle Tracking
For each capability reference (ConstructorRef, MintRef, TransferRef, BurnRef, DeleteRef, FreezeRef):

| Ref Type | Created In | Stored In | Storage Address | Who Can Access Store | Used In | Security Notes |
|----------|-----------|-----------|----------------|---------------------|---------|---------------|

Critical checks:
- Is the Ref stored in a resource that any address can read?
- Can the Ref be extracted via a public function?
- Is the Ref's lifetime limited (e.g., ConstructorRef used only during init)?
- Are Refs for the same object spread across multiple modules?

### Signal Elevation Tags

During attack surface analysis, tag risk signals that warrant explicit follow-up with `[ELEVATE]`:

Apply `[ELEVATE]` when you observe:
- `has copy` on value-bearing struct -> `[ELEVATE:COPY_ON_VALUE] Verify copy ability is intentional and safe`
- `has drop` on receipt/enforcement struct -> `[ELEVATE:DROP_ON_RECEIPT] Verify drop does not bypass enforcement`
- Fork ancestry match detected -> `[ELEVATE:FORK_ANCESTRY:{parent}] Verify known {parent} vulnerability classes addressed`
- Asymmetric branch sizes in deposit/withdraw or profit/loss logic -> `[ELEVATE:BRANCH_ASYMMETRY] Verify state completeness in shorter branch (Rule 17)`
- `dispatchable` FA or closures -> `[ELEVATE:REENTRANCY_HOOK] Verify state consistency around hook execution`
- `init_module` without idempotency check -> `[ELEVATE:INIT_RISK] Verify initialization cannot be replayed`
- `SignerCapability` stored in global storage with public accessor -> `[ELEVATE:SIGNER_CAP_EXPOSURE] Verify SignerCapability cannot be extracted by unauthorized party`
- Generic function with unconstrained type parameter operating on value -> `[ELEVATE:TYPE_CONFUSION] Verify type parameter validation prevents wrong token/asset substitution`
- `&mut` reference to valuable struct passed to public function -> `[ELEVATE:MUT_REF_RISK] Verify mutable reference cannot be abused via mem::swap`
- `borrow_global_mut` held across a cross-module function call -> `[ELEVATE:REENTRANCY] Verify module reentrancy safety -- mut borrow held across external call`
- Any Ref (MintRef, TransferRef, BurnRef) stored in global storage -> `[ELEVATE:REF_LEAK] Verify Ref access control -- stored at {address}, accessible by {who}`
- Object with ungated_transfer enabled -> `[ELEVATE:UNGATED_TRANSFER] Verify object transfer restrictions are intentional`
- Hot potato struct (no drop, no store) -> `[ELEVATE:HOT_POTATO] Verify all code paths consume the hot potato`
- Phantom type parameter used for access control -> `[ELEVATE:PHANTOM_ABUSE] Verify phantom type cannot be spoofed`

Write `[ELEVATE]` tags directly into the relevant section of `attack_surface.md`.

Write to {SCRATCHPAD}/attack_surface.md

## TASK 6: Pattern Detection

Grep in .move source files (exclude build/, .aptos/, tests/):

| Pattern | Flag |
|---------|------|
| `epoch\|timestamp\|duration\|interval\|period\|block::get_current\|timestamp::now` | TEMPORAL |
| `oracle\|price_feed\|pyth\|switchboard\|price_oracle\|PriceFeed\|price_info` | ORACLE |
| `randomness\|random\|aptos_framework::randomness\|#\[randomness\]` | RANDOMNESS |
| `flash_loan\|flash\|hot_potato\|borrow.*repay\|FlashLoan` | FLASH_LOAN |
| `fungible_asset\|FungibleAsset\|FungibleStore\|primary_fungible_store\|dispatchable` | FA_STANDARD |
| `balance.*coin\|coin::value\|coin::balance\|fungible_asset::balance\|primary_fungible_store::balance` | BALANCE_DEPENDENT |
| `bridge\|cross_chain\|layer_zero\|wormhole\|message\|LayerZero` | CROSS_CHAIN |
| `admin\|governance\|owner\|operator\|SignerCapability\|resource_account\|authority` | SEMI_TRUSTED_ROLE |
| `migrate\|upgrade\|v2\|deprecated\|legacy\|aptos_framework::code` | MIGRATION |
| `shares\|allocation\|distribute\|pro_rata\|proportional\|vest` | SHARE_ALLOCATION |
| `rate\|emission\|mint\|supply\|inflation\|reward_rate\|fee\|basis_point\|bps` | MONETARY_PARAMETER |
| `object::\|Object<\|ConstructorRef\|TransferRef\|ExtendRef\|DeleteRef` | OBJECT_MODEL |
| `use.*0x[2-9a-f]\|friend\|public(friend)` | EXTERNAL_LIB |
| `dispatchable\|closure\|function_value\|withdraw_hook\|deposit_hook` | REENTRANCY |
| `coin::register\|coin::transfer\|coin::deposit\|coin::withdraw\|Coin<` | COIN_STANDARD |
| `<<\|>>` | BIT_SHIFT |
| `phantom` | PHANTOM_TYPE |
| `has copy\|has drop\|has store\|has key` | ABILITY_USAGE |
| `init_module\|initialize` | INITIALIZATION |
| `MintRef\|TransferRef\|BurnRef\|ConstructorRef\|FreezeRef\|DeleteRef` | REF_LIFECYCLE |
| `#\[view\]` | VIEW_FUNCTIONS |
| `acquires ` | RESOURCE_ACQUISITION |
| `vector::.*length\|table::.*length\|smart_table\|simple_map\|big_vector` | COLLECTION_USAGE |
| `ed25519::verify\|ed25519::signature_verify_strict\|multi_ed25519\|SignedMessage\|signature::verify\|rotate_authentication_key` | HAS_SIGNATURES |

Write to {SCRATCHPAD}/detected_patterns.md:
```markdown
# Detected Patterns -- Aptos Move

| Flag | Pattern Matched | Locations (file:line) | Count |
|------|----------------|----------------------|-------|

## Active Flags
{list of all detected flags}

## Flag Details
### {FLAG_NAME}
- **Matches**: {count}
- **Locations**: {file:line list}
- **Relevance**: {why this matters for security}
```

## TASK 7: Prep Artifacts

**Admin/authority-gated functions**: Grep for signer-checked entry functions, capability-gated functions, friend-only functions
Write to {SCRATCHPAD}/setter_list.md:
```markdown
# Setter/Admin Functions -- Aptos Move

## Signer-Gated Functions (entry functions with admin/operator signer checks)
| Module | Function | Required Signer | What It Modifies |
|--------|----------|----------------|-----------------|

## Capability-Gated Functions
| Module | Function | Required Capability | What It Modifies |
|--------|----------|-------------------|-----------------|

## Friend-Only Functions
| Module | Function | Friend Modules | What It Modifies |
|--------|----------|---------------|-----------------|

## Permissionless State-Modifiers
| Module | Function | Entry? | What It Modifies | Can Grief? |
|--------|----------|--------|-----------------|-----------|
```

**Events**: Grep `emit\|event::emit\|event::emit_event\|#\[event\]` -> {SCRATCHPAD}/emit_list.md
```markdown
# Event Inventory -- Aptos Move

| Module | Event Struct | Emitted In Function(s) | Fields |
|--------|-------------|----------------------|--------|
```

**Constraint variables**: Grep `min\|max\|cap\|limit\|rate\|fee\|threshold\|factor\|multiplier\|ratio\|weight\|duration\|delay\|period\|decimal\|precision\|bps\|basis_point` in .move source files. Mark UNENFORCED for variables with setters but no bounds validation.
Write to {SCRATCHPAD}/constraint_variables.md:
```markdown
# Constraint Variables -- Aptos Move

| Module | Variable | Type | Default | Setter Function | Bounds Enforced? | Notes |
|--------|----------|------|---------|----------------|-----------------|-------|
```

**Setter x Emit Cross-Reference**: For each setter/admin function, check if it emits an event. Flag SILENT SETTERs.
```markdown
## Setter x Emit Cross-Reference
| Setter Function | Module | Emits Event? | Event Name | Missing? |
|----------------|--------|-------------|------------|---------|
```

## TASK 10: Template Recommendations

### Aptos Move-Specific Templates (in ~/.claude/agents/skills/aptos/)
- ABILITY_ANALYSIS -- **ALWAYS required** (verify struct abilities match semantic intent: copy/drop/store/key)
- BIT_SHIFT_SAFETY -- **ALWAYS required** (Move aborts on shift >= bit width, Cetus $223M pattern)
- TYPE_SAFETY -- **ALWAYS required** (generic type parameter exploitation, phantom type abuse)
- REF_LIFECYCLE -- **ALWAYS required** (ConstructorRef/MintRef/TransferRef/BurnRef/DeleteRef/FreezeRef lifecycle security)

### Conditional Templates (in ~/.claude/agents/skills/aptos/)
- FUNGIBLE_ASSET_SECURITY -- FA_STANDARD flag (FungibleStore manipulation, dispatchable hooks, primary store creation)
- REENTRANCY_ANALYSIS -- REENTRANCY flag (module reentrancy via circular calls with mutable borrows, dispatchable hooks)
- DEPENDENCY_AUDIT -- EXTERNAL_LIB flag (third-party module trust, upgrade risk, friend function abuse, interface compliance)

### Shared Templates (adapted for Move, in ~/.claude/agents/skills/aptos/ or shared)
- SEMI_TRUSTED_ROLES -- SEMI_TRUSTED_ROLE flag (admin/operator/capability-based role analysis, SignerCapability trust)
- TOKEN_FLOW_TRACING -- BALANCE_DEPENDENT flag (Coin<T>/FungibleAsset balance dependency, donation attacks, internal tracking)
- SHARE_ALLOCATION_FAIRNESS -- SHARE_ALLOCATION flag (share/allocation fairness, first depositor, rounding)
- TEMPORAL_PARAMETER_STALENESS -- TEMPORAL flag (timestamp-based logic, epoch boundaries, cached parameters)
- ECONOMIC_DESIGN_AUDIT -- MONETARY_PARAMETER flag (fee/rate/emission parameter sustainability, Rule 17 symmetric operations)
- EXTERNAL_PRECONDITION_AUDIT -- External module calls detected (cross-module precondition inference)
- ORACLE_ANALYSIS -- ORACLE flag (Pyth/Switchboard on Aptos, staleness, decimals, zero return)
- FLASH_LOAN_INTERACTION -- FLASH_LOAN flag (flash loan + hot potato pattern analysis, atomic sequence modeling)
- ZERO_STATE_RETURN -- Vault/first-depositor pattern (empty vault, zero shares, inflation attack)
- CROSS_CHAIN_TIMING -- CROSS_CHAIN flag (bridge/cross-chain timing, message ordering)
- MIGRATION_ANALYSIS -- MIGRATION flag (module upgrade, V2 migration, stranded resources)
- CENTRALIZATION_RISK -- 3+ privileged roles (optional, capability concentration, single signer risks)
- FORK_ANCESTRY -- Always (historical vulnerability inheritance from parent programs)
- VERIFICATION_PROTOCOL -- Always (used by verifiers for PoC methodology)

For EACH recommended template provide: Trigger, Relevance, Instantiation Parameters, Key Questions.

---

## BINDING MANIFEST (MANDATORY)

> **CRITICAL**: Orchestrator MUST spawn an agent for every template marked `Required: YES`.

```markdown
## BINDING MANIFEST

| Template | Pattern Trigger | Required? | Reason |
|----------|-----------------|-----------|--------|
| ABILITY_ANALYSIS | Always (Aptos Move) | YES | Foundational Move security -- ability misuse enables token duplication, obligation bypass |
| BIT_SHIFT_SAFETY | Always (Aptos Move) | YES | Move aborts on shift >= bit width -- DoS risk in all shift operations (Cetus $223M pattern) |
| TYPE_SAFETY | Always (Aptos Move) | YES | Generic type exploitation, phantom type abuse, type confusion in Coin<T>/FA |
| REF_LIFECYCLE | Always (Aptos Move) | YES | Capability reference security -- MintRef/TransferRef/BurnRef leaks enable unauthorized operations |
| FORK_ANCESTRY | Always | YES | Historical vulnerability inheritance |
| FUNGIBLE_ASSET_SECURITY | FA_STANDARD flag | {YES/NO} | {FungibleAsset/FungibleStore/dispatchable patterns found} |
| REENTRANCY_ANALYSIS | REENTRANCY flag | {YES/NO} | {dispatchable hooks or mutable borrows across module calls found} |
| DEPENDENCY_AUDIT | EXTERNAL_LIB flag | {YES/NO} | {third-party module dependencies found} |
| SEMI_TRUSTED_ROLES | SEMI_TRUSTED_ROLE flag | {YES/NO} | {admin/operator/SignerCapability/authority patterns found} |
| TOKEN_FLOW_TRACING | BALANCE_DEPENDENT flag | {YES/NO} | {direct balance usage without internal tracking} |
| SHARE_ALLOCATION_FAIRNESS | SHARE_ALLOCATION flag | {YES/NO} | {share/allocation/distribution patterns found} |
| TEMPORAL_PARAMETER_STALENESS | TEMPORAL flag | {YES/NO} | {timestamp-based logic with cached parameters} |
| ECONOMIC_DESIGN_AUDIT | MONETARY_PARAMETER flag | {YES/NO} | {monetary parameter setters found} |
| EXTERNAL_PRECONDITION_AUDIT | External module calls detected | {YES/NO} | {N external module call sites} |
| ORACLE_ANALYSIS | ORACLE flag | {YES/NO} | {Pyth/Switchboard patterns found} |
| FLASH_LOAN_INTERACTION | FLASH_LOAN flag | {YES/NO} | {flash loan / hot potato patterns found} |
| ZERO_STATE_RETURN | Vault/first-depositor pattern | {YES/NO} | {vault pattern with share calculation found} |
| CROSS_CHAIN_TIMING | CROSS_CHAIN flag | {YES/NO} | {bridge/cross-chain patterns found} |
| MIGRATION_ANALYSIS | MIGRATION flag | {YES/NO} | {migration/upgrade patterns found} |
| CENTRALIZATION_RISK | 3+ privileged roles | {YES/NO} | {capability/signer concentration detected} |

### Binding Rules
- ABILITY_ANALYSIS **ALWAYS REQUIRED** for Aptos Move modules
- BIT_SHIFT_SAFETY **ALWAYS REQUIRED** for Aptos Move modules
- TYPE_SAFETY **ALWAYS REQUIRED** for Aptos Move modules
- REF_LIFECYCLE **ALWAYS REQUIRED** for Aptos Move modules
- FORK_ANCESTRY **ALWAYS REQUIRED**
- FA_STANDARD flag detected -> FUNGIBLE_ASSET_SECURITY **REQUIRED**
- REENTRANCY flag detected -> REENTRANCY_ANALYSIS **REQUIRED**
- EXTERNAL_LIB flag detected -> DEPENDENCY_AUDIT **REQUIRED**
- SEMI_TRUSTED_ROLE flag detected -> SEMI_TRUSTED_ROLES **REQUIRED**
- BALANCE_DEPENDENT flag detected -> TOKEN_FLOW_TRACING **REQUIRED**
- SHARE_ALLOCATION flag detected -> SHARE_ALLOCATION_FAIRNESS **REQUIRED**
- TEMPORAL flag detected -> TEMPORAL_PARAMETER_STALENESS **REQUIRED**
- MONETARY_PARAMETER flag detected -> ECONOMIC_DESIGN_AUDIT **REQUIRED**
- External module calls detected -> EXTERNAL_PRECONDITION_AUDIT **REQUIRED**
- ORACLE flag detected -> ORACLE_ANALYSIS **REQUIRED**
- FLASH_LOAN flag detected -> FLASH_LOAN_INTERACTION **REQUIRED**
- CROSS_CHAIN flag detected -> CROSS_CHAIN_TIMING **REQUIRED**
- MIGRATION flag detected -> MIGRATION_ANALYSIS **REQUIRED**

### Injectable Skills
{List any injectable skills recommended based on protocol type classification}
- If protocol_type == 'vault': Recommend VAULT_ACCOUNTING injectable (from ~/.claude/agents/skills/injectable/vault-accounting/SKILL.md)
- Inject Into: Core state or economic design agent (M4)

### Niche Agent Binding Rules
- MISSING_EVENT flag detected (setter_list.md has MISSING EVENT entries OR emit_list.md shows state-changing functions without events) → EVENT_COMPLETENESS **niche agent** REQUIRED
- HAS_SIGNATURES flag detected (ed25519::verify/multi_ed25519/SignedMessage patterns found) → SIGNATURE_VERIFICATION_AUDIT **niche agent** REQUIRED
- DOCUMENTATION is non-empty AND contains testable protocol claims (fee structures, thresholds, permissions, distribution logic) → SPEC_COMPLIANCE_AUDIT **niche agent** REQUIRED (set `HAS_DOCS` flag)
- HAS_MULTI_CONTRACT flag detected (2+ in-scope modules AND constraint_variables.md shows shared parameters/formulas across modules) → SEMANTIC_CONSISTENCY_AUDIT **niche agent** REQUIRED

### Niche Agents (Phase 4b - standalone focused agents, 1 budget slot each)

| Niche Agent | Trigger | Required? | Reason |
|-------------|---------|-----------|--------|
| EVENT_COMPLETENESS | MISSING_EVENT flag (setter_list.md / emit_list.md) | {YES/NO} | {if YES: N setters without events found} |
| SIGNATURE_VERIFICATION_AUDIT | HAS_SIGNATURES flag (detected_patterns.md) | {YES/NO} | {if YES: signature verification patterns found} |
| SPEC_COMPLIANCE_AUDIT | HAS_DOCS flag (non-empty DOCUMENTATION with testable claims) | {YES/NO} | {if YES: docs contain testable claims} |
| SEMANTIC_CONSISTENCY_AUDIT | HAS_MULTI_CONTRACT flag (contract_inventory.md + constraint_variables.md) | {YES/NO} | {if YES: N shared parameters/formulas across M modules} |

### Manifest Summary
- **Total Required Breadth Agents**: {count of YES in skill templates}
- **Total Required Niche Agents**: {count of YES in niche agents}
- **Total Optional Agents**: {count of NO with recommendation}
- **HARD GATE**: Orchestrator MUST spawn agent for each REQUIRED template AND each REQUIRED niche agent
```

Write to {SCRATCHPAD}/template_recommendations.md

Return: 'DONE: {N} modules inventoried ({L} lines), {M} patterns detected, {K} templates recommended, flags: [{list}]'
")
```

---

## After ALL 4 Recon Agents Return

1. **Verify artifacts exist**: `ls {scratchpad}/` -- must have all files:
   - `meta_buffer.md` (1A), `design_context.md` (1B), `external_production_behavior.md` (1B)
   - `build_status.md`, `function_list.md`, `call_graph.md`, `state_variables.md`, `modifiers.md`, `event_definitions.md`, `external_interfaces.md`, `static_analysis.md`, `test_results.md` (2)
   - `contract_inventory.md`, `attack_surface.md`, `detected_patterns.md`, `setter_list.md`, `emit_list.md`, `constraint_variables.md`, `template_recommendations.md` (3)

2. **RAG resilience check**: If `meta_buffer.md` missing/empty (Agent 1A timed out):
   - Spawn lightweight RAG-retry agent (haiku, <2 min, 3 queries only):
     1. get_common_vulnerabilities(protocol_type)
     2. get_attack_vectors(primary_pattern)
     3. search_solodit_live(protocol_category=[category], language='Move', quality_score=3, max_results=10)
   - If retry fails: proceed with empty meta_buffer.md

3. **Read summary artifacts**: template_recommendations.md (BINDING MANIFEST), attack_surface.md, detected_patterns.md

4. **Write recon_summary.md**:
```markdown
# Recon Summary -- Aptos Move
1. **Build Status**: {success/failed}
2. **Package**: {name from Move.toml}
3. **Modules**: {count} totaling {lines} lines
4. **Entry Functions**: {count} (user-callable attack surface)
5. **External Module Dependencies**: {count} -- {names}
6. **Token Standard**: {Coin<T> / FungibleAsset / both}
7. **Detected Patterns**: {list flags}
8. **Recommended Templates**: {list with brief reason each}
9. **Move Prover Status**: {available and passed / unavailable / specs not found}
10. **Upgrade Policy**: {compatible/immutable/not specified}
11. **Artifacts Written**: {list all files}
12. **Coverage Gaps**: {tools that failed, missing analysis}
```

5. **Hard gate**: ALL artifacts must exist before Phase 2. If any missing, re-spawn the responsible agent.
