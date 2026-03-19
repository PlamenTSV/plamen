# Phase 1: Recon Agent Prompt Template - Sui Move

> **Usage**: Orchestrator reads this file and spawns recon agents with these prompts for Sui Move packages.
> Replace `{path}`, `{scratchpad}`, `{docs_path_or_url_if_provided}`, `{network_if_provided}`, `{scope_file_if_provided}`, `{scope_notes_if_provided}` with actual values. Omit lines for empty placeholders.
>
> **ORCHESTRATOR SPLIT DIRECTIVE**: Same 4-agent split as EVM/Solana to prevent timeout:
>
> | Agent | Tasks | Model | Why Separate |
> |-------|-------|-------|-------------|
> | **1A: RAG-only** | TASK 0 steps 1-5 (vuln-db + Solodit) | sonnet | Mechanical query+format - no deep reasoning needed |
> | **1B: Docs + External + Fork** | TASK 0 step 6 (fork ancestry), TASK 3, TASK 11 | opus | Trust model inference requires reasoning |
> | **2: Build + Static + Tests** | TASK 1, 2, 8, 9 | sonnet | Tool execution+output formatting - no deep reasoning needed |
> | **3: Patterns + Surface + Templates** | TASK 4, 5, 6, 7, 10 | opus | Attack surface + template selection requires reasoning |
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
You are Recon Agent 1A (RAG-only) for a Sui Move package audit.

PROJECT_PATH: {path}
SCRATCHPAD: {scratchpad}

## RESILIENCE RULES
1. **MCP call fails/times out?** -> Document the failure and CONTINUE. Never retry more than once.
2. **Write-first principle**: Write partial results before slow external calls.
3. **No task is blocking**: Skip stuck tasks, document why, move on.

## TASK 0: RAG Meta-Buffer Retrieval

### Step 1: Classify Protocol Type
Scan .move source files (exclude build/, tests/) to determine type:

| Protocol Type | Key Indicators | Query |
|---------------|----------------|-------|
| staking | stake, unstake, validator, delegation, staking_pool, sui_system | `get_common_vulnerabilities(protocol_type='staking')` |
| lending | borrow, lend, collateral, liquidation, obligation, reserve | `get_common_vulnerabilities(protocol_type='lending')` |
| dex | swap, liquidity, pool, reserves, amm, tick, clmm | `get_common_vulnerabilities(protocol_type='dex')` |
| vault | deposit, withdraw, shares, strategy, vault | `get_common_vulnerabilities(protocol_type='vault')` |
| bridge | bridge, wormhole, relay, message, portal | `get_common_vulnerabilities(protocol_type='bridge')` |
| governance | vote, propose, timelock, quorum, dao | `get_common_vulnerabilities(protocol_type='governance')` |
| nft | collection, mint, marketplace, royalty, kiosk | `get_common_vulnerabilities(protocol_type='nft')` |
| orderbook | order_book, bid, ask, clob, limit_order, deepbook | `get_common_vulnerabilities(protocol_type='dex')` |

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
4. **MANDATORY**: mcp__unified-vuln-db__search_solodit_live(protocol_category=['{DeFi/Bridge/etc.}'], tags=['{relevant}', 'Sui', 'Move'], language='Move', quality_score=3, sort_by='Quality', max_results=20)
5. If SEMI_TRUSTED_ROLE detected: search_solodit_live(keywords='reward compound timing front-run keeper operator admin capability', impact=['HIGH','MEDIUM'], max_results=15)
6. search_solodit_live(keywords='Move sui object ownership PTB shared type safety', impact=['HIGH','CRITICAL'], max_results=15)
7. search_solodit_live(keywords='Move ability constraint copy drop store key hot potato', impact=['HIGH','MEDIUM'], max_results=10)

### Step 3: Synthesize into {SCRATCHPAD}/meta_buffer.md
```markdown
# Meta-Buffer: {PROTOCOL_NAME} ({PROTOCOL_TYPE}) -- Sui Move
## Protocol Classification
- **Type**: {protocol_type}
- **Runtime**: Sui Move
- **Key Indicators**: {what patterns led to classification}
## Common Vulnerabilities for {PROTOCOL_TYPE} on Sui
| Category | Frequency | Key Modules/Functions to Check |
## Sui Move-Specific Vulnerability Classes
| Class | Description | Check |
|-------|-------------|-------|
| Missing ability constraints | Struct with `copy` on value tokens or `drop` on obligations | All struct definitions with abilities |
| Object ownership confusion | Shared vs owned vs frozen object usage mismatch | All transfer/share/freeze calls |
| PTB composability exploit | Multi-step atomic transaction manipulates state across calls | All public functions that read shared state |
| Package upgrade compatibility | Upgraded package breaks struct layouts or invariants | Move.toml published-at, UpgradeCap usage |
| Shared object contention | Race conditions on shared objects in concurrent txs | All shared object mutations |
| Hot potato bypass | Receipt/ticket pattern missing drop prevention | Structs without drop+store+copy+key |
| Type confusion in generics | Generic T instantiated with unexpected type | All generic function signatures |
| Dynamic field manipulation | Unauthorized add/remove/borrow of dynamic fields | All dynamic_field/dynamic_object_field calls |
| Bit-shift abort DoS | Shift by >= type width causes Move VM abort | All << and >> operations |
| Unchecked arithmetic overflow | u64/u128/u256 overflow causes abort or wrapping | All arithmetic in critical paths |
| Missing UID verification | Object UID not properly tied to type identity | Custom UID management |
| Clock manipulation | Reliance on Clock without understanding validator timestamp bounds | All clock::timestamp_ms usage |
| One-Time Witness forgery | OTW pattern not properly consuming the witness | init() functions |
| Frozen object mutation | Attempting to mutate frozen (immutable) objects | All &mut references to shared state |
| Coin splitting/joining errors | Incorrect Coin<T> split/join leading to fund loss | All coin::split, coin::join, coin::zero |
| key-only vs key+store confusion | Object with `key+store` can be publicly transferred by anyone | All object definitions -- capability/admin objects should be `key`-only |

**NOTE**: Sui Move has NO reentrancy vulnerability class -- the Move VM does not support callbacks or hooks during execution. Do NOT look for reentrancy patterns.
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
2. {question derived from Sui-specific attack vectors}
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
You are Recon Agent 1B (Docs + External + Fork) for a Sui Move package audit.

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

## TASK 0 Step 6: Fork Ancestry Research -- Sui Parent Packages

Read ~/.claude/agents/skills/sui/fork-ancestry/SKILL.md (if exists) or apply the methodology below with Sui-specific parent detection:

### Known Sui Parent Packages

| Parent | Detection Patterns |
|--------|-------------------|
| Cetus | `cetus\|clmm\|tick\|concentrated_liquidity\|cetus_clmm\|cetus_router` |
| Suilend | `suilend\|lending_market\|reserve\|obligation\|refresh\|suilend_` |
| NAVI | `navi\|navi_protocol\|lending\|pool_manager\|incentive\|navi_` |
| Scallop | `scallop\|s_coin\|market\|obligation\|borrow_dynamics\|scallop_` |
| Turbos | `turbos\|pool_factory\|position_manager\|turbos_clmm\|turbos_` |
| DeepBook | `deepbook\|clob\|order_book\|custodian\|deep_book\|clob_v2` |
| Aftermath | `aftermath\|af_lp\|pool_registry\|amm_v2\|aftermath_` |
| Bucket | `bucket\|bucket_protocol\|tank\|well\|fountain\|buck` |
| Kriya | `kriya\|kriya_dex\|spot_dex\|kriya_clmm` |
| FlowX | `flowx\|flowx_clmm\|router\|pair_v2\|flowx_` |
| Kai Finance | `kai\|vault\|strategy\|kai_finance\|kai_vault` |
| Haedal | `haedal\|hasui\|staked_sui\|validator_staking\|haedal_` |
| Sui Staking | `staking_pool\|validator\|sui_system\|delegation\|validator_cap` |
| Celer | `celer\|cbridge\|wormhole_bridge\|bridge_message` |
| Wormhole | `wormhole\|vaa\|guardian\|emitter_chain\|wormhole_` |
| Pyth | `pyth\|price_feed\|price_info\|price_identifier\|pyth_` |

**Detection**:
1. Grep .move source files for patterns (exclude build/, tests/)
2. Check Move.toml `[dependencies]` for parent package names or git URLs
3. Check README for fork attribution or reference to parent protocol
4. Compare module/struct/function names against known parent interfaces

**For each detected parent**:
- Query Solodit + Tavily for known vulnerabilities affecting the parent
- Analyze divergences: modified constraints, changed access control, added/removed functions, modified object ownership model, changed ability constraints, altered shared object patterns
- Append to {SCRATCHPAD}/meta_buffer.md under '## Fork Ancestry Analysis'

> **SKIP POLICY**: If web searches fail, write 'Fork ancestry: web search unavailable' and continue with code-level divergence analysis only.

## TASK 3: Documentation Context

1. Read README.md, docs/ folder, or fetch provided URL
2. Extract: protocol purpose, key invariants, trust model, external package dependencies
3. Identify:
   - Authority model (AdminCap, OwnerCap, Publisher, multi-sig, governance)
   - Upgradeability (UpgradeCap retained? make_immutable called? upgrade policy?)
   - External package dependencies (verified/audited? version-pinned?)
   - Object ownership model (which objects are shared vs owned vs frozen vs wrapped?)
   - Token model (Coin<T>, Balance<T>, custom token types?)
   - One-Time Witness (OTW) usage in init()
4. If no docs: note 'Inferring purpose from code'
5. **Trust Assumption Table** (MANDATORY): From ASSUMPTIONS.txt, docs, README, code comments, and access control patterns, extract ALL trust assumptions into a structured table in design_context.md:

| # | Actor | Trust Level | Assumption | Source |
|---|-------|-------------|------------|--------|
| 1 | {role, e.g., AdminCap holder} | FULLY_TRUSTED | Will not act maliciously | {source} |
| 2 | {role, e.g., operator} | SEMI_TRUSTED(bounds: {on-chain limit}) | Cannot exceed {stated bounds} | {source} |
| 3 | - | PRECONDITION | {config state assumed at launch, e.g., UpgradeCap frozen} | {source} |
| 4 | Package publisher | FULLY_TRUSTED | Package publisher is protocol team | {source} |
| 5 | Shared object creators | {level} | {assumption about who can create shared objects} | {source} |

Trust levels: `FULLY_TRUSTED` (will not act maliciously -- e.g., multisig, governance, DAO), `SEMI_TRUSTED(bounds: ...)` (bounded by on-chain parameters), `PRECONDITION` (deployment/config state assumption), `UNTRUSTED` (default for users, external packages).
If no explicit trust documentation exists, infer from capability patterns and access control and note `Source: inferred`.

Write to {SCRATCHPAD}/design_context.md

## TASK 11: External Package Verification (MANDATORY)

> **SKIP POLICY**: If Tavily calls fail, skip that step, document 'UNAVAILABLE', and continue.

For EACH critical external package the protocol depends on:

1. **Find package addresses**: Search codebase for:
   - `published-at` in Move.toml
   - Hardcoded address constants (e.g., `@0x...`)
   - Named addresses in Move.toml `[addresses]` section
   - Dependency declarations in Move.toml `[dependencies]` section
2. **Verify known packages**: Cross-reference against well-known packages:
   - `0x1` (Move stdlib)
   - `0x2` (Sui framework -- sui::coin, sui::object, sui::transfer, sui::tx_context, etc.)
   - `0x3` (Sui system -- sui_system, staking_pool, validator)
   - known DeFi protocol package addresses (identified via import analysis)
   - Known DeFi protocol addresses (identify from Move.toml dependencies and import statements)
3. **Check dependency versioning**: Is the dependency pinned to a specific revision/digest?
   - Git dependencies with `rev = ...` -> version-pinned
   - Git dependencies without rev -> FLOATING (risk of upstream changes)
   - Local path dependencies -> document
4. **Check hardcoded vs dynamic**: Are external package addresses hardcoded or passed as arguments?
   - Hardcoded in Move.toml named addresses -> STATIC (safer)
   - Passed as function arguments -> DYNAMIC (need runtime validation)
5. **Document unknown packages**: Dependencies that are NOT well-known Sui framework/stdlib
   - Search Tavily for audit history -- **skip if fails**
   - Mark as UNVERIFIED if no audit found
6. **Token/Coin transferability**: For each token/coin type the protocol handles:
   - `Coin<T>` with `store` ability: Can be transferred unsolicited via `transfer::public_transfer`
   - Objects with `store` ability: Can be transferred to any address
   - Shared objects: Can be mutated by any transaction that references them
   - Objects without `store`: Can only be transferred by the owning module
   - Does the protocol track balances internally or rely on `coin::value()`/`balance::value()` directly?

Write to {SCRATCHPAD}/external_production_behavior.md

**If package addresses unavailable**: Mark all external deps as 'UNVERIFIED', add severity note (Rule 4 adversarial assumption), set severity floor MEDIUM for HIGH worst-case.

Return: 'DONE: design_context.md, external_production_behavior.md written. Fork ancestry: {found/none}. External packages: {N} verified, {M} unverified'
")
```

---

## Agent 2: Build + Static Analysis + Tests

```
Task(subagent_type="general-purpose", prompt="
You are Recon Agent 2 (Build + Static + Tests) for a Sui Move package.

PROJECT_PATH: {path}
SCRATCHPAD: {scratchpad}

## RESILIENCE RULES
1. **Build/tool call fails?** -> Document failure and CONTINUE. Never retry more than once.
2. **Write-first principle**: Write partial results before slow operations.
3. **No task is blocking**: Skip stuck tasks, document why, move on.

## TASK 1: Build Environment

> **PATH note**: On Windows, `sui` may not be in Claude Code's default PATH. Prefix Bash calls with: `export PATH="$HOME/.local/bin:$PATH" &&` if not found on first attempt.

1. Check for Move.toml (primary manifest for Sui Move packages)
1b. Verify toolchain availability before building:
   - `sui --version` or `sui client --version` -- if missing, document as TOOLCHAIN WARNING
   - `sui move --version` (move compiler) -- if missing, document as TOOLCHAIN WARNING
   If any required tool is missing, document in build_status.md and attempt build anyway (may fail gracefully).
1c. **Dependency Recovery** (before first build attempt):
   - Run `git submodule update --init --recursive`
   - If Move.toml references git dependencies: verify network access, run `sui move build` once to trigger dependency resolution
2. Read Move.toml for:
   - Package name, version, edition
   - `published-at` address (indicates production deployment)
   - `[addresses]` section (named addresses)
   - `[dependencies]` section (external packages, Sui framework version)
   - `[dev-dependencies]` section (test-only dependencies)
   - `[dev-addresses]` section (test-only address overrides)
3. Build: `sui move build` in the package directory
   - If multiple packages exist (workspace), build each separately
   - Note any compilation warnings
4. If build fails, try:
   - Check if `sui` CLI version matches the edition in Move.toml
   - Try `sui move build --skip-fetch-latest-git-deps` (avoid network dependency fetching)
   - After 3 attempts, document failure and continue
5. Check for Move.lock file (dependency resolution lockfile)

Write to {SCRATCHPAD}/build_status.md:
```markdown
# Build Status
- **Language**: Sui Move (edition: {edition from Move.toml})
- **Sui CLI Version**: {version or MISSING}
- **Build Result**: success/failed ({error})
- **Package Name**: {name}
- **Published At**: {address or NONE}
- **Dependencies**: {list from Move.toml}
- **Named Addresses**: {list}
- **Compilation Warnings**: {list or none}
```

## TASK 2: Static Analysis Artifacts

Sui Move does not have a Slither equivalent. Extract program structure using grep as the PRIMARY method.

### Function inventory
Grep in .move files (exclude build/, tests/ directories):
- `public fun ` -> public functions (callable by any package)
- `public(package) fun ` -> package-visible functions (callable by friend modules only)
- `public entry fun ` -> entry functions (callable directly from transactions/PTBs)
- `entry fun ` -> entry-only functions (callable from transactions but NOT other Move code)
- `fun ` (without public/entry) -> private functions (internal only)
- For each function: note parameters (especially &mut references to shared objects, Coin<T>, Balance<T>)
- Flag all functions that take `&mut TxContext` (can create objects, transfer, etc.)

Write to {SCRATCHPAD}/function_list.md with columns:
| Module | Function | Visibility | Entry? | Parameters (key types) | Returns | Notes |

### Struct/Object inventory
Grep for struct definitions:
- `struct .* has ` -> structs with explicit abilities
- `struct .* {` -> all struct definitions
- For each struct: note abilities (`key`, `store`, `copy`, `drop`)
  - `key` = this is an object (has UID)
  - `store` = can be stored in other objects or transferred freely
  - `copy` = can be duplicated (DANGEROUS for value tokens)
  - `drop` = can be silently discarded (DANGEROUS for obligations/receipts)
  - No abilities (phantom/hot potato) = must be explicitly consumed
- Flag structs with `key` but missing `store` (restricted transfer)
- Flag structs with `copy` that hold `Balance<T>` or `Coin<T>` fields -> VALUE_TOKEN_COPY_RISK
- Flag structs without `drop` that are used as receipts/tickets -> HOT_POTATO (intentional, verify pattern)

Write to {SCRATCHPAD}/state_variables.md with columns:
| Module | Struct | Abilities | Is Object? | Key Fields | Notes |

### Cross-module call graph
Grep for inter-module calls:
- `use .*::` -> module imports
- `{module}::{function}` -> cross-module function calls
- `transfer::transfer\|transfer::public_transfer\|transfer::share_object\|transfer::public_share_object\|transfer::freeze_object\|transfer::public_freeze_object` -> object lifecycle operations
- `dynamic_field::add\|dynamic_field::remove\|dynamic_field::borrow\|dynamic_field::borrow_mut\|dynamic_field::exists_` -> dynamic field operations
- `dynamic_object_field::add\|dynamic_object_field::remove\|dynamic_object_field::borrow\|dynamic_object_field::borrow_mut` -> dynamic object field operations
- Note: Full call graph analysis is limited without a Move-native static analyzer

Write to {SCRATCHPAD}/call_graph.md

### Access control / Guards (modifiers equivalent)
Grep for access control patterns:
- `assert!` statements with error codes -> document all assertion guards
- `abort ` statements -> document abort conditions
- Capability pattern: functions requiring `&AdminCap`, `&OwnerCap`, `&Publisher`, or similar capability references
- `tx_context::sender(ctx)` comparisons -> address-based access control
- `object::id(` comparisons -> object-identity-based access control
- Friend declarations: `friend ` -> module-level access control

Write to {SCRATCHPAD}/modifiers.md with columns:
| Module | Function | Guard Type | Condition | Error Code |

### Events
Grep for event definitions and emissions:
- `struct .*Event.* has copy, drop` -> event struct definitions
- `event::emit(` -> event emission sites
- `emit(` -> shortened event emission

Write to {SCRATCHPAD}/event_definitions.md

### External interfaces
Grep for external package usage:
- `use ` statements referencing non-local modules
- Named addresses from Move.toml that are not the package itself
- `friend ` declarations (who can call package-visible functions)

Write to {SCRATCHPAD}/external_interfaces.md

## TASK 8: Run Static Detectors

Run targeted grep checks for Sui Move-specific vulnerability patterns:

### Ability Safety
- `struct .* has copy` on structs containing `Balance<\|Coin<\|ID\|UID` -> UNSAFE_COPY_ON_VALUE (Critical pattern: allows duplication of value-bearing objects)
- `struct .* has drop` on structs used as receipts/tickets/obligations -> UNSAFE_DROP_ON_OBLIGATION (allows skipping required actions)
- `struct .* has store` on structs with sensitive capabilities -> UNRESTRICTED_STORE (allows wrapping/transferring sensitive objects)
- Structs with `key` missing `store` -> RESTRICTED_TRANSFER (intentional? verify)

### Object Ownership
- `transfer::share_object\|transfer::public_share_object` -> SHARED_OBJECT_CREATION (document all sharing points, verify only called in init or controlled contexts)
- `transfer::freeze_object\|transfer::public_freeze_object` -> FROZEN_OBJECT_CREATION (verify immutability is intended)
- `transfer::transfer` vs `transfer::public_transfer` -> TRANSFER_PATTERN (transfer requires module, public_transfer requires store)
- Objects created with `object::new(ctx)` but never transferred/shared/frozen -> ORPHANED_OBJECT_RISK

### Coin/Balance Safety
- `public fun ` or `public entry fun ` that take `Coin<` parameters -> COIN_HANDLING_PUBLIC (document all Coin-handling public functions)
- `coin::zero<` -> ZERO_COIN_CREATION (verify proper handling)
- `coin::split\|coin::join` in loops -> LOOP_COIN_OPS (gas cost concern)
- `balance::destroy_zero` without preceding zero-check -> UNCHECKED_DESTROY_ZERO (will abort if non-zero)
- `coin::into_balance\|balance::join\|balance::split` -> BALANCE_OPS (trace fund flow)

### Arithmetic Safety
- `as u64\|as u128\|as u256\|as u8\|as u16\|as u32` -> UNSAFE_CAST (truncation risk, overflow/underflow)
- `<<\|>>` -> BIT_SHIFT_RISK (shift by >= type bit-width causes Move VM abort, DoS vector)
- `/ ` followed by `* ` on the same variable -> DIVIDE_BEFORE_MULTIPLY (precision loss)
- `% ` (modulo) -> verify divisor is non-zero

### Init Pattern
- `fun init(witness:` or `fun init(otw:` -> OTW_INIT_PATTERN (One-Time Witness usage)
- `init(` functions -> INIT_PATTERN (verify one-time execution guarantee)
- `init` function creating shared objects -> INIT_SHARED_CREATION (verify cannot be re-called)
- Publisher creation: `package::claim(` -> PUBLISHER_CREATION

### Hot Potato Pattern
- Structs without `drop`, `copy`, `store`, or `key` abilities -> HOT_POTATO_CANDIDATE
- Functions returning hot potato types -> document creation sites
- Functions consuming hot potato types -> document destruction sites
- Gap between creation and destruction -> verify all paths consume the potato
- `public fun .*destroy\|public fun .*burn\|public fun .*consume\|public fun .*redeem` -> DESTRUCTION_SITE (document all explicit destruction/consumption functions)

### Dynamic Fields
- `dynamic_field::add\|dynamic_object_field::add` -> DYNAMIC_FIELD_ADDITION (is it bounded? can it grow unboundedly?)
- `dynamic_field::remove\|dynamic_object_field::remove` -> DYNAMIC_FIELD_REMOVAL (who can remove? leftover fields on object deletion?)
- `dynamic_field::borrow_mut\|dynamic_object_field::borrow_mut` -> DYNAMIC_FIELD_MUTATION (who can mutate?)
- `object::delete(` with remaining dynamic fields -> ORPHANED_DYNAMIC_FIELDS (fields become inaccessible)

### Clock/Timestamp
- `clock::timestamp_ms\|Clock` -> CLOCK_USAGE (validator-controlled timestamp, ~2-3 second granularity)
- Timestamp comparisons with tight bounds (< 1 minute) -> TIGHT_TIMESTAMP_BOUND (unreliable on Sui)

### Package Upgrade
- `upgrade_policy\|UpgradeCap` -> UPGRADE_CAP_USAGE (who holds the UpgradeCap?)
- `package::make_immutable` -> IMMUTABLE_PACKAGE (good -- package cannot be upgraded)
- UpgradeCap transferred to an address -> UPGRADE_CONTROL (who controls upgrades?)
- Missing `make_immutable` and UpgradeCap not frozen -> UPGRADEABLE_PACKAGE (verify upgrade path is secure)

### Miscellaneous
- `vector::length` in loop bounds with external data -> UNBOUNDED_LOOP (DoS via gas exhaustion)
- `while (true)\|loop {` -> INFINITE_LOOP_RISK (verify termination)
- `sui::test_scenario\|sui::test_utils` in non-test files -> TEST_CODE_IN_PROD
- `#[test_only]` annotations -> verify test-only code is properly gated

Write to {SCRATCHPAD}/static_analysis.md

## TASK 9: Run Test Suite

- Run `sui move test` in the package directory
- If multiple packages, test each separately
- If specific test filter needed: `sui move test --filter {name}`
- Note test count, pass/fail, and any test warnings
- If tests fail, note as TEST HEALTH WARNING
- Check for test coverage gaps: modules with 0 tests

Write to {SCRATCHPAD}/test_results.md

Return: 'DONE: Build {success/failed}, {N} functions, {M} structs/objects, {K} static issues, tests: {pass/fail/skip}'
")
```

---

## Agent 3: Patterns + Surface + Templates

```
Task(subagent_type="general-purpose", prompt="
You are Recon Agent 3 (Patterns + Surface + Templates) for a Sui Move package.

PROJECT_PATH: {path}
SCRATCHPAD: {scratchpad}

## RESILIENCE RULES
1. **Write-first principle**: Write partial results before any slow operation.
2. **No task is blocking**: Skip stuck tasks, document why, move on.

## TASK 4: Contract Inventory

1. Count lines of all .move files (exclude build/, tests/ directories)
2. List each module with: line count, public function count, struct count, shared object count
3. List helper/utility modules
4. Note total package count if multi-package workspace
5. **Scope filtering**: If SCOPE_FILE is set, read it and mark modules as IN_SCOPE or OUT_OF_SCOPE. If SCOPE_NOTES is set, use them to refine scope. If neither is set, all non-library modules are in scope.

Write to {SCRATCHPAD}/contract_inventory.md:
```markdown
# Contract Inventory -- Sui Move

| Module | Path | Lines | Public Fns | Entry Fns | Structs | Shared Objects | Description |
|--------|------|-------|-----------|-----------|---------|---------------|-------------|
| {name} | {path} | {N} | {N} | {N} | {N} | {N} | {brief} |

**Total**: {N} modules, {L} lines of Move code
```

## TASK 5: Attack Surface Discovery

### Part A: External Package Calls
For each external package dependency (non-stdlib, non-sui-framework):

| External Package | Address/Source | Call Sites (file:line) | Functions Called | Objects Passed | Return Values Used |
|-----------------|----------------|----------------------|-----------------|----------------|-------------------|

For each external call:
1. Package address hardcoded in Move.toml or passed dynamically?
2. Is the dependency version-pinned (git rev)?
3. What objects/capabilities are passed to the external package?
4. Are return values validated before use?
5. Could the external package upgrade and change behavior?

### Part B: Object Inventory Matrix

| Object (struct name) | Module | Abilities | Ownership Model | UID Tracking | Created By | Transferred/Shared By | Deleted By | Dynamic Fields? |
|---------------------|--------|-----------|----------------|-------------|-----------|---------------------|-----------|----------------|

Ownership models:
- **Owned**: Transferred to a specific address via `transfer::transfer` or `transfer::public_transfer`
- **Shared**: Made shared via `transfer::share_object` or `transfer::public_share_object` (anyone can use in tx)
- **Frozen**: Made immutable via `transfer::freeze_object` or `transfer::public_freeze_object`
- **Wrapped**: Stored as field inside another object
- **Dynamic**: Attached as dynamic field to another object

For each shared object: WHO can mutate it? (any transaction vs capability-gated)

### Part C: Token/Coin Mapping

| Token Type | Coin<T> or Balance<T> | Where Held (object/module) | Who Can Mint | Who Can Burn | Transfer Constraints | Internal Balance Tracking? | Unsolicited Transfer? |
|-----------|----------------------|---------------------------|-------------|-------------|---------------------|--------------------------|---------------------|

For **Unsolicited Transfer?**:
- `Coin<T>` with `store`: YES -- can be sent via `transfer::public_transfer` to any address
- Objects with `store` containing `Balance<T>`: YES -- wrapping object can be transferred
- Shared objects holding `Balance<T>`: Mutable by any tx referencing the object
- `Balance<T>` inside owned objects: NO direct unsolicited transfer (but object owner can manipulate)

For **Internal Balance Tracking?**: Does the protocol maintain its own accounting separate from `balance::value()` / `coin::value()`? If NO, donation/inflation attacks may be possible.

### Part D: Dynamic Field Tracking

| Parent Object | Field Name/Key Type | Value Type | Who Can Add | Who Can Remove | Who Can Mutate | Bounded? |
|--------------|-------------------|-----------|-----------|--------------|---------------|---------|

Flag unbounded dynamic field additions (no limit on number of fields that can be added).
Flag dynamic fields that survive parent object deletion (orphaned fields).

### Signal Elevation Tags

During attack surface analysis, tag risk signals that warrant explicit follow-up with `[ELEVATE]`:

Apply `[ELEVATE]` when you observe:
- Shared object without capability-gated mutation -> `[ELEVATE:SHARED_UNGUARDED] Verify shared object mutation safety -- any tx can mutate`
- PTB-composable public functions that read and write shared state -> `[ELEVATE:PTB_COMPOSE] Verify single-tx composition safety -- multiple calls in one PTB may violate assumptions`
- Package dependency on upgradeable third-party (no rev pin, or UpgradeCap not frozen) -> `[ELEVATE:PKG_UPGRADE] Verify upgrade compatibility -- upstream changes may break protocol`
- Asymmetric branch sizes in profit/loss or deposit/withdraw logic -> `[ELEVATE:BRANCH_ASYMMETRY] Verify state completeness in shorter branch (Rule 17)`
- Fork ancestry match detected -> `[ELEVATE:FORK_ANCESTRY:{parent}] Verify known {parent} vulnerability classes addressed`
- Object wrapping without corresponding unwrap path -> `[ELEVATE:WRAPPED_STUCK] Verify wrapped object exit path -- object may become permanently inaccessible`
- Struct with `copy` ability holding value-bearing fields -> `[ELEVATE:COPY_VALUE] Verify copy safety -- value token duplication risk`
- Struct without `drop` that can reach dead-end code path -> `[ELEVATE:HOT_POTATO_STUCK] Verify hot potato consumption -- all code paths must consume`
- `init()` sharing objects that could be front-run -> `[ELEVATE:INIT_FRONTRUN] Verify initialization ordering safety`
- Dynamic fields added without bound -> `[ELEVATE:UNBOUNDED_DFIELD] Verify dynamic field growth is bounded`
- `UpgradeCap` not frozen or destroyed in init -> `[ELEVATE:UPGRADE_CAP] Verify package upgrade security`

Write `[ELEVATE]` tags directly into the relevant section of `attack_surface.md`.

Write to {SCRATCHPAD}/attack_surface.md

## TASK 6: Pattern Detection

Grep in .move source files (exclude build/, tests/ directories):

| Pattern | Flag |
|---------|------|
| `coin::split\|coin::join\|coin::zero\|Coin<\|Balance<` | COIN_FLOW |
| `object::new\|object::delete\|UID\|ID` | OBJECT_MODEL |
| `transfer::share_object\|transfer::public_share_object` | SHARED_OBJECT |
| `transfer::freeze_object\|transfer::public_freeze_object` | FROZEN_OBJECT |
| `dynamic_field::\|dynamic_object_field::` | DYNAMIC_FIELDS |
| `oracle\|price_feed\|pyth\|switchboard\|supra\|PriceInfoObject` | ORACLE |
| `clock::timestamp_ms\|Clock` | TEMPORAL |
| `flash_loan\|borrow.*repay\|Receipt` (structs without drop/store/copy/key) | FLASH_LOAN |
| `balance::value\|coin::value\|balance::join\|balance::split` | BALANCE_DEPENDENT |
| `admin\|AdminCap\|governance\|OwnerCap\|publisher\|Publisher` | SEMI_TRUSTED_ROLE |
| `shares\|allocation\|distribute\|proportional\|vest` | SHARE_ALLOCATION |
| `rate\|emission\|mint\|supply\|inflation\|fee\|reward` | MONETARY_PARAMETER |
| `bridge\|cross.*chain\|relay\|wormhole\|layerzero` | CROSS_CHAIN |
| `migrate\|upgrade\|v2\|deprecated\|legacy\|UpgradeCap` | MIGRATION |
| `init(.*TxContext\|init(.*OTW` | OTW_PATTERN |
| `public(package)` | PACKAGE_VISIBILITY |
| third-party deps in Move.toml `[dependencies]` (not Sui/MoveStdlib) | EXTERNAL_LIB |
| `upgrade_policy\|UpgradeCap\|make_immutable` | PACKAGE_UPGRADE |
| `vector::length\|vector::push_back\|vector::pop_back` in loops | VECTOR_LOOP |
| `<<\|>>` | BIT_SHIFT |
| `as u64\|as u128\|as u256\|as u8` | UNSAFE_CAST |
| `copy\b` ability on structs with value fields | COPY_ON_VALUE |
| `has key\|has key, store\|has store\|has copy\|has drop` | ABILITY_DECLARATION |
| `friend ` | FRIEND_DECLARATION |
| `#\[allow(unused\|lint_allow` | SUPPRESSED_WARNING |
| `ecdsa_k1::secp256k1_verify\|ed25519::ed25519_verify\|ecdsa_r1\|hash::blake2b256\|hmac::hmac_sha3_256` | HAS_SIGNATURES |

Write to {SCRATCHPAD}/detected_patterns.md with format:
```markdown
# Detected Patterns -- Sui Move

| Flag | Count | Locations (file:line) | Severity Signal |
|------|-------|-----------------------|----------------|
| {FLAG} | {N} | {top 5 locations} | {HIGH/MEDIUM/LOW/INFO} |

## Flags Summary
Active flags: [{comma-separated list}]
```

## TASK 7: Prep Artifacts

**Admin/Capability-gated functions**: Grep for functions requiring capability references:
- `&AdminCap\|&OwnerCap\|&TreasuryCap\|&Publisher\|&UpgradeCap\|&ManagerCap`
- `assert!.*sender\|assert!.*owner` (address-based access control)
- `public(package) fun` (module-level access control via friend)

Write to {SCRATCHPAD}/setter_list.md with structure:
```markdown
# Privileged Functions -- Sui Move

## Capability-Gated Functions
| Function | Module | Required Capability | What It Modifies |
|----------|--------|-------------------|-----------------|

## Address-Gated Functions
| Function | Module | Address Check | What It Modifies |
|----------|--------|--------------|-----------------|

## Package-Visible Functions (friend access)
| Function | Module | Friend Modules | What It Modifies |
|----------|--------|---------------|-----------------|

## Permissionless State-Modifiers
| Function | Module | Visibility | State Modified | Risk Level |
```

**Events**: Grep `event::emit\|emit(` -> {SCRATCHPAD}/emit_list.md

**Constraint variables**: Grep `min\|max\|cap\|limit\|rate\|fee\|threshold\|factor\|multiplier\|ratio\|weight\|duration\|delay\|period\|decimal\|precision\|basis_point\|bps`.
- For each: find setter function, check bounds enforcement
- Mark UNENFORCED for variables with setters but no bounds
Write to {SCRATCHPAD}/constraint_variables.md

**Setter x Emit Cross-Reference**: For each setter/privileged function, check if it emits an event. Flag SILENT SETTERs (setter modifies state but emits no event).

## TASK 10: Template Recommendations

### Sui-Specific Templates (Always Required)

These templates are ALWAYS required for Sui Move audits:

- **ABILITY_ANALYSIS** -- Foundational Move security: verify `copy`, `drop`, `store`, `key` abilities are correctly assigned on every struct. Check for `copy` on value tokens, `drop` on obligations, missing `store` where transferability is needed.
- **BIT_SHIFT_SAFETY** -- Move VM aborts on shift >= type width. Check all `<<` and `>>` for DoS risk via abort.
- **TYPE_SAFETY** -- Generic type parameter exploitation. Verify generic functions cannot be instantiated with types that bypass intended constraints (e.g., `Coin<FAKE>` passed where `Coin<SUI>` expected).
- **OBJECT_OWNERSHIP** -- Object lifecycle security: verify shared/owned/frozen/wrapped transitions are correct, verify UID is properly managed, verify object deletion cleans up dynamic fields.
- **FORK_ANCESTRY** -- Always required: historical vulnerability inheritance from parent protocols.

### Conditional Templates (Triggered by Flags)

For EACH recommended template, provide:
- **Trigger**: What pattern/flag triggered this
- **Relevance**: Why this matters for this protocol
- **Instantiation Parameters**: Protocol-specific values
- **Key Questions**: Protocol-specific investigation questions

Available conditional templates:
- PTB_COMPOSABILITY -- PTB flag or shared objects (multi-step atomic transaction exploitation)
- PACKAGE_VERSION_SAFETY -- PACKAGE_UPGRADE flag (upgrade compatibility, UpgradeCap security)
- DEPENDENCY_AUDIT -- EXTERNAL_LIB flag (third-party package risk, version pinning)
- SEMI_TRUSTED_ROLES -- SEMI_TRUSTED_ROLE flag (AdminCap/OwnerCap analysis, bidirectional)
- TOKEN_FLOW_TRACING -- BALANCE_DEPENDENT flag (Coin/Balance flow, donation attacks)
- ORACLE_ANALYSIS -- ORACLE flag (Pyth/Switchboard/Supra staleness, decimals, zero-return)
- FLASH_LOAN_INTERACTION -- FLASH_LOAN flag (hot-potato-based flash loan, atomic manipulation)
- ZERO_STATE_RETURN -- Vault/first-depositor (empty pool/vault edge cases)
- TEMPORAL_PARAMETER_STALENESS -- TEMPORAL flag (Clock-based staleness, cached parameters)
- ECONOMIC_DESIGN_AUDIT -- MONETARY_PARAMETER flag (fee/rate/emission sustainability)
- EXTERNAL_PRECONDITION_AUDIT -- External package calls (third-party interface assumptions)
- SHARE_ALLOCATION_FAIRNESS -- SHARE_ALLOCATION flag (share/token allocation fairness)
- CROSS_CHAIN_TIMING -- CROSS_CHAIN flag (bridge/cross-chain timing)
- MIGRATION_ANALYSIS -- MIGRATION flag (package upgrade, v2 migration)
- CENTRALIZATION_RISK -- 3+ privileged capability types (concentration of control)
- VERIFICATION_PROTOCOL -- always used by verifiers

---

## BINDING MANIFEST (MANDATORY)

> **CRITICAL**: Orchestrator MUST spawn an agent for every template marked `Required: YES`.

```markdown
## BINDING MANIFEST

| Template | Pattern Trigger | Required? | Reason |
|----------|-----------------|-----------|--------|
| ABILITY_ANALYSIS | Always (Sui) | YES | Foundational Move security -- ability misuse is critical |
| BIT_SHIFT_SAFETY | Always (Sui) | YES | Move abort risk from bit shifts -- DoS vector |
| TYPE_SAFETY | Always (Sui) | YES | Generic type exploitation -- type confusion attacks |
| OBJECT_OWNERSHIP | Always (Sui) | YES | Object lifecycle security -- ownership model correctness |
| FORK_ANCESTRY | Always | YES | Historical vulnerability inheritance |
| PTB_COMPOSABILITY | SHARED_OBJECT flag or 3+ public fns | {YES/NO} | {PTB composition risk with shared state} |
| PACKAGE_VERSION_SAFETY | PACKAGE_UPGRADE flag | {YES/NO} | {UpgradeCap patterns found} |
| DEPENDENCY_AUDIT | EXTERNAL_LIB flag | {YES/NO} | {N third-party dependencies} |
| SEMI_TRUSTED_ROLES | SEMI_TRUSTED_ROLE flag | {YES/NO} | {AdminCap/OwnerCap/publisher patterns} |
| TOKEN_FLOW_TRACING | BALANCE_DEPENDENT or COIN_FLOW flag | {YES/NO} | {direct balance/coin value usage} |
| ORACLE_ANALYSIS | ORACLE flag | {YES/NO} | {Pyth/Switchboard/Supra patterns found} |
| FLASH_LOAN_INTERACTION | FLASH_LOAN flag | {YES/NO} | {flash loan / hot potato receipt patterns} |
| ZERO_STATE_RETURN | Vault/first-depositor | {YES/NO} | {vault/pool pattern found} |
| TEMPORAL_PARAMETER_STALENESS | TEMPORAL flag | {YES/NO} | {Clock-based operations with cached params} |
| ECONOMIC_DESIGN_AUDIT | MONETARY_PARAMETER flag | {YES/NO} | {monetary parameter setters found} |
| EXTERNAL_PRECONDITION_AUDIT | External package calls detected | {YES/NO} | {N external package calls} |
| SHARE_ALLOCATION_FAIRNESS | SHARE_ALLOCATION flag | {YES/NO} | {share/allocation patterns} |
| CROSS_CHAIN_TIMING | CROSS_CHAIN flag | {YES/NO} | {bridge/cross-chain patterns} |
| MIGRATION_ANALYSIS | MIGRATION or PACKAGE_UPGRADE flag | {YES/NO} | {migration/upgrade patterns} |
| CENTRALIZATION_RISK | 3+ capability types | {YES/NO} | {N distinct capability types} |
| VERIFICATION_PROTOCOL | Always | YES | Verification methodology for PoC generation |

### Binding Rules
- ABILITY_ANALYSIS **ALWAYS REQUIRED** for Sui Move packages
- BIT_SHIFT_SAFETY **ALWAYS REQUIRED** for Sui Move packages
- TYPE_SAFETY **ALWAYS REQUIRED** for Sui Move packages
- OBJECT_OWNERSHIP **ALWAYS REQUIRED** for Sui Move packages
- FORK_ANCESTRY **ALWAYS REQUIRED**
- SHARED_OBJECT flag or 3+ public fns -> PTB_COMPOSABILITY **REQUIRED**
- PACKAGE_UPGRADE flag -> PACKAGE_VERSION_SAFETY **REQUIRED**
- EXTERNAL_LIB flag -> DEPENDENCY_AUDIT **REQUIRED**
- SEMI_TRUSTED_ROLE flag -> SEMI_TRUSTED_ROLES **REQUIRED**
- BALANCE_DEPENDENT or COIN_FLOW flag -> TOKEN_FLOW_TRACING **REQUIRED**
- ORACLE flag -> ORACLE_ANALYSIS **REQUIRED**
- FLASH_LOAN flag -> FLASH_LOAN_INTERACTION **REQUIRED**
- TEMPORAL flag -> TEMPORAL_PARAMETER_STALENESS **REQUIRED**
- MONETARY_PARAMETER flag -> ECONOMIC_DESIGN_AUDIT **REQUIRED**
- External package calls detected -> EXTERNAL_PRECONDITION_AUDIT **REQUIRED**
- SHARE_ALLOCATION flag -> SHARE_ALLOCATION_FAIRNESS **REQUIRED**
- CROSS_CHAIN flag -> CROSS_CHAIN_TIMING **REQUIRED**
- MIGRATION or PACKAGE_UPGRADE flag -> MIGRATION_ANALYSIS **REQUIRED**
- VERIFICATION_PROTOCOL **ALWAYS REQUIRED**

### Injectable Skills
{List injectable skills if protocol type matches -- e.g., VAULT_ACCOUNTING for vault protocol type}

### Niche Agent Binding Rules
- MISSING_EVENT flag detected (setter_list.md has MISSING EVENT entries OR emit_list.md shows state-changing functions without events) → EVENT_COMPLETENESS **niche agent** REQUIRED
- HAS_SIGNATURES flag detected (ecdsa_k1/ed25519/ecdsa_r1 verify patterns found) → SIGNATURE_VERIFICATION_AUDIT **niche agent** REQUIRED
- DOCUMENTATION is non-empty AND contains testable protocol claims (fee structures, thresholds, permissions, distribution logic) → SPEC_COMPLIANCE_AUDIT **niche agent** REQUIRED (set `HAS_DOCS` flag)
- HAS_MULTI_CONTRACT flag detected (2+ in-scope modules AND constraint_variables.md shows shared parameters/formulas across modules) → SEMANTIC_CONSISTENCY_AUDIT **niche agent** REQUIRED

### Niche Agents (Phase 4b -- standalone focused agents, 1 budget slot each)

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
# Recon Summary -- Sui Move
1. **Build Status**: {success/failed}
2. **Language**: Sui Move (edition: {edition})
3. **Modules**: {count} totaling {lines} lines
4. **Public Functions**: {count}
5. **Entry Functions**: {count}
6. **Shared Objects**: {count} -- {names}
7. **External Package Dependencies**: {count} -- {names}
8. **Detected Patterns**: {list flags}
9. **Recommended Templates**: {list with brief reason each}
10. **Sui CLI Version**: {version or MISSING}
11. **Package Upgrade Status**: {immutable/upgradeable/unknown}
12. **Artifacts Written**: {list all files}
13. **Coverage Gaps**: {tools that failed}
```

5. **Hard gate**: ALL artifacts must exist before Phase 2. If any missing, re-spawn the responsible agent.
