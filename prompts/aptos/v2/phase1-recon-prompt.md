# Phase 1: Recon Agent (Aptos pipeline)

You are the Reconnaissance Agent. Your job is to gather ALL information
needed for the security audit and write it to the scratchpad. Execute
the recon orchestration plan and write the required handoff artifacts.

**CRITICAL**: Spawn only the recon workers assigned by this prompt. Do NOT ask the user
questions. Do NOT call AskUserQuestion (it is unavailable in this
context). All configuration has already been collected by the wizard
and passed to you via the placeholders below. If a placeholder is empty,
treat the corresponding input as "not provided" and continue.

**Resilience**: If any tool call (web search, aptos, move-prover) fails
or times out, record the failure in the relevant output file and
continue to the next task. Never retry more than once. Partial recon is
better than no recon.

**FIRST ACTION**: Run `ls {SCRATCHPAD}/` to see which mechanical artifacts the deterministic pre-pass already produced. Draft only what's missing (see TURN BUDGET POLICY below). DO NOT re-generate pre-pass artifacts " they're authoritative for the mechanical data they cover.

## Inputs (pre-resolved by the driver)

- **PROJECT_PATH**: {path}
- **SCRATCHPAD**: {scratchpad}
- **LANGUAGE**: {LANGUAGE}
- **MODE**: {MODE}
- **DOCUMENTATION**: {docs_path_or_url_if_provided}
- **NETWORK**: {network_if_provided}
- **SCOPE_FILE**: {scope_file_if_provided}
- **SCOPE_NOTES**: {scope_notes_if_provided}

## RESILIENCE RULES (apply to ALL tasks)

1. **External tool fails/times out?** -> Document the failure and CONTINUE. Never retry more than once.
2. **Web search fails?** -> Note "UNAVAILABLE - web search failed" and CONTINUE.
3. **Write-first principle**: Write partial results before slow external calls.
4. **No task is blocking**: Skip stuck tasks, document why, move on.
5. **Task-local writes are mandatory**: As soon as you finish one assigned task, write its output file immediately before moving to the next.

## TURN BUDGET POLICY - DRAFT-FIRST, ENRICH-LATER (MANDATORY)

You run inside `claude -p` with a hard **--max-turns cap** (currently 80
for recon) and a **--wall-clock timeout** (1500s for small projects,
auto-scaled by the driver for larger ones). A single Read/Bash/Grep/Write
call costs ONE turn. Large codebases (10k+ LOC, 30+ modules) can consume
50+ turns on exploration alone. If you hit the cap or timeout without
writing the required artifacts, the driver's gate fails and the whole
pipeline aborts.

**Rule**: In the FIRST 5—10 turns, write SUBSTANTIVE DRAFTS of ALL 11
required artifacts. A mechanical pre-pass (`recon_prepass.py`) may have
already written some of them " check with `ls {SCRATCHPAD}/` FIRST and
only draft the missing ones. After drafts exist, spend remaining turns
enriching them.

The 11 required artifacts (gate will reject if any is missing). Note:
the SC gate is uniform across all languages " Aptos uses the same
`contract_inventory.md` filename as EVM (not `module_inventory.md`):

| File | Status check | Minimum-valid-draft content |
|---|---|---|
| `{SCRATCHPAD}/design_context.md` | check pre-pass | `# Design Context (draft)\n- Project: best-known target\n- Language: Aptos Move\n- Key Invariants: best-known findings so far\n- Operational Implications: best-known findings so far\n` |
| `{SCRATCHPAD}/contract_inventory.md` | check pre-pass | `# Module Inventory (draft)\n- Modules enumerated during enrichment\n` |
| `{SCRATCHPAD}/state_variables.md` | check pre-pass | `# State / Resources (draft)\n- Resources, structs, objects enumerated during enrichment\n` |
| `{SCRATCHPAD}/function_list.md` | check pre-pass | `# Function List (draft)\n- Entry/public/friend/private functions enumerated during enrichment\n` |
| `{SCRATCHPAD}/attack_surface.md` | LLM writes | `# Attack Surface (draft)\n- Surfaces enumerated during enrichment\n` |
| `{SCRATCHPAD}/template_recommendations.md` | check pre-pass | Full skill scaffold from deterministic pre-pass; LLM flips Required â†’ **YES** for triggered skills |
| `{SCRATCHPAD}/detected_patterns.md` | LLM writes | `# Detected Patterns (draft)` plus the complete flag table with best-effort YES/NO defaults |
| `{SCRATCHPAD}/setter_list.md` | LLM writes | `# Setter List (draft)` plus discovered or explicitly unavailable setter/admin function inventory |
| `{SCRATCHPAD}/emit_list.md` | LLM writes | `# Emit List (draft)` plus discovered or explicitly unavailable event inventory |
| `{SCRATCHPAD}/build_status.md` | check pre-pass | Already filled by pre-pass build attempt (aptos move compile / move build) |
| `{SCRATCHPAD}/recon_summary.md` | LLM writes last | `# Recon Summary (draft)\n- Target: best-known target\n- Language: Aptos Move\n- Skills to load: best-known skill list\n` |

**Recommended turn budget (target, not hard rule):**

| Turns | Activity |
|---|---|
| 1—2  | `ls {SCRATCHPAD}/` + top-level project inspection (Move.toml, README.md) |
| 3—8  | Draft any artifacts not written by the pre-pass (Write tool, one per turn) |
| 9—25 | Enrich design_context.md (deepest artifact) from docs + key modules |
| 26—45 | Enrich template_recommendations.md with triggered skills based on attack surface |
| 46—60 | Enrich attack_surface.md, state_variables.md, contract_inventory.md with details the pre-pass missed |
| 61—80 | Final pass: rewrite recon_summary.md with real content; overwrite drafts where you have enrichment |

If you reach turn 70 and have not re-written all artifacts with real
content, STOP exploration and overwrite the remaining drafts with
whatever you have. Partial real content beats "perfect analysis that
never lands on disk."

**Do NOT spend more than 5 turns on any single file exploration**. If
grep returns more than you can read, write a summary + "deferred" note
to the draft and move on.
## CLEAN HANDOFF CONTRACT (MANDATORY)

Draft-first is a crash-recovery tactic, not a pass condition. Before returning
`RECON COMPLETE`, re-open every required recon artifact and replace all draft-only,
placeholder, `best-known target`, `[LLM TO ...]`, `TODO`, and "explicitly unavailable after bounded inspection"
markers with the best real content available.

If time or turn budget is nearly exhausted, stop exploration immediately and
write a minimal substantive final version of `recon_summary.md` and
`build_status.md` before any other work:
- `recon_summary.md` must name the target, language, scope, key components,
  detected patterns, recommended templates, and artifact list.
- `build_status.md` must record the actual build/static-analysis command(s),
  result, failure/unavailable reason when applicable, and fallback used.

Do not return `RECON COMPLETE` while any required artifact is still draft-only.
If an artifact remains incomplete, say `RECON INCOMPLETE` and list the exact
files still needing enrichment; the driver will retry recon instead of letting
a dirty handoff poison instantiate/breadth.

Execute these tasks IN ORDER:

## TASK 0: RAG Meta-Buffer (DEFERRED)

RAG vulnerability-database research is deferred to Phase 4b.5 (RAG
Validation Sweep), which runs after depth analysis. That phase has its
own MCP + WebSearch fallback path.

Write to `{SCRATCHPAD}/meta_buffer.md`:

```
# Meta-Buffer

## RAG: DEFERRED to Phase 4b.5

Recon does not perform RAG queries in the V2 driver. Phase 4b.5 RAG
External precedent research will later populate typed context proposals; it never supplies finding scores
after depth analysis completes.
```

Continue to TASK 0.5 (Fork Ancestry) and then TASK 1.

## TASK 0.5: Fork Ancestry Research -- Aptos Move Parent Programs

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
1. If a web search tool (WebSearch/Tavily) is available, search: `{parent_name} Aptos Move vulnerability exploit audit finding` and `site:solodit.xyz {parent_name}` -- **skip if unavailable or if the call fails**
2. If a web search tool is available, search: `{parent_name} fork modified divergence Move` -- **skip if unavailable or if the call fails**
3. Analyze divergences: modified struct abilities, changed access control, added/removed functions, modified resource storage patterns, changed signer requirements, altered module dependencies

### Hardcoded Known-Issue Floor (Web Search Fallback)

If web searches fail or are unavailable, use this minimum catalog -- check EACH applicable dependency type.

This floor is keyed on the dependency's **TYPE** (generic mechanism), NOT on any specific protocol name -- brand-keyed rows are prohibited (a floor row naming a specific protocol is the confirmed benchmark-contamination vector; see the HARD no-overfit rule). Classify the detected parent into a type below and check the generic known-issue class; use at most one illustrative brand only in prose, never as the row key.

| Dependency Type | Critical Known Issue | Root Cause | Search Keywords |
|------------------|---------------------|------------|-----------------|
| AMM / swap pool (incl. concentrated-liquidity) | Bit shift overflow in liquidity math (e.g. a concentrated-liquidity DEX's $223M-class exploit, 2025); curve calculation precision loss at extreme reserves | Unchecked `<<` shift with value >= bit width causes overflow; integer division truncation in swap calculation at boundary values | `amm bit shift overflow liquidity exploit` / `amm curve precision reserves swap calculation` |
| Stability pool / CDP protocol | Stability pool reward calculation manipulation | Reward timing attack via strategic deposit/withdraw around distribution | `stability pool reward timing attack` |
| Lending / money market | Oracle price staleness enabling unfair liquidation | Stale price feed used for health factor calculation | `aptos lending oracle stale liquidation health` |
| Liquid staking / LST protocol | Exchange rate manipulation via direct native-token transfer | Unsolicited deposit inflates exchange rate | `aptos liquid staking exchange rate donation attack` |
| Voting-escrow (ve-token) / gauge protocol | Voting power calculation error at epoch boundary | Checkpoint staleness during epoch transition | `ve_token voting power epoch boundary checkpoint` |
| Yield farm / reward-per-share protocol | Reward per share overflow with small deposits | Large multiplier applied to tiny deposit amounts | `masterchef reward overflow small deposit` |
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

Also run: `git rev-list --count HEAD` " if result is 1, include `REPO_SHAPE: squashed_import`, otherwise `REPO_SHAPE: normal_dev`. This tells FORK_ANCESTRY whether git history analysis is useful.

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

**MANDATORY — Chosen build root**: the audit scope dir is often source-only;
the real `Move.toml` package root frequently lives in a sibling or ancestor
directory. After resolving where the build actually compiled, emit EXACTLY
this line into `build_status.md` (the mechanical PoC executor parses it
verbatim): `**Chosen build root**: ` followed by the absolute path of the
directory that owns `Move.toml`, wrapped in backticks — e.g.
`` **Chosen build root**: `/abs/path/to/package` ``. If no build environment
exists at all, emit `` **Chosen build root**: `(none)` ``.

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
6. **Operational Implications** (MANDATORY): Immediately after documenting Key Invariants, add a subsection to design_context.md:

```
## Operational Implications
State what each invariant means for how the system works " not what it checks,
but what it tells you about the system's accounting model.
Derive these from the invariant formulas and the struct/resource definitions in the code.
Each implication must reference specific data structure signatures or formula
components " restating the invariant in different words is not an implication.
```

7. **Trust Assumption Table** (MANDATORY): From docs, README, code comments, and access control patterns, extract ALL trust assumptions into a structured table in design_context.md:

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
| `oracle\|price_feed\|pyth\|switchboard\|price_oracle\|PriceFeed\|price_info\|sqrt_price\|current_tick\|pool_reserves` | ORACLE |
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
| `\w+_for\(\|\w+_for_\w+\(\|delegate_to\|_on_behalf\|on_behalf_of\|for_owner\|for_user\|operator\s*:\s*address\|delegate\s*:\s*address\|approve\|allowance\|transfer_from` (public entry functions writing state for a caller-provided address target distinct from the signer — behalf-of suffix-family shape, e.g. `deposit_for`/`stake_for`/`delegate_to`/`mint_for`/`withdraw_for`, not a fixed literal list, plus address-typed operator/delegate params plus delegated-action methods (approve/allowance/transfer_from); excludes purely internal helpers with no address-subject parameter) | MULTI_STEP_OPS |
| External module calls to named protocols in Move.toml deps or use statements: `thala\|echelon\|aries\|liquidswap\|pancakeswap\|tortuga\|amnis\|merkle_trade\|hippo\|aptin\|cellana\|cetus\|pyth\|layerzero\|wormhole` (EXCLUDE: aptos_framework::, aptos_std::, aptos_token::, std:: " standard framework modules) | NAMED_EXTERNAL_PROTOCOL |
| ANY external module call whose implementation is NOT vendored in-repo (only a `Move.toml` dependency or an address-qualified `use` is known, no local source module with a real function body), is NOT a recognized framework module (aptos_framework::, aptos_std::, aptos_token::, std::), AND whose returned resource/value is consumed (borrowed, branched on, or used to move coins/state) | EXTERNAL_DEPENDENCY (alias: also sets NAMED_EXTERNAL_PROTOCOL for back-compat) |

**`EXTERNAL_DEPENDENCY` is a GENERIC, non-brand mechanical trigger** — the row
above (`NAMED_EXTERNAL_PROTOCOL`) only fires for ~15 named protocol modules
and misses every custom/unfamous external module. The test is structural,
never a name: (a) no in-repo module implementation, (b) not a standard
framework module, (c) returned resource/value is consumed. Every dependency
that sets EXTERNAL_DEPENDENCY or NAMED_EXTERNAL_PROTOCOL gets a row in the
External Dependency Research Ledger in TASK 11 below.

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
| INTEGRATION_HAZARD_RESEARCH | NAMED_EXTERNAL_PROTOCOL flag | {YES/NO} | {if YES: list detected protocols " e.g., "Thala, Liquidswap"} |
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
- NAMED_EXTERNAL_PROTOCOL flag detected -> INTEGRATION_HAZARD_RESEARCH **REQUIRED** (injectable into depth-external)
- ORACLE flag detected -> ORACLE_ANALYSIS **REQUIRED**
- FLASH_LOAN flag detected -> FLASH_LOAN_INTERACTION **REQUIRED**
- CROSS_CHAIN flag detected -> CROSS_CHAIN_TIMING **REQUIRED**
- MIGRATION flag detected -> MIGRATION_ANALYSIS **REQUIRED**

### Injectable Skills
{List any injectable skills recommended based on protocol type classification}
- If protocol_type == 'vault': Recommend VAULT_ACCOUNTING injectable (from ~/.claude/agents/skills/injectable/vault-accounting/SKILL.md)
- If protocol_type == 'lending': Recommend LENDING_PROTOCOL_SECURITY injectable (from ~/.claude/agents/skills/injectable/lending-protocol-security/SKILL.md)
- If protocol_type == 'dex_integration': Recommend DEX_INTEGRATION_SECURITY injectable (from ~/.claude/agents/skills/injectable/dex-integration-security/SKILL.md)
- If protocol_type == 'governance': Recommend GOVERNANCE_ATTACK_VECTORS injectable (from ~/.claude/agents/skills/injectable/governance-attack-vectors/SKILL.md)
- If protocol_type == 'nft': Recommend NFT_PROTOCOL_SECURITY injectable (from ~/.claude/agents/skills/injectable/nft-protocol-security/SKILL.md)
- If protocol_type == 'outcome_determinism': Recommend OUTCOME_DETERMINISM injectable (from ~/.claude/agents/skills/injectable/outcome-determinism/SKILL.md)
- Inject Into: See skill-index.md for merge target per injectable
- If vault detected â†’ ZERO_STATE_RETURN **REQUIRED** (first-depositor analysis)

### Niche Agent Binding Rules
- MISSING_EVENT flag detected (setter_list.md has MISSING EVENT entries OR emit_list.md shows state-changing functions without events) â†’ EVENT_COMPLETENESS **niche agent** REQUIRED
- HAS_SIGNATURES flag detected (ed25519::verify/multi_ed25519/SignedMessage patterns found) â†’ SIGNATURE_VERIFICATION_AUDIT **niche agent** REQUIRED
- DOCUMENTATION is non-empty AND contains testable protocol claims (fee structures, thresholds, permissions, distribution logic) â†’ SPEC_COMPLIANCE_AUDIT **niche agent** REQUIRED (set `HAS_DOCS` flag)
- HAS_MULTI_CONTRACT flag detected (2+ in-scope modules AND constraint_variables.md shows shared parameters/formulas across modules) â†’ SEMANTIC_CONSISTENCY_AUDIT **niche agent** REQUIRED
- MULTI_STEP_OPS flag detected (approve/delegate/allowance or deposit_for/stake_for/delegate_to patterns found) â†’ MULTI_STEP_OPERATION_SAFETY **niche agent** REQUIRED

### Niche Agents (Phase 4b - standalone focused agents, 1 budget slot each)

| Niche Agent | Trigger | Required? | Reason |
|-------------|---------|-----------|--------|
| EVENT_COMPLETENESS | MISSING_EVENT flag (setter_list.md / emit_list.md) | {YES/NO} | {if YES: N setters without events found} |
| SIGNATURE_VERIFICATION_AUDIT | HAS_SIGNATURES flag (detected_patterns.md) | {YES/NO} | {if YES: signature verification patterns found} |
| SPEC_COMPLIANCE_AUDIT | HAS_DOCS flag (non-empty DOCUMENTATION with testable claims) | {YES/NO} | {if YES: docs contain testable claims} |
| SEMANTIC_CONSISTENCY_AUDIT | HAS_MULTI_CONTRACT flag (contract_inventory.md + constraint_variables.md) | {YES/NO} | {if YES: N shared parameters/formulas across M modules} |
| MULTI_STEP_OPERATION_SAFETY | MULTI_STEP_OPS flag (detected_patterns.md) | {YES/NO} | {if YES: approve/delegate or on-behalf-of patterns found} |

### Manifest Summary
- **Total Required Breadth Agents**: {count of YES in skill templates}
- **Total Required Niche Agents**: {count of YES in niche agents}
- **Total Optional Agents**: {count of NO with recommendation}
- **HARD GATE**: Orchestrator MUST spawn agent for each REQUIRED template AND each REQUIRED niche agent
```

Write to {SCRATCHPAD}/template_recommendations.md

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

### External Dependency Research Ledger (MANDATORY)

You are the ONLY phase with both live Tavily/WebSearch/WebFetch AND full
attack-surface knowledge of every external module call. depth-phase workers
run with `--disallowedTools mcp__*` and no live web tools — they can only
READ the ledger you bake here. Do the research now, not later.

For EVERY dependency flagged `NAMED_EXTERNAL_PROTOCOL` or `EXTERNAL_DEPENDENCY`
in TASK 6 (named or generic), write one row to
`{SCRATCHPAD}/external_dependency_research.md`:

| Dependency | Integration Surface | Assumed Behavior | Real Behavior | Source | Conformance | Fetch Status |
|------------|----------------------|-------------------|-----------------|--------|-------------|---------------|

- **Dependency**: module name (or a short descriptive label for a
  generic/unnamed external module).
- **Integration Surface**: ALL call sites, `file:line`, comma-separated.
- **Assumed Behavior**: what the calling code assumes, as coded.
- **Real Behavior**: researched real semantics (Tavily/WebSearch/WebFetch —
  official docs, verified module source, audit reports).
- **Source**: URL + fetch date (`fetched {DATE}`), or `verified module
  source: {address}`.
- **Conformance**: `MATCH` / `MISMATCH` (flag for depth) / `CHECK`.
- **Fetch Status**: `OK`, or `FETCH_FAILED:{reason}`.

**Never drop a row.** A failed lookup still gets a row with `Fetch Status:
FETCH_FAILED:{reason}` and `Conformance: CHECK` — carried forward, never
silently omitted.

Write to `{SCRATCHPAD}/external_dependency_research.md`. If NO dependencies
were flagged in TASK 6, still write the file with only the header row.

---

## Final step: Write recon_summary.md

Write to {SCRATCHPAD}/recon_summary.md:
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

Return: 'RECON COMPLETE: {N} modules, {M} dependencies, {K} templates recommended, patterns: [flags]'

SCOPE: Write ONLY to the scratchpad files described above. Do NOT spawn subagents.
Do NOT proceed to subsequent pipeline phases (breadth, depth, verification, report).
Return your findings and stop.
