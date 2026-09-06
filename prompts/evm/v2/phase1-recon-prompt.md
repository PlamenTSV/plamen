# Phase 1: Recon Agent (EVM pipeline)

## V2 Driver-Owned Recon Contract

The current V2 driver normally runs recon through Python-owned worker PTYs
rather than a single recon coordinator. In that mode, the worker prompt is the
authoritative execution contract:

- each worker writes only its assigned `recon_*.md` shard;
- workers do not write canonical recon files directly;
- the driver merges shards into `recon_summary.md`, `build_status.md`, and the
  other canonical recon handoff artifacts;
- `build_static` / light-mode `context_static` may run bounded build setup and
  compile-repair commands so later verification can execute PoCs;
- recon workers must not run `forge test`, `npx hardhat test`, PoC tests,
  Medusa, Echidna, Halmos, fuzz/invariant campaigns, Slither detector target
  runs, or later-phase verification commands.

If this file is read from a worker prompt, treat the worker prompt's Output
Allowlist and Command Boundary as higher priority than any monolithic task
below. The monolithic tasks remain background methodology for legacy/non-worker
routes and for deciding what evidence categories matter.

You are the Reconnaissance Agent. Your job is to gather ALL information
needed for the security audit and write it to the scratchpad. Execute
the recon orchestration plan and write the required handoff artifacts.

**CRITICAL**: Spawn only the recon workers assigned by this prompt. Do NOT ask the user
questions. Do NOT call AskUserQuestion (it is unavailable in this
context). All configuration has already been collected by the wizard
and passed to you via the placeholders below. If a placeholder is empty,
treat the corresponding input as "not provided" and continue.

**Resilience**: If any tool call (web search, slither, forge) fails or
times out, record the failure in the relevant output file and continue
to the next task. Never retry more than once. Partial recon is better
than no recon.

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

1. **External tool fails/times out?** â†’ Document the failure in the relevant output file and CONTINUE to the next task. Never retry more than once.
2. **Web search (Tavily/WebSearch) fails?** â†’ Note "UNAVAILABLE - web search failed" in output and CONTINUE. Analysis agents will compensate.
3. **Write-first principle**: Before making any slow external call (web, shell), write whatever results you already have to the scratchpad file FIRST. This ensures partial results survive if the agent is killed.
4. **No task is blocking**: If any task is stuck, skip it, document why, and move to the next. Partial recon is better than no recon.
5. **Task-local writes are mandatory**: As soon as you finish one assigned task, write its output file immediately before moving to the next task. Do not hold multiple completed outputs in memory.

## CONTEXT DELEGATION PROTOCOL

Use the deterministic pre-pass artifacts as the source of truth for bulk
enumeration. Do not reread or reproduce large generated lists unless the
specific recon task needs a sampled correction. When context is tight, delegate
detail to the scratchpad by writing concise, source-cited summaries in the
assigned recon artifacts instead of carrying long code or command output in the
conversation.

## TURN BUDGET POLICY - DRAFT-FIRST, ENRICH-LATER (MANDATORY)

You run inside `claude -p` with a hard **--max-turns cap** (currently 80
for recon) and a **--wall-clock timeout** (1500s for small projects,
auto-scaled by the driver for larger ones). A single Read/Bash/Grep/Write
call costs ONE turn. Large codebases (10k+ LOC, 30+ contracts) can
consume 50+ turns on exploration alone. If you hit the cap or timeout
without writing the required artifacts, the driver's gate fails and the
whole pipeline aborts.

**Rule**: In the FIRST 5—10 turns, write SUBSTANTIVE DRAFTS of ALL 11
required artifacts. A mechanical pre-pass (`recon_prepass.py`) may have
already written some of them " check with `ls {SCRATCHPAD}/` FIRST and
only draft the missing ones. After drafts exist, spend remaining turns
enriching them.

The 11 required artifacts (gate will reject if any is missing):

| File | Status check | Minimum-valid-draft content |
|---|---|---|
| `{SCRATCHPAD}/design_context.md` | check pre-pass | `# Design Context (draft)\n- Project: best-known target\n- Language: EVM/Solidity\n- Key Invariants: best-known findings so far\n- Operational Implications: best-known findings so far\n` |
| `{SCRATCHPAD}/contract_inventory.md` | check pre-pass | `# Contract Inventory (draft)\n- Contracts enumerated during enrichment\n` |
| `{SCRATCHPAD}/state_variables.md` | check pre-pass | `# State Variables (draft)\n- Variables enumerated during enrichment\n` |
| `{SCRATCHPAD}/function_list.md` | check pre-pass | `# Function List (draft)\n- Functions enumerated during enrichment\n` |
| `{SCRATCHPAD}/attack_surface.md` | LLM writes | `# Attack Surface (draft)\n- Surfaces enumerated during enrichment\n` |
| `{SCRATCHPAD}/template_recommendations.md` | check pre-pass | Full skill scaffold from deterministic pre-pass; LLM flips Required â†’ **YES** for triggered skills |
| `{SCRATCHPAD}/detected_patterns.md` | LLM writes | `# Detected Patterns (draft)` plus the complete flag table with best-effort YES/NO defaults |
| `{SCRATCHPAD}/setter_list.md` | LLM writes | `# Setter List (draft)` plus discovered or explicitly unavailable setter/admin function inventory |
| `{SCRATCHPAD}/emit_list.md` | LLM writes | `# Emit List (draft)` plus discovered or explicitly unavailable event inventory |
| `{SCRATCHPAD}/build_status.md` | check pre-pass | Already filled by pre-pass build attempt (forge build / npx hardhat compile) |
| `{SCRATCHPAD}/recon_summary.md` | LLM writes last | `# Recon Summary (draft)\n- Target: best-known target\n- Language: EVM/Solidity\n- Skills to load: best-known skill list\n` |

**Recommended turn budget (target, not hard rule):**

| Turns | Activity |
|---|---|
| 1—2  | `ls {SCRATCHPAD}/` + top-level project inspection (foundry.toml, hardhat.config.js, package.json, README.md) |
| 3—8  | Draft any artifacts not written by the pre-pass (Write tool, one per turn) |
| 9—25 | Enrich design_context.md (deepest artifact) from docs + key contracts |
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

Continue to TASK 1.

## TASK 1: Build Environment

> **PATH note**:
> On Windows, `forge`/`anvil`/`cast` may not be in the default PowerShell PATH.
> If `forge` is not found on first attempt:
> 1. try `$env:Path += ";$HOME\\.foundry\\bin"`
> 2. if still missing, call the explicit binary path such as
>    `~/.foundry/bin/forge`
> 3. record the fallback used in `build_status.md`

1. Check for foundry.toml or hardhat.config.js
2. If Hardhat only: create minimal foundry.toml scaffold
3. Run `npm install` or `yarn` if needed
3b. **Dependency Recovery** (before first build attempt):
   - Run `git submodule update --init --recursive` (resolves lib/ dependencies)
   - If lib/ directory is missing or empty after submodule update: run `forge install`
   - Install forge-std if not present: `forge install foundry-rs/forge-std --no-git`
3c. **Compilation Weight Check** (before first build attempt):
   Count total `.sol` files: `find {path} -name "*.sol" | wc -l`
   Read `foundry.toml` for `via-ir` and `auto_detect_solc` settings.
   Assess compilation weight:
   - **HEAVY** (any of: >500 `.sol` files, `via-ir = true` + >200 files, `auto_detect_solc = true` + multiple pragma versions in src/): Add `threads = 2` to `[profile.default]` in foundry.toml if not already set. Record `COMPILE_WEIGHT: heavy (threads capped at 2)` in build_status.md.
   - **MODERATE** (200-500 `.sol` files without via-ir): Add `threads = 3` if not already set. Record `COMPILE_WEIGHT: moderate`.
   - **LIGHT** (<200 files): No change needed. Record `COMPILE_WEIGHT: light`.
   If `auto_detect_solc = true` and all src/ pragmas use the same minor version (e.g., all `^0.8.x`): pin `solc_version` to the highest patch and set `auto_detect_solc = false`. This prevents Foundry from spawning multiple solc versions.
   **Do NOT modify** profiles other than `[profile.default]` " specialized profiles (medusa, invariant) may have intentional settings.
4. Run `forge build`
5. If build fails: read error output, apply targeted fix from this recovery ladder:
   - **Missing import/dependency** â†’ `forge install {dep} --no-git` (extract dep name from error)
   - **Remapping error** â†’ Verify remappings.txt against lib/ subdirectories, auto-generate if missing
   - **Compiler version mismatch** â†’ Check pragma, run `forge build --use {required_version}`
   - **Stack too deep** â†’ Add `--via-ir` flag to foundry.toml `[profile.default]`
   - **Interface mismatch / abstract contract** â†’ May need draft implementation, document and skip
   Retry after each fix (max 5 attempts total, was 3)
6. If build fails after 5 attempts, document failure reason and continue
7. Probe Medusa availability: run `medusa --version`. If available, record version. If not found, record unavailable.

Write build result to {SCRATCHPAD}/build_status.md
Include: `MEDUSA_AVAILABLE: true/false` (and version if available)
Include: `REPO_SHAPE: squashed_import` if `git rev-list --count HEAD` returns 1, otherwise `REPO_SHAPE: normal_dev`. This tells FORK_ANCESTRY whether git history analysis is useful.

**MANDATORY — Chosen build root**: the audit scope dir is often source-only
(no `foundry.toml`/`hardhat.config.js`); the real build manifest lives in a
sibling or ancestor directory. After resolving where `forge build` / `npx
hardhat compile` actually compiled, emit EXACTLY this line into
`build_status.md` (the mechanical PoC executor parses it verbatim):

`**Chosen build root**: ` followed by the absolute path of the directory that
owns the build manifest, wrapped in backticks — e.g.
`` **Chosen build root**: `/abs/path/to/contracts` ``. If no build
environment exists at all, emit `` **Chosen build root**: `(none)` ``.

## TASK 2: Static Analysis Artifacts

### Pre-Slither Compatibility: hardhat-dependency-compiler fix
`hardhat-dependency-compiler` creates temp `.sol` files under `contracts/hardhat-dependency-compiler/`, compiles them, then **deletes** them. Slither's `crytic-compile` crashes with `InvalidCompilation: Unknown file` because it expects all source paths from `build-info` to exist on disk. No upstream fix exists ([slither#1283](https://github.com/crytic/slither/issues/1283), open since 2022).

**Detection**: Grep `hardhat.config.js` (or `.ts`) for `dependencyCompiler` or `hardhat-dependency-compiler`.

**If detected**:
1. Check if `keep: true` is already present in the `dependencyCompiler` config block
2. If NOT present: add `keep: true` to the config object and recompile (`npx hardhat clean && npx hardhat compile --force`)
3. Verify `contracts/hardhat-dependency-compiler/` directory exists after recompile
4. Log in build_status.md: `HARDHAT_DEPENDENCY_COMPILER: detected, keep: true applied`

**If not detected**: skip this step.

### Slither Fail-Fast Policy
Slither can crash on projects with namespace imports (`import X as Y`), mixed compiler versions, or unusual AST structures. Do NOT retry endlessly.

**Call-graph artifact hygiene**:
- If any CLI fallback or auxiliary analysis generates `*.call-graph.dot`,
  `all_contracts.call-graph.dot`, or other call-graph DOT files in the project
  root, move them into `{path}/artifacts/call-graphs/` immediately.
- Create `{path}/artifacts/call-graphs/` if it does not exist.
- `call_graph.md` should reference that folder as the location of raw DOT
  artifacts. Do NOT leave generated graph files in the project root.
- If no DOT artifacts are generated, still keep `call_graph.md` in the
  scratchpad as the canonical textual summary.

**Procedure**:
1. Try invoking Slither directly via the shell (e.g., `slither {path} --print human-summary`) with a strict timeout
2. If Slither runs successfully â†’ parse its output into the artifacts below
3. If Slither fails, crashes, times out, or is not installed â†’ set `SLITHER_AVAILABLE = false`, jump directly to **grep fallback** below

**If SLITHER_AVAILABLE = true**, extract / derive these artifacts from Slither output:
- function list â†’ {SCRATCHPAD}/function_list.md
- call graph â†’ {SCRATCHPAD}/call_graph.md (plus any DOT artifacts under `{path}/artifacts/call-graphs/`)
- state variables â†’ {SCRATCHPAD}/state_variables.md
- modifiers â†’ {SCRATCHPAD}/modifiers.md
- events â†’ {SCRATCHPAD}/event_definitions.md

**If SLITHER_AVAILABLE = false**, use grep fallback (ALL of these):
- Grep `function ` in all .sol files (exclude mocks/, node_modules/) â†’ {SCRATCHPAD}/function_list.md
- Grep `modifier ` â†’ {SCRATCHPAD}/modifiers.md
- Grep `event ` â†’ {SCRATCHPAD}/event_definitions.md
- Grep state variable declarations â†’ {SCRATCHPAD}/state_variables.md
- Note "Call graph unavailable - Slither failed" in {SCRATCHPAD}/call_graph.md
- Append to {SCRATCHPAD}/build_status.md: "SLITHER: UNAVAILABLE - {error message}. Grep fallback used. Depth agents must compensate for missing static analysis."
- If any prior fallback step produced root-level DOT graph files, move them to
  `{path}/artifacts/call-graphs/` and note that relocation in
  `{SCRATCHPAD}/call_graph.md`.

**Aderyn fallback**: When SLITHER_AVAILABLE = false, if `aderyn` is installed as a CLI, run it directly against the project and append results to {SCRATCHPAD}/static_analysis.md under "## Aderyn Static Analysis". If aderyn is not available, skip and continue with grep-only fallback.

Grep interfaces directory â†’ {SCRATCHPAD}/external_interfaces.md (always, regardless of Slither status)

## TASK 3: Documentation Context
1. Read README.md, docs/ folder, or fetch provided URL
2. Extract: protocol purpose, key invariants, trust model, external dependencies
3. If no docs: note 'Inferring purpose from code'
4. **Operational Implications** (MANDATORY): Immediately after documenting Key Invariants, add a subsection to design_context.md:

```
## Operational Implications
State what each invariant means for how the system works " not what it checks,
but what it tells you about the system's accounting model.
Derive these from the invariant formulas and the mapping signatures in the code.
Each implication must reference specific data structure signatures or formula
components " restating the invariant in different words is not an implication.
```

5. **Trust Assumption Table** (MANDATORY): From ASSUMPTIONS.txt, docs, README, code comments, and access control patterns, extract ALL trust assumptions into a structured table in design_context.md:

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
3. **Scope filtering**: If SCOPE_FILE is set, read it and mark contracts as IN_SCOPE or OUT_OF_SCOPE accordingly. Only IN_SCOPE contracts are primary audit targets. If SCOPE_NOTES is set, use them to further refine scope (e.g., "focus on vault module" â†’ prioritize vault-related contracts). If neither is set, all non-library contracts are in scope.
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
- Proxy/upgradeable storage layout (delegatecall with storage slots) â†’ `[ELEVATE:STORAGE_LAYOUT] Verify storage slot alignment across proxy and implementation`
- Single mapping entry per user (no nonce/epoch key) â†’ `[ELEVATE:SINGLE_ENTRY] Analyze user-level DoS from single entry constraint`
- Fork ancestry match (Yearn, Compound, Aave pattern detected) â†’ `[ELEVATE:FORK_ANCESTRY:{parent}] Verify known {parent} vulnerability classes addressed`
- Asymmetric branch sizes in profit/loss or deposit/withdraw logic â†’ `[ELEVATE:BRANCH_ASYMMETRY] Verify state completeness in shorter branch (Rule 17)`
- MULTI_TOKEN_STANDARD detected AND function takes both token address + id parameter â†’ `[ELEVATE:TYPE_DISCRIMINATOR] Verify all token operations in function branch on type, not just the primary one`
- `initialize()` without `initializer` modifier â†’ `[ELEVATE:REINIT_RISK] Verify reinitialization protection`
- Assembly blocks (`assembly { }`) â†’ `[ELEVATE:INLINE_ASSEMBLY] Verify memory safety, return data handling, and calldata reads (calldataload at hardcoded offsets) in assembly`

Write `[ELEVATE]` tags directly into the relevant section of `attack_surface.md`.

Write to {SCRATCHPAD}/attack_surface.md

## TASK 6: Pattern Detection
Grep for these patterns (exclude lib/, test/, mocks/):

| Pattern | Flag |
|---------|------|
| `interval\|epoch\|period\|duration` | TEMPORAL |
| `oracle\|latestRoundData\|TWAP\|chainlink\|slot0\|sqrtPrice\|getSlot0` | ORACLE |
| `random\|keccak256.*block\|prevrandao\|VRF` | RANDOMNESS_WEAK_SOURCE |
| `keccak256.*%\|uint.*%.*length\|modulo\|select.*index\|pick.*winner` | RANDOMNESS_DETERMINISTIC_SELECTION |
| `flashLoan\|flash\|callback.*amount` | FLASH_LOAN |
| `IUniswapV2Router\|IUniswapV3Pool\|IBalancerVault\|swap.*token\|addLiquidity\|removeLiquidity\|getReserves\|IVault.*swap\|IPool.*swap` | FLASH_LOAN_EXTERNAL |
| `ERC4626\|vault\|deposit.*shares` | ERC4626 |
| `delegation\|staking.*receipt\|liquid.*staking\|getLiquidRewards\|unbond\|stake.*share\|validator\|deposit.*voucher\|withdraw.*voucher\|claimReward` | STAKING_RECEIPT |
| `balanceOf.*this\|address.*balance` | BALANCE_DEPENDENT |
| `bridge\|L1\|L2\|tunnel\|messenger\|crossChain` | CROSS_CHAIN |
| `onlyBot\|onlyOperator\|onlyKeeper\|BOT_ROLE` | SEMI_TRUSTED_ROLE |
| `reinitializer\|V2\|V3\|_deprecated\|migrat\|upgrade\|legacy` | MIGRATION |
| `shares\|allocation\|distribute\|pro.rata\|proportional\|vest` | SHARE_ALLOCATION |
| `rate\|rebase\|supply\|mint.*burn\|emission\|inflation\|peg\|price.*cap\|price.*floor` | MONETARY_PARAMETER |
| `mulDiv\|mulWad\|divWad\|rayMul\|rayDiv\|FullMath\.mulDiv` (AND codebase also contains `1e6\|1e8\|decimals()\|10 \*\*\|feed\.decimals`) | MIXED_DECIMALS |
| `IERC6909\|ERC6909\|IERC1155\|ERC1155\|onERC1155Received` | MULTI_TOKEN_STANDARD |
| `ecrecover\|ECDSA.recover\|SignatureChecker\|isValidSignature\|EIP712\|domainSeparator\|_domainSeparatorV4\|permit(` | HAS_SIGNATURES |
| `proxy\|upgradeable\|diamond\|delegatecall\|sstore\|sload\|assembly\s*{` | STORAGE_LAYOUT |
| `lzReceive\|ccipReceive\|receiveWormholeMessages\|_nonblockingLzReceive\|setPeer\|setTrustedRemote\|setTrustedRemoteAddress\|onOFTReceived` | CROSS_CHAIN_MSG |
| EVM contract SERIALIZES data for a NON-EVM destination VM: `Borsh\|base58\|bech32\|solana\|Pubkey\|programId\|ed25519\|bytes32.*pubkey\|bytes20\(.*sender` OR a custom assembly byte encoder building a foreign account/instruction/message layout (Solana/Bitcoin/Move/Cosmos target) | NON_EVM_TARGET |
| `_safeMint\|safeTransfer\|onERC721Received\|onERC1155Received\|tokensReceived\|onTransferReceived\|onFlashLoan\|executeOperation\|FlashCallback\|beforeSwap\|afterSwap` | OUTCOME_CALLBACK |
| `\w+For\(\|\w+ForUser\(\|delegateTo\(\|onBehalfOf\|OnBehalf\(` (public/external functions writing state for a caller-provided address target distinct from msg.sender — behalf-of suffix-family shape, e.g. `depositFor`/`stakeFor`/`mintFor`/`withdrawFor`/`claimFor`/`harvestFor`/`compoundFor`, not a fixed literal list; excludes purely internal helpers with no address-subject parameter) OR (`approve\(\|safeApprove\(\|increaseAllowance\(\|permit\(.*deadline\|transferFrom\(` AND `multicall\|batch\|aggregate\|loop.*approve\|for.*approve`) | MULTI_STEP_OPS |
| `IUniswapV2Router\|IUniswapV3Pool\|IUniswapV4Pool\|IBalancerVault\|IWeightedPool\|IAToken\|ILendingPool\|IPool\(aave\)\|ICToken\|IComptroller\|ICurvePool\|IStableSwap\|IChainlinkAggregator\|AggregatorV3Interface\|IStETH\|IWstETH` (EXCLUDE: @openzeppelin generic utilities, solmate, solady " only flag when calling protocol-specific functions) | NAMED_EXTERNAL_PROTOCOL |
| `.call{value\|.call(\|.delegatecall(` targeting non-hardcoded address after state change | OUTCOME_CALLBACK_LOW_LEVEL |
| `deadline\|claimPeriod\|default.*selection\|fallback.*assign\|getDefault\|expir` AND time-gated with fallback path | OUTCOME_DELAY |
| ANY imported `interface`/abstract contract whose implementation is NOT vendored in-repo (only an ABI/address is known — not a local `.sol` with a real function body), is NOT a recognized stdlib/@openzeppelin/solmate/solady-class utility, AND whose return value or side effect is consumed by the calling code (assigned to a variable, branched on, or used to move funds/state) | EXTERNAL_DEPENDENCY (alias: also sets NAMED_EXTERNAL_PROTOCOL for back-compat) |

Write detected flags to {SCRATCHPAD}/detected_patterns.md

**`EXTERNAL_DEPENDENCY` is a GENERIC, non-brand mechanical trigger** — it exists
because the row above it (`NAMED_EXTERNAL_PROTOCOL`) only fires for ~15 famous
interface names and misses every custom/unfamous bridge, messenger, or pool.
The test is structural, never a name: (a) no in-repo implementation body, (b)
not a stdlib/OZ/solmate/solady utility, (c) return value or side effect is
consumed. A codebase can trip `EXTERNAL_DEPENDENCY` without matching a single
brand regex above — that is the intended widening, not a bug. Every dependency
that sets EXTERNAL_DEPENDENCY or NAMED_EXTERNAL_PROTOCOL gets a row in the
External Dependency Research Ledger in TASK 11 below.

**`NON_EVM_TARGET` is a MECHANICAL trigger — do NOT downgrade it on judgment.**
Set `NON_EVM_TARGET = YES` whenever BOTH hold: (a) the codebase builds bytes via
`abi.encode`/`abi.encodePacked` or a custom assembly/byte encoder (e.g.
a Borsh/BCS packer); AND (b) that output flows into a
cross-chain send / message / withdraw call whose destination is a confirmed
non-EVM VM (a non-EVM chain-id constant, a Solana/Move/Cosmos/Bitcoin
program-id or address, or base58/bech32/32-byte-pubkey handling on that path).
You do NOT need to judge whether the encoding is correct — surfacing the surface
is the trigger; conformance is the `CROSS_VM_SERIALIZATION_CONFORMANCE` skill's
job downstream. Marking `NON_EVM_TARGET = NO` while an EVM-side encoder
demonstrably feeds a non-EVM destination is a recall-losing misclassification.
(FP guard: if the encoder output is consumed by an EVM-compatible `abi.decode`
reader — an EVM L2/sidechain target or an on-chain re-encoding hop — it is NOT a
non-EVM target.)

## TASK 7: Prep Artifacts
From function_list.md, extract:
- Setter/admin functions â†’ {SCRATCHPAD}/setter_list.md
- Emit statements â†’ {SCRATCHPAD}/emit_list.md
- min/max/cap/limit/rate/fee/threshold/factor/multiplier/ratio/weight/duration/delay/period variables â†’ {SCRATCHPAD}/constraint_variables.md
  Mark âš ï¸ UNENFORCED for variables with setters but no enforcement
- Permissionless public/external functions that emit events or modify shared state â†’ append to {SCRATCHPAD}/setter_list.md under "## Permissionless State-Modifiers"

### SetterÃ—Emit Cross-Reference (append to setter_list.md)
For each setter function in setter_list.md, check if it emits an event:
| Setter Function | Contract | Emits Event? | Event Name | Missing? |
If a setter modifies a parameter used in user-facing logic but emits NO event â†’ flag as âš ï¸ SILENT SETTER (potential monitoring blind spot, Info-level signal for report).

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

Also grep for unused struct fields (defined but never read) â†’ append to static_analysis.md
Write to {SCRATCHPAD}/static_analysis.md

## TASK 9: Run Test Suite

Driver-owned recon worker mode: do not execute this task. Record test-suite
execution as deferred to verification/PoC phases after compile health is known.
The build-static worker may only establish compile readiness and bounded build
repair evidence.

Legacy monolithic recon mode only:

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

> **CRITICAL**: This matrix binds pattern detection to later agent-planning decisions. Recon MUST NOT spawn agents and MUST NOT create any separate roster or coordination artifact. A later driver-owned phase consumes `template_recommendations.md`.

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
| STORAGE_LAYOUT_SAFETY | STORAGE_LAYOUT flag | {YES/NO} | {if YES: proxy/delegatecall/assembly patterns found} |
| CROSS_CHAIN_MESSAGE_INTEGRITY | CROSS_CHAIN_MSG flag | {YES/NO} | {if YES: lzReceive/ccipReceive/setPeer patterns found} |
| INTEGRATION_HAZARD_RESEARCH | NAMED_EXTERNAL_PROTOCOL flag (includes generic EXTERNAL_DEPENDENCY hits, which alias it) | {YES/NO} | {if YES: list detected dependencies, named or generic " e.g., "Uniswap V3, Chainlink, custom bridge messenger"} |

### Binding Rules
- SEMI_TRUSTED_ROLE flag detected â†’ SEMI_TRUSTED_ROLES **REQUIRED**
- BALANCE_DEPENDENT flag detected â†’ TOKEN_FLOW_TRACING **REQUIRED**
- STAKING_RECEIPT flag detected â†’ STAKING_RECEIPT_TOKENS **REQUIRED**
- MIGRATION flag detected â†’ MIGRATION_ANALYSIS **REQUIRED**
- CROSS_CHAIN flag detected â†’ CROSS_CHAIN_TIMING **REQUIRED**
- TEMPORAL flag detected â†’ TEMPORAL_PARAMETER_STALENESS **REQUIRED**
- SHARE_ALLOCATION flag detected â†’ SHARE_ALLOCATION_FAIRNESS **REQUIRED**
- FLASH_LOAN flag detected â†’ FLASH_LOAN_INTERACTION **REQUIRED**
- FLASH_LOAN_EXTERNAL flag detected â†’ FLASH_LOAN_INTERACTION **REQUIRED**
- ORACLE flag detected â†’ ORACLE_ANALYSIS **REQUIRED**
- MONETARY_PARAMETER flag detected â†’ ECONOMIC_DESIGN_AUDIT **REQUIRED**
- External interactions detected in attack_surface.md â†’ EXTERNAL_PRECONDITION_AUDIT **REQUIRED**
- ERC4626 flag detected â†’ ZERO_STATE_RETURN **REQUIRED**
- STORAGE_LAYOUT flag detected â†’ STORAGE_LAYOUT_SAFETY **REQUIRED**
- CROSS_CHAIN_MSG flag detected â†’ CROSS_CHAIN_MESSAGE_INTEGRITY **REQUIRED**
- NAMED_EXTERNAL_PROTOCOL flag detected â†’ INTEGRATION_HAZARD_RESEARCH **REQUIRED** (injectable into depth-external)
- NON_EVM_TARGET flag detected â†’ CROSS_VM_SERIALIZATION_CONFORMANCE **REQUIRED** (injectable into the cross-chain/encoding breadth agent and depth-external). Audits OUTBOUND EVM-side serialization vs the destination VM's layout (CROSS_CHAIN_MESSAGE_INTEGRITY covers inbound only).
- MIXED_DECIMALS flag detected â†’ DIMENSIONAL_ANALYSIS **niche agent** RECOMMENDED (standalone agent, 1 budget slot)

### Injectable Skills
{List any injectable skills recommended based on protocol type classification}
- If protocol_type == 'vault': Recommend VAULT_ACCOUNTING injectable (from ~/.claude/agents/skills/injectable/vault-accounting/SKILL.md)
- If protocol_type == 'lending': Recommend LENDING_PROTOCOL_SECURITY injectable (from ~/.claude/agents/skills/injectable/lending-protocol-security/SKILL.md)
- If protocol_type == 'dex_integration': Recommend DEX_INTEGRATION_SECURITY injectable (from ~/.claude/agents/skills/injectable/dex-integration-security/SKILL.md)
- If protocol_type == 'governance': Recommend GOVERNANCE_ATTACK_VECTORS injectable (from ~/.claude/agents/skills/injectable/governance-attack-vectors/SKILL.md)
- If protocol_type == 'nft': Recommend NFT_PROTOCOL_SECURITY injectable (from ~/.claude/agents/skills/injectable/nft-protocol-security/SKILL.md)
- If protocol_type == 'account_abstraction': Recommend ACCOUNT_ABSTRACTION_SECURITY injectable (from ~/.claude/agents/skills/injectable/account-abstraction-security/SKILL.md)
- If protocol_type == 'outcome_determinism': Recommend OUTCOME_DETERMINISM injectable (from ~/.claude/agents/skills/injectable/outcome-determinism/SKILL.md)
- If NON_EVM_TARGET flag set: Recommend CROSS_VM_SERIALIZATION_CONFORMANCE injectable (from ~/.claude/agents/skills/injectable/cross-vm-serialization-conformance/SKILL.md) — REQUIRED, inject into the cross-chain/encoding breadth agent and depth-external
- Inject Into: See skill-index.md for merge target per injectable

### Niche Agent Binding Rules
- MISSING_EVENT flag detected (setter_list.md has MISSING EVENT entries OR emit_list.md shows state-changing functions without events) â†’ EVENT_COMPLETENESS **niche agent** REQUIRED
- HAS_SIGNATURES flag detected (ecrecover/ECDSA.recover/permit/EIP712/domainSeparator/nonces/isValidSignature patterns found) â†’ SIGNATURE_VERIFICATION_AUDIT **niche agent** REQUIRED
- DOCUMENTATION is non-empty AND contains testable protocol claims (fee structures, thresholds, permissions, distribution logic) â†’ SPEC_COMPLIANCE_AUDIT **niche agent** REQUIRED (set `HAS_DOCS` flag)
- HAS_MULTI_CONTRACT flag detected (2+ in-scope contracts AND constraint_variables.md shows shared parameters/formulas across contracts) â†’ SEMANTIC_CONSISTENCY_AUDIT **niche agent** REQUIRED
- MULTI_STEP_OPS flag detected (approve/safeApprove/increaseAllowance/permit or depositFor/stakeFor/delegateTo/mintFor/withdrawFor/OnBehalf/claimFor/harvestFor/compoundFor patterns found) â†’ MULTI_STEP_OPERATION_SAFETY **niche agent** REQUIRED
- OUTCOME_CALLBACK flag detected (onERC721Received/onERC1155Received/tokensReceived/onTransferReceived/onFlashLoan/executeOperation patterns found) â†’ CALLBACK_RECEIVER_SAFETY **niche agent** REQUIRED

### Niche Agents (Phase 4b - standalone focused agents, 1 budget slot each)

| Niche Agent | Trigger | Required? | Reason |
|-------------|---------|-----------|--------|
| EVENT_COMPLETENESS | MISSING_EVENT flag (setter_list.md / emit_list.md) | {YES/NO} | {if YES: N setters without events found} |
| SIGNATURE_VERIFICATION_AUDIT | HAS_SIGNATURES flag (detected_patterns.md) | {YES/NO} | {if YES: signature patterns found - ecrecover/ECDSA/permit/EIP712} |
| SEMANTIC_CONSISTENCY_AUDIT | HAS_MULTI_CONTRACT flag (contract_inventory.md + constraint_variables.md) | {YES/NO} | {if YES: N shared parameters/formulas across M contracts} |
| MULTI_STEP_OPERATION_SAFETY | MULTI_STEP_OPS flag (detected_patterns.md) | {YES/NO} | {if YES: approve/safeApprove/increaseAllowance/permit or depositFor/stakeFor/delegateTo/OnBehalf patterns found} |
| CALLBACK_RECEIVER_SAFETY | OUTCOME_CALLBACK flag (detected_patterns.md) | {YES/NO} | {if YES: callback handler patterns found - onERC721Received/tokensReceived/etc.} |
| SPEC_COMPLIANCE_AUDIT | HAS_DOCS flag (non-empty DOCUMENTATION with testable claims) | {YES/NO} | {if YES: docs contain testable claims} |
| DIMENSIONAL_ANALYSIS | MIXED_DECIMALS flag (mulDiv/mulWad + 1e6/1e8/decimals()/10** in scope) | {YES/NO} | {if YES: mixed-decimal fixed-point arithmetic detected " standalone DA agent} |

### Recommendation Summary
- **Total Required Breadth Agents**: {count of YES in skill templates}
- **Total Required Niche Agents**: {count of YES in niche agents}
- **Total Optional Agents**: {count of NO with recommendation}
- **Downstream use**: later driver-owned phases consume this table; recon stops after writing `template_recommendations.md` and other recon artifacts
```

---

Write to {SCRATCHPAD}/template_recommendations.md

## TASK 11: External Contract Verification (MANDATORY)

> **SKIP POLICY**: Web/chain lookups are best-effort. If any call fails or times out, document "UNAVAILABLE" for that dependency and continue. The "addresses unavailable" fallback below covers this case. Do NOT let a failed lookup block the entire task.

For EACH critical external contract:
1. **Find production address**: Search codebase for deployed addresses, configs, deployment scripts. If NETWORK is set, use it as the default network for all chain data queries. Otherwise infer from codebase (chainId, RPC URLs, deployment configs).
2. **Fetch ABI/source**: If a web-search or chain-data tool is available (WebFetch/WebSearch), attempt to retrieve the ABI or verified source from a block explorer for the discovered address. **Skip if unavailable or if the call fails.**
3. **Compare mock vs production**: For each function the protocol calls:
   | Function | Mock Behavior | Production Behavior | DIFFERS? |
4. **Document token transferability**: Can tokens be sent TO protocol unsolicited?
5. **Documentation lookup**: If a web search tool is available, search for protocol documentation of the external dependency (official docs, audit reports) and record key behaviors. **Skip if unavailable or if the call fails.**

Write to {SCRATCHPAD}/external_production_behavior.md

**If addresses unavailable** (no deployed contracts found):
- Mark all external deps as 'UNVERIFIED' in attack_surface.md
- Add severity note: UNVERIFIED deps trigger Rule 4 (adversarial assumption)
- Analysis agents MUST NOT use mock behavior as evidence to REFUTE findings
- Verifiers MUST return CONTESTED (not REFUTED) for external dep related hypotheses
- **Severity floor**: UNVERIFIED external deps with HIGH worst-case â†’ minimum MEDIUM

### External Dependency Research Ledger (MANDATORY)

You are the ONLY phase with both live WebSearch/WebFetch/tavily_search AND full
attack-surface knowledge of every external call site. depth-phase workers run
with `--disallowedTools mcp__*` and no live web tools — they can only READ the
ledger you bake here, they cannot re-research it themselves. Do the research
now, not later.

For EVERY dependency flagged `NAMED_EXTERNAL_PROTOCOL` or `EXTERNAL_DEPENDENCY`
in TASK 6 (named or generic), write one row to
`{SCRATCHPAD}/external_dependency_research.md`:

| Dependency | Integration Surface | Assumed Behavior | Real Behavior | Source | Conformance | Fetch Status |
|------------|----------------------|-------------------|-----------------|--------|-------------|---------------|

- **Dependency**: interface/contract name (or a short descriptive label for a
  generic/unnamed dependency, e.g. `custom bridge messenger`).
- **Integration Surface**: ALL call sites, `file:line`, comma-separated.
- **Assumed Behavior**: what the calling code assumes, as coded (infer from
  how the return value/side effect is consumed).
- **Real Behavior**: the researched real semantics (via WebSearch/WebFetch/
  tavily_search — official docs, verified deployed source, audit reports). If
  a deployed address is known, prefer fetching verified source (block
  explorer) over prose docs.
- **Source**: URL + fetch date (`fetched {DATE}`), or `verified deployed
  source: {address}`.
- **Conformance**: `MATCH` (assumed == real) / `MISMATCH` (assumed != real —
  flag for depth) / `CHECK` (could not fully determine, needs depth
  follow-up).
- **Fetch Status**: `OK`, or `FETCH_FAILED:{reason}` if the web lookup failed
  or timed out.

**Never drop a row.** If research fails for a dependency, still write the row
with `Fetch Status: FETCH_FAILED:{reason}` and `Conformance: CHECK` — a
carried-forward unresolved obligation, not a silent omission.

Write to `{SCRATCHPAD}/external_dependency_research.md`. If NO dependencies
were flagged in TASK 6, still write the file with only the header row (empty
ledger is a valid terminal state — the downstream gate treats it as "nothing
to check", not "recon didn't run").

---

## Final step: Write recon_summary.md

Write COMPLETE summary to {SCRATCHPAD}/recon_summary.md:
1. Build Status: [success/failed]
2. Contracts: [count] totaling [lines] lines
3. External Dependencies: [count] - [names]
4. Detected Patterns: [list flags]
5. Recommended Templates: [list with brief reason each]
6. Artifacts Written: [list all files]

Return: 'RECON COMPLETE: {N} contracts, {M} dependencies, {K} templates recommended, patterns: [flags]'

SCOPE: Write ONLY to the scratchpad files described above. Do NOT spawn subagents.
Do NOT proceed to subsequent pipeline phases (breadth, depth, verification, report).
Return your findings and stop.
