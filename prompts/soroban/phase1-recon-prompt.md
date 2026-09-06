# Phase 1: Recon Agent Prompt Template - Soroban

> **Legacy compatibility template.** V2 uses
> `prompts/soroban/v2/phase1-recon-prompt.md`; recon receives no MCP and external
> precedent is deferred to post-freeze `rag_sweep`.

> **Usage**: Orchestrator reads this file and spawns recon agents with these prompts for Soroban/Stellar smart contracts.
> Replace `{path}`, `{scratchpad}`, `{docs_path_or_url_if_provided}`, `{network_if_provided}`, `{scope_file_if_provided}`, `{scope_notes_if_provided}` with actual values. Omit lines for empty placeholders.
>
> **ORCHESTRATOR SPLIT DIRECTIVE**: Same 4-agent split as EVM/Solana to prevent timeout:
>
> | Agent | Model | Tasks | Why Separate |
> |-------|-------|-------|-------------|
> | **1A: RAG-only** | sonnet | TASK 0 steps 1-5 (vuln-db + Solodit) | Mechanical query + format - no deep reasoning needed |
> | **1B: Docs + External + Fork** | opus | TASK 0 step 6 (fork ancestry), TASK 3, TASK 11 | Tavily can hang; fork ancestry needs reasoning |
> | **2: Build + Static + Tests** | sonnet | TASK 1, 2, 8, 9 | Tool execution + output formatting - no deep reasoning needed |
> | **3: Patterns + Surface + Templates** | opus | TASK 4, 5, 6, 7, 10 | Pure codebase analysis, fast; pattern detection needs reasoning |
>
>
> **CRITICAL - RAG TIMEOUT POLICY**:
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
> Agent 2 writes: `build_status.md`, `function_list.md`, `call_graph.md`, `state_variables.md`, `modifiers.md`, `event_definitions.md`, `external_interfaces.md`, `static_analysis.md`, `test_results.md`, `caller_map.md`, `callee_map.md`, `state_write_map.md`, `function_summary.md`
> Agent 3 writes: `contract_inventory.md`, `attack_surface.md`, `detected_patterns.md`, `setter_list.md`, `emit_list.md`, `constraint_variables.md`, `template_recommendations.md`
> Orchestrator writes: `recon_summary.md` (after Agents 1B, 2, 3 complete - NOT waiting for 1A)

---

## Agent 1A: RAG-only

```
Task(subagent_type="general-purpose", prompt="
You are Recon Agent 1A (RAG-only) for a Soroban/Stellar smart contract audit.

PROJECT_PATH: {path}
SCRATCHPAD: {scratchpad}

## RESILIENCE RULES
1. **MCP call fails/times out?** -> Document the failure and CONTINUE. Never retry more than once.
2. **Write-first principle**: Write partial results before slow external calls.
3. **No task is blocking**: Skip stuck tasks, document why, move on.

## TASK 0: RAG Meta-Buffer Retrieval

### Step 1: Classify Protocol Type
Scan contract source (lib.rs or contract files) to determine type:

| Protocol Type | Key Indicators | Query |
|---------------|----------------|-------|
| staking | stake, unstake, validator, delegation, stake_pool | `get_common_vulnerabilities(protocol_type='staking')` |
| lending | borrow, lend, collateral, liquidation, health_factor | `get_common_vulnerabilities(protocol_type='lending')` |
| dex | swap, liquidity, pool, reserves, amm | `get_common_vulnerabilities(protocol_type='dex')` |
| vault | deposit, withdraw, shares, strategy, vault | `get_common_vulnerabilities(protocol_type='vault')` |
| bridge | bridge, relay, message, stellar_anchor | `get_common_vulnerabilities(protocol_type='bridge')` |
| governance | vote, propose, timelock, quorum, dao | `get_common_vulnerabilities(protocol_type='governance')` |

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
4. **MANDATORY**: mcp__unified-vuln-db__search_solodit_live(protocol_category=['{DeFi/Bridge/etc.}'], tags=['{relevant}', 'Soroban', 'Stellar'], language='Rust', quality_score=3, sort_by='Quality', max_results=20)
5. If SEMI_TRUSTED_ROLE detected: search_solodit_live(keywords='admin access control authorization require_auth', impact=['HIGH','MEDIUM'], max_results=15)
6. search_solodit_live(keywords='Soroban Stellar storage TTL overflow arithmetic', impact=['HIGH','CRITICAL'], max_results=15)

### Step 3: Synthesize into {SCRATCHPAD}/meta_buffer.md
```markdown
# Meta-Buffer: {PROTOCOL_NAME} ({PROTOCOL_TYPE}) -- Soroban
## Protocol Classification
- **Type**: {protocol_type}
- **Runtime**: Soroban/Stellar
- **Key Indicators**: {what patterns led to classification}
## Common Vulnerabilities for {PROTOCOL_TYPE} on Soroban
| Category | Frequency | Key Functions to Check |
## Soroban-Specific Vulnerability Classes
| Class | Description | Check |
|-------|-------------|-------|
| Unprotected upgrade | update_current_contract_wasm without require_auth | All upgrade paths |
| Arithmetic overflow | overflow-checks missing in release profile | All arithmetic ops |
| TTL expiry data loss | Persistent/Temporary storage without extend_ttl | All storage reads |
| Instance storage DoS | Vec/Map grown unboundedly in Instance storage | All Instance writes |
| Auth bypass | Missing require_auth on state-mutating functions | All public fn |
| invoke vs try_invoke | env.invoke_contract traps on error (no recovery) | All cross-contract calls |
| Allowance expiration | SEP-41 approve with stale expiration_ledger | All approve/transfer_from |
| Token balance donation | Using token balance directly instead of tracked internal balance | Balance reads |
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
2. {question derived from Soroban-specific attack vectors}
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
You are Recon Agent 1B (Docs + External + Fork) for a Soroban/Stellar smart contract audit.

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

## TASK 0 Step 6: Fork Ancestry Research -- Soroban Parent Contracts

Read ~/.claude/agents/skills/soroban/fork-ancestry/SKILL.md if it exists, otherwise apply this methodology:

Execute all 4 steps with Soroban-specific parent detection:

### Known Soroban/Stellar Parent Protocols

| Parent | Detection Patterns |
|--------|-------------------|
| Soroswap | `soroswap\|SoroswapRouter\|SoroswapPair\|soroswap_pair\|soroswap_factory` |
| Phoenix DEX | `phoenix\|PhoenixPair\|phoenix_factory\|lp_token\|phoenix_multihop` |
| Blend Protocol | `blend\|BlendPool\|b_token\|d_token\|backstop\|blend_capital` |
| Aquarius | `aquarius\|aqua\|governance_vote\|locker\|aquarius_amm` |
| Stellar Anchor | `stellar_anchor\|sep.*24\|sep.*31\|sep.*38\|withdrawal_anchor` |
| Comet AMM | `comet\|CometPool\|bind\|rebind\|gulp\|denormalized_weight` |

**Detection**: 1) Grep contract source for patterns, 2) Check Cargo.toml deps for parent crate names, 3) Check README for fork attribution, 4) Compare function/struct names against known parent contracts.

**For each detected parent**: Query Solodit + Tavily for known vulns, analyze divergences (modified auth checks, changed cross-contract targets, added/removed functions, modified storage key schemas, changed admin requirements). Append to {SCRATCHPAD}/meta_buffer.md under '## Fork Ancestry Analysis'.

> **SKIP POLICY**: If web searches fail, write 'Fork ancestry: web search unavailable' and continue with code-level divergence analysis only.

## TASK 3: Documentation Context

1. Read README.md, docs/ folder, or fetch provided URL
2. Extract: protocol purpose, key invariants, trust model, external contract dependencies
3. Identify: admin model (owner/multi-sig/DAO), upgradeability (update_current_contract_wasm usage?), external cross-contract call targets (verified/audited?), key storage schema, token standard (SEP-41?)
4. If no docs: note 'Inferring purpose from code'
5. **Operational Implications** (MANDATORY): Immediately after documenting Key Invariants, add a subsection to design_context.md:

```
## Operational Implications
State what each invariant means for how the system works — not what it checks,
but what it tells you about the system's accounting model.
Derive these from the invariant formulas and the storage struct definitions in the code.
Each implication must reference specific data structure signatures or formula
components — restating the invariant in different words is not an implication.
```

6. **Trust Assumption Table** (MANDATORY): From ASSUMPTIONS.txt, docs, README, code comments, and access control patterns (require_auth / require_auth_for_args), extract ALL trust assumptions into a structured table in design_context.md:

| # | Actor | Trust Level | Assumption | Source |
|---|-------|-------------|------------|--------|
| 1 | {role} | FULLY_TRUSTED | Will not act maliciously | {source} |
| 2 | {role} | SEMI_TRUSTED(bounds: {on-chain limit}) | Cannot exceed {stated bounds} | {source} |
| 3 | - | PRECONDITION | {config state assumed at launch} | {source} |

Trust levels: `FULLY_TRUSTED` (will not act maliciously - e.g., multisig, governance, DAO), `SEMI_TRUSTED(bounds: ...)` (bounded by on-chain parameters), `PRECONDITION` (deployment/config state assumption), `UNTRUSTED` (default for users, external contracts).
If no explicit trust documentation exists, infer from require_auth patterns and admin checks, and note `Source: inferred`.

Write to {SCRATCHPAD}/design_context.md

## TASK 11: External Contract Verification (MANDATORY)

> **SKIP POLICY**: If Tavily calls fail, skip that step, document 'UNAVAILABLE', and continue.

For EACH critical external contract the protocol invokes via env.invoke_contract() or env.try_invoke_contract():

1. **Find contract address**: Search codebase for Address constants, env.deployer() patterns, stored contract addresses
2. **Verify contract identity**: Cross-reference against known Soroban contracts (Stellar Asset Contract SAC, SEP-41 token, Soroswap, Phoenix, Blend)
3. **Check hardcoded vs dynamic**: Is the cross-contract call target hardcoded or loaded from storage? If from storage, who can change it?
4. **invoke vs try_invoke distinction**: Document whether each cross-contract call uses:
   - `env.invoke_contract()` — TRAPS the Wasm VM on error, entire transaction reverts. No error recovery.
   - `env.try_invoke_contract()` — Returns `Result`, allows error handling. Preferred for external calls.
   - Flag any `env.invoke_contract()` calls to unverified/untrusted contracts as HIGH risk.
5. **Stellar Asset Contract (SAC)**: Check if the protocol interacts with SAC-wrapped Stellar classic assets.
   - SAC allows unauthorized transfers if the calling contract is the asset issuer
   - Verify whether any SAC clawback authority could affect protocol balances
6. **Document unknown contracts**: Cross-contract call targets not identifiable as well-known protocols
   - Search Tavily for audit history -- **skip if fails**
   - Mark as UNVERIFIED if no audit found
7. **Token balance security**: For each token contract the protocol interacts with:
   - Does protocol track internal balance vs relying on token.balance(contract_address)?
   - Can tokens be transferred unsolicited to the protocol contract? (YES for SEP-41 tokens)
   - If protocol uses env.invoke_contract(token, "balance", ...) without internal tracking → DONATION_ATTACK_RISK

Write to {SCRATCHPAD}/external_production_behavior.md

**If contract addresses unavailable**: Mark all external deps as 'UNVERIFIED', add severity note (Rule 4 adversarial assumption), set severity floor MEDIUM for HIGH worst-case.

### External Dependency Research Ledger (MANDATORY)

You are the ONLY phase with both live Tavily/WebSearch/WebFetch AND full
attack-surface knowledge of every cross-contract call. depth-phase workers
run with `--disallowedTools mcp__*` and no live web tools — they can only
READ the ledger you bake here. Do the research now, not later.

For EVERY dependency flagged `NAMED_EXTERNAL_PROTOCOL` or `EXTERNAL_DEPENDENCY`
in TASK 6 (named or generic; if Agent 3's `detected_patterns.md` is not yet
written when you run, do your own pass over `env.invoke_contract`/
`try_invoke_contract` call sites using the same test), write one row to
`{SCRATCHPAD}/external_dependency_research.md`:

| Dependency | Integration Surface | Assumed Behavior | Real Behavior | Source | Conformance | Fetch Status |
|------------|----------------------|-------------------|-----------------|--------|-------------|---------------|

- **Dependency**: contract/crate name (or a short descriptive label for a
  generic/unnamed cross-contract target).
- **Integration Surface**: ALL `invoke_contract`/`try_invoke_contract` call
  sites, `file:line`, comma-separated.
- **Assumed Behavior**: what the calling code assumes, as coded.
- **Real Behavior**: researched real semantics (Tavily/WebSearch/WebFetch —
  official docs, verified contract source, audit reports).
- **Source**: URL + fetch date (`fetched {DATE}`), or `verified contract
  source: {address}`.
- **Conformance**: `MATCH` / `MISMATCH` (flag for depth) / `CHECK`.
- **Fetch Status**: `OK`, or `FETCH_FAILED:{reason}`.

**Never drop a row.** A failed lookup still gets a row with `Fetch Status:
FETCH_FAILED:{reason}` and `Conformance: CHECK` — carried forward, never
silently omitted.

Write to `{SCRATCHPAD}/external_dependency_research.md`. If NO dependencies
were flagged, still write the file with only the header row.

Return: 'DONE: design_context.md, external_production_behavior.md written. Fork ancestry: {found/none}. External contracts: {N} verified, {M} unverified'
")
```

---

## Agent 2: Build + Static Analysis + Tests

```
Task(subagent_type="general-purpose", prompt="
You are Recon Agent 2 (Build + Static + Tests) for a Soroban/Stellar smart contract.

PROJECT_PATH: {path}
SCRATCHPAD: {scratchpad}

## RESILIENCE RULES
1. **Build/tool call fails?** -> Document failure and CONTINUE. Never retry more than once.
2. **Write-first principle**: Write partial results before slow operations.
3. **No task is blocking**: Skip stuck tasks, document why, move on.

## TASK 1: Build Environment

> **PATH note**: On Windows, `stellar` and `cargo` may not be in Claude Code's default PATH. Prefix Bash calls with: `export PATH="$HOME/.cargo/bin:$PATH" &&` if not found on first attempt. The Soroban target is `wasm32v1-none` (NOT `wasm32-unknown-unknown`).

1. Check for Cargo.toml with `soroban-sdk` dependency, `crate-type = ["cdylib"]`, `.stellar/` directory
1b. Verify toolchain availability before building:
   - `stellar --version` -- if missing, document as TOOLCHAIN WARNING
   - `cargo --version` -- required
   - `rustup target list --installed | grep wasm32` -- verify `wasm32v1-none` target installed
   - `stellar contract build --help` -- verify Stellar CLI available
   - `cargo +nightly fuzz --version` -- record availability for Phase 4b/5 fuzz campaigns. If it succeeds, set `cargo_fuzz_available: true`; if it fails (cargo-fuzz not installed, or no nightly toolchain), set `cargo_fuzz_available: false` (the verifier falls back to proptest, then boundary-value parameterized tests)
   If any required tool is missing, document in build_status.md and attempt build anyway.
1c. **CRITICAL - Overflow Check Gate** (MANDATORY before anything else):
   Read Cargo.toml and look for `[profile.release]` section. Check for `overflow-checks = true`.
   - If `overflow-checks = true` → document `OVERFLOW_SAFE: true`
   - If `overflow-checks = false` → document `OVERFLOW_SAFE: false` AND set flag `SOROBAN_OVERFLOW_UNSAFE`
   - If `[profile.release]` section exists but `overflow-checks` is absent → document `OVERFLOW_SAFE: MISSING` AND set flag `SOROBAN_OVERFLOW_UNSAFE`
   - If `[profile.release]` section is entirely absent → document `OVERFLOW_SAFE: MISSING` AND set flag `SOROBAN_OVERFLOW_UNSAFE`
   **WHY CRITICAL**: Soroban compiles to Wasm. Without `overflow-checks = true` in the release profile, ALL integer arithmetic (addition, subtraction, multiplication) silently wraps on overflow in production Wasm builds. Debug builds panic on overflow but release Wasm does not — this is a silent correctness difference that affects every arithmetic operation in the contract.
1d. **Dependency Recovery** (before first build attempt):
   - Run `git submodule update --init --recursive`
   - Run `cargo fetch` to pre-download crate dependencies
1e. **Compilation Weight Check** (before first build attempt):
   Count total `.rs` files (excluding target/): use Glob to find all *.rs files outside target/.
   Count workspace members: check `[workspace] members` in root Cargo.toml.
   Assess compilation weight:
   - **HEAVY** (any of: >200 `.rs` files, >3 workspace members, multiple contracts/ subdirs): Prefix ALL build commands with `CARGO_BUILD_JOBS=2`. Record `COMPILE_WEIGHT: heavy (jobs capped at 2)` in build_status.md.
   - **MODERATE** (100-200 `.rs` files): Prefix build commands with `CARGO_BUILD_JOBS=3`. Record `COMPILE_WEIGHT: moderate`.
   - **LIGHT** (<100 files): No change needed. Record `COMPILE_WEIGHT: light`.
2. Build: `stellar contract build` (wraps `cargo build --target wasm32v1-none --release`). If COMPILE_WEIGHT heavy/moderate, prefix with `CARGO_BUILD_JOBS=N`. On failure, try: `cargo build --target wasm32v1-none --release`.
3. Run `cargo clippy -- -W clippy::all` for security-relevant lint warnings
4. Run `cargo audit` for known vulnerable dependencies (if cargo-audit installed)
5. Check Cargo.toml for:
   - `soroban-sdk` version -- note for known vuln cross-reference
   - `stellar-xdr` version if present
   - `[profile.release] overflow-checks = true` (documented in step 1c above)
6. If build fails after 3 attempts, document failure and continue

Also run: `git rev-list --count HEAD` — if result is 1, include `REPO_SHAPE: squashed_import`, otherwise `REPO_SHAPE: normal_dev`. This tells FORK_ANCESTRY whether git history analysis is useful.

Write to {SCRATCHPAD}/build_status.md:
```markdown
# Build Status
- **Framework**: Soroban SDK {version}
- **Stellar CLI**: {version or MISSING}
- **Build Result**: success/failed ({error})
- **Wasm Target**: wasm32v1-none (confirmed/missing)
- **overflow-checks (release)**: true/false/MISSING -- SOROBAN_OVERFLOW_UNSAFE: {yes/no}
- **Clippy Warnings (security-relevant)**: {list}
- **Cargo Audit Results**: {vulnerabilities or clean}
- **SCOUT_AVAILABLE**: {true/false} (set in TASK 2)
- **cargo_fuzz_available**: true/false (`cargo +nightly fuzz --version` probe; gates Soroban Thorough-mode libFuzzer fuzzing — proptest fallback if false)
- **proptest_available**: true/false (check Cargo.toml dev-dependencies; fallback fuzzer when cargo-fuzz absent)
- **RAG_TOOLS_AVAILABLE**: {true/false} (set by Agent 1A probe)
- **COMPILE_WEIGHT**: light/moderate/heavy
```

## TASK 2: Static Analysis Artifacts

### Scout (CoinFabrik) Fail-Fast Policy
Scout is the primary static analysis tool for Soroban. It is a CLI tool — NOT an MCP server.
Run it directly via Bash. It has 23 detectors covering Soroban-specific patterns.

**Procedure**:
1. Make ONE probe: run `cargo scout-audit --help` in the project directory
2. If probe **succeeds** -> set `SCOUT_AVAILABLE = true`, run full Scout analysis
3. If probe **fails** (command not found) -> set `SCOUT_AVAILABLE = false`, skip Scout, use grep fallback

**If SCOUT_AVAILABLE = true**: Run Scout analysis:
   ```
   cargo scout-audit --output-format json 2>/dev/null > {scratchpad}/scout_raw.json
   ```
   If JSON fails, try: `cargo scout-audit --output-format markdown 2>&1 | head -500`
   Extract all Scout findings (detector ID, severity, location, description).
   Append results to {SCRATCHPAD}/static_analysis.md under '## Scout Static Analysis'.

**Regardless of Scout status**, extract contract structure using grep (PRIMARY method):

**Function inventory**:
- Grep `pub fn ` in .rs files under contracts/ or src/ (exclude target/, tests/)
- Grep `#\[contractimpl\]` trait impl blocks for public contract interface
- Grep `fn ` within `#[contractimpl]` blocks for all contract entrypoints
Write to {SCRATCHPAD}/function_list.md

**Storage key inventory**:
- Grep `env\.storage()\.instance()\.get\|env\.storage()\.persistent()\.get\|env\.storage()\.temporary()\.get` for storage reads
- Grep `env\.storage()\.instance()\.set\|env\.storage()\.persistent()\.set\|env\.storage()\.temporary()\.set` for storage writes
- Grep `env\.storage()\.instance()\.extend_ttl\|persistent()\.extend_ttl\|temporary()\.extend_ttl` for TTL management
- Grep `#\[contracttype\]` for storage key enums and data structs
Write to {SCRATCHPAD}/state_variables.md (include storage type: Instance/Persistent/Temporary)

**Cross-contract call graph**:
- Grep `env\.invoke_contract\|env\.try_invoke_contract` for cross-contract calls
- For each call site: extract target address, function name, args type, return type, error handling
- Note: `invoke_contract` traps on failure vs `try_invoke_contract` returns Result
Write to {SCRATCHPAD}/call_graph.md

**Auth patterns** (modifiers equivalent):
- Grep `require_auth\|require_auth_for_args` for authorization checks
- Grep `env\.current_contract_address\|env\.invoker\|Address::` for identity usage
- Note which functions are missing require_auth on state-mutating operations
Write to {SCRATCHPAD}/modifiers.md

**Events**: Grep `env\.events()\.publish\|#\[contractevent\]` -> {SCRATCHPAD}/event_definitions.md

**External interfaces**: Grep `contractimport!\|soroban_sdk::xdr\|Address::from_string\|Address::new` -> {SCRATCHPAD}/external_interfaces.md

### TASK 2.1: Derived Graph Artifacts (depth-agent inputs, uniform schema across all 5 languages)

**SCIP PRE-CHECK (v2.5.0)**: Before grep-based derivation, check if each
artifact already exists with `> **Status**: POPULATED` on line 1. The Python
recon prepass runs `rust-analyzer scip` and may have already produced
SCIP-sourced graph artifacts. If an artifact is POPULATED, **skip** the
grep-based derivation for that file — SCIP data is strictly more accurate.
If POPULATED but sparse (< 5 rows), append grep-derived rows below a
`## Grep Supplement` heading.

Produce four derived artifacts that downstream phases consume via Read (V2
driver disables MCP except in rag_sweep). Soroban is Rust/WASM with no
Slither equivalent; cargo-scout provides some AST-level data but the
schema below is grep-based to stay uniform with the other four languages
(SCIP bake provides an AST-level alternative when rust-analyzer is available).

**Schema contract.** Every file opens with:
```
> **Status**: POPULATED | UNAVAILABLE: {reason}
> **Source**: grep-based derivation (+ cargo-scout augmentation if SCOUT_AVAILABLE=true)
> **Generated**: {timestamp UTC}
```

#### Artifact 1: `caller_map.md`

| Callee | Caller | Call Site |
|--------|--------|-----------|
| `contract::function` | `contract::function` | `file.rs:L123` |

Generation: For each `pub fn` in `function_list.md` (especially
`#[contractimpl]` methods), grep `\bfn_name\s*\(` across contract
sources (exclude target/, tests/). Identify containing function from
the nearest preceding `pub fn`/`fn` declaration.

Write to `{SCRATCHPAD}/caller_map.md`.

#### Artifact 2: `callee_map.md`

| Caller | Callee | Call Site |
|--------|--------|-----------|
| `contract::function` | `contract::function` or `<env>::crypto/storage/events` | `file.rs:L45` |

Generation: For each function body, grep:
- Intra-contract: `\bself\.\w+\s*\(`, `Self::\w+\s*\(`
- Env calls: `env\.storage\(\)`, `env\.events\(\)`, `env\.crypto\(\)`, `env\.current_contract_address`, `env\.invoke_contract`
- Cross-contract: `\bclient\.\w+\s*\(` (from `contractimport!`)
- Token: `env\.token\(\)`, SEP-41 `TokenClient::transfer`, etc.

Write to `{SCRATCHPAD}/callee_map.md`.

#### Artifact 3: `state_write_map.md`

Soroban state lives in persistent/instance/temporary storage keyed by
`DataKey` enum variants. "State variable" here means a storage key.

| State Variable | Writer Function | Write Site | Access |
|----------------|-----------------|------------|--------|
| `DataKey::Balance(Address)` | `token::transfer` | `token.rs:L89` | set |

Generation: For each `DataKey` variant in `state_variables.md`, grep:
- `env.storage().persistent().set`, `.temporary().set`, `.instance().set`
- `.update(&key, |v| ...)` closures
- `.remove(&key)`
- `.extend_ttl(&key, ...)` — lifecycle write, access=`ttl`

Access column: `set` / `update` / `remove` / `ttl`.

Write to `{SCRATCHPAD}/state_write_map.md`.

#### Artifact 4: `function_summary.md`

| Function | Visibility | Modifiers | #Callers | #Callees | State Reads | State Writes |
|----------|-----------|-----------|----------|----------|-------------|--------------|
| `Token::transfer` | pub (contractimpl) | require_auth | 3 | 5 | DataKey::Balance | DataKey::Balance |

Generation: Aggregate from `function_list.md` + `modifiers.md` +
caller/callee/state-write maps. `Modifiers` = `require_auth()`,
`require_admin()`, `extend_ttl`, any Soroban auth pattern.

Write to `{SCRATCHPAD}/function_summary.md`.

## TASK 8: Run Static Detectors

**If SCOUT_AVAILABLE = true**: Results already captured in static_analysis.md. Supplement with grep checks below.

Run targeted grep checks for Soroban-specific vulnerability patterns:

**Auth & Access**:
- `pub fn ` in `#[contractimpl]` without nearby `require_auth` → MISSING_AUTH_CHECK
- `env\.current_contract_address()` used as authority → SELF_AUTH_RISK
- Admin-gated functions without stored admin check → MISSING_ADMIN_CHECK

**Arithmetic & Overflow** (critical if SOROBAN_OVERFLOW_UNSAFE flag set):
- Unchecked `+\|-\|*` on integer types → UNCHECKED_MATH (HIGH if overflow-checks missing)
- `as u64\|as u128\|as i64\|as u32` casts → UNSAFE_CAST
- Division before multiplication `/ ` then `* ` in same expression → DIVIDE_BEFORE_MULTIPLY
- `.unwrap()` on checked arithmetic results → UNWRAP_PANIC

**Storage & TTL**:
- `env\.storage()\.persistent()\.get` without nearby `extend_ttl` → TTL_NOT_EXTENDED
- `env\.storage()\.temporary()\.get` without TTL-aware logic → TEMP_STORAGE_EXPIRY_RISK
- `env\.storage()\.instance()\.set\|instance()\.get` with Vec or Map types → INSTANCE_STORAGE_GROWTH_RISK (DoS vector)
- `env\.storage()\.persistent()\.get` returning None without handling → ARCHIVED_DATA_ACCESS

**Cross-Contract Calls**:
- `env\.invoke_contract` without `env\.try_invoke_contract` for external calls → TRAP_ON_EXTERNAL_FAILURE
- Contract address loaded from storage that can be changed by admin → MUTABLE_CALL_TARGET
- No re-read of storage after cross-contract call (stale local state) → STALE_STATE_AFTER_INVOKE

**Upgrade & Admin**:
- `update_current_contract_wasm` → check for require_auth guard → UNPROTECTED_UPGRADE if missing
- Admin stored as Address in Instance storage without TTL extension → ADMIN_TTL_RISK

**Token & Balance**:
- `token_client.balance(contract_address)` without internal balance tracking → DONATION_ATTACK_RISK
- `approve` / `transfer_from` without checking `expiration_ledger` → STALE_ALLOWANCE

**Panic & Errors**:
- `panic!` macro usage → PANIC_TRAPS_VM (Drop code does NOT run; use panic_with_error!)
- `unwrap()` on user-controlled values → UNWRAP_PANIC

Write to {SCRATCHPAD}/static_analysis.md

**OpenGrep PRE-CHECK (v2.5.0)**: The Python recon prepass may have run OpenGrep
(cross-ecosystem SARIF scanner). Check if `{SCRATCHPAD}/opengrep_findings.md`
exists. If it does, read it and APPEND its findings to `static_analysis.md`
under `## OpenGrep Findings`. This is complementary to grep-based analysis —
do not skip grep-based derivation even if OpenGrep produced results.

## TASK 9: Run Test Suite

- Run: `cargo test --features testutils 2>&1 | tail -100`
- If that fails: `cargo test 2>&1 | tail -100`
- Note: Soroban testutils require `features = ["testutils"]` for test environments
- Check for integration tests using `soroban-sdk`'s `Env::default()` test environment
- Note coverage quality: are edge cases tested? TTL expiry scenarios? Auth bypass attempts?
If tests fail, note as TEST HEALTH WARNING.
Write to {SCRATCHPAD}/test_results.md

Return: 'DONE: Build {success/failed}, Scout {available/unavailable}, overflow-checks {true/false/MISSING}, {N} functions, {M} storage keys, {K} cross-contract calls, {J} static issues, tests: {pass/fail/skip}'
")
```

---

## Agent 3: Patterns + Surface + Templates

```
Task(subagent_type="general-purpose", prompt="
You are Recon Agent 3 (Patterns + Surface + Templates) for a Soroban/Stellar smart contract.

PROJECT_PATH: {path}
SCRATCHPAD: {scratchpad}

## RESILIENCE RULES
1. **Write-first principle**: Write partial results before any slow operation.
2. **No task is blocking**: Skip stuck tasks, document why, move on.

## TASK 4: Contract Inventory

1. Count lines for all .rs files in contracts/ or src/ (exclude target/, node_modules/, .stellar/)
2. List each contract with line count, public function count, storage key count, #[contracttype] struct count
3. List helper/utility crates and shared types
4. **Scope filtering**: If SCOPE_FILE is set, read it and mark contracts as IN_SCOPE or OUT_OF_SCOPE. If SCOPE_NOTES is set, use them to refine scope. If neither is set, all contracts are in scope.

Write to {SCRATCHPAD}/contract_inventory.md

## TASK 5: Attack Surface Discovery

### Part A: External Cross-Contract Calls
| External Contract | Address Source | Call Sites (file:line) | invoke vs try_invoke | Args Passed | Return Handling |
For each call: 1) Address hardcoded or from storage? 2) Who can update stored address? 3) try_invoke or invoke (trap risk)? 4) Post-call state re-read needed? 5) Return value validated?

### Part B: Storage Schema Matrix
| Storage Key | Storage Type | Data Type | TTL Extended? | Size-Bounded? | Contracts Using It |
Include: Instance (shared TTL ~64KB), Persistent (independent TTL, archivable), Temporary (independent TTL, permanently deleted on expiry).

### Part C: Token Interaction Mapping
| Token Contract | Standard | Protocol Tracks Internally? | Uses balance() Directly? | Approve Used? | Expiration Ledger Validated? |

Note: ANY SEP-41 token can receive unsolicited transfers. If protocol calls token.balance(contract_address) without internal tracking, it is vulnerable to donation attacks. Temporary allowances (SEP-41 approve with expiration_ledger) expire and leave transfer_from calls silently failing or reverting.

### Signal Elevation Tags

During attack surface analysis, tag risk signals that warrant explicit follow-up with `[ELEVATE]`:

Apply `[ELEVATE]` when you observe:
- `update_current_contract_wasm` anywhere → `[ELEVATE:UPGRADE_PATH] Verify upgrade is guarded by require_auth and admin check`
- Instance storage holding Vec or Map types → `[ELEVATE:INSTANCE_GROWTH_DOS] Verify Instance storage size cannot be grown by user input`
- `env.invoke_contract` (non-try) to external contracts → `[ELEVATE:TRAP_ON_FAILURE] Verify external call failure modes are acceptable`
- Missing `overflow-checks = true` in release profile → `[ELEVATE:OVERFLOW_UNSAFE] ALL arithmetic is wrap-on-overflow in production Wasm`
- Asymmetric branch sizes in deposit/withdraw or mint/burn logic → `[ELEVATE:BRANCH_ASYMMETRY] Verify state completeness in shorter branch`
- Persistent storage reads without extend_ttl → `[ELEVATE:TTL_EXPIRY] Verify TTL management covers all persistent storage reads`
- Fork ancestry match (known protocol pattern detected) → `[ELEVATE:FORK_ANCESTRY:{parent}] Verify known {parent} vulnerability classes addressed`

Write `[ELEVATE]` tags directly into the relevant section of `attack_surface.md`.

### Part D: TTL Management Analysis
| Storage Key | Storage Type | TTL Extended Where? | Min TTL | Max TTL | Risk if Expired |
Note: Temporary storage is PERMANENTLY DELETED on expiry (not archivable). Persistent storage is archived (recoverable via restore). Instance storage shares a single TTL for the entire contract instance.

Write to {SCRATCHPAD}/attack_surface.md

## TASK 6: Pattern Detection

Grep in contract .rs files (exclude target/, tests/, node_modules/, .stellar/):

| Pattern | Flag |
|---------|------|
| `token_client\|token\.balance\|token\.transfer\|token\.mint\|token\.burn` | BALANCE_DEPENDENT |
| `env\.ledger()\.timestamp\|env\.ledger()\.sequence\|expiration_ledger\|ledger_key_contract_instance` | TEMPORAL |
| `admin\|owner\|require_auth\|has_role\|is_authorized` | SEMI_TRUSTED_ROLE |
| `oracle\|price_feed\|get_price\|fetch_price\|PriceData\|sqrt_price\|get_pool_state\|reserve_a\|reserve_b` | ORACLE |
| `flash\|borrow.*repay\|loan\|flash_loan` | FLASH_LOAN |
| `fee_rate\|reward_rate\|interest\|emission\|mint_rate\|multiplier` | MONETARY_PARAMETER |
| `bridge\|stellar_anchor\|sep.*24\|sep.*31\|cross.*chain\|relay` | CROSS_CHAIN |
| `shares\|allocation\|distribute\|pro.rata\|proportional\|vest` | SHARE_ALLOCATION |
| `env\.events()\.publish\|#\[contractevent\]` | HAS_EVENTS (check coverage) |
| `env\.crypto()\.ed25519_verify\|secp256k1_recover\|ed25519_sign\|verify_sig` | HAS_SIGNATURES |
| `update_current_contract_wasm` | SOROBAN_UNPROTECTED_UPGRADE (check for auth guard) |
| `env\.storage()\.instance()\.set\|instance()\.get` | INSTANCE_STORAGE (check for Vec/Map types) |
| `env\.storage()\.persistent()\.get\|persistent()\.set` | PERSISTENT_STORAGE |
| `env\.storage()\.temporary()\.get\|temporary()\.set` | TEMPORARY_STORAGE |
| `extend_ttl` | TTL_MANAGEMENT |
| `migrate\|upgrade\|v2\|deprecated\|legacy` | MIGRATION |
| `env\.invoke_contract\|env\.try_invoke_contract` | CROSS_CONTRACT |
| `approve\|transfer_from\|allowance\|expiration_ledger` | SEP41_ALLOWANCE |
| `panic!\|panic_with_error!\|unwrap()` | PANIC_PATTERNS |
| (2+ contract crates in Cargo workspace members within scope) | HAS_MULTI_CONTRACT |
| CPI targets to known protocol contract addresses or named crates: `soroswap\|phoenix\|blend\|aquarius\|comet` (EXCLUDE: soroban-sdk, soroban-token-sdk, stellar-xdr — standard SDK crates) | NAMED_EXTERNAL_PROTOCOL |
| `\w+_for\(\|\w+_for_\w+\(\|delegate_to\|on_behalf_of\|for_owner\|for_recipient\|operator\s*:\s*Address\|delegate\s*:\s*Address\|transfer_from\|burn_from\|approve\|allowance` (public functions writing state for a caller-provided Address target distinct from the caller — behalf-of suffix shape family (`deposit_for`/`stake_for`/`mint_for`/`withdraw_for`/`claim_for_user`/etc., not a fixed literal list) plus Address-typed operator/delegate params plus SEP-41 delegated-action methods; excludes purely internal helpers with no Address-subject parameter) | MULTI_STEP_OPS |
| ANY `env.invoke_contract`/`try_invoke_contract` target or Cargo dependency whose implementation is NOT vendored in-repo (only a contract address / external crate dependency is known, no local source with a real function body), is NOT a recognized SDK crate (soroban-sdk, soroban-token-sdk, stellar-xdr), AND whose returned value is consumed (assigned, branched on, or used to move balances/state) | EXTERNAL_DEPENDENCY (alias: also sets NAMED_EXTERNAL_PROTOCOL for back-compat) |

**`EXTERNAL_DEPENDENCY` is a GENERIC, non-brand mechanical trigger** — the row
above (`NAMED_EXTERNAL_PROTOCOL`) only fires for ~5 named protocol crates and
misses every custom/unfamous cross-contract target. The test is structural,
never a name: (a) no in-repo contract implementation, (b) not a standard SDK
crate, (c) returned value is consumed. Every dependency that sets
EXTERNAL_DEPENDENCY or NAMED_EXTERNAL_PROTOCOL gets a row in the External
Dependency Research Ledger in TASK 11 above.

Write to {SCRATCHPAD}/detected_patterns.md

## TASK 7: Prep Artifacts

**Admin/Authority-gated functions**: Grep for `require_auth\|require_auth_for_args`, admin Address checks, role guards
Write to {SCRATCHPAD}/setter_list.md (include '## Permissionless State-Modifiers' section)

**Events**: Grep `env\.events()\.publish\|#\[contractevent\]` -> {SCRATCHPAD}/emit_list.md
Cross-reference: For each state-changing function in setter_list.md, check if a corresponding event is published. Flag SILENT SETTERs where state changes are not emitted.

**Constraint variables**: Grep `min\|max\|cap\|limit\|rate\|fee\|threshold\|factor\|multiplier\|ratio\|weight\|duration\|delay\|period\|decimal\|precision`. Mark UNENFORCED for variables with setters but no bounds.
Write to {SCRATCHPAD}/constraint_variables.md

**Setter x Emit Cross-Reference**: For each admin setter, check if it emits an event. Flag SILENT SETTERs.

## TASK 10: Template Recommendations

### Soroban-Specific Skills (in ~/.claude/agents/skills/soroban/ — create as needed)
- AUTH_ANALYSIS -- **ALWAYS required** (require_auth coverage, auth tree propagation across invoke_contract, admin checks)
- STORAGE_LIFECYCLE -- TEMPORAL or PERSISTENT_STORAGE flag (TTL extension completeness, expiry handling, Instance storage size bounds; alias: STORAGE_TTL_SAFETY)
- UPGRADE_SAFETY -- SOROBAN_UNPROTECTED_UPGRADE flag (update_current_contract_wasm guard, post-upgrade state validity)

### Shared Templates (in ~/.claude/agents/skills/ — use soroban-adapted versions)
- SEMI_TRUSTED_ROLES, TOKEN_FLOW_TRACING, SHARE_ALLOCATION_FAIRNESS, TEMPORAL_PARAMETER_STALENESS
- ECONOMIC_DESIGN_AUDIT, EXTERNAL_PRECONDITION_AUDIT (adapted for cross-contract calls)
- EXTERNAL_PRECONDITION_AUDIT (covers Soroban oracle integrations via ORACLE flag), FLASH_LOAN_INTERACTION
- ZERO_STATE_RETURN, CROSS_CHAIN_TIMING, MIGRATION_ANALYSIS, FORK_ANCESTRY, VERIFICATION_PROTOCOL

For EACH recommended template provide: Trigger, Relevance, Instantiation Parameters, Key Questions.

---

## BINDING MANIFEST (MANDATORY)

> **CRITICAL**: Orchestrator MUST spawn an agent for every template marked `Required: YES`.

```markdown
## BINDING MANIFEST

| Template | Pattern Trigger | Required? | Reason |
|----------|-----------------|-----------|--------|
| AUTH_ANALYSIS | Always (Soroban) | YES | Foundational Soroban security — require_auth coverage |
| STORAGE_LIFECYCLE | TEMPORAL or PERSISTENT_STORAGE or TEMPORARY_STORAGE flag | {YES/NO} | {storage pattern details} |
| UPGRADE_SAFETY | SOROBAN_UNPROTECTED_UPGRADE flag | {YES/NO} | {update_current_contract_wasm found} |
| SEMI_TRUSTED_ROLES | SEMI_TRUSTED_ROLE flag | {YES/NO} | {admin/owner/role patterns} |
| TOKEN_FLOW_TRACING | BALANCE_DEPENDENT flag | {YES/NO} | {direct balance usage without internal tracking} |
| SHARE_ALLOCATION_FAIRNESS | SHARE_ALLOCATION flag | {YES/NO} | {share/allocation patterns} |
| TEMPORAL_PARAMETER_STALENESS | TEMPORAL flag | {YES/NO} | {ledger timestamp/sequence-dependent patterns} |
| ECONOMIC_DESIGN_AUDIT | MONETARY_PARAMETER flag | {YES/NO} | {fee/rate/reward parameter setters found} |
| EXTERNAL_PRECONDITION_AUDIT | CROSS_CONTRACT flag | {YES/NO} | {N cross-contract call targets} |
| INTEGRATION_HAZARD_RESEARCH | NAMED_EXTERNAL_PROTOCOL flag | {YES/NO} | {if YES: list detected protocols — e.g., "Soroswap, Phoenix"} |
| EXTERNAL_PRECONDITION_AUDIT | ORACLE flag | {YES/NO} | {oracle integration patterns found} |
| FLASH_LOAN_INTERACTION | FLASH_LOAN flag | {YES/NO} | {flash loan patterns found} |
| ZERO_STATE_RETURN | Vault/first-depositor | {YES/NO} | {vault/share pattern found} |
| CROSS_CHAIN_TIMING | CROSS_CHAIN flag | {YES/NO} | {bridge/anchor patterns} |
| MIGRATION_ANALYSIS | MIGRATION flag | {YES/NO} | {migration/upgrade patterns} |
| FORK_ANCESTRY | Always | YES | Historical vulnerability inheritance |

### Binding Rules
- AUTH_ANALYSIS **ALWAYS REQUIRED** for Soroban contracts
- FORK_ANCESTRY **ALWAYS REQUIRED**
- TEMPORAL or PERSISTENT_STORAGE or TEMPORARY_STORAGE flag → STORAGE_LIFECYCLE **REQUIRED**
- SOROBAN_UNPROTECTED_UPGRADE flag → UPGRADE_SAFETY **REQUIRED**
- SEMI_TRUSTED_ROLE flag → SEMI_TRUSTED_ROLES **REQUIRED**
- BALANCE_DEPENDENT flag → TOKEN_FLOW_TRACING **REQUIRED**
- SHARE_ALLOCATION flag → SHARE_ALLOCATION_FAIRNESS **REQUIRED**
- TEMPORAL flag → TEMPORAL_PARAMETER_STALENESS **REQUIRED**
- MONETARY_PARAMETER flag → ECONOMIC_DESIGN_AUDIT **REQUIRED**
- CROSS_CONTRACT flag → EXTERNAL_PRECONDITION_AUDIT **REQUIRED**
- NAMED_EXTERNAL_PROTOCOL flag → INTEGRATION_HAZARD_RESEARCH **REQUIRED** (injectable into depth-external)
- ORACLE flag → EXTERNAL_PRECONDITION_AUDIT **REQUIRED**
- FLASH_LOAN flag → FLASH_LOAN_INTERACTION **REQUIRED**
- CROSS_CHAIN flag → CROSS_CHAIN_TIMING **REQUIRED**
- MIGRATION flag → MIGRATION_ANALYSIS **REQUIRED**
- vault pattern → ZERO_STATE_RETURN **REQUIRED** (first-depositor share inflation analysis)

### Injectable Skills
{List any injectable skills recommended based on protocol type classification}
- If protocol_type == 'vault': Recommend VAULT_ACCOUNTING injectable (from ~/.claude/agents/skills/injectable/vault-accounting/SKILL.md)
- If protocol_type == 'lending': Recommend LENDING_PROTOCOL_SECURITY injectable (from ~/.claude/agents/skills/injectable/lending-protocol-security/SKILL.md)
- If protocol_type == 'dex_integration': Recommend DEX_INTEGRATION_SECURITY injectable (from ~/.claude/agents/skills/injectable/dex-integration-security/SKILL.md)
- If protocol_type == 'governance': Recommend GOVERNANCE_ATTACK_VECTORS injectable (from ~/.claude/agents/skills/injectable/governance-attack-vectors/SKILL.md)
- If protocol_type == 'nft': Recommend NFT_PROTOCOL_SECURITY injectable (from ~/.claude/agents/skills/injectable/nft-protocol-security/SKILL.md)
- Inject Into: See skill-index.md for merge target per injectable

### Niche Agent Binding Rules
- MISSING_EVENT flag detected (setter_list.md has SILENT SETTER entries OR emit_list.md shows state-changing functions without env.events().publish()) → EVENT_COMPLETENESS **niche agent** REQUIRED
- HAS_SIGNATURES flag detected (env.crypto().ed25519_verify / secp256k1_recover patterns found) → SIGNATURE_VERIFICATION_AUDIT **niche agent** REQUIRED
- DOCUMENTATION is non-empty AND contains testable protocol claims (fee structures, thresholds, permissions, distribution logic) → SPEC_COMPLIANCE_AUDIT **niche agent** REQUIRED (set `HAS_DOCS` flag)
- HAS_MULTI_CONTRACT flag detected (2+ in-scope contracts AND constraint_variables.md shows shared parameters/formulas across contracts) → SEMANTIC_CONSISTENCY_AUDIT **niche agent** REQUIRED
- MULTI_STEP_OPS flag detected (deposit_for/stake_for/delegate_to or on-behalf-of patterns found) → MULTI_STEP_OPERATION_SAFETY **niche agent** REQUIRED
- SOROBAN_OVERFLOW_UNSAFE flag set (overflow-checks missing or false) AND arithmetic-heavy contract → flag for depth-edge-case priority; this is a HIGH severity base issue regardless of niche agent
- Fork-ancestry detects Curve/StableSwap as parent (get_d|get_y|ramp_a|StableSwap|stableswap|calc_withdraw_one_coin|remove_liquidity_imbalance patterns with confidence MEDIUM+) → STABLESWAP_COMPLIANCE **niche agent** REQUIRED (set `STABLESWAP_FORK` flag)

### Niche Agents (Phase 4b - standalone focused agents, 1 budget slot each)

| Niche Agent | Trigger | Required? | Reason |
|-------------|---------|-----------|--------|
| EVENT_COMPLETENESS | MISSING_EVENT flag (setter_list.md / emit_list.md) | {YES/NO} | {if YES: N setters without events found} |
| SIGNATURE_VERIFICATION_AUDIT | HAS_SIGNATURES flag (detected_patterns.md) | {YES/NO} | {if YES: crypto signature patterns found} |
| SPEC_COMPLIANCE_AUDIT | HAS_DOCS flag (non-empty DOCUMENTATION with testable claims) | {YES/NO} | {if YES: docs contain testable claims} |
| SEMANTIC_CONSISTENCY_AUDIT | HAS_MULTI_CONTRACT flag (contract_inventory.md + constraint_variables.md) | {YES/NO} | {if YES: N shared parameters/formulas across M contracts} |
| MULTI_STEP_OPERATION_SAFETY | MULTI_STEP_OPS flag (detected_patterns.md) | {YES/NO} | {if YES: on-behalf-of or multi-step auth patterns found} |
| STABLESWAP_COMPLIANCE | STABLESWAP_FORK flag (fork-ancestry detects Curve/StableSwap parent) | {YES/NO} | {if YES: get_d/get_y/ramp_a patterns detected with MEDIUM+ confidence} |

### Manifest Summary
- **Total Required Breadth Agents**: {count of YES in skill templates}
- **Total Required Niche Agents**: {count of YES in niche agents}
- **Total Optional Agents**: {count of NO with recommendation}
- **SOROBAN_OVERFLOW_UNSAFE**: {YES/NO} — if YES, ALL depth agents must treat arithmetic as suspect
- **HARD GATE**: Orchestrator MUST spawn agent for each REQUIRED template AND each REQUIRED niche agent
```

Write to {SCRATCHPAD}/template_recommendations.md

Return: 'DONE: {N} contracts inventoried ({L} lines), {M} patterns detected, {K} templates recommended, flags: [{list}]'
")
```

---

## After ALL 4 Recon Agents Return

1. **Verify artifacts exist**: list {scratchpad}/ -- must have all files:
   - `meta_buffer.md` (1A), `design_context.md` (1B), `external_production_behavior.md` (1B)
   - `build_status.md`, `function_list.md`, `call_graph.md`, `state_variables.md`, `modifiers.md`, `event_definitions.md`, `external_interfaces.md`, `static_analysis.md`, `test_results.md` (2)
   - `contract_inventory.md`, `attack_surface.md`, `detected_patterns.md`, `setter_list.md`, `emit_list.md`, `constraint_variables.md`, `template_recommendations.md` (3)

2. **RAG resilience check**: If `meta_buffer.md` missing/empty (Agent 1A timed out):
   - Spawn lightweight RAG-retry agent (haiku, <2 min, 3 queries only)
   - If retry fails: proceed with empty meta_buffer.md

3. **Read summary artifacts**: template_recommendations.md (BINDING MANIFEST), attack_surface.md, detected_patterns.md

4. **Write recon_summary.md**:
```markdown
# Recon Summary -- Soroban
1. **Build Status**: {success/failed}
2. **Framework**: Soroban SDK {version}
3. **Contracts**: {count} totaling {lines} lines
4. **Public Functions**: {count}
5. **External Contract Dependencies**: {count} -- {names}
6. **Detected Patterns**: {list flags}
7. **Overflow Safety**: {SAFE (overflow-checks=true) / UNSAFE (missing or false) — CRITICAL if UNSAFE}
8. **Upgrade Path**: {protected/UNPROTECTED/none}
9. **Recommended Templates**: {list with brief reason each}
10. **Scout Status**: {available/unavailable}
11. **Artifacts Written**: {list all files}
12. **Coverage Gaps**: {tools that failed}
```

5. **Hard gate**: ALL artifacts must exist before Phase 2. If any missing, re-spawn the responsible agent.
