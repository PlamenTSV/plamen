# Phase 1: Recon Agent Prompt Template - Solana

> **Usage**: Orchestrator reads this file and spawns recon agents with these prompts for Solana/Anchor programs.
> Replace `{path}`, `{scratchpad}`, `{docs_path_or_url_if_provided}`, `{network_if_provided}`, `{scope_file_if_provided}`, `{scope_notes_if_provided}` with actual values. Omit lines for empty placeholders.
>
> **ORCHESTRATOR SPLIT DIRECTIVE**: Same 4-agent split as EVM to prevent timeout:
>
> | Agent | Model | Tasks | Why Separate |
> |-------|-------|-------|-------------|
> | **1A: RAG-only** | sonnet | TASK 0 steps 1-5 (vuln-db + Solodit) | Mechanical query + format - no deep reasoning needed |
> | **1B: Docs + External + Fork** | opus | TASK 0 step 6 (fork ancestry), TASK 3, TASK 11 | Tavily/Helius can hang; fork ancestry needs reasoning |
> | **2: Build + Static + Tests** | sonnet | TASK 1, 2, 8, 9 | Tool execution + output formatting - no deep reasoning needed |
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
You are Recon Agent 1A (RAG-only) for a Solana/Anchor program audit.

PROJECT_PATH: {path}
SCRATCHPAD: {scratchpad}

## RESILIENCE RULES
1. **MCP call fails/times out?** -> Document the failure and CONTINUE. Never retry more than once.
2. **Write-first principle**: Write partial results before slow external calls.
3. **No task is blocking**: Skip stuck tasks, document why, move on.

## TASK 0: RAG Meta-Buffer Retrieval

### Step 1: Classify Protocol Type
Scan program source (lib.rs or processor.rs) to determine type:

| Protocol Type | Key Indicators | Query |
|---------------|----------------|-------|
| staking | stake, unstake, validator, delegation, stake_pool | `get_common_vulnerabilities(protocol_type='staking')` |
| lending | borrow, lend, collateral, liquidation, obligation | `get_common_vulnerabilities(protocol_type='lending')` |
| dex | swap, liquidity, pool, reserves, amm, tick_array | `get_common_vulnerabilities(protocol_type='dex')` |
| vault | deposit, withdraw, shares, strategy, vault | `get_common_vulnerabilities(protocol_type='vault')` |
| bridge | bridge, wormhole, relay, message, portal | `get_common_vulnerabilities(protocol_type='bridge')` |
| governance | vote, propose, timelock, quorum, realm | `get_common_vulnerabilities(protocol_type='governance')` |

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
4. **MANDATORY**: mcp__unified-vuln-db__search_solodit_live(protocol_category=['{DeFi/Bridge/etc.}'], tags=['{relevant}', 'Solana'], language='Rust', quality_score=3, sort_by='Quality', max_results=20)
5. If SEMI_TRUSTED_ROLE detected: search_solodit_live(keywords='reward compound timing front-run keeper crank', impact=['HIGH','MEDIUM'], max_results=15)
6. search_solodit_live(keywords='Solana anchor account validation missing signer', impact=['HIGH','CRITICAL'], max_results=15)

### Step 3: Synthesize into {SCRATCHPAD}/meta_buffer.md
```markdown
# Meta-Buffer: {PROTOCOL_NAME} ({PROTOCOL_TYPE}) -- Solana
## Protocol Classification
- **Type**: {protocol_type}
- **Runtime**: Solana/Anchor
- **Key Indicators**: {what patterns led to classification}
## Common Vulnerabilities for {PROTOCOL_TYPE} on Solana
| Category | Frequency | Key Instructions to Check |
## Solana-Specific Vulnerability Classes
| Class | Description | Check |
|-------|-------------|-------|
| Missing signer check | Instruction does not verify signer | All instruction handlers |
| Missing owner check | Account owner not validated | All deserialized accounts |
| PDA seed collision | Predictable or overlapping PDA seeds | All PDA derivations |
| CPI privilege escalation | Signer seeds leaked or CPI to wrong program | All invoke/invoke_signed |
| Account reinitialization | init_if_needed or missing initialized check | All init instructions |
| Arithmetic overflow | unchecked math (if overflow-checks=false) | All arithmetic |
| Remaining accounts abuse | Unvalidated remaining_accounts access | All remaining_accounts usage |
| Type cosplay | Account deserialized as wrong type | All AccountInfo deserializations |
| Closing account revival | Closed account can be revived within same tx | All close operations |
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
2. {question derived from Solana-specific attack vectors}
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
You are Recon Agent 1B (Docs + External + Fork) for a Solana/Anchor program audit.

PROJECT_PATH: {path}
SCRATCHPAD: {scratchpad}
DOCUMENTATION: {docs_path_or_url_if_provided}
NETWORK: {network_if_provided}
SCOPE_FILE: {scope_file_if_provided}
SCOPE_NOTES: {scope_notes_if_provided}

## RESILIENCE RULES
1. **MCP/Tavily/Helius call fails?** -> Document failure and CONTINUE. Never retry more than once.
2. **Write-first principle**: Write partial results before slow external calls.
3. **No task is blocking**: Skip stuck tasks, document why, move on.

## TASK 0 Step 6: Fork Ancestry Research -- Solana Parent Programs

Read ~/.claude/agents/skills/solana/fork-ancestry/SKILL.md and execute all 4 steps with Solana-specific parent detection:

### Known Solana Parent Programs

| Parent | Detection Patterns |
|--------|-------------------|
| Marinade | `marinade\|mSOL\|StakePool\|liquid_staking\|marinade_finance` |
| Jupiter | `jupiter\|jup\|swap_route\|limit_order\|dca\|jupiter_aggregator` |
| Orca/Whirlpool | `whirlpool\|orca\|tick_array\|concentrated_liquidity\|tick_spacing` |
| Raydium | `raydium\|amm_v3\|concentrated_liquidity\|clmm\|raydium_amm` |
| marginfi | `marginfi\|margin_account\|lending_account\|bank\|marginfi_v2` |
| Drift | `drift\|perp_market\|spot_market\|insurance_fund\|drift_program` |
| Solend/Save | `solend\|save\|lending_market\|reserve\|obligation\|refresh_reserve` |
| Metaplex | `metaplex\|mpl_token_metadata\|collection\|creator\|master_edition` |
| SPL Stake Pool | `stake_pool\|ValidatorList\|preferred_deposit\|validator_list` |
| Serum/OpenBook | `serum\|openbook\|order_book\|market\|event_queue\|request_queue` |
| Mango | `mango\|mango_v4\|health_cache\|perp_market\|serum3` |
| Phoenix | `phoenix\|phoenix_v1\|order_packet\|fee_model` |
| Kamino | `kamino\|strategy\|whirlpool_strategy\|scope_prices` |
| Tensor | `tensor\|tcomp\|tensor_swap\|bid_state` |

**Detection**: 1) Grep program source for patterns, 2) Check Cargo.toml deps for parent crate names, 3) Check README for fork attribution, 4) Compare instruction/account struct names against parent.

**For each detected parent**: Query Solodit + Tavily for known vulns, analyze divergences (modified constraints, changed CPI targets, added/removed instructions, modified PDA seeds, changed authority requirements). Append to {SCRATCHPAD}/meta_buffer.md under '## Fork Ancestry Analysis'.

> **SKIP POLICY**: If web searches fail, write 'Fork ancestry: web search unavailable' and continue with code-level divergence analysis only.

## TASK 3: Documentation Context

1. Read README.md, docs/ folder, or fetch provided URL
2. Extract: protocol purpose, key invariants, trust model, external program dependencies
3. Identify: authority model (admin/multi-sig/DAO), upgradeability (BPFLoaderUpgradeable?), external CPI targets (verified/audited?), key PDA account model, token model (SPL Token or Token-2022?)
4. If no docs: note 'Inferring purpose from code'
5. **Trust Assumption Table** (MANDATORY): From ASSUMPTIONS.txt, docs, README, code comments, and access control patterns, extract ALL trust assumptions into a structured table in design_context.md:

| # | Actor | Trust Level | Assumption | Source |
|---|-------|-------------|------------|--------|
| 1 | {role} | FULLY_TRUSTED | Will not act maliciously | {source} |
| 2 | {role} | SEMI_TRUSTED(bounds: {on-chain limit}) | Cannot exceed {stated bounds} | {source} |
| 3 | - | PRECONDITION | {config state assumed at launch} | {source} |

Trust levels: `FULLY_TRUSTED` (will not act maliciously - e.g., multisig, governance, DAO), `SEMI_TRUSTED(bounds: ...)` (bounded by on-chain parameters), `PRECONDITION` (deployment/config state assumption), `UNTRUSTED` (default for users, external programs).
If no explicit trust documentation exists, infer from signer checks and authority patterns and note `Source: inferred`.

Write to {SCRATCHPAD}/design_context.md

## TASK 11: External Program Verification (MANDATORY)

> **SKIP POLICY**: If Helius or Tavily calls fail, skip that step, document 'UNAVAILABLE', and continue.

For EACH critical external program the protocol CPIs into:

1. **Find program ID**: Search codebase for `declare_id!`, program ID constants, Anchor.toml
2. **Verify program identity**: Cross-reference against known programs (SPL Token, Token-2022, Associated Token, System Program, Rent, Stake Program)
3. **Check hardcoded vs dynamic**: Is CPI target hardcoded or passed as account? If passed, is program ID checked?
4. **Fetch on-chain data** (if program IDs found):
   - mcp__helius__getAccountInfo(address={program_id}) -- verify program exists and is executable
   - mcp__helius__getAsset(id={program_id}) -- check program metadata if applicable
   - **Skip if calls fail** -- document 'UNAVAILABLE'
5. **Document unknown programs**: CPI targets that are NOT well-known SPL/system programs
   - Search Tavily for audit history -- **skip if fails**
   - Mark as UNVERIFIED if no audit found
6. **Token account verification**: For each token account the protocol interacts with:
   - Can tokens be transferred unsolicited? (always YES for SPL token accounts)
   - Does the protocol use `amount` field directly or track balances internally?

Write to {SCRATCHPAD}/external_production_behavior.md

**If program IDs unavailable**: Mark all external deps as 'UNVERIFIED', add severity note (Rule 4 adversarial assumption), set severity floor MEDIUM for HIGH worst-case.

Return: 'DONE: design_context.md, external_production_behavior.md written. Fork ancestry: {found/none}. External programs: {N} verified, {M} unverified'
")
```

---

## Agent 2: Build + Static Analysis + Tests

```
Task(subagent_type="general-purpose", prompt="
You are Recon Agent 2 (Build + Static + Tests) for a Solana/Anchor program.

PROJECT_PATH: {path}
SCRATCHPAD: {scratchpad}

## RESILIENCE RULES
1. **MCP/build call fails?** -> Document failure and CONTINUE. Never retry more than once.
2. **Write-first principle**: Write partial results before slow operations.
3. **No task is blocking**: Skip stuck tasks, document why, move on.

## TASK 1: Build Environment

> **PATH note**: On Windows, `solana`/`anchor`/`cargo-build-sbf` may not be in Claude Code's default PATH. Prefix Bash calls with: `export PATH="$HOME/.local/share/solana/install/active_release/bin:$HOME/.avm/bin:$HOME/.cargo/bin:$PATH" &&` if not found on first attempt.

1. Check for Anchor.toml, Cargo.toml, package.json
1b. Verify toolchain availability before building:
   - `solana --version` - if missing, document as TOOLCHAIN WARNING
   - `anchor --version` (if Anchor.toml present) - if missing, document as TOOLCHAIN WARNING
   - `rustup target list --installed | grep -E 'bpf|sbf'` - verify BPF/SBF target installed
   - `trident --version` (if Anchor.toml present) - record availability for Phase 4b/5 fuzz campaigns. Trident v0.11+ uses built-in TridentSVM (no honggfuzz/AFL needed, works on Linux/macOS/Windows)
   If any required tool is missing, document in build_status.md and attempt build anyway (may fail gracefully).
1c. **Dependency Recovery** (before first build attempt):
   - Run `git submodule update --init --recursive`
   - Run `cargo fetch` to pre-download crate dependencies
1d. **Windows symlink check** (Windows only): If build fails with "A required privilege is not held by the client" (error 1314), this is a symlink privilege issue. Document in build_status.md as `windows_symlink_error: true` and add note: "Enable Windows Developer Mode (Settings > System > For Developers) or run in admin terminal, then retry." Attempt build once more after documenting.
2. Build: Anchor (`anchor build`) or native (`cargo build-sbf`) or plain (`cargo build`)
3. Run `cargo clippy -- -W clippy::all` for security-relevant lint warnings
4. Run `cargo audit` for known vulnerable dependencies (if cargo-audit installed)
5. Check Cargo.toml for:
   - `[profile.release] overflow-checks = true` -- if FALSE/missing, flag as HIGH priority (integer overflow risk)
   - Anchor version -- note for known vuln cross-reference
6. If build fails after 3 attempts, document failure and continue

Write to {SCRATCHPAD}/build_status.md:
```markdown
# Build Status
- **Framework**: Anchor {version} / Native
- **Build Result**: success/failed ({error})
- **overflow-checks (release)**: true/false/MISSING
- **Clippy Warnings (security-relevant)**: {list}
- **Cargo Audit Results**: {vulnerabilities or clean}
- **trident_available**: true/false (Anchor + trident-cli. v0.11+ requires no honggfuzz/AFL)
- **proptest_available**: true/false (check Cargo.toml dev-dependencies)
- **FENDER_AVAILABLE**: {true/false} (set in TASK 2)
```

## TASK 2: Static Analysis Artifacts

### Fender Fail-Fast Policy
Fender MCP (`mcp__solana-fender__*`) provides Solana-specific static analysis. It may not be available or may fail on certain projects.

**Procedure**:
1. Make ONE probe call: `mcp__solana-fender__security_check_program(path={path})`
2. If probe **succeeds** -> set `FENDER_AVAILABLE = true`, use Fender results
3. If probe **fails** -> set `FENDER_AVAILABLE = false`, skip ALL Fender calls, use grep fallback

**If FENDER_AVAILABLE = true**: Append Fender results to {SCRATCHPAD}/static_analysis.md under '## Fender Static Analysis'. Extract any findings into appropriate artifact files.

**Regardless of Fender status**, extract program structure using grep (PRIMARY method):

**Function/Instruction inventory**:
- Grep `pub fn ` in .rs files under programs/ (exclude target/, tests/)
- Anchor: grep `#\[instruction\|pub fn ` for instruction handlers
- Native: grep `fn process_instruction\|match instruction` for processor dispatch
Write to {SCRATCHPAD}/function_list.md

**Account struct inventory**:
- Grep `#\[account\|#\[derive(.*Account\|pub struct.*{` in program .rs files
- Anchor: grep `#\[account(` constraint annotations
- Native: grep `unpack\|try_from_slice\|deserialize` for manual deserialization
Write to {SCRATCHPAD}/state_variables.md

**CPI call graph**:
- Grep `invoke(\|invoke_signed(\|CpiContext::new\|CpiContext::new_with_signer`
- For each CPI site: extract target program, accounts passed, signer seeds
- Note: no full call graph equivalent exists for Solana -- this is a coverage gap
Write to {SCRATCHPAD}/call_graph.md

**Account constraints (modifiers equivalent)**:
- Grep `#\[account(` with details: `has_one\|constraint\|seeds\|bump\|mut\|init\|close\|token::authority\|token::mint\|address`
- Grep `#\[access_control(` for access control decorators
- Native: grep `next_account_info\|is_signer\|is_writable\|owner ==`
Write to {SCRATCHPAD}/modifiers.md

**Events**: Grep `emit!\|emit_cpi!\|#\[event\]\|sol_log_data\|msg!` -> {SCRATCHPAD}/event_definitions.md

**External interfaces**: Grep `use.*::{`, `declare_id!`, `Pubkey::new_from_array`, `#\[program\]` -> {SCRATCHPAD}/external_interfaces.md

## TASK 8: Run Static Detectors

**If FENDER_AVAILABLE = true**: Results already captured. Supplement with grep checks below.

Run targeted grep checks for Solana-specific vulnerability patterns:

**Account Validation**: `UncheckedAccount\|AccountInfo` without owner check -> MISSING_OWNER_CHECK; `remaining_accounts` -> REMAINING_ACCOUNTS_RISK; `init_if_needed` -> REINIT_RISK; deserialization without `Account<>` wrapper -> TYPE_COSPLAY_RISK

**CPI Security**: `invoke(` without hardcoded program ID -> CPI_PROGRAM_SPOOF; signer seeds in `invoke_signed` -> document patterns; `.to_account_info()` after CPI without `reload()` -> STALE_ACCOUNT_AFTER_CPI

**Arithmetic**: `as u64\|as u128\|as i64\|as u32` -> UNSAFE_CAST; if overflow-checks=false: unchecked `+\|-\|*\|/` -> UNCHECKED_MATH; `/ ` followed by `* ` -> DIVIDE_BEFORE_MULTIPLY; `try_into().unwrap()` -> UNWRAP_OVERFLOW

**Account Lifecycle**: `close =\|CloseAccount` -> document sites; closed accounts not zeroed -> ACCOUNT_REVIVAL_RISK; lamports zeroed without discriminator zeroing -> INCOMPLETE_CLOSE

**PDA**: `find_program_address\|create_program_address\|seeds =` -> document derivations; user-controlled seeds without length prefix -> PDA_COLLISION_RISK; bump not stored/verified -> BUMP_SEED_CANONICALIZATION

**Token**: `token::transfer\|Transfer {\|mint_to\|MintTo\|burn\|Burn {` -> document sites; authority not validated -> MISSING_AUTHORITY_CHECK

**Misc**: `msg!.*secret\|msg!.*key` -> SENSITIVE_LOG; `Clock::get` -> timestamp deps; loops over `remaining_accounts` or unbounded vectors -> UNBOUNDED_LOOP

Write to {SCRATCHPAD}/static_analysis.md

## TASK 9: Run Test Suite

- If `package.json` exists: run `npm install` or `yarn` first to ensure TS test dependencies are available
- Anchor: `anchor test --skip-local-validator`, fallback `anchor test`, fallback `cargo test-sbf`
- Native: `cargo test-sbf`, fallback `cargo test`
- If TypeScript tests exist (tests/*.ts, tests/*.js): run them after Rust tests
If tests fail, note as TEST HEALTH WARNING.
Write to {SCRATCHPAD}/test_results.md

Return: 'DONE: Build {success/failed}, Fender {available/unavailable}, {N} functions, {M} account structs, {K} CPI sites, {J} static issues, tests: {pass/fail/skip}'
")
```

---

## Agent 3: Patterns + Surface + Templates

```
Task(subagent_type="general-purpose", prompt="
You are Recon Agent 3 (Patterns + Surface + Templates) for a Solana/Anchor program.

PROJECT_PATH: {path}
SCRATCHPAD: {scratchpad}

## RESILIENCE RULES
1. **Write-first principle**: Write partial results before any slow operation.
2. **No task is blocking**: Skip stuck tasks, document why, move on.

## TASK 4: Contract Inventory

1. Run `wc -l` on all .rs files in programs/ (exclude target/, node_modules/, .anchor/)
2. List each program with line count, instruction count, account struct count, state account count
3. List helper/utility crates
4. **Scope filtering**: If SCOPE_FILE is set, read it and mark programs as IN_SCOPE or OUT_OF_SCOPE. If SCOPE_NOTES is set, use them to refine scope. If neither is set, all programs are in scope.

Write to {SCRATCHPAD}/contract_inventory.md

## TASK 5: Attack Surface Discovery

### Part A: External Program CPIs
| External Program | Program ID | CPI Sites (file:line) | Accounts Forwarded | Signers Forwarded | Return Handling |

For each CPI: 1) Program ID hardcoded or passed? 2) Accounts re-validated? 3) PDA signer seeds correct? 4) Post-CPI reload? 5) Return data validated?

### Part B: Account Inventory Matrix
| Account Field | Type | PDA? | Seeds | Owner Check | Mutable? | Instructions Using It | Token Account? |

### Part C: Token Account Mapping
| Token Account | Mint | Authority | Protocol Reads Balance? | Uses amount Field? | Internal Tracking? | Unsolicited Transfer Impact |

Note: ANY SPL token account can receive unsolicited transfers. If protocol uses `token_account.amount` directly without internal tracking, it is vulnerable to donation attacks.

### Signal Elevation Tags

During attack surface analysis, tag risk signals that warrant explicit follow-up with `[ELEVATE]`:

Apply `[ELEVATE]` when you observe:
- `zero_copy(unsafe)` or `repr(C)` in account structs → `[ELEVATE:STRUCT_LAYOUT] Verify padding arithmetic in zero_copy structs`
- Single PDA per user constraint (seeds without epoch/nonce) → `[ELEVATE:SINGLE_RECEIPT] Analyze user-level DoS from single receipt constraint`
- Fork ancestry match (Yearn, Compound, Aave pattern detected) → `[ELEVATE:FORK_ANCESTRY:{parent}] Verify known {parent} vulnerability classes addressed`
- Asymmetric branch sizes in profit/loss or deposit/withdraw logic → `[ELEVATE:BRANCH_ASYMMETRY] Verify state completeness in shorter branch (Rule 17)`
- Non-idempotent account creation in init paths → `[ELEVATE:INIT_FRONTRUN] Verify front-running resistance of initialization`
- `init_if_needed` on security-critical accounts → `[ELEVATE:REINIT_RISK] Verify reinitialization protection`

Write `[ELEVATE]` tags directly into the relevant section of `attack_surface.md`.

### Part D: PDA Seed Analysis
| PDA | Seeds | Bump Storage | User-Controlled Components | Collision Risk |

Collision risk: fixed strings -> LOW; user pubkey -> LOW; user-supplied bytes without length prefix -> HIGH; numeric IDs -> MEDIUM.

Write to {SCRATCHPAD}/attack_surface.md

## TASK 6: Pattern Detection

Grep in program .rs files (exclude target/, tests/, node_modules/, .anchor/):

| Pattern | Flag |
|---------|------|
| `#\[account(init\|init_if_needed` | INITIALIZATION |
| `remaining_accounts` | REMAINING_ACCOUNTS |
| `invoke\|invoke_signed\|CpiContext` | CPI |
| `token::mint\|token::authority\|TokenAccount\|spl_token` | TOKEN_FLOW |
| `Pyth\|switchboard\|chainlink\|oracle\|price_feed\|PriceFeed` | ORACLE |
| `close\|CloseAccount\|close =` | ACCOUNT_CLOSING |
| `seeds\|bump\|find_program_address\|create_program_address` | PDA |
| `transfer_checked\|TransferChecked\|spl_token_2022\|Token2022` | TOKEN_2022 |
| `load_instruction_at\|Sysvar1nstructions\|sysvar::instructions` | INSTRUCTION_INTROSPECTION |
| `upgrade_authority\|BPFLoaderUpgradeab1e\|set_upgrade_authority` | UPGRADEABLE |
| `crank\|keeper\|bot\|operator\|#\[access_control\|authority\|admin` | SEMI_TRUSTED_ROLE |
| `epoch\|slot\|Clock\|unix_timestamp\|duration\|interval\|period` | TEMPORAL |
| `shares\|allocation\|distribute\|pro.rata\|proportional\|vest` | SHARE_ALLOCATION |
| `rate\|emission\|mint_to\|supply\|inflation\|reward_rate` | MONETARY_PARAMETER |
| `flash\|borrow.*repay\|loan\|flash_loan` | FLASH_LOAN |
| `\.amount\b.*\bcalculat\|\.amount\b.*\bdiv\|get_balance` | BALANCE_DEPENDENT |
| `wormhole\|bridge\|portal\|cross.*chain\|message.*account` | CROSS_CHAIN |
| `migrate\|upgrade\|v2\|deprecated\|legacy` | MIGRATION |
| `ed25519_program\|Secp256k1\|verify_signature\|Signature\|ed25519_instruction\|Secp256k1Program` | HAS_SIGNATURES |

Write to {SCRATCHPAD}/detected_patterns.md

## TASK 7: Prep Artifacts

**Admin/Authority-gated functions**: Grep for `has_one = authority`, `constraint = authority`, admin `Signer`, `#[access_control(*)]`
Write to {SCRATCHPAD}/setter_list.md (include '## Permissionless State-Modifiers' section)

**Events**: Grep `emit!\|emit_cpi!\|sol_log_data\|msg!` -> {SCRATCHPAD}/emit_list.md

**Constraint variables**: Grep `min\|max\|cap\|limit\|rate\|fee\|threshold\|factor\|multiplier\|ratio\|weight\|duration\|delay\|period\|decimal\|precision`. Mark UNENFORCED for variables with setters but no bounds.
Write to {SCRATCHPAD}/constraint_variables.md

**Setter x Emit Cross-Reference**: For each setter, check if it emits an event. Flag SILENT SETTERs.

## TASK 10: Template Recommendations

### Solana-Specific Templates (in ~/.claude/agents/skills/solana/)
- ACCOUNT_VALIDATION -- **ALWAYS required** (signer/owner/type checks, constraint completeness)
- CPI_SECURITY -- CPI flag (program ID validation, account forwarding, signer seeds, post-CPI reload)
- PDA_SECURITY -- PDA flag (seed collision, bump canonicalization, PDA authority)
- ACCOUNT_LIFECYCLE -- ACCOUNT_CLOSING flag (close account revival, rent reclaim, data zeroing)
- TOKEN_2022_EXTENSIONS -- TOKEN_2022 flag (transfer hooks, confidential transfers, fees, mint close)
- INSTRUCTION_INTROSPECTION -- INSTRUCTION_INTROSPECTION flag (introspection manipulation, relay attacks)

### Shared Templates (in ~/.claude/agents/skills/)
- SEMI_TRUSTED_ROLES, TOKEN_FLOW_TRACING, SHARE_ALLOCATION_FAIRNESS, TEMPORAL_PARAMETER_STALENESS
- ECONOMIC_DESIGN_AUDIT, EXTERNAL_PRECONDITION_AUDIT (adapted for CPI targets)
- ORACLE_ANALYSIS (adapted for Pyth/Switchboard), FLASH_LOAN_INTERACTION
- ZERO_STATE_RETURN, CROSS_CHAIN_TIMING, MIGRATION_ANALYSIS, FORK_ANCESTRY, VERIFICATION_PROTOCOL

For EACH recommended template provide: Trigger, Relevance, Instantiation Parameters, Key Questions.

---

## BINDING MANIFEST (MANDATORY)

> **CRITICAL**: Orchestrator MUST spawn an agent for every template marked `Required: YES`.

```markdown
## BINDING MANIFEST

| Template | Pattern Trigger | Required? | Reason |
|----------|-----------------|-----------|--------|
| ACCOUNT_VALIDATION | Always (Solana) | YES | Foundational Solana security |
| CPI_SECURITY | CPI flag | {YES/NO} | {N CPI sites found} |
| PDA_SECURITY | PDA flag | {YES/NO} | {N PDA derivations found} |
| ACCOUNT_LIFECYCLE | ACCOUNT_CLOSING flag | {YES/NO} | {N close operations found} |
| TOKEN_2022_EXTENSIONS | TOKEN_2022 flag | {YES/NO} | {Token-2022 patterns found} |
| INSTRUCTION_INTROSPECTION | INSTRUCTION_INTROSPECTION flag | {YES/NO} | {introspection patterns found} |
| SEMI_TRUSTED_ROLES | SEMI_TRUSTED_ROLE flag | {YES/NO} | {authority/admin/crank patterns} |
| TOKEN_FLOW_TRACING | BALANCE_DEPENDENT flag | {YES/NO} | {direct amount usage w/o internal tracking} |
| SHARE_ALLOCATION_FAIRNESS | SHARE_ALLOCATION flag | {YES/NO} | {share/allocation patterns} |
| TEMPORAL_PARAMETER_STALENESS | TEMPORAL flag | {YES/NO} | {temporal patterns with cached params} |
| ECONOMIC_DESIGN_AUDIT | MONETARY_PARAMETER flag | {YES/NO} | {monetary parameter setters found} |
| EXTERNAL_PRECONDITION_AUDIT | CPI targets detected | {YES/NO} | {N external CPI targets} |
| ORACLE_ANALYSIS | ORACLE flag | {YES/NO} | {Pyth/Switchboard patterns found} |
| FLASH_LOAN_INTERACTION | FLASH_LOAN flag | {YES/NO} | {flash loan patterns found} |
| ZERO_STATE_RETURN | Vault/first-depositor | {YES/NO} | {vault pattern found} |
| CROSS_CHAIN_TIMING | CROSS_CHAIN flag | {YES/NO} | {bridge/cross-chain patterns} |
| MIGRATION_ANALYSIS | MIGRATION flag | {YES/NO} | {migration/upgrade patterns} |
| FORK_ANCESTRY | Always | YES | Historical vulnerability inheritance |

### Binding Rules
- ACCOUNT_VALIDATION **ALWAYS REQUIRED** for Solana programs
- FORK_ANCESTRY **ALWAYS REQUIRED**
- CPI flag -> CPI_SECURITY **REQUIRED**
- PDA flag -> PDA_SECURITY **REQUIRED**
- ACCOUNT_CLOSING flag -> ACCOUNT_LIFECYCLE **REQUIRED**
- TOKEN_2022 flag -> TOKEN_2022_EXTENSIONS **REQUIRED**
- INSTRUCTION_INTROSPECTION flag -> INSTRUCTION_INTROSPECTION **REQUIRED**
- SEMI_TRUSTED_ROLE flag -> SEMI_TRUSTED_ROLES **REQUIRED**
- BALANCE_DEPENDENT flag -> TOKEN_FLOW_TRACING **REQUIRED**
- SHARE_ALLOCATION flag -> SHARE_ALLOCATION_FAIRNESS **REQUIRED**
- TEMPORAL flag -> TEMPORAL_PARAMETER_STALENESS **REQUIRED**
- MONETARY_PARAMETER flag -> ECONOMIC_DESIGN_AUDIT **REQUIRED**
- CPI targets detected -> EXTERNAL_PRECONDITION_AUDIT **REQUIRED**
- ORACLE flag -> ORACLE_ANALYSIS **REQUIRED**
- FLASH_LOAN flag -> FLASH_LOAN_INTERACTION **REQUIRED**
- CROSS_CHAIN flag -> CROSS_CHAIN_TIMING **REQUIRED**
- MIGRATION flag -> MIGRATION_ANALYSIS **REQUIRED**

### Niche Agent Binding Rules
- MISSING_EVENT flag detected (setter_list.md has MISSING EVENT entries OR emit_list.md shows state-changing functions without events) → EVENT_COMPLETENESS **niche agent** REQUIRED
- HAS_SIGNATURES flag detected (ed25519_program/Secp256k1/verify_signature patterns found) → SIGNATURE_VERIFICATION_AUDIT **niche agent** REQUIRED
- DOCUMENTATION is non-empty AND contains testable protocol claims (fee structures, thresholds, permissions, distribution logic) → SPEC_COMPLIANCE_AUDIT **niche agent** REQUIRED (set `HAS_DOCS` flag)
- HAS_MULTI_CONTRACT flag detected (2+ in-scope programs AND constraint_variables.md shows shared parameters/formulas across programs) → SEMANTIC_CONSISTENCY_AUDIT **niche agent** REQUIRED

### Niche Agents (Phase 4b - standalone focused agents, 1 budget slot each)

| Niche Agent | Trigger | Required? | Reason |
|-------------|---------|-----------|--------|
| EVENT_COMPLETENESS | MISSING_EVENT flag (setter_list.md / emit_list.md) | {YES/NO} | {if YES: N setters without events found} |
| SIGNATURE_VERIFICATION_AUDIT | HAS_SIGNATURES flag (detected_patterns.md) | {YES/NO} | {if YES: signature verification patterns found} |
| SPEC_COMPLIANCE_AUDIT | HAS_DOCS flag (non-empty DOCUMENTATION with testable claims) | {YES/NO} | {if YES: docs contain testable claims} |
| SEMANTIC_CONSISTENCY_AUDIT | HAS_MULTI_CONTRACT flag (contract_inventory.md + constraint_variables.md) | {YES/NO} | {if YES: N shared parameters/formulas across M programs} |

### Manifest Summary
- **Total Required Breadth Agents**: {count of YES in skill templates}
- **Total Required Niche Agents**: {count of YES in niche agents}
- **Total Optional Agents**: {count of NO with recommendation}
- **HARD GATE**: Orchestrator MUST spawn agent for each REQUIRED template AND each REQUIRED niche agent
```

Write to {SCRATCHPAD}/template_recommendations.md

Return: 'DONE: {N} programs inventoried ({L} lines), {M} patterns detected, {K} templates recommended, flags: [{list}]'
")
```

---

## After ALL 4 Recon Agents Return

1. **Verify artifacts exist**: `ls {scratchpad}/` -- must have all files:
   - `meta_buffer.md` (1A), `design_context.md` (1B), `external_production_behavior.md` (1B)
   - `build_status.md`, `function_list.md`, `call_graph.md`, `state_variables.md`, `modifiers.md`, `event_definitions.md`, `external_interfaces.md`, `static_analysis.md`, `test_results.md` (2)
   - `contract_inventory.md`, `attack_surface.md`, `detected_patterns.md`, `setter_list.md`, `emit_list.md`, `constraint_variables.md`, `template_recommendations.md` (3)

2. **RAG resilience check**: If `meta_buffer.md` missing/empty (Agent 1A timed out):
   - Spawn lightweight RAG-retry agent (haiku, <2 min, 3 queries only)
   - If retry fails: proceed with empty meta_buffer.md

3. **Read summary artifacts**: template_recommendations.md (BINDING MANIFEST), attack_surface.md, detected_patterns.md

4. **Write recon_summary.md**:
```markdown
# Recon Summary -- Solana
1. **Build Status**: {success/failed}
2. **Framework**: Anchor {version} / Native
3. **Programs**: {count} totaling {lines} lines
4. **Instructions**: {count}
5. **External Program Dependencies**: {count} -- {names}
6. **Detected Patterns**: {list flags}
7. **Recommended Templates**: {list with brief reason each}
8. **Overflow Checks**: {enabled/disabled/missing}
9. **Fender Status**: {available/unavailable}
10. **Artifacts Written**: {list all files}
11. **Coverage Gaps**: {tools that failed}
```

5. **Hard gate**: ALL artifacts must exist before Phase 2. If any missing, re-spawn the responsible agent.
