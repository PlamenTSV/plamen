# MCP Tools Reference - Solana

> **MCP tools are available directly** - call them without ToolSearch or loading.
> If a tool call fails with "No such tool available", the MCP server failed to start.

> **MCP tools are your PRIMARY interface to Fender and the vulnerability database.** Call `mcp__solana-fender__*` and `mcp__unified-vuln-db__*` tools DIRECTLY - never route through Bash or CLI unless the MCP call itself has failed. This is not a preference; it is a hard requirement. CLI is the fallback, not the default.

> **Mental model**: You are good at understanding INTENT and tracing LOGIC. Tools are good at EXHAUSTIVE ENUMERATION. You miss things when scanning large files manually. Tools never skip anything but can't understand intent. **Use both.**

> **MCP TIMEOUT POLICY (MANDATORY)**: When an MCP tool call returns a timeout error or fails, do NOT retry the same call. Record `[MCP: TIMEOUT]` and skip ALL remaining calls to that provider - switch immediately to fallback (code analysis, grep, WebSearch). Claude Code's default tool timeout is 60s (configurable via `MCP_TOOL_TIMEOUT` env var). You cannot cancel a pending call, but you control what happens after the error returns.

## Solana MCP Servers

### helius - On-Chain Account Data (Production Verification)

> **Package**: `@mcp-dockmaster/mcp-server-helius` (dcSpark). Requires `HELIUS_API_KEY`.

| Tool | What It Gives You | When to Use |
|------|-------------------|-------------|
| `mcp__helius__helius_get_balance` | SOL balance of account | Production balance verification |
| `mcp__helius__helius_get_account_info` | Full account data (owner, data, lamports) | Verify account type and ownership |
| `mcp__helius__helius_get_token_accounts_by_owner` | All token accounts for a wallet | Inventory protocol's token holdings |
| `mcp__helius__helius_get_asset` | Digital asset metadata (DAS API) | NFT/token metadata verification |
| `mcp__helius__helius_get_signatures_for_address` | Transaction history for account | Trace production behavior |
| `mcp__helius__helius_get_program_accounts` | All accounts owned by a program | Enumerate protocol state accounts |
| `mcp__helius__helius_get_multiple_accounts` | Batch account data fetch | Bulk state verification |
| `mcp__helius__helius_get_transaction` | Full transaction data | Verify specific tx behavior |
| `mcp__helius__helius_get_token_supply` | Token mint supply | Verify total supply |
| `mcp__helius__helius_get_token_account_balance` | SPL token account balance | Specific token account verification |
| `mcp__helius__helius_get_minimum_balance_for_rent_exemption` | Rent-exempt lamport threshold | Rent calculation verification |
| `mcp__helius__helius_get_block_height` | Current block height | Chain state reference |
| `mcp__helius__helius_get_slot` | Current slot | Chain state reference |
| `mcp__helius__helius_get_latest_blockhash` | Recent blockhash | Transaction construction |

**Usage**: Production verification (TASK 11), external contract verification, on-chain state checks.
**Evidence tag**: Results tagged as `[PROD-ONCHAIN]` - valid for REFUTED verdicts.

### solana-fender - Static Analysis (Anchor Programs)

> **Package**: `anchor-mcp` + `solana_fender` (honey-guard). Installed via Cargo.

| Tool | What It Gives You | When to Use |
|------|-------------------|-------------|
| `mcp__solana-fender__security_check_program` | Run all 19 security detectors on an Anchor program directory | TASK 2 - after build succeeds |
| `mcp__solana-fender__security_check_file` | Run detectors on a single Anchor source file | Targeted analysis during depth |

**19 Fender Detectors**: missing-owner-check, arbitrary-cpi, closing-accounts, duplicate-mutable-accounts, type-cosplay, reentrancy, integer-overflow, precision-loss, seed-collision, bump-seed-canonicalization, missing-signer-check, account-validation, pda-security, signer-check, remaining-accounts, sysvar-check, authority-check, reinitialization, unsafe-math.

**Failure Policy**: Same as Slither - ONE probe call. If fails, `FENDER_AVAILABLE = false` for entire audit. Grep fallback for all subsequent tasks.

### unified-vuln-db - Vulnerability Database

> **Package**: Local SQLite + Solodit live search. No API key required.

| Tool | What It Gives You | When to Use |
|------|-------------------|-------------|
| `mcp__unified-vuln-db__get_common_vulnerabilities(protocol_type)` | Common vulnerability patterns for a protocol category | TASK 0 - protocol classification |
| `mcp__unified-vuln-db__get_attack_vectors(bug_class)` | Specific attack vectors for a vulnerability class | Understanding exploit mechanics |
| `mcp__unified-vuln-db__search_solodit_live(keywords, tags, impact, language, quality_score, ...)` | Live search across Solodit finding database (50k+) | Cross-referencing with historical findings. Use `language="Rust"` for Solana, `quality_score=3` for good findings |
| `mcp__unified-vuln-db__validate_hypothesis(hypothesis)` | Confidence score for a hypothesis based on historical data | Before verification - calibrate confidence |
| `mcp__unified-vuln-db__get_similar_findings(description)` | Similar historical findings with severity info | Calibrate severity |
| `mcp__unified-vuln-db__assess_hypothesis_strength(hypothesis)` | Strength assessment based on evidence | Chain analysis RAG validation |
| `mcp__unified-vuln-db__analyze_code_pattern(pattern)` | Known vulnerability patterns matching a code structure | Depth agent pattern analysis |
| `mcp__unified-vuln-db__get_root_cause_analysis(pattern)` | Root cause classification for a vulnerability pattern | Understanding underlying causes |

**Solana-specific Solodit tags**: `Account Validation`, `CPI`, `PDA`, `Anchor`, `Solana`, `Token-2022`.

### tavily-search - Web Research

> **Package**: `tavily-mcp` (Tavily). Requires `TAVILY_API_KEY`.

| Tool | What It Gives You | When to Use |
|------|-------------------|-------------|
| `mcp__tavily-search__tavily_search(query)` | Web search results | Protocol documentation, known Solana exploits |
| `mcp__tavily-search__tavily_extract(url)` | Content extraction from URL | Reading docs, whitepapers |
| `mcp__tavily-search__tavily_research(topic)` | Multi-query research on a topic | Fork ancestry research, deep-dive on exploit patterns |
| `mcp__tavily-search__tavily_crawl(url)` | Recursive URL crawling | Exploring documentation sites |
| `mcp__tavily-search__tavily_map(url)` | URL mapping/sitemap | Understanding documentation structure |

---

## Static Analysis Escalation Ladder - Solana

| Priority | Tool | When to Use |
|----------|------|-------------|
| 1 (Primary) | `mcp__solana-fender__security_check_program` | Always attempt first |
| 2 (Fallback A) | `cargo clippy` via Bash | When Fender fails |
| 3 (Fallback B) | Grep + Read tools | When all tools fail |

---

## Verification Tools - Solana

| Purpose | Tool | Notes |
|---------|------|-------|
| PoC testing | LiteSVM (Rust test framework) | No Anvil equivalent. Manual account dumps. |
| Account inspection | `mcp__helius__helius_get_account_info` | Production account data |
| Transaction replay | `mcp__helius__helius_get_signatures_for_address` | Historical tx analysis |
| Evidence level | `[PROD-LITESVM]` for LiteSVM tests | Valid for REFUTED |

**Fork testing limitation**: No Anvil-equivalent for Solana. Use `solana account --output json <address>` to dump production accounts, then load into LiteSVM for testing. Document as coverage gap.

---

## Cascaded Model Selection Reference

| Task Type | Default Model | Budget Degradation (>15 agents) |
|-----------|--------------|--------------------------------|
| Scoring agent | haiku | haiku (no change) |
| Index agent (6a) | haiku | haiku (no change) |
| Breadth agents | sonnet | sonnet (no change) |
| Depth agents | specialized (depth-*) | specialized (no change) |
| Blind spot scanners | sonnet (general-purpose) | sonnet (no change) |
| Validation sweep | sonnet (general-purpose) | sonnet (no change) |
| Critical+High tier writer (6b) | opus | opus (no change - quality critical) |
| Medium tier writer (6b) | sonnet | haiku (if >15 agents used) |
| Low+Info tier writer (6b) | sonnet | haiku (if >15 agents used) |
| Assembler (6c) | haiku (≤25 findings), sonnet (>25) | sonnet if >25 (no change) |

**Optional skill skip**: If total agent count > 15, skip optional skills (CENTRALIZATION_RISK) to conserve budget.

---

## Tool Availability Notes

- **Helius MCP**: Requires `HELIUS_API_KEY` env var. If unavailable, use `solana` CLI as fallback.
- **Fender MCP**: Requires Anchor project structure and Cargo-installed `anchor-mcp` binary. If unavailable, use grep fallback.
- Both servers need validation during first Solana audit. Document availability in `build_status.md`.
