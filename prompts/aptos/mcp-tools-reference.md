# MCP Tools Reference -- Aptos/Move

> **No Move-specific MCP servers are available.** Unlike EVM (which has Slither MCP and Farofino), the Aptos/Move ecosystem does not have dedicated MCP static analysis servers. Use CLI tools via Bash for compilation, testing, and formal verification.
>
> **MCP tools (`mcp__unified-vuln-db__*`, `mcp__tavily-search__*`) are available directly.** The servers are configured globally in `~/.claude.json` and load automatically at session start. Call them directly -- no ToolSearch or loading step needed.
>
> **If a tool call fails with "No such tool available"**, it means the MCP server failed to start. Check with `claude mcp list` and restart the session.

> **Mental model**: You are good at understanding INTENT and tracing LOGIC. Tools are good at EXHAUSTIVE ENUMERATION. You miss things when scanning large files manually. Tools never skip anything but can't understand intent. **Use both.**

> **MCP TIMEOUT POLICY (MANDATORY)**: When an MCP tool call returns a timeout error or fails, do NOT retry the same call. Record `[MCP: TIMEOUT]` and skip ALL remaining calls to that provider - switch immediately to fallback (code analysis, grep, WebSearch). Claude Code's default tool timeout is 60s (configurable via `MCP_TOOL_TIMEOUT` env var). You cannot cancel a pending call, but you control what happens after the error returns.

---

## Static Analysis Escalation Ladder for Aptos/Move

When analyzing Move code, use this tool chain in priority order:

| Priority | Tool | What It Provides | When to Use |
|----------|------|-----------------|-------------|
| 1 (Primary) | `aptos move prove` | Formal verification against spec annotations | Always attempt first if `spec` blocks exist in source |
| 2 (Fallback A) | `aptos move compile --check` | Type checking, ability verification, dependency resolution | When Move Prover fails or no spec annotations present |
| 3 (Fallback B) | Grep + Read tools | Manual pattern search, call graph tracing, ability auditing | When all CLI tools fail or for targeted analysis |

### Move Prover (`aptos move prove`)

**What it catches**: Formal property violations, arithmetic overflow/underflow (with specs), resource invariant violations, abort condition verification, loop bound violations.

**How to use**:
```bash
# Run prover on entire package
aptos move prove --package-dir {PROJECT_DIR}

# Run prover on specific module
aptos move prove --package-dir {PROJECT_DIR} --filter {module_name}
```

**Evidence level**: Move Prover violations are [CODE] evidence at highest quality. A Prover-confirmed violation is strong evidence for CONFIRMED verdict. Prover success for a relevant `spec` property is strong evidence for FALSE_POSITIVE.

**Failure modes**: The Move Prover may fail on:
- Modules without `spec` annotations (nothing to verify)
- Complex data structures (Tables, SmartVectors with nested generics)
- External module dependencies not available locally
- Timeout on complex verification conditions

**Recon policy**: Probe Move Prover with one `aptos move prove` call during TASK 2. If it fails, set `PROVER_AVAILABLE = false` in `build_status.md`. Do not retry.

### Compilation Check (`aptos move compile --check`)

**What it catches**: Type errors, ability constraint violations, missing dependencies, visibility violations, unused variables/imports.

**How to use**:
```bash
# Check compilation of entire package
aptos move compile --check --package-dir {PROJECT_DIR}

# Full compilation (generates bytecode)
aptos move compile --package-dir {PROJECT_DIR}
```

**Recon policy**: Always run `aptos move compile --check` during TASK 2, regardless of Prover availability. Compilation warnings and errors are promoted as static analysis findings.

### Build Status Documentation

The recon agent documents tool availability in `{SCRATCHPAD}/build_status.md`:

```markdown
# Build Status
- COMPILE_AVAILABLE = true/false  (aptos move compile succeeded)
- PROVER_AVAILABLE = true/false   (aptos move prove succeeded on at least one module)
- TEST_AVAILABLE = true/false     (aptos move test succeeded)
- PROVER_FAILURE_REASON = {reason if false}
- COMPILE_FAILURE_REASON = {reason if false}
```

### Manual Analysis (Grep + Read)

When CLI tools fail or for targeted analysis beyond what the compiler checks:

| Pattern | Grep Command | What It Finds |
|---------|-------------|---------------|
| Ability annotations | `has key`, `has store`, `has drop`, `has copy` | All struct ability declarations |
| Public functions | `public fun`, `public entry fun`, `public(friend) fun` | Full visibility surface |
| Friend declarations | `friend ` | Cross-module trust boundaries |
| External calls | `use 0x1::`, `use {addr}::` | Framework and third-party dependencies |
| Resource operations | `move_to`, `move_from`, `borrow_global`, `borrow_global_mut`, `exists` | Global storage access patterns |
| Object operations | `object::create_object`, `ConstructorRef`, `TransferRef`, `MintRef`, `BurnRef`, `ExtendRef`, `DeleteRef` | Object lifecycle and capability management |
| Bit shifts | `<<`, `>>` | Potential abort vectors (MR2) |
| Assertions | `assert!`, `abort` | Error handling and precondition checks |
| Randomness | `randomness::`, `#[randomness]` | Randomness API usage (AR4) |
| Dispatchable hooks | `dispatchable_fungible_asset`, `deposit_dispatch`, `withdraw_dispatch` | FA hook registration (AR2) |
| Event emissions | `event::emit` | Event correctness audit inputs |

**Depth agent policy**: Since no MCP static analyzer exists for Move, depth agents use Read tool for source extraction and Grep for caller/callee tracing. This is the standard path, not a fallback.

---

## unified-vuln-db -- Your Attack Pattern Library

### Local Database Tools (~3.4k indexed findings)

| Tool | What It Gives You | When to Use |
|------|-------------------|-------------|
| `get_root_cause_analysis(bug_class)` | Why specific bug classes occur | Step 1c -- prime your analysis |
| `get_attack_vectors(bug_class)` | How exploits work mechanically | Depth agents -- understand exploit mechanics |
| `analyze_code_pattern(pattern, code_context)` | Pattern matching against known vulns | Step 6 -- validate hypotheses |
| `validate_hypothesis(hypothesis)` | Cross-reference against known bugs | Step 6 -- before verification |
| `get_similar_findings(description)` | Similar bugs from other audits | Step 6 -- calibrate severity |

**Bug classes**: reentrancy, access-control, arithmetic-precision, oracle-manipulation, flash-loan, dos, ability-misuse, bit-shift-overflow

**Aptos-specific query tips**: The database is EVM-heavy but vulnerability patterns transfer. Frame queries in terms of the underlying pattern:
- For ability misuse: `get_root_cause_analysis(bug_class='access-control')` + search for "copy"/"drop" patterns
- For bit-shift overflow: `get_attack_vectors(bug_class='arithmetic-precision')` covers overflow patterns
- For type confusion: `get_root_cause_analysis(bug_class='access-control')` + search for "type" patterns
- For ref lifecycle: `get_attack_vectors(bug_class='access-control')` + search for "capability"/"permission" patterns
- "resource access control" maps to -> access-control
- "oracle price manipulation" maps to -> oracle-manipulation
- "donation attack threshold manipulation" maps to -> dos

### Live Solodit API (50k+ findings -- MANDATORY for comprehensive analysis)

| Tool | What It Gives You | When to Use |
|------|-------------------|-------------|
| `search_solodit_live(...)` | Full Solodit database search | **MANDATORY** during hypothesis validation and deep dives |

**MANDATORY Usage -- Call `search_solodit_live` when:**
1. Local search returns < 5 results -> Expand search
2. Validating HIGH/CRITICAL hypothesis -> Cross-reference comprehensively
3. Protocol-specific deep dive -> Search by protocol name
4. Understanding attack patterns -> Search by vulnerability tags

**Parameters:**
```
search_solodit_live(
  keywords="ability misuse copy drop Move",     # Free-text search
  impact=["HIGH", "MEDIUM"],                    # Severity filter
  tags=["Move", "Aptos", "Logic Error"],        # Solodit vulnerability tags
  protocol="",                                  # Protocol name (partial match)
  protocol_category=["DeFi"],                   # Category filter (array)
  firms=["{RELEVANT_FIRM}"],                     # Audit firm filter
  language="Move",                              # Language: Solidity/Rust/Cairo/Move
  quality_score=3,                              # Min quality (0-5), use >=3
  rarity_score=3,                               # Min rarity (0-5), unique patterns
  min_finders=1, max_finders=1,                # Solo finds only
  sort_by="Quality",                            # Quality/Recency/Rarity
  sort_direction="Desc",                        # Desc/Asc
  max_results=20                                # Up to 50
)
```

**Common Solodit Tags (general)**: Reentrancy, Oracle, Access Control, Flash Loan, Front-running,
Price Manipulation, Logic Error, DOS, Griefing, Signature, Upgrade, Initialization,
Precision Loss, Rounding, First Depositor, Share Inflation, ERC4626, Liquidation,
Governance, Cross-chain, Bridge, Slippage, Timestamp, Randomness, Delegatecall

**Aptos/Move-Relevant Solodit Tags**: Move, Aptos, Ability, Bit Shift, FungibleAsset,
Object, Resource, Type Safety, Module Upgrade, Capability

> **Note**: The Solodit database is predominantly EVM-focused. For Move/Aptos-specific patterns, supplement with `tavily_search` for Aptos-specific vulnerability disclosures, Move security blog posts, and Aptos framework changelog entries.

---

## tavily-search -- Web Research

| Tool | What It Gives You | When to Use |
|------|-------------------|-------------|
| `mcp__tavily-search__tavily_search` | Web search results | During recon for protocol documentation, known issues, Aptos-specific vulnerabilities |
| `mcp__tavily-search__tavily_extract` | Extract content from URLs | When documentation URL is provided by user |
| `mcp__tavily-search__tavily_research` | Deep research on topic | Understanding protocol architecture from public sources |
| `mcp__tavily-search__tavily_crawl` | Crawl site for content | Gathering comprehensive documentation from protocol site |

**Fork Ancestry usage**: Use `tavily_search` during TASK 0 to research known vulnerabilities of detected parent codebases: `tavily_search(query="{parent_name} Move smart contract vulnerability exploit")`. See FORK_ANCESTRY skill for methodology.

**Aptos-specific research queries**:
- `"Aptos Move security vulnerability {pattern}"` -- for Move-specific vuln patterns
- `"aptos-framework changelog breaking changes"` -- for framework dependency risks
- `"Move Prover formal verification {module_pattern}"` -- for verification approaches
- `"Aptos object model security"` -- for Object/resource model risks
- `"dispatchable fungible asset hook security"` -- for FA dispatch hook patterns

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
| Critical+High tier writer (6b) | opus | opus (no change -- quality critical) |
| Medium tier writer (6b) | sonnet | haiku (if >15 agents used) |
| Low+Info tier writer (6b) | sonnet | haiku (if >15 agents used) |
| Assembler (6c) | haiku (<=25 findings), sonnet (>25) | sonnet if >25 (no change) |

**Optional skill skip**: If total agent count > 15, skip optional skills (EVENT_CORRECTNESS, CENTRALIZATION_RISK) to conserve budget.

---

## MCP Failure Policy -- Aptos Summary

| Scenario | Action |
|----------|--------|
| Move Prover fails (no specs, prover error) | Set `PROVER_AVAILABLE = false`, all analysis via Read + Grep |
| `aptos move compile` fails | Set `COMPILE_AVAILABLE = false`, analyze source directly via Read |
| `aptos move test` fails | Set `TEST_AVAILABLE = false`, verifiers write PoC tests but note compilation failure |
| unified-vuln-db MCP fails | Document failure, proceed without RAG (RAG_Match axis = 0.3 floor) |
| tavily-search MCP fails | Document failure, proceed without web research |
| All MCP tools fail | Full audit proceeds via Read + Grep tools only -- document in build_status.md |

**Key difference from EVM**: There is no Slither equivalent for Move. The entire static analysis pipeline relies on Move Prover (formal verification) and compile-time checks. When these fail, manual pattern search via Grep is the ONLY fallback. This makes thorough manual source review even more critical for Move audits.
