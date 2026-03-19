# MCP Tools Reference - Sui Move

> **No Slither for Move**: Sui Move does not have Slither or equivalent AST-level static analysis MCP tools. The primary static analysis tool is `sui move build` with warnings enabled. All `mcp__slither-analyzer__*` and `mcp__farofino__*` tools are NOT applicable to Sui Move packages.
>
> **Solana tools are NOT applicable**: `mcp__solana-fender__*` tools target Solana/Anchor programs and MUST NOT be used for Sui Move analysis.
>
> **No Sui-specific MCP servers available.** Use `sui move build` via Bash for static checks, and `Read` + `Grep` tools for all source analysis. The only available MCP tools are the language-agnostic ones: `mcp__unified-vuln-db__*` (vulnerability database) and `mcp__tavily-search__*` (web research).
>
> **MCP tools (`mcp__unified-vuln-db__*`) are available directly.** The servers are configured globally in `~/.claude.json` and load automatically at session start. Call them directly -- no ToolSearch or loading step needed.
>
> **If a tool call fails with "No such tool available"**, it means the MCP server failed to start. Check with `claude mcp list` and restart the session.

> **Mental model**: You are good at understanding INTENT and tracing LOGIC. Tools are good at EXHAUSTIVE ENUMERATION. You miss things when scanning large files manually. Tools never skip anything but can't understand intent. **Use both.**

> **MCP TIMEOUT POLICY (MANDATORY)**: When an MCP tool call returns a timeout error or fails, do NOT retry the same call. Record `[MCP: TIMEOUT]` and skip ALL remaining calls to that provider - switch immediately to fallback (code analysis, grep, WebSearch). Claude Code's default tool timeout is 60s (configurable via `MCP_TOOL_TIMEOUT` env var). You cannot cancel a pending call, but you control what happens after the error returns.

---

## Static Analysis for Sui Move

### No Slither Equivalent

Sui Move has no Slither-equivalent MCP tool. The primary static checks come from the Move compiler and (when available) the Sui Move Prover for formal verification.

**What this means for agents**:
- Do NOT call any `mcp__slither-analyzer__*` tools -- they will fail
- Do NOT call any `mcp__farofino__*` tools -- they are EVM-specific
- Do NOT call any `mcp__solana-fender__*` tools -- they are Solana-specific
- Use `sui move build` for compilation warnings and errors
- Use `Read` tool for all source code extraction
- Use `Grep` tool for caller/callee tracing, pattern detection, and function enumeration

### Static Analysis Escalation Ladder

| Priority | Tool | What It Provides | When to Use |
|----------|------|-----------------|-------------|
| 1 (Primary) | `sui move build` (via Bash) | Compilation errors, unused warnings, ability violations, type mismatches | Always attempt first |
| 2 (If available) | Sui Move Prover | Formal verification against specs | When `.spec` blocks exist in source or separate spec files present |
| 3 (Always available) | Grep + Read tools | Manual pattern search, source extraction, call tracing | Primary analysis method for all agents |

### Build Check Policy

**Recon (Phase 1)**: Agent 2 runs `sui move build` on the package. Results documented in `build_status.md`:
```markdown
BUILD_AVAILABLE = true/false
BUILD_TOOL = sui move build
BUILD_WARNINGS = [list of compiler warnings]
BUILD_ERRORS = [list of errors, if any]
PROVER_AVAILABLE = true/false
```

If build fails:
- Document failure reason in `build_status.md`
- ALL analysis proceeds via `Read` + `Grep` tools (manual source analysis)
- Agents MUST NOT attempt `sui move build` calls if recon documented BUILD_AVAILABLE = false

If build succeeds:
- Compiler warnings are promoted to findings by the inventory agent (Phase 4a)
- Promotable warnings: unused variables, dead code, unused imports, ability constraint violations

**Depth agent policy**: If `build_status.md` shows BUILD_AVAILABLE = false, use `Read` tool for all source extraction and `Grep` for caller/callee tracing. Do NOT attempt build commands.

**Verification (Phase 5)**: Verifiers check `build_status.md` for build status. If build available, write `sui move test` PoC using `test_scenario`. If unavailable, use `Read` tool for all source analysis and mark evidence as [CODE] only.

### Grep-Based Analysis Patterns (Replace Slither Functions)

| Slither Equivalent | Grep Pattern | Purpose |
|-------------------|-------------|---------|
| `list_functions` | `grep -n "public\|public(package)\|entry\|fun " *.move` | Function inventory |
| `list_contracts` | `grep -rn "module " sources/` | Module inventory |
| `get_function_callees` | `grep -n "{module}::{function}" sources/` | Cross-module call tracing |
| `analyze_state_variables` | `grep -n "struct.*has\|let mut\|borrow_mut" sources/` | State variable analysis |
| `analyze_modifiers` | `grep -n "assert!\|abort\|#\[" sources/` | Guard/assertion analysis |
| `find_dead_code` | Build warnings + `grep` for unused definitions | Dead code detection |
| `export_call_graph` | `grep -rn "use\|::" sources/` combined with module analysis | Dependency mapping |

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

**Bug classes**: access-control, arithmetic-precision, oracle-manipulation, dos, ability-misuse, bit-shift-overflow, object-ownership

**Sui-specific query tips**:
- For ability misuse: `get_root_cause_analysis('ability-misuse')` or `get_attack_vectors('access-control')` with Move context
- For object ownership: `get_similar_findings('shared object concurrent modification')` or `get_attack_vectors('object-ownership')`
- For bit-shift: `get_root_cause_analysis('bit-shift-overflow')` or `get_attack_vectors('arithmetic-precision')` with shift context

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
  keywords="object ownership shared concurrent",  # Free-text search
  impact=["HIGH", "MEDIUM"],                      # Severity filter
  tags=["Move", "Sui", "Object", "Ability"],      # Solodit vulnerability tags
  protocol="{PROTOCOL_NAME}",                     # Protocol name (partial match)
  protocol_category=["DeFi"],                     # Category filter (array)
  firms=["{RELEVANT_FIRM}"],                       # Audit firm filter
  language="Move",                                # Language: Solidity/Rust/Cairo/Move
  quality_score=3,                                # Min quality (0-5), use >=3
  rarity_score=3,                                 # Min rarity (0-5), unique patterns
  min_finders=1, max_finders=1,                  # Solo finds only
  sort_by="Quality",                              # Quality/Recency/Rarity
  sort_direction="Desc",                          # Desc/Asc
  max_results=20                                  # Up to 50
)
```

**Common Solodit Tags for Sui/Move**: Move, Sui, Object, Shared Object, PTB, Ability, Bit Shift,
Access Control, Oracle, Logic Error, DOS, Griefing, Precision Loss, Rounding, Initialization,
Upgrade, Front-running, Price Manipulation, Governance, Cross-chain,
Slippage, Timestamp, Type Safety, Hot Potato

---

## tavily-search -- Web Research

| Tool | What It Gives You | When to Use |
|------|-------------------|-------------|
| `mcp__tavily-search__tavily_search` | Web search results | During recon for protocol documentation, known Move/Sui issues |
| `mcp__tavily-search__tavily_extract` | Extract content from URLs | When documentation URL is provided by user |
| `mcp__tavily-search__tavily_research` | Deep research on topic | Understanding protocol architecture from public sources |
| `mcp__tavily-search__tavily_crawl` | Crawl site for content | Gathering comprehensive documentation from protocol site |

**Fork Ancestry usage**: Use `tavily_search` during TASK 0 to research known vulnerabilities of detected parent codebases: `tavily_search(query="{parent_name} Move Sui smart contract vulnerability exploit")`. See FORK_ANCESTRY skill for methodology.

**Sui-specific search queries**:
- `tavily_search(query="Sui Move object ownership vulnerability")` -- shared object attack patterns
- `tavily_search(query="Sui PTB programmable transaction block exploit")` -- PTB composability issues
- `tavily_search(query="Move ability constraint bypass")` -- ability misuse patterns
- `tavily_search(query="Sui package upgrade vulnerability")` -- upgrade safety issues

---

## MCP Failure Policy

### Tool Availability Documentation

Document in `build_status.md`:
```markdown
## Tool Availability
BUILD_AVAILABLE = true/false        # sui move build
PROVER_AVAILABLE = true/false       # Sui Move Prover (formal verification)
VULN_DB_AVAILABLE = true/false      # mcp__unified-vuln-db__*
TAVILY_AVAILABLE = true/false       # mcp__tavily-search__*
SLITHER_AVAILABLE = N/A             # Not applicable to Sui Move
FAROFINO_AVAILABLE = N/A            # Not applicable to Sui Move
SOLANA_FENDER_AVAILABLE = N/A       # Not applicable to Sui Move
```

### Failure Handling

| Tool | If Fails | Action |
|------|----------|--------|
| `sui move build` | Build errors | All analysis via Read + Grep. Document errors for context. |
| Sui Move Prover | Not available or specs missing | Skip formal verification. Note in build_status.md. |
| `mcp__unified-vuln-db__*` | MCP server down | Proceed without RAG. Set `RAG_AVAILABLE = false`. Floor RAG axis at 0.3 in scoring. |
| `mcp__tavily-search__*` | MCP server down | Skip web research. Document gap. Use codebase-only analysis. |

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

**Optional skill skip**: If total agent count > 15, skip optional skills to conserve budget.
