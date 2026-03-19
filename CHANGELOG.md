# Changelog

All notable changes to Plamen will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.4] - 2026-03-19

### Changed
- **Scanner A (EVM)**: Added CHECK 1b — mandatory rebasing vs FOT severity differentiation. Rebasing tokens now escalate to **High** (separate finding); FOT stays **Medium**. Prevents merging two distinct risks with different timing, magnitude, and fixes.
- **Inventory TASK 1.5 (EVM)**: Added explicit-capability WITHIN-BOUNDS heuristic. When a SEMI_TRUSTED actor's attack action appears verbatim in their `bounds:` clause, presume WITHIN-BOUNDS. Reduces over-reporting of design-level risks as implementation bugs.
- **Recon TASK 4 (EVM)**: Added `CODEBASE_SCALE: SMALL` detection. Codebases <1500 in-scope LOC with <5 contracts are flagged, activating reduced agent budgets downstream.
- **Confidence scoring**: Added SMALL_CODEBASE depth floor override (`depth_floor=8`, Phase 3b skip, Phase 3c ≤3 agents). Reduces total agent count by 8-12 for small codebases.
- **plamen-feedback command**: Added Step 6 — automatic git branch creation, staging, and commit message suggestion after applying pipeline improvements.

## [1.0.3] - 2026-03-19

### Added
- **Solana invariant fuzz campaign**: New `phase4b-invariant-fuzz.md` for Solana/Anchor — mirrors EVM v1.1.0 structure with protocol-derived invariants, finding-derived fuzz targets, lifecycle handlers, and 5 mandatory categories. Fills the EVM/Solana parity gap (was explicitly skipped in `phase4b-loop.md`)
- **Trident API reference**: New `TRIDENT_API_REFERENCE.md` (v0.12.0) — prevents method signature hallucination with correct CLI commands, types, and patterns
- **Lending/Liquidation injectable skill**: 247-line methodology covering health factor boundaries, interest accrual, liquidation mechanism safety, DoS vectors, bad debt socialization, collateral factor manipulation, asymmetric pause analysis
- **DEX/Slippage injectable skill**: 134-line methodology covering slippage parameters, deadline enforcement, return value handling, fee tier assumptions, router approval safety
- **Self-transfer accounting check**: Added to TOKEN_FLOW_TRACING in all 4 language trees — detects `sender == recipient` manipulating fees/rewards/snapshots
- **Timestamp unit confusion check**: Added to TEMPORAL_PARAMETER_STALENESS for Sui (`clock::timestamp_ms` vs seconds) and Aptos (`now_seconds` vs `now_microseconds`)
- **Denylist enforcement lag check**: Added to CROSS_CHAIN_TIMING for Sui and Aptos
- **Invariant quality self-check**: Tautological/sensitivity/testability filter before generating fuzz code
- **Scope selector**: Foundation/Integration/Temporal campaign scope based on protocol characteristics
- **Non-triviality guards**: Prevents false confidence from broken fuzz setups (0% success rate detection)
- **Platform dependencies guide**: New `docs/dependencies.md` with per-platform installation, troubleshooting, and Trident version compatibility matrix
- **Windows Developer Mode check**: `plamen.py` auto-detects and warns if Developer Mode is OFF (required for Solana symlinks)
- **OpenSSL auto-detection**: Fuzz templates inline-detect OpenSSL on Windows for Trident compilation
- **Cost estimation in `/plamen`**: Launch confirmation with codebase size, agent count, token estimate, API cost, and plan usage % with color-coded warnings

### Fixed
- **Trident v0.12 commands**: Replaced all `run-hfuzz`/`debug-hfuzz`/`HFUZZ_RUN_ARGS` references with v0.11+ commands (`trident fuzz run fuzz_0`). Trident v0.11+ uses TridentSVM — no honggfuzz/AFL required
- **Cross-platform Trident**: Documented and verified working on Windows (with Developer Mode + OpenSSL), macOS, and Linux
- **Recon probe**: No longer checks for `honggfuzz --version` — checks `trident --version` only

### Changed
- Solana skills: 19 → 20 (added TRIDENT_API_REFERENCE)
- Injectable skills: 5 → 7 (added LENDING_PROTOCOL_SECURITY, DEX_INTEGRATION_SECURITY)

## [1.0.2] - 2026-03-19

### Improved
- **EVM fuzzing**: Invariant fuzz and Medusa campaigns now derive invariants from `design_context.md` (protocol economics) and `findings_inventory.md` (bug targets), not just structural write-site analysis
- **No artificial caps**: Removed max 8/5 invariant limits and max 15 handler limit -- fuzz execution is zero token cost regardless of count
- **Lifecycle sequence handlers**: Mandatory multi-step handlers (create->repay->close) that construct realistic state random individual calls cannot reach
- **Realistic value bounds**: Handlers use protocol-actual decimals and parameter ranges from `constraint_variables.md`
- **Campaign config**: 256 runs x depth 25 (was 64x15), 5 mandatory invariant categories with coverage table in output
- **README restructured**: 865 lines -> 134 lines. Follows Ruff/Foundry landing page pattern
- **Documentation**: New `docs/` directory with 7 focused guides (setup, architecture, audit modes, MCP servers, usage, internals, repository structure)

## [1.0.1] - 2026-03-19

### Added
- **Rule 12**: THOROUGH MODE COMPLETENESS -- mandatory checklist of 13 non-negotiable Thorough steps with violation logging
- **Rule 13**: NO SPEED OPTIMIZATION IN THOROUGH MODE -- blocks weasel phrases that skip steps
- **Pre-Depth checkpoint**: Assertions for invariant fuzz and Medusa campaign completion
- **Post-Depth checkpoint**: Assertions for confidence scores, adaptive loop log, manifest, iteration 2 enforcement
- **Phase 4b.5 inline**: RAG Validation Sweep explicitly marked MANDATORY for Core/Thorough
- **Skeptic-Judge enforcement**: Positive statement that Thorough HIGH/CRIT must run skeptic

### Fixed
- Design Stress Testing now unconditional (1 reserved slot, not budget-conditional)
- AUDIT MODES table updated to match Rule 12 (DST: "1 reserved slot, UNCONDITIONAL")
- `violations.md` and `checkpoint_postdepth.md` registered as scratchpad artifacts
- Removed internal planning document (`RAG_OVERHAUL_STATUS.md`) from public repo

### Changed
- GitHub repo topics added: web3-security, smart-contract-audit, claude-code, solidity, solana, aptos, sui, ai-agent, security-audit, ethereum

## [1.0.0] - 2026-03-14

### Initial public release

Plamen is an autonomous Web3 security auditing agent for Claude Code. This is the first open-source release.

### Core Pipeline
- 8-phase audit pipeline: Recon → Instantiation → Breadth Analysis → Re-Scan → Inventory → Depth Loop → Chain Analysis → Verification → Report
- Two audit modes: **Core** (22-40 agents, HIGH/CRIT focus) and **Thorough** (32-90 agents, all severities)
- **Compare** mode for post-audit improvement against ground truth reports
- Adaptive depth loop with 4-axis confidence scoring and Devil's Advocate iteration
- Iterative chain analysis with enabler enumeration and postcondition-precondition matching
- Mandatory PoC execution with fuzz variants for Medium+ findings
- Tiered report generation (Opus for Critical+High, Sonnet for Medium, Sonnet for Low+Info)

### Language Support
- **EVM/Solidity** — 18 skills, Foundry/Hardhat build, Slither integration, fork testing
- **Solana/Anchor** — 19 skills, LiteSVM tests, Trident fuzzing, Helius on-chain data
- **Aptos Move** — 21 skills, Move test framework, resource/capability analysis
- **Sui Move** — 21 skills, test_scenario framework, object ownership analysis

### Skills System
- 79 language-specific skills across 4 trees
- 5 injectable skills (Vault Accounting, Account Abstraction, NFT Protocol, Governance, Outcome Determinism)
- 5 niche agents (Event Completeness, Semantic Gap Investigator, Spec Compliance, Signature Verification, Semantic Consistency)
- Flag-triggered loading to prevent context dilution

### Scanner Templates
- Blind Spot Scanner A: Tokens & Parameters (+ msg.value loops, returnbomb, gas griefing)
- Blind Spot Scanner B: Guards, Visibility & Inheritance + Override Safety
- Blind Spot Scanner C: Role Lifecycle, Capability Exposure & Reachability
- Validation Sweep Agent with write-completeness checks
- Design Stress Testing Agent (Thorough mode, budget redirect)

### Verification Protocol
- Pre-PoC feasibility gates (Reachability + Math Bounds)
- Evidence source tracking with mandatory audit tables
- Mock rejection rule (CONTESTED, not REFUTED, on mock evidence)
- RAG confidence override (historical precedent protection)
- Chain hypothesis protection with full-sequence PoC requirements
- Bidirectional role analysis for semi-trusted actor findings

### MCP Server Integration
- unified-vuln-db: RAG vulnerability database with Solodit API, DeFiHackLabs, Immunefi
- slither-mcp: Slither static analyzer (Trail of Bits)
- farofino-mcp: Solidity analysis fallback
- foundry-suite: Anvil fork testing, Forge scripts, Heimdall bytecode analysis
- evm-chain-data: On-chain contract ABI/state queries
- helius: Solana on-chain data
- tavily-search: Web search for fork ancestry and documentation

### Python Wrapper (plamen.py)
- Terminal UI with Rich + InquirerPy
- Mode selection, target detection, docs/scope/network configuration
- Auto-detection of project type (Foundry, Hardhat, Anchor, Move)
- Dependency checking, Ctrl+C handling, terminal width adaptation
- CLI fast path for scripted usage

### Security Rules
- 16 rules (R1-R16) covering adversarial assumptions, combinatorial impact, bidirectional roles, cached parameters, worst-state severity, unsolicited tokens, exhaustive enablers, anti-normalization, cross-variable invariants, flash loan preconditions, oracle integrity
- Finding output format with step execution tracking and depth evidence tags
- Severity matrix (Impact x Likelihood) with downgrade modifiers
