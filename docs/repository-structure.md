# Repository Structure

```
~/.plamen/
├── CLAUDE.md                          # Orchestrator config — mode table, rules, file refs
├── plamen.py                          # Terminal wrapper (Rich + InquirerPy)
├── plamen / plamen.sh / plamen.bat    # Launcher scripts (plamen = extensionless, for PATH symlink installs)
├── VERSION                            # Semantic version (2.2.4)
│
├── commands/                          # Claude Code slash commands (4 files)
│   ├── plamen.md                      # /plamen — full SC audit workflow
│   ├── plamen-wizard.md               # /plamen-wizard — interactive setup + driver launch
│   ├── plamen-l1.md                   # /plamen-l1 — L1 infrastructure workflow
│   └── plamen-l1-wizard.md            # /plamen-l1-wizard — interactive L1 setup
│   # Codex slash commands live under codex-adapter/commands/ (same 4 names)
│
├── rules/                             # Shared rules (all languages)
│   ├── finding-output-format.md       # Finding template, Rules Applied, Depth Evidence Tags
│   ├── orchestrator-rules.md          # Orchestration modes, critical rules
│   ├── phase3b-rescan-prompt.md       # Breadth re-scan (Thorough)
│   ├── phase4-confidence-scoring.md   # 4-axis scoring, anti-dilution, convergence
│   ├── phase4c-chain-prompt.md        # Chain analysis — enabler enum + chain matching
│   ├── phase5-poc-execution.md        # Mandatory PoC execution protocol
│   ├── phase6-report-prompts.md       # Report pipeline — Index → Writers → Assembler
│   ├── report-template.md             # Report format, severity matrix, consolidation
│   ├── skill-index.md                 # Master skill registry (all trees)
│   ├── post-audit-improvement-protocol.md
│   ├── language-toolchain-registry.json  # Build/test/fuzz command registry per language
│   └── skill-registry.json            # Machine-readable skill trigger/injection registry
│
├── agents/                            # Agent definitions (language-agnostic)
│   ├── depth-token-flow.md
│   ├── depth-state-trace.md
│   ├── depth-edge-case.md
│   ├── depth-external.md
│   ├── depth-consensus-invariant.md   # L1 mode: consensus safety/liveness
│   ├── depth-network-surface.md       # L1 mode: p2p/RPC/mempool attack surface
│   ├── security-analyzer.md
│   └── security-verifier.md
│
├── prompts/                           # Language-specific prompts
│   ├── evm/                           # 13 files (includes invariant-fuzz)
│   ├── solana/                        # 13 files (includes invariant-fuzz)
│   ├── aptos/                         # 12 files
│   ├── sui/                           # 12 files
│   ├── soroban/                       # 13 files (Soroban/Stellar)
│   ├── daml/                          # 5 files (DAML/Canton)
│   ├── l1/                            # L1 infrastructure prompts
│   ├── go/                            # Go depth-template supplement (L1 mode)
│   ├── rust/                          # Rust depth-template supplement (L1 mode)
│   └── shared/                        # Shared prompt components
│       └── v2/                        # V2-specific shared prompts
│
├── agents/skills/
│   ├── evm/                           # 18 EVM skill templates
│   ├── solana/                        # 20 Solana skill templates
│   ├── aptos/                         # 22 Aptos skill templates (21 + core directives)
│   ├── sui/                           # 22 Sui skill templates (21 + core directives)
│   ├── soroban/                       # 19 Soroban skill templates
│   ├── daml/                          # 12 DAML/Canton skill templates
│   ├── injectable/                    # 9 protocol-type-specific skills
│   │   └── l1/                        # 24 L1 infrastructure skills (+ _opengrep-rules/ local rule pack)
│   └── niche/                         # 9 flag-triggered niche agents
│
├── scripts/                           # V2 driver and utilities
│   ├── plamen_driver.py               # Phase scheduling, PTY worker-pool orchestration, disk-derived completion, ecosystem auto-detect, haltless repair-then-degrade, retry/recovery (+ _bake_go_scip for L1 Go)
│   ├── plamen_types.py                # Canonical definitions (evidence tags, severities, plamen_home)
│   ├── plamen_parsers.py              # LLM output parsing
│   ├── plamen_validators.py           # Artifact quality gates
│   ├── plamen_prompt.py               # Phase prompt building
│   ├── plamen_mechanical.py           # Deterministic report assembly / mechanical phases (report_index recovery, verify backfill/queue manifests, report_dedup builder)
│   ├── plamen_display.py              # Rich terminal UI for driver
│   ├── plamen_contracts.py            # Worker artifact / marker-envelope contracts
│   ├── plamen_markdown.py             # Markdown AST helpers (parser-side)
│   ├── pty_exec.py                    # Backend PTY session — drives each worker through a pseudo-terminal (POSIX openpty + Popen / SIGCHLD reset on macOS+Linux, Win winpty)
│   ├── preflight_pty_transports.py    # PTY transport probe + cache (schema v3)
│   ├── mechanical_verify.py           # Phase 5 mechanical verification helpers
│   ├── chain_prep.py                  # Chain-analysis pre-pass (candidate pair extraction)
│   ├── report_index_machinery.py      # Report-index ID assignment / coverage
│   ├── codex_adapter.py               # Codex CLI backend adapter (BETA) — per-job depth fan-out, usage-cap auto-wait
│   ├── recon_prepass.py               # Pre-recon static analysis (deterministic recon prepass)
│   └── enumeration_gate.py            # Mechanical enumeration-completeness gate
│
├── codex-adapter/                     # Codex CLI backend config source (BETA, cost-saving alternative backend)
│   ├── AGENTS.md                      # Codex orchestrator config (injected into ~/.codex/AGENTS.md)
│   ├── README.md                      # Codex adapter notes
│   ├── config.toml                    # Codex model/profile config template (shipped source, distinct from generated ~/.codex/config.toml)
│   ├── mcp_permissions.toml           # Per-server MCP permission gates
│   ├── agents/                        # TOML role definitions (spawned via Codex spawn_agent)
│   ├── commands/                      # Codex slash commands (4 files, mirror commands/)
│   └── skills/                        # Codex skill overrides
│
├── custom-mcp/                        # MCP servers
│   ├── unified-vuln-db/               # RAG database (code only, data/ gitignored)
│   ├── solana-fender/                 # Solana static analysis
│   ├── farofino-mcp/                  # [submodule] Aderyn integration
│   └── slither-mcp/                   # [submodule] Trail of Bits Slither
│
├── opengrep-rules/                    # Opengrep rule-pack submodules (cross-ecosystem static analysis)
│   ├── aptos-move-rules/              # [submodule] Aptos Move semgrep rules
│   ├── decurity-rules/                # [submodule] Decurity smart-contract rules
│   └── opengrep-rules/                # [submodule] Opengrep OSS rule pack
│
├── docs/                              # Documentation
│   ├── l1-mode/                       # L1 mode design docs and severity matrix
│   └── design/                        # Internal design/remediation planning docs
├── mcp-packages/                      # Pinned npm MCP server packages
├── mcp.json.example                   # MCP server config template
├── settings.json.example              # Permissions config template
├── requirements.txt                   # Runtime deps (UI, PTY, typed schemas, Markdown/JSON validation)
├── requirements-dev.txt               # Test-only pinned deps (pytest, pytest-xdist) — layered on requirements.txt, not read by the installer/runtime
├── pyproject.toml                     # [tool.pytest.ini_options]: unit/integration/slow markers, auto-applied by filename
├── .github/
│   └── workflows/
│       └── tests.yml                  # CI: full pytest suite on push/PR, fast parallel lane + serial integration lane, 3-OS matrix
├── .gitmodules                        # Submodule refs
└── .gitignore
```

---

**See also**: [architecture.md](architecture.md) · [internals.md](internals.md) · [updating.md](updating.md) · [glossary.md](glossary.md) · [docs index](README.md)
