# Plamen

Autonomous smart contract security auditor for [Claude Code](https://docs.anthropic.com/en/docs/claude-code).

Orchestrates 15-95 AI agents across 8 phases to produce audit reports with verified PoC exploits. Supports **EVM/Solidity**, **Solana/Anchor**, **Aptos Move**, and **Sui Move**.

---

## Prerequisites

[Claude Code CLI](https://docs.anthropic.com/en/docs/claude-code), [Python 3.11+](https://python.org), [Node.js 18+](https://nodejs.org), [Git](https://git-scm.com)

> The install step below checks for these and tells you what's missing. Per-language tools (Foundry, Solana CLI, etc.) are installed automatically via `plamen setup`.

---

## Install

```bash
git clone https://github.com/gultekinmakif/plamen.git ~/.claude
cd ~/.claude && git submodule update --init --recursive
```

Then pick **one** of these setup paths:

### Option A: Let Claude set it up (recommended)

Open Claude Code and run:

```
> /plamen setup
```

Or paste the contents of [`SETUP.md`](SETUP.md) into Claude Code. It installs all dependencies, configures MCP servers, and builds the RAG database for you automatically.

### Option B: Manual

<details>
<summary>Click to expand manual setup commands (~5-10 min)</summary>

> `plamen setup` does all of this automatically. These commands are for reference or if you prefer manual control.

```bash
# 1. Python deps (~2GB download — PyTorch for embeddings)
pip install -r requirements.txt
pip install -r custom-mcp/unified-vuln-db/requirements.txt
pip install -r custom-mcp/solodit-scraper/requirements.txt
pip install -r custom-mcp/defihacklabs-rag/requirements.txt
pip install -e custom-mcp/solana-fender
pip install -r custom-mcp/farofino-mcp/requirements.txt
pip install -e custom-mcp/slither-mcp              # EVM only (needs Python 3.11+)

# 2. Configure MCP servers
cp mcp.json.example mcp.json                       # edit with your API keys
cp settings.json.example settings.json
# Get free keys: solodit.cyfrin.io, etherscan.io/apis, tavily.com

# 3. Build RAG database (~5 min)
export SOLODIT_API_KEY=your_key_here                # free at solodit.cyfrin.io
cd custom-mcp/unified-vuln-db
python -m unified_vuln.indexer index -s solodit --max-pages 10
python -m unified_vuln.indexer index -s defihacklabs
python -m unified_vuln.indexer index -s immunefi
cd ../..

# 4. Chain tools (install what you need)
curl -L https://foundry.paradigm.xyz | bash && foundryup          # EVM
pip install slither-analyzer                                       # EVM static analysis
# See docs/setup.md for Solana, Aptos, Sui, Medusa, Trident
```

> **Windows + Solana**: Enable Developer Mode (Settings > System > For Developers) and install OpenSSL (`winget install ShiningLight.OpenSSL.Dev`) before building. See [docs/dependencies.md](docs/dependencies.md).

See [docs/setup.md](docs/setup.md) for the full guide with all per-language prerequisites.

</details>

### Run your first audit

```bash
plamen                    # terminal wrapper with interactive wizard
```

Or inside Claude Code: `/plamen`

---

## Audit Modes

| Mode | Plan | Agents | Key Features |
|------|------|--------|-------------|
| **Light** | Pro | ~15-18 | Fast scan, all Sonnet, no fuzzing |
| **Core** | Max | ~25-45 | Full depth, PoC verification for Medium+ |
| **Thorough** | Max | ~35-95 | Iterative depth, invariant fuzzing, Medusa, skeptic-judge |

See [docs/audit-modes.md](docs/audit-modes.md) for the full comparison.

---

## How to Run

**Terminal wrapper** (recommended — includes setup, cost estimation):

```bash
plamen                                              # interactive wizard
plamen core /path/to/project                        # skip wizard
plamen thorough /path/to/project --proven-only      # strict evidence mode
plamen setup                                        # install tools only
```

**Inside Claude Code**:

```
> /plamen core
> /plamen thorough docs: whitepaper.pdf scope: scope.txt
```

See [docs/usage.md](docs/usage.md) for PATH setup and all CLI options.

---

## Feedback Loop

When Plamen misses a finding, run the backward reflection pipeline to auto-generate targeted improvements:

```
> /plamen-feedback reentrancy in withdraw() — balance updated after external call lang:evm
```

The pipeline walks backward from report → recon, asking each layer "would I have caught this?" and proposes the minimal diff needed. Changes require your approval before any files are modified.

Shortcuts: `/plamen-feedback lang:evm <description>`, `/plamen-feedback lang:solana <description>`

---

## Supported Chains

| Language | Build Tool | Static Analysis | Fuzzing |
|----------|-----------|----------------|---------|
| **EVM/Solidity** | Foundry, Hardhat | Slither, Aderyn | Foundry invariant, Medusa |
| **Solana/Anchor** | Anchor, cargo-build-sbf | Fender | Trident, proptest |
| **Aptos Move** | aptos CLI | Move Prover | Parameterized tests |
| **Sui Move** | sui CLI | -- | Parameterized tests |

Language detection is automatic based on config files.

---

## Documentation

| Topic | Link |
|-------|------|
| Full setup guide | [docs/setup.md](docs/setup.md) |
| Platform dependencies | [docs/dependencies.md](docs/dependencies.md) |
| Audit mode comparison | [docs/audit-modes.md](docs/audit-modes.md) |
| Pipeline architecture | [docs/architecture.md](docs/architecture.md) |
| MCP servers & API keys | [docs/mcp-servers.md](docs/mcp-servers.md) |
| Usage & CLI options | [docs/usage.md](docs/usage.md) |
| Skills, rules & internals | [docs/internals.md](docs/internals.md) |
| Repository structure | [docs/repository-structure.md](docs/repository-structure.md) |
| Automated setup (Claude) | [SETUP.md](SETUP.md) |

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Skills are the most impactful contribution — teach methodology (how to look), not patterns (what to find).

## License

[MIT](LICENSE)

## Acknowledgments

- [Trail of Bits](https://github.com/trailofbits) — Slither MCP server
- [Farofino](https://github.com/italoag/farofino-mcp) — Aderyn integration
- [SunWeb3Sec](https://github.com/SunWeb3Sec/DeFiHackLabs) — DeFiHackLabs exploit corpus
- [Solodit](https://solodit.xyz) — Audit finding database
- [Anthropic](https://anthropic.com) — Claude Code runtime
