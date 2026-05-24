# Plamen (v2.0.2)

Autonomous Web3 security auditor for [Claude Code](https://docs.anthropic.com/en/docs/claude-code) and [OpenAI Codex CLI](https://github.com/openai/codex).

Orchestrates 18-100 AI agents across 8 phases to produce audit reports with verified PoC exploits — for **smart contracts** and **L1 node-client infrastructure**.

Supports **EVM/Solidity**, **Solana/Anchor**, **Aptos Move**, **Sui Move**, **Soroban/Stellar**, and **L1 Go/Rust node clients**.

---

## Prerequisites

[Claude Code CLI](https://docs.anthropic.com/en/docs/claude-code) or [OpenAI Codex CLI](https://github.com/openai/codex), [Python 3.11-3.12](https://python.org) + pip, [Node.js 18+](https://nodejs.org), [Git](https://git-scm.com)

> **Backend CLIs.** Install at least one. If you only have time to install
> one, pick **Claude Code** — it has the broadest MCP support (Slither,
> ChromaDB, Solodit). Codex is a strong alternative when you'd rather use
> OpenAI models, but pure-LLM phases fall back to WebSearch where MCPs aren't
> available. You can install both side-by-side; the audit wizard lets you
> pick per-run.
>
> - **Claude Code**:
>   >   npm install -g @anthropic-ai/claude-code
>   > - **OpenAI Codex CLI** — install **without `sudo`** using a user-local npm prefix to avoid `EACCES` on Homebrew/system Node installs:
>
>   >   mkdir -p ~/.npm-global && npm config set prefix ~/.npm-global
>   echo 'export PATH="$HOME/.npm-global/bin:$PATH"' >> ~/.zshrc   # or ~/.bashrc
>   npm install -g @openai/codex
>   >
>   Codex doesn't yet support every MCP server — pure-LLM phases use a WebSearch fallback. See [docs/mcp-servers.md](docs/mcp-servers.md).
>
> **macOS**: Also run `xcode-select --install` (needed for C++ dependency compilation).
>
> **Windows**: Enable Developer Mode before installing (required for symlinks). Settings > System > For Developers > toggle ON. Or in admin PowerShell: `reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock /v AllowDevelopmentWithoutDevLicense /t REG_DWORD /d 1 /f`
>
> Per-language tools (Foundry, Solana CLI, etc.) are installed automatically via `plamen setup`.
>
> **PEP 668 / externally-managed Python**: On Homebrew Python and Ubuntu 23.04+, system `pip` refuses to write into the system site-packages. `plamen install` detects this and, by default, creates a local `.plamen-venv` for Plamen dependencies. To force installation into the system Python, set `PLAMEN_ALLOW_SYSTEM_PIP=1`, which enables pip's `--break-system-packages` behavior.

---

## Install

### Option A: Let your AI assistant set it up

Open Claude Code or Codex CLI in any project directory and paste the contents
of [`SETUP.md`](SETUP.md). It is the only Plamen doc designed for AI-assistant
consumption — it has step-by-step error handling, expected-output anchors,
and stops the assistant from running the heavy RAG build or the toolchain
wizard from a non-TTY context. The assistant handles cloning, the
non-interactive install (`plamen install`), and `plamen install --codex` if
you have Codex.

> Do **not** paste [`docs/setup.md`](docs/setup.md) or
> [`docs/getting-started.md`](docs/getting-started.md) into the AI — those
> are long-form manuals for humans and contain the RAG build inline.

After paste-setup, run `plamen setup` from a real terminal yourself to install
chain toolchains (Foundry, Solana CLI, Anchor, etc.) and `plamen rag` to
build the optional vulnerability DB (~6GB RAM).

### Option B: Terminal

**Linux / macOS:**
git clone --recurse-submodules https://github.com/PlamenTSV/plamen.git ~/.plamen
cd ~/.plamen && python3 plamen.py install
python3 plamen.py install --codex    # optional: add Codex CLI backend

**Windows (PowerShell):**
git clone --recurse-submodules https://github.com/PlamenTSV/plamen.git $HOME\.plamen
cd $HOME\.plamen; python plamen.py install
python plamen.py install --codex     # optional: add Codex CLI backend

> **Use `git clone --recurse-submodules`, not "Download ZIP"**. The repo ships
> `custom-mcp/slither-mcp/` and `custom-mcp/farofino-mcp/` as git submodules; ZIP
> downloads silently omit them. If you already cloned without
> `--recurse-submodules`, run `git submodule update --init --recursive` from
> inside `~/.plamen/` before `plamen install`.
>
> **`install` vs `setup`**: `plamen install` is non-interactive (symlinks +
> config + Python deps + dangling-hook self-heal) and is safe in any context
> — Claude Code Bash, Codex shell, CI, headless servers. `plamen setup` runs
> the install then drops into an interactive toolchain wizard (Foundry,
> Solana CLI, etc.) — run it from a real terminal. In a non-TTY context,
> `plamen setup` exits cleanly after the install rather than crashing on the
> picker.
>
> **Before building the RAG database**: add `SOLODIT_API_KEY` to `~/.claude/settings.json` → `"env"` section (or `~/.codex/config.toml` → `[env]` for Codex). Free key from [solodit.cyfrin.io](https://solodit.cyfrin.io). This is the only place the key is reliably visible to both `plamen rag` and audit agent subprocesses. A terminal `export` is not sufficient — Claude Code and Codex CLI spawn non-interactive subshells that don't source `.bashrc`/`.zshrc`.
>
> Python dependencies are installed automatically on first run. On macOS/Linux use `python3`, on Windows use `python`.

After install, add to PATH so you can run `plamen` from anywhere:

**Linux (bash):**
echo 'export PATH="$HOME/.plamen:$PATH"' >> ~/.bashrc && source ~/.bashrc

**macOS (zsh):**
echo 'export PATH="$HOME/.plamen:$PATH"' >> ~/.zshrc && source ~/.zshrc

**Windows (PowerShell, one-time):**
[System.Environment]::SetEnvironmentVariable("Path", "$env:USERPROFILE\.plamen;" + [System.Environment]::GetEnvironmentVariable("Path", "User"), "User")

Then use `plamen` from anywhere:
plamen                              # interactive audit wizard
plamen doctor                       # verify install (no audit run, no API calls)
plamen setup                        # toolchain wizard + optional RAG build
plamen migrate                      # upgrade a v1.x install layout
plamen rag                          # rebuild RAG database only
plamen uninstall                    # remove Plamen symlinks

> **Important**: Always use `plamen` (not `python3 plamen.py`) after PATH is set. The `python3 plamen.py` form only works from inside `~/.plamen/`.

The installer (`plamen install`):
- Creates symlinks from `~/.plamen` into `~/.claude/` so Claude Code discovers Plamen's agents, rules, prompts, and commands
- Merges Plamen's permissions into your existing `~/.claude/settings.json` (additive only — won't remove your entries)
- Merges MCP server definitions into `~/.claude/mcp.json` (won't overwrite your existing servers)
- Injects Plamen instructions into `~/.claude/CLAUDE.md` between `<!-- PLAMEN:START/END -->` markers (preserves your content)
- Installs Python dependencies in a local `.plamen-venv` when needed on externally managed Python installs; use `PLAMEN_ALLOW_SYSTEM_PIP=1` to opt into system-level pip installs with `--break-system-packages`
- Installs Python dependencies (RAG database is built separately via `plamen rag`)

For Codex CLI support, also run `plamen install --codex`. This sets up `~/.codex/plamen/` (symlinked from `~/.plamen/`) with:
- Codex orchestrator config in `~/.codex/AGENTS.md` (equivalent of `CLAUDE.md`), generated from `codex-adapter/AGENTS.md`
- MCP/tool config in `~/.codex/config.toml` (equivalent of `settings.json` + `mcp.json`), generated from `codex-adapter/config.toml`
- Codex-specific slash commands in `~/.codex/commands/`, generated from `codex-adapter/commands/`

Your existing Claude Code and Codex CLI configuration is preserved.

<details>
<summary>How symlinks work</summary>

The Plamen repo stays at `~/.plamen`. The installer creates symlinks (shortcuts) pointing back to `~/.plamen/`:

- **Claude Code** (`plamen install`): symlinks into `~/.claude/` — agents, rules, skills, prompts, commands
- **Codex CLI** (`plamen install --codex`): symlinks `~/.codex/plamen/` → `~/.plamen/` (shared methodology), and copies `codex-adapter/{AGENTS.md,config.toml,agents/,skills/,commands/}` into `~/.codex/`

When the AI runtime reads `~/.claude/agents/depth-edge-case.md` (or `~/.codex/plamen/agents/depth-edge-case.md`), the OS transparently reads `~/.plamen/agents/depth-edge-case.md`. This means:
- `git pull` in `~/.plamen` updates symlinked files (agents, rules, skills, prompts) automatically for both backends
- **You still need `plamen install` (and `plamen install --codex`) after pull** — `CLAUDE.md`/`AGENTS.md`, `settings.json`/`config.toml`, and `mcp.json` are injected/merged copies, not symlinks. Without re-install, the orchestrator follows stale rules. See [docs/updating.md](docs/updating.md).
- Your own files in `~/.claude/` or `~/.codex/` (custom agents, commands) are untouched
- Deleting `~/.plamen` would break the symlinks for both backends — don't delete it while Plamen is installed

| Platform | How links are created | Requirements |
|----------|----------------------|-------------|
| **Linux / macOS** | Standard symlinks (`os.symlink`) | None |
| **Windows (directories)** | Junctions (`mklink /J`) | None |
| **Windows (files)** | Symlinks (`os.symlink`) | Developer Mode enabled |

</details>

> **Migrating from v1.0.x** (installed directly in `~/.claude`): Close Claude Code (and Codex CLI if running) first, then run:
>
> > cd ~/.plamen 2>/dev/null || cd ~/.claude    # cd into whichever exists
> python3 plamen.py migrate                    # or `python plamen.py migrate` on Windows
> >
> `plamen migrate` strips any dangling Plamen hook references from
> `~/.claude/settings.json` (which would otherwise block PreToolUse Bash
> and lock you out of shell commands in Claude Code), moves the repo to
> `~/.plamen`, runs the non-interactive install, and verifies the
> `CLAUDE.md` marker block. If you prefer the manual path:
>
> Linux/macOS: `mv ~/.claude ~/.plamen && cd ~/.plamen && python3 plamen.py install`
>
> Windows (PowerShell): `Rename-Item $HOME\.claude $HOME\.plamen; cd $HOME\.plamen; python plamen.py install`
>
> Either route moves the repo to `~/.plamen` and recreates `~/.claude` with symlinks + merged config. Claude Code will not work between the move and install — run them together (or just use `plamen migrate`). For Codex support, follow up with `plamen install --codex`.

### Option C: Manual dependency install

<details>
<summary>Click to expand (~5-10 min)</summary>

> Option B handles this automatically. These commands are for reference only.

cd ~/.plamen

# 1. Python deps (~2GB download — PyTorch for embeddings)
# Recommended on PEP 668 systems: create and activate a local virtualenv first.
python3 -m venv .plamen-venv
source .plamen-venv/bin/activate                    # Windows PowerShell: .\.plamen-venv\Scripts\Activate.ps1
pip install -r requirements.txt
pip install -r custom-mcp/unified-vuln-db/requirements.txt
pip install -e custom-mcp/solana-fender
pip install -r custom-mcp/farofino-mcp/requirements.txt
pip install -e custom-mcp/slither-mcp              # EVM only (needs Python 3.11+)

# To force system Python on externally managed installs instead:
# PLAMEN_ALLOW_SYSTEM_PIP=1 pip install --break-system-packages -r requirements.txt

# 2. Build RAG database (~5 min)
# IMPORTANT: a `export SOLODIT_API_KEY=...` here works for this terminal only.
# For `plamen rag` and audit agents to see it later, put the key in
# ~/.claude/settings.json -> "env" (Claude Code) or ~/.codex/config.toml -> [env]
# (Codex CLI). See the callout above. Below uses an inline export so this manual
# loop completes in one shell:
export SOLODIT_API_KEY=your_key_here                # free at solodit.cyfrin.io
cd custom-mcp/unified-vuln-db
python3 -m unified_vuln.indexer index -s solodit --max-pages 10
python3 -m unified_vuln.indexer index -s defihacklabs
python3 -m unified_vuln.indexer index -s immunefi
python3 -m unified_vuln.indexer index -s immunefi-competitions
cd ../..
# Note: on Windows use 'python' instead of 'python3'

# 3. Chain tools (install what you need)
curl -L https://foundry.paradigm.xyz | bash && foundryup          # EVM
pip install slither-analyzer                                       # EVM static analysis
# See docs/setup.md for Solana, Aptos, Sui, Medusa, Trident

# 4. Codex backend (optional — after steps 1-3)
python3 plamen.py install --codex
# This generates ~/.codex/plamen/ with AGENTS.md, config.toml, and commands/
# from the Claude-side manifests. No additional deps needed.

> **Windows + Solana**: Enable Developer Mode (Settings > System > For Developers) and install OpenSSL (`winget install ShiningLight.OpenSSL.Dev`) before building. See [docs/dependencies.md](docs/dependencies.md).

See [docs/setup.md](docs/setup.md) for the full guide with all per-language prerequisites.

</details>

### Updating

cd ~/.plamen && git pull && plamen install
plamen install --codex    # if using Codex backend

That's it. `plamen install` is idempotent — it re-links symlinks, re-injects the updated `CLAUDE.md`, and merges any new `settings.json`/`mcp.json` entries. Adding `--codex` does the same for `AGENTS.md` and `config.toml`. Neither wipes your RAG database, re-installs toolchains, or overwrites your API keys.

> **Why `plamen install` after pull?** Most files auto-update via symlinks, but injected/merged files (`CLAUDE.md`/`AGENTS.md`, `settings.json`/`config.toml`, `mcp.json`) are copies, not symlinks. Without re-install, the orchestrator follows stale rules while everything else is updated. `plamen` will warn you if it detects a version mismatch.

See [docs/updating.md](docs/updating.md) for details on what updates automatically and what doesn't.

### Run your first audit

plamen                    # terminal wrapper with interactive wizard

Or inside Claude Code: `/plamen` · Inside Codex CLI: `$plamen core /path/to/project`

---

## Audit Modes

| Mode | Plan | Agents | Indicative Cost | Key Features |
|------|------|--------|-----------------|-------------|
| **Light** | Pro | ~18-22 | **~$1–5** / ~10-25 min | Fast scan, all Sonnet, no fuzzing |
| **Core** | Max | ~30-50 | **~$10–30** / ~30-90 min | Full depth, PoC verification for Medium+ |
| **Thorough** | Max | ~40-100 | **~$30–100+** / ~1-4 hr | Iterative depth, invariant fuzzing, Medusa, skeptic-judge |

> Cost / runtime are rough indicators for a ~5k-line codebase on a Claude
> subscription. Larger codebases scale roughly linearly. The wizard runs
> `plamen --estimate` before each audit to show a per-project number based
> on lines, scope, and target plan — use that for budgeting. API-key users
> (pay-as-you-go) see costs ~2–3× higher than subscription users.

See [docs/audit-modes.md](docs/audit-modes.md) for the full comparison.

---

## L1 Infrastructure Audits

Plamen also audits **L1 node clients and blockchain infrastructure** — consensus engines, p2p networking, mempool logic, RPC surfaces, and validator lifecycle code in Go and Rust.

plamen l1 core /path/to/node-client

Or inside Claude Code: `/plamen l1 core` · Inside Codex CLI: `$plamen l1 core /path/to/node-client`

L1 mode adds:
- **22+ injectable skills** covering consensus safety, fork choice, p2p DoS/eclipse, mempool asymmetric DoS, BLS aggregation, light client proofs, state sync/pruning, execution client hardening, validator lifecycle, and more
- **2 new depth agents**: `depth-consensus-invariant` and `depth-network-surface`
- **Phase 0.5 "Bake"**: Batch-indexes repos with scip-go / rust-analyzer SCIP before depth agents run
- **L1-specific severity matrix** aligned with Immunefi v2.3 classification
- **Go and Rust** language support with concurrency safety and unsafe-block auditing

See [docs/l1-mode/design.md](docs/l1-mode/design.md) for the full L1 architecture.

---

## How to Run

**Terminal wrapper** (recommended — includes setup, cost estimation):

plamen                                              # interactive wizard
plamen core /path/to/project                        # skip wizard
plamen thorough /path/to/project --proven-only      # strict evidence mode
plamen setup                                        # install tools only

**Inside Claude Code**:

> /plamen core
> /plamen thorough docs: whitepaper.pdf scope: scope.txt

**Inside Codex CLI**:

> $plamen core
> $plamen l1 thorough /path/to/node-client

See [docs/usage.md](docs/usage.md) for PATH setup and all CLI options.

---

## Resumable Pipeline (V2)

The V2 pipeline (`plamen-wizard`) runs a Python driver that executes one `claude -p` (or `codex exec`) subprocess per phase. If usage runs out or the process crashes, re-run the same command — it auto-resumes from the last successful checkpoint.

# Launch via wizard (interactive)
plamen                              # terminal wrapper starts wizard
/plamen-wizard                      # inside Claude Code
$plamen-wizard                      # inside Codex CLI

# Resume a crashed/interrupted audit
python3 ~/.plamen/scripts/plamen_driver.py /path/to/project/.scratchpad/config.json

The driver handles: phase scheduling, artifact gating, rate-limit pauses, retry-with-degradation, and subprocess isolation via the `plamen_home()` abstraction (resolves to `~/.claude/` or `~/.codex/plamen/` based on the configured backend). The LLM handles: agent orchestration, finding analysis, PoC execution, and report generation.

---

## Codex CLI Backend

Plamen supports [OpenAI Codex CLI](https://github.com/openai/codex) as an alternative backend. The V2 driver translates tool calls (Write to `apply_patch`, Bash to `shell`), rewrites paths (`~/.claude/` to `~/.codex/plamen/`), and adapts sandbox constraints.

# Install Codex backend (after standard install)
plamen install --codex

# Run via Codex
$plamen core /path/to/project       # inside Codex CLI

Codex shares methodology via `~/.codex/plamen/` (symlinked to `~/.plamen/`). Config files are copied to `~/.codex/`:

| Claude Code | Codex CLI | Purpose |
|-------------|-----------|---------|
| `~/.claude/CLAUDE.md` | `~/.codex/AGENTS.md` | Orchestrator rules |
| `~/.claude/settings.json` | `~/.codex/config.toml` | Permissions, env vars |
| `~/.claude/mcp.json` | N/A (Codex uses tool translation) | MCP server definitions |
| `~/.claude/commands/` | `~/.codex/plamen/commands/` | Slash commands |

---

## Supported Chains

| Language | Build Tool | Static Analysis | Fuzzing |
|----------|-----------|----------------|---------|
| **EVM/Solidity** | Foundry, Hardhat | Slither, Aderyn | Foundry invariant, Medusa |
| **Solana/Anchor** | Anchor, cargo-build-sbf | Fender | Trident, proptest |
| **Aptos Move** | aptos CLI | Move Prover | Parameterized tests |
| **Sui Move** | sui CLI | -- | Parameterized tests |
| **Soroban/Stellar** | Stellar CLI | -- | proptest, cargo-fuzz |
| **L1 Go/Rust** | go build, cargo | scip-go, rust-analyzer, Opengrep | proptest, go test -fuzz |

Language detection is automatic based on config files.

---

## Documentation

| Topic | Link |
|-------|------|
| Glossary of terms | [docs/glossary.md](docs/glossary.md) |
| Full setup guide | [docs/setup.md](docs/setup.md) |
| Updating after git pull | [docs/updating.md](docs/updating.md) |
| Platform dependencies | [docs/dependencies.md](docs/dependencies.md) |
| Audit mode comparison | [docs/audit-modes.md](docs/audit-modes.md) |
| Pipeline architecture | [docs/architecture.md](docs/architecture.md) |
| MCP servers & API keys | [docs/mcp-servers.md](docs/mcp-servers.md) |
| Usage & CLI options | [docs/usage.md](docs/usage.md) |
| Skills, rules & internals | [docs/internals.md](docs/internals.md) |
| Repository structure | [docs/repository-structure.md](docs/repository-structure.md) |
| L1 mode design | [docs/l1-mode/design.md](docs/l1-mode/design.md) |
| L1 severity matrix | [docs/l1-mode/severity-matrix.md](docs/l1-mode/severity-matrix.md) |
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
- [Immunefi](https://immunefi.com) — Bug bounty & audit competition findings
- [Anthropic](https://anthropic.com) — Claude Code runtime
- [OpenAI](https://openai.com) — Codex CLI runtime