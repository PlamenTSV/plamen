# Getting Started

> **⚠️ Do NOT paste this file or setup.md into Claude Code / Codex CLI.** Follow these instructions in your terminal. Pasting into an AI coding assistant causes autonomous command execution including the optional RAG build (~6GB RAM).
>
> Want your AI assistant to install for you instead? Paste [SETUP.md](../SETUP.md) (only), not this file.

> **Platform boundary:** this guide's install and audit commands apply to
> Windows and admitted Linux production hosts. Native macOS production install
> and E2E auditing are not yet supported because the governed package
> transaction and worker-containment layers fail closed on Darwin. Mac users
> can continue source development with the
> [macOS bootstrap](development/macos.md) and
> [machine-migration guide](development/machine-migration.md); remaining work
> is recorded in the [Plamen-v3 continuation goal](continuation/GOAL.md).

> Just installed Plamen? This page tells you exactly what to do next — what's required, what's optional, and how to run your first audit.

> **Note:** On Windows use `python`; on Linux use `python3.12`.

> **First thing to run:** `plamen doctor` — verifies the signed committed package, managed backend selections, private Python and Node runtimes, backend configuration, and authentication without paid/provider calls. The exact installed-package integrity pass checks hundreds of files and may take up to a minute. If `plamen` isn't found, see [README.md](../README.md); do not add or edit files inside `~/.plamen`. See [glossary.md](glossary.md) for terminology.

## What did install do?

`plamen install` (or `plamen setup`) set up:

| Component | What it is | Status after install |
|-----------|-----------|---------------------|
| **Committed package** | Publishes an authenticated, immutable runtime snapshot at `~/.plamen/`; the source checkout remains installation input only | Done |
| **Backend integration** | Creates a receipt-bound Claude projection from the committed package and transactionally copies/merges Codex integration files under `~/.codex/` | Done |
| **Config** | Merges backend settings and managed MCP configuration; audit subprocesses apply stricter phase-local isolation | Done |
| **Orchestrator rules** | Injected `~/.claude/CLAUDE.md` (Claude Code) or `~/.codex/AGENTS.md` (Codex CLI) — the orchestrator's top-level instructions | Done |
| **Core Python deps** | `rich`, `InquirerPy` (wrapper UI) | Done |
| **Managed JS runtime** | Exact Node.js 24.20.0/npm 11.19.0 plus Claude Code 2.1.252, Codex 0.152.0, and locked MCP payloads | Done |
| **Chain toolchains** | Foundry, Solana CLI, Anchor, Aptos, Sui, etc. | Only if you selected them |
| **RAG database** | Vulnerability knowledge base (PyTorch + embeddings) | **Not installed** — separate step |

## What do I actually need?

### Required for all audits

The installer materializes the managed components automatically. The host needs
only the acquisition/bootstrap prerequisites below; ambient `node`, `npm`,
`npx`, `claude`, and `codex` commands are neither required nor trusted.

- **CPython 3.12** (`python3.12`, or `python` on Windows when it resolves to 3.12)
- **Git**
- A complete reviewed Plamen source tree, kept outside `~/.plamen/`

### Required per chain (install only what you audit)

You do **not** need all chain tools. Install only the ones for your target:

| I'm auditing... | I need | Install command |
|-----------------|--------|-----------------|
| **EVM / Solidity** | Foundry (forge) | `plamen setup` → select EVM |
| **Solana / Anchor** | Solana CLI + Anchor | `plamen setup` → select Solana |
| **Aptos Move** | Aptos CLI | `plamen setup` → select Move |
| **Sui Move** | Sui CLI | `plamen setup` → select Move |
| **Soroban / Stellar** | Stellar CLI + Rust | `plamen setup` → select Soroban |
| **DAML / Canton** | DAML SDK (`daml` CLI) | install the DAML SDK; auto-detected on `.daml` sources |
| **L1 / Node Client** | Go or Rust + scip-go/rust-analyzer | `plamen setup` → select L1 |

> **Slither** (EVM static analysis) and **Medusa** (EVM stateful fuzzing) are recommended but optional. The pipeline works without them — it just has less static analysis coverage.

### Optional: RAG vulnerability database (~6GB RAM required)

RAG gives the pipeline historical vulnerability pattern matching — it searches a local database of 4k+ past audit findings (from Solodit, DeFiHackLabs, Immunefi bug bounties, and Immunefi audit competitions). The pipeline works without it (falls back to web search), but RAG improves finding quality.

> **Resource warning**: RAG build loads PyTorch + sentence-transformers + ChromaDB. Peak RAM: ~4-6GB. On machines with ≤8GB total RAM, close other applications first or skip this step entirely.

```bash
# Build the RAG database (~10-20 min, CPU + RAM intensive)
export SOLODIT_API_KEY=your_key_here    # free at solodit.cyfrin.io (recommended)
plamen rag
```

You can always build it later. Run the same command to rebuild after updates.

### Optional: API keys

These keys are optional. Global MCP configuration is used only for manual
adapter sessions; Plamen audit subprocesses use phase-local policy. Claude
headless can select `unified-vuln-db` only for RAG, while Claude PTY and Codex
use Web fallback. Replace the `YOUR_*` placeholders only for integrations you
actually enable:

> **`SOLODIT_API_KEY` is the exception — it does NOT go in mcp.json.** Add `SOLODIT_API_KEY` to `~/.claude/settings.json` → `"env"` section (or `~/.codex/config.toml` → `[env]` for Codex). This is the only place the key is reliably visible to both `plamen rag` and audit agent subprocesses. If you put it in mcp.json, `plamen rag` will silently fail to index Solodit (smaller/near-empty RAG DB) with no error. The remaining keys below go in mcp.json. Free key from [solodit.cyfrin.io](https://solodit.cyfrin.io).

| Key | What it does | Impact if missing | Get it |
|-----|-------------|-------------------|--------|
| `ETHERSCAN_API_KEY` | Fetches verified source code on-chain | No production source verification (EVM only) | [etherscan.io/apis](https://etherscan.io/apis) (free) |
| `TAVILY_API_KEY` | Web search fallback when RAG fails | Falls back to built-in web search | [tavily.com](https://tavily.com) (free tier) |
| `HELIUS_API_KEY` | Solana on-chain data | No Solana account inspection | [helius.dev](https://helius.dev) (free tier) |
| RPC URL | Ethereum fork testing | No fork-mode PoC verification (EVM only) | Alchemy, Infura, or `https://eth.llamarpc.com` |

**None of these are required.** The pipeline runs without any API keys — it just has less production verification and RAG coverage.

## Run your first audit

### Option A: Terminal wizard (recommended for first time)

```bash
plamen
```

The interactive wizard walks you through: mode selection → target project → docs → scope → cost estimate → launch. The V2 driver auto-detects your backend (Claude Code or Codex CLI) via `plamen_home()`, and auto-detects (and auto-corrects) the target ecosystem/language at startup — no halt-to-rerun if the detected language is off; the resolved ecosystem is shown on the startup banner.

### Option B: One-liner

```bash
plamen core /path/to/your/project
```

The terminal shows the launch summary and requires confirmation. In CI or another non-interactive shell, validate first with `plamen plan core /path/to/your/project --codex`, then add `--yes` to the audit command. Model fallback is disabled unless `--allow-model-fallback` is explicitly supplied.

### Option C: From inside your AI coding assistant

**Claude Code:**
```
/plamen-wizard          # Smart contract audit
/plamen-l1-wizard       # L1 infrastructure audit
```

**Codex CLI:**

After the standard governed install, the same slash commands are installed into
`~/.codex/commands/` (from `codex-adapter/commands/`), so they work the same way:
```
/plamen-wizard          # Smart contract audit
/plamen-l1-wizard       # L1 infrastructure audit
```
Or use the terminal wrapper directly (no slash command needed):
```
$plamen core /path/to/project
```

All paths invoke the same V2 deterministic driver. The backend difference is transparent — agent prompts, depth templates, and verification logic are identical. Claude routes are pinned to **Opus 5** (`claude-opus-5`), **Sonnet 5** (`claude-sonnet-5`), and `claude-haiku-4-5-20251001`; override only through the explicit `PLAMEN_*_MODEL` controls.

### How the driver runs workers (v2.1.0)

- **Backend-specific worker execution.** Claude worker pools use the dedicated
  PTY transport and infer completion from artifacts written to disk (including
  the `<!-- PLAMEN_STATUS: COMPLETE -->` marker), not a stdout/JSON envelope.
  Codex does not use that PTY transport; the driver invokes `codex exec`
  directly and retains the same artifact ownership and phase-gate contract.
- **Haltless resilience.** A finished audit is never thrown away at the finish line. The report-index, verify, inventory, and resume paths repair-then-degrade: any unfinished obligation is surfaced as a flagged Appendix-B item in `AUDIT_REPORT.md` rather than halting the run. Stale or corrupt checkpoints recover instead of stranding the audit, and rate-limit / usage-cap conditions auto-wait then resume.
- **Deterministic plumbing.** Report-index recovery, verify backfill, and finding dedup are mechanical Python steps (LLM out of the loop) for reliability.

## Where's my report?

When the audit finishes, the deliverable is written to the **root of the
audited project**:

```
<project>/AUDIT_REPORT.md
```

It contains an Executive Summary, a severity summary table, and a dedicated
section per finding — **Severity**, **Location** (`file:Lnnn`), **Description**
with the offending code, **Impact**, **PoC Result** (`[POC-PASS]` /
`[POC-FAIL]` / `[CODE-TRACE]`), and a **Recommendation** (a minimal fix diff for
PoC-confirmed findings) — followed by a Priority Remediation Order. Appendix A
lists excluded/duplicate findings; **Appendix B** surfaces any unfinished
obligation the haltless pipeline flagged for human triage. See
[`../rules/report-template.md`](../rules/report-template.md) for the exact
structure.

All intermediate artifacts (recon context, findings inventory, depth traces,
verification PoCs, the resume checkpoint) live in a per-audit workspace at
`<project>/.scratchpad/`. It is preserved for resume and discarded only on a
`--fresh` restart — you normally never need to open it. See [glossary.md](glossary.md)
for the `.scratchpad/` layout.

## What mode should I pick?

| Mode | When to use | Plan needed | Time (small codebase) | Time (large codebase) |
|------|-------------|-------------|-----------------------|-----------------------|
| **Light** | Quick scan, small codebases (<3k lines), Pro plan | Pro | ~15-30 min | ~1-2 hours |
| **Core** | Standard audit, most projects | Max | ~30-90 min | ~3-5 hours |
| **Thorough** | High-value audit, complex DeFi, want fuzzing | Max | ~1-3 hours | ~6-12 hours |

Small codebase = under ~3k lines of in-scope source. Large/complex codebases (multi-contract DeFi, L1 node clients) sit in the right-hand column — see `pipeline-phases-presentation.md` for per-phase budgets.

Start with **Light** if you're on a Pro plan or just trying it out. Use **Core** for real audits.

These tiers apply to both smart contract and L1 infrastructure audits. For node client / infrastructure codebases (Go/Rust), use `plamen l1 [light|core|thorough]` — same three tiers, same depth loop and verification pipeline, with L1-specific depth agents (consensus-invariant, network-surface) replacing token-flow.

## Verify everything works

Run `plamen setup` at any time to see your toolchain status. The box below is
**illustrative** — your real output will differ depending on what you have
installed, and it also includes a separate `Backend` row and an `MCP`
server-health row:

```
  ╭─────────────────────────────────────────────────────────╮
  │  Toolchain                                                │
  │                                                           │
  │    python  git                                        ok │
  │  Managed   Node 24.20.0/npm 11.19.0                  ok │
  │  Backend   Claude 2.1.252  Codex 0.152.0             ok │
  ├───────────────────────────────────────────────────────────┤
  │  EVM        ✓forge ✓anvil ✓cast ✓slither ○medusa      4/5 │
  │  Solana     ○solana ○anchor ○cargo ○trident ○scout    0/5 │
  │  Move       ○aptos ○sui ○ast-grep                     0/3 │
  │  Soroban    ○stellar ○scout ○cargo-fuzz               0/3 │
  │  L1 (Go)    ○go ○scip-go ○opengrep                    0/3 │
  │  L1 (Rust)  ○cargo ○rust-analyzer ○ast-grep ○cargo-fuzz 0/4│
  ├───────────────────────────────────────────────────────────┤
  │  RAG DB     vulnerability knowledge base       not built  │
  ├───────────────────────────────────────────────────────────┤
  │  MCP        static-analysis servers                   ... │
  ╰───────────────────────────────────────────────────────────╯
```

- **✓** = installed
- **○** = not installed (optional — install only what you need)
- The `EVM` / `Solana` / `Move` / `Soroban` / `L1 (Go)` / `L1 (Rust)` rows each
  cover one audited ecosystem — install only the toolchains for the ecosystems
  you audit (L1 Go/Rust is for node-client / infrastructure audits)
- Plamen installs exact managed Claude and Codex payloads; choose the backend
  you authenticate and use for an audit
- **RAG DB** = run `plamen rag` to build
- **MCP** = static-analysis server health probes (may show `...` while probing)

## Updating

Update the dedicated source checkout, review the change, and install from that
source directory:

```bash
cd /path/to/plamen-source
git pull --ff-only
python3.12 plamen.py install
```

Never run `git pull` inside `~/.plamen/`, globally update the managed npm
packages, or point a backend at the mutable source checkout. Publication is a
transaction: the new source closure must validate before it can replace the
signed committed package and its backend projections/configuration.

See [updating.md](updating.md) for details on what auto-updates and what doesn't.

## Troubleshooting

Production audits run on Windows and admitted Linux hosts. macOS arm64 and
x86_64 currently support the isolated source-development bootstrap only; see
[development/macos.md](development/macos.md). See
[dependencies.md](dependencies.md) for supported-host dependency details.

**Windows: "Microsoft Store python stub" warning.** On a fresh Windows install,
`plamen doctor` may warn that a Microsoft Store App Execution Alias stub for
`python.exe` / `python3.exe` sits in
`%LOCALAPPDATA%\Microsoft\WindowsApps\`. These are 0-byte stubs that open the
Store instead of running Python, and they sit at the front of `PATH`, so an LLM
agent that types `python`/`python3` mid-audit can keep popping the Store. This
warning is **expected** and does not affect Plamen's own subprocess calls
(which use the real interpreter directly). To silence it, turn the aliases off
under **Settings > Apps > Advanced app settings > App execution aliases**
(disable the App Installer `python` / `python3` entries), or install a real
Python from python.org / the system package manager and ensure it precedes
`WindowsApps` on `PATH`.
