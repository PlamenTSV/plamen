# Plamen (v2.2.4)

Autonomous Web3 security auditor for [Claude Code](https://docs.anthropic.com/en/docs/claude-code) and [OpenAI Codex CLI](https://github.com/openai/codex).

Orchestrates 18-100 AI agents across 40+ phases to produce audit reports with verified PoC exploits — for **smart contracts** and **L1 node-client infrastructure**.

Supports **EVM/Solidity**, **Solana/Anchor**, **Aptos Move**, **Sui Move**, **Soroban/Stellar**, **DAML/Canton**, and **L1 Go/Rust node clients**.

> **Plamen-v3 platform status.** The governed production install and audit
> runtime is supported on Windows and admitted Linux hosts. Native macOS
> production installation and E2E auditing are **not yet supported**: the
> package transaction and worker-containment layers fail closed on Darwin.
> macOS arm64 and x86_64 are supported for isolated source development through
> [`scripts/bootstrap_macos_dev.sh`](scripts/bootstrap_macos_dev.sh); see the
> [macOS development guide](docs/development/macos.md) and
> [machine-migration guide](docs/development/machine-migration.md). Completing
> native or governed-host Mac audit execution remains part of the
> [Plamen-v3 continuation goal](docs/continuation/GOAL.md).

---

## Prerequisites

[CPython 3.12](https://python.org) and [Git](https://git-scm.com). Plamen materializes its reviewed Claude Code and Codex backends itself.

> **Backend CLIs.** Claude Code and Codex use the same
> deterministic local analyzer/toolchain phases. During model phases, Claude
> headless may expose only `unified-vuln-db` to `rag_sweep`; Claude PTY and
> Codex expose no MCP servers and use governed Web precedent research. Plamen
> installs both immutable, reviewed copies side-by-side; the audit wizard lets
> you pick per run. No global npm package is required.
>
> Plamen does not execute ambient `node`, `npm`, `npx`, or Windows npm shell
> wrappers during materialization. It downloads the exact official Node.js
> 24.20.0 archive for the host platform, verifies the checked-in SHA-256, seals
> the complete bundled npm 11.19.0 implementation closure, and invokes the
> exact `npm-cli.js` through that managed Node executable.
>
> Do not install global Claude, Codex, Node, or npm packages for Plamen. The
> governed install owns both backends and their complete executable closures.
>   Audit subprocesses intentionally ignore ambient Codex MCP configuration.
>   See [docs/mcp-servers.md](docs/mcp-servers.md).
>
> MCP is limited to receipt-bound Claude-headless RAG on contained hosts.
> Windows uses a Job object; Linux uses delegated cgroup v2 plus Landlock when
> supported. Unsupported Linux hosts fail closed before MCP spawn and use the
> governed Web/local fallback. Claude PTY and Codex use no MCP servers.
>
> Per-language tools (Foundry, Solana CLI, etc.) are installed automatically via `plamen setup`.
>
> **Python isolation**: Plamen never writes to system or user site-packages and never uses `--break-system-packages`. It creates `~/.local/share/plamen/runtime/py312`, installs only exact wheel hashes from the universal locks, and binds generated launchers to that interpreter.

---

## Install

### Option A: Let your AI assistant set it up

Open Claude Code or Codex CLI in any project directory and paste the contents
of [`SETUP.md`](SETUP.md). It is the only Plamen doc designed for AI-assistant
consumption — it has step-by-step error handling and stops the assistant from
running the heavy RAG build or the toolchain wizard from a non-TTY context.
The assistant acquires source separately and runs one governed install for
both model backends on a supported production host. On macOS, follow the
[source-development bootstrap](docs/development/macos.md) instead.

> Do **not** paste [`docs/setup.md`](docs/setup.md) or
> [`docs/getting-started.md`](docs/getting-started.md) into the AI — those
> are long-form manuals for humans and contain the RAG build inline.

After paste-setup, run `plamen setup` from a real terminal yourself to install
chain toolchains (Foundry, Solana CLI, Anchor, etc.) and `plamen rag` to
build the optional vulnerability DB (~6GB RAM).

### Option B: Terminal

Clone into a dedicated source directory, not `~/.plamen`. That path is
reserved for the authenticated installed package.

**Linux:**
```bash
git clone --recurse-submodules https://github.com/PlamenTSV/plamen.git "$HOME/plamen-source"
cd "$HOME/plamen-source" && python3.12 plamen.py install
```

**Windows (PowerShell):**
```powershell
git clone --recurse-submodules https://github.com/PlamenTSV/plamen.git "$HOME\plamen-source"
Set-Location "$HOME\plamen-source"; python plamen.py install
```

> **Use `git clone --recurse-submodules`, not "Download ZIP"**. The repo ships
> `custom-mcp/slither-mcp/`, `custom-mcp/farofino-mcp/`, and the three
> `opengrep-rules/*` rule sets (`aptos-move-rules`, `decurity-rules`,
> `opengrep-rules`) as git submodules; ZIP downloads silently omit them. If you already cloned without
> `--recurse-submodules`, run `git submodule update --init --recursive` from
> inside the source checkout before `plamen install`.
>
> **`install` vs `setup`**: `plamen install` is the non-interactive,
> transactional package/runtime install and is safe in any context
> — Claude Code Bash, Codex shell, CI, headless servers. `plamen setup` runs
> the install and then drops into an interactive toolchain wizard (Foundry,
> Solana CLI, etc.), so run it from a real terminal. In a non-TTY context it
> refuses before making changes and directs you to run `plamen install`.
>
> **Before building the RAG database**: add `SOLODIT_API_KEY` to `~/.claude/settings.json` → `"env"` section (or `~/.codex/config.toml` → `[env]` for Codex). Free key from [solodit.cyfrin.io](https://solodit.cyfrin.io). This is the only place the key is reliably visible to both `plamen rag` and audit agent subprocesses. A terminal `export` is not sufficient — Claude Code and Codex CLI spawn non-interactive subshells that don't source `.bashrc`/`.zshrc`.
>
> Hash-locked Python dependencies are installed into Plamen's private runtime on first run. Use CPython 3.12 (`python3.12` on Linux; `python` on Windows when it resolves to 3.12).

The installed front is written to `~/.local/bin`. Add that directory to PATH
if needed; do not add the source directory or `~/.plamen`.

**Linux (bash):**
```bash
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc && source ~/.bashrc
```

**Windows (PowerShell, one-time):**
```powershell
[System.Environment]::SetEnvironmentVariable("Path", "$env:USERPROFILE\.local\bin;" + [System.Environment]::GetEnvironmentVariable("Path", "User"), "User")
```

Then use `plamen` from anywhere:
```bash
plamen                              # interactive audit wizard
plamen plan core /path --codex      # zero-provider launch/model preflight
plamen resume                       # resume an interrupted audit from last checkpoint
plamen doctor                       # verify install (no audit run, no API calls)
plamen setup                        # toolchain wizard + optional RAG build
plamen migrate                      # upgrade a v1.x install layout
plamen rag                          # rebuild RAG database only
plamen compare                      # diff two audit reports
plamen uninstall                    # remove the managed installation
plamen help                         # full command + option reference
```

Direct commands show a launch summary in a terminal. Non-interactive launches
must add `--yes`; model fallback remains disabled unless
`--allow-model-fallback` is explicitly supplied.

> Audit runs accept additional options (`--tier`, `--modules`, `--network`, `--notes`, `--claude`, ...). Run `plamen help` or see [docs/usage.md](docs/usage.md) for the complete list.

> **Important**: Use `plamen` after installation. Invoke `plamen.py install`
> only from a complete source release; never execute or edit installed internals.

The installer validates the exact governed 764-row source closure before any
publication. It transactionally commits the authenticated package at
`~/.plamen`, a private hash-locked Python environment, managed Node.js
24.20.0/npm 11.19.0, and exact Claude Code 2.1.252 and Codex 0.152.0 payloads.
A signed current selection binds the runtime generation, receipts, policy,
backend resource closures, and permitted MCP launches.

The initial materialization may take several minutes. Normal launches are
fast: they authenticate the committed receipt and selected bounded executable
closure instead of rerunning installation. `plamen doctor` validates this
state without provider calls or ambient Node/npm/npx/Claude/Codex tools.

Do not install component requirement files, use editable installs, manually
link a checkout, or update installed files. See [docs/setup.md](docs/setup.md)
for chain-tool prerequisites and [docs/mcp-servers.md](docs/mcp-servers.md) for
the narrow contained Claude-headless RAG route.

### Updating

Acquire the new complete source release separately, then run its
`plamen.py install`. Never run `git pull` inside `~/.plamen` or update a
backend with npm. See [docs/updating.md](docs/updating.md) for authenticated
update and recovery details.

### Run your first audit

```bash
plamen                    # terminal wrapper with interactive wizard
```

Or inside Claude Code: `/plamen` · Inside Codex CLI: `/plamen core /path/to/project`

---

## What You Get

When an audit finishes, the headline deliverable is written to the **root of the
audited project**:

```
<project>/AUDIT_REPORT.md
```

`AUDIT_REPORT.md` is a self-contained Markdown report (per
[`rules/report-template.md`](rules/report-template.md)) containing:

- **An Executive Summary** and a **severity summary table** (Critical / High / Medium / Low / Informational counts).
- **A "Components Audited" table** listing the contracts/modules in scope.
- **Severity-tiered findings** — every finding gets its own section with **Severity**, **Location** (`file:Lnnn`), a **Description** (with the offending code), an **Impact** statement, the **PoC Result** (`[POC-PASS]` / `[POC-FAIL]` / `[CODE-TRACE]` — see [docs/glossary.md](docs/glossary.md)), and a **Recommendation** (a minimal fix diff when the PoC passed). Cosmetic Low/Info items may be grouped into a compact "Quality Observations" table.
- **A Priority Remediation Order** — a numbered, most-urgent-first list using the clean client-facing IDs (`C-01`, `H-01`, `M-01`, …).
- **Appendix A** — findings excluded as false-positives or duplicates (client-facing summary).
- **Appendix B** — *flagged obligations*: any unfinished work the haltless pipeline could not fully complete is surfaced here for human triage instead of silently dropped (see [Resumable Pipeline](#resumable-pipeline-v2)).

**Intermediate artifacts** live in a per-audit workspace inside the project:

```
<project>/.scratchpad/
```

This holds everything the pipeline produced on the way to the report — recon
context, the findings inventory, depth traces, verification PoCs, the
report index, and the resume checkpoint. It is preserved between runs so the
audit can resume on crash, and discarded only on a `--fresh` restart. You
normally never need to open it; `AUDIT_REPORT.md` is the deliverable. See
[docs/glossary.md](docs/glossary.md) for the `.scratchpad/` layout.

---

## What Changed in v2.2.4

Highlights since v2.1.0 — recall-focused mechanical gates and cross-platform hardening, not a change to *what* the agents analyze:

- **M2 multi-axis coverage meta-pass, now 6 axes** — in Thorough mode, a deterministic driver-owned hot-function matrix checks orthogonal analysis axes (including caller identity / authorization subject). Closed structured evidence is primary and bounded Description/Impact cues are secondary; ambiguity still resolves to `GAP`. A Sonnet worker runs only when the prepass emits GAP rows.
- **Mechanical recall gates** — sibling/variant-coverage, external-dependency research-with-citation, and pipeline promotion-completeness are now graph-grounded, append-only gates instead of advisory prose, each routing low-confidence candidates through the existing verify-then-report filter rather than asserting a body finding directly.
- **Force-by-default PoC gate** — any finding with a concrete material harm is now forced into an executable proof-of-concept attempt unless a small closed set of code-grounded blockers applies, closing a self-declared-skip loophole across every supported ecosystem.
- **Non-EVM PoC execution hardened** — cargo-workspace test discovery for Rust-based ecosystems, plus a fixed PoC-registry lookup that had silently missed on non-EVM dispatch.
- **Cross-OS source hygiene gate** — an always-on static gate over the driver's
  own source catches missing text encodings and platform-only code paths. The
  macOS source-test lane is portability evidence only; it does not qualify a
  native Mac production install or E2E audit.
- **DAML/Canton coverage extended** — the ledger-based ecosystem now participates in the M2 hot-set and identity-axis machinery alongside its existing recon/depth/verification support.

Full release notes: [CHANGELOG.md](CHANGELOG.md). Upgrade guidance: [docs/updating.md](docs/updating.md).

---

## Audit Modes

| Mode | Plan | Agents | Indicative Cost | Key Features |
|------|------|--------|-----------------|-------------|
| **Light** | Pro | ~18-22 | **~$1–5** / ~10-25 min | Fast scan, all Sonnet, no fuzzing |
| **Core** | Max | ~30-50 | **~$10–30** / ~30-90 min | Full depth, PoC verification for Medium+ |
| **Thorough** | Max | ~40-100 | **~$30–100+** / ~1-4 hr | Iterative depth, invariant fuzzing, Medusa, skeptic-judge, Exploration-Completeness skeptic |

> On the Claude backend, model tiers are pinned to `claude-opus-5`,
> `claude-sonnet-5`, and `claude-haiku-4-5-20251001`. Override them with
> `PLAMEN_OPUS_MODEL`, `PLAMEN_THOROUGH_OPUS_MODEL`, `PLAMEN_SONNET_MODEL`,
> or `PLAMEN_HAIKU_MODEL` only when deliberately changing audit policy.

> Cost / runtime are rough indicators for a ~5k-line codebase on a Claude
> subscription. Larger codebases scale roughly linearly. The wizard runs
> `plamen --estimate` (an internal flag invoked by the wizard / `/plamen`
> slash command — not a direct-CLI option, see [docs/usage.md](docs/usage.md))
> before each audit to show a per-project number based on lines, scope, and
> target plan — use the interactive `plamen` wizard for a standalone estimate.
> API-key users (pay-as-you-go) see costs ~2–3× higher than subscription users.

See [docs/audit-modes.md](docs/audit-modes.md) for the full comparison.

---

## L1 Infrastructure Audits

Plamen also audits **L1 node clients and blockchain infrastructure** — consensus engines, p2p networking, mempool logic, RPC surfaces, and validator lifecycle code in Go and Rust.

```bash
plamen l1 core /path/to/node-client
```

Or inside Claude Code: `/plamen l1 core` · Inside Codex CLI: `/plamen l1 core /path/to/node-client`

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

```bash
plamen                                              # interactive wizard
plamen core /path/to/project                        # direct config + confirmation
plamen thorough /path/to/project --proven-only      # strict evidence mode
plamen setup                                        # install tools only
```

**Inside Claude Code**:

```
> /plamen core
> /plamen thorough docs: whitepaper.pdf scope: scope.txt
```

**Inside Codex CLI**:

```
> /plamen core
> /plamen l1 thorough /path/to/node-client
```

See [docs/usage.md](docs/usage.md) for PATH setup and all CLI options.

---

## Resumable Pipeline (V2)

Plamen is a Python orchestrator that drives Claude (or Codex) workers. Phases run in one of three shapes: **LLM phase session** (single `claude -p` / `codex exec` subprocess), **Python mechanical** (no LLM), or **Direct PTY worker pool** (driver supervises one Claude PTY per worker artifact — used for breadth, depth, and rescan). PTY-supervised execution drives each worker through a pseudo-terminal and infers turn completion from artifacts written to disk rather than a fragile stdout/JSON envelope — eliminating the 0-byte-stdio ambiguity and silent-hang class. A dedicated PTY transport preflight runs at startup to pick a working terminal transport. For worker-pool phases the driver treats disk artifacts with `<!-- PLAMEN_STATUS: COMPLETE -->` markers as the only source of truth — Claude saying "done" is no longer trusted. If usage runs out or the process crashes, re-run the same command — it auto-resumes from the last successful checkpoint and, for worker-pool phases, only retries missing or `IN_PROGRESS` rows (completed worker rows are preserved). Stale or corrupt checkpoints recover rather than stranding the run.

**Haltless resilience.** A finished audit is never thrown away at the finish line. The report_index, verify, inventory, and resume paths **repair-then-degrade** — surfacing unfinished obligations as flagged items in `AUDIT_REPORT.md` (Appendix B) instead of halting the pipeline. Several formerly fragile LLM phases are now **deterministic Python** (LLM out of the loop): mechanical smart-contract report_index recovery, verify backfill / queue manifests, the data-loss-free `report_dedup` builder, and the recon prepass.

```bash
# Launch via wizard (interactive)
plamen                              # terminal wrapper starts wizard
/plamen-wizard                      # inside Claude Code
/plamen-wizard                      # inside Codex CLI

# Resume a crashed/interrupted audit
plamen resume /path/to/project/.scratchpad/config.json
```

The driver handles: phase scheduling, worker-pool orchestration, artifact gating, rate-limit pauses, retry-with-degradation, and subprocess isolation via the `plamen_home()` abstraction (resolves to `~/.claude/` or `~/.codex/plamen/` based on the configured backend). The LLM handles: in-phase agent reasoning for phase-LLM phases, finding analysis, PoC execution, and report content. For worker-pool phases the LLM is a bounded executor — one role, one output file, one artifact.

After install, `~/.plamen/` is the authenticated package and must not be
edited. The source checkout remains separate and has no live-runtime
authority. `/plamen` and `/plamen-wizard` can be launched from inside an
active Claude Code session: the driver strips parent Claude identity variables
from child subprocesses so nested invocations do not collide.

---

## Codex CLI Backend (BETA — cost-saving)

Plamen supports [OpenAI Codex CLI](https://github.com/openai/codex) as an alternative, cost-saving backend (**beta**). The V2 driver translates **prompt text** (Write→`apply_patch`, Bash→`shell`, `Task()`→`spawn_agent`, `~/.claude/`→`~/.codex/plamen/`) and adapts sandbox constraints. This is prompt-text rewriting, not an MCP transport shim: Codex audit subprocesses load no MCP servers and use governed Web precedent research. The Claude PTY transport is Claude-only; Codex invokes `codex exec` directly — one `codex exec` per depth job, so depth fans out cleanly across jobs. Codex usage-cap errors (which Codex emits as natural-language text, not structured codes) are detected and the driver auto-waits instead of halting, and context-exceeded no longer perma-fails. Codex depth runs real Devil's-Advocate iteration 2 and seeds the full mandatory first-pass artifact set so recon/depth stop degrading lossily.

```bash
# Run via Codex after the standard governed install
/plamen core /path/to/project       # inside Codex CLI
```

The standard install publishes authenticated Claude and Codex projections from
the same committed package. Codex uses the exact 0.152.0 executable in the
signed current selection; it does not consult a global Codex installation.

| Claude Code | Codex CLI | Purpose |
|-------------|-----------|---------|
| `~/.claude/CLAUDE.md` | `~/.codex/AGENTS.md` | Orchestrator rules |
| `~/.claude/settings.json` | `~/.codex/config.toml` | Permissions, env vars |
| Contained Claude-headless RAG route | No MCP configuration | Audit research transport |
| `~/.claude/commands/` | `~/.codex/commands/` (from `codex-adapter/commands/`) | Slash commands |

---

## Supported Chains

| Language | Build Tool | Static Analysis | Fuzzing |
|----------|-----------|----------------|---------|
| **EVM/Solidity** | Foundry, Hardhat | Slither, Aderyn | Foundry invariant, Medusa |
| **Solana/Anchor** | Anchor, cargo-build-sbf | Fender | Trident, proptest |
| **Aptos Move** | aptos CLI | Move Prover | Parameterized tests |
| **Sui Move** | sui CLI | -- | Parameterized tests |
| **Soroban/Stellar** | Stellar CLI | -- | proptest, cargo-fuzz |
| **DAML/Canton** | daml CLI (`daml build`/`daml test`) | -- (DLint is style-only) | DAML Script boundary-value tests |
| **L1 Go/Rust** | go build, cargo | scip-go, rust-analyzer, Opengrep | proptest, go test -fuzz |

Ecosystem (language) is auto-detected and **auto-corrected at startup** with no halt-to-rerun — the resolved ecosystem is shown on the startup banner. Detection uses manifest-priority rules (a suffix-only match never clobbers an explicit config; Pinocchio / native-SDK Solana is detected at high confidence).

---

## Documentation

| Topic | Link |
|-------|------|
| Docs index | [docs/README.md](docs/README.md) |
| Glossary of terms | [docs/glossary.md](docs/glossary.md) |
| Full setup guide | [docs/setup.md](docs/setup.md) |
| Authenticated updates | [docs/updating.md](docs/updating.md) |
| macOS source development | [docs/development/macos.md](docs/development/macos.md) |
| Move development to a Mac | [docs/development/machine-migration.md](docs/development/machine-migration.md) |
| Plamen-v3 continuation goal | [docs/continuation/GOAL.md](docs/continuation/GOAL.md) |
| Platform dependencies | [docs/dependencies.md](docs/dependencies.md) |
| Audit mode comparison | [docs/audit-modes.md](docs/audit-modes.md) |
| Pipeline architecture | [docs/architecture.md](docs/architecture.md) |
| MCP servers & API keys | [docs/mcp-servers.md](docs/mcp-servers.md) |
| Codex backend (BETA) limitations | [docs/codex-backend.md](docs/codex-backend.md) |
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
