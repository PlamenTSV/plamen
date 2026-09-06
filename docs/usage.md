# Usage

> V3's production commands currently apply to Windows. Linux/macOS are
> source-development and validation hosts until the POSIX package transaction,
> keeper, and recovery work in `continuation/GOAL.md` is complete.

> **Just installed?** See [getting-started.md](getting-started.md) first — what's required, what's optional, and how to run your first audit.

All invocations -- terminal CLI, Claude Code slash commands, and Codex CLI --
launch the same V2 deterministic driver (`plamen_driver.py`). Model-owned phases
run through the selected isolated transport: Claude PTY sessions or headless
`codex exec`. Breadth, depth, and rescan use driver-supervised worker pools with
one backend invocation per artifact and disk-derived completion
(`<!-- PLAMEN_STATUS: COMPLETE -->`). See
[pipeline-phases-presentation.md](pipeline-phases-presentation.md) for the
per-phase execution shape. The driver provides automatic checkpointing,
manifest-exact retry (only missing/bad worker rows re-spawn, not whole phases),
gating, rate-limit pause/resume, and haltless resilience — late phases
repair-then-degrade and flag unfinished obligations in the report instead of
throwing away a finished audit. Bookkeeping-heavy stages (report-index recovery,
verify backfill, finding dedup) run as deterministic Python rather than fragile
LLM prose parsing.

---

## Quick Start

### Terminal (recommended)

```bash
plamen                                  # Interactive wizard
plamen core /path/to/project            # SC audit, Core mode
plamen l1 thorough /path/to/node-client # L1 audit, Thorough mode
```

### Claude Code

```
/plamen-wizard          # SC audit — interactive config then driver launch
/plamen-l1-wizard       # L1 infrastructure audit
```

### Codex CLI (beta)

The OpenAI Codex CLI (`codex exec`) is supported as an alternative, cost-saving backend (beta). It runs one `codex exec` per depth job, detects usage caps from natural-language output and auto-waits instead of halting, and seeds the full mandatory first-pass artifact set so recon/depth degrade losslessly.

> **Before relying on Codex**, read [codex-backend.md](codex-backend.md) — it consolidates the known BETA limitations: reduced fan-out vs Claude, no MCP in audit subprocesses (governed Web fallback), ChatGPT-auth/usage-cap behavior, and that `plamen compare` is Claude-only. Model routing fails closed by default; fallback requires explicit authorization.

Codex requires prior governed setup: run `plamen.py install --codex` from a
complete reviewed source checkout. The installer publishes the signed package
at `~/.plamen/`, materializes exact managed Node.js 24.20.0/npm 11.19.0 and
Codex 0.152.0 payloads, and transactionally copies the Codex commands and
configuration into `~/.codex/`. After that, invoke the slash commands (for
example `/plamen-wizard` or `/plamen-l1-wizard`) or use the terminal wrapper:

```
$plamen core /path/to/project
$plamen l1 core /path/to/node-client
```

---

## CLI Reference (`plamen` / `plamen.py`)

All commands below launch the V2 deterministic driver. The `plamen` command is
an atomically published launcher bound to the signed COMMITTED package, not a
symlink to a mutable source checkout.

### Audit Commands

| Command | Description |
|---------|-------------|
| `plamen` | Interactive wizard: mode selection, target, docs, scope, cost estimate, launch |
| `plamen plan core /path` | Validate target/backend/model routes without writes to the audit target or provider calls |
| `plamen light /path` | Smart contract audit in Light mode (Pro plan, ~18-22 agents) |
| `plamen core /path` | Smart contract audit in Core mode (Max plan, ~30-50 agents) |
| `plamen thorough /path` | Smart contract audit in Thorough mode (Max plan, ~40-100 agents) |
| `plamen l1 light /path` | L1 infrastructure audit in Light mode |
| `plamen l1 core /path` | L1 infrastructure audit in Core mode |
| `plamen l1 thorough /path` | L1 infrastructure audit in Thorough mode |
| `plamen compare` | Diff two audit reports (post-mortem analysis) |
| `plamen resume` | Resume an interrupted audit from last checkpoint |
| `plamen resume /path/config.json` | Resume a specific audit config |

### Setup Commands

| Command | Description |
|---------|-------------|
| `plamen setup` | Toolchain installer: installs chain tools, checks dependencies, shows status |
| `plamen install` | Validate source, publish `~/.plamen/`, materialize exact managed backends, and update the receipt-bound Claude projection plus Codex configuration |
| `plamen install --codex` | Same governed package/backend publication with Codex integration only (no Claude projection) |
| `plamen install --codex --check` | Validate the exact local source package and install direction without changing files |
| `plamen rag` | Build or rebuild the RAG vulnerability knowledge base |
| `plamen uninstall` | Remove only authenticated Plamen-owned projection, configuration, and launcher state while preserving foreign/user content |

### Options

| Option | Applies to | Description |
|--------|-----------|-------------|
| `--docs PATH` | SC audits | Path to whitepaper or spec file |
| `--scope PATH` | SC audits | Path to scope file listing contracts |
| `--notes TEXT` | SC audits | Free-text scope notes |
| `--network NAME` | SC audits | Target network (ethereum, arbitrum, optimism, base, polygon, bsc, avalanche) |
| `--proven-only` | SC audits | Cap findings with only `[CODE-TRACE]` evidence at Low severity |
| `--tier T0\|T1\|T2\|T3` | L1 audits | L1 tier override (auto-detected from LOC by default) |
| `--modules a,b,c` | L1 T1 audits | Module selection for T1 subsystem scope |
| `--codex` | All audits | Force Codex CLI backend |
| `--claude` | All audits | Force Claude Code backend (default) |
| `--yes` | Direct audit commands | Confirm a non-interactive launch (use `plamen plan` first) |
| `--allow-model-fallback` | Codex audits | Explicitly authorize fallback to a different model route |
| `--json` | `plamen plan` | Emit the zero-provider plan as JSON |
| `--explain-routes` | `plamen plan` | Print every phase-to-model route |

### Examples

```bash
# SC audit with docs and scope
plamen core /path/to/project --docs whitepaper.pdf --scope scope.txt

# SC Thorough with proven-only and network
plamen thorough /path/to/project --network ethereum --proven-only

# L1 audit targeting specific modules
plamen l1 core /path/to/geth --tier t1 --modules consensus,p2p

# Zero-provider preflight, then an explicitly confirmed non-interactive run
plamen plan core /path/to/project --codex --explain-routes
plamen core /path/to/project --codex --yes

# Build RAG database (requires ~6GB RAM)
export SOLODIT_API_KEY=your_key_here
plamen rag
```

---

## PATH Setup

To use `plamen` as a command after a supported Windows install:

```powershell
# Windows (PowerShell, one-time)
[System.Environment]::SetEnvironmentVariable("Path", "$env:USERPROFILE\.local\bin;" + $env:Path, "User")
```

Do not add the source checkout or `~/.plamen` to `PATH`. macOS and Linux
contributors should use the isolated
[source-development workflow](development/macos.md); it intentionally does not
publish a `plamen` production command.

---

## Resuming an Interrupted Audit

The driver checkpoints after each phase. If the process crashes, hits rate limits, or is interrupted:

```bash
# Auto-detect and resume
plamen resume

# Resume a specific config
plamen resume /path/to/project/.scratchpad/config.json

# Direct driver launch (advanced)
python3 ~/.plamen/scripts/plamen_driver.py --startup-intent RESUME_EXISTING /path/to/project/.scratchpad/config.json

# New run (new config and distinct clean destination; prior run is preserved)
python3 ~/.plamen/scripts/plamen_driver.py --startup-intent START_NEW_RUN /path/to/new-clean-project/.scratchpad/config.json
```

From Claude Code, running `/plamen-wizard` auto-detects an existing scratchpad and offers to resume.

Each scratchpad has a `.plamen_run.lock` that prevents concurrent driver invocations against the same audit. If a stale process owns the lock from a previous crash, the driver refuses to start until the lock is cleared — `rm .scratchpad/.plamen_run.lock` removes it.

---

## Running from inside Claude Code

`/plamen` and `/plamen-wizard` can be launched while a parent Claude Code session is active. The driver strips the parent's Claude identity env vars (`CLAUDECODE`, `CLAUDE_CODE_SESSION_ID`, `CLAUDE_CODE_ENTRYPOINT`, `CLAUDE_CODE_EXECPATH`, `AI_AGENT`) from every child subprocess so the nested `claude` invocations start as fresh sessions instead of detecting a nested-active-session and exiting rc=0 with no work done. The same applies on macOS/Linux where the POSIX PTY layer additionally resets inherited `SIGCHLD` disposition before each spawn (see [architecture.md § PTY Transport](architecture.md)).

---

## Operator controls and runtime behavior

- **Escape / halt**: pressing Escape (or sending a halt signal) cancels every **queued** worker immediately via `_cancel_pending_worker_futures` and terminates **in-flight** workers with a 2-second grace (`_HALT_TERMINATE_GRACE_S = 2.0`) before SIGKILL. The driver then exits with rc=−3 so you can resume with `plamen resume`.
- **Compaction heartbeat**: Claude auto-compacting its context during a worker turn prints a single informational line ("Claude compacted context; continuing normally (disk gate is source of truth)"). This is **not a warning** — the driver continues under disk-gate validation. If the artifact reaches `PLAMEN_STATUS: COMPLETE`, the worker is done regardless of compaction notice.
- **Worker-pool progress**: operators see live per-worker progress directly in the UI (no longer hidden inside Claude's Task tool stdio). File creation, marker transitions (`IN_PROGRESS` → `COMPLETE`), and worker completion events are all visible.
- **Multiple Claude PTY processes**: during breadth/rescan/depth you will see multiple `claude` processes in the process tree — one per worker artifact. This is expected (driver-owned worker pool), not duplication or runaway processes.
- **Ecosystem auto-detect**: the driver mechanically detects the codebase ecosystem (EVM, Solana, Aptos, Sui, Soroban, DAML, or L1 Go/Rust) at startup, shows it on the banner, and auto-corrects a mismatched `config.language` in place — no halt-to-rerun. Detection is recall-safe: it only overrides on a genuine high/medium-confidence mismatch, and on ambiguity it keeps the configured value and warns rather than guessing. Corrections are surfaced on the TUI (`[startup] auto-detected ecosystem=...`).
- **Truthful completion / no-ship**: late failures are repaired or recorded as typed debt. A report is released only when terminal integrity allows it; otherwise the UI says `NO DELIVERABLE`, quarantines/withholds the report, returns a degraded status, and prints the exact resume command. Stale or corrupt checkpoints recover instead of silently claiming success.

---

## When to Use Which

| | Terminal (`plamen`) | Claude Code | Codex CLI |
|---|---|---|---|
| **First time** | Use this | `/plamen-wizard` | Need Codex + tools |
| **Cost estimate** | Shows estimate | No estimate | No estimate |
| **Resume on crash** | `plamen resume` | `/plamen-wizard` (auto-detects) | `$plamen resume` |
| **Daily use** | `plamen core .` | `/plamen-wizard` | `$plamen core .` |

---

## Cost Estimation

The terminal wrapper estimates token usage before launch:
- Input/Output tokens (millions)
- API cost (USD)
- Weekly plan usage (% of Pro, Max x5, Max x20)

Estimates are rough -- actual usage varies with protocol complexity. Run `/cost` after an audit for actuals.

> `plamen --estimate TARGET MODE [--scope PATH] [--l1]` is an **internal** flag invoked by the `/plamen` slash command and the interactive wizard to produce a per-project estimate (printed as JSON). It is not part of the supported direct-CLI option set and is intentionally omitted from `plamen help`; use the interactive `plamen` wizard for a standalone cost estimate.
