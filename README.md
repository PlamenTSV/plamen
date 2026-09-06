# Plamen V3.0.0

Autonomous Web3 security auditor for [Claude Code](https://docs.anthropic.com/en/docs/claude-code) and [OpenAI Codex CLI](https://github.com/openai/codex).

Coordinates roughly 18-100 analysis workers across a deterministic ten-family
audit graph, including evidence-backed verification and PoC attempts, for
**smart contracts** and **L1 node-client infrastructure**.

Supports **EVM/Solidity**, **Solana/Anchor**, **Aptos Move**, **Sui Move**, **Soroban/Stellar**, **DAML/Canton**, and **L1 Go/Rust node clients**.

> **Branch and release status.** V3 lives on the `Plamen-v3` branch; `main`
> remains the V2 line. V3 is active and incomplete until the
> [continuation goal](docs/continuation/GOAL.md) is satisfied, including clean
> packaged Codex and Claude E2E runs. Do not interpret the version heading as a
> completed release or benchmark result.
>
> **Plamen-v3 platform status.** The governed production install and audit
> runtime is currently release-qualified on Windows. Native Linux and macOS
> production installation and E2E auditing are **not yet supported**: V3's
> hardened package transaction, crash keeper, and recovery transport are still
> Windows-native. POSIX remains a source-development and validation target.
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
> MCP is limited to receipt-bound Claude-headless RAG on contained production
> hosts. The current Windows lane uses a Job object. Linux cgroup v2/Landlock
> containment remains implemented substrate but is not a production-support
> claim until the POSIX install transaction is complete. Claude PTY and Codex
> use no MCP servers.
>
> Per-language tools (Foundry, Solana CLI, etc.) are installed automatically via `plamen setup`.
>
> **Python isolation**: Plamen never writes to system or user site-packages and never uses `--break-system-packages`. It creates `~/.local/share/plamen/runtime/py312`, installs only exact wheel hashes from the universal locks, and binds generated launchers to that interpreter.
>
> **Repository size and launch speed:** GitHub's “1,000 files” directory
> truncation is only a web-UI listing limit. The source tree intentionally keeps
> tests, fault fixtures, architecture records, and continuation research beside
> the implementation. A production install publishes the exact governed
> 764-row closure (733 runtime rows plus 31 Codex-adapter rows); normal CLI/audit
> launch does not recursively enumerate every source test or research file.
> Dependency and integrity census work is concentrated at install/update time.

---

## Install

### Option A: Let your AI assistant set it up

Open Claude Code or Codex CLI in any project directory and paste the contents
of [`SETUP.md`](SETUP.md). It is the only Plamen doc designed for AI-assistant
consumption — it has step-by-step error handling and stops the assistant from
running the heavy RAG build or the toolchain wizard from a non-TTY context.
The assistant acquires source separately and runs one governed install for
both model backends on a supported Windows host. On macOS, follow the
[source-development bootstrap](docs/development/macos.md) instead.

For V3, require the assistant to clone and verify the `Plamen-v3` branch before
running `plamen.py install`. A default clone checks out `main`, which remains
the V2 line.

> Do **not** paste [`docs/setup.md`](docs/setup.md) or
> [`docs/getting-started.md`](docs/getting-started.md) into the AI — those
> are long-form manuals for humans and contain the RAG build inline.

After paste-setup, run `plamen setup` from a real terminal yourself to install
chain toolchains (Foundry, Solana CLI, Anchor, etc.) and `plamen rag` to
build the optional vulnerability DB (~6GB RAM).

### Option B: Terminal

Clone into a dedicated source directory, not `~/.plamen`. That path is
reserved for the authenticated installed package.

**Windows (PowerShell):**
```powershell
git clone --branch Plamen-v3 --single-branch --recurse-submodules https://github.com/PlamenTSV/plamen.git "$HOME\plamen-source"
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
> transactional package/runtime install and is safe in any supported Windows
> context — Claude Code Bash, Codex shell, CI, or a headless Windows host. `plamen setup` runs
> the install and then drops into an interactive toolchain wizard (Foundry,
> Solana CLI, etc.), so run it from a real terminal. In a non-TTY context it
> refuses before making changes and directs you to run `plamen install`.
>
> **Before building the RAG database**: add `SOLODIT_API_KEY` to `~/.claude/settings.json` → `"env"` section (or `~/.codex/config.toml` → `[env]` for Codex). Free key from [solodit.cyfrin.io](https://solodit.cyfrin.io). This is the only place the key is reliably visible to both `plamen rag` and audit agent subprocesses. A terminal `export` is not sufficient — Claude Code and Codex CLI spawn non-interactive subshells that don't source `.bashrc`/`.zshrc`.
>
> Hash-locked Python dependencies are installed into Plamen's private runtime on first run. Use `python` on Windows when it resolves to CPython 3.12. Linux and macOS contributors should follow the source-development boundary above; `plamen.py install` exits before mutation there.

The installed front is written to `~/.local/bin`. Add that directory to PATH
if needed; do not add the source directory or `~/.plamen`.

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

For an existing V3 source checkout, keep the branch selection explicit:

```bash
git switch Plamen-v3
git pull --ff-only origin Plamen-v3
python3.12 plamen.py install
```

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
- **Appendix B** — *flagged obligations*: any unfinished work the pipeline
  could not fully complete is surfaced for human triage instead of silently
  dropped (see [Plamen V3 Architecture](#plamen-v3-architecture)).

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

## What Changes in Plamen V3.0.0

V3 moves Plamen from prompt-and-file convention toward explicit, typed
authority. The branch currently contains these implemented foundations and
hardening paths:

- **Typed authority instead of a monolithic ledger.** Domain-specific immutable
  JSON records, PhaseIO contracts, semantic journals, content identities, and
  output-prestate/CAS checks bind producer inputs to incorporated outputs.
  Markdown and completion markers remain human-readable projections or
  transport evidence; their presence alone is not semantic completion.
- **Methodology has named ownership.** The MethodCard catalog and
  method-application policy separate normative method content from prompts,
  provider facts, scheduler behavior, dispositions, and report projection.
  Migrating every live consumer to that single-owner model is still active
  work, not a completed cutover.
- **Program Facts and graphs are capability-scoped.** Typed symbol, call,
  state-write, dependency, and relation evidence can seed sibling coverage,
  assumption checks, and further investigation. Missing, stale, unsupported,
  or partial graph evidence may add candidates or debt but cannot authorize a
  clean negative, demotion, or safe conclusion.
- **Recall work is routed, not asserted.** Adaptive attention, global `ATT-N`
  queue identity, enumeration-gap exploration, application and exploration
  skeptics, niche routing, multi-axis hot-function coverage, dependency
  research, and promotion-completeness checks feed candidates into the normal
  deduplication and verification boundaries. They do not mint report findings
  merely because a graph edge or heuristic matched.
- **Worker orchestration is driver-owned.** Manifests assign one output to each
  worker; route, model, input generation, process ownership, output prestate,
  validation, and parent incorporation are distinct lifecycle steps. Retry,
  timeout, cancellation, crash, and resume preserve explicit debt rather than
  translating missing work into success.
- **Verification and reporting are separated.** Material-harm findings are
  routed to executable PoC attempts unless a closed blocker applies;
  verification queues are mechanically sharded and reconciled. Report index,
  tier writers, deduplication, disposition, material-harm floor, and final
  assembly project accepted evidence. Report workers cannot silently mint,
  delete, omit, or rerate canonical findings.
- **Packaging is source-governed.** The current installer admits an exact
  764-row source closure, hash-locked Python wheels, reviewed Node/npm and
  backend payloads, immutable installed bytes, and receipt-bound selections
  instead of ambient tools or an editable installed checkout.
- **Claude and Codex share logical denominators.** Claude retains its PTY and
  narrowly contained headless-RAG route; Codex uses direct `codex exec`, loads
  no audit MCP servers, and uses governed Web/local precedent fallback.
  Requested and observed backend/model/fallback facts have typed recording
  paths, while unobservable results remain explicit `UNKNOWN_BLOCKED` debt.
- **Cross-platform claims are fail-closed.** Windows is the current production
  target. Linux remains covered by source tests, and macOS has a reviewed source
  bootstrap and portability checks; neither POSIX platform currently has a
  supported native production installer or E2E audit runtime.

These changes are not a whole-tool acceptance claim. Clean-package validation,
the remaining requirements reconciliation, macOS production execution, and
fresh Codex and Claude E2E completion are still open. See the
[continuation goal](docs/continuation/GOAL.md), its
[evidence index](docs/continuation/EVIDENCE_INDEX.json), and the
[architecture](docs/architecture.md) for the current boundary. Comparative
benchmarking against older Plamen versions is explicitly deferred.

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

## Plamen V3 Architecture

The Python driver is the sole phase sequencer. For smart-contract audits it
implements ten semantic phase families; brackets identify mode-dependent
families:

```text
Recon (1) -> Breadth (2) -> [Re-scan (3)] -> [Per-contract (4)]
  -> Inventory (5) -> [Semantic Invariants (6)] -> Depth Loop (7)
  -> Chain Analysis (8) -> Verification (9) -> Report (10)
```

Internal preparation, repair, skeptical review, deduplication, verification
shards, and report shards expand those families into additional work units;
they are not dozens of independent top-level phases. L1 audits retain the same
driver-owned discovery-to-report discipline while adding their documented bake
and graph-sweep work and using L1-specific depth and verification roles. Chain
composition is specific to the smart-contract path.

Each work unit uses one of three execution shapes: deterministic Python,
a bounded model phase session, or a driver-owned parallel worker pool. Claude
workers use the Claude-only PTY supervision transport. Codex workers are
launched directly with `codex exec`; Codex has no PTY pool or status-envelope
protocol. Both backends must satisfy the same artifact, identity, debt, and
incorporation semantics.

A process exit, model statement, marker, or output file is not enough to
complete work. The driver checks the expected artifact, phase/worker ownership,
immutable input and route binding, semantic shape, output prestate, and parent
incorporation before advancing. Mechanical preparation and reconciliation own
queue manifests, inventory joins, verification aggregation, report assembly,
and receipt publication where model judgment is unnecessary.

Retry and resume operate on missing or rejected work rather than intentionally
accepted rows. Unsupported tooling, capacity limits, malformed evidence, and
unrecoverable lifecycle conditions remain explicit debt and can block a
critical boundary; they are never converted into evidence that no issue
exists. Late-stage repair paths can surface bounded unfinished obligations for
human review, but cannot manufacture a successful E2E acceptance record.

```bash
# Launch via wizard (interactive)
plamen                              # terminal wrapper starts wizard
/plamen-wizard                      # inside Claude Code
/plamen-wizard                      # inside Codex CLI

# Resume a crashed/interrupted audit
plamen resume /path/to/project/.scratchpad/config.json
```

The driver handles scheduling, worker ownership, artifact gates, retry/resume,
typed incorporation, and final report publication. Model workers handle bounded
analysis, verification, and report-writing assignments; they do not sequence
the pipeline or self-authorize completion.

After install, `~/.plamen/` is the authenticated package and must not be
edited. The source checkout remains separate and has no live-runtime
authority. `/plamen` and `/plamen-wizard` can be launched from inside an
active Claude Code session: the driver strips parent Claude identity variables
from child subprocesses so nested invocations do not collide.

---

## Codex CLI Backend (BETA — cost-saving)

Plamen supports [OpenAI Codex CLI](https://github.com/openai/codex) as an
alternative backend (**beta**). The V3 runtime adapts prompt text and sandbox
constraints for Codex while preserving the same phase and artifact contracts.
This is not an MCP transport shim: Codex audit subprocesses load no MCP servers
and use governed Web/local precedent research. The Claude PTY transport remains
Claude-only; Codex invokes `codex exec` directly per assigned work unit.
Usage-cap and context failures are routed through explicit retry/debt handling,
and requested versus observed route facts are retained when observable. A
fresh packaged Codex E2E completion remains an open V3 acceptance gate.

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
| Automated setup (Claude/Codex) | [SETUP.md](SETUP.md) |

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
