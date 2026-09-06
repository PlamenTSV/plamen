# Platform Dependencies

> V3 production install/setup is currently qualified only on Windows. On macOS
> use the [source-development bootstrap](development/macos.md); Linux is also a
> source-validation host until the POSIX transaction/keeper goal is complete.

> Complete dependency guide for all platforms. **Not sure what you need?** See [getting-started.md](getting-started.md) — most users only need tools for their target chain.
>
> `plamen setup` installs only exact checksum-backed tool recipes. Toolchains whose upstream bootstrap channel is mutable remain operator-provided and are reported by `plamen doctor`. `plamen rag` builds/rebuilds the RAG vulnerability database separately.

## Quick Start

```bash
# Auto-install everything (interactive)
plamen setup                                    # if PATH is set on Windows
cd $HOME\.plamen; python plamen.py setup        # Windows PowerShell (before PATH)
```

The setup wizard detects your OS and installed tools, installs only admitted locked recipes, and labels everything else as an external prerequisite. It never executes pipe-to-shell, package-manager, `latest`, or moving-branch installers.

---

## Required (All Platforms)

| Tool | Version | Purpose | Install |
|------|---------|---------|---------|
| Claude Code and Codex CLI payloads | Claude Code 2.1.252; Codex 0.152.0 | Managed AI runtimes (authenticate the backend you use) | `plamen install` materializes and signs both exact payloads; no global package is required |
| CPython | 3.12 (required) | Reproducible wheel ABI for the private runtime | [python.org](https://python.org) |
| Managed Node.js/npm | Node.js 24.20.0; npm 11.19.0 | Executes the authenticated backend and MCP closures | Materialized and checksum-verified by `plamen install`; ambient Node/npm/npx are not used |
| Git | any | Submodules, version control | [git-scm.com](https://git-scm.com) |
| Rust | stable | Solana (Trident fuzzer), Soroban contracts, L1 Rust clients | [rustup.rs](https://rustup.rs) — Solana, Soroban, and L1 Rust |
| `pywinpty` (Windows only) | exact + wheel SHA-256 | PTY supervision transport for Claude workers | private Python 3.12 runtime from `requirements-runtime-full.lock`; macOS/Linux use stdlib PTY support |
| `pydantic` | exact + wheel SHA-256 | Typed mechanical contract schemas and validation | private Python 3.12 runtime from `requirements-runtime-full.lock` |
| `markdown-it-py` | exact + wheel SHA-256 | Structure-aware parsing of methodology and finding artifacts | private Python 3.12 runtime from `requirements-runtime-full.lock` |
| `jsonschema` | exact + wheel SHA-256 | Strict provider-output validation | private Python 3.12 runtime from `requirements-runtime-full.lock` |

> **PTY-supervised execution (v2.1.0)**: the driver now drives each Claude/Codex
> worker through a pseudo-terminal and infers turn completion from artifacts
> written to disk (the `<!-- PLAMEN_STATUS: COMPLETE -->` marker), not from a
> stdout/JSON envelope. This removes the 0-byte-stdio ambiguity and silent-hang
> class from v2.0.x. A one-time PTY transport preflight
> (`scripts/preflight_pty_transports.py`) probes which continuation mechanisms
> the installed Claude Code binary supports; results are cached per
> `claude --version` and the driver always falls back to a slower respawn path
> if a probe is inconclusive — no extra setup is required.

### Windows: Developer Mode (only for external toolchains that need it)

Plamen installation does not require a mutable-checkout symlink. It publishes a
signed package at `~/.plamen/`, uses a receipt-bound Claude projection with
governed link/copy fallbacks, and transactionally copies/merges Codex integration
files. Windows Developer Mode is still needed by some external chain toolchains
that create their own file symlinks.

**Enable Developer Mode** (one-time):
- **Settings UI**: Settings > System > For Developers > toggle ON
- **Admin PowerShell**: `reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock /v AllowDevelopmentWithoutDevLicense /t REG_DWORD /d 1 /f`
- **Admin CMD**: `reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock /v AllowDevelopmentWithoutDevLicense /t REG_DWORD /d 1 /f`

For example, Solana builds may require it because `cargo-build-sbf` creates
symlinks internally.

> **macOS / Linux**: Plamen uses native atomic publication and does not require
> an elevated mutable-source symlink setup.

---

## EVM/Solidity

| Tool | Purpose | Install | Required? |
|------|---------|---------|-----------|
| Foundry (forge, cast, anvil) | Build, test, invariant fuzz, fork testing | Operator-provided reviewed release from [Foundry](https://book.getfoundry.sh/getting-started/installation) | Yes |
| Slither | Static analysis (MCP) | Private hash-locked Plamen runtime | Recommended |
| Medusa | Stateful fuzzing (Thorough mode) | `plamen setup` exact v1.5.1 via Go checksum verification | Optional |

### EVM Platform Notes

**Windows**: Foundry works natively. No special setup needed.
**macOS (Apple Silicon)**: Foundry works natively via Rosetta or arm64.
**Linux**: Foundry works natively.

Medusa requires an operator-provided Go SDK. Plamen will not bootstrap the SDK, but can install exact Medusa v1.5.1 through Go's module checksum mechanism once Go is present.

---

## Solana

| Tool | Purpose | Install | Required? |
|------|---------|---------|-----------|
| Solana CLI | Toolchain, account data | [docs.anza.xyz](https://docs.anza.xyz/cli/install) | Yes |
| Anchor (via AVM) | Build Anchor programs | Operator-provided reviewed release | Yes (for Anchor projects) |
| Trident | Stateful fuzzing | Operator-provided reviewed release; prerelease-only channels are not admitted | Recommended |
| Solana Fender | Optional Solana static analysis | Exact reviewed `solana_fender` release | Optional |

### Solana Platform Notes

<details>
<summary><strong>Windows -- Required Setup</strong></summary>

**1. Enable Developer Mode** (one-time, required for `cargo-build-sbf`):

Solana's build tools create symlinks internally. Without Developer Mode, builds fail with:
```
error 1314: A required privilege is not held by the client
```

Fix (choose one):
- **Settings UI**: Settings > System > For Developers > toggle Developer Mode ON
- **Admin PowerShell**: `reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock /v AllowDevelopmentWithoutDevLicense /t REG_DWORD /d 1 /f`
- **Per-session**: Run your terminal as Administrator (right-click > Run as administrator)

**2. Install OpenSSL** (required for Trident fuzz compilation):

Provide a reviewed OpenSSL build through your organization's normal software channel. Plamen deliberately does not invoke `winget` or another mutable resolver.

The `plamen.py` wrapper auto-detects OpenSSL in standard locations and sets environment variables. It checks (in order):
1. Existing `OPENSSL_LIB_DIR` / `OPENSSL_INCLUDE_DIR` env vars
2. vcpkg installation (`$VCPKG_ROOT/installed/x64-windows/`)
3. ShiningLight installer paths (`C:\Program Files\OpenSSL-Win64`, `C:\Program Files\OpenSSL`, `C:\OpenSSL-Win64`)

If auto-detection fails, set manually in PowerShell:
```powershell
$env:OPENSSL_DIR = "C:\Program Files\OpenSSL-Win64"
$env:OPENSSL_LIB_DIR = "C:\Program Files\OpenSSL-Win64\lib\VC\x64\MD"
$env:OPENSSL_INCLUDE_DIR = "C:\Program Files\OpenSSL-Win64\include"
```

**3. Anchor workspace glob issue** (Anchor CLI < 0.32):

If `anchor build` fails with `error: failed to load manifest for workspace member programs/*`, the Anchor CLI's `\\?\` long path prefix breaks glob expansion. Workaround: temporarily replace `"programs/*"` in `Cargo.toml` with explicit member paths, or use `cargo build-sbf` directly.

</details>

<details>
<summary><strong>macOS -- Notes</strong></summary>

- Solana CLI installs natively on both Intel and Apple Silicon
- Trident v0.11+ works on Apple Silicon (no honggfuzz dependency)
- Provide OpenSSL through a reviewed OS or organization software channel; Plamen does not invoke Homebrew.

</details>

<details>
<summary><strong>Linux -- Notes</strong></summary>

- All tools install natively
- System OpenSSL dev packages may be needed: `sudo apt install libssl-dev pkg-config` (Ubuntu/Debian) or `sudo dnf install openssl-devel` (Fedora)
- Trident v0.11+ works without honggfuzz

</details>

### Trident Version Compatibility

| Trident | Honggfuzz Required? | Platforms | Solana SDK |
|---------|---------------------|-----------|------------|
| **v0.12.x (current)** | No (TridentSVM) | Linux, macOS, Windows | 2.3 |
| **v0.11.x** | No (TridentSVM) | Linux, macOS, Windows | >=1.17.3 |
| v0.10.x and below | Yes (Linux only) | Linux only | >=1.17.3 |

> **Important**: Trident v0.11+ completely replaced honggfuzz with its own TridentSVM engine. There is NO need to install honggfuzz or AFL.

---

## Aptos Move

| Tool | Purpose | Install | Required? |
|------|---------|---------|-----------|
| Aptos CLI | Build, test, prove | [aptos.dev/build/cli](https://aptos.dev/build/cli) |  Yes |

Works on all platforms. The Aptos CLI is operator-provided because its upstream bootstrap/package-manager channels are mutable; Plamen validates visibility but does not execute those channels.

---

## Sui Move

| Tool | Purpose | Install | Required? |
|------|---------|---------|-----------|
| Sui CLI (via suiup) | Build, test | [docs.sui.io](https://docs.sui.io/guides/developer/getting-started/sui-install) | Yes |

Works on all platforms. The Sui CLI is operator-provided because moving `suiup` channels are not an immutable installation boundary.

---

## Soroban/Stellar

| Tool | Purpose | Install | Required? |
|------|---------|---------|-----------|
| Stellar CLI | Build, deploy, test Soroban contracts | [stellar.org/docs](https://stellar.org/docs/build/smart-contracts/getting-started) | Yes |
| Rust (stable) | Soroban contract compilation | [rustup.rs](https://rustup.rs) | Yes |
| Scout (cargo-scout-audit) | Soroban static analysis | `plamen setup` exact 0.3.16 + Cargo lock | Recommended |
| cargo-fuzz | Thorough-mode libFuzzer fuzzing | `plamen setup` exact 0.13.2 + pinned nightly-2026-08-01 (not offered on Windows) | Recommended |

Soroban contracts are Rust-based. The Stellar CLI (`stellar`) handles contract building and testing. Install Rust stable toolchain first, then install the Stellar CLI.

### Soroban Platform Notes

Works on all platforms. No special setup needed beyond Rust and the Stellar CLI.

---

## DAML / Canton

| Tool | Purpose | Install | Required? |
|------|---------|---------|-----------|
| DAML SDK (`daml` CLI) | Build (`daml build`) and test (`daml test`) DAML templates | [docs.daml.com/getting-started/installation.html](https://docs.daml.com/getting-started/installation.html) | Yes |

DAML has no security-focused static analyzer (DLint is style-only) and no
native fuzzer — Thorough-mode fuzzing falls back to boundary-value
parameterized DAML Scripts. Auto-detected on `.daml` sources; works on all
platforms.

---

## L1 Infrastructure (Go/Rust Node Clients)

> These tools are needed only for L1 mode (`plamen l1`). Skip if you only audit smart contracts.

| Tool | Purpose | Install | Required? |
|------|---------|---------|-----------|
| Go 1.25+ | Build Go-based node clients | [go.dev/dl](https://go.dev/dl/) | Yes (Go clients) |
| Rust (stable) | Build Rust-based node clients | [rustup.rs](https://rustup.rs) (preferred) | Yes (Rust clients) |
| scip-go | SCIP indexer for Go | `plamen setup` exact version from the governance lock | Recommended |
| rust-analyzer | SCIP indexer for Rust | Operator-provided reviewed component/build | Recommended |
| cargo-fuzz | libFuzzer harness runner for Rust (Thorough-mode fuzzing) | `plamen setup` exact 0.13.2 + nightly-2026-08-01 (Unix only) | Recommended (L1 Rust) |
| ast-grep | Structural code search | `plamen setup` exact 0.45.2 + Cargo lock | Recommended |
| CodeQL CLI | Advanced static analysis | [github.com/github/codeql-cli-binaries](https://github.com/github/codeql-cli-binaries) | Optional |

> **macOS/Linux Rust note**: Rust and rust-analyzer are operator-provided.
> Plamen does not choose or mutate a Homebrew/rustup/system toolchain. Once a
> working Cargo is visible, setup may install only the exact Cargo recipes in
> the governance lock; `doctor` reports any remaining external prerequisite.

These tools power the Phase 0.5 "Bake" step that batch-indexes repositories before depth analysis. The pipeline works without them (falls back to grep-based analysis), but SCIP indexing significantly improves cross-reference accuracy.

---

## MCP Servers & RAG

The locked MCP packages are shared installation assets, not ambient audit
authority. Claude headless may load only `unified-vuln-db` during `rag_sweep`;
the default Claude PTY and Codex audit transports load no MCP servers and use
Web fallback for precedent context. Codex's optional global MCP blocks are for
manual interoperability and are ignored by `codex exec` audit subprocesses.
See [mcp-servers.md](mcp-servers.md) for the runtime matrix.

| Component | Purpose | Install | Required? |
|-----------|---------|---------|-----------|
| unified-vuln-db | RAG vulnerability database | `requirements-runtime-full.lock` via `plamen install` | Recommended |
| slither-mcp | Slither static analyzer bridge | reviewed local source + full lock | EVM only |
| farofino-mcp | Aderyn/Slither fallback | reviewed local source + full lock | EVM only |
| solana-fender | Solana security checks | reviewed local source + full lock | Solana only |

> **Note**: The unified-vuln-db install pulls ~2GB (includes PyTorch for sentence-transformers). It is optional unless you choose Claude headless RAG; PTY/Codex audits avoid its cold start.

### API Keys

| Key | Source | Purpose | Required? |
|-----|--------|---------|-----------|
| `SOLODIT_API_KEY` | [solodit.cyfrin.io](https://solodit.cyfrin.io) | Index 3400+ Solodit audit findings for RAG (4k+ total across all sources) | Recommended (free) |
| `TAVILY_API_KEY` | [tavily.com](https://tavily.com) | Web search fallback for RAG | Optional (free tier) |
| `ETHERSCAN_API_KEY` | [etherscan.io/apis](https://etherscan.io/apis) | Contract source verification | Optional (free) |
| `HELIUS_API_KEY` | [helius.dev](https://helius.dev) | Solana on-chain data | Optional (free tier) |
| RPC URL | Alchemy/Infura/public | Ethereum fork testing | Optional (free tier) |

Set MCP-specific keys only when using the optional manual adapters. Audit-time
Web and governed CLI credentials are supplied through the documented runtime
environment; global MCP configuration is not inherited. See [MCP Servers](mcp-servers.md).

---

## Development & Test Suite (Contributors)

> These are **dev-only** dependencies for running Plamen's own test suite — not
> needed to run audits, and not read by the installer or the audit runtime.
> Runtime deps stay in `requirements.txt`; test-only deps are layered
> separately so a production install never pulls them in.

| Tool | Version | Purpose | Install |
|------|---------|---------|---------|
| pytest | pinned (see `requirements-dev.txt`) | Test runner | `pip install -r requirements-dev.txt` |
| pytest-xdist | pinned (see `requirements-dev.txt`) | Parallel test execution (`-n auto`) | `pip install -r requirements-dev.txt` |

```bash
pip install -r requirements.txt        # runtime deps
pip install -r requirements-dev.txt    # + test-only deps, layered on top
```

**Pytest markers** (`pyproject.toml` → `[tool.pytest.ini_options]`): tests are
registered under `unit`, `integration`, and `slow` markers. Tests that spawn a
real subprocess or a real multi-second sleep are auto-marked by filename from
a single source of truth — no per-test annotation needed.

**CI lanes** (`.github/workflows/tests.yml`): the full suite runs on push/PR
across the three supported operating systems, split into two lanes that
together cover every test:
- **Fast lane**: marker-excluded fast tests, parallelized across all CPU cores
  via `pytest-xdist` (`-n auto`).
- **Integration lane**: the slower/integration-marked tests, run serially.

Both lanes force the same non-interactive-safe environment override used
locally (see below) so neither lane can block on an interactive prompt.

**Non-interactive test runs**: a couple of confirmation prompts (e.g. an
artifact-purge confirmation) poll for a keypress and will hang indefinitely
under a non-TTY execution context (CI, an agent shell). These prompts honor a
cross-platform environment-variable override and a non-interactive-terminal
guard that defaults safely to "keep artifacts, do not auto-purge" — the same
mechanism already used by other confirmation prompts in the codebase.

---

## Troubleshooting

### Common install failure modes

These are the most frequent post-install problems and their fixes. Run
`plamen doctor` first — it checks most of these and exits non-zero on hard
failures.

- **Managed backend missing or mismatched.** Re-run `plamen.py install` from a
  complete reviewed source checkout. Do not repair this with `npm install -g`,
  an ambient Node/npm/npx executable, or a mutable package under `~/.plamen/`.
  `plamen doctor` validates the signed current selection and exact managed
  Claude 2.1.252/Codex 0.152.0 launchers.
- **Claude is unauthenticated ("Not logged in").** An
  unauthenticated `claude -p` returns rc=0 with a "Not logged in" message and
  does no work, so an audit appears to start and then produces nothing.
  `plamen doctor` probes auth state and points at both supported paths: log in
  with `/login` (OAuth) **or** set `ANTHROPIC_API_KEY` in your environment.
  Note: an API key dropped into `~/.claude/settings.json` is **not** read as a
  credential — it must be a real env var or an OAuth login.
- **PATH not persisted ("command not found" mid-audit).** If `plamen` (or a
  toolchain binary) works in one shell but a later command reports
  "command not found", the PATH entry was not persisted to your shell profile.
  Re-run `plamen setup` (it appends the PATH export to your shell rc) and then
  **restart your shell** (or `source ~/.bashrc` / `~/.zshrc`). On Windows, the
  one-time `SetEnvironmentVariable(... "User")` from the README persists across
  sessions — open a new terminal after setting it.
- **`cargo install` MSRV failures.** A toolchain whose stable `rustc` predates
  a dependency's latest minimum-supported Rust version (e.g. `rustc 1.92` vs a
  dep requiring `1.94`) used to fail to build scout / cargo-fuzz / trident /
  rust-analyzer. As of v2.1.0 these are installed with `--locked`, so they
  build against the tool's tested lockfile instead of pulling a newer,
  incompatible transitive dependency. If you install one of these manually, add
  both an exact version and `--locked`; setup uses `cargo-scout-audit` 0.3.16.
- **Dependency audit is marked unavailable even though `govulncheck` or
  `cargo-audit` is installed.** A zero-known-CVE result is accepted only
  against an operator-owned, freshness-bound local advisory database. Set
  `PLAMEN_GOVULNDB` (Go) and/or `PLAMEN_RUSTSEC_DB` (Rust) to directories
  outside the target checkout. Each directory must contain
  `plamen-advisory-source.json` with schema
  `plamen.advisory_source.v1`, the governed `source_id` and `provider`, UTC
  `as_of` and `expires_at` timestamps, and the SHA-256 of the directory's
  sorted relative paths and bytes (excluding the manifest and `.git`). The
  maximum validity window is seven days; stale, future-dated, expired,
  target-controlled, or digest-mismatched data remains typed coverage debt.
  The exact provider strings and policy live in
  `verification_policy/toolchain_governance.v1.json`. Do not “refresh” only
  the manifest: the receipt must be emitted by the process that refreshed the
  advisory bytes.
- **A Move or Soldeer build/test is skipped by the supply-chain gate.**
  `Move.lock` and `soldeer.lock` are deliberately in the dependency
  denominator, but OSV-Scanner does not currently list either format as
  supported and Plamen does not claim an authoritative replacement. Until a
  governed advisory provider/parser exists, this is an explicit unsupported
  outcome rather than a false clean. Go projects are checked through `go.mod`
  (the OSV-supported manifest) when `go.sum` is present. OSV-Scanner v2 is
  invoked with `scan -L`,
  `--offline`, and `--offline-vulnerabilities`.
- **A tool version is later disclosed as vulnerable.** Add the affected
  version-output token and/or exact executable SHA-256 to that tool's
  `revocation_policy` in
  `verification_policy/toolchain_governance.v1.json`. Runtime snapshot
  construction evaluates this machine policy on Windows, Linux, and macOS and
  fails closed before a revoked binary can become audit evidence. Empty
  revocation lists mean “captured and reviewable,” not “permanently trusted”;
  mutable installer channels remain explicitly marked `GOVERNED_DEBT`.

### Windows: `error 1314: A required privilege is not held by the client`
Enable Developer Mode. See [Solana > Windows](#solana-platform-notes) above.

### Windows: `Could not find directory of OpenSSL installation`
Provide a reviewed OpenSSL build and rerun `plamen doctor`. See [Solana > Windows](#solana-platform-notes) above.

### macOS: `Unsupported MAC OS X version` when installing honggfuzz
You don't need honggfuzz. Trident v0.11+ uses TridentSVM. Just `cargo install trident-cli`.

### `Failed to list installed solana versions`
This occurs when Anchor CLI encounters Agave v3 (Solana CLI 3.x). Use Solana CLI 2.x for Anchor projects that specify `solana_version = "2.x"` in Anchor.toml.

### MCP server won't start (`spawn python ENOENT` or server shows as failed)
(Claude Code: edit mcp.json; Codex: the equivalent command lives in ~/.codex/config.toml [mcp_servers.*] blocks). **If you used `plamen install`, skip the sed below** — the installer already resolves the Python path (`_merge_mcp_json()` rewrites `"command": "python"`/`"python3"` to your interpreter's absolute path via `_resolve_command()`), so it is unnecessary and could clobber the resolved path. The sed is **only** for the manual `cp mcp.json.example` path. In that copied file the Python-based MCP servers use `"command": "python"` in mcp.json. On macOS/Linux, change to `"command": "python3"`:
```bash
sed -i '' 's/"command": "python"/"command": "python3"/g' ~/.claude/mcp.json  # macOS
sed -i 's/"command": "python"/"command": "python3"/g' ~/.claude/mcp.json    # Linux
```
Restart Claude Code after editing. On Windows, keep `"command": "python"`.

### MCP server timeout on first call
Claude Code only. ChromaDB and all-MiniLM-L6-v2 load on first use (~5s cold start). This is normal. The pipeline handles it with probe-first patterns and WebSearch fallback. The tool timeout is set to 300s in `settings.json`.

### RAG database build failed or entries count is too low
Run `plamen rag` again — it wipes the existing database and rebuilds from scratch. Ensure `SOLODIT_API_KEY` is set in `~/.claude/settings.json` → `"env"` section (Claude Code) or `~/.codex/config.toml` → `[env]` section (Codex). Safe to re-run as many times as needed.

### `No IDL files found`
Run `anchor build` or `cargo build-sbf` first to generate IDL files before `trident init`.

### Python version error
Plamen requires CPython 3.12 because its universal binary-wheel lock is reviewed for the `cp312` ABI:
```bash
# macOS (Homebrew)
# Install a reviewed CPython 3.12 build from python.org or your OS policy.
cd ~/.plamen && python3.12 plamen.py install

# Ubuntu/Debian
sudo apt install python3.12 python3.12-venv
cd ~/.plamen && python3.12 plamen.py install
```

### Slither runtime setup fails
Re-run `python3.12 plamen.py install`; Slither and its transitive dependencies come only from `requirements-runtime-full.lock`.

### ChromaDB: `Your system has an unsupported version of sqlite3`
ChromaDB requires SQLite >= 3.35. Older Python versions or OS builds may bundle an older SQLite. Fixes:
- **Easiest**: Use Python 3.11+ from [python.org](https://python.org) (bundles recent SQLite)
- **Linux**: `pip install pysqlite3-binary` then add to your script before importing chromadb:
  ```python
  __import__('pysqlite3')
  import sys
  sys.modules['sqlite3'] = sys.modules.pop('pysqlite3')
  ```
- **Windows**: repair/reinstall the reviewed CPython 3.12 distribution; do not replace its DLLs with an unpinned download

### macOS: `Failed to build hnswlib` during pip install
ChromaDB depends on `hnswlib` which needs a C++ compiler. Install Xcode Command Line Tools first:
```bash
xcode-select --install
```
If you get `clang: error: the clang compiler does not support '-march=native'`, set:
```bash
export HNSWLIB_NO_NATIVE=1
pip3 install chromadb
```

### `externally-managed-environment` error
The supported installer cannot produce this error because it writes only to Plamen's private venv. If you see it, a manual/system `pip` command was used; stop and run `python3.12 plamen.py install` instead.

### `error: failed to load manifest for workspace member programs/*`
Anchor CLI < 0.32 glob issue on Windows. See [Solana > Windows](#solana-platform-notes) above.

### Worker appears to "hang" with no output (PTY supervision)
As of v2.1.0 the driver supervises each worker over a pseudo-terminal and treats
the on-disk `<!-- PLAMEN_STATUS: COMPLETE -->` marker as the only completion
signal. A worker that is doing slow-but-real work no longer trips the old
context-thrash fast-fail; quiet stdio is expected. The driver detects completion
from disk, repairs-then-degrades rather than halting at the finish line, and
surfaces any unfinished obligations as flagged Appendix-B items in
`AUDIT_REPORT.md`. On Windows, ensure `pywinpty>=2.0.14` is installed (see
[Required](#required-all-platforms)); macOS/Linux use the stdlib `pty` module.

### Wrong toolchain selected / ecosystem mismatch
v2.1.0 auto-detects the target ecosystem (EVM, Solana, Aptos, Sui, Soroban, or
L1) at startup, auto-corrects it without a halt-to-rerun, and shows the resolved
ecosystem on the startup banner. Detection uses manifest-priority rules
(file-suffix-only signals never clobber an explicit config; Pinocchio/native-SDK
Solana is detected at high confidence). If the banner shows the wrong ecosystem,
set it explicitly in your project config and re-run — the explicit value wins.
