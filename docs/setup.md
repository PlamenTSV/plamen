# Setup Guide

This guide installs Plamen for smart-contract and L1 audits on Windows and
admitted Linux hosts. Both Claude and Codex audit backends are included in the
same governed installation.

Native macOS production installation and E2E auditing are not yet supported:
the governed package transaction and worker-containment layers fail closed on
Darwin. Mac users can continue source development on arm64 or x86_64 with
[`scripts/bootstrap_macos_dev.sh`](../scripts/bootstrap_macos_dev.sh). Follow
the [macOS development guide](development/macos.md) and
[machine-migration guide](development/machine-migration.md); the remaining
runtime work is tracked by the [Plamen-v3 continuation goal](continuation/GOAL.md).

For AI-assisted setup, use [SETUP.md](../SETUP.md). The steps below are for a
human operator in a terminal.

## Prerequisites

Plamen needs only these ambient installation tools:

- CPython 3.12 exactly;
- Git, including submodule support;
- normal network access for the initial reviewed runtime downloads.

Do not install global Node, npm, npx, Claude Code, or Codex packages for
Plamen. The installer downloads the exact official Node.js 24.20.0 archive
for the host, verifies its checked-in SHA-256, authenticates the complete npm
11.19.0 closure, and materializes exact Claude Code 2.1.252 and Codex 0.152.0
payloads from the reviewed lock.

The Python dependencies are also isolated. Plamen creates a private CPython
3.12 environment and installs only hash-locked wheels; it never writes to the
system or user site-packages and never uses `--break-system-packages`.

Chain-specific compilers and analyzers are separate from the model runtime.
Run `plamen setup` after installation to select reviewed recipes for Foundry,
Solana/Anchor, Aptos, Sui, Soroban/Stellar, DAML/Canton, or Go/Rust L1 work.
See [dependencies.md](dependencies.md) for platform details and operator-
provided tools whose upstream installation channel cannot be pinned safely.

## Acquire source

Use a dedicated source directory. Do not clone into `~/.plamen`: that path is
reserved for the authenticated installed package.

Linux:

```bash
git clone --recurse-submodules https://github.com/PlamenTSV/plamen.git "$HOME/plamen-source"
cd "$HOME/plamen-source"
```

Windows PowerShell:

```powershell
git clone --recurse-submodules https://github.com/PlamenTSV/plamen.git "$HOME\plamen-source"
Set-Location "$HOME\plamen-source"
```

If you cloned without submodules, run this in the source checkout before
installing:

```bash
git submodule update --init --recursive
```

A Git ZIP is not an equivalent source bundle because it omits submodule
content. Never overwrite an existing source or installed directory to repair
an incomplete download.

## Install

Linux:

```bash
python3.12 plamen.py install
```

Windows PowerShell, with `python` resolving to CPython 3.12:

```powershell
python plamen.py install
```

The installer first validates the exact governed 764-row source closure. It
then performs a transactional publication to `~/.plamen`, commits an
authenticated installation receipt, creates the private Python runtime,
materializes managed Node/npm and both backends, and publishes the signed
current runtime selection. A failed or interrupted transaction cannot become
current.

The source directory is only installation input. The installed package is a
governed copy, not a symlink or junction back to a mutable checkout. Likewise,
the user-facing command in `~/.local/bin` is wired to the authenticated
installed front. Do not manually link, copy, or edit either location.

One install handles Claude and Codex. A separate `plamen install --codex`,
global npm install, or backend-specific updater is not part of normal setup.

## First-install cost

The initial install can take several minutes. It may download and verify the
managed Node archive, run exact managed `npm ci`, seal the generation census,
probe both locked backend versions, and build the private Python environment.
No ambient `node`, `npm`, `npx`, npm wrapper, Claude, or Codex executable is
used.

This is a materialization cost, not an audit-start cost. Normal `plamen`
launches authenticate the committed receipt and signed current selection and
validate the bounded native resource closure for the chosen backend.

## PATH

The installed front is:

- Linux: `~/.local/bin/plamen`
- Windows: `%USERPROFILE%\.local\bin\plamen.cmd`

Add `~/.local/bin` to PATH with your normal shell or operating-system settings
if it is not already present. Do not add the source directory or `~/.plamen`
itself to PATH.

## Verify

Open a fresh terminal after changing PATH and run:

```bash
plamen help
plamen doctor
plamen plan core /path/to/project --claude
plamen plan core /path/to/project --codex
```

Doctor and plan are read-only and make zero provider calls. Doctor checks the
package receipt, private Python runtime, managed Node/npm generation, exact
backend selection, and relevant containment capability. It does not consult
or require global Node/npm/npx/Claude/Codex tools.

Then run the optional interactive toolchain setup from a real terminal:

```bash
plamen setup
```

## Optional vulnerability index

Build the local vulnerability database only if you want the optional RAG
corpus and have the required memory and disk capacity:

```bash
plamen rag
```

Some sources require `SOLODIT_API_KEY`; keep it in the documented provider
environment configuration, not in source, receipts, or generated commands.

MCP is not required for general audit execution. Plamen exposes the
receipt-bound `unified-vuln-db` only to Claude-headless `rag_sweep` on a host
where containment is admitted. Windows uses a Job object; Linux uses the
delegated cgroup v2 plus Landlock path when supported. Unsupported Linux hosts
deny MCP before spawn and use the governed Web/local fallback. Claude PTY
workers and all Codex audit subprocesses use no MCP servers. See
[mcp-servers.md](mcp-servers.md).

## Run an audit

```bash
plamen
plamen core /path/to/project --claude
plamen core /path/to/project --codex
plamen l1 core /path/to/node-client --claude
```

The interactive wizard is the easiest way to select smart-contract or L1
mode, audit depth, scope, documentation, and backend. Both backends are
available through the governed package on supported production hosts. macOS
source-development support does not imply that either backend can run a native
Mac audit.

## Permissions and project writes

Plamen writes audit artifacts only inside the selected project's
`.scratchpad` workspace and writes the completed `AUDIT_REPORT.md` at the
project root. Provider subprocesses receive phase-specific permissions and
artifact ownership. Review the target path shown by `plamen plan` before
starting an unattended audit.

## Update

Acquire the new complete source release separately and run its
`plamen.py install`. Never `git pull` inside `~/.plamen`, replace the installed
tree with a checkout, or use npm to update a backend. See
[updating.md](updating.md) for the authenticated update and recovery model.
