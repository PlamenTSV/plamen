# Automated Setup — Paste This Into Claude Code or Codex

> For users who want an AI assistant to perform the non-interactive install.
> Copy everything below the line into a Claude Code or Codex session. The
> assistant must stop on any failed check. It must not start an audit, build
> the optional RAG index, or run the interactive toolchain wizard.
>
> **macOS boundary:** the governed production installer and native audit
> runtime are not yet supported on Darwin. On a Mac, do not run the production
> steps below. Use the development-only procedure in
> [`docs/development/macos.md`](docs/development/macos.md), which invokes
> `scripts/bootstrap_macos_dev.sh` and deliberately does not install or launch
> Plamen. For a machine switch, also follow
> [`docs/development/machine-migration.md`](docs/development/machine-migration.md).
> The remaining work is tracked in
> [`docs/continuation/GOAL.md`](docs/continuation/GOAL.md).

---

Please install Plamen (Web3 Security Auditor) on my machine. Follow these
steps in order. Report an error and stop if any command fails.

## 1. Check the only ambient prerequisites

```bash
python3.12 --version 2>/dev/null || python --version
git --version
```

Plamen requires CPython 3.12 and Git. Do not install or probe ambient Node,
npm, npx, Claude Code, or Codex packages. The governed installer acquires and
authenticates its own Node.js 24.20.0/npm 11.19.0 runtime and its own exact
Claude Code 2.1.252 and Codex 0.152.0 backends. Never run `npm install -g`.

If Python 3.12 or Git is absent, stop and ask the user to install it through
their operating-system policy. Do not make system-level changes yourself.

## 2. Acquire a complete source tree

Clone into a dedicated source directory, not `~/.plamen`. `~/.plamen` is the
authenticated installed package and must not be a mutable Git checkout.

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

If that source directory already exists, do not overwrite or delete it. Ask
the user which trusted source directory to use. A Git archive/ZIP is not an
equivalent source because it omits submodule content.

## 3. Run the governed install

Linux:

```bash
python3.12 plamen.py install
```

Windows PowerShell (where `python` resolves to CPython 3.12):

```powershell
python plamen.py install
```

This one command installs both supported model backends. It validates the
exact governed 764-row source closure before publishing a transactional,
authenticated package at `~/.plamen`; creates the installed `plamen` front in
`~/.local/bin`; builds the private hash-locked Python runtime; and
materializes the reviewed Node/npm and backend generation. It also publishes
a signed current selection binding the immutable Claude and Codex executables
and receipt-bound MCP launch data.

The first install, or an install that changes the lock, can take several
minutes because it downloads and verifies Node and npm packages. This is a
one-time materialization cost. Normal `plamen` launches validate the signed
selection and bounded executable closure and are fast.

Do not run `plamen install --codex` as a second installation step, manually
link the source tree into `~/.plamen`, or edit the installed package. Do not
treat any integrity, receipt, materialization, or projection warning as
non-critical.

## 4. Ensure the installed front is on PATH

The installer writes `~/.local/bin/plamen` on Linux and
`%USERPROFILE%\.local\bin\plamen.cmd` on Windows. If `~/.local/bin` is not
already on PATH, add only that directory using the user's normal shell or OS
settings. Do not add the source directory or `~/.plamen` to PATH.

## 5. Verify without invoking ambient tools

Open a fresh terminal if PATH changed, then run:

```bash
plamen help
plamen doctor
```

`plamen doctor` is read-only and makes no provider calls. It authenticates
the installed receipt, private runtimes, immutable generation, and current
selection; it must not depend on global Node/npm/npx/Claude/Codex commands.

Do not run `plamen setup` or bare `plamen` from this AI session. Those are
interactive terminal wizards. Tell the user to run `plamen setup` in a real
terminal for optional chain toolchains and bare `plamen` to start an audit.

Do not run `plamen rag` here. It is an optional, resource-intensive index
build that the user can start later. Production audits remain supported on
Windows and admitted Linux hosts with either Claude or Codex. Contained MCP
RAG is used only on supported Claude-headless routes; all other supported
routes use governed Web/local fallbacks.

## Done

Report the source directory and confirm that the authenticated installed
package is at `~/.plamen` and the command front is in `~/.local/bin`. Remind
the user that every future upgrade must be applied from reviewed source by
running `plamen.py install`; never update the installed tree with `git pull`
or npm.
