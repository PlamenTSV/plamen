# Updating Plamen

Plamen upgrades are authenticated install transactions. The installed tree at
`~/.plamen` is not a Git checkout, npm prefix, or editable development tree.
Do not run `git pull`, npm, or an editor inside it.

## Safe update procedure

Acquire the release in a separate source directory, including its submodules,
then run the installer from that source.

Linux:

```bash
git clone --recurse-submodules https://github.com/PlamenTSV/plamen.git "$HOME/plamen-source-next"
cd "$HOME/plamen-source-next"
python3.12 plamen.py install
```

Windows PowerShell:

```powershell
git clone --recurse-submodules https://github.com/PlamenTSV/plamen.git "$HOME\plamen-source-next"
Set-Location "$HOME\plamen-source-next"
python plamen.py install
```

macOS currently has a separate source-development workflow. Do not run the
governed production installer or treat a development bootstrap as an update to
an audit runtime. Update the `Plamen-v3` source checkout with normal reviewed
Git operations, then rerun `scripts/bootstrap_macos_dev.sh`; see the
[macOS development guide](development/macos.md) and
[machine-migration guide](development/machine-migration.md). Native or
governed-host audit support remains an open exit criterion in the
[Plamen-v3 continuation goal](continuation/GOAL.md).

An existing trusted source checkout may be updated according to your normal
source-control policy, but `plamen.py install` must still be run from the
complete reviewed result. Never point Git at `~/.plamen` and never replace
the installed package by copying or linking a checkout over it.

## What the installer authenticates

Before changing live state, `plamen install` validates the exact governed
764-row source closure. It then publishes the new package transactionally and
commits a receipt that binds the installed package, managed runtime, adapter,
and model-runtime projection. An interrupted transaction is recovered or
rejected; a partially published package is not accepted as current.

The same transaction manages:

- a private, hash-locked CPython 3.12 dependency environment;
- the reviewed Node.js 24.20.0 archive and complete npm 11.19.0 closure;
- immutable Claude Code 2.1.252 and Codex 0.152.0 backend payloads;
- a signed current selection binding generation, receipt, census, request,
  policy, executable resource closures, and permitted MCP launches;
- the authenticated `plamen` command front and backend integration files.

There is no separate global Claude/Codex upgrade and no supported `npm -g`
path. Do not run `plamen install --codex` as a second update step: the governed
install carries both backends together.

## Materialization cost and normal launches

The first install, or an update that changes a locked runtime, may download
and extract the reviewed Node archive and run managed `npm ci`. That one-time
materialization can take several minutes. Plamen never executes ambient
`node`, `npm`, `npx`, or npm shell wrappers for this work.

Normal audit launches do not repeat installation. They authenticate the
committed receipt and signed current selection, then validate the bounded
native resource closure for the selected backend. This keeps launches fast
while rejecting stale, missing, replaced, or partially updated generations.

## Verification

After an update, open a fresh terminal and run:

```bash
plamen doctor
plamen plan core /path/to/project --claude
plamen plan core /path/to/project --codex
```

`plamen doctor` and `plamen plan` are read-only and make zero provider calls.
Doctor validates the authenticated installed state and private runtimes; it
does not depend on, repair from, or report success because of ambient
Node/npm/npx/Claude/Codex tools.

## MCP behavior after an update

MCP configuration is not a mutable set of package paths. On a supported
Claude-headless RAG route, Plamen admits only the server launch recorded in
the signed current selection and revalidates its generation under a held
lock. Claude PTY and all Codex audit subprocesses run without MCP servers.

Windows uses Job-object descendant containment. Linux uses the delegated
cgroup v2 and Landlock route when the host supports the required policy.
Unsupported Linux hosts fail closed before MCP spawn and use the governed
Web/local research fallback. On macOS, the earlier package-transaction and
worker-containment gates currently block production audits entirely; the MCP
fallback does not make native Mac E2E execution supported.

## Rollback and recovery

Do not manually swap directories, rewrite receipts, or repoint command
symlinks. Re-run `plamen.py install` from the last trusted complete source if
you need to return to that release. The installer owns recovery of interrupted
transactions and will refuse foreign or unauthenticated state.

Your projects, `.scratchpad` audit workspaces, reports, API keys, and
operator-installed chain toolchains are outside the installed package
transaction and are not removed by an ordinary update.
