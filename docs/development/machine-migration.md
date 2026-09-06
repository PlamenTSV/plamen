# Move Plamen-v3 development to a Mac

Move the canonical Git source, not the installed runtime or the machine's
working directories. Install receipts, native launchers, managed runtimes,
backend credentials, and in-progress audit scratchpads are host-bound state.

## What to transfer

- the pushed `Plamen-v3` branch and its exact commit;
- committed Git submodule links;
- reviewed source, methodology, tests, locks, documentation, and continuation
  goal files in that branch; and
- separately archived final audit reports or exported evidence that must be
  retained for reference.

Record the source identity on the old machine:

```sh
git status --short --branch
git rev-parse HEAD
git submodule status --recursive
git diff --check
```

Commit and push only reviewed source. Do not treat a zip of the user profile or
drive as a source migration.

## What not to transfer

Do not copy or commit:

- `~/.plamen` or `~/.codex/plamen`;
- `~/.local/share/plamen` managed Python, Node, npm, MCP, or backend
  generations;
- `~/.codex/auth.json`, `~/.claude`, API keys, OAuth tokens, keychain exports,
  settings containing secrets, or shell-history files;
- `.venv-dev`, `__pycache__`, pytest caches, installer receipts, transaction
  journals, junctions, symlinks materialized for the old machine, or absolute
  path manifests;
- `.scratchpad` directories from active Windows audits; or
- test/run debris such as `Temp/`, `.pytest_*`, `bpa_*`, `bpc_*`,
  `diag-recon-*`, and accidental marker-output files.

The RunBundle tooling exports and verifies evidence; it does not import an
active run into the driver. Therefore an in-progress Windows scratchpad is not
a supported Mac resume mechanism.

## Stop point on the old machine

Before switching machines:

1. Let any audit that must be preserved reach a stable terminal state, or stop
   it and retain the old host for later resumption.
2. Preserve its final report/export separately from the Plamen source branch.
3. Review every untracked path before staging. Generated output is excluded by
   default; only deliberately reviewed source enters `Plamen-v3`.
4. Push the branch and record its commit and submodule identities.

Do not delete the old machine's state merely because the Git push succeeded.
Keep it until the branch has been cloned and validated on the Mac.

## Bootstrap the Mac

Install Xcode Command Line Tools and a reviewed CPython 3.12, then clone outside
the reserved runtime directories:

```sh
xcode-select --install
mkdir -p "$HOME/src"
git clone \
  --branch Plamen-v3 \
  --recurse-submodules \
  https://github.com/PlamenTSV/plamen.git \
  "$HOME/src/plamen"
cd "$HOME/src/plamen"
```

Verify that the clone is the intended source generation:

```sh
test "$(git rev-parse HEAD)" = "REPLACE_WITH_RECORDED_COMMIT"
git submodule status --recursive
git status --short --branch
```

Create the isolated source-development environment:

```sh
sh scripts/bootstrap_macos_dev.sh --python "$(command -v python3.12)"
. .venv-dev/bin/activate
```

Authenticate Git and the provider CLIs afresh only when needed. Never put
provider credentials in the repository or migration archive.

## Current continuation boundary

The successful bootstrap means that source development and its focused checks
work. It does **not** mean that `plamen.py install`, Codex audits, Claude
headless audits, or full native Mac E2E execution work.

The canonical next work is recorded in
[the Plamen-v3 continuation goal](../continuation/GOAL.md). It owns the choice
between a proof-grade native Darwin executor and a governed Linux VM/container
executor, along with the Darwin installer, Claude Keychain route, offline
advisory bootstrap, and dual-backend E2E acceptance.

Until that goal's macOS exit criteria pass:

- develop and run source-level tests on the Mac;
- run real audits on the retained supported Windows host;
- do not pass `PLAMEN_SKIP_SUPPLY_CHAIN_GATE=1` as a portability workaround;
- do not weaken process/write authority checks; and
- do not restore the legacy direct/symlink installer for Darwin.

To make automation prove this boundary rather than infer it:

```sh
sh scripts/bootstrap_macos_dev.sh --require-native-audit
```

It must fail with status `3` in the current generation. Change that contract
only together with the continuation goal's implementation and E2E evidence.
