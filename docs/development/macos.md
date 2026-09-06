# macOS source development

Plamen-v3 supports an isolated **source-development environment** on macOS
arm64 and x86_64. It does not yet support installing or running the native
macOS audit runtime. The bootstrap in this document never calls
`plamen.py install`, never writes into `~/.plamen`, and never claims that a
provider or E2E audit completed.

## Current support boundary

| Capability | arm64 | x86_64 | Status |
|---|---:|---:|---|
| Clone and edit the source checkout | Yes | Yes | Supported |
| Hash-locked development venv | Yes | Yes | Supported when every reviewed wheel is available |
| Dependency-authority and focused source checks | Yes | Yes | Supported |
| Managed Node/backend package definitions | Present | Present | Source validation only |
| `plamen.py install` | No | No | Windows-native install transaction blocks Darwin |
| Codex E2E audit | No | No | Transaction-grade process/write authority is unavailable |
| Claude headless E2E audit | No | No | Same authority gap; default stored subscription also lacks Keychain materialization |
| Claude PTY | Partial legacy code | Partial legacy code | Not a release-qualified macOS E2E lane |

An explicit environment OAuth token can avoid the current Claude Keychain
materialization gap, but it does not fix process containment or make E2E audits
supported.

## Prerequisites

- macOS on Apple Silicon (`arm64`) or Intel/Rosetta (`x86_64`)
- Xcode Command Line Tools: `xcode-select --install`
- Git
- CPython 3.12 exactly, from a reviewed organizational or python.org channel
- Network access to clone pinned submodules and obtain hash-verified Python
  wheels

Do not install development source under `~/.plamen`, `~/.codex/plamen`, or
`~/.claude`. Those are installed/backend authority locations, not Git working
trees.

## Fresh checkout

```sh
mkdir -p "$HOME/src"
git clone \
  --branch Plamen-v3 \
  --recurse-submodules \
  https://github.com/PlamenTSV/plamen.git \
  "$HOME/src/plamen"
cd "$HOME/src/plamen"
git submodule status --recursive
```

Run the development bootstrap with the exact Python interpreter:

```sh
sh scripts/bootstrap_macos_dev.sh --python "$(command -v python3.12)"
```

The default venv is `.venv-dev`. To keep it elsewhere:

```sh
sh scripts/bootstrap_macos_dev.sh \
  --python "$(command -v python3.12)" \
  --venv "$HOME/.local/share/plamen-dev/venv"
```

The bootstrap is idempotent. It:

1. admits only Darwin `arm64` or `x86_64` and CPython 3.12;
2. refuses a checkout inside an installed/backend directory;
3. synchronizes the repository's pinned Git submodules;
4. runs the isolated deterministic dependency-authority gate;
5. creates or reuses a development-only venv;
6. installs `requirements-ci.lock` with `--require-hashes` and
   `--only-binary=:all:`; and
7. compiles the main source files and runs focused POSIX/bootstrap tests.

It never removes an incompatible existing venv. Move that directory aside
yourself after reviewing its path, then rerun the bootstrap.

For the slower static portability checks:

```sh
sh scripts/bootstrap_macos_dev.sh --extended-validation
```

## Continue development

```sh
cd "$HOME/src/plamen"
. .venv-dev/bin/activate
python -I scripts/ci_dependency_authority.py static --root .
python -m pytest -q -p no:cacheprovider scripts/test_bootstrap_macos_dev.py
git diff --check
git submodule status --recursive
```

The full unit/integration matrix includes intentional production-runtime
fail-closed behavior. It is a release gate, not evidence that the present
Darwin runtime is supported. Run it while implementing the continuation goal,
and resolve failures instead of weakening them into skips:

```sh
(cd scripts && python -m pytest -m "not integration" -n auto -q)
(cd scripts && python -m pytest -m "integration" -q)
```

## Honest native-audit check

Automation that requires a working native audit runtime must ask explicitly:

```sh
sh scripts/bootstrap_macos_dev.sh --require-native-audit
```

This currently exits with status `3` before creating or changing the venv.
That behavior prevents a source-development success from being mistaken for
an install or E2E audit success.

Do not bypass the supply-chain gate, weaken process-scope checks to ordinary
process groups, copy a Windows install into the Mac home directory, or use the
old direct/symlink installer as a Darwin fallback.

## Route to supported macOS audits

The remaining work is part of the canonical
[Plamen-v3 continuation goal](../continuation/GOAL.md). A release-qualified
implementation must complete all of these before this document can mark native
audits supported:

1. A Darwin install transaction with no-follow path operations, retained
   single-writer authority, atomic publication, directory durability, and
   crash recovery equivalent to the supported platforms.
2. A truthful worker executor with exhaustive descendant termination and
   transaction-scoped write authority. A process group alone is insufficient.
3. A decision and implementation for either native Darwin containment or a
   governed Linux VM/container audit host with read-only source mounts,
   scratch-only writes, bounded lifecycle, and durable execution receipts.
4. Claude macOS stored-subscription Keychain observation/materialization, plus
   separate tests for stored subscription and explicit OAuth-token routes.
5. Documented, reproducible, governed offline advisory-data preparation for the
   fail-closed supply-chain gate.
6. Clean-home installation, `doctor`, provider-free `plan`, and credentialed
   tiny-fixture E2E audits for both Codex and Claude on every supported Mac
   architecture, with complete phase/report receipts.

Until those exit criteria pass, use macOS for source work and an existing
supported Windows/Linux host for real audits.
