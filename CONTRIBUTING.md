# Contributing to Plamen

Thank you for contributing to Plamen. This guide covers source development;
production installation is a separate authenticated publication process.

## How Plamen works

Plamen is a multi-agent security-audit pipeline for Claude Code and OpenAI
Codex CLI. Its main source areas are:

- `rules/`: phase definitions, scoring models, and report templates;
- `prompts/{evm,solana,aptos,sui,soroban,daml}/` and `prompts/l1/`:
  ecosystem-specific prompts and templates;
- `agents/skills/`: methodology files read by agents at audit time;
- `agents/depth-*.md`: depth-agent role definitions;
- `custom-mcp/`: RAG and static-analysis tool servers;
- `scripts/`: the V2 driver, parsers, validators, and deterministic gates;
- `agents/skills/injectable/l1/`: L1 infrastructure methodology;
- `codex-adapter/`: Codex-specific commands and adaptations; and
- `plamen.py`: the terminal front and production installer.

## Ways to contribute

### Skills

Skills teach agents how to analyze a vulnerability class. Regular skills live
under `agents/skills/{language}/{skill-name}/`; injectable skills live under
`agents/skills/injectable/`; niche skills live under `agents/skills/niche/`.

A skill should:

- teach methodology (how to look), not a list of expected answers;
- state precise activation conditions;
- include an execution checklist and common false positives;
- remain under the applicable file-size cap; and
- be tested on at least one relevant codebase on a supported audit host.

### Scanner checks

Scanner templates live at
`prompts/{language}/phase4b-scanner-templates.md`. Checks should be broadly
applicable, concise, and have a low false-positive rate.

### Bugs and infrastructure

Bug reports should include the mode, ecosystem, observed failure, and
sanitized scratchpad evidence when possible. Contributions are also welcome
for the CLI, deterministic driver, verification gates, Codex adaptation, MCP
servers, and L1 methodology.

Never attach provider credentials, API keys, OAuth material, private target
source, or an unreviewed scratchpad.

## Development setup

### Prerequisites

- CPython 3.12 exactly;
- Git with submodule support; and
- a source checkout outside `~/.plamen`, `~/.codex/plamen`, and `~/.claude`.

The governed production package owns its reviewed Node, npm, Claude, and Codex
payloads. Do not install global copies merely to develop Plamen. Provider-backed
integration tests may require separately authenticated provider tooling, but
source-level development and the default checks do not.

### macOS source development

Native macOS production installation and E2E auditing are not yet supported.
The Darwin package transaction and worker-containment paths fail closed. Both
arm64 and x86_64 Macs can use the isolated source-development bootstrap:

```bash
git clone --branch Plamen-v3 --recurse-submodules \
  https://github.com/PlamenTSV/plamen.git "$HOME/src/plamen"
cd "$HOME/src/plamen"
sh scripts/bootstrap_macos_dev.sh --python "$(command -v python3.12)"
. .venv-dev/bin/activate
```

This creates a development environment, not an installed audit runtime. Read
the [macOS development guide](docs/development/macos.md), the
[machine-migration guide](docs/development/machine-migration.md), and the
[Plamen-v3 continuation goal](docs/continuation/GOAL.md) before changing the
Darwin support boundary.

### Windows and Linux source development

Clone with submodules into an ordinary development directory, create a
CPython 3.12 virtual environment, and install the reviewed CI closure.

Linux:

```bash
git clone --branch Plamen-v3 --recurse-submodules \
  https://github.com/PlamenTSV/plamen.git "$HOME/src/plamen"
cd "$HOME/src/plamen"
python3.12 -m venv .venv-dev
. .venv-dev/bin/activate
python -m pip install --require-hashes --only-binary=:all: -r requirements-ci.lock
python -I scripts/ci_dependency_authority.py static --root .
```

Windows PowerShell:

```powershell
git clone --branch Plamen-v3 --recurse-submodules https://github.com/PlamenTSV/plamen.git "$HOME\src\plamen"
Set-Location "$HOME\src\plamen"
py -3.12 -m venv .venv-dev
.\.venv-dev\Scripts\Activate.ps1
python -m pip install --require-hashes --only-binary=:all: -r requirements-ci.lock
python -I scripts/ci_dependency_authority.py static --root .
```

Do not use `plamen.py install` to create a development environment. A
production install is an authenticated publication from reviewed source, not
an editable checkout; see [docs/setup.md](docs/setup.md). The current governed
source closure contains 764 rows and publishes Claude and Codex together.

## Testing changes

Begin with the dependency authority, relevant focused tests, and repository
hygiene:

```bash
python -I scripts/ci_dependency_authority.py static --root .
python -m pytest -q -p no:cacheprovider scripts/test_bootstrap_macos_dev.py
git diff --check
git submodule status --recursive
```

- Skills: on a supported audit host, run a Core audit on a relevant fixture
  and inspect the assigned scratchpad artifact.
- Scanner checks: on a supported audit host, run a Core audit and inspect the
  blind-spot scanner artifact for the new check ID.
- Driver and wrapper changes: run the directly relevant unit/integration lanes
  plus provider-free `plan` validation where available.
- macOS changes: run the bootstrap and portability tests on both intended
  architectures. Do not represent bootstrap success, a skip, or source-only
  validation as a completed E2E audit.

Do not weaken a fail-closed platform or supply-chain gate merely to make a test
green. Update support claims only with the implementation and release evidence
required by the continuation goal.

## Pull requests

1. Fork the repository.
2. Create a focused branch from the intended base.
3. Make and test the change.
4. Review the full diff for generated files, absolute paths, and secrets.
5. Open a pull request explaining why the change improves audit quality or
   reliability and what evidence validates it.

Every pull request must confirm:

- new methodology follows the applicable size caps and format;
- no credentials, private source, or generated audit artifacts are included;
- changed triggers, roles, and artifact contracts remain coherent;
- relevant deterministic and E2E tests were run, with unsupported/skipped
  lanes stated honestly; and
- documentation matches the real backend and platform boundary.

## DCO

By contributing, you certify that the contribution is your own work and that
you may submit it under the MIT license. Sign off commits:

```bash
git commit -s -m "Describe the change"
```

## File-size caps

| File category | Cap |
|---|---:|
| Individual skills | 300 lines |
| Scanner templates | 600 lines |
| Depth templates | 250 lines |
| Generic security rules | 1000 lines |
| Recon prompt | 1100 lines |

Questions are welcome in GitHub Discussions or an issue tagged `question`.
