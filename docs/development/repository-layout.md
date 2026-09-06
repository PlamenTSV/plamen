# Repository Layout and Source Boundaries

This repository is the canonical, reviewable source for Plamen. A source
checkout is intentionally separate from the installed package, managed
runtimes, backend configuration, and audit output. Keeping those boundaries
explicit makes a clean clone reproducible and prevents machine-local state from
silently becoming part of a release.

## Canonical source tree

The branch root is the repository root. Do not add another `Plamen-v3/`
directory around the project and do not mirror an installed home into this
tree.

| Path | Responsibility |
| --- | --- |
| `.github/` | Continuous-integration and release workflows. |
| `agents/` | Backend-neutral agent definitions and ecosystem skills. |
| `codex-adapter/` | Codex roles, commands, skills, and source configuration. |
| `commands/` | User-facing Plamen command methodology. |
| `custom-mcp/` | MCP server source maintained or integrated by Plamen. |
| `methodology/` | Machine-readable methodology assets. |
| `opengrep-rules/` | Pinned external rule-pack submodules. |
| `prompts/` | Shared and ecosystem-specific phase prompts. |
| `rules/` | Normative audit rules, schemas, registries, and report contracts. |
| `scripts/` | Driver, validators, deterministic machinery, platform adapters, and tests. |
| `verification_policy/` | Machine-readable verification and toolchain policy. |
| `tests/` | Tests that do not live beside the script they exercise. |
| `docs/` | User, operator, architecture, development, and historical documentation. |
| `requirements*.in`, `requirements*.lock` | Reviewed Python dependency intent and resolved locks. |
| `plamen.py` and launchers | Checkout-local installation entry points. |

New production behavior belongs in these owned directories. A temporary
workspace, copied checkout, audit report, or generated receipt must not become a
second source of truth.

## Authority rules

1. The checked-in branch, including its pinned submodule commits, is the source
   authority.
2. Current executable code, machine-readable policy, methodology, and tests
   take precedence over narrative history.
3. Generated installed files are projections of a reviewed commit. They are
   never edited to implement a change and never copied back over source.
4. A change is complete only when its source, tests, documentation, and any
   governed manifests agree in the same commit.
5. Historical research under `docs/history/research/` is explicitly
   non-normative. It cannot override current code, prompts, rules, schemas, or
   release gates.

If two source checkouts contain different uncommitted work, reconcile them by
reviewed diff and tests. Modification time, installation success, or the fact
that one copy is used by a live audit does not make that copy authoritative.

## Source, installation, runtime, and audit state

These are separate classes of data:

| Class | Typical location | Mutability and retention |
| --- | --- | --- |
| Source checkout | A dedicated Git clone chosen by the developer | Mutable through reviewed Git changes. |
| Installed package | `~/.plamen` | Installer-owned and receipt-bound; treat as immutable. |
| Command front | `~/.local/bin/plamen` | Installer-owned; do not hand-edit or point it at a development tree. |
| Managed runtimes | `~/.local/share/plamen` | Generated and replaceable from governed inputs; never commit. |
| Backend integration | Installer-managed files beneath backend homes | Generated from `codex-adapter/` or other repository assets; do not use as source. |
| Audit scratch | The audited project's `.scratchpad/` or configured external scratch root | Run-specific evidence; archive separately when required and never add to this repository. |
| Test scratch and caches | Temporary directories, `.pytest_cache/`, `__pycache__/`, coverage output | Disposable and ignored. |

Audit configuration can contain target paths, provider choices, or other local
details. Keep it with the run, not in the Plamen source repository. Reports and
run bundles are audit deliverables, not tool source. A useful regression derived
from a run must be minimized, sanitized, and promoted into an owned test or
fixture before it is committed.

## Submodules

The repository pins five external repositories through `.gitmodules`:

- `custom-mcp/farofino-mcp`
- `custom-mcp/slither-mcp`
- `opengrep-rules/aptos-move-rules`
- `opengrep-rules/decurity-rules`
- `opengrep-rules/opengrep-rules`

The superproject commit records the permitted commit for each submodule. Do not
replace a submodule with a copied directory. Do not publish from a dirty
submodule or advance a pin without reviewing the upstream change and recording
the new gitlink in the superproject.

This command should show one clean, initialized commit per submodule:

```bash
git submodule status --recursive
```

A leading `-`, `+`, or `U` means the checkout is incomplete, at a different
commit, or conflicted. Resolve that state before installation validation or a
release.

## Clean-clone workflow

Use a new directory rather than reusing an installed package or an older source
tree. For the V3 development branch on macOS or Linux:

```bash
git clone --branch Plamen-v3 --single-branch --recurse-submodules \
  https://github.com/PlamenTSV/plamen.git "$HOME/plamen-source"
cd "$HOME/plamen-source"
git status --short
git submodule status --recursive
python3.12 plamen.py install
~/.local/bin/plamen doctor
```

`git status --short` must be empty before local development begins. Clone with
Git rather than a source ZIP because Git archives do not include submodule
content. Do not clone into `~/.plamen`; that name is reserved for the governed
installed package.

For an isolated development/test environment:

```bash
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m pip install -r requirements-dev.txt
python -m pytest
```

The developer environment is distinct from the private runtime created by
`plamen.py install`. Passing tests in the developer environment does not replace
the clean-clone install and `plamen doctor` checks.

## Repository hygiene

Before committing or publishing, verify that the change set contains no audit
scratchpads, private targets, provider credentials, session material, caches,
generated runtimes, copied Git repositories, or absolute host paths. Large
fixtures must be deterministic, minimal, license-compatible, and genuinely
required by tests. Preserve raw run evidence outside the source repository and
record only a sanitized regression plus provenance where it adds lasting value.
