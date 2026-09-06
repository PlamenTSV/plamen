---
name: plamen
description: "Launch the Plamen deterministic Web3 security audit pipeline"
---

# Plamen V3.0.0 Wizard Launcher For Codex

Use this skill whenever the user invokes `$plamen`, `/plamen`, asks to
start, resume, or configure a Plamen audit, or asks for the Plamen wizard
inside Codex.

## Hard Rule

Do not manually orchestrate Plamen phases. Do not spawn recon, breadth,
depth, verification, or report agents yourself. The Python driver is the
sole owner of phase sequencing for both Claude and Codex routes.

Your job is the same job as the Claude `/plamen` command wizard:

1. Detect an existing audit and offer resume/fresh/new.
2. Collect missing launch parameters.
3. Write or reuse `{PROJECT_ROOT}/.scratchpad/config.json`.
4. Launch the deterministic driver.
5. Report the resume command and basic status.

For new Codex launches, `config.json` must set `"cli_backend": "codex"`.
For existing audits, do not rewrite the config on resume.

## Wizard Files

Follow the Codex-native wizard references in this skill directory:

- Smart-contract audits: `plamen-wizard.md`
- L1 infrastructure audits: `plamen-l1-wizard.md`

Read only the relevant file:

- If the user says `l1`, `L1`, `infra`, `client`, `go`, `rust node`, or
  the target looks like a chain/client codebase, use `plamen-l1-wizard.md`.
- Otherwise use `plamen-wizard.md`.

## Invocation Syntax

```text
$plamen [l1] [light|core|thorough] [path] [docs:<path-or-url>] [scope:<path>] [notes:<text>]
$plamen resume [path-or-config]
```

Defaults:

- `pipeline`: `sc`
- `mode`: `core`
- `project_root`: current working directory
- `cli_backend`: `codex`

Do not ask a model-selection question from this skill. The user is already
running inside the model/backend they chose.

## Driver Commands

Codex route:

```
plamen resume "{CONFIG_PATH}"
```

New run (only with a new config pointing at a distinct clean destination;
never reuse or modify an existing run root):

```
plamen start-config "{NEW_CONFIG_PATH}"
```

These public commands are mandatory: the installer-generated `plamen`
launcher supplies the locked Python/tool runtime. Never invoke the installed
driver with ambient `python`.
