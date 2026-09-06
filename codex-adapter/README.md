# Plamen Codex Adapter

This directory contains Codex-compatible configuration files generated from the
Plamen audit pipeline's Claude-side manifests. These files allow Plamen to run
inside the [Codex CLI](https://github.com/openai/codex) in addition to Claude Code.

## Installation

```bash
# From a complete reviewed Plamen source directory:
python3.12 plamen.py install --codex   # macOS/Linux
python plamen.py install --codex       # Windows
```

The installer:
1. Validates the complete source closure before any install mutation.
2. Transactionally publishes the signed COMMITTED package at `~/.plamen/`.
3. Materializes managed Node.js 24.20.0/npm 11.19.0 and exact Claude Code
   2.1.252/Codex 0.152.0 payloads.
4. Transactionally copies the receipt-bound Codex files (`AGENTS.md`, role
   TOMLs, skills, and commands) into `~/.codex/` and merges the managed config.

The source checkout is installation input only. `~/.plamen/` is not a Git
checkout, and Codex must never be pointed back at mutable source bytes.

## Usage

After installation, open the Codex CLI and use the Plamen skill:

```bash
plamen-codex
# Then inside Codex:
/plamen core /path/to/project
/plamen thorough /path/to/project --docs /path/to/whitepaper.pdf
```

## Architecture

### Shared committed runtime

The Plamen methodology and driver runtime live in the authenticated package at
`~/.plamen/`. Public launchers and installed adapter configuration are bound to
that committed generation; they do not trust the source checkout. This includes:

- `prompts/` -- language-specific phase prompts (recon, inventory, depth, verification)
- `agents/` -- depth agent definitions and skill files
- `rules/` -- finding format, confidence scoring, chain analysis, report templates
- `custom-mcp/` -- MCP server source code

### What is Codex-specific (in this source directory)

- `AGENTS.md` -- Condensed orchestrator rules (under 32KB for Codex context)
- `config.toml` -- Codex main config with model, MCP server mappings
- `agents/*.toml` -- Role TOML files for each agent type
- `skills/plamen/SKILL.md` -- The `/plamen` orchestrator skill for Codex

### Regenerating source assets

Maintainers who update Claude-side files, agent definitions, or adapter
templates may regenerate the source assets below. This does not install them;
run the governed installer afterward so the changed closure is validated and
committed:

```bash
python scripts/codex_adapter.py
python3.12 plamen.py install --codex
```

## Current Limitations

- **Model**: On ChatGPT-authenticated Codex, use an entitled base model
  (`gpt-5.6-sol` for the opus tier, `gpt-5.6-terra` for sonnet, `gpt-5.6-luna` for haiku;
  see `_CODEX_MODEL_MAP` in `scripts/plamen_types.py`). `-codex`/preview
  suffixes such as `gpt-5.3-codex` are rejected on ChatGPT accounts. Codex
  context is smaller than Claude Code's Opus (1M context), so Thorough mode may
  require more careful context management.
- **MCP policy**: Codex audit subprocesses intentionally load no MCP servers;
  phases use governed local tools and Web precedent-research fallbacks. The
  managed user config may contain MCP entries, but audit launch isolation is
  authoritative.
- **Platform**: The governed installer and public launchers support Windows,
  Linux, and macOS. Do not hand-edit generated paths to work around an install
  failure; use `plamen doctor` and reinstall from reviewed source.
