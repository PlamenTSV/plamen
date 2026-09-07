# Plamen Documentation

Index of the Plamen docs. New here? Start with **Getting Started**, then pick by
topic. The project [README](../README.md) and the AI-assistant install guide
[SETUP.md](../SETUP.md) live in the repo root.

## Start here

| Doc | What it covers |
|-----|----------------|
| [getting-started.md](getting-started.md) | What install did, what you actually need, running your first audit, where your report lands |
| [glossary.md](glossary.md) | Plamen-specific terminology (pipeline, workers, PTY, haltless, scratchpad, evidence tags, …), plus a legend for the mechanical recall gates/mechanisms/axes mnemonics (G1, G2, Gate V, Gate P, M1, M2, AD-1…AD-6, …) |

## Setup & maintenance

| Doc | What it covers |
|-----|----------------|
| [setup.md](setup.md) | Full setup guide with all per-language prerequisites |
| [dependencies.md](dependencies.md) | Platform dependencies, per-chain toolchains, and troubleshooting (incl. common install failure modes) |
| [updating.md](updating.md) | What updates on `git pull` vs what needs `plamen install`, v1.x migration, v2.1.0 changes |
| [mcp-servers.md](mcp-servers.md) | The 9 MCP servers, API keys, and Codex MCP caveats |

## Plamen-v3 development handoff

| Doc | What it covers |
|-----|----------------|
| [continuation/README.md](continuation/README.md) | Ordered index for the active goal, ledger, evidence, research corpus, and E2E procedure |
| [continuation/GOAL.md](continuation/GOAL.md) | Full continuation objective, definition of done, and explicit benchmark deferral |
| [continuation/E2E_RUNBOOK.md](continuation/E2E_RUNBOOK.md) | Pinned DODO Codex/Claude release-candidate E2E procedure and pending gates |
| [development/macos.md](development/macos.md) | Apple Silicon source-development bootstrap and honest native-runtime boundary |
| [development/machine-migration.md](development/machine-migration.md) | Safe Windows-to-macOS source and private-state migration |

## Using Plamen

| Doc | What it covers |
|-----|----------------|
| [usage.md](usage.md) | CLI reference, all commands and options, PATH setup, resuming an audit, operator controls |
| [audit-modes.md](audit-modes.md) | Light / Core / Thorough comparison |
| [codex-backend.md](codex-backend.md) | Codex CLI (BETA) backend known limitations |

## How it works

| Doc | What it covers |
|-----|----------------|
| [architecture.md](architecture.md) | Pipeline overview, driver architecture, PTY transport, haltless resilience |
| [pipeline-phases-presentation.md](pipeline-phases-presentation.md) | Phase-by-phase reference (all 40+ phases) |
| [internals.md](internals.md) | Skill system, security rules R1–R16, severity matrix, evidence tags, driver internals |
| [repository-structure.md](repository-structure.md) | Repository layout / directory map |

## L1 infrastructure mode

| Doc | What it covers |
|-----|----------------|
| [l1-mode/design.md](l1-mode/design.md) | L1 node-client audit architecture |
| [l1-mode/severity-matrix.md](l1-mode/severity-matrix.md) | L1-specific severity matrix |

## Design notes (internal)

| Doc | What it covers |
|-----|----------------|
| [design/regex-fragility-remediation-plan.md](design/regex-fragility-remediation-plan.md) | Internal engineering plan — fragile-regex class audit and remediation (not user-facing) |
