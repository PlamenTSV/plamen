# Codex Backend: Known Limitations (BETA)

> **Status**: Claude Code is the default, fully-supported backend. The OpenAI
> [Codex CLI](https://github.com/openai/codex) (`codex exec`) is a
> **cost-saving BETA** added in v2.1.0. It works for full smart-contract and L1
> audits, but the caveats below are real and worth understanding before you
> rely on it for a high-value review.

This page consolidates the Codex caveats that are otherwise scattered across
[mcp-servers.md](mcp-servers.md), [usage.md](usage.md),
[updating.md](updating.md), and the [CHANGELOG](../CHANGELOG.md). Everything
here is derived from the shipped code and docs — nothing speculative.

For what Codex *does* support and how to install it, see
[architecture.md § Codex Backend](architecture.md#codex-backend-cost-saving-beta)
and the [README Codex section](../README.md#codex-cli-backend-beta--cost-saving).

---

## 1. Bounded transactional fan-out on both backends

Codex and headless Claude use the same driver-owned bounded scheduler for the
parallel discovery phases. Recon, breadth, re-scan, and depth pre-bind every
worker's exact input/output transaction before the first provider launch, run
independent rows concurrently within their phase-specific ceiling, join the
whole wave, and only then perform canonical merge/gate work. Depth preserves
its producer-before-consumer barriers while parallelizing every ready wave.

The provider transport still differs: Codex invokes isolated `codex exec`
processes directly, while Claude invokes its authenticated headless provider.
The older Claude PTY supervision transport, host preflight, and informational
compaction heartbeat remain Claude-only compatibility paths. Those transport
differences no longer imply reduced Codex discovery fan-out or a serial Codex
methodology.

## 2. Audit subprocesses intentionally load no MCP on Codex

The installer can place nine optional MCP adapters in the user's Codex config
for manual interoperability. The audit driver does not inherit them: every
`codex exec` subprocess is ephemeral and uses `--ignore-user-config`. All
ordinary audit phases use local files and governed command-line tools directly.
`rag_sweep` receives filesystem + network authority and uses Web search for
precedent context; its typed launch receipt does not claim MCP.

Claude differs only in explicit headless mode, where `rag_sweep` may receive a
receipt-bound singleton `unified-vuln-db` config. The default Claude PTY and all
Codex audits use the same Web fallback and never inherit ambient MCP servers.
See [mcp-servers.md](mcp-servers.md) for the exact runtime matrix.

## 3. Global Codex MCP permissions do not affect audits

Interactive approval may still be required when a user invokes an optional MCP
adapter manually from Codex. It is not part of a Plamen audit launch, because
the driver ignores global Codex configuration and supplies its own phase policy.

## 4. Explicit model mapping and opt-in fallback

Plamen's tier aliases (`opus` / `sonnet` / `haiku`) are mapped to Codex models
in `_CODEX_MODEL_MAP` (`scripts/plamen_types.py`):

| Plamen tier | Default Codex model | Override env var |
|-------------|--------------------|------------------|
| `opus` | `gpt-5.6-sol` | `PLAMEN_CODEX_OPUS_MODEL` |
| `sonnet` | `gpt-5.6-terra` | `PLAMEN_CODEX_SONNET_MODEL` |
| `haiku` | `gpt-5.6-luna` | `PLAMEN_CODEX_HAIKU_MODEL` |

Three things to know:

- These are the current OpenAI GPT-5.6 family defaults. If a model is not
  available to your account, override it with the env vars
  above (or `PLAMEN_CODEX_FALLBACK_MODELS` for the fallback chain).
- `_resolve_codex_model_alias` fails closed on an unknown tier alias. A typo can
  no longer silently select the sonnet route.
- Model-unavailable, capacity, and rejected-`--model` fallbacks are disabled by
  default. Use `--allow-model-fallback` only when you intentionally authorize a
  different model route. `plamen plan MODE PATH --codex --explain-routes`
  resolves every phase route with zero provider calls.

## 5. ChatGPT-auth / usage-cap behavior

Codex usage-cap and ChatGPT-subscription quota errors arrive as
**natural-language prose, not structured error codes**. The driver detects
these and **auto-waits** (preserving state) instead of treating them as a phase
failure that retries into a halt (`scripts/plamen_driver.py`). A
`context-exceeded` condition is likewise recoverable rather than fatal.

This means a Codex audit on a capped ChatGPT subscription will pause and resume
rather than crash — but you are still subject to your ChatGPT/Codex account's
own auth and usage limits, which Plamen cannot raise.

## 6. `plamen compare` is Claude-only

The `plamen compare` command (diff two audit reports / post-mortem analysis)
runs `/plamen compare` inside a **Claude Code** session and requires `claude`
in PATH — it exits if `claude` is not found (`plamen.py:launch_claude`). There
is no Codex code path for `compare`. If you only have Codex installed, the
audit pipeline works but `compare` will not.

---

## See also

- [getting-started.md](getting-started.md) · [usage.md](usage.md) · [architecture.md](architecture.md) · [mcp-servers.md](mcp-servers.md) · [updating.md](updating.md)
