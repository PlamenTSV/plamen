# V3 prompt-only reliability and recall experiment — 2026-09-26

## Decision and isolation boundary

Run 90 is the unchanged Codex/DODO baseline and must finish before installing
this source generation. It was still in low/info verification when these source
edits began. Do not edit its installed runtime, config, source snapshot, or
scratchpad. The next clean run must use the same immutable DODO commit,
Thorough mode, Codex backend, scope, and tool configuration so that prompt
changes are the primary treatment. A clean E2E result and adjudicated recall
comparison are not yet established.

This is a prompt-only treatment, not the entire deferred output-contract
backlog. Keep graph generation, toolchain, PhaseIO publication, validators,
reasoning-effort configuration, and finding adjudication unchanged for the
comparison. Native structured-final-output adapters, Stop hooks, file
archiving, and checklist integration are separate experiments. Combining them
now would make a recall change uninterpretable and could recreate artifact
ownership failures while the baseline is still running.

## Implemented source changes

- The common phase wrapper no longer tells a Codex worker it is in a Claude
  subprocess or offers an unavailable MCP/WebSearch fallback. Direct-phase
  output resumption remains driver-owned.
- The six smart-contract depth templates now require a reachable terminal
  financial **or non-financial** harm, retain unresolved candidates rather
  than confirming them merely because a defense is unproven, and correct the
  four-technique lists. They preserve R10's impact-level external-assumption
  treatment when the in-scope mechanism is proven. The three-technique
  injectable lists remain three.
- The four SC and two L1 depth role files describe analysis method rather
  than assigning output paths, IDs, verdict vocabulary, or `DONE` lines.
  Driver-generated PhaseIO and file contracts retain that authority.
- One shared intent/harm check reaches breadth, rescan, depth, and the legacy
  skeptic override; uncertain candidates remain visible instead of being
  silently discarded. The active application-skeptic phase has a separate,
  bound negative-evidence contract and is not a raw finding reviewer.
- The depth template projector now accepts the common anchor used by all six
  SC language templates. The old exact-EVM wording failed on qualified
  Solana/Soroban/DAML anchors.
- Standard depth workers now receive the concise semantic-proof method next
  to the driver-required section; it had previously lived only in the
  undelivered coordinator prompt.
- Stale V2/model-version labels in the visible command and legacy driver
  prompts were corrected without changing model routing.

## Backend mechanism limits verified

- Codex `codex exec --output-schema` constrains the final response, not files
  written during the turn: https://learn.chatgpt.com/docs/non-interactive-mode
- Claude Code `--json-schema` likewise returns a `structured_output` final
  field: https://code.claude.com/docs/en/headless
- Claude `--bare` skips ambient hooks **and subscription OAuth credentials**.
  The current Claude launch keeps OAuth and applies an explicit isolation
  `--settings` overlay instead; a future hook must be governed and deliberately
  included in that overlay. Codex run 90 passes `--ignore-user-config`, so
  ambient Codex hooks are not an output gate either.
- Claude Stop hooks expose `stop_hook_active` and have a default
  eight-consecutive-continuation cap. They can give bounded local correction,
  but cannot replace the driver's post-attempt artifact validation:
  https://code.claude.com/docs/en/hooks
- Shorter, non-contradictory prompts are plausible improvements, not a
  guaranteed recall gain. OpenAI recommends changing one instruction group
  at a time and measuring representative tasks:
  https://developers.openai.com/api/docs/guides/latest-model?model=gpt-5.6
  Anthropic recommends pruning instructions that obscure the real task:
  https://code.claude.com/docs/en/best-practices

The locally installed CLIs at review time were Codex 0.156.1 and Claude Code
2.1.281. Do not rely on the older 0.152.0/2.1.252 pair named in the deferred
plan. If a future phase uses native schema or Stop hooks, first design the
driver-owned publication transaction and test exact pinned CLI behavior on
both backends; a final-message schema cannot certify a separate scratchpad
artifact.

## Acceptance sequence

1. Finish run 90 unchanged. Record E2E completion, first-attempt validator
   pass rates and retries by worker type, debt, tool/graph/PoC coverage, token
   usage, and adjudicated findings. If it fails, preserve the failure as a
   baseline limitation rather than inventing a green reference.
2. Run prompt-render and relevant PhaseIO tests; regenerate the governed
   runtime-closure manifest after source changes. Current focused suite:
   31 passed, including exact standard-depth prompt rendering for Codex,
   Claude PTY, and Claude headless. The complete scoped-install census suite
   passed (10 passed,
   three skipped), and four package/Claude-projection regressions passed with
   a fresh isolated pytest temp path. The system temp parent has more than 6,000
   entries and trips the installer's 4,096-entry path-safety bound; this is a
   test-environment limitation, not a prompt change. A broader existing suite
   had 177 passed and three inventory/receipt failures. The backend-dispatch
   suite had 38 passed and eight fixture failures: seven omit the now-required
   `constraint_variables.md` input, and one lacks a source-scope snapshot.
   These are not evidence of prompt correctness or E2E readiness; resolve or
   classify them before install.
3. Install this generation only after the baseline driver exits. Start one
   distinct clean DODO destination through the public `plamen start-config`
   route. Do not reuse run 90's scratchpad or run root.
4. Compare format pass rate, retries/debt, graph/PoC/tool coverage, token
   usage and independently adjudicated findings against run 90. Prompt tokens
   saved are not themselves evidence that the model spent more reasoning
   compute; report actual usage and behavior.
5. Only after the isolated prompt comparison, decide whether to pilot the
   structured-verdict adapter, hooks, examples, checklist routing, or offline
   optimization one mechanism at a time.
