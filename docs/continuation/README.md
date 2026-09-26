- **[HANDOFF 2026-09-21](HANDOFF_2026-09-21.md) — READ FIRST: interrupted normalization migration, Codex continuation, measured conformance results and remaining work.**
- [HANDOFF 2026-09-19](HANDOFF_2026-09-19.md) — prior run history and architecture context.
# Plamen-v3 continuation index

This directory is the public, privacy-safe handoff for finishing Plamen-v3.
It is an active engineering record, not a release-completion claim.

## Current source boundary

- Branch: `Plamen-v3`
- `d42b851e706d30ab4f921f1384fc9fea290a0114` is the last attempted Codex
  E2E baseline, not the handoff branch identity. That attempt completed Recon
  with recorded dependency-research debt and was then intentionally stopped.
- The authoritative handoff candidate is the fetched `origin/Plamen-v3` tip.
  Record `git rev-parse HEAD` after cloning and require it to match
  `git rev-parse origin/Plamen-v3`; do not substitute the historical baseline.
- Neither backend has a complete release-candidate E2E. The exact reproducible
  start and resume procedure is in [E2E_RUNBOOK.md](E2E_RUNBOOK.md).
- Native Linux and macOS production audits remain unsupported. macOS is a
  source-development handoff only until the POSIX gates in
  [GOAL.md](GOAL.md) close.

## Read in this order

1. [GOAL.md](GOAL.md) — full objective, definition of done, and explicit
   benchmark deferral.
2. [REQUIREMENTS.jsonl](REQUIREMENTS.jsonl) — machine-readable cumulative
   acceptance ledger. Empty implementation or evidence arrays are explicit
   unresolved mappings, not omissions or clean results.
3. [DECISIONS.md](DECISIONS.md) — durable architecture, methodology, privacy,
   backend, and lifecycle decisions.
4. [NEXT_ACTIONS.md](NEXT_ACTIONS.md) — dependency-ordered execution plan and
   current checkpoint.
4a. [../design/gate-repair-architecture.md](../design/gate-repair-architecture.md)
   — **read before changing any phase gate, validator, parser, or adding a
   deterministic repair.** Binding principle (unusable vs mechanically
   repairable), the required normalise-then-gate ordering, the three repair
   laws, the eleven-defect history with root causes, and the research basis.
   Section 6 is an explicitly OPEN rollout question with stated falsifiers —
   do not generalise it without the evidence listed there.
4b. [TYPED_ARTIFACT_BOUNDARY_DECISION_2026-09-23.md](TYPED_ARTIFACT_BOUNDARY_DECISION_2026-09-23.md)
   — accepted direction for retiring model-authored Markdown as inter-phase
   authority. It preserves strict identity/provenance gates while moving
   presentation out of the semantic protocol.
5. [E2E_RUNBOOK.md](E2E_RUNBOOK.md) — pinned DODO Codex/Claude release-candidate
   audit procedure, status, resume rules, logs, checkpoints, and acceptance.
6. [EVIDENCE_INDEX.json](EVIDENCE_INDEX.json) — scoped evidence and explicit
   missing gates. A green narrow record never proves the whole tool.
7. [CORPUS_MANIFEST.json](CORPUS_MANIFEST.json) — the 131-source research
   denominator and 127 public ports.
8. [MODEL_ROUTING_PORTABLE_REPLAY.json](MODEL_ROUTING_PORTABLE_REPLAY.json) —
   exact public replay graph and declared private-prerequisite blocks.
9. [PRIVATE_ARTIFACTS.md](PRIVATE_ARTIFACTS.md) — out-of-Git transfer and
   retention policy. It is not a private inventory.

## Fresh-machine checks

From a clean clone of `Plamen-v3`:

```text
python -B -m pytest -q -p no:cacheprovider scripts/test_continuation_handoff.py scripts/test_model_routing_research_portable_replay.py
python -B scripts/replay_model_routing_research.py --root . --accept-declared-blocks
```

The replay command proves public-port integrity and the exact public replay
subset. Its eight declared non-public prerequisite blocks remain blocks; they
must not be converted into passes by searching for machine-local files.

For Apple Silicon source development, continue with
[the macOS guide](../development/macos.md) and
[machine-migration guide](../development/machine-migration.md). Real audits
must use a supported, authenticated Windows installation until the POSIX
runtime acceptance gates are proven.
- [Prompt trends & discovery reality check (2026-09)](../research/PROMPT_TRENDS_REALITY_CHECK_2026-09.md) — registries (Pashov/Forefy/QuillShield/ToB), 2026 benchmarks, where Plamen's discovery prompts lag, ranked recommendations
