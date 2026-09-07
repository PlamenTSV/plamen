# Plamen-v3 continuation index

This directory is the public, privacy-safe handoff for finishing Plamen-v3.
It is an active engineering record, not a release-completion claim.

## Current source boundary

- Branch: `Plamen-v3`
- Last pushed public code baseline recorded by this handoff:
  `7e8d82eadadb9f1f655fac947b092d83daa433a3`
- Its parent handoff freeze is
  `17ddb029244337491a6477f553f1db39f81671c8`.
- Work after `7e8d82e` may still be pending in the source worktree. Do not invent
  or record a final release-candidate SHA until those changes are reviewed,
  committed, pushed, and verified from a fresh clone.
- Codex and Claude release-candidate E2Es remain pending. The exact reproducible
  procedure is in [E2E_RUNBOOK.md](E2E_RUNBOOK.md).
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
