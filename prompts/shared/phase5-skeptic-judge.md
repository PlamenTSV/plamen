---
description: "Legacy pointer: Phase 5.1 independent skeptic challenge generation"
---

# Phase 5.1: Independent skeptic challenges

This legacy path is retained only for compatibility. The executable methodology
is `~/.claude/prompts/shared/v2/phase5-skeptic.md` (resolved to the active Plamen
home by the backend adapter).

The governing boundary is:

- the driver selects an exact, all-severity trigger denominator;
- the skeptic produces challenge proposals only and cannot dispose, demote,
  upgrade, merge, or exclude a finding;
- a separate worker adjudicates premise/evidence-bound severity challenges;
- only the validated typed severity ledger can change a report tier;
- `UNRESOLVED` and `PARTIAL` preserve the highest still-supported tier, remain
  in the report body, and carry visible human-review debt;
- missing, stale, malformed, or incomplete challenge/adjudication receipts cause
  repair/retry or recall-safe retention, never silent acceptance or deletion.

Do not restore the obsolete per-finding inline skeptic/judge workflow here.
