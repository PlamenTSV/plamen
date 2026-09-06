# Phase 6e: Material-Harm Body Floor

> **Loaded by**: The V2 driver's Phase 6e dispatch.
> **Execution model**: PYTHON-NATIVE. The driver invokes
> `scripts/report_disposition_authority.py::reconcile_report_dispositions`
> directly. No LLM
> subprocess runs for this phase. This prompt file exists only so that
> `build_phase_prompt` returns a non-error placeholder when the phase is
> queried — it is **never** sent to a model.
>
> **critical=False (LOAD-BEARING)**: a crash, missing/stale/tampered authority,
> or malformed proposal MUST NOT halt the run or remove a finding. The driver
> preserves BODY at upstream severity and emits visible human-review/no-ship
> debt. This is the FINAL report mutation.

## What the Python phase does

After `report_disposition` writes proposal-only `disposition.md`, this phase:

1. Replays exact queue, verifier-receipt, typed-decision, applied-alias,
   report-index, and proposal hashes into `report_disposition_authority.json`.
2. Applies only APPENDIX proposals backed by an independent typed full-claim
   zero-security-consequence decision with no contradiction. Lexical
   classification can veto/request adjudication but never authorize.
3. Preserves complete original section bytes in
   `report_appendix_full_content.json`, validates client-field parity, and only
   then relocates the authorized `### [X-NN]` body section into
   `## Appendix C: Quality & Hardening Observations` (one row each — never
   dropped; recall-safe).
4. Decrements the `## Summary` counts table so the delivered report's summary
   matches its remaining body sections.

Idempotent and haltless: missing or invalid authority is a BODY-preserving
no-op plus visible debt; repeated valid execution validates the same sidecar.

## No further instructions

This phase has no LLM-visible instructions. The Python module is the single
source of truth. If you are an LLM reading this file, you should not be —
return immediately.
