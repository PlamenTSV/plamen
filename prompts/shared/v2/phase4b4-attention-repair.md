# Attention Repair (Thorough Only)

> **Trigger**: Run ONLY when `{SCRATCHPAD}/attention_repair_queue.md` exists.
> **Mode gate**: Thorough mode only.
> **Purpose**: Repair specific queue-driven coverage/attention gaps.
> This is NOT a general analysis pass — only the rows in the queue are in scope.

---

## Inputs

- `{SCRATCHPAD}/attention_repair_queue.md` (the queue — REQUIRED, phase does not run without it)
- The exact source file or artifact named in each queue row
- `function_list.md`, `contract_inventory.md`, `call_graph.md`, and `state_variables.md` ONLY when the queued row needs symbol resolution
- `{SCRATCHPAD}/spec_expectations.md` when present, for context only. It lists
  test/mock/harness files that are specification evidence, not production
  coverage debt.
- `{SCRATCHPAD}/skill_execution_checklist.md` when a queue row has kind
  `skill-execution-gap`.

**Do NOT read** large bulk artifacts (analysis/depth/verify outputs, the full scratchpad). Only read the queue row's named target.

Do NOT re-audit the whole protocol. This phase is scoped to the specific gaps in the queue.

Test, mock, script, fixture, and harness files are not production coverage
obligations. They should not appear as `uncited-security-file` queue rows. If
one appears due to stale queue state, mark it `NO_FINDING`, cite
`spec_expectations.md` or the file path, and do not spend depth-analysis budget
auditing the support file itself. Use support files only to derive expectations
that production code may satisfy or violate.

---

## Output Files

| File | Purpose |
|------|---------|
| `{SCRATCHPAD}/attention_repair_summary.md` | Per-row verdict table (ALWAYS written) |
| `{SCRATCHPAD}/attention_repair_findings.md` | Finding blocks for CONFIRMED issues (written only if findings exist) |

---

## Summary Table Format

For every queue row, write one row to `attention_repair_summary.md`:

| Queue # | Kind | Target | Verdict | Evidence | Notes |
|---------|------|--------|---------|----------|-------|

**Receipt contract**:
- Copy the queue's `QUEUE_BINDING_SHA256` line verbatim near the top of
  `attention_repair_summary.md`. A summary without the exact binding is stale
  and will be rejected.
- The `Queue #` cell MUST equal the queue row number.
- The `Kind` cell MUST equal the queue row kind.
- The `Target` cell MUST copy the queue row `Target` value exactly, including
  the full relative path. Do not shorten it to a basename or summarize it by
  folder.
- The `Evidence` cell MUST cite the exact target path again with file:line
  evidence when source is available. If the file is unavailable, cite the exact
  target path and explain `NEEDS_HUMAN`.

The validator treats a missing exact target-path receipt as incomplete repair.
Do not return only a prose summary.

---

## Allowed Verdicts

| Verdict | Meaning | Requirements |
|---------|---------|-------------|
| `SAFE` | Reviewed and no issue | Include file:line evidence OR a concrete reason why the row is unreachable |
| `CONFIRMED` | Issue exists | Write a finding block in `attention_repair_findings.md` |
| `NO_FINDING` | Row was stale or already covered | Cite the existing finding/source that already covers this |
| `NEEDS_HUMAN` | Cannot determine mechanically | Only if source is unavailable or semantics depend on deployment data outside the repository |

---

## Finding Format

Confirmed findings MUST use `ATT-N`, where `N` is the exact **global Queue #**
from the receipt row. Do not renumber only the confirmed rows: if queue row 5 is
the first confirmed issue, its finding ID is `ATT-5`, not `ATT-1`. Use the
following standard fields:

```markdown
### Finding [ATT-1]: title

**Severity**: High/Medium/Low/Informational
**Location**: contracts/path/Contract.sol:L123
**Preferred Tag**: CODE-TRACE
**Evidence Tag**: CODE-TRACE
**Source IDs**: attention_repair_queue.md row N
**Description**: ...
**Impact**: ...
**Evidence**: ...

### Precondition Analysis (if applicable)
**Missing Precondition**: [What blocks this attack]
**Precondition Type**: STATE / ACCESS / TIMING / EXTERNAL / BALANCE
**Why This Blocks**: [Specific reason]

### Postcondition Analysis (if applicable)
**Postconditions Created**: [What conditions this creates]
**Postcondition Types**: [STATE, ACCESS, TIMING, EXTERNAL, BALANCE]
**Who Benefits**: [Who can use these]
```

---

## Repair Priorities by Queue Kind

### NOTREAD or Uncovered Files

Inspect every externally reachable function in the queued file for:
- Access control correctness
- Value flow integrity
- External-call side effects
- Accounting invariants
- Stale reads
- Upgrade/storage layout safety
- Unbounded iteration

### Uncited Security Files

Inspect only the named file and direct callers/callees needed to determine reachability. Do not expand scope beyond what is needed to resolve the queue row.

### Graph/Coverage Rows

Resolve the exact uncertain row and either:
- Confirm it with evidence (file:line + explanation), or
- Mark it SAFE with the missing edge explained

### Skill-Execution Gap Rows

Read the matching row in `skill_execution_checklist.md`, then inspect the
specific target files listed in that row. Do not rerun the whole depth phase.
Either produce a narrow `ATT-*` finding for a real missed issue, or mark the row
`NO_FINDING`/`SAFE` with evidence that the missing methodology step is already
covered elsewhere or not applicable.

---

## Scope Containment

SCOPE: Write ONLY to `attention_repair_summary.md` and, if needed, `attention_repair_findings.md`. Do NOT proceed to RAG, chain analysis, verification, or report. Return your findings and stop.

---

## Integration with Pipeline

Attention repair findings (`ATT-*` IDs) are picked up by:
1. The inventory merge step (appended to `findings_inventory.md`)
2. Chain analysis (checked for postcondition/precondition matches)
3. Verification (included in verify queue if Medium+)
4. Report index (assigned report IDs alongside other findings)

The driver handles this integration — the repair agent only needs to write its output files correctly.
