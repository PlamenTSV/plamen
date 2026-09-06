# Phase 4b Post-Precedent Boundary (Driver-Only)

This legacy prompt name remains for compatibility, but it is not an LLM
re-scoring phase. The code-derived `confidence_scores.md` produced before
external research is immutable at this boundary.

The deterministic driver must:

1. extract the single bounded proposal block from `rag_validation.md`;
2. compare proposals with independently derived typed mechanism and
   precondition facts;
3. write `precedent_evidence_authority.json` plus its exact investigation
   `precedent_context.md` and eligible-only `precedent_report_context.md` projections; and
4. leave every confidence value, classification, verdict, severity, and
   remaining-depth decision unchanged.

Read `~/.claude/rules/precedent-evidence-policy.md`. Generic methodology
literature supplies context only. Exact precedent requires a primary source,
the same mechanism class, and matching preconditions. Exact precedent may
raise investigation priority and report context only. RAG may never clear or
demote, force `CONTESTED`, change severity, satisfy proof, or reduce depth.
Family propagation requires typed equivalence; otherwise each sibling remains
unscored.

If proposal extraction, research, or reconciliation fails, emit visible typed
debt and continue with `UNSCORED` precedent. Never invent a numeric floor and
never invoke a scoring agent to repair this boundary.

SCOPE: The deterministic reconciler MAY read `confidence_scores.md`,
`rag_validation.md`, and current typed finding/equivalence facts as immutable
inputs. It writes only `precedent_evidence_authority.json`,
`precedent_context.md`, and `precedent_report_context.md`. It MUST NOT modify confidence scores, upstream analysis,
verification, severity, disposition, or report artifacts.
