# Semantic transitions: implementation contract

This is a validator-engineering checkpoint, not evidence of a completed audit.
The backend remains Codex. No existing audit configuration or checkpoint is
rewritten by these checks.

> Migration scope: the tolerant Markdown reader in this document is a
> compatibility boundary for existing and historical artifacts. It is not the
> terminal inter-phase protocol. New model boundaries migrate to
> schema-constrained typed JSON and deterministic projections under
> `TYPED_ARTIFACT_BOUNDARY_DECISION_2026-09-23.md`; downstream phases must not
> recover semantic authority by parsing those projections.

## Decisions informed by research

1. **One tolerant representation reader, many strict semantic consumers.**
   Fowler's [Tolerant Reader](https://martinfowler.com/bliki/TolerantReader.html)
   recommends minimal assumptions about incidental payload structure and one
   encapsulated reader. Here that means accepting equivalent Markdown through
   `artifact_surface`, not adding a separate regex exception to every gate.
2. **Normalize, validate the resulting state, then publish.** Kubernetes'
   [admission guidance](https://kubernetes.io/docs/concepts/cluster-administration/admission-webhooks-good-practices/)
   requires idempotence of both individual mutations and their composition,
   with final-state validation. Applied here: repairs must preserve identity,
   survive replay, and not create a new gate failure downstream. This is an
   architectural inference, not a claim Kubernetes supplies an audit workflow.
3. **Tolerance is not semantic coercion.** Pydantic's
   [strict-mode documentation](https://pydantic.dev/docs/validation/latest/concepts/strict_mode/)
   distinguishes useful input coercion from cases where coercion is undesirable.
   Plamen needs no new dependency for this distinction: normalize decoration,
   but require a finite, consumer-owned vocabulary for identity and decisions.
4. **Replay is not a new execution.** The AWS Builders' Library explains
   [idempotent request identity and semantic responses](https://aws.amazon.com/builders-library/making-retries-safe-with-idempotent-APIs/).
   Applied here, a replay must preserve the registered run/attempt and source
   preimages. Once the arm step returns `execute=False`, validate the existing
   publication; do not issue another commit and silently mint a new attempt.

## Non-negotiable invariants

- Equivalent presentation must not change a semantic decision.
- Quoted examples are not assertions. A lifecycle status cannot be completed
  by a fenced example or a legacy sentinel contradicting a current assertion.
- Equivalent duplicate columns may resolve; contradictory columns may not.
- A generic ordinal beside a finding ID is not a second finding ID.
- Missing, ignored ancillary data, unknown assertions, and contradictory
  assertions are different states. Unknown is not permission to select the
  more convenient column.
- Identity, deduplication, severity, disposition, and authenticated provenance
  are not repaired by guessing. Retain original evidence and visible debt.
- Normalize before publication. Already committed bytes and their authority
  must not be rewritten just because the replacement has equivalent meaning;
  byte-identical no-op publication should preserve physical identity too.
- Content equality is not authority equality. A registered producer handoff
  remains a state transition even if bytes and normalized inputs are identical.
  Replay the successor's authority and record the ownership transition; do not
  alternate between treating it as a no-op and rejecting its changed owner.
- Assessment must not pre-publish another phase's authoritative output.
  Validators can emit their assigned diagnostics; terminal receipts are created
  only after their typed producer is armed. Correct-looking unowned bytes are
  not authority and are not silently adopted on resume.
- Retaining a report candidate in BODY is a conservative placement fallback,
  not a claim the candidate is verified or its severity settled.
- Terminal acceptance must still reject unresolved obligations and execution
  debt. A clean-looking report is not a completion receipt.

## Checked table API

`Table.role_indices(role)` preserves every matching column, while legacy
`row.get(role)` remains compatible. `Table.resolve_role(row, role, normalizer=,
property_name=)` returns a value only for `RESOLVED`, alongside assertions and
typed defects. Other states are `MISSING`, `IGNORED`, `UNKNOWN`, `CONFLICT`.

The caller's normalizer returns a canonical string, `None` for unknown, or
`IGNORE_ROLE_VALUE` for explicitly ancillary content. It must not ignore
unrecognized authoritative values. Defects use the supplied property family;
duplicate-column formatting debt alone is not a reason to reject equivalent
values. Assertion cells retain the surface-normalized text; the original
physical source remains available at `row.line.raw`.

First consumer: report placement reads every competing ID and disposition,
retains every recognized affected report ID in BODY when unresolved, records
diagnostics, and aggregates duplicate rows without last-row-wins suppression.

Remaining consumers to migrate, with separate tests before rollout:

- candidate-negative table harvesting and zero-candidate claims;
- report-index identity/severity/status authority;
- coverage accounting status;
- chain severity-upgrade authorization.

Do not claim this additive API alone fixes those consumers. Do not replace
every `get()` blindly: notes and supporting evidence need different policies
from candidate-closing decisions.

## Ledger replay publication

`artifact_ledger.write_artifact_ledger` now preserves inode and mtime only when
its canonical payload exactly matches a stable, no-follow read of the existing
single-link regular file. Destination checks still run first; CAS authorization,
candidate validation and committed-revision checks remain in their caller.
Changed bytes still publish normally. The focused replay/CAS suites pass 19
checks; three no-op cases failed before this guard.

This is not a blanket claim that all publishers are idempotent. The legacy
`plamen_validators._write_artifact_state` remains unchanged, and the precise
resume caller behind the original full-tail rewrite has not been proven.
The full-tail rerun now passes that immutable-input assertion and proceeds
through assembly, deduplication and disposition. It exposes a separate
report-floor assurance successor-authority mismatch, so the complete tail
still has not passed.

The next mismatch was traced to a real, authenticated disposition producer
handoff with identical report bytes and identical normalized inputs. The weaker
byte-identical-owner allowance bypassed successor authentication, so preparation
returned without invalidating the old producer; the next prebind rejected the
owner again. `_prepare_assurance_projection_reexecution` now requires the
existing authenticated-successor path for that handoff. There is no broader
owner allowlist or hash-check bypass. A focused real-authority regression and
forged-commit/foreign-run/unregistered-owner controls pass, alongside existing
producer-handoff tests: 31 checks including diagnostic control flow.

Assurance diagnostics now also preserve recovery failures instead of discarding
them behind the original prebind symptom. That improves other failure cases;
the observed no-change handoff itself returned a no-op rather than an exception.
The subsequent full-tail run passes that handoff and exposes a later final
evidence-quality issue. The assembly quality gate had published the terminal
receipt before its typed owner was armed. The gate now calls shared read-only
`assess_final_report_evidence_delivery`; only the typed finalizer publishes or
compares the receipt. All 78 related checks pass. Already unowned receipts are
not silently adopted or deleted; they remain visible repair debt.

Read-only assessment also isolates a separate heading incompatibility: assembly
strips private finding IDs from titles and appends an index-authorized status,
whereas delivery parity compares the entire heading to the raw typed title.
All other fields match in the retained synthetic run. The correction must
validate an exact authority-bound presentation projection, not ignore arbitrary
title or status changes. The fresh synthetic nonempty tail now passes through
final evidence quality (run06, 710.056 seconds), with its intentional degraded
severity outcome intact. This is scoped fixture acceptance, not audit E2E.

### Authenticated heading presentation

`report_heading_presentation` now shares the assembler's public title
normalization and exact status interpretation with delivery assessment. Its
read-only loader replays the index's registered producer contract, DRIVER
launch policy, commit authority, current bytes and run identity. The issued
in-memory projection is bound to the exact typed bundle and sealed against
content changes. Final quality includes the index in its immutable inputs;
both advisory assessment and native completion replay receive the source
project root, even when the report itself is staged elsewhere.

Without this authenticated context, the pure delivery API retains strict
raw-title comparison. It never infers a display status from a verdict, strips
arbitrary labels, or treats `UNVERIFIED`/`NOT VERIFIED` as `VERIFIED`.
The projection is not a new proof or severity authority. Empty evidence bundles
need no invented status rows. Terminal receipt publication remains separate.

The focused heading/legacy/completion group passes 144 checks, including 75
shared-reader metamorphic cases, and the evidence quality group passes 78 at
runtime closure
`20492883282fcc8af9519314a4dd22707878fef17a55c42815f21e26430f1b54`.
Five older fixture failures were corrected by publishing real registered
index/evidence inputs, not by bypassing authority or weakening their tamper,
overclaim, replay or report-swap assertions. Fresh nonempty (710.056 seconds)
and empty assembly (374.37 seconds) integrations passed at the preceding
heading-projection revision. Exact compare-only replay of the successful
nonempty receipt under the shared-reader revision also passes without any
ledger/receipt byte, inode or mtime change. This source revision is not yet
the installed runtime.

The heading reader uses `artifact_surface` checked roles for report identity,
title and display status. Both legitimate `Verification` and `Verdict` headers
resolve, while Evidence Tag remains ancillary. Equivalent duplicate columns
and rows resolve; contradictory or unknown assertions cannot select a winner.
Quoted examples cannot supply authority or terminate real sections. Escaped
and code-span pipes, heading levels, setext, decoration and column order are
representation-only. Unlimited decimal IDs preserve their exact zeroes.
Ambiguous unterminated quotation boundaries and truncated/lossy reads remain
explicit unresolved authority, not permission to authorize a partial map.
This does not migrate all older report-index consumers, listed above.

### Inventory execution and recall continuity

A new upstream fixture reproduced a genuine controlled inventory child whose
MODEL output was recorded without its execution receipt. Exact registered
`inventory_chunk_a/b/c` `model.attemptNNNN` leaves now enter the existing POSIX
incorporation path; zero attempts, aliases, other chunks and DRIVER roles do
not. Execution authority does not waive candidate completeness or reconciliation.
The shared routing and transport checks pass 76 cases. The new actual child
fixture is Codex-compatible; no live Claude provider parity is claimed.

After that correction, the upstream fixture exposed a distinct duplicate:
additive repair retained source A-02 as INV-002 but emitted no authenticated
Source Actions marker. Later promotion missed the existing referent and
allocated INV-004 for the same source. The three-ID expectation is unchanged;
the emitter must carry its already-bound source hash through to the consumer.
This fresh-run provenance correction is in progress. Old committed receipts
must not be rewritten or adopted without a governed compatibility path.

## Repeatable offline checks

From the repository root, with runtime sources frozen:

```sh
python3.12 scripts/toolchain_control_authority.py render-runtime-closure \
  --root . --output verification_policy/toolchain_runtime_closure.v1.json
python3.12 docs/continuation/tools/run_semantic_transition_checks.py \
  --output /tmp/plamen-transition-checks-new-run
```

The runner refuses an existing output directory, saves one log per suite,
records commands and hashes, and runs each suite in a separate interpreter.
Each suite keeps its fixtures under that evidence directory, outside pytest's
rotating temporary-directory retention. Python stack timers are opt-in through
`--stack-dump-after`; they use pytest's
[faulthandler timeout](https://docs.pytest.org/en/stable/how-to/failures.html).
They are disabled by default: on this CPython 3.12.12 build, native samples
showed its diagnostic thread repeatedly inside `PyCode_Addr2Line`, emitting
only a truncated traceback and adding CPU load. This is a local observation,
not a confirmed upstream bug attribution. Use external sampling here instead.
The independent process deadline defaults to 1,800 seconds; a timeout is not
counted as either a pass or an assertion failure.
It does not launch audit workers or model providers. It exercises parser
conformance and selected real depth, chain, queue, report and terminal-receipt
transactions. Terminal-receipt fixtures synthesize preceding closure; they do
not prove that the whole pipeline generated it.

## E2E gap and safety boundary

No continuous production recon-to-report fixture exists in the inspected tree.
The deterministic fault-matrix helper currently drives a toy three-stage
workflow. The genuine nonempty tail begins at severity and intentionally ends
degraded. Neither is evidence for flawless real audits or measurable V3 recall.

The first installed smoke check found stale help: it said compatibility mode
cannot launch governed audits, although the actual dispatcher supports local
reduced-isolation runs separately from native completion authority. A proposed
plan-blocking change was therefore withdrawn. Help and planning should disclose
the reduced assurance, not invent a launch prohibition. This correction does
not bypass any native admission or execution policy.

The current public audit policy has no static-only mode: Light/Core require
execution attempts for Medium+ findings; Thorough requires all severities.
Consequently this continuation does not launch autonomous DODO exploit
reproduction. Offline validator and transaction checks remain in scope; no
execution requirement or terminal acceptance rule is bypassed to obtain green
results. A defensible next E2E milestone is a continuous benign synthetic
pipeline fixture with controlled Codex children and the real phase authorities.

## Cross-epoch physical identity correction (Run 69)

Run 69 disproved the remaining blanket physical-identity assumption.  A
byte-identical late-CI successor changed only the directory entry for one
canonical artifact.  The old replay rule compared that new inode with the
producer's historical inode, rejected the producer, and thereby poisoned
unchanged siblings in the producer bundle.  That is an implementation failure,
not an authenticity failure.

The contract is therefore refined as follows:

1. Historical issuance records retain physical metadata as signed telemetry
   and must remain internally self-consistent.
2. Durable live replay compares exact bytes, size, producer/run/contract,
   inputs, and transaction lineage.  It does not require a filesystem object
   to retain one inode forever.
3. Each validation invocation records the live path and physical identity and
   rejoins them before return.  Any replacement during that epoch still fails.
4. Safe single-link regular-file checks remain mandatory.  Content equality
   never legitimizes a symlink, hardlink alias, foreign owner, or unregistered
   transition.
5. The shared DRIVER byte publisher performs an exact-byte no-op for every
   phase.  The ledger rule remains independently tolerant of exact
   rematerialization so correctness does not depend on every call site using
   that optimization.

The regression suite now includes the original no-op publisher path and a
deliberately hostile legacy atomic-replace path inside an armed late-CI
successor.  Both must complete with the same semantic authority; changed bytes
and unsafe aliases remain negative controls.  This closes the same failure
class at producer replay, successor progress, and downstream prebind rather
than patching enumgap alone.

## Provider-normalized graph handoff (Run 70)

The semantic transition into invariants and Depth is defined over a complete
graph generation, not over a provider-specific side effect. Every provider
must expose these exact consumer identities:

- `_mechanical_graph.json`;
- `caller_map.md`;
- `callee_map.md`;
- `state_write_map.md`;
- `function_summary.md`; and
- `_mechanical_graph_generation.json`, binding hashes and sizes for the five
  semantic graph artifacts.

When recon already published a complete precise generation, consumers validate
and reuse it. When only the mechanical graph exists, the registered
`inventory/mechanical_graph_projection` DRIVER transaction deterministically
materializes the remaining denominator. The Inventory-to-Depth transaction is
armed only after that provider-normalization boundary succeeds. Partial or
conflicting generations remain explicit debt and are never repaired by
overwriting an existing member in place.
