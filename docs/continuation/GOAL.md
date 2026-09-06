# Plamen v3 continuation goal

Status: **ACTIVE**
Branch: `Plamen-v3`
Acceptance owner: the user

## Objective

Complete Plamen v3 as one coherent, portable Web3 security-auditing tool. The
finished branch must contain the authoritative source, methodology, schemas,
prompts, orchestration, tests, installation logic, and operator documentation
needed to install and continue development from a clean clone on macOS or
Windows. It must be validated as a tool; comparative quality benchmarking
against older Plamen versions is a later, separate goal.

The target is not merely an audit report or a passing fixture. It is a
source-governed tool whose claimed behavior is production-reachable, whose
failures remain explicit debt, and whose validation evidence is bound to exact
source and package identities.

## Governing requirement namespaces

Completion must reconcile all three namespaces in
[`REQUIREMENTS.jsonl`](REQUIREMENTS.jsonl):

1. The historical acceptance ledger: 44 P0 obligations and 13 P1 obligations,
   plus its separately tracked program and user-acceptance gates.
2. The canonical architecture registry: 166 requirements in
   [`architecture/canonical-requirement-ownership.v2.json`](../../architecture/canonical-requirement-ownership.v2.json).
3. Current runtime and operational requirements discovered during the 2026-09
   validation continuation.

Omission from a later summary does not close a requirement. A requirement may
leave the active denominator only through an explicit reviewed supersession
that identifies its successor and demonstrates no loss of security, recall,
precision, backend, ecosystem, lifecycle, portability, or operational scope.

## Definition of done

Plamen v3 is complete only when all of the following are true:

### 1. Requirements and architecture

- Every row in all three requirement namespaces is `DONE`, or is covered by a
  reviewed supersession with a named successor, rationale, and no-scope-loss
  evidence.
- The five canonical normative sources and two redirect-only compatibility
  documents are internally consistent, package-reachable, link-clean, and
  independently reviewed.
- Method content, provider facts, scheduler behavior, premise/disposition
  authority, and report authority each have one declared normative owner.

### 2. Methodology and analysis reachability

- Recon, dependency research, breadth, re-scan, per-contract analysis,
  inventory, semantic invariants, depth, chain analysis, verification, and
  reporting use the V2 driver phase graph and its artifact gates.
- Program Facts, typed graphs, method cards, adaptive attention, niche routing,
  assumption checking, and historical-precedent fallbacks are reachable where
  applicable and produce typed, capability-scoped receipts.
- Partial, missing, stale, unsupported, timed-out, or malformed evidence can
  add candidates or debt but cannot authorize a negative, demotion, safe
  conclusion, or silent phase completion.
- Findings and their exact aliases, premises, evidence, severity decisions,
  verification state, and report projection survive every transformation
  unless an authorized disposition says otherwise.

### 3. Orchestration and lifecycle

- The Python driver remains the sole phase sequencer. Worker files, process
  exit, disk idleness, or model self-report never become semantic completion
  authority by themselves.
- Every worker attempt has immutable input, route, ownership, output-prestate,
  execution, completion, and incorporation bindings.
- Cancellation, retry, timeout, crash, resume, compaction, and missing-output
  paths cannot permit late writes, cross-worker writes, duplicate authority,
  or false completion.
- Temporary output, process trees, cleanup ledgers, and retained evidence have
  bounded, recoverable, cross-platform lifecycle policies.

### 4. Backend parity

- Claude and Codex use the same logical denominators and authority semantics,
  while retaining their documented transport differences.
- The requested and actual backend, model, effort, service tier, fallback, and
  terminal provider outcome are recorded or explicitly `UNKNOWN_BLOCKED`.
- No fallback, resume, retry, or provider recovery silently changes semantic
  tier or execution generation.

### 5. Packaging and portability

- A clean checkout builds and installs without depending on mutable installed
  trees, local backups, caches, absolute paths, or ambient Python state.
- Public install, upgrade, rollback, repair, uninstall, and development setup
  are documented and tested on current macOS and Windows environments.
- Installed-byte receipts, packaged assets, source manifests, dependency locks,
  and runtime closures agree without manually rebasing expected identities.
- Generated audit artifacts stay under owned output roots and never pollute an
  audited source tree.

### 6. Validation

- Focused tests, the full serial suite, supported parallel suites, packaging
  tests, clean-install tests, fault/recovery tests, and resume tests pass on the
  exact release candidate.
- At least one fresh, non-ground-truth end-to-end audit completes through final
  report on Codex, and at least one completes on Claude.
- Representative supported ecosystems and L1 paths receive bounded canaries
  sufficient to justify their advertised support.
- Validation claims cite immutable evidence records in
  [`EVIDENCE_INDEX.json`](EVIDENCE_INDEX.json); scoped evidence never expands
  into a whole-tool claim.

### 7. Handoff

- A new machine can clone the branch, follow the documented macOS or Windows
  setup, run smoke validation, start an audit, resume it, and continue this goal
  using only versioned public inputs plus separately supplied credentials.
- Known limitations and unresolved debt are visible. No local runtime,
  credential, audit target, private finding, or ground-truth artifact is needed
  to understand the remaining work.

## Explicitly deferred

The following are outside this goal and must not block tool completion:

- old-Plamen versus Plamen-v3 quality benchmarking;
- DODO, Spectra, or other ground-truth scoring;
- recall/precision improvement claims based on held-out corpora;
- tuning methodology, routing, or agent counts against grader-only answers.

The tool and its blinded evaluation interfaces must remain capable of supporting
that later work. Deferral is not permission to delete evaluation contracts or
weaken the out-of-tree ground-truth boundary.

## Evidence rule

`DONE` requires production-reachable implementation, a generic red fixture,
focused proof, applicable full-suite proof, applicable fault/migration/resume
proof, clean-package proof, required backend/platform proof, and no silent loss
of identity, obligation, candidate, evidence, independently authorized
negative, or report content. Code volume, a schema, a green unit test, a phase
gate, or one generated report is insufficient on its own.
