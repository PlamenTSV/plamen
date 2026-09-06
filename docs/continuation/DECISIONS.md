# Plamen v3 durable decisions

These decisions constrain implementation and supersession. Changing one requires
a reviewed replacement decision, an old-to-new invariant crosswalk, and evidence
that no security or operational scope was lost.

## Authority architecture

1. **Do not revive the big-bang SQLite ledger.** The database-first event/finding
   design is superseded by domain-typed immutable JSON authorities, PhaseIO,
   semantic journals, CAS-bound worker incorporation, exact reconciliation, and
   explicit projections.
2. **One normative owner per concern.** Shared authority and disposition belong
   to the method-application RFC; provider facts to the ecosystem contract;
   method content to MethodCards; worker lifecycle to the scheduler; evaluation
   governance to the evaluation plan.
3. **Markdown and disk markers are projections or transport evidence.** They are
   never universal semantic or execution authority.
4. **Stable identities are not display IDs.** Content, source, premise, work,
   attempt, evidence, alias, route, and report identities remain exact and
   digest-bound across transformations.

## Methodology and negative authority

5. **MethodCards are the sole normative method-content catalog.** Prompts,
   skills, and verifier registries reference versioned cards instead of creating
   competing method definitions.
6. **Program Facts and graphs are additive evidence.** Capability-limited,
   incomplete, stale, or failed facts may add candidates or disagreement; they
   cannot authorize a negative, demotion, clean receipt, or safe conclusion.
7. **Adaptive attention follows exact coverage debt.** Static blanket agent-count
   increases are not a substitute. Program Facts and attention policy remain
   separate mechanisms and future experimental factors.
8. **Terminal negatives require independent authority.** Model confidence,
   bounded search, failed tooling, precedent, trust tags, provider declarations,
   or missing output cannot close a candidate by themselves.
9. **Reports are projections.** Report agents cannot mint, delete, silently omit,
   rerate, or legitimize unsupported dispositions. Verification precedes report
   authority.

### August research constraints

- **Rule 0: enumerate mechanically, decide semantically.** Python must enumerate
  every mechanically discoverable obligation. LLM workers receive bounded
  shards of about five rows only when disposition requires protocol intent;
  merged results reconcile exactly against the full worklist.
- **A zero scan is dead instrumentation, not a clean result.** Every mechanical
  deriver emits `sites_scanned` and `candidates_emitted`, and every harvesting
  gate has a real producer-output fixture plus a non-zero assertion where work
  was expected.
- **Fuzz and symbolic PASS are not favorable security evidence.** Only an
  authenticated counterexample may raise evidence strength. Mutation may test
  invariant vacuity or deriver liveness, but may not stand in for a recall
  benchmark.
- **Research confidence is preserved.** `CONFIRMED` work may proceed against the
  current tree; `REPORTED` is reverified before action; `VERIFY-FIRST` is
  rederived before code changes; `INFERRED` remains a hypothesis.
- **Improvement must replace legacy complexity.** The reviewed change had added
  about 370,000 lines with none removed, enlarged three god-functions, and left
  24 modules / 39,824 lines unreachable. Each P-item deletes or replaces its
  legacy counterpart; driver size and god-function length do not increase
  without a separately reviewed exception.

### Do not build

The August decision layer rejects these attractive but unsupported expansions:

- mutation as a recall benchmark (mutation remains allowed for vacuity and
  positive-control checks);
- the Certora AutoProver agent layer;
- a standalone symbolic-execution dependency instead of the narrow Foundry
  refutation lane;
- fan-out-then-debate on one question (parallel scope partition and bounded
  worklist sharding remain required);
- prompt-only “double-check” scaffolding;
- an SMTChecker migration.

## Orchestration and execution

10. **The Python V2 driver solely sequences audit phases.** Do not manually
    orchestrate recon, breadth, depth, verification, or report phases.
11. **Instantiate templates; do not inject replacement methodology.** Workers
    read their complete versioned prompt/methodology resources.
12. **File presence is not completion.** A worker result becomes authoritative
    only after immutable input binding, owned execution closure, semantic
    validation, exact output-prestate/CAS checks, and parent incorporation.
13. **Failure remains debt.** Missing, malformed, stale, capped, timed-out,
    unsupported, inaccessible, or ambiguous work cannot be translated to clean
    absence or silent phase success.
14. **Retry and resume preserve generation identity.** A retry cannot reuse
    mismatched route or inputs; resume mismatch stops before mutation unless a
    distinct-destination migration is explicitly authorized.

## Backend and platform behavior

15. **Claude and Codex share logical denominators and authority semantics.** PTY,
    direct-exec, MCP availability, sandboxing, and OS primitives may differ, but
    completion, fallback, debt, and evidence meaning do not.
16. **Requested route is not actual route.** Backend, model, effort, service
    tier, fallback, and terminal provider outcome are observed and recorded. An
    unobservable result is `UNKNOWN_BLOCKED`, never inferred from the command.
17. **Fallback changes are explicit generations.** Capacity, authentication,
    safety, or availability fallback cannot silently substitute a semantic tier.
18. **Cross-platform differences are adapters.** Windows Job Objects and POSIX
    process/session primitives implement one lifecycle contract; platform
    variance cannot weaken it.
19. **Current production installation is Windows-only.** The macOS bootstrap is
    source-development support, not native runtime proof. Linux and macOS become
    supported only after a POSIX dispatcher plus keeper/recovery adapter passes
    clean install, start, stop, crash recovery, and resume validation. Until
    then, public commands fail explicitly before mutation on those platforms.

## Packaging and storage

20. **The repository is the editable source of truth.** Installed trees,
    development checkouts, caches, and packaged runtimes are distinct. Installed
    bytes are immutable and receipt-bound.
21. **Generated audit artifacts never enter target source directories.** They
    live under an owned scratch/output root with explicit retention and cleanup.
22. **Bound both returned data and backing storage.** Tail truncation does not
    satisfy a spool quota. Logs, transcripts, ledgers, and temporary files need
    explicit capacity and lifecycle policies.
23. **Cleanup evidence is reference-bound.** Age or terminal state alone is not
    deletion authority. Retention changes preserve exact replay, parent/path
    semantics, concurrent readers, crash recovery, and rollback.

## Evaluation and privacy

24. **Ground truth and the neutral evaluator remain out of tree.** The public
    branch contains interfaces, schemas, and blinded export support, not private
    answers or evaluator control.
25. **Benchmarking is deferred, not deleted.** This goal validates the improved
    tool. Comparative recall, precision, report-quality, and cost benchmarking
    against old Plamen happens later under a separate goal.
26. **Runtime E2E audits are validation, not benchmarking.** They may exercise
    the tool without exposing or scoring against grader-only ground truth.

## Historical corrections

- The July observation that seven named architecture artifacts were absent is
  superseded by their current presence. Presence does not prove semantic
  completeness or runtime reachability.
- The failed private-target p18 run is sealed failure evidence. Its staged output must not
  be repaired in place or presented as a completed audit.
- Scoped green tests remain scoped. No test count, phase gate, source hash, or
  generated report expands into whole-tool acceptance without its required
  package, backend, platform, fault, and E2E evidence.
- The earlier claim that producer output caps were the highest-leverage recall
  fix is corrected: measured caps were non-binding, while under-enumeration was
  dominant. Severity-prioritization language still goes; Rule 0 is the repair.
- Off-by-one analysis is already owned by the Validation Sweep; its observed
  failure is delivery/enumeration, not an absent method class.
- Narrowing-cast coverage is not globally absent. It exists in four non-EVM
  ecosystems; the verified gap is specifically total in EVM.
- The P-14 prototype was cheap and discriminating but did not prove a missed
  real bug, and one target produced 81 obligations against a historical cap of
  15. Treat it as throwaway evidence, not production implementation.
