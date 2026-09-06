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

## Packaging and storage

19. **The repository is the editable source of truth.** Installed trees,
    development checkouts, caches, and packaged runtimes are distinct. Installed
    bytes are immutable and receipt-bound.
20. **Generated audit artifacts never enter target source directories.** They
    live under an owned scratch/output root with explicit retention and cleanup.
21. **Bound both returned data and backing storage.** Tail truncation does not
    satisfy a spool quota. Logs, transcripts, ledgers, and temporary files need
    explicit capacity and lifecycle policies.
22. **Cleanup evidence is reference-bound.** Age or terminal state alone is not
    deletion authority. Retention changes preserve exact replay, parent/path
    semantics, concurrent readers, crash recovery, and rollback.

## Evaluation and privacy

23. **Ground truth and the neutral evaluator remain out of tree.** The public
    branch contains interfaces, schemas, and blinded export support, not private
    answers or evaluator control.
24. **Benchmarking is deferred, not deleted.** This goal validates the improved
    tool. Comparative recall, precision, report-quality, and cost benchmarking
    against old Plamen happens later under a separate goal.
25. **Runtime E2E audits are validation, not benchmarking.** They may exercise
    the tool without exposing or scoring against grader-only ground truth.

## Historical corrections

- The July observation that seven named architecture artifacts were absent is
  superseded by their current presence. Presence does not prove semantic
  completeness or runtime reachability.
- The failed DODO p18 run is sealed failure evidence. Its staged output must not
  be repaired in place or presented as a completed audit.
- Scoped green tests remain scoped. No test count, phase gate, source hash, or
  generated report expands into whole-tool acceptance without its required
  package, backend, platform, fault, and E2E evidence.
