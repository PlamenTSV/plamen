# Work-unit scheduler architecture

Status: normative scheduling and execution contract
Migration: semantic labels and typed work authority over the existing phase
sequence; not a big-bang phase rewrite

## 1. Purpose

The driver remains deterministic and resumable, but completion authority moves
from phase-local status markers and worker prose to exact semantic work plans,
immutable rosters, execution receipts, joins, and stop receipts.

Operational phases remain useful batching and UI boundaries. Their semantic
labels are:

1. acquire and model;
2. enumerate;
3. discover;
4. expand and challenge;
5. verify and adjudicate;
6. reconcile; and
7. render.

Parallelism is used for decomposable evidence work. Inventory, lifecycle,
negative disposition, severity, deduplication, report projection, and
generation-to-generation joins remain deterministic central operations.

## 2. WorkPlan envelope

Every model or native work unit binds:

- run, generation, source snapshot, scope, configuration, and methodology
  identities;
- operational phase and semantic stage;
- method IDs, versions, steps, and exact subject/relation/obligation IDs;
- exact input artifacts and hashes;
- required provider/evidence capabilities and fidelity;
- backend, model tier, tool, child, network, environment, and process policy;
- one attempt-specific read-only input view;
- one exclusive staged output assignment and output schema;
- materiality, uncertainty, and scheduling reason;
- retry, completion, and resource policies;
- parent obligation and predecessor receipt identities;
- PhaseIO contract and artifact-ledger bindings; and
- stable work-unit identity.

Work-unit identity excludes scheduling ordinal, runtime batch, and maximum
concurrency. Those affect execution order, not semantic work.

A retry retains the semantic work identity and gets a new attempt identity.
Changing source, method, subject set, backend capability, model policy, graph
treatment, or semantic budget requires targeted invalidation or a new
generation.

## 3. Obligation and channel state

The scheduler projects immutable receipts into these semantic obligation
states:

- `UNASSIGNED`
- `ASSIGNED`
- `EVIDENCE`
- `DISPUTED`
- `DEBT`
- `CLOSED`

`CLOSED` requires the obligation-specific independent authority. A worker
cannot mint it.

A channel groups compatible obligation slices with:

- exact obligation and evidence-slice IDs;
- distinct role and methodology assignment;
- source and provider treatment;
- predecessor receipts;
- worker/runtime policy; and
- resource grant.

Channel identity is content-addressed from those semantic fields. A generic
`SAFE`, `NO_FINDING`, `NO ISSUE`, or equivalent worker response becomes a
retained negative proposal and moves the affected obligation to `DISPUTED`. It
does not receive coverage, novelty, or closure credit.

## 4. Immutable roster and amendments

Before dispatch, the driver freezes:

- the exact obligation denominator;
- the base channel roster;
- stable channel ordering;
- resource reservations; and
- the roster digest.

New or reopened work never rewrites the base roster. It creates a
content-addressed `RosterAmendment` binding:

- prior effective roster digest;
- newly scheduled channels;
- exact reason and predecessor receipts;
- resource reservations;
- sequence and amendment identity; and
- resulting effective roster digest.

Missing, duplicate, reordered, forked, or torn amendments fail closed. Sequence
validates the chain but is excluded from channel identity.

## 5. Scheduling inputs

Allowed scheduling inputs are exact or explicitly lower-bound:

- uncovered method obligations and steps;
- uncovered axes, components, source entities, relations, state symbols, and
  boundary classes;
- provider disagreement, unsupported capability, and coverage debt;
- open candidate aliases and constituents;
- premise and independent-challenge debt;
- chain pairs and dependency generations;
- verifier queue items and late candidates;
- application, evidence, and lifecycle receipts;
- assurance debt; and
- frozen resource reservations and capability availability.

Forbidden scheduling inputs include:

- raw finding count;
- Markdown finding-block count;
- severity count;
- average or median finding yield;
- protocol-specific ground truth;
- evaluator identity or outcome; and
- a model's assertion that coverage is complete.

Priority may use materiality, uncertainty, unresolved-obligation criticality,
distinct evidence value, and capability match. Graph facts may raise priority
or add work, but cannot lower the legacy floor or authorize a negative.

## 6. Adaptive expansion

Adaptive attention is a deterministic controller over the same work contract.
It:

1. validates the frozen plan inputs;
2. compiles the exact obligation denominator;
3. replays authoritative receipts;
4. derives obligation states;
5. groups uncovered compatible obligations into diverse channels;
6. enforces role/evidence/source/method/provider heterogeneity;
7. reserves the entire resource grant before publication;
8. emits an immutable base roster or append-only amendment;
9. dispatches ready channels;
10. joins their WorkerTransactions centrally;
11. recompiles only after a semantic join; and
12. emits a clean, bounded-debt, or halt stop receipt.

Static blanket agent-count increases are not the adaptive policy. Total channel
caps and maximum concurrency are separate. Changing concurrency must produce
the same semantic roster, reservations, joins, and stop classification.

### Follow-up trigger contract

Follow-up is closed to the following generic triggers:

| Trigger | Denominator and predecessor | Stop/debt rule |
|---|---|---|
| new relation or composition edge | newly validated edge × affected subject; fact/chain receipt | stop when every affected pair is dispositioned; otherwise relation debt |
| unresolved external premise | exact premise/candidate set; research/challenge receipt | stop on challenged evidence decision; otherwise external-premise debt |
| reachability dispute | disputed claim/path set; verifier/provider receipts | stop on scoped independent decision; otherwise reachability debt |
| supported mechanism with unresolved harm | mechanism-confirmed candidate set; mechanism receipt | stop on material-harm decision; never infer safe |
| tool/model disagreement | exact conflicting fact/claim set; both receipts | stop on independent reconciliation; otherwise conflict debt |
| severity inconsistency | affected finding/alias/constituent set; severity decisions | stop on independent severity decision; otherwise adjudication debt |
| provider low fidelity or debt | affected capability/subject set; provider receipt | stop on adequate replacement evidence or explicit bounded debt |
| writer-created claim | exact new claim/content; writer output receipt | stop after normal discovery/verification path; writer has no authority |
| late candidate | post-roster candidate set; producer receipt | stop after append-only roster amendment and lifecycle join |
| unresolved alias or constituent | exact cluster membership; alias/dedup receipt | stop on lossless set decision; otherwise retain all members |
| chain generation successor | exact predecessor generation and new pairs | stop after sequential generation join or bounded tail debt |

Every trigger compiles a content-addressed amendment identity from its exact
denominator and predecessor receipts, reserves its own budget, and declares a
completion predicate. A cap or unavailable capability records every omitted
identity as typed debt; it never silently suppresses the amendment.

## 7. Resource policy

Resource grants cover:

- channels and concurrent channels;
- input files and bytes;
- prompt/context and output bytes;
- model tokens or a conservative full reservation when telemetry is
  unavailable;
- tools and child processes;
- wall and CPU time;
- retries;
- provider facts and graph radius; and
- staged artifacts.

A channel that cannot reserve its full declared grant is not dispatched. Its
obligations become exact budget or capability debt.

Unused budget is not reassigned after observing model findings in a controlled
experiment. Overflow uses deterministic stable ordering, persists every omitted
identity, and resumes backlog-first.

## 8. WorkerTransaction boundary

The driver arms execution before creating any child:

1. validate WorkPlan and roster membership;
2. acquire the attempt lease and owned process scope;
3. materialize the attempt-specific immutable input view;
4. register exact allowed outputs and output prestates;
5. launch through the selected Claude, Codex, PTY, or native adapter;
6. supervise the complete descendant process scope;
7. terminate and join on timeout, cancellation, error, or parent death;
8. validate output schema, file denominator, mutation scope, and attempt CAS;
9. stage incorporation;
10. revalidate inputs and output prestates;
11. incorporate exact bytes through PhaseIO;
12. record artifact and transaction receipts; and
13. prove process-scope zero before the attempt becomes terminal.

The worker never receives a canonical output path and cannot publish directly.
An adapter reports transport/execution facts; it cannot authorize a finding,
negative closure, merge, severity, report state, or phase completion.

PTY output-ready or end-turn is provisional until descendant closure and exact
incorporation succeed.

## 9. Central join

A phase join reconciles:

- base roster and every amendment;
- one terminal attempt/transaction state per scheduled channel;
- committed output and artifact-ledger bindings;
- cancellations, failures, retries, and debt;
- exact obligation application and outcome rows;
- newly emitted candidates and obligations; and
- downstream amendments.

A join may pass with debt only when every scheduled channel is terminal and
every unresolved obligation is represented in typed debt. It passes cleanly
only when the clean-stop predicate is satisfied.

A status marker, Markdown file, model exit code, or partial worker pool result
is not a semantic join.

## 10. Stop semantics

### Clean stop

Clean stop requires:

- exact denominator authority;
- every mandatory obligation `CLOSED`;
- every channel and amendment terminal and replayable;
- no unresolved, disputed, invalid, stale, contradictory, overflow, or
  capability debt;
- no unauthorized negative;
- exact PhaseIO/artifact/WorkerTransaction joins; and
- no active or uncertain process scope.

### Bounded stop with debt

Budget exhaustion, unavailable optional capability, retry exhaustion,
cancellation, or declared bounded degradation may stop the phase only with a
receipt enumerating every unresolved identity, reason, retry state, and
assurance projection. It cannot claim full coverage.

### Halt

Halt is required when semantic authority cannot be preserved, including a
corrupt/forked roster chain, snapshot mismatch, ambiguous canonical ownership,
uncontainable late writer, artifact-ledger conflict, or inability to publish
the lossless debt denominator.

Repair-then-degrade does not override these preconditions.

## 11. Resume and recovery

Resume:

1. validates run/generation/source/config/methodology/backend policy;
2. replays the base roster and amendments;
3. replays PhaseIO, leases, attempts, worker, incorporation, and join receipts;
4. accepts a completion only when exact current artifact bytes and ledger
   authority agree;
5. terminates or quarantines abandoned attempts;
6. reconstructs a missing post-commit receipt only from exact immutable
   evidence;
7. reuses valid completed work;
8. schedules only missing, invalid, reopened, or new obligations; and
9. emits amendments without invalidating unrelated siblings.

An exact completed resume launches no model/tool process and mutates no semantic
artifact. A mismatch stops before model launch and requires explicit new-run or
migration authority.

### Multi-output projection recovery

Every output member has durable `PENDING`, `STAGED`, `INCORPORATED`, and
`RECEIPTED` progress bound to one transaction, immutable CAS object, output
prestate, and member digest. The transaction is complete only when every
declared member and the aggregate receipt are `RECEIPTED`.

After a crash, recovery validates the transaction, immutable CAS, exact member
denominator, current output prestates, prior incorporation receipts, and
artifact authority. It then rolls forward only missing members and receipts.
It never best-effort rolls back already incorporated authority, replays a
member whose bytes or prestate differ, or treats a partially projected bundle
as complete. An irreconcilable member quarantines the transaction and leaves
all affected identities visible.

## 12. Phase behavior

- Recon schedules source/model/dependency/environment obligations.
- Breadth is the first adaptive enforcement cutover: axes × components ×
  relations × method steps, packed into small diverse channels.
- Rescan and per-contract work target exact uncovered obligations rather than
  duplicate broad passes.
- Semantic-invariant work publishes typed invariants and conflict debt.
- Depth expansion follows unresolved mechanism, premise, relation, and
  evidence obligations.
- Repair is a content-addressed amendment tail, not an anonymous fixed batch.
- Skeptic and negative challenge remain independent from their producers.
- Chain work parallelizes within a dependency generation; generations join
  sequentially.
- Verification preserves queue/work-plan authority and appends late-candidate
  amendments.
- Reporting is deterministic and centrally joined; report writers do not
  create lifecycle decisions.

## 13. Backend, ecosystem, and OS parity

Claude PTY, Claude headless, Codex, and native tools receive the same semantic
roster and normalized resource grants. Transport-only instructions may differ.
A missing backend capability becomes debt; it does not silently change work
selection or add agents.

Every supported ecosystem and both SC/L1 pipelines use the same WorkPlan,
roster, transaction, join, stop, and resume semantics. Ecosystem selectors and
tools affect capability availability and work content, not authority rules.

Windows uses reviewed Job Object/process and path containment; Linux uses
reviewed process-group/cgroup semantics; macOS uses its proven subset. An
unsupported process-scope guarantee is typed unavailable debt, never a raw
launcher bypass.

## 14. Ground-truth isolation

Ground-truth files, identities, benchmark labels, evaluator keys, and
adjudicated outcomes are forbidden from:

- project workspaces;
- source/scope/config artifacts;
- environment;
- WorkPlans and rosters;
- prompts;
- provider plans and graph slices;
- worker output contracts;
- logs and receipts; and
- RunBundles before the neutral grader's authorized join.

Terminal preparation proves forbidden inputs are excluded and prior audits are
sealed before any user-run acceptance audit.

## 15. Acceptance

Scheduler acceptance requires:

- stable-ID and roster/amendment property tests;
- exact denominator reconciliation;
- concurrency-1/concurrency-N semantic equivalence;
- no raw finding-count scheduling reachability;
- generic negatives becoming disputed proposals;
- exact resource reservation and overflow;
- crash at every arm/stage/CAS/incorporation boundary;
- timeout, cancellation, process death, parent death, retry, and no-late-write
  evidence;
- same-output and disjoint-output concurrency;
- exact resume with no relaunch/mutation;
- PhaseIO-only publication;
- assurance-visible bounded stops;
- Claude/Codex/native normalized parity;
- SC/L1, mode, ecosystem, tool-present/absent, and cross-OS matrices;
- clean/source-archive/read-only-install/package evidence; and
- neutral equal-budget adaptive A/B evidence before replacing the fixed policy.

The current `QueueWorkPlan`, verifier roster, semantic work plan,
WorkerTransaction, PhaseIO, and adaptive modules are migration substrate. Their
presence alone does not prove the generic scheduler is fully cut over.
