# Application-coverage and lifecycle evaluation plan

Status: normative evaluation contract
Production runner access: ground-truth blind
Current evidence ceiling: local B0/user-run mechanics until all B1 external
authorities exist

## 1. Questions

The evaluation program answers separately:

1. Can the current method catalog express the ground-truth issue?
2. Was the relevant method and subject scheduled?
3. Was every required method step actually applied?
4. Was the issue discovered?
5. If discovered, where was it retained, challenged, verified, demoted, merged,
   dropped, or reported?
6. Was the final validity, severity, root-cause grouping, and report treatment
   correct?
7. What resource cost and operational failure accompanied the result?

It must not collapse “not reported” into “not found,” or “applied” into
“correctly judged.”

## 2. Independence and prohibited inputs

The evaluator lives in the separately owned, out-of-tree
`plamen-eval-control` repository, represented here by the portable role
`<OUT_OF_TREE_EVALUATOR_REPOSITORY>`. Its checkout location is host-configured
and non-normative. Audit workers, RAG systems, providers, drivers, and
production exporters cannot read:

- ground-truth reports or annotations;
- private case locks or expected issue/root counts;
- grader labels, matches, or reviewer decisions;
- benchmark/private case identifiers;
- evaluation keys; or
- prior scored outputs.

The public audit workspace receives only an opaque public case token and public
run policy. Ground-truth paths are explicit forbidden inputs during terminal
preparation.

The evaluator imports a sealed public RunBundle before joining any private
case lock. System and treatment labels remain blinded until matches, lifecycle
observations, novelty decisions, severities, and report-quality votes are
sealed.

No implementer may be the sole grader of their change. Corpus, launch,
review/adjudication, scoring, and publication authorities remain separated as
specified by the evidence profile.

The private campaign lock also freezes:

- the catalog/method cutoff before any held-out report is opened;
- model pretraining-exposure class and uncertainty;
- exclusion of examples used to create or revise a method, gate, prompt,
  provider, fixture, or policy;
- exact external-query and retrieval logs;
- retrieval-enabled and retrieval-disabled treatment labels; and
- a protocol-family exclusion receipt covering forks, variants, and revisions.

Missing or unverifiable leakage evidence marks the affected comparison
non-comparable; it does not become a clean campaign.

## 3. Evidence profiles

### Synthetic v1

`plamen.run-bundle.synthetic.v1` remains byte-for-byte compatible and proves
only deterministic B0 control-plane mechanics.

### Real-audit v2

`plamen.run-bundle.real-audit.v2` records a real audit without ground truth. Its
public objects include:

- run and public-case manifest;
- committed phase events;
- distinct candidate claims;
- lossless native-ID and alias lineage;
- raw-output object index;
- final report projection;
- harvest/debt receipt; and
- bundle index and seal.

The exporter is a recorder, not a grader. A malformed production row is
preserved as minimally parsed evidence plus debt or makes export fail if even
opaque preservation is impossible. It is never silently dropped.

### Trust labels

- `USER_RUN`: prepare-only/user-operated workflow; integrity-bound but not B1.
- `B0_LOCAL`: local fixture/synthetic mechanics.
- `B1_INCOMPLETE`: real profile present but one or more governed authorities,
  signatures, corpus, launcher, reviewers, comparator, or measurements absent.
- `B1_COMPLETE`: every precommitted external and local authority validates.

Schema validation can never promote a user run or B0 result to B1.

## 4. Corpus

The governed corpus is stratified by:

- publication time;
- audit firm/source;
- severity;
- protocol and subsystem category;
- vulnerability rarity and reasoning type;
- source size and architecture;
- EVM, Solana, Aptos, Sui, Soroban, Daml, Go L1, and Rust L1;
- clean-fixed, vulnerable, and precision-safe/adversarial controls; and
- evidence/report quality.

Required tracks are:

1. chronological professional-report holdout;
2. EVMbench or another independently governed EVM track;
3. non-EVM real and independently seeded suites;
4. clean/fixed/adversarial precision controls; and
5. future-time shadow holdout.

Repository, firm, family, and temporal splits are group-aware. Forks,
near-duplicates, audit revisions, and issue variants remain in one split.

Any case used to design a method, gate, provider, fixture, or policy is
regression-only. Spectra is always regression-only. DODO and Spectra are
user-run post-handoff acceptance workflows, not B1 tuning or headline evidence.

## 5. Ground-truth annotation

Two independent annotators and an adjudicator freeze:

- GT issue and root-cause identities;
- reportability and severity;
- generic semantic operators;
- exact relevant entity/relation/axis classes;
- environmental and external premises;
- evidence/proof needed;
- ecosystem knowledge needed;
- reasoning depth;
- tool needs;
- likely failure point;
- earliest stage at which the issue is expressible;
- distinct variants versus aliases;
- clean/fixed expectations; and
- annotation confidence and disagreement.

Annotations describe reusable operators and evidence, never target-specific
instructions for audit workers.

GT issue identity and root identity are private. Production canonical finding
IDs, titles, locations, and audit clusters never substitute for them.

## 6. Lifecycle localization

For each applicable GT issue, the evaluator freezes two related but distinct
views. The outcome lifecycle is:

- `EXPRESSIBLE`
- `SCHEDULED`
- `APPLIED`
- `DISCOVERED`
- `RETAINED`
- `VERIFIED`
- `REPORTED`

Each milestone is `YES`, `NO`, `UNKNOWN`, or `NOT_APPLICABLE` under closed
rules and exact production evidence.

The mutually exclusive primary miss localizer uses the finer eight-step chain:

1. `METHOD_CONTENT` — the normative catalog expresses the generic operator;
2. `COMPILER_APPLICABILITY` — selectors make it applicable to the exact case;
3. `TARGET_RELATION_ENUMERATION` — relevant targets, relations, paths,
   boundaries, and pairs are in the denominator;
4. `SCHEDULE` — exact obligations reach an immutable roster;
5. `VALID_APPLICATION_RECEIPT` — required steps and target/evidence coverage
   validate;
6. `INTERMEDIATE_CLAIM` — a materially matching claim/candidate is emitted;
7. `JUDGMENT_DISPOSITION` — mechanism, premises, harm, proof, and severity are
   independently judged without unauthorized negative authority; and
8. `LIFECYCLE_REPORT_SURVIVAL` — the exact identity survives harvest,
   verification, skeptic, report index, and final assembly.

Each step is `YES`, `NO`, `UNKNOWN`, or `NOT_APPLICABLE` with exact evidence
IDs. The primary miss is the earliest applicable `NO`; an earlier `UNKNOWN`
makes the primary class unknown and prevents a later success from hiding it.
The seven outcome milestones remain reported for continuity but cannot replace
the eight-step diagnosis. Secondary losses remain counted so one successful
alias cannot hide another wrong-safe or dropped path for the same root.

Wrong-safe requires all of:

1. a materially matching candidate;
2. a positive GT issue;
3. a producer or downstream negative/demotion/exclusion;
4. inadequate premise/evidence authority for that negative; and
5. exact lifecycle lineage tying the decision to the candidate.

An absence of output is not automatically wrong-safe; it localizes earlier.

## 7. Candidate, alias, and root identity

The real RunBundle preserves:

- every distinct audit claim;
- source/native candidate IDs from every phase;
- producer and consumer artifacts;
- applied and proposed alias/merge edges;
- candidate lifecycle and report projection; and
- export ambiguity/debt.

Audit alias classes are audit-local and non-GT. The private evaluator later
decides whether they fragment one GT root or incorrectly merge incompatible
roots.

Novel valid findings remain valid-output evidence. They are not forced into a
known GT match or counted as known-GT false positives.

## 8. Metrics

### Recall and application

- expressible issue/root denominator;
- obligations generated and scheduled;
- valid application receipts;
- target coverage;
- relation, path, boundary, and paired-operation coverage;
- required-step coverage;
- unresolved material work;
- independently sampled false-application rate;
- scheduled / expressible;
- applied / scheduled;
- discovery issue and root recall;
- material-harm recall;
- composition/seam recall;
- ecosystem-knowledge and ecosystem-semantics recall;
- retention recall;
- verification recall;
- report recall;
- found-to-report survival;
- per-stage loss rate;
- false-safe/unsupported-negative count and reopen rate; and
- missing/invalid/unknown method-step rate.

### Precision and proof

- adjudicated valid candidate rate;
- known-GT precision, reported separately from all-output validity;
- novel-valid rate;
- unsupported proof-grade claim count;
- external-premise and oracle-scope errors;
- clean/fixed false-positive rate; and
- unadjudicated-output debt.

### Severity

- exact and within-one-tier accuracy;
- overcall and undercall distributions;
- catastrophic undercall rate;
- impact and likelihood calibration; and
- unsupported inflation/demotion rate.

### Fragmentation and report quality

- candidates per GT issue/root;
- effective alias classes per root;
- duplicate/root fragmentation;
- incorrect merge count and cross-root impurity;
- consequence/remediation loss during consolidation;
- report body/appendix/exclusion correctness;
- factual/evidence completeness;
- clarity, actionability, and remediation quality; and
- assurance/debt disclosure.

### Exact survival

- discovery harvest entry/exit and missing-ID reconciliation;
- verifier queue entry and verifier exit;
- skeptic entry and exact decision;
- report-index admission;
- final body/appendix/exclusion/unresolved placement;
- unsupported demotion or exclusion;
- candidate/alias/constituent reconciliation loss; and
- fixed-input-state to final-assembly set equality.

### Efficiency and operations

- input/output tokens;
- tool calls and external processes;
- wall/CPU time;
- peak memory and artifact bytes;
- channels, attempts, retries, amendments, and concurrency;
- timeout/cancellation/crash/resume outcomes;
- provider/tool unavailable and stale-reuse rates; and
- cost per unique valid root and marginal root.

Every metric publishes its exact denominator, unknown/debt count, aggregation
policy, and confidence interval where applicable.

Issue-level tables are published alongside case aggregates. A metric with a
denominator below its precommitted minimum is descriptive only; it cannot
promote a treatment. `UNKNOWN` is reported explicitly and never removed from
the denominator to improve a score.

## 9. P0-P5 staged screen

The original staged screen isolates three discovery hypotheses:

| Cell | Context | SOP | Seam roles |
|---|---|---|---|
| P0 | current retrieval | current | current |
| P1 | full/component-complete bundle | current | current |
| P2 | current retrieval | compact SOP | current |
| P3 | current retrieval | current | explicit seams |
| P4 | full/component-complete bundle | compact SOP | explicit seams |
| P5 / X-PASHOV | exact pinned Pashov V3 | Pashov | Pashov |

P0-P4 is a screen, not a factorial. P5 is an external comparator, not another
Plamen treatment.

The full Plamen factorial contains all eight `F000` through `F111`
combinations of:

- full/component-complete context;
- compact SOP; and
- explicit seam roles.

Staged and factorial corresponding cells must bind identical run contracts.
Staged baseline is P0; factorial baseline is F000; P5 compares to P0 under a
separate precommitted comparator policy.

## 10. Program-facts and adaptive-attention experiment

Program facts (G) and adaptive attention (A) are measured as a separate 2x2:

- `G0A0`: neither treatment;
- `G1A0`: program facts only;
- `G0A1`: adaptive attention only; and
- `G1A1`: both.

The interaction term is reported. A gain from adaptive scheduling cannot be
attributed to graph enrichment, and vice versa.

Graph-off and graph-on use the same baseline source/method obligation
denominator. Graph facts can add candidates, evidence, disagreement, or
priority but cannot remove baseline work.

Adaptive and fixed policies use equal frozen semantic inputs and matched-total
resource reservations in the primary comparison. Per-agent/cost-observed
analysis is secondary.

## 10.1 Typed-authority ablations

The following factors are ablated separately from P0-P5 and from graph/adaptive
attention:

1. finding/candidate lifecycle authority;
2. premise and disposition authority;
3. MethodCard obligation compilation and application receipts;
4. typed program-fact provider facts; and
5. multi-hop and follow-up scheduling.

Each ablation changes exactly one predeclared authority/treatment and preserves
source, methods, backend, budgets, tools, exporter, and evaluator. It reports
application, false-safe, survival, precision, fragmentation, severity, report
quality, and cost deltas. Disabling an authority never grants a negative; the
control uses the legacy path plus explicit treatment debt.

## 11. Fairness and repetition

Within a comparison freeze:

- source snapshot and public instructions;
- exact build, installation, launch, and expected-artifact instructions;
- model/provider version and capability tier;
- tool versions and permissions;
- context/SOP/role artifact digests;
- total token/tool/process/time budget;
- seed policy and repetitions;
- backend and mode;
- RAG exposure;
- measurement policy; and
- exporter/evaluator versions.

Use at least three independent repetitions for screening and the larger
precommitted count required by B1 power analysis. Case × cell × repetition is
enumerated exactly. Omissions, duplicates, foreign jobs, or seed drift
invalidate the campaign.

For projects too large for useful full-source density, “full context” means a
precommitted component-complete architectural bundle, not arbitrary truncation.

Repetitions are averaged within case before paired case deltas. Comparisons use
two-sided 95% intervals and an oriented promotion bound. Family-wise or false
discovery control is declared before reading outcomes.

Reviewer effort is measured as sealed review/adjudication time and decision
count per issue/candidate. It is reported, not used to change a production
schedule.

## 12. Blinded review

Independent reviewers receive opaque candidate and GT labels, sanitized source
context, claim/evidence/lineage, and applicable GT text without system or cell
identity.

Separate packets cover:

- candidate-to-issue/root matching and partial credit;
- lifecycle observations;
- severity;
- novelty; and
- report quality.

Reviewers seal votes independently. Adjudication sees disagreements only after
both votes are sealed. Unblinding occurs only after all match, lifecycle,
novelty, severity, and quality artifacts are frozen.

## 13. Pashov adapter

Pashov V3 input is accepted only through a pinned, versioned adapter and
loss-accounting receipt. The external authority must freeze:

- exact public release/archive digest and provenance;
- license;
- parser and schema digests;
- execution instructions;
- budget mapping; and
- output completeness rules.

One emitted Pashov finding becomes one candidate unless Pashov supplies exact
applied alias authority. Missing or malformed output is debt, not zero
findings. Local format fixtures do not prove the independently operated P5 run
or fairness.

The comparator protocol additionally requires:

- report blocking until both pre-report raw outputs are sealed;
- preservation and publication of permitted raw outputs and parser loss;
- separate pre-report candidate scoring and final-report scoring;
- blinded root-cause and partial-match adjudication;
- exact product, model, method, adapter, and run version/date;
- disclosure of implementer/operator conflicts and unavailable evidence;
- the same issue-level tables, reviewer-effort accounting, and resource
  normalization used for Plamen; and
- `NON_COMPARABLE`, never zero, when the system, version, artifacts, or
  operation cannot be independently reproduced.

## 14. RunBundle validation

Real-audit v2 uses strict schemas for:

- public/private case locks;
- run manifest;
- phase events;
- candidate findings and lineage;
- raw output index and objects;
- report projection;
- harvest receipt and bundle index;
- public/private isolation receipts;
- blind review;
- lifecycle adjudication;
- score and comparison; and
- external/Pashov adapter receipts.

Validation rejects unknown keys, duplicate JSON keys/IDs, noncanonical paths,
symlink/junction/reparse/hardlink aliases, missing objects, digest mismatch,
ambiguous identity, forbidden private fields, incomplete lineage, early
unblinding, signature/principal conflicts, and profile confusion.

Synthetic v1 validation remains unchanged.

## 15. Resume and preservation

Before any user or governed run:

1. hash-seal prior scratchpads, reports, logs, and archives;
2. create a fresh isolated workspace;
3. bind source, mode, backend, config, methodology, tools, public case token,
   and forbidden-input proof;
4. launch only through the authorized user-run or B1 path;
5. require exact resume authority and zero semantic mutation/relaunch for a
   completed run; and
6. export only after the driver is terminal.

Export is resumable through staging and content-addressed objects. It never
overwrites a sealed bundle in place.

## 16. Promotion gates

No treatment is promoted unless:

- zero silent candidate/identity/lifecycle/report loss;
- zero unauthorized safe/negative closure;
- zero proof-grade claim without executed/bound evidence;
- exact denominators and no hidden remainder;
- application completeness improves or does not regress under the
  precommitted bound;
- raw, retained, verified, and report recall meet the promotion bound;
- clean/fixed precision does not regress beyond the bound;
- severity, fragmentation, and report-quality constraints pass;
- matched resource budgets and operational failure constraints pass;
- exact resume, deterministic export, and cross-OS/backend parity pass;
- future-time shadow constraints pass; and
- independent review/publication authority validates the evidence.

A regression fixture recovering its motivating issue cannot satisfy these
gates by itself.

## 17. B0 versus B1 completion

Local implementation can complete schemas, harvesting, bundle
validation/sealing, lifecycle localization, blind rendering, deterministic
scoring/comparison, Pashov format fixtures, and USER_RUN/B0 workflows.

B1 remains externally blocked until an independent organization provides:

- governed unpublished corpus and private GT;
- secure OS/container/VM launcher and denial probes;
- distinct corpus, launch, reviewer/adjudication, score, and publication
  authorities/keys;
- exact comparator provenance and operation;
- provider credentials and enforceable measurements; and
- the complete precommitted multi-case/multi-seed execution campaign.

The correct final local claim is “B0/user-run evaluation mechanics complete;
B1 externally blocked,” never “recall improvement proven.”
