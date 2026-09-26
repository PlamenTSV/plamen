# Gate / repair architecture: principle, defect history, research basis

> **Audience**: anyone changing a phase gate, a validator, a parser, or adding a
> deterministic repair to the Plamen driver.
> **Status**: active design guidance. Sections 1-3 are binding; section 6 is an
> open rollout question that is deliberately NOT yet decided.
> **Scope**: the Python DRIVER's handling of its own artifacts. This document
> says nothing about audit methodology, which is governed by
> `rules/post-audit-improvement-protocol.md` Part 0.

---

## 0. Why this document exists

Between runs 34 and 40 of the SC pipeline, eleven distinct defects were found
and fixed. On review, roughly seven shared a single shape, and the shape was not
what it first looked like. The cost of rediscovering that shape is high: each
instance cost a full end-to-end run (30-120 minutes) plus the diagnosis.

This is the durable record so a later agent does not re-derive it, and does not
repeat the two implementation mistakes that nearly shipped.

---

## 1. The principle

**A gate must distinguish an artifact that is UNUSABLE from one that is
IMPERFECT BUT MECHANICALLY REPAIRABLE. Only the former may halt.**

An imperfect-but-repairable artifact should produce:

1. a deterministic downstream repair that restores the missing form, and
2. typed, visible debt naming exactly what was repaired and from where.

Both halves are required. Repair without visibility is provenance laundering,
which is the failure mode this driver exists to prevent. Visibility without
repair is an unwinnable contract: a worker told to fix something it has no
power to fix will rewrite correct work and drift.

### 1.1 The corollary that matters most

**Never charge a producer for a fault it cannot repair.**

Three recurring instances, all of which killed runs:

- A shard is failed for debt whose bytes do not exist in the SOURCE
  (`UNPARSEABLE_*`). No rewrite can transcribe an absent facet.
- A shard is failed for a duplicate identity in a DIFFERENT, upstream artifact.
- A phase is failed because a deterministic repair stage refuses to run, while
  telling the operator to "repair the canonical projection instead" — which is
  impossible when the source holds no bytes to copy.

When a gate fires, ask: *which actor can act on this, and with what?* If the
answer is "none", the gate is asserting a contract nobody can satisfy.

### 1.1a "Over-strict validators" is the WRONG lesson -- read this before loosening anything

It is tempting to summarise the defect history as "the validators are too
strict, loosen them". That summary is wrong, it is dangerous, and the project's
own history refutes it: validators were LOOSER earlier and that produced real
losses -- provenance laundering, dropped findings, the `never_cut_checkpoint`
and inventory-manifest defects. Recall-safety is why the gates exist.

Note also that degrade-not-halt was NOT invented by the 2026-09 work. It was
already established across depth (several), verify shards, verify_queue and
report_index. The inventory-chunk lane is one more instance of an existing
pattern, not a new philosophy.

The distinction that actually held up across all eleven defects is not
strict-vs-loose. It is WHAT THE GATE KEYS ON:

| Defect | What was wrong | What was NOT wrong |
|---|---|---|
| `\| CC ID \|` unrecognised | recogniser did not match the language producers emit | strictness -- fixing it PREVENTED 37 phantom rows |
| facet containment | compared REPRESENTATION (unbroken substring) not the PROPERTY (content survived) | requiring preservation |
| `UNPARSEABLE_*` gating | charged a producer for bytes absent UPSTREAM | requiring the facet |

Every fix corrected a PROXY that measured the wrong thing. None weakened a
correctness property. The test before changing any gate is therefore:

  * Does the predicate measure the property, or a representation of it?
    (substring containment vs content survival; one header spelling vs any
    identity column)
  * Can the actor the gate blocks actually satisfy it? (see 1.1)
  * Would relaxing it admit an artifact that is genuinely unusable, or only
    one that is differently SHAPED?

If the answer to the last is "genuinely unusable", the gate is correct and the
producer must be fixed. LangSec's framing is the precise one: a recogniser must
match the intended language EXACTLY -- no more powerful, and no narrower.

### 1.1b Corroboration from the test suite's own fossils (2026-09-19)

Two long-red contracts in `scripts/test_pipeline_contracts.py` turned out to be
stale TESTS asserting the pre-recall-safe behaviour, and they are the clearest
independent evidence for 1.1a's direction of travel:

- One required depth findings scoring below 0.70 to be DROPPED from inventory.
  `_promote_depth_findings_to_inventory` now ignores that threshold outright:
  "confidence and consensus are routing telemetry for later verification and
  can never erase a discovered producer action".
- One required niche findings in the generic bulk promotion list. They moved to
  a dedicated receipt-bearing publisher precisely so one inventory mutation
  does not have two owners.

Both changes REMOVED a proxy (a pre-verification score; a bulk glob) without
weakening any correctness property, and both increased recall. Neither touched
identity. That is 1.1a's test applied twice, with the outcome recorded in
product code before anyone articulated the rule.

### 1.2 What may never be relaxed

Bind repairability to SHAPE, never to CONTENT.

| Gate protects | Repairable? |
|---|---|
| Rendering: header tokens, heading depth, field labels, facet containment, table column naming | YES — canonicalise the form |
| Identity: finding IDs, dedup absorbed->survivor binding, severity-ledger authority, disposition authority, source-action authentication | **NO — stay fail-closed** |

A repair that *infers identity* can silently merge or drop a finding. That is
the one class of integrity loss this pipeline has never suffered, and it must
stay that way. A repair must canonicalise FORM; the moment it must infer
CONTENT, stop — that is the "faulty parse tree" failure mode, and it is worse
than the halt.

---

## 2. Implementation ordering (binding)

**Normalise, THEN gate. Do not gate-with-exemption and then repair.**

This is the single most important correction in this document, and it comes
from a production precedent rather than taste. Kubernetes runs mutating
admission webhooks FIRST and validating webhooks afterwards, precisely because
a validating webhook is the only thing that can "guarantee it sees the final
state of the object". Kubebuilder states it plainly: *use a validating webhook
to validate that a mutated object has the expected configuration*.

Why it matters here, concretely:

- **normalise -> gate**: the predicate never weakens, there is no exempt path,
  and **a repair that silently does nothing is caught immediately**, because the
  unchanged gate still fails.
- **gate-with-exemption -> repair**: exactly that bug is invisible.

The current inventory implementation uses the second ordering. It was written
before this was understood, and it cost two real bugs (section 4.3). An
exemption/repair predicate shared by both sides guarantees only that the two
SETS coincide; it does **not** guarantee the repair did anything correct.

### 2.1 Three laws every repair must satisfy

Transposed from the lens laws (Foster et al., *Combinators for Bidirectional
Tree Transformations*, ACM TOPLAS 29(3), 2007):

```
1.  gate(repair(x)) == true      for every x the predicate exempts
2.  gate(x)  =>  repair(x) == x  (identity on already-valid input)
3.  repair(repair(x)) == repair(x)   (idempotence)
```

**Law 1 is non-negotiable.** It kills the silent-no-op class instantly and
would have caught both bugs in section 4.3 before they reached a run.

### 2.2 Exact denominators must be shared across a phase boundary

**A producer that feeds an exact consumer must derive its work from the same
exact denominator.** A heuristic or capped producer cannot satisfy an exact
consumer, even when every emitted record is individually valid.

Run 75 exposed this at Gate P. The registered-delivery boundary enumerated 490
source actions exactly, while Gate P selected candidates with Markdown shape
heuristics and limits of 64 per file and 512 per run. The consumer was correct
to retain 361 residual actions; the producer was structurally incapable of
delivering them all. Raising the limits would only postpone the same defect.

The binding pattern is now:

1. derive registered actions from the registry's exact delivery projection;
2. route every valid, content-bearing, nonterminal action without heuristic
   count caps;
3. retain bounded heuristic recovery only for material outside that exact
   action set; and
4. re-run the exact delivery projection in disposable staging and require a
   CLEAN postcondition before any canonical successor is published.

This is the same materials/products principle used by content-addressed build
and supply-chain systems: the producer's declared input set and the consumer's
verification set are one identity-bound set, not two independently sampled
views. Availability bounds may reject an oversized artifact before mutation,
but they may never silently truncate registered semantic actions.

---

## 3. Defect history

All eleven were the DRIVER mishandling ITS OWN artifacts — table headers, chunk
formats, hook envelopes, scope boundaries — not the model underperforming.

### 3.1 The seven "validator stricter than the property it protects"

| # | Defect | Root cause |
|---|---|---|
| 1 | Preservation gate scored ENRICHMENT as loss | substring containment; an inserted code citation broke contiguity |
| 2 | Retries driven against unresolvable upstream debt | `UNPARSEABLE_*` charged to the shard |
| 3 | Table identity column unrecognised | parser accepted only `Finding ID`/`ID`; a shard wrote `CC ID`, so 37 table rows lost identity and could not merge with their 37 detail blocks -> **74 rows parsed from 37 findings** -> duplicate source actions -> forced retry -> churn -> degrade |
| 4 | Gate blocked on rows Python restores deterministically | gate and repair had no shared predicate |
| 5 | Mixed-axis rows gated on their unwinnable half | `['ROOT_CAUSE','UNPARSEABLE_IMPACT']` — one half restorable, one half impossible |
| 6 | Upstream duplicate IDs killed a downstream phase | a per-contract worker wrote rescan STEP labels (`### RS-1 ...`) as finding headings; `bind_exact_source_actions` raised |
| 7 | Composite issue string read as atomic | the driver joins all chunk sub-issues into ONE string; a per-issue test saw a fatal class riding inside a preservation-marked element |

### 3.2 The four that are a different class

| # | Defect | Class |
|---|---|---|
| 8 | Bounded-web permission mode | provider drift: CLI reports `dontAsk`, authority hardcoded `default`. The lane was DEAD, not strict — zero web receipts of any kind in any run, ever |
| 9 | WebSearch response contract | structural shape assumption: parser modelled `[block]*count + [summary]` and indexed positionally; the real shape INTERLEAVES a block per search with assistant text. Only `searchCount == 1` ever fit |
| 10 | Facet restoration ran only at CHUNK scope | genuine architectural gap; the final projection has a different denominator and different rows |
| 11 | Reemit refusal fired on an unrepairable row | demanded a repair that cannot exist |

### 3.3 The measured cause of the transcription defects

Preservation failure scales with source facet LENGTH, not shard quality. Same
model, same prompt, same contract, three shards of one run:

```
identities   median source facet   preservation debt
   37             887 ch                8  (22%)
   37           1,223 ch               24  (65%)
   57         breadth-heavy            43  (75%, on ATTEMPT 1)
```

A 38% longer median facet tripled the failure rate. **The shard is not
degrading between shards; it is being handed progressively more bytes to copy
verbatim.** Byte-exact transcription of long structured content is not
something a model does reliably: one retry was handed 11 exact source facets in
its prompt and reworded them anyway.

**Consequence, and it is the architectural through-line:** data routed through
a model's OUTPUT channel gets overwritten by its priors. The model should emit
IDENTITIES AND JUDGMENTS; Python should own the bytes. The same pattern
appeared one layer up in the web lane — a worker with 130 harvested URLs in
context emitted a URL it recalled from priors instead, and the gate correctly
refused it.

### 3.4 Integrity vs availability

**No finding was ever lost.** One run traced 129 breadth + 15 rescan/per-contract
-> 132 normalised -> 132 in the final inventory. Every halt preserved every
artifact with full provenance.

But in Fox & Brewer's terms (*Harvest, Yield, and Scalable Tolerant Systems*,
HotOS-VII 1999) a halted run has **harvest 1.0 and yield 0**. A complete answer
that never arrives is not a partial success; it is a total failure of the
delivered service. Do not read "no data lost" as "no harm done".

The integrity property is still load-bearing: because every finding survives
with provenance, the repair target is WELL-DEFINED. Without it, repair would be
guesswork.

---

## 4. Implementation lessons (learned the expensive way)

### 4.1 Verify field presence with the PRODUCT parser, never with grep

A strict `grep '^\*\*Root Cause\*\*:'` found ZERO in an artifact that the
product parser read correctly — the shard had written
`**Root Cause** (verbatim upstream Description; ...):`, a parenthetical the
tolerant `_FIELD_RE` accepts. An ad-hoc grep is a different, stricter recogniser
than the product's, and disagreeing with it proves nothing.

### 4.2 Build fixtures with the product's own builders

Three separate fixture mistakes in one session, each briefly read as a product
defect when the product was right:

- invented `obligation_id` values — they are content DIGESTS of their own row;
- hand-rolled a policy manifest — it is self-binding via `manifest_digest`;
- asserted ecosystem-flavoured finding IDs (`SOL-3`, `APT-11`) must parse —
  no producer emits them. Identity is keyed to AGENT ROLES (`B*` breadth,
  `RS*` rescan, `PC*` per-contract), which are identical across ecosystems.

### 4.3 String presence is not execution

Two bugs in the same repair, both invisible to reading the diff:

- **silent no-op**: the final-scope pass keyed on `proposed_target_finding_id`,
  an `INV-NNN` allocated inside `_render_inventory` — so at merge time, when the
  pass must run, no entry carries it. It restored 0 facets and looked fine.
- **`NameError`**: the call referenced a name bound only inside a different
  function. It raised on EVERY aggregate and broke 47 tests.

The wiring test that was supposed to catch this asserted a STRING APPEARED IN
THE FILE. It passed while the code was broken. The replacement inspects the
compiled function's bytecode: every name the call site references must be bound
in that scope. **Law 1 of section 2.1 catches this whole class.**

### 4.4 Measure before tightening a shared parser

The obvious fix for defect 6 was to require bracketed finding IDs. Measured
first: that would have dropped **11 blocks from four artifacts** in the same run
that legitimately use unbracketed per-contract/rescan headings. Losing real
findings to suppress phantom ones is the wrong trade. The shipped fix made the
ambiguous identity bind to NOTHING while every unambiguous identity in the same
artifact still binds.

### 4.5 Never install into a live or merely-stopped run

A run's generation is fixed for its entire life. `audit_snapshot` binds
`methodology` and `toolchain` digests at run START, so installing while a run is
merely STOPPED still invalidates its resume (`snapshot_verdict: MISMATCH`). The
refusal is correct and fail-closed, but in-place migration is not implemented,
so the run becomes terminal. Decide BEFORE installing: finish the run on its
generation, or accept that installing ends it.

### 4.6 Freeze the tree before running the suite

Running pytest against a tree being edited produces order-dependent phantom
failures. Copy to a frozen directory, run there, and A/B any failure by
reverting the specific change before concluding it is yours.

### 4.7 Fold tool transcripts as events; do not validate them as unique rows

Human-readable tool output is an ordered event stream, not a database table.
The same terminal fact may be emitted when it is discovered and again in the
final summary.  A transcript validator must therefore fold observations by
semantic identity:

- repeated `(identity, status)` observations are idempotent;
- two different terminal statuses for one identity are contradictory and
  remain invalid;
- missing expected identities and unknown identities remain invalid; and
- counts and exact rosters come from the tool's authenticated final summary or
  the folded identity set, never from the number of matching log lines.

Real DODO Run 76 exposed this at the shared Medusa finalizer.  Medusa 1.4.1
prints a failed property from `ReportTestCaseFinished`, then deliberately
prints every test case again from `printExitingResults` before the final tally.
The old validator interpreted those two identical `FAILED` observations as two
properties and downgraded a real 137,949-call, two-counterexample campaign to
`UNSCORED`.  The finalizer now accepts consistent repeats and rejects only a
`PASSED`/`FAILED` contradiction for the same declared property.  The rule is in
the shared campaign authority, so it applies to every Medusa workspace and not
only to DODO.

The adjacent production-parser sweep found no second human transcript parser
that rejected identical repeated terminal events.  Forge failure totals are
already folded with `max` and failure identities with a set.  Duplicate checks
over PhaseIO outputs, artifact IDs, exact rosters, paths, and producer
ownership are not transcript checks and remain strict.

Primary implementation evidence:

- Medusa 1.4.1 reports a finished test case at discovery:
  <https://github.com/crytic/medusa/blob/v1.4.1/fuzzing/fuzzer.go#L318-L340>
- Medusa 1.4.1 prints the complete test-case roster again at exit:
  <https://github.com/crytic/medusa/blob/v1.4.1/fuzzing/fuzzer.go#L1225-L1268>
- Medusa property-testing configuration and `property_` discovery contract:
  <https://secure-contracts.com/program-analysis/medusa/docs/src/project_configuration/testing_config.html>

### 4.8 An identity change is a typed transition, not a dropped row plus a new row

An exact-partition validator cannot compare only the identifier sets on both
sides of a policy stage when that same stage is authorized to canonicalize an
identifier.  It must account for identity transitions as first-class records.
Otherwise one lossless relabel appears simultaneously as one missing input and
one invented output.

Real DODO Run 76 exposed the contradiction at T2 -> T6.  T2 losslessly
canonicalized 12 single-member hypotheses (`INV-*` -> `H-*`), preserving the
old ID as both an alias and a parent-bound `MIGRATION_DEBT` lineage link.  The
active denominator remained 738 records.  The old T6 predicate nevertheless
required literal set equality, classified all 12 sources as visible debt and
all 12 targets as unaccounted additions, and halted before verification.

The replacement accounting schema records a transition only when all of these
are true:

- the source is absent and the target is new;
- the old ID appears in the target's typed alias set and in an explicit
  parent-bound migration lineage link;
- every claim-, evidence-, severity-, scope-, location-, and
  disposition-bearing field has the same canonical digest (queue order and
  the identity envelope are the only permitted differences);
- source and target form a one-to-one mapping; and
- the target is bound to exactly one active or authorized-excluded partition.

The downstream gate replays the transition against the typed target record and
its digest; it does not trust T2's `exact_partition` Boolean.  Arbitrary
additions, semantic edits, one-to-many fan-out, many-to-one absorption,
duplicate active/excluded membership, and unlinked renames remain invalid.
Unrouted base identities remain visible debt rather than disappearing.

This follows the W3C PROV model's distinction between an identifier and the
underlying thing: two identifiers may describe alternate representations of
the same thing only through an explicit provenance relation, while their
attributes remain fixed for the represented entity.  Kubernetes makes the
complementary operational point: names support idempotent retrieval, while a
distinct UID disambiguates historical identity.  In Plamen, the work-item
digest plays the occurrence-identity role and the typed transition supplies
the provenance relation; a coincidental title or prose mention supplies
neither.

Primary architecture evidence:

- W3C PROV constraints for alternate entities, identifiers, and fixed
  attributes: <https://www.w3.org/TR/prov-constraints/>
- W3C PROV formal semantics for `alternateOf` and `specializationOf`:
  <https://www.w3.org/TR/prov-sem/>
- Kubernetes object names and UIDs, including historical-occurrence
  disambiguation: <https://kubernetes.io/docs/concepts/overview/working-with-objects/names/>

### 4.9 Compile generated tool inputs before spending the campaign

A generated fuzz harness is a program, not prose.  A clean production build
does not prove that newly generated test bytes compile.  The tool phase must
therefore preflight the exact generated input through the same adapter path the
campaign will use, repair bounded compiler-only defects, and bind only the
successfully compiled bytes into the campaign request.

Real DODO Run 77 exposed an asymmetric contract: Foundry invariant fuzzing
allowed three targeted compile repairs, while the Medusa methodology explicitly
forbade retry after the first generated-harness compiler error.  Medusa reached
the real `crytic-compile`/Foundry adapter, but two direct proxy-to-contract casts
violated Solidity's payable-conversion rule.  The resulting campaign was
correctly `UNSCORED`, yet a deterministic, repairable syntax error discarded the
entire stateful-fuzz budget.

The shared Medusa methodology now requires:

- compile the exact `.medusa-tests` lane using the same Foundry build-info path
  consumed by the Crytic adapter;
- permit at most three targeted harness-only repairs for compiler/type/import/
  wiring defects;
- never delete or weaken a property, edit the production snapshot, install a
  dependency, or switch build systems to obtain a green compile;
- bind only the final successfully compiled harness/config bytes into the secure
  campaign launcher; and
- classify a remaining compiler failure as visible `COMPILATION_FAILED` debt,
  never as a pass and never as an artifact-gate halt.

The compatibility driver also canonicalizes the exact recurring Solidity
surface before materialization: a direct implementation-contract cast around
`address(new *Proxy(...))` becomes the type-equivalent
`payable(address(new *Proxy(...)))`.  This projection is comment/string aware,
idempotent, restricted to generated `.medusa-tests` Solidity, and records both
the model-source digest and the projected-byte digest in the fuzz bundle
manifest.  It never edits production sources or the model-owned finding
artifact.  Replaying the projection against Run 77's exact bundle produced the
two compiler-required payable casts without touching either property oracle.

This is the tool-input analogue of normalise-then-gate: bounded deterministic
repair occurs before the expensive consumer, while the consumer's correctness
predicate stays unchanged.  Solidity documents that payable conversions must be
explicit (including the general `payable(address(c))` form), and Medusa's own
configuration documentation requires Foundry projects to be compiled as the
project root through `crytic-compile` so dependencies and remappings are
retained.

Primary implementation evidence:

- Solidity 0.8 conversion rules for `address` and `address payable`:
  <https://docs.soliditylang.org/en/latest/080-breaking-changes.html>
- Medusa compilation configuration and the Foundry/Hardhat project-root rule:
  <https://secure-contracts.com/program-analysis/medusa/docs/src/project_configuration/compilation_config.html>
- Crytic-compile's official Foundry usage and build-system abstraction:
  <https://github.com/crytic/crytic-compile>

### 4.10 An isolated validator must capture the transitive witness closure

Disposable staging is a security boundary, not permission to validate an
incomplete world.  If a validator's decision depends on a receipt, alias
authority, worklist, ledger binding, or production source byte, that witness is
part of the validator input even when the primary artifact does not mention it
directly.  Copying only the artifact under review converts valid provenance
into apparent absence and creates a deterministic false halt.

Real DODO Run 77 exposed this at Gate P.  The live scratchpad contained a CLEAN
enumgap disposition receipt for all 15 exploration-clear obligations.  Gate P
copied the obligation queue into its disposable project but omitted the
receipt, its PhaseIO lineage, the immutable prior aliases, and four project
sources bound by the reconciliation unit.  The isolated registered-delivery
projection therefore reported every obligation as unresolved even though an
exact replay against the live authority returned all 15 dispositions.

The binding rule is now:

1. start from the property checked at the boundary, not from a hand-maintained
   list of convenient files;
2. follow every typed authority edge needed to evaluate that property until
   reaching immutable source bytes;
3. capture scratchpad witnesses and PhaseIO-bound project inputs into the
   disposable project with the same relative topology expected by the product
   resolver;
4. seal every captured byte by size and SHA-256 in the successor plan;
5. compare-and-swap those preimages again before canonical publication; and
6. keep the semantic postcondition strict.  Missing, drifting, ambiguous, or
   unauthenticated witnesses remain failures.

This is not validator loosening.  It makes the validator's isolated input
complete while preserving its exact predicate.  A primary-artifact-only unit
test is insufficient: each destructive phase boundary needs an acceptance test
that replays the full property with at least one valid cross-artifact witness
and proves that removing or changing any witness fails closed.

The model follows the W3C PROV notion that validity is constrained over a
provenance graph, not over an entity node in isolation: derivation and
specialization constraints can require related entities and activities before
a conclusion is valid.  The captured closure is the finite subgraph required
for one boundary decision; the successor plan is its content-addressed
snapshot.

Primary architecture evidence:

- W3C PROV constraints and inference rules:
  <https://www.w3.org/TR/prov-constraints/>
- W3C PROV formal semantics:
  <https://www.w3.org/TR/prov-sem/>

### 4.11 A transaction journal cannot be its own immutable input

The transitive witness closure can contain mutable control-plane state.  Such a
witness must be snapshotted for isolated replay, but it cannot automatically be
placed in the transaction's semantic compare-and-swap denominator.  If arming
the transaction necessarily updates that same journal, the transaction would
invalidate itself before publishing any semantic output.

Real DODO Run 78 exposed this after the Run 77 witness-closure fix.  Gate P
correctly copied `_artifact_state.json` into disposable staging so the enumgap
lineage could be authenticated.  It then also declared the whole live ledger an
immutable PhaseIO input.  Recording `gate_p.source_capture` appended its own
work-unit row to the ledger, so immediate validation failed with `semantic
input hash changed` even though no producer artifact changed.

The architectural split is now explicit:

1. semantic source artifacts are bound by PhaseIO and remain under CAS before
   publication;
2. the mutable ledger is hash-sealed in the Gate-P plan and checked once before
   the capture transaction is armed;
3. the exact pre-arm ledger bytes are copied into disposable staging for
   provenance replay;
4. the expected journal mutation caused by arming is not mistaken for semantic
   source drift; and
5. `PhaseIOContract` globally rejects the whole `_artifact_state.json` as an
   immutable or bounded semantic input.  Consumers must bind selected producer
   artifacts/records or use a sealed pre-arm staging witness.

This preserves both sides of the safety property: the validator sees the full
historical authority it needs, while concurrent changes to actual semantic
sources still fail closed.  The same rule already underlies report-index
staging, which copies a validated ledger projection after arming rather than
binding the self-mutating live journal.

---

## 5. Research basis

### 5.1 The pattern has a name

**Active Integrity Constraints** — integrity constraints paired with their
repair actions. Flesca, Greco & Zumpano (2004); Caroprese, Greco & Zumpano,
*Active Integrity Constraints for Database Consistency Maintenance*, IEEE TKDE
21(7):1042-1058, 2009. Motivating line: *"simply detecting that a database is
inconsistent does not give any information on how it can be repaired."*

Hazards from that literature: multiple repairs can exist and some are
circularly self-supporting (hence "justified" rather than merely "founded"
repairs); founded-repair existence is Sigma-2-P-complete; termination and
confluence are not automatic once repairs can re-trigger across artifacts. Keep
each repair local, total, and non-circular.

### 5.2 Why the ordering is what it is

Kubernetes dynamic admission control: mutating webhooks first, validating
webhooks after, because only the latter sees final state. This is the
industrial precedent for normalise-then-gate (section 2).

### 5.3 Why the recogniser is usually the real defect

**LangSec** (Sassaman & Patterson 2011; Bratus et al., USENIX Security 2013):
the recogniser must match the intended language exactly — no more powerful, and
**no narrower**. A divergence between two components' notions of validity is a
**parser differential**. Defect 3 (`CC ID`) and defect 9 (interleaved response)
are parser differentials, not "strict validators".

The 2024 CrowdStrike outage is the cautionary version: content passed the
validator, the kernel consumer parsed it differently, fail-stop across ~8.5M
machines. Note the remediation was NOT "make the consumer tolerant" — it was
staged rollout plus making validator and consumer agree on the language.

### 5.4 Tolerance is not the lesson; SPECIFIED recovery is

RFC 9413 (*Maintaining Robust Protocols*) documents how tolerance entrenches
aberrant behaviour into bug-for-bug compatibility; Allman, CACM 54(8), 2011.
Protocol tolerance has produced real attacks (Rochet & Pereira, PoPETs 2018(2),
on Tor).

HTML5 did **not** win by being tolerant — it won by SPECIFYING the error
recovery so every implementation recovers identically. Our splice is defensible
only because it is deterministic, shared, and reported.

### 5.5 Metrics worth adopting

- **Effective false positive** (Sadowski et al., *Lessons from Building Static
  Analysis Tools at Google*, CACM 61(4):58-66, 2018): any finding the developer
  took no positive action on. Their policy — **~0% effective FP for
  compile-time/halting checks, <=10% for advisory checks**. Above that,
  developers ignore the channel entirely ("warning blindness").
- **Spurious Trip Rate** (IEC 61511 / ISO TR 12489 / ISA TR84.00.02): the rate
  of unnecessary shutdowns, required to be ESTIMATED AND CONSIDERED when
  selecting an architecture. 75 halting gates in series is a 1-out-of-75
  vote-to-trip system: maximum protection, maximum spurious trips.
- **Harvest / yield** (Fox & Brewer, HotOS-VII 1999): log both per run.

### 5.6 What goes wrong with warn tiers (measured)

- Self-admitted technical debt IS mostly repaid (74.4%) but median survival is
  weeks to months and the STOCK GROWS because new instances outpace fixes
  (Maldonado et al., ICSME 2017; Bavota & Russo, MSR 2016). Set an explicit
  age threshold at which unrepaid debt re-escalates.
- Quarantining a noisy signal hides real bugs (Luo et al., *An Empirical
  Analysis of Flaky Tests*, FSE 2014).

### 5.7 On constraining model output

Grammar-constrained decoding distorts the model's distribution (Park et al.,
*Grammar-Aligned Decoding*, NeurIPS 2024). Format restrictions degrade
reasoning, and stricter restrictions degrade more (Tam et al., EMNLP 2024
Industry) — in JSON mode, 100% of one model's responses put `answer` before
`reason`, silently converting zero-shot CoT into direct answering. Contested by
a vendor rebuttal; treat as unsettled.

**Combined recommendation, which is coherent with our measurements:**
constrain/normalise the SURFACE, validate the CONTENT, and keep the grammar
permissive where reasoning happens.

Parser error-recovery literature supplies the discipline: a repaired artifact
that is silently wrong is worse than a halt (Burke & Fisher, TOPLAS 9(2), 1987;
Diekmann & Tratt, ECOOP 2020 — "panic mode's repairs are so bad that on a
modern machine it's worse than having no error recovery at all").

### 5.8 The counter-case, kept deliberately

APR overfitting: patches satisfying available tests break untested-but-correct
behaviour, 70-98% overfitting across studies (Smith et al., ESEC/FSE 2015; Le
et al., EMSE 2018; Ye et al., EMSE 26(2), 2021). Kali (Qi, Long, Achour &
Rinard, ISSTA 2015) matched state of the art by ONLY DELETING FUNCTIONALITY —
**if an acceptance criterion can be satisfied by degradation, degradation is
what you get.**

The transfer is partial: our repair is a deterministic byte-splice with no
search. But our exposure is worse in one respect — **the oracle that would
catch a bad repair is the very gate we exempted.** Hence section 2: put the
repair IN FRONT of the gate, not in place of it.

---

## 6. OPEN: applying this to the other ~70 gates

**Not decided. Do not roll out without the evidence below.**

The current evidence is 11 defects over 5 runs, with no denominator. The
research's prediction — and it is a falsifier, not a caveat — is that the
spurious trips concentrate in **3-5 ID/heading/containment predicates**, in
which case the correct fix is to repair those RECOGNISERS, not to build a repair
framework for 70 gates. Defect 3 was exactly that: a recogniser fix.

Also note `rules/mechanical-gate-registry.json` counts every independently
fireable predicate against a per-seam ceiling. Seventy per-gate exemption
predicates would blow that budget. **One normalisation stage per seam with a
table of shape-rules is ONE gate.**

### Gather first

1. **Per-gate trip ledger with a denominator**: for every gate, over all runs —
   times fired, each labelled *true reject* (artifact genuinely unusable) vs
   *spurious trip*. Compute per-gate STR.
2. **Frozen regression corpus + false-fire budget**: artifacts from all runs
   plus mutants. Each repair: red->green on the known-bad case AND no-fire
   across the known-good corpus.
3. **Property tests for the three laws** (section 2.1), per repair.
4. **Harvest/yield telemetry** per run, and **debt-age telemetry** per emitted
   debt item.

### Stop-the-rollout conditions

- A repaired run differs SEMANTICALLY from hand-repaired ground truth at
  Medium+ severity, even once. Repair changes shape, never meaning.
- Measured STR is low and concentrated -> the diagnosis was wrong; fix
  recognisers.
- **Repair-invocation rate RISES across runs** — normalization of deviance
  (Vaughan 1996): producers drifting toward exempt-shaped output because it is
  now accepted. Track as a first-class metric.
- Typed-debt items are systematically never closed — the warn tier has become a
  discard tier, trading a visible availability failure for an invisible
  integrity one.
- Any repair requires inferring CONTENT rather than canonicalising FORM.

### One thing that cannot be undone

Hyrum's Law: now that `CC ID` is accepted as an identity column, producers will
depend on it and it can never be tightened again. Every tolerance added here is
permanent. Add them deliberately.

---

## 6a. Evaluated and NOT adopted: third-party classifier as a gate (2026-09-19)

Evaluated **Jev** (TypeSafe AI, launched 2026-09-15) as a candidate verifier of
worker output. It is a genuine classifier: POST a state plus typed questions,
get typed answers with probability distributions, no text generation at all
(Choice / Score / Noul primitives; ~70-500ms; $0.042/1M input tokens, output
free; model `jev-1.13.0`). The interface is well designed and unusually well
documented, including its own failure modes.

**Not adopted as a gate or as terminal authority.** Four blockers, in order of
how binding they are:

1. **Data egress.** US-hosted API, no self-hosted or on-prem option, zero data
   retention available only as a negotiated enterprise term or per-request via
   Vercel AI Gateway. Our artifacts are unpublished vulnerabilities in private
   client code. This is an NDA question before it is a technical one, and it
   is decided independently of accuracy.
2. **No rationale, ever.** It returns a probability with no trace. Every
   disposition in this pipeline binds to a receipt and must be auditable and
   human-reviewable. A bare number can ROUTE; it can never DISPOSE of a
   finding.
3. **Its weakest benchmarked domain is ours.** Security-incident workflows
   61.7%, the lowest of its four workflows and below every frontier
   comparator. Note the benchmark's "accuracy" is AGREEMENT WITH TWO FRONTIER
   MODELS, not ground truth -- the vendor says so plainly.
4. **Reproducibility.** The `jev-latest` alias drifts silently behind whatever
   thresholds you set. Any use would have to pin `jev-1.13.0` exactly.

**The vendor's own "jaggedness" page independently confirms our measurement.**
Two of its listed weaknesses describe our workload exactly:
  * "Accuracy falls as the state fills with material the question doesn't
    need" -- our chunk artifacts are 100-170KB;
  * "No arithmetic, no counting, no date ordering" -- our gates count
    identities, compare denominators, and verify digests.

That is the same length-not-difficulty degradation measured in section 3.3,
arrived at independently by the vendor. It is corroboration of the principle,
not a reason to adopt the product.

**Where a classifier of this shape WOULD fit** (advisory, reversible,
high-volume, never terminal): dedup-pair pre-filtering ahead of chain analysis;
triage routing; a cheap pre-screen before expensive verification; flagging
agent traces whose claims contradict their own tool results. If ever adopted
for those, it must sit BEFORE a deterministic check, never in place of one --
the same ordering rule as section 2.

**Generalisable rule this evaluation establishes:** a probabilistic component
may PRIORITISE work, never AUTHORISE a disposition. The gates in this pipeline
are deterministic Python predicates precisely so that the same artifact always
produces the same verdict and the verdict is auditable. Substituting a
stochastic judgment there would trade a reproducible availability failure for
an unreproducible integrity risk -- the exact trade section 1 exists to
prevent.

## 6b. Rule: a probabilistic component may PRIORITISE, never AUTHORISE

Researched 2026-09-19, product-agnostic, deliberately framed to attack the
proposal. Two candidate roles for an LLM classifier were evaluated separately.
The conclusions generalise to any vendor.

### ROLE A -- "is this artifact usable or merely imperfect?"  ADOPT-WITH-CONSTRAINTS

Good task shape (closed binary label, semantic equivalence, demonstrably
over-strict baseline), wrong deployment position as originally imagined.

**The constraint that dissolves the problem.** Do not let the classifier decide
halt-vs-proceed. Let it ROUTE: `REPAIRABLE` -> attempt the deterministic repair
-> **re-run the SAME deterministic validator on the repaired artifact**;
`UNUSABLE` -> existing path. With post-repair re-validation the classifier
cannot cause a bad artifact to pass, and its accuracy stops being
safety-relevant -- it becomes a throughput optimisation. This is section 2's
normalise-then-gate ordering restated for a probabilistic component.

Mandatory if ever built: self-hosted / pinned weights (not a third-party API --
see 6a); receipt records model id + weights hash + prompt hash + input hash +
output AND records that the decision is not reproducible by re-execution; chunk
inputs below the length at which our own workers were measured to degrade.

**Do the cheaper thing first.** Seven of the eleven defects in section 3 were
the deterministic validator rejecting substantively-correct output on a
surface/format mismatch. That is a VALIDATOR SPECIFICATION BUG, not a
missing-intelligence problem. Section 3.3 measures that halving facet length
takes failure from 65% to 22% -- a ~3x improvement obtained deterministically,
which no classifier can match. Adding a probabilistic component to compensate
for over-strict predicates treats the symptom and permanently increases system
entropy.

### ROLE B -- "is this finding real?" (false-positive filtering)  DO-NOT-ADOPT

Five independent reasons, any one sufficient:

1. **The binding metric is the literature's worst measured quantity.** Acting
   on a "not real" verdict drops a true finding. Measured LLM-verifier
   false-negative rates: **95.8%** (Graph Coloring) and **97.1%** (Mystery
   Blocksworld) -- alongside 72-80% AGGREGATE ACCURACY (Stechly, Valmeekam &
   Kambhampati, ICLR 2025). Accuracy hides FNR completely. Any evaluation here
   must report class-conditional error rates, never accuracy.
2. **On objective correctness, judges are near-random.** GPT-4o scores 50.9%
   on JudgeBench (random = 50%); best model 64%; "verification is nearly as
   difficult as generation" (Tan et al., ICLR 2025). The 80%+ agreement figures
   everyone quotes are on SUBJECTIVE PREFERENCE (Zheng et al., NeurIPS 2023),
   a different task.
3. **The verification advantage shrinks as the generator improves** -- "errors
   made by weak generators are easier to detect than those made by strong
   generators" (ICLR 2026). Our depth agents are Opus-class; their errors are
   precisely the subtle kind verifiers miss.
4. **Adversarial input, and this is the sharpest one.** A Role B classifier
   reads content derived from the AUDITED code -- comments, strings, docstrings
   authored by the party being audited. Judge prompt injection is documented.
   A contract author who wants a finding suppressed can write a comment
   designed to persuade the classifier it is a false positive. Deterministic
   predicates are immune by construction. This hands our one real adversary a
   new channel.
5. **The favourable SAST-triage evidence does not transfer.** That literature
   succeeds at ~865k alerts/year where recall loss is tolerable and the
   true-positive base rate is tiny. We have ~132 findings per engagement, each
   expensive to lose, each going into a client deliverable. Same technique,
   inverted cost structure. Peer-reviewed gains are modest (IRIS, ICLR 2025:
   +5pp false-discovery improvement); the 95-96% figures are unpublished vendor
   marketing.

**The defensible version of Role B** is a proposal-only ANNOTATOR under the
contract already written for precedent evidence: it may add, reorder, flag for
human review, or attach advisory metadata, and may NEVER remove, demote, close,
or change severity. Our own `RECALL_GENERATOR` gate class already describes
this shape ("may add or reopen only... no terminal finding authority"). Value
accrues from ORDERING the human triage queue, not from gating. Enforce it with
a deterministic invariant (`|findings_out| >= |findings_in|`), not a policy.

### Why this is the right shape, structurally

The safety-critical literature settled this: **Simplex / runtime assurance**
(Sha, IEEE Software 2001; NASA Formal Methods 2024) pairs an unverified
high-performance component with a formally verified simple one, and keeps
SWITCHING AUTHORITY in the verified monitor. NASA's assessment of ML under
DO-178C is that an ML model "cannot be traced to requirements or tests... the
corresponding coverage objective is not achievable" -- the accepted answer is
not to exclude ML but to deny it authority.

This pipeline already implements that pattern three times: precedent evidence
is proposal-only and "never a confidence/disposition/severity input"; skeptic
output is proposal-only requiring a separate typed adjudicator; the driver is
repair-then-degrade. **Any classifier must enter as a fourth proposal-only lane
under the same contract.** The asymmetry to avoid -- not any particular
accuracy number -- is granting authority the deterministic layer does not
independently re-check.

### Reproducibility, which is a hard blocker for receipts

Temperature 0 is NOT sufficient for determinism: the cause is lack of batch
invariance (batch size varies with server load, changing kernel reduction
order), measured as 80 unique completions across 1,000 temperature-zero
requests (Thinking Machines Lab, 2025 -- blog, not peer reviewed). Model
versions also drift measurably over months (Chen, Zaharia & Zou, Harvard Data
Science Review 2024). You can hash a classifier's input, output and model id;
you cannot hash the FUNCTION, and you cannot re-derive the verdict two years
later. A receipt over a non-reproducible decision documents that a decision
happened -- it does not preserve reviewability. That is a strict downgrade from
a Python predicate, which is re-runnable forever.

Note: the EU AI Act high-risk regime is a good TEMPLATE (Art. 12 logging,
Art. 14 oversight) but an automated smart-contract auditor is almost certainly
not an Annex III high-risk system. The binding constraints are CONTRACTUAL
(what was warranted to the client about report provenance) and
PROFESSIONAL-LIABILITY (can you reconstruct in two years why finding M-07 did
or did not ship?). Those are stronger arguments and point the same way.

## 7. Guard against overfitting

Every fix above operates on artifacts the DRIVER defines — its own table
headers, chunk formats, hook envelopes — never on audited code. Identity is
keyed to AGENT ROLES (`B*`, `RS*`, `PC*`, `DEC*`), which are identical across
evm/solana/aptos/sui/soroban, which is why these port unchanged.

`scripts/test_driver_fixes_are_protocol_agnostic.py` enforces this: it
tokenizes the guarded modules and fails if protocol vocabulary appears in
EXECUTABLE code (docstrings may cite a run as evidence — that records WHY a
generic rule exists and is the opposite of overfitting). Its vocabulary list
deliberately includes ecosystems unrelated to any current target, so it is not
a single-project filter.
