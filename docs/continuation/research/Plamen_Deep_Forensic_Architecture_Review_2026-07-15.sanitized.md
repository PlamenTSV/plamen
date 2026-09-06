<!-- PORTABLE SANITIZED RESEARCH COPY
Source identity: Plamen_Deep_Forensic_Architecture_Review_2026-07-15.md
Raw bytes remain outside Git. Architecture, methodology, execution, acceptance, and comparison semantics are retained; personal paths, private target identities, target-specific candidate/artifact identifiers, artifact digests, and concrete private finding descriptions use deterministic placeholders. See CORPUS_MANIFEST.json and research/PRIVATE_GAP_INDEX.json for provenance and the redaction rule.
-->

# Plamen Deep Forensic Architecture and Methodology Review

**Date:** 2026-07-15  
**System reviewed:** `<PLAMEN_SOURCE_ROOT>`, branch `hardening/backlog-and-nonevm-poc`, base commit `SOURCE-REVISION-004`  
**Production replay examined:** `<PRIVATE_REGRESSION_SCRATCHPAD>`  
**Current uncommitted change examined:** R10 external-assumption demotion-side gate in `scripts/plamen_validators.py` and `scripts/plamen_driver.py`  

## Executive verdict

Plamen's high-level `discover -> challenge -> verify -> report` method is sound. Its current implementation is not recall-safe end to end.

The primary architectural defect is not insufficient agent count, insufficient methodology prose, or lack of another scanner. It is that the pipeline treats mutable Markdown as both narrative and machine state. Every synthesis, dedup, chain, queue, verification, and report phase reparses and rewrites that state through a different informal schema. Those boundaries are lossy codecs. The private regression target run contains direct examples of mechanically generated obligations, explicit anti-dedup decisions, external-assumption warnings, and distinct root causes being discarded or corrupted by those codecs.

This architecture materially contributes to all four outcomes in question:

1. **Recall loss:** valid candidates and falsification obligations are not recognized, are collapsed, or become unreachable after a phase transition.
2. **False-safe decisions:** downstream verifiers receive compressed cards without the evidence and unresolved assumptions that made the candidate credible; the same verifier may then invent a benign premise and use it to excuse execution.
3. **False methodology-application receipts:** the system can prove that a worker existed and wrote a file, but not that each required methodology obligation was executed successfully.
4. **Quality and bloat loss:** semantic dedup is performed with unreliable provenance, followed by verbatim absorption to satisfy a lexical “no data loss” check. The result can be simultaneously over-merged and bloated.

The single highest-leverage change is to make an immutable, typed candidate/assumption/evidence ledger the source of truth and reduce Markdown to rendered views. The existing `plamen_contracts.py` is a useful seed, but it is not currently load-bearing: it defines only spawn and rescan models, and production code does not import it. It should be expanded incrementally around the current pipeline, not replaced in one rewrite.

The second highest-leverage change is a **demotion proof-obligation gate**. A finding must not become safe merely because a verifier asserts a favorable premise. Every premise that defeats harm must be individually supported by in-scope code, an executed experiment, a cited external source, or an authoritative specification. Unsupported premises produce `UNRESOLVED` and an independent appeal/research obligation, regardless of the candidate's current severity.

The third is a **methodology application compiler**. Assignment, reading, execution, and successful completion are different states. Plamen currently conflates them.

### Direct answer about proprietary competitors

No. There is no basis for assuming Solace, Grego, Pashov's skills, Krait, or other proprietary systems already use the architecture recommended here.

- Public Pashov methodology is a much simpler twelve-agent parallel scan followed by single-pass dedup/gating/reporting. It explicitly skips independent re-verification because of cost. It does have two useful hard constraints Plamen should borrow: function-level isolation and raw `(contract, function)` completeness. See the current [Pashov solidity-auditor skill](https://github.com/pashov/skills/blob/main/solidity-auditor/SKILL.md).
- Grego publicly advertises Solidity AST/IR, call/dataflow graphs, whole-repository analysis, state-transition reasoning, and path/PoC work. That is directionally aligned with a structured code substrate, but its public material says nothing sufficient about candidate lineage, demotion proofs, dedup identity, or report-loss gates. See [Grego's public architecture claims](https://grego.ai/).
- Solace's architecture is not public enough to evaluate. The creator's statement that it learned from and improved Plamen is evidence of an empirical improvement workflow, not evidence of a particular internal architecture. Treat it as a benchmark claim to test, not an architectural fact.
- The likely reference behind “private semantic-query claim” is **Krait**. Krait v8.1 added structured `stepExecution`, `rulesApplied`, evidence, precondition, and postcondition fields derived partly from Plamen. Its three-contest pilot reports a large recall gain, but the authors explicitly say the full regression has not been run. Its published v8 baseline is 15.2% recall, and the new fields are optional. This supports the value of application telemetry; it does not establish that Krait has solved lifecycle correctness. See [Krait's methodology and caveats](https://github.com/ZealynxSecurity/krait/blob/main/METHODOLOGY.md).

Proprietary competitors may have better models, private corpora, structured program representations, better sandboxing, or better learned workflows. None should be presumed superior at lifecycle correctness without black-box ablations or source access. The right response is to build an evaluation harness that localizes misses by lifecycle stage and compare systems on the same frozen repositories.

## Review scope and evidentiary standard

This was a source-level forensic review of the load-bearing execution paths, not a claim that every line of every prompt was manually interpreted in isolation.

The production toolchain contains 23 non-test Python files and approximately 80,208 lines. The two largest files are `plamen_driver.py` and `plamen_validators.py`, each approximately 20,000 lines; `plamen_mechanical.py` and `plamen_parsers.py` add approximately 18,000 more. I mapped:

- all declared SC and L1 phases and their static artifact contracts;
- dynamic worker-pool construction for recon, breadth, rescan, depth, and verification;
- phase gates, containment, artifact ownership, resume handling, mechanical derivation, verification aggregation, report construction, report dedup, disposition, and floor logic;
- the finding/ID parsers used at inventory, chain, queue, verification, and report boundaries;
- actual prompt snapshots and outputs from the private regression target run;
- one representative professional-report miss from discovery through final report;
- current R10 code, its synthetic tests, and an isolated replay using the real private regression target PRIVATE-FINDING-005 artifacts;
- public primary material for human audit practice, Pashov, Grego, Krait, program analysis, formal verification, and EVMbench.

Assumptions and limits:

- The private regression target working tree was already heavily dirty. I do not attribute all 20 modified source paths or 107 untracked PoC files to the latest Plamen run. The relevant fact is that the pipeline accepted and verified against a contaminated shared workspace without a frozen source baseline.
- Professional reports are treated as the requested ground truth, but they can omit valid novel findings. Metrics should retain an adjudication state for novel candidates rather than automatically label them false positives.
- Solace and other proprietary products cannot be architecture-reviewed from marketing claims.
- The R10 workflow was still uncommitted and had not produced the claimed multi-repository validation report when inspected. The grade below applies to the current diff, not to a future revision.

## Priority findings

| Priority | Finding | Failure class | Evidence from current code/run | Consequence |
|---|---|---|---|---|
| P0 | Method-application telemetry manufactures success | Discovery/non-application | Missing depth traces are synthesized from generic evidence tags into `(general), Executed=yes`; private regression target then reports all inherited skill steps executed | Existing methodology can remain unapplied while repair is suppressed |
| P0 | A verifier can author both a benign premise and its own PoC escape | Pipeline loss/false-safe | PRIVATE-FINDING-005 was `unit`, but the verifier asserted an unresearched external invariant, marked harm absent, and used `STRUCTURAL_NO_EXECUTABLE_HARM_ASSERTION` to skip execution | Found mechanisms become “safe” without an independent proof of the rebuttal |
| P0 | Recon worker decomposition omits mandatory external research | Discovery and false-safe | Monolithic Soroban recon mandates a row for every dependency; the live four-worker recon contract has no research owner and forbids opening the monolithic method | External assumptions reach depth and verify without authoritative semantics |
| P0 | Report dedup misparses prose as provenance and merges unrelated roots | Quality/precision/bloat | A summary prose line in `finding_mapping.md` made PRIVATE-FINDING-001 appear co-sourced with PRIVATE-FINDING-010/PRIVATE-FINDING-005/PRIVATE-FINDING-009/PRIVATE-FINDING-003; four unrelated findings were absorbed into PRIVATE-FINDING-004 | Client report is semantically incorrect despite “DATA-LOSS GATE: PASS” |
| P1 | Chain anti-overmerge decisions are undone by an ID grammar mismatch | Pipeline loss | Chain split three groups into seven `GRP-*` IDs with alphabetic suffixes; queue parsers accept only `GRP-\d+` | Distinct hypotheses collapse back into retired H IDs before verification |
| P1 | Nineteen committed invariants are silently unharvestable | Discovery/false-safe | private regression target log: 24 present, 5 matching; later 25 present, 6 matching. The producer emits `PRIVATE-ARTIFACT-ID-001` while the consumer accepts IDs beginning `CI-` | Falsification work designed to challenge safe/downgrade conclusions is lost |
| P1 | Skill output contracts conflict with worker containment | Discovery/non-application | Integration skill mandates `integration_hazard_catalog.md`; worker says write exactly one file and ignore other output requests; agent marked step 0e incomplete “by design” | Downstream consumers do not receive required methodology products |
| P1 | Verification mutates and reuses a shared source workspace | Precision/reproducibility | No per-candidate worktree/overlay/restore; “isolated” mechanical execution means test filter only; private regression target has 20 modified paths and 107 untracked PoC source files outside scratchpad | Candidates can affect later candidates, builds, scope, and reproducibility |
| P1 | Artifact ownership is not transformation provenance | Architecture/resume | `_artifact_state.json` records 282 artifacts, but 188 final hashes differ after legitimate downstream mutation and owners remain original | It cannot answer which phase transformed which semantic field or why |
| P2 | Report accounting is syntactically lossless but semantically incoherent | Quality/bloat | Final report says 52 findings but contains 36 primary headings; 13 consolidated sections occupy about 40% of report characters; generated PoCs appear in audited scope | Poor client signal and ambiguous metrics |

## 1. Methodology soundness

### What is sound

The overall generator/discriminator separation is correct:

- independent discovery roles reduce correlated omission;
- a semantic invariant pass before adaptive depth is useful;
- exploration skepticism and chain composition target different reasoning classes;
- executable verification is a stronger evidence tier than persuasive prose;
- additive mechanical recall generators are safer than deterministic vulnerability assertions;
- promotion-completeness and mechanical evidence integrity are the correct kinds of gates;
- preserving unresolved evidence for human review is preferable to silent deletion.

The problem is not the existence of these phases. It is that their contracts do not preserve the objects they reason about.

### Structural recall failure modes

#### 1. Rich claims are compressed into queue cards

Inventory and depth findings can contain mechanism traces, alternative roots, external assumptions, unresolved questions, preconditions, postconditions, and evidence provenance. The verification queue reduces this to title, bug class, preferred tag, location, primary artifact, PoC class, and severity. The verifier shard explicitly instructs the model to read only its queue row, exact source locations, and the named primary artifact.

This is good context hygiene only if the queue card is a lossless reference to structured supporting data. It is not. It is a prose summary.

The systematic under-service is **context-dependent rebuttal reasoning**: external dependency semantics, specification intent, chain-created preconditions, historical state, deployment assumptions, and conflicting prior evidence. These are precisely the facts needed to avoid false-safe conclusions.

#### 2. The same agent both rebuts and decides whether proof is owed

The verification protocol tries to force PoCs, but its escape paths depend on the verifier's own characterization of the claim. Once the verifier says “no harm exists,” a unit/property candidate can become structurally untestable. This is circular.

A discriminator may refute a candidate, but it should not be able to make its rebuttal proof-free merely by restating the disputed premise. The rebuttal itself needs evidence.

#### 3. Severity controls whether a finding receives independent skepticism

The skeptic phase examines High/Critical findings. That is economical for severity calibration, but unsafe for recall when severity has already been reduced by a lossy phase. PRIVATE-FINDING-005 entered verification as Low, so the unsupported false-safe conclusion was never independently appealed.

Appeal eligibility should depend on **disagreement and premise uncertainty**, not only current severity.

#### 4. Fixed phase sequencing cannot react to unresolved obligations

The pipeline contains many conditional roles, but the control flow is still mostly phase-oriented. When a late gate discovers an unsupported external premise, the scheduler does not naturally return to research and then re-run verification. It stamps or routes an artifact after the verifier shards have completed.

This under-serves vulnerabilities whose proof requires iterative environment acquisition: external semantics, fork state, multi-contract mocks, specification clarification, complex state sequences, and formal properties.

#### 5. Role-scoped sweeps create correlated seams

Parallel role sweeps are useful, but they divide ownership by vulnerability lens. Many important findings live between roles: accounting plus authorization, state freshness plus external semantics, lifecycle plus upgrade, local correctness plus network behavior, or two individually safe functions whose composition is unsafe. Chain analysis helps only for candidates already represented with compatible pre/postconditions.

Without a typed relation model, composition is keyword- and prose-dependent. The architecture systematically under-serves **novel relational invariants and implicit protocol intent**.

### Structural precision failure modes

- Mechanical candidates are correctly low confidence, but the queue can become dominated by Low/Informational generator output. In private regression target, 138 of 184 queue rows were Low and 21 Informational. Fifteen-row verifier shards then make many sequential judgments in one session.
- Verification mostly produced code traces, not executed evidence: 159 of 185 verifier files recorded `Attempted: NO`; only 25 recorded `YES`. Mechanical execution protects against fabricated passes, but it cannot correct a prose-only false-safe.
- Dedup optimizes lexical or provenance overlap without a stable semantic identity. This creates both fragmentation and false merges.
- Severity is repeatedly copied, capped, floored, normalized, and inferred from prose. It is not calculated from one stable impact/precondition record.

### Vulnerability/reasoning classes under-served by this shape

1. Protocol-intent and economic-design bugs that require a formal statement of intended behavior.
2. Multi-transaction and long-horizon state machines whose relevant history is not in a bounded queue card.
3. External-integration bugs requiring live upstream semantics or deployed-state research.
4. Cross-contract/cross-chain failures where the tested local mechanism is real but material harm depends on another system.
5. Non-EVM client failures involving concurrency schedules, network partitions, resource exhaustion, nondeterminism, or distributed safety/liveness.
6. Emergent composition between candidates whose pre/postconditions are described differently.
7. Specification omissions: properties nobody wrote down cannot be proven or fuzzed.
8. Adversarial environment modeling: mandatory PoC execution is not equivalent to testing the correct environment.

## 2. Architecture correctness

### Driver and phase graph

The SC graph has 73 declared Thorough phases, 54 Core phases, and 50 Light phases. L1 has 57/47/43. The number itself is not the problem. The problem is that the graph is only superficially declarative:

- `Phase` declares name, markers, expected artifacts, timeout, model, mode, and a few gate flags.
- Actual agent construction, prompt selection, dynamic outputs, deterministic hooks, phase rewrites, and cross-phase mutations live across `main()`, `run_phase()`, `_run_phase_validators()`, prompt builders, validators, parsers, and mechanical modules.
- All `Phase.agent`/prompt ownership is effectively imperative.

This makes it hard to answer fundamental questions statically: What exact input schema does a phase consume? Which fields may it change? What evidence must survive? What event schedules a retry? Which later phase owns a newly created obligation?

### Disk gates

Disk artifacts are more reliable than model self-report, but “file exists and is large enough” proves only materialization. It does not prove semantic completion.

The `skill_execution_checklist.md` gate is the clearest example: the generic validator accepts it when it exceeds 200 bytes. private regression target's file claimed 22 skills executed and zero partial/not-executed, including integration research grounded in an empty ledger.

Status markers are useful envelopes. They should not be mistaken for semantic contracts.

### Worker pools

The worker pools improve containment, resumability, concurrency, and output ownership. They also create three risks:

1. **Method decomposition drift:** the coordinator methodology may contain work that no worker owns, as with recon external research.
2. **Auxiliary artifact suppression:** a skill may require a product that the single-output worker is forbidden to create.
3. **Input under-provisioning:** strict bounded reads can omit the exact evidence necessary to challenge a conclusion.

The right solution is not to relax containment. It is to compile each worker's declared method inputs and outputs into its task contract before execution.

### Mechanical substrate

The mechanical graph, queue JSON, verdict manifest, judge sidecar, canonical IDs, obligation ledgers, and PoC rerunner are valuable. They demonstrate the correct direction: state that affects control flow should be typed and deterministic.

But the layer is a federation of one-off sidecars. It does not define one canonical Candidate entity or an append-only transition log. Some consumers prefer JSON; others reparse Markdown; some mutate Markdown and refresh sidecars; others leave original ownership/hash records stale.

`plamen_contracts.py` describes the desired rule—valid JSON is authoritative; invalid JSON hard-fails; Markdown is a legacy import—but only `SpawnManifest` and `RescanManifest` are modeled. Production modules do not import or call `load_contract`; the live references are its tests and documentation. The architecture documentation therefore overstates the adoption of the contract layer.

### Shared mutable source workspace

Verification agents write PoCs and sometimes module declarations into the live audit tree. Mechanical verification runs from the live build root. No source snapshot, per-candidate worktree, overlay filesystem, or automatic source restore was found.

The word “isolated” in `mechanical_verify.py` refers to selecting an individual test/filter, not isolating filesystem state. This distinction matters.

In the private regression target tree, after excluding scratchpads/archives, Git reports 20 modified paths, 135 untracked paths, and 107 untracked PoC source files. Because there is no clean-start snapshot, not all are attributable to this run; that is itself the defect. Generated `poc_*.rs` files also appear in the client report's “Components Audited” table.

### Cleaner architecture

Keep the current analysis roles but introduce a load-bearing domain core:

```text
Frozen Source Snapshot
        |
Mechanical Code Model + Scope Manifest
        |
Obligation Scheduler ---- Method Work Units
        |                         |
Candidate Event Ledger <---- Agent/Tool Evidence Events
        |
Premise Closure + Verification Scheduler
        |
Disposition / Root-Cause Cluster Views
        |
Internal Evidence Report + Client Report Renderer
```

The canonical entities should include:

- `Candidate`: immutable ID, origin, claim, affected surfaces, mechanism, impact theory.
- `Assumption`: subject, predicate, polarity, scope, source type, status.
- `Evidence`: source-code trace, test execution, formal result, static result, external citation, specification citation.
- `MethodObligation`: method ID, step ID, enumerated target, required outputs, completion state, evidence references.
- `Relation`: duplicate-of, variant-of, enables, depends-on, contradicts, same-fix-as.
- `Decision`: actor, verdict, severity, reasons, rebutted premises, evidence references.
- `ArtifactEvent`: producer, source revision, input IDs/hashes, output IDs/hashes.

Phases append events. They do not overwrite candidates. Markdown files are deterministic projections for agents and humans. A parser failure can then invalidate a view without destroying the underlying objects.

### Hard invariants to enforce

1. Every emitted candidate has exactly one current terminal or active disposition.
2. No phase may delete or replace a candidate; it may add a decision or relation.
3. Every merge retains distinct candidate IDs; a cluster is a view, not a destructive collapse.
4. Every demotion/refutation names each defeating premise and evidence for it.
5. Unsupported external/spec/deployment premises yield `UNRESOLVED`, never `SAFE`.
6. Every required method obligation has `completed`, `not_applicable` with evidence, or `open`; absence is not success.
7. Every verifier runs against the same frozen source revision plus an isolated candidate patch.
8. Every client-report section maps to one root-cause cluster and lists constituent candidate IDs internally.
9. Every schema producer/consumer pair is contract-tested from the same model definition.

## 3. Prior-art and competitor comparison

### Leading human audits

OpenZeppelin publicly describes freezing an exact commit and scope, reviewing architecture and goals, assigning at least two auditors to the same codebase, mixing manual analysis with static/fuzz tools, communicating with developers, and reviewing isolated fixes. See [OpenZeppelin's audit process](https://www.openzeppelin.com/news/what-is-a-smart-contract-audit-lessons-from-openzeppelins-1000-audits).

Plamen approximates multiple reviewers with specialized agents, but differs in three important ways:

- human teams overlap on the same code, while many Plamen roles are disjoint;
- humans can ask the protocol team to resolve intent and deployment assumptions;
- professional workflows freeze the source revision and preserve reviewer notes rather than repeatedly compressing them through report schemas.

Borrow: frozen scope, at least two genuinely independent full-code passes, explicit client-question/assumption ledger, and fix review against isolated diffs.

### Static analysis and structured program models

Static analysis offers exhaustive enumeration over the representation it models: call graphs, dataflow, taint, dominance, write/read sets, inheritance, and reachable sinks. It is weaker at novel intent and economic harm, but stronger than LLM prose at “enumerate all” tasks. Trail of Bits' [Building Secure Contracts program-analysis material](https://secure-contracts.com/program-analysis/) treats tools such as Slither, Echidna, Medusa, and symbolic systems as complementary rather than interchangeable.

Plamen's mechanical graph is a good start. It should become the common address space for agent claims: stable function/state/call-site IDs, not file-line strings and titles.

Borrow: AST/IR-normalized identifiers, interprocedural dataflow, call/state graphs, and mechanically complete target sets. Use LLMs to interpret graph slices and propose properties, not to reproduce enumeration.

### Fuzzing and property testing

Fuzzers can search long input/state sequences and shrink failures. They capture boundary interactions and stateful emergent behavior that a one-example PoC misses. They prove existence of a counterexample under a harness, not absence of all failures.

Plamen currently uses fuzzing as conditional side work, while verification is mainly candidate-specific. It should promote invariant synthesis and harness quality to first-class artifacts, then preserve coverage/corpus/assumption metadata as evidence.

Borrow: state-machine handlers, coverage guidance, corpus reuse, invariant mutation testing, and explicit environment models.

### Symbolic execution and formal verification

Symbolic/formal tools can exhaustively prove bounded or specified properties across paths and transactions, but only relative to a model and specification. Solidity's [SMTChecker documentation](https://docs.soliditylang.org/en/latest/smtchecker.html) distinguishes bounded and CHC reasoning and documents abstraction/unknown limitations. Certora's documentation emphasizes [rule sanity/vacuity checks](https://docs.certora.com/en/latest/docs/prover/checking/sanity.html), [mutation testing](https://docs.certora.com/en/latest/docs/prover/checking/mutation.html), and invariant modeling ([CVL invariants](https://docs.certora.com/en/latest/docs/cvl/invariants.html)).

Plamen should borrow the meta-verification principles more than any single prover:

- prove that an obligation is non-vacuous;
- mutate code/spec and require the method to notice;
- record environment assumptions explicitly;
- classify `unknown` separately from `safe`;
- use generated counterexamples as Candidate evidence events.

### Other LLM-agent systems

Pashov's public design gets simplicity and function isolation right, but a single-pass dedup and no independent re-verification are incompatible with Plamen's recall objective.

Krait's public history is unusually useful because it reports both regressions and low recall. Its v3 “over-engineered” regression and v8.1 method-trace experiment support two conclusions: more modules/phases do not guarantee recall, and structured application fields can materially help. Its pilot fields should be mandatory, target-scoped, and mechanically validated if adopted; optional self-report is insufficient.

Grego's advertised AST/IR and graph foundation is likely a capability Plamen should match. Public marketing cannot establish its lifecycle correctness.

EVMbench contributes two important lessons. It uses 117 curated vulnerabilities from 40 audits and isolated deterministic environments for executable grading, and it observes that detection agents often stop after one issue. It also acknowledges that report matching cannot reliably classify novel findings. See [OpenAI's EVMbench description](https://openai.com/index/introducing-evmbench/) and the [open harness](https://github.com/paradigmxyz/evmbench).

Borrow: isolated graders, explicit exhaustive stop conditions, and distinct detection/patch/execution metrics. Extend them with lifecycle localization.

## 4. Mechanical deriver/gate layer

### Is the strategy sound?

Yes, with a strict boundary: deterministic code should mechanize completeness, reconciliation, and consistency over typed facts. It should not infer vulnerability truth from prose cues.

This is one of Plamen's strongest design ideas. The current execution is uneven.

### Where it helps most

- Enumerating functions, storage, calls, setters, events, and co-references.
- Diffing expected vs observed method targets.
- Reconciling every candidate with a disposition.
- Checking every claimed test against an actual command/result/assertion.
- Detecting missing report promotion.
- Enumerating untested boundaries, symmetric operations, and uncovered risk axes.
- Enforcing source revision and artifact provenance.
- Detecting producer/consumer schema drift before a live run.

### Where it becomes theater

1. **Regex over free prose is treated as a contract.** The committed-invariant and GRP suffix failures show that additive intent does not matter if the consumer cannot parse the producer.
2. **Warnings are dead ends.** private regression target logged the 19 dropped invariant blocks twice and completed without scheduling repair.
3. **Self-report is mechanically laundered.** Generic evidence tags are converted into “all skill steps executed.”
4. **Lexical data preservation substitutes for semantic preservation.** Report dedup retains verbatim absorbed sections and passes while root-cause identity is wrong.
5. **Late gates lack control-flow authority.** A post-aggregate “requeue” that does not create and execute a verifier task is a label, not a lifecycle repair.

### Mechanizable miss classes

| Miss class | Deterministic treatment |
|---|---|
| Producer/consumer ID grammar drift | Generate parsers/renderers from one schema; property-test all legal IDs |
| Candidate found but absent downstream | Set difference over immutable candidate IDs and dispositions |
| Distinct chain split collapsed | Preserve cluster membership; prohibit destructive ID replacement |
| Method assigned but target/step unaddressed | Enumerate `(method, step, target)` obligations and diff receipts |
| Auxiliary method artifact missing | Compile declared outputs into worker allowlist and phase gate |
| External premise uncited | Join assumption to research/spec evidence; mark open if absent |
| PoC claimed but not executed | Existing mechanical rerun/integrity downgrade, extended with assertion semantics |
| Boundary untested | Enumerate domain boundaries from types/guards and diff executed cases |
| Symmetric operation unpaired | Mechanical sibling set plus state/call signature comparison |
| Candidate merged but constituent fix/impact lost | Field-level constituent matrix; render cluster only when all distinct facets represented |
| Workspace drift | Hash frozen source and run each verifier in disposable worktree/overlay |
| Phase non-application | Phase input/output event parity plus obligation completion |

### Miss classes requiring judgment

- deriving a novel protocol invariant;
- deciding whether two mechanisms truly share a root cause/fix;
- judging realistic economic harm and attacker incentives;
- interpreting ambiguous protocol intent;
- deciding whether an external behavior is applicable to this integration;
- constructing a meaningful environment/harness rather than a tautological mock;
- identifying multi-step compositions not represented by explicit relations;
- severity calibration under uncertain deployment conditions.

Mechanical code can demand evidence and preserve uncertainty for these tasks. It should not decide them from keywords.

## 5. Recall improvements ranked by expected gain vs complexity

### Combined ranking

| Rank | Change | Primary miss side | Expected gain | Complexity | Why |
|---:|---|---|---|---|---|
| 1 | Typed append-only Candidate/Assumption/Evidence ledger with lifecycle invariants | Pipeline loss | Very high | Medium-high | Removes repeated lossy Markdown transformations and makes every drop/merge/demotion auditable |
| 2 | Demotion premise-closure gate plus independent appeal for any uncertain rebuttal | Found-then-false-safe | Very high | Medium | Directly targets roughly half of reported misses |
| 3 | Compile method work units and validate `(method, step, target)` receipts | Never-found/non-application | Very high | Medium | Directly targets the other reported half; replaces false coverage receipts |
| 4 | Fix and property-test all current schema drifts | Both | High immediate | Low | GRP suffixes, committed-invariant IDs, table-only provenance parsing, R10 candidate shape |
| 5 | Restore a real external-research owner in recon and gate dependency-row parity | Both | High for integrations | Low-medium | Prevents unsupported assumptions at their source |
| 6 | Freeze source and use disposable per-candidate verification workspaces | Precision and false-safe | Medium-high | Medium | Eliminates cross-candidate contamination and makes PoCs reproducible |
| 7 | Obligation-driven scheduler capable of research/reverify loops | Both | High | High | Allows late gates to cause real work rather than stamps |
| 8 | Fresh verifier session or small batch for disputed/high-value candidates | False-safe | Medium | Medium cost | Reduces sequential fatigue and correlated decisions |
| 9 | Program-analysis/formal/fuzz evidence providers integrated into the ledger | Never-found and proof | High long-term | High | Captures classes LLM prose cannot exhaustively reason about |
| 10 | Deterministic report renderer from root-cause clusters | Quality, not raw recall | Medium | Medium | Stops report-stage semantic loss and bloat |

### Discovery-side levers

1. **Method obligation compiler.** Each skill needs a small machine manifest:

   ```yaml
   method_id: integration-hazard-research.v1
   triggers: [NAMED_EXTERNAL_PROTOCOL]
   inputs: [dependency_ledger, call_sites]
   outputs: [hazard_catalog]
   steps:
     - id: ledger-row-per-dependency
       enumerate: dependency_ledger.required_dependencies
       success: cited_or_fetch_failed_row_exists
     - id: state-toctou-per-external-read
       enumerate: code_model.external_state_reads
       success: disposition_with_evidence
   ```

   The agent supplies judgment; the driver supplies target enumeration and completion accounting.

2. **Independent overlapping full-code passes.** Keep specialties, but add two smaller independent “entire system” reviews with different reasoning styles. Human firms gain recall from overlap, not only decomposition.
3. **Property discovery as an explicit product.** Track proposed invariants separately from findings; score their non-vacuity and mutation sensitivity.
4. **Risk-based scheduling.** Hot functions and open assumptions should drive more work. A fixed three-iteration ceiling should be replaced by budgeted obligation closure.
5. **Tool diversity.** Static/symbolic/fuzz/formal tools should emit the same typed candidates/evidence, not separate reports that agents may or may not read.

### Pipeline-loss levers

1. **No destructive transformations.** Dedup creates a cluster relation; it never deletes/relabels candidate identity.
2. **No severity-only appeal filter.** Trigger appeal on verifier/upstream disagreement, unsupported premises, unexecuted testable claims, or external/spec uncertainty.
3. **Field-level conservation.** Before a queue/report projection, mechanically assert preservation of mechanism, preconditions, assumptions, evidence, impact, and distinct fixes—not just IDs or locations.
4. **Terminal-disposition parity.** Every candidate must resolve to confirmed, refuted-with-proof, unresolved, duplicate-of, or out-of-scope-with-basis.
5. **Control-flow-capable gates.** A gate that says reverify must create a work item and block final disposition until that work item closes or explicitly degrades to human review.

## 6. Precision, anti-bloat, dedup, and severity

Recall-safe does not require showing every raw candidate as a full client finding. It requires preserving every raw candidate internally and making any suppression reversible and auditable.

### Separate three products

1. **Candidate evidence store:** lossless and verbose; all leads, refutations, tests, and assumptions.
2. **Reviewer workbench:** clusters, disagreements, unresolved premises, and evidence summaries.
3. **Client report:** concise root-cause findings with affected variants and evidence.

The current report attempts to make product 3 lossless by embedding absorbed reports verbatim. That is why it bloats.

### Two-stage dedup

- Before verification, generate non-destructive cluster suggestions to share context and tests. Never collapse identities.
- After verification, synthesize one report root only when mechanism, fix, trust boundary, and impact are compatible.
- Use an affected-variants table for sibling functions/contracts.
- If fixes differ materially, keep separate findings even at the same site.
- Never auto-merge solely because one source-ID set is a subset of another.

### private regression target report evidence

- Executive summary: 52 findings.
- Primary finding headings after dedup/floor: 36.
- Consolidated markers: 13.
- Approximate characters from consolidated blocks to the next finding heading: 69,824, about 40% of the report.
- Four unrelated findings—four distinct private finding roots—were absorbed into PRIVATE-FINDING-004, an unrelated private finding root.
- The report still says `DATA-LOSS GATE: PASS` because text survived.

This is not a cosmetic issue. A client can apply the wrong fix, miss ownership, misunderstand severity, and be unable to track remediation.

### False-positive reduction without recall loss

- Preserve weak candidates in the internal backlog rather than deleting them.
- Use cheap deterministic plausibility checks to prioritize verification, not assert falsehood.
- Require each reportable claim to name asset/control at risk, reachable actor, violating transition, and evidence.
- Classify environmental uncertainty separately from mechanism confidence.
- Use adversarial spec/harness review before calling a failed PoC a refutation.
- Track novel unadjudicated findings separately in benchmark precision.

### Severity

Store severity inputs, not only the label:

- impact asset/control and maximum loss;
- affected population and persistence;
- attacker capability;
- precondition evidence and controllability;
- likelihood of required external/deployment state;
- proof grade;
- uncertainty.

One independent severity arbiter should render Impact × Likelihood after verification. Other phases may propose severity but should not silently mutate it. Worst-case R10 behavior should be encoded as an assumption policy applied to structured premises, not a regex over verifier prose.

## 7. Blind spots and what I would do differently

### Biggest wrong assumptions

#### “Additive” means recall-safe

An additive producer is not recall-safe if the consumer silently rejects its schema or if its candidate is later destructively collapsed. Additivity must be proven across the whole lifecycle.

#### A disk artifact proves methodology application

It proves that some process wrote bytes. private regression target's synthesized traces and skill receipt demonstrate the gap.

#### Mandatory PoC execution makes verification proof-oriented

Only 25 of 185 verifier files attempted a PoC. The system is proof-oriented for positive claims that happen to produce tests; it is still prose-oriented for many refutations and demotions. A false-safe rebuttal needs as much proof discipline as a positive assertion.

#### More phases monotonically increase recall

Every phase can add discovery, but every serialization boundary can lose information. The marginal phase is beneficial only if it adds independent evidence while preserving canonical state.

#### Duplicate loss is cosmetic

A duplicate is cosmetic only when it is truly the same root cause, impact, and fix. The current code comment that a wrong merge is at worst cosmetic is disproved by the private regression target PRIVATE-FINDING-004 merge.

#### Haltless degradation is always recall-safe

Repair-then-degrade is appropriate for optional enrichment. For a failed proof of application, source integrity, candidate identity, or unsupported demotion, “continue” must carry a visible unresolved item into the client/reviewer result. A log warning alone is silent failure from the audit consumer's perspective.

### Single highest-leverage change

Build the **Candidate and Premise Ledger** first.

Do not begin with another scanner or a large orchestration rewrite. Introduce it at the inventory boundary and dual-write current Markdown plus typed events. Then migrate queue, verifier, and report consumers in order. This attacks the empirically dominant found-then-lost problem and creates the substrate required to fix false-safe decisions and methodology application.

### What I would retain

- deterministic driver ownership;
- isolated PTY worker output boundaries;
- mechanical code/reference graph;
- low-confidence additive generators;
- mechanical PoC rerun and evidence integrity downgrade;
- promotion-completeness principle;
- exploration skeptic, chain composition, and attention repair roles;
- resumability and checkpointing;
- ecosystem-specific methodology injection;
- recall-first internal retention.

### What I would retire

- Markdown as authoritative state;
- destructive candidate dedup/relabeling;
- generic evidence-tag-to-method-execution synthesis;
- warnings for known semantic loss without a tracked unresolved obligation;
- verifier-authored PoC escape based on its own disputed conclusion;
- shared mutable verification workspace;
- report “losslessness” measured by retained text tokens;
- phase-local patches that claim requeue without scheduler-level work creation.

## private regression target forensic: the PRIVATE-FINDING-001/PRIVATE-FINDING-005 lifecycle

This trace matters because it separates “the model missed it” from “the system lost it.”

| Stage | What existed | What happened |
|---|---|---|
| Recon | Blend was identified as a named external dependency | `external_dependency_research.md` remained a prepass stub with zero data rows because no live recon worker owned mandatory research |
| Inventory | PRIVATE-INVENTORY-001/042 described the cached/fresh-rate asymmetry and explicitly flagged `NEEDS_DEPENDENCY_RESEARCH` | Mechanism and uncertainty were present |
| Depth | External/state roles confirmed the sibling asymmetry and conditional harm; R10 worst-case handling retained material concern | Discovery succeeded |
| Chain retry | PRIVATE-FINDING-005 was deliberately split into `PRIVATE-GROUP-001` and `PRIVATE-GROUP-002` because roots were distinct | Correct anti-overmerge decision existed |
| Queue parser | `PRIVATE-GROUP-001/b` were not legal under `GRP-\d+`; retired PRIVATE-FINDING-005 was reconstructed and context collapsed | First pipeline loss |
| Queue card | PRIVATE-FINDING-005 entered as Low with `PRIVATE-ARTIFACT-ID-002, PRIVATE-ARTIFACT-ID-003`; explicit external-research context was no longer a first-class field | Evidence compression |
| Verifier prompt | Allowed reads were its row, exact source, and primary artifact; not the external ledger or all depth evidence | The verifier could not resolve the premise correctly from assigned inputs |
| Verifier | Confirmed the asymmetry, asserted `b_rate` was time-invariant from a local comment, marked no harm, skipped the unit PoC | Unsupported benign external premise became a false-safe conclusion |
| Mechanical verify | Correctly stamped no test/Code Trace | It checks proof integrity, not premise truth |
| Skeptic | Reviewed only High/Critical findings | No appeal because upstream severity was Low |
| Report | PRIVATE-FINDING-011 remained contested, then was mechanically absorbed into unrelated PRIVATE-FINDING-004 because provenance parsing consumed a prose summary line | Second semantic loss and client-report corruption |

The pipeline did not merely “find PRIVATE-FINDING-001 and then demote it.” It failed at recon task ownership, chain ID preservation, verifier context, rebuttal proof, appeal scheduling, and report semantic identity. Fixing only the final demotion predicate is therefore insufficient.

## Current R10 patch review

### What it intends

The direction is correct: if a confirmed in-scope mechanism is dismissed solely because of an uncited best-case external premise, veto the demotion, restore a severity floor, keep the item in the report, and reverify it under the worst realistic external condition.

That is a valuable defense-in-depth gate.

### Current replay result

Synthetic tests: **11/11 pass**.

Real private regression target isolated replay:

```text
finding_id       PRIVATE-FINDING-005
depth_verdict    (inv-absent)
verifier_sev     Low
restored_floor   Low
expected_sev     Low
promotion receipt absent
promotion routing absent
[promotion-gate] ledger write failed: KeyError('candidate_id')
```

The predicate noticed the real file, which is useful. It did not recover the professional finding outcome.

### Defects

1. **No depth join.** Queue IDs are H/GRP IDs; inventory blocks are INV IDs. The code calls final inventory a “depth verdict” but gets `(inv-absent)` and allows empty to pass.
2. **Low-to-Low floor.** It restores the queue's claimed severity. PRIVATE-FINDING-005 had already been reduced to Low, so it cannot recover depth's Medium or professional High assessment.
3. **No real requeue.** The hook runs after verifier shards at `verify_aggregate`. It cannot rewind the phase graph. The `route_promotion_orphans` call receives `disposition=NEEDS_VERIFICATION`, while Gate P recognizes `BODY`/`APPENDIX_C` and expects a full candidate shape. It fails on missing `candidate_id` and writes no executable verification work.
4. **Test isolation hides the integration defect.** The test imports `plamen_validators` but not the mechanical router and asserts only the local ledger/stamp behavior.
5. **External cue precision is lexical.** Generic “stable per block/timestamp” prose can match internal invariants with no external dependency.
6. **`EXT-CITED` suppression is syntactic.** A matching location and tag do not prove the citation supports the benign premise.
7. **Any attempted PASS/FAIL suppresses the gate.** A local test may validate the mechanism without validating the external premise.
8. **REFUTED is excluded.** Unsupported false-safe conclusions may use `REFUTED`, likely an important portion of the stated 50% demotion misses.

### Grade

| Dimension | Grade | Rationale |
|---|---|---|
| Problem selection | A- | Directly targets an observed asymmetric policy failure |
| Generic/no-overfit design | B | No protocol name, but lexical stability cue is broader than a typed external premise |
| Predicate correctness | C | Detects PRIVATE-FINDING-005 but does not prove depth confirmation or external dependency |
| Lifecycle/control-flow correctness | F | Does not produce or execute a re-verification task |
| Severity recovery | D- | Restores an already-lossy queue label |
| Synthetic tests | C | Good local fire/no-fire cases; no router/scheduler integration |
| Claimed private regression target recovery | F | PRIVATE-FINDING-005 remains Low and was already in the report body; no new verification executes |
| Overall current patch | D+ | Useful detector prototype, not the claimed fix |

### Commit recommendation

**Do not commit the current patch under the claim that it recovers PRIVATE-FINDING-001 or requeues PRIVATE-FINDING-005.** It can be retained as a detection ledger prototype after its log/message is corrected.

Minimum acceptance criteria:

1. Join the immutable candidate lineage, not H-to-INV string equality.
2. Read the last supported upstream severity/evidence event, not the queue label.
3. Emit a first-class `VerificationObligation` consumed by a real second-pass verifier phase.
4. Require a premise record classified as external and unresolved; do not infer only from prose.
5. Re-run the candidate in a disposable workspace and record a new verdict event.
6. Test the real Gate P/scheduler import path and assert a new verifier receipt exists.
7. Replay private regression target and assert the final cluster is not false-merged and the unresolved premise is visible.
8. Run multi-repository no-fire regression and report candidate-level deltas.

R10 should remain a narrow backstop. The primary fix is premise closure at the original verifier boundary plus the missing recon research role.

## Phase-by-phase dataflow audit

### SC discovery and synthesis

| Phase(s) | Declared output | Actual role | Main contract risk |
|---|---|---|---|
| `recon` | 11 canonical recon files | Prepass plus 2/4 direct workers and merge | Worker decomposition omits tasks from monolithic methodology; stub files satisfy presence |
| `instantiate` | `spawn_manifest.md` | LLM plans breadth/depth roster | Manifest remains Markdown; typed `SpawnManifest` is not used in production |
| `breadth` | `analysis_*.md` | Parallel specialty workers | Skill application is instructed but not target/step-accounted |
| `rescan_prepare` | `rescan_manifest.md` | Deterministic plan | Good separation; typed `RescanManifest` not used |
| `rescan` | rescan and per-contract analyses | Parallel gap/contract workers | Generated PoC/source files can contaminate per-contract scope |
| `inventory_prepare` | shard plan | Deterministic planning | Useful bounded synthesis |
| `inventory_chunk_a/b/c` | chunk inventories | LLM extraction/synthesis | Repeated prose parsing can alter titles, IDs, evidence, and verdicts |
| `inventory` | `findings_inventory.md` | Merge/canonicalize | “Canonical” file is later mutated and not an immutable source of truth |
| `invariants`, `invariants_p2` | `semantic_invariants.md` | LLM invariant/gap generation | Free-form IDs and append-in-place state create consumer drift |
| `depth` | many depth/scanner/niche/sidecar files | Direct worker pool | Single-output containment conflicts with auxiliary skill products; synthesized traces create false application success |
| `attention_repair` | repair summary | Repair from gaps | Cannot repair gaps that telemetry falsely declares closed |
| `rag_sweep` | validation | External/retrieval validation | Useful, but external dependency truth should already be structured in recon |
| `exploration_skeptic` | additive findings and committed invariants | Challenge completeness | 19/24 committed-invariant blocks not harvestable |
| `enumgap_exploration` | obligation exploration | Converts mechanical hints into investigations | Correct pattern; should consume typed obligations |
| `axis_coverage` | axis findings | Fills hot-function/axis gaps | “Examined” should be target-level evidence, not tag inference |
| `sc_semantic_dedup` | dedup decisions, deduped inventory | LLM semantic clustering | Destructive dedup before verification risks losing distinct claims |
| `chain`, `chain_agent2`, `chain_iter2` | hypotheses/mapping/compositions | Root/chain synthesis | Correct anti-overmerge split was undone by downstream ID grammar |

### SC verification and reporting

| Phase(s) | Declared output | Actual role | Main contract risk |
|---|---|---|---|
| `sc_verify_queue` | queue Markdown/JSON | Build/shard candidates | Lossy card compression and hypothesis collapse |
| `sc_verify_crithigh`, `high_b..j`, `medium_a..j`, `low_a..j` | dynamic `verify_*.md` | Sequential per-shard verification | Same worker handles many rows; bounded context omits evidence; shared source workspace |
| `sc_verify_aggregate` | `verify_core.md` | Aggregate and apply post-verifier policies | Late gates cannot naturally schedule prior verifier work |
| `sc_mechanical_verify` | manifest plus stamps | Re-execute referenced tests | Strong for proof integrity; not filesystem-isolated and cannot adjudicate prose premises |
| `post_verify_extract` | extracted candidates | Mine verification for new issues | Correct additive concept; should append events |
| `skeptic` | skeptic/judge decisions | High/Critical adversarial severity review | Severity-gated appeal misses already-demoted candidates |
| `crossbatch` | consistency | Cross-verifier comparison | Useful; needs typed field comparisons |
| `report_index` | index/coverage | Decide report population | Generic parser titles and repeated status inference |
| body writers and tier shards/merges | tier Markdown | Compose report bodies | Multiple rewrite boundaries; data duplication |
| `report_assemble` | audit report | Assembly | Scope is derived from contaminated live artifacts |
| `report_dedup_agent`, `report_dedup` | decisions/mapping | LLM plus mechanical dedup | Prose line misparsed as provenance; unrelated roots merged |
| `report_disposition`, `report_floor` | disposition/floor ledgers | Material-harm routing | Useful policy but applied after semantic corruption; 28 items moved in private regression target |

### L1-specific delta

The L1 graph shares the same inventory, depth, verification, and report architecture, so the lifecycle findings apply. It adds `bake`, graph sweeps, and location recovery, which are helpful structured inputs. It also has injectable methods that require auxiliary artifacts such as `config_parameter_usage.md`, `tx_type_caps.md`, and `peer_scoring_symmetry.md`; these must be checked against single-output worker containment in the same way as the integration catalog.

## Measurement redesign

One aggregate recall/precision score is not enough to improve this system. Record:

1. **Discovery candidate recall:** was any semantically equivalent candidate emitted?
2. **Mechanism recall:** was the correct code-level root cause represented?
3. **Impact/precondition recall:** were the required harm conditions preserved?
4. **Pipeline survival:** did the candidate remain traceable to a terminal disposition?
5. **False-safe rate:** ground-truth findings marked refuted/harmless.
6. **Unsupported-demotion rate:** demotions containing at least one premise without adequate evidence.
7. **Method application coverage:** completed `(method, step, target)` obligations / required obligations.
8. **Report root-cause recall:** did a distinct client-remediable root appear as its own report finding or explicit variant?
9. **Fragmentation:** report roots per ground-truth root.
10. **False merge rate:** clusters containing incompatible fixes or mechanisms.
11. **Severity error:** distance on Impact and Likelihood separately.
12. **Novel adjudication yield:** valid non-ground-truth findings after independent review.

For each miss, automatically classify the earliest failing stage:

```text
scope -> method scheduled -> method applied -> candidate emitted ->
inventory retained -> chain/dedup retained -> queue retained ->
verifier premise-correct -> execution adequate -> disposition retained ->
report root retained -> severity calibrated
```

This will stop the team from adding discovery prose to fix a report parser, or adding a late gate to fix missing recon work.

## Recommended implementation sequence

### Release 1: immediate correctness fixes

- Accept the complete legal committed-invariant and hypothesis ID grammars from one shared schema.
- Parse only actual table rows in `finding_mapping.md`; never all co-occurring IDs in prose.
- Add fixture/property tests using the exact private regression target artifacts for those defects.
- Restore an explicit recon external-research worker and require dependency-set parity even on fetch failure.
- Replace “warning only” for known dropped candidates with an unresolved obligation carried to the run result.
- Correct R10 messaging so detection is not called requeue/reverification until it is real.

### Release 2: candidate ledger at inventory through verification

- Introduce typed `Candidate`, `Assumption`, `Evidence`, `Relation`, and `Decision` models.
- Dual-write current Markdown and a canonical append-only JSONL/SQLite event store.
- Build queue cards from IDs/references rather than copied prose.
- Make verifier output a typed decision plus rendered Markdown.
- Enforce candidate terminal-disposition parity.

### Release 3: premise closure and real appeals

- Require structured rebuttal premises.
- Add external/spec/deployment evidence joins.
- Schedule independent appeal for unsupported or disputed demotions at every severity.
- Add a real verification-obligation queue after late gates.

### Release 4: methodology compiler

- Add manifests for high-value skills first.
- Mechanically enumerate targets from the code/reference graph.
- Delete generic evidence-tag trace synthesis.
- Make incomplete auxiliary outputs valid open obligations, not fake success.
- Add mutation tests: remove a required analysis result and require the gate to fail.

### Release 5: isolation and report rendering

- Freeze commit/scope and hash all in-scope files.
- Use disposable Git worktrees/overlays per candidate; capture PoC patches/results.
- Render internal and client reports from typed clusters.
- Remove verbatim absorbed report bodies and generated PoCs from audited scope.

### Release 6: obligation-driven scheduling and tool expansion

- Replace fixed loops with budgeted closure of high-value open obligations.
- Integrate static, fuzz, symbolic, and formal results as evidence providers.
- Run benchmark ablations to justify every always-on phase.

## Final assessment

Plamen is battle-tested in the useful sense: it has accumulated concrete defenses from real misses. It is also showing the classic failure mode of an organically hardened system: every local postmortem adds a phase, parser, sidecar, regex, or gate, but no central semantic model absorbs the lessons. Local defenses then interact in ways their authors did not intend.

The best next move is not to copy an opaque competitor or add more methodology text. It is to make the findings, assumptions, method obligations, and evidence impossible to lose.

If that foundation is built, the existing breadth/depth expertise becomes more valuable: agents can still be creative and ecosystem-specific, while deterministic code handles identity, completeness, provenance, and lifecycle. That division of labor is the strongest route to the stated objective—recall first, then precision and report quality—without uncontrolled bloat.

