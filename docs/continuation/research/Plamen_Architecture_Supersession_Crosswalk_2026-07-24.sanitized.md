# Plamen Architecture Supersession Crosswalk

Date: 2026-07-24  
Status: read-only architecture disposition; not an implementation or completion claim  
Implementation repository: `<LOCAL_USER_ROOT>\plamen-codex-implementation`  
Observed repository state: HEAD `67a0f85adc7a8169d79a286908b00bef7adb764a` plus a large uncommitted working tree  
Validation performed: source/document inspection only; no tests, audits, ground-truth access, network access, configuration changes, or repository edits

## 1. Executive disposition

The seven absent Section 19 artifacts must not be recreated verbatim from the
2026-07-15 architecture plan. Their semantic requirements remain valid, but the
proposed physical architecture does not.

The governing supersession is:

> Replace the proposed single SQLite finding/event/work ledger with
> domain-typed, immutable JSON authorities and projections, owned and committed
> through PhaseIO, semantic-mutation journals, report transactions, CAS-backed
> worker incorporation, and exact reconciliation. Preserve every identity,
> lifecycle, premise, evidence, application, negative-authority, report, retry,
> and recovery invariant. Do not restore a big-bang database cutover.

The current tree contains substantial pieces of that strangler architecture,
but it does not yet provide one complete architecture contract and does not
satisfy the acceptance ledger's `DONE` boundary. This crosswalk therefore
classifies each requirement as one of:

- `LIVE-PARTIAL`: production-reachable source exists, but the intended
  end-to-end authority or acceptance evidence is incomplete.
- `LIVE-SCOPED`: production-reachable for a narrower phase or domain than the
  canonical requirement.
- `SHADOW/TEST`: schema or implementation substrate exists but is not the live
  authority for the intended path.
- `DESIGN-ONLY`: a reviewed implementation design exists, but production code
  does not.
- `MISSING`: no adequate design or implementation exists.
- `EXTERNAL-BLOCKED`: implementation depends on a governed external input or
  authority that is intentionally unavailable.
- `SUPERSEDED-PHYSICAL`: the semantic requirement survives, but the original
  SQLite/database mechanism is rejected.

No `LIVE-*` label in this document means `PROVEN`. The plan-completion audit
correctly classifies nearly all implementation rows as `IMPLEMENTED_UNPROVEN`
or `IN_PROGRESS`.

## 2. High-level disposition of the seven absent artifacts

| Original Section 19 path | Original purpose | Current disposition | Principal superseding sources | Residual canonical action |
|---|---|---|---|---|
| `architecture/method-application-rfc.md` | Shared semantic objects, lifecycle, invariants, concurrency, and errors | Still required, but must describe the typed-sidecar/PhaseIO architecture, not a database-centered object store | `methodology_application*.py`, `security_obligation_*.py`, `finding_lifecycle_authority.py`, `artifact_ledger.py`, `phase_io_contracts.py`, the P0-I/P0-AM/terminal-negative designs | Create a revised normative RFC and make it the shared authority/policy contract |
| `architecture/ecosystem-graph-provider-contract.md` | Common graph facts, provider capabilities, provenance, build matrices, conformance, fallback | Still required and materially revised | CPG/adaptive research; `recon_prepass.py`; `enumeration_type_ir.py`; `enumeration_anchor_facts.py`; asset-representation foundation | Create an additive program-facts provider contract; no graph-derived negative authority |
| `methodology/method-cards-v1.yaml` | Versioned universal methods, selectors, steps, receipts, prompts, capability requirements | Still required; current prompt/verification registries are incomplete substitutes | breadth semantic kernel; verification method registry/compiler; skills; skill selection and application ledgers | Create one machine-readable catalog as the sole normative method-content source |
| `architecture/finding-ledger-migration.md` | SQLite schema, dual-write, IDs, reconciliation, projection, rollback, parser retirement | Original physical design is superseded | PhaseIO/artifact ledger, finding lifecycle, inventory reconciliation, report disposition/mutation, semantic dedup, assurance projections | Do not create a second normative design; add a non-normative redirect to the migration section of the revised method-application RFC |
| `benchmarks/application-coverage-evaluation-plan.md` | Corpora, GT schema, leakage, lifecycle metrics, ablations, competitor protocol, thresholds | Still required; implementation is mostly absent or external-blocked | Goal ledger B0/B1 rules; post-audit protocol; terminal audit preparation; CPG/adaptive neutral experiment | Create a governed, GT-blind evaluation contract and real-run RunBundle adapter plan |
| `architecture/work-unit-scheduler.md` | Semantic stages, leases, idempotency, retries, budgets, convergence, follow-ups, human review | Still required and materially revised | queue/roster modules; P0-AM WorkerTransaction design; CPG adaptive-channel design; PhaseIO | Create one scheduler/worker-transaction contract; do not duplicate backend or method content |
| `architecture/premise-and-disposition-policy.md` | Polarity, sources, research, challenge, severity, and R10 migration | Semantics remain required, but should be part of the shared authority RFC | candidate-negative/application-skeptic, severity ledger/runtime, negative-closure policy/broker, terminal-negative design, report disposition | Add a redirect to the normative premise/disposition section of the revised method-application RFC |

The minimum canonical set is therefore five normative artifacts, not seven:

1. `architecture/method-application-rfc.md`
2. `architecture/ecosystem-graph-provider-contract.md`
3. `methodology/method-cards-v1.yaml`
4. `architecture/work-unit-scheduler.md`
5. `benchmarks/application-coverage-evaluation-plan.md`

The two retired paths should exist only as short supersession notices pointing
to exact sections of `method-application-rfc.md`. They must contain no copied
schemas, policy text, or methodology.

## 3. Canonical invariant translation: old architecture to current target

| 2026-07-15 invariant or mechanism | Required target meaning | Superseding mechanism | Current state |
|---|---|---|---|
| One canonical state store | Exactly one authorized source for each semantic decision; no competing Markdown/model/callback authority | Domain-specific typed authorities loaded through one consumer boundary; Markdown is projection or proposal | `LIVE-PARTIAL` |
| Append-only semantic history | Prior accepted identities, evidence, decisions, and lineage remain replayable | Generation-linked JSON ledgers, semantic-mutation events, immutable receipts, applied-alias chains | `LIVE-PARTIAL` |
| Stable identities | Display IDs never serve as joins; content, source, premise, work, and alias identities remain exact | canonical finding map, typed queue IDs, Source-ID lineage, content/premise digests, work-plan IDs | `LIVE-PARTIAL` |
| Transactional writes | No output gains authority without pre-execution input/output-prestate binding and checked commit | PhaseIO input arm, output commit/quarantine, report mutation transaction, proposed worker CAS incorporation | PhaseIO `IN_PROGRESS`; worker incorporation `DESIGN-ONLY` |
| Idempotent retries and leases | Retry only exact missing/invalid work; no duplicate authority or late writers | stable queue/work IDs, verifier rosters, attempt-specific WorkerTransaction design | verifier `LIVE-SCOPED`; generic worker lifecycle `DESIGN-ONLY` |
| Explicit uncertainty | Missing, malformed, stale, failed, unsupported, capped, or timed-out work cannot become clean absence | typed debt, quarantine, assurance limitations, unresolved queues, terminal-negative default retain/reopen | `LIVE-PARTIAL` |
| Report as projection | Writers cannot create, delete, rerate, or silently omit canonical findings | report-disposition authority, report transaction, mandatory reverification, lifecycle retention | `LIVE-PARTIAL` |
| Provider capability/fidelity routing | Precise, conservative, approximate, unavailable, and failed facts have different authority | current graph/source/type facts plus proposed program-facts receipt and capability vocabulary | current facts `LIVE-SCOPED`; common provider contract `MISSING` |
| Database backup/recovery | Durable recovery must replay immutable artifacts and journals without minting retroactive authority | snapshot binding, PhaseIO recovery, semantic-mutation recovery, report transaction recovery, proposed worker transaction recovery | `LIVE-PARTIAL` |
| JSONL export | A portable, hash-bound run/evaluation bundle must preserve typed records and artifacts | proposed GT-blind `RunBundle`; no requirement that JSONL itself be authoritative | `MISSING` |

## 4. `architecture/method-application-rfc.md` requirement crosswalk

### 4.1 Shared records and semantic separations

| ID | Intended requirement | Current implementation/artifact | Status | Residual action |
|---|---|---|---|---|
| MA-01 | A run manifest binds run ID, source snapshot, repository revision/content, mode, ecosystems, driver, method catalog, prompt bundle, providers, toolchains, OS, and backend | `audit_snapshot.py`, config/checkpoint/run IDs, backend runtime contract, per-authority receipts | `LIVE-PARTIAL` | Define one normative binding envelope and say which existing artifacts jointly satisfy it; do not add a database table |
| MA-02 | MethodCard is a versioned, stable semantic method record | breadth kernel, skills, `verification_method_registry.v1.json` | `LIVE-SCOPED` | Define the catalog schema in `method-cards-v1.yaml`; current verification operators are only one consumer profile |
| MA-03 | Obligation binds method/version, exact targets/relations, source snapshot, origin/parents, materiality, uncertainty, capabilities, completion requirements, and semantic idempotency | security-obligation authority/lifecycle, queue work items, verification method dispatch, axis/enumgap worklists | `LIVE-PARTIAL` | Define a common obligation envelope and adapters; do not force every domain into one physical ledger |
| MA-04 | EvidenceReceipt binds exact obligation/work/worker/prompt/method/targets/steps/evidence/outcome/candidates/premises/artifact hash | methodology application receipts, verifier output receipts, evidence capabilities, WER receipts | `LIVE-PARTIAL` | Specify receipt composition and the distinction between application attestation, execution observation, and semantic authority |
| MA-05 | Application coverage and finding correctness are orthogonal | `methodology_application_states.py` separates application completeness, delivery integrity, semantic outcome, and evidence basis | `LIVE-SCOPED` | Generalize beyond selected skill/verification paths and require every MethodCard consumer to preserve both axes |
| MA-06 | Claim records decompose mechanism, reachability, precondition, invariant, effect, external behavior, harm, likelihood, and remediation | distributed across finding lifecycle, severity, evidence, and negative-closure records | `LIVE-PARTIAL` | Define a shared claim reference vocabulary; do not introduce a monolithic claim database before consumers exist |
| MA-07 | Premises are stable, direction-aware objects with scope, source class, research status, challenge status, and decision use | severity ledger premise IDs/kinds; candidate-negative premise IDs; negative broker subject bindings | `LIVE-PARTIAL` | Add the normative premise schema and exact adapter rules in the RFC |
| MA-08 | Candidate and finding share stable lineage; human display IDs are never join keys | finding lifecycle authority, canonical finding identity map, queue identity/lineage, Source-ID preservation | `LIVE-PARTIAL` | Publish the canonical identity precedence and collision rules; finish all-consumer parity |
| MA-09 | FindingEvent is append-only; state is a deterministic fold, never an in-place Markdown history edit | finding lifecycle generations, semantic mutation events, specialized ledgers | `LIVE-PARTIAL` | State explicitly that per-domain immutable events/generations supersede one universal SQL event table |
| MA-10 | DispositionDecision binds exact finding/content, decision, before/after state or severity, claims, premises, evidence, counterfactual, challenge, and policy result | report disposition, severity decisions, semantic dedup authority, central negative decisions | `LIVE-PARTIAL` | Define shared minimum decision bindings and effect-specific extensions |
| MA-11 | Root-cause clustering preserves all members, evidence, consequences, and affected components | semantic dedup authority, chain grouping authority/assurance | `LIVE-PARTIAL` | Finish transitive PhaseIO and report binding; document that clustering is relation/projection, never deletion |
| MA-12 | ReportProjection is deterministic over current authorized state and includes body, appendices, exclusions, unresolved review, and coverage summary | report disposition authority, report mutation transaction, mandatory reverification, assurance limitations | `LIVE-PARTIAL` | Make exact report/body/sidecar parity normative and close final integrated evidence |

### 4.2 Lifecycle and hard invariants

| ID | Intended requirement | Current implementation/artifact | Status | Residual action |
|---|---|---|---|---|
| MA-13 | Obligation lifecycle distinguishes derived, scheduled, active/attempted, receipt submitted, validated, supported/refuted/not-applicable, follow-up, invalid, retry, and human-review debt; unqualified `completed` is forbidden | security-obligation lifecycle; methodology application states; verifier roster/debt | `LIVE-PARTIAL` | Reconcile state names through an adapter matrix and prohibit terminal clean state from file presence |
| MA-14 | Finding lifecycle separates candidate, triage, verification, mechanism, harm, external-fact uncertainty, evidence state, and report placement | finding lifecycle authority; evidence capabilities; severity/report authorities | `LIVE-PARTIAL` | Publish a common state projection and close central terminal-negative authority |
| MA-15 | Every candidate-producing receipt points to a stable candidate/finding, and every candidate has a current state | finding producer registry, finding lifecycle authority, inventory reconciliation | `LIVE-PARTIAL` | Close all producer/backend/ecosystem paths and final lifecycle reconciliation |
| MA-16 | Every dismissal, downgrade, merge, split, or exclusion is an explicit evidence- and premise-bound decision | semantic dedup, severity ledger, report disposition, central negative broker | `LIVE-PARTIAL` | Remove remaining prose/regex/caller fallback seams; add exact content plus premise bindings everywhere |
| MA-17 | No report index/body/tier entry may exist without a canonical finding; every eligible finding is body, appendix, or explicitly excluded | report-index machinery, report disposition, mandatory reverification | `LIVE-PARTIAL` | Complete exact report block bindings and no-ship reconciliation |
| MA-18 | Merge never deletes members; split preserves parentage and original evidence | semantic dedup applied-alias receipts; chain grouping relation-only repair | `LIVE-PARTIAL` | Finish integrated alias/report parity and fault/resume evidence |
| MA-19 | Proof-grade status requires exact executed evidence bound to the decisive claim; missing/malformed evidence cannot produce proof or safe dismissal | evidence capabilities, execution-scope runtime, mechanical successor receipts, negative-closure policy | `LIVE-PARTIAL` | Finish all-severity/provider/backend execution and terminal-provider authority |
| MA-20 | Unresolved material obligations are always visible in coverage or human-review output | assurance limitations, lifecycle report retention, repair/debt queues | `LIVE-PARTIAL` | Bind axis, gate, program-facts, worker, negative-provider, and scheduler debt into the unified projection |
| MA-21 | Resume cannot reuse changed semantic inputs; source/provider/method/prompt/tool/model dependencies invalidate exact descendants | audit snapshot, artifact ledger semantic freshness/invalidation, PhaseIO contracts | `LIVE-PARTIAL` | Finish shared PhaseIO commit-CAS/output-prestate migration and independent review |
| MA-22 | Provider fidelity propagates into obligation/evidence confidence and may not mint exact completion | security-obligation feature facts, asset-representation provider matrix, type IR | `LIVE-SCOPED` | Generalize under the program-facts provider contract |
| MA-23 | A worker cannot be its own required challenger | application skeptic, severity adjudication identities, terminal-negative reviewer design | `LIVE-PARTIAL` | Replace WER assessor-name metadata with linked executions and enforce independence in every applicable domain |
| MA-24 | Rendering is deterministic from a fixed state hash | report transactions, report disposition/mutation digests | `LIVE-PARTIAL` | Add one final report/state binding and reproducible render acceptance |

### 4.3 Compilation, concurrency, and failure semantics

| ID | Intended requirement | Current implementation/artifact | Status | Residual action |
|---|---|---|---|---|
| MA-25 | Compile each method by provider capabilities, applicability, exact targets, relations/paths/boundaries/pairs, stable obligations, worker strategy, and unavailable-fact debt | security-obligation derivation and verification method compiler are narrower implementations | `LIVE-SCOPED` | Implement the catalog-wide obligation compiler after method-card and provider contracts stabilize |
| MA-26 | Mechanization enumerates consideration work but never concludes vulnerability or safety | enumeration gates, candidate-negative policy, CPG research consumer rules | `LIVE-PARTIAL` | Enforce via populated gate registry and provider/consumer authority lint |
| MA-27 | Evidence validation checks locations, target membership, step states, hashes, execution commands/results, valid N/A reasons, complete targets, external citations/status, and canonical finding references | methodology application validator, verification method compiler, evidence capabilities | `LIVE-PARTIAL` | Define the common validation interface and add MethodCard-specific fixtures |
| MA-28 | Independently sample apparently clean/no-candidate receipts | application skeptic currently targets structured negative outcomes; terminal-negative review design is stricter | `LIVE-SCOPED` | Define sampling policy and measured false-safe budget in evaluation/gate documents |
| MA-29 | Convergence creates follow-up work for new relations, external premises, reachability disputes, supported mechanism/unresolved harm, tool-model conflict, severity inconsistency, low graph fidelity, or writer-created claims | specialized late/reverify/chain/severity/assurance queues | `LIVE-PARTIAL` | Encode all trigger classes in the scheduler contract; no free-form recursive phase growth |
| MA-30 | Niche methods are fact/capability triggered and read only exact cards plus common evidence protocol | skill selection authority and skill consumer coverage | `LIVE-PARTIAL` | Move normative method content into the catalog and retain skill files as referenced prompt/executor material |
| MA-31 | The honest application checker follows expected -> obligation -> valid receipt -> step evidence; models do not invent the coverage universe | methodology application modules and security-obligation authority | `LIVE-SCOPED` | Extend to the universal catalog and all backends/ecosystems |
| MA-32 | Work is idempotent and concurrency-safe; one semantic output has one owner; retries do not duplicate state | PhaseIO ownership, typed queues, verifier rosters | `LIVE-PARTIAL` | Implement generic WorkerTransaction and PhaseWorkRoster incorporation |
| MA-33 | Failure is haltless only when it emits typed debt, identifies affected subjects, prevents false completion, schedules fallback, surfaces material debt, and lowers coverage confidence | quarantine/debt/assurance patterns exist | `LIVE-PARTIAL` | Remove remaining false-clean paths, especially axis and provider/gate zero cases |

## 5. `architecture/ecosystem-graph-provider-contract.md` requirement crosswalk

| ID | Intended requirement | Current implementation/artifact | Status | Residual action |
|---|---|---|---|---|
| GP-01 | One common graph core covers packages/modules/contracts, stable entities, types, entry points, calls, dispatch, effects, control/data flow, privileges, storage/object relations, external boundaries, and build provenance | `_mechanical_graph.json`, SCIP/source/Slither paths, typed signature/state/anchor facts cover subsets | `LIVE-SCOPED` | Define `plamen.program_facts.v1` and extension points; do not flatten into unversioned arrays |
| GP-02 | Typed entities and facts carry stable IDs, qualified names, exact locations, provider symbol identity, typed predicates, qualifiers, and evidence provenance | graph v3 foundations and typed signature/anchor facts | `LIVE-SCOPED` | Normalize occurrence IDs and fact bindings across ecosystems |
| GP-03 | Multiple overlays may contribute facts with distinct provenance and confidence | existing source/SCIP/Slither/model facts are combined, but without one reviewed overlay contract | `LIVE-PARTIAL` | Keep facts in a dedicated sidecar; legacy graph stores only a digest/capability reference |
| GP-04 | Provider manifest pins provider/version, ecosystem, toolchain, snapshot, build matrix, capabilities, limitations, and artifacts | audit/build snapshots and provider names are fragmented | `LIVE-PARTIAL` | Implement the CPG research receipt fields, including compiled-file denominator and exact build/config/environment |
| GP-05 | Controlled capability/fidelity vocabulary distinguishes precise, conservative, approximate, unavailable, failed, partial, degraded, and unknown | several local vocabularies exist | `LIVE-SCOPED` | Publish one normative vocabulary and conversion table |
| GP-06 | Source/build/provider/config freshness is semantic and content-bound, never mtime-only | snapshot/PhaseIO freshness exists; legacy graph freshness includes weaker behavior | `LIVE-PARTIAL` | Give program-facts bake its own PhaseIO unit and exact reuse predicate |
| GP-07 | Provider failure, partial build, unsupported construct, exclusion, truncation, or zero facts produces explicit debt, not absence proof | CPG design specifies it; existing graph paths do not uniformly enforce it | `DESIGN-ONLY` for common contract | Implement receipt/debt artifacts and forbid clean `FULL` without exact denominator |
| GP-08 | Graph consumers may add obligations, prioritize, create slices/disagreements, and widen context; graph facts cannot suppress, demote, refute, or certify clean application | CPG/adaptive research gives exact G1/G2/M1/M2/chain rules | `DESIGN-ONLY` | Add consumer-specific typed adapters and authority tests |
| GP-09 | Static/model disagreement creates mandatory review | CPG research | `DESIGN-ONLY` | Add stable disagreement obligation and assurance projection |
| GP-10 | Models receive bounded, source-bound fact slices and IDs, not an unbounded raw graph | CPG research and current bounded context patterns | `DESIGN-ONLY` for program facts | Implement slice provider and receipt |
| GP-11 | EVM provider uses compiler/AST/storage/ABI/source-map/build facts with Slither enrichment and explicit proxy/modifier/alias/assembly/profile limits | current Slither/source graph is partial; PR #21 spike is not pipeline code | `LIVE-SCOPED` | Deliver EVM emit-only provider first, then one measured additive consumer at a time |
| GP-12 | Go provider uses build-aware packages/types/SSA and labelled CHA/RTA/VTA roots; handles tags, dispatch, reflection, unsafe, cgo, goroutines, channels | SCIP/source graph exists; Go SSA provider does not | `DESIGN-ONLY` | Implement a small pinned Go helper after v1 contract |
| GP-13 | Rust/Solana/Soroban provider handles HIR/MIR or honest approximation, traits/dynamic dispatch, macros/features, unsafe/FFI, account/auth/storage semantics | SCIP/source graph and local ecosystem facts are incomplete | `DESIGN-ONLY` | Implement provider profiles without claiming full precision |
| GP-14 | Aptos and Sui use distinct Move adapters preserving source maps, compiler/opcodes, resources/objects, abilities, generics, native calls, upgrades, and unresolved debt | source/regex graph only; no common typed provider | `DESIGN-ONLY` | Implement separate adapters; no shared false capability |
| GP-15 | Daml uses LF/DAR/package semantics or explicitly remains unsupported | current Daml graph is source/no-op quality | `LIVE-SCOPED`/unsupported | Keep `UNSUPPORTED` until a genuine provider exists |
| GP-16 | Cross-OS semantic output is normalized and comparable while runners remain OS-specific | existing path normalization and CI cover parts | `LIVE-PARTIAL` | Add portable payload vs environment-receipt hashes and Windows/Linux semantic parity fixtures |
| GP-17 | Provider conformance covers symbol identity, locations, build variants, call/read/write, generated code, dispatch, failure fallback, truthfulness, cache invalidation, and OS parity | scattered tests only; revised provider does not exist | `MISSING` as a unified suite | Create a provider conformance harness from the contract |
| GP-18 | Rollout is contract -> EVM emit-only -> measured additive EVM consumers -> Go -> Rust ecosystems -> Move; legacy behavior remains on failure | CPG research defines this | `DESIGN-ONLY` | Preserve this order and keep M1 unchanged initially |

## 6. `methodology/method-cards-v1.yaml` requirement crosswalk

| ID | Intended requirement | Current implementation/artifact | Status | Residual action |
|---|---|---|---|---|
| MC-01 | The initial universal kernel contains the twelve operators: authority/capability; value/accounting; state transitions; lifecycle/ordering; boundary/numerical; symmetry/reversibility; identity/domain; external assumptions; availability/resources; configuration/governance/upgrade; composition/shared state; concurrency/finality/replay | `prompts/shared/v2/breadth-semantic-operator-kernel.md` | `LIVE-SCOPED` to SC breadth | Move these identities and required semantics into the catalog; prompts render/reference them |
| MC-02 | Every card has stable `method_id`, title, semantic operator, and semantic version | verification registry has operator/module IDs but is not the universal catalog | `LIVE-SCOPED` | Define catalog keys and version/hash rules |
| MC-03 | Applicability selectors use entity/node kinds and required/optional capabilities | verification registry uses phase/pipeline/ecosystem/bug-class selectors | `LIVE-SCOPED` | Add graph/entity/capability selectors |
| MC-04 | Target and relation selectors identify effects, paired operations, reads/writes/calls, paths, boundaries, and other enumerables | scattered deterministic derivers and security-obligation rules | `LIVE-PARTIAL` | Make selectors declarative where reliable and allow referenced compiler functions where not |
| MC-05 | Required steps are explicit and stable | skill checklists and verification operators provide partial step sets | `LIVE-SCOPED` | Define steps once in YAML and bind exact methodology bytes |
| MC-06 | Required receipt fields include targets, steps, evidence, outcomes, and unresolved assumptions | methodology/verification receipts | `LIVE-PARTIAL` | Add per-card receipt requirements and common evidence protocol references |
| MC-07 | Completion policy defines valid N/A and routes material unresolved work to review | methodology application states and verification N/A predicates | `LIVE-SCOPED` | Require selector-consistent N/A and exact unresolved debt |
| MC-08 | Cards name required ecosystem/provider capabilities and accepted fidelity | absent as one catalog contract | `MISSING` | Add capability requirements referencing the graph-provider vocabulary |
| MC-09 | Prompt fragments are referenced by path/hash; the catalog does not duplicate prompt bodies | current skills/prompts exist and are digest-bound in selected paths | `LIVE-PARTIAL` | Store only references and hashes in YAML |
| MC-10 | Universal methods remain compact; crypto, serialization, runtime, ecosystem, and niche methods are conditional | skill selection authority and injectable skills | `LIVE-PARTIAL` | Encode selectors and consumer declarations in the catalog |
| MC-11 | Initial cards include at least boundary values, paired/symmetric operations, shared-state readers/writers, auth/capability entry points, local invariants, external interaction inventory, and lifecycle/initialization | current pipeline implements pieces across prompts/gates/skills | `LIVE-PARTIAL` | Create initial cards and exact positive/N/A/missing-target/missing-relation fixtures |
| MC-12 | A card describes how to analyze, never a protocol-specific expected bug | Part-0 policy and generic kernel mostly comply; a known protocol/finding-specific validator comment remains | `LIVE-PARTIAL` | Remove the recorded Part-0 defect and add catalog/registry lint |
| MC-13 | Method catalog version is source/snapshot/resume bound | methodology hashes exist on selected paths | `LIVE-SCOPED` | Bind the entire catalog digest in RunManifest/PhaseIO/WorkPlan |
| MC-14 | The catalog is the only normative method-content source | content is currently duplicated among kernel, skills, prompt bundles, and verification registry | `MISSING` | Assign ownership: YAML semantics; prompt/skill files are referenced rendering/execution material only |

The existing `verification_policy/verification_method_registry.v1.json` must not
be renamed and declared to be `method-cards-v1`. It is a useful Phase-5
operator profile, not the universal method catalog.

## 7. `architecture/finding-ledger-migration.md` requirement crosswalk

| ID | Original requirement | Supersession disposition | Current mechanism | Residual action |
|---|---|---|---|---|
| FL-01 | SQLite run database as the single physical store | `SUPERSEDED-PHYSICAL` | typed per-domain JSON authorities plus immutable artifacts | State an explicit prohibition in the revised RFC |
| FL-02 | SQL schema/migrations for identities, events, work leases, provider manifests, and report decisions | `SUPERSEDED-PHYSICAL`; semantic schemas/migrations survive | versioned JSON schemas and migration readers | Publish schema-version and migration rules per authority |
| FL-03 | Append-only FindingEvent API and deterministic current-state fold | semantic invariant retained | finding lifecycle generations; semantic mutation events; specialized ledgers | Standardize generation/previous-digest/replay conventions |
| FL-04 | Stable semantic ID migration; display-ID changes never break joins | retained | canonical finding map, queue IDs, lineage, content/premise digests | Finish all consumer/backend parity and collision handling |
| FL-05 | Dual-write existing candidate/inventory/depth/verifier/skeptic/report events into SQL and Markdown | database dual-write rejected; shadow/strangler parity retained | typed sidecars alongside legacy Markdown | Require one-way adapter/projection parity by subsystem, not a global DB dual-write |
| FL-06 | Database/Markdown lifecycle reconciliation | retained as authority/projection reconciliation | inventory reconciliation, lifecycle/report/assurance parity receipts | Add a canonical projection parity matrix |
| FL-07 | Report rendered from ledger and complete over eligible findings | retained | report disposition/mutation/mandatory reverification | Finish exact block bindings and final no-ship check |
| FL-08 | Explicit merge/split/exclude/downgrade events | retained | semantic dedup, finding lifecycle, severity/report decisions | Close remaining lexical/caller fallback paths |
| FL-09 | Retry/resume idempotency and concurrent writer safety | retained | PhaseIO, artifact ledger, report transaction, proposed WorkerTransaction | Finish commit-CAS and worker incorporation |
| FL-10 | Database backup/recovery and tested rollback | physical mechanism rejected; recovery invariant retained | immutable snapshots/artifacts, mutation journals, transaction recovery | Define a hash-bound recovery/export bundle and fault matrix |
| FL-11 | JSONL export/import round trip | JSONL is no longer prescribed | no complete portable RunBundle | Define canonical JSON bundle/export; JSONL may be an optional stream encoding |
| FL-12 | Feature flags `ledger_dual_write`, `ledger_authoritative`, and `report_from_ledger` | obsolete global cutover model | subsystem-specific live/shadow/legacy adapters | Use per-authority activation/cutover receipts and exact consumer matrices |
| FL-13 | Rollback to previous authoritative source and policy version | retained | legacy artifacts retained proposal-only; schema/policy digests in receipts | Document non-destructive rollback without retroactive authority |
| FL-14 | Remove legacy parsers only after equivalent/better frozen replay | retained | regex-fragility plan and typed migrations | Require exact recall/precision/recovery evidence per parser family |
| FL-15 | Old Markdown remains available and byte-compatible where required | retained as compatibility, not authority | current pipeline preserves named artifacts | Name which files are client/API compatibility surfaces and which may change |
| FL-16 | Foreign keys and unique constraints enforce referential integrity | semantic invariant retained, SQL mechanism rejected | closed schemas, exact digests, set equality, resolver validation | Add cross-artifact identity/referential conformance tests |

### 7.1 Physical assumptions that must not return

The following 2026-07-15 assumptions are obsolete:

1. A SQLite database must exist before Release 1 can make lifecycle safe.
2. One universal SQL event stream must precede domain-specific authority.
3. Work leases, finding state, provider manifests, and report inclusion must
   share one transaction store.
4. Global database/Markdown dual-write is the migration mechanism.
5. `ledger_authoritative` and `report_from_ledger` are global cutover switches.
6. JSONL is the required recovery authority.
7. Database backup/downgrade is the primary resume guarantee.
8. A report query over one database automatically closes producer, identity,
   premise, evidence, and worker-transaction gaps.

The following semantics from that design remain mandatory:

- stable identities and exact joins;
- immutable/append-only history;
- explicit decisions for every destructive transition;
- idempotency and checked concurrency;
- deterministic report projection;
- reconciliation against legacy projections;
- non-destructive migration and rollback;
- portable export/replay;
- no parser retirement without measured parity.

SQLite may still be used by an unrelated dependency such as ChromaDB or as an
implementation detail of a future cache. It must not become Plamen's semantic
authority without a new reviewed supersession and evidence that the current
typed authority boundaries are preserved.

## 8. `benchmarks/application-coverage-evaluation-plan.md` requirement crosswalk

| ID | Intended requirement | Current implementation/artifact | Status | Residual action |
|---|---|---|---|---|
| EV-01 | Four tracks: chronological real-report holdout, EVMbench, ecosystem-balanced non-EVM real/seeded suites, and precision/adversarial-safe cases | plan only; L1 docs include an older benchmark sketch | `MISSING`/`EXTERNAL-BLOCKED` | Specify governed corpora without placing GT in the audit workspace |
| EV-02 | Frozen source commits, build instructions, method cutoff, protocol-family exclusion, and report blinding | terminal audit preparation handles isolation/forbidden inputs for user canaries | `LIVE-SCOPED` | Add corpus authority and evaluator-side source/build manifests |
| EV-03 | Ground-truth schema includes root cause, entities/relations, operators, ecosystem knowledge, external facts, reasoning depth, tool needs, severity, consolidation, and likely failure points | B0 synthetic evaluator mechanics exist outside this tree; no generic schema in repo | `MISSING` | Define evaluator-owned GT schema; never expose it to workers |
| EV-04 | Difficult GT cases receive two independent annotations and reconciled adjudication | B1 prerequisites are pending | `EXTERNAL-BLOCKED` | Name annotator/adjudicator roles and independence receipts |
| EV-05 | Leakage controls hash the catalog before reports open, forbid GT retrieval, separate protocol families, track pretraining exposure, exclude method-source examples, log external queries, and separate retrieval/no-retrieval | post-audit protocol and terminal launcher cover parts | `LIVE-PARTIAL` | Reconcile the two policies in one evaluator contract |
| EV-06 | Recall metrics cover issue, root cause, material harm, severity band, final report, composition, and ecosystem | compare/post-audit prose supports some metrics | `LIVE-SCOPED` | Implement normalized metric computation in the evaluator |
| EV-07 | Application metrics cover obligations generated/scheduled, receipts, steps, targets, relations/paths, unresolved material work, and sampled false application | no real-run adapter | `MISSING` | Harvest typed scratchpad authorities into a GT-blind RunBundle |
| EV-08 | Pipeline survival metrics cover harvest, verify, skeptic, report index, final assembly, unsupported demotion, and reconciliation errors | individual receipts exist; no generic localizer | `MISSING` | Implement lifecycle localizer over exact IDs and aliases |
| EV-09 | Precision/quality metrics cover verified/report precision, false-safe, candidate burden, fragmentation, incorrect merges, unsupported severity, evidence completeness, and reviewer effort | B0 mechanics only | `MISSING` | Add adjudication and comparison renderer |
| EV-10 | Efficiency metrics cover tokens/time per obligation, tool cost, follow-ups, reuse, failures/retries, and provider builds | scattered runtime data | `MISSING` as an evaluator | Define RunBundle telemetry and missing-data semantics |
| EV-11 | Ablations isolate lifecycle, premise model, obligations, provider facts, and multi-hop scheduling | original A-E plan; new graph/attention research adds 2x2 arms | `DESIGN-ONLY` | Replace the old ledger yes/no factor with typed-authority activation profiles |
| EV-12 | CPG and adaptive attention are separate experimental factors under equal budgets | CPG/adaptive research defines G0A0/G1A0/G0A1/G1A1 | `DESIGN-ONLY` | Implement only after authority substrate is stable |
| EV-13 | Thresholds require zero silent seeded loss/omission/proof-without-evidence, non-increasing false-safe, improved non-application, no precision regression, resume stability, OS parity, and visible debt | acceptance ledger states the bar | `DESIGN-ONLY` | Bind numeric thresholds to a frozen baseline and independent evaluator |
| EV-14 | Recall reports confidence intervals and issue-level results; small samples are not reduced to one percentage | no implementation | `MISSING` | Specify statistical treatment and minimum denominators |
| EV-15 | Competitor comparisons require reproducible interfaces/raw outputs, identical source/budgets, report blocking, root-cause adjudication, pre-report and final scoring, version/date, and disclosure | no generic adapter | `MISSING` | Treat unavailable/proprietary systems as non-comparable, not zero |
| EV-16 | Miss localization asks method content -> compiler applicability -> target/relation -> schedule -> receipt -> intermediate claim -> judgment -> lifecycle loss | plan only | `MISSING` | Implement the eight-step localizer from RunBundle plus GT |
| EV-17 | Neutral evaluator B0 proves mechanics only; B1 requires governed corpus, authorities, denial probes, secure launcher, and comparator | goal ledger | B0 `PROVEN` for synthetic mechanics; B1 `EXTERNAL-BLOCKED` | Preserve the distinction in the canonical plan |
| EV-18 | Real-run harvesting is GT-blind; GT joins happen only after run lock | plan audit identifies missing scratchpad-to-RunBundle adapter | `MISSING` | Implement harvester, localizer, and blinded renderer |
| EV-19 | <PRIVATE_AUDIT_TARGET>/<PRIVATE_REGRESSION_TARGET> are user-run post-handoff acceptance, never implementation tuning or Codex-run canaries | goal ledger and terminal launcher docs | `LIVE-SCOPED` preparation; execution `USER_RUN` | Keep both outside benchmark development and worker inputs |

### 8.1 Evaluation-policy conflict and resolution

The 2026-07-15 plan says to create frozen corpora and ground-truth artifacts.
`rules/post-audit-improvement-protocol.md` says no benchmark directory, no
persistent ground truth, and only approved methodology changes plus aggregate
metrics may survive.

Both goals are valid when authority is separated:

- The implementation repository stores only benchmark schemas, corpus IDs and
  digests, source/build manifests, launch contracts, and aggregate receipts.
- The governed evaluator stores reports/ground truth outside the audit
  workspace and outside worker-readable paths.
- The audit-side harvester produces a GT-blind RunBundle.
- The evaluator joins GT only after the run is locked.
- Development comparisons may remain ephemeral; decisive release evidence must
  have an independently governed, hash-bound receipt.
- <PRIVATE_AUDIT_TARGET> and <PRIVATE_REGRESSION_TARGET> remain user-run post-handoff acceptance and may not become
  tuning corpora.

This resolves anti-overfit policy without making reproducible evaluation
impossible.

## 9. `architecture/work-unit-scheduler.md` requirement crosswalk

| ID | Intended requirement | Current implementation/artifact | Status | Residual action |
|---|---|---|---|---|
| WS-01 | Schedule a small semantic stage graph: acquire/model, enumerate, discover, expand, verify/challenge, reconcile, render | deterministic phase list remains operational batching | `LIVE-PARTIAL` | Document semantic stages as labels over existing phases, not a big-bang phase rewrite |
| WS-02 | A work unit binds run/snapshot, stage, method/version, targets/relations, exact inputs/hashes, capabilities/fidelity, worker/tool policy, output schema, priority, retry/budget, parent reason, and exclusive namespace | queue items, verifier roster, PhaseIO LaunchSpec each cover parts | `LIVE-SCOPED` | Define a common WorkPlan envelope and domain adapters |
| WS-03 | Freeze a phase roster before launch; adaptive additions use explicit amendments and stable IDs | verifier roster exists; generic PhaseWorkRoster is design-only | `LIVE-SCOPED` | Implement `PhaseWorkRoster` and `RosterAmendment` generically |
| WS-04 | A status marker without a schema-valid receipt is not semantic completion | current architecture docs still describe disk marker completion; PhaseIO/WER designs reject it | conflict; `LIVE-PARTIAL` | Demote markers to transport/legacy evidence in docs and code |
| WS-05 | Work is leased/armed before child creation and idempotent by semantic inputs | verifier plans and WER arms exist in selected paths | `LIVE-SCOPED` | Implement attempt-specific generic WorkerTransaction |
| WS-06 | Retry reuses exact valid completions and schedules only missing rows; backend/model/policy changes create a new generation | verifier roster/queue supports scoped behavior | `LIVE-SCOPED` | Extend to all model/native/repair/provider launches |
| WS-07 | Budget policy covers items, bytes, files, prompt/context, tokens, wall clock, tools/processes, output, concurrency, and overflow debt | many local caps; gate registry is empty | `LIVE-PARTIAL` | Define common budget schema and populate mechanical-gate registry |
| WS-08 | Priority uses materiality, uncertainty, unresolved obligations, and distinct evidence value rather than raw finding count | adaptive-channel research | `DESIGN-ONLY` | Implement after exact denominator authorities exist |
| WS-09 | Adaptive count derives from uncovered obligations/axes/components/relations/provider debt/challenges/chain pairs/verifier items | current counts are fixed or Markdown-derived | `MISSING` | Implement versioned evidence-channel plan with total-agent and concurrency caps |
| WS-10 | Distinct channel identity binds obligation set, evidence slice, role, source, methodology, graph treatment, and runtime policy | adaptive research | `DESIGN-ONLY` | Add stable channel IDs and diversity checks |
| WS-11 | Central joins remain sequential for inventory, dedup, disposition, severity, and report authority; parallelism is for decomposable evidence work | CPG/adaptive research | `DESIGN-ONLY` policy, partially current | Encode phase policy in scheduler without duplicating phase methodology |
| WS-12 | Follow-up triggers are exact and bounded; chain generations remain sequential | chain-tail/late/reverify authorities implement pieces | `LIVE-PARTIAL` | Centralize trigger/denominator semantics |
| WS-13 | Budget exhaustion, failure, unsupported capability, or human-review fallback retains exact pending identities as debt | local queues/assurance exist | `LIVE-PARTIAL` | Require denominator = incorporated completions + explicit debt |
| WS-14 | Worker process scope is owned from arm through complete descendant termination and zero-population proof | WER supports selected headless paths but generalized `OwnedProcessScope` does not exist | `LIVE-SCOPED`; PTY `DESIGN-ONLY` | Implement Windows Job and Linux cgroup providers; unsupported OS is proposal/debt |
| WS-15 | A worker receives an attempt-specific read-only view and one staged output assignment; it never receives a canonical output path | current workers write shared canonical scratchpad; design requires staging | `DESIGN-ONLY` | Implement staging, write confinement, and CAS |
| WS-16 | Provisional PTY `end_turn`/output-ready is followed by full process-scope closure before parsing or authority | current PTY can finalize before cleanup | `DESIGN-ONLY` | Reduce PTY session to codec and migrate through trusted provider |
| WS-17 | PhaseIO is the only canonical publisher; model/native output requires execution and incorporation receipts | PhaseIO exists, but generic incorporation chain does not | `LIVE-PARTIAL` | Add durable projection arm, CAS incorporation, and execution-authority requirement |
| WS-18 | Multi-output projection rolls forward after crash; best-effort rollback is insufficient | report transaction has scoped recovery; worker bundle projection design only | `LIVE-SCOPED`/`DESIGN-ONLY` | Implement generic durable per-member progress |
| WS-19 | Cancellation/rate-limit/timeout terminates and joins every started attempt; queued rows get explicit terminal states; no late writes | current pools/PTY do not prove this | `DESIGN-ONLY` | Replace `_NonBlockingWorkerPool` and raw launchers |
| WS-20 | Parent clean commit requires every required plan incorporated, all attempts terminal, no active process scope, linked native children, and explicit optional/adaptive dispositions | verifier roster covers a subset | `LIVE-SCOPED` | Add generic roster reconciliation to phase commit/resume |
| WS-21 | Resume recovers armed attempts, reuses safe completed CAS, rolls forward projections, and never adopts legacy bytes retroactively | PhaseIO/recovery patterns exist; generic worker recovery absent | `LIVE-PARTIAL` | Implement `recover_worker_transactions` and exact invalidation |
| WS-22 | Claude PTY, Claude headless, Codex exec, and native commands have identical logical denominators; adapters differ only in transport | current paths differ materially | `IN_PROGRESS` | Migrate shared headless first, PTY next, generic/native paths after |
| WS-23 | Mechanical/native tools use the same owned process and mutation contracts | raw launches remain in recon, PoC, snapshot, supply-chain and support tools | `IN_PROGRESS` | Migrate in the P0-AM staged order; blocking raw-launch lint is the final ratchet |
| WS-24 | Ground-truth identity/path never reaches a work unit | terminal launcher preparation and evaluator design | `LIVE-SCOPED` | Bind forbidden-input proofs into scheduler/evaluation receipts |

The present `queue_work_items.py` and `verifier_work_roster.py` are valuable,
production-reachable verifier substrates. They are not the generic scheduler.
`worker_execution_receipts.py` is production-used by skeptic and severity
workers, but its current publication/process model is not the P0-AM target.

## 10. `architecture/premise-and-disposition-policy.md` requirement crosswalk

| ID | Intended requirement | Current implementation/artifact | Status | Residual action |
|---|---|---|---|---|
| PD-01 | Premises have stable IDs and exact subject/content binding | severity, candidate-negative, and broker records have scoped premise IDs | `LIVE-PARTIAL` | Require content and canonical premise set together in every consumer |
| PD-02 | Polarity is direction-aware: true/false may increase or reduce harm | severity premise kinds and direction-neutral rules implement part | `LIVE-SCOPED` | Add normative polarity/counterfactual fields |
| PD-03 | Source classes distinguish repository facts, executed evidence, cited external facts, assumed facts, unresolved facts, model hypotheses, and provider facts | evidence-capability and local policy vocabularies | `LIVE-PARTIAL` | Publish one conversion table without flattening proof scope |
| PD-04 | Research status and citations are explicit; external claims cannot disappear behind prose | R10 research ledgers/citation gates and precedent policy | `LIVE-PARTIAL` | Move authority from regex/prose cues to typed premise records |
| PD-05 | Both unsupported adverse premises and unsupported favorable/safety premises are challenged | typed severity is direction-neutral; application/candidate skeptics target negatives | `LIVE-PARTIAL` | Close the general challenge denominator and all severities |
| PD-06 | Mechanism and harm are separate; supported mechanism with unresolved harm is not `safe` | evidence capabilities, severity ledger, negative policy | `LIVE-PARTIAL` | Make the separation common to finding/report lifecycle |
| PD-07 | Disposition binds exact decision, claims, premises, evidence, proof scope, counterfactual, reviewer, and policy result | specialized decision ledgers | `LIVE-PARTIAL` | Define the shared decision minimum in the RFC |
| PD-08 | Impact and Likelihood remain separate, with mechanism/premise/evidence/severity confidence | severity decision ledger/runtime | `LIVE-PARTIAL` | Finish live/adjudication/report projection evidence |
| PD-09 | Independent severity challenge triggers on low rating after supported mechanism, downward change, decisive favorable premise, cluster inconsistency, composition, prose/rating mismatch, or stage disagreement | severity shadow/adjudication implements much of this | `LIVE-PARTIAL` | Complete same-reviewer/worker authority, all consumers, and canaries |
| PD-10 | R10 remains active until typed policy has exact replay parity and precision evidence | live R10 demotion floor; typed severity expresses favorable-premise rule | `LIVE-PARTIAL` | Dual-evaluate and retire only after frozen parity |
| PD-11 | R10 is a floor against unsupported demotion, not a severity recovery system; it must not inflate beyond evidence | plan audit and severity ledger | `LIVE-PARTIAL` | Remove stale prose implying broader authority |
| PD-12 | Terminal negatives are limited to applied lossless equivalence, decidable mechanical scope, complete finite domain plus oracle, or checked proof | terminal-negative implementation design | `DESIGN-ONLY` except applied equivalence | Implement code-owned registry/providers one domain at a time |
| PD-13 | Model judgments, bounded tests/fuzzing, failed PoCs, no witness, confidence, precedent, trust, L1 model facts, and compound analyst conclusions are proposal-only | negative-closure policy and current broker default retain/reopen | `LIVE-PARTIAL` | Remove capability declarations/fallbacks that imply terminal authority |
| PD-14 | Terminal decision requires registry support, exact content and premise set, pinned implementation, broker-derived completeness, decisive oracle, independent review, committed transaction, and replay | terminal-negative design | `DESIGN-ONLY` | Implement v2 artifacts and negative-authority phase |
| PD-15 | `OUT_OF_SCOPE`, `REFUTED_FULL`, `ZERO_HARM`, and `ALIAS` have distinct exact predicates; all other effects are unsupported | terminal-negative design; applied alias path live | `LIVE-SCOPED`/`DESIGN-ONLY` | Implement only structured scope first; do not add a generic model provider |
| PD-16 | Completeness is exact expected/observed set equality with no missing/duplicate/unexpected/unknown/error/conflict and all relevant dimensions represented | terminal-negative design | `DESIGN-ONLY` | Replace provider-declared `exhaustive=true` |
| PD-17 | Reviewer evidence is broker recomputation or a second observed independent execution; WER assessor labels are not evidence | terminal-negative and P0-AM designs | `DESIGN-ONLY` | Change current validation before provider cutover |
| PD-18 | Central broker is the sole production replay boundary; consumers do not accept direct callbacks/bundles | `closure_broker_v2.py` and negative-closure policy | `LIVE-PARTIAL` | Migrate to v2 exact bindings and localized debt |
| PD-19 | Every consumer supplies exact content and premise identities; missing legacy binding retains/body/reverifies | current consumers split content vs premise bindings and broker falls back | `IN_PROGRESS` | Add canonical subject-binding sidecar and remove fallback |
| PD-20 | Severity is not automatically lowered by terminal negative authority; lifecycle/disposition and positive severity evidence remain separate | terminal design | `DESIGN-ONLY` policy; current behavior partial | Enforce in consumer adapters |
| PD-21 | Compound and L1 negative conclusions bind exact constituents, content, premises, verifier execution, claim formula, report block, and central decisions | compound/L1 substrates are partial/test-only for terminal use | `IN_PROGRESS` | Wire live compound evaluation/report binding and L1 final adapter |
| PD-22 | Unknown, malformed, stale, partial, timed-out, conflicting, unsupported, or unreviewed results retain/reopen/body/reverify/human-review and never become clean | negative policy and design | `LIVE-PARTIAL` | Implement phase transaction, scoped debt, resume, packaging and canaries |

### 10.1 R10 and assert-side conflict

The current tree contains both:

- a recall-safe R10 demotion-side floor/veto for an uncited favorable external
  premise; and
- an assert-side external-assumption cap that can destructively cap severity.

The typed target is direction-neutral premise/evidence adjudication. The
demotion-side floor stays until replay parity is proven. The assert-side cap
must not be copied into the canonical premise policy as a general rule; it
should be migrated into typed severity evidence/adjudication and retired only
after recall and precision parity.

## 11. Cross-document conflicts that require explicit resolution

| Conflict | Evidence | Required resolution |
|---|---|---|
| SQLite-first vs no-big-bang/typed strangler | 2026-07-15 Sections 10.5/10.6/18/19 versus its own Section 21 and the 2026-07-24 plan audit | Mark the physical SQLite plan superseded; retain semantic invariants |
| Disk marker as completion authority vs PhaseIO/WER | `docs/architecture.md` says disk markers are the only completion authority; P0-AM requires observed process closure, CAS, incorporation, and PhaseIO | Rewrite docs: marker is transport/legacy gate only, never semantic/execution authority |
| Inventory Markdown as single source of truth vs typed authorities | `docs/pipeline-phases-presentation.md` calls `findings_inventory.md` master truth | Treat inventory as compatibility projection/input; typed identities/decisions/reconciliations are authoritative by domain |
| All mechanical derivers are append-only/idempotent vs forensic evidence | `docs/architecture.md` makes a blanket claim; gate forensic finds destructive/unguarded paths and PhaseIO gaps | Replace blanket claim with per-gate registry direction, failure, budget, and receipt |
| Axis is safe additive vs false-clean/pre-commit mutation | current docs/phase and `axis_disposition.py` substrate versus P0-I design | Do not wire v1; implement worklist v2, typed dispositions, repair, promotion, debt, and ordering |
| Application skeptic runs before axis CLEARs exist | current `SC_PHASES` order | Move axis before application skeptic only as part of the P0-I typed cutover |
| Graph as ground truth vs proposal-only program facts | original graph plan/PR #21 language versus CPG research | Facts are structural evidence with capability scope; never negative authority |
| CPG and agent-count increase conflated | PR #21/new program request | Keep program facts and adaptive attention as separate factors and cutovers |
| Verification registry presented as universal method catalog | current registry/compiler is Phase-5 oriented | Keep it as a profile generated from/referencing the universal MethodCard catalog |
| Persistent benchmark reproducibility vs anti-overfit no-GT persistence | canonical evaluation plan versus post-audit protocol | Govern GT outside repo/workspace; store digests/contracts/receipts only |
| Central negative broker exists vs providers operational | current negative-closure doc can be misread as availability | State that applied alias is live; mechanical/exhaustive launch and registration are absent |
| Broker v1 validation vs terminal-provider v2 requirements | current provider-declared exhaustiveness/assessor labels/fallback binding | Freeze provider cutover; implement v2 exact registry, review, transaction and binding |
| Generic scheduler implied by verifier queue/roster | current typed queue is strong but scoped | Do not call it the general scheduler until P0-AM/PhaseWorkRoster is live |
| Gate registry policy vs empty runtime registry | registry file has zero gates/budgets and no production loader | Baseline, independently review, shadow receipts, PhaseIO bind, then activate ratchet/budgets |
| Current line-number-heavy docs vs moving dirty tree | architecture/internals contain stale line references and behavior claims | Normative docs identify modules/symbols/schema IDs; generated inventories carry non-authoritative line evidence |

## 12. Residual actionable implementation items by canonical artifact

### 12.1 Method application and shared authority

1. Finish PhaseIO output-prestate/commit-CAS/shared caller migration and
   independently review it.
2. Publish shared identity, obligation, evidence, claim, premise, decision,
   lifecycle, and report-projection envelopes plus adapters.
3. Make `method-cards-v1.yaml` the versioned catalog authority.
4. Extend application compilation/receipts from selected skills and Phase 5 to
   every declared catalog consumer.
5. Complete production P0-I axis planning, typed model disposition, repair,
   reconciliation, promotion, negative challenge, resume, and assurance.
6. Complete exact finding/report/alias/premise consumer parity.

### 12.2 Program facts

1. Define `plamen.program_facts.v1`, receipt, debt, provider registry, portable
   payload hash, and environment receipt hash.
2. Add `recon/program_facts_bake` as a deterministic PhaseIO unit.
3. Implement EVM emit-only with pinned Slither/compiler APIs and no consumer
   behavior change.
4. Add one measured additive consumer per release.
5. Implement Go, Rust ecosystems, and separate Move adapters only after the
   contract and conformance suite are stable.

### 12.3 Scheduler and worker transactions

1. Implement `PhaseWorkRoster`, generic `WorkPlan`, attempt arm, CAS,
   completion/debt, incorporation, and recovery.
2. Consolidate OS process authority and require complete Windows Job/Linux
   cgroup cleanup before completion.
3. Migrate shared headless providers, then PTY, then generic/native launchers.
4. Enforce no canonical output paths for workers and no phase commit with
   active attempts.
5. Replace fixed/homogeneous expansion with an exact-denominator adaptive
   evidence-channel experiment; do not cut over without neutral gains.

### 12.4 Premise and terminal disposition

1. Add a canonical subject binding carrying both candidate-content digest and
   exact premise-set digest to every consumer.
2. Add the explicit `negative_authority` phase in SC and L1 between severity
   adjudication and report index.
3. Implement v2 challenge ledger, registry, work plan, subject/domain/oracle
   manifests, raw result, reviewer receipt, provider bundle, transaction
   journal, and central decision.
4. Cut over only applied equivalence and exact structured scope first.
5. Wire compound evidence/report binding and L1 post-verification adapter.
6. Preserve R10 until typed replay parity and precision evidence.

### 12.5 Evaluation

1. Define the governed corpus and GT schemas plus B1 authorities.
2. Implement a GT-blind scratchpad-to-RunBundle harvester.
3. Implement the eight-step lifecycle miss localizer.
4. Implement blinded comparison and issue-level/confidence-interval rendering.
5. Run the separate program-facts/adaptive-attention 2x2 experiment under
   equal budgets.
6. Keep <PRIVATE_AUDIT_TARGET>/<PRIVATE_REGRESSION_TARGET> user-run and excluded from tuning.

### 12.6 Mechanical gate governance

1. Approve registry scope and decision classes.
2. Generate and independently reconcile the active baseline.
3. Populate existing gates as `LEGACY_ACTIVE_UNGOVERNED`.
4. Add shadow execution receipts and PhaseIO binding.
5. Enable activation-parity lint and then runtime/overflow/false-fire budgets.
6. Remove the known Part-0-specific implementation commentary.

## 13. Minimum canonical document set and ownership rules

### 13.1 Normative artifacts

| Canonical file | Sole normative ownership | Must reference, not duplicate |
|---|---|---|
| `architecture/method-application-rfc.md` | Shared record envelopes; authority precedence; identity; lifecycle; application semantics; premise/disposition policy; report projection; typed-sidecar migration/rollback; error/concurrency semantics | Method content, provider fact definitions, scheduler backend details, benchmark corpora |
| `architecture/ecosystem-graph-provider-contract.md` | Program-fact/entity schemas; provider manifests; capabilities/fidelity; provenance/freshness; additive consumer authority; ecosystem profiles; conformance | Vulnerability methods, scheduler counts, terminal-negative policy |
| `methodology/method-cards-v1.yaml` | Method/operator IDs, selectors, required steps/receipts, valid N/A, prompt references, capability requirements, versions | Prompt bodies, backend launch mechanics, benchmark findings |
| `architecture/work-unit-scheduler.md` | Phase roster, WorkPlan, attempts, WorkerTransaction, budgets, adaptive channels, joins, cancellation/retry/resume, PhaseIO incorporation | Method instructions, provider fact semantics, GT |
| `benchmarks/application-coverage-evaluation-plan.md` | Corpus/GT governance, leakage, RunBundle, metrics, ablations, thresholds, adjudication, competitor protocol | Method content and implementation-specific pipeline prose |

### 13.2 Non-normative compatibility notices

- `architecture/finding-ledger-migration.md`: a short supersession notice
  pointing to `method-application-rfc.md` sections "Typed authority storage and
  migration" and "Rollback/parser retirement". It must explicitly say that the
  SQLite/dual-write plan is retired.
- `architecture/premise-and-disposition-policy.md`: a short supersession notice
  pointing to `method-application-rfc.md` sections "Premises", "Disposition
  policy", "Terminal negatives", and "R10 migration".

### 13.3 Implementation profiles, not additional architecture sources

Promote the five 2026-07-24 design/research documents into the repository under
`docs/design/` as implementation profiles:

- `program-facts-and-adaptive-attention.md`
- `axis-disposition-integration.md`
- `worker-transaction.md`
- `terminal-negative-providers.md`
- `mechanical-gate-registry.md`

Each profile should declare:

- the canonical sections it implements;
- status (`DESIGN`, `SHADOW`, `LIVE`, `SUNSET`);
- affected schema/module/work-unit IDs;
- unresolved acceptance rows;
- source-tree digest reviewed;
- superseded implementation details.

Profiles may specialize exact file layouts, stages, fixtures, and migration
order. They must not restate the twelve methods, premise policy, graph
authority rules, or scheduler lifecycle.

## 14. Exact documentation update plan

This is a documentation plan only. Implementation work remains gated by the
acceptance ledger and closure order.

1. Freeze and record a source-tree digest, because HEAD alone does not identify
   the current dirty worktree.
2. Add `architecture/method-application-rfc.md` version `1.0-draft` with:
   - an explicit supersession statement over the 2026-07-15 SQLite design;
   - the shared envelopes and authority precedence from Sections 3, 4, 7, and
     10 of this crosswalk;
   - one old-to-new invariant table;
   - per-domain adapter references;
   - typed-sidecar migration, rollback, export, and parser-retirement rules;
   - no copied methodology text.
3. Add `architecture/ecosystem-graph-provider-contract.md` version
   `1.0-draft` from Section 5 and the CPG research:
   - dedicated program-facts sidecar;
   - provider/run/build receipt;
   - portable fact vs environment receipt hashes;
   - additive-only consumer matrix;
   - ecosystem profiles and conformance suite;
   - explicit `no graph-derived terminal negative`.
4. Add `methodology/method-cards-v1.yaml`:
   - encode the twelve stable operator identities;
   - add the seven initial reliable cards;
   - reference existing prompt/skill/verification fragments by path and hash;
   - define exact selectors, steps, receipts, N/A, capability/fidelity, and
     versioning;
   - add no protocol/finding examples.
5. Add `architecture/work-unit-scheduler.md` from Section 9 plus the P0-AM and
   adaptive-channel designs:
   - semantic stage labels over existing phases;
   - PhaseWorkRoster/WorkPlan/attempt schemas;
   - process/write authority and CAS incorporation;
   - retry/resume/cancellation/late-write rules;
   - exact-denominator adaptive expansion;
   - backend/OS adapters by reference.
6. Add `benchmarks/application-coverage-evaluation-plan.md` from Section 8:
   - governed external GT;
   - GT-blind RunBundle;
   - lifecycle localizer;
   - metrics/thresholds/adjudication;
   - old A-E ablation translated to typed authority profiles;
   - separate 2x2 program-facts/attention experiment;
   - <PRIVATE_AUDIT_TARGET>/<PRIVATE_REGRESSION_TARGET> user-run boundary.
7. Add the two compatibility notices at the retired Section 19 paths. Each
   should be under one page and contain links only, not duplicated contracts.
8. Move the five 2026-07-24 design/research inputs into `docs/design/` with
   implementation-profile headers and canonical cross-references.
9. Update `docs/architecture.md`, `docs/internals.md`, and
   `docs/pipeline-phases-presentation.md` to remove:
   - disk-marker-only semantic completion;
   - inventory Markdown as the universal source of truth;
   - blanket append-only/idempotent claims for every gate;
   - stale Gate-P and verdict-flip behavior;
   - v1 axis safety claims;
   - line numbers as durable identities.
10. Update `docs/design/negative-closure-authority.md` to mark current v1
    registration/replay as migration substrate and link the v2 terminal
    provider profile.
11. Add a documentation ownership/duplication lint:
    - twelve operator definitions occur only in the MethodCard catalog;
    - premise/terminal policy occurs only in the shared RFC;
    - provider capabilities occur only in the graph contract;
    - worker lifecycle occurs only in the scheduler contract;
    - retired paths contain only approved redirects;
    - normative links resolve in a clean package/archive install.
12. Obtain independent architecture review of this supersession mapping before
    any canonical document is marked `ACCEPTED`.

## 15. Acceptance conditions for the supersession itself

The architecture supersession is reviewed and complete only when:

1. Every requirement ID in Sections 4 through 10 is represented by one
   canonical section, one explicit implementation profile, or one accepted
   residual item.
2. No requirement is marked complete merely because its original SQLite
   mechanism was rejected.
3. No canonical document claims the current dirty tree is proven.
4. No method content is duplicated outside `method-cards-v1.yaml`.
5. No graph/provider fact can authorize a negative, demotion, or clean
   application receipt.
6. No worker output can become semantic authority from a disk marker, file
   presence, or caller assertion.
7. No terminal negative can come from a model, bounded search, failed test,
   confidence, precedent, trust tag, or provider self-declaration.
8. No legacy parser/gate is retired without exact replay, recall, precision,
   fault, and resume evidence.
9. The benchmark plan keeps GT outside worker-readable scope and preserves the
   user-run boundary.
10. The five canonical sources and two redirects pass clean-checkout,
    packaging, link, ownership, and duplication checks.

## 16. Final verdict

The absence of the seven named Section 19 files is a real architecture gap, but
the correct repair is not to reconstruct the 2026-07-15 database plan.

The no-scope-loss resolution is:

- five normative canonical artifacts;
- two redirect-only compatibility paths;
- five implementation profiles for the current 2026-07-24 designs;
- explicit retirement of the big-bang SQLite/event-ledger/dual-write model;
- preservation of every identity, lifecycle, evidence, premise,
  disposition, report, scheduling, provider, evaluation, rollback, and
  no-silent-loss invariant;
- implementation status kept honest as partial, scoped, design-only, missing,
  or external-blocked until the acceptance ledger is actually satisfied.

This crosswalk closes the documentation disposition question. It does not
close P0-I, P0-AM, terminal-negative providers, mechanical-gate governance,
program facts, adaptive attention, real-run evaluation, PhaseIO integration,
or final validation.
