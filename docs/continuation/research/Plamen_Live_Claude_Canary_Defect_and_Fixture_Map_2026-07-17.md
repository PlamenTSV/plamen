# Plamen Live Claude Canary: Defect and Fixture Map

Date: 2026-07-17  
Status: working acceptance artifact; not a completion claim  
Run: `evm-siloconfig-thorough-007-claude-frozen`  
Backend: Claude legacy path (`cli_backend=claude`, PTY)  
Use: architecture canary and regression evidence only; never benchmark recall evidence

## 1. Acceptance boundary

The canary is frozen against implementation HEAD `67a0f85adc7a8169d79a286908b00bef7adb764a` plus the pre-run dirty tree. No implementation file may change until the run and its clean-resume check are captured. The run is intentionally unscored: it can reproduce structural failures, but it cannot establish comparative recall.

Every change below must satisfy all of these conditions:

1. A red fixture reproduces the observed structural failure before the fix.
2. The fix is generic and Part-0 clean: no protocol names or expected finding answers.
3. The fixture turns green without deleting an obligation, candidate, source identity, or negative disposition.
4. Focused tests and the full fast-lane suite pass.
5. A fresh Claude legacy-backend run exercises the changed path.
6. Resume is idempotent: no LLM relaunch and no artifact mutation when the accepted checkpoint is unchanged.
7. Precision is measured as well as recall: unsupported clears are retained, but mechanically valid in-scope clears are not reinflated.

## 2. Priority-0: methodology delivery and negative-disposition correctness

### P0-0. Exploration-skeptic findings bypass the normal promotion path

Code evidence: `exploration_skeptic` runs before `sc_semantic_dedup` and is explicitly authorized to emit NEW, UPGRADE, and RE-OPEN results. Immediately before semantic dedup, the driver calls `_promote_depth_findings_to_inventory()`. Its `_DEPTH_PROMOTION_FILES` list does not include `exploration_skeptic_findings.md`, and the report-time promotion gate's `_PROMO_FEEDER_GLOBS` does not include it either. By contrast, the two following recall-positive phases (`enumgap_exploration` and `axis_coverage`) have explicit promotion hooks. Therefore an exploration-skeptic finding can exist on disk yet bypass inventory, semantic dedup, chain analysis, normal verification, and even the bounded report-time orphan harvest.

Live reproduction: the frozen Claude canary emitted 22 standard `SKEP-*` finding blocks (19 NEW plus one RE-OPEN and two UPGRADE-class actions described by its summary). Immediately after phase acceptance, none of those IDs existed as inventory findings. Three IDs occurred only as incidental text inside mechanically committed-invariant source descriptions; that is not promotion. This proves the loss path on the actual legacy Claude backend, not only by static inspection.

This is a direct found-then-lost defect and becomes the first edit after the frozen run.

Fix contract:

- Give exploration actions a typed identity contract: NEW / UPGRADE / RE-OPEN, source action ID, target ID when applicable, location(s), severity claim, evidence scope, and source artifact hash.
- Promote every well-formed NEW action into the inventory before semantic dedup while preserving its source identity.
- Route UPGRADE and RE-OPEN as explicit amendment candidates tied to the target identity; never overwrite or silently mutate the original finding.
- Malformed but content-bearing actions degrade to a retained low-confidence verification/human-review obligation, not zero parsed rows.
- Reconcile headings/actions parsed versus emitted and write a durable receipt. Any nonzero source actions with zero promoted/amended rows is loud and degraded.
- Include the artifact in the report-time completeness harvest as defense in depth, but do not rely on that late path as the primary route.

Required fixtures:

- one NEW action reaches inventory, dedup, chain input, and verify queue;
- one UPGRADE retains the original plus a target-bound amendment and cannot be severity-downgraded by the bridge;
- one RE-OPEN targets a prior negative disposition and reaches verification;
- mixed actions with coverage-table rows do not parse coverage rows as findings;
- arbitrary/legacy finding heading with substantive content is retained rather than silently skipped;
- duplicate action on resume is idempotent;
- zero-action no-findings artifact is a clean no-op;
- parser drift (source heading count > 0, emitted count = 0) produces a degraded receipt and report-visible completeness debt;
- report-time promotion gate independently sees any deliberately unpromoted substantive block.

### P0-1. Foundry invariant-fuzz violations also bypass promotion

Code evidence: the EVM invariant-fuzz methodology requires every executed violation to be emitted as a standard `[FUZZ-N]` finding in `invariant_fuzz_results.md`. `_PROMOTABLE_FEEDER_ID_PATTERN` recognizes `FUZZ-N`, but `_DEPTH_PROMOTION_FILES` does not include `invariant_fuzz_results.md`; only the Medusa, Trident, and cargo-fuzz output files are listed. The canonical-ID scanner sees the Foundry artifact, which can create misleading identity telemetry without actually delivering its findings into inventory. The report-time promotion feeder globs also omit this filename.

Fix contract:

- Add the Foundry invariant output to the same pre-dedup promotion/reconciliation path as other fuzz producers.
- Preserve related-finding linkage and the new proof-scope fields; an executed mechanism probe must not be inflated into harm proof.
- Reconcile violation headings/table entries against promoted rows and make any mismatch loud.
- Replace manually duplicated feeder filename lists with one typed producer registry or derive them from registered phase/job output contracts. Canonical identity, promotion, inventory floor, report harvest, and containment must consume the same registry projection so a new producer cannot be registered in one layer and omitted from another.

Required fixtures:

- Foundry `[FUZZ-1]` violation reaches inventory and verify;
- no-violation campaign is a clean no-op;
- mechanism-only violation retains low-confidence harm status while still being promoted;
- Medusa/Trident/cargo existing routes remain unchanged;
- a synthetic newly registered finding producer fails a registry-completeness test until every required consumer projection includes it;
- canonical-ID presence without promotion receipt is a failing reconciliation condition, not evidence of delivery.

### P0-2. Driver-recovered depth self-exclusions are promised downstream delivery but are not promotable

Code evidence: `_reemit_depth_self_exclusions()` writes standard `### Finding [DXRE-N]` blocks to `depth_selfexcl_reemit_findings.md` and its docstring explicitly says the normal inventory/chain/verify consumers will ingest the file because it matches `depth_*_findings.md`. The live promotion bridge is not a generic `depth_*_findings.md` scan: `_DEPTH_PROMOTION_FILES` is a manually enumerated tuple that omits this filename, and `_PROMOTABLE_FEEDER_ID_PATTERN` recognizes `DX-N` but not `DXRE-N`. The report-time Gate-P glob can see the file, but its content-shape floor deliberately rejects the content-less appendix-only cases that this producer explicitly promises to retain. Canonical identity can therefore observe `DXRE-*` while normal delivery does not.

Live reproduction: the frozen Claude canary emitted five `DXRE-*` blocks. None is covered by the pre-dedup promotion tuple or prefix grammar. This is a direct contradiction between the recovery producer's contract and its consumers, and another instance of the same manual-registry architecture defect as SKEP/FUZZ loss.

Fix contract:

- Register the self-exclusion re-emitter as a typed post-inventory producer and register `DXRE-N` as its local-ID grammar.
- Content-bearing rows take the normal inventory -> dedup -> chain -> verify path at their retained provisional severity.
- Content-less rows remain methodology/human-review debt with exact source identity; they must not be fabricated into vulnerability findings, but they also must not vanish merely because Gate P's harm-shape predicate correctly declines them.
- The producer receipt reconciles every recovered source row to exactly one content-bearing candidate or content-less review disposition.
- The same typed producer registry supplies canonical identity, pre-dedup delivery, late orphan defense, report human-review projection, containment, and resume hashing.

Required fixtures: one content-bearing `DXRE-1` reaches verification; one content-less `DXRE-1` reaches the report-visible methodology-debt appendix but not the client vulnerability body; mixed rows reconcile exactly; malformed heading creates loud residual debt; resume is idempotent; sibling, invariant-fuzz, exploration, and existing depth producers remain registry-complete.

### P0-A. Selected skills do not reach every declared consumer

Live evidence: `ORACLE_ANALYSIS` and `LENDING_PROTOCOL_SECURITY` were selected and reached breadth, but their declared depth consumers did not receive the skill. Current `_parse_sc_skill_bindings()` trusts only explicit `spawn_manifest.md` assignment rows; the existing required-skill validator proves only that a skill appears somewhere, not that it reaches all declared scheduled consumers.

Fix contract:

- Build a typed `skill_consumer_coverage.json` before worker launch.
- Parse selected Required skills structurally.
- Resolve each skill only within the active ecosystem or approved shared catalog.
- Read canonical consumer destinations from section-scoped `rules/skill-index.md` metadata and cross-check the skill's own `Inject Into` metadata.
- Normalize destinations through the closed scheduled-role registry.
- Add missing declared bindings before prompt construction; never silently discard an unknown destination.
- For an unresolved or conflicting declaration, emit a durable `UNKNOWN` review obligation.
- Bind the coverage artifact and methodology hashes into the dispatch contract.

Required fixtures:

- selected skill missing one declared depth consumer -> binding added;
- selected skill missing several declared consumers -> all scheduled consumers receive it;
- already complete binding -> byte/idempotency stable;
- non-selected skill -> never injected;
- declared consumer not scheduled in the current mode -> explicit mode-scoped disposition, not a fake application;
- conflicting index and SKILL metadata -> UNKNOWN/loud, no silent choice;
- wrong-ecosystem collision -> never inherited;
- EVM, Solana, Aptos, Sui, and Soroban resolution fixtures;
- Claude PTY, Claude headless, and Codex dispatch descriptors byte-equivalent apart from backend receipt fields;
- existing R10 constituent/source ID join survives the dispatch change.

### P0-B. Application completeness is conflated with semantic outcome

Live evidence: `validate_phase_application()` turns any result containing SAFE, no finding, or N/A into a GAP even when the step was executed with source evidence. The repair producer then reruns applied work as if it were missing. It also writes `methodology_skeptic_queue_<phase>.json`, but no later phase consumes that queue.

Live receipt evidence quantifies the failure on the production Claude path. Breadth initially closed 2/23 scheduled steps and left 21 gaps; its repair closed 8 of 21 repair obligations and still left 13. Rescan closed 2/15 and left 13; its repair received eight rows and closed zero. Depth closed 25/57 and left 32; its repair received 29 rows and closed zero. The corresponding skeptic queues contain 9/8 breadth rows, 3/0 rescan rows, and 8/10 depth rows across original/repair receipts, yet no downstream phase consumes them. The checkpoint still reports no degradation. The reason distribution proves the overload rather than merely suggesting it: nine initial breadth gaps, three rescan gaps, and eight depth gaps are already-applied SAFE/negative attestations awaiting skepticism, while other rows are missing/partial, lack resolvable evidence, or are absent trace rows. Repair reruns both populations; for example, all 29 depth-repair rows report `executed=yes`, but ten remain negative/skeptic obligations and nineteen remain evidence-unresolved. These figures are application-control evidence, not proof that every gap is a missed vulnerability; they prove that the current repair/receipt machinery neither achieves application closure nor routes authored negative outcomes to an independent discriminator.

Fix contract:

- Replace the overloaded disposition with orthogonal typed fields:
  - `delivery_integrity`: CURRENT / INVALID / UNKNOWN;
  - `application_completeness`: APPLIED / MISSING / INVALID / UNKNOWN;
  - `semantic_outcome`: CANDIDATE / NEGATIVE / NOT_APPLICABLE / INCONCLUSIVE;
  - `evidence_basis`: IN_SCOPE_SOURCE / IN_SCOPE_EXECUTION / PRIMARY_EXTERNAL_CITED / EXTERNAL_UNRESEARCHED / NONE;
  - `skeptic_required`: boolean plus reason.
- Only MISSING/INVALID application work enters the methodology repair producer.
- Applied-negative work enters an independent skeptic queue and is never counted as closed solely by its author.
- Preserve compatibility projections for existing Markdown/report readers, but make typed JSON authoritative.

Required fixtures:

- genuinely missing step -> repair exactly once;
- applied positive with resolvable source -> APPLIED/CANDIDATE, no skeptic solely for positivity;
- applied negative with in-scope source -> APPLIED/NEGATIVE plus skeptic, no methodology rerun;
- one N/A sub-clause inside a detailed applied result -> does not become MISSING;
- generic self-attestation -> INVALID/UNKNOWN, not APPLIED;
- malformed/missing trace -> MISSING or INVALID;
- repeated run -> no duplicate repair or skeptic rows;
- old schema -> deterministic compatibility migration, never silent reinterpretation.

### P0-C. Unsupported SAFE/NO_FINDING clears are accepted

Live evidence: the attention-repair producer cleared selected obligations as SAFE using unresearched external assumptions such as out-of-scope deployer/factory behavior. This reproduces the user's dominant `found/applied then wrongly safe` miss before verify, where post-verify R10 cannot recover it.

Fix contract:

- SAFE/NO_FINDING may close only on `IN_SCOPE_SOURCE`, `IN_SCOPE_EXECUTION`, or a cited authoritative external source bound to the exact premise.
- External-control language without premise-bound evidence becomes `NEEDS_EXTERNAL_EVIDENCE` or `CANDIDATE_CARRIED`; it is not automatically a vulnerability and is not deleted.
- The validator rejects unsupported clears mechanically while leaving semantic judgment to an independent worker/verifier.
- Consume the typed skeptic queue in Thorough/Core. The consumer must read the exact methodology path/hash/step and the original evidence/result, not merely checklist prose.
- Add one conditional `application_skeptic` phase after depth/attention repair and before semantic dedup/verification queue freeze. It consumes the original and repair queues from breadth, rescan, and depth with exact input-to-disposition parity. Agreement creates a durable negative decision carrying both assessor identities and evidence hashes; disagreement creates a typed candidate proposal that the shared producer registry promotes through normal dedup/chain/verification. An unavailable or budget-exhausted discriminator leaves report-visible debt, never a clean negative.
- Keep this role distinct from the post-verification finding skeptic: it adjudicates methodology-step negative outcomes before candidate identity may exist. Shard only by a deterministic manifest, require exact tail coverage, and forbid the original producer session/model invocation from self-adjudicating its own row.

Required fixtures:

- in-scope refutation with valid source line -> clear remains valid;
- executed in-scope negative test -> clear remains valid;
- primary external citation that directly proves the premise -> clear remains valid;
- `factory/deployer/out-of-scope/assume/guaranteed` without premise evidence -> cannot close;
- irrelevant external citation -> cannot close;
- unsupported negative with no finding block -> obligation retained and independently reviewed;
- independent skeptic agrees -> durable negative disposition with both identities/hashes;
- independent skeptic disagrees -> candidate routed to normal inventory/verify;
- skeptic unavailable -> haltless human-review debt, never silent closure;
- empty queue -> deterministic `NOT_TRIGGERED` receipt and no model call;
- breadth/rescan/depth original plus repair queues -> exact union with no duplicate or omitted obligation;
- discriminator disagreement becomes a registry candidate before queue freeze and receives independent verification;
- partial shard/tail overflow remains exact debt and resumes without re-adjudicating completed rows.

### P0-D. Attention-repair queue is Markdown-shape dependent and not content-bound

Live evidence: `_extract_skill_execution_repair_items()` treated an investigation-question table row (`Q3`) as a skill gap. The queue contains labels and prose but not an exact methodology path/hash/step contract; the attention producer reads the checklist summary rather than the source methodology bytes.

Fix contract:

- Authoritative queue is typed JSON derived from application receipts and structured obligation artifacts.
- Every row binds phase, worker, output, methodology path/hash, step, original result/evidence, disposition class, and source artifact hash.
- Markdown is projection only. Legacy fallback must be section/header scoped and must reject unrelated tables.
- Prompt construction must read the exact bound methodology bytes and verify the hash before launch.

Required fixtures: unrelated five-column table; investigation-question table; valid legacy gap table; hash drift; missing skill path; duplicate row; reordered Markdown projection; retry/idempotency.

### P0-E. Recall-positive phase degradation is not delivered inside the report

Code evidence: `_validate_exploration_skeptic()` states that absence of this additive phase loses no prior finding. That is literally true only for already-emitted candidates, but methodologically misleading: the phase exists to discover missing directions, siblings, and neighbours, so its absence can lose new true positives. The driver records `.degraded`, exits with a degraded status, and prints it to the terminal, but the final report path does not mechanically include the active degradation/completeness debt.

Fix contract:

- Preserve haltless behavior after bounded repair/retry.
- Classify degraded phases by assurance impact: discovery recall, verification confidence, report integrity, or enrichment-only.
- Before report assembly, project every active degradation and unresolved application/skeptic obligation into a mechanically generated `Audit Completeness and Assurance Limitations` section.
- The report cannot claim a clean/full audit when a recall-bearing phase degraded.
- A report-assembly failure remains a hard no-ship condition; an earlier phase degradation remains a loud, user-visible qualified report plus non-zero driver exit.

Required fixtures:

- exploration-skeptic missing -> discovery-recall limitation in report and degraded exit;
- axis-coverage missing -> same;
- optional context-only research missing -> enrichment limitation, not falsely elevated to verification failure;
- resolved retry removes the limitation and stale sentinel;
- resume preserves active limitation exactly once;
- report assembler cannot omit or rewrite the mechanical limitation section;
- clean run has no limitation banner.

### P0-F. Invalid exploration clears are detected but never repaired or consumed

Live evidence: `_validate_exploration_skeptic()` detected 67 `NO-GAP`/`ASSESSED` coverage rows lacking the required concrete evidence locus. It wrote `exploration_skeptic.instance_gap`, returned an empty issue list by design, and the driver immediately started `enumgap_exploration`. No downstream code reads that sentinel. The methodology text says those rows must be re-surfaced as ADD work, but the implementation only records prose that nobody consumes.

Fix contract:

- Produce a typed invalid-clear receipt, not an unconsumed text sentinel.
- On the first accepted artifact, invalid clears trigger one bounded targeted repair/continuation that receives only the invalid row identities plus their source finding/action context.
- Repair may provide canonical source/prior-ID evidence, change the row to an additive action, or mark it UNRESOLVED; it may not manufacture evidence.
- If bounded repair still cannot close a row, route it as an exploration obligation to an independent consumer and project it into report-visible completeness debt. Do not auto-assert a vulnerability.
- The phase cannot be marked clean while invalid-clear obligations remain.
- Any sentinel/receipt written by a gate must have a registered consumer or a report projection; a static registry test rejects dead operational artifacts.

Required fixtures:

- invalid clear -> targeted repair invoked once;
- repaired exact source locus -> closes;
- repaired exact prior-finding referent -> closes;
- unsupported blanket wording -> remains unresolved and is independently queued;
- substantive unsafe result -> emits/promotes action;
- repair timeout -> haltless degraded state plus report limitation;
- resume does not duplicate repair or obligation rows;
- no dead `.instance_gap` artifact remains outside the typed lifecycle.

### P0-G. Post-verification side findings are self-certified and bypass verification

Code/methodology evidence: `phase5_5-post-verify-extract.md` asks one agent to harvest side observations from verifier prose, deduplicate them semantically, append them directly to `hypotheses.md`, accept the original verifier's severity, and explicitly **not** re-queue them because “the verifier already documented the evidence.” But a verifier assigned to hypothesis X is a generator—not an independent discriminator—for a newly noticed Y. Its PoC may not execute Y at all. This contradicts generator/discriminator separation and the rule that only executed, exact-scope PoCs are proof-grade.

Fix contract:

- Extract to a typed `post_verify_candidates` queue; never append a newly generated side observation directly to reportable hypotheses.
- Bind any claimed inherited execution to the exact test file, command, exit/result, assertion, location, and proof scope.
- If the original mechanical evidence exactly exercises the side candidate, pass it through the ordinary integrity/verdict gate under a new candidate identity.
- Otherwise schedule bounded late verification before skeptic/report. In Thorough mode every severity follows the configured all-severity execution rule.
- Extraction/dedup and verification must be independent sessions/roles.
- Missing/partial late verification retains the candidate with an explicit unverified disposition and report-visible assurance limitation; it never becomes `VERIFIED` by prose inheritance.

Required fixtures:

- side observation covered by a distinct executed assertion -> exact evidence binding accepted;
- observation merely mentioned while verifying another issue -> late verify queued;
- original PoC pass unrelated to side assertion -> cannot inherit proof;
- extractor-proposed severity is advisory only;
- late verification confirms/refutes/contests through normal gates;
- extraction phase missing while `[VER-NEW-*]` exists -> deterministic harvest fallback or degraded recall debt;
- zero side observations -> clean no-op;
- retry/resume idempotency and no duplicate hypothesis/report IDs.

### P0-H. Inventory trust tags are treated as unchallengeable severity authority

Methodology evidence: the report-index rules mechanically apply a one-tier `TRUSTED-ACTOR` downgrade from an inventory tag and explicitly forbid the index agent from overriding it “for verification results or analytical reasoning,” calling the Inventory Agent the sole authority. This is another generator/self-certification asymmetry: an early consolidator can misclassify an actor or infer a trust assumption, after which later evidence is prohibited from correcting the demotion.

Fix contract:

- Inventory trust classification is a claim, not final authority.
- A `FULLY_TRUSTED` claim must bind the exact actor/capability, the user-supplied scope/trust statement or authoritative primary documentation, and the concrete action required for harm.
- Category labels such as admin/governance/multisig are not by themselves proof of a project trust assumption.
- An independent trust/evidence reconciliation produces the report adjustment; verification or skeptic evidence may challenge the classification.
- Unproven/conflicting trust claims retain the finding and original severity with a visible trust-uncertainty note; they do not auto-downgrade.
- A valid, explicitly scoped fully-trusted assumption may still apply the documented adjustment.

Required fixtures:

- user scope explicitly trusts a named capability -> adjustment valid;
- generic admin/governance label without scope evidence -> no automatic downgrade;
- semi-trusted/operator/oracle role -> never FULLY_TRUSTED adjustment;
- inventory tag conflicts with verifier evidence -> independent reconciliation, not inventory fiat;
- actor cannot cause the required transition -> premise refuted separately;
- report index consumes a typed, provenance-bound adjustment ledger and cannot invent/remove rows;
- non-EVM capability/authority identities covered.

### P0-I. Enumeration and axis prompts promise input-to-disposition reconciliation that the gates do not perform

Methodology/code evidence: both `phase4b7-enumgap-exploration.md` and `phase4b8-axis-coverage.md` require one coverage row per input obligation/GAP cell and claim downstream gating will confirm this. Their validators primarily check that an output artifact exists; the promoters parse well-formed finding headings but do not diff every structured input row against exactly one FINDING/UNRESOLVED/CLEAR disposition. Missing rows and vague clears can therefore pass while raw fallback candidates preserve only a hint, not proof that the methodology was applied.

Fix contract:

- Reconcile authoritative structured worklists (`_enumeration_obligations.json`, `_hot_function_axes.json`) against typed output dispositions.
- Every input identity receives exactly one current disposition; duplicates/conflicts are invalid.
- FINDING/UNRESOLVED evidence must resolve to an emitted/promoted action identity.
- CLEAR evidence must resolve to an in-scope source locus, executed evidence, or existing finding identity; external assumptions follow the unsupported-SAFE rule.
- First failure receives a bounded targeted repair. Residual gaps remain queued and report-visible; the raw low-confidence fallback remains but is not mislabeled as methodology application.
- Caps/truncation record the exact omitted identities and never report complete coverage.

Required fixtures:

- all inputs disposed exactly once -> complete;
- one missing row -> targeted repair and durable obligation;
- duplicate/conflicting dispositions -> invalid;
- finding disposition with absent heading -> invalid;
- vague/unsupported clear -> cannot close;
- exact in-scope clear -> closes;
- truncated input/output -> exact shortfall receipt;
- empty worklist -> clean no-op;
- resume/retry preserves identities and promotions idempotently.

### P0-J. The variant gate recursively re-runs the co-reference generator over generated candidates

Methodology/code evidence: `_run_accepted_depth_postprocessors()` invokes `run_enumeration_gate()` and then `compute_variant_gaps()`. The former already runs `validate_enumeration_coverage()` and appends its co-reference `ENUMGAP` candidates to `findings_inventory.md`. Despite its driver documentation saying that the second call supplies only axes 2 and 3, `compute_variant_gaps()` calls `compute_enumeration_obligations()` and `validate_enumeration_coverage()` again before running boundary and symmetric-operation derivation. The second co-reference pass therefore observes an inventory already containing mechanical candidates and may derive candidates from candidates.

Live reproduction: the frozen two-contract Claude canary's first enumeration processor emitted 46 rows (40 co-reference plus six committed-invariant rows). The immediately following variant processor emitted another 55 rows: 40 were a second co-reference tranche and only 15 were the intended boundary tranche. The resulting pre-dedup inventory contained 80 `ENUMGAP` and 15 `VARGAP` blocks. This is not merely cosmetic duplication: the second tranche used later inventory identities as its bases, consumes exploration/chain/verification context and caps, and can crowd out genuine findings.

Fix contract:

- `run_enumeration_gate()` is the sole axis-1/co-reference owner at the accepted depth boundary.
- `compute_variant_gaps()` computes only boundary-input and symmetric-operation work. Preserve the existing result schema with `axis1_emitted = 0` if compatibility requires the key.
- No generator may consume its own or another generator's low-confidence candidate as an origin unless a typed rule explicitly declares composition and preserves the original non-generated anchor.
- The accepted-depth journal binds every generator to its authoritative non-generated inputs and records origin kind, observed count, retained count, and exact omitted identities.
- Candidate-family grouping and later grounded exploration remain additive; removing recursive generation must not remove the first-pass co-reference candidates or intended boundary/symmetry work.

Required fixtures:

- one source finding that produces an axis-1 gap: the first pass emits it and the variant pass emits zero axis-1 rows;
- a mechanical candidate present before the variant call cannot become a new co-reference origin;
- boundary and symmetric-operation rows still emit after axis-1 removal;
- repeated finalization is idempotent and receipt-bound;
- an explicitly grounded/promoted finding derived from an earlier candidate is treated as a normal finding only after its typed promotion state changes;
- source and non-EVM graph identities remain covered;
- the live-canary isolation replay falls from 80 to the single intended co-reference tranche without losing any first-pass identity.

### P0-K. Structured Source-ID lineage is filtered through a stale free-form allow-list

Code evidence: `_records_from_inventory_text()` describes `finding_records.json` as the immutable downstream identity ledger, but it parses the already-structured `Source IDs` field with `_extract_finding_ids_from_text()`. That free-form helper admits only `_FID_ALLOWED_PREFIXES`, a separate manually written allow-list. The allow-list omits currently emitted prefixes including `IP` (interface-parity breadth) and the methodology-application prefixes `MAB`/`MAR`/`MAD`, despite the unified internal grammar documenting the latter. Other producer lists independently omit `SP` from canonical-producer scanning and omit the newly observed SKEP/DXRE routes. This is an encoding/registry error: a valid structured identity is discarded because a prose-noise filter is applied after the parser has already isolated the authoritative field.

Live reproduction: the frozen canary's Markdown inventory structurally contains `Source IDs: IP-1, CC-01` and `Source IDs: MAB-1, CC-07`. The generated `finding_records.json` retains `CC-01`/`CC-07` but drops `IP-1`/`MAB-1`. The inventory remains visible, so this is not yet a body-finding disappearance in this run; it is proven lineage loss in the artifact that downstream location, reconciliation, and grouping code treats as authoritative.

Fix contract:

- Parse an isolated structured Source-ID field with a structured token grammar, not a free-form prose allow-list.
- The typed producer registry owns local-ID grammar and semantic kind; compatibility parsing may preserve unknown well-formed structured identities as `UNKNOWN_REGISTERED_ID` debt rather than silently deleting them.
- Keep free-form exclusions for EIP/ERC/CVE/RFC-like prose tokens only in prose-scanning call sites.
- Dual-write the Markdown field and typed record, then assert exact set parity for every finding block.
- Alias/group operations union every constituent identity; no survivor may lose a source alias.

Required fixtures: `IP-1`, `MAB-1`, `MAR-1`, `MAD-1`, `SP-1`, `SKEP-001`, `DXRE-1`, ecosystem-specific multi-part IDs, an unknown well-formed structured token, EIP/ERC/CVE prose, source ranges, alias union, and Markdown-to-JSON exact parity.

### P0-L. Inventory parity is threshold-based and changes its authority to chunks before proving raw-source disposition

Code evidence: `_validate_inventory_parity()` is explicitly a truncation heuristic. In sharded mode it compares the final inventory only to `findings_inventory_chunk_*.md`, not to raw discovery artifacts, and fails missing-ID coverage only below 45 percent. Consequently a chunk producer may omit a minority—or even slightly more than half—of discovery IDs while the final merge passes. A source ID mentioned in a summary/exclusion table is also weaker evidence than a retained finding body or an explicit supported negative disposition. This does not meet the pipeline's stated recall-safe contract.

Live evidence: this canary happened to preserve all 46 standard breadth/rescan/per-contract IDs across parsed chunk entries, so it is a healthy positive fixture, not a reproduction of loss. The code path nevertheless permits loss by construction; exact set reconciliation is mechanically decidable over artifacts already present and does not require model judgment.

Fix contract:

- Before accepting each inventory chunk, enumerate every assigned source finding identity and require exactly one typed disposition: RETAINED in a concrete chunk block, MERGED into a concrete survivor with alias union, SUPPORTED_REFUTATION with an in-scope evidence basis, or UNRESOLVED/REPAIR.
- After mechanical merge, reconcile raw discovery identities -> chunk dispositions -> final inventory identities exactly. A threshold may control retry strategy, never whether an omitted identity is considered accounted for.
- On a missing/unparseable identity, repair mechanically by preserving the raw substantive block as `NEEDS_INVENTORY_REVIEW` where safe; otherwise queue bounded targeted repair and expose residual debt. Never accept an unbound mention as retention.
- Bind sharding plans to source artifact hashes and finding identities so resume cannot reuse a stale partial plan.
- Use the typed producer registry for raw-source discovery; no manual source-pattern drift.

Required fixtures: 100 percent retained; one of 100 omitted; 54 percent omitted; explicit many-to-one merge with full alias union; bare summary-table mention without block; supported refutation; malformed source block; shard hash drift; retry/resume; empty audit; L1 graph-sweep and non-EVM discovery artifacts.

### P0-M. Optional-`Finding` heading parsing promotes methodology step sections as vulnerabilities

Code evidence: `_parse_depth_finding_blocks()` accepts `#{2,4} (?:Finding)? [ID]`, with `Finding` optional, and defaults a block with no explicit severity to Medium and no location to `unknown`. `_DEPTH_PROMOTION_FILES` also re-scans pre-inventory rescan/per-contract artifacts. `RS-N` is both a methodology step namespace (`RS-0` through `RS-5`) and a permitted niche finding prefix, while actual rescan findings in the live output use `RS1-N`/`RS3-N`. The parser consequently has no semantic boundary between a method section and a finding block.

Live reproduction: immediately before semantic dedup, `depth_promotion_receipt.md` promoted 27 rows. Five were `RS-0`, `RS-1`, `RS-2`, `RS-4`, and `RS-5` headings such as “Under-Explored-Surface Selection” and “Time-Dependent State Under Operation Sequences,” not findings. They were assigned default finding fields and sent toward dedup/chain/verification. The real `RS1-1`/`RS3-*` findings were already present through the earlier inventory synthesis, so this added only false work and identity confusion.

Fix contract:

- The typed producer registry declares each artifact's lifecycle position, semantic kind, local-ID grammar, and accepted block schemas.
- Canonical producer output requires an explicit `Finding` heading. A narrowly declared legacy heading without that word is accepted only when the same bounded block contains required finding fields (at minimum severity, concrete location, mechanism/root cause, and impact/verdict) and the registered local-ID grammar matches.
- Methodology step/checklist/coverage namespaces are never vulnerability producers merely because their labels are ID-shaped.
- Pre-inventory producers already reconciled into inventory are not blindly re-promoted later; their emergency recovery path operates only on identities proven absent from the exact inventory-disposition ledger.
- Row-only fallback remains limited to a registered finding-catalog table with typed column semantics.

Required fixtures: `## RS-0 — selection` does not promote; `## Finding [RS3-1]` promotes when absent; a legitimate registered legacy `## [DE-1]` block with all fields promotes; the same heading missing fields becomes schema debt; step-execution tables do not promote; chain-summary row fallback still works; source finding already inventoried is idempotent; non-EVM legacy block formats are covered.

### P0-N. Resume repairs can acknowledge a newly detected queue dropout without ever verifying it

Code evidence: startup reconciliation calls `backfill_unrouted_inventory_into_queue()`. If any verify shard is already checkpointed, it deliberately chooses `route="excluded"`; the helper writes each newly noticed inventory identity to `verification_queue_evidence_excluded.md` as "Deferred on resume" specifically to avoid rewinding verification. The parity validator then counts the excluded row as acknowledged. This repairs checkpoint shape, but it does not repair the security lifecycle: a finding that was discovered and persisted in inventory can satisfy parity without any verifier ever examining it. The current comment explicitly optimizes away verification reruns, contrary to recall-first policy.

Fix contract:

- An inventory identity discovered as unrouted after verify shards completed remains verification work; an excluded/deferred row cannot satisfy final retention merely because it satisfies queue cardinality.
- Route the missing identities to a bounded recovery-verification manifest using the existing recovery-shard machinery, preserving their original severity, location, evidence class, and lineage.
- Invalidate/recompute only the affected verification aggregate, skeptic/cross-batch, and report descendants; do not rerun unrelated completed shards.
- If a recovery verifier cannot run, keep the identity report-visible at its upstream severity as `UNVERIFIED/UNRESOLVED` with a human-review limitation. Never silently convert it into evidence-excluded work.
- Resume is idempotent: one identity has one recovery job and one eventual disposition; completing recovery closes the debt without a loop.

Required fixtures: dropout before any shard -> active queue; dropout after unrelated shards -> recovery manifest, not excluded-only; recovery confirms/refutes/contests through ordinary gates; recovery unavailable -> in-body unresolved item; affected descendants rewind while unrelated shard receipts remain valid; a legitimately mode-excluded Low/Info row remains excluded; repeated resume does not duplicate or loop.

### P0-O. Ambiguous grouped-PoC matching currently demotes every constituent

Code evidence: `_apply_poc_fail_demotions()` tries to protect a multi-constituent hypothesis when verifier prose matches exactly one constituent title by Jaccard similarity. But when the match is `ambiguous` (best score below `0.40`), it explicitly applies the hypothesis-level `cap-all` fallback. `shared_claim` also falls through to cap-all. Ambiguity is absence of proof scope, not evidence that every absorbed mechanism was disproved. This makes the existing protection fail in the direction most damaging to recall: the less precisely the verifier describes what it tested, the broader the demotion becomes.

Fix contract:

- A demotion is scoped to the exact constituent premise(s) exercised by executed evidence. Title similarity is routing telemetry, not proof authority.
- `single_winner` may demote only the evidence-bound constituent and must split/requeue the others.
- `ambiguous` demotes none of the constituents; it creates a proof-scope repair/reverification obligation.
- `shared_claim` may demote multiple constituents only when the executed assertion and premise-evidence ledger explicitly bind every affected constituent to the same tested harm. Lexical overlap alone is insufficient.
- Failure to complete scoped reverification keeps the untested constituents at their pre-demotion severity with an unresolved-evidence flag.

Required fixtures: one tested constituent; ambiguous verifier summary; two lexically similar but semantically separate constituents; one truly shared assertion bound to all members; mechanism-only execution; harm-scoped execution; partial recovery failure; chain alias/split-parent IDs; idempotent replay. The central assertion is monotonic: widening uncertainty can never widen a demotion.

### P0-P. Blind-first severity is a one-way, single-verifier mechanical downgrade authority

Code evidence: `_apply_independent_severity_caps()` reads the same verifier's `Independent Severity` field and mechanically applies `final = min(independent, claimed)`. It can only lower severity, never raise it, and does not require a structured statement of which impact or likelihood premise was refuted. Missing/unparseable fields fail safely, but a confidently wrong Low/Informational value becomes binding. Combined with the user's measured miss class (findings found and then incorrectly judged safe), this is an asymmetric amplifier of exactly the dominant retention failure. R10 only floors some externally premised cases to the depth-claimed severity; it cannot recover a depth-side under-rating or an internally premised erroneous cap.

Fix contract:

- Blind-first assessment remains an independent challenge, not automatic downgrade authority.
- Any decrease requires a typed decision event binding: affected identity/constituents, prior severity, proposed severity, impact premise, likelihood premise, the premise actually refuted, exact evidence IDs, and proof scope.
- A severity disagreement without premise-resolving evidence remains `UNRESOLVED(<upstream>)` and triggers bounded independent adjudication; it does not silently choose the lower value.
- The same mechanism is direction-neutral: confirmed stronger harm/composition can raise a challenge as well as lower one. The final arbiter applies Impact x Likelihood from evidence, with R10 worst-case policy for unresolved external premises.
- Precision protection comes from a separate adjudicator and evidence burden, not from monotonic lowering. Report writers only render the resulting decision ledger.

Required fixtures: unsupported Low challenge against a confirmed mechanism -> no automatic cap; premise-resolving executed evidence -> valid downgrade; mechanism-only PoC -> unresolved; external favorable premise -> R10 interaction; depth under-rating -> upward challenge; multi-constituent scoped decision; conflicting independent arbiters; no decision event -> upstream severity retained; report cannot mutate the adjudicated result. Benchmark the change on both recall and severity calibration; never accept an apparent recall gain that merely inflates every finding.

### P0-Q. Semantic dedup's advertised zero-data-loss coupling does not preserve the absorbed finding body

Code evidence: `_apply_merges_to_inventory()` removes absorbed SC inventory blocks after `_couple_absorbed_into_survivor_block()`. The coupling helper's contract claims it carries distinct Impact and Recommendation, but its implementation carries only location, source IDs, higher severity, strongest evidence, and a short `Coupled from <ID>: <title>` paragraph. It does not copy the absorbed Root Cause, Description, Impact, Recommendation, preconditions, or evidence narrative. Unlike final report dedup, this semantic-inventory path does not run `_dedup_data_loss_gate()` after transformation. A merge can therefore preserve the heading/title identity while deleting the reasoning needed for later chain analysis and verification.

Live reproduction: the canary entered dedup with 199 inventory blocks and exited with 188. The decisions file contained 93 canonical `MERGED into` pairs, but the executor physically removed only 11 blocks. For the 11 applied merges, an exact field audit found the absorbed Impact field absent from every survivor (93/93 decision rows also fail an intent-level Impact-presence check); the three applied substantive pairs retain only title/location coupling, not the absorbed reasoning body. The 82 rejected family merges expose the separate proposed-vs-applied lineage defect below.

Fix contract:

- Semantic dedup produces an alias-preserving group card first; it does not destructively remove member records needed for verification/application coverage.
- If a physical merge is retained for bounded context, the survivor must losslessly embed every member's typed mechanism, preconditions, impact, location, recommendation, evidence/proof scope, external premises, and lineage before removal.
- Run a field-aware post-transform diff over every absorbed member. Missing or unparseable fields veto the destructive merge and keep the members separate; a title or source-ID mention is not sufficient.
- Boundary/variant work is grouped for scheduling but retains every member identity and required test/disposition. One representative PoC cannot clear the family without per-member evidence binding.
- The canonical alias map remains split-capable through chain, verification, report index, and resume.

Required fixtures: same title/location but distinct root causes; same mechanism with distinct boundary values; distinct external premise; stronger absorbed impact; unique recommendation; unique PoC/evidence scope; malformed member; transitive group; non-EVM locations; destructive transform loses one field -> veto; exact superset -> accepted and byte/field diff proves preservation.

### P0-S. Proposed dedup decisions are consumed downstream as if every proposal was actually applied

Live reproduction: `dedup_decisions.md` claimed 93 absorbed-to-survivor pairs. The survivor-superset executor accepted only 11, as proven by the exact inventory delta (199 -> 188) and the continued presence of examples such as `INV-063` and `INV-140` in `findings_inventory.md`. Nevertheless, `_propagate_dedup_absorbed_to_finding_mapping()` built `dedup_absorbed_map.md` with all 93 proposal rows. That map instructs Chain Agent 1 not to create an absorbed ID as a standalone hypothesis. The deterministic pre-chain `finding_mapping.md` simultaneously contains those rejected IDs as one-to-one hypotheses. The pipeline has therefore created two contradictory authorities: actual inventory says the candidate survived; the proposal-derived alias map says it was absorbed and must not survive independently.

Additional signal: the dedup coverage repair appended `PASSTHROUGH` rows for candidate pairs it failed to recognize even when the same file already contained LLM `MERGE:` groups. A single Markdown artifact can now assert MERGE and PASSTHROUGH for the same pair without an exact conflict gate.

Fix contract:

- Treat LLM dedup output as proposals only. The executor writes a typed, immutable applied-decision receipt containing proposal identity, member IDs, accepted/rejected status, rejection reason, actual survivor, transformed artifact hash, and per-member field-preservation result.
- `dedup_absorbed_map`, hypothesis aliases, queue parity, coverage seed, attribution, and report consolidation consume only `ACCEPTED` applied events, never raw prose proposals.
- Exact postcondition: `accepted_absorbed_ids == pre_inventory_ids - post_inventory_ids`; every rejected member remains independently live; every accepted member resolves to one existing survivor.
- Conflicting MERGE/KEEP/PASSTHROUGH dispositions for the same normalized pair/group trigger deterministic reconciliation or keep-separate, never warning-only continuation.
- The Markdown decisions file becomes a projection of proposal plus applied receipt, not a mixed mutable authority.

Required fixtures: proposed merge rejected by superset gate; partially accepted transitive group; proposal direction flipped; member already absent; conflicting MERGE/PASSTHROUGH; stale decisions on resume; exact before/after hash mismatch; non-EVM row-form queue; downstream alias map contains accepted rows only; rejected members reach separate verification jobs.

### P0-R. Report completeness treats lexical exclusion or appendix relocation as equivalent to a sound disposition

Code evidence: `_collect_index_acknowledged_ids()` and `_check_index_completeness()` count every ID appearing in the report index's Excluded Findings table as accounted. `_validate_report_index_triage_safety()` is warning-only and accepts broad lexical reasons such as low confidence, contested, no trace, or insufficient evidence without binding them to the verifier/judge decision; `APPENDIX_ONLY` is itself an unconditional Medium+ allow token. `_check_promotion_symmetry()` mines only `CONFIRMED` receipts and considers an ID successful when it appears in the body, Appendix/Excluded Findings, consolidation/internal traceability, or any acknowledged `report_coverage.md` status. `PARTIAL`/`CONTESTED`/`UNRESOLVED` reportable decisions do not receive this stronger body-retention check at all. Separately, `report_disposition` may write any parseable `APPENDIX` row; `parse_disposition_md()` validates only syntax, and `report_floor` trusts it instead of recomputing/validating material harm. Relocation then deletes the full body section and keeps only a compact Appendix-C row. Thus cardinality completeness can be green while a reportable finding was semantically excluded or stripped by an unsupported writer judgment.

The driver-authored fallback is not a semantic authority either. `write_disposition_md()` concatenates matching verifier prose, extracts the first available `Material Harm`/`Impact`/`Description` field, and calls `classify_body_or_appendix()`. That classifier explicitly ignores severity and decides from a finite harm regex plus a pure-quality keyword vocabulary. A quality keyword wins APPENDIX whenever the finite harm regex misses the wording, even for a High/Medium identity; the default-to-BODY behavior reduces but does not eliminate this false-relocation class. A deterministic lexical classifier is suitable as a disagreement alarm or conservative BODY veto, not as proof of zero security consequence.

Fix contract:

- Separate `identity_accounted` from `disposition_authorized`. Completeness requires both; only the independent verifier/judge/trust/premise decision ledger may authorize non-body status.
- Report index is a renderer/consolidator. It cannot create `REFUTED`, `LOW_CONFIDENCE`, `CONTESTED`, `DUPLICATE`, `CONSOLIDATED`, or appendix authority from prose. Every non-body row must cite an exact structured decision/alias event for the same identity and proof scope.
- `DEFERRED` coverage backfill and resume-excluded rows remain unresolved verification debt, not successful report disposition. If no authorized decision exists, retain the finding in body at the upstream severity with an `UNVERIFIED/UNRESOLVED` marker.
- An LLM `APPENDIX` proposal is applied only when an independent, typed material-harm decision concludes zero security consequence and no mechanism/impact/premise ledger contradicts it. Lexical classification may veto relocation or request adjudication but may not establish zero harm. Disagreement, missing fields, parse failure, and unsupported High/Medium quality labels default to BODY.
- If relocation occurs, retain an auditable full-content sidecar and prove the appendix representation preserves all client-relevant fields. No row-only compaction is called zero-data-loss without a field diff.

Required fixtures: verifier-confirmed Medium excluded as "low confidence" -> body; verifier `PARTIAL`/`CONTESTED`/`UNRESOLVED` omitted or appendix-relocated -> body at authorized tier; verifier-refuted item -> authorized exclusion; duplicate with exact survivor alias -> authorized consolidation; arbitrary APPENDIX proposal for harm-bearing Low -> veto/body; harm-bearing High/Medium containing a pure-quality keyword but harm phrased outside the lexical vocabulary -> body; negated harm wording; first-field extraction conflicts with a later typed impact record; true style-only item with dual agreement -> appendix; R10 external-premise item -> body; coverage-only unverified candidate -> recovery/unresolved, not complete; full-content preservation; missing/stale/mismatched decision ID; repeated report floor is idempotent.

### P0-T. Real-signal chain-composition pairs may remain permanently unexamined while the phase still completes

Code evidence: `reconcile_chain_iter2_tail()` correctly distinguishes consumed tail pairs from unresolved packet rows and bounded overflow, writing `DEGRADED_COVERAGE_GAPS`. `_validate_chain_iter2()` nevertheless treats both `COMPLETE` and `DEGRADED_COVERAGE_GAPS` as a successful soft phase and returns no issue. The remaining real-signal pairs live only in `chain_composition_coverage_gaps.md`; no later phase is required to analyze them, promote them, or render them as unresolved coverage. On the two-contract canary, pre-chain artifacts already include a 1.60MB structured tail payload and a 632KB gap ledger, so this is not a theoretical large-repository corner.

Live completion evidence: the Claude worker substantively analyzed and wrote all 15 assigned packet rows, but rendered the mandated section as `## 2. Tail Pair Dispositions`. `reconcile_chain_iter2_tail()` accepts only an exact unnumbered `## Tail Pair Dispositions` regex, so it parsed zero rows and wrote `consumed_pairs=0`, `unresolved_packet_pairs=15`, `overflow_pairs=7529`, `status=DEGRADED_COVERAGE_GAPS`. The worker's own artifact simultaneously states `15 / 15` covered. `_validate_chain_iter2()` returned success by design. Although that function attempts to write `chain_iter2.degraded`, the generic successful-phase cleanup removed the sentinel; the completed live scratchpad contains no `*.degraded` file and the checkpoint reports zero degraded phases. This is direct evidence that some apparent methodology non-application is actually an encoding/consumer failure after the methodology was applied, followed by mechanical debt erasure.

Live delivery evidence exposes the opposite failure mode: retaining debt without a bounded projection. Python assembly inlined the 15 unresolved packet pairs and 7,529 overflow pairs as 7,546 table rows in the client-facing human-review appendix. That one subsection is 761,144 characters; Appendix B is 789,233 of the report's 928,052 characters (85.04%). The quality gate still reports the document structurally healthy apart from an unrelated privacy false positive. Exact recall debt was not lost, but the report became dominated by low-level enumeration state. This is not a reason to delete the debt: it proves that a lossless machine ledger and a bounded client projection must be separate artifacts.

Fix contract:

- The structured pair manifest is authoritative and every real-signal pair receives exactly one terminal semantic disposition or an explicit unresolved-composition candidate.
- Process the tail in deterministic bounded shards, advancing a cursor until closure; do not cap the universe and call overflow coverage.
- Reduce redundant work by alias-preserving equivalence families keyed by stable graph identities, but retain every member pair and allow a family to split when evidence differs.
- A timeout/budget stop is haltless: remaining pairs become durable unresolved work and a report-visible assurance limitation, with exact counts/IDs. It is not phase-complete methodology application.
- Keep the full pair-level debt in a typed, hash-bound sidecar with exact denominator, identities, family membership, cursor, and disposition. The client report renders bounded aggregate counts by reason/family plus representative samples and a digest/path reference; it never inlines thousands of near-identical rows. Renderer parity proves that the summary denominator and sidecar digest cover the complete ledger, so anti-bloat cannot become silent recall loss.
- Newly composed findings enter ordinary verification; a chain worker cannot self-certify them.

Required fixtures: all packet rows consumed under exact and numbered section headings; one missing row; heading/table schema drift with substantive rows -> targeted normalization or persistent debt, never clean completion; overflow beyond one shard; duplicate/reversed pair; family-equivalent pairs; family member with divergent evidence; pair generator failure; resume cursor idempotency; budget stop -> exact unresolved ledger plus bounded report limitation; 7,500+ unresolved rows remain exact in the sidecar while the client projection stays within its configured row/byte ceiling; summary denominator/digest mismatch; sidecar missing or stale; new composition -> verification queue; no real-signal pairs -> clean no-op; worker-claimed 15/15 versus mechanical 0/15 must surface the mechanical mismatch in checkpoint and delivered assurance status.

### P0-U. Report-index "repair" legitimizes an unsupported severity downgrade without restoring severity

Code evidence: `_validate_report_index_inputs()` compares each report row with `_expected_report_index_severities()`. When the Index Agent silently writes a lower severity and leaves Trust Adjustment empty, `_repair_report_index_severity_provenance()` does not restore the upstream severity or request adjudication. It edits only the Trust Adjustment cell to add `SEVERITY_OVERRIDE(upstream=<higher>, llm=<lower>, reason=llm-downgrade-no-judge)` and records a ledger row; the lower Severity cell remains unchanged. The next validation pass accepts that reason, and tier routing/report writers consume the lower severity. The repair therefore converts an unauthorized semantic demotion into an authorized syntactic one. This is distinct from P0-P: P0-P concerns verifier-side blind-first caps; P0-U occurs later in a report renderer and can demote an otherwise correctly adjudicated finding.

Fix contract:

- Report index is a projection, not a severity authority. Its Severity cell must be derived from the latest authorized, identity- and premise-bound decision event.
- A lower writer proposal with no authorized decision is rejected or mechanically restored to the upstream severity. The event remains visible as an index-drift violation; merely stamping a reason cannot make it valid.
- If upstream authorities genuinely disagree, route to the same direction-neutral severity adjudicator specified by P0-P and retain the conservative upstream severity until resolution.
- The override ledger records detected drift and the applied restoration/adjudication result. It may not itself authorize the lower value it is documenting.
- Multi-constituent rows derive severity from the exact applied consolidation/chain decision and preserve per-member disagreements; choosing the minimum member severity is forbidden.
- Report tier manifests and final report must prove parity with the authorized severity ledger, not with mutable report-index prose.

Required fixtures: silent Medium-to-Low index change -> restored Medium; authorized premise-bound Medium-to-Low decision -> Low; unsupported inflation -> adjudication/hard repair; exact same severity -> no-op; malformed/empty Trust Adjustment; stale or mismatched override ledger; multi-constituent row with different severities; R10-undemoted identity; resume/idempotency; tier manifest and final report retain the restored severity.

### P0-V. Skeptic and judge are one self-adjudicating phase, and uncertainty mechanically lowers severity

Methodology/code evidence: `prompts/shared/v2/phase5-skeptic.md` tells one phase process to act as the adversarial skeptic and then, on disagreement, apply the judge framing inline: “Do NOT spawn a judge subagent.” The same context therefore authors the objection and decides whether its own objection wins. The prompt further mandates that an `UNRESOLVED` outcome receives a one-tier demotion, and its tie rule says the side with more specific code locations wins. `_parse_skeptic_judge_table()` validates only ID and decision-token syntax; `write_judge_decisions_json_sidecar()` projects those rows; `_collect_judge_downgrade_map()` and tier assignment consume `DOWNGRADE` as authority without a premise-to-evidence soundness check. `_validate_skeptic_scope()` and `_validate_skeptic_full_ch_coverage()` prove enumeration, not ruling validity. Finally, the manifest is restricted to provisional High/Critical findings, so an earlier wrong Low/Medium assignment suppresses the only independent appeal. This violates the pipeline's stated no-self-certification and generator/discriminator separation principles.

Live Medium-E evidence proves the severity-gated appeal gap is active. Four queue-Medium rows finalized as one `PARTIAL` and three `REFUTED`; one of the refutations is unexecuted `[CODE-TRACE]`, while two carry `[POC-FAIL]`. All four omit Independent Severity and Impact/Likelihood axes, yet the current verifier gate accepted the shard without retry. Because the skeptic manifest is High/Critical-only, none is guaranteed an independent challenge merely because it proposes a terminal refutation or non-body disposition. This is not a claim that the three refutations are substantively wrong; it proves that a wrong Medium refutation would traverse the exact unappealed path in the user's measured found-then-safe miss class. Receipt: `evm-siloconfig-thorough-007.verify-lifecycle.phase38-medium-e.v1.json`, extractor SHA-256 `741B28960A005F163451FF69B07ECDBCFA56E51475F9BA861D0C3017913B3649`, receipt SHA-256 `7A61F277B05BFD533BD5577FDC3D8C1354D73393C79000E0BC03636AB9ED9A36`.

The completed skeptic phase confirms the same boundary over the full frozen queue. After aggregate/mechanical processing, the 174 verifier records contained 116 `REFUTED`, nine `CONTESTED`, four `PARTIAL`, and 45 `CONFIRMED` decisions, while the active queue contained only two provisional High rows, 24 Medium rows, and 148 Low/Informational rows. The exact dispatched skeptic prompt contains nine Critical/High scope references, zero Low/Info appeal references, and zero references to any `methodology_skeptic_queue_*` artifact. It produced one typed judge-decision row and completed cleanly. This is expected under the current prompt, but it proves the architecture does not independently adjudicate the high-volume negative-disposition or methodology-safe queues; output-count success in the verifier shards is therefore not evidence that the user's wrong-safe miss class was closed.

Fix contract:

- Separate skeptic proposal from adjudication by worker identity and context. The adjudicator receives the original claim packet, the skeptic challenge, immutable evidence receipts, and neither author's hidden reasoning; it emits a typed decision event.
- `UNRESOLVED` is an evidence state, not a severity discount. Preserve the highest still-supported Impact x Likelihood result until a premise-resolving decision authorizes change; flag the disagreement in body.
- A downgrade or dismissal must identify the exact affected claim/constituents, prior/final severity, impact or likelihood premise, refuted premise, evidence receipt IDs, proof scope, and decision author. Markdown rationale alone is not authority.
- Replace severity-gated appeal with challenge triggers: confirmed mechanism plus unresolved harm/external premise, material verifier/depth disagreement, evidence-integrity downgrade, grouped proof-scope ambiguity, or any proposed decrease/non-body disposition. Provisional Low/Medium must not suppress these triggers.
- Remove citation-count tie breaking. Evidence relevance, execution authenticity, premise coverage, and environment fidelity decide; unresolved conflicts remain visible.
- Use the shared direction-neutral adjudication ledger from P0-P/P0-U. The skeptic, index, and report are projections/consumers and cannot create a second severity authority.
- Haltless failure means the prior supported severity remains in body with `UNRESOLVED` and an assurance limitation; it never means automatic demotion.

Required fixtures: High objection with no premise-resolving evidence -> no demotion; balanced evidence -> unresolved at prior severity; concrete defense proven by executed harm-scoped evidence -> authorized downgrade; external best-case assumption -> R10 preservation; provisional Low confirmed mechanism receives challenge; evidence-integrity downgrade triggers review; same worker cannot author and adjudicate one event; stale/foreign evidence receipt; multi-constituent partial defense; adjudicator unavailable; resume idempotency; tier/report parity with adjudicated result.

### P0-W. Chain anti-absorption repair is a destructive lossy rewrite with self-authorized equivalence

Code evidence: `_validate_chain_anti_absorption()` uses severity span and lexical root-cause Jaccard as its hard signals, but skips the group entirely when the chain-authored hypothesis contains `Anti-absorption override`. `_chain_group_violates_anti_absorption()` then treats all members at one normalized file/function locus as one bug without testing invariant, precondition, effect, impact, or fix equivalence. When a split is triggered, `_repair_chain_anti_absorption_splits()` rebuilds **all** `hypotheses.md` and `finding_mapping.md` rows from `_parse_inventory_finding_meta()` and `_build_merged_group()`. The rebuilt hypothesis keeps IDs, maximum severity, a title plus merged titles, and a short reason; it does not preserve the chain agent's original mechanism narrative, preconditions, invariant, impact, evidence scope, composition relations, or enabler reasoning. There is no post-transform field-diff/data-loss veto. The implementation comment also says the partition key includes severity tier, while `_partition_into_subclusters()` actually keys only `(file, function)`, demonstrating executable-contract/documentation drift. If violations persist after one retry, the driver proceeds and relies on per-constituent demotion limiting; that does not prevent one grouped confirmation, one missed member, or one report body from collapsing distinct mechanisms.

Live end-to-end reproduction: chain attempt 1 completed successfully at the PTY boundary, after which the driver mechanically split five constituents from two groups but still detected eight over-merged hypothesis groups. Immediately before the repair, the live files were approximately 39.7KB (`hypotheses.md`) and 17.3KB (`finding_mapping.md`). The quarantined post-repair projections are only 20,016 and 6,080 bytes respectively. The driver then quarantined all three chain outputs, including the unchanged 37,335-byte `enabler_results.md`, and launched attempt 2. `anti_absorption_repair.md` records only old/new IDs, source finding, and a locus-based reason; it contains no receipt proving preservation of the removed semantic fields. This confirms that the risk is active in the legacy-Claude end-to-end path, not just reachable code.

Fix contract:

- Chain grouping is an additive composition relation, not destructive identity consolidation. Every base finding remains an independently addressable claim and verification obligation unless an applied typed equivalence decision proves same mechanism, preconditions, effect, impact, and remediation scope.
- Exact locus, lexical similarity, common title, or nearby severity is candidate-generation evidence only; none is sufficient equivalence authority. Same-function distinct bugs remain separable, while cross-function true equivalents may be grouped only with explicit typed proof.
- A chain worker may propose an override but cannot authorize its own anti-absorption exception. An independent deterministic/arbiter decision records the exact equivalence dimensions and members.
- Repair patches only affected relation records. It never regenerates whole semantic artifacts from a reduced parser projection. A field-aware pre/post diff over every affected claim is mandatory; any lost field vetoes the transform and keeps members separate.
- Persistent ambiguity uses conservative split/independent member verification and a visible unresolved grouping debt, not warning-only completion.
- Verification and reporting consume alias-preserving group cards. Evidence must bind per member; composition evidence is additional and cannot silently replace base-claim proof.
- The applied receipt records input/output hashes, accepted/rejected group decisions, preserved field sets, member-to-work-unit mapping, and idempotent resume state.

Required fixtures: same function with two distinct state transitions; same line with different preconditions/impacts; cross-function same mechanism/fix; lexical paraphrases at one locus; same mechanism with different remediation; explicit self-authored override; split one of several groups without changing unaffected bytes/records; unique chain narrative/invariant/evidence survives; malformed location; missing root cause; multi-member partial proof; persistent ambiguity; code/comment partition-key parity; resume idempotency and exact pre/post field diff.

### P0-X. A producer-authored inventory verdict can exclude its own candidate before independent verification

Code evidence: `_queue_rows_from_inventory_with_exclusions()` reads `Verdict`/`Final Verdict`/`Status` from every inventory block. If `_verifier_status_from_text()` resolves the inventory producer's prose to a non-reportable status (`REFUTED`, `FALSE_POSITIVE`, `INFEASIBLE`, `DUPLICATE`, `APPENDIX_ONLY`, and related tokens), the row is removed from the active verification queue and written directly to `verification_queue_evidence_excluded.md`. Queue parity then treats that exclusion route as accounted. This applies the verifier's status parser to a pre-verification producer artifact and lets the generator dispose of its own output. Some promotion bridges defensively rewrite producer negatives to `NEEDS_VERIFICATION`—the live niche bridge did so for `SGI-3` and `SGI-4`—but that is feeder-specific protection, not a universal lifecycle invariant.

Fix contract:

- A discovery/depth/inventory verdict is a producer assessment only. Once a concrete candidate identity exists, it routes to an independent discriminator or a typed, independently authorized negative disposition; producer prose alone never enters the excluded route.
- The active producer registry records each candidate's origin assessment separately from discriminator state. Queue generation consumes discriminator state, not a generic `Verdict` field parsed from arbitrary Markdown.
- A deterministic exclusion is permitted only for exact mechanical scope facts (for example, a source path proven outside the bound production scope) and remains a typed scope decision with evidence, not a vulnerability refutation.
- To control cost, producer-negative candidates may use bounded batched blind discrimination, but Thorough mode cannot silently skip them. Discriminator unavailable -> unresolved/human-review visibility at upstream severity.
- Every feeder, including legacy/fallback/recovery sources, shares the same contract; no feeder-specific `NEEDS_VERIFICATION` rewrite is relied upon for safety.

Required fixtures: inventory `REFUTED` with no independent decision -> active discriminator work; producer `DUPLICATE` without applied alias -> active; exact applied alias -> authorized consolidation; verified false positive -> excluded; deterministic out-of-scope file -> typed scope exclusion; malformed verdict; negative producer through each feeder family; discriminator unavailable; resume idempotency; active+excluded identity partition uses authorized decisions only.

### P0-Y. Citation/identifier quality is used as finding validity, and the decision loses identity across hypothesis relabeling

Code/live evidence: `_filter_verification_queue_by_evidence()` removes Low/Informational rows on `IDENTIFIER_UNVERIFIED` alone and removes any tier when both location and provenance are bad. A wrong or parser-inferred identifier is evidence that the citation needs repair, not evidence that the mechanism is false. In the canary, `inventory_evidence_validation.md` marks `INV-025` `IDENTIFIER_UNVERIFIED` because it inferred the ordinary title word `argument` as a code identifier not found in the source index. `INV-025` is a content-bearing Low candidate with two source IDs (`AC-2`, `CC-02`) and concrete source locations. Separately, SC queue generation performs `_dedup_queue_by_hypothesis()` **before** the evidence filter, relabeling `INV-025` to `H-19`; the filter looks up validation records by the queue ID, so the `INV-025` decision may be bypassed after relabeling. The same policy can therefore falsely exclude a standalone candidate yet fail open for an equivalent grouped candidate solely because its display ID changed.

Fix contract:

- Separate `location_quality`, `source_provenance_quality`, `scope_state`, and `claim_disposition`. Citation defects create location-repair/verification obligations; they cannot establish falsehood or non-reportability.
- Only an exact, snapshot-bound scope predicate may authorize scope exclusion. Inferred identifier absence, unparseable prose, or a stale line is never sufficient.
- Bind evidence-validation records to stable candidate identity and lineage. Hypothesis/chain aliases carry member identities; consumers aggregate per-member state conservatively and cannot lose or bypass a decision on display-ID relabeling.
- Run deterministic location recovery before verification. If recovery fails, verify the mechanism using the source lineage and flag location unresolved; do not delete the claim.
- Queue parity distinguishes routed-to-verification, authorized-scope-excluded, and unresolved-location debt. An appendix ledger is observability, not proof of a valid disposition.

Required fixtures: title contains ordinary word parsed as identifier; valid source ID plus bad line; bad source ID plus valid location; both unresolved but mechanism recoverable; exact non-production path; `INV` -> `H` relabel; multi-member group with one valid/one invalid location; absorbed alias; non-EVM symbol formats; malformed validation row; location repair succeeds/fails; resume and alias-map idempotency.

### P0-Z. Resume validates output shape, not semantic dependency freshness

Code evidence: `_reconcile_completed_checkpoint_artifacts()` enforces prefix closure and reruns each completed phase's current artifact/gate checks. It does not bind a completed phase to hashes of the semantic inputs it consumed. A downstream artifact can remain parseable and satisfy its byte/shape validator after an upstream repair, alias-map change, queue change, decision-ledger update, or generator promotion changed its meaning. The code has several targeted rewinds/refreshes (overflow healing, dynamic report-manifest refresh, verify-queue backfill), but each is a hand-coded exception. P0-N is one concrete failure caused by that model: avoiding a broad rewind won over verifying newly discovered work. The new P0-Q/S/W repairs would create the same risk unless they explicitly invalidate every affected consumer.

Fix contract:

- Introduce driver-owned semantic completion receipts at critical drift boundaries, not a full database migration. A receipt records stage/work-unit identity, graph/schema version, method/snapshot identity, exact input artifact hashes or canonical record-set digest, output hashes, terminal state, and unresolved/degraded debt.
- Resume recomputes the input digest before honoring completion. A changed input invalidates that stage and only its semantic descendants; unchanged independent shards remain complete.
- Any repair or late promotion emits a mutation event naming affected record identities and atomically invalidates/rebuilds the relevant aggregate, skeptic/cross-batch, index, tier, dedup/floor, and report projections.
- Mutable Markdown projections are never used as both input authority and completion receipt. Canonical typed sidecars/receipts are dual-written first; existing recovery paths remain until parity is proven.
- Hash equality is necessary but not sufficient: schema/denominator/identity-set parity must also match, preventing a stale valid-looking subset from passing.
- Haltless behavior remains: if a required descendant cannot rerun, retain the new/changed identity as report-visible unresolved work and mark the assurance limitation; do not bless stale output.

Required fixtures: upstream content changes with same filename/size and still-valid Markdown; one member added/removed; alias map changes without count change; severity decision changes; methodology/schema version changes; independent shard unchanged; aggregate invalidated; late finding after verify; report disposition after report body; repair crash between mutation and invalidation; resume twice; no-change resume runs zero LLM work.

### P0-AA. Report-index dropout recovery converts missing work into an internal `DEFERRED` acknowledgement

Code evidence: `_report_index_dropped_ids()` defines indexed coverage as the union of Master Index, Excluded Findings, consolidation aliases, and any acknowledged `report_coverage.md` status. `_backfill_report_coverage_dropouts()` then appends every still-missing reference ID as `DEFERRED` specifically "so the completeness gate passes." `_collect_report_coverage_acknowledged_ids()` accepts that token. The repair does not require an independent disposition, does not re-queue the candidate to verification or index adjudication, and does not assign it to a report body or Appendix A.

The later human-review projection does not close this path. `_build_human_review_appendix()` consumes `report_semantic_*.md`, chain coverage gaps, and depth-finalization debt, not arbitrary `report_coverage.md` dropout rows. The semantic-risk validator only projects selected Medium+ rows with extracted facets; the mechanical backfill writes severity `unknown`, so a recovered dropout can satisfy cardinality accounting while remaining absent from the delivered report. This is a concrete instance of found-then-lost, not merely weak observability.

Fix contract:

- A mechanical repair may restore identity and schedule work, but may not author a terminal semantic disposition.
- Backfilled IDs enter a typed `UNRESOLVED_PIPELINE_DROPOUT` state that is non-terminal for completeness: re-run the missing independent discriminator/index work when possible, otherwise retain the candidate in a delivered human-review appendix with its best upstream severity, title, location, and evidence pointers.
- `DEFERRED` is valid only when backed by a typed, authorized decision naming actor/phase, reason class, evidence basis, next action, and public retention target. A bare lexical status is not authorization.
- Completeness has separate predicates for identity accounting, independent disposition, and delivered projection. Passing one cannot satisfy the others.
- The recovery remains haltless: if the semantic worker cannot run, deliver the unresolved item and assurance limitation; never bless the missing decision.

Required fixtures: verified ID absent from index; seed-only ID without verify output; Medium+ and Low dropouts; unknown-severity legacy row with upstream severity available; dropout after report assembly; mechanical backfill followed by resume; authorized deferral; unauthorized bare `DEFERRED`; human-review projection failure; report contains an actionable opaque/public reference; no duplicate body section after successful retry; repeated recovery is idempotent.

### P0-AB. Chain state-composition coverage is silently zeroed by producer/parser schema drift

Live reproduction: `state_write_map.md` is mechanically populated with 29 qualified state symbols in the actual two-column schema `State Variable | Writers`. `_parse_state_write_map()` documents and expects contract-scoped headings plus a different four-column schema; it retains keys such as `Contract.symbol` rather than a canonical symbol identity plus bare alias. `_parse_state_variable_inventory()` finds zero keys because the later recon artifact no longer contains its expected canonical `File | Variable` table. Across 188 parsed inventory findings, `_finding_state_vars()` therefore resolves exactly zero finding-to-state edges, even though the inventory contains many direct bare references to those state variables. The live chain preparation result is `STATE=0`, `TYPE=7,614`, variable-map rows `0`, and enabler baseline states `24`. The phase reports `status=ok` and proceeds.

This is both a recall and bloat defect: shared-state composition—the strongest declared chain signal—does not run, while identifier/proximity overlap creates thousands of lower-specificity pairs. The 70-pair bounded packet and 15-pair tail packet can then be crowded by the wrong signal family, leaving 7,529 rows as coverage gaps. The fallback instruction to use grep is model-optional and cannot prove enumeration.

Fix contract:

- Make the already-emitted `_mechanical_graph.json` the chain-prep authority and complete its ecosystem-neutral state-symbol records where needed: stable symbol ID, qualified name, bare aliases, declaration locus, read/write sites, and graph confidence. Markdown tables remain compatibility projections, not the primary parsing authority.
- Until cutover, the compatibility parser accepts and tests every driver-produced legacy schema, including global qualified two-column and contract-scoped multi-column forms. It normalizes qualified/bare aliases without conflating same-named symbols from different contracts/modules.
- Bind findings to state through exact cited-location AST/reference-graph edges first; bounded, word-boundary prose aliases are a lower-confidence additive fallback. A qualified producer symbol must match its own bare spelling when unambiguous.
- Chain preparation writes an exact resolution receipt: input symbol count, finding count, graph/prose edge counts, unresolved symbols/findings, per-schema counts, and signal-family pair counts. A populated graph plus zero resolved edges is `DEGRADED_GRAPH_APPLICATION`, not `ok`, unless a deterministic negative proof establishes that no finding touches any state.
- Preserve separate quotas and complete tail dispositions by signal class so type/proximity volume cannot displace state pairs. P0-T governs unresolved tail closure.
- Recon narrative cannot overwrite the authoritative mechanical state inventory. It writes a separate projection/annotation artifact or a typed merge with denominator parity.

Required fixtures: direct producer→consumer contract tests using the real Slither and SCIP projection writers (not a test-only third schema); actual global two-column qualified schema; documented contract-scoped legacy schema; qualified and bare aliases; same bare symbol in two contracts; constructor-only immutable; read-only state reference; cited-location graph edge without prose mention; prose fallback without graph edge; populated graph with zero legitimate touches; populated graph with zero due parser drift; overwritten narrative projection; partial AST availability; EVM, Rust/Solana/Soroban, Move/Aptos/Sui, and Go symbol forms; state-pair quota under 10,000 type pairs; exact unresolved receipt; resume idempotency and schema-version invalidation.

### P0-AC. FC4 converts failed semantic, identity, and methodology-application gates into successful completion

Live reproduction: `_phase_content_gate_issues()` is explicitly a presence/shape-only resume check. `_fc4_autocomplete_if_content_valid()` nevertheless applies it after **every** critical degrade branch, then clears the retry hint, deletes retry-quarantine backups, removes the degraded phase/sentinel, and marks the phase completed. The frozen Claude canary reproduced this twice in unrelated domains. Recon failed its selected-skill/BINDING-MANIFEST semantic gate on every attempt, but FC4 marked recon complete because its Markdown files were non-empty. Later, chain attempt 2 re-minted 29 existing `H-*` IDs with different content; the ID-ledger gate correctly failed, but FC4 again erased the failure and advanced to `chain_agent2`. The checkpoint consequently records both phases as completed with an empty degraded set. This is a direct mechanism for both observed miss classes: methodology can fail to apply without a durable debt, and found identities can change or disappear while downstream consumers are told the producer succeeded.

The retry behavior makes the defect harder to diagnose. Recon attempts 2 and 3 completed in approximately one second because already-complete worker shards were not invalidated, so the failed producer was never actually repaired. FC4 then deleted the quarantine directory that could have established before/after lineage. A haltless policy does not require declaring a failed predicate true or destroying its evidence.

The report-stage run reproduced a second retry-compiler failure without FC4. `report_dedup_agent` received a 937,456-byte assembled report whose human-review appendix was dominated by 7,546 chain-debt rows. Attempt 1 remained in the Claude PTY for the full 900-second timeout and emitted no `report_dedup_agent_decisions.md`; the driver immediately launched a whole-phase retry. The attempt-2 prompt is only 4,435 bytes and identifies the missing filename plus a >=100-byte disk contract. It says to read the original 23,385-byte methodology prompt only if the filename error is not recognized, and it does not carry the candidate-pair denominator, required semantic decision schema, report digest, or proof that the enormous report was examined. A retry can therefore turn “no semantic work completed” into a gate-passing file by satisfying presence alone, while repeating the expensive input when the model does consult the original prompt. This is a deterministic methodology-non-application mechanism created by prompt compilation, not model laziness.

The same false-clean transition is not limited to FC4. `chain_iter2` produced a typed receipt with `status=DEGRADED_COVERAGE_GAPS`, zero of fifteen packet pairs mechanically consumed, and 7,529 overflow pairs. Its soft validator writes a degraded sentinel but returns an empty issue list; the generic success path then clears that sentinel and marks the phase clean. The live checkpoint and scratchpad retain neither degraded state nor sentinel. Completion/debt semantics therefore need one shared state machine across critical and soft phases, not a local FC4 patch.

Static control-flow inventory confirms why a local patch is insufficient: `plamen_driver.py` currently contains 43 direct `checkpoint.mark_completed(...)` calls, 45 direct degraded-sentinel clears, and 23 direct degraded-list appends, distributed across model phases, Python-native fast paths, conditional skips, repair branches, and report expansion. FC4 itself has only two live call sites plus its definition. The fix must collapse these independent authorities behind one commit controller; otherwise removing FC4 leaves dozens of structurally equivalent false-clean opportunities.

Fix contract:

- Give every gate a stable ID and typed class: artifact presence, schema, semantic identity/lineage, methodology selection, methodology application, evidence integrity, independent disposition, delivered projection, containment, or advisory quality. A validator returns structured failed predicates and affected identities, not an undifferentiated string list.
- A fallback may discharge only the exact predicate class it proves. Content presence can never supersede identity collision, selection/application parity, evidence integrity, containment, or disposition/delivery failures. Remove the generic "content-valid => completed" implication.
- Preserve haltless execution as `COMPLETED_WITH_DEBT`/`DEGRADED_WITH_OUTPUT`, with the exact failed gate, affected identities, retry history, before/after hashes, and permitted downstream fallback. Debt persists through checkpoint, resume, verification, report index, and the delivered assurance-limitations/human-review projection until the same gate or an explicitly authorized stronger gate clears it.
- Some outputs are unsafe as semantic authority even when the pipeline continues. An unresolved ID collision must retain both immutable versions/lineages and route an unresolved identity family to repair or human review; downstream may not silently consume the later redefinition as canonical. A missing skill manifest may use a mechanically reconstructed typed manifest, but may not be treated as proof of application.
- Retry only the producer/work unit capable of changing the failed predicate. Record its semantic input/output digest and require observable predicate progress before consuming another model attempt. A zero-work retry is recorded once and transitions to visible debt rather than looping or self-clearing.
- Retain quarantine and retry receipts until the phase's original failed gates pass and all affected descendant projections are rebuilt. Cleanup is transactional and cannot run merely because replacement files exist.
- Resume re-evaluates the original gate IDs against the recorded inputs. It cannot use the weaker generic content contract to bless a previously semantic-degraded phase.

Required fixtures: non-empty recon files plus failed skill-selection parity; non-empty chain files plus one and 29 ID collisions; malformed-but-large report plus failed disposition; genuine presence-only failure repaired; advisory-quality failure with explicitly allowed fallback; zero-work retry; targeted retry changes predicate; retry writes replacement but semantic gate still fails; timeout before any semantic decision followed by a filename-only retry; retry prompt carries the exact failed semantic predicates, denominator, schema, and input digest; >=100-byte placeholder cannot clear semantic work; crash before/after debt commit; quarantine retention/cleanup; `COMPLETED_WITH_DEBT` propagation into verification and final report; same-gate clearance; attempted cross-class clearance; resume twice; checkpoint degraded/debt parity; every critical phase enumerated through the shared branch; no-halt continuation without false completion.

### P0-AD. Recon skill selection loses polarity and schema authority, selecting explicit `NO`/`N/A` rows as required work

Live reproduction: the canary's `template_recommendations.md` contains the recommendation matrix twice. Each copy has exactly three `YES` selections, thirty `NO` rows, and three `N/A` rows; it contains no `## BINDING MANIFEST`. `_prose_required_skill_tokens()` enters the broadly named recommendation section with `positive_context=True`, extracts every installed skill token from each row, and only suppresses a row if a prose negative regex matches. That regex does not understand the table's `NO` or `N/A (...)` cell. The first gate failure falsely selected nine negative/niche rows; the retry artifact expanded the false selection to 34 skills, including the three true positives and the explicitly rejected rows. `_rewrite_required_skill_rows()` can only modify an exact `## BINDING MANIFEST`, so reconciliation is a no-op when the producer emits the schema it was actually prompted to write. `_selected_skill_manifest_issues()` then asks the same producer to invent the absent canonical rows; already-complete shards do no work, and P0-AC erases the failure. This creates both bloat (dozens of irrelevant skills) and non-application ambiguity (the three real selections still lack a durable consumer contract).

Fix contract:

- Replace recommendation-section inference with a driver-owned typed selection record keyed by canonical skill ID and ecosystem. Its state is an enum such as `REQUIRED`, `NOT_REQUIRED`, `DEFERRED_TRIGGER`, `ALWAYS_ON_CONSUMER`, or `UNKNOWN`; rationale/evidence facts and selecting authority are separate fields. Markdown is a projection.
- Parse legacy tables by headers and exact cells. `YES` is positive; `NO`, `N/A`, `NOT SET`, `SKIP`, and their documented aliases are negative/deferred states, never overridden by a positive section title. Free-form prose can add an unresolved recommendation obligation but cannot silently flip an explicit structured negative.
- Build the canonical catalog rows mechanically for the active ecosystem before recon. Recon may update evidence/state for existing IDs; it cannot be required to recreate the schema or choose a cross-ecosystem location. Unknown and wrong-ecosystem IDs remain loud, typed debts.
- Keep selection, assignment, application, and outcome as separate receipts. A correct `REQUIRED` row is not application proof; P0-A closes the selected-skill-to-consumer graph and P0-B/C close unsupported outcome clears.
- Reconcile duplicate/addendum projections by stable skill identity and explicit precedence, emitting a conflict when states differ. Do not union all positive-looking prose. A syntactically valid structured signal is authoritative only for its declared producer/snapshot and remains subject to catalog/ecosystem validation.
- A repair reruns or mechanically rebuilds only the selection manifest. It must demonstrate an exact state-set change or stop with persistent debt; it must not rerun four unrelated recon workers or append another full duplicate matrix.

Required fixtures: three `YES` plus thirty `NO` plus three `N/A` rows yields exactly three required skills; bold and plain cells; `NOT SET`, `not applicable`, `skip`, and unknown values; duplicated identical matrix; duplicated conflicting matrix; missing BINDING MANIFEST; legacy BINDING MANIFEST; structured empty `required_skills`; positive prose without a row; negative prose after positive heading; wrong-ecosystem skill; unknown skill; catalog row reconstruction; one true selection delivered to breadth/depth/niche consumers; zero-work retry; retry addendum without duplication; resume idempotency; all supported ecosystems and Windows/Linux newline/encoding forms.

### P0-AE. Rendered phase prompts, artifact ownership, containment, and gates do not share one I/O contract

Live rendered-prompt evidence: `chain_agent2`'s generated **HARD** output contract says its only writable files are `chain_hypotheses.md`, `composition_coverage.md`, and `synthesis_full.md`; the phase-isolation block says every prior-phase artifact is read-only and any conflicting methodology instruction must be ignored. The inherited chain methodology later orders the same process to update `hypotheses.md`, and the final SCOPE line creates an ad hoc exception for that update. `_owned_artifact_patterns()` assigns `hypotheses.md` exclusively to the preceding `chain` phase, not `chain_agent2`. Because foreign-write containment is derived from **future** phase ownership, mutation of this prior-phase artifact is not a live containment violation; it instead changes a previous owner's content behind its recorded hash. The model must therefore choose between two hard directives: ignore a methodology application step or perform an unowned, semantically stale cross-phase mutation.

Live outcome: the model chose the second branch. `chain_agent2` completed after writing its three owned outputs and then modified the prior phase's `hypotheses.md` at 16:47:54. The checkpoint still records both phases as cleanly completed and no degradation, despite the previous owner's artifact changing after its gate and hash boundary. This converts the prompt contradiction into a reproduced stale-completion/resume defect: the methodology step was applied, but outside the architecture's ownership and invalidation model.

The next live phase reproduced the same split in the opposite direction. `chain_iter2`'s generated HARD contract, isolation block, direct-execution policy, resumption protocol, and `Phase.expected_artifacts` all name only `chain_iteration2.md`; its phase methodology and final SCOPE order writes to three files, including prior `chain_hypotheses.md` and `composition_coverage.md`. `_owned_artifact_patterns()` separately treats those two prior artifacts as intentional shared ownership. Claude followed the methodology and modified `composition_coverage.md`; no containment or invalidation event occurred. The architecture therefore has three mutually inconsistent answers for what the phase owns, and whichever instruction the model follows can violate another subsystem's contract.

The same contract split appears in smaller form elsewhere: the attention-repair hard contract requires only `attention_repair_summary.md`, while its final SCOPE permits `attention_repair_findings.md`. Required outputs, optional outputs, shared append targets, containment, resumption, and the inherited Markdown methodology are separate hand-maintained lists. This is a structural source of the reported "methodology existed but was not applied" failures; prompt strength cannot resolve contradictory machine-generated authorities.

The frozen verifier prompt adds a non-I/O example of the same compiler drift: its hard cost override says the phase model is Sonnet and forbids requesting Opus, while the actual Claude subprocess was launched as `claude-opus-4-8` by Thorough-mode `phase_model()`. The L1 override also says every shard is currently Sonnet even though the resolver now explicitly promotes Thorough L1 verifier shards to Opus. The executable model wins, so this did not downgrade the running process, but it proves prompts and runtime policy are independently authored. Model/backend/mode facts in a rendered prompt must be derived from the same resolved launch specification as the command, not stale prose.

The embedded methodology-application boundary reproduces the ownership split for driver/child outputs. It runs a conditional repair subprocess inside the accepted breadth/rescan/depth transaction, then writes application receipts, skeptic queues, and report-semantic debt before the parent phase is checkpointed. In the live artifact ledger, `analysis_methodology_repair_breadth.md` and `depth_methodology_repair_findings.md` happen to acquire their parent owners through broad `analysis_*`/`depth_*` globs; `analysis_methodology_repair_rescan.md` has no owner record because it misses rescan's narrower ownership pattern. The application receipt, skeptic queue, and report-semantic projection are also unowned. Semantically identical child transactions therefore have different provenance solely because their filenames collide with different glob widths.

An all-73-phase SC prompt/ownership scan found further candidates, then the frozen execution path separated real defects from dead/generic prompt noise. The actual recon run produced `meta_buffer.md` and `external_dependency_research.md`, but neither has any `_artifact_state.json` owner record. The driver-produced `rescan_manifest.md` is likewise present and unowned. Two actual depth worker prompts assigned `niche_semantic_gap_findings.md` and `validation_sweep_findings.md`; the workers produced substantive 45,185-byte and 37,311-byte artifacts, yet both are absent from the ownership ledger because `_owned_artifact_patterns()` omits their exact names. By contrast, several static-scan hits were merely read references or generic coordinator text not used by the worker-pool launch path. This distinction is load-bearing: the compiled-contract linter must analyze the exact dispatched prompt and resolved dynamic contract for each subprocess/Python-native phase, not an unused generic phase rendering and not every `.md` mention.

The same scan exposes the next live checkpoint to watch: `post_verify_extract` is owned only for `post_verify_extract.md`, while its standalone method explicitly orders the model to append new records to prior-phase `hypotheses.md`. Before that phase, the frozen `hypotheses.md` is 35,637 bytes with SHA-256 `B9DB777B0B31A47B4FF6F0BAACABAE813B5F0D74A2BE6A35FC76D4E24C249C28` and currently has no active owner record at all. This is code/prompt evidence only until phase 5.5 executes; the observer will classify the eventual outcome rather than assume mutation.

The downstream observation strengthens the defect while separating two cases. `post_verify_extract` completed with an explicit no-new-candidate result, so it wrote only its owned 839-byte `post_verify_extract.md`; `hypotheses.md` retained the exact pre-phase SHA-256 above. Thus this run did not exercise the contradictory append branch, and no mutation claim is made for that phase. In contrast, the two immediately preceding Python-native boundaries did mutate prior verifier outputs. From the Low-J cutoff to `sc_verify_aggregate`, 29 of 174 `verify_*.md` files changed content; from aggregate to `sc_mechanical_verify`, another 145 changed, so the union is all 174 verifier files. The mechanical log independently reports `annotated=174`. Receipt comparison found no verdict, authored-severity, or evidence-tag changes across those rewrites, while aggregate added one `[UNPROVEN-EXTERNAL]` stamp; the point here is ownership and freshness, not whether those annotations were substantively correct. `_artifact_state.json` still assigns all 174 files to seventeen earlier verifier phases, assigns none to `sc_mechanical_verify`, and all 174 recorded hashes are now stale, yet the checkpoint records aggregate and mechanical verification cleanly with no degradation. Therefore the split contract is not only prompt-side: driver-native postprocessors can rewrite every prior decision artifact without an ownership transfer, descendant invalidation, or refreshed producer state.

The subsequent `crossbatch` phase demonstrates the complementary unknown-output blind spot. Its hard contract declares `cross_batch_consistency.md`, but the live Sonnet process also created three scratchpad helper files (`non_inv_findings.txt`, `ledger_full.txt`, and `ledger_rows.txt`). They remain absent from `_artifact_state.json`; containment did not quarantine or flag them because it is primarily future-phase-pattern based rather than an exact current-phase write-set check. The phase then completed cleanly despite a separate two-reference ID-ledger warning. These helpers are not themselves recall findings, but their unobserved creation proves that “not owned by a future phase” is currently treated as writable, contradicting the prompt's exact-output claim and preventing complete provenance or cleanup guarantees.

The `report_index` prework reproduces the same ownership gap for deterministic Python outputs rather than model-created helpers. Before the report-index model launched, the driver wrote `severity_binding.md`, `status_binding.md`, `report_index_coverage_seed.md`, `candidate_semantic_facets.md`, and `external_research_gaps.md`. All five are live inputs to report construction, but none has an `_artifact_state.json` owner or stored hash. `report_records.json` and the four JSON files under `body_manifests/` were then generated as driver-owned routing authorities between index and tier writers and are likewise absent from the artifact ledger. The model-authored `report_index.md` and `report_coverage.md` are owned and hashed, so the present ledger covers the prose projection while omitting the deterministic semantic inputs and projections that actually drive the next launches. A clean checkpoint therefore cannot establish report-stage dependency freshness even before a downstream mutation occurs.

Fix contract:

- Define one typed `PhaseIOContract` per phase with required outputs, optional outputs, driver-generated outputs, immutable inputs, bounded lookup inputs, and explicitly shared mutable projections. Each output declares owner, schema/version, write mode (`CREATE`, `REPLACE`, `APPEND`, `MERGE`), minimum semantic gate, and downstream consumers.
- Generate the prompt's expected-output block, phase-isolation block, resumption instructions, PTY file monitoring, ownership ledger, containment rules, retry quarantine, artifact gate, and semantic completion receipt from that same object. No second filename list may override it in prose.
- Compile/lint every exact dispatch prompt before launch. Reject or deterministically rewrite any imperative write/update/append directive whose target or mode is absent from the resolved I/O contract, any required contract output omitted by the methodology, and any contradictory read-only/write instruction. The linter consumes worker-pool manifests/dynamic verifier rows and knows when a phase is Python-native; it must not lint an unused generic coordinator rendering as if it were launched. Run this for Claude and Codex renderings, every ecosystem/mode, retry/repair prompts, worker rows, and Python-native bypass receipts.
- Prefer immutable phase outputs and explicit downstream unions over cross-phase mutation. For this case, `chain_hypotheses.md` should be the authoritative Agent-2 addition and verification/report consumers should read the typed union; remove the instruction to rewrite `hypotheses.md`. Where shared mutation is truly required, use a driver-owned merge event with before/after hashes, identity parity, and P0-Z descendant invalidation rather than letting an LLM edit a prior owner's file.
- Optional recall-bearing outputs are never merely allowlisted. Their trigger, expected denominator, produced identities, and downstream disposition are captured in a conditional output receipt; `not triggered`, `triggered and empty`, `produced`, and `failed` are distinct.
- A phase cannot complete if its rendered prompt failed the contract linter. Haltless behavior may use a driver-authored safe prompt projection, but it must retain the compile defect as assurance debt instead of running contradictory instructions.
- Treat resolved backend, model, mode, pipeline, ecosystem, timeout, and tool policy as typed prompt-compilation inputs. Render them from the exact launch specification and hash that specification into the dispatch receipt; no template may hard-code a model alias that disagrees with the executable command.

Required fixtures: `chain_agent2` prior-output update contradiction; `post_verify_extract` append to `hypotheses.md`; recon auxiliary outputs; rescan-prepare driver manifest; depth niche-semantic-gap and validation-sweep worker outputs; attention-repair optional finding output; invariant append mode; report phases that may mutate `AUDIT_REPORT.md`; dynamic verifier shards; worker-pool parent versus actual worker outputs; unused generic coordinator rendering must not create a false failure; Python-native phase must carry a no-model dispatch receipt; methodology-application breadth/rescan/depth child repairs with identical typed ownership; driver-generated application receipt/skeptic/debt outputs; retry/repair prompts; glob and exact files; Windows absolute and POSIX paths; duplicate basenames; conditional non-trigger; prompt references in explanatory/read-only text versus write imperatives; inherited methodology adds/removes an output; ownership hash after an authorized merge; unauthorized prior/future mutation; Thorough SC/L1 resolved Opus command versus stale Sonnet prose; Light/Core and explicit model override; backend fallback; timeout/tool-policy parity; all SC/L1 phases, modes, ecosystems, and both Claude/Codex renderers.

Implementation topology for P0-AC/P0-AE (the architectural acceptance shape, not an optional refactor):

- Add immutable typed records for `ArtifactSpec`, `PhaseIOContract`, `LaunchSpec`, `GateFailure`, `RetryReceipt`, and `PhaseCommit`. A resolved contract is keyed by `(pipeline, mode, ecosystem, backend, phase, work_unit_id)` so worker-pool children, dynamically planned verifier units, retry/repair children, and Python-native phases cannot inherit a vague parent-only contract.
- `ArtifactSpec` carries exact/glob identity, required/optional/conditional class, owner, schema/version, write mode (`CREATE`, `REPLACE`, `APPEND`, or driver-owned `MERGE`), minimum gate, and consumer set. Prior materialized outputs are immutable by default. A shared projection is mutable only through a driver merge event with before/after hashes and identity reconciliation.
- `GateFailure` carries stable gate ID/class, affected identities, input/output/contract digests, evidence paths, repair owner, and allowed fallback. Clearance is an explicit event referencing the original failure and requires the same gate ID or a registered stronger gate in the same semantic domain. Presence/shape can never clear identity, application, evidence, containment, disposition, or delivery debt.
- `PhaseCommit.state` is one of `CLEAN`, `COMPLETED_WITH_DEBT`, or `DEGRADED_WITH_OUTPUT`; it embeds the resolved contract/launch digests and unresolved failure IDs. The legacy checkpoint `completed`/`degraded` arrays become backward-compatible projections of these commits, not independent authorities. `CLEAN` is mechanically impossible while any non-advisory failed gate remains unresolved.
- Route every completion path--including Python-native fast paths, zero-work placeholders, conditional skips, worker-pool parents, rate-limit recovery, critical repair, and soft validators--through one `PhaseCommitController`. Remove direct `mark_completed`/sentinel-clear pairs from phase branches. Add a structural test that rejects new direct completion/debt writes outside the controller and checkpoint migration code.
- Remove `_fc4_autocomplete_if_content_valid()` rather than weakening it. The controller may commit a content-bearing phase with semantic debt and continue haltlessly, but it cannot rewrite the failed predicate to success, delete quarantine, or mark the commit clean. Import legacy `.degraded` files into typed debt on resume; never bulk-delete them before reconciliation.
- Retry transactions record the exact producer/work unit, semantic input/output hashes, failed predicate set before and after, and quarantine lineage. A retry that changes no relevant digest is recorded once as `NO_PROGRESS` and transitions to durable debt. Quarantine cleanup is permitted only after the original gate IDs clear and affected descendant commits are invalidated/rebuilt.
- Compile the exact dispatched prompt from the resolved I/O and launch contracts. The same object drives model-facing output rules, PTY monitoring, containment, retry quarantine, artifact-state ownership, and completion gates. Persist a dispatch receipt even for Python-native phases (`model_invoked=false`) so the all-phase matrix is mechanically enumerable.
- Replace direct cross-phase LLM mutation with immutable deltas: `chain_agent2` owns its additions; `chain_iter2` owns an iteration delta; `post_verify_extract` owns late candidate proposals. Driver-owned typed unions feed later consumers. No LLM subprocess edits `hypotheses.md` or another prior owner's artifact.
- The first red suite must prove the two live FC4 failures and the soft-chain false-clean transition. The final structural suite must enumerate every active SC/L1 phase across modes/backends, demonstrate that no phase can bypass the controller, and prove resume preserves debt and performs zero model launches when every semantic dependency digest is unchanged.

### P0-AF. Genuine compound chain findings bypass compound verification and may borrow constituent proof

Code evidence: `chain_agent2` runs after inventory/dedup and emits new `CH-*` compound claims. `_write_mechanical_verification_queue_from_inventory()` writes the queue exclusively from `findings_inventory.md`; no producer promotes justified `CH-*` claims into that inventory or queue. `_forced_chain_seed_rows()` has only downstream uses: it force-adds justified High/Critical chains to the **report-index coverage seed** and renders a deferred note when it considers them unqueueable. Its docstring says the helper prevents a chain from missing the "verify queue / coverage seed," but it does not write the verify queue. Report construction then explicitly skips `verify_CH-*` and treats constituent verifier files as the canonical evidence for a chain; the report-index repair guidance likewise permits `H-a+H-b` when only constituent verifiers exist. Existing tests prove a justified chain stays separate **if a test manually places a CH row into the queue**, but do not test the real chain-producer→queue contract.

Live downstream outcome: Agent 2 emitted `CH-01` and `CH-02`, including an external-gated low-confidence chain whose artifact explicitly requires mandatory verification. The mechanical SC queue then materialized 174 active rows across 30 shards and zero excluded rows, but contained no `CH-*` identity. Neither compound claim reached a verifier work item. This proves the producer-to-queue gap on the legacy Claude path before report construction can obscure it.

Live report-construction outcome: both compound identities nevertheless entered `report_index.md` as separate High report rows. `_build_sc_body_writer_manifests()` then followed its explicit constituent-substitution branch: each compound manifest row named multiple existing constituent verifier files, and `report_records.json` replaced the compound `finding_id` with the first constituent verifier identity. That produced two identity collisions in the 61 active records--the same constituent identity appeared once as its own Medium report finding and again as the proof identity for a High compound report--while the `CH-*` identities disappeared from the active record set. The resulting records also inherit the first constituent's verdict rather than representing a composition verdict. Separately, one chain-enabler report row had no verifier file at all; the manifest correctly marked it blocked, but the record builder's `verdict or "CONFIRMED"` fallback serialized it as `CONFIRMED`. This is process evidence, not a judgment about the substantive claims: it proves that report routing can manufacture a positive record and can erase the identity/proof-scope boundary that independent compound verification is supposed to enforce.

Additional live-regression fixtures must assert that a constituent identity never replaces a compound identity in `report_records`, a constituent reported independently and inside a chain cannot collide or double-count, an absent compound/enabler verifier can never default to `CONFIRMED`, and multi-constituent status disagreement remains explicit rather than inheriting the first file's verdict.

Verification of two constituent mechanisms is not verification of their composition, ordering, shared-state transition, reachability, or combined harm. A chain can be false even when both constituents are individually true, and a claimed severity elevation exists precisely because of an effect absent from either constituent alone. Allowing the new claim into a proof-grade body using only constituent files breaks generator/discriminator separation and the stated executed-PoC boundary.

Fix contract:

- Normalize every `Severity-Upgrade-Justified: YES` chain into a typed compound candidate before queue finalization, with stable chain ID, constituent identities, ordering/precondition/postcondition edges, combined-impact claim, proposed severity, and source/coverage lineage. It enters the same independent verification lifecycle as every other new candidate.
- Give the compound candidate its own verifier work item and evidence scope. Constituent results are inputs, never a terminal verdict. The verifier must adjudicate composition feasibility, ordering/reachability, whether both mechanisms are required, and whether the claimed combined impact/severity follows. An executed composed harness/trace may establish `COMPOSITION`/`HARM` proof scope; separate constituent PoCs cannot.
- A justified chain with no independent compound verification remains `UNVERIFIED_COMPOUND`/human-review visible at its best proposed severity and cannot receive a proof-grade status or body severity elevation. Haltless operation preserves the claim and assurance debt; it does not synthesize proof from constituent files.
- A `Severity-Upgrade-Justified: NO` restatement is not a new claim: retain its alias/coverage relation and consolidate it into constituents without a redundant chain verifier. Mechanical self-restatement/anti-absorption checks remain proposals until this classification is structurally valid.
- Report bindings require `verify_CH-*` (or a typed equivalent compound-verification receipt) for a separate/elevated chain. Remove the generic constituent-verifier substitution for the compound claim; constituent files may still be linked as supporting evidence.
- Run chain promotion before shard manifests and semantic completion receipts are frozen. Late chain/iteration-2 additions invalidate the affected queue/shards/aggregate/report descendants under P0-Z.

Required fixtures: real `chain_agent2`→queue contract; justified High chain over two Medium constituents; justified same-tier combined impact; unjustified restatement; both constituents confirmed but composition refuted; one constituent refuted; constituents confirmed but ordering unreachable; compound composed execution confirms; compound evidence proves mechanism only; no harness available; verifier unavailable; chain iteration 2 adds work after initial queue digest; report attempts constituent substitution; mode parity including Thorough all-severity behavior; L1/SC parity; duplicate/alias chain IDs; resume and targeted invalidation; no double-counting after a chain is consolidated.

### P0-AG. Severity-matrix enforcement is directionally biased toward demotion and treats one verifier's prose as independent evidence

Code evidence: `_enforce_severity_matrix()` documents and implements an explicitly asymmetric rule. When the verifier's authored severity is lower than the mechanically computed matrix, the verifier wins without a Trust Adjustment or evidence-bound rationale; when it is higher, the matrix wins. The same verifier authors `Impact`, `Likelihood`, modifier prose, and `Severity`, so neither side is an independent adjudication. Inline text such as `High (adjusted to Medium)` is accepted as final intent without binding the adjustment to a refuted premise or proof scope. If matrix axes are missing, a queued Critical/High is mechanically capped at Medium whenever the verifier omits a severity field.

The modifier substrate is also inconsistent. `_MATRIX_TRUST_FULLY_RE` was hardened to require structured affirmative forms after a real false demotion, but `_MATRIX_VIEW_FN_RE` and `_MATRIX_ONCHAIN_RE` still scan the entire verifier document for broad phrases with no field boundary or negation guard. Multiple modifiers stack mechanically; an otherwise Critical matrix value can become Low. This is a generic path by which explanatory prose or a single mistaken assessment can silently reduce visibility.

Test-oracle evidence: `test_phase_b_severity_matrix.py` explicitly locks `verifier_lower_than_matrix_wins` and `verifier_higher_than_matrix_loses`. `test_severity_provenance_fixes.py` simultaneously claims the rule was made symmetric and that explicit verifier severity is authoritative in both directions. Its alleged higher-than-matrix fixture no longer contains an actual disagreement after the trust regex was tightened: High x Medium computes High and the narrative trust mention is ignored, so both values are High. The suite therefore passes while preserving contradictory specifications and never tests the claimed symmetric behavior. This is specification/test drift, not merely missing coverage.

This directly amplifies the measured found-then-wrongly-demoted half of recall loss. It is not corrected by R10.1: R10 protects a bounded class of favorable external-premise demotions and floors to an upstream claimed severity, while this path applies to internal premises, missing fields, modifier parsing, and an already-under-rated upstream severity.

Prompt-delivery evidence: the frozen Claude shard prompt's `Assigned verifier output checklist` and standalone `SC Verify Shard Contract` hard-require only `Severity`, `Evidence Tag`, and `Verdict` plus the PoC ledger. The standalone contract says it and `phase5-poc-execution.md` are the complete verifier methodology. Neither generated prompt contains `Likelihood`, `Trust Adjustment`, `Independent Severity`, or `Severity Matrix`; the mandated phase-5 file contains impact-premise verification but no severity-assessment schema. The downstream driver nevertheless calls severity-matrix enforcement and interprets missing axes. Thus the common missing-axis result is partly deterministic prompt/compiler drift: the producer is not contractually told to emit the state the consumer treats as authority. This is a direct methodology-non-application mechanism, not an inference that the model ignored a present instruction.

Live verifier-path evidence: the frozen Claude canary's first verification shard consumed two queue rows proposed as High. One verifier retained High as `CONTESTED` without parseable Impact/Likelihood axes; the other emitted `CONFIRMED`, Impact=High, Likelihood=Low, and final Severity=Medium, with no Trust Adjustment field. The latter artifact also authored its own code-trace evidence and PoC ledger. This is **not** evidence that the Medium decision is factually wrong--the canary is not a ground-truth benchmark--but it proves the production Claude route exercises the exact single-author downward-authority path described above. The regression fixture must therefore assert process correctness: a supported downward proposal becomes a typed challenge requiring premise-bound evidence plus independent adjudication, while the candidate remains retained regardless of the final tier.

Checkpoint-complete Medium-A evidence strengthens the process result. Across the six verifier files completed through phase 34, five lacked parseable Impact/Likelihood axes. All six recorded `Attempted: YES`; one Medium-queued row was authored as `CONFIRMED` Low with `[POC-PASS]`, while the other three Medium-A rows remained Medium/`PARTIAL` without axes. Again, this does not adjudicate the correct substantive tier; it proves that executed evidence does not repair the missing decision schema and that a downward result can be authored without the fields the later matrix consumer expects. The superseding metadata-only receipt is `evm-siloconfig-thorough-007.verify-lifecycle.phase34-medium-a.v2.json`, SHA-256 `4CE8BF7722F3BE9B9097021A0C4E30518FA0266BD8E79BDCDA35D04FC64CEA2B`, produced by extractor SHA-256 `A206721D918A20FB3EDFCA62E410EFB16DE0E3B02C2B2C488D1BB26223B72C6C`. The earlier receipt is preserved but superseded because its first implementation scanned proof-tag mentions instead of the authoritative Evidence Tag field.

Checkpoint-complete Medium-D evidence exercises the same authority after a successful bounded repair. The four queue-Medium rows all finalized as `CONTESTED`, two at Low and two at Informational. Three record concrete executed test commands/results and one retains an accepted structural no-execution blocker; all four include an Independent Severity equal to the authored result, but none includes parseable Impact, Likelihood, or Trust Adjustment. The process result is therefore independent of whether the individual lower tiers are substantively correct: the runtime accepted four downward decisions without the facts required by its own later matrix/adjudication logic, and the same worker authored both the evidence interpretation and severity. Receipt: `evm-siloconfig-thorough-007.verify-lifecycle.phase37-medium-d.v1.json`, extractor SHA-256 `741B28960A005F163451FF69B07ECDBCFA56E51475F9BA861D0C3017913B3649`, receipt SHA-256 `CC8F795A38DDEF3E7F7DFEA357B8D570A0575AE38EA13E3FCE539663B647107E`.

Medium-F supplies a fourth independent checkpoint with the same schema defect: all four queue-Medium rows lack Impact/Likelihood axes, although three are `CONFIRMED` Medium with `[POC-PASS]` and one is `REFUTED` Informational with an unexecuted `[CODE-TRACE]` structural skip. Independent Severity is present for all four but equals the same worker's authored value, so it is not independent authorship. Receipt: `evm-siloconfig-thorough-007.verify-lifecycle.phase40.sc_verify_medium_f.auto.json`, SHA-256 `CE7980B36E60E5C70A547AD1975FF0029A4939E817894FAAE14C927222DE9270`.

Fix contract:

- Represent severity assessment as typed facts: candidate identity and constituents, impact class and harmed asset/capability, likelihood premises, actor/precondition facts, modifier claims, evidence IDs, evidence/proof scope, assessor identity, and proposed severity. Markdown is a projection, not authority.
- Use the Impact x Likelihood matrix as a consistency calculation over those facts, not a directionally privileged terminal decision. A disagreement in either direction creates a typed challenge.
- A downward decision requires the exact impact or likelihood premise that was refuted, evidence capable of resolving that premise, and an independently authored adjudication. A verifier's bare lower number, inline adjustment phrase, missing axis, or self-authored modifier cannot authorize a demotion.
- An upward decision carries the same premise/evidence burden. Unresolved disagreement preserves the best upstream severity as `UNRESOLVED_SEVERITY` for retention and routes bounded adjudication; it does not automatically choose either the minimum or maximum as final truth.
- Make modifiers structured enums with applicability predicates and evidence. Negated or explanatory prose never applies them. Stacking is permitted only when each modifier is independently valid and the combination is semantically compatible.
- Missing/unparseable axes preserve the upstream proposed severity with a completeness debt and targeted repair; they do not cap Critical/High to Medium. Severity never controls whether an identity remains queued, verified, or delivered.
- Generate the verifier's mandatory output fields, prompt checklist, typed parser, completeness gate, repair delta, and report projection from one severity-decision schema. The prompt must explicitly require impact and likelihood facts, evidence-bound modifiers, assessor identity, and any adjustment rationale; a test must compare the compiled Claude/Codex shard prompt against the consumer schema so a required field cannot disappear during prompt assembly.
- Reconcile this with P0-P/P0-V/P0-U through one direction-neutral severity-decision ledger. R10 external-premise policy is one evidence/premise rule in that ledger, not a separate competing authority.

Required fixtures: verifier lower than matrix with no rationale; rationale without evidence; evidence-bound refutation of impact; evidence-bound refutation of likelihood; verifier higher than matrix; missing one/both axes for Critical/High/Medium; compiled Claude and Codex shard prompts contain every consumer-required severity field; deletion of one schema field fails prompt/consumer parity; targeted repair requests only the missing typed delta; inline adjustment up and down; negated `view-function-only`; explanatory `on-chain-only` mention; structured affirmative modifiers; incompatible and valid modifier stacking; external favorable premise and R10.1; internal premise; depth-side under-rating; grouped constituents with different premise outcomes; independent adjudicator agrees/disagrees; adjudicator unavailable; report-index drift; resume and idempotency; contradictory legacy tests replaced by one executable policy table; calibration against held-out severity ground truth without making retention severity-dependent.

### P0-AH. Thorough's documented all-severity PoC scope is silently capped at Medium+

Specification/code evidence: `docs/audit-modes.md` and `rules/orchestrator-rules.md` declare Thorough verification as `ALL severities`, and `rules/phase5-poc-execution.md` mechanically defines the Thorough required-ID set as all hypotheses including Low/Informational. `_poc_contract_required()` instead returns true only for Critical/High/Medium in every non-Light mode. Its comment explicitly says Low/Info `Attempted: NO` is normal and justifies the override as avoiding futile retries. The SC queue still creates 126 Low and 22 Informational rows in the frozen canary, but the hard attempt contract cannot fire for any of them. This is an intentional runtime-policy override of an explicit methodology requirement, directly contrary to the Thorough no-speed-optimization rule.

The Medium-D checkpoint adds a second, distinct contract lesson. Attempt 1 wrote all four assigned files and the hard gate rejected exactly one self-declared non-executable row as a mandatory property PoC. The targeted retry prompt named that one failure but correctly required a final pass over all four rows; the retry modified three rows and the final checkpoint contains three executed attempts plus one accepted structural skip. This demonstrates useful repair behavior, but not a sound classification authority: `_effective_poc_class()` and `_has_valid_skip_blocker()` still decide whether the verifier may waive execution partly from finite lexical cues and fields/verdicts authored by that same verifier. The gate can catch a cue-matching unsupported escape, while a semantically equivalent paraphrase or self-authored blocker may take a different route. The fix must therefore retain the sticky recall floor while replacing lexical/self-authored terminal classification with typed claim facts, evidence-bound blockers, and independent review for any no-execution negative disposition.

Medium-E then exercised the circular branch directly: one queued Medium row finalized `REFUTED` with `[CODE-TRACE]`, self-declared `PoC Class: structural`, `PoC Required: NO`, `Attempted: NO`, and `STRUCTURAL_NO_EXECUTABLE_HARM_ASSERTION`; the shard passed without retry. `_has_valid_skip_blocker()` treats the verifier's own REFUTED verdict as a valid blocker, so the same worker can author the negative disposition that relaxes its execution obligation. This may be correct for a genuinely source-proven refutation, but correctness is not structurally established by self-declaration. The typed negative-decision/adjudication path must authorize the blocker; otherwise it remains unproven and independently challenged.

Medium-F reproduced the same process shape in the next independent shard: three rows finalized `CONFIRMED` with `[POC-PASS]`, while one finalized `REFUTED` at Informational with `[CODE-TRACE]`, `Attempted: NO`, and a structural skip. All four omitted parseable Impact/Likelihood axes, and each Independent Severity merely matched the same worker's authored severity. This does not adjudicate the substantive outcomes; it shows the execution waiver and downward authority are repeatable production paths rather than a one-shard anomaly. Receipt: `evm-siloconfig-thorough-007.verify-lifecycle.phase40.sc_verify_medium_f.auto.json`, SHA-256 `CE7980B36E60E5C70A547AD1975FF0029A4939E817894FAAE14C927222DE9270`.

Fix contract:

- Separate verification coverage from fuzz-neighborhood policy. In Thorough, every queued severity receives independent verification, and every locally testable unit/property claim receives at least one bounded execution attempt. The detailed Phase-5 rule may continue to require the additional fuzz variant only for Medium+; update the mode summary so `with fuzz` cannot be misread as fuzzing every Low/Info row.
- Core retains the Medium+ mandatory-attempt threshold. Light retains its documented reduced policy. Mode is a typed input to the decision; severity is not allowed to silently override Thorough.
- A non-testable classification or unavailable harness must carry a typed, evidence-bound blocker and an `UNPROVEN` proof scope. A verifier cannot self-reclassify away from execution and then use its own reclassification as a terminal refutation; P0-V/P1-E adjudication applies.
- A compile/run failure proves only the scope established by the oracle and receipt. It cannot delete or globally demote a candidate, and grouped findings require constituent-specific outcomes under P0-O.
- Bound cost with per-row execution budgets, reusable compiled harnesses, shard-level environment setup, and deterministic skip receipts--not by exempting a severity tier. Report runtime/cost telemetry separately from recall policy.

Required fixtures: Thorough Low unit and property rows require an attempt; Thorough Informational testable row requires an attempt; structural/spec/docs with valid blocker remains unexecuted and `UNPROVEN`; unsupported self-reclassification cannot escape; Core Low/Info do not require execution; Core Medium+ do; Light policy; compile failure; assertion failure with mechanism-only oracle; successful harm-scoped execution; grouped mixed-testability constituents; external integration without environment; shard retry does not duplicate successful executions; Windows/Linux harness commands; EVM, Solana, Aptos, Sui, Soroban, Go, and Rust runners; exact queue-to-attempt receipt parity; resume idempotency; runtime budget exhaustion becomes visible debt rather than a false completion.

Implementation anchors and compatibility constraints: make the policy change in both `_poc_contract_required()` and the cheap severity pre-filter inside `_validate_poc_contract_for_rows()`; changing only the former leaves every Low/Informational row unread and is therefore a silent no-op. `_validate_poc_attempt_coverage()` already distinguishes Core from Thorough at its second-stage severity gate, so its behavior should be reconciled with the same shared mode policy rather than independently rewritten. Replace `test_B_low_info_never_require_mandatory_poc` in `test_three_false_positive_fixes.py` with a mode-by-severity policy table: the current test deliberately locks the specification violation. Preserve the existing effective-class and valid-blocker behavior--Thorough requires attempts for locally testable Low/Informational claims, not fabricated execution for a genuinely structural/spec/docs claim. Add a shard-level fixture proving the hard validator actually opens and validates the Low/Informational verify files, because a direct unit test of `_poc_contract_required()` alone would not detect the current pre-filter bypass. Reuse a single helper for Light/Core/Thorough eligibility in the hard contract, soft coverage audit, prompts, and telemetry so those authorities cannot drift again.

### P0-AI. The standalone verifier compiler strands mandatory ecosystem methodology in dead legacy templates

Code and compiled-prompt evidence: `_STANDALONE_PROMPT_MAP` routes every SC verifier shard to `prompts/shared/v2/phase5-verification-sc.md` and every L1 verifier shard to the shared L1 equivalent. The SC standalone prompt explicitly says not to open the legacy language-specific verifier prompt and declares itself plus `phase5-poc-execution.md` to be the complete verifier methodology. The frozen Claude prompt contains that exact prohibition. The active SC contract covers shard isolation and PoC execution, but the ecosystem verifier templates it excludes contain mandatory dual-perspective checking, anti-downgrade and class-before-false-positive guards, realistic-parameter and protocol-context validation, error traces, committed-invariant emission, new-observation handling, independent severity, and ecosystem harness patterns. Some old sections were correctly decomposed into later skeptic/cross-batch phases and must not be duplicated; several others have no equivalent in either the standalone prompt or the PoC rule. The L1 standalone output schema similarly lacks a complete impact/likelihood/severity decision contract even though L1-specific severity methodology exists elsewhere.

Dead does not mean correct. The excluded legacy templates also encode rules that should **not** be resurrected as written: a one-way `min(independent, claimed)` severity cap, categorical minimum severity for a broad defense-parity shape, a popularity-based `3+ agents` override, fixed TVL arithmetic examples, and stale MCP/fork/model assumptions. Blindly concatenating these files would restore some recall operators while reintroducing directional bias, anchoring, protocol-shaped examples, and prompt bloat. The reachability audit must therefore review each operator's semantics as well as prove that it has a live consumer.

Test evidence: tests such as `test_independent_severity_cap.py` inspect the legacy ecosystem prompt for mandatory methodology even though live shards are forbidden to read that file. `test_sc_verification_prompts_require_poc_testability_ledger` checks that the shared and legacy files independently contain the PoC subset, but does not assert semantic parity of the actually compiled prompt with every active downstream consumer. These tests can therefore remain green while the live verifier never receives the method they claim to protect. The phase-36 cutoff receipt `evm-siloconfig-thorough-007.verify-lifecycle.phase36-medium-c.v2.json` (extractor SHA-256 `8CD134DAAB78192498B14870FA6D8B02494339B48740C4027904B5FD83E5BA93`; receipt SHA-256 `141EBED6509BF5517B996D8BD37202722A66EDE8B3B1E74A1A8E33FDDA980B9F`) makes the consequence measurable without observing the active next shard: 14 finalized verifier files, all 14 recording an execution attempt/result, but 13/14 lacking parseable Impact/Likelihood axes and 8/14 lacking Independent Severity. The four newly finalized Medium-C rows all lack both the axes and Independent Severity, yet satisfy the current hard gate. This does not prove their substantive verdicts wrong; it proves the methodology-delivery and consumer-schema contract is incomplete.

This is broader than prompt wording. Shards are told to read only the cited location and one primary artifact. A local mechanism can therefore be judged safe without the caller/state/actor/dependency context needed to resolve the harm premise, while the excluded legacy method says to validate protocol-level context. The exact-location restriction is useful for cost and contamination control, but it needs a typed, bounded context-expansion rule rather than an absolute cutoff.

Fix contract:

- Build a versioned verification-method registry and compiler, not a concatenation of the old 250--750-line prompts. Its compact generic core defines mechanism trace, class-before-negative-disposition, harm-premise challenge, realistic-parameter/environment validation, context closure, evidence/proof scope, direction-neutral severity facts, negative/error trace, and new-observation staging. Ecosystem executor modules are selected conditionally from language, PoC class, and bug class.
- Create a one-time methodology-reachability manifest over every currently marked `MANDATORY` section. Each rule is classified `ACTIVE_IN_VERIFIER`, `MOVED_TO_INDEPENDENT_CONSUMER`, or `RETIRED_WITH_RATIONALE`, with an owning phase, compiled module/schema field, and test. A mandatory rule with no live consumer is a build failure. Skeptic/judge and cross-batch logic remain independent phases; restoring them inside the writer would violate discriminator separation.
- Compile the prompt's output schema, mandatory reads, allowed bounded context expansion, retry delta, and validator expectations from the same typed contract under P0-AE. Hash the selected method modules into the phase dispatch receipt and require the per-row result to cite that dispatch identity.
- Emit a typed per-row operator receipt: each selected operator is `APPLIED`, `NOT_APPLICABLE` with a mechanically valid predicate, or `BLOCKED` with evidence/debt. `APPLIED` requires the operator-specific evidence fields; merely repeating the method name is not application. The downstream application skeptic consumes negative or blocked outcomes before any terminal demotion/refutation.
- Replace the absolute exact-location read rule with deterministic context packets derived from the call/state/reference graph: cited function plus bounded callers/callees, touched state writers/readers, privilege/config sources, and relevant dependency boundary. If the packet cannot resolve the harm premise, one bounded expansion or a visible `CONTEXT_UNRESOLVED` debt is required; the verifier may not convert missing context into SAFE.
- New observations become typed candidate proposals routed through the normal registry and independent verification under P0-G. Committed invariants become reusable negative-evidence records under P1-D. Neither is self-certified by the verifier that emitted it.
- Keep prompts small by conditional operator/module selection and referenced typed context packets. Measure compiled prompt bytes/tokens and operator count, but never remove a recall-bearing operator merely to meet a budget; overflow becomes an exact split/coverage receipt.

Required fixtures: generated Claude and Codex prompts for EVM, Solana, Aptos, Sui, Soroban, Go, Rust, and mixed L1; every active consumer-required field present; dead legacy-only mandatory rule detected; intentionally moved skeptic/cross-batch rule accepted only with a real independent consumer; retired rule without rationale rejected; class check before REFUTED/SAFE; realistic-parameter challenge; protocol-context packet resolves and refutes a local assumption; unresolved context retains the candidate; bounded expansion with hub/fan-out limit; ecosystem executor module selected only when relevant; module hash mismatch; operator falsely marked APPLIED without evidence; valid NOT_APPLICABLE; blocker becomes report-visible debt; new observation enters the candidate registry; no target-specific methodology text; Windows/Linux path rendering; resume with unchanged module/context hashes; targeted invalidation when either hash changes. Acceptance also requires a held-out A/B over previously mis-demoted cases and mechanically valid negatives, scored by a neutral adjudicator for recovery and reinflation--the frozen canary is only the structural regression fixture.

### P0-AJ. Queue JSON, Markdown, shard prompts, and verifier filenames disagree on the same work item

Live typed/projection evidence: the canonical `verification_queue.json` contains 174 rows, but 92 rows retain an `expected output file` derived from an earlier inventory identity (`verify_INV-*.md`) while their current `finding id` is an `H-*`/`GRP-*` queue identity. The shard Markdown and runtime checklist instead derive `verify_<current Finding ID>.md`, and the completed workers wrote those current-ID files. For example, the typed row can say current ID `H-NN` plus expected file `verify_INV-NNN.md`, while the actual shard contract and gate require `verify_H-NN.md`. This is not cosmetic: any new typed consumer that trusts `expected output file` will diverge from the existing filename-derived consumer, and grouped/relabelled identities can collide.

The human/LLM projection is independently malformed. `verification_queue.md` declares ten columns, yet 18 of 174 data rows contain 11--30 parsed cells because free-form title/location/evidence text includes unescaped pipe operators or pipe-separated corroboration. The authoritative JSON retains the intended `poc class` and location, while the rendered row shifts those values into undeclared columns. The live Medium-B model recovered the intended class for its four rows by re-reading source and authoring its own ledger, but recovery by one model is not a contract. The shard prompt explicitly tells the verifier that its Markdown row is canonical and does not direct it to the typed sidecar; driver parsers prefer the correct JSON when it is fresh, so the model and mechanical consumer can see different records and both believe they followed the contract.

Code-shape evidence: `_canonical_queue_row()` preserves a non-empty upstream `expected output file` instead of recomputing it from the canonicalized current finding identity. The Markdown queue/subset renderer interpolates free-form cells without a single round-trip-safe escaping contract. The later JSON sidecars make driver parsing more robust but do not repair the already-compiled model input. This is a generic identity/serialization bug and directly intersects R10's constituent joins, grouped findings, resume, and all-severity PoC routing.

Observer disposition (phase 36): the first queue-projection receipt incorrectly reported 187 shard JSON rows because its PowerShell reader treated each explicit empty envelope (`row_count: 0`, `rows: []`) as one row. That receipt is preserved but superseded. The corrected schema-aware observer (`audit_queue_projection.ps1`, SHA-256 `9D458B8BF714E6D92B6891C141BF5ED74D30E062EA320EE60A1AD7E1363CADCE`) produced `evm-siloconfig-thorough-007.queue-projection.phase36.v2.json` (SHA-256 `5ADD01A8697256032A28F185BF83D4EF2EAB7465CF00424DD6EDC63EFDAA26A9`). It proves exact main-to-shard identity conservation: 174 main IDs, 174 shard IDs, 174 unique shard IDs, zero duplicates across shards, and zero missing/extra IDs. It simultaneously reproduces the real projection defects unchanged: 92 stale expected-output projections, 18 malformed-width Markdown rows, and one duplicate stale output target. Therefore shard allocation is not presently indicted; typed identity/filename and renderer parity remain P0-AJ.

Fix contract:

- Make `QueueWorkItem` typed and authoritative before any shard prompt is built: stable candidate identity/lineage, current work-item ID, aliases/constituents, severity proposal, evidence class, location records, primary artifacts, PoC class, and expected output identity. `expected_output_file` is a validated computed projection of the current work-item ID; prior `INV`/source IDs remain aliases, never executable filenames.
- Write the canonical queue and every shard sidecar atomically before launch. Compile the model input directly from that typed object--prefer a bounded JSON record/card block over a free-form Markdown table--and bind its digest into the prompt and phase receipt. Markdown is a human projection only.
- If a Markdown table remains, use one renderer that escapes pipes, backslashes, newlines, code delimiters, and ecosystem/path syntax, then mechanically parse it back and require exact typed-field parity and header/data column count before launch. A projection defect produces a driver-rendered safe JSON/card prompt plus visible compile debt; it never asks the model to guess shifted columns.
- Remove freshness-by-mtime as semantic authority. Sidecar/projection pairs carry schema version, source digest, record-set digest, and rendering digest; mismatch selects neither silently and triggers deterministic regeneration from the typed source.
- Preserve alias and constituent lineage through queue generation, grouping, R10 joins, verifier lookup, report indexing, and resume. Every consumer uses the work-item ID for file lookup and the lineage set for joins; no consumer re-derives identity from a filename or display heading.

Required fixtures: `INV` to `H` relabel with stale expected filename; `INV` to `GRP` many-to-one grouping; two aliases targeting one current item; duplicate expected filenames rejected; raw and escaped pipe in title/location; `||`, regex/grep pipe, Markdown code span, backslash, newline, Unicode, Windows drive/path, and POSIX path; 10-column header with 10-column round trip; malformed 11/30-cell legacy rows; JSON newer/older/same timestamp; JSON/Markdown digest mismatch; shard sidecar present before launch; Claude/Codex compiled prompts bind the same record digest; verifier writes exactly current-ID file; legacy alias preserved for R10 constituent/source join; resume idempotency and targeted invalidation. Acceptance on the frozen fixture requires zero stale expected-output projections and zero row/header cell-count mismatches without dropping any of the 174 identities.

### P0-AK. Fixed verifier phase slots silently defeat the four-findings-per-shard attention budget

Code/live evidence: `VERIFY_TARGET_PER_SHARD = 4` and its adjacent contract say every severity tier uses the same small per-shard target and that phase-slot pools must be large enough never to throttle below it. `compute_sc_verify_shards()` instead caps `chunk_count` at the fixed names in `SC_VERIFY_SHARD_MANIFESTS`. The SC phase graph defines only ten Low/Info verifier phases. The frozen queue has 126 Low plus 22 Informational rows, so exact adherence requires 37 four-row work units; the fixed pool silently compresses them into ten shards of 14--15 rows. Medium happens to fit exactly: 24 rows across six non-empty four-row shards. The target invariant is therefore executable documentation drift, and the highest-volume/lowest-upstream-tier work receives 3.5--3.75x the intended per-session attention load.

This is a recall issue, not only cost or latency. A true vulnerability under-rated upstream enters the Low/Info pool, where one Claude session must independently trace, classify, execute, and write up to fifteen findings under the same context. The user's dominant non-application and wrong-safe miss modes are precisely the expected failure modes of overloaded per-row methodology. The frozen canary cannot prove a substantive miss, but it proves the capacity contract is violated before any model runs. Adding more fixed lettered phases would merely move the next cliff and duplicate SC/L1 policy.

The first overloaded Low shard now supplies live outcome evidence for the process risk. One Opus session handled fifteen queue rows and finalized all fifteen in about ten minutes: six `CONFIRMED` and nine `REFUTED`. Every row lacked parseable Impact/Likelihood axes and Independent Severity. All nine refutations carried `[POC-PASS]`; two additional confirmations carried `[POC-PASS]`, while the remaining four confirmations were `[CODE-TRACE]` with no execution attempt. All fifteen also retained stale queue `expected output file` identities, although the runtime wrote the current-ID files. The shard passed with no repair or degraded state. This does not establish that any verdict is wrong; it proves that one 3.75x-over-capacity session can issue nine terminal negative dispositions under the same incomplete decision schema, at a tier excluded from the existing High/Critical skeptic appeal. Executed tests improve evidence authenticity, but P1-E still requires the receipt to encode whether the oracle proves mechanism, one parameterization, or the full harm premise. Receipt: `evm-siloconfig-thorough-007.verify-lifecycle.phase44-low-a.v1.json`, extractor SHA-256 `741B28960A005F163451FF69B07ECDBCFA56E51475F9BA861D0C3017913B3649`, receipt SHA-256 `9C71D03C54316D5768B9E05E514CE05B1081A62BED2AC1FE0D75248B4A886D3E`. The bound prompt was 21,327 bytes and the typed shard sidecar 16,299 bytes, but the phase cost ledger records 101,960 output tokens and 6,812,543 total input tokens across the session, with long-context pricing flagged and 95% cache reuse. The primary defect is therefore per-session work/decision load, not merely initial prompt byte length; the fixed slot ceiling concentrates cost and reasoning into an extreme long-context transaction instead of enforcing the documented bound.

Low-B independently repeats and sharpens the pattern: fourteen of fifteen rows finalized `REFUTED` and one `CONTESTED`; every row carried `[POC-PASS]`, but all fifteen again lacked Impact/Likelihood axes and Independent Severity and all fifteen carried stale expected-output identities. The session consumed 104,094 output tokens and 7,695,853 total input tokens, again in the long-context tier. Receipt: `evm-siloconfig-thorough-007.verify-lifecycle.sc_verify_low_b.auto.json`, SHA-256 `D6D091B967ABC2839A41976A2DEB5E18D3277CDE9D620530F0041986ECFAE8A0`. The two shards therefore yield twenty-three terminal refutations from thirty Low rows under two independent overloaded sessions with the same missing decision schema. This remains process evidence only: executed generated tests are stronger than unsupported prose, but without typed oracle provenance, proof scope, premise binding, or independent negative-disposition review, the pipeline cannot know whether the test result refutes the candidate's full claim.

Low-C provides the third independent overloaded-session observation. Its fifteen rows finalized eight `REFUTED`, five `CONFIRMED`, and two `CONTESTED`; all fifteen again omitted parseable Impact/Likelihood axes. Unlike Low-A/B, all fifteen contained the nominal Independent Severity field, proving that field emission is session-variable rather than enforced by the consumer. Twelve rows recorded an execution attempt and three a valid non-execution classification; five used `[POC-PASS]` and ten `[CODE-TRACE]`. Fourteen of fifteen retained stale expected-output identities. The session consumed 100,398 output tokens and 8,573,095 total input tokens with 96% cache reuse. Receipt: `evm-siloconfig-thorough-007.verify-lifecycle.sc_verify_low_c.auto.json`, SHA-256 `12223160502CE86C13BAC175554C26C831D4B8AEE9018F8F4C92E13F140FD356`. Cumulatively, Low-A/B/C contain 45 rows with 31 `REFUTED`, 11 `CONFIRMED`, and three `CONTESTED`; every row lacks Impact/Likelihood axes, 30 lack Independent Severity, and 44 retain stale expected-output identities. This is stronger evidence for a structural application/attention defect, but still not evidence that any substantive verdict is wrong.

The planned Low-E midpoint separates the defects further. Low-D and Low-E each finalized all fifteen rows `REFUTED` with `[POC-PASS]` and an execution attempt; every row still omitted Impact/Likelihood and Independent Severity, while their current-ID expected-output projections were no longer stale. Low-D consumed 123,299 output tokens and 7,128,156 total input tokens; Low-E consumed 64,203 output tokens and 7,716,061 total input tokens. Their lifecycle receipt SHA-256 values are respectively `6AA8206594A01385F9B13E899AC3A69CEA4F0F3171CEE29EC75FAE19CD95FFAC` and `CD358F537453EB745E18F9E6CBE6008BDBF7664D1F04D64495AC592CF75C7EB5`. Across Low-A through Low-E, 75 rows yield 61 `REFUTED`, 11 `CONFIRMED`, and three `CONTESTED`; all 75 omit both axes, 60 omit Independent Severity, 68 record execution attempts, and 44 carry stale expected-output identities. Because the decision-schema omission and concentrated negative-disposition rate persist after queue identity becomes correct, P0-AK/P0-AG/P0-V cannot be dismissed as merely a Markdown filename drift. The canary remains regression/process evidence only and supplies no ground-truth judgment about those verdicts.

The final Low-J cutoff closes the tier-level observation without relying on model self-report. All ten fixed Low/Info phase slots completed and wrote 148 verifier files for 148 assigned rows, but each session still carried fourteen or fifteen rows instead of the documented maximum of four. The cumulative external receipt contains 32 `CONFIRMED`, 112 `REFUTED`, and four `CONTESTED` verdicts. All 148 rows omit Likelihood; 141 omit Impact; 118 omit Independent Severity. Only 118 record an execution attempt, while 30 use a non-execution path; the evidence labels are 81 `[POC-PASS]`, 15 `[POC-FAIL]`, and 52 `[CODE-TRACE]`. Sixty-six rows retain a queue `expected output file` different from the verifier file actually written. Receipt: `evm-siloconfig-thorough-007.verify-lifecycle.sc_verify_low_j.auto.json`, SHA-256 `3516915833D50537EAFB44FE0AC275553A9237794161979951900CD1785CEBB9`. This proves full file production but not methodology-complete or independently adjudicated decisions: field omission and work compression survive even when output-count parity is exact. As throughout this canary, these are lifecycle/process facts, not a claim that any individual verdict is substantively right or wrong.

Fix contract:

- Replace fixed verify-slot capacity with a driver-owned dynamic `VerifyWorkPlan`. It consumes typed `QueueWorkItem` records from P0-AJ and emits as many stable work units as required to satisfy a configured maximum workload (default four rows, with optional mechanically computed complexity weights). It is shared by SC and L1 and projected into backend-specific execution only after planning.
- Treat each work unit as a child transaction of one tier pool, not a permanently hand-written top-level phase. Claude and Codex use the same work-item IDs, row-set digest, model/mode policy, expected outputs, gate IDs, and resume receipt; only the launcher differs. Bound concurrency separately from total work, so a four-worker runtime limit never causes 37 obligations to be crammed into four prompts.
- Preserve haltless semantics without coverage compression. If time/rate/resource budget prevents execution, unstarted work units remain exact verification debt with their identities and upstream severity; they are never declared completed and never merged into an oversized last shard.
- Make assignment stable on unchanged inputs and append/split-capable for late candidates. Resume skips a child only when its queue-record digest, method-registry digest, context-packet digest, launch spec, outputs, and gates match. A late row invalidates/creates only affected work units, not all completed siblings.
- Enforce exact set parity and capacity before launch: union(work-unit IDs) equals active queue IDs, intersections are empty, no unit exceeds its row/weight limit, and every output identity has exactly one owner. Overflow or planner failure is typed debt, never a fallback to an oversized prompt.
- Report per-unit prompt size, row/complexity weight, wall time, retries, execution coverage, and application receipt. Use held-out A/B to determine whether four remains the right default; never tune the target on the motivating canary alone.

Required fixtures: 0/1/4/5/40/41/148 queue rows; mixed Critical/High/Medium/Low/Info; max-four invariant; complexity-weight split; exact union/no overlap; stable unchanged plan; late appended candidate; severity move between tiers; grouped/compound identity; child retry; one child degraded; rate limit after partial completion; resume twice; no oversized fallback; Claude PTY/headless and Codex launch parity; SC and L1; every ecosystem; Windows/POSIX paths; target configured to another value; planner manifest corruption; prompt-size ceiling; neutral A/B on per-row application and negative-disposition quality.

## 3. Priority-1: recall generators without combinatorial noise

### P0-AL. Raw substring ID privacy matching can reject an otherwise valid final report

Live reproduction: Python assembly produced a 61-section `AUDIT_REPORT.md`, and `report_quality.md` passed section-count parity, exact report-ID parity, promotion receipts, evidence/content checks, location checks, duplicate checks, and every other recorded predicate. The sole failure was `internal_id_leak = ['of-1']`. The matched text was ordinary prose containing the hyphenated phrase `price-of-1`; it was not a pipeline finding identity. The validator imports `_ID_ALL_NONHYPO`, whose niche alternation contains `OF-\d+`, wraps that union only in `\b...\b`, and applies it case-insensitively over the entire report. A hyphen is a regex non-word character, so the substring after `price-` satisfies the left word boundary and becomes a false internal-ID token.

Runtime consequence: `report_assemble` was marked degraded even though the report existed at the project root and every other quality predicate passed. The driver then continued into `report_dedup_agent` with `report_assemble` absent from the completed set and present in the degraded set. This simultaneously creates a false halt/degradation, an ambiguous downstream authority boundary, and a resume hazard: later phases can mutate/consume a report whose producing phase never committed. This is a generic Markdown/regex encoding defect, not a target-specific methodology issue, and directly answers why a healthy reasoning result can still fail at the last mechanical boundary.

Fix contract:

- Detect private identifiers by intersecting token candidates with the typed ID/lineage ledger, using the shared ASCII identifier boundaries `(?<![A-Za-z0-9_-])` and `(?![A-Za-z0-9_-])`; do not treat a free substring matching a prefix grammar as an actual identity.
- Normalize/casefold only after tokenization. An exact known private identity written in lowercase remains a leak, while `price-of-1`, `proof-of-2`, file names, compound words, and longer hyphenated tokens do not become identities merely because they contain a prefix-shaped suffix.
- Public report IDs and explicitly rendered client-safe aliases remain allowlisted by typed mapping, not by length heuristics. Unknown ID-shaped strings become an advisory privacy candidate unless a producer/lineage record proves they are internal.
- Assembly writes a phase commit binding the report hash and every quality predicate. A genuine privacy failure may be deterministically redacted through an exact alias event and revalidated; otherwise the report remains delivered with explicit privacy debt. No downstream phase may consume a report whose producer has neither a clean commit nor a typed degraded-output commit.
- Compile the same identifier serializer/parser/boundary policy into Markdown renderers, privacy validation, alias rewriting, report dedup, and resume checks so one subsystem cannot accept a token another rejects.

Required fixtures: ordinary `price-of-1`, `proof-of-2`, `out-of-3`, and `state-of-4` prose; exact known `OF-1` and lowercase `of-1` private identities; unknown `OF-999`; identity adjacent to punctuation, backticks, brackets, slash, underscore, and Unicode dash; identity inside code/test names; public H/M/L/I report IDs; private ID with a public alias; alias rewrite followed by rescan; one real leak among many benign substrings; Windows/POSIX paths; report hash/phase-commit parity; downstream launch after clean, degraded-with-output, and absent assembly commits; identical resume performs no model work.

### P0-AM. Model-owned background agents are invisible to the driver transaction

Live reproduction: the exact `report_dedup_agent` prompt says all Task calls **must be foreground/synchronous** and explicitly forbids `run_in_background: true`. During retry attempt 2, the Claude coordinator nevertheless announced that it was waiting for six background agents, each reading assigned report sections. One child finished after 1m52s while five remained outstanding. At 4m06s the driver observed no required decision artifact and launched a fresh missing-only PTY. That new session had no durable child-work manifest to join; it re-read the original/retry prompt chain, candidate pairs, and 937KB report while the first coordinator's child work was no longer transactionally attached to the phase.

This is direct evidence for a core non-application class: a tool/lifecycle rule present in Markdown is not an enforceable execution policy. PTY supervision sees the coordinator turn and disk artifact, not Task-child ownership, liveness, denominators, or late writes. A fresh repair can duplicate work, lose completed child judgments, race a late child write, or accept a shallow replacement. The finding does not depend on whether any individual child analysis was correct; the transaction cannot prove which work the final artifact incorporated.

Fix contract:

- Required fan-out is driver-owned. A typed `WorkPlan` enumerates child work-unit IDs, exact inputs/digests, output identities, schema, model/backend/tool policy, capacity, and aggregation predicate before launch. The coordinator may propose a partition but cannot create untracked required work.
- For backends whose in-session Task tool remains enabled, enforce foreground-only/allowed-parameter policy at the tool adapter or disable Task for phases whose worker pool is driver-owned. A prose prohibition is an explanatory projection, not the control.
- Each child writes one immutable, uniquely owned result or returns a typed no-result/debt event. Shared final artifacts are assembled only by the driver after exact work-unit set reconciliation; children never race-write the aggregate.
- Phase end/commit is impossible while a required child is running, unjoined, unaccounted, or capable of a late write. Timeout cancels or detaches the exact child transaction with a durable debt receipt before any retry begins.
- Retry reattaches to valid completed child receipts and schedules only missing/invalid work units. It cannot launch a new coordinator over the whole denominator or follow a pointer chain of progressively weaker prompts.
- Persist child launch/finish/cancel IDs, input/output hashes, backend session identity, and incorporation map. Claude and Codex use the same work-plan/commit semantics even if their subprocess APIs differ.

Required fixtures: coordinator obeys foreground policy; coordinator attempts a background Task and adapter rejects it; six children with one/five split; coordinator end-turn before children; child finishes after coordinator exit; child writes after retry begins; timeout/cancel race; one child crash; duplicate child result; child output under wrong name; aggregation before exact closure; retry reuses five valid children and schedules one; retry prompt retains full semantic contract; backend without Task; Claude PTY/headless and Codex parity; process crash/resume; no late mutation after phase commit.

### P0-AN. Backend runtime state is misclassified as immutable audit input

Live reproduction: retry attempt 2 created a 124-byte project-local `.claude/scheduled_tasks.lock` (SHA-256 `8A64ABBE84D4911A62B381C9D756890AFC3E62FE8991FF242998A020B3D3F9A3`) while the background Task machinery was active. The file did not exist in the frozen startup snapshot. `_project_context_files()` intentionally binds the complete stable project context, but its skip policy excludes `.git`, `.scratchpad`, build caches, and generated audit artifacts--not backend runtime directories or this lock. Post-execution snapshot verification therefore reported `changed_components = [source_scope]` and stopped the run immediately after `report_dedup_agent_decisions.md` was finally written.

Failing closed on a genuine source/config change is correct. The defect is that a supported backend's own ephemeral scheduler state shares the same namespace and digest as audited inputs. The run stopped at phase 72/75, left the new decision artifact uncommitted, retained `report_assemble` degradation, and never reached mechanical dedup, disposition, or floor. This is distinct from P0-AM: foreground enforcement would prevent this specific background-task trigger, but any allowed backend runtime/cache/lock written under the project could still manufacture source drift unless runtime ownership and snapshot classification agree.

Fix contract:

- Define a typed `BackendRuntimeContract` for each backend/mode/OS. Runtime locks, session state, caches, and scheduler metadata are placed in a driver-owned directory under the scratchpad or another explicitly isolated run root, never in the audited project namespace.
- Bind stable backend inputs that can influence reasoning--for example checked-in project instructions or approved settings--as named snapshot inputs. Do not solve the problem by ignoring an entire `.claude`, `.codex`, or similar directory: a pre-existing instruction/config change must invalidate evidence.
- If a backend cannot relocate one exact runtime path, predeclare that path with an ownership sentinel and type, exclude only that exact driver/backend-owned runtime artifact from source digests, hash it in an operational receipt, and prohibit agents from using it as source context. Unknown files under the same directory remain frozen inputs or containment violations.
- Snapshot revalidation and foreign-write containment consume the same classification object. A known runtime mutation is operational evidence; a source/config mutation is input drift; an undeclared project write is a containment failure. One event cannot be classified differently by the two subsystems.
- Commit ordering is transactional: validate source inputs, containment, backend runtime writes, required outputs, and child closure before accepting the phase. If a post-execution failure occurs, retain the output in quarantine with lineage and do not leave an unowned semantically usable file.

Required fixtures: Claude `scheduled_tasks.lock` creation on Windows/POSIX; Codex session/cache equivalents; headless and PTY modes; pre-existing checked-in `CLAUDE.md`/`AGENTS.md` unchanged and changed; approved settings changed mid-phase; runtime lock changed mid-phase; unknown file beside the lock; source file changed by agent, user, and build tool; symlink/junction escape; concurrent runs; runtime directory unavailable/read-only; phase output written immediately before drift detection; quarantine/commit parity; identical resume; snapshot contains stable backend inputs but excludes only owned ephemeral state.

### P0-AO. Resume mismatch silently becomes a destructive fresh run

Live reproduction: after the frozen legacy-Claude canary stopped at `report_dedup_agent:post-execution`, an invocation with the identical configuration was made to prove a clean resume. Startup classified the run as `MISMATCH` because source/runtime and toolchain snapshot components no longer matched. Without an explicit restart instruction, `_bind_checkpoint_audit_snapshot()` invoked `archive_stale_scratchpad()`, moved the active scratchpad under `.plamen-stale-snapshots`, replaced the 70-phase checkpoint with an empty checkpoint, archived project-root report/fuzz artifacts, rebound a new snapshot, and continued into recon. Multiple new Claude recon workers and model artifacts appeared before the observer was manually terminated.

The archive is byte-preserving but the operation is not resume-safe. Hash mapping proved all 701 scratchpad paths from the authoritative pre-resume receipt exist in the archive unchanged, yet the independent before/after comparator returned `FAIL`, `no_model_relaunch=false`, and `no_semantic_mutation=false`: the active report disappeared, 37 generated-test paths disappeared from their original locations, the authoritative checkpoint identity changed, five new prompts and four new model logs appeared, and partial recon output was written. Preservation in an undiscoverable/archive namespace is not transactional continuation, and an action hint saying “restart from recon” is not restart authority.

Current tests encode the unsafe behavior as success: `test_legacy_or_mismatched_progress_is_full_safe_rewind` asserts that a mismatch returns a fresh empty checkpoint and removes the active report. That is appropriate only for an explicit new-run operation, not an ordinary resume. The same ambiguity exists for legacy-unbound state and active-graph/mode mismatch recovery. A backend/runtime false drift therefore compounds into a second destructive lifecycle transition.

Fix contract:

- Introduce a typed startup intent: `RESUME_EXISTING`, `START_NEW_RUN`, or `MIGRATE_EXISTING`. Loading an existing checkpoint defaults to `RESUME_EXISTING`; no snapshot verdict may silently change that intent.
- `RESUME_EXISTING` accepts only exact snapshot/transaction parity. On mismatch, legacy-unbound state, graph mismatch, or incomplete post-execution transaction, stop before any model launch and write a typed decision receipt outside the evidence being protected. The receipt records run ID, stored/current component digests, changed paths/classes where available, allowed next actions, and a non-success exit status.
- `START_NEW_RUN` requires explicit authorization and a new immutable run ID/destination. It may consume a read-only copy/bundle of the same audited sources, but it must not move, delete, rename, or overwrite the prior run's scratchpad, report, generated tests, logs, checkpoint, or receipts. Prior answer-key outputs are excluded from the new input bundle by construction, not removed from the old run.
- `MIGRATE_EXISTING` is a separately authorized, versioned state migration. It writes before/after manifests and an exact migration ledger, preserves the original run, and may resume only if every migrated phase commit and dependency validates. Unsupported migration stops; it never falls through to recon.
- Give every run a durable identity independent of project path and scratchpad basename. Checkpoint, artifact ownership, phase commits, reports, process manifests, archives, and evaluator receipts bind that identity. A newly created run cannot impersonate the old run merely because it reuses `config.json`.
- Post-execution drift leaves the phase output quarantined with lineage and the prior checkpoint authoritative. A subsequent resume cannot consume or discard the quarantined output until the drift is classified and explicitly resolved.
- Root-level outputs participate in the same transaction as scratchpad outputs. Report/test/harness preservation is a hard postcondition; “move, never delete” is insufficient when callers and resume logic address the original identity.
- Harden the independent resume observer with `abort_on_first_model_child`, bounded observation duration, and `finally`-written process/manifest receipts. An observed model child causes the observer to terminate only the launched process tree, wait for closure, capture post-state, and still emit an admissible failure receipt.

Required fixtures: exact matching resume with zero writes/model children; source mismatch; methodology mismatch; toolchain mismatch; backend-runtime-only mutation after P0-AN classification; legacy-unbound checkpoint; active-graph/mode mismatch; partial post-execution output; explicit `START_NEW_RUN` to a distinct destination; refused same-destination restart; authorized/unsupported migration; report and generated-test preservation; quarantine consumption attempt; crash during decision-receipt write; crash during explicit new-run creation; concurrent resumes; run-ID collision; Windows/POSIX paths; observer detects first Claude/Codex child, terminates the launched tree, and writes its receipt; repeated resume is idempotent and launches no model.

### P1-A. Enumeration uses enclosing-function state instead of finding-local anchors

Live evidence: 153 inventory blocks included 80 ENUMGAP and 15 VARGAP blocks. The enumerator selected up to six variables touched by the entire enclosing function and cross-multiplied co-referencing functions; constructor hubs generated large unrelated families.

Fix contract:

- Anchor to exact symbols mentioned by the finding and statement-level AST references at cited locations.
- Use normalized reference-graph identities, not lexical substring matches.
- Apply hub/fan-out handling: constructor/initializer/control-plane nodes require an exact anchor; otherwise emit one UNKNOWN control-plane obligation rather than a Cartesian family.
- Keep an alias-preserving family card containing every member/source/location. Grouping may reduce work items but may never delete identities or prevent later split.
- Stage generator output as typed obligations; only analysis output becomes finding-shaped.

Required fixtures: local two-variable statement; unrelated variable elsewhere in the same function; constructor with many immutables; aliased member; overloaded function; unresolved location; non-EVM AST identity; group split; exact identity preservation.

### P1-B. Boundary generator is type-blind

Live evidence: one lexical cue on any parameter applied `{0,1,min,MAX,empty,self}` to the function as a whole, creating numeric/empty/self candidates for address contexts.

Fix contract:

- Enumerate per parameter from normalized ecosystem type IR.
- Address/identity, boolean, integer, bytes/array, option/resource, enum, and ecosystem-specific domains have separate generic boundary families.
- Threshold-adjacent values require an actual threshold expression.
- Unsupported type -> one UNKNOWN typed-boundary obligation, not universal guesses.

Required fixtures: mixed address/uint/bool/bytes parameters; threshold expression; no threshold; alias types; Move resource/option; Soroban address/bytes; unsupported type; idempotency.

### P1-C. Security-obligation triggers use broad prose keywords

Live evidence: eight obligations were generated from single tokens such as `asset`, `revert`, and `struct` across flattened Markdown narratives.

Fix contract:

- Generate from typed graph/recon feature facts first.
- Require explicit co-occurrence/structural predicates for fallback triggers.
- Record trigger source, fact identities, and rule version.
- Diff after depth/application receipts and queue only unaccounted obligations.
- A rule owns one canonical obligation; overlapping rules link aliases rather than fragment.

Required fixtures: documentation-only keyword; code-derived feature fact; required co-occurrence; repeated artifact prose; already-accounted obligation; conflicting facts; non-EVM facts.

### P1-D. Semantic-invariant receipt trusts one lossy Markdown source

Live evidence: `state_variables.md` was narrative/duplicated, producing `UNMEASURABLE` with zero expected variables even though state tracing covered 29 immutable fields.

Fix contract:

- Enumerate expected state from typed graph/AST plus state-write map, with Markdown only as compatibility fallback.
- Preserve source provenance and distinguish mutable, immutable/configuration, derived, and external state.
- Reconcile invariant coverage by stable symbol identity.

Required fixtures: missing state_variables with healthy graph; duplicated Markdown; immutables only; alias symbols; unsupported graph; non-EVM storage/resource model; source disagreement.

## 4. Priority-1: evidence and confidence correctness

### P1-E. Fuzzer execution authenticity is treated as protocol-harm proof

Live evidence: the fuzzer artifacts themselves distinguish contract obligations from input-acceptance probes and explicitly state that several failures prove mechanism/acceptance, not harm. Mechanical scoring nevertheless treats `[MEDUSA-PASS]` and `[FUZZ-PASS]` as proof-grade without encoding oracle provenance or proof scope.

The Medium-E verifier checkpoint demonstrates the inverse execution-scope problem on the live Claude path. Two rows receive terminal `REFUTED` verdicts with `[POC-FAIL]` because an authored harm assertion did not reproduce in the generated harness. The metadata proves that code executed; it does not encode whether the oracle is contract-authored or model-generated, which preconditions/environment were represented, or whether the failure refutes the mechanism, reachability, one parameterization, or protocol harm. A negative generated oracle therefore needs the same provenance and proof-scope discipline as a positive fuzzer result. The canary does not adjudicate whether either refutation is correct; it proves the current schema cannot express the distinction required to know.

Fix contract:

- Add orthogonal evidence dimensions:
  - execution authenticity;
  - assertion/oracle provenance;
  - reachability/environment fidelity;
  - proof scope: MECHANISM_ONLY / REACHABILITY / HARM;
  - external premises and their evidence state.
- Candidate-derived or heuristic assertions cannot auto-prove protocol harm.
- Missing scope/provenance downgrades the effective proof claim, never deletes the candidate.
- Verification remains responsible for harm and severity.

Required fixtures: contract-authored invariant failure; generated mechanism probe; generated harm oracle with in-scope derivation; unreachable harness; external dependency; missing scope legacy artifact; genuine PoC execution; tag/prose mismatch.

### P1-F. RAG precedent is mixed into code-confidence and disposition

Live evidence: generic boundary-analysis literature raised fifteen unrelated boundary candidates from 0.3 to 0.4 despite no matching precedent; representative results were propagated across large families. Current scoring can use this axis both to stop depth and to force CONTESTED.

Fix contract:

- Separate `precedent_strength` from mechanism/code confidence.
- Generic methodology literature supplies context only, with zero confidence uplift.
- Any positive precedent requires exact mechanism class and matching preconditions.
- RAG cannot clear/demote a candidate, force CONTESTED, or reduce investigation depth.
- Exact precedent may raise investigation priority and report context only.
- Family propagation requires typed equivalence; otherwise each member remains unscored.

Required fixtures: generic methodology article; exact primary precedent with matching preconditions; superficially similar precedent; refuting article; family with one exact member; offline/timeout fallback; no-network idempotency.

### P1-G. Single-domain consensus defaults to full agreement

Observed code path: `_compute_depth_confidence` can assign consensus `1.0` when only one domain contributed. One voice is not consensus.

Fix contract: distinguish independent support count from within-worker confidence; single-domain evidence receives no consensus bonus. Required fixtures cover one worker, duplicated worker identity, two independent roles, mechanically shared source, and contradictory roles.

### P1-K. Report evidence quality and proof scope are soft or label-dependent

Code evidence: `_validate_report_body()` detects missing substantive Impact/PoC content but deliberately excludes those errors from its hard `ok` predicate. The final report-quality gate likewise records missing C/H/M Impact or PoC sections, thin sections, placeholder titles, duplicate title/location pairs, and many blocked/stub sections as warnings. A literal boilerplate phrase or structural ID error can fail, but a semantically empty paraphrase can ship. In parallel, a section containing `[CONFIRMED]` is exempted from the PoC requirement because the label may mean code-trace confirmation with no execution. This makes a single overloaded word control both perceived confidence and quality policy, contrary to the stated rule that only executed PoCs are proof-grade.

Fix contract:

- Separate verdict, evidence authenticity, proof scope, and report presentation: `CONFIRMED_MECHANISM` with `CODE_TRACE` is not rendered or validated as executed proof; only an execution receipt with harm-scoped oracle provenance may render proof-grade language.
- Require typed report records to carry non-empty mechanism, preconditions, impact, evidence scope/result, affected location, and recommendation fields before body rendering. Markdown prose is a projection of those records.
- Apply one bounded semantic-repair pass for missing/placeholder fields using the exact delta. If repair remains unavailable or uncertain, keep the finding but render a clear evidence/quality limitation; do not silently pass it as a polished section.
- Low/Informational sections may use a reduced schema, but security-impacting content cannot be discarded merely to satisfy brevity. Thinness by character count remains telemetry, not a validity decision.
- Report completion distinguishes structurally delivered, semantically complete, and degraded-delivery states. Haltless degradation is visible in the delivered report and final receipt.

Required fixtures: C/H/M code-trace-only confirmation; executed mechanism-only PoC; executed harm-scoped PoC; empty Impact heading; generic paraphrased Impact; missing recommendation; placeholder title; duplicate title/location but distinct mechanism; legitimate concise Low; repair success; repair failure -> delivered limitation; typed record/Markdown parity; final quality receipt states the correct assurance level.

### P1-L. L1 mode removes composition analysis on the false premise that node-client bugs are point vulnerabilities

Code/methodology evidence: `commands/plamen-l1.md`, `rules/skill-index.md`, `docs/l1-mode/design.md`, `docs/audit-modes.md`, `scripts/plamen_types.py`, and `test_chain_iter2_wiring.py` all encode or test the categorical assertion that L1 bugs are point vulnerabilities and Phase 4c therefore does not apply. The replacement is a minimal cross-domain tag harvester feeding isolated candidates to verification. That may avoid applying a DeFi-shaped postcondition matcher where it does not fit, but it also removes any independent reasoning over cross-subsystem sequences, timing/order dependencies, concurrency and scheduling interactions, upgrade/activation boundaries, validation-to-propagation effects, storage/rollback/reorganization state, or one finding changing the reachability/impact of another. Those are composition questions even when they are not DeFi enabler chains.

Fix contract:

- Do not copy the SC chain prompt into L1. Add a conditional L1 composition phase over a typed cross-subsystem interaction graph: finding/state/event/actor/timing/concurrency/activation facts become nodes and dependency, ordering, shared-resource, validation-propagation, rollback, and trust-boundary relations become edges.
- Mechanically enumerate only compatible cross-layer/cross-domain edges from existing inventory, call/state graph, subsystem map, lifecycle facts, and depth summaries. Hub/fan-out nodes produce bounded family obligations rather than an all-pairs Cartesian product.
- Give the L1 composer full source/context slices for each bounded packet and require exact input-to-disposition coverage. A new combined-impact or reachability claim becomes a distinct compound candidate and enters independent verification under the same P0-AF proof-scope rules; constituent evidence cannot prove composition.
- Run only in Core/Thorough when the typed graph contains compatible unresolved edges. Empty graph -> deterministic `NOT_TRIGGERED`; budget exhaustion -> exact report-visible coverage debt. This is injectable/conditional and does not add SC prompt bloat.
- Treat the existing cross-domain tag harvester as a generator feeding this phase, not as an adequate substitute for composition judgment.

Required fixtures: two individually valid L1 findings with a typed cross-subsystem dependency; validation-to-propagation sequence; timing/activation boundary; shared-resource or concurrency ordering; storage rollback/replay dependency; same-root restatement that must not become a chain; incompatible layers; one constituent refuted; both constituents confirmed but composition unreachable; composed mechanism confirmed with harm still unproven; hub fan-out bound; Go, Rust, and mixed-client graphs; Core/Thorough conditional trigger; exact tail coverage; resume/invalidation; verifier and report lifecycle parity. Acceptance requires a held-out L1 A/B showing recall gain without unacceptable fragmentation--the categorical removal should be rejected now, but always-on deployment still needs evidence.

### P1-M. The arm-before-trust / mutual-zero methodology extension is directionally sound but its current implementation does not prove application

Evidence and current-diff review: `Plamen_ArmBeforeTrust_Methodology_Coverage_Input_2026-07-16.md` establishes a genuine generic methodology gap: no always-on operator jointly asks whether an authentication anchor can remain at its zero/empty default while verification is operational and whether a degenerate input can derive to that same default and be accepted. The dirty worktree adds the paired question to the signature niche, adds an EVM oracle-authentication row, and adds `_mutual_zero_roles()` plus chain-prompt language. The direct positive and fail-closed/armed negative unit fixtures pass the intended logical shape.

That is not yet end-to-end application evidence. The role matcher classifies free-form inventory prose with finite regexes, while its strongest positive fixtures hand-author `AUTH_ANCHOR_ROLE` and `DERIVED_IDENTITY_ROLE` vocabulary that no typed producer contract currently requires. The methodology-presence tests grep source files but do not prove the exact live breadth/depth/niche prompt contains the operator or that an ordinary Claude artifact emits consumable role facts. The cross-boundary probe required by the handoff is absent. The composition test stops at `chain_candidate_pairs.md`; P0-AF has independently proven that a new `CH-*` claim does not currently enter verification, so “survives to verification” is false under the frozen architecture. Finally, the shared `chain_prep.py` and shared chain prompts were changed before the handoff's >=2-repository/>=2-ecosystem validation gate, even though the governance note required EVM-first deployment before cross-tree generalization.

The frozen Claude dispatch confirms the reachability concern on a real Thorough run. Across 63 exact `_prompt_*.md` dispatches, only `chain_agent2` and `chain_iter2` contain `mutual-zero`; zero dispatches name `signature-verification-audit/SKILL.md`, zero name `generic-security-rules.md`, and zero contain the new `Authentication armed`, `paired boundary`, `fail-closed until the anchor is armed`, or `zero-derived identity` text. Recon mentions the signature skill token, but no actual analysis-worker prompt dispatches its file. More strongly, recon's exact first-attempt prompt states that the mechanical `HAS_SIGNATURES` flag was detected and the niche is required, while both emitted recommendation matrices and the downstream spawn manifest retain `SIGNATURE_VERIFICATION_AUDIT` as `Required=NO`; no signature worker was launched. That is the P0-A/P0-AD selection-to-application defect exercised on this exact methodology. The oracle breadth worker instead dispatches `oracle-analysis/SKILL.md`, which was not extended by this change. Prompt hashes: oracle breadth `C99289346F2282E92F5AE50292FB4129E9820B50AEF52E7B9138A40ADFDD9F2E`; chain Agent 2 `25971DA051841ABFF336C502B3D6F7A132AE491DD79C6DE1C08E6E76027E4358`; chain iteration 2 `9639A734DA99FB08E4C4EBC768092CF06EB5085298BE115F7B79C1240A91E7DB`. This does not prove the operator would never be reachable on another trigger set; it proves the current canary's only live application is the downstream chain nomination text, not either discovery producer that must generate the two halves.

Fix contract:

- Keep the generic paired operator; it is a real recall improvement, not a protocol-specific check. Compile it through P0-AI so the active EVM consumer and its exact dispatch hash are provable rather than inferred from file presence.
- Emit typed authentication-role facts from the applicable discovery operator: anchor identity/default, arming and de-arming paths, operational-while-unarmed reachability, degenerate input domain, derived identity, accept/reject result, privileged effect, evidence locations, and in-scope/external provenance. Regex over prose remains a compatibility nominator, never the authoritative role decision.
- Generate a mutual-zero composition obligation only when both complementary positive facts exist and neither has an armed/inert or fail-closed refutation. Preserve each half as an independent identity; the composer judges the conjunction and P0-AF gives any combined-impact claim its own verifier work item.
- For an out-of-scope authenticator, emit a typed external-premise/dependency-research obligation without claiming the external system is unarmed. R10 governs retention if a later discriminator attempts a best-case unsupported demotion.
- Hold shared/non-EVM activation behind the documented >=2 repositories across >=2 ecosystems gate. Until then, EVM activation may use the shared implementation only behind an ecosystem selector with explicit NOT_TRIGGERED receipts elsewhere.

Required fixtures: the handoff's different-vocabulary positive pair; ordinary untagged Claude-style prose; missing one half; atomically armed/inert-until-armed anchor; fail-closed zero derivation; de-arming rotation; zero threshold/empty set; exact live EVM prompt reachability and operator receipt; signature niche triggered and not triggered; always-on EVM oracle path; out-of-scope authenticator -> external research obligation; combined candidate -> distinct `CH-*` verification work item; constituent proof cannot certify composition; prompt/role digest mismatch; resume idempotency; Part-0 scan; at least two repositories across two ecosystems before non-EVM activation; held-out recall/noise A/B rather than the motivating example.

## 5. Priority-1: reconciliation/parser correctness

### P1-H. Self-exclusion parsers re-emit context and already-accounted rows

Live evidence: per-contract re-emission created 11 contentless candidates from source-list prose, an `Exclusion Universe` section, a table header, and already-referent-bound rows. Depth re-emission created five more from a header, plain canonical IDs not recognized as referents, and an N/A negative-control row.

Fix contract:

- Prefer typed exclusion records: candidate ID, status, referent IDs/locations, evidence basis, external premise.
- Legacy parser is section/header scoped, excludes universe/context sections, skips table headers, recognizes bracketed and plain canonical IDs, groups continuations, and distinguishes no-candidate/N/A rows from actual drops.
- Substantive referent-less exclusions still re-emit; no candidate is lost.

Required fixtures mirror every live false positive plus a true referent-less drop, a content-bearing drop, multiple referents, continuation rows, and idempotent replay.

### P1-I. Citation syntax rejects resolvable Claude output

Live evidence: Claude commonly emits `file:42`; the current application validator accepts only `file:L42`.

Fix contract: normalize an in-root existing `file:line` citation to canonical `file:Lline`; reject nonexistent, out-of-root, ambiguous, or malformed paths. Typed source locations are preferred. Required fixtures cover Windows/POSIX paths, spaces, colons, traversal, line zero, line beyond EOF, and both canonical forms.

### P1-J. Recon signal stripping deletes structured authority

Live evidence: a recon shard emitted `PLAMEN_SIGNALS`, but `_strip_recon_worker_markers()` removed every `PLAMEN_*` line from the canonical recommendation artifact. Prose fallback could then treat Required=NO rows as selected.

Fix contract: preserve and validate structured signals; strip only transport/status markers; make structured signal/table data authoritative and use section-scoped fallback. Fixtures cover YES/NO rows, malformed signals, duplicate signals, worker metadata, and no-signal legacy output.

## 6. Priority-2: runtime cost, containment, and representation

### P2-A. Fuzz workspace is incompletely snapshot-bound

Live evidence: generated `.t.sol` and `.medusa-tests` files are excluded from snapshot tracking; pre-existing user tests can therefore affect execution without being bound into the run evidence.

Fix contract: use an isolated driver-owned fuzz workspace, snapshot/hash all pre-existing relevant tests/configuration, and bind generated harness hashes plus tool versions/commands/results. No user test is silently trusted or overwritten.

### P2-B. Raw logs and unbounded assurance ledgers consume excessive context

Live evidence: Medusa consumed roughly 215k cache-read input and emitted a 54KB artifact; checklist/perturbation sidecars used Opus-class execution despite being described as mechanical/low-cost.

Report-stage live evidence: the client report reached 937,456 bytes because 7,546 chain-debt rows were inlined. The Sonnet `report_dedup_agent` spent the full 900-second PTY deadline on attempt 1 and produced no decision artifact, forcing a whole-phase retry. Attempt 2 then had to rediscover the original methodology and re-read the same report/candidate inputs. Thus representation bloat is not only cosmetic: it directly consumes the discriminator's bounded reasoning window and converts a deterministic coverage ledger into repeated model work.

Fix contract: deterministic bounded result manifests, raw logs and full debt ledgers as hashed evidence sidecars, digest-bound bounded projections for model/client consumption, deterministic checklist closure where possible, and job-specific model selection when LLM judgment remains. Model packets declare exact denominators and retrieve only decision-relevant records in bounded shards; truncation/budget exhaustion is loud and preserves every unresolved identity in the authoritative sidecar.

### P2-C. Markdown is being used as an operational database

Verdict: do not begin a full ledger migration. Introduce typed sidecars only at drift boundaries: skill/consumer coverage, application/skeptic state, obligations, evidence scope, exclusion records, and alias-preserving candidate families. Dual-write Markdown projections and prove parity before retiring any recovery path.

## 7. Implementation order after the frozen baseline

1. P0-AC/P0-AE/P0-AL/P0-AM/P0-AN/P0-AO typed gate/debt semantics, phase I/O and driver-owned child-work/runtime contracts, prompt compilation, FC4 removal/refactoring, ledger-bound report-ID privacy matching, enforceable foreground/transaction closure, stable-input/runtime namespace separation, and explicit non-destructive resume/new-run intent. Until semantic failures, contradictory output contracts, unjoined background work, backend runtime drift, silent restart, and false report-stage identity matches can no longer be laundered as completion or degradation, later gates and regression results are not trustworthy.
2. P0-AD/P0-A typed skill selection plus selected-skill consumer closure. This closes the canary's reproduced false-selection bloat and genuine-selection non-application path together.
3. P0-0/P0-1/P0-2 producer delivery closure plus the shared typed producer registry; this closes reproduced found-on-disk/absent-downstream loss before any discriminator work.
4. P0-J candidate-on-candidate recursion removal; this restores the intended generator contract and frees bounded analysis/verification capacity without deleting first-pass candidates.
5. P0-AJ/P0-AK/P0-K/P0-L/P0-M/P0-X/P0-Y typed queue/projection parity, dynamic bounded verifier work planning, structured identity parity, exact discovery-to-inventory disposition closure, producer/discriminator separation, citation-repair routing, and semantic parser boundaries.
6. P0-AB typed state-symbol schema/alias parity and exact chain state-application receipts, before spending more chain budget on lower-specificity pairs.
7. P0-AF compound-chain promotion and independent verification; no new combined-impact claim may cross into report indexing by borrowing constituent proof.
8. P0-AI/P0-B/P0-C/P0-D compiled methodology reachability, per-row operator receipts, typed application state, active skeptic consumer, and unsupported-SAFE guard.
9. P0-AG/P0-AH/P0-P/P0-V direction-neutral, premise-bound severity adjudication, Thorough all-severity execution coverage, and independently authored skeptic decisions; replace one-way matrix/blind-first/self-adjudicating authority while keeping severity independent from candidate retention.
10. P0-E/P0-F/P0-I degradation delivery and exact input-to-disposition reconciliation.
11. P0-Z targeted semantic completion receipts and descendant invalidation, then P0-N/P0-O/P0-W resume-time recovery verification, evidence-scoped constituent demotion, and lossless alias-preserving chain grouping/repair.
12. P0-G/P0-H late-candidate verification and provenance-bound trust adjustments.
13. P0-Q/P0-R/P0-S/P0-T lossless semantic grouping, decision-authorized report disposition, applied-vs-proposed dedup receipts, and exact chain-tail closure.
14. P0-AA non-terminal dropout recovery and three-way identity/disposition/delivery closure; reuse the shared decision ledger and human-review delivery path rather than inventing a lexical exception.
15. P0-U report-index severity projection and unauthorized-downgrade restoration; share the P0-AG/P0-P/P0-V decision ledger rather than creating a second authority.
16. P1-H/P1-I/P1-J parser and signal correctness.
17. P1-C/P1-D/P1-M structured obligation and semantic-invariant receipts plus typed arm-before-trust role application, gated behind P0-AI/P0-AF and ecosystem evidence.
18. P1-A/P1-B generator anchoring, type domains, and obligation staging.
19. P1-F/P1-G confidence/RAG separation and alias-preserving work cards.
20. P1-E/P1-K/P1-L/P2-A/P2-B proof-scope, typed report evidence quality, conditional L1 composition A/B, fuzz containment, and context bounding.
21. Focused suites -> full suite -> fresh Claude EVM -> clean resume -> fresh Claude non-EVM -> clean resume.

This order attacks both observed halves of the recall problem: P0-0/1 close proven pipeline loss; P0-A closes selected-skill consumer gaps; P0-AI closes live prompt/compiler methodology reachability and context-application gaps; P0-B/C/D close applied-but-wrongly-cleared work before findings can vanish. P0-J removes capacity-consuming recursive noise before corrected end-to-end measurement. Later waves reduce generator and evidence noise without deleting recall-bearing identities.

## 8. Claims deliberately not made

- This one canary does not prove recall improvement.
- Passing unit tests does not prove whole-pipeline application.
- The R10 regression repository is not a held-out benchmark.
- No competitor superiority claim is valid without the neutral governed corpus.
- P0-P5 comparative scoring remains pending the external B1 corpus, authorities, secure launcher, and adapter.
- No merge, push, install, or cutover is authorized by this artifact.
