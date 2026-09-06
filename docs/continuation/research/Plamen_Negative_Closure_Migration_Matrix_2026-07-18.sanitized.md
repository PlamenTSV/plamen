# Plamen negative-closure migration matrix

Date reviewed: 2026-07-19  
Requested artifact name: `Plamen_Negative_Closure_Migration_Matrix_2026-07-18.md`  
Repository reviewed: `<LOCAL_USER_ROOT>\plamen-codex-implementation`

## Executive verdict

Negative-decision authority is not yet centralized. The current branch has the beginning of the right abstraction in `scripts/negative_closure_policy.py`, and `candidate_negative_authority.adjudicate_candidate_negative` now uses it to reopen exact candidate-negative agreements that lack provider authority. That protection is local to one path. Several later consumers can still terminally exclude, demote, suppress composition, or consolidate a discovered claim using evidence that the new policy correctly classifies as supporting-only.

The highest-risk split is:

1. `candidate_negative_authority` says source citations, external citations, model agreement, and an ordinary in-scope execution are nonterminal;
2. `application_skeptic`, `inventory_reconciliation`, `finding_lifecycle_authority`, and `report_disposition_authority` can still accept those same evidence shapes as terminal;
3. `compound_verification` and `l1_composition_authority` can suppress compound work from a typed but not necessarily executed refutation;
4. legacy promotion/report machinery still contains lexical negative paths that act before the central policy.

This is a structural source of wrong-safe recall loss. Fixing only R10 or only the candidate-negative wrapper cannot close it.

The clean invariant should be:

> Every discovered, content-bearing security claim remains active until exactly one centralized, replayable negative-closure provider authorizes terminal scope exclusion, proves a lossless applied equivalence to a live survivor, or authenticates exhaustive negative execution over the full claim and harm premise. Everything else reopens to mandatory verification or remains visible human-review debt.

Under the pipeline's stated current invariant, source citations, external research, model analysis, a single failed PoC, bounded negative tests, and unauthenticated “full claim” labels are supporting evidence only. They must not independently authorize `REFUTED`, `FALSE_POSITIVE`, zero-harm relocation, composition suppression, or a severity decrease.

## Proposed centralized contract

Expand `negative_closure_policy.py` from its current application-skeptic-shaped helper into a subject-neutral pure policy. Do not duplicate evidence rules in each consumer.

Suggested semantic input:

- subject identity and immutable content digest;
- lineage and exact premise IDs, including the harm premise;
- proposed action: `EXCLUDE_SCOPE`, `REFUTE`, `ZERO_HARM_NONBODY`, `ALIAS`, `SEVERITY_DECREASE`, or `SUPPRESS_COMPOSITION`;
- source phase and independent discriminator identity;
- supporting evidence claims, which never self-authorize;
- provider receipt and provider-specific replay validator;
- current scope snapshot, current candidate denominator, and live-survivor state when relevant.

Suggested result:

- `AUTHORIZED_TERMINAL_SCOPE_EXCLUSION`;
- `AUTHORIZED_LOSSLESS_ALIAS`;
- `AUTHORIZED_EXHAUSTIVE_NEGATIVE_EXECUTION`;
- `REOPEN_MANDATORY_VERIFICATION`;
- `RETAIN_VISIBLE_HUMAN_REVIEW`;
- `CONFLICT_DEBT`.

Only these provider families should be terminal under the current design principles:

1. `MECHANICAL_SCOPE_EXCLUSION`: a deterministic scope predicate replayed against a hash-bound scope snapshot. No model-issued scope label qualifies.
2. `APPLIED_LOSSLESS_EQUIVALENCE`: an applied transformation receipt proving the absorbed bytes/semantic fields and lineage are preserved under one current, live survivor; no cycles, stale survivor, or proposal-only merge.
3. `AUTHENTICATED_EXHAUSTIVE_NEGATIVE_EXECUTION`: provider-observed execution, exact subject/premise/harm binding, explicit complete domain or mechanically proven exhaustive coverage, independent oracle, immutable results, and no conflicting evidence. An ordinary or single failed PoC is not exhaustive.

`FORMAL_PROOF` should remain nonterminal unless the project explicitly changes its “only executed PoCs are proof-grade” invariant and implements a real proof-provider validator. Merely naming `FORMAL_PROOF` in a JSON record is not proof authority.

## Migration matrix

| Priority | File / function | Current negative or destructive authority | Recall / precision risk | Required centralized-policy hook | Red-to-green fixtures | Order |
|---|---|---|---|---|---|---|
| P0 | `scripts/application_skeptic.py:697` `adjudicate_application_skeptic` | `AGREE_NEGATIVE` becomes `NEGATIVE_AGREEMENT` when basis is `IN_SCOPE_SOURCE`, `IN_SCOPE_EXECUTION`, or `PRIMARY_EXTERNAL_CITED` and a digest exists. | Direct contradiction with the new policy: citation-shaped evidence and ordinary execution can close methodology non-application. This is the broad generic path, not just candidate-negative proposals. | Call the central policy for every `AGREE_NEGATIVE`. Supporting-only evidence must synthesize/reuse the deterministic candidate seed and emit `REGISTRY_CANDIDATE_PROPOSED`; unavailable seed becomes visible debt, never agreement. | `test_source_supported_agreement_reopens_generic_application_candidate`; `test_external_citation_reopens_generic_application_candidate`; `test_single_execution_reopens_generic_application_candidate`; `test_provider_valid_exhaustive_negative_can_close_generic_application_candidate`. | NC-1 |
| P0 | `scripts/candidate_negative_authority.py:1101` `adjudicate_candidate_negative` | Current local hook reopens unsupported exact negatives. Derived/conflicted/producer-unresolved identities become debt. Provider adapters are not implemented. | Direction is correct, but it is not yet a complete authority: no typed provider ledger, no exhaustive provider, and no mandatory-verification receipt. Local pre-transformation can drift from other consumers. | Retain this as the first caller, but move all policy semantics and authority validation into the central module. Bind the returned policy decision and provider receipt into `candidate_negative_denominator.json`. | Existing supporting-evidence reopen fixtures plus `test_candidate_negative_denominator_binds_policy_decision_digest`; `test_candidate_negative_terminal_provider_replays`; `test_candidate_negative_stale_provider_reopens`. | NC-1 |
| P0 | `scripts/inventory_reconciliation.py:524` `_validate_negative_authority`; `:598` `_authority_disposition` | A distinct decision/evidence provider, source-bound JSON record, `REFUTED`, `IN_SCOPE_SOURCE` or `IN_SCOPE_EXECUTION`, `proof_scope=HARM`, a file:line pointer, and hashes authorize `AUTHORIZED_REFUTATION`. | The record proves shape and provenance, not truth, independence of the oracle, exhaustive coverage, or full-premise refutation. A model-authored source analysis or bounded test can erase a raw discovery identity before verification. | Replace local semantic acceptance with central provider replay. Existing record becomes supporting evidence. Only mechanical scope exclusion or authenticated exhaustive negative execution may return `AUTHORIZED_REFUTATION`; otherwise retain content-bearing inventory review and emit a mandatory-verification candidate. | `test_inventory_source_bound_analysis_cannot_authorize_refutation`; `test_inventory_single_execution_cannot_authorize_refutation`; `test_inventory_exhaustive_execution_provider_can_authorize_refutation`; `test_inventory_failed_provider_replay_retains_source_block`. | NC-2 |
| P0 | `scripts/finding_lifecycle_authority.py:421` `_decision_authorization_reason`; `:1230` `authorized_finding_exclusions` | `REFUTED` and `AUTHORIZED_ZERO_HARM` accept `INDEPENDENT_EXECUTION`, `FORMAL_PROOF`, or `INDEPENDENT_ANALYSIS` with `FULL_CLAIM`; exclusion is then terminal. | This is the intended central lifecycle, but today a self-declared evidence basis and proof scope are sufficient. `INDEPENDENT_ANALYSIS` is explicitly nonterminal under the new policy; a non-exhaustive execution is also insufficient. Every report gate inherits this over-grant. | Make lifecycle decisions carry a central policy decision ID and validated provider receipt digest. Remove direct basis-name authorization. Rejected terminal decisions must create `RECOVERY_INDEPENDENT_VERIFICATION` plus visible retention. `AUTHORIZED_ZERO_HARM` must use the same negative authority as exclusion. | `test_lifecycle_independent_analysis_refutation_reopens`; `test_lifecycle_formal_label_without_provider_reopens`; `test_lifecycle_nonexhaustive_execution_reopens`; `test_lifecycle_mechanical_scope_exclusion_terminal`; `test_lifecycle_exhaustive_negative_execution_terminal`; `test_lifecycle_zero_harm_requires_terminal_provider`. | NC-2 |
| P0 | `scripts/report_disposition_authority.py:324` `_decision`; `:431` `build_report_disposition_authority`; `:668` `authorized_nonbody_internal_ids` | A provider-observed verifier launch/output receipt plus a parsed verifier status is converted to a lifecycle decision with `evidence_basis=INDEPENDENT_ANALYSIS` and `proof_scope=FULL_CLAIM`. `REFUTED` is excluded; selected zero-harm statuses can be Appendix authority. | The execution receipt authenticates that the verifier ran and wrote bytes; it does not prove the negative conclusion, the stated full scope, or an oracle. This is the most consequential downstream wrong-safe seam because it turns verifier prose into terminal authority. | Treat verifier negative/zero-harm output as a proposal and supporting evidence. Ask the central policy for a provider-backed terminal decision. If denied, retain BODY/HUMAN_REVIEW and create a mandatory re-verification obligation tied to unresolved premises. | `test_report_verifier_refuted_prose_without_negative_provider_stays_body`; `test_report_verifier_zero_harm_analysis_without_provider_stays_visible`; `test_report_exhaustive_negative_provider_authorizes_excluded`; `test_report_stale_launch_or_provider_never_excludes`. | NC-2 |
| P0 | `scripts/compound_verification.py:719` `evaluate_compound_work_item`; `:906` `bind_compound_report` | `is_typed_composition_refutation` needs one typed false fact but not `executed`, command/result digests, exhaustive coverage, or proof-grade status. `bind_compound_report` excludes when a matched refutation exists even if `proof_grade=False`. | A model- or adapter-authored boolean can eliminate a distinct composition finding. “Could not observe combined harm” is not proof that the composition is impossible. | Route composition refutations through central policy with exact composition/harm premises. Without authenticated exhaustive negative execution or deterministic reachability exclusion, disposition is `HUMAN_REVIEW` and the compound stays queued. Require terminal exclusion to imply proof-grade provider validation, not merely a matched record. | `test_compound_unexecuted_refutation_is_human_review`; `test_compound_single_negative_execution_is_nonterminal`; `test_compound_exhaustive_ordering_exclusion_can_refute`; `test_compound_refuted_result_without_proof_grade_cannot_bind_exclusion`. | NC-3 |
| P0 | `scripts/l1_composition_authority.py:207` `_pair_eligible`; `:224` `enumerate_l1_composition_graph` | Any fact with `candidate_state=REFUTED` is excluded from pair enumeration, and the graph records `REFUTED_CONSTITUENT` suppression. | The fact schema validates shape, not terminal negative authority. A wrong-safe constituent prevents entire cross-subsystem bug classes from ever being composed. | Facts must carry a validated central negative-closure decision digest before `REFUTED` can suppress composition. Unbacked refuted state is normalized to `UNRESOLVED` for enumeration and creates debt. | `test_l1_unbacked_refuted_constituent_remains_composition_eligible`; `test_l1_mechanical_scope_excluded_constituent_can_suppress_pair`; `test_l1_stale_negative_decision_reopens_composition`; `test_l1_refutation_suppression_denominator_is_exact`. | NC-3 |
| P0 | `scripts/plamen_mechanical.py:5017` `_promo_shape_ok`; `:5267` `_promo_disposition`; `route_promotion_orphans` | Lexical no-finding/safe blocks can be rejected by the harvester; lexical refuted/false-positive blocks are routed directly to Appendix A; classifier zero-harm results go Appendix C. | Gate P is the recovery net for found-then-lost findings. Letting the same producer/verifier prose suppress that recovery defeats its purpose and can hide the exact miss class it should rescue. | Harvest negative-shaped content as a negative proposal, not a non-candidate. Route through central policy. Unsupported negatives become `BODY/NEEDS_VERIFICATION` or content-bearing human-review debt. Appendix A/C only after central authority. | `test_gate_p_safe_prose_is_harvested_as_negative_proposal`; `test_gate_p_refuted_prose_reopens_without_provider`; `test_gate_p_zero_harm_classifier_is_veto_only`; `test_gate_p_terminal_scope_provider_allows_appendix_a`. | NC-2 |
| P0 | Reopened-candidate route across `finding_producer_registry.py`, `plamen_validators.py:5970` `_promote_depth_findings_to_inventory`, `plamen_parsers.py:4645` `_dedup_queue_by_hypothesis`, and verifier roster construction | A valid ASKP projection usually reaches inventory and the queue, but it has no typed `verification_required` authority. Promotion may defer negative/status, low-confidence, or contentless records; semantic/chain grouping can replace its standalone identity with a representative hypothesis. | “Reopened” does not currently mean “this exact premise must be independently verified.” A grouped verifier can reason about another constituent, and a future score/status change can send the reopen to debt rather than verification. | Add a `negative_reopen` receipt with candidate/premise/harm IDs and `mandatory_verification=true`. It bypasses confidence/mode/materiality filters. Dedup is allowed only if the live survivor's verifier packet losslessly contains the exact reopened premise. Queue plan and verifier completion receipts must prove one exact disposition per reopen ID. | `test_reopened_negative_bypasses_promotion_confidence`; `test_reopened_negative_survives_hypothesis_grouping_with_exact_premise`; `test_reopened_negative_has_unique_verifier_work_or_lossless_survivor`; `test_reopened_negative_missing_verify_output_is_pipeline_debt`; `test_reopened_negative_cannot_reach_report_before_verify`. | NC-5 |
| P1 | `scripts/plamen_parsers.py:6303` `_parse_chunk_heading_inventory`; `:6394` `_parse_chunk_table_inventory`; `:10864` `_non_reportable_marker` | Lexical non-reportable markers can synthesize `Severity=Informational` and `Verdict=REFUTED`. Negation guards reduce false fires but the parser still assigns semantic authority. | Encoding/parser tolerance should not decide claim truth or severity. New wording can still false-fire; even true parsing is only a producer proposal. | Parser emits exact `negative_proposal` telemetry while preserving upstream severity and content. Central policy/lifecycle decides later. Keep lexical cues only for harvesting and work routing. | `test_inventory_parser_refuted_marker_preserves_severity`; `test_inventory_parser_false_positive_marker_is_proposal_only`; `test_inventory_parser_negated_and_quoted_history_never_demotes`; `test_inventory_parser_conflicting_negative_fields_become_debt`. | NC-1 |
| P1 | `scripts/plamen_validators.py:5970` `_promote_depth_findings_to_inventory` | Non-reportable origin status is skipped; score below 0.70 for ordinary FINDING producers is deferred; contentless candidates are deferred. | Negative status may be the wrong-safe error being repaired. Thresholding before the independent verifier can prevent a reopened finding from receiving its first proper discrimination. | Consult central policy output. `REOPEN_MANDATORY_VERIFICATION` must bypass all confidence and origin-negative filters. Ordinary low-confidence positives may remain current policy if their content is retained as debt. | `test_mandatory_reopen_ignores_origin_refuted`; `test_mandatory_reopen_ignores_depth_score_threshold`; `test_nonmandatory_low_confidence_remains_visible_debt`; `test_malformed_reopen_cannot_disappear`. | NC-5 |
| P1 | `scripts/plamen_mechanical.py:10303` `_write_mechanical_report_index` | Any non-reportable verifier status is immediately placed in Excluded Findings. It also auto-consolidates groups of three by a derived signature. | The later typed report gate helps, but the destructive projection is already built from prose. Auto-clustering can combine sibling causes and hide independent identities before authority is checked. | Builder defaults every queue identity to BODY/HUMAN_REVIEW. Apply non-body/alias outcomes only from centralized lifecycle decisions and applied alias receipts. Signature clusters are proposals only. | `test_mechanical_index_refuted_without_authority_stays_body`; `test_mechanical_index_signature_cluster_is_proposal_only`; `test_mechanical_index_applied_alias_can_consolidate`; `test_mechanical_index_exact_denominator_survives_all_statuses`. | NC-3 |
| P1 | `scripts/report_index_machinery.py:264` `validate_report_index_actions_json`; `:359` `render_report_index_markdown` | The LLM may choose `MERGE_INTO`, `APPENDIX_ONLY`, and several `DROP_*` actions; validation checks schema/referents, then renderer excludes or consolidates. | This optional renderer is structurally capable of acting on writer proposals before negative/alias authority. Later no-ship gates are defense in depth, not a safe primary application boundary. | Convert actions to proposals. Before rendering, join every non-body action to a central lifecycle decision or applied alias. Unauthorized actions render BODY/HUMAN_REVIEW and explicit debt. | `test_driver_renderer_drop_action_without_authority_is_retained`; `test_driver_renderer_merge_requires_applied_alias`; `test_driver_renderer_authority_join_is_content_digest_bound`; `test_driver_renderer_unknown_or_stale_authority_fails_recall_safe`. | NC-3 |
| P1 | `scripts/plamen_parsers.py:4645` `_dedup_queue_by_hypothesis` | Many inventory rows can collapse to one hypothesis ID; title/severity/location are represented by one row plus constituent IDs. | This is not a terminal drop, but it can erase premise-level verifier attention. It is especially unsafe for reopened negatives because the verifier may test the aggregate or a different constituent. | Treat grouping as scheduling compression only. Require a lossless verifier input packet containing each constituent's mechanism/harm/premise and an exact completion disposition per constituent. Central alias authority is required only if identities become terminally consolidated. | `test_hypothesis_queue_packet_contains_every_constituent_premise`; `test_hypothesis_verifier_completion_covers_each_constituent`; `test_reopened_constituent_cannot_be_covered_by_group_label_only`; `test_group_failure_requeues_exact_constituents`. | NC-5 |
| P1 | `scripts/plamen_validators.py:26879` `_apply_poc_fail_demotions` | A failed PoC with P1-E negative-disposition eligibility and scope receipts can cap severity; grouped caps have additional scope guards. | A failed witness normally proves only that one attempt did not establish its assertion, not that likelihood or impact is lower. Even exact subject binding is not exhaustiveness. This can reproduce wrong-safe demotion while retaining the finding. | Add a central `SEVERITY_DECREASE` policy. Non-exhaustive negative execution becomes challenge/reverification and preserves upstream severity. Only exhaustive negative execution or another explicit mechanically justified severity premise may lower it. | `test_single_failed_poc_does_not_cap_severity`; `test_exact_but_nonexhaustive_group_failure_preserves_severity`; `test_exhaustive_negative_execution_can_cap_bound_premise`; `test_failed_poc_and_positive_trace_conflict_preserves_higher_severity`. | NC-4 |
| P1 | `scripts/severity_decision_ledger.py` `build_severity_decision` / `adjudicate_severity_challenge` | Recent design is typed and non-dropping, but model/provider records can label impact or likelihood premises `REFUTED`; resolved changes depend on evidence-receipt binding rather than the centralized terminal-negative policy. | Good containment exists, but negative premise truth can drift from the global rule and R10 covers only one external-assumption subclass. | Keep the typed ledger; require central policy decisions for any downward resolution based on refuted premises. Supporting-only negative evidence yields `RETAINED_REFUTED_PREMISE` at upstream severity plus re-verification. | `test_severity_refuted_premise_without_terminal_provider_preserves_upstream`; `test_severity_external_citation_is_supporting_only`; `test_severity_terminal_provider_is_premise_and_harm_bound`; `test_severity_conflict_is_monotonic_recall_safe`. | NC-4 |
| P1 | `scripts/plamen_validators.py:27703` `_apply_external_assumption_undemotions` | R10 reopens a narrow class of uncited best-case external demotions, with several conservative guards. | Valuable defense, but it is a lexical specialization after the verifier decision. It cannot cover wrong-safe internal reachability, trust, economics, timing, scope, or invariant assumptions. It also cannot raise an under-rated upstream severity. | Retain R10 as a detector that emits premise/evidence claims into the centralized severity/negative policy. It should not be a separate source of truth. Generalize premise IDs and authority, not the cue list. | `test_r10_detector_feeds_central_premise_policy`; `test_internal_premise_wrong_safe_uses_same_policy`; `test_r10_cannot_override_valid_terminal_provider`; `test_r10_reopen_preserves_upstream_severity_floor`. | NC-4 |
| P1 | `scripts/plamen_mechanical.py:6094` `_dedup_report_python` | Agent-semantic or mechanical same-fix/source signals can merge report sections. A data-loss gate embeds absorbed text verbatim, but no finding-lifecycle applied-alias receipt is required at this report-level transform. | Content is mostly preserved, so recall loss is lower than semantic omission, but standalone identity and signal can be hidden; wrong grouping harms report precision and client actionability. | Reuse `APPLIED_LOSSLESS_EQUIVALENCE`. Emit a report-level applied alias receipt bound to pre/post report bytes and live survivor. Otherwise use a non-destructive group presentation with both standalone IDs. | `test_report_dedup_requires_applied_alias_receipt`; `test_report_dedup_verbatim_embedding_preserves_all_fields`; `test_report_dedup_wrong_semantic_proposal_keeps_standalone_sections`; `test_report_dedup_alias_survivor_must_remain_live`. | NC-3 |
| P2 | `scripts/semantic_dedup_authority.py:672` `write_applied_receipt`; `:899` `load_applied_aliases` | Applied merge authority requires exact pre/post identity delta, a matching proposal, a live survivor, conflicts absent, and field-complete preserved raw bytes. | This is the closest existing implementation of a legitimate terminal alias. The remaining risk is policy duplication and whether downstream verifier packets retain premise-level attention. | Make it the provider adapter for `APPLIED_LOSSLESS_EQUIVALENCE`; do not rewrite it. Add central-policy receipt binding and downstream premise-delivery checks. | `test_central_policy_accepts_current_applied_dedup_receipt`; `test_central_policy_rejects_stale_or_cyclic_alias`; `test_alias_verifier_packet_preserves_absorbed_premises`. | NC-3 |
| P2 | `scripts/plamen_parsers.py:3953` `_filter_verification_queue_by_mode` | Low/Info rows are removed from active verification outside Thorough and moved to an evidence-excluded sidecar. | This is an intentional cost/mode boundary, not evidence of safety. In Core/Light it can prevent first verification and later look like an exclusion. Thorough is unaffected. | Rename the route to `MODE_DEFERRED_HUMAN_REVIEW`; never grant terminal negative authority. Mandatory reopened candidates bypass it regardless of proposed severity. | `test_mode_filter_is_nonterminal_retention`; `test_mandatory_reopen_bypasses_mode_filter`; `test_thorough_filters_nothing`; `test_mode_deferred_identity_reaches_report_debt`. | NC-5 |
| P2 | `scripts/plamen_validators.py:20641` `_filter_verification_queue_by_evidence` | Current implementation retains all evidence-defective candidates and writes repair debt. | This is already recall-safe and should be preserved as a negative control during migration. | No semantic change. Add a central-policy regression proving location/source defects never become negative authority. | `test_evidence_defect_never_authorizes_negative_closure`; retain existing queue-evidence fixtures. | NC-0 |
| P2 | `scripts/plamen_validators.py:15124` `_backfill_report_coverage_dropouts`; `:15342` `_repair_report_index_dropouts` | Missing report identities are delivered to content-bearing human review or restored to body; typed non-body authority is required for exclusion. | Direction is correct. Human-review delivery closes delivery accounting but must not be mistaken for verification completion. | Bind retention receipts to lifecycle `REPORT_PROJECTION` only; keep verification obligations open when no verifier completion exists. | `test_dropout_human_review_does_not_close_verification_obligation`; `test_dropout_with_verify_completion_closes_only_delivery`; `test_dropout_repair_never_reconstructs_negative_from_prose`. | NC-5 |

## Is a reopened unsupported negative guaranteed mandatory verification today?

No. It is usually routed there, but the guarantee is not encoded end to end.

For a well-formed candidate-negative reopen on the current SC path, the intended route is:

`candidate_negative_skeptic_proposals.md` -> registered producer scan -> promotion into `findings_inventory.md` before semantic dedup -> chain/hypothesis processing -> `verification_queue.md` -> verifier shards.

The current projection gives the reopened candidate Medium severity, no negative verdict, an analytical scope, and an unproven harm marker. Because it normally has no depth-confidence entry, it ordinarily passes the promoter's threshold. In Thorough mode, the Low/Info mode filter also does not apply. Therefore the common happy path reaches verification.

That is not the same as a deterministic mandatory-verification invariant:

- the promoter can defer contentless, origin-negative, or explicitly low-scored records;
- parser or delivery failure produces debt, not a verifier work item;
- semantic dedup can alias the candidate;
- SC hypothesis dedup can replace its standalone queue identity with a grouped hypothesis;
- no receipt currently proves that the grouped verifier packet carried this exact reopened premise and harm;
- no exact reopen-denominator -> queue-plan -> verifier-completion reconciliation exists.

The material-harm report floor does not normally discard a valid ASKP reopen before verification in Thorough mode: it runs after report assembly. The dangerous pre-verification mechanisms are promotion thresholds/status handling, alias/group compression, and absence of an exact mandatory route. Gate P's own material/refutation classifier is a separate recovery path and can route its orphans to Appendix before verification, which is why it is P0 in the matrix.

Required invariant for NC-5:

> For every central-policy result `REOPEN_MANDATORY_VERIFICATION`, exactly one current verifier work item or one validated lossless-survivor work item contains every bound premise and harm ID; exactly one provider-observed completion disposition exists; and no confidence, severity-mode, lexical materiality, report, or grouping filter can satisfy or remove that obligation.

## Ordered implementation program

### NC-0 — Freeze negative controls and the pure policy

1. Preserve current safe behavior: evidence defects stay active; report dropouts stay visible; malformed authority fails recall-safe.
2. Generalize `negative_closure_policy.py` without wiring consumers.
3. Implement provider registries and pure replay validators with no imports from driver/report modules.
4. Freeze property tests: supporting evidence can never produce a terminal result; only validated provider kinds can.

Checkpoint: pure policy tests, existing candidate-negative tests, queue-evidence tests, lifecycle tests, strict JSON duplicate/nonfinite tests.

### NC-1 — Producer/parser and both application skeptics

1. Stop parsers from minting semantic refutation/severity changes.
2. Wire candidate-negative and generic application-skeptic through the same policy.
3. Bind policy decision receipts into both denominators/projections.
4. Keep containment and provider-observed assessor execution independent from negative truth authority.

Checkpoint: application-skeptic, candidate-negative, containment, producer-registry, promotion-parser, and PhaseIO suites.

### NC-2 — Inventory, lifecycle, report disposition, and Gate P

1. Migrate inventory refutation authority.
2. Make finding lifecycle the only downstream terminal decision ledger, backed by central policy decision IDs.
3. Convert verifier negative prose into proposals; remove `INDEPENDENT_ANALYSIS` as terminal report authority.
4. Make Gate P reopen negative-shaped orphan content instead of trusting/refusing lexical negatives.

Checkpoint: inventory reconciliation, lifecycle, report disposition, report dropout, Gate P, report no-ship, resume/stale-receipt, and adversarial mutation suites.

### NC-3 — Composition and all alias/dedup consumers

1. Prevent unbacked L1 `REFUTED` facts from suppressing pair enumeration.
2. Require provider-backed compound negative closure.
3. Register semantic dedup as the canonical lossless-equivalence provider.
4. Remove destructive report-index/report-dedup actions without applied authority.

Checkpoint: SC chain, L1 composition, compound verification, inventory/queue semantic dedup, report-index action renderer, report dedup, alias-cycle, and field-preservation suites.

### NC-4 — Severity-negative authority

1. Route all downward decisions through premise IDs and central negative authority.
2. Treat single/bounded PoC failure as re-verification evidence, not a severity cap.
3. Feed R10 detectors into the shared premise ledger.
4. Preserve upstream severity on missing, conflicting, stale, self-issued, or non-exhaustive evidence.

Checkpoint: P1-E, P0-O, severity ledger/adjudicator, R10/R10.1, external-research, grouped constituents, and report severity projection suites.

### NC-5 — Mandatory reopened-candidate delivery

1. Add the exact reopen denominator and queue-plan join.
2. Bypass confidence/mode/materiality filters for mandatory reopens.
3. Require premise-complete verifier packets through grouping/aliasing.
4. Reconcile provider-observed verifier completion and report delivery separately.

Checkpoint: fresh synthetic EVM and non-EVM fixture repos, resume from every boundary, worker timeout/crash, stale output, grouping, alias, report dropout, and clean-package suites. Only after these are green should the planned non-ground-truth canaries and final legacy-Claude Thorough audits run.

## Highest-priority defects

1. `report_disposition_authority._decision` currently converts authenticated verifier output bytes plus a prose status into `INDEPENDENT_ANALYSIS/FULL_CLAIM` terminal authority. This is the clearest remaining architectural form of “the verifier said safe for some reason.”
2. `finding_lifecycle_authority._decision_authorization_reason` accepts `INDEPENDENT_ANALYSIS` and a declared `FORMAL_PROOF` label as terminal refutation/zero-harm authority. Because downstream gates trust the lifecycle, this over-grant is systemic.
3. `inventory_reconciliation._validate_negative_authority` treats source-bound analysis or execution as a supported refutation without proving exhaustiveness or oracle validity, allowing loss before the normal verifier.
4. `application_skeptic.adjudicate_application_skeptic` still closes negatives that the candidate-specific wrapper now correctly reopens. The same methodology application can therefore receive opposite disposition depending on entry path.
5. Compound and L1 composition logic accept unexecuted/unbacked `REFUTED` state as reason to exclude composition work, creating a never-discovered downstream class from an upstream wrong-safe decision.
6. Gate P still lexically refuses or appendixes negative-shaped recovery candidates. A recovery gate must be more skeptical of negative producer prose than the normal path, not less.
7. A reopened candidate has no exact mandatory-verification lifecycle. It commonly reaches verify, but grouping, aliasing, parser/score drift, or delivery failure can substitute debt or representative-level reasoning.

## Scope and assumptions

- This was a bounded read-mostly review of the current working tree. No core/shared files, commits, pushes, installs, or audits were performed.
- The tree is under active implementation. Line numbers identify the reviewed state and may move; function names are the stable migration anchors.
- I treated a finding moved to a lossless, explicit human-review artifact as retained but not verified. Delivery accounting must not close verification accounting.
- I treated severity reduction as a negative decision even when the finding remains visible, because wrong-safe premise reasoning can materially damage recall scoring and client prioritization.
- I did not treat the current evidence-location queue filter or report-dropout retention as defects; they are included as negative controls that the migration must preserve.
- No target-specific vulnerability or exploit content is included.
