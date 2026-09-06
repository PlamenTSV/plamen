# Cut-4 transactional recon publication R2 amendment

Date: 2026-08-10
Status: Part-0 R2 architecture repair only
Supersedes: only the repaired clauses of
`architecture/cut4-transactional-recon-publication-amendment.md`
Authority: design for another independent review; no fixtures, production
implementation, cutover, G3, release, or audit-readiness authority

## 0. R2 decision

R2 retains the accepted core of R1:

- one DRIVER-owned, immutable, typed `_recon/prepass_seed/` namespace;
- one registry compiler that fixes every seed/provider/canonical path before
  execution;
- nonempty outcome/evidence/debt slots for each registered provider;
- one DRIVER `recon/canonical_merge` owner for the complete SC or L1 canonical
  tuple plus `recon_signal_transform_receipt.json`;
- no public glob or post-write discovery, no conditional repair marker, no
  provider/project-root mutation, and no zero-byte authority;
- deterministic encoding and sorted, alias-free walks;
- unchanged MODEL output identities, dependency work units, and public
  canonical filenames; and
- no edit or authority change to `scripts/artifact_ledger.py` or any G3 file or
  pin.

R2 repairs the three blockers in the authenticated R1 REPAIR review:

1. Private seeds are private from public publication and writes, not from
   MODEL reads. Every MODEL role receives a minimal exact seed/provider input
   set through the existing typed worker contract, prompt allowlist, prelaunch
   binding, and commit revalidation machinery.
2. Transactional publication applies only to fresh scratchpads. Existing
   legacy canonical bytes are not adopted, moved, deleted, overwritten, or
   called transactional authority. Legacy runs continue read-only under loud
   `LEGACY_COMPATIBILITY_DEBT`, or the operator starts a fresh run.
3. Marker/degrade/resume transforms use one exact typed request embedded in the
   already persisted configuration input. A changed configuration digest is a
   real ledger-bound input change; the canonical LaunchSpec profile remains
   static, and the ordinary same-key semantic reexecution history carries the
   request and snapshots. There is no request artifact, co-writer, or manual
   attempt key.

The ambiguous R1 69-node prose denominator is replaced by the closed 165-node
ID roster in section 9.

## 1. Authenticated repair basis

The mandatory review was read end to end and matched SHA-256
`3b6ff6ff20d2ac1aa6b7128cb0b5ddfe941b17a8bb8631d8f1021f48199078f5`:

`review_fixtures/cut4_transactional_recon_publication_amendment_independent_review_20260810.md`.

The R1 amendment and receipt remain frozen at:

- `architecture/cut4-transactional-recon-publication-amendment.md`:
  `98032f3fbd33987bf5ff4c6d035c088fe6eab34cc9c8b8425b2ff9280e19356e`;
- `review_fixtures/cut4_transactional_recon_publication_amendment_author_receipt_20260810.md`:
  `b49c79c450bf740fe437eefc957ca87f1dbf3424e1ee2fcb572c5d7abc159d15`.

The accepted V7 RED review remains bounded authority at
`c8e19b0f089b3e671e5191244aed2e56e277b20190b6db7d06087b1e4fd39223`.
R2 does not edit or reinterpret its bytes as production GREEN.

## 2. Closed ownership and order

Fresh transactional runs use this order:

```text
exact raw project/config inputs
       |
       v
recon/prepass (DRIVER; private typed seed/provider outputs)
       |
       +--> exact role-specific readable input sets
       |                  |
       |                  v
       |        recon/worker.* (MODEL; unchanged outputs)
       |                  |
       +--> unchanged dependency obligations/research/reconcile
                          |
                          v
recon/canonical_merge (DRIVER; sole canonical/transform owner)
                          |
                          v
existing instantiate/breadth consumers
```

Prepass and providers never write canonical names. MODEL workers cannot write
the seed namespace. Canonical merge does not read prior canonical files as
semantic inputs. Validation disposition is included unconditionally in the
transform receipt; R2 removes R1's redundant optional
`recon/supplementary_disposition` unit.

Legacy scratchpads never enter this graph. Section 6 defines their separate,
debt-bearing compatibility branch.

## 3. Seed visibility through current MODEL machinery

### 3.1 Contract binding

The role list, fanout count, models, prompts from `prompts/**`, and MODEL output
identities remain unchanged. The integration changes only runtime-generated
worker contracts and runtime-generated prompt readable-input blocks:

- `_recon_worker_jobs()` continues selecting the same jobs.
- `_typed_model_worker_contract_and_launch()` asks the shared recon registry
  for `model_inputs_for_role(role)`.
- `resolve_phase_io_contract(... phase="recon", work_unit_id="worker.*")`
  places those identities in `immutable_inputs` rather than the old public
  `contract_inventory.md`, `function_list.md`, `state_variables.md`, and
  `meta_buffer.md` lookup set.
- Every seed/provider identity gets an `InputAuthorityRequirement` for the
  exact same-run `<dimensions>/recon/prepass` producer, writer DRIVER, and exact
  contract/launch authority.
- `_prepare_typed_model_worker_launch()` uses the existing
  `_bind_typed_model_worker_inputs()` -> `record_work_unit_inputs()` ->
  `validate_work_unit_inputs()` sequence before the model starts.
- `_record_typed_model_worker_artifact()` revalidates the same bound inputs
  before the MODEL output commit.

Missing, stale, tampered, wrong-owner, wrong-run, incomplete, or extra role
inputs are launch-blocking debt. The model may never fill the gap by reading an
unbound public file. The private paths are read-only to MODEL and writable only
by the prepass DRIVER transaction.

The dynamically built worker prompt gets a generated `Bound Prepass Evidence`
section containing exactly the contract identities and absolute scratchpad
paths in registry order. Static methodology prompt files remain byte-unchanged.
The generated block says each provider evidence/debt file is evidence or
limitation, never proof a provider ran or a safe conclusion.

### 3.2 Exact role-to-seed mapping

All paths below are under `_recon/prepass_seed/`. `providers:*` means the exact
outcome/evidence/debt triple for every registry provider applicable to the
selected ecosystem; it is expanded to concrete identities before binding.

| MODEL role | Exact readable seed/provider inputs | Recall responsibility |
|---|---|---|
| SC `build_static` | `plan.json`, `source_capture.json`, `build_evidence.json`, `tool_coverage.json`, `providers:build` | Build/capability facts, exact failures, and all rejected build-provider fragments. |
| SC `design_context` | `plan.json`, `source_capture.json`, `base_evidence.json`, `design_evidence.json`, `dependency_seed.json`, `mechanical_graph.json`, `render_seed.json`, `providers:graph` | Purpose/trust/dependency/invariant context grounded in captured rows and graph limitations. |
| SC `inventory_surface` | `plan.json`, `source_capture.json`, `base_evidence.json`, `mechanical_graph.json`, `niche_findings.json`, `tool_coverage.json`, `providers:graph`, `providers:scanner` | Contracts/functions/state/setters/disclosures, entry points, graph edges, niche rows, scanner evidence/debt. |
| SC `templates_patterns` | `plan.json`, `source_capture.json`, `base_evidence.json`, `template_pattern_evidence.json`, `mechanical_graph.json`, `niche_findings.json`, `tool_coverage.json`, `providers:all` | Pattern and skill signals see every accepted row and every provider limitation. |
| SC light `context_static` | union of `build_static` and `design_context` | No evidence removed by role combination. |
| SC light `inventory_templates` | union of `inventory_surface` and `templates_patterns` | No inventory/niche/provider row removed by role combination. |
| L1 `l1_threat_fork` | `plan.json`, `source_capture.json`, `base_evidence.json`, `design_evidence.json`, `mechanical_graph.json`, `dependency_seed.json`, `providers:graph` | Threat/fork/state-transition evidence and graph debt. |
| L1 `l1_subsystem_scope` | `plan.json`, `source_capture.json`, `base_evidence.json`, `design_evidence.json`, `mechanical_graph.json`, `providers:graph` | Full captured subsystem/source denominator and unread/unresolved debt. |
| L1 `l1_attack_trust` | `plan.json`, `source_capture.json`, `base_evidence.json`, `design_evidence.json`, `mechanical_graph.json`, `niche_findings.json`, `providers:scanner` | Attack/trust/privilege surfaces plus scanner/niche limitations. |
| L1 `l1_build_static` | `plan.json`, `source_capture.json`, `build_evidence.json`, `tool_coverage.json`, `providers:build` | Build/static availability and failure facts without execution claims. |
| L1 `l1_templates_patterns` | `plan.json`, `source_capture.json`, `base_evidence.json`, `template_pattern_evidence.json`, `niche_findings.json`, `tool_coverage.json`, `providers:all` | Generic pattern/selection signals and all provider debt. |
| L1 light `l1_subsystem_attack_trust` | union of `l1_subsystem_scope` and `l1_attack_trust` | No subsystem/attack/trust evidence removed. |
| L1 light `l1_build_templates` | union of `l1_build_static` and `l1_templates_patterns` | No build/provider/template evidence removed. |
| L1 light `l1_threat_fork` | same as full `l1_threat_fork` | Threat/fork denominator is mode-invariant. |

`providers:build`, `providers:graph`, and `providers:scanner` are registry
categories, never globs. `providers:all` is their duplicate-free union.

### 3.3 Row/fragment conservation

Every provider triple is nonempty in every terminal state. `outcome.json`
records provider/config/tool identity, terminal state, raw byte digest and size,
parser version, observed fragment count, accepted row IDs, rejected fragment
digests, and reason codes. `evidence.json` contains all accepted typed rows or
an explicit typed zero. `debt.json` contains every rejected/unrepresentable
fragment digest/reason and a CLEAR or OPEN disposition.

The following equations must hold before any MODEL launch:

```text
observed_fragment_count
  = accepted_row_count + rejected_fragment_count

accepted_row_ids
  = evidence.json row IDs

rejected_fragment_digests
  = debt.json rejected-fragment digests
```

Every accepted row is readable by at least one role in the table and is later
PROJECTED or RETAINED_PRIVATE with a named consumer in the canonical transform
receipt. Every rejected fragment is readable as debt by the role responsible
for that provider category. This proves that private publication causes no
recall loss.

A provider disabled while applicable writes OPEN debt with
`PROVIDER_DISABLED_BY_CONFIG`. It may be CLEAR only when the registry proves
`NOT_APPLICABLE`, or when an exact registered substitute succeeds and its
coverage-key set equals the disabled provider's required coverage set.

## 4. Fixed seed/provider bundles and canonical owner

R2 inherits R1's fixed base seed bundle and exact provider triples. The
compiler runs before execution and rejects unknown IDs, duplicates,
case-fold/path aliases, glob metacharacters, absolute/dot/parent paths, and an
empty denominator. Provider outcome never changes path membership.

The registered provider universe for the R2 denominator is closed:

| Provider ID | Registry category | Applicable cells |
|---|---|---|
| `source_graph` | graph | SC EVM/Aptos/Sui/Solana/Soroban and L1 mixed fallback |
| `build_probe` | build | every SC/L1 cell |
| `slither` | graph/scanner | SC EVM |
| `opengrep` | scanner | all non-DAML SC cells |
| `sec3` | scanner | SC Solana |
| `scip_rust` | graph | SC Solana/Soroban and L1 Rust/mixed |
| `scip_go` | graph | L1 Go/mixed |
| `daml_source_graph` | graph | SC DAML |

Not-applicable providers still appear in the compiled plan only as registry
applicability records; provider output triples are compiled for every provider
registered to the selected cell. Within a cell, enabled, disabled, success,
unavailable, nonzero, timeout, malformed, or unrepresentable changes bytes and
debt, never paths.

SC canonical output remains the 11 R1 names plus
`recon_signal_transform_receipt.json`; L1 remains seven plus the receipt.
`recon/canonical_merge` exclusively owns the complete tuple atomically. Its
inputs are the committed prepass bundle, exact committed MODEL shards, exact
dependency units, and the bound normalized configuration described in section
5. It never uses an existing public canonical byte as semantic input.

The transform receipt unconditionally carries canonical validation disposition
CLEAR or DEBT. Therefore no supplementary unit exists and no later unit writes
a canonical path.

## 5. Same-key typed transform request

### 5.1 Authority-compatible encoding

The frozen ledger requires a stable LaunchSpec for deterministic same-key
reexecution. R2 therefore treats `LaunchSpec/configuration digest` as an exact
pair, not as permission to mutate the launch manifest:

- LaunchSpec has the fixed profile `recon-canonical-transform.v2` and fixed
  tool-policy marker `recon-transform-config-v1` from the first execution.
- The existing persisted `scratchpad:config.json` is an exact canonical-merge
  immutable input with a raw-input boundary, and its byte digest participates
  in the ArtifactLedger input-set digest.
- The normalized config contains one typed `recon_transform_request` and its
  stable unsigned digest. Thus the request is encoded in the configuration
  digest associated with the fixed LaunchSpec profile.
- Per-request data is deliberately not inserted into `LaunchSpec.to_dict()`;
  doing so would create forbidden launch drift under the unchanged ledger API.

There is no `_recon_transform_request.json`, marker file, repair file, or other
co-owned request artifact.

The request schema is:

```json
{
  "schema": "plamen.recon_transform_request.v1",
  "sequence": 4,
  "action": "NORMALIZE_MARKER",
  "reason_code": "LEGACY_MARKER_PRESENT_IN_BOUND_SEED",
  "source_snapshot_digest": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "output_snapshot_digest": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  "previous_request_digest": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
  "request_digest": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
}
```

`request_digest` hashes the other seven fields in canonical encoding. The
bounded action enum is:

```text
INITIAL_PUBLISH
REFRESH_CHANGED_SEED
REFRESH_CHANGED_SHARD
NORMALIZE_MARKER
DEGRADE_INCOMPLETE_SEED
RESUME_RECONCILIATION
```

`source_snapshot_digest` hashes the exact current committed seed, MODEL shard,
dependency, and relevant config input records. `output_snapshot_digest` hashes
the complete current canonical output records, or the typed explicit-absence
tuple for initial publication. The driver computes both before altering config.

### 5.2 State transitions

Initial fresh publication writes sequence 0 / `INITIAL_PUBLISH` before the
canonical input arm. Exact resume recomputes the snapshots; if they and the
request are unchanged, it does not rewrite config and canonical replay is a
strict byte/mtime/ledger no-op.

A real marker, degrade, resume-reconciliation, seed, or shard change creates
the next sequence with the exact bounded action and chained prior digest,
atomically rewrites the existing normalized config, and then calls
`authorize_deterministic_work_unit_reexecution()`. ArtifactLedger observes the
changed ACTIVE config input and records the ordinary same-key semantic
invalidation/reexecution history before any canonical overwrite.

The canonical commit authority/history must retain action, reason, old/new
configuration digest, source/output snapshot digests, request digest, attempt
ordinal, and the unchanged six-component work-unit key. A repeated request,
wrong previous digest, skipped sequence, unknown action/reason, snapshot
mismatch, or config-byte tamper rejects before reexecution. Output-only drift
remains tamper and cannot manufacture a request.

## 6. Legacy compatibility without adoption

### 6.1 Branch selection

The driver makes a preflight choice before any transactional arm:

- **FRESH_TRANSACTIONAL** only when no legacy canonical/prepass path exists,
  no old recon contract is active, and the checkpoint declares the current R2
  registry version or a new empty run.
- **LEGACY_READ_ONLY** when any known legacy canonical/prepass byte or
  pre-R2 recon checkpoint/contract exists.

The legacy roster is versioned and exact for detection only; it is not an input
adoption roster. Unknown files do not expand it.

### 6.2 Active legacy behavior

`LEGACY_READ_ONLY` never calls the new prepass or canonical transaction against
the legacy public paths. It never moves, deletes, normalizes, strips markers,
backs up, overwrites, binds, or adopts those bytes. It does not synthesize
ArtifactLedger ownership.

The driver records `LEGACY_COMPATIBILITY_DEBT` through the existing durable
phase-debt/checkpoint channel, prints a prominent warning with the fresh-run
command, and continues without halting solely because the scratchpad is
legacy. Existing non-mutating readers may consume the old files under their old
unproven ownership behavior. Missing, zero, mixed, marker-bearing, aliased, or
otherwise invalid legacy bytes remain explicit debt and can only reduce
assurance; they cannot become clean. A legacy run requiring recon repair is
directed to a fresh-run upgrade rather than mutating the old namespace.

This branch grants no Cut-4 transactional claim. It is intentionally compatible
and haltless, not silently upgraded.

### 6.3 Fresh-run upgrade and future migration

The supported upgrade is a fresh run using the existing archive/fresh workflow.
The archived scratchpad remains untouched evidence; the new empty scratchpad
uses R2 transactions.

A future external-input snapshot migration may be mechanically possible
without changing ArtifactLedger only if a separately reviewed design registers
every legacy byte as an exact immutable external input, proves one closed
roster and physical identity, publishes to different initially absent paths,
and never disposes of the source bytes. That migration is **FUTURE / NOT
ACTIVE / NO AUTHORITY** in R2. R2 defines no validator, migration unit,
adoption, retirement, or deletion protocol and does not generalize any V5/T1
repair API.

## 7. Transaction, isolation, and failure rules

Fresh prepass and canonical transactions retain R1's exact plan, complete
staging, `plan_driver_successor_transaction()`, input arm, ordered successor
steps, expected-output commit, and validation sequence. The named failpoints
remain:

```text
after_capture -> after_arm -> after_stage -> after_publish -> before_commit
```

Recovery through the same publisher exposes only a fully validated all-old
preimage or fully committed all-new postimage before any consumer. A consumer
is blocked while the tuple is armed, partial, mixed, oversized, aliased, or
quarantined. Every semantic output is nonempty; typed zero is schema-valid
nonempty content.

Providers receive only a copied/materialized attempt-private input snapshot.
No argv, cwd, environment variable, symlink, junction, file descriptor, or
writable handle points at project root or scratchpad. Foundry config, source,
dependencies, cache, and output directories exist only in the temporary
overlay. Project-root before/after equality is a defense-in-depth assertion,
not the primary containment mechanism. A mutation attempt fails in isolation
and opens provider debt; it cannot alter the real project.

Windows locked replacement/long paths and POSIX rename/permission failures are
typed transaction failures. Symlink, junction, hardlink/same-file, case-fold,
dot/parent, and absolute-path aliases reject before publication.

## 8. Implementation ownership

The R1 serialized ownership remains, with these R2 clarifications:

1. Contract/registry worker owns `scripts/phase_io_contracts.py` and planned
   `scripts/recon_publication_transaction.py`: registry, role input maps,
   transform request validation, exact contracts, transaction/recovery.
2. Prepass worker owns `scripts/recon_prepass.py`: pure typed seed/provider
   production and provider isolation. It does not edit prompts or public
   canonical files.
3. Canonical worker owns `scripts/plamen_mechanical.py`: pure registry-derived
   render/receipt; no direct marker/degrade writer.
4. Driver worker owns `scripts/plamen_driver.py`: generated readable-input
   blocks, current prelaunch binding calls, transform config transitions,
   fresh/legacy branch, loud debt, and ordering.
5. Fixture worker owns only new copy-on-write R2 successor fixtures and receipt.

No workers concurrently edit a shared file. Methodology prompt files, accepted
V1-V7 fixtures, `scripts/artifact_ledger.py`, and all G3 artifacts/pins remain
unchanged.

## 9. Exact closed successor test roster

### 9.1 Count and interpretation

The authoritative roster is the exact JSON array below. Every string is one
pytest node ID after parametrization. Duplicate IDs are forbidden. The closed
count is exactly **165**:

- 9 registry/cell nodes;
- 64 provider nodes (8 provider IDs x 8 terminal states);
- 23 complete-set/path/physical-containment nodes;
- 18 MODEL visibility/binding nodes;
- 15 transaction/crash/no-op nodes;
- 10 typed transform-request/reexecution nodes;
- 6 fresh/legacy nodes;
- 12 preserved MODEL/dependency/downstream application controls; and
- 8 OS/provider-root isolation nodes.

`disabled_applicable` must be OPEN debt; `disabled_not_applicable` may be
CLEAR. `success`, `unavailable`, `nonzero`, `timeout`, `malformed`, and
`unrepresentable` each verify the same exact nonempty outcome/evidence/debt
path triple and row/fragment accounting.

```json
[
  "cut4_r2.plan.sc_evm",
  "cut4_r2.plan.sc_aptos",
  "cut4_r2.plan.sc_sui",
  "cut4_r2.plan.sc_solana",
  "cut4_r2.plan.sc_soroban",
  "cut4_r2.plan.sc_daml",
  "cut4_r2.plan.l1_go",
  "cut4_r2.plan.l1_rust",
  "cut4_r2.plan.l1_mixed",
  "cut4_r2.provider.source_graph.disabled_applicable",
  "cut4_r2.provider.source_graph.disabled_not_applicable",
  "cut4_r2.provider.source_graph.success",
  "cut4_r2.provider.source_graph.unavailable",
  "cut4_r2.provider.source_graph.nonzero",
  "cut4_r2.provider.source_graph.timeout",
  "cut4_r2.provider.source_graph.malformed",
  "cut4_r2.provider.source_graph.unrepresentable",
  "cut4_r2.provider.build_probe.disabled_applicable",
  "cut4_r2.provider.build_probe.disabled_not_applicable",
  "cut4_r2.provider.build_probe.success",
  "cut4_r2.provider.build_probe.unavailable",
  "cut4_r2.provider.build_probe.nonzero",
  "cut4_r2.provider.build_probe.timeout",
  "cut4_r2.provider.build_probe.malformed",
  "cut4_r2.provider.build_probe.unrepresentable",
  "cut4_r2.provider.slither.disabled_applicable",
  "cut4_r2.provider.slither.disabled_not_applicable",
  "cut4_r2.provider.slither.success",
  "cut4_r2.provider.slither.unavailable",
  "cut4_r2.provider.slither.nonzero",
  "cut4_r2.provider.slither.timeout",
  "cut4_r2.provider.slither.malformed",
  "cut4_r2.provider.slither.unrepresentable",
  "cut4_r2.provider.opengrep.disabled_applicable",
  "cut4_r2.provider.opengrep.disabled_not_applicable",
  "cut4_r2.provider.opengrep.success",
  "cut4_r2.provider.opengrep.unavailable",
  "cut4_r2.provider.opengrep.nonzero",
  "cut4_r2.provider.opengrep.timeout",
  "cut4_r2.provider.opengrep.malformed",
  "cut4_r2.provider.opengrep.unrepresentable",
  "cut4_r2.provider.sec3.disabled_applicable",
  "cut4_r2.provider.sec3.disabled_not_applicable",
  "cut4_r2.provider.sec3.success",
  "cut4_r2.provider.sec3.unavailable",
  "cut4_r2.provider.sec3.nonzero",
  "cut4_r2.provider.sec3.timeout",
  "cut4_r2.provider.sec3.malformed",
  "cut4_r2.provider.sec3.unrepresentable",
  "cut4_r2.provider.scip_rust.disabled_applicable",
  "cut4_r2.provider.scip_rust.disabled_not_applicable",
  "cut4_r2.provider.scip_rust.success",
  "cut4_r2.provider.scip_rust.unavailable",
  "cut4_r2.provider.scip_rust.nonzero",
  "cut4_r2.provider.scip_rust.timeout",
  "cut4_r2.provider.scip_rust.malformed",
  "cut4_r2.provider.scip_rust.unrepresentable",
  "cut4_r2.provider.scip_go.disabled_applicable",
  "cut4_r2.provider.scip_go.disabled_not_applicable",
  "cut4_r2.provider.scip_go.success",
  "cut4_r2.provider.scip_go.unavailable",
  "cut4_r2.provider.scip_go.nonzero",
  "cut4_r2.provider.scip_go.timeout",
  "cut4_r2.provider.scip_go.malformed",
  "cut4_r2.provider.scip_go.unrepresentable",
  "cut4_r2.provider.daml_source_graph.disabled_applicable",
  "cut4_r2.provider.daml_source_graph.disabled_not_applicable",
  "cut4_r2.provider.daml_source_graph.success",
  "cut4_r2.provider.daml_source_graph.unavailable",
  "cut4_r2.provider.daml_source_graph.nonzero",
  "cut4_r2.provider.daml_source_graph.timeout",
  "cut4_r2.provider.daml_source_graph.malformed",
  "cut4_r2.provider.daml_source_graph.unrepresentable",
  "cut4_r2.set.seed_complete",
  "cut4_r2.set.seed_partial",
  "cut4_r2.set.seed_superset",
  "cut4_r2.set.seed_duplicate",
  "cut4_r2.set.seed_wrong_order",
  "cut4_r2.set.seed_zero_member",
  "cut4_r2.set.seed_casefold_alias",
  "cut4_r2.set.seed_dot_parent_alias",
  "cut4_r2.set.seed_hardlink_same_file",
  "cut4_r2.set.seed_symlink_junction_escape",
  "cut4_r2.set.seed_absolute_path",
  "cut4_r2.set.seed_namespace_extra",
  "cut4_r2.set.canonical_complete_sc",
  "cut4_r2.set.canonical_complete_l1",
  "cut4_r2.set.canonical_partial",
  "cut4_r2.set.canonical_superset",
  "cut4_r2.set.canonical_duplicate",
  "cut4_r2.set.canonical_wrong_order",
  "cut4_r2.set.canonical_zero_member",
  "cut4_r2.set.canonical_casefold_path_alias",
  "cut4_r2.set.canonical_hardlink_same_file",
  "cut4_r2.set.canonical_symlink_junction_escape",
  "cut4_r2.set.canonical_transform_conservation",
  "cut4_r2.model.sc_build_static",
  "cut4_r2.model.sc_design_context",
  "cut4_r2.model.sc_inventory_surface",
  "cut4_r2.model.sc_templates_patterns",
  "cut4_r2.model.sc_light_context_static",
  "cut4_r2.model.sc_light_inventory_templates",
  "cut4_r2.model.l1_threat_fork",
  "cut4_r2.model.l1_subsystem_scope",
  "cut4_r2.model.l1_attack_trust",
  "cut4_r2.model.l1_build_static",
  "cut4_r2.model.l1_templates_patterns",
  "cut4_r2.model.l1_light_threat_fork",
  "cut4_r2.model.l1_light_subsystem_attack_trust",
  "cut4_r2.model.l1_light_build_templates",
  "cut4_r2.model.missing_seed_rejected",
  "cut4_r2.model.tampered_seed_rejected",
  "cut4_r2.model.wrong_prepass_owner_rejected",
  "cut4_r2.model.provider_rejected_fragment_visible_debt",
  "cut4_r2.txn.prepass.after_capture",
  "cut4_r2.txn.prepass.after_arm",
  "cut4_r2.txn.prepass.after_stage",
  "cut4_r2.txn.prepass.after_publish",
  "cut4_r2.txn.prepass.before_commit",
  "cut4_r2.txn.canonical.after_capture",
  "cut4_r2.txn.canonical.after_arm",
  "cut4_r2.txn.canonical.after_stage",
  "cut4_r2.txn.canonical.after_publish",
  "cut4_r2.txn.canonical.before_commit",
  "cut4_r2.txn.prepass_exact_noop",
  "cut4_r2.txn.canonical_exact_noop",
  "cut4_r2.txn.prepass_recovery_all_old_or_all_new",
  "cut4_r2.txn.canonical_recovery_all_old_or_all_new",
  "cut4_r2.txn.consumer_blocked_while_armed_or_mixed",
  "cut4_r2.request.exact_resume_no_config_change",
  "cut4_r2.request.marker_request_same_key_history",
  "cut4_r2.request.degrade_request_same_key_history",
  "cut4_r2.request.resume_reconciliation_same_key_history",
  "cut4_r2.request.source_snapshot_change",
  "cut4_r2.request.output_snapshot_tamper_rejected",
  "cut4_r2.request.unknown_action_rejected",
  "cut4_r2.request.config_digest_tamper_rejected",
  "cut4_r2.request.replay_no_new_history",
  "cut4_r2.request.manual_attempt_key_rejected",
  "cut4_r2.compat.fresh_transactional",
  "cut4_r2.compat.legacy_completed_read_only_debt_haltless",
  "cut4_r2.compat.legacy_incomplete_read_only_debt_haltless",
  "cut4_r2.compat.legacy_zero_mixed_alias_unmodified",
  "cut4_r2.compat.fresh_run_upgrade_required",
  "cut4_r2.compat.future_migration_inactive",
  "cut4_r2.existing.fanout.sc_light_codex",
  "cut4_r2.existing.fanout.sc_core_claude_headless",
  "cut4_r2.existing.fanout.sc_thorough_pty",
  "cut4_r2.existing.fanout.l1_light_pty",
  "cut4_r2.existing.fanout.l1_core_codex",
  "cut4_r2.existing.fanout.l1_thorough_claude_headless",
  "cut4_r2.existing.dependency_wave.codex",
  "cut4_r2.existing.dependency_wave.claude_headless",
  "cut4_r2.existing.dependency_wave.pty",
  "cut4_r2.existing.dependency_typed_zero",
  "cut4_r2.existing.instantiate_exact_binding",
  "cut4_r2.existing.breadth_exact_binding",
  "cut4_r2.platform.windows_locked_replace",
  "cut4_r2.platform.windows_long_path",
  "cut4_r2.platform.posix_rename_failure",
  "cut4_r2.platform.posix_permission_failure",
  "cut4_r2.platform.provider_has_no_project_root_path_or_handle",
  "cut4_r2.platform.foundry_temp_overlay_only",
  "cut4_r2.platform.project_root_mutation_impossible",
  "cut4_r2.platform.private_stage_extra_rejected"
]
```

### 9.2 Execution phases

Run the roster in the array's group order, with pytest cache disabled, unique
system-temp bases, and no live external provider requirement:

1. `plan`, `provider`, and `set` establish contract denominators first.
2. `model` proves every unchanged role sees and binds its exact seeds before
   any MODEL execution.
3. `txn` proves exact replay and all five crash points for both publishers.
4. `request` proves genuine config-input drift, same-key history, replay, and
   tamper rejection.
5. `compat` proves fresh versus legacy behavior without adoption or halt.
6. `existing` reruns the six MODEL fanout, three dependency wave, typed zero,
   instantiate, and breadth controls.
7. `platform` proves OS failures and complete provider/project isolation.
8. Run all 165 IDs together, then the frozen V7 hash/control selectors and the
   bounded recon adjacency/smoke suite.

No prose family, wildcard, or inherited fixture adds an uncounted node. Live
providers, native OS runners not represented by injected platform adapters,
full repository regression, release, and audit-quality assessment remain later
gates.

## 10. Acceptance and non-goals

R2 architecture is implementable only if every MODEL input row is exact and
producer-bound; every provider fragment is accepted or debt-accounted; legacy
bytes remain unmodified and unadopted; a changed typed config request is the
real input behind every non-no-op canonical reexecution; canonical ownership
is exclusive; all complete-set/alias/zero/crash/isolation properties pass; and
the 165-node roster is exact.

Non-goals remain protocol hints, methodology prompt changes, MODEL output or
fanout redesign, dependency-unit redesign, ArtifactLedger changes, generic
legacy migration/adoption, G3 authority/pins, MethodCard application, severity,
dedup, report authority, production edits in Part-0, release, or audit-readiness
claims.
