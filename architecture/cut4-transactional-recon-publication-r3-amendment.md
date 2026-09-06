# Cut-4 transactional recon publication R3 amendment

Date: 2026-08-10
Status: Part-0 R3 architecture repair only
Supersedes: only the repaired clauses of the R1 and R2 amendments
Authority: design for independent review; no production, test, fixture,
cutover, G3, release, or audit-readiness authority

## 0. Decision and frozen scope

R3 inherits the accepted R2 architecture: one DRIVER-owned immutable typed
prepass namespace; a registry-compiled output denominator; fixed nonempty
provider slots; unchanged MODEL shards and dependency units; one DRIVER
`recon/canonical_merge` owner for the complete SC or L1 canonical tuple and
transform receipt; registry-derived canonical projection; deterministic
encoding and walks; complete-set, nonzero, alias, crash, replay, containment,
and namespace-capture gates; and no public glob, post-write discovery,
conditional repair marker, provider/direct project-root mutation, or canonical
co-writer.

R3 repairs only four R2 clauses:

1. Runtime recon prompts and PhaseIO input contracts receive the same exact
   role-specific seed/provider set, and no positive instruction still treats a
   retired public prepass path as readable authority.
2. Canonical reexecution uses current `PhaseIOContract`, `LaunchSpec`, and
   `ArtifactLedger` APIs. Its changed authority is an admitted configuration
   input whose request is stable after commit and contains no output snapshot.
3. Fresh versus legacy classification uses one closed, versioned, exact path
   registry and a total predicate over path, registry-version, and recon-unit
   states. Legacy bytes are never adopted or mutated.
4. All eight provider triples exist in every plan cell. Their outcome status is
   exactly one of `NOT_APPLICABLE`, `NOT_SELECTED`, `SUCCESS`, `FAILURE`,
   `TIMEOUT`, or `MALFORMED`.

There are no protocol hints, methodology-role changes, ArtifactLedger edits,
G3 authority or pin changes, production edits, test edits, or prior-artifact
edits in this Part-0 amendment.

## 1. Authenticated basis and actual APIs

The mandatory R2 REPAIR review was read end to end and matched SHA-256
`5039a4f4ba09a253cba7cca27e55cf6b8f0fe94d0cacfef9bdfd5580c949f855`:

`review_fixtures/cut4_transactional_recon_publication_r2_amendment_independent_review_20260810.md`.

The frozen R2 amendment remains 30,919 bytes with SHA-256
`7400193cb40771ce61910b14b3d34830584f76b86219ee41ab4c2f0fc21c0f73`.
The accepted V7 review remains bounded evidence at
`c8e19b0f089b3e671e5191244aed2e56e277b20190b6db7d06087b1e4fd39223`;
it is not production GREEN.

The API trace establishes these constraints:

- `LaunchSpec` has exactly `work_unit_key`, pipeline/mode/ecosystem/backend,
  `model`, `timeout_s`, `exec_mode`, `tool_policy`, and `launch_version`. It has
  no profile or arbitrary configuration field.
- `PhaseIOContract.launch_profile` admits only
  `DRIVER_PYTHON_NO_TOOLS`; ArtifactLedger requires that profile to use
  `model="driver"`, `exec_mode="python"`, and an empty tool policy.
- `InputAuthorityRequirement(allow_raw=True)` can bind a canonical
  `scratchpad:` or `project:` raw input. Produced inputs can instead require an
  exact same-run producer, writer, contract, and launch authority.
- `authorize_deterministic_work_unit_reexecution()` requires a same-run,
  DRIVER-only deterministic producer, an unchanged launch and static contract,
  live prior outputs, and real current input drift. It returns `None` when no
  semantic input changed and rejects output-only drift.
- `record_work_unit_inputs()` re-arms the same key after the authorization and
  appends the validated authorization to `semantic_reexecution_history`; it
  preserves an exact committed replay without rewriting timestamps or state.

R3 uses those APIs as they exist. It adds no launch-profile value, launch
field, ArtifactLedger schema field, manual ledger row, or attempt-suffixed key.

## 2. Inherited closed bundles and ownership

The registry compiler runs before execution and fixes one ordered denominator.
The base seed paths under `scratchpad:_recon/prepass_seed/` remain:

```text
plan.json
source_capture.json
base_evidence.json
design_evidence.json
template_pattern_evidence.json
build_evidence.json
mechanical_graph.json
niche_findings.json
dependency_seed.json
tool_coverage.json
render_seed.json
namespace_capture.json
```

The provider universe is the exact ordered tuple:

```text
source_graph
build_probe
slither
opengrep
sec3
scip_rust
scip_go
daml_source_graph
```

For every provider, in every SC/L1 plan cell, the compiler adds exactly:

```text
providers/<provider-id>/outcome.json
providers/<provider-id>/evidence.json
providers/<provider-id>/debt.json
```

The seed denominator is therefore always 36 paths: 12 base paths plus 24
provider paths. Applicability, selection, execution, or failure changes bytes,
never membership. All files are nonempty typed records. `namespace_capture`
compares this planned set with an exact, sorted, NFC/casefold-safe private walk;
the walk checks containment and never discovers outputs.

SC canonical publication remains the exact 12-path tuple:

```text
recon_summary.md
design_context.md
attack_surface.md
state_variables.md
function_list.md
contract_inventory.md
template_recommendations.md
detected_patterns.md
setter_list.md
emit_list.md
build_status.md
recon_signal_transform_receipt.json
```

L1 canonical publication remains the exact eight-path tuple:

```text
recon_summary.md
threat_model.md
subsystem_map.md
attack_surface.md
trust_boundaries.md
template_recommendations.md
scope_leftover.md
recon_signal_transform_receipt.json
```

`recon/canonical_merge` exclusively owns and atomically commits the selected
tuple. It binds all 36 prepass outputs, the exact selected MODEL shards, the
unchanged dependency units, and the admitted configuration identity. Marker
strip, degrade, and resume are deterministic reexecutions of that same owner,
not new units. A supplementary disposition, if later required, is a separate
sidecar consumer that writes no canonical path. Canonical projection and the
transform-receipt row-disposition map are compiled from this same registry.

## 3. Runtime prompt and MODEL-input repair

### 3.1 Exact current contradiction inventory

Only the generated recon leaf prompt is authoritative during recon. Static
`prompts/**`, agent roles, methodology prose, fanout, models, and output names
remain byte-unchanged. Later-phase templates may continue reading the stable
canonical paths after canonical merge; those are canonical-consumer
instructions, not retired-prepass authority.

The complete current generated-prompt/input contradiction inventory is:

| Locus | Current named path/instruction | R3 mechanical result |
|---|---|---|
| `_build_recon_worker_prompt()` `inventory_surface` guidance | positive authority for `contract_inventory.md`, `function_list.md`, `state_variables.md` | Substitute the role's bound `base_evidence.json`, `source_capture.json`, and `mechanical_graph.json` paths in registry order. All non-path prose and role duties remain unchanged. |
| same, `templates_patterns` guidance | the same positive triple | Substitute its exact bound `base_evidence.json` and `mechanical_graph.json`, plus its concrete `providers:*` triples. |
| same, light `inventory_templates` guidance | the same positive triple | Substitute the union compiled for that combined role. |
| same, `build_static` guidance | `Do not write build_status.md directly` | Retain as a negative canonical-output prohibition; it is never emitted in a readable-input block and grants no input authority. |
| same, `external_dependency_research` guidance | `external_dependency_obligations.json` and base shards | Retain: these are unchanged dependency/shard inputs, not prepass-public authority. |
| same, `Driver-provided recon inputs` | `_recon_static_probe.md` | Replace with bound `source_capture.json` and `base_evidence.json`. |
| same readable block | `build_status.md` | Replace with bound `build_evidence.json` and concrete `providers:build` triples. |
| same readable block | `slither/primitive_status.md` | Replace with the concrete `providers/slither/{outcome,evidence,debt}.json` triple and `tool_coverage.json`. |
| same readable block | `contract_inventory.md`, `state_variables.md`, `function_list.md` | Replace with the exact role mapping below; never list all three reflexively. |
| same readable block | `external_dependency_obligations.json`, `recon_design_context.md`, `recon_inventory_surface.md`, project `impact_map.md` | Retain only when the resolved contract already binds that dependency/shard/project input for that role; otherwise omit. |
| `_build_l1_recon_worker_prompt()` `l1_build_static` guidance | positive read of `primitive_status.md` | Replace with bound `build_evidence.json` and concrete `providers:build` triples. |
| same, light `l1_build_templates` guidance | positive read of `primitive_status.md` | Replace with the combined role's exact build/template/provider bundle. |
| same, fixed readable block | `primitive_status.md` | Remove and emit the resolved role bundle instead. |
| `resolve_phase_io_contract(... recon, worker.*)` | SC bounded public inventory/meta inputs or L1 immutable `primitive_status.md` | Replace with exact immutable seed/provider identities plus only explicitly retained dependency/shard/project identities. |
| `_typed_model_worker_contract_and_launch()`, `_bind_typed_model_worker_inputs()`, `_prepare_typed_model_worker_launch()`, `_record_typed_model_worker_artifact()` | role is not carried through construction/replay | Add required `role`; validate exact `(agent_id, role, output)` membership in `_recon_worker_jobs()` at prelaunch and postcommit replay. |

The methodology provenance path printed in the leaf prompt remains a path to
an explicitly forbidden coordinator document. Its contents are neither opened
nor concatenated, so no static-methodology filename can contradict the runtime
allowlist. No textual search-and-replace is applied to methodology files.

### 3.2 One source of truth and mechanical rendering

`compile_recon_publication_plan()` exposes
`model_inputs_for_role(role) -> tuple[artifact identity,...]`. The resolver puts
that tuple in `immutable_inputs` with exact same-run prepass producer
requirements. The prompt renderer receives the resolved contract—not a second
role table—and emits absolute readable paths from `contract.immutable_inputs`
in contract order. Non-seed dependency/shard/project entries are separately
tagged and bound. The prelaunch binder and post-output recorder reconstruct the
same contract with the explicit role and reject any difference.

The compiled prompt ends with a machine-checkable `Bound Recon Evidence`
block. A contradiction scan tokenizes positive read/authority clauses and
fails if they contain any retired-prepass identity from section 6. Negative
write prohibitions and post-merge canonical-output names are classified, not
mistaken for read grants. The scan also fails if a path appears in the prompt
but not the PhaseIO denominator, or in the denominator but not the generated
read block.

### 3.3 Exact role visibility and recall conservation

All seed paths below are under `_recon/prepass_seed/`; provider categories
expand to concrete triples before contract construction.

| Role | Exact compiled seed/provider inputs |
|---|---|
| SC `build_static` | `plan`, `source_capture`, `build_evidence`, `tool_coverage`, `providers:build` |
| SC `design_context` | `plan`, `source_capture`, `base_evidence`, `design_evidence`, `dependency_seed`, `mechanical_graph`, `render_seed`, `providers:graph` |
| SC `inventory_surface` | `plan`, `source_capture`, `base_evidence`, `mechanical_graph`, `niche_findings`, `tool_coverage`, `providers:graph`, `providers:scanner` |
| SC `templates_patterns` | `plan`, `source_capture`, `base_evidence`, `template_pattern_evidence`, `mechanical_graph`, `niche_findings`, `tool_coverage`, `providers:all` |
| SC light `context_static` | ordered duplicate-free union of `build_static` and `design_context` |
| SC light `inventory_templates` | ordered duplicate-free union of `inventory_surface` and `templates_patterns` |
| L1 `l1_threat_fork` | `plan`, `source_capture`, `base_evidence`, `design_evidence`, `mechanical_graph`, `dependency_seed`, `providers:graph` |
| L1 `l1_subsystem_scope` | `plan`, `source_capture`, `base_evidence`, `design_evidence`, `mechanical_graph`, `providers:graph` |
| L1 `l1_attack_trust` | `plan`, `source_capture`, `base_evidence`, `design_evidence`, `mechanical_graph`, `niche_findings`, `providers:scanner` |
| L1 `l1_build_static` | `plan`, `source_capture`, `build_evidence`, `tool_coverage`, `providers:build` |
| L1 `l1_templates_patterns` | `plan`, `source_capture`, `base_evidence`, `template_pattern_evidence`, `niche_findings`, `tool_coverage`, `providers:all` |
| L1 light `l1_threat_fork` | same as full `l1_threat_fork` |
| L1 light `l1_subsystem_attack_trust` | ordered duplicate-free union of `l1_subsystem_scope` and `l1_attack_trust` |
| L1 light `l1_build_templates` | ordered duplicate-free union of `l1_build_static` and `l1_templates_patterns` |

Provider category membership is a registry tuple, never a glob. For every
observed provider fragment:

```text
observed = accepted + rejected
accepted row IDs = evidence row IDs
rejected digests = debt rejected-fragment digests
```

Every accepted row has at least one role consumer and a transform-receipt
disposition of `PROJECTED`, `EXPLICIT_ZERO`, or `RETAINED_PRIVATE` with a named
later consumer. Every rejected fragment is visible to at least one responsible
role as OPEN debt. Thus making prepass publication private loses no found
output, while exact typed inputs prevent unrelated raw noise or stale public
bytes from becoming evidence. This improves recall without sacrificing
precision.

## 4. Exact provider receipt semantics

Applicability is the pure registry predicate `A(provider_id, pipeline,
ecosystem)`. Selection is the pure normalized-config predicate
`S(provider_id)`, and compilation enforces `S => A`. The only admitted states
are:

| Status | Exact predicate | attempted | Evidence/debt meaning |
|---|---|---:|---|
| `NOT_APPLICABLE` | `A=false`, `S=false` | false | typed-zero evidence; `NEUTRAL` debt slot with zero debt. It is neither evidence of coverage nor debt. |
| `NOT_SELECTED` | `A=true`, `S=false` | false | typed-zero evidence; OPEN debt `PROVIDER_NOT_SELECTED`. |
| `SUCCESS` | `A=true`, `S=true`, invocation completed and every observed fragment was canonically parsed | true | accepted evidence or typed zero; CLEAR debt. |
| `FAILURE` | `A=true`, `S=true`, unavailable/start/exit/isolation/unrepresentable failure | true or false as observed | retain any safely parsed rows; OPEN debt with exact reason code. |
| `TIMEOUT` | `A=true`, `S=true`, deadline terminal | true | retain any fully captured parseable rows; OPEN debt `PROVIDER_TIMEOUT`. No retry. |
| `MALFORMED` | `A=true`, `S=true`, output/schema/encoding malformed | true | retain independently valid fragments, reject the rest by digest; OPEN debt. |

The fixed `outcome.json` schema is:

```json
{
  "schema": "plamen.recon_provider_outcome.v3",
  "provider_id": "slither",
  "category": ["graph", "scanner"],
  "applicability_predicate_id": "sc.evm",
  "applicable": true,
  "selection_predicate_id": "config.providers.slither",
  "selected": true,
  "status": "SUCCESS",
  "attempted": true,
  "tool_identity": "slither@normalized-version",
  "parser_version": "cut4.provider.slither.v3",
  "raw_capture": {"sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "size": 123},
  "observed_fragment_count": 3,
  "accepted_row_ids": ["slither:0", "slither:1", "slither:2"],
  "rejected_fragment_digests": [],
  "reason_codes": []
}
```

`evidence.json` and `debt.json` repeat the provider ID, status, and outcome
digest. `debt.disposition` is exactly `NEUTRAL`, `CLEAR`, or `OPEN` as defined
above. Even `NOT_APPLICABLE` has all three nonempty slots, but consumers must
not count its typed zero as evidence or its neutral record as debt. Malformed
status/predicate combinations reject the prepass transaction.

Providers receive only attempt-private copied inputs and handles. Foundry
configuration, source, dependencies, output, and cache live in a temporary
overlay. No provider argv, cwd, environment, symlink/junction, descriptor, or
writable handle points to project root or scratchpad. Provider failure changes
only its typed triple and cannot shrink the path denominator or mutate the
project.

## 5. Stable same-key transform request

### 5.1 Configuration admission

The actual CLI `config_path` is resolved before any recon PhaseIO arm. Fresh
transactional mode is admitted only when that exact file is a regular,
nonempty, NFC/casefold-safe path physically contained under the configured
scratchpad. The plan stores its exact `scratchpad:<relative-path>` identity.
Canonical merge includes that identity in `immutable_inputs` with
`InputAuthorityRequirement(allow_raw=True)`. This uses current PhaseIO fields
and prevents project-root config mutation.

A config outside scratchpad, a symlink/junction/hardlink alias, a zero or
malformed config, or a config whose physical identity aliases any output is
not silently copied. It enters the haltless `LEGACY_COMPATIBILITY_DEBT` branch
with `TRANSACTION_CONFIG_NOT_ADMITTED` and a fresh-run/wizard instruction.
This is a compatibility limitation, not transactional authority. A future
external-input snapshot design is not active.

### 5.2 Supported contract and launch

The canonical contract uses the ordinary key
`<pipeline>/<mode>/<ecosystem>/<backend>/recon/canonical_merge`,
`model_invoked=False`, DRIVER outputs, `required_commit_actor="DRIVER"`, and
`launch_profile="DRIVER_PYTHON_NO_TOOLS"`. Its stable launch is constructed
only with supported fields:

```json
{
  "launch_version": "plamen.launch.v1",
  "work_unit_key": "sc/core/evm/codex/recon/canonical_merge",
  "pipeline": "sc",
  "mode": "core",
  "ecosystem": "evm",
  "backend": "codex",
  "model": "driver",
  "timeout_s": 300,
  "exec_mode": "python",
  "tool_policy": []
}
```

No action or sequence is placed in the launch. The contract input identities
also remain fixed for the run; only the bound bytes/generations change.

### 5.3 Non-self-referential request

Before the first canonical input arm, the DRIVER writes exactly one
`recon_transform_request` member into the admitted scratchpad configuration.
For a changed transform it atomically replaces that same configuration file
before calling the reexecution API. There is no sidecar, request output,
co-writer, manual ledger row, or dynamic `/attempt-N` key.

```json
{
  "schema": "plamen.recon_transform_request.v3",
  "sequence": 4,
  "action": "NORMALIZE_MARKER",
  "reason_code": "MARKER_IN_BOUND_SEED",
  "normalizer_version": "cut4.recon.normalizer.v3",
  "source_input_set_digest": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "previous_commit_receipt_digest": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  "previous_history_prefix_digest": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
  "previous_request_digest": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
  "request_digest": "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
}
```

`request_digest` is SHA-256 of canonical UTF-8 JSON for the other fields with
sorted object keys and compact separators. `source_input_set_digest` hashes
the sorted live input records for all seed, MODEL, dependency, and normalized
non-request config projection inputs. It explicitly excludes:

- the request member itself;
- all current or prior canonical output bytes;
- output prestates, output snapshot digests, mtimes, and staging paths; and
- the request digest field.

The action enum is exact:

```text
INITIAL_PUBLISH
REFRESH_CHANGED_SOURCE_INPUT
REFRESH_CHANGED_MODEL_SHARD
REFRESH_CHANGED_DEPENDENCY
REFRESH_NORMALIZER_VERSION
NORMALIZE_MARKER
DEGRADE_INCOMPLETE_SEED
RESUME_RECONCILIATION
```

Reason codes are the matching action name with `_REQUEST` appended, except
`NORMALIZE_MARKER` uses `MARKER_IN_BOUND_SEED`. No free-form reason influences
authority. Sequence zero uses three all-zero predecessor digests. A later
sequence must increment by one; `previous_request_digest` chains the preceding
request; `previous_commit_receipt_digest` is the exact committed canonical
work-unit receipt that was live before invalidation; and
`previous_history_prefix_digest` hashes the exact existing
`semantic_reexecution_history` prefix before the new authorization.

These are historical preimages. They deliberately continue naming the prior
commit after the successor commits, so the request remains valid rather than
becoming stale against its own new output.

### 5.4 Exact API sequence and replay proof

For initial publication the driver writes sequence zero before
`record_work_unit_inputs()`. For a later action it performs:

1. Replay the exact current contract/launch and validate current committed
   outputs, input receipt, commit receipt, and history prefix.
2. Compute the new source-input digest without reading canonical outputs as
   semantic inputs. Create and atomically persist the next request in the
   already admitted config.
3. Call `authorize_deterministic_work_unit_reexecution()` on the same contract
   and launch. The API observes real drift in the config identity and, where
   applicable, the changed seed/shard/dependency identity. It validates old
   outputs before marking the same key `STALE_INPUT`.
4. Call `record_work_unit_inputs()` with that same authority. The existing API
   validates the stale authorization, binds the new config/source generations,
   and appends the existing authorization record to
   `semantic_reexecution_history`.
5. Use the existing driver successor transaction, complete staging, ordered
   publication, expected-output commit, and validation. The transform receipt
   records the request digest and predecessor receipt/history identities as
   output evidence, not as a semantic input.

On resume, the config bytes equal the current recorded config binding, the
source digest equals the request, the transform receipt carries the same
request chain, and the latest history entry has the config identity among its
changed inputs with the stored history prefix. The authorization API therefore
returns `None`; input recording returns the committed receipt unchanged; no
config, canonical byte, mtime, sequence, or history row changes. Output-only
tamper, a self/output snapshot field, wrong predecessor, unknown action/reason,
skipped sequence, source mismatch, config tamper, history mismatch, launch
drift, or a manual key fails before publication.

The existing history bound of 32 is authoritative. Sequence 32 is explicit
debt requiring a fresh run, never a new key or truncated history.

## 6. Closed legacy detection and compatibility

### 6.1 Exact versioned path registry

`LEGACY_RECON_PATHS_V3` is the duplicate-free union of these exact arrays. No
directory glob, recursive discovery, suffix match, or unknown file can expand
it.

```json
{
  "sc_canonical": [
    "recon_summary.md",
    "design_context.md",
    "attack_surface.md",
    "state_variables.md",
    "function_list.md",
    "contract_inventory.md",
    "template_recommendations.md",
    "detected_patterns.md",
    "setter_list.md",
    "emit_list.md",
    "build_status.md"
  ],
  "l1_canonical": [
    "recon_summary.md",
    "threat_model.md",
    "subsystem_map.md",
    "attack_surface.md",
    "trust_boundaries.md",
    "template_recommendations.md",
    "scope_leftover.md"
  ],
  "retired_prepass_auxiliary": [
    "_recon_static_probe.md",
    "meta_buffer.md",
    "slither/primitive_status.md",
    "_mechanical_graph.json",
    "_mechanical_graph_generation.json",
    "caller_map.md",
    "callee_map.md",
    "state_write_map.md",
    "function_summary.md",
    "niche_interface_parity_findings.md",
    "niche_permissionless_setters_findings.md",
    "tool_coverage_ledger.json",
    "tool_coverage_ledger.md",
    "tool_coverage_ledger_repair_required.md",
    "opengrep_results.sarif",
    "opengrep_findings.md",
    "sec3_results.sarif",
    "sec3_findings.md",
    "scip_rust.index",
    "daml_prepass_noop.md",
    ".sec3-output"
  ]
}
```

`primitive_status.md` at scratchpad root is an L1 Bake input, not a retired
recon path. Dependency obligation/research outputs and MODEL shards are also
unchanged units and are not legacy indicators. The exact distinction prevents
a fresh L1 or dependency wave from being falsely classified as legacy.

Detection uses `lstat` on each listed identity. For regular files it records
nonempty/zero, digest, size, marker state, and physical file identity; for the
one registered directory it records directory type without walking it. A
symlink, junction, reparse point, device, casefold collision, hardlink alias,
or wrong type is legacy debt. Detection never follows, deletes, moves, opens
for write, or adopts a listed object.

### 6.2 Total predicate

The classifier derives four closed state enums:

```text
PATH_STATE    = NONE | CURRENT_OWNED_COMPLETE | PRESENT_UNOWNED_OR_MIXED
VERSION_STATE = ABSENT | CUT4_RECON_V3 | OLD_UNKNOWN_OR_MALFORMED
UNIT_STATE    = NONE | CURRENT_V3_ONLY | OLD_OR_MIXED
CANON_STATE   = ABSENT | CURRENT_COMMITTED | CURRENT_INFLIGHT | INVALID_OR_OLD
```

`UNIT_STATE` considers only the exact current recon keys compiled by the plan
(prepass, selected unchanged MODEL/dependency units, and canonical merge) plus
the closed pre-v3 recon key roster. It never searches arbitrary ledger keys.
`CURRENT_V3_ONLY` requires exact current contract version, launch, run, and
registry digest for every present current key. `CURRENT_INFLIGHT` is admitted
only when the existing successor authority and recovery record replay exactly.

The total classification is:

| Predicate | Result |
|---|---|
| Config admitted; `PATH=NONE`, `VERSION=ABSENT`, `UNIT=NONE`, `CANON=ABSENT` | `FRESH_TRANSACTIONAL` new run |
| Config admitted; `VERSION=CUT4_RECON_V3`, `UNIT` is `NONE` or `CURRENT_V3_ONLY`, no auxiliary legacy object exists, and `CANON` is `ABSENT`, `CURRENT_COMMITTED`, or valid `CURRENT_INFLIGHT`; every present canonical path has exact canonical-merge prestate/current ownership | `FRESH_TRANSACTIONAL` initialize/resume/recover |
| Every other combination, including any old/malformed version, old/mixed unit, unowned canonical byte, partial canonical set, retired auxiliary object, invalid inflight state, physical alias, marker, zero, or unadmitted config | `LEGACY_COMPATIBILITY_DEBT` |

This is exhaustive and precedence-ordered; there is no inference from
checkpoint completion alone. A current committed SC or L1 tuple does not
reclassify itself as legacy merely because its canonical paths exist.

### 6.3 Compatibility behavior

`LEGACY_COMPATIBILITY_DEBT` is loud and haltless by itself. The driver records
the exact predicate row through the existing phase-debt/checkpoint channel,
prints the fresh-run instruction, and preserves old ownership/read behavior.
It does not invoke the new prepass/canonical transaction against those paths;
bind, normalize, strip markers, repair, back up, rename, unlink, overwrite,
delete, or synthesize ledger ownership; or claim transactional publication.
Invalid legacy bytes can only reduce assurance.

The supported upgrade is a fresh run using the existing archive/fresh
workflow. A mechanically safe external-input snapshot migration might later
register exact immutable legacy inputs and publish to initially absent new
paths without ArtifactLedger changes, but it is **FUTURE / NOT ACTIVE / NO
AUTHORITY**. R3 defines no adoption or deletion protocol.

## 7. Transaction, failure, and implementation ownership

Both DRIVER publishers retain the failpoints
`after_capture`, `after_arm`, `after_stage`, `after_publish`, and
`before_commit`. Recovery exposes a validated all-old preimage or an atomically
committed all-new complete tuple; an armed, partial, mixed, zero, aliased,
oversized, or quarantined set is not consumable. Exact replay is byte/mtime/
ledger/history no-op. Windows locked replacement/long-path errors and POSIX
rename/permission failures are typed transaction failures.

Implementation is serialized by file ownership:

1. Contract/registry worker owns `scripts/phase_io_contracts.py` and the planned
   `scripts/recon_publication_transaction.py`: registry, exact contracts,
   provider schema, legacy predicate, transaction/recovery.
2. Prepass worker owns `scripts/recon_prepass.py`: pure 36-output seed/provider
   production and provider overlays; no public canonical write.
3. Canonical worker owns `scripts/plamen_mechanical.py`: pure registry-derived
   rendering and transform receipt; no independent marker/degrade writer.
4. Driver worker owns `scripts/plamen_driver.py`: explicit role plumbing,
   generated read blocks and contradiction scan, config request transition,
   compatibility choice, same-key API sequence, ordering, and loud debt.
5. Fixture worker owns only new copy-on-write R3 successor fixtures and their
   execution receipt.

No workers concurrently edit a shared file. `scripts/artifact_ledger.py`,
methodology prompts, accepted V1-V7/R1/R2 artifacts, G3 artifacts/pins, and
MODEL/dependency identities remain unchanged.

## 8. Exact closed successor test roster

The JSON array below is the entire authoritative roster. It contains exactly
**187** unique parametrized node IDs:

- 9 plan cells;
- 48 provider states (8 providers x 6 statuses);
- 23 complete-set/path/physical nodes;
- 27 MODEL visibility and contradiction nodes;
- 15 transaction/crash/no-op nodes;
- 16 stable-request/reexecution nodes;
- 29 fresh/legacy predicate nodes;
- 12 unchanged fanout/dependency/downstream controls; and
- 8 platform/provider-isolation nodes.

```json
[
  "cut4_r3.plan.sc_evm",
  "cut4_r3.plan.sc_aptos",
  "cut4_r3.plan.sc_sui",
  "cut4_r3.plan.sc_solana",
  "cut4_r3.plan.sc_soroban",
  "cut4_r3.plan.sc_daml",
  "cut4_r3.plan.l1_go",
  "cut4_r3.plan.l1_rust",
  "cut4_r3.plan.l1_mixed",
  "cut4_r3.provider.source_graph.not_applicable",
  "cut4_r3.provider.source_graph.not_selected",
  "cut4_r3.provider.source_graph.success",
  "cut4_r3.provider.source_graph.failure",
  "cut4_r3.provider.source_graph.timeout",
  "cut4_r3.provider.source_graph.malformed",
  "cut4_r3.provider.build_probe.not_applicable",
  "cut4_r3.provider.build_probe.not_selected",
  "cut4_r3.provider.build_probe.success",
  "cut4_r3.provider.build_probe.failure",
  "cut4_r3.provider.build_probe.timeout",
  "cut4_r3.provider.build_probe.malformed",
  "cut4_r3.provider.slither.not_applicable",
  "cut4_r3.provider.slither.not_selected",
  "cut4_r3.provider.slither.success",
  "cut4_r3.provider.slither.failure",
  "cut4_r3.provider.slither.timeout",
  "cut4_r3.provider.slither.malformed",
  "cut4_r3.provider.opengrep.not_applicable",
  "cut4_r3.provider.opengrep.not_selected",
  "cut4_r3.provider.opengrep.success",
  "cut4_r3.provider.opengrep.failure",
  "cut4_r3.provider.opengrep.timeout",
  "cut4_r3.provider.opengrep.malformed",
  "cut4_r3.provider.sec3.not_applicable",
  "cut4_r3.provider.sec3.not_selected",
  "cut4_r3.provider.sec3.success",
  "cut4_r3.provider.sec3.failure",
  "cut4_r3.provider.sec3.timeout",
  "cut4_r3.provider.sec3.malformed",
  "cut4_r3.provider.scip_rust.not_applicable",
  "cut4_r3.provider.scip_rust.not_selected",
  "cut4_r3.provider.scip_rust.success",
  "cut4_r3.provider.scip_rust.failure",
  "cut4_r3.provider.scip_rust.timeout",
  "cut4_r3.provider.scip_rust.malformed",
  "cut4_r3.provider.scip_go.not_applicable",
  "cut4_r3.provider.scip_go.not_selected",
  "cut4_r3.provider.scip_go.success",
  "cut4_r3.provider.scip_go.failure",
  "cut4_r3.provider.scip_go.timeout",
  "cut4_r3.provider.scip_go.malformed",
  "cut4_r3.provider.daml_source_graph.not_applicable",
  "cut4_r3.provider.daml_source_graph.not_selected",
  "cut4_r3.provider.daml_source_graph.success",
  "cut4_r3.provider.daml_source_graph.failure",
  "cut4_r3.provider.daml_source_graph.timeout",
  "cut4_r3.provider.daml_source_graph.malformed",
  "cut4_r3.set.seed_complete_36",
  "cut4_r3.set.seed_partial",
  "cut4_r3.set.seed_superset",
  "cut4_r3.set.seed_duplicate",
  "cut4_r3.set.seed_wrong_order",
  "cut4_r3.set.seed_zero_member",
  "cut4_r3.set.seed_casefold_alias",
  "cut4_r3.set.seed_dot_parent_alias",
  "cut4_r3.set.seed_hardlink_same_file",
  "cut4_r3.set.seed_symlink_junction_escape",
  "cut4_r3.set.seed_absolute_path",
  "cut4_r3.set.seed_namespace_extra",
  "cut4_r3.set.canonical_complete_sc",
  "cut4_r3.set.canonical_complete_l1",
  "cut4_r3.set.canonical_partial",
  "cut4_r3.set.canonical_superset",
  "cut4_r3.set.canonical_duplicate",
  "cut4_r3.set.canonical_wrong_order",
  "cut4_r3.set.canonical_zero_member",
  "cut4_r3.set.canonical_casefold_alias",
  "cut4_r3.set.canonical_hardlink_same_file",
  "cut4_r3.set.canonical_symlink_junction_escape",
  "cut4_r3.set.transform_row_conservation",
  "cut4_r3.model.sc_build_static",
  "cut4_r3.model.sc_design_context",
  "cut4_r3.model.sc_inventory_surface",
  "cut4_r3.model.sc_templates_patterns",
  "cut4_r3.model.sc_light_context_static",
  "cut4_r3.model.sc_light_inventory_templates",
  "cut4_r3.model.l1_threat_fork",
  "cut4_r3.model.l1_subsystem_scope",
  "cut4_r3.model.l1_attack_trust",
  "cut4_r3.model.l1_build_static",
  "cut4_r3.model.l1_templates_patterns",
  "cut4_r3.model.l1_light_threat_fork",
  "cut4_r3.model.l1_light_subsystem_attack_trust",
  "cut4_r3.model.l1_light_build_templates",
  "cut4_r3.model.missing_seed_rejected",
  "cut4_r3.model.tampered_seed_rejected",
  "cut4_r3.model.wrong_prepass_owner_rejected",
  "cut4_r3.model.provider_rejected_fragment_visible_debt",
  "cut4_r3.model.prompt_sc_inventory_surface_rewritten",
  "cut4_r3.model.prompt_sc_templates_patterns_rewritten",
  "cut4_r3.model.prompt_sc_light_inventory_templates_rewritten",
  "cut4_r3.model.prompt_sc_readable_block_exact",
  "cut4_r3.model.prompt_l1_build_static_rewritten",
  "cut4_r3.model.prompt_l1_light_build_templates_rewritten",
  "cut4_r3.model.prompt_l1_readable_block_exact",
  "cut4_r3.model.prompt_retired_positive_authority_absent",
  "cut4_r3.model.prompt_contract_visibility_bijection",
  "cut4_r3.txn.prepass.after_capture",
  "cut4_r3.txn.prepass.after_arm",
  "cut4_r3.txn.prepass.after_stage",
  "cut4_r3.txn.prepass.after_publish",
  "cut4_r3.txn.prepass.before_commit",
  "cut4_r3.txn.canonical.after_capture",
  "cut4_r3.txn.canonical.after_arm",
  "cut4_r3.txn.canonical.after_stage",
  "cut4_r3.txn.canonical.after_publish",
  "cut4_r3.txn.canonical.before_commit",
  "cut4_r3.txn.prepass_exact_noop",
  "cut4_r3.txn.canonical_exact_noop",
  "cut4_r3.txn.prepass_all_old_or_all_new",
  "cut4_r3.txn.canonical_all_old_or_all_new",
  "cut4_r3.txn.consumer_blocked_armed_partial_mixed",
  "cut4_r3.request.initial_stable_preimage",
  "cut4_r3.request.marker_same_key_history",
  "cut4_r3.request.degrade_same_key_history",
  "cut4_r3.request.resume_same_key_history",
  "cut4_r3.request.source_input_change",
  "cut4_r3.request.model_shard_change",
  "cut4_r3.request.dependency_change",
  "cut4_r3.request.normalizer_version_change",
  "cut4_r3.request.previous_commit_history_chain",
  "cut4_r3.request.no_output_snapshot_or_self_reference",
  "cut4_r3.request.exact_replay_no_config_or_history_change",
  "cut4_r3.request.config_tamper_rejected",
  "cut4_r3.request.sequence_action_reason_rejected",
  "cut4_r3.request.source_digest_rejected",
  "cut4_r3.request.previous_receipt_history_rejected",
  "cut4_r3.request.manual_dynamic_key_rejected",
  "cut4_r3.compat.empty_absent_fresh",
  "cut4_r3.compat.current_prepublish_fresh",
  "cut4_r3.compat.current_sc_committed_fresh",
  "cut4_r3.compat.current_l1_committed_fresh",
  "cut4_r3.compat.old_version_no_paths_debt",
  "cut4_r3.compat.old_unit_no_paths_debt",
  "cut4_r3.compat.unowned_canonical_debt",
  "cut4_r3.compat.partial_mixed_canonical_debt",
  "cut4_r3.compat.invalid_inflight_debt",
  "cut4_r3.compat.unadmitted_config_debt",
  "cut4_r3.compat.future_migration_inactive",
  "cut4_r3.compat.path.sc.recon_summary",
  "cut4_r3.compat.path.sc.design_context",
  "cut4_r3.compat.path.sc.attack_surface",
  "cut4_r3.compat.path.sc.state_variables",
  "cut4_r3.compat.path.sc.function_list",
  "cut4_r3.compat.path.sc.contract_inventory",
  "cut4_r3.compat.path.sc.template_recommendations",
  "cut4_r3.compat.path.sc.detected_patterns",
  "cut4_r3.compat.path.sc.setter_list",
  "cut4_r3.compat.path.sc.emit_list",
  "cut4_r3.compat.path.sc.build_status",
  "cut4_r3.compat.path.l1.recon_summary",
  "cut4_r3.compat.path.l1.threat_model",
  "cut4_r3.compat.path.l1.subsystem_map",
  "cut4_r3.compat.path.l1.attack_surface",
  "cut4_r3.compat.path.l1.trust_boundaries",
  "cut4_r3.compat.path.l1.template_recommendations",
  "cut4_r3.compat.path.l1.scope_leftover",
  "cut4_r3.existing.fanout.sc_light_codex",
  "cut4_r3.existing.fanout.sc_core_claude_headless",
  "cut4_r3.existing.fanout.sc_thorough_pty",
  "cut4_r3.existing.fanout.l1_light_pty",
  "cut4_r3.existing.fanout.l1_core_codex",
  "cut4_r3.existing.fanout.l1_thorough_claude_headless",
  "cut4_r3.existing.dependency_wave.codex",
  "cut4_r3.existing.dependency_wave.claude_headless",
  "cut4_r3.existing.dependency_wave.pty",
  "cut4_r3.existing.dependency_typed_zero",
  "cut4_r3.existing.instantiate_exact_binding",
  "cut4_r3.existing.breadth_exact_binding",
  "cut4_r3.platform.windows_locked_replace",
  "cut4_r3.platform.windows_long_path",
  "cut4_r3.platform.posix_rename_failure",
  "cut4_r3.platform.posix_permission_failure",
  "cut4_r3.platform.provider_no_project_root_path_or_handle",
  "cut4_r3.platform.foundry_temp_overlay_only",
  "cut4_r3.platform.project_root_unchanged",
  "cut4_r3.platform.private_namespace_extra_rejected"
]
```

Execute groups in array order with pytest cache disabled, unique system-temp
roots, injected providers/platform adapters, and no live provider dependency.
Provider cases assert the exact applicability/selection predicate, same 36-path
bundle, nonempty triple, status, and NEUTRAL/CLEAR/OPEN meaning. Where a
provider is applicable to every registered cell (`build_probe`), its
`not_applicable` node is the required negative case: a forged
`NOT_APPLICABLE` receipt is rejected, so the roster tests the closed predicate
rather than inventing an impossible cell. MODEL cases
assert role visibility and scan compiled prompts for contradictions. Compat
path cases are parametrized over every SC/L1 canonical registry member and
assert bytes/mtime/physical identity are unchanged. Then run all 187 IDs
together, frozen V7 hash/control selectors, and the bounded recon adjacency
smoke suite. No wildcard, inherited family, prose count, or hidden
parametrization adds a node.

## 9. Acceptance and non-goals

R3 is acceptable only when one registry determines every path and consumer;
all 36 seed/provider slots are nonempty and path-stable; `NOT_APPLICABLE` is
neutral; every found or rejected fragment is conserved; compiled MODEL prompts
and bound inputs are bijective and contradiction-free; the sole canonical
owner atomically publishes the complete tuple; a non-no-op same-key execution
has a genuine stable config/source preimage and ordinary ledger history;
legacy classification is total and non-mutating; project-root/provider
containment holds; exact replay is a no-op; and the closed 187-node roster
passes.

Non-goals are methodology prose/role changes, MODEL shard or dependency-unit
redesign, legacy adoption/migration, provider installation, live-provider
claims, ArtifactLedger changes, G3 authority/pins, protocol findings, severity,
deduplication, report authority, production/test edits in Part-0, release, or
audit-readiness claims.
