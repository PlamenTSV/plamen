# Plamen Typed Program-Facts / CPG Implementation Blueprint

Date: 2026-07-24  
Status: implementation-ready architecture; no code or configuration changes made  
Scope: revised PR21, deterministic program facts, additive consumers, and rollout evidence  
Repository reviewed: `<LOCAL_USER_ROOT>\plamen-codex-implementation` at inspected HEAD `67a0f85adc7a8169d79a286908b00bef7adb764a` (working tree was not assumed clean)

## 1. Decision

Do **not** integrate literal PR21 and do not add flattened CPG arrays directly to `_mechanical_graph.json`.

Implement a driver-owned, snapshot/build/tool-bound **typed program-facts sidecar**. It is structural evidence that may add review obligations, ranking features, slices, and cross-function seam candidates. It is never:

- ground truth about exploitability, authorization, asset impact, or protocol intent;
- negative authority;
- permission to suppress, demote, refute, close, or mark a surface examined;
- a substitute for the existing G1 denominator, M1 reasoning, verifier, or human review.

The canonical owned outputs are:

1. `mechanical_program_facts.v1.json` — portable, content-addressed fact payload.
2. `mechanical_program_facts_receipt.v1.json` — environment-specific snapshot/build/tool/execution/PhaseIO receipt.
3. `mechanical_program_facts_debt.v1.json` — explicit unsupported, partial, unresolved, stale, and provider-conflict debt.

The existing graph remains a legacy projection. Consumers load the sidecar directly. A later graph schema may contain only a validated reference to the three sidecars; it must not contain their arrays.

This blueprint intentionally does not implement adaptive attention. First measure program facts with a fixed worker roster and fixed budgets. The later attention experiment is a separate change.

## 2. Why literal PR21 is unsafe in this repository

### 2.1 Existing writers reconstruct and erase unknown fields

`scripts/recon_prepass.py::_write_mechanical_graph_json` (currently around lines 3556–3637) reconstructs `_mechanical_graph.json` from exactly:

- `schema_version`;
- `function_signature_schema`;
- `source`;
- `state_symbols`;
- `var_refs`;
- `functions`;
- `function_signatures`.

It writes with `Path.write_text`, catches all exceptions, and has no preservation path for an unknown PR21 field. Any inline `nodes`, `edges`, `semantic_edges`, `feature_facts`, `build_receipt`, or `program_facts_ref` added by another producer is lost on the next bake.

### 2.2 Existing readers also erase schema data

`scripts/enumeration_gate.py::_load_graph` (around lines 267–331) parses the raw object but returns a new object containing only:

- `source`;
- cleaned `var_refs`;
- cleaned `functions`;
- `_graph_health_diagnostics`.

It drops the current `schema_version`, `function_signature_schema`, `state_symbols`, and `function_signatures`, as well as all prospective PR21 fields. This is concrete current schema data loss, not a hypothetical migration concern.

`scripts/security_obligation_authority.py::_extract_graph_facts` reads the raw graph independently. `scripts/asset_representation_foundation.py::extract_semantic_edge_foundation` recognizes a reserved `plamen.mechanical_graph.v3` inline `semantic_edges` shape, but declares its provider receipt unavailable and keeps it proposal-only. Production recon still emits `plamen.mechanical_graph.v2`. Reusing or silently changing the meaning of v3 would conflate a test/reserved migration with a new authority contract.

### 2.3 Current bakes do not prove semantic completeness

The current providers are useful legacy projections, not typed CPG authority:

- `recon_prepass.py::_bake_evm_slither_graph` runs Slither in-process, mutates `FOUNDRY_PROFILE`, and extracts functions, state reads/writes, and selected callees. It does not bind a complete compiled-file denominator, CFG/post-dominator facts, typed SlithIR operations, dependency context, unresolved dynamic calls, or an execution receipt.
- `_bake_evm_source_graph`, `_bake_move_graph`, `_bake_rust_source_graph`, and `_bake_go_source_graph` are approximate source parsers.
- `_scip_to_graph_artifacts` infers same-file callees from occurrence co-location and applies hard caps (including node and callee caps); those facts cannot be relabeled exact.
- `_scip_bake_is_fresh` is mtime-oriented. It does not bind the exact executable/module digest, compiler, build flags, generated/dependency closure, parser digest, environment, or complete source denominator.
- `_finalize_source_graph` performs provider-time filtering, including dropping high-reference symbols. A portable fact substrate must retain covered facts and represent output limits as debt, not silently change the denominator.

### 2.4 Current execution and publication ownership is wrong for authority

The startup path in `scripts/plamen_driver.py` invokes `run_recon_prepass(config)` synchronously and in-process at approximately lines 45267–45296. Later breadth hooks call `_bake_rust_graph` and `_bake_go_graph` directly based on file existence and environment switches. These paths write canonical files outside an explicit PhaseIO owner.

`scripts/phase_io_contracts.py::resolve_phase_io_contract` has no `recon/program_facts_bake` work-unit shape and deliberately rejects unknown work units. `scripts/artifact_ledger.py::record_work_unit_artifacts` is the existing atomic ledger authority and must be used.

The reviewed WorkerTransaction P0-AM design correctly places native tools behind `NativeCommandAdapter`, owned OS-process scope, immutable attempt staging/CAS, and driver-only PhaseIO incorporation. The current `scripts/worker_execution_receipts.py::run_observed_worker` is useful migration substrate, but it is not the finished, universally adopted `WorkerTransaction` authority. PR21 must not create another native launcher.

## 3. Non-negotiable invariants

The implementation must encode and test the following invariants.

1. **Snapshot binding:** every payload binds the already-established audit `snapshot_digest` and `source_scope.digest`.
2. **Exact denominator:** the receipt lists every eligible source file, every attempted compilation unit/build variant, every compiled file, every exclusion, and every unresolved item.
3. **Tool binding:** provider implementation, executable/module, compiler/toolchain, parser, arguments, allowed environment, config, and raw output are digest-bound.
4. **Portable/environment split:** portable facts do not contain host paths, timestamps, PIDs, usernames, temp paths, or OS-specific executable locations. Those belong in the receipt.
5. **One publisher:** provider processes write only into WorkerTransaction staging. PhaseIO incorporation is the only canonical publisher.
6. **Closed schemas:** unknown keys, invalid enums, duplicate IDs, dangling references, invalid paths, and self-digest mismatch fail validation.
7. **Additive authority only:** no fact or provider capability can grant suppression, demotion, closure, examined-state, “safe,” or “unreachable” authority.
8. **Partial is explicit:** unsupported and degraded runs still publish valid zero-or-partial fact, receipt, and debt files. Missing artifacts are never interpreted as clean.
9. **No negative inference:** absence of a path, domination, dependency, sink, call edge, or tool diagnostic proves nothing outside the stated positive fact.
10. **Disagreement is work:** conflicting providers or provider/source projections create mandatory review debt; no “highest confidence wins” collapse.
11. **Stable identity:** IDs derive from canonical semantic bindings, never iteration order or host absolute paths.
12. **Source containment:** no traversal, symlink/reparse escape, case-fold collision, mutable external target, or unbound generated source may enter the portable payload.
13. **Resume equivalence:** reuse requires exact equality of snapshot, source manifest, build variants, provider registry, tool identities, parser, configuration, and capabilities.
14. **Backend neutrality:** program-fact bytes are independent of Claude/Codex backend and model because the bake is `model_invoked=False`.
15. **Ground-truth isolation:** benchmark ground truth is grader-only and cannot enter prompts, provider plans, ranking, slices, or audit configuration.

## 4. Artifact and digest model

### 4.1 Canonicalization

Add one canonical encoder in `scripts/program_facts_types.py`:

```python
def canonical_json_bytes(value: Mapping[str, Any] | Sequence[Any]) -> bytes
def signed_payload(value: Mapping[str, Any], digest_field: str) -> dict[str, Any]
def validate_signed_payload(value: Mapping[str, Any], digest_field: str) -> None
```

Rules:

- UTF-8, no BOM, LF final newline for files;
- JSON data model only; reject NaN, infinity, floats, duplicate keys, and non-string object keys;
- keys sorted by Unicode code point;
- compact separators for hashing; pretty serialization may be used only if file bytes and byte digest are recorded separately;
- arrays with semantic set meaning are sorted by stable ID;
- integer byte offsets and line/column values only;
- digest is lowercase SHA-256 of canonical JSON with the document’s own digest field omitted;
- file receipt records both semantic document digest and exact file-byte SHA-256.

Use `sha256:<64-lowercase-hex>` in cross-artifact references. Do not rely on modification time.

### 4.2 Path and source identity

A portable source binding is:

```json
{
  "source_file_id": "PFS-<24 hex>",
  "path": "src/Vault.sol",
  "path_casefold_key": "src/vault.sol",
  "source_sha256": "<64 hex>",
  "size_bytes": 1234,
  "language": "solidity",
  "scope_class": "PRODUCTION|EXPLICIT_SCOPE|BOUND_DEPENDENCY|GENERATED_BOUND",
  "physical_identity_digest": "<64 hex or empty>"
}
```

`path` is case-preserving, project-relative POSIX form. External explicit targets use the audit snapshot’s opaque outside identity and never expose an absolute path. `path_casefold_key` is used only to reject collisions; it is not the display identity. Raw source bytes determine `source_sha256`. Occurrences use byte offsets over those raw bytes; line/column are derived convenience fields and must replay.

Reject:

- absolute paths, `..`, NULs, alternate data streams, invalid Unicode, or platform separators after normalization;
- two path spellings with the same case-fold key;
- symlinks, junctions, or reparse points escaping the permitted root;
- two logical paths resolving to the same physical file without an explicit duplicate/dependency policy;
- source whose bytes change between manifest capture, provider launch, parse, and PhaseIO incorporation.

`source_file_id` is the first 24 hex characters of:

```text
sha256(canonical_json({
  "source_scope_digest": ...,
  "path": ...,
  "source_sha256": ...,
  "scope_class": ...
}))
```

### 4.3 Content-addressed layers

The logical canonical filenames remain stable for PhaseIO. Internally, every layer is addressed separately:

| Layer | Digest input | Purpose |
|---|---|---|
| Audit snapshot | existing `audit_snapshot.snapshot_digest` | whole-run evidence validity |
| Source manifest | ordered source rows plus scope/exclusion policy | exact source denominator |
| Build variant | manifests, dependency closure, compiler, roots, profiles, features/tags/remappings/defines/generated policy | compilation context |
| Provider identity | provider registry row, implementation/module/executable/parser digests | supply-chain and parser identity |
| Worker plan | snapshot + PhaseIO + tool + argv/env + assignment/write scope | launch authority |
| Raw result | exact WorkerTransaction CAS bytes | replay/forensics |
| Portable payload | normalized nodes/occurrences/facts/coverage | environment-independent fact identity |
| Receipt | all environment and execution bindings plus payload/debt byte hashes | reuse/publication proof |

Do not put raw tool output in the canonical sidecar. Retain it under immutable WorkerTransaction CAS and refer to it by digest.

## 5. Schemas

Store strict Draft 2020-12 schemas under:

- `rules/schemas/mechanical_program_facts.v1.schema.json`
- `rules/schemas/mechanical_program_facts_receipt.v1.schema.json`
- `rules/schemas/mechanical_program_facts_debt.v1.schema.json`
- `rules/schemas/program_facts_provider_registry.v1.schema.json`
- `rules/schemas/program_facts_slice.v1.schema.json`
- `rules/schemas/program_facts_disagreement.v1.schema.json`

Each object uses `additionalProperties: false`; required arrays are present even when empty. Python validators in `scripts/program_facts_types.py` enforce cross-reference and digest invariants that JSON Schema cannot.

### 5.1 Portable fact payload

`mechanical_program_facts.v1.json`:

```json
{
  "schema_version": "plamen.mechanical_program_facts.v1",
  "canonicalization_version": "plamen.canonical_json.v1",
  "authority": {
    "semantic_authority": "ADDITIVE_PROPOSAL_ONLY",
    "terminal_negative_authority": false,
    "can_suppress": false,
    "can_demote": false,
    "can_refute": false,
    "can_mark_examined": false,
    "can_certify_clean": false
  },
  "snapshot_ref": {
    "snapshot_digest": "<64 hex>",
    "source_scope_digest": "<64 hex>",
    "source_manifest_digest": "<64 hex>"
  },
  "ecosystem": "evm|go|rust|solana|soroban|aptos|sui|daml|mixed",
  "build_variants": [],
  "source_files": [],
  "provider_capability_refs": [],
  "nodes": [],
  "occurrences": [],
  "facts": [],
  "coverage": [],
  "payload_sha256": "<digest excluding this field>"
}
```

No environment-specific execution fields are permitted here.

#### Build variant

```json
{
  "build_variant_id": "PFB-<24 hex>",
  "ecosystem": "evm",
  "build_system": "foundry",
  "build_root_id": "root-0",
  "manifest_digests": [{"path": "foundry.toml", "sha256": "..."}],
  "dependency_closure_digest": "...",
  "compiler_identity_digest": "...",
  "profile": "default",
  "features": [],
  "tags": [],
  "remappings": [],
  "defines": [],
  "target_triples": [],
  "generated_source_policy": "BOUND_INCLUDED|BOUND_EXCLUDED",
  "variant_digest": "..."
}
```

A monorepo may have multiple variants. Facts are variant-scoped; cross-variant merging requires identical source and semantic identity. Do not silently union mutually exclusive features.

#### Nodes

Node kinds are closed and versioned:

```text
COMPILATION_UNIT, PACKAGE, MODULE, CONTRACT, INTERFACE, LIBRARY, TRAIT,
IMPL, FUNCTION, METHOD, MODIFIER, CONSTRUCTOR, BASIC_BLOCK, PARAMETER,
LOCAL, STATE_SYMBOL, TYPE, RESOURCE, OBJECT, ACCOUNT_FIELD, AUTH_SUBJECT,
STORAGE_KEY, EXTERNAL_SYMBOL, UNKNOWN_TARGET
```

Node shape:

```json
{
  "node_id": "PFN-<24 hex>",
  "kind": "FUNCTION",
  "qualified_name": "Vault.withdraw(address,uint256)",
  "display_name": "withdraw",
  "build_variant_id": "PFB-...",
  "source_binding": {
    "source_file_id": "PFS-...",
    "start_byte": 100,
    "end_byte": 240,
    "start_line": 10,
    "start_column": 4,
    "end_line": 16,
    "end_column": 5,
    "statement_sha256": "..."
  },
  "signature": {
    "canonical": "withdraw(address,uint256)",
    "language_specific": {},
    "signature_fact_ref": ""
  },
  "attributes": []
}
```

`node_id` hashes ecosystem, build variant, node kind, qualified signature, and exact source binding. `EXTERNAL_SYMBOL` and `UNKNOWN_TARGET` require a reason and may omit a local source binding.

#### Occurrences

```json
{
  "occurrence_id": "PFO-<24 hex>",
  "kind": "CALL_SITE|READ_SITE|WRITE_SITE|BRANCH_PREDICATE|RETURN_SITE|SINK_SITE|AUTH_SITE|TRANSFER_SITE|CREATE_SITE",
  "enclosing_node_id": "PFN-...",
  "source_binding": {
    "source_file_id": "PFS-...",
    "start_byte": 300,
    "end_byte": 324,
    "start_line": 22,
    "start_column": 8,
    "end_line": 22,
    "end_column": 32,
    "statement_sha256": "..."
  },
  "ir_binding": {
    "compilation_unit_digest": "...",
    "block_id": "provider-local-stable-id",
    "instruction_id": "provider-local-stable-id",
    "ir_sha256": "..."
  }
}
```

Source fallback may leave `ir_binding` empty but must use `provenance_origin=SOURCE_PARSE` and weak precision.

#### Facts

Closed v1 relation kinds:

```text
CONTAINS
DECLARES
INHERITS_OR_IMPLEMENTS
EXACT_CFG_EDGE
EXACT_CFG_DOMINATES
EXACT_CFG_POST_DOMINATES
MAY_DEPENDENCY_FUNCTION
MAY_DEPENDENCY_CONTRACT
RESOLVED_STATIC_CALL
MAY_REACH_CHA
MAY_REACH_RTA
MAY_REACH_VTA
UNRESOLVED_DYNAMIC_CALL
READS_STATE
WRITES_STATE
READS_ACCOUNT_FIELD
WRITES_ACCOUNT_FIELD
SYNTACTIC_SINK
HOST_SEMANTIC_SINK
AUTH_CHECK_OCCURRENCE
VALUE_TRANSFER_OCCURRENCE
CREATE_OCCURRENCE
RESOURCE_FLOW_OCCURRENCE
OBJECT_FLOW_OCCURRENCE
HOST_CONSTRAINT_OCCURRENCE
```

Use `dominating_predicates`, never “access guards.” CFG domination is a structural relation; it does not prove that a predicate authorizes the action or holds on every semantic path.

Fact shape:

```json
{
  "fact_id": "PFF-<24 hex>",
  "relation_kind": "RESOLVED_STATIC_CALL",
  "subject_id": "PFN-...",
  "object_id": "PFN-...",
  "occurrence_ids": ["PFO-..."],
  "build_variant_id": "PFB-...",
  "provider_run_id": "run-local-provider-id",
  "capability_id": "evm.slither.calls.v1",
  "provenance_origin": "COMPILER_IR|SSA|AST|BYTECODE|SOURCE_PARSE|INDEX_REFERENCE",
  "precision": "EXACT|MAY|HEURISTIC|SYNTACTIC",
  "coverage_scope": "OCCURRENCE|FUNCTION|CONTRACT|PACKAGE|BUILD_VARIANT",
  "structural_confidence": "PROVIDER_EXACT|PROVIDER_MAY|SOURCE_FALLBACK|UNKNOWN",
  "context": {
    "call_dispatch": "INTERNAL|LIBRARY|INTERFACE|HIGH_LEVEL|LOW_LEVEL|DELEGATE|CREATE|DYNAMIC|UNKNOWN",
    "analysis_algorithm": "",
    "root_set_digest": "",
    "dominating_predicates": [],
    "host_semantic_kind": ""
  },
  "semantic_authority": "ADDITIVE_PROPOSAL_ONLY"
}
```

`fact_id` hashes the normalized relation, endpoints, occurrences, variant, capability, precision, and semantic context. Provider run and host execution IDs are excluded from portable identity but retained as provenance references. Two providers may therefore attest the same portable fact; the payload stores a sorted `attestations` list when deduplicating identical semantic facts.

Do not use a single numeric confidence score. Keep these orthogonal:

- provenance origin;
- structural precision;
- coverage status;
- provider capability;
- application authority.

#### Coverage

Coverage is positive bookkeeping, not clean authority:

```json
{
  "coverage_id": "PFC-<24 hex>",
  "capability_id": "evm.slither.cfg.v1",
  "build_variant_id": "PFB-...",
  "status": "FULL|PARTIAL|UNSUPPORTED|UNKNOWN",
  "eligible_source_file_ids": [],
  "covered_source_file_ids": [],
  "excluded_source_file_ids": [],
  "unresolved_debt_ids": [],
  "denominator_digest": "...",
  "terminal_negative_authority": false
}
```

`FULL` is legal only when the exact eligible denominator equals the covered denominator and there is no capability-scoped unresolved debt. Even then, absence of a fact cannot suppress an obligation.

### 5.2 Environment-specific receipt

`mechanical_program_facts_receipt.v1.json`:

```json
{
  "schema_version": "plamen.mechanical_program_facts_receipt.v1",
  "run_id": "...",
  "status": "WRITTEN|REUSED|DEGRADED|UNAVAILABLE|FAILED|STALE",
  "audit_snapshot": {
    "snapshot_digest": "...",
    "source_scope_digest": "...",
    "audit_config_digest": "...",
    "methodology_digest": "...",
    "toolchain_digest": "..."
  },
  "source_manifest": {
    "policy_version": "plamen.program_facts_source_scope.v1",
    "eligible_files": [],
    "excluded_files": [],
    "file_count": 0,
    "byte_count": 0,
    "manifest_digest": "..."
  },
  "build_attempts": [],
  "provider_runs": [],
  "worker_transaction_refs": [],
  "phase_io": {
    "contract_digest": "...",
    "launch_digest": "...",
    "input_set_digest": "...",
    "work_unit_key": "...",
    "ledger_record_digest": "..."
  },
  "artifacts": {
    "facts": {"path": "mechanical_program_facts.v1.json", "document_sha256": "...", "file_sha256": "...", "size": 0},
    "debt": {"path": "mechanical_program_facts_debt.v1.json", "document_sha256": "...", "file_sha256": "...", "size": 0}
  },
  "reuse_key": "...",
  "receipt_sha256": "<digest excluding this field>"
}
```

Each `build_attempt` binds:

- build variant ID and digest;
- build root as an opaque root ID plus project-relative path where possible;
- manifest and lockfile hashes;
- dependency-closure digest;
- compiler/toolchain names, versions, executable/module hashes, target triples;
- profiles, features, tags, remappings, defines, package selection, generated-source policy;
- exact eligible, compiled, excluded, and failed source IDs;
- build stdout/stderr CAS references and bounded/truncated flags;
- exit/timeout status and debt IDs.

Each `provider_run` binds:

- provider ID, schema version, provider registry digest, implementation digest;
- resolved executable or module digest and version output digest;
- parser callable/source digest and expected raw schema digest;
- exact argv as an array;
- allowed environment names and value digests (secrets must be redacted and normally forbidden);
- working-directory root ID;
- OS, architecture, runtime versions, locale and filesystem case-sensitivity;
- WorkerTransaction WorkPlan, arm, completion/debt, CAS, and incorporation references;
- capabilities requested, emitted, unavailable, and partial;
- input and output ceilings, timeouts, truncation, cancellation, and process-scope-zero proof.

The receipt is environment-specific by design. It must never be folded into the portable payload hash.

The existing audit snapshot is stored in `Checkpoint.audit_snapshot` and serialized in `scratchpad:_v2_checkpoint.json`. `audit_snapshot.py::build_audit_snapshot` exposes source counts and digests but not the exact file rows or compiled-file denominator. Add a public source-manifest builder that shares the same walker/policy code; do not reconstruct the set differently inside each provider.

### 5.3 Debt

`mechanical_program_facts_debt.v1.json` always exists:

```json
{
  "schema_version": "plamen.mechanical_program_facts_debt.v1",
  "snapshot_digest": "...",
  "source_manifest_digest": "...",
  "authority": "MANDATORY_REVIEW_NO_NEGATIVE_INFERENCE",
  "debts": [],
  "summary": {
    "by_reason": {},
    "affected_capabilities": [],
    "affected_source_file_ids": [],
    "has_blocking_reuse_debt": false
  },
  "debt_sha256": "<digest excluding this field>"
}
```

Closed initial debt reasons:

```text
PROVIDER_UNAVAILABLE
PROVIDER_UNSUPPORTED_ECOSYSTEM
PROVIDER_IDENTITY_UNBOUND
PROVIDER_VERSION_DRIFT
EXECUTABLE_DIGEST_DRIFT
PARSER_DIGEST_DRIFT
BUILD_CONFIGURATION_UNRESOLVED
BUILD_FAILED
BUILD_PARTIAL
DEPENDENCY_CLOSURE_UNRESOLVED
GENERATED_SOURCE_UNBOUND
SOURCE_EXCLUDED
SOURCE_CHANGED_DURING_RUN
SOURCE_CASE_COLLISION
SOURCE_ESCAPE_REJECTED
UNSUPPORTED_CONSTRUCT
UNRESOLVED_DYNAMIC_CALL
UNRESOLVED_PROXY_DISPATCH
UNRESOLVED_ASSEMBLY
ANALYSIS_TIMEOUT
OUTPUT_TRUNCATED
RESOURCE_LIMIT
RAW_OUTPUT_MALFORMED
DANGLING_REFERENCE
DUPLICATE_ID_CONFLICT
PROVIDER_DISAGREEMENT
CAPABILITY_PARTIAL
OS_PROCESS_SCOPE_UNPROVEN
WORKER_TRANSACTION_INCOMPLETE
PHASE_IO_INCORPORATION_FAILED
STALE_SNAPSHOT
UNSUPPORTED_HOST_SEMANTICS
LICENSE_OR_DISTRIBUTION_RESTRICTED
```

Each debt row has stable `debt_id`, scope IDs, provider/capability/build references, explanation, evidence references, `retryable`, `blocks_reuse`, and `terminal_negative_authority=false`.

Unsupported behavior is a valid zero-fact payload with `coverage.status=UNSUPPORTED`, a receipt status of `UNAVAILABLE` or `DEGRADED`, and at least one debt row. Tool absence must not result in absent sidecars or a “successful empty graph.”

### 5.4 Disagreement

Disagreement is generated by a separate deterministic consumer:

```json
{
  "schema_version": "plamen.program_facts_disagreement.v1",
  "disagreement_id": "PFDG-...",
  "canonical_obligation_id": "PFOB-...",
  "providers": [],
  "fact_ids": [],
  "conflict_kind": "TARGET|PRECISION|SOURCE_BINDING|DISPATCH|COVERAGE|HOST_SEMANTICS",
  "required_action": "ADD_REVIEW_OBLIGATION",
  "resolution": "UNRESOLVED",
  "terminal_negative_authority": false
}
```

There is no automatic winner. An exact occurrence from one provider may rank higher for display, but the conflicting fact and debt remain visible until independently reconciled.

## 6. PhaseIO and WorkerTransaction ownership

### 6.1 Required prerequisite

Land the P0-AE immutable CAS/projection work and P0-AM WorkerTransaction/`NativeCommandAdapter` authority before enabling a semantic provider in production. The program-facts implementation consumes, rather than duplicates, these reviewed APIs:

```python
compile_phase_work_roster(...)
compile_worker_plan(...)
execute_worker_transaction(plan, adapter, cancel_token) -> ExecutionRef
recover_worker_transactions(run_id, scratchpad) -> RecoveryStatus
incorporate_worker_execution(execution_ref, phase_io_contract) -> IncorporationRef
reconcile_phase_work_roster(roster) -> PhaseExecutionStatus
```

`OwnedProcessScope` owns creation, Job/cgroup/process-group assignment, identity, stream ceilings, cancellation, termination, population-zero proof, and cleanup. `NativeCommandAdapter` owns argv/tool-policy shaping and provisional raw parsing only. It cannot certify process closure or publish canonical outputs.

Do not call `subprocess`, `_run_hardened`, Slither in-process, `rust-analyzer scip`, `scip-go`, a Move compiler, or a Go helper directly from the program-facts orchestrator.

### 6.2 New PhaseIO work unit

Register this exact resolver shape in `scripts/phase_io_contracts.py::resolve_phase_io_contract` before the generic rejection branch:

```text
phase: recon
work_unit_id: program_facts_bake
model_invoked: false
writer: DRIVER
artifact_class: DRIVER_GENERATED
write_mode: CREATE or REPLACE_EXACT_PRESTATE through PhaseIO incorporation
```

Exact outputs:

```text
mechanical_program_facts.v1.json
mechanical_program_facts_receipt.v1.json
mechanical_program_facts_debt.v1.json
```

Schema gates:

- facts: `SIGNED_CLOSED_SCHEMA_CROSS_REFERENCE_AND_SOURCE_BINDING_VALID`;
- receipt: `SNAPSHOT_BUILD_TOOL_EXECUTION_AND_OUTPUT_PARITY`;
- debt: `TOTAL_UNSUPPORTED_PARTIAL_AND_DISAGREEMENT_ACCOUNTING`.

Immutable inputs must include the exact `_v2_checkpoint.json` prestate or a PhaseIO-produced immutable snapshot binding, the provider registry, the schema files, and any driver-produced build-plan/config artifacts. The source manifest itself is embedded and digest-bound in the receipt because current PhaseIO identities do not enumerate project source files individually. The WorkPlan binds `source_snapshot_digest` and exact source-manifest digest.

Because the receipt must include PhaseIO incorporation identity while PhaseIO validates the receipt, avoid a digest cycle:

1. Prebind `PhaseIOContract`, `LaunchSpec`, and immutable-input prestate.
2. Compile provider WorkPlans.
3. Execute providers into attempt staging/CAS.
4. Driver parses and composes the three staged canonical documents.
5. Receipt binds contract digest, launch digest, input-set digest, and the provider execution refs, but leaves `ledger_record_digest` empty with `ledger_binding_state=PRECOMMIT`.
6. PhaseIO atomically incorporates the exact three bytes and records them with `record_work_unit_artifacts`.
7. Store the resulting ledger row outside the immutable receipt as the normal artifact ledger authority. Do not rewrite the receipt after commit.

If a post-commit linkage is required, add a separate PhaseIO incorporation receipt owned by the generic transaction layer; do not create a self-referential program-facts receipt.

### 6.3 Stage location

In `scripts/plamen_driver.py`, call a new `_ensure_program_facts_bake(checkpoint, scratchpad, config)`:

1. after `_bind_checkpoint_audit_snapshot` has returned `SNAPSHOT_NEW` or `SNAPSHOT_MATCH`;
2. after the run lock is acquired;
3. before the current mechanical `run_recon_prepass(config)` call;
4. before any recon model worker, pre-breadth SCIP hook, enumeration gate, chain preparation, or prompt slice generation.

On resume, run the side-effect-free validator first. Reuse only when the exact reuse key and PhaseIO ledger binding match. Otherwise do not overwrite prior canonical evidence in place: require an authorized exact-prestate replacement transaction or a distinct run destination.

For both SC and L1, this is a deterministic recon prework unit, not a model phase. Do not repurpose the current L1 `bake` phase: that phase has model/tool probing and a `primitive_status.md` fallback, while program facts require identical snapshot/receipt/PhaseIO semantics in SC and L1.

### 6.4 Ownership split

| Component | Owns | Must not own |
|---|---|---|
| Audit snapshot | stable run source/config/methodology/toolchain digest | compiled denominator or provider success |
| Program-facts planner | provider selection, exact source/build denominator, WorkPlans | process creation, canonical writes |
| WorkerTransaction | attempts, process/write scope, streams, CAS, completion/debt | semantic truth, canonical publication |
| Provider adapter | tool invocation and raw-format parser | cleanup proof, output authority |
| Program-facts composer | strict normalization, IDs, coverage/debt/disagreement | direct tool launch |
| PhaseIO | exact canonical incorporation and ledger | fact interpretation |
| Consumers | additive obligations/ranking/slices | suppression, demotion, clean certification |

## 7. Provider registry and ecosystem rollout

Add `rules/program-facts-provider-registry.v1.json`, validated by `scripts/program_facts_provider_registry.py`. It is a reviewed closed map, not environment discovery. Each row binds:

- provider ID and adapter module/symbol;
- supported ecosystem/language/toolchain ranges;
- capability IDs and maximum precision;
- raw schema/parser binding;
- executable/module resolution policy and expected version syntax;
- pinned distribution name/version/checksum or module source digest;
- license/distribution classification;
- time/memory/output limits;
- supported OS/architectures;
- fallback provider and maximum fallback precision;
- host-semantic authority flags, always additive;
- installation provenance and supply-chain policy.

Unknown provider, tool drift, unpinned download, registry mismatch, or license restriction yields debt.

### 7.1 EVM — first production provider

Create `scripts/program_facts_providers/evm_slither.py` with:

```python
def plan_evm_slither(context: ProviderContext) -> ProviderPlan
def parse_evm_slither_raw(raw: bytes, plan: ProviderPlan) -> ProviderResult
def normalize_evm_slither(result: ProviderResult) -> FactContribution
```

Run a pinned helper subprocess through `NativeCommandAdapter`; do not import Slither into the driver or mutate process-wide `FOUNDRY_PROFILE`. Bind the exact `slither-analyzer` distribution, Python interpreter, helper module digest, compiler/Solc, Crytic compile config, Foundry/Hardhat/Truffle build roots, remappings, profiles, optimizer/EVM version, dependencies, generated files, and compiled denominator.

Emit:

- functions/contracts/inheritance/modifiers and exact source occurrences;
- exact CFG edges and provider-computed dominators/post-dominators when replayable;
- SlithIR typed reads/writes and operation occurrences;
- dependency results labeled `MAY_DEPENDENCY_FUNCTION` or `MAY_DEPENDENCY_CONTRACT` with context;
- resolved internal/library/interface/high-level calls;
- low-level/delegate/create call occurrences with dispatch classification;
- syntactic sinks distinct from EVM host-semantic sinks;
- unresolved proxy, dynamic dispatch, assembly/Yul, compiler/build, and truncated-analysis debt.

Never translate a dominating predicate into “access guard.” Never translate successful Slither compilation into complete semantic coverage.

Release EVM in emit-only mode first. Then enable one additive consumer at a time under measurement.

### 7.2 Go — second provider family

Add a small reviewed helper under `tools/program-facts-go/` with its own pinned `go.mod` and `go.sum`. Use `go/packages` and `go/ssa` from a pinned `golang.org/x/tools`. Do not use deprecated `go/pointer`, and do not make Joern the initial dependency.

Create `scripts/program_facts_providers/go_ssa.py`. Bind Go version, module/workspace files, build tags, GOOS/GOARCH, cgo policy, replacements/vendor state, package patterns, generated-file policy, test exclusion, and exact loaded package/file denominator.

Capabilities are separate:

- `go.ssa.cfg.v1`;
- `go.ssa.calls.static.v1`;
- `go.ssa.reachability.cha.v1`;
- `go.ssa.reachability.rta.v1`;
- `go.ssa.reachability.vta.v1`.

Emit `MAY_REACH_CHA`, `MAY_REACH_RTA`, and `MAY_REACH_VTA` as distinct facts. RTA/VTA require a digest-bound root set and algorithm limits. CHA may be the conservative default may-reachability baseline. Never merge the algorithms into one unlabeled call graph.

### 7.3 Generic Rust, Solana, and Soroban

Generic Rust initially supports:

- rust-analyzer/SCIP references as `INDEX_REFERENCE`, `REFERENCE_ONLY`, or `MAY`;
- a pinned, explicitly experimental rustc MIR helper only on a supported toolchain;
- stable source fallback as `SOURCE_PARSE`/`SYNTACTIC`.

The current SCIP co-location callee heuristic must remain heuristic and its caps must become debt. It cannot be upgraded by renaming the source `scip`.

Solana and Soroban require separate host-semantic adapters over the Rust substrate:

`scripts/program_facts_providers/solana_host.py` recognizes, with exact source/SDK bindings where available:

- account metas and Anchor constraints;
- signer, writable, owner, executable, discriminator, and rent/data constraints;
- PDA seeds, program ID, bump, derivation occurrences;
- CPI targets, remaining accounts, arbitrary account forwarding;
- lamport/token ownership and transfer/create/close/realloc occurrences.

`scripts/program_facts_providers/soroban_host.py` recognizes:

- authorization trees and `require_auth` subjects/arguments;
- contract client/cross-contract invocation;
- instance/persistent/temporary storage class;
- TTL extension, archive/restore behavior;
- SAC/token-client flows and custom authorization.

Generic Rust call/CFG facts never imply these host properties. Unrecognized macros, generated code, SDK-version drift, or unresolved expansion creates `UNSUPPORTED_HOST_SEMANTICS` debt.

### 7.4 Aptos and Sui Move

Do not keep the current single `_bake_move_graph` as semantic authority. Add separate:

- `scripts/program_facts_providers/aptos_move.py`;
- `scripts/program_facts_providers/sui_move.py`.

Bind the exact Aptos/Sui CLI/compiler, package/lock/address configuration, dependency closure, bytecode/source maps, language edition, named addresses, features, and upgrade context. Emit distinct capabilities for:

- modules/functions/resources/objects;
- signer/reference flow;
- abilities, generics, phantom parameters, native functions;
- borrow/move/copy/read/write/global storage operations;
- Aptos account/resource semantics;
- Sui object ownership/shared/immutable/dynamic-field semantics;
- `TxContext`, transfer/share/freeze/delete/create occurrences;
- entry/visibility/friend/package boundaries.

Missing source maps, compiler/version mismatch, native behavior, generic resolution, upgrades, or object/resource semantics produce debt. A fact from one Move ecosystem is not portable semantic authority for the other.

### 7.5 DAML

Publish a valid unsupported bundle:

- zero facts;
- coverage `UNSUPPORTED`;
- receipt status `UNAVAILABLE`;
- `PROVIDER_UNSUPPORTED_ECOSYSTEM` debt.

Do not synthesize a source-parser graph and call the typed CPG available.

## 8. Dedicated sidecar and legacy graph reference

### 8.1 Initial release

Keep `_mechanical_graph.json` v2 byte behavior unchanged for the first emit-only and additive-consumer releases. Program-fact consumers call:

```python
load_bound_program_facts(
    scratchpad,
    expected_snapshot_digest,
    required_capabilities=(),
) -> ProgramFactsBundle
```

The loader validates all three sidecars, PhaseIO ledger ownership, hashes, source/build/tool receipt links, closed schemas, cross-references, and debt. It returns explicit `AVAILABLE`, `DEGRADED`, `UNSUPPORTED`, `STALE`, or `INVALID`, never `None == clean`.

### 8.2 Later legacy graph reference

Only after `_mechanical_graph.json` itself has a single PhaseIO owner and atomic writer, introduce `plamen.mechanical_graph.v4`:

```json
{
  "program_facts_ref": {
    "facts_identity": "scratchpad:mechanical_program_facts.v1.json",
    "facts_schema": "plamen.mechanical_program_facts.v1",
    "payload_sha256": "...",
    "receipt_identity": "scratchpad:mechanical_program_facts_receipt.v1.json",
    "receipt_sha256": "...",
    "debt_identity": "scratchpad:mechanical_program_facts_debt.v1.json",
    "debt_sha256": "...",
    "status": "AVAILABLE|DEGRADED|UNSUPPORTED|STALE|INVALID",
    "capability_ids": []
  }
}
```

The reference is discovery metadata only. Consumers must still validate the sidecars and ledger. Do not overload reserved inline v3. Retain v3 parsing as legacy proposal-only migration behavior until explicit retirement tests exist.

Update `_write_mechanical_graph_json` only when graph ownership migrates: accept a validated `ProgramFactsRef` argument and construct v4 atomically. Never preserve arbitrary unknown raw keys. Update `enumeration_gate::_load_graph` to return a typed `LegacyGraphEnvelope` if it needs the ref; program-fact consumers should not depend on `_load_graph`.

## 9. Additive consumers

All consumer outputs are deterministic driver-owned PhaseIO work units with their own schemas and receipts. No model reads the full raw sidecar by default.

### 9.1 G1 enumeration union

At `scripts/enumeration_gate.py::compute_enumeration_obligations`:

```text
final_required = legacy_required UNION graph_extra
```

Never replace or shrink `legacy_required`. Generate graph-extra obligations only from positively bound facts:

- state/account/resource/object co-reference;
- call seam;
- write/read seam;
- unresolved dynamic call;
- syntactic/host sink;
- domination/post-domination review question.

Deduplicate by `canonical_obligation_id`, not prose. Any unsupported/degraded capability adds a coverage-debt obligation; it does not remove an existing obligation.

### 9.2 G2 prioritization and slicing

At the coverage-gap and exploration path, use facts to:

- rank existing obligations;
- build bounded relevant function/occurrence slices;
- add provider disagreements and unresolved edges;
- link exact source occurrences.

Ranking must be monotonic-additive. A legacy obligation without a graph hit retains its original priority floor. No score may be negative, and graph absence is not a demotion feature.

### 9.3 M2 fact-axis family

At `compute_hot_function_set` and `compute_axis_coverage_gaps`, add a separate `PROGRAM_FACT_SEAM` axis family. It is not an “examined” marker and cannot clear a GAP. Deduplicate its generated work by canonical obligation ID.

M1 remains unchanged through the first measured releases. If M1 later receives facts, that is a separately gated experiment after G1/G2/chain/M2 evidence.

### 9.4 Chain preparation

At `scripts/chain_prep.py::compute_chain_candidate_pairs`, union fact-derived seam pairs and bounded slices with existing candidate pairs. Preserve the existing state-resolution and finding-evidence path. Do not replace `_parse_state_write_map`; its documented “Access Guard” column is not currently parsed and should not be retrofitted with domination semantics.

Useful positive additions:

- resolved/may call seam;
- state/resource/object write-to-read seam;
- external call or host sink followed by state mutation;
- create/initialize/upgrade seam;
- auth occurrence and protected effect occurrence;
- unresolved dynamic/proxy/CPI/client-call seam.

No path, post-dominator, or negative reachability result may remove a pair.

### 9.5 Security-obligation foundation

Do not feed the new facts through the existing inline v3 `feature_facts` path. Add a dedicated program-fact projection in `security_obligation_authority.py` that accepts only validated fact slices and emits proposal-only obligation candidates plus debt. Keep asset-representation and occurrence-semantic-edge authorities distinguishable.

## 10. Prompt exposure

Current prompts mostly consume human-readable `caller_map.md`, `state_write_map.md`, `function_summary.md`, call-graph projections, enumeration obligations, and chain candidates. Preserve that bounded-input pattern.

Add `scripts/program_facts_slicing.py`:

```python
build_program_facts_slice(bundle, request: SliceRequest) -> ProgramFactsSlice
render_program_facts_slice_markdown(slice) -> str
validate_program_facts_slice(slice, bundle) -> None
```

Per work unit, PhaseIO materializes:

```text
program_facts_slices/<phase>/<work-unit-id>.json
program_facts_slices/<phase>/<work-unit-id>.md
```

Every slice includes:

- snapshot/payload/receipt/debt digests;
- requested obligation IDs and selection predicate;
- exact fact/node/occurrence IDs;
- bounded source excerpts or references with source hashes;
- provider capability/precision/provenance;
- disagreement and coverage debt banner;
- the fixed statement: “Structural evidence only; absence is not safety; do not suppress, demote, refute, or mark examined.”

The selection request is bound before model launch and recorded as a PhaseIO immutable input. Cap facts, bytes, excerpts, and graph radius deterministically. Truncation generates slice debt and an explicit “additional facts omitted” obligation.

Update only the relevant prompt templates after slice validation is live:

- `prompts/shared/v2/phase3-breadth.md`;
- `prompts/shared/v2/phase4b-depth.md`;
- `prompts/shared/v2/phase4b7-enumgap-exploration.md`;
- `prompts/shared/v2/phase4b8-axis-coverage.md`;
- `prompts/shared/v2/phase4c-chain-agent2.md`;
- `prompts/shared/v2/phase4c-chain-iter2.md`;
- ecosystem depth templates for EVM, Solana, Soroban, Aptos, and Sui.

Prompts receive the slice, not the raw payload, raw tool output, provider command, hidden ranking trace, or benchmark ground truth.

## 11. Cache, resume, concurrency, and crash behavior

### 11.1 Reuse key

Compute:

```text
reuse_key = sha256(canonical_json({
  snapshot_digest,
  source_scope_digest,
  source_manifest_digest,
  build_variant_digests,
  provider_registry_digest,
  provider_identity_digests,
  parser_digests,
  requested_capability_ids,
  limits_and_policy_digest,
  canonicalization_version,
  payload_schema,
  receipt_schema,
  debt_schema
}))
```

Reuse requires:

- exact reuse-key equality;
- valid self-digests and file hashes;
- matching PhaseIO contract/launch/input binding and artifact ledger owner;
- no stale source/build/tool/parser/capability debt;
- immutable CAS objects present where policy requires replay;
- no active WorkerTransaction attempt;
- exact three-file denominator.

Mtime, file existence, a successful prior exit, or matching tool version text alone is insufficient.

### 11.2 Concurrency

- Freeze a one-unit `PhaseWorkRoster` for the program-facts bake and one WorkPlan per provider/build variant.
- Provider attempts use unique immutable directories and may run in parallel only when build/mutation scopes do not overlap.
- Dependency installation, compiler cache writes, generated sources, and build directories require explicit mutation leases or isolated copies.
- A deterministic composer waits for every required attempt to reach completion/debt, sorts contributions by stable IDs, and writes one atomic staged bundle.
- No provider writes the canonical sidecar or legacy graph.
- Lock order is fixed: run lock → roster/attempt registry → provider mutation lease → PhaseIO transaction. Never acquire in reverse.

### 11.3 Crash and cancellation

- Recover armed attempts before reuse or launch.
- Completion requires zero owned process population and successful cleanup.
- A hard crash after publication arm but before commit is resolved by generic PhaseIO recovery, not by overwriting.
- Timeout, stream overflow, parse failure, nonzero exit, cancellation, process-leak uncertainty, or output-denominator mismatch produces durable execution debt.
- Partial raw output may be retained as proposal material but cannot mint provider completion.
- If one provider fails, compose a degraded bundle from valid completed providers plus debt; never infer facts from failed raw output without a separately labeled source fallback.

### 11.4 Security and supply chain

- Resolve executables before arm and hash exact bytes.
- For Python providers, bind interpreter, installed distribution metadata/RECORD, helper module tree, and parser source.
- For Go/Rust helper builds, check in source plus lock/sum files; build through a pinned toolchain; hash the produced binary; never `go install ...@latest`.
- Disallow network access during bake by default. Any dependency acquisition is a separate setup step with pinned URL/version/checksum and a receipt.
- Environment is deny-by-default. Permit only reviewed names; hash values; forbid secrets unless a provider explicitly requires a redacted, nonsemantic credential.
- Bound stdout/stderr/raw output/file counts/node counts/fact counts/recursion/radius/time/memory.
- Reject archives/path traversal/symlink or reparse escapes and case-fold collisions.
- Treat compiler plugins, build scripts, proc macros, and generated code as potentially executable supply chain; isolate them and record their closure or degrade coverage.
- CodeQL, if ever supported, is optional and license/distribution aware. It is not a required first provider.
- No MCP service is part of the deterministic fact authority.

## 12. Exact implementation map

### 12.1 New modules and symbols

| File | Required symbols/responsibility |
|---|---|
| `scripts/program_facts_types.py` | enums/dataclasses; canonical JSON; signed validators; `ProgramFactsPayload`, `ProgramFactsReceipt`, `ProgramFactsDebt`, `ProgramFactsBundle`; cross-reference and additive-authority validation |
| `scripts/program_facts_source_manifest.py` | `build_program_facts_source_manifest`, shared source selection, case/symlink/physical identity checks, compiled-denominator reconciliation |
| `scripts/program_facts_provider_registry.py` | `load_program_facts_provider_registry`, tool resolution, registry/capability validation |
| `scripts/program_facts_provider_api.py` | `ProviderContext`, `ProviderPlan`, `ProviderResult`, `FactContribution`, provider protocol |
| `scripts/program_facts_bake.py` | `plan_program_facts_bake`, `execute_program_facts_bake`, `compose_program_facts_bundle`, `validate_program_facts_resume`, `ensure_program_facts_bake` |
| `scripts/program_facts_loader.py` | `load_bound_program_facts`, strict three-artifact/ledger/status loader |
| `scripts/program_facts_slicing.py` | bounded slice request, selection, schema validation, Markdown projection |
| `scripts/program_facts_obligations.py` | canonical obligation IDs, additive union, disagreement and debt obligations |
| `scripts/program_facts_providers/evm_slither.py` | EVM plan/raw parse/normalize |
| `scripts/program_facts_providers/go_ssa.py` | Go helper plan/raw parse/normalize |
| `scripts/program_facts_providers/rust_reference.py` | SCIP/RA reference and MIR experimental lanes |
| `scripts/program_facts_providers/solana_host.py` | Solana host-semantic enrichment |
| `scripts/program_facts_providers/soroban_host.py` | Soroban host-semantic enrichment |
| `scripts/program_facts_providers/aptos_move.py` | Aptos Move adapter |
| `scripts/program_facts_providers/sui_move.py` | Sui Move adapter |
| `scripts/program_facts_providers/daml_unsupported.py` | deterministic unsupported bundle contribution |
| `rules/program-facts-provider-registry.v1.json` | reviewed closed capability/tool matrix |
| `rules/schemas/*.schema.json` | six strict schemas listed above |
| `tools/program-facts-go/go.mod`, `go.sum`, source | pinned Go SSA helper |

P0-AM should provide, in its own reviewed modules, `WorkerTransaction`, `NativeCommandAdapter`, WorkPlan/roster compilation, recovery, CAS, and PhaseIO incorporation. Do not put reduced copies in `program_facts_bake.py`.

### 12.2 Existing modules and call sites

| Existing symbol/call site | Change |
|---|---|
| `audit_snapshot.py::_source_component` / `build_audit_snapshot` | factor/publicize exact source-manifest enumeration so snapshot and provider denominator share policy; retain existing snapshot schema unless separately migrated |
| `production_source_scope.py` | extend shared path policy only through versioned, parity-tested helpers; do not let providers implement different walkers |
| `phase_io_contracts.py::resolve_phase_io_contract` | register `recon/program_facts_bake` and later slice/obligation work units; fixed outputs and exact inputs; `model_invoked=False` |
| `artifact_ledger.py::record_work_unit_artifacts` | use unchanged as canonical owner; add validator hooks only if generic structured-output gates require them |
| `plamen_driver.py` after `_bind_checkpoint_audit_snapshot` and run-lock acquisition, before `run_recon_prepass` | call `_ensure_program_facts_bake`; perform side-effect-free resume validation first |
| `plamen_driver.py` current pre-breadth `_bake_rust_graph`/`_bake_go_graph` hooks | retain only as legacy graph projections initially; never treat them as typed sidecar authority; later route native execution through WorkerTransaction |
| `recon_prepass.py::_bake_evm_slither_graph` and language bakes | keep for compatibility projection initially; do not call from typed provider; eventually make them projections from validated facts where lossless |
| `recon_prepass.py::_write_mechanical_graph_json` | no PR21 arrays; later atomic v4 writer with validated ref after graph ownership migration |
| `enumeration_gate.py::_load_graph` | stop using as a program-fact loader; later return typed legacy envelope to avoid current key loss |
| `enumeration_gate.py::compute_enumeration_obligations` | union fact-derived obligations with legacy required set |
| `enumeration_gate.py::compute_hot_function_set` | additive nonnegative program-fact ranking feature; preserve legacy set/floor |
| `enumeration_gate.py::compute_axis_coverage_gaps` | separate `PROGRAM_FACT_SEAM` axis; cannot clear GAP or set examined |
| `chain_prep.py::compute_chain_candidate_pairs` | union fact-derived seams/slices; never remove existing pairs |
| `security_obligation_authority.py::_extract_graph_facts` | add separate bound program-fact projection path, not inline-v3 injection |
| `asset_representation_foundation.py::extract_semantic_edge_foundation` | retain v3 proposal-only legacy behavior; do not reinterpret as new sidecar authority |
| shared/ecosystem prompt templates listed in §10 | add only bounded validated slice inputs and authority banner |
| `plamen.py` setup/install | install checked-in helper/tools and schemas; replace unpinned provider installs; include health/version/digest reporting |
| `requirements.txt` | add compatible pinned `protobuf` because `plamen_l1/scip_pb2.py` imports it; pin provider/runtime dependencies or isolate them in provider lockfiles |

Current packaging hazards to close:

- `plamen.py` installs `slither-analyzer` without a version.
- `plamen.py` installs `scip-go@latest`.
- `plamen_l1/scip_reader.py` documents `protobuf>=5`, `scip_pb2.py` imports it, but core `requirements.txt` omits it.
- New `tools/` content is not covered merely because `scripts/` and `plamen_l1/` are installed; explicitly add it to install, cachebuster, uninstall/repair, doctor, and packaging tests.

## 13. Rollout order

Do not combine these stages into one PR.

### Stage 0 — authority prerequisites

1. Complete P0-AE PhaseIO CAS/projection/recovery.
2. Complete P0-AM WorkerTransaction with `NativeCommandAdapter` on supported OSes.
3. Prove no typed-provider native launcher can bypass it.
4. Add generic structured-output validation and exact three-file PhaseIO transaction fixture.

Exit: PhaseIO is the only canonical publisher; process-scope-zero and exact staging denominator are proven.

### Stage 1 — contract and fixture substrate

1. Add schemas, types, canonicalization, source manifest, registry, loader, unsupported bundle, and fault fixtures.
2. Register `recon/program_facts_bake`.
3. Add resume/reuse and stale-rejection tests.
4. No semantic provider and no consumer.

Exit: deterministic zero/unsupported bundle works on every supported backend and OS.

### Stage 2 — EVM emit-only

1. Add pinned EVM helper and Slither provider.
2. Publish sidecars; do not change prompts, enumeration, ranking, chain, or reports.
3. Compare portable payload determinism across clean reruns and Windows/Linux.

Exit: exact receipt/coverage/debt and no legacy behavior change.

### Stage 3 — one additive consumer per release

Order:

1. G2 bounded slices/ranking;
2. G1 obligation union;
3. chain seam union;
4. M2 `PROGRAM_FACT_SEAM` axis.

M1 remains unchanged. Each release has its own A/B and rollback switch that disables only the consumer, not receipt/debt generation.

### Stage 4 — Go

Add pinned Go SSA helper, algorithm-labeled reachability, monorepo/build-tag fixtures, and L1 A/B.

### Stage 5 — Rust host ecosystems

Add generic Rust reference/MIR experimental capabilities, then Solana and Soroban adapters separately. No generic Rust-to-host semantic promotion.

### Stage 6 — Aptos and Sui

Add separate compiler/toolchain adapters and ecosystem-specific fixtures/acceptance.

### Stage 7 — legacy graph v4 reference

Only after graph writer ownership and consumer migration are proven. Add ref, not arrays.

### Stage 8 — adaptive attention experiment

Outside this blueprint’s implementation scope. When ready, run the neutral 2×2 experiment:

```text
G0A0  no program facts, fixed attention
G1A0  program facts, fixed attention
G0A1  no program facts, adaptive attention
G1A1  program facts, adaptive attention
```

This separates CPG value from controller value and interaction effects.

## 14. Test and fault matrix

### 14.1 Schema and deterministic fixtures

For every schema:

- empty valid bundle;
- one fact of every node/occurrence/relation/precision/provenance kind;
- unknown key/enum rejection;
- duplicate JSON key rejection;
- self-digest mismatch;
- duplicate ID with identical and conflicting body;
- dangling subject/object/occurrence/build/capability/source reference;
- unsorted set array;
- float/NaN/infinity;
- line/column not replaying byte offsets;
- portable payload containing a host path, timestamp, PID, or executable path;
- forbidden authority flag set true.

Run byte-identical reruns with randomized provider iteration and filesystem enumeration order.

### 14.2 Source/build fixtures

- clean repository and dirty uncommitted source;
- mixed-case paths and case-only collision;
- Unicode composed/decomposed names;
- symlink, junction, reparse point, hardlink duplicate, traversal, outside explicit target;
- monorepo with multiple build roots;
- multiple Foundry profiles/remappings and Hardhat compiler variants;
- generated source included/excluded;
- dependency source and vendored source;
- mutually exclusive feature sets/build tags;
- source mutation before launch, during tool run, before parse, before PhaseIO commit;
- partial build, compiler mismatch, missing dependency, unresolved root;
- exact compiled denominator smaller/larger than eligible denominator.

### 14.3 Provider fixtures

EVM:

- inheritance, modifiers, overloaded functions, libraries/interfaces;
- internal/high-level/low-level/delegate/create calls;
- proxy/dynamic dispatch and inline assembly debt;
- state read/write, reentrancy-like external-call/state seams;
- CFG branch/loop/early return/revert/try-catch;
- dominance that is structural but not authorization;
- multi-contract and multi-build-root projects.

Go:

- interfaces, generics, method values, closures, reflection, init functions;
- CHA/RTA/VTA disagreement;
- no valid RTA roots;
- build tags, GOOS/GOARCH, workspace, replace/vendor, cgo debt;
- goroutine/channel/synchronization occurrences without semantic overclaim.

Rust/Solana/Soroban:

- macro/proc-macro expansion available and missing;
- trait/dynamic dispatch;
- SCIP caps/truncation;
- stable fallback versus pinned MIR;
- Solana signer/writable/owner/PDA/CPI/remaining-account cases;
- Soroban auth tree, storage classes, TTL/archive, SAC/custom auth.

Aptos/Sui:

- resource versus object operations;
- abilities/generics/native calls;
- signer/TxContext;
- dynamic fields/shared objects;
- missing source maps, dependency/upgrade/version mismatch.

DAML:

- deterministic unsupported artifacts and mandatory debt.

### 14.4 WorkerTransaction and PhaseIO faults

At every boundary inject:

- crash before arm, after arm, after child create, after scope assignment;
- timeout, cancellation, nonzero exit, signal termination;
- stdout/stderr overflow;
- child/grandchild leak and delayed grandchild;
- output missing/extra/duplicate/symlink/reparse;
- malformed raw JSON/protobuf and parser exception;
- CAS mutation or deletion;
- source/tool/parser drift after arm;
- crash before/after composition arm and before/after each publication;
- PhaseIO input-prestate drift and output-prestate collision;
- ledger write failure and recovery;
- two concurrent bakes for the same run;
- provider mutation-lease conflict;
- unsupported OS process authority.

No fault may produce a successful receipt without process-scope-zero, exact output denominator, valid parser binding, CAS parity, and PhaseIO incorporation.

### 14.5 Cross-OS, ecosystem, backend matrix

Minimum required matrix:

| OS | Filesystem concern | Backend | EVM | Go | Rust | Solana | Soroban | Aptos | Sui | DAML |
|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Windows 11 | NTFS case-insensitive, junction/reparse, Job Object | Claude PTY/headless, Codex, native | full | full | reference | host | host | fixture | fixture | unsupported |
| Ubuntu LTS | ext4 case-sensitive, cgroup v2 | Claude headless, Codex, native | full | full | reference/MIR exp. | host | host | full | full | unsupported |
| macOS current | APFS case behavior, process-group limitations | Codex/native where P0-AM is proven | emit/degraded per registry | emit/degraded | reference | host/degraded | host/degraded | fixture | fixture | unsupported |

“Full” means provider capability coverage for the exact fixture denominator, not negative audit authority. An OS without proven process-scope authority is `UNAVAILABLE`/debt, not an alternate direct-launch path.

Backends must yield the same program-fact payload for the same snapshot/toolchain because the bake is native and model-free. Backend-specific PhaseIO/WorkPlan receipts may differ only in explicitly environment-specific fields.

### 14.6 Consumer regression

- fact-disabled output byte parity with current legacy output;
- G1 union never smaller than legacy required set;
- ranking never lowers a legacy floor;
- chain pairs never removed;
- M2 program-fact axis never clears a preexisting gap or marks examined;
- unsupported/degraded bundle creates/reopens a review obligation;
- disagreement survives deduplication;
- slice truncation is visible;
- no raw sidecar or ground truth reaches prompts;
- removing the sidecar after ledger commit fails closed to debt, not fallback-clean.

## 15. A/B acceptance

### 15.1 First experiment: program facts only

Compare:

- `G0`: program-fact consumer disabled; current fixed roster/budgets.
- `G1`: one specified additive consumer enabled; identical fixed roster/budgets.

Hold constant:

- audit snapshot and source;
- backend/model versions;
- worker counts, roles, prompts except the bound slice input;
- time/token/tool budgets;
- phase order and verifier policy;
- finding dedup/severity/report logic;
- provider tools for non-CPG detectors;
- randomization/order policy.

Ground truth remains grader-only. Use hidden eligible fixtures and real historical cases not used to design prompts.

### 15.2 Metrics

Primary:

- unique independently confirmed root causes;
- application completeness over the frozen denominator;
- eligible root causes found only in G1 and lost from G0;
- false-safe/demoted/suppressed/reopened counts;
- verifier confirmation yield;
- unsupported/degraded negative-inference violations.

Secondary:

- duplicate and fragmentation rate;
- obligation-to-confirmed-finding yield;
- chain/root-cause consolidation quality;
- severity/report signal preservation;
- slice relevance and overlap;
- facts/debt shown versus used;
- wall time, CPU/memory, token cost, tool cost, prompt bytes;
- provider/build failure and stale-reuse rates.

Report confidence intervals and paired per-target differences, not only aggregate means.

### 15.3 Cutover gates

A consumer can default on only if all hold:

1. No observed suppression, demotion, refutation, examined-state, or clean certification caused by fact absence.
2. Legacy G1/M1/chain denominators have exact non-loss parity.
3. Recall is non-inferior under a predeclared paired bound, with uncertainty reported.
4. At least one held-out eligible root cause is gained and independently verified for the target ecosystem before claiming effectiveness.
5. Unsupported/degraded/fault cases reliably produce visible debt and review obligations.
6. Deterministic payload and exact resume/stale rejection pass on supported OSes.
7. Cost/time/prompt growth stays within predeclared limits.
8. Adversarial review finds no provider receipt, supply-chain, path, concurrency, or PhaseIO bypass.
9. Results reproduce on at least two ecosystems before making cross-ecosystem claims.

Roll back the consumer independently if a gate fails. Keep emit-only receipt/debt collection if it remains safe and useful for diagnosis.

### 15.4 Later 2×2 acceptance

Only after adaptive attention is independently implemented and validated, run G0A0/G1A0/G0A1/G1A1. Require the same no-loss/negative-authority gates for each arm and quantify the interaction term. Do not attribute an attention improvement to program facts or vice versa.

## 16. Definition of done

Revised PR21 is complete only when:

- the three sidecars are strict, signed, content/snapshot/build/tool bound, and PhaseIO-owned;
- all native providers use WorkerTransaction/`NativeCommandAdapter`;
- unsupported and partial cases publish total debt rather than disappear;
- the portable payload is host-independent and reproducible;
- exact source and compiled denominators are auditable;
- EVM emit-only ships before any consumer;
- every consumer is additive and individually switchable/measured;
- prompts receive only bounded validated slices;
- graph v2 remains compatible until a separately proven v4 reference migration;
- packages and provider tools are pinned and installed reproducibly;
- fixture, fault, cross-OS, ecosystem, and backend matrices pass;
- A/B gates show no recall/denominator loss and no negative-authority violation;
- adaptive attention remains a separate subsequent experiment.

The core design principle is simple: **typed program facts may create more questions and better routes to evidence; they may never declare that a question no longer needs asking.**
