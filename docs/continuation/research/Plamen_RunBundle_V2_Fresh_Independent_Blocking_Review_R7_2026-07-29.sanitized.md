# RunBundle V2 fresh independent blocking review - R7

Review date: 2026-07-29  
Reviewer role: fresh independent adversarial reviewer  
Overall disposition: **BLOCK**

This review is bound to the exact R7 handoff and freeze below. It covers local
implementation, deterministic replay, packaging, and fixture behavior only.
It is not B1 effectiveness evidence, audit-quality evidence, benchmark
evidence, production cutover authorization, or a comparative claim.

## 1. Review authority and exact submitted boundary

The requested handoff hash matched before any analysis:

| Artifact | Bytes | Raw SHA-256 |
|---|---:|---|
| `<LOCAL_USER_ROOT>\Downloads\Plamen_RunBundle_V2_Codex_Repair_Handoff_R7_2026-07-29.md` | 14,037 | `5dd38753ea05ef7fe4ce6fd79d98433133914620c5d62c3fd6cf4d7ba0f9faac` |
| `<LOCAL_USER_ROOT>\Downloads\Plamen_RunBundle_Evaluator_Implementation_Blueprint_2026-07-24.md` | 65,713 | `be5a97fed34286ca8e9197a38dcdbe62a254afa2ed6cd5fffbe1fcbd18053a5a` |
| `<LOCAL_USER_ROOT>\Downloads\Plamen_Plan_Completion_Audit_2026-07-24.md` | 13,932 | `357e049c1a738d2e8682f1f2e0c339dad77d876172e7cf0f1ddc8bf6d947a5de` |
| `<LOCAL_USER_ROOT>\Downloads\Plamen_Architecture_Supersession_Crosswalk_2026-07-24.md` | 70,357 | `e485320fb9b71e64bc676b3208f2531ca41c549fbac439c7d7e1d125b84ec926` |
| `<LOCAL_USER_ROOT>\Downloads\Plamen_RunBundle_V2_Local_Freeze_R7_2026-07-29.json` | 68,203 | `961c8556551f1ef432bad1f0e11a9329daf312f914ba34a5585a8ea4f2aac845` |
| `<LOCAL_USER_ROOT>\<PRIVATE_EVALUATOR_REPO>\dist\frozen-v7\plamen_eval_control-0.2.0-py3-none-any.whl` | 162,258 | `8ccc90f531f5ac788e23d78184be875ad1f0e5e936e41d00b767346b82bdf33f` |

The manifest's embedded self-digest was independently reproduced by removing
only `freeze_manifest_sha256`, serializing the remaining object as sorted,
compact JSON, and hashing the result:

`cd7be59ee425b22bc15b32ce72e3e63f6bd029c2295951ec2157eb2977e04a59`

Exact freeze replay before the review and again after all R7 adversarial work,
before the separate successor repair lane began, returned:

```json
{"freeze_manifest_sha256":"cd7be59ee425b22bc15b32ce72e3e63f6bd029c2295951ec2157eb2977e04a59","status":"REPLAYED"}
```

An independent verifier re-enumerated every declared glob and exact path,
compared the complete roster, byte length, and content digest for every file,
recomputed every tree preimage, checked the key-file bindings, and separately
replayed the wheel ZIP roster:

| Source set | Files | Tree SHA-256 |
|---|---:|---|
| Production runtime | 7 | `89f8b180f421c5079bb35b5fe21227778a8a9a57c4d4cd80da5697f0a93c53e2` |
| Production tests | 6 | `31be45ad9521c54feefb80ff2da289be0d1453780450867fd4c75069f7266e67` |
| Evaluator source | 28 | `d8eaa59a5aeac8d34b6cc5e59ecf5271d25bb2297ad3f0003f5bb0f801bd9131` |
| Evaluator schemas | 47 | `2423f116380205e01c6d7114112c2b95d24081a0fb7f09aa8a113ccc6484cad8` |
| Evaluator tests | 29 | `a64a84636c7771c7df0196c7680eab9f12873cf646b2fff1a20eabebc5870d9b` |
| Evaluator packaging | 2 | `e2fc6d9fd29aeff2fa21f0aef5212644226279232b81b3a87854b241adeabe34` |
| Freeze tooling | 2 | `f24b707632887106e231f4906fe304d2c26f670f88f20f7b8838c697e2fdcb39` |

The wheel independently contained 80 unique, traversal-safe members. Its
recomputed member-preimage digest was
`0828df80c035f5a428f0c43b17c7841b652a153287ef04bc30843f778c04b256`.

The repositories remained at the recorded revisions:

- evaluator: `345d016d0c86b6201e90cec908c37c6a66f739c3`
- production: `67a0f85adc7a8169d79a286908b00bef7adb764a`

Both worktrees were already large, shared, and dirty. No source, schema, test,
handoff, manifest, wheel, commit, provider, or audit state was changed by this
review.

## 2. Executive disposition

| Boundary | Independent R7 result | Disposition |
|---|---|---|
| R6-B06 stale frozen-vote digest | Shared freeze/unblind validation rejects stale verdict, reviewer, label, roster, order, field-roster, schema, seal, packet, permutation, and digest mutations. CLI also fails closed and emits no adjudication. | **CLOSED** |
| Keyless replacement of the complete vote object | A structurally valid replacement plus a newly computed unkeyed digest accepts. R7 explicitly does not claim reviewer authentication; B1 requires externally governed reviewers, keys, and signatures. | **B1 INELIGIBLE / DISCLOSED LIMIT** |
| Pashov v3 retained-byte and authority binding | Exact CRLF bytes replayed. Re-signed projection forgery, fully rederived source relabel, and validation without both external authorities rejected. | **PASS** |
| GT blindness, namespace and authority split, lifecycle/lineage, phase maps, privacy, resume, budget, launcher denial, Windows/cross-OS, packaging | Frozen contracts and tests passed within the declared local structural scope. B1 launcher effectiveness remains external and unclaimed. | **PASS / B1 UNOBSERVABLE** |
| Full-duration export mutation exclusion | A report mutation synchronized immediately after `inventory_run_sources()` completed was excluded from the captured generation, but export still sealed, promoted, and independently verified while claiming stable input. | **BLOCK - R7-B07** |

The decisive result is **BLOCK**. R7 must not be accepted, merged, used for
cutover, or treated as completion evidence until R7-B07 is repaired and a new
freeze is independently reviewed.

## 3. R7-B07 - late source mutation can produce an accepted stale seal

### 3.1 Governing requirement

The blueprint is explicit:

- export snapshots all inputs at start;
- after harvesting into fresh staging, it re-hashes **every input before
  seal**;
- any mutation yields `MUTATED_DURING_EXPORT` and no accepted seal; and
- S-13 requires report/scratchpad mutation during export to produce no seal
  and a mutation receipt.

These are the requirements at blueprint lines 815-823 and the S-13 row at
line 1180.

### 3.2 Root cause

`scripts/runbundle_sources.py:590-627` enumerates once and performs two
immediate physical reads. It correctly rejects differences between those two
reads and returns immutable bytes with `stable=True`.

`scripts/runbundle_export.py:1038-1059` then:

1. calls `inventory_run_sources()`;
2. builds a harvest draft from the returned bytes;
3. materializes all local documents;
4. stages, indexes, seals, verifies, and promotes the bundle.

There is no final live source-roster enumeration or live input rehash after
line 1043 and before the accepted seal. The internal double-read protects a
short capture window; it does not implement the required full export-duration
mutation exclusion. Reusing only the original roster also cannot detect a new
scratchpad file added after the first enumeration.

### 3.3 Deterministic synchronized counterexample

This was a temporary-directory-only mutation. The hook is placed at the first
instruction after inventory returns: `build_harvest_draft()`. The hook:

- confirms that the returned inventory contains the original report bytes and
  claims `stable=True`;
- rewrites the live `AUDIT_REPORT.md`;
- then invokes the unmodified harvest builder.

Exact command:

```powershell
$env:PYTHONDONTWRITEBYTECODE='1'
$env:PYTHONPATH='<LOCAL_USER_ROOT>\plamen-codex-implementation\scripts'
@'
import hashlib,json,tempfile
from pathlib import Path
from unittest.mock import patch
import runbundle_contracts as C
import runbundle_export as E
import test_runbundle_real_harvest_export as T
import test_runbundle_v2_contracts as V2
original_builder=E.H.build_harvest_draft
with tempfile.TemporaryDirectory(prefix="r7-export-toctou-") as td:
    root=Path(td)
    scratch,report=T._write_fixture_run(root)
    original=report.read_bytes()
    changed=b"# Audit report\n\nMUTATED AFTER THE EXPORT SNAPSHOT.\n"
    lock=V2._public_lock()
    baseline=V2._manifest(lock)
    schedule={
        "schema_version":E.PUBLIC_SCHEDULE_ROW_SCHEMA,
        "trust_profile":"USER_RUN",
        "run_id":baseline["run_id"],
        "experiment_id":baseline["experiment_id"],
        "cell_id":baseline["cell_id"],
        "repetition_index":baseline["repetition_index"],
        "seed":baseline["seed"],
        "audit_system":"PLAMEN",
        "adapter":baseline["adapter"],
        "experiment_plan_sha256":baseline["experiment_plan_sha256"],
        "campaign_schedule_sha256":baseline["campaign_schedule_sha256"],
        "model_backend":baseline["model_backend"],
        "tool_policy":baseline["tool_policy"],
        "budget":baseline["budget"],
        "resume":baseline["resume"],
        "public_launch_receipt":None,
        "pipeline_kind":"SC",
    }
    lockp=root/"public-lock.json"
    schedp=root/"schedule.json"
    lockp.write_bytes(C.canonical_document_bytes(lock))
    schedp.write_bytes(C.canonical_document_bytes(schedule))
    captured={}
    def mutate_after_inventory(*args,**kwargs):
        inventory=kwargs["inventory"]
        row=next(
            x for x in inventory.artifacts
            if x.relative_source_path=="AUDIT_REPORT.md"
        )
        captured["raw"]=row.raw
        captured["stable"]=inventory.stable
        report.write_bytes(changed)
        return original_builder(*args,**kwargs)
    out=root/"bundle"
    with patch.object(
        E.H,"build_harvest_draft",side_effect=mutate_after_inventory
    ):
        receipt=E.export_from_run(
            project_root=root,
            scratchpad=scratch,
            report=report,
            public_case_lock=lockp,
            schedule_row=schedp,
            out=out,
        )
    verified=C.verify_runbundle_v2(out,lockp.read_bytes())
    print(json.dumps({
        "captured_is_original":captured["raw"]==original,
        "captured_report_sha256":hashlib.sha256(captured["raw"]).hexdigest(),
        "export_succeeded":out.is_dir(),
        "harvest_claimed_stable":captured["stable"],
        "live_is_changed":report.read_bytes()==changed,
        "live_report_sha256":hashlib.sha256(report.read_bytes()).hexdigest(),
        "original_report_sha256":hashlib.sha256(original).hexdigest(),
        "post_snapshot_report_sha256":hashlib.sha256(changed).hexdigest(),
        "seal_sha256":receipt.bundle_seal_sha256,
        "verified":(
            verified.bundle_seal_sha256==receipt.bundle_seal_sha256
        ),
    },sort_keys=True,separators=(",",":")))
'@ | python -B -
```

Exact result:

```json
{"captured_is_original":true,"captured_report_sha256":"d2e15f49224e5b50389a49836d0da57aa7ca4bf78f9f782848d9a6fad2b48ccd","export_succeeded":true,"harvest_claimed_stable":true,"live_is_changed":true,"live_report_sha256":"6df60535d15fca18d38795d8ef9820dfa87d0a11c0e86e7d1b07aed829097eef","original_report_sha256":"d2e15f49224e5b50389a49836d0da57aa7ca4bf78f9f782848d9a6fad2b48ccd","post_snapshot_report_sha256":"6df60535d15fca18d38795d8ef9820dfa87d0a11c0e86e7d1b07aed829097eef","seal_sha256":"0e3fbf552d2f4aba8f815451cc773eddc2d77ab64a8841ef464af7a9f455ef62","verified":true}
```

This is not a scheduler-probability argument. The synchronization proves an
accepted execution in which the source mutates during export after the
exporter's last live read. It directly contradicts the normative requirement.

### 3.4 Required repair and closure fixtures

The repair must introduce a late pre-seal source authority, not merely a third
read adjacent to the existing two:

1. Freeze the initial exact source roster and per-path physical identity,
   state, length, and raw digest.
2. Immediately before an accepted seal, re-enumerate the exact live
   scratchpad/report roster and re-open/re-read every input using the hardened
   physical path and regular-file rules.
3. Compare roster and physical state as well as bytes. Detect add, remove,
   rename, case collision, symlink/reparse/junction, hardlink, ADS, sparse
   transition, and file-identity substitution.
4. On any difference, emit the typed `MUTATED_DURING_EXPORT` outcome, make the
   staging generation unaccepted, create no accepted seal, and preserve any
   previous sealed generation.
5. Ensure recovery cannot promote a generation whose late source authority is
   absent or mismatched.

Required deterministic fault points:

- mutation after the first capture;
- mutation after the current second capture;
- add/remove/rename during harvest;
- mutation during document materialization;
- mutation after index and immediately before seal;
- relevant Windows ADS/reparse/hardlink identity substitutions at the late
  check; and
- interrupted recovery with both matching and drifted late source authority.

The exact counterexample above must change from accepted-and-verified to
`MUTATED_DURING_EXPORT`, with no accepted output directory or seal.

## 4. R7 frozen-vote repair

R6-B06 is closed for stale-content integrity.

The R7 delta is narrow: only evaluator `README.md`,
`src/plamen_eval/blinding.py`,
`tests/test_real_v2_blinding_comparison.py`,
`tests/test_real_v2_cli.py`, and the freeze documentation/tooling changed.
There was no production runtime/test, schema, public API, or phase protocol
change.

`_validated_frozen_review_votes()` now enforces:

- exact six-field frozen object roster;
- exact three-field vote-row roster;
- schema and `sealed: true`;
- lowercase 64-hex digest;
- digest recomputation over every field except `votes_sha256`;
- exact packet and permutation binding;
- exact label coverage and uniqueness; and
- canonical packet-label order.

Freeze and unblind share this validator, and unblind consumes only its
validated rows.

A deterministic two-candidate independent matrix produced:

- **18/18 stale mutations rejected**: verdict, reviewer, label, omission,
  duplication, row extra, top-level extra, row reorder, schema, seal, packet
  digest, permutation digest, uppercase/short/non-string digest, non-list
  votes, empty reviewer, and boolean reviewer;
- **13/13 recomputed but structurally invalid variants rejected**;
- **5/5 invalid freeze-side inputs rejected**; and
- valid API and CLI baselines accepted, while the exact stale
  verdict-plus-reviewer CLI mutation returned rc 2 and created no output.

The baseline frozen vote digest was
`04d928f5e51a7eff1e7de80220e560ab29ed4eea5a4a3a2fadf7731191d9719c`.

A fully replaced but valid vote row with a newly computed unkeyed digest
`e3c4df0c915a1a8df5ea01aca2dbe3d6b495067125515b9cee609449d671ce8b`
accepted. This demonstrates exactly what R7 does and does not prove:
self-consistency and freeze consumption are enforced, but reviewer identity
and intent are not authenticated by the unkeyed digest.

That residual is not silently accepted as B1 evidence. The blueprint requires
independent reviewers and publication signature completeness, while the R7
claim scope explicitly excludes the external B1 authorities, reviewers, and
keys. Consequently:

- local B0 vote-object consistency: **PASS**;
- authenticated reviewer seal: **not implemented by this digest**; and
- B1 publication eligibility without external signed authority: **DENIED**.

## 5. Other adversarial boundaries

| Boundary | Result | Notes |
|---|---|---|
| GT blindness | **PASS** | Private/GT keys, schema identities, path forms, nested values, environment variables, private lock mixing, and score/outcome fields fail closed. Export remains a recorder, not a grader. |
| Candidate/root namespace separation | **PASS** | Opaque candidate IDs are not treated as GT issue/root IDs; only private adjudication can create the mapping. |
| Public/private authority split | **PASS locally** | The public lock is the runner authority; private lock and reviewer/signature authorities remain evaluator/external. No local artifact is B1 proof. |
| Lifecycle and lineage | **PASS** | Explicit occurrences, dispositions, evidence quality, committed phase ordering, absence-to-`UNOBSERVABLE`, and report projection bindings validate fail closed. |
| Replay and phase map | **PASS** | Exact SC and L1 maps are immutable and evaluator pinned. Protocol hashes replay as SC `28779f0e8bfb0358f0b496661b61918f7b837530c05ff1295f63e83d5d5ac9ae` and L1 `1eb129d128fc47427b1de2d0502aa82f3162546246f57d6d738090d441c526a6`. |
| Secure launcher denial | **PASS locally / B1 UNOBSERVABLE** | The local exporter produces `USER_RUN`/B0 evidence and cannot self-promote the same payload to B1. The secure launcher and its effectiveness evidence remain external. |
| Pashov exact adapter | **PASS** | Exact original bytes, path roster, external public-lock bytes, adapter pin, deterministic six-projection replay, and external capture roster are jointly required. Verification status is not invented. |
| Private identity/display safety | **PASS** | The full evaluator suite covers normalized/fragmented tokens, all nine bidi controls, RLO visual reversal, token-roster pruning, context omission/reorder/replacement, and valid-MAC reauthorization attempts. |
| Paths, links, ADS, and physical reads | **PASS inside each read; BLOCK across export duration** | Symlink, reparse/junction, hardlink, ADS, sparse/file-identity, casefold, traversal, and restored-metadata attacks are covered. R7-B07 is the missing late whole-export check. |
| Resume and recovery | **PASS except inherited R7-B07 requirement** | Journal topology, explicit output capability, object drift, exact lock input, and interrupted staging checks pass. Recovery must also bind the new late source authority. |
| Equal budget and schedule parity | **PASS** | Typed measurement receipts, summary binding, resume lineage, backend/seed/factorial matrix, and parity group constraints fail closed. |
| Packaging and cross-OS | **PASS** | Exact packaging denominator, cross-OS gate, deterministic wheel, isolated offline install, and native Windows physical tests passed. |
| Comparative claims | **PASS** | This review makes none. R7 is not comparison, score, recall, precision, audit-quality, or B1 effectiveness evidence. |

Independent Pashov probe result:

```json
{"baseline":"PASS","exact_retained_sha256":"bc2082f278720bde5ebe0250002347a902d27e734a9c4c539c16891ef0420a0b","missing_external_authority":"ContractError","recomputed_projection_forgery":"ContractError","recomputed_source_relabel":"ContractError","trusted_roster":"98e8e7c8731550b6e9fe2bb84101112b7974fc922b887cdcc5ea7914aba67f2f"}
```

## 6. Exact validation denominators

All pytest commands used `PYTHONDONTWRITEBYTECODE=1`,
`PYTEST_DISABLE_PLUGIN_AUTOLOAD=1`, `python -B`, and
`-p no:cacheprovider`.

### 6.1 Evaluator focused and full

```powershell
$env:PYTHONDONTWRITEBYTECODE='1'
$env:PYTEST_DISABLE_PLUGIN_AUTOLOAD='1'
$env:PYTHONPATH='<LOCAL_USER_ROOT>\<PRIVATE_EVALUATOR_REPO>\src'
python -B -m pytest -q -p no:cacheprovider `
  tests/test_pashov_v3_adapter.py `
  tests/test_real_v2_blinding_comparison.py `
  tests/test_real_v2_cli.py
```

Result: **79 passed in 2.32s**.

```powershell
python -B -m pytest -q -p no:cacheprovider tests
```

with the same environment and evaluator working directory.

Result: **229 passed, 6 subtests passed in 56.89s**.

### 6.2 Production exact RunBundle denominator

```powershell
python -B -m pytest -q -p no:cacheprovider `
  scripts/test_runbundle_export_ready_marker.py `
  scripts/test_runbundle_phase_map.py `
  scripts/test_runbundle_real_harvest_export.py `
  scripts/test_runbundle_v2_contracts.py `
  scripts/test_runbundle_v2_privacy.py `
  scripts/test_runbundle_v2_r5_regressions.py
```

Result: **509 passed in 126.19s**.

### 6.3 Packaging, cross-OS, and native Windows

```powershell
python -B -m pytest -q -p no:cacheprovider `
  scripts/test_python_packaging_contracts.py `
  scripts/test_public_packaging_freeze.py
```

Result: **9 passed in 90.11s**.

A wider non-denominator packaging run started while a shared owning lane was
introducing `scripts/program_facts_bake.py`. Its initial archive snapshot
correctly reported that the then-new helper was absent from the archive. The
owning lane's already-scoped visibility rule stabilized the shared tree; the
exact required 9-test denominator above then passed. This concurrent,
non-frozen observation is not used to weaken or strengthen the R7 verdict.

```powershell
python -B -m pytest -q -p no:cacheprovider `
  scripts/test_cross_os_toolchain_pre_handoff_gate.py
```

Result: **22 passed in 6.47s**.

```powershell
python -B -m pytest -q -p no:cacheprovider `
  scripts/test_runbundle_v2_privacy.py `
  -k "physical_ntfs or windows_stream or physical_windows_junction"
```

Result: **4 passed, 120 deselected in 0.86s**.

### 6.4 Compile and textual integrity

```powershell
python -B -m compileall -q src tests tools
```

Evaluator result: **PASS**.

The frozen production runtime and six test files were also compiled:
**PASS**.

```powershell
git diff --check
```

Result in both repositories: **exit 0; line-ending warnings only**.

## 7. Deterministic build, isolated install, and R7 replay

Two clean builds were made only to external temporary destinations:

```powershell
python -B tools/runbundle_v2_freeze.py build-wheel `
  --evaluator-root <LOCAL_USER_ROOT>\<PRIVATE_EVALUATOR_REPO> `
  --destination <LOCAL_USER_ROOT>\AppData\Local\Temp\20260729_r7_independent_a.whl

python -B tools/runbundle_v2_freeze.py build-wheel `
  --evaluator-root <LOCAL_USER_ROOT>\<PRIVATE_EVALUATOR_REPO> `
  --destination <LOCAL_USER_ROOT>\AppData\Local\Temp\20260729_r7_independent_b.whl
```

Both returned:

```json
{"status":"BUILT","wheel_sha256":"8ccc90f531f5ac788e23d78184be875ad1f0e5e936e41d00b767346b82bdf33f"}
```

Both were byte-identical to the preserved R7 wheel.

The exact preserved wheel installed into a new temporary venv using:

```powershell
python -B -m venv <LOCAL_USER_ROOT>\AppData\Local\Temp\plamen_eval_r7_isolated_review
<LOCAL_USER_ROOT>\AppData\Local\Temp\plamen_eval_r7_isolated_review\Scripts\python.exe `
  -I -m pip install --no-index --no-deps `
  <LOCAL_USER_ROOT>\<PRIVATE_EVALUATOR_REPO>\dist\frozen-v7\plamen_eval_control-0.2.0-py3-none-any.whl
```

With no `PYTHONPATH`, `PYTHONNOUSERSITE=1`, `python -I`, and temporary
`HOME`/`USERPROFILE`, it loaded version `0.2.0`, imported `plamen_eval` from
that venv's `site-packages`, found exactly 47 installed schemas, and the
isolated CLI returned version `0.2.0`.

The exact R7 replay command, run after the adversarial and validation work but
before the separate successor repair lane began, was:

```powershell
python -B tools/runbundle_v2_freeze.py replay `
  <LOCAL_USER_ROOT>\Downloads\Plamen_RunBundle_V2_Local_Freeze_R7_2026-07-29.json `
  --production-root <LOCAL_USER_ROOT>\plamen-codex-implementation `
  --evaluator-root <LOCAL_USER_ROOT>\<PRIVATE_EVALUATOR_REPO>
```

R7 snapshot result:

```json
{"freeze_manifest_sha256":"cd7be59ee425b22bc15b32ce72e3e63f6bd029c2295951ec2157eb2977e04a59","status":"REPLAYED"}
```

### 7.1 Post-receipt shared-tree drift

After the orchestrator accepted R7-B07 and started a separate R8 repair lane,
a final shared-worktree replay correctly stopped matching the historical R7
freeze. Independent byte comparison localized the successor drift to:

| R7 frozen path | R7 SHA-256 | Later shared-tree SHA-256 |
|---|---|---|
| `scripts/runbundle_privacy.py` | `a9355db3854d1ad33fb483beb4fe13c1a04df2184f11345793bb3c98884f25eb` | `8962f43fb361029be4cd7332cbcc37b302a766d43e82fd25bd603b5a91e9b2e2` |
| `scripts/runbundle_sources.py` | `d4c741de6a0975e4556dfc3e3073d3a9338e8b93fb68a2c5ab6ef9447b893cac` | `e0d8048a639b7f1ef66e59adbaa58ca1500b0411cf7344b04872dd131f25c697` |
| `scripts/test_runbundle_real_harvest_export.py` | `9b91bcadfbb7a06f9e43aa2dfba8fd8576541873cfd3f4f9a2093f613a13169e` | `6385d0d630f1ab1655636755e63c97fe7a4e957f718896345e85a12f7dbb08d0` |

The post-receipt tool result was therefore the expected fail-closed error:

```text
ERROR: freeze manifest differs from replayed source/API/wheel
```

This report remains bound to the exact R7 manifest and the successful R7
snapshot replays recorded above. The later shared tree is not R7, is not
reviewed here, and must receive a new handoff, freeze, and independent review.
No R7 source was edited by this reviewer.

## 8. Final decision

**R7 is BLOCKED.**

The vote repair is substantively correct for stale-content integrity, and the
exact R7 boundary was reproducible at its reviewed snapshot. Those facts do
not compensate for an
exporter that can accept and verify a seal after its live report or
scratchpad input has changed during the same export. The governing blueprint
makes that behavior an explicit failure.

A successor review must bind a new handoff and freeze, reproduce the exact
R7-B07 fixture as a fail-closed negative control, and independently test the
late roster/state/byte authority across seal and recovery. Until then, no
completion, cutover, comparative, audit-quality, or B1 claim is authorized.
