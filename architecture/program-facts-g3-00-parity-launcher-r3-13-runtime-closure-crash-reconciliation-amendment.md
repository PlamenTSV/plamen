# Program Facts G3-00 parity launcher R3.13 runtime-closure and crash-reconciliation amendment

## Status and authority

This amendment defines the exact inactive R3.13 Windows-native audit-handoff
candidate. It repairs only the six blockers independently recorded against
R3.12. It does not install, register, select, admit, publish through a provider,
change a driver, modify an artifact ledger, activate a candidate, or perform a
cutover. `CANDIDATE_ACTIVE` and every global/provider/production authority bit
remain exact Boolean false.

The only executable native authority is the separately pinned 507-byte fixture
permit with SHA-256
`1cbec6e810df578b31325d2f115c9e0da5a4e0713c9e8b1a3a1bd746283346a0`.
It is restricted to an ordinary-user owned `r313-native-*` root below the
system temporary directory. It grants no production native execution,
admission, provider, global, cutover, power-loss, or directory-durability
authority.

## Frozen predecessor and required repair inputs

The R3.13 predecessor fixture is the exact 4,181-byte file with SHA-256
`20dcbb1ab58baa332377653da2f143593f44366b322f5ad498b0fc3baf20d46b`.
Before implementation it produced exactly `19 failed`. After the new R3.13
module exists, its current replay produces `18 failed, 1 passed`; the eighteen
failures continue to assert only the unchanged R3.12 subject, while the one
passing row observes that the separate R3.13 successor now exists.

The two mandatory R3.12 review inputs are exact:

- state/schema/operational REPAIR: 26,801 bytes, SHA-256
  `36303e8fe2a3fc8f6836a0cae1a1f9e1e90ad05e6ebe7c64002ed0a86808183e`;
- Windows-native contract REPAIR: 22,084 bytes, SHA-256
  `32e80e8c012821bd79d723bc5b471dae418ad6d435bc5a7cba29828152ec05dd`.

R3.12 is not edited. R3.13's governed dependency tuple preserves all fifteen
R3.12 dependencies and adds the exact R3.12 candidate, amendment, handoff,
both REPAIR reviews, R3.13 RED and permit, both shared regression sources, and
the R3.12 bounded-stage regression source. All are authenticated and retained
before any principal is parsed or any validator child is created.

## Loaded interpreter/runtime closure

The caller supplies a separately frozen runtime manifest and its SHA-256. The
R3.13 governed-host manifest is 42,269 bytes with SHA-256
`8ea9b901bf3c62e1a1e0392d64a807ddd48f4b2020dc2020aba7141c2593a6d8`.
It identifies:

- the absolute `python.exe` origin, exact size, and exact SHA-256;
- the exact `python312._pth` path and its governed `PRESENT` or `ABSENT` state;
- every loaded child `sys.modules` origin and existing bytecode-cache origin;
- every loaded process image returned by `EnumProcessModulesEx`, including
  `python312.dll`, `vcruntime140.dll`, Python extension modules, dependent
  runtime libraries, and Windows images; and
- the exact x64 pointer size and CPython version string.

The governed snapshot contains 104 module-origin rows and 32 loaded-image
rows. Every physical file is opened through an extended-length spelling,
made non-inheritable, retained without write/delete sharing, bound to the
expected named object, hashed through the retained handle, and replayed after
the child. Trusted Windows component hardlinks are permitted only after the
named and retained handles have equal volume/FileId identity; ordinary
single-link governed dependencies retain their stricter existing check.

The validator uses `subprocess.Popen`, retains the process-creation object,
bounds and drains stdout/stderr concurrently, and accepts a receipt only when
the child-reported PID equals `Popen.pid` and differs from the parent PID. The
child's complete module/image-origin lists must equal the frozen manifest.

The R3.12 same-byte executable attack was replayed. A copied exact
`python.exe` plus adjacent `python312._pth` and attacker-selected
`subprocess.py` is rejected as
`DEPENDENCY_CLOSURE/RUNTIME_EXECUTABLE_ORIGIN_MISMATCH` before a validator
child or attacker `Popen` executes.

## Total dependency and scalar outcomes

All dependency authentication occurs inside one guarded `for row in
REQUIRED_INPUTS` closure. Only after the loop completes does R3.13 derive the
three R3.11 principals from the already authenticated raw bytes. Missing or
tampered principal-bearing ordinals 11, 12, and 13 therefore return the same
sealed `DEPENDENCY_CLOSURE/DEPENDENCY_READ_FAILURE` result as every other
governed input; none can raise an unclassified `FileNotFoundError` or identity
exception.

The timeout domain excludes Boolean values, non-numeric values, NaN, infinity,
zero, negative values, and values above 300. Every invalid value returns a
sealed `CALLER_INPUT/TIMEOUT_INVALID` receipt before dependency retention or
process creation.

## One-shot subject/context/permit capability

`ValidatedCandidateCapability` has no caller constructor argument and direct
construction always raises `TypeError`. There is no module sentinel. An
internal locked registry records the exact capability object identity and a
weak reference, validated subject bytes and hash, canonical publication
context hash, exact permit hash, and validation receipt.

Publication has no payload argument. It atomically consumes the registry row
and can use only `validated_subject_bytes`. A second use or a copied/directly
created object is unknown. A context mismatch consumes and rejects the attempt.
The boundary is stated honestly: it is process-local state under a trusted
same-process caller assumption, not a Python-language unforgeability claim.

## Handle-security native transaction and reconciliation

Every directory and file DACL observation uses `GetSecurityInfo` on the exact
already retained handle. No stage or destination security decision reopens a
legacy path. Ancestors from the trust anchor through the protected root are
retained with no-follow and no delete sharing, joined to final path,
volume/FileId/attributes/reparse identity, and checked twice before mutation
and after the terminal state.

Normal publication creates a new no-follow/write-through source, writes only
the validated subject bytes, verifies bytes through the handle, flushes before
rename, executes class-22 `FileRenameInfoEx` with flags zero and the absolute
extended-length destination, flushes after rename, and verifies destination
FileId, volume, bytes, and DACL through retained handles.

`reconcile_windows_process_crash_publication_once` consumes a newly validated
capability for the same subject/context/permit and classifies the two names:

- exact `SOURCE_ONLY`: open and bind the stage, require exact subject bytes,
  governed volume, non-reparse identity, and private handle DACL, then flush,
  rename, post-flush, and reverify the terminal destination;
- exact `DESTINATION_ONLY`: open and bind the destination, require exact
  subject bytes, governed volume, non-reparse identity, and private handle
  DACL, then flush and accept the terminal destination;
- both present or neither present: reject `AMBIGUOUS` without mutation; and
- any foreign/mismatched single object: reject without deletion or overwrite.

Real `os._exit(97)` fixtures prove `AFTER_PRE_FLUSH -> SOURCE_ONLY` and
`AFTER_RENAME -> DESTINATION_ONLY`; each restart reaches exact terminal
destination bytes with the stage absent. A logical path longer than 260
characters completes end to end with handle security and extended-spelling
fixture observation/cleanup.

This is process-crash reconciliation only. It does not claim directory flush,
power-loss durability, reboot/controller behavior, ReFS/SMB parity, 32-bit
ABI support, or production authority.

## Exact implementation and regression sources

| Path | Bytes | SHA-256 |
|---|---:|---|
| `scripts/program_facts_windows_native_launcher_r3_13.py` | 86,265 | `68c56c036ceed57ea75b316ad379a538c8314299229a2d4140a472fd77dcfbd8` |
| `scripts/program_facts_r3_13_evidence_builder.py` | 1,993 | `07b45846a91042520a223e206ea9f2e1e4341d1927fcd3f485e1ef7e1c92d8dc` |
| `test_r3_13_predecessor_red.py` | 4,181 | `20dcbb1ab58baa332377653da2f143593f44366b322f5ad498b0fc3baf20d46b` |
| `test_r3_13_launcher_green.py` | 9,427 | `33cc983ffc2887243d65fa6c47861660d8953555f8cfbefebbc1d3eef7e0b00f` |
| `test_r3_13_windows_native_green.py` | 10,109 | `a74ea3ef3155d274f342faec2b8e0be7b32824e28eca8f247ebc2c2035425ac7` |
| `r3_13_fixture_native_execution_permit.v1.json` | 507 | `1cbec6e810df578b31325d2f115c9e0da5a4e0713c9e8b1a3a1bd746283346a0` |
| `r3_13_runtime_closure.v1.json` | 42,269 | `8ea9b901bf3c62e1a1e0392d64a807ddd48f4b2020dc2020aba7141c2593a6d8` |
| `scripts/test_isolated_execution_host.py` | 17,557 | `3db922c8cfbfcb7e08b16c1acd5e54caaab1d732174d51db795c01b009be1841` |
| `scripts/test_semantic_runtime_dependency_r6_author_adversarial.py` | 5,738 | `11218b4f560ff0ee27480c00ca58978625f64fe8680d7883a530227e43c19d22` |
| `test_r3_12_bounded_stage_red.py` | 2,655 | `da03435ef70b30be39f25dde8b1fa10d4b64f463ca36e7cd9065eda5f964437d` |

## Executed result ceiling

- Frozen pre-implementation RED: `19 failed`.
- Current predecessor replay: `18 failed, 1 passed`.
- R3.13 combined state/runtime/native/crash/long-path GREEN: `19 passed in
  112.53s`.
- Exact shared regression repeat 1: `37 passed in 7.42s`.
- Exact shared regression repeat 2: `37 passed in 10.61s`.
- Shared survivor-free repeat count: `2`.

R3.13 remains an inactive candidate requiring fresh independent state and
Windows-native reviews. These results cannot be consumed as provider,
admission, installation, global publication, ledger selection, or cutover
approval.
