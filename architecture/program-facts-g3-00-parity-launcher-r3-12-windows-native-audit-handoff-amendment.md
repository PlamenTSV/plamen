# Program-facts G3.00 parity launcher R3.12 Windows-native audit-handoff amendment

Date: 2026-08-09
Author principal: `Codex:/root/author_launcher_r3_12_windows_native_r1`
Status: `INACTIVE_PRODUCTION_CANDIDATE_AWAITING_INDEPENDENT_STATE_AND_NATIVE_REVIEW`
Profile: `WINDOWS_ORDINARY_USER_PROTECTED_ROOT_PROCESS_CRASH_R3_12`

## Decision

R3.12 is a Windows-native, fixture-backed successor to the R3.11 repair handoff. It implements the ordinary-user protected-root publication path and the fresh validation boundary needed to answer the R3.11 state and native `REPAIR` findings. It is not wired into `plamen_driver.py`, provider selection, program-facts admission, or the artifact-ledger selection state. Every global, native, provider, publication, installation, and cutover authority bit remains false.

The implemented claim is deliberately narrow:

> After an exact candidate passes a newly started `python -I -S` R3.11 validator process, an ordinary Windows process can create a new staged file below an owned protected root, flush the payload, rename it without replacement through `SetFileInformationByHandle(FileRenameInfoEx)`, flush the renamed file handle, and prove exact post-operation handle/name/bytes/DACL equality. The evidence supports process-crash recovery only. It does not support power-loss or directory-durability authority.

No Linux, WSL, macOS, provider, admission, install, or cutover behavior is added.

## Frozen predecessor and repair inputs

The launcher stages and verifies 15 exact raw-byte inputs. Each is bounded to at most `1,000,000` bytes and joined by path, exact size, and SHA-256. The first ten inputs are the R3.11 validator closure. The remaining five are the exact R3.11 amendment, state review, native review, author self-review, and protected-control-root recovery V4 inputs.

The predecessor principals are not aliases authored into R3.12. They are parsed from the pinned reviewed artifacts after those artifacts pass their size/hash checks:

- R3.11 state reviewer: `Codex:/root/review_cut4_recon_red_r1`;
- R3.11 native reviewer: `Codex:/root/crosscheck_claude_backlog_r2`; and
- R3.11 subject author: `Codex:/root/author_launcher_r3_11`.

The R3.12 author principal above is distinct from all three. No independence conclusion is granted by the launcher; independent R3.12 review remains outstanding.

## Fixture-first freeze

The two predecessor-facing fixture files were frozen before implementation:

- `test_r3_12_predecessor_red.py`: `5,665` bytes, SHA-256 `e3f25f6e8e7d6d3d4e301c41fd73a024847af52f7a794001197a174911f3f2ca`;
- `test_r3_12_bounded_stage_red.py`: `2,655` bytes, SHA-256 `da03435ef70b30be39f25dde8b1fa10d4b64f463ca36e7cd9065eda5f964437d`.

Their combined pre-implementation run was exactly `13 failed, 1 passed in 13.50s`. The failures covered property-exact lineage, artifact-derived principals, the `1,000,001`-byte no-terminal-LF case, missing dependencies after cache warm, fresh launcher existence, exact Windows source/destination identities and open policy, class-22 buffer shape, flush results, post-destination equality, and ancestor/DACL derivation.

That RED result is a historical freeze, not a current acceptance command. The GREEN acceptance matrix uses the repaired tests and the bounded-stage file separately.

## Shared bounded staging repair

One pre-announced shared edit was necessary in `scripts/isolated_execution_host.py`. `_WindowsImmutableDependencyStage.copy_verified` now accepts an optional `maximum_bytes` argument.

- Omitting it preserves the prior `Path.read_bytes()` behavior and call signature.
- A declared size over the bound is rejected before source materialization.
- A bounded call uses `bounded_artifact_io.read_bounded_regular_bytes`.
- Invalid Boolean/negative limits and observed over-limit/change conditions fail closed as `IsolatedExecutionProtocolError`.
- The launcher supplies `1,000,000` for its launcher, interpreter witness, validator, and every dependency.

The shared file changed from SHA-256 `c1bb9ace2a181777b14b7b558e552e2b15727c46ba3fab696d51241818968b00` to `7dce9db3f3651b99669c86673b89dc566e88756966f134435491b61db0b73f22`. The final shared regression matrix is `37 passed in 35.67s`, including the legacy caller and limit-minus-one, limit, and limit-plus-one cases.

No change was made to `artifact_ledger.py`, `rooted_path_io.py`, `owned_directory_guard.py`, `claude_stored_subscription_source.py`, `report_assembly_capture.py`, `bounded_artifact_io.py`, or protected-root V4.

## Fresh validation transaction

`validate_candidate_fresh` is the only way to obtain an in-process `ValidatedCandidateCapability`. The capability has an opaque process-local token and cannot be constructed with public arguments or serialized.

The transaction is:

1. bounded-read the subject, R3.12 launcher, and selected `python.exe`, requiring single-link regular files;
2. compare launcher and interpreter bytes to caller-supplied SHA-256 pins;
3. authenticate the 15-input predecessor closure and derive the three predecessor principals;
4. create a new immutable dependency stage below a caller-owned runtime root;
5. copy every input with the exact bounded staging primitive;
6. start the selected interpreter with `-I -S -B`, the staged launcher, and the staged R3.11 validator;
7. send the exact raw subject bytes through bounded standard input, with no appended LF;
8. require a zero exit, empty stderr, bounded canonical JSON stdout, a different positive child PID, isolated/no-site flags, exact subject hash, and exact validator hash; and
9. issue an opaque capability only for the exact R3.11 accepted pair.

There is no validation cache. Each call creates a new stage and process. A pinned predecessor removed after one accepted call is rejected on the next call as `DEPENDENCY_CLOSURE / DEPENDENCY_READ_FAILURE`, before child start and without a capability. `1,000,001` raw bytes are rejected before a validator child exists.

The receipt SHA is computed with `artifact_ledger._canonical_json_digest`, reusing the ledger's canonical receipt-preimage primitive. R3.12 never calls a ledger read/write, selection, commit, admission, or reconciliation function.

## Protected-root and ACL transaction

The publication entrypoint requires the opaque validation capability and uses existing rooted/native primitives. It accepts only canonical single path components for the stage and destination and rejects case-fold aliases.

For every directory from the explicit trust anchor through the protected root, inclusive, it:

- opens and retains a no-delete-share directory handle without following a reparse point;
- records volume serial, 128-bit file ID, attributes, and reparse tag;
- obtains the final handle path and compares it to the expected canonical component path;
- calls the existing ordered-ACE security reduction twice and requires equality;
- requires the owner to equal the current launcher token user;
- rejects unsupported ACE types and sensitive allow ACEs for any principal outside the current token user, local system, or built-in administrators;
- requires a sensitive allow ACE for the current token user; and
- records the ordered-ACE count/digest and exact trust-policy name without persisting raw SIDs.

All retained identities and DACL digests are rechecked before the rename and after post-destination observation. An untrusted `Everyone` sensitive-access fixture fails before the staged file is created.

## Exact source, rename, and destination frames

The staged source is opened by `CreateFileW` with:

- exact absolute protected-root path;
- `CREATE_NEW`;
- `GENERIC_READ | GENERIC_WRITE | DELETE | SYNCHRONIZE`;
- `FILE_SHARE_READ` only;
- `FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_WRITE_THROUGH`;
- null security attributes, followed by an explicit non-inheritable-handle check.

The receipt records the source path, handle value, file ID, volume serial, desired access, share mode, disposition, flags, DACL digest, and ACE-derived policy. Writes record requested/written byte counts, success, and `GetLastError` for every chunk. Source bytes are replayed from the retained handle before publication.

The selected rename request is:

- API: `SetFileInformationByHandle`;
- information class: `FileRenameInfoEx`, numeric class `22`;
- structure: repository-native `FILE_RENAME_INFO`;
- flags: `0`, so replacement is not enabled;
- `RootDirectory`: null;
- filename: exact absolute extended-length destination path encoded UTF-16LE without a NUL in `FileNameLength`;
- allocation: `sizeof(FILE_RENAME_INFO) + filename_bytes`;
- exact offsets for flags, reserved bytes, `RootDirectory`, `FileNameLength`, and `FileName`;
- exact full buffer bytes/hash; and
- explicit zero reserved bytes and zero tail bytes.

The retained protected-root directory handle is classified as `RETAINED_PRE_POST_VERIFICATION_ANCHOR_NOT_REQUEST_OPERAND`. This is the compensating absolute-path contract expressly permitted by the R3.11 native review: complete ancestor no-follow identities, exact path-to-handle comparison, and post-call identity comparison are mandatory.

On this governed Windows host, the attempted class-22 relative-name/retained-`RootDirectory` form returned `ERROR_INVALID_PARAMETER (87)` with both the `sizeof` and `FileName.offset` allocation variants. Class 3 behaved the same for the relative form. Class 22 and class 3 both succeeded with the documented absolute-name/null-root form. R3.12 therefore does not fabricate a relative request operand that the tested host rejected.

Two exact `FlushFileBuffers` results are required and recorded in order:

1. ordinal `0`, `PRE_RENAME_PAYLOAD`; and
2. ordinal `1`, `POST_RENAME_DESTINATION`.

Each must return success with the captured error branch equal to zero. A name-only barrier is insufficient.

After rename, the retained source handle identity must remain unchanged; the stage name must be absent; the destination name under the retained directory must exist with the same volume and 128-bit file ID. The destination is reopened no-follow with exact `GENERIC_READ | SYNCHRONIZE`, `FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE`, `OPEN_EXISTING`, and `FILE_FLAG_OPEN_REPARSE_POINT`. Its handle identity, bytes, and DACL must equal the staged source observations. The destination open frame is included in the receipt.

## Recovery ceiling and native evidence

The native tests use only owned temporary roots. The shell token was observed at medium integrity (`S-1-16-8192`), so the evidence does not rely on an elevated token.

Two subprocesses terminated by `os._exit(97)` after real native calls:

- after the pre-rename payload flush: source present, destination absent, source bytes exact; and
- after rename but before the post-rename flush: source absent, destination present, destination bytes exact.

The normal success path also proves both flush returns and all post-equality checks. These observations are process-crash fixtures. They are not reboot, power-cut, filesystem-controller, directory-flush, or power-loss evidence. `directory_flush_claimed=false` and `power_loss_authority=false` are mandatory receipt fields.

## Property-exact 67-row lineage

`scripts/program_facts_r3_12_lineage_builder.py` pins the exact R3.11 lineage recipe bytes (`40,388`, SHA-256 `29dc8afa8c6c5b7550527af2ef41b3fbecbf008126f8a463081a282aeb17d903`). It contains an explicit ordinal-indexed table of 67 distinct successor JSON pointers. There is no keyword router and no seven-diagnostic alias collapse.

For each predecessor property the frozen recipe records:

- its unique successor JSON pointer;
- the exact full-model SHA and exact property precondition;
- a type-aware replacement value;
- the SHA-256 of the complete resealed mutated successor model;
- the exact predecessor diagnostic pair; and
- a property-specific equivalence rationale.

The executable evaluator accepts only the one exact full-model mutation for the requested ordinal. Any second-property drift, wrong mutation, or invalid ordinal returns a lineage-harness rejection rather than falling back to a diagnostic family. All 67 exact mutations reproduce their predecessor diagnostic pairs in the GREEN fixture.

## Final evidence matrix

- R3.12 GREEN matrix: `18 passed in 70.77s`.
- Shared isolated-execution regression matrix: `37 passed in 35.67s`.
- Live normal native publication: class 22 success, two successful flush results, exact source/destination identity and bytes.
- Live crash matrix: `2 / 2` expected exit/poststate pairs.
- Lineage matrix: `67 / 67` exact mutation/diagnostic pairs plus cross-property rejection.
- No install, dependency audit, provider mutation, driver wiring, ledger state mutation, V4 change, commit, or push was performed.

The canonical test receipt is `Temp/program_facts_g3_launcher_r3_12_20260809/r3_12_test_receipt.v1.json`, `4,269` bytes, SHA-256 `b1596de88a67bb9a33673b4a98cdc532195cd98c43fd03a3a042688c32552f27`.

## Production-candidate artifact identities

| Artifact | Bytes | SHA-256 |
|---|---:|---|
| `scripts/program_facts_windows_native_launcher_r3_12.py` | 44,534 | `a1ebb40eea8dbab01375d32ed1cfc23fdd7907bdbd267d826dfb6eb1258299b1` |
| `scripts/program_facts_r3_12_lineage_builder.py` | 12,632 | `3f4ee6c185f1c3c457117d9b2af292b29550e401b35421cc034d22c52adc71bf` |
| `r3_12_lineage_model.v1.json` | 3,453 | `94ed03ec872bfec8feea444abf5b8302cbb81889c27464528848f00cebf35165` |
| `r3_12_lineage_recipes.v1.json` | 72,561 | `4bcec9458572d1f1c808879ab479fc5c2ddd8ab25a23a35db2467477ff844ccd` |
| `test_r3_12_launcher_green.py` | 14,867 | `09b09aa8eb6a8b4cc1bdf55233baaf499e4dccc598e73c46df507e8e3a1405bf` |
| `test_r3_12_lineage_green.py` | 3,784 | `4ae7c1c69a673406c49eec1f271385d9ddb196ce689645530cc7035ab42334f0` |

These hashes precede only this amendment and its handoff/identity wrappers; the production candidate and frozen fixture bytes are final for independent review.

## Independent review and activation boundary

R3.12 does not authorize itself. Before any consumer can treat it as native execution or publication authority, a fresh reviewer set must independently:

1. replay every pinned input and artifact identity;
2. review the fresh-child, no-cache, raw-byte, and opaque-capability boundary;
3. review source/destination access/share/identity joins and the complete class-22 buffer;
4. reproduce the medium-integrity owned-root normal and process-crash matrices;
5. verify the ordered-ACE policy and every-ancestor no-follow roster against the exact protected-root scope;
6. replay all 67 lineage mutations and cross-property rejections;
7. decide whether the absolute-name/null-root compensating contract is acceptable for the supported Windows host set;
8. separately design and review any artifact-ledger/provider admission bridge; and
9. keep power-loss, directory durability, install, and global cutover outside this artifact.

Until that review produces a distinct, pinned approval artifact and a separately reviewed activation bridge, the only correct authority result is `false`.
