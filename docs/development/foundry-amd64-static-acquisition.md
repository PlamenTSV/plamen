# Foundry and amd64 compatibility static acquisition

Reviewed on 2026-09-14. These are setup-only inputs for the native
source-bootstrap coordinator. Audit execution is networkless and cannot use
`foundryup`, `apt`, or an ambient package manager. The checked-in JSON files
are frozen inputs, not Python-issued installation authority.

## Foundry v1.8.1, Linux arm64

The stable release observed during review was v1.8.1. Primary sources:

- GitHub release API: <https://api.github.com/repos/foundry-rs/foundry/releases/tags/v1.8.1>
- immutable release: <https://github.com/foundry-rs/foundry/releases/tag/v1.8.1>
- upstream verification contract: <https://github.com/foundry-rs/foundry/security>
- archive: <https://github.com/foundry-rs/foundry/releases/download/v1.8.1/foundry_v1.8.1_linux_arm64.tar.gz>
- checksum: <https://github.com/foundry-rs/foundry/releases/download/v1.8.1/foundry_v1.8.1_linux_arm64.sha256>
- Sigstore bundle: <https://github.com/foundry-rs/foundry/releases/download/v1.8.1/foundry_v1.8.1_linux_arm64.sigstore.json>

The archive is 114,076,891 bytes with SHA-256
`27a32bd282d73018ab4d043de15ab0320b561c71b4bf3a549b130a0806e79f5c`.
The Sigstore certificate binds workflow
`foundry-rs/foundry/.github/workflows/release.yml`, tag `v1.8.1`, commit
`982849d3140c01fd3b72905759581a132df7aa98`, and GitHub Actions issuer
`https://token.actions.githubusercontent.com`.

The native producer must authenticate the five exact root archive members,
then project them in byte-sorted name order to `bin/<name>` in USTAR format.
Every output header uses uid/gid/mtime 0, empty uname/gname, and mode 0555.
The resulting static payload is 269,271,040 bytes with SHA-256
`b19dfe910e75b23aabd21f58181f561bca73d51a24be39fa3b900ecd5f0d288b`.

## Debian amd64 direct compatibility closure

The closure uses the same exact Debian `bookworm-20260824-slim` multi-platform
index already selected by the arm64 runtime. Primary sources:

- registry index: <https://registry-1.docker.io/v2/library/debian/manifests/bookworm-20260824-slim>
- exact amd64 manifest: <https://registry-1.docker.io/v2/library/debian/manifests/sha256:5ae3c39ebd15e229dcedd5cee596b2497182493d41ff162e824ba13fc1b2b867>
- official Debian image page: <https://hub.docker.com/_/debian>
- frozen official-images declaration: <https://raw.githubusercontent.com/docker-library/official-images/b9c995a1c91bf8b195b035893ebdf8e877e7f7fa/library/debian>

The index SHA-256 is
`88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171`.
Its amd64 manifest binds layer SHA-256
`a8ac7f6c67abc236e4c745052c404112b8fab6fe8ac3a329d1ef3b867ad67c71`
and DiffID
`1d69a5fd31932841d7825ef4780c06f008eea65aaa9f3110fe09d5832ed5c7d8`.

The native producer selects only the exact loader, libc, libdl, libm,
libpthread, librt, and three required symlink rows recorded in the reviewed
receipt. It emits byte-sorted USTAR with normalized ownership/timestamps and
preserved in-root link semantics. The resulting payload is 3,112,960 bytes
with SHA-256
`4e9c886e6558a93cfbdab5cec905852209fc3c61a867c9672a0162522e36e490`.

## Native operation-4 handoff

`scripts/native_static_acquisition_policies.py` validates each policy,
semantic receipt prefix, and retained runtime source manifest. Its
`native_operation4_static_policy_input(role)` function returns the exact
compile-time row for roles `foundry` and `amd64_compat`, including enum
ordinals, validator IDs, all SHA-256/size bindings, semantic schema, and the
producer FD size. A real producer FD is:

`exact canonical semantic receipt bytes || 512-byte native producer footer`

Only the signed native coordinator may authenticate upstream descriptors,
perform the deterministic projection, and append that footer.
