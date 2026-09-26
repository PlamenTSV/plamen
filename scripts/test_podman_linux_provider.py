#!/usr/bin/env python3
"""Fake-only adversarial tests; this suite performs no native effects."""

from __future__ import annotations

import dataclasses
import json
import math
import platform
import stat
import time
import unittest
from pathlib import Path
from unittest import mock

try:
    from scripts import podman_linux_provider as p
except ImportError:  # direct execution from scripts/
    import podman_linux_provider as p


H, G, K = "1" * 64, "2" * 64, "3" * 64
IMAGE_ID, CONTAINER_ID = "4" * 64, "5" * 64
POLICY, SECCOMP = "6" * 64, "7" * 64
EMPTY = p._hash(b"")


class SimulatedProcessDeath(BaseException):
    """Fake-only abrupt death that bypasses normal in-process unwind."""


def stable_inode(purpose: str, source: Path) -> int:
    return 1000 + int(p._hash((purpose + str(source)).encode())[:8], 16)


def executable(name: str, index: int) -> p.ExecutableIdentity:
    return p.ExecutableIdentity(
        Path("/opt/plamen-bin") / name, 10, 100 + index, 1000, 0,
        stat.S_IFREG | 0o555, 1, H, G, EMPTY,
    )


def components() -> p.ComponentIdentities:
    identities = tuple(executable(name, index) for index, name in enumerate(
        ("podman", "conmon", "crun", "newuidmap", "newgidmap", "fuse-overlayfs"), 1))
    provenance = tuple(
        p.ReleaseProvenance(label, version, G, K, H, identity.sha256, True)
        for (label, version), identity in zip(p.ComponentIdentities.pins(), identities, strict=True)
    )
    return p.ComponentIdentities(*identities, provenance)


def host() -> p.HostFacts:
    return p.HostFacts(
        "Linux", "x86_64", 1000, 1000, 1000, True, "v2", True, True,
        ("cpu", "memory", "pids"), True, 65536, 65536, True, True, True,
        Path("/home/alice"),
        (Path("/home/alice/.ssh"), Path("/var/lib/plamen-credentials")),
    )


def roots() -> p.ProviderRoots:
    return p.ProviderRoots(
        Path("/private/plamen/storage"), Path("/private/plamen/runroot"),
        Path("/private/plamen/tmp"), Path("/private/plamen/home"),
        Path("/private/plamen/runtime"), Path("/private/plamen/overlay"),
    )


def spec() -> p.ContainerSpec:
    sources = {
        "project-lower": Path("/audit/project"),
        "project-upper": Path("/private/plamen/overlay/upper"),
        "project-work": Path("/private/plamen/overlay/work"),
        "project-merged": Path("/private/plamen/overlay/merged"),
        "runtime": Path("/audit/runtime"), "state": Path("/audit/state"),
        "scratch": Path("/audit/scratch"),
        "seccomp": Path("/audit/seccomp.json"),
    }
    image = p.ImageSpec("localhost/plamen/audit@sha256:" + H, H)
    mounts = tuple(p.MountRequest(purpose, sources[purpose])
                   for purpose in p._MOUNT_ROSTER)
    return p.ContainerSpec(
        "dodo-audit", 1, image, "/opt/plamen/driver", ("thorough",),
        ("PLAMEN_MODE=thorough",), mounts, POLICY, SECCOMP,
    )


class FakePaths:
    def __init__(self) -> None:
        self.counter = 1000
        self.drift_purpose: str | None = None
        self.unsafe: dict[str, dict[str, object]] = {}
        self.overlay_drift = False
        self.export_committed = False
        self.export_changes: dict[str, object] = {}
        self.export_commit: p.ArtifactCommit | None = None
        self.packaged_sources: tuple[str, ...] = ()
        self.ephemeral_root_tokens = False
        self.export_slot_drift = False
        self.export_preexisting = False
        self.export_race_preexisting = False
        self.validate_export_calls = 0
        self.validate_export_failure = False
        self.admission_cleanup_calls = 0

    def security_contract(self) -> p.PathAuthorityContract:
        return p.PathAuthorityContract(p.PROVIDER_SCHEMA, "paths", *([True] * 24))

    def admit(self, source: Path, *, purpose: str, target: str,
              readonly: bool, kind: str, byte_limit: int,
              mapped_uid: int, mapped_gid: int,
              reservation: p.AdmissionReservation | None = None
              ) -> p.PathBinding:
        self.counter += 1
        overlay = purpose in {"project-upper", "project-work", "project-merged"}
        filesystem = ("fuse-overlayfs" if purpose == "project-merged"
                      else ("ext4" if overlay else "xfs"))
        mode = ((stat.S_IFDIR | 0o700) if kind == "directory"
                else (stat.S_IFREG | 0o600))
        stable = stable_inode(purpose, source)
        token_seed = purpose + str(source)
        if self.ephemeral_root_tokens and purpose.startswith("provider-"):
            token_seed += ":" + str(self.counter)
        binding = p.PathBinding(
            p._hash(token_seed.encode()), purpose, source, target,
            readonly, kind, 20, stable, mode, 1000, 1000,
            2 if kind == "directory" else 1, byte_limit, H,
            p._hash(str(source).encode()),
            SECCOMP if purpose == "seccomp" else H, EMPTY,
            stable + 100, 90, filesystem, G, mapped_uid, mapped_gid,
            not readonly, False, False, False, False, False,
        )
        if purpose in self.unsafe:
            binding = dataclasses.replace(binding, **self.unsafe[purpose])
        return binding

    def revalidate(self, binding: p.PathBinding) -> p.PathBinding:
        if self.drift_purpose == binding.purpose:
            return dataclasses.replace(binding, inode=binding.inode + 1)
        return binding

    def admit_overlay(self, bindings: tuple[p.PathBinding, ...], *,
                      uid: int, gid: int,
                      reservation: p.AdmissionReservation
                      ) -> p.OverlayTopology:
        by = {item.purpose: item for item in bindings}
        return p.OverlayTopology(
            p.PROVIDER_SCHEMA, "paths", by["project-lower"].token,
            by["project-upper"].token, by["project-work"].token,
            by["project-merged"].token, G, K,
            by["project-merged"].mount_id, by["project-lower"].mount_id,
            "fuse-overlayfs", True, True, True, True, True, uid, gid,
        )

    def revalidate_overlay(self, topology: p.OverlayTopology,
                           bindings: tuple[p.PathBinding, ...]) -> p.OverlayTopology:
        return (dataclasses.replace(topology, keeper_token=H)
                if self.overlay_drift else topology)

    def admit_export(self, destination: Path, *, byte_limit: int,
                     mapped_uid: int,
                     mapped_gid: int) -> p.ArtifactDestination:
        parent = self.admit(
            destination.parent, purpose="export-parent", target="",
            readonly=False, kind="directory", byte_limit=byte_limit,
            mapped_uid=mapped_uid, mapped_gid=mapped_gid)
        return p.ArtifactDestination(
            p.PROVIDER_SCHEMA, "paths",
            p._hash(("slot:" + str(destination)).encode()), destination,
            parent, destination.name, byte_limit, mapped_uid, mapped_gid,
            not self.export_preexisting, True, True, True)

    def revalidate_export(self, destination: p.ArtifactDestination
                          ) -> p.ArtifactDestination:
        return (dataclasses.replace(destination, token=H)
                if self.export_slot_drift else destination)

    def package_artifacts(self, sources: tuple[p.PathBinding, ...],
                          destination: p.ArtifactDestination, *, attempt_id: str,
                          manifest_sha256: str,
                          timeout: float) -> p.ArtifactCommit:
        p._timeout(timeout)
        if self.export_race_preexisting:
            raise RuntimeError("destination appeared")
        self.export_committed = True
        self.packaged_sources = tuple(item.purpose for item in sources)
        source_set = p._hash(p._canonical_json(
            [item.document for item in sources]))
        committed = self.admit(
            destination.path, purpose="export", target="", readonly=False,
            kind="regular", byte_limit=destination.byte_limit,
            mapped_uid=destination.mapped_uid,
            mapped_gid=destination.mapped_gid)
        committed = dataclasses.replace(committed, snapshot_sha256=G,
                                        device=destination.parent.device)
        result = p.ArtifactCommit(
            schema=p.PROVIDER_SCHEMA, authority_id="paths",
            destination_token=destination.token, binding=committed,
            commit_token=K, attempt_id=attempt_id,
            manifest_sha256=manifest_sha256,
            source_set_sha256=source_set, archive_sha256=G,
            census_sha256=H, entry_count=3, byte_count=1024,
            committed_monotonic_ns=time.monotonic_ns(),
            atomic_no_replace=True, destination_was_absent=True,
            temporary_file_fsync=True, file_fsync=True, parent_fsync=True,
            reopened_after_publish=True, descriptor_relative_readback=True,
            complete_census=True, regular_files_only=True,
            links_rejected=True, authenticated=True,
            archive_format="pax-tar-v1", manifest_embedded=True,
            census_matches_archive=True, deterministic_metadata=True,
        )
        if self.export_changes:
            binding_changes = self.export_changes.pop("binding", None)
            if isinstance(binding_changes, dict):
                result = dataclasses.replace(
                    result,
                    binding=dataclasses.replace(result.binding,
                                                **binding_changes))
            result = dataclasses.replace(result, **self.export_changes)
        self.export_commit = result
        return result

    def validate_export(self, destination: p.ArtifactDestination, *,
                        expected_commit: p.ArtifactCommit | None,
                        attempt_id: str,
                        manifest_sha256: str,
                        source_set_sha256: str,
                        timeout: float) -> p.ArtifactCommit:
        p._timeout(timeout)
        self.validate_export_calls += 1
        if self.validate_export_failure:
            raise RuntimeError("archive missing or corrupt")
        if self.export_commit is not None:
            return self.export_commit
        unchanged = self.admit(
            destination.path, purpose="export", target="", readonly=False,
            kind="regular", byte_limit=destination.byte_limit,
            mapped_uid=destination.mapped_uid,
            mapped_gid=destination.mapped_gid)
        unchanged = dataclasses.replace(
            unchanged, snapshot_sha256=G,
            device=destination.parent.device)
        return p.ArtifactCommit(
            schema=p.PROVIDER_SCHEMA, authority_id="paths",
            destination_token=destination.token, binding=unchanged,
            commit_token=K, attempt_id=attempt_id,
            manifest_sha256=manifest_sha256,
            source_set_sha256=source_set_sha256, archive_sha256=G,
            census_sha256=H, entry_count=3, byte_count=1024,
            committed_monotonic_ns=time.monotonic_ns(),
            atomic_no_replace=True, destination_was_absent=True,
            temporary_file_fsync=True, file_fsync=True, parent_fsync=True,
            reopened_after_publish=True, descriptor_relative_readback=True,
            complete_census=True, regular_files_only=True,
            links_rejected=True, authenticated=True,
            archive_format="pax-tar-v1", manifest_embedded=True,
            census_matches_archive=True, deterministic_metadata=True,
        )

    def verify_artifact(self, commit: p.ArtifactCommit) -> bool:
        return commit.authority_id == "paths" and commit.authenticated

    @staticmethod
    def _release(kind: str, token: str, context_sha256: str,
                 release_nonce: str) -> p.ResourceReleaseReceipt:
        return p.ResourceReleaseReceipt(
            p.PROVIDER_SCHEMA, "paths", kind, token, context_sha256,
            release_nonce, time.monotonic_ns(), True, True, True, H)

    def release_overlay(self, topology: p.OverlayTopology, *,
                        context_sha256: str,
                        release_nonce: str) -> p.ResourceReleaseReceipt:
        return self._release("overlay-keeper", topology.keeper_token,
                             context_sha256, release_nonce)

    def verify_release(self, receipt: p.ResourceReleaseReceipt) -> bool:
        return receipt.authority_id == "paths" and receipt.authenticated

    def cleanup_admission(self, reservation: p.AdmissionReservation, *,
                          cleanup_nonce: str
                          ) -> p.AdmissionCleanupReceipt:
        self.admission_cleanup_calls += 1
        return p.AdmissionCleanupReceipt(
            p.JOURNAL_SCHEMA, "paths", "paths", reservation.digest,
            reservation.attempt_id, cleanup_nonce, time.monotonic_ns(),
            True, True, True, H)

    def verify_admission_cleanup(
            self, receipt: p.AdmissionCleanupReceipt) -> bool:
        return receipt.authority_id == "paths" and receipt.authenticated


class FakeNetwork:
    def __init__(self, kind: p.NetworkKind = p.NetworkKind.VERIFIED_NARROW_PROXY) -> None:
        self.kind, self.changed, self.revoked = kind, False, False
        self.admit_calls = 0
        self.release_tamper = False
        self.admission_cleanup_calls = 0

    def security_contract(self) -> p.NetworkAuthorityContract:
        return p.NetworkAuthorityContract(p.PROVIDER_SCHEMA, "network", *([True] * 10))

    def admit(self, policy_sha256: str,
              reservation: p.AdmissionReservation | None = None
              ) -> p.NetworkProof:
        self.admit_calls += 1
        network = "none" if self.kind is p.NetworkKind.PRIVATE_SHIM else "ns:/proc/self/fd/9"
        endpoint = ("connected-seqpacket-fd" if self.kind is p.NetworkKind.PRIVATE_SHIM
                    else "network-namespace-fd")
        return p.NetworkProof(
            p.PROVIDER_SCHEMA, "network", self.kind, policy_sha256, H, G,
            endpoint, 1, time.monotonic_ns() + 10**12, network, 9,
            True, True, True, False,
        )

    def revalidate(self, proof: p.NetworkProof) -> p.NetworkProof:
        if self.revoked:
            return dataclasses.replace(proof, revoked=True)
        if self.changed:
            return dataclasses.replace(proof, generation=2)
        return proof

    def release(self, proof: p.NetworkProof, *, context_sha256: str,
                release_nonce: str) -> p.ResourceReleaseReceipt:
        receipt = p.ResourceReleaseReceipt(
            p.PROVIDER_SCHEMA, "network", "namespace-endpoint",
            proof.endpoint_token, context_sha256, release_nonce,
            time.monotonic_ns(), True, True, True, H)
        return (dataclasses.replace(receipt, resource_token=K)
                if self.release_tamper else receipt)

    def verify_release(self, receipt: p.ResourceReleaseReceipt) -> bool:
        return receipt.authority_id == "network" and receipt.authenticated

    def cleanup_admission(self, reservation: p.AdmissionReservation, *,
                          cleanup_nonce: str
                          ) -> p.AdmissionCleanupReceipt:
        self.admission_cleanup_calls += 1
        return p.AdmissionCleanupReceipt(
            p.JOURNAL_SCHEMA, "network", "network", reservation.digest,
            reservation.attempt_id, cleanup_nonce, time.monotonic_ns(),
            True, True, True, H)

    def verify_admission_cleanup(
            self, receipt: p.AdmissionCleanupReceipt) -> bool:
        return receipt.authority_id == "network" and receipt.authenticated


class FakeJournal:
    def __init__(self) -> None:
        self.records: dict[str, p.MutationRecord] = {}
        self.history: dict[str, list[p.MutationRecord]] = {}
        self.anchors: dict[str, p.JournalAnchor] = {}
        self.anchor_history: dict[str, list[p.JournalAnchor]] = {}
        self.observation_generations: dict[str, int] = {}
        self.observation_challenges: dict[str, p.ObservationChallenge] = {}
        self.observation_anchors: dict[str, p.ObservationAnchor] = {}
        self.admissions: dict[str, p.AdmissionReservation] = {}
        self.admission_stages: dict[str, list[p.AdmissionStageReceipt]] = {}
        self.admission_stage_history: list[p.AdmissionStageReceipt] = []
        self.cleaned_admission_stages: dict[
            str, tuple[p.AdmissionStageReceipt, ...]] = {}
        self.admission_cleanup_claims: dict[str, str] = {}
        self.attempt_recovery_history: list[p.AttemptRecoverySnapshot] = []
        self.admission_retirement_history: list[p.AdmissionRetirement] = []
        self.monotonic_counter = 0
        self.fail_write = False
        self.fail_message = "secret /home/alice/.ssh/id_ed25519"

    def security_contract(self) -> p.JournalContract:
        return p.JournalContract(p.PROVIDER_SCHEMA, "journal", *([True] * 22))

    def load(self, attempt_id: str) -> p.MutationRecord | None:
        return self.records.get(attempt_id)

    def load_anchor(self, attempt_id: str) -> p.JournalAnchor | None:
        return self.anchors.get(attempt_id)

    def load_current(self, attempt_id: str) -> p.JournalSnapshot | None:
        record, anchor = (self.records.get(attempt_id),
                          self.anchors.get(attempt_id))
        if record is None and anchor is None:
            return None
        if record is None or anchor is None:
            raise RuntimeError("record/anchor mismatch")
        return p.JournalSnapshot(
            p.JOURNAL_SCHEMA, "journal", record, anchor,
            p._hash((attempt_id + ":read:" +
                     str(self.monotonic_counter)).encode()),
            H, True, True, True)

    def verify_snapshot(self, snapshot: p.JournalSnapshot) -> bool:
        return (snapshot.anchor in self.anchor_history.get(
                    snapshot.record.attempt_id, [])
                and snapshot.authenticated)

    def load_cleanup_record(self, attempt_id: str) -> p.MutationRecord | None:
        history = self.history.get(attempt_id, [])
        return history[-1] if history else None

    def verify_cleanup_record(self, record: p.MutationRecord) -> bool:
        return record in self.history.get(record.attempt_id, [])

    def write(self, record: p.MutationRecord) -> p.JournalAnchor:
        if self.fail_write:
            raise RuntimeError(self.fail_message)
        prior = self.anchors.get(record.attempt_id)
        expected = ((1, "0" * 64) if prior is None else
                    (prior.generation + 1, prior.record_sha256))
        if (record.generation, record.previous_record_sha256) != expected:
            raise RuntimeError("journal fork")
        if prior is None:
            reservation = self.admissions.get(record.attempt_id)
            stages = self.admission_stages.get(record.attempt_id, [])
            if (reservation is None or reservation.token !=
                    record.admission.token or len(stages) != 5
                    or tuple(stages) != record.admission_stages
                    or record.attempt_id in self.admission_cleanup_claims):
                raise RuntimeError("admission not durably complete")
        self.monotonic_counter += 1
        anchor = p.JournalAnchor(
            p.JOURNAL_SCHEMA, "journal", record.attempt_id,
            record.generation, record.digest, record.previous_record_sha256,
            self.monotonic_counter, H, True, True, True)
        self.records[record.attempt_id] = record
        self.anchors[record.attempt_id] = anchor
        self.anchor_history.setdefault(record.attempt_id, []).append(anchor)
        self.history.setdefault(record.attempt_id, []).append(record)
        if prior is None:
            self.admissions.pop(record.attempt_id, None)
            self.admission_stages.pop(record.attempt_id, None)
            self.admission_cleanup_claims.pop(record.attempt_id, None)
        return anchor

    def verify_anchor(self, anchor: p.JournalAnchor) -> bool:
        return anchor in self.anchor_history.get(anchor.attempt_id, [])

    def issue_observation_challenge(self, scope: str
                                    ) -> p.ObservationChallenge:
        generation = self.observation_generations.get(scope, 0) + 1
        self.observation_generations[scope] = generation
        challenge = p.ObservationChallenge(
            p.JOURNAL_SCHEMA, "journal", scope,
            p._hash(f"{scope}:{generation}".encode()), generation,
            time.monotonic_ns(), True)
        self.observation_challenges[scope] = challenge
        return challenge

    def commit_observation(self, challenge: p.ObservationChallenge, *,
                           observation_sha256: str, sequence: int,
                           observed_monotonic_ns: int
                           ) -> p.ObservationAnchor:
        if self.observation_challenges.get(challenge.scope) != challenge:
            raise RuntimeError("challenge replay")
        self.observation_challenges.pop(challenge.scope)
        anchor = p.ObservationAnchor(
            p.JOURNAL_SCHEMA, "journal", challenge.scope,
            challenge.digest, observation_sha256, sequence,
            challenge.generation, observed_monotonic_ns,
            H, True, True, True)
        self.observation_anchors[challenge.scope] = anchor
        return anchor

    def verify_observation_anchor(self, anchor: p.ObservationAnchor) -> bool:
        return self.observation_anchors.get(anchor.scope) == anchor

    def load_admission(self, attempt_id: str
                       ) -> p.AdmissionReservation | None:
        return self.admissions.get(attempt_id)

    def reserve_admission(self, attempt_id: str, *,
                          base_spec_sha256: str
                          ) -> p.AdmissionReservation:
        if (attempt_id in self.admissions or attempt_id in self.records
                or attempt_id in self.admission_cleanup_claims):
            raise RuntimeError("admission owner exists")
        self.monotonic_counter += 1
        reservation = p.AdmissionReservation(
            p.JOURNAL_SCHEMA, "journal", attempt_id, base_spec_sha256,
            p._hash((attempt_id + ":admission:" +
                     str(self.monotonic_counter)).encode()),
            self.monotonic_counter,
            p._hash(("cleanup:" + attempt_id).encode()),
            time.monotonic_ns(), True, True, True)
        self.admissions[attempt_id] = reservation
        self.admission_stages[attempt_id] = []
        return reservation

    def verify_admission(self, reservation: p.AdmissionReservation) -> bool:
        return self.admissions.get(reservation.attempt_id) == reservation

    def commit_admission_stage(
            self, reservation: p.AdmissionReservation, *, stage: str,
            ordinal: int, resource_sha256: str,
            previous_stage_sha256: str) -> p.AdmissionStageReceipt:
        if not self.verify_admission(reservation):
            raise RuntimeError("admission reservation changed")
        if reservation.attempt_id in self.admission_cleanup_claims:
            raise RuntimeError("admission cleanup already claimed")
        stages = self.admission_stages[reservation.attempt_id]
        prior = stages[-1].digest if stages else "0" * 64
        if ordinal != len(stages) + 1 or previous_stage_sha256 != prior:
            raise RuntimeError("admission stage fork")
        receipt = p.AdmissionStageReceipt(
            p.JOURNAL_SCHEMA, "journal", reservation.digest, stage,
            ordinal, resource_sha256, previous_stage_sha256,
            time.monotonic_ns(), True, True, H)
        stages.append(receipt)
        self.admission_stage_history.append(receipt)
        return receipt

    def load_admission_stages(
            self, reservation: p.AdmissionReservation
            ) -> tuple[p.AdmissionStageReceipt, ...]:
        return tuple(self.admission_stages.get(reservation.attempt_id, []))

    def verify_admission_stage(self,
                               receipt: p.AdmissionStageReceipt) -> bool:
        return receipt in self.admission_stage_history

    def claim_attempt_recovery(
            self, attempt_id: str, *, base_spec_sha256: str
            ) -> p.AttemptRecoverySnapshot:
        record_snapshot = self.load_current(attempt_id)
        reservation = self.admissions.get(attempt_id)
        if record_snapshot is not None and reservation is not None:
            raise RuntimeError("conflicting attempt heads")
        stages: tuple[p.AdmissionStageReceipt, ...] = ()
        claim: str | None = None
        claimed = False
        if reservation is not None:
            if reservation.base_spec_sha256 != base_spec_sha256:
                raise RuntimeError("attempt specification changed")
            claim = self.admission_cleanup_claims.get(attempt_id)
            if claim is None:
                claim = p._hash((reservation.digest + ":cleanup-claim").encode())
                self.admission_cleanup_claims[attempt_id] = claim
            stages = tuple(self.admission_stages.get(attempt_id, []))
            claimed = True
        self.monotonic_counter += 1
        snapshot = p.AttemptRecoverySnapshot(
            p.JOURNAL_SCHEMA, "journal", attempt_id, base_spec_sha256,
            record_snapshot, reservation, stages, claim,
            self.monotonic_counter,
            p._hash((attempt_id + ":attempt-read:" +
                     str(self.monotonic_counter)).encode()),
            H, True, claimed, True, True)
        self.attempt_recovery_history.append(snapshot)
        return snapshot

    def verify_attempt_recovery(
            self, snapshot: p.AttemptRecoverySnapshot) -> bool:
        return snapshot in self.attempt_recovery_history

    def complete_admission_cleanup(
            self, reservation: p.AdmissionReservation,
            cleanup_claim_sha256: str,
            receipts: tuple[p.AdmissionCleanupReceipt, ...]
            ) -> p.AdmissionRetirement:
        if (not self.verify_admission(reservation)
                or self.admission_cleanup_claims.get(
                    reservation.attempt_id) != cleanup_claim_sha256
                or tuple(item.kind for item in receipts) !=
                   ("network", "paths", "runner")):
            raise RuntimeError("admission retirement changed")
        self.cleaned_admission_stages[reservation.attempt_id] = tuple(
            self.admission_stages.get(reservation.attempt_id, []))
        self.monotonic_counter += 1
        retirement = p.AdmissionRetirement(
            p.JOURNAL_SCHEMA, "journal", reservation.attempt_id,
            reservation.digest, reservation.generation,
            cleanup_claim_sha256,
            p._hash(p._canonical_json([item.digest for item in receipts])),
            self.monotonic_counter, time.monotonic_ns(),
            True, True, True)
        self.admission_retirement_history.append(retirement)
        self.admissions.pop(reservation.attempt_id, None)
        self.admission_stages.pop(reservation.attempt_id, None)
        self.admission_cleanup_claims.pop(reservation.attempt_id, None)
        return retirement

    def verify_admission_retirement(
            self, retirement: p.AdmissionRetirement) -> bool:
        return retirement in self.admission_retirement_history


class FakeRunner:
    def __init__(self, paths: FakePaths) -> None:
        self.paths = paths
        self.state = p.ContainerState.ABSENT
        self.image_present = True
        self.exit_code = 0
        self.calls: list[dict[str, object]] = []
        self.receipt_changes: dict[str, object] = {}
        self.inspect_changes: dict[str, object] = {}
        self.raise_message: str | None = None
        self.last_create: tuple[str, ...] = ()
        self.component_sequence = 0
        self.extinction_sequence = 0
        self.extinction_populated = 0
        self.extinction_descendants = 0
        self.extinction_conmon = True
        self.cleanup_changed = False
        self.component_changed = False
        self.last_component: p.ComponentObservation | None = None
        self.last_extinction: p.ExtinctionObservation | None = None
        self.admission_cleanup_calls = 0

    def security_contract(self, components_: p.ComponentIdentities,
                          roots_: p.ProviderRoots, host_: p.HostFacts,
                          root_bindings: tuple[p.PathBinding, ...]) -> p.RunnerContract:
        digest = p._hash(p._canonical_json([item.document for item in root_bindings]))
        return p.RunnerContract(
            p.PROVIDER_SCHEMA, "runner", components_.digest, host_.digest,
            roots_.digest, digest, p._ISOLATED_CONFIG_SHA256, *([True] * 23),
        )

    def acquire_lease(self, attempt_seed: str, *, uid: int,
                      gid: int, reservation: p.AdmissionReservation
                      ) -> p.ExecutionLease:
        return p.ExecutionLease(
            schema=p.PROVIDER_SCHEMA, authority_id="runner",
            attempt_seed=attempt_seed, token=K, cgroup_token=H,
            keeper_token=G,
            cgroup_path="/sys/fs/cgroup/user.slice/plamen-" + attempt_seed[-16:],
            cgroup_device=30, cgroup_inode=40, cgroup_mount_id=50,
            conmon_scope_sha256=G,
            uidmap_sha256=p._hash(f"keep-id:{uid}:{gid}".encode()),
            keeper_pid=1234, delegated=True,
        )

    def revalidate_lease(self, lease: p.ExecutionLease) -> p.ExecutionLease:
        return lease

    def acquire_cleanup(self, lease: p.ExecutionLease) -> p.CleanupLease:
        return p.CleanupLease(
            p.PROVIDER_SCHEMA, "runner", lease.attempt_seed,
            p._hash((lease.token + "cleanup").encode()), lease.digest,
            lease.cgroup_token, lease.keeper_token, True, True, True, True,
        )

    def revalidate_cleanup(self, cleanup: p.CleanupLease) -> p.CleanupLease:
        return (dataclasses.replace(cleanup, token=K)
                if self.cleanup_changed else cleanup)

    def observe_components(self, components_: p.ComponentIdentities,
                           challenge: p.ObservationChallenge
                           ) -> p.ComponentObservation:
        self.component_sequence = challenge.generation
        executables = (components_.podman, components_.conmon,
                       components_.crun, components_.newuidmap,
                       components_.newgidmap, components_.overlay_helper)
        content = p._hash(p._canonical_json([
            {"dev": item.device, "ino": item.inode, "size": item.size,
             "mode": item.mode, "sha256": item.sha256,
             "chain": item.component_chain_sha256,
             "xattr": item.xattr_sha256} for item in executables
        ]))
        if self.component_changed:
            content = K
        observation = p.ComponentObservation(
            p.PROVIDER_SCHEMA, "runner", components_.digest, content,
            challenge.digest,
            self.component_sequence, time.monotonic_ns(), True, True)
        self.last_component = observation
        return observation

    def observe_extinction(self, lease: p.ExecutionLease,
                           cleanup: p.CleanupLease,
                           challenge: p.ObservationChallenge
                           ) -> p.ExtinctionObservation:
        self.extinction_sequence = challenge.generation
        observation = p.ExtinctionObservation(
            p.PROVIDER_SCHEMA, "runner", cleanup.digest, lease.digest,
            lease.cgroup_token, lease.keeper_token, challenge.digest,
            self.extinction_sequence, time.monotonic_ns(),
            self.extinction_populated, self.extinction_descendants,
            self.extinction_conmon, True,
        )
        self.last_extinction = observation
        return observation

    def emergency_extinguish(self, lease: p.ExecutionLease,
                             cleanup: p.CleanupLease,
                             challenge: p.ObservationChallenge,
                             expected_container_id: str | None, *,
                             timeout: float
                             ) -> p.ExtinctionObservation:
        p._timeout(timeout)
        if expected_container_id not in (None, CONTAINER_ID):
            raise RuntimeError("wrong emergency target")
        self.state, self.exit_code = p.ContainerState.EXITED, 137
        return self.observe_extinction(lease, cleanup, challenge)

    def release_execution(self, lease: p.ExecutionLease,
                          cleanup: p.CleanupLease, *,
                          context_sha256: str,
                          release_nonce: str
                          ) -> tuple[p.ResourceReleaseReceipt, ...]:
        def receipt(kind: str, token: str) -> p.ResourceReleaseReceipt:
            return p.ResourceReleaseReceipt(
                p.PROVIDER_SCHEMA, "runner", kind, token, context_sha256,
                release_nonce, time.monotonic_ns(), True, True, True, H)
        return (receipt("cleanup-authority", cleanup.token),
                receipt("execution-lease", lease.token),
                receipt("execution-cgroup", lease.cgroup_token),
                receipt("execution-keeper", lease.keeper_token))

    def verify_release(self, receipt: p.ResourceReleaseReceipt) -> bool:
        return receipt.authority_id == "runner" and receipt.authenticated

    def cleanup_admission(self, reservation: p.AdmissionReservation, *,
                          cleanup_nonce: str
                          ) -> p.AdmissionCleanupReceipt:
        self.admission_cleanup_calls += 1
        return p.AdmissionCleanupReceipt(
            p.JOURNAL_SCHEMA, "runner", "runner", reservation.digest,
            reservation.attempt_id, cleanup_nonce, time.monotonic_ns(),
            True, True, True, H)

    def verify_admission_cleanup(
            self, receipt: p.AdmissionCleanupReceipt) -> bool:
        return receipt.authority_id == "runner" and receipt.authenticated

    @staticmethod
    def _value(argv: tuple[str, ...], flag: str) -> str:
        for index, item in enumerate(argv):
            if item == flag:
                return argv[index + 1]
            if item.startswith(flag + "="):
                return item.split("=", 1)[1]
        raise AssertionError(flag)

    def _inspect(self, bindings: tuple[p.PathBinding, ...],
                 network: p.NetworkProof | None,
                 lease: p.ExecutionLease) -> dict[str, object]:
        argv = self.last_create
        labels: dict[str, str] = {}
        env: list[str] = []
        security: list[str] = []
        tmpfs: dict[str, str] = {}
        for index, item in enumerate(argv):
            if item == "--label":
                key, value = argv[index + 1].split("=", 1)
                labels[key] = value
            elif item == "--env":
                env.append(argv[index + 1])
            elif item == "--security-opt":
                security.append(argv[index + 1])
            elif item == "--tmpfs":
                target, options = argv[index + 1].split(":", 1)
                tmpfs[target] = options
        mounts = []
        for purpose in p._CONTAINER_MOUNTS:
            binding = next(item for item in bindings if item.purpose == purpose)
            mounts.append({
                "Type": "bind", "Source": str(binding.source),
                "Destination": binding.target, "RW": not binding.readonly,
                "Propagation": "rprivate",
                "Options": ["bind", "rprivate", "bind-nonrecursive"],
            })
        running, exited = (self.state is p.ContainerState.RUNNING,
                           self.state is p.ContainerState.EXITED)
        result: dict[str, object] = {
            "id": CONTAINER_ID, "name": self._value(argv, "--name"),
            "image_digest": "sha256:" + H,
            "state": ("created" if self.state is p.ContainerState.CREATED
                      else self.state.value),
            "running": running, "exit_code": self.exit_code if exited else 0,
            "pid": 2222 if running else 0,
            "conmon_pid": 3333 if running else 0,
            "cgroup_path": lease.cgroup_path, "labels": labels,
            "hostname": self._value(argv, "--hostname"),
            "use_image_hosts": False, "use_image_hostname": False,
            "network_mode": (network.podman_network if network is not None
                             else self._value(argv, "--network")),
            "user": self._value(argv, "--user"),
            "userns_mode": self._value(argv, "--userns"), "env": env,
            "mounts": mounts, "tmpfs": tmpfs, "effective_caps": [],
            "bounding_caps": [], "oci_runtime": "crun",
            "restart_policy": "no", "read_only": True,
            "privileged": False, "devices": [], "cap_add": [],
            "pid_mode": "private", "ipc_mode": "private",
            "uts_mode": "private", "cgroup_mode": "private",
            "cgroups": "enabled",
            "memory": int(self._value(argv, "--memory")),
            "memory_swap": int(self._value(argv, "--memory-swap")),
            "nano_cpus": int(float(self._value(argv, "--cpus")) * 1_000_000_000),
            "pids_limit": int(self._value(argv, "--pids-limit")),
            "ulimits": [{"Name": "nofile", "Soft": 4096, "Hard": 4096},
                        {"Name": "core", "Soft": 0, "Hard": 0}],
            "security_opt": security, "log_driver": "none",
            "healthcheck": None, "systemd": False, "sdnotify": "ignore",
        }
        result.update(self.inspect_changes)
        return result

    def __call__(self, argv: tuple[str, ...], *, env: tuple[str, ...],
                 components: p.ComponentIdentities,
                 bindings: tuple[p.PathBinding, ...],
                 output: p.PathBinding | None, network: p.NetworkProof | None,
                 lease: p.ExecutionLease | None,
                 cleanup: p.CleanupLease | None,
                 component_observation: p.ComponentObservation,
                 timeout: float,
                 output_limit: int, capability: object) -> p.RunnerResult:
        if self.raise_message:
            raise RuntimeError(self.raise_message)
        operation = capability.operation
        stdout, rc = b"", 0
        if operation.startswith("version-"):
            label = operation.removeprefix("version-")
            version = dict(p.ComponentIdentities.pins())[label]
            if label in {"newuidmap", "newgidmap"}:
                stdout = f"{label} from shadow-utils {version}\n".encode()
            elif label == "fuse-overlayfs":
                stdout = f"fuse-overlayfs: version {version}\n".encode()
            else:
                stdout = f"{label} version {version}\n".encode()
        elif operation == "image-exists":
            rc = 0 if self.image_present else 1
        elif operation == "image-inspect":
            stdout = json.dumps({
                "id": "sha256:" + IMAGE_ID, "digest": "sha256:" + H,
                "os": "linux", "architecture": "amd64",
                "repo_digests": ["localhost/plamen/audit@sha256:" + H],
            }, separators=(",", ":")).encode()
        elif operation == "image-load":
            self.image_present = True
        elif operation == "container-exists":
            rc = 1 if self.state is p.ContainerState.ABSENT else 0
        elif operation == "container-create":
            self.last_create, self.state = argv, p.ContainerState.CREATED
            stdout = (CONTAINER_ID + "\n").encode()
        elif operation == "container-inspect":
            assert lease is not None
            stdout = json.dumps(self._inspect(bindings, network, lease),
                                separators=(",", ":")).encode()
        elif operation == "container-start":
            self.state = p.ContainerState.RUNNING
        elif operation == "container-wait":
            self.state = p.ContainerState.EXITED
            stdout = str(self.exit_code).encode()
        elif operation == "container-cancel":
            self.state, self.exit_code = p.ContainerState.EXITED, 137
        elif operation == "container-delete":
            self.state = p.ContainerState.ABSENT
        self.calls.append({"operation": operation, "argv": argv, "env": env,
                           "bindings": bindings, "network": network,
                           "lease": lease, "cleanup": cleanup,
                           "component_observation": component_observation})
        binding_digest = p._hash(p._canonical_json(
            [item.document for item in bindings]))
        receipt = p.InvocationReceipt(
            p.PROVIDER_SCHEMA, "runner", capability.nonce,
            components.digest, component_observation.digest,
            p._hash(p._canonical_json(list(argv))),
            p._hash(p._canonical_json(list(env))), binding_digest,
            tuple(item.token for item in bindings),
            output.token if output else None,
            network.digest if network else None,
            network.endpoint_token if network else None,
            lease.digest if lease else None,
            lease.cgroup_token if lease else None,
            lease.conmon_scope_sha256 if lease else None,
            cleanup.digest if cleanup else None,
            cleanup.token if cleanup else None,
            True, True, True, True, True, True, True,
            operation not in {"container-create", "container-start"},
            0 if operation in {"container-wait", "container-cancel",
                               "container-export", "container-delete"} else 1,
            True, cleanup is not None,
        )
        if self.receipt_changes:
            receipt = dataclasses.replace(receipt, **self.receipt_changes)
        return p.RunnerResult(rc, stdout, b"", receipt)


class Harness:
    def __init__(self, kind: p.NetworkKind = p.NetworkKind.VERIFIED_NARROW_PROXY) -> None:
        self.paths, self.network = FakePaths(), FakeNetwork(kind)
        self.journal = FakeJournal()
        self.runner = FakeRunner(self.paths)
        self.provider = p.PodmanLinuxProvider(
            components=components(), roots=roots(), runner=self.runner,
            paths=self.paths, journal=self.journal, network=self.network,
            host_facts=host(),
        )

    def preflight(self) -> None:
        with mock.patch.object(platform, "system", return_value="Linux"):
            self.provider.preflight()

    def cold_provider(self) -> p.PodmanLinuxProvider:
        provider = p.PodmanLinuxProvider(
            components=components(), roots=roots(), runner=self.runner,
            paths=self.paths, journal=self.journal, network=self.network,
            host_facts=host(),
        )
        with mock.patch.object(platform, "system", return_value="Linux"):
            provider.preflight()
        return provider


class ProviderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.h, self.spec = Harness(), spec()
        self.h.preflight()

    @staticmethod
    def exit_container(h: Harness, candidate: p.ContainerSpec) -> None:
        h.provider.create(candidate)
        h.provider.start(candidate, CONTAINER_ID)
        h.provider.wait(candidate, CONTAINER_ID)

    def test_full_fake_lifecycle(self) -> None:
        self.assertTrue(p.verify_receipt(self.h.provider.create(self.spec)))
        self.h.provider.start(self.spec, CONTAINER_ID)
        waited = self.h.provider.wait(self.spec, CONTAINER_ID)
        self.assertEqual(waited.document["exit_code"], 0)
        exported = self.h.provider.export(self.spec, CONTAINER_ID,
                                          Path("/audit/export.tar"))
        self.assertEqual(exported.document["artifact"], G)
        self.h.provider.delete(self.spec, CONTAINER_ID)

    def test_export_destination_rejects_every_authority_tree(self) -> None:
        self.exit_container(self.h, self.spec)
        for destination in (
            Path("/audit/state/result.tar"),
            Path("/private/plamen/storage/result.tar"),
            Path("/opt/plamen-bin/result.tar"),
            Path("/home/alice/result.tar"),
        ):
            with self.subTest(destination=destination):
                with self.assertRaises(p.AdmissionError):
                    self.h.provider.export(
                        self.spec, CONTAINER_ID, destination)

    def test_export_destination_native_alias_rejected(self) -> None:
        self.exit_container(self.h, self.spec)
        self.h.paths.unsafe["export-parent"] = {
            "device": 20,
            "inode": stable_inode("state", Path("/audit/state")),
        }
        with self.assertRaises(p.AdmissionError):
            self.h.provider.export(
                self.spec, CONTAINER_ID, Path("/audit/out.tar"))

    def test_artifact_commit_must_preserve_binding_and_prove_census(self) -> None:
        cases = (
            {"binding": {"purpose": "other"}},
            {"binding": {"mode": stat.S_IFREG | 0o644}},
            {"binding": {"has_socket": True}},
            {"binding": {"sensitive_overlap": True}},
            {"atomic_no_replace": False},
            {"destination_was_absent": False},
            {"temporary_file_fsync": False},
            {"reopened_after_publish": False},
            {"descriptor_relative_readback": False},
            {"complete_census": False},
            {"manifest_embedded": False},
            {"census_matches_archive": False},
            {"archive_sha256": K},
        )
        for changes in cases:
            with self.subTest(changes=changes):
                h, candidate = Harness(), spec()
                h.preflight(); self.exit_container(h, candidate)
                h.paths.export_changes = dict(changes)
                with self.assertRaises(p.AmbiguousMutationError):
                    h.provider.export(candidate, CONTAINER_ID,
                                      Path("/audit/result.tar"))

    def test_export_slot_requires_absence_and_new_published_inode(self) -> None:
        self.exit_container(self.h, self.spec)
        self.h.paths.export_preexisting = True
        with self.assertRaises(p.AdmissionError):
            self.h.provider.export(
                self.spec, CONTAINER_ID, Path("/audit/result.tar"))
        self.h.paths.export_preexisting = False
        self.h.provider.export(
            self.spec, CONTAINER_ID, Path("/audit/result.tar"))
        commit = self.h.paths.export_commit
        self.assertIsNotNone(commit)
        assert commit is not None
        slot = self.h.paths.admit_export(
            Path("/audit/another.tar"), byte_limit=16 * 1024**3,
            mapped_uid=self.spec.uid, mapped_gid=self.spec.gid)
        self.assertNotEqual(
            (commit.binding.device, commit.binding.inode),
            (slot.parent.device, slot.parent.inode))
        self.assertTrue(commit.atomic_no_replace)
        self.assertTrue(commit.reopened_after_publish)

    def test_export_concurrent_destination_appearance_is_ambiguous(self) -> None:
        self.exit_container(self.h, self.spec)
        self.h.paths.export_race_preexisting = True
        with self.assertRaises(p.AmbiguousMutationError):
            self.h.provider.export(
                self.spec, CONTAINER_ID, Path("/audit/result.tar"))
        record = self.h.journal.records[
            self.h.provider._attempt_id(self.spec)]
        self.assertIs(record.state, p.MutationState.PENDING)

    def test_artifacts_are_packaged_post_extinction_not_podman_export(self) -> None:
        self.exit_container(self.h, self.spec)
        receipt = self.h.provider.export(
            self.spec, CONTAINER_ID, Path("/audit/result.tar"))
        self.assertEqual(self.h.paths.packaged_sources,
                         ("project-merged", "state", "scratch"))
        self.assertNotIn("container-export",
                         [call["operation"] for call in self.h.runner.calls])
        self.assertEqual(receipt.document["artifact_census"], H)
        self.assertEqual(receipt.document["cgroup_populated"], 0)
        with self.assertRaises(p.ContractError):
            self.h.provider._plan(
                "container-export", self.h.provider._global_argv() +
                ("container", "export", "--output", "/audit/evil.tar",
                 CONTAINER_ID), mutating=True, journal_nonce=H)

    def test_export_recensuses_after_atomic_package(self) -> None:
        self.exit_container(self.h, self.spec)
        original = self.h.paths.package_artifacts
        def repopulate(*args: object, **kwargs: object) -> p.ArtifactCommit:
            commit = original(*args, **kwargs)  # type: ignore[arg-type]
            self.h.runner.extinction_populated = 1
            return commit
        self.h.paths.package_artifacts = repopulate  # type: ignore[method-assign]
        with self.assertRaises(p.StateError):
            self.h.provider.export(
                self.spec, CONTAINER_ID, Path("/audit/result.tar"))

    def test_overlay_project_is_writable_merged_only(self) -> None:
        argv = self.h.provider.render_create_argv(self.spec)
        mounts = [argv[i + 1] for i, item in enumerate(argv) if item == "--mount"]
        joined = "\n".join(mounts)
        self.assertIn("source=/private/plamen/overlay/merged,destination=/workspace/project,ro=false", joined)
        self.assertNotIn("source=/audit/project,", joined)
        self.assertNotIn("/overlay/upper,", joined)
        self.assertNotIn("/overlay/work,", joined)
        self.assertIn("bind-propagation=rprivate,bind-nonrecursive", joined)

    def test_keep_id_mapping_and_nonroot(self) -> None:
        argv = self.h.provider.render_create_argv(self.spec)
        self.assertIn("--userns=keep-id:uid=65532,gid=65532,size=65536", argv)
        self.assertEqual(argv[argv.index("--user") + 1], "65532:65532")

    def test_lifecycle_calls_bind_context(self) -> None:
        self.h.provider.create(self.spec)
        self.h.provider.start(self.spec, CONTAINER_ID)
        for call in self.h.runner.calls:
            if str(call["operation"]).startswith("container-"):
                self.assertGreaterEqual(len(call["bindings"]), 14)
                self.assertIsNotNone(call["network"])
                self.assertIsNotNone(call["lease"])

    def test_journal_stores_full_context(self) -> None:
        self.h.provider.create(self.spec)
        context = self.h.provider._context(self.spec)
        record = self.h.journal.records[context.attempt_id]
        self.assertEqual(record.bindings, context.bindings)
        self.assertEqual(record.root_bindings, self.h.provider._root_bindings)
        self.assertEqual(record.topology, context.topology)
        self.h.journal.records[context.attempt_id] = dataclasses.replace(
            record, bindings_sha256=G)
        with self.assertRaises(p.StateError):
            self.h.provider.inspect(self.spec)

    def test_source_path_changes_fingerprint(self) -> None:
        mounts = list(self.spec.mounts)
        mounts[0] = p.MountRequest("project-lower", Path("/audit/another"))
        other = dataclasses.replace(self.spec, mounts=tuple(mounts))
        self.assertNotEqual(self.spec.base_fingerprint, other.base_fingerprint)

    def test_proxy_network_and_private_shim_fail_closed(self) -> None:
        argv = self.h.provider.render_create_argv(self.spec)
        self.assertIn("--network=ns:/proc/self/fd/9", argv)
        h = Harness(p.NetworkKind.PRIVATE_SHIM); h.preflight()
        with self.assertRaises(p.AdmissionError):
            h.provider.render_create_argv(spec())

    def test_network_revoke_change_rejected(self) -> None:
        self.h.provider.render_create_argv(self.spec)
        self.h.network.revoked = True
        with self.assertRaises(p.AdmissionError):
            self.h.provider.inspect(self.spec, absent_ok=True)

    def test_revoked_network_cannot_block_cleanup_or_release(self) -> None:
        self.h.provider.create(self.spec)
        self.h.provider.start(self.spec, CONTAINER_ID)
        self.h.network.revoked = True
        cancelled = self.h.provider.cancel(self.spec, CONTAINER_ID)
        deleted = self.h.provider.delete(self.spec, CONTAINER_ID)
        released = self.h.provider.release(self.spec)
        self.assertEqual(cancelled.document["cgroup_populated"], 0)
        self.assertEqual(deleted.document["cgroup_populated"], 0)
        self.assertEqual(
            released.document["resources"],
            ["namespace-endpoint", "overlay-keeper", "cleanup-authority",
             "execution-lease", "execution-cgroup", "execution-keeper"],
        )
        record = self.h.journal.records[
            self.h.provider._attempt_id(self.spec)]
        self.assertEqual(len(record.release_receipts), 6)
        self.assertTrue(all(item.authenticated
                            for item in record.release_receipts))
        cleanup_calls = [call for call in self.h.runner.calls
                         if call["operation"] in {
                             "container-cancel", "container-delete"}]
        self.assertTrue(cleanup_calls)
        self.assertTrue(all(call["network"] is None
                            and call["cleanup"] is not None
                            for call in cleanup_calls))
        with self.assertRaises(p.StateError):
            self.h.provider.inspect(self.spec, absent_ok=True)

    def test_cold_cleanup_uses_durable_authority_after_revocation(self) -> None:
        self.h.provider.create(self.spec)
        self.h.provider.start(self.spec, CONTAINER_ID)
        self.h.network.revoked = True
        cold = self.h.cold_provider()
        receipt = cold.cancel(self.spec, CONTAINER_ID)
        self.assertEqual(receipt.document["cgroup_populated"], 0)
        call = next(call for call in reversed(self.h.runner.calls)
                    if call["operation"] == "container-cancel")
        self.assertIsNone(call["network"])
        self.assertIsNotNone(call["cleanup"])

    def test_release_receipt_tamper_is_ambiguous(self) -> None:
        self.exit_container(self.h, self.spec)
        self.h.provider.delete(self.spec, CONTAINER_ID)
        self.h.network.release_tamper = True
        with self.assertRaises(p.AmbiguousMutationError):
            self.h.provider.release(self.spec)

    def test_pending_release_recovers_idempotently_from_stable_record(self) -> None:
        self.exit_container(self.h, self.spec)
        self.h.provider.delete(self.spec, CONTAINER_ID)
        original, count = self.h.journal.write, 0
        def fail_completion(record: p.MutationRecord) -> None:
            nonlocal count
            count += 1
            if count > 1:
                raise RuntimeError("secret")
            return original(record)  # type: ignore[return-value]
        self.h.journal.write = fail_completion  # type: ignore[method-assign]
        with self.assertRaises(p.AmbiguousMutationError):
            self.h.provider.release(self.spec)
        self.h.journal.write = original  # type: ignore[method-assign]
        cold = self.h.cold_provider()
        recovered = cold.recover(self.spec)
        self.assertEqual(recovered.document["operation"], "release")
        self.assertEqual(recovered.document["status"], "reconciled")
        self.h.network.revoked, self.h.network.changed = False, True
        with self.assertRaises(p.AdmissionError):
            self.h.provider.inspect(self.spec, absent_ok=True)

    def test_overlay_and_path_drift_rejected_pre_runner(self) -> None:
        self.h.provider.render_create_argv(self.spec)
        count = len(self.h.runner.calls)
        self.h.paths.overlay_drift = True
        with self.assertRaises(p.AdmissionError):
            self.h.provider.inspect(self.spec, absent_ok=True)
        self.h.paths.overlay_drift = False
        self.h.paths.drift_purpose = "project-merged"
        with self.assertRaises(p.AdmissionError):
            self.h.provider.inspect(self.spec, absent_ok=True)
        self.assertEqual(len(self.h.runner.calls), count)

    def test_home_and_ancestor_mounts_rejected(self) -> None:
        mounts = list(self.spec.mounts)
        mounts[0] = p.MountRequest("project-lower", Path("/home/alice/project"))
        with self.assertRaises(p.AdmissionError):
            self.h.provider.render_create_argv(
                dataclasses.replace(self.spec, mounts=tuple(mounts)))
        mounts = list(self.spec.mounts)
        mounts[5] = p.MountRequest("state", Path("/audit"))
        with self.assertRaises(p.ContractError):
            dataclasses.replace(self.spec, mounts=tuple(mounts)).validate()

    def test_unsafe_tree_evidence_rejected(self) -> None:
        cases = ({"has_symlink": True}, {"has_hardlink": True},
                 {"has_special_file": True}, {"has_socket": True},
                 {"sensitive_overlap": True}, {"xattr_sha256": G})
        for changes in cases:
            h = Harness(); h.paths.unsafe["runtime"] = changes; h.preflight()
            with self.assertRaises(p.AdmissionError, msg=str(changes)):
                h.provider.render_create_argv(spec())

    def test_native_mount_alias_rejected(self) -> None:
        h = Harness()
        h.paths.unsafe["runtime"] = {
            "device": 20,
            "inode": stable_inode("project-lower", Path("/audit/project")),
        }
        h.preflight()
        with self.assertRaises(p.AdmissionError):
            h.provider.render_create_argv(spec())

    def test_provider_roots_overlap_and_alias_rejected(self) -> None:
        bad = dataclasses.replace(roots(),
                                  tmp=Path("/private/plamen/storage/tmp"))
        with self.assertRaises(p.PreflightError):
            bad.validate(host())
        h, original = Harness(), None
        original = h.paths.admit
        storage_inode = stable_inode(
            "provider-storage", Path("/private/plamen/storage"))
        def alias(*args: object, **kwargs: object) -> p.PathBinding:
            result = original(*args, **kwargs)
            return (dataclasses.replace(result, inode=storage_inode)
                    if kwargs["purpose"] == "provider-runroot" else result)
        h.paths.admit = alias  # type: ignore[method-assign]
        with mock.patch.object(platform, "system", return_value="Linux"):
            with self.assertRaises(p.PreflightError):
                h.provider.preflight()

    def test_unmapped_writable_mount_rejected(self) -> None:
        h = Harness(); h.paths.unsafe["state"] = {"keep_id_writable": False}; h.preflight()
        with self.assertRaises(p.AdmissionError):
            h.provider.render_create_argv(spec())

    def test_exact_hardening_argv(self) -> None:
        argv = self.h.provider.render_create_argv(self.spec)
        for flag in ("--pull=never", "--read-only", "--read-only-tmpfs=false",
                     "--cap-drop=all", "--unsetenv-all", "--http-proxy=false",
                     "--image-volume=ignore", "--no-healthcheck",
                     "--hosts-file=none", "--log-driver=none"):
            self.assertIn(flag, argv)
        self.assertEqual(argv.count("--tmpfs"), 4)
        self.assertIn("mount_program=/opt/plamen-bin/fuse-overlayfs", argv)

    def test_inspect_rejects_security_drift(self) -> None:
        self.h.provider.create(self.spec)
        cases = {
            "network_mode": "bridge", "userns_mode": "host",
            "hostname": "evil", "use_image_hosts": True,
            "use_image_hostname": True, "effective_caps": ["CAP_SYS_ADMIN"],
            "bounding_caps": ["CAP_NET_RAW"], "read_only": False,
            "privileged": True, "devices": ["/dev/kvm"], "pid_mode": "host",
            "ipc_mode": "host", "uts_mode": "host", "cgroup_mode": "host",
            "memory": 0, "memory_swap": -1, "nano_cpus": 0,
            "pids_limit": 0, "log_driver": "journald", "healthcheck": {},
            "systemd": True, "sdnotify": "container",
            "cgroup_path": "/sys/fs/cgroup/other", "security_opt": [],
            "tmpfs": {}, "ulimits": [], "mounts": [],
        }
        for key, value in cases.items():
            self.h.runner.inspect_changes = {key: value}
            with self.assertRaises(p.StateError, msg=key):
                self.h.provider.inspect(self.spec)

    def test_recreation_detected(self) -> None:
        self.h.provider.create(self.spec)
        self.h.runner.inspect_changes = {"id": G}
        with self.assertRaises(p.StateError):
            self.h.provider.inspect(self.spec)

    def test_unknown_inspect_field_and_state_rejected(self) -> None:
        self.h.provider.create(self.spec)
        self.h.runner.inspect_changes = {"unexpected": "field"}
        with self.assertRaises(p.ContractError):
            self.h.provider.inspect(self.spec)
        self.h.runner.inspect_changes = {"state": "paused"}
        with self.assertRaises(p.StateError):
            self.h.provider.inspect(self.spec)

    def test_runner_receipt_binds_endpoint_cgroup_fds(self) -> None:
        cases = ({"network_proof_sha256": G}, {"network_endpoint_token": H},
                 {"lease_sha256": H}, {"cgroup_token": K},
                 {"conmon_scope_sha256": H}, {"component_digest": G},
                 {"component_observation_sha256": H},
                 {"cleanup_sha256": H},
                 {"all_descriptors_held": False}, {"binding_digest": H})
        for changes in cases:
            h = Harness(); h.preflight(); h.runner.receipt_changes = changes
            with self.assertRaises(p.ContractError, msg=str(changes)):
                h.provider.inspect(spec(), absent_ok=True)

    def test_terminal_descendants_conmon_rejected(self) -> None:
        self.h.provider.create(self.spec)
        self.h.provider.start(self.spec, CONTAINER_ID)
        self.h.runner.receipt_changes = {"cgroup_populated": 1,
                                         "conmon_extinct": False}
        with self.assertRaises(p.StateError):
            self.h.provider.wait(self.spec, CONTAINER_ID)

    def test_later_fresh_extinction_census_cannot_be_hardcoded(self) -> None:
        self.h.provider.create(self.spec)
        self.h.provider.start(self.spec, CONTAINER_ID)
        self.h.runner.extinction_populated = 1
        with self.assertRaises(p.StateError):
            self.h.provider.wait(self.spec, CONTAINER_ID)
        self.h.runner.extinction_populated = 0
        receipt = self.h.provider.wait(self.spec, CONTAINER_ID)
        self.assertGreaterEqual(receipt.document["extinction_sequence"], 2)
        self.assertEqual(receipt.document["cgroup_populated"], 0)

    def test_local_image_miss_never_pulls(self) -> None:
        self.h.runner.image_present = False
        with self.assertRaises(p.AdmissionError):
            self.h.provider.ensure_local_image(self.spec)
        args = [item for call in self.h.runner.calls for item in call["argv"]]
        self.assertNotIn("pull", args)

    def test_pending_load_recovery(self) -> None:
        self.h.runner.image_present = False
        archive = p.ImageArchive(Path("/audit/image.oci"), H, H, True, True)
        original, count = self.h.journal.write, 0
        def fail_completion(record: p.MutationRecord) -> None:
            nonlocal count
            count += 1
            if count > 1:
                raise RuntimeError("secret")
            return original(record)  # type: ignore[return-value]
        self.h.journal.write = fail_completion  # type: ignore[method-assign]
        with self.assertRaises(p.AmbiguousMutationError):
            self.h.provider.ensure_local_image(self.spec, archive)
        self.h.journal.write = original  # type: ignore[method-assign]
        attempt = next(iter(self.h.journal.records))
        admissions = self.h.network.admit_calls
        cold = self.h.cold_provider()
        recovered = cold.recover(self.spec)
        self.assertEqual(recovered.document["operation"], "load")
        self.assertEqual(recovered.document["attempt"], attempt)
        self.assertEqual(self.h.network.admit_calls, admissions)

    def test_cold_recovery_adopts_persisted_roots_not_new_tokens(self) -> None:
        h, candidate = Harness(), spec()
        h.paths.ephemeral_root_tokens = True
        h.preflight()
        h.provider.create(candidate)
        attempt = h.provider._attempt_id(candidate)
        persisted = h.journal.records[attempt].root_bindings
        cold = h.cold_provider()
        self.assertNotEqual(cold._root_bindings, persisted)
        recovered = cold.recover(candidate)
        self.assertEqual(recovered.document["status"], "complete")
        self.assertEqual(cold._root_bindings, persisted)

    def test_pending_export_recovery(self) -> None:
        self.h.provider.create(self.spec)
        self.h.provider.start(self.spec, CONTAINER_ID)
        self.h.provider.wait(self.spec, CONTAINER_ID)
        original, count = self.h.journal.write, 0
        def fail_completion(record: p.MutationRecord) -> None:
            nonlocal count
            count += 1
            if count > 1:
                raise RuntimeError("secret")
            return original(record)  # type: ignore[return-value]
        self.h.journal.write = fail_completion  # type: ignore[method-assign]
        with self.assertRaises(p.AmbiguousMutationError):
            self.h.provider.export(self.spec, CONTAINER_ID,
                                   Path("/audit/result.tar"))
        self.h.journal.write = original  # type: ignore[method-assign]
        attempt = next(iter(self.h.journal.records))
        admissions = self.h.network.admit_calls
        cold = self.h.cold_provider()
        recovered = cold.recover(self.spec)
        self.assertEqual(recovered.document["operation"], "export")
        self.assertEqual(recovered.document["attempt"], attempt)
        self.assertEqual(self.h.network.admit_calls, admissions)

    def test_complete_export_recovery_requires_full_durable_readback(self) -> None:
        self.exit_container(self.h, self.spec)
        self.h.provider.export(
            self.spec, CONTAINER_ID, Path("/audit/result.tar"))
        before = self.h.paths.validate_export_calls
        cold = self.h.cold_provider()
        receipt = cold.recover(self.spec)
        self.assertEqual(receipt.document["status"], "complete")
        self.assertEqual(self.h.paths.validate_export_calls, before + 1)
        self.assertEqual(receipt.document["artifact"], G)

        commit = self.h.paths.export_commit
        assert commit is not None
        self.h.paths.export_commit = dataclasses.replace(
            commit, archive_sha256=K,
            binding=dataclasses.replace(commit.binding,
                                        snapshot_sha256=K))
        with self.assertRaises(p.AmbiguousMutationError):
            self.h.cold_provider().recover(self.spec)

    def test_complete_export_missing_archive_never_recovers_complete(self) -> None:
        self.exit_container(self.h, self.spec)
        self.h.provider.export(
            self.spec, CONTAINER_ID, Path("/audit/result.tar"))
        self.h.paths.validate_export_failure = True
        with self.assertRaises(p.AmbiguousMutationError):
            self.h.cold_provider().recover(self.spec)

    def test_complete_export_slot_or_published_inode_rebind_fails(self) -> None:
        self.exit_container(self.h, self.spec)
        self.h.provider.export(
            self.spec, CONTAINER_ID, Path("/audit/result.tar"))
        self.h.paths.export_slot_drift = True
        with self.assertRaises(p.AdmissionError):
            self.h.cold_provider().recover(self.spec)
        self.h.paths.export_slot_drift = False
        self.h.paths.drift_purpose = "export"
        with self.assertRaises(p.AdmissionError):
            self.h.cold_provider().recover(self.spec)

    def test_component_observation_replay_fails_after_cold_restart(self) -> None:
        replay = self.h.runner.last_component
        assert replay is not None
        self.h.runner.observe_components = (  # type: ignore[method-assign]
            lambda _components, _challenge: replay)
        provider = p.PodmanLinuxProvider(
            components=components(), roots=roots(), runner=self.h.runner,
            paths=self.h.paths, journal=self.h.journal,
            network=self.h.network, host_facts=host())
        with mock.patch.object(platform, "system", return_value="Linux"):
            with self.assertRaises(p.PreflightError):
                provider.preflight()

    def test_extinction_observation_replay_fails_after_cold_restart(self) -> None:
        self.exit_container(self.h, self.spec)
        self.h.provider.export(
            self.spec, CONTAINER_ID, Path("/audit/result.tar"))
        replay = self.h.runner.last_extinction
        assert replay is not None
        cold = self.h.cold_provider()
        self.h.runner.observe_extinction = (  # type: ignore[method-assign]
            lambda _lease, _cleanup, _challenge: replay)
        with self.assertRaises(p.StateError):
            cold.recover(self.spec)

    def test_hash_chain_rejects_forked_concurrent_successor(self) -> None:
        self.h.provider.create(self.spec)
        attempt = self.h.provider._attempt_id(self.spec)
        parent = self.h.journal.records[attempt]
        first = dataclasses.replace(
            parent, generation=parent.generation + 1,
            previous_record_sha256=parent.digest, nonce=G)
        second = dataclasses.replace(first, nonce=K)
        self.h.journal.write(first)
        with self.assertRaises(RuntimeError):
            self.h.journal.write(second)

    def test_native_monotonic_challenge_contract_is_mandatory(self) -> None:
        h = Harness()
        original = h.journal.security_contract
        h.journal.security_contract = (  # type: ignore[method-assign]
            lambda: dataclasses.replace(
                original(), external_monotonic_anchor=False))
        with mock.patch.object(platform, "system", return_value="Linux"):
            with self.assertRaises(p.PreflightError):
                h.provider.preflight()

    def test_rolled_back_head_triggers_authenticated_emergency_cleanup(self) -> None:
        self.h.provider.create(self.spec)
        attempt = self.h.provider._attempt_id(self.spec)
        old_create = self.h.journal.records[attempt]
        self.h.provider.start(self.spec, CONTAINER_ID)
        self.assertIs(self.h.runner.state, p.ContainerState.RUNNING)
        self.h.journal.records[attempt] = old_create
        cold = self.h.cold_provider()
        receipt = cold.cancel(self.spec, CONTAINER_ID)
        self.assertEqual(receipt.document["kind"],
                         "rollback-safe-cleanup")
        self.assertEqual(receipt.document["status"], "extinguished")
        self.assertIs(self.h.runner.state, p.ContainerState.EXITED)
        self.assertEqual(receipt.document["cgroup_populated"], 0)

    def test_rollback_cleanup_requires_fresh_extinction(self) -> None:
        self.h.provider.create(self.spec)
        attempt = self.h.provider._attempt_id(self.spec)
        old_create = self.h.journal.records[attempt]
        self.h.provider.start(self.spec, CONTAINER_ID)
        self.h.journal.records[attempt] = old_create
        self.h.runner.extinction_populated = 1
        with self.assertRaises(p.StateError):
            self.h.cold_provider().cancel(self.spec, CONTAINER_ID)

    def test_corrupt_reloadable_head_still_uses_cleanup_history(self) -> None:
        self.h.provider.create(self.spec)
        self.h.provider.start(self.spec, CONTAINER_ID)
        attempt = self.h.provider._attempt_id(self.spec)
        self.h.journal.records[attempt] = dataclasses.replace(
            self.h.journal.records[attempt], bindings_sha256=G)
        receipt = self.h.cold_provider().cancel(self.spec, CONTAINER_ID)
        self.assertEqual(receipt.document["kind"],
                         "rollback-safe-cleanup")
        self.assertIs(self.h.runner.state, p.ContainerState.EXITED)

    def test_rollback_cleanup_ignores_unrelated_path_overlay_drift(self) -> None:
        self.h.provider.create(self.spec)
        attempt = self.h.provider._attempt_id(self.spec)
        old_create = self.h.journal.records[attempt]
        self.h.provider.start(self.spec, CONTAINER_ID)
        self.h.journal.records[attempt] = old_create
        self.h.paths.drift_purpose = "project-merged"
        cold = self.h.cold_provider()
        receipt = cold.cancel(self.spec, CONTAINER_ID)
        self.assertEqual(receipt.document["kind"],
                         "rollback-safe-cleanup")
        self.assertIs(self.h.runner.state, p.ContainerState.EXITED)

    def test_closed_grammar_plan_capability_forgery(self) -> None:
        with self.assertRaises(p.ContractError):
            self.h.provider._plan("test", ("/opt/plamen-bin/podman", "info"))
        forged = object.__new__(p._InvocationPlan)
        with self.assertRaises(p.ContractError):
            self.h.provider._invoke(forged, bindings=(), output=None,
                                    network=None, lease=None, timeout=1)
        with self.assertRaises(p.ContractError):
            self.h.provider._plan(
                "container-delete", self.h.provider._global_argv() +
                ("container", "rm", CONTAINER_ID))
        forged_cap = object.__new__(p._RunnerCapability)
        with self.assertRaises(p.ContractError):
            p._consume_capability(forged_cap, "x")

    def test_inspect_grammar_requires_exact_template(self) -> None:
        prefix = self.h.provider._global_argv()
        with self.assertRaises(p.ContractError):
            self.h.provider._plan(
                "image-inspect",
                prefix + ("image", "inspect", "--format",
                          p._IMAGE_INSPECT_TEMPLATE + "junk",
                          self.spec.image.reference))
        with self.assertRaises(p.ContractError):
            self.h.provider._plan(
                "container-inspect",
                prefix + ("container", "inspect", "--format",
                          p._CONTAINER_INSPECT_TEMPLATE + "junk",
                          "plamen-a"))

    def test_pre_effect_failure_is_aborted_and_safely_retryable(self) -> None:
        with mock.patch.object(
                self.h.provider, "render_create_argv",
                side_effect=p.ContractError("pre-effect")):
            with self.assertRaises(p.ProviderError):
                self.h.provider.create(self.spec)
        attempt = self.h.provider._attempt_id(self.spec)
        record = self.h.journal.records[attempt]
        self.assertIs(record.state, p.MutationState.ABORTED)
        recovered = self.h.provider.recover(self.spec)
        self.assertEqual(recovered.document["status"], "aborted-safe-retry")
        created = self.h.provider.create(self.spec)
        self.assertEqual(created.document["container_id"], CONTAINER_ID)

    def test_render_has_durable_admission_and_cold_recovery_cleans(self) -> None:
        self.h.provider.render_create_argv(self.spec)
        attempt = self.h.provider._attempt_id(self.spec)
        self.assertNotIn(attempt, self.h.journal.records)
        self.assertIn(attempt, self.h.journal.admissions)
        self.assertEqual(
            tuple(item.stage for item in self.h.journal.admission_stages[attempt]),
            ("paths", "overlay", "network", "execution", "cleanup"))
        receipt = self.h.cold_provider().recover(self.spec)
        self.assertEqual(receipt.document["kind"], "admission-recovery")
        self.assertEqual(receipt.document["status"],
                         "reservation-resources-extinct")
        self.assertNotIn(attempt, self.h.journal.admissions)
        self.assertEqual(self.h.paths.admission_cleanup_calls, 1)
        self.assertEqual(self.h.network.admission_cleanup_calls, 1)
        self.assertEqual(self.h.runner.admission_cleanup_calls, 1)
        # The first process cannot use a cached context after another process
        # durably retired the reservation.
        with self.assertRaises(p.StateError):
            self.h.provider.create(self.spec)

    def test_process_death_after_every_admission_acquisition_prefix(self) -> None:
        expected = ("paths", "overlay", "network", "execution", "cleanup")
        for acquired in range(7):
            with self.subTest(acquisition_prefix=acquired):
                h, candidate = Harness(), spec()
                h.preflight()
                original_commit = h.provider._commit_admission_stage

                def commit_or_die(*args: object, **kwargs: object) -> None:
                    ordinal = kwargs["ordinal"]
                    if ordinal == acquired:
                        raise SimulatedProcessDeath
                    original_commit(*args, **kwargs)

                if acquired == 0:
                    patcher = mock.patch.object(
                        h.paths, "admit", side_effect=SimulatedProcessDeath)
                elif acquired <= 5:
                    # The Nth resource has been acquired, but its durable
                    # commitment has not yet returned when the process dies.
                    patcher = mock.patch.object(
                        h.provider, "_commit_admission_stage",
                        side_effect=commit_or_die)
                else:
                    # All five commitments are durable; die before the context
                    # can be cached or adopted by the first mutation record.
                    patcher = mock.patch.object(
                        h.provider, "_revalidate_context",
                        side_effect=SimulatedProcessDeath)
                with patcher:
                    with self.assertRaises(SimulatedProcessDeath):
                        h.provider.render_create_argv(candidate)
                attempt = h.provider._attempt_id(candidate)
                self.assertIn(attempt, h.journal.admissions)
                durable_prefix = (0 if acquired == 0 else acquired - 1)
                if acquired == 6:
                    durable_prefix = 5
                self.assertEqual(
                    tuple(item.stage for item in
                          h.journal.admission_stages[attempt]),
                    expected[:durable_prefix])
                receipt = h.cold_provider().recover(candidate)
                self.assertEqual(receipt.document["kind"],
                                 "admission-recovery")
                self.assertEqual(receipt.document["status"],
                                 "reservation-resources-extinct")
                self.assertNotIn(attempt, h.journal.admissions)
                self.assertEqual(h.paths.admission_cleanup_calls, 1)
                self.assertEqual(h.network.admission_cleanup_calls, 1)
                self.assertEqual(h.runner.admission_cleanup_calls, 1)

    def test_normal_admission_failure_fully_unwinds_and_retries(self) -> None:
        with mock.patch.object(
                self.h.runner, "acquire_cleanup",
                side_effect=RuntimeError("secret acquisition failure")):
            with self.assertRaises(p.AdmissionError) as caught:
                self.h.provider.render_create_argv(self.spec)
        self.assertIsNone(caught.exception.__cause__)
        self.assertIsNone(caught.exception.__context__)
        attempt = self.h.provider._attempt_id(self.spec)
        self.assertNotIn(attempt, self.h.journal.admissions)
        self.assertEqual(self.h.paths.admission_cleanup_calls, 1)
        self.assertEqual(self.h.network.admission_cleanup_calls, 1)
        self.assertEqual(self.h.runner.admission_cleanup_calls, 1)
        self.h.provider.render_create_argv(self.spec)

    def test_partial_cleanup_attempts_all_authorities_and_cold_retries(self) -> None:
        self.h.provider.render_create_argv(self.spec)
        attempt = self.h.provider._attempt_id(self.spec)

        def fail_network(*_args: object, **_kwargs: object) -> object:
            self.h.network.admission_cleanup_calls += 1
            raise RuntimeError("secret network cleanup failure")

        with mock.patch.object(
                self.h.network, "cleanup_admission",
                side_effect=fail_network):
            with self.assertRaises(p.StateError) as caught:
                self.h.cold_provider().recover(self.spec)
        self.assertIsNone(caught.exception.__cause__)
        self.assertIsNone(caught.exception.__context__)
        self.assertIn(attempt, self.h.journal.admissions)
        self.assertEqual(self.h.network.admission_cleanup_calls, 1)
        self.assertEqual(self.h.paths.admission_cleanup_calls, 1)
        self.assertEqual(self.h.runner.admission_cleanup_calls, 1)
        receipt = self.h.cold_provider().recover(self.spec)
        self.assertEqual(receipt.document["status"],
                         "reservation-resources-extinct")
        self.assertNotIn(attempt, self.h.journal.admissions)
        self.assertEqual(self.h.network.admission_cleanup_calls, 2)
        self.assertEqual(self.h.paths.admission_cleanup_calls, 2)
        self.assertEqual(self.h.runner.admission_cleanup_calls, 2)

    def test_corrupt_admission_stage_cannot_block_conservative_cleanup(self) -> None:
        self.h.provider.render_create_argv(self.spec)
        attempt = self.h.provider._attempt_id(self.spec)
        stages = self.h.journal.admission_stages[attempt]
        stages[0] = dataclasses.replace(stages[0], resource_sha256=K)
        receipt = self.h.cold_provider().recover(self.spec)
        self.assertEqual(receipt.document["status"],
                         "reservation-resources-extinct")
        self.assertIs(receipt.document["stages_authenticated"], False)
        self.assertNotIn(attempt, self.h.journal.admissions)
        self.assertEqual(self.h.network.admission_cleanup_calls, 1)
        self.assertEqual(self.h.paths.admission_cleanup_calls, 1)
        self.assertEqual(self.h.runner.admission_cleanup_calls, 1)

    def test_concurrent_first_use_is_serialized_and_cleanup_invalidates_peer(self) -> None:
        self.h.provider.render_create_argv(self.spec)
        second = self.h.cold_provider()
        network_calls = self.h.network.admit_calls
        with self.assertRaises(p.AmbiguousMutationError):
            second.render_create_argv(self.spec)
        self.assertEqual(self.h.network.admit_calls, network_calls)
        cleaned = second.recover(self.spec)
        self.assertEqual(cleaned.document["kind"], "admission-recovery")
        with self.assertRaises(p.StateError):
            self.h.provider.create(self.spec)

    def test_atomic_attempt_snapshot_closes_adoption_false_clean_race(self) -> None:
        self.h.provider.render_create_argv(self.spec)
        cold = self.h.cold_provider()
        original = self.h.journal.claim_attempt_recovery
        raced = False

        def adopt_before_atomic_read(
                attempt_id: str, *, base_spec_sha256: str
                ) -> p.AttemptRecoverySnapshot:
            nonlocal raced
            if not raced:
                raced = True
                self.h.provider.create(self.spec)
            return original(
                attempt_id, base_spec_sha256=base_spec_sha256)

        with mock.patch.object(
                self.h.journal, "claim_attempt_recovery",
                side_effect=adopt_before_atomic_read):
            receipt = cold.recover(self.spec)
        self.assertTrue(raced)
        self.assertEqual(receipt.document["status"], "complete")
        self.assertEqual(receipt.document["operation"], "create")
        attempt = self.h.provider._attempt_id(self.spec)
        self.assertIs(self.h.journal.records[attempt].state,
                      p.MutationState.COMPLETE)

    def test_retirement_receipt_remains_old_generation_scoped_on_reacquire(self) -> None:
        self.h.provider.render_create_argv(self.spec)
        attempt = self.h.provider._attempt_id(self.spec)
        old_reservation = self.h.journal.admissions[attempt]
        cleaner = self.h.cold_provider()
        original_verify = self.h.journal.verify_admission_retirement
        peer: list[p.PodmanLinuxProvider] = []

        def reacquire_before_receipt(
                retirement: p.AdmissionRetirement) -> bool:
            other = self.h.cold_provider()
            other.render_create_argv(self.spec)
            peer.append(other)
            return original_verify(retirement)

        with mock.patch.object(
                self.h.journal, "verify_admission_retirement",
                side_effect=reacquire_before_receipt):
            receipt = cleaner.recover(self.spec)
        self.assertEqual(receipt.document["status"],
                         "reservation-resources-extinct")
        self.assertEqual(receipt.document["reservation"],
                         old_reservation.digest)
        self.assertEqual(receipt.document["reservation_generation"],
                         old_reservation.generation)
        self.assertIn(attempt, self.h.journal.admissions)
        self.assertNotEqual(self.h.journal.admissions[attempt],
                            old_reservation)
        self.assertEqual(
            tuple(item.stage for item in
                  self.h.journal.admission_stages[attempt]),
            ("paths", "overlay", "network", "execution", "cleanup"))
        self.assertEqual(len(peer), 1)

    def test_exception_sanitization(self) -> None:
        self.h.runner.raise_message = "TOKEN=supersecret /home/alice/.ssh/id"
        with self.assertRaises(p.ProviderError) as caught:
            self.h.provider.inspect_image(self.spec.image)
        error = caught.exception
        self.assertNotIn("supersecret", str(error))
        self.assertIsNone(error.__cause__)
        self.assertIsNone(error.__context__)
        self.h.runner.raise_message = None
        self.h.journal.fail_write = True
        with self.assertRaises(p.AmbiguousMutationError) as caught:
            self.h.provider.create(self.spec)
        self.assertIsNone(caught.exception.__cause__)
        self.assertIsNone(caught.exception.__context__)

    def test_env_config_poisoning_closed(self) -> None:
        bad = dataclasses.replace(self.spec,
                                  environment=("HTTP_PROXY=http://evil",))
        with self.assertRaises(p.ContractError):
            bad.validate()
        self.h.provider.inspect_image(self.spec.image)
        env = self.h.runner.calls[-1]["env"]
        self.assertIn("CONTAINERS_CONF=/dev/null", env)
        self.assertIn("REGISTRY_AUTH_FILE=/dev/null", env)
        self.assertFalse(any(item.startswith("HTTP_PROXY=") for item in env))

    def test_bounds_json_duplicates_nan_huge(self) -> None:
        for value in (math.nan, math.inf, -math.inf, 0, 10**100):
            with self.assertRaises(p.BoundsError):
                self.h.provider.inspect_image(self.spec.image, timeout=value)
        with self.assertRaises(p.ContractError):
            p._strict_object(b'{"id":"x","id":"y"}', frozenset({"id"}))
        with self.assertRaises(p.ContractError):
            p._strict_object(b'{"id":NaN}', frozenset({"id"}))

    def test_provenance_and_helper_tamper(self) -> None:
        good = components()
        provenance = list(good.provenance)
        provenance[-1] = dataclasses.replace(provenance[-1], binary_sha256=G)
        with self.assertRaises(p.PreflightError):
            dataclasses.replace(good, provenance=tuple(provenance)).validate()
        with self.assertRaises(p.PreflightError):
            dataclasses.replace(
                good, overlay_helper=dataclasses.replace(good.overlay_helper,
                                                         nlink=2)).validate()

    def test_any_writable_executable_and_fresh_content_drift_rejected(self) -> None:
        good = components()
        for bits in (0o200, 0o020, 0o002):
            with self.subTest(bits=oct(bits)):
                bad = dataclasses.replace(
                    good,
                    podman=dataclasses.replace(
                        good.podman,
                        mode=stat.S_IFREG | 0o555 | bits))
                with self.assertRaises(p.PreflightError):
                    bad.validate()
        calls = len(self.h.runner.calls)
        self.h.runner.component_changed = True
        with self.assertRaises(p.PreflightError):
            self.h.provider.inspect_image(self.spec.image)
        self.assertEqual(len(self.h.runner.calls), calls)

    def test_mutable_image_tag_rejected(self) -> None:
        with self.assertRaises(p.AdmissionError):
            p.ImageSpec("localhost/plamen/audit:latest", H).validate()

    def test_expired_wrong_network_modes(self) -> None:
        authority = self.h.network.security_contract()
        proof = self.h.network.admit(POLICY)
        with self.assertRaises(p.AdmissionError):
            dataclasses.replace(proof, expires_monotonic_ns=1).validate(authority)
        with self.assertRaises(p.AdmissionError):
            dataclasses.replace(proof, podman_network="bridge").validate(authority)


if __name__ == "__main__":
    unittest.main()
