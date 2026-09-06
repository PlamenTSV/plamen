"""Hostile regressions for authoritative protobuf retained-closure replay."""
from __future__ import annotations

import copy
import hashlib
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest import mock

import audit_snapshot as SNAPSHOT


@unittest.skipUnless(os.name == "nt", "Windows retained descriptor semantics")
class ProtobufClosureCacheTests(unittest.TestCase):
    def tearDown(self) -> None:
        SNAPSHOT._release_retained_hardlink_denials()

    def _capture(self, project: Path) -> dict[str, object]:
        return SNAPSHOT._python_distribution_closure(
            "protobuf",
            "google.protobuf",
            project_root=project,
        )

    @staticmethod
    def _refold(payload: dict[str, object]) -> None:
        physical_fold = hashlib.sha256()
        for row in payload["rows"]:  # type: ignore[index]
            physical_fold.update(SNAPSHOT._canonical_json({
                "device": int(row["device"]),
                "file_id": int(row["file_id"]),
                "link_count": int(row["link_count"]),
                "path": str(row["path"]),
                "relative_name": str(row["relative_name"]),
                "size": int(row["size"]),
            }))
        payload["physical_fold_sha256"] = physical_fold.hexdigest()

    def test_hot_replay_rehashes_exact_native_and_live_denominators(self) -> None:
        with tempfile.TemporaryDirectory(prefix="snapshot-protobuf-") as raw:
            project = Path(raw)
            cold = self._capture(project)
            payload = SNAPSHOT._PYTHON_DISTRIBUTION_CLOSURE_CACHE["protobuf"][0]
            rows = payload["rows"]
            self.assertEqual(len(rows), cold["record_row_count"])
            self.assertEqual(
                len(SNAPSHOT._RETAINED_HARDLINK_DENIAL_FDS),
                cold["record_member_native_identity_count"],
            )
            started = time.perf_counter()
            with mock.patch(
                "importlib.metadata.distributions",
                side_effect=AssertionError(
                    "hot replay repeated distribution metadata discovery"
                ),
            ), mock.patch.object(
                SNAPSHOT,
                "_validate_protobuf_live_distribution_denominator",
                wraps=SNAPSHOT._validate_protobuf_live_distribution_denominator,
            ) as live_denominator, mock.patch.object(
                SNAPSHOT,
                "_assert_windows_default_stream_only",
                wraps=SNAPSHOT._assert_windows_default_stream_only,
            ) as streams:
                hot = self._capture(project)
            elapsed = time.perf_counter() - started
            self.assertEqual(hot, cold)
            self.assertEqual(live_denominator.call_count, 1)
            self.assertEqual(streams.call_count, len(rows))
            # This is deliberately generous under parallel CI load.  Its role
            # is to catch accidental return to per-row metadata/path discovery.
            self.assertLess(elapsed, 10.0)

    def test_hot_replay_rejects_live_extra_and_reachable_key_row_omission(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(prefix="snapshot-protobuf-") as raw:
            project = Path(raw)
            self._capture(project)
            original_live = SNAPSHOT._protobuf_live_distribution_paths
            with mock.patch.object(
                SNAPSHOT,
                "_protobuf_live_distribution_paths",
                side_effect=lambda root, name: (
                    original_live(root, name)
                    | {"google/protobuf/attacker_unrecorded.py"}
                ),
            ):
                with self.assertRaisesRegex(
                    SNAPSHOT.SnapshotInputError,
                    "live denominator differs from RECORD",
                ):
                    self._capture(project)

            original = SNAPSHOT._PYTHON_DISTRIBUTION_CLOSURE_CACHE["protobuf"]
            forged = copy.deepcopy(original[0])
            victim = next(
                row
                for row in forged["rows"]
                if not row["record_member"] and not row["module_member"]
            )
            forged["rows"].remove(victim)
            self._refold(forged)
            # The HMAC key is reachable module state and therefore explicitly
            # not authority: even a correctly re-tagged reduced roster fails
            # against the RECORD bytes held by the retained descriptor.
            SNAPSHOT._PYTHON_DISTRIBUTION_CLOSURE_CACHE["protobuf"] = (
                forged,
                SNAPSHOT._python_distribution_closure_cache_tag(forged),
            )
            try:
                with self.assertRaisesRegex(
                    SNAPSHOT.SnapshotInputError,
                    "RECORD denominator",
                ):
                    self._capture(project)
            finally:
                SNAPSHOT._PYTHON_DISTRIBUTION_CLOSURE_CACHE["protobuf"] = original

    def test_hot_replay_rejects_same_cardinality_ghost_and_named_stream(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(prefix="snapshot-protobuf-") as raw:
            project = Path(raw)
            self._capture(project)
            original = SNAPSHOT._PYTHON_DISTRIBUTION_CLOSURE_CACHE["protobuf"]
            forged = copy.deepcopy(original[0])
            victim = next(
                row
                for row in forged["rows"]
                if not row["record_member"] and not row["module_member"]
            )
            victim["path"] = str(project / "external-ghost.py")
            self._refold(forged)
            SNAPSHOT._PYTHON_DISTRIBUTION_CLOSURE_CACHE["protobuf"] = (
                forged,
                SNAPSHOT._python_distribution_closure_cache_tag(forged),
            )
            try:
                with self.assertRaisesRegex(
                    SNAPSHOT.SnapshotInputError,
                    "retargeted",
                ):
                    self._capture(project)
            finally:
                SNAPSHOT._PYTHON_DISTRIBUTION_CLOSURE_CACHE["protobuf"] = original

            fixture = project / "stream-fixture.py"
            fixture.write_bytes(b"safe default stream")
            named = Path(str(fixture) + ":attacker")
            try:
                named.write_bytes(b"hidden mutation")
            except OSError as exc:
                self.skipTest(f"fixture volume has no named streams: {exc}")
            try:
                with self.assertRaisesRegex(
                    SNAPSHOT.SnapshotInputError,
                    "alternate data stream",
                ):
                    SNAPSHOT._assert_windows_default_stream_only(
                        fixture,
                        label="protobuf ADS fixture",
                    )
            finally:
                try:
                    named.unlink()
                except OSError:
                    pass


if __name__ == "__main__":
    unittest.main()
