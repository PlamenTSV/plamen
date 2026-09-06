"""Focused regressions for externally hardlinked Python provider files."""
from __future__ import annotations

import importlib.util
from importlib import metadata
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import py_compile
import shutil
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock

import audit_snapshot as SNAPSHOT


@unittest.skipUnless(os.name == "nt", "Windows hardlink semantics")
class ExternalProviderHardlinkTests(unittest.TestCase):
    def test_runtime_tool_accepts_only_retained_external_alias_set(self) -> None:
        with tempfile.TemporaryDirectory(prefix="snapshot-runtime-hardlink-") as raw:
            root = Path(raw)
            project = root / "target"
            executable = root / "runtime-a" / "solc.exe"
            alias = root / "runtime-b" / "solc.exe"
            project.mkdir()
            executable.parent.mkdir()
            alias.parent.mkdir()
            payload = b"reviewed runtime tool bytes"
            executable.write_bytes(payload)
            os.link(executable, alias)
            # The denial handle deliberately lives for the snapshot process
            # lifetime.  Exercise that production boundary in a child so the
            # fixture can be removed only after the authority has exited.
            script = f"""
import json
import sys
from pathlib import Path
from unittest import mock
sys.path.insert(0, {str(Path(SNAPSHOT.__file__).resolve().parent)!r})
import audit_snapshot as snapshot
executable = Path({str(executable)!r})
project = Path({str(project)!r})
with mock.patch.object(snapshot.shutil, 'which', return_value=str(executable)), mock.patch.object(
    snapshot, '_semantic_probe_output', return_value='rc=0\\nsolc fixture'
):
    observed = json.loads(snapshot._runtime_tool_fingerprint(
        ('solc', '--version'), project_root=project
    ))
print('RUNTIME_FINGERPRINT=' + json.dumps(observed, sort_keys=True))
"""
            run = subprocess.run(
                [sys.executable, "-B", "-Werror", "-c", script],
                capture_output=True,
                text=True,
                timeout=30,
            )
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
            marker = next(
                line for line in run.stdout.splitlines()
                if line.startswith("RUNTIME_FINGERPRINT=")
            )
            observed = json.loads(marker.partition("=")[2])
            self.assertEqual(
                observed["executable_sha256"],
                hashlib.sha256(payload).hexdigest(),
            )

    def test_default_cross_directory_alias_remains_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="snapshot-hardlink-") as raw:
            root = Path(raw)
            project = root / "target"
            first = root / "runtime-a" / "provider.py"
            alias = root / "runtime-b" / "provider.py"
            project.mkdir()
            first.parent.mkdir()
            alias.parent.mkdir()
            first.write_bytes(b"reviewed provider bytes")
            os.link(first, alias)
            with self.assertRaisesRegex(
                SNAPSHOT.SnapshotInputError,
                "hardlink alias",
            ):
                SNAPSHOT._reject_unexpected_hardlinks(
                    first,
                    "runtime tool fixture",
                    project_root=project,
                )

    def test_retained_external_alias_denies_post_snapshot_mutation(self) -> None:
        with tempfile.TemporaryDirectory(prefix="snapshot-hardlink-") as raw:
            root = Path(raw)
            project = root / "target"
            first = root / "runtime-a" / "provider.py"
            alias = root / "runtime-b" / "provider.py"
            project.mkdir()
            first.parent.mkdir()
            alias.parent.mkdir()
            first.write_bytes(b"reviewed provider bytes")
            os.link(first, alias)
            script = f"""
import sys
from pathlib import Path
sys.path.insert(0, {str(Path(SNAPSHOT.__file__).resolve().parent)!r})
import audit_snapshot as snapshot
first = Path({str(first)!r})
alias = Path({str(alias)!r})
project = Path({str(project)!r})
snapshot._reject_unexpected_hardlinks(
    first,
    'Python provider module fixture',
    project_root=project,
    retain_fully_enumerated_external_aliases=True,
)
try:
    alias.write_bytes(b'attacker replacement')
except OSError:
    print('POST_SNAPSHOT_ALIAS_MUTATION_DENIED')
else:
    raise AssertionError('retained denial handle allowed alias mutation')
"""
            run = subprocess.run(
                [sys.executable, "-B", "-Werror", "-c", script],
                capture_output=True,
                text=True,
                timeout=30,
            )
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
            self.assertIn("POST_SNAPSHOT_ALIAS_MUTATION_DENIED", run.stdout)
            self.assertEqual(first.read_bytes(), b"reviewed provider bytes")

    def test_retained_approval_fast_path_rejects_alias_and_identity_drift(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(prefix="snapshot-hardlink-cache-") as raw:
            root = Path(raw)
            script = f"""
import os
import sys
from pathlib import Path
from unittest import mock
sys.path.insert(0, {str(Path(SNAPSHOT.__file__).resolve().parent)!r})
import audit_snapshot as snapshot
root = Path({str(root)!r})
project = root / 'target'
first = root / 'runtime-a' / 'provider.py'
alias = root / 'runtime-b' / 'provider.py'
extra = root / 'runtime-c' / 'provider.py'
other = root / 'other' / 'provider.py'
for directory in (project, first.parent, alias.parent, extra.parent, other.parent):
    directory.mkdir(parents=True, exist_ok=True)
first.write_bytes(b'reviewed provider bytes')
os.link(first, alias)
other.write_bytes(b'other bytes')
snapshot._reject_unexpected_hardlinks(
    first,
    'Python provider module fixture',
    project_root=project,
    retain_fully_enumerated_external_aliases=True,
    retained_authority_root=root,
)
with mock.patch.object(
    snapshot,
    '_windows_hardlink_aliases',
    side_effect=AssertionError('fast path re-enumerated aliases'),
):
    snapshot._reject_unexpected_hardlinks(
        first,
        'Python provider module fixture',
        project_root=project,
        retain_fully_enumerated_external_aliases=True,
        retained_authority_root=root,
    )
os.link(first, extra)
try:
    snapshot._reject_unexpected_hardlinks(
        first,
        'Python provider module fixture',
        project_root=project,
        retain_fully_enumerated_external_aliases=True,
        retained_authority_root=root,
    )
except snapshot.SnapshotInputError as exc:
    if 'approval drifted' not in str(exc):
        raise
else:
    raise AssertionError('retained approval reused after alias addition')
first = root / 'runtime-d' / 'provider.py'
alias = root / 'runtime-e' / 'provider.py'
first.parent.mkdir(); alias.parent.mkdir()
first.write_bytes(b'second reviewed provider bytes')
os.link(first, alias)
snapshot._reject_unexpected_hardlinks(
    first,
    'Python provider module fixture',
    project_root=project,
    retain_fully_enumerated_external_aliases=True,
    retained_authority_root=root,
)
identity = (int(first.stat().st_dev), int(first.stat().st_ino))
other_identity, _ = snapshot._retain_windows_hardlink_write_denial(other)
snapshot._RETAINED_HARDLINK_DENIAL_FDS[identity] = (
    snapshot._RETAINED_HARDLINK_DENIAL_FDS[other_identity]
)
try:
    snapshot._reject_unexpected_hardlinks(
        first,
        'Python provider module fixture',
        project_root=project,
        retain_fully_enumerated_external_aliases=True,
        retained_authority_root=root,
    )
except snapshot.SnapshotInputError as exc:
    if 'approval drifted' not in str(exc):
        raise
else:
    raise AssertionError('retained approval reused after handle identity drift')
first = root / 'runtime-f' / 'provider.py'
alias = root / 'runtime-g' / 'provider.py'
first.parent.mkdir(); alias.parent.mkdir()
first.write_bytes(b'third reviewed provider bytes')
os.link(first, alias)
snapshot._reject_unexpected_hardlinks(
    first,
    'Python provider module fixture',
    project_root=project,
    retain_fully_enumerated_external_aliases=True,
    retained_authority_root=root,
)
identity = (int(first.stat().st_dev), int(first.stat().st_ino))
descriptor = snapshot._RETAINED_HARDLINK_DENIAL_FDS.pop(identity)
os.close(descriptor)
alias.unlink()
if first.stat().st_nlink != 1:
    raise AssertionError('fixture did not reach singleton drift state')
try:
    snapshot._reject_unexpected_hardlinks(
        first,
        'Python provider module fixture',
        project_root=project,
        retain_fully_enumerated_external_aliases=True,
        retained_authority_root=root,
    )
except snapshot.SnapshotInputError as exc:
    if 'denial handle is missing' not in str(exc):
        raise
else:
    raise AssertionError('singleton drift bypassed retained approval checks')
print('FAST_REUSE_AND_DRIFT_REJECTION_OK')
"""
            run = subprocess.run(
                [sys.executable, "-B", "-Werror", "-c", script],
                capture_output=True,
                text=True,
                timeout=30,
            )
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
            self.assertIn("FAST_REUSE_AND_DRIFT_REJECTION_OK", run.stdout)

    def test_opted_in_alias_inside_target_remains_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="snapshot-hardlink-") as raw:
            root = Path(raw)
            project = root / "target"
            first = root / "runtime" / "provider.py"
            alias = project / "provider-alias.py"
            project.mkdir()
            first.parent.mkdir()
            first.write_bytes(b"reviewed provider bytes")
            os.link(first, alias)
            with self.assertRaisesRegex(
                SNAPSHOT.SnapshotInputError,
                "hardlink alias",
            ):
                SNAPSHOT._reject_unexpected_hardlinks(
                    first,
                    "Python provider module fixture",
                    project_root=project,
                    retain_fully_enumerated_external_aliases=True,
                )

    def test_opted_in_incomplete_alias_enumeration_remains_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="snapshot-hardlink-") as raw:
            root = Path(raw)
            project = root / "target"
            first = root / "runtime-a" / "provider.py"
            alias = root / "runtime-b" / "provider.py"
            project.mkdir()
            first.parent.mkdir()
            alias.parent.mkdir()
            first.write_bytes(b"reviewed provider bytes")
            os.link(first, alias)
            with mock.patch.object(
                SNAPSHOT,
                "_windows_hardlink_aliases",
                return_value=(first,),
            ):
                with self.assertRaisesRegex(
                    SNAPSHOT.SnapshotInputError,
                    "hardlink alias",
                ):
                    SNAPSHOT._reject_unexpected_hardlinks(
                        first,
                        "Python provider module fixture",
                        project_root=project,
                        retain_fully_enumerated_external_aliases=True,
                    )

    def test_live_slither_distribution_external_alias_closure_is_bound(self) -> None:
        spec = importlib.util.find_spec("slither")
        if spec is None or not spec.origin:
            self.skipTest("slither is not installed")
        module = Path(spec.origin).resolve(strict=True)
        if module.stat().st_nlink <= 1:
            self.skipTest("installed slither module has no hardlink alias")
        with tempfile.TemporaryDirectory(prefix="snapshot-target-") as raw:
            project = Path(raw)
            closure = SNAPSHOT._python_distribution_closure(
                "slither-analyzer",
                "slither",
                project_root=project,
            )
            with mock.patch(
                "importlib.metadata.distributions",
                side_effect=AssertionError(
                    "retained closure replay re-enumerated distribution metadata"
                ),
            ), mock.patch.object(
                SNAPSHOT,
                "_assert_no_lexical_links",
                wraps=SNAPSHOT._assert_no_lexical_links,
            ) as lexical:
                replayed = SNAPSHOT._python_distribution_closure(
                    "slither-analyzer",
                    "slither",
                    project_root=project,
                )
            self.assertEqual(replayed, closure)
            self.assertEqual(lexical.call_count, 1)
            authority = SNAPSHOT.capture_python_provider_authority(
                "slither",
                project_root=project,
            )
        self.assertEqual(closure["module_origin"], str(module))
        self.assertEqual(len(closure["module_sha256"]), 64)
        self.assertGreater(closure["distribution_file_count"], 0)
        slither_dist = next(
            dist
            for dist in metadata.distributions()
            if str(dist.metadata.get("Name") or "").casefold()
            == "slither-analyzer"
        )
        expected_record_count = len(tuple(slither_dist.files or ()))
        self.assertEqual(closure["record_row_count"], expected_record_count)
        self.assertEqual(
            closure["record_member_file_count"], expected_record_count
        )
        self.assertEqual(
            closure["record_member_native_identity_count"],
            expected_record_count,
        )
        # Complete physical leasing is necessary for stable observation, but
        # it cannot manufacture reviewed content authority for Slither's still
        # unbound crytic-compile/transitive closure.
        self.assertEqual(
            authority["authority_status"],
            "OBSERVED_NONAUTHORITATIVE",
        )
        self.assertIs(
            authority["deterministic_provider_authority"],
            False,
        )
        self.assertEqual(
            authority["record_member_file_count"],
            expected_record_count,
        )
        self.assertEqual(
            authority["record_member_native_identity_count"],
            expected_record_count,
        )
        alternate = next(
            alias
            for alias in SNAPSHOT._windows_hardlink_aliases(module)
            if os.path.normcase(str(alias)) != os.path.normcase(str(module))
        )
        with self.assertRaises(OSError):
            with alternate.open("r+b"):
                pass

        pyc = next(
            Path(slither_dist.locate_file(relative)).resolve(strict=True)
            for relative in slither_dist.files or ()
            if str(relative).replace("\\", "/").endswith(".pyc")
            and Path(slither_dist.locate_file(relative)).stat().st_nlink > 1
        )
        pyc_alternate = next(
            alias
            for alias in SNAPSHOT._windows_hardlink_aliases(pyc)
            if os.path.normcase(str(alias)) != os.path.normcase(str(pyc))
        )
        with self.assertRaises(OSError):
            with pyc_alternate.open("r+b"):
                pass

        # The module-local cache key is intentionally treated as reachable,
        # not as authority.  Even an attacker who recomputes a valid cache tag
        # cannot omit one retained row from the live RECORD denominator.
        cache_key = "slither-analyzer"
        project.mkdir(parents=True, exist_ok=True)
        original_cache = SNAPSHOT._PYTHON_DISTRIBUTION_CLOSURE_CACHE[cache_key]
        forged_payload = copy.deepcopy(original_cache[0])
        victim = next(
            row
            for row in forged_payload["rows"]
            if not row["record_member"] and not row["module_member"]
        )
        forged_payload["rows"].remove(victim)
        physical_fold = hashlib.sha256()
        for row in forged_payload["rows"]:
            physical_fold.update(SNAPSHOT._canonical_json({
                "device": int(row["device"]),
                "file_id": int(row["file_id"]),
                "link_count": int(row["link_count"]),
                "path": str(row["path"]),
                "relative_name": str(row["relative_name"]),
                "size": int(row["size"]),
            }))
        forged_payload["physical_fold_sha256"] = physical_fold.hexdigest()
        SNAPSHOT._PYTHON_DISTRIBUTION_CLOSURE_CACHE[cache_key] = (
            forged_payload,
            SNAPSHOT._python_distribution_closure_cache_tag(forged_payload),
        )
        try:
            with self.assertRaisesRegex(
                SNAPSHOT.SnapshotInputError,
                "RECORD denominator",
            ):
                SNAPSHOT._python_distribution_closure(
                    "slither-analyzer", "slither", project_root=project
                )
        finally:
            SNAPSHOT._PYTHON_DISTRIBUTION_CLOSURE_CACHE[cache_key] = (
                original_cache
            )

        # Removing the native denial descriptor is independently fatal even
        # when the authenticated roster itself is untouched.
        victim_identity = (int(victim["device"]), int(victim["file_id"]))
        victim_descriptor = SNAPSHOT._RETAINED_HARDLINK_DENIAL_FDS.pop(
            victim_identity
        )
        try:
            with self.assertRaisesRegex(
                SNAPSHOT.SnapshotInputError,
                "denial handle is missing",
            ):
                SNAPSHOT._python_distribution_closure(
                    "slither-analyzer", "slither", project_root=project
                )
        finally:
            SNAPSHOT._RETAINED_HARDLINK_DENIAL_FDS[victim_identity] = (
                victim_descriptor
            )
            shutil.rmtree(project.parent, ignore_errors=True)

    def test_timestamp_valid_pyc_alias_cannot_replace_loaded_code(self) -> None:
        with tempfile.TemporaryDirectory(prefix="snapshot-pyc-record-") as raw:
            root = Path(raw)
            project = root / "project"
            install = root / "runtime-a" / "Lib" / "site-packages"
            package = install / "fixture_pkg"
            cache = package / "__pycache__"
            dist_info = install / "fixture_dist-1.0.dist-info"
            alias_root = root / "runtime-b"
            project.mkdir()
            cache.mkdir(parents=True)
            dist_info.mkdir()
            alias_root.mkdir()

            source = package / "__init__.py"
            source.write_text("VALUE = 'SAFE'\n", encoding="utf-8")
            fixed_ns = 1_700_000_000_000_000_000
            os.utime(source, ns=(fixed_ns, fixed_ns))
            pyc = cache / (
                "__init__." + sys.implementation.cache_tag + ".pyc"
            )
            py_compile.compile(
                str(source),
                cfile=str(pyc),
                doraise=True,
                invalidation_mode=py_compile.PycInvalidationMode.TIMESTAMP,
            )
            safe_pyc = pyc.read_bytes()

            source.write_text("VALUE = 'EVIL'\n", encoding="utf-8")
            os.utime(source, ns=(fixed_ns, fixed_ns))
            evil_pyc_path = root / "evil.pyc"
            py_compile.compile(
                str(source),
                cfile=str(evil_pyc_path),
                doraise=True,
                invalidation_mode=py_compile.PycInvalidationMode.TIMESTAMP,
            )
            evil_pyc = evil_pyc_path.read_bytes()
            self.assertEqual(safe_pyc[:16], evil_pyc[:16])
            source.write_text("VALUE = 'SAFE'\n", encoding="utf-8")
            os.utime(source, ns=(fixed_ns, fixed_ns))
            pyc.write_bytes(safe_pyc)
            evil_pyc_path.unlink()

            pyc_alias = alias_root / pyc.name
            os.link(pyc, pyc_alias)

            def record_hash(path: Path) -> str:
                encoded = base64.urlsafe_b64encode(
                    hashlib.sha256(path.read_bytes()).digest()
                ).decode("ascii").rstrip("=")
                return "sha256=" + encoded

            source_name = "fixture_pkg/__init__.py"
            pyc_name = (
                "fixture_pkg/__pycache__/" + pyc.name
            )
            record_name = "fixture_dist-1.0.dist-info/RECORD"
            record = dist_info / "RECORD"
            record.write_text(
                f"{source_name},{record_hash(source)},{source.stat().st_size}\n"
                f"{pyc_name},,\n"
                f"{record_name},,\n",
                encoding="utf-8",
            )

            class FixtureDistribution:
                metadata = {"Name": "fixture-dist"}
                files = (Path(source_name), Path(pyc_name), Path(record_name))

                @staticmethod
                def locate_file(relative: object) -> Path:
                    return install / Path(str(relative))

            before = set(SNAPSHOT._RETAINED_HARDLINK_DENIAL_FDS)
            try:
                with mock.patch(
                    "importlib.metadata.distributions",
                    return_value=[FixtureDistribution()],
                ), mock.patch(
                    "importlib.util.find_spec",
                    return_value=types.SimpleNamespace(origin=str(source)),
                ):
                    closure = SNAPSHOT._python_distribution_closure(
                        "fixture-dist",
                        "fixture_pkg",
                        project_root=project,
                    )
                self.assertEqual(closure["record_row_count"], 3)
                self.assertEqual(closure["record_member_file_count"], 3)
                self.assertEqual(
                    closure["record_member_native_identity_count"], 3
                )
                with self.assertRaises(OSError):
                    pyc_alias.write_bytes(evil_pyc)

                module_name = "_snapshot_safe_pyc_fixture"
                loaded_spec = importlib.util.spec_from_file_location(
                    module_name, source
                )
                self.assertIsNotNone(loaded_spec)
                assert loaded_spec is not None and loaded_spec.loader is not None
                loaded = importlib.util.module_from_spec(loaded_spec)
                loaded_spec.loader.exec_module(loaded)
                self.assertEqual(loaded.VALUE, "SAFE")
            finally:
                created = (
                    set(SNAPSHOT._RETAINED_HARDLINK_DENIAL_FDS) - before
                )
                for identity in created:
                    descriptor = SNAPSHOT._RETAINED_HARDLINK_DENIAL_FDS.pop(
                        identity
                    )
                    os.close(descriptor)


if __name__ == "__main__":
    unittest.main(verbosity=2)
