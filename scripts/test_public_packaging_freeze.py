"""Clean-archive and private-content contracts for the public distribution.

The repository is the distribution package: there is no independent Python
wheel/sdist manifest.  These tests assemble the intended public tree through a
temporary Git index, archive that tree, and exercise the extracted result.  The
real index is read-only throughout, so the fixture is safe in a dirty
multi-worker checkout before the human-controlled cutover.
"""
from __future__ import annotations

import ast
from functools import lru_cache
import hashlib
import os
from pathlib import Path, PurePosixPath
import subprocess
import sys
import tarfile

import toolchain_control_authority as TOOLCHAIN_CONTROL


REPO_ROOT = Path(__file__).resolve().parents[1]

_INDEX_ONLY_REMOVALS = (
    ".plamen-manifest.json",
    "review_fixtures",
    "write_dedup.py",
)
_FORBIDDEN_ARCHIVE_PREFIXES = (
    ".canary",
    ".pytest",
    ".claude-l1-backup/",
    ".l1_backup_",
    ".scratchpad/",
    ".tmp",
    "Temp/",
    "backups/",
    "bpa_",
    "bpc_",
    "cache/",
    "custom-mcp/defihacklabs-rag/data/",
    "custom-mcp/solodit-scraper/data/",
    "custom-mcp/unified-vuln-db/data/",
    "downloads/",
    "diag-",
    "file-history/",
    "local/",
    "memory/",
    "paste-cache/",
    "pipeline_audit_",
    "plans/",
    "plugins/",
    "projects/",
    "review_fixtures/",
    "scripts/bounty/",
    "scripts/bounty_targets/",
    "immunefi_cache/",
    "sessions/",
    "shell-snapshots/",
    "tasks/",
    "telemetry/",
    "todos/",
    "target",
)
_FORBIDDEN_ARCHIVE_PATHS = {
    ".plamen-manifest.json",
    "codex-adapter/config.toml",
    "mcp.json",
    "integration",
    "production",
    "settings.json",
    "scripts/test_impact_map_injection.py",
    "scripts/claude_test_launch_authority.py",
    "write_dedup.py",
}
_PUBLIC_UNTRACKED_ROOTS = {
    "agents",
    "architecture",
    "benchmarks",
    "codex-adapter",
    "commands",
    "docs",
    "methodology",
    "plamen_l1",
    "prompts",
    "rules",
    "scripts",
    "verification_policy",
}
_PUBLIC_UNTRACKED_FILES = {
    ".github/dependabot.yml",
    "requirements-ci.constraints",
    "requirements-ci.lock",
    "requirements-ci-resolver.in",
    "requirements-ci-resolver.lock",
}
_REQUIRED_POLICY_FILES = {
    "verification_policy/ci_advisory_evidence.v1.json",
    "verification_policy/ci_dependency_authority.v1.json",
    "verification_policy/ci_dependency_provenance.v2.json",
    "verification_policy/ci_dependency_provenance.v2.schema.json",
    "verification_policy/ci_release_metadata_evidence.v1.json",
    "verification_policy/__init__.py",
    "verification_policy/methodology_reachability.v1.json",
    "verification_policy/toolchain_runtime_closure.v1.json",
    "verification_policy/toolchain_governance.v1.json",
    "verification_policy/toolchain_version_lock.v1.json",
    "verification_policy/verification_method_registry.v1.json",
}
_REQUIRED_LIVE_ASSETS = {
    "architecture/ecosystem-graph-provider-contract.md",
    "architecture/finding-ledger-migration.md",
    "architecture/method-application-rfc.md",
    "architecture/premise-and-disposition-policy.md",
    "architecture/work-unit-scheduler.md",
    "benchmarks/application-coverage-evaluation-plan.md",
    "docs/asset-representation-foundation.md",
    "docs/design/negative-closure-authority.md",
    "docs/terminal-legacy-claude-audits.md",
    "prompts/shared/v2/phase4b7-application-skeptic.md",
    "prompts/shared/v2/phase5-severity-adjudication-shadow.md",
    "prompts/shared/v2/phase6b0-report-evidence-repair.md",
    "methodology/method-cards-v1.yaml",
    "rules/precedent-evidence-policy.md",
}
_REQUIRED_PUBLIC_SCRIPT_RULES = {
    "!scripts/bootstrap_macos_dev.sh",
    "!scripts/attention_repair_shards.py",
    "!scripts/auxiliary_writable_root_lease.py",
    "!scripts/auxiliary_writable_root_startup.py",
    "!scripts/axis_promotion_lineage.py",
    "!scripts/bb_verification_policy.py",
    "!scripts/chain_candidate_inventory_union.py",
    "!scripts/chain_pair_auto_map_transaction.py",
    "!scripts/claude_attempt_profile.py",
    "!scripts/claude_auth_route.py",
    "!scripts/claude_child_environment.py",
    "!scripts/claude_executable_observation.py",
    "!scripts/claude_headless_profile.py",
    "!scripts/claude_launch_security.py",
    "!scripts/claude_runtime_materialization.py",
    "!scripts/claude_stored_subscription_source.py",
    "!scripts/claude_stream_json_evidence.py",
    "!scripts/ci_dependency_authority.py",
    "!scripts/codex_dependency_research.py",
    "!scripts/depth_handoff.py",
    "!scripts/headless_worker_runtime.py",
    "!scripts/linux_cgroup_exec.py",
    "!scripts/owned_process_scope.py",
    "!scripts/plamen_mcp_runtime.py",
    "!scripts/preverify_frozen_projection.py",
    "!scripts/preverify_projection_authority.py",
    "!scripts/provider_command_authority.py",
    "!scripts/pty_completion_codec.py",
    "!scripts/pty_completion_observer.py",
    "!scripts/pty_transport_bridge.py",
    "!scripts/pty_worker_host.py",
    "!scripts/pty_worker_protocol.py",
    "!scripts/pty_worker_provider.py",
    "!scripts/recovery_execution_authority.py",
    "!scripts/refresh_ci_dependency_evidence.py",
    "!scripts/report_index_canonical_validator.py",
    "!scripts/windows_low_integrity_lease.py",
    "!scripts/worker_transaction.py",
    "!scripts/bb_wrapper_provider_adapter.py",
    "!scripts/claude_provider_policy.py",
}
_PRIVATE_TEXT_MARKERS = (
    b"C:\\\\Users\\\\" + b"plmnt",
    b"D:/Programming/Web3/" + b"Private",
)
_TEXT_SUFFIXES = {
    ".bat",
    ".json",
    ".md",
    ".py",
    ".sh",
    ".toml",
    ".txt",
    ".yaml",
    ".yml",
}


def _git(
    *args: str,
    env: dict[str, str] | None = None,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        ["git", *args],
        cwd=REPO_ROOT,
        env=env,
        check=False,
        capture_output=True,
        text=True,
    )
    if check and result.returncode != 0:
        raise AssertionError(
            f"git {' '.join(args)} failed ({result.returncode}): "
            f"{result.stderr.strip()}"
        )
    return result


def _real_index_digest() -> str:
    # Hash the semantic index (mode/object/path), not the raw index file. Git
    # may legitimately refresh only cached filesystem metadata after a freshly
    # initialized submodule or worktree; those byte changes do not stage or
    # unstage content and made this preservation assertion flaky.
    result = _git("ls-files", "--stage", "-z")
    return hashlib.sha256(
        result.stdout.encode("utf-8", errors="surrogateescape")
    ).hexdigest()


def _lines(result: subprocess.CompletedProcess[str]) -> set[str]:
    return {line.strip().replace("\\", "/") for line in result.stdout.splitlines() if line.strip()}


def _git_ignored_paths(paths: set[str] | list[str] | tuple[str, ...]) -> set[str]:
    """Return Git's exact effective ignore result, including late negations."""

    normalized = sorted(
        {
            PurePosixPath(path).as_posix().removeprefix("./")
            for path in paths
            if path
        }
    )
    if not normalized:
        return set()
    if any("\x00" in path for path in normalized):
        raise AssertionError("packaging path contains NUL")
    result = subprocess.run(
        ["git", "check-ignore", "--no-index", "-z", "--stdin"],
        cwd=REPO_ROOT,
        input=b"".join(
            path.encode("utf-8", errors="surrogateescape") + b"\x00"
            for path in normalized
        ),
        check=False,
        capture_output=True,
    )
    if result.returncode not in {0, 1}:
        raise AssertionError(
            "git check-ignore failed "
            f"({result.returncode}): "
            f"{result.stderr.decode('utf-8', errors='replace').strip()}"
        )
    return {
        item.decode("utf-8", errors="surrogateescape")
        for item in result.stdout.split(b"\x00")
        if item
    }


def _structurally_forbidden(path: str) -> bool:
    normalized = PurePosixPath(path).as_posix()
    while normalized.startswith("./"):
        normalized = normalized[2:]
    if normalized in _FORBIDDEN_ARCHIVE_PATHS:
        return True
    return any(
        normalized.startswith(prefix) or f"/{prefix}" in normalized
        for prefix in _FORBIDDEN_ARCHIVE_PREFIXES
    )


@lru_cache(maxsize=None)
def _is_forbidden(path: str) -> bool:
    normalized = PurePosixPath(path).as_posix()
    while normalized.startswith("./"):
        normalized = normalized[2:]
    return _structurally_forbidden(normalized) or normalized in (
        _git_ignored_paths((normalized,))
    )


def _public_worktree_paths() -> list[str]:
    changed = _lines(
        _git("diff", "--name-only", "--diff-filter=ACMR", "HEAD", "--")
    )
    changed |= _lines(
        _git("diff", "--cached", "--name-only", "--diff-filter=ACMR", "--")
    )
    untracked = _lines(_git("ls-files", "--others", "--exclude-standard", "--"))

    ignored = _git_ignored_paths(changed | untracked)
    selected = {
        path
        for path in changed
        if (
            (REPO_ROOT / path).is_file()
            and path not in ignored
            and not _structurally_forbidden(path)
        )
    }
    for path in untracked:
        candidate = REPO_ROOT / path
        if (
            candidate.is_file()
            and PurePosixPath(path).parts
            and (
                path in _PUBLIC_UNTRACKED_FILES
                or PurePosixPath(path).parts[0]
                in _PUBLIC_UNTRACKED_ROOTS
            )
            and path not in ignored
            and not _structurally_forbidden(path)
        ):
            selected.add(path)
    # The digest-bound reachable-runtime projection is the package authority.
    # A typed top-level asset does not need a second filename allowlist, while
    # ignored/private assets fail rather than being force-added.
    for path in TOOLCHAIN_CONTROL.TOOLCHAIN_RUNTIME_REQUIRED_FILES:
        candidate = REPO_ROOT / path
        if not candidate.is_file():
            raise AssertionError(
                f"typed runtime asset is absent from source: {path}"
            )
        if _is_forbidden(path):
            raise AssertionError(
                f"typed runtime asset is ignored/private: {path}"
            )
        selected.add(path)
    return sorted(selected)


def _temporary_index_paths(env: dict[str, str]) -> list[str]:
    result = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=REPO_ROOT,
        env=env,
        check=False,
        capture_output=True,
    )
    if result.returncode != 0:
        raise AssertionError(
            "git ls-files failed for temporary package index: "
            + result.stderr.decode("utf-8", errors="replace").strip()
        )
    return [
        item.decode("utf-8", errors="surrogateescape")
        for item in result.stdout.split(b"\x00")
        if item
    ]


def _prune_forbidden_index(env: dict[str, str]) -> set[str]:
    """Remove every ignored/private path from an isolated package index."""

    paths = _temporary_index_paths(env)
    forbidden = sorted(
        _git_ignored_paths(paths)
        | {path for path in paths if _structurally_forbidden(path)}
    )
    for offset in range(0, len(forbidden), 64):
        _git(
            "rm",
            "-q",
            "-f",
            "--cached",
            "--ignore-unmatch",
            "--",
            *forbidden[offset : offset + 64],
            env=env,
        )
    return set(forbidden)


def _temporary_public_archive(tmp_path: Path) -> Path:
    """Build an intended-public archive without touching the real Git index."""
    real_index_before = _real_index_digest()
    temp_index = tmp_path / "public.index"
    env = os.environ.copy()
    env["GIT_INDEX_FILE"] = str(temp_index)

    _git("read-tree", "HEAD", env=env)
    _git(
        "rm",
        "-r",
        "--cached",
        "--ignore-unmatch",
        "--",
        *_INDEX_ONLY_REMOVALS,
        env=env,
    )
    _prune_forbidden_index(env)

    paths = _public_worktree_paths()
    for offset in range(0, len(paths), 64):
        _git("add", "--", *paths[offset : offset + 64], env=env)
    runtime_paths = list(
        TOOLCHAIN_CONTROL.TOOLCHAIN_RUNTIME_REQUIRED_FILES
    )
    for path in runtime_paths:
        if _is_forbidden(path):
            raise AssertionError(
                f"typed runtime asset cannot enter public archive: {path}"
            )
    for offset in range(0, len(runtime_paths), 64):
        _git(
            "add",
            "-f",
            "--",
            *runtime_paths[offset : offset + 64],
            env=env,
        )
    indexed = set(_temporary_index_paths(env))
    missing_runtime = set(runtime_paths) - indexed
    if missing_runtime:
        raise AssertionError(
            "temporary package index omitted typed runtime assets: "
            f"{sorted(missing_runtime)}"
        )

    tree = _git("write-tree", env=env).stdout.strip()
    archive = tmp_path / "plamen-public.tar"
    _git(
        "archive",
        "--format=tar",
        f"--output={archive}",
        tree,
        env=env,
    )
    with tarfile.open(archive, "r") as package:
        members = {
            PurePosixPath(member.name).as_posix().rstrip("/"): member
            for member in package.getmembers()
            if member.isfile()
        }
        if set(runtime_paths) - set(members):
            raise AssertionError(
                "public archive omitted typed runtime assets: "
                f"{sorted(set(runtime_paths) - set(members))}"
            )
        expected_digests = {
            row["path"]: (row["digest_mode"], row["sha256"])
            for row in TOOLCHAIN_CONTROL.TOOLCHAIN_RUNTIME_ASSET_ROWS
        }
        for path, (digest_mode, expected) in expected_digests.items():
            stream = package.extractfile(members[path])
            if stream is None:
                raise AssertionError(
                    f"public archive typed asset unreadable: {path}"
                )
            raw = stream.read()
            canonical = (
                raw.decode("utf-8")
                .replace("\r\n", "\n")
                .encode("utf-8")
                if digest_mode == "utf8-lf-v1"
                else raw
            )
            observed = hashlib.sha256(canonical).hexdigest()
            if observed != expected:
                raise AssertionError(
                    f"public archive typed asset digest mismatch: {path}"
                )
    assert _real_index_digest() == real_index_before, (
        "temporary packaging fixture mutated the real Git index"
    )
    return archive


def _archive_members(archive: Path) -> set[str]:
    with tarfile.open(archive, "r") as package:
        return {
            PurePosixPath(member.name).as_posix().rstrip("/")
            for member in package.getmembers()
            if member.isfile()
        }


def test_intended_public_archive_has_complete_runtime_and_no_private_files(
    tmp_path: Path,
) -> None:
    archive = _temporary_public_archive(tmp_path)
    members = _archive_members(archive)

    assert ".plamen-manifest.json" not in members
    forbidden_root_members = sorted(
        path
        for path in members
        if path in {"integration", "production"}
        or path.startswith(
            (
                ".pytest",
                "Temp/",
                "bpa_",
                "bpc_",
                "diag-",
                "review_fixtures/",
                "target",
            )
        )
    )
    assert not forbidden_root_members, (
        "private/generated root entered public staged snapshot: "
        f"{forbidden_root_members}"
    )

    contract_roots = (
        REPO_ROOT / "architecture",
        REPO_ROOT / "benchmarks",
        REPO_ROOT / "methodology",
        REPO_ROOT / "rules" / "schemas",
    )
    current_contract_assets = {
        path.relative_to(REPO_ROOT).as_posix()
        for root in contract_roots
        if root.is_dir()
        for path in root.rglob("*")
        if path.is_file() and not _is_forbidden(
            path.relative_to(REPO_ROOT).as_posix()
        )
    }
    current_public_scripts = {
        path
        for path in _public_worktree_paths()
        if path.startswith("scripts/")
        and path.endswith(".py")
        and PurePosixPath(path).parent == PurePosixPath("scripts")
    }
    required = (
        current_public_scripts
        | current_contract_assets
        | _REQUIRED_POLICY_FILES
        | _REQUIRED_LIVE_ASSETS
        | _PUBLIC_UNTRACKED_FILES
        | {"scripts/bb_verification_policy.py"}
    )
    assert required <= members, (
        "intended clean archive is missing public runtime files: "
        f"{sorted(required - members)}"
    )

    forbidden = sorted(
        _git_ignored_paths(members)
        | {path for path in members if _structurally_forbidden(path)}
    )
    assert not forbidden, f"private/generated files entered public archive: {forbidden}"

    with tarfile.open(archive, "r") as package:
        for member in package.getmembers():
            path = PurePosixPath(member.name)
            if (
                not member.isfile()
                or path.suffix.lower() not in _TEXT_SUFFIXES
                or member.size > 2 * 1024 * 1024
            ):
                continue
            source = package.extractfile(member)
            assert source is not None
            data = source.read()
            leaked = [
                marker.decode("ascii")
                for marker in _PRIVATE_TEXT_MARKERS
                if marker in data
            ]
            assert not leaked, (
                f"private host/audit marker in public archive member "
                f"{member.name}: {leaked}"
            )


def test_claude_provider_policy_is_visible_in_a_fresh_public_archive(
    tmp_path: Path,
) -> None:
    """The public BB adapter's policy compiler must survive a fresh checkout."""

    assert subprocess.run(
        [
            "git",
            "check-ignore",
            "--no-index",
            "--quiet",
            "--",
            "scripts/claude_provider_policy.py",
        ],
        cwd=REPO_ROOT,
        check=False,
        capture_output=True,
        text=True,
    ).returncode == 1
    archive = _temporary_public_archive(tmp_path)
    members = _archive_members(archive)
    assert "scripts/claude_provider_policy.py" in members
    assert "scripts/bb_wrapper_provider_adapter.py" in members


def test_clean_archive_compiles_and_imports_runtime_from_itself(
    tmp_path: Path,
) -> None:
    archive = _temporary_public_archive(tmp_path)
    extracted = tmp_path / "extracted"
    extracted.mkdir()
    with tarfile.open(archive, "r") as package:
        package.extractall(extracted, filter="data")

    compile_result = subprocess.run(
        [
            sys.executable,
            "-I",
            "-m",
            "compileall",
            "-q",
            str(extracted / "scripts"),
            str(extracted / "verification_policy"),
        ],
        cwd=extracted,
        check=False,
        capture_output=True,
        text=True,
    )
    assert compile_result.returncode == 0, compile_result.stderr

    code = (
        "from pathlib import Path\n"
        "import sys\n"
        f"root = Path({str(extracted)!r}).resolve()\n"
        "sys.path[:0] = [str(root / 'scripts'), str(root)]\n"
        "import bb_wrapper_provider_adapter, claude_provider_policy\n"
        "import plamen_driver, plamen_validators, verification_policy\n"
        "for module in (bb_wrapper_provider_adapter, claude_provider_policy, "
        "plamen_driver, plamen_validators, verification_policy):\n"
        "    path = Path(module.__file__).resolve()\n"
        "    assert path == root or root in path.parents, (module.__name__, path)\n"
    )
    env = os.environ.copy()
    env.pop("PYTHONPATH", None)
    env["PYTHONNOUSERSITE"] = "1"
    imported = subprocess.run(
        [sys.executable, "-I", "-c", code],
        cwd=extracted,
        env=env,
        check=False,
        capture_output=True,
        text=True,
    )
    assert imported.returncode == 0, imported.stderr


def _positive_gitignore_rules() -> tuple[str, ...]:
    return tuple(
        line.strip()
        for line in (REPO_ROOT / ".gitignore").read_text(
            encoding="utf-8"
        ).splitlines()
        if line.strip()
        and not line.lstrip().startswith("#")
        and not line.lstrip().startswith("!")
    )


def _sentinel_for_ignore_rule(rule: str) -> str:
    value = rule.strip().replace("\\", "/")
    while value.startswith("/"):
        value = value[1:]
    value = value.replace("**/", "nested/")
    value = value.replace("**", "nested")
    value = value.replace("*", "private")
    if value.endswith("/"):
        value += "private-sentinel.txt"
    return PurePosixPath(value).as_posix()


def test_every_positive_gitignore_rule_is_in_package_forbidden_denominator() -> None:
    rules = _positive_gitignore_rules()
    sentinels = {
        _sentinel_for_ignore_rule(rule): rule
        for rule in rules
    }
    ignored = _git_ignored_paths(set(sentinels))
    missing = {
        path: rule
        for path, rule in sentinels.items()
        if path not in ignored or not _is_forbidden(path)
    }
    assert not missing, (
        "positive .gitignore rules escaped the public-package denominator: "
        f"{missing}"
    )


def test_isolated_index_prunes_force_tracked_ignored_sentinels(
    tmp_path: Path,
) -> None:
    real_index_before = _real_index_digest()
    temp_index = tmp_path / "private-sentinel.index"
    env = os.environ.copy()
    env["GIT_INDEX_FILE"] = str(temp_index)
    _git("read-tree", "--empty", env=env)
    blob = _git("rev-parse", "HEAD:README.md").stdout.strip()
    sentinels = sorted(
        {
            _sentinel_for_ignore_rule(rule)
            for rule in _positive_gitignore_rules()
        }
    )
    index_rows = b"".join(
        f"100644 {blob}\t{path}".encode(
            "utf-8", errors="surrogateescape"
        )
        + b"\x00"
        for path in sentinels
    )
    update = subprocess.run(
        ["git", "update-index", "-z", "--index-info"],
        cwd=REPO_ROOT,
        env=env,
        input=index_rows,
        check=False,
        capture_output=True,
    )
    assert update.returncode == 0, update.stderr.decode(
        "utf-8", errors="replace"
    )
    assert set(_temporary_index_paths(env)) == set(sentinels)
    pruned = _prune_forbidden_index(env)
    assert set(sentinels) <= pruned
    assert _temporary_index_paths(env) == []
    assert _real_index_digest() == real_index_before


def test_private_and_generated_paths_remain_explicitly_ignored() -> None:
    rules = set(
        (REPO_ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
    )
    required_rules = {
        "/.pytest*/",
        "/.canary*",
        "/.plamen-manifest.json",
        "/.tmp*",
        "/Temp/",
        "/review_fixtures/",
        "/bpa_*/",
        "/bpc_*/",
        "/diag-*/",
        "/integration",
        "/production",
        "/target*",
        "/write_dedup.py",
        "codex-adapter/config.toml",
        "scripts/bounty/",
        "scripts/bounty_targets/",
        "scripts/test_impact_map_injection.py",
        "**/immunefi_cache/",
        ".credentials.json",
        ".env.*",
        "mcp.json",
        "settings.json",
    }
    assert required_rules <= rules, (
        "private/generated ignore rules were removed: "
        f"{sorted(required_rules - rules)}"
    )
    assert _REQUIRED_PUBLIC_SCRIPT_RULES <= rules, (
        "required public runtime allowlist rules were removed: "
        f"{sorted(_REQUIRED_PUBLIC_SCRIPT_RULES - rules)}"
    )


def test_plamen_v3_pushes_run_platform_boundary_smoke() -> None:
    workflow = (REPO_ROOT / ".github" / "workflows" / "install-smoke.yml").read_text(
        encoding="utf-8"
    )
    push_block = workflow.partition("  push:\n")[2].partition("  pull_request:")[0]
    assert push_block, "install-smoke workflow has no push branch block"
    assert "      - Plamen-v3\n" in push_block, (
        "Plamen-v3 pushes must exercise the platform-boundary smoke workflow"
    )
    assert "os: [windows-latest]" in workflow
    assert "Linux source validation / production rejection" in workflow
    assert 'if [ "$STATUS" -ne 3 ]' in workflow
    front = (REPO_ROOT / "plamen.py").read_text(encoding="utf-8")
    assert "production installation is currently qualified" in front
    assert 'raise SystemExit(3)' in front


def test_production_scripts_cannot_import_test_only_claude_authority() -> None:
    offenders: list[str] = []
    for path in sorted((REPO_ROOT / "scripts").glob("*.py")):
        if path.name.startswith("test_") or path.name == (
            "claude_test_launch_authority.py"
        ):
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names = {alias.name for alias in node.names}
            elif isinstance(node, ast.ImportFrom):
                names = {node.module or ""}
            else:
                continue
            if "claude_test_launch_authority" in names:
                offenders.append(path.relative_to(REPO_ROOT).as_posix())
                break
    assert not offenders, (
        "production modules import test-only Claude launch authority: "
        f"{offenders}"
    )
