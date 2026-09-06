import json
import hashlib
import os
import sys
from pathlib import Path
from unittest import mock

import recon_prepass as recon


def test_opengrep_grants_only_scratchpad_write_authority(tmp_path: Path) -> None:
    scratch = tmp_path / "scratch"
    project = tmp_path / "project"
    source = project / "src" / "Contract.sol"
    rules = tmp_path / "rules"
    scratch.mkdir()
    source.parent.mkdir(parents=True)
    source.write_text("contract Contract {}\n", encoding="utf-8")
    (rules / "solidity" / "security").mkdir(parents=True)
    seen: dict[str, object] = {}

    def contained_scan(command, *args, **kwargs):
        seen["command"] = list(command)
        seen.update(kwargs)
        destination = Path(command[command.index("--sarif-output") + 1])
        destination.write_text(
            json.dumps(
                {
                    "version": "2.1.0",
                    "runs": [
                        {
                            "tool": {"driver": {"name": "opengrep"}},
                            "results": [],
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        return 0, ""

    with mock.patch.object(recon.shutil, "which", return_value="/tool/opengrep"), \
         mock.patch.object(
             recon,
             "_ensure_opengrep_rules",
             return_value={"opengrep-rules": rules, "decurity-rules": rules},
         ), \
         mock.patch.object(
             recon, "_production_source_files", return_value=[source]
         ), \
         mock.patch.object(
             recon, "_run_hardened", side_effect=contained_scan
         ):
        project_identity = os.path.normcase(str(project.resolve())).replace(
            "\\", "/"
        )
        context = {
            "run_id": "opengrep-writable-root-fixture",
            "phase": "recon-prebreadth",
            "snapshot_sha256": "1" * 64,
            "project_root_sha256": hashlib.sha256(
                project_identity.encode("utf-8")
            ).hexdigest(),
            "ecosystem": "evm",
            "pipeline": "sc",
            "mode": "thorough",
            "platform": "windows" if sys.platform == "win32" else "linux",
        }
        status = recon._run_opengrep_scan(
            scratch, project, "evm", context=context
        )

    assert status == "WRITTEN:0 findings"
    writable_roots = seen["writable_roots"]
    assert isinstance(writable_roots, tuple)
    assert len(writable_roots) == 1
    stage = writable_roots[0]
    assert isinstance(stage, Path)
    assert stage.parent == scratch
    assert stage.name.startswith(".og-")
    assert stage != scratch
    assert project not in writable_roots
    scanner_env = seen["env"]
    assert isinstance(scanner_env, dict)
    assert scanner_env["TEMP"] == str(stage)
    assert scanner_env["TMP"] == str(stage)
    assert scanner_env["TMPDIR"] == str(stage)
    assert scanner_env["XDG_CACHE_HOME"] == str(stage)
    assert scanner_env["SEMGREP_SETTINGS_FILE"] == str(
        stage / "settings.yml"
    )
    assert scanner_env["SEMGREP_VERSION_CACHE_PATH"] == str(
        stage / "version"
    )
    assert scanner_env["SEMGREP_LOG_FILE"] == str(stage / "scanner.log")
    assert scanner_env["OPENGREP_ENABLE_VERSION_CHECK"] == "0"
    assert "--disable-version-check" in seen["command"]
    assert not stage.exists()
