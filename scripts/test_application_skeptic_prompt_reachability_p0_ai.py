from pathlib import Path

from plamen_prompt import build_phase_prompt
from plamen_types import L1_PHASES, SC_PHASES


def _phase(phases):
    return next(item for item in phases if item.name == "application_skeptic")


def test_application_skeptic_standalone_prompt_is_reachable_for_sc_and_l1(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    v1 = tmp_path / "unused-v1.md"
    v1.write_text("# compatibility fallback\n", encoding="utf-8")
    for pipeline, language, phases in (
        ("sc", "evm", SC_PHASES),
        ("l1", "rust", L1_PHASES),
    ):
        rendered = build_phase_prompt(
            v1,
            _phase(phases),
            {
                "pipeline": pipeline,
                "language": language,
                "mode": "thorough",
                "project_root": str(project),
                "scratchpad": str(project / ".scratchpad"),
                "cli_backend": "claude",
            },
        )
        assert "Application Skeptic" in rendered
        assert "driver-owned work plan" in rendered
        assert "independent" in rendered.lower()
