from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_posix_fronts_require_reviewed_cpython_312() -> None:
    for name in ("plamen", "plamen.sh"):
        source = (ROOT / name).read_text(encoding="utf-8")
        assert ".local/share/plamen/runtime/py312/bin/python" in source
        assert "command -v python3.12" in source
        assert "command -v python3 ||" not in source
        assert "command -v python)" not in source
        assert 'exec "$PLAMEN_PYTHON" -I -B ' in source
        assert "exit 126" in source
