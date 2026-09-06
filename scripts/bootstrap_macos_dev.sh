#!/bin/sh
# Bootstrap an isolated Plamen source-development environment on macOS.
# This script deliberately does not install or launch the production audit runtime.

set -eu

usage() {
    cat <<'EOF'
Usage: sh scripts/bootstrap_macos_dev.sh [OPTIONS]

Options:
  --python PATH           CPython 3.12 interpreter (default: python3.12)
  --venv PATH             Development venv (default: REPO/.venv-dev)
  --extended-validation   Run the slower cross-platform source checks
  --require-native-audit  Fail unless native macOS E2E auditing is supported
  -h, --help              Show this help

The current Plamen-v3 tree supports source development on macOS, not native
E2E audit execution. --require-native-audit therefore exits with status 3.
EOF
}

fail() {
    code=$1
    shift
    printf '%s\n' "macOS development bootstrap: $*" >&2
    exit "$code"
}

python_command=${PLAMEN_DEV_PYTHON:-python3.12}
venv_path=${PLAMEN_DEV_VENV:-}
extended_validation=0
require_native_audit=0

while [ "$#" -gt 0 ]; do
    case "$1" in
        --python)
            [ "$#" -ge 2 ] || fail 2 "--python requires a path"
            python_command=$2
            shift 2
            ;;
        --venv)
            [ "$#" -ge 2 ] || fail 2 "--venv requires a path"
            venv_path=$2
            shift 2
            ;;
        --extended-validation)
            extended_validation=1
            shift
            ;;
        --require-native-audit)
            require_native_audit=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            fail 2 "unknown option: $1"
            ;;
    esac
done

host_system=$(uname -s 2>/dev/null || true)
[ "$host_system" = "Darwin" ] || fail 2 "this bootstrap supports macOS (Darwin) only"

host_arch=$(uname -m 2>/dev/null || true)
case "$host_arch" in
    arm64|x86_64)
        ;;
    *)
        fail 2 "unsupported macOS architecture: ${host_arch:-unknown}; expected arm64 or x86_64"
        ;;
esac

if [ "$require_native_audit" -eq 1 ]; then
    fail 3 "native macOS E2E audit execution is not supported by this tree; continue docs/continuation/GOAL.md or use a supported Windows/Linux audit host"
fi

script_dir=$(CDPATH= cd "$(dirname "$0")" && pwd -P)
repo_root=$(CDPATH= cd "$script_dir/.." && pwd -P)

[ -n "${HOME:-}" ] || fail 2 "HOME is not set"
home_root=$(CDPATH= cd "$HOME" && pwd -P)
case "$repo_root/" in
    "$home_root/.plamen/"*|"$home_root/.codex/plamen/"*|"$home_root/.claude/"*)
        fail 2 "the source checkout is inside a reserved installed/backend tree; clone it under a development directory such as \$HOME/src/plamen"
        ;;
esac

command -v xcode-select >/dev/null 2>&1 || fail 2 "xcode-select is unavailable; install the Xcode Command Line Tools"
xcode-select -p >/dev/null 2>&1 || fail 2 "Xcode Command Line Tools are not selected; run: xcode-select --install"
command -v git >/dev/null 2>&1 || fail 2 "git is unavailable"
command -v "$python_command" >/dev/null 2>&1 || fail 2 "CPython 3.12 was not found as: $python_command"

python_path=$(
    "$python_command" -I -c 'import os, sys; print(os.path.realpath(sys.executable))'
) || fail 2 "could not resolve the requested Python interpreter"

python_identity=$(
    "$python_path" -I -c 'import platform, sys; print(f"{sys.implementation.name}:{sys.version_info.major}.{sys.version_info.minor}:{platform.machine()}")'
) || fail 2 "could not inspect the requested Python interpreter"
case "$python_identity" in
    cpython:3.12:arm64|cpython:3.12:x86_64)
        ;;
    *)
        fail 2 "expected CPython 3.12 for arm64/x86_64, observed: $python_identity"
        ;;
esac

git -C "$repo_root" rev-parse --is-inside-work-tree >/dev/null 2>&1 || fail 2 "script is not inside a Git checkout"

for required_path in \
    requirements-ci.lock \
    requirements-ci-resolver.lock \
    scripts/ci_dependency_authority.py \
    scripts/plamen_driver.py \
    plamen.py
do
    [ -f "$repo_root/$required_path" ] || fail 2 "required source input is missing: $required_path"
done

printf '%s\n' "[1/6] Synchronizing pinned submodules"
git -C "$repo_root" submodule sync --recursive
git -C "$repo_root" submodule update --init --recursive
submodule_status=$(git -C "$repo_root" submodule status --recursive)
if printf '%s\n' "$submodule_status" | grep -E '^[-+U]' >/dev/null 2>&1; then
    fail 2 "submodule state differs from the committed Git links"
fi

printf '%s\n' "[2/6] Verifying the exact CI dependency authority"
"$python_path" -I "$repo_root/scripts/ci_dependency_authority.py" \
    bootstrap-gate --root "$repo_root"

if [ -z "$venv_path" ]; then
    venv_path="$repo_root/.venv-dev"
fi
case "$venv_path" in
    /*)
        ;;
    *)
        venv_path="$repo_root/$venv_path"
        ;;
esac

if [ -e "$venv_path" ] && [ ! -f "$venv_path/pyvenv.cfg" ]; then
    fail 2 "development environment path exists but is not a venv: $venv_path"
fi

printf '%s\n' "[3/6] Creating or reusing the isolated development environment"
if [ ! -f "$venv_path/pyvenv.cfg" ]; then
    "$python_path" -I -m venv "$venv_path"
fi
venv_python="$venv_path/bin/python"
[ -x "$venv_python" ] || fail 2 "venv interpreter is unavailable: $venv_python"
venv_identity=$(
    "$venv_python" -I -c 'import platform, sys; print(f"{sys.implementation.name}:{sys.version_info.major}.{sys.version_info.minor}:{platform.machine()}")'
) || fail 2 "could not inspect the development venv"
[ "$venv_identity" = "$python_identity" ] || fail 2 "existing venv uses $venv_identity, expected $python_identity; move it aside and rerun"

printf '%s\n' "[4/6] Installing hash-locked development inputs"
PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_NO_INPUT=1 \
    "$venv_python" -I -m pip install \
    --disable-pip-version-check \
    --only-binary=:all: \
    --require-hashes \
    -r "$repo_root/requirements-ci.lock"

printf '%s\n' "[5/6] Running source and bootstrap validation"
"$venv_python" -I -B -m py_compile \
    "$repo_root/plamen.py" \
    "$repo_root/scripts/plamen_driver.py" \
    "$repo_root/scripts/plamen_mcp_runtime.py" \
    "$repo_root/scripts/ci_dependency_authority.py"
(
    cd "$repo_root"
    "$venv_python" -B -m pytest -q -p no:cacheprovider \
        scripts/test_bootstrap_macos_dev.py \
        scripts/test_posix_path_persistence.py \
        scripts/test_posix_committed_read.py \
        scripts/test_managed_node_materialization.py
)

if [ "$extended_validation" -eq 1 ]; then
    printf '%s\n' "[6/6] Running extended cross-platform source validation"
    (
        cd "$repo_root"
        "$venv_python" -B -m pytest -q -p no:cacheprovider \
            scripts/test_cross_os_hygiene.py \
            scripts/test_cross_os_toolchain_pre_handoff_gate.py \
            scripts/test_preflight_pty.py \
            scripts/test_toolchain_crossos_adversarial_reds.py
    )
else
    printf '%s\n' "[6/6] Extended validation skipped (use --extended-validation to run it)"
fi

cat <<EOF

Plamen source-development environment is ready.
  repository: $repo_root
  architecture: $host_arch
  interpreter: $venv_python

Activate it with:
  . "$venv_path/bin/activate"

Native macOS audit runtime: UNSUPPORTED IN THIS TREE.
Do not run plamen.py install or claim a macOS E2E audit from this bootstrap.
Continue the native/VM audit-host work tracked in docs/continuation/GOAL.md,
or run audits on an already-supported Windows/Linux host.
EOF
