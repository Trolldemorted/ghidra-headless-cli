#!/usr/bin/env bash
# Run the end-to-end tests: builds the CLI, then runs both halves, each in its
# own Python process (so only one half's JVMs are alive at a time):
#
#   local   every test_*.py except test_shared_*.py: one RPC server on a
#           throwaway local Ghidra project
#   shared  test_shared_*.py: a throwaway Ghidra Server + repository, the RPC
#           server launched through ghidra-headless.sh, and a second client
#
#   GHIDRA_HOME=/path/to/ghidra_<ver>_PUBLIC tests/e2e/run.sh [local|shared|unittest args]
#
# Examples:
#   tests/e2e/run.sh                         # everything (local, then shared)
#   tests/e2e/run.sh local                   # only the local-project half
#   tests/e2e/run.sh shared                  # only the Ghidra Server half
#   tests/e2e/run.sh test_comments           # one file
#   tests/e2e/run.sh -k bitfield             # tests matching a name
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"

if [ -z "${GHIDRA_HOME:-${GHIDRA_INSTALL:-}}" ]; then
    echo "run.sh: set GHIDRA_HOME to a Ghidra installation directory" >&2
    exit 2
fi
if [ -z "${GHIDRA_CLI:-}" ]; then
    (cd "$REPO/ghidra-headless-cli" && cargo build --release --quiet)
fi

cd "$HERE"
mapfile -t LOCAL < <(ls test_*.py | grep -v '^test_shared_' | sed 's/\.py$//')
mapfile -t SHARED < <(ls test_shared_*.py | sed 's/\.py$//')

part() {
    echo "==== e2e: $1 tests" >&2
    shift
    python3 -m unittest -v "$@"
}

case "${1:-all}" in
    all)
        status=0
        part local "${LOCAL[@]}" || status=1
        part shared "${SHARED[@]}" || status=1
        exit "$status"
        ;;
    local)
        part local "${LOCAL[@]}"
        ;;
    shared)
        part shared "${SHARED[@]}"
        ;;
    *)
        exec python3 -m unittest -v "$@"
        ;;
esac
