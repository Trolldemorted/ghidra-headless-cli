#!/usr/bin/env bash
#
# Run Checkstyle against every Java source under this server.
#
# Why a shell script (not a Makefile): the repo has no Makefile yet, and the
# Java file list is built by `find` so adding new procedure packages picks up
# automatically. The script exits non-zero on any warning so CI fails fast.

set -euo pipefail

# Resolve repo root from this script's location, regardless of CWD.
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"

cd "$ROOT"

# Discover all Java sources: the top-level RpcServer entrypoint + every
# procedures/**/*.java under it.
mapfile -t SOURCES < <(
    {
        [ -f RpcServer.java ] && echo RpcServer.java
        find procedures -name '*.java'
    } | sort -u
)

if [ "${#SOURCES[@]}" -eq 0 ]; then
    echo "no Java sources found under $ROOT" >&2
    exit 2
fi

# Checkstyle exits 0 on clean, non-zero on any warning (config severity=warning).
exec checkstyle -c tools/checkstyle.xml "${SOURCES[@]}"