#!/usr/bin/env bash
#
# Compile every Java source of the RPC server against a Ghidra installation.
#
# Why this exists: the server has no build step. Ghidra's script host compiles
# RpcServer.java and procedures/** when the server STARTS, so a call that does
# not match the pinned Ghidra's API used to surface only then — after the
# image had been built and pushed. This runs the same compilation up front;
# the Dockerfile calls it, so a broken source tree fails the image build.
#
# Usage:  GHIDRA_HOME=/path/to/ghidra_<ver>_PUBLIC tools/compile-check.sh
#         (GHIDRA_INSTALL is accepted as well; it is what ghidra-headless.sh uses)
#
# Nothing is kept: classes go to a temporary directory that is removed on exit.

set -euo pipefail

GHIDRA="${GHIDRA_HOME:-${GHIDRA_INSTALL:-}}"
if [ -z "$GHIDRA" ] || [ ! -d "$GHIDRA/Ghidra" ]; then
    echo "compile-check: set GHIDRA_HOME to a Ghidra installation directory" >&2
    exit 2
fi

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
cd "$ROOT"

OUT="$(mktemp -d)"
trap 'rm -rf "$OUT"' EXIT

CP="$(find "$GHIDRA" -name '*.jar' | sort | tr '\n' ':')"
mapfile -t SOURCES < <({ echo RpcServer.java; find procedures -name '*.java'; } | sort -u)

# -proc:none: no annotation processing (some Ghidra jars register processors
# that are irrelevant here). -Werror is deliberately NOT set: deprecation
# notes from Ghidra's API are not failures.
javac -proc:none -d "$OUT" -cp "$CP" -sourcepath . "${SOURCES[@]}"
echo "compile-check: ${#SOURCES[@]} sources compile against $GHIDRA"
