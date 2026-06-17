#!/usr/bin/env bash
#
# ghidra-headless.sh - drive a headless Ghidra process against a SHARED Ghidra
# Server repository (no GUI), run a GhidraScript on a program, and optionally
# commit the result so the change is visible to every other Ghidra client.
#
# It does three non-obvious things that plain `analyzeHeadless ghidra://...` gets
# wrong in a container:
#   1. Sets the login identity. Ghidra authenticates as the JVM `user.name`, NOT
#      the value you pass to -connect or an authenticator. In a container that is
#      usually `root`, so we override it with -Duser.name=$GHIDRA_USER via
#      _JAVA_OPTIONS. (Verified: without this you get "Authentication failed".)
#   2. Feeds the password to -p over stdin (non-interactive).
#   3. Targets the shared repo with a ghidra://host:port/repo[/folder] URL and,
#      when not read-only, passes -commit so edits are checked in server-side.
#
# All connection details come from environment variables:
#   GHIDRA_INSTALL   Ghidra install dir      (default: /workdir/ghidra_12.1.2_PUBLIC)
#   GHIDRA_ADDRESS   server host[:port]      (required, e.g. ghidra.stronk.pw or host:13100)
#   GHIDRA_PROJECT   repository name         (required, e.g. P3)
#   GHIDRA_USER      login user              (required, e.g. claude)
#   GHIDRA_PASSWORD  login password          (required)
#   GHIDRA_FOLDER    repo subfolder          (default: / )
#   GHIDRA_PROGRAM   program to process      (default: empty => recurse all)
#   GHIDRA_SCRIPT    post-script to run      (default: CreateStructHeadless.java)
#   GHIDRA_SCRIPTPATH script search dir      (default: dir of this script)
#   GHIDRA_COMMIT_MSG commit comment         (default: empty => read-only, no commit)
#
# Examples:
#   # read-only: enumerate every program in the repo
#   GHIDRA_HOST=ghidra.stronk.pw GHIDRA_PROJECT=P3 GHIDRA_USER=claude \
#   GHIDRA_PASSWORD=... GHIDRA_SCRIPT=ServerProbe.java ./ghidra-headless.sh
#
#   # edit one program and commit a new struct (visible to other clients)
#   GHIDRA_HOST=ghidra.stronk.pw GHIDRA_PROJECT=P3 GHIDRA_USER=claude \
#   GHIDRA_PASSWORD=... GHIDRA_PROGRAM=Mapeditor.exe \
#   GHIDRA_COMMIT_MSG="add ClaudeHeadlessStruct" ./ghidra-headless.sh
#
set -euo pipefail

GHIDRA_INSTALL="${GHIDRA_INSTALL:-/workdir/ghidra_12.1.2_PUBLIC}"
GHIDRA_FOLDER="${GHIDRA_FOLDER:-/}"
GHIDRA_SCRIPT="${GHIDRA_SCRIPT:-RpcServer.java}"
GHIDRA_SCRIPTPATH="${GHIDRA_SCRIPTPATH:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
GHIDRA_PROGRAM="${GHIDRA_PROGRAM:-}"
GHIDRA_COMMIT_MSG="${GHIDRA_COMMIT_MSG:-}"

: "${GHIDRA_ADDRESS:?set GHIDRA_ADDRESS (host or host:port, e.g. ghidra.stronk.pw)}"
: "${GHIDRA_PROJECT:?set GHIDRA_PROJECT (repository name, e.g. P3)}"
: "${GHIDRA_USER:?set GHIDRA_USER (e.g. claude)}"
: "${GHIDRA_PASSWORD:?set GHIDRA_PASSWORD}"

# Split GHIDRA_ADDRESS into host[:port]; default port 13100.
GHIDRA_HOST="${GHIDRA_ADDRESS%%:*}"
if [ "$GHIDRA_ADDRESS" = "$GHIDRA_HOST" ]; then GHIDRA_PORT=13100; else GHIDRA_PORT="${GHIDRA_ADDRESS##*:}"; fi

HEADLESS="$GHIDRA_INSTALL/support/analyzeHeadless"
[ -x "$HEADLESS" ] || { echo "analyzeHeadless not found/executable at $HEADLESS" >&2; exit 1; }

# Normalise folder so we build ghidra://host:port/repo/folder cleanly.
folder="/${GHIDRA_FOLDER#/}"; folder="${folder%/}"
URL="ghidra://${GHIDRA_HOST}:${GHIDRA_PORT}/${GHIDRA_PROJECT}${folder}"

# Build the argument list. -noanalysis: these scripts drive edits on already-
# analyzed programs; we don't want re-analysis noise in the committed diff.
# Set GHIDRA_ANALYSIS=1 to re-enable auto-analysis.
args=( "$URL" -p -scriptPath "$GHIDRA_SCRIPTPATH" )
[ "${GHIDRA_ANALYSIS:-0}" = "1" ] || args+=( -noanalysis )

if [ -n "$GHIDRA_PROGRAM" ]; then
  args+=( -process "$GHIDRA_PROGRAM" )
else
  args+=( -process -recursive )
fi

if [ -n "$GHIDRA_COMMIT_MSG" ]; then
  args+=( -commit "$GHIDRA_COMMIT_MSG" )      # writeable: changes checked in to the server
else
  args+=( -readOnly )                          # safe default: never mutates the repo
fi

args+=( -postScript "$GHIDRA_SCRIPT" )

echo ">> headless: $HEADLESS ${args[*]}" >&2
echo ">> login user: $GHIDRA_USER  (mode: $([ -n "$GHIDRA_COMMIT_MSG" ] && echo COMMIT || echo READ-ONLY))" >&2

# user.name override is the critical piece; password goes to -p via stdin.
printf '%s\n' "$GHIDRA_PASSWORD" | _JAVA_OPTIONS="-Duser.name=${GHIDRA_USER}" "$HEADLESS" "${args[@]}"
