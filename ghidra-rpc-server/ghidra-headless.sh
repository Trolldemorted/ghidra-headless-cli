#!/usr/bin/env bash
#
# ghidra-headless.sh - drive a headless Ghidra process against a SHARED Ghidra
# Server repository (no GUI) and run a GhidraScript. Its primary job is to launch
# RpcServer.java, which serves Ghidra operations over TCP and addresses every
# program in the repository on demand by path.
#
# It does three non-obvious things that plain `analyzeHeadless ghidra://...` gets
# wrong in a container:
#   1. Sets the login identity. Ghidra authenticates as the JVM `user.name`, NOT
#      the value you pass to -connect or an authenticator. In a container that is
#      usually `root`, so we override it with -Duser.name=$GHIDRA_USER via
#      _JAVA_OPTIONS. (Verified: without this you get "Authentication failed".)
#   2. Feeds the password to -p over stdin (non-interactive).
#   3. Targets the shared repo with a ghidra://host:port/repo[/folder] URL.
#
# ZERO PROGRAMS BY DEFAULT: the RPC server is not bound to any program. It opens
# each request's target on demand (with its own checkout/check-in), so it must
# start with NO program open. We achieve that by running the script as a
# -preScript with no -process: a pre-script executes exactly once even when
# headless processes no program at all (a post-script would never run without
# one). currentProgram is then null and the server begins empty.
#
# PROJECT MODE: per-request check-ins require a WRITEABLE project, so by default
# we pass NEITHER -readOnly (which opens the project read-only -> "checkout
# permitted in writeable project only") NOR -commit (which only auto-commits
# *processed* programs -- we process none). The project opens writeable and the
# server's own per-request check-ins are the persistence. Set GHIDRA_READONLY=1
# for read-only diagnostic scripts.
#
# All connection details come from environment variables:
#   GHIDRA_INSTALL   Ghidra install dir      (default: /workdir/ghidra_12.1.2_PUBLIC)
#   GHIDRA_ADDRESS   server host[:port]      (required, e.g. ghidra.stronk.pw or host:13100)
#   GHIDRA_PROJECT   repository name         (required, e.g. P3)
#   GHIDRA_USER      login user              (required, e.g. claude)
#   GHIDRA_PASSWORD  login password          (required)
#   GHIDRA_FOLDER    repo subfolder          (default: / )
#   GHIDRA_PROGRAM   process a specific prog (default: empty => NONE, zero programs;
#                                             "__recursive__" => process every program)
#   GHIDRA_SCRIPT    script to run           (default: RpcServer.java)
#   GHIDRA_SCRIPTPATH script search dir      (default: dir of this script)
#   GHIDRA_READONLY  1 => open read-only     (default: 0 => writeable project)
#   GHIDRA_COMMIT_MSG -commit comment        (default: empty; only relevant with GHIDRA_PROGRAM)
#
# Examples:
#   # launch the RPC server (zero programs, writeable, opens targets on demand)
#   GHIDRA_ADDRESS=ghidra.stronk.pw GHIDRA_PROJECT=P3 GHIDRA_USER=claude \
#   GHIDRA_PASSWORD=... ./ghidra-headless.sh
#
#   # read-only: enumerate every program in the repo
#   GHIDRA_ADDRESS=ghidra.stronk.pw GHIDRA_PROJECT=P3 GHIDRA_USER=claude \
#   GHIDRA_PASSWORD=... GHIDRA_READONLY=1 GHIDRA_SCRIPT=ServerProbe.java ./ghidra-headless.sh
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

# The project name and folder path are embedded in a ghidra://host:port/...
# URL that Ghidra parses with java.net.URI (RFC 3986 strict). Spaces, '?',
# '#', '[', ']' in those segments throw URISyntaxException
# ("Illegal character in path") at AnalyzeHeadless.launch:134. The caller
# MUST percent-encode any segment that contains such characters BEFORE
# exporting it (e.g. via `printf '%s' "$x" | jq -sRr @uri | sed
# 's|%2F|/|g'`, or Python `urllib.parse.quote(s, safe="/")`); the launcher
# does NOT touch the values.
URL="ghidra://${GHIDRA_HOST}:${GHIDRA_PORT}/${GHIDRA_PROJECT}${folder}"

# Build the argument list. -noanalysis: these scripts drive edits on already-
# analyzed programs; we don't want re-analysis noise in the committed diff.
# Set GHIDRA_ANALYSIS=1 to re-enable auto-analysis.
args=( "$URL" -p -scriptPath "$GHIDRA_SCRIPTPATH" )
[ "${GHIDRA_ANALYSIS:-0}" = "1" ] || args+=( -noanalysis )

# Program selection. By default we process NO program: the server starts with zero
# programs and opens targets on demand by path. Set GHIDRA_PROGRAM to also process a
# specific program (one-shot edit scripts) or "__recursive__" for every program.
if [ "$GHIDRA_PROGRAM" = "__recursive__" ]; then
  args+=( -process -recursive )
elif [ -n "$GHIDRA_PROGRAM" ]; then
  args+=( -process "$GHIDRA_PROGRAM" )
fi

# Project mode (see header). Default: writeable, no auto-commit -> the server's own
# per-request check-ins persist changes. -readOnly only for read-only diagnostics;
# -commit only makes sense alongside GHIDRA_PROGRAM (auto-commits processed programs).
if [ "${GHIDRA_READONLY:-0}" = "1" ]; then
  args+=( -readOnly )
  mode="READ-ONLY"
elif [ -n "$GHIDRA_COMMIT_MSG" ]; then
  args+=( -commit "$GHIDRA_COMMIT_MSG" )
  mode="COMMIT"
else
  mode="WRITEABLE"
fi

# Run as a -preScript: it executes once even when no program is processed (a
# -postScript would not), which is exactly what the zero-program server needs.
args+=( -preScript "$GHIDRA_SCRIPT" )

echo ">> headless: $HEADLESS ${args[*]}" >&2
echo ">> login user: $GHIDRA_USER  (mode: $mode, programs: ${GHIDRA_PROGRAM:-none})" >&2

# user.name override is the critical piece; password goes to -p via stdin.
printf '%s\n' "$GHIDRA_PASSWORD" | _JAVA_OPTIONS="-Duser.name=${GHIDRA_USER}" "$HEADLESS" "${args[@]}"
