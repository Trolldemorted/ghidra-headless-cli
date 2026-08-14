#!/usr/bin/env bash
#
# ghidra-headless.sh - drive a headless Ghidra process against a SHARED Ghidra
# Server repository (no GUI) and run a GhidraScript. Its primary job is to launch
# RpcServer.java, which serves Ghidra operations over TCP and addresses every
# program in the repository on demand by path.
#
# It does four non-obvious things that plain `analyzeHeadless ghidra://...` gets
# wrong in a container:
#   1. Sets the login identity. Ghidra authenticates as the JVM `user.name`, NOT
#      the value you pass to -connect or an authenticator. In a container that is
#      usually `root`, so we override it with -Duser.name=$GHIDRA_USER via
#      _JAVA_OPTIONS. (Verified: without this you get "Authentication failed".)
#   2. Feeds the password to -p over stdin (non-interactive).
#   3. Targets the shared repo with a ghidra://host:port/repo[/folder] URL.
#   4. BYPASSES upstream `support/analyzeHeadless` + `support/launch.sh` +
#      `support/launch.properties` entirely. We resolve a Java binary, find
#      Utility.jar, and exec `java -cp Utility.jar ghidra.Ghidra
#      ghidra.app.util.headless.AnalyzeHeadless` directly. This project's
#      contract with `/workdir/ghidra_12.1.2_PUBLIC/support/*` is zero
#      dependencies — we never read those files. Updating Ghidra is always
#      safe (the wrapper is upstream-agnostic). See
#      /root/.claude/plans/glimmering-snuggling-flurry.md and the memory
#      entry `launch-sh-env-var-migration` for the rationale.
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
#   GHIDRA_REFRESH_PW removed 2026-07-30: password refresh on connect is now
#                        always-on whenever GHIDRA_PASSWORD is exported to the
#                        JVM (see comment near `export GHIDRA_PASSWORD` below).
#                        To opt out, unset GHIDRA_PASSWORD before launching.
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

# Resolve a Java binary. Prefer $JAVA_HOME/bin/java (matches what upstream
# support/launch.sh resolved when it called into LaunchSupport); fall back to
# PATH via `command -v`. Fail with a clear message if neither is usable.
# We do NOT route through upstream support/launch.sh, so we also do NOT call
# LaunchSupport.jar's interactive JDK picker (no TTY expected in container).
JAVA_BIN="${JAVA_HOME:+${JAVA_HOME}/bin/java}"
if [ -z "${JAVA_BIN:-}" ] || [ ! -x "${JAVA_BIN}" ]; then
    JAVA_BIN="$(command -v java || true)"
fi
[ -n "${JAVA_BIN:-}" ] && [ -x "${JAVA_BIN}" ] || {
    echo "no java found; set JAVA_HOME or install java in PATH" >&2; exit 2
}

# Find Utility.jar. It carries ghidra.Ghidra/GhidraClassLoader, which loads the
# rest of the framework jars via the bundling convention. Path follows the
# production layout that upstream support/launch.sh assembled for callers.
CPATH="${GHIDRA_INSTALL}/Ghidra/Framework/Utility/lib/Utility.jar"
[ -f "${CPATH}" ] || { echo "cannot find ${CPATH}" >&2; exit 2; }

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

echo ">> java: $JAVA_BIN -cp <Utility.jar> ghidra.Ghidra ghidra.app.util.headless.AnalyzeHeadless ${args[*]}" >&2
echo ">> login user: $GHIDRA_USER  (mode: $mode, programs: ${GHIDRA_PROGRAM:-none})" >&2

# Forward GHIDRA_PASSWORD to the JVM as an environment variable so RpcServer.java
# can call RepositoryServerAdapter.setPassword(...) on connect and push out the
# server-side password expiry. The wrapper reads it via System.getenv(...) in
# Java — env vars are opaque to the JVM-arg parser and survive arbitrary
# content, including whitespace (which broke the old `-Dghidra.rpc.password`
# path through launch.sh's word-split). See feedback_password_whitespace_jvm_arg.md.
export GHIDRA_PASSWORD

# Export the connection-identifying env vars so the RPC server's JVM can
# read them via System.getenv(...) when its stale-checkout self-heal
# helper needs to open a fresh RepositoryServerAdapter. Without these,
# self-heal degrades to "no orphan found" and the request fails with the
# manual CleanCheckouts hint. See /workdir/notes/checkin-rollback.md
# "Known gaps — Checkout-acquired-but-unmodified files".
export GHIDRA_HOST
export GHIDRA_PORT
export GHIDRA_USER
export GHIDRA_PROJECT

# Single source of truth for JVM args. As of 2026-08-05 the wrapper bypasses
# upstream `support/launch.sh` / `support/launch.properties` /
# `support/analyzeHeadless` entirely — see the bypass note at the top of this
# file. All JVM args live here in `JDK_JAVA_OPTIONS` (preferred) and
# `_JAVA_OPTIONS` (JVM-init-phase flags only). The JVM launcher reads and
# tokenizes both env vars itself (not bash), so values containing whitespace
# survive intact and the launch.sh:238 `${VMARGS_FROM_CALLER}` word-split bug
# is bypassed at its source (we never invoke that script). Flags below
# originally came from upstream support/launch.properties.
#
# --enable-native-access=ALL-UNNAMED  — JDK 21+ JEP 413/414 module-init flag
#                                       (required by FlatLaf).
# -Djavax.xml.accessExternal{DTD,Schema,Stylesheet}=  — empty disables JAXP
#                                       resolution to external resources
#                                       (security hardening).
# -Djdk.tls.client.protocols=TLSv1.2,TLSv1.3  — restrict TLS versions for
#                                       SSL/Ghidra-Server connections.
# -Dfile.encoding=UTF8  — Linux/macOS already default UTF-8, but the JVM
#                          on Windows defaults to platform encoding; pin it
#                          everywhere for deterministic C-source output.
# -Dpython.console.encoding=UTF-8  — Jython reads at framework init.
# -XX:ParallelGCThreads=2 / -XX:CICompilerCount=2  — headless instances
#                                       scale on shared hosts (one parallel
#                                       GC thread per core over-subscribes
#                                       when many run concurrently).
# -Djava.awt.headless=true  — explicit; JVM defaults true without DISPLAY
#                              but a foreground DISPLAY would flip it.
# -Xshare:off  — CDS off. Temurin 21.0.11+10-LTS races with
#                                       java.system.class.loader at
#                                       System.initPhase3 (Class.forName
#                                       for ghidra.GhidraClassLoader throws
#                                       ClassNotFoundException despite the
#                                       class being on -cp). Same JDK from
#                                       Ubuntu ships a clean CDS cache; the
#                                       fix lands in Temurin 21.0.12+. Until
#                                       then, route around it.
JDK_JAVA_OPTIONS="${JDK_JAVA_OPTIONS:-} \
  --enable-native-access=ALL-UNNAMED \
  -Djavax.xml.accessExternalDTD= \
  -Djavax.xml.accessExternalSchema= \
  -Djavax.xml.accessExternalStylesheet= \
  -Djdk.tls.client.protocols=TLSv1.2,TLSv1.3 \
  -Dfile.encoding=UTF8 \
  -Dpython.console.encoding=UTF-8 \
  -XX:ParallelGCThreads=2 \
  -XX:CICompilerCount=2 \
  -Djava.awt.headless=true \
  -Xshare:off"
export JDK_JAVA_OPTIONS

# En_US is the only locale Ghidra's resource bundles ship with. JVM reads
# these from `user.country`/`user.language` at initPhase3 — JDK_JAVA_OPTIONS
# is too late in some resource-bundle paths, so set both. Mirrors what
# launch.properties used to set.
_JAVA_OPTIONS="${_JAVA_OPTIONS:-} \
  -Duser.name=${GHIDRA_USER} \
  -Duser.country=US \
  -Duser.language=en \
  -Duser.variant= \
  -Djava.system.class.loader=ghidra.GhidraClassLoader"
export _JAVA_OPTIONS

# Log the effective JDK_JAVA_OPTIONS the wrapper just exported so debugging
# classloader / VM-init issues (e.g. Temurin-LTS CDS race with
# java.system.class.loader) doesn't require re-running with bash -x. The
# JVM echoes this exact string back under `Picked up JDK_JAVA_OPTIONS:` in
# its startup banner (paired with the `openjdk version` line under
# -showversion) — keep this wrapper-side log line AND the JVM-side echo
# so the full picture is visible without bash -x.
echo ">> java vmargs (JDK_JAVA_OPTIONS): ${JDK_JAVA_OPTIONS:-<unset>}" >&2
echo ">> java vmargs (_JAVA_OPTIONS): ${_JAVA_OPTIONS:-<unset>}" >&2

# Direct java exec. Bypass upstream support/launch.sh + support/analyzeHeadless
# entirely — those files are not read by this project (see header comment).
# Password goes to -p via stdin; -Duser.name in _JAVA_OPTIONS makes Ghidra
# authenticate as $GHIDRA_USER (not the container's `root`, which fails).
# -showversion makes the JVM echo `Picked up JDK_JAVA_OPTIONS:` / `Picked up
# _JAVA_OPTIONS:` plus the openjdk banner, paired with the wrapper-side log
# lines above for full visibility without `bash -x`.
printf '%s\n' "$GHIDRA_PASSWORD" | exec "${JAVA_BIN}" \
    -showversion \
    -cp "${CPATH}" \
    ghidra.Ghidra \
    ghidra.app.util.headless.AnalyzeHeadless \
    "${args[@]}"
