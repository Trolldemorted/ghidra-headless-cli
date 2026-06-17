# Headless Ghidra against a shared Ghidra Server

Goal: open a project that lives on a **shared Ghidra Server** without launching the
Ghidra GUI, make a change (e.g. create a struct), and have that change become
visible to every other Ghidra client — all driven from the command line / scripts.

This is solved with Ghidra's **`analyzeHeadless`** (a.k.a. the Headless Analyzer)
pointed at a `ghidra://` repository URL, plus a thin env-driven wrapper and a few
GhidraScripts. Everything lives in `/workdir/ghidrascript/`.

## TL;DR — run it

```bash
export GHIDRA_HOST=ghidra.stronk.pw      # server
export GHIDRA_PROJECT=P3                  # repository name
export GHIDRA_USER=claude                 # login user
export GHIDRA_PASSWORD=300ef19481d5...    # login password (plaintext sent to server)

# Read-only: list every program in the repo
GHIDRA_SCRIPT=ServerProbe.java /workdir/ghidrascript/ghidra-headless.sh

# Edit one program and COMMIT a struct (visible to other clients)
GHIDRA_PROGRAM=Mapeditor.exe \
GHIDRA_COMMIT_MSG="add ClaudeHeadlessStruct" \
/workdir/ghidrascript/ghidra-headless.sh

# Verify a fresh client sees it
GHIDRA_PROGRAM=Mapeditor.exe GHIDRA_SCRIPT=VerifyStruct.java \
/workdir/ghidrascript/ghidra-headless.sh
```

## Environment

- Ghidra **12.1.2 PUBLIC** installed at `/workdir/ghidra_12.1.2_PUBLIC`
  (download: NSA GitHub release `Ghidra_12.1.2_build`). It is protocol-compatible
  with the `ghidra.stronk.pw` server (no "incompatible server version" error).
- JDK 21 (`/usr/bin/java`) — required by Ghidra 12.x.
- Server reached at `ghidra.stronk.pw:13100` (the default Ghidra Server RMI port;
  the server also uses 13101/13102 for the RMI callback/stream services).

## The repository URL

```
ghidra://<host>[:<port>]/<repository>[/<folder>[/<program>]]
```
e.g. `ghidra://ghidra.stronk.pw:13100/P3`. Hand this to `analyzeHeadless` *instead
of* a local `<project_location> <project_name>` pair. Ghidra creates a hidden,
throwaway **transient project** that proxies the server repo.

## The three things that make it actually work

1. **Login identity = JVM `user.name`, NOT `-connect`.**
   The `P3` server authenticates with username/password, but it does **not** send
   a username callback — Ghidra uses the JVM system property `user.name` as the
   login name. In this container that is `root`, so you get
   `FailedLoginException: Authentication failed` even with the right password.
   `analyzeHeadless`'s documented `-connect <user>` flag did **not** override it
   in testing. The reliable fix is to set the property via the JVM:
   ```bash
   _JAVA_OPTIONS="-Duser.name=claude"
   ```
   (The wrapper does this for you.) Confirmed log line on success:
   `Password authenticating to ghidra.stronk.pw as user 'claude'`.

2. **Password is supplied non-interactively via `-p` + stdin.**
   `-p` makes headless prompt for the server password; piping it on stdin
   (`printf '%s\n' "$PASSWORD" | analyzeHeadless ... -p`) answers the prompt with
   no TTY. The password is sent as **plaintext**; the server hashes & compares it
   (so the value in `GHIDRA_PASSWORD` must be the real password, not its hash).

3. **Committing needs an *exclusive* checkout — clear stale checkouts first.**
   With `-commit "<msg>"` (and *without* `-readOnly`) headless checks the program
   out, runs the script, saves, and checks the new version in. It requires an
   **exclusive** checkout. A transient run that dies mid-commit can orphan a
   `NORMAL` checkout server-side (the transient project that owned it is gone),
   and that leftover blocks the next exclusive checkout:
   `failed to get exclusive file checkout required for commit`.
   Run `CleanCheckouts.java` to terminate **your own** stale checkouts, then retry.

## Read-only vs commit (wrapper behaviour)

- No `GHIDRA_COMMIT_MSG`  → `-readOnly` (never mutates the repo). Safe default.
- `GHIDRA_COMMIT_MSG` set → `-commit "<msg>"`, changes are checked in as a new
  version, visible to all clients.
- `-noanalysis` is passed by default so the committed diff is exactly your script's
  change (no re-analysis noise). Set `GHIDRA_ANALYSIS=1` to re-enable auto-analysis.

## Scripts in /workdir/ghidrascript

| file | role |
|------|------|
| `ghidra-headless.sh`       | **the launcher** — env-driven wrapper around `analyzeHeadless` |
| `CreateStructHeadless.java`| creates/replaces a struct in the program DTM (the demo edit) |
| `VerifyStruct.java`        | read-only check that the struct is in the latest version |
| `ServerProbe.java`         | read-only: prints each program + its data-type count |
| `RepoInspect.java`         | dumps permissions, items, versions, and outstanding checkouts |
| `CleanCheckouts.java`      | terminates *your own* stale/orphaned checkouts |
| `DiagConnect.java` / `DiagConnect2.java` | connection/auth diagnostics (verbose callbacks) |

The `*.java` files are **GhidraScripts** (run with `-postScript`). They use the
GhidraScript API and, for the server-management ones, the `ghidra.framework.client`
API (`ClientUtil`, `PasswordClientAuthenticator`, `RepositoryServerAdapter`,
`RepositoryAdapter`). All read connection details from the same env vars.

### Why Java for the in-Ghidra scripts (not Kotlin)
Ghidra's `GhidraScriptProvider` only recognises **`.java`** and **`.py`** scripts —
there is no Kotlin script engine, so a `.kt` post-script can't be loaded by
headless without writing a custom provider/extension. The in-Ghidra logic is
therefore Java; the orchestration layer (`ghidra-headless.sh`) is a dependency-free
shell wrapper (no Kotlin toolchain is installed, and it is a thin `analyzeHeadless`
launcher where Bash is the idiomatic choice).

## Diagnostic flow used to get here (for future debugging)

1. `DiagConnect.java` — installs `PasswordClientAuthenticator(user,pass)` and prints
   `RepositoryServerAdapter.getLastConnectError()`. This turned the opaque
   "Unauthorized" into the precise `FailedLoginException`, and later listed
   `repositories(1): P3` on success.
2. `DiagConnect2.java` — logs every auth callback; proved the server asks for a
   password only (no name/SSH/PKI/anonymous, no "change password"), so the failure
   was a plain identity/password mismatch — which led to the `user.name` fix.
3. `RepoInspect.java` — showed `me=claude write=true admin=true` and the orphaned
   `claude(v1,NORMAL)` checkout that blocked `-commit`.

## Raw command (what the wrapper runs)

```bash
printf '%s\n' "$GHIDRA_PASSWORD" | \
_JAVA_OPTIONS="-Duser.name=$GHIDRA_USER" \
/workdir/ghidra_12.1.2_PUBLIC/support/analyzeHeadless \
  ghidra://$GHIDRA_HOST:$GHIDRA_PORT/$GHIDRA_PROJECT \
  -p -noanalysis \
  -process Mapeditor.exe \
  -commit "add ClaudeHeadlessStruct" \
  -scriptPath /workdir/ghidrascript \
  -postScript CreateStructHeadless.java
```

Success markers in the log:
```
Password authenticating to ghidra.stronk.pw as user 'claude'
[CreateStruct] created /ClaudeHeadless/ClaudeHeadlessStruct size=12 bytes
Checkin completed for Mapeditor.exe
REPORT: Committed file changes to repository: /Mapeditor.exe
```
(The trailing `Transient project (P3) use count has gone negative` line is a benign
teardown warning from Ghidra's transient-project cleanup; the commit still lands.)
