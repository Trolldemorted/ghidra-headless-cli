# Ghidra TCP ndjson RPC Server — `ghidra.app.cmd.function`

A line-oriented JSON-over-TCP server that exposes **every non-deprecated command in
Ghidra's `ghidra.app.cmd.function` package** as an RPC procedure. It runs as a
headless GhidraScript (`RpcServer.java`) inside `analyzeHeadless`, so it has live
access to the analyzed program and the full Ghidra API.

## Files

| file | role |
|------|------|
| `/workdir/ghidrascript/RpcServer.java` | main script: socket accept loop, ndjson parse, dispatch |
| `/workdir/ghidrascript/procedures/RpcProcedure.java` | handler interface (`execute` + `mutates()`) |
| `/workdir/ghidrascript/procedures/RpcContext.java` | shared program access: lock, checkout/checkin, `applyCommand`, resolvers |
| `/workdir/ghidrascript/procedures/RpcResponse.java` | response POJO (`success`, `error`) |
| `/workdir/ghidrascript/procedures/ghidra/app/cmd/function/*Handler.java` | one handler per command (mirrors Ghidra's package) |
| `/workdir/ghidrascript/procedures/ghidra/app/decompiler/flatapi/FlatDecompilerAPIHandler.java` | decompile-to-C procedure |
| `/workdir/ghidrascript/procedures/ghidra/app/util/importer/ProgramLoaderHandler.java` | import a new program from bytes in the request |
| `/workdir/ghidrascript/ghidra-headless.sh` | headless launcher (env-driven) |
| `/workdir/ghidrascript/Dockerfile`, `.dockerignore` | package Ghidra + scripts into a container image (build context = this dir) |
| `/workdir/testscripts/rpc_client.py` | ndjson test client |
| `/workdir/testscripts/VerifyFnCmd.java` | read-only persistence checker |
| `/workdir/notes/procedures/<Cmd>.md` | one doc per procedure, request as a TypeScript interface |

Handlers live in package `procedures.ghidra.app.cmd.function`, named `<GhidraCmd>Handler`
(e.g. `SetFunctionNameCmdHandler`), mirroring the original Ghidra package below
`procedures/`.

## Wire protocol (ndjson)

* One JSON object per line (UTF-8, `\n`-terminated); the `"procedure"` field is a
  Ghidra command's **simple name** (e.g. `"SetFunctionNameCmd"`).
* Program-related procedures (the default — see `RpcProcedure.needsProgram()`) also
  carry a **mandatory `"program"`** field: the target program's project path
  (e.g. `"/Mapeditor.exe"`; a bare name with no `/` is resolved by name search). One
  server addresses **every program in the repository**, not just the one it launched on.
* Exactly one JSON response per request: `{"success":true,...}` or
  `{"success":false,"error":"..."}`.
* Long-lived connection; many clients at once (one thread per connection).

```
-> {"procedure":"SetFunctionNameCmd","program":"/Mapeditor.exe","address":"0x4024f1","name":"main"}
<- {"success":true}
```

## Dispatch

`"procedure"` -> `procedures.ghidra.app.cmd.function.<procedure>Handler`. All 36
handlers are pre-registered (compile-time linkage); unknown names fall back to
reflection (drop-in `<Name>Handler.java`). Unknown procedure / malformed JSON / a
missing field each return an error and keep the connection open.

## Program selection

**The server starts with ZERO programs open** and is not bound to any one program: it
opens each request's target on demand. For a procedure with `needsProgram()` true (every
current one), `dispatch` reads the mandatory `"program"` path, resolves it against the
project (`ProjectData.getFile(path)`, else a recursive name search), checks the versioned
file out (exclusive) **before** opening it, then opens it —
`DomainFile.getDomainObject(consumer, upgrade, recover, monitor)` — caching the instance
in `RpcContext` keyed by canonical path. The resolved program becomes the request's
**active program**; all resolvers (`requireAddress`, `requireFunctionAt`, `applyCommand`,
...) operate on it, so handlers never name the program themselves. On shutdown
`closeAll()` releases every program the server opened. Procedures that act on the whole
project rather than one program (e.g. `ProgramLoader`) set `needsProgram()` false and take
no `"program"` field; `RpcContext.project()` gives them the project.

There is no seeded/launcher program: `analyzeHeadless` is run as a **`-preScript` with
no `-process`** (a pre-script runs once even when no program is processed; a post-script
would not run at all), so `currentProgram` is null and the cache begins empty — see the
launcher section.

## Synchronization (precise)

* **Sockets:** one daemon thread per client — concurrent at the I/O layer.
* **Program access:** a single `ReentrantLock` in `RpcContext` serializes the **entire
  request lifecycle** — program resolution (open/cache), checkout, the procedure's
  mutation (inside a program transaction), and the check-in — so those steps are atomic
  with respect to
  other clients; no other client can interleave a read or write between them. Ghidra's
  program DB is not safe for concurrent mutation, so procedures effectively run one at a
  time. The lock is reentrant so `applyCommand`/`runWrite` can open nested program
  transactions. Program transactions (`startTransaction`/`endTransaction`) are a
  separate Ghidra mechanism, always entered while holding the lock.

## Checkout / check-in policy

* **Every procedure checks the file out first** (inside `RpcContext.openProgram`, before
  `getDomainObject`): if the versioned file is not already checked out, it takes an
  exclusive checkout. No-op for an already-checked-out or non-versioned file. Checkout
  MUST precede the open — a versioned file opened while not checked out yields a read-only
  in-memory Program whose check-in fails.
* **Every successful mutating procedure is checked in immediately**
  (`RpcContext.checkin`): `save()` then `DomainFile.checkin(...)` with
  `keepCheckedOut=true`, pushing a new server version visible to other clients at once.
  **If the push fails the whole call fails** and returns
  `{"success":false,"error":"Check-in/push failed: ..."}`. All function-cmd handlers
  are mutating (`RpcProcedure.mutates()` defaults true).
* The headless enclosing transaction is ended at startup (`endEnclosingTransaction`)
  so per-request check-ins land mid-session.

## Procedure execution

Each handler: parse JSON -> resolve args via `RpcContext` helpers
(`requireAddress`, `addressSet`, `requireDataType`, `requireRegister`,
`requireFunctionAt`, `requireVariable`, `sourceType`, `parseSignature`,
`serviceProvider`, `openedDecompiler`) -> construct the Ghidra `Command` -> hand it to
`RpcContext.applyCommand`, which runs it in a transaction (`BackgroundCommand`s get the
monitor) and maps the boolean result + `getStatusMsg()` to the response. Bad input
throws `IllegalArgumentException`, surfaced as the error message.

## Procedures (38 total)

All non-deprecated, concrete `Command`s in `ghidra.app.cmd.function` (36). The four
**deprecated** ones are intentionally excluded: `AddParameterCommand`,
`AddRegisterParameterCommand`, `AddStackParameterCommand`, `AddMemoryParameterCommand`
(use `UpdateFunctionCommand` instead). Plus two procedures outside that package
(pre-registered in `RpcServer`, since the reflection fallback only covers
`ghidra.app.cmd.function`):
* `FlatDecompilerAPI` — decompile a function to C (program-level, read-only).
* `ProgramLoader` — import a new program from base64 bytes in the request (PROJECT-level:
  `needsProgram()` false, no `"program"` field; saves + adds to version control itself).
  Wraps the `ProgramLoader` builder (the older `AutoImporter` is deprecated).
Per-procedure request specs (TypeScript interfaces) live in
`/workdir/notes/procedures/<Cmd>.md`.

Notes on a few that need more than plain values:
* `ApplyFunctionSignatureCmd` / `UpdateFunctionCommand` — signature/return/params are
  parsed from C strings / data-type names via `FunctionSignatureParser` + `DataTypeParser`.
* `CreateFunctionDefinitionCmd` — needs a `ServiceProvider`; a stub is supplied
  (headless has no DataType GUI services, so this may be limited).
* `ApplyFunctionDataTypesCmd` / `CaptureFunctionDataTypesCmd` — use the program's own
  data type manager as source/destination (no external archives are opened headless).
* `Decompiler*Cmd` — a `DecompInterface` is opened on the program (and the function
  decompiled for `DecompilerSwitchAnalysisCmd`) and disposed after the call.

## Configuration / running

Launcher env (see `ghidra-headless.sh`): `GHIDRA_ADDRESS` (host[:port]),
`GHIDRA_PROJECT`, `GHIDRA_USER`, `GHIDRA_PASSWORD`. Optional: `GHIDRA_PROGRAM`
(default none → zero programs; set it to also `-process` a specific program, or
`__recursive__` for all), `GHIDRA_READONLY=1` (read-only diagnostics),
`GHIDRA_COMMIT_MSG` (auto-`-commit`, only meaningful alongside `GHIDRA_PROGRAM`).
Server env: `RPC_BIND` (default 0.0.0.0), `RPC_PORT` (default 18000).

**Launch model (verified):** the launcher runs `RpcServer.java` as a **`-preScript`
with no `-process`** and **no mode flag**, so the server starts with **zero programs**
on a **writeable** project:
* `-preScript` (not `-postScript`) so the script runs once even though no program is
  processed — a post-script only runs per processed program.
* **No `-readOnly`**: that opens the *project* read-only and per-request checkout fails
  with `"checkout permitted in writeable project only"`. **No `-commit`** either: it only
  auto-commits *processed* programs (there are none); persistence is the server's own
  per-request check-ins. The default project mode (no flag) is writeable, which is what
  per-request checkout/check-in needs.

```bash
# zero-program server (opens targets on demand by path)
GHIDRA_ADDRESS=ghidra.stronk.pw GHIDRA_PROJECT=P3 GHIDRA_USER=claude \
GHIDRA_PASSWORD=... RPC_PORT=18080 ./ghidra-headless.sh
```

## Container image

`ghidrascript/Dockerfile` + `.dockerignore` package Ghidra + JDK 21 + these scripts into
one image that runs the server. Build **context = `ghidrascript/`** (so `.dockerignore`
applies and the scripts are the only `COPY` source); Ghidra is downloaded in the image
(pinned `12.1.2_PUBLIC_20260605`, overridable via `--build-arg GHIDRA_URL=...` /
`GHIDRA_SHA256=...`). The remote server target + credentials are supplied at run time.

**Signal handling:** PID 1 is `tini -g` (`ENTRYPOINT ["/usr/bin/tini","-g","--","bash",…]`).
Ghidra's launcher chain never execs (`analyzeHeadless` → `launch.sh` → `java`, each a child),
so the JVM is a great-grandchild of the entrypoint. A bare `bash` entrypoint would NOT
forward `SIGTERM` to it (verified: SIGTERM to the entrypoint bash leaves the JVM orphaned and
running — and as PID 1 bash ignores SIGTERM outright), so `docker stop` would burn the grace
period then SIGKILL. `tini -g` forwards the signal to the whole process group, which the JVM
shares, so it exits cleanly (verified: a group-directed SIGTERM tears down the entire tree
including the JVM). Plain `docker run --init` is NOT enough — it signals only tini's direct
child, not the group.

```bash
docker build -t ghidra-rpc /workdir/ghidrascript
docker run --rm -p 18000:18000 \
  -e GHIDRA_ADDRESS=ghidra.stronk.pw:13100 -e GHIDRA_PROJECT=P3 \
  -e GHIDRA_USER=claude -e GHIDRA_PASSWORD=... ghidra-rpc
```

## Verification

Compiles cleanly against Ghidra 12.1.2 jars (`RpcServer.java` + all 36 handlers, 0
errors). Live-tested against `P3/Mapeditor.exe`:

* `SetFunctionNameCmd`, `ApplyFunctionSignatureCmd`, `SetReturnDataTypeCmd`,
  `AddFunctionTagCmd`, `FunctionStackAnalysisCmd`, `SetVariableNameCmd`,
  `CreateFunctionTagCmd`, `UpdateFunctionCommand`, `DecompilerSwitchAnalysisCmd` all
  returned success;
* a fresh **independent read-only client** confirmed the edits persisted on the server
  (`name=fn_cmd_rpc_test returnType=undefined4 params=2 tags=[RPC_TAG]`) — i.e. the
  per-command check-in pushed each change;
* error paths: missing field, no-such-procedure, and an unparseable signature
  (`"Can't find function name"`) all returned clean errors with the connection intact.

**ProgramLoader (verified live, 2026-06-17, P3):** uploaded a real ELF as base64 →
imported to `/imports/rpc_pl_test.bin` with `format="Executable and Linking Format (ELF)"`,
added to version control (v1), confirmed by an independent JVM. A name collision
auto-uniquified to `…/rpc_pl_test.bin.0` (no failure). Error paths clean: missing `bytes`,
and un-loadable content → `"No load spec found"`. Test imports deleted (`CleanImports.java`);
P3 back to just `Mapeditor.exe`.

No deprecated Ghidra APIs are used: all 42 sources compile clean under
`javac -Xlint:deprecation`. The original `AutoImporter` was deprecated, so this wraps the
`ProgramLoader` builder instead. Two gotchas: `ProgramLoader.builder().load(Object)` is the
deprecated overload — use the no-arg `load()`; and `Loaded.getDomainObject()` (no-arg) is
deprecated-for-removal — use `Loaded.apply(Consumer<Program>)`. The `source(byte[])`
overload leaves the `ByteProvider` name null, which NPEs filename-sniffing loaders
(GZF/GDT/Tenet), so a named `ByteArrayProvider(name, bytes)` is passed via
`source(ByteProvider)` (and `name()` sets a clean program name — no byte-range suffix).

**Zero-program launch (verified live, 2026-06-17, P3):** server started with the
launcher (`-preScript`, no `-process`, writeable project) reporting `0 programs open`.
Targeting `/Mapeditor.exe` on demand: read decompile OK; `SetFunctionNameCmd` rename
succeeded and the check-in **pushed v21→v22→v23** (confirmed by an independent JVM).
Error cases clean (missing/unknown `"program"`, bare-name resolution). The per-request
checkout is **TRANSIENT** (session-scoped): after the server JVM exits the repo shows
`checkouts=none`, so the zero-program server leaves **no stale checkout** — an
improvement over the old commit-mode trigger.

Note: first start after a code change recompiles the OSGi script bundle (slow, ~1–2
min). If the bundle cache wedges, clear
`/root/.config/ghidra/<ver>/osgi/{felixcache,compiled-bundles}/*`.
