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
| `/workdir/ghidrascript/ghidra-headless.sh` | headless launcher (env-driven) |
| `/workdir/testscripts/rpc_client.py` | ndjson test client |
| `/workdir/testscripts/VerifyFnCmd.java` | read-only persistence checker |
| `/workdir/notes/procedures/<Cmd>.md` | one doc per command, request as a TypeScript interface |

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
project rather than one program (e.g. a future binary-import RPC) set `needsProgram()`
false and take no `"program"` field.

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

## Procedures (wrapped Ghidra commands)

All non-deprecated, concrete `Command`s in `ghidra.app.cmd.function` (36). The four
**deprecated** ones are intentionally excluded: `AddParameterCommand`,
`AddRegisterParameterCommand`, `AddStackParameterCommand`, `AddMemoryParameterCommand`
(use `UpdateFunctionCommand` instead). Per-command request specs (TypeScript
interfaces) live in `/workdir/notes/procedures/<Cmd>.md`.

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
