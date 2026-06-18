# `ghidra-headless-cli` — Rust client for the RPC server

A small, synchronous, dependency-light Rust CLI that talks to the Ghidra TCP
ndjson RPC server (see [rpc-server.md](rpc-server.md)). One invocation = one
request = one response. Subcommands mirror the server's 39 procedures, grouped by
the area they act on. Function-scoped operations are nested under `function`:
tags under `function tag` and variable operations under `function variable`.

## Location & build

* Source: `/workdir/ghidra-headless-cli/` (cargo crate `ghidra-headless-cli`).
* Toolchain lives under `/workdir/.cargo` + `/workdir/.rustup` (so it survives the
  container). Export before building:
  ```bash
  export RUSTUP_HOME=/workdir/.rustup CARGO_HOME=/workdir/.cargo PATH=/workdir/.cargo/bin:$PATH
  cd /workdir/ghidra-headless-cli && cargo build --release
  ```
* Binary: `target/release/ghidra-headless-cli`.

## Dependencies

Deliberately minimal (the task asked to avoid dependencies; no async, no serde):
`clap` (derive, subcommands), `log`, `simple_logger`. JSON serialization and
parsing are hand-rolled in `src/json.rs`; base64 (for `program load`) in
`src/common.rs`.

## Source layout

| file | role |
|------|------|
| `src/main.rs` | clap top-level parser, logger init, dispatch to a group |
| `src/client.rs` | TCP ndjson transport: `call` (one request/response), `invoke` (logs server/transport errors, gates on `success`), `run_simple` |
| `src/json.rs` | `Json` value, compact serializer (`Display`), recursive-descent parser, `Req` request builder (only emits supplied optional fields) |
| `src/common.rs` | shared clap value types (`Source`), `address_set`/`parameters` builders, base64, arg-error logging |
| `src/commands/*.rs` | one module per command group (see below); each has a clap `Subcommand` enum and a `run` fn |

## Global options

These two are the only short flags (the task's stated exceptions to the
"no shorthand" rule); every per-command argument is long-only.

| flag | meaning |
|------|---------|
| `-H`, `--host <HOST>` | RPC server `host:port` (default `127.0.0.1:18000`). Global. |
| `-v`, `--verbose...` | repeatable. 0 = `info` (default), `-v` = `debug`, `-vv` = `trace` (logs the raw ndjson request `->` and response `<-`). Global. |

## Output & exit codes

* **stdout** carries command *data* only (decompiled C source, disassembly
  listing); logs go to **stderr** — so `function decompile … > out.c` yields clean
  source.
* Status, results summaries, and errors are emitted via `log` to stderr.
* Exit `0` on `success:true`; exit `1` on any transport error, malformed
  response, client-side argument error, or a `success:false` reply.
* Server error messages are emitted **verbatim** (no post-processing) at the
  `error` level.

## Argument conventions

* `--source <user-defined|analysis|imported|default>` maps to the wire
  `SourceType` (`USER_DEFINED`, …). Omit to let the server default
  (`USER_DEFINED`) apply.
* Optional fields are sent **only when given**, so the server's documented
  defaults always apply when a flag is omitted. Boolean options take an explicit
  value: `--force true`, `--create-bookmarks false`. Every optional flag's
  `--help` line ends with the effective default it falls back to (e.g.
  `[default: user-defined]`, `[default: true]`, `[default: 0 = unlimited]`),
  matching the server-side defaults in `notes/procedures/<Cmd>.md`.
* Address sets: `--address <hex>` (single) **or** `--address-set <START[:END]>`
  (repeatable). At least one is required client-side; each `--address-set` entry
  becomes `{start[,end]}`. Example: `--address-set 0x401000:0x401050 --address-set 0x402000`.
* `function update --parameter <[NAME=]DATATYPE>` (repeatable):
  `--parameter "count=int" --parameter "void *"` →
  `[{name:"count",dataType:"int"},{dataType:"void *"}]`.
* `program load --file <PATH>` reads the local file and base64-encodes it into
  the request's `bytes`.

## Command groups → procedures

| group / subcommand | procedure |
|--------------------|-----------|
| `function create` | CreateFunctionCmd |
| `function create-multiple` | CreateMultipleFunctionsCmd |
| `function create-thunk` | CreateThunkFunctionCmd |
| `function create-external` | CreateExternalFunctionCmd |
| `function create-definition` | CreateFunctionDefinitionCmd |
| `function delete` | DeleteFunctionCmd |
| `function set-name` | SetFunctionNameCmd |
| `function set-return-type` | SetReturnDataTypeCmd |
| `function apply-signature` | ApplyFunctionSignatureCmd |
| `function update` | UpdateFunctionCommand |
| `function set-varargs` | SetFunctionVarArgsCommand |
| `function set-purge` | SetFunctionPurgeCommand |
| `function set-repeatable-comment` | SetFunctionRepeatableCommentCmd |
| `function tag create` | CreateFunctionTagCmd |
| `function tag delete` | DeleteFunctionTagCmd |
| `function tag change` | ChangeFunctionTagCmd |
| `function tag add` | AddFunctionTagCmd |
| `function tag remove` | RemoveFunctionTagCmd |
| `function variable add-stack` | AddStackVarCmd |
| `function variable add-register` | AddRegisterVarCmd |
| `function variable add-memory` | AddMemoryVarCmd |
| `function variable delete` | DeleteVariableCmd |
| `function variable set-name` | SetVariableNameCmd |
| `function variable set-type` | SetVariableDataTypeCmd |
| `function variable set-comment` | SetVariableCommentCmd |
| `stack set-depth-change` | SetStackDepthChangeCommand |
| `stack remove-depth-change` | RemoveStackDepthChangeCommand |
| `analysis stack` | FunctionStackAnalysisCmd |
| `analysis stack-new` | NewFunctionStackAnalysisCmd |
| `analysis stack-result-state` | FunctionResultStateStackAnalysisCmd |
| `analysis purge` | FunctionPurgeAnalysisCmd |
| `analysis decompiler-param-id` | DecompilerParameterIdCmd |
| `analysis decompiler-switch` | DecompilerSwitchAnalysisCmd |
| `analysis decompiler-convention` | DecompilerParallelConventionAnalysisCmd |
| `function decompile` | FlatDecompilerAPI |
| `function disassemble` | Disassemble |
| `function find-by-name` | FindFunctionsByName |
| `function find-by-tag` | FindFunctionsByTag |
| `datatype apply-function` | ApplyFunctionDataTypesCmd |
| `datatype capture-function` | CaptureFunctionDataTypesCmd |
| `program load` | ProgramLoader |
| `program analyze` | Analyze |

Per-procedure request/response field specs live in
`/workdir/notes/procedures/<Cmd>.md`.

## Examples

```bash
BIN=/workdir/ghidra-headless-cli/target/release/ghidra-headless-cli

# Decompile to clean C on stdout (logs on stderr)
$BIN --host 127.0.0.1:18000 function decompile --program /Mapeditor.exe --address 0x4024f1 > fn.c

# Disassemble a function (one "<address>  <bytes>  <repr>" line per instruction on stdout)
$BIN --host 127.0.0.1:18000 function disassemble --program /Mapeditor.exe --address 0x4024f1
$BIN --host 127.0.0.1:18000 function disassemble --program /Mapeditor.exe --address 0x4024f1 --bytes false

# Find functions by name ("<address>  <name>" per match); substring, regex, or case-insensitive
$BIN --host 127.0.0.1:18000 function find-by-name --program /Mapeditor.exe --query fn_cmd
$BIN --host 127.0.0.1:18000 function find-by-name --program /Mapeditor.exe --query "^FUN_0040" --regex true --limit 50

# Find functions by tag ("<address>  <name>  [tag,...]" per match)
# Plain query = EXACT tag name ("has this tag"); use --regex for a substring/pattern.
$BIN --host 127.0.0.1:18000 function find-by-tag --program /Mapeditor.exe --query RPC_TAG
$BIN --host 127.0.0.1:18000 function find-by-tag --program /Mapeditor.exe --query RPC --regex true

# Rename a function (mutating: checked out, checked in on success)
$BIN --host 127.0.0.1:18000 function set-name \
  --program /Mapeditor.exe --address 0x401000 --name main --source user-defined

# Update a signature in one shot
$BIN --host 127.0.0.1:18000 function update --program /Mapeditor.exe --address 0x401000 \
  --calling-convention __stdcall --return-type int \
  --parameter "count=int" --parameter "void *" --update-type dynamic-storage-formal-params

# Stack analysis over a range, with raw ndjson tracing
$BIN -vv --host 127.0.0.1:18000 analysis stack \
  --program /Mapeditor.exe --address-set 0x401000:0x401050 --force-processing true

# Import a local binary, then analyze it
$BIN --host 127.0.0.1:18000 program load --name foo.exe --file ./foo.exe --folder /imports
$BIN --host 127.0.0.1:18000 program analyze --program /imports/foo.exe --force true
```

## Verification (2026-06-17, live against P3 @ ghidra.stronk.pw)

* Read-only `function decompile /Mapeditor.exe 0x4024f1` → exit 0, full C source on stdout
  (escaped newlines/quotes parsed correctly by the hand-rolled JSON parser),
  status logs on stderr.
* Read-only `function disassemble /Mapeditor.exe 0x4024f1` → exit 0, 34 instructions on
  stdout with `CodeUnitFormat`-resolved operands (e.g. `CALL dword ptr
  [PTR_LoadLibraryA_004c0ca4]`, `JMP FUN_004100b0`); `--bytes false` drops the bytes
  column; bad address → `No function at deadbeef.` verbatim, exit 1.
* Read-only `function find-by-name`/`find-by-tag` on /Mapeditor.exe → name substring `fn_cmd`
  found `fn_cmd_rpc_test`; `--ignore-case` matched `entry`; `--regex` anchoring works. Tag
  search is EXACT by default: `--query RPC` → 0, `--query RPC_TAG` → `fn_cmd_rpc_test
  [RPC_TAG]`, `--query RPC --regex true` → match. An invalid regex → `Invalid regex: …`
  verbatim, exit 1.
* Mutating `function set-repeatable-comment` → `success`, exit 0 (server checked
  the new version in); reset afterward.
* Error paths: bad address → `No function at deadbeef.`; unknown program →
  `No program found for '/NoSuchProgram.exe'.` — both verbatim, exit 1.
* Mock server (`/workdir/testscripts/mock_rpc_server.py`) covers connection
  refused (exit 1), `success`/`error` modes, `-vv` raw ndjson, address-set and
  parameter encoding, client-side address validation, and base64 of `program load`.
