# `ghidra-headless-cli` — Rust client for the RPC server

A small, synchronous, dependency-light Rust CLI that talks to the Ghidra TCP
ndjson RPC server (see [rpc-server.md](rpc-server.md)). One invocation = one
request = one response. Subcommands mirror the server's 96 procedures (92
pre-registered + 4 reflection-loaded class-management verbs), grouped by
the area they act on. Function-scoped operations are nested under `function`:
tags under `function tag`, variable operations under `function variable`,
data-type apply/capture under `function apply-types`/`function capture-types`.
Comment operations are nested under `comment`: each of the 6 Ghidra comment types
(EOL/PRE/POST/PLATE/REPEATABLE/DECOMPILER) gets its own subcommand, and each
type has `get`/`set`/`append`/`clear` ops. Data-type management (list / show /
create / replace / edit / delete) lives under `datatype`. Laying a type at an
address (`apply`) is a memory operation and lives under `memory apply-type`.

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
parsing are hand-rolled in `src/json.rs`; base64 (for `file load`) in
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
* `file load --file <PATH>` reads the local file and base64-encodes it into
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
| `function set-class-association` | FunctionSetClassAssociation |
| `function set-namespace` | FunctionSetNamespace |
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
| `function find` | FindFunction (--query required; --name/--tag/--address mutually-exclusive scoping) |
| `function apply-data-types` | ApplyFunctionDataTypesCmd |
| `function capture-data-types` | CaptureFunctionDataTypesCmd |
| `file load` | ProgramLoader |
| `file analyze` | Analyze |
| `file list` | ListFiles |
| `file metadata` | FileMetadata |
| `comment eol get` | EolGet |
| `comment eol set` | EolSet |
| `comment eol append` | EolAppend |
| `comment eol clear` | EolClear |
| `comment pre get` | PreGet |
| `comment pre set` | PreSet |
| `comment pre append` | PreAppend |
| `comment pre clear` | PreClear |
| `comment post get` | PostGet |
| `comment post set` | PostSet |
| `comment post append` | PostAppend |
| `comment post clear` | PostClear |
| `comment plate get` | PlateGet |
| `comment plate set` | PlateSet |
| `comment plate append` | PlateAppend |
| `comment plate clear` | PlateClear |
| `comment repeatable get` | RepeatableGet |
| `comment repeatable set` | RepeatableSet |
| `comment repeatable append` | RepeatableAppend |
| `comment repeatable clear` | RepeatableClear |
| `comment decompiler get` | DecompilerGet |
| `comment decompiler set` | DecompilerSet |
| `comment decompiler append` | DecompilerAppend |
| `comment decompiler clear` | DecompilerClear |
| `datatype list` | ListDataTypes |
| `datatype show` | ShowDataType |
| `datatype create` | CreateDataType (supports `--definition`) |
| `datatype replace` | ReplaceDataType (supports `--path`; GUI "Replace..." semantic) |
| `datatype edit` | EditDataType (supports `--definition`) |
| `datatype set-field-comment` | SetDataTypeFieldComment |
| `datatype set-variant-comment` | SetDataTypeVariantComment |
| `datatype set-field-type` | SetDataTypeFieldType (per-field retype; `--force` for grow/shrink) |
| `datatype set-field-name` | SetDataTypeFieldName (per-field rename) |
| `datatype delete` | DeleteDataType |
| `xrefs` | GetXrefs |
| `import` | GetImports |
| `export` | GetExports |
| `callgraph` | Callgraph |
| `memory create-label` | CreateLabel |
| `memory rename-label` | RenameLabel |
| `memory delete-label` | DeleteLabel |
| `memory set-primary` | SetPrimary |
| `memory list-label` | ListLabels |
| `memory lookup-label` | LookupLabel |
| `memory get-label` | GetLabel |
| `memory read-bytes` | ReadBytes |
| `memory apply-type` | ApplyDataType |
| `memory undefine` | ClearCodeUnits |
| `string search` | SearchStrings |
| `string get` | GetString |
| `string define` | DefineString |
| `string delete` | DeleteString |
| `namespace create-class` | NamespaceCreateClass |
| `namespace rename-class` | NamespaceRenameClass |
| `namespace delete-class` | NamespaceDeleteClass |
| `namespace get-class` | NamespaceGetClass |
| `namespace list-class` | NamespaceListClasses |

Per-procedure request/response field specs live in
`/workdir/notes/procedures/<Cmd>.md`.

## Examples

```bash
BIN=/workdir/ghidra-headless-cli/target/release/ghidra-headless-cli

# Decompile to clean C on stdout (logs on stderr)
$BIN --host 127.0.0.1:18000 function decompile --file /Mapeditor.exe --address 0x4024f1 > fn.c

# Disassemble a function (one "<address>  <bytes>  <repr>" line per instruction on stdout)
$BIN --host 127.0.0.1:18000 function disassemble --file /Mapeditor.exe --address 0x4024f1
$BIN --host 127.0.0.1:18000 function disassemble --file /Mapeditor.exe --address 0x4024f1 --bytes false

# Find functions by name, tag, or address. --query is required. The scoping
# flags --name / --tag / --address are mutually exclusive; without one, the
# query is matched against names AND tags AND addresses ("everything" default).
# Output: "<address>  <name>" per match (with "  [tag,...]" when the function has tags).

# Name scope (substring against qualified "ns::leaf" by default; regex with --regex):
$BIN --host 127.0.0.1:18000 function find --file /Mapeditor.exe --query fn_cmd --name
$BIN --host 127.0.0.1:18000 function find --file /Mapeditor.exe --query "^FUN_0040" --name --regex true --limit 50

# Tag scope (substring against tag names; substring default differs from the old
# find-by-tag which was always exact — see notes/procedures/FindFunction.md):
$BIN --host 127.0.0.1:18000 function find --file /Mapeditor.exe --query RPC --tag
$BIN --host 127.0.0.1:18000 function find --file /Mapeditor.exe --query RPC --tag --regex true

# Address scope (single-function lookup; uses getFunctionContaining then
# getFunctionAt — handles mid-function code pointers):
$BIN --host 127.0.0.1:18000 function find --file /Patrician3.exe --query 0x0064F2C1 --address

# `--ignore-case true` is long-only (no `-i` short — the project's
# shorthand policy reserves shorts for `-H` and `-v` only). Without
# it the match is case-sensitive, so `--query ENTRY --name` finds nothing
# for a leaf named `entry`:
$BIN --host 127.0.0.1:18000 function find --file /Mapeditor.exe --query ENTRY --name --ignore-case true --limit 5

# Everything scope (the new default — searches names AND tags AND addresses):
$BIN --host 127.0.0.1:18000 function find --file /Mapeditor.exe --query RPC

# Rename a function (mutating: checked out, checked in on success)
$BIN --host 127.0.0.1:18000 function set-name \
  --file /Mapeditor.exe --address 0x401000 --name main --source user-defined

# Update a signature in one shot
$BIN --host 127.0.0.1:18000 function update --file /Mapeditor.exe --address 0x401000 \
  --calling-convention __stdcall --return-type int \
  --parameter "count=int" --parameter "void *" --update-type dynamic-storage-formal-params

# Set calling convention to __thiscall on a member function. NOTE:
# `__thiscall` carries an IMPLICIT `this` in ECX (RCX on x64) that
# this API cannot retype. Do NOT pass `this` in --parameter — it is
# not a real parameter; the ABI places it in a register. To TYPE
# `this` (give it a class pointer type like `BennitestStub *`),
# create a class with `namespace create-class` then use
# `function set-class-association` (see its --help). After
# `function update --calling-convention __thiscall`, the decompile
# header reads `void __thiscall thunk_FUN_00419580(void *this,
# int param_1)` — `this` is auto-added and the call site pushes
# the actual `this` value into ECX/RCX. List your --parameter
# entries excluding `this`:
$BIN --host 127.0.0.1:18000 function update --file /Mapeditor.exe --address 0x0040100a \
  --calling-convention __thiscall --return-type void --parameter "int" \
  --update-type dynamic-storage-formal-params
# Verify: $BIN function decompile --file /Mapeditor.exe --address 0x0040100a
#   -> "void __thiscall thunk_FUN_00419580(void *this, int param_1) { ... }"

# Stack analysis over a range, with raw ndjson tracing
$BIN -vv --host 127.0.0.1:18000 analysis stack \
  --file /Mapeditor.exe --address-set 0x401000:0x401050 --force-processing true

# Import a local binary, then analyze it
$BIN --host 127.0.0.1:18000 file load --name foo.exe --file ./foo.exe --folder /imports
$BIN --host 127.0.0.1:18000 file analyze --file /imports/foo.exe --force true

# Manage comments: per-type get/set/append/clear
$BIN --host 127.0.0.1:18000 comment eol get    --file /Mapeditor.exe --address 0x4024f1
$BIN --host 127.0.0.1:18000 comment pre set    --file /Mapeditor.exe --address 0x4024f1 --text "loop entry"
$BIN --host 127.0.0.1:18000 comment post append --file /Mapeditor.exe --address 0x4024f1 --text "fallthrough"
$BIN --host 127.0.0.1:18000 comment plate clear --file /Mapeditor.exe --address 0x4024f1
$BIN --host 127.0.0.1:18000 comment decompiler set --file /Mapeditor.exe --address 0x4024f1 --text "int main(int argc, char **argv)"
```
