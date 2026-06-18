# `ghidra-headless-cli` — Rust client for the RPC server

A small, synchronous, dependency-light Rust CLI that talks to the Ghidra TCP
ndjson RPC server (see [rpc-server.md](rpc-server.md)). One invocation = one
request = one response. Subcommands mirror the server's 44+24+6 procedures, grouped by
the area they act on. Function-scoped operations are nested under `function`:
tags under `function tag`, variable operations under `function variable`,
data-type apply/capture under `function apply-types`/`function capture-types`.
Comment operations are nested under `comment`: each of the 6 Ghidra comment types
(EOL/PRE/POST/PLATE/REPEATABLE/DECOMPILER) gets its own subcommand, and each
type has `get`/`set`/`append`/`clear` ops. Data-type management (list / show /
create / edit / delete / apply) lives under `datatype`.

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
| `datatype edit` | EditDataType (supports `--definition`) |
| `datatype delete` | DeleteDataType |
| `datatype apply` | ApplyDataType |
| `xrefs` | GetXrefs |
| `imports` | GetImports |
| `exports` | GetExports |
| `memory create-label` | CreateLabel |
| `memory rename-label` | RenameLabel |
| `memory delete-label` | DeleteLabel |
| `memory set-primary` | SetPrimary |
| `memory list-labels` | ListLabels |
| `memory lookup-label` | LookupLabel |
| `memory get-label` | GetLabel |
| `memory read-bytes` | ReadBytes |
| `string search` | SearchStrings |
| `string get` | GetString |
| `string define` | DefineString |
| `string delete` | DeleteString |

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

# Find functions by name ("<address>  <name>" per match); substring, regex, or case-insensitive
$BIN --host 127.0.0.1:18000 function find-by-name --file /Mapeditor.exe --query fn_cmd
$BIN --host 127.0.0.1:18000 function find-by-name --file /Mapeditor.exe --query "^FUN_0040" --regex true --limit 50

# Find functions by tag ("<address>  <name>  [tag,...]" per match)
# Plain query = EXACT tag name ("has this tag"); use --regex for a substring/pattern.
$BIN --host 127.0.0.1:18000 function find-by-tag --file /Mapeditor.exe --query RPC_TAG
$BIN --host 127.0.0.1:18000 function find-by-tag --file /Mapeditor.exe --query RPC --regex true

# Rename a function (mutating: checked out, checked in on success)
$BIN --host 127.0.0.1:18000 function set-name \
  --file /Mapeditor.exe --address 0x401000 --name main --source user-defined

# Update a signature in one shot
$BIN --host 127.0.0.1:18000 function update --file /Mapeditor.exe --address 0x401000 \
  --calling-convention __stdcall --return-type int \
  --parameter "count=int" --parameter "void *" --update-type dynamic-storage-formal-params

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

## Verification (2026-06-18, live against P3 @ ghidra.stronk.pw)

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
* Data-type management: `datatype create --definition`, `--fields`, `--base`,
  `--enum-size`; `datatype edit --definition`, `--add-fields`, `--replace-fields`.
  `--definition` requires a NAMED C snippet — `struct Foo { … };`, not
  `struct { … };`. Anonymous snippets return `C snippet must define a
  NAMED type. Got an anonymous struct/union/enum body — write e.g.
  `struct Foo { int x; };` with an identifier.` On `create`, `--kind`
  and `--name` are optional when `--definition` is given (the parsed
  type's name is used). On `edit`, the snippet's name must equal the
  target's `path` last segment; mismatches return
  `C snippet name 'X' does not match target 'Y'. The snippet must
  declare the target's name (e.g. `struct Y { ... };`).` On the server
  side, the C snippet is parsed by Ghidra's `CParser` directly into the
  program DTM. `create` uses `DEFAULT_HANDLER` and FAILS on a name
  collision (`Data type /Y/Foo already exists.`); `datatype replace` is
  the explicit `REPLACE_HANDLER` path that silently overwrites in place.
  On `edit`, `--definition` replaces the type's body wholesale. `kind`
  mismatch returns `C snippet kind 'X' does not match target 'Y'.`;
  bad parse returns `C parse error: …` verbatim.
* Cross-references: `xrefs --to <spec> --type function|symbol|address`.
  Resolved function/symbol/address (the target itself is echoed in the
  response so the caller can see what was hit) and listed every caller
  with ref type, operand index, offcut flag, and the enclosing function.
  `--type` defaults to `function`. Tested all three resolve modes against
  `/dt-1781777965 main` (resolved to `00101040`, returned the
  `_elfSectionHeaders` DATA ref at `00000310` op=0 and the external
  UNCONDITIONAL_CALL ref at `00001018`). Error paths: `--type foo` →
  `Invalid 'type' 'foo': must be function, symbol, or address.` (exit 1);
  unknown target → `No function matched 'NoSuchFunction'.` (exit 1);
  `--limit 1` → truncated, single ref returned.
* Imports: `imports --file <F> [--type function] [--limit N]`. Iterates
  `Program.getExternalManager().getExternalLocations(libraryName)` per
  library, returns each entry's name / EXTERNAL-space address / original
  imported name / source / isFunction. Default `type=all` includes both
  function and data imports. Ghidra's own `DEFAULT` stubs are filtered
  out so the response only contains symbols the binary actually pulled
  in (`IMPORTED`) or that the user later annotated (`USER_DEFINED`).
  Tested on `/noanno-1781782566`: 2 imports under `<EXTERNAL>` —
  `__libc_start_main` and `__cxa_finalize`, both `function`, both
  `IMPORTED`. `--type function` produces the same set (no data imports
  to filter). `--limit 1` → truncated after the first entry. Invalid
  `--type` → `Invalid 'type' 'foo': must be all or function.` (exit 1).
  Unknown program → `No program found for '/NoSuch'.` (exit 1).
* Exports: `exports --file <F> [--type function] [--limit N]`. Iterates
  `SymbolTable.getSymbolIterator()` in address order, filters
  `Symbol.isExternalEntryPoint() && Symbol.isPrimary()` (and rejects any
  address in EXTERNAL space, which would be an import not an export).
  Each row carries the in-program address (NOT `EXTERNAL:`), the
  `SymbolType` string, `isFunction`, and `isThunk`. Tested on
  `/noanno-1781782566`: 12 exports (7 functions + 5 labels) including
  `_init`, `main`, `_start`, `frame_dummy`, `add`, `_fini`, plus
  `_IO_stdin_used` / `data_start` / etc. as labels. `--type function`
  narrows to 7 rows. `--limit 1` → truncated, single export returned.
  Error paths identical to imports (`--type foo`, unknown program).
  Resolved function/symbol/address (the target itself is echoed in the
  response so the caller can see what was hit) and listed every caller
  with ref type, operand index, offcut flag, and the enclosing function.
  `--type` defaults to `function`. Tested all three resolve modes against
  `/dt-1781777965 main` (resolved to `00101040`, returned the
  `_elfSectionHeaders` DATA ref at `00000310` op=0 and the external
  UNCONDITIONAL_CALL ref at `00001018`). Error paths: `--type foo` →
  `Invalid 'type' 'foo': must be function, symbol, or address.` (exit 1);
  unknown target → `No function matched 'NoSuchFunction'.` (exit 1);
  `--limit 1` → truncated, single ref returned.
* Error paths: bad address → `No function at deadbeef.`; unknown program →
  `No program found for '/NoSuchProgram.exe'.` — both verbatim, exit 1.
* Mock server (`/workdir/testscripts/mock_rpc_server.py`) covers connection
  refused (exit 1), `success`/`error` modes, `-vv` raw ndjson, address-set and
  parameter encoding, client-side address validation, and base64 of `file load`.
* Memory subcommand: all 8 verbs tested live against `/Mapeditor.exe`.
  - `memory create-label --file /Mapeditor.exe --address 0x401000 --name g_tick`
    → label visible in subsequent `list-labels`; idempotent on re-run.
  - `memory list-labels --query dat` → 3 hits; `--limit 8` → 8 with `truncated=true`;
    `--query` optional (empty/missing matches all `SymbolType.LABEL`, excludes
    function entry-points / namespace labels / externals / dynamic).
  - `memory lookup-label --query data_start` → 2 symbols (`data_start`,
    `__data_start`) across all symbol types; `--address` narrows to a single
    address; `--regex true` / `--ignore-case true` work like `find-by-name`.
  - `memory get-label --address 0x401000` → `primary=data_start`,
    `all=[{data_start, primary:true}, {__data_start, primary:false}]`.
  - `memory set-primary --query __data_start --address 0x401000` promotes the
    secondary; second call → `'<name>' is already the primary label at <addr>.`
  - `memory rename-label --query g_tick --new-name g_frame` → exit 0;
    `--query no_such_label` → `No label matched 'no_such_label'.`; collision
    with existing name → `Duplicate name: 'g_frame' already exists.`.
  - `memory delete-label --query g_frame` → exit 0; deleting a function
    entry-point label → `'<name>' is a function entry-point label; use
    'function delete' to remove the function itself.`.
  - `memory read-bytes --address 0x401000 --length 16` (default `format=hex`)
    → `f3 0f 1e fa b8 03 00 00 00 c3 66 0f 1f 44 00 00`.
  - `memory read-bytes --address 0x401000 --length 32 --format dump` → 2 rows of
    16 bytes each with the 8/8 gutter and ASCII column aligned.
  - `memory read-bytes --length 100000` → `Length must be 1..65536.` (cap).
  - `memory read-bytes --address 0xDEADBEEF` → `Address not in any memory
    block: deadbeef.` (start-outside-block check).
  - `memory read-bytes --format banana` → `Invalid 'format' 'banana': must
    be hex or dump.` (exit 1).
* String subcommand: all 4 verbs (`search` / `get` / `define` / `delete`)
  tested live on P3. (The CLI group was renamed from `strings` to
  `string` (singular) to match the other verb-based groups: `function`,
  `memory`, `comment`, `datatype`, `stack`, `analysis`, `file`. The
  underlying RPC procedure names are unchanged: `SearchStrings`,
  `GetString`, `DefineString`, `DeleteString`.)
  - `string search --file /Mapeditor.exe` (no query) → 995 strings, mixed
    ASCII/UTF-8/UTF-16 (US-ASCII / `string`, UTF-8 / `string-utf8`, UTF-16 /
    `PascalUnicode`, etc.). Output: `<address>  <representation>  [N bytes,
    <charset>, <dataType>]`. The "no query" path is the canonical
    "list all" (the old `list-defined` verb was merged into `search`).
  - `string search --file /Mapeditor.exe --query Mapeditor` → 1 hit,
    `004c8274  u"Mapeditor"  [20 bytes, UTF-16, PascalUnicode]`.
  - `string search --file /Mapeditor.exe --query 'ELF|GNU' --regex true`
    on a small ELF → 5 hits including multiple `"GNU"` matches and a
    `__GNU_EH_FRAME_HDR` UTF-8 entry.
  - `string search --file /Mapeditor.exe --query error --ignore-case true
    --limit 5` → ERROR: DrawAt called for uninitialized Animation, NOTIFY:
    Error Loading Texture ID %d from File %s, etc.
  - `string search --file /Mapeditor.exe --query '^[A-Z]+$' --regex true
    --limit 5` → `MZ`, `PE`, `FALSE`, plus UTF-16 `ER` / `UF` PascalUnicode
    matches (regex matches the DECODED string, not raw bytes).
  - `string search --file /noanno-1781782566 --query '[unclosed' --regex
    true` → `Invalid regex: Unclosed character class near index 8` (exit 1).
  - `string search --file /noanno-1781782566 --address 0x100374` → exactly
    1 string at that address. `--address-set 0x100449:0x1004c0` → 8 strings
    in the data-section range.
  - `string get --file /noanno-1781782566 --address 0x100374` → ` `
    `/lib64/ld-linux-x86-64.so.2` `  [28 bytes, US-ASCII, TerminatedCString]`
    (full match shape echoed in `string`).
  - `string get --file /noanno-1781782566 --address 0x100001` → `no defined
    string at 00100001` (the ELF magic at 0x100000 is defined as a 4-byte
    `char[]` array, not an AbstractStringDataType, so a miss here is the
    correct behaviour).
  - `string define --file /Mapeditor.exe --address 0x0047ffd0 --kind
    cstring` → defined; `success`, exit 0. Commit pipeline runs end-to-end.
  - `string define --file /noanno-1781782566 --address 0x100220 --kind
    string` → `'length' is required for fixed-length kind 'string' (must
    be >= 1).` (exit 1).
  - `string define --file /Mapeditor.exe --address 0x0047ffd0 --kind
    banana` → `Unknown kind 'banana': must be cstring, string, utf8, utf16,
    unicode, pascal, pascal255.` (exit 1).
  - `string define --file /Mapeditor.exe --address 0xDEADBEEF --kind
    cstring` → `Could not create Data at address deadbeef` (unmapped).
  - `string define --file /NoSuchProgram --address 0x401000 --kind cstring`
    → `No program found for '/NoSuchProgram'.` (exit 1).
  - `string delete --file /Mapeditor.exe --address 0x0047ffd0` →
    `deleted string at 0047ffd0 (1 bytes, TerminatedCString)`. Follow-up
    `string get --address 0x0047ffd0` → `no defined string at 0047ffd0`
    (the `GetString` miss is now correctly null after a delete — without
    the `isString` guard the 1-byte undefined Data left behind by the
    delete would otherwise look like a hit with `dataType: "undefined"`).
  - Round-trip: `string define ... cstring` → `string delete` →
    `string define ... cstring` → `string delete` all succeed and net
    out to no change. After each delete, `string get` shows the miss.
  - `string delete --file /Mapeditor.exe --address 0x00401000` →
    `No defined data at 00401000.` (the address is code, not data).
  - `string delete --file /Mapeditor.exe --address 0xDEADBEEF` →
    `No defined data at deadbeef.` (unmapped).
  - `string delete --file /NoSuch --address 0x401000` →
    `No program found for '/NoSuch'.` (exit 1).
  - Old `strings` (plural) → clap rejects: `error: unrecognized
    subcommand 'strings'` with `tip: a similar subcommand exists:
    'string'`. Confirmed the rename is complete.
