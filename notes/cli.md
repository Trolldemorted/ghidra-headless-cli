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
| `datatype replace` | ReplaceDataType (supports `--path`; GUI "Replace..." semantic) |
| `datatype edit` | EditDataType (supports `--definition`) |
| `datatype delete` | DeleteDataType |
| `xrefs` | GetXrefs |
| `import` | GetImports |
| `export` | GetExports |
| `callgraph` | Callgraph |
| `memory create-label` | CreateLabel |
| `memory rename-label` | RenameLabel |
| `memory delete-label` | DeleteLabel |
| `memory set-primary` | SetPrimary |
| `memory list-labels` | ListLabels |
| `memory lookup-label` | LookupLabel |
| `memory get-label` | GetLabel |
| `memory read-bytes` | ReadBytes |
| `memory apply-type` | ApplyDataType |
| `memory undefine` | ClearCodeUnits |
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
  `--enum-size`; `datatype edit --definition`, `--add-fields`, `--replace-fields`;
  `datatype replace --path /X/Y --kind struct --fields ...` and
  `datatype replace --path /X/Y --definition 'struct Y { ... };'`.
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
  `datatype replace` also accepts `--path` (full path) instead of
  `--name`+`--category`; the two are mutually exclusive on the clap
  side. `--path` is the disambiguating form when the same name appears
  in multiple categories (as with archive stubs). Path errors: a
  relative path → `'path' must be absolute (start with '/'): 'X'.`;
  trailing-slash path → `'path' must end with a type name: '/X/'.`;
  nonexistent category → `No data-type category for '/X'.` Parent
  categories in `--path` are auto-created on the `replace` path (both
  C-snippet and explicit-JSON) — `replace --path /MyTest/Sub/Bar ...`
  creates `/MyTest/Sub` if it didn't exist. The C-snippet path
  re-parents the parsed type to match `--path` so
  `--path /MyTest/L_String --definition 'struct L_String { ... };'`
  lands at `/MyTest/L_String`, not at root. On `edit`,
  `--definition` replaces the type's body wholesale. `kind` mismatch
  returns `C snippet kind 'X' does not match target 'Y'.`; bad parse
  returns `C parse error: …` verbatim. Tested `datatype replace
  --path /CLIENT_ID --kind struct --fields '[...]'` and
  `datatype replace --path /L_String --definition 'struct L_String { ... };'`
  on `/Mapeditor.exe`: both replaced the existing entries; subsequent
  `datatype show` reflected the new fields.
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
* Import: `import --file <F> [--type function] [--limit N]`. Iterates
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
* Export: `export --file <F> [--type function] [--limit N]`. Iterates
  `SymbolTable.getSymbolIterator()` in address order, filters
  `Symbol.isExternalEntryPoint() && Symbol.isPrimary()` (and rejects any
  address in EXTERNAL space, which would be an import not an export).
  Each row carries the in-program address (NOT `EXTERNAL:`), the
  `SymbolType` string, `isFunction`, and `isThunk`. Tested on
  `/noanno-1781782566`: 12 exports (7 functions + 5 labels) including
  `_init`, `main`, `_start`, `frame_dummy`, `add`, `_fini`, plus
  `_IO_stdin_used` / `data_start` / etc. as labels. `--type function`
  narrows to 7 rows. `--limit 1` → truncated, single export returned.
  Error paths identical to import (`--type foo`, unknown program).
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
    Auto-generated `DAT_<addr>` placeholders are reachable via the
    dynamic-name probe (see `Memory.md` → `LookupLabel`), so a substring
    search for `DAT_` that matches one such label will surface it even
    though `list-labels` skips it.
  - `memory get-label --address 0x401000` → `primary=data_start`,
    `all=[{data_start, primary:true}, {__data_start, primary:false}]`.
  - `memory set-primary --query __data_start --address 0x401000` promotes the
    secondary; second call → `'<name>' is already the primary label at <addr>.`
  - `memory rename-label --query g_tick --name g_frame` → exit 0; the
    target name is `--name` (matching `create-label --name`; the server
    request field is still `newName`); `--query no_such_label` → `No label
    matched 'no_such_label'.`; collision with existing name → `Duplicate
    name: 'g_frame' already exists.`.
  - `memory delete-label --query g_frame` → exit 0; deleting a function
    entry-point label → `'<name>' is a function entry-point label; use
    'function delete' to remove the function itself.`.
  - `memory read-bytes --address 0x401000 --length 16` (default `format=hex`)
    → `f3 0f 1e fa b8 03 00 00 00 c3 66 0f 1f 44 00 00`.
  - `memory apply-type --type int --address 0x401000` → lays 4 bytes;
    `--length 1` → `Cannot override length for non-Dynamic type 'int'
    (4 bytes); 'length' is only honored for Dynamic types …`; `--length 4`
    (equal) silently accepts; `--type string --length 8` (Dynamic) → 8 bytes.
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

* Callgraph: `callgraph --file <F> [--function <name|0x...>]
  [--direction called|calling] [--depth 1..10] [--format mermaid|json]
  [--include-refs true|false]`. BFS-walks the call graph from a function
  in either direction up to `--depth` layers, default `called` at depth
  `2`. Output is Mermaid by default (`graph TD` for called, `graph BT`
  for calling), pipeable to any Mermaid renderer; `--format json`
  switches to a structured `nodes[]` / `edges[]` envelope. External
  callees render as leaf nodes (tinted `classDef leaf`) and are NOT
  recursed into. Cycle edges are emitted (not dropped) so loops are
  visible. Edge count is hard-capped at 5000; when hit, `truncated=true`
  is set in the response and the diagram is still well-formed. Read-only
  — no checkout/check-in cycle. The response deliberately does NOT
  carry `nodeCount` / `edgeCount` — the CLI derives them from the
  Mermaid source (count node-definition lines and `-->` / `-.->`
  arrows) or the JSON `nodes[]` / `edges[]` lengths, so both formats
  report the same number in the log line.
  - `--function 0x419580 --direction calling --depth 2 --format json`
    on `/Mapeditor.exe` → `2 nodes, 1 edges`. Edges: `thunk_FUN_00419580
    -> FUN_00419580 (UNCONDITIONAL_CALL)`. The single call site is the
    entry thunk.
  - `--function 0x419580 --direction called --depth 3 --include-refs
    true --format json` → `3 nodes, 3 edges`. Same root; the called walk
    reaches `chkesp` twice (one local, one external `EXTERNAL:000001cb`)
    and the tail-call cycle `chkesp -> chkesp (COMPUTED_JUMP)`. Only
    present because `--include-refs true` follows the COMPUTED_JUMP;
    the same call without it produces just 1 node / 1 edge.
  - `--function chkesp --direction calling --depth 2` on
    `/Mapeditor.exe` → `1025 nodes, 2057 edges` (the binary's full
    reverse-call fan-in up to depth 2; under the 5000 cap so
    `truncated=false`).
  - Default `--format mermaid` emits a clean `graph TD` / `graph BT`
    block on stdout, with the summary line on stderr. Pipe test:
    `... | tail -n +2 | head -5` returns the first five Mermaid lines
    (header + 3 nodes + 1 edge), confirming the stdout/stderr split.
  - `--function main` on `/noanno-1781782566` → `1 node, 0 edges` (the
    binary's `main` doesn't call anything; the BFS terminates
    immediately). Pipe-friendly.
  - `--function does_not_exist` → `No function matched 'does_not_exist'.`
    (exit 1).
  - `--depth 99` → `'depth' must be between 1 and 10.` (exit 1).
  - `--direction sideways` → `Invalid 'direction' 'sideways': must be
    called or calling.` (exit 1).
  - `--format svg` → `Invalid 'format' 'svg': must be mermaid or json.`
    (exit 1).
  - `--file /NoSuch --function main` → `No program found for '/NoSuch'.`
    (exit 1).
  - Server log: `Procedures (91)` — was 90; +1 for `Callgraph`.

* Datatype delete `-BAD-` referrer detection (added 2026-06-19): the
  response to `datatype delete` now carries a `referrers` array listing
  every program-DTM type whose structure depended on the deleted type.
  The CLI prints them on stderr so the user knows which composites now
  hold `-BAD-` placeholders and need to be re-resolved
  (`datatype replace --path <referrer> --definition '...'`).
  - Scenario: created `/TestInner` (struct) and `/TestOuter` (union with
    a `TestInner` field) on `/noanno-1781782566`. `datatype delete
    --file /noanno-1781782566 --path /TestInner` → exit 0; CLI output:
    `deleted /TestInner` then `note: 1 type(s) referenced this and now
    show '-BAD-'; run 'datatype replace' on each to heal:` then `  /TestOuter`.
    The outer union's field listing went from `"type":"TestInner"`
    to `"size":-1,"type":"-BAD-"` exactly as expected (matches the
    user-reported symptom from P3).
  - Negative case: deleted `/Orphan` (a struct nothing references) →
    just `deleted /Orphan`, no `note:` line. The referrers array is
    present but empty in the raw JSON
    (`{"path":"/Orphan","deleted":true,"referrers":[],"success":true}`).
  - Built-in still rejected: `datatype delete --path /int` →
    `Cannot delete built-in type 'int'.` (no referrers line).
  - Detection is structural (recursive walk of `getComponents()` for
    composites, `getBaseDataType()` for typedefs, element-type for
    arrays/pointers, return+parameter types for `FunctionDefinition`),
    comparing by `categoryPath/name` rather than `DataType` instance
    identity. Empirically `DataType.dependsOn()` returns false for
    referrers that hold a stale instance of the same name (the field
    type was resolved from the DTM by name when the referrer was built,
    so it points at a different object than the one the caller asked to
    delete). Path-based comparison catches both stale and current
    handles. Cycle-safe via an IdentityHashMap-based `seen` set so a
    struct with a pointer-to-self doesn't loop forever.

* Apply-type `--address-set` single-application semantics (added
  2026-06-19, fixes the 17×16-byte bug): each `addressSet` entry lays
  the type ONCE at `start`, consuming `dt.getLength()` bytes; `end` is
  an upper bound. Pre-validates every range against the type length
  (whole call rejected if any range is too small; response carries a
  `warnings` array if any range is larger than the type). The CLI
  prints the warnings on stderr.
  - User-reported bug:
    `memory apply-type --type /TaskContainer --address-set 0x100000:0x100010`
    on `/noanno-1781782566` → was `applied TaskContainer (17 entries,
    272 bytes)` (overlapping copies). Now: `applied TaskContainer
    (1 entries, 16 bytes)` + `note: 1 range(s) had uncovered bytes; the
    type's length was shorter than the range end-to-start:` +
    `  00100000:00100010 (type consumes 16 of 17 bytes)`. Matches the
    GUI's press-D-and-type behavior.
  - `memory apply-type --type int --address-set 0x100400:0x100413` (4-byte
    type, 20-byte range) → `applied int (1 entries, 4 bytes)` + warning
    `00100400:00100413 (type consumes 4 of 20 bytes)`.
  - `memory apply-type --type /TaskContainer --address-set 0x100300:0x100305`
    (16-byte type, 6-byte range) → exit 1 with `Type 'TaskContainer'
    consumes 16 bytes but range 00100300:00100305 is only 6 byte(s).`.
  - Single `--address` mode unchanged: `memory apply-type --type
    /TaskContainer --address 0x100200` → `applied TaskContainer
    (1 entries, 16 bytes)`, no warnings (single-address entries skip
    the size check).
  - `--length` Dynamic-only behavior unchanged (see `apply_type_length`
    memory entry); `length` equal to `dt.getLength()` is silently
    accepted for non-Dynamic types.

* `memory undefine` (added 2026-06-19; 92nd procedure `ClearCodeUnits`)
  is the inverse of `apply-type` and mirrors the GUI's "Clear Code
  Bytes" action. Bytes are preserved; only Data/Instruction listing
  entries are removed. Single `--address` clears the containing unit
  (Ghidra semantics: clearing mid-unit clears the whole unit); each
  `--address-set START[:END]` clears the inclusive range.
  - Roundtrip smoke test on `/noanno-1781782566`:
    1. `memory apply-type --type qword --address 0x103fc0` → `applied
       qword (1 entries, 8 bytes)`.
    2. `memory undefine --address 0x103fc0` → `cleared 1 code unit(s)
       across 1 range(s)`.
    3. `memory apply-type --type dword --address 0x103fc8` → `applied
       dword (1 entries, 4 bytes)`.
    4. `memory undefine --address-set 0x103fc8:0x103fcb` → `cleared 1
       code unit(s) across 1 range(s)`.
    5. `memory undefine --address 0x103fc0` (re-clear) → `cleared 1
       code unit(s) across 1 range(s)` (no error, already-undefined
       addresses are a no-op).
  - Error paths:
    - `memory undefine` (no args) → exit 1 with `Missing 'address' or
      'addressSet'.`.
    - `memory undefine --address-set 0x103fc0:0x103fbf` → exit 1 with
      `addressSet entry end '00103fbf' precedes start '00103fc0'.`.
    - `memory undefine --address-set 0xdeadbeef:0xdeadbeef` → exit 0
      with `cleared 0 code unit(s) across 1 range(s)` (unmapped
      addresses are a silent no-op; the `cleared` count tells the
      caller nothing was there).
    - `memory undefine --file /NoSuchFile --address 0x1000` → exit 1
      with `No program found for '/NoSuchFile'.`.
