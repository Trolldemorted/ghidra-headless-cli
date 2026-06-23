# Memory subcommand

Grouped RPC procedures for working with **static memory addresses** in a
program: data labels (create / rename / delete / set-primary / list / lookup /
get), raw byte reads, applying a data type at an address, and clearing
listing entries. Ten procedures, one per verb.

| procedure     | mutates? | request                                                          | response                          |
|---------------|----------|------------------------------------------------------------------|-----------------------------------|
| CreateLabel   | yes      | `file, address, name, source?`                                   | `{name, address, source}`         |
| RenameLabel   | yes      | `file, query, address?, newName, source?`                        | `{name, address, source}`         |
| DeleteLabel   | yes      | `file, query, address?`                                          | `{deleted, name, address}`        |
| SetPrimary    | yes      | `file, query, address`                                           | `{name, address, source}`         |
| ListLabels    | no       | `file, query?, regex?, ignoreCase?, limit?`                      | `{count, truncated, refs[]}`      |
| LookupLabel   | no       | `file, query, regex?, ignoreCase?, address?`                     | `{count, refs[]}`                 |
| GetLabel      | no       | `file, address`                                                  | `{address, primary, all[]}`       |
| ReadBytes     | no       | `file, address, length, format?` (max length 65536)              | `{address, length, bytesRead, data}` |
| ApplyDataType | yes      | `file, type, address?, length?, addressSet?`                     | `{type, path?, created, bytes, warnings?}` |
| ClearCodeUnits| yes      | `file, address?, addressSet?, clearContext?`                     | `{ranges, cleared}`               |

Mutations run in a transaction via `RpcContext.runWrite`; the program is
checked back in on success, rolled back on error. Like all other mutating
procedures the file must be exclusively checked out (the GUI must be closed
on it).

## Common error cases

* `Length must be 1..65536.` — `ReadBytes` length cap.
* `Address not in any memory block: <addr>.` — `ReadBytes` start address is
  outside every defined block.
* `Unreadable at <addr>: <message>.` — `MemoryAccessException` from
  `Memory.getBytes`.
* `Invalid 'format' '<x>': must be hex or dump.`
* `Invalid 'type' '<x>': must be ...` — for any handler that takes `type`.
* `No label matched '<name>'.`
* `Multiple labels match '<name>'; pass --address to disambiguate: <list>.`
* `'<name>' is already the primary label at <addr>.`
* `'<name>' is a function entry-point label; use 'function delete' to remove
  the function itself.`
* `createLabel: <InvalidInputException message>` — bad name (whitespace,
  empty, etc.).

## Source types

`CreateLabel` and `RenameLabel` accept a `source` field (default
`USER_DEFINED`). Case-insensitive. `DEFAULT` is rejected because Ghidra's
`createLabel` refuses it for new symbols.

## Disambiguation rule (Rename / Delete / SetPrimary)

These three handlers match the symbol by name **exactly** (whitespace-sensitive).
If multiple symbols share the name, the request is rejected with the list of
candidate addresses and the user is told to pass `--address` to disambiguate.
`SetPrimary` requires `--address` because promoting only makes sense at a
specific address.

## Procedures in detail

### CreateLabel

```json
{ "procedure": "CreateLabel", "file": "/Mapeditor.exe",
  "address": "0x401000", "name": "g_tick", "source": "USER_DEFINED" }
```

Creates a label at `address` in the global namespace with the given
`SourceType`. If a symbol with that name already lives at the address, Ghidra
returns it without modification (idempotent).

If `address` points to a function entry point, the new symbol is created
alongside the function symbol; the function is NOT renamed — use
`function set-name` for that.

### RenameLabel

```json
{ "procedure": "RenameLabel", "file": "/Mapeditor.exe",
  "query": "g_tick", "newName": "g_frame", "source": "USER_DEFINED" }
```

Looks up the symbol by `query` (exact name match) via
`SymbolTable.getSymbols(query)`, which falls back to Ghidra's
dynamic-name table for auto-generated `DAT_<addr>` placeholders. On hit,
calls `Symbol.setName(newName, source)`. Throws `DuplicateNameException`
if `newName` is already in use by another symbol in the same namespace —
caught and returned as a clear error. Renaming a dynamic `DAT_…` label
will fail (dynamic labels are read-only); the workaround is to
`create-label` a USER_DEFINED label at the same address, which makes the
existing dynamic label a secondary shadow.

### DeleteLabel

```json
{ "procedure": "DeleteLabel", "file": "/Mapeditor.exe",
  "query": "g_tick" }
```

Looks up the symbol by `query` (exact **literal** match —
`String.equals`, no regex/substring/glob) via
`SymbolTable.getSymbols(query)`, which falls back to Ghidra's
dynamic-name table for auto-generated `DAT_<addr>` placeholders. Calls
`Symbol.delete()` on the resolved symbol. Refuses to delete
`SymbolType.FUNCTION` symbols (use `function delete` for that). The
`deleted` field on the response is the boolean return from Ghidra's
`Symbol.delete()`. Dynamic `DAT_…` labels cannot be deleted directly
(they're synthesized); create a USER_DEFINED label at the address to
shadow them.

Name match is literal — dots, parens, etc. are matched as themselves
(see `RenameLabel.md` "Name match is LITERAL"). On miss, the error
payload is diagnostic: when `--address` is provided, it lists the
labels actually at the address; when `--address` is absent, it offers
up to five "did you mean?" substring matches. Same contract as
`RenameLabel`.

### SetPrimary

```json
{ "procedure": "SetPrimary", "file": "/Mapeditor.exe",
  "query": "g_secondary", "address": "0x401000" }
```

Promotes a secondary label at `address` to the primary slot. `--address` is
required. Errors with `'<name>' is already the primary label at <addr>.` if
the target is already primary.

### ListLabels

```json
{ "procedure": "ListLabels", "file": "/Mapeditor.exe",
  "query": "g_", "regex": false, "ignoreCase": false, "limit": 50 }
```

Walks `SymbolTable.getSymbolIterator()` and returns every `SymbolType.LABEL`
whose name matches the query (substring by default; `regex:true` and
`ignoreCase:true` work the same way as `function find-by-name`). Excludes
function entry-point labels, namespace labels, parameters/locals, and external
symbols. Sorted by address, then by name. `query` is OPTIONAL — pass an empty
or absent value to list all labels.

### LookupLabel

```json
{ "procedure": "LookupLabel", "file": "/Mapeditor.exe",
  "query": "data_start", "address": "0x401000" }
```

Same matching semantics as `ListLabels` but returns *all* symbol types
(function entry-point labels, namespace labels, external imports, ...). Use
this when you want to ask "is there anything with this name, and where?".
`--address` narrows the search to a single address.

**Auto-generated `DAT_<addr>` labels.** Ghidra synthesizes `DAT_xxxxxxxx`
labels on demand for any address that has been defined but has no real
symbol record — these are the labels `memory get-label --address <X>`
returns when X is a typed byte that has no user/analysis name. The
name-indexed `SymbolTable.getSymbols(query)` API (used by `RenameLabel` /
`DeleteLabel` / `LookupLabel`) has a built-in dynamic-name fallback that
finds these on **exact** query match, so lookups like
`--query DAT_006cbb30` succeed. `list-labels` still skips them (via its
`s.isDynamic()` filter) — use `lookup-label` instead when working with
`DAT_…` names.

**Substring search over `DAT_…` labels is partial.** The main iterator
walks real DB records, and the dynamic-name probe synthesizes at most
one match for the **exact** query — substring queries like `--query
DAT_006c` may miss `DAT_006cbb30` because Ghidra does not enumerate the
dynamic-symbol address space for partial names. The reliable pattern:
look up the address with `get-label --address <X>`, then use the exact
returned name with `rename-label` / `delete-label` / `lookup-label`.

### GetLabel

```json
{ "procedure": "GetLabel", "file": "/Mapeditor.exe",
  "address": "0x401000" }
```

Returns:
- `primary` — the primary label name at the address, or `null` if the
  address is unlabeled.
- `all` — every symbol at the address (primary + secondary labels), with
  `isPrimary` per entry.

### ReadBytes

```json
{ "procedure": "ReadBytes", "file": "/Mapeditor.exe",
  "address": "0x401000", "length": 16, "format": "hex" }
```

Reads up to `length` bytes starting at `address` and returns them as hex.
`length` is capped at 65536. `format` is `hex` (default — single
space-separated string) or `dump` (`hexdump -C`-style rows with an ASCII
column on the right).

The actual byte count returned may be less than the requested `length` if
the range runs off the end of a memory block; the `bytesRead` field reports
the truth. Unmapped start addresses fail with a clear error.

`dump` example:

```
00101040  f3 0f 1e fa b8 03 00 00  00 c3 66 0f 1f 44 00 00  |..........f..D..|
00101050  f3 0f 1e fa 31 ed 49 89  d1 5e 48 89 e2 48 83 e4  |....1.I..^H..H..|
```

## CLI

```bash
ghidra-headless-cli memory create-label --file /Mapeditor.exe --address 0x401000 --name g_tick
ghidra-headless-cli memory rename-label --file /Mapeditor.exe --query g_tick --name g_frame
ghidra-headless-cli memory delete-label --file /Mapeditor.exe --query g_frame
ghidra-headless-cli memory set-primary  --file /Mapeditor.exe --query g_secondary --address 0x401000
ghidra-headless-cli memory list-labels  --file /Mapeditor.exe [--query g_] [--regex true] [--ignore-case true] [--limit 50]
ghidra-headless-cli memory lookup-label --file /Mapeditor.exe <NAME> [--regex true] [--ignore-case true] [--address 0x401000]
ghidra-headless-cli memory get-label    --file /Mapeditor.exe --address 0x401000
ghidra-headless-cli memory read-bytes   --file /Mapeditor.exe --address 0x401000 --length 16 [--format hex|dump]
ghidra-headless-cli memory apply-type   --file /Mapeditor.exe --type int --address 0x401000
ghidra-headless-cli memory undefine     --file /Mapeditor.exe --address 0x401000
```

Note on `--regex` / `--ignore-case`: clap's `Option<bool>` requires an
explicit value (`--regex true` or `--regex false`), not just `--regex`.
