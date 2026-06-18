# String subcommand

Grouped RPC procedures for working with the program's **defined strings**:
substring/regex search (with `--query` optional — empty means "list all"),
point lookup of the single string at an address, defining a new string at
an address, and deleting a defined string at an address. Four procedures,
one per verb. The user explicitly chose to operate on **defined** strings
(Ghidra's data-model layer), not on raw memory — so we use
`DefinedStringIterator` and never `StringSearcher`.

| procedure      | mutates? | request                                                                  | response                                                                              |
|----------------|----------|--------------------------------------------------------------------------|---------------------------------------------------------------------------------------|
| `SearchStrings`| no       | `file, query?, regex?, ignoreCase?, limit?, address?, addressSet?`        | `{count, truncated, strings:[{address, value, representation, length, charset, dataType}]}` |
| `GetString`    | no       | `file, address`                                                          | `{address, string:{address, value, representation, length, charset, dataType} \| null}` |
| `DefineString` | yes      | `file, address, kind, length?`                                           | `{address, kind, length, charset}`                                                    |
| `DeleteString` | yes      | `file, address`                                                          | `{address, dataType, length}` (echoes back what was removed) |

`SearchStrings` is the merged `FindStrings` + `ListDefinedStrings`: an
optional `query` does the substring/regex filter, and when the query is
absent/empty the procedure returns EVERY defined string in scope
("list all"). Internally the handler delegates to `DefinedStringScan`,
which uses `StringQuery.containsOptional(req)` to swap the matcher
between `s -> true` and `StringQuery.contains(req)` based on the
request's query field. The match shape and scope semantics are
unchanged.

`GetString` is the point-lookup companion to `SearchStrings`: it does
NOT walk the program. It reads `program.getListing().getDataAt(addr)`
and wraps the resulting `Data` in `StringDataInstance`. If the address
has no defined string, the response's `string` field is `null` (the
`address` is always echoed back, even on miss). The shape mirrors
`GetLabel` — `{address, <thing>:<T>|null}`.

Mutations (`DefineString`, `DeleteString`) run through
`RpcContext.runWrite` / `RpcContext.applyCommand`. The program is checked
back in on success and rolled back on error; the file must be exclusively
checked out (the GUI must be closed on it).

`DeleteString` is the inverse of `DefineString`: it looks up the `Data` at
the address, refuses anything that isn't a defined string (via
`StringDataInstance.isString(data)` — same check `GetString` uses), and
calls `Listing.clearCodeUnits(start, end, false)` inside `runWrite`. The
`clearBytes=false` flag removes the Data type interpretation but preserves
the underlying memory bytes, so the caller can re-define a different
string at the same address later without losing the byte content.

## Match shape

Every string hit carries six fields:

| field             | meaning                                                          | example                              |
|-------------------|------------------------------------------------------------------|--------------------------------------|
| `address`         | Ghidra address of the string's first byte                        | `00100449`                           |
| `value`           | Decoded string value, no surrounding quotes                      | `__libc_start_main`                  |
| `representation`  | Quoted + C-escaped form (suitable for display)                   | `"__libc_start_main"`                |
| `length`          | String length in BYTES (`Data.getLength()`)                      | `18`                                 |
| `charset`         | Charset name from `StringDataInstance.getCharsetName()`          | `US-ASCII`, `UTF-8`, `UTF-16LE`, …   |
| `dataType`        | Ghidra DataType name (`getDataType().getName()`)                 | `string`, `unicode`, `TerminatedCString`, `PascalUnicode`, `string-utf8`, … |

`representation` is what Ghidra would print in the listing (e.g. `"hello\n"`).
The same shape is used by both `SearchStrings` (one entry per string in
`strings[]`) and `GetString` (one entry in `string`).

## `--kind` table (DefineString)

| `--kind`   | Ghidra DataType class                | length arg | layout                  |
|------------|--------------------------------------|------------|-------------------------|
| `cstring`  | `TerminatedStringDataType`           | ignored    | null-terminated ASCII   |
| `utf16`    | `TerminatedUnicodeDataType`          | ignored    | null-terminated UTF-16  |
| `string`   | `StringDataType`                     | required   | fixed-length ASCII      |
| `utf8`     | `StringUTF8DataType`                 | required   | fixed-length UTF-8      |
| `unicode`  | `UnicodeDataType`                    | required   | fixed-length UTF-16     |
| `pascal`   | `PascalStringDataType`               | ignored    | 2-byte length prefix    |
| `pascal255`| `PascalString255DataType`            | ignored    | 1-byte length prefix    |

For null-terminated and Pascal kinds Ghidra derives the byte length from the
data (terminator or length prefix). For fixed-length kinds the caller MUST
pass `--length`; we call `Listing.createData(addr, dt, length)` directly
inside `runWrite` because `CreateDataCmd` has no length overload.

## Common error cases

* `Invalid regex: <message>.` — propagated from `StringQuery.contains`.
* `Missing required field 'kind' (cstring, string, utf8, utf16, unicode, pascal, pascal255).`
* `Unknown kind '<x>': must be cstring, string, utf8, utf16, unicode, pascal, pascal255.`
* `'length' is required for fixed-length kind '<x>' (must be >= 1).`
* `Could not create Data at address <addr>` — `CreateDataCmd` failure
  (unmapped address, conflict with existing code unit, etc.).
* `Cannot define string at <addr>: <message>.` — `Listing.createData`
  failure (insufficient memory, conflicting data range, etc.).
* `No defined data at <addr>.` — `GetString`/`DeleteString` miss: no
  `Data` is currently defined at the address.
* `No defined string at <addr> (data type is <X>).` — the address has
  defined `Data` but its type isn't a string (e.g. an int, a struct, a
  pointer, or the post-delete 1-byte undefined Data left behind by a
  previous `DeleteString`).
* `Cannot delete string at <addr>: <message>.` — `Listing.clearCodeUnits`
  failure.
* `No program found for '/<X>'.` — unknown file path.

## Scope

`SearchStrings` and `DefineString` accept an optional address scope:
- `--address <hex>` (single address), OR
- `--address-set <START:END>` (repeatable).

If neither is given, the scope is the whole program. `DefinedStringIterator`
silently skips uninitialized memory (`.bss`, bit-mapped regions) via
`StringDataInstance.isString(Data)`'s `!data.isInitializedMemory()` short
circuit.

`GetString` is a point lookup — it takes only `address` (no scope).

## Procedures in detail

### SearchStrings

```bash
# Substring search
ghidra-headless-cli string search --file /Mapeditor.exe --query error

# Regex
ghidra-headless-cli string search --file /Mapeditor.exe --query '^[A-Z]+$' --regex true --limit 50

# Case-insensitive substring
ghidra-headless-cli string search --file /Mapeditor.exe --query MapEditor --ignore-case true

# List all defined strings (no query = match every defined string in scope)
ghidra-headless-cli string search --file /Mapeditor.exe
ghidra-headless-cli string search --file /Mapeditor.exe --limit 10

# Scope to one address
ghidra-headless-cli string search --file /Mapeditor.exe --query Mapeditor --address 0x004c8274

# Scope to one or more address ranges
ghidra-headless-cli string search --file /Mapeditor.exe --address-set 0x00475000:0x00477000
```

Filters defined strings whose **decoded value** matches the query (substring
by default, regex with `--regex true`, case-insensitive with `--ignore-case
true`). Empty/absent `--query` returns every defined string in the scope,
sorted by address. `count` reflects the matched-set size (post-filter);
`truncated` is set when `--limit` caps the result.

### GetString

```bash
# Hit
ghidra-headless-cli string get --file /Mapeditor.exe --address 0x004c8274
# → u"Mapeditor"  [20 bytes, UTF-16, PascalUnicode]

# Miss (no defined string at that address)
ghidra-headless-cli string get --file /noanno-1781782566 --address 0x100001
# → no defined string at 00100001
```

O(1) listing lookup at one address. Returns `{address, string: <T>|null}`
— `string` is the same per-string shape that `SearchStrings` uses for
each entry of `strings[]`, or `null` when the address does not host a
defined string. Does not walk the program.

### DefineString

```bash
# null-terminated ASCII (length computed from data)
ghidra-headless-cli string define --file /Mapeditor.exe --address 0x0047fff0 --kind cstring

# fixed-length ASCII (length required)
ghidra-headless-cli string define --file /Mapeditor.exe --address 0x0047fff0 --kind string --length 8

# null-terminated UTF-16
ghidra-headless-cli string define --file /Mapeditor.exe --address 0x0047fff0 --kind utf16
```

Materializes a Defined String at `address`. The kind string picks which
Ghidra DataType subclass to instantiate; see the kind table above.

### DeleteString

```bash
# Delete the defined string at an address
ghidra-headless-cli string delete --file /Mapeditor.exe --address 0x0047fff0

# After delete, GetString at the same address returns the miss shape:
ghidra-headless-cli string get --file /Mapeditor.exe --address 0x0047fff0
# → no defined string at 0047fff0

# And the address is free to re-define with a different kind:
ghidra-headless-cli string define --file /Mapeditor.exe --address 0x0047fff0 --kind string --length 8
```

Removes the `Data` type interpretation at `address` but leaves the
underlying memory bytes intact (`Listing.clearCodeUnits(start, end,
false)`). One point lookup per call, no scope — pass a single address
exactly as `GetString` does. Errors when the address has no defined
string (see the "Common error cases" section above).

## CLI

```bash
ghidra-headless-cli string search  --file <F> [--query <TEXT>] [--regex true] [--ignore-case true] [--limit N] [--address 0x... | --address-set 0x...:0x...]
ghidra-headless-cli string get     --file <F> --address 0x...
ghidra-headless-cli string define  --file <F> --address 0x... --kind <KIND> [--length N]
ghidra-headless-cli string delete  --file <F> --address 0x...
```

Notes:
- `--query` on `search` is optional. Empty/omitted means "list every
  defined string in scope".
- `--regex` / `--ignore-case`: clap's `Option<bool>` requires an explicit
  value (`--regex true` or `--regex false`), not just `--regex`.
- `string get` is an exact-address point lookup (no substring/regex/limit
  /address-set). To search, use `string search` with `--query` and a
  scope.
