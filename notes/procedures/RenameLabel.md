# RenameLabel

Rename a label by exact name match. Pass `--address` to disambiguate when
multiple symbols share the name (e.g. two vtables named `vftable`).

Wraps `Symbol.setName(...)` via `SymbolTable`. Mutating: the file is checked out
before the call and checked in immediately after; the call fails with an error if
the push fails.

<!-- Shared types: SourceType = "USER_DEFINED" | "ANALYSIS" | "IMPORTED" | "DEFAULT";
     AddressRange = { start: string; end?: string }  (hex addresses) -->

## Request
```typescript
interface RenameLabelRequest {
  procedure: "RenameLabel";
  file: string;              // project path of the target program, e.g. "/Mapeditor.exe"
  query: string;             // current label name (exact match)
  name: string;              // new label name
  source?: SourceType;       // default "USER_DEFINED"
  address?: string;          // disambiguate when multiple symbols share `query`
}
```

## Response
`{ "success": true, "name": "<new>", "address": "...", "source": "..." }`,
or `{ "success": false, "error": "<message>" }`.

## Example
```json
{"procedure": "RenameLabel", "file": "/Mapeditor.exe",
 "query": "FUN_00401000", "name": "my_helper"}
```

## Errors

- `"No label matched '<query>'."` — the exact name lookup in
  `SymbolTable.getSymbols(query)` returned nothing. See
  [Auto-generated DEFAULT labels](#auto-generated-default-labels) below for the
  common cause (auto-generated vftable-style names like
  `CMainWnd_vftable_0066e3c0`).
- `"Multiple labels match '<query>'; pass --address to disambiguate: ..."` —
  the same name exists at more than one address. Pass `--address` to pick
  the target.
- `"renameLabel: <message>"` — Ghidra rejected the rename (e.g.
  `DuplicateNameException` for a name clash at the destination namespace).

## Auto-generated DEFAULT labels

When `apply-type` lays a data type named `vftable` at an address, Ghidra's
MS RTTI analyzer auto-generates a label of the form
`<ClassName>_vftable_<hexaddr>` (e.g. `CMainWnd_vftable_0066e3c0`) with
SourceType `DEFAULT`. These labels are visible in `get-label` (which uses
`getPrimarySymbol`) but may not be findable via `getSymbols(query)` — the
name-index lookup that backs `RenameLabel` does not fall through to the
dynamic-name synthesis path for non-`DAT_<addr>` names.

**Workaround (verified 2026-06-22):** `create-label --address 0x0066e3c0
--name CMainWnd_vftable` creates a fresh USER_DEFINED label at that
address. USER_DEFINED outranks DEFAULT, so the new label auto-promotes to
primary; the prior DEFAULT `CMainWnd_vftable_0066e3c0` is now a secondary
shadow. The follow-up `set-primary` is redundant — already primary.
No `rename-label` call is needed.

If the exact-name rename is still wanted, pass `--address` so the lookup
is scoped to that address (`SymbolTable.getSymbolsAsIterator(addr)` plus
exact-name filter), which does find DEFAULT-source records:
```sh
memory rename-label --file <file> --query CMainWnd_vftable_0066e3c0 \
  --name CMainWnd_vftable --address 0x0066e3c0
```

This is the same pattern documented for `DAT_<addr>` labels — use
`get-label --address X` to discover the exact name, then pass that name
+ address to `rename-label`.

## See also

- `CreateLabel` — create a label at an address
- `SetPrimary` — promote a label to primary at its address
- `GetLabel` — read primary (and secondaries) at an address
- `ListLabels` — substring search over all labels
- `LookupLabel` — substring/regex search, returns source + primary + type
