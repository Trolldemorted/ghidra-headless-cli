# RenameLabel

Rename a label by exact name match. Pass `--address` to disambiguate when
multiple symbols share the name (e.g. two vtables named `vftable`).

Wraps `Symbol.setName(...)` via `SymbolTable`. Mutating: the file is checked out
before the call and checked in immediately after; the call fails with an error if
the push fails.

<!-- Shared types: SourceType = "USER_DEFINED" | "ANALYSIS" | "IMPORTED" | "DEFAULT";
     AddressRange = { start: string; end?: string }  (hex addresses) -->

## Name match is LITERAL

`--query` is matched against the stored symbol name with `String.equals`
(byte-for-byte, case-sensitive, whitespace-sensitive). There is no regex,
no glob, no substring, no case folding. Dots, parens, brackets, dollar
signs, etc. are matched as themselves. This is why auto-generated labels
whose names contain `.` (e.g. `s_V1.1_0069719c` from Ghidra's
string-analysis pass, or class names like `ns.MyClass_vftable`) round-trip
exactly: copy the name `get-label` prints and pass it as `--query`.

If your `--query` doesn't match, the error tells you what is actually
stored (see [Diagnostics](#diagnostics) below).

## Request
```typescript
interface RenameLabelRequest {
  procedure: "RenameLabel";
  file: string;              // project path of the target program, e.g. "/Mapeditor.exe"
  query: string;             // current label name (exact literal match — see "Name match is LITERAL")
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

Rename an auto-generated string label verbatim (dots included):
```sh
memory rename-label --file /Mapeditor.exe \
  --query "s_V1.1_0069719c" --name s_Version \
  --address 0x0069719c
```

## Errors

- `"No label matched '<query>'. Name match is literal (String.equals
  on the stored symbol name)"` — the exact name lookup returned nothing.
  See [Diagnostics](#diagnostics) for the recovery path.
- `"Multiple labels match '<query>'; pass --address to disambiguate:
  ..."` — the same name exists at more than one address. Pass `--address`
  to pick the target.
- `"renameLabel: <message>"` — Ghidra rejected the rename (e.g.
  `DuplicateNameException` for a name clash at the destination namespace).

## Diagnostics

When the lookup misses, the error payload is actionable, not just a bare
"No label matched". Two paths:

**With `--address`** (address-scoped lookup): the error lists every label
that IS at the address, with their actual stored names. This catches the
common case where the user copy-pastes a name from `get-label` but the
stored name has an invisible char (NBSP, trailing whitespace, …) or a
typo. The user can immediately see what's there and re-issue the
rename with the exact stored name:
```
No label matched 'wrong_typo_name'. Name match is literal (String.equals on the stored symbol name)
Labels at address 00404000:
  00404000  real_name_at_404000
Use `memory get-label --address 00404000` to see the exact stored names.
```

**Without `--address`** (program-wide lookup): the error offers up to
five "did you mean?" symbols whose names contain `--query` as a
substring (case-insensitive). This catches typos and shortened forms.
The user can then re-issue with the full name, or run
`memory list-label --query "..."` for a full substring search:
```
No label matched 'real_nam'. Name match is literal (String.equals on the stored symbol name)
Did you mean one of these?
  00404000  real_name_at_404000
Use `memory list-label --query "real_nam"` to search.
```

Both paths are wired through [`LabelLookup`](../../ghidra-rpc-server/procedures/ghidra/program/model/listing/LabelLookup.java)
and surface in the same way for `delete-label`.

## Auto-generated DEFAULT labels (fix 2026-06-23)

When `apply-type` lays a data type named `vftable` at an address, Ghidra's
MS RTTI analyzer auto-generates a label of the form
`<ClassName>_vftable_<hexaddr>` (e.g. `CMainWnd_vftable_0066e3c0`) with
SourceType `DEFAULT`. Likewise, `string define` and `string create`
create DEFAULT-source labels like `s_V1.1_0069719c`.

Prior to 2026-06-23, neither `rename-label` nor `delete-label` could
match these — both `SymbolTable.getSymbolsAsIterator(addr)` (used by the
address-scoped path) and `SymbolTable.getSymbols(name)` (used by the
program-wide path) explicitly exclude DEFAULT-source symbols and
dynamic-memory symbols per the Ghidra 12.1.2 Javadoc. The error message
even claimed "literal match" which was technically true — the symbol
just wasn't in the result set to begin with.

**Fixed 2026-06-23 in `LabelLookup.byName` (both modes):**

- **Address-scoped** now uses `SymbolTable.getSymbols(Address)` (the
  array-returning overload), which — per the Ghidra 12.1.2 Javadoc —
  "will include a dynamic memory symbol if one exists". DEFAULT-source
  labels at the address are returned.
- **Program-wide** now walks `SymbolTable.getSymbolIterator()` (no-arg)
  and filters by `.getName().equals(name)` client-side. This returns
  all label symbols including DEFAULT-source ones.

Both `rename-label` and `delete-label` go through `LabelLookup.byName`,
so the fix covers both. DEFAULT-source labels can now be renamed or
deleted directly — no `--address` needed (though `--address` is still
the right disambiguator when multiple labels share the name):

```sh
memory rename-label --file <file> --query "CMainWnd_vftable_0066e3c0" \
  --name CMainWnd_vftable --address 0x0066e3c0
memory rename-label --file <file> --query "s_V1.1_0069719c" \
  --name s_Version --address 0x0069719c
```

If the lookup still misses, the diagnostic now correctly lists what IS
at the address (or "did you mean?" for program-wide). The "dots are
dots" copy was also wrong about the failure mode and has been replaced
with "Name match is literal (String.equals on the stored symbol name)"
in both handlers — the literal match IS still happening; the bug was
that the lookup was looking at the wrong symbol set.

## See also

- `CreateLabel` — create a label at an address
- `SetPrimary` — promote a label to primary at its address
- `GetLabel` — read primary (and secondaries) at an address
- `ListLabels` — substring search over all labels
- `LookupLabel` — substring/regex search, returns source + primary + type
- `DeleteLabel` — same lookup + diagnostics contract