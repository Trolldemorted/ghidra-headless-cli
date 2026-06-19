# DataType — List

Enumerate data types under a category, optionally filtered by kind, with a
recursive-walk default and a result cap. Read-only.

## Path syntax

A type's *path* is `{category-path}/{name}` where `{category-path}` is rooted
at `/` (root category) and may contain subcategories separated by `/`. A bare
`/Name` means root + name; a `Sub/Name` or `/Sub/Name` means category `Sub` +
name; nested categories work the same (`/A/B/Name`).

The same path syntax is used by `ShowDataType`, `EditDataType`, `DeleteDataType`.
`ApplyDataType` uses a separate `type` field that accepts C-syntax
expressions (`int`, `char *`, `MyStruct[4]`).

## Request
```typescript
interface ListDataTypesRequest {
  procedure: "ListDataTypes";
  file: string;            // project path, e.g. "/test/foo.exe"
  category?: string;       // starting category path [default: "/" = root]
  recursive?: boolean;     // descend into subcategories [default: true]
  kind?: "struct" | "union" | "enum" | "typedef" | "all";
                           // [default: "all"]
  limit?: number;          // cap results; sets truncated:true [default: 0 = unlimited]
}
```

## Response
```typescript
interface ListDataTypesResponse {
  success: true;
  count: number;
  truncated: boolean;
  types: DataTypeSummary[];
}
interface DataTypeSummary {
  name: string;            // bare type name, e.g. "Elf64_Ehdr"
  path: string;            // full path including category, e.g. "ELF/Elf64_Ehdr"
  category: string;        // category path, e.g. "/ELF" or "/"
  kind: "struct" | "union" | "enum" | "typedef"
       | "pointer" | "array" | "functiondef" | "bitfield" | "primitive";
  size: number;            // byte length (-1 for variable-length primitives like TerminatedCString)
  source: "USER" | "BUILTIN" | "ARCHIVE";
                           // coarse source: USER=user-defined, BUILTIN=BuiltIns/ANSI_C/windows_vs,
                           // ARCHIVE=everything else (typed in as a data type archive)
  sourceArchive: string | null;  // archive name when source=ARCHIVE, else null
}
```

## Notes

- `recursive=false` lists types in the category but not in subcategories.
- `kind` is case-insensitive; unknown values return an empty list (not an error).
- The list is sorted alphabetically by `path` before truncation, so `limit=N`
  is deterministic.
- BUILTIN source corresponds to types from the program's BUILT_IN archive
  (BuiltIns / ANSI_C / windows_vs all share the same archive key). USER
  means no source archive — types the user added directly to this program.
  ARCHIVE is anything else: types pulled in from a `.gdt`/`.sdt` archive or
  auto-imported from the analyzed binary's type information.

## CLI

The default output is a **tree grouped by category path**; pass `--json`
to get the raw `types[]` array (one line per query, parseable by `jq`).

### Default — tree

```
$ ghidra-headless-cli datatype list --file /Mapeditor.exe --kind struct --limit 20
/Mapeditor.exe: 20 types (truncated) (recursive, /, kind=struct)
IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct  struct     4  Mapeditor.exe (archive)
L_String                                        struct     8  Mapeditor.exe (archive)
ClaudeHeadless/
    └── ClaudeHeadlessStruct  struct    12  Mapeditor.exe (archive)
DOS/
    └── IMAGE_DOS_HEADER  struct   128  Mapeditor.exe (archive)
PE/
    ├── IMAGE_BASE_RELOCATION                      struct     8  Mapeditor.exe (archive)
    ├── IMAGE_DATA_DIRECTORY                       struct     8  Mapeditor.exe (archive)
    ...
    └── IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct  struct     4  Mapeditor.exe (archive)
```

Layout conventions:

- The header line (`/Mapeditor.exe: 20 types ...`) is on **stderr** so
  `datatype list ... 2>/dev/null` strips it and leaves only the tree on
  stdout (script-friendly).
- Types whose `category` is the scope root (`/` by default, or the
  `--category` value) print **flush-left with no connector**.
- Each child category prints as a `<lastSeg>/` header, also flush-left
  if it's a direct child of the scope root. Only the **last segment**
  of the category path is shown; the tree shape conveys the full path.
- Types inside a category are indented one level (`    ` = 4 spaces)
  with `├── ` / `└── ` connectors.
- **Empty intermediate categories are synthesized** when a row sits at
  a deep path like `/Demangler/std/ios_base` but neither `/Demangler`
  nor `/Demangler/std` have direct rows. The DTM allows this; the
  tree shows all of them so the full path is visible.
- The source column combines `source` and `sourceArchive`:
  - `USER` → `program (user)`
  - `BUILTIN` (no archive) → `built-in (builtin)`
  - `BUILTIN` (with archive, e.g. `windows_vs`) → `<archive> (builtin)`
  - `ARCHIVE` → `<sourceArchive> (archive)` (or `? (archive)` if the
    archive name is missing).
- Scoped (`--category /Demangler`): the scope root replaces `/` as
  the "root level" — types directly in `/Demangler` print flush-left,
  types under `/Demangler/std` and `/Demangler/std/ios_base` appear
  indented as nested subcategories.

### `--json`

Dumps the raw server `types[]` array on a single line, parseable by
`jq`:

```
$ ghidra-headless-cli datatype list --file /Mapeditor.exe --kind struct --limit 3 --json
[{"name":"ClaudeHeadlessStruct","path":"/ClaudeHeadless/ClaudeHeadlessStruct","category":"/ClaudeHeadless","kind":"struct","size":12,"source":"ARCHIVE","sourceArchive":"Mapeditor.exe"}, ...]

$ ghidra-headless-cli datatype list --file /Mapeditor.exe --json --limit 100 \
    | jq '[.[] | select(.source == "USER")] | length'
3
```

`--json` writes only the array (no header on stdout) — redirect
`2>/dev/null` to suppress log lines if you need truly silent JSON.
