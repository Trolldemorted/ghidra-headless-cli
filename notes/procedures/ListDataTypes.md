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
