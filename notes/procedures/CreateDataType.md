# DataType — Create

Create a new struct / union / enum / typedef. Program-level and mutating.
Built-in types cannot be created (the root category only accepts types from
the BUILT_IN archive).

## Request
```typescript
interface CreateDataTypeRequest {
  procedure: "CreateDataType";
  file: string;
  kind: "struct" | "union" | "enum" | "typedef";
  name: string;             // must be unique in target category
  category?: string;        // target category [default: "/" = root]
  // struct / union:
  fields?: Array<{ name: string; type: string }>;
  // struct only:
  size?: number;            // 0 = packed/growing; >0 = fixed length [default: 0]
  // enum:
  entries?: Array<{ name: string; value: number }>;
  enumSize?: number;        // byte width [default: 4]
  // typedef:
  base: string;             // C-syntax type expression, e.g. "int", "char *", "byte[16]"
}
```

## Response

Same shape as `ShowDataType` — the freshly-created type, fully described.

## Notes

- **Conflict policy**: strict — a name clash in the target category returns
  `success:false` with the error `Data type 'X' already exists in /...`. The
  caller must explicitly delete the existing type first. No silent rename
  (unlike Ghidra's `DataTypeConflictHandler.DEFAULT_HANDLER`, which would
  append `.conflict` to the name).
- `type` (in `fields`) and `base` (typedef) are parsed via
  `RpcContext.requireDataType` against the program's DTM, so any existing
  type in the program can be referenced (including arrays: `MyStruct[4]`).
- **Alignment/packing** of struct: Ghidra's default. The `size` field sets
  the initial length (0 = packed/growing); alignment cannot be set on creation
  via the public API. Use `EditDataType` for post-create tweaks.
- `entries` are appended in order; enum values are stored as the program-DTM
  enum width (default 4 bytes). `enumSize` overrides the byte width.
- `enumSize` ≤ 0 falls back to 4 (default).
- Both type construction and `Category.addDataType` run inside one Ghidra
  transaction so partial-creation rollback is automatic on error.
