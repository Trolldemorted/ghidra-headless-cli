# DataType — Create

Create (or replace) a struct / union / enum / typedef. Program-level and
mutating. Built-in types cannot be edited/created (the root category only
accepts types from the BUILT_IN archive), but user-defined types at any
name are accepted.

## Request
```typescript
interface CreateDataTypeRequest {
  procedure: "CreateDataType";
  file: string;
  // Explicit-JSON path. Required when `definition` is NOT given.
  kind?: "struct" | "union" | "enum" | "typedef";
  name: string;             // type name; existing types with the same name are REPLACED
  category?: string;        // target category [default: "/" = root]
  // struct / union:
  fields?: Array<{ name: string; type: string }>;
  // struct only:
  size?: number;            // 0 = packed/growing; >0 = fixed length [default: 0]
  // enum:
  entries?: Array<{ name: string; value: number }>;
  enumSize?: number;        // byte width [default: 4]
  // typedef:
  base?: string;            // C-syntax type expression, e.g. "int", "char *", "byte[16]"
  // OR a full C-snippet definition. When `definition` is given it wins over
  // the per-kind fields above; `kind` becomes optional (parsed type's kind
  // is used). `name` is still required.
  definition?: string;      // C snippet, e.g. "struct Foo { int x; char *name; };"
}
```

## Response

Same shape as `ShowDataType` — the freshly-created type, fully described.

## Notes

- **Conflict policy: REPLACE in place.** A name clash in the target category
  is resolved by `DataTypeConflictHandler.REPLACE_HANDLER`: the existing
  type is replaced at its path, identity preserved so all references
  (function signatures, applied data, other types) keep working. There
  is no `success:false` for "already exists" — the existing type is
  silently upgraded to the new definition. To get strict-fail behaviour
  (delete-then-create), use `datatype show` first to confirm whether the
  name is in use, then `datatype delete` if you'd rather not replace.
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

## `definition` — C-snippet input

A single `definition` string can replace `fields`/`entries`/`base` for any
kind. It's parsed with Ghidra's `CParser` directly into the program DTM
(the program's open archives resolve user types like `MyOther` alongside
built-ins like `int` / `char *`). The parsed type is then added with
`DataTypeConflictHandler.REPLACE_HANDLER` — same code path the pyghidra
idiom uses:

```java
CParser parser = new CParser(dtm);
DataType parsed = parser.parse(snippet);
dtm.addDataType(parsed, DataTypeConflictHandler.REPLACE_HANDLER);
```

```jsonc
// Named snippets use the embedded name:
{"definition":"struct CFoo { int x; char *name; double ratio; };"}
{"definition":"enum Color { RED=0, GREEN=1, BLUE=2 };"}
{"definition":"typedef char *string_t;"}
```

Rules:

- `kind` and `name` are optional when `definition` is given (the parsed
  type's kind and name are used). On the explicit-JSON path, both are
  required.
- **Anonymous snippets are rejected.** `struct { int x; };` returns
  `C snippet must define a NAMED type. Got an anonymous struct/union/enum
  body — write e.g. `struct Foo { int x; };` with an identifier.`
  Ghidra's CParser handles anonymous types inconsistently (sometimes
  returning the last field's type, sometimes auto-naming to `enum_1`),
  so we surface a clear error instead.
- The snippet must produce exactly ONE type. Forward declarations and
  multi-type snippets return an error.
- The closing brace of struct/union/enum must be followed by `;`. Without
  it the CParser errors out with `Encountered "<EOF>" …`.
- When `definition` is supplied, it wins over `fields`/`entries`/`base`
  (the explicit fields/entries/base on the request are ignored).
- Parse failures return `IllegalArgumentException`'s message verbatim
  (`C parse error: …` or `C parse failed: …`), so CParser diagnostics
  surface as-is to the caller.
