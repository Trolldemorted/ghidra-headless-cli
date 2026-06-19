# DataType — Create

Create a struct / union / enum / typedef. Program-level and mutating.
Fails on a name collision in the target category (whether the existing
type is archive-resolved or local). To overwrite an existing type in
place, use [`ReplaceDataType`](ReplaceDataType.md) instead.

## Request
```typescript
interface CreateDataTypeRequest {
  procedure: "CreateDataType";
  file: string;
  // Explicit-JSON path. Required when `definition` is NOT given.
  kind?: "struct" | "union" | "enum" | "typedef";
  name: string;             // type name; existing types with the same name cause an ERROR
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

- **Conflict policy: strict-fail.** A name clash in the target category —
  whether the existing type is archive-resolved (a stub pulled in from
  an upstream archive) or a local program-DTM type — causes the call
  to return `success:false` with a message of the form
  `Data type 'X' already exists in /Y (kind=..., size=..., source=...).
  The source field tells you whether you're colliding with a BUILTIN,
  ARCHIVE, or program-DTM type, and the response points you at the
  right next step. To overwrite in place, use
  [`ReplaceDataType`](ReplaceDataType.md).
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

## See also

- [`ReplaceDataType`](ReplaceDataType.md) — overwrite an existing type
  in place (GUI "Replace..." semantic). Accepts `--path` to
  disambiguate when the same name appears in multiple categories.
- [`ShowDataType`](ShowDataType.md) — read-only inspection of any type
  by path.
- [`EditDataType`](EditDataType.md) — non-destructive edits (rename,
  move, append fields, replace fields). Cannot change total size or
  typedef base kind.
- [`DeleteDataType`](DeleteDataType.md) — remove a user-defined type.

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
- **Anonymous OUTER types are rejected.** `struct { int x; };` returns
  `C snippet must define a NAMED type. Got an anonymous struct/union/enum
  body — write e.g. `struct Foo { int x; };` with an identifier.`
  Ghidra's CParser handles anonymous outer types inconsistently (sometimes
  returning the last field's type, sometimes auto-naming to `enum_1`),
  so we surface a clear error instead.
- **Anonymous NESTED types are auto-named.** A `struct { … }` or
  `union { … }` used as a field type inside a named outer type is valid C,
  so CParser accepts it — and because the DTM requires every composite to
  have a name, CParser assigns one from a per-DTM counter:
  `_struct_1`, `_struct_2`, … (and `_union_N` / `_enum_N` for the other
  kinds). The field is still usable; the type just has a generated name.
  If that generated name is already taken in the DTM (by a prior parse,
  a built-in, or an imported archive), `addDataType` with
  `REPLACE_HANDLER` resolves the collision by suffixing `.conflict`
  (then `.conflict1`, …). Example:

  ```c
  // Sent:
  union MyUnion { struct { int x; int y; } s; int z; };
  // After parsing, the field `s` shows up as type `_struct_2` (or
  // `_struct_2.conflict` if that name was already in the DTM).
  ```

  **Recommendation:** if you want a predictable name, declare the nested
  type explicitly:

  ```c
  union MyUnion { struct Inner { int x; int y; } s; int z; };
  //                 ^^^^^^ now lands as `Inner`, no auto-name, no .conflict
  ```
- The snippet must produce exactly ONE type. Forward declarations and
  multi-type snippets return an error.
- The closing brace of struct/union/enum must be followed by `;`. Without
  it the CParser errors out with `Encountered "<EOF>" …`.
- When `definition` is supplied, it wins over `fields`/`entries`/`base`
  (the explicit fields/entries/base on the request are ignored).
- Parse failures return `IllegalArgumentException`'s message verbatim
  (`C parse error: …` or `C parse failed: …`), so CParser diagnostics
  surface as-is to the caller.

## Common gotcha: `stdint.h` types (`uintN_t` / `intN_t`)

Ghidra's two parsers each ship with their own built-in alias map for
common C type names, and those maps are **incomplete and asymmetric**:

- **Unsigned `uint8_t` / `uint16_t` / `uint32_t` / `uint64_t`** are
  built into `CParser`'s typedef table (the `--definition` path). They
  auto-resolve to `ulonglong` etc. without any pre-definition:
  `typedef unsigned long long uint64_t;` and
  `struct With64 { uint64_t x; };` both succeed. The act of parsing
  also drops a `uint64_t` typedef into the DTM, so subsequent
  `--fields --type uint64_t` resolves it through `DataTypeParser`.
- **Signed `int8_t` / `int16_t` / `int32_t` / `int64_t`** are
  **not** in either parser's built-in map. They fail in both paths:
  - `--definition "struct Bar { int64_t x; };"` →
    `C parse error: Undefined data type "int64_t"`.
  - `--fields --type int64_t` →
    `Unrecognized data type of "int64_t"`.
- The standard C primitives `short`, `float`, `wchar_t`, `bool`,
  `double`, `long long`, etc. are in both maps and work everywhere.

This is a Ghidra limitation, not a bug in our parser layer —
`CDefinitionParser` and `RpcContext.requireDataType` both delegate to
Ghidra's parsers, and the parsers' built-in tables are what they are.
We do not paper over it silently because the silent-coercion surprise
("my struct used `int32_t` and now half the fields are 4 bytes shorter
than expected") is worse than the loud error.

**Workaround.** Define the missing signed-stdint typedefs once via
`--definition`. The act of defining `int64_t` puts it in the program
DTM, which makes `DataTypeParser` resolve it on every subsequent
`--fields --type int64_t`:

```bash
ghidra-headless-cli datatype create --file /your-program --definition "typedef long long  int64_t;"
ghidra-headless-cli datatype create --file /your-program --definition "typedef int         int32_t;"
ghidra-headless-cli datatype create --file /your-program --definition "typedef short       int16_t;"
ghidra-headless-cli datatype create --file /your-program --definition "typedef signed char  int8_t;"
```

After that, both `--definition "struct Foo { int64_t x; };"` and
`--fields --type int64_t` resolve correctly. The four typedefs cost
~20 bytes of DTM storage and persist for the lifetime of the program.

If you only need them transiently for one snippet, you can pre-declare
them at the top of the same `definition` string — but CParser still
won't recognize `int64_t` until the `typedef` line above it has been
parsed into the DTM, so for a single-call flow you still need the
preamble to run first.
