# DataType — Edit

Apply a batch of edits to a single data type. Program-level and mutating.
All operations run in a single Ghidra transaction; if any operation fails,
the entire batch rolls back and the program is not modified.

## Request
```typescript
interface EditDataTypeRequest {
  procedure: "EditDataType";
  file: string;
  path: string;             // full type path
  // All fields are optional. Any combination can be supplied in one call.
  rename?: string;          // new name; must be unique in target category
  move?: string;            // move to a different category path
  description?: string;     // type-level doc comment; "" clears. Not supported on typedefs.
  // struct / union:
  replaceFields?: boolean;  // drop all existing fields before adding [default: false]
  addFields?: Array<{ name: string; type: string }>;
  // enum:
  addEntries?: Array<{ name: string; value: number }>;
  // per-element comments have their own procedures:
  //   - SetDataTypeFieldComment  (struct/union field)
  //   - SetDataTypeVariantComment (enum variant)
  // typedef:
  base?: string;            // not yet supported — returns an error if supplied
  // OR a C snippet to merge into addFields/addEntries (see below):
  definition?: string;      // "struct { long long sum; char tag; };"
}
```

## Response

Lean confirmation (`ShowDataTypeHandler.ConfirmResponse`):

```typescript
interface EditDataTypeResponse {
  success: true;
  verb: "edited";
  kind: "struct" | "union" | "enum" | "typedef";
  name: string;
  path: string;
  category: string;
  size: number;            // post-edit
  source: "USER";
  sourceArchive: null;
  // Per-kind: exactly one of these is set; the others are absent.
  fieldCount?: number;     // struct, union — post-edit count
  entryCount?: number;     // enum — post-edit count
  base?: string;           // typedef (unchanged by edit; reported for consistency)
}
```

**Default CLI output** (one line on stdout):

```
edited <name> (<kind>, size 0xNN, N fields)
edited <name> (<kind>, size 0xNN, N entries)     // enum
edited <name> (<kind>, size 0xNN, base=<base>)  // typedef
```

The C declaration (`c` field) and the full structured `detail` object
are INTENTIONALLY OMITTED from the confirmation. For a multi-step
edit (e.g. `replaceFields: true` + 5 `addFields`) the user typically
already has a script that produced the call — they want a yes/no
line, not the re-rendered C block. To get the C declaration, run
`datatype show --path /X` afterwards. To get the structured detail,
add `--json` (planned).

## Notes

- **Built-in types are rejected**: any type whose source archive is the
  program's `BUILT_IN_ARCHIVE_UNIVERSAL_ID` (BuiltIns / ANSI_C / windows_vs)
  returns `Cannot edit built-in type 'X'`. User-defined types in the root
  category are editable.
- **`replaceFields: true` deletes all existing fields before `addFields` is
  applied**, so a struct goes from `[a, b, c]` to `[d, e]` with one call.
  Without `replaceFields`, `addFields` appends.
- `rename` invokes `DataType.setName`; a name clash in the destination
  category returns an error.
- `move` resolves the target category up-front; an unknown category returns
  `No data-type category found for '/X'`.
- `addFields` field types and `addEntries` values are parsed/applied in
  order. Empty `addFields` array is a no-op.
- `base` change for typedef returns `Typedef 'base' change requires delete +
  recreate; not yet supported.` — the workaround is `datatype delete` then
  `datatype create`.
- All edits are batched into one transaction: if step 3 of 3 fails, steps
  1-2 are rolled back. The program is checked in by the dispatcher on
  commit; on rollback, no check-in occurs.

## `description` — type-level doc comment

`description` sets the free-text doc comment shown in the Data Type
Manager for the type itself. It maps to Ghidra's `DataType.setDescription`
and is preserved on round-trip via `ShowDataType` (the `description` key
in the `detail` block). Pass `""` to clear.

```jsonc
{"path":"/ClaudeHeadlessStruct","description":"Header struct written by ghidra-headless-cli."}
```

Constraints:

- **Not supported on typedefs — and the underlying reason is subtle.**
  Ghidra's `TypedefDataType` does NOT override `DataType.setDescription`
  (verified by `javap` on `SoftwareModeling.jar` for Ghidra 12.1.2:
  only `getDescription` is declared, not `setDescription`). The
  inherited default is a **silent no-op** — the call returns
  successfully, exits with code 0, and the description is *not*
  persisted. The handler detects the typedef up front and surfaces
  a clear error before any commit:
  `Cannot set description on typedef '/X' — Ghidra's TypedefDataType
  does not persist per-typedef descriptions. Set the description on
  the underlying type instead (use datatype show --path /X to discover
  the path).` Set the description on the underlying struct / enum
  directly.
- **Built-ins are rejected** with `Cannot edit built-in type 'X'`
  (same guard as `rename` and `move`).
- Per-field and per-variant comments have their own procedures:
  `SetDataTypeFieldComment` and `SetDataTypeVariantComment`. Use those
  to annotate a struct field or an enum variant; `description` is
  strictly the type-level field.

## `definition` — C-snippet replace

`definition` is the most powerful edit op: parse a C snippet, then
`DataTypeConflictHandler.REPLACE_HANDLER` swaps the parsed type into
the target's slot in place. References in function signatures, applied
data, and other types are preserved (REPLACE is in-place, not
delete+create). `rename` and `move` happen first, so the snippet's
body replaces the type at its new path/name.

```jsonc
// Replace a struct's body wholesale. The snippet must declare the
// target's name (struct CFoo) — REPLACE_HANDLER collides on name.
{"path":"/CFoo","definition":"struct CFoo { long long sum; char tag; };"}

// Replace an enum's body the same way:
{"path":"/Color","definition":"enum Color { BLUE=2, ALPHA=3 };"}
```

Rules:

- The snippet must produce exactly ONE type. The target type's `path`
  defines the kind being edited; the snippet's kind must match
  (`struct`/`union` ↔ composite target, `enum` ↔ enum target,
  `typedef` ↔ typedef target). Mismatches return
  `C snippet kind 'X' does not match target 'Y'.` BEFORE any commit.
- **The snippet's name must equal the target's name.** Mismatches return
  `C snippet name 'X' does not match target 'Y'. The snippet must
  declare the target's name (e.g. `struct Y { ... };`).` The
  `EditDataType` request does NOT auto-inject the target's name — write
  it into the snippet.
- **Anonymous snippets are rejected** (same rule as `CreateDataType`).
  Write `struct TargetName { int x; };`, not `struct { int x; };`.
- `definition` wins over `addFields`/`addEntries` on the request — the
  explicit arrays are dropped, mirroring the precedence rule on
  `CreateDataType`.
- Parse failures return `IllegalArgumentException`'s message verbatim.
