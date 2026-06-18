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
  // struct / union:
  replaceFields?: boolean;  // drop all existing fields before adding [default: false]
  addFields?: Array<{ name: string; type: string }>;
  // enum:
  addEntries?: Array<{ name: string; value: number }>;
  // typedef:
  base?: string;            // not yet supported — returns an error if supplied
  // OR a C snippet to merge into addFields/addEntries (see below):
  definition?: string;      // "struct { long long sum; char tag; };"
}
```

## Response

Same shape as `ShowDataType` — the edited type, fully described (post-edit).

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
