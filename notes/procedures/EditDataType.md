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
