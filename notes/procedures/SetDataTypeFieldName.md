# DataType — Set Field Name

Rename a single field of a struct or union. The field's type, the
field's comment, and the field's offset are all preserved. Program-level
and mutating.

This is the surgical alternative to
[`EditDataType`](EditDataType.md#rename) for renaming a single
field; the latter renames the whole type and changes every field at
once, which is wrong for the common case "I gave this field a bad
name earlier, fix it without disturbing the rest."

## Request
```typescript
interface SetDataTypeFieldNameRequest {
  procedure: "SetDataTypeFieldName";
  file: string;
  path: string;             // full type path, e.g. "/MyStruct"
  field: string;            // field name | @0xN offset | index (see below)
  name: string;             // new bare field name
}
```

`name` is the new bare field name (no path, no whitespace). Ghidra's
`DataTypeComponent.setFieldName` validates the name and throws
`InvalidInputException` for empty strings, names with forbidden
characters, and names that collide with another field in the same
composite. The exception is caught and surfaced as a normal `error`
response so the caller sees the exact cause.

### `field` — name, offset, or index

`field` accepts three forms; the resolver is shared with
[`SetDataTypeFieldComment`](SetDataTypeFieldComment.md#field--name-or-index)
and [`SetDataTypeFieldType`](SetDataTypeFieldType.md#field--name-offset-or-index):

- All-digit value (e.g. `"5"`) — literal index, after a bounds check.
- `@0xN` or `@0XN` (e.g. `"@0x10"`) — byte offset into a struct;
  rejected on unions with the same message as `set-field-type`.
- Anything else — first component whose `getFieldName()` matches;
  ambiguous → error.

## Response
```typescript
interface SetDataTypeFieldNameResponse {
  success: true;
  path: string;             // echoes the input
  field: string;            // NEW name
  type: string;             // unchanged type full path
  comment: string | null;   // unchanged comment
  previous: string;         // OLD name
}
```

`type` and `comment` are echoed (rather than just the new name) so
the caller can confirm "yes, the type and comment are still the
ones I expect after the rename" without a follow-up `datatype show`.

## Notes

- **Type guard: Composite only.** The target must be a struct or
  union. Enums, pointers, arrays, typedefs, and built-ins all
  return `Field renames are only supported on struct/union types; '/X' is a Y.`
  For typedefs the error points the caller at the underlying type.
  Built-ins return `Cannot edit built-in type 'X'.`.
- **Empty composite.** `'/X' has no fields to rename.` is returned
  for a composite with zero components.
- **Unnamed components.** Allowed — a field whose current name is
  `null` is a legal rename target. The new name simply replaces
  the `(unnamed)` display with whatever the caller provides.
- **Persistence.** The change runs inside one Ghidra transaction
  (`SetDataTypeFieldName`); on commit the dispatcher checks the
  project file in so other clients see the new name immediately.
  On throw the transaction rolls back and the field's previous
  name is left untouched.
- **Round-trip.** The new name is visible in
  `ShowDataType`'s `detail.fields[].name` after a successful call.
  Decompiler output that referenced the field by its old name
  re-resolves on the next `function decompile`.
