# DataType — Set Field Comment

Set the comment on a single field of a struct or union. Program-level and
mutating. Per-field write path for `description`-style annotations on a
composite; the type-level doc comment is set via the [`description` field on
`EditDataType`](EditDataType.md#description--type-level-doc-comment).

## Request
```typescript
interface SetDataTypeFieldCommentRequest {
  procedure: "SetDataTypeFieldComment";
  file: string;
  path: string;             // full type path, e.g. "/MyStruct"
  field: string;            // field name OR zero-based index (see below)
  comment?: string;         // new comment; "" clears. Omitted is treated as "".
}
```

### `field` — name or index

`field` accepts either a name or a non-negative integer (as a string). The
server picks the right one:

- All-digit value -> literal index, after a bounds check against
  `getNumComponents()`. Out-of-range errors return
  `Field index N out of range for '/X' (valid: 0..M).`.
- Anything else -> first component whose `getFieldName()` matches. If
  multiple fields share a name the call errors with
  `Field name 'X' is ambiguous in '/path' (matches at least indices I and J); use the index instead.`
  — a struct with two fields named `pad` (legal in C via
  `-fms-extensions` and unnamed-bitfield padding patterns) is one such
  case.
- Not-found errors list the first 5 field names:
  `Field 'X' not found in '/path'. Available fields: [a, b, c, d, e]`.

## Response
```typescript
interface SetDataTypeFieldCommentResponse {
  success: true;
  path: string;             // echoes the input
  field: string;            // resolved field name (NOT the input specifier;
                             // `"0"` input becomes the actual field name)
  comment: string | null;   // new comment (null when cleared)
  previous: string | null;  // comment before the call (null when none was set)
}
```

`previous` lets the caller diff without re-querying. The CLI's
`datatype set-field-comment` prints `was: <prev>` and `now: <new>` (or
`cleared (was: <prev>)` when the new value is empty).

## Notes

- **Type guard: Composite only.** The target must be a struct or union.
  Enums, pointers, arrays, typedefs, and built-ins all return
  `Field comments are only supported on struct/union types; '/X' is a Y.`
  For typedefs this is intentional: typedefs share storage with the
  underlying type, and editing the comment on a typedef field would
  silently change it for every consumer of the struct. The error
  message points the caller at the underlying type.
- **Built-in guard.** Types whose source archive is
  `BUILT_IN_ARCHIVE_UNIVERSAL_ID` (BuiltIns / ANSI_C / windows_vs)
  return `Cannot edit built-in type 'X'.`.
- **Empty string clears.** A `""` (or omitted) `comment` clears the
  field's comment. `previous` still reflects the prior value so the
  caller can show "cleared (was: foo)".
- **Persistence.** The change runs inside one Ghidra transaction
  (`SetDataTypeFieldComment`); on commit the dispatcher checks the
  project file in so other clients see the new comment immediately.
  On throw the transaction rolls back and the field's previous
  comment is left untouched.
- **Round-trip.** The new comment is visible in
  `ShowDataType`'s `detail.fields[].comment` after a successful call.
