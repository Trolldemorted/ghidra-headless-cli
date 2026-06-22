# DataType — Set Variant Comment

Set the comment on a single variant of an enum. Program-level and mutating.
Per-variant write path for `description`-style annotations on an enum; the
type-level doc comment is set via the [`description` field on
`EditDataType`](EditDataType.md#description--type-level-doc-comment).

## Request
```typescript
interface SetDataTypeVariantCommentRequest {
  procedure: "SetDataTypeVariantComment";
  file: string;
  path: string;             // full type path, e.g. "/Color"
  variant: string;          // variant name (must already exist on the enum)
  comment?: string;         // new comment; "" clears. Omitted is treated as "".
}
```

## Response
```typescript
interface SetDataTypeVariantCommentResponse {
  success: true;
  path: string;             // echoes the input
  variant: string;          // echoes the input
  comment: string | null;   // new comment (null when cleared)
  previous: string | null;  // comment before the call (null when none was set)
}
```

`previous` lets the caller diff without re-querying. The CLI's
`datatype set-variant-comment` prints `was: <prev>` and `now: <new>` (or
`cleared (was: <prev>)` when the new value is empty).

## Implementation note — `remove` + `add`

Ghidra's `Enum` interface exposes no `setComment(String, String)`
method. Variants are `(name, value, comment)` triples written via
`add(name, value, comment)`. To change a comment the handler must
`remove(name)` the variant and re-`add(name, value, newComment)` it.

Consequences:

- **Visible order is preserved.** `Enum.getNames()` is sorted by value,
  not insertion order, so the displayed order in the Data Type
  Manager is stable across the round-trip (assuming the new value
  matches the original, which we keep).
- **The variant's value is unchanged.** `getValue(name)` is captured
  before `remove` and passed to `add`, so the underlying numeric
  mapping never shifts. Two variants with the same value would lose
  insertion ordering — that is a malformed enum, and the API does not
  preserve it anyway.
- **Atomicity.** `remove` + `add` run inside one transaction. If
  `add` fails for any reason (collision on a duplicate name+value) the
  transaction rolls back and the variant's previous comment is left
  untouched.

## Notes

- **Type guard: Enum only.** The target must be an enum. Structs,
  unions, typedefs, pointers, arrays, and built-ins all return
  `Variant comments are only supported on enum types; '/X' is a Y.`.
  For typedefs this is intentional: typedefs share storage with the
  underlying type. The error message points the caller at the
  underlying enum.
- **Built-in guard.** Types whose source archive is
  `BUILT_IN_ARCHIVE_UNIVERSAL_ID` (BuiltIns / ANSI_C / windows_vs)
  return `Cannot edit built-in type 'X'.`.
- **Variant must already exist.** Adding a brand-new variant with a
  comment is the job of `EditDataType --add-entries` (which currently
  does not accept a per-entry comment — use a C `--definition`
  snippet like `enum Color { RED=0 /* primary */, BLUE=1; };` for
  that). On a not-found name the error lists the first 5 variant
  names: `Variant 'X' not found in enum '/path'. Available variants: [A, B, C, D, E]`.
- **Empty string clears.** A `""` (or omitted) `comment` clears the
  variant's comment. `previous` still reflects the prior value so the
  caller can show "cleared (was: foo)".
- **Persistence.** The change runs inside one Ghidra transaction
  (`SetDataTypeVariantComment`); on commit the dispatcher checks the
  project file in so other clients see the new comment immediately.
  On throw the transaction rolls back and the variant's previous
  comment is left untouched.
- **Round-trip.** The new comment is visible in
  `ShowDataType`'s `detail.entries[].comment` after a successful call.
