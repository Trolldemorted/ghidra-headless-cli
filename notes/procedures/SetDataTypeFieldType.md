# DataType — Set Field Type

Retype a single field of a struct or union. The field's name, the field's
comment, and every other field in the composite are preserved. Program-level
and mutating.

This is the surgical alternative to
[`EditDataType`](EditDataType.md) (which only supports
`--add-fields` and `--replace-fields true` — the latter drops the entire
body). Most common use case: turning a `void*` or `uchar[]` placeholder
into a real pointer / struct type after the user has identified what
the field actually is, without re-emitting the whole struct as a
`#pragma pack(1)` C snippet.

## Request
```typescript
interface SetDataTypeFieldTypeRequest {
  procedure: "SetDataTypeFieldType";
  file: string;
  path: string;             // full type path, e.g. "/MyStruct"
  field: string;            // field name | @0xN offset | index (see below)
  type: string;             // C-syntax or full path of new type
  force?: boolean;          // default false; allow grow/shrink when set
}
```

`type` accepts the same forms as `EditDataType`'s `--fields` —
C-syntax expressions (`int`, `char *`, `byte[16]`, `MyStruct *`) and
full paths (`/MyCat/MyStruct`). The underlying
[`RpcContext.requireDataType`](../../ghidra-rpc-server/procedures/RpcContext.java)
handles both.

### `field` — name, offset, or index

`field` accepts three forms; the resolver is shared with
[`SetDataTypeFieldComment`](SetDataTypeFieldComment.md#field--name-or-index)
and [`SetDataTypeFieldName`](SetDataTypeFieldName.md#field--name-offset-or-index):

- All-digit value (e.g. `"5"`) — literal index, after a bounds check
  against `getNumComponents()`. Out-of-range errors return
  `Field index N out of range for '/X' (valid: 0..M).`.
- `@0xN` or `@0XN` (e.g. `"@0x10"`) — byte offset into a struct,
  resolved via `Structure.getComponentContaining(offset)`. Rejected on
  unions (all components share offset 0) with `@offset form is not
  supported on unions (all components share offset 0); use the field
  name or numeric index instead.`. If no component covers the offset
  (unaligned / packed layout) the error lists the available offsets:
  `No component at offset 0xN in '/X'. Available offsets: [0x0, 0x4 ('a'), 0x8, ...]`.
- Anything else — first component whose `getFieldName()` matches. If
  multiple fields share a name the call errors with
  `Field name 'X' is ambiguous in '/path' (matches at least indices I and J); use the index or @offset instead.`.
  Not-found errors list the first 5 field names.

## Length policy (strict-equal default)

Without `force:true`, the new type's `getLength()` must equal the
existing component's length exactly. Mismatch returns
`New type 'T' (length N) does not match existing component length M at field 'F' (index I) of '/X'. Retype requires identical length; pass force=true to allow grow/shrink (may shift trailing components).`.

The strict-equal default is conservative on purpose. Same-size
retype always hits Ghidra's `Structure.replace` fast path: the
component's offset is preserved, the comment is preserved (the 5-arg
form of `replace` takes a `newComment` parameter; the handler reads
the existing comment and passes it back so the call doesn't
silently clear it), and trailing components are untouched. This
covers every "turn this placeholder into a real type" case the user
ran into in the [WISH that prompted this
procedure](https://example.invalid/2026-06-24-wish-field-retype).

With `force:true`, Ghidra's slow path runs — the struct may grow or
shrink, and trailing components may shift. The call still preserves
the field's name and comment (passed explicitly to `replace`). After
a force-retype the caller should re-run `datatype show` to verify the
new layout. Packed structs (`#pragma pack(1)`) preserve their
explicit alignment: `replace` calls `repack(false, false)` which
respects `isPackingEnabled()`.

### Zero-length components

`Structure.replace` rejects `0 → N` (a 0-length component can only
be replaced by another 0-length component). The `--force` flag does
not rescue this — it's a hard API limit. If you need to insert
bytes at a 0-length slot, use
[`EditDataType`](EditDataType.md) with `--add-fields` or
`--replace-fields true` instead.

## Response
```typescript
interface SetDataTypeFieldTypeResponse {
  success: true;
  path: string;             // echoes the input
  field: string;            // resolved field name
  type: string;             // NEW type full path
  typeLength: number;       // NEW length
  comment: string | null;   // current comment (preserved)
  previousType: string;     // OLD type full path
  previousLength: number;   // OLD length
  previousComment: string | null;
  forced: boolean;          // echoes force for audit
}
```

The `previousType` / `previousLength` / `previousComment` triple is
a single pre-write read; the CLI uses it to print a `was: / now:`
diff without a follow-up `datatype show`. The `[forced]` tag is
appended to the `now:` line when `force:true` was supplied.

## Notes

- **Type guard: Composite only.** The target must be a struct or
  union. Enums, pointers, arrays, typedefs, and built-ins all return
  `Field retypes are only supported on struct/union types; '/X' is a Y.`
  For typedefs the error points the caller at the underlying type
  (typedefs share storage with the underlying struct, so editing
  through the typedef would silently change it for every consumer).
  Built-ins return `Cannot edit built-in type 'X'.`.
- **Empty composite.** `'/X' has no fields to retype.` is returned
  for a composite with zero components.
- **Unnamed components.** A field whose name is `null` (e.g. an
  anonymous bitfield) is rejected with `Field at index N of '/X' is
  unnamed; give it a real name first with set-field-name.` —
  the 5-arg `Structure.replace` would otherwise set its name to `""`
  (which Ghidra normalizes to `(unnamed)`, a visible change).
- **Struct vs union implementation.** Structs use the 5-arg form of
  `Structure.replace(int, DataType, int, String, String)` which
  takes a name+comment and is the only form that does not silently
  clear the comment (verified via `DataTypeComponentDB.update`
  bytecode, which calls `setString(4, comment)` unconditionally;
  pass `null` to clear). Unions have no `replace` API — the union
  path is `Composite.delete(int) + Composite.insert(int, dt, len,
  name, comment)` at the same ordinal. The new component appears at
  the same index in the union's iteration order.
- **Persistence.** The change runs inside one Ghidra transaction
  (`SetDataTypeFieldType`); on commit the dispatcher checks the
  project file in so other clients see the new type immediately.
  On throw (the new type doesn't resolve, the length check fails,
  or `replace` raises) the transaction rolls back and the
  composite is left untouched.
- **Round-trip.** The new type is visible in
  `ShowDataType`'s `detail.fields[].type` after a successful call.
  For a non-trivial retype (e.g. placeholder → real pointer), this
  also re-resolves referrers' use of the field; the new pointer type
  will flow through the decompiler on the next `function decompile`.
