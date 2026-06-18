# DataType — Apply

Apply a data type at an address (single) or address range. Program-level
and mutating.

## Request
```typescript
interface ApplyDataTypeRequest {
  procedure: "ApplyDataType";
  file: string;
  type: string;             // C-syntax type expression (parsed via DataTypeParser)
                           // e.g. "int", "char *", "MyStruct", "Elf64_Ehdr", "byte[4]"
  // Single address:
  address?: string;         // hex address, e.g. "0x4024f1"
  length?: number;          // bytes to consume [default: type's length]
  // OR address range (one or more START:END ranges):
  addressSet?: Array<{ start: string; end?: string }>;
                           // end omitted = single-address range
                           // when supplied, overrides `address`
}
```

## Response
```typescript
interface ApplyDataTypeResponse {
  success: true;
  type: string;             // display name, e.g. "MyStruct"
  path: string | null;      // full DTM path of the resolved type, or null for primitives
  created: number;          // number of data units laid
  bytes: number;            // total bytes consumed
}
```

## Notes

- `type` accepts any C-syntax expression the DTM can parse: built-in
  primitives (`int`, `byte`, `char *`), user-defined types (`MyStruct`),
  arrays (`MyStruct[4]`), typedefs (`MyBytes`), etc. Resolution happens
  via `RpcContext.requireDataType`.
- **Reads-then-mutates**: existing code units are cleared first via
  `Listing.clearCodeUnits`, so an existing instruction doesn't fight the
  new data. Both operations run inside one Ghidra transaction.
- For ranges, the type is applied at every aligned address within every
  supplied range. The `length` field is only meaningful for single-address
  applications (it caps the bytes consumed below the type's natural
  length, e.g. applying `int` with `length=2` to consume only 2 bytes).
- An out-of-range or unmapped address returns
  `Insufficent memory at address XXXXXXXX (length: N bytes)`. The
  transaction is rolled back on this error.
- `created` counts the number of `Listing.createData` calls that returned
  non-null; if the address falls inside an existing data structure that's
  smaller than `length`, fewer units may be laid. `bytes` is the sum of
  those units' lengths.
