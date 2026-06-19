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
  created: number;          // number of data units laid (1 for --address,
                             // 1 per --address-set entry)
  bytes: number;            // total bytes consumed
  warnings?: string[];      // one entry per --address-set range where the
                             // type's length is shorter than the range.
                             // Format: "START:END (type consumes N of M bytes)".
                             // Absent when all ranges exactly match the
                             // type's length or only --address was used.
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
- **Range semantics: single-application per entry.** Each element of
  `addressSet` lays the type ONCE at `start`, consuming
  `dt.getLength()` bytes (or `length` for Dynamic types). The `end` is
  an upper bound. This matches the GUI's press-D-and-type behavior:
  apply once at the cursor, let the type's length extend it. To fill a
  region with copies of a type, pass multiple `addressSet` entries
  stepped by the type's length. The previous implementation iterated
  every byte in the range and laid the type at each address, which
  produced overlapping copies for any type that consumes more than one
  byte (the user-reported "17×16-byte struct over a 16-byte range" bug).
- **Pre-validation.** Before any mutation, every range is checked
  against the type's length:
  - **Type longer than range** → whole call rejected with `Type 'X'
    consumes N bytes but range A:B is only M byte(s). Widen the range,
    shorten the type, or remove the entry from addressSet.`
  - **Type shorter than range** → mutation proceeds; the response
    carries a `warnings` entry for the range, listing the uncovered
    byte count. The CLI prints the warning on stderr so the user can
    decide whether to widen the type or narrow the range.
  - **Type exactly matches range** → no warning.
  - **Single-address (`--address`)** → no size check (the type naturally
    extends forward from the single address).
- **`length` is only honored for Dynamic types** (typedefs, strings,
  `FactoryDataType`-based composites). For fixed-length types (int, char,
  struct, union, primitive pointer, ...) Ghidra's
  `Listing.createData(addr, dt, len)` silently overwrites `len` with
  `dt.getLength()`, so a `length` that differs from the type's natural
  length would be a no-op. To avoid the silent-ignore footgun, the call
  rejects mismatched `length` against non-Dynamic types with a clear
  error. A `length` that equals `dt.getLength()` is silently accepted
  (no-op hint). Examples:
  - `apply-type --type int --address 0x401000 --length 1` → error
    (`Cannot override length for non-Dynamic type 'int' (4 bytes)`).
  - `apply-type --type int --address 0x401000 --length 4` → ok, lays 4.
  - `apply-type --type string --address 0x401000 --length 8` → ok,
    Dynamic type honors the hint.
- An out-of-range or unmapped address returns
  `Insufficent memory at address XXXXXXXX (length: N bytes)`. The
  transaction is rolled back on this error.
- `created` is the number of `Listing.createData` calls that returned
  non-null. For `--address` it's 1. For `--address-set` it's 1 per
  range element (the type is laid once per range). `bytes` is the sum
  of those units' lengths.
