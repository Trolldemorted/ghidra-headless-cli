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
  force?: boolean;          // default false; clear conflicting code units
                           // inside the type's consumed range and retry
                           // (raw bytes preserved; listing entries erased).
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
  forced: boolean;          // true if at least one range needed the
                             // force-clear retry path; false for clean
                             // creates (no conflict) and for hard errors.
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
- **Conflict with existing data — fix with `memory undefine`.** When the
  range the type would consume (start .. start+len-1) already contains a
  defined Data unit (whether it's another struct, a primitive, or a
  previously-applied type), Ghidra's `CodeManager.checkValidAddressRange`
  walks the data records forward AND backward and throws
  `CodeUnitInsertionException("Conflicting data exists at address X to Y",
  startData, endData)`. The handler catches that and re-throws with an
  explicit fix appended:

  ```
  Conflicting data exists at address 00101058 to 0010105b. Fix: clear the
  conflicting range first with
  `memory undefine --file /<file> --address-set 00101050:0010105f` (the
  struct's internal fields overlap with previously-typed bytes;
  apply-type will not silently clobber them). Then re-run apply-type.
  ```

  The address-set in the hint covers the FULL range the new type would
  consume (start .. start+len-1), not just the conflicting sub-range —
  the user typically wants to start clean. The transaction is rolled
  back on this error (no partial state).

  Why we surface this: Ghidra's default `Listing.createData(addr, dt, len)`
  (used by `CodeManager.createCodeUnit`) is destructive — it deletes the
  conflicting cache entries and lays the new type on top. The conflict
  exception fires only when the conflicting bytes are STRICTLY INSIDE
  the new type's range (not just adjacent), because the forward walk
  checks `existing.min <= end` and the backward walk checks
  `existing.max >= start`. So a struct whose internal fields overlap a
  previously-typed byte triggers the error; a struct placed AFTER an
  existing definition does not. Users reported the former case as
  confusing — the message now tells them to `memory undefine` first.
- `created` is the number of `Listing.createData` calls that returned
  non-null. For `--address` it's 1. For `--address-set` it's 1 per
  range element (the type is laid once per range). `bytes` is the sum
  of those units' lengths.

### `--force true`: opt into clearing conflicting code units

By default, when `Listing.createData` throws `CodeUnitInsertionException`
(see the conflict-with-existing-data section above), the call is rejected
with a clear error pointing at `memory undefine`. Passing `force:true`
opts into this instead:

1. Catch the `CodeUnitInsertionException`.
2. Widen the pre-mutation clear from `[start, start]` to
   `[start, start + len - 1]` — the full consumed range. Raw bytes are
   preserved; only their listing entries (Data/Instruction definitions)
   are erased.
3. Retry `Listing.createData(start, dt, len)`.
4. If the retry still throws (e.g. the conflicting byte is part of an
   Instruction that `clearCodeUnits` won't touch — `clearCodeUnits`
   preserves Instructions), surface the post-clear error verbatim with
   the cleared range appended.

The CLI flag is `--force true` (matching `datatype set-field-type`'s
shape; long-only, no short alias per the project's shorthand policy).

**What `--force` does NOT relax**:
- The strict-length guard on `--length` against non-Dynamic types
  (see "length is only honored for Dynamic types" above). Relaxing
  that one would silently clobber bytes the type would have laid;
  hard-rejected on both sides.
- The "type longer than range" pre-validation (multi-address only).
  Silently expanding past the user-supplied upper bound would be
  surprising.
- The non-conflicting default path: a clean create with `--force true`
  is identical to one without; `forced` on the response stays `false`.

**Use case**: a struct (say a 0x30-byte reader_blob) sits where you
want to lay a different struct (say a 0x30-byte AIM_Stream). The new
struct's first field is a 4-byte int; the existing struct's first
field is a 4-byte int of the same width. `apply-type` rejects because
the second field of the new struct overlaps the existing struct's
sub-fields. Without `--force`, the user must first run `memory undefine`
on the whole 0x30-byte range; with `--force true`, the apply-type call
itself does the clear+create in one transaction.
