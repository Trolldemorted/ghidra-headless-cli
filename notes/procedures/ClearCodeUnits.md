# Listing — ClearCodeUnits

Remove Data/Instruction listing entries at one or more addresses (or
address ranges). Bytes are preserved. Program-level and mutating.

Mirrors the GUI's "Clear Code Bytes" action on the Bytes panel — useful
for undoing a wrong `memory apply-type` (e.g. the accidental 17×16-byte
overlap from the per-byte iteration bug), re-laying a type at the same
address, or stripping disassembled instructions from a region.

## Request
```typescript
interface ClearCodeUnitsRequest {
  procedure: "ClearCodeUnits";
  file: string;
  // Single address:
  address?: string;         // hex, e.g. "0x4024f1"
  // OR address range (one or more START:END ranges):
  addressSet?: Array<{ start: string; end?: string }>;
                           // end omitted = single-address range
                           // when supplied, overrides `address`
  clearContext?: boolean;   // also drop references and analysis
                           // context. [default: false]
}
```

## Response
```typescript
interface ClearCodeUnitsResponse {
  success: true;
  ranges: number;          // number of ranges (or single addresses)
                           // processed.
  cleared: number;         // number of code units (Data + Instruction)
                           // that existed before the clear. Already-
                           // undefined addresses count as 0.
}
```

## Notes

- **Mutating.** Goes through `RpcContext.runWrite` so the transaction,
  checkout, and check-in happen via the standard path. Commit failures
  are reported by the caller (`apply-type`'s commit-failure-after-
  mutation pattern is identical — but `clearCodeUnits` doesn't touch
  DTM types, so it's strictly an address-mutation).
- **Bytes are preserved.** `Listing.clearCodeUnits` removes the
  Data/Instruction entry but leaves the underlying bytes untouched.
  This is the inverse of `apply-type` and matches the GUI's "Clear
  Code Bytes" semantics.
- **Single-address semantics.** When the address falls inside a
  multi-byte unit (e.g. mid-way through a 4-byte int), Ghidra's
  `clearCodeUnits(start, end, false)` clears from the **containing
  unit's min address**. So `--address 0x103fc2` against a 4-byte int at
  0x103fc0 clears the whole int, not just the one byte. This is the
  GUI's behavior; it is not a bug.
- **Range semantics.** With `--address-set`, the clear runs from
  `start` to `end` inclusive. `end < start` is rejected before any
  mutation (the whole call fails, transaction is rolled back).
- **`clearContext` defaults to false.** When `false`, only the listing
  entries are removed; references from other locations to the cleared
  bytes (and any associated analysis context) are kept. Pass
  `--clear-context true` to also drop references — useful if the
  cleared region is being repurposed and old cross-references would
  just be noise.
- **Already-undefined addresses are not an error.** An `--address` or
  `--address-set` that points at no code unit returns
  `cleared: 0` (the operation is a no-op, the transaction still
  commits). To verify a clear actually did something, inspect
  `cleared` in the response. To verify the address is truly
  undefined afterward, use a future listing query.
- **Unmapped addresses are not an error.** The behavior is identical to
  "already-undefined" — Ghidra's `Listing.clearCodeUnits` silently
  skips non-memory regions and `cleared: 0` is returned.
- **Out-of-memory-block syntax errors.** The address parser
  (`ctx.requireAddress`) rejects strings Ghidra cannot parse (e.g.
  typoed hex) before mutation runs.
- The `cleared` count is computed BEFORE the clear, by walking
  `Listing.getCodeUnitAfter` over `[start, end]` and counting
  Data+Instruction hits. This is O(units-in-range) and bounded by the
  range size.
