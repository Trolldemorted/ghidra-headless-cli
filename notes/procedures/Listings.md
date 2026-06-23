# Listings

Return the GUI Listings-window content for an address range.

Iterates every `Instruction` and `Data` code unit in the requested range via
`Listing.getCodeUnits(addrSet, true)` and renders each with
`CodeUnitFormat.DEFAULT`, the same call `Disassemble` uses — operand references
resolve the way the GUI listings does (e.g. `CALL dword ptr [PTR_LoadLibraryA_004c0ca4]`,
`JMP FUN_004100b0`, stack-var and parameter names).

This is the **range-scoped** companion to [Disassemble](Disassemble.md):
`Disassemble` only walks a function body and yields instructions; `Listings`
walks any address range (across function boundaries, into `.rdata`, etc.) and
yields both instructions and data.

This is **not** a `ghidra.app.cmd.function` command (a listing read is a
`Listing` query, not a `Command`); like `Disassemble` and `FlatDecompilerAPI`
it is pre-registered in `RpcServer` and its handler lives in
`procedures.ghidra.program.model.listing`. Read-only: the file is checked out
before the call (per policy) but **not** checked in, since reading the listing
does not modify the program (`mutates()` is false).

Undefined bytes (gaps with no listing entry) inside the requested range are
**skipped** — the GUI shows them too, but v1 of this procedure deliberately
omits them. If a caller needs the unmapped-gap layout they can compute it
from `count` vs. `end - start + 1`. Comments (EOL/pre/post/repeatable/plate)
are also out of scope for v1 — extend with a `comments` flag if a real need
arises.

## Request
```typescript
interface ListingsRequest {
  procedure: "Listings";
  file: string;        // project path of the target program, e.g. "/Mapeditor.exe"
  // Exactly one of the two:
  address?: string;        // single address, hex, e.g. "0x401000"
  addressSet?: { start: string; end?: string }[];   // one entry, START:END
  bytes?: boolean;         // include raw bytes (hex); default true
}
```

## Response
```typescript
interface ListingsUnit {
  kind: "instruction" | "data";
  address: string;          // unit's address, e.g. "00401000"
  label?: string;           // primary symbol at this address (omit if none)
  bytes?: string;           // raw bytes as hex (omit if --bytes=false or memory unreadable)
  mnemonic?: string;        // instructions only (e.g. "MOV")
  type?: string;            // data only (e.g. "char[14]", "int *")
  representation: string;   // full GUI-style text (e.g. "MOV EAX,dword ptr [ESP + x]",
                           //   or "\"Hello, world!\"" for a defined string)
}

interface ListingsResponse {
  success: true;
  start?: string;           // first requested address, normalized (omitted for empty range)
  end?: string;             // last requested address, normalized (omitted for empty range)
  count: number;            // number of code units (instructions + data)
  units: ListingsUnit[];
}
```
or `{ "success": false, "error": "<message>" }`.

## Examples

Instructions only (a small range inside a function):

Request:
```json
{"procedure": "Listings", "file": "/Mapeditor.exe",
 "addressSet": [{"start": "0x401000", "end": "0x401020"}]}
```

Response (truncated):
```json
{"success": true, "start": "00401000", "end": "00401020", "count": 5, "units": [
  {"kind": "instruction", "address": "00401000", "label": "main",
   "bytes": "558bec", "mnemonic": "PUSH", "representation": "PUSH EBP"},
  {"kind": "instruction", "address": "00401001",
   "bytes": "8bec", "mnemonic": "MOV", "representation": "MOV EBP,ESP"},
  ...
]}
```

Data path (a range that lands in `.rdata`):

Request:
```json
{"procedure": "Listings", "file": "/Mapeditor.exe",
 "address": "0x402050"}
```

Response:
```json
{"success": true, "start": "00402050", "end": "00402050", "count": 1, "units": [
  {"kind": "data", "address": "00402050", "label": "g_szName",
   "bytes": "a48656c6c6f00", "type": "char[14]",
   "representation": "\"Hello, world!\""}
]}
```

Without raw bytes:
```json
{"procedure": "Listings", "file": "/Mapeditor.exe",
 "addressSet": [{"start": "0x401000", "end": "0x401020"}], "bytes": false}
```

## Typical flow
1. (If raw) [Analyze](Analyze.md) — recover functions/disassembly.
2. `Listings` — read the range's listing-window content (this procedure).
3. For function-scoped dumps, [Disassemble](Disassemble.md) (instructions
   only, function body) or [FlatDecompilerAPI](FlatDecompilerAPI.md) (C-level
   view) are smaller and more targeted.

## When to use which

| You want... | Use |
| --- | --- |
| Instructions inside a function body | [Disassemble](Disassemble.md) — function-scoped, instructions only |
| C-level view of a function | [FlatDecompilerAPI](FlatDecompilerAPI.md) |
| Instructions + Data across an arbitrary range | **Listings** — this procedure |
| Raw bytes only (no listing interpretation) | [ReadBytes](ReadBytes.md) |
