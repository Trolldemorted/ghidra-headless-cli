# Disassemble

Return the instruction listing of the function at `address`.

Iterates the function body's instructions in address order
(`Listing.getInstructions(function.getBody(), true)` — the body may span several
ranges; the iterator covers them all) and renders each with `CodeUnitFormat.DEFAULT`,
which resolves operand references the way the GUI listing does (e.g.
`CALL dword ptr [PTR_LoadLibraryA_004c0ca4]`, `JMP FUN_004100b0`, stack-var and
parameter names).

This is **not** a `ghidra.app.cmd.function` command (disassembly is a `Listing`
read, not a `Command`); like [FlatDecompilerAPI](FlatDecompilerAPI.md) it is
pre-registered in `RpcServer` and its handler lives in
`procedures.ghidra.program.model.listing`. Read-only: the file is checked out
before the call (per policy) but **not** checked in, since reading the listing does
not modify the program (`mutates()` is false).

Only instructions are returned; data or undefined code units inside the body are
skipped. An external or not-yet-disassembled function simply yields an empty list
(`count: 0`) rather than an error. Run [Analyze](Analyze.md) first if a freshly
imported program has no instructions yet.

## Request
```typescript
interface DisassembleRequest {
  procedure: "Disassemble";
  file: string;        // project path of the target program, e.g. "/Mapeditor.exe"
  address: string;        // function entry, hex, e.g. "0x401000"
  bytes?: boolean;        // include raw instruction bytes (hex); default true
}
```

## Response
```typescript
interface DisassembleInstruction {
  address: string;        // instruction address, e.g. "004024f1"
  bytes?: string;         // raw bytes as hex (omitted if bytes=false or memory unreadable)
  mnemonic: string;       // e.g. "MOV"
  representation: string; // full GUI-style text, e.g. "MOV EAX,dword ptr [ESP + x]"
}

interface DisassembleResponse {
  success: true;
  function: string;                     // function name
  address: string;                      // resolved entry point
  count: number;                        // number of instructions
  instructions: DisassembleInstruction[];
}
```
or `{ "success": false, "error": "<message>" }`.

## Error: no function at `address`

When `address` does not point to a function, the error message is enriched
by `RpcContext.diagnoseMissingFunction` (lifted from
`FlatDecompilerAPIHandler`, 2026-06-22). The error includes:

- The original `"No function matched '<addr>' (by address or name)."` line
  (verbatim — log scrapers may parse it), followed by `"Nothing
  decompilable exists at <addr>."` (preserved from the original
  decompile-only diagnostic for log-scraper compatibility),
- What IS at the address: a primary symbol name (e.g. `LAB_00438360`),
  an Instruction (code disassembled but no function wraps it), a Data
  unit, or "no code unit covers the address" (unmapped bytes).
- A copy-pasteable fix: `function create --file /<file> --address <addr>`,
  plus a `function rename` recipe if the primary symbol is a `LAB_xxx`.

Example (unmapped bytes):
```
No function matched '0x00438360' (by address or name).
No code unit covers the address either — the bytes are unmapped.
Fix: create a function at 00438360 so the analyzer wraps the body:
  function create --file /<file> --address 00438360
If the bytes are unmapped, add a memory block first (memory create),
then disassemble, then create the function.
```

Example (label only):
```
No function matched '0x00401045' (by address or name). There IS a label
there: 'LAB_00401045' (primary symbol at 00401045). A Data unit (not
code) is defined at that address. Fix: create a function at 00401045 so
the analyzer wraps the body:
  function create --file /<file> --address 00401045
Optionally rename the entry point after creation:
  function rename --file /<file> --address 00401045 --name <descriptive_name>
If the bytes are not yet instructions, disassemble first:
  function disassemble --file /<file> --address 00401045
```

For non-parseable `address` values (a name with no function match),
the bare `"No function matched '...'"` message is returned — there's
nothing to diagnose. This mirrors `FlatDecompilerAPI`'s behavior; the
diagnostic is shared via `RpcContext.requireFunction` so the two
procedures produce consistent errors.

## Example
Request:
```json
{"procedure": "Disassemble", "file": "/Mapeditor.exe", "address": "0x4024f1"}
```
Response (truncated):
```json
{"success": true, "function": "fn_cmd_rpc_test", "address": "004024f1", "count": 34,
 "instructions": [
   {"address": "004024f1", "bytes": "8b44e404", "mnemonic": "MOV", "representation": "MOV EAX,dword ptr [ESP + x]"},
   {"address": "004024f5", "bytes": "83ec20", "mnemonic": "SUB", "representation": "SUB ESP,0x20"},
   {"address": "0040257f", "bytes": "e92cdb0000", "mnemonic": "JMP", "representation": "JMP FUN_004100b0"}
 ]}
```

Without raw bytes:
```json
{"procedure": "Disassemble", "file": "/Mapeditor.exe", "address": "0x4024f1", "bytes": false}
```

## Typical flow
1. (If raw) [Analyze](Analyze.md) — recover functions/disassembly.
2. `Disassemble` — read the instruction listing (this procedure).
3. [FlatDecompilerAPI](FlatDecompilerAPI.md) — the C-level view of the same function.
