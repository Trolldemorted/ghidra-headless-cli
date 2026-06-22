# FlatDecompilerAPI

Decompile the function at `address` to C source and return the text.

Wraps Ghidra's `ghidra.app.decompiler.flatapi.FlatDecompilerAPI` (`decompile(Function)` /
`decompile(Function, timeoutSecs)`). Read-only: the file is checked out before the call
(per policy) but **not** checked in, since decompilation does not modify the program.

This is the only non-`ghidra.app.cmd.function` procedure; it is pre-registered in
`RpcServer` and its handler lives in `procedures.ghidra.app.decompiler.flatapi`.

## Request
```typescript
interface FlatDecompilerAPIRequest {
  procedure: "FlatDecompilerAPI";
  file: string;              // project path of the target program, e.g. "/Mapeditor.exe"
  address: string;        // function entry, hex, e.g. "0x401000"
  timeoutSecs?: number;   // decompiler timeout (s); omit/0 = library default
}
```

## Response
```typescript
interface FlatDecompilerAPIResponse {
  success: true;
  function: string;       // function name
  address: string;        // resolved entry point
  decompilation: string;  // C source
}
```
or `{ "success": false, "error": "<message>" }`.

## Example
```json
{"procedure": "FlatDecompilerAPI", "file": "/Mapeditor.exe", "address": "0x401000"}
```
```json
{"procedure": "FlatDecompilerAPI", "file": "/Mapeditor.exe", "address": "0x401000", "timeoutSecs": 120}
```

## Errors

- `No function matched '<spec>' (by address or name). Nothing decompilable exists at <addr>. [<diagnosis>] Fix: ...`
  — the address resolves to no function (and no exact-name match). The
  diagnostic is shared with `Disassemble` via
  `RpcContext.diagnoseMissingFunction` (lifted out of the handler 2026-06-22),
  so both procedures produce the same helpful error on miss.
  The handler diagnoses what IS at the address and appends a copy-pasteable
  `function create` invocation. Three sub-cases:

  1. **Label without function** (the common vtable-slot / thunked-call case):
     the listing shows `LAB_00438360` but no function wraps that entry
     point. Output:
     ```
     No function matched '0x438360' (by address or name). Nothing
     decompilable exists at 00438360. There IS a label there:
     'LAB_00438360' (primary symbol at 00438360). A Data unit (not code)
     is defined at that address. Fix: create a function at 00438360 so
     the analyzer wraps the body:
       function create --file /<file> --address 00438360
     Optionally rename the entry point after creation:
       function rename --file /<file> --address 00438360 --name <descriptive_name>
     If the bytes are not yet instructions, disassemble first:
       function disassemble --file /<file> --address 00438360
     ```
     The original `No function matched '<spec>'` wording is preserved
     verbatim (existing log scrapers / test assertions still match); the
     augmentation is appended.

  2. **Disassembled instruction but no function body**: an Instruction is
     laid at the address but no Function wraps it. Same fix suggestion
     (create the function).

  3. **No code unit at all** (address not in any memory block): output
     notes the address is unmapped and suggests adding a memory block
     (`memory create`) before disassembling or creating a function.

- `Insufficent memory at address <addr> (length: <n> bytes)` — the
  program has no memory block covering the address; cannot decompile.
