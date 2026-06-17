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
{"procedure": "FlatDecompilerAPI", "address": "0x401000"}
```
```json
{"procedure": "FlatDecompilerAPI", "address": "0x401000", "timeoutSecs": 120}
```
