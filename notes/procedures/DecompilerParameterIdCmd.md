# DecompilerParameterIdCmd

Use the decompiler to identify and commit parameters/return for functions in the set.

Wraps Ghidra's `ghidra.app.cmd.function.DecompilerParameterIdCmd`. Mutating: the file is checked out
before the call and checked in immediately after; the call fails with an error if
the push fails.

<!-- Shared types: SourceType = "USER_DEFINED" | "ANALYSIS" | "IMPORTED" | "DEFAULT";
     AddressRange = { start: string; end?: string }  (hex addresses) -->

## Request
```typescript
interface DecompilerParameterIdCmdRequest {
  procedure: "DecompilerParameterIdCmd";
  program: string;              // project path of the target program, e.g. "/Mapeditor.exe"
  address?: string;             // single entry point, OR
  addressSet?: AddressRange[];  // explicit ranges (one of address/addressSet required)
  source?: SourceType;          // default "USER_DEFINED"
  commitDataTypes?: boolean;    // default true
  commitVoidReturn?: boolean;   // default true
  timeout?: number;             // decompiler timeout (s), default 60
}
```

## Response
`{ "success": true }`, or `{ "success": false, "error": "<message>" }`.

## Example
```json
{"procedure": "DecompilerParameterIdCmd", "program": "/Mapeditor.exe", "address": "0x401000"}
```
