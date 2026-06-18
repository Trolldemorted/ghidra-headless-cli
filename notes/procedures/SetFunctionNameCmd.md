# SetFunctionNameCmd

Rename the function at `address` (falls back to a label if no function).

Wraps Ghidra's `ghidra.app.cmd.function.SetFunctionNameCmd`. Mutating: the file is checked out
before the call and checked in immediately after; the call fails with an error if
the push fails.

<!-- Shared types: SourceType = "USER_DEFINED" | "ANALYSIS" | "IMPORTED" | "DEFAULT";
     AddressRange = { start: string; end?: string }  (hex addresses) -->

## Request
```typescript
interface SetFunctionNameCmdRequest {
  procedure: "SetFunctionNameCmd";
  file: string;              // project path of the target program, e.g. "/Mapeditor.exe"
  address: string;              // hex, e.g. "0x401000"
  name: string;
  source?: SourceType;          // default "USER_DEFINED"
}
```

## Response
`{ "success": true }`, or `{ "success": false, "error": "<message>" }`.

## Example
```json
{"procedure": "SetFunctionNameCmd", "file": "/Mapeditor.exe", "address": "0x401000", "name": "main"}
```
