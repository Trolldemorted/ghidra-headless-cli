# DeleteFunctionCmd

Delete the function at `address`.

Wraps Ghidra's `ghidra.app.cmd.function.DeleteFunctionCmd`. Mutating: the file is checked out
before the call and checked in immediately after; the call fails with an error if
the push fails.

<!-- Shared types: SourceType = "USER_DEFINED" | "ANALYSIS" | "IMPORTED" | "DEFAULT";
     AddressRange = { start: string; end?: string }  (hex addresses) -->

## Request
```typescript
interface DeleteFunctionCmdRequest {
  procedure: "DeleteFunctionCmd";
  file: string;              // project path of the target program, e.g. "/Mapeditor.exe"
  address: string;              // hex, e.g. "0x401000"
}
```

## Response
`{ "success": true }`, or `{ "success": false, "error": "<message>" }`.

## Example
```json
{"procedure": "DeleteFunctionCmd", "file": "/Mapeditor.exe", "address": "0x401000"}
```
