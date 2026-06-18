# DeleteVariableCmd

Delete a named variable from the function at `address`.

Wraps Ghidra's `ghidra.app.cmd.function.DeleteVariableCmd`. Mutating: the file is checked out
before the call and checked in immediately after; the call fails with an error if
the push fails.

<!-- Shared types: SourceType = "USER_DEFINED" | "ANALYSIS" | "IMPORTED" | "DEFAULT";
     AddressRange = { start: string; end?: string }  (hex addresses) -->

## Request
```typescript
interface DeleteVariableCmdRequest {
  procedure: "DeleteVariableCmd";
  file: string;              // project path of the target program, e.g. "/Mapeditor.exe"
  address: string;              // hex, e.g. "0x401000"
  name: string;                 // variable name
}
```

## Response
`{ "success": true }`, or `{ "success": false, "error": "<message>" }`.

## Example
```json
{"procedure": "DeleteVariableCmd", "file": "/Mapeditor.exe", "address": "0x401000", "name": "count"}
```
