# SetVariableDataTypeCmd

Set a variable's data type in the function at `address`.

Wraps Ghidra's `ghidra.app.cmd.function.SetVariableDataTypeCmd`. Mutating: the file is checked out
before the call and checked in immediately after; the call fails with an error if
the push fails.

<!-- Shared types: SourceType = "USER_DEFINED" | "ANALYSIS" | "IMPORTED" | "DEFAULT";
     AddressRange = { start: string; end?: string }  (hex addresses) -->

## Request
```typescript
interface SetVariableDataTypeCmdRequest {
  procedure: "SetVariableDataTypeCmd";
  program: string;              // project path of the target program, e.g. "/Mapeditor.exe"
  address: string;              // hex, e.g. "0x401000"
  name: string;                 // variable name
  dataType: string;
  source?: SourceType;          // default "USER_DEFINED"
}
```

## Response
`{ "success": true }`, or `{ "success": false, "error": "<message>" }`.

## Example
```json
{"procedure": "SetVariableDataTypeCmd", "program": "/Mapeditor.exe", "address": "0x401000", "name": "count", "dataType": "int"}
```
