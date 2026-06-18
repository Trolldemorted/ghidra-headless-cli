# SetVariableNameCmd

Rename a variable (`oldName`->`newName`) in the function at `address`.

Wraps Ghidra's `ghidra.app.cmd.function.SetVariableNameCmd`. Mutating: the file is checked out
before the call and checked in immediately after; the call fails with an error if
the push fails.

<!-- Shared types: SourceType = "USER_DEFINED" | "ANALYSIS" | "IMPORTED" | "DEFAULT";
     AddressRange = { start: string; end?: string }  (hex addresses) -->

## Request
```typescript
interface SetVariableNameCmdRequest {
  procedure: "SetVariableNameCmd";
  file: string;              // project path of the target program, e.g. "/Mapeditor.exe"
  address: string;              // hex, e.g. "0x401000"
  oldName: string;
  newName: string;
  source?: SourceType;          // default "USER_DEFINED"
}
```

## Response
`{ "success": true }`, or `{ "success": false, "error": "<message>" }`.

## Example
```json
{"procedure": "SetVariableNameCmd", "file": "/Mapeditor.exe", "address": "0x401000", "oldName": "local_8", "newName": "count"}
```
