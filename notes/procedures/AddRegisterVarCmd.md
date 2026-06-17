# AddRegisterVarCmd

Add a register variable to the function at `address`.

Wraps Ghidra's `ghidra.app.cmd.function.AddRegisterVarCmd`. Mutating: the file is checked out
before the call and checked in immediately after; the call fails with an error if
the push fails.

<!-- Shared types: SourceType = "USER_DEFINED" | "ANALYSIS" | "IMPORTED" | "DEFAULT";
     AddressRange = { start: string; end?: string }  (hex addresses) -->

## Request
```typescript
interface AddRegisterVarCmdRequest {
  procedure: "AddRegisterVarCmd";
  program: string;              // project path of the target program, e.g. "/Mapeditor.exe"
  address: string;              // hex, e.g. "0x401000"
  register: string;             // e.g. "EAX"
  name?: string;
  dataType?: string;
  source?: SourceType;          // default "USER_DEFINED"
}
```

## Response
`{ "success": true }`, or `{ "success": false, "error": "<message>" }`.

## Example
```json
{"procedure": "AddRegisterVarCmd", "program": "/Mapeditor.exe", "address": "0x401000", "register": "EAX", "name": "ret", "dataType": "int"}
```
