# UpdateFunctionCommand

Update a function's signature in one shot: calling convention, return type, and parameter list.

Wraps Ghidra's `ghidra.app.cmd.function.UpdateFunctionCommand`. Mutating: the file is checked out
before the call and checked in immediately after; the call fails with an error if
the push fails.

<!-- Shared types: SourceType = "USER_DEFINED" | "ANALYSIS" | "IMPORTED" | "DEFAULT";
     AddressRange = { start: string; end?: string }  (hex addresses) -->

## Request
```typescript
interface UpdateFunctionCommandRequest {
  procedure: "UpdateFunctionCommand";
  program: string;              // project path of the target program, e.g. "/Mapeditor.exe"
  address: string;              // hex, e.g. "0x401000"
  updateType?: "DYNAMIC_STORAGE_FORMAL_PARAMS" | "DYNAMIC_STORAGE_ALL_PARAMS" | "CUSTOM_STORAGE"; // default DYNAMIC_STORAGE_FORMAL_PARAMS
  callingConvention?: string;   // e.g. "__stdcall"
  returnType?: string;          // data type name
  parameters?: { name?: string; dataType: string }[];
  source?: SourceType;          // default "USER_DEFINED"
  force?: boolean;              // default false; override conflicting storage
}
```

## Response
`{ "success": true }`, or `{ "success": false, "error": "<message>" }`.

## Example
```json
{"procedure": "UpdateFunctionCommand", "program": "/Mapeditor.exe", "address": "0x401000", "returnType": "int", "parameters": [{"name": "a", "dataType": "int"}, {"name": "b", "dataType": "char *"}]}
```
