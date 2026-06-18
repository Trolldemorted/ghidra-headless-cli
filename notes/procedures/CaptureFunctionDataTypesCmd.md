# CaptureFunctionDataTypesCmd

Capture function signatures (as data types) in the set into the program's DTM.

Wraps Ghidra's `ghidra.app.cmd.function.CaptureFunctionDataTypesCmd`. Mutating: the file is checked out
before the call and checked in immediately after; the call fails with an error if
the push fails.

<!-- Shared types: SourceType = "USER_DEFINED" | "ANALYSIS" | "IMPORTED" | "DEFAULT";
     AddressRange = { start: string; end?: string }  (hex addresses) -->

## Request
```typescript
interface CaptureFunctionDataTypesCmdRequest {
  procedure: "CaptureFunctionDataTypesCmd";
  file: string;              // project path of the target program, e.g. "/Mapeditor.exe"
  address?: string;             // single entry point, OR
  addressSet?: AddressRange[];  // explicit ranges (one of address/addressSet required)
}
```

## Response
`{ "success": true }`, or `{ "success": false, "error": "<message>" }`.

## Example
```json
{"procedure": "CaptureFunctionDataTypesCmd", "file": "/Mapeditor.exe", "address": "0x401000"}
```
