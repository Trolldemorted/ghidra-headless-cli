# CreateExternalFunctionCmd

Create an external function `name` in `library`, optionally bound to `address`.

Wraps Ghidra's `ghidra.app.cmd.function.CreateExternalFunctionCmd`. Mutating: the file is checked out
before the call and checked in immediately after; the call fails with an error if
the push fails.

<!-- Shared types: SourceType = "USER_DEFINED" | "ANALYSIS" | "IMPORTED" | "DEFAULT";
     AddressRange = { start: string; end?: string }  (hex addresses) -->

## Request
```typescript
interface CreateExternalFunctionCmdRequest {
  procedure: "CreateExternalFunctionCmd";
  file: string;              // project path of the target program, e.g. "/Mapeditor.exe"
  library: string;              // external library name
  name: string;
  address?: string;             // optional memory address
  source?: SourceType;          // default "USER_DEFINED"
}
```

## Response
`{ "success": true }`, or `{ "success": false, "error": "<message>" }`.

## Example
```json
{"procedure": "CreateExternalFunctionCmd", "file": "/Mapeditor.exe", "library": "KERNEL32.DLL", "name": "Sleep"}
```
