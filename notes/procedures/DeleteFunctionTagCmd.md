# DeleteFunctionTagCmd

Delete a function tag program-wide.

Wraps Ghidra's `ghidra.app.cmd.function.DeleteFunctionTagCmd`. Mutating: the file is checked out
before the call and checked in immediately after; the call fails with an error if
the push fails.

<!-- Shared types: SourceType = "USER_DEFINED" | "ANALYSIS" | "IMPORTED" | "DEFAULT";
     AddressRange = { start: string; end?: string }  (hex addresses) -->

## Request
```typescript
interface DeleteFunctionTagCmdRequest {
  procedure: "DeleteFunctionTagCmd";
  file: string;              // project path of the target program, e.g. "/Mapeditor.exe"
  name: string;
}
```

## Response
`{ "success": true }`, or `{ "success": false, "error": "<message>" }`.

## Example
```json
{"procedure": "DeleteFunctionTagCmd", "file": "/Mapeditor.exe", "name": "REVIEWED"}
```
