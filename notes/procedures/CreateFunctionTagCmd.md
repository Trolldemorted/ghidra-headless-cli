# CreateFunctionTagCmd

Create a new function tag (program-wide), with optional comment.

Wraps Ghidra's `ghidra.app.cmd.function.CreateFunctionTagCmd`. Mutating: the file is checked out
before the call and checked in immediately after; the call fails with an error if
the push fails.

<!-- Shared types: SourceType = "USER_DEFINED" | "ANALYSIS" | "IMPORTED" | "DEFAULT";
     AddressRange = { start: string; end?: string }  (hex addresses) -->

## Request
```typescript
interface CreateFunctionTagCmdRequest {
  procedure: "CreateFunctionTagCmd";
  file: string;              // project path of the target program, e.g. "/Mapeditor.exe"
  name: string;
  comment?: string;
}
```

## Response
`{ "success": true }`, or `{ "success": false, "error": "<message>" }`.

## Example
```json
{"procedure": "CreateFunctionTagCmd", "file": "/Mapeditor.exe", "name": "REVIEWED", "comment": "manually reviewed"}
```
