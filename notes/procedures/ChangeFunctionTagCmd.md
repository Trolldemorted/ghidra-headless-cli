# ChangeFunctionTagCmd

Edit a tag's name or comment program-wide.

Wraps Ghidra's `ghidra.app.cmd.function.ChangeFunctionTagCmd`. Mutating: the file is checked out
before the call and checked in immediately after; the call fails with an error if
the push fails.

<!-- Shared types: SourceType = "USER_DEFINED" | "ANALYSIS" | "IMPORTED" | "DEFAULT";
     AddressRange = { start: string; end?: string }  (hex addresses) -->

## Request
```typescript
interface ChangeFunctionTagCmdRequest {
  procedure: "ChangeFunctionTagCmd";
  file: string;              // project path of the target program, e.g. "/Mapeditor.exe"
  tagName: string;              // existing tag
  value: string;                // new name or comment
  field?: "name" | "comment";   // default "name"
}
```

## Response
`{ "success": true }`, or `{ "success": false, "error": "<message>" }`.

## Example
```json
{"procedure": "ChangeFunctionTagCmd", "file": "/Mapeditor.exe", "tagName": "REVIEWED", "value": "AUDITED", "field": "name"}
```
