# RemoveFunctionTagCmd

Remove tag `tag` from the function at `address`.

Wraps Ghidra's `ghidra.app.cmd.function.RemoveFunctionTagCmd`. Mutating: the file is checked out
before the call and checked in immediately after; the call fails with an error if
the push fails.

<!-- Shared types: SourceType = "USER_DEFINED" | "ANALYSIS" | "IMPORTED" | "DEFAULT";
     AddressRange = { start: string; end?: string }  (hex addresses) -->

## Request
```typescript
interface RemoveFunctionTagCmdRequest {
  procedure: "RemoveFunctionTagCmd";
  program: string;              // project path of the target program, e.g. "/Mapeditor.exe"
  tag: string;
  address: string;              // hex, e.g. "0x401000"
}
```

## Response
`{ "success": true }`, or `{ "success": false, "error": "<message>" }`.

## Example
```json
{"procedure": "RemoveFunctionTagCmd", "program": "/Mapeditor.exe", "tag": "REVIEWED", "address": "0x401000"}
```
