# SetStackDepthChangeCommand

Set a stack-depth-change value at `address`.

Wraps Ghidra's `ghidra.app.cmd.function.SetStackDepthChangeCommand`. Mutating: the file is checked out
before the call and checked in immediately after; the call fails with an error if
the push fails.

<!-- Shared types: SourceType = "USER_DEFINED" | "ANALYSIS" | "IMPORTED" | "DEFAULT";
     AddressRange = { start: string; end?: string }  (hex addresses) -->

## Request
```typescript
interface SetStackDepthChangeCommandRequest {
  procedure: "SetStackDepthChangeCommand";
  file: string;              // project path of the target program, e.g. "/Mapeditor.exe"
  address: string;              // hex, e.g. "0x401000"
  stackDepthChange?: number;    // default 0
}
```

## Response
`{ "success": true }`, or `{ "success": false, "error": "<message>" }`.

## Example
```json
{"procedure": "SetStackDepthChangeCommand", "file": "/Mapeditor.exe", "address": "0x401010", "stackDepthChange": -4}
```
