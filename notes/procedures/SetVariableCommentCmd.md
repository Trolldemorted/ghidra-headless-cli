# SetVariableCommentCmd

Set the comment on a named variable of the function at `address`.

Wraps Ghidra's `ghidra.app.cmd.function.SetVariableCommentCmd`. Mutating: the file is checked out
before the call and checked in immediately after; the call fails with an error if
the push fails.

<!-- Shared types: SourceType = "USER_DEFINED" | "ANALYSIS" | "IMPORTED" | "DEFAULT";
     AddressRange = { start: string; end?: string }  (hex addresses) -->

## Request
```typescript
interface SetVariableCommentCmdRequest {
  procedure: "SetVariableCommentCmd";
  address: string;              // hex, e.g. "0x401000"
  name: string;                 // variable name
  comment: string;
}
```

## Response
`{ "success": true }`, or `{ "success": false, "error": "<message>" }`.

## Example
```json
{"procedure": "SetVariableCommentCmd", "address": "0x401000", "name": "count", "comment": "loop counter"}
```
