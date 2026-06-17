# AddStackVarCmd

Add a stack variable to the function at `address`.

Wraps Ghidra's `ghidra.app.cmd.function.AddStackVarCmd`. Mutating: the file is checked out
before the call and checked in immediately after; the call fails with an error if
the push fails.

<!-- Shared types: SourceType = "USER_DEFINED" | "ANALYSIS" | "IMPORTED" | "DEFAULT";
     AddressRange = { start: string; end?: string }  (hex addresses) -->

## Request
```typescript
interface AddStackVarCmdRequest {
  procedure: "AddStackVarCmd";
  address: string;              // hex, e.g. "0x401000"
  stackOffset?: number;         // default 0
  name?: string;
  dataType?: string;
  source?: SourceType;          // default "USER_DEFINED"
}
```

## Response
`{ "success": true }`, or `{ "success": false, "error": "<message>" }`.

## Example
```json
{"procedure": "AddStackVarCmd", "address": "0x401000", "stackOffset": -8, "name": "buf", "dataType": "char[16]"}
```
