# CreateThunkFunctionCmd

Create a thunk function at `address`; point it at `referencedFunctionAddress` or auto-detect.

Wraps Ghidra's `ghidra.app.cmd.function.CreateThunkFunctionCmd`. Mutating: the file is checked out
before the call and checked in immediately after; the call fails with an error if
the push fails.

<!-- Shared types: SourceType = "USER_DEFINED" | "ANALYSIS" | "IMPORTED" | "DEFAULT";
     AddressRange = { start: string; end?: string }  (hex addresses) -->

## Request
```typescript
interface CreateThunkFunctionCmdRequest {
  procedure: "CreateThunkFunctionCmd";
  address: string;              // hex, e.g. "0x401000"
  referencedFunctionAddress?: string; // thunked function; omit to auto-detect
  checkExisting?: boolean;       // default false (used when auto-detecting)
}
```

## Response
`{ "success": true }`, or `{ "success": false, "error": "<message>" }`.

## Example
```json
{"procedure": "CreateThunkFunctionCmd", "address": "0x401000", "referencedFunctionAddress": "0x419580"}
```
