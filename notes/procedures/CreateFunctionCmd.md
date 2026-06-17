# CreateFunctionCmd

Create a function at `address` (body computed by disassembly).

Wraps Ghidra's `ghidra.app.cmd.function.CreateFunctionCmd`. Mutating: the file is checked out
before the call and checked in immediately after; the call fails with an error if
the push fails.

<!-- Shared types: SourceType = "USER_DEFINED" | "ANALYSIS" | "IMPORTED" | "DEFAULT";
     AddressRange = { start: string; end?: string }  (hex addresses) -->

## Request
```typescript
interface CreateFunctionCmdRequest {
  procedure: "CreateFunctionCmd";
  address: string;              // hex, e.g. "0x401000"
  name?: string;                // default FUN_/thunk naming
  source?: SourceType;          // default "USER_DEFINED"
}
```

## Response
`{ "success": true }`, or `{ "success": false, "error": "<message>" }`.

## Example
```json
{"procedure": "CreateFunctionCmd", "address": "0x401000", "name": "my_func"}
```
