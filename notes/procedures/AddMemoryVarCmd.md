# AddMemoryVarCmd

Add a memory variable (at `memoryAddress`) to the function at `address`.

Wraps Ghidra's `ghidra.app.cmd.function.AddMemoryVarCmd`. Mutating: the file is checked out
before the call and checked in immediately after; the call fails with an error if
the push fails.

<!-- Shared types: SourceType = "USER_DEFINED" | "ANALYSIS" | "IMPORTED" | "DEFAULT";
     AddressRange = { start: string; end?: string }  (hex addresses) -->

## Request
```typescript
interface AddMemoryVarCmdRequest {
  procedure: "AddMemoryVarCmd";
  memoryAddress: string;        // variable storage address
  address: string;              // hex, e.g. "0x401000"
  name?: string;
  dataType?: string;
  source?: SourceType;          // default "USER_DEFINED"
}
```

## Response
`{ "success": true }`, or `{ "success": false, "error": "<message>" }`.

## Example
```json
{"procedure": "AddMemoryVarCmd", "memoryAddress": "0x40a000", "address": "0x401000", "name": "g", "dataType": "int"}
```
