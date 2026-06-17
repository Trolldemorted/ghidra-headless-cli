# CreateMultipleFunctionsCmd

Create functions across an address set.

Wraps Ghidra's `ghidra.app.cmd.function.CreateMultipleFunctionsCmd`. Mutating: the file is checked out
before the call and checked in immediately after; the call fails with an error if
the push fails.

<!-- Shared types: SourceType = "USER_DEFINED" | "ANALYSIS" | "IMPORTED" | "DEFAULT";
     AddressRange = { start: string; end?: string }  (hex addresses) -->

## Request
```typescript
interface CreateMultipleFunctionsCmdRequest {
  procedure: "CreateMultipleFunctionsCmd";
  address?: string;             // single entry point, OR
  addressSet?: AddressRange[];  // explicit ranges (one of address/addressSet required)
  source?: SourceType;          // default "USER_DEFINED"
}
```

## Response
`{ "success": true }`, or `{ "success": false, "error": "<message>" }`.

## Example
```json
{"procedure": "CreateMultipleFunctionsCmd", "address": "0x401000"}
```
