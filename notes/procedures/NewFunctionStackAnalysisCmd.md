# NewFunctionStackAnalysisCmd

Newer stack-analysis pass over the set.

Wraps Ghidra's `ghidra.app.cmd.function.NewFunctionStackAnalysisCmd`. Mutating: the file is checked out
before the call and checked in immediately after; the call fails with an error if
the push fails.

<!-- Shared types: SourceType = "USER_DEFINED" | "ANALYSIS" | "IMPORTED" | "DEFAULT";
     AddressRange = { start: string; end?: string }  (hex addresses) -->

## Request
```typescript
interface NewFunctionStackAnalysisCmdRequest {
  procedure: "NewFunctionStackAnalysisCmd";
  address?: string;             // single entry point, OR
  addressSet?: AddressRange[];  // explicit ranges (one of address/addressSet required)
  forceProcessing?: boolean;    // default false
}
```

## Response
`{ "success": true }`, or `{ "success": false, "error": "<message>" }`.

## Example
```json
{"procedure": "NewFunctionStackAnalysisCmd", "address": "0x401000"}
```
