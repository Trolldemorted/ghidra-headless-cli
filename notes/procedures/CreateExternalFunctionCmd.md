# CreateExternalFunctionCmd

Create an external function `name` in `library`, optionally bound to `address`.

Wraps Ghidra's `ghidra.app.cmd.function.CreateExternalFunctionCmd`. Mutating: the file is checked out
before the call and checked in immediately after; the call fails with an error if
the push fails.

<!-- Shared types: SourceType = "USER_DEFINED" | "ANALYSIS" | "IMPORTED" | "DEFAULT";
     AddressRange = { start: string; end?: string }  (hex addresses) -->

## Request
```typescript
interface CreateExternalFunctionCmdRequest {
  procedure: "CreateExternalFunctionCmd";
  library: string;              // external library name
  name: string;
  address?: string;             // optional memory address
  source?: SourceType;          // default "USER_DEFINED"
}
```

## Response
`{ "success": true }`, or `{ "success": false, "error": "<message>" }`.

## Example
```json
{"procedure": "CreateExternalFunctionCmd", "library": "KERNEL32.DLL", "name": "Sleep"}
```
