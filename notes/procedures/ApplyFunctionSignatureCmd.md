# ApplyFunctionSignatureCmd

Apply a C-style `signature` to the function at `address`.

Wraps Ghidra's `ghidra.app.cmd.function.ApplyFunctionSignatureCmd`. Mutating: the file is checked out
before the call and checked in immediately after; the call fails with an error if
the push fails.

<!-- Shared types: SourceType = "USER_DEFINED" | "ANALYSIS" | "IMPORTED" | "DEFAULT";
     AddressRange = { start: string; end?: string }  (hex addresses) -->

## Request
```typescript
interface ApplyFunctionSignatureCmdRequest {
  procedure: "ApplyFunctionSignatureCmd";
  file: string;              // project path of the target program, e.g. "/Mapeditor.exe"
  address: string;              // hex, e.g. "0x401000"
  signature: string;            // e.g. "int foo(char *s, int n)"
  source?: SourceType;          // default "USER_DEFINED"
}
```

## Response
`{ "success": true }`, or `{ "success": false, "error": "<message>" }`.

## Example
```json
{"procedure": "ApplyFunctionSignatureCmd", "file": "/Mapeditor.exe", "address": "0x401000", "signature": "int foo(char *s, int n)"}
```
