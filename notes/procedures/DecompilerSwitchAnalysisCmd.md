# DecompilerSwitchAnalysisCmd

Recover switch tables for the function at `address` (decompiles it first).

Wraps Ghidra's `ghidra.app.cmd.function.DecompilerSwitchAnalysisCmd`. Mutating: the file is checked out
before the call and checked in immediately after; the call fails with an error if
the push fails.

<!-- Shared types: SourceType = "USER_DEFINED" | "ANALYSIS" | "IMPORTED" | "DEFAULT";
     AddressRange = { start: string; end?: string }  (hex addresses) -->

## Request
```typescript
interface DecompilerSwitchAnalysisCmdRequest {
  procedure: "DecompilerSwitchAnalysisCmd";
  program: string;              // project path of the target program, e.g. "/Mapeditor.exe"
  address: string;              // hex, e.g. "0x401000"
  timeout?: number;             // decompiler timeout (s), default 60
}
```

## Response
`{ "success": true }`, or `{ "success": false, "error": "<message>" }`.

## Example
```json
{"procedure": "DecompilerSwitchAnalysisCmd", "program": "/Mapeditor.exe", "address": "0x401000"}
```
