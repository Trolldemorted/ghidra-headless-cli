# Analyze

Run Ghidra's full auto-analysis pipeline over a program and check the result back in.

Programs created by [ProgramLoader](ProgramLoader.md) land **raw** — no functions, no
disassembly. `Analyze` is the standalone pass that recovers them. It mirrors the headless
analyzer's own sequence (`AutoAnalysisManager.initializeOptions()` →
`reAnalyzeAll(null)` → `startAnalysis(monitor)`) inside one transaction, then marks the
program analyzed. Analysis runs **on the Ghidra/server side** (the machine the RPC server
runs on), not on the client that uploaded the file; the shared Ghidra Server is only a
versioned file store and never analyzes anything.

`startAnalysis` blocks the request thread until analysis completes — there is no GUI
analysis tool in a headless server.

## Concurrency / locking (important)

`Analyze` is program-targeted and mutating, so dispatch takes an **exclusive checkout**
of the file **before** opening it and checks a new version in afterward. That exclusive
checkout is held for the **entire** analysis, which can run for minutes on a large
binary. For its whole duration:

* this server is single-flight (the global dispatch lock), and
* no other repository client can check the file out.

So prefer to `Analyze` freshly imported files (nobody is waiting on them) rather than
shared programs others may need.

## Request
```typescript
interface AnalyzeRequest {
  procedure: "Analyze";
  file: string;   // project path of the target, e.g. "/imports/foo.exe"
  force?: boolean;    // re-analyze even if already analyzed; default true.
                      // when false, an already-analyzed program is left untouched.
}
```

## Response
```typescript
interface AnalyzeResponse {
  success: true;
  analyzed: boolean;       // did this call run the pipeline? (false = skipped, see force)
  wasAnalyzed: boolean;    // had the program already been analyzed before this call?
  functionCount: number;   // functions present after the call
  symbolCount: number;     // symbols present after the call
  format: string;          // executable format, e.g. "Executable and Linking Format (ELF)"
}
```
or `{ "success": false, "error": "<message>" }`.

## Example
Request:
```json
{"procedure": "Analyze", "file": "/imports/analyze_test_true", "force": true}
```
Response:
```json
{"success": true, "analyzed": true, "wasAnalyzed": false, "functionCount": 134, "symbolCount": 554, "format": "Executable and Linking Format (ELF)"}
```

A second call with `"force": false` on the same program is a no-op:
```json
{"success": true, "analyzed": false, "wasAnalyzed": true, "functionCount": 134, "symbolCount": 554, "format": "Executable and Linking Format (ELF)"}
```

## Typical flow
1. `ProgramLoader` — import the raw binary.
2. `Analyze` — recover functions/disassembly (this procedure).
3. `SetFunctionNameCmd`, `FlatDecompilerAPI`, … — work on the recovered functions.
