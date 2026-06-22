# SetFunctionNameCmd

Rename the function whose entry point is `address`.

Wraps Ghidra's `ghidra.app.cmd.function.SetFunctionNameCmd`. Mutating: the file is checked out
before the call and checked in immediately after; the call fails with an error if
the push fails.

<!-- Shared types: SourceType = "USER_DEFINED" | "ANALYSIS" | "IMPORTED" | "DEFAULT";
     AddressRange = { start: string; end?: string }  (hex addresses) -->

## Request
```typescript
interface SetFunctionNameCmdRequest {
  procedure: "SetFunctionNameCmd";
  file: string;              // project path of the target program, e.g. "/Mapeditor.exe"
  address: string;              // hex, e.g. "0x401000"
  name: string;
  source?: SourceType;          // default "USER_DEFINED"
}
```

## Response
`{ "success": true }`, or `{ "success": false, "error": "<message>" }`.

## Example
```json
{"procedure": "SetFunctionNameCmd", "file": "/Mapeditor.exe", "address": "0x401000", "name": "main"}
```

## Error: no function at `address`

If there is no function at `address`, the call returns an error rather than
silently succeeding. Ghidra's `SetFunctionNameCmd.applyTo` returns `true`
immediately when `Listing.getFunctionAt(entry)` is `null` (verified by
disassembling `SetFunctionNameCmd.class` in `Base.jar` for Ghidra 12.1.2 —
bytecode at offset 31-36 is `ifnonnull 37; iconst_1; ireturn`). Without
this guard, the caller would see `success: true` but nothing was renamed —
no function is created, no symbol is renamed, the program is not dirty.

```
No function at 00101100; SetFunctionNameCmd cannot rename what does not
exist. Use `function create --address 00101100 --name X` to create the
function with this name in one call, or call `function create` first and
then `function set-name`.
```

This commonly happens after `namespace delete` demolishes the functions in
a namespace, leaving their entry addresses as bare code. To rebuild the
functions with their prior names, call `function create --name X` at each
address instead of `function set-name`.

See also `CreateFunctionCmd` for the create path; the suggested
`create --name X` form creates AND names in one transaction, matching the
intent behind most post-`namespace delete` recovery flows.
