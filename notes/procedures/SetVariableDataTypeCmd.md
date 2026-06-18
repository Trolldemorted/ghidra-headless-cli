# SetVariableDataTypeCmd

Set a variable's data type in the function at `address`.

Wraps Ghidra's `ghidra.app.cmd.function.SetVariableDataTypeCmd`. Mutating: the file is checked out
before the call and checked in immediately after; the call fails with an error if
the push fails.

<!-- Shared types: SourceType = "USER_DEFINED" | "ANALYSIS" | "IMPORTED" | "DEFAULT";
     AddressRange = { start: string; end?: string }  (hex addresses) -->

## Request
```typescript
interface SetVariableDataTypeCmdRequest {
  procedure: "SetVariableDataTypeCmd";
  file: string;              // project path of the target program, e.g. "/Mapeditor.exe"
  address: string;              // hex, e.g. "0x401000"
  name: string;                 // variable name
  dataType: string;
  source?: SourceType;          // default "USER_DEFINED"
}
```

## Response
`{ "success": true }`, or `{ "success": false, "error": "<message>" }`.

## Example
```json
{"procedure": "SetVariableDataTypeCmd", "file": "/Mapeditor.exe", "address": "0x401000", "name": "count", "dataType": "int"}
```

## Notes

**Data-type name vs path.** A type's canonical path (`datatype show --path /X`
returns `{path:"/X"}`) starts with `/`, but its **name** does not. Ghidra's
`DataTypeParser` treats a leading `/` as a category separator, so passing the
path form as a *value* (e.g. `dataType: "/L_String"`) makes it look up
"type `String` in category `L`" — which usually fails.

The RPC server normalises this for you: a single leading `/` in `dataType`
is stripped before parsing, so both forms resolve the same type:

```
dataType: "L_String"     # the name (preferred)
dataType: "/L_String"    # the path form — also accepted, leading '/' dropped
```

For multi-segment paths like `/cat/sub/Type`, only the leaf (`Type`) is
matched against the type table. That works when `Type` is unambiguous across
categories; if you need a specific category's `Type`, look it up first with
`datatype show --path /cat/sub/Type` to find a distinguishing name. The same
normalisation applies to every procedure that takes a data-type value:
`AddStackVarCmd`, `AddRegisterVarCmd`, `AddMemoryVarCmd`, `SetReturnDataTypeCmd`,
`UpdateFunctionCommand`, `ApplyFunctionSignatureCmd`, `ApplyDataTypeCmd`,
`CreateDataTypeCmd` (`base`, `fields[].type`), `EditDataTypeCmd`, `ReplaceDataTypeCmd`.
