# SetFunctionNameCmd

Rename the function whose entry point is `address`. The new name MUST be a bare
leaf — this command does NOT move the function across namespaces.

Wraps Ghidra's `ghidra.app.cmd.function.SetFunctionNameCmd`. Mutating: the file
is checked out before the call and checked in immediately after; the call fails
with an error if the push fails.

<!-- Shared types: SourceType = "USER_DEFINED" | "ANALYSIS" | "IMPORTED" | "DEFAULT";
     AddressRange = { start: string; end?: string }  (hex addresses) -->

## Request
```typescript
interface SetFunctionNameCmdRequest {
  procedure: "SetFunctionNameCmd";
  file: string;              // project path of the target program, e.g. "/Mapeditor.exe"
  address: string;              // hex, e.g. "0x401000"
  name: string;                  // bare leaf — must NOT contain "::" or "/"
  source?: SourceType;          // default "USER_DEFINED"
}
```

## Response
`{ "success": true }`, or `{ "success": false, "error": "<message>" }`.

## Example
```json
{"procedure": "SetFunctionNameCmd", "file": "/Mapeditor.exe", "address": "0x401000", "name": "main"}
```

## Error: `name` contains `::` (namespace hint rejected)

If `name` contains `::` (e.g. `MultiplayerScreen::Foo`), the call is rejected
with a clear error pointing at `FunctionSetNamespace`. This is a deliberate
guard against a silent-corruption bug:

```
--name takes a bare leaf and must not contain '::'.
Got 'MultiplayerScreen::Foo'. To change a function's namespace, use
`function set-namespace` (--namespace PATH --name LEAF); to set a class
association specifically, use `function set-class-association`.
```

### Why reject rather than let Ghidra try

`SetFunctionNameCmd.applyTo(Program)` is a thin wrapper over
`Function.setName(name, source)`. When `name` contains `::`, Ghidra's
`Function.setName` parses the parent-path, looks it up relative to the
function's CURRENT namespace, and falls back to literal mangling when the
parent doesn't resolve. The result depends on the function's current namespace:

* `GameScreen::MultiplayerScreen_ResetPlayerSessionState` + `MultiplayerScreen::MultiplayerScreen_ResetPlayerSessionState`
  → `GameScreen::MultiplayerScreen__MultiplayerScreen_ResetPlayerSessionState`
  (the `::` becomes `__`, then Ghidra doubles the prefix onto the existing
  leaf to avoid a name collision).
* Same input against a function in the GLOBAL namespace behaves differently —
  it does not double, and sometimes creates the namespace.

Behaviour depending on the function's current namespace is exactly what makes
the silent fabrication dangerous: bulk renames report `success: true` while
producing garbage. The CLI error above replaces that with an explicit, scoped
error and a pointer to the right verb.

### Use `FunctionSetNamespace` for namespace moves

```bash
# Move + rename in one transaction:
ghidra-headless-cli function set-namespace \
  --file /Patrician3.exe --address 0x4381e0 \
  --namespace /Game/MultiplayerScreen \
  --name   MultiplayerScreen_ResetPlayerSessionState
```

See [`FunctionSetNamespace`](./FunctionSetNamespace.md) for the full request
shape and behaviour. For the class-only variant (with auto-stub semantics for
`__thiscall`'s implicit `this`), use [`FunctionSetClassAssociation`](./FunctionSetClassAssociation.md).

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
