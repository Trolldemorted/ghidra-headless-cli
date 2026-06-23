# FunctionSetNamespace

Move a function into a (possibly different) namespace and rename it. Both
edits are applied atomically inside one transaction so a partial failure
rolls back cleanly.

This is the explicit counterpart to [`SetFunctionNameCmd`](./SetFunctionNameCmd.md)
when the desired fully-qualified name lives in a different namespace than the
function's current one (e.g. promoting `GameScreen::Foo` to `Multiplayer::Foo`).
Unlike `SetFunctionNameCmd`, which silently mangles a `Foo::Bar` input, this
verb splits the namespace path and the leaf name and applies both atomically —
no doubling, no guessing.

<!-- Shared types: SourceType = "USER_DEFINED" | "ANALYSIS" | "IMPORTED" | "DEFAULT" -->

## Request
```typescript
interface FunctionSetNamespaceRequest {
  procedure: "FunctionSetNamespace";
  file: string;                     // project path, e.g. "/Patrician3.exe"
  address: string;                  // function entry-point address (hex)
  namespace?: string;               // slash-delimited namespace path, e.g. "/Game/MultiplayerScreen";
                                    //   "/" or empty/absent = global namespace
  name: string;                      // BARE leaf name — must NOT contain "::" or "/"
  source?: SourceType;              // default "USER_DEFINED"
}
```

## Response
```typescript
interface FunctionSetNamespaceResponse {
  success: true;
  functionName: string;             // the resulting leaf name
  namespacePath: string;            // slash-delimited path, e.g. "/Game/MultiplayerScreen"
}
```

Or `{ "success": false, "error": "<message>" }`.

## Example

Input:
```json
{"procedure": "FunctionSetNamespace", "file": "/Patrician3.exe",
 "address": "0x4381e0", "namespace": "/Game/MultiplayerScreen",
 "name": "MultiplayerScreen_ResetPlayerSessionState"}
```

Output:
```json
{
  "success": true,
  "functionName": "MultiplayerScreen_ResetPlayerSessionState",
  "namespacePath": "/Game/MultiplayerScreen"
}
```

## Behaviour

1. Looks up the function at `address`. Fails with `"No function at <addr>."`
   if none exists.
2. Rejects `name` containing `::` or `/` (those belong to `--namespace`).
3. Resolves `namespace` via the shared `NamespaceResolve` helper (strict
   path-match; on miss, surfaces up to 5 leaf-name candidates as
   `"did you mean ...?"` hints).
4. Inside a single transaction:
   * `function.setParentNamespace(target)` — moves the function.
   * `function.setName(leaf, source)` — renames the leaf in the new namespace.
   Any exception rolls back BOTH edits.

## Plain namespaces vs. classes

This verb accepts plain `Namespace` AND `GhidraClass` targets — `setParentNamespace`
takes the common base type and works for both. If you need the class-only
variant (with the auto-stub semantics for `__thiscall`'s implicit `this`),
use [`FunctionSetClassAssociation`](./FunctionSetClassAssociation.md) instead.
That verb restricts to `GhidraClass` so the auto-stub contract is enforced.

## CLI

```bash
ghidra-headless-cli function set-namespace \
  --file /Patrician3.exe \
  --address 0x4381e0 \
  --namespace /Game/MultiplayerScreen \
  --name   MultiplayerScreen_ResetPlayerSessionState \
  --source user-defined
```

## Why this verb exists

Prior to this, `function set-name --name "Foo::Bar"` was the only way to
express a namespace move from the CLI. Ghidra's `Function.setName("Foo::Bar", ...)`
silently fabricates a leaf (`Foo__Bar`) when the parent path can't be
resolved relative to the function's current namespace, and the resulting
garbage is invisible in `find-by-name` (which matches the literal mangled
leaf). Bulk renames reported `success: true` for ~25 functions while
producing 25 doubled names.

The fix is twofold:
1. `SetFunctionNameCmd` rejects `::` in `name` up front.
2. `FunctionSetNamespace` (this verb) provides the explicit, well-typed
   path for the namespace-move case.

See [`SetFunctionNameCmd`](./SetFunctionNameCmd.md) for the matching
rejection and the rationale.
