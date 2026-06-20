# NamespaceGetClass

Get metadata for a class namespace — the CLI equivalent of inspecting a
class in the GUI's Symbol Tree.

A "class" in Ghidra is a `Namespace` whose type is `CLASS` (a
`GhidraClass`). This verb only returns classes — passing a plain
namespace's path returns an error (mirrors the create / rename / delete
verbs' symmetry). The response shape is the same regardless of how the
class was created (fresh via `createClass`, or via
`convertNamespaceToClass`).

Resolves the path with `NamespaceUtils.getNamespaceByPath` (with a
recursive simple-name fallback) via the shared `NamespaceResolve`
helper, then collects:

- **`name`** — bare name (`Namespace.getName()`).
- **`path`** — slash-delimited full path. The default
  `Namespace.getName(true)` returns `::`-delimited paths; we use
  slash-delimited output so the value is directly usable as
  `--class PATH` input to the mutating namespace verbs.
- **`parentPath`** — slash-delimited parent path (`"/"` for top-level).
- **`isClass`** — always `true` for this verb.
- **`source`** — the symbol's `SourceType` (e.g. `USER_DEFINED`,
  `IMPORTED`). Null if the symbol has no source set.
- **`id`** — `Namespace.getID()` (long).
- **`memberCount`** — number of functions whose parent namespace is
  this class. Matches the GUI's Symbol Tree "Functions" count.
  Includes both `this`-bound methods (associated via
  `FunctionSetClassAssociation`) and any free functions parented here.
- **`childNamespaceCount`** — number of immediate children whose
  symbol type is NAMESPACE or CLASS. Computed by walking
  `SymbolTable.getSymbols(ns)` filtered to
  `sym.getSymbolType().isNamespace()`.
- **`bodyAddress`** — the class's anchor address (the auto-stubbed
  struct's entry point, or the function-body address if the class
  was converted from a function namespace). Goes through the symbol
  because `Namespace.getBody()` is null/empty for non-function
  namespaces.

Read-only: the file is checked out by dispatch per policy but not
checked in. No transaction is opened.

## Request
```typescript
interface NamespaceGetClassRequest {
  procedure: "NamespaceGetClass";
  file: string;              // project path of the target program
  class: string;             // full path of the class, e.g. "/Game/OpMarketTrade"
}
```

## Response
```typescript
interface NamespaceGetClassResponse {
  success: true;
  name: string;              // bare name
  path: string;              // full slash-delimited path
  parentPath: string;        // slash-delimited parent path; "/" for top-level
  isClass: true;             // always true for this verb
  source: string | null;     // "USER_DEFINED" | "ANALYSIS" | "IMPORTED" | "DEFAULT" | null
  id: number;                // Namespace.getID()
  memberCount: number;       // functions parented under this class
  childNamespaceCount: number;  // immediate namespace/class children
  bodyAddress: string | null;   // the class's anchor address (auto-stub entry point)
}
```

Or `{ "success": false, "error": "<message>" }`. Common errors:
- `"Missing required field 'class'."`
- `"No namespace found for '<path>'."`
- `"'<path>' is not a class (it's a plain namespace); this verb only returns classes."`

## Example

```json
{"procedure": "NamespaceGetClass", "file": "/Mapeditor.exe",
 "class": "/Demangler/L_String"}
```

```json
{
  "success": true,
  "name": "L_String",
  "path": "/Demangler/L_String",
  "parentPath": "/Demangler",
  "isClass": true,
  "source": "USER_DEFINED",
  "id": 12345,
  "memberCount": 1,
  "childNamespaceCount": 0,
  "bodyAddress": "0x00401000"
}
```

The `path` field can be passed straight to `NamespaceRenameClass`,
`NamespaceDeleteClass`, or `FunctionSetClassAssociation --class PATH`,
making this a useful building block for class-management scripts.
