# NamespaceListClasses

List class namespaces under an optional parent. The CLI equivalent of
the GUI's Symbol Tree filtered to show only classes.

Only `GhidraClass` namespaces (i.e. namespaces whose type is CLASS) are
emitted; plain namespaces are not listed by this verb. The list is
deterministic (sorted by slash-delimited path) so the output is
script-friendly.

## Walk semantics

- **`parent`** — path of the namespace to start from. `null`/empty/`"/"`
  defaults to the program's global namespace (root).
- **`recursive`** — when `true` (default), the walk descends into plain
  namespaces to find classes nested deeper. Stops descending into
  classes themselves (matches the GUI's Symbol Tree: a class's
  members are flattened under it, but a sub-class of the class is
  visited via its parent namespace's recursive descent). Concretely:
  we recurse into each child whose `getObject() instanceof Namespace`
  (covers both NAMESPACE and CLASS), but when a child's type is
  CLASS we record it and *do not* recurse into *its* children.
- **`limit`** — cap on the number of classes returned. `0` (default)
  means unlimited. When the cap is hit, `truncated` is `true` and
  the walk stops early (we don't keep counting — limits are exact,
  not "at least").

Cancellation: `ctx.monitor().checkCancelled()` is called per
iteration (mirrors `ListLabelsHandler`'s pattern).

## Output

Each entry carries:

- **`name`** — bare name.
- **`path`** — slash-delimited full path (so it can be fed directly
  into `--class PATH` for the mutating verbs).
- **`parentPath`** — slash-delimited path of the immediate parent
  namespace (the namespace directly containing the class).

The top-level response has:

- **`count`** — number of classes emitted.
- **`truncated`** — `true` iff the walk hit `limit` before completion.
- **`classes`** — array of class entries (sorted by `path`).

Read-only: the file is checked out by dispatch per policy but not
checked in. No transaction is opened.

## Request
```typescript
interface NamespaceListClassesRequest {
  procedure: "NamespaceListClasses";
  file: string;              // project path of the target program
  parent?: string;           // path of the namespace to start from;
                             //   null/empty/"/" -> global namespace
                             //   default: null (root)
  recursive?: boolean;       // recurse into plain namespaces; default true
  limit?: number;            // cap on results; 0 = unlimited; default 0
}
```

## Response
```typescript
interface NamespaceListClassesResponse {
  success: true;
  count: number;             // number of classes emitted
  truncated: boolean;        // true iff `limit` was hit
  classes: Array<{
    name: string;            // bare name
    path: string;            // slash-delimited full path
    parentPath: string;      // slash-delimited immediate parent path
  }>;
}
```

Or `{ "success": false, "error": "<message>" }`. Common errors:
- `"No namespace found for '<path>'."` — strict-mode miss; if a
  similar path exists in the program the error is suffixed with
  `Did you mean '<cand1>' or '<cand2>'?` (up to 5 leaf-name
  candidates across the whole namespace tree). Same shape and
  semantics as `NamespaceGetClass`'s error path — see
  [`NamespaceGetClass`](./NamespaceGetClass.md) for details.

## Examples

```json
// All classes in the program (recursive from root)
{"procedure": "NamespaceListClasses", "file": "/Mapeditor.exe"}

// Only direct children of /Game
{"procedure": "NamespaceListClasses", "file": "/Mapeditor.exe",
 "parent": "/Game", "recursive": false}

// First 5 classes
{"procedure": "NamespaceListClasses", "file": "/Mapeditor.exe",
 "limit": 5}
```

```json
{
  "success": true,
  "count": 2,
  "truncated": false,
  "classes": [
    {"name": "L_String", "path": "/Demangler/L_String",
     "parentPath": "/Demangler"},
    {"name": "OpMarketTrade", "path": "/Game/OpMarketTrade",
     "parentPath": "/Game"}
  ]
}
```

The `classes[].path` field can be passed straight to
`NamespaceGetClass`, `NamespaceRenameClass`, `NamespaceDeleteClass`,
or `FunctionSetClassAssociation --class PATH` — `list-class` is the
intended discovery verb for all four.
