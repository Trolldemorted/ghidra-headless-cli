# NamespaceDeleteClass

Remove a class namespace symbol. **Does NOT delete any matching struct in
the DTM.**

Class and struct are independent objects that share only a name (see
`FunctionSetClassAssociation.md`). Deleting the class leaves the struct
untouched — if the user wants the struct gone too, call `DeleteDataType`
separately.

## Children: what survives, what doesn't

Only **functions** survive the delete. They are detached to the class's
parent namespace (e.g. `"/"` for a top-level class) so their entry point,
calling convention, signature, body, tags, and class association (if any)
remain intact — verified 2026-06-23 on P3 against `/Mapeditor.exe`:

| What was in the class               | After delete-class                                                |
| ----------------------------------- | ----------------------------------------------------------------- |
| Function member                     | **Survives as orphan at class's parent namespace** (still defined) |
| Sub-class                           | **Deleted** (along with ITS function members, also re-parented)   |
| Sub-namespace (plain)               | **Deleted** (along with ITS function members, also re-parented)   |
| Struct of the same name in the DTM  | **Untouched** (DTM is separate)                                    |
| Entry-point label of a function     | Label goes with the function (preserved)                          |

The function-preservation re-parents recursively: deleting `/Outer` also
re-parents functions inside `/Outer/Inner` and `/Outer/Inner2/Leaf` to the
parent of `/Outer` before `/Outer` and its subtree are torn down. Without
this, Ghidra's underlying `SymbolTable.removeSymbolSpecial` on a class
symbol destroys the function objects themselves (verified: after a plain
delete of `/DeleteClassBugTest`, `function decompile --address 0x4011f0`
returned `"No function matched '0x4011f0'... A Data unit (not code) is
defined at that address"`) — a silent data loss.

## Path validation

If the path resolves to a plain namespace (not a class), the call returns
an error. There is no plain-namespace-delete verb yet — out of scope this
round.

## Implementation

`detachFunctionDescendants` snapshots the class's children, then for each:

* If it's a `Function`, call `setParentNamespace(parent)` — pulling it OUT
  of the deleted subtree. Snapshot first so the iterator isn't invalidated
  by the re-parenting.
* If it's a `Namespace` (sub-namespace or sub-class), recurse with the
  SAME `reparentTo` target so deep functions escape to the top-level
  parent of the deleted class, not the deleted subtree.

After all functions are detached, `SymbolTable.removeSymbolSpecial` is
called on the class symbol; the (now empty) sub-namespaces and sub-classes
go with it.

## Caveats

* If a class has a function whose name collides with an existing function
  in the parent namespace, Ghidra's `setParentNamespace` will throw
  `DuplicateNameException`. The transaction is aborted and the class is
  left intact (no partial delete). Rename the conflicting orphan first.
* Class association on a re-parented function is preserved by Ghidra's
  `Function.setParentNamespace` — the function is no longer a class member
  (the class is gone) but if it had an `instance`/`static` association via
  `FunctionSetClassAssociation`, that survives on the orphan.

Mutating: the file is checked out before the call and checked in immediately
after; the call fails if the push fails.

## Request

```typescript
interface NamespaceDeleteClassRequest {
  procedure: "NamespaceDeleteClass";
  file: string;              // project path of the target program
  class: string;             // full path of the class to delete, e.g. "/Game/MyClass"
}
```

## Response

```typescript
interface NamespaceDeleteClassResponse {
  success: true;
  path: string;              // the deleted class's former path (echo of the request)
}
```

Or `{ "success": false, "error": "<message>" }`. Common errors:

- `"'<path>' is not a class (it's a plain namespace); this verb only deletes classes."`
- `"No namespace found for '<path>'."`
- A `DuplicateNameException` from `setParentNamespace` if a function in
  the class collides with an existing function in the parent namespace —
  rename the colliding orphan first.

## Example

```json
{"procedure": "NamespaceDeleteClass", "file": "/Patrician3.exe",
 "class": "/Game/MyClass"}
```
