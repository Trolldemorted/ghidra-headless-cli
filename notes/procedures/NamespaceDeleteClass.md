# NamespaceDeleteClass

Remove a class namespace symbol. **Does NOT delete any matching struct in
the DTM.**

Class and struct are independent objects that share only a name (see
`FunctionSetClassAssociation.md`). Deleting the class leaves the struct
untouched — if the user wants the struct gone too, call `DeleteDataType`
separately.

Children of the class (functions, sub-namespaces) become orphans under the
parent namespace, matching the GUI's right-click → Delete on a class in the
Symbol Tree.

If the path resolves to a plain namespace (not a class), the call returns an
error. There is no plain-namespace-delete verb yet — out of scope this round.

Removes via `SymbolTable.removeSymbolSpecial` on the class's underlying
symbol, which handles namespace symbols correctly (plain `removeSymbol`
refuses them).

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

## Example

```json
{"procedure": "NamespaceDeleteClass", "file": "/Patrician3.exe",
 "class": "/Game/MyClass"}
```
