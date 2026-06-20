# NamespaceRenameClass

Rename a class namespace. **PURE NAMESPACE RENAME — does NOT rename any
matching struct.**

Class and struct are independent objects that share only a name (see
`FunctionSetClassAssociation.md` for the coupling). If a struct with the old
name exists in the DTM, it stays. If the decompiler needs to resolve `this`
by class name after the rename, the user must rename the struct separately
via `EditDataType` (or keep both names in sync).

Renames via the public `Symbol.setName(String, SourceType)` on the class's
underlying symbol. (`GhidraClassDB.setName` exists but is package-private to
`ghidra.program.database.symbol`.)

Mutating: the file is checked out before the call and checked in immediately
after; the call fails if the push fails.

<!-- Shared types: SourceType = "USER_DEFINED" | "ANALYSIS" | "IMPORTED" | "DEFAULT" -->

## Request
```typescript
interface NamespaceRenameClassRequest {
  procedure: "NamespaceRenameClass";
  file: string;              // project path of the target program
  class: string;             // full path of the class to rename, e.g. "/Game/OldName"
  name: string;              // new bare name (no slash)
  source?: SourceType;       // default "USER_DEFINED"
}
```

## Response
```typescript
interface NamespaceRenameClassResponse {
  success: true;
  path: string;              // new full path of the renamed class
  parentPath: string;        // full path of the parent namespace (unchanged)
}
```

Or `{ "success": false, "error": "<message>" }`. Common errors:
- `"'<path>' is not a class (it's a plain namespace); use namespace create-class --from-namespace to convert it first."`
- `"Duplicate name" / "Invalid name"` (from Ghidra's name validation)
- `"No namespace found for '<path>'."`

## Example

```json
{"procedure": "NamespaceRenameClass", "file": "/Patrician3.exe",
 "class": "/Game/OldName", "name": "NewName"}
```
