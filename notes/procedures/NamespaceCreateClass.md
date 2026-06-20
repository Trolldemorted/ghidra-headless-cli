# NamespaceCreateClass

Create a new class namespace, OR convert an existing plain namespace into a class.

A "class" in Ghidra is a `Namespace` whose type is `CLASS` (a `GhidraClass`).
It is coupled to a struct in the program's Data Type Manager by **name only** —
the decompiler does the lookup at decompile time. See
`FunctionSetClassAssociation.md` for the association step that triggers the
class->struct name resolution.

This procedure does NOT touch the DTM. Association may auto-stub a struct on
edit; see `FunctionSetClassAssociation.md` for the warning.

Wraps `SymbolTable.createClass` (fresh mode) and `SymbolTable.convertNamespaceToClass`
(convert mode). Mutating: the file is checked out before the call and checked
in immediately after; the call fails if the push fails.

<!-- Shared types: SourceType = "USER_DEFINED" | "ANALYSIS" | "IMPORTED" | "DEFAULT" -->

## Request
```typescript
interface NamespaceCreateClassRequest {
  procedure: "NamespaceCreateClass";
  file: string;              // project path of the target program

  // Exactly one of the following two modes must be supplied:
  parent?: string;           // path of an existing parent namespace (e.g. "/Game");
                             // required with `name`; mutually exclusive with `fromNamespace`
  fromNamespace?: string;    // path of an existing PLAIN namespace to convert to a class;
                             // its body / children survive; the namespace's type flips
                             // from NAMESPACE to CLASS. Mutually exclusive with `parent`.

  name?: string;             // bare name (no slash) of the new class; required with `parent`,
                             // ignored with `fromNamespace`
  source?: SourceType;       // default "USER_DEFINED"
}
```

## Response
```typescript
interface NamespaceCreateClassResponse {
  success: true;
  path: string;              // full path of the new class, e.g. "/Game/MyClass"
  parentPath: string;        // full path of the parent namespace
}
```

Or `{ "success": false, "error": "<message>" }`. Common errors:
- `"Exactly one of 'parent' or 'fromNamespace' is required."`
- `"'name' is required when creating a class under 'parent'."`
- `"'<path>' is already a class; use rename-class to change its name."`
- `"No namespace found for '<path>'."`

## Example

```json
// Fresh class under /Game:
{"procedure": "NamespaceCreateClass", "file": "/Patrician3.exe",
 "parent": "/Game", "name": "OpMarketTrade"}

// Convert an existing plain namespace to a class:
{"procedure": "NamespaceCreateClass", "file": "/Patrician3.exe",
 "fromNamespace": "/Game/OldNamespace"}
```
