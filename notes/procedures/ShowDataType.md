# DataType — Show

Read a single data type by full path and return its full description (struct
fields, enum entries, typedef base, pointer/array base, etc.). Read-only.

## Request
```typescript
interface ShowDataTypeRequest {
  procedure: "ShowDataType";
  file: string;
  path: string;            // full type path, e.g. "/ELF/Elf64_Ehdr" or "/int"
}
```

## Response
```typescript
interface ShowDataTypeResponse {
  success: true;
  kind: "struct" | "union" | "enum" | "typedef"
       | "pointer" | "array" | "functiondef" | "bitfield" | "primitive";
  name: string;
  path: string;
  category: string;
  size: number;            // byte length; -1 for variable-length primitives
  source: "USER" | "BUILTIN" | "ARCHIVE";
  sourceArchive: string | null;

  // Optional fields, depending on `kind`:
  fields?: FieldEntry[];       // struct/union
  entries?: EnumEntry[];       // enum
  base?: string;               // typedef / pointer / array base (display name)
  count?: number;              // array element count
  signature?: string;          // function definition prototype
  bitOffset?: number;          // bitfield
  bitSize?: number;
  packed?: boolean;            // struct
  alignment?: number;          // struct
  description?: string;
}
interface FieldEntry {
  name: string;                // "" for unnamed fields
  offset: number;
  size: number;
  type: string;                // C-syntax display name, e.g. "char *", "MyStruct[4]"
}
interface EnumEntry {
  name: string;
  value: number;               // long, but JS numbers are fine
}
```

## Notes

- `path` resolution: the last `/` separates the category path from the type
  name. `/byte` is the root category + name "byte". `ELF/Elf64_Ehdr` and
  `/ELF/Elf64_Ehdr` both resolve to category `/ELF` + name `Elf64_Ehdr`.
- Field types render as **C-syntax display names** (`char *`, `MyStruct[4]`)
  to avoid infinite recursion through nested struct types. Use
  `ShowDataType` recursively if you need the full field-detail of a nested
  type.
- `size: -1` means the type is variable-length (e.g. `TerminatedCString`).
- `category` on built-in primitives is always `"/"` (the root category).
