# ReplaceDataType

Create or **overwrite** a struct / union / enum / typedef in the program's
Data Type Manager (DTM). Mirrors the Ghidra GUI **"Replace..."** action on
a type in the Data Type Manager: a name collision silently overwrites the
existing type in place, and all references in function signatures, applied
data, and other types are preserved.

## When to use

- Promoting an **archive-resolved stub** to a user-defined version under
  the same name. This is the case for auto-typed defaults pulled in from
  upstream archives (e.g. `L_String` arriving from `Battle_Realms_F.exe`
  before you've defined your own `L_String` struct).
- Overwriting a previously defined local type with a new shape (after
  learning more about the structure from the binary).
- Editing an existing type **in place** when the only path forward is a
  destructive replacement — `EditDataType` cannot change a struct's
  total size, and cannot change a typedef's base kind.

For the safe counterpart (fails on collision, won't overwrite an existing
type), see [`CreateDataType`](CreateDataType.md).

## Path vs name+category

The target can be specified two ways:

- `path` (preferred for disambiguation) — the full path, used verbatim.
  Example: `"/Demangler/L_String"`. This is the right form when the same
  name appears in multiple categories, as happens with archive stubs.
- `name` + optional `category` (default `"/"`) — shorter, but ambiguous
  when name collisions exist across categories.

The two forms are mutually exclusive on the JSON request; the server
errors out if both are set.

## Input shapes

Same as `CreateDataType` — pick **one** of:

1. **C snippet** (`definition`): `"struct Foo { int x; char *name; };"`.
   The snippet's embedded name is the type's name. The `name`, `kind`,
   `fields`, `entries`, and `base` parameters are ignored on this path.
   Anonymous snippets (`struct { int x; };`) are rejected — the snippet
   must declare a name.

2. **Explicit JSON** (`kind` + `name` + one of `fields` / `entries` / `base`):
   - `kind`: `struct` | `union` | `enum` | `typedef`
   - `fields` (struct/union): `[{"name":"x","type":"int"}, ...]`
   - `entries` (enum): `[{"name":"RED","value":0}, ...]`
   - `base` (typedef): a C-syntax type expression, e.g. `"int"`, `"char *"`,
     `"byte[16]"`
   - `enumSize` (enum, default 4): byte width

## Conflict policy

Uses `DataTypeConflictHandler.REPLACE_HANDLER`:
- If a type with the same name exists in the target category (whether
  archive-resolved or local), it is silently overwritten.
- If the target category does not exist, the call fails with
  `No data-type category for '<path>'.`
- If the C snippet is invalid or the kind is unknown, the call fails
  before any modification.
- The conflict handler preserves references — function signatures and
  applied data that pointed to the old type now point to the new one.

## Path form: GUI-equivalent example

Ghidra's GUI shows archive-resolved types in italics (or with a small lock
icon, depending on the theme) in the Data Type Manager. To replace one,
right-click → "Replace..." → enter the new definition. The CLI
equivalent:

```sh
ghidra-headless-cli datatype replace \
  --file /Battle_Realms_F.exe \
  --path /Demangler/L_String \
  --definition 'struct L_String { char *ptr; int len; };'
```

The new type lives in the program DTM under `/Demangler/L_String`, the
archive stub is shadowed, and every reference that previously resolved
through the archive now resolves through the local copy.

## Category auto-creation

When the parent category in `--path` (or `--name` + `--category`) does
not exist in the program DTM yet, it is created automatically. The
operation is idempotent — if the category already exists, this is a
no-op. Both `createCategory` and `addDataType` require an active
transaction, so the lookup + creation + add run inside the same
`runWrite` block.

```sh
# Both of these succeed even when /MyTest or /MyTest/Sub didn't exist:
ghidra-headless-cli datatype replace --path /MyTest/Foo --kind struct --fields '...'
ghidra-headless-cli datatype replace --path /MyTest/Sub/Bar --kind struct --fields '...'
```

## C-snippet path resolution

When `--definition` is given, the parsed type's natural category is
overridden to match `--path` (via `setNameAndCategory`). This means
`--path /MyTest/L_String --definition 'struct L_String { ... };'`
correctly lands at `/MyTest/L_String`, not at root. The snippet's
embedded name must still match the path's last segment; mismatches
return an error rather than silently landing at the wrong place.

## Response

Returns the same shape as `ShowDataType`:
```json
{
  "kind": "struct",
  "name": "L_String",
  "path": "/Demangler/L_String",
  "category": "/Demangler",
  "size": 8,
  "source": "ARCHIVE",          // or "USER" if the archive stub was promoted
  "sourceArchive": "Battle_Realms_F.exe",  // or null when source=USER
  "detail": { ...fields, packed, alignment, ... }
}
```

The `source` / `sourceArchive` fields are the disambiguator: they tell
you whether the type now lives in the program's DTM (`USER`) or whether
the replace was performed against the archive's local copy
(`ARCHIVE: <name>`). Both are legitimate outcomes; the GUI does the
same.

## Errors

- `Missing 'name' (or 'path').`
- `'path' must be absolute (start with '/'): 'X'.`
- `'path' must end with a type name: '/X/'.`
- `No data-type category for '<path>'.`
- C snippet parse errors (from `CDefinitionParser`).
- `Unknown kind 'X' (use struct|union|enum|typedef).`

## See also

- [`CreateDataType`](CreateDataType.md) — strict counterpart; fails on
  name collision instead of overwriting.
- [`ShowDataType`](ShowDataType.md) — read-only inspection of any type
  by path.
- [`EditDataType`](EditDataType.md) — non-destructive edits (rename,
  move, append fields, replace fields). Cannot change total size or
  typedef base kind.
- [`DeleteDataType`](DeleteDataType.md) — remove a user-defined type.
