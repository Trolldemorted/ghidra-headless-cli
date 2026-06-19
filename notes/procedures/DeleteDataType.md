# DataType — Delete

Remove a user-defined data type by full path. Program-level and mutating.
Built-in types and archive-resolved stubs are rejected with a clear
error; the user-side equivalent of "remove an archive stub" is
[`ReplaceDataType`](ReplaceDataType.md) (which shadows the stub with a
user-defined version in place).

## Request
```typescript
interface DeleteDataTypeRequest {
  procedure: "DeleteDataType";
  file: string;
  path: string;             // full type path, e.g. "/MyStruct" or "/MyCat/MyStruct"
}
```

## Response
```typescript
interface DeleteDataTypeResponse {
  success: true;
  path: string;             // echoes the input
  deleted: true;
}
```

## Path resolution (merged view)

`path` is resolved through the **merged view**: if the program DTM has
no entry at the requested path, every open source archive is searched
for a type with the matching `CategoryPath + Name`. This makes
`datatype show --path /X/Y/Z` and `datatype delete --path /X/Y/Z` work
even when the path lives only in an upstream archive (e.g.
`/Demangler/L_String` from `Battle_Realms_F.exe`).

## Errors

- `Missing data-type path.` — `path` was empty.
- `No data type at path '/X'.` — no type (program-DTM or archive) matches
  the path. Either the name is misspelled, the parent category doesn't
  exist anywhere, or the type was removed in a prior operation.
- `Cannot delete built-in type 'X'.` — the type lives in the BUILT_IN
  archive (BuiltIns / ANSI_C / windows_vs). These types are immutable
  and shared across all programs in the repository.
- `Cannot delete 'X' at '/X' (source archive: <name>). Archive-resolved
  types are immutable; use 'datatype replace' to shadow the entry with a
  user-defined version under the same name.` — the resolved type came
  from an upstream archive (BuiltInTypes, Mapeditor.exe, ...) and
  `remove()` no-op'd. This is the Ghidra GUI's "Delete" menu being
  disabled for archive members.
- `Failed to delete 'X' (in use or category conflict).` — the type is
  referenced by a code unit, function signature, or another type; remove
  those references first.

## Notes

- Implemented via `DataTypeManager.remove(List<DataType>, TaskMonitor)` — the
  bulk entry point. The singleton `remove(DataType, TaskMonitor)` is
  deprecated for removal (Ghidra roadmap).
- After the remove, the path is re-resolved: if the type is still there
  (silent no-op on immutable archives), the call fails with the
  archive-immutable error above.
- Deletion is recursive for composite types only if the contained types are
  also being deleted; orphan types stay put.
- The program is checked in by the dispatcher on success; on failure, the
  transaction is rolled back and no check-in occurs.
