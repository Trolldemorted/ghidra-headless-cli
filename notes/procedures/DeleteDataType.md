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
  referrers: string[];      // paths of program-DTM types whose fields now
                             // reference this type by `-BAD-`. Empty array
                             // when nothing depended on the deleted type.
}
```

## Referrers (`-BAD-` warning)

When a struct / union / enum / typedef is used as a field type by
another composite, Ghidra stores the reference as a `DataType` instance
handle on the field. After delete, that handle becomes a `-BAD-`
placeholder (size -1, name `-BAD-`) until the referrer is re-resolved —
typically by running `datatype replace` on the referrer (which rebuilds
it and resolves field types by name) or `datatype delete + create` on
the referrer.

The response carries a `referrers` array listing every program-DTM type
whose structure referenced the deleted type. The CLI prints them on
stderr as:

```
deleted /OpHeaderBytes
note: 2 type(s) referenced this and now show '-BAD-'; run `datatype replace` on each to heal:
  /OpCodes/OpRecord
  /OpCodes/OpPacket
```

Use those paths with `datatype replace --path <X> --definition '...';`
the referrer's structure is rebuilt and field types resolve to the new
`OpHeaderBytes` (or to whatever you re-created under that name).

Detection is structural: every program-DTM type is walked; for each
composite its `getComponents()` are inspected, for each typedef the
base, for each array/pointer the element — recursive and cycle-safe
(via an IdentityHashMap-based `seen` set, so self-referential types
don't loop). Built-ins are skipped (they never reference a local
type by full path). The walk compares by `categoryPath/name`, not by
`DataType` instance identity, so it correctly catches referrers that
hold a stale handle to an old instance of the same name (e.g. after a
prior replace).

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
- `Cannot delete 'X' at '/X' (source archive: <name> [<id>])[<provenance>].
  Archive-resolved types are immutable in Ghidra (the GUI's Delete menu
  is disabled for the same reason). To remove this entry, shadow it
  with a user-defined version at the same path:
    datatype replace --file /<file> --path '/X' --definition '<your definition here>'
  After the replace, your user-defined version becomes the resolver hit
  at '/X', and a follow-up `datatype delete --path '/X'` removes it
  like any other local type. Alternatively, create under a different
  name (e.g. 'X_local') and leave the stub in place.`
  — the resolved type came from an upstream archive (BuiltInTypes,
  Mapeditor.exe, another older version of the same program in the same
  repo, ...) and `dtm.remove()` silently no-op'd. The error includes:
  - the source archive NAME and its UniversalID, so an archive whose
    display name happens to match the current program's name (e.g.
    `Battle_Realms_F.exe` pulled in from `Battle_Realms_F.exe_old` in
    the same repo) is distinguishable from the local archive;
  - a provenance note when the archive's name matches the current
    program but its ID differs — that's the "different program with
    the same display name" case and it's the most common source of
    confusion in this error;
  - a copy-pasteable `datatype replace` command template (with the
    user's exact path filled in) and the alternative "use a different
    name" workaround.
  See `notes/memcorruption` for the audit that motivated surfacing the
  archive ID (helps disambiguate when the GUI and the CLI see
  differently-named archives with similar shapes).
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
