# DataType — Delete

Remove a user-defined data type by full path. Program-level and mutating.
Built-in types are rejected.

## Request
```typescript
interface DeleteDataTypeRequest {
  procedure: "DeleteDataType";
  file: string;
  path: string;             // full type path, e.g. "/MyStruct"
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

## Errors

- `Cannot delete built-in type 'X'.` — the type lives in the BUILT_IN archive
  (BuiltIns / ANSI_C / windows_vs). These types are immutable and shared
  across all programs in the repository.
- `Failed to delete 'X' (in use or category conflict).` — the type is
  referenced by a code unit, function signature, or another type; remove
  those references first.

## Notes

- Implemented via `DataTypeManager.remove(List<DataType>, TaskMonitor)` — the
  bulk entry point. The singleton `remove(DataType, TaskMonitor)` is
  deprecated for removal (Ghidra roadmap).
- Deletion is recursive for composite types only if the contained types are
  also being deleted; orphan types stay put.
- The program is checked in by the dispatcher on success; on failure, the
  transaction is rolled back and no check-in occurs.
