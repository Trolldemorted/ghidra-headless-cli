# Comment — REPEATABLE

Repeatable comments at an address — automatically copied onto references to
this address. Stored on the `CodeUnit` via
`CodeUnit.setComment(REPEATABLE, ...)` / `CodeUnit.getComment(REPEATABLE)`.
Four procedures: `RepeatableGet`, `RepeatableSet`, `RepeatableAppend`,
`RepeatableClear`. Set/Append use `SetCommentCmd` / `AppendCommentCmd` for
undo/redo.

Note: this is the per-CodeUnit repeatable comment, distinct from the
function-level repeatable comment managed by `SetFunctionRepeatableCommentCmd`.

## Request
```typescript
interface RepeatableGetRequest {
  procedure: "RepeatableGet";
  file: string;
  address: string;
}
interface RepeatableSetRequest {
  procedure: "RepeatableSet";
  file: string;
  address: string;
  text?: string;
}
interface RepeatableAppendRequest {
  procedure: "RepeatableAppend";
  file: string;
  address: string;
  text: string;
  separator?: string; // default: "\n"
}
interface RepeatableClearRequest {
  procedure: "RepeatableClear";
  file: string;
  address: string;
}
```

## Response
```typescript
interface RepeatableGetResponse {
  success: true;
  type: "REPEATABLE";
  address: string;
  comment: string;
}
interface RepeatableMutateResponse {
  success: true;
  type: "REPEATABLE";
  address: string;
  comment: string;
  previous: string;
}
```
or `{ "success": false, "error": "<message>" }`.

## Example
Request:
```json
{"procedure": "RepeatableSet", "file": "/Mapeditor.exe", "address": "0x4024f1",
 "text": "BUFFER_SIZE = 0x100"}
```
Response:
```json
{"success": true, "type": "REPEATABLE", "address": "004024f1",
 "comment": "BUFFER_SIZE = 0x100", "previous": ""}
```