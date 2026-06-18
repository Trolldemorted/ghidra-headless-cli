# Comment — POST

Post comments (rendered below the line) at an address. Stored on the
`CodeUnit` via `CodeUnit.setComment(POST, ...)` / `CodeUnit.getComment(POST)`.
Four procedures: `PostGet`, `PostSet`, `PostAppend`, `PostClear`.
Set/Append use `SetCommentCmd` / `AppendCommentCmd` for undo/redo.

## Request
```typescript
interface PostGetRequest {
  procedure: "PostGet";
  file: string;
  address: string;
}
interface PostSetRequest {
  procedure: "PostSet";
  file: string;
  address: string;
  text?: string;
}
interface PostAppendRequest {
  procedure: "PostAppend";
  file: string;
  address: string;
  text: string;
  separator?: string; // default: "\n"
}
interface PostClearRequest {
  procedure: "PostClear";
  file: string;
  address: string;
}
```

## Response
```typescript
interface PostGetResponse {
  success: true;
  type: "POST";
  address: string;
  comment: string;
}
interface PostMutateResponse {
  success: true;
  type: "POST";
  address: string;
  comment: string;
  previous: string;
}
```
or `{ "success": false, "error": "<message>" }`.

## Example
Request:
```json
{"procedure": "PostGet", "file": "/Mapeditor.exe", "address": "0x4024f1"}
```
Response:
```json
{"success": true, "type": "POST", "address": "004024f1", "comment": ""}
```