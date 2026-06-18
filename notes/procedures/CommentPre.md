# Comment — PRE

Pre comments (rendered above the line) at an address. Stored on the `CodeUnit`
via `CodeUnit.setComment(PRE, ...)` / `CodeUnit.getComment(PRE)`. Four
procedures: `PreGet`, `PreSet`, `PreAppend`, `PreClear`. Set/Append use
`SetCommentCmd` / `AppendCommentCmd` for proper undo/redo. Get is read-only.

## Request
```typescript
interface PreGetRequest {
  procedure: "PreGet";
  file: string;
  address: string;
}
interface PreSetRequest {
  procedure: "PreSet";
  file: string;
  address: string;
  text?: string;      // omit or pass "" to clear
}
interface PreAppendRequest {
  procedure: "PreAppend";
  file: string;
  address: string;
  text: string;
  separator?: string; // default: "\n"
}
interface PreClearRequest {
  procedure: "PreClear";
  file: string;
  address: string;
}
```

## Response
```typescript
interface PreGetResponse {
  success: true;
  type: "PRE";
  address: string;
  comment: string;
}
interface PreMutateResponse {
  success: true;
  type: "PRE";
  address: string;
  comment: string;
  previous: string;
}
```
or `{ "success": false, "error": "<message>" }`.

## Example
Request:
```json
{"procedure": "PreSet", "file": "/Mapeditor.exe", "address": "0x4024f1",
 "text": "decoded framebuffer pointer"}
```
Response:
```json
{"success": true, "type": "PRE", "address": "004024f1",
 "comment": "decoded framebuffer pointer", "previous": ""}
```