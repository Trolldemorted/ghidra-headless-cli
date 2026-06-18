# Comment — EOL

End-of-line (trailing) comments at an address. Stored on the `CodeUnit` via
`CodeUnit.setComment(EOL, ...)` / `CodeUnit.getComment(EOL)`. The four
procedures (`EolGet`, `EolSet`, `EolAppend`, `EolClear`) cover read, replace,
append-with-separator, and clear. Set/Append use `ghidra.app.cmd.comments.SetCommentCmd`
and `AppendCommentCmd` for proper undo/redo. Get is read-only.

## Request (Get)
```typescript
interface EolGetRequest {
  procedure: "EolGet";
  file: string;       // project path, e.g. "/Mapeditor.exe"
  address: string;    // hex address, e.g. "0x4024f1"
}
```

## Request (Set / Append / Clear)
```typescript
interface EolSetRequest {
  procedure: "EolSet";
  file: string;
  address: string;
  text?: string;      // omit or pass "" to clear
}
interface EolAppendRequest {
  procedure: "EolAppend";
  file: string;
  address: string;
  text: string;       // required
  separator?: string; // default: "\n"
}
interface EolClearRequest {
  procedure: "EolClear";
  file: string;
  address: string;
}
```

## Response
```typescript
interface EolGetResponse {
  success: true;
  type: "EOL";
  address: string;     // canonicalised address
  comment: string;     // current comment ("" if none)
}
interface EolMutateResponse {
  success: true;
  type: "EOL";
  address: string;
  comment: string;     // new comment after the op
  previous: string;    // comment before the op (may be "")
}
```
or `{ "success": false, "error": "<message>" }` (e.g. `No code unit at address 0xdeadbeef.`).

## Example
Request (Get):
```json
{"procedure": "EolGet", "file": "/Mapeditor.exe", "address": "0x4024f1"}
```
Response:
```json
{"success": true, "type": "EOL", "address": "004024f1", "comment": "loop entry"}
```

Request (Append):
```json
{"procedure": "EolAppend", "file": "/Mapeditor.exe", "address": "0x4024f1",
 "text": "fallthrough", "separator": " | "}
```
Response:
```json
{"success": true, "type": "EOL", "address": "004024f1",
 "comment": "loop entry | fallthrough", "previous": "loop entry"}
```