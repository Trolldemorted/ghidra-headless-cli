# Comment — PLATE

Plate comments — the function-header comment shown above a function in the
listing. Stored on the `CodeUnit` at the function's entry point via
`CodeUnit.setComment(PLATE, ...)` / `CodeUnit.getComment(PLATE)`. Four
procedures: `PlateGet`, `PlateSet`, `PlateAppend`, `PlateClear`. The address
must reference an existing instruction / data unit (typically the function's
entry point); an unmapped address yields `No code unit at address <addr>.`.

## Request
```typescript
interface PlateGetRequest {
  procedure: "PlateGet";
  file: string;
  address: string;
}
interface PlateSetRequest {
  procedure: "PlateSet";
  file: string;
  address: string;
  text?: string;
}
interface PlateAppendRequest {
  procedure: "PlateAppend";
  file: string;
  address: string;
  text: string;
  separator?: string; // default: "\n"
}
interface PlateClearRequest {
  procedure: "PlateClear";
  file: string;
  address: string;
}
```

## Response
```typescript
interface PlateGetResponse {
  success: true;
  type: "PLATE";
  address: string;
  comment: string;
}
interface PlateMutateResponse {
  success: true;
  type: "PLATE";
  address: string;
  comment: string;
  previous: string;
}
```
or `{ "success": false, "error": "<message>" }`.

## Example
Request:
```json
{"procedure": "PlateSet", "file": "/Mapeditor.exe", "address": "0x4024f1",
 "text": "main loop: dispatch one queued command per iteration"}
```
Response:
```json
{"success": true, "type": "PLATE", "address": "004024f1",
 "comment": "main loop: dispatch one queued command per iteration", "previous": ""}
```