# Comment — DECOMPILER

The function-level **decompiler** comment — rendered at the top of the
function in the Decompiler view. Stored on `Function` via
`Function.setComment(...)` / `Function.getComment()`. The request's
`address` resolves to the *containing* function (`FunctionManager.getFunctionContaining`),
so any address inside the function body works; an address outside any function
yields `No function contains address <addr>.`. Four procedures:
`DecompilerGet`, `DecompilerSet`, `DecompilerAppend`, `DecompilerClear`.
Get is read-only; Set/Append run inside a transaction
(`Function.setComment` has no dedicated `Command` class).

## Request
```typescript
interface DecompilerGetRequest {
  procedure: "DecompilerGet";
  file: string;
  address: string;     // any address inside the target function
}
interface DecompilerSetRequest {
  procedure: "DecompilerSet";
  file: string;
  address: string;
  text?: string;       // omit or pass "" to clear
}
interface DecompilerAppendRequest {
  procedure: "DecompilerAppend";
  file: string;
  address: string;
  text: string;
  separator?: string;  // default: "\n"
}
interface DecompilerClearRequest {
  procedure: "DecompilerClear";
  file: string;
  address: string;
}
```

## Response
```typescript
interface DecompilerGetResponse {
  success: true;
  type: "DECOMPILER";
  address: string;
  function: string;    // resolved function name
  comment: string;
}
interface DecompilerMutateResponse {
  success: true;
  type: "DECOMPILER";
  address: string;
  function: string;
  comment: string;
  previous: string;
}
```
or `{ "success": false, "error": "<message>" }` (e.g. `No function contains address 0xdeadbeef.`).

## Example
Request:
```json
{"procedure": "DecompilerSet", "file": "/Mapeditor.exe", "address": "0x4024f1",
 "text": "main loop body"}
```
Response:
```json
{"success": true, "type": "DECOMPILER", "address": "004024f1",
 "function": "FUN_004024f0", "comment": "main loop body", "previous": ""}
```