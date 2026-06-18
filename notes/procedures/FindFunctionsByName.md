# FindFunctionsByName

List all functions whose name matches `query`.

By default `query` is a **substring** (`name.contains(query)`); with `regex: true` it is a
regular expression matched with `find()` semantics — i.e. it matches anywhere in the name,
so an exact match is requested by anchoring (`^name$`). `ignoreCase` makes either mode
case-insensitive. Iterates the program's defined functions (via `FunctionManager.getFunctions(true)`)
in address order; an optional `limit` caps the result and sets `truncated`.

Not a `ghidra.app.cmd.function` command; pre-registered in `RpcServer`, handler in
`procedures.ghidra.program.model.listing`. Read-only: the file is checked out by dispatch
(per policy) but not checked in (`mutates()` is false). Query logic is shared with
[FindFunctionsByTag](FindFunctionsByTag.md) (`procedures.StringQuery`).

## Request
```typescript
interface FindFunctionsByNameRequest {
  procedure: "FindFunctionsByName";
  file: string;     // project path of the target program, e.g. "/Mapeditor.exe"
  query: string;       // substring, or a regex when regex=true
  regex?: boolean;     // treat query as a regex; default false
  ignoreCase?: boolean; // case-insensitive match; default false
  limit?: number;      // cap results; default 0 = unlimited
}
```

## Response
```typescript
interface FunctionMatch {
  name: string;
  address: string;     // entry point, e.g. "004024f1"
  tags?: string[];     // omitted by name search (see FindFunctionsByTag)
}
interface FindFunctionsResponse {
  success: true;
  count: number;       // matches returned
  truncated: boolean;  // true if limit cut the result short
  functions: FunctionMatch[];
}
```
or `{ "success": false, "error": "<message>" }` (e.g. `"Invalid regex: <detail>"`).

## Example
Request:
```json
{"procedure": "FindFunctionsByName", "file": "/Mapeditor.exe", "query": "fn_cmd"}
```
Response:
```json
{"success": true, "count": 1, "truncated": false,
 "functions": [{"address": "004024f1", "name": "fn_cmd_rpc_test"}]}
```

Regex, anchored, capped:
```json
{"procedure": "FindFunctionsByName", "file": "/Mapeditor.exe", "query": "^FUN_0040", "regex": true, "limit": 50}
```
