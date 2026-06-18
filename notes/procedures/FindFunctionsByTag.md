# FindFunctionsByTag

List all functions that have the tag named `query`.

By default `query` is matched **exactly** against tag names — a function matches if it has a
tag whose name equals `query` (this is "functions having this tag", not "tags containing this
text"). With `regex: true`, `query` is instead a regular expression matched against each tag
name (`find()` semantics; anchor with `^tag$` for a whole-name match). `ignoreCase` makes
either mode case-insensitive. Each match carries the function's full, sorted tag list.
Iterates the program's defined functions (via `FunctionManager.getFunctions(true)`) in address
order; an optional `limit` caps the result and sets `truncated`.

There is no reverse tag→function index in the public API (`FunctionTagManager` only exposes
`getAllFunctionTags`/`getUseCount`), and substring/regex over tag names requires inspecting
each function anyway, so this does one O(functions) pass checking `Function.getTags()`.

Not a `ghidra.app.cmd.function` command; pre-registered in `RpcServer`, handler in
`procedures.ghidra.program.model.listing`. Read-only (`mutates()` false). Query logic is shared
with [FindFunctionsByName](FindFunctionsByName.md) (`procedures.StringQuery`).

## Request
```typescript
interface FindFunctionsByTagRequest {
  procedure: "FindFunctionsByTag";
  program: string;     // project path of the target program, e.g. "/Mapeditor.exe"
  query: string;       // exact tag name, or a regex over tag names when regex=true
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
  tags: string[];      // the function's tags (sorted)
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
{"procedure": "FindFunctionsByTag", "program": "/Mapeditor.exe", "query": "RPC"}
```
Response:
```json
{"success": true, "count": 1, "truncated": false,
 "functions": [{"address": "004024f1", "name": "fn_cmd_rpc_test", "tags": ["RPC_TAG"]}]}
```
