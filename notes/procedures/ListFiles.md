# ListFiles

Enumerate the project's files under a folder.

Project-level and read-only: walks the `DomainFolder` tree via `ProjectData` and never opens
or checks out any program (`needsProgram()` false → dispatch resolves nothing; `mutates()`
false). `folder` (default `/`) scopes the walk; `recursive` (default true) descends into
subfolders; `includeFolders` (default false) also emits folder entries; `contentType`
(optional) keeps only files of that content type (e.g. `Program`, case-insensitive). An
optional `limit` caps results and sets `truncated`. Entries are returned sorted by path.

Not a `ghidra.app.cmd.function` command; pre-registered in `RpcServer`, handler in
`procedures.ghidra.framework.model`. File-only attributes (`version`/`versioned`/`checkedOut`)
are omitted from folder entries.

## Request
```typescript
interface ListFilesRequest {
  procedure: "ListFiles";
  folder?: string;        // project folder to list; default "/"
  recursive?: boolean;    // descend into subfolders; default true
  includeFolders?: boolean; // also emit folder entries; default false
  contentType?: string;   // keep only this content type (e.g. "Program"); default all
  limit?: number;         // cap results; default 0 = unlimited
}
```

## Response
```typescript
interface FileEntry {
  path: string;           // project path, e.g. "/Mapeditor.exe"
  name: string;
  isFolder: boolean;
  contentType?: string;   // files only, e.g. "Program"
  version?: number;       // files only
  versioned?: boolean;    // files only
  checkedOut?: boolean;   // files only
}
interface ListFilesResponse {
  success: true;
  count: number;          // entries returned
  truncated: boolean;     // true if limit cut the result short
  files: FileEntry[];
}
```
or `{ "success": false, "error": "<message>" }` (e.g. `"No folder found for '/nope'."`).

## Example
Request:
```json
{"procedure": "ListFiles", "contentType": "Program"}
```
Response:
```json
{"success": true, "count": 1, "truncated": false,
 "files": [{"path": "/Mapeditor.exe", "name": "Mapeditor.exe", "isFolder": false,
            "contentType": "Program", "version": 27, "versioned": true, "checkedOut": false}]}
```
