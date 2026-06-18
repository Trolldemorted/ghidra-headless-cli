# FileMetadata

Return a project file's attributes and stored metadata.

Project-level and read-only: resolves the `file` path to a `DomainFile` (same path/bare-name
resolution as program selection) WITHOUT opening or checking it out (`needsProgram()` false,
`mutates()` false). The `metadata` map is `DomainFile.getMetadata()` — persisted alongside
the file and readable without instantiating the program. For a Program this includes
Executable Format, Language ID, Compiler, Created-With Ghidra Version, MD5/SHA256, counts,
etc.; the exact keys depend on the content type and tool that wrote them.

Not a `ghidra.app.cmd.function` command; pre-registered in `RpcServer`, handler in
`procedures.ghidra.framework.model`. `size` is `DomainFile.length()` (or `-1` if unavailable).

## Request
```typescript
interface FileMetadataRequest {
  procedure: "FileMetadata";
  file: string;           // project path of the target file, e.g. "/Mapeditor.exe"
}
```

## Response
```typescript
interface FileMetadataResponse {
  success: true;
  path: string;           // "/Mapeditor.exe"
  name: string;           // "Mapeditor.exe"
  contentType: string;    // e.g. "Program"
  version: number;        // current version (versioned files)
  versioned: boolean;
  checkedOut: boolean;
  readOnly: boolean;
  size: number;           // bytes, or -1 if unavailable
  lastModified: number;   // epoch millis
  fileID: string;
  metadata: { [key: string]: string }; // stored metadata map
}
```
or `{ "success": false, "error": "<message>" }` (e.g. `"No file found for '/NoSuch.exe'."`).

## Example
Request:
```json
{"procedure": "FileMetadata", "file": "/Mapeditor.exe"}
```
Response (truncated):
```json
{"success": true, "path": "/Mapeditor.exe", "name": "Mapeditor.exe", "contentType": "Program",
 "version": 27, "versioned": true, "checkedOut": false, "readOnly": false,
 "size": 10158080, "lastModified": 1781760972076, "fileID": "c0a8b221eee72043206118680600",
 "metadata": {"Language ID": "x86:LE:32:default (4.7)", "Executable Format": "Portable Executable (PE)",
              "Executable MD5": "b19cba7ae0ffd46ec1d4b59ef9ad7c10", "Analyzed": "true"}}
```
