# ProgramLoader

Import a new program into the project from bytes carried in the request, choosing the
loader by best guess from the content.

Wraps Ghidra's `ghidra.app.util.importer.ProgramLoader` builder
(`source(ByteProvider).name(...).load()`). Because Ghidra runs on a separate machine from
the client, the file is **embedded in the request as base64** (`bytes`) rather than
referenced by a server-side path. (Replaces the deprecated `AutoImporter`.)

Project-level: unlike the function commands this takes **no `program`** field. It saves
the imported program into the project and, in a shared repository, adds it to version
control so other clients see it immediately. A name collision does not fail — Ghidra
auto-uniquifies (e.g. `foo.exe` -> `foo.exe.0`); the response's `imported`/`primary`
report the actual path used.

## Request
```typescript
interface ProgramLoaderRequest {
  procedure: "ProgramLoader";
  name: string;        // program name to create in the project, e.g. "foo.exe"
  bytes: string;       // base64-encoded file content
  folder?: string;     // destination project folder, created if missing; default "/"
  comment?: string;    // version-control comment; default "RPC import <name>"
}
```

## Response
```typescript
interface ProgramLoaderResponse {
  success: true;
  imported: string[];  // project paths of every program created (usually one)
  primary: string;     // project path of the primary program
  format: string;      // primary program's executable format, e.g. "Portable Executable (PE)"
}
```
or `{ "success": false, "error": "<message>" }` (e.g. no loader matched, invalid base64).

## Example
Request (bytes truncated):
```json
{"procedure": "ProgramLoader", "name": "hello.exe", "folder": "/imports", "bytes": "TVqQAAMAAAA..."}
```
Response:
```json
{"success": true, "imported": ["/imports/hello.exe"], "primary": "/imports/hello.exe", "format": "Portable Executable (PE)"}
```

Producing the `bytes` field (client side):
```bash
base64 -w0 hello.exe
```
