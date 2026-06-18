# GetImports

List **external symbols this program imports** from its linked libraries.
Mirrors the Ghidra Imports window — one group per library, each with the
imported entries (functions and data).

> The CLI group is `import` (singular). The RPC procedure name is still
> `GetImports` and is sent as `"procedure": "GetImports"`.

Read-only — does not mutate the program or check anything back in.

## Request

```json
{
  "procedure": "GetImports",
  "file": "/Mapeditor.exe",
  "type": "all",
  "limit": 0
}
```

| field   | type   | required | default | meaning                                       |
|---------|--------|----------|---------|-----------------------------------------------|
| `file`  | string | yes      | —       | project path of the target program            |
| `type`  | string | no       | `all`   | `all` (function + data) or `function` only    |
| `limit` | int    | no       | `0`     | cap on TOTAL entries across all libraries; `0` = unlimited |

## Response

```json
{
  "count": 2,
  "libraryCount": 1,
  "truncated": false,
  "libraries": [
    {
      "name": "<EXTERNAL>",
      "count": 2,
      "entries": [
        {
          "name": "__libc_start_main",
          "address": "EXTERNAL:00000001",
          "originalName": null,
          "source": "IMPORTED",
          "isFunction": true
        },
        {
          "name": "__cxa_finalize",
          "address": "EXTERNAL:00000002",
          "originalName": null,
          "source": "IMPORTED",
          "isFunction": true
        }
      ]
    }
  ]
}
```

| field                          | type             | meaning                                                          |
|--------------------------------|------------------|------------------------------------------------------------------|
| `count`                        | int              | total entries across all libraries (== sum of `libraries[].count`) |
| `libraryCount`                 | int              | number of distinct external libraries                            |
| `truncated`                    | bool             | `true` if `limit` was hit                                       |
| `libraries[].name`             | string           | external library name (e.g. `KERNEL32.dll`); `<EXTERNAL>` when Ghidra has no library tag |
| `libraries[].count`            | int              | entries under this library                                      |
| `entries[].name`               | string           | imported label                                                  |
| `entries[].address`            | string           | the EXTERNAL-space address Ghidra assigned, e.g. `EXTERNAL:00000010` |
| `entries[].originalName`       | string \| null   | unmangled/original name when Ghidra records it                   |
| `entries[].source`             | string \| null   | `SourceType` of the import: `IMPORTED` / `USER_DEFINED` / etc.   |
| `entries[].isFunction`         | bool             | external function vs. external data                             |

The `address` is always in `EXTERNAL` space. Unlike a real program address,
it cannot be passed back to `function disassemble` or `xrefs` — it is a
stable identifier within the Ghidra project only.

Ghidra's own `DEFAULT` stub entries (created during analysis with no real
backing import) are filtered out, so the response only contains symbols
the binary actually pulled in (`IMPORTED`) or that the user annotated
(`USER_DEFINED`).

## Errors

* `Invalid 'type' '<x>': must be all or function.`
* `No program found for '<path>'.`

## CLI

```bash
ghidra-headless-cli import --file /Mapeditor.exe
ghidra-headless-cli import --file /Mapeditor.exe --type function
ghidra-headless-cli import --file /test/tiny64 --limit 50
```

Output (analyzed ELF on P3):

```
found 2 import(s) across 1 library
  <EXTERNAL> (2)
    __libc_start_main             EXTERNAL:00000001   function  IMPORTED
    __cxa_finalize                EXTERNAL:00000002   function  IMPORTED
```

## Notes

* Ordering: libraries are returned in `ExternalManager.getExternalLibraryNames()` order;
  entries within a library in `ExternalLocationIterator` order. Sort client-side if a
  stable order is required.
* `limit` is total across all libraries, not per-library. When hit, the current
  library is still emitted (with however many entries fit), then iteration stops.
