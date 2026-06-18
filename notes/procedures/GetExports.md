# GetExports

List **in-program symbols flagged as external entry points** — what this
binary exposes to other modules. Mirrors the Ghidra Exports window.

> The CLI group is `export` (singular). The RPC procedure name is still
> `GetExports` and is sent as `"procedure": "GetExports"`.

Read-only — does not mutate the program or check anything back in.

## Request

```json
{
  "procedure": "GetExports",
  "file": "/Mapeditor.exe",
  "type": "all",
  "limit": 0
}
```

| field   | type   | required | default | meaning                                       |
|---------|--------|----------|---------|-----------------------------------------------|
| `file`  | string | yes      | —       | project path of the target program            |
| `type`  | string | no       | `all`   | `all` (functions + labels) or `function` only |
| `limit` | int    | no       | `0`     | cap on result count; `0` = unlimited           |

## Response

```json
{
  "count": 12,
  "truncated": false,
  "refs": [
    {
      "name": "_init",
      "address": "00101000",
      "symbolType": "Function",
      "isFunction": true,
      "isThunk": false
    },
    {
      "name": "main",
      "address": "00101040",
      "symbolType": "Function",
      "isFunction": true,
      "isThunk": false
    },
    {
      "name": "_IO_stdin_used",
      "address": "00102000",
      "symbolType": "Label",
      "isFunction": false,
      "isThunk": false
    }
  ]
}
```

| field              | type    | meaning                                                       |
|--------------------|---------|---------------------------------------------------------------|
| `count`            | int     | number of exports returned (== `refs.length`)                 |
| `truncated`        | bool    | `true` if `limit` was hit                                     |
| `refs[].name`      | string  | export name (function or label name)                          |
| `refs[].address`   | string  | in-program address, e.g. `00101000` (NEVER `EXTERNAL:`)       |
| `refs[].symbolType`| string  | `SymbolType` — `Function`, `Label`, `FunctionThunk`, ...      |
| `refs[].isFunction`| bool    | `true` if a `Function` exists at that address                 |
| `refs[].isThunk`   | bool    | `isFunction && Function.isThunk()` (forwarder)                |

Unlike `GetImports`, the `address` is a **real program address** (in the
`.text` / `.rdata` / etc. memory space), not `EXTERNAL` space. That means it
can be piped directly into other procedures:

```bash
# pick an export, then disassemble it
ADDR=$(ghidra-headless-cli export --file /Mapeditor.exe --type function --limit 1 | awk 'NR==2 {print $1}')
ghidra-headless-cli function disassemble --file /Mapeditor.exe --address "$ADDR"
# or follow the calls into it
ghidra-headless-cli xrefs --file /Mapeditor.exe --to "$ADDR" --type address
```

Only `Symbol.isPrimary()` entries are returned, so multi-symbol addresses
(thunk bodies that share an address with their target) are de-duplicated.

## Errors

* `Invalid 'type' '<x>': must be all or function.`
* `No program found for '<path>'.`

## CLI

```bash
ghidra-headless-cli export --file /Mapeditor.exe
ghidra-headless-cli export --file /Mapeditor.exe --type function
ghidra-headless-cli export --file /test/tiny64 --limit 20
```

Output (analyzed ELF on P3):

```
found 12 export(s)
00101000  _init                             Function
00101040  main                              Function
00101050  _start                            Function
001010f0  __do_global_dtors_aux             Function
00101130  frame_dummy                       Function
00101139  add                               Function
00101144  _fini                             Function
00102000  _IO_stdin_used                    Label
00104000  data_start                        Label
...
```

## Notes

* Results are in `SymbolTable.getSymbolIterator()` order — by ascending
  address, with labels and functions interleaved.
* `isThunk` is set when the export is a forwarder (a one-instruction jump
  to another function). The thunk itself is a real function in the program
  and is returned as a single export row.
* Win32 PE binaries will typically show `_DllMainCRTStartup` and any
  user-defined exports; ELF shared objects will show their dynamic symbols;
  static archives / position-independent executables will usually show
  zero exports.
