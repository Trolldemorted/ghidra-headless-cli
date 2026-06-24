# GetXrefs

List **references TO** a function, symbol, or memory address. Read-only —
does not mutate the program or check anything back in.

The mirror of Ghidra's *References → References To* window: every caller of
a function, every instruction that loads from a global, every offcut that
lands on a byte inside a multi-byte instruction.

## Request

```json
{
  "procedure": "GetXrefs",
  "file": "/test/tiny64",
  "to": "main",
  "type": "function",
  "includeOffcut": true,
  "limit": 0
}
```

| field           | type    | required | default  | meaning                                          |
|-----------------|---------|----------|----------|--------------------------------------------------|
| `file`          | string  | yes      | —        | project path of the target program (e.g. `/Mapeditor.exe`) |
| `to`            | string  | yes      | —        | the spec — interpreted by `type`                 |
| `type`          | string  | no       | `function` | one of `function` / `symbol` / `address`       |
| `includeOffcut` | bool    | no       | `true`   | include references whose `from` is mid-instruction |
| `limit`         | int     | no       | `0`      | cap on result count; `0` = unlimited             |

### Target resolution

* **`function`** — if `to` parses as an address, `getFunctionAt` is tried first;
  otherwise an exact-name match is run against the function table (case-sensitive,
  mirrors the `find --query X --name` substring behaviour). The first match wins; the
  response always carries the resolved address so the caller can detect
  collisions.

* **`symbol`** — exact name match against `SymbolTable`, skipping external
  entries. A symbol's xrefs include any in-program instruction that
  references the label (the `isExternal` field of the response is set when
  the resolved symbol itself is an external, not the xref).

* **`address`** — `to` is parsed as a hex address against the program's
  default address factory. Offcut targets are allowed (this is what the
  Ghidra References window shows).

## Response

```json
{
  "target": { "type": "function", "query": "main", "address": "00101040" },
  "count": 2,
  "truncated": false,
  "refs": [
    {
      "fromAddress": "00000310",
      "fromFunction": "_elfSectionHeaders",
      "refType": "DATA",
      "opIndex": 0,
      "isExternal": false,
      "isOffcut": false
    },
    {
      "fromAddress": "00001018",
      "fromFunction": null,
      "refType": "UNCONDITIONAL_CALL",
      "opIndex": -1,
      "isExternal": true,
      "isOffcut": false
    }
  ]
}
```

| field               | type    | meaning                                                   |
|---------------------|---------|-----------------------------------------------------------|
| `target.type`       | string  | echo of the requested `type`                              |
| `target.query`      | string  | echo of the requested `to`                                |
| `target.address`    | string  | resolved address the xref iterator was opened on          |
| `count`             | int     | number of xrefs returned (== `refs.length`)               |
| `truncated`         | bool    | `true` if `limit` was hit                                |
| `refs[].fromAddress`| string  | address the reference originates from                     |
| `refs[].fromFunction`| string \| null | name of the function containing the `from` (null if in the header / no enclosing function) |
| `refs[].refType`    | string  | Ghidra reference type (e.g. `UNCONDITIONAL_CALL`, `DATA`, `READ`) |
| `refs[].opIndex`    | int     | operand index; `-1` for operand-less refs (calls, jumps) |
| `refs[].isExternal` | bool    | this xref was created by an external reference            |
| `refs[].isOffcut`   | bool    | `from` is mid-instruction (offcut reference)             |

## Errors

* `Missing 'to'.` — empty `to` field.
* `Missing 'type' (function|symbol|address).` — empty `type` field.
* `Invalid 'type' '<x>': must be function, symbol, or address.`
* `No function|symbol|address matched '<to>'.` — the resolver found nothing.
* `Failed to check out '<file>' (held by another user?).` — the program is
  already exclusively checked out (e.g. by the Ghidra GUI). xrefs is
  read-only but the server still needs an exclusive checkout to open the
  program in this build.

## CLI

```bash
ghidra-headless-cli xrefs --file /test/tiny64 --to main
ghidra-headless-cli xrefs --file /Mapeditor.exe --to 0x00401000 --type address
ghidra-headless-cli xrefs --file /test/tiny64 --to main --limit 10
```

Output:

```
target: function 'main' -> 00101040
found 2 xref(s)
00000310 <_elfSectionHeaders>  DATA  op=0
00001018  UNCONDITIONAL_CALL  op=-1  [external]
```

## Notes

* Results are in the order returned by `ReferenceIterator` (reference rank).
  Sort client-side by `fromAddress` if address order is needed.
* `fromFunction` is `null` when the from-address is in the program header
  or any address not enclosed by a function body (e.g. `_elfSectionHeaders`
  is a function with a special body that wraps program-header bytes).
* The procedure declares `mutates() == false`, so it never checks the
  program back in even though the server acquires an exclusive checkout
  to open it.
