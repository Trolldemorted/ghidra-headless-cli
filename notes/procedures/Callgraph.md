# Callgraph

Walk a function's callers or callees up to a depth and return either a
Mermaid `flowchart` string (default) or a structured nodes/edges JSON
envelope. Built on top of `ReferenceManager` + `FunctionManager` — no
Ghidra call-graph API to wrap (Ghidra's only call-graph utility,
`AcyclicCallGraphBuilder`, returns a `DependencyGraph<Address>` of the
acyclic portion with vertices as addresses; it isn't a fit for a
depth-bounded, directional walker).

> The CLI group is `callgraph` (singular). The RPC procedure name is
> `Callgraph` and is sent as `"procedure": "Callgraph"`.

Read-only — does NOT mutate the program. The framework still acquires an
exclusive checkout to open the program (so the per-request file state is
stable), but no check-in happens because `mutates()` returns `false`.

## Request

```json
{
  "procedure": "Callgraph",
  "file": "/Mapeditor.exe",
  "function": "main",
  "direction": "called",
  "depth": 2,
  "format": "mermaid",
  "includeRefs": false
}
```

| field        | type    | required | default   | meaning |
|--------------|---------|----------|-----------|---------|
| `function`   | string  | yes      |           | Function name (exact match against the function table) OR a hex address. First match wins; the response always carries the resolved name+address so the caller can detect collisions. |
| `direction`  | string  | no       | `called`  | `called` walks what the root calls (callees, BFS downward); `calling` walks who calls the root (callers, BFS upward). |
| `depth`      | int     | no       | `2`       | Max BFS layers from the root. 1 = direct neighbors only. Cap is 10 — deeper traversals on real binaries explode fast. |
| `format`     | string  | no       | `mermaid` | `mermaid` returns a Mermaid `flowchart` source string; `json` returns a structured nodes/edges envelope. |
| `includeRefs`| bool    | no       | `false`   | When `false`, only `RefType.isCall()` references are walked. When `true`, jump/data refs to functions are also followed (so a `COMPUTED_JUMP` tail-call or a `DATA` ref into a function is part of the graph). |

## Response (`format=mermaid`)

```json
{
  "root":      { "name": "main", "address": "00101040", "depth": 0, "isExternal": false },
  "direction": "called",
  "depth": 2,
  "truncated": false,
  "mermaid":   "graph TD\n  n_main[\"main @00101040\"]\n  n_add[\"add @00101139\"]\n  n_main --> n_add\n  ..."
}
```

The `mermaid` field is the diagram source. For `direction="called"` it's
`graph TD` (root at top, children below); for `direction="calling"` it's
`graph BT` (root at bottom, callers above). External / leaf nodes get a
tinted `classDef` so they stand out at a glance.

Node and edge counts are deliberately NOT in the response — the data is
right there (count the node-definition lines and the `-->` / `-.->`
arrows in `mermaid`, or switch to `format=json` and read
`nodes[].length` / `edges[].length`). The CLI computes the count for its
log line either way.

## Response (`format=json`)

```json
{
  "root":      { "name": "main", "address": "00101040", "depth": 0, "isExternal": false },
  "direction": "called",
  "depth": 2,
  "truncated": false,
  "nodes": [
    { "name": "main", "address": "00101040", "depth": 0, "isExternal": false },
    { "name": "add",  "address": "00101139", "depth": 1, "isExternal": false }
  ],
  "edges": [
    { "from": "main", "to": "add", "depth": 1, "refType": "UNCONDITIONAL_CALL" }
  ]
}
```

The Mermaid emitter reads the same node/edge lists internally — the two
formats are the same data in different envelopes.

## Direction semantics

* `direction=called` — for each function at depth D, iterate references
  FROM its body (`ReferenceManager.getReferenceIterator` on the function
  body's address ranges). For each call ref, resolve the callee via
  `FunctionManager.getFunctionAt(ref.getToAddress())`. Same loop as
  ghidrecomp's `get_called_funcs_memo` (ghidrecomp/callgraph.py:573-612).
* `direction=calling` — for each function at depth D, iterate
  `ReferenceManager.getReferencesTo(fn.getEntryPoint())`. For each ref,
  resolve the caller via `FunctionManager.getFunctionContaining(ref.getFromAddress())`.
  Same loop as ghidrecomp's `get_calling_funcs_memo` (ghidrecomp/callgraph.py:538-569).

The walker is BFS (not DFS like ghidrecomp) — chosen so the Mermaid
emitter can rely on parents always appearing before children in the
output, and so the `depth` field is the actual BFS layer from the root.

## Cycles & external functions

* **Cycles:** when a neighbor function is already visited at the same or
  shallower depth, the edge is still emitted (so the cycle is visible in
  the output) but the function is NOT re-enqueued. ghidrecomp drops the
  cycle edge entirely (ghidrecomp/callgraph.py:647-653); we keep it
  because cycles are often the most informative part of a call graph.
* **External functions:** emitted as leaf nodes with a `EXTERNAL:<addr>`
  address marker, never recursed into. Same short-circuit as
  ghidrecomp's `func_is_external` (ghidrecomp/callgraph.py:680-682). The
  name comes from the symbol table's primary symbol at the EXTERNAL
  address; on a miss it falls back to the raw address.

## Truncation

A hard cap of 5000 edges per call (`MAX_EDGES`). When the cap is hit the
walker stops enqueuing new work and the response sets `truncated=true`.
The Mermaid output remains well-formed; the JSON output is just a
shorter list of edges. `truncated` is also set if the server's
`TaskMonitor` is cancelled mid-walk.

## Errors

* `Missing 'function'.`
* `No function matched '<x>'.` — exact name + address both failed.
* `Invalid 'direction' '<x>': must be called or calling.`
* `'depth' must be between 1 and 10.`
* `Invalid 'format' '<x>': must be mermaid or json.`
* `No program found for '/<x>'.` — standard.

## CLI

```bash
# Callee walk, Mermaid, depth 2 (default)
ghidra-headless-cli callgraph --file /Mapeditor.exe --function main
ghidra-headless-cli callgraph --file /Mapeditor.exe --function 0x401000

# Caller walk, Mermaid
ghidra-headless-cli callgraph --file /Mapeditor.exe --function chkesp --direction calling

# Deeper walk
ghidra-headless-cli callgraph --file /Mapeditor.exe --function main --depth 5

# Structured output (nodes[]/edges[])
ghidra-headless-cli callgraph --file /Mapeditor.exe --function main --format json

# Follow jump/data refs too (e.g. COMPUTED_JUMP tail calls)
ghidra-headless-cli callgraph --file /Mapeditor.exe --function thunk_FUN_00419580 --include-refs true
```

Mermaid output (logs on stderr, diagram on stdout — pipeable):

```
graph TD
  n_FUN_00419580["FUN_00419580 @00419580"]
  n_chkesp["chkesp @004475ba"]
  n_FUN_00419580 --> n_chkesp
  n_FUN_00419580 --> n_chkesp
  n_chkesp --> n_chkesp
  classDef leaf fill:#fef,stroke:#333
  class n_chkesp leaf
```

JSON output:

```
callgraph for FUN_00419580 (depth=3, 3 nodes, 3 edges)
# nodes (3):
  FUN_00419580 @ 00419580 (depth=0)
  chkesp @ 004475ba (depth=1)
  chkesp @ EXTERNAL:000001cb (depth=2) [external]
# edges (3):
  FUN_00419580 -> chkesp (depth=1, UNCONDITIONAL_CALL)
  FUN_00419580 -> chkesp (depth=1, UNCONDITIONAL_CALL)
  chkesp -> chkesp (depth=2, COMPUTED_JUMP)
```

## Notes

* The `mermaid` field is a plain string — pipe it to a Mermaid renderer
  (mermaid-cli, a web app, a Mermaid live URL, etc.) to get a picture.
  The procedure does NOT upload to `mermaid.live` (ghidrecomp does, but
  the RPC server has no business depending on an external service).
* Node and edge counts are not in the response; the CLI computes them
  from the data (Mermaid line count, or JSON array length). The Mermaid
  diagram may draw fewer nodes than the JSON reports when two nodes
  share a sanitized id (e.g. an in-program function and its EXTERNAL
  twin both named `chkesp` collide on `n_chkesp` in the diagram). The
  JSON is the authoritative record.
* Cycle edges (e.g. `chkesp -> chkesp` above) are emitted as normal
  edges. Deduplicating them or computing shortest paths is out of scope.
* Function resolution is exact name match (case-sensitive), not
  substring. The response carries the resolved address so the caller
  can see which one was picked.
