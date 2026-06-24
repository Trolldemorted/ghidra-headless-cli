# FindFunction

Unified function search. Replaces the older
[`FindFunctionsByName`](FindFunctionsByName.md) and
[`FindFunctionsByTag`](FindFunctionsByTag.md) procedures; adds
address lookup. Read-only.

## Request
```typescript
interface FindFunctionRequest {
  procedure: "FindFunction";
  file: string;
  query: string;             // search pattern (required)
  field?: "all" | "name" | "tag" | "address";  // default "all"
  regex?: boolean;
  ignoreCase?: boolean;
  limit?: number;            // default 0 = unlimited
}
```

- `query` is the search pattern. Required.
- `field` is one of `"all"` (default), `"name"`, `"tag"`, `"address"`.
  When omitted, the query is matched against function names AND tags
  AND addresses (the "everything" default).
- `regex`, `ignoreCase`, `limit` work as in the older procedures.

## Field dispatch

| `field` | Behavior |
|---------|----------|
| `"all"` (default) | Match `query` against the function's qualified name OR any of its tags; ALSO if `parseAddress(query)` succeeds, include the function returned by `getFunctionContaining(addr)` then `getFunctionAt(addr)`. |
| `"name"` | Match `query` against the qualified name only. |
| `"tag"` | Match `query` against each tag name. |
| `"address"` | Parse `query` as an address (`ctx.parseAddress` — accepts `0x401000`, `401000`, `ram:401000`); return the function whose body contains it, or the function whose entry point equals it, or empty if neither matches. |

In `"all"` mode, an address hit is included as an OR — if the query
happens to parse as an address AND the resulting function's name or
tags don't match the substring/regex predicate, the function is
still returned. In `"address"` mode, the substring/regex predicate is
not consulted at all.

## Why this design

Three constraints shaped the surface:

1. `find-by-name` was the legacy name-search; it stays as the
   "search names" verb (`--query X --name`).
2. `find-by-tag` was the legacy tag-search; it stays as the "search
   tags" verb (`--query X --tag`). Substring default (vs the old
   exact-match default) is deliberate — the unified verb shares
   `--regex` semantics across all three scopes.
3. The new address lookup — the WISH — is the "look up at this
   address" verb (`--query 0x0064F2C1 --address`).

`--query X` alone (no scoping flag) is the "everywhere" default: the
most common case ("I'm looking for `X` somewhere, I don't know
where") shouldn't require the caller to pick a field.

## Response
```typescript
interface FunctionMatch {
  name: string;        // qualified "ns::leaf" — matches the decompiler's view
  address: string;     // entry point, e.g. "0064f2c1"
  tags?: string[];     // omitted by Gson when empty/null
}
interface FindFunctionsResponse {
  success: true;
  count: number;
  truncated: boolean;  // true if limit cut the result short
  functions: FunctionMatch[];
}
```

In all four field modes the response shape is identical. The `tags`
array is populated for every returned function (so an "all" search
shows what tags each match has, and address-mode returns the single
function's full tag list for free).

## Qualified-name semantics (carried over)

Match and display use `Function.getName(true)` — the parent namespace
chain joined with `"::"` plus the leaf. So for a function whose leaf
is `Foo__Bar` and lives in namespace `GameScreen`, both `name` and
match are `"GameScreen::Foo__Bar"` (literal `__`, not rewritten to
`::`). This is the same string the decompiler prints (see
`function decompile`), so the search output agrees with the
decompiler's view of the same symbol.

## Examples

WISH — look up the function at a hex address:
```bash
ghidra-headless-cli function find --file /Patrician3.exe --query 0x0064F2C1 --address
```
Returns (typically):
```
0064f2c1  String_AssignFromCStr
```

Legacy `find-by-name` behavior — substring match against qualified names:
```bash
ghidra-headless-cli function find --file /Mapeditor.exe --query fn_cmd --name
```

Legacy `find-by-tag` behavior — substring match against tag names:
```bash
ghidra-headless-cli function find --file /Mapeditor.exe --query RPC --tag
```

"Everywhere" search (the new default — names AND tags AND addresses):
```bash
ghidra-headless-cli function find --file /Mapeditor.exe --query RPC
```

Regex, anchored, capped:
```bash
ghidra-headless-cli function find --file /Mapeditor.exe --query "^FUN_0040" --name --regex true --limit 50
```

## CLI shorthand policy

`--query`, `--name`, `--tag`, `--address`, `--regex`, `--ignore-case`,
`--limit` are all long-only — no short aliases. The project's
shorthand policy reserves shorts for `-H/--host` and `-v/--verbose`
only.

## Notes

- **Type guard: not applicable.** The target is a whole program, not
  a struct or a memory address; no built-in / typedef / composite
  guards are needed.
- **Read-only.** `mutates()` returns false; the file is checked out
  by dispatch (per policy) but not checked in.
- **Address parsing.** `ctx.parseAddress` returns null for an
  unparseable string (e.g. `"bogus"`). In `"address"` mode the null
  return becomes an error response (`Invalid or missing address:
  bogus`); in `"all"` mode the null is silent and the address-slot
  of the OR is simply skipped — the search continues to match names
  and tags.
- **Containment vs entry-point.** Address lookup tries
  `getFunctionContaining` first (the function whose body covers the
  address) then falls back to `getFunctionAt` (exact entry point).
  Both null → empty result, no error. This handles the common case
  of a hex address from a register dump or call stack — the address
  is often inside a function body, not at its start.
- **Persistence.** No project mutations. The result is computed
  fresh on each call; no caching.