# Required-Fields Audit (server-side defaults → explicit wire fields)

Date: 2026-06-24
Trigger: making every field that the server was silently defaulting into an
explicit required field. The CLI now sends the old default; the server
rejects missing fields with `Missing required field 'X'.` Errors match
the `reqStr(req, "X")` shape so third-party clients see one consistent
contract.

**This file is the canonical reference for the wire contract.** Per-procedure
markdown (`/workdir/notes/procedures/<Cmd>.md`) lists the field-by-field
shape; if you find a discrepancy, this audit wins. Generated as part of
the 2026-06-24 push to make defaults explicit across the API surface.
See [`rpc-server.md`](rpc-server.md) §"Required vs optional fields" for
the high-level summary.

## Categories

1. **`optBool(req, "X", Y)` → `reqBool(req, "X")`** — Y was a server-picked
   default. Now the wire MUST carry the boolean.
2. **`optInt(req, "X", Y)` → `reqInt(req, "X")`** — same shape for ints.
3. **`optStr(req, "X")` with implicit default in handler** — handler did
   `s == null || s.isEmpty() ? "DEFAULT" : s`. Convert to `reqStr` and
   the CLI must send the default string. Examples: `direction`/`format`
   on `Callgraph`, `type` on `GetExports`/`GetImports`.
4. **Genuinely nullable `optStr`** — field's absence is a real "no value"
   state (e.g. optional text content, optional filter, optional comment,
   optional name when the function is auto-named). The handler may use
   `null` as a real input (e.g. `CreateFunctionCmd`'s `name`, comment
   clearings). These STAY optional — the wire contract is
   "present-or-omitted, never defaulted by the server".
5. **"Length is independent of the default" specials** — e.g.
   `ApplyDataType.length` (defaults to the type's length when omitted,
   not to a fixed numeric). Stays optional (the handler's "default" is
   derived from another input, not a server pick). Required presence of
   the field is meaningless here; what's required is honoring the
   Dynamic-only override rule (already enforced).

## Boolean fields becoming required

| File | Field | Old default |
|---|---|---|
| StringQuery | `ignoreCase` | false |
| StringQuery | `regex` | false |
| ApplyDataType | `force` | false |
| Analyze | `force` | true |
| ApplyDataType (line 85) | `length` | derived — stays optional |
| ShowDataType | `with_deps` | false |
| SetDataTypeFieldType | `force` | false |
| ClearCodeUnits | `clearContext` | false |
| Disassemble | `bytes` | true |
| Listings | `bytes` | true |
| GetXrefs | `includeOffcut` | true |
| Callgraph | `includeRefs` | false |
| ApplyFunctionDataTypes | `createBookmarks` | true |
| ApplyFunctionDataTypes | `alwaysReplace` | false |
| DecompilerParameterId | `commitDataTypes` | true |
| DecompilerParameterId | `commitVoidReturn` | true |
| SetFunctionVarArgs | `hasVarArgs` | true |
| CreateThunk (checkExisting) | `checkExisting` | false |
| NewFunctionStackAnalysis | `forceProcessing` | false |
| FunctionResultStateStackAnalysis | `forceProcessing` | false |
| FunctionStackAnalysis | `forceProcessing` | false |
| UpdateFunctionCommand | `force` | false |
| ListFiles | `recursive` | true |
| ListFiles | `includeFolders` | false |
| ListDataTypes | `recursive` | true |
| ListLabels | `ignoreCase` | false |
| ListLabels | `regex` | false |
| NamespaceListClasses | `recursive` | true |

## Integer fields becoming required

| File | Field | Old default |
|---|---|---|
| GetXrefs | `limit` | 0 (unlimited) |
| GetExports | `limit` | 0 |
| GetImports | `limit` | 0 |
| FindFunction | `limit` | 0 |
| ListFiles | `limit` | 0 |
| ListDataTypes | `limit` | 0 |
| ListLabels | `limit` | 0 |
| DefinedStringScan | `limit` | 0 |
| Callgraph | `depth` | 2 |
| FlatDecompilerAPI | `timeoutSecs` | 0 (no timeout) |
| DecompilerSwitchAnalysis | `timeout` | 60 |
| DecompilerParameterId | `timeout` | 60 |
| DecompilerParallelConventionAnalysis | `timeout` | 60 |
| SetFunctionPurge | `purge` | 0 |
| SetStackDepthChange | `stackDepthChange` | 0 |
| AddStackVar | `stackOffset` | 0 |
| ApplyDataType (line 85) | `length` | derived — stays optional |

## String fields with implicit defaults (becoming required)

| File | Field | Old default | New required value |
|---|---|---|---|
| Callgraph | `direction` | "called" | "called" |
| Callgraph | `format` | "mermaid" | "mermaid" |
| GetExports | `type` | "all" | "all" |
| GetImports | `type` | "all" | "all" |
| UpdateFunctionCommand | `updateType` | "DYNAMIC_STORAGE_FORMAL_PARAMS" | same |
| GetXrefs | `type` | (already required) | — |

## Strings staying nullable (optStr, no default in handler)

| File | Field | Why nullable |
|---|---|---|
| `source` (across many handlers) | `source` | string absent → "no source set" (caller genuinely has no opinion) — DEFER. The SourceType helper does the defaulting with a hard-coded `USER_DEFINED` when the string is empty. **The contract is "omit means USER_DEFINED"**; the CLI must NOT send `"USER_DEFINED"` explicitly (we'd be saying "the user typed the default" not "the user didn't say"). **KEEP as optStr**, but make the CLI default to omitting it. |
| CreateFunctionCmd | `name` | null is meaningful (auto-name) — KEEP optStr |
| CreateExternalFunction | `address` | null = unbound — KEEP optStr |
| CreateThunk | `referencedFunctionAddress` | null = auto-detect — KEEP optStr |
| AddRegisterVar/AddStackVar/AddMemoryVar | `name` | null = unnamed — KEEP optStr |
| AddRegisterVar/AddStackVar/AddMemoryVar | `dataType` | null = use default data type — KEEP optStr |
| NamespaceCreateClass | `parent` | null = global namespace — KEEP optStr |
| NamespaceCreateClass | `fromNamespace` | optional rename source — KEEP optStr |
| NamespaceCreateClass | `name` | required-ish (we'll add reqStr here) — **VERIFY** |
| FunctionSetNamespace | `namespace` | null = global — KEEP optStr |
| comment `text` | `text` | required by usage (every Set/Append uses it as the comment) — **VERIFY** |
| comment `separator` | `separator` | null = no separator — KEEP optStr |
| comment `comment` fields | `comment` | nullable (e.g. Clear) — KEEP optStr |
| SetDataTypeFieldComment | `comment` | nullable (clearing) — KEEP optStr |
| SetDataTypeVariantComment | `comment` | nullable (clearing) — KEEP optStr |
| SetVariableComment | `comment` | nullable (clearing) — KEEP optStr |
| SetFunctionRepeatableComment | `comment` | nullable (clearing) — KEEP optStr |
| ShowDataType | `path` / `name` / `archive` / `category` | exactly-one-of lookup; nullable by design — KEEP optStr |
| ListDataTypes | `category` | null = root — KEEP optStr |
| ListDataTypes | `kind` | null = all kinds — KEEP optStr |
| ListFiles | `folder` | null = root "/" — **implicit default — should be required "/"?** |
| ListFiles | `contentType` | null = no filter — KEEP optStr |
| ReplaceDataType | `path` / `category` / `definition` | at least one lookup mode — KEEP optStr |
| CreateDataType | `category` / `definition` | `definition` is required by usage; `category` has implicit default — **VERIFY** |
| EditDataType | `definition` | required by usage — **VERIFY** |
| CreateDataType | `size` / `enumSize` | derived/required — **VERIFY** |
| CreateLabel | `source` | SourceType — see `source` rule above |
| RenameLabel | `source` | SourceType — see `source` rule above |
| DeleteLabel | `address` | `address` is required — **VERIFY** |
| LookupLabel | `address` | `address` is required — **VERIFY** |
| RenameLabel | `address` | `address` is required — **VERIFY** |
| FindFunction | `field` | filter field selector — KEEP optStr |
| ChangeFunctionTag | `field` | tag name — required — **VERIFY** |
| ProgramLoader | `folder` / `comment` | `folder` has implicit default "/" — **VERIFY** |
| ReadBytes | `format` | "hex" default — **VERIFY** (and see below) |

## SourceType — special note

`ctx.sourceType(s)` defaults to `USER_DEFINED` when `s` is null/empty. This
is the **shared canonical default** and is documented in the Javadoc and
the help text on every flag. The CLI uses `Source::opt` which
maps `Option<Source>` → `Option<String>` (None stays absent). Keeping
this as "omit means USER_DEFINED" preserves the principle of least
surprise: the user types no `--source` and gets the documented default;
the wire stays empty so the server's default is exercised. **Stays optStr.**
(Aligns with the standing user feedback that "USER_DEFINED" is the
right default and should not be sent unless explicitly requested.)

## Decisions

1. Add `reqBool(req, "X")` and `reqInt(req, "X")` to `RpcContext`. They
   mirror the existing `reqStr` — throw `IllegalArgumentException`
   ("Missing required field 'X'.") when missing/null.
2. The CLI flags that map to these new required fields get a clap
   `default_value` matching the OLD server default, and switch from
   `Option<bool>` to `bool` (or `Option<i64>` to `i64`) so the request
   builder ALWAYS emits the field.
3. `source` stays nullable. The SourceType defaulting is documented and
   universal; making it required would force every CLI command to
   repeat `[default: user-defined]` AND send the string on the wire.
4. `CreateDataType`'s `category` (default `"/"`) — keep nullable, the
   "category = root" is a real input.
5. `ListFiles`'s `folder` (default `"/"`) — same: keep nullable.
6. `ProgramLoader`'s `folder` (default `"/"`) — same.

## Implementation order

1. Add `reqBool` / `reqInt` to `RpcContext`.
2. Convert every `optBool`/`optInt` call in handlers (table above).
3. Convert the implicit-default `optStr` calls in handlers.
4. For each converted field, locate the matching CLI flag and:
   - change the type from `Option<bool>` to `bool` (or `Option<i64>` to
     `i64`),
   - add `default_value = "..."` (matches the OLD server default),
   - change `opt_bool`/`opt_int` in the request builder to
     `bool`/`int` (always emit).
5. Update the procedure docs (`/workdir/notes/procedures/*.md`) for every
   field that was converted.
