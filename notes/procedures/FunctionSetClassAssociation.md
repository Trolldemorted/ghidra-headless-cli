# FunctionSetClassAssociation

Associate a function with a class namespace — the CLI equivalent of the
GUI's **Edit → Set Class Association…**.

After association, the decompiler types the function's implicit `this`
parameter (for `__thiscall` / MSVC member functions on x86) as a pointer to
the DTM type whose name matches the class. The lookup is name-based: class
and struct are coupled by **name only**.

## Auto-stub warning

If no struct with the class's name exists in the program's DTM,
Ghidra's `FunctionDB.createClassStructIfNeeded` auto-creates a stub
(size 0/1, no fields) on this edit. The stub is a placeholder —
populate it with `EditDataType` after the fact, or **prevent it by
creating a struct with the class's name BEFORE running this command**.

The auto-stub is triggered by ANY edit to a function with a class
association, not just by this command (e.g. changing the calling
convention to `__thiscall` on an already-associated function will
also fire it). This is Ghidra-internal behavior, not specific to
the CLI.

Rejects plain namespaces as targets — only `GhidraClass` instances
are valid.

Wraps `Function.setParentNamespace(classNamespace)`, which fires
`createClassStructIfNeeded` automatically inside the call. Mutating:
the file is checked out before the call and checked in immediately
after; the call fails if the push fails.

## The right way to type `this` on `__thiscall` functions on x86

```text
# 1. Struct FIRST (skips auto-stub on step 3)
datatype create --file /X --kind struct --name OpMarketTrade ...

# 2. Create the class
namespace create-class --file /X --parent /Game --name OpMarketTrade

# 3. Associate the function
function set-class-association --file /X --address 0xNNNNNNNN \
    --class /Game/OpMarketTrade
```

After step 3, the decompiler types `this` as `OpMarketTrade *` and
dereferences it.

## Request
```typescript
interface FunctionSetClassAssociationRequest {
  procedure: "FunctionSetClassAssociation";
  file: string;              // project path of the target program
  address: string;           // hex, function entry point
  class: string;             // full path of the class namespace, e.g. "/Game/OpMarketTrade"
}
```

## Response
```typescript
interface FunctionSetClassAssociationResponse {
  success: true;
  functionName: string;      // the function's name after association
  classPath: string;         // the class's full path
}
```

Or `{ "success": false, "error": "<message>" }`. Common errors:
- `"No function at <address>."`
- `"'<path>' is not a class (it's a plain namespace); create the class first via namespace create-class."`
- `"No namespace found for '<path>'."`

## Example

```json
{"procedure": "FunctionSetClassAssociation", "file": "/Patrician3.exe",
 "address": "0x00401000", "class": "/Game/OpMarketTrade"}
```
