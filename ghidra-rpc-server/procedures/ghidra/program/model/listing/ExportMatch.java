package procedures.ghidra.program.model.listing;

/**
 * One exported symbol (an in-program function or label that other modules can
 * call). Serialized by gson. The address is a real program address (never
 * EXTERNAL space), so it can be handed back to other RPC procedures verbatim.
 */
final class ExportMatch {
    final String name;            // e.g. "fn_cmd_rpc_test"
    final String address;         // e.g. "00402E40"
    final String symbolType;      // SymbolType.toString() — "FUNCTION", "LABEL", ...
    final boolean isFunction;     // there's a Function at this address
    final boolean isThunk;        // isFunction && f.isThunk()

    ExportMatch(String name, String address, String symbolType,
            boolean isFunction, boolean isThunk) {
        this.name = name;
        this.address = address;
        this.symbolType = symbolType;
        this.isFunction = isFunction;
        this.isThunk = isThunk;
    }
}
