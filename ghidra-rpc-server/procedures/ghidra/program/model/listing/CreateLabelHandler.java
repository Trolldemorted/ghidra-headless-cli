package procedures.ghidra.program.model.listing;

import com.google.gson.JsonObject;

import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.exception.InvalidInputException;

import procedures.RpcContext;
import procedures.RpcProcedure;
import procedures.RpcResponse;

/**
 * Procedure CreateLabel: add a data label at an address in the global
 * namespace.
 *
 * <p>Request: {@code { file, address, name, source? }}.
 * {@code source} defaults to {@code USER_DEFINED} (case-insensitive). Pass any
 * of {@code USER_DEFINED}, {@code IMPORTED}, {@code ANALYSIS}, {@code AI}.
 * {@code DEFAULT} is rejected — Ghidra's API refuses it for new labels.
 *
 * <p>Mutating. Runs in a transaction via {@link RpcContext#runWrite}.
 */
public final class CreateLabelHandler implements RpcProcedure {

    @Override
    public RpcResponse execute(JsonObject req, RpcContext ctx) throws Exception {
        Address addr = ctx.requireAddress(RpcContext.reqStr(req, "address"));
        String name = RpcContext.reqStr(req, "name");
        SourceType source = ctx.sourceType(RpcContext.optStr(req, "source"));
        if (source == SourceType.DEFAULT) {
            return RpcResponse.error("Source type DEFAULT is reserved for system labels; "
                + "use USER_DEFINED.");
        }

        SymbolTable st = ctx.program().getSymbolTable();
        Symbol[] result = { null };
        try {
            ctx.runWrite("create-label " + name, () -> {
                try {
                    result[0] = st.createLabel(addr, name, null, source);
                } catch (InvalidInputException e) {
                    throw new RuntimeException(e);
                }
            });
        } catch (RuntimeException e) {
            return RpcResponse.error("createLabel: " + e.getMessage());
        }
        Symbol s = result[0];
        return new CreateLabelResponse(
            s.getName(),
            s.getAddress().toString(),
            s.getSource() == null ? null : s.getSource().toString()
        );
    }

    @Override
    public boolean mutates() {
        return true;
    }
}
