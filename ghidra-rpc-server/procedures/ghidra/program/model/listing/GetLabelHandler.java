package procedures.ghidra.program.model.listing;

import java.util.ArrayList;
import java.util.List;

import com.google.gson.JsonObject;

import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;

import procedures.RpcContext;
import procedures.RpcProcedure;
import procedures.RpcResponse;

/**
 * Procedure GetLabel: report the primary label name at a given address, plus
 * the full set of labels (primary + secondary) at that address.
 *
 * <p>Read-only.
 */
public final class GetLabelHandler implements RpcProcedure {

    @Override
    public RpcResponse execute(JsonObject req, RpcContext ctx) throws Exception {
        Address addr = ctx.requireAddress(RpcContext.reqStr(req, "address"));
        SymbolTable st = ctx.program().getSymbolTable();
        Symbol primary = st.getPrimarySymbol(addr);
        List<LabelAtAddress> all = new ArrayList<>();
        SymbolIterator it = st.getSymbolsAsIterator(addr);
        while (it.hasNext()) {
            Symbol s = it.next();
            all.add(new LabelAtAddress(s.getName(), s.isPrimary()));
        }
        return new GetLabelResponse(
            addr.toString(),
            primary == null ? null : primary.getName(),
            all
        );
    }

    @Override
    public boolean mutates() {
        return false;
    }
}
