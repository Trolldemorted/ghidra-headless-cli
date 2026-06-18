package procedures.ghidra.program.model.listing;

import com.google.gson.JsonObject;

import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.Symbol;

import procedures.RpcContext;
import procedures.RpcProcedure;
import procedures.RpcResponse;

/**
 * Procedure SetPrimaryLabel: promote a secondary label at an address to the
 * primary slot. The address is required because "set primary" only makes
 * sense for one of the symbols at a single address.
 *
 * <p>Mutating. Runs in a transaction via {@link RpcContext#runWrite}.
 */
public final class SetPrimaryLabelHandler implements RpcProcedure {

    @Override
    public RpcResponse execute(JsonObject req, RpcContext ctx) throws Exception {
        String name = RpcContext.reqStr(req, "query");
        Address addr = ctx.requireAddress(RpcContext.reqStr(req, "address"));

        // Address-scoped lookup: the lookup helper accepts the address and
        // narrows the search.
        LabelLookup lookup = LabelLookup.byName(ctx, name, addr);
        if (lookup.match == null) {
            if (lookup.candidates == null || lookup.candidates.isEmpty()) {
                return RpcResponse.error("No label '" + name + "' at " + addr + ".");
            }
            // Address was given, so the only candidates are at that address.
            StringBuilder sb = new StringBuilder("Multiple labels named '" + name + "' at "
                + addr + "; use 'get-label --address " + addr + "' to list them.");
            return RpcResponse.error(sb.toString());
        }
        Symbol sym = lookup.match;
        if (sym.isPrimary()) {
            return RpcResponse.error("'" + name + "' is already the primary label at " + addr + ".");
        }

        final Symbol fsym = sym;
        ctx.runWrite("set-primary " + name, fsym::setPrimary);
        return new CreateLabelResponse(
            sym.getName(),
            sym.getAddress().toString(),
            sym.getSource() == null ? null : sym.getSource().toString()
        );
    }

    @Override
    public boolean mutates() {
        return true;
    }
}
