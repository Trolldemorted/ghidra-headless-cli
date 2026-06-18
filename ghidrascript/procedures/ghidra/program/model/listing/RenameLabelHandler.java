package procedures.ghidra.program.model.listing;

import com.google.gson.JsonObject;

import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

import procedures.RpcContext;
import procedures.RpcProcedure;
import procedures.RpcResponse;

/**
 * Procedure RenameLabel: rename a label identified by its current name (and,
 * optionally, its address to disambiguate).
 *
 * <p>Request: {@code { file, query, address?, newName, source? }}.
 * {@code query} is matched exactly (whitespace-sensitive). If multiple symbols
 * share the name, pass {@code --address} to pick the one at that address —
 * otherwise the request is rejected with the candidate addresses.
 *
 * <p>Mutating. Runs in a transaction via {@link RpcContext#runWrite}.
 */
public final class RenameLabelHandler implements RpcProcedure {

    @Override
    public RpcResponse execute(JsonObject req, RpcContext ctx) throws Exception {
        String name = RpcContext.reqStr(req, "query");
        String newName = RpcContext.reqStr(req, "newName");
        SourceType source = ctx.sourceType(RpcContext.optStr(req, "source"));
        Address addr = null;
        String addrRaw = RpcContext.optStr(req, "address");
        if (addrRaw != null && !addrRaw.isEmpty()) {
            addr = ctx.parseAddress(addrRaw);
            if (addr == null) return RpcResponse.error("Invalid address: " + addrRaw);
        }

        LabelLookup lookup = LabelLookup.byName(ctx, name, addr);
        if (lookup.match == null) {
            if (lookup.candidates == null || lookup.candidates.isEmpty()) {
                return RpcResponse.error("No label matched '" + name + "'.");
            }
            StringBuilder sb = new StringBuilder("Multiple labels match '" + name + "'; pass --address to disambiguate:");
            for (Symbol s : lookup.candidates) {
                sb.append("\n  ").append(s.getAddress()).append("  ").append(s.getName());
            }
            return RpcResponse.error(sb.toString());
        }
        Symbol sym = lookup.match;

        try {
            ctx.runWrite("rename-label " + name + " -> " + newName, () -> {
                try {
                    sym.setName(newName, source);
                } catch (DuplicateNameException | InvalidInputException e) {
                    throw new RuntimeException(e);
                }
            });
        } catch (RuntimeException e) {
            return RpcResponse.error("renameLabel: " + e.getMessage());
        }
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
