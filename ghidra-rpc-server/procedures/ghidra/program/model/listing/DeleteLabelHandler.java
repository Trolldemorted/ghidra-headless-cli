package procedures.ghidra.program.model.listing;

import com.google.gson.JsonObject;

import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolType;

import procedures.RpcContext;
import procedures.RpcProcedure;
import procedures.RpcResponse;

/**
 * Procedure DeleteLabel: remove a label identified by its name (and, optionally,
 * its address to disambiguate). Disambiguation rule and miss diagnostics
 * mirror {@link RenameLabelHandler} — see {@link LabelLookup}.
 *
 * <p>Refuses to delete function entry-point labels (SymbolType.FUNCTION) — use
 * {@code function delete} for that.
 *
 * <p>Mutating. Runs in a transaction via {@link RpcContext#runWrite}.
 */
public final class DeleteLabelHandler implements RpcProcedure {

    @Override
    public RpcResponse execute(JsonObject req, RpcContext ctx) throws Exception {
        String name = RpcContext.reqStr(req, "query");
        Address addr = null;
        String addrRaw = RpcContext.optStr(req, "address");
        if (addrRaw != null && !addrRaw.isEmpty()) {
            addr = ctx.parseAddress(addrRaw);
            if (addr == null) return RpcResponse.error("Invalid address: " + addrRaw);
        }

        LabelLookup lookup = LabelLookup.byName(ctx, name, addr);
        if (lookup.match == null) {
            if (lookup.candidates != null && !lookup.candidates.isEmpty()) {
                StringBuilder sb = new StringBuilder("Multiple labels match '" + name + "'; pass --address to disambiguate:");
                for (Symbol s : lookup.candidates) {
                    sb.append("\n  ").append(LabelLookup.formatSymbol(s));
                }
                return RpcResponse.error(sb.toString());
            }
            StringBuilder sb = new StringBuilder("No label matched '" + name + "'.");
            sb.append(" Name match is literal (String.equals on the stored symbol name)");
            if (lookup.atAddress != null && !lookup.atAddress.isEmpty()) {
                sb.append("\nLabels at address ").append(addr).append(':');
                for (Symbol s : lookup.atAddress) {
                    sb.append("\n  ").append(LabelLookup.formatSymbol(s));
                }
                sb.append("\nUse `memory get-label --address ").append(addr)
                  .append("` to see the exact stored names.");
            } else if (lookup.suggestions != null && !lookup.suggestions.isEmpty()) {
                sb.append("\nDid you mean one of these?");
                for (Symbol s : lookup.suggestions) {
                    sb.append("\n  ").append(LabelLookup.formatSymbol(s));
                }
                sb.append("\nUse `memory list-labels --query \"").append(name)
                  .append("\"` to search.");
            }
            return RpcResponse.error(sb.toString());
        }
        Symbol sym = lookup.match;
        if (sym.getSymbolType() == SymbolType.FUNCTION) {
            return RpcResponse.error("'" + name + "' is a function entry-point label; use "
                + "'function delete' to remove the function itself.");
        }
        if (!sym.getParentNamespace().isGlobal()
            && sym.getSymbolType() != SymbolType.LABEL) {
            // Defensive: only top-level labels and function labels live in
            // the global namespace; if the symbol is not in the global
            // namespace AND is not a function, it's a parameter/local we
            // don't want to expose via this verb.
            return RpcResponse.error("Refusing to delete non-label symbol '"
      + name + "' (type=" + sym.getSymbolType() + ").");
        }

        final String deletedName = sym.getName();
        final String deletedAddr = sym.getAddress().toString();
        final boolean[] ok = { false };
        ctx.runWrite("delete-label " + name, () -> { ok[0] = sym.delete(); });
        return new DeleteLabelResponse(ok[0], deletedName, deletedAddr);
    }

    @Override
    public boolean mutates() {
        return true;
    }
}
