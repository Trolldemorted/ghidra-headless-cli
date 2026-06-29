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
 * {@code query} is matched <b>literally</b> — {@code String.equals} against the
 * stored symbol name. Dots, parens, brackets, dollar signs, etc. are matched
 * as themselves: no regex, no glob, no substring. Auto-generated labels
 * whose names contain {@code .} (e.g. {@code s_V1.1_0069719c} from Ghidra's
 * string-analysis pass) round-trip exactly. If multiple symbols share the
 * name, pass {@code --address} to pick the one at that address — otherwise
 * the request is rejected with the candidate addresses.
 *
 * <p>Misses are diagnostic: when {@code --address} was passed but no
 * exact-name match exists at that address, the response lists the labels
 * that ARE at the address (with their actual stored names — useful for
 * spotting typos / invisible chars in {@code --query}); when
 * {@code --address} is absent and the program-wide lookup misses, up to
 * five substring-containing symbols are offered as a "did you mean?"
 * hint. See {@link LabelLookup}.
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
            if (lookup.candidates != null && !lookup.candidates.isEmpty()) {
                StringBuilder sb = new StringBuilder("Multiple labels match '" + name + "'; pass --address to disambiguate:");
                for (Symbol s : lookup.candidates) {
                    sb.append("\n  ").append(LabelLookup.formatSymbol(s));
                }
                return RpcResponse.error(sb.toString());
            }
            // Miss. Distinguish two cases by which diagnostic list the
            // lookup populated — address-scoped miss dumps the labels that
            // ARE at the address (the actual stored names, so the user can
            // spot typos / invisible chars in --query); program-wide miss
            // dumps up to 5 substring-containing "did you mean?" symbols.
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
