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
import procedures.StringQuery;

/**
 * Procedure LookupLabel: find symbols by name. Unlike {@link ListLabelsHandler}
 * this also returns function entry-point labels, namespace labels, and
 * external (import) symbols — it answers the question "is there anything with
 * this name, and where?". Use {@code --address} to scope the search to one
 * address; otherwise the search is program-wide.
 *
 * <p>{@code query} is interpreted by {@link StringQuery} (substring by
 * default; {@code --regex} or {@code --ignore-case} for the alternatives).
 *
 * <p>Read-only.
 */
public final class LookupLabelHandler implements RpcProcedure {

    @Override
    public RpcResponse execute(JsonObject req, RpcContext ctx) throws Exception {
        String query = RpcContext.reqStr(req, "query");
        java.util.function.Predicate<String> matches = StringQuery.contains(req);
        Address addr = null;
        String addrRaw = RpcContext.optStr(req, "address");
        if (addrRaw != null && !addrRaw.isEmpty()) {
            addr = ctx.parseAddress(addrRaw);
            if (addr == null) {
                return RpcResponse.error("Invalid address: " + addrRaw);
            }
        }

        SymbolTable st = ctx.program().getSymbolTable();
        List<LabelMatch> results = new ArrayList<>();
        SymbolIterator it = st.getSymbolIterator();
        while (it.hasNext()) {
            ctx.monitor().checkCancelled();
            Symbol s = it.next();
            if (!matches.test(s.getName())) continue;
            if (addr != null && !s.getAddress().equals(addr)) continue;
            results.add(new LabelMatch(
                s.getName(),
                s.getAddress().toString(),
                s.getSource() == null ? null : s.getSource().toString(),
                s.getSymbolType().toString(),
                s.isExternal(),
                s.isPrimary()
            ));
        }
        // getSymbolIterator() only returns symbols with real DB records, so
        // it misses auto-generated DAT_<addr> placeholders that Ghidra
        // synthesizes on demand. Probe st.getSymbols(query) — which has a
        // built-in getSymbolForDynamicName fallback — and add any new match
        // we haven't already recorded. We run this unconditionally (not
        // gated on results.isEmpty()) so a partial DB hit doesn't hide a
        // dynamic match at a different address. The match predicate and
        // address filter still apply, so unrelated extras are skipped.
        if (!query.isEmpty()) {
            java.util.Set<String> seen = new java.util.HashSet<>();
            for (LabelMatch m : results) seen.add(m.name + "@" + m.address);
            SymbolIterator dynIt = st.getSymbols(query);
            while (dynIt.hasNext()) {
                Symbol s = dynIt.next();
                if (!matches.test(s.getName())) continue;
                if (addr != null && !s.getAddress().equals(addr)) continue;
                String key = s.getName() + "@" + s.getAddress();
                if (seen.add(key)) {
                    results.add(new LabelMatch(
                        s.getName(),
                        s.getAddress().toString(),
                        s.getSource() == null ? null : s.getSource().toString(),
                        s.getSymbolType().toString(),
                        s.isExternal(),
                        s.isPrimary()
                    ));
                }
            }
        }
        return new LookupLabelResponse(results.size(), results);
    }

    @Override
    public boolean mutates() {
        return false;
    }
}
