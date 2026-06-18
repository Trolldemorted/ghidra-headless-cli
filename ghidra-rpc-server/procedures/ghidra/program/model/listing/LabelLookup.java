package procedures.ghidra.program.model.listing;

import java.util.ArrayList;
import java.util.List;

import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;

import procedures.RpcContext;

/**
 * Shared symbol-lookup helper for the memory mutators. Two modes:
 *
 * <ul>
 *   <li><b>Exact name</b> — matches a single symbol; multi-match is an error.
 *   <li><b>Name + address</b> — when {@code address} is non-null, narrows the
 *       match to that address (still exact-name matched).
 * </ul>
 *
 * <p>Returns a {@link Result} that tells the caller which path was taken and
 * what to do next.
 */
final class LabelLookup {
    /** The match — exactly one symbol. */
    final Symbol match;
    /** When non-null and {@code match == null}, all the matching symbols —
     *  the caller should ask the user to disambiguate by --address. */
    final List<Symbol> candidates;

    private LabelLookup(Symbol match, List<Symbol> candidates) {
        this.match = match;
        this.candidates = candidates;
    }

    static LabelLookup byName(RpcContext ctx, String name, Address addr) {
        SymbolTable st = ctx.program().getSymbolTable();
        if (addr != null) {
            // Address-scoped: walk all symbols at the address; pick exact-name.
            SymbolIterator it = st.getSymbolsAsIterator(addr);
            List<Symbol> all = new ArrayList<>();
            Symbol exact = null;
            while (it.hasNext()) {
                Symbol s = it.next();
                all.add(s);
                if (s.getName().equals(name)) {
                    if (exact != null) {
                        // multiple symbols with the same name at the same
                        // address — disambiguate by primary.
                        if (s.isPrimary()) exact = s;
                    } else {
                        exact = s;
                    }
                }
            }
            if (exact != null) return new LabelLookup(exact, null);
            return new LabelLookup(null, all);
        }
        // Program-wide exact-name lookup. Symbols with the same name can
        // exist in different namespaces, so use the iterator instead of
        // getLabelOrFunctionSymbols to keep namespaces out of the picture.
        SymbolIterator it = st.getSymbolIterator();
        List<Symbol> matches = new ArrayList<>();
        while (it.hasNext()) {
            Symbol s = it.next();
            if (s.getName().equals(name)) matches.add(s);
        }
        if (matches.size() == 1) return new LabelLookup(matches.get(0), null);
        if (matches.isEmpty()) return new LabelLookup(null, null);
        return new LabelLookup(null, matches);
    }
}
