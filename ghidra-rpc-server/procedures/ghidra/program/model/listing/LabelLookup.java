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
 * <p>Name matching is <b>always literal</b>: {@code String.equals} against the
 * stored symbol name. Dots, parens, brackets, dollar signs, etc. are
 * matched as themselves — no regex, no glob, no substring. This is the
 * documented contract for {@code rename-label --query} and
 * {@code delete-label --query}; auto-generated labels whose names
 * contain {@code .} (e.g. {@code s_V1.1_0069719c} from Ghidra's
 * string-analysis pass) round-trip exactly.
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
    /**
     * Diagnostic payload. {@code atAddress != null} means the lookup was
     * address-scoped and we found no exact-name match — the caller can
     * surface this list as "labels that ARE at this address" so the user
     * can see the actual stored names (and notice typos / invisible
     * chars in their --query). {@code suggestions} is non-null when the
     * program-wide lookup missed — populated with up to 5 symbols whose
     * names contain {@code query} as a substring (case-insensitive),
     * capped to 80 chars each, to act as a "did you mean?" hint.
     */
    final List<Symbol> atAddress;
    final List<Symbol> suggestions;

    private LabelLookup(Symbol match, List<Symbol> candidates,
                        List<Symbol> atAddress, List<Symbol> suggestions) {
        this.match = match;
        this.candidates = candidates;
        this.atAddress = atAddress;
        this.suggestions = suggestions;
    }

    /** Constructor for the success / multi-match / miss cases (no diagnostics). */
    private static LabelLookup of(Symbol match, List<Symbol> candidates) {
        return new LabelLookup(match, candidates, null, null);
    }

    /** Constructor that augments a miss with diagnostic lists. */
    private static LabelLookup miss(List<Symbol> atAddress, List<Symbol> suggestions) {
        return new LabelLookup(null, null, atAddress, suggestions);
    }

    static LabelLookup byName(RpcContext ctx, String name, Address addr) {
        SymbolTable st = ctx.program().getSymbolTable();
        if (addr != null) {
            // Address-scoped: walk all symbols at the address; pick exact-name.
            // Use st.getSymbols(Address) (array-returning) — it includes
            // dynamic memory symbols, which st.getSymbolsAsIterator(addr)
            // explicitly excludes (per the Ghidra 12.1.2 Javadoc: "Any
            // dynamic symbol at the address will be excluded"). DEFAULT-
            // source auto-labels created by `string define` / auto-analysis
            // are stored as dynamic symbols, so the iterator form silently
            // drops them — the user's get-label would still show them via
            // st.getPrimarySymbol(addr), but rename/delete wouldn't find
            // them. The array form is the more inclusive lookup and
            // matches getPrimarySymbol's coverage. Snapshot EVERY symbol
            // at the address — even if .equals(name) fails — so the caller
            // can list the actual stored names on miss.
            List<Symbol> all = new ArrayList<>();
            for (Symbol s : st.getSymbols(addr)) {
                all.add(s);
            }
            Symbol exact = null;
            for (Symbol s : all) {
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
            if (exact != null) return LabelLookup.of(exact, null);
            // No exact match — return the address's label set as a
            // diagnostic so the caller can dump it.
            return LabelLookup.miss(all, null);
        }
        // Program-wide exact-name lookup. Walk st.getSymbolIterator() (no-
        // arg) and filter by .getName().equals(name). This returns
        // symbols with real DB records, including DEFAULT-source labels
        // (the kind `string define` and auto-analysis create). The
        // name-indexed st.getSymbols(name) explicitly excludes "default
        // thunks" per its Javadoc and is more aggressive about excluding
        // DEFAULT-source symbols, so it is NOT the right lookup here.
        // The dynamic-label fallback (st.getSymbols(name) for DAT_<addr>
        // placeholders synthesized on demand) does not apply to a literal
        // name search — dynamic placeholders are generated on demand when
        // a user references DAT_<addr> by name, not pre-existing. If the
        // user wants to find a DAT_<addr> placeholder, they can use
        // `memory lookup-label` which has a dedicated fallback.
        SymbolIterator it = st.getSymbolIterator();
        List<Symbol> matches = new ArrayList<>();
        while (it.hasNext()) {
            Symbol s = it.next();
            if (s.getName().equals(name)) matches.add(s);
        }
        if (matches.size() == 1) return LabelLookup.of(matches.get(0), null);
        if (!matches.isEmpty()) return LabelLookup.of(null, matches);
        // Miss — produce "did you mean?" suggestions: any symbol whose
        // name CONTAINS `name` (case-insensitive). Capped to 5 so the
        // error stays readable on large programs.
        return LabelLookup.miss(null, didYouMean(ctx, name));
    }

    /** Up to 5 symbols whose names contain {@code needle} as a substring. */
    private static List<Symbol> didYouMean(RpcContext ctx, String needle) {
        if (needle == null || needle.isEmpty()) return null;
        String n = needle.toLowerCase();
        List<Symbol> hits = new ArrayList<>();
        for (Symbol s : ctx.program().getSymbolTable().getSymbolIterator()) {
            if (s.getName().toLowerCase().contains(n)) {
                hits.add(s);
                if (hits.size() >= 5) break;
            }
        }
        return hits.isEmpty() ? null : hits;
    }

    /** Format a single symbol as {@code "<addr>  <name>"}, name truncated to 80. */
    static String formatSymbol(Symbol s) {
        String n = s.getName();
        if (n.length() > 80) n = n.substring(0, 77) + "...";
        return s.getAddress() + "  " + n;
    }
}