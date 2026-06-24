package procedures.ghidra.program.model.listing;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.function.Predicate;

import com.google.gson.JsonObject;

import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolType;

import procedures.RpcContext;
import procedures.RpcProcedure;
import procedures.RpcResponse;
import procedures.StringQuery;

/**
 * Procedure ListLabels: list non-function labels (SymbolType.LABEL) whose name
 * matches {@code query} (substring by default; see {@link StringQuery}).
 *
 * <p>Read-only: like {@code FindFunction} the file is checked out by dispatch
 * per policy but not checked in. Labels are returned sorted by address
 * (ascending), then by name.
 *
 * <p>Function entry-point symbols (SymbolType.FUNCTION), namespace labels,
 * parameters, locals, and external symbols are excluded.
 */
public final class ListLabelsHandler implements RpcProcedure {

    @Override
    public RpcResponse execute(JsonObject req, RpcContext ctx) throws Exception {
        // query is OPTIONAL for list-labels: an empty/absent query means
        // "match all labels". Use StringQuery.contains' pieces directly so
        // we can default the needle to "" instead of requiring it.
        String query = RpcContext.optStr(req, "query");
        if (query == null) query = "";
        boolean ignoreCase = RpcContext.optBool(req, "ignoreCase", false);
        boolean regex = RpcContext.optBool(req, "regex", false);
        final String needle = regex ? query : (ignoreCase ? query.toLowerCase() : query);
        final boolean isRegex = regex;
        final boolean isCaseInsensitive = ignoreCase;
        final java.util.regex.Pattern pattern = isRegex
            ? java.util.regex.Pattern.compile(query, ignoreCase ? java.util.regex.Pattern.CASE_INSENSITIVE : 0)
            : null;
        final Predicate<String> matches = isRegex
            ? s -> pattern.matcher(s).find()
            : (isCaseInsensitive
                ? s -> s.toLowerCase().contains(needle)
                : s -> s.contains(needle));
        int limit = RpcContext.optInt(req, "limit", 0);

        SymbolTable st = ctx.program().getSymbolTable();
        List<LabelMatch> results = new ArrayList<>();
        boolean truncated = false;
        SymbolIterator it = st.getSymbolIterator();
        while (it.hasNext()) {
            ctx.monitor().checkCancelled();
            Symbol s = it.next();
            if (s.getSymbolType() != SymbolType.LABEL) continue;
            if (s.isExternal()) continue;
            if (s.isDynamic()) continue;
            if (!matches.test(s.getName())) continue;
            results.add(new LabelMatch(
                s.getName(),
                s.getAddress().toString(),
                s.getSource() == null ? null : s.getSource().toString()
            ));
            if (limit > 0 && results.size() >= limit) {
                truncated = true;
                break;
            }
        }
        // The iterator is address-ordered already, but sort defensively so the
        // order doesn't depend on Ghidra internals.
        results.sort(Comparator.comparing((LabelMatch m) -> m.address)
            .thenComparing(m -> m.name));
        return new ListLabelsResponse(results.size(), truncated, results);
    }

    @Override
    public boolean mutates() {
        return false;
    }
}
