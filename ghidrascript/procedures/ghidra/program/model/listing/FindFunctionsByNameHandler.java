package procedures.ghidra.program.model.listing;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Predicate;

import com.google.gson.JsonObject;

import procedures.RpcProcedure;
import procedures.RpcContext;
import procedures.RpcResponse;
import procedures.StringQuery;

import ghidra.program.model.listing.Function;

/**
 * Procedure FindFunctionsByName: list all functions whose name matches {@code query}
 * (substring by default, regex when {@code regex} is true; see {@link StringQuery}).
 *
 * Read-only (like FlatDecompilerAPI/Disassemble): the file is checked out by dispatch per
 * policy but not checked in. Iterates the program's defined functions in address order;
 * an optional {@code limit} caps the result and sets {@code truncated}.
 */
public final class FindFunctionsByNameHandler implements RpcProcedure {

    @Override
    public RpcResponse execute(JsonObject req, RpcContext ctx) throws Exception {
        Predicate<String> matches = StringQuery.contains(req);
        int limit = RpcContext.optInt(req, "limit", 0);

        List<FunctionMatch> results = new ArrayList<>();
        boolean truncated = false;
        for (Function function : ctx.program().getFunctionManager().getFunctions(true)) {
            ctx.monitor().checkCancelled();
            if (matches.test(function.getName())) {
                results.add(new FunctionMatch(function.getName(),
                    function.getEntryPoint().toString(), null));
                if (limit > 0 && results.size() >= limit) {
                    truncated = true;
                    break;
                }
            }
        }
        return new FindFunctionsResponse(results.size(), truncated, results);
    }

    /** Searching does not change the program. */
    @Override
    public boolean mutates() {
        return false;
    }
}
