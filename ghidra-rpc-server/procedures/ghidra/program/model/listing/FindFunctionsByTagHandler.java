package procedures.ghidra.program.model.listing;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.function.Predicate;

import com.google.gson.JsonObject;

import procedures.RpcProcedure;
import procedures.RpcContext;
import procedures.RpcResponse;
import procedures.StringQuery;

import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionTag;

/**
 * Procedure FindFunctionsByTag: list all functions that have the tag named {@code query}
 * (exact tag-name match by default; a regex over tag names when {@code regex} is true — see
 * {@link StringQuery#exact}). Each match carries the function's full tag list.
 *
 * Read-only. There is no reverse tag->function index in the public API
 * ({@code FunctionTagManager} only exposes getAllFunctionTags/getUseCount), and supporting
 * substring/regex over tag names requires inspecting each function anyway, so this does one
 * O(functions) pass over the defined functions in address order. An optional {@code limit}
 * caps the result and sets {@code truncated}.
 */
public final class FindFunctionsByTagHandler implements RpcProcedure {

    @Override
    public RpcResponse execute(JsonObject req, RpcContext ctx) throws Exception {
        Predicate<String> matches = StringQuery.exact(req);
        int limit = RpcContext.optInt(req, "limit", 0);

        List<FunctionMatch> results = new ArrayList<>();
        boolean truncated = false;
        for (Function function : ctx.program().getFunctionManager().getFunctions(true)) {
            ctx.monitor().checkCancelled();
            List<String> tags = new ArrayList<>();
            for (FunctionTag tag : function.getTags()) {
                tags.add(tag.getName());
            }
            if (tags.stream().anyMatch(matches)) {
                Collections.sort(tags);
                results.add(new FunctionMatch(function.getName(),
                    function.getEntryPoint().toString(), tags));
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
